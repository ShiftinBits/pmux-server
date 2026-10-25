import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { createTestDO, type MockDOState } from './helpers/mock-do';
import { MockWebSocket } from './helpers/mock-websocket';
import { createJWT } from '../auth';
import type { SignalingDO } from '../signaling';
import { version } from '../../package.json';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

let doInstance: SignalingDO;
let mockDOState: MockDOState;

beforeEach(async () => {
  const result = await createTestDO();
  doInstance = result.doInstance;
  mockDOState = result.mockState;
});

afterEach(() => {
  vi.restoreAllMocks();
});

/**
 * Register a device and get a valid JWT for WebSocket auth.
 */
async function setupDevice(
  deviceId: string,
  deviceType: 'host' | 'mobile'
): Promise<string> {
  doInstance.registerDevice(deviceId, `pubkey-${deviceId}`, deviceType);
  return createJWT(deviceId, deviceType, JWT_SECRET);
}

/**
 * Create a mock WebSocket and authenticate it with the DO.
 */
async function connectAndAuth(
  deviceId: string,
  deviceType: 'host' | 'mobile'
): Promise<{ ws: MockWebSocket; token: string }> {
  const token = await setupDevice(deviceId, deviceType);
  const ws = new MockWebSocket();

  // Simulate Hibernation API: DO accepts the WebSocket (adds to accepted list)
  mockDOState.acceptedWebSockets.push(ws as unknown as WebSocket);

  // Set initial attachment with lastMessageTime
  ws.serializeAttachment({
    authenticated: false,
    lastMessageTime: Date.now(),
  });

  doInstance.setConnection(deviceId, ws as unknown as WebSocket);

  // Authenticate
  await doInstance.webSocketMessage(
    ws as unknown as WebSocket,
    JSON.stringify({ type: 'auth', token })
  );

  return { ws, token };
}

describe('Signaling server efficiency [T3.10]', () => {
  describe('idle WebSocket cleanup', () => {
    it('closes WebSocket idle past the timeout', async () => {
      const { ws } = await connectAndAuth('agent-1', 'host');

      // Simulate that the WS has been idle for 6 minutes
      const att = ws.deserializeAttachment() as Record<string, unknown>;
      att.lastMessageTime = Date.now() - 6 * 60 * 1000; // 6 minutes ago
      ws.serializeAttachment(att);

      // Trigger alarm
      await doInstance.alarm();

      expect(ws.closed).toBe(true);
      expect(ws.closeCode).toBe(1000);
      expect(ws.closeReason).toBe('idle timeout');
    });

    it('keeps active WebSocket alive (message within idle timeout)', async () => {
      const { ws } = await connectAndAuth('agent-1', 'host');

      // Simulate recent activity (30 seconds ago — within the 90s idle window)
      const att = ws.deserializeAttachment() as Record<string, unknown>;
      att.lastMessageTime = Date.now() - 30 * 1000; // 30 seconds ago
      ws.serializeAttachment(att);

      // Trigger alarm
      await doInstance.alarm();

      expect(ws.closed).toBe(false);
    });

    // Boundary tests pin the 90s timeout so a regression back to the old 5min
    // window (or any value above ~2x the 30s presence heartbeat) is caught.
    it('closes WebSocket just past the 90s threshold (91s idle)', async () => {
      const { ws } = await connectAndAuth('agent-1', 'host');

      const att = ws.deserializeAttachment() as Record<string, unknown>;
      att.lastMessageTime = Date.now() - 91 * 1000; // 91s ago — just over 90s
      ws.serializeAttachment(att);

      await doInstance.alarm();

      expect(ws.closed).toBe(true);
      expect(ws.closeReason).toBe('idle timeout');
    });

    it('keeps WebSocket alive just under the 90s threshold (89s idle)', async () => {
      const { ws } = await connectAndAuth('agent-1', 'host');

      const att = ws.deserializeAttachment() as Record<string, unknown>;
      att.lastMessageTime = Date.now() - 89 * 1000; // 89s ago — just under 90s
      ws.serializeAttachment(att);

      await doInstance.alarm();

      expect(ws.closed).toBe(false);
    });

    it('keeps WebSocket alive after receiving messages', async () => {
      const { ws } = await connectAndAuth('agent-1', 'host');

      // Send a message (presence heartbeat) — this should update lastMessageTime
      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'presence' })
      );

      // Verify lastMessageTime was updated to recent
      const att = ws.deserializeAttachment() as Record<string, unknown>;
      expect(att.lastMessageTime).toBeGreaterThan(Date.now() - 1000);

      // Trigger alarm
      await doInstance.alarm();

      // WebSocket should still be alive (recent message)
      expect(ws.closed).toBe(false);
    });

    it('re-schedules alarm when active connections remain', async () => {
      const { ws } = await connectAndAuth('agent-1', 'host');

      // Simulate recent activity
      const att = ws.deserializeAttachment() as Record<string, unknown>;
      att.lastMessageTime = Date.now();
      ws.serializeAttachment(att);

      // Trigger alarm
      await doInstance.alarm();

      // Alarm should be re-scheduled (since there are active connections)
      expect(mockDOState.scheduledAlarm).not.toBeNull();
      expect(mockDOState.scheduledAlarm).toBeGreaterThan(Date.now());
    });
  });

  describe('expired pairing code cleanup', () => {
    it('purges expired pairing codes during alarm', async () => {
      // Create a pairing session with a short expiry
      const code = doInstance.createPairingSession(
        'agent-1',
        'x25519-key',
        'ed-key'
      );

      // Verify the code is active before expiry
      // Note: We can't consume it because that would remove it.
      // Instead, verify it exists by creating another and checking the first still resolves.

      // Fast-forward time past the 5-minute expiry
      const realDateNow = Date.now;
      Date.now = () => realDateNow() + 6 * 60 * 1000; // 6 minutes in the future

      // Trigger alarm (which calls cleanExpiredPairings)
      await doInstance.alarm();

      // Try to consume the code — should be null (expired and cleaned)
      const session = doInstance.consumePairingSession(code);
      expect(session).toBeNull();

      Date.now = realDateNow;
    });

    it('does not purge active pairing codes during alarm', async () => {
      const code = doInstance.createPairingSession(
        'agent-1',
        'x25519-key',
        'ed-key'
      );

      // Trigger alarm (pairing code is still fresh)
      await doInstance.alarm();

      // Code should still be consumable
      const session = doInstance.consumePairingSession(code);
      expect(session).not.toBeNull();
      expect(session!.hostDeviceId).toBe('agent-1');
    });
  });

  describe('alarm scheduling', () => {
    it('schedules alarm on WebSocket upgrade via DO fetch', async () => {
      // The DO's handleWebSocketUpgrade calls scheduleAlarmIfNeeded().
      // Since WebSocketPair is not available in the test env, we test
      // alarm scheduling by directly calling the DO's /ws endpoint
      // with a rate-limited mock that allows the request but catches
      // the WebSocketPair error. Instead, verify via the alarm() path:
      // when alarm fires with active connections, it re-schedules.
      const { ws } = await connectAndAuth('agent-1', 'host');

      // Simulate recent activity
      const att = ws.deserializeAttachment() as Record<string, unknown>;
      att.lastMessageTime = Date.now();
      ws.serializeAttachment(att);

      // Reset alarm tracking
      mockDOState.scheduledAlarm = null;

      // Fire alarm — should re-schedule since there's an active connection
      await doInstance.alarm();

      expect(mockDOState.scheduledAlarm).not.toBeNull();
      expect(mockDOState.scheduledAlarm).toBeGreaterThan(Date.now());
    });

    it('does not re-schedule alarm when no active connections remain', async () => {
      // No connections added to the accepted list
      mockDOState.scheduledAlarm = null;

      await doInstance.alarm();

      // No active connections, so alarm should NOT be re-scheduled
      expect(mockDOState.scheduledAlarm).toBeNull();
    });
  });

  describe('SQLite schema verification', () => {
    it('pairings table is functional after schema initialization', () => {
      // Trigger schema initialization by registering devices
      doInstance.registerDevice('test-host', 'test-key-host', 'host');
      doInstance.registerDevice('test-mobile', 'test-key-mobile', 'mobile');

      // Create a pairing — verifies the pairings table exists and is functional
      doInstance.createPairing('test-host', 'test-mobile');
      expect(doInstance.isPaired('test-host', 'test-mobile')).toBe(true);
      expect(doInstance.getPairedMobile('test-host')).toBe('test-mobile');
    });
  });

  describe('alarm cleanup details', () => {
    it('sends host_offline to paired mobile when idle host WS is closed by alarm', async () => {
      // Pair a host and mobile
      doInstance.registerDevice('alarm-host', 'pubkey-alarm-host', 'host');
      doInstance.registerDevice('alarm-mobile', 'pubkey-alarm-mobile', 'mobile');
      doInstance.createPairing('alarm-host', 'alarm-mobile');

      const hostToken = await createJWT('alarm-host', 'host', JWT_SECRET);
      const mobileToken = await createJWT('alarm-mobile', 'mobile', JWT_SECRET);

      const hostWs = new MockWebSocket();
      const mobileWs = new MockWebSocket();

      mockDOState.acceptedWebSockets.push(hostWs as unknown as WebSocket);
      mockDOState.acceptedWebSockets.push(mobileWs as unknown as WebSocket);

      hostWs.serializeAttachment({ authenticated: false, lastMessageTime: Date.now() });
      mobileWs.serializeAttachment({ authenticated: false, lastMessageTime: Date.now() });

      await doInstance.webSocketMessage(hostWs as unknown as WebSocket, JSON.stringify({ type: 'auth', token: hostToken }));
      await doInstance.webSocketMessage(mobileWs as unknown as WebSocket, JSON.stringify({ type: 'auth', token: mobileToken }));

      // Simulate host WS idle for 6 minutes (machine went offline silently)
      const att = hostWs.deserializeAttachment() as Record<string, unknown>;
      att.lastMessageTime = Date.now() - 6 * 60 * 1000;
      hostWs.serializeAttachment(att);

      await doInstance.alarm();

      expect(hostWs.closed).toBe(true);

      // Mobile should receive exactly one host_offline
      const offlineMessages = mobileWs.messagesOfType('host_offline');
      expect(offlineMessages.length).toBe(1);
      expect(offlineMessages[0]?.['deviceId']).toBe('alarm-host');
    });

    it('stamps ts on host_offline sent by the alarm idle reap [SB-1375]', async () => {
      const now = 1_800_000_000_000;
      vi.spyOn(Date, 'now').mockReturnValue(now);
      const { ws: hostWs } = await connectAndAuth('alarm-host', 'host');
      const { ws: mobileWs } = await connectAndAuth('alarm-mobile', 'mobile');
      doInstance.createPairing('alarm-host', 'alarm-mobile');

      const att = hostWs.deserializeAttachment() as Record<string, unknown>;
      att.lastMessageTime = now - 6 * 60 * 1000;
      hostWs.serializeAttachment(att);

      vi.spyOn(Date, 'now').mockReturnValue(now + 1_000);
      await doInstance.alarm();

      const offlineMessages = mobileWs.messagesOfType('host_offline');
      expect(offlineMessages).toHaveLength(1);
      expect(offlineMessages[0]?.['ts']).toBe(now + 1_000);
    });

    it('does not send host_offline for idle mobile WS closed by alarm', async () => {
      doInstance.registerDevice('alarm-host2', 'pubkey-alarm-host2', 'host');
      doInstance.registerDevice('alarm-mobile2', 'pubkey-alarm-mobile2', 'mobile');
      doInstance.createPairing('alarm-host2', 'alarm-mobile2');

      const hostToken = await createJWT('alarm-host2', 'host', JWT_SECRET);
      const mobileToken = await createJWT('alarm-mobile2', 'mobile', JWT_SECRET);

      const hostWs = new MockWebSocket();
      const mobileWs = new MockWebSocket();

      mockDOState.acceptedWebSockets.push(hostWs as unknown as WebSocket);
      mockDOState.acceptedWebSockets.push(mobileWs as unknown as WebSocket);

      hostWs.serializeAttachment({ authenticated: false, lastMessageTime: Date.now() });
      mobileWs.serializeAttachment({ authenticated: false, lastMessageTime: Date.now() });

      await doInstance.webSocketMessage(hostWs as unknown as WebSocket, JSON.stringify({ type: 'auth', token: hostToken }));
      await doInstance.webSocketMessage(mobileWs as unknown as WebSocket, JSON.stringify({ type: 'auth', token: mobileToken }));

      // Keep host active, make mobile idle
      const mobileAtt = mobileWs.deserializeAttachment() as Record<string, unknown>;
      mobileAtt.lastMessageTime = Date.now() - 6 * 60 * 1000;
      mobileWs.serializeAttachment(mobileAtt);

      // Keep host active
      const hostAtt = hostWs.deserializeAttachment() as Record<string, unknown>;
      hostAtt.lastMessageTime = Date.now();
      hostWs.serializeAttachment(hostAtt);

      await doInstance.alarm();

      expect(mobileWs.closed).toBe(true);
      expect(hostWs.closed).toBe(false);

      // Host should NOT receive host_offline (mobile disconnected, not host)
      const offlineToHost = hostWs.messagesOfType('host_offline');
      expect(offlineToHost.length).toBe(0);
    });

    it('does not send host_offline when an idle host WS closes but other connections remain', async () => {
      doInstance.registerDevice('multi-host', 'pubkey-multi-host', 'host');
      doInstance.registerDevice('multi-mobile', 'pubkey-multi-mobile', 'mobile');
      doInstance.createPairing('multi-host', 'multi-mobile');

      const hostToken = await createJWT('multi-host', 'host', JWT_SECRET);
      const mobileToken = await createJWT('multi-mobile', 'mobile', JWT_SECRET);

      // Simulate two host connections (e.g., agent + pair CLI)
      const hostWs1 = new MockWebSocket();
      const hostWs2 = new MockWebSocket();
      const mobileWs = new MockWebSocket();

      mockDOState.acceptedWebSockets.push(hostWs1 as unknown as WebSocket);
      mockDOState.acceptedWebSockets.push(hostWs2 as unknown as WebSocket);
      mockDOState.acceptedWebSockets.push(mobileWs as unknown as WebSocket);

      hostWs1.serializeAttachment({ authenticated: false, lastMessageTime: Date.now() });
      hostWs2.serializeAttachment({ authenticated: false, lastMessageTime: Date.now() });
      mobileWs.serializeAttachment({ authenticated: false, lastMessageTime: Date.now() });

      // Authenticate both host connections (two JWTs for same device)
      const hostToken2 = await createJWT('multi-host', 'host', JWT_SECRET);
      await doInstance.webSocketMessage(hostWs1 as unknown as WebSocket, JSON.stringify({ type: 'auth', token: hostToken }));
      await doInstance.webSocketMessage(hostWs2 as unknown as WebSocket, JSON.stringify({ type: 'auth', token: hostToken2 }));
      await doInstance.webSocketMessage(mobileWs as unknown as WebSocket, JSON.stringify({ type: 'auth', token: mobileToken }));

      expect(doInstance.getWsConnectionCount('multi-host')).toBe(2);

      // Let one host connection go idle
      const att1 = hostWs1.deserializeAttachment() as Record<string, unknown>;
      att1.lastMessageTime = Date.now() - 6 * 60 * 1000;
      hostWs1.serializeAttachment(att1);

      await doInstance.alarm();

      expect(hostWs1.closed).toBe(true);
      expect(hostWs2.closed).toBe(false);
      expect(doInstance.getWsConnectionCount('multi-host')).toBe(1);

      // Mobile should NOT receive host_offline — one connection is still active
      const offlineMessages = mobileWs.messagesOfType('host_offline');
      expect(offlineMessages.length).toBe(0);
    });

    it('does not send host_offline for an unpaired host closed by alarm', async () => {
      // Register a host with no pairing
      doInstance.registerDevice('unpaired-host', 'pubkey-unpaired-host', 'host');
      const hostToken = await createJWT('unpaired-host', 'host', JWT_SECRET);

      const hostWs = new MockWebSocket();
      mockDOState.acceptedWebSockets.push(hostWs as unknown as WebSocket);
      hostWs.serializeAttachment({ authenticated: false, lastMessageTime: Date.now() });

      await doInstance.webSocketMessage(hostWs as unknown as WebSocket, JSON.stringify({ type: 'auth', token: hostToken }));

      // Make it idle
      const att = hostWs.deserializeAttachment() as Record<string, unknown>;
      att.lastMessageTime = Date.now() - 6 * 60 * 1000;
      hostWs.serializeAttachment(att);

      // Should not throw even though there is no paired mobile
      await expect(doInstance.alarm()).resolves.toBeUndefined();
      expect(hostWs.closed).toBe(true);
    });

    it('removes idle authenticated WS from connection cache and decrements count', async () => {
      const { ws } = await connectAndAuth('agent-1', 'host');

      // Verify connection is tracked
      expect(doInstance.getConnection('agent-1')).toBeDefined();
      expect(doInstance.getWsConnectionCount('agent-1')).toBe(1);

      // Simulate idle for 6 minutes
      const att = ws.deserializeAttachment() as Record<string, unknown>;
      att.lastMessageTime = Date.now() - 6 * 60 * 1000;
      ws.serializeAttachment(att);

      await doInstance.alarm();

      expect(ws.closed).toBe(true);
      expect(ws.closeCode).toBe(1000);
      expect(ws.closeReason).toBe('idle timeout');
      // WS connection count should be decremented
      expect(doInstance.getWsConnectionCount('agent-1')).toBe(0);

      // Remove the closed WS from accepted list (simulates runtime cleanup)
      const idx = mockDOState.acceptedWebSockets.indexOf(ws as unknown as WebSocket);
      if (idx >= 0) mockDOState.acceptedWebSockets.splice(idx, 1);

      // After runtime cleanup, connection should not be findable
      expect(doInstance.getConnection('agent-1')).toBeUndefined();
    });

    it('handles WebSocket with no attachment gracefully during alarm', async () => {
      // Add a WS with null/no attachment to the accepted list
      const ws = new MockWebSocket();
      mockDOState.acceptedWebSockets.push(ws as unknown as WebSocket);

      // Should not throw
      await doInstance.alarm();

      // WS without attachment should not be closed (no lastMessageTime to compare)
      expect(ws.closed).toBe(false);
    });
  });

  // A sleeping host's overdue heartbeat can land on a socket the alarm already
  // closed (macOS DarkWake). That socket must stay dead [SB-1393].
  describe('sockets the DO closed stay closed [SB-1393]', () => {
    const asWs = (ws: MockWebSocket): WebSocket => ws as unknown as WebSocket;
    const presence = JSON.stringify({ type: 'presence' });
    const connectRequest = JSON.stringify({ type: 'connect_request', targetDeviceId: 'sleepy-host' });

    function backdate(ws: MockWebSocket): void {
      const att = ws.deserializeAttachment() as Record<string, unknown>;
      att.lastMessageTime = Date.now() - 6 * 60 * 1000;
      ws.serializeAttachment(att);
    }

    /** Pair a host and mobile, then let the alarm reap the idle host socket. */
    async function reapPairedHost(): Promise<{ hostWs: MockWebSocket; mobileWs: MockWebSocket }> {
      const { ws: hostWs } = await connectAndAuth('sleepy-host', 'host');
      const { ws: mobileWs } = await connectAndAuth('sleepy-mobile', 'mobile');
      doInstance.createPairing('sleepy-host', 'sleepy-mobile');
      backdate(hostWs);
      await doInstance.alarm();
      expect(hostWs.closed).toBe(true);
      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(1);
      hostWs.sent = [];
      mobileWs.sent = [];
      return { hostWs, mobileWs };
    }

    it('ignores a late presence frame: no host_online, no touch, no reply', async () => {
      const { hostWs, mobileWs } = await reapPairedHost();
      const before = (hostWs.deserializeAttachment() as Record<string, unknown>)['lastMessageTime'];

      await doInstance.webSocketMessage(asWs(hostWs), presence);

      expect(mobileWs.messagesOfType('host_online')).toHaveLength(0);
      expect(hostWs.sent).toHaveLength(0);
      expect((hostWs.deserializeAttachment() as Record<string, unknown>)['lastMessageTime']).toBe(before);
    });

    it('does not throw when the closed socket refuses sends', async () => {
      const { hostWs } = await reapPairedHost();
      hostWs.send = () => {
        throw new TypeError("Can't call WebSocket send() after close().");
      };

      await expect(doInstance.webSocketMessage(asWs(hostWs), presence)).resolves.toBeUndefined();
    });

    it('keeps the host offline for the auth snapshot and connect_request after a late frame', async () => {
      const { hostWs } = await reapPairedHost();
      await doInstance.webSocketMessage(asWs(hostWs), presence);
      // Like the runtime: relaying into the closed socket would throw → peer_unavailable
      hostWs.send = () => {
        throw new TypeError("Can't call WebSocket send() after close().");
      };

      const { ws: mobileWs } = await connectAndAuth('sleepy-mobile', 'mobile');
      expect(mobileWs.messagesOfType('host_online')).toHaveLength(0);

      await doInstance.webSocketMessage(asWs(mobileWs), connectRequest);
      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(1);
      expect(mobileWs.messagesOfType('peer_unavailable')).toHaveLength(0);
    });

    it('keeps an alarm-closed socket dead when it reports OPEN again (hibernation rehydrate)', async () => {
      const { hostWs, mobileWs } = await reapPairedHost();
      // Only the attachment flag survives hibernation; readyState may read OPEN
      hostWs.readyState = 1;

      await doInstance.webSocketMessage(asWs(hostWs), presence);
      await doInstance.webSocketMessage(asWs(mobileWs), connectRequest);

      expect(mobileWs.messagesOfType('host_online')).toHaveLength(0);
      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(1);
      expect(hostWs.messagesOfType('connect_request')).toHaveLength(0);
    });

    it('does not route to a CLOSING socket the DO did not flag', async () => {
      const { ws: hostWs } = await connectAndAuth('sleepy-host', 'host');
      const { ws: mobileWs } = await connectAndAuth('sleepy-mobile', 'mobile');
      doInstance.createPairing('sleepy-host', 'sleepy-mobile');
      hostWs.readyState = 2;

      await doInstance.webSocketMessage(asWs(mobileWs), connectRequest);

      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(1);
      expect(hostWs.messagesOfType('connect_request')).toHaveLength(0);
    });

    it('routes to the live socket when the cache holds an alarm-closed one', async () => {
      const { hostWs, mobileWs } = await reapPairedHost();
      const { ws: liveWs } = await connectAndAuth('sleepy-host', 'host');
      await doInstance.webSocketMessage(asWs(hostWs), presence);
      doInstance.setConnection('sleepy-host', asWs(hostWs));

      await doInstance.webSocketMessage(asWs(mobileWs), connectRequest);

      expect(liveWs.messagesOfType('connect_request')).toHaveLength(1);
      expect(hostWs.messagesOfType('connect_request')).toHaveLength(0);
      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(0);
    });

    it('sends host_offline when the last live socket closes beside an alarm-closed one', async () => {
      const { mobileWs } = await reapPairedHost();
      const { ws: liveWs } = await connectAndAuth('sleepy-host', 'host');
      mobileWs.sent = [];

      liveWs.close(1000, 'bye');
      await doInstance.webSocketClose(asWs(liveWs), 1000, 'bye', true);

      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(1);
    });

    it('does not reprocess an alarm-closed socket on later sweeps', async () => {
      const { hostWs, mobileWs } = await reapPairedHost();
      const closeSpy = vi.spyOn(hostWs, 'close');

      await doInstance.alarm();

      expect(closeSpy).not.toHaveBeenCalled();
      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(0);
    });

    it('sends exactly one host_offline when two idle host sockets are reaped in one sweep', async () => {
      const { ws: a } = await connectAndAuth('sleepy-host', 'host');
      const { ws: b } = await connectAndAuth('sleepy-host', 'host');
      const { ws: mobileWs } = await connectAndAuth('sleepy-mobile', 'mobile');
      doInstance.createPairing('sleepy-host', 'sleepy-mobile');
      backdate(a);
      backdate(b);

      await doInstance.alarm();

      expect(a.closed).toBe(true);
      expect(b.closed).toBe(true);
      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(1);
    });

    it('treats the runtime close event after an alarm reap as already handled', async () => {
      const { hostWs, mobileWs } = await reapPairedHost();

      await doInstance.webSocketClose(asWs(hostWs), 1000, 'idle timeout', true);

      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(0);
    });

    it('treats a runtime error event after an alarm reap as already handled', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      const { hostWs, mobileWs } = await reapPairedHost();

      await doInstance.webSocketError(asWs(hostWs), new Error('reset'));

      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(0);
    });

    it.each(['close', 'error'] as const)(
      'does not decrement the WS count twice when %s follows an alarm reap',
      async (event) => {
        vi.spyOn(console, 'error').mockImplementation(() => {});
        const { ws: reaped } = await connectAndAuth('sleepy-host', 'host');
        await connectAndAuth('sleepy-host', 'host');
        backdate(reaped);
        await doInstance.alarm();
        expect(doInstance.getWsConnectionCount('sleepy-host')).toBe(1);

        if (event === 'close') {
          await doInstance.webSocketClose(asWs(reaped), 1000, 'idle timeout', true);
        } else {
          await doInstance.webSocketError(asWs(reaped), new Error('reset'));
        }

        expect(doInstance.getWsConnectionCount('sleepy-host')).toBe(1);
      }
    );

    it('rebuilds the connection cache and counts without the alarm-closed socket', async () => {
      await reapPairedHost();
      const { ws: liveWs } = await connectAndAuth('sleepy-host', 'host');
      doInstance.removeConnection('sleepy-host');
      doInstance.clearWsConnectionCounts();

      expect(doInstance.getConnection('sleepy-host')).toBe(liveWs);
      expect(doInstance.getWsConnectionCount('sleepy-host')).toBe(1);
    });

    it('does not re-authenticate a socket that was closed while its JWT was verifying', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      const { ws: hostWs, token } = await connectAndAuth('sleepy-host', 'host');
      const auth = doInstance.webSocketMessage(asWs(hostWs), JSON.stringify({ type: 'auth', token }));
      await doInstance.webSocketError(asWs(hostWs), new Error('reset'));
      await auth;

      expect((hostWs.deserializeAttachment() as Record<string, unknown>)['closed']).toBe(true);
      expect(doInstance.getWsConnectionCount('sleepy-host')).toBe(0);
    });

    it('stops routing to a socket after webSocketError', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      const { ws: hostWs } = await connectAndAuth('sleepy-host', 'host');
      const { ws: mobileWs } = await connectAndAuth('sleepy-mobile', 'mobile');
      doInstance.createPairing('sleepy-host', 'sleepy-mobile');

      await doInstance.webSocketError(asWs(hostWs), new Error('reset'));
      mobileWs.sent = [];
      await doInstance.webSocketMessage(asWs(mobileWs), connectRequest);

      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(1);
      expect(hostWs.messagesOfType('connect_request')).toHaveLength(0);
    });
  });
});

// The socket caches are rebuilt from getWebSockets() once per wake; every later
// lookup reads the per-device socket sets instead of rescanning.
describe('socket cache rebuilt once per wake', () => {
  const asWs = (ws: MockWebSocket): WebSocket => ws as unknown as WebSocket;
  const connectRequest = (target: string): string =>
    JSON.stringify({ type: 'connect_request', targetDeviceId: target });

  /** Spy on the DO's getWebSockets(), then force (and prove) the one rebuild. */
  function spyAfterRebuild(): ReturnType<typeof vi.spyOn> {
    const scans = vi.spyOn(mockDOState, 'getWebSockets');
    doInstance.getConnection('nobody');
    expect(scans).toHaveBeenCalledTimes(1);
    scans.mockClear();
    return scans;
  }

  it('does not rescan for a connect_request to an offline host', async () => {
    doInstance.registerDevice('off-host', 'pubkey-off-host', 'host');
    const scans = spyAfterRebuild();
    const { ws: mobileWs } = await connectAndAuth('eff-mobile', 'mobile');
    doInstance.createPairing('off-host', 'eff-mobile');

    await doInstance.webSocketMessage(asWs(mobileWs), connectRequest('off-host'));

    expect(mobileWs.messagesOfType('host_offline')).toHaveLength(1);
    expect(scans).not.toHaveBeenCalled();
  });

  it('does not rescan when a mobile with offline paired hosts authenticates', async () => {
    const token = await setupDevice('eff-mobile', 'mobile');
    for (let i = 0; i < 10; i++) {
      doInstance.registerDevice(`off-host-${i}`, `pubkey-off-host-${i}`, 'host');
      doInstance.createPairing(`off-host-${i}`, 'eff-mobile');
    }
    const scans = spyAfterRebuild();
    const mobileWs = new MockWebSocket();
    mockDOState.acceptedWebSockets.push(asWs(mobileWs));

    await doInstance.webSocketMessage(asWs(mobileWs), JSON.stringify({ type: 'auth', token }));

    expect(mobileWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
    expect(mobileWs.messagesOfType('host_online')).toHaveLength(0);
    expect(scans).not.toHaveBeenCalled();
  });

  it('does not rescan for an ice_candidate relayed to a departed peer', async () => {
    const scans = spyAfterRebuild();
    const { ws: hostWs } = await connectAndAuth('eff-host', 'host');
    const { ws: mobileWs } = await connectAndAuth('eff-mobile', 'mobile');
    doInstance.createPairing('eff-host', 'eff-mobile');
    mockDOState.acceptedWebSockets.splice(mockDOState.acceptedWebSockets.indexOf(asWs(mobileWs)), 1);
    await doInstance.webSocketClose(asWs(mobileWs), 1000, 'bye', true);

    await doInstance.webSocketMessage(
      asWs(hostWs),
      JSON.stringify({ type: 'ice_candidate', candidate: 'candidate:1', targetDeviceId: 'eff-mobile' })
    );

    expect(hostWs.messagesOfType('peer_unavailable')).toHaveLength(1);
    expect(scans).not.toHaveBeenCalled();
  });

  it('scans once in total when 500 sockets authenticate after a wake', async () => {
    const tokens: string[] = [];
    for (let d = 0; d < 100; d++) tokens.push(await setupDevice(`load-host-${d}`, 'host'));
    doInstance.clearWsConnectionCounts();
    const scans = vi.spyOn(mockDOState, 'getWebSockets');

    const sockets: MockWebSocket[] = [];
    for (let i = 0; i < 500; i++) {
      const ws = new MockWebSocket();
      sockets.push(ws);
      mockDOState.acceptedWebSockets.push(asWs(ws));
      await doInstance.webSocketMessage(asWs(ws), JSON.stringify({ type: 'auth', token: tokens[i % 100]! }));
    }

    expect(scans).toHaveBeenCalledTimes(1);
    expect(sockets.every((ws) => ws.messagesOfType('auth').length === 1 && !ws.closed)).toBe(true);
    expect(doInstance.getWsConnectionCount('load-host-0')).toBe(5);
  });

  it('enforces the per-device cap after a wake', async () => {
    for (let i = 0; i < 5; i++) await connectAndAuth('cap-host', 'host');
    doInstance.clearWsConnectionCounts();
    const scans = vi.spyOn(mockDOState, 'getWebSockets');

    const { ws: sixth } = await connectAndAuth('cap-host', 'host');

    expect(sixth.closeCode).toBe(1008);
    expect(doInstance.getWsConnectionCount('cap-host')).toBe(5);
    expect(scans).toHaveBeenCalledTimes(1);
  });

  it('keeps a sibling socket routable after the cached socket closes', async () => {
    const scans = spyAfterRebuild();
    const { ws: olderWs } = await connectAndAuth('eff-host', 'host');
    const { ws: cachedWs } = await connectAndAuth('eff-host', 'host');
    const { ws: mobileWs } = await connectAndAuth('eff-mobile', 'mobile');
    doInstance.createPairing('eff-host', 'eff-mobile');
    mockDOState.acceptedWebSockets.splice(mockDOState.acceptedWebSockets.indexOf(asWs(cachedWs)), 1);
    await doInstance.webSocketClose(asWs(cachedWs), 1000, 'bye', true);
    mobileWs.sent = [];

    await doInstance.webSocketMessage(asWs(mobileWs), connectRequest('eff-host'));

    expect(olderWs.messagesOfType('connect_request')).toHaveLength(1);
    expect(mobileWs.messagesOfType('host_offline')).toHaveLength(0);
    expect(doInstance.getConnection('eff-host')).toBe(olderWs);
    expect(scans).not.toHaveBeenCalled();
  });

  it('notifies every socket of a multi-socket device after a wake', async () => {
    const { ws: agentWs } = await connectAndAuth('eff-host', 'host');
    const { ws: cliWs } = await connectAndAuth('eff-host', 'host');
    const token = await setupDevice('eff-mobile', 'mobile');
    doInstance.createPairing('eff-host', 'eff-mobile');
    doInstance.clearWsConnectionCounts();
    const mobileWs = new MockWebSocket();
    mockDOState.acceptedWebSockets.push(asWs(mobileWs));

    await doInstance.webSocketMessage(asWs(mobileWs), JSON.stringify({ type: 'auth', token, name: 'Renamed Phone' }));

    for (const ws of [agentWs, cliWs]) {
      expect(ws.messagesOfType('mobile_name_updated')).toEqual([
        { type: 'mobile_name_updated', deviceId: 'eff-mobile', name: 'Renamed Phone' },
      ]);
    }
  });

  it.each(['close', 'error'] as const)(
    'does not route to a socket whose %s is the first event after a wake',
    async (event) => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      const { ws: olderWs } = await connectAndAuth('eff-host', 'host');
      const { ws: gone } = await connectAndAuth('eff-host', 'host');
      const { ws: mobileWs } = await connectAndAuth('eff-mobile', 'mobile');
      doInstance.createPairing('eff-host', 'eff-mobile');
      // A real wake also empties the 1:1 cache
      doInstance.removeConnection('eff-host');
      doInstance.removeConnection('eff-mobile');
      doInstance.clearWsConnectionCounts();
      const scans = vi.spyOn(mockDOState, 'getWebSockets');

      if (event === 'close') {
        await doInstance.webSocketClose(asWs(gone), 1000, 'bye', true);
      } else {
        await doInstance.webSocketError(asWs(gone), new Error('reset'));
      }
      mobileWs.sent = [];
      await doInstance.webSocketMessage(asWs(mobileWs), connectRequest('eff-host'));

      expect(gone.messagesOfType('connect_request')).toHaveLength(0);
      expect(olderWs.messagesOfType('connect_request')).toHaveLength(1);
      expect(doInstance.getConnection('eff-host')).toBe(olderWs);
      expect(doInstance.getWsConnectionCount('eff-host')).toBe(1);
      expect(scans).toHaveBeenCalledTimes(1);
    }
  );

  // The runtime reports the socket as CLOSED by the time webSocketClose runs
  // (auto-reply to close), so the wake rebuild already leaves it out
  it.each(['close', 'error'] as const)(
    'keeps the sibling counted when an already-closed socket\'s %s is the first event after a wake',
    async (event) => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      const { ws: olderWs } = await connectAndAuth('eff-host', 'host');
      const { ws: gone } = await connectAndAuth('eff-host', 'host');
      const { ws: mobileWs } = await connectAndAuth('eff-mobile', 'mobile');
      doInstance.createPairing('eff-host', 'eff-mobile');
      doInstance.removeConnection('eff-host');
      doInstance.clearWsConnectionCounts();
      gone.readyState = 3;

      if (event === 'close') {
        await doInstance.webSocketClose(asWs(gone), 1000, 'bye', true);
      } else {
        await doInstance.webSocketError(asWs(gone), new Error('reset'));
      }

      expect(doInstance.getWsConnectionCount('eff-host')).toBe(1);
      expect(doInstance.getConnection('eff-host')).toBe(olderWs);
      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(0);
    }
  );
});

describe('Worker root redirect', () => {
  it('returns 308 redirect to https://pmux.io for GET /', async () => {
    const worker = (await import('../worker')).default;

    const mockEnv = {
      SIGNALING: {} as DurableObjectNamespace,
      TURN_TOKEN_ID: '',
      TURN_API_TOKEN: '',
      JWT_SECRET: JWT_SECRET,
    };

    const request = new Request('http://localhost/');
    const response = await worker.fetch(request, mockEnv);

    expect(response.status).toBe(308);
    expect(response.headers.get('Location')).toBe('https://pmux.io');
  });

  it('root redirect includes correlation headers', async () => {
    const worker = (await import('../worker')).default;

    const mockEnv = {
      SIGNALING: {} as DurableObjectNamespace,
      TURN_TOKEN_ID: '',
      TURN_API_TOKEN: '',
      JWT_SECRET: JWT_SECRET,
    };

    const request = new Request('http://localhost/');
    const response = await worker.fetch(request, mockEnv);

    expect(response.headers.get('X-Request-Id')).toBeTruthy();
    expect(response.headers.get('X-Response-Time')).toBeTruthy();
  });
});

describe('Health endpoint [T3.10]', () => {
  it('returns JSON with status, version, and timestamp', async () => {
    // Import the worker handler
    const worker = (await import('../worker')).default;

    const mockEnv = {
      SIGNALING: {} as DurableObjectNamespace,
      TURN_TOKEN_ID: '',
      TURN_API_TOKEN: '',
      JWT_SECRET: JWT_SECRET,
    };

    const request = new Request('http://localhost/health');
    const response = await worker.fetch(request, mockEnv);

    expect(response.status).toBe(200);

    const body = await response.json() as Record<string, unknown>;
    expect(body.status).toBe('ok');
    expect(body.version).toBe(version);
    expect(typeof body.timestamp).toBe('number');
    expect(body.timestamp).toBeGreaterThan(0);
  });

  it('includes Content-Type application/json header', async () => {
    const worker = (await import('../worker')).default;

    const mockEnv = {
      SIGNALING: {} as DurableObjectNamespace,
      TURN_TOKEN_ID: '',
      TURN_API_TOKEN: '',
      JWT_SECRET: JWT_SECRET,
    };

    const request = new Request('http://localhost/health');
    const response = await worker.fetch(request, mockEnv);

    expect(response.headers.get('Content-Type')).toBe('application/json');
  });
});

describe('Correlation IDs and response timing [T3.10]', () => {
  it('health response includes X-Request-Id header', async () => {
    const worker = (await import('../worker')).default;

    const mockEnv = {
      SIGNALING: {} as DurableObjectNamespace,
      TURN_TOKEN_ID: '',
      TURN_API_TOKEN: '',
      JWT_SECRET: JWT_SECRET,
    };

    const request = new Request('http://localhost/health');
    const response = await worker.fetch(request, mockEnv);

    const requestId = response.headers.get('X-Request-Id');
    expect(requestId).toBeTruthy();
    // Should be a valid UUID format
    expect(requestId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    );
  });

  it('health response includes X-Response-Time header', async () => {
    const worker = (await import('../worker')).default;

    const mockEnv = {
      SIGNALING: {} as DurableObjectNamespace,
      TURN_TOKEN_ID: '',
      TURN_API_TOKEN: '',
      JWT_SECRET: JWT_SECRET,
    };

    const request = new Request('http://localhost/health');
    const response = await worker.fetch(request, mockEnv);

    const responseTime = response.headers.get('X-Response-Time');
    expect(responseTime).toBeTruthy();
    // Should match pattern like "0ms", "42ms", etc.
    expect(responseTime).toMatch(/^\d+ms$/);
  });

  it('404 response includes correlation headers and requestId in body', async () => {
    const worker = (await import('../worker')).default;

    const mockEnv = {
      SIGNALING: {} as DurableObjectNamespace,
      TURN_TOKEN_ID: '',
      TURN_API_TOKEN: '',
      JWT_SECRET: JWT_SECRET,
    };

    // Non-public routes require auth. Provide a valid JWT so the request
    // passes auth middleware and falls through to the 404 handler.
    const token = await createJWT('device-1', 'host', JWT_SECRET);
    const request = new Request('http://localhost/nonexistent', {
      headers: new Headers({ Authorization: `Bearer ${token}` }),
    });
    const response = await worker.fetch(request, mockEnv);

    expect(response.status).toBe(404);

    // Should have correlation headers
    expect(response.headers.get('X-Request-Id')).toBeTruthy();
    expect(response.headers.get('X-Response-Time')).toBeTruthy();

    // Body should include requestId
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe('Not Found');
    expect(body.requestId).toBeTruthy();
    expect(body.requestId).toBe(response.headers.get('X-Request-Id'));
  });

  it('401 error response includes requestId in body', async () => {
    const worker = (await import('../worker')).default;

    const mockEnv = {
      SIGNALING: {} as DurableObjectNamespace,
      TURN_TOKEN_ID: '',
      TURN_API_TOKEN: '',
      JWT_SECRET: JWT_SECRET,
    };

    // /turn/credentials requires auth — request without Authorization header
    const request = new Request('http://localhost/turn/credentials');
    const response = await worker.fetch(request, mockEnv);

    expect(response.status).toBe(401);

    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBeTruthy();
    expect(body.requestId).toBeTruthy();
    expect(body.requestId).toBe(response.headers.get('X-Request-Id'));
  });

  it('each request gets a unique X-Request-Id', async () => {
    const worker = (await import('../worker')).default;

    const mockEnv = {
      SIGNALING: {} as DurableObjectNamespace,
      TURN_TOKEN_ID: '',
      TURN_API_TOKEN: '',
      JWT_SECRET: JWT_SECRET,
    };

    const response1 = await worker.fetch(
      new Request('http://localhost/health'),
      mockEnv
    );
    const response2 = await worker.fetch(
      new Request('http://localhost/health'),
      mockEnv
    );

    const id1 = response1.headers.get('X-Request-Id');
    const id2 = response2.headers.get('X-Request-Id');

    expect(id1).not.toBe(id2);
  });
});
