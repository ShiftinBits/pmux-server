import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDOCompat as createTestDOCompat, createTestDO, type MockDOState } from './helpers/mock-do';
import { MockWebSocket } from './helpers/mock-websocket';
import { createJWT } from '../auth';
import type { SignalingDO } from '../signaling';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

let doInstance: SignalingDO;
let mockState: MockDOState;

beforeEach(async () => {
  const result = await createTestDO();
  doInstance = result.doInstance;
  mockState = result.mockState;
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

  // Simulate Hibernation API: DO accepts the WebSocket (must be in acceptedWebSockets
  // for notifyDevice/notifyPairedMobile to find it via state.getWebSockets())
  mockState.acceptedWebSockets.push(ws as unknown as WebSocket);
  doInstance.setConnection(deviceId, ws as unknown as WebSocket);

  // Authenticate
  await doInstance.webSocketMessage(
    ws as unknown as WebSocket,
    JSON.stringify({ type: 'auth', token })
  );

  return { ws, token };
}

describe('WebSocket signaling [T1.8]', () => {
  describe('authentication', () => {
    it('accepts valid JWT and responds with auth ok', async () => {
      const token = await setupDevice('agent-1', 'host');
      const ws = new MockWebSocket();

      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token })
      );

      expect(ws.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      expect(ws.closed).toBe(false);
    });

    it('rejects invalid JWT and closes connection', async () => {
      const ws = new MockWebSocket();

      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: 'invalid-token' })
      );

      expect(ws.lastMessage()).toEqual({ type: 'error', error: 'Authentication failed' });
      expect(ws.closed).toBe(true);
      expect(ws.closeCode).toBe(4001);
    });

    it('rejects non-auth messages before authentication', async () => {
      const ws = new MockWebSocket();
      ws.serializeAttachment({ authenticated: false });

      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'presence' })
      );

      expect(ws.lastMessage()).toEqual({ type: 'error', error: 'Not authenticated' });
    });

    it('rejects invalid JSON', async () => {
      const ws = new MockWebSocket();

      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        'not-json'
      );

      expect(ws.lastMessage()).toEqual({ type: 'error', error: 'Invalid JSON' });
    });
  });

  describe('presence', () => {
    it('accepts presence heartbeat from authenticated agent', async () => {
      const { ws } = await connectAndAuth('agent-1', 'host');
      const beforeCount = ws.sent.length;

      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'presence' })
      );

      // Presence is silently acknowledged — no response sent
      expect(ws.sent.length).toBe(beforeCount);
    });
  });

  describe('host_online / host_offline', () => {
    it('emits host_online to paired mobile when host authenticates', async () => {
      // Register host, mobile, and create pairing
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      const agentToken = await setupDevice('agent-1', 'host');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear messages from mobile auth
      mobileWs.sent.length = 0;

      // Now agent authenticates
      const hostWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken })
      );

      // Mobile should receive host_online
      const onlineMessages = mobileWs.messagesOfType('host_online');
      expect(onlineMessages).toHaveLength(1);
      expect(onlineMessages[0]!['deviceId']).toBe('agent-1');
    });

    it('includes name in host_online when host has a name', async () => {
      // Register host with a name
      doInstance.registerDevice('agent-1', 'pubkey-agent-1', 'host', 'my-workstation');
      const agentToken = await createJWT('agent-1', 'host', JWT_SECRET);

      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');
      mobileWs.sent.length = 0;

      // Host authenticates
      const hostWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken })
      );

      // Mobile should receive host_online with name
      const onlineMessages = mobileWs.messagesOfType('host_online');
      expect(onlineMessages).toHaveLength(1);
      expect(onlineMessages[0]!['deviceId']).toBe('agent-1');
      expect(onlineMessages[0]!['name']).toBe('my-workstation');
    });

    it('omits name from host_online when host has no name', async () => {
      // Register host without a name
      const agentToken = await setupDevice('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');
      mobileWs.sent.length = 0;

      // Host authenticates
      const hostWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken })
      );

      // Mobile should receive host_online without name
      const onlineMessages = mobileWs.messagesOfType('host_online');
      expect(onlineMessages).toHaveLength(1);
      expect(onlineMessages[0]!['deviceId']).toBe('agent-1');
      expect(onlineMessages[0]!['name']).toBeUndefined();
    });

    it('includes name in presence snapshot when mobile authenticates', async () => {
      // Register host with a name and connect it
      doInstance.registerDevice('agent-1', 'pubkey-agent-1', 'host', 'dev-server');
      const agentToken = await createJWT('agent-1', 'host', JWT_SECRET);

      // Connect and auth the host — must also add to acceptedWebSockets
      // so state.getWebSockets() returns it during presence snapshot scan
      const hostWs = new MockWebSocket();
      mockState.acceptedWebSockets.push(hostWs as unknown as WebSocket);
      doInstance.setConnection('agent-1', hostWs as unknown as WebSocket);
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken })
      );

      // Register mobile and create pairing BEFORE mobile connects
      doInstance.registerDevice('mobile-1', 'pubkey-mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Now mobile connects ��� should get presence snapshot with name
      const mobileToken = await createJWT('mobile-1', 'mobile', JWT_SECRET);
      const mobileWs = new MockWebSocket();
      doInstance.setConnection('mobile-1', mobileWs as unknown as WebSocket);
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: mobileToken })
      );

      const onlineMessages = mobileWs.messagesOfType('host_online');
      expect(onlineMessages).toHaveLength(1);
      expect(onlineMessages[0]!['deviceId']).toBe('agent-1');
      expect(onlineMessages[0]!['name']).toBe('dev-server');
    });

    it('emits host_offline to paired mobile when host disconnects', async () => {
      // Set up host and mobile with pairing
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear prior messages
      mobileWs.sent.length = 0;

      // Agent disconnects
      await doInstance.webSocketClose(
        hostWs as unknown as WebSocket,
        1000,
        'normal closure',
        true
      );

      // Mobile should receive host_offline
      const offlineMessages = mobileWs.messagesOfType('host_offline');
      expect(offlineMessages).toHaveLength(1);
      expect(offlineMessages[0]!['deviceId']).toBe('agent-1');
    });

    it('does not emit host_offline when mobile disconnects', async () => {
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear prior messages
      hostWs.sent.length = 0;

      // Mobile disconnects
      await doInstance.webSocketClose(
        mobileWs as unknown as WebSocket,
        1000,
        'normal closure',
        true
      );

      // Agent should NOT receive host_offline
      const offlineMessages = hostWs.messagesOfType('host_offline');
      expect(offlineMessages).toHaveLength(0);
    });
  });

  describe('connect_request relay', () => {
    it('relays connect_request from mobile to agent when paired', async () => {
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear prior messages
      hostWs.sent.length = 0;

      // Mobile sends connect_request to agent
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-1' })
      );

      // Agent should receive connect_request with mobile's deviceId
      const requests = hostWs.messagesOfType('connect_request');
      expect(requests).toHaveLength(1);
      expect(requests[0]!['targetDeviceId']).toBe('mobile-1');
    });

    it('returns error when target device is not connected', async () => {
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');

      // Clear auth messages
      mobileWs.sent.length = 0;

      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'nonexistent-agent' })
      );

      const errors = mobileWs.messagesOfType('error');
      expect(errors).toHaveLength(1);
      expect(errors[0]!['error']).toContain('not connected');
    });
  });

  describe('SDP/ICE relay', () => {
    it('relays sdp_offer from agent to mobile when paired', async () => {
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear prior messages
      mobileWs.sent.length = 0;

      // Agent sends SDP offer to mobile
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_offer',
          sdp: 'v=0\r\no=- 12345 IN IP4 127.0.0.1\r\n...',
          targetDeviceId: 'mobile-1',
        })
      );

      // Mobile should receive offer with agent's deviceId
      const offers = mobileWs.messagesOfType('sdp_offer');
      expect(offers).toHaveLength(1);
      expect(offers[0]!['sdp']).toContain('v=0');
      expect(offers[0]!['targetDeviceId']).toBe('agent-1');
    });

    it('relays sdp_answer from mobile to agent when paired', async () => {
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear prior messages
      hostWs.sent.length = 0;

      // Mobile sends SDP answer to agent
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_answer',
          sdp: 'v=0\r\no=- 67890 IN IP4 127.0.0.1\r\n...',
          targetDeviceId: 'agent-1',
        })
      );

      // Agent should receive answer with mobile's deviceId
      const answers = hostWs.messagesOfType('sdp_answer');
      expect(answers).toHaveLength(1);
      expect(answers[0]!['sdp']).toContain('v=0');
      expect(answers[0]!['targetDeviceId']).toBe('mobile-1');
    });

    it('relays ice_candidate bidirectionally when paired', async () => {
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear prior messages
      hostWs.sent.length = 0;
      mobileWs.sent.length = 0;

      // Agent sends ICE candidate to mobile
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'ice_candidate',
          candidate: 'candidate:1 1 udp 2130706431 192.168.1.1 12345 typ host',
          targetDeviceId: 'mobile-1',
        })
      );

      // Mobile sends ICE candidate to agent
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({
          type: 'ice_candidate',
          candidate: 'candidate:2 1 udp 2130706431 10.0.0.1 54321 typ host',
          targetDeviceId: 'agent-1',
        })
      );

      // Check mobile received agent's candidate
      const mobileCandidates = mobileWs.messagesOfType('ice_candidate');
      expect(mobileCandidates).toHaveLength(1);
      expect(mobileCandidates[0]!['candidate']).toContain('192.168.1.1');
      expect(mobileCandidates[0]!['targetDeviceId']).toBe('agent-1');

      // Check agent received mobile's candidate
      const hostCandidates = hostWs.messagesOfType('ice_candidate');
      expect(hostCandidates).toHaveLength(1);
      expect(hostCandidates[0]!['candidate']).toContain('10.0.0.1');
      expect(hostCandidates[0]!['targetDeviceId']).toBe('mobile-1');
    });

    it('silently drops relay to disconnected target', async () => {
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');

      // Agent sends SDP offer to a mobile that never connected
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_offer',
          sdp: 'v=0\r\n...',
          targetDeviceId: 'disconnected-mobile',
        })
      );

      // Should not crash — message is silently dropped
      // No error sent back for SDP/ICE relay (only connect_request gets error)
    });
  });

  describe('full signaling flow', () => {
    it('agent and mobile exchange SDP/ICE through the DO', async () => {
      // 1. Register devices and create pairing
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear auth messages
      hostWs.sent.length = 0;
      mobileWs.sent.length = 0;

      // 2. Mobile sends connect_request
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-1' })
      );

      // Agent receives connect_request
      expect(hostWs.messagesOfType('connect_request')).toHaveLength(1);

      // 3. Agent sends SDP offer
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_offer',
          sdp: 'offer-sdp',
          targetDeviceId: 'mobile-1',
        })
      );

      // Mobile receives SDP offer
      const offers = mobileWs.messagesOfType('sdp_offer');
      expect(offers).toHaveLength(1);
      expect(offers[0]!['targetDeviceId']).toBe('agent-1');

      // 4. Mobile sends SDP answer
      hostWs.sent.length = 0;
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_answer',
          sdp: 'answer-sdp',
          targetDeviceId: 'agent-1',
        })
      );

      // Agent receives SDP answer
      const answers = hostWs.messagesOfType('sdp_answer');
      expect(answers).toHaveLength(1);
      expect(answers[0]!['targetDeviceId']).toBe('mobile-1');

      // 5. Exchange ICE candidates
      mobileWs.sent.length = 0;
      hostWs.sent.length = 0;

      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'ice_candidate',
          candidate: 'agent-candidate',
          targetDeviceId: 'mobile-1',
        })
      );

      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({
          type: 'ice_candidate',
          candidate: 'mobile-candidate',
          targetDeviceId: 'agent-1',
        })
      );

      expect(mobileWs.messagesOfType('ice_candidate')).toHaveLength(1);
      expect(hostWs.messagesOfType('ice_candidate')).toHaveLength(1);
    });
  });

  describe('cross-pairing isolation', () => {
    it('rejects connect_request to unpaired device', async () => {
      // Agent and mobile exist but are NOT paired
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');

      mobileWs.sent.length = 0;

      // Mobile tries to connect to agent it's not paired with
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-1' })
      );

      // Should get an error, not relay to the agent
      const errors = mobileWs.messagesOfType('error');
      expect(errors).toHaveLength(1);
      expect(errors[0]!['error']).toContain('not connected');

      // Agent should NOT have received anything
      const hostRequests = hostWs.messagesOfType('connect_request');
      expect(hostRequests).toHaveLength(0);
    });

    it('silently drops SDP relay to unpaired device', async () => {
      // Agent and mobile exist but are NOT paired
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');

      mobileWs.sent.length = 0;

      // Agent tries to send SDP offer to unpaired mobile
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_offer',
          sdp: 'malicious-offer',
          targetDeviceId: 'mobile-1',
        })
      );

      // Mobile should NOT receive the offer
      const offers = mobileWs.messagesOfType('sdp_offer');
      expect(offers).toHaveLength(0);
    });
  });

  describe('WebSocket error handling', () => {
    it('handles webSocketError gracefully', async () => {
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');

      await doInstance.webSocketError(
        hostWs as unknown as WebSocket,
        new Error('connection reset')
      );

      expect(hostWs.closed).toBe(true);
      expect(hostWs.closeCode).toBe(1011);
    });

    it('emits host_offline on webSocketError for paired host', async () => {
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      doInstance.createPairing('agent-1', 'mobile-1');

      mobileWs.sent.length = 0;

      // Agent WebSocket errors out
      await doInstance.webSocketError(
        hostWs as unknown as WebSocket,
        new Error('connection reset')
      );

      // Mobile should receive host_offline
      const offlineMessages = mobileWs.messagesOfType('host_offline');
      expect(offlineMessages).toHaveLength(1);
      expect(offlineMessages[0]!['deviceId']).toBe('agent-1');
    });

    it('handles unknown message type', async () => {
      const { ws } = await connectAndAuth('agent-1', 'host');
      ws.sent.length = 0;

      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'unknown_type' })
      );

      const errors = ws.messagesOfType('error');
      expect(errors).toHaveLength(1);
      expect(errors[0]!['error']).toContain('Unknown message type');
    });
  });
});
