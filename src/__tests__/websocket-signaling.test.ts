import { describe, it, expect, beforeEach, vi } from 'vitest';
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

    it('rejects auth message with missing token [SB-361]', async () => {
      const ws = new MockWebSocket();

      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'auth' })
      );

      expect(ws.lastMessage()).toEqual({ type: 'error', error: 'Missing or invalid auth token' });
      expect(ws.closed).toBe(true);
      expect(ws.closeCode).toBe(4001);
    });

    it('rejects auth message with non-string token [SB-361]', async () => {
      const ws = new MockWebSocket();

      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: 12345 })
      );

      expect(ws.lastMessage()).toEqual({ type: 'error', error: 'Missing or invalid auth token' });
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
  });

  describe('host name update on auth [SB-358]', () => {
    it('updates host name from auth message when name is provided', async () => {
      // Register host with old name
      doInstance.registerDevice('agent-1', 'pubkey-agent-1', 'host', 'old-name');
      const agentToken = await createJWT('agent-1', 'host', JWT_SECRET);

      // Authenticate with new name
      const hostWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken, name: 'new-name' })
      );

      expect(hostWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });

      // Verify DB was updated
      const device = doInstance.getDevice('agent-1');
      expect(device?.name).toBe('new-name');
    });

    it('updates mobile device name from auth message', async () => {
      doInstance.registerDevice('mobile-1', 'pubkey-mobile-1', 'mobile');
      const mobileToken = await createJWT('mobile-1', 'mobile', JWT_SECRET);

      const mobileWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: mobileToken, name: 'My iPhone' })
      );

      expect(mobileWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      const device = doInstance.getDevice('mobile-1');
      expect(device?.name).toBe('My iPhone');
    });

    it('ignores name longer than 64 characters in auth message', async () => {
      doInstance.registerDevice('agent-1', 'pubkey-agent-1', 'host', 'good-name');
      const agentToken = await createJWT('agent-1', 'host', JWT_SECRET);

      const longName = 'x'.repeat(65);
      const hostWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken, name: longName })
      );

      expect(hostWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      const device = doInstance.getDevice('agent-1');
      expect(device?.name).toBe('good-name');
    });

    it('ignores empty string name in auth message', async () => {
      doInstance.registerDevice('agent-1', 'pubkey-agent-1', 'host', 'existing-name');
      const agentToken = await createJWT('agent-1', 'host', JWT_SECRET);

      const hostWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken, name: '' })
      );

      expect(hostWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      const device = doInstance.getDevice('agent-1');
      expect(device?.name).toBe('existing-name');
    });

    it('accepts name exactly 64 characters in auth message', async () => {
      doInstance.registerDevice('agent-1', 'pubkey-agent-1', 'host', 'old-name');
      const agentToken = await createJWT('agent-1', 'host', JWT_SECRET);

      const exactName = 'a'.repeat(64);
      const hostWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken, name: exactName })
      );

      expect(hostWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      const device = doInstance.getDevice('agent-1');
      expect(device?.name).toBe(exactName);
    });

    it('ignores name with NUL control character in auth message', async () => {
      doInstance.registerDevice('agent-1', 'pubkey-agent-1', 'host', 'good-name');
      const agentToken = await createJWT('agent-1', 'host', JWT_SECRET);

      const hostWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken, name: 'bad\x00name' })
      );

      expect(hostWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      const device = doInstance.getDevice('agent-1');
      expect(device?.name).toBe('good-name');
    });

    it('ignores name with DEL control character in auth message', async () => {
      doInstance.registerDevice('agent-1', 'pubkey-agent-1', 'host', 'good-name');
      const agentToken = await createJWT('agent-1', 'host', JWT_SECRET);

      const hostWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken, name: 'bad\x7fname' })
      );

      expect(hostWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      const device = doInstance.getDevice('agent-1');
      expect(device?.name).toBe('good-name');
    });

    it('ignores non-string name (number) in auth message', async () => {
      doInstance.registerDevice('agent-1', 'pubkey-agent-1', 'host', 'good-name');
      const agentToken = await createJWT('agent-1', 'host', JWT_SECRET);

      const hostWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken, name: 42 })
      );

      expect(hostWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      const device = doInstance.getDevice('agent-1');
      expect(device?.name).toBe('good-name');
    });

    it('uses updated name in host_online notification sent to mobile', async () => {
      doInstance.registerDevice('agent-1', 'pubkey-agent-1', 'host', 'old-name');
      const agentToken = await createJWT('agent-1', 'host', JWT_SECRET);

      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');
      mobileWs.sent.length = 0;

      const hostWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken, name: 'new-name' })
      );

      const onlineMessages = mobileWs.messagesOfType('host_online');
      expect(onlineMessages).toHaveLength(1);
      expect(onlineMessages[0]!['deviceId']).toBe('agent-1');
      expect(onlineMessages[0]!['name']).toBe('new-name');
    });

  });

  describe('mobile name update on auth', () => {
    it('sends mobile_name_updated to paired host when name changes', async () => {
      // Register mobile with old name, host, and create pairing
      doInstance.registerDevice('mobile-1', 'pubkey-mobile-1', 'mobile', 'Old Phone');
      const mobileToken = await createJWT('mobile-1', 'mobile', JWT_SECRET);
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear prior messages
      hostWs.sent.length = 0;

      // Mobile authenticates with a new name
      const mobileWs = new MockWebSocket();
      mockState.acceptedWebSockets.push(mobileWs as unknown as WebSocket);
      doInstance.setConnection('mobile-1', mobileWs as unknown as WebSocket);
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: mobileToken, name: 'New Phone' })
      );

      // Host should receive mobile_name_updated
      const nameMessages = hostWs.messagesOfType('mobile_name_updated');
      expect(nameMessages).toHaveLength(1);
      expect(nameMessages[0]!['deviceId']).toBe('mobile-1');
      expect(nameMessages[0]!['name']).toBe('New Phone');

      // Verify DB was updated
      const device = doInstance.getDevice('mobile-1');
      expect(device?.name).toBe('New Phone');
    });

    it('does not send mobile_name_updated when name unchanged', async () => {
      // Register mobile with a name, host, and create pairing
      doInstance.registerDevice('mobile-1', 'pubkey-mobile-1', 'mobile', 'Same Phone');
      const mobileToken = await createJWT('mobile-1', 'mobile', JWT_SECRET);
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear prior messages
      hostWs.sent.length = 0;

      // Mobile authenticates with same name
      const mobileWs = new MockWebSocket();
      mockState.acceptedWebSockets.push(mobileWs as unknown as WebSocket);
      doInstance.setConnection('mobile-1', mobileWs as unknown as WebSocket);
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: mobileToken, name: 'Same Phone' })
      );

      // Host should NOT receive mobile_name_updated
      const nameMessages = hostWs.messagesOfType('mobile_name_updated');
      expect(nameMessages).toHaveLength(0);
    });

    it('ignores empty or too-long mobile names', async () => {
      doInstance.registerDevice('mobile-1', 'pubkey-mobile-1', 'mobile', 'Original Name');
      const mobileToken = await createJWT('mobile-1', 'mobile', JWT_SECRET);
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear prior messages
      hostWs.sent.length = 0;

      // Auth with empty name
      const mobileWs1 = new MockWebSocket();
      await doInstance.webSocketMessage(
        mobileWs1 as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: mobileToken, name: '' })
      );

      // DB unchanged
      let device = doInstance.getDevice('mobile-1');
      expect(device?.name).toBe('Original Name');

      // Auth with too-long name
      const mobileWs2 = new MockWebSocket();
      await doInstance.webSocketMessage(
        mobileWs2 as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: mobileToken, name: 'x'.repeat(65) })
      );

      // DB still unchanged
      device = doInstance.getDevice('mobile-1');
      expect(device?.name).toBe('Original Name');

      // No notifications sent to host
      const nameMessages = hostWs.messagesOfType('mobile_name_updated');
      expect(nameMessages).toHaveLength(0);
    });
  });

  describe('host_offline', () => {
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

    it('returns connection_rejected when target device is not paired', async () => {
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');

      // Clear auth messages
      mobileWs.sent.length = 0;

      // Target device doesn't exist and no pairing — hits isPaired check first
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'nonexistent-agent' })
      );

      const rejections = mobileWs.messagesOfType('connection_rejected');
      expect(rejections).toHaveLength(1);
      expect(rejections[0]!['reason']).toBe('not_paired');
    });

    it('sends host_offline when target is paired but offline', async () => {
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear auth messages
      mobileWs.sent.length = 0;

      // Mobile sends connect_request to paired agent that is NOT connected
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-1' })
      );

      // Should receive host_offline, not a generic error
      const offlineMessages = mobileWs.messagesOfType('host_offline');
      expect(offlineMessages).toHaveLength(1);
      expect(offlineMessages[0]!['deviceId']).toBe('agent-1');

      // Should NOT receive a generic error
      const errors = mobileWs.messagesOfType('error');
      expect(errors).toHaveLength(0);
    });

    it('returns connection_rejected for connect_request to unpaired device', async () => {
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      // No pairing created — agent-1 is unknown to mobile-1

      // Clear auth messages
      mobileWs.sent.length = 0;

      // Mobile sends connect_request to an unpaired device
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-1' })
      );

      // Should get connection_rejected (security: don't reveal device existence)
      const rejections = mobileWs.messagesOfType('connection_rejected');
      expect(rejections).toHaveLength(1);
      expect(rejections[0]!['reason']).toBe('not_paired');

      // Should NOT receive host_offline
      const offlineMessages = mobileWs.messagesOfType('host_offline');
      expect(offlineMessages).toHaveLength(0);
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

      // Agent sends ICE candidate to mobile (with sdpMid/sdpMLineIndex)
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'ice_candidate',
          candidate: 'candidate:1 1 udp 2130706431 192.168.1.1 12345 typ host',
          targetDeviceId: 'mobile-1',
          sdpMid: '0',
          sdpMLineIndex: 0,
        })
      );

      // Mobile sends ICE candidate to agent
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({
          type: 'ice_candidate',
          candidate: 'candidate:2 1 udp 2130706431 10.0.0.1 54321 typ host',
          targetDeviceId: 'agent-1',
          sdpMid: '0',
          sdpMLineIndex: 0,
        })
      );

      // Check mobile received agent's candidate (including sdpMid/sdpMLineIndex)
      const mobileCandidates = mobileWs.messagesOfType('ice_candidate');
      expect(mobileCandidates).toHaveLength(1);
      expect(mobileCandidates[0]!['candidate']).toContain('192.168.1.1');
      expect(mobileCandidates[0]!['targetDeviceId']).toBe('agent-1');
      expect(mobileCandidates[0]!['sdpMid']).toBe('0');
      expect(mobileCandidates[0]!['sdpMLineIndex']).toBe(0);

      // Check agent received mobile's candidate
      const hostCandidates = hostWs.messagesOfType('ice_candidate');
      expect(hostCandidates).toHaveLength(1);
      expect(hostCandidates[0]!['candidate']).toContain('10.0.0.1');
      expect(hostCandidates[0]!['targetDeviceId']).toBe('mobile-1');
      expect(hostCandidates[0]!['sdpMid']).toBe('0');
      expect(hostCandidates[0]!['sdpMLineIndex']).toBe(0);
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

    it('strips unknown fields from relayed messages', async () => {
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');

      // Clear auth messages
      hostWs.sent.length = 0;
      mobileWs.sent.length = 0;

      // Send sdp_offer with an extra malicious field
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_offer',
          sdp: 'v=0\r\noffer',
          targetDeviceId: 'mobile-1',
          malicious: 'injected-payload',
          extra: { nested: true },
        })
      );

      const offers = mobileWs.messagesOfType('sdp_offer');
      expect(offers).toHaveLength(1);
      expect(offers[0]!['type']).toBe('sdp_offer');
      expect(offers[0]!['sdp']).toBe('v=0\r\noffer');
      expect(offers[0]!['targetDeviceId']).toBe('agent-1');
      // Unknown fields must NOT be present
      expect(offers[0]).not.toHaveProperty('malicious');
      expect(offers[0]).not.toHaveProperty('extra');
    });

    it('only includes sdp field when present in original message', async () => {
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');

      hostWs.sent.length = 0;
      mobileWs.sent.length = 0;

      // Send ice_candidate (no sdp field)
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'ice_candidate',
          candidate: 'candidate:1 1 udp 2130706431 192.168.1.1 12345 typ host',
          targetDeviceId: 'mobile-1',
        })
      );

      const candidates = mobileWs.messagesOfType('ice_candidate');
      expect(candidates).toHaveLength(1);
      expect(candidates[0]!['candidate']).toContain('192.168.1.1');
      expect(candidates[0]!['targetDeviceId']).toBe('agent-1');
      // sdp should not be present on ice_candidate relay
      expect(candidates[0]).not.toHaveProperty('sdp');
    });

    it('rejects oversized WebSocket messages', async () => {
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');

      // Send a message exceeding 16 KB
      const oversizedPayload = JSON.stringify({
        type: 'sdp_offer',
        sdp: 'x'.repeat(20_000),
        targetDeviceId: 'mobile-1',
      });

      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        oversizedPayload
      );

      const errors = hostWs.messagesOfType('error');
      expect(errors).toHaveLength(1);
      expect(errors[0]!['error']).toBe('Message too large');
      expect(hostWs.closed).toBe(true);
      expect(hostWs.closeCode).toBe(1009);
      expect(hostWs.closeReason).toBe('Message too large');
    });

    it('relays connection_rejected with reason field preserved', async () => {
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile');
      doInstance.createPairing('agent-1', 'mobile-1');

      hostWs.sent.length = 0;
      mobileWs.sent.length = 0;

      // Agent rejects connection with a reason
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'connection_rejected',
          reason: 'already_connected',
          targetDeviceId: 'mobile-1',
        })
      );

      const rejections = mobileWs.messagesOfType('connection_rejected');
      expect(rejections).toHaveLength(1);
      expect(rejections[0]!['reason']).toBe('already_connected');
      expect(rejections[0]!['targetDeviceId']).toBe('agent-1');
      // Should not have extra fields
      expect(Object.keys(rejections[0]!)).toEqual(
        expect.arrayContaining(['type', 'reason', 'targetDeviceId'])
      );
      expect(Object.keys(rejections[0]!)).toHaveLength(3);
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

      // Should get connection_rejected, not relay to the agent
      const rejections = mobileWs.messagesOfType('connection_rejected');
      expect(rejections).toHaveLength(1);
      expect(rejections[0]!['reason']).toBe('not_paired');

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

  describe('WebSocket connection limits', () => {
    it('rejects connection when device exceeds MAX_WS_CONNECTIONS_PER_DEVICE', async () => {
      const token = await setupDevice('agent-1', 'host');

      // Authenticate 5 WebSockets (the maximum)
      for (let i = 0; i < 5; i++) {
        const ws = new MockWebSocket();
        mockState.acceptedWebSockets.push(ws as unknown as WebSocket);
        await doInstance.webSocketMessage(
          ws as unknown as WebSocket,
          JSON.stringify({ type: 'auth', token })
        );
        expect(ws.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      }

      // 6th connection should be rejected
      const ws6 = new MockWebSocket();
      await doInstance.webSocketMessage(
        ws6 as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token })
      );

      expect(ws6.lastMessage()).toEqual({ type: 'error', error: 'Too many WebSocket connections' });
      expect(ws6.closed).toBe(true);
      expect(ws6.closeCode).toBe(1008);
    });

    it('returns "Device not found" for deleted device with valid JWT', async () => {
      // Register device, create JWT, then delete the device
      const token = await setupDevice('agent-1', 'host');
      doInstance.removeDevice('agent-1');

      const ws = new MockWebSocket();
      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token })
      );

      expect(ws.lastMessage()).toEqual({ type: 'error', error: 'Device not found' });
      expect(ws.closed).toBe(true);
      expect(ws.closeCode).toBe(4004);
    });
  });

  describe('message edge cases', () => {
    it('silently ignores binary/ArrayBuffer messages', async () => {
      const { ws } = await connectAndAuth('agent-1', 'host');
      const beforeCount = ws.sent.length;

      // Send an ArrayBuffer (binary message)
      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        new ArrayBuffer(16)
      );

      // No response should be sent
      expect(ws.sent.length).toBe(beforeCount);
      expect(ws.closed).toBe(false);
    });

    it('returns "Missing message type" for JSON without type field', async () => {
      const { ws } = await connectAndAuth('agent-1', 'host');
      ws.sent.length = 0;

      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ data: 'no type field' })
      );

      const errors = ws.messagesOfType('error');
      expect(errors).toHaveLength(1);
      expect(errors[0]!['error']).toBe('Missing message type');
    });

    it('returns 426 for non-WebSocket /ws request', async () => {
      // Send a regular HTTP request to /ws without Upgrade header
      const request = new Request('http://localhost/ws', {
        method: 'GET',
        headers: { 'X-Client-IP': '127.0.0.1' },
      });
      const response = await doInstance.fetch(request);

      expect(response.status).toBe(426);
    });

    it('webSocketClose is a no-op for non-authenticated connection', async () => {
      const ws = new MockWebSocket();
      ws.serializeAttachment({ authenticated: false });

      // Should not throw or send any messages
      await doInstance.webSocketClose(
        ws as unknown as WebSocket,
        1000,
        'normal',
        true
      );

      expect(ws.sent.length).toBe(0);
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

    it('logs the error via console.error', async () => {
      const { ws: hostWs } = await connectAndAuth('agent-1', 'host');
      const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const err = new Error('connection reset');
      await doInstance.webSocketError(
        hostWs as unknown as WebSocket,
        err
      );

      expect(spy).toHaveBeenCalledWith(
        '[ws-error] deviceId=%s error=%o',
        'agent-1',
        err
      );
      spy.mockRestore();
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
