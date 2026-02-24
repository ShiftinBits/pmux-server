import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDO } from './helpers/mock-do';
import { MockWebSocket } from './helpers/mock-websocket';
import { createJWT } from '../auth';
import type { SignalingDO } from '../signaling';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

let doInstance: SignalingDO;

beforeEach(async () => {
  doInstance = await createTestDO();
});

/**
 * Register a device and get a valid JWT for WebSocket auth.
 */
async function setupDevice(
  deviceId: string,
  deviceType: 'agent' | 'mobile',
  userId?: string
): Promise<string> {
  doInstance.registerDevice(deviceId, `pubkey-${deviceId}`, deviceType, userId);
  const device = doInstance.getDevice(deviceId)!;
  return createJWT(device.id, device.userId, device.deviceType, JWT_SECRET);
}

/**
 * Create a mock WebSocket and authenticate it with the DO.
 */
async function connectAndAuth(
  deviceId: string,
  deviceType: 'agent' | 'mobile',
  userId?: string
): Promise<{ ws: MockWebSocket; token: string }> {
  const token = await setupDevice(deviceId, deviceType, userId);
  const ws = new MockWebSocket();

  // Simulate Hibernation API: DO accepts the WebSocket
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
      const token = await setupDevice('agent-1', 'agent');
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
      const { ws } = await connectAndAuth('agent-1', 'agent');
      const beforeCount = ws.sent.length;

      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'presence' })
      );

      // Presence is silently acknowledged — no response sent
      expect(ws.sent.length).toBe(beforeCount);
    });
  });

  describe('agent_online / agent_offline', () => {
    it('emits agent_online to mobile when agent authenticates', async () => {
      // Register agent and mobile under same user
      const agentToken = await setupDevice('agent-1', 'agent');
      const agentDevice = doInstance.getDevice('agent-1')!;
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile', agentDevice.userId);

      // Clear messages from mobile auth
      mobileWs.sent.length = 0;

      // Now agent authenticates
      const agentWs = new MockWebSocket();
      await doInstance.webSocketMessage(
        agentWs as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: agentToken })
      );

      // Mobile should receive agent_online
      const onlineMessages = mobileWs.messagesOfType('agent_online');
      expect(onlineMessages).toHaveLength(1);
      expect(onlineMessages[0]!['deviceId']).toBe('agent-1');
    });

    it('emits agent_offline to mobile when agent disconnects', async () => {
      // Set up both under same user
      const agentDevice = doInstance.registerDevice('agent-1', 'pubkey-agent', 'agent');
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile', agentDevice.userId);
      const { ws: agentWs } = await connectAndAuth('agent-1', 'agent', agentDevice.userId);

      // Clear prior messages
      mobileWs.sent.length = 0;

      // Agent disconnects
      await doInstance.webSocketClose(
        agentWs as unknown as WebSocket,
        1000,
        'normal closure',
        true
      );

      // Mobile should receive agent_offline
      const offlineMessages = mobileWs.messagesOfType('agent_offline');
      expect(offlineMessages).toHaveLength(1);
      expect(offlineMessages[0]!['deviceId']).toBe('agent-1');
    });

    it('does not emit agent_offline when mobile disconnects', async () => {
      const agentDevice = doInstance.registerDevice('agent-1', 'pubkey-agent', 'agent');
      const { ws: agentWs } = await connectAndAuth('agent-1', 'agent', agentDevice.userId);
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile', agentDevice.userId);

      // Clear prior messages
      agentWs.sent.length = 0;

      // Mobile disconnects
      await doInstance.webSocketClose(
        mobileWs as unknown as WebSocket,
        1000,
        'normal closure',
        true
      );

      // Agent should NOT receive agent_offline
      const offlineMessages = agentWs.messagesOfType('agent_offline');
      expect(offlineMessages).toHaveLength(0);
    });
  });

  describe('connect_request relay', () => {
    it('relays connect_request from mobile to agent', async () => {
      const agentDevice = doInstance.registerDevice('agent-1', 'pubkey-agent', 'agent');
      const { ws: agentWs } = await connectAndAuth('agent-1', 'agent', agentDevice.userId);
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile', agentDevice.userId);

      // Clear prior messages
      agentWs.sent.length = 0;

      // Mobile sends connect_request to agent
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-1' })
      );

      // Agent should receive connect_request with mobile's deviceId
      const requests = agentWs.messagesOfType('connect_request');
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
    it('relays sdp_offer from agent to mobile', async () => {
      const agentDevice = doInstance.registerDevice('agent-1', 'pubkey-agent', 'agent');
      const { ws: agentWs } = await connectAndAuth('agent-1', 'agent', agentDevice.userId);
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile', agentDevice.userId);

      // Clear prior messages
      mobileWs.sent.length = 0;

      // Agent sends SDP offer to mobile
      await doInstance.webSocketMessage(
        agentWs as unknown as WebSocket,
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

    it('relays sdp_answer from mobile to agent', async () => {
      const agentDevice = doInstance.registerDevice('agent-1', 'pubkey-agent', 'agent');
      const { ws: agentWs } = await connectAndAuth('agent-1', 'agent', agentDevice.userId);
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile', agentDevice.userId);

      // Clear prior messages
      agentWs.sent.length = 0;

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
      const answers = agentWs.messagesOfType('sdp_answer');
      expect(answers).toHaveLength(1);
      expect(answers[0]!['sdp']).toContain('v=0');
      expect(answers[0]!['targetDeviceId']).toBe('mobile-1');
    });

    it('relays ice_candidate bidirectionally', async () => {
      const agentDevice = doInstance.registerDevice('agent-1', 'pubkey-agent', 'agent');
      const { ws: agentWs } = await connectAndAuth('agent-1', 'agent', agentDevice.userId);
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile', agentDevice.userId);

      // Clear prior messages
      agentWs.sent.length = 0;
      mobileWs.sent.length = 0;

      // Agent sends ICE candidate to mobile
      await doInstance.webSocketMessage(
        agentWs as unknown as WebSocket,
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
      const agentCandidates = agentWs.messagesOfType('ice_candidate');
      expect(agentCandidates).toHaveLength(1);
      expect(agentCandidates[0]!['candidate']).toContain('10.0.0.1');
      expect(agentCandidates[0]!['targetDeviceId']).toBe('mobile-1');
    });

    it('silently drops relay to disconnected target', async () => {
      const agentDevice = doInstance.registerDevice('agent-1', 'pubkey-agent', 'agent');
      const { ws: agentWs } = await connectAndAuth('agent-1', 'agent', agentDevice.userId);

      // Agent sends SDP offer to a mobile that never connected
      await doInstance.webSocketMessage(
        agentWs as unknown as WebSocket,
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
      // 1. Register devices under same user
      const agentDevice = doInstance.registerDevice('agent-1', 'pubkey-agent', 'agent');
      const { ws: agentWs } = await connectAndAuth('agent-1', 'agent', agentDevice.userId);
      const { ws: mobileWs } = await connectAndAuth('mobile-1', 'mobile', agentDevice.userId);

      // Clear auth messages
      agentWs.sent.length = 0;
      mobileWs.sent.length = 0;

      // 2. Mobile sends connect_request
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-1' })
      );

      // Agent receives connect_request
      expect(agentWs.messagesOfType('connect_request')).toHaveLength(1);

      // 3. Agent sends SDP offer
      await doInstance.webSocketMessage(
        agentWs as unknown as WebSocket,
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
      agentWs.sent.length = 0;
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_answer',
          sdp: 'answer-sdp',
          targetDeviceId: 'agent-1',
        })
      );

      // Agent receives SDP answer
      const answers = agentWs.messagesOfType('sdp_answer');
      expect(answers).toHaveLength(1);
      expect(answers[0]!['targetDeviceId']).toBe('mobile-1');

      // 5. Exchange ICE candidates
      mobileWs.sent.length = 0;
      agentWs.sent.length = 0;

      await doInstance.webSocketMessage(
        agentWs as unknown as WebSocket,
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
      expect(agentWs.messagesOfType('ice_candidate')).toHaveLength(1);
    });
  });

  describe('WebSocket error handling', () => {
    it('handles webSocketError gracefully', async () => {
      const { ws: agentWs } = await connectAndAuth('agent-1', 'agent');

      await doInstance.webSocketError(
        agentWs as unknown as WebSocket,
        new Error('connection reset')
      );

      expect(agentWs.closed).toBe(true);
      expect(agentWs.closeCode).toBe(1011);
    });

    it('handles unknown message type', async () => {
      const { ws } = await connectAndAuth('agent-1', 'agent');
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
