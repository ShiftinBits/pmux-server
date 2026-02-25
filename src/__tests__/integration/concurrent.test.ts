/**
 * Integration test: Concurrent connections and device isolation.
 *
 * Verifies:
 * 1. Multiple agents and mobiles under the same user can connect
 * 2. Messages route correctly (agent A's mobile talks to agent A, not B)
 * 3. Device count limit enforced (max 10 per user)
 * 4. WebSocket connection limit enforced (max 5 per device)
 * 5. Cross-user isolation prevents unauthorized signaling
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDO } from '../helpers/mock-do';
import { MockWebSocket } from '../helpers/mock-websocket';
import { createJWT } from '../../auth';
import {
  MAX_DEVICES_PER_USER,
  MAX_WS_CONNECTIONS_PER_DEVICE,
} from '../../middleware/ratelimit';
import type { SignalingDO } from '../../signaling';
import type { MockDOState } from '../helpers/mock-do';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

let doInstance: SignalingDO;
let mockState: MockDOState;

beforeEach(async () => {
  const result = await createTestDO();
  doInstance = result.doInstance;
  mockState = result.mockState;
});

// --- Helpers ---

async function setupDevice(
  deviceId: string,
  deviceType: 'host' | 'mobile',
  userId?: string
): Promise<string> {
  doInstance.registerDevice(deviceId, `pubkey-${deviceId}`, deviceType, userId);
  const device = doInstance.getDevice(deviceId)!;
  return createJWT(device.id, device.userId, device.deviceType, JWT_SECRET);
}

async function connectAndAuth(
  deviceId: string,
  deviceType: 'host' | 'mobile',
  userId?: string
): Promise<{ ws: MockWebSocket; token: string }> {
  const token = await setupDevice(deviceId, deviceType, userId);
  const ws = new MockWebSocket();

  doInstance.setConnection(deviceId, ws as unknown as WebSocket);

  await doInstance.webSocketMessage(
    ws as unknown as WebSocket,
    JSON.stringify({ type: 'auth', token })
  );

  return { ws, token };
}

async function postJSON(
  path: string,
  body: unknown,
  headers?: Record<string, string>
): Promise<{ status: number; data: Record<string, unknown> }> {
  const reqHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Client-IP': '127.0.0.1',
    ...headers,
  };
  const request = new Request(`http://localhost${path}`, {
    method: 'POST',
    headers: reqHeaders,
    body: JSON.stringify(body),
  });
  const response = await doInstance.fetch(request);
  const data = (await response.json()) as Record<string, unknown>;
  return { status: response.status, data };
}

// --- Tests ---

describe('Concurrent connections integration [T3.11]', () => {
  describe('multi-device messaging', () => {
    it('routes connect_request to correct agent under same user', async () => {
      // User A has agent-A and mobile-A
      const agentADev = doInstance.registerDevice('agent-A', 'pubkey-agent-A', 'host');
      const userA = agentADev.userId;

      const { ws: agentAWs } = await connectAndAuth('agent-A', 'host', userA);
      const { ws: mobileAWs } = await connectAndAuth('mobile-A', 'mobile', userA);

      // User B has agent-B and mobile-B
      const agentBDev = doInstance.registerDevice('agent-B', 'pubkey-agent-B', 'host');
      const userB = agentBDev.userId;

      const { ws: agentBWs } = await connectAndAuth('agent-B', 'host', userB);
      await connectAndAuth('mobile-B', 'mobile', userB);

      // Clear all auth messages
      agentAWs.sent.length = 0;
      agentBWs.sent.length = 0;

      // Mobile A sends connect_request to agent A
      await doInstance.webSocketMessage(
        mobileAWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-A' })
      );

      // Agent A should receive connect_request
      const agentARequests = agentAWs.messagesOfType('connect_request');
      expect(agentARequests).toHaveLength(1);
      expect(agentARequests[0]!['targetDeviceId']).toBe('mobile-A');

      // Agent B should NOT receive anything
      const agentBRequests = agentBWs.messagesOfType('connect_request');
      expect(agentBRequests).toHaveLength(0);
    });

    it('relays SDP between correct device pairs', async () => {
      // User A: agent-A + mobile-A
      const agentADev = doInstance.registerDevice('agent-sdp-A', 'pubkey-A', 'host');
      const userA = agentADev.userId;
      const { ws: agentAWs } = await connectAndAuth('agent-sdp-A', 'host', userA);
      const { ws: mobileAWs } = await connectAndAuth('mobile-sdp-A', 'mobile', userA);

      // User B: agent-B + mobile-B
      const agentBDev = doInstance.registerDevice('agent-sdp-B', 'pubkey-B', 'host');
      const userB = agentBDev.userId;
      const { ws: agentBWs } = await connectAndAuth('agent-sdp-B', 'host', userB);
      const { ws: mobileBWs } = await connectAndAuth('mobile-sdp-B', 'mobile', userB);

      // Clear messages
      mobileAWs.sent.length = 0;
      mobileBWs.sent.length = 0;

      // Agent A sends SDP offer to mobile A
      await doInstance.webSocketMessage(
        agentAWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_offer',
          sdp: 'offer-from-A',
          targetDeviceId: 'mobile-sdp-A',
        })
      );

      // Agent B sends SDP offer to mobile B
      await doInstance.webSocketMessage(
        agentBWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_offer',
          sdp: 'offer-from-B',
          targetDeviceId: 'mobile-sdp-B',
        })
      );

      // Mobile A should only receive agent A's offer
      const mobileAOffers = mobileAWs.messagesOfType('sdp_offer');
      expect(mobileAOffers).toHaveLength(1);
      expect(mobileAOffers[0]!['sdp']).toBe('offer-from-A');

      // Mobile B should only receive agent B's offer
      const mobileBOffers = mobileBWs.messagesOfType('sdp_offer');
      expect(mobileBOffers).toHaveLength(1);
      expect(mobileBOffers[0]!['sdp']).toBe('offer-from-B');
    });

    it('prevents cross-user signaling', async () => {
      // User A agent
      const { ws: agentAWs } = await connectAndAuth('agent-cross-A', 'host');
      // agentADevice exists but we only need agentAWs for assertions

      // User B mobile
      const { ws: mobileBWs } = await connectAndAuth('mobile-cross-B', 'mobile');

      // Mobile B tries to connect to agent A (different user)
      mobileBWs.sent.length = 0;
      await doInstance.webSocketMessage(
        mobileBWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-cross-A' })
      );

      // Should get an error
      const errors = mobileBWs.messagesOfType('error');
      expect(errors).toHaveLength(1);
      expect(errors[0]!['error']).toContain('not connected');

      // Agent A should NOT receive the request
      agentAWs.sent.length = 0;
      const agentRequests = agentAWs.messagesOfType('connect_request');
      expect(agentRequests).toHaveLength(0);

      // Agent A also cannot send SDP to mobile B (cross-user)
      mobileBWs.sent.length = 0;
      await doInstance.webSocketMessage(
        agentAWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_offer',
          sdp: 'malicious-offer',
          targetDeviceId: 'mobile-cross-B',
        })
      );

      // Mobile B should NOT receive the offer (silently dropped)
      const mobileBOffers = mobileBWs.messagesOfType('sdp_offer');
      expect(mobileBOffers).toHaveLength(0);
    });
  });

  describe('device count limits', () => {
    it('enforces MAX_DEVICES_PER_USER limit during pairing', async () => {
      expect(MAX_DEVICES_PER_USER).toBe(10);

      // Create a user with an agent
      const initResult = await postJSON('/pair/initiate', {
        deviceId: 'agent-limit',
        publicKey: 'pub-key-agent-limit',
        x25519PublicKey: 'x25519-key-agent-limit',
      });
      const code = initResult.data['pairingCode'] as string;

      const completeResult = await postJSON('/pair/complete', {
        pairingCode: code,
        deviceId: 'mobile-limit-1',
        publicKey: 'pub-key-mobile-1',
        x25519PublicKey: 'x25519-key-mobile-1',
      });
      const userId = completeResult.data['userId'] as string;

      // Register devices to reach the limit (already have 2)
      for (let i = 2; i < MAX_DEVICES_PER_USER; i++) {
        doInstance.registerDevice(
          `mobile-limit-${i}`,
          `pub-key-mobile-${i}`,
          'mobile',
          userId
        );
      }

      // Verify at limit
      expect(doInstance.countDevicesByUser(userId)).toBe(MAX_DEVICES_PER_USER);

      // Try to pair an 11th device
      const initResult2 = await postJSON('/pair/initiate', {
        deviceId: 'agent-limit',
        publicKey: 'pub-key-agent-limit',
        x25519PublicKey: 'x25519-key-agent-limit',
      });
      const code2 = initResult2.data['pairingCode'] as string;

      const { status, data } = await postJSON('/pair/complete', {
        pairingCode: code2,
        deviceId: 'mobile-overflow',
        publicKey: 'pub-key-overflow',
        x25519PublicKey: 'x25519-key-overflow',
      });

      expect(status).toBe(400);
      expect(data['error']).toContain('Maximum device limit');
    });
  });

  describe('WebSocket connection limits', () => {
    it('enforces MAX_WS_CONNECTIONS_PER_DEVICE', async () => {
      expect(MAX_WS_CONNECTIONS_PER_DEVICE).toBe(5);

      const token = await setupDevice('agent-ws-limit', 'host');

      // Open connections up to the limit
      const sockets: MockWebSocket[] = [];
      for (let i = 0; i < MAX_WS_CONNECTIONS_PER_DEVICE; i++) {
        const ws = new MockWebSocket();
        await doInstance.webSocketMessage(
          ws as unknown as WebSocket,
          JSON.stringify({ type: 'auth', token })
        );
        expect(ws.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
        expect(ws.closed).toBe(false);
        sockets.push(ws);
      }

      expect(doInstance.getWsConnectionCount('agent-ws-limit')).toBe(5);

      // 6th connection should be rejected
      const ws6 = new MockWebSocket();
      await doInstance.webSocketMessage(
        ws6 as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token })
      );

      expect(ws6.lastMessage()).toEqual({
        type: 'error',
        error: 'Too many WebSocket connections',
      });
      expect(ws6.closed).toBe(true);
      expect(ws6.closeCode).toBe(1008);
    });

    it('allows new connections after closing one', async () => {
      const token = await setupDevice('agent-ws-reopen', 'host');

      // Open 5 connections
      const sockets: MockWebSocket[] = [];
      for (let i = 0; i < MAX_WS_CONNECTIONS_PER_DEVICE; i++) {
        const ws = new MockWebSocket();
        ws.serializeAttachment({
          deviceId: 'agent-ws-reopen',
          userId: 'test-user',
          deviceType: 'host',
          authenticated: true,
        });
        await doInstance.webSocketMessage(
          ws as unknown as WebSocket,
          JSON.stringify({ type: 'auth', token })
        );
        sockets.push(ws);
      }

      // Close one
      await doInstance.webSocketClose(
        sockets[0] as unknown as WebSocket,
        1000,
        'normal closure',
        true
      );

      expect(doInstance.getWsConnectionCount('agent-ws-reopen')).toBe(4);

      // New connection should succeed
      const wsNew = new MockWebSocket();
      await doInstance.webSocketMessage(
        wsNew as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token })
      );
      expect(wsNew.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      expect(wsNew.closed).toBe(false);
      expect(doInstance.getWsConnectionCount('agent-ws-reopen')).toBe(5);
    });

    it('different devices have independent connection limits', async () => {
      const token1 = await setupDevice('agent-ws-indep-1', 'host');
      const token2 = await setupDevice('agent-ws-indep-2', 'host');

      // Fill limit for device 1
      for (let i = 0; i < MAX_WS_CONNECTIONS_PER_DEVICE; i++) {
        const ws = new MockWebSocket();
        await doInstance.webSocketMessage(
          ws as unknown as WebSocket,
          JSON.stringify({ type: 'auth', token: token1 })
        );
      }

      // Device 1 is at limit
      expect(doInstance.getWsConnectionCount('agent-ws-indep-1')).toBe(5);

      // Device 2 should still be able to connect
      const ws2 = new MockWebSocket();
      await doInstance.webSocketMessage(
        ws2 as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: token2 })
      );
      expect(ws2.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      expect(ws2.closed).toBe(false);
    });
  });

  describe('concurrent operations', () => {
    it('handles multiple simultaneous connect_requests correctly', async () => {
      // One user with one agent and two mobiles
      const agentDev = doInstance.registerDevice('agent-concurrent', 'pubkey-agent', 'host');
      const userId = agentDev.userId;

      const { ws: hostWs } = await connectAndAuth('agent-concurrent', 'host', userId);
      const { ws: mobile1Ws } = await connectAndAuth('mobile-concurrent-1', 'mobile', userId);
      const { ws: mobile2Ws } = await connectAndAuth('mobile-concurrent-2', 'mobile', userId);

      hostWs.sent.length = 0;

      // Both mobiles send connect_request simultaneously
      await doInstance.webSocketMessage(
        mobile1Ws as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-concurrent' })
      );
      await doInstance.webSocketMessage(
        mobile2Ws as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-concurrent' })
      );

      // Agent should receive both connect_requests
      const requests = hostWs.messagesOfType('connect_request');
      expect(requests).toHaveLength(2);

      const senders = requests.map((r) => r['targetDeviceId']).sort();
      expect(senders).toEqual(['mobile-concurrent-1', 'mobile-concurrent-2']);
    });

    it('handles simultaneous SDP exchanges between multiple pairs', async () => {
      // User with agent + 2 mobiles
      const agentDev = doInstance.registerDevice('agent-multi-sdp', 'pubkey-agent', 'host');
      const userId = agentDev.userId;

      const { ws: hostWs } = await connectAndAuth('agent-multi-sdp', 'host', userId);
      const { ws: mobile1Ws } = await connectAndAuth('mobile-multi-sdp-1', 'mobile', userId);
      const { ws: mobile2Ws } = await connectAndAuth('mobile-multi-sdp-2', 'mobile', userId);

      mobile1Ws.sent.length = 0;
      mobile2Ws.sent.length = 0;

      // Agent sends different SDP offers to each mobile
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_offer',
          sdp: 'offer-for-mobile-1',
          targetDeviceId: 'mobile-multi-sdp-1',
        })
      );
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_offer',
          sdp: 'offer-for-mobile-2',
          targetDeviceId: 'mobile-multi-sdp-2',
        })
      );

      // Each mobile should receive only its own offer
      const mobile1Offers = mobile1Ws.messagesOfType('sdp_offer');
      expect(mobile1Offers).toHaveLength(1);
      expect(mobile1Offers[0]!['sdp']).toBe('offer-for-mobile-1');

      const mobile2Offers = mobile2Ws.messagesOfType('sdp_offer');
      expect(mobile2Offers).toHaveLength(1);
      expect(mobile2Offers[0]!['sdp']).toBe('offer-for-mobile-2');
    });

    it('host disconnect sends host_offline to all mobiles under same user', async () => {
      const agentDev = doInstance.registerDevice('agent-offline-all', 'pubkey-agent', 'host');
      const userId = agentDev.userId;

      const { ws: hostWs } = await connectAndAuth('agent-offline-all', 'host', userId);
      const { ws: mobile1Ws } = await connectAndAuth('mobile-offline-1', 'mobile', userId);
      const { ws: mobile2Ws } = await connectAndAuth('mobile-offline-2', 'mobile', userId);

      mobile1Ws.sent.length = 0;
      mobile2Ws.sent.length = 0;

      // Agent disconnects
      await doInstance.webSocketClose(
        hostWs as unknown as WebSocket,
        1000,
        'normal closure',
        true
      );

      // Both mobiles should receive host_offline
      const mobile1Offline = mobile1Ws.messagesOfType('host_offline');
      expect(mobile1Offline).toHaveLength(1);
      expect(mobile1Offline[0]!['deviceId']).toBe('agent-offline-all');

      const mobile2Offline = mobile2Ws.messagesOfType('host_offline');
      expect(mobile2Offline).toHaveLength(1);
      expect(mobile2Offline[0]!['deviceId']).toBe('agent-offline-all');
    });
  });
});
