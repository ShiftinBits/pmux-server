/**
 * Integration test: Concurrent connections and device isolation.
 *
 * Verifies:
 * 1. Paired devices can connect and exchange messages
 * 2. Unpaired devices cannot signal each other
 * 3. WebSocket connection limit enforced (max 5 per device)
 * 4. Multiple simultaneous signaling flows work correctly
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDO, createMockKVStorage } from '../helpers/mock-do';
import { createMockSqlStorage } from '../helpers/mock-sql-storage';
import { MockWebSocket } from '../helpers/mock-websocket';
import { createJWT } from '../../auth';
import {
  MAX_WS_CONNECTIONS_PER_DEVICE,
} from '../../middleware/ratelimit';
import { SignalingDO } from '../../signaling';
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
  deviceType: 'host' | 'mobile'
): Promise<string> {
  doInstance.registerDevice(deviceId, `pubkey-${deviceId}`, deviceType);
  return createJWT(deviceId, deviceType, JWT_SECRET);
}

async function connectAndAuth(
  deviceId: string,
  deviceType: 'host' | 'mobile'
): Promise<{ ws: MockWebSocket; token: string }> {
  const token = await setupDevice(deviceId, deviceType);
  const ws = new MockWebSocket();

  // Must be in acceptedWebSockets for notifyDevice/notifyPairedMobile
  mockState.acceptedWebSockets.push(ws as unknown as WebSocket);
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
  describe('paired device messaging', () => {
    it('routes connect_request between paired devices', async () => {
      // Pair A: agent-A + mobile-A
      const { ws: agentAWs } = await connectAndAuth('agent-A', 'host');
      const { ws: mobileAWs } = await connectAndAuth('mobile-A', 'mobile');
      doInstance.createPairing('agent-A', 'mobile-A');

      // Pair B: agent-B + mobile-B
      const { ws: agentBWs } = await connectAndAuth('agent-B', 'host');
      await connectAndAuth('mobile-B', 'mobile');
      doInstance.createPairing('agent-B', 'mobile-B');

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

    it('relays SDP between correct paired device pairs', async () => {
      // Pair A: agent-A + mobile-A
      const { ws: agentAWs } = await connectAndAuth('agent-sdp-A', 'host');
      const { ws: mobileAWs } = await connectAndAuth('mobile-sdp-A', 'mobile');
      doInstance.createPairing('agent-sdp-A', 'mobile-sdp-A');

      // Pair B: agent-B + mobile-B
      const { ws: agentBWs } = await connectAndAuth('agent-sdp-B', 'host');
      const { ws: mobileBWs } = await connectAndAuth('mobile-sdp-B', 'mobile');
      doInstance.createPairing('agent-sdp-B', 'mobile-sdp-B');

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

    it('prevents cross-pairing signaling', async () => {
      // Agent A paired with mobile A
      const { ws: agentAWs } = await connectAndAuth('agent-cross-A', 'host');
      await connectAndAuth('mobile-cross-A', 'mobile');
      doInstance.createPairing('agent-cross-A', 'mobile-cross-A');

      // Mobile B paired with agent B (different pairing)
      await connectAndAuth('agent-cross-B', 'host');
      const { ws: mobileBWs } = await connectAndAuth('mobile-cross-B', 'mobile');
      doInstance.createPairing('agent-cross-B', 'mobile-cross-B');

      // Mobile B tries to connect to agent A (not its paired host)
      mobileBWs.sent.length = 0;
      await doInstance.webSocketMessage(
        mobileBWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-cross-A' })
      );

      // Should get connection_rejected
      const rejections = mobileBWs.messagesOfType('connection_rejected');
      expect(rejections).toHaveLength(1);
      expect(rejections[0]!['reason']).toBe('not_paired');

      // Agent A should NOT receive the request
      agentAWs.sent.length = 0;
      const agentRequests = agentAWs.messagesOfType('connect_request');
      expect(agentRequests).toHaveLength(0);

      // Agent A also cannot send SDP to mobile B (cross-pairing)
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

    it('rebuilds wsConnectionCounts after hibernation wake', async () => {
      const token = await setupDevice('agent-ws-hibernate', 'host');

      // Open 3 authenticated connections (builds up wsConnectionCounts).
      // Push each socket to acceptedWebSockets first (simulating the WebSocket
      // upgrade path), so getWebSockets() returns them after "hibernation".
      const sockets: MockWebSocket[] = [];
      for (let i = 0; i < 3; i++) {
        const ws = new MockWebSocket();
        mockState.acceptedWebSockets.push(ws as unknown as WebSocket);
        await doInstance.webSocketMessage(
          ws as unknown as WebSocket,
          JSON.stringify({ type: 'auth', token })
        );
        expect(ws.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
        sockets.push(ws);
      }
      expect(doInstance.getWsConnectionCount('agent-ws-hibernate')).toBe(3);

      // Simulate hibernation wake: create a new DO instance sharing the same
      // backing state (SQL + acceptedWebSockets). The new DO's in-memory maps
      // are empty, just like after a real hibernation wake.
      const freshMockKV = createMockKVStorage();
      const freshSql = await createMockSqlStorage();
      const freshMockState = {
        storage: {
          sql: freshSql,
          get: freshMockKV.get,
          put: freshMockKV.put,
          async setAlarm(): Promise<void> {},
          async getAlarm(): Promise<number | null> { return null; },
          async deleteAlarm(): Promise<void> {},
        },
        acceptWebSocket(): void {},
        getWebSockets(): WebSocket[] {
          // Return the same hibernated sockets from the original DO
          return mockState.acceptedWebSockets;
        },
      };
      const freshEnv = {
        SIGNALING: {} as DurableObjectNamespace,
        TURN_TOKEN_ID: 'test-turn-token-id',
        TURN_API_TOKEN: 'test-turn-api-token',
        JWT_SECRET: 'test-jwt-secret-at-least-32-chars-long',
      };
      const freshDO = new SignalingDO(
        freshMockState as unknown as DurableObjectState,
        freshEnv
      );

      // Register the device in the fresh DO's SQL (required for auth check)
      freshDO.registerDevice('agent-ws-hibernate', 'pubkey-agent-ws-hibernate', 'host');

      // Before rebuild, in-memory counts are 0 (hibernation wiped them)
      expect(freshDO.getWsConnectionCount('agent-ws-hibernate')).toBe(0);

      // Trigger rebuildConnectionCache() via getConnection()
      freshDO.getConnection('agent-ws-hibernate');

      // After rebuild, wsConnectionCounts should reflect the 3 hibernated sockets
      expect(freshDO.getWsConnectionCount('agent-ws-hibernate')).toBe(3);

      // Verify the limit is still enforced: open 2 more (to reach 5), then the 6th fails
      for (let i = 0; i < 2; i++) {
        const ws = new MockWebSocket();
        await freshDO.webSocketMessage(
          ws as unknown as WebSocket,
          JSON.stringify({ type: 'auth', token })
        );
        expect(ws.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      }
      expect(freshDO.getWsConnectionCount('agent-ws-hibernate')).toBe(5);

      // 6th connection should be rejected
      const wsOver = new MockWebSocket();
      await freshDO.webSocketMessage(
        wsOver as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token })
      );
      expect(wsOver.lastMessage()).toEqual({
        type: 'error',
        error: 'Too many WebSocket connections',
      });
      expect(wsOver.closed).toBe(true);
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
    it('handles connect_request from paired mobile to host', async () => {
      // One host paired with one mobile
      const { ws: hostWs } = await connectAndAuth('agent-concurrent', 'host');
      const { ws: mobileWs } = await connectAndAuth('mobile-concurrent', 'mobile');
      doInstance.createPairing('agent-concurrent', 'mobile-concurrent');

      hostWs.sent.length = 0;

      // Mobile sends connect_request
      await doInstance.webSocketMessage(
        mobileWs as unknown as WebSocket,
        JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-concurrent' })
      );

      // Agent should receive connect_request
      const requests = hostWs.messagesOfType('connect_request');
      expect(requests).toHaveLength(1);
      expect(requests[0]!['targetDeviceId']).toBe('mobile-concurrent');
    });

    it('handles simultaneous SDP exchanges between multiple paired pairs', async () => {
      // Pair 1: agent-1 + mobile-1
      const { ws: hostWs } = await connectAndAuth('agent-multi-sdp', 'host');
      const { ws: mobile1Ws } = await connectAndAuth('mobile-multi-sdp-1', 'mobile');
      doInstance.createPairing('agent-multi-sdp', 'mobile-multi-sdp-1');

      // Pair 2: agent-2 + mobile-2
      const { ws: host2Ws } = await connectAndAuth('agent-multi-sdp-2', 'host');
      const { ws: mobile2Ws } = await connectAndAuth('mobile-multi-sdp-2', 'mobile');
      doInstance.createPairing('agent-multi-sdp-2', 'mobile-multi-sdp-2');

      mobile1Ws.sent.length = 0;
      mobile2Ws.sent.length = 0;

      // Agent 1 sends SDP offer to mobile 1
      await doInstance.webSocketMessage(
        hostWs as unknown as WebSocket,
        JSON.stringify({
          type: 'sdp_offer',
          sdp: 'offer-for-mobile-1',
          targetDeviceId: 'mobile-multi-sdp-1',
        })
      );

      // Agent 2 sends SDP offer to mobile 2
      await doInstance.webSocketMessage(
        host2Ws as unknown as WebSocket,
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

    it('host disconnect sends host_offline to paired mobile only', async () => {
      // Pair: agent + mobile-1
      const { ws: hostWs } = await connectAndAuth('agent-offline-all', 'host');
      const { ws: mobile1Ws } = await connectAndAuth('mobile-offline-1', 'mobile');
      doInstance.createPairing('agent-offline-all', 'mobile-offline-1');

      // Unpaired mobile-2 (connected but not paired with this host)
      const { ws: mobile2Ws } = await connectAndAuth('mobile-offline-2', 'mobile');

      mobile1Ws.sent.length = 0;
      mobile2Ws.sent.length = 0;

      // Agent disconnects
      await doInstance.webSocketClose(
        hostWs as unknown as WebSocket,
        1000,
        'normal closure',
        true
      );

      // Paired mobile should receive host_offline
      const mobile1Offline = mobile1Ws.messagesOfType('host_offline');
      expect(mobile1Offline).toHaveLength(1);
      expect(mobile1Offline[0]!['deviceId']).toBe('agent-offline-all');

      // Unpaired mobile should NOT receive host_offline
      const mobile2Offline = mobile2Ws.messagesOfType('host_offline');
      expect(mobile2Offline).toHaveLength(0);
    });
  });
});
