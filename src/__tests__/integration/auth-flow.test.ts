/**
 * Integration test: Full auth flow from pairing through WebSocket signaling.
 *
 * Tests the complete lifecycle:
 * 1. Agent initiates pairing
 * 2. Mobile completes pairing
 * 3. Both devices exchange tokens using Ed25519 signatures
 * 4. Both connect via WebSocket and authenticate
 * 5. Mobile sends connect_request, agent receives it
 * 6. SDP/ICE relay works between paired devices
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createTestDO } from '../helpers/mock-do';
import { MockWebSocket } from '../helpers/mock-websocket';
import { verifyJWT, createJWT } from '../../auth';
import type { SignalingDO } from '../../signaling';
import type { MockDOState } from '../helpers/mock-do';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

let doInstance: SignalingDO;
let mockState: MockDOState;

const realDateNow = Date.now;

beforeEach(async () => {
  const result = await createTestDO();
  doInstance = result.doInstance;
  mockState = result.mockState;
});

afterEach(() => {
  Date.now = realDateNow;
});

// --- Crypto helpers ---

async function generateEd25519Keypair() {
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const publicKeyRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', keyPair.publicKey)
  );
  return { keyPair, publicKeyRaw };
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

async function signEd25519(privateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign('Ed25519', privateKey, message);
  return new Uint8Array(sig);
}

// --- HTTP helpers ---

async function postJSON(
  path: string,
  body: unknown,
  headers?: Record<string, string>
): Promise<{ status: number; data: Record<string, unknown>; response: Response }> {
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
  return { status: response.status, data, response };
}

// --- WebSocket helpers ---

async function connectAndAuth(
  deviceId: string,
  deviceType: 'agent' | 'mobile',
  userId?: string
): Promise<{ ws: MockWebSocket; token: string }> {
  doInstance.registerDevice(deviceId, `pubkey-${deviceId}`, deviceType, userId);
  const device = doInstance.getDevice(deviceId)!;
  const token = await createJWT(device.id, device.userId, device.deviceType, JWT_SECRET);
  const ws = new MockWebSocket();

  doInstance.setConnection(deviceId, ws as unknown as WebSocket);

  await doInstance.webSocketMessage(
    ws as unknown as WebSocket,
    JSON.stringify({ type: 'auth', token })
  );

  return { ws, token };
}

// --- Tests ---

describe('Full auth flow integration [T3.11]', () => {
  it('completes full pairing + token + WebSocket + signaling lifecycle', async () => {
    // 1. Generate Ed25519 keys for agent and mobile
    const agentKeys = await generateEd25519Keypair();
    const mobileKeys = await generateEd25519Keypair();
    const agentPubBase64 = bytesToBase64(agentKeys.publicKeyRaw);
    const mobilePubBase64 = bytesToBase64(mobileKeys.publicKeyRaw);

    // 2. Agent initiates pairing
    const initResult = await postJSON('/pair/initiate', {
      deviceId: 'agent-integ',
      publicKey: agentPubBase64,
      x25519PublicKey: 'agent-x25519-pub',
    });
    expect(initResult.status).toBe(200);
    const pairingCode = initResult.data['pairingCode'] as string;
    expect(pairingCode).toHaveLength(6);

    // 3. Mobile completes pairing
    const completeResult = await postJSON('/pair/complete', {
      pairingCode,
      deviceId: 'mobile-integ',
      publicKey: mobilePubBase64,
      x25519PublicKey: 'mobile-x25519-pub',
    });
    expect(completeResult.status).toBe(200);
    expect(completeResult.data['agentDeviceId']).toBe('agent-integ');
    expect(completeResult.data['agentX25519PublicKey']).toBe('agent-x25519-pub');

    const userId = completeResult.data['userId'] as string;
    expect(userId).toBeTruthy();

    // Verify both devices are under the same user
    const devices = doInstance.getDevicesByUser(userId);
    expect(devices).toHaveLength(2);
    const deviceTypes = devices.map((d) => d.deviceType).sort();
    expect(deviceTypes).toEqual(['agent', 'mobile']);

    // 4. Agent exchanges signature for JWT
    const agentTimestamp = String(Math.floor(Date.now() / 1000));
    const agentMessage = new TextEncoder().encode('agent-integ' + agentTimestamp);
    const agentSig = await signEd25519(agentKeys.keyPair.privateKey, agentMessage);
    const agentSigBase64 = bytesToBase64(agentSig);

    const agentTokenResult = await postJSON('/token', {
      deviceId: 'agent-integ',
      timestamp: agentTimestamp,
      signature: agentSigBase64,
    });
    expect(agentTokenResult.status).toBe(200);
    const agentJWT = agentTokenResult.data['token'] as string;

    // Verify the agent JWT has correct claims
    const agentPayload = await verifyJWT(agentJWT, JWT_SECRET);
    expect(agentPayload.deviceId).toBe('agent-integ');
    expect(agentPayload.sub).toBe('agent-integ');
    expect(agentPayload.aud).toBe('pocketmux');
    expect(agentPayload.deviceType).toBe('agent');
    expect(agentPayload.userId).toBe(userId);

    // 5. Mobile exchanges signature for JWT
    const mobileTimestamp = String(Math.floor(Date.now() / 1000));
    const mobileMessage = new TextEncoder().encode('mobile-integ' + mobileTimestamp);
    const mobileSig = await signEd25519(mobileKeys.keyPair.privateKey, mobileMessage);
    const mobileSigBase64 = bytesToBase64(mobileSig);

    const mobileTokenResult = await postJSON('/token', {
      deviceId: 'mobile-integ',
      timestamp: mobileTimestamp,
      signature: mobileSigBase64,
    });
    expect(mobileTokenResult.status).toBe(200);
    const mobileJWT = mobileTokenResult.data['token'] as string;

    // Verify the mobile JWT
    const mobilePayload = await verifyJWT(mobileJWT, JWT_SECRET);
    expect(mobilePayload.deviceId).toBe('mobile-integ');
    expect(mobilePayload.deviceType).toBe('mobile');
    expect(mobilePayload.userId).toBe(userId);

    // 6. Both connect via WebSocket and authenticate
    const agentWs = new MockWebSocket();
    doInstance.setConnection('agent-integ', agentWs as unknown as WebSocket);
    await doInstance.webSocketMessage(
      agentWs as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: agentJWT })
    );
    expect(agentWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });

    const mobileWs = new MockWebSocket();
    doInstance.setConnection('mobile-integ', mobileWs as unknown as WebSocket);
    await doInstance.webSocketMessage(
      mobileWs as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: mobileJWT })
    );
    expect(mobileWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });

    // 7. Mobile sends connect_request, agent receives it
    agentWs.sent.length = 0;
    await doInstance.webSocketMessage(
      mobileWs as unknown as WebSocket,
      JSON.stringify({ type: 'connect_request', targetDeviceId: 'agent-integ' })
    );

    const agentRequests = agentWs.messagesOfType('connect_request');
    expect(agentRequests).toHaveLength(1);
    expect(agentRequests[0]!['targetDeviceId']).toBe('mobile-integ');

    // 8. SDP/ICE exchange
    mobileWs.sent.length = 0;
    await doInstance.webSocketMessage(
      agentWs as unknown as WebSocket,
      JSON.stringify({
        type: 'sdp_offer',
        sdp: 'v=0\r\no=- 123 IN IP4 127.0.0.1\r\n',
        targetDeviceId: 'mobile-integ',
      })
    );

    const offers = mobileWs.messagesOfType('sdp_offer');
    expect(offers).toHaveLength(1);
    expect(offers[0]!['sdp']).toContain('v=0');
    expect(offers[0]!['targetDeviceId']).toBe('agent-integ');

    agentWs.sent.length = 0;
    await doInstance.webSocketMessage(
      mobileWs as unknown as WebSocket,
      JSON.stringify({
        type: 'sdp_answer',
        sdp: 'v=0\r\no=- 456 IN IP4 127.0.0.1\r\n',
        targetDeviceId: 'agent-integ',
      })
    );

    const answers = agentWs.messagesOfType('sdp_answer');
    expect(answers).toHaveLength(1);
    expect(answers[0]!['targetDeviceId']).toBe('mobile-integ');

    // ICE candidates
    mobileWs.sent.length = 0;
    agentWs.sent.length = 0;

    await doInstance.webSocketMessage(
      agentWs as unknown as WebSocket,
      JSON.stringify({
        type: 'ice_candidate',
        candidate: 'candidate:1 1 udp 2130706431 192.168.1.1 12345 typ host',
        targetDeviceId: 'mobile-integ',
      })
    );

    await doInstance.webSocketMessage(
      mobileWs as unknown as WebSocket,
      JSON.stringify({
        type: 'ice_candidate',
        candidate: 'candidate:2 1 udp 2130706431 10.0.0.1 54321 typ host',
        targetDeviceId: 'agent-integ',
      })
    );

    expect(mobileWs.messagesOfType('ice_candidate')).toHaveLength(1);
    expect(agentWs.messagesOfType('ice_candidate')).toHaveLength(1);
  });

  it('rejects token exchange with wrong key', async () => {
    // Generate two different key pairs
    const realKeys = await generateEd25519Keypair();
    const wrongKeys = await generateEd25519Keypair();

    // Register with the real public key
    await postJSON('/pair/initiate', {
      deviceId: 'agent-wrong-key',
      publicKey: bytesToBase64(realKeys.publicKeyRaw),
      x25519PublicKey: 'x25519-key',
    });

    // Sign with the wrong private key
    const timestamp = String(Math.floor(Date.now() / 1000));
    const message = new TextEncoder().encode('agent-wrong-key' + timestamp);
    const wrongSig = await signEd25519(wrongKeys.keyPair.privateKey, message);

    const result = await postJSON('/token', {
      deviceId: 'agent-wrong-key',
      timestamp,
      signature: bytesToBase64(wrongSig),
    });

    expect(result.status).toBe(401);
    expect(result.data['error']).toContain('Signature verification failed');
  });

  it('blocks WebSocket auth with expired token', async () => {
    // Register a device
    doInstance.registerDevice('agent-expired', 'pubkey-agent', 'agent');
    const device = doInstance.getDevice('agent-expired')!;

    // Create a JWT that is already expired (by manipulating Date.now)
    // afterEach restores Date.now if this test throws
    Date.now = () => realDateNow() - 2 * 60 * 60 * 1000; // 2 hours ago
    const expiredToken = await createJWT(
      device.id,
      device.userId,
      device.deviceType,
      JWT_SECRET
    );
    Date.now = realDateNow;

    const ws = new MockWebSocket();
    await doInstance.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: expiredToken })
    );

    expect(ws.lastMessage()).toEqual({ type: 'error', error: 'Authentication failed' });
    expect(ws.closed).toBe(true);
    expect(ws.closeCode).toBe(4001);
  });

  it('emits agent_online/offline during connection lifecycle', async () => {
    // Register under same user
    const agentDevice = doInstance.registerDevice('agent-notify', 'pubkey-agent', 'agent');
    const { ws: mobileWs } = await connectAndAuth(
      'mobile-notify',
      'mobile',
      agentDevice.userId
    );

    // Clear mobile messages from auth
    mobileWs.sent.length = 0;

    // Agent connects - mobile should get agent_online
    const agentToken = await createJWT(
      'agent-notify',
      agentDevice.userId,
      'agent',
      JWT_SECRET
    );
    const agentWs = new MockWebSocket();
    doInstance.setConnection('agent-notify', agentWs as unknown as WebSocket);
    await doInstance.webSocketMessage(
      agentWs as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: agentToken })
    );

    const onlineMessages = mobileWs.messagesOfType('agent_online');
    expect(onlineMessages).toHaveLength(1);
    expect(onlineMessages[0]!['deviceId']).toBe('agent-notify');

    // Agent disconnects - mobile should get agent_offline
    mobileWs.sent.length = 0;
    await doInstance.webSocketClose(
      agentWs as unknown as WebSocket,
      1000,
      'normal closure',
      true
    );

    const offlineMessages = mobileWs.messagesOfType('agent_offline');
    expect(offlineMessages).toHaveLength(1);
    expect(offlineMessages[0]!['deviceId']).toBe('agent-notify');
  });
});
