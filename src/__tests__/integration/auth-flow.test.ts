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
import { generateEd25519Keypair, bytesToBase64, signEd25519, fetchChallenge, signedPairInitiateBodyWithChallenge } from '../helpers/crypto';
import type { SignalingDO } from '../../signaling';
import type { MockDOState } from '../helpers/mock-do';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

// Valid 32-hex device IDs (format: hex(SHA-256(publicKey)[0:16]))
const AGENT_INTEG = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1';
const MOBILE_INTEG = 'b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1';
const AGENT_WRONG_KEY = 'cccccccccccccccccccccccccccccccc';

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
  deviceType: 'host' | 'mobile'
): Promise<{ ws: MockWebSocket; token: string }> {
  doInstance.registerDevice(deviceId, `pubkey-${deviceId}`, deviceType);
  const token = await createJWT(deviceId, deviceType, JWT_SECRET);
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

// --- Tests ---

describe('Full auth flow integration [T3.11]', () => {
  it('completes full pairing + token + WebSocket + signaling lifecycle', async () => {
    // 1. Generate Ed25519 keys for agent and mobile
    const agentKeys = await generateEd25519Keypair();
    const mobileKeys = await generateEd25519Keypair();
    const agentPubBase64 = bytesToBase64(agentKeys.publicKeyRaw);
    const mobilePubBase64 = bytesToBase64(mobileKeys.publicKeyRaw);

    // 2. Agent initiates pairing
    const initBody = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_INTEG, agentKeys.keyPair, agentPubBase64, 'agent-x25519-pub');
    const initResult = await postJSON('/pair/initiate', initBody);
    expect(initResult.status).toBe(200);
    const pairingCode = initResult.data['pairingCode'] as string;
    expect(pairingCode).toHaveLength(6);

    // 3. Mobile completes pairing
    const completeResult = await postJSON('/pair/complete', {
      pairingCode,
      deviceId: MOBILE_INTEG,
      ed25519PublicKey: mobilePubBase64,
      x25519PublicKey: 'mobile-x25519-pub',
    });
    expect(completeResult.status).toBe(200);
    expect(completeResult.data['hostDeviceId']).toBe(AGENT_INTEG);
    expect(completeResult.data['hostX25519PublicKey']).toBe('agent-x25519-pub');
    // No userId in response
    expect(completeResult.data['userId']).toBeUndefined();

    // Verify pairing was created
    expect(doInstance.isPaired(AGENT_INTEG, MOBILE_INTEG)).toBe(true);

    // 4. Agent exchanges signature for JWT
    const agentNonce = await fetchChallenge(doInstance, AGENT_INTEG);
    const agentMessage = new TextEncoder().encode(AGENT_INTEG + '|' + agentNonce);
    const agentSig = await signEd25519(agentKeys.keyPair.privateKey, agentMessage);
    const agentSigBase64 = bytesToBase64(agentSig);

    const agentTokenResult = await postJSON('/token', {
      deviceId: AGENT_INTEG,
      nonce: agentNonce,
      signature: agentSigBase64,
    });
    expect(agentTokenResult.status).toBe(200);
    const agentJWT = agentTokenResult.data['token'] as string;

    // Verify the agent JWT has correct claims
    const agentPayload = await verifyJWT(agentJWT, JWT_SECRET);
    expect(agentPayload.deviceId).toBe(AGENT_INTEG);
    expect(agentPayload.sub).toBe(AGENT_INTEG);
    expect(agentPayload.aud).toBe('pocketmux');
    expect(agentPayload.deviceType).toBe('host');

    // 5. Mobile exchanges signature for JWT
    const mobileNonce = await fetchChallenge(doInstance, MOBILE_INTEG);
    const mobileMessage = new TextEncoder().encode(MOBILE_INTEG + '|' + mobileNonce);
    const mobileSig = await signEd25519(mobileKeys.keyPair.privateKey, mobileMessage);
    const mobileSigBase64 = bytesToBase64(mobileSig);

    const mobileTokenResult = await postJSON('/token', {
      deviceId: MOBILE_INTEG,
      nonce: mobileNonce,
      signature: mobileSigBase64,
    });
    expect(mobileTokenResult.status).toBe(200);
    const mobileJWT = mobileTokenResult.data['token'] as string;

    // Verify the mobile JWT
    const mobilePayload = await verifyJWT(mobileJWT, JWT_SECRET);
    expect(mobilePayload.deviceId).toBe(MOBILE_INTEG);
    expect(mobilePayload.deviceType).toBe('mobile');

    // 6. Both connect via WebSocket and authenticate
    const hostWs = new MockWebSocket();
    doInstance.setConnection(AGENT_INTEG, hostWs as unknown as WebSocket);
    await doInstance.webSocketMessage(
      hostWs as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: agentJWT })
    );
    expect(hostWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });

    const mobileWs = new MockWebSocket();
    doInstance.setConnection(MOBILE_INTEG, mobileWs as unknown as WebSocket);
    await doInstance.webSocketMessage(
      mobileWs as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: mobileJWT })
    );
    expect(mobileWs.lastMessage()).toEqual({ type: 'auth', status: 'ok' });

    // 7. Mobile sends connect_request, agent receives it
    hostWs.sent.length = 0;
    await doInstance.webSocketMessage(
      mobileWs as unknown as WebSocket,
      JSON.stringify({ type: 'connect_request', targetDeviceId: AGENT_INTEG })
    );

    const hostRequests = hostWs.messagesOfType('connect_request');
    expect(hostRequests).toHaveLength(1);
    expect(hostRequests[0]!['targetDeviceId']).toBe(MOBILE_INTEG);

    // 8. SDP/ICE exchange
    mobileWs.sent.length = 0;
    await doInstance.webSocketMessage(
      hostWs as unknown as WebSocket,
      JSON.stringify({
        type: 'sdp_offer',
        sdp: 'v=0\r\no=- 123 IN IP4 127.0.0.1\r\n',
        targetDeviceId: MOBILE_INTEG,
      })
    );

    const offers = mobileWs.messagesOfType('sdp_offer');
    expect(offers).toHaveLength(1);
    expect(offers[0]!['sdp']).toContain('v=0');
    expect(offers[0]!['targetDeviceId']).toBe(AGENT_INTEG);

    hostWs.sent.length = 0;
    await doInstance.webSocketMessage(
      mobileWs as unknown as WebSocket,
      JSON.stringify({
        type: 'sdp_answer',
        sdp: 'v=0\r\no=- 456 IN IP4 127.0.0.1\r\n',
        targetDeviceId: AGENT_INTEG,
      })
    );

    const answers = hostWs.messagesOfType('sdp_answer');
    expect(answers).toHaveLength(1);
    expect(answers[0]!['targetDeviceId']).toBe(MOBILE_INTEG);

    // ICE candidates
    mobileWs.sent.length = 0;
    hostWs.sent.length = 0;

    await doInstance.webSocketMessage(
      hostWs as unknown as WebSocket,
      JSON.stringify({
        type: 'ice_candidate',
        candidate: 'candidate:1 1 udp 2130706431 192.168.1.1 12345 typ host',
        targetDeviceId: MOBILE_INTEG,
      })
    );

    await doInstance.webSocketMessage(
      mobileWs as unknown as WebSocket,
      JSON.stringify({
        type: 'ice_candidate',
        candidate: 'candidate:2 1 udp 2130706431 10.0.0.1 54321 typ host',
        targetDeviceId: AGENT_INTEG,
      })
    );

    expect(mobileWs.messagesOfType('ice_candidate')).toHaveLength(1);
    expect(hostWs.messagesOfType('ice_candidate')).toHaveLength(1);
  });

  it('rejects token exchange with wrong key', async () => {
    // Generate two different key pairs
    const realKeys = await generateEd25519Keypair();
    const wrongKeys = await generateEd25519Keypair();

    // Register with the real public key via signed pair/initiate
    const initBody = await signedPairInitiateBodyWithChallenge(
      doInstance, AGENT_WRONG_KEY, realKeys.keyPair, bytesToBase64(realKeys.publicKeyRaw), 'x25519-key'
    );
    await postJSON('/pair/initiate', initBody);

    // Fetch a nonce then sign with the wrong private key
    const nonce = await fetchChallenge(doInstance, AGENT_WRONG_KEY);
    const message = new TextEncoder().encode(AGENT_WRONG_KEY + '|' + nonce);
    const wrongSig = await signEd25519(wrongKeys.keyPair.privateKey, message);

    const result = await postJSON('/token', {
      deviceId: AGENT_WRONG_KEY,
      nonce,
      signature: bytesToBase64(wrongSig),
    });

    expect(result.status).toBe(401);
    expect(result.data['error']).toContain('Signature verification failed');
  });

  it('blocks WebSocket auth with expired token', async () => {
    // Register a device
    doInstance.registerDevice('agent-expired', 'pubkey-agent', 'host');

    // Create a JWT that is already expired (by manipulating Date.now)
    // afterEach restores Date.now if this test throws
    Date.now = () => realDateNow() - 2 * 60 * 60 * 1000; // 2 hours ago
    const expiredToken = await createJWT(
      'agent-expired',
      'host',
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

  it('emits host_online/offline during connection lifecycle', async () => {
    // Register and pair host + mobile
    doInstance.registerDevice('agent-notify', 'pubkey-agent', 'host');
    const { ws: mobileWs } = await connectAndAuth('mobile-notify', 'mobile');
    doInstance.createPairing('agent-notify', 'mobile-notify');

    // Clear mobile messages from auth
    mobileWs.sent.length = 0;

    // Agent connects - mobile should get host_online
    const agentToken = await createJWT(
      'agent-notify',
      'host',
      JWT_SECRET
    );
    const hostWs = new MockWebSocket();
    mockState.acceptedWebSockets.push(hostWs as unknown as WebSocket);
    doInstance.setConnection('agent-notify', hostWs as unknown as WebSocket);
    await doInstance.webSocketMessage(
      hostWs as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: agentToken })
    );

    const onlineMessages = mobileWs.messagesOfType('host_online');
    expect(onlineMessages).toHaveLength(1);
    expect(onlineMessages[0]!['deviceId']).toBe('agent-notify');

    // Agent disconnects - mobile should get host_offline
    mobileWs.sent.length = 0;
    await doInstance.webSocketClose(
      hostWs as unknown as WebSocket,
      1000,
      'normal closure',
      true
    );

    const offlineMessages = mobileWs.messagesOfType('host_offline');
    expect(offlineMessages).toHaveLength(1);
    expect(offlineMessages[0]!['deviceId']).toBe('agent-notify');
  });
});
