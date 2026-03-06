import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDOCompat as createTestDO, createTestDO as createTestDOFull } from './helpers/mock-do';
import { MockWebSocket } from './helpers/mock-websocket';
import { createJWT } from '../auth';
import { generateEd25519Keypair, bytesToBase64, signEd25519, signedPairInitiateBody } from './helpers/crypto';
import type { SignalingDO } from '../signaling';

let doInstance: SignalingDO;
let keyPair: CryptoKeyPair;
let ed25519PublicKeyBase64: string;

beforeEach(async () => {
  doInstance = await createTestDO();
  const keys = await generateEd25519Keypair();
  keyPair = keys.keyPair;
  ed25519PublicKeyBase64 = bytesToBase64(keys.publicKeyRaw);
});

async function postJSON(
  path: string,
  body: unknown
): Promise<{ status: number; data: Record<string, unknown> }> {
  const request = new Request(`http://localhost${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const response = await doInstance.fetch(request);
  const data = await response.json() as Record<string, unknown>;
  return { status: response.status, data };
}

describe('POST /pair/initiate', () => {
  it('returns a pairing code', async () => {
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    const { status, data } = await postJSON('/pair/initiate', body);

    expect(status).toBe(200);
    expect(data['pairingCode']).toBeTypeOf('string');
    expect((data['pairingCode'] as string).length).toBe(6);
  });

  it('registers the agent device', async () => {
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    await postJSON('/pair/initiate', body);

    const device = doInstance.getDevice('agent-1');
    expect(device).not.toBeNull();
    expect(device!.deviceType).toBe('host');
    expect(device!.ed25519PublicKey).toBe(ed25519PublicKeyBase64);
  });

  it('rejects missing fields', async () => {
    const { status, data } = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      // missing publicKey, x25519PublicKey, timestamp, signature
    });

    expect(status).toBe(400);
    expect(data['error']).toContain('Missing required fields');
  });

  it('stores host name when provided', async () => {
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent', 'my-workstation');
    await postJSON('/pair/initiate', body);

    const device = doInstance.getDevice('agent-1');
    expect(device).not.toBeNull();
    expect(device!.name).toBe('my-workstation');
  });

  it('updates name on re-initiation', async () => {
    // First initiation with name
    const body1 = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent', 'old-name');
    await postJSON('/pair/initiate', body1);

    // Second initiation with a new name (device already exists)
    const body2 = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent', 'new-name');
    await postJSON('/pair/initiate', body2);

    const device = doInstance.getDevice('agent-1');
    expect(device!.name).toBe('new-name');
  });

  it('stores null name when not provided', async () => {
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    await postJSON('/pair/initiate', body);

    const device = doInstance.getDevice('agent-1');
    expect(device!.name).toBeNull();
  });

  it('rejects name longer than 64 characters', async () => {
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent', 'x'.repeat(65));
    const { status, data } = await postJSON('/pair/initiate', body);

    expect(status).toBe(400);
    expect(data['error']).toContain('64 characters');
  });

  it('rejects initiation with wrong key for existing device', async () => {
    // First initiation registers the device with keyPair (keyA)
    const body1 = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent', 'original-name');
    await postJSON('/pair/initiate', body1);

    // Generate a second keypair (keyB)
    const keysB = await generateEd25519Keypair();
    const pubB = bytesToBase64(keysB.publicKeyRaw);

    // Second initiation uses keyB's public key and signature — should fail
    // because signature from keyB won't verify against stored keyA
    const body2 = await signedPairInitiateBody('agent-1', keysB.keyPair, pubB, 'x25519-pub-key-agent', 'spoofed-name');
    const { status, data } = await postJSON('/pair/initiate', body2);

    expect(status).toBe(401);
    expect(data['error']).toContain('Signature verification failed');
  });

  it('invalidates previous pairing code when re-initiating', async () => {
    // First initiation — get a pairing code
    const body1 = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    const first = await postJSON('/pair/initiate', body1);
    expect(first.status).toBe(200);
    const firstCode = first.data['pairingCode'] as string;

    // Second initiation — same host, new code replaces the old one
    const body2 = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    const second = await postJSON('/pair/initiate', body2);
    expect(second.status).toBe(200);
    const secondCode = second.data['pairingCode'] as string;

    // First code should be invalidated (404)
    const completeFirst = await postJSON('/pair/complete', {
      pairingCode: firstCode,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });
    expect(completeFirst.status).toBe(404);
    expect(completeFirst.data['error']).toContain('Invalid or expired');

    // Second code should still work (200)
    const completeSecond = await postJSON('/pair/complete', {
      pairingCode: secondCode,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });
    expect(completeSecond.status).toBe(200);
    expect(completeSecond.data['hostDeviceId']).toBe('agent-1');
  });

  it('rejects missing timestamp and signature', async () => {
    const { status, data } = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      ed25519PublicKey: ed25519PublicKeyBase64,
      x25519PublicKey: 'x25519-pub-key-agent',
    });

    expect(status).toBe(400);
    expect(data['error']).toContain('Missing required fields');
  });

  it('rejects invalid signature', async () => {
    const badSig = bytesToBase64(new Uint8Array(64));
    const { status, data } = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      ed25519PublicKey: ed25519PublicKeyBase64,
      x25519PublicKey: 'x25519-pub-key-agent',
      timestamp: String(Math.floor(Date.now() / 1000)),
      signature: badSig,
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Signature verification failed');
  });

  it('rejects stale timestamp', async () => {
    const staleTimestamp = String(Math.floor(Date.now() / 1000) - 600);
    const message = new TextEncoder().encode('agent-1' + staleTimestamp);
    const sig = await signEd25519(keyPair.privateKey, message);

    const { status, data } = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      ed25519PublicKey: ed25519PublicKeyBase64,
      x25519PublicKey: 'x25519-pub-key-agent',
      timestamp: staleTimestamp,
      signature: bytesToBase64(sig),
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Timestamp out of range');
  });

  it('rejects future timestamp', async () => {
    const futureTimestamp = String(Math.floor(Date.now() / 1000) + 600);
    const message = new TextEncoder().encode('agent-1' + futureTimestamp);
    const sig = await signEd25519(keyPair.privateKey, message);

    const { status, data } = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      ed25519PublicKey: ed25519PublicKeyBase64,
      x25519PublicKey: 'x25519-pub-key-agent',
      timestamp: futureTimestamp,
      signature: bytesToBase64(sig),
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Timestamp out of range');
  });
});

describe('POST /pair/complete', () => {
  it('completes pairing flow successfully', async () => {
    // Step 1: Agent initiates pairing
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    const initResult = await postJSON('/pair/initiate', body);
    const pairingCode = initResult.data['pairingCode'] as string;

    // Step 2: Mobile completes pairing
    const { status, data } = await postJSON('/pair/complete', {
      pairingCode,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });

    expect(status).toBe(200);
    expect(data['hostX25519PublicKey']).toBe('x25519-pub-key-agent');
    expect(data['hostDeviceId']).toBe('agent-1');
    // userId should NOT be in the response
    expect(data['userId']).toBeUndefined();
  });

  it('creates a pairing between host and mobile', async () => {
    // Initiate
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    const initResult = await postJSON('/pair/initiate', body);

    // Complete
    await postJSON('/pair/complete', {
      pairingCode: initResult.data['pairingCode'],
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });

    // Verify pairing exists
    expect(doInstance.isPaired('agent-1', 'mobile-1')).toBe(true);
    expect(doInstance.getPairedMobile('agent-1')).toBe('mobile-1');
  });

  it('rejects invalid pairing code', async () => {
    const { status, data } = await postJSON('/pair/complete', {
      pairingCode: 'BADCODE',
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });

    expect(status).toBe(404);
    expect(data['error']).toContain('Invalid or expired');
  });

  it('rejects reused pairing code', async () => {
    // Initiate
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    const initResult = await postJSON('/pair/initiate', body);
    const code = initResult.data['pairingCode'] as string;

    // First complete — succeeds
    const first = await postJSON('/pair/complete', {
      pairingCode: code,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile-1',
      x25519PublicKey: 'x25519-pub-key-mobile-1',
    });
    expect(first.status).toBe(200);

    // Second complete with same code — fails
    const second = await postJSON('/pair/complete', {
      pairingCode: code,
      deviceId: 'mobile-2',
      ed25519PublicKey: 'ed25519-pub-key-mobile-2',
      x25519PublicKey: 'x25519-pub-key-mobile-2',
    });
    expect(second.status).toBe(404);
    expect(second.data['error']).toContain('Invalid or expired');
  });

  it('rejects expired pairing code', async () => {
    // Initiate
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    const initResult = await postJSON('/pair/initiate', body);
    const code = initResult.data['pairingCode'] as string;

    // Advance time past 5-minute expiry
    const realDateNow = Date.now;
    Date.now = () => realDateNow() + 6 * 60 * 1000;

    try {
      const { status, data } = await postJSON('/pair/complete', {
        pairingCode: code,
        deviceId: 'mobile-1',
        ed25519PublicKey: 'ed25519-pub-key-mobile',
        x25519PublicKey: 'x25519-pub-key-mobile',
      });

      expect(status).toBe(404);
      expect(data['error']).toContain('Invalid or expired');
    } finally {
      Date.now = realDateNow;
    }
  });

  it('rejects missing fields', async () => {
    const { status, data } = await postJSON('/pair/complete', {
      pairingCode: 'ABCDEF',
      // missing deviceId, publicKey, x25519PublicKey
    });

    expect(status).toBe(400);
    expect(data['error']).toContain('Missing required fields');
  });

  it('sends pair_complete to all WebSockets for the host device', async () => {
    const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';
    const { doInstance: do2, mockState } = await createTestDOFull();

    // Generate keypair for this DO instance
    const keys = await generateEd25519Keypair();
    const kp = keys.keyPair;
    const pubBase64 = bytesToBase64(keys.publicKeyRaw);

    // Helper for HTTP requests against this DO instance
    async function post(path: string, body: unknown) {
      const req = new Request(`http://localhost${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const res = await do2.fetch(req);
      return { status: res.status, data: await res.json() as Record<string, unknown> };
    }

    // Initiate pairing (registers the host device)
    const initBody = await signedPairInitiateBody('agent-1', kp, pubBase64, 'x25519-pub-key-agent');
    const initResult = await post('/pair/initiate', initBody);
    expect(initResult.status).toBe(200);
    const pairingCode = initResult.data['pairingCode'] as string;

    // Create two WebSockets for the same host device (background agent + pair CLI)
    const token = await createJWT('agent-1', 'host', JWT_SECRET);

    const agentWs = new MockWebSocket();
    const pairCliWs = new MockWebSocket();

    // Add both to the hibernation API's WebSocket list
    mockState.acceptedWebSockets.push(
      agentWs as unknown as WebSocket,
      pairCliWs as unknown as WebSocket,
    );

    // Authenticate both WebSockets
    await do2.webSocketMessage(agentWs as unknown as WebSocket, JSON.stringify({ type: 'auth', token }));
    await do2.webSocketMessage(pairCliWs as unknown as WebSocket, JSON.stringify({ type: 'auth', token }));

    // Clear auth responses
    agentWs.sent.length = 0;
    pairCliWs.sent.length = 0;

    // Complete pairing
    const completeResult = await post('/pair/complete', {
      pairingCode,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });
    expect(completeResult.status).toBe(200);

    // Both WebSockets should have received pair_complete
    const agentMsgs = agentWs.messagesOfType('pair_complete');
    const pairCliMsgs = pairCliWs.messagesOfType('pair_complete');

    expect(agentMsgs).toHaveLength(1);
    expect(pairCliMsgs).toHaveLength(1);
    expect(agentMsgs[0]['mobileDeviceId']).toBe('mobile-1');
    expect(pairCliMsgs[0]['mobileX25519PublicKey']).toBe('x25519-pub-key-mobile');
  });

  it('re-pairing replaces old mobile and sends device_unpaired notification', async () => {
    const { doInstance: do2, mockState } = await createTestDOFull();

    // Generate keypair for this DO instance
    const keys = await generateEd25519Keypair();
    const kp = keys.keyPair;
    const pubBase64 = bytesToBase64(keys.publicKeyRaw);

    async function post(path: string, body: unknown) {
      const req = new Request(`http://localhost${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const res = await do2.fetch(req);
      return { status: res.status, data: await res.json() as Record<string, unknown> };
    }

    // First pairing: agent-1 + mobile-1
    const initBody1 = await signedPairInitiateBody('agent-1', kp, pubBase64, 'x25519-pub-key-agent');
    const init1 = await post('/pair/initiate', initBody1);
    const code1 = init1.data['pairingCode'] as string;

    const complete1 = await post('/pair/complete', {
      pairingCode: code1,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile-1',
      x25519PublicKey: 'x25519-pub-key-mobile-1',
    });
    expect(complete1.status).toBe(200);

    // Verify initial pairing
    expect(do2.isPaired('agent-1', 'mobile-1')).toBe(true);

    // Connect mobile-1 via WebSocket so it can receive notifications
    const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';
    const mobile1Token = await createJWT('mobile-1', 'mobile', JWT_SECRET);
    const mobile1Ws = new MockWebSocket();
    mockState.acceptedWebSockets.push(mobile1Ws as unknown as WebSocket);
    do2.setConnection('mobile-1', mobile1Ws as unknown as WebSocket);
    await do2.webSocketMessage(
      mobile1Ws as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: mobile1Token })
    );
    mobile1Ws.sent.length = 0;

    // Second pairing: agent-1 + mobile-2 (replaces mobile-1)
    const initBody2 = await signedPairInitiateBody('agent-1', kp, pubBase64, 'x25519-pub-key-agent');
    const init2 = await post('/pair/initiate', initBody2);
    const code2 = init2.data['pairingCode'] as string;

    const complete2 = await post('/pair/complete', {
      pairingCode: code2,
      deviceId: 'mobile-2',
      ed25519PublicKey: 'ed25519-pub-key-mobile-2',
      x25519PublicKey: 'x25519-pub-key-mobile-2',
    });
    expect(complete2.status).toBe(200);

    // Verify new pairing replaced old one
    expect(do2.isPaired('agent-1', 'mobile-2')).toBe(true);
    expect(do2.isPaired('agent-1', 'mobile-1')).toBe(false);

    // Old mobile should have received device_unpaired notification
    const unpairedMsgs = mobile1Ws.messagesOfType('device_unpaired');
    expect(unpairedMsgs).toHaveLength(1);
    expect(unpairedMsgs[0]!['hostDeviceId']).toBe('agent-1');
    expect(unpairedMsgs[0]!['reason']).toBe('replaced_by_new_pairing');
  });

  it('stores mobile name from /pair/complete', async () => {
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    const initResult = await postJSON('/pair/initiate', body);
    const pairingCode = initResult.data['pairingCode'] as string;

    const { status } = await postJSON('/pair/complete', {
      pairingCode,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
      name: "Ryan's iPhone",
    });

    expect(status).toBe(200);
    const device = doInstance.getDevice('mobile-1');
    expect(device).not.toBeNull();
    expect(device!.name).toBe("Ryan's iPhone");
  });

  it('pair_complete WS message includes mobileName', async () => {
    const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';
    const { doInstance: do2, mockState } = await createTestDOFull();

    const keys = await generateEd25519Keypair();
    const kp = keys.keyPair;
    const pubBase64 = bytesToBase64(keys.publicKeyRaw);

    async function post(path: string, body: unknown) {
      const req = new Request(`http://localhost${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const res = await do2.fetch(req);
      return { status: res.status, data: await res.json() as Record<string, unknown> };
    }

    // Initiate pairing
    const initBody = await signedPairInitiateBody('agent-1', kp, pubBase64, 'x25519-pub-key-agent');
    const initResult = await post('/pair/initiate', initBody);
    expect(initResult.status).toBe(200);
    const pairingCode = initResult.data['pairingCode'] as string;

    // Connect host WebSocket
    const token = await createJWT('agent-1', 'host', JWT_SECRET);
    const agentWs = new MockWebSocket();
    mockState.acceptedWebSockets.push(agentWs as unknown as WebSocket);
    await do2.webSocketMessage(agentWs as unknown as WebSocket, JSON.stringify({ type: 'auth', token }));
    agentWs.sent.length = 0;

    // Complete pairing with mobile name
    const completeResult = await post('/pair/complete', {
      pairingCode,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
      name: "Ryan's iPhone",
    });
    expect(completeResult.status).toBe(200);

    const pairMsgs = agentWs.messagesOfType('pair_complete');
    expect(pairMsgs).toHaveLength(1);
    expect(pairMsgs[0]['mobileName']).toBe("Ryan's iPhone");
  });

  it('omits mobileName when not provided', async () => {
    const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';
    const { doInstance: do2, mockState } = await createTestDOFull();

    const keys = await generateEd25519Keypair();
    const kp = keys.keyPair;
    const pubBase64 = bytesToBase64(keys.publicKeyRaw);

    async function post(path: string, body: unknown) {
      const req = new Request(`http://localhost${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const res = await do2.fetch(req);
      return { status: res.status, data: await res.json() as Record<string, unknown> };
    }

    // Initiate pairing
    const initBody = await signedPairInitiateBody('agent-1', kp, pubBase64, 'x25519-pub-key-agent');
    const initResult = await post('/pair/initiate', initBody);
    const pairingCode = initResult.data['pairingCode'] as string;

    // Connect host WebSocket
    const token = await createJWT('agent-1', 'host', JWT_SECRET);
    const agentWs = new MockWebSocket();
    mockState.acceptedWebSockets.push(agentWs as unknown as WebSocket);
    await do2.webSocketMessage(agentWs as unknown as WebSocket, JSON.stringify({ type: 'auth', token }));
    agentWs.sent.length = 0;

    // Complete pairing WITHOUT name
    await post('/pair/complete', {
      pairingCode,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });

    const pairMsgs = agentWs.messagesOfType('pair_complete');
    expect(pairMsgs).toHaveLength(1);
    expect(pairMsgs[0]['mobileName']).toBeUndefined();
  });

  it('ignores mobile name over 64 chars', async () => {
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    const initResult = await postJSON('/pair/initiate', body);
    const pairingCode = initResult.data['pairingCode'] as string;

    const { status } = await postJSON('/pair/complete', {
      pairingCode,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
      name: 'x'.repeat(65),
    });

    expect(status).toBe(200);
    const device = doInstance.getDevice('mobile-1');
    expect(device).not.toBeNull();
    expect(device!.name).toBeNull();
  });

  it('ignores mobile name with control characters', async () => {
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    const initResult = await postJSON('/pair/initiate', body);
    const pairingCode = initResult.data['pairingCode'] as string;

    const { status } = await postJSON('/pair/complete', {
      pairingCode,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
      name: 'Evil\x1b[2JPhone',
    });

    expect(status).toBe(200);
    const device = doInstance.getDevice('mobile-1');
    expect(device).not.toBeNull();
    expect(device!.name).toBeNull();
  });

  it('same mobile re-pairing does not send device_unpaired notification', async () => {
    const { doInstance: do2, mockState } = await createTestDOFull();
    const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

    // Generate keypair for this DO instance
    const keys = await generateEd25519Keypair();
    const kp = keys.keyPair;
    const pubBase64 = bytesToBase64(keys.publicKeyRaw);

    async function post(path: string, body: unknown) {
      const req = new Request(`http://localhost${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const res = await do2.fetch(req);
      return { status: res.status, data: await res.json() as Record<string, unknown> };
    }

    // First pairing: agent-1 + mobile-1
    const initBody1 = await signedPairInitiateBody('agent-1', kp, pubBase64, 'x25519-pub-key-agent');
    const init1 = await post('/pair/initiate', initBody1);
    const code1 = init1.data['pairingCode'] as string;

    await post('/pair/complete', {
      pairingCode: code1,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile-1',
      x25519PublicKey: 'x25519-pub-key-mobile-1',
    });
    expect(do2.isPaired('agent-1', 'mobile-1')).toBe(true);

    // Connect mobile-1 via WebSocket
    const mobile1Token = await createJWT('mobile-1', 'mobile', JWT_SECRET);
    const mobile1Ws = new MockWebSocket();
    mockState.acceptedWebSockets.push(mobile1Ws as unknown as WebSocket);
    do2.setConnection('mobile-1', mobile1Ws as unknown as WebSocket);
    await do2.webSocketMessage(
      mobile1Ws as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: mobile1Token })
    );
    mobile1Ws.sent.length = 0;

    // Same mobile re-pairs with same host
    const initBody2 = await signedPairInitiateBody('agent-1', kp, pubBase64, 'x25519-pub-key-agent-2');
    const init2 = await post('/pair/initiate', initBody2);
    const code2 = init2.data['pairingCode'] as string;

    await post('/pair/complete', {
      pairingCode: code2,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile-1',
      x25519PublicKey: 'x25519-pub-key-mobile-1b',
    });

    // Pairing should still exist
    expect(do2.isPaired('agent-1', 'mobile-1')).toBe(true);

    // NO device_unpaired notification should have been sent
    const unpairedMsgs = mobile1Ws.messagesOfType('device_unpaired');
    expect(unpairedMsgs).toHaveLength(0);
  });

  it('returns 409 when a host device attempts to complete pairing as mobile', async () => {
    // Register agent-1 as a host via /pair/initiate
    const body = await signedPairInitiateBody('agent-1', keyPair, ed25519PublicKeyBase64, 'x25519-pub-key-agent');
    const initResult = await postJSON('/pair/initiate', body);
    const pairingCode = initResult.data['pairingCode'] as string;

    // Now try to complete pairing using the same device ID (agent-1) as mobile
    const { status, data } = await postJSON('/pair/complete', {
      pairingCode,
      deviceId: 'agent-1', // already registered as 'host'
      ed25519PublicKey: ed25519PublicKeyBase64,
      x25519PublicKey: 'x25519-pub-key-agent',
    });

    expect(status).toBe(409);
    expect(data['error']).toContain('Device type conflict');

    // Original device should still be a host
    const device = doInstance.getDevice('agent-1');
    expect(device).not.toBeNull();
    expect(device!.deviceType).toBe('host');
  });
});

describe('DELETE /pairing', () => {
  it('removes existing pairing and returns removed: true', async () => {
    const { doInstance: do2 } = await createTestDOFull();

    const keys = await generateEd25519Keypair();
    const kp = keys.keyPair;
    const pubBase64 = bytesToBase64(keys.publicKeyRaw);

    async function post(path: string, body: unknown) {
      const req = new Request(`http://localhost${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const res = await do2.fetch(req);
      return { status: res.status, data: await res.json() as Record<string, unknown> };
    }

    // Create pairing
    const initBody = await signedPairInitiateBody('agent-1', kp, pubBase64, 'x25519-pub-key-agent', 'my-host');
    const init = await post('/pair/initiate', initBody);
    await post('/pair/complete', {
      pairingCode: init.data['pairingCode'],
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });
    expect(do2.isPaired('agent-1', 'mobile-1')).toBe(true);

    // DELETE /pairing (simulates worker injecting X-Device-Id from JWT)
    const delReq = new Request('http://localhost/pairing', {
      method: 'DELETE',
      headers: { 'X-Device-Id': 'agent-1' },
    });
    const delRes = await do2.fetch(delReq);
    const delData = await delRes.json() as Record<string, unknown>;

    expect(delRes.status).toBe(200);
    expect(delData['removed']).toBe(true);
    expect(do2.isPaired('agent-1', 'mobile-1')).toBe(false);
  });

  it('notifies connected mobile with device_unpaired reason host_unpaired', async () => {
    const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';
    const { doInstance: do2, mockState } = await createTestDOFull();

    const keys = await generateEd25519Keypair();
    const kp = keys.keyPair;
    const pubBase64 = bytesToBase64(keys.publicKeyRaw);

    async function post(path: string, body: unknown) {
      const req = new Request(`http://localhost${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const res = await do2.fetch(req);
      return { status: res.status, data: await res.json() as Record<string, unknown> };
    }

    // Create pairing
    const initBody = await signedPairInitiateBody('agent-1', kp, pubBase64, 'x25519-pub-key-agent', 'my-host');
    const init = await post('/pair/initiate', initBody);
    await post('/pair/complete', {
      pairingCode: init.data['pairingCode'],
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });

    // Connect mobile via WebSocket
    const mobileToken = await createJWT('mobile-1', 'mobile', JWT_SECRET);
    const mobileWs = new MockWebSocket();
    mockState.acceptedWebSockets.push(mobileWs as unknown as WebSocket);
    await do2.webSocketMessage(
      mobileWs as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: mobileToken })
    );
    mobileWs.sent.length = 0;

    // DELETE /pairing
    const delReq = new Request('http://localhost/pairing', {
      method: 'DELETE',
      headers: { 'X-Device-Id': 'agent-1' },
    });
    await do2.fetch(delReq);

    // Mobile should receive device_unpaired with reason 'host_unpaired'
    const unpairedMsgs = mobileWs.messagesOfType('device_unpaired');
    expect(unpairedMsgs).toHaveLength(1);
    expect(unpairedMsgs[0]!['reason']).toBe('host_unpaired');
    expect(unpairedMsgs[0]!['hostDeviceId']).toBe('agent-1');
    expect(unpairedMsgs[0]!['hostName']).toBe('my-host');
  });

  it('returns removed: false when no pairing exists', async () => {
    const { doInstance: do2 } = await createTestDOFull();

    // Register a host device but don't pair it
    const keys = await generateEd25519Keypair();
    const kp = keys.keyPair;
    const pubBase64 = bytesToBase64(keys.publicKeyRaw);
    const initBody = await signedPairInitiateBody('agent-1', kp, pubBase64, 'x25519-pub-key-agent');
    await do2.fetch(new Request('http://localhost/pair/initiate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(initBody),
    }));

    // DELETE without completing pairing
    const delReq = new Request('http://localhost/pairing', {
      method: 'DELETE',
      headers: { 'X-Device-Id': 'agent-1' },
    });
    const delRes = await do2.fetch(delReq);
    const delData = await delRes.json() as Record<string, unknown>;

    expect(delRes.status).toBe(200);
    expect(delData['removed']).toBe(false);
  });

  it('rejects non-DELETE methods with 405', async () => {
    const req = new Request('http://localhost/pairing', {
      method: 'GET',
    });
    const res = await doInstance.fetch(req);

    expect(res.status).toBe(405);
    expect(res.headers.get('Allow')).toBe('DELETE');
  });

  it('returns 400 when X-Device-Id header is missing', async () => {
    const delReq = new Request('http://localhost/pairing', {
      method: 'DELETE',
    });
    const delRes = await doInstance.fetch(delReq);
    const delData = await delRes.json() as Record<string, unknown>;

    expect(delRes.status).toBe(400);
    expect(delData['error']).toContain('Missing device ID');
  });
});
