import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createTestDOCompat as createTestDO, createTestDO as createTestDOFull } from './helpers/mock-do';
import { MockWebSocket } from './helpers/mock-websocket';
import { createJWT } from '../auth';
import { generateEd25519Keypair, bytesToBase64, signEd25519, signedPairInitiateBodyWithChallenge, HOST_X25519_KEY } from './helpers/crypto';
import type { SignalingDO } from '../signaling';

// Valid 32-hex device ID for agent (format: hex(SHA-256(publicKey)[0:16]))
const AGENT_1 = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1';

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
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    const { status, data } = await postJSON('/pair/initiate', body);

    expect(status).toBe(200);
    expect(data['pairingCode']).toBeTypeOf('string');
    expect((data['pairingCode'] as string).length).toBe(6);
  });

  it('registers the agent device', async () => {
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    await postJSON('/pair/initiate', body);

    const device = doInstance.getDevice(AGENT_1);
    expect(device).not.toBeNull();
    expect(device!.deviceType).toBe('host');
    expect(device!.ed25519PublicKey).toBe(ed25519PublicKeyBase64);
  });

  it('rejects invalid JSON body on initiate', async () => {
    const request = new Request('http://localhost/pair/initiate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not valid json{{{',
    });
    const response = await doInstance.fetch(request);
    const data = await response.json() as Record<string, unknown>;

    expect(response.status).toBe(400);
    expect(data['error']).toContain('Invalid JSON');
  });

  it('rejects missing fields', async () => {
    const { status, data } = await postJSON('/pair/initiate', {
      deviceId: AGENT_1,
      // missing publicKey, x25519PublicKey, timestamp, signature
    });

    expect(status).toBe(400);
    expect(data['error']).toContain('Missing required fields');
  });

  it('stores host name when provided', async () => {
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY, 'my-workstation');
    await postJSON('/pair/initiate', body);

    const device = doInstance.getDevice(AGENT_1);
    expect(device).not.toBeNull();
    expect(device!.name).toBe('my-workstation');
  });

  it('updates name on re-initiation', async () => {
    // First initiation with name
    const body1 = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY, 'old-name');
    await postJSON('/pair/initiate', body1);

    // Second initiation with a new name (device already exists)
    const body2 = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY, 'new-name');
    await postJSON('/pair/initiate', body2);

    const device = doInstance.getDevice(AGENT_1);
    expect(device!.name).toBe('new-name');
  });

  it('stores null name when not provided', async () => {
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    await postJSON('/pair/initiate', body);

    const device = doInstance.getDevice(AGENT_1);
    expect(device!.name).toBeNull();
  });

  it('rejects name longer than 64 characters', async () => {
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY, 'x'.repeat(65));
    const { status, data } = await postJSON('/pair/initiate', body);

    expect(status).toBe(400);
    expect(data['error']).toContain('64 characters');
  });

  it('accepts name exactly 64 characters on initiate', async () => {
    const exactName = 'a'.repeat(64);
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY, exactName);
    const { status } = await postJSON('/pair/initiate', body);

    expect(status).toBe(200);
    const device = doInstance.getDevice(AGENT_1);
    expect(device!.name).toBe(exactName);
  });

  it('rejects name with ESC control character on initiate', async () => {
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY, 'Evil\x1b[2JName');
    const { status, data } = await postJSON('/pair/initiate', body);

    expect(status).toBe(400);
    expect(data['error']).toContain('control characters');
  });

  it('rejects initiation with wrong key for existing device', async () => {
    // First initiation registers the device with keyPair (keyA)
    const body1 = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY, 'original-name');
    await postJSON('/pair/initiate', body1);

    // Generate a second keypair (keyB)
    const keysB = await generateEd25519Keypair();
    const pubB = bytesToBase64(keysB.publicKeyRaw);

    // Second initiation uses keyB's public key and signature — should fail
    // because signature from keyB won't verify against stored keyA
    const body2 = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keysB.keyPair, pubB, HOST_X25519_KEY, 'spoofed-name');
    const { status, data } = await postJSON('/pair/initiate', body2);

    expect(status).toBe(401);
    expect(data['error']).toContain('Signature verification failed');
  });

  it('invalidates previous pairing code when re-initiating', async () => {
    // First initiation — get a pairing code
    const body1 = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    const first = await postJSON('/pair/initiate', body1);
    expect(first.status).toBe(200);
    const firstCode = first.data['pairingCode'] as string;

    // Second initiation — same host, new code replaces the old one
    const body2 = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
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
    expect(completeSecond.data['hostDeviceId']).toBe(AGENT_1);
  });

  it('rejects missing nonce and signature', async () => {
    const { status, data } = await postJSON('/pair/initiate', {
      deviceId: AGENT_1,
      ed25519PublicKey: ed25519PublicKeyBase64,
      x25519PublicKey: 'x25519-pub-key-agent',
    });

    expect(status).toBe(400);
    expect(data['error']).toContain('Missing required fields');
  });

  it('rejects invalid signature', async () => {
    const { fetchChallenge: fc } = await import('./helpers/crypto');
    const nonce = await fc(doInstance, AGENT_1);
    const badSig = bytesToBase64(new Uint8Array(64));
    const { status, data } = await postJSON('/pair/initiate', {
      deviceId: AGENT_1,
      ed25519PublicKey: ed25519PublicKeyBase64,
      x25519PublicKey: HOST_X25519_KEY,
      nonce,
      signature: badSig,
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Signature verification failed');
  });

  it('rejects an expired nonce', async () => {
    const { fetchChallenge: fc } = await import('./helpers/crypto');
    const nonce = await fc(doInstance, AGENT_1);

    // Advance time past 60s challenge TTL
    const realDateNow = Date.now;
    Date.now = () => realDateNow() + 70_000;

    try {
      const message = new TextEncoder().encode(AGENT_1 + '|' + nonce);
      const sig = await signEd25519(keyPair.privateKey, message);

      const { status, data } = await postJSON('/pair/initiate', {
        deviceId: AGENT_1,
        ed25519PublicKey: ed25519PublicKeyBase64,
        x25519PublicKey: HOST_X25519_KEY,
        nonce,
        signature: bytesToBase64(sig),
      });

      expect(status).toBe(401);
      expect(data['error']).toContain('Invalid or expired challenge');
    } finally {
      Date.now = realDateNow;
    }
  });

  it('rejects a replayed nonce at pair/initiate', async () => {
    // Use the nonce once successfully
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    const first = await postJSON('/pair/initiate', body);
    expect(first.status).toBe(200);

    // Try to reuse the same nonce (it's already been consumed)
    const { status, data } = await postJSON('/pair/initiate', body);
    expect(status).toBe(401);
    expect(data['error']).toContain('Invalid or expired challenge');
  });
});

describe('POST /pair/initiate input validation', () => {
  async function initiateWith(overrides: Record<string, unknown>, existing = false) {
    if (existing) {
      const first = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
      expect((await postJSON('/pair/initiate', first)).status).toBe(200);
    }
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    return postJSON('/pair/initiate', { ...body, ...overrides });
  }

  it('returns 401 for a non-base64 signature on a new host', async () => {
    const { status, data } = await initiateWith({ signature: '!!!' });
    expect(status).toBe(401);
    expect(data['error']).toBe('Invalid signature format');
  });

  it('returns 401 for a non-base64 signature on an existing host', async () => {
    const { status, data } = await initiateWith({ signature: '!!!' }, true);
    expect(status).toBe(401);
    expect(data['error']).toBe('Invalid signature format');
  });

  it('returns 401 for a non-base64 ed25519PublicKey on a new host', async () => {
    const { status, data } = await initiateWith({ ed25519PublicKey: '!!!' });
    expect(status).toBe(401);
    expect(data['error']).toBe('Invalid signature format');
  });

  it.each([
    ['non-base64', '!!!'],
    ['wrong length', bytesToBase64(new Uint8Array(16))],
    ['non-string', 42],
  ])('returns 400 for a %s x25519PublicKey without burning the nonce', async (_label, value) => {
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    const bad = await postJSON('/pair/initiate', { ...body, x25519PublicKey: value });
    expect(bad.status).toBe(400);
    expect(bad.data['error']).toBe('Invalid x25519PublicKey');
    expect((await postJSON('/pair/initiate', body)).status).toBe(200);
  });

  it('returns 400 for a malformed ed25519PublicKey on an existing host', async () => {
    const { status, data } = await initiateWith({ ed25519PublicKey: 'not-a-key' }, true);
    expect(status).toBe(400);
    expect(data['error']).toBe('Invalid ed25519PublicKey');
  });
});

describe('DO fetch never rejects on malformed bodies', () => {
  const routes: Array<[string, string]> = [
    ['POST', '/challenge'],
    ['POST', '/pair/initiate'],
    ['POST', '/pair/complete'],
    ['POST', '/token'],
    ['DELETE', '/pairing'],
    ['DELETE', '/device'],
  ];
  const bodies: unknown[] = [
    null,
    42,
    'str',
    [],
    {},
    { deviceId: 5, nonce: {}, signature: [], ed25519PublicKey: 1, x25519PublicKey: 2, pairingCode: 3, name: 4 },
    { deviceId: AGENT_1, nonce: 'n', signature: '!!!', ed25519PublicKey: '!!!', x25519PublicKey: '!!!', pairingCode: 'ABCDEF' },
  ];

  it.each(routes)('%s %s resolves for every body shape', async (method, path) => {
    for (const body of bodies) {
      const response = await doInstance.fetch(new Request(`http://localhost${path}`, {
        method,
        headers: { 'Content-Type': 'application/json', 'X-Device-Id': AGENT_1, 'X-Device-Type': 'host' },
        body: JSON.stringify(body),
      }));
      expect(response.status).toBeGreaterThanOrEqual(200);
      expect(response.status).toBeLessThan(600);
    }
  });
});

describe('POST /pair/initiate code collisions', () => {
  const AGENT_2 = 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2';

  // Zero bytes always generate the same code ('AAAAAA'), forcing collisions.
  function forceConstantCode(): void {
    vi.spyOn(crypto, 'getRandomValues').mockImplementation(<T extends ArrayBufferView | null>(array: T): T => {
      if (array) new Uint8Array(array.buffer, array.byteOffset, array.byteLength).fill(0);
      return array;
    });
  }

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns 503 without touching the host existing state when every code collides', async () => {
    // AGENT_1 has an existing session with a random code.
    const first = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    const { data: firstData } = await postJSON('/pair/initiate', first);
    const existingCode = firstData['pairingCode'] as string;

    // Another host holds the only code the generator can now produce.
    forceConstantCode();
    doInstance.createPairingSession(AGENT_2, 'x25519-other', 'ed-other');
    const settleSpy = vi.spyOn(doInstance as unknown as { settlePendingPair: () => void }, 'settlePendingPair');
    const sqlStore = (doInstance as unknown as { sql: { exec: (q: string, ...b: unknown[]) => unknown } }).sql;
    const execSpy = vi.spyOn(sqlStore, 'exec');
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const second = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    execSpy.mockClear();
    const { status, data } = await postJSON('/pair/initiate', second);

    expect(status).toBe(503);
    expect(data['error']).toBe('Pairing temporarily unavailable');
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('[pair]'));
    expect(settleSpy).not.toHaveBeenCalled();
    const deletes = execSpy.mock.calls.filter(([q]) => typeof q === 'string' && q.startsWith('DELETE FROM pairing_sessions WHERE host_device_id'));
    expect(deletes).toHaveLength(0);
    const pendingDeletes = execSpy.mock.calls.filter(([q]) => typeof q === 'string' && q.startsWith('DELETE FROM pending_pair_complete'));
    expect(pendingDeletes).toHaveLength(0);

    const rows = (sqlStore.exec('SELECT code FROM pairing_sessions WHERE host_device_id = ?', AGENT_1) as { toArray(): Array<{ code: string }> }).toArray();
    expect(rows.map((r) => r.code)).toEqual([existingCode]);
  });

  it('does not treat the host own existing code as a collision', async () => {
    forceConstantCode();
    const first = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    const { status: s1, data: d1 } = await postJSON('/pair/initiate', first);
    expect(s1).toBe(200);

    const second = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    const { status: s2, data: d2 } = await postJSON('/pair/initiate', second);
    expect(s2).toBe(200);
    expect(d2['pairingCode']).toBe(d1['pairingCode']);
  });
});

describe('POST /pair/complete', () => {
  it('completes pairing flow successfully', async () => {
    // Step 1: Agent initiates pairing
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
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
    expect(data['hostX25519PublicKey']).toBe(HOST_X25519_KEY);
    expect(data['hostDeviceId']).toBe(AGENT_1);
    // userId should NOT be in the response
    expect(data['userId']).toBeUndefined();
  });

  it('creates a pairing between host and mobile', async () => {
    // Initiate
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    const initResult = await postJSON('/pair/initiate', body);

    // Complete
    await postJSON('/pair/complete', {
      pairingCode: initResult.data['pairingCode'],
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });

    // Verify pairing exists
    expect(doInstance.isPaired(AGENT_1, 'mobile-1')).toBe(true);
    expect(doInstance.getPairedMobile(AGENT_1)).toBe('mobile-1');
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
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
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
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
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
    const initBody = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, kp, pubBase64, HOST_X25519_KEY);
    const initResult = await post('/pair/initiate', initBody);
    expect(initResult.status).toBe(200);
    const pairingCode = initResult.data['pairingCode'] as string;

    // Create two WebSockets for the same host device (background agent + pair CLI)
    const token = await createJWT(AGENT_1, 'host', JWT_SECRET);

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

  describe('deferred pair_complete delivery (SB-1002)', () => {
    const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

    // Shared setup: initiate + complete pairing on a fresh DO, optionally with
    // a live host WebSocket connected during /pair/complete.
    async function setupPairing(withLiveHostWs: boolean, mobileName?: string, pairMac?: string | null) {
      const { doInstance: do2, mockState } = await createTestDOFull();
      const keys = await generateEd25519Keypair();
      const pubBase64 = bytesToBase64(keys.publicKeyRaw);
      const keyPairForHost = keys.keyPair;

      async function post(path: string, body: unknown) {
        const req = new Request(`http://localhost${path}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        const res = await do2.fetch(req);
        return { status: res.status, data: await res.json() as Record<string, unknown> };
      }

      const initBody = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, keys.keyPair, pubBase64, HOST_X25519_KEY);
      const initResult = await post('/pair/initiate', initBody);
      expect(initResult.status).toBe(200);

      const token = await createJWT(AGENT_1, 'host', JWT_SECRET);

      async function authHostWs(): Promise<MockWebSocket> {
        const ws = new MockWebSocket();
        mockState.acceptedWebSockets.push(ws as unknown as WebSocket);
        await do2.webSocketMessage(ws as unknown as WebSocket, JSON.stringify({ type: 'auth', token }));
        return ws;
      }

      let liveWs: MockWebSocket | null = null;
      if (withLiveHostWs) {
        liveWs = await authHostWs();
        liveWs.sent.length = 0;
      }

      const completeResult = await post('/pair/complete', {
        pairingCode: initResult.data['pairingCode'] as string,
        deviceId: 'mobile-1',
        ed25519PublicKey: 'ed25519-pub-key-mobile',
        x25519PublicKey: 'x25519-pub-key-mobile',
        ...(mobileName !== undefined && { name: mobileName }),
        ...(pairMac !== undefined && { pairMac }),
      });
      expect(completeResult.status).toBe(200);

      async function initiate() {
        const reInitBody = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, keyPairForHost, pubBase64, HOST_X25519_KEY);
        const reInit = await post('/pair/initiate', reInitBody);
        expect(reInit.status).toBe(200);
        return reInit;
      }

      // Re-initiate + complete with a different mobile (host still offline)
      async function repairWith(deviceId: string, x25519PublicKey: string) {
        const reInit = await initiate();
        const res = await post('/pair/complete', {
          pairingCode: reInit.data['pairingCode'] as string,
          deviceId,
          ed25519PublicKey: `ed25519-pub-key-${deviceId}`,
          x25519PublicKey,
        });
        expect(res.status).toBe(200);
      }

      return { do2, authHostWs, liveWs, repairWith, initiate, post, initResult };
    }

    it('delivers pair_complete on next host WS auth when host was offline', async () => {
      const { authHostWs } = await setupPairing(false);

      const hostWs = await authHostWs();
      const msgs = hostWs.messagesOfType('pair_complete');
      expect(msgs).toHaveLength(1);
      expect(msgs[0]['mobileDeviceId']).toBe('mobile-1');
      expect(msgs[0]['mobileX25519PublicKey']).toBe('x25519-pub-key-mobile');
    });

    it('sends the auth reply before the deferred pair_complete', async () => {
      const { authHostWs } = await setupPairing(false);

      const hostWs = await authHostWs();
      const types = hostWs.sent.map((m) => (m as { type: string }).type);
      expect(types.indexOf('auth')).toBeGreaterThanOrEqual(0);
      expect(types.indexOf('auth')).toBeLessThan(types.indexOf('pair_complete'));
    });

    it('delivers the deferred pair_complete only once', async () => {
      const { authHostWs } = await setupPairing(false);

      const firstWs = await authHostWs();
      expect(firstWs.messagesOfType('pair_complete')).toHaveLength(1);

      const secondWs = await authHostWs();
      expect(secondWs.messagesOfType('pair_complete')).toHaveLength(0);
    });

    it('does not persist pair_complete when delivered to a live host WS', async () => {
      const { authHostWs, liveWs } = await setupPairing(true);

      expect(liveWs!.messagesOfType('pair_complete')).toHaveLength(1);

      // Reconnecting must not produce a duplicate
      const reconnectWs = await authHostWs();
      expect(reconnectWs.messagesOfType('pair_complete')).toHaveLength(0);
    });

    it('does not deliver a stale pair_complete after the pairing was removed', async () => {
      const { do2, authHostWs } = await setupPairing(false);

      do2.removePairing(AGENT_1);

      const hostWs = await authHostWs();
      expect(hostWs.messagesOfType('pair_complete')).toHaveLength(0);

      // Row is consumed even when stale — a later auth stays clean too
      const laterWs = await authHostWs();
      expect(laterWs.messagesOfType('pair_complete')).toHaveLength(0);
    });

    it('propagates mobileName through the deferred path', async () => {
      const { authHostWs } = await setupPairing(false, 'my-phone');

      const hostWs = await authHostWs();
      const msgs = hostWs.messagesOfType('pair_complete');
      expect(msgs).toHaveLength(1);
      expect(msgs[0]['mobileName']).toBe('my-phone');
    });

    it('omits mobileName in the deferred message when not provided', async () => {
      const { authHostWs } = await setupPairing(false);

      const hostWs = await authHostWs();
      const msgs = hostWs.messagesOfType('pair_complete');
      expect(msgs).toHaveLength(1);
      expect('mobileName' in msgs[0]).toBe(false);
    });

    // 32-byte MAC, standard base64 with padding
    const VALID_PAIR_MAC = 'A'.repeat(43) + '=';

    it('relays pairMac on the live path', async () => {
      const { liveWs } = await setupPairing(true, undefined, VALID_PAIR_MAC);

      const msgs = liveWs!.messagesOfType('pair_complete');
      expect(msgs).toHaveLength(1);
      expect(msgs[0]['pairMac']).toBe(VALID_PAIR_MAC);
    });

    it('persists pairMac and delivers it exactly once on the deferred path', async () => {
      const { authHostWs } = await setupPairing(false, undefined, VALID_PAIR_MAC);

      const firstWs = await authHostWs();
      const msgs = firstWs.messagesOfType('pair_complete');
      expect(msgs).toHaveLength(1);
      expect(msgs[0]['pairMac']).toBe(VALID_PAIR_MAC);

      const secondWs = await authHostWs();
      expect(secondWs.messagesOfType('pair_complete')).toHaveLength(0);
    });

    it('omits pairMac from live and deferred payloads when absent', async () => {
      const live = await setupPairing(true);
      const liveMsgs = live.liveWs!.messagesOfType('pair_complete');
      expect(liveMsgs).toHaveLength(1);
      expect('pairMac' in liveMsgs[0]).toBe(false);

      const deferred = await setupPairing(false);
      const hostWs = await deferred.authHostWs();
      const msgs = hostWs.messagesOfType('pair_complete');
      expect(msgs).toHaveLength(1);
      expect('pairMac' in msgs[0]).toBe(false);
    });

    it.each([
      ['base64url', 'A'.repeat(42) + '-_'],
      ['unpadded', 'A'.repeat(43)],
      ['64 chars', 'A'.repeat(64)],
    ])('relays a non-canonical pairMac (%s) verbatim', async (_label, mac) => {
      const { liveWs } = await setupPairing(true, undefined, mac);

      const msgs = liveWs!.messagesOfType('pair_complete');
      expect(msgs).toHaveLength(1);
      expect(msgs[0]['pairMac']).toBe(mac);
    });

    it('treats a null pairMac as absent', async () => {
      const { liveWs } = await setupPairing(true, undefined, null);

      const msgs = liveWs!.messagesOfType('pair_complete');
      expect(msgs).toHaveLength(1);
      expect('pairMac' in msgs[0]).toBe(false);
    });

    it.each([
      ['non-string', 12345],
      ['over 64 chars', 'A'.repeat(65)],
      ['bad charset', 'not base64!!'],
      ['empty string', ''],
    ])('rejects a malformed pairMac (%s) with 400', async (_label, badMac) => {
      const { post, initResult } = await setupPairing(false);

      // initResult's code is already spent, so only pairMac validation can fail here
      const res = await post('/pair/complete', {
        pairingCode: initResult.data['pairingCode'] as string,
        deviceId: 'mobile-bad',
        ed25519PublicKey: 'ed25519-pub-key-bad',
        x25519PublicKey: 'x25519-pub-key-bad',
        pairMac: badMac,
      });
      expect(res.status).toBe(400);
      expect(res.data['error']).toBe('Invalid pairMac');
    });

    it('migrates a pending_pair_complete table created before mobile_pair_mac', async () => {
      const { doInstance: do2 } = await createTestDOFull();
      const sql = do2['sql'];
      sql.exec(`CREATE TABLE pending_pair_complete (
        host_device_id TEXT PRIMARY KEY,
        mobile_device_id TEXT NOT NULL,
        mobile_x25519_public_key TEXT NOT NULL,
        mobile_name TEXT,
        created_at INTEGER NOT NULL
      )`);

      do2.createPairingSession(AGENT_1, 'x25519-pub-key-agent', 'ed-pub-key-agent'); // runs ensureSchema

      const cols = sql.exec('PRAGMA table_info(pending_pair_complete)').toArray().map((c) => c['name']);
      expect(cols).toContain('mobile_pair_mac');
    });

    it('drops a pending pair_complete when the host initiates a new pairing', async () => {
      const { authHostWs, initiate } = await setupPairing(false, undefined, VALID_PAIR_MAC);

      // The new pair CLI must not receive the earlier attempt's pair_complete,
      // whose pairMac was computed with the old pairing secret.
      await initiate();

      const hostWs = await authHostWs();
      expect(hostWs.messagesOfType('pair_complete')).toHaveLength(0);
    });

    it('re-pairing while host is offline overwrites the pending row', async () => {
      const { authHostWs, repairWith } = await setupPairing(false);

      // Second pairing (mobile-2) completes before the host ever reconnects
      await repairWith('mobile-2', 'x25519-pub-key-mobile-2');

      const hostWs = await authHostWs();
      const msgs = hostWs.messagesOfType('pair_complete');
      expect(msgs).toHaveLength(1);
      expect(msgs[0]['mobileDeviceId']).toBe('mobile-2');
      expect(msgs[0]['mobileX25519PublicKey']).toBe('x25519-pub-key-mobile-2');
    });
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
    const initBody1 = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, kp, pubBase64, HOST_X25519_KEY);
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
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(true);

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
    const initBody2 = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, kp, pubBase64, HOST_X25519_KEY);
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
    expect(do2.isPaired(AGENT_1, 'mobile-2')).toBe(true);
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(false);

    // Old mobile should have received device_unpaired notification
    const unpairedMsgs = mobile1Ws.messagesOfType('device_unpaired');
    expect(unpairedMsgs).toHaveLength(1);
    expect(unpairedMsgs[0]!['hostDeviceId']).toBe(AGENT_1);
    expect(unpairedMsgs[0]!['reason']).toBe('replaced_by_new_pairing');
  });

  it('stores mobile name from /pair/complete', async () => {
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
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
    const initBody = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, kp, pubBase64, HOST_X25519_KEY);
    const initResult = await post('/pair/initiate', initBody);
    expect(initResult.status).toBe(200);
    const pairingCode = initResult.data['pairingCode'] as string;

    // Connect host WebSocket
    const token = await createJWT(AGENT_1, 'host', JWT_SECRET);
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
    const initBody = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, kp, pubBase64, HOST_X25519_KEY);
    const initResult = await post('/pair/initiate', initBody);
    const pairingCode = initResult.data['pairingCode'] as string;

    // Connect host WebSocket
    const token = await createJWT(AGENT_1, 'host', JWT_SECRET);
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
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
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
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
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
    const initBody1 = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, kp, pubBase64, HOST_X25519_KEY);
    const init1 = await post('/pair/initiate', initBody1);
    const code1 = init1.data['pairingCode'] as string;

    await post('/pair/complete', {
      pairingCode: code1,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile-1',
      x25519PublicKey: 'x25519-pub-key-mobile-1',
    });
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(true);

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
    const initBody2 = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, kp, pubBase64, HOST_X25519_KEY);
    const init2 = await post('/pair/initiate', initBody2);
    const code2 = init2.data['pairingCode'] as string;

    await post('/pair/complete', {
      pairingCode: code2,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile-1',
      x25519PublicKey: 'x25519-pub-key-mobile-1b',
    });

    // Pairing should still exist
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(true);

    // NO device_unpaired notification should have been sent
    const unpairedMsgs = mobile1Ws.messagesOfType('device_unpaired');
    expect(unpairedMsgs).toHaveLength(0);
  });

  it('returns 409 when a host device attempts to complete pairing as mobile', async () => {
    // Register agent-1 as a host via /pair/initiate
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
    const initResult = await postJSON('/pair/initiate', body);
    const pairingCode = initResult.data['pairingCode'] as string;

    // Now try to complete pairing using the same device ID (agent-1) as mobile
    const { status, data } = await postJSON('/pair/complete', {
      pairingCode,
      deviceId: AGENT_1, // already registered as 'host'
      ed25519PublicKey: ed25519PublicKeyBase64,
      x25519PublicKey: 'x25519-pub-key-agent',
    });

    expect(status).toBe(409);
    expect(data['error']).toBe('Device conflict: device cannot be registered');

    // Original device should still be a host
    const device = doInstance.getDevice(AGENT_1);
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
    const initBody = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, kp, pubBase64, HOST_X25519_KEY, 'my-host');
    const init = await post('/pair/initiate', initBody);
    await post('/pair/complete', {
      pairingCode: init.data['pairingCode'],
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(true);

    // DELETE /pairing (simulates worker injecting X-Device-Id from JWT)
    const delReq = new Request('http://localhost/pairing', {
      method: 'DELETE',
      headers: { 'X-Device-Id': AGENT_1 },
    });
    const delRes = await do2.fetch(delReq);
    const delData = await delRes.json() as Record<string, unknown>;

    expect(delRes.status).toBe(200);
    expect(delData['removed']).toBe(true);
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(false);
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
    const initBody = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, kp, pubBase64, HOST_X25519_KEY, 'my-host');
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
      headers: { 'X-Device-Id': AGENT_1 },
    });
    await do2.fetch(delReq);

    // Mobile should receive device_unpaired with reason 'host_unpaired'
    const unpairedMsgs = mobileWs.messagesOfType('device_unpaired');
    expect(unpairedMsgs).toHaveLength(1);
    expect(unpairedMsgs[0]!['reason']).toBe('host_unpaired');
    expect(unpairedMsgs[0]!['hostDeviceId']).toBe(AGENT_1);
    expect(unpairedMsgs[0]!['hostName']).toBe('my-host');
  });

  it('returns removed: false when no pairing exists', async () => {
    const { doInstance: do2 } = await createTestDOFull();

    // Register a host device but don't pair it
    const keys = await generateEd25519Keypair();
    const kp = keys.keyPair;
    const pubBase64 = bytesToBase64(keys.publicKeyRaw);
    const initBody = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, kp, pubBase64, HOST_X25519_KEY);
    await do2.fetch(new Request('http://localhost/pair/initiate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(initBody),
    }));

    // DELETE without completing pairing
    const delReq = new Request('http://localhost/pairing', {
      method: 'DELETE',
      headers: { 'X-Device-Id': AGENT_1 },
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
