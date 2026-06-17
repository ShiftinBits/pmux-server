import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDOCompat as createTestDO } from './helpers/mock-do';
import { verifyJWT } from '../auth';
import {
  generateEd25519Keypair,
  bytesToBase64,
  signEd25519,
  signedPairInitiateBodyWithChallenge,
  fetchChallenge,
} from './helpers/crypto';
import type { SignalingDO } from '../signaling';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

// Valid 32-hex device IDs (format: hex(SHA-256(publicKey)[0:16]))
const AGENT_1 = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1';
const AGENT_2 = 'a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2';

let doInstance: SignalingDO;

beforeEach(async () => {
  doInstance = await createTestDO();
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

/**
 * Register a device through the pairing flow so it has a stored public key.
 */
async function registerAgentDevice(
  deviceId: string,
  ed25519PublicKeyBase64: string,
  keyPair: CryptoKeyPair
) {
  const body = await signedPairInitiateBodyWithChallenge(doInstance, deviceId, keyPair, ed25519PublicKeyBase64, 'x25519-placeholder');
  await postJSON('/pair/initiate', body);
}

describe('POST /token', () => {
  it('issues a JWT for a valid nonce+signature', async () => {
    const { keyPair, publicKeyRaw } = await generateEd25519Keypair();
    const ed25519PublicKeyBase64 = bytesToBase64(publicKeyRaw);

    // Register device
    await registerAgentDevice(AGENT_1, ed25519PublicKeyBase64, keyPair);

    // Fetch a challenge nonce
    const nonce = await fetchChallenge(doInstance, AGENT_1);

    // Sign deviceId + "|" + nonce
    const message = new TextEncoder().encode(AGENT_1 + '|' + nonce);
    const signature = await signEd25519(keyPair.privateKey, message);
    const signatureBase64 = bytesToBase64(signature);

    // Exchange for token
    const { status, data } = await postJSON('/token', {
      deviceId: AGENT_1,
      nonce,
      signature: signatureBase64,
    });

    expect(status).toBe(200);
    expect(data['token']).toBeTypeOf('string');

    // Verify the issued JWT
    const payload = await verifyJWT(data['token'] as string, JWT_SECRET);
    expect(payload.deviceId).toBe(AGENT_1);
    expect(payload.deviceType).toBe('host');
  });

  it('rejects an invalid signature', async () => {
    const { publicKeyRaw, keyPair } = await generateEd25519Keypair();
    const ed25519PublicKeyBase64 = bytesToBase64(publicKeyRaw);

    await registerAgentDevice(AGENT_1, ed25519PublicKeyBase64, keyPair);

    const nonce = await fetchChallenge(doInstance, AGENT_1);

    // Use a garbage signature
    const badSig = bytesToBase64(new Uint8Array(64));
    const { status, data } = await postJSON('/token', {
      deviceId: AGENT_1,
      nonce,
      signature: badSig,
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Signature verification failed');
  });

  it('rejects an unknown device', async () => {
    const unknownId = 'dddddddddddddddddddddddddddddddd';
    const nonce = await fetchChallenge(doInstance, unknownId);
    const { status, data } = await postJSON('/token', {
      deviceId: unknownId,
      nonce,
      signature: bytesToBase64(new Uint8Array(64)),
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Unknown device');
  });

  it('rejects invalid JSON body', async () => {
    const request = new Request('http://localhost/token', {
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
    const { status, data } = await postJSON('/token', {
      deviceId: AGENT_1,
      // missing nonce and signature
    });

    expect(status).toBe(400);
    expect(data['error']).toContain('Missing required fields');
  });

  it('rejects a replayed nonce (replay attack)', async () => {
    const { keyPair, publicKeyRaw } = await generateEd25519Keypair();
    const ed25519PublicKeyBase64 = bytesToBase64(publicKeyRaw);

    await registerAgentDevice(AGENT_1, ed25519PublicKeyBase64, keyPair);

    const nonce = await fetchChallenge(doInstance, AGENT_1);
    const message = new TextEncoder().encode(AGENT_1 + '|' + nonce);
    const signature = await signEd25519(keyPair.privateKey, message);
    const signatureBase64 = bytesToBase64(signature);

    // First use — should succeed
    const first = await postJSON('/token', { deviceId: AGENT_1, nonce, signature: signatureBase64 });
    expect(first.status).toBe(200);

    // Second use with the same nonce — must be rejected. The first call deleted
    // the nonce (single-use); the device itself is unaffected.
    const replayResult = await postJSON('/token', {
      deviceId: AGENT_1,
      nonce,
      signature: signatureBase64,
    });
    expect(replayResult.status).toBe(401);
    expect(replayResult.data['error']).toContain('Invalid or expired challenge');
  });

  it('rejects a nonce issued to a different device', async () => {
    const { keyPair, publicKeyRaw } = await generateEd25519Keypair();
    const ed25519PublicKeyBase64 = bytesToBase64(publicKeyRaw);

    await registerAgentDevice(AGENT_1, ed25519PublicKeyBase64, keyPair);

    // Get a nonce for agent-2, but try to use it for agent-1
    const nonceForAgent2 = await fetchChallenge(doInstance, AGENT_2);
    const message = new TextEncoder().encode(AGENT_1 + '|' + nonceForAgent2);
    const signature = await signEd25519(keyPair.privateKey, message);

    const { status, data } = await postJSON('/token', {
      deviceId: AGENT_1,
      nonce: nonceForAgent2,
      signature: bytesToBase64(signature),
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Invalid or expired challenge');
  });
});
