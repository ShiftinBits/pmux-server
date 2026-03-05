import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDOCompat as createTestDO } from './helpers/mock-do';
import { verifyJWT } from '../auth';
import { generateEd25519Keypair, bytesToBase64, signEd25519, signedPairInitiateBody } from './helpers/crypto';
import type { SignalingDO } from '../signaling';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

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
  const body = await signedPairInitiateBody(deviceId, keyPair, ed25519PublicKeyBase64, 'x25519-placeholder');
  await postJSON('/pair/initiate', body);
}

describe('POST /token', () => {
  it('issues a JWT for a valid signature', async () => {
    const { keyPair, publicKeyRaw } = await generateEd25519Keypair();
    const ed25519PublicKeyBase64 = bytesToBase64(publicKeyRaw);

    // Register device
    await registerAgentDevice('agent-1', ed25519PublicKeyBase64, keyPair);

    // Create signature
    const timestamp = String(Math.floor(Date.now() / 1000));
    const message = new TextEncoder().encode('agent-1' + timestamp);
    const signature = await signEd25519(keyPair.privateKey, message);
    const signatureBase64 = bytesToBase64(signature);

    // Exchange for token
    const { status, data } = await postJSON('/token', {
      deviceId: 'agent-1',
      timestamp,
      signature: signatureBase64,
    });

    expect(status).toBe(200);
    expect(data['token']).toBeTypeOf('string');

    // Verify the issued JWT
    const payload = await verifyJWT(data['token'] as string, JWT_SECRET);
    expect(payload.deviceId).toBe('agent-1');
    expect(payload.deviceType).toBe('host');
  });

  it('rejects an invalid signature', async () => {
    const { publicKeyRaw, keyPair } = await generateEd25519Keypair();
    const ed25519PublicKeyBase64 = bytesToBase64(publicKeyRaw);

    await registerAgentDevice('agent-1', ed25519PublicKeyBase64, keyPair);

    // Use a garbage signature
    const badSig = bytesToBase64(new Uint8Array(64));
    const { status, data } = await postJSON('/token', {
      deviceId: 'agent-1',
      timestamp: String(Math.floor(Date.now() / 1000)),
      signature: badSig,
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Signature verification failed');
  });

  it('rejects an unknown device', async () => {
    const { status, data } = await postJSON('/token', {
      deviceId: 'nonexistent',
      timestamp: String(Math.floor(Date.now() / 1000)),
      signature: bytesToBase64(new Uint8Array(64)),
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Unknown device');
  });

  it('rejects missing fields', async () => {
    const { status, data } = await postJSON('/token', {
      deviceId: 'agent-1',
      // missing timestamp and signature
    });

    expect(status).toBe(400);
    expect(data['error']).toContain('Missing required fields');
  });

  it('rejects a stale timestamp (replay attack)', async () => {
    const { keyPair, publicKeyRaw } = await generateEd25519Keypair();
    const ed25519PublicKeyBase64 = bytesToBase64(publicKeyRaw);

    await registerAgentDevice('agent-1', ed25519PublicKeyBase64, keyPair);

    // Use a timestamp from 10 minutes ago
    const staleTimestamp = String(Math.floor(Date.now() / 1000) - 600);
    const message = new TextEncoder().encode('agent-1' + staleTimestamp);
    const signature = await signEd25519(keyPair.privateKey, message);
    const signatureBase64 = bytesToBase64(signature);

    const { status, data } = await postJSON('/token', {
      deviceId: 'agent-1',
      timestamp: staleTimestamp,
      signature: signatureBase64,
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Timestamp out of range');
  });

  it('rejects a future timestamp', async () => {
    const { keyPair, publicKeyRaw } = await generateEd25519Keypair();
    const ed25519PublicKeyBase64 = bytesToBase64(publicKeyRaw);

    await registerAgentDevice('agent-1', ed25519PublicKeyBase64, keyPair);

    // Use a timestamp 10 minutes in the future
    const futureTimestamp = String(Math.floor(Date.now() / 1000) + 600);
    const message = new TextEncoder().encode('agent-1' + futureTimestamp);
    const signature = await signEd25519(keyPair.privateKey, message);
    const signatureBase64 = bytesToBase64(signature);

    const { status, data } = await postJSON('/token', {
      deviceId: 'agent-1',
      timestamp: futureTimestamp,
      signature: signatureBase64,
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Timestamp out of range');
  });
});
