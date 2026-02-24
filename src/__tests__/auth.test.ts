import { describe, it, expect, vi, afterEach } from 'vitest';
import { verifyEd25519Signature, createJWT, verifyJWT } from '../auth';

// --- Ed25519 helpers ---

async function generateEd25519Keypair() {
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const publicKeyRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', keyPair.publicKey)
  );
  return { keyPair, publicKeyRaw };
}

async function signEd25519(privateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign('Ed25519', privateKey, message);
  return new Uint8Array(sig);
}

// --- Ed25519 signature verification ---

describe('verifyEd25519Signature', () => {
  it('verifies a valid signature', async () => {
    const { keyPair, publicKeyRaw } = await generateEd25519Keypair();
    const message = new TextEncoder().encode('device123|1708700000');
    const signature = await signEd25519(keyPair.privateKey, message);

    const valid = await verifyEd25519Signature(publicKeyRaw, message, signature);
    expect(valid).toBe(true);
  });

  it('rejects a tampered signature', async () => {
    const { keyPair, publicKeyRaw } = await generateEd25519Keypair();
    const message = new TextEncoder().encode('device123|1708700000');
    const signature = await signEd25519(keyPair.privateKey, message);

    // Tamper with one byte
    signature[0] = signature[0]! ^ 0xff;

    const valid = await verifyEd25519Signature(publicKeyRaw, message, signature);
    expect(valid).toBe(false);
  });

  it('rejects signature with wrong public key', async () => {
    const keypair1 = await generateEd25519Keypair();
    const keypair2 = await generateEd25519Keypair();
    const message = new TextEncoder().encode('device123|1708700000');
    const signature = await signEd25519(keypair1.keyPair.privateKey, message);

    // Verify with wrong key
    const valid = await verifyEd25519Signature(keypair2.publicKeyRaw, message, signature);
    expect(valid).toBe(false);
  });

  it('rejects signature for different message', async () => {
    const { keyPair, publicKeyRaw } = await generateEd25519Keypair();
    const message1 = new TextEncoder().encode('device123|1708700000');
    const message2 = new TextEncoder().encode('device456|1708700000');
    const signature = await signEd25519(keyPair.privateKey, message1);

    const valid = await verifyEd25519Signature(publicKeyRaw, message2, signature);
    expect(valid).toBe(false);
  });

  it('rejects a public key of wrong length', async () => {
    const shortKey = new Uint8Array(16);
    const message = new TextEncoder().encode('test');
    const sig = new Uint8Array(64);
    await expect(verifyEd25519Signature(shortKey, message, sig)).rejects.toThrow(
      'expected 32 bytes'
    );
  });

  it('rejects a signature of wrong length', async () => {
    const { publicKeyRaw } = await generateEd25519Keypair();
    const message = new TextEncoder().encode('test');
    const shortSig = new Uint8Array(32);
    await expect(verifyEd25519Signature(publicKeyRaw, message, shortSig)).rejects.toThrow(
      'expected 64 bytes'
    );
  });
});

// --- JWT creation and verification ---

const TEST_SECRET = 'test-jwt-secret-at-least-32-chars-long';

describe('createJWT', () => {
  it('creates a valid JWT string with 3 parts', async () => {
    const token = await createJWT('device-1', 'user-1', 'agent', TEST_SECRET);
    const parts = token.split('.');
    expect(parts.length).toBe(3);
  });

  it('includes correct payload fields', async () => {
    const token = await createJWT('device-1', 'user-1', 'agent', TEST_SECRET);
    const payload = JSON.parse(atob(token.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')));
    expect(payload.deviceId).toBe('device-1');
    expect(payload.userId).toBe('user-1');
    expect(payload.deviceType).toBe('agent');
    expect(payload.iat).toBeTypeOf('number');
    expect(payload.exp).toBeTypeOf('number');
    expect(payload.exp).toBeGreaterThan(payload.iat);
  });
});

describe('verifyJWT', () => {
  it('round-trips: create then verify', async () => {
    const token = await createJWT('device-1', 'user-1', 'mobile', TEST_SECRET);
    const payload = await verifyJWT(token, TEST_SECRET);

    expect(payload.deviceId).toBe('device-1');
    expect(payload.userId).toBe('user-1');
    expect(payload.deviceType).toBe('mobile');
    expect(payload.exp).toBeGreaterThan(payload.iat);
  });

  it('rejects a tampered token', async () => {
    const token = await createJWT('device-1', 'user-1', 'agent', TEST_SECRET);

    // Tamper with payload
    const parts = token.split('.');
    const tamperedPayload = btoa(JSON.stringify({
      deviceId: 'hacker',
      userId: 'user-1',
      deviceType: 'agent',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
    await expect(verifyJWT(tampered, TEST_SECRET)).rejects.toThrow('signature verification failed');
  });

  it('rejects a token signed with wrong secret', async () => {
    const token = await createJWT('device-1', 'user-1', 'agent', TEST_SECRET);
    await expect(verifyJWT(token, 'wrong-secret-here-definitely')).rejects.toThrow(
      'signature verification failed'
    );
  });

  it('rejects an expired token', async () => {
    // Mock Date.now to create an already-expired token
    const realDateNow = Date.now;
    const pastTime = Date.now() - 2 * 60 * 60 * 1000; // 2 hours ago
    vi.spyOn(Date, 'now').mockReturnValue(pastTime);

    const token = await createJWT('device-1', 'user-1', 'agent', TEST_SECRET);

    // Restore real time — the token is now expired
    vi.spyOn(Date, 'now').mockReturnValue(realDateNow());

    await expect(verifyJWT(token, TEST_SECRET)).rejects.toThrow('token expired');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('rejects malformed JWT (wrong number of parts)', async () => {
    await expect(verifyJWT('only.two', TEST_SECRET)).rejects.toThrow('expected 3 parts');
    await expect(verifyJWT('no-dots', TEST_SECRET)).rejects.toThrow('expected 3 parts');
  });

  it('rejects JWT with alg:none header', async () => {
    const token = await createJWT('device-1', 'user-1', 'agent', TEST_SECRET);
    const parts = token.split('.');
    // Replace header with alg:none
    const noneHeader = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' }))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const tampered = `${noneHeader}.${parts[1]}.${parts[2]}`;
    await expect(verifyJWT(tampered, TEST_SECRET)).rejects.toThrow('unsupported algorithm');
  });

  it('rejects JWT with iat in the future', async () => {
    // Mock Date.now to create a token far in the future
    const futureTime = Date.now() + 2 * 60 * 60 * 1000; // 2 hours from now
    vi.spyOn(Date, 'now').mockReturnValue(futureTime);

    const token = await createJWT('device-1', 'user-1', 'agent', TEST_SECRET);

    // Restore real time — the token's iat is now 2 hours in the future
    vi.restoreAllMocks();

    await expect(verifyJWT(token, TEST_SECRET)).rejects.toThrow('issued in the future');
  });

  it('sets expiry to ~1 hour from creation', async () => {
    const before = Math.floor(Date.now() / 1000);
    const token = await createJWT('device-1', 'user-1', 'agent', TEST_SECRET);
    const after = Math.floor(Date.now() / 1000);

    const payload = await verifyJWT(token, TEST_SECRET);
    const expiryDuration = payload.exp - payload.iat;

    expect(expiryDuration).toBe(3600); // exactly 1 hour
    expect(payload.iat).toBeGreaterThanOrEqual(before);
    expect(payload.iat).toBeLessThanOrEqual(after);
  });
});
