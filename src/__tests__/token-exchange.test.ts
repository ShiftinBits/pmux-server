import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createTestDOCompat as createTestDO, createTestDO as createTestDOFull } from './helpers/mock-do';
import { verifyJWT } from '../auth';
import {
  newTestDevice,
  bytesToBase64,
  signAuthChallenge,
  signLegacyAuthChallenge,
  signedPairInitiateBodyWithChallenge,
  HOST_X25519_KEY,
  TEST_ORIGIN,
  fetchChallenge,
} from './helpers/crypto';
import type { SignalingDO } from '../signaling';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

// AGENT_1 is derived from the host key, as /pair/initiate requires of a new device.
// AGENT_2 only ever receives a challenge, so it needs no key.
let AGENT_1: string;
let host: Awaited<ReturnType<typeof newTestDevice>>;
const AGENT_2 = 'a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2';

let doInstance: SignalingDO;

beforeEach(async () => {
  doInstance = await createTestDO();
  host = await newTestDevice();
  AGENT_1 = host.deviceId;
});

afterEach(() => {
  vi.restoreAllMocks();
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
  const body = await signedPairInitiateBodyWithChallenge(doInstance, deviceId, keyPair, ed25519PublicKeyBase64, HOST_X25519_KEY);
  await postJSON('/pair/initiate', body);
}

describe('POST /token challenge signature config', () => {
  const LAN_ORIGIN = 'http://192.168.1.5:8787';

  it('binds signatures to PMUX_AUTH_ORIGINS entries instead of the request origin', async () => {
    doInstance = (await createTestDOFull({ PMUX_AUTH_ORIGINS: ' HTTP://192.168.1.5:8787/ , https://signal.pmux.io:443' })).doInstance;
    const { keyPair, publicKeyRaw } = host;
    const body = await signedPairInitiateBodyWithChallenge(
      doInstance, AGENT_1, keyPair, bytesToBase64(publicKeyRaw), HOST_X25519_KEY, undefined, { origin: LAN_ORIGIN }
    );
    expect((await postJSON('/pair/initiate', body)).status).toBe(200);
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    for (const origin of [LAN_ORIGIN, 'https://signal.pmux.io']) {
      const nonce = await fetchChallenge(doInstance, AGENT_1);
      const signature = await signAuthChallenge(keyPair.privateKey, origin, AGENT_1, nonce);
      const { status } = await postJSON('/token', { deviceId: AGENT_1, nonce, signature });
      expect(status).toBe(200);
    }

    const nonce = await fetchChallenge(doInstance, AGENT_1);
    const signature = await signAuthChallenge(keyPair.privateKey, TEST_ORIGIN, AGENT_1, nonce);
    const { status, data } = await postJSON('/token', { deviceId: AGENT_1, nonce, signature });
    expect(status).toBe(401);
    expect(data['error']).toBe('Signature verification failed');
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('fails loudly on a PMUX_AUTH_ORIGINS entry that is not a URL', async () => {
    doInstance = (await createTestDOFull({ PMUX_AUTH_ORIGINS: 'signal.pmux.io' })).doInstance;
    const { keyPair, publicKeyRaw } = host;
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const body = await signedPairInitiateBodyWithChallenge(doInstance, AGENT_1, keyPair, bytesToBase64(publicKeyRaw), HOST_X25519_KEY);

    const { status, data } = await postJSON('/pair/initiate', body);

    expect(status).toBe(500);
    expect(data['error']).toBe('Internal error');
    expect(errorSpy).toHaveBeenCalled();
    expect(doInstance.getDevice(AGENT_1)).toBeNull();
  });

  it('rejects a legacy signature when PMUX_REJECT_LEGACY_AUTH is true', async () => {
    doInstance = (await createTestDOFull({ PMUX_REJECT_LEGACY_AUTH: 'true' })).doInstance;
    const { keyPair, publicKeyRaw } = host;
    await registerAgentDevice(AGENT_1, bytesToBase64(publicKeyRaw), keyPair);
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const legacyNonce = await fetchChallenge(doInstance, AGENT_1);
    const legacySignature = await signLegacyAuthChallenge(keyPair.privateKey, AGENT_1, legacyNonce);
    const legacy = await postJSON('/token', { deviceId: AGENT_1, nonce: legacyNonce, signature: legacySignature });
    expect(legacy.status).toBe(401);
    expect(legacy.data['error']).toBe('Signature verification failed');
    expect(warnSpy).not.toHaveBeenCalled();

    const nonce = await fetchChallenge(doInstance, AGENT_1);
    const signature = await signAuthChallenge(keyPair.privateKey, TEST_ORIGIN, AGENT_1, nonce);
    expect((await postJSON('/token', { deviceId: AGENT_1, nonce, signature })).status).toBe(200);
  });
});

describe('POST /token', () => {
  it('issues a JWT for a valid nonce+signature', async () => {
    const { keyPair, publicKeyRaw } = host;
    const ed25519PublicKeyBase64 = bytesToBase64(publicKeyRaw);

    // Register device
    await registerAgentDevice(AGENT_1, ed25519PublicKeyBase64, keyPair);

    // Fetch a challenge nonce
    const nonce = await fetchChallenge(doInstance, AGENT_1);

    const signatureBase64 = await signAuthChallenge(keyPair.privateKey, TEST_ORIGIN, AGENT_1, nonce);
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

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
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('rejects a signature bound to a different origin', async () => {
    const { keyPair, publicKeyRaw } = host;
    await registerAgentDevice(AGENT_1, bytesToBase64(publicKeyRaw), keyPair);
    const nonce = await fetchChallenge(doInstance, AGENT_1);

    const signature = await signAuthChallenge(keyPair.privateKey, 'https://signal.pmux.io', AGENT_1, nonce);
    const { status, data } = await postJSON('/token', { deviceId: AGENT_1, nonce, signature });

    expect(status).toBe(401);
    expect(data['error']).toBe('Signature verification failed');
  });

  it('accepts a legacy signature with a warning, once per nonce', async () => {
    const { keyPair, publicKeyRaw } = host;
    await registerAgentDevice(AGENT_1, bytesToBase64(publicKeyRaw), keyPair);
    const nonce = await fetchChallenge(doInstance, AGENT_1);
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const signature = await signLegacyAuthChallenge(keyPair.privateKey, AGENT_1, nonce);
    const first = await postJSON('/token', { deviceId: AGENT_1, nonce, signature });

    expect(first.status).toBe(200);
    expect(first.data['token']).toBeTypeOf('string');
    expect(warnSpy).toHaveBeenCalledWith('[auth] legacy signature accepted', { route: 'token' });

    const replay = await postJSON('/token', { deviceId: AGENT_1, nonce, signature });
    expect(replay.status).toBe(401);
    expect(replay.data['error']).toBe('Invalid or expired challenge');
  });

  it('rejects an invalid signature', async () => {
    const { keyPair, publicKeyRaw } = host;
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

  it('rejects a non-base64 signature with 401', async () => {
    const { keyPair, publicKeyRaw } = host;
    await registerAgentDevice(AGENT_1, bytesToBase64(publicKeyRaw), keyPair);
    const nonce = await fetchChallenge(doInstance, AGENT_1);

    const { status, data } = await postJSON('/token', { deviceId: AGENT_1, nonce, signature: '!!!' });

    expect(status).toBe(401);
    expect(data['error']).toBe('Invalid signature format');
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
    const { keyPair, publicKeyRaw } = host;
    const ed25519PublicKeyBase64 = bytesToBase64(publicKeyRaw);

    await registerAgentDevice(AGENT_1, ed25519PublicKeyBase64, keyPair);

    const nonce = await fetchChallenge(doInstance, AGENT_1);
    const signatureBase64 = await signAuthChallenge(keyPair.privateKey, TEST_ORIGIN, AGENT_1, nonce);

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
    const { keyPair, publicKeyRaw } = host;
    const ed25519PublicKeyBase64 = bytesToBase64(publicKeyRaw);

    await registerAgentDevice(AGENT_1, ed25519PublicKeyBase64, keyPair);

    // Get a nonce for agent-2, but try to use it for agent-1
    const nonceForAgent2 = await fetchChallenge(doInstance, AGENT_2);
    const signature = await signAuthChallenge(keyPair.privateKey, TEST_ORIGIN, AGENT_1, nonceForAgent2);

    const { status, data } = await postJSON('/token', {
      deviceId: AGENT_1,
      nonce: nonceForAgent2,
      signature,
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Invalid or expired challenge');
  });
});
