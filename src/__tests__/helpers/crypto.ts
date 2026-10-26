/**
 * Shared Ed25519 crypto helpers for tests.
 * Extracted from token-exchange.test.ts to avoid duplication.
 */

import type { SignalingDO } from '../../signaling';

export async function generateEd25519Keypair() {
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const publicKeyRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', keyPair.publicKey)
  );
  return { keyPair, publicKeyRaw };
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/** A well-formed 32-byte base64 X25519 public key for /pair/initiate bodies. */
export const HOST_X25519_KEY = bytesToBase64(new Uint8Array(32).fill(7));

/**
 * A well-formed 32-byte base64 key derived from a label, for placeholder
 * /pair/complete keys. The same label always gives the same key; distinct
 * labels give distinct keys.
 */
export function testKey(label: string): string {
  const bytes = new Uint8Array(32);
  new TextEncoder().encode(label).forEach((c, i) => {
    bytes[i % 32] = (bytes[i % 32]! * 31 + c) & 0xff;
  });
  return bytesToBase64(bytes);
}

/**
 * Independent test-side device ID derivation (first 16 bytes of
 * SHA-256(publicKey), lowercase hex), deliberately not importing the
 * production implementation so a production bug isn't masked.
 */
export async function deriveDeviceId(publicKeyRaw: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKeyRaw));
  return Array.from(digest.slice(0, 16), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** A fresh Ed25519 identity whose device ID is derived from its key. */
export async function newTestDevice() {
  const { keyPair, publicKeyRaw } = await generateEd25519Keypair();
  return {
    deviceId: await deriveDeviceId(publicKeyRaw),
    keyPair,
    publicKeyRaw,
    publicKeyB64: bytesToBase64(publicKeyRaw),
  };
}

export async function signEd25519(privateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign('Ed25519', privateKey, message);
  return new Uint8Array(sig);
}

/** The DO's origin in tests: every test request URL is http://localhost/... */
export const TEST_ORIGIN = 'http://localhost';

/**
 * Sign an auth challenge in the origin-bound form
 * (`pocketmux-auth-v1|<origin>|<deviceId>|<nonce>`), built here rather than
 * with the production helper so a production bug isn't masked.
 * Returns the base64 signature.
 */
export async function signAuthChallenge(
  privateKey: CryptoKey,
  origin: string,
  deviceId: string,
  nonce: string
): Promise<string> {
  const message = new TextEncoder().encode(`pocketmux-auth-v1|${origin}|${deviceId}|${nonce}`);
  return bytesToBase64(await signEd25519(privateKey, message));
}

/** Sign an auth challenge in the legacy `<deviceId>|<nonce>` form. Returns the base64 signature. */
export async function signLegacyAuthChallenge(privateKey: CryptoKey, deviceId: string, nonce: string): Promise<string> {
  return bytesToBase64(await signEd25519(privateKey, new TextEncoder().encode(deviceId + '|' + nonce)));
}

/** How signedPairInitiateBody signs the challenge. */
export interface ChallengeSignOptions {
  /** Origin to bind the signature to; defaults to TEST_ORIGIN. */
  origin?: string;
  /** Sign the legacy `<deviceId>|<nonce>` form instead of the origin-bound one. */
  legacy?: boolean;
}

/**
 * Obtain a nonce challenge from the DO for the given deviceId.
 * Calls POST /challenge on the DO directly.
 */
export async function fetchChallenge(doInstance: SignalingDO, deviceId: string): Promise<string> {
  const request = new Request('http://localhost/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId }),
  });
  const response = await doInstance.fetch(request);
  if (!response.ok) {
    throw new Error(`fetchChallenge failed: ${response.status}`);
  }
  const data = await response.json() as { nonce: string };
  return data.nonce;
}

/**
 * Build a signed request body for POST /pair/initiate, signing the
 * challenge in the origin-bound form unless options.legacy is set.
 */
export async function signedPairInitiateBody(
  deviceId: string,
  keyPair: CryptoKeyPair,
  ed25519PublicKeyBase64: string,
  x25519PublicKey: string,
  name?: string,
  nonce?: string,
  options: ChallengeSignOptions = {}
): Promise<Record<string, string>> {
  // nonce must be provided; callers pre-fetch it via fetchChallenge (or use
  // signedPairInitiateBodyWithChallenge). Fail loudly rather than signing a
  // placeholder that mysteriously 401s at the server.
  if (nonce === undefined) {
    throw new Error('signedPairInitiateBody: nonce is required; use signedPairInitiateBodyWithChallenge');
  }
  const signature = options.legacy
    ? await signLegacyAuthChallenge(keyPair.privateKey, deviceId, nonce)
    : await signAuthChallenge(keyPair.privateKey, options.origin ?? TEST_ORIGIN, deviceId, nonce);
  return {
    deviceId,
    ed25519PublicKey: ed25519PublicKeyBase64,
    x25519PublicKey,
    nonce,
    signature,
    ...(name !== undefined ? { name } : {}),
  };
}

/**
 * Build a signed request body for POST /pair/initiate, fetching the challenge
 * nonce from the DO automatically. Convenience wrapper.
 */
export async function signedPairInitiateBodyWithChallenge(
  doInstance: SignalingDO,
  deviceId: string,
  keyPair: CryptoKeyPair,
  ed25519PublicKeyBase64: string,
  x25519PublicKey: string,
  name?: string,
  options: ChallengeSignOptions = {}
): Promise<Record<string, string>> {
  const nonce = await fetchChallenge(doInstance, deviceId);
  return signedPairInitiateBody(deviceId, keyPair, ed25519PublicKeyBase64, x25519PublicKey, name, nonce, options);
}
