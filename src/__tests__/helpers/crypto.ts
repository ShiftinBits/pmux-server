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

export async function signEd25519(privateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign('Ed25519', privateKey, message);
  return new Uint8Array(sig);
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
 * Build a signed request body for POST /pair/initiate.
 * Uses the nonce-based challenge protocol (SB-996).
 */
export async function signedPairInitiateBody(
  deviceId: string,
  keyPair: CryptoKeyPair,
  ed25519PublicKeyBase64: string,
  x25519PublicKey: string,
  name?: string,
  nonce?: string
): Promise<Record<string, string>> {
  // nonce must be provided; callers pre-fetch it via fetchChallenge (or use
  // signedPairInitiateBodyWithChallenge). Fail loudly rather than signing a
  // placeholder that mysteriously 401s at the server.
  if (nonce === undefined) {
    throw new Error('signedPairInitiateBody: nonce is required; use signedPairInitiateBodyWithChallenge');
  }
  const message = new TextEncoder().encode(deviceId + '|' + nonce);
  const signature = await signEd25519(keyPair.privateKey, message);
  return {
    deviceId,
    ed25519PublicKey: ed25519PublicKeyBase64,
    x25519PublicKey,
    nonce,
    signature: bytesToBase64(signature),
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
  name?: string
): Promise<Record<string, string>> {
  const nonce = await fetchChallenge(doInstance, deviceId);
  return signedPairInitiateBody(deviceId, keyPair, ed25519PublicKeyBase64, x25519PublicKey, name, nonce);
}
