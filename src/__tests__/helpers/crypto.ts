/**
 * Shared Ed25519 crypto helpers for tests.
 * Extracted from token-exchange.test.ts to avoid duplication.
 */

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
 * Build a signed request body for POST /pair/initiate.
 */
export async function signedPairInitiateBody(
  deviceId: string,
  keyPair: CryptoKeyPair,
  ed25519PublicKeyBase64: string,
  x25519PublicKey: string,
  name?: string
): Promise<Record<string, string>> {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const message = new TextEncoder().encode(deviceId + timestamp);
  const signature = await signEd25519(keyPair.privateKey, message);
  return {
    deviceId,
    ed25519PublicKey: ed25519PublicKeyBase64,
    x25519PublicKey,
    timestamp,
    signature: bytesToBase64(signature),
    ...(name !== undefined ? { name } : {}),
  };
}
