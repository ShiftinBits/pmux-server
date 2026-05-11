/**
 * HMAC-SHA256 client signature validation.
 *
 * Two formula versions are supported, selected by whether the request path
 * starts with /v1/:
 *
 * Legacy (unversioned paths):
 *   Signature: HMAC-SHA256(secret, "{timestamp}:{pathname}") as hex
 *   Headers required: pmux-signature, pmux-timestamp
 *
 * V1 (/v1/ paths):
 *   Signature: HMAC-SHA256(secret, "{timestamp}:{nonce}:{pathname}") as hex
 *   Headers required: pmux-signature, pmux-timestamp, pmux-nonce
 *   Nonce: 32 lowercase hex characters (16 random bytes) — prevents replay
 *   Pathname: the full path including the /v1/ prefix
 *
 * Clock skew tolerance: ±60 seconds for both versions.
 *
 * NOTE: Full replay prevention for v1 (server-side nonce uniqueness enforcement)
 * requires an HMAC_NONCES KV namespace binding to track seen nonces within the
 * tolerance window. Nonce format is validated but uniqueness is not yet enforced.
 * Track as a follow-up: add HMAC_NONCES KV binding to wrangler.toml and implement
 * checkAndRecordNonce() in this file.
 *
 * Uses Web Crypto API (Cloudflare Workers compatible).
 */

import { textEncode } from './auth';

const CLOCK_SKEW_TOLERANCE_S = 60;

/** Expected nonce length for v1: 32 hex chars (16 random bytes). */
const NONCE_HEX_LENGTH = 32;
const NONCE_HEX_PATTERN = /^[0-9a-f]{32}$/;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    textEncode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

/**
 * Legacy: compute HMAC-SHA256(secret, "{timestamp}:{pathname}") as hex.
 * Used for unversioned API paths.
 */
export async function computeSignature(
  secret: string,
  timestamp: string,
  pathname: string
): Promise<string> {
  const key = await importHmacKey(secret);
  const message = `${timestamp}:${pathname}`;
  const sig = await crypto.subtle.sign('HMAC', key, textEncode(message));
  return bytesToHex(new Uint8Array(sig));
}

/**
 * V1: compute HMAC-SHA256(secret, "{timestamp}:{nonce}:{pathname}") as hex.
 * Used for /v1/ API paths. Pathname should include the /v1/ prefix.
 */
export async function computeSignatureV1(
  secret: string,
  timestamp: string,
  nonce: string,
  pathname: string
): Promise<string> {
  const key = await importHmacKey(secret);
  const message = `${timestamp}:${nonce}:${pathname}`;
  const sig = await crypto.subtle.sign('HMAC', key, textEncode(message));
  return bytesToHex(new Uint8Array(sig));
}

type ValidationResult = { valid: true } | { valid: false; error: string };

async function verifySignatureHex(
  key: CryptoKey,
  hexSig: string,
  message: string
): Promise<boolean> {
  if (hexSig.length !== 64 || !/^[0-9a-f]+$/i.test(hexSig)) {
    return false;
  }
  const sigBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    sigBytes[i] = parseInt(hexSig.slice(i * 2, i * 2 + 2), 16);
  }
  return crypto.subtle.verify('HMAC', key, sigBytes, textEncode(message));
}

/**
 * Validate a legacy (unversioned) client HMAC signature.
 * Formula: HMAC-SHA256(secret, "{timestamp}:{pathname}")
 */
export async function validateClientSignature(
  request: Request,
  secret: string
): Promise<ValidationResult> {
  const signature = request.headers.get('pmux-signature');
  const timestampHeader = request.headers.get('pmux-timestamp');

  if (!signature || !timestampHeader) {
    return { valid: false, error: 'missing client signature' };
  }

  const timestamp = parseInt(timestampHeader, 10);
  if (isNaN(timestamp)) {
    return { valid: false, error: 'invalid timestamp' };
  }

  const nowS = Math.floor(Date.now() / 1000);
  if (Math.abs(nowS - timestamp) > CLOCK_SKEW_TOLERANCE_S) {
    return { valid: false, error: 'request expired' };
  }

  if (signature.length !== 64 || !/^[0-9a-f]+$/i.test(signature)) {
    return { valid: false, error: 'invalid client signature' };
  }

  const pathname = new URL(request.url).pathname;
  const key = await importHmacKey(secret);
  const valid = await verifySignatureHex(key, signature, `${timestampHeader}:${pathname}`);

  return valid ? { valid: true } : { valid: false, error: 'invalid client signature' };
}

/**
 * Validate a v1 client HMAC signature (requires pmux-nonce header).
 * Formula: HMAC-SHA256(secret, "{timestamp}:{nonce}:{pathname}")
 * Pathname is the full original path including the /v1/ prefix.
 */
export async function validateClientSignatureV1(
  request: Request,
  secret: string
): Promise<ValidationResult> {
  const signature = request.headers.get('pmux-signature');
  const timestampHeader = request.headers.get('pmux-timestamp');
  const nonce = request.headers.get('pmux-nonce');

  if (!signature || !timestampHeader || !nonce) {
    return { valid: false, error: 'missing client signature' };
  }

  const timestamp = parseInt(timestampHeader, 10);
  if (isNaN(timestamp)) {
    return { valid: false, error: 'invalid timestamp' };
  }

  const nowS = Math.floor(Date.now() / 1000);
  if (Math.abs(nowS - timestamp) > CLOCK_SKEW_TOLERANCE_S) {
    return { valid: false, error: 'request expired' };
  }

  if (nonce.length !== NONCE_HEX_LENGTH || !NONCE_HEX_PATTERN.test(nonce)) {
    return { valid: false, error: 'invalid nonce' };
  }

  if (signature.length !== 64 || !/^[0-9a-f]+$/i.test(signature)) {
    return { valid: false, error: 'invalid client signature' };
  }

  const pathname = new URL(request.url).pathname;
  const key = await importHmacKey(secret);
  const valid = await verifySignatureHex(key, signature, `${timestampHeader}:${nonce}:${pathname}`);

  return valid ? { valid: true } : { valid: false, error: 'invalid client signature' };
}
