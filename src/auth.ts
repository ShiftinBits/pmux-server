/**
 * Auth module — Ed25519 signature verification and JWT creation/verification.
 *
 * Uses Web Crypto API (available in Cloudflare Workers and Node.js 18+).
 * JWTs are HS256-signed with a server secret. Ed25519 is used for device
 * identity verification during token exchange.
 */

import type { DeviceType } from '@pocketmux/shared';

// --- JWT Payload ---

export interface JWTPayload {
  sub: string;       // Subject — device ID (standard JWT claim)
  aud: string;       // Audience — must be 'pocketmux'
  deviceId: string;  // Device ID (mirrors sub for backward compatibility)
  deviceType: DeviceType;
  iat: number;
  exp: number;
}

// --- Base64url helpers ---

function base64urlEncode(data: Uint8Array): string {
  let binary = '';
  for (const byte of data) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (padded.length % 4)) % 4;
  const base64 = padded + '='.repeat(padding);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function textEncode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function textDecode(data: Uint8Array): string {
  return new TextDecoder().decode(data);
}

// --- Ed25519 Signature Verification ---

/**
 * Verify an Ed25519 signature against a public key.
 *
 * @param publicKey - Raw 32-byte Ed25519 public key
 * @param message - The message bytes that were signed
 * @param signature - The 64-byte Ed25519 signature
 * @returns true if the signature is valid
 */
export async function verifyEd25519Signature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  if (publicKey.length !== 32) {
    throw new Error('Invalid Ed25519 public key: expected 32 bytes');
  }
  if (signature.length !== 64) {
    throw new Error('Invalid Ed25519 signature: expected 64 bytes');
  }

  const key = await crypto.subtle.importKey(
    'raw',
    publicKey,
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  return crypto.subtle.verify('Ed25519', key, signature, message);
}

/**
 * The message a device signs to answer an auth challenge, bound to the
 * server's origin (`scheme://host[:port]`, as `URL.origin` gives it) so a
 * signature made for one server cannot be replayed at another.
 */
export function authChallengeMessage(origin: string, deviceId: string, nonce: string): Uint8Array {
  return textEncode(`pocketmux-auth-v1|${origin}|${deviceId}|${nonce}`);
}

/**
 * Verify a challenge signature, trying the origin-bound message for each
 * accepted origin and then, when acceptLegacy is set, the legacy
 * `deviceId|nonce` message that older clients sign.
 *
 * @returns 'v1' for an origin-bound signature, 'legacy' for an accepted legacy one, null otherwise
 * @throws Error if the key or signature has the wrong length
 */
export async function verifyChallengeSignature(
  publicKey: Uint8Array,
  origins: readonly string[],
  deviceId: string,
  nonce: string,
  signature: Uint8Array,
  acceptLegacy: boolean
): Promise<'v1' | 'legacy' | null> {
  for (const origin of origins) {
    if (await verifyEd25519Signature(publicKey, authChallengeMessage(origin, deviceId, nonce), signature)) {
      return 'v1';
    }
  }
  if (acceptLegacy && await verifyEd25519Signature(publicKey, textEncode(`${deviceId}|${nonce}`), signature)) {
    return 'legacy';
  }
  return null;
}

/**
 * Derive a device ID from a raw Ed25519 public key: lowercase hex of the first
 * 16 bytes of SHA-256(publicKey), 32 hex chars (SPEC §7, docs/SECURITY.md).
 * Matches the agent's identity.go deriveDeviceID and the mobile app's
 * identity.ts deriveDeviceId.
 */
export async function deriveDeviceId(publicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(publicKey)));
  return bytesToHex(digest.subarray(0, 16));
}

/** Lowercase hex encoding of a byte array. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// --- HMAC-SHA256 helpers for JWT ---

const hmacKeys = new Map<string, Promise<CryptoKey>>();

export function getHmacKey(secret: string): Promise<CryptoKey> {
  let key = hmacKeys.get(secret);
  if (!key) {
    key = crypto.subtle.importKey(
      'raw',
      textEncode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );
    hmacKeys.set(secret, key);
    key.catch(() => {
      if (hmacKeys.get(secret) === key) hmacKeys.delete(secret);
    });
  }
  return key;
}

async function hmacSign(secret: string, data: string): Promise<Uint8Array> {
  const key = await getHmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, textEncode(data));
  return new Uint8Array(sig);
}

async function hmacVerify(secret: string, data: string, signature: Uint8Array): Promise<boolean> {
  const key = await getHmacKey(secret);
  return crypto.subtle.verify('HMAC', key, signature, textEncode(data));
}

// --- JWT ---

const JWT_HEADER = base64urlEncode(textEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
const JWT_EXPIRY_MS = 60 * 60 * 1000; // 1 hour
const JWT_AUDIENCE = 'pocketmux';
const JWT_MAX_CLOCK_SKEW_S = 60; // Maximum allowed clock skew in seconds

/**
 * Create a signed JWT for a device.
 *
 * @param deviceId - The device identifier
 * @param deviceType - "host" or "mobile"
 * @param secret - Server-side HMAC secret
 * @returns Compact JWT string (header.payload.signature)
 */
export async function createJWT(
  deviceId: string,
  deviceType: DeviceType,
  secret: string
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: JWTPayload = {
    sub: deviceId,
    aud: JWT_AUDIENCE,
    deviceId,
    deviceType,
    iat: now,
    exp: now + Math.floor(JWT_EXPIRY_MS / 1000),
  };

  const encodedPayload = base64urlEncode(textEncode(JSON.stringify(payload)));
  const signingInput = `${JWT_HEADER}.${encodedPayload}`;
  const signature = await hmacSign(secret, signingInput);

  return `${signingInput}.${base64urlEncode(signature)}`;
}

/** Thrown by verifyJWT when a token is otherwise valid but past its expiry [SB-1004]. */
export class TokenExpiredError extends Error {
  constructor() {
    super('Invalid JWT: token expired');
    this.name = 'TokenExpiredError';
  }
}

/**
 * Verify and decode a JWT.
 *
 * @param token - Compact JWT string
 * @param secret - Server-side HMAC secret
 * @returns Decoded payload if valid
 * @throws Error if token is invalid, tampered, or expired
 */
export async function verifyJWT(token: string, secret: string): Promise<JWTPayload> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT: expected 3 parts');
  }

  const [header, payload, sig] = parts;
  if (!header || !payload || !sig) {
    throw new Error('Invalid JWT: empty part');
  }

  // Verify header matches expected algorithm (defense against alg:none attacks)
  if (header !== JWT_HEADER) {
    throw new Error('Invalid JWT: unsupported algorithm');
  }

  // Verify signature
  const signingInput = `${header}.${payload}`;
  const signature = base64urlDecode(sig);
  const valid = await hmacVerify(secret, signingInput, signature);

  if (!valid) {
    throw new Error('Invalid JWT: signature verification failed');
  }

  // Decode payload
  const decoded = JSON.parse(textDecode(base64urlDecode(payload))) as JWTPayload;

  // Verify audience claim
  if (decoded.aud !== JWT_AUDIENCE) {
    throw new Error('Invalid JWT: invalid audience');
  }

  // Verify subject claim exists and matches deviceId
  if (!decoded.sub || decoded.sub !== decoded.deviceId) {
    throw new Error('Invalid JWT: missing or mismatched subject');
  }

  // Check expiry
  const now = Math.floor(Date.now() / 1000);
  if (decoded.exp <= now) {
    throw new TokenExpiredError();
  }

  // Check iat is not in the future (allow configured clock skew)
  if (decoded.iat > now + JWT_MAX_CLOCK_SKEW_S) {
    throw new Error('Invalid JWT: issued in the future');
  }

  return decoded;
}
