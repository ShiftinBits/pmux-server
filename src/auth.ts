/**
 * Auth module — Ed25519 signature verification and JWT creation/verification.
 *
 * Uses Web Crypto API (available in Cloudflare Workers and Node.js 18+).
 * JWTs are HS256-signed with a server secret. Ed25519 is used for device
 * identity verification during token exchange.
 */

// --- JWT Payload ---

export interface JWTPayload {
  deviceId: string;
  userId: string;
  deviceType: string;
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

function textEncode(str: string): Uint8Array {
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
  const key = await crypto.subtle.importKey(
    'raw',
    publicKey,
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  return crypto.subtle.verify('Ed25519', key, signature, message);
}

// --- HMAC-SHA256 helpers for JWT ---

async function hmacSign(secret: string, data: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    textEncode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, textEncode(data));
  return new Uint8Array(sig);
}

async function hmacVerify(secret: string, data: string, signature: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    'raw',
    textEncode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  return crypto.subtle.verify('HMAC', key, signature, textEncode(data));
}

// --- JWT ---

const JWT_HEADER = base64urlEncode(textEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
const JWT_EXPIRY_MS = 60 * 60 * 1000; // 1 hour

/**
 * Create a signed JWT for a device.
 *
 * @param deviceId - The device identifier
 * @param userId - The user identifier
 * @param deviceType - "agent" or "mobile"
 * @param secret - Server-side HMAC secret
 * @returns Compact JWT string (header.payload.signature)
 */
export async function createJWT(
  deviceId: string,
  userId: string,
  deviceType: string,
  secret: string
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: JWTPayload = {
    deviceId,
    userId,
    deviceType,
    iat: now,
    exp: now + Math.floor(JWT_EXPIRY_MS / 1000),
  };

  const encodedPayload = base64urlEncode(textEncode(JSON.stringify(payload)));
  const signingInput = `${JWT_HEADER}.${encodedPayload}`;
  const signature = await hmacSign(secret, signingInput);

  return `${signingInput}.${base64urlEncode(signature)}`;
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

  // Verify signature
  const signingInput = `${header}.${payload}`;
  const signature = base64urlDecode(sig);
  const valid = await hmacVerify(secret, signingInput, signature);

  if (!valid) {
    throw new Error('Invalid JWT: signature verification failed');
  }

  // Decode payload
  const decoded = JSON.parse(textDecode(base64urlDecode(payload))) as JWTPayload;

  // Check expiry
  const now = Math.floor(Date.now() / 1000);
  if (decoded.exp <= now) {
    throw new Error('Invalid JWT: token expired');
  }

  return decoded;
}
