/**
 * HMAC-SHA256 client signature validation.
 *
 * When `PMUX_HMAC_SECRET` is configured, all HTTP requests (except /health and /)
 * must include valid `pmux-signature` and `pmux-timestamp` headers.
 *
 * Signature format: HMAC-SHA256(secret, "{timestamp}:{pathname}") as hex string
 * Timestamp format: Unix seconds as integer string
 * Clock skew tolerance: ±60 seconds
 *
 * Uses Web Crypto API (Cloudflare Workers compatible).
 */

const CLOCK_SKEW_TOLERANCE_S = 60;

function textEncode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

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
 * Compute HMAC-SHA256(secret, "{timestamp}:{pathname}") and return as hex string.
 */
export async function computeSignature(secret: string, timestamp: string, pathname: string): Promise<string> {
  const key = await importHmacKey(secret);
  const message = `${timestamp}:${pathname}`;
  const sig = await crypto.subtle.sign('HMAC', key, textEncode(message));
  return bytesToHex(new Uint8Array(sig));
}

/**
 * Validate the client-supplied HMAC-SHA256 signature on an incoming request.
 *
 * @param request - The incoming HTTP request
 * @param secret  - The shared HMAC secret (PMUX_HMAC_SECRET)
 * @returns `{ valid: true }` on success, `{ valid: false; error: string }` on failure
 */
export async function validateClientSignature(
  request: Request,
  secret: string
): Promise<{ valid: true } | { valid: false; error: string }> {
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

  // Compute expected signature
  const pathname = new URL(request.url).pathname;
  const message = `${timestampHeader}:${pathname}`;

  const key = await importHmacKey(secret);

  // Convert the provided hex signature to Uint8Array for constant-time comparison
  // Validate hex string length first (SHA-256 = 32 bytes = 64 hex chars)
  if (signature.length !== 64 || !/^[0-9a-f]+$/i.test(signature)) {
    return { valid: false, error: 'invalid client signature' };
  }

  const signatureBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    signatureBytes[i] = parseInt(signature.slice(i * 2, i * 2 + 2), 16);
  }

  // Use crypto.subtle.verify for constant-time comparison
  const valid = await crypto.subtle.verify('HMAC', key, signatureBytes, textEncode(message));

  if (!valid) {
    return { valid: false, error: 'invalid client signature' };
  }

  return { valid: true };
}
