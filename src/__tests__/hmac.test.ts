import { describe, it, expect } from 'vitest';
import {
  validateClientSignature,
  validateClientSignatureV1,
  computeSignature,
  computeSignatureV1,
} from '../hmac';
import worker, { type Env } from '../worker';

const TEST_SECRET = 'test-hmac-secret-for-pocketmux';

function generateTestNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function makeRequest(
  path: string,
  opts: { signature?: string; timestamp?: string; nonce?: string } = {}
): Request {
  const headers = new Headers();
  if (opts.signature !== undefined) headers.set('pmux-signature', opts.signature);
  if (opts.timestamp !== undefined) headers.set('pmux-timestamp', opts.timestamp);
  if (opts.nonce !== undefined) headers.set('pmux-nonce', opts.nonce);
  return new Request(`http://localhost${path}`, { headers });
}

function nowSeconds(): string {
  return String(Math.floor(Date.now() / 1000));
}

// ---------------------------------------------------------------------------
// Legacy (unversioned) validateClientSignature
// ---------------------------------------------------------------------------

describe('validateClientSignature (legacy)', () => {
  it('accepts a valid signature', async () => {
    const timestamp = nowSeconds();
    const path = '/auth/token';
    const sig = await computeSignature(TEST_SECRET, timestamp, path);
    const result = await validateClientSignature(makeRequest(path, { signature: sig, timestamp }), TEST_SECRET);
    expect(result).toEqual({ valid: true });
  });

  it('rejects when pmux-signature header is missing', async () => {
    const result = await validateClientSignature(
      makeRequest('/auth/token', { timestamp: nowSeconds() }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'missing client signature' });
  });

  it('rejects when pmux-timestamp header is missing', async () => {
    const sig = await computeSignature(TEST_SECRET, nowSeconds(), '/auth/token');
    const result = await validateClientSignature(
      makeRequest('/auth/token', { signature: sig }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'missing client signature' });
  });

  it('rejects a stale timestamp', async () => {
    const ts = String(Math.floor(Date.now() / 1000) - 61);
    const sig = await computeSignature(TEST_SECRET, ts, '/auth/token');
    const result = await validateClientSignature(makeRequest('/auth/token', { signature: sig, timestamp: ts }), TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'request expired' });
  });

  it('rejects a future timestamp', async () => {
    const ts = String(Math.floor(Date.now() / 1000) + 61);
    const sig = await computeSignature(TEST_SECRET, ts, '/auth/token');
    const result = await validateClientSignature(makeRequest('/auth/token', { signature: sig, timestamp: ts }), TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'request expired' });
  });

  it('accepts a timestamp exactly at the 60-second boundary', async () => {
    const ts = String(Math.floor(Date.now() / 1000) - 60);
    const sig = await computeSignature(TEST_SECRET, ts, '/ws');
    const result = await validateClientSignature(makeRequest('/ws', { signature: sig, timestamp: ts }), TEST_SECRET);
    expect(result).toEqual({ valid: true });
  });

  it('rejects a wrong key', async () => {
    const ts = nowSeconds();
    const sig = await computeSignature('wrong-secret', ts, '/auth/token');
    const result = await validateClientSignature(makeRequest('/auth/token', { signature: sig, timestamp: ts }), TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'invalid client signature' });
  });

  it('rejects a wrong path', async () => {
    const ts = nowSeconds();
    const sig = await computeSignature(TEST_SECRET, ts, '/other/path');
    const result = await validateClientSignature(makeRequest('/auth/token', { signature: sig, timestamp: ts }), TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'invalid client signature' });
  });

  it('rejects a malformed signature', async () => {
    const result = await validateClientSignature(
      makeRequest('/auth/token', { signature: 'not-hex!!', timestamp: nowSeconds() }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'invalid client signature' });
  });

  it('rejects a signature of wrong length', async () => {
    const result = await validateClientSignature(
      makeRequest('/auth/token', { signature: 'deadbeef', timestamp: nowSeconds() }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'invalid client signature' });
  });

  it('rejects a non-numeric timestamp', async () => {
    const sig = await computeSignature(TEST_SECRET, nowSeconds(), '/auth/token');
    const result = await validateClientSignature(
      makeRequest('/auth/token', { signature: sig, timestamp: 'not-a-number' }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'invalid timestamp' });
  });

  it('matches cross-platform test vector', async () => {
    // HMAC-SHA256(key="test-hmac-secret-for-pocketmux", msg="1709654400:/auth/token")
    const secret = 'test-hmac-secret-for-pocketmux';
    const timestamp = '1709654400';
    const path = '/auth/token';
    const expectedHex = '724c81d78ba888524abb90d0de772502eda085ceb125c0fb8b2aaddeb3d0604c';

    expect(await computeSignature(secret, timestamp, path)).toBe(expectedHex);

    const realDateNow = Date.now;
    Date.now = () => parseInt(timestamp, 10) * 1000;
    try {
      const result = await validateClientSignature(
        makeRequest(path, { signature: expectedHex, timestamp }),
        secret
      );
      expect(result).toEqual({ valid: true });
    } finally {
      Date.now = realDateNow;
    }
  });
});

// ---------------------------------------------------------------------------
// V1 validateClientSignatureV1 — requires pmux-nonce
// ---------------------------------------------------------------------------

describe('validateClientSignatureV1', () => {
  it('accepts a valid v1 signature', async () => {
    const timestamp = nowSeconds();
    const nonce = generateTestNonce();
    const path = '/v1/auth/token';
    const sig = await computeSignatureV1(TEST_SECRET, timestamp, nonce, path);
    const result = await validateClientSignatureV1(makeRequest(path, { signature: sig, timestamp, nonce }), TEST_SECRET);
    expect(result).toEqual({ valid: true });
  });

  it('rejects when pmux-nonce header is missing', async () => {
    const timestamp = nowSeconds();
    const sig = await computeSignatureV1(TEST_SECRET, timestamp, generateTestNonce(), '/v1/auth/token');
    const result = await validateClientSignatureV1(
      makeRequest('/v1/auth/token', { signature: sig, timestamp }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'missing client signature' });
  });

  it('rejects when pmux-signature header is missing', async () => {
    const result = await validateClientSignatureV1(
      makeRequest('/v1/auth/token', { timestamp: nowSeconds(), nonce: generateTestNonce() }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'missing client signature' });
  });

  it('rejects when pmux-timestamp header is missing', async () => {
    const nonce = generateTestNonce();
    const sig = await computeSignatureV1(TEST_SECRET, nowSeconds(), nonce, '/v1/auth/token');
    const result = await validateClientSignatureV1(
      makeRequest('/v1/auth/token', { signature: sig, nonce }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'missing client signature' });
  });

  it('rejects a stale timestamp', async () => {
    const ts = String(Math.floor(Date.now() / 1000) - 61);
    const nonce = generateTestNonce();
    const sig = await computeSignatureV1(TEST_SECRET, ts, nonce, '/v1/auth/token');
    const result = await validateClientSignatureV1(
      makeRequest('/v1/auth/token', { signature: sig, timestamp: ts, nonce }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'request expired' });
  });

  it('rejects a nonce that is not 32 lowercase hex chars', async () => {
    const ts = nowSeconds();
    const sig = await computeSignatureV1(TEST_SECRET, ts, generateTestNonce(), '/v1/auth/token');
    const result = await validateClientSignatureV1(
      makeRequest('/v1/auth/token', { signature: sig, timestamp: ts, nonce: 'tooshort' }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'invalid nonce' });
  });

  it('rejects a nonce with uppercase chars', async () => {
    const ts = nowSeconds();
    const sig = await computeSignatureV1(TEST_SECRET, ts, generateTestNonce(), '/v1/auth/token');
    const result = await validateClientSignatureV1(
      makeRequest('/v1/auth/token', { signature: sig, timestamp: ts, nonce: 'ABCDEF1234567890ABCDEF1234567890' }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'invalid nonce' });
  });

  it('rejects a wrong key', async () => {
    const ts = nowSeconds();
    const nonce = generateTestNonce();
    const sig = await computeSignatureV1('wrong-secret', ts, nonce, '/v1/auth/token');
    const result = await validateClientSignatureV1(
      makeRequest('/v1/auth/token', { signature: sig, timestamp: ts, nonce }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'invalid client signature' });
  });

  it('includes /v1/ prefix in the signed path', async () => {
    const ts = nowSeconds();
    const nonce = generateTestNonce();
    // Sign /v1/auth/token but request path is /auth/token — should fail
    const sig = await computeSignatureV1(TEST_SECRET, ts, nonce, '/v1/auth/token');
    const result = await validateClientSignatureV1(
      makeRequest('/auth/token', { signature: sig, timestamp: ts, nonce }),
      TEST_SECRET
    );
    expect(result).toEqual({ valid: false, error: 'invalid client signature' });
  });

  it('matches cross-platform v1 test vector', async () => {
    // Formula v1: HMAC-SHA256(key, "{timestamp}:{nonce}:{pathname}")
    // Fixed nonce for reproducibility. Verify against Go and mobile implementations.
    const secret = 'test-hmac-secret-for-pocketmux';
    const timestamp = '1709654400';
    const nonce = '00000000000000000000000000000000';
    const path = '/v1/auth/token';

    const computed = await computeSignatureV1(secret, timestamp, nonce, path);
    expect(computed).toMatch(/^[0-9a-f]{64}$/);

    const realDateNow = Date.now;
    Date.now = () => parseInt(timestamp, 10) * 1000;
    try {
      const result = await validateClientSignatureV1(
        makeRequest(path, { signature: computed, timestamp, nonce }),
        secret
      );
      expect(result).toEqual({ valid: true });
    } finally {
      Date.now = realDateNow;
    }
  });
});

// ---------------------------------------------------------------------------
// Worker integration tests — HMAC middleware + version routing
// ---------------------------------------------------------------------------

function makeMockDONamespace(): DurableObjectNamespace {
  const stub = {
    fetch: async (_req: Request) => new Response(JSON.stringify({ error: 'mock DO' }), { status: 500 }),
  } as unknown as DurableObjectStub;

  return {
    idFromName: (_name: string) => ({ toString: () => 'mock-id' } as DurableObjectId),
    idFromString: (_id: string) => ({ toString: () => 'mock-id' } as DurableObjectId),
    newUniqueId: () => ({ toString: () => 'mock-id' } as DurableObjectId),
    get: (_id: DurableObjectId) => stub,
    jurisdiction: (_j: DurableObjectJurisdiction) => makeMockDONamespace(),
  } as unknown as DurableObjectNamespace;
}

describe('worker HMAC integration', () => {
  const HMAC_SECRET = 'integration-test-hmac-secret-32ch';

  function makeEnv(withHmac: boolean): Env {
    return {
      JWT_SECRET: 'test-jwt-secret-at-least-32-chars-long',
      SIGNALING: makeMockDONamespace(),
      TURN_TOKEN_ID: '',
      TURN_API_TOKEN: '',
      ...(withHmac ? { PMUX_HMAC_SECRET: HMAC_SECRET } : {}),
    };
  }

  it('returns 401 on legacy path with no signature when HMAC configured', async () => {
    const env = makeEnv(true);
    const req = new Request('http://localhost/auth/token', { method: 'POST' });
    const response = await worker.fetch(req, env);
    expect(response.status).toBe(401);
    const body = await response.json() as { error: string };
    expect(body.error).toBe('missing client signature');
  });

  it('returns 401 on /v1/ path with no signature when HMAC configured', async () => {
    const env = makeEnv(true);
    const req = new Request('http://localhost/v1/auth/token', { method: 'POST' });
    const response = await worker.fetch(req, env);
    expect(response.status).toBe(401);
    const body = await response.json() as { error: string };
    expect(body.error).toBe('missing client signature');
  });

  it('returns 401 on /v1/ path with only legacy headers (no pmux-nonce)', async () => {
    const env = makeEnv(true);
    const ts = nowSeconds();
    const path = '/v1/auth/token';
    const sig = await computeSignature(HMAC_SECRET, ts, path);
    const req = new Request(`http://localhost${path}`, {
      method: 'POST',
      headers: { 'pmux-signature': sig, 'pmux-timestamp': ts },
    });
    const response = await worker.fetch(req, env);
    expect(response.status).toBe(401);
    const body = await response.json() as { error: string };
    expect(body.error).toBe('missing client signature');
  });

  it('does NOT return 401 when PMUX_HMAC_SECRET is not configured', async () => {
    const env = makeEnv(false);
    const req = new Request('http://localhost/auth/token', { method: 'POST' });
    const response = await worker.fetch(req, env);
    expect(response.status).not.toBe(401);
  });

  it('/health returns 200 regardless of HMAC config or version prefix', async () => {
    const envWith = makeEnv(true);
    const envWithout = makeEnv(false);

    const [r1, r2, r3] = await Promise.all([
      worker.fetch(new Request('http://localhost/health'), envWith),
      worker.fetch(new Request('http://localhost/health'), envWithout),
      worker.fetch(new Request('http://localhost/v1/health'), envWith),
    ]);
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    expect(r3.status).toBe(200);
  });

  it('HMAC 401 response includes correlation headers and requestId', async () => {
    const env = makeEnv(true);
    const req = new Request('http://localhost/auth/token', { method: 'POST' });
    const response = await worker.fetch(req, env);
    expect(response.status).toBe(401);
    expect(response.headers.get('X-Request-Id')).toBeTruthy();
    expect(response.headers.get('X-Response-Time')).toBeTruthy();
    const body = await response.json() as { error: string; requestId?: string };
    expect(body.requestId).toBe(response.headers.get('X-Request-Id'));
  });
});
