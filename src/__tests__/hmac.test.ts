import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { validateClientSignature, computeSignature } from '../hmac';
import worker, { type Env } from '../worker';

const TEST_SECRET = 'test-hmac-secret-for-pocketmux';

/**
 * Build a Request with the given pmux-signature and pmux-timestamp headers.
 */
function makeRequest(
  path: string,
  opts: { signature?: string; timestamp?: string } = {}
): Request {
  const headers = new Headers();
  if (opts.signature !== undefined) {
    headers.set('pmux-signature', opts.signature);
  }
  if (opts.timestamp !== undefined) {
    headers.set('pmux-timestamp', opts.timestamp);
  }
  return new Request(`http://localhost${path}`, { headers });
}

/**
 * Compute a valid signature matching the production algorithm.
 * Used in tests to construct correctly-signed requests.
 */
async function computeTestSignature(secret: string, timestamp: string, path: string): Promise<string> {
  return computeSignature(secret, timestamp, path);
}

function nowSeconds(): string {
  return String(Math.floor(Date.now() / 1000));
}

describe('validateClientSignature', () => {
  it('accepts a valid signature with correct timestamp and path', async () => {
    const timestamp = nowSeconds();
    const path = '/auth/token';
    const sig = await computeTestSignature(TEST_SECRET, timestamp, path);
    const req = makeRequest(path, { signature: sig, timestamp });

    const result = await validateClientSignature(req, TEST_SECRET);
    expect(result).toEqual({ valid: true });
  });

  it('rejects when pmux-signature header is missing', async () => {
    const timestamp = nowSeconds();
    const req = makeRequest('/auth/token', { timestamp }); // no signature

    const result = await validateClientSignature(req, TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'missing client signature' });
  });

  it('rejects when pmux-timestamp header is missing', async () => {
    const sig = await computeTestSignature(TEST_SECRET, nowSeconds(), '/auth/token');
    const req = makeRequest('/auth/token', { signature: sig }); // no timestamp

    const result = await validateClientSignature(req, TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'missing client signature' });
  });

  it('rejects a timestamp older than 60 seconds', async () => {
    const staleTimestamp = String(Math.floor(Date.now() / 1000) - 61);
    const sig = await computeTestSignature(TEST_SECRET, staleTimestamp, '/auth/token');
    const req = makeRequest('/auth/token', { signature: sig, timestamp: staleTimestamp });

    const result = await validateClientSignature(req, TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'request expired' });
  });

  it('rejects a timestamp more than 60 seconds in the future', async () => {
    const futureTimestamp = String(Math.floor(Date.now() / 1000) + 61);
    const sig = await computeTestSignature(TEST_SECRET, futureTimestamp, '/auth/token');
    const req = makeRequest('/auth/token', { signature: sig, timestamp: futureTimestamp });

    const result = await validateClientSignature(req, TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'request expired' });
  });

  it('accepts a timestamp exactly at the 60-second boundary', async () => {
    const edgeTimestamp = String(Math.floor(Date.now() / 1000) - 60);
    const sig = await computeTestSignature(TEST_SECRET, edgeTimestamp, '/ws');
    const req = makeRequest('/ws', { signature: sig, timestamp: edgeTimestamp });

    const result = await validateClientSignature(req, TEST_SECRET);
    expect(result).toEqual({ valid: true });
  });

  it('rejects a signature computed with the wrong key', async () => {
    const timestamp = nowSeconds();
    const path = '/auth/token';
    const sig = await computeTestSignature('wrong-secret-entirely', timestamp, path);
    const req = makeRequest(path, { signature: sig, timestamp });

    const result = await validateClientSignature(req, TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'invalid client signature' });
  });

  it('rejects a signature computed with the wrong path', async () => {
    const timestamp = nowSeconds();
    const sig = await computeTestSignature(TEST_SECRET, timestamp, '/other/path');
    const req = makeRequest('/auth/token', { signature: sig, timestamp });

    const result = await validateClientSignature(req, TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'invalid client signature' });
  });

  it('rejects a malformed signature (not valid hex)', async () => {
    const timestamp = nowSeconds();
    const req = makeRequest('/auth/token', { signature: 'not-hex!!', timestamp });

    const result = await validateClientSignature(req, TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'invalid client signature' });
  });

  it('rejects a signature of wrong length', async () => {
    const timestamp = nowSeconds();
    const req = makeRequest('/auth/token', { signature: 'deadbeef', timestamp });

    const result = await validateClientSignature(req, TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'invalid client signature' });
  });

  it('matches cross-platform test vector', async () => {
    // This vector must match Go and React Native implementations.
    // Message: "1709654400:/auth/token"
    // HMAC-SHA256(secret="test-hmac-secret-for-pocketmux", message) = hex below
    const secret = 'test-hmac-secret-for-pocketmux';
    const timestamp = '1709654400';
    const path = '/auth/token';
    const expectedHex = '724c81d78ba888524abb90d0de772502eda085ceb125c0fb8b2aaddeb3d0604c';

    // Verify computeSignature produces the expected hex
    const computed = await computeSignature(secret, timestamp, path);
    expect(computed).toBe(expectedHex);

    // Also verify validateClientSignature accepts it (with a mocked timestamp window)
    // We supply the pre-computed hex directly and validate against a fake "now"
    // by constructing a request and temporarily adjusting Date.now
    const realDateNow = Date.now;
    // Set "now" to exactly the timestamp so it's within the 60s window
    Date.now = () => parseInt(timestamp, 10) * 1000;
    try {
      const req = makeRequest(path, { signature: expectedHex, timestamp });
      const result = await validateClientSignature(req, secret);
      expect(result).toEqual({ valid: true });
    } finally {
      Date.now = realDateNow;
    }
  });

  it('rejects a non-numeric timestamp with "invalid timestamp" error', async () => {
    const sig = await computeTestSignature(TEST_SECRET, nowSeconds(), '/auth/token');
    const req = makeRequest('/auth/token', { signature: sig, timestamp: 'not-a-number' });

    const result = await validateClientSignature(req, TEST_SECRET);
    expect(result).toEqual({ valid: false, error: 'invalid timestamp' });
  });
});

// ---------------------------------------------------------------------------
// Worker integration tests — verify HMAC middleware wiring in worker.ts
// ---------------------------------------------------------------------------

/**
 * Minimal mock for DurableObjectNamespace.
 * Only used in paths that reach routeToDO(); HMAC rejection happens before
 * that point, so the mock only needs to satisfy TypeScript.
 */
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

  it('returns 401 with HMAC error when PMUX_HMAC_SECRET is set and request has no signature headers', async () => {
    const env = makeEnv(true);
    const req = new Request('http://localhost/auth/token', { method: 'POST' });

    const response = await worker.fetch(req, env);
    expect(response.status).toBe(401);

    const body = await response.json() as { error: string };
    expect(body.error).toBe('missing client signature');
  });

  it('does NOT return HMAC 401 when PMUX_HMAC_SECRET is not set', async () => {
    const env = makeEnv(false);
    const req = new Request('http://localhost/auth/token', { method: 'POST' });

    const response = await worker.fetch(req, env);
    // HMAC is disabled — request reaches downstream (DO mock or 404/500).
    // The key assertion is that it was NOT rejected by the HMAC layer.
    expect(response.status).not.toBe(401);

    // Extra guard: if it somehow IS a 401, it must not be from the HMAC layer
    if (response.status === 401) {
      const body = await response.json() as { error: string };
      expect(body.error).not.toBe('missing client signature');
    }
  });

  it('/health returns 200 regardless of HMAC config', async () => {
    const envWithHmac = makeEnv(true);
    const envWithoutHmac = makeEnv(false);

    const req1 = new Request('http://localhost/health');
    const req2 = new Request('http://localhost/health');

    const [res1, res2] = await Promise.all([
      worker.fetch(req1, envWithHmac),
      worker.fetch(req2, envWithoutHmac),
    ]);

    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
  });
});
