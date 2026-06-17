/**
 * Integration test: Rate limiting across the full DO request lifecycle.
 *
 * Verifies:
 * 1. Rate limits enforce correctly at the DO endpoint level
 * 2. 429 responses include Retry-After header
 * 3. Rate limit state persists within the same DO instance
 * 4. Different IPs have independent rate limits
 * 5. Different endpoints have independent rate limits
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDO } from '../helpers/mock-do';
import { generateEd25519Keypair, bytesToBase64, signedPairInitiateBodyWithChallenge } from '../helpers/crypto';
import type { SignalingDO } from '../../signaling';

// Limits mirror the native Workers Rate Limiting bindings (wrangler.toml).
const PAIR_LIMIT = 10;
const TOKEN_LIMIT = 30;

let doInstance: SignalingDO;

beforeEach(async () => {
  const result = await createTestDO();
  doInstance = result.doInstance;
});

async function postJSON(
  path: string,
  body: unknown,
  headers?: Record<string, string>
): Promise<{ status: number; data: Record<string, unknown>; response: Response }> {
  const reqHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Client-IP': '192.168.1.1',
    ...headers,
  };
  const request = new Request(`http://localhost${path}`, {
    method: 'POST',
    headers: reqHeaders,
    body: JSON.stringify(body),
  });
  const response = await doInstance.fetch(request);
  const data = (await response.json()) as Record<string, unknown>;
  return { status: response.status, data, response };
}

/** Pad an arbitrary string to a 32-hex device ID for testing (ponytail: test-only, not real derivation). */
function toTestDeviceId(s: string): string {
  const hex = Array.from(s).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
  return hex.slice(0, 32).padEnd(32, '0');
}

async function signedInitiateBody(deviceId: string, x25519Key: string) {
  const keys = await generateEd25519Keypair();
  const hexId = toTestDeviceId(deviceId);
  return signedPairInitiateBodyWithChallenge(doInstance, hexId, keys.keyPair, bytesToBase64(keys.publicKeyRaw), x25519Key);
}

describe('Rate limiting integration [T3.11]', () => {
  describe('/pair/initiate rate limit', () => {
    it('allows 10 requests and blocks the 11th with 429', async () => {
      const limit = PAIR_LIMIT;
      expect(limit).toBe(10);

      // Send requests up to the limit
      for (let i = 0; i < limit; i++) {
        const body = await signedInitiateBody(`agent-${i}`, `x25519-key-${i}`);
        const { status } = await postJSON('/pair/initiate', body);
        expect(status).toBe(200);
      }

      // 11th request should be rate limited (body doesn't matter — 429 fires before handler)
      const { status, data, response } = await postJSON('/pair/initiate', {
        deviceId: 'agent-overflow',
        ed25519PublicKey: 'pub-key-overflow',
        x25519PublicKey: 'x25519-key-overflow',
      });

      expect(status).toBe(429);
      expect(data['error']).toBe('Too many requests');

      const retryAfter = response.headers.get('Retry-After');
      expect(retryAfter).toBeDefined();
      expect(Number(retryAfter)).toBeGreaterThan(0);
      expect(Number(retryAfter)).toBeLessThanOrEqual(60);
    });

    it('rate limit state persists within the same DO', async () => {
      const limit = PAIR_LIMIT;

      // Send 5 requests
      for (let i = 0; i < 5; i++) {
        const body = await signedInitiateBody(`agent-persist-${i}`, `x25519-key-${i}`);
        const { status } = await postJSON('/pair/initiate', body);
        expect(status).toBe(200);
      }

      // Send remaining requests to hit the limit
      for (let i = 5; i < limit; i++) {
        const body = await signedInitiateBody(`agent-persist-${i}`, `x25519-key-${i}`);
        const { status } = await postJSON('/pair/initiate', body);
        expect(status).toBe(200);
      }

      // Next request should still be blocked (state persisted)
      const { status } = await postJSON('/pair/initiate', {
        deviceId: 'agent-persist-overflow',
        ed25519PublicKey: 'pub-key-overflow',
        x25519PublicKey: 'x25519-key-overflow',
      });
      expect(status).toBe(429);
    });
  });

  describe('independent IP limits', () => {
    it('different IPs have independent rate limits', async () => {
      const limit = PAIR_LIMIT;

      // Exhaust limit for IP A
      for (let i = 0; i < limit; i++) {
        const body = await signedInitiateBody(`agent-a-${i}`, `x25519-key-a-${i}`);
        const { status } = await postJSON('/pair/initiate', body, { 'X-Client-IP': '10.0.0.1' });
        expect(status).toBe(200);
      }

      // IP A is blocked
      const blockedA = await postJSON(
        '/pair/initiate',
        {
          deviceId: 'agent-a-blocked',
          ed25519PublicKey: 'pub-key-a-blocked',
          x25519PublicKey: 'x25519-key-a-blocked',
        },
        { 'X-Client-IP': '10.0.0.1' }
      );
      expect(blockedA.status).toBe(429);

      // IP B is still allowed
      const bodyB = await signedInitiateBody('agent-b-1', 'x25519-key-b-1');
      const allowedB = await postJSON('/pair/initiate', bodyB, { 'X-Client-IP': '10.0.0.2' });
      expect(allowedB.status).toBe(200);

      // IP C is also allowed
      const bodyC = await signedInitiateBody('agent-c-1', 'x25519-key-c-1');
      const allowedC = await postJSON('/pair/initiate', bodyC, { 'X-Client-IP': '10.0.0.3' });
      expect(allowedC.status).toBe(200);
    });
  });

  describe('independent endpoint limits', () => {
    it('/pair/initiate and /pair/complete have separate counters', async () => {
      const limit = PAIR_LIMIT;

      // Exhaust /pair/initiate limit
      for (let i = 0; i < limit; i++) {
        const body = await signedInitiateBody(`agent-sep-${i}`, `x25519-key-sep-${i}`);
        await postJSON('/pair/initiate', body);
      }

      // /pair/initiate is blocked
      const blocked = await postJSON('/pair/initiate', {
        deviceId: 'agent-sep-overflow',
        ed25519PublicKey: 'pub-key-sep-overflow',
        x25519PublicKey: 'x25519-key-sep-overflow',
      });
      expect(blocked.status).toBe(429);

      // /pair/complete should still work (returns 404 for bad code, not 429)
      const complete = await postJSON('/pair/complete', {
        pairingCode: 'ABCDEF',
        deviceId: 'mobile-sep-1',
        ed25519PublicKey: 'pub-key-mobile',
        x25519PublicKey: 'x25519-key-mobile',
      });
      expect(complete.status).toBe(404); // Bad code, but NOT rate limited
    });

    it('/pairing has its own counter, independent of /pair/initiate', async () => {
      // Exhaust /pair/initiate for this IP
      for (let i = 0; i < PAIR_LIMIT; i++) {
        const body = await signedInitiateBody(`agent-pg-${i}`, `x25519-key-pg-${i}`);
        await postJSON('/pair/initiate', body);
      }
      const blockedInitiate = await postJSON('/pair/initiate', {
        deviceId: 'agent-pg-overflow',
        ed25519PublicKey: 'pub',
        x25519PublicKey: 'x25519',
      });
      expect(blockedInitiate.status).toBe(429);

      // /pairing (DELETE) shares PAIR_LIMITER but is keyed separately, so it is
      // NOT rate limited — it returns its handler's status, not 429.
      const request = new Request('http://localhost/pairing', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json', 'X-Client-IP': '192.168.1.1' },
        body: JSON.stringify({ hostDeviceId: 'nonexistent' }),
      });
      const response = await doInstance.fetch(request);
      expect(response.status).not.toBe(429);
    });

    it('/token has its own limit (30/min)', async () => {
      const tokenLimit = TOKEN_LIMIT;
      expect(tokenLimit).toBe(30);

      // Send 30 token requests (all fail with 401/missing-nonce but should not be rate limited)
      const fakeDeviceId = 'ee' + '0'.repeat(30); // valid 32-hex
      for (let i = 0; i < tokenLimit; i++) {
        const { status } = await postJSON('/token', {
          deviceId: fakeDeviceId,
          nonce: 'fake-nonce',
          signature: bytesToBase64(new Uint8Array(64)),
        });
        expect(status).toBe(401);
      }

      // 31st should be rate limited
      const { status } = await postJSON('/token', {
        deviceId: fakeDeviceId,
        nonce: 'fake-nonce',
        signature: bytesToBase64(new Uint8Array(64)),
      });
      expect(status).toBe(429);
    });
  });

  // Window reset is owned by the native Workers Rate Limiting binding (the
  // platform's time window), not unit-testable via fake timers — covered by
  // the binding's own configured `period`, not asserted here.

  describe('429 response format', () => {
    it('includes proper error body and Retry-After header', async () => {
      const limit = PAIR_LIMIT;

      // Fill the limit
      for (let i = 0; i < limit; i++) {
        const body = await signedInitiateBody(`agent-format-${i}`, `x25519-key-format-${i}`);
        await postJSON('/pair/initiate', body);
      }

      // Trigger 429
      const { status, data, response } = await postJSON('/pair/initiate', {
        deviceId: 'agent-format-overflow',
        ed25519PublicKey: 'pub-key-overflow',
        x25519PublicKey: 'x25519-key-overflow',
      });

      expect(status).toBe(429);
      expect(data['error']).toBe('Too many requests');

      const retryAfter = response.headers.get('Retry-After');
      expect(retryAfter).toBeDefined();
      const retryAfterNum = Number(retryAfter);
      expect(retryAfterNum).toBeGreaterThan(0);
      expect(retryAfterNum).toBeLessThanOrEqual(60);

      // Content-Type should be JSON
      expect(response.headers.get('Content-Type')).toBe('application/json');
    });
  });
});
