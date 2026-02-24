import { describe, it, expect } from 'vitest';
import { createJWT } from '../auth';
import { authenticateRequest, PUBLIC_PATHS } from '../worker';
import type { Env } from '../worker';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

/**
 * Create a minimal Request with the given Authorization header.
 */
function makeRequest(authHeader: string | null): Request {
  const headers = new Headers();
  if (authHeader) {
    headers.set('Authorization', authHeader);
  }
  return new Request('http://localhost/ws', { headers });
}

/**
 * Create a minimal Env with just JWT_SECRET for middleware testing.
 */
const mockEnv: Env = {
  JWT_SECRET,
  SIGNALING: undefined as unknown as DurableObjectNamespace,
  TURN_TOKEN_ID: '',
  TURN_API_TOKEN: '',
};

describe('auth middleware', () => {
  it('passes valid JWT through', async () => {
    const token = await createJWT('device-1', 'user-1', 'agent', JWT_SECRET);
    const result = await authenticateRequest(makeRequest(`Bearer ${token}`), mockEnv);

    expect(result.error).toBeUndefined();
    expect(result.payload?.deviceId).toBe('device-1');
    expect(result.payload?.userId).toBe('user-1');
  });

  it('rejects missing Authorization header', async () => {
    const result = await authenticateRequest(makeRequest(null), mockEnv);
    expect(result.error).toContain('Missing Authorization');
  });

  it('rejects non-Bearer format', async () => {
    const result = await authenticateRequest(makeRequest('Basic abc123'), mockEnv);
    expect(result.error).toContain('Invalid Authorization format');
  });

  it('rejects expired token', async () => {
    // Create an already-expired token
    const realDateNow = Date.now;
    Date.now = () => realDateNow() - 2 * 60 * 60 * 1000; // 2 hours ago

    const token = await createJWT('device-1', 'user-1', 'agent', JWT_SECRET);

    Date.now = realDateNow; // restore

    const result = await authenticateRequest(makeRequest(`Bearer ${token}`), mockEnv);
    expect(result.error).toContain('expired');
  });

  it('rejects tampered token', async () => {
    const token = await createJWT('device-1', 'user-1', 'agent', JWT_SECRET);
    // Tamper with the token
    const parts = token.split('.');
    const tampered = `${parts[0]}.${parts[1]}abc.${parts[2]}`;

    const result = await authenticateRequest(makeRequest(`Bearer ${tampered}`), mockEnv);
    expect(result.error).toBeDefined();
  });

  it('rejects token signed with wrong secret', async () => {
    const token = await createJWT('device-1', 'user-1', 'agent', 'different-secret-entirely');
    const result = await authenticateRequest(makeRequest(`Bearer ${token}`), mockEnv);
    expect(result.error).toContain('signature verification failed');
  });

  describe('public routes bypass middleware', () => {
    const publicRoutes = [
      '/health',
      '/auth/pair/initiate',
      '/auth/pair/complete',
      '/auth/token',
    ];

    for (const route of publicRoutes) {
      it(`${route} is public`, () => {
        expect(PUBLIC_PATHS.has(route)).toBe(true);
      });
    }

    const protectedRoutes = ['/turn/credentials', '/ws', '/devices/abc'];

    for (const route of protectedRoutes) {
      it(`${route} requires auth`, () => {
        expect(PUBLIC_PATHS.has(route)).toBe(false);
      });
    }
  });
});
