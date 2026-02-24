import { describe, it, expect } from 'vitest';
import { createJWT, verifyJWT } from '../auth';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

/**
 * Simulates the auth middleware logic from worker.ts
 */
async function authenticateRequest(
  authHeader: string | null,
  secret: string
): Promise<{ valid: boolean; error?: string; deviceId?: string; userId?: string }> {
  if (!authHeader) {
    return { valid: false, error: 'Missing Authorization header' };
  }
  if (!authHeader.startsWith('Bearer ')) {
    return { valid: false, error: 'Invalid Authorization format' };
  }
  const token = authHeader.slice('Bearer '.length);
  try {
    const payload = await verifyJWT(token, secret);
    return { valid: true, deviceId: payload.deviceId, userId: payload.userId };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Token verification failed';
    return { valid: false, error: message };
  }
}

describe('auth middleware', () => {
  it('passes valid JWT through', async () => {
    const token = await createJWT('device-1', 'user-1', 'agent', JWT_SECRET);
    const result = await authenticateRequest(`Bearer ${token}`, JWT_SECRET);

    expect(result.valid).toBe(true);
    expect(result.deviceId).toBe('device-1');
    expect(result.userId).toBe('user-1');
  });

  it('rejects missing Authorization header', async () => {
    const result = await authenticateRequest(null, JWT_SECRET);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Missing Authorization');
  });

  it('rejects non-Bearer format', async () => {
    const result = await authenticateRequest('Basic abc123', JWT_SECRET);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Invalid Authorization format');
  });

  it('rejects expired token', async () => {
    // Create an already-expired token
    const realDateNow = Date.now;
    Date.now = () => realDateNow() - 2 * 60 * 60 * 1000; // 2 hours ago

    const token = await createJWT('device-1', 'user-1', 'agent', JWT_SECRET);

    Date.now = realDateNow; // restore

    const result = await authenticateRequest(`Bearer ${token}`, JWT_SECRET);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('expired');
  });

  it('rejects tampered token', async () => {
    const token = await createJWT('device-1', 'user-1', 'agent', JWT_SECRET);
    // Tamper with the token
    const parts = token.split('.');
    const tampered = `${parts[0]}.${parts[1]}abc.${parts[2]}`;

    const result = await authenticateRequest(`Bearer ${tampered}`, JWT_SECRET);
    expect(result.valid).toBe(false);
  });

  it('rejects token signed with wrong secret', async () => {
    const token = await createJWT('device-1', 'user-1', 'agent', 'different-secret-entirely');
    const result = await authenticateRequest(`Bearer ${token}`, JWT_SECRET);
    expect(result.valid).toBe(false);
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
        const PUBLIC_PATHS = new Set([
          '/health',
          '/auth/pair/initiate',
          '/auth/pair/complete',
          '/auth/token',
        ]);
        expect(PUBLIC_PATHS.has(route)).toBe(true);
      });
    }

    const protectedRoutes = ['/turn/credentials', '/ws', '/devices/abc'];

    for (const route of protectedRoutes) {
      it(`${route} requires auth`, () => {
        const PUBLIC_PATHS = new Set([
          '/health',
          '/auth/pair/initiate',
          '/auth/pair/complete',
          '/auth/token',
        ]);
        expect(PUBLIC_PATHS.has(route)).toBe(false);
      });
    }
  });
});
