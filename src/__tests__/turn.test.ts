import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { generateTurnCredentials } from '../turn';
import type { Env } from '../worker';

const mockEnv: Env = {
  TURN_TOKEN_ID: 'test-turn-token-id',
  TURN_API_TOKEN: 'test-turn-api-token',
  JWT_SECRET: 'test-jwt-secret-at-least-32-chars-long',
  SIGNALING: undefined as unknown as DurableObjectNamespace,
};

// Store the original fetch so we can restore it
const originalFetch = globalThis.fetch;

beforeEach(() => {
  // Reset fetch mock before each test
  globalThis.fetch = vi.fn();
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('generateTurnCredentials', () => {
  it('returns credentials with correct format', async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          iceServers: {
            username: 'test-user',
            credential: 'test-cred',
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const creds = await generateTurnCredentials(mockEnv);

    expect(creds.urls).toHaveLength(3);
    expect(creds.urls).toContain('stun:stun.cloudflare.com:3478');
    expect(creds.urls).toContain('turn:turn.cloudflare.com:3478');
    expect(creds.urls).toContain('turns:turn.cloudflare.com:5349');
    expect(creds.username).toBe('test-user');
    expect(creds.credential).toBe('test-cred');
  });

  it('calls Cloudflare API with correct parameters', async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          iceServers: { username: 'u', credential: 'c' },
        }),
        { status: 200 }
      )
    );

    await generateTurnCredentials(mockEnv);

    expect(globalThis.fetch).toHaveBeenCalledWith(
      `https://rtc.live.cloudflare.com/v1/turn/keys/${mockEnv.TURN_TOKEN_ID}/credentials/generate`,
      expect.objectContaining({
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${mockEnv.TURN_API_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ttl: 3600 }),
      })
    );
  });

  it('throws on non-OK response (rate limit)', async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(
      new Response('Rate limit exceeded', { status: 429 })
    );

    await expect(generateTurnCredentials(mockEnv)).rejects.toThrow(
      'Cloudflare TURN API error (429)'
    );
  });

  it('throws on invalid API token (401)', async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401 })
    );

    await expect(generateTurnCredentials(mockEnv)).rejects.toThrow(
      'Cloudflare TURN API error (401)'
    );
  });

  it('throws on missing iceServers in response', async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({}), { status: 200 })
    );

    await expect(generateTurnCredentials(mockEnv)).rejects.toThrow(
      'missing iceServers credentials'
    );
  });

  it('throws on malformed iceServers response', async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({ iceServers: { username: 'u' } }), // missing credential
        { status: 200 }
      )
    );

    await expect(generateTurnCredentials(mockEnv)).rejects.toThrow(
      'missing iceServers credentials'
    );
  });

  it('does not include raw response body in error message', async () => {
    const sensitiveBody = 'account-id: acct_1234, endpoint: internal.cloudflare.com/v1/turn';
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(
      new Response(sensitiveBody, { status: 500 })
    );

    try {
      await generateTurnCredentials(mockEnv);
      expect.fail('Expected generateTurnCredentials to throw');
    } catch (err) {
      const message = (err as Error).message;
      expect(message).toBe('Cloudflare TURN API error (500)');
      expect(message).not.toContain(sensitiveBody);
      expect(message).not.toContain('account-id');
      expect(message).not.toContain('internal.cloudflare.com');
    }
  });

  it('handles network errors gracefully', async () => {
    vi.mocked(globalThis.fetch).mockRejectedValueOnce(new Error('Network error'));

    await expect(generateTurnCredentials(mockEnv)).rejects.toThrow('Network error');
  });
});
