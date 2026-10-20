import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createTestDOCompat as createTestDO } from './helpers/mock-do';
import type { SignalingDO } from '../signaling';

const HOUR_MS = 60 * 60 * 1000;
const T0 = new Date('2026-01-01T00:00:00Z').getTime();

const originalFetch = globalThis.fetch;
let doInstance: SignalingDO;

function credsResponse(username: string): Response {
  return new Response(
    JSON.stringify({ iceServers: { username, credential: `${username}-cred` } }),
    { status: 200 }
  );
}

async function getCreds(): Promise<{ status: number; data: Record<string, unknown> }> {
  const response = await doInstance.fetch(new Request('http://localhost/turn/credentials'));
  return { status: response.status, data: await response.json() as Record<string, unknown> };
}

beforeEach(async () => {
  doInstance = await createTestDO();
  globalThis.fetch = vi.fn();
  // Fake only Date — sql.js WASM and promise scheduling stay real
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(T0);
});

afterEach(() => {
  vi.useRealTimers();
  globalThis.fetch = originalFetch;
});

describe('TURN credential cache', () => {
  it('serves cached credentials within the refresh window', async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(credsResponse('first'));

    const a = await getCreds();
    vi.setSystemTime(T0 + HOUR_MS - 1);
    const b = await getCreds();

    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    expect(a.status).toBe(200);
    expect(b.data).toEqual(a.data);
    expect(b.data['username']).toBe('first');
  });

  it('refetches once the cache is older than the refresh window', async () => {
    vi.mocked(globalThis.fetch)
      .mockResolvedValueOnce(credsResponse('first'))
      .mockResolvedValueOnce(credsResponse('second'));

    await getCreds();
    vi.setSystemTime(T0 + HOUR_MS);
    const b = await getCreds();

    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
    expect(b.data['username']).toBe('second');
  });

  it('dedupes concurrent cold-cache requests into one fetch', async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(credsResponse('first'));

    const results = await Promise.all([getCreds(), getCreds(), getCreds()]);

    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    for (const r of results) {
      expect(r.status).toBe(200);
      expect(r.data['username']).toBe('first');
    }
  });

  it('falls back to cached credentials when a refresh fails', async () => {
    vi.mocked(globalThis.fetch)
      .mockResolvedValueOnce(credsResponse('first'))
      .mockResolvedValueOnce(new Response('upstream down', { status: 503 }));

    await getCreds();
    vi.setSystemTime(T0 + 2 * HOUR_MS);
    const b = await getCreds();

    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
    expect(b.status).toBe(200);
    expect(b.data['username']).toBe('first');
  });

  it('returns 502 when a refresh fails and the cache is too old to serve', async () => {
    vi.mocked(globalThis.fetch)
      .mockResolvedValueOnce(credsResponse('first'))
      .mockRejectedValueOnce(new Error('Network error'));

    await getCreds();
    vi.setSystemTime(T0 + 13 * HOUR_MS);
    const b = await getCreds();

    expect(b.status).toBe(502);
  });

  it('does not cache failures — the next request retries', async () => {
    vi.mocked(globalThis.fetch)
      .mockRejectedValueOnce(new Error('Network error'))
      .mockResolvedValueOnce(credsResponse('first'));

    const a = await getCreds();
    const b = await getCreds();

    expect(a.status).toBe(502);
    expect(b.status).toBe(200);
    expect(b.data['username']).toBe('first');
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });
});
