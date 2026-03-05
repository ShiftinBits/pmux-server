import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDOCompat as createTestDO } from './helpers/mock-do';
import type { SignalingDO } from '../signaling';

let doInstance: SignalingDO;

beforeEach(async () => {
  doInstance = await createTestDO();
});

async function sendRequest(
  method: string,
  path: string
): Promise<{ status: number; headers: Headers; data: Record<string, unknown> }> {
  const request = new Request(`http://localhost${path}`, { method });
  const response = await doInstance.fetch(request);
  const data = await response.json() as Record<string, unknown>;
  return { status: response.status, headers: response.headers, data };
}

describe('405 Method Not Allowed', () => {
  it('returns 405 for GET /pair/initiate with Allow: POST', async () => {
    const { status, headers, data } = await sendRequest('GET', '/pair/initiate');

    expect(status).toBe(405);
    expect(headers.get('Allow')).toBe('POST');
    expect(data['error']).toBe('Method Not Allowed');
  });

  it('returns 405 for GET /pair/complete with Allow: POST', async () => {
    const { status, headers, data } = await sendRequest('GET', '/pair/complete');

    expect(status).toBe(405);
    expect(headers.get('Allow')).toBe('POST');
    expect(data['error']).toBe('Method Not Allowed');
  });

  it('returns 405 for GET /token with Allow: POST', async () => {
    const { status, headers, data } = await sendRequest('GET', '/token');

    expect(status).toBe(405);
    expect(headers.get('Allow')).toBe('POST');
    expect(data['error']).toBe('Method Not Allowed');
  });

  it('returns 405 for POST /turn/credentials with Allow: GET', async () => {
    const { status, headers, data } = await sendRequest('POST', '/turn/credentials');

    expect(status).toBe(405);
    expect(headers.get('Allow')).toBe('GET');
    expect(data['error']).toBe('Method Not Allowed');
  });

  it('returns 405 for PUT /pair/initiate with Allow: POST', async () => {
    const { status, headers, data } = await sendRequest('PUT', '/pair/initiate');

    expect(status).toBe(405);
    expect(headers.get('Allow')).toBe('POST');
    expect(data['error']).toBe('Method Not Allowed');
  });

  it('returns 405 for DELETE /token with Allow: POST', async () => {
    const { status, headers, data } = await sendRequest('DELETE', '/token');

    expect(status).toBe(405);
    expect(headers.get('Allow')).toBe('POST');
    expect(data['error']).toBe('Method Not Allowed');
  });
});

describe('404 Not Found', () => {
  it('returns 404 for unknown paths', async () => {
    const { status, data } = await sendRequest('GET', '/nonexistent');

    expect(status).toBe(404);
    expect(data['error']).toBe('Not Found');
  });

  it('returns 404 for GET with unknown path', async () => {
    const { status, data } = await sendRequest('POST', '/unknown/path');

    expect(status).toBe(404);
    expect(data['error']).toBe('Not Found');
  });
});
