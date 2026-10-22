import { describe, it, expect } from 'vitest';
import worker, { type Env } from '../worker';
import { createJWT } from '../auth';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

// DO stub that records the request the worker forwards to it
function makeCapturingEnv(): { env: Env; received: () => Request } {
  let captured: Request | undefined;
  const stub = {
    fetch: async (req: Request) => {
      captured = req;
      return new Response('{}');
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_name: string) => ({ toString: () => 'mock-id' } as DurableObjectId),
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;

  return {
    env: { JWT_SECRET, SIGNALING: namespace, TURN_TOKEN_ID: '', TURN_API_TOKEN: '' },
    received: () => {
      if (!captured) throw new Error('request never reached the DO');
      return captured;
    },
  };
}

describe('worker context headers [SB-1340]', () => {
  it('replaces client-sent X-Client-IP and strips device headers on a public route', async () => {
    const { env, received } = makeCapturingEnv();
    const req = new Request('http://localhost/auth/token', {
      method: 'POST',
      headers: {
        'CF-Connecting-IP': '1.2.3.4',
        'X-Client-IP': '9.9.9.9',
        'x-device-id': 'evil',
        'X-Device-Type': 'host',
      },
    });

    await worker.fetch(req, env);

    const headers = received().headers;
    expect(headers.get('X-Client-IP')).toBe('1.2.3.4');
    expect(headers.get('X-Device-Id')).toBeNull();
    expect(headers.get('X-Device-Type')).toBeNull();
    expect(headers.get('Upgrade')).toBeNull();
  });

  it('forwards Upgrade but no other client header on /ws', async () => {
    const { env, received } = makeCapturingEnv();
    const req = new Request('http://localhost/ws', {
      headers: {
        'CF-Connecting-IP': '1.2.3.4',
        Upgrade: 'websocket',
        'X-Client-IP': '9.9.9.9',
        'X-Anything': 'client-value',
      },
    });

    await worker.fetch(req, env);

    const headers = received().headers;
    expect(headers.get('Upgrade')).toBe('websocket');
    expect(headers.get('X-Client-IP')).toBe('1.2.3.4');
    expect(headers.get('X-Anything')).toBeNull();
    expect(headers.get('CF-Connecting-IP')).toBeNull();
  });

  it('replaces client-sent X-Client-IP / X-Device-Id / X-Device-Type on a JWT route', async () => {
    const { env, received } = makeCapturingEnv();
    const token = await createJWT('device-1', 'mobile', JWT_SECRET);
    const req = new Request('http://localhost/turn/credentials', {
      headers: {
        Authorization: `Bearer ${token}`,
        'CF-Connecting-IP': '1.2.3.4',
        'x-client-ip': '9.9.9.9',
        'X-Device-Id': 'evil',
        'X-Device-Type': 'host',
        'X-Anything': 'client-value',
      },
    });

    await worker.fetch(req, env);

    const headers = received().headers;
    expect(headers.get('X-Client-IP')).toBe('1.2.3.4');
    expect(headers.get('X-Device-Id')).toBe('device-1');
    expect(headers.get('X-Device-Type')).toBe('mobile');
    expect(headers.get('X-Anything')).toBeNull();
    expect(headers.get('Authorization')).toBeNull();
  });
});
