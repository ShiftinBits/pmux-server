import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  checkRateLimit,
  rateLimitResponse,
  ENDPOINT_LIMITS,
  MAX_WS_CONNECTIONS_PER_DEVICE,
  type RateLimitStorage,
} from '../middleware/ratelimit';
import { createTestDOCompat as createTestDO, createMockKVStorage } from './helpers/mock-do';
import { MockWebSocket } from './helpers/mock-websocket';
import { createJWT } from '../auth';
import { generateEd25519Keypair, bytesToBase64, signedPairInitiateBody } from './helpers/crypto';
import type { SignalingDO } from '../signaling';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

// --- Unit tests: checkRateLimit ---

describe('checkRateLimit', () => {
  let storage: RateLimitStorage;

  beforeEach(() => {
    const kv = createMockKVStorage();
    storage = kv;
  });

  it('allows requests under the limit', async () => {
    const result = await checkRateLimit(storage, '192.168.1.1', '/pair/initiate');
    expect(result.allowed).toBe(true);
    expect(result.current).toBe(1);
    expect(result.limit).toBe(10);
  });

  it('allows requests up to the limit', async () => {
    const limit = ENDPOINT_LIMITS['/pair/initiate']!.maxRequests;

    for (let i = 0; i < limit; i++) {
      const result = await checkRateLimit(storage, '192.168.1.1', '/pair/initiate');
      expect(result.allowed).toBe(true);
      expect(result.current).toBe(i + 1);
    }
  });

  it('blocks requests over the limit with retryAfter', async () => {
    const limit = ENDPOINT_LIMITS['/pair/initiate']!.maxRequests;

    // Fill up the limit
    for (let i = 0; i < limit; i++) {
      await checkRateLimit(storage, '192.168.1.1', '/pair/initiate');
    }

    // Next request should be blocked
    const result = await checkRateLimit(storage, '192.168.1.1', '/pair/initiate');
    expect(result.allowed).toBe(false);
    expect(result.retryAfter).toBeGreaterThan(0);
    expect(result.retryAfter).toBeLessThanOrEqual(60);
    expect(result.current).toBe(limit); // current stays at limit, not incremented
    expect(result.limit).toBe(limit);
  });

  it('resets after window expires', async () => {
    const limit = ENDPOINT_LIMITS['/pair/initiate']!.maxRequests;
    const windowMs = ENDPOINT_LIMITS['/pair/initiate']!.windowMs;

    // Fill the limit
    for (let i = 0; i < limit; i++) {
      await checkRateLimit(storage, '192.168.1.1', '/pair/initiate');
    }

    // Verify blocked
    const blocked = await checkRateLimit(storage, '192.168.1.1', '/pair/initiate');
    expect(blocked.allowed).toBe(false);

    // Advance time past the window
    const realDateNow = Date.now;
    Date.now = () => realDateNow() + windowMs + 1;

    try {
      // Should be allowed again
      const result = await checkRateLimit(storage, '192.168.1.1', '/pair/initiate');
      expect(result.allowed).toBe(true);
      expect(result.current).toBe(1);
    } finally {
      Date.now = realDateNow;
    }
  });

  it('isolates rate limits per IP', async () => {
    const limit = ENDPOINT_LIMITS['/pair/initiate']!.maxRequests;

    // Fill limit for IP 1
    for (let i = 0; i < limit; i++) {
      await checkRateLimit(storage, '10.0.0.1', '/pair/initiate');
    }

    // IP 1 is blocked
    const blocked = await checkRateLimit(storage, '10.0.0.1', '/pair/initiate');
    expect(blocked.allowed).toBe(false);

    // IP 2 should still be allowed
    const allowed = await checkRateLimit(storage, '10.0.0.2', '/pair/initiate');
    expect(allowed.allowed).toBe(true);
    expect(allowed.current).toBe(1);
  });

  it('isolates rate limits per endpoint', async () => {
    const limit = ENDPOINT_LIMITS['/pair/initiate']!.maxRequests;

    // Fill limit for /pair/initiate
    for (let i = 0; i < limit; i++) {
      await checkRateLimit(storage, '192.168.1.1', '/pair/initiate');
    }

    // /pair/initiate is blocked
    const blocked = await checkRateLimit(storage, '192.168.1.1', '/pair/initiate');
    expect(blocked.allowed).toBe(false);

    // /pair/complete should still be allowed (separate counter)
    const allowed = await checkRateLimit(storage, '192.168.1.1', '/pair/complete');
    expect(allowed.allowed).toBe(true);
  });

  it('allows unknown endpoints (no limit configured)', async () => {
    const result = await checkRateLimit(storage, '192.168.1.1', '/unknown');
    expect(result.allowed).toBe(true);
    expect(result.limit).toBe(0);
  });

  describe('per-endpoint limits', () => {
    it('/pair/initiate allows 10 per minute', () => {
      expect(ENDPOINT_LIMITS['/pair/initiate']!.maxRequests).toBe(10);
      expect(ENDPOINT_LIMITS['/pair/initiate']!.windowMs).toBe(60_000);
    });

    it('/pair/complete allows 10 per minute', () => {
      expect(ENDPOINT_LIMITS['/pair/complete']!.maxRequests).toBe(10);
      expect(ENDPOINT_LIMITS['/pair/complete']!.windowMs).toBe(60_000);
    });

    it('/token allows 30 per minute', () => {
      expect(ENDPOINT_LIMITS['/token']!.maxRequests).toBe(30);
      expect(ENDPOINT_LIMITS['/token']!.windowMs).toBe(60_000);
    });

    it('/turn/credentials allows 20 per minute', () => {
      expect(ENDPOINT_LIMITS['/turn/credentials']!.maxRequests).toBe(20);
      expect(ENDPOINT_LIMITS['/turn/credentials']!.windowMs).toBe(60_000);
    });

    it('/ws allows 8 per 10 seconds', () => {
      expect(ENDPOINT_LIMITS['/ws']!.maxRequests).toBe(8);
      expect(ENDPOINT_LIMITS['/ws']!.windowMs).toBe(10_000);
    });
  });
});

describe('rateLimitResponse', () => {
  it('returns 429 with Retry-After header', async () => {
    const response = rateLimitResponse(42);
    expect(response.status).toBe(429);
    expect(response.headers.get('Retry-After')).toBe('42');

    const body = await response.json() as Record<string, unknown>;
    expect(body['error']).toBe('Too many requests');
  });
});

// --- Integration tests: DO with rate limiting ---

describe('DO rate limiting integration', () => {
  let doInstance: SignalingDO;

  beforeEach(async () => {
    doInstance = await createTestDO();
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
    const data = await response.json() as Record<string, unknown>;
    return { status: response.status, data, response };
  }

  describe('pairing rate limits', () => {
    it('allows pairing requests under the limit', async () => {
      for (let i = 0; i < 10; i++) {
        const keys = await generateEd25519Keypair();
        const body = await signedPairInitiateBody(
          `agent-${i}`, keys.keyPair, bytesToBase64(keys.publicKeyRaw), `x25519-key-${i}`
        );
        const { status } = await postJSON('/pair/initiate', body);
        expect(status).toBe(200);
      }
    });

    it('blocks 11th pairing request with 429', async () => {
      // Send 10 requests (the limit)
      for (let i = 0; i < 10; i++) {
        const keys = await generateEd25519Keypair();
        const body = await signedPairInitiateBody(
          `agent-${i}`, keys.keyPair, bytesToBase64(keys.publicKeyRaw), `x25519-key-${i}`
        );
        const { status } = await postJSON('/pair/initiate', body);
        expect(status).toBe(200);
      }

      // 11th should be rate limited (body doesn't matter — 429 fires before handler)
      const { status, data, response } = await postJSON('/pair/initiate', {
        deviceId: 'agent-overflow',
        publicKey: 'pub-key-overflow',
        x25519PublicKey: 'x25519-key-overflow',
      });
      expect(status).toBe(429);
      expect(data['error']).toBe('Too many requests');
      expect(response.headers.get('Retry-After')).toBeDefined();
    });

    it('rate limits /pair/complete separately from /pair/initiate', async () => {
      // Exhaust /pair/initiate limit
      for (let i = 0; i < 10; i++) {
        const keys = await generateEd25519Keypair();
        const body = await signedPairInitiateBody(
          `agent-${i}`, keys.keyPair, bytesToBase64(keys.publicKeyRaw), `x25519-key-${i}`
        );
        await postJSON('/pair/initiate', body);
      }

      // /pair/complete should still work (separate counter)
      const { status } = await postJSON('/pair/complete', {
        pairingCode: 'ABCDEF',
        deviceId: 'mobile-1',
        publicKey: 'pub-key-mobile',
        x25519PublicKey: 'x25519-key-mobile',
      });
      // 404 because the pairing code is invalid, but NOT 429
      expect(status).toBe(404);
    });

    it('different IPs have separate rate limits', async () => {
      // Fill limit for IP 1
      for (let i = 0; i < 10; i++) {
        const keys = await generateEd25519Keypair();
        const body = await signedPairInitiateBody(
          `agent-${i}`, keys.keyPair, bytesToBase64(keys.publicKeyRaw), `x25519-key-${i}`
        );
        await postJSON('/pair/initiate', body, { 'X-Client-IP': '10.0.0.1' });
      }

      // IP 1 is blocked
      const blocked = await postJSON('/pair/initiate', {
        deviceId: 'agent-blocked',
        publicKey: 'pub-key-blocked',
        x25519PublicKey: 'x25519-key-blocked',
      }, { 'X-Client-IP': '10.0.0.1' });
      expect(blocked.status).toBe(429);

      // IP 2 is still allowed
      const keys = await generateEd25519Keypair();
      const body = await signedPairInitiateBody(
        'agent-allowed', keys.keyPair, bytesToBase64(keys.publicKeyRaw), 'x25519-key-allowed'
      );
      const allowed = await postJSON('/pair/initiate', body, { 'X-Client-IP': '10.0.0.2' });
      expect(allowed.status).toBe(200);
    });
  });

  describe('token rate limits', () => {
    it('allows token requests under the limit', async () => {
      // Send 30 token requests (the limit) — they'll fail (unknown device) but should not be rate limited
      for (let i = 0; i < 30; i++) {
        const { status } = await postJSON('/token', {
          deviceId: 'nonexistent-device',
          timestamp: String(Math.floor(Date.now() / 1000)),
          signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        });
        // 401 because device is unknown, but NOT 429
        expect(status).toBe(401);
      }
    });

    it('blocks 31st token request with 429', async () => {
      // Send 30 requests (the limit)
      for (let i = 0; i < 30; i++) {
        await postJSON('/token', {
          deviceId: 'nonexistent-device',
          timestamp: String(Math.floor(Date.now() / 1000)),
          signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        });
      }

      // 31st should be rate limited
      const { status, data } = await postJSON('/token', {
        deviceId: 'nonexistent-device',
        timestamp: String(Math.floor(Date.now() / 1000)),
        signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      });
      expect(status).toBe(429);
      expect(data['error']).toBe('Too many requests');
    });
  });
});

// --- WebSocket connection limits ---

describe('WebSocket connection limits', () => {
  let doInstance: SignalingDO;

  beforeEach(async () => {
    doInstance = await createTestDO();
  });

  async function setupDevice(
    deviceId: string,
    deviceType: 'host' | 'mobile'
  ): Promise<string> {
    doInstance.registerDevice(deviceId, `pubkey-${deviceId}`, deviceType);
    return createJWT(deviceId, deviceType, JWT_SECRET);
  }

  async function connectAndAuth(
    deviceId: string,
    deviceType: 'host' | 'mobile'
  ): Promise<{ ws: MockWebSocket; token: string }> {
    const token = await setupDevice(deviceId, deviceType);
    const ws = new MockWebSocket();

    doInstance.setConnection(deviceId, ws as unknown as WebSocket);

    await doInstance.webSocketMessage(
      ws as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token })
    );

    return { ws, token };
  }

  it('allows up to MAX_WS_CONNECTIONS_PER_DEVICE connections', async () => {
    expect(MAX_WS_CONNECTIONS_PER_DEVICE).toBe(5);

    const token = await setupDevice('agent-1', 'host');

    // Open 5 connections (the limit)
    for (let i = 0; i < MAX_WS_CONNECTIONS_PER_DEVICE; i++) {
      const ws = new MockWebSocket();
      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token })
      );
      expect(ws.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
      expect(ws.closed).toBe(false);
    }

    expect(doInstance.getWsConnectionCount('agent-1')).toBe(5);
  });

  it('rejects 6th WebSocket from same device with code 1008', async () => {
    const token = await setupDevice('agent-1', 'host');

    // Open 5 connections
    for (let i = 0; i < MAX_WS_CONNECTIONS_PER_DEVICE; i++) {
      const ws = new MockWebSocket();
      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token })
      );
    }

    // 6th connection should be rejected
    const ws6 = new MockWebSocket();
    await doInstance.webSocketMessage(
      ws6 as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token })
    );

    expect(ws6.lastMessage()).toEqual({ type: 'error', error: 'Too many WebSocket connections' });
    expect(ws6.closed).toBe(true);
    expect(ws6.closeCode).toBe(1008);
  });

  it('decrements count on WebSocket close', async () => {
    const token = await setupDevice('agent-1', 'host');

    // Open 5 connections
    const sockets: MockWebSocket[] = [];
    for (let i = 0; i < MAX_WS_CONNECTIONS_PER_DEVICE; i++) {
      const ws = new MockWebSocket();
      ws.serializeAttachment({
        deviceId: 'agent-1',
        deviceType: 'host',
        authenticated: true,
      });
      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token })
      );
      sockets.push(ws);
    }

    expect(doInstance.getWsConnectionCount('agent-1')).toBe(5);

    // Close one connection
    await doInstance.webSocketClose(
      sockets[0] as unknown as WebSocket,
      1000,
      'normal closure',
      true
    );

    expect(doInstance.getWsConnectionCount('agent-1')).toBe(4);

    // Now a new connection should succeed
    const wsNew = new MockWebSocket();
    await doInstance.webSocketMessage(
      wsNew as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token })
    );
    expect(wsNew.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
    expect(wsNew.closed).toBe(false);
    expect(doInstance.getWsConnectionCount('agent-1')).toBe(5);
  });

  it('decrements count on WebSocket error', async () => {
    const { ws } = await connectAndAuth('agent-1', 'host');

    expect(doInstance.getWsConnectionCount('agent-1')).toBe(1);

    await doInstance.webSocketError(
      ws as unknown as WebSocket,
      new Error('connection reset')
    );

    expect(doInstance.getWsConnectionCount('agent-1')).toBe(0);
  });

  it('different devices have independent connection limits', async () => {
    const token1 = await setupDevice('agent-1', 'host');
    const token2 = await setupDevice('agent-2', 'host');

    // Fill limit for device 1
    for (let i = 0; i < MAX_WS_CONNECTIONS_PER_DEVICE; i++) {
      const ws = new MockWebSocket();
      await doInstance.webSocketMessage(
        ws as unknown as WebSocket,
        JSON.stringify({ type: 'auth', token: token1 })
      );
    }

    // Device 1 is at limit
    const ws1Overflow = new MockWebSocket();
    await doInstance.webSocketMessage(
      ws1Overflow as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: token1 })
    );
    expect(ws1Overflow.closeCode).toBe(1008);

    // Device 2 should still be able to connect
    const ws2 = new MockWebSocket();
    await doInstance.webSocketMessage(
      ws2 as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: token2 })
    );
    expect(ws2.lastMessage()).toEqual({ type: 'auth', status: 'ok' });
    expect(ws2.closed).toBe(false);
  });
});

// --- Pairing code expiry ---

describe('pairing code expiry enforcement', () => {
  let doInstance: SignalingDO;
  let realDateNow: () => number;

  beforeEach(async () => {
    doInstance = await createTestDO();
    realDateNow = Date.now;
  });

  afterEach(() => {
    Date.now = realDateNow;
  });

  async function postJSON(
    path: string,
    body: unknown
  ): Promise<{ status: number; data: Record<string, unknown> }> {
    const request = new Request(`http://localhost${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-IP': '127.0.0.1',
      },
      body: JSON.stringify(body),
    });
    const response = await doInstance.fetch(request);
    const data = await response.json() as Record<string, unknown>;
    return { status: response.status, data };
  }

  it('rejects pairing code after 5-minute expiry', async () => {
    // Create pairing session
    const keys = await generateEd25519Keypair();
    const body = await signedPairInitiateBody(
      'agent-1', keys.keyPair, bytesToBase64(keys.publicKeyRaw), 'x25519-key-agent'
    );
    const initResult = await postJSON('/pair/initiate', body);
    const code = initResult.data['pairingCode'] as string;

    // Advance time past 5-minute expiry
    Date.now = () => realDateNow() + 6 * 60 * 1000;

    const { status, data } = await postJSON('/pair/complete', {
      pairingCode: code,
      deviceId: 'mobile-1',
      publicKey: 'pub-key-mobile',
      x25519PublicKey: 'x25519-key-mobile',
    });

    expect(status).toBe(404);
    expect(data['error']).toContain('Invalid or expired');
  });

  it('accepts pairing code within 5-minute window', async () => {
    const keys = await generateEd25519Keypair();
    const body = await signedPairInitiateBody(
      'agent-1', keys.keyPair, bytesToBase64(keys.publicKeyRaw), 'x25519-key-agent'
    );
    const initResult = await postJSON('/pair/initiate', body);
    const code = initResult.data['pairingCode'] as string;

    // Advance time to just under 5 minutes
    Date.now = () => realDateNow() + 4 * 60 * 1000;

    const { status } = await postJSON('/pair/complete', {
      pairingCode: code,
      deviceId: 'mobile-1',
      publicKey: 'pub-key-mobile',
      x25519PublicKey: 'x25519-key-mobile',
    });

    expect(status).toBe(200);
  });
});

// --- Legitimate usage stays under limits ---

describe('legitimate usage patterns', () => {
  let doInstance: SignalingDO;

  beforeEach(async () => {
    doInstance = await createTestDO();
  });

  async function postJSON(
    path: string,
    body: unknown,
    headers?: Record<string, string>
  ): Promise<{ status: number; data: Record<string, unknown> }> {
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
    const data = await response.json() as Record<string, unknown>;
    return { status: response.status, data };
  }

  it('normal pairing flow stays under limits', async () => {
    // A normal user: 1 pair/initiate + 1 pair/complete
    const keys = await generateEd25519Keypair();
    const body = await signedPairInitiateBody(
      'agent-1', keys.keyPair, bytesToBase64(keys.publicKeyRaw), 'x25519-key-agent'
    );
    const initResult = await postJSON('/pair/initiate', body);
    expect(initResult.status).toBe(200);

    const { status } = await postJSON('/pair/complete', {
      pairingCode: initResult.data['pairingCode'],
      deviceId: 'mobile-1',
      publicKey: 'pub-key-mobile',
      x25519PublicKey: 'x25519-key-mobile',
    });
    expect(status).toBe(200);
  });

  it('multiple token refreshes from different IPs stay under limits', async () => {
    // 5 token requests from each of 3 different IPs = 15 total, all under the 30/min per IP
    for (let ip = 1; ip <= 3; ip++) {
      for (let i = 0; i < 5; i++) {
        const { status } = await postJSON('/token', {
          deviceId: 'device-1',
          timestamp: String(Math.floor(Date.now() / 1000)),
          signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        }, { 'X-Client-IP': `10.0.0.${ip}` });
        // Expect 401 (bad sig) not 429 (rate limited)
        expect(status).toBe(401);
      }
    }
  });
});

// --- Worker client IP extraction ---

describe('worker client IP extraction', () => {
  it('extractClientIp uses CF-Connecting-IP first', async () => {
    const { extractClientIp } = await import('../worker');
    const request = new Request('http://localhost/', {
      headers: {
        'CF-Connecting-IP': '1.2.3.4',
        'X-Forwarded-For': '5.6.7.8',
      },
    });
    expect(extractClientIp(request)).toBe('1.2.3.4');
  });

  it('extractClientIp falls back to X-Forwarded-For', async () => {
    const { extractClientIp } = await import('../worker');
    const request = new Request('http://localhost/', {
      headers: {
        'X-Forwarded-For': '5.6.7.8, 9.10.11.12',
      },
    });
    expect(extractClientIp(request)).toBe('5.6.7.8');
  });

  it('extractClientIp defaults to 127.0.0.1', async () => {
    const { extractClientIp } = await import('../worker');
    const request = new Request('http://localhost/');
    expect(extractClientIp(request)).toBe('127.0.0.1');
  });
});
