import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDOCompat as createTestDO, createTestDO as createTestDOFull } from './helpers/mock-do';
import { MockWebSocket } from './helpers/mock-websocket';
import { createJWT } from '../auth';
import type { SignalingDO } from '../signaling';

let doInstance: SignalingDO;

beforeEach(async () => {
  doInstance = await createTestDO();
});

async function postJSON(
  path: string,
  body: unknown
): Promise<{ status: number; data: Record<string, unknown> }> {
  const request = new Request(`http://localhost${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const response = await doInstance.fetch(request);
  const data = await response.json() as Record<string, unknown>;
  return { status: response.status, data };
}

describe('POST /pair/initiate', () => {
  it('returns a pairing code', async () => {
    const { status, data } = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });

    expect(status).toBe(200);
    expect(data['pairingCode']).toBeTypeOf('string');
    expect((data['pairingCode'] as string).length).toBe(6);
  });

  it('registers the agent device', async () => {
    await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });

    const device = doInstance.getDevice('agent-1');
    expect(device).not.toBeNull();
    expect(device!.deviceType).toBe('host');
    expect(device!.publicKey).toBe('ed25519-pub-key-agent');
  });

  it('rejects missing fields', async () => {
    const { status, data } = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      // missing publicKey and x25519PublicKey
    });

    expect(status).toBe(400);
    expect(data['error']).toContain('Missing required fields');
  });

  it('stores host name when provided', async () => {
    await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
      name: 'my-workstation',
    });

    const device = doInstance.getDevice('agent-1');
    expect(device).not.toBeNull();
    expect(device!.name).toBe('my-workstation');
  });

  it('updates name on re-initiation', async () => {
    // First initiation with name
    await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
      name: 'old-name',
    });

    // Second initiation with a new name (device already exists)
    await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
      name: 'new-name',
    });

    const device = doInstance.getDevice('agent-1');
    expect(device!.name).toBe('new-name');
  });

  it('stores null name when not provided', async () => {
    await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });

    const device = doInstance.getDevice('agent-1');
    expect(device!.name).toBeNull();
  });

  it('rejects name longer than 64 characters', async () => {
    const { status, data } = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
      name: 'x'.repeat(65),
    });

    expect(status).toBe(400);
    expect(data['error']).toContain('64 characters');
  });

  it('does not update name when publicKey does not match', async () => {
    // First initiation registers the device
    await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
      name: 'original-name',
    });

    // Second initiation with wrong publicKey should not update name
    await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'wrong-public-key',
      x25519PublicKey: 'x25519-pub-key-agent',
      name: 'spoofed-name',
    });

    const device = doInstance.getDevice('agent-1');
    expect(device!.name).toBe('original-name');
  });

  it('invalidates previous pairing code when re-initiating', async () => {
    // First initiation — get a pairing code
    const first = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });
    expect(first.status).toBe(200);
    const firstCode = first.data['pairingCode'] as string;

    // Second initiation — same host, new code replaces the old one
    const second = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });
    expect(second.status).toBe(200);
    const secondCode = second.data['pairingCode'] as string;

    // First code should be invalidated (404)
    const completeFirst = await postJSON('/pair/complete', {
      pairingCode: firstCode,
      deviceId: 'mobile-1',
      publicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });
    expect(completeFirst.status).toBe(404);
    expect(completeFirst.data['error']).toContain('Invalid or expired');

    // Second code should still work (200)
    const completeSecond = await postJSON('/pair/complete', {
      pairingCode: secondCode,
      deviceId: 'mobile-1',
      publicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });
    expect(completeSecond.status).toBe(200);
    expect(completeSecond.data['hostDeviceId']).toBe('agent-1');
  });
});

describe('POST /pair/complete', () => {
  it('completes pairing flow successfully', async () => {
    // Step 1: Agent initiates pairing
    const initResult = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });
    const pairingCode = initResult.data['pairingCode'] as string;

    // Step 2: Mobile completes pairing
    const { status, data } = await postJSON('/pair/complete', {
      pairingCode,
      deviceId: 'mobile-1',
      publicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });

    expect(status).toBe(200);
    expect(data['hostX25519PublicKey']).toBe('x25519-pub-key-agent');
    expect(data['hostDeviceId']).toBe('agent-1');
    // userId should NOT be in the response
    expect(data['userId']).toBeUndefined();
  });

  it('creates a pairing between host and mobile', async () => {
    // Initiate
    const initResult = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });

    // Complete
    await postJSON('/pair/complete', {
      pairingCode: initResult.data['pairingCode'],
      deviceId: 'mobile-1',
      publicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });

    // Verify pairing exists
    expect(doInstance.isPaired('agent-1', 'mobile-1')).toBe(true);
    expect(doInstance.getPairedMobile('agent-1')).toBe('mobile-1');
  });

  it('rejects invalid pairing code', async () => {
    const { status, data } = await postJSON('/pair/complete', {
      pairingCode: 'BADCODE',
      deviceId: 'mobile-1',
      publicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });

    expect(status).toBe(404);
    expect(data['error']).toContain('Invalid or expired');
  });

  it('rejects reused pairing code', async () => {
    // Initiate
    const initResult = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });
    const code = initResult.data['pairingCode'] as string;

    // First complete — succeeds
    const first = await postJSON('/pair/complete', {
      pairingCode: code,
      deviceId: 'mobile-1',
      publicKey: 'ed25519-pub-key-mobile-1',
      x25519PublicKey: 'x25519-pub-key-mobile-1',
    });
    expect(first.status).toBe(200);

    // Second complete with same code — fails
    const second = await postJSON('/pair/complete', {
      pairingCode: code,
      deviceId: 'mobile-2',
      publicKey: 'ed25519-pub-key-mobile-2',
      x25519PublicKey: 'x25519-pub-key-mobile-2',
    });
    expect(second.status).toBe(404);
    expect(second.data['error']).toContain('Invalid or expired');
  });

  it('rejects expired pairing code', async () => {
    // Initiate
    const initResult = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });
    const code = initResult.data['pairingCode'] as string;

    // Advance time past 5-minute expiry
    const realDateNow = Date.now;
    Date.now = () => realDateNow() + 6 * 60 * 1000;

    try {
      const { status, data } = await postJSON('/pair/complete', {
        pairingCode: code,
        deviceId: 'mobile-1',
        publicKey: 'ed25519-pub-key-mobile',
        x25519PublicKey: 'x25519-pub-key-mobile',
      });

      expect(status).toBe(404);
      expect(data['error']).toContain('Invalid or expired');
    } finally {
      Date.now = realDateNow;
    }
  });

  it('rejects missing fields', async () => {
    const { status, data } = await postJSON('/pair/complete', {
      pairingCode: 'ABCDEF',
      // missing deviceId, publicKey, x25519PublicKey
    });

    expect(status).toBe(400);
    expect(data['error']).toContain('Missing required fields');
  });

  it('sends pair_complete to all WebSockets for the host device', async () => {
    const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';
    const { doInstance: do2, mockState } = await createTestDOFull();

    // Helper for HTTP requests against this DO instance
    async function post(path: string, body: unknown) {
      const req = new Request(`http://localhost${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const res = await do2.fetch(req);
      return { status: res.status, data: await res.json() as Record<string, unknown> };
    }

    // Initiate pairing (registers the host device)
    const initResult = await post('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });
    expect(initResult.status).toBe(200);
    const pairingCode = initResult.data['pairingCode'] as string;

    // Create two WebSockets for the same host device (background agent + pair CLI)
    const token = await createJWT('agent-1', 'host', JWT_SECRET);

    const agentWs = new MockWebSocket();
    const pairCliWs = new MockWebSocket();

    // Add both to the hibernation API's WebSocket list
    mockState.acceptedWebSockets.push(
      agentWs as unknown as WebSocket,
      pairCliWs as unknown as WebSocket,
    );

    // Authenticate both WebSockets
    await do2.webSocketMessage(agentWs as unknown as WebSocket, JSON.stringify({ type: 'auth', token }));
    await do2.webSocketMessage(pairCliWs as unknown as WebSocket, JSON.stringify({ type: 'auth', token }));

    // Clear auth responses
    agentWs.sent.length = 0;
    pairCliWs.sent.length = 0;

    // Complete pairing
    const completeResult = await post('/pair/complete', {
      pairingCode,
      deviceId: 'mobile-1',
      publicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });
    expect(completeResult.status).toBe(200);

    // Both WebSockets should have received pair_complete
    const agentMsgs = agentWs.messagesOfType('pair_complete');
    const pairCliMsgs = pairCliWs.messagesOfType('pair_complete');

    expect(agentMsgs).toHaveLength(1);
    expect(pairCliMsgs).toHaveLength(1);
    expect(agentMsgs[0]['mobileDeviceId']).toBe('mobile-1');
    expect(pairCliMsgs[0]['mobileX25519PublicKey']).toBe('x25519-pub-key-mobile');
  });

  it('re-pairing replaces old mobile and sends device_unpaired notification', async () => {
    const { doInstance: do2, mockState } = await createTestDOFull();

    async function post(path: string, body: unknown) {
      const req = new Request(`http://localhost${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const res = await do2.fetch(req);
      return { status: res.status, data: await res.json() as Record<string, unknown> };
    }

    // First pairing: agent-1 + mobile-1
    const init1 = await post('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });
    const code1 = init1.data['pairingCode'] as string;

    const complete1 = await post('/pair/complete', {
      pairingCode: code1,
      deviceId: 'mobile-1',
      publicKey: 'ed25519-pub-key-mobile-1',
      x25519PublicKey: 'x25519-pub-key-mobile-1',
    });
    expect(complete1.status).toBe(200);

    // Verify initial pairing
    expect(do2.isPaired('agent-1', 'mobile-1')).toBe(true);

    // Connect mobile-1 via WebSocket so it can receive notifications
    const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';
    const mobile1Token = await createJWT('mobile-1', 'mobile', JWT_SECRET);
    const mobile1Ws = new MockWebSocket();
    mockState.acceptedWebSockets.push(mobile1Ws as unknown as WebSocket);
    do2.setConnection('mobile-1', mobile1Ws as unknown as WebSocket);
    await do2.webSocketMessage(
      mobile1Ws as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: mobile1Token })
    );
    mobile1Ws.sent.length = 0;

    // Second pairing: agent-1 + mobile-2 (replaces mobile-1)
    const init2 = await post('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });
    const code2 = init2.data['pairingCode'] as string;

    const complete2 = await post('/pair/complete', {
      pairingCode: code2,
      deviceId: 'mobile-2',
      publicKey: 'ed25519-pub-key-mobile-2',
      x25519PublicKey: 'x25519-pub-key-mobile-2',
    });
    expect(complete2.status).toBe(200);

    // Verify new pairing replaced old one
    expect(do2.isPaired('agent-1', 'mobile-2')).toBe(true);
    expect(do2.isPaired('agent-1', 'mobile-1')).toBe(false);

    // Old mobile should have received device_unpaired notification
    const unpairedMsgs = mobile1Ws.messagesOfType('device_unpaired');
    expect(unpairedMsgs).toHaveLength(1);
    expect(unpairedMsgs[0]!['hostDeviceId']).toBe('agent-1');
    expect(unpairedMsgs[0]!['reason']).toBe('replaced_by_new_pairing');
  });

  it('same mobile re-pairing does not send device_unpaired notification', async () => {
    const { doInstance: do2, mockState } = await createTestDOFull();
    const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

    async function post(path: string, body: unknown) {
      const req = new Request(`http://localhost${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const res = await do2.fetch(req);
      return { status: res.status, data: await res.json() as Record<string, unknown> };
    }

    // First pairing: agent-1 + mobile-1
    const init1 = await post('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });
    const code1 = init1.data['pairingCode'] as string;

    await post('/pair/complete', {
      pairingCode: code1,
      deviceId: 'mobile-1',
      publicKey: 'ed25519-pub-key-mobile-1',
      x25519PublicKey: 'x25519-pub-key-mobile-1',
    });
    expect(do2.isPaired('agent-1', 'mobile-1')).toBe(true);

    // Connect mobile-1 via WebSocket
    const mobile1Token = await createJWT('mobile-1', 'mobile', JWT_SECRET);
    const mobile1Ws = new MockWebSocket();
    mockState.acceptedWebSockets.push(mobile1Ws as unknown as WebSocket);
    do2.setConnection('mobile-1', mobile1Ws as unknown as WebSocket);
    await do2.webSocketMessage(
      mobile1Ws as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: mobile1Token })
    );
    mobile1Ws.sent.length = 0;

    // Same mobile re-pairs with same host
    const init2 = await post('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent-2',
    });
    const code2 = init2.data['pairingCode'] as string;

    await post('/pair/complete', {
      pairingCode: code2,
      deviceId: 'mobile-1',
      publicKey: 'ed25519-pub-key-mobile-1',
      x25519PublicKey: 'x25519-pub-key-mobile-1b',
    });

    // Pairing should still exist
    expect(do2.isPaired('agent-1', 'mobile-1')).toBe(true);

    // NO device_unpaired notification should have been sent
    const unpairedMsgs = mobile1Ws.messagesOfType('device_unpaired');
    expect(unpairedMsgs).toHaveLength(0);
  });
});
