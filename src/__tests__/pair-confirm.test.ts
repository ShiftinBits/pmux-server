import { describe, it, expect, afterEach, vi } from 'vitest';
import { createTestDO } from './helpers/mock-do';
import { MockWebSocket } from './helpers/mock-websocket';
import { createJWT } from '../auth';
import {
  generateEd25519Keypair,
  bytesToBase64,
  signEd25519,
  fetchChallenge,
  signedPairInitiateBodyWithChallenge,
  HOST_X25519_KEY,
} from './helpers/crypto';

// Host-confirmed pairing: /pair/complete is held until the host answers [SB-1348]

const AGENT_1 = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1';
const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

interface CompleteOverrides {
  ed25519PublicKey?: string;
  x25519PublicKey?: string;
}

async function setup(opts: { pairConfirm?: boolean; liveHost?: boolean; hostName?: string } = {}) {
  const { pairConfirm = true, liveHost = true, hostName } = opts;
  const { doInstance: do2, mockState } = await createTestDO();
  const keys = await generateEd25519Keypair();
  const pubBase64 = bytesToBase64(keys.publicKeyRaw);

  function request(path: string, body: unknown): Request {
    return new Request(`http://localhost${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  async function initiateBody(): Promise<Record<string, unknown>> {
    const body = await signedPairInitiateBodyWithChallenge(
      do2, AGENT_1, keys.keyPair, pubBase64, HOST_X25519_KEY, hostName
    );
    const res = await do2.fetch(request('/pair/initiate', { ...body, ...(pairConfirm && { pairConfirm: true }) }));
    expect(res.status).toBe(200);
    return (await res.json()) as Record<string, unknown>;
  }

  async function initiate(): Promise<string> {
    return (await initiateBody())['pairingCode'] as string;
  }

  async function authWs(deviceId: string, deviceType: 'host' | 'mobile', keepSent = false): Promise<MockWebSocket> {
    const ws = new MockWebSocket();
    mockState.acceptedWebSockets.push(ws as unknown as WebSocket);
    const token = await createJWT(deviceId, deviceType, JWT_SECRET);
    await do2.webSocketMessage(ws as unknown as WebSocket, JSON.stringify({ type: 'auth', token }));
    if (!keepSent) ws.sent.length = 0;
    return ws;
  }

  function complete(code: string, deviceId = 'mobile-1', overrides: CompleteOverrides = {}): Promise<Response> {
    return do2.fetch(request('/pair/complete', {
      pairingCode: code,
      deviceId,
      ed25519PublicKey: overrides.ed25519PublicKey ?? `ed25519-pub-key-${deviceId}`,
      x25519PublicKey: overrides.x25519PublicKey ?? `x25519-pub-key-${deviceId}`,
      pairMac: 'bWFj',
    }));
  }

  async function send(ws: MockWebSocket, msg: unknown): Promise<void> {
    await do2.webSocketMessage(ws as unknown as WebSocket, JSON.stringify(msg));
  }

  function heldCount(): number {
    return (do2['pendingPairs'] as Map<string, unknown>).size;
  }

  const code = await initiate();
  const hostWs = liveHost ? await authWs(AGENT_1, 'host') : null;
  return { do2, code, hostWs, initiate, initiateBody, authWs, complete, send, request, heldCount };
}

/** Wait until the held request has relayed pair_complete to the host socket. */
async function relayed(ws: MockWebSocket, count = 1): Promise<void> {
  await vi.waitFor(() => expect(ws.messagesOfType('pair_complete')).toHaveLength(count));
}

describe('host-confirmed pairing (SB-1348)', () => {
  it('stores pair_confirm from /pair/initiate on the session', async () => {
    const { do2, code } = await setup();
    expect(do2.consumePairingSession(code)!.pairConfirm).toBe(true);

    const legacy = await setup({ pairConfirm: false });
    expect(legacy.do2.consumePairingSession(legacy.code)!.pairConfirm).toBe(false);
  });

  it('echoes pairConfirm: true from /pair/initiate only when requested', async () => {
    const confirming = await setup();
    expect(await confirming.initiateBody()).toEqual({ pairingCode: expect.any(String), pairConfirm: true });

    const legacy = await setup({ pairConfirm: false });
    const body = await legacy.initiateBody();
    expect(body).toEqual({ pairingCode: expect.any(String) });
    expect(body).not.toHaveProperty('pairConfirm');
  });

  it('holds /pair/complete without committing until pair_accept, then commits and acks the host', async () => {
    const { do2, code, hostWs, complete, send } = await setup({ hostName: 'build-box' });
    const pending = complete(code);
    await relayed(hostWs!);

    const relay = hostWs!.messagesOfType('pair_complete')[0]!;
    expect(relay['mobileDeviceId']).toBe('mobile-1');
    expect(relay['pairMac']).toBe('bWFj');
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(false);
    expect(do2.getDevice('mobile-1')).toBeNull();

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    const res = await pending;
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      hostDeviceId: AGENT_1,
      hostX25519PublicKey: HOST_X25519_KEY,
      hostName: 'build-box',
    });
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(true);
    expect(hostWs!.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-1', ok: true }]);
  });

  it('commits a real Ed25519 key that the mobile can then exchange for a token', async () => {
    const mobileId = 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2';
    const mobileKeys = await generateEd25519Keypair();
    const mobilePub = bytesToBase64(mobileKeys.publicKeyRaw);
    const { do2, code, hostWs, complete, send, request } = await setup();

    const pending = complete(code, mobileId, { ed25519PublicKey: mobilePub });
    await relayed(hostWs!);
    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: mobileId });
    expect((await pending).status).toBe(200);
    expect(do2.getDevice(mobileId)!.ed25519PublicKey).toBe(mobilePub);

    const nonce = await fetchChallenge(do2, mobileId);
    const signature = await signEd25519(
      mobileKeys.keyPair.privateKey,
      new TextEncoder().encode(mobileId + '|' + nonce)
    );
    const tokenRes = await do2.fetch(request('/token', { deviceId: mobileId, nonce, signature: bytesToBase64(signature) }));
    expect(tokenRes.status).toBe(200);
    expect(await tokenRes.json()).toEqual({ token: expect.any(String) });
  });

  it('relays the held pair_complete to every connected host socket', async () => {
    const { code, hostWs, authWs, complete, send } = await setup();
    const pairCliWs = await authWs(AGENT_1, 'host');

    const pending = complete(code);
    await relayed(hostWs!);
    await relayed(pairCliWs);

    await send(pairCliWs, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect((await pending).status).toBe(200);
  });

  it('on pair_reject answers 403, sends no reply and keeps the old pairing (no device_unpaired)', async () => {
    const { do2, code, hostWs, authWs, complete, send } = await setup();
    do2.registerDevice('mobile-old', 'ed25519-pub-key-mobile-old', 'mobile');
    do2.createPairing(AGENT_1, 'mobile-old');
    const oldWs = await authWs('mobile-old', 'mobile');

    const pending = complete(code);
    await relayed(hostWs!);
    await send(hostWs!, { type: 'pair_reject', mobileDeviceId: 'mobile-1' });

    expect((await pending).status).toBe(403);
    expect(hostWs!.messagesOfType('pair_result')).toHaveLength(0);
    expect(do2.isPaired(AGENT_1, 'mobile-old')).toBe(true);
    expect(do2.getDevice('mobile-1')).toBeNull();
    expect(oldWs.messagesOfType('device_unpaired')).toHaveLength(0);
  });

  it('answers a pair_accept after a pair_reject with ok:false and commits nothing', async () => {
    const { do2, code, hostWs, complete, send } = await setup();
    const pending = complete(code);
    await relayed(hostWs!);

    await send(hostWs!, { type: 'pair_reject', mobileDeviceId: 'mobile-1' });
    expect((await pending).status).toBe(403);
    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });

    expect(hostWs!.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-1', ok: false }]);
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(false);
    expect(do2.getDevice('mobile-1')).toBeNull();
  });

  it('evicts the old mobile only when the host accepts', async () => {
    const { do2, code, hostWs, authWs, complete, send } = await setup();
    do2.registerDevice('mobile-old', 'ed25519-pub-key-mobile-old', 'mobile');
    do2.createPairing(AGENT_1, 'mobile-old');
    const oldWs = await authWs('mobile-old', 'mobile');

    const pending = complete(code);
    await relayed(hostWs!);
    expect(oldWs.messagesOfType('device_unpaired')).toHaveLength(0);

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect((await pending).status).toBe(200);
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(true);
    expect(do2.isPaired(AGENT_1, 'mobile-old')).toBe(false);
    expect(oldWs.messagesOfType('device_unpaired')[0]).toMatchObject({ reason: 'replaced_by_new_pairing' });
  });

  it('answers 504 exactly at the timeout and a late pair_accept commits nothing', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const { do2, code, hostWs, complete, send, heldCount } = await setup();
    const pending = complete(code);
    // Not vi.waitFor: under fake timers it advances the clock on every poll.
    for (let i = 0; i < 100 && heldCount() === 0; i++) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    expect(hostWs!.messagesOfType('pair_complete')).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(29_999);
    expect(heldCount()).toBe(1);

    await vi.advanceTimersByTimeAsync(1);
    expect((await pending).status).toBe(504);
    expect(heldCount()).toBe(0);

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(false);
    expect(do2.getDevice('mobile-1')).toBeNull();
    expect(hostWs!.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-1', ok: false }]);
  });

  it('ignores a decision for the wrong mobile or from a mobile-typed socket', async () => {
    const { do2, code, hostWs, authWs, complete, send, heldCount } = await setup();
    // A socket authed with a mobile JWT carrying the host's own device ID.
    const spoofWs = await authWs(AGENT_1, 'mobile');

    const pending = complete(code);
    await relayed(hostWs!);

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-other' });
    await send(hostWs!, { type: 'pair_reject', mobileDeviceId: 'mobile-other' });
    await send(spoofWs, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    await send(spoofWs, { type: 'pair_reject', mobileDeviceId: 'mobile-1' });
    expect(hostWs!.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-other', ok: false }]);
    expect(spoofWs.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-1', ok: false }]);
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(false);
    expect(heldCount()).toBe(1);

    // Still held: the real host's accept goes through.
    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect((await pending).status).toBe(200);
  });

  it('delivers the held pair_complete once, after the auth reply, when the host connects during the hold', async () => {
    const { do2, code, authWs, complete, send, heldCount } = await setup({ liveHost: false });
    const pending = complete(code);
    // Let the request reach the hold before the host connects.
    await vi.waitFor(() => expect(heldCount()).toBe(1));
    // Confirming hosts never use the SQL deferral table
    expect(do2['sql'].exec('SELECT * FROM pending_pair_complete').toArray()).toHaveLength(0);

    const hostWs = await authWs(AGENT_1, 'host', true);
    const types = hostWs.sent.map((m) => (m as { type: string }).type);
    expect(hostWs.messagesOfType('pair_complete')).toHaveLength(1);
    expect(hostWs.messagesOfType('pair_complete')[0]).toMatchObject({ mobileDeviceId: 'mobile-1', pairMac: 'bWFj' });
    expect(types.indexOf('auth')).toBeGreaterThanOrEqual(0);
    expect(types.indexOf('auth')).toBeLessThan(types.indexOf('pair_complete'));

    await send(hostWs, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect((await pending).status).toBe(200);
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(true);
  });

  it('a new /pair/initiate supersedes the held request with 409', async () => {
    const { do2, code, hostWs, initiate, authWs, complete, send, heldCount } = await setup();
    const first = complete(code, 'mobile-1');
    await relayed(hostWs!);

    const code2 = await initiate();
    expect((await first).status).toBe(409);
    expect(heldCount()).toBe(0);

    // A host socket authed now gets nothing from the superseded attempt.
    const freshWs = await authWs(AGENT_1, 'host', true);
    expect(freshWs.messagesOfType('pair_complete')).toHaveLength(0);

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect(hostWs!.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-1', ok: false }]);

    const second = complete(code2, 'mobile-2');
    await relayed(hostWs!, 2);
    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-2' });
    expect((await second).status).toBe(200);
    expect(do2.isPaired(AGENT_1, 'mobile-2')).toBe(true);
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(false);
    expect(do2.getDevice('mobile-1')).toBeNull();
  });

  it.each([
    {
      conflict: 'device-type',
      introduce: (do2: Awaited<ReturnType<typeof setup>>['do2']) => {
        do2.registerDevice('mobile-1', 'ed25519-pub-key-mobile-1', 'host');
      },
    },
    {
      conflict: 'Ed25519 key',
      introduce: (do2: Awaited<ReturnType<typeof setup>>['do2']) => {
        do2.registerDevice('mobile-squatter', 'ed25519-pub-key-mobile-1', 'mobile');
      },
    },
  ])('a $conflict conflict at accept answers 409 and keeps the old pairing', async ({ introduce }) => {
    const { do2, code, hostWs, authWs, complete, send, heldCount } = await setup();
    do2.registerDevice('mobile-old', 'ed25519-pub-key-mobile-old', 'mobile');
    do2.createPairing(AGENT_1, 'mobile-old');
    const oldWs = await authWs('mobile-old', 'mobile');

    const pending = complete(code);
    await relayed(hostWs!);
    introduce(do2);

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect((await pending).status).toBe(409);
    expect(hostWs!.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-1', ok: false }]);
    expect(heldCount()).toBe(0);
    expect(do2.isPaired(AGENT_1, 'mobile-old')).toBe(true);
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(false);
    expect(oldWs.messagesOfType('device_unpaired')).toHaveLength(0);
  });

  it('answers 500 and pair_result ok:false when the commit throws', async () => {
    const { do2, code, hostWs, complete, send, heldCount } = await setup();
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const pending = complete(code);
    await relayed(hostWs!);
    vi.spyOn(do2, 'createPairing').mockImplementation(() => {
      throw new Error('storage failure');
    });

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    const res = await pending;
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: 'Pairing failed' });
    expect(hostWs!.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-1', ok: false }]);
    expect(heldCount()).toBe(0);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('[pair]'), expect.any(Error));
  });

  it('rolls back a failed commit: the old pairing survives and the old mobile is not told', async () => {
    const { do2, code, hostWs, authWs, complete, send, heldCount } = await setup();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    do2.registerDevice('mobile-old', 'ed25519-pub-key-mobile-old', 'mobile');
    do2.createPairing(AGENT_1, 'mobile-old');
    const oldWs = await authWs('mobile-old', 'mobile');

    const pending = complete(code);
    await relayed(hostWs!);
    // Fails after the old pairing was removed and the new mobile registered.
    vi.spyOn(do2, 'createPairing').mockImplementation(() => {
      throw new Error('storage failure');
    });

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect((await pending).status).toBe(500);
    expect(hostWs!.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-1', ok: false }]);
    expect(heldCount()).toBe(0);
    expect(do2.isPaired(AGENT_1, 'mobile-old')).toBe(true);
    expect(do2.getDevice('mobile-old')).not.toBeNull();
    expect(do2.getDevice('mobile-1')).toBeNull();
    expect(oldWs.messagesOfType('device_unpaired')).toHaveLength(0);
  });

  it('a second /pair/complete for the host supersedes the held one with 409', async () => {
    const { do2, code, hostWs, complete, send, heldCount } = await setup();
    const first = complete(code, 'mobile-1');
    await relayed(hostWs!);

    // Codes are single-use, so plant a second session for the same host directly.
    do2['sql'].exec(
      'INSERT INTO pairing_sessions (code, host_device_id, host_x25519_public_key, host_ed_public_key, expires_at, pair_confirm) VALUES (?, ?, ?, ?, ?, 1)',
      'ZZZZZZ', AGENT_1, 'x25519-pub-key-agent', 'unused', Date.now() + 60_000
    );
    const second = complete('ZZZZZZ', 'mobile-2');
    const res = await first;
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: 'Pairing superseded by a newer request' });
    await relayed(hostWs!, 2);
    expect(heldCount()).toBe(1);

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-2' });
    expect((await second).status).toBe(200);
    expect(do2.isPaired(AGENT_1, 'mobile-2')).toBe(true);
  });

  it.each([
    { path: '/device', action: 'uninstall' },
    { path: '/pairing', action: 'unpair' },
  ])('host $action during the hold answers 409 and a late pair_accept commits nothing', async ({ path }) => {
    const { do2, code, hostWs, complete, send, heldCount } = await setup();
    const pending = complete(code);
    await relayed(hostWs!);

    const del = await do2.fetch(new Request(`http://localhost${path}`, {
      method: 'DELETE',
      headers: { 'X-Device-Id': AGENT_1 },
    }));
    expect(del.status).toBe(200);

    const res = await pending;
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: 'Pairing cancelled by the host' });
    expect(heldCount()).toBe(0);

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect(hostWs!.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-1', ok: false }]);
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(false);
    expect(do2.getDevice('mobile-1')).toBeNull();
  });

  it.each([
    { field: 'deviceId', value: 'd'.repeat(65) },
    { field: 'ed25519PublicKey', value: 'k'.repeat(129) },
    { field: 'x25519PublicKey', value: 'x'.repeat(129) },
  ])('rejects an oversized $field with 400 without consuming the code', async ({ field, value }) => {
    const { code, hostWs, complete, send, request, do2 } = await setup();
    const body: Record<string, string> = {
      pairingCode: code,
      deviceId: 'mobile-1',
      ed25519PublicKey: 'ed25519-pub-key-mobile-1',
      x25519PublicKey: 'x25519-pub-key-mobile-1',
      [field]: value,
    };
    expect((await do2.fetch(request('/pair/complete', body))).status).toBe(400);

    const pending = complete(code);
    await relayed(hostWs!);
    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect((await pending).status).toBe(200);
  });

  it.each([
    { conflict: 'device-type', deviceId: 'mobile-1', key: 'ed25519-pub-key-mobile-1', type: 'host' as const },
    { conflict: 'Ed25519 key', deviceId: 'mobile-squatter', key: 'ed25519-pub-key-mobile-1', type: 'mobile' as const },
  ])('rejects a $conflict conflict with 409 before evicting the old mobile', async ({ deviceId, key, type }) => {
    const { do2, code, complete } = await setup({ pairConfirm: false, liveHost: false });
    do2.registerDevice('mobile-old', 'ed25519-pub-key-mobile-old', 'mobile');
    do2.createPairing(AGENT_1, 'mobile-old');
    do2.registerDevice(deviceId, key, type);

    expect((await complete(code)).status).toBe(409);
    expect(do2.isPaired(AGENT_1, 'mobile-old')).toBe(true);
  });
});
