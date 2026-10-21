import { describe, it, expect, afterEach, vi } from 'vitest';
import { createTestDO } from './helpers/mock-do';
import { MockWebSocket } from './helpers/mock-websocket';
import { createJWT } from '../auth';
import { generateEd25519Keypair, bytesToBase64, signedPairInitiateBodyWithChallenge } from './helpers/crypto';

// Host-confirmed pairing: /pair/complete is held until the host answers [SB-1348]

const AGENT_1 = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1';
const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

afterEach(() => {
  vi.useRealTimers();
});

async function setup(opts: { pairConfirm?: boolean; liveHost?: boolean } = {}) {
  const { pairConfirm = true, liveHost = true } = opts;
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

  async function initiate(): Promise<string> {
    const body = await signedPairInitiateBodyWithChallenge(do2, AGENT_1, keys.keyPair, pubBase64, 'x25519-pub-key-agent');
    const res = await do2.fetch(request('/pair/initiate', { ...body, ...(pairConfirm && { pairConfirm: true }) }));
    expect(res.status).toBe(200);
    return ((await res.json()) as { pairingCode: string }).pairingCode;
  }

  async function authWs(deviceId: string, deviceType: 'host' | 'mobile', keepSent = false): Promise<MockWebSocket> {
    const ws = new MockWebSocket();
    mockState.acceptedWebSockets.push(ws as unknown as WebSocket);
    const token = await createJWT(deviceId, deviceType, JWT_SECRET);
    await do2.webSocketMessage(ws as unknown as WebSocket, JSON.stringify({ type: 'auth', token }));
    if (!keepSent) ws.sent.length = 0;
    return ws;
  }

  function complete(code: string, deviceId = 'mobile-1'): Promise<Response> {
    return do2.fetch(request('/pair/complete', {
      pairingCode: code,
      deviceId,
      ed25519PublicKey: `ed25519-pub-key-${deviceId}`,
      x25519PublicKey: `x25519-pub-key-${deviceId}`,
      pairMac: 'bWFj',
    }));
  }

  async function send(ws: MockWebSocket, msg: unknown): Promise<void> {
    await do2.webSocketMessage(ws as unknown as WebSocket, JSON.stringify(msg));
  }

  const code = await initiate();
  const hostWs = liveHost ? await authWs(AGENT_1, 'host') : null;
  return { do2, code, hostWs, initiate, authWs, complete, send };
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

  it('holds /pair/complete without committing until pair_accept, then commits and acks the host', async () => {
    const { do2, code, hostWs, complete, send } = await setup();
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
    expect(await res.json()).toMatchObject({ hostDeviceId: AGENT_1, hostX25519PublicKey: 'x25519-pub-key-agent' });
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(true);
    expect(hostWs!.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-1', ok: true }]);
  });

  it('on pair_reject answers 403 and keeps the old pairing (no device_unpaired)', async () => {
    const { do2, code, hostWs, authWs, complete, send } = await setup();
    do2.registerDevice('mobile-old', 'ed25519-pub-key-mobile-old', 'mobile');
    do2.createPairing(AGENT_1, 'mobile-old');
    const oldWs = await authWs('mobile-old', 'mobile');

    const pending = complete(code);
    await relayed(hostWs!);
    await send(hostWs!, { type: 'pair_reject', mobileDeviceId: 'mobile-1' });

    expect((await pending).status).toBe(403);
    expect(do2.isPaired(AGENT_1, 'mobile-old')).toBe(true);
    expect(do2.getDevice('mobile-1')).toBeNull();
    expect(oldWs.messagesOfType('device_unpaired')).toHaveLength(0);
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

  it('answers 504 after the timeout and a late pair_accept commits nothing', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const { do2, code, hostWs, complete, send } = await setup();
    const pending = complete(code);
    await relayed(hostWs!);

    await vi.advanceTimersByTimeAsync(30_000);
    expect((await pending).status).toBe(504);

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(false);
    expect(hostWs!.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-1', ok: false }]);
  });

  it('ignores a decision for the wrong mobile or from a mobile socket', async () => {
    const { do2, code, hostWs, authWs, complete, send } = await setup();
    do2.registerDevice('mobile-x', 'ed25519-pub-key-mobile-x', 'mobile');
    const mobileWs = await authWs('mobile-x', 'mobile');

    const pending = complete(code);
    await relayed(hostWs!);

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-other' });
    await send(mobileWs, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect(hostWs!.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-other', ok: false }]);
    expect(mobileWs.messagesOfType('pair_result')).toEqual([{ type: 'pair_result', mobileDeviceId: 'mobile-1', ok: false }]);
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(false);

    // Still held: the real host's accept goes through.
    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect((await pending).status).toBe(200);
  });

  it('delivers the held pair_complete when the host connects during the hold', async () => {
    const { do2, code, authWs, complete, send } = await setup({ liveHost: false });
    const pending = complete(code);
    // Let the request reach the hold before the host connects.
    await vi.waitFor(() => expect(do2['pendingPairs'].size).toBe(1));

    const hostWs = await authWs(AGENT_1, 'host', true);
    expect(hostWs.messagesOfType('pair_complete')[0]).toMatchObject({ mobileDeviceId: 'mobile-1', pairMac: 'bWFj' });

    await send(hostWs, { type: 'pair_accept', mobileDeviceId: 'mobile-1' });
    expect((await pending).status).toBe(200);
    expect(do2.isPaired(AGENT_1, 'mobile-1')).toBe(true);
    // Confirming hosts never use the SQL deferral table
    expect(do2['sql'].exec('SELECT * FROM pending_pair_complete').toArray()).toHaveLength(0);
  });

  it('a newer /pair/complete for the same host supersedes the held one with 409', async () => {
    const { code, hostWs, initiate, complete, send } = await setup();
    const first = complete(code, 'mobile-1');
    await relayed(hostWs!);

    const code2 = await initiate();
    const second = complete(code2, 'mobile-2');
    expect((await first).status).toBe(409);
    await relayed(hostWs!, 2);

    await send(hostWs!, { type: 'pair_accept', mobileDeviceId: 'mobile-2' });
    expect((await second).status).toBe(200);
  });

  it('rejects a device-type conflict with 409 before evicting the old mobile', async () => {
    const { do2, code, complete } = await setup({ pairConfirm: false, liveHost: false });
    do2.registerDevice('mobile-old', 'ed25519-pub-key-mobile-old', 'mobile');
    do2.createPairing(AGENT_1, 'mobile-old');
    do2.registerDevice('mobile-1', 'ed25519-pub-key-mobile-1', 'host');

    expect((await complete(code)).status).toBe(409);
    expect(do2.isPaired(AGENT_1, 'mobile-old')).toBe(true);
  });
});
