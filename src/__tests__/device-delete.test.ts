import { describe, it, expect } from 'vitest';
import { createTestDO as createTestDOFull } from './helpers/mock-do';
import { MockWebSocket } from './helpers/mock-websocket';
import { createJWT } from '../auth';
import { generateEd25519Keypair, bytesToBase64, signedPairInitiateBodyWithChallenge, fetchChallenge, signEd25519, HOST_X25519_KEY } from './helpers/crypto';
import type { SignalingDO } from '../signaling';

const JWT_SECRET = 'test-jwt-secret-at-least-32-chars-long';

// Valid 32-hex device IDs (format: hex(SHA-256(publicKey)[0:16]))
const HOST_1 = 'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1';

/** Helper: POST JSON to a DO instance. */
async function postJSON(
  doInstance: SignalingDO,
  path: string,
  body: unknown
): Promise<{ status: number; data: Record<string, unknown> }> {
  const request = new Request(`http://localhost${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const response = await doInstance.fetch(request);
  const data = (await response.json()) as Record<string, unknown>;
  return { status: response.status, data };
}

/** Helper: send DELETE /device with X-Device-Id header. */
async function deleteDevice(
  doInstance: SignalingDO,
  deviceId: string,
  deviceType = 'host'
): Promise<{ status: number; data: Record<string, unknown> }> {
  const req = new Request('http://localhost/device', {
    method: 'DELETE',
    headers: { 'X-Device-Id': deviceId, 'X-Device-Type': deviceType },
  });
  const res = await doInstance.fetch(req);
  const data = (await res.json()) as Record<string, unknown>;
  return { status: res.status, data };
}

/** Helper: register a host and a mobile, complete pairing, return both keypairs. */
async function setupPairedDevices(doInstance: SignalingDO, hostName?: string) {
  const hostKeys = await generateEd25519Keypair();
  const hostPubBase64 = bytesToBase64(hostKeys.publicKeyRaw);

  const initBody = await signedPairInitiateBodyWithChallenge(
    doInstance,
    HOST_1,
    hostKeys.keyPair,
    hostPubBase64,
    HOST_X25519_KEY,
    hostName
  );
  const initResult = await postJSON(doInstance, '/pair/initiate', initBody);
  const pairingCode = initResult.data['pairingCode'] as string;

  await postJSON(doInstance, '/pair/complete', {
    pairingCode,
    deviceId: 'mobile-1',
    ed25519PublicKey: 'ed25519-pub-key-mobile',
    x25519PublicKey: 'x25519-pub-key-mobile',
  });

  return { hostKeys, hostPubBase64 };
}

describe('DELETE /device', () => {
  it('deletes device and pairing, returns { removed: true }', async () => {
    const { doInstance } = await createTestDOFull();
    await setupPairedDevices(doInstance, 'my-workstation');

    // Verify pairing exists before deletion
    expect(doInstance.isPaired(HOST_1, 'mobile-1')).toBe(true);
    expect(doInstance.getDevice(HOST_1)).not.toBeNull();

    const { status, data } = await deleteDevice(doInstance, HOST_1);

    expect(status).toBe(200);
    expect(data['removed']).toBe(true);

    // Pairing should be gone
    expect(doInstance.isPaired(HOST_1, 'mobile-1')).toBe(false);

    // Host device should be gone
    expect(doInstance.getDevice(HOST_1)).toBeNull();
  });

  it('returns { removed: false } for non-existent device', async () => {
    const { doInstance } = await createTestDOFull();

    const { status, data } = await deleteDevice(doInstance, 'no-such-device');

    expect(status).toBe(200);
    expect(data['removed']).toBe(false);
  });

  it('returns { removed: true } for device with no pairing', async () => {
    const { doInstance } = await createTestDOFull();

    // Register host but don't complete pairing
    const hostKeys = await generateEd25519Keypair();
    const hostPubBase64 = bytesToBase64(hostKeys.publicKeyRaw);
    const initBody = await signedPairInitiateBodyWithChallenge(
      doInstance,
      HOST_1,
      hostKeys.keyPair,
      hostPubBase64,
      HOST_X25519_KEY
    );
    await postJSON(doInstance, '/pair/initiate', initBody);
    expect(doInstance.getDevice(HOST_1)).not.toBeNull();

    const { status, data } = await deleteDevice(doInstance, HOST_1);

    expect(status).toBe(200);
    expect(data['removed']).toBe(true);
    expect(doInstance.getDevice(HOST_1)).toBeNull();
  });

  it('notifies paired mobile with device_unpaired reason host_uninstalled', async () => {
    const { doInstance, mockState } = await createTestDOFull();
    await setupPairedDevices(doInstance, 'my-workstation');

    // Connect mobile via WebSocket
    const mobileToken = await createJWT('mobile-1', 'mobile', JWT_SECRET);
    const mobileWs = new MockWebSocket();
    mockState.acceptedWebSockets.push(mobileWs as unknown as WebSocket);
    await doInstance.webSocketMessage(
      mobileWs as unknown as WebSocket,
      JSON.stringify({ type: 'auth', token: mobileToken })
    );
    mobileWs.sent.length = 0;

    await deleteDevice(doInstance, HOST_1);

    const unpairedMsgs = mobileWs.messagesOfType('device_unpaired');
    expect(unpairedMsgs).toHaveLength(1);
    expect(unpairedMsgs[0]!['reason']).toBe('host_uninstalled');
    expect(unpairedMsgs[0]!['hostDeviceId']).toBe(HOST_1);
    expect(unpairedMsgs[0]!['hostName']).toBe('my-workstation');
  });

  it('cleans up orphaned mobile device after deletion', async () => {
    const { doInstance } = await createTestDOFull();
    await setupPairedDevices(doInstance);

    // Mobile device should exist before deletion
    expect(doInstance.getDevice('mobile-1')).not.toBeNull();

    await deleteDevice(doInstance, HOST_1);

    // Mobile device should be removed (orphaned — no remaining pairings)
    expect(doInstance.getDevice('mobile-1')).toBeNull();
  });

  it('host device is gone after deletion — token exchange fails', async () => {
    const { doInstance } = await createTestDOFull();
    const { hostKeys, hostPubBase64 } = await setupPairedDevices(doInstance);

    await deleteDevice(doInstance, HOST_1);

    // Try to exchange a token for the deleted host — should fail
    // Nonce fetch succeeds (device need not exist for challenge), but /token rejects unknown device
    const nonce = await fetchChallenge(doInstance, HOST_1);
    const message = new TextEncoder().encode(HOST_1 + '|' + nonce);
    const sig = await signEd25519(hostKeys.keyPair.privateKey, message);
    const sigBase64 = bytesToBase64(sig);

    const { status, data } = await postJSON(doInstance, '/token', {
      deviceId: HOST_1,
      nonce,
      signature: sigBase64,
    });

    expect(status).toBe(401);
    expect(data['error']).toContain('Unknown device');
  });

  it('returns 400 when X-Device-Id header is missing', async () => {
    const { doInstance } = await createTestDOFull();

    const req = new Request('http://localhost/device', {
      method: 'DELETE',
    });
    const res = await doInstance.fetch(req);
    const data = (await res.json()) as Record<string, unknown>;

    expect(res.status).toBe(400);
    expect(data['error']).toContain('Missing device ID');
  });

  it('returns 403 for a mobile caller and leaves all rows intact', async () => {
    const { doInstance } = await createTestDOFull();
    await setupPairedDevices(doInstance);

    const dev = await deleteDevice(doInstance, 'mobile-1', 'mobile');
    expect(dev.status).toBe(403);
    expect(dev.data['error']).toBe('Only a host can remove a device');

    const pairingReq = new Request('http://localhost/pairing', {
      method: 'DELETE',
      headers: { 'X-Device-Id': HOST_1, 'X-Device-Type': 'mobile' },
    });
    const pairingRes = await doInstance.fetch(pairingReq);
    const pairingData = (await pairingRes.json()) as Record<string, unknown>;
    expect(pairingRes.status).toBe(403);
    expect(pairingData['error']).toBe('Only a host can remove a pairing');

    const noTypeReq = new Request('http://localhost/device', {
      method: 'DELETE',
      headers: { 'X-Device-Id': HOST_1 },
    });
    expect((await doInstance.fetch(noTypeReq)).status).toBe(403);

    expect(doInstance.getDevice('mobile-1')).not.toBeNull();
    expect(doInstance.getDevice(HOST_1)).not.toBeNull();
    expect(doInstance.isPaired(HOST_1, 'mobile-1')).toBe(true);
  });

  it('rejects non-DELETE methods with 405', async () => {
    const { doInstance } = await createTestDOFull();

    const req = new Request('http://localhost/device', {
      method: 'GET',
    });
    const res = await doInstance.fetch(req);

    expect(res.status).toBe(405);
    expect(res.headers.get('Allow')).toBe('DELETE');
  });

  describe('closes the sockets of removed device rows', () => {
    const HOST_2 = 'c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2';

    async function authWs(
      doInstance: SignalingDO,
      mockState: { acceptedWebSockets: WebSocket[] },
      deviceId: string,
      deviceType: 'host' | 'mobile'
    ): Promise<MockWebSocket> {
      const ws = new MockWebSocket();
      mockState.acceptedWebSockets.push(ws as unknown as WebSocket);
      const token = await createJWT(deviceId, deviceType, JWT_SECRET);
      await doInstance.webSocketMessage(ws as unknown as WebSocket, JSON.stringify({ type: 'auth', token }));
      // A host's first auth also flushes the deferred pair_complete
      expect(ws.messagesOfType('auth')).toEqual([{ type: 'auth', status: 'ok' }]);
      ws.sent.length = 0;
      return ws;
    }

    it("closes every host socket with 4004 and leaves the host unroutable", async () => {
      const { doInstance, mockState } = await createTestDOFull();
      await setupPairedDevices(doInstance);
      const agentWs = await authWs(doInstance, mockState, HOST_1, 'host');
      const cliWs = await authWs(doInstance, mockState, HOST_1, 'host');
      expect(doInstance.getWsConnectionCount(HOST_1)).toBe(2);
      doInstance['sql'].exec(
        'INSERT INTO signaling_sessions (host_device_id, mobile_device_id, expires_at) VALUES (?, ?, ?)',
        HOST_1, 'mobile-1', Date.now() + 10_000
      );

      await deleteDevice(doInstance, HOST_1);

      for (const ws of [agentWs, cliWs]) {
        expect(ws.closeCode).toBe(4004);
        expect(ws.closeReason).toBe('Device removed');
        expect(ws.deserializeAttachment()).toMatchObject({ closed: true });
      }
      expect(doInstance.getWsConnectionCount(HOST_1)).toBe(0);
      expect(doInstance.getConnection(HOST_1)).toBeUndefined();
      expect(doInstance['sql'].exec('SELECT 1 FROM signaling_sessions WHERE host_device_id = ?', HOST_1).toArray()).toHaveLength(0);
    });

    it('a later webSocketClose cleans up nothing twice and sends no host_offline', async () => {
      const { doInstance, mockState } = await createTestDOFull();
      await setupPairedDevices(doInstance);
      // mobile-1 also pairs with HOST_2, so it survives and stays connected
      doInstance.registerDevice(HOST_2, 'pubkey-host-2', 'host');
      doInstance.createPairing(HOST_2, 'mobile-1');
      const hostWs = await authWs(doInstance, mockState, HOST_1, 'host');
      const mobileWs = await authWs(doInstance, mockState, 'mobile-1', 'mobile');

      await deleteDevice(doInstance, HOST_1);
      expect(hostWs.closeCode).toBe(4004);

      // The host pairs again before the runtime reports the old close
      doInstance.registerDevice(HOST_1, 'pubkey-host-1', 'host');
      doInstance.createPairing(HOST_1, 'mobile-1');
      const freshWs = await authWs(doInstance, mockState, HOST_1, 'host');
      expect(doInstance.getWsConnectionCount(HOST_1)).toBe(1);
      mobileWs.sent.length = 0;

      await doInstance.webSocketClose(hostWs as unknown as WebSocket, 4004, 'Device removed', true);

      expect(doInstance.getWsConnectionCount(HOST_1)).toBe(1);
      expect(doInstance.getConnection(HOST_1)).toBe(freshWs);
      expect(mobileWs.messagesOfType('host_offline')).toHaveLength(0);
    });

    it('sends device_unpaired to the orphaned mobile, then closes its sockets', async () => {
      const { doInstance, mockState } = await createTestDOFull();
      await setupPairedDevices(doInstance);
      const presenceWs = await authWs(doInstance, mockState, 'mobile-1', 'mobile');
      const signalingWs = await authWs(doInstance, mockState, 'mobile-1', 'mobile');

      await deleteDevice(doInstance, HOST_1);

      // notifyDevice skips closed sockets, so delivery proves it went first
      for (const ws of [presenceWs, signalingWs]) {
        expect(ws.messagesOfType('device_unpaired')).toHaveLength(1);
        expect(ws.closeCode).toBe(4004);
      }
      expect(doInstance.getWsConnectionCount('mobile-1')).toBe(0);
      expect(doInstance.getConnection('mobile-1')).toBeUndefined();
    });

    it('keeps the sockets of a mobile still paired with another host', async () => {
      const { doInstance, mockState } = await createTestDOFull();
      await setupPairedDevices(doInstance);
      doInstance.registerDevice(HOST_2, 'pubkey-host-2', 'host');
      doInstance.createPairing(HOST_2, 'mobile-1');
      const mobileWs = await authWs(doInstance, mockState, 'mobile-1', 'mobile');

      await deleteDevice(doInstance, HOST_1);

      expect(mobileWs.messagesOfType('device_unpaired')).toHaveLength(1);
      expect(mobileWs.closed).toBe(false);
      expect(doInstance.getWsConnectionCount('mobile-1')).toBe(1);
    });

    it('DELETE /pairing closes the orphaned mobile and keeps the host connected', async () => {
      const { doInstance, mockState } = await createTestDOFull();
      await setupPairedDevices(doInstance);
      const hostWs = await authWs(doInstance, mockState, HOST_1, 'host');
      const mobileWs = await authWs(doInstance, mockState, 'mobile-1', 'mobile');

      const res = await doInstance.fetch(new Request('http://localhost/pairing', {
        method: 'DELETE',
        headers: { 'X-Device-Id': HOST_1, 'X-Device-Type': 'host' },
      }));
      expect(res.status).toBe(200);

      expect(mobileWs.messagesOfType('device_unpaired')).toHaveLength(1);
      expect(mobileWs.closeCode).toBe(4004);
      expect(doInstance.getWsConnectionCount('mobile-1')).toBe(0);
      expect(hostWs.closed).toBe(false);
      expect(doInstance.getWsConnectionCount(HOST_1)).toBe(1);
      expect(doInstance.getConnection(HOST_1)).toBe(hostWs);
    });

    it('DELETE /pairing keeps the sockets of a mobile still paired with another host', async () => {
      const { doInstance, mockState } = await createTestDOFull();
      await setupPairedDevices(doInstance);
      doInstance.registerDevice(HOST_2, 'pubkey-host-2', 'host');
      doInstance.createPairing(HOST_2, 'mobile-1');
      const mobileWs = await authWs(doInstance, mockState, 'mobile-1', 'mobile');

      await doInstance.fetch(new Request('http://localhost/pairing', {
        method: 'DELETE',
        headers: { 'X-Device-Id': HOST_1, 'X-Device-Type': 'host' },
      }));

      expect(mobileWs.messagesOfType('device_unpaired')).toHaveLength(1);
      expect(mobileWs.closed).toBe(false);
    });
  });

  it('rate limits after 10 requests', async () => {
    const { doInstance } = await createTestDOFull();

    // All requests use the same device ID so they share the same rate limit counter
    for (let i = 0; i < 10; i++) {
      const { status } = await deleteDevice(doInstance, 'same-device');
      expect(status).toBe(200);
    }

    // 11th should be rate limited
    const { status } = await deleteDevice(doInstance, 'same-device');
    expect(status).toBe(429);
  });
});
