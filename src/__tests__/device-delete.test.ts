import { describe, it, expect } from 'vitest';
import { createTestDO as createTestDOFull } from './helpers/mock-do';
import { MockWebSocket } from './helpers/mock-websocket';
import { createJWT } from '../auth';
import { generateEd25519Keypair, bytesToBase64, signedPairInitiateBodyWithChallenge, fetchChallenge, signEd25519 } from './helpers/crypto';
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
  deviceId: string
): Promise<{ status: number; data: Record<string, unknown> }> {
  const req = new Request('http://localhost/device', {
    method: 'DELETE',
    headers: { 'X-Device-Id': deviceId },
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
    'x25519-pub-key-host',
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
      'x25519-pub-key-host'
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

  it('rejects non-DELETE methods with 405', async () => {
    const { doInstance } = await createTestDOFull();

    const req = new Request('http://localhost/device', {
      method: 'GET',
    });
    const res = await doInstance.fetch(req);

    expect(res.status).toBe(405);
    expect(res.headers.get('Allow')).toBe('DELETE');
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
