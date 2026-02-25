import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDOCompat as createTestDO } from './helpers/mock-do';
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
    expect(device!.deviceType).toBe('agent');
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
    expect(data['agentX25519PublicKey']).toBe('x25519-pub-key-agent');
    expect(data['agentDeviceId']).toBe('agent-1');
    expect(data['userId']).toBeTypeOf('string');
  });

  it('links both devices under the same user', async () => {
    // Initiate
    const initResult = await postJSON('/pair/initiate', {
      deviceId: 'agent-1',
      publicKey: 'ed25519-pub-key-agent',
      x25519PublicKey: 'x25519-pub-key-agent',
    });

    // Complete
    const completeResult = await postJSON('/pair/complete', {
      pairingCode: initResult.data['pairingCode'],
      deviceId: 'mobile-1',
      publicKey: 'ed25519-pub-key-mobile',
      x25519PublicKey: 'x25519-pub-key-mobile',
    });

    const userId = completeResult.data['userId'] as string;
    const devices = doInstance.getDevicesByUser(userId);

    expect(devices).toHaveLength(2);
    const types = devices.map(d => d.deviceType).sort();
    expect(types).toEqual(['agent', 'mobile']);
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
});
