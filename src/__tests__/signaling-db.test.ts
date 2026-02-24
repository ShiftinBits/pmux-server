import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDO } from './helpers/mock-do';
import type { SignalingDO } from '../signaling';

let doInstance: SignalingDO;

beforeEach(async () => {
  doInstance = await createTestDO();
});

describe('device registration', () => {
  it('registers an agent device and creates a new user', () => {
    const result = doInstance.registerDevice(
      'agent-device-1',
      'ed25519-public-key-agent',
      'agent'
    );

    expect(result.deviceId).toBe('agent-device-1');
    expect(result.userId).toBeTruthy();
    expect(typeof result.userId).toBe('string');
  });

  it('registers a mobile device linked to an existing user', () => {
    // First: register agent (creates user)
    const agentResult = doInstance.registerDevice(
      'agent-device-1',
      'ed25519-public-key-agent',
      'agent'
    );

    // Second: register mobile under the same user
    const mobileResult = doInstance.registerDevice(
      'mobile-device-1',
      'ed25519-public-key-mobile',
      'mobile',
      agentResult.userId
    );

    expect(mobileResult.userId).toBe(agentResult.userId);
    expect(mobileResult.deviceId).toBe('mobile-device-1');
  });
});

describe('getDevice', () => {
  it('returns a registered device', () => {
    doInstance.registerDevice('device-1', 'pub-key-1', 'agent');

    const device = doInstance.getDevice('device-1');
    expect(device).not.toBeNull();
    expect(device!.id).toBe('device-1');
    expect(device!.publicKey).toBe('pub-key-1');
    expect(device!.deviceType).toBe('agent');
    expect(device!.createdAt).toBeTypeOf('number');
  });

  it('returns null for non-existent device', () => {
    const device = doInstance.getDevice('nonexistent');
    expect(device).toBeNull();
  });
});

describe('getDevicesByUser', () => {
  it('returns all devices for a user', () => {
    const agentResult = doInstance.registerDevice(
      'agent-1',
      'pub-key-agent',
      'agent'
    );
    doInstance.registerDevice(
      'mobile-1',
      'pub-key-mobile',
      'mobile',
      agentResult.userId
    );

    const devices = doInstance.getDevicesByUser(agentResult.userId);
    expect(devices).toHaveLength(2);

    const types = devices.map(d => d.deviceType).sort();
    expect(types).toEqual(['agent', 'mobile']);

    const ids = devices.map(d => d.id).sort();
    expect(ids).toEqual(['agent-1', 'mobile-1']);
  });

  it('returns empty array for non-existent user', () => {
    const devices = doInstance.getDevicesByUser('nonexistent');
    expect(devices).toHaveLength(0);
  });
});

describe('removeDevice', () => {
  it('removes a device and returns true', () => {
    doInstance.registerDevice('device-1', 'pub-key', 'agent');

    const removed = doInstance.removeDevice('device-1');
    expect(removed).toBe(true);

    const device = doInstance.getDevice('device-1');
    expect(device).toBeNull();
  });

  it('returns false for non-existent device', () => {
    const removed = doInstance.removeDevice('nonexistent');
    expect(removed).toBe(false);
  });

  it('does not remove the user when removing a device', () => {
    const result = doInstance.registerDevice('device-1', 'pub-key-1', 'agent');
    doInstance.registerDevice('device-2', 'pub-key-2', 'mobile', result.userId);

    doInstance.removeDevice('device-1');

    // The other device should still exist under the same user
    const remaining = doInstance.getDevicesByUser(result.userId);
    expect(remaining).toHaveLength(1);
    expect(remaining[0]!.id).toBe('device-2');
  });
});

describe('pairing session management', () => {
  it('creates a pairing session with a 6-char code', () => {
    const code = doInstance.createPairingSession(
      'agent-1',
      'x25519-pub-key',
      'ed25519-pub-key'
    );

    expect(code).toHaveLength(6);
    expect(code).toMatch(/^[A-Z2-9]+$/);
  });

  it('consumes a pairing session (single-use)', () => {
    const code = doInstance.createPairingSession(
      'agent-1',
      'x25519-pub-key',
      'ed25519-pub-key'
    );

    const session = doInstance.consumePairingSession(code);
    expect(session).not.toBeNull();
    expect(session!.agentDeviceId).toBe('agent-1');
    expect(session!.agentX25519PublicKey).toBe('x25519-pub-key');
    expect(session!.agentEdPublicKey).toBe('ed25519-pub-key');

    // Second consume should return null (single-use)
    const again = doInstance.consumePairingSession(code);
    expect(again).toBeNull();
  });

  it('returns null for invalid code', () => {
    const session = doInstance.consumePairingSession('BADCODE');
    expect(session).toBeNull();
  });

  it('rejects expired pairing code', async () => {
    // Create session, then advance time past expiry
    const realDateNow = Date.now;
    const code = doInstance.createPairingSession(
      'agent-1',
      'x25519-pub-key',
      'ed25519-pub-key'
    );

    // Advance time by 6 minutes (past the 5-minute expiry)
    const future = realDateNow() + 6 * 60 * 1000;
    Date.now = () => future;

    try {
      const session = doInstance.consumePairingSession(code);
      expect(session).toBeNull();
    } finally {
      Date.now = realDateNow;
    }
  });
});
