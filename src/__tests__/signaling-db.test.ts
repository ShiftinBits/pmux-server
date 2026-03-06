import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDOCompat as createTestDO } from './helpers/mock-do';
import type { SignalingDO } from '../signaling';
import { DeviceTypeConflictError } from '../signaling';

let doInstance: SignalingDO;

beforeEach(async () => {
  doInstance = await createTestDO();
});

describe('device registration', () => {
  it('registers a host device and returns deviceId', () => {
    const result = doInstance.registerDevice(
      'agent-device-1',
      'ed25519-public-key-agent',
      'host'
    );

    expect(result.deviceId).toBe('agent-device-1');
  });

  it('registers a mobile device', () => {
    const result = doInstance.registerDevice(
      'mobile-device-1',
      'ed25519-public-key-mobile',
      'mobile'
    );

    expect(result.deviceId).toBe('mobile-device-1');
  });

  it('registers a device with an optional name', () => {
    doInstance.registerDevice(
      'agent-1',
      'pub-key-agent',
      'host',
      'My Workstation'
    );

    const device = doInstance.getDevice('agent-1');
    expect(device).not.toBeNull();
    expect(device!.name).toBe('My Workstation');
  });

  it('re-registering a device with the same type updates allowed fields', () => {
    doInstance.registerDevice('device-1', 'pub-key-v1', 'host', 'Old Name');
    doInstance.registerDevice('device-1', 'pub-key-v2', 'host', 'New Name');

    const device = doInstance.getDevice('device-1');
    expect(device).not.toBeNull();
    expect(device!.ed25519PublicKey).toBe('pub-key-v2');
    expect(device!.name).toBe('New Name');
  });

  it('throws DeviceTypeConflictError when re-registering with a different device_type', () => {
    doInstance.registerDevice('device-1', 'pub-key-1', 'host', 'My Host');

    expect(() => {
      doInstance.registerDevice('device-1', 'pub-key-2', 'mobile', 'My Mobile');
    }).toThrow(DeviceTypeConflictError);
  });

  it('preserves the original record after a device_type conflict', () => {
    doInstance.registerDevice('device-1', 'pub-key-1', 'host', 'My Host');

    try {
      doInstance.registerDevice('device-1', 'pub-key-2', 'mobile', 'My Mobile');
    } catch {
      // expected
    }

    const device = doInstance.getDevice('device-1');
    expect(device).not.toBeNull();
    expect(device!.deviceType).toBe('host');
    expect(device!.ed25519PublicKey).toBe('pub-key-1');
    expect(device!.name).toBe('My Host');
  });

  it('throws DeviceTypeConflictError when mobile re-registers as host', () => {
    doInstance.registerDevice('device-1', 'pub-key-1', 'mobile');

    expect(() => {
      doInstance.registerDevice('device-1', 'pub-key-2', 'host');
    }).toThrow(DeviceTypeConflictError);
  });
});

describe('getDevice', () => {
  it('returns a registered device', () => {
    doInstance.registerDevice('device-1', 'pub-key-1', 'host');

    const device = doInstance.getDevice('device-1');
    expect(device).not.toBeNull();
    expect(device!.id).toBe('device-1');
    expect(device!.ed25519PublicKey).toBe('pub-key-1');
    expect(device!.deviceType).toBe('host');
    expect(device!.createdAt).toBeTypeOf('number');
  });

  it('returns null for non-existent device', () => {
    const device = doInstance.getDevice('nonexistent');
    expect(device).toBeNull();
  });

  it('does not include userId in the returned device', () => {
    doInstance.registerDevice('device-1', 'pub-key-1', 'host');

    const device = doInstance.getDevice('device-1');
    expect(device).not.toBeNull();
    expect(device).not.toHaveProperty('userId');
  });
});

describe('removeDevice', () => {
  it('removes a device and returns true', () => {
    doInstance.registerDevice('device-1', 'pub-key', 'host');

    const removed = doInstance.removeDevice('device-1');
    expect(removed).toBe(true);

    const device = doInstance.getDevice('device-1');
    expect(device).toBeNull();
  });

  it('returns false for non-existent device', () => {
    const removed = doInstance.removeDevice('nonexistent');
    expect(removed).toBe(false);
  });
});

describe('createPairing', () => {
  it('creates a pairing between a host and a mobile device', () => {
    doInstance.registerDevice('host-1', 'pub-key-host', 'host');
    doInstance.registerDevice('mobile-1', 'pub-key-mobile', 'mobile');

    doInstance.createPairing('host-1', 'mobile-1');

    const mobileId = doInstance.getPairedMobile('host-1');
    expect(mobileId).toBe('mobile-1');
  });

  it('replaces existing pairing for the same host (PRIMARY KEY constraint)', () => {
    doInstance.registerDevice('host-1', 'pub-key-host', 'host');
    doInstance.registerDevice('mobile-1', 'pub-key-mobile-1', 'mobile');
    doInstance.registerDevice('mobile-2', 'pub-key-mobile-2', 'mobile');

    doInstance.createPairing('host-1', 'mobile-1');
    doInstance.createPairing('host-1', 'mobile-2');

    const mobileId = doInstance.getPairedMobile('host-1');
    expect(mobileId).toBe('mobile-2');
  });
});

describe('getPairedMobile', () => {
  it('returns the paired mobile device ID', () => {
    doInstance.registerDevice('host-1', 'pub-key-host', 'host');
    doInstance.registerDevice('mobile-1', 'pub-key-mobile', 'mobile');
    doInstance.createPairing('host-1', 'mobile-1');

    expect(doInstance.getPairedMobile('host-1')).toBe('mobile-1');
  });

  it('returns null when host has no pairing', () => {
    doInstance.registerDevice('host-1', 'pub-key-host', 'host');

    expect(doInstance.getPairedMobile('host-1')).toBeNull();
  });

  it('returns null for non-existent host', () => {
    expect(doInstance.getPairedMobile('nonexistent')).toBeNull();
  });
});

describe('isPaired', () => {
  it('returns true when pairing exists', () => {
    doInstance.registerDevice('host-1', 'pub-key-host', 'host');
    doInstance.registerDevice('mobile-1', 'pub-key-mobile', 'mobile');
    doInstance.createPairing('host-1', 'mobile-1');

    expect(doInstance.isPaired('host-1', 'mobile-1')).toBe(true);
  });

  it('returns false when no pairing exists', () => {
    doInstance.registerDevice('host-1', 'pub-key-host', 'host');
    doInstance.registerDevice('mobile-1', 'pub-key-mobile', 'mobile');

    expect(doInstance.isPaired('host-1', 'mobile-1')).toBe(false);
  });

  it('returns false when host is paired with a different mobile', () => {
    doInstance.registerDevice('host-1', 'pub-key-host', 'host');
    doInstance.registerDevice('mobile-1', 'pub-key-mobile-1', 'mobile');
    doInstance.registerDevice('mobile-2', 'pub-key-mobile-2', 'mobile');
    doInstance.createPairing('host-1', 'mobile-1');

    expect(doInstance.isPaired('host-1', 'mobile-2')).toBe(false);
  });
});

describe('removePairing', () => {
  it('removes a pairing and returns the mobile device ID', () => {
    doInstance.registerDevice('host-1', 'pub-key-host', 'host');
    doInstance.registerDevice('mobile-1', 'pub-key-mobile', 'mobile');
    doInstance.createPairing('host-1', 'mobile-1');

    const removedMobileId = doInstance.removePairing('host-1');
    expect(removedMobileId).toBe('mobile-1');
    expect(doInstance.getPairedMobile('host-1')).toBeNull();
  });

  it('returns null when no pairing exists', () => {
    expect(doInstance.removePairing('nonexistent')).toBeNull();
  });

  it('cleans up orphaned mobile device when no remaining pairings', () => {
    doInstance.registerDevice('host-1', 'pub-key-host', 'host');
    doInstance.registerDevice('mobile-1', 'pub-key-mobile', 'mobile');
    doInstance.createPairing('host-1', 'mobile-1');

    doInstance.removePairing('host-1');

    // Mobile device should be deleted since it has no remaining pairings
    const device = doInstance.getDevice('mobile-1');
    expect(device).toBeNull();
  });

  it('does not clean up mobile device when it still has other pairings', () => {
    doInstance.registerDevice('host-1', 'pub-key-host-1', 'host');
    doInstance.registerDevice('host-2', 'pub-key-host-2', 'host');
    doInstance.registerDevice('mobile-1', 'pub-key-mobile', 'mobile');
    doInstance.createPairing('host-1', 'mobile-1');
    doInstance.createPairing('host-2', 'mobile-1');

    doInstance.removePairing('host-1');

    // Mobile device should still exist since host-2 is still paired with it
    const device = doInstance.getDevice('mobile-1');
    expect(device).not.toBeNull();

    // host-2 pairing should still be intact
    expect(doInstance.isPaired('host-2', 'mobile-1')).toBe(true);
  });

  it('does not remove the host device when removing a pairing', () => {
    doInstance.registerDevice('host-1', 'pub-key-host', 'host');
    doInstance.registerDevice('mobile-1', 'pub-key-mobile', 'mobile');
    doInstance.createPairing('host-1', 'mobile-1');

    doInstance.removePairing('host-1');

    // Host device should still exist
    const device = doInstance.getDevice('host-1');
    expect(device).not.toBeNull();
  });
});

describe('getHostsForMobile', () => {
  it('returns all host device IDs paired with a mobile', () => {
    doInstance.registerDevice('host-1', 'pub-key-host-1', 'host');
    doInstance.registerDevice('host-2', 'pub-key-host-2', 'host');
    doInstance.registerDevice('mobile-1', 'pub-key-mobile', 'mobile');
    doInstance.createPairing('host-1', 'mobile-1');
    doInstance.createPairing('host-2', 'mobile-1');

    const hosts = doInstance.getHostsForMobile('mobile-1');
    expect(hosts).toHaveLength(2);
    expect(hosts.sort()).toEqual(['host-1', 'host-2']);
  });

  it('returns empty array when mobile has no pairings', () => {
    doInstance.registerDevice('mobile-1', 'pub-key-mobile', 'mobile');

    const hosts = doInstance.getHostsForMobile('mobile-1');
    expect(hosts).toHaveLength(0);
  });

  it('returns empty array for non-existent mobile', () => {
    const hosts = doInstance.getHostsForMobile('nonexistent');
    expect(hosts).toHaveLength(0);
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
    expect(session!.hostDeviceId).toBe('agent-1');
    expect(session!.hostX25519PublicKey).toBe('x25519-pub-key');
    expect(session!.hostEdPublicKey).toBe('ed25519-pub-key');

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
