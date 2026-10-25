/**
 * SignalingDO — Durable Object for WebSocket signaling, presence, and storage.
 *
 * Uses built-in SQLite for devices, pairings, and short-lived pairing/auth/signaling rows.
 * Uses in-memory maps for the WebSocket connection cache (rebuilt after hibernation).
 * Uses the WebSocket Hibernation API for cost-efficient persistent connections.
 * Uses DO key-value storage for the TURN credential cache.
 * Rate limiting uses native Workers Rate Limiting bindings (env.*_LIMITER).
 */

import type { Env } from './worker';
import type {
  DeviceType,
  SignalingClientMessage,
  HostOnlineMessage,
  HostOfflineMessage,
  TurnCredentials,
  PairCompleteMessage,
  PairAcceptMessage,
  PairRejectMessage,
  PairResultMessage,
} from '@pocketmux/shared';
import { verifyEd25519Signature, createJWT, verifyJWT, TokenExpiredError } from './auth';
import { generateTurnCredentials, TURN_REFRESH_AGE_MS, TURN_MAX_SERVE_AGE_MS } from './turn';
import {
  rateLimitResponse,
  MAX_WS_CONNECTIONS_PER_DEVICE,
} from './middleware/ratelimit';

/** Maximum WebSocket message length in characters (16K — generous for SDP/ICE signaling). */
const MAX_WS_MESSAGE_SIZE = 16_384;

/** DO KV storage key for the cached TURN credentials. */
const TURN_CACHE_KEY = 'turn_cache';

interface TurnCacheEntry {
  creds: TurnCredentials;
  fetchedAt: number;
}

/** Maximum attempts to find an unused pairing code before giving up. */
const MAX_PAIRING_CODE_ATTEMPTS = 10;

/** Maximum device name length in characters. */
const MAX_DEVICE_NAME_LENGTH = 64;

/** Control characters that are not allowed in device names (prevents terminal escape injection). */
const CONTROL_CHAR_RE = /[\x00-\x1f\x7f]/;

/** Thrown when a device re-registers with a different device_type than stored. */
export class DeviceTypeConflictError extends Error {
  constructor(deviceId: string, storedType: string, incomingType: string) {
    super(
      `Device ${deviceId} is registered as '${storedType}' but attempted to re-register as '${incomingType}'`
    );
    this.name = 'DeviceTypeConflictError';
  }
}

/**
 * Validate and sanitize a device name from untrusted input.
 * Returns the name if valid, undefined otherwise.
 */
function validateDeviceName(name: unknown): string | undefined {
  if (typeof name !== 'string' || name.length === 0 || name.length > MAX_DEVICE_NAME_LENGTH) {
    return undefined;
  }
  if (CONTROL_CHAR_RE.test(name)) {
    return undefined;
  }
  return name;
}

/**
 * Validate a connect attempt ID from untrusted input [SB-1375].
 * Returns the ID if it is 32 lowercase hex chars, undefined otherwise.
 */
function validateAttemptId(attemptId: unknown): string | undefined {
  return typeof attemptId === 'string' && /^[0-9a-f]{32}$/.test(attemptId) ? attemptId : undefined;
}

// --- Types ---

export interface StoredDevice {
  id: string;
  ed25519PublicKey: string;
  deviceType: DeviceType;
  name: string | null;
  createdAt: number;
}

export interface PairingSession {
  hostDeviceId: string;
  hostX25519PublicKey: string;
  hostEdPublicKey: string;
  expiresAt: number;
  /** The host confirms pair_complete (pair_accept/pair_reject) before the server commits. */
  pairConfirm: boolean;
}

/** A /pair/complete request held open until the host accepts or rejects [SB-1348]. */
interface PendingPair {
  /** Relayed to the host, and re-sent to a host socket that authenticates during the hold. */
  pairComplete: PairCompleteMessage;
  mobileEd25519PublicKey: string;
  hostX25519PublicKey: string;
  hostName: string | null;
  resolve: (response: Response) => void;
  timer: ReturnType<typeof setTimeout>;
}

export interface StoredPairing {
  hostDeviceId: string;
  mobileDeviceId: string;
  createdAt: number;
}

/** Per-WebSocket metadata, survives DO hibernation via serializeAttachment. */
export interface WsAttachment {
  deviceId: string;
  deviceType: DeviceType;
  authenticated: boolean;
  /** Epoch ms of last received message (for idle timeout). */
  lastMessageTime?: number;
  /**
   * Set when the DO closed this socket (idle sweep or error). A closing socket
   * stays in getWebSockets() until the peer acks, so this keeps it out of
   * routing, presence and counts, and its late frames are ignored [SB-1393].
   */
  closed?: boolean;
}

/** Interval (ms) between alarm-based cleanup sweeps. */
const ALARM_INTERVAL_MS = 30_000; // 30 seconds

/** Age (seconds) after which a host that never paired is purged. */
const UNPAIRED_HOST_TTL_S = 86_400; // 1 day

/**
 * Maximum idle time (ms) before a WebSocket is closed.
 *
 * A sleeping/hibernated host is frozen, not disconnected — the OS sends no
 * TCP FIN, so the only way the server learns the host is gone is this idle
 * sweep. Kept tight (3× the agent's 30s presence heartbeat + grace) so a
 * "host online" status goes stale within ~90-120s of the machine sleeping,
 * not the ~5min a laxer timeout allowed. Must stay >= 2× the presence
 * interval or a single dropped heartbeat would flap the host offline.
 * Note: 3× assumes the agent's 30s default; at its 45s keepalive clamp cap
 * this is exactly 2× (zero dropped-heartbeat margin) — don't raise that cap
 * without revisiting this window.
 */
const WS_IDLE_TIMEOUT_MS = 90_000; // 90 seconds

/**
 * How long the host has to reply to a relayed connect_request (sdp_offer or
 * connection_rejected) before both ends get peer_unavailable [SB-1001].
 * Must exceed the agent's worst-case pre-offer delay: on a cold TURN cache it
 * fetches credentials first with a 10s HTTP timeout (agent peer.go), then
 * offers. Kept below the mobile's fastest negotiation watchdog (15s) so the
 * server's signal arrives first.
 */
const SIGNALING_SESSION_TIMEOUT_MS = 12_000; // 12 seconds

/**
 * How long /pair/complete waits for a confirming host's pair_accept/pair_reject
 * before answering 504 [SB-1348]. Covers the pair CLI connecting its WebSocket
 * after the QR is shown. The mobile's fetch timeout (45s) must stay above it.
 */
const PAIR_CONFIRM_TIMEOUT_MS = 30_000; // 30 seconds

/** Upper bounds on /pair/complete identity fields (a 32-hex ID and base64 32-byte keys fit well inside). */
const MAX_PAIR_DEVICE_ID_LENGTH = 64;
const MAX_PAIR_PUBLIC_KEY_LENGTH = 128;

// --- Durable Object ---

export class SignalingDO implements DurableObject {
  private state: DurableObjectState;
  private env: Env;
  private initialized = false;

  // In-memory WebSocket cache indexed by deviceId (rebuilt after hibernation wake)
  private connections = new Map<string, WebSocket>();

  // In-memory WebSocket connection count per device ID (for abuse prevention)
  private wsConnectionCounts = new Map<string, number>();

  // Every authenticated socket per device ID, rebuilt from getWebSockets() once
  // per wake and kept current on auth/close/error/idle-close
  private deviceSockets = new Map<string, Set<WebSocket>>();

  // Set only here: a hibernation wake re-runs the constructor, so the first
  // lookup after a wake rebuilds the caches above exactly once
  private cacheRebuilt = false;

  // TURN credential cache, mirrored to DO KV storage (TURN_CACHE_KEY) so it survives
  // hibernation. Shared by all paired devices: they are time-limited
  // and relay-only.
  private turnCache: TurnCacheEntry | null = null;
  private turnFetch: Promise<TurnCredentials> | null = null;

  // Held /pair/complete requests by host device ID [SB-1348]. In-memory only:
  // the in-flight HTTP request keeps the DO from hibernating, and a DO restart
  // drops the request with nothing committed.
  private pendingPairs = new Map<string, PendingPair>();

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  private get sql(): SqlStorage {
    return this.state.storage.sql;
  }

  /**
   * Apply a native Workers Rate Limiting binding for the given key.
   * Returns a 429 Response when over the limit, or null when allowed.
   *
   * The limiter is a standard `env` binding (this.env), available inside the
   * DO just as in the Worker. `retryAfter` is the binding's full window in
   * seconds — the binding does not expose the exact reset time, so this is an
   * upper bound, not the precise remaining time the old limiter computed.
   */
  private async checkLimit(
    limiter: RateLimit,
    key: string,
    retryAfter: number
  ): Promise<Response | null> {
    const { success } = await limiter.limit({ key });
    return success ? null : rateLimitResponse(retryAfter);
  }

  // --- Schema initialization ---

  private ensureSchema(): void {
    if (this.initialized) return;

    // Migrate column name from public_key to ed25519_public_key (SB-340)
    try {
      this.sql.exec('ALTER TABLE devices RENAME COLUMN public_key TO ed25519_public_key');
    } catch {
      // Column already renamed or table doesn't exist yet — CREATE TABLE handles it
    }

    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        ed25519_public_key TEXT NOT NULL UNIQUE,
        device_type TEXT NOT NULL CHECK(device_type IN ('host', 'mobile')),
        name TEXT,
        created_at INTEGER NOT NULL
      )
    `);

    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS pairings (
        host_device_id TEXT PRIMARY KEY REFERENCES devices(id),
        mobile_device_id TEXT NOT NULL REFERENCES devices(id),
        created_at INTEGER NOT NULL
      )
    `);

    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS pairing_sessions (
        code TEXT PRIMARY KEY,
        host_device_id TEXT NOT NULL,
        host_x25519_public_key TEXT NOT NULL,
        host_ed_public_key TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      )
    `);

    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS pending_pair_complete (
        host_device_id TEXT PRIMARY KEY,
        mobile_device_id TEXT NOT NULL,
        mobile_x25519_public_key TEXT NOT NULL,
        mobile_name TEXT,
        created_at INTEGER NOT NULL,
        mobile_pair_mac TEXT
      )
    `);

    // Opaque pairing MAC relayed to the host (column added after initial release).
    // Check for the column instead of catching the ALTER's error, so the
    // migration doesn't depend on SqlStorage's error wording.
    const pendingCols = this.sql.exec('PRAGMA table_info(pending_pair_complete)').toArray();
    if (!pendingCols.some((col) => col['name'] === 'mobile_pair_mac')) {
      this.sql.exec('ALTER TABLE pending_pair_complete ADD COLUMN mobile_pair_mac TEXT');
    }

    // Host confirms pair_complete before the server commits [SB-1348]
    const sessionCols = this.sql.exec('PRAGMA table_info(pairing_sessions)').toArray();
    if (!sessionCols.some((col) => col['name'] === 'pair_confirm')) {
      this.sql.exec('ALTER TABLE pairing_sessions ADD COLUMN pair_confirm INTEGER NOT NULL DEFAULT 0');
    }

    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS challenges (
        nonce TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      )
    `);

    // Pending connect_request awaiting the host's first reply [SB-1001]
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS signaling_sessions (
        host_device_id TEXT PRIMARY KEY,
        mobile_device_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        attempt_id TEXT
      )
    `);

    // Mobile's connect attempt ID, echoed on the session's peer_unavailable [SB-1375]
    const signalingCols = this.sql.exec('PRAGMA table_info(signaling_sessions)').toArray();
    if (!signalingCols.some((col) => col['name'] === 'attempt_id')) {
      this.sql.exec('ALTER TABLE signaling_sessions ADD COLUMN attempt_id TEXT');
    }

    this.initialized = true;
  }

  // --- Device CRUD ---

  /**
   * Register a device. New devices are inserted; existing devices are updated
   * only if the device_type matches. Throws DeviceTypeConflictError on mismatch.
   */
  registerDevice(
    deviceId: string,
    ed25519PublicKey: string,
    deviceType: DeviceType,
    name?: string
  ): { deviceId: string } {
    this.ensureSchema();
    const now = Math.floor(Date.now() / 1000);

    // Try to insert — does nothing if device already exists (primary key conflict)
    this.sql.exec(
      'INSERT OR IGNORE INTO devices (id, ed25519_public_key, device_type, name, created_at) VALUES (?, ?, ?, ?, ?)',
      deviceId,
      ed25519PublicKey,
      deviceType,
      name ?? null,
      now
    );

    // Check if the device was just inserted or already existed
    const existing = this.getDevice(deviceId);
    if (!existing) {
      throw new Error(`Failed to register device ${deviceId}`);
    }

    // If the device existed before our insert, validate device_type matches
    if (existing.deviceType !== deviceType) {
      throw new DeviceTypeConflictError(deviceId, existing.deviceType, deviceType);
    }

    // Update allowed fields for existing devices (key rotation, name change)
    if (existing.ed25519PublicKey !== ed25519PublicKey || existing.name !== (name ?? null)) {
      this.sql.exec(
        'UPDATE devices SET ed25519_public_key = ?, name = ?, created_at = ? WHERE id = ?',
        ed25519PublicKey,
        name ?? null,
        now,
        deviceId
      );
    }

    return { deviceId };
  }

  // --- Pairing CRUD ---

  /**
   * Create a pairing between a host and a mobile device.
   * Uses INSERT OR REPLACE — a host can only be paired with one mobile at a time.
   */
  createPairing(hostDeviceId: string, mobileDeviceId: string): void {
    this.ensureSchema();
    const now = Math.floor(Date.now() / 1000);
    this.sql.exec(
      'INSERT OR REPLACE INTO pairings (host_device_id, mobile_device_id, created_at) VALUES (?, ?, ?)',
      hostDeviceId,
      mobileDeviceId,
      now
    );
  }

  /**
   * Get the paired mobile device ID for a host, or null if not paired.
   */
  getPairedMobile(hostDeviceId: string): string | null {
    this.ensureSchema();
    const rows = this.sql.exec(
      'SELECT * FROM pairings WHERE host_device_id = ?',
      hostDeviceId
    );
    const results = [...rows];
    if (results.length === 0) return null;
    return rowToPairing(results[0]!).mobileDeviceId;
  }

  /**
   * Check if a specific host-mobile pairing exists.
   */
  isPaired(hostDeviceId: string, mobileDeviceId: string): boolean {
    this.ensureSchema();
    const rows = this.sql.exec(
      'SELECT 1 FROM pairings WHERE host_device_id = ? AND mobile_device_id = ?',
      hostDeviceId,
      mobileDeviceId
    );
    return [...rows].length > 0;
  }

  /**
   * Remove the pairing for a host device.
   * If the mobile device has no remaining pairings, removes the orphaned mobile device.
   * Returns the removed mobile device ID, or null if no pairing existed.
   */
  removePairing(hostDeviceId: string): string | null {
    this.ensureSchema();
    // Find the mobile device ID before deleting
    const mobileId = this.getPairedMobile(hostDeviceId);
    if (!mobileId) return null;

    this.sql.exec('DELETE FROM pairings WHERE host_device_id = ?', hostDeviceId);

    // Clean up orphaned mobile device (no remaining pairings referencing it)
    const remaining = this.sql.exec(
      'SELECT 1 FROM pairings WHERE mobile_device_id = ?',
      mobileId
    );
    if ([...remaining].length === 0) {
      this.sql.exec('DELETE FROM devices WHERE id = ?', mobileId);
    }

    return mobileId;
  }

  /**
   * Remove a host device and its pairing in one operation.
   * Used when a host uninstalls pmux — cleans up both the pairing
   * (including orphaned mobile) and the host device record itself.
   */
  removeDeviceAndPairing(hostDeviceId: string): { removedPairing: boolean; removedDevice: boolean } {
    const removedMobileId = this.removePairing(hostDeviceId);
    const removedDevice = this.removeDevice(hostDeviceId);
    return { removedPairing: removedMobileId !== null, removedDevice };
  }

  /**
   * Get all host device IDs paired with a given mobile device.
   */
  getHostsForMobile(mobileDeviceId: string): string[] {
    this.ensureSchema();
    const rows = this.sql.exec(
      'SELECT * FROM pairings WHERE mobile_device_id = ?',
      mobileDeviceId
    );
    return [...rows].map(row => rowToPairing(row).hostDeviceId);
  }

  /**
   * Get a single device by ID.
   */
  getDevice(deviceId: string): StoredDevice | null {
    this.ensureSchema();
    const rows = this.sql.exec(
      'SELECT id, ed25519_public_key, device_type, name, created_at FROM devices WHERE id = ?',
      deviceId
    );

    const results = [...rows];
    if (results.length === 0) return null;
    return rowToDevice(results[0]!);
  }

  /**
   * Remove a device by ID.
   */
  removeDevice(deviceId: string): boolean {
    this.ensureSchema();
    const before = this.sql.exec('SELECT COUNT(*) as count FROM devices WHERE id = ?', deviceId);
    const count = rowToCount([...before][0]!);
    if (count === 0) return false;

    this.sql.exec('DELETE FROM devices WHERE id = ?', deviceId);
    return true;
  }

  /**
   * Update a device's display name.
   */
  updateDeviceName(deviceId: string, name: string): void {
    this.ensureSchema();
    this.sql.exec('UPDATE devices SET name = ? WHERE id = ?', name, deviceId);
  }

  // --- Pairing session management ---

  /**
   * Create a pairing session. Returns a 6-character alphanumeric code, or null
   * when no unused code was found within MAX_PAIRING_CODE_ATTEMPTS; in that
   * case the host's existing session and any held /pair/complete are untouched.
   * Stored in SQLite so it survives DO hibernation.
   */
  createPairingSession(
    hostDeviceId: string,
    hostX25519PublicKey: string,
    hostEdPublicKey: string,
    pairConfirm = false
  ): string | null {
    this.ensureSchema();
    // Clean up expired sessions
    this.cleanExpiredPairings();

    // Pick a free code before mutating anything. The host's own row is about to
    // be replaced, so it does not count as a collision.
    let code: string | null = null;
    for (let attempt = 0; attempt < MAX_PAIRING_CODE_ATTEMPTS; attempt++) {
      const candidate = generatePairingCode();
      const taken = this.sql
        .exec('SELECT 1 FROM pairing_sessions WHERE code = ? AND host_device_id != ?', candidate, hostDeviceId)
        .toArray();
      if (taken.length === 0) {
        code = candidate;
        break;
      }
    }
    if (code === null) {
      return null;
    }

    // Invalidate any existing sessions for this host (prevents multiple valid codes)
    this.sql.exec('DELETE FROM pairing_sessions WHERE host_device_id = ?', hostDeviceId);
    // Drop any pair_complete still pending from an earlier attempt: it was MAC'd
    // with that attempt's pairing secret, so the new pair CLI would reject it.
    this.sql.exec('DELETE FROM pending_pair_complete WHERE host_device_id = ?', hostDeviceId);
    // Likewise a /pair/complete still held for a confirming host [SB-1348].
    this.settlePendingPair(hostDeviceId, pairSupersededResponse());

    this.sql.exec(
      'INSERT INTO pairing_sessions (code, host_device_id, host_x25519_public_key, host_ed_public_key, expires_at, pair_confirm) VALUES (?, ?, ?, ?, ?, ?)',
      code,
      hostDeviceId,
      hostX25519PublicKey,
      hostEdPublicKey,
      Date.now() + 5 * 60 * 1000,
      pairConfirm ? 1 : 0
    );

    return code;
  }

  /**
   * Consume a pairing session by code. Returns the session and removes it (single-use).
   * Reads from SQLite so it survives DO hibernation.
   */
  consumePairingSession(code: string): PairingSession | null {
    this.ensureSchema();
    this.cleanExpiredPairings();

    const rows = this.sql.exec(
      'SELECT host_device_id, host_x25519_public_key, host_ed_public_key, expires_at, pair_confirm FROM pairing_sessions WHERE code = ?',
      code
    ).toArray();

    if (rows.length === 0) return null;

    const row = rows[0]!;
    this.sql.exec('DELETE FROM pairing_sessions WHERE code = ?', code);

    return rowToPairingSession(row);
  }

  private cleanExpiredPairings(): void {
    this.ensureSchema();
    this.sql.exec('DELETE FROM pairing_sessions WHERE expires_at <= ?', Date.now());
  }

  // --- Challenge management ---

  /**
   * Create a single-use nonce challenge for a device. Nonce is 32 random bytes
   * base64-encoded, with a 60-second TTL.
   */
  createChallenge(deviceId: string): string {
    this.ensureSchema();
    this.cleanExpiredChallenges();

    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    const nonce = btoa(String.fromCharCode(...bytes));

    this.sql.exec(
      'INSERT INTO challenges (nonce, device_id, expires_at) VALUES (?, ?, ?)',
      nonce,
      deviceId,
      Date.now() + 60_000
    );

    return nonce;
  }

  /**
   * Consume a nonce challenge: deletes the nonce unconditionally (single-use)
   * and returns true only if a matching row existed, device_id matched, and it
   * was not expired.
   */
  consumeChallenge(nonce: string, deviceId: string): boolean {
    this.ensureSchema();
    // No expiry sweep here: the unconditional DELETE below removes this nonce,
    // and the `expires_at > Date.now()` check rejects an expired one. Sweeping
    // first would race a nonce expiring at the exact TTL boundary into a
    // spurious failure. Storage hygiene is handled by createChallenge's sweep.

    const rows = this.sql.exec(
      'SELECT device_id, expires_at FROM challenges WHERE nonce = ?',
      nonce
    ).toArray();

    // Delete unconditionally — single-use regardless of validity
    this.sql.exec('DELETE FROM challenges WHERE nonce = ?', nonce);

    if (rows.length === 0) return false;
    const row = rows[0]!;
    return (row['device_id'] as string) === deviceId && (row['expires_at'] as number) > Date.now();
  }

  private cleanExpiredChallenges(): void {
    this.sql.exec('DELETE FROM challenges WHERE expires_at <= ?', Date.now());
  }

  // --- WebSocket connection management ---

  /**
   * Find a WebSocket by deviceId. Checks the 1:1 cache first, then falls back
   * to the freshest live socket in the device's set (no rescan), caching it.
   * webSocketClose leaves the cache empty when a sibling outlives the cached
   * socket, so the fallback is what keeps that sibling routable.
   */
  private findWebSocket(deviceId: string): WebSocket | undefined {
    this.ensureConnectionCache();
    const cached = this.connections.get(deviceId);
    if (cached) return cached;

    let best: WebSocket | undefined;
    let bestTime = -1;
    for (const ws of this.deviceSockets.get(deviceId) ?? []) {
      const att = ws.deserializeAttachment() as WsAttachment | null;
      if (!att?.authenticated || att.deviceId !== deviceId || !isLive(ws, att)) continue;
      const last = att.lastMessageTime ?? 0;
      if (last > bestTime) {
        best = ws;
        bestTime = last;
      }
    }
    if (best) this.connections.set(deviceId, best);
    return best;
  }

  /**
   * Rebuild the in-memory socket caches from getWebSockets() once per wake.
   * Every later lookup reads the per-device sets, which auth/close/error and
   * the idle sweep keep current.
   */
  private ensureConnectionCache(): void {
    if (this.cacheRebuilt) return;
    this.cacheRebuilt = true;
    this.rebuildConnectionCache();
  }

  /**
   * Scan hibernated WebSockets into the connections cache, the per-device
   * counts and the per-device socket sets. Only ensureConnectionCache() calls it.
   */
  private rebuildConnectionCache(): void {
    if (!this.state.getWebSockets) return;
    this.wsConnectionCounts.clear();
    this.deviceSockets.clear();
    // When a device has several sockets, keep the freshest one [SB-1360]
    const freshest = new Map<string, number>();
    for (const ws of this.state.getWebSockets()) {
      const att = ws.deserializeAttachment() as WsAttachment | null;
      if (att?.authenticated && att.deviceId && isLive(ws, att)) {
        const last = att.lastMessageTime ?? 0;
        if (!this.connections.has(att.deviceId) || last > (freshest.get(att.deviceId) ?? 0)) {
          this.connections.set(att.deviceId, ws);
          freshest.set(att.deviceId, last);
        }
        const count = this.wsConnectionCounts.get(att.deviceId) ?? 0;
        this.wsConnectionCounts.set(att.deviceId, count + 1);
        let sockets = this.deviceSockets.get(att.deviceId);
        if (!sockets) {
          sockets = new Set();
          this.deviceSockets.set(att.deviceId, sockets);
        }
        sockets.add(ws);
      }
    }
  }

  /** Track an authenticated socket in its device's set. */
  private addDeviceSocket(deviceId: string, ws: WebSocket): void {
    this.ensureConnectionCache();
    let sockets = this.deviceSockets.get(deviceId);
    if (!sockets) {
      sockets = new Set();
      this.deviceSockets.set(deviceId, sockets);
    }
    sockets.add(ws);
  }

  /** Drop a socket from its device's set, removing the entry once it empties. */
  private removeDeviceSocket(deviceId: string, ws: WebSocket): void {
    this.ensureConnectionCache();
    const sockets = this.deviceSockets.get(deviceId);
    if (!sockets) return;
    sockets.delete(ws);
    if (sockets.size === 0) this.deviceSockets.delete(deviceId);
  }

  /**
   * Send a message to the paired mobile device of a host.
   * Looks up the pairing table and notifies all WebSocket connections for that mobile.
   */
  private notifyPairedMobile(hostDeviceId: string, message: unknown): void {
    const mobileId = this.getPairedMobile(hostDeviceId);
    if (mobileId) {
      this.notifyDevice(mobileId, message);
    }
  }

  /**
   * Send a message to ALL live WebSocket connections for a specific device.
   * Iterates the device's socket set (not the 1:1 connections map) so that
   * every connection receives the message — critical when a device has
   * multiple concurrent connections (e.g., background agent + pair CLI).
   * Returns the number of connections the message was sent to.
   */
  private notifyDevice(deviceId: string, message: unknown): number {
    this.ensureConnectionCache();
    let delivered = 0;
    for (const ws of this.deviceSockets.get(deviceId) ?? []) {
      const att = ws.deserializeAttachment() as WsAttachment | null;
      if (att?.authenticated && att.deviceId === deviceId && isLive(ws, att)) {
        try {
          wsSend(ws, message);
          delivered++;
        } catch {
          // WebSocket may have disconnected
        }
      }
    }
    return delivered;
  }

  // Backward-compatible helpers used by handlePairComplete and tests
  setConnection(deviceId: string, ws: WebSocket): void {
    this.connections.set(deviceId, ws);
  }

  getConnection(deviceId: string): WebSocket | undefined {
    return this.findWebSocket(deviceId);
  }

  removeConnection(deviceId: string): void {
    this.connections.delete(deviceId);
  }

  /** Get current WebSocket connection count for a device (for testing). */
  getWsConnectionCount(deviceId: string): number {
    return this.wsConnectionCounts.get(deviceId) ?? 0;
  }

  /**
   * Simulate DO hibernation by clearing in-memory connection counts and socket
   * sets, so the next lookup rebuilds them (for testing).
   */
  clearWsConnectionCounts(): void {
    this.wsConnectionCounts.clear();
    this.deviceSockets.clear();
    this.cacheRebuilt = false;
  }

  /** Simulate DO hibernation by clearing the in-memory TURN credential cache (for testing). */
  clearTurnCache(): void {
    this.turnCache = null;
  }

  // --- HTTP routing ---

  /** Allowed HTTP methods per path (excluding /ws which has no method restriction). */
  private static readonly ROUTE_METHODS: Record<string, string> = {
    '/challenge': 'POST',
    '/pair/initiate': 'POST',
    '/pair/complete': 'POST',
    '/token': 'POST',
    '/turn/credentials': 'GET',
    '/pairing': 'DELETE',
    '/device': 'DELETE',
  };

  async fetch(request: Request): Promise<Response> {
    try {
      return await this.route(request);
    } catch (err) {
      console.error('[do] unhandled error path=%s', new URL(request.url).pathname, err);
      return jsonResponse({ error: 'Internal error' }, 500);
    }
  }

  private async route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const clientIp = request.headers.get('X-Client-IP') ?? '127.0.0.1';
    const deviceId = request.headers.get('X-Device-Id') ?? '';

    // Check method-restricted routes first
    const allowedMethod = SignalingDO.ROUTE_METHODS[url.pathname];
    if (allowedMethod !== undefined) {
      if (request.method !== allowedMethod) {
        return new Response(JSON.stringify({ error: 'Method Not Allowed' }), {
          status: 405,
          headers: { 'Content-Type': 'application/json', 'Allow': allowedMethod },
        });
      }

      // Method matches — apply rate limiting and dispatch to handler.
      // Keys are namespaced by endpoint so endpoints sharing a limiter
      // binding (PAIR_LIMITER) keep independent counters.
      switch (url.pathname) {
        case '/challenge': {
          // ponytail: reuse TOKEN_LIMITER w/ namespaced key — no new wrangler binding; independent counter
          const limited = await this.checkLimit(this.env.TOKEN_LIMITER, `challenge:${clientIp}`, 60);
          if (limited) return limited;
          return this.handleChallenge(request);
        }
        case '/pair/initiate': {
          const limited = await this.checkLimit(this.env.PAIR_LIMITER, `pair/initiate:${clientIp}`, 60);
          if (limited) return limited;
          return this.handlePairInitiate(request);
        }
        case '/pair/complete': {
          const limited = await this.checkLimit(this.env.PAIR_LIMITER, `pair/complete:${clientIp}`, 60);
          if (limited) return limited;
          return this.handlePairComplete(request);
        }
        case '/token': {
          // Token uses IP as key since device ID comes from the request body (pre-auth)
          const limited = await this.checkLimit(this.env.TOKEN_LIMITER, `token:${clientIp}`, 60);
          if (limited) return limited;
          return this.handleTokenExchange(request);
        }
        case '/turn/credentials': {
          const limited = await this.checkLimit(this.env.TURN_LIMITER, `turn:${deviceId || clientIp}`, 60);
          if (limited) return limited;
          return this.handleTurnCredentials(deviceId, request.headers.get('X-Device-Type'));
        }
        case '/pairing': {
          const limited = await this.checkLimit(this.env.PAIR_LIMITER, `pairing:${deviceId || clientIp}`, 60);
          if (limited) return limited;
          return this.handleDeletePairing(request);
        }
        case '/device': {
          const limited = await this.checkLimit(this.env.PAIR_LIMITER, `device:${deviceId || clientIp}`, 60);
          if (limited) return limited;
          return this.handleDeleteDevice(request);
        }
      }
    }

    // /ws has no method restriction (upgrade check is inside the handler)
    if (url.pathname === '/ws') {
      const limited = await this.checkLimit(this.env.WS_LIMITER, `ws:${clientIp}`, 10);
      if (limited) return limited;
      return this.handleWebSocketUpgrade(request);
    }

    return new Response(JSON.stringify({ error: 'Not Found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // --- WebSocket upgrade [T1.8] ---

  /**
   * Handle WebSocket upgrade requests.
   * Uses the Hibernation API so idle connections don't burn compute.
   */
  private async handleWebSocketUpgrade(request: Request): Promise<Response> {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected WebSocket upgrade', { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    // Accept with Hibernation API — DO will sleep when no messages flow
    this.state.acceptWebSocket(server);
    server.serializeAttachment({
      authenticated: false,
      lastMessageTime: Date.now(),
    } as WsAttachment);

    // Schedule cleanup alarm on first WebSocket connection
    await this.scheduleAlarmIfNeeded();

    return new Response(null, { status: 101, webSocket: client });
  }

  // --- WebSocket Hibernation API handlers [T1.8] ---

  /**
   * Called by the runtime when a hibernated WebSocket receives a message.
   */
  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    // A late frame on a socket the DO already closed must not revive it: no
    // touch, no host_online re-announce, no reply (send would throw) [SB-1393]
    if (!isLive(ws, ws.deserializeAttachment() as WsAttachment | null)) return;

    if (typeof message !== 'string') return;

    if (message.length > MAX_WS_MESSAGE_SIZE) {
      wsSend(ws, { type: 'error', error: 'Message too large' });
      ws.close(1009, 'Message too large');
      return;
    }

    // Malformed frames do not count as activity: parse and shape-check first
    let data: SignalingClientMessage;
    try {
      data = JSON.parse(message) as SignalingClientMessage;
    } catch {
      wsSend(ws, { type: 'error', error: 'Invalid JSON' });
      return;
    }
    const parsed: unknown = data;
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      wsSend(ws, { type: 'error', error: 'Invalid message' });
      return;
    }

    // A host whose sockets were all stale was hidden from mobile presence by
    // isWebSocketFresh(); note it so it can be re-announced once live [SB-1004]
    const priorAtt = ws.deserializeAttachment() as WsAttachment | null;
    const hostWasHidden =
      priorAtt?.authenticated === true &&
      priorAtt.deviceType === 'host' &&
      !this.findFreshWebSocket(priorAtt.deviceId);

    // Update lastMessageTime on every received message (for idle timeout tracking)
    this.touchWebSocket(ws);

    // Re-auth announces host_online itself in handleWsAuth
    if (hostWasHidden && priorAtt && data.type !== 'auth') {
      const msg: HostOnlineMessage = { type: 'host_online', deviceId: priorAtt.deviceId, ts: Date.now() };
      const name = this.getDevice(priorAtt.deviceId)?.name;
      if (name) msg.name = name;
      this.notifyPairedMobile(priorAtt.deviceId, msg);
    }

    if (!data.type) {
      wsSend(ws, { type: 'error', error: 'Missing message type' });
      return;
    }

    // Auth must be handled before any other message type
    if (data.type === 'auth') {
      if (typeof data.token !== 'string') {
        wsSend(ws, { type: 'error', error: 'Missing or invalid auth token' });
        ws.close(4001, 'Missing or invalid auth token');
        return;
      }
      await this.handleWsAuth(ws, data.token, data.name);
      return;
    }

    // All other messages require authentication
    const attachment = ws.deserializeAttachment() as WsAttachment | null;
    if (!attachment?.authenticated) {
      wsSend(ws, { type: 'error', error: 'Not authenticated' });
      return;
    }

    switch (data.type) {
      case 'presence':
        wsSend(ws, { type: 'presence_ack' });
        break;

      case 'connect_request':
        // Only a mobile initiates a connection [SB-1360]
        if (attachment.deviceType !== 'mobile') {
          wsSend(ws, { type: 'error', error: 'connect_request is only accepted from a mobile device' });
          break;
        }
        await this.handleConnectRequest(ws, attachment, data.targetDeviceId, data.attemptId);
        break;

      case 'sdp_offer':
      case 'sdp_answer':
      case 'ice_candidate':
      case 'connection_rejected':
        this.relaySignalingMessage(ws, attachment, data);
        break;

      case 'pair_accept':
      case 'pair_reject':
        this.handlePairDecision(ws, attachment, data);
        break;

      default:
        wsSend(ws, { type: 'error', error: `Unknown message type: ${(data as { type: string }).type}` });
    }
  }

  /**
   * Called by the runtime when a WebSocket closes.
   */
  async webSocketClose(ws: WebSocket, _code: number, _reason: string, _wasClean: boolean): Promise<void> {
    const attachment = ws.deserializeAttachment() as WsAttachment | null;
    // A socket the DO closed was already cleaned up where it was closed [SB-1393]
    if (!attachment?.authenticated || attachment.closed) return;

    // First, so a rebuild this triggers (close as the first event after a
    // wake) can't re-add the socket or skew the count below
    this.removeDeviceSocket(attachment.deviceId, ws);

    // Only remove from cache if this WS is the one currently stored.
    // A device may have multiple concurrent WebSockets (e.g., mobile uses one
    // for presence on the host list and another for WebRTC signaling). If a
    // stale WS closes after a newer one registered, blindly deleting would
    // remove the newer WS's routing entry.
    if (this.connections.get(attachment.deviceId) === ws) {
      this.connections.delete(attachment.deviceId);
    }

    // Decrement WebSocket connection count (used by alarm-path guard)
    this.decrementWsCount(attachment.deviceId);

    // If this was the last connection for a host, notify the paired mobile.
    // Count live sockets in the device's set (rebuilt from getWebSockets()
    // once per wake), excluding the closing WS.
    if (attachment.deviceType === 'host') {
      const otherCount = this.countOtherActiveWsForDevice(attachment.deviceId, ws);
      if (otherCount === 0) {
        this.clearSignalingSession(attachment.deviceId);
        const msg: HostOfflineMessage = { type: 'host_offline', deviceId: attachment.deviceId, ts: Date.now() };
        this.notifyPairedMobile(attachment.deviceId, msg);
      }
    }
  }

  /**
   * Called by the runtime when a WebSocket encounters an error.
   */
  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    const attachment = ws.deserializeAttachment() as WsAttachment | null;
    console.error('[ws-error] deviceId=%s error=%o', attachment?.deviceId, error);
    // Skip cleanup already done when the DO closed this socket [SB-1393]
    if (attachment?.authenticated && !attachment.closed) {
      // Before markClosed, so a rebuild this triggers still counts the socket
      // that the decrement below removes
      this.removeDeviceSocket(attachment.deviceId, ws);
      this.markClosed(ws);
      if (this.connections.get(attachment.deviceId) === ws) {
        this.connections.delete(attachment.deviceId);
      }
      this.decrementWsCount(attachment.deviceId);
      // If this was the last connection for a host, notify the paired mobile,
      // counting the device's other live sockets as webSocketClose does.
      if (
        attachment.deviceType === 'host' &&
        this.countOtherActiveWsForDevice(attachment.deviceId, ws) === 0
      ) {
        this.clearSignalingSession(attachment.deviceId);
        const msg: HostOfflineMessage = { type: 'host_offline', deviceId: attachment.deviceId, ts: Date.now() };
        this.notifyPairedMobile(attachment.deviceId, msg);
      }
    }
    try {
      ws.close(1011, 'WebSocket error');
    } catch {
      // May already be closed
    }
  }

  // --- Idle timeout tracking ---

  /**
   * Update the lastMessageTime in the WebSocket's attachment.
   * Called on every received message to track idle state.
   */
  private touchWebSocket(ws: WebSocket): void {
    const att = ws.deserializeAttachment() as WsAttachment | null;
    if (att) {
      att.lastMessageTime = Date.now();
      ws.serializeAttachment(att);
    }
  }

  /** Flag a socket the DO is closing so nothing treats it as live again [SB-1393]. */
  private markClosed(ws: WebSocket): void {
    const att = ws.deserializeAttachment() as WsAttachment | null;
    if (att) {
      att.closed = true;
      ws.serializeAttachment(att);
    }
  }

  /**
   * A WebSocket is "fresh" if its last received message is within the idle
   * timeout. A sleeping/frozen host stops sending heartbeats, but its socket
   * lingers until the idle sweep reaps it (up to WS_IDLE_TIMEOUT_MS + one alarm
   * interval later). Treating a stale socket as offline keeps presence accurate
   * during that window — a mobile listing hosts or trying to connect sees the
   * host as offline immediately, instead of being told it is online while it is
   * actually asleep and unreachable.
   */
  private isWebSocketFresh(ws: WebSocket): boolean {
    const att = ws.deserializeAttachment() as WsAttachment | null;
    const last = att?.lastMessageTime ?? 0;
    return isLive(ws, att) && last > 0 && Date.now() - last <= WS_IDLE_TIMEOUT_MS;
  }

  /**
   * Find a fresh socket for a device. Prefers the cached socket, then falls back
   * to any other fresh socket in the device's socket set [SB-1004].
   */
  private findFreshWebSocket(deviceId: string): WebSocket | undefined {
    const cached = this.findWebSocket(deviceId);
    if (cached && this.isWebSocketFresh(cached)) return cached;
    for (const ws of this.deviceSockets.get(deviceId) ?? []) {
      if (ws === cached) continue;
      const att = ws.deserializeAttachment() as WsAttachment | null;
      if (att?.authenticated && att.deviceId === deviceId && this.isWebSocketFresh(ws)) {
        this.connections.set(deviceId, ws);
        return ws;
      }
    }
    return undefined;
  }

  // --- DO alarm handler (idle WS cleanup + expired pairing purge) ---

  private isPairedDevice(deviceId: string, deviceType: string | null): boolean {
    if (!deviceId) return false;
    if (deviceType === 'host') return this.getPairedMobile(deviceId) !== null;
    if (deviceType === 'mobile') return this.getHostsForMobile(deviceId).length > 0;
    return false;
  }

  /**
   * Called by the runtime on the scheduled alarm.
   * Closes idle WebSockets and purges expired pairing codes.
   */
  async alarm(): Promise<void> {
    const now = Date.now();
    let activeCount = 0;
    const liveDeviceIds = new Set<string>();

    if (this.state.getWebSockets) {
      for (const ws of this.state.getWebSockets()) {
        const att = ws.deserializeAttachment() as WsAttachment | null;
        // Already reaped and still lingering: don't close, count or notify again [SB-1393]
        if (!att || att.closed) continue;

        const lastMsg = att.lastMessageTime ?? 0;
        if (lastMsg > 0 && now - lastMsg > WS_IDLE_TIMEOUT_MS) {
          const authed = att.authenticated && !!att.deviceId;
          // Before markClosed, as in webSocketError, so a rebuild this triggers
          // still counts the socket that the decrement below removes
          if (authed) this.removeDeviceSocket(att.deviceId, ws);
          // Mark first, as webSocketError does, then close the idle WebSocket
          this.markClosed(ws);
          try {
            ws.close(1000, 'idle timeout');
          } catch {
            // May already be closed
          }
          if (authed) {
            if (this.connections.get(att.deviceId) === ws) {
              this.connections.delete(att.deviceId);
            }
            this.decrementWsCount(att.deviceId);
            // Notify the paired mobile that the host is offline only when this
            // is the last connection for the device, counting its other live
            // sockets in the per-device set, so multi-WS devices are handled
            // correctly even after DO hibernation.
            if (
              att.deviceType === 'host' &&
              this.countOtherActiveWsForDevice(att.deviceId, ws) === 0
            ) {
              this.clearSignalingSession(att.deviceId);
              const msg: HostOfflineMessage = { type: 'host_offline', deviceId: att.deviceId, ts: Date.now() };
              this.notifyPairedMobile(att.deviceId, msg);
            }
          }
        } else {
          activeCount++;
          if (att.authenticated && att.deviceId && isLive(ws, att)) liveDeviceIds.add(att.deviceId);
        }
      }
    }

    // Purge expired pairing codes
    this.cleanExpiredPairings();

    this.purgeUnpairedHosts(now, liveDeviceIds);

    // Time out connect_requests the host never answered [SB-1001]
    this.expireSignalingSessions(now);

    // Re-schedule: next idle sweep if there are still active connections,
    // pulled forward to the earliest pending signaling session expiry.
    let next = activeCount > 0 ? Date.now() + ALARM_INTERVAL_MS : Infinity;
    const pending = this.sql
      .exec('SELECT MIN(expires_at) AS next FROM signaling_sessions')
      .toArray()[0]?.['next'];
    if (typeof pending === 'number') next = Math.min(next, pending);
    // Keep the unpaired-host purge scheduled; clamp so a host that was skipped
    // (live socket, pending pairing) can't re-fire the alarm in a hot loop.
    const oldest = this.sql
      .exec(
        "SELECT MIN(created_at) AS oldest FROM devices WHERE device_type = 'host' AND id NOT IN (SELECT host_device_id FROM pairings)"
      )
      .toArray()[0]?.['oldest'];
    if (typeof oldest === 'number') {
      const due = oldest * 1000 + UNPAIRED_HOST_TTL_S * 1000 + ALARM_INTERVAL_MS;
      next = Math.min(next, Math.max(due, Date.now() + ALARM_INTERVAL_MS));
    }
    if (next !== Infinity) {
      await this.state.storage.setAlarm(next);
    }
  }

  /**
   * Delete host rows that never paired and are older than UNPAIRED_HOST_TTL_S.
   * Hosts with a pairing session, a held confirming /pair/complete or a live
   * authenticated socket are kept (e.g. a host mid `pmux pair` after unpair).
   */
  private purgeUnpairedHosts(now: number, liveDeviceIds: Set<string>): void {
    const cutoff = Math.floor(now / 1000) - UNPAIRED_HOST_TTL_S;
    const rows = this.sql
      .exec(
        `SELECT id FROM devices WHERE device_type = 'host' AND created_at < ?
           AND id NOT IN (SELECT host_device_id FROM pairings)
           AND id NOT IN (SELECT host_device_id FROM pairing_sessions)
           AND id NOT IN (SELECT host_device_id FROM pending_pair_complete)`,
        cutoff
      )
      .toArray();
    for (const row of rows) {
      const id = row['id'] as string;
      if (this.pendingPairs.has(id) || liveDeviceIds.has(id)) continue;
      this.sql.exec('DELETE FROM devices WHERE id = ?', id);
    }
  }

  /**
   * Schedule the cleanup alarm if not already scheduled.
   * Called on first WebSocket connection.
   */
  private async scheduleAlarmIfNeeded(): Promise<void> {
    const currentAlarm = await this.state.storage.getAlarm();
    if (!currentAlarm) {
      await this.state.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
    }
  }

  /**
   * Ensure the alarm fires no later than `time` — moves an existing later
   * alarm forward, leaves an earlier one alone.
   */
  private async scheduleAlarmBy(time: number): Promise<void> {
    const currentAlarm = await this.state.storage.getAlarm();
    if (!currentAlarm || currentAlarm > time) {
      await this.state.storage.setAlarm(time);
    }
  }

  /**
   * Drop a host's pending signaling session [SB-1001]. Called wherever the host
   * answers or host_offline is sent, so a timeout never follows host_offline.
   * Given an attemptId, a session tagged with a different attempt is kept, so a
   * late answer to an older attempt can't cancel the current one's timeout.
   */
  private clearSignalingSession(hostDeviceId: string, attemptId?: string): void {
    this.ensureSchema();
    const attempt = attemptId ?? null;
    this.sql.exec(
      'DELETE FROM signaling_sessions WHERE host_device_id = ? AND (? IS NULL OR attempt_id IS NULL OR attempt_id = ?)',
      hostDeviceId,
      attempt,
      attempt
    );
  }

  /**
   * Expire signaling sessions whose host never replied to connect_request and
   * tell both ends with peer_unavailable [SB-1001]. Every socket of each device
   * is notified — a mobile may hold separate presence and signaling sockets.
   */
  private expireSignalingSessions(now: number): void {
    this.ensureSchema();
    const expired = this.sql
      .exec(
        'SELECT host_device_id, mobile_device_id, attempt_id FROM signaling_sessions WHERE expires_at <= ?',
        now
      )
      .toArray();
    if (expired.length === 0) return;
    this.sql.exec('DELETE FROM signaling_sessions WHERE expires_at <= ?', now);

    for (const row of expired) {
      const hostId = row['host_device_id'] as string;
      const mobileId = row['mobile_device_id'] as string;
      // Unpaired since the request — the devices must learn nothing of each other
      if (!this.isPaired(hostId, mobileId)) continue;

      const attemptId = row['attempt_id'] as string | null;
      this.notifyDevice(mobileId, {
        type: 'peer_unavailable',
        deviceId: hostId,
        ...(attemptId !== null && { attemptId }),
      });
      this.notifyDevice(hostId, {
        type: 'peer_unavailable',
        deviceId: mobileId,
        ...(attemptId !== null && { attemptId }),
      });
    }
  }

  // --- WebSocket connection count helpers ---

  private incrementWsCount(deviceId: string): void {
    const current = this.wsConnectionCounts.get(deviceId) ?? 0;
    this.wsConnectionCounts.set(deviceId, current + 1);
  }

  private decrementWsCount(deviceId: string): void {
    const current = this.wsConnectionCounts.get(deviceId) ?? 0;
    if (current <= 1) {
      this.wsConnectionCounts.delete(deviceId);
    } else {
      this.wsConnectionCounts.set(deviceId, current - 1);
    }
  }

  /**
   * Count live authenticated WebSocket connections for a device, excluding a
   * specific WebSocket (typically the one that is closing or erroring).
   * Reads the device's socket set, rebuilt from the runtime's getWebSockets()
   * once per wake and kept current on auth/close/error/idle-close, so it is
   * correct straight after DO hibernation.
   *
   * Safe to use for the auth-time cap check (excludeWs = the socket being
   * authenticated): a socket joins the set only once it authenticates, so the
   * current socket is never counted.
   */
  private countOtherActiveWsForDevice(deviceId: string, excludeWs: WebSocket): number {
    this.ensureConnectionCache();
    let count = 0;
    for (const ws of this.deviceSockets.get(deviceId) ?? []) {
      if (ws === excludeWs) continue;
      const att = ws.deserializeAttachment() as WsAttachment | null;
      if (att?.authenticated && att.deviceId === deviceId && isLive(ws, att)) count++;
    }
    return count;
  }

  // --- WebSocket message handlers ---

  /**
   * Handle auth message: verify JWT and associate WebSocket with device.
   * Enforces per-device WebSocket connection limit.
   */
  private async handleWsAuth(ws: WebSocket, token: string, name?: string): Promise<void> {
    try {
      const payload = await verifyJWT(token, this.env.JWT_SECRET);

      // The socket may have been closed during the await; don't overwrite its
      // closed attachment with a fresh authenticated one [SB-1393]
      if (!isLive(ws, ws.deserializeAttachment() as WsAttachment | null)) return;

      // Check WebSocket connection limit per device. Count from the per-device
      // socket set, rebuilt from getWebSockets() on the first lookup after a
      // wake, so a device can't bypass the cap by timing connections to hit a
      // hibernated DO [SB-993].
      const currentCount = this.countOtherActiveWsForDevice(payload.deviceId, ws);
      if (currentCount >= MAX_WS_CONNECTIONS_PER_DEVICE) {
        console.warn(
          `[ws-limit] Rejected: deviceId=${payload.deviceId} connections=${currentCount} limit=${MAX_WS_CONNECTIONS_PER_DEVICE}`
        );
        wsSend(ws, { type: 'error', error: 'Too many WebSocket connections' });
        ws.close(1008, 'Too many connections');
        return;
      }

      // Verify device still exists in DB (may have been deleted by orphan cleanup after re-pairing)
      const device = this.getDevice(payload.deviceId);
      if (!device) {
        wsSend(ws, { type: 'error', error: 'Device not found' });
        ws.close(4004, 'Device not found');
        return;
      }

      const attachment: WsAttachment = {
        deviceId: payload.deviceId,
        deviceType: payload.deviceType,
        authenticated: true,
        lastMessageTime: Date.now(),
      };
      ws.serializeAttachment(attachment);

      // Update in-memory cache, socket set and connection count
      this.connections.set(payload.deviceId, ws);
      this.addDeviceSocket(payload.deviceId, ws);
      this.incrementWsCount(payload.deviceId);

      // Update device name if provided in auth message
      const validName = validateDeviceName(name);

      if (validName && payload.deviceType === 'mobile') {
        const nameChanged = device.name !== validName;
        this.updateDeviceName(payload.deviceId, validName);
        if (nameChanged) {
          const pairedHosts = this.getHostsForMobile(payload.deviceId);
          for (const hostDeviceId of pairedHosts) {
            this.notifyDevice(hostDeviceId, {
              type: 'mobile_name_updated',
              deviceId: payload.deviceId,
              name: validName,
            });
          }
        }
      } else if (validName && payload.deviceType === 'host') {
        this.updateDeviceName(payload.deviceId, validName);
      }

      // If host, notify the paired mobile of host_online (with name from DB)
      if (payload.deviceType === 'host') {
        const hostOnlineMsg: HostOnlineMessage = {
          type: 'host_online',
          deviceId: payload.deviceId,
          ts: Date.now(),
        };
        if (validName) {
          hostOnlineMsg.name = validName;
        } else if (device.name) {
          hostOnlineMsg.name = device.name;
        }
        const pairedMobileId = this.getPairedMobile(payload.deviceId);
        if (pairedMobileId) {
          this.notifyDevice(pairedMobileId, hostOnlineMsg);
        }

        // Auth reply before any pair_complete: a pair CLI reads the auth reply
        // first and would drop a pair_complete that arrived ahead of it.
        wsSend(ws, { type: 'auth', status: 'ok' });

        // Deliver a pair_complete that was persisted while the host was offline.
        // Only if the pairing still matches — it may have been replaced/removed since.
        const pending = this.sql
          .exec(
            'SELECT mobile_device_id, mobile_x25519_public_key, mobile_name, mobile_pair_mac FROM pending_pair_complete WHERE host_device_id = ?',
            payload.deviceId
          )
          .toArray()[0];
        if (pending) {
          if (pairedMobileId === pending['mobile_device_id']) {
            // Broadcast to ALL host connections (this newly authed socket is
            // already in the device's socket set),
            // matching the live-delivery invariant for agent + pair CLI.
            this.notifyDevice(payload.deviceId, {
              type: 'pair_complete',
              mobileDeviceId: pending['mobile_device_id'],
              mobileX25519PublicKey: pending['mobile_x25519_public_key'],
              ...(pending['mobile_name'] !== null && { mobileName: pending['mobile_name'] }),
              ...(pending['mobile_pair_mac'] != null && { pairMac: pending['mobile_pair_mac'] }),
            });
          }
          this.sql.exec('DELETE FROM pending_pair_complete WHERE host_device_id = ?', payload.deviceId);
        }

        // A confirming host's pair_complete is held in memory, not in SQL. Send it
        // only to this socket; sockets that were already connected got it when
        // /pair/complete relayed it.
        const held = this.pendingPairs.get(payload.deviceId);
        if (held) wsSend(ws, held.pairComplete);
      }

      // If mobile, send current presence snapshot for all paired hosts that are connected.
      if (payload.deviceType === 'mobile') {
        const pairedHosts = this.getHostsForMobile(payload.deviceId);
        for (const hostDeviceId of pairedHosts) {
          if (this.findFreshWebSocket(hostDeviceId)) {
            const device = this.getDevice(hostDeviceId);
            const msg: HostOnlineMessage = { type: 'host_online', deviceId: hostDeviceId, ts: Date.now() };
            if (device?.name) {
              msg.name = device.name;
            }
            wsSend(ws, msg);
          }
        }
        // Re-assert this WS as the cached connection. The socket caches are
        // rebuilt at most once per wake, by the cap check above (before this
        // socket authenticated), and the host lookups above re-cache only host
        // entries. Re-setting here keeps the freshly authenticated WS the
        // routable entry over an older sibling (e.g., a presence WS from
        // HostListScreen that is mid-close).
        this.connections.set(payload.deviceId, ws);

        wsSend(ws, { type: 'auth', status: 'ok' });
      }
    } catch (err) {
      if (err instanceof TokenExpiredError) {
        // [SB-1004] Distinct code so clients can refresh their JWT; text and close code stay back-compat.
        wsSend(ws, { type: 'error', error: 'Authentication failed', code: 'token_expired' });
        ws.close(4001, 'token_expired');
        return;
      }
      wsSend(ws, { type: 'error', error: 'Authentication failed' });
      ws.close(4001, 'Authentication failed');
    }
  }

  /**
   * Handle connect_request: mobile wants to connect to a host.
   * Relays the request to the target host with the mobile's deviceId.
   * Only allows signaling between paired devices.
   */
  private async handleConnectRequest(
    ws: WebSocket,
    sender: WsAttachment,
    targetDeviceId: string,
    rawAttemptId: unknown
  ): Promise<void> {
    // Stored, forwarded and echoed on peer_unavailable; invalid IDs are dropped
    const attemptId = validateAttemptId(rawAttemptId);

    // Check pairing FIRST (before WS lookup) — don't reveal device existence to unpaired callers.
    // The sender is always a mobile: webSocketMessage rejects connect_request from hosts [SB-1360].
    const hostId = targetDeviceId;
    const mobileId = sender.deviceId;
    if (!this.isPaired(hostId, mobileId)) {
      wsSend(ws, { type: 'connection_rejected', reason: 'not_paired' });
      return;
    }

    // Paired — check if target is online. A stale socket (host asleep but not
    // yet reaped by the idle sweep) is treated as offline so the mobile gets an
    // immediate host_offline instead of a connect_request that never reaches a
    // frozen host.
    const targetWs = this.findFreshWebSocket(targetDeviceId);
    if (!targetWs) {
      // Paired but offline → send host_offline so mobile can schedule reconnect
      this.clearSignalingSession(hostId);
      const msg: HostOfflineMessage = { type: 'host_offline', deviceId: targetDeviceId, ts: Date.now() };
      wsSend(ws, msg);
      return;
    }

    // Relay to target with sender's deviceId as the origin
    try {
      wsSend(targetWs, {
        type: 'connect_request',
        targetDeviceId: sender.deviceId,
        ...(attemptId !== undefined && { attemptId }),
      });
    } catch {
      if (this.connections.get(targetDeviceId) === targetWs) {
        this.connections.delete(targetDeviceId);
      }
      // Unreachable host — drop any earlier attempt's session, whose expiry
      // would carry a stale attemptId, and fail this attempt now
      this.clearSignalingSession(hostId);
      this.sendPeerUnavailable(ws, targetDeviceId, attemptId);
      return;
    }

    // Relayed — track until the host replies so a silent host times out [SB-1001]
    const expiresAt = Date.now() + SIGNALING_SESSION_TIMEOUT_MS;
    this.sql.exec(
      'INSERT OR REPLACE INTO signaling_sessions (host_device_id, mobile_device_id, expires_at, attempt_id) VALUES (?, ?, ?, ?)',
      hostId,
      mobileId,
      expiresAt,
      attemptId ?? null
    );
    await this.scheduleAlarmBy(expiresAt);
  }

  /**
   * Relay SDP/ICE signaling messages between devices.
   * Swaps targetDeviceId to the sender's deviceId so the recipient knows the origin.
   * Only allows signaling between paired devices.
   */
  private relaySignalingMessage(
    ws: WebSocket,
    sender: WsAttachment,
    data: { type: string; targetDeviceId: string; [key: string]: unknown }
  ): void {
    // Verify sender and target are paired (prevents cross-pairing signaling).
    // Checked BEFORE the WS lookup so unpaired senders learn nothing about
    // whether the target device exists or is online.
    const hostId = sender.deviceType === 'host' ? sender.deviceId : data.targetDeviceId;
    const mobileId = sender.deviceType === 'mobile' ? sender.deviceId : data.targetDeviceId;
    if (!this.isPaired(hostId, mobileId)) return;

    // Relayed through and reflected on peer_unavailable; invalid IDs are dropped [SB-1375]
    const attemptId = validateAttemptId(data.attemptId);

    // Host answered the connect_request — signaling session complete [SB-1001].
    // An offer only completes its own attempt; connection_rejected is untagged.
    if (sender.deviceType === 'host') {
      if (data.type === 'sdp_offer') {
        this.clearSignalingSession(hostId, attemptId);
      } else if (data.type === 'connection_rejected') {
        this.clearSignalingSession(hostId);
      }
    }

    // A stale socket (e.g. a sleeping host not yet reaped) is as unreachable
    // as a missing one, but any fresh socket of the device will do [SB-1360]
    const targetWs = this.findFreshWebSocket(data.targetDeviceId);
    if (!targetWs) {
      // Target disconnected mid-negotiation [SB-1000] — tell the sender so it
      // can fail fast or retry instead of stalling until its watchdog fires.
      this.sendPeerUnavailable(ws, data.targetDeviceId, attemptId);
      return;
    }

    // Relay only known fields — never spread untrusted data
    try {
      wsSend(targetWs, {
        type: data.type,
        targetDeviceId: sender.deviceId,
        ...(data.sdp !== undefined && { sdp: data.sdp }),
        ...(data.candidate !== undefined && { candidate: data.candidate }),
        ...(data.sdpMid !== undefined && { sdpMid: data.sdpMid }),
        ...(data.sdpMLineIndex !== undefined && { sdpMLineIndex: data.sdpMLineIndex }),
        ...('reason' in data && data.reason !== undefined && { reason: data.reason }),
        ...(attemptId !== undefined && data.type !== 'connection_rejected' && { attemptId }),
      });
    } catch {
      if (this.connections.get(data.targetDeviceId) === targetWs) {
        this.connections.delete(data.targetDeviceId);
      }
      // Send to target failed — same failure mode as target-not-found [SB-1000]
      this.sendPeerUnavailable(ws, data.targetDeviceId, attemptId);
    }
  }

  /**
   * Best-effort peer_unavailable notification to a relay sender [SB-1000].
   * Guarded: if the sender's own socket is also dead, there is nothing left
   * to notify — never let that propagate out of the message handler.
   */
  private sendPeerUnavailable(ws: WebSocket, deviceId: string, attemptId?: string): void {
    try {
      wsSend(ws, {
        type: 'peer_unavailable',
        deviceId,
        ...(attemptId !== undefined && { attemptId }),
      });
    } catch {
      // Sender gone too — nothing to do
    }
  }

  // --- Challenge endpoint [SB-996] ---

  /**
   * POST /challenge
   * Issues a single-use nonce for a device to sign as part of Ed25519 auth.
   * Body: { deviceId } (device need not exist yet — used at pair/initiate time too)
   * Returns: { nonce } (base64, 32 random bytes, 60s TTL)
   */
  private async handleChallenge(request: Request): Promise<Response> {
    let body: { deviceId?: unknown };
    try {
      body = await request.json() as typeof body;
    } catch {
      return jsonResponse({ error: 'Invalid JSON' }, 400);
    }

    const { deviceId } = body;
    if (typeof deviceId !== 'string' || !/^[0-9a-f]{32}$/.test(deviceId)) {
      return jsonResponse({ error: 'Missing or invalid deviceId (must be 32 lowercase hex chars)' }, 400);
    }

    const nonce = this.createChallenge(deviceId);
    return jsonResponse({ nonce });
  }

  // --- Pairing endpoints [T1.5] ---

  /**
   * POST /pair/initiate
   * Host calls this to start pairing. Creates a pairing session.
   * Body: { deviceId, ed25519PublicKey, x25519PublicKey, nonce, signature, name?, pairConfirm? }
   * Returns: { pairingCode, pairConfirm? } — pairConfirm: true is echoed when
   * requested, telling the host this server holds /pair/complete for its decision.
   */
  private async handlePairInitiate(request: Request): Promise<Response> {
    let body: {
      deviceId?: string;
      ed25519PublicKey?: string;
      x25519PublicKey?: string;
      nonce?: string;
      signature?: string;
      name?: string;
      pairConfirm?: boolean;
    };
    try {
      body = await request.json() as typeof body;
    } catch {
      return jsonResponse({ error: 'Invalid JSON' }, 400);
    }

    if (!body.deviceId || !body.ed25519PublicKey || !body.x25519PublicKey || !body.nonce || !body.signature) {
      return jsonResponse(
        { error: 'Missing required fields: deviceId, ed25519PublicKey, x25519PublicKey, nonce, signature' },
        400
      );
    }

    // Validate name if provided
    if (body.name !== undefined && validateDeviceName(body.name) === undefined) {
      return jsonResponse({ error: 'Name must be a string of 1-64 characters with no control characters' }, 400);
    }

    // Checked before consumeChallenge so a 400 does not burn the nonce
    if (!isBase64OfLength(body.x25519PublicKey, 32)) {
      return jsonResponse({ error: 'Invalid x25519PublicKey' }, 400);
    }

    // Consume the nonce challenge (single-use, validates expiry and device binding)
    if (!this.consumeChallenge(body.nonce, body.deviceId)) {
      return jsonResponse({ error: 'Invalid or expired challenge' }, 401);
    }

    // Verify signature against stored key (if device exists) or request body key
    const existing = this.getDevice(body.deviceId);
    // For an existing host the body key is stored as host_ed_public_key without
    // being the verify key, so it must be well-formed on its own
    if (existing && !isBase64OfLength(body.ed25519PublicKey, 32)) {
      return jsonResponse({ error: 'Invalid ed25519PublicKey' }, 400);
    }
    const verifyKey = existing ? existing.ed25519PublicKey : body.ed25519PublicKey;
    const message = new TextEncoder().encode(body.deviceId + '|' + body.nonce);

    let valid: boolean;
    try {
      const publicKeyBytes = base64ToBytes(verifyKey);
      const signatureBytes = base64ToBytes(body.signature);
      valid = await verifyEd25519Signature(publicKeyBytes, message, signatureBytes);
    } catch {
      return jsonResponse({ error: 'Invalid signature format' }, 401);
    }
    if (!valid) {
      return jsonResponse({ error: 'Signature verification failed' }, 401);
    }

    // Register the host device if not already registered, or update name
    if (!existing) {
      this.registerDevice(body.deviceId, body.ed25519PublicKey, 'host', body.name);
      await this.scheduleAlarmBy(Date.now() + UNPAIRED_HOST_TTL_S * 1000 + ALARM_INTERVAL_MS);
    } else if (body.name !== undefined) {
      // Signature already verified against stored key, safe to update name
      this.updateDeviceName(body.deviceId, body.name);
    }

    const pairConfirm = body.pairConfirm === true;
    const pairingCode = this.createPairingSession(
      body.deviceId,
      body.x25519PublicKey,
      body.ed25519PublicKey,
      pairConfirm
    );
    if (pairingCode === null) {
      console.warn('[pair] no free pairing code after retries');
      return jsonResponse({ error: 'Pairing temporarily unavailable' }, 503);
    }

    return jsonResponse(pairConfirm ? { pairingCode, pairConfirm } : { pairingCode });
  }

  /**
   * POST /pair/complete
   * Mobile calls this with the pairing code to complete pairing.
   * Body: { pairingCode, deviceId, ed25519PublicKey, x25519PublicKey, name?, pairMac? }
   * Returns: { hostX25519PublicKey, hostDeviceId, hostName? }
   * For a confirming host (pairConfirm at initiate) the request is held until
   * the host answers: 200 accepted, 403 rejected, 504 no answer, 409 superseded
   * by a newer pairing, cancelled by the host's unpair/uninstall, or a
   * device-type/key conflict at commit, 500 commit failure.
   * Either path answers 409 for a device-type/key conflict before any pairing
   * changes.
   */
  private async handlePairComplete(request: Request): Promise<Response> {
    let body: {
      pairingCode?: string;
      deviceId?: string;
      ed25519PublicKey?: string;
      x25519PublicKey?: string;
      name?: string;
      pairMac?: string | null;
    };
    try {
      body = await request.json() as typeof body;
    } catch {
      return jsonResponse({ error: 'Invalid JSON' }, 400);
    }

    if (!body.pairingCode || !body.deviceId || !body.ed25519PublicKey || !body.x25519PublicKey) {
      return jsonResponse(
        { error: 'Missing required fields: pairingCode, deviceId, ed25519PublicKey, x25519PublicKey' },
        400
      );
    }

    // Bound what a held confirming-path request can pin in memory. Validate
    // before consuming the code.
    if (
      typeof body.deviceId !== 'string' || body.deviceId.length > MAX_PAIR_DEVICE_ID_LENGTH ||
      typeof body.ed25519PublicKey !== 'string' || body.ed25519PublicKey.length > MAX_PAIR_PUBLIC_KEY_LENGTH ||
      typeof body.x25519PublicKey !== 'string' || body.x25519PublicKey.length > MAX_PAIR_PUBLIC_KEY_LENGTH
    ) {
      return jsonResponse({ error: 'Invalid deviceId or public key' }, 400);
    }

    // pairMac is an opaque pass-through (the agent verifies it); optional so
    // older mobile builds still pair, and null counts as absent. Only bound the
    // size and charset (any base64 variant) so a MAC format change doesn't need
    // a server deploy. Validate before consuming the code.
    if (
      body.pairMac != null &&
      (typeof body.pairMac !== 'string' ||
        !/^[A-Za-z0-9+/=_-]{1,64}$/.test(body.pairMac))
    ) {
      return jsonResponse({ error: 'Invalid pairMac' }, 400);
    }
    const pairMac = body.pairMac ?? undefined;

    const mobileName = validateDeviceName(body.name);

    // Consume the pairing session (single-use, validates expiry)
    const session = this.consumePairingSession(body.pairingCode);
    if (!session) {
      return jsonResponse({ error: 'Invalid or expired pairing code' }, 404);
    }

    // Get the host device
    const hostDevice = this.getDevice(session.hostDeviceId);
    if (!hostDevice) {
      return jsonResponse({ error: 'Host device not found' }, 500);
    }

    const pairComplete: PairCompleteMessage = {
      type: 'pair_complete',
      mobileDeviceId: body.deviceId,
      mobileX25519PublicKey: body.x25519PublicKey,
      ...(mobileName !== undefined && { mobileName }),
      ...(pairMac !== undefined && { pairMac }),
    };

    // Confirming host: hold the request until it accepts or rejects [SB-1348].
    if (session.pairConfirm) {
      // Fast-fail a conflict before holding the request; commitPairing
      // re-checks at accept time.
      if (this.hasMobileConflict(body.deviceId, body.ed25519PublicKey)) {
        return mobileConflictResponse();
      }

      const hostDeviceId = session.hostDeviceId;
      // createPairingSession already settles a held request when it issues a
      // new code; settle here too so an entry is never overwritten unanswered.
      this.settlePendingPair(hostDeviceId, pairSupersededResponse());
      const mobileEd25519PublicKey = body.ed25519PublicKey;
      const response = new Promise<Response>((resolve) => {
        const entry: PendingPair = {
          pairComplete,
          mobileEd25519PublicKey,
          hostX25519PublicKey: session.hostX25519PublicKey,
          hostName: hostDevice.name,
          resolve,
          timer: setTimeout(() => {
            if (this.pendingPairs.get(hostDeviceId) === entry) {
              this.settlePendingPair(hostDeviceId, jsonResponse({ error: 'Host did not respond' }, 504));
            }
          }, PAIR_CONFIRM_TIMEOUT_MS),
        };
        this.pendingPairs.set(hostDeviceId, entry);
      });

      // Host not connected yet: handleWsAuth delivers it from pendingPairs.
      this.notifyDevice(hostDeviceId, pairComplete);
      return response;
    }

    // Legacy host: commit now, before the host has checked pairMac.
    const committed = this.commitPairing(
      session.hostDeviceId,
      hostDevice.name,
      body.deviceId,
      body.ed25519PublicKey,
      mobileName
    );
    if (!committed) {
      return mobileConflictResponse();
    }

    // Relay mobile's X25519 key to ALL host WebSocket connections.
    // The host may have multiple connections (background agent + pair CLI).
    // After DO hibernation, the connections map only stores one per device,
    // so we iterate all WebSockets directly to ensure the pair CLI receives it.
    const delivered = this.notifyDevice(session.hostDeviceId, pairComplete);

    // Host offline — persist the pair_complete for delivery on its next WS auth.
    // ponytail: no TTL cleanup — at most one row per host, consumed on next auth;
    // add a purge to the alarm sweep if orphaned rows ever matter.
    if (delivered === 0) {
      this.sql.exec(
        'INSERT OR REPLACE INTO pending_pair_complete (host_device_id, mobile_device_id, mobile_x25519_public_key, mobile_name, created_at, mobile_pair_mac) VALUES (?, ?, ?, ?, ?, ?)',
        session.hostDeviceId,
        body.deviceId,
        body.x25519PublicKey,
        mobileName ?? null,
        Date.now(),
        pairMac ?? null
      );
    }

    return pairCompleteResponse(session.hostDeviceId, session.hostX25519PublicKey, hostDevice.name);
  }

  /**
   * Whether the mobile can't be registered: its ID belongs to a non-mobile
   * device, or its Ed25519 key is already registered to a different device
   * (devices.ed25519_public_key is UNIQUE).
   */
  private hasMobileConflict(mobileDeviceId: string, mobileEd25519PublicKey: string): boolean {
    const existing = this.getDevice(mobileDeviceId);
    if (existing && existing.deviceType !== 'mobile') return true;
    const keyOwners = this.sql
      .exec('SELECT 1 FROM devices WHERE ed25519_public_key = ? AND id != ?', mobileEd25519PublicKey, mobileDeviceId)
      .toArray();
    return keyOwners.length > 0;
  }

  /**
   * Replace any existing pairing for the host, register the mobile and create
   * the pairing in one transaction. Validates first and returns false on a
   * conflict without touching the old pairing; returns true once committed.
   * A throw rolls back, leaving the old pairing intact. The replaced mobile is
   * told only after the commit succeeds.
   */
  private commitPairing(
    hostDeviceId: string,
    hostName: string | null,
    mobileDeviceId: string,
    mobileEd25519PublicKey: string,
    mobileName: string | undefined
  ): boolean {
    if (this.hasMobileConflict(mobileDeviceId, mobileEd25519PublicKey)) return false;

    const existingMobileId = this.getPairedMobile(hostDeviceId);
    this.state.storage.transactionSync(() => {
      // Remove the old pairing (also cleans up an orphaned old mobile device)
      if (existingMobileId) this.removePairing(hostDeviceId);
      // Validated above, so this registers (or refreshes) a mobile device
      this.registerDevice(mobileDeviceId, mobileEd25519PublicKey, 'mobile', mobileName);
      this.createPairing(hostDeviceId, mobileDeviceId);
    });

    // A different mobile was replaced; the same mobile re-pairing isn't told.
    if (existingMobileId && existingMobileId !== mobileDeviceId) {
      this.notifyDevice(existingMobileId, {
        type: 'device_unpaired',
        reason: 'replaced_by_new_pairing',
        hostDeviceId,
        hostName: hostName ?? undefined,
      });
    }
    return true;
  }

  /**
   * Answer the /pair/complete request held for this host, if any, and drop it
   * [SB-1348]. Every way a held request ends goes through here.
   */
  private settlePendingPair(hostDeviceId: string, response: Response): void {
    const entry = this.pendingPairs.get(hostDeviceId);
    if (!entry) return;
    this.pendingPairs.delete(hostDeviceId);
    clearTimeout(entry.timer);
    entry.resolve(response);
  }

  /**
   * pair_accept / pair_reject from a confirming host [SB-1348]. Settles the held
   * /pair/complete request; on accept, commits the pairing and answers the host
   * with pair_result so it stores the shared secret only once the server has.
   * pair_reject gets no reply.
   */
  private handlePairDecision(
    ws: WebSocket,
    attachment: WsAttachment,
    data: PairAcceptMessage | PairRejectMessage
  ): void {
    const mobileDeviceId = typeof data.mobileDeviceId === 'string' ? data.mobileDeviceId : '';
    const isAccept = data.type === 'pair_accept';
    const result = (ok: boolean): void => {
      if (!isAccept) return;
      const msg: PairResultMessage = { type: 'pair_result', mobileDeviceId, ok };
      wsSend(ws, msg);
    };

    const hostDeviceId = attachment.deviceId;
    const entry = attachment.deviceType === 'host' ? this.pendingPairs.get(hostDeviceId) : undefined;
    if (!entry || entry.pairComplete.mobileDeviceId !== mobileDeviceId) {
      result(false);
      return;
    }

    if (!isAccept) {
      this.settlePendingPair(hostDeviceId, jsonResponse({ error: 'Host rejected the pairing' }, 403));
      return;
    }

    let committed: boolean;
    try {
      committed = this.commitPairing(
        hostDeviceId,
        entry.hostName,
        mobileDeviceId,
        entry.mobileEd25519PublicKey,
        entry.pairComplete.mobileName
      );
    } catch (err) {
      console.error(`[pair] Commit failed for host ${hostDeviceId}:`, err);
      this.settlePendingPair(hostDeviceId, jsonResponse({ error: 'Pairing failed' }, 500));
      result(false);
      return;
    }

    if (!committed) {
      this.settlePendingPair(hostDeviceId, mobileConflictResponse());
      result(false);
      return;
    }
    this.settlePendingPair(hostDeviceId, pairCompleteResponse(hostDeviceId, entry.hostX25519PublicKey, entry.hostName));
    result(true);
  }

  // --- Token exchange endpoint [T1.6] ---

  /**
   * POST /token
   * Device exchanges a signed challenge for a JWT.
   * Body: { deviceId, nonce, signature }
   * signature = Ed25519.sign(privateKey, deviceId + "|" + nonce)
   * Returns: { token }
   */
  private async handleTokenExchange(request: Request): Promise<Response> {
    let body: { deviceId?: string; nonce?: string; signature?: string };
    try {
      body = await request.json() as typeof body;
    } catch {
      return jsonResponse({ error: 'Invalid JSON' }, 400);
    }

    if (!body.deviceId || !body.nonce || !body.signature) {
      return jsonResponse(
        { error: 'Missing required fields: deviceId, nonce, signature' },
        400
      );
    }

    // Consume the nonce challenge first (single-use, validates expiry and device binding)
    if (!this.consumeChallenge(body.nonce, body.deviceId)) {
      return jsonResponse({ error: 'Invalid or expired challenge' }, 401);
    }

    // Look up the device to get its public key
    const device = this.getDevice(body.deviceId);
    if (!device) {
      return jsonResponse({ error: 'Unknown device' }, 401);
    }

    // Verify the signature: sign(privateKey, deviceId + "|" + nonce)
    const message = new TextEncoder().encode(body.deviceId + '|' + body.nonce);

    let valid: boolean;
    try {
      const publicKeyBytes = base64ToBytes(device.ed25519PublicKey);
      const signatureBytes = base64ToBytes(body.signature);
      valid = await verifyEd25519Signature(publicKeyBytes, message, signatureBytes);
    } catch {
      return jsonResponse({ error: 'Invalid signature format' }, 401);
    }

    if (!valid) {
      return jsonResponse({ error: 'Signature verification failed' }, 401);
    }

    // Issue JWT
    const token = await createJWT(
      device.id,
      device.deviceType,
      this.env.JWT_SECRET
    );

    return jsonResponse({ token });
  }

  // --- TURN credentials [T3.5] ---

  /**
   * DELETE /pairing
   * Removes the pairing for the authenticated host device and notifies
   * the paired mobile via device_unpaired. Called by `pmux unpair`.
   */
  private handleDeletePairing(request: Request): Response {
    const hostDeviceId = request.headers.get('X-Device-Id') ?? '';
    if (!hostDeviceId) {
      return jsonResponse({ error: 'Missing device ID' }, 400);
    }
    if (request.headers.get('X-Device-Type') !== 'host') {
      return jsonResponse({ error: 'Only a host can remove a pairing' }, 403);
    }

    // A held confirming-path request must not commit after the unpair
    this.settlePendingPair(hostDeviceId, pairCancelledResponse());

    // Get host device name before removing pairing (for the notification)
    const hostDevice = this.getDevice(hostDeviceId);
    const hostName = hostDevice?.name ?? undefined;

    // Notify the paired mobile before removing the pairing record
    this.notifyPairedMobile(hostDeviceId, {
      type: 'device_unpaired',
      reason: 'host_unpaired',
      hostDeviceId,
      hostName,
    });

    // Remove pairing (also cleans up orphaned mobile device)
    const removedMobileId = this.removePairing(hostDeviceId);

    return jsonResponse({ removed: removedMobileId !== null });
  }

  /**
   * DELETE /device
   * Removes the host device record, its pairing, and notifies the paired mobile.
   * Called by `pmux uninstall` when a host completely removes Pocketmux.
   */
  private handleDeleteDevice(request: Request): Response {
    const hostDeviceId = request.headers.get('X-Device-Id') ?? '';
    if (!hostDeviceId) {
      return jsonResponse({ error: 'Missing device ID' }, 400);
    }
    if (request.headers.get('X-Device-Type') !== 'host') {
      return jsonResponse({ error: 'Only a host can remove a device' }, 403);
    }

    // A held confirming-path request must not commit after the uninstall
    this.settlePendingPair(hostDeviceId, pairCancelledResponse());

    // Get host device name before removal (for the notification)
    const hostDevice = this.getDevice(hostDeviceId);
    const hostName = hostDevice?.name ?? undefined;

    // Notify the paired mobile before removing records
    this.notifyPairedMobile(hostDeviceId, {
      type: 'device_unpaired',
      reason: 'host_uninstalled',
      hostDeviceId,
      hostName,
    });

    // Remove pairing + host device
    const { removedDevice } = this.removeDeviceAndPairing(hostDeviceId);

    return jsonResponse({ removed: removedDevice });
  }

  /**
   * GET /turn/credentials
   * Returns TURN credentials from Cloudflare Realtime API.
   * Rate limited per device ID. Routed through DO for rate limit storage access.
   * Cached for TURN_REFRESH_AGE_MS (in memory + DO KV storage); concurrent refetches
   * share one request, and a failed refetch falls back to cached credentials up to
   * TURN_MAX_SERVE_AGE_MS old.
   */
  private async handleTurnCredentials(deviceId: string, deviceType: string | null): Promise<Response> {
    if (!this.isPairedDevice(deviceId, deviceType)) {
      return jsonResponse({ error: 'Device not paired' }, 403);
    }
    if (!this.turnCache) {
      const stored = await this.state.storage.get<TurnCacheEntry>(TURN_CACHE_KEY);
      this.turnCache ??= stored ?? null;
    }
    if (this.turnCache && Date.now() - this.turnCache.fetchedAt < TURN_REFRESH_AGE_MS) {
      return jsonResponse(this.turnCache.creds);
    }

    try {
      this.turnFetch ??= this.refreshTurnCredentials();
      return jsonResponse(await this.turnFetch);
    } catch (err) {
      if (this.turnCache && Date.now() - this.turnCache.fetchedAt < TURN_MAX_SERVE_AGE_MS) {
        console.warn('[turn] Refresh failed, serving cached credentials:', err);
        return jsonResponse(this.turnCache.creds);
      }
      console.error('[turn] Failed to generate credentials:', err);
      return jsonResponse({ error: 'Failed to generate TURN credentials' }, 502);
    }
  }

  /** Fetch fresh TURN credentials and update the cache. Shared by concurrent callers via turnFetch. */
  private async refreshTurnCredentials(): Promise<TurnCredentials> {
    try {
      const creds = await generateTurnCredentials(this.env);
      this.turnCache = { creds, fetchedAt: Date.now() };
      await this.state.storage.put(TURN_CACHE_KEY, this.turnCache);
      return creds;
    } finally {
      this.turnFetch = null;
    }
  }
}

// --- Helpers ---

function rowToDevice(row: Record<string, SqlStorageValue>): StoredDevice {
  return {
    id: row['id'] as string,
    ed25519PublicKey: row['ed25519_public_key'] as string,
    deviceType: row['device_type'] as DeviceType,
    name: row['name'] as string | null,
    createdAt: row['created_at'] as number,
  };
}

function rowToPairing(row: Record<string, SqlStorageValue>): StoredPairing {
  return {
    hostDeviceId: row['host_device_id'] as string,
    mobileDeviceId: row['mobile_device_id'] as string,
    createdAt: row['created_at'] as number,
  };
}

function rowToPairingSession(row: Record<string, SqlStorageValue>): PairingSession {
  return {
    hostDeviceId: row['host_device_id'] as string,
    hostX25519PublicKey: row['host_x25519_public_key'] as string,
    hostEdPublicKey: row['host_ed_public_key'] as string,
    expiresAt: row['expires_at'] as number,
    pairConfirm: row['pair_confirm'] === 1,
  };
}

function rowToCount(row: Record<string, SqlStorageValue>): number {
  return row['count'] as number;
}

function generatePairingCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 chars, no 0/O/1/I
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars[bytes[i]! % chars.length];
  }
  return code;
}

function base64ToBytes(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function isBase64OfLength(value: unknown, length: number): boolean {
  if (typeof value !== 'string') return false;
  try {
    return atob(value).length === length;
  } catch {
    return false;
  }
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Successful /pair/complete body. */
function pairCompleteResponse(hostDeviceId: string, hostX25519PublicKey: string, hostName: string | null): Response {
  return jsonResponse({ hostX25519PublicKey, hostDeviceId, hostName: hostName ?? '' });
}

/**
 * 409 for a /pair/complete mobile that can't be registered. One message for
 * every conflict kind, so the caller learns nothing about stored devices.
 */
function mobileConflictResponse(): Response {
  return jsonResponse({ error: 'Device conflict: device cannot be registered' }, 409);
}

/** 409 for a held /pair/complete replaced by a newer pairing attempt for the host. */
function pairSupersededResponse(): Response {
  return jsonResponse({ error: 'Pairing superseded by a newer request' }, 409);
}

/** 409 for a held /pair/complete whose host unpaired or uninstalled meanwhile. */
function pairCancelledResponse(): Response {
  return jsonResponse({ error: 'Pairing cancelled by the host' }, 409);
}

/** Send a JSON message over a WebSocket. */
function wsSend(ws: WebSocket, data: unknown): void {
  ws.send(JSON.stringify(data));
}

/**
 * Whether a socket can still be used: not closed by the DO and not CLOSING or
 * CLOSED (readyState 2/3). An unknown readyState counts as live so a runtime
 * quirk can never take every socket offline [SB-1393].
 */
function isLive(ws: WebSocket, att: WsAttachment | null): boolean {
  return !att?.closed && !(ws.readyState >= 2);
}
