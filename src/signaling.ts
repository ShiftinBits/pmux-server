/**
 * SignalingDO — Durable Object for WebSocket signaling, presence, and storage.
 *
 * Uses built-in SQLite for persistent device/pairing storage.
 * Uses in-memory maps for ephemeral state (pairing codes, WebSocket sessions).
 * Uses the WebSocket Hibernation API for cost-efficient persistent connections.
 * Uses DO key-value storage for rate limit counters.
 */

import type { Env } from './worker';
import type { DeviceType, SignalingClientMessage, HostOnlineMessage } from '@pocketmux/shared';
import { verifyEd25519Signature, createJWT, verifyJWT } from './auth';
import { generateTurnCredentials } from './turn';
import {
  checkRateLimit,
  rateLimitResponse,
  MAX_WS_CONNECTIONS_PER_DEVICE,
  type RateLimitStorage,
} from './middleware/ratelimit';

/** Maximum WebSocket message length in characters (16K — generous for SDP/ICE signaling). */
const MAX_WS_MESSAGE_SIZE = 16_384;

// --- Types ---

export interface StoredDevice {
  id: string;
  publicKey: string;
  deviceType: DeviceType;
  name: string | null;
  createdAt: number;
}

export interface PairingSession {
  hostDeviceId: string;
  hostX25519PublicKey: string;
  hostEdPublicKey: string;
  expiresAt: number;
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
}

/** Interval (ms) between alarm-based cleanup sweeps. */
const ALARM_INTERVAL_MS = 60_000; // 60 seconds

/** Maximum idle time (ms) before a WebSocket is closed. */
const WS_IDLE_TIMEOUT_MS = 5 * 60_000; // 5 minutes

// --- Durable Object ---

export class SignalingDO implements DurableObject {
  private state: DurableObjectState;
  private env: Env;
  private initialized = false;

  // In-memory WebSocket cache indexed by deviceId (rebuilt after hibernation wake)
  private connections = new Map<string, WebSocket>();

  // In-memory WebSocket connection count per device ID (for abuse prevention)
  private wsConnectionCounts = new Map<string, number>();

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  private get sql(): SqlStorage {
    return this.state.storage.sql;
  }

  /** Access DO storage as a RateLimitStorage for the rate limiter. */
  private get rateLimitStorage(): RateLimitStorage {
    return this.state.storage as unknown as RateLimitStorage;
  }

  // --- Schema initialization ---

  private ensureSchema(): void {
    if (this.initialized) return;

    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        public_key TEXT NOT NULL UNIQUE,
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

    this.initialized = true;
  }

  // --- Device CRUD ---

  /**
   * Register a device. INSERT OR REPLACE — re-registering updates the record.
   * Returns the deviceId.
   */
  registerDevice(
    deviceId: string,
    publicKey: string,
    deviceType: DeviceType,
    name?: string
  ): { deviceId: string } {
    this.ensureSchema();
    const now = Math.floor(Date.now() / 1000);

    this.sql.exec(
      'INSERT OR REPLACE INTO devices (id, public_key, device_type, name, created_at) VALUES (?, ?, ?, ?, ?)',
      deviceId,
      publicKey,
      deviceType,
      name ?? null,
      now
    );

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
      'SELECT id, public_key, device_type, name, created_at FROM devices WHERE id = ?',
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
   * Create a pairing session. Returns a 6-character alphanumeric code.
   * Stored in SQLite so it survives DO hibernation.
   */
  createPairingSession(
    hostDeviceId: string,
    hostX25519PublicKey: string,
    hostEdPublicKey: string
  ): string {
    this.ensureSchema();
    // Clean up expired sessions
    this.cleanExpiredPairings();

    // Invalidate any existing sessions for this host (prevents multiple valid codes)
    this.sql.exec('DELETE FROM pairing_sessions WHERE host_device_id = ?', hostDeviceId);

    let code: string;
    do {
      code = generatePairingCode();
    } while (this.sql.exec('SELECT 1 FROM pairing_sessions WHERE code = ?', code).toArray().length > 0);

    this.sql.exec(
      'INSERT INTO pairing_sessions (code, host_device_id, host_x25519_public_key, host_ed_public_key, expires_at) VALUES (?, ?, ?, ?, ?)',
      code,
      hostDeviceId,
      hostX25519PublicKey,
      hostEdPublicKey,
      Date.now() + 5 * 60 * 1000
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
      'SELECT host_device_id, host_x25519_public_key, host_ed_public_key, expires_at FROM pairing_sessions WHERE code = ?',
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

  // --- WebSocket connection management ---

  /**
   * Find a WebSocket by deviceId. Checks in-memory cache first,
   * then scans hibernated WebSockets and rebuilds cache.
   */
  private findWebSocket(deviceId: string): WebSocket | undefined {
    const cached = this.connections.get(deviceId);
    if (cached) return cached;

    // After hibernation wake, the in-memory cache is empty — rebuild it.
    this.rebuildConnectionCache();
    return this.connections.get(deviceId);
  }

  /**
   * Rebuild the in-memory connections cache from hibernated WebSockets.
   * Called when the cache might be stale (e.g., after hibernation wake).
   */
  private rebuildConnectionCache(): void {
    if (!this.state.getWebSockets) return;
    this.wsConnectionCounts.clear();
    for (const ws of this.state.getWebSockets()) {
      const att = ws.deserializeAttachment() as WsAttachment | null;
      if (att?.authenticated && att.deviceId) {
        this.connections.set(att.deviceId, ws);
        const count = this.wsConnectionCounts.get(att.deviceId) ?? 0;
        this.wsConnectionCounts.set(att.deviceId, count + 1);
      }
    }
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
   * Send a message to ALL WebSocket connections for a specific device.
   * Iterates hibernated WebSockets directly (not the 1:1 connections map)
   * so that every connection receives the message — critical when a device
   * has multiple concurrent connections (e.g., background agent + pair CLI).
   */
  private notifyDevice(deviceId: string, message: unknown): void {
    if (!this.state.getWebSockets) return;
    for (const ws of this.state.getWebSockets()) {
      const att = ws.deserializeAttachment() as WsAttachment | null;
      if (att?.authenticated && att.deviceId === deviceId) {
        try {
          wsSend(ws, message);
        } catch {
          // WebSocket may have disconnected
        }
      }
    }
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

  // --- HTTP routing ---

  /** Allowed HTTP methods per path (excluding /ws which has no method restriction). */
  private static readonly ROUTE_METHODS: Record<string, string> = {
    '/pair/initiate': 'POST',
    '/pair/complete': 'POST',
    '/token': 'POST',
    '/turn/credentials': 'GET',
  };

  async fetch(request: Request): Promise<Response> {
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

      // Method matches — apply rate limiting and dispatch to handler
      switch (url.pathname) {
        case '/pair/initiate': {
          const rl = await checkRateLimit(this.rateLimitStorage, clientIp, '/pair/initiate');
          if (!rl.allowed) return rateLimitResponse(rl.retryAfter!);
          return this.handlePairInitiate(request);
        }
        case '/pair/complete': {
          const rl = await checkRateLimit(this.rateLimitStorage, clientIp, '/pair/complete');
          if (!rl.allowed) return rateLimitResponse(rl.retryAfter!);
          return this.handlePairComplete(request);
        }
        case '/token': {
          // Token uses IP as key since device ID comes from the request body (pre-auth)
          const rl = await checkRateLimit(this.rateLimitStorage, clientIp, '/token');
          if (!rl.allowed) return rateLimitResponse(rl.retryAfter!);
          return this.handleTokenExchange(request);
        }
        case '/turn/credentials': {
          const rl = await checkRateLimit(this.rateLimitStorage, deviceId || clientIp, '/turn/credentials');
          if (!rl.allowed) return rateLimitResponse(rl.retryAfter!);
          return this.handleTurnCredentials();
        }
      }
    }

    // /ws has no method restriction (upgrade check is inside the handler)
    if (url.pathname === '/ws') {
      const rl = await checkRateLimit(this.rateLimitStorage, clientIp, '/ws');
      if (!rl.allowed) return rateLimitResponse(rl.retryAfter!);
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
    if (typeof message !== 'string') return;

    if (message.length > MAX_WS_MESSAGE_SIZE) {
      wsSend(ws, { type: 'error', error: 'Message too large' });
      ws.close(1009, 'Message too large');
      return;
    }

    // Update lastMessageTime on every received message (for idle timeout tracking)
    this.touchWebSocket(ws);

    let data: SignalingClientMessage;
    try {
      data = JSON.parse(message) as SignalingClientMessage;
    } catch {
      wsSend(ws, { type: 'error', error: 'Invalid JSON' });
      return;
    }

    if (!data.type) {
      wsSend(ws, { type: 'error', error: 'Missing message type' });
      return;
    }

    // Auth must be handled before any other message type
    if (data.type === 'auth') {
      await this.handleWsAuth(ws, data.token);
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
        // Host heartbeat — acknowledged. DO stays awake due to message receipt.
        break;

      case 'connect_request':
        this.handleConnectRequest(ws, attachment, data.targetDeviceId);
        break;

      case 'sdp_offer':
      case 'sdp_answer':
      case 'ice_candidate':
      case 'connection_rejected':
        this.relaySignalingMessage(attachment, data);
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
    if (!attachment?.authenticated) return;

    // Only remove from cache if this WS is the one currently stored.
    // A device may have multiple concurrent WebSockets (e.g., mobile uses one
    // for presence on the host list and another for WebRTC signaling). If a
    // stale WS closes after a newer one registered, blindly deleting would
    // remove the newer WS's routing entry.
    if (this.connections.get(attachment.deviceId) === ws) {
      this.connections.delete(attachment.deviceId);
    }

    // Decrement WebSocket connection count
    this.decrementWsCount(attachment.deviceId);

    // If host disconnected, notify the paired mobile
    if (attachment.deviceType === 'host') {
      this.notifyPairedMobile(attachment.deviceId, {
        type: 'host_offline',
        deviceId: attachment.deviceId,
      });
    }
  }

  /**
   * Called by the runtime when a WebSocket encounters an error.
   */
  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    const attachment = ws.deserializeAttachment() as WsAttachment | null;
    console.error('[ws-error] deviceId=%s error=%o', attachment?.deviceId, error);
    if (attachment?.authenticated) {
      if (this.connections.get(attachment.deviceId) === ws) {
        this.connections.delete(attachment.deviceId);
      }
      this.decrementWsCount(attachment.deviceId);
      // Notify the paired mobile if host errored out
      if (attachment.deviceType === 'host') {
        this.notifyPairedMobile(attachment.deviceId, {
          type: 'host_offline',
          deviceId: attachment.deviceId,
        });
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

  // --- DO alarm handler (idle WS cleanup + expired pairing purge) ---

  /**
   * Called by the runtime on the scheduled alarm.
   * Closes idle WebSockets and purges expired pairing codes.
   */
  async alarm(): Promise<void> {
    const now = Date.now();
    let activeCount = 0;

    if (this.state.getWebSockets) {
      for (const ws of this.state.getWebSockets()) {
        const att = ws.deserializeAttachment() as WsAttachment | null;
        if (!att) continue;

        const lastMsg = att.lastMessageTime ?? 0;
        if (lastMsg > 0 && now - lastMsg > WS_IDLE_TIMEOUT_MS) {
          // Close idle WebSocket
          try {
            ws.close(1000, 'idle timeout');
          } catch {
            // May already be closed
          }
          if (att.authenticated && att.deviceId) {
            if (this.connections.get(att.deviceId) === ws) {
              this.connections.delete(att.deviceId);
            }
            this.decrementWsCount(att.deviceId);
          }
        } else {
          activeCount++;
        }
      }
    }

    // Purge expired pairing codes
    this.cleanExpiredPairings();

    // Re-schedule alarm if there are still active connections
    if (activeCount > 0) {
      await this.state.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
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

  // --- WebSocket message handlers ---

  /**
   * Handle auth message: verify JWT and associate WebSocket with device.
   * Enforces per-device WebSocket connection limit.
   */
  private async handleWsAuth(ws: WebSocket, token: string): Promise<void> {
    try {
      const payload = await verifyJWT(token, this.env.JWT_SECRET);

      // Check WebSocket connection limit per device
      const currentCount = this.wsConnectionCounts.get(payload.deviceId) ?? 0;
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

      // Update in-memory cache and connection count
      this.connections.set(payload.deviceId, ws);
      this.incrementWsCount(payload.deviceId);

      // If host, notify the paired mobile of host_online (with name from DB)
      if (payload.deviceType === 'host') {
        const hostDevice = this.getDevice(payload.deviceId);
        const hostOnlineMsg: HostOnlineMessage = {
          type: 'host_online',
          deviceId: payload.deviceId,
        };
        if (hostDevice?.name) {
          hostOnlineMsg.name = hostDevice.name;
        }
        const pairedMobileId = this.getPairedMobile(payload.deviceId);
        if (pairedMobileId) {
          this.notifyDevice(pairedMobileId, hostOnlineMsg);
        }
      }

      // If mobile, send current presence snapshot for all paired hosts that are connected.
      if (payload.deviceType === 'mobile') {
        const pairedHosts = this.getHostsForMobile(payload.deviceId);
        for (const hostDeviceId of pairedHosts) {
          const hostWs = this.findWebSocket(hostDeviceId);
          if (hostWs) {
            const device = this.getDevice(hostDeviceId);
            const msg: HostOnlineMessage = { type: 'host_online', deviceId: hostDeviceId };
            if (device?.name) {
              msg.name = device.name;
            }
            wsSend(ws, msg);
          }
        }
      }

      wsSend(ws, { type: 'auth', status: 'ok' });
    } catch {
      wsSend(ws, { type: 'error', error: 'Authentication failed' });
      ws.close(4001, 'Authentication failed');
    }
  }

  /**
   * Handle connect_request: mobile wants to connect to a host.
   * Relays the request to the target host with the mobile's deviceId.
   * Only allows signaling between paired devices.
   */
  private handleConnectRequest(ws: WebSocket, sender: WsAttachment, targetDeviceId: string): void {
    // Check pairing FIRST (before WS lookup) — don't reveal device existence to unpaired callers
    const hostId = sender.deviceType === 'host' ? sender.deviceId : targetDeviceId;
    const mobileId = sender.deviceType === 'mobile' ? sender.deviceId : targetDeviceId;
    if (!this.isPaired(hostId, mobileId)) {
      wsSend(ws, { type: 'connection_rejected', reason: 'not_paired' });
      return;
    }

    // Paired — check if target is online
    const targetWs = this.findWebSocket(targetDeviceId);
    if (!targetWs) {
      // Paired but offline → send host_offline so mobile can schedule reconnect
      wsSend(ws, { type: 'host_offline', deviceId: targetDeviceId });
      return;
    }

    // Relay to target with sender's deviceId as the origin
    wsSend(targetWs, {
      type: 'connect_request',
      targetDeviceId: sender.deviceId,
    });
  }

  /**
   * Relay SDP/ICE signaling messages between devices.
   * Swaps targetDeviceId to the sender's deviceId so the recipient knows the origin.
   * Only allows signaling between paired devices.
   */
  private relaySignalingMessage(
    sender: WsAttachment,
    data: { type: string; targetDeviceId: string; [key: string]: unknown }
  ): void {
    const targetWs = this.findWebSocket(data.targetDeviceId);
    if (!targetWs) return;

    // Verify sender and target are paired (prevents cross-pairing signaling)
    const hostId = sender.deviceType === 'host' ? sender.deviceId : data.targetDeviceId;
    const mobileId = sender.deviceType === 'mobile' ? sender.deviceId : data.targetDeviceId;
    if (!this.isPaired(hostId, mobileId)) return;

    // Relay only known fields — never spread untrusted data
    wsSend(targetWs, {
      type: data.type,
      targetDeviceId: sender.deviceId,
      ...(data.sdp !== undefined && { sdp: data.sdp }),
      ...(data.candidate !== undefined && { candidate: data.candidate }),
      ...('reason' in data && data.reason !== undefined && { reason: data.reason }),
    });
  }

  // --- Pairing endpoints [T1.5] ---

  /**
   * POST /pair/initiate
   * Host calls this to start pairing. Creates a pairing session.
   * Body: { deviceId, publicKey, x25519PublicKey, timestamp, signature, name? }
   * Returns: { pairingCode }
   */
  private async handlePairInitiate(request: Request): Promise<Response> {
    let body: {
      deviceId?: string;
      publicKey?: string;
      x25519PublicKey?: string;
      timestamp?: string;
      signature?: string;
      name?: string;
    };
    try {
      body = await request.json() as typeof body;
    } catch {
      return jsonResponse({ error: 'Invalid JSON' }, 400);
    }

    if (!body.deviceId || !body.publicKey || !body.x25519PublicKey || !body.timestamp || !body.signature) {
      return jsonResponse(
        { error: 'Missing required fields: deviceId, publicKey, x25519PublicKey, timestamp, signature' },
        400
      );
    }

    // Validate name if provided
    if (body.name !== undefined && (typeof body.name !== 'string' || body.name.length > 64)) {
      return jsonResponse({ error: 'Name must be a string of 64 characters or fewer' }, 400);
    }

    // Validate timestamp is within 5-minute window
    const ts = parseInt(body.timestamp, 10);
    const now = Math.floor(Date.now() / 1000);
    if (isNaN(ts) || Math.abs(now - ts) > 300) {
      return jsonResponse({ error: 'Timestamp out of range' }, 401);
    }

    // Verify signature against stored key (if device exists) or request body key
    const existing = this.getDevice(body.deviceId);
    const verifyKey = existing ? existing.publicKey : body.publicKey;
    const message = new TextEncoder().encode(body.deviceId + body.timestamp);
    const publicKeyBytes = base64ToBytes(verifyKey);
    const signatureBytes = base64ToBytes(body.signature);

    let valid: boolean;
    try {
      valid = await verifyEd25519Signature(publicKeyBytes, message, signatureBytes);
    } catch {
      return jsonResponse({ error: 'Invalid signature format' }, 401);
    }
    if (!valid) {
      return jsonResponse({ error: 'Signature verification failed' }, 401);
    }

    // Register the host device if not already registered, or update name
    if (!existing) {
      this.registerDevice(body.deviceId, body.publicKey, 'host', body.name);
    } else if (body.name !== undefined) {
      // Signature already verified against stored key, safe to update name
      this.updateDeviceName(body.deviceId, body.name);
    }

    const pairingCode = this.createPairingSession(
      body.deviceId,
      body.x25519PublicKey,
      body.publicKey
    );

    return jsonResponse({ pairingCode });
  }

  /**
   * POST /pair/complete
   * Mobile calls this with the pairing code to complete pairing.
   * Body: { pairingCode, deviceId, publicKey, x25519PublicKey }
   * Returns: { hostX25519PublicKey, hostDeviceId, hostName? }
   */
  private async handlePairComplete(request: Request): Promise<Response> {
    let body: {
      pairingCode?: string;
      deviceId?: string;
      publicKey?: string;
      x25519PublicKey?: string;
    };
    try {
      body = await request.json() as typeof body;
    } catch {
      return jsonResponse({ error: 'Invalid JSON' }, 400);
    }

    if (!body.pairingCode || !body.deviceId || !body.publicKey || !body.x25519PublicKey) {
      return jsonResponse(
        { error: 'Missing required fields: pairingCode, deviceId, publicKey, x25519PublicKey' },
        400
      );
    }

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

    // Check if this host already has a paired mobile — if so, replace it
    const existingMobileId = this.getPairedMobile(session.hostDeviceId);
    if (existingMobileId && existingMobileId !== body.deviceId) {
      // Notify the old mobile that it has been unpaired
      this.notifyDevice(existingMobileId, {
        type: 'device_unpaired',
        reason: 'replaced_by_new_pairing',
        hostDeviceId: session.hostDeviceId,
        hostName: hostDevice.name ?? undefined,
      });
      // Remove the old pairing (also cleans up orphaned mobile device)
      this.removePairing(session.hostDeviceId);
    } else if (existingMobileId) {
      // Same mobile re-pairing — just remove old pairing, no notification needed
      this.removePairing(session.hostDeviceId);
    }

    // Register the mobile device
    this.registerDevice(
      body.deviceId,
      body.publicKey,
      'mobile'
    );

    // Create the pairing
    this.createPairing(session.hostDeviceId, body.deviceId);

    // Relay mobile's X25519 key to ALL host WebSocket connections.
    // The host may have multiple connections (background agent + pair CLI).
    // After DO hibernation, the connections map only stores one per device,
    // so we iterate all WebSockets directly to ensure the pair CLI receives it.
    this.notifyDevice(session.hostDeviceId, {
      type: 'pair_complete',
      mobileDeviceId: body.deviceId,
      mobileX25519PublicKey: body.x25519PublicKey,
    });

    return jsonResponse({
      hostX25519PublicKey: session.hostX25519PublicKey,
      hostDeviceId: session.hostDeviceId,
      hostName: hostDevice.name ?? '',
    });
  }

  // --- Token exchange endpoint [T1.6] ---

  /**
   * POST /token
   * Device exchanges a signed challenge for a JWT.
   * Body: { deviceId, timestamp, signature }
   * signature = Ed25519.sign(privateKey, deviceId + timestamp)
   * Returns: { token }
   */
  private async handleTokenExchange(request: Request): Promise<Response> {
    let body: { deviceId?: string; timestamp?: string; signature?: string };
    try {
      body = await request.json() as typeof body;
    } catch {
      return jsonResponse({ error: 'Invalid JSON' }, 400);
    }

    if (!body.deviceId || !body.timestamp || !body.signature) {
      return jsonResponse(
        { error: 'Missing required fields: deviceId, timestamp, signature' },
        400
      );
    }

    // Validate timestamp is recent (within 5 minutes) to prevent replay attacks
    const ts = parseInt(body.timestamp, 10);
    const now = Math.floor(Date.now() / 1000);
    if (isNaN(ts) || Math.abs(now - ts) > 300) {
      return jsonResponse({ error: 'Timestamp out of range' }, 401);
    }

    // Look up the device to get its public key
    const device = this.getDevice(body.deviceId);
    if (!device) {
      return jsonResponse({ error: 'Unknown device' }, 401);
    }

    // Verify the signature: sign(privateKey, deviceId + timestamp)
    const message = new TextEncoder().encode(body.deviceId + body.timestamp);
    const publicKeyBytes = base64ToBytes(device.publicKey);
    const signatureBytes = base64ToBytes(body.signature);

    let valid: boolean;
    try {
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
   * GET /turn/credentials
   * Returns TURN credentials from Cloudflare Realtime API.
   * Rate limited per device ID. Routed through DO for rate limit storage access.
   */
  private async handleTurnCredentials(): Promise<Response> {
    try {
      const credentials = await generateTurnCredentials(this.env);
      return jsonResponse(credentials);
    } catch (err) {
      console.error('[turn] Failed to generate credentials:', err);
      return jsonResponse({ error: 'Failed to generate TURN credentials' }, 502);
    }
  }
}

// --- Helpers ---

function rowToDevice(row: Record<string, SqlStorageValue>): StoredDevice {
  return {
    id: row['id'] as string,
    publicKey: row['public_key'] as string,
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

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Send a JSON message over a WebSocket. */
function wsSend(ws: WebSocket, data: unknown): void {
  ws.send(JSON.stringify(data));
}
