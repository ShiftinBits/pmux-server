/**
 * SignalingDO — Durable Object for WebSocket signaling, presence, and storage.
 *
 * Uses built-in SQLite for persistent device/user storage.
 * Uses in-memory maps for ephemeral state (pairing codes, WebSocket sessions).
 * Uses the WebSocket Hibernation API for cost-efficient persistent connections.
 * Uses DO key-value storage for rate limit counters.
 */

import type { Env } from './worker';
import type { DeviceType, SignalingClientMessage } from '@pocketmux/shared';
import { verifyEd25519Signature, createJWT, verifyJWT } from './auth';
import { generateTurnCredentials } from './turn';
import {
  checkRateLimit,
  rateLimitResponse,
  ENDPOINT_LIMITS,
  MAX_DEVICES_PER_USER,
  MAX_WS_CONNECTIONS_PER_DEVICE,
  type RateLimitStorage,
} from './middleware/ratelimit';

// --- Types ---

export interface StoredDevice {
  id: string;
  userId: string;
  publicKey: string;
  deviceType: DeviceType;
  name: string | null;
  createdAt: number;
}

export interface StoredUser {
  id: string;
  createdAt: number;
}

export interface PairingSession {
  agentDeviceId: string;
  agentX25519PublicKey: string;
  agentEdPublicKey: string;
  expiresAt: number;
}

/** Per-WebSocket metadata, survives DO hibernation via serializeAttachment. */
export interface WsAttachment {
  deviceId: string;
  userId: string;
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

  // Ephemeral pairing state (in-memory, not SQLite)
  private pairingSessions = new Map<string, PairingSession>();

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
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL
      )
    `);

    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id),
        public_key TEXT NOT NULL UNIQUE,
        device_type TEXT NOT NULL CHECK(device_type IN ('agent', 'mobile')),
        name TEXT,
        created_at INTEGER NOT NULL
      )
    `);

    this.sql.exec(
      'CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id)'
    );

    this.initialized = true;
  }

  // --- Device CRUD ---

  /**
   * Register a new device. If no userId is provided, creates a new user.
   * Returns the userId and deviceId.
   */
  registerDevice(
    deviceId: string,
    publicKey: string,
    deviceType: DeviceType,
    userId?: string,
    name?: string
  ): { userId: string; deviceId: string } {
    this.ensureSchema();
    const now = Math.floor(Date.now() / 1000);

    if (!userId) {
      // First device — create a new user
      userId = crypto.randomUUID();
      this.sql.exec(
        'INSERT INTO users (id, created_at) VALUES (?, ?)',
        userId,
        now
      );
    }

    this.sql.exec(
      'INSERT OR REPLACE INTO devices (id, user_id, public_key, device_type, name, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      deviceId,
      userId,
      publicKey,
      deviceType,
      name ?? null,
      now
    );

    return { userId, deviceId };
  }

  /**
   * Get all devices belonging to a user.
   */
  getDevicesByUser(userId: string): StoredDevice[] {
    this.ensureSchema();
    const rows = this.sql.exec(
      'SELECT id, user_id, public_key, device_type, name, created_at FROM devices WHERE user_id = ?',
      userId
    );

    return [...rows].map(rowToDevice);
  }

  /**
   * Count devices belonging to a user.
   */
  countDevicesByUser(userId: string): number {
    this.ensureSchema();
    const rows = this.sql.exec(
      'SELECT COUNT(*) as count FROM devices WHERE user_id = ?',
      userId
    );
    const result = [...rows][0];
    return (result?.['count'] as number) ?? 0;
  }

  /**
   * Get a single device by ID.
   */
  getDevice(deviceId: string): StoredDevice | null {
    this.ensureSchema();
    const rows = this.sql.exec(
      'SELECT id, user_id, public_key, device_type, name, created_at FROM devices WHERE id = ?',
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
    const count = [...before][0]?.['count'] as number;
    if (count === 0) return false;

    this.sql.exec('DELETE FROM devices WHERE id = ?', deviceId);
    return true;
  }

  // --- Pairing session management ---

  /**
   * Create a pairing session. Returns a 6-character alphanumeric code.
   */
  createPairingSession(
    agentDeviceId: string,
    agentX25519PublicKey: string,
    agentEdPublicKey: string
  ): string {
    // Clean up expired sessions
    this.cleanExpiredPairings();

    let code: string;
    do {
      code = generatePairingCode();
    } while (this.pairingSessions.has(code));
    this.pairingSessions.set(code, {
      agentDeviceId,
      agentX25519PublicKey,
      agentEdPublicKey,
      expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
    });

    return code;
  }

  /**
   * Consume a pairing session by code. Returns the session and removes it (single-use).
   */
  consumePairingSession(code: string): PairingSession | null {
    this.cleanExpiredPairings();

    const session = this.pairingSessions.get(code);
    if (!session) return null;

    this.pairingSessions.delete(code);
    return session;
  }

  private cleanExpiredPairings(): void {
    const now = Date.now();
    for (const [code, session] of this.pairingSessions) {
      if (session.expiresAt <= now) {
        this.pairingSessions.delete(code);
      }
    }
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
    for (const ws of this.state.getWebSockets()) {
      const att = ws.deserializeAttachment() as WsAttachment | null;
      if (att?.authenticated && att.deviceId) {
        this.connections.set(att.deviceId, ws);
      }
    }
  }

  /**
   * Send a message to all connected mobile devices belonging to a user.
   */
  private notifyMobileDevices(userId: string, message: unknown, excludeDeviceId?: string): void {
    // Always rebuild cache to ensure no WebSockets are missed after hibernation wake
    this.rebuildConnectionCache();

    for (const [, ws] of this.connections) {
      const att = ws.deserializeAttachment() as WsAttachment | null;
      if (
        att?.authenticated &&
        att.userId === userId &&
        att.deviceType === 'mobile' &&
        att.deviceId !== excludeDeviceId
      ) {
        wsSend(ws, message);
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

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const clientIp = request.headers.get('X-Client-IP') ?? '127.0.0.1';
    const deviceId = request.headers.get('X-Device-Id') ?? '';

    // Route to specific handlers based on path, with rate limiting
    if (url.pathname === '/pair/initiate' && request.method === 'POST') {
      const rl = await checkRateLimit(this.rateLimitStorage, clientIp, '/pair/initiate');
      if (!rl.allowed) return rateLimitResponse(rl.retryAfter!);
      return this.handlePairInitiate(request);
    }
    if (url.pathname === '/pair/complete' && request.method === 'POST') {
      const rl = await checkRateLimit(this.rateLimitStorage, clientIp, '/pair/complete');
      if (!rl.allowed) return rateLimitResponse(rl.retryAfter!);
      return this.handlePairComplete(request);
    }
    if (url.pathname === '/token' && request.method === 'POST') {
      // Token uses IP as key since device ID comes from the request body (pre-auth)
      const rl = await checkRateLimit(this.rateLimitStorage, clientIp, '/token');
      if (!rl.allowed) return rateLimitResponse(rl.retryAfter!);
      return this.handleTokenExchange(request);
    }
    if (url.pathname === '/turn/credentials' && request.method === 'GET') {
      const rl = await checkRateLimit(this.rateLimitStorage, deviceId || clientIp, '/turn/credentials');
      if (!rl.allowed) return rateLimitResponse(rl.retryAfter!);
      return this.handleTurnCredentials();
    }
    if (url.pathname === '/ws') {
      const rl = await checkRateLimit(this.rateLimitStorage, clientIp, '/ws');
      if (!rl.allowed) return rateLimitResponse(rl.retryAfter!);
      return this.handleWebSocketUpgrade(request);
    }

    return new Response('Not Found', { status: 404 });
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
        // Agent heartbeat — acknowledged. DO stays awake due to message receipt.
        break;

      case 'connect_request':
        this.handleConnectRequest(ws, attachment, data.targetDeviceId);
        break;

      case 'sdp_offer':
      case 'sdp_answer':
      case 'ice_candidate':
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

    // Remove from in-memory cache
    this.connections.delete(attachment.deviceId);

    // Decrement WebSocket connection count
    this.decrementWsCount(attachment.deviceId);

    // If agent disconnected, notify mobile clients
    if (attachment.deviceType === 'agent') {
      this.notifyMobileDevices(attachment.userId, {
        type: 'agent_offline',
        deviceId: attachment.deviceId,
      });
    }
  }

  /**
   * Called by the runtime when a WebSocket encounters an error.
   */
  async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
    const attachment = ws.deserializeAttachment() as WsAttachment | null;
    if (attachment?.authenticated) {
      this.connections.delete(attachment.deviceId);
      this.decrementWsCount(attachment.deviceId);
      // Notify mobile clients if agent errored out
      if (attachment.deviceType === 'agent') {
        this.notifyMobileDevices(attachment.userId, {
          type: 'agent_offline',
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
            this.connections.delete(att.deviceId);
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

      const attachment: WsAttachment = {
        deviceId: payload.deviceId,
        userId: payload.userId,
        deviceType: payload.deviceType,
        authenticated: true,
        lastMessageTime: Date.now(),
      };
      ws.serializeAttachment(attachment);

      // Update in-memory cache and connection count
      this.connections.set(payload.deviceId, ws);
      this.incrementWsCount(payload.deviceId);

      // If agent, notify connected mobile clients of agent_online
      if (payload.deviceType === 'agent') {
        this.notifyMobileDevices(payload.userId, {
          type: 'agent_online',
          deviceId: payload.deviceId,
        });
      }

      // If mobile, send current presence snapshot for all connected agents.
      // Read directly from getWebSockets() instead of rebuildConnectionCache()
      // to avoid overwriting the connections map entry for this mobile's deviceId
      // (there may be multiple WebSockets for the same mobile device — one for
      // presence on the agent list, another for WebRTC signaling).
      if (payload.deviceType === 'mobile' && this.state.getWebSockets) {
        for (const connWs of this.state.getWebSockets()) {
          const att = connWs.deserializeAttachment() as WsAttachment | null;
          if (
            att?.authenticated &&
            att.userId === payload.userId &&
            att.deviceType === 'agent'
          ) {
            wsSend(ws, { type: 'agent_online', deviceId: att.deviceId });
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
   * Handle connect_request: mobile wants to connect to an agent.
   * Relays the request to the target agent with the mobile's deviceId.
   */
  private handleConnectRequest(ws: WebSocket, sender: WsAttachment, targetDeviceId: string): void {
    const targetWs = this.findWebSocket(targetDeviceId);
    if (!targetWs) {
      wsSend(ws, { type: 'error', error: `Device ${targetDeviceId} is not connected` });
      return;
    }

    // Verify target belongs to the same user (prevents cross-user signaling)
    const targetAtt = targetWs.deserializeAttachment() as WsAttachment | null;
    if (!targetAtt || targetAtt.userId !== sender.userId) {
      wsSend(ws, { type: 'error', error: `Device ${targetDeviceId} is not connected` });
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
   */
  private relaySignalingMessage(
    sender: WsAttachment,
    data: { type: string; targetDeviceId: string; [key: string]: unknown }
  ): void {
    const targetWs = this.findWebSocket(data.targetDeviceId);
    if (!targetWs) return;

    // Verify target belongs to the same user (prevents cross-user signaling)
    const targetAtt = targetWs.deserializeAttachment() as WsAttachment | null;
    if (!targetAtt || targetAtt.userId !== sender.userId) return;

    // Relay with sender's deviceId as the origin
    wsSend(targetWs, {
      ...data,
      targetDeviceId: sender.deviceId,
    });
  }

  // --- Pairing endpoints [T1.5] ---

  /**
   * POST /pair/initiate
   * Agent calls this to start pairing. Creates a pairing session.
   * Body: { deviceId, publicKey, x25519PublicKey }
   * Returns: { pairingCode }
   */
  private async handlePairInitiate(request: Request): Promise<Response> {
    let body: { deviceId?: string; publicKey?: string; x25519PublicKey?: string };
    try {
      body = await request.json() as typeof body;
    } catch {
      return jsonResponse({ error: 'Invalid JSON' }, 400);
    }

    if (!body.deviceId || !body.publicKey || !body.x25519PublicKey) {
      return jsonResponse(
        { error: 'Missing required fields: deviceId, publicKey, x25519PublicKey' },
        400
      );
    }

    // Register the agent device if not already registered
    const existing = this.getDevice(body.deviceId);
    if (!existing) {
      this.registerDevice(body.deviceId, body.publicKey, 'agent');
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
   * Returns: { agentX25519PublicKey, agentDeviceId, userId }
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

    // Get the agent device to find its userId
    const agentDevice = this.getDevice(session.agentDeviceId);
    if (!agentDevice) {
      return jsonResponse({ error: 'Agent device not found' }, 500);
    }

    // Enforce device count limit per user
    const deviceCount = this.countDevicesByUser(agentDevice.userId);
    if (deviceCount >= MAX_DEVICES_PER_USER) {
      return jsonResponse(
        { error: `Maximum device limit reached (${MAX_DEVICES_PER_USER})` },
        400
      );
    }

    // Register the mobile device under the same user as the agent
    this.registerDevice(
      body.deviceId,
      body.publicKey,
      'mobile',
      agentDevice.userId
    );

    // Relay mobile's X25519 key to agent via WebSocket if connected
    const agentWs = this.getConnection(session.agentDeviceId);
    if (agentWs) {
      try {
        agentWs.send(JSON.stringify({
          type: 'pair_complete',
          mobileDeviceId: body.deviceId,
          mobileX25519PublicKey: body.x25519PublicKey,
        }));
      } catch {
        // Agent WS may have disconnected — pairing data is still stored
      }
    }

    return jsonResponse({
      agentX25519PublicKey: session.agentX25519PublicKey,
      agentDeviceId: session.agentDeviceId,
      userId: agentDevice.userId,
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
      device.userId,
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
      const message = err instanceof Error ? err.message : 'Failed to generate TURN credentials';
      return jsonResponse({ error: message }, 502);
    }
  }
}

// --- Helpers ---

function rowToDevice(row: Record<string, SqlStorageValue>): StoredDevice {
  return {
    id: row['id'] as string,
    userId: row['user_id'] as string,
    publicKey: row['public_key'] as string,
    deviceType: row['device_type'] as DeviceType,
    name: row['name'] as string | null,
    createdAt: row['created_at'] as number,
  };
}

function generatePairingCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 31 chars, no 0/O/1/I
  const maxUnbiased = 248; // 31 * 8 = 248, largest multiple of 31 <= 256
  let code = '';
  for (let i = 0; i < 6; ) {
    const byte = new Uint8Array(1);
    crypto.getRandomValues(byte);
    if (byte[0]! < maxUnbiased) {
      code += chars[byte[0]! % chars.length];
      i++;
    }
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
