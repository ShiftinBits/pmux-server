/**
 * SignalingDO — Durable Object for WebSocket signaling, presence, and storage.
 *
 * Uses built-in SQLite for persistent device/user storage.
 * Uses in-memory maps for ephemeral state (pairing codes, WebSocket sessions).
 */

import type { Env } from './worker';
import type { DeviceType } from '@pocketmux/shared';

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

// --- Durable Object ---

export class SignalingDO implements DurableObject {
  private state: DurableObjectState;
  private env: Env;
  private initialized = false;

  // Ephemeral pairing state (in-memory, not SQLite)
  private pairingSessions = new Map<string, PairingSession>();

  // WebSocket connections indexed by deviceId
  private connections = new Map<string, WebSocket>();

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  private get sql(): SqlStorage {
    return this.state.storage.sql;
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
        public_key TEXT NOT NULL,
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
      'INSERT INTO devices (id, user_id, public_key, device_type, name, created_at) VALUES (?, ?, ?, ?, ?, ?)',
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

    const code = generatePairingCode();
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

  // --- WebSocket connection tracking ---

  setConnection(deviceId: string, ws: WebSocket): void {
    this.connections.set(deviceId, ws);
  }

  getConnection(deviceId: string): WebSocket | undefined {
    return this.connections.get(deviceId);
  }

  removeConnection(deviceId: string): void {
    this.connections.delete(deviceId);
  }

  // --- HTTP routing ---

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Route to specific handlers based on path
    if (url.pathname === '/pair/initiate' && request.method === 'POST') {
      return this.handlePairInitiate(request);
    }
    if (url.pathname === '/pair/complete' && request.method === 'POST') {
      return this.handlePairComplete(request);
    }
    if (url.pathname === '/token' && request.method === 'POST') {
      return this.handleTokenExchange(request);
    }
    if (url.pathname === '/ws') {
      // TODO [T1.8]: Handle WebSocket upgrades for signaling
      return new Response('WebSocket endpoint - not yet implemented', { status: 501 });
    }

    return new Response('Not Found', { status: 404 });
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

  // --- Token exchange endpoint (stub for T1.6) ---

  private async handleTokenExchange(_request: Request): Promise<Response> {
    return new Response('Not implemented', { status: 501 });
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
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I to avoid confusion
  let code = '';
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  for (const byte of bytes) {
    code += chars[byte % chars.length];
  }
  return code;
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
