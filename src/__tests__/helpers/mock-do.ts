/**
 * Create a SignalingDO instance with mocked DurableObjectState for testing.
 */

import { SignalingDO } from '../../signaling';
import { createMockSqlStorage } from './mock-sql-storage';
import type { Env } from '../../worker';

/**
 * In-memory key-value store that mimics DO storage.get() / storage.put().
 * Used for rate limit counters and any other DO KV storage needs.
 */
export function createMockKVStorage(): {
  get: <T>(key: string) => Promise<T | undefined>;
  put: (key: string, value: unknown) => Promise<void>;
  store: Map<string, unknown>;
} {
  const store = new Map<string, unknown>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      return store.get(key) as T | undefined;
    },
    async put(key: string, value: unknown): Promise<void> {
      store.set(key, value);
    },
    store,
  };
}

/**
 * Counting mock for a native Workers Rate Limiting binding.
 * Blocks after `limit` calls per key. No time window — the platform binding
 * owns the window and isn't fake-timer controllable, so counting is the
 * honest testable surface (exhaust → blocked; distinct keys independent).
 */
export function createMockRateLimit(limit: number): RateLimit & { counts: Map<string, number> } {
  const counts = new Map<string, number>();
  return {
    counts,
    async limit({ key }: { key: string }): Promise<{ success: boolean }> {
      const n = (counts.get(key) ?? 0) + 1;
      counts.set(key, n);
      return { success: n <= limit };
    },
  } as RateLimit & { counts: Map<string, number> };
}

export interface MockDOState {
  acceptedWebSockets: WebSocket[];
  scheduledAlarm: number | null;
}

export async function createTestDO(): Promise<{ doInstance: SignalingDO; mockState: MockDOState }> {
  const mockSql = await createMockSqlStorage();
  const mockKV = createMockKVStorage();

  // Track accepted WebSockets for the Hibernation API mock
  const acceptedWebSockets: WebSocket[] = [];

  // Track alarm scheduling
  let scheduledAlarm: number | null = null;

  const trackableState: MockDOState = {
    acceptedWebSockets,
    scheduledAlarm,
  };

  const mockState = {
    storage: {
      sql: mockSql,
      get: mockKV.get,
      put: mockKV.put,
      async setAlarm(scheduledTime: number): Promise<void> {
        scheduledAlarm = scheduledTime;
        trackableState.scheduledAlarm = scheduledTime;
      },
      async getAlarm(): Promise<number | null> {
        return scheduledAlarm;
      },
      async deleteAlarm(): Promise<void> {
        scheduledAlarm = null;
        trackableState.scheduledAlarm = null;
      },
    },
    acceptWebSocket(ws: WebSocket): void {
      acceptedWebSockets.push(ws);
    },
    getWebSockets(): WebSocket[] {
      return acceptedWebSockets;
    },
  };

  const mockEnv: Env = {
    SIGNALING: {} as DurableObjectNamespace,
    TURN_TOKEN_ID: 'test-turn-token-id',
    TURN_API_TOKEN: 'test-turn-api-token',
    JWT_SECRET: 'test-jwt-secret-at-least-32-chars-long',
    TOKEN_LIMITER: createMockRateLimit(30),
    PAIR_LIMITER: createMockRateLimit(10),
    TURN_LIMITER: createMockRateLimit(20),
    WS_LIMITER: createMockRateLimit(8),
  };

  const doInstance = new SignalingDO(
    mockState as unknown as DurableObjectState,
    mockEnv
  );

  return { doInstance, mockState: trackableState };
}

/**
 * Legacy helper — returns just the DO instance for backward compatibility
 * with existing tests that destructure as `doInstance = await createTestDO()`.
 */
export async function createTestDOCompat(): Promise<SignalingDO> {
  const { doInstance } = await createTestDO();
  return doInstance;
}
