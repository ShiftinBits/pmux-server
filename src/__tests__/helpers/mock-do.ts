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

export async function createTestDO(): Promise<SignalingDO> {
  const mockSql = await createMockSqlStorage();
  const mockKV = createMockKVStorage();

  // Track accepted WebSockets for the Hibernation API mock
  const acceptedWebSockets: WebSocket[] = [];

  const mockState = {
    storage: {
      sql: mockSql,
      get: mockKV.get,
      put: mockKV.put,
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
  };

  return new SignalingDO(
    mockState as unknown as DurableObjectState,
    mockEnv
  );
}
