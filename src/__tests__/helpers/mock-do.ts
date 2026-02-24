/**
 * Create a SignalingDO instance with mocked DurableObjectState for testing.
 */

import { SignalingDO } from '../../signaling';
import { createMockSqlStorage } from './mock-sql-storage';
import type { Env } from '../../worker';

export async function createTestDO(): Promise<SignalingDO> {
  const mockSql = await createMockSqlStorage();

  // Track accepted WebSockets for the Hibernation API mock
  const acceptedWebSockets: WebSocket[] = [];

  const mockState = {
    storage: {
      sql: mockSql,
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
