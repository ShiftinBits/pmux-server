import type { Env } from './worker';

export class SignalingDO implements DurableObject {
  private state: DurableObjectState;
  private env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    // TODO [T1.4]: Initialize SQLite schema
    // TODO [T1.8]: Handle WebSocket upgrades for signaling
    return new Response('SignalingDO stub', { status: 200 });
  }
}
