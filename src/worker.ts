import { SignalingDO } from './signaling';

export { SignalingDO };

export interface Env {
  SIGNALING: DurableObjectNamespace;
  TURN_TOKEN_ID: string;
  TURN_API_TOKEN: string;
  JWT_SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return new Response('OK', { status: 200 });
    }

    // TODO [T1.3–T1.8]: Route to auth, pairing, TURN, and WebSocket endpoints
    return new Response('Not Found', { status: 404 });
  },
};
