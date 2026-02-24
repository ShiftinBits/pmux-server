import { SignalingDO } from './signaling';

export { SignalingDO };

export interface Env {
  SIGNALING: DurableObjectNamespace;
  TURN_TOKEN_ID: string;
  TURN_API_TOKEN: string;
  JWT_SECRET: string;
}

// Routes that don't require JWT authentication
const PUBLIC_ROUTES = new Set([
  '/health',
  '/auth/pair/initiate',
  '/auth/pair/complete',
  '/auth/token',
]);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return new Response('OK', { status: 200 });
    }

    // Routes that dispatch to the Durable Object
    if (url.pathname.startsWith('/auth/') || url.pathname === '/ws') {
      return routeToDO(request, url, env);
    }

    // TODO [T1.7]: GET /turn/credentials (authenticated)

    return new Response('Not Found', { status: 404 });
  },
};

/**
 * Route requests to the SignalingDO.
 * Uses a single DO instance (named "global") for all signaling.
 */
async function routeToDO(request: Request, url: URL, env: Env): Promise<Response> {
  const id = env.SIGNALING.idFromName('global');
  const stub = env.SIGNALING.get(id);

  // Strip /auth prefix for the DO's internal routing
  // /auth/pair/initiate -> /pair/initiate
  // /auth/pair/complete -> /pair/complete
  // /auth/token -> /token
  // /ws stays as /ws
  let doPath = url.pathname;
  if (doPath.startsWith('/auth/')) {
    doPath = doPath.slice('/auth'.length);
  }

  const doUrl = new URL(doPath, url.origin);
  const doRequest = new Request(doUrl.toString(), {
    method: request.method,
    headers: request.headers,
    body: request.body,
  });

  return stub.fetch(doRequest);
}
