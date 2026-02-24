import { SignalingDO } from './signaling';
import { verifyJWT, type JWTPayload } from './auth';
import { generateTurnCredentials } from './turn';

export { SignalingDO };

export interface Env {
  SIGNALING: DurableObjectNamespace;
  TURN_TOKEN_ID: string;
  TURN_API_TOKEN: string;
  JWT_SECRET: string;
}

// Routes that don't require JWT authentication
export const PUBLIC_PATHS = new Set([
  '/health',
  '/auth/pair/initiate',
  '/auth/pair/complete',
  '/auth/token',
  '/ws', // WebSocket auth is handled at the DO level via auth message, not HTTP headers
]);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return new Response('OK', { status: 200 });
    }

    // Auth middleware: verify JWT for non-public routes
    if (!PUBLIC_PATHS.has(url.pathname)) {
      const authResult = await authenticateRequest(request, env);
      if (authResult.error) {
        return new Response(JSON.stringify({ error: authResult.error }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      // Clone request to preserve body stream, then inject auth context headers
      request = new Request(request.clone(), {
        headers: new Headers([
          ...request.headers,
          ['X-Device-Id', authResult.payload!.deviceId],
          ['X-User-Id', authResult.payload!.userId],
          ['X-Device-Type', authResult.payload!.deviceType],
        ]),
      });
    }

    // Routes that dispatch to the Durable Object
    if (url.pathname.startsWith('/auth/') || url.pathname === '/ws') {
      return routeToDO(request, url, env);
    }

    // TURN credentials (authenticated — JWT already verified by middleware above)
    if (url.pathname === '/turn/credentials' && request.method === 'GET') {
      return handleTurnCredentials(env);
    }

    return new Response('Not Found', { status: 404 });
  },
};

/**
 * Verify JWT from Authorization header.
 */
export async function authenticateRequest(
  request: Request,
  env: Env
): Promise<{ payload?: JWTPayload; error?: string }> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) {
    return { error: 'Missing Authorization header' };
  }

  if (!authHeader.startsWith('Bearer ')) {
    return { error: 'Invalid Authorization format, expected Bearer token' };
  }

  const token = authHeader.slice('Bearer '.length);

  try {
    const payload = await verifyJWT(token, env.JWT_SECRET);
    return { payload };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Token verification failed';
    return { error: message };
  }
}

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

/**
 * Generate and return TURN credentials from Cloudflare Realtime API.
 */
async function handleTurnCredentials(env: Env): Promise<Response> {
  try {
    const credentials = await generateTurnCredentials(env);
    return new Response(JSON.stringify(credentials), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to generate TURN credentials';
    return new Response(JSON.stringify({ error: message }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}
