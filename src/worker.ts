import { SignalingDO } from './signaling';
import { verifyJWT, type JWTPayload } from './auth';

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

/** Package version, used in health endpoint. */
const VERSION = '0.1.0';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const startTime = Date.now();
    const requestId = crypto.randomUUID();

    const url = new URL(request.url);

    // Health endpoint — fast path, still gets correlation headers
    if (url.pathname === '/health') {
      return addCorrelationHeaders(
        new Response(
          JSON.stringify({
            status: 'ok',
            version: VERSION,
            timestamp: Date.now(),
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }
        ),
        requestId,
        startTime
      );
    }

    // Extract client IP for rate limiting (Cloudflare provides CF-Connecting-IP)
    const clientIp = extractClientIp(request);

    // Auth middleware: verify JWT for non-public routes
    if (!PUBLIC_PATHS.has(url.pathname)) {
      const authResult = await authenticateRequest(request, env);
      if (authResult.error) {
        return addCorrelationHeaders(
          new Response(
            JSON.stringify({ error: authResult.error, requestId }),
            {
              status: 401,
              headers: { 'Content-Type': 'application/json' },
            }
          ),
          requestId,
          startTime
        );
      }
      // Clone request to preserve body stream, then inject auth context headers
      request = new Request(request.clone(), {
        headers: new Headers([
          ...request.headers,
          ['X-Device-Id', authResult.payload!.deviceId],
          ['X-User-Id', authResult.payload!.userId],
          ['X-Device-Type', authResult.payload!.deviceType],
          ['X-Client-IP', clientIp],
        ]),
      });
    } else {
      // Public routes still need client IP for rate limiting
      request = new Request(request.clone(), {
        headers: new Headers([
          ...request.headers,
          ['X-Client-IP', clientIp],
        ]),
      });
    }

    // Routes that dispatch to the Durable Object (including TURN credentials)
    if (url.pathname.startsWith('/auth/') || url.pathname === '/ws' || url.pathname === '/turn/credentials') {
      const response = await routeToDO(request, url, env);
      return addCorrelationHeaders(response, requestId, startTime);
    }

    return addCorrelationHeaders(
      new Response(JSON.stringify({ error: 'Not Found', requestId }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      }),
      requestId,
      startTime
    );
  },
};

/**
 * Extract client IP from Cloudflare headers with fallbacks.
 * CF-Connecting-IP is set by Cloudflare on all requests.
 */
export function extractClientIp(request: Request): string {
  return (
    request.headers.get('CF-Connecting-IP') ??
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
    '127.0.0.1'
  );
}

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
 * Add X-Request-Id and X-Response-Time headers to a response.
 * Clones the response to allow header mutation.
 */
function addCorrelationHeaders(
  response: Response,
  requestId: string,
  startTime: number
): Response {
  const durationMs = Date.now() - startTime;
  const newResponse = new Response(response.body, response);
  newResponse.headers.set('X-Request-Id', requestId);
  newResponse.headers.set('X-Response-Time', `${durationMs}ms`);
  return newResponse;
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
  // /turn/credentials stays as /turn/credentials
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
