/**
 * Rate-limit response helper and WebSocket connection-count constant.
 *
 * Per-endpoint request rate limiting now uses the native Cloudflare Workers
 * Rate Limiting bindings (see wrangler.toml and signaling.ts) [SB-995].
 * The concurrent-connection cap below is separate (SB-993) and stays in the DO.
 */

/**
 * Create a 429 Too Many Requests response with Retry-After header.
 */
export function rateLimitResponse(retryAfter: number): Response {
  return new Response(
    JSON.stringify({ error: 'Too many requests' }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(retryAfter),
      },
    }
  );
}

// --- Constants ---

/** Maximum simultaneous WebSocket connections per device ID. */
export const MAX_WS_CONNECTIONS_PER_DEVICE = 5;
