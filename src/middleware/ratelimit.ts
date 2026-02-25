/**
 * Fixed-window rate limiting using Durable Object storage.
 *
 * Stores counters as key-value pairs in DO storage (not SQLite).
 * Each counter tracks request count and window start time.
 * Counters automatically reset when the window expires.
 */

// --- Types ---

export interface RateLimitConfig {
  /** Maximum requests allowed in the window. */
  maxRequests: number;
  /** Window duration in milliseconds. */
  windowMs: number;
}

export interface RateLimitResult {
  /** Whether the request is allowed. */
  allowed: boolean;
  /** Seconds until the window resets (included when blocked). */
  retryAfter?: number;
  /** Current request count in the window. */
  current: number;
  /** Maximum allowed requests. */
  limit: number;
}

interface RateLimitCounter {
  count: number;
  windowStart: number;
}

/**
 * Minimal subset of DurableObjectStorage used for rate limiting.
 * Allows the module to be tested without a full DO runtime.
 */
export interface RateLimitStorage {
  get<T>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
}

// --- Endpoint limits ---

/**
 * Per-endpoint rate limit configuration.
 * Keys match the DO-internal path (after /auth prefix is stripped by the worker).
 */
export const ENDPOINT_LIMITS: Record<string, RateLimitConfig> = {
  '/pair/initiate': { maxRequests: 10, windowMs: 60_000 },
  '/pair/complete': { maxRequests: 10, windowMs: 60_000 },
  '/token': { maxRequests: 30, windowMs: 60_000 },
  '/turn/credentials': { maxRequests: 20, windowMs: 60_000 },
  '/ws': { maxRequests: 30, windowMs: 60_000 },
};

// --- Core rate limit check ---

/**
 * Check whether a request is within the rate limit for a given endpoint and key.
 *
 * @param storage - DO storage instance (get/put)
 * @param key - Rate limit key (IP address or device ID)
 * @param endpoint - The endpoint path (must be a key in ENDPOINT_LIMITS)
 * @returns RateLimitResult indicating whether the request is allowed
 */
export async function checkRateLimit(
  storage: RateLimitStorage,
  key: string,
  endpoint: string
): Promise<RateLimitResult> {
  const config = ENDPOINT_LIMITS[endpoint];
  if (!config) {
    // Unknown endpoint — allow by default (no rate limit configured)
    return { allowed: true, current: 0, limit: 0 };
  }

  const storageKey = `ratelimit:${endpoint}:${key}`;
  const now = Date.now();

  const counter = await storage.get<RateLimitCounter>(storageKey);

  if (!counter || now >= counter.windowStart + config.windowMs) {
    // Window expired or no counter — start a new window
    await storage.put(storageKey, { count: 1, windowStart: now });
    return { allowed: true, current: 1, limit: config.maxRequests };
  }

  // Window still active
  const newCount = counter.count + 1;

  if (newCount > config.maxRequests) {
    // Rate limit exceeded
    const windowEnd = counter.windowStart + config.windowMs;
    const retryAfter = Math.ceil((windowEnd - now) / 1000);

    console.warn(
      `[rate-limit] Blocked: endpoint=${endpoint} key=${key} count=${newCount} limit=${config.maxRequests}`
    );

    return {
      allowed: false,
      retryAfter: Math.max(retryAfter, 1),
      current: counter.count,
      limit: config.maxRequests,
    };
  }

  // Within limit — increment
  await storage.put(storageKey, { count: newCount, windowStart: counter.windowStart });
  return { allowed: true, current: newCount, limit: config.maxRequests };
}

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

/** Maximum number of paired devices per user (per agent identity). */
export const MAX_DEVICES_PER_USER = 10;

/** Maximum simultaneous WebSocket connections per device ID. */
export const MAX_WS_CONNECTIONS_PER_DEVICE = 5;
