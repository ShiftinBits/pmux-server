# CLAUDE.md — pmux-server

Cloudflare Worker + Durable Object signaling server for Pocketmux. Zero-knowledge relay — never sees terminal content.

## Quick Reference

| Task | Command |
|------|---------|
| Dev | `npm run dev` (wrangler dev --ip 0.0.0.0) |
| Deploy | `npm run deploy` |
| Test (unit) | `npm test` |
| Test (integration) | `npm run test:integration` |

Worker name: `pmux-signaling` | Domain: `signal.pmux.io`

Secrets: `TURN_TOKEN_ID`, `TURN_API_TOKEN`, `JWT_SECRET` — set in `.dev.vars` locally, `wrangler secret put` in production.

## Architecture

Single global Durable Object instance — `env.SIGNALING.idFromName('global')` in `worker.ts` — `routeToDO()`.

| File | Responsibility |
|------|---------------|
| `src/worker.ts` | HTTP entry, JWT auth middleware, route dispatch to DO |
| `src/signaling.ts` | `SignalingDO`: WebSocket signaling, SQLite storage, pairing, presence |
| `src/auth.ts` | Ed25519 verification (Web Crypto), JWT create/verify (HS256) |
| `src/turn.ts` | TURN credential generation via Cloudflare Realtime API |
| `src/types.ts` | Re-exports from `@pocketmux/shared` (type-only, no runtime dep) |
| `src/middleware/ratelimit.ts` | Fixed-window rate limiting via DO KV storage |

### Storage Model

| Layer | What | Backing |
|-------|------|---------|
| SQLite (persistent) | devices, pairings, pairing_sessions | `state.storage.sql` |
| DO KV (ephemeral) | Rate limit counters (`ratelimit:{endpoint}:{key}`) | `state.storage.get/put` |
| In-memory maps | WebSocket connection cache, per-device WS counts | `Map<string, WebSocket>` |
| WS Attachments | Per-socket metadata (survives hibernation) | `serializeAttachment()` |

### Endpoints

REST (worker → DO): `/auth/pair/initiate`, `/auth/pair/complete`, `/auth/token`, `/turn/credentials`
WebSocket: `/ws` (Hibernation API — DO sleeps when idle)

Worker strips `/auth` prefix before forwarding to DO (e.g., `/auth/token` → `/token`). See `worker.ts` — `routeToDO()`.

Public (no JWT): `/health`, `/auth/pair/*`, `/auth/token`, `/ws` (WS auth via in-band message, not HTTP header).
Authenticated (JWT): `/turn/credentials`.

All endpoints must match spec Section 5.1.

## Conventions

- **Workers runtime only** — Web Crypto API, not Node.js crypto
- TypeScript strict mode + `noUncheckedIndexedAccess` enabled
- Named exports, `async`/`await`, `const` by default

## Rate Limiting

Fixed-window per-endpoint, stored in DO KV (`checkRateLimit()` in `ratelimit.ts`):

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `/pair/initiate` | 10 | 60s | IP |
| `/pair/complete` | 10 | 60s | IP |
| `/token` | 30 | 60s | **IP** (body untrusted pre-auth) |
| `/turn/credentials` | 20 | 60s | device ID or IP |
| `/ws` | 8 | 10s | IP |

Max 5 concurrent WebSocket connections per device (`MAX_WS_CONNECTIONS_PER_DEVICE`).

## Testing

Vitest with mocked DO environment. Unit tests in `src/__tests__/`, integration in `src/__tests__/integration/`.

| Helper | Purpose |
|--------|---------|
| `helpers/mock-do.ts` | `createTestDO()` — mocked SQL, KV, WebSocket lifecycle |
| `helpers/mock-sql-storage.ts` | sql.js WASM SQLite matching Cloudflare's `SqlStorage` API |
| `helpers/mock-websocket.ts` | `MockWebSocket` with `sent[]`, attachment tracking, `messagesOfType()` |

Real Web Crypto used in tests (not mocked). Ed25519 keys generated per-test.

## Gotchas

- **Hibernation cache rebuild**: After DO wake, `connections` map is empty. `rebuildConnectionCache()` scans `state.getWebSockets()` to restore. See `signaling.ts` — `findWebSocket()`.
- **notifyDevice iterates ALL WebSockets**: Not the 1:1 cache — a device may have multiple connections (agent + pair CLI). Critical for `pair_complete` delivery.
- **Request cloning**: Worker clones request before injecting auth headers (`X-Device-Id`, `X-Device-Type`, `X-Client-IP`) to preserve body stream.
- **Pairing code**: Direct modulo indexing (alphabet is 32 chars, divides 256 evenly), base32-like alphabet (no 0/O/1/I), 6 chars, 5-min expiry, single-use.
- **Device orphan cleanup**: On re-pair, old mobile removed only if zero remaining pairings elsewhere.
- **JWT defenses**: Explicit header check (HS256 only — blocks alg:none), audience `pocketmux`, sub must match deviceId, clock skew ≤60s.
- **Alarm lifecycle**: Scheduled on first WS connection (`scheduleAlarmIfNeeded()`), re-schedules only if active connections remain after cleanup sweep.
