# CLAUDE.md — pmux-server

Cloudflare Worker + Durable Object signaling server for Pocketmux. Zero-knowledge relay — never sees terminal content.

## Quick Reference

| Task | Command |
|------|---------|
| Dev | `npm run dev` (wrangler dev --ip 0.0.0.0) |
| Deploy | `npm run deploy` (CI: `v*` tag or manual → `wrangler-action`) |
| Test (all, incl. integration) | `npm test` |
| Test (integration subset) | `npm run test:integration` |
| Build check (what CI runs) | `npx wrangler deploy --dry-run --outdir dist` |

Worker name: `pmux-signaling` | Domain: `signal.pmux.io` (custom domain; `workers_dev` and `preview_urls` off)

Secrets: `TURN_TOKEN_ID`, `TURN_API_TOKEN`, `JWT_SECRET`, optional `PMUX_HMAC_SECRET` — `.dev.vars` locally, `wrangler secret put` in production.

**Type-checking:** CI runs only vitest + the wrangler dry-run, never `tsc`. `npx tsc --noEmit` currently fails on main with pre-existing errors (`auth.ts`, `hmac.ts`, `signaling.ts`, `worker.ts`) — diff against main's output rather than expecting clean. `tsconfig.json` excludes `src/__tests__`, so tests are never type-checked.

## Architecture

Single global Durable Object instance — `env.SIGNALING.idFromName('global')` in `worker.ts` — `routeToDO()`.

| File | Responsibility |
|------|---------------|
| `src/worker.ts` | HTTP entry: `/v1` strip, HMAC check, JWT auth, header injection, route dispatch to DO |
| `src/signaling.ts` | `SignalingDO`: REST handlers, WebSocket signaling, SQLite storage, pairing, presence, alarm, TURN cache |
| `src/auth.ts` | Ed25519 verification (Web Crypto), JWT create/verify (HS256) |
| `src/hmac.ts` | Optional client HMAC signature validation (legacy + v1 formulas) |
| `src/turn.ts` | TURN credential generation via Cloudflare Realtime API |
| `src/types.ts` | Re-exports from `@pocketmux/shared` |
| `src/middleware/ratelimit.ts` | `rateLimitResponse()` (429 + `Retry-After`) and `MAX_WS_CONNECTIONS_PER_DEVICE` (5) |

`@pocketmux/shared` imports are all `import type` — no runtime dependency. The git dep's SHA is pinned in `package-lock.json`.

### Request Pipeline (`worker.ts` default `fetch`)

1. Strip `/v1` prefix (`/v1/x` → `/x`, sets `apiVersion`).
2. `/health` (JSON status) and `/` (308 → `pmux.io`) return immediately — no HMAC, auth, or rate limit.
3. If `PMUX_HMAC_SECRET` is set → HMAC check (below). Applies to `/ws` upgrades too.
4. Path not in `PUBLIC_PATHS` → JWT required (`authenticateRequest()`). Runs before routing, so unknown paths without a JWT get 401, not 404.
5. Build the DO request's headers from empty: `X-Client-IP` (all), `X-Device-Id`/`X-Device-Type` (JWT routes) and the client's `Upgrade`. No other client header reaches the DO [SB-1340]. Then `routeToDO()` strips `/auth` (`/auth/token` → `/token`). Query string is dropped.

### Endpoints

| Public path | DO path | Method | Auth | Limiter | Key |
|-------------|---------|--------|------|---------|-----|
| `/auth/challenge` | `/challenge` | POST | none | `TOKEN_LIMITER` | `challenge:IP` |
| `/auth/pair/initiate` | `/pair/initiate` | POST | Ed25519 + challenge | `PAIR_LIMITER` | `pair/initiate:IP` |
| `/auth/pair/complete` | `/pair/complete` | POST | pairing code | `PAIR_LIMITER` | `pair/complete:IP` |
| `/auth/token` | `/token` | POST | Ed25519 + challenge | `TOKEN_LIMITER` | `token:IP` (body untrusted pre-auth) |
| `/auth/pairing` | `/pairing` | DELETE | JWT, host only (`pmux unpair`) | `PAIR_LIMITER` | `pairing:deviceId` |
| `/auth/device` | `/device` | DELETE | JWT, host only (`pmux uninstall`) | `PAIR_LIMITER` | `device:deviceId` |
| `/turn/credentials` | same | GET | JWT | `TURN_LIMITER` | `turn:deviceId` |
| `/ws` | same | upgrade | in-band `{type:'auth', token}` | `WS_LIMITER` | `ws:IP` |

Limits (`wrangler.toml` `[[ratelimits]]`, period must be 10 or 60): TOKEN 30/60s, PAIR 10/60s, TURN 20/60s, WS 8/10s. Bindings shared across endpoints keep independent counters via the namespaced key. Wrong method → 405 via `SignalingDO.ROUTE_METHODS`. Max 5 concurrent WebSockets per device. All endpoints must match SPEC §5.1.

### HMAC (`hmac.ts`)

Headers `pmux-signature` + `pmux-timestamp` (unix seconds, ±60s); `/v1/*` also needs `pmux-nonce` (32 lowercase hex). Signature = hex `HMAC-SHA256(secret, msg)`:
- v1 (`validateClientSignatureV1`): `"{timestamp}:{nonce}:{pathname}"`
- legacy (`validateClientSignature`): `"{timestamp}:{pathname}"`

`pathname` is the **original** path including `/v1`. Method, query and body are not signed. Nonce is format-checked only — no replay store.

### Storage Model

| Layer | What | Backing |
|-------|------|---------|
| SQLite | `devices`, `pairings`, `pairing_sessions`, `pending_pair_complete`, `challenges`, `signaling_sessions` | `state.storage.sql`, created in `ensureSchema()` |
| Rate Limiting binding | Per-endpoint request limits | native Workers Rate Limiting (`env.*_LIMITER`) |
| In-memory maps | WebSocket connection cache and per-device socket sets (the per-device cap, `host_offline` and `getWsConnectionCount()` count live sockets in the set) | `connections`, `deviceSockets`; rebuilt once per wake |
| In-memory map | Held `/pair/complete` requests awaiting `pair_accept`/`pair_reject` (30s) | `pendingPairs`, keyed by host; the in-flight request keeps the DO awake |
| DO KV + in-memory | TURN credential cache | key `turn_cache`, mirrored in `turnCache` |
| WS attachments | `{deviceId, deviceType, authenticated, lastMessageTime, closed?}` (survives hibernation; `deviceType` comes from the `devices` row, not the JWT; `closed` = the DO closed it (idle sweep, `webSocketError` or `closeDeviceSockets`), so it is ignored for routing, presence, counts and late frames [SB-1393]) | `serializeAttachment()` |

Host rows with no pairing are purged after 1 day (`UNPAIRED_HOST_TTL_S`, measured from `devices.created_at`) by `alarm()`, skipping hosts with a `pairing_sessions` or `pending_pair_complete` row, a `pendingPairs` entry or a live authenticated socket. A host that unpaired and sits idle is purged too; `pmux pair` re-registers it. The alarm is scheduled at new-host `/pair/initiate` and rescheduled while unpaired hosts remain.

Schema changes: `CREATE TABLE IF NOT EXISTS` + idempotent `ALTER` in `ensureSchema()` (guarded by a `PRAGMA table_info` column check; the older RENAME uses try/catch); no schema-version table. **Units differ:** `devices`/`pairings` `created_at` are seconds; every `expires_at` and `pending_pair_complete.created_at` are ms.

## Conventions

- **Workers runtime only** — Web Crypto API, not Node.js crypto
- Strict mode + `noUncheckedIndexedAccess` (hence `!` on indexed access)
- Error bodies: worker → `{error, requestId}`; DO → `{error}`. Logging is `console.warn/error` with `[tag]` prefixes.

## Testing

Vitest, no Miniflare/workerd — tests call `doInstance.fetch()` and the WS handler methods directly. Integration tests (`src/__tests__/integration/`) use the same mocks, just multi-step flows. Real Web Crypto; Ed25519 keys generated per test.

| Helper | Purpose |
|--------|---------|
| `helpers/mock-do.ts` | `createTestDO()` → `{doInstance, mockState}`; `createMockRateLimit()`, `createMockKVStorage()` |
| `helpers/mock-sql-storage.ts` | sql.js WASM SQLite matching Cloudflare's `SqlStorage` API |
| `helpers/mock-websocket.ts` | `MockWebSocket` with `sent[]`, `closeCode`, attachments, `messagesOfType()` |
| `helpers/crypto.ts` | Keypairs, signing (`signAuthChallenge()`, origin `TEST_ORIGIN` = `http://localhost`), `fetchChallenge()`, `signedPairInitiateBody()` |

- **Mock SQL returns rows only for queries starting with `SELECT` or `PRAGMA`** — a `WITH` CTE or `RETURNING` clause silently yields nothing in tests.
- `createMockRateLimit()` is a plain counter with no time window. `createTestDO()` env has no `PMUX_HMAC_SECRET`, `PMUX_AUTH_ORIGINS` or `PMUX_REJECT_LEGACY_AUTH`; pass `envOverrides` to set them.

## Gotchas

- **Hibernation cache rebuild**: A wake re-runs the constructor, so `connections` and `deviceSockets` (every authenticated socket per device) start empty. The first lookup calls `ensureConnectionCache()`, which scans `state.getWebSockets()` once; after that nothing rescans. `handleWsAuth` adds to `deviceSockets` and `webSocketClose`/`webSocketError`/the idle sweep/`closeDeviceSockets` remove, each after `ensureConnectionCache()`, so a close that is the first event after a wake isn't undone by the rebuild. There is no separate count to keep in step: counts are read from the set. A `connections` miss falls back to the freshest live socket in the device's set (`findWebSocket()`). Tests simulate a wake with `clearWsConnectionCounts()`, which leaves `connections` alone.
- **notifyDevice iterates the device's whole socket set**, not the 1:1 cache — a device may have multiple connections (agent + pair CLI). Critical for `pair_complete` delivery. It skips dead sockets and returns the delivered count, which decides `pending_pair_complete` persistence.
- **Two pairing paths** [SB-1348], chosen by `pairing_sessions.pair_confirm` (agent sends `pairConfirm: true` at initiate):
  - *Confirming:* `/pair/initiate` echoes `pairConfirm: true`. `/pair/complete` relays `pair_complete` and holds the request in `pendingPairs` (30s); a host socket that authenticates during the hold gets it right after its `auth` ok reply. The host answers `pair_accept`/`pair_reject`. Only an accept runs `commitPairing` (validate, then remove old pairing + register + create pairing in one `transactionSync`, then tell the evicted mobile), and only an accept gets `pair_result {ok}`. Otherwise the result is 403 (reject), 504 (timeout), 409 (superseded by a newer `/pair/initiate`, cancelled by DELETE `/pairing` or `/device`, or a device conflict — one generic message for every kind) or 500 (commit threw and rolled back; old pairing intact). Every outcome goes through `settlePendingPair`.
  - *Legacy:* commits immediately. An undelivered `pair_complete` goes to `pending_pair_complete` and is flushed on host WS auth.
- **Malformed input never throws out of the DO**: `fetch()` wraps `route()` in a catch (500 `Internal error`, logged `[do]`). A JSON body that is not an object (`null`, number, string, array) is 400 `Invalid JSON` (`readJsonObject()`). `/pair/initiate` and `/token` reject a `deviceId` that is not 32 lowercase hex or a `signature` that is not canonical 64-byte base64 with 400, and `/pair/initiate` rejects a non-canonical 32-byte-base64 `x25519PublicKey` or `ed25519PublicKey` with 400, all before `getDevice` and the nonce consumption; for an existing device it then requires a `host` row (409 otherwise) and a body `ed25519PublicKey` equal to the registered key (401 otherwise), both checked after the signature. A new device gets 401 unless its `deviceId` is `hex(SHA-256(key)[:16])`. `/pair/complete` requires canonical 32-byte keys and a derived `deviceId` (400, before the code is consumed). `registerDevice` never changes an existing device's key. Bad base64 in a stored verify key is 401 `Invalid signature format`. `webSocketMessage` parses and shape-checks a frame before touching the socket, so `null`/number/string/array frames get an error reply and do not count as activity.
- **Challenge signatures**: `/token` and `/pair/initiate` verify Ed25519 over `pocketmux-auth-v1|<origin>|<deviceId>|<nonce>`, where origin is any normalized `PMUX_AUTH_ORIGINS` entry (comma-separated) or, when that is unset, the DO request's `URL.origin` (`routeToDO()` keeps the public origin). `wrangler dev` rewrites the request URL to `http://signal.pmux.io` (the route host), so set `PMUX_AUTH_ORIGINS` in `.dev.vars` to the URL local clients dial. The legacy `<deviceId>|<nonce>` form is accepted, logged as `[auth] legacy signature accepted` with the route, unless `PMUX_REJECT_LEGACY_AUTH` is `true`; set it once every supported agent and mobile release signs the origin-bound form, then remove the fallback.
- **DO header allowlist**: `routeToDO()` forwards only the method, body and the worker-built headers. A new header the DO must read has to be added explicitly in `worker.ts`.
- **Local dev rate limiting is effectively off**: `extractClientIp()` falls back to `crypto.randomUUID()` when `CF-Connecting-IP` is missing, so every request gets a fresh bucket.
- **Pairing code**: base32-like alphabet (no 0/O/1/I), 6 chars, direct modulo (32 divides 256), 5-min expiry, single-use. Challenges: 60s TTL, consumed unconditionally on use, swept in `createChallenge()`.
- **Re-pair**: replaced mobile gets `device_unpaired` (`replaced_by_new_pairing`); its `devices` row is removed only if no other pairings reference it. DELETE `/pairing` → `host_unpaired`, `/device` → `host_uninstalled`.
- **No socket outlives its `devices` row**: wherever a row is deleted under live sockets (DELETE `/device` for the host and an orphaned mobile, DELETE `/pairing` and `commitPairing` for an orphaned mobile), close its sockets through `closeDeviceSockets(id, reason)` (4004), after `device_unpaired` goes out. It marks each socket closed and does the cleanup itself (cache, count, socket set, a host's `signaling_sessions` row), because `webSocketClose` skips `closed` attachments. It sends no `host_offline` (the pairing is already gone). Don't close inside `removePairing`/`removeDevice`.
- **One auth per socket**: an `auth` frame on an already-authenticated socket (or one racing another auth on the same socket) gets `{type:'error', error:'Already authenticated'}` and changes nothing; the socket stays open.
- **JWT defenses**: exact header match (HS256 only — blocks alg:none), `aud` `pocketmux`, `sub` must equal `deviceId`, 1h expiry, ≤60s future-`iat` skew.
- **WS relay**: `sdp_offer`/`sdp_answer`/`ice_candidate`/`connection_rejected` relay only whitelisted fields; unpaired senders are dropped silently (`connect_request` instead gets `connection_rejected` `not_paired`). Relay failure → `peer_unavailable` to sender.
- **Alarm lifecycle**: every 30s (`ALARM_INTERVAL_MS`) while sockets remain; closes sockets idle >90s (`WS_IDLE_TIMEOUT_MS`), cleans expired pairing codes, expires `signaling_sessions`. Scheduled on WS upgrade (`scheduleAlarmIfNeeded()`), pulled earlier (never later) by `scheduleAlarmBy()`. Unanswered `connect_request` → `peer_unavailable` to both ends after 12s; session also cleared wherever `host_offline` is sent [SB-1001].
- **Idle timeout is coupled to the agent heartbeat**: 90s = 3× the agent's 30s heartbeat, but only 2× at its 45s keepalive clamp cap (zero dropped-heartbeat margin). Don't raise that cap or lower the timeout without checking the other side.
- **TURN credential cache**: requested with 24h TTL, shared by all paired devices (`/turn/credentials` returns 403 `Device not paired` for a host with no mobile or a mobile with no host), refetched once older than 1h. Concurrent refetches share one in-flight request (5s timeout); on Realtime API failure, cached creds up to 12h old are served instead of a 502. Persisted to DO KV (`turn_cache`) — the one server-owned secret stored besides pairings; no user data [SB-1003].
