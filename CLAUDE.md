# CLAUDE.md — pmux-server

Cloudflare Worker + Durable Object signaling server for PocketMux.

## Key Rules

- This is a **Cloudflare Worker** project — use Workers runtime APIs (Web Crypto, Durable Objects, not Node.js APIs)
- Durable Object uses **SQLite** (not KV) for persistent storage
- All endpoints must match spec Section 5.1
- TypeScript strict mode, no `any`
- Worker name: `pmux-signaling`
- Custom domain: `signal.pmux.io`

## Endpoints (spec Section 5.1)

REST: `/auth/pair/initiate`, `/auth/pair/complete`, `/auth/token`, `/turn/credentials`, `/devices/:id`
WebSocket: `/ws` (via Durable Object) — auth, presence, SDP/ICE relay

## Commands

```bash
npm run dev        # npx wrangler dev (local development)
npm run deploy     # npx wrangler deploy (production)
npm test           # run tests
```

## Environment

Secrets: `TURN_TOKEN_ID`, `TURN_API_TOKEN`, `JWT_SECRET`
Set locally in `.dev.vars`, in production via `wrangler secret put`.
