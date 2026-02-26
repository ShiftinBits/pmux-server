# pmux-server

Cloudflare Worker + Durable Object signaling server for [PocketMux](https://github.com/ShiftinBits/pocketmux).

## Architecture

- **Worker** — HTTP ingress, auth middleware, REST endpoints for pairing and TURN credentials
- **Durable Object** — WebSocket signaling for SDP/ICE relay, device presence tracking, SQLite storage for device pairings

The server is a zero-knowledge relay. It facilitates WebRTC connection establishment between agents and mobile clients but **never** sees terminal content, session metadata, or user activity.

## Development

```bash
# Install dependencies
npm install

# Start local dev server
npm run dev          # → http://localhost:8787

# Health check
curl http://localhost:8787/health
```

## Environment Secrets

Set via `wrangler secret put <NAME>`:

| Secret | Description |
|--------|-------------|
| `TURN_TOKEN_ID` | Cloudflare Realtime TURN Token ID |
| `TURN_API_TOKEN` | Cloudflare Realtime API token |
| `JWT_SECRET` | Secret for signing JWTs |

## Deployment

```bash
npm run deploy       # → deploys to Cloudflare
```

Worker name: `pmux-signaling`
Custom domain: `signal.pocketmux.dev` (configured in Cloudflare dashboard)

## License

MIT — see [LICENSE](./LICENSE)
