# pmux-server

[![Test Results](https://img.shields.io/github/actions/workflow/status/shiftinbits/pmux-server/test.yml?branch=main&logo=vitest&logoColor=white&label=tests)](https://github.com/shiftinbits/pmux-server/actions/workflows/test.yml?query=branch%3Amain) [![Code Coverage](https://img.shields.io/codecov/c/github/shiftinbits/pmux-server?logo=codecov&logoColor=white)](https://app.codecov.io/gh/shiftinbits/pmux-server/) [![CodeQL Results](https://github.com/ShiftinBits/pmux-server/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/ShiftinBits/pmux-server/actions/workflows/github-code-scanning/codeql) [![Snyk Security Monitored](https://img.shields.io/badge/security-monitored-8A2BE2?logo=snyk)](https://snyk.io/test/github/shiftinbits/pmux-server) [![License](https://img.shields.io/badge/license-MIT-3DA639?logo=opensourceinitiative&logoColor=white)](LICENSE)

Cloudflare Worker + Durable Object signaling server for [pmux](https://pmux.io).

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

## License

MIT — see [LICENSE](./LICENSE)
