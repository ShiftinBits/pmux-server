/**
 * TURN Credential Generation — Cloudflare Realtime API
 *
 * Generates short-lived STUN/TURN credentials for WebRTC peer connections.
 * Credentials are requested from Cloudflare's Realtime API and include
 * STUN, TURN (UDP), and TURNS (TLS) server URLs.
 */

import type { Env } from './worker';
import type { TurnCredentials } from '@pocketmux/shared';

/** TTL for TURN credentials in seconds (1 hour). */
const CREDENTIAL_TTL = 3600;

/** Expected ICE server URLs from Cloudflare's TURN service. */
const ICE_URLS = [
  'stun:stun.cloudflare.com:3478',
  'turn:turn.cloudflare.com:3478',
  'turns:turn.cloudflare.com:5349',
] as const;

/**
 * Generate short-lived TURN credentials by calling the Cloudflare Realtime API.
 * Returns ICE server config with STUN, TURN, and TURNS URLs.
 */
export async function generateTurnCredentials(env: Env): Promise<TurnCredentials> {
  const url = `https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_TOKEN_ID}/credentials/generate`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.TURN_API_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ ttl: CREDENTIAL_TTL }),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => 'unknown error');
    console.error(`[turn] Cloudflare TURN API error (${response.status}): ${text}`);
    throw new Error(`Cloudflare TURN API error (${response.status})`);
  }

  const data = await response.json() as {
    iceServers?: { username?: string; credential?: string };
  };

  if (!data.iceServers?.username || !data.iceServers?.credential) {
    throw new Error('Invalid response from Cloudflare TURN API: missing iceServers credentials');
  }

  return {
    urls: [...ICE_URLS],
    username: data.iceServers.username,
    credential: data.iceServers.credential,
  };
}
