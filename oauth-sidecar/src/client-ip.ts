/**
 * Resolving the real client IP for rate-limit keying.
 *
 * Lives in its own module so it can be unit-tested: `server.ts` opens the DB and
 * calls `app.listen()` at import scope, so nothing defined in it is reachable
 * from a test.
 *
 * ## The deployment this reasons about
 *
 * ```
 *   visitor → Cloudflare (Full-strict) → Fly proxy → Caddy :8080 → sidecar :8081
 * ```
 *
 * Each hop rewrites what "the peer" means, so header choice is not
 * interchangeable:
 *
 *  - `cf-connecting-ip` — set by Cloudflare to the **true visitor**, with any
 *    client-supplied copy stripped at the edge. Authoritative here *because*
 *    `deploy/Caddyfile` refuses (403) any request lacking Cloudflare's injected
 *    `X-Origin-Auth` secret, and fails closed when that secret is unset — so a
 *    request that reaches this sidecar provably transited Cloudflare. This is
 *    also the header the Rust app trusts
 *    (`FEATHERREADER_TRUSTED_IP_HEADER=cf-connecting-ip` in `fly.toml`), so the
 *    two halves of the app now agree on who the client is.
 *
 *  - `fly-client-ip` — set by Fly's proxy to the peer **Fly** sees. Behind
 *    Cloudflare that is the Cloudflare edge IP, *not* the visitor. Preferring it
 *    collapses every visitor behind a given edge IP into one rate-limit bucket
 *    (see the note in `deploy/Caddyfile`: overwriting the visitor IP with the CF
 *    edge IP "defeats the whole point"). Kept only as a fallback for a
 *    Cloudflare-less deployment, where Fly is the outermost proxy and this
 *    header *is* the visitor.
 *
 *  - `req.ip` — the socket peer, which the in-container Caddy hop makes
 *    permanently loopback. Useless as a key; see {@link clientIp}.
 *
 * Raw `X-Forwarded-For` is deliberately never consulted: any client can send it.
 * Fastify is likewise constructed without `trustProxy`, so it never parses
 * `X-Forwarded-*` into `req.ip` either.
 */

import type { IncomingHttpHeaders } from 'node:http';

/**
 * The part of a request this needs. Structurally satisfied by `FastifyRequest`,
 * so `clientIp` can be handed straight to `@fastify/rate-limit` as its
 * `keyGenerator` while staying trivially constructible in a test.
 */
export interface ClientIpSource {
  headers: IncomingHttpHeaders;
  ip: string;
}

/**
 * The right-most comma-separated entry of a header, trimmed.
 *
 * A trusted proxy appends its observation last, so anything to the left may be
 * client-forged. This mirrors `client_ip` in `src/web.rs`, which takes
 * `raw.split(',').next_back()` for the same reason. Returns `null` for a missing
 * header, an array-valued one (a repeated header is not something our proxies
 * emit, and guessing which copy is authoritative would be exactly the wrong
 * instinct), or an empty value.
 */
function trustedHeader(headers: IncomingHttpHeaders, name: string): string | null {
  const raw = headers[name];
  if (typeof raw !== 'string') return null;
  const parts = raw.split(',');
  const last = parts[parts.length - 1]?.trim();
  return last ? last : null;
}

/**
 * Rate-limit key: the true client IP.
 *
 * Order matters and is the point of this function — see the module header.
 * Cloudflare's view wins, Fly's is the Cloudflare-less fallback, and the socket
 * peer is last.
 *
 * The `req.ip` fallback is reached only if neither platform header is present,
 * which in the deployed topology cannot happen. If it ever does, it degrades to
 * loopback — one shared bucket for everyone rather than a per-visitor one. That
 * is deliberately the *safe* direction (over-limiting, not a bypass), but it
 * means a missing platform header shows up as unexplained 429s rather than as
 * silently unlimited traffic.
 */
export function clientIp(req: ClientIpSource): string {
  return (
    trustedHeader(req.headers, 'cf-connecting-ip') ??
    trustedHeader(req.headers, 'fly-client-ip') ??
    req.ip
  );
}
