/**
 * Resolving the real client IP for rate-limit keying.
 *
 * Lives in its own module so it can be unit-tested: `server.ts` opens the DB and
 * calls `app.listen()` at import scope, so nothing defined in it is reachable
 * from a test.
 *
 * ## One configured header, not a guessed order
 *
 * Which header carries the visitor is a property of the DEPLOYMENT, not of the
 * code, so it is configuration (`SIDECAR_TRUSTED_IP_HEADER`) rather than a
 * built-in preference list. This mirrors the Rust server's
 * `FEATHERREADER_TRUSTED_IP_HEADER` and its `client_ip()` in `src/web.rs`, so
 * both halves of the app agree on who the client is by construction.
 *
 * The distinction matters because every hop rewrites what "the peer" means:
 *
 * ```
 *   visitor → Cloudflare (Full-strict) → Fly proxy → Caddy :8080 → sidecar :8081
 * ```
 *
 *  - `cf-connecting-ip` is set by Cloudflare to the **true visitor**, with any
 *    client-supplied copy stripped at the edge. It is authoritative only because
 *    `deploy/Caddyfile` 403s any request lacking Cloudflare's injected
 *    `X-Origin-Auth` secret (and fails closed when that secret is unset), so a
 *    request reaching this sidecar provably transited Cloudflare. This is the
 *    value to configure for the deployed topology.
 *  - `fly-client-ip` is set by Fly to the peer **Fly** sees — behind Cloudflare
 *    that is the CF edge, not the visitor. Correct only where Fly is the
 *    outermost proxy.
 *
 * Naming a header here is therefore also asserting "every request provably
 * transits the proxy that sets it". Configure one that an arbitrary client can
 * set and the limiter becomes trivially evadable — which is exactly why this is
 * a deliberate, per-deployment choice rather than a default.
 *
 * Raw `X-Forwarded-For` is never special-cased: it is only ever consulted if an
 * operator explicitly names it, which they should not behind an edge that does
 * not rewrite it. Fastify is likewise constructed without `trustProxy`, so it
 * never parses `X-Forwarded-*` into `req.ip` either.
 */

import type { IncomingHttpHeaders } from 'node:http';

/**
 * The part of a request this needs. Structurally satisfied by `FastifyRequest`,
 * so the generated key function can be handed straight to `@fastify/rate-limit`
 * while staying trivially constructible in a test.
 */
export interface ClientIpSource {
  headers: IncomingHttpHeaders;
  ip: string;
}

/**
 * The right-most comma-separated entry of a header, trimmed.
 *
 * A trusted proxy appends its observation last, so anything to the left may be
 * client-forged. Mirrors `client_ip` in `src/web.rs`, which takes
 * `raw.split(',').next_back()` for the same reason. Returns `null` for a missing
 * header, an array-valued one (a repeated header is not something our proxies
 * emit, and guessing which copy is authoritative would be exactly the wrong
 * instinct), or an empty value.
 */
function rightmost(headers: IncomingHttpHeaders, name: string): string | null {
  const raw = headers[name];
  if (typeof raw !== 'string') return null;
  const parts = raw.split(',');
  const last = parts[parts.length - 1]?.trim();
  return last ? last : null;
}

/**
 * Rate-limit key: the true client IP, per the configured trusted header.
 *
 * `trustedHeader` must already be lower-cased — Node lower-cases incoming header
 * names, and `loadConfig` normalises the configured value to match.
 *
 * Falls back to the socket peer when no header is configured, or when the
 * configured one is absent/unusable. Behind the in-container Caddy hop that peer
 * is permanently loopback, so the fallback means one bucket shared by every such
 * request. That is deliberately the *safe* direction — over-limiting rather than
 * a bypass — but it shows up as unexplained 429s rather than as silently
 * unlimited traffic, which is why `SIDECAR_TRUSTED_IP_HEADER` is required in
 * production instead of quietly defaulting.
 */
export function clientIp(req: ClientIpSource, trustedHeader: string | null): string {
  if (trustedHeader) {
    const found = rightmost(req.headers, trustedHeader);
    if (found) return found;
  }
  return req.ip;
}

/**
 * Bind a trusted header to produce a `@fastify/rate-limit` `keyGenerator`.
 * Resolved once at boot so the per-request path stays a single header lookup.
 */
export function clientIpKeyGenerator(
  trustedHeader: string | null,
): (req: ClientIpSource) => string {
  return (req) => clientIp(req, trustedHeader);
}
