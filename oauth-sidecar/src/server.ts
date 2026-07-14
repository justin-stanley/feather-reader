/**
 * FeatherReader atproto OAuth sidecar — HTTP server.
 *
 * This is the small TypeScript/Node component that owns the atproto OAuth
 * confidential-client handshake (PAR / PKCE / DPoP / token refresh) via
 * `@atproto/oauth-client-node`, so the Rust server (`featherreader`) never has to
 * touch any of it. The Rust side keeps a signed session cookie keyed by DID and
 * makes `com.atproto.repo.*` calls *through this sidecar* over a shared-secret
 * internal API.
 *
 * ─── PUBLIC (browser-facing) endpoints ───────────────────────────────────────
 *
 *  GET /client-metadata.json
 *    The OAuth client metadata document (dev localhost client or prod
 *    confidential client — see `oauth.ts`). Content-Type: application/json.
 *
 *  GET /jwks.json                        (prod only; 404 in dev)
 *    The public JWKS for the confidential client's signing key.
 *
 *  GET /login?handle=<handle-or-did>
 *    Begins OAuth: resolves handle → DID → PDS, does PAR, then 302-redirects the
 *    browser to the PDS authorize URL. Optional `?return=<opaque>` is round-
 *    tripped back to the app callback as `&return=<opaque>`.
 *
 *  GET /callback?code=…&state=…&iss=…
 *    Completes OAuth (the library validates state, exchanges the code with DPoP,
 *    persists the per-DID session). Mints an opaque `session_id`, stores
 *    `session_id → {did, handle}`, then 302-redirects the browser to the Rust
 *    app's callback:  `${SIDECAR_APP_CALLBACK_URL}?session_id=<id>[&return=…]`.
 *    On failure: `${SIDECAR_APP_CALLBACK_URL}?error=<slug>&error_description=…`.
 *
 * ─── INTERNAL (Rust-server-facing) endpoints ─────────────────────────────────
 * All require header  `X-Internal-Secret: <SIDECAR_INTERNAL_SECRET>`  (403 on
 * mismatch). JSON in, JSON out.
 *
 *  GET  /internal/session/:id   → 200 {did, handle} | 404 {error}
 *    Resolve a session id to who is logged in. (The Rust app calls this to learn
 *    the DID behind a cookie it holds.)
 *
 *  POST /internal/revoke        → 200 {ok:true, did, revoked, hadSession}
 *    Body: { did }. Revokes the DID's tokens at the PDS (`oauthClient.revoke`)
 *    AND purges the local oauth_session + app_session rows. Idempotent.
 *
 * Every `com.atproto.repo.*` write/list is bounded to the `community.lexicon.rss.*`
 * namespace (see `collections.ts`) — a compromised app/secret can only touch RSS
 * records, not the user's whole PDS. Out-of-namespace ops return 403
 * `CollectionNotAllowed`. Stored tokens/state + the signing JWK are AEAD-encrypted
 * at rest (AES-256-GCM, key from `SIDECAR_ENC_KEY`; see `crypto.ts`). Sessions
 * past their absolute/idle TTL are swept by a periodic reaper.
 *
 *  POST /internal/repo          → the authed PDS-op API.
 *    Body: {
 *      did:        string,                 // whose repo (must have a live session)
 *      action:     "list"|"create"|"put"|"delete"|"applyWrites",
 *      collection?: string,                // required for list/create/put/delete
 *      rkey?:      string,                 // required for put/delete
 *      record?:    object,                 // required for create/put; the record body
 *      cursor?:    string,                 // list pagination
 *      limit?:     number,                 // list page size (default 100)
 *      writes?:    Array<{                 // required for applyWrites
 *        $type|action?: "create"|"update"|"delete",
 *        collection: string, rkey?: string, value?: object
 *      }>
 *    }
 *    The sidecar `restore(did)`s the OAuth session (refreshing tokens as needed),
 *    gets a DPoP-bound authenticated fetch, and performs the corresponding
 *    `com.atproto.repo.*` XRPC call. Returns the PDS JSON verbatim under `data`:
 *      200 { ok: true, data: <xrpc-response-json> }
 *      4xx/5xx { ok: false, error: "<slug>", message: "<detail>", status?: n }
 *    `error: "SessionNotFound"` (404) when no OAuth session exists for the DID —
 *    the Rust app should treat that as "re-login required".
 *
 *  GET  /internal/health        → 200 {ok:true}  (secret-guarded liveness)
 *
 * ─── SESSION-ID HANDOFF (summary for the Rust integration) ───────────────────
 *  1. Rust app links the user to  `${SIDECAR_PUBLIC_URL}/login?handle=…`.
 *  2. Sidecar drives OAuth, then redirects to
 *     `${SIDECAR_APP_CALLBACK_URL}?session_id=<opaque>`.
 *  3. Rust `/oauth/callback` reads `session_id`, calls
 *     `GET /internal/session/<id>` (with the secret) → `{did, handle}`,
 *     sets its own signed cookie keyed by that DID.
 *  4. For every PDS read/write the Rust app calls `POST /internal/repo`
 *     with `{did, action, …}` and the secret.
 * The `session_id` is a bearer handoff token — it is SINGLE-USE (deleted on the
 * first successful `GET /internal/session/:id`) and TTL-bounded (rejected after
 * HANDOFF_TTL_MS), so a leaked callback URL cannot be replayed; it does not
 * itself authenticate PDS calls (those go by `did` + the secret).
 */

import { randomBytes } from 'node:crypto';
import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { Agent } from '@atproto/api';
import { loadConfig } from './config.js';
import { SqliteStores, type SessionTtls } from './stores.js';
import { buildOAuthClient } from './oauth.js';
import { Aead, NullCodec, type Codec } from './crypto.js';
import { isAllowedCollection, ALLOWED_COLLECTION_ROOT } from './collections.js';

const cfg = loadConfig();
// At-rest AEAD for stored tokens/state/JWK. In dev with no key set we use the
// pass-through NullCodec (config.ts has already warned); prod always has a key.
const codec: Codec = cfg.encKey ? new Aead(cfg.encKey) : new NullCodec();
const stores = new SqliteStores(cfg.dbPath, codec);
const {
  client: oauthClient,
  metadata,
  jwks,
} = await buildOAuthClient(cfg, stores, codec);

const ttls: SessionTtls = {
  absoluteMs: cfg.sessionAbsoluteTtlMs,
  idleMs: cfg.sessionIdleTtlMs,
};

// Freshness bound for the one-shot session-id handoff. The browser round-trips
// sidecar redirect -> app callback -> `GET /internal/session/:id` in well under
// a second; 2 minutes is generous headroom for a slow client while keeping a
// leaked callback URL useless almost immediately.
const HANDOFF_TTL_MS = 120_000;

const app = Fastify({
  logger: { level: process.env.SIDECAR_LOG_LEVEL ?? 'info' },
});

/**
 * Rate-limit key: the true client IP. Behind Fly (and optionally Cloudflare) the
 * platform sets an un-spoofable client-IP header, and the in-container Caddy hop
 * makes `req.ip` useless for limiting (it's always loopback). Prefer the platform
 * headers — matching the Rust server's trusted-IP handling — and never key on raw
 * X-Forwarded-For (which the client can spoof).
 */
function clientIp(req: FastifyRequest): string {
  const h = req.headers;
  const fly = h['fly-client-ip'];
  if (typeof fly === 'string' && fly.trim()) return fly.trim();
  const cf = h['cf-connecting-ip'];
  if (typeof cf === 'string' && cf.trim()) return cf.trim();
  return req.ip;
}

/** Per-IP budget for the public, unauthenticated browser routes. */
const PUBLIC_RATE_LIMIT = { max: 30, timeWindow: '1 minute' } as const;

// Rate limiting for the PUBLIC OAuth routes (/login, /callback): both resolve
// arbitrary handles and drive outbound PDS/identity network calls, so leaving
// them un-throttled is a resource-exhaustion + outbound-amplification vector.
// Caddy routes /oauth/* straight to this sidecar, bypassing the Rust server's
// limiter, so the throttle has to live here. `global: false` — routes opt in
// individually, so the shared-secret internal API (hit frequently by the Rust
// server) is never limited.
await app.register(rateLimit, { global: false, keyGenerator: clientIp });

function newSessionId(): string {
  return randomBytes(24).toString('base64url');
}

/** Append a query param to a URL string (handles existing `?`). */
function withQuery(base: string, params: Record<string, string>): string {
  const u = new URL(base);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return u.toString();
}

// ─── Public: client metadata + JWKS ──────────────────────────────────────────

app.get('/client-metadata.json', async (_req, reply) => {
  reply.header('content-type', 'application/json');
  return metadata;
});

app.get('/jwks.json', async (_req, reply) => {
  if (!jwks) {
    reply.code(404);
    return {
      error: 'NotFound',
      message: 'no published JWKS in dev/localhost mode',
    };
  }
  reply.header('content-type', 'application/json');
  return jwks;
});

// ─── Public: begin OAuth ─────────────────────────────────────────────────────

app.get(
  '/login',
  { config: { rateLimit: PUBLIC_RATE_LIMIT } },
  async (req: FastifyRequest, reply: FastifyReply) => {
    const q = req.query as Record<string, string | undefined>;
    const handle = (q.handle ?? '').trim();
    if (!handle) {
      reply.code(400);
      return { error: 'BadRequest', message: 'missing ?handle' };
    }
    // Round-trip an opaque app value (e.g. a post-login redirect target) via the
    // OAuth `state`; the library returns it to us at the callback.
    const appReturn = (q.return ?? '').trim();
    try {
      const url = await oauthClient.authorize(handle, {
        scope: cfg.scope,
        state: appReturn ? JSON.stringify({ r: appReturn }) : undefined,
      });
      reply.redirect(url.toString());
    } catch (err) {
      // Keep the library's detail server-side only; return a fixed slug so we don't
      // reflect internal error strings (which can embed request/token context) to
      // the browser.
      req.log.error({ err }, 'authorize failed');
      reply.code(400);
      return {
        error: 'AuthorizeFailed',
        message: 'could not start login for that handle',
      };
    }
  },
);

// ─── Public: OAuth callback ──────────────────────────────────────────────────

app.get(
  '/callback',
  { config: { rateLimit: PUBLIC_RATE_LIMIT } },
  async (req: FastifyRequest, reply: FastifyReply) => {
    const params = new URLSearchParams(req.query as Record<string, string>);
    try {
      const { session, state } = await oauthClient.callback(params);
      const did = session.did;

      // Resolve the handle for the who-is-this response (best-effort).
      let handle: string | null = null;
      try {
        const agent = new Agent(session);
        const prof = await agent.com.atproto.repo.describeRepo({ repo: did });
        handle = prof.data.handle ?? null;
      } catch {
        handle = null;
      }

      const sessionId = newSessionId();
      stores.putAppSession(sessionId, did, handle);

      let appReturn: string | undefined;
      if (state) {
        try {
          appReturn = (JSON.parse(state) as { r?: string }).r;
        } catch {
          appReturn = undefined;
        }
      }

      const target = withQuery(
        cfg.appCallbackUrl,
        appReturn
          ? { session_id: sessionId, return: appReturn }
          : { session_id: sessionId },
      );
      reply.redirect(target);
    } catch (err) {
      // Detail stays in the server log; the user-facing redirect carries a fixed
      // slug, not the library's raw error string (which can embed token/request
      // context).
      req.log.error({ err }, 'callback failed');
      const target = withQuery(cfg.appCallbackUrl, {
        error: 'OAuthCallbackFailed',
        error_description: 'login could not be completed',
      });
      reply.redirect(target);
    }
  },
);

// ─── Internal: shared-secret guard ───────────────────────────────────────────

function requireSecret(req: FastifyRequest, reply: FastifyReply): boolean {
  const got = req.headers['x-internal-secret'];
  const want = cfg.internalSecret;
  // Constant-time-ish compare on strings of equal length.
  if (typeof got !== 'string' || got.length !== want.length) {
    reply
      .code(403)
      .send({
        ok: false,
        error: 'Forbidden',
        message: 'bad or missing X-Internal-Secret',
      });
    return false;
  }
  let diff = 0;
  for (let i = 0; i < want.length; i++)
    diff |= got.charCodeAt(i) ^ want.charCodeAt(i);
  if (diff !== 0) {
    reply
      .code(403)
      .send({
        ok: false,
        error: 'Forbidden',
        message: 'bad or missing X-Internal-Secret',
      });
    return false;
  }
  return true;
}

app.get('/internal/health', async (req, reply) => {
  if (!requireSecret(req, reply)) return;
  return { ok: true };
});

app.get(
  '/internal/session/:id',
  async (req: FastifyRequest, reply: FastifyReply) => {
    if (!requireSecret(req, reply)) return;
    const { id } = req.params as { id: string };
    const row = stores.getAppSession(id);
    if (!row) {
      reply.code(404);
      return { error: 'SessionNotFound', message: 'no such session id' };
    }
    // The handoff token is SINGLE-USE and short-lived. Consume it on the first
    // successful resolve, and reject a stale row, so a `session_id` that leaks via
    // the callback URL (browser history, proxy/tunnel access logs) is useless
    // after the one legitimate resolve or after HANDOFF_TTL_MS. Delete first, then
    // check freshness, so an expired id is also consumed (can't be retried).
    stores.deleteAppSession(id);
    if (Date.now() - row.createdAt > HANDOFF_TTL_MS) {
      reply.code(404);
      return { error: 'SessionExpired', message: 'session id expired' };
    }
    return { did: row.did, handle: row.handle };
  },
);

// ─── Internal: revoke a DID's session (logout / account teardown) ─────────────

app.post(
  '/internal/revoke',
  async (req: FastifyRequest, reply: FastifyReply) => {
    if (!requireSecret(req, reply)) return;
    const body = (req.body ?? {}) as { did?: string };
    const did = body.did;
    if (!did) {
      reply.code(400);
      return { ok: false, error: 'BadRequest', message: 'did is required' };
    }
    // Best-effort token revocation at the PDS (revokes refresh + access tokens and
    // deletes the library-managed session row). Then purge our own rows so nothing
    // lingers even if the network call failed.
    let revoked = false;
    try {
      await oauthClient.revoke(did);
      revoked = true;
    } catch (err) {
      req.log.warn(
        { err, did },
        'oauth revoke failed; purging local rows anyway',
      );
    }
    const hadSession = stores.purgeDid(did);
    return { ok: true, did, revoked, hadSession };
  },
);

// ─── Internal: authed com.atproto.repo.* ─────────────────────────────────────

interface RepoBody {
  did?: string;
  action?: 'list' | 'create' | 'put' | 'delete' | 'applyWrites';
  collection?: string;
  rkey?: string;
  record?: Record<string, unknown>;
  cursor?: string;
  limit?: number;
  writes?: Array<{
    $type?: string;
    action?: 'create' | 'update' | 'delete';
    collection: string;
    rkey?: string;
    value?: Record<string, unknown>;
  }>;
}

app.post('/internal/repo', async (req: FastifyRequest, reply: FastifyReply) => {
  if (!requireSecret(req, reply)) return;
  const body = (req.body ?? {}) as RepoBody;
  const { did, action } = body;

  if (!did || !action) {
    reply.code(400);
    return {
      ok: false,
      error: 'BadRequest',
      message: 'did and action are required',
    };
  }

  // Restore the OAuth session for this DID (refreshes tokens transparently).
  let agent: Agent;
  try {
    const session = await oauthClient.restore(did);
    agent = new Agent(session);
  } catch (err) {
    req.log.warn({ err, did }, 'no restorable OAuth session for DID');
    reply.code(404);
    return {
      ok: false,
      error: 'SessionNotFound',
      message: 'no live OAuth session for this DID — re-login required',
    };
  }

  try {
    switch (action) {
      case 'list': {
        if (!body.collection)
          return badReq(reply, 'collection required for list');
        if (!isAllowedCollection(body.collection))
          return collectionDenied(reply, body.collection);
        const res = await agent.com.atproto.repo.listRecords({
          repo: did,
          collection: body.collection,
          limit: body.limit ?? 100,
          cursor: body.cursor,
        });
        return { ok: true, data: res.data };
      }
      case 'create': {
        if (!body.collection)
          return badReq(reply, 'collection required for create');
        if (!isAllowedCollection(body.collection))
          return collectionDenied(reply, body.collection);
        if (!body.record) return badReq(reply, 'record required for create');
        const res = await agent.com.atproto.repo.createRecord({
          repo: did,
          collection: body.collection,
          rkey: body.rkey,
          record: body.record,
        });
        return { ok: true, data: res.data };
      }
      case 'put': {
        if (!body.collection)
          return badReq(reply, 'collection required for put');
        if (!isAllowedCollection(body.collection))
          return collectionDenied(reply, body.collection);
        if (!body.rkey) return badReq(reply, 'rkey required for put');
        if (!body.record) return badReq(reply, 'record required for put');
        const res = await agent.com.atproto.repo.putRecord({
          repo: did,
          collection: body.collection,
          rkey: body.rkey,
          record: body.record,
        });
        return { ok: true, data: res.data };
      }
      case 'delete': {
        if (!body.collection)
          return badReq(reply, 'collection required for delete');
        if (!isAllowedCollection(body.collection))
          return collectionDenied(reply, body.collection);
        if (!body.rkey) return badReq(reply, 'rkey required for delete');
        const res = await agent.com.atproto.repo.deleteRecord({
          repo: did,
          collection: body.collection,
          rkey: body.rkey,
        });
        return { ok: true, data: res.data };
      }
      case 'applyWrites': {
        if (!Array.isArray(body.writes) || body.writes.length === 0) {
          return badReq(reply, 'writes[] required for applyWrites');
        }
        // Allow-list EVERY write's collection before touching the PDS — one
        // out-of-namespace write fails the whole batch (applyWrites is atomic).
        for (const w of body.writes) {
          if (!isAllowedCollection(w.collection))
            return collectionDenied(reply, w.collection);
        }
        const writes = body.writes.map((w) => {
          const kind = w.action ?? w.$type?.split('#')[1];
          switch (kind) {
            case 'create':
              return {
                $type: 'com.atproto.repo.applyWrites#create' as const,
                collection: w.collection,
                rkey: w.rkey,
                value: w.value ?? {},
              };
            case 'update':
              return {
                $type: 'com.atproto.repo.applyWrites#update' as const,
                collection: w.collection,
                rkey: w.rkey ?? '',
                value: w.value ?? {},
              };
            case 'delete':
              return {
                $type: 'com.atproto.repo.applyWrites#delete' as const,
                collection: w.collection,
                rkey: w.rkey ?? '',
              };
            default:
              throw new Error(
                `unknown write action for collection ${w.collection}`,
              );
          }
        });
        const res = await agent.com.atproto.repo.applyWrites({
          repo: did,
          writes,
        });
        return { ok: true, data: res.data };
      }
      default:
        return badReq(reply, `unknown action ${String(action)}`);
    }
  } catch (err) {
    // Surface the atproto XRPC error shape where possible.
    const anyErr = err as { status?: number; error?: string; message?: string };
    const status = typeof anyErr.status === 'number' ? anyErr.status : 502;
    req.log.error({ err, did, action }, 'repo op failed');
    reply.code(status);
    return {
      ok: false,
      error: anyErr.error ?? 'RepoOpFailed',
      message: anyErr.message ?? String(err),
      status,
    };
  }
});

function badReq(reply: FastifyReply, message: string) {
  reply.code(400);
  return { ok: false, error: 'BadRequest', message };
}

/**
 * Hard server-side rejection of any write/list outside `community.lexicon.rss.*`.
 * 403 (not 400): this is an authorization bound, not a malformed request — even a
 * compromised app/secret cannot reach the user's other collections through here.
 */
function collectionDenied(reply: FastifyReply, collection: unknown) {
  reply.code(403);
  return {
    ok: false,
    error: 'CollectionNotAllowed',
    message: `collection ${JSON.stringify(collection)} is outside the allowed namespace ${ALLOWED_COLLECTION_ROOT}.*`,
  };
}

// ─── Boot ────────────────────────────────────────────────────────────────────

try {
  await app.listen({ host: cfg.host, port: cfg.port });
  app.log.info(
    {
      publicUrl: cfg.publicUrl,
      dev: cfg.dev,
      appCallbackUrl: cfg.appCallbackUrl,
      clientId: metadata.client_id,
      encAtRest: cfg.encKey ? 'aes-256-gcm' : 'PLAINTEXT(dev)',
      sessionAbsoluteTtlMs: cfg.sessionAbsoluteTtlMs,
      sessionIdleTtlMs: cfg.sessionIdleTtlMs,
    },
    'featherreader-oauth-sidecar listening',
  );
} catch (err) {
  app.log.error({ err }, 'failed to start');
  process.exit(1);
}

// ─── TTL reaper ───────────────────────────────────────────────────────────────
// Periodically sweep sessions past their absolute/idle TTL so dormant refresh
// tokens don't accumulate forever. Each expired DID is revoked at the PDS
// (best-effort) then purged locally. `unref()` so the timer never keeps the
// process alive on its own.
const reaperTimer = setInterval(() => {
  void stores
    .reap(ttls, async (did) => {
      try {
        await oauthClient.revoke(did);
      } catch (err) {
        app.log.warn({ err, did }, 'reaper: token revocation failed');
      }
    })
    .then((dids) => {
      if (dids.length > 0)
        app.log.info(
          { count: dids.length, dids },
          'reaper: purged expired sessions',
        );
    })
    .catch((err) => app.log.error({ err }, 'reaper sweep failed'));
}, cfg.reaperIntervalMs);
reaperTimer.unref();

// Graceful shutdown flushes the WAL / closes the DB.
for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, async () => {
    clearInterval(reaperTimer);
    try {
      await app.close();
    } finally {
      stores.close();
      process.exit(0);
    }
  });
}
