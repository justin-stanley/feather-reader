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
 * The `session_id` is a bearer handoff token — it is only ever transmitted app↔
 * sidecar (both loopback / same tunnel) and resolved once; it does not itself
 * authenticate PDS calls (those go by `did` + the secret).
 */

import { randomBytes } from 'node:crypto';
import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import { Agent } from '@atproto/api';
import { loadConfig } from './config.js';
import { SqliteStores } from './stores.js';
import { buildOAuthClient } from './oauth.js';

const cfg = loadConfig();
const stores = new SqliteStores(cfg.dbPath);
const { client: oauthClient, metadata, jwks } = await buildOAuthClient(cfg, stores);

const app = Fastify({ logger: { level: process.env.SIDECAR_LOG_LEVEL ?? 'info' } });

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
    return { error: 'NotFound', message: 'no published JWKS in dev/localhost mode' };
  }
  reply.header('content-type', 'application/json');
  return jwks;
});

// ─── Public: begin OAuth ─────────────────────────────────────────────────────

app.get('/login', async (req: FastifyRequest, reply: FastifyReply) => {
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
    req.log.error({ err }, 'authorize failed');
    reply.code(400);
    return {
      error: 'AuthorizeFailed',
      message: err instanceof Error ? err.message : String(err),
    };
  }
});

// ─── Public: OAuth callback ──────────────────────────────────────────────────

app.get('/callback', async (req: FastifyRequest, reply: FastifyReply) => {
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
      appReturn ? { session_id: sessionId, return: appReturn } : { session_id: sessionId },
    );
    reply.redirect(target);
  } catch (err) {
    req.log.error({ err }, 'callback failed');
    const target = withQuery(cfg.appCallbackUrl, {
      error: 'OAuthCallbackFailed',
      error_description: err instanceof Error ? err.message : String(err),
    });
    reply.redirect(target);
  }
});

// ─── Internal: shared-secret guard ───────────────────────────────────────────

function requireSecret(req: FastifyRequest, reply: FastifyReply): boolean {
  const got = req.headers['x-internal-secret'];
  const want = cfg.internalSecret;
  // Constant-time-ish compare on strings of equal length.
  if (typeof got !== 'string' || got.length !== want.length) {
    reply.code(403).send({ ok: false, error: 'Forbidden', message: 'bad or missing X-Internal-Secret' });
    return false;
  }
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= got.charCodeAt(i) ^ want.charCodeAt(i);
  if (diff !== 0) {
    reply.code(403).send({ ok: false, error: 'Forbidden', message: 'bad or missing X-Internal-Secret' });
    return false;
  }
  return true;
}

app.get('/internal/health', async (req, reply) => {
  if (!requireSecret(req, reply)) return;
  return { ok: true };
});

app.get('/internal/session/:id', async (req: FastifyRequest, reply: FastifyReply) => {
  if (!requireSecret(req, reply)) return;
  const { id } = req.params as { id: string };
  const row = stores.getAppSession(id);
  if (!row) {
    reply.code(404);
    return { error: 'SessionNotFound', message: 'no such session id' };
  }
  return { did: row.did, handle: row.handle };
});

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
    return { ok: false, error: 'BadRequest', message: 'did and action are required' };
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
        if (!body.collection) return badReq(reply, 'collection required for list');
        const res = await agent.com.atproto.repo.listRecords({
          repo: did,
          collection: body.collection,
          limit: body.limit ?? 100,
          cursor: body.cursor,
        });
        return { ok: true, data: res.data };
      }
      case 'create': {
        if (!body.collection) return badReq(reply, 'collection required for create');
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
        if (!body.collection) return badReq(reply, 'collection required for put');
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
        if (!body.collection) return badReq(reply, 'collection required for delete');
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
              throw new Error(`unknown write action for collection ${w.collection}`);
          }
        });
        const res = await agent.com.atproto.repo.applyWrites({ repo: did, writes });
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

// ─── Boot ────────────────────────────────────────────────────────────────────

try {
  await app.listen({ host: cfg.host, port: cfg.port });
  app.log.info(
    {
      publicUrl: cfg.publicUrl,
      dev: cfg.dev,
      appCallbackUrl: cfg.appCallbackUrl,
      clientId: metadata.client_id,
    },
    'featherreader-oauth-sidecar listening',
  );
} catch (err) {
  app.log.error({ err }, 'failed to start');
  process.exit(1);
}

// Graceful shutdown flushes the WAL / closes the DB.
for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, async () => {
    try {
      await app.close();
    } finally {
      stores.close();
      process.exit(0);
    }
  });
}
