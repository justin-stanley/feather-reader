# FeatherReader OAuth sidecar

The small TypeScript/Node component that owns the atproto **OAuth confidential-client**
handshake (PAR / PKCE / DPoP / token refresh) via
[`@atproto/oauth-client-node`](https://www.npmjs.com/package/@atproto/oauth-client-node),
so the Rust server (`featherreader`) never touches any of it.

Per the design (and the gaming-SDK prior art), atproto OAuth is fiddly and is
**not** hand-rolled in Rust — the Rust server keeps a signed session cookie keyed
by DID and makes `com.atproto.repo.*` calls *through this sidecar* over a small,
shared-secret-guarded internal HTTP API.

## Run (dev)

```bash
npm install
npm run build
SIDECAR_PUBLIC_URL=http://127.0.0.1:8081 \
SIDECAR_APP_CALLBACK_URL=http://localhost:8080/oauth/callback \
npm start
# GET http://127.0.0.1:8081/client-metadata.json  -> the localhost dev client metadata
```

In dev/localhost mode the sidecar uses atproto's **localhost development client**
(`client_id` = `http://localhost?redirect_uri=…&scope=…`), so no published JWKS
or PKI is needed and it boots + is manually testable. See `.env.example`.

## Endpoints

### Public (browser)
| Method + path | Purpose |
|---|---|
| `GET /client-metadata.json` | OAuth client metadata (dev localhost client or prod confidential client). |
| `GET /jwks.json` | Public JWKS (prod only; 404 in dev). |
| `GET /login?handle=<handle>` | Begin OAuth: resolve handle→DID→PDS, PAR, 302 to the PDS authorize URL. Optional `?return=` round-tripped. |
| `GET /callback` | Complete OAuth, persist per-DID session, mint `session_id`, 302 to `${SIDECAR_APP_CALLBACK_URL}?session_id=…`. |

### Internal (Rust server — requires `X-Internal-Secret`)
| Method + path | Purpose |
|---|---|
| `GET /internal/session/:id` | Resolve `session_id` → `{did, handle}`. |
| `POST /internal/repo` | Authed `com.atproto.repo.*` op (`list`/`create`/`put`/`delete`/`applyWrites`) on the DID's repo. |
| `GET /internal/health` | Secret-guarded liveness. |

The exact request/response JSON shapes are documented at the top of
[`src/server.ts`](src/server.ts).

## Production

Set `SIDECAR_PUBLIC_URL=https://feather-reader.com/oauth` (or a dedicated
subdomain), a strong `SIDECAR_INTERNAL_SECRET`, and
`SIDECAR_APP_CALLBACK_URL=https://feather-reader.com/oauth/callback`. The
confidential-client signing key is generated once and persisted to
`${SIDECAR_DB}.jwk.json` (keep it with the DB volume); `/jwks.json` serves its
public half. `client-metadata.json` and `jwks.json` must be reachable at the edge.

`SIDECAR_TRUSTED_IP_HEADER` is also required in production, and the sidecar
refuses to boot without it. It names the header your edge sets to the real
client IP — `cf-connecting-ip` behind Cloudflare, `fly-client-ip` where Fly is
the outermost proxy — and it keys the rate limiter on `/login` and `/callback`.

Two things about it are worth stating plainly, because getting either wrong
fails quietly rather than loudly:

- **Name the header set by a proxy every request provably transits.** Naming one
  an arbitrary client can set makes the limiter evadable: the client just varies
  it to mint a fresh bucket per request. For `cf-connecting-ip` that guarantee
  comes from the CF-only origin lock in [`deploy/Caddyfile`](../deploy/Caddyfile),
  not from Cloudflare alone.
- **Name the outermost proxy's header, not the innermost.** Behind Cloudflare,
  Fly sets `fly-client-ip` to the *Cloudflare edge* IP, so choosing it there
  collapses every visitor behind that edge into one shared bucket — over-limiting
  that surfaces as unexplained 429s for innocent users, not as an obvious fault.

There is deliberately no default. Behind a proxy the socket peer is always
loopback, so a silent fallback would be exactly that shared-bucket failure. This
mirrors the Rust server's `FEATHERREADER_TRUSTED_IP_HEADER`; set both to the same
value.
