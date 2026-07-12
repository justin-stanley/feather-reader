/**
 * Builds the `NodeOAuthClient` (`@atproto/oauth-client-node`) — the component
 * that owns the whole atproto OAuth dance so the Rust server never touches
 * PAR / PKCE / DPoP / token refresh.
 *
 * Two client shapes, chosen by {@link SidecarConfig.dev}:
 *
 *  - **dev / localhost** — atproto's special *localhost development client*.
 *    `client_id` is `http://localhost` with the redirect_uri + scope encoded as
 *    query params; no JWKS and no published metadata document are required, so
 *    the sidecar boots and is manually testable with zero PKI. (This is the path
 *    the design's "truly-zero-config localhost is login-limited" caveat refers
 *    to — it works against real PDSes for testing.)
 *
 *  - **production** — a confidential client with a real, edge-reachable
 *    `client-metadata.json` at `${publicUrl}/client-metadata.json`, a signed
 *    JWKS (`jwks_uri` → `${publicUrl}/jwks.json`), and
 *    `token_endpoint_auth_method: private_key_jwt`. The signing keypair is
 *    generated once and persisted to disk next to the DB (`<db>.jwk.json`) so it
 *    survives restarts; the *public* half is what the JWKS endpoint serves.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { NodeOAuthClient, type OAuthClientMetadataInput } from '@atproto/oauth-client-node';
import { JoseKey } from '@atproto/jwk-jose';
import type { SidecarConfig } from './config.js';
import type { SqliteStores } from './stores.js';

/** Where the persisted signing key lives (prod only). */
function keyPath(cfg: SidecarConfig): string {
  return `${cfg.dbPath}.jwk.json`;
}

/** Load or generate the confidential-client signing key (persisted to disk). */
async function loadOrCreateKey(cfg: SidecarConfig): Promise<JoseKey> {
  const path = keyPath(cfg);
  if (existsSync(path)) {
    const jwk = JSON.parse(readFileSync(path, 'utf8'));
    return JoseKey.fromJWK(jwk);
  }
  const key = await JoseKey.generate(['ES256'], 'featherreader-oauth-1');
  writeFileSync(path, JSON.stringify(key.privateJwk), { mode: 0o600 });
  return key;
}

/**
 * The client metadata document served at `GET /client-metadata.json`.
 * In dev this is the localhost dev-client's synthesized metadata; in prod it is
 * the real published document. Exposed separately so the HTTP layer can serve it
 * verbatim from `client.clientMetadata`.
 */
export function buildClientMetadata(cfg: SidecarConfig): OAuthClientMetadataInput {
  const redirectUri = `${cfg.publicUrl}/callback`;

  if (cfg.dev) {
    // atproto localhost development client. The client_id encodes redirect_uri +
    // scope; the library recognizes the `http://localhost` prefix and applies the
    // dev-client rules (no JWKS required, PDS trusts loopback redirect).
    const params = new URLSearchParams();
    params.set('redirect_uri', redirectUri);
    params.set('scope', cfg.scope);
    return {
      client_id: `http://localhost?${params.toString()}`,
      client_name: 'FeatherReader (dev)',
      redirect_uris: [redirectUri],
      scope: cfg.scope,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      application_type: 'web',
      token_endpoint_auth_method: 'none',
      dpop_bound_access_tokens: true,
    };
  }

  // Production confidential client.
  return {
    client_id: `${cfg.publicUrl}/client-metadata.json`,
    client_name: 'FeatherReader',
    client_uri: cfg.publicUrl,
    redirect_uris: [redirectUri],
    scope: cfg.scope,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    application_type: 'web',
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'ES256',
    dpop_bound_access_tokens: true,
    jwks_uri: `${cfg.publicUrl}/jwks.json`,
  };
}

export interface BuiltClient {
  client: NodeOAuthClient;
  metadata: OAuthClientMetadataInput;
  /** Public JWKS to serve at `/jwks.json` (prod). `null` in dev. */
  jwks: { keys: unknown[] } | null;
}

export async function buildOAuthClient(
  cfg: SidecarConfig,
  stores: SqliteStores,
): Promise<BuiltClient> {
  const metadata = buildClientMetadata(cfg);

  const common = {
    clientMetadata: metadata,
    stateStore: stores.stateStore(),
    sessionStore: stores.sessionStore(),
    // Handle resolver bootstrap host; the library resolves handle→DID→PDS itself
    // and defaults DID (did:plc) resolution to the public PLC directory.
    handleResolver: cfg.handleResolver,
    // In dev/localhost the issuer/PDS may be plain http (a local PDS); allow it.
    allowHttp: cfg.dev,
  };

  if (cfg.dev) {
    const client = new NodeOAuthClient(common);
    return { client, metadata, jwks: null };
  }

  const key = await loadOrCreateKey(cfg);
  const client = new NodeOAuthClient({ ...common, keyset: [key] });
  return { client, metadata, jwks: { keys: [key.publicJwk] } };
}
