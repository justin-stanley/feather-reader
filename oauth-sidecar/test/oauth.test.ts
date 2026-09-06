/**
 * Tests for the OAuth client-metadata document (`src/oauth.ts`).
 *
 * This document is the sidecar's public identity to every PDS it talks to: the
 * `client_id` a PDS fetches and pins, the `redirect_uri` it will hand an
 * authorization code to, and the authentication method it expects at the token
 * endpoint. A silent change here does not fail loudly — it fails as "login
 * stopped working against real PDSes", or worse, as a client that authenticates
 * more weakly than intended. So the invariants are asserted rather than assumed.
 *
 * `buildClientMetadata` is pure (config in, document out), which is why it is
 * testable at all; `buildOAuthClient` around it needs a store, a keypair on disk
 * and a handle resolver, and is left to integration.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildClientMetadata } from '../src/oauth.js';
import type { SidecarConfig } from '../src/config.js';
import type { OAuthClientMetadataInput } from '@atproto/oauth-client-node';

/**
 * A complete config with the fields `buildClientMetadata` reads made explicit.
 * Everything else is filled with values that are valid but deliberately
 * uninteresting, so a test that starts depending on them stands out.
 */
function cfg(overrides: Partial<SidecarConfig> = {}): SidecarConfig {
  return {
    host: '127.0.0.1',
    port: 8081,
    publicUrl: 'https://reader.example.com/oauth',
    dbPath: '/tmp/unused.db',
    internalSecret: 'x'.repeat(32),
    appCallbackUrl: 'https://reader.example.com/oauth/callback',
    handleResolver: 'https://bsky.social',
    plcDirectory: 'https://plc.directory',
    dev: false,
    scope: 'atproto repo:generic',
    encKey: 'k'.repeat(32),
    sessionAbsoluteTtlMs: 1_000,
    sessionIdleTtlMs: 500,
    reaperIntervalMs: 100,
    ...overrides,
  };
}

/**
 * Parse `client_id` as a URL, failing the test if it is absent. Upstream types
 * it optional; for this sidecar it is always populated, and asserting that is
 * itself worth doing rather than casting past it.
 */
function clientIdUrl(m: OAuthClientMetadataInput): URL {
  assert.equal(typeof m.client_id, 'string', 'client_id must always be present');
  return new URL(m.client_id as string);
}

// ─── Production: confidential client ─────────────────────────────────────────

test('prod: client_id is the published metadata URL and jwks_uri sits beside it', () => {
  const m = buildClientMetadata(cfg());

  assert.equal(m.client_id, 'https://reader.example.com/oauth/client-metadata.json');
  assert.equal(m.jwks_uri, 'https://reader.example.com/oauth/jwks.json');
  assert.equal(m.client_uri, 'https://reader.example.com/oauth');
});

test('prod: authenticates with private_key_jwt over ES256, never "none"', () => {
  const m = buildClientMetadata(cfg());

  // A confidential client that advertised `none` would let anyone who learned
  // the client_id redeem codes issued for it.
  assert.equal(m.token_endpoint_auth_method, 'private_key_jwt');
  assert.equal(m.token_endpoint_auth_signing_alg, 'ES256');
});

test('prod: binds access tokens to DPoP', () => {
  // Without this a stolen bearer token is replayable from anywhere.
  assert.equal(buildClientMetadata(cfg()).dpop_bound_access_tokens, true);
});

test('prod: redirect_uris is exactly the one callback under publicUrl', () => {
  const m = buildClientMetadata(cfg());

  // Extra entries here widen where a PDS may send an authorization code.
  assert.deepEqual(m.redirect_uris, ['https://reader.example.com/oauth/callback']);
});

// ─── Dev: atproto localhost development client ───────────────────────────────

test('dev: client_id is the http://localhost dev client carrying redirect_uri + scope', () => {
  const m = buildClientMetadata(cfg({ dev: true }));

  const id = clientIdUrl(m);
  assert.equal(id.protocol, 'http:');
  assert.equal(id.hostname, 'localhost');
  assert.equal(
    id.searchParams.get('redirect_uri'),
    'https://reader.example.com/oauth/callback',
  );
  assert.equal(id.searchParams.get('scope'), 'atproto repo:generic');
});

test('dev: the redirect_uri inside client_id matches the one in redirect_uris', () => {
  // The library derives dev-client rules from the query params, while the PDS
  // also sees redirect_uris. If the two ever disagreed, the mismatch would only
  // show up as an opaque redirect_uri rejection mid-login.
  const m = buildClientMetadata(cfg({ dev: true }));

  const fromId = clientIdUrl(m).searchParams.get('redirect_uri');
  assert.deepEqual(m.redirect_uris, [fromId]);
});

test('dev: publishes no JWKS, because the dev client has no keypair', () => {
  const m = buildClientMetadata(cfg({ dev: true }));

  assert.equal(m.token_endpoint_auth_method, 'none');
  assert.equal(m.jwks_uri, undefined);
});

test('dev: still binds access tokens to DPoP', () => {
  // Weakening this in dev would make the dev path unrepresentative of prod.
  assert.equal(buildClientMetadata(cfg({ dev: true })).dpop_bound_access_tokens, true);
});

// ─── Shared shape ────────────────────────────────────────────────────────────

test('both modes request only authorization_code + refresh_token, response_type code', () => {
  for (const dev of [false, true]) {
    const m = buildClientMetadata(cfg({ dev }));
    assert.deepEqual(m.grant_types, ['authorization_code', 'refresh_token'], `dev=${dev}`);
    assert.deepEqual(m.response_types, ['code'], `dev=${dev}`);
    assert.equal(m.application_type, 'web', `dev=${dev}`);
  }
});

test('both modes propagate the configured scope verbatim', () => {
  const scope = 'atproto repo:community.lexicon.rss';
  for (const dev of [false, true]) {
    assert.equal(buildClientMetadata(cfg({ dev, scope })).scope, scope, `dev=${dev}`);
  }
});

test('publicUrl drives every derived URL, so a redeploy under a new origin stays consistent', () => {
  const m = buildClientMetadata(cfg({ publicUrl: 'https://other.example.org/sc' }));

  assert.equal(m.client_id, 'https://other.example.org/sc/client-metadata.json');
  assert.equal(m.jwks_uri, 'https://other.example.org/sc/jwks.json');
  assert.deepEqual(m.redirect_uris, ['https://other.example.org/sc/callback']);
});

test('a scope with characters needing escaping survives the dev client_id round-trip', () => {
  // The dev client_id builds its query with URLSearchParams; a scope containing
  // a space or `:` must come back byte-identical rather than mangled.
  const scope = 'atproto repo:generic transition:email';
  const m = buildClientMetadata(cfg({ dev: true, scope }));

  assert.equal(clientIdUrl(m).searchParams.get('scope'), scope);
});
