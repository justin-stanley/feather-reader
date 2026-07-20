/**
 * Runtime configuration for the FeatherReader atproto OAuth sidecar.
 *
 * Everything is env-driven. The sidecar owns the OAuth handshake (PAR / PKCE /
 * DPoP / token refresh) via `@atproto/oauth-client-node`; the Rust server
 * (`featherreader`) talks to it over a small internal HTTP API guarded by a
 * shared secret. See `README`/module docs in `server.ts` for the exact contract.
 *
 * | Variable                       | Default                                   | Meaning |
 * |--------------------------------|-------------------------------------------|---------|
 * | `SIDECAR_PORT`                 | `8081`                                    | TCP port the sidecar binds (loopback). |
 * | `SIDECAR_HOST`                 | `127.0.0.1`                               | Bind host. |
 * | `SIDECAR_PUBLIC_URL`           | `http://127.0.0.1:8081`                   | The sidecar's own externally-reachable base URL. In prod: `https://feather-reader.com/oauth` if fronted at that path, else its own subdomain. Determines `client_id`, `redirect_uri`, `client-metadata.json` location. |
 * | `SIDECAR_DB`                   | `oauth-sidecar.db`                        | SQLite file for the OAuth state + session stores. |
 * | `SIDECAR_INTERNAL_SECRET`     | *(required in prod; dev default warned)*  | Shared secret the Rust server sends as `X-Internal-Secret` on `/internal/*`. |
 * | `SIDECAR_APP_CALLBACK_URL`     | `http://localhost:8080/oauth/callback`    | The Rust app's callback the sidecar redirects the browser back to after a successful login, with `?session_id=…` (or `?error=…`). |
 * | `SIDECAR_HANDLE_RESOLVER`      | `https://bsky.social`                     | Bootstrap host for handle resolution. |
 * | `SIDECAR_PLC_DIRECTORY`        | `https://plc.directory`                   | PLC directory for did:plc resolution. |
 * | `SIDECAR_DEV`                  | auto (`true` when PUBLIC_URL is localhost)| Force the atproto localhost dev-client rules on/off. |
 *
 * In "dev" mode (localhost `SIDECAR_PUBLIC_URL`) the client uses atproto's
 * special localhost development client: `client_id` is
 * `http://localhost?redirect_uri=…&scope=…` and no published JWKS is required,
 * so the sidecar boots and is manually testable with zero PKI. In production the
 * client is a confidential client with a real published `client-metadata.json`
 * and a signed JWKS.
 */

export interface SidecarConfig {
  host: string;
  port: number;
  /** The sidecar's own base URL (no trailing slash). client-metadata lives at `${publicUrl}/client-metadata.json`. */
  publicUrl: string;
  dbPath: string;
  /** Shared secret required on every `/internal/*` request via `X-Internal-Secret`. */
  internalSecret: string;
  /** Where the browser is redirected after login: `${appCallbackUrl}?session_id=…`. */
  appCallbackUrl: string;
  handleResolver: string;
  plcDirectory: string;
  /** True → atproto localhost dev-client rules (no JWKS, `http://localhost` client_id). */
  dev: boolean;
  /** The OAuth scope requested. FeatherReader needs generic read+write of its own repo records. */
  scope: string;
  /**
   * Raw `SIDECAR_ENC_KEY` value used to derive the at-rest AEAD key. `undefined`
   * only in dev (stores fall back to plaintext); required + length-guarded in prod.
   */
  encKey: string | undefined;
  /** Absolute session lifetime (ms): a session older than this is reaped even if used. */
  sessionAbsoluteTtlMs: number;
  /** Idle session lifetime (ms): a session untouched for this long is reaped. */
  sessionIdleTtlMs: number;
  /** How often (ms) the TTL reaper sweeps expired sessions. */
  reaperIntervalMs: number;
}

/** The insecure dev default for the internal secret (must never boot in prod). */
export const DEV_INTERNAL_SECRET = 'dev-internal-secret-change-me';
/** Minimum accepted length (bytes) for prod secrets/keys. */
export const MIN_SECRET_BYTES = 32;

function envStr(key: string, fallback: string): string {
  const v = process.env[key];
  return v !== undefined && v.trim() !== '' ? v.trim() : fallback;
}

function envOpt(key: string): string | undefined {
  const v = process.env[key];
  return v !== undefined && v.trim() !== '' ? v.trim() : undefined;
}

function envIntMs(key: string, fallback: number): number {
  const v = envOpt(key);
  if (v === undefined) return fallback;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`${key}: expected a positive integer (ms), got ${JSON.stringify(v)}`);
  }
  return n;
}

/** Byte length of a UTF-8 string (what "≥32 bytes" is measured against). */
function byteLen(s: string): number {
  return Buffer.byteLength(s, 'utf8');
}

function stripSlash(u: string): string {
  return u.replace(/\/+$/, '');
}

function isLocalhostUrl(u: string): boolean {
  try {
    const h = new URL(u).hostname;
    return h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1';
  } catch {
    return false;
  }
}

export function loadConfig(): SidecarConfig {
  const port = Number.parseInt(envStr('SIDECAR_PORT', '8081'), 10);
  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    throw new Error(`SIDECAR_PORT: invalid port ${process.env.SIDECAR_PORT ?? ''}`);
  }
  const host = envStr('SIDECAR_HOST', '127.0.0.1');
  const publicUrl = stripSlash(envStr('SIDECAR_PUBLIC_URL', `http://127.0.0.1:${port}`));
  const dbPath = envStr('SIDECAR_DB', 'oauth-sidecar.db');
  const appCallbackUrl = envStr('SIDECAR_APP_CALLBACK_URL', 'http://localhost:8080/oauth/callback');
  const handleResolver = envStr('SIDECAR_HANDLE_RESOLVER', 'https://bsky.social');
  const plcDirectory = envStr('SIDECAR_PLC_DIRECTORY', 'https://plc.directory');
  const scope = envStr('SIDECAR_SCOPE', 'atproto transition:generic');

  // `dev` here drives ONLY the atproto client shape (localhost dev-client vs.
  // published confidential client / PKI). It is intentionally still allowed to
  // be inferred from a localhost PUBLIC_URL — that inference does not relax any
  // security guard.
  const devForced = envOpt('SIDECAR_DEV');
  const dev =
    devForced !== undefined ? /^(1|true|yes|on)$/i.test(devForced) : isLocalhostUrl(publicUrl);

  // `securityDev` drives the FAIL-LOUD secret/key guards below. Unlike `dev`,
  // it is NOT inferred from a localhost PUBLIC_URL: a dev bypass must be an
  // explicit `SIDECAR_DEV` opt-in, so a misconfigured prod box that happens to
  // have a loopback PUBLIC_URL still refuses insecure secrets.
  const securityDev = devForced !== undefined && /^(1|true|yes|on)$/i.test(devForced);

  // --- shared internal secret (fail-loud in prod) -------------------------
  const rawSecret = envOpt('SIDECAR_INTERNAL_SECRET');
  let internalSecret: string;
  if (rawSecret === undefined) {
    if (securityDev) {
      internalSecret = DEV_INTERNAL_SECRET;
      // oxlint-disable-next-line no-console
      console.warn(
        '[config] SIDECAR_INTERNAL_SECRET unset — using an insecure dev default (SIDECAR_DEV set). NEVER do this in prod.',
      );
    } else {
      throw new Error(
        'SIDECAR_INTERNAL_SECRET is required in production. Set a random value ≥32 bytes ' +
          '(or set SIDECAR_DEV=true for an explicit local dev stack).',
      );
    }
  } else if (!securityDev) {
    // Prod: refuse the dev default and refuse anything too short/weak.
    if (rawSecret === DEV_INTERNAL_SECRET) {
      throw new Error(
        'SIDECAR_INTERNAL_SECRET is the insecure dev default — refusing to boot in production. ' +
          'Set a random value ≥32 bytes.',
      );
    }
    if (byteLen(rawSecret) < MIN_SECRET_BYTES) {
      throw new Error(
        `SIDECAR_INTERNAL_SECRET is too short (${byteLen(rawSecret)} bytes; need ≥${MIN_SECRET_BYTES}). ` +
          'Refusing to boot in production.',
      );
    }
    internalSecret = rawSecret;
  } else {
    internalSecret = rawSecret;
  }

  // --- at-rest encryption key (fail-loud in prod) -------------------------
  const rawEncKey = envOpt('SIDECAR_ENC_KEY');
  let encKey: string | undefined;
  if (rawEncKey === undefined) {
    if (securityDev) {
      encKey = undefined; // stores fall back to plaintext for a local dev stack
      // oxlint-disable-next-line no-console
      console.warn(
        '[config] SIDECAR_ENC_KEY unset — persisting OAuth tokens/JWK in PLAINTEXT (SIDECAR_DEV set). ' +
          'Set SIDECAR_ENC_KEY (via fly secrets) before any real deploy.',
      );
    } else {
      throw new Error(
        'SIDECAR_ENC_KEY is required in production (at-rest token/JWK encryption). ' +
          'Deliver a random value ≥32 bytes via fly secrets; never write it to the volume. ' +
          '(Or set SIDECAR_DEV=true for an explicit local dev stack.)',
      );
    }
  } else if (!securityDev && byteLen(rawEncKey) < MIN_SECRET_BYTES) {
    throw new Error(
      `SIDECAR_ENC_KEY is too short (${byteLen(rawEncKey)} bytes; need ≥${MIN_SECRET_BYTES}). ` +
        'Refusing to boot in production.',
    );
  } else {
    encKey = rawEncKey;
  }

  // --- session TTLs + reaper cadence --------------------------------------
  const sessionAbsoluteTtlMs = envIntMs('SIDECAR_SESSION_ABS_TTL_MS', 90 * 24 * 60 * 60 * 1000); // 90d
  const sessionIdleTtlMs = envIntMs('SIDECAR_SESSION_IDLE_TTL_MS', 30 * 24 * 60 * 60 * 1000); // 30d
  const reaperIntervalMs = envIntMs('SIDECAR_REAPER_INTERVAL_MS', 60 * 60 * 1000); // 1h

  return {
    host,
    port,
    publicUrl,
    dbPath,
    internalSecret,
    appCallbackUrl,
    handleResolver,
    plcDirectory,
    dev,
    scope,
    encKey,
    sessionAbsoluteTtlMs,
    sessionIdleTtlMs,
    reaperIntervalMs,
  };
}
