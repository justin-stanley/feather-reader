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
 * | `SIDECAR_PUBLIC_URL`           | `http://127.0.0.1:8081`                   | The sidecar's own externally-reachable base URL. In prod: `https://reader.justin-stanley.com/oauth` if fronted at that path, else its own subdomain. Determines `client_id`, `redirect_uri`, `client-metadata.json` location. |
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
}

function envStr(key: string, fallback: string): string {
  const v = process.env[key];
  return v !== undefined && v.trim() !== '' ? v.trim() : fallback;
}

function envOpt(key: string): string | undefined {
  const v = process.env[key];
  return v !== undefined && v.trim() !== '' ? v.trim() : undefined;
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

  const devForced = envOpt('SIDECAR_DEV');
  const dev =
    devForced !== undefined ? /^(1|true|yes|on)$/i.test(devForced) : isLocalhostUrl(publicUrl);

  // The shared secret. Required for any real deployment; in dev we allow a
  // loud default so the sidecar boots for manual testing.
  let internalSecret = envOpt('SIDECAR_INTERNAL_SECRET') ?? '';
  if (internalSecret === '') {
    if (dev) {
      internalSecret = 'dev-internal-secret-change-me';
      // eslint-disable-next-line no-console
      console.warn(
        '[config] SIDECAR_INTERNAL_SECRET unset — using an insecure dev default. Set it before any real deploy.',
      );
    } else {
      throw new Error('SIDECAR_INTERNAL_SECRET is required (no default outside dev/localhost mode)');
    }
  }

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
  };
}
