//! Runtime configuration for the FeatherReader server.
//!
//! Everything is env-driven with a sane default for every knob, so a bare
//! `./featherreader` boots and works — no config file required (the OSS
//! "trivial to self-host" promise, §7 of the design). The environment variables
//! all share the `FEATHERREADER_*` prefix:
//!
//! | Variable                     | Default                  | Meaning |
//! |------------------------------|--------------------------|---------|
//! | `FEATHERREADER_BIND`         | `127.0.0.1:8080`         | `host:port` the HTTP server binds. |
//! | `FEATHERREADER_DB`           | `featherreader.db`       | Path to the SQLite cache file. |
//! | `FEATHERREADER_PUBLIC_URL`   | `http://localhost:8080`  | Externally-reachable base URL (OAuth callback + client metadata). |
//! | `FEATHERREADER_ALLOWED_DIDS` | *(empty = open)*         | Comma-separated login allow-list of atproto DIDs. |
//! | `FEATHERREADER_POLL_INTERVAL`| `3600` (1h)              | Default per-feed poll interval, in seconds. |
//! | `FEATHERREADER_RETENTION_DAYS`| `90`                    | Prune read, unstarred entries older than this. |
//! | `FEATHERREADER_PROXY_IMAGES` | `false`                  | Proxy feed images so reader IPs aren't leaked to feed hosts. |
//!
//! The atproto OAuth sidecar (`@atproto/oauth-client-node`) is configured with a
//! second small block — the base URL the Rust server reaches it on and the shared
//! secret gating its internal API (see [`SidecarConfig`]):
//!
//! | Variable                       | Default                   | Meaning |
//! |--------------------------------|---------------------------|---------|
//! | `SIDECAR_PUBLIC_URL`           | `http://127.0.0.1:8081`   | Base URL of the OAuth sidecar (its public `/login` + internal API). |
//! | `SIDECAR_INTERNAL_SECRET`      | *(dev fallback)*          | Shared `X-Internal-Secret` for the sidecar's `/internal/*` API. |
//! | `FEATHERREADER_COOKIE_SECRET`  | *(dev fallback)*          | HMAC key used to sign the session cookie. |
//! | `FEATHERREADER_DEV_DID`        | *(unset)*                 | When set, a request with no session cookie acts as this DID (local runs without the sidecar). |
//!
//! `FEATHERREADER_BIND` also accepts the design's `FEATHERREADER_ADDR` spelling
//! as a fallback for compatibility.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};

/// Fully-resolved server configuration, materialized once at startup.
#[derive(Debug, Clone)]
pub struct Config {
    /// The socket address the HTTP server binds to.
    pub bind: SocketAddr,
    /// Filesystem path to the SQLite cache/database file.
    pub db_path: PathBuf,
    /// The externally-reachable base URL (used to build the atproto OAuth
    /// callback and client-metadata URLs). No trailing slash.
    pub public_url: String,
    /// Optional login allow-list of atproto DIDs. Empty means the instance is
    /// open to any atproto identity that can log in.
    pub allowed_dids: Vec<String>,
    /// The default per-feed poll interval.
    pub poll_interval: Duration,
    /// Retention window: read, unstarred entries older than this are pruned.
    pub retention_days: u32,
    /// Whether to proxy feed images through the server (privacy vs. bandwidth).
    pub proxy_images: bool,
    /// The atproto OAuth sidecar wiring (base URL + shared internal secret).
    pub sidecar: SidecarConfig,
    /// HMAC key used to sign the session cookie. In production this MUST be set
    /// (`FEATHERREADER_COOKIE_SECRET`); a stable dev fallback is used otherwise
    /// so local runs work without configuration.
    pub cookie_secret: String,
    /// Optional dev-only DID: when set, a request with no valid session cookie
    /// is served as this DID (local runs without the OAuth sidecar). Unset in a
    /// real deployment — no session then means "logged out".
    pub dev_did: Option<String>,
}

/// Configuration for the atproto OAuth sidecar (`@atproto/oauth-client-node`).
///
/// The Rust server drives the sidecar over two surfaces:
/// * the **public** `${public_url}/login` URL the browser is redirected to, and
/// * the **internal** `${public_url}/internal/*` API (session lookup + the authed
///   `com.atproto.repo.*` proxy), gated by the shared [`internal_secret`] sent as
///   the `X-Internal-Secret` header.
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    /// Base URL of the sidecar (no trailing slash), e.g. `http://127.0.0.1:8081`.
    pub public_url: String,
    /// Shared secret for the sidecar's internal API (`X-Internal-Secret`).
    pub internal_secret: String,
}

/// The sidecar's own dev fallback for the shared secret (matches the sidecar's
/// `dev-internal-secret-change-me`) so a fully-local dev stack works untouched.
const DEV_INTERNAL_SECRET: &str = "dev-internal-secret-change-me";

/// The default sidecar base URL — loopback, matching the sidecar's own default.
const DEFAULT_SIDECAR_URL: &str = "http://127.0.0.1:8081";

/// A stable, clearly-marked dev cookie key. Overridden by
/// `FEATHERREADER_COOKIE_SECRET` in any real deployment.
const DEV_COOKIE_SECRET: &str = "featherreader-dev-cookie-secret-change-me";

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            public_url: DEFAULT_SIDECAR_URL.to_string(),
            internal_secret: DEV_INTERNAL_SECRET.to_string(),
        }
    }
}

impl SidecarConfig {
    /// The sidecar's public `/login` URL (the browser redirect target).
    pub fn login_url(&self) -> String {
        format!("{}/login", self.public_url)
    }

    /// The sidecar's `/internal/session/:id` URL.
    pub fn session_url(&self, session_id: &str) -> String {
        format!("{}/internal/session/{}", self.public_url, session_id)
    }

    /// The sidecar's `/internal/repo` URL (the authed `com.atproto.repo.*` proxy).
    pub fn repo_url(&self) -> String {
        format!("{}/internal/repo", self.public_url)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Loopback-only by default: safe for a first run; front with a
            // reverse proxy / tunnel to expose it.
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            db_path: PathBuf::from("featherreader.db"),
            public_url: "http://localhost:8080".to_string(),
            allowed_dids: Vec::new(),
            poll_interval: Duration::from_secs(3600),
            retention_days: 90,
            proxy_images: false,
            sidecar: SidecarConfig::default(),
            cookie_secret: DEV_COOKIE_SECRET.to_string(),
            dev_did: None,
        }
    }
}

impl Config {
    /// Build a [`Config`] from the process environment, falling back to the
    /// defaults above for anything unset. Returns an error only when a *present*
    /// variable fails to parse — an unset variable is never an error.
    pub fn from_env() -> Result<Self> {
        let defaults = Config::default();

        // FEATHERREADER_BIND (preferred) or FEATHERREADER_ADDR (design alias).
        let bind = match env_opt("FEATHERREADER_BIND").or_else(|| env_opt("FEATHERREADER_ADDR")) {
            Some(raw) => raw
                .parse::<SocketAddr>()
                .with_context(|| format!("FEATHERREADER_BIND: invalid socket address {raw:?}"))?,
            None => defaults.bind,
        };

        let db_path = env_opt("FEATHERREADER_DB")
            .map(PathBuf::from)
            .unwrap_or(defaults.db_path);

        let public_url = env_opt("FEATHERREADER_PUBLIC_URL")
            // Normalize away a trailing slash so callers can join paths cleanly.
            .map(|u| u.trim_end_matches('/').to_string())
            .unwrap_or(defaults.public_url);

        let allowed_dids = env_opt("FEATHERREADER_ALLOWED_DIDS")
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or(defaults.allowed_dids);

        let poll_interval = match env_opt("FEATHERREADER_POLL_INTERVAL") {
            Some(raw) => {
                let secs: u64 = raw.parse().with_context(|| {
                    format!("FEATHERREADER_POLL_INTERVAL: expected seconds, got {raw:?}")
                })?;
                Duration::from_secs(secs)
            }
            None => defaults.poll_interval,
        };

        let retention_days = match env_opt("FEATHERREADER_RETENTION_DAYS") {
            Some(raw) => raw.parse().with_context(|| {
                format!("FEATHERREADER_RETENTION_DAYS: expected an integer, got {raw:?}")
            })?,
            None => defaults.retention_days,
        };

        let proxy_images = match env_opt("FEATHERREADER_PROXY_IMAGES") {
            Some(raw) => parse_bool(&raw).with_context(|| {
                format!("FEATHERREADER_PROXY_IMAGES: expected a boolean, got {raw:?}")
            })?,
            None => defaults.proxy_images,
        };

        // --- atproto OAuth sidecar --------------------------------------
        let sidecar_url = env_opt("SIDECAR_PUBLIC_URL")
            .map(|u| u.trim_end_matches('/').to_string())
            .unwrap_or_else(|| defaults.sidecar.public_url.clone());
        let internal_secret =
            env_opt("SIDECAR_INTERNAL_SECRET").unwrap_or_else(|| defaults.sidecar.internal_secret.clone());
        let sidecar = SidecarConfig {
            public_url: sidecar_url,
            internal_secret,
        };

        let cookie_secret =
            env_opt("FEATHERREADER_COOKIE_SECRET").unwrap_or_else(|| defaults.cookie_secret.clone());

        // A dev DID is opt-in: only present when explicitly configured, so a real
        // deployment never silently falls back to a shared identity.
        let dev_did = env_opt("FEATHERREADER_DEV_DID");

        Ok(Self {
            bind,
            db_path,
            public_url,
            allowed_dids,
            poll_interval,
            retention_days,
            proxy_images,
            sidecar,
            cookie_secret,
            dev_did,
        })
    }

    /// Whether the given atproto DID is permitted to log in. When no allow-list
    /// is configured the instance is open, so every DID is allowed.
    pub fn did_allowed(&self, did: &str) -> bool {
        self.allowed_dids.is_empty() || self.allowed_dids.iter().any(|d| d == did)
    }
}

/// Read an env var, treating an empty value the same as unset.
fn env_opt(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

/// Parse a permissive boolean: `1/true/yes/on` vs `0/false/no/off`
/// (case-insensitive).
fn parse_bool(raw: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => anyhow::bail!("not a boolean: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert_eq!(c.bind.port(), 8080);
        assert_eq!(c.poll_interval, Duration::from_secs(3600));
        assert_eq!(c.retention_days, 90);
        assert!(!c.proxy_images);
        assert!(c.allowed_dids.is_empty());
    }

    #[test]
    fn open_instance_allows_any_did() {
        let c = Config::default();
        assert!(c.did_allowed("did:plc:anything"));
    }

    #[test]
    fn allow_list_gates_dids() {
        let c = Config {
            allowed_dids: vec!["did:plc:me".to_string()],
            ..Config::default()
        };
        assert!(c.did_allowed("did:plc:me"));
        assert!(!c.did_allowed("did:plc:stranger"));
    }

    #[test]
    fn parse_bool_accepts_common_spellings() {
        assert!(parse_bool("Yes").unwrap());
        assert!(!parse_bool("OFF").unwrap());
        assert!(parse_bool("maybe").is_err());
    }
}
