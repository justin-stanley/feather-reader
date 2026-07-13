//! Runtime configuration for the FeatherReader server.
//!
//! Everything is env-driven with a sane default for every knob, so a bare
//! `./featherreader` boots and works — no config file required (the
//! "trivial to self-host" promise). The environment variables
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
//! | `FEATHERREADER_TRUSTED_IP_HEADER` | *(unset)*           | Trusted reverse-proxy header for the real client IP (e.g. `Fly-Client-IP`, `CF-Connecting-IP`). Unset trusts the socket peer only. |
//! | `FEATHERREADER_MAX_SUBS_PER_DID` | `500`                | Per-DID subscription cap. |
//! | `FEATHERREADER_MAX_FEEDS`    | `10000`                  | Global distinct-feed ceiling. |
//! | `FEATHERREADER_MAX_ENTRIES_PER_FEED` | `2000`           | Per-feed retained-entry cap (newest N). |
//! | `FEATHERREADER_DB_SIZE_WATERMARK_BYTES` | `2 GiB`       | Above this the poller stops fetching new content (0 disables). |
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
    /// Closed-beta seat cap: the maximum number of DIDs that may hold beta
    /// access at once (redeeming an invite fails with `CapacityFull` past this).
    /// From `FEATHERREADER_BETA_CAP`, default 100.
    pub beta_cap: i64,
    /// The reverse-proxy header the rate limiter TRUSTS for the real client IP,
    /// e.g. `Fly-Client-IP` (bare Fly) or `CF-Connecting-IP` (Cloudflare). When
    /// set, ONLY this header is consulted — never the spoofable multi-hop
    /// `X-Forwarded-For` chain — and it falls back to the socket peer if the
    /// header is absent/unparseable. Unset (the default) trusts the socket peer
    /// only, which is correct for a direct bind with no proxy in front.
    /// From `FEATHERREADER_TRUSTED_IP_HEADER`.
    pub trusted_ip_header: Option<String>,
    /// Per-DID subscription cap. A DID may hold at most this many subscriptions;
    /// `add_subscription` rejects over it and `import_opml` trims to it. Bounds
    /// the storage/poller blast radius of one account on a small box.
    /// From `FEATHERREADER_MAX_SUBS_PER_DID`, default 500.
    pub max_subs_per_did: i64,
    /// Global ceiling on distinct feeds in the shared cache. A new feed is
    /// refused once the `feeds` table holds this many rows (existing feeds still
    /// poll). From `FEATHERREADER_MAX_FEEDS`, default 10_000.
    pub max_feeds_global: i64,
    /// Cap on how many entries are retained per feed on insert — the newest N by
    /// published date; older rows are pruned in the same transaction so one
    /// firehose feed can't fill the disk. From `FEATHERREADER_MAX_ENTRIES_PER_FEED`,
    /// default 2_000.
    pub max_entries_per_feed: i64,
    /// DB-size watermark, in bytes. Above it the background poller stops fetching
    /// new content (and logs an alert) so the `$3.50 box` can't be filled to a
    /// crash. `0` disables the watermark. From `FEATHERREADER_DB_SIZE_WATERMARK_BYTES`,
    /// default 2 GiB.
    pub db_size_watermark_bytes: i64,
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
            beta_cap: 100,
            trusted_ip_header: None,
            max_subs_per_did: 500,
            max_feeds_global: 10_000,
            max_entries_per_feed: 2_000,
            db_size_watermark_bytes: 2 * 1024 * 1024 * 1024,
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

        let beta_cap = match env_opt("FEATHERREADER_BETA_CAP") {
            Some(raw) => raw.parse().with_context(|| {
                format!("FEATHERREADER_BETA_CAP: expected an integer, got {raw:?}")
            })?,
            None => defaults.beta_cap,
        };

        // Trusted client-IP header for the rate limiter. Normalized to lowercase
        // (header lookup is case-insensitive); unset => trust only the socket peer.
        let trusted_ip_header =
            env_opt("FEATHERREADER_TRUSTED_IP_HEADER").map(|h| h.trim().to_ascii_lowercase());

        let max_subs_per_did = match env_opt("FEATHERREADER_MAX_SUBS_PER_DID") {
            Some(raw) => raw.parse().with_context(|| {
                format!("FEATHERREADER_MAX_SUBS_PER_DID: expected an integer, got {raw:?}")
            })?,
            None => defaults.max_subs_per_did,
        };

        let max_feeds_global = match env_opt("FEATHERREADER_MAX_FEEDS") {
            Some(raw) => raw.parse().with_context(|| {
                format!("FEATHERREADER_MAX_FEEDS: expected an integer, got {raw:?}")
            })?,
            None => defaults.max_feeds_global,
        };

        let max_entries_per_feed = match env_opt("FEATHERREADER_MAX_ENTRIES_PER_FEED") {
            Some(raw) => raw.parse().with_context(|| {
                format!("FEATHERREADER_MAX_ENTRIES_PER_FEED: expected an integer, got {raw:?}")
            })?,
            None => defaults.max_entries_per_feed,
        };

        let db_size_watermark_bytes = match env_opt("FEATHERREADER_DB_SIZE_WATERMARK_BYTES") {
            Some(raw) => raw.parse().with_context(|| {
                format!("FEATHERREADER_DB_SIZE_WATERMARK_BYTES: expected an integer, got {raw:?}")
            })?,
            None => defaults.db_size_watermark_bytes,
        };

        // --- atproto OAuth sidecar --------------------------------------
        let sidecar_url = env_opt("SIDECAR_PUBLIC_URL")
            .map(|u| u.trim_end_matches('/').to_string())
            .unwrap_or_else(|| defaults.sidecar.public_url.clone());
        let internal_secret = env_opt("SIDECAR_INTERNAL_SECRET")
            .unwrap_or_else(|| defaults.sidecar.internal_secret.clone());
        let sidecar = SidecarConfig {
            public_url: sidecar_url,
            internal_secret,
        };

        let cookie_secret = env_opt("FEATHERREADER_COOKIE_SECRET")
            .unwrap_or_else(|| defaults.cookie_secret.clone());

        // A dev DID is opt-in: only present when explicitly configured, so a real
        // deployment never silently falls back to a shared identity.
        let dev_did = env_opt("FEATHERREADER_DEV_DID");

        let config = Self {
            bind,
            db_path,
            public_url,
            allowed_dids,
            poll_interval,
            retention_days,
            proxy_images,
            beta_cap,
            trusted_ip_header,
            max_subs_per_did,
            max_feeds_global,
            max_entries_per_feed,
            db_size_watermark_bytes,
            sidecar,
            cookie_secret,
            dev_did,
        };

        // FAIL LOUD: a non-loopback (public) instance must never fall back to the
        // repo-published dev secrets — those are known to any attacker, who could
        // then forge a session cookie offline. Refuse to boot instead.
        config.validate_secrets()?;

        Ok(config)
    }

    /// Whether this instance is "production-like" and therefore MUST have strong,
    /// non-default secrets. True when `FEATHERREADER_ENV=prod`, or when either the
    /// bind address or the public URL points at a non-loopback host — i.e. the
    /// server is reachable by someone other than the local operator.
    fn is_prod_like(&self) -> bool {
        if env_opt("FEATHERREADER_ENV")
            .map(|v| v.eq_ignore_ascii_case("prod") || v.eq_ignore_ascii_case("production"))
            .unwrap_or(false)
        {
            return true;
        }
        // A non-loopback bind (incl. 0.0.0.0, reachable off-box) is public; so is
        // a public_url that resolves to a non-loopback host.
        !self.bind.ip().is_loopback() || public_url_is_non_loopback(&self.public_url)
    }

    /// Enforce the secret policy for a production-like instance. On a
    /// loopback/dev instance the dev fallbacks are kept for convenience; on a
    /// public one each secret must be explicitly set, not equal to its published
    /// dev constant, and at least 32 bytes. Returns `Err` (refuse boot) otherwise.
    fn validate_secrets(&self) -> Result<()> {
        if !self.is_prod_like() {
            return Ok(());
        }
        check_secret(
            "FEATHERREADER_COOKIE_SECRET",
            &self.cookie_secret,
            DEV_COOKIE_SECRET,
        )?;
        check_secret(
            "SIDECAR_INTERNAL_SECRET",
            &self.sidecar.internal_secret,
            DEV_INTERNAL_SECRET,
        )?;
        Ok(())
    }

    /// Whether the given atproto DID is permitted to log in. When no allow-list
    /// is configured the instance is open, so every DID is allowed.
    pub fn did_allowed(&self, did: &str) -> bool {
        self.allowed_dids.is_empty() || self.allowed_dids.iter().any(|d| d == did)
    }

    /// The admin-bootstrap seed for the closed-beta gate: the DIDs that get a
    /// `beta_access` seat automatically (via [`crate::store::ensure_seed`]) so a
    /// fresh instance always has at least the operator(s) inside the gate and
    /// able to mint invite codes.
    ///
    /// Reuses `ALLOWED_DIDS` as the seed source — the same "these are the people
    /// I trust on this instance" concept — so operators don't configure the list
    /// twice. Returns a borrowed slice (empty when the instance is open / no
    /// allow-list is set, in which case there is nothing to seed).
    pub fn admin_seed_dids(&self) -> &[String] {
        &self.allowed_dids
    }
}

/// Minimum length (in bytes) for a production secret. 32 bytes = 256 bits, the
/// floor for an HMAC-SHA256 key with a full-strength security margin.
const MIN_SECRET_BYTES: usize = 32;

/// Enforce that a production secret is set, not the published dev constant, and
/// long enough. Returns a fail-loud `Err` naming the offending variable.
fn check_secret(var: &str, value: &str, dev_constant: &str) -> Result<()> {
    if value.is_empty() || value == dev_constant {
        anyhow::bail!(
            "{var} is unset or still the published dev default on a non-loopback (production) \
             instance; refusing to boot. Set {var} to a random secret of at least \
             {MIN_SECRET_BYTES} bytes."
        );
    }
    if value.len() < MIN_SECRET_BYTES {
        anyhow::bail!(
            "{var} is too short ({} bytes) for a production instance; it must be at least \
             {MIN_SECRET_BYTES} bytes.",
            value.len()
        );
    }
    Ok(())
}

/// Whether a `public_url` points at a non-loopback host. A parse failure or a
/// missing host is treated as non-loopback (fail closed toward "public").
fn public_url_is_non_loopback(public_url: &str) -> bool {
    match url::Url::parse(public_url) {
        Ok(u) => match u.host() {
            Some(url::Host::Domain(d)) => {
                !(d.eq_ignore_ascii_case("localhost") || d.eq_ignore_ascii_case("localhost."))
            }
            Some(url::Host::Ipv4(ip)) => !ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => !ip.is_loopback(),
            None => true,
        },
        Err(_) => true,
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
        assert_eq!(c.beta_cap, 100);
        // Hardening caps default to safe, non-zero bounds; no trusted proxy header.
        assert!(c.trusted_ip_header.is_none());
        assert_eq!(c.max_subs_per_did, 500);
        assert_eq!(c.max_feeds_global, 10_000);
        assert_eq!(c.max_entries_per_feed, 2_000);
        assert_eq!(c.db_size_watermark_bytes, 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn admin_seed_reuses_allowed_dids() {
        let open = Config::default();
        assert!(open.admin_seed_dids().is_empty());
        let gated = Config {
            allowed_dids: vec!["did:plc:me".to_string(), "did:plc:you".to_string()],
            ..Config::default()
        };
        assert_eq!(gated.admin_seed_dids(), &["did:plc:me", "did:plc:you"]);
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

    #[test]
    fn loopback_instance_keeps_dev_fallback_secrets() {
        // Default config is loopback + dev secrets: must be allowed to boot.
        let c = Config::default();
        assert!(!c.is_prod_like());
        assert!(c.validate_secrets().is_ok());
    }

    #[test]
    fn public_bind_with_dev_cookie_secret_refuses_boot() {
        let c = Config {
            bind: SocketAddr::from(([0, 0, 0, 0], 8080)),
            ..Config::default()
        };
        assert!(c.is_prod_like());
        // Still carries the published dev cookie secret → must fail loud.
        let err = c.validate_secrets().unwrap_err().to_string();
        assert!(err.contains("FEATHERREADER_COOKIE_SECRET"), "{err}");
    }

    #[test]
    fn public_bind_with_short_secret_refuses_boot() {
        let c = Config {
            bind: SocketAddr::from(([203, 0, 113, 5], 8080)),
            cookie_secret: "too-short".to_string(),
            ..Config::default()
        };
        assert!(c.is_prod_like());
        assert!(c.validate_secrets().is_err());
    }

    #[test]
    fn public_bind_with_dev_sidecar_secret_refuses_boot() {
        let c = Config {
            bind: SocketAddr::from(([203, 0, 113, 5], 8080)),
            // Strong cookie secret, but sidecar secret still the dev default.
            cookie_secret: "x".repeat(48),
            ..Config::default()
        };
        let err = c.validate_secrets().unwrap_err().to_string();
        assert!(err.contains("SIDECAR_INTERNAL_SECRET"), "{err}");
    }

    #[test]
    fn public_bind_with_strong_secrets_boots() {
        let c = Config {
            bind: SocketAddr::from(([203, 0, 113, 5], 8080)),
            cookie_secret: "a".repeat(48),
            sidecar: SidecarConfig {
                public_url: DEFAULT_SIDECAR_URL.to_string(),
                internal_secret: "b".repeat(48),
            },
            ..Config::default()
        };
        assert!(c.is_prod_like());
        assert!(c.validate_secrets().is_ok());
    }

    #[test]
    fn public_url_non_loopback_detection() {
        assert!(!public_url_is_non_loopback("http://localhost:8080"));
        assert!(!public_url_is_non_loopback("http://127.0.0.1:8080"));
        assert!(!public_url_is_non_loopback("http://[::1]:8080"));
        assert!(public_url_is_non_loopback(
            "https://feather-reader.com"
        ));
        assert!(public_url_is_non_loopback("http://203.0.113.5"));
    }
}
