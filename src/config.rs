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
//! | `FEATHERREADER_RESOLVER_HOST` | `https://bsky.social`    | atproto handle-resolver base (`com.atproto.identity.resolveHandle`) the pre-handshake beta gate uses to honor an existing seat on a cookie-less login. |
//! | `FEATHERREADER_BOT_SECRET`   | *(unset = `/bot/claims` disabled)* | Shared bearer secret (`X-Bot-Secret`) gating the headless follow→invite bot's mint endpoint `POST /bot/claims`. Unset ⇒ endpoint returns 503. MUST be set (strong) on a production-like instance if the bot is used. |
//! | `FEATHERREADER_CLAIM_TTL_SECS` | `1209600` (14 days)   | TTL for a bot-minted claim invite code — long, since the claim link is delivered asynchronously (a public skeet). |
//! | `FEATHERREADER_RELAY_HOSTS`  | `relay1.us-west.bsky.network,relay1.us-east.bsky.network` | Relays queried for the network adoption count. Bare hosts or full URLs. Setting it to the **empty string** names no relays and so disables the probe (unset ⇒ the defaults above; the two are deliberately distinguished). |
//! | `FEATHERREADER_ADOPTION_INTERVAL_SECS` | `86400` (24h)  | Adoption-probe cadence (±10% jitter). `0` disables the probe. |
//! | `FEATHERREADER_SHOW_ADOPTION` | `false`                 | Render the one-line adoption fact on `/about`. |
//!
//! The atproto OAuth sidecar (`@atproto/oauth-client-node`) is configured with a
//! second small block — the base URL the Rust server reaches it on and the shared
//! secret gating its internal API (see [`SidecarConfig`]):
//!
//! | Variable                       | Default                   | Meaning |
//! |--------------------------------|---------------------------|---------|
//! | `SIDECAR_PUBLIC_URL`           | `http://127.0.0.1:8081`   | Public base URL of the OAuth sidecar (its browser-facing `/login`, plus the OAuth `client_id`/`redirect_uri`). |
//! | `SIDECAR_INTERNAL_URL`         | *(= `SIDECAR_PUBLIC_URL`)* | Loopback base URL the Rust server reaches the sidecar's `/internal/*` API on. Defaults to the public URL for single-URL local dev. |
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
    /// The Rust-native OAuth client's own wiring. Read whatever the backend, so
    /// a misconfiguration is caught at startup rather than at the moment the
    /// switch is thrown.
    pub oauth: OauthConfig,
    /// HMAC key used to sign the session cookie. In production this MUST be set
    /// (`FEATHERREADER_COOKIE_SECRET`); a stable dev fallback is used otherwise
    /// so local runs work without configuration.
    pub cookie_secret: String,
    /// Optional dev-only DID: when set, a request with no valid session cookie
    /// is served as this DID (local runs without the OAuth sidecar). Unset in a
    /// real deployment — no session then means "logged out".
    pub dev_did: Option<String>,
    /// Which repo implementation serves `com.atproto.repo.*` — the cutover
    /// switch. Defaults to the sidecar, so deploying the Rust client changes
    /// nothing until this is set deliberately.
    pub repo_backend: crate::metrics::Backend,
    /// Base URL of the atproto handle resolver (`com.atproto.identity.resolveHandle`),
    /// no trailing slash. Used by the pre-handshake beta gate to turn a submitted
    /// handle into a DID so an existing seat can be honored on a cookie-less first
    /// login. Defaults to [`crate::atproto::DEFAULT_RESOLVER_HOST`]. From
    /// `FEATHERREADER_RESOLVER_HOST`.
    pub resolver_base: String,
    /// Shared bearer secret gating the headless bot mint endpoint (`POST
    /// /bot/claims`), sent by the follow→invite bot as `X-Bot-Secret`. When empty
    /// the endpoint is DISABLED (503) — a bot can't mint. Like the cookie/sidecar
    /// secrets it MUST be set on a production-like instance (fail-loud at boot);
    /// on a loopback/dev instance it stays unset so `/bot/claims` is simply off
    /// until an operator opts in. From `FEATHERREADER_BOT_SECRET`.
    pub bot_secret: Option<String>,
    /// TTL (seconds) for a claim invite code minted by `POST /bot/claims`. The
    /// bot delivers the claim link asynchronously (a public skeet), so this is a
    /// generous window — the admin-mint browser flow's 30-minute TTL would expire
    /// before the follower ever taps the link. From `FEATHERREADER_CLAIM_TTL_SECS`,
    /// default 14 days.
    pub claim_ttl_secs: i64,
    /// Relay bases queried for the network adoption count, as normalized origin
    /// URLs (scheme + host, no trailing slash) — the fetch layer is handed
    /// something [`crate::net`] can scheme-allow-list rather than being asked to
    /// guess. An empty list disables the probe, and `FEATHERREADER_RELAY_HOSTS=`
    /// (present, empty) is how an operator asks for exactly that — distinct from
    /// leaving the variable unset, which takes the defaults. Bare hostnames are
    /// accepted and normalized to `https://…`.
    pub relay_hosts: Vec<String>,
    /// Entries of `FEATHERREADER_RELAY_HOSTS` that were rejected as unusable, in
    /// `"value" (reason)` form. Parsing happens before `init_tracing`, so these
    /// are carried here and warned about by the adoption probe task instead of
    /// being lost — or, as they were previously, aborting boot.
    pub relay_host_errors: Vec<String>,
    /// How often the adoption probe runs. [`Duration::ZERO`] (the env value `0`)
    /// DISABLES it. From `FEATHERREADER_ADOPTION_INTERVAL_SECS`, default 24 h.
    pub adoption_interval: Duration,
    /// Render the one-line adoption fact on `/about`. Default **false**: a count
    /// of `1` reads as a status claim rather than a fact, and the honest home for
    /// it today is the log. From `FEATHERREADER_SHOW_ADOPTION`.
    pub show_adoption: bool,
}

/// Configuration for the atproto OAuth sidecar (`@atproto/oauth-client-node`).
///
/// The Rust server drives the sidecar over two surfaces:
/// * the **public** `${public_url}/login` URL the browser is redirected to (and
///   which anchors the sidecar's OAuth `client_id`/`redirect_uri`), and
/// * the **internal** `${internal_url}/internal/*` API (session lookup + the authed
///   `com.atproto.repo.*` proxy), gated by the shared [`internal_secret`] sent as
///   the `X-Internal-Secret` header.
///
/// The two URLs differ in a split deployment (public = the edge origin, internal =
/// a loopback address the app reaches the sidecar on); they collapse to the same
/// value in single-URL local dev.
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    /// Public base URL of the sidecar (no trailing slash), e.g.
    /// `https://feather-reader.com/oauth`. Anchors the browser `/login` redirect.
    pub public_url: String,
    /// Loopback base URL for the sidecar's `/internal/*` API (no trailing slash),
    /// e.g. `http://127.0.0.1:8081`. Defaults to `public_url` in single-URL dev.
    pub internal_url: String,
    /// Shared secret for the sidecar's internal API (`X-Internal-Secret`).
    pub internal_secret: String,
}

/// Wiring for the Rust-native OAuth client.
#[derive(Debug, Clone)]
pub struct OauthConfig {
    /// Path to the client's ES256 signing key. Encrypted at rest with
    /// `encryption_key`, in the SAME `enc.v1` format the sidecar writes, so the
    /// two can share one file and a rollback finds the key it expects.
    pub key_path: PathBuf,
    /// Passphrase for the at-rest encryption of the signing key and the stored
    /// sessions. `None` leaves them in plaintext — refused on a production-like
    /// instance by `validate_secrets`.
    pub encryption_key: Option<String>,
    /// The PLC directory used to resolve `did:plc` documents.
    pub plc_directory: String,
    /// The OAuth scope requested at login. Part of the dev `client_id`, so
    /// changing it changes the client's identity in dev.
    pub scope: String,
}

/// The default PLC directory — the canonical one operated by Bluesky.
const DEFAULT_PLC_DIRECTORY: &str = "https://plc.directory";

/// The scope the reader needs: `atproto` for identity, `transition:generic` for
/// the `com.atproto.repo.*` writes. Matches the sidecar's.
const DEFAULT_OAUTH_SCOPE: &str = "atproto transition:generic";

impl Default for OauthConfig {
    fn default() -> Self {
        Self {
            key_path: PathBuf::from("oauth-signing-key.json"),
            encryption_key: None,
            plc_directory: DEFAULT_PLC_DIRECTORY.to_string(),
            scope: DEFAULT_OAUTH_SCOPE.to_string(),
        }
    }
}

/// The sidecar's own dev fallback for the shared secret (matches the sidecar's
/// `dev-internal-secret-change-me`) so a fully-local dev stack works untouched.
const DEV_INTERNAL_SECRET: &str = "dev-internal-secret-change-me";

/// The default sidecar base URL — loopback, matching the sidecar's own default.
const DEFAULT_SIDECAR_URL: &str = "http://127.0.0.1:8081";

/// A stable, clearly-marked dev cookie key. Overridden by
/// `FEATHERREADER_COOKIE_SECRET` in any real deployment.
const DEV_COOKIE_SECRET: &str = "featherreader-dev-cookie-secret-change-me";

/// Default TTL for a bot-minted claim code: 14 days. Long enough that an
/// asynchronously-delivered claim link (a public follow-back skeet) is still
/// live when the follower taps it.
const DEFAULT_CLAIM_TTL_SECS: i64 = 14 * 24 * 60 * 60;

/// Default adoption-probe cadence: once a day. One unauthenticated GET per relay
/// per day is the entire network cost of the feature.
const DEFAULT_ADOPTION_INTERVAL: Duration = Duration::from_secs(86_400);

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            public_url: DEFAULT_SIDECAR_URL.to_string(),
            internal_url: DEFAULT_SIDECAR_URL.to_string(),
            internal_secret: DEV_INTERNAL_SECRET.to_string(),
        }
    }
}

impl SidecarConfig {
    /// The sidecar's public `/login` URL (the browser redirect target).
    pub fn login_url(&self) -> String {
        format!("{}/login", self.public_url)
    }

    /// The sidecar's `/internal/session/:id` URL (loopback internal API).
    pub fn session_url(&self, session_id: &str) -> String {
        format!("{}/internal/session/{}", self.internal_url, session_id)
    }

    /// The sidecar's `/internal/repo` URL (the authed `com.atproto.repo.*` proxy).
    pub fn repo_url(&self) -> String {
        format!("{}/internal/repo", self.internal_url)
    }
}

/// Parse the cutover switch. Unknown values are an ERROR rather than a silent
/// fall back to the default: a typo in `FEATHERREADER_REPO_BACKEND=rsut` that
/// quietly kept the sidecar live would make the whole comparison a measurement
/// of the sidecar against itself.
fn parse_repo_backend(raw: &str) -> Result<crate::metrics::Backend> {
    match raw.trim() {
        "sidecar" => Ok(crate::metrics::Backend::Sidecar),
        "rust" => Ok(crate::metrics::Backend::Rust),
        other => anyhow::bail!(
            "FEATHERREADER_REPO_BACKEND: expected \"sidecar\" or \"rust\", got {other:?}"
        ),
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
            oauth: OauthConfig::default(),
            cookie_secret: DEV_COOKIE_SECRET.to_string(),
            // The sidecar stays the live path until the switch is thrown.
            repo_backend: crate::metrics::Backend::Sidecar,
            dev_did: None,
            resolver_base: crate::atproto::DEFAULT_RESOLVER_HOST.to_string(),
            bot_secret: None,
            claim_ttl_secs: DEFAULT_CLAIM_TTL_SECS,
            relay_host_errors: Vec::new(),
            relay_hosts: crate::network::DEFAULT_RELAY_HOSTS
                .iter()
                .map(|h| format!("https://{h}"))
                .collect(),
            adoption_interval: DEFAULT_ADOPTION_INTERVAL,
            show_adoption: false,
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
        // The internal API is reached over loopback in a split deployment; it
        // falls back to the resolved public URL so single-URL local dev works.
        let internal_url = env_opt("SIDECAR_INTERNAL_URL")
            .map(|u| u.trim_end_matches('/').to_string())
            .unwrap_or_else(|| sidecar_url.clone());
        let internal_secret = env_opt("SIDECAR_INTERNAL_SECRET")
            .unwrap_or_else(|| defaults.sidecar.internal_secret.clone());
        let sidecar = SidecarConfig {
            public_url: sidecar_url,
            internal_url,
            internal_secret,
        };

        let cookie_secret = env_opt("FEATHERREADER_COOKIE_SECRET")
            .unwrap_or_else(|| defaults.cookie_secret.clone());

        // A dev DID is opt-in: only present when explicitly configured, so a real
        // deployment never silently falls back to a shared identity.
        let dev_did = env_opt("FEATHERREADER_DEV_DID");

        let resolver_base = env_opt("FEATHERREADER_RESOLVER_HOST")
            .map(|u| u.trim_end_matches('/').to_string())
            .unwrap_or(defaults.resolver_base);

        // Shared bot secret gating `POST /bot/claims`. Unset => the endpoint is
        // disabled; `validate_secrets` still fail-loud rejects the *published dev
        // default* / a too-short value on a production-like instance.
        let bot_secret = env_opt("FEATHERREADER_BOT_SECRET");

        let claim_ttl_secs = match env_opt("FEATHERREADER_CLAIM_TTL_SECS") {
            Some(raw) => {
                let secs: i64 = raw.parse().with_context(|| {
                    format!("FEATHERREADER_CLAIM_TTL_SECS: expected seconds, got {raw:?}")
                })?;
                validate_claim_ttl(secs)?
            }
            None => defaults.claim_ttl_secs,
        };

        // Relay hosts for the adoption probe. Read with `env::var` and NOT with
        // `env_opt`, which folds a present-but-empty value into `None` — i.e.
        // straight back to the two Bluesky defaults. `FEATHERREADER_RELAY_HOSTS=`
        // is the documented kill switch, so "set, and set to nothing" has to stay
        // distinguishable from "not set".
        let relay_hosts_raw = env::var("FEATHERREADER_RELAY_HOSTS").ok();
        let (relay_hosts, relay_host_errors) =
            parse_relay_hosts(relay_hosts_raw.as_deref(), defaults.relay_hosts);

        // NOTE: parsed here, NOT via the scheduler's `env_duration_secs`, which
        // maps `0` back to its default — that would silently turn the documented
        // "0 disables" kill switch into "every 24 h".
        let adoption_interval = match env_opt("FEATHERREADER_ADOPTION_INTERVAL_SECS") {
            Some(raw) => {
                let secs: u64 = raw.parse().with_context(|| {
                    format!("FEATHERREADER_ADOPTION_INTERVAL_SECS: expected seconds, got {raw:?}")
                })?;
                Duration::from_secs(secs)
            }
            None => defaults.adoption_interval,
        };

        let oauth = OauthConfig {
            key_path: env_opt("FEATHERREADER_OAUTH_KEY_PATH")
                .map(PathBuf::from)
                .unwrap_or(defaults.oauth.key_path),
            encryption_key: env_opt("FEATHERREADER_OAUTH_ENCRYPTION_KEY"),
            plc_directory: env_opt("FEATHERREADER_PLC_DIRECTORY")
                .map(|u| u.trim_end_matches('/').to_string())
                .unwrap_or(defaults.oauth.plc_directory),
            scope: env_opt("FEATHERREADER_OAUTH_SCOPE").unwrap_or(defaults.oauth.scope),
        };

        let repo_backend = match env_opt("FEATHERREADER_REPO_BACKEND") {
            Some(raw) => parse_repo_backend(&raw)?,
            None => defaults.repo_backend,
        };

        let show_adoption = match env_opt("FEATHERREADER_SHOW_ADOPTION") {
            Some(raw) => parse_bool(&raw).with_context(|| {
                format!("FEATHERREADER_SHOW_ADOPTION: expected a boolean, got {raw:?}")
            })?,
            None => defaults.show_adoption,
        };

        let config = Self {
            oauth,
            repo_backend,
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
            resolver_base,
            bot_secret,
            claim_ttl_secs,
            relay_hosts,
            relay_host_errors,
            adoption_interval,
            show_adoption,
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
        // The bot secret is OPTIONAL (unset => `/bot/claims` disabled, which is a
        // safe default). But if it IS set on a production-like instance it must be
        // strong — a weak/short shared bearer would let anyone mint claim codes.
        if let Some(bot_secret) = &self.bot_secret {
            check_secret("FEATHERREADER_BOT_SECRET", bot_secret, "")?;
        }
        // Split-deploy footgun: on a production-like instance, if the sidecar's
        // INTERNAL base equals its PUBLIC base and that base is non-loopback, the
        // Rust server would send the `X-Internal-Secret` + all session/repo
        // traffic to the PUBLIC edge URL over the network (SIDECAR_INTERNAL_URL
        // was left unset and fell back to SIDECAR_PUBLIC_URL). The canonical
        // container bakes SIDECAR_INTERNAL_URL to loopback; a bare-binary deploy
        // must set it explicitly. Refuse to boot rather than leak the secret.
        if self.sidecar.internal_url == self.sidecar.public_url
            && public_url_is_non_loopback(&self.sidecar.public_url)
        {
            anyhow::bail!(
                "SIDECAR_INTERNAL_URL is unset (defaulting to the public \
                 SIDECAR_PUBLIC_URL '{}') on a production-like instance: the internal \
                 API secret and all session/repo traffic would traverse the public \
                 network. Set SIDECAR_INTERNAL_URL to the sidecar's loopback/private \
                 address (e.g. http://127.0.0.1:8081).",
                self.sidecar.public_url
            );
        }
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

/// Validate a parsed `FEATHERREADER_CLAIM_TTL_SECS`: it MUST be positive. The
/// bot-minted claim link is delivered ASYNCHRONOUSLY (a public skeet), so a
/// non-positive TTL mints an instantly-expired, dead link the follower can never
/// redeem. Fail loud at boot rather than silently hand out broken links.
fn validate_claim_ttl(secs: i64) -> Result<i64> {
    if secs <= 0 {
        anyhow::bail!(
            "FEATHERREADER_CLAIM_TTL_SECS must be > 0 (got {secs}); a non-positive TTL yields \
             instantly-expired, dead claim links"
        );
    }
    Ok(secs)
}

/// Read an env var, treating an empty value the same as unset.
fn env_opt(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

/// Parse `FEATHERREADER_RELAY_HOSTS` into normalized relay origin URLs.
///
/// `raw` is `None` **only** when the variable is genuinely absent, in which case
/// `defaults` wins. A *present* value — including `""`, `"   "`, or `","` —
/// yields exactly the hosts it names, so an empty one yields an empty list and
/// the probe never runs. That distinction is the whole point of this function
/// existing rather than being inlined behind `env_opt`, which collapses
/// present-but-empty into absent and so silently restored the two Bluesky relay
/// defaults for an operator who had explicitly asked for none.
///
/// A *malformed* host is **dropped, not fatal**, and returned in the second
/// element so the caller can surface it once logging exists.
///
/// This deliberately breaks the "a present-but-bad var fails loud" rule, because
/// here that rule had a worse failure mode than the thing it was guarding:
/// `Config::from_env` runs before `init_tracing` (`main.rs:38` vs `:41`), so a
/// hard error is an unexplained non-zero exit, and `deploy/container-entrypoint.sh`
/// turns that into a restart loop. A typo in an **optional metric's** host list
/// would have taken the whole reader offline. `run_adoption_probe` already
/// states the intended contract — "a typo'd relay host must disable an optional
/// metric, never block boot" — and this makes it true.
fn parse_relay_hosts(raw: Option<&str>, defaults: Vec<String>) -> (Vec<String>, Vec<String>) {
    let Some(raw) = raw else {
        return (defaults, Vec::new());
    };
    let mut hosts = Vec::new();
    let mut rejected = Vec::new();
    for h in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match crate::network::normalize_relay_host(h) {
            Ok(host) => hosts.push(host),
            Err(err) => rejected.push(format!("{h:?} ({err})")),
        }
    }
    (hosts, rejected)
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
        // The adoption probe ships on (one GET per relay per day) but its
        // /about line ships off.
        assert_eq!(
            c.relay_hosts,
            vec![
                "https://relay1.us-west.bsky.network".to_string(),
                "https://relay1.us-east.bsky.network".to_string(),
            ]
        );
        assert_eq!(c.adoption_interval, Duration::from_secs(86_400));
        assert!(!c.show_adoption);
    }

    /// The default host list must be exactly what `RelayClient` accepts — i.e.
    /// already normalized, so a default boot needs no re-parse and cannot fail.
    #[test]
    fn default_relay_hosts_are_already_normalized() {
        for host in Config::default().relay_hosts {
            assert_eq!(crate::network::normalize_relay_host(&host).unwrap(), host);
        }
    }

    fn relay_defaults() -> Vec<String> {
        Config::default().relay_hosts
    }

    /// **Regression (v0.2.8):** `FEATHERREADER_RELAY_HOSTS=` (present, empty) is
    /// the documented kill switch and must yield NO relays. Routing it through
    /// `env_opt` collapsed empty into absent, restoring the two Bluesky defaults
    /// and probing them daily against the operator's explicit instruction.
    #[test]
    fn empty_relay_hosts_env_disables_the_probe() {
        for raw in ["", "   ", ",", " , ,\t"] {
            let (hosts, rejected) = parse_relay_hosts(Some(raw), relay_defaults());
            assert!(
                hosts.is_empty(),
                "FEATHERREADER_RELAY_HOSTS={raw:?} must name no relays, got {hosts:?}"
            );
            assert!(rejected.is_empty(), "an empty value is not a typo");
        }
    }

    /// The other half of the same distinction: *unset* still takes the defaults.
    #[test]
    fn absent_relay_hosts_env_keeps_the_defaults() {
        assert_eq!(
            parse_relay_hosts(None, relay_defaults()).0,
            relay_defaults()
        );
    }

    #[test]
    fn relay_hosts_env_is_split_trimmed_and_normalized() {
        assert_eq!(
            parse_relay_hosts(
                Some(" relay.example , https://other.example/ ,"),
                Vec::new()
            )
            .0,
            vec![
                "https://relay.example".to_string(),
                "https://other.example".to_string(),
            ]
        );
    }

    /// **Regression (v0.2.8 review):** a typo used to abort `Config::from_env`,
    /// and because config is parsed before `init_tracing` that surfaced as an
    /// unexplained exit — which `container-entrypoint.sh` turns into a restart
    /// loop. A bad host in an OPTIONAL metric's list must never take the reader
    /// offline: drop it, keep the good ones, and hand the operator the reason so
    /// the probe task can warn.
    #[test]
    fn malformed_relay_host_is_dropped_not_fatal() {
        let (hosts, rejected) =
            parse_relay_hosts(Some("relay.example,wss://relay.example"), Vec::new());
        assert_eq!(hosts, vec!["https://relay.example".to_string()]);
        assert_eq!(rejected.len(), 1, "the bad entry is reported, not silent");
        assert!(rejected[0].contains("wss://relay.example"), "{rejected:?}");
    }

    /// Every entry bad ⇒ no hosts ⇒ the probe disables itself, still no panic
    /// and still no boot failure.
    #[test]
    fn all_relay_hosts_malformed_disables_the_probe_without_failing() {
        let (hosts, rejected) =
            parse_relay_hosts(Some("wss://a.example, ftp://b.example"), relay_defaults());
        assert!(hosts.is_empty());
        assert_eq!(rejected.len(), 2);
    }

    /// **A typo must fail loudly.**
    ///
    /// `FEATHERREADER_REPO_BACKEND=rsut` falling back to the default would leave
    /// the sidecar serving every request while the operator believed the Rust
    /// path was live. Every number in the comparison would then be the sidecar
    /// measured against itself, and the cutover would look flawless right up
    /// until the flag was removed.
    #[test]
    fn an_unknown_repo_backend_is_an_error_rather_than_a_silent_default() {
        let err = parse_repo_backend("rsut").expect_err("a typo must not be ignored");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("rsut"),
            "the message must name the bad value: {rendered}"
        );
        assert!(rendered.contains("sidecar") && rendered.contains("rust"));
    }

    /// Both spellings parse, and surrounding whitespace (a stray newline in a
    /// compose file or secret) does not change the backend.
    #[test]
    fn the_two_backends_parse_including_stray_whitespace() {
        assert_eq!(
            parse_repo_backend("sidecar").unwrap(),
            crate::metrics::Backend::Sidecar
        );
        assert_eq!(
            parse_repo_backend("rust").unwrap(),
            crate::metrics::Backend::Rust
        );
        assert_eq!(
            parse_repo_backend(" rust\n").unwrap(),
            crate::metrics::Backend::Rust
        );
    }

    /// The default is the SIDECAR. Deploying this branch must not move anyone
    /// onto the new path by merely shipping; the switch has to be thrown.
    #[test]
    fn the_default_backend_is_the_sidecar() {
        assert_eq!(
            Config::default().repo_backend,
            crate::metrics::Backend::Sidecar
        );
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
                internal_url: DEFAULT_SIDECAR_URL.to_string(),
                internal_secret: "b".repeat(48),
            },
            ..Config::default()
        };
        assert!(c.is_prod_like());
        assert!(c.validate_secrets().is_ok());
    }

    #[test]
    fn public_sidecar_url_without_internal_url_refuses_boot() {
        // Strong secrets, but the sidecar internal URL fell back to a
        // non-loopback public URL → the internal secret would go over the wire.
        let c = Config {
            bind: SocketAddr::from(([203, 0, 113, 5], 8080)),
            cookie_secret: "a".repeat(48),
            sidecar: SidecarConfig {
                public_url: "https://feather-reader.com/oauth".to_string(),
                internal_url: "https://feather-reader.com/oauth".to_string(),
                internal_secret: "b".repeat(48),
            },
            ..Config::default()
        };
        let err = c.validate_secrets().unwrap_err().to_string();
        assert!(err.contains("SIDECAR_INTERNAL_URL"), "{err}");
    }

    #[test]
    fn public_sidecar_url_with_loopback_internal_url_boots() {
        // Same public sidecar URL, but an explicit loopback internal URL: safe.
        let c = Config {
            bind: SocketAddr::from(([203, 0, 113, 5], 8080)),
            cookie_secret: "a".repeat(48),
            sidecar: SidecarConfig {
                public_url: "https://feather-reader.com/oauth".to_string(),
                internal_url: "http://127.0.0.1:8081".to_string(),
                internal_secret: "b".repeat(48),
            },
            ..Config::default()
        };
        assert!(c.validate_secrets().is_ok());
    }

    #[test]
    fn bot_secret_defaults_unset() {
        let c = Config::default();
        assert!(c.bot_secret.is_none());
        assert_eq!(c.claim_ttl_secs, DEFAULT_CLAIM_TTL_SECS);
    }

    #[test]
    fn claim_ttl_must_be_positive() {
        // A positive TTL passes through unchanged.
        assert_eq!(validate_claim_ttl(3600).unwrap(), 3600);
        assert_eq!(
            validate_claim_ttl(DEFAULT_CLAIM_TTL_SECS).unwrap(),
            DEFAULT_CLAIM_TTL_SECS
        );
        // Zero and negative are rejected loudly (they mint dead, expired links).
        for bad in [0, -1, -1209600] {
            let err = validate_claim_ttl(bad).unwrap_err().to_string();
            assert!(err.contains("FEATHERREADER_CLAIM_TTL_SECS"), "{err}");
            assert!(err.contains("must be > 0"), "{err}");
        }
    }

    #[test]
    fn loopback_instance_allows_weak_bot_secret() {
        // On a dev/loopback instance the bot secret isn't validated (the whole
        // secret policy is skipped), so even a short one is accepted.
        let c = Config {
            bot_secret: Some("short".to_string()),
            ..Config::default()
        };
        assert!(!c.is_prod_like());
        assert!(c.validate_secrets().is_ok());
    }

    #[test]
    fn public_bind_with_short_bot_secret_refuses_boot() {
        let c = Config {
            bind: SocketAddr::from(([203, 0, 113, 5], 8080)),
            cookie_secret: "a".repeat(48),
            sidecar: SidecarConfig {
                public_url: DEFAULT_SIDECAR_URL.to_string(),
                internal_url: DEFAULT_SIDECAR_URL.to_string(),
                internal_secret: "b".repeat(48),
            },
            bot_secret: Some("too-short".to_string()),
            ..Config::default()
        };
        let err = c.validate_secrets().unwrap_err().to_string();
        assert!(err.contains("FEATHERREADER_BOT_SECRET"), "{err}");
    }

    #[test]
    fn public_bind_with_strong_bot_secret_boots() {
        let c = Config {
            bind: SocketAddr::from(([203, 0, 113, 5], 8080)),
            cookie_secret: "a".repeat(48),
            sidecar: SidecarConfig {
                public_url: DEFAULT_SIDECAR_URL.to_string(),
                internal_url: DEFAULT_SIDECAR_URL.to_string(),
                internal_secret: "b".repeat(48),
            },
            bot_secret: Some("c".repeat(48)),
            ..Config::default()
        };
        assert!(c.validate_secrets().is_ok());
    }

    #[test]
    fn public_bind_with_unset_bot_secret_boots() {
        // An unset bot secret is fine on prod (the endpoint is just disabled).
        let c = Config {
            bind: SocketAddr::from(([203, 0, 113, 5], 8080)),
            cookie_secret: "a".repeat(48),
            sidecar: SidecarConfig {
                public_url: DEFAULT_SIDECAR_URL.to_string(),
                internal_url: DEFAULT_SIDECAR_URL.to_string(),
                internal_secret: "b".repeat(48),
            },
            bot_secret: None,
            ..Config::default()
        };
        assert!(c.validate_secrets().is_ok());
    }

    #[test]
    fn public_url_non_loopback_detection() {
        assert!(!public_url_is_non_loopback("http://localhost:8080"));
        assert!(!public_url_is_non_loopback("http://127.0.0.1:8080"));
        assert!(!public_url_is_non_loopback("http://[::1]:8080"));
        assert!(public_url_is_non_loopback("https://feather-reader.com"));
        assert!(public_url_is_non_loopback("http://203.0.113.5"));
    }
}
