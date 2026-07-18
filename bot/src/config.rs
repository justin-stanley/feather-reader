//! Bot configuration — env-driven, secrets NEVER hardcoded.
//!
//! Every secret is read from the environment so it can be Vaultwarden-injected at
//! runtime (per the homelab agent-isolation pattern) rather than baked into an
//! image. The bot fails loud at startup if a required secret is missing.
//!
//! | Variable                     | Required | Meaning |
//! |------------------------------|----------|---------|
//! | `BOT_PDS_HOST`               | no (default `https://pds.justin-stanley.com`) | The account's OWN PDS — every XRPC call (login, getFollowers, post) targets it, so this works for a self-hosted PDS, not just bsky.social. |
//! | `BOT_HANDLE`                 | no (default `feather-reader.com`) | The bot account handle used to log in + as the `getFollowers` actor. |
//! | `BOT_DID`                    | no (default `did:plc:cxauapbtkbmf7b24e5icd32j`) | The account DID (the `repo` for `createRecord` + skip-self guard). |
//! | `BOT_APP_PASSWORD`           | **yes**  | A DEDICATED atproto app password with WRITE scope (not the account's primary password). Vaultwarden-injected. |
//! | `FEATHERREADER_APP_BASE`     | no (default `https://feather-reader.com`) | Base URL of the FeatherReader app the bot mints claims against. |
//! | `FEATHERREADER_BOT_SECRET`   | **yes**  | Shared bearer for `POST /bot/claims` (== the app's Fly secret of the same name). Vaultwarden-injected. |
//! | `BOT_STATE_DB`               | no (default `invite-bot.db`) | SQLite idempotency store on the bot host. MUST be an ABSOLUTE path on a persistent volume in production (a relative/ephemeral path re-mints on every restart). |
//! | `BOT_POLL_INTERVAL_SECS`     | no (default `300` = 5 min) | How often to poll `getFollowers`. |
//! | `BOT_MAX_PER_CYCLE`          | no (default `10`) | Safety cap on how many NEW followers to process per poll (blunts a follow spike). |
//! | `BOT_MAX_DAILY_MINTS`        | no (default `50`) | Global daily budget on fresh claim mints across ALL cycles — a sybil-farming brake (a flood of throwaway follows can't drain the beta in a day). Idempotent re-posts/waitlist-welcomes don't count. |
//! | `RUST_LOG`                   | no (default `info`) | Tracing filter. |

use anyhow::{Context, Result};

/// The bot account's canonical DID (the `@feather-reader.com` account).
pub const DEFAULT_BOT_DID: &str = "did:plc:cxauapbtkbmf7b24e5icd32j";
/// The bot account's canonical handle.
pub const DEFAULT_BOT_HANDLE: &str = "feather-reader.com";
/// The account's self-hosted PDS.
pub const DEFAULT_PDS_HOST: &str = "https://pds.justin-stanley.com";
/// The FeatherReader app's public base URL.
pub const DEFAULT_APP_BASE: &str = "https://feather-reader.com";

/// Fully-resolved bot configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// The account's PDS base URL (no trailing slash). Every XRPC call hits it.
    pub pds_host: String,
    /// The bot account handle (login identifier + getFollowers actor).
    pub handle: String,
    /// The bot account DID (repo for createRecord; skip-self guard).
    pub did: String,
    /// A dedicated app password with write scope. NEVER the primary password.
    pub app_password: String,
    /// The FeatherReader app base URL the bot mints claims against.
    pub app_base: String,
    /// Shared bearer for the app's `POST /bot/claims` (`X-Bot-Secret`).
    pub bot_secret: String,
    /// Path to the local idempotency SQLite DB.
    pub state_db: String,
    /// Poll interval (seconds).
    pub poll_interval_secs: u64,
    /// Max new followers processed per poll cycle.
    pub max_per_cycle: usize,
    /// Global daily budget on FRESH claim mints across all cycles (sybil brake).
    pub max_daily_mints: usize,
}

impl Config {
    /// Build from the environment, failing loud on a missing required secret.
    pub fn from_env() -> Result<Self> {
        let app_password = require("BOT_APP_PASSWORD")
            .context("a dedicated app password (write scope) is required; do not use the primary account password")?;
        let bot_secret = require("FEATHERREADER_BOT_SECRET").context(
            "the shared /bot/claims secret is required (must match the app's Fly secret)",
        )?;

        Ok(Self {
            pds_host: opt("BOT_PDS_HOST")
                .unwrap_or_else(|| DEFAULT_PDS_HOST.to_string())
                .trim_end_matches('/')
                .to_string(),
            handle: opt("BOT_HANDLE").unwrap_or_else(|| DEFAULT_BOT_HANDLE.to_string()),
            did: opt("BOT_DID").unwrap_or_else(|| DEFAULT_BOT_DID.to_string()),
            app_password,
            app_base: opt("FEATHERREADER_APP_BASE")
                .unwrap_or_else(|| DEFAULT_APP_BASE.to_string())
                .trim_end_matches('/')
                .to_string(),
            bot_secret,
            state_db: resolve_state_db()?,
            poll_interval_secs: parse_or("BOT_POLL_INTERVAL_SECS", 300)?,
            max_per_cycle: parse_or("BOT_MAX_PER_CYCLE", 10)?,
            max_daily_mints: parse_or("BOT_MAX_DAILY_MINTS", 50)?,
        })
    }
}

/// Resolve `BOT_STATE_DB`, warning LOUDLY if it is a relative (non-absolute) path.
///
/// The state DB is the bot's per-DID idempotency cache; if it lives on an ephemeral
/// filesystem (or a relative path that changes with the working directory), a
/// restart re-processes every follower. The app-side DID idempotency (B1) is the
/// authoritative backstop against re-minting, but a non-persistent store still
/// causes needless re-posting and waitlist churn, so we insist on an absolute path
/// on a persistent volume. We WARN rather than hard-fail on the default so a quick
/// local run still works, but a clearly-ephemeral `/tmp` path is called out.
fn resolve_state_db() -> Result<String> {
    let path = opt("BOT_STATE_DB").unwrap_or_else(|| "invite-bot.db".to_string());
    let p = std::path::Path::new(&path);
    if !p.is_absolute() {
        tracing::warn!(
            %path,
            "BOT_STATE_DB is a RELATIVE path — in production set it to an ABSOLUTE \
             path on a PERSISTENT volume, or a restart will re-process every follower"
        );
    } else if path.starts_with("/tmp/") || path.starts_with("/var/tmp/") {
        tracing::warn!(
            %path,
            "BOT_STATE_DB is under a temp dir — this is NOT a persistent volume; a \
             reboot loses the idempotency cache and re-processes followers"
        );
    }
    Ok(path)
}

/// An env var, empty treated as unset.
fn opt(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

/// A required env var (fail-loud if unset/empty).
fn require(key: &str) -> Result<String> {
    opt(key).with_context(|| format!("required environment variable {key} is unset"))
}

/// Parse an integer env var or fall back to `default`.
fn parse_or<T: std::str::FromStr>(key: &str, default: T) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    match opt(key) {
        Some(raw) => raw.parse::<T>().map_err(|e| anyhow::anyhow!("{key}: {e}")),
        None => Ok(default),
    }
}
