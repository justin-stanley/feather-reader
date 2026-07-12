//! **FeatherReader** — a minimalist, atproto-native RSS/Atom feed reader.
//!
//! Your feed subscriptions live in your own [atproto](https://atproto.com) PDS
//! (via the open `community.lexicon.rss.*` community lexicon), so your reading
//! list follows you across any compatible reader — you own your data, not the
//! app. Minimalist by design.
//!
//! This crate ships as a single server binary (`featherreader`) plus this small
//! library, which declares the module tree and the shared types the binary and
//! its subsystems build on. The heavy lifting lives in sibling modules:
//!
//! - [`config`]  — env-driven runtime configuration (`FEATHERREADER_*`).
//! - [`lexicon`] — the `community.lexicon.rss.*` record schemas (subscription,
//!   folder, saved, readState) as serde types.
//! - [`store`]   — the per-DID SQLite cache + read-state working copy (sqlx,
//!   runtime queries).
//! - [`feed`]    — polite fetching (conditional GET, backoff), feed-rs parsing,
//!   and ammonia sanitization.
//! - [`atproto`] — the atproto identity + PDS record layer (subscriptions,
//!   folders, saved, batched read-state sync). Phase 0 ships a scaffolded auth
//!   seam; the full OAuth confidential-client sidecar is a documented TODO.
//! - [`web`]     — the axum router + askama server-rendered views.
//!
//! **Status:** early. This `0.1.0` is a compiling Phase-0 skeleton with the real
//! core seams present. See <https://reader.justin-stanley.com>.

// The Phase-0 module tree. Siblings fill these in; the layout owns the wiring.
pub mod atproto;
pub mod config;
pub mod feed;
pub mod lexicon;
pub mod store;
pub mod web;

use std::sync::Arc;

use config::Config;
use store::Pool;

/// Shared application state handed to every axum handler.
///
/// Holds the resolved [`Config`] and the SQLite pool. It is `Clone` (cheap —
/// the pool and config are behind `Arc`/handles) and is cloned into each
/// request. Later phases extend this with the atproto session registry, the
/// HTTP fetch client, and the scheduler handle. It lives in the library (not
/// the binary) so both [`web`] and the `featherreader` binary share one type.
#[derive(Clone)]
pub struct AppState {
    /// Immutable runtime configuration.
    pub config: Arc<Config>,
    /// The per-DID SQLite cache pool.
    pub db: Pool,
}

/// The crate version — surfaced for the server's `--version` / health output.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The `User-Agent` FeatherReader identifies itself with when fetching feeds.
///
/// Being a polite, identifiable client is a feed-hygiene requirement (§5 of the
/// design): publishers ask readers to say who they are so they can be reached or
/// rate-limited sanely rather than silently blocked.
pub const USER_AGENT: &str =
    concat!("featherreader/", env!("CARGO_PKG_VERSION"), " (+https://reader.justin-stanley.com)");
