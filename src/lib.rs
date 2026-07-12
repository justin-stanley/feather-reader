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

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use atproto::SidecarClient;
use config::Config;
use store::Pool;

/// One logged-in identity, resolved from the OAuth sidecar and keyed by DID.
///
/// The DID is the primary key for everything local; the handle is carried for
/// display. This is what the signed session cookie resolves to.
#[derive(Clone, Debug)]
pub struct Session {
    /// The account DID (the primary key for all per-user local state).
    pub did: String,
    /// The account handle at login time (display only).
    pub handle: Option<String>,
}

/// In-memory session registry: DID → [`Session`].
///
/// The signed cookie carries the DID; this maps it back to the full session
/// (handle, and room to grow). It is populated at the OAuth callback (after the
/// sidecar resolves the one-shot `session_id` to `{did, handle}`) and read on
/// every request. Being in-memory it's cleared on restart — but that's fine: the
/// **durable** OAuth session lives in the sidecar's SQLite store, so a returning
/// cookie whose DID isn't yet in the registry can be re-hydrated (the sidecar
/// still has the OAuth session; only the handle needs refetching), and repo ops
/// key off the DID + shared secret regardless.
#[derive(Clone, Default)]
pub struct SessionRegistry {
    inner: Arc<RwLock<HashMap<String, Session>>>,
}

impl SessionRegistry {
    /// A fresh, empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or refresh a session, keyed by its DID.
    pub fn insert(&self, session: Session) {
        if let Ok(mut map) = self.inner.write() {
            map.insert(session.did.clone(), session);
        }
    }

    /// Look up a session by DID.
    pub fn get(&self, did: &str) -> Option<Session> {
        self.inner.read().ok().and_then(|m| m.get(did).cloned())
    }

    /// Drop a session (logout).
    pub fn remove(&self, did: &str) {
        if let Ok(mut map) = self.inner.write() {
            map.remove(did);
        }
    }
}

/// Shared application state handed to every axum handler.
///
/// Holds the resolved [`Config`], the SQLite pool, a shared [`reqwest::Client`]
/// (feed fetch + sidecar calls), the [`SidecarClient`] (the live atproto
/// `com.atproto.repo.*` path), and the in-memory [`SessionRegistry`] (DID ↔
/// handle, resolved via the sidecar's `/internal/session`). It is `Clone` (cheap
/// — everything is behind `Arc`/handles) and is cloned into each request. It
/// lives in the library so both [`web`] and the `featherreader` binary share it.
#[derive(Clone)]
pub struct AppState {
    /// Immutable runtime configuration.
    pub config: Arc<Config>,
    /// The per-DID SQLite cache pool.
    pub db: Pool,
    /// Shared HTTP client (feed fetch + sidecar internal API).
    pub http: reqwest::Client,
    /// The atproto OAuth sidecar client — the live repo-op path.
    pub sidecar: SidecarClient,
    /// DID ↔ handle session registry (cookie-resolved identity).
    pub sessions: SessionRegistry,
}

impl AppState {
    /// Assemble the shared state from config + an initialized store pool.
    ///
    /// Builds the shared HTTP client and the [`SidecarClient`] from the config's
    /// [`crate::config::SidecarConfig`], and starts with an empty session
    /// registry. The binary's `main` calls this after opening the store.
    pub fn new(config: Config, db: Pool) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .build()?;
        let sidecar = SidecarClient::new(
            http.clone(),
            config.sidecar.public_url.clone(),
            config.sidecar.internal_secret.clone(),
        );
        Ok(Self {
            config: Arc::new(config),
            db,
            http,
            sidecar,
            sessions: SessionRegistry::new(),
        })
    }
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
