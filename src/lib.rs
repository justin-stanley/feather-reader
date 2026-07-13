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
//!   folders, saved, batched read-state sync). Live repo writes go through the
//!   OAuth confidential-client sidecar ([`atproto::SidecarClient`]).
//! - [`web`]     — the axum router + askama server-rendered views.
//!
//! **Status:** experimental / pre-1.0. See <https://feather-reader.com>.

// The module tree; the layout owns the wiring between subsystems.
pub mod atproto;
pub mod config;
pub mod feed;
pub mod lexicon;
pub mod net;
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

/// In-memory session registry: **opaque random session-id → [`Session`]**.
///
/// The signed cookie carries a random, server-minted session id (`sid`), *not*
/// the DID: the DID is never attacker-supplied, so a session cookie cannot be
/// forged by resolving a victim's DID — an attacker would need both the server's
/// HMAC secret *and* to guess a 256-bit random sid that only exists server-side.
/// Sessions are therefore also **revocable** (drop the sid → the cookie is dead)
/// and are cleared on restart (every client re-logs in; the durable OAuth
/// session still lives in the sidecar's store).
#[derive(Clone, Default)]
pub struct SessionRegistry {
    inner: Arc<RwLock<HashMap<String, Session>>>,
}

impl SessionRegistry {
    /// A fresh, empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new session for `session`, returning its freshly-minted random
    /// session id (the value the signed cookie carries).
    pub fn create(&self, session: Session) -> String {
        let sid = new_session_id();
        if let Ok(mut map) = self.inner.write() {
            map.insert(sid.clone(), session);
        }
        sid
    }

    /// Look up a session by its opaque session id.
    pub fn get(&self, sid: &str) -> Option<Session> {
        self.inner.read().ok().and_then(|m| m.get(sid).cloned())
    }

    /// Drop a session by its session id (logout / revoke).
    pub fn remove(&self, sid: &str) {
        if let Ok(mut map) = self.inner.write() {
            map.remove(sid);
        }
    }
}

/// Mint a fresh, unguessable session id: 32 random bytes (256 bits) as URL-safe
/// hex. Sourced from the OS CSPRNG via `getrandom` (pulled in transitively);
/// falls back to a time+address-seeded mix only if the OS RNG is unavailable,
/// which never happens on the supported platforms.
fn new_session_id() -> String {
    let mut bytes = [0u8; 32];
    if getrandom::fill(&mut bytes).is_err() {
        // Extremely defensive fallback: mix a few entropy-ish sources. Not used
        // on any supported platform (getrandom uses the OS CSPRNG).
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seed = nanos as u64 ^ (&bytes as *const _ as u64);
        let mut x = seed | 1;
        for b in bytes.iter_mut() {
            // xorshift64 — only reached if the OS CSPRNG is unavailable.
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
    }
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
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
        let http = reqwest::Client::builder().user_agent(USER_AGENT).build()?;
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
pub const USER_AGENT: &str = concat!(
    "featherreader/",
    env!("CARGO_PKG_VERSION"),
    " (+https://feather-reader.com)"
);
