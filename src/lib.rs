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
//!   folders, saved, batched read-state sync), including the Node sidecar's
//!   client ([`atproto::SidecarClient`]).
//! - [`oauth`]   — the Rust-native atproto OAuth client (the `rust` repo
//!   backend, which production runs).
//! - [`repo`]    — the one dispatcher every `com.atproto.repo.*` call goes
//!   through, choosing the sidecar or the Rust client by
//!   `FEATHERREADER_REPO_BACKEND`.
//! - [`standard_site`] — reading standard.site publications from their
//!   authors' repos.
//! - [`network`] — read-only queries against the *public* atproto network (the
//!   relay adoption probe). A projection, never a source of truth, and never on
//!   a reader path.
//! - [`web`]     — the axum router + askama server-rendered views.
//! - [`sanitized_html`] — the reader's article body, re-sanitized at render
//!   so the template never emits a stored string unescaped.
//!
//! **Status:** experimental / pre-1.0. See <https://feather-reader.com>.

// The module tree; the layout owns the wiring between subsystems.
pub mod atproto;
pub mod config;
pub mod feed;
pub mod lexicon;
pub mod metrics;
pub mod net;
pub mod network;
pub mod oauth;
pub mod readstate;
pub mod repo;
pub mod runtime_health;
pub mod safe_link;
pub mod sanitized_html;
pub mod standard_site;
pub mod store;
pub mod vetted;
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
/// Holds the resolved [`Config`], the SQLite pool, a shared `reqwest::Client`
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
    /// The atproto OAuth sidecar client — the repo-op path when
    /// [`Config::repo_backend`] selects `Sidecar`. Production selects `Rust`.
    pub sidecar: SidecarClient,
    /// DID ↔ handle session registry (cookie-resolved identity).
    pub sessions: SessionRegistry,
    /// Repo-op latency for BOTH backends, for reading the two side by side
    /// across a cutover flip.
    pub metrics: Arc<metrics::RepoMetrics>,
    /// The Rust OAuth client's runtime. `None` when it could not be built —
    /// tolerated only while the sidecar is the selected backend, and refused at
    /// startup otherwise.
    pub oauth: Option<Arc<oauth::runtime::OauthRuntime>>,
    /// What the background loops are doing right now — the poll heartbeat and
    /// the watermark pause. Written by the scheduler, read by `/health` and
    /// `/stats`. See [`runtime_health`] for why these two states needed a home
    /// outside the log stream.
    pub runtime_health: Arc<runtime_health::RuntimeHealth>,
}

impl AppState {
    /// Assemble the shared state from config + an initialized store pool.
    ///
    /// Builds the shared HTTP client and the [`SidecarClient`] from the config's
    /// [`crate::config::SidecarConfig`], and starts with an empty session
    /// registry. The binary's `main` calls this after opening the store.
    pub fn new(config: Config, db: Pool) -> anyhow::Result<Self> {
        let http = build_http_client()?;

        // Built whatever the backend, so a bad OAuth config is caught on every
        // deploy rather than at the moment the switch is thrown. With the
        // sidecar selected a failure is only a warning; with the Rust backend
        // selected it is fatal, because there would be nothing to serve with.
        let oauth = match oauth::runtime::OauthRuntime::new(&config) {
            Ok(runtime) => Some(Arc::new(runtime)),
            Err(err) if config.repo_backend == metrics::Backend::Sidecar => {
                tracing::warn!(
                    %err,
                    "the Rust OAuth runtime could not be built; the sidecar backend is \
                     unaffected, but FEATHERREADER_REPO_BACKEND=rust would refuse to start"
                );
                None
            }
            Err(err) => return Err(err.context(
                "FEATHERREADER_REPO_BACKEND=rust, but the Rust OAuth runtime could not be built",
            )),
        };
        let sidecar = SidecarClient::new(
            http.clone(),
            config.sidecar.public_url.clone(),
            config.sidecar.internal_url.clone(),
            config.sidecar.internal_secret.clone(),
        );
        Ok(Self {
            config: Arc::new(config),
            db,
            http,
            sidecar,
            sessions: SessionRegistry::new(),
            metrics: Arc::new(metrics::RepoMetrics::new()),
            oauth,
            runtime_health: Arc::new(runtime_health::RuntimeHealth::new()),
        })
    }
}

/// The shared HTTP client [`AppState`] carries, also used by the binary's
/// maintenance commands (`--revoke-all-sessions`) so they reach the network
/// exactly as the serving app does.
///
/// `.no_proxy()` for the same reason as `net::build_pinned_client` and
/// `feed::build_client`: ambient `HTTP_PROXY` would route this client's traffic
/// through a proxy that resolves hostnames itself, out from under the SSRF
/// guard's address checks.
pub fn build_http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .no_proxy()
        .build()
}

/// Run `future` on a new multi-thread runtime — what `#[tokio::main]` builds —
/// then shut that runtime down waiting **at most `shutdown`** for work still on
/// its blocking pool, where dropping it would wait without limit. The server's
/// `main` runs on this; see its `RUNTIME_SHUTDOWN_TIMEOUT` for why (#226: an
/// abandoned ingest sanitize cannot be cancelled).
pub fn block_on_then_shutdown<F: std::future::Future>(
    future: F,
    shutdown: std::time::Duration,
) -> std::io::Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let output = runtime.block_on(future);
    runtime.shutdown_timeout(shutdown);
    Ok(output)
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

#[cfg(test)]
mod runtime_shutdown_tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Blocking work still running when the future returns holds the shutdown
    /// up for the bound and no longer — a plain drop of the runtime would wait
    /// the full 10 s for it (vacuous-test hunt of #274: `main`'s
    /// `shutdown_timeout` had no test).
    #[test]
    fn shutdown_waits_for_blocking_work_at_most_the_bound() {
        let started = Instant::now();
        let out = block_on_then_shutdown(
            async {
                drop(tokio::task::spawn_blocking(|| {
                    std::thread::sleep(Duration::from_secs(10))
                }));
                7
            },
            Duration::from_millis(100),
        )
        .unwrap();
        let took = started.elapsed();
        assert_eq!(out, 7);
        assert!(took < Duration::from_secs(2), "shutdown took {took:?}");
    }
}
