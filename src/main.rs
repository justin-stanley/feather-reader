//! FeatherReader server entrypoint.
//!
//! The `main` here is deliberately thin — it wires the seams that sibling
//! modules own and then serves. The startup sequence is:
//!
//! 1. Load [`Config`] from the environment (with sane defaults).
//! 2. Initialize tracing (respecting `RUST_LOG`).
//! 3. Open + migrate the per-DID SQLite cache via [`store::init`].
//! 4. Build the shared [`AppState`] (pool + HTTP client + atproto sidecar).
//! 5. Spawn the background schedulers — the **poll scheduler** and the
//!    **read-state flusher** — as `tokio` tasks, behind a config flag so
//!    tests/dev can disable them ([`scheduler::spawn`]). Both share the same
//!    graceful-shutdown signal as the HTTP server.
//! 6. Build the axum [`Router`] via [`web::router`] and serve until shutdown.
//!
//! Shutdown is broadcast to *both* the server and the background tasks via a
//! `tokio::sync::watch` channel, so a single Ctrl-C drains the HTTP server, the
//! poller, and the flusher (the flusher does one final read-state flush) before
//! the process exits.

use anyhow::{Context, Result};
use feather_reader::config::Config;
use feather_reader::{store, web, AppState, VERSION};
use tokio::sync::watch;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

// The background schedulers (poll scheduler + read-state flusher) live in
// `scheduler.rs` and are compiled as a module of the *binary* crate — they wire
// the library's public seams (AppState / store / feed / atproto / config)
// together, which is the binary's job, not the library's.
#[path = "scheduler.rs"]
mod scheduler;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Configuration — env-driven, every knob defaulted.
    let config = Config::from_env().context("loading configuration")?;

    // 2. Tracing — `RUST_LOG` controls verbosity; default to `info`.
    init_tracing();

    info!(version = VERSION, bind = %config.bind, db = %config.db_path.display(), "starting featherreader");

    // 3. SQLite cache — open the pool and run embedded migrations.
    let db = store::init(&config)
        .await
        .context("initializing the SQLite store")?;

    // Seed the closed-beta admin bootstrap: every DID on the ALLOWED_DIDS
    // admin seed gets a beta_access seat so a fresh instance always has its
    // operator(s) inside the invite gate and able to mint codes. Idempotent.
    match store::ensure_seed(&db, config.admin_seed_dids()).await {
        Ok(new_seats) => {
            if new_seats > 0 {
                info!(new_seats, "seeded admin DIDs into beta_access");
            }
        }
        Err(err) => return Err(err).context("seeding admin beta_access DIDs"),
    }

    // 4. Shared application state — pool + HTTP client + atproto sidecar +
    //    session registry.
    let bind = config.bind;
    let state = AppState::new(config, db).context("building application state")?;

    // 5. Shutdown fan-out. A single Ctrl-C flips this watch channel; the HTTP
    //    server and both background tasks each hold a receiver and stop.
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    tokio::spawn(async move {
        signal_ctrl_c().await;
        // Send is best-effort: if every receiver has already dropped we are
        // already shutting down.
        let _ = shutdown_tx.send(());
    });

    // Spawn the poll scheduler + read-state flusher (no-op when disabled via
    // FEATHERREADER_DISABLE_SCHEDULER — the seam tests/pure-web dev use).
    let scheduler_handles = scheduler::spawn(state.clone(), shutdown_rx.clone());

    // 6. HTTP surface — build the axum router over shared state, and serve.
    let router = web::router(state);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding to {bind}"))?;
    info!(addr = %bind, "listening");

    // `into_make_service_with_connect_info` exposes the peer `SocketAddr` to the
    // per-IP rate-limit middleware via `ConnectInfo<SocketAddr>`.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
    .await
    .context("HTTP server error")?;

    // Give the background tasks a moment to drain (the flusher's final flush) so
    // shutdown doesn't race the process exit.
    for h in scheduler_handles {
        let _ = h.await;
    }

    info!("shutdown complete");
    Ok(())
}

/// Install the tracing subscriber. `RUST_LOG` overrides the default `info`
/// filter; format is compact human-readable to the terminal.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();
}

/// Resolve when the process receives Ctrl-C (SIGINT).
async fn signal_ctrl_c() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::error!(%err, "failed to install Ctrl-C handler");
    }
    info!("shutdown signal received");
}

/// A clonable-per-call shutdown future: resolves the first time the `watch`
/// channel fires (or when the sender is dropped). Each consumer (axum, the
/// poller, the flusher) gets its own receiver and awaits this.
async fn wait_for_shutdown(mut rx: watch::Receiver<()>) {
    // The initial value is already "seen"; wait for the next change (the send) or
    // for the sender to drop.
    let _ = rx.changed().await;
}
