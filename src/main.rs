//! FeatherReader server entrypoint.
//!
//! The `main` here is deliberately thin — it wires the seams that sibling
//! modules own and then serves. The startup sequence is:
//!
//! 1. Load [`Config`] from the environment (with sane defaults).
//! 2. Initialize tracing (respecting `RUST_LOG`).
//! 3. Open + migrate the per-DID SQLite cache via [`store::init`].
//! 4. Build the axum [`Router`] via [`web::router`], sharing an [`AppState`].
//! 5. Bind and serve on the configured address until shutdown.
//!
//! The scheduler/fetcher and read-state flusher are spawned from within
//! [`web::router`]'s setup in later phases; Phase 0 stands up the HTTP surface.

use std::sync::Arc;

use anyhow::{Context, Result};
use feather_reader::config::Config;
use feather_reader::{store, web, AppState, VERSION};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

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

    // 4. HTTP surface — build the axum router over shared state.
    let state = AppState {
        config: Arc::new(config.clone()),
        db,
    };
    let router = web::router(state);

    // 5. Bind + serve.
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("binding to {}", config.bind))?;
    info!(addr = %config.bind, "listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server error")?;

    info!("shutdown complete");
    Ok(())
}

/// Install the tracing subscriber. `RUST_LOG` overrides the default `info`
/// filter; format is compact human-readable to the terminal.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();
}

/// Resolve when the process receives Ctrl-C (SIGINT) — the hook where the
/// read-state flusher will drain dirty per-feed cursors to the PDS before exit
/// (§4 of the design). Phase 0 just completes cleanly.
async fn shutdown_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::error!(%err, "failed to install Ctrl-C handler");
    }
    info!("shutdown signal received");
}
