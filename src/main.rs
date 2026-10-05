//! FeatherReader server entrypoint.
//!
//! The `main` here is deliberately thin — it wires the seams that sibling
//! modules own and then serves. The startup sequence is:
//!
//! 1. Load [`Config`] from the environment (with sane defaults).
//! 2. Initialize tracing (respecting `RUST_LOG`).
//! 3. Open + migrate the per-DID SQLite cache via [`store::init`].
//! 4. Build the shared [`AppState`] (pool + HTTP client + atproto sidecar).
//! 5. Spawn the background schedulers — the RSS and publication **pollers**,
//!    the **read-state flusher**, the sweepers, the adoption probe and the
//!    metrics flusher — as `tokio` tasks, behind a config flag so tests/dev can
//!    disable them ([`scheduler::spawn`]). All share the same graceful-shutdown
//!    signal as the HTTP server.
//! 6. Build the axum `axum::Router` via [`web::router`] and serve until shutdown.
//!
//! Shutdown is broadcast to *both* the server and the background tasks via a
//! `tokio::sync::watch` channel, so a single SIGINT/SIGTERM drains the HTTP
//! server, the poller, and the flusher (the flusher does one final read-state
//! flush) before the process exits.

use anyhow::{Context, Result};
use feather_reader::config::Config;
use feather_reader::{store, web, AppState, VERSION};
use tokio::sync::watch;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

// The background schedulers (pollers, flushers, sweepers, adoption probe) live in
// `scheduler.rs` and are compiled as a module of the *binary* crate — they wire
// the library's public seams (AppState / store / feed / atproto / config)
// together, which is the binary's job, not the library's.
#[path = "scheduler.rs"]
mod scheduler;

#[tokio::main]
async fn main() -> Result<()> {
    // Maintenance mode: sign every stored session out and exit, without binding
    // a port or starting a scheduler. Checked before anything can fail through
    // `?`, so every failure of this mode is an explicit exit 2 ("nothing done")
    // rather than whatever an error from `main` happens to exit with.
    if wants_revoke_all(std::env::args()) {
        let sweep = wants_sweep(std::env::args());
        std::process::exit(run_revoke_all(sweep).await);
    }

    // 1. Configuration — env-driven, every knob defaulted.
    let config = Config::from_env().context("loading configuration")?;

    // 2. Tracing — `RUST_LOG` controls verbosity; default to `info`.
    init_tracing();

    info!(version = VERSION, bind = %config.bind, db = %config.db_path.display(), "starting featherreader");

    // 3. SQLite cache — open the pool and run embedded migrations.
    let db = store::init(&config)
        .await
        .context("initializing the SQLite store")?;

    // Maintenance mode: run the one-off auto_vacuum migration and exit without
    // ever binding a port or starting a scheduler. See `run_vacuum_migration`.
    if wants_vacuum_migration(std::env::args()) {
        let outcome = run_vacuum_migration(&db, &config).await;
        db.close().await;
        return outcome;
    }

    // Startup safety: surface the effective DB-size watermark and warn the
    // operator if it can't actually protect the volume (watermark >= free space
    // means the disk fills before the poller ever pauses). Best-effort; never
    // fatal.
    check_watermark_vs_disk(&config);

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
    // Stamp the boot time before anything can be served, so `/health` can answer
    // "is this container restarting" — the first question about a process under a
    // supervisor that tears the machine down whenever a child exits.
    state
        .runtime_health
        .set_started_at(chrono::Utc::now().timestamp());

    // 5. Shutdown fan-out. SIGINT (Ctrl-C) or SIGTERM flips this watch channel;
    //    the HTTP server and both background tasks each hold a receiver and stop.
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    tokio::spawn(async move {
        shutdown_signal().await;
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

/// One of the two maintenance flags this binary understands (the other is
/// [`REVOKE_ALL_SESSIONS_FLAG`]). Everything else is env-driven.
const MIGRATE_AUTO_VACUUM_FLAG: &str = "--migrate-auto-vacuum";

/// Whether the invocation asked for the maintenance migration.
///
/// Skips `argv[0]`, which the previous `args().any(…)` scan included — so a
/// binary that happened to be installed at a path containing the flag would have
/// triggered it. Not remotely reachable, but this gate starts an operation that
/// takes an exclusive whole-database write lock for minutes, and it should be
/// exactly as loose as an argument match and no looser.
fn wants_vacuum_migration<I: IntoIterator<Item = String>>(args: I) -> bool {
    args.into_iter()
        .skip(1)
        .any(|a| a == MIGRATE_AUTO_VACUUM_FLAG)
}

/// Run the one-off `auto_vacuum = NONE → INCREMENTAL` migration, then exit.
///
/// **Why a flag and not a boot step.** SQLite ignores `PRAGMA auto_vacuum` on a
/// populated database unless it is followed by a full `VACUUM` — so the only way
/// off the mode where `reclaim` cannot work is to run the exact operation that
/// is unsafe under disk pressure. Doing that automatically at boot, on a
/// supervisor that tears the machine down whenever a child exits, is the crash
/// loop shape the poller lease was just written to remove. So it is deliberate,
/// operator-timed, and refuses itself when the volume lacks headroom:
///
/// ```text
/// fly ssh console -C "/app/featherreader --migrate-auto-vacuum"
/// ```
///
/// Databases CREATED after this change are already INCREMENTAL (`store::init_url`
/// sets it before the first table exists), so this exists only for instances
/// that predate it. It reports `NotNeeded` and exits 0 on those, which makes it
/// safe to run blindly.
async fn run_vacuum_migration(db: &store::Pool, config: &Config) -> Result<()> {
    info!(db = %config.db_path.display(), "auto_vacuum migration: starting");
    // The VACUUM holds an exclusive lock for its whole duration. Against the
    // app's 5 s `busy_timeout` that means concurrent writes do not queue, they
    // FAIL — including the OAuth session writes, so logins break. Say so before
    // starting rather than leaving an operator to infer it from a broken site.
    info!(
        "auto_vacuum migration: this rewrites the whole database file and holds an \
         exclusive lock for minutes. Writes from a RUNNING instance will FAIL (not \
         queue) for the duration, logins included. Stop the app first."
    );
    let available = available_disk_bytes(&config.db_path);
    match store::migrate_to_incremental_vacuum(db, available).await? {
        store::VacuumMigration::NotNeeded(mode) => {
            info!(?mode, "auto_vacuum migration: nothing to do");
        }
        store::VacuumMigration::RefusedNoHeadroom {
            needed,
            available,
            file_bytes,
        } => {
            // Not an error exit: the operator asked a reasonable question and
            // got a correct answer. Failing here would be indistinguishable from
            // a broken binary in a deploy script.
            tracing::warn!(
                needed_bytes = needed,
                available_bytes = available,
                // The on-disk size too: the requirement is computed from LIVE
                // pages, and on exactly this population (NONE mode, big
                // freelist) the file is materially larger — so an operator
                // comparing the number to `ls -l` would otherwise distrust it.
                file_bytes = file_bytes.unwrap_or(0),
                "auto_vacuum migration: REFUSED. A full VACUUM writes a second copy of \
                 the database, so it needs roughly twice the LIVE size free (the file on \
                 disk is larger; the freelist is not copied). Free space on the volume \
                 (or grow it) and run this again."
            );
        }
        store::VacuumMigration::Migrated {
            bytes_before,
            bytes_after,
            file_before,
            file_after,
        } => {
            info!(
                bytes_before,
                bytes_after,
                // The file sizes are the pair that answers "did this help?".
                // The live-page figures barely move — reclaiming the freelist is
                // the whole point — so reporting only those read as a no-op.
                file_before = file_before.unwrap_or(0),
                file_after = file_after.unwrap_or(0),
                "auto_vacuum migration: complete; the database is now INCREMENTAL"
            );
        }
    }
    Ok(())
}

/// The operator's fleet-wide sign-out, run by `deploy/teardown.sh` (#257).
const REVOKE_ALL_SESSIONS_FLAG: &str = "--revoke-all-sessions";

/// `--revoke-all-sessions` exit code: every session revoked (or none stored).
const REVOKE_EXIT_OK: i32 = 0;
/// Some revocations failed. Every row is still deleted locally, so a teardown
/// may proceed — but those tokens may stay live at their PDS until they expire.
///
/// **Deliberately not 1.** 1 is what everything else exits with: `main`
/// returning `Err`, a wrapper (`docker compose exec`, `fly ssh`) failing, and —
/// the case that matters — an OLDER binary that does not know this flag, ignores
/// it, tries to start a server and fails to bind. A teardown that read 1 as
/// "partially revoked, proceed" wiped with nothing revoked.
const REVOKE_EXIT_SOME_FAILED: i32 = 3;
/// Nothing was revoked and nothing deleted (not configured, unreadable store,
/// bad configuration). A teardown MUST NOT wipe after this.
const REVOKE_EXIT_ABORT: i32 = 2;

/// The line a completed revoke-all prints LAST, which `deploy/teardown.sh`
/// requires before it will wipe. An exit code alone can be produced by
/// something that is not this command; this line cannot be produced by an
/// older binary or a wrapper that never ran it.
fn revoke_all_sentinel(report: &feather_reader::oauth::revoke::RevokeAllReport) -> String {
    format!(
        "revoke-all-sessions: revoked={} no_session={} failed={}",
        report.revoked.len(),
        report.no_session.len(),
        report.failed.len()
    )
}

/// Whether the invocation asked for the revoke-all. Skips `argv[0]`, like
/// [`wants_vacuum_migration`]: this signs every user out, so a binary installed
/// at a path containing the flag must not trigger it.
fn wants_revoke_all<I: IntoIterator<Item = String>>(args: I) -> bool {
    args.into_iter()
        .skip(1)
        .any(|a| a == REVOKE_ALL_SESSIONS_FLAG)
}

/// `--revoke-all-sessions --sweep`: the post-stop pass `deploy/teardown.sh`
/// makes after stopping the app.
const SWEEP_FLAG: &str = "--sweep";

/// Whether this is the post-stop sweep. Only relaxes ONE check: that the app's
/// `/oauth/jwks.json` can be fetched to confirm the signing key — impossible
/// once the app is stopped. A fetched key that does not match still refuses.
/// Skips `argv[0]`, like the other flags.
fn wants_sweep<I: IntoIterator<Item = String>>(args: I) -> bool {
    args.into_iter().skip(1).any(|a| a == SWEEP_FLAG)
}

/// The exit code for a completed revoke-all: any failure is reported, because
/// those tokens may still be live at their PDS even though the rows are gone.
fn revoke_all_exit_code(report: &feather_reader::oauth::revoke::RevokeAllReport) -> i32 {
    if report.failed.is_empty() {
        REVOKE_EXIT_OK
    } else {
        REVOKE_EXIT_SOME_FAILED
    }
}

/// The exit code when the Rust OAuth runtime cannot be built, given how many
/// sessions are stored.
///
/// Without a runtime there is no codec to read the tokens and no client
/// identity to revoke them with. Stored sessions then cannot be revoked — and
/// must not be quietly dropped either, so this refuses and the caller deletes
/// nothing. An empty store has nothing to revoke, which is success.
fn unconfigured_exit_code(stored_sessions: usize) -> i32 {
    if stored_sessions == 0 {
        REVOKE_EXIT_OK
    } else {
        REVOKE_EXIT_ABORT
    }
}

/// Entry point for `featherreader --revoke-all-sessions`. Returns the process
/// exit code; every error that means "nothing was done" maps to
/// [`REVOKE_EXIT_ABORT`] and prints no sentinel, so a teardown aborts. Only a
/// completed walk prints the sentinel ([`revoke_all_sentinel`]) and exits 0 or
/// [`REVOKE_EXIT_SOME_FAILED`].
///
/// **Safe against a LIVE app's database** — on Fly this runs over `fly ssh
/// console` beside the serving process. The pool is opened with WAL and the
/// same 5 s `busy_timeout` the app uses (`store::init_url`), so a concurrent
/// app write makes a statement wait rather than fail; every sign-out deletes one
/// row in its own statement, so the lock is never held across a network call;
/// and a delete that still cannot get the lock is reported as that DID's
/// failure, not a crash of the whole run.
async fn run_revoke_all(sweep: bool) -> i32 {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("revoke-all: ABORT — loading configuration: {err:#}");
            return REVOKE_EXIT_ABORT;
        }
    };
    init_tracing();
    run_revoke_all_with(&config, sweep).await
}

/// [`run_revoke_all`] after configuration — split out so the refusals that
/// depend on files on disk can be tested.
async fn run_revoke_all_with(config: &Config, sweep: bool) -> i32 {
    // `store::init` creates a missing database. Here that would answer "0
    // sessions, all good" about the WRONG file and let a teardown wipe the
    // real one with every token still live.
    if !config.db_path.exists() {
        eprintln!(
            "revoke-all: ABORT — no database at {} (is FEATHERREADER_DB set as the app sees it?)",
            config.db_path.display()
        );
        return REVOKE_EXIT_ABORT;
    }
    let db = match store::init(config).await {
        Ok(db) => db,
        Err(err) => {
            eprintln!("revoke-all: ABORT — opening the database: {err:#}");
            return REVOKE_EXIT_ABORT;
        }
    };
    let http = match feather_reader::build_http_client() {
        Ok(http) => http,
        Err(err) => {
            eprintln!("revoke-all: ABORT — building the HTTP client: {err:#}");
            db.close().await;
            return REVOKE_EXIT_ABORT;
        }
    };
    // Load-only: this mode must never CREATE a signing key (see
    // `OauthRuntime::without_creating_key`). A missing key is a runtime that
    // cannot be built, which refuses if any session is stored.
    let runtime = feather_reader::oauth::runtime::OauthRuntime::without_creating_key(config);
    let code = revoke_all_sessions(&db, runtime, &http, sweep).await;
    db.close().await;
    code
}

/// Revoke every stored session with `runtime`, printing a line per DID and a
/// summary. Returns the process exit code.
///
/// Whether the runtime is the PRODUCTION client (confidential, a real codec,
/// the served signing key) is the pre-flight's job
/// ([`feather_reader::oauth::revoke::preflight`]), which runs before the first
/// sign-out whenever sessions are stored.
async fn revoke_all_sessions(
    db: &store::Pool,
    runtime: Result<feather_reader::oauth::runtime::OauthRuntime>,
    http: &reqwest::Client,
    sweep: bool,
) -> i32 {
    let runtime = match runtime {
        Ok(runtime) => runtime,
        Err(err) => {
            let stored = match feather_reader::oauth::store::list_session_subs(db).await {
                Ok(subs) => subs.len(),
                Err(err) => {
                    eprintln!("revoke-all: ABORT — listing the sessions: {err:#}");
                    return REVOKE_EXIT_ABORT;
                }
            };
            let code = unconfigured_exit_code(stored);
            if code == REVOKE_EXIT_OK {
                println!(
                    "revoke-all: the Rust OAuth client is not configured ({err:#}), and no \
                     sessions are stored — nothing to revoke."
                );
                println!(
                    "{}",
                    revoke_all_sentinel(&feather_reader::oauth::revoke::RevokeAllReport::default())
                );
            } else {
                eprintln!(
                    "revoke-all: ABORT — {stored} session(s) are stored but the Rust OAuth \
                     client cannot be built ({err:#}). Nothing was revoked and NOTHING WAS \
                     DELETED. Run this with the app's own environment (\
                     FEATHERREADER_OAUTH_ENCRYPTION_KEY, FEATHERREADER_PUBLIC_URL, \
                     FEATHERREADER_OAUTH_KEY_PATH) and try again."
                );
            }
            return code;
        }
    };

    // The secrets must be the production ones, not merely present: a wrong
    // encryption key or signing key "works" — every sign-out fails and
    // deletes its row. Checked before the first sign-out. Nothing deleted.
    let jwks_url = feather_reader::oauth::metadata::jwks_uri(&runtime.client);
    if let Err(err) =
        feather_reader::oauth::revoke::preflight(&runtime, http, db, &jwks_url, sweep).await
    {
        eprintln!(
            "revoke-all: ABORT — {err:#}. Nothing was revoked and NOTHING WAS DELETED. Run \
             this inside the app's own environment."
        );
        return REVOKE_EXIT_ABORT;
    }

    // A clock, not a timestamp: each sign-out mints a 60-second client
    // assertion, so the time must be read per session (see `revoke_all`).
    let clock = || chrono::Utc::now().timestamp();
    let report = match feather_reader::oauth::revoke::revoke_all(&runtime, http, db, clock).await {
        Ok(report) => report,
        Err(err) => {
            eprintln!("revoke-all: ABORT — listing the sessions: {err:#}");
            return REVOKE_EXIT_ABORT;
        }
    };
    for did in &report.revoked {
        println!("    revoked {did}");
    }
    for did in &report.no_session {
        println!("    already signed out {did}");
    }
    for did in &report.late {
        println!("    appeared during the walk (signed out by a re-list) {did}");
    }
    for (did, reason) in &report.failed {
        println!("    FAILED  {did}: {reason}");
    }
    // A failed revocation still deletes its row, EXCEPT a session that kept
    // rotating or kept reappearing: that one is left on record, possibly live.
    println!(
        "revoke-all: {} revoked, {} already gone, {} failed ({} appeared during the walk).",
        report.revoked.len(),
        report.no_session.len(),
        report.failed.len(),
        report.late.len()
    );
    // LAST, always: the teardown requires it before it will wipe.
    println!("{}", revoke_all_sentinel(&report));
    revoke_all_exit_code(&report)
}

/// Startup safety check for the DB-size watermark vs. the actual DB volume.
///
/// The watermark (`FEATHERREADER_DB_SIZE_WATERMARK_BYTES`, default 2 GiB) is what
/// pauses new polling before the disk fills. But its default is bigger than a
/// common small volume (a 1 GB box fills first), so on such a box the watermark
/// never trips and can't protect the disk. This logs the effective watermark at
/// startup and, on unix, best-effort `statvfs(3)`s the DB's filesystem and WARNS
/// when the watermark is at/above the available space — telling the operator to
/// set it below the volume size. It never changes the default (the deploy runbook
/// sets it per-volume) and never fails startup.
fn check_watermark_vs_disk(config: &Config) {
    let watermark = config.db_size_watermark_bytes;
    if watermark <= 0 {
        info!("DB-size watermark disabled (0): the poller will not pause on disk pressure");
        return;
    }
    info!(
        watermark_bytes = watermark,
        db = %config.db_path.display(),
        "DB-size watermark effective (poller pauses new fetches at/above this)"
    );

    match available_disk_bytes(&config.db_path) {
        Some(avail) if watermark as u64 >= avail => {
            tracing::warn!(
                watermark_bytes = watermark,
                available_bytes = avail,
                db = %config.db_path.display(),
                "DB-size watermark is >= free space on its volume: it cannot protect the disk \
                 (the volume fills before the poller pauses). Set \
                 FEATHERREADER_DB_SIZE_WATERMARK_BYTES BELOW the volume size."
            );
        }
        Some(avail) => info!(
            available_bytes = avail,
            "DB volume free space checked; watermark below it"
        ),
        None => debug_no_statvfs(),
    }
}

/// Log that the disk-headroom check was skipped (no `statvfs`, or a non-unix
/// target). The effective watermark was already logged, which is the minimum the
/// task requires when `statvfs` is unavailable.
fn debug_no_statvfs() {
    info!(
        "could not read DB volume free space (statvfs unavailable); watermark value logged above"
    );
}

/// Best-effort available bytes on the filesystem holding `path`, via `statvfs(3)`.
/// `None` when the platform has no `statvfs` or the call fails. Uses the parent
/// directory when `path` (the DB file) may not exist yet.
#[cfg(unix)]
fn available_disk_bytes(path: &std::path::Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    // statvfs the DB file's directory — it exists even before the DB file is
    // created, and reports the same filesystem.
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let target = dir.unwrap_or_else(|| std::path::Path::new("."));
    let cstr = std::ffi::CString::new(target.as_os_str().as_bytes()).ok()?;
    // SAFETY: `stat` is written by statvfs on success; we only read it after a 0
    // return. `cstr` is a valid NUL-terminated C string for the duration.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(cstr.as_ptr(), &mut stat) };
    if rc != 0 {
        return None;
    }
    // Available blocks to a non-root process * fragment size. Cast through u128 to
    // avoid overflow on 32-bit `f_frsize`/`f_bavail` widths, then clamp.
    let frsize = stat.f_frsize as u128;
    let bavail = stat.f_bavail as u128;
    Some((frsize.saturating_mul(bavail)).min(u64::MAX as u128) as u64)
}

/// Non-unix fallback: no portable `statvfs`, so the headroom comparison is
/// skipped (the effective watermark is still logged by the caller).
#[cfg(not(unix))]
fn available_disk_bytes(_path: &std::path::Path) -> Option<u64> {
    None
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

/// Resolve when the process receives a shutdown signal: SIGINT (Ctrl-C) or, on
/// unix, SIGTERM. Container runtimes (Fly, Docker, `kill`) stop a process with
/// SIGTERM, whose default disposition is immediate termination — which would
/// skip the graceful-shutdown fan-out and the flusher's final read-state flush,
/// and tear down SQLite abruptly. Handling it drives the same clean drain as
/// Ctrl-C.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    r = tokio::signal::ctrl_c() => {
                        if let Err(err) = r {
                            tracing::error!(%err, "failed to install Ctrl-C handler");
                        }
                    }
                    _ = sigterm.recv() => {}
                }
            }
            Err(err) => {
                // Fall back to SIGINT-only rather than never shutting down.
                tracing::error!(%err, "failed to install SIGTERM handler");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        info!("shutdown signal received");
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(%err, "failed to install Ctrl-C handler");
        }
        info!("shutdown signal received");
    }
}

/// A clonable-per-call shutdown future: resolves the first time the `watch`
/// channel fires (or when the sender is dropped). Each consumer (axum, the
/// poller, the flusher) gets its own receiver and awaits this.
async fn wait_for_shutdown(mut rx: watch::Receiver<()>) {
    // The initial value is already "seen"; wait for the next change (the send) or
    // for the sender to drop.
    let _ = rx.changed().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use feather_reader::oauth::revoke::{fit_to_revoke, RevokeAllReport};

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// `--sweep` is an argument too, and only ever relaxes the sweep's JWKS
    /// reachability check — so it must not be read off argv[0] either.
    #[test]
    fn the_sweep_flag_is_an_argument_not_the_program_path() {
        assert!(wants_sweep(args(&[
            "/app/featherreader",
            "--revoke-all-sessions",
            "--sweep"
        ])));
        assert!(!wants_sweep(args(&[
            "/app/featherreader",
            "--revoke-all-sessions"
        ])));
        assert!(!wants_sweep(args(&["--sweep", "--revoke-all-sessions"])));
    }

    /// **A store no row of which decrypts is refused before anything is
    /// signed out**: a wrong or rotated encryption key. The production client
    /// is otherwise intact (confidential, real codec, the existing key), so
    /// only the pre-flight stands between this and deleting every row
    /// unrevoked. Offline: the decrypt check runs before the JWKS fetch.
    #[tokio::test]
    async fn a_wrong_encryption_key_is_refused_and_deletes_nothing() {
        let dir = scratch("wrongenc");
        let config = confidential_config(&dir);
        let runtime = feather_reader::oauth::runtime::OauthRuntime::new(&config).unwrap();
        assert!(fit_to_revoke(&runtime).is_ok(), "precondition: fit");

        let db = store::init_url("sqlite::memory:").await.unwrap();
        let other = feather_reader::oauth::crypto::Codec::new(Some(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ))
        .unwrap();
        for i in 0..2 {
            feather_reader::oauth::store::put_session(
                &db,
                &other,
                &feather_reader::oauth::store::OAuthSession {
                    sub: format!("did:plc:{i:024}"),
                    issuer: "https://as.invalid".into(),
                    aud: "https://pds.invalid".into(),
                    dpop_key_jwk: "{}".into(),
                    access_token: "a".into(),
                    refresh_token: "r".into(),
                    token_type: "DPoP".into(),
                    granted_scope: "atproto".into(),
                    expires_at: None,
                },
            )
            .await
            .unwrap();
        }

        let code = revoke_all_sessions(&db, Ok(runtime), &reqwest::Client::new(), false).await;
        assert_eq!(
            code, 2,
            "a key that decrypts nothing was allowed to sign out"
        );
        assert_eq!(rows(&db).await, 2, "rows were deleted unrevoked");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The flag is matched as an ARGUMENT only: a binary whose install path
    /// contains it (argv[0]) must not sign every user out on an ordinary start.
    #[test]
    fn the_revoke_all_flag_is_an_argument_not_the_program_path() {
        assert!(wants_revoke_all(args(&[
            "/app/featherreader",
            "--revoke-all-sessions"
        ])));
        assert!(!wants_revoke_all(args(&["--revoke-all-sessions"])));
        assert!(!wants_revoke_all(args(&["/app/featherreader"])));
        assert!(!wants_revoke_all(args(&[
            "/app/featherreader",
            "--migrate-auto-vacuum"
        ])));
    }

    /// 0 when nothing failed; 1 when anything did, so a teardown can warn.
    #[test]
    fn the_exit_code_reports_any_failure() {
        assert_eq!(revoke_all_exit_code(&RevokeAllReport::default()), 0);
        let ok = RevokeAllReport {
            revoked: vec!["did:plc:a".into()],
            no_session: vec!["did:plc:b".into()],
            failed: vec![],
            late: vec![],
        };
        assert_eq!(revoke_all_exit_code(&ok), 0);
        let some_failed = RevokeAllReport {
            failed: vec![("did:plc:c".into(), "status 500".into())],
            ..ok
        };
        assert_eq!(
            revoke_all_exit_code(&some_failed),
            3,
            "partial failure must not share 1 with every generic failure"
        );
    }

    /// The sentinel is exact: `deploy/teardown.sh` matches it with a regex and
    /// cross-checks `failed=` against the exit code.
    #[test]
    fn the_sentinel_names_every_count() {
        let report = RevokeAllReport {
            revoked: vec!["a".into(), "b".into()],
            no_session: vec!["c".into()],
            failed: vec![("d".into(), "x".into())],
            late: vec![],
        };
        assert_eq!(
            revoke_all_sentinel(&report),
            "revoke-all-sessions: revoked=2 no_session=1 failed=1"
        );
        assert_eq!(
            revoke_all_sentinel(&RevokeAllReport::default()),
            "revoke-all-sessions: revoked=0 no_session=0 failed=0"
        );
    }

    /// A per-test scratch directory under the system temp dir.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fr-main-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A production-like (confidential client, rust backend) configuration
    /// whose database and signing key live in `dir`.
    fn confidential_config(dir: &std::path::Path) -> Config {
        Config {
            db_path: dir.join("featherreader.db"),
            repo_backend: feather_reader::metrics::Backend::Rust,
            public_url: "https://feather-reader.com".into(),
            oauth: feather_reader::config::OauthConfig {
                encryption_key: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
                key_path: dir.join("oauth-signing-key.json"),
                plc_directory: "https://plc.invalid".into(),
                ..feather_reader::config::OauthConfig::default()
            },
            ..Config::default()
        }
    }

    /// **No database, no answer.** `store::init` would create an empty file and
    /// report "0 sessions" about it — and a teardown would then wipe the REAL
    /// database with every token in it still live.
    #[tokio::test]
    async fn a_missing_database_is_refused_and_not_created() {
        let dir = scratch("nodb");
        let config = confidential_config(&dir);
        assert_eq!(run_revoke_all_with(&config, false).await, 2);
        assert!(
            !config.db_path.exists(),
            "the revoke-all created a database at the wrong path"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A missing signing key is refused, never created.**
    ///
    /// `OauthRuntime::new` creates the key when it is absent. Run from the wrong
    /// directory (the default path is RELATIVE) that minted a fresh key under
    /// the same `kid`; the live app still published the old JWKS, so every
    /// client assertion was rejected — and every row deleted anyway, leaving the
    /// teardown to proceed over live tokens.
    #[tokio::test]
    async fn a_missing_signing_key_is_refused_and_not_created() {
        let dir = scratch("nokey");
        let config = confidential_config(&dir);
        let url = format!("sqlite://{}", config.db_path.display());
        let pool = store::init_url(&url).await.unwrap();
        sqlx::query(
            "INSERT INTO oauth_session (sub, issuer, aud, dpop_key_jwk, access_token, \
             refresh_token, token_type, granted_scope, expires_at) \
             VALUES ('did:plc:keyless', 'https://as.invalid', 'https://pds.invalid', \
             'x', 'x', 'x', 'DPoP', 'atproto', NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        assert_eq!(run_revoke_all_with(&config, false).await, 2);
        assert!(
            !config.oauth.key_path.exists(),
            "the revoke-all CREATED a signing key the PDSes have never seen"
        );
        let pool = store::init_url(&url).await.unwrap();
        assert_eq!(
            rows(&pool).await,
            1,
            "rows were deleted without a revocation"
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **An incomplete environment must not revoke as the wrong client.**
    ///
    /// Without `FEATHERREADER_PUBLIC_URL`, `Config` falls back to localhost:
    /// not production-like, so the production checks are skipped and the
    /// runtime builds as atproto's PUBLIC dev client. Every revocation is then
    /// sent under the wrong `client_id` (or the rows fail to decrypt), the
    /// sign-out deletes each row anyway, and a teardown proceeds over live
    /// tokens. With sessions stored, that runtime is refused and nothing goes.
    #[tokio::test]
    async fn a_public_dev_client_runtime_is_refused_while_sessions_are_stored() {
        let dir = scratch("devclient");
        let mut config = confidential_config(&dir);
        config.public_url = "http://127.0.0.1:8080".into();
        let runtime = feather_reader::oauth::runtime::OauthRuntime::new(&config);
        assert!(runtime.is_ok(), "precondition: the dev runtime builds");
        // Named as what it is, so the operator knows WHICH variable is missing
        // (the keyless check alone would also refuse, for a misleading reason).
        let why = format!(
            "{:#}",
            fit_to_revoke(runtime.as_ref().unwrap()).expect_err("the dev client was accepted")
        );
        assert!(why.contains("public dev client"), "{why}");

        let db = db_with_rows(2).await;
        let code = revoke_all_sessions(&db, runtime, &reqwest::Client::new(), false).await;
        assert_eq!(code, 2, "revoked as the public dev client");
        assert_eq!(rows(&db).await, 2, "rows were deleted unrevoked");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same for a confidential client with NO encryption key: the `Null`
    /// codec cannot read a single production row, so every sign-out would
    /// fail and delete.
    #[tokio::test]
    async fn a_null_codec_runtime_is_refused_while_sessions_are_stored() {
        let dir = scratch("nullcodec");
        let mut config = confidential_config(&dir);
        config.oauth.encryption_key = None;
        let runtime = feather_reader::oauth::runtime::OauthRuntime::new(&config);
        assert!(
            matches!(
                runtime.as_ref().map(|rt| &rt.codec),
                Ok(feather_reader::oauth::crypto::Codec::Null)
            ),
            "precondition: a confidential runtime with the Null codec"
        );

        let db = db_with_rows(2).await;
        let code = revoke_all_sessions(&db, runtime, &reqwest::Client::new(), false).await;
        assert_eq!(code, 2, "revoked with the Null codec");
        assert_eq!(rows(&db).await, 2, "rows were deleted unrevoked");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The fitness check accepts exactly the production client: confidential,
    /// a real codec, and a loaded key.
    #[test]
    fn only_the_production_client_is_fit_to_revoke() {
        let dir = scratch("fit");
        let config = confidential_config(&dir);
        let rt = feather_reader::oauth::runtime::OauthRuntime::new(&config).unwrap();
        assert!(fit_to_revoke(&rt).is_ok(), "{:?}", fit_to_revoke(&rt).err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A confidential client WITHOUT its key (the sidecar backend, no key file
    /// on disk — `new` then neither loads nor creates one) cannot sign a single
    /// client assertion, so it is not fit either.
    #[test]
    fn a_confidential_client_without_its_key_is_not_fit() {
        let dir = scratch("nokeyfit");
        let mut config = confidential_config(&dir);
        config.repo_backend = feather_reader::metrics::Backend::Sidecar;
        let rt = feather_reader::oauth::runtime::OauthRuntime::new(&config).unwrap();
        assert!(rt.client_key.is_none(), "precondition: no key loaded");
        let err = fit_to_revoke(&rt).expect_err("a keyless confidential client was accepted");
        assert!(format!("{err:#}").contains("signing key"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without a runtime, stored sessions cannot be revoked: refuse (2) rather
    /// than report success. An empty store has nothing to revoke (0).
    #[test]
    fn an_unconfigured_runtime_refuses_only_when_sessions_exist() {
        assert_eq!(unconfigured_exit_code(0), 0);
        assert_eq!(unconfigured_exit_code(1), 2);
        assert_eq!(unconfigured_exit_code(500), 2);
    }

    async fn db_with_rows(n: usize) -> store::Pool {
        let pool = store::init_url("sqlite::memory:").await.unwrap();
        for i in 0..n {
            sqlx::query(
                "INSERT INTO oauth_session (sub, issuer, aud, dpop_key_jwk, access_token, \
                 refresh_token, token_type, granted_scope, expires_at) \
                 VALUES (?, 'https://as.example', 'https://pds.example', 'x', 'x', 'x', \
                 'DPoP', 'atproto', NULL)",
            )
            .bind(format!("did:plc:{i:024}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        pool
    }

    async fn rows(pool: &store::Pool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_session")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// **Rows that cannot be revoked are not silently dropped.** With no
    /// runtime, the command refuses with 2 and leaves every row in place, so
    /// the operator can fix the configuration and run it again.
    #[tokio::test]
    async fn an_unconfigured_runtime_with_sessions_refuses_and_deletes_nothing() {
        let db = db_with_rows(2).await;
        let code = revoke_all_sessions(
            &db,
            Err(anyhow::anyhow!("no encryption key")),
            &reqwest::Client::new(),
            false,
        )
        .await;
        assert_eq!(code, 2);
        assert_eq!(rows(&db).await, 2, "rows were dropped without a revocation");
    }

    #[tokio::test]
    async fn an_unconfigured_runtime_with_no_sessions_has_nothing_to_do() {
        let db = db_with_rows(0).await;
        let code = revoke_all_sessions(
            &db,
            Err(anyhow::anyhow!("no encryption key")),
            &reqwest::Client::new(),
            false,
        )
        .await;
        assert_eq!(code, 0);
    }
}
