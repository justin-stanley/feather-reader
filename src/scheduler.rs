//! Background schedulers — the **poll scheduler** and the **read-state flusher**.
//!
//! These are the two long-lived `tokio` tasks that turn FeatherReader from a
//! request/response web app into a live reader. Both are spawned from `main`
//! after the [`AppState`] is built, behind a config flag so tests and local
//! dev can disable them, and both are **graceful-shutdown-aware**: they select
//! on a shutdown signal and drain before returning.
//!
//! ## Poll scheduler ([`run_poller`])
//!
//! A single interval loop that, on each tick, asks the store for the feeds
//! whose `next_poll` is **due** ([`store::due_feeds`]) and polls each with
//! [`feed::poll_feed`] — which already does the conditional GET (`ETag` /
//! `Last-Modified`) and returns a [`feed::PollOutcome`]. The scheduler owns
//! **cadence**: `poll_feed` deliberately leaves `next_poll = None`, so after
//! each poll the scheduler computes the next-poll time from the feed's
//! `fetchHint` cadence (or the configured default) — and on failure honours the
//! **backoff** the outcome carries. Polls are **staggered / rate-limited** with
//! a bounded [`Semaphore`] and a small per-launch delay, so a batch of due
//! feeds does not stampede.
//!
//! ## Read-state flusher ([`run_flusher`])
//!
//! A **debounced** loop (default ~60 s, `Config`-tunable via the env) that
//! scans the store for **dirty** per-feed read cursors ([`store::dirty_cursors`])
//! across every DID, coalesces each DID's dirty cursors into **one**
//! `com.atproto.repo.applyWrites` batch via
//! `SidecarClient::flush_read_states`, and — only on success — clears the
//! `dirty` flag ([`store::clear_cursor_dirty`]). Dozens of articles read in one
//! sitting collapse into one write per feed (one record per feed, keyed by a
//! feed-derived rkey), and several feeds' cursors ride one round-trip. It also
//! flushes **once more on graceful shutdown** so a Ctrl-C never strands unsynced
//! read-state.
//!
//! ## Relay adoption probe ([`run_adoption_probe`])
//!
//! One unauthenticated GET per configured relay per day, counting the repos on
//! the public atproto network that hold `community.lexicon.rss.subscription`
//! (see `design/NETWORK-SPEC.md` §4 and [`feather_reader::network`]). It holds no
//! personal data, writes one `network_stat` row per relay, and cannot affect the
//! reader: every failure is a `warn!` that leaves the previous observation in
//! place. `FEATHERREADER_ADOPTION_INTERVAL_SECS=0` disables it on its own.

use std::sync::Arc;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use sqlx::Row;
use tokio::sync::{watch, Semaphore};
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, error, info, warn};

use feather_reader::feed::{self, PollOutcome};
use std::collections::HashSet;

use feather_reader::lexicon::nsid;
use feather_reader::network::RelayClient;
use feather_reader::readstate::{flush_did, fnv1a_64};
use feather_reader::store::{self, Feed, Pool};
use feather_reader::AppState;

// ---------------------------------------------------------------------------
// Tunables (env-overridable so tests/dev can move fast; sane defaults)
// ---------------------------------------------------------------------------

/// How often the poll scheduler wakes to look for due feeds. This is the *loop*
/// cadence, not the per-feed poll interval — a feed is only fetched when its own
/// `next_poll` is due. Overridable via `FEATHERREADER_POLL_TICK_SECS`.
const DEFAULT_POLL_TICK: Duration = Duration::from_secs(60);

/// Max feeds pulled off the due queue per tick — bounds the burst of work a
/// single wake can schedule. Overridable via `FEATHERREADER_POLL_BATCH`.
const DEFAULT_POLL_BATCH: i64 = 50;

/// Max feeds fetched concurrently — the rate limit. Overridable via
/// `FEATHERREADER_POLL_CONCURRENCY`.
const DEFAULT_POLL_CONCURRENCY: usize = 4;

/// Small delay between *launching* each feed fetch, so a batch of due feeds is
/// staggered rather than fired in one instant (polite to the network + to any
/// single upstream). Overridable via `FEATHERREADER_POLL_STAGGER_MS`.
const DEFAULT_POLL_STAGGER: Duration = Duration::from_millis(250);

/// The read-state flush debounce window — a given DID's dirty cursors are
/// flushed at most once per this interval. ~60 s per the design. Overridable via
/// `FEATHERREADER_FLUSH_DEBOUNCE_SECS`.
const DEFAULT_FLUSH_DEBOUNCE: Duration = Duration::from_secs(60);

/// How often the invite-code TTL sweep runs, expiring `active` codes past their
/// `expires_at`. Hourly is plenty — expiry is coarse-grained and `redeem_code`
/// already rejects a past-expiry code at redeem time regardless of this sweep, so
/// this is just housekeeping. Overridable via `FEATHERREADER_CODE_SWEEP_SECS`.
const DEFAULT_CODE_SWEEP: Duration = Duration::from_secs(3600);

/// How often the retention sweep runs, deleting shared-cache entries older than
/// `config.retention_days`. Daily is plenty — the window is coarse (days) and the
/// per-feed `max_entries_per_feed` trim already bounds any single feed on every
/// poll. Overridable via `FEATHERREADER_RETENTION_SWEEP_SECS`.
const DEFAULT_RETENTION_SWEEP: Duration = Duration::from_secs(24 * 60 * 60);

/// Delay before the FIRST adoption probe after boot. Unlike the local sweeps,
/// this tick is an outbound request to somebody else's relay, and
/// `deploy/container-entrypoint.sh` tears the machine down (and Fly recreates it)
/// the moment any child exits — so an immediate first tick would probe the relay
/// once per crash-loop restart rather than once per day.
const ADOPTION_STARTUP_DELAY: Duration = Duration::from_secs(5 * 60);

/// Delay before each local loop's FIRST tick after boot.
///
/// All four used to fire immediately. Combined with the container supervisor —
/// which tears the machine down the moment any child exits, and Fly restarts it
/// — "once per boot" becomes "once per crash-loop restart", and the loops all
/// pile onto the same instant while the machine is still opening its database
/// and warming its caches. The adoption probe already reasoned about exactly
/// this ([`ADOPTION_STARTUP_DELAY`]); its three siblings did not.
///
/// The values are deliberately DISTINCT rather than jittered. There is exactly
/// one machine, so there is no fleet to de-synchronise; what matters is that the
/// four loops do not land together, and fixed offsets give that property while
/// staying reproducible in a test. They are also short enough to be irrelevant
/// to an hourly poller and a daily sweep.
///
/// `FEATHERREADER_STARTUP_DELAY_SECS` scales all of them (0 restores the old
/// immediate-first-tick behaviour), for dev loops and integration tests that
/// cannot wait.
const POLLER_STARTUP_DELAY: Duration = Duration::from_secs(30);
const PENDING_SWEEP_STARTUP_DELAY: Duration = Duration::from_secs(45);
const CODE_SWEEP_STARTUP_DELAY: Duration = Duration::from_secs(60);
const RETENTION_STARTUP_DELAY: Duration = Duration::from_secs(90);

/// Which background loop an offset belongs to.
///
/// **An enum, not a string key.** The first cut of this used `&'static str`
/// names looked up with `.unwrap_or(POLLER_STARTUP_DELAY)`, and a review showed
/// that was strictly WORSE than the per-loop constants it replaced: mistyping
/// `offset_for("pending-sweeper")` compiled, passed all 706 tests, and silently
/// moved that loop onto the poller's tick — the everything-at-once collision the
/// offsets exist to prevent. A wrong constant name used to be a compile error;
/// a wrong string was a silent production change.
///
/// With an enum and an exhaustive `match` the table is total by construction,
/// there is no fallback to be wrong, and a typo is a compile error again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Loop {
    Poller,
    PendingSweep,
    CodeSweep,
    Retention,
    Adoption,
}

impl Loop {
    /// The registry: every offset-bearing loop, in the order `spawn` starts them.
    ///
    /// A variant missing from here is never STARTED — a visible absence — rather
    /// than started with the wrong offset, which was silent.
    const ALL: [Loop; 5] = [
        Loop::Poller,
        Loop::PendingSweep,
        Loop::CodeSweep,
        Loop::Retention,
        Loop::Adoption,
    ];

    /// Start this loop, with its own offset.
    ///
    /// **The variant names the loop AND the offset, in one place.** The previous
    /// shape passed `offset_for(Loop::X)` as a positional argument at five
    /// near-identical `tokio::spawn` lines, ~600 lines from the loop it
    /// configured — so writing `offset_for(Loop::Poller)` at the pending-sweeper
    /// site compiled, passed 707 tests and clippy, and silently collided the two
    /// loops at boot. That is the third form of this same bug; the first two were
    /// a wrong constant and a mistyped string key.
    ///
    /// **What is still NOT prevented:** pairing a variant with the wrong `run_*`
    /// in an arm below — `Loop::PendingSweep => run_poller(..)` compiles and the
    /// suite passes. That is a different failure (one loop never starts, another
    /// runs twice) and it is narrower: one exhaustive match in one place, rather
    /// than five spawn sites scattered through the file. Catching it would need
    /// each loop to report that it started, i.e. production instrumentation for a
    /// test — not obviously worth it, but it is a hole, not an absence of one.
    fn spawn_with(
        self,
        state: AppState,
        shutdown: watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let startup = offset_for(self);
        match self {
            Loop::Poller => tokio::spawn(run_poller(state, shutdown, startup)),
            Loop::PendingSweep => tokio::spawn(run_pending_sweeper(state, shutdown, startup)),
            Loop::CodeSweep => tokio::spawn(run_code_sweeper(state, shutdown, startup)),
            Loop::Retention => tokio::spawn(run_retention_sweeper(state, shutdown, startup)),
            Loop::Adoption => tokio::spawn(run_adoption_probe(state, shutdown, startup)),
        }
    }

    /// This loop's startup offset. Exhaustive: adding a variant without an
    /// offset does not compile.
    const fn startup_offset(self) -> Duration {
        match self {
            Loop::Poller => POLLER_STARTUP_DELAY,
            Loop::PendingSweep => PENDING_SWEEP_STARTUP_DELAY,
            Loop::CodeSweep => CODE_SWEEP_STARTUP_DELAY,
            Loop::Retention => RETENTION_STARTUP_DELAY,
            Loop::Adoption => ADOPTION_STARTUP_DELAY,
        }
    }
}

/// One loop's offset with the `FEATHERREADER_STARTUP_DELAY_SECS` ceiling applied.
/// The one place the startup-override variable is named.
///
/// **A constant, because the name was untested glue.** `offset_for` is the
/// production path and no test could reach it without `set_var`, so mistyping
/// the key by one character left the whole suite AND clippy green while silently
/// disabling the override for every loop. The test below spells the name
/// independently, so the two have to agree.
const STARTUP_DELAY_ENV: &str = "FEATHERREADER_STARTUP_DELAY_SECS";

fn offset_for(which: Loop) -> Duration {
    offset_from(which, std::env::var(STARTUP_DELAY_ENV).ok())
}

/// [`offset_for`] with the environment value passed in.
///
/// Split for the same reason `startup_delay_from` is: so the COMPOSITION —
/// this loop's offset, then the ceiling — is testable without reading the
/// environment. Deleting the ceiling here disables
/// `FEATHERREADER_STARTUP_DELAY_SECS` for every loop at once, and asserting it
/// through `offset_for` could not catch that without `set_var`, which is a
/// documented data race against the ~39 `env::var` reads in this binary.
fn offset_from(which: Loop, raw: Option<String>) -> Duration {
    startup_delay_from(which.startup_offset(), raw)
}

/// Apply the `FEATHERREADER_STARTUP_DELAY_SECS` override to a startup delay,
/// with the environment value passed in.
///
/// The variable is a CEILING, not a replacement: it can only shorten the wait,
/// so setting it cannot accidentally push a production loop out further than its
/// constant intends.
///
/// Takes the raw value rather than reading it, so the ceiling behaviour is
/// testable without `std::env::set_var` — a documented data race against the ~39
/// `std::env::var` reads elsewhere in this binary, and this was the only
/// `set_var` in `src/`, in a 650-test multithreaded runner.
///
/// Split out so the ceiling behaviour is testable without `std::env::set_var`,
/// which is a documented data race against the ~39 `std::env::var` reads
/// elsewhere in this binary — and this was the only `set_var` in `src/`, in a
/// 650-test multithreaded runner. Latent today because nothing else reads that
/// key; a flaky crash the moment something does.
fn startup_delay_from(default: Duration, raw: Option<String>) -> Duration {
    match raw.as_deref().map(str::trim) {
        Some(v) => match v.parse::<u64>() {
            Ok(secs) => {
                let requested = Duration::from_secs(secs);
                if requested > default {
                    // The variable is a CEILING, which is a good property and a
                    // surprising one: setting it to 300 changes nothing. Saying
                    // so beats leaving an operator to wonder why.
                    info!(
                        requested_secs = secs,
                        effective_secs = default.as_secs(),
                        "FEATHERREADER_STARTUP_DELAY_SECS is a ceiling and can only \
                         SHORTEN a startup delay; using the built-in value"
                    );
                    return default;
                }
                requested
            }
            Err(_) => {
                warn!(
                    value = v,
                    "FEATHERREADER_STARTUP_DELAY_SECS is not a number; ignoring it"
                );
                default
            }
        },
        None => default,
    }
}

/// An `Interval` whose first tick is `delay` from now, then every `period`,
/// skipping missed ticks rather than bursting to catch up.
fn delayed_interval(delay: Duration, period: Duration) -> tokio::time::Interval {
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + delay, period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker
}

/// Read a `Duration` (in seconds) from the environment, or fall back.
fn env_duration_secs(key: &str, default: Duration) -> Duration {
    match std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(secs) if secs > 0 => Duration::from_secs(secs),
        _ => default,
    }
}

/// Read a `u64`/`usize`/`i64` scalar from the environment, or fall back.
fn env_scalar<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<T>().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Config flag — is the background machinery enabled?
// ---------------------------------------------------------------------------

/// Whether the background schedulers should run.
///
/// Defaults to **on** for a real deployment, but is disabled when
/// `FEATHERREADER_DISABLE_SCHEDULER` is truthy (`1`/`true`/`yes`/`on`) — the
/// seam tests and pure-web local runs use so they don't spin poll/flush loops.
/// Kept here (not in `Config`) so this task owns its own flag and touches no
/// other module.
pub fn schedulers_enabled() -> bool {
    match std::env::var("FEATHERREADER_DISABLE_SCHEDULER") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

// ---------------------------------------------------------------------------
// Spawn helper — wire both tasks to a shared shutdown signal
// ---------------------------------------------------------------------------

/// Spawn the poll scheduler and the read-state flusher as detached `tokio`
/// tasks, each wired to the same graceful-shutdown signal.
///
/// Returns immediately with the [`JoinHandle`](tokio::task::JoinHandle)s so the
/// caller *may* await them at shutdown; `main` typically fires-and-forgets since
/// the shutdown channel is what actually stops them. A no-op (returns an empty
/// vec) when [`schedulers_enabled`] is false.
///
/// `shutdown` is a `watch` receiver that fires when the process is asked to stop
/// (the same signal `axum::serve` uses for graceful shutdown). Each task takes
/// its own clone of the receiver.
pub fn spawn(state: AppState, shutdown: watch::Receiver<()>) -> Vec<tokio::task::JoinHandle<()>> {
    if !schedulers_enabled() {
        info!("background schedulers disabled (FEATHERREADER_DISABLE_SCHEDULER)");
        // Recorded so a handler can tell "never started" from "started and
        // stopped ticking" — identical from the outside, opposite responses.
        state.runtime_health.set_schedulers_enabled(false);
        return Vec::new();
    }
    state.runtime_health.set_schedulers_enabled(true);

    info!(
        "spawning background schedulers (poller + sweepers + adoption probe + read-state flusher)"
    );

    // **Driven off the registry, not five hand-written lines.** Every offset-
    // bearing loop is started here by iterating `Loop::ALL`, so a loop cannot be
    // given another's offset — the variant chooses both.
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    for_each_loop(|l| handles.push(l.spawn_with(state.clone(), shutdown.clone())));

    // The two loops with NO startup offset. `run_metrics_flusher` deliberately
    // fires immediately at boot; `run_flusher` swallows its first tick. Neither
    // is in `Loop`, so neither is covered by the distinctness invariant — stated
    // here because the test's message would otherwise read as covering all loops.
    handles.push({
        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move { run_metrics_flusher(state, shutdown).await })
    });
    // Last: consumes the un-cloned `state` / `shutdown` by move.
    handles.push(tokio::spawn(
        async move { run_flusher(state, shutdown).await },
    ));

    handles
}

/// Call `f` once for every offset-bearing loop, in registry order.
///
/// **The iteration itself, extracted so a test can watch it.** `spawn` iterated
/// `Loop::ALL` inline and nothing in the tree reached `spawn` — so a `.filter()`
/// dropping one loop compiled, passed the whole suite, passed clippy, and the
/// pending-login sweeper simply never started while nonce rows accumulated
/// unbounded.
///
/// That is the FOURTH form of one defect in this file. Each fix closed the seam
/// a level down — a wrong constant, then a wrong string key, then a wrong
/// positional argument — while the untested glue moved a level up. This is the
/// level `spawn` actually decides at.
fn for_each_loop(mut f: impl FnMut(Loop)) {
    for l in Loop::ALL {
        f(l);
    }
}

/// Resolve when the `watch` channel fires (the shutdown broadcast) or its sender
/// is dropped — the shared "time to stop" signal both loops select on.
async fn shutdown_fired(rx: &mut watch::Receiver<()>) {
    let _ = rx.changed().await;
}

// ---------------------------------------------------------------------------
// Poll scheduler
// ---------------------------------------------------------------------------

/// The poll-scheduler loop. Wakes on an interval, selects due feeds, and polls
/// each (conditional-GET + backoff via [`feed::poll_feed`]), staggered and
/// concurrency-bounded. Returns when `shutdown` resolves.
pub async fn run_poller(state: AppState, mut shutdown: watch::Receiver<()>, startup: Duration) {
    let tick = env_duration_secs("FEATHERREADER_POLL_TICK_SECS", DEFAULT_POLL_TICK);
    let batch = env_scalar::<i64>("FEATHERREADER_POLL_BATCH", DEFAULT_POLL_BATCH).max(1);
    let concurrency =
        env_scalar::<usize>("FEATHERREADER_POLL_CONCURRENCY", DEFAULT_POLL_CONCURRENCY).max(1);
    // The stagger default is sub-second, so read the ms knob directly.
    let stagger = std::env::var("FEATHERREADER_POLL_STAGGER_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_POLL_STAGGER);

    info!(
        ?tick,
        batch,
        concurrency,
        ?stagger,
        default_interval = ?state.config.poll_interval,
        "poll scheduler started"
    );

    let client = match feed::build_client() {
        Ok(c) => c,
        Err(err) => {
            error!(%err, "poll scheduler: failed to build HTTP client; poller will not run");
            return;
        }
    };
    let limiter = Arc::new(Semaphore::new(concurrency));

    // Not an immediate first tick: see `POLLER_STARTUP_DELAY`. Missed ticks are
    // skipped rather than burst through, so a slow poll round does not queue up.
    let mut ticker = delayed_interval(startup, tick);

    loop {
        tokio::select! {
            _ = shutdown_fired(&mut shutdown) => {
                info!("poll scheduler: shutdown signal received, stopping");
                break;
            }
            _ = ticker.tick() => {
                if let Err(err) =
                    poll_due_once(&state, &client, &limiter, batch, stagger, &shutdown).await
                {
                    // A store-level error is worth logging, but must not kill the
                    // loop — the next tick retries.
                    error!(%err, "poll scheduler: tick failed");
                }
                // Heartbeat, stamped on COMPLETION — including after a failed
                // tick, which is the honest reading: the loop is alive and
                // erroring, which is a different condition from the loop being
                // wedged, and `/health` reports them differently. A tick that
                // hangs forever never reaches here, which is the point.
                state.runtime_health.poll_tick_completed(Utc::now().timestamp());
            }
        }
    }
}

/// One poll round: select due feeds and poll each, concurrency-bounded and
/// staggered. Feed-level failures are handled per-feed (rescheduled with the
/// outcome's backoff); only a store-level failure to *select* propagates.
async fn poll_due_once(
    state: &AppState,
    client: &reqwest::Client,
    limiter: &Arc<Semaphore>,
    batch: i64,
    stagger: Duration,
    shutdown: &watch::Receiver<()>,
) -> anyhow::Result<()> {
    // DB-size watermark: above it, stop pulling NEW content so a small box can't
    // be filled to a crash by the poller. Reads/serving continue; only fetching
    // is paused. `<= 0` disables the watermark.
    let watermark = state.config.db_size_watermark_bytes;
    if watermark > 0 {
        match store::db_size_bytes(&state.db).await {
            Ok(size) if size >= watermark => {
                warn!(
                    db_size_bytes = size,
                    watermark_bytes = watermark,
                    "DB size at/above watermark: pausing new polling until it drops (retention/prune)"
                );
                // No VACUUM here. `db_size_bytes` is already freelist-aware
                // (page_count - freelist_count), so the daily retention sweep's
                // DELETE lowers the measured size and lifts the watermark WITHOUT
                // a full-file rewrite — and the sweeper reclaims after it prunes
                // (see `run_retention_sweeper`). Running VACUUM on every poll tick
                // while over the watermark was both redundant (freelist accounting
                // already reflects freed pages) and dangerous: a full VACUUM needs
                // free disk ~= the live DB size to write the new file, which is
                // exactly what's scarce under the disk pressure that tripped the
                // watermark.
                //
                // Recorded, not just logged. This is one of the two states that
                // stop feeds updating, and until now the per-tick `warn!` was its
                // ONLY trace — so `/stats` showed `overdue` climbing and
                // `polled_last_hour` falling with nothing to say which of the two
                // causes was responsible. See `runtime_health`.
                state.runtime_health.set_watermark(true);
                return Ok(());
            }
            Ok(_) => state.runtime_health.set_watermark(false),
            Err(err) => warn!(%err, "could not read DB size for watermark check; polling anyway"),
        }
    }

    let now = now_rfc3339();
    let due = store::due_feeds(&state.db, &now, batch).await?;
    if due.is_empty() {
        debug!("poll scheduler: no feeds due");
        return Ok(());
    }
    info!(count = due.len(), "poll scheduler: polling due feeds");

    let mut handles = Vec::with_capacity(due.len());
    let mut abandoned = 0usize;
    for feed in due {
        // **Stop LAUNCHING once shutdown is asked for.**
        //
        // The loop above only checked shutdown between ticks, so once inside a
        // tick this ran to completion: a full batch is 50 feeds at a 250 ms
        // stagger — 12.5 s just to launch — against Fly's default 5 s
        // `kill_timeout`. Every feed in the batch has already been leased an hour
        // forward by `poll_and_reschedule`, and SIGKILL rolls nothing back, so a
        // routine deploy landing mid-tick silently pushed up to 50 feeds out by
        // an hour. Nobody would attribute that: it presents as "some feeds are
        // behind after a deploy", and `/stats` cannot show it as overdue because
        // `next_poll` was moved FORWARD.
        //
        // Feeds not launched keep whatever `next_poll` they had, so they stay due
        // and the next boot picks them up immediately.
        if shutdown.has_changed().unwrap_or(true) {
            abandoned += 1;
            continue;
        }
        // Acquire a permit *before* launching so at most `concurrency` fetches
        // are ever in flight; the permit is released when the task ends.
        let permit = match Arc::clone(limiter).acquire_owned().await {
            Ok(p) => p,
            Err(_) => break, // semaphore closed — shutting down
        };
        let pool = state.db.clone();
        let client = client.clone();
        let default_interval = state.config.poll_interval;
        let max_entries_per_feed = state.config.max_entries_per_feed;
        handles.push(tokio::spawn(async move {
            let _permit = permit; // held for the duration of this poll
            poll_and_reschedule(
                &pool,
                &client,
                &feed,
                default_interval,
                max_entries_per_feed,
            )
            .await;
        }));
        // Stagger launches so a batch doesn't fire in one instant.
        if !stagger.is_zero() {
            tokio::time::sleep(stagger).await;
        }
    }

    if abandoned > 0 {
        info!(
            abandoned,
            "poll scheduler: shutdown requested mid-round; these feeds were not \
             launched and stay due"
        );
    }

    // Drain the batch so the next tick starts from a clean slate.
    for h in handles {
        if let Err(err) = h.await {
            warn!(%err, "poll scheduler: a feed poll task panicked");
        }
    }
    Ok(())
}

/// Poll one feed and persist its **next** poll time.
///
/// [`feed::poll_feed`] never returns `Err` for a merely-broken feed (only for a
/// broken local store), and it deliberately leaves `next_poll` unset — cadence
/// is the scheduler's job. So on every outcome we compute and store the next
/// poll time: the feed's cadence on success/not-modified, the outcome's backoff
/// on failure.
async fn poll_and_reschedule(
    pool: &Pool,
    client: &reqwest::Client,
    feed: &Feed,
    default_interval: Duration,
    max_entries_per_feed: i64,
) {
    poll_and_reschedule_with(pool, feed, default_interval, |pool, feed| {
        feed::poll_feed(pool, client, feed, max_entries_per_feed)
    })
    .await;
}

/// [`poll_and_reschedule`] with the fetch injected, so the ordering guarantee
/// below can be tested without a network — the same shape the OAuth
/// orchestrators use.
async fn poll_and_reschedule_with<'a, F, Fut>(
    pool: &'a Pool,
    feed: &'a Feed,
    default_interval: Duration,
    poll: F,
) where
    F: FnOnce(&'a Pool, &'a Feed) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<PollOutcome>>,
{
    // **Lease the feed forward BEFORE fetching it.**
    //
    // Nothing used to be written to the feed row until after `poll_feed`
    // returned. `due_feeds` orders by `next_poll ASC` and the poller's first
    // tick fires immediately, so a feed whose fetch or parse takes the PROCESS
    // down was re-selected first on every restart — forever, with no escape
    // short of editing the database by hand.
    //
    // The trigger is plausible on a 512 MB box: `MAX_BODY_BYTES` is 8 MiB and
    // concurrency is 4, so 32 MiB of raw bodies can be in flight, and `feed_rs`
    // builds an in-memory model several times the wire size alongside the
    // sanitized `Vec<NewEntry>`. `deploy/container-entrypoint.sh` tears the
    // machine down the moment any child exits, and Fly restarts it — which is
    // what turns "one bad poll" into a loop.
    //
    // Writing the optimistic next time FIRST converts that permanent loop into
    // a single restart: the killer feed goes to the BACK of the due queue
    // instead of the front, every other feed gets polled, and the instance
    // heals itself. The value is the cadence the feed would have got had the
    // poll succeeded, so the common case — the poll returns and overwrites this
    // — is unchanged.
    //
    // The cost is one extra tiny UPDATE per feed per poll on a single-writer
    // database. Against an unrecoverable instance, that is not a close call.
    if let Err(err) = set_next_poll(pool, &feed.url, cadence_for(feed, default_interval)).await {
        // Non-fatal: the poll is still worth attempting. It just means a crash
        // during THIS fetch is not protected.
        warn!(feed = %feed.url, %err, "failed to lease next_poll before fetching; \
                                       a crash during this poll would re-select this feed first");
    }

    let next_delay = match poll(pool, feed).await {
        Ok(PollOutcome::Updated { new_entries }) => {
            debug!(feed = %feed.url, new_entries, "polled: updated");
            // A successful poll clears the consecutive-error streak so a
            // previously-broken feed returns to its normal cadence.
            if let Err(err) = store::reset_feed_errors(pool, &feed.url).await {
                warn!(feed = %feed.url, %err, "failed to reset feed error count");
            }
            cadence_for(feed, default_interval)
        }
        Ok(PollOutcome::NotModified) => {
            debug!(feed = %feed.url, "polled: not modified");
            // 304 is a healthy poll too — reset the error streak.
            if let Err(err) = store::reset_feed_errors(pool, &feed.url).await {
                warn!(feed = %feed.url, %err, "failed to reset feed error count");
            }
            cadence_for(feed, default_interval)
        }
        Ok(PollOutcome::Failed { backoff }) => {
            // Record the failure and recompute the backoff from the feed's REAL
            // consecutive-error count so a persistently-broken feed climbs toward
            // the ceiling instead of retrying at the 5-min floor forever. If the
            // bump fails (store hiccup) fall back to the outcome's floor backoff.
            let backoff = match store::bump_feed_errors(pool, &feed.url).await {
                Ok(count) => feed::backoff_for(count.max(1) as u32),
                Err(err) => {
                    warn!(feed = %feed.url, %err, "failed to bump feed error count; using floor backoff");
                    backoff
                }
            };
            warn!(feed = %feed.url, ?backoff, "polled: failed, backing off");
            backoff
        }
        Err(err) => {
            // Store-level error for this feed — log and reschedule on the normal
            // cadence so we retry rather than getting stuck re-polling instantly.
            error!(feed = %feed.url, %err, "polled: store error");
            cadence_for(feed, default_interval)
        }
    };

    if let Err(err) = set_next_poll(pool, &feed.url, next_delay).await {
        error!(feed = %feed.url, %err, "failed to persist next_poll");
    }
}

/// Persist a feed's `next_poll = now + delay` via the store's feed upsert.
async fn set_next_poll(pool: &Pool, url: &str, delay: Duration) -> anyhow::Result<()> {
    let next = Utc::now()
        + chrono::Duration::from_std(delay).unwrap_or_else(|_| chrono::Duration::hours(1));
    let next_poll = next.to_rfc3339_opts(SecondsFormat::Secs, true);
    // upsert_feed COALESCEs unset fields, so supplying only url + next_poll bumps
    // the schedule without clobbering title/validators/last_polled. That claim
    // was false when it was written — etag and last_modified were assigned
    // unconditionally, so this call, which runs after EVERY poll of EVERY feed,
    // erased both and made conditional GET dead code instance-wide. The store
    // now COALESCEs them; `validators_survive_a_partial_upsert` pins it.
    let nf = store::NewFeed {
        url: url.to_string(),
        next_poll: Some(next_poll),
        ..Default::default()
    };
    store::upsert_feed(pool, &nf).await.map(|_| ())
}

/// The per-feed poll cadence. Honours the feed's `fetchHint` when the feed row
/// carries one; otherwise the configured default interval.
///
/// The `fetchHint` cadence hint (`realtime`/`hourly`/`daily`/`weekly`) lives on
/// the PDS-side `subscription` record. It is not yet projected onto the local
/// [`Feed`] row, so this maps the known values when present and otherwise falls
/// back to the config default — the mapping is factored out so wiring the
/// projected hint later is a one-line change.
fn cadence_for(feed: &Feed, default_interval: Duration) -> Duration {
    // `fetchHint` is not yet projected onto the local `feeds` row, so there is no
    // hint to read yet — this resolves to the configured default. The mapping is
    // routed through `cadence_from_hint` so wiring the projected hint later is a
    // one-line change here (pass `feed`'s hint instead of `None`).
    let hint: Option<&str> = feed_fetch_hint(feed);
    match hint {
        Some(h) => cadence_from_hint(h, default_interval),
        None => default_interval,
    }
}

/// The feed's `fetchHint`, if the local row carries one. The local `feeds` row
/// does not yet project the PDS-side hint, so this currently always returns
/// `None` — the single place to change when the hint column lands.
fn feed_fetch_hint(_feed: &Feed) -> Option<&str> {
    None
}

/// Map a `fetchHint` known-value to a poll cadence. Referenced by
/// [`cadence_for`] once the hint is projected onto the feed row; retained now so
/// the mapping is defined in one place and unit-tested.
fn cadence_from_hint(hint: &str, default_interval: Duration) -> Duration {
    match hint.trim().to_ascii_lowercase().as_str() {
        "realtime" => Duration::from_secs(5 * 60),
        "hourly" => Duration::from_secs(60 * 60),
        "daily" => Duration::from_secs(24 * 60 * 60),
        "weekly" => Duration::from_secs(7 * 24 * 60 * 60),
        _ => default_interval,
    }
}

// ---------------------------------------------------------------------------
// Invite-code TTL sweeper
// ---------------------------------------------------------------------------

/// The invite-code TTL sweep loop. On a periodic tick (hourly by default) it
/// flips every `active` invite code past its `expires_at` to `expired`
/// ([`store::expire_old_codes`]), keeping the closed-beta table tidy. Returns
/// when `shutdown` resolves. Failures are logged and never kill the loop — a
/// missed sweep is harmless because `redeem_code` re-checks expiry itself.
pub async fn run_code_sweeper(
    state: AppState,
    mut shutdown: watch::Receiver<()>,
    startup: Duration,
) {
    let period = env_duration_secs("FEATHERREADER_CODE_SWEEP_SECS", DEFAULT_CODE_SWEEP);
    info!(?period, "invite-code TTL sweeper started");

    // Delayed first tick (see `CODE_SWEEP_STARTUP_DELAY`) rather than the
    // immediate one this used to have — a long-stale set of codes is still swept
    // a minute into the boot, and `redeem_code` re-checks expiry itself, so the
    // sweep was never on the correctness path to begin with.
    let mut ticker = delayed_interval(startup, period);
    loop {
        tokio::select! {
            _ = shutdown_fired(&mut shutdown) => {
                info!("invite-code TTL sweeper: shutdown signal received, stopping");
                break;
            }
            _ = ticker.tick() => {
                match store::expire_old_codes(&state.db).await {
                    Ok(0) => debug!("invite-code TTL sweeper: nothing to expire"),
                    Ok(n) => info!(expired = n, "invite-code TTL sweeper: expired codes"),
                    Err(err) => error!(%err, "invite-code TTL sweeper: sweep failed"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Retention sweeper
// ---------------------------------------------------------------------------

/// The retention sweep loop. On a periodic tick (daily by default) it deletes
/// shared-cache entries older than `config.retention_days`
/// ([`store::prune_old_entries`]) — the mechanism that makes the README/wiki
/// "90-day rolling window" claim TRUE — and, after a sweep that actually deleted
/// rows, calls [`store::reclaim`] so the freed pages return to the OS (otherwise
/// the file never shrinks and the DB-size watermark can stay latched). Orphaned
/// entry ids are scrubbed from the affected `read_cursor` id-sets inside the
/// prune itself.
///
/// The loop runs if EITHER knob is on. `retention_days == 0` disables only the
/// rolling window; `retention_hard_days` still evicts everything past the
/// ceiling, and that is deliberate — the ceiling is what bounds the shared cache
/// for entries a reader pinned by starring or marking unread, and the per-feed
/// trim now spares those. Only when both are zero does the loop log once and
/// return, spawning no ticker; that configuration has no bound at all and says
/// so. Failures are logged and never kill the loop — a missed sweep just means
/// the window is enforced on the next tick.
pub async fn run_retention_sweeper(
    state: AppState,
    mut shutdown: watch::Receiver<()>,
    startup: Duration,
) {
    let days = state.config.retention_days as i64;
    let hard_days = state.config.retention_hard_days as i64;
    if days <= 0 && hard_days <= 0 {
        info!(
            "retention sweeper: retention_days=0 and retention_hard_days=0, \
             retention disabled entirely (no rolling window, NO ceiling — the \
             shared cache is unbounded in this configuration)"
        );
        return;
    }
    let period = env_duration_secs(
        "FEATHERREADER_RETENTION_SWEEP_SECS",
        DEFAULT_RETENTION_SWEEP,
    );
    info!(
        retention_days = days,
        retention_hard_days = hard_days,
        ?period,
        "retention sweeper started"
    );

    // Delayed first tick (see `RETENTION_STARTUP_DELAY`). This is the heaviest
    // of the local loops — it takes the single write lock for the whole delete —
    // so firing it into a boot that is still opening the database and warming
    // caches was the worst timing available.
    let mut ticker = delayed_interval(startup, period);
    loop {
        tokio::select! {
            _ = shutdown_fired(&mut shutdown) => {
                info!("retention sweeper: shutdown signal received, stopping");
                break;
            }
            _ = ticker.tick() => {
                match store::prune_old_entries(&state.db, days, hard_days).await {
                    Ok(0) => debug!("retention sweeper: nothing past the retention window"),
                    Ok(n) => {
                        info!(
                            pruned = n,
                            retention_days = days,
                            retention_hard_days = hard_days,
                            "retention sweeper: pruned old entries"
                        );
                        // Return the freed pages to the OS so the file actually
                        // shrinks and the DB-size watermark can fall back.
                        if let Err(err) = store::reclaim(&state.db).await {
                            warn!(%err, "retention sweeper: reclaim after prune failed");
                        }
                    }
                    Err(err) => error!(%err, "retention sweeper: prune failed"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Relay adoption probe
// ---------------------------------------------------------------------------

/// The relay adoption probe loop (`design/NETWORK-SPEC.md` §4). On a periodic
/// tick (daily by default) it asks every configured relay how many repos hold
/// `community.lexicon.rss.subscription`, logs the number — **the log is the
/// metric**; there is no `/metrics` endpoint — and upserts one `network_stat`
/// row per relay.
///
/// Two kill switches: `FEATHERREADER_ADOPTION_INTERVAL_SECS=0` (or an empty
/// `FEATHERREADER_RELAY_HOSTS`) stops just this loop, and the pre-existing
/// `FEATHERREADER_DISABLE_SCHEDULER` stops it with the other four.
///
/// It deviates from its four siblings in exactly one way: `interval_at` with an
/// [`ADOPTION_STARTUP_DELAY`] instead of an immediate first tick, because this
/// tick is a request to a third party and the container supervisor turns "once
/// per boot" into "once per crash-loop restart". Nothing it does can fail the
/// process: every error path is a `warn!` that leaves the previous observation
/// in place.
pub async fn run_adoption_probe(
    state: AppState,
    mut shutdown: watch::Receiver<()>,
    startup: Duration,
) {
    let period = state.config.adoption_interval;
    if period.is_zero() {
        info!("adoption probe: disabled (FEATHERREADER_ADOPTION_INTERVAL_SECS=0)");
        return;
    }
    // Rejected entries are surfaced HERE rather than at parse time: config is
    // read before `init_tracing` (main.rs:38 vs :41), so a warning emitted during
    // parsing would go nowhere. Warn whether or not any usable host survived —
    // a typo the operator never hears about is the failure mode this replaced a
    // boot abort with, and it must not be silent as well as non-fatal.
    for bad in &state.config.relay_host_errors {
        warn!(
            entry = %bad,
            "adoption probe: ignoring unusable FEATHERREADER_RELAY_HOSTS entry"
        );
    }
    if state.config.relay_hosts.is_empty() {
        info!("adoption probe: no relay hosts configured, probe disabled");
        return;
    }
    // A typo'd relay host must disable an optional metric, never block boot —
    // so the client is built here, in the task, not in `main`.
    let client = match RelayClient::new(state.http.clone(), &state.config.relay_hosts) {
        Ok(client) => client,
        Err(err) => {
            warn!(%err, "adoption probe: unusable FEATHERREADER_RELAY_HOSTS, probe disabled");
            return;
        }
    };

    let period = jittered(period, &state.config.public_url);
    info!(
        ?period,
        relays = client.hosts().len(),
        "adoption probe started"
    );

    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + startup, period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown_fired(&mut shutdown) => {
                info!("adoption probe: shutdown signal received, stopping");
                break;
            }
            _ = ticker.tick() => probe_adoption_once(&state, &client).await,
        }
    }
}

/// One probe run. Returns `()` — no error can reach the loop body, because none
/// of them is actionable: a relay outage, a 429, a malformed body, and a SQLite
/// write failure all leave the previous row in place and change nothing else.
/// (Deliberately unlike `poll_due_once`, which returns `Result` because a
/// store-level failure there IS a real signal.)
async fn probe_adoption_once(state: &AppState, client: &RelayClient) {
    let report = client.count_repos_with_collection(nsid::SUBSCRIPTION).await;

    for failure in &report.failures {
        warn!(
            host = %failure.host,
            reason = %failure.reason,
            "adoption probe: relay query failed; keeping previous observation"
        );
    }

    for obs in &report.observations {
        // §4.4: this log line IS the operator-facing metric.
        info!(
            key = store::ADOPTION_STAT_KEY,
            source = %obs.source,
            repos = obs.repos,
            truncated = obs.truncated,
            "adoption probe: observed"
        );
        let stat = store::NetworkStat {
            key: store::ADOPTION_STAT_KEY.to_string(),
            source: obs.source.clone(),
            // Bounded by MAX_PAGES × the page limit, far inside i64.
            value: obs.repos as i64,
            truncated: obs.truncated,
            observed_at: obs.observed_at.clone(),
        };
        if let Err(err) = store::record_network_stat(&state.db, &stat).await {
            warn!(%err, source = %obs.source, "adoption probe: failed to persist observation");
        }
    }

    // §4.1: two relays disagreeing is itself worth logging — non-archival
    // relays index different host sets, so this is information, not an error.
    if report.disagrees() {
        let counts: Vec<(String, u64)> = report
            .observations
            .iter()
            .map(|o| (o.source.clone(), o.repos))
            .collect();
        info!(
            ?counts,
            "adoption probe: relays disagree; the max is surfaced"
        );
    }
}

/// Spread the probe cadence ±10% so many self-hosted instances do not
/// synchronise on the relay.
///
/// Seeded from the instance's public URL through the FNV hash already in this
/// file, so it is **stable across restarts** (a restart must never re-roll into
/// a tighter cadence) and unit-testable — no `rand` dependency, no RNG in the
/// loop. The result is clamped to at least one second.
fn jittered(period: Duration, seed: &str) -> Duration {
    // 0..=200 → −100..=+100 tenths of a percent… i.e. ±10%.
    let basis = (fnv1a_64(seed.as_bytes()) % 201) as i64 - 100;
    let secs = period.as_secs_f64() * (1.0 + basis as f64 / 1000.0);
    Duration::from_secs_f64(secs.max(1.0))
}

// ---------------------------------------------------------------------------
// Pending-login sweeper
// ---------------------------------------------------------------------------

/// How often abandoned logins and stale nonces are swept.
const PENDING_SWEEP_SECS: u64 = 900;

/// How long an untouched DPoP nonce is kept. A server nonce lasts minutes; a day
/// is generous and keeps the table to the origins actually in use.
const NONCE_MAX_AGE_SECS: i64 = 24 * 60 * 60;

/// Delete expired pending logins.
///
/// An abandoned login — the user is redirected to their PDS and closes the tab —
/// leaves an `oauth_state` row behind. `take_pending` only ever consumes rows
/// that come BACK, so nothing else removes these, and each one holds a sealed
/// DPoP private key and a PKCE verifier. Without this the table grows without
/// bound and accumulates secret material that can no longer be used for
/// anything.
///
/// Runs on both backends: the rows are written by the Rust login path, and a
/// deployment that flips back to the sidecar still has whatever it left behind.
pub async fn run_pending_sweeper(
    state: AppState,
    mut shutdown: watch::Receiver<()>,
    startup: Duration,
) {
    let period = Duration::from_secs(PENDING_SWEEP_SECS);
    info!(?period, "pending-login sweeper started");

    // Delayed first tick, like its siblings (see `PENDING_SWEEP_STARTUP_DELAY`).
    let mut ticker = delayed_interval(startup, period);
    loop {
        tokio::select! {
            _ = shutdown_fired(&mut shutdown) => {
                info!("pending-login sweeper: shutdown signal received, stopping");
                break;
            }
            _ = ticker.tick() => {
                let now = Utc::now().timestamp();
                match feather_reader::oauth::store::sweep_expired_pending(&state.db, now).await {
                    Ok(0) => debug!("pending-login sweeper: nothing to expire"),
                    Ok(n) => info!(swept = n, "pending-login sweeper: removed abandoned logins"),
                    Err(err) => error!(%err, "pending-login sweeper: sweep failed"),
                }
                // Same volume, same pre-auth write primitive, and a stale nonce
                // is worthless — the server issues a new one with the next
                // challenge.
                match feather_reader::oauth::store::sweep_stale_nonces(
                    &state.db,
                    now - NONCE_MAX_AGE_SECS,
                )
                .await
                {
                    Ok(0) => debug!("nonce sweeper: nothing stale"),
                    Ok(n) => info!(swept = n, "nonce sweeper: removed stale DPoP nonces"),
                    Err(err) => error!(%err, "nonce sweeper: sweep failed"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Repo-timing flusher
// ---------------------------------------------------------------------------

/// How often buffered repo timings are written to SQLite.
///
/// Frequent enough that a crash loses little, rare enough that the write is
/// nowhere near the request path. Recording itself only touches memory.
const METRICS_FLUSH_SECS: u64 = 30;

/// Periodically persist buffered repo timings, and once more on shutdown.
///
/// The shutdown flush is the one that matters for a CUTOVER: throwing the
/// switch means a restart, and unflushed samples from the outgoing backend
/// would be lost at precisely the moment they became the thing worth comparing
/// against.
pub async fn run_metrics_flusher(state: AppState, mut shutdown: watch::Receiver<()>) {
    let period = Duration::from_secs(METRICS_FLUSH_SECS);
    info!(?period, "repo-timing flusher started");
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => flush_metrics_once(&state).await,
            _ = shutdown.changed() => {
                flush_metrics_once(&state).await;
                info!("repo-timing flusher stopped (final flush done)");
                return;
            }
        }
    }
}

/// One flush. A metrics write must never be able to take anything else down, so
/// a failure is logged and the loop continues.
async fn flush_metrics_once(state: &AppState) {
    if let Err(err) =
        feather_reader::metrics::flush(&state.metrics, &state.db, Utc::now().timestamp()).await
    {
        warn!(%err, "could not persist repo timings");
    }
}

// ---------------------------------------------------------------------------
// Read-state flusher
// ---------------------------------------------------------------------------

/// The read-state flusher loop. On a debounced interval it flushes every DID's
/// dirty read cursors to the PDS in batches; on shutdown it flushes once more so
/// no read-state is stranded. Returns when `shutdown` resolves.
pub async fn run_flusher(state: AppState, mut shutdown: watch::Receiver<()>) {
    let debounce = env_duration_secs("FEATHERREADER_FLUSH_DEBOUNCE_SECS", DEFAULT_FLUSH_DEBOUNCE);
    info!(?debounce, "read-state flusher started");

    // Which DIDs we have already reported as parked, so the log line is once
    // per DID per process rather than once per minute forever.
    let mut parked: HashSet<String> = HashSet::new();

    let mut ticker = interval(debounce);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // The first `tick()` completes immediately; swallow it so the debounce window
    // is respected before the first flush.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = shutdown_fired(&mut shutdown) => {
                info!("read-state flusher: shutdown signal received, final flush");
                // Final drain so Ctrl-C never strands unsynced read-state.
                if let Err(err) = flush_all_dirty(&state, &mut parked).await {
                    error!(%err, "read-state flusher: final flush failed");
                }
                break;
            }
            _ = ticker.tick() => {
                if let Err(err) = flush_all_dirty(&state, &mut parked).await {
                    error!(%err, "read-state flusher: flush round failed");
                }
            }
        }
    }
}

/// Flush every DID that has dirty cursors. Coalesces each DID's dirty cursors
/// into a single `applyWrites` batch, then clears the `dirty` flag on the ones
/// that flushed successfully.
async fn flush_all_dirty(state: &AppState, parked: &mut HashSet<String>) -> anyhow::Result<()> {
    let dids = dids_with_dirty_cursors(&state.db).await?;
    if dids.is_empty() {
        debug!("read-state flusher: nothing dirty");
        return Ok(());
    }
    debug!(
        dids = dids.len(),
        "read-state flusher: flushing dirty cursors"
    );

    for did in dids {
        // **A DID with no session is PARKED, not failed (#117).**
        //
        // Attempting the flush anyway is what produced the production incident:
        // `Repo::session` fails before any network call, the enclosing
        // `flush_read_states` records an error, and the whole thing repeats
        // every 60s forever. 20 failures in the first 20 minutes, and nothing
        // about it could ever have succeeded — the user is signed out.
        //
        // The cursors stay DIRTY on purpose. The reads are not discarded; they
        // wait, and flush on the user's next sign-in. Clearing the flag here
        // would turn a stalled sync into silent data loss, which is strictly
        // worse than the bug being fixed.
        match state.repo().has_session(&did).await {
            Ok(false) => {
                // Once per DID per process: enough to diagnose, not enough to
                // drown the log or mask a real failure during the soak.
                if parked.insert(did.clone()) {
                    info!(
                        %did,
                        "read-state flusher: no OAuth session; parking this DID's \
                         read-state until it signs in again"
                    );
                }
                continue;
            }
            Ok(true) => {
                // It had a session and may have just got one back — stop
                // suppressing its log line, so a LATER park is reported.
                parked.remove(&did);
            }
            Err(err) => {
                // The precondition check itself failed (a DB problem, not an
                // absent session). Fall through and let the flush attempt
                // produce the real error rather than silently skipping.
                warn!(%did, %err, "read-state flusher: session check failed; attempting anyway");
            }
        }

        if let Err(err) = flush_did(state, &did).await {
            // One DID's PDS hiccup must not block the others — its cursors stay
            // dirty and retry next round. This arm is now genuinely transient
            // failures only; the permanent case is parked above.
            warn!(%did, %err, "read-state flusher: DID flush failed; will retry");
        }
    }
    Ok(())
}

/// Every DID that currently has at least one dirty read cursor.
///
/// The store exposes `dirty_cursors(did)` (per-DID, the flusher's hot query) but
/// not the DID enumeration the *global* flusher needs, so this runs the small
/// `SELECT DISTINCT did` directly against the pool. Kept in this module so the
/// scheduler owns its own query and touches no other file.
async fn dids_with_dirty_cursors(pool: &Pool) -> anyhow::Result<Vec<String>> {
    let rows = sqlx::query("SELECT DISTINCT did FROM read_cursor WHERE dirty = 1")
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| r.get::<String, _>("did"))
        .collect())
}

/// Current time as an RFC3339 string (UTC, second precision) — the shape the
/// store's timestamp columns use.
fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use feather_reader::store::ReadCursor;

    /// A feed row that is due right now (`next_poll` NULL), plus its store.
    async fn due_feed(url: &str) -> (Pool, Feed) {
        let pool = store::init_url("sqlite::memory:").await.unwrap();
        store::upsert_feed(
            &pool,
            &store::NewFeed {
                url: url.to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let feed = store::get_feed_by_url(&pool, url).await.unwrap().unwrap();
        assert!(
            feed.next_poll.is_none(),
            "fixture must start due (NULL next_poll sorts FIRST in due_feeds)"
        );
        (pool, feed)
    }

    /// **`next_poll` must already be in the future when the fetch is invoked.**
    ///
    /// This is the ordering that converts a process-killing feed from a permanent
    /// crash loop into a single restart. A test cannot kill the process, so it
    /// asserts the observable form of the same fact: at the moment the fetch
    /// begins, the durable state a restart would read has already moved on.
    #[tokio::test]
    async fn next_poll_moves_before_the_fetch_is_invoked() {
        let url = "https://killer.example/feed.xml";
        let (pool, feed) = due_feed(url).await;

        let seen_at_fetch = std::sync::Arc::new(std::sync::Mutex::new(None::<Option<String>>));
        let probe = std::sync::Arc::clone(&seen_at_fetch);

        poll_and_reschedule_with(&pool, &feed, Duration::from_secs(3600), |pool, feed| {
            let probe = std::sync::Arc::clone(&probe);
            let url = feed.url.clone();
            async move {
                // What a restart happening RIGHT NOW would find.
                let row = store::get_feed_by_url(pool, &url).await.unwrap().unwrap();
                *probe.lock().unwrap() = Some(row.next_poll);
                // Then take the process down, as far as this test can simulate it:
                // never produce an outcome the caller could reschedule from.
                Err(anyhow::anyhow!("the fetch killed the process"))
            }
        })
        .await;

        let at_fetch = seen_at_fetch.lock().unwrap().clone().expect("fetch ran");
        let at_fetch = at_fetch.expect(
            "next_poll was still NULL when the fetch began: a crash here re-selects \
             this feed FIRST on every restart, forever",
        );
        assert!(
            at_fetch > now_rfc3339(),
            "next_poll was leased to {at_fetch}, which is not in the future"
        );
    }

    /// The lease is optimistic, not final: a poll that returns overwrites it.
    /// A failure must land on its backoff, not sit at the full cadence.
    #[tokio::test]
    async fn a_returning_poll_overwrites_the_lease() {
        let url = "https://slow.example/feed.xml";
        let (pool, feed) = due_feed(url).await;

        // A cadence far in the future, so "the lease survived" is unmistakable.
        poll_and_reschedule_with(&pool, &feed, Duration::from_secs(86_400), |_, _| async {
            Ok(PollOutcome::Failed {
                backoff: Duration::from_secs(300),
            })
        })
        .await;

        let after = store::get_feed_by_url(&pool, url)
            .await
            .unwrap()
            .unwrap()
            .next_poll
            .expect("next_poll must be set after a poll");
        let horizon =
            (Utc::now() + chrono::Duration::hours(1)).to_rfc3339_opts(SecondsFormat::Secs, true);
        assert!(
            after < horizon,
            "the failure backoff did not overwrite the 24h lease: next_poll={after}"
        );
        assert!(
            after > now_rfc3339(),
            "next_poll must still be in the future"
        );
    }

    /// The startup-delay override can only SHORTEN the wait. A deployment that
    /// sets an enormous value must not push a production loop further out than
    /// the constant intends.
    ///
    /// Tested through `startup_delay_from` rather than the environment: a
    /// `set_var` here would be the only one in `src/`, racing ~39 `var` reads on
    /// other test threads.
    #[test]
    fn the_startup_delay_override_is_a_ceiling() {
        let d = POLLER_STARTUP_DELAY;
        let at = |v: &str| startup_delay_from(d, Some(v.to_string()));

        assert_eq!(at("0"), Duration::ZERO);
        assert_eq!(at("5"), Duration::from_secs(5));
        assert_eq!(at(" 5 "), Duration::from_secs(5), "surrounding space");
        assert_eq!(at("99999"), d, "the override lengthened the wait");
        assert_eq!(at("not-a-number"), d);
        assert_eq!(at(""), d);
        assert_eq!(startup_delay_from(d, None), d);
    }

    /// **The loops must not land on the same instant at boot.**
    ///
    /// The original version compared the CONSTANTS with no call site involved,
    /// so pointing all five loops at `POLLER_STARTUP_DELAY` passed. The second
    /// version asserted on a string-keyed table and made things worse — see the
    /// `Loop` doc. This reads the exhaustive mapping the code actually uses.
    ///
    /// Asserts against `startup_offset()` directly, NOT `offset_for()`: the
    /// latter applies the `FEATHERREADER_STARTUP_DELAY_SECS` ceiling, which is a
    /// documented dev setting, and asserting through it made the suite fail
    /// under `FEATHERREADER_STARTUP_DELAY_SECS=0`. Keeping env out of this
    /// module's tests is why `startup_delay_from` was split out in the first
    /// place.
    #[test]
    fn the_startup_delays_are_distinct() {
        let offsets: Vec<Duration> = Loop::ALL.iter().map(|l| l.startup_offset()).collect();
        let unique: std::collections::HashSet<Duration> = offsets.iter().copied().collect();
        assert_eq!(
            unique.len(),
            Loop::ALL.len(),
            "two loops share a startup delay: {offsets:?}",
        );
        assert!(
            offsets.iter().all(|d| *d > Duration::ZERO),
            "a loop still fires immediately at boot: {offsets:?}",
        );
    }

    /// **`spawn` really visits every loop — the iteration, not a const array.**
    ///
    /// The previous test asserted `Loop::ALL.len() == 5`, which says nothing
    /// about whether `spawn` reads it. A `.filter()` dropping a loop was green.
    /// This drives the same function `spawn` drives.
    #[test]
    fn every_loop_is_visited_exactly_once() {
        let mut seen = Vec::new();
        for_each_loop(|l| seen.push(l));
        assert_eq!(
            seen,
            Loop::ALL.to_vec(),
            "the iteration `spawn` uses does not visit every loop exactly once, \
             in registry order",
        );
    }

    /// The startup-override key is spelled the same in the code and here.
    ///
    /// Independently written on purpose: mistyping it in `offset_for` silently
    /// disabled the override for every loop with a green suite and green clippy.
    #[test]
    fn the_startup_override_env_key_is_the_documented_one() {
        assert_eq!(STARTUP_DELAY_ENV, "FEATHERREADER_STARTUP_DELAY_SECS");
    }

    /// The registry holds each loop exactly once.
    ///
    /// A pure statement about `Loop::ALL`. It says nothing about `spawn` — see
    /// `spawn_starts_every_registered_loop` for that, and read the note there
    /// before trusting a test in this file that has "spawn" in its name.
    #[test]
    fn the_registry_lists_each_loop_exactly_once() {
        let unique: std::collections::HashSet<Loop> = Loop::ALL.iter().copied().collect();
        assert_eq!(
            unique.len(),
            Loop::ALL.len(),
            "a loop is listed twice in the registry and would be started twice",
        );
    }

    /// **`spawn` starts one task per registered loop — by calling `spawn`.**
    ///
    /// This test previously carried this name while asserting only
    /// `Loop::ALL.len() == 5` plus uniqueness. It never called `spawn`, so the
    /// callback `spawn` passes to `for_each_loop` was an untested decision
    /// point, and dropping a loop there was silent:
    ///
    /// ```ignore
    /// for_each_loop(|l| {
    ///     if l != Loop::PendingSweep {           // 697 lib + 13 bin green,
    ///         handles.push(l.spawn_with(..));    // clippy -D warnings clean
    ///     }
    /// });
    /// ```
    ///
    /// The pending-login sweeper never starts and nonce rows grow without
    /// bound. That is the FOURTH form of this file's recurring defect — after a
    /// wrong constant, a mistyped string key, and a wrong positional argument —
    /// and the round that introduced `for_each_loop` to close the third form
    /// also introduced the mis-named test that hid this one.
    ///
    /// The `+ 2` is the two loops with no startup offset: the metrics flusher
    /// (which fires immediately at boot, deliberately) and the read-state
    /// flusher. Neither is in `Loop`.
    #[tokio::test]
    async fn spawn_starts_every_registered_loop() {
        // `spawn` returns early with an empty Vec when the kill switch is set,
        // which would make the assertion below vacuously wrong rather than
        // failing for a real reason. Say so instead of measuring nothing.
        assert!(
            schedulers_enabled(),
            "FEATHERREADER_DISABLE_SCHEDULER is set in this test process, so \
             `spawn` returns no handles and this test cannot measure anything",
        );
        let state = rust_state().await;
        let (tx, rx) = watch::channel(());
        let handles = spawn(state, rx);
        assert_eq!(
            handles.len(),
            Loop::ALL.len() + 2,
            "`spawn` started {} tasks for {} registered loops + 2 unoffset ones \
             — it is not starting one task per registry entry",
            handles.len(),
            Loop::ALL.len(),
        );
        // Shut them down rather than leaking tasks into the rest of the suite.
        drop(tx);
        for h in handles {
            let _ = h.await;
        }
    }

    /// The ceiling still applies on the way to a loop — the one thing
    /// `offset_for` adds over the raw table.
    ///
    /// Pinned because a mutation deleting `startup_delay(..)` from `offset_for`
    /// — disabling `FEATHERREADER_STARTUP_DELAY_SECS` for every loop at once —
    /// passed the whole suite. Uses `startup_delay_from` so no environment
    /// variable is read.
    #[test]
    fn the_startup_ceiling_applies_to_every_loop() {
        for l in Loop::ALL {
            assert_eq!(
                offset_from(l, Some("0".into())),
                Duration::ZERO,
                "{l:?} ignored the startup-delay ceiling",
            );
        }
    }

    /// **Each variant gets ITS OWN offset — spelled out, not derived.**
    ///
    /// This replaces `assert_eq!(offset_from(l, None), l.startup_offset())`,
    /// which was a tautology: `offset_from` is
    /// `startup_delay_from(which.startup_offset(), raw)` and
    /// `startup_delay_from(d, None)` is `d`, so both sides reduced to the same
    /// expression and the assertion could not fail for ANY mapping. Swapping
    /// two variants' arms in `startup_offset` passed the whole suite.
    ///
    /// The table below is written independently of the `match`, so the two have
    /// to agree — the same reason `the_startup_override_env_key_is_the_documented_one`
    /// spells the env key out by hand. Spelling the seconds here rather than
    /// naming the constants is the point: naming them would reintroduce the
    /// tautology one level up.
    #[test]
    fn every_loop_is_on_its_documented_offset() {
        let documented = [
            (Loop::Poller, 30),
            (Loop::PendingSweep, 45),
            (Loop::CodeSweep, 60),
            (Loop::Retention, 90),
            (Loop::Adoption, 300),
        ];
        assert_eq!(
            documented.len(),
            Loop::ALL.len(),
            "a loop was added to the registry without an entry in this table",
        );
        for (l, secs) in documented {
            assert_eq!(
                l.startup_offset(),
                Duration::from_secs(secs),
                "{l:?} is not on its documented {secs}s offset",
            );
        }
    }

    #[test]
    fn cadence_from_hint_maps_known_values() {
        let d = Duration::from_secs(3600);
        assert_eq!(cadence_from_hint("hourly", d), Duration::from_secs(3600));
        assert_eq!(cadence_from_hint("daily", d), Duration::from_secs(86_400));
        assert_eq!(cadence_from_hint("weekly", d), Duration::from_secs(604_800));
        assert_eq!(cadence_from_hint("realtime", d), Duration::from_secs(300));
        assert_eq!(cadence_from_hint("bogus", d), d);
    }

    #[test]
    fn jitter_stays_within_ten_percent_and_is_seed_stable() {
        let period = Duration::from_secs(86_400);
        let seeds = [
            "https://feather-reader.com",
            "http://localhost:8080",
            "https://reader.example.org",
        ];
        for seed in seeds {
            let j = jittered(period, seed);
            assert!(
                j >= Duration::from_secs(77_760) && j <= Duration::from_secs(95_040),
                "{seed}: {j:?} escaped ±10% of a day"
            );
            // Stable across "restarts": the same seed always yields the same
            // cadence, so a crash loop cannot walk the interval tighter.
            assert_eq!(j, jittered(period, seed));
        }
        // Different instances land on different cadences.
        assert_ne!(jittered(period, seeds[0]), jittered(period, seeds[1]));
    }

    #[test]
    fn jitter_never_returns_a_sub_second_period() {
        assert!(jittered(Duration::from_secs(1), "x") >= Duration::from_secs(1));
        assert!(jittered(Duration::from_millis(1), "x") >= Duration::from_secs(1));
    }

    // ── #117: orphaned dirty read-state ──────────────────────────────────────

    /// An `AppState` on the rust backend with an empty in-memory store.
    ///
    /// `key_path` is per-test: the default is the RELATIVE
    /// `oauth-signing-key.json`, so a rust-backend test would write real
    /// encrypted key material into the working directory and later runs would
    /// fail to decrypt it under a fresh key.
    async fn rust_state() -> AppState {
        let db = store::init_url("sqlite::memory:").await.unwrap();
        AppState::new(
            feather_reader::config::Config {
                repo_backend: feather_reader::metrics::Backend::Rust,
                oauth: feather_reader::config::OauthConfig {
                    key_path: std::env::temp_dir().join(format!(
                        "fr-sched-oauth-key-{}-{:p}.json",
                        std::process::id(),
                        &db as *const _
                    )),
                    encryption_key: Some("a".repeat(43)),
                    ..feather_reader::config::OauthConfig::default()
                },
                ..feather_reader::config::Config::default()
            },
            db,
        )
        .unwrap()
    }

    /// A dirty cursor for `did`, as a mark-read would leave it.
    async fn dirty_cursor_for(state: &AppState, did: &str) {
        store::upsert_cursor(
            &state.db,
            &ReadCursor {
                did: did.to_string(),
                feed_url: "https://example.com/feed.xml".into(),
                read_through: None,
                read_ids: "[\"1\"]".into(),
                unread_ids: "[]".into(),
                dirty: true,
                pds_created: false,
                updated_at: now_rfc3339(),
            },
        )
        .await
        .unwrap();
    }

    /// **#117 — a DID with no OAuth session is PARKED, not retried.**
    ///
    /// The inverse of the characterization test this replaces. Before the fix,
    /// five rounds produced five recorded failures and a `warn!` each; nothing
    /// about them could ever have succeeded, because the user is signed out.
    ///
    /// Asserts the two properties the fix has to hold together:
    ///   1. no error is recorded, however many rounds run — the soak is not
    ///      polluted by a condition that is not a failure; and
    ///   2. the cursor stays DIRTY — the reads are parked, not discarded.
    ///
    /// (2) is the one worth guarding. The cheapest way to silence the loop is to
    /// clear the flag, and that would turn a stalled sync into silent data loss.
    #[tokio::test]
    async fn a_did_with_no_session_is_parked_not_retried() {
        let state = rust_state().await;
        let did = "did:plc:orphanedreadstate00000000";
        dirty_cursor_for(&state, did).await;

        let mut parked = HashSet::new();
        const ROUNDS: usize = 5;
        for round in 1..=ROUNDS {
            flush_all_dirty(&state, &mut parked)
                .await
                .expect("a parked DID must not abort the sweep");
            assert_eq!(
                store::dirty_cursors(&state.db, did).await.unwrap().len(),
                1,
                "round {round}: the parked cursor was cleared — the reads are now lost",
            );
        }

        let err = state
            .metrics
            .snapshot()
            .into_iter()
            .find(|r| r.op == "flush_read_states")
            .map(|r| r.stats.err_count)
            .unwrap_or(0);
        assert_eq!(err, 0, "a parked DID was counted as {err} flush failures");
        assert_eq!(parked.len(), 1, "the DID should be recorded as parked once");
    }

    /// **The reads survive the gap: parking holds them until the user returns.**
    ///
    /// This is the test that makes parking defensible rather than merely quiet.
    /// A cursor parked while signed out must still be there — and still flush —
    /// once a session exists again.
    ///
    /// The flush itself fails here (the fixture PDS is unreachable), which is
    /// the point: what is asserted is that the DID is no longer SKIPPED, so the
    /// attempt is made at all. A fix that parked permanently would pass the test
    /// above and fail this one.
    #[tokio::test]
    async fn a_parked_cursor_is_retried_once_the_user_signs_in_again() {
        let state = rust_state().await;
        let did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
        dirty_cursor_for(&state, did).await;
        let mut parked = HashSet::new();

        flush_all_dirty(&state, &mut parked).await.unwrap();
        assert!(
            parked.contains(did),
            "precondition: parked while signed out"
        );
        assert_eq!(
            state
                .metrics
                .snapshot()
                .into_iter()
                .find(|r| r.op == "flush_read_states")
                .map(|r| r.stats.ok_count + r.stats.err_count)
                .unwrap_or(0),
            0,
            "precondition: no flush was attempted while parked",
        );

        // The user signs back in.
        let runtime = state.oauth.as_deref().expect("oauth runtime");
        feather_reader::oauth::store::put_session(
            &state.db,
            &runtime.codec,
            &feather_reader::oauth::store::OAuthSession {
                sub: did.into(),
                issuer: "https://auth.invalid".into(),
                aud: "https://pds.invalid".into(),
                dpop_key_jwk: feather_reader::oauth::keys::SigningKey::generate("session-dpop")
                    .to_jwk_json()
                    .unwrap(),
                access_token: "at".into(),
                refresh_token: "rt".into(),
                token_type: "DPoP".into(),
                granted_scope: "atproto".into(),
                expires_at: Some(Utc::now().timestamp() + 3600),
            },
        )
        .await
        .unwrap();

        flush_all_dirty(&state, &mut parked).await.unwrap();

        assert!(
            !parked.contains(did),
            "the DID is still marked parked after regaining a session",
        );
        let attempts = state
            .metrics
            .snapshot()
            .into_iter()
            .find(|r| r.op == "flush_read_states")
            .map(|r| r.stats.ok_count + r.stats.err_count)
            .unwrap_or(0);
        assert_eq!(
            attempts, 1,
            "the parked read-state was never re-attempted after sign-in",
        );
        assert_eq!(
            store::dirty_cursors(&state.db, did).await.unwrap().len(),
            1,
            "the unflushed cursor must remain dirty after a failed attempt",
        );
    }
}
