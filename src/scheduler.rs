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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use sqlx::Row;
use tokio::sync::{watch, Semaphore};
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, error, info, warn};

use feather_reader::feed::{self, PollOutcome};
use feather_reader::lexicon::ReadState;
use feather_reader::store::{self, Feed, Pool, ReadCursor};
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
        return Vec::new();
    }

    info!("spawning background schedulers (poller + read-state flusher)");

    let poller = {
        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move { run_poller(state, shutdown).await })
    };
    let sweeper = {
        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move { run_code_sweeper(state, shutdown).await })
    };
    let retention = {
        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move { run_retention_sweeper(state, shutdown).await })
    };
    let flusher = tokio::spawn(async move { run_flusher(state, shutdown).await });

    vec![poller, sweeper, retention, flusher]
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
pub async fn run_poller(state: AppState, mut shutdown: watch::Receiver<()>) {
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

    let mut ticker = interval(tick);
    // If the loop falls behind (a slow poll round), skip missed ticks rather than
    // firing a burst to catch up.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown_fired(&mut shutdown) => {
                info!("poll scheduler: shutdown signal received, stopping");
                break;
            }
            _ = ticker.tick() => {
                if let Err(err) = poll_due_once(&state, &client, &limiter, batch, stagger).await {
                    // A store-level error is worth logging, but must not kill the
                    // loop — the next tick retries.
                    error!(%err, "poll scheduler: tick failed");
                }
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
                // Reclaim freed pages so any prior retention/prune deletions
                // actually shrink the file — otherwise freed-but-not-returned
                // pages keep the watermark tripped and latch polling off forever.
                if let Err(err) = store::reclaim(&state.db).await {
                    warn!(%err, "reclaim after watermark trip failed");
                }
                return Ok(());
            }
            Ok(_) => {}
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
    for feed in due {
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
    let next_delay = match feed::poll_feed(pool, client, feed, max_entries_per_feed).await {
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
    // the schedule without clobbering title/validators/last_polled.
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
pub async fn run_code_sweeper(state: AppState, mut shutdown: watch::Receiver<()>) {
    let period = env_duration_secs("FEATHERREADER_CODE_SWEEP_SECS", DEFAULT_CODE_SWEEP);
    info!(?period, "invite-code TTL sweeper started");

    let mut ticker = interval(period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // The first `tick()` fires immediately — do an initial sweep on startup so a
    // long-stale set of codes gets cleaned up promptly rather than after a full
    // period.
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
/// `retention_days == 0` disables retention entirely: the loop logs once and
/// returns, spawning no ticker. Failures are logged and never kill the loop — a
/// missed sweep just means the window is enforced on the next tick.
pub async fn run_retention_sweeper(state: AppState, mut shutdown: watch::Receiver<()>) {
    let days = state.config.retention_days as i64;
    if days <= 0 {
        info!("retention sweeper: retention_days=0, retention disabled (no rolling window)");
        return;
    }
    let period = env_duration_secs(
        "FEATHERREADER_RETENTION_SWEEP_SECS",
        DEFAULT_RETENTION_SWEEP,
    );
    info!(retention_days = days, ?period, "retention sweeper started");

    let mut ticker = interval(period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // The first `tick()` fires immediately — sweep on startup so a long-stale
    // cache is trimmed promptly rather than after a full period.
    loop {
        tokio::select! {
            _ = shutdown_fired(&mut shutdown) => {
                info!("retention sweeper: shutdown signal received, stopping");
                break;
            }
            _ = ticker.tick() => {
                match store::prune_old_entries(&state.db, days).await {
                    Ok(0) => debug!("retention sweeper: nothing past the retention window"),
                    Ok(n) => {
                        info!(pruned = n, retention_days = days, "retention sweeper: pruned old entries");
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
// Read-state flusher
// ---------------------------------------------------------------------------

/// The read-state flusher loop. On a debounced interval it flushes every DID's
/// dirty read cursors to the PDS in batches; on shutdown it flushes once more so
/// no read-state is stranded. Returns when `shutdown` resolves.
pub async fn run_flusher(state: AppState, mut shutdown: watch::Receiver<()>) {
    let debounce = env_duration_secs("FEATHERREADER_FLUSH_DEBOUNCE_SECS", DEFAULT_FLUSH_DEBOUNCE);
    info!(?debounce, "read-state flusher started");

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
                if let Err(err) = flush_all_dirty(&state).await {
                    error!(%err, "read-state flusher: final flush failed");
                }
                break;
            }
            _ = ticker.tick() => {
                if let Err(err) = flush_all_dirty(&state).await {
                    error!(%err, "read-state flusher: flush round failed");
                }
            }
        }
    }
}

/// Flush every DID that has dirty cursors. Coalesces each DID's dirty cursors
/// into a single `applyWrites` batch, then clears the `dirty` flag on the ones
/// that flushed successfully.
async fn flush_all_dirty(state: &AppState) -> anyhow::Result<()> {
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
        if let Err(err) = flush_did(state, &did).await {
            // One DID's PDS hiccup must not block the others — its cursors stay
            // dirty and retry next round.
            warn!(%did, %err, "read-state flusher: DID flush failed; will retry");
        }
    }
    Ok(())
}

/// Flush a single DID's dirty cursors in one batched `applyWrites`, then clear
/// the `dirty` flag for the cursors that were included.
async fn flush_did(state: &AppState, did: &str) -> anyhow::Result<()> {
    let cursors = store::dirty_cursors(&state.db, did).await?;
    if cursors.is_empty() {
        return Ok(());
    }

    // Build (rkey, ReadState) pairs, deduping on rkey so two rows that hash to
    // the same feed-key don't produce two ops in one batch (applyWrites rejects
    // duplicate writes to the same key). Deterministic order for stable batches.
    let mut batch: BTreeMap<String, (ReadState, ReadCursor)> = BTreeMap::new();
    for cursor in cursors {
        let rkey = read_state_rkey(&cursor.feed_url);
        let record = read_state_record(&cursor);
        batch.insert(rkey, (record, cursor));
    }

    // Each op carries whether its PDS record already exists: a not-yet-created
    // cursor becomes an applyWrites#create (not an #update, which would error and,
    // since applyWrites is atomic-per-repo, drop the whole DID batch on a feed's
    // first flush). All create + update ops ride ONE batch.
    let ops: Vec<(String, ReadState, bool)> = batch
        .iter()
        .map(|(rkey, (record, cursor))| (rkey.clone(), record.clone(), cursor.pds_created))
        .collect();

    // ONE applyWrites round-trip for all of this DID's dirty feeds.
    state.sidecar.flush_read_states(did, &ops).await?;

    // Success — for each flushed cursor: mark its PDS record as created (so future
    // flushes emit an update), then clear `dirty` but ONLY if its `updated_at`
    // still matches the snapshot we just flushed. A mark-read that landed DURING
    // the in-flight PDS write bumped `updated_at` and re-dirtied the row; the
    // conditional clear leaves that row dirty so its new reads re-flush next
    // round instead of being silently dropped.
    let flushed = ops.len();
    for (_rkey, (_record, cursor)) in batch {
        // Flip the created flag first: the record now exists in the PDS regardless
        // of whether the dirty-clear below is a no-op due to a concurrent bump.
        if !cursor.pds_created {
            if let Err(err) = store::mark_cursor_pds_created(&state.db, did, &cursor.feed_url).await
            {
                warn!(%did, feed = %cursor.feed_url, %err, "failed to mark cursor pds_created");
            }
        }
        if let Err(err) =
            store::clear_cursor_dirty(&state.db, did, &cursor.feed_url, &cursor.updated_at).await
        {
            // The PDS write already landed; a failure to clear the local flag
            // just means we harmlessly re-flush this cursor next round.
            warn!(%did, feed = %cursor.feed_url, %err, "failed to clear cursor dirty flag");
        }
    }

    info!(%did, feeds = flushed, "read-state flusher: flushed dirty cursors");
    Ok(())
}

/// Turn a local [`ReadCursor`] row into the PDS [`ReadState`] lexicon record.
///
/// The store keeps `read_ids` / `unread_ids` as JSON arrays of ids; the lexicon
/// wants string arrays. `read_through` is optional both locally AND in the
/// record: when the cursor has no local high-water-mark we pass `None` so the
/// record OMITS `readThrough` entirely. This is the conservative behaviour —
/// `readThrough` is a "everything seen/published `<=` this is read" water-mark,
/// so synthesizing a flush-time (`≈ now`) value for a cursor that has none would
/// assert the whole unread backlog is read. With `None` only the explicit
/// `read_ids` mark entries read. Both id-sets are capped at [`ReadState::MAX_IDS`]
/// to respect the lexicon bound.
fn read_state_record(cursor: &ReadCursor) -> ReadState {
    let read_ids = parse_id_array(&cursor.read_ids);
    let unread_ids = parse_id_array(&cursor.unread_ids);

    // Do NOT synthesize a water-mark from `updated_at`: an unset local
    // `read_through` means "no high-water-mark", which the record represents by
    // omitting `readThrough` (None), not by back-dating it to flush time.
    let mut record = ReadState::new(
        &cursor.feed_url,
        cursor.read_through.clone(),
        &cursor.updated_at,
    );
    record.read_ids = cap(read_ids, ReadState::MAX_IDS);
    record.unread_ids = cap(unread_ids, ReadState::MAX_IDS);
    record
}

/// Parse a stored JSON id-array into `Vec<String>`, tolerating both string and
/// numeric ids (the store keeps entry ids). A malformed/empty value yields an
/// empty set rather than an error — read-state must never fail to flush over a
/// cosmetic parse issue.
fn parse_id_array(raw: &str) -> Vec<String> {
    if raw.trim().is_empty() {
        return Vec::new();
    }
    match serde_json::from_str::<Vec<serde_json::Value>>(raw) {
        Ok(vals) => vals
            .into_iter()
            .map(|v| match v {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            })
            .collect(),
        Err(err) => {
            warn!(%err, raw, "read-state flusher: unparseable id array; treating as empty");
            Vec::new()
        }
    }
}

/// Truncate a set to `max`, keeping the most recent (tail) ids. This only
/// enforces the lexicon's hard cap; it does not fold covered ids into the
/// `read_through` water-mark (there is no compaction step yet — the exception
/// sets are expected to stay well under the cap in normal use).
fn cap(mut ids: Vec<String>, max: usize) -> Vec<String> {
    if ids.len() > max {
        let drop = ids.len() - max;
        ids.drain(0..drop);
    }
    ids
}

/// Derive the deterministic, stable rkey for a feed's read-state record from its
/// URL, so there is exactly **one record per feed** (a fixed key, not a fresh tid
/// per flush).
///
/// atproto record keys must match `[A-Za-z0-9._~:-]{1,512}` (and not be `.`/`..`).
/// A lowercase-hex FNV-1a-64 digest of the feed URL satisfies that, is stable
/// across restarts and instances, and collides only on genuine hash collision
/// (astronomically unlikely at feed scale; the flusher additionally dedups by
/// rkey within a batch as a belt-and-braces guard).
///
/// The stable rkey is what makes create-then-update work: a feed's FIRST flush
/// emits an `applyWrites#create` at this key (tracked by `read_cursor.pds_created`)
/// and every subsequent flush an `#update` at the same key, so there is exactly
/// one record per feed and the first flush never fails on a missing record.
pub fn read_state_rkey(feed_url: &str) -> String {
    format!("rs-{:016x}", fnv1a_64(feed_url.as_bytes()))
}

/// FNV-1a 64-bit — a tiny, dependency-free stable hash for the feed-key.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
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

    #[test]
    fn rkey_is_stable_and_valid() {
        let a = read_state_rkey("https://example.com/feed.xml");
        let b = read_state_rkey("https://example.com/feed.xml");
        assert_eq!(a, b, "rkey must be deterministic");
        assert_ne!(a, read_state_rkey("https://other.example/feed.xml"));
        // Valid atproto rkey charset and length.
        assert!(a.len() <= 512 && !a.is_empty());
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~' | b':')));
        assert!(a != "." && a != "..");
    }

    #[test]
    fn parse_id_array_tolerates_shapes() {
        assert_eq!(parse_id_array(""), Vec::<String>::new());
        assert_eq!(parse_id_array("[]"), Vec::<String>::new());
        assert_eq!(parse_id_array(r#"["a","b"]"#), vec!["a", "b"]);
        assert_eq!(parse_id_array("[1,2,3]"), vec!["1", "2", "3"]);
        assert_eq!(parse_id_array("not json"), Vec::<String>::new());
    }

    #[test]
    fn cap_keeps_tail_within_bound() {
        let ids: Vec<String> = (0..10).map(|i| i.to_string()).collect();
        let capped = cap(ids, 3);
        assert_eq!(capped, vec!["7", "8", "9"]);
    }

    #[test]
    fn record_maps_cursor_fields() {
        let cursor = ReadCursor {
            did: "did:plc:abc".into(),
            feed_url: "https://example.com/feed.xml".into(),
            read_through: Some("2026-07-12T00:00:00Z".into()),
            read_ids: r#"["10","11"]"#.into(),
            unread_ids: "[]".into(),
            dirty: true,
            pds_created: false,
            updated_at: "2026-07-12T01:00:00Z".into(),
        };
        let rec = read_state_record(&cursor);
        assert_eq!(rec.feed_url, "https://example.com/feed.xml");
        assert_eq!(rec.read_through.as_deref(), Some("2026-07-12T00:00:00Z"));
        assert_eq!(rec.read_ids, vec!["10", "11"]);
        assert!(rec.unread_ids.is_empty());
        assert_eq!(rec.updated_at, "2026-07-12T01:00:00Z");
    }

    #[test]
    fn read_through_omitted_when_local_unset() {
        // A cursor with no local high-water-mark must NOT synthesize one from
        // `updated_at` (≈ now) — doing so would mark the whole backlog read. The
        // record omits `readThrough` (None) so only explicit read_ids apply.
        let cursor = ReadCursor {
            did: "did:plc:abc".into(),
            feed_url: "https://example.com/feed.xml".into(),
            read_through: None,
            read_ids: r#"["42"]"#.into(),
            unread_ids: "[]".into(),
            dirty: true,
            pds_created: false,
            updated_at: "2026-07-12T01:00:00Z".into(),
        };
        let rec = read_state_record(&cursor);
        assert_eq!(
            rec.read_through, None,
            "no local water-mark => readThrough absent (backlog not implicitly read)"
        );
        // The explicit read_ids still carry through.
        assert_eq!(rec.read_ids, vec!["42"]);
        // Serialized form must not carry a readThrough field at all.
        let json = serde_json::to_value(&rec).expect("serialize");
        assert!(json.get("readThrough").is_none());
    }

    #[test]
    fn read_through_present_when_local_high_water_mark_exists() {
        // A real high-water-mark IS written through unchanged.
        let cursor = ReadCursor {
            did: "did:plc:abc".into(),
            feed_url: "https://example.com/feed.xml".into(),
            read_through: Some("2026-07-11T00:00:00Z".into()),
            read_ids: "[]".into(),
            unread_ids: "[]".into(),
            dirty: true,
            pds_created: false,
            updated_at: "2026-07-12T01:00:00Z".into(),
        };
        let rec = read_state_record(&cursor);
        assert_eq!(rec.read_through.as_deref(), Some("2026-07-11T00:00:00Z"));
    }

    #[test]
    fn flush_with_only_read_ids_sets_no_read_through() {
        // The core F1 guarantee: a flush whose cursor carries only explicit
        // read_ids (and no water-mark) emits a record WITHOUT readThrough, so the
        // user's PDS never asserts the backlog is read.
        let cursor = ReadCursor {
            did: "did:plc:abc".into(),
            feed_url: "https://example.com/feed.xml".into(),
            read_through: None,
            read_ids: r#"["100","101","102"]"#.into(),
            unread_ids: "[]".into(),
            dirty: true,
            pds_created: false,
            updated_at: "2026-07-12T02:00:00Z".into(),
        };
        let rec = read_state_record(&cursor);
        assert_eq!(rec.read_through, None);
        assert_eq!(rec.read_ids, vec!["100", "101", "102"]);
        let json = serde_json::to_value(&rec).expect("serialize");
        assert!(json.get("readThrough").is_none());
        assert_eq!(json["readIds"], serde_json::json!(["100", "101", "102"]));
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
}
