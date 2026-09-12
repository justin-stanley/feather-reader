//! Side-by-side latency for the two repo backends.
//!
//! The cutover runs one backend at a time behind a flag, so the comparison is
//! across a flip rather than within a request. That makes the *shape* of the
//! measurement the thing to get right: both paths are timed at the same
//! boundary — the call site in `web.rs`, which is what a user's request
//! actually waits on — by one wrapper rather than two hand-placed timers, so a
//! difference in the numbers is a difference in the backends.
//!
//! **Failures are timed separately from successes.** A backend that is fast
//! because it is erroring out early would otherwise look like a win, and that
//! is precisely the regression a cutover needs to catch.

use std::collections::HashMap;
use std::sync::Mutex;

/// Which repo implementation served a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Backend {
    /// The Node `@atproto/oauth-client` sidecar.
    Sidecar,
    /// The Rust-native OAuth client.
    Rust,
}

impl Backend {
    /// Read back a persisted row's backend name. `None` for anything this
    /// version does not know, so a row from a newer build is skipped rather
    /// than failing the whole table.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "sidecar" => Some(Backend::Sidecar),
            "rust" => Some(Backend::Rust),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Sidecar => "sidecar",
            Backend::Rust => "rust",
        }
    }
}

/// How many recent samples are kept per (backend, operation).
///
/// Exact percentiles over a bounded recent window, rather than approximate ones
/// over all time: a cutover comparison cares about how the backend is behaving
/// *now*, and a window that includes the first cold-start minute forever would
/// hide a later improvement.
const WINDOW: usize = 1024;

/// Timings for one (backend, operation) pair.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    /// Durations of SUCCESSFUL calls, most recent `WINDOW` kept.
    ok_micros: Vec<u64>,
    /// Durations of FAILED calls, kept apart so they cannot flatter a
    /// percentile.
    err_micros: Vec<u64>,
    /// Totals over all time, unaffected by the window.
    pub ok_count: u64,
    pub err_count: u64,
}

impl Stats {
    fn record(&mut self, micros: u64, ok: bool) {
        let (samples, count) = if ok {
            (&mut self.ok_micros, &mut self.ok_count)
        } else {
            (&mut self.err_micros, &mut self.err_count)
        };
        *count += 1;
        if samples.len() == WINDOW {
            samples.remove(0);
        }
        samples.push(micros);
    }

    /// The `p`th percentile of SUCCESSFUL calls, in microseconds.
    ///
    /// `None` when nothing has succeeded — reporting `0` for an operation that
    /// has never completed would read as "instant" on exactly the dashboard
    /// someone uses to decide a cutover is safe.
    pub fn percentile(&self, p: f64) -> Option<u64> {
        percentile_of(&self.ok_micros, p)
    }

    /// The same percentile over FAILED calls, for reading beside the successes.
    pub fn error_percentile(&self, p: f64) -> Option<u64> {
        percentile_of(&self.err_micros, p)
    }
}

/// Nearest-rank percentile over a copy of the samples.
fn percentile_of(samples: &[u64], p: f64) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    // Nearest-rank: ceil(p/100 * n), clamped into the slice.
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    Some(sorted[rank.min(sorted.len()) - 1])
}

/// One rendered line: a backend, an operation, and its timings.
#[derive(Debug, Clone)]
pub struct Row {
    pub backend: Backend,
    pub op: String,
    pub stats: Stats,
}

/// Cap on unflushed samples held in memory.
///
/// A backstop, not a tuning knob: if the flusher ever stops, this bounds what
/// the buffer can grow to rather than letting a metrics buffer take the process
/// down. Oldest are dropped, because the recent ones are the interesting ones.
const MAX_PENDING: usize = 16_384;

/// The process-wide table. Cheap to clone into handlers via `AppState`.
#[derive(Debug, Default)]
pub struct RepoMetrics {
    stats: Mutex<HashMap<(Backend, &'static str), Stats>>,
    /// Samples not yet written to SQLite.
    ///
    /// Recording buffers rather than writing, because a synchronous insert on
    /// the request path would put the instrument inside the thing it measures --
    /// every repo call would carry a database write that the sidecar path never
    /// had, and the comparison would be of the instrumentation.
    pending: Mutex<Vec<Sample>>,
}

/// A buffered sample awaiting its write.
#[derive(Debug, Clone, Copy)]
struct Sample {
    backend: Backend,
    op: &'static str,
    micros: u64,
    ok: bool,
}

impl RepoMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one call: into the live window, and into the write buffer.
    pub fn record(&self, backend: Backend, op: &'static str, micros: u64, ok: bool) {
        self.stats
            .lock()
            .expect("metrics table poisoned")
            .entry((backend, op))
            .or_default()
            .record(micros, ok);

        let mut pending = self.pending.lock().expect("metrics buffer poisoned");
        if pending.len() >= MAX_PENDING {
            pending.remove(0);
        }
        pending.push(Sample {
            backend,
            op,
            micros,
            ok,
        });
    }

    /// This PROCESS's samples, sorted for stable rendering.
    ///
    /// Only ever one backend's rows, since a flip is a restart. Use
    /// [`persisted_rows`] for the cross-flip comparison.
    pub fn snapshot(&self) -> Vec<Row> {
        let stats = self.stats.lock().expect("metrics table poisoned");
        let mut rows: Vec<Row> = stats
            .iter()
            .map(|((backend, op), stats)| Row {
                backend: *backend,
                op: (*op).to_string(),
                stats: stats.clone(),
            })
            .collect();
        rows.sort_by(|a, b| (a.backend, &a.op).cmp(&(b.backend, &b.op)));
        rows
    }

    /// Take everything buffered, leaving the buffer empty.
    fn drain(&self) -> Vec<Sample> {
        std::mem::take(&mut *self.pending.lock().expect("metrics buffer poisoned"))
    }
}

/// Time one repo call and record it.
///
/// The single instrumentation point for both backends. Anything measured
/// elsewhere would be measuring a different boundary, and the comparison would
/// be between the timers rather than the implementations.
pub async fn timed<T, E, F>(
    metrics: &RepoMetrics,
    backend: Backend,
    op: &'static str,
    call: F,
) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let started = std::time::Instant::now();
    let result = call.await;
    metrics.record(
        backend,
        op,
        started.elapsed().as_micros() as u64,
        result.is_ok(),
    );
    result
}

/// Write the buffered samples and prune each key back to its window.
///
/// Called on a timer and before rendering. Errors are returned rather than
/// logged here so the caller decides: a metrics write failing must never take
/// down the request that produced the sample.
pub async fn flush(metrics: &RepoMetrics, pool: &sqlx::SqlitePool, now: i64) -> anyhow::Result<()> {
    let samples = metrics.drain();
    if samples.is_empty() {
        return Ok(());
    }

    let mut tx = pool.begin().await?;
    for sample in &samples {
        sqlx::query(
            "INSERT INTO repo_timing (backend, op, micros, ok, at) VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(sample.backend.as_str())
        .bind(sample.op)
        .bind(sample.micros as i64)
        .bind(i64::from(sample.ok))
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // All-time counts, kept apart from the window so PRUNING CANNOT LOSE
        // THEM. Without this a long-running backend would appear to have served
        // fewer calls than a freshly-flipped one, which is the opposite of the
        // truth and exactly the kind of number someone would act on.
        sqlx::query(
            "INSERT INTO repo_timing_total (backend, op, ok_count, err_count) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(backend, op) DO UPDATE SET \
               ok_count  = ok_count  + excluded.ok_count, \
               err_count = err_count + excluded.err_count",
        )
        .bind(sample.backend.as_str())
        .bind(sample.op)
        .bind(i64::from(sample.ok))
        .bind(i64::from(!sample.ok))
        .execute(&mut *tx)
        .await?;
    }

    // Prune per (backend, op, ok): successes and failures have their OWN
    // windows, so a burst of failures cannot evict the successes it should be
    // compared against.
    for (backend, op, ok) in distinct_keys(&samples) {
        sqlx::query(
            "DELETE FROM repo_timing WHERE backend = ?1 AND op = ?2 AND ok = ?3 AND id NOT IN \
             (SELECT id FROM repo_timing WHERE backend = ?1 AND op = ?2 AND ok = ?3 \
              ORDER BY id DESC LIMIT ?4)",
        )
        .bind(backend.as_str())
        .bind(op)
        .bind(i64::from(ok))
        .bind(WINDOW as i64)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

/// The (backend, op, ok) keys touched by a batch, deduplicated.
fn distinct_keys(samples: &[Sample]) -> Vec<(Backend, &'static str, bool)> {
    let mut keys: Vec<(Backend, &'static str, bool)> =
        samples.iter().map(|s| (s.backend, s.op, s.ok)).collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Read the persisted rows for BOTH backends.
///
/// This is what makes the comparison possible at all: a flip is a restart, so
/// the outgoing backend's numbers exist only here.
pub async fn persisted_rows(pool: &sqlx::SqlitePool) -> anyhow::Result<Vec<Row>> {
    let totals: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT backend, op, ok_count, err_count FROM repo_timing_total ORDER BY backend, op",
    )
    .fetch_all(pool)
    .await?;

    let mut rows = Vec::with_capacity(totals.len());
    for (backend, op, ok_count, err_count) in totals {
        let Some(backend) = Backend::parse(&backend) else {
            // A row written by a version that knew a backend this one does not.
            // Skipped rather than failing the whole table.
            continue;
        };
        let samples: Vec<(i64, i64)> =
            sqlx::query_as("SELECT micros, ok FROM repo_timing WHERE backend = ?1 AND op = ?2")
                .bind(backend.as_str())
                .bind(&op)
                .fetch_all(pool)
                .await?;

        let mut stats = Stats {
            ok_count: ok_count as u64,
            err_count: err_count as u64,
            ..Stats::default()
        };
        for (micros, ok) in samples {
            if ok == 1 {
                stats.ok_micros.push(micros as u64);
            } else {
                stats.err_micros.push(micros as u64);
            }
        }
        rows.push(Row { backend, op, stats });
    }
    Ok(rows)
}

/// Render a snapshot as a plain-text table.
///
/// Milliseconds with one decimal, because the interesting differences here are
/// tens of milliseconds (a sidecar hop) and microsecond precision would just be
/// noise from the scheduler.
///
/// Both the success and the failure columns are shown. Reading `ok` without
/// `err` is how a backend that fails half its calls in 2 ms gets mistaken for a
/// fast one.
pub fn render(rows: &[Row]) -> String {
    let mut out = String::from(
        "backend  operation                      ok   p50ms   p95ms    err  errp50ms\n",
    );
    if rows.is_empty() {
        out.push_str("(no repo operations recorded yet)\n");
        return out;
    }
    for row in rows {
        out.push_str(&format!(
            "{:<8} {:<28} {:>4} {:>7} {:>7} {:>6} {:>9}\n",
            row.backend.as_str(),
            row.op,
            row.stats.ok_count,
            render_micros(row.stats.percentile(50.0)),
            render_micros(row.stats.percentile(95.0)),
            row.stats.err_count,
            render_micros(row.stats.error_percentile(50.0)),
        ));
    }
    out
}

/// `-` rather than `0.0` for an absent measurement: a dash is obviously "no
/// data", while a zero reads as the fastest row in the table.
fn render_micros(micros: Option<u64>) -> String {
    match micros {
        Some(micros) => format!("{:.1}", micros as f64 / 1000.0),
        None => "-".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats_of(ok: &[u64], err: &[u64]) -> Stats {
        let mut stats = Stats::default();
        for micros in ok {
            stats.record(*micros, true);
        }
        for micros in err {
            stats.record(*micros, false);
        }
        stats
    }

    /// Nearest-rank percentiles, checked against a distribution whose answers
    /// can be read off by hand.
    #[test]
    fn percentiles_come_from_the_recorded_samples() {
        let stats = stats_of(&[10, 20, 30, 40, 50, 60, 70, 80, 90, 100], &[]);
        assert_eq!(stats.percentile(50.0), Some(50));
        assert_eq!(stats.percentile(95.0), Some(100));
        assert_eq!(stats.percentile(100.0), Some(100));
        // The lowest percentile must still land on a real sample, not index -1.
        assert_eq!(stats.percentile(0.0), Some(10));
    }

    /// **A failed call must not enter the success percentiles.**
    ///
    /// An erroring backend fails fast — a refused connection returns far quicker
    /// than a real PDS round trip. Mixing those in makes the broken path look
    /// like the faster one on the very dashboard used to decide whether the
    /// cutover is safe.
    #[test]
    fn failures_are_counted_but_kept_out_of_the_success_percentiles() {
        // Ten slow successes, ninety instant failures.
        let stats = stats_of(&[1000; 10], &[1; 90]);

        assert_eq!(
            stats.percentile(50.0),
            Some(1000),
            "fast failures dragged the success percentile down, which is how a \
             broken backend passes for a fast one"
        );
        assert_eq!(stats.ok_count, 10);
        assert_eq!(stats.err_count, 90);
        assert_eq!(stats.error_percentile(50.0), Some(1));
    }

    /// An operation nobody has exercised reports nothing. Zero would render as
    /// "instant" and read as the best row in the table.
    #[test]
    fn an_unexercised_operation_reports_nothing_rather_than_zero() {
        let stats = Stats::default();
        assert_eq!(stats.percentile(50.0), None);
        assert_eq!(stats.error_percentile(50.0), None);
    }

    /// An operation that has only ever failed has no success percentile, but its
    /// failures are still visible — the row must not vanish.
    #[test]
    fn an_operation_that_only_ever_fails_still_reports_its_failures() {
        let stats = stats_of(&[], &[5, 7, 9]);
        assert_eq!(stats.percentile(50.0), None);
        assert_eq!(stats.err_count, 3);
        assert_eq!(stats.error_percentile(50.0), Some(7));
    }

    /// The window keeps the MOST RECENT samples. A window that dropped the
    /// newest instead would freeze the picture at start-up and never show a
    /// regression.
    #[test]
    fn the_window_keeps_the_most_recent_samples() {
        let mut stats = Stats::default();
        for i in 0..(WINDOW as u64 + 10) {
            stats.record(i, true);
        }
        assert_eq!(stats.ok_count, WINDOW as u64 + 10, "the total counts all");
        assert_eq!(
            stats.percentile(0.0),
            Some(10),
            "the oldest samples should have aged out of the window"
        );
        assert_eq!(stats.percentile(100.0), Some(WINDOW as u64 + 9));
    }

    /// Both backends land in one table under the same operation name, which is
    /// what makes the two rows comparable.
    #[test]
    fn the_two_backends_are_recorded_side_by_side() {
        let metrics = RepoMetrics::new();
        metrics.record(Backend::Sidecar, "list_subscriptions", 5_000, true);
        metrics.record(Backend::Rust, "list_subscriptions", 2_000, true);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.len(), 2);
        let sidecar = snapshot
            .iter()
            .find(|r| r.backend == Backend::Sidecar)
            .expect("the sidecar row");
        let rust = snapshot
            .iter()
            .find(|r| r.backend == Backend::Rust)
            .expect("the rust row");
        assert_eq!(
            sidecar.op, rust.op,
            "the same operation name, or the rows cannot be compared"
        );
        assert_eq!(sidecar.stats.percentile(50.0), Some(5_000));
        assert_eq!(rust.stats.percentile(50.0), Some(2_000));
    }

    /// An absent measurement renders as `-`, never `0.0`. A zero in a latency
    /// column is indistinguishable from "the fastest thing here" at a glance,
    /// which is the wrong reading of "never succeeded".
    #[test]
    fn an_absent_measurement_renders_as_a_dash_rather_than_zero() {
        let metrics = RepoMetrics::new();
        metrics.record(Backend::Rust, "list_folders", 3_000, false);
        let table = render(&metrics.snapshot());

        assert!(
            !table.contains("0.0"),
            "a never-succeeded operation rendered as 0.0ms, which reads as instant:\n{table}"
        );
        assert!(
            table.contains('-'),
            "expected a dash for the absent p50:\n{table}"
        );
        // The failure itself is still visible — the row must not be silently dropped.
        assert!(table.contains("list_folders"), "the row vanished:\n{table}");
        assert!(
            table.contains("3.0"),
            "the failure latency is missing:\n{table}"
        );
    }

    /// An empty table says so rather than rendering a bare header that looks
    /// like a working instrument reporting nothing wrong.
    #[test]
    fn an_empty_snapshot_says_so() {
        assert!(render(&[]).contains("no repo operations recorded"));
    }

    /// `timed` records the outcome, not just the duration — the wrapper is the
    /// only instrumentation point, so if it lost the ok/err distinction the
    /// separation above would never happen in production.
    #[tokio::test]
    async fn timed_records_success_and_failure_distinctly() {
        let metrics = RepoMetrics::new();
        let _: Result<(), ()> = timed(&metrics, Backend::Rust, "op", async { Ok(()) }).await;
        let _: Result<(), ()> = timed(&metrics, Backend::Rust, "op", async { Err(()) }).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot[0].stats.ok_count, 1);
        assert_eq!(snapshot[0].stats.err_count, 1);
    }

    // ── persistence: the reason the comparison is possible at all ────────────

    async fn pool() -> sqlx::SqlitePool {
        crate::store::init_url("sqlite::memory:").await.unwrap()
    }

    /// **The whole point.** A backend flip is a RESTART, so the outgoing
    /// backend's numbers exist only if they were written down. Two processes
    /// are simulated by two `RepoMetrics` sharing one database, which is exactly
    /// what a flip produces.
    ///
    /// Without persistence the table can only ever show the backend currently
    /// running, which is not a comparison.
    #[tokio::test]
    async fn a_backend_flip_keeps_the_earlier_backends_rows() {
        let pool = pool().await;

        // Process 1: the sidecar backend serves some traffic.
        let before = RepoMetrics::new();
        for _ in 0..5 {
            before.record(Backend::Sidecar, "list_subscriptions_sorted", 9_000, true);
        }
        flush(&before, &pool, 1_700_000_000).await.unwrap();

        // ... the operator flips the flag and restarts. New process, new table.
        let after = RepoMetrics::new();
        for _ in 0..5 {
            after.record(Backend::Rust, "list_subscriptions_sorted", 3_000, true);
        }
        flush(&after, &pool, 1_700_000_100).await.unwrap();

        assert_eq!(
            after.snapshot().len(),
            1,
            "in-process memory only ever holds the running backend"
        );

        let rows = persisted_rows(&pool).await.unwrap();
        assert_eq!(
            rows.len(),
            2,
            "both backends must survive the flip: {rows:?}"
        );
        let sidecar = rows.iter().find(|r| r.backend == Backend::Sidecar).unwrap();
        let rust = rows.iter().find(|r| r.backend == Backend::Rust).unwrap();
        assert_eq!(sidecar.stats.percentile(50.0), Some(9_000));
        assert_eq!(rust.stats.percentile(50.0), Some(3_000));
        assert_eq!(sidecar.op, rust.op, "rows must be comparable by operation");
    }

    /// Successes and failures are timed apart in the DATABASE too, not just in
    /// memory — otherwise the property the in-memory tests pin would be lost the
    /// moment it was written down.
    #[tokio::test]
    async fn persisted_failures_stay_out_of_the_success_percentiles() {
        let pool = pool().await;
        let metrics = RepoMetrics::new();
        for _ in 0..10 {
            metrics.record(Backend::Rust, "add_subscription", 1_000, true);
        }
        for _ in 0..90 {
            metrics.record(Backend::Rust, "add_subscription", 1, false);
        }
        flush(&metrics, &pool, 1_700_000_000).await.unwrap();

        let rows = persisted_rows(&pool).await.unwrap();
        let stats = &rows[0].stats;
        assert_eq!(
            stats.percentile(50.0),
            Some(1_000),
            "fast failures dragged the persisted success percentile down"
        );
        assert_eq!(stats.ok_count, 10);
        assert_eq!(stats.err_count, 90);
    }

    /// **All-time counts must survive pruning.** The window is bounded, but the
    /// totals are not: a long-running backend that had its oldest samples pruned
    /// would otherwise appear to have served FEWER calls than one freshly
    /// flipped to — the opposite of the truth, and the kind of number someone
    /// would act on.
    #[tokio::test]
    async fn pruning_bounds_the_window_without_losing_the_totals() {
        let pool = pool().await;
        let metrics = RepoMetrics::new();
        let total = WINDOW + 250;
        for i in 0..total {
            metrics.record(Backend::Rust, "list_folders_sorted", i as u64 + 1, true);
        }
        flush(&metrics, &pool, 1_700_000_000).await.unwrap();

        let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM repo_timing")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(kept, WINDOW as i64, "the window is not bounded");

        let rows = persisted_rows(&pool).await.unwrap();
        assert_eq!(
            rows[0].stats.ok_count, total as u64,
            "pruning ate the all-time count"
        );
        // The window kept the NEWEST samples, so the smallest surviving value is
        // the 251st recorded, not the 1st.
        assert_eq!(rows[0].stats.percentile(0.0), Some(251));
    }

    /// A burst of failures must not evict the successes it is being compared
    /// against — the two have separate windows.
    #[tokio::test]
    async fn a_burst_of_failures_does_not_evict_the_successes() {
        let pool = pool().await;
        let metrics = RepoMetrics::new();
        metrics.record(Backend::Rust, "put_read_state", 5_000, true);
        for _ in 0..(WINDOW + 100) {
            metrics.record(Backend::Rust, "put_read_state", 2, false);
        }
        flush(&metrics, &pool, 1_700_000_000).await.unwrap();

        let rows = persisted_rows(&pool).await.unwrap();
        assert_eq!(
            rows[0].stats.percentile(50.0),
            Some(5_000),
            "the only success was evicted by a flood of failures"
        );
    }

    /// Flushing twice must not double-count: the buffer is drained, not copied.
    #[tokio::test]
    async fn flushing_twice_does_not_double_count() {
        let pool = pool().await;
        let metrics = RepoMetrics::new();
        metrics.record(Backend::Rust, "remove_saved", 1_000, true);
        flush(&metrics, &pool, 1_700_000_000).await.unwrap();
        flush(&metrics, &pool, 1_700_000_001).await.unwrap();

        let rows = persisted_rows(&pool).await.unwrap();
        assert_eq!(rows[0].stats.ok_count, 1, "the sample was counted twice");
    }
}
