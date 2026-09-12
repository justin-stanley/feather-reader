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

/// The process-wide table. Cheap to clone into handlers via `AppState`.
#[derive(Debug, Default)]
pub struct RepoMetrics {
    stats: Mutex<HashMap<(Backend, &'static str), Stats>>,
}

impl RepoMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one call.
    pub fn record(&self, backend: Backend, op: &'static str, micros: u64, ok: bool) {
        let mut stats = self.stats.lock().expect("metrics table poisoned");
        stats.entry((backend, op)).or_default().record(micros, ok);
    }

    /// A snapshot, sorted for stable rendering.
    pub fn snapshot(&self) -> Vec<((Backend, &'static str), Stats)> {
        let stats = self.stats.lock().expect("metrics table poisoned");
        let mut rows: Vec<_> = stats.iter().map(|(k, v)| (*k, v.clone())).collect();
        rows.sort_by_key(|((backend, op), _)| (*backend, *op));
        rows
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

/// Render a snapshot as a plain-text table.
///
/// Milliseconds with one decimal, because the interesting differences here are
/// tens of milliseconds (a sidecar hop) and microsecond precision would just be
/// noise from the scheduler.
///
/// Both the success and the failure columns are shown. Reading `ok` without
/// `err` is how a backend that fails half its calls in 2 ms gets mistaken for a
/// fast one.
pub fn render(rows: &[((Backend, &'static str), Stats)]) -> String {
    let mut out = String::from(
        "backend  operation                      ok   p50ms   p95ms    err  errp50ms\n",
    );
    if rows.is_empty() {
        out.push_str("(no repo operations recorded yet)\n");
        return out;
    }
    for ((backend, op), stats) in rows {
        out.push_str(&format!(
            "{:<8} {:<28} {:>4} {:>7} {:>7} {:>6} {:>9}\n",
            backend.as_str(),
            op,
            stats.ok_count,
            render_micros(stats.percentile(50.0)),
            render_micros(stats.percentile(95.0)),
            stats.err_count,
            render_micros(stats.error_percentile(50.0)),
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
            .find(|((b, _), _)| *b == Backend::Sidecar)
            .expect("the sidecar row");
        let rust = snapshot
            .iter()
            .find(|((b, _), _)| *b == Backend::Rust)
            .expect("the rust row");
        assert_eq!(
            sidecar.0 .1, rust.0 .1,
            "the same operation name, or the \
                   rows cannot be compared"
        );
        assert_eq!(sidecar.1.percentile(50.0), Some(5_000));
        assert_eq!(rust.1.percentile(50.0), Some(2_000));
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
        let stats = &snapshot[0].1;
        assert_eq!(stats.ok_count, 1);
        assert_eq!(stats.err_count, 1);
    }
}
