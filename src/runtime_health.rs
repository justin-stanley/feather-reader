//! What the background loops are actually doing, readable from a request.
//!
//! The two states that stop feeds from updating — the DB-size watermark pause
//! and a poller that has stopped ticking — were previously observable only as
//! log lines. `/stats` publishes `overdue` and `polled_last_hour`, which move in
//! BOTH states and distinguish neither, and `/health` returned a constant
//! string. So every degraded-but-running instance presented as a green machine,
//! and "my feeds stopped updating" left the operator with `fly logs` and nothing
//! else.
//!
//! This is deliberately **process-local and lossy**: a few atomics, no
//! persistence, no history. It answers "what is the loop doing right now",
//! which is the question an operator has in the middle of an incident. Anything
//! that needs to survive a restart already lives in SQLite (`feeds.next_poll`,
//! `feeds.consecutive_errors`), and is read from there.
//!
//! Everything here is a **machine fact** — no user counts, no DIDs, no feed
//! URLs — so it can be published on the same terms as `/stats`.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

/// Shared record of background-loop state. Cheap to read from a handler.
#[derive(Debug, Default)]
pub struct RuntimeHealth {
    /// Unix seconds when the poll loop last COMPLETED a tick. `0` = never.
    ///
    /// Completed, not started: a tick that begins and then hangs must not keep
    /// the heartbeat looking fresh, since a hung poller is exactly the condition
    /// this exists to surface.
    last_poll_tick: AtomicI64,
    /// Whether the DB-size watermark is currently pausing new fetches.
    watermark_paused: AtomicBool,
    /// Whether the background loops were started at all
    /// (`FEATHERREADER_DISABLE_SCHEDULER` turns them off for dev and tests).
    ///
    /// Without this, "the poller has never ticked" and "the poller was never
    /// started" look identical from a handler — and they call for completely
    /// different responses.
    schedulers_enabled: AtomicBool,
}

impl RuntimeHealth {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the background loops were (or were not) spawned.
    pub fn set_schedulers_enabled(&self, enabled: bool) {
        self.schedulers_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn schedulers_enabled(&self) -> bool {
        self.schedulers_enabled.load(Ordering::Relaxed)
    }

    /// Stamp a completed poll tick at `now_unix`.
    pub fn poll_tick_completed(&self, now_unix: i64) {
        self.last_poll_tick.store(now_unix, Ordering::Relaxed);
    }

    /// Seconds since the last completed poll tick, or `None` if there has not
    /// been one yet.
    pub fn secs_since_poll_tick(&self, now_unix: i64) -> Option<i64> {
        match self.last_poll_tick.load(Ordering::Relaxed) {
            0 => None,
            // Never negative: a clock step backwards reads as "just now" rather
            // than as a negative age, matching `store::secs_between`.
            t => Some((now_unix - t).max(0)),
        }
    }

    /// Record the outcome of a watermark check.
    ///
    /// Deliberately just the verdict, not the measured size. The size is already
    /// in the log line that accompanies a pause, and the two surfaces that read
    /// this — `/health` and `/stats` — are both reachable without the Cloudflare
    /// origin lock or a session, so neither publishes precise internal numbers.
    pub fn set_watermark(&self, paused: bool) {
        self.watermark_paused.store(paused, Ordering::Relaxed);
    }

    /// Whether the watermark is currently pausing new fetches. This is the
    /// state in which `polled_last_hour` falls and `overdue` climbs for a reason
    /// that has nothing to do with the poller being too slow.
    pub fn watermark_paused(&self) -> bool {
        self.watermark_paused.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_record_reports_nothing_rather_than_zero() {
        let h = RuntimeHealth::new();
        // "Never ticked" must not read as "ticked 0 seconds ago" — on a machine
        // that has just booted, the latter is the healthiest possible answer to
        // a question nothing has answered yet.
        assert_eq!(h.secs_since_poll_tick(1_000), None);
        assert!(!h.watermark_paused());
        assert!(!h.schedulers_enabled());
    }

    #[test]
    fn a_tick_ages_and_a_backwards_clock_does_not_go_negative() {
        let h = RuntimeHealth::new();
        h.poll_tick_completed(1_000);
        assert_eq!(h.secs_since_poll_tick(1_090), Some(90));
        assert_eq!(
            h.secs_since_poll_tick(900),
            Some(0),
            "a clock step backwards must read as 'just now', not as a negative age"
        );
    }

    #[test]
    fn the_watermark_verdict_round_trips_both_ways() {
        let h = RuntimeHealth::new();
        h.set_watermark(true);
        assert!(h.watermark_paused());
        // And it must clear again — a pause that latched would keep every page
        // claiming an outage long after the retention sweep freed the space.
        h.set_watermark(false);
        assert!(!h.watermark_paused());
    }
}
