//! The crate's one clock, one timestamp format, and one RFC3339 parser.
//!
//! **Why this module exists.** The store compares timestamps as STRINGS —
//! `COALESCE(published, fetched_at) < cutoff`, the per-feed keep-set, both
//! retention sweeps, the read cursor — so the byte format of a timestamp is a
//! correctness property, not a display choice. A writer that emitted
//! `...:05.123Z` beside rows holding `...:05Z` would sort them wrong, and
//! nothing would fail loudly. So the format lives in exactly one place.
//!
//! It replaced `chrono`, which RustSec marks unmaintained (RUSTSEC-2026-0543),
//! and it was written to reproduce chrono's observable behaviour exactly rather
//! than approximately. `the_format_and_parser_match_what_chrono_did` holds the
//! oracle: fifty cases recorded from chrono itself before it was removed, as
//! literal strings, so the test still means something with chrono gone.
//!
//! The parser is hand-written rather than delegated to jiff's, because several
//! callers feed it EXTERNAL input — `publishedAt` off an atproto record, read
//! state from a reader's PDS — and for those the accept/reject boundary is part
//! of the contract. A more permissive parser would quietly admit values chrono
//! refused. jiff supplies the `Timestamp` type, the clock and duration
//! arithmetic; the boundary is defined here, in code this crate controls.

pub use jiff::{SignedDuration, Timestamp};

/// Now.
pub fn now() -> Timestamp {
    Timestamp::now()
}

/// `now()` in the store's format. See [`fmt_secs`].
pub fn now_rfc3339() -> String {
    fmt_secs(now())
}

/// RFC3339 in UTC to whole seconds with a `Z` suffix: `2026-01-01T00:00:00Z`.
///
/// **Truncates; never rounds.** `...:05.999999999` is `...:05Z`. chrono's
/// `SecondsFormat::Secs` did the same, and rounding would move a row across a
/// cutoff it used to sit on the right side of.
pub fn fmt_secs(t: Timestamp) -> String {
    let (secs, _) = split(t);
    civil(secs)
}

/// RFC3339 in UTC with the shortest of 0, 3, 6 or 9 fractional digits that
/// loses nothing — chrono's `SecondsFormat::AutoSi`. Used only where a remote
/// timestamp's precision must survive normalisation.
pub fn fmt_auto(t: Timestamp) -> String {
    let (secs, nanos) = split(t);
    let base = civil(secs);
    let stem = &base[..base.len() - 1];
    if nanos == 0 {
        base
    } else if nanos % 1_000_000 == 0 {
        format!("{stem}.{:03}Z", nanos / 1_000_000)
    } else if nanos % 1_000 == 0 {
        format!("{stem}.{:06}Z", nanos / 1_000)
    } else {
        format!("{stem}.{nanos:09}Z")
    }
}

/// Method-call spelling of [`fmt_secs`] and [`fmt_auto`], for the long
/// arithmetic chains in the store that compute an instant and format it in one
/// expression. Exists so those chains read the same as before; it adds no
/// behaviour of its own.
pub trait TimestampExt {
    /// [`fmt_secs`].
    fn rfc3339_secs(self) -> String;
    /// [`fmt_auto`].
    fn rfc3339_auto(self) -> String;
}

impl TimestampExt for Timestamp {
    fn rfc3339_secs(self) -> String {
        fmt_secs(self)
    }
    fn rfc3339_auto(self) -> String {
        fmt_auto(self)
    }
}

/// From Unix microseconds, as atproto TIDs carry them.
pub fn from_micros(micros: i64) -> Option<Timestamp> {
    Timestamp::from_microsecond(micros).ok()
}

/// A whole number of days, for fixed windows written as constants.
///
/// Saturates rather than panicking: `SignedDuration::from_hours` panics when
/// the hours overflow i64 seconds, and that is not a failure a constant should
/// be able to cause. For a window taken from CONFIG use [`try_days`], which
/// reports the overflow instead of silently clamping it.
pub fn days(n: i64) -> SignedDuration {
    SignedDuration::from_secs(n.saturating_mul(86_400))
}

/// A whole number of days, or `None` if it does not fit — chrono's
/// `Duration::try_days`. Retention windows come from operator configuration,
/// and a unit slip such as `RETENTION_DAYS=1000000000000000` must be reported,
/// not panic at boot and not quietly become a different window.
pub fn try_days(n: i64) -> Option<SignedDuration> {
    n.checked_mul(86_400).map(SignedDuration::from_secs)
}

/// Parse an RFC3339 timestamp to a UTC instant, accepting EXACTLY what chrono's
/// `DateTime::parse_from_rfc3339` accepted.
///
/// That boundary, from the oracle: `T`, `t` or a single space between date and
/// time; seconds required; an optional `.` fraction of one or more digits, cut
/// to nine; `Z`, `z` or `+HH:MM` / `-HH:MM` with the colon and an hour below 24.
/// No surrounding whitespace, no basic (colon-less) form, no `+YYYY` years, no
/// `,` fraction, no hour 24, and a real calendar date.
///
/// **Two deliberate divergences, both forced by what a `Timestamp` can hold.**
///
/// - chrono kept a leap second as `:60`. A `Timestamp` cannot represent one, so
///   `:60` is accepted and read as `:59` of the same minute — still accepted,
///   and it still orders before the following minute.
/// - chrono reached `9999-12-31T23:59:59Z`; a `Timestamp` stops at
///   `9999-12-30T22:00:00.999999999Z`, measured rather than taken from the docs
///   (which state the bound as a civil time in another offset). The final
///   26 hours of year 9999 are REFUSED rather than clamped, because clamping
///   would invent a value. That is also the safe direction for every caller:
///   published dates are already discarded above a future ceiling, and in a
///   read-state "latest wins" merge a year-9999 remote timestamp would
///   otherwise win every comparison it took part in.
pub fn parse_rfc3339(s: &str) -> Option<Timestamp> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let d = b.get(r)?;
        d.iter()
            .all(u8::is_ascii_digit)
            .then(|| d.iter().fold(0i64, |a, c| a * 10 + i64::from(c - b'0')))
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    if !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, mut sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) {
        return None;
    }
    if h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    if sec == 60 {
        sec = 59;
    }
    let mut i = 19;
    let mut nanos = 0i64;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            if i - start < 9 {
                nanos = nanos * 10 + i64::from(b[i] - b'0');
            }
            i += 1;
        }
        let n = i - start;
        if n == 0 {
            return None;
        }
        for _ in n..9 {
            nanos *= 10;
        }
    }
    let offset = match b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() && b[i + 3] == b':' => {
            let (oh, om) = (num(i + 1..i + 3)?, num(i + 4..i + 6)?);
            if oh > 23 || om > 59 {
                return None;
            }
            let o = oh * 3600 + om * 60;
            if *sign == b'-' {
                -o
            } else {
                o
            }
        }
        _ => return None,
    };
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec - offset;
    Timestamp::from_nanosecond(i128::from(secs) * 1_000_000_000 + i128::from(nanos)).ok()
}

/// Whole seconds (floored) and the non-negative nanoseconds within them.
fn split(t: Timestamp) -> (i64, i64) {
    let ns = t.as_nanosecond();
    let secs = ns.div_euclid(1_000_000_000) as i64;
    let nanos = ns.rem_euclid(1_000_000_000) as i64;
    (secs, nanos)
}

/// `YYYY-MM-DDTHH:MM:SSZ` for Unix seconds.
fn civil(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's `days_from_civil` / `civil_from_days`: exact over the whole
// proleptic Gregorian calendar, no lookup tables.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every row below was produced by chrono 0.4.45 itself, immediately before
    /// it was removed, and pasted in as literals. The TWO rows whose expected
    /// value differs from what chrono printed are overridden in the loop, by
    /// input, with the reason given on [`parse_rfc3339`] — so a divergence has to
    /// be stated here to exist at all.
    #[test]
    fn the_format_and_parser_match_what_chrono_did() {
        let parse: &[(&str, &str)] = &[
            ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00Z"),
            ("2026-01-01T05:30:00+05:30", "2026-01-01T00:00:00Z"),
            ("2026-01-01T00:00:00-08:00", "2026-01-01T08:00:00Z"),
            ("2026-01-01T00:00:00.123Z", "2026-01-01T00:00:00.123Z"),
            (
                "2026-01-01T00:00:00.123456789Z",
                "2026-01-01T00:00:00.123456789Z",
            ),
            (
                "2026-01-01T00:00:00.1234567891Z",
                "2026-01-01T00:00:00.123456789Z",
            ),
            ("2026-01-01t00:00:00z", "2026-01-01T00:00:00Z"),
            ("2026-01-01 00:00:00Z", "2026-01-01T00:00:00Z"),
            ("2026-01-01T00:00:00", "ERR"),
            ("2026-01-01", "ERR"),
            ("2026-01-01T00:00Z", "ERR"),
            ("2026-12-31T23:59:60Z", "2026-12-31T23:59:60Z"),
            ("2026-02-30T00:00:00Z", "ERR"),
            (" 2026-01-01T00:00:00Z", "ERR"),
            ("2026-01-01T00:00:00-00:00", "2026-01-01T00:00:00Z"),
            ("+2026-01-01T00:00:00Z", "ERR"),
            ("2026-01-01T00:00:00+0000", "ERR"),
            ("2026-01-01T00:00:00+05", "ERR"),
            ("", "ERR"),
            ("9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z"),
            ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"),
            ("2026-01-01T24:00:00Z", "ERR"),
            ("2026-1-1T00:00:00Z", "ERR"),
            ("2026-01-01T00:00:00.Z", "ERR"),
            ("2026-01-01T00:00:00,5Z", "ERR"),
            ("2026-01-01T00:00:00+24:00", "ERR"),
            ("2026-01-01T00:00:00+23:59", "2025-12-31T00:01:00Z"),
            ("20260101T000000Z", "ERR"),
            ("2026-01-01T00:00:00 Z", "ERR"),
            ("2026-01-01T00:00:00Z ", "ERR"),
            ("1969-12-31T23:59:59Z", "1969-12-31T23:59:59Z"),
        ];
        for &(input, want) in parse {
            let want = match input {
                // chrono: `:60`, which a Timestamp cannot hold.
                "2026-12-31T23:59:60Z" => "2026-12-31T23:59:59Z",
                // chrono: accepted; past Timestamp::MAX, so refused, not clamped.
                "9999-12-31T23:59:59Z" => "ERR",
                _ => want,
            };
            let got = parse_rfc3339(input).map(fmt_auto);
            assert_eq!(
                got.as_deref().unwrap_or("ERR"),
                want,
                "parse_rfc3339({input:?}) disagrees with chrono",
            );
        }

        let format: &[(i64, i64, &str, &str)] = &[
            (
                1800000000,
                0,
                "2027-01-15T08:00:00Z",
                "2027-01-15T08:00:00Z",
            ),
            (
                1800000000,
                999999999,
                "2027-01-15T08:00:00Z",
                "2027-01-15T08:00:00.999999999Z",
            ),
            (
                1800000000,
                500000000,
                "2027-01-15T08:00:00Z",
                "2027-01-15T08:00:00.500Z",
            ),
            (
                1800000000,
                123000000,
                "2027-01-15T08:00:00Z",
                "2027-01-15T08:00:00.123Z",
            ),
            (
                1800000000,
                123456000,
                "2027-01-15T08:00:00Z",
                "2027-01-15T08:00:00.123456Z",
            ),
            (
                1800000000,
                1,
                "2027-01-15T08:00:00Z",
                "2027-01-15T08:00:00.000000001Z",
            ),
            (
                32503680000,
                0,
                "3000-01-01T00:00:00Z",
                "3000-01-01T00:00:00Z",
            ),
            (0, 0, "1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z"),
        ];
        for &(secs, nanos, want_secs, want_auto) in format {
            let t =
                Timestamp::from_nanosecond(i128::from(secs) * 1_000_000_000 + i128::from(nanos))
                    .unwrap();
            assert_eq!(fmt_secs(t), want_secs, "fmt_secs({secs}.{nanos:09})");
            assert_eq!(fmt_auto(t), want_auto, "fmt_auto({secs}.{nanos:09})");
        }

        let micros: &[(i64, &str)] = &[
            (0, "1970-01-01T00:00:00Z"),
            (1, "1970-01-01T00:00:00Z"),
            (999999, "1970-01-01T00:00:00Z"),
            (1800000000123456, "2027-01-15T08:00:00Z"),
        ];
        for &(m, want) in micros {
            assert_eq!(fmt_secs(from_micros(m).unwrap()), want, "from_micros({m})");
        }
    }

    /// Calendar validity beyond what the oracle happened to sample. It has
    /// February 30th; it has no 29th in a non-leap year, and without that the
    /// leap-year rule could be deleted with every row above still passing.
    #[test]
    fn february_the_29th_exists_only_in_a_leap_year() {
        for (s, ok) in [
            ("2024-02-29T00:00:00Z", true),  // divisible by 4
            ("2025-02-29T00:00:00Z", false), // not
            ("1900-02-29T00:00:00Z", false), // by 100, not by 400
            ("2000-02-29T00:00:00Z", true),  // by 400
        ] {
            assert_eq!(parse_rfc3339(s).is_some(), ok, "{s}");
        }
    }

    /// **A configured window that does not fit is reported, not clamped and not
    /// a panic.** This is why [`try_days`] exists beside [`days`]: retention
    /// windows come from operator config, and a unit slip there used to be
    /// handled by chrono's `try_days` returning `None`. Saturating instead would
    /// quietly turn a typo into a different, valid-looking window.
    #[test]
    fn an_unrepresentable_day_count_is_none_rather_than_a_different_window() {
        assert_eq!(try_days(14), Some(SignedDuration::from_secs(14 * 86_400)));
        assert_eq!(try_days(i64::MAX), None);
        assert_eq!(try_days(i64::MAX / 86_400 + 1), None);
        // And `days`, for constants, saturates without panicking.
        let _ = days(i64::MAX);
    }

    /// The property the whole module exists for: the format sorts the same way
    /// the instants do, across a span wide enough to cross every field rollover.
    #[test]
    fn the_format_sorts_like_the_instants_it_names() {
        let mut prev: Option<(Timestamp, String)> = None;
        let mut t = parse_rfc3339("1999-12-31T23:59:58Z").unwrap();
        for _ in 0..2_000 {
            let s = fmt_secs(t);
            assert_eq!(parse_rfc3339(&s), Some(t), "round-trip of {s}");
            if let Some((pt, ps)) = &prev {
                assert_eq!(pt.cmp(&t), ps.as_str().cmp(s.as_str()), "{ps} vs {s}");
            }
            prev = Some((t, s));
            t += SignedDuration::from_secs(86_400 * 37 + 3_671);
        }
    }
}
