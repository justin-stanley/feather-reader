//! `synthfeeds`: a synthetic feed server for the capacity measurement (#263).
//!
//! Serves `N` RSS feeds at `/f/{i}.xml`, every byte a pure function of the
//! seed, the feed index and the simulated clock, so a run can be repeated and
//! two runs compared. Feeds update on their own schedules (the "churn"), honour
//! `If-None-Match` / `If-Modified-Since` with `304`s, and a small, fixed share
//! of them misbehave (slow, 404, 500, oversized) so backoff and the body cap are
//! exercised as they are in production. Hostile bodies are out of scope: #326
//! and #327 cover those.
//!
//! `/stats` counts what was served, so throughput is measured from this side
//! too. `synthfeeds seed` prints the SQL that registers the feeds in a
//! FeatherReader database. See README.md for a run.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};

/// Configuration, from the environment (`SYNTH_*`).
#[derive(Clone, Debug)]
struct Config {
    /// Feeds served: `/f/0.xml` … `/f/{feeds-1}.xml`.
    feeds: u64,
    /// Seeds every choice; the same seed serves the same bytes.
    seed: u64,
    /// Simulated seconds per real second. 1 is real time; 24 runs a day in an
    /// hour.
    time_scale: f64,
    /// Where to listen.
    bind: SocketAddr,
}

impl Config {
    fn from_env() -> Result<Self> {
        fn var<T: std::str::FromStr>(name: &str, default: T) -> Result<T>
        where
            T::Err: std::fmt::Display,
        {
            match std::env::var(name) {
                Ok(v) => v.parse().map_err(|e| anyhow::anyhow!("{name}={v:?}: {e}")),
                Err(_) => Ok(default),
            }
        }
        let c = Config {
            feeds: var("SYNTH_FEEDS", 1_000)?,
            seed: var("SYNTH_SEED", 263)?,
            time_scale: var("SYNTH_TIME_SCALE", 1.0)?,
            bind: var("SYNTH_BIND", SocketAddr::from(([127, 0, 0, 1], 8263)))?,
        };
        if c.feeds == 0 {
            bail!("SYNTH_FEEDS must be at least 1");
        }
        if !(c.time_scale.is_finite() && c.time_scale > 0.0) {
            bail!("SYNTH_TIME_SCALE must be a positive number");
        }
        Ok(c)
    }
}

/// SplitMix64: a small, well-mixed, dependency-free generator. Every value
/// served is `mix(seed, …)` of fixed inputs, never a running state, so any feed
/// can be rendered alone.
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn hash(parts: &[u64]) -> u64 {
    parts.iter().fold(0x5EED, |h, &p| mix(h ^ p))
}

/// A uniform value in `[0, 1)` from a hash.
fn unit(h: u64) -> f64 {
    (h >> 11) as f64 / (1u64 << 53) as f64
}

/// How a feed behaves, fixed by its index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behaviour {
    /// 20–50 items of ordinary article bodies.
    Normal,
    /// ~2,000 short items, 2–5 MB: a big podcast-style feed.
    Big,
    /// Answers after 3–8 s.
    Slow,
    /// Always 404.
    NotFound,
    /// Always 500.
    ServerError,
    /// A body over FeatherReader's 8 MiB cap.
    Oversized,
}

/// Shares of each misbehaviour, out of 1,000 feeds. Production-like: most
/// feeds are healthy, and a few of each kind of trouble are always present.
const BIG_PER_MILLE: u64 = 10;
const SLOW_PER_MILLE: u64 = 20;
const NOT_FOUND_PER_MILLE: u64 = 10;
const SERVER_ERROR_PER_MILLE: u64 = 10;
const OVERSIZED_PER_MILLE: u64 = 5;

/// Over FeatherReader's `MAX_BODY_BYTES` (8 MiB).
const OVERSIZED_BYTES: usize = 9 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
struct Feed {
    index: u64,
    behaviour: Behaviour,
    /// Simulated seconds between new items. `None`: dormant, never updates.
    period: Option<u64>,
    /// Offsets this feed's schedule, so feeds don't all update together.
    phase: u64,
    /// Items in the document.
    items: u64,
}

const HOUR: u64 = 3_600;
const DAY: u64 = 24 * HOUR;

impl Feed {
    fn new(seed: u64, index: u64) -> Self {
        let roll = hash(&[seed, index, 1]) % 1_000;
        let mut at = 0;
        let mut take = |n: u64| {
            at += n;
            roll < at
        };
        let behaviour = if take(BIG_PER_MILLE) {
            Behaviour::Big
        } else if take(SLOW_PER_MILLE) {
            Behaviour::Slow
        } else if take(NOT_FOUND_PER_MILLE) {
            Behaviour::NotFound
        } else if take(SERVER_ERROR_PER_MILLE) {
            Behaviour::ServerError
        } else if take(OVERSIZED_PER_MILLE) {
            Behaviour::Oversized
        } else {
            Behaviour::Normal
        };
        // Churn: 30% hourly, 40% daily, 20% weekly, 10% dormant.
        let period = match hash(&[seed, index, 2]) % 10 {
            0..=2 => Some(HOUR),
            3..=6 => Some(DAY),
            7 | 8 => Some(7 * DAY),
            _ => None,
        };
        let phase = hash(&[seed, index, 3]) % period.unwrap_or(DAY);
        let items = match behaviour {
            Behaviour::Big => 2_000,
            _ => 20 + hash(&[seed, index, 4]) % 31,
        };
        Feed {
            index,
            behaviour,
            period,
            phase,
            items,
        }
    }

    /// The newest item's number at simulated time `sim` (seconds since start).
    /// Item numbers count up from `items`, so the first document is full.
    fn latest(&self, sim: u64) -> u64 {
        match self.period {
            Some(p) => self.items + (sim + self.phase) / p,
            None => self.items,
        }
    }
}

/// The simulated clock: real time since start, scaled.
#[derive(Clone, Copy, Debug)]
struct Clock {
    start: DateTime<Utc>,
    scale: f64,
}

impl Clock {
    fn sim_secs(&self, now: DateTime<Utc>) -> u64 {
        let real = (now - self.start).num_milliseconds().max(0) as f64 / 1_000.0;
        (real * self.scale) as u64
    }

    /// The real time at which simulated second `sim` falls. May be before
    /// start, for the backlog the first document carries.
    fn real_at(&self, sim: i64) -> DateTime<Utc> {
        self.start + chrono::Duration::milliseconds(((sim as f64 / self.scale) * 1_000.0) as i64)
    }

    /// When item `k` of `feed` was published, in real time.
    fn published(&self, feed: &Feed, k: u64) -> DateTime<Utc> {
        let period = feed.period.unwrap_or(DAY) as i64;
        // Item `latest(0)` is published at or just before start.
        let newest_at_start = feed.latest(0) as i64;
        let offset = (k as i64 - newest_at_start) * period - (feed.phase as i64 % period);
        self.real_at(offset)
    }
}

/// Words for article text. Ordinary prose, so the sanitizer's work is ordinary.
const WORDS: &[&str] = &[
    "the", "reader", "feed", "morning", "river", "station", "quiet", "account", "season", "garden",
    "letter", "market", "window", "harbour", "practice", "number", "evening", "bridge", "library",
    "weather", "kitchen", "journey", "signal", "pattern", "notes", "between", "against", "because",
    "although", "whenever", "careful", "simple", "early",
];

/// An article body of `bytes` bytes (roughly), as HTML.
fn article(seed: u64, feed: u64, k: u64, bytes: usize) -> String {
    let mut out = String::with_capacity(bytes + 256);
    let mut n = 0u64;
    while out.len() < bytes {
        out.push_str("<p>");
        let sentence_len = 40 + hash(&[seed, feed, k, n, 9]) % 80;
        for w in 0..sentence_len {
            let word = WORDS[(hash(&[seed, feed, k, n, w]) % WORDS.len() as u64) as usize];
            match hash(&[seed, feed, k, n, w, 7]) % 40 {
                0 => {
                    let _ = write!(
                        out,
                        "<a href=\"https://example.com/{feed}/{k}/{n}\">{word}</a> "
                    );
                }
                1 => {
                    let _ = write!(out, "<em>{word}</em> ");
                }
                _ => {
                    out.push_str(word);
                    out.push(' ');
                }
            }
        }
        out.push_str("</p>\n");
        if n % 6 == 3 {
            let _ = writeln!(
                out,
                "<p><img src=\"https://example.com/img/{feed}/{k}/{n}.png\" alt=\"figure {n}\"></p>"
            );
        }
        n += 1;
    }
    out
}

/// An ordinary item's body size: 6–18 KB, mean ~12 KB, matching the stored
/// bodies measured in production (mean 11.9 KB, p99 17.5 KB).
fn body_bytes(seed: u64, feed: u64, k: u64) -> usize {
    let u: f64 = (0..3)
        .map(|j| unit(hash(&[seed, feed, k, 100 + j])))
        .sum::<f64>()
        / 3.0;
    6_000 + (u * 12_000.0) as usize
}

fn http_date(t: DateTime<Utc>) -> String {
    t.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// The RSS document for `feed` at simulated time `sim`.
fn render(seed: u64, clock: &Clock, feed: &Feed, sim: u64) -> String {
    let latest = feed.latest(sim);
    let first = latest + 1 - feed.items;
    let mut out = String::with_capacity(64 * 1024);
    let _ = write!(
        out,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rss version=\"2.0\"><channel>\
         <title>Synthetic feed {i}</title><link>https://synth.example/{i}</link>\
         <description>Capacity bench feed {i}</description>\
         <lastBuildDate>{date}</lastBuildDate>\n",
        i = feed.index,
        date = clock.published(feed, latest).to_rfc2822(),
    );
    for k in (first..=latest).rev() {
        let body = match feed.behaviour {
            Behaviour::Big => {
                // Short show-notes-style items: 2,000 x ~1.5 KB.
                article(seed, feed.index, k, 1_200)
            }
            _ => article(seed, feed.index, k, body_bytes(seed, feed.index, k)),
        };
        let _ = writeln!(
            out,
            "<item><title>Item {k} of feed {i}</title>\
             <link>https://synth.example/{i}/{k}</link>\
             <guid isPermaLink=\"false\">synth-{i}-{k}</guid>\
             <pubDate>{date}</pubDate>\
             <description><![CDATA[{body}]]></description></item>",
            i = feed.index,
            date = clock.published(feed, k).to_rfc2822(),
        );
    }
    out.push_str("</channel></rss>\n");
    out
}

/// What was served, since start.
#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    ok: AtomicU64,
    not_modified: AtomicU64,
    errors: AtomicU64,
    bytes: AtomicU64,
}

#[derive(Clone)]
struct App {
    config: Arc<Config>,
    clock: Clock,
    counters: Arc<Counters>,
}

fn router(app: App) -> Router {
    Router::new()
        .route("/f/{file}", get(serve_feed))
        .route("/stats", get(stats))
        .route("/health", get(|| async { "ok synthfeeds" }))
        .with_state(app)
}

async fn serve_feed(
    State(app): State<App>,
    Path(file): Path<String>,
    headers: HeaderMap,
) -> Response {
    let c = &app.counters;
    c.requests.fetch_add(1, Relaxed);
    let Some(index) = file
        .strip_suffix(".xml")
        .and_then(|i| i.parse::<u64>().ok())
    else {
        c.errors.fetch_add(1, Relaxed);
        return StatusCode::NOT_FOUND.into_response();
    };
    if index >= app.config.feeds {
        c.errors.fetch_add(1, Relaxed);
        return StatusCode::NOT_FOUND.into_response();
    }
    let seed = app.config.seed;
    let feed = Feed::new(seed, index);
    match feed.behaviour {
        Behaviour::NotFound => {
            c.errors.fetch_add(1, Relaxed);
            return StatusCode::NOT_FOUND.into_response();
        }
        Behaviour::ServerError => {
            c.errors.fetch_add(1, Relaxed);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Behaviour::Slow => {
            let ms = 3_000 + hash(&[seed, index, 5]) % 5_000;
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        Behaviour::Oversized => {
            c.ok.fetch_add(1, Relaxed);
            c.bytes.fetch_add(OVERSIZED_BYTES as u64, Relaxed);
            let body = format!(
                "<?xml version=\"1.0\"?><rss version=\"2.0\"><channel><title>big</title>{}",
                " ".repeat(OVERSIZED_BYTES)
            );
            return ([(header::CONTENT_TYPE, "application/rss+xml")], body).into_response();
        }
        Behaviour::Normal | Behaviour::Big => {}
    }

    let sim = app.clock.sim_secs(Utc::now());
    let latest = feed.latest(sim);
    let etag = format!("\"{seed}-{index}-{latest}\"");
    let last_modified = http_date(app.clock.published(&feed, latest));
    let fresh = match headers.get(header::IF_NONE_MATCH) {
        Some(v) => v.to_str().is_ok_and(|v| v == etag),
        None => headers
            .get(header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == last_modified),
    };
    if fresh {
        c.not_modified.fetch_add(1, Relaxed);
        return (
            StatusCode::NOT_MODIFIED,
            [(header::ETAG, etag), (header::LAST_MODIFIED, last_modified)],
        )
            .into_response();
    }
    let body = render(seed, &app.clock, &feed, sim);
    c.ok.fetch_add(1, Relaxed);
    c.bytes.fetch_add(body.len() as u64, Relaxed);
    (
        [
            (header::CONTENT_TYPE, "application/rss+xml".to_string()),
            (header::ETAG, etag),
            (header::LAST_MODIFIED, last_modified),
        ],
        body,
    )
        .into_response()
}

async fn stats(State(app): State<App>) -> Json<serde_json::Value> {
    let c = &app.counters;
    let now = Utc::now();
    Json(serde_json::json!({
        "feeds": app.config.feeds,
        "seed": app.config.seed,
        "time_scale": app.config.time_scale,
        "started": app.clock.start.to_rfc3339(),
        "sim_secs": app.clock.sim_secs(now),
        "requests": c.requests.load(Relaxed),
        "ok": c.ok.load(Relaxed),
        "not_modified": c.not_modified.load(Relaxed),
        "errors": c.errors.load(Relaxed),
        "bytes": c.bytes.load(Relaxed),
    }))
}

/// SQL registering feeds `0..n` at `base`, with first polls spread evenly over
/// `spread_secs` from now (FeatherReader makes every never-polled row due at
/// once otherwise, which is a burst no real instance sees).
///
/// **A row that already exists is reset, not skipped** (found in review): its
/// schedule, error count and validators go back to a fresh feed's, so a
/// re-seed for the next size doesn't inherit past-due rows and backoff from
/// the last run. Its stored entries stay; restore the snapshot between sizes
/// for a clean database (bench/README.md).
fn seed_sql(base: &str, n: u64, spread_secs: u64, now: DateTime<Utc>) -> String {
    let base = base.trim_end_matches('/');
    let mut out = String::from("BEGIN;\n");
    for i in 0..n {
        let at = now + chrono::Duration::seconds((i * spread_secs / n.max(1)) as i64);
        let _ = writeln!(
            out,
            "INSERT INTO feeds (url, kind, next_poll) VALUES ('{base}/f/{i}.xml', 'rss', '{}') \
             ON CONFLICT (url) DO UPDATE SET next_poll = excluded.next_poll, \
             consecutive_errors = 0, last_error_kind = NULL, last_error = NULL, \
             etag = NULL, last_modified = NULL;",
            at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        );
    }
    out.push_str("COMMIT;\n");
    out
}

/// Ctrl-C, or SIGTERM: in the container this is PID 1 with no init, and a
/// PID 1 without a handler ignores the SIGTERM `docker stop` sends, so every
/// stop waited out the timeout and was killed (found in review).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  synthfeeds                      serve (SYNTH_FEEDS, SYNTH_SEED, SYNTH_TIME_SCALE, SYNTH_BIND)\n  \
         synthfeeds seed BASE_URL N SPREAD_SECS   print SQL registering N feeds"
    );
    std::process::exit(2)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => {}
        Some("seed") => {
            let [_, base, n, spread] = args.as_slice() else {
                usage()
            };
            if !(base.starts_with("https://") || base.starts_with("http://")) || base.contains('\'')
            {
                bail!("BASE_URL must be an http(s) URL without quotes");
            }
            let n: u64 = n.parse().context("N")?;
            let spread: u64 = spread.parse().context("SPREAD_SECS")?;
            print!("{}", seed_sql(base, n, spread, Utc::now()));
            return Ok(());
        }
        Some(_) => usage(),
    }

    let config = Config::from_env()?;
    let app = App {
        clock: Clock {
            start: Utc::now(),
            scale: config.time_scale,
        },
        config: Arc::new(config.clone()),
        counters: Arc::default(),
    };
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("binding {}", config.bind))?;
    eprintln!(
        "synthfeeds: {} feeds, seed {}, time x{}, on {}",
        config.feeds, config.seed, config.time_scale, config.bind
    );
    axum::serve(listener, router(app))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use chrono::TimeZone;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app(feeds: u64, scale: f64) -> App {
        App {
            config: Arc::new(Config {
                feeds,
                seed: 263,
                time_scale: scale,
                bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            }),
            clock: Clock {
                start: Utc.with_ymd_and_hms(2026, 10, 18, 0, 0, 0).unwrap(),
                scale,
            },
            counters: Arc::default(),
        }
    }

    fn first_normal(seed: u64) -> u64 {
        (0..)
            .find(|&i| {
                Feed::new(seed, i).behaviour == Behaviour::Normal
                    && Feed::new(seed, i).period == Some(HOUR)
            })
            .unwrap()
    }

    /// The same inputs serve the same bytes: runs are repeatable.
    #[test]
    fn rendering_is_deterministic() {
        let a = app(10, 1.0);
        let f = Feed::new(263, 3);
        assert_eq!(
            render(263, &a.clock, &f, 5_000),
            render(263, &a.clock, &f, 5_000)
        );
    }

    /// The mix of behaviours lands near the configured shares.
    #[test]
    fn behaviour_shares_match_the_configuration() {
        let n = 100_000;
        let count = |b: Behaviour| {
            (0..n).filter(|&i| Feed::new(263, i).behaviour == b).count() as f64 / n as f64 * 1_000.0
        };
        for (b, want) in [
            (Behaviour::Big, BIG_PER_MILLE),
            (Behaviour::Slow, SLOW_PER_MILLE),
            (Behaviour::NotFound, NOT_FOUND_PER_MILLE),
            (Behaviour::ServerError, SERVER_ERROR_PER_MILLE),
            (Behaviour::Oversized, OVERSIZED_PER_MILLE),
        ] {
            let got = count(b);
            assert!(
                (got - want as f64).abs() < 2.0,
                "{b:?}: {got} per mille, want {want}"
            );
        }
    }

    /// Ordinary bodies match production's measured size: mean ~12 KB, all
    /// within 6–18 KB.
    #[test]
    fn body_sizes_match_production() {
        let sizes: Vec<usize> = (0..2_000)
            .map(|k| article(263, 1, k, body_bytes(263, 1, k)).len())
            .collect();
        let mean = sizes.iter().sum::<usize>() as f64 / sizes.len() as f64;
        assert!((10_500.0..13_500.0).contains(&mean), "mean {mean}");
        assert!(
            sizes.iter().all(|&s| (6_000..19_000).contains(&s)),
            "out of range"
        );
    }

    /// A document holds `items` items, newest first, and a feed's newest item
    /// advances with its period.
    #[test]
    fn churn_adds_items_on_schedule() {
        let a = app(10, 1.0);
        let i = first_normal(263);
        let f = Feed::new(263, i);
        let doc = render(263, &a.clock, &f, 0);
        assert_eq!(doc.matches("<item>").count() as u64, f.items);
        assert_eq!(f.latest(HOUR) - f.latest(0), 1);
        assert_eq!(f.latest(10 * HOUR) - f.latest(0), 10);
        let dormant = (0..)
            .map(|i| Feed::new(263, i))
            .find(|f| f.period.is_none())
            .unwrap();
        assert_eq!(dormant.latest(30 * DAY), dormant.latest(0));
    }

    async fn get(app: &App, path: &str, etag: Option<&str>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut req = Request::get(path);
        if let Some(e) = etag {
            req = req.header(header::IF_NONE_MATCH, e);
        }
        let resp = router(app.clone())
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        (
            parts.status,
            parts.headers,
            body.collect().await.unwrap().to_bytes().to_vec(),
        )
    }

    /// A conditional GET with the current ETag is a 304; the counters see both.
    #[tokio::test]
    async fn conditional_get_answers_304() {
        let a = app(1_000, 1.0);
        let path = format!("/f/{}.xml", first_normal(263));
        let (status, headers, body) = get(&a, &path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with(b"<?xml"));
        let etag = headers[header::ETAG].to_str().unwrap().to_string();
        let (status, _, body) = get(&a, &path, Some(&etag)).await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);
        assert!(body.is_empty());
        assert_eq!(a.counters.ok.load(Relaxed), 1);
        assert_eq!(a.counters.not_modified.load(Relaxed), 1);
    }

    /// Misbehaving feeds misbehave, and paths outside the set are 404s.
    #[tokio::test]
    async fn misbehaving_feeds_and_unknown_paths() {
        let a = app(10_000, 1.0);
        let find = |b: Behaviour| {
            (0..10_000)
                .find(|&i| Feed::new(263, i).behaviour == b)
                .unwrap()
        };
        let (s, _, _) = get(&a, &format!("/f/{}.xml", find(Behaviour::NotFound)), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _, _) = get(
            &a,
            &format!("/f/{}.xml", find(Behaviour::ServerError)),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
        let (s, _, body) = get(&a, &format!("/f/{}.xml", find(Behaviour::Oversized)), None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(body.len() > 8 * 1024 * 1024);
        for path in ["/f/10000.xml", "/f/x.xml", "/f/1"] {
            assert_eq!(get(&a, path, None).await.0, StatusCode::NOT_FOUND, "{path}");
        }
    }

    /// **The documents parse with the parser FeatherReader uses** (feed-rs, the
    /// app's version), with every item's guid, date and body intact: a bench
    /// whose feeds the app rejects would measure parse failures.
    #[test]
    fn documents_parse_with_the_apps_parser() {
        let a = app(10_000, 1.0);
        for b in [Behaviour::Normal, Behaviour::Big] {
            let i = (0..10_000)
                .find(|&i| Feed::new(263, i).behaviour == b)
                .unwrap();
            let f = Feed::new(263, i);
            let doc = render(263, &a.clock, &f, 7 * DAY);
            let parsed = feed_rs::parser::parse(doc.as_bytes()).expect("parse");
            assert_eq!(parsed.entries.len() as u64, f.items, "{b:?}");
            for e in &parsed.entries {
                assert!(
                    e.id.starts_with(&format!("synth-{i}-")),
                    "{b:?} guid {}",
                    e.id
                );
                assert!(e.published.is_some(), "{b:?} {} has no date", e.id);
                let body = e.summary.as_ref().map_or(0, |t| t.content.len());
                assert!(body > 1_000, "{b:?} {} body {body}", e.id);
            }
            if b == Behaviour::Big {
                assert!(
                    (2_000_000..6_000_000).contains(&doc.len()),
                    "big feed {} bytes",
                    doc.len()
                );
            }
        }
    }

    /// The seed SQL registers every feed once, spread over the window.
    #[test]
    fn seed_sql_spreads_first_polls() {
        let now = Utc.with_ymd_and_hms(2026, 10, 18, 0, 0, 0).unwrap();
        let sql = seed_sql("https://synth.example/", 4, 3_600, now);
        assert_eq!(sql.matches("INSERT INTO feeds").count(), 4);
        assert_eq!(sql.matches("ON CONFLICT (url) DO UPDATE").count(), 4);
        assert!(sql.contains("'https://synth.example/f/0.xml', 'rss', '2026-10-18T00:00:00Z'"));
        assert!(sql.contains("'https://synth.example/f/3.xml', 'rss', '2026-10-18T00:45:00Z'"));
    }
}
