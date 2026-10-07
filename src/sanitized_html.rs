//! The reader view's article body.
//!
//! **This is its own module because of the private field**, for the reason
//! `safe_link.rs` gives: a private field is private to the MODULE, so a type
//! declared in `web.rs` could be built beside its own constructor there and the
//! guarantee would be a convention again.
//!
//! Two things live here. [`SanitizedHtml`] is the type: markup that has been
//! through the ingest sanitizer in this process. [`BodyRenderer`] is the path a
//! stored body takes to become one at render, with the three bounds that keep
//! a pathological row from costing more than its own page view: a size cap, a
//! concurrency limit and a cache.
//!
//! **Why bounds, and why these.** Real bodies re-clean cheaply: on 545 real
//! bodies from 20 public feeds, p50 31 µs, p99 1.1 ms, max 3.5 ms (a 561 KB
//! body). But the sanitizer is quadratic on shapes any feed can serve, and
//! **ingest can store them** (#226, fixed separately): a stored 2 MiB body of
//! nested `<div>`s takes ~37 s to re-clean, a 2 MiB `&` run 2.4 s, a U+00A0
//! run 3.4 s. Such rows may already exist in databases upgraded from ≤ 0.4.6,
//! and until #226's fix lands any feed can add one; after it, bodies that
//! sanitize under its timeout can still be slow here. So nothing here assumes
//! a stored body is fast. The bounds cap what one slow body can cost
//! everyone else: it is cleaned at most once per process (cache + single
//! flight), holding one of two permits, so a second such body can be in the
//! sanitizer at the same time and no more; other readers' uncached bodies
//! wait up to two seconds for a permit and then get a "temporarily
//! unavailable" note instead of a hung page. The slow body's own readers pay
//! its full cost, once.
//!
//! An earlier version of this module tried to *predict* the cost with a scan
//! that re-implemented html5ever's tree-construction rules in front of
//! html5ever; three review rounds each found a mismatch, and the last found
//! the scan cutting real articles (`li` in `li` after a stripped `<section>`,
//! a 245 KB `<pre>` XML listing, `<rt>` inside a `<span>` in `<ruby>`). The
//! bounds here predict nothing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::{watch, Semaphore};
use tracing::warn;

/// Article-body HTML that has been through the sanitizer **in this process**
/// — and so can be emitted into a page without escaping.
///
/// **Why it exists (#151).** `entries.content_html` reached `entry.html` as a
/// raw `Option<String>` rendered with `|safe` — the one expression in the
/// reader that bypassed Askama's escaper. Its safety was ingest's `ammonia`
/// pass in `feed.rs`, on a different code path, holding only while every
/// future writer to the column remembered to go through it. That is the same
/// procedural guard `SafeLink` replaced for the entry's `href`s.
///
/// **The guarantee cannot ride through storage.** The column is SQLite `TEXT`,
/// so a type set at ingest means nothing by the time a row is read back. It is
/// re-established at render instead: the only constructor runs the ingest
/// sanitizer, `feed::sanitize_html`, over whatever the row holds. A newtype
/// that wrapped the stored string without cleaning it was rejected in the
/// issue as a guarantee in name only.
///
/// - **One policy.** It calls ingest's function rather than holding its own
///   `ammonia` builder, so ingest and render cannot drift; a test pins them
///   byte for byte.
/// - **No change for readers.** Sanitizer output is a fixed point of the
///   sanitizer, so a body ingest stored comes back byte-identical (all 545
///   real bodies measured). Two known exceptions, both the same page to a
///   browser: a literal U+00A0 in a standard.site plain-text summary comes
///   back as `&nbsp;`, and a table whose `<tfoot>` the policy stripped gains
///   the `<tbody>` a browser would build around those rows anyway.
/// - **Bounded blast radius.** Not here: in [`BodyRenderer`], which is how the
///   reader's handler gets one of these from a stored row.
///
/// There is no `From<String>`, no `Deref`, and no public field. A raw string
/// does not become one — not by struct literal (E0451, private field):
///
/// ```compile_fail,E0451
/// use feather_reader::sanitized_html::SanitizedHtml;
/// let _ = SanitizedHtml { html: String::from("<script>alert(1)</script>") };
/// ```
///
/// and not by conversion (E0277, no `From`):
///
/// ```compile_fail,E0277
/// use feather_reader::sanitized_html::SanitizedHtml;
/// let _: SanitizedHtml = String::from("<script>alert(1)</script>").into();
/// ```
///
/// Only through the cleaning constructor:
///
/// ```
/// use feather_reader::sanitized_html::SanitizedHtml;
/// let html = SanitizedHtml::clean("<p>hi</p><script>alert(1)</script>");
/// assert_eq!(html.as_str(), "<p>hi</p>");
/// ```
pub struct SanitizedHtml {
    html: String,
}

impl SanitizedHtml {
    /// Sanitize `raw` with the ingest policy. The only way to make one.
    ///
    /// Blocks for as long as the sanitizer runs, on the whole of `raw`: on an
    /// async task use [`SanitizedHtml::clean_off_runtime`], and for a stored
    /// body use [`BodyRenderer`], which also applies the bounds.
    pub fn clean(raw: &str) -> Self {
        Self {
            html: crate::feed::sanitize_html(raw),
        }
    }

    /// [`SanitizedHtml::clean`] on tokio's blocking pool, so a slow clean
    /// stalls no other request sharing the async worker. This does not make
    /// the clean cheaper or bound it; [`BodyRenderer`] does that.
    pub async fn clean_off_runtime(raw: String) -> anyhow::Result<Self> {
        tokio::task::spawn_blocking(move || Self::clean(&raw))
            .await
            .map_err(|e| anyhow::anyhow!("sanitizing an entry body failed: {e}"))
    }

    /// The cleaned markup.
    pub fn as_str(&self) -> &str {
        &self.html
    }
}

impl std::fmt::Display for SanitizedHtml {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.html)
    }
}

impl askama::filters::HtmlSafe for SanitizedHtml {}

/// What the reader gets back for a stored body: the markup, or one of two
/// reasons it is not shown. Both reasons are notes in `entry.html` pointing
/// at the original.
pub enum BodyRender {
    /// Cleaned and ready to emit.
    Html(SanitizedHtml),
    /// The stored body is longer than [`MAX_RENDER_HTML_BYTES`], which ingest
    /// never writes. It was not given to the sanitizer at all.
    TooLarge,
    /// Every sanitizer permit stayed busy for [`RENDER_WAIT`] — only while
    /// [`RENDER_PERMITS`] slow bodies are being cleaned at once, each for the
    /// first time this process. The reader can retry; by then the slow ones
    /// are cached.
    Unavailable,
    /// The body was cleaned once this process and was slow to clean
    /// (`SLOW_CLEAN`, 500 ms); it has since left the cache, and render does not
    /// clean it again — that would put a slow clean on every view of it.
    TooSlow,
}

/// The longest stored body render will sanitize: ingest's own stored bound
/// (`feed::MAX_CONTENT_HTML_BYTES`), so no body ingest wrote is ever refused.
/// Only a row that skipped `feed.rs`, or one from before the bound existed
/// (#224), can be longer, and such a row is not given to the sanitizer at all.
pub const MAX_RENDER_HTML_BYTES: usize = crate::feed::MAX_CONTENT_HTML_BYTES;

/// How many stored bodies may be in the sanitizer at once, process-wide.
///
/// Normal content never contends for these: a real clean takes microseconds
/// to a few milliseconds. The limit exists for the pathological row (~37 s
/// for 2 MiB of nested `<div>`s), which can occupy at most one permit per
/// page view of it, and so at most this many blocking-pool threads and CPU
/// cores in total. One would let a single slow row stall every other uncached
/// view for its whole duration; two keeps one lane open past one slow row,
/// which is the most this path should ever spend.
pub const RENDER_PERMITS: usize = 2;

/// How long a page view waits for a sanitizer permit before showing the
/// "temporarily unavailable" note instead of the body.
///
/// Real cleans finish in ≤ 3.5 ms, so a queue of real work drains in well
/// under this; a wait this long means every permit is held by a pathological
/// body, and the reader is better served by the note and the link to the
/// original than by a page that hangs for the rest of a 37 s clean. The wait
/// itself is async (`Semaphore::acquire`) and never occupies a worker thread.
pub const RENDER_WAIT: Duration = Duration::from_secs(2);

/// The most cleaned markup the render cache holds, in bytes of output.
///
/// Typical bodies are small (p50 4.4 KB, p99 132 KB), so [`CACHE_MAX_ENTRIES`]
/// usually binds first and this is a ceiling on memory for a reader of large
/// articles: at least four bodies of the maximum stored size fit, and a body
/// whose cleaned form alone exceeds it is simply not cached.
pub const CACHE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// The most bodies the render cache holds. A reader paging through a list
/// re-views far fewer than this before anything is evicted.
pub const CACHE_MAX_ENTRIES: usize = 256;

/// A clean slower than this is logged with the body's size and hash, so the
/// row — a hostile feed's body (#226), or one written some other way — can be
/// found.
const SLOW_CLEAN: Duration = Duration::from_millis(500);

/// How many slow bodies render remembers (`SlowSet`). 32 bytes each, so
/// 128 KiB at most; far more slow bodies than any instance should ever hold.
pub const SLOW_KEYS_MAX: usize = 4096;

/// The bodies whose clean took longer than [`SLOW_CLEAN`], by hash, oldest
/// out first. **Separate from the output cache on purpose:** the cache evicts
/// by bytes and age, so a handful of slow ~2 MiB bodies viewed in turn would
/// push each other out and re-run a ~37 s clean on every view. A body in this
/// set is cleaned at most once per process however the cache churns; after
/// its result leaves the cache it renders as [`BodyRender::TooSlow`].
struct SlowSet {
    keys: std::collections::HashSet<Key>,
    order: std::collections::VecDeque<Key>,
}

impl SlowSet {
    fn new() -> Self {
        Self {
            keys: std::collections::HashSet::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    fn contains(&self, key: &Key) -> bool {
        self.keys.contains(key)
    }

    fn insert(&mut self, key: Key) {
        if !self.keys.insert(key) {
            return;
        }
        self.order.push_back(key);
        while self.order.len() > SLOW_KEYS_MAX {
            if let Some(old) = self.order.pop_front() {
                self.keys.remove(&old);
            }
        }
    }
}

/// SHA-256 of the stored body: the cache key.
///
/// **A strong hash, not a fast one.** A collision here would serve one
/// entry's markup for another's, so a fast non-cryptographic hash (whose
/// collisions a hostile feed can manufacture) is not an option. `ring` is
/// already a direct dependency.
type Key = [u8; 32];

fn key_of(raw: &str) -> Key {
    let digest = ring::digest::digest(&ring::digest::SHA256, raw.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(digest.as_ref());
    key
}

/// Cleaned output, keyed by the hash of the stored body, least recently
/// used out first, bounded in entries and in bytes of output.
///
/// Small enough (≤ [`CACHE_MAX_ENTRIES`]) that eviction is a scan for the
/// oldest, which costs less than hashing the key did.
struct Cache {
    max_bytes: usize,
    max_entries: usize,
    bytes: usize,
    tick: u64,
    slots: HashMap<Key, Slot>,
}

struct Slot {
    html: Arc<str>,
    last_used: u64,
}

impl Cache {
    fn new(max_bytes: usize, max_entries: usize) -> Self {
        Self {
            max_bytes,
            max_entries,
            bytes: 0,
            tick: 0,
            slots: HashMap::new(),
        }
    }

    fn get(&mut self, key: &Key) -> Option<Arc<str>> {
        self.tick += 1;
        let slot = self.slots.get_mut(key)?;
        slot.last_used = self.tick;
        Some(Arc::clone(&slot.html))
    }

    fn insert(&mut self, key: Key, html: Arc<str>) {
        if html.len() > self.max_bytes || self.max_entries == 0 {
            return;
        }
        if let Some(old) = self.slots.remove(&key) {
            self.bytes -= old.html.len();
        }
        while !self.slots.is_empty()
            && (self.slots.len() >= self.max_entries || self.bytes + html.len() > self.max_bytes)
        {
            let Some(oldest) = self
                .slots
                .iter()
                .min_by_key(|(_, s)| s.last_used)
                .map(|(k, _)| *k)
            else {
                break;
            };
            if let Some(gone) = self.slots.remove(&oldest) {
                self.bytes -= gone.html.len();
            }
        }
        self.tick += 1;
        self.bytes += html.len();
        self.slots.insert(
            key,
            Slot {
                html,
                last_used: self.tick,
            },
        );
    }
}

/// What one in-flight clean produced, broadcast to everyone who asked for the
/// same body while it ran.
#[derive(Clone)]
enum Outcome {
    Html(Arc<str>),
    Unavailable,
}

/// The in-flight cleans, by body hash: a receiver that resolves when the
/// leader finishes. Joiners clone the receiver and wait; they take no permit.
type InFlight = HashMap<Key, watch::Receiver<Option<Outcome>>>;

struct Inner {
    permits: Arc<Semaphore>,
    wait: Duration,
    cache: Mutex<Cache>,
    in_flight: Mutex<InFlight>,
    /// Bodies already cleaned slowly once this process ([`SlowSet`]).
    slow_keys: Mutex<SlowSet>,
    /// A clean slower than this marks the body slow ([`SLOW_CLEAN`]; tests
    /// lower it).
    slow: Duration,
    /// Test-only: runs between the cache lookup and the in-flight check.
    #[cfg(test)]
    after_lookup: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// How many times the sanitizer has run through this renderer. Tests use
    /// it to show the cap, the cache and single flight keep it from running.
    cleans: AtomicUsize,
}

/// The path from a stored `content_html` row to a [`BodyRender`], with the
/// three bounds. One process-wide instance, [`BodyRenderer::shared`], serves
/// the reader; tests build their own with smaller parameters.
///
/// For a body of `n` bytes a render costs, in order:
/// 1. nothing but a length check if `n` > [`MAX_RENDER_HTML_BYTES`]
///    ([`BodyRender::TooLarge`]);
/// 2. a SHA-256 of the body and a cache lookup, on the blocking pool;
/// 3. on a miss, **single flight**: if the same body is already being
///    cleaned, this request waits for that result and takes no permit;
///    otherwise it becomes the leader and spawns the clean as its own task,
///    so a requester that disconnects neither cancels the clean nor leaves
///    anyone waiting on a leader that is gone;
/// 4. the leader waits up to [`RENDER_WAIT`] for one of [`RENDER_PERMITS`]
///    permits ([`BodyRender::Unavailable`] for everyone waiting if none
///    comes), then cleans on the blocking pool holding the permit, caches the
///    result and publishes it.
///
/// So each distinct body is cleaned at most once at a time; a fast body again
/// only after it leaves the cache; and a body that was slow to clean
/// (`SLOW_CLEAN`, 500 ms) at most once per process — after its result leaves the
/// cache it renders as [`BodyRender::TooSlow`] instead (`SlowSet`). A slow
/// body therefore costs one clean, holding one permit, per process. The
/// async worker is never blocked: the hash, the lookup and the clean run on
/// the blocking pool, and every wait is an async one.
///
/// **What these bounds are for.** A stored body may be slow to re-clean:
/// ingest can store one (#226; real bodies p50 31 µs, max 3.5 ms, but a
/// hostile feed's 2 MiB of nested `<div>`s re-cleans in ~37 s, a `&` run in
/// 2.4 s), and such rows may already exist in databases upgraded from
/// ≤ 0.4.6. The bounds here cap what such a row can cost other readers: it is
/// cleaned once per process, holding one of two permits, and everyone else's
/// uncached body waits at most [`RENDER_WAIT`] before a note. They do not
/// predict or reduce its own cost.
#[derive(Clone)]
pub struct BodyRenderer(Arc<Inner>);

/// Removes an in-flight entry when the leader's task ends, however it ends —
/// result published, `Unavailable`, or a panic in the sanitizer — so a key
/// can never stay in flight with no one working on it.
struct InFlightGuard {
    inner: Arc<Inner>,
    key: Key,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.inner.in_flight().remove(&self.key);
    }
}

impl BodyRenderer {
    /// A renderer with its own permits and cache. The reader uses
    /// [`BodyRenderer::shared`]; this is for tests and for the shared
    /// instance's construction.
    pub fn new(permits: usize, wait: Duration, cache_bytes: usize, cache_entries: usize) -> Self {
        Self(Arc::new(Inner {
            permits: Arc::new(Semaphore::new(permits)),
            wait,
            cache: Mutex::new(Cache::new(cache_bytes, cache_entries)),
            in_flight: Mutex::new(HashMap::new()),
            slow_keys: Mutex::new(SlowSet::new()),
            slow: SLOW_CLEAN,
            #[cfg(test)]
            after_lookup: Mutex::new(None),
            cleans: AtomicUsize::new(0),
        }))
    }

    /// This renderer, with a different slow-clean threshold. Tests only:
    /// the inner state must not be shared yet.
    #[cfg(test)]
    fn with_slow_threshold(mut self, slow: Duration) -> Self {
        Arc::get_mut(&mut self.0)
            .expect("set the slow threshold before sharing the renderer")
            .slow = slow;
        self
    }

    /// Run `hook` between the cache lookup and the in-flight check.
    #[cfg(test)]
    fn set_after_lookup(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self
            .0
            .after_lookup
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(hook));
    }

    /// The process-wide renderer, with [`RENDER_PERMITS`], [`RENDER_WAIT`],
    /// [`CACHE_MAX_BYTES`] and [`CACHE_MAX_ENTRIES`].
    pub fn shared() -> &'static BodyRenderer {
        static SHARED: LazyLock<BodyRenderer> = LazyLock::new(|| {
            BodyRenderer::new(
                RENDER_PERMITS,
                RENDER_WAIT,
                CACHE_MAX_BYTES,
                CACHE_MAX_ENTRIES,
            )
        });
        &SHARED
    }

    /// A stored body, cleaned for this render — or the reason it is not.
    ///
    /// `Err` only if the blocking pool failed to run the task (a panic in the
    /// sanitizer, or runtime shutdown); the two bounded outcomes are values.
    pub async fn render(&self, raw: String) -> anyhow::Result<BodyRender> {
        if raw.len() > MAX_RENDER_HTML_BYTES {
            warn!(
                bytes = raw.len(),
                bound = MAX_RENDER_HTML_BYTES,
                "stored entry body is over the ingest bound; not rendering it"
            );
            return Ok(BodyRender::TooLarge);
        }

        // Hash and look up off the runtime: SHA-256 of a 2 MiB body is
        // milliseconds, which is more than an async worker should spend.
        let inner = Arc::clone(&self.0);
        let (raw, key, hit) = tokio::task::spawn_blocking(move || {
            let key = key_of(&raw);
            let hit = inner.cache().get(&key);
            (raw, key, hit)
        })
        .await
        .map_err(|e| anyhow::anyhow!("looking up an entry body failed: {e}"))?;
        if let Some(html) = hit {
            return Ok(BodyRender::Html(SanitizedHtml {
                html: html.to_string(),
            }));
        }
        #[cfg(test)]
        if let Some(hook) = self
            .0
            .after_lookup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            hook();
        }

        // Join the clean already in flight for this body, or lead one. The
        // map is checked and the entry inserted under one lock, so two misses
        // for the same key cannot both lead. Under that lock, in this order:
        // 1. the cache again — a leader may have finished between the lookup
        //    above and here (it caches before it leaves the in-flight table),
        //    and starting a second clean of a body just cleaned is the cost
        //    single flight exists to avoid;
        // 2. a clean in flight — join it. Checked before the slow set because
        //    a leader marks its body slow before it publishes, and its
        //    joiners should get that result, not a refusal;
        // 3. the slow set — cleaned slowly once already, and out of the cache
        //    now: not again (`TooSlow`);
        // 4. otherwise lead.
        // Lock order is always in-flight, then cache or slow set; nothing
        // takes them the other way round.
        let mut rx = {
            let mut in_flight = self.0.in_flight();
            if let Some(html) = self.0.cache().get(&key) {
                return Ok(BodyRender::Html(SanitizedHtml {
                    html: html.to_string(),
                }));
            }
            match in_flight.get(&key) {
                Some(rx) => rx.clone(),
                None if self.0.slow_keys().contains(&key) => {
                    return Ok(BodyRender::TooSlow);
                }
                None => {
                    let (tx, rx) = watch::channel(None);
                    in_flight.insert(key, rx.clone());
                    // The leader's work is its own task: a requester that goes
                    // away (client disconnect) does not cancel it, and the
                    // guard inside removes the entry however the task ends.
                    tokio::spawn(Self::lead(Arc::clone(&self.0), key, raw, tx));
                    rx
                }
            }
        };
        let outcome = match rx.wait_for(|v| v.is_some()).await {
            Ok(v) => v.clone(),
            // The leader's task ended without publishing: the sanitizer
            // panicked or the runtime is shutting down.
            Err(_gone) => anyhow::bail!("sanitizing an entry body failed"),
        };
        match outcome {
            Some(Outcome::Html(html)) => Ok(BodyRender::Html(SanitizedHtml {
                html: html.to_string(),
            })),
            Some(Outcome::Unavailable) | None => Ok(BodyRender::Unavailable),
        }
    }

    /// The leader of one in-flight clean: take a permit (or give up), clean on
    /// the blocking pool, cache, publish to every joiner.
    async fn lead(inner: Arc<Inner>, key: Key, raw: String, tx: watch::Sender<Option<Outcome>>) {
        let _guard = InFlightGuard {
            inner: Arc::clone(&inner),
            key,
        };
        let permit = match tokio::time::timeout(
            inner.wait,
            Arc::clone(&inner.permits).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            // The permits closed (never: they live in a static) or the
            // wait elapsed.
            Ok(Err(_)) | Err(_) => {
                warn!(
                    bytes = raw.len(),
                    waited_ms = inner.wait.as_millis() as u64,
                    "no sanitizer permit became free; not rendering this entry body now"
                );
                let _ = tx.send(Some(Outcome::Unavailable));
                return;
            }
        };
        let work = Arc::clone(&inner);
        let cleaned = tokio::task::spawn_blocking(move || {
            // The permit is held for exactly as long as this closure runs.
            let _permit = permit;
            work.cleans.fetch_add(1, Ordering::Relaxed);
            let started = Instant::now();
            let html: Arc<str> = Arc::from(SanitizedHtml::clean(&raw).html.as_str());
            let took = started.elapsed();
            if took > work.slow {
                work.slow_keys().insert(key);
            }
            if took > SLOW_CLEAN {
                warn!(
                    bytes = raw.len(),
                    out_bytes = html.len(),
                    took_ms = took.as_millis() as u64,
                    sha256 = %hex_prefix(&key),
                    "a stored entry body was slow to sanitize (#226); cached now, so once per process"
                );
            }
            work.cache().insert(key, Arc::clone(&html));
            html
        })
        .await;
        // A join error (the sanitizer panicked) publishes nothing: the sender
        // drops with this task, and joiners see the channel close.
        if let Ok(html) = cleaned {
            let _ = tx.send(Some(Outcome::Html(html)));
        }
    }

    /// How many times this renderer has run the sanitizer.
    pub fn cleans(&self) -> usize {
        self.0.cleans.load(Ordering::Relaxed)
    }

    /// How many bodies are being cleaned right now.
    pub fn in_flight(&self) -> usize {
        self.0.in_flight().len()
    }

    /// Bodies in the cache, and the bytes of cleaned markup they hold.
    pub fn cache_size(&self) -> (usize, usize) {
        let cache = self.0.cache();
        (cache.slots.len(), cache.bytes)
    }

    /// The permit pool, so a test can hold permits and show what a render
    /// does without one.
    #[cfg(test)]
    fn permits(&self) -> Arc<Semaphore> {
        Arc::clone(&self.0.permits)
    }
}

impl Inner {
    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        // Nothing here panics while holding the lock; recovering a poisoned
        // lock rather than propagating is the right call for a cache.
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn slow_keys(&self) -> std::sync::MutexGuard<'_, SlowSet> {
        self.slow_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn in_flight(&self) -> std::sync::MutexGuard<'_, InFlight> {
        self.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// The first eight bytes of a key as hex, enough to find a row by.
fn hex_prefix(key: &Key) -> String {
    key[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::sanitize_html;

    /// Hostile bodies, each with something the sanitizer must remove.
    const HOSTILE: &[&str] = &[
        "<p>a</p><script>alert(1)</script>",
        r#"<img src="x" onerror="alert(1)">"#,
        r#"<a href="javascript:alert(1)">x</a>"#,
        r#"<a href="  JaVaScRiPt:alert(1)">x</a>"#,
        r#"<iframe src="https://evil.example/"></iframe>"#,
        r#"<p onclick="alert(1)" style="background:url(javascript:alert(1))">x</p>"#,
        "<svg><script>alert(1)</script></svg>",
        "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        r#"<form action="https://evil.example/"><input name="pw"></form>"#,
        r#"<object data="javascript:alert(1)"></object><embed src="x.swf">"#,
        r#"<meta http-equiv="refresh" content="0;url=javascript:alert(1)">"#,
        "<base href=\"https://evil.example/\"><a href=\"/x\">x</a>",
        r#"<p><img src=x onerror=alert(1)//><a href="java&#115;cript:alert(1)">x</a></p>"#,
        r#"<div onclick="alert(1)"><a href=" javascript:alert(1)" onerror="x">y</a></div>"#,
    ];

    /// **Same policy as ingest, byte for byte.** The render-time clean is not a
    /// second, independently maintained allow-list: if it were, the two would
    /// drift, and a body ingest would refuse could render, or the reverse.
    #[test]
    fn clean_is_the_ingest_sanitizer() {
        for raw in HOSTILE.iter().chain(ARTICLES) {
            assert_eq!(
                SanitizedHtml::clean(raw).as_str(),
                sanitize_html(raw),
                "render-time clean diverged from ingest on {raw:?}",
            );
        }
    }

    #[test]
    fn clean_leaves_nothing_active() {
        for raw in HOSTILE {
            let out = SanitizedHtml::clean(raw).as_str().to_ascii_lowercase();
            for needle in [
                "<script",
                "onerror",
                "onclick",
                "javascript:",
                "<iframe",
                "<style",
                "<form",
                "<input",
                "<object",
                "<embed",
                "<meta",
                "<base",
                "<svg",
                "<math",
            ] {
                assert!(!out.contains(needle), "`{needle}` survived {raw:?}: {out}");
            }
        }
    }

    /// Representative article markup, as a feed would send it — exercising what
    /// ammonia normalizes: attribute quoting and order, `rel` on links, entities
    /// (named, numeric, and the U+00A0 it re-encodes), void elements, comments,
    /// stripped tags with kept text, and code with `<` and `&`.
    const ARTICLES: &[&str] = &[
        concat!(
            "<h1>Title</h1><h2 id=x>Sub</h2>",
            "<p>Hello&nbsp;world &copy; 2026 &#8212; caf\u{e9} \u{1f600} \u{a0}nbsp-char ",
            "<a href='https://example.com/a?b=1&c=2' title=\"t\" rel=nofollow target=_blank>link</a>",
            " <strong>b</strong> <em>i</em> <code>x &lt; y &amp;&amp; z</code></p>",
            "<!-- a comment --><br><hr/>",
            "<figure><img src=\"https://example.com/i.png\" alt=\"pic\" width=\"10\" ",
            "srcset=\"https://example.com/i2.png 2x\"><figcaption>cap</figcaption></figure>",
            "<blockquote cite=\"https://example.com\"><p>quote</p></blockquote>",
            "<pre><code class=\"language-rust\">fn main() { if a < b && c > d {} }</code></pre>",
            "<ul><li>one<li>two</ul><ol start=3><li>three</ol>",
            "<table><thead><tr><th>h</th></tr></thead><tbody><tr><td>d</td></tr></tbody></table>",
            "<div class=\"wrap\"><span style=\"color:red\">styled</span></div>",
            "<p>unclosed <b>bold <i>both</p><font color=red>font</font>",
        ),
        concat!(
            "<h2>Lists, tables, ruby</h2>",
            "<ul><li><p>para in item</p><ul><li>nested <a href=\"https://e.example/\">",
            "<img src=\"https://e.example/i.png\" alt=\"\"></a></li></ul></li><li>two</li></ul>",
            "<dl><dt>term</dt><dd>def <em>emph</em></dd><dt>t2</dt><dd>d2</dd></dl>",
            "<table><caption>cap</caption><colgroup><col><col></colgroup>",
            "<thead><tr><th>a</th><th>b</th></tr></thead>",
            "<tbody><tr><td><p>cell &amp; para</p></td><td><table><tr><td>inner</td></tr></table></td></tr>",
            "</tbody></table>",
            "<p>A<ruby>\u{6f22}<rp>(</rp><rt>kan</rt><rp>)</rp></ruby> line<br>break ",
            "x<sup>2</sup> H<sub>2</sub>O <del>old</del><ins>new</ins> <abbr title=\"t\">ab</abbr> ",
            "<q>quoted</q> <kbd>Ctrl</kbd> <mark>m</mark> <time>2026</time> <s>s</s> <u>u</u></p>",
            "<hr><details><summary>more</summary><p>hidden</p></details>",
            "<blockquote><p>q1</p><blockquote><p>q2</p></blockquote></blockquote>",
            "<h3>code</h3><pre><code>a &lt;b&gt; &amp;&amp; c\n  indented</code></pre>",
            "<div><div><span><a href=\"https://e.example/\"><b><i>deep</i></b></a></span></div></div>",
        ),
        "<p>x</p>",
        "plain text with a bare < and an & and a > and \"quotes\" and 'apostrophes'",
        "",
    ];

    /// **Re-cleaning a stored body changes nothing.** What ingest stored is
    /// already `sanitize_html` output, and that output is a fixed point — so a
    /// reader sees exactly what they saw before the render-time clean existed.
    #[test]
    fn cleaning_stored_html_is_idempotent() {
        for raw in ARTICLES.iter().chain(HOSTILE) {
            let stored = sanitize_html(raw);
            assert_eq!(
                SanitizedHtml::clean(&stored).as_str(),
                stored,
                "re-cleaning the stored form of {raw:?} changed it",
            );
        }
    }

    /// **The one exception, pinned.** standard.site summaries are stored by
    /// `plain_text_to_html`, which escapes `& < >` and adds `<br>` but leaves a
    /// literal U+00A0 alone; the sanitizer's serializer writes U+00A0 as
    /// `&nbsp;`. That is the same character to a browser, so a reader sees no
    /// change — but it is not byte-identical, and this says so. Everything
    /// else in a plain-text summary survives byte for byte.
    #[test]
    fn plain_text_summaries_differ_only_in_how_u00a0_is_spelled() {
        let text = "a < b && c > d\n\"q\" 'a' caf\u{e9} \u{1f600}\nnon\u{a0}breaking";
        let stored = crate::feed::plain_text_to_html(text);
        let cleaned = SanitizedHtml::clean(&stored);
        assert_eq!(cleaned.as_str(), stored.replace('\u{a0}', "&nbsp;"));
        let without_nbsp = crate::feed::plain_text_to_html(&text.replace('\u{a0}', " "));
        assert_eq!(SanitizedHtml::clean(&without_nbsp).as_str(), without_nbsp);
    }

    /// **The second exception, found by a fixture.** The policy keeps `tr` but
    /// not `tfoot`, so a feed table with a footer is stored with its footer
    /// rows directly in `<table>`; parsing that again wraps them in a
    /// `<tbody>` — which is what a browser builds from the stored form too, so
    /// the page is the same. A second re-clean is a fixed point. (None of the
    /// 545 real bodies measured has a `<tfoot>`.)
    #[test]
    fn a_stripped_tfoot_gains_a_tbody_and_nothing_else() {
        let stored = sanitize_html(
            "<table><tbody><tr><td>a</td></tr></tbody><tfoot><tr><td>f</td></tr></tfoot></table>",
        );
        assert_eq!(
            stored,
            "<table><tbody><tr><td>a</td></tr></tbody><tr><td>f</td></tr></table>"
        );
        let out = SanitizedHtml::clean(&stored);
        assert_eq!(
            out.as_str(),
            "<table><tbody><tr><td>a</td></tr></tbody><tbody><tr><td>f</td></tr></tbody></table>"
        );
        assert_eq!(SanitizedHtml::clean(out.as_str()).as_str(), out.as_str());
    }

    /// **Review of #273, third round: shapes ingest legitimately stores must
    /// render in full.** Each `raw` here is ordinary feed markup; `stored` is
    /// exactly what ingest writes for it (`sanitize_html`), and the article
    /// continues after the shape. The render-time clean must carry the whole
    /// stored body through, with nothing cut and nothing noted:
    ///
    /// 1. ammonia strips a wrapper (`section`, `form`, `object`) that html5ever
    ///    had treated as a nesting boundary, so the stored form has `li` in
    ///    `li`, `p` in `p`, `a` in `a`, `h2` in `h1` with every closer matching;
    /// 2. an unhighlighted `<pre><code>` XML listing of ~245 KB — every `<`
    ///    stored as `&lt;` — followed by more article;
    /// 3. `<rt>` inside an inline wrapper inside `<ruby>`.
    ///
    /// Red against the pre-scan this module used to have: five of the six
    /// were cut before the sanitizer saw them.
    #[test]
    fn bodies_ingest_stores_render_in_full() {
        const REST: &str = "<p>REST-OF-ARTICLE</p>";
        let mut listing = String::new();
        let mut i = 0;
        while listing.len() < 245_000 {
            listing.push_str(&format!("&lt;item id=\"{i}\"&gt;value {i}&lt;/item&gt;\n"));
            i += 1;
        }
        let shapes = [
            (
                "li in li after a stripped section",
                format!("<ul><li>one<section><li>two</li></section></li></ul>{REST}"),
            ),
            (
                "p in p after a stripped form",
                format!("<p>a<form><p>b</p></form></p>{REST}"),
            ),
            (
                "a in a after a stripped object",
                format!(
                    r#"<a href="https://x.example/">a<object><a href="https://y.example/">b</a></object></a>{REST}"#
                ),
            ),
            (
                "heading in heading after a stripped form",
                format!("<h1>a<form><h2>b</h2></form></h1>{REST}"),
            ),
            (
                "245 KB unhighlighted XML listing",
                format!("<pre><code>{listing}</code></pre>{REST}"),
            ),
            (
                "rt in a span in ruby",
                format!("<p>A<ruby><span>\u{6f22}<rt>kan</rt></span></ruby> B</p>{REST}"),
            ),
        ];
        let mut cut = Vec::new();
        for (name, raw) in &shapes {
            let stored = sanitize_html(raw);
            assert!(
                stored.contains("REST-OF-ARTICLE"),
                "{name}: ingest itself dropped the rest; this shape tests nothing"
            );
            let out = SanitizedHtml::clean(&stored);
            if !out.as_str().contains("REST-OF-ARTICLE") {
                cut.push(format!(
                    "{name} (stored tail …{:?})",
                    &stored[stored.len().saturating_sub(60)..]
                ));
                continue;
            }
            assert_eq!(
                out.as_str(),
                sanitize_html(&stored),
                "{name}: render diverged from the ingest sanitizer on the stored body"
            );
        }
        assert!(
            cut.is_empty(),
            "the rest of the article was cut at render for: {cut:#?}"
        );
        // The shapes without a stripped wrapper are fixed points: byte-identical.
        for (name, raw) in &shapes[4..] {
            let stored = sanitize_html(raw);
            assert_eq!(
                SanitizedHtml::clean(&stored).as_str(),
                stored,
                "{name}: re-cleaning changed the stored body"
            );
        }
    }

    /// The off-runtime constructor is the same clean, not a different one.
    #[tokio::test]
    async fn cleaning_off_the_runtime_is_the_same_clean() {
        for raw in HOSTILE.iter().chain(ARTICLES) {
            let off = SanitizedHtml::clean_off_runtime(raw.to_string())
                .await
                .unwrap();
            assert_eq!(off.as_str(), SanitizedHtml::clean(raw).as_str());
        }
    }

    /// **`entry.html` has no `|safe` left at all.** The body renders through
    /// [`SanitizedHtml`]'s `HtmlSafe` impl; a `|safe` here would be the old
    /// bypass, and on a raw `String` it would still compile.
    #[test]
    fn the_reader_template_has_no_safe_filter() {
        let template = include_str!("../templates/entry.html");
        let squashed: String = template.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            !squashed.contains("|safe"),
            "templates/entry.html uses `|safe` again"
        );
    }

    // ----- the three bounds ------------------------------------------------

    fn renderer() -> BodyRenderer {
        BodyRenderer::new(
            RENDER_PERMITS,
            Duration::from_millis(200),
            CACHE_MAX_BYTES,
            CACHE_MAX_ENTRIES,
        )
    }

    fn html(render: BodyRender) -> String {
        match render {
            BodyRender::Html(h) => h.as_str().to_string(),
            BodyRender::TooLarge => panic!("the body was refused as too large"),
            BodyRender::Unavailable => panic!("the body was refused as unavailable"),
            BodyRender::TooSlow => panic!("the body was refused as too slow"),
        }
    }

    /// **The size cap.** A body over [`MAX_RENDER_HTML_BYTES`] — which ingest
    /// never writes — is refused without the sanitizer running. The body here
    /// is the measured worst shape (nested `<div>`s, ~37 s at 2 MiB in
    /// release, far longer in debug), so a render that reached the sanitizer
    /// would also blow the time bound. A body exactly at the cap is cleaned.
    #[tokio::test]
    async fn a_body_over_the_stored_bound_is_refused_without_cleaning() {
        assert_eq!(MAX_RENDER_HTML_BYTES, crate::feed::MAX_CONTENT_HTML_BYTES);
        let r = renderer();
        let depth = MAX_RENDER_HTML_BYTES / 11 + 1;
        let over = format!("{}{}", "<div>".repeat(depth), "</div>".repeat(depth));
        assert!(over.len() > MAX_RENDER_HTML_BYTES);
        let started = Instant::now();
        let out = r.render(over).await.unwrap();
        assert!(
            matches!(out, BodyRender::TooLarge),
            "an over-size body was not refused"
        );
        assert_eq!(r.cleans(), 0, "the sanitizer ran on an over-size body");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "refusing an over-size body took {:?}",
            started.elapsed()
        );
        assert_eq!(r.cache_size(), (0, 0), "a refused body was cached");

        let at = format!("<p>{}</p>", "a".repeat(MAX_RENDER_HTML_BYTES - 7));
        assert_eq!(at.len(), MAX_RENDER_HTML_BYTES);
        let out = html(r.render(at.clone()).await.unwrap());
        assert_eq!(
            out, at,
            "a body exactly at the bound was not rendered whole"
        );
        assert_eq!(r.cleans(), 1);
    }

    /// **The concurrency limit, and that waiting for it never blocks the
    /// runtime.** With every permit held, an uncached body waits the renderer's
    /// wait and comes back [`BodyRender::Unavailable`] with the sanitizer never
    /// run; a cached body still renders at once; and a cheap task joined
    /// beside the waiting render completes long before it — on a
    /// current-thread runtime, which is where a blocking wait would show.
    /// When the permits come back, the same body renders.
    #[tokio::test]
    async fn exhausted_permits_mean_a_note_not_a_blocked_worker() {
        let r = BodyRenderer::new(
            2,
            Duration::from_millis(300),
            CACHE_MAX_BYTES,
            CACHE_MAX_ENTRIES,
        );
        let cached = "<p>already seen</p>".to_string();
        assert_eq!(html(r.render(cached.clone()).await.unwrap()), cached);
        assert_eq!(r.cleans(), 1);

        let held = r.permits().acquire_many_owned(2).await.unwrap();
        assert_eq!(r.permits().available_permits(), 0);

        let fresh = "<p>never seen</p>".to_string();
        let started = Instant::now();
        let (render, timer_done) = tokio::join!(r.render(fresh.clone()), async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Instant::now()
        });
        let render_done = Instant::now();
        assert!(
            matches!(render.unwrap(), BodyRender::Unavailable),
            "an uncached body rendered with no permit free"
        );
        assert_eq!(r.cleans(), 1, "the sanitizer ran with no permit free");
        assert!(
            render_done.duration_since(started) >= Duration::from_millis(300),
            "the render did not wait for a permit"
        );
        assert!(
            timer_done < render_done
                && timer_done.duration_since(started) < Duration::from_millis(250),
            "a concurrent task was held up by the waiting render: timer at {:?}, render at {:?}",
            timer_done.duration_since(started),
            render_done.duration_since(started)
        );
        // A cached body does not need a permit.
        assert_eq!(html(r.render(cached.clone()).await.unwrap()), cached);
        assert_eq!(r.cleans(), 1);

        drop(held);
        assert_eq!(html(r.render(fresh.clone()).await.unwrap()), fresh);
        assert_eq!(r.cleans(), 2);
    }

    /// **The cache.** A body is cleaned once per process: the second render of
    /// the same bytes does not run the sanitizer and returns the same markup.
    #[tokio::test]
    async fn a_body_is_cleaned_once_and_then_served_from_the_cache() {
        let r = renderer();
        for raw in HOSTILE.iter().chain(ARTICLES) {
            let first = html(r.render(raw.to_string()).await.unwrap());
            let cleans = r.cleans();
            let second = html(r.render(raw.to_string()).await.unwrap());
            assert_eq!(
                r.cleans(),
                cleans,
                "the second render of {raw:?} ran the sanitizer"
            );
            assert_eq!(first, second);
            assert_eq!(first, sanitize_html(raw));
        }
        // Distinct bodies were each cleaned exactly once.
        let distinct: std::collections::HashSet<_> = HOSTILE.iter().chain(ARTICLES).collect();
        assert_eq!(r.cleans(), distinct.len());
    }

    /// **The key is the content, all of it.** Two bodies of the same length,
    /// or differing only far from the start or the end, or in a single byte,
    /// must each get their own markup — a collision would show one entry's
    /// body on another's page. (Entry ids are not part of the key: the same
    /// bytes clean to the same markup whichever row holds them.)
    #[tokio::test]
    async fn bodies_that_differ_anywhere_do_not_share_a_cache_slot() {
        let r = renderer();
        let filler = "x".repeat(50_000);
        let pairs = [
            ("<p>aaaa</p>".to_string(), "<p>bbbb</p>".to_string()),
            (
                format!("<p>{filler}A{filler}</p>"),
                format!("<p>{filler}B{filler}</p>"),
            ),
            (
                format!("<p>{filler}</p><p>tail one</p>"),
                format!("<p>{filler}</p><p>tail two</p>"),
            ),
            (
                format!("<p>head one</p><p>{filler}</p>"),
                format!("<p>head two</p><p>{filler}</p>"),
            ),
            (
                r#"<a href="https://a.example/">x</a>"#.to_string(),
                r#"<a href="https://b.example/">x</a>"#.to_string(),
            ),
        ];
        for (a, b) in &pairs {
            assert_eq!(a.len(), b.len(), "the pair must have the same length");
            let out_a = html(r.render(a.clone()).await.unwrap());
            let out_b = html(r.render(b.clone()).await.unwrap());
            assert_eq!(out_a, sanitize_html(a));
            assert_eq!(out_b, sanitize_html(b));
            assert_ne!(
                out_a, out_b,
                "two different bodies rendered the same markup"
            );
            // And again, from the cache this time.
            let cleans = r.cleans();
            assert_eq!(html(r.render(a.clone()).await.unwrap()), out_a);
            assert_eq!(html(r.render(b.clone()).await.unwrap()), out_b);
            assert_eq!(r.cleans(), cleans);
        }
    }

    /// **The cache stays within its bounds**, in bytes and in entries, evicting
    /// the least recently used first; a body whose cleaned form alone is over
    /// the byte bound is rendered but not cached.
    #[tokio::test]
    async fn the_cache_stays_within_its_byte_and_entry_bounds() {
        let body = |i: usize| format!("<p>{i:04} {}</p>", "b".repeat(20_000));
        // Byte-bound first: 100 KB holds four 20 KB bodies.
        let r = BodyRenderer::new(2, Duration::from_millis(200), 100_000, 1_000);
        for i in 0..50 {
            html(r.render(body(i)).await.unwrap());
            let (entries, bytes) = r.cache_size();
            assert!(bytes <= 100_000, "cache held {bytes} B after body {i}");
            assert!(
                (1..=4).contains(&entries),
                "cache held {entries} entries after body {i}"
            );
        }
        // The most recent bodies are the ones kept; the first is long gone.
        let cleans = r.cleans();
        html(r.render(body(49)).await.unwrap());
        assert_eq!(r.cleans(), cleans, "the most recent body was evicted");
        html(r.render(body(0)).await.unwrap());
        assert_eq!(r.cleans(), cleans + 1, "the oldest body was still cached");

        // A hit refreshes recency: 3 slots, touch the oldest, then insert.
        let r = BodyRenderer::new(2, Duration::from_millis(200), 1_000_000, 3);
        for i in 0..3 {
            html(r.render(body(i)).await.unwrap());
        }
        html(r.render(body(0)).await.unwrap()); // 0 is now the most recent
        html(r.render(body(3)).await.unwrap()); // evicts 1
        let cleans = r.cleans();
        html(r.render(body(0)).await.unwrap());
        assert_eq!(r.cleans(), cleans, "a recently hit body was evicted");
        html(r.render(body(1)).await.unwrap());
        assert_eq!(
            r.cleans(),
            cleans + 1,
            "the least recently used body was kept"
        );
        assert_eq!(r.cache_size().0, 3);

        // Entry-bound: 256 entries, 50 KB bodies, 8 MiB — entries bind.
        let r = renderer();
        for i in 0..CACHE_MAX_ENTRIES + 20 {
            html(r.render(body(i)).await.unwrap());
        }
        let (entries, bytes) = r.cache_size();
        assert_eq!(entries, CACHE_MAX_ENTRIES);
        assert!(bytes <= CACHE_MAX_BYTES);

        // Over the byte bound on its own: rendered, not cached, cleaned again.
        let r = BodyRenderer::new(2, Duration::from_millis(200), 10_000, 10);
        let big = body(0);
        assert!(big.len() > 10_000);
        assert_eq!(html(r.render(big.clone()).await.unwrap()), big);
        assert_eq!(r.cache_size(), (0, 0));
        html(r.render(big.clone()).await.unwrap());
        assert_eq!(r.cleans(), 2);
    }

    /// A body slow enough to clean (~2 s in a debug build, ~20 ms in release)
    /// that two renders of it overlap: 48 KiB of nested `<div>`s.
    fn slow_body() -> String {
        let depth = 48 * 1024 / 11;
        format!("{}{}", "<div>".repeat(depth), "</div>".repeat(depth))
    }

    /// **Single flight.** Two concurrent renders of the same uncached body run
    /// the sanitizer once and both get its result; the second does not take a
    /// permit, so with two permits a third, different body still renders at
    /// once — it finishes before either of the slow pair.
    #[tokio::test]
    async fn concurrent_renders_of_one_body_clean_it_once() {
        let r = BodyRenderer::new(
            2,
            Duration::from_secs(10),
            CACHE_MAX_BYTES,
            CACHE_MAX_ENTRIES,
        );
        let slow = slow_body();
        let other = "<p>a different, cheap body</p>".to_string();
        let (a, b, (c, c_done)) =
            tokio::join!(r.render(slow.clone()), r.render(slow.clone()), async {
                // Let the slow pair start first.
                tokio::time::sleep(Duration::from_millis(5)).await;
                (r.render(other.clone()).await, Instant::now())
            });
        let pair_done = Instant::now();
        let (a, b) = (html(a.unwrap()), html(b.unwrap()));
        assert_eq!(a, b);
        assert_eq!(a, sanitize_html(&slow));
        assert_eq!(html(c.unwrap()), other);
        assert_eq!(
            r.cleans(),
            2,
            "the slow body was cleaned more than once, or the cheap one was not"
        );
        assert!(
            c_done < pair_done,
            "the cheap body waited behind the slow pair: no permit was free"
        );
    }

    /// **A requester that goes away leaves nothing behind.** The first render
    /// of a slow body is dropped a few milliseconds in (a client disconnect);
    /// the clean it led goes on as its own task. A second render of the same
    /// body joins that clean rather than starting another — one clean in all —
    /// and when it is done the in-flight table is empty again.
    #[tokio::test]
    async fn a_dropped_requester_leaves_no_stale_in_flight_entry() {
        let r = BodyRenderer::new(
            2,
            Duration::from_secs(10),
            CACHE_MAX_BYTES,
            CACHE_MAX_ENTRIES,
        );
        let slow = slow_body();
        tokio::select! {
            _ = r.render(slow.clone()) => panic!("the slow body rendered within 5 ms"),
            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
        assert_eq!(
            r.in_flight(),
            1,
            "the dropped requester's clean is not in flight"
        );
        let again = html(r.render(slow.clone()).await.unwrap());
        assert_eq!(again, sanitize_html(&slow));
        assert_eq!(
            r.cleans(),
            1,
            "the dropped requester's clean was not joined"
        );
        assert_eq!(r.in_flight(), 0, "a finished clean stayed in flight");
        // Nothing in flight after a plain render either, cached or not.
        html(r.render("<p>x</p>".to_string()).await.unwrap());
        html(r.render("<p>x</p>".to_string()).await.unwrap());
        assert_eq!(r.in_flight(), 0);
    }

    /// **A slow body is cleaned once per process, eviction or not.** Every
    /// clean here counts as slow (threshold zero) and the cache holds one
    /// body, so viewing A, then B, evicts A. Viewing A again must not clean it
    /// a second time — a hostile feed's handful of slow bodies, viewed in
    /// turn, would otherwise re-run a ~37 s clean on every view and keep both
    /// permits busy. It is shown as too slow to display instead.
    #[tokio::test]
    async fn a_slow_body_is_not_cleaned_again_after_eviction() {
        let r = BodyRenderer::new(2, Duration::from_secs(10), 1_000_000, 1)
            .with_slow_threshold(Duration::ZERO);
        let a = "<p>body A</p>".to_string();
        let b = "<p>body B</p>".to_string();
        html(r.render(a.clone()).await.unwrap());
        html(r.render(b.clone()).await.unwrap());
        assert_eq!(r.cleans(), 2);
        let again = r.render(a.clone()).await.unwrap();
        assert_eq!(r.cleans(), 2, "an evicted slow body was cleaned again");
        assert!(
            matches!(again, BodyRender::TooSlow),
            "an evicted slow body was not reported as too slow"
        );
        // A body that was fast stays an ordinary cache miss: cleaned again.
        let fast = BodyRenderer::new(2, Duration::from_secs(10), 1_000_000, 1);
        html(fast.render(a.clone()).await.unwrap());
        html(fast.render(b.clone()).await.unwrap());
        html(fast.render(a.clone()).await.unwrap());
        assert_eq!(fast.cleans(), 3, "a fast body was refused after eviction");
    }

    /// **No second clean in the window between a miss and the in-flight
    /// check.** A request misses the cache; before it takes the in-flight
    /// lock, the leader of the same body finishes, caches its result and
    /// leaves the in-flight table. The request must use that result, not
    /// lead a second clean.
    #[tokio::test]
    async fn a_clean_that_finishes_after_a_miss_is_not_repeated() {
        let r = BodyRenderer::new(2, Duration::from_secs(10), 1_000_000, 16);
        let body = "<p>raced</p>".to_string();
        let cached: Arc<str> = Arc::from(sanitize_html(&body).as_str());
        let key = key_of(&body);
        let inner = Arc::clone(&r.0);
        r.set_after_lookup(move || inner.cache().insert(key, Arc::clone(&cached)));
        let out = html(r.render(body.clone()).await.unwrap());
        assert_eq!(out, sanitize_html(&body));
        assert_eq!(
            r.cleans(),
            0,
            "a clean that had just finished was run again"
        );
    }

    /// The shared instance carries the documented parameters.
    #[test]
    fn the_shared_renderer_has_the_documented_parameters() {
        let shared = BodyRenderer::shared();
        assert_eq!(shared.0.permits.available_permits(), RENDER_PERMITS);
        assert_eq!(shared.0.wait, RENDER_WAIT);
        let cache = shared.0.cache();
        assert_eq!(cache.max_bytes, CACHE_MAX_BYTES);
        assert_eq!(cache.max_entries, CACHE_MAX_ENTRIES);
    }
}
