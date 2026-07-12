//! Feed fetch → parse → sanitize → store pipeline.
//!
//! This is the module that turns a feed URL into rows in the [`store`]. It is
//! deliberately conservative on three axes, because a feed reader ingests
//! **hostile, arbitrary web input**:
//!
//! 1. **Politeness** — fetches use a **conditional GET** (`If-None-Match` /
//!    `If-Modified-Since` from the stored `ETag` / `Last-Modified`), an
//!    identifiable [`crate::USER_AGENT`], a request timeout, and a simple
//!    exponential backoff hint on error. A `304 Not Modified` is a no-op:
//!    the feed is untouched apart from bumping its next-poll time.
//! 2. **Safety** — every entry's HTML is run through [`ammonia`] before it is
//!    ever stored (and therefore before it is ever rendered). Scripts, event
//!    handlers, `javascript:` URLs, tracking pixels' dangerous attributes, and
//!    other XSS vectors are stripped. Feeds carrying `<script>` is not
//!    hypothetical; treat all feed HTML as untrusted.
//! 3. **Robustness** — a malformed feed is **logged and skipped**, never a
//!    panic. One bad publisher must not take down the poller. All non-test
//!    paths use `Result`/`anyhow`; there are no `unwrap`/`expect`s.
//!
//! The normalized shape written to the store is the store's own
//! [`store::NewFeed`] / [`store::NewEntry`]; dedup is by feed-native GUID via
//! [`store::insert_entries`]'s `ON CONFLICT (feed_id, guid)` upsert.

use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use feed_rs::model::{Entry as RawEntry, Feed as RawFeed, Text};
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use reqwest::{Client, StatusCode};
use sqlx::SqlitePool;
use url::Url;

use crate::store::{self, Feed, NewEntry, NewFeed};

/// The privacy classification of a feed URL — the output of
/// [`classify_feed_privacy`].
///
/// A **private** feed carries a secret (a token / key / auth credential) *in the
/// URL itself* (Substack `…/feed/private/<token>`, Patreon `?auth=…`, Ghost
/// members, etc.). Because atproto PDS records are **public** (unauth
/// `getRecord`/`listRecords` + firehose, retained after delete), writing such a
/// URL to the PDS would leak paid / members-only access to the whole network. So
/// the data layer keeps the secret URL **local-only** and writes a *redacted*
/// PDS record. See [`crate::lexicon::Subscription`]'s `private` marker for the
/// full contract and the stopgap→permissioned-data migration note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedPrivacy {
    /// No secret detected in the URL; safe to store the URL in a public PDS
    /// record verbatim.
    Public,
    /// A secret was detected in the URL. The `String` is a short, human-readable
    /// reason (for logging / UI), e.g. `"substack private feed path"`. The secret
    /// URL must be kept local-only and the PDS record must be redacted.
    Private(String),
}

impl FeedPrivacy {
    /// Whether this classification is [`FeedPrivacy::Private`].
    pub fn is_private(&self) -> bool {
        matches!(self, FeedPrivacy::Private(_))
    }
}

/// Query-parameter *keys* that, when present, mark a URL as carrying a secret.
/// Conservative and lowercase-compared; these are the credential markers used by
/// Patreon (`auth`), token-in-query feeds (`token`/`key`/`k`), and the generic
/// `secret`. Matched as a whole key (case-insensitive) so a benign `keyword=`
/// does NOT trip `key`.
const SECRET_QUERY_KEYS: &[&str] = &["token", "key", "k", "auth", "secret", "apikey", "api_key"];

/// Classify whether a feed URL carries a secret credential in the URL itself.
///
/// Returns [`FeedPrivacy::Private`] (with a reason) when the URL looks like it
/// embeds a token / key / auth credential, else [`FeedPrivacy::Public`]. This is
/// deliberately **conservative** — a false positive merely keeps a feed URL
/// local-only (still fully functional, just not mirrored verbatim to the PDS),
/// whereas a false negative would LEAK a paid-content secret onto the public
/// atproto network. When in doubt we lean toward `Private`.
///
/// Detection heuristics (any one is sufficient):
/// 1. **Known private-feed path shapes** — Substack's `/feed/private/<token>`,
///    or any `/private/` path segment (Ghost/others expose members feeds this
///    way). These are unambiguous "this is a secret feed" markers.
/// 2. **Credential query parameters** — a query key in [`SECRET_QUERY_KEYS`]
///    (Patreon `?auth=`, token-in-query feeds `?token=`/`?key=`/`?k=`, generic
///    `?secret=`/`?apikey=`).
/// 3. **High-entropy opaque segments** — a long, high-entropy path segment or
///    query value that looks like an embedded key/token even without a telltale
///    name (e.g. a 32+ char base64/hex blob). Bounded by a length + entropy
///    floor so ordinary slugs (`my-first-post`) don't trip it.
///
/// An unparseable URL is treated as [`FeedPrivacy::Public`]: the poller/SSRF
/// guard will reject it downstream anyway, and we don't want a parse quirk to
/// silently reclassify (and thus withhold) an otherwise-normal feed.
pub fn classify_feed_privacy(url: &str) -> FeedPrivacy {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        // Can't parse => can't have extracted a secret with confidence; the
        // fetch path will reject a malformed URL regardless.
        Err(_) => return FeedPrivacy::Public,
    };

    let path = parsed.path();
    let path_lower = path.to_ascii_lowercase();

    // (1) Known private-feed path shapes.
    if path_lower.contains("/feed/private/") {
        return FeedPrivacy::Private("substack private feed path".to_string());
    }
    // A `/private/` segment anywhere in the path (Ghost members feeds, and a
    // common convention for tokened feeds). Match on segment boundaries so we
    // don't trip on a literal word like `/my-private-life/`.
    if parsed
        .path_segments()
        .map(|segs| segs.into_iter().any(|s| s.eq_ignore_ascii_case("private")))
        .unwrap_or(false)
    {
        return FeedPrivacy::Private("private path segment".to_string());
    }

    // (2) Credential query parameters.
    for (k, v) in parsed.query_pairs() {
        let key = k.as_ref().to_ascii_lowercase();
        if SECRET_QUERY_KEYS.iter().any(|sk| *sk == key) && !v.is_empty() {
            return FeedPrivacy::Private(format!("credential query parameter `{key}`"));
        }
    }

    // (3) High-entropy opaque path/query segments (an embedded key/token with no
    // telltale name). Only trip on a genuinely key-shaped blob to avoid
    // reclassifying ordinary long slugs.
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        if looks_like_embedded_secret(seg) {
            return FeedPrivacy::Private("high-entropy path segment".to_string());
        }
    }
    for (_, v) in parsed.query_pairs() {
        if looks_like_embedded_secret(v.as_ref()) {
            return FeedPrivacy::Private("high-entropy query value".to_string());
        }
    }

    FeedPrivacy::Public
}

/// Heuristic: does `s` look like an embedded secret (an opaque high-entropy
/// token / key), as opposed to an ordinary slug or word?
///
/// Requires ALL of: length >= 24, no `-`/`.`/`_`-delimited word structure that
/// dominates (i.e. it isn't a hyphenated slug like `my-first-blog-post`), a mix
/// of letter *and* digit characters, and a high ratio of distinct characters.
/// Deliberately strict so it only fires on things that really look like keys —
/// false negatives here are covered by the named-marker checks (1) and (2); this
/// is only the catch-all for unnamed tokens.
fn looks_like_embedded_secret(s: &str) -> bool {
    // Long enough to plausibly be a token, not a word.
    if s.len() < 24 {
        return false;
    }
    // Hyphen/dot-heavy slugs (`this-is-a-normal-post-title`) are not secrets.
    let separators = s
        .bytes()
        .filter(|b| *b == b'-' || *b == b'.' || *b == b' ')
        .count();
    if separators >= 3 {
        return false;
    }
    // Must be plausibly token-charset: letters/digits (plus a few base64/url
    // chars). Anything with lots of other punctuation is more likely a path.
    let token_chars = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '='))
        .count();
    if token_chars < s.chars().count() {
        return false;
    }
    let has_alpha = s.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    if !(has_alpha && has_digit) {
        // A token almost always mixes letters and digits; a pure-alpha long
        // segment is far more likely to be a normal (if long) slug/word.
        return false;
    }
    // Distinct-character ratio: real tokens use most of the alphabet, words
    // repeat a small set. Require >= 12 distinct chars.
    let mut seen = std::collections::HashSet::new();
    for c in s.chars() {
        seen.insert(c.to_ascii_lowercase());
    }
    seen.len() >= 12
}

/// How long a single feed fetch may take before we give up.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-read idle timeout: cap the wait for the *next* body chunk, so a server
/// that trickles bytes forever can't tie up a fetch under the total timeout.
const READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Base backoff applied after a failed poll; the caller multiplies this by the
/// feed's consecutive-error count (with a ceiling) to space out retries.
const BACKOFF_BASE: Duration = Duration::from_secs(300);

/// Ceiling on backoff so a persistently broken feed still gets retried daily.
const BACKOFF_MAX: Duration = Duration::from_secs(24 * 3600);

/// The outcome of polling a single feed. Lets the scheduler decide how to
/// reschedule (and lets tests assert what happened) without inspecting the DB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// The feed was fetched, parsed, and stored. `new_entries` is the number of
    /// entries inserted or updated by this poll.
    Updated { new_entries: u64 },
    /// The server returned `304 Not Modified` — nothing changed, nothing stored.
    NotModified,
    /// The fetch or parse failed; the feed was left intact and skipped. Carries
    /// the suggested backoff before the next attempt. Never a panic.
    Failed { backoff: Duration },
}

/// Build a `reqwest::Client` configured for polite **and safe** feed fetching.
///
/// Callers should build this **once** and share it (connection pooling), then
/// hand a reference to [`poll_feed`]. Kept here so the fetch policy (UA,
/// timeout, redirect behaviour) lives with the code that depends on it.
///
/// Auto-redirect is **disabled** on purpose: feed URLs are untrusted, so
/// redirects are followed manually by [`crate::net::guarded_get`], which
/// re-validates the scheme + resolved IP of every hop (SSRF defence). A client
/// that silently followed redirects could be bounced onto `169.254.169.254` or
/// `127.0.0.1` between the guard's check and the connect.
pub fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent(crate::USER_AGENT)
        .timeout(FETCH_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        // No auto-redirect: net::guarded_get follows + re-validates each hop.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build feed HTTP client")
}

/// Compute the backoff for the `n`th consecutive failure (1-based), clamped to
/// [`BACKOFF_MAX`]. Exponential in the error count so transient blips retry soon
/// while a durably-broken feed backs off toward daily.
fn backoff_for(consecutive_errors: u32) -> Duration {
    let n = consecutive_errors.max(1);
    // Saturating shift: base * 2^(n-1), capped. Avoids overflow for large n.
    let factor = 1u64.checked_shl(n.saturating_sub(1)).unwrap_or(u64::MAX);
    let secs = BACKOFF_BASE
        .as_secs()
        .saturating_mul(factor)
        .min(BACKOFF_MAX.as_secs());
    Duration::from_secs(secs)
}

/// Fetch, parse, sanitize, normalize, and store a single feed.
///
/// Performs a conditional GET using the feed's stored `ETag` / `Last-Modified`.
/// On `304` it returns [`PollOutcome::NotModified`] without touching entries. On
/// `200` it parses with `feed-rs`, sanitizes every entry's HTML with `ammonia`,
/// upserts the feed row (carrying the fresh validators) and inserts new entries
/// (deduped by GUID). Any fetch/parse error is logged and returned as
/// [`PollOutcome::Failed`] — it never panics and never propagates as `Err` for
/// a merely-broken feed, so one bad publisher can't stall the scheduler.
///
/// `Err` is reserved for *store* failures (a broken local DB is a real error the
/// caller should see), not for feed misbehaviour.
pub async fn poll_feed(pool: &SqlitePool, client: &Client, feed: &Feed) -> Result<PollOutcome> {
    // --- conditional GET (through the SSRF guard) ----------------------------
    // The guard re-validates the scheme + resolved IP of the target and of every
    // redirect hop, so a subscribed feed can't bounce the poller onto an
    // internal address (cloud metadata / loopback). Conditional-GET validators
    // ride along as extra headers.
    let mut extra: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)> = Vec::new();
    if let Some(etag) = feed.etag.as_deref() {
        if let Ok(v) = reqwest::header::HeaderValue::from_str(etag) {
            extra.push((IF_NONE_MATCH, v));
        }
    }
    if let Some(lm) = feed.last_modified.as_deref() {
        if let Ok(v) = reqwest::header::HeaderValue::from_str(lm) {
            extra.push((IF_MODIFIED_SINCE, v));
        }
    }

    let resp = match crate::net::guarded_get(client, &feed.url, &extra).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(feed = %feed.url, error = %e, "feed fetch failed (or blocked by SSRF guard)");
            return Ok(PollOutcome::Failed {
                backoff: backoff_for(1),
            });
        }
    };

    let status = resp.status();
    if status == StatusCode::NOT_MODIFIED {
        tracing::debug!(feed = %feed.url, "feed not modified (304)");
        // Bump last_polled/next_poll only; leave validators + entries untouched.
        touch_polled(pool, &feed.url, None, None)
            .await
            .with_context(|| format!("touch_polled after 304 for {}", feed.url))?;
        return Ok(PollOutcome::NotModified);
    }
    if !status.is_success() {
        tracing::warn!(feed = %feed.url, %status, "feed returned non-success status");
        return Ok(PollOutcome::Failed {
            backoff: backoff_for(1),
        });
    }

    // Capture validators for the *next* conditional GET before consuming body.
    let new_etag = header_str(resp.headers().get(ETAG));
    let new_last_modified = header_str(resp.headers().get(LAST_MODIFIED));

    // Stream the body with a hard byte cap, aborting mid-stream if it exceeds
    // it. We never trust Content-Length: reqwest's gzip layer strips it, so a
    // small gzip bomb could otherwise inflate to GBs before any size check.
    let body = match crate::net::read_capped(resp).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(feed = %feed.url, error = %e, "feed body rejected (too large / read error)");
            return Ok(PollOutcome::Failed {
                backoff: backoff_for(1),
            });
        }
    };

    // --- parse (malformed feed => log + skip, never panic) -------------------
    let parsed = match feed_rs::parser::parse(&body[..]) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(feed = %feed.url, error = %e, "malformed feed; skipping");
            return Ok(PollOutcome::Failed {
                backoff: backoff_for(1),
            });
        }
    };

    // --- normalize + sanitize ------------------------------------------------
    let (title, site_url) = feed_metadata(&parsed);
    let new_feed = NewFeed {
        url: feed.url.clone(),
        title,
        site_url,
        etag: new_etag,
        last_modified: new_last_modified,
        last_polled: Some(now_rfc3339()),
        next_poll: None, // the scheduler owns cadence; leave it to set next_poll.
        // The poller doesn't classify privacy; upsert_feed ORs the flag so this
        // `false` can never clobber a feed the subscribe path marked private.
        private: false,
    };

    let entries: Vec<NewEntry> = parsed.entries.iter().map(normalize_entry).collect();

    // --- store (a store failure IS a real error) -----------------------------
    let feed_id = store::upsert_feed(pool, &new_feed)
        .await
        .with_context(|| format!("upsert_feed for {}", feed.url))?;
    let n = store::insert_entries(pool, feed_id, &entries)
        .await
        .with_context(|| format!("insert_entries for {}", feed.url))?;

    tracing::info!(feed = %feed.url, entries = n, "feed polled");
    Ok(PollOutcome::Updated { new_entries: n })
}

/// Bump `last_polled` (and optionally validators) without changing entries —
/// used on the `304 Not Modified` path.
async fn touch_polled(
    pool: &SqlitePool,
    url: &str,
    etag: Option<String>,
    last_modified: Option<String>,
) -> Result<()> {
    // upsert_feed's ON CONFLICT overwrites etag/last_modified unconditionally,
    // so on a 304 we re-supply the existing validators (fetched from the row) to
    // avoid clobbering them. The caller passes `None` to mean "keep current".
    let existing = store::get_feed_by_url(pool, url).await?;
    let (etag, last_modified) = match existing {
        Some(f) => (etag.or(f.etag), last_modified.or(f.last_modified)),
        None => (etag, last_modified),
    };
    let nf = NewFeed {
        url: url.to_string(),
        etag,
        last_modified,
        last_polled: Some(now_rfc3339()),
        ..Default::default()
    };
    store::upsert_feed(pool, &nf).await?;
    Ok(())
}

/// Extract `(title, site_url)` from a parsed feed. `site_url` prefers an
/// `alternate`/no-rel HTML link over the feed's self link.
fn feed_metadata(parsed: &RawFeed) -> (Option<String>, Option<String>) {
    let title = parsed.title.as_ref().map(text_plain);
    let site_url = parsed
        .links
        .iter()
        // Prefer an explicit human-facing page: rel="alternate" or no rel at all.
        .find(|l| {
            l.rel.as_deref() == Some("alternate")
                || (l.rel.is_none()
                    && l.media_type.as_deref() != Some("application/rss+xml")
                    && l.media_type.as_deref() != Some("application/atom+xml"))
        })
        .or_else(|| {
            parsed
                .links
                .iter()
                .find(|l| l.rel.as_deref() != Some("self"))
        })
        .or_else(|| parsed.links.first())
        .map(|l| l.href.clone());
    (title, site_url)
}

/// Turn a parsed [`RawEntry`] into the store's [`NewEntry`], sanitizing HTML.
///
/// Content preference: full `content` body, else `summary`. Whichever is chosen
/// is **always** passed through [`sanitize_html`] before storage. GUID falls
/// back to the entry link, then to a stable hash of title+link, so an entry
/// missing an `id` still deduplicates instead of being re-inserted forever.
fn normalize_entry(e: &RawEntry) -> NewEntry {
    let url = entry_link(e);
    let content_html = e
        .content
        .as_ref()
        .and_then(|c| c.body.as_deref())
        .or_else(|| e.summary.as_ref().map(|t| t.content.as_str()))
        .map(sanitize_html);

    // GUID may use the raw link (dedup key only, never rendered), so prefer the
    // entry's first raw link for identity even when it's not a safe href.
    let guid = if !e.id.trim().is_empty() {
        e.id.trim().to_string()
    } else if let Some(link) = raw_entry_link(e) {
        link
    } else {
        // Last resort: derive a stable id so re-fetches dedup rather than dupe.
        stable_guid(e)
    };

    NewEntry {
        guid,
        url,
        title: e.title.as_ref().map(text_plain),
        author: entry_author(e),
        published: entry_time(e),
        content_html,
        fetched_at: None, // store defaults to "now".
    }
}

/// The raw best-permalink URL for an entry (no scheme filtering) — used only as
/// a dedup GUID, never rendered as an href.
fn raw_entry_link(e: &RawEntry) -> Option<String> {
    e.links
        .iter()
        .find(|l| l.rel.as_deref() == Some("alternate") || l.rel.is_none())
        .or_else(|| e.links.first())
        .map(|l| l.href.clone())
}

/// The best display/permalink URL for an entry, **scheme-allow-listed** so it is
/// safe to render as an `href`: prefer `rel="alternate"` or a no-rel link, else
/// the first link — but only if it is an `http`/`https` URL. A `javascript:` or
/// `data:` permalink (a stored-XSS vector that survives HTML escaping, since it
/// carries no HTML-special characters) is dropped here at ingest, before it can
/// ever reach the store or a template.
fn entry_link(e: &RawEntry) -> Option<String> {
    raw_entry_link(e).and_then(|href| crate::net::safe_link(&href))
}

/// First author name, if any.
fn entry_author(e: &RawEntry) -> Option<String> {
    e.authors.first().map(|p| p.name.clone())
}

/// Best publication time (published, else updated) as an RFC3339 string.
fn entry_time(e: &RawEntry) -> Option<String> {
    e.published.or(e.updated).map(fmt_time)
}

/// Extract the plain string content of a feed [`Text`] node.
fn text_plain(t: &Text) -> String {
    t.content.trim().to_string()
}

/// Sanitize hostile feed HTML with ammonia's whitelist cleaner. Safe on plain
/// text too (it will simply escape/strip as needed), so it's applied to *all*
/// entry bodies unconditionally.
fn sanitize_html(raw: &str) -> String {
    ammonia::clean(raw)
}

/// Format a chrono timestamp as RFC3339 (UTC, seconds precision) to match the
/// store's string columns.
fn fmt_time(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// "Now" in the store's RFC3339 shape.
fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// A stable GUID derived from an entry's title + first link, for feeds that
/// supply neither an id nor a usable link id. Deterministic so re-fetches dedup.
fn stable_guid(e: &RawEntry) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    e.title.as_ref().map(|t| t.content.as_str()).hash(&mut h);
    e.links.first().map(|l| l.href.as_str()).hash(&mut h);
    e.summary.as_ref().map(|s| s.content.as_str()).hash(&mut h);
    format!("featherreader:synthetic:{:016x}", h.finish())
}

/// Decode an HTTP header value to an owned `String`, dropping non-UTF-8 values.
fn header_str(v: Option<&reqwest::header::HeaderValue>) -> Option<String> {
    v.and_then(|h| h.to_str().ok()).map(str::to_string)
}

/// Discover a feed URL from a site's HTML via
/// `<link rel="alternate" type="application/rss+xml|atom+xml" href="…">`.
///
/// Returns the first RSS/Atom autodiscovery link found, resolved against the
/// page URL if the `href` is relative. This is what lets a user paste a *site*
/// URL and have FeatherReader find the actual feed (design §3, "Subscribe by
/// URL"). Returns `None` if the HTML carries no autodiscovery link.
///
/// The `base` is the URL the HTML was fetched from, used to resolve relative
/// `href`s. Pass `None` to only accept absolute hrefs.
pub fn discover_feed(site_html: &str, base: Option<&Url>) -> Option<Url> {
    // Parse the HTML with html5ever (via ammonia's dependency graph is separate;
    // use a light hand-rolled scan over <link> tags to avoid a new dependency).
    // We look for <link ...> elements whose rel contains "alternate" and whose
    // type is an RSS/Atom feed media type, and take the href.
    for tag in link_tags(site_html) {
        let rel = attr(&tag, "rel").unwrap_or_default().to_ascii_lowercase();
        let typ = attr(&tag, "type").unwrap_or_default().to_ascii_lowercase();
        let is_feed_type = typ.contains("application/rss+xml")
            || typ.contains("application/atom+xml")
            || typ.contains("application/feed+json")
            || typ.contains("application/json");
        // rel="alternate" is the standard; be lenient and also accept a bare
        // feed type with any rel, but require the feed media type either way.
        let rel_ok = rel.split_whitespace().any(|r| r == "alternate") || rel.is_empty();
        if is_feed_type && rel_ok {
            if let Some(href) = attr(&tag, "href") {
                let href = href.trim();
                if href.is_empty() {
                    continue;
                }
                // Absolute URL wins directly; otherwise resolve against `base`.
                if let Ok(u) = Url::parse(href) {
                    return Some(u);
                }
                if let Some(b) = base {
                    if let Ok(u) = b.join(href) {
                        return Some(u);
                    }
                }
            }
        }
    }
    None
}

/// Extract the raw text of every `<link ...>` tag (self-closing or not) from an
/// HTML string. A deliberately small, allocation-light scan — feed
/// autodiscovery does not need a full DOM, and avoiding one keeps the dependency
/// surface minimal (design bias: boring, small-dependency).
fn link_tags(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = html.as_bytes();
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(rel_idx) = lower[search_from..].find("<link") {
        let start = search_from + rel_idx;
        // Ensure it's a tag boundary ("<link" followed by whitespace, '>' or '/').
        let after = bytes.get(start + 5).copied();
        let boundary = matches!(after, Some(b) if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == b'>' || b == b'/');
        if !boundary {
            search_from = start + 5;
            continue;
        }
        // Find the closing '>' for this tag.
        if let Some(end_rel) = html[start..].find('>') {
            let end = start + end_rel;
            out.push(html[start..=end].to_string());
            search_from = end + 1;
        } else {
            break;
        }
    }
    out
}

/// Read an attribute value from a single tag string, handling both single- and
/// double-quoted values. Case-insensitive attribute name match.
fn attr(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{name}=");
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(&needle) {
        let name_start = from + rel;
        // Guard against matching a suffix of a longer attribute name
        // (e.g. matching "type=" inside "mytype="): the char before must be a
        // tag/whitespace boundary.
        let ok_prefix = name_start == 0
            || matches!(
                tag.as_bytes().get(name_start - 1),
                Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') | Some(b'<')
            );
        let val_start = name_start + needle.len();
        if !ok_prefix {
            from = val_start;
            continue;
        }
        let rest = &tag[val_start..];
        let quote = rest.chars().next();
        let value = match quote {
            Some('"') => rest[1..].split('"').next(),
            Some('\'') => rest[1..].split('\'').next(),
            // Unquoted: read up to whitespace, '>' or '/'.
            _ => rest
                .split(|c: char| c.is_whitespace() || c == '>' || c == '/')
                .next(),
        };
        return value.map(str::to_string);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSS_SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Example RSS Feed</title>
    <link>https://example.com/</link>
    <description>An example feed for tests</description>
    <item>
      <title>First post</title>
      <link>https://example.com/first</link>
      <guid>https://example.com/first</guid>
      <author>alice@example.com (Alice)</author>
      <pubDate>Fri, 10 Jul 2026 08:00:00 GMT</pubDate>
      <description><![CDATA[<p>Hello <b>world</b>.</p><script>alert('xss')</script><img src="x" onerror="alert(1)">]]></description>
    </item>
    <item>
      <title>Second post</title>
      <link>https://example.com/second</link>
      <guid>guid-second</guid>
      <pubDate>Sat, 11 Jul 2026 08:00:00 GMT</pubDate>
      <description><![CDATA[<a href="javascript:alert(1)">click</a><a href="https://ok.example/">ok</a>]]></description>
    </item>
  </channel>
</rss>"#;

    const ATOM_SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Example Atom Feed</title>
  <link rel="alternate" href="https://atom.example.com/"/>
  <link rel="self" href="https://atom.example.com/feed.xml"/>
  <id>urn:uuid:feed-1</id>
  <updated>2026-07-11T08:00:00Z</updated>
  <entry>
    <title>Atom entry</title>
    <id>urn:uuid:entry-1</id>
    <link rel="alternate" href="https://atom.example.com/a"/>
    <author><name>Bob</name></author>
    <updated>2026-07-11T08:00:00Z</updated>
    <content type="html"><![CDATA[<p>Safe <em>text</em>.</p><script>steal()</script><iframe src="evil"></iframe>]]></content>
  </entry>
</feed>"#;

    /// Parse a static RSS sample through feed-rs + our normalize/sanitize path
    /// (no network) and assert the entries come out sanitized and well-shaped.
    #[test]
    fn rss_parses_and_sanitizes() {
        let parsed = feed_rs::parser::parse(RSS_SAMPLE.as_bytes()).expect("RSS should parse");
        assert_eq!(
            parsed.title.as_ref().map(text_plain).as_deref(),
            Some("Example RSS Feed")
        );
        assert_eq!(parsed.entries.len(), 2);

        let (title, site) = feed_metadata(&parsed);
        assert_eq!(title.as_deref(), Some("Example RSS Feed"));
        assert_eq!(site.as_deref(), Some("https://example.com/"));

        let e0 = normalize_entry(&parsed.entries[0]);
        assert_eq!(e0.guid, "https://example.com/first");
        assert_eq!(e0.title.as_deref(), Some("First post"));
        assert_eq!(e0.url.as_deref(), Some("https://example.com/first"));
        assert!(e0.published.is_some());
        let html0 = e0.content_html.expect("content present");
        // Sanitized: benign markup kept, script + onerror stripped.
        assert!(html0.contains("Hello"));
        assert!(html0.contains("<b>world</b>") || html0.contains("<b>"));
        assert!(!html0.to_ascii_lowercase().contains("<script"));
        assert!(!html0.to_ascii_lowercase().contains("onerror"));
        assert!(!html0.to_ascii_lowercase().contains("alert"));

        // Second entry: javascript: URL scrubbed, safe link kept.
        let e1 = normalize_entry(&parsed.entries[1]);
        assert_eq!(e1.guid, "guid-second");
        let html1 = e1.content_html.expect("content present");
        assert!(!html1.to_ascii_lowercase().contains("javascript:"));
        assert!(html1.contains("https://ok.example/"));
    }

    /// Same, for an Atom sample: alternate link is the site URL, dangerous
    /// elements are stripped from entry content.
    #[test]
    fn atom_parses_and_sanitizes() {
        let parsed = feed_rs::parser::parse(ATOM_SAMPLE.as_bytes()).expect("Atom should parse");
        let (title, site) = feed_metadata(&parsed);
        assert_eq!(title.as_deref(), Some("Example Atom Feed"));
        // alternate link preferred over rel="self".
        assert_eq!(site.as_deref(), Some("https://atom.example.com/"));

        assert_eq!(parsed.entries.len(), 1);
        let e = normalize_entry(&parsed.entries[0]);
        assert_eq!(e.guid, "urn:uuid:entry-1");
        assert_eq!(e.title.as_deref(), Some("Atom entry"));
        assert_eq!(e.author.as_deref(), Some("Bob"));
        assert_eq!(e.url.as_deref(), Some("https://atom.example.com/a"));
        let html = e.content_html.expect("content present");
        assert!(html.contains("Safe"));
        assert!(!html.to_ascii_lowercase().contains("<script"));
        assert!(!html.to_ascii_lowercase().contains("<iframe"));
    }

    #[test]
    fn discover_finds_rss_link() {
        let html = r#"<!doctype html><html><head>
            <title>Blog</title>
            <link rel="stylesheet" href="/style.css">
            <link rel="alternate" type="application/rss+xml" title="RSS" href="/feed.xml">
        </head><body>hi</body></html>"#;
        let base = Url::parse("https://blog.example.com/").unwrap();
        let found = discover_feed(html, Some(&base)).expect("should discover feed");
        assert_eq!(found.as_str(), "https://blog.example.com/feed.xml");
    }

    #[test]
    fn discover_finds_atom_absolute_link() {
        let html = r#"<head><link rel="alternate" type="application/atom+xml" href="https://x.example/atom"></head>"#;
        let found = discover_feed(html, None).expect("should discover absolute feed");
        assert_eq!(found.as_str(), "https://x.example/atom");
    }

    #[test]
    fn discover_returns_none_without_feed_link() {
        let html =
            r#"<head><link rel="stylesheet" href="/s.css"><link rel="icon" href="/f.ico"></head>"#;
        assert!(discover_feed(html, None).is_none());
    }

    #[test]
    fn synthetic_guid_is_stable_and_dedups() {
        // An item with neither guid nor link: feed-rs will hash the link (absent)
        // to a UUID id, but to exercise *our* synthetic fallback we clear the id
        // on the parsed entry and confirm normalize yields a deterministic guid.
        let xml = r#"<?xml version="1.0"?><rss version="2.0"><channel>
            <title>t</title>
            <item><title>only a title</title><description>body</description></item>
        </channel></rss>"#;
        let mut parsed = feed_rs::parser::parse(xml.as_bytes()).expect("parse");
        parsed.entries[0].id.clear();
        parsed.entries[0].links.clear();
        let g1 = normalize_entry(&parsed.entries[0]).guid;
        let g2 = normalize_entry(&parsed.entries[0]).guid;
        assert_eq!(g1, g2);
        assert!(g1.starts_with("featherreader:synthetic:"));
    }

    #[test]
    fn entry_link_scheme_allowlist_neutralizes_javascript() {
        // An entry whose only link is a javascript: URL must yield no href.
        let xml = r#"<?xml version="1.0"?><rss version="2.0"><channel>
            <title>t</title>
            <item>
              <title>evil</title>
              <link>javascript:alert(document.domain)</link>
              <guid>evil-1</guid>
            </item>
        </channel></rss>"#;
        let parsed = feed_rs::parser::parse(xml.as_bytes()).expect("parse");
        let e = normalize_entry(&parsed.entries[0]);
        // url is dropped (not a safe http(s) link)…
        assert_eq!(e.url, None);
        // …but the entry still dedups (guid preserved from <guid>).
        assert_eq!(e.guid, "evil-1");

        // A data: URL is likewise dropped.
        let xml2 = r#"<?xml version="1.0"?><rss version="2.0"><channel>
            <title>t</title>
            <item><title>d</title><link>data:text/html,<script>1</script></link><guid>d1</guid></item>
        </channel></rss>"#;
        let parsed2 = feed_rs::parser::parse(xml2.as_bytes()).expect("parse");
        let e2 = normalize_entry(&parsed2.entries[0]);
        assert_eq!(e2.url, None);

        // A normal https link survives.
        let xml3 = r#"<?xml version="1.0"?><rss version="2.0"><channel>
            <title>t</title>
            <item><title>ok</title><link>https://ok.example/post</link><guid>ok1</guid></item>
        </channel></rss>"#;
        let parsed3 = feed_rs::parser::parse(xml3.as_bytes()).expect("parse");
        let e3 = normalize_entry(&parsed3.entries[0]);
        assert_eq!(e3.url.as_deref(), Some("https://ok.example/post"));
    }

    #[test]
    fn classify_privacy_flags_known_secret_urls() {
        // Substack private feed path.
        assert!(
            classify_feed_privacy("https://author.substack.com/feed/private/abcdef123456")
                .is_private()
        );

        // Patreon-style ?auth= credential.
        assert!(
            classify_feed_privacy("https://www.patreon.com/rss/author?auth=SEKRET").is_private()
        );

        // Generic token/key/secret query params.
        assert!(classify_feed_privacy("https://example.com/feed?token=xyz").is_private());
        assert!(classify_feed_privacy("https://example.com/feed?key=xyz").is_private());
        assert!(classify_feed_privacy("https://example.com/feed?k=xyz").is_private());
        assert!(classify_feed_privacy("https://example.com/feed?secret=xyz").is_private());

        // A `/private/` path segment (Ghost members, tokened feeds).
        assert!(classify_feed_privacy("https://blog.example.com/private/rss").is_private());

        // A high-entropy opaque token embedded in the path with no telltale name.
        assert!(
            classify_feed_privacy("https://feeds.example.com/aB3xK9zQ7mP2rT5wL8nD4vF6")
                .is_private()
        );
    }

    #[test]
    fn classify_privacy_leaves_normal_public_feeds_public() {
        assert_eq!(
            classify_feed_privacy("https://example.com/feed.xml"),
            FeedPrivacy::Public
        );
        assert_eq!(
            classify_feed_privacy("https://blog.example.com/rss"),
            FeedPrivacy::Public
        );
        // A long, hyphenated slug must NOT be mistaken for an embedded secret.
        assert_eq!(
            classify_feed_privacy("https://example.com/2026/07/my-first-long-blog-post-title/feed"),
            FeedPrivacy::Public
        );
        // A benign query key that merely contains "key" as a substring is fine.
        assert_eq!(
            classify_feed_privacy("https://example.com/feed?keyword=rust"),
            FeedPrivacy::Public
        );
        // An empty credential value is not a secret.
        assert_eq!(
            classify_feed_privacy("https://example.com/feed?token="),
            FeedPrivacy::Public
        );
        // Unparseable URL: treated as Public (fetch path rejects it downstream).
        assert_eq!(classify_feed_privacy("not a url"), FeedPrivacy::Public);
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_for(1), BACKOFF_BASE);
        assert!(backoff_for(2) > backoff_for(1));
        assert_eq!(backoff_for(100), BACKOFF_MAX);
    }
}
