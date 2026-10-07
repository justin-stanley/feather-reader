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
//! 2. **Safety** — every entry's HTML is run through `ammonia` before it is
//!    ever stored. Scripts, event handlers, `javascript:` URLs, tracking
//!    pixels' dangerous attributes, and other XSS vectors are stripped. Feeds
//!    carrying `<script>` is not hypothetical; treat all feed HTML as
//!    untrusted. The reader does not rely on this alone: it re-cleans the
//!    stored body with the same `sanitize_html` at render, through
//!    [`crate::sanitized_html::SanitizedHtml`] (#151).
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
use feed_rs::model::{Entry as RawEntry, Feed as RawFeed, Link as RawLink, Text};
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use reqwest::{Client, StatusCode};
use sqlx::SqlitePool;
use url::Url;

use crate::store::{self, Feed, NewEntry, NewFeed};

/// The privacy classification of a feed URL — the output of
/// [`classify_feed_privacy`].
///
/// A **private** feed carries a secret (a token / key / auth credential) *in the
/// URL itself* — a Substack `…/feed/private/<token>`, a Patreon `?auth=…` feed,
/// a Ghost members `?uuid=` feed, a private-podcast token feed (Supercast,
/// Supporting Cast, tokened Megaphone/Acast+), and so on. FeatherReader stores a
/// user's subscriptions as records in their **public PDS** (unauthenticated
/// `getRecord` / `listRecords` + the firehose, retained even after delete), so
/// writing such a URL anywhere — the PDS *or* the server's own store — would risk
/// leaking paid / members-only access.
///
/// **Decision (stopgap until atproto permissioned data ships): FeatherReader
/// supports PUBLIC feeds only.** A feed classified [`FeedPrivacy::Private`] is
/// *refused* at the add / import boundary — never fetched, never stored, never
/// written to the PDS. There is no local-secret fallback and no override: the
/// server holds NO private secret, ever, which keeps "your data lives in your
/// public PDS" 100% honest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedPrivacy {
    /// No secret detected in the URL; safe to add as a public feed.
    Public,
    /// A secret was detected in the URL. The `String` is a short, human-readable
    /// reason (for logging / the skip report), e.g. `"substack private feed
    /// path"`. The feed is refused — not fetched, stored, or written anywhere.
    Private(String),
}

impl FeedPrivacy {
    /// Whether this classification is [`FeedPrivacy::Private`].
    pub fn is_private(&self) -> bool {
        matches!(self, FeedPrivacy::Private(_))
    }
}

/// Query-parameter *keys* that, when present with a long/opaque value, mark a URL
/// as carrying a secret. Conservative and lowercase-compared; matched as a whole
/// key (case-insensitive) so a benign `keyword=` does NOT trip `key`. This is the
/// generic, provider-agnostic credential-in-query defence — it catches paid
/// feeds from providers we've never heard of. Covers Patreon (`auth`), Ghost
/// members (`uuid`), token-in-query feeds (`token`/`key`/`k`/`sig`/`hash`), and
/// the long tail (`access`/`apikey`/`private`/`password`/`u`/`s`/`p`/…).
const SECRET_QUERY_KEYS: &[&str] = &[
    "token", "key", "auth", "secret", "k", "sig", "hash", "access", "apikey", "api_key", "uuid",
    "id", "u", "s", "p", "private", "password", "pw",
];

/// Path *segments* / fragments that mark a private-feed URL shape. Matched as a
/// case-insensitive substring of the (lowercased) path so `/feed/private/<tok>`,
/// `/members/…`, `/subscriber/…` etc. all trip regardless of the token that
/// follows. Provider-agnostic: many paid providers expose members-only feeds
/// under one of these path conventions.
const PRIVATE_PATH_MARKERS: &[&str] = &[
    "/private/",
    "/feed/private/",
    "/rss/private/",
    "/private-feed/",
    "/members/",
    "/member/",
    "/subscriber/",
];

/// A KNOWN paid/private feed provider, matched by host substring + (optionally) a
/// path/query marker specific to that provider. This is the **secondary**,
/// precision layer on top of the generic heuristic — it names providers so the
/// skip report can say *why* and so we catch provider-specific shapes that the
/// generic pass might rate as borderline. Data-driven and easy to extend: add a
/// row, don't touch the matcher.
struct KnownProvider {
    /// Substring that must appear in the URL host (lowercased), e.g.
    /// `substack.com`.
    host_contains: &'static str,
    /// Optional lowercased substring that must appear in the path-or-query for a
    /// match (a provider's private-feed marker). `None` = the host alone is
    /// enough (used for hosts that ONLY serve private/tokened feeds).
    marker: Option<&'static str>,
    /// Human-readable reason for the skip report.
    reason: &'static str,
}

/// The known-provider table. Covers paid NEWSLETTERS and private PODCASTS — an
/// RSS reader ingests both. Kept intentionally verbose/commented so it's obvious
/// what each row targets and safe to extend.
const KNOWN_PROVIDERS: &[KnownProvider] = &[
    // --- Paid newsletters -------------------------------------------------
    // Substack private feed: author.substack.com/feed/private/<token>.
    KnownProvider {
        host_contains: "substack.com",
        marker: Some("/feed/private/"),
        reason: "Substack private feed",
    },
    // Patreon RSS carries the member token as ?auth=.
    KnownProvider {
        host_contains: "patreon.com",
        marker: Some("auth="),
        reason: "Patreon member feed",
    },
    // Ghost members feed: ?uuid=<member-uuid> (or a members token path).
    KnownProvider {
        host_contains: "ghost.io",
        marker: Some("uuid="),
        reason: "Ghost members feed",
    },
    // Buttondown paid RSS uses a per-subscriber token in the path/query.
    KnownProvider {
        host_contains: "buttondown.email",
        marker: Some("token"),
        reason: "Buttondown premium feed",
    },
    KnownProvider {
        host_contains: "buttondown.com",
        marker: Some("token"),
        reason: "Buttondown premium feed",
    },
    // Beehiiv premium RSS carries a subscriber token.
    KnownProvider {
        host_contains: "beehiiv.com",
        marker: Some("token"),
        reason: "Beehiiv premium feed",
    },
    // Memberful-gated feeds (host or ?auth token).
    KnownProvider {
        host_contains: "memberful.com",
        marker: None,
        reason: "Memberful members feed",
    },
    // Pico / Steady member feeds.
    KnownProvider {
        host_contains: "pico.link",
        marker: None,
        reason: "Pico member feed",
    },
    KnownProvider {
        host_contains: "steadyhq.com",
        marker: None,
        reason: "Steady member feed",
    },
    // --- Private podcasts -------------------------------------------------
    // Supercast private podcast feeds (host serves tokened member feeds only).
    KnownProvider {
        host_contains: "supercast.com",
        marker: None,
        reason: "Supercast private podcast",
    },
    KnownProvider {
        host_contains: "supercast.tech",
        marker: None,
        reason: "Supercast private podcast",
    },
    // Supporting Cast private podcast feeds (supportingcast.fm).
    KnownProvider {
        host_contains: "supportingcast.fm",
        marker: None,
        reason: "Supporting Cast private podcast",
    },
    // RedCircle private/exclusive feeds.
    KnownProvider {
        host_contains: "redcircle.com",
        marker: Some("private"),
        reason: "RedCircle private podcast",
    },
    // Private/tokened Megaphone, Acast+, and Omny feeds carry an access token.
    KnownProvider {
        host_contains: "megaphone.fm",
        marker: Some("token"),
        reason: "Megaphone private podcast",
    },
    KnownProvider {
        host_contains: "acast.com",
        marker: Some("token"),
        reason: "Acast+ private podcast",
    },
    KnownProvider {
        host_contains: "omny.fm",
        marker: Some("token"),
        reason: "Omny private podcast",
    },
    // Apple / Spotify subscriber podcast feeds carry a per-listener token.
    KnownProvider {
        host_contains: "podcasts.apple.com",
        marker: Some("token"),
        reason: "Apple subscriber podcast",
    },
    KnownProvider {
        host_contains: "spotify.com",
        marker: Some("token"),
        reason: "Spotify subscriber podcast",
    },
];

/// Whether a URL may be **stored or published** as a feed URL at all.
///
/// This is the storage-side twin of the scheme check `net::check_scheme` applies
/// before fetching. The fetch side has always been safe, because nothing can
/// reach the network except through `net.rs` — but "safe to fetch" and "safe to
/// write down" are different questions, and only the first had an answer.
///
/// Two paths took a URL from outside and stored it with no validation at all:
/// `resolve_subscriptions` (any atproto client can write a subscription record
/// into a user's repo) and the OPML import (`xmlUrl` is whatever the file says).
/// `classify_feed_privacy` does not cover this — it deliberately returns
/// `Public` for an unparseable URL, on the stated assumption that "the add path
/// will reject it as malformed regardless", and those two paths are the ones
/// that never had an add path to do the rejecting.
///
/// Note that `javascript:alert(1)` and `file:///etc/passwd` both *parse* cleanly
/// as URLs, so parsing is not the check — the scheme is.
pub fn is_storable_feed_url(url: &str, allow_at_uri: bool) -> bool {
    // **`at://` is checked BEFORE `Url::parse`, because `Url::parse` cannot read
    // the form that matters.** `at://did:plc:…/…` fails to parse with *invalid
    // port number* — the colons in the DID are taken as a port separator — while
    // the handle form `at://alice.example.com/…` parses fine. So adding `"at"`
    // to the `matches!` below would appear to work and silently reject every
    // DID-based at-URI, which is all of them in practice.
    if let Some(rest) = crate::atproto::strip_at_prefix(url) {
        // **Recognised case-insensitively, stored canonically.** Schemes are
        // case-insensitive, so `At://` names the same publication — but
        // `feeds.url` is UNIQUE, so accepting both spellings is two rows for
        // one publication, the hazard the canonical-handle rule exists for.
        // Recognising it here rather than letting it fall through to the
        // generic checks is what keeps it out of the poller: nothing can fetch
        // it under any spelling.
        if !url.starts_with(crate::atproto::AT_URI_PREFIX) {
            return false;
        }
        // **This gates STORING only — polling is handled by exclusion**, by
        // kind rather than by any re-description of the URL, and
        // `FeedKind::POLLABLE` is the one place the why is written down.
        return allow_at_uri && is_storable_publication_uri(rest);
    }
    match Url::parse(url) {
        Ok(u) => {
            // No host check: for http(s) the `url` crate refuses every hostless
            // spelling at parse (`http://`, `https://?q`, `http:///` are all
            // "empty host") and turns `https:///x` into host `x`. A conjunct
            // requiring a non-empty host was unreachable — a test hunt listed
            // it as untested, and the honest answer was that no input reaches
            // it. The `Err` arm below is what refuses a hostless URL.
            matches!(u.scheme(), "http" | "https")
        }
        Err(_) => false,
    }
}

/// The body of an `at://` URI — `<did-or-handle>/<collection>/<rkey>` — judged
/// as a **storable feed**.
///
/// An allowlist entry, not a loosening: exactly one foreign collection is
/// accepted, `site.standard.publication`. The two paths this guard exists for
/// (`resolve_subscriptions`, the OPML import) take records written by any
/// atproto client, so "it is an at-URI" is not a reason to store it — only "it
/// is a publication this reader knows how to poll" is.
fn is_storable_publication_uri(rest: &str) -> bool {
    let mut parts = rest.split('/');
    let (Some(authority), Some(collection), Some(rkey)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    parts.next().is_none()
        && collection == crate::lexicon::nsid::STANDARD_PUBLICATION
        // **The rkey is validated against atproto's rules, not a blacklist.**
        //
        // A blacklist was the first attempt and it leaked twice: `is_control()`
        // is Unicode category Cc only, so a bidi override (Cf) passed — and it
        // reordered both the manage page and `scheduler.rs`'s `%feed.url` log
        // line. Worse, nothing stopped a query string or fragment living inside
        // the rkey, which satisfies the three-segment check and is exactly what
        // `classify_feed_privacy`'s `at://` exemption keys off: a token
        // smuggled there would have been declared public.
        //
        // An allowlist cannot leak the next character class someone finds.
        // The charset alone still admitted `.`, `..` and a 10 000-byte key;
        // `is_valid_rkey` carries the length and reserved-name rules too.
        && crate::atproto::is_valid_rkey(rkey)
        && is_storable_at_authority(authority)
}

/// The DID form only. `did:plc:` identifiers are validated by
/// [`crate::oauth::identity::is_atproto_did`] rather than a `did:` prefix check,
/// which would accept `did:plc:TOOSHORT`.
///
/// **The handle form is not storable, for the reason the canonical-handle rule
/// already gave:** `feeds.url` is UNIQUE, so `at://alice.example.com/…` beside
/// `at://did:plc:…/…` is two rows — two sidebar entries, and two polled copies
/// once the reader is wired — for one publication. A handle is a mutable name
/// for a DID; the row is keyed on the identity. Resolving a pasted or imported
/// handle to its DID is the reader's job (#165 already resolves DIDs to their
/// PDS), and belongs at input, not in storage.
fn is_storable_at_authority(authority: &str) -> bool {
    crate::oauth::identity::is_atproto_did(authority)
}

/// Classify whether a feed URL carries a secret credential in the URL itself.
///
/// Returns [`FeedPrivacy::Private`] (with a reason) when the URL looks like it
/// embeds a token / key / auth credential, else [`FeedPrivacy::Public`].
///
/// **Design — provider-agnostic first.** The primary defence is a generic
/// credential-in-URL heuristic that catches paid feeds from *any* provider, not
/// just the ones we've named; a secondary known-provider table adds precision
/// (and a nicer reason) for the common paid newsletters and private podcasts. We
/// deliberately **bias toward flagging**: a false-positive block of a public feed
/// is low-harm (the user just can't add that one feed yet), whereas a false
/// negative would leak a paid secret onto the public network — high-harm.
///
/// Detection (any one is sufficient):
/// 1. **Userinfo** — `https://user:pass@host/…` embeds credentials directly.
/// 2. **Known private-feed path markers** — `PRIVATE_PATH_MARKERS`
///    (`/feed/private/`, `/members/`, `/subscriber/`, …).
/// 3. **Credential query parameters** — a query key in `SECRET_QUERY_KEYS` with
///    a long/opaque value (Patreon `?auth=`, Ghost `?uuid=`, `?token=`, …).
/// 4. **High-entropy opaque token segments** — a long opaque blob (hex ≥ 16,
///    base64url ≥ 16, or a UUID) anywhere in the path or a query value, even
///    without a telltale name.
/// 5. **Known providers** — `KNOWN_PROVIDERS` host (+ optional marker) match.
///
/// An unparseable URL is treated as [`FeedPrivacy::Public`]: the add path rejects
/// a malformed URL downstream anyway, and we don't want a parse quirk to
/// misclassify.
pub fn classify_feed_privacy(url: &str) -> FeedPrivacy {
    // **`at://` is classified deliberately, and NOT doing so refused real
    // subscriptions.** An atproto rkey is a TID — 13 base32-sortable characters
    // — which is exactly what the generic "high-entropy token in path"
    // heuristic below is looking for. Measured: without this arm,
    // `at://did:plc:…/site.standard.publication/3lab2c4d5e6f7g8h` is
    // classified PRIVATE and the subscription refused, while the DID form slips
    // through only because it fails to parse as a `Url` at all.
    //
    // `Public` is the right answer: a publication is a public record in a
    // public repo and the rkey is a handle, not a secret, so there is no
    // private/paid shape for this scheme to carry.
    if let Some(rest) = crate::atproto::strip_at_prefix(url) {
        // A non-canonical scheme spelling is an at-URI this reader will not
        // store, not an unparseable string for the `Err(_) => Public` arm below
        // to wave through. Fail closed.
        if !url.starts_with(crate::atproto::AT_URI_PREFIX) {
            return FeedPrivacy::Private("non-canonical at:// scheme spelling".to_string());
        }
        // **Only a WELL-FORMED publication URI is exempt.** The first version
        // of this was a bare prefix match, which declared any attacker-chosen
        // string starting `at://` safe to publish — skipping the userinfo
        // check, the known-provider table, the private-path markers, the
        // secret-query keys and the entropy heuristics all at once. That is a
        // regression against every one of them, on a path
        // (`rename_subscription`) where this function is the only gate and the
        // value is written to the user's PUBLIC repo.
        //
        // Anything else falls through to the generic checks below, which is
        // where a credential-bearing string belongs.
        if is_storable_publication_uri(rest) {
            return FeedPrivacy::Public;
        }
        // **Malformed `at://` is REFUSED, not passed through.** Falling through
        // reaches `Url::parse`, which fails on the DID form and lands on the
        // `Err(_) => Public` arm below — whose justification is "the add path
        // will reject it as a malformed URL regardless".
        //
        // **Defence in depth, not a live gate.** This comment used to say the
        // justification is false on the `rename_subscription` path, "where this
        // function is the only gate". That stopped being true when storability
        // moved ahead of privacy on the repoint: a review then found no
        // production caller can reach this arm at all — add pre-checks the
        // `at://` prefix, rename and OPML and `resolve_subscriptions` all
        // refuse a non-storable URL first. It stays because a fail-closed
        // branch is worth its keep for the next caller that arrives without
        // one, and because deleting a guard on the grounds that nothing
        // currently reaches it is how the next one gets it wrong. It is not
        // load-bearing today, and saying so is the honest version.
        return FeedPrivacy::Private("not a well-formed at:// publication URI".to_string());
    }
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        // Can't parse => the add path will reject it as a malformed URL regardless.
        Err(_) => return FeedPrivacy::Public,
    };

    // (1) Userinfo (`https://user:pass@host/…`) — credentials in the authority.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return FeedPrivacy::Private("credentials in URL userinfo".to_string());
    }

    let path_lower = parsed.path().to_ascii_lowercase();
    let query_lower = parsed.query().unwrap_or("").to_ascii_lowercase();
    let host_lower = parsed.host_str().unwrap_or("").to_ascii_lowercase();

    // (0) Public-feed allowlist. A handful of large, fully-public feed shapes
    // carry a high-entropy-looking id in the query that would otherwise trip the
    // generic entropy heuristic. YouTube channel/playlist RSS
    // (`youtube.com/feeds/videos.xml?channel_id=UC…` / `?playlist_id=PL…`) is the
    // canonical way any reader subscribes to a channel — the id is a PUBLIC
    // handle, not a secret. Allowlist it before the generic checks so we don't
    // false-block it. (Userinfo / known-provider markers are checked below and
    // still apply, so this can't be used to smuggle a credential.)
    if is_public_youtube_feed(&host_lower, &path_lower, &parsed) {
        return FeedPrivacy::Public;
    }

    // (5) Known-provider precision layer (checked early so its specific reason
    // wins over a generic one). Host substring + optional path/query marker.
    for kp in KNOWN_PROVIDERS {
        if host_lower.contains(kp.host_contains) {
            let marker_ok = match kp.marker {
                None => true,
                Some(m) => {
                    let m = m.to_ascii_lowercase();
                    path_lower.contains(&m) || query_lower.contains(&m)
                }
            };
            if marker_ok {
                return FeedPrivacy::Private(kp.reason.to_string());
            }
        }
    }

    // (2) Known private-feed path markers.
    for marker in PRIVATE_PATH_MARKERS {
        if path_lower.contains(marker) {
            return FeedPrivacy::Private(format!("private feed path `{marker}`"));
        }
    }

    // (3) Credential query parameters with a long/opaque value.
    for (k, v) in parsed.query_pairs() {
        let key = k.as_ref().to_ascii_lowercase();
        if SECRET_QUERY_KEYS.iter().any(|sk| *sk == key) && value_is_opaque(v.as_ref()) {
            return FeedPrivacy::Private(format!("credential query parameter `{key}`"));
        }
    }

    // (4) High-entropy opaque token segments (an embedded key/token with no
    // telltale name): hex ≥ 16, base64url ≥ 16, or a UUID, in path or query.
    // The dominant real-world private-podcast shape delivers the token as a
    // *filename* (`<token>.rss` / `<token>.xml`) or affixed inside a larger
    // segment (`feed-<uuid>`), so [`segment_hides_secret`] strips a trailing feed
    // extension AND scans dot/underscore/hyphen-delimited sub-parts, not just the
    // whole segment.
    for seg in parsed.path().split('/').filter(|s| !s.is_empty()) {
        if segment_hides_secret(seg) {
            return FeedPrivacy::Private("high-entropy token in path".to_string());
        }
    }
    for (_, v) in parsed.query_pairs() {
        if looks_like_embedded_secret(v.as_ref()) {
            return FeedPrivacy::Private("high-entropy token in query".to_string());
        }
    }

    FeedPrivacy::Public
}

/// Whether a *named* credential query value (`?token=<v>`) is long/opaque enough
/// to count as a secret. A short value (e.g. an enum like `?token=none`) is not.
/// We treat a UUID, or anything ≥ 8 chars that isn't an obvious plain word, as
/// opaque — named credential keys already signal intent, so the length bar is
/// low.
fn value_is_opaque(v: &str) -> bool {
    if v.is_empty() {
        return false;
    }
    if is_uuid(v) {
        return true;
    }
    v.len() >= 8
}

/// Heuristic: does `s` look like an embedded secret (an opaque high-entropy
/// token), as opposed to an ordinary slug or word? Matches a UUID, a hex string
/// ≥ 16 chars, or a base64url-ish blob ≥ 16 chars that mixes letters and digits
/// and isn't a hyphen/dot slug. Deliberately strict so it only fires on things
/// that really look like keys — the named-marker and known-provider checks cover
/// the rest.
fn looks_like_embedded_secret(s: &str) -> bool {
    if is_uuid(s) {
        return true;
    }
    // Hex string ≥ 16 chars (e.g. a 32-char MD5-ish token).
    if s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // base64url-ish opaque blob ≥ 16 chars.
    if s.len() < 16 {
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
    // Must be plausibly token-charset: base64url alphabet only. `=` is accepted
    // as base64 padding (it only ever appears trailing on a real blob, so a
    // padded base64url token like `…dnc=` still counts).
    let token_chars = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '='))
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
    // repeat a small set. Require >= 10 distinct chars for a 16+ char blob.
    let mut seen = std::collections::HashSet::new();
    for c in s.chars() {
        seen.insert(c.to_ascii_lowercase());
    }
    seen.len() >= 10
}

/// Known feed/file extensions a token filename may wear (`<token>.rss`,
/// `<token>.xml`, …). Stripped before the whole-segment secret test so a
/// tokened *filename* — the dominant private-podcast URL shape — is still caught.
const FEED_EXTENSIONS: &[&str] = &["rss", "xml", "atom", "json", "rss20"];

/// Whether a single path segment hides an embedded secret. Beyond the plain
/// whole-segment [`looks_like_embedded_secret`] test, this also catches the two
/// real-world shapes that wrap a token so the whole segment is no longer a clean
/// blob:
///
/// 1. **Token-as-filename** — `<token>.rss` / `<token>.xml`: strip a trailing
///    feed extension and re-test the stem.
/// 2. **Token affixed inside a larger segment** — `feed-<uuid>`, `<token>.xml`,
///    `pod_<hex32>`: split on `.`/`_`/`-` and test each sub-part, so a
///    high-entropy blob delimited by an affix is still found.
fn segment_hides_secret(seg: &str) -> bool {
    if looks_like_embedded_secret(seg) {
        return true;
    }
    // (1) Strip a trailing known feed extension and re-test the stem.
    if let Some((stem, ext)) = seg.rsplit_once('.') {
        if FEED_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
            && looks_like_embedded_secret(stem)
        {
            return true;
        }
    }
    // (2) A UUID embedded with an affix (`feed-<uuid>`, `<uuid>-audio`) — the
    // `-` delimiters inside the UUID mean a naive split can't see it, so scan for
    // a canonical UUID substring directly.
    if contains_uuid(seg) {
        return true;
    }
    // (3) Scan `.`/`_`/`-`-delimited sub-parts for a high-entropy blob affixed to
    // an ordinary word (`pod_<hex32>`, `<hex32>.mp3`). Only fires on multi-part
    // segments (a single-part segment was already covered by the whole-segment
    // test above), so a plain `my-normal-post-slug` — whose parts are short
    // dictionary words — can't trip it.
    if seg.contains(['.', '_', '-']) {
        for part in seg.split(['.', '_', '-']).filter(|p| !p.is_empty()) {
            if looks_like_embedded_secret(part) {
                return true;
            }
        }
    }
    false
}

/// Whether `s` contains a canonical 8-4-4-4-12 UUID as a substring (allowing an
/// affix on either side, e.g. `feed-<uuid>` or `<uuid>-audio`). Slides a 36-char
/// window over the string and tests each with [`is_uuid`].
fn contains_uuid(s: &str) -> bool {
    const UUID_LEN: usize = 36; // 8+4+4+4+12 + 4 hyphens.
    let bytes = s.as_bytes();
    if bytes.len() < UUID_LEN {
        return false;
    }
    // ASCII-only window: a UUID is pure ASCII hex/hyphen, so byte indexing is
    // safe here (a multi-byte char in the window just fails is_uuid).
    (0..=bytes.len() - UUID_LEN).any(|i| s.get(i..i + UUID_LEN).map(is_uuid).unwrap_or(false))
}

/// Whether this is a PUBLIC YouTube channel/playlist RSS feed
/// (`www.youtube.com/feeds/videos.xml?channel_id=UC…` or `?playlist_id=PL…`).
/// The channel/playlist id is a public handle, not a credential, so these feeds
/// must NOT be flagged by the generic entropy heuristic. We require the exact
/// public host + feeds path + one of the two public id keys, so this narrow
/// allowlist can't be abused to smuggle a `?token=` past classification.
fn is_public_youtube_feed(host_lower: &str, path_lower: &str, parsed: &Url) -> bool {
    let host_ok = host_lower == "youtube.com"
        || host_lower == "www.youtube.com"
        || host_lower.ends_with(".youtube.com");
    if !host_ok || !path_lower.starts_with("/feeds/videos.xml") {
        return false;
    }
    // Only the public id keys may appear; a `token`/`auth`/… key means treat it
    // as a normal (potentially private) URL and let the checks below run.
    parsed.query_pairs().all(|(k, _)| {
        let k = k.as_ref().to_ascii_lowercase();
        k == "channel_id" || k == "playlist_id" || k == "user"
    })
}

/// Whether `s` is a canonical 8-4-4-4-12 hyphenated UUID (any hex case).
fn is_uuid(s: &str) -> bool {
    let groups = [8usize, 4, 4, 4, 12];
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != groups.len() {
        return false;
    }
    parts
        .iter()
        .zip(groups.iter())
        .all(|(p, &n)| p.len() == n && p.chars().all(|c| c.is_ascii_hexdigit()))
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
    /// The feed was fetched, but **this instance** could not sanitize its
    /// bodies now: every sanitize permit stayed held — by sanitizes other
    /// feeds' polls gave up on — for the whole timeout (#226). Not the feed's
    /// fault, so nothing is stored and nothing counts against it: no entries,
    /// no validators, no error. It is polled again on its normal cadence.
    Deferred,
    /// The fetch or parse failed; the feed was left intact and skipped. Carries
    /// the suggested backoff before the next attempt. Never a panic.
    ///
    /// **`kind` and `detail` are the reason, and they exist because their
    /// absence cost a production investigation.** Until #159 the error was
    /// logged here and discarded, so `feeds` recorded that a feed was failing
    /// and never why — which is how sixty feeds broken by our own 304 handling
    /// looked exactly like sixty dead blogs. `kind` is a small closed
    /// vocabulary so failures can be counted by cause; `detail` is the message
    /// for a human reading one row.
    Failed {
        backoff: Duration,
        kind: FailureKind,
        detail: String,
    },
}

/// Why a poll failed, as a closed set.
///
/// Closed on purpose: the point is to *count* failures by cause, and a free-text
/// kind cannot be counted. The detail string carries whatever else matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The request never produced a response — DNS, TLS, timeout, connection
    /// refused, or a refusal by the SSRF guard.
    Fetch,
    /// A response arrived with a non-success status.
    Status,
    /// The body was too large, or reading it failed part-way.
    Body,
    /// The body arrived and is not a feed this parser can read.
    Parse,
}

/// What the poller does with a feed row.
///
/// **A column, not a predicate.** "Can this be fetched?" used to be
/// `substr(url, 1, 5) = 'at://'` spliced into four statements, with a fifth
/// reader that had already drifted from them. Deciding it once, in Rust, at
/// insert — and storing the answer — means SQL cannot disagree with the
/// fetcher, and wiring the standard.site reader becomes a change to this
/// function plus a dispatch, rather than an edit to every statement that
/// mentions a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedKind {
    /// An RSS/Atom/JSON feed document fetched over http(s).
    Rss,
    /// An `at://…/site.standard.publication/…` record pair in somebody's PDS,
    /// read by `standard_site` and pollable since 0.4.0.
    Publication,
    /// Any other `at://` row: another collection, or a spelling the storage
    /// guard would refuse. Rows like this predate that guard. **Never
    /// pollable** — handing one to the standard.site reader would fail its
    /// collection check every tick and publish it as an unreachable publisher —
    /// and counted as unpollable so the capacity it holds stays visible.
    Unsupported,
}

impl FeedKind {
    /// The kinds the scheduler may select: RSS, and since 0.4.0 standard.site
    /// publications. [`FeedKind::Unsupported`] is the kind it never selects.
    ///
    /// **This is the canonical home of the exclusion; the other sites point
    /// here.** It used to be a SQL string predicate in `store`, carrying
    /// its own copy of the rule — which is how one reader (`count_feeds`) came
    /// to drift from it unnoticed.
    ///
    /// Why an unpollable kind is skipped rather than failed: an `Unsupported`
    /// row names nothing either reader can fetch — another collection, a handle,
    /// a non-canonical spelling — so polling it could only fail.
    /// Handing such a row to the poller does not leave the feature dormant — it
    /// manufactures one permanent failure per row, which the public cause
    /// histogram then reports as an unreachable publisher. Unsupported is not
    /// broken, and telling those apart is the entire reason a failure cause is
    /// recorded. (Rows like this exist: subscriptions written by other clients
    /// before this reader refused the scheme.)
    ///
    /// **`store::count_feeds` is deliberately NOT filtered by this.** The
    /// global ceiling bounds storage on a small box, and an unpollable row
    /// occupies a row, so it counts against the cap. An earlier version of this
    /// note listed the readers without naming the exception, which read as
    /// completeness it did not have: a review found the ceiling consuming
    /// capacity that appeared on no surface, since `/stats` measures the poller
    /// and excludes these rows. `/admin/metrics` renders
    /// `store::unpollable_feeds` for exactly that reason.
    /// **Adding a kind here makes a population of rows due all at once.**
    /// `store::due_feeds` orders `next_poll IS NOT NULL, next_poll ASC`, so a
    /// row with no scheduled poll sorts ahead of every dated one. Rows that
    /// were never pollable have no schedule, so the boot that reclassifies
    /// them hands the poller a block of N rows that outrank every regular
    /// feed until they drain — `ceil(N / batch)` ticks, measured, during which
    /// `/stats` shows a climbing backlog and nothing logs why. Bounded and
    /// harmless at ninety feeds; not at ten thousand. Whoever wires the next
    /// kind should seed or stagger `next_poll` for the rows it admits.
    pub const POLLABLE: &'static [FeedKind] = &[FeedKind::Rss, FeedKind::Publication];

    /// The kinds whose entries the retention **window** applies to.
    ///
    /// **Age is the wrong retention policy for an archive, and that is a
    /// measurement, not a preference.** Three real publications, read through
    /// `standard_site::fetch` on 2026-09-27: Standard.site's newest document was
    /// **131 days** old, Annotated's **109** (with its oldest at 373), and minus
    /// listens' **241**. Against the instance default window of 14 days, every
    /// one of them stored **zero** rows — a green poll, an empty feed, and an
    /// info log as the only trace. Long-form publishing is not news-paced.
    ///
    /// So a publication is bounded by COUNT instead: `max_entries_per_feed` in
    /// `insert_entries`, which caps a feed at the newest N plus up to N starred.
    /// That is a real bound — it is what keeps this from being "retention off" —
    /// and it is the one that suits a source whose value is its archive.
    ///
    /// A generous absolute ceiling still applies (`publication_retention_days`),
    /// because "not aged out" must not mean "immortal": rows belonging to a feed
    /// nobody polls any more would otherwise never be reaped at all, and the
    /// per-feed trim only runs when a poll stores something.
    pub const AGED: &'static [FeedKind] = &[FeedKind::Rss];

    /// The column value. Stable — it is persisted.
    pub fn as_str(self) -> &'static str {
        match self {
            FeedKind::Rss => "rss",
            FeedKind::Publication => "publication",
            FeedKind::Unsupported => "unsupported",
        }
    }

    /// A closed vocabulary on the way back in: a kind written by a newer build
    /// is not silently read as one this build knows.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "rss" => Some(FeedKind::Rss),
            "publication" => Some(FeedKind::Publication),
            "unsupported" => Some(FeedKind::Unsupported),
            _ => None,
        }
    }

    /// What a URL will be stored as. The only place the question is asked.
    ///
    /// `store::feeds.kind` is a cache of this function, re-derived from the URL
    /// on every start and on every upsert, so a change here needs no migration
    /// and SQL cannot hold an opinion of its own about what a row is.
    ///
    /// **Case-insensitive on purpose.** An earlier version was case-sensitive,
    /// with a test pinning that a mixed-case `At://` row IS handed to the
    /// poller — reasoning that if Rust does not call it an at-URI, neither
    /// should anything else. That was wrong in the direction that matters: URL
    /// schemes are case-insensitive, so `Url::parse` folds `At://` to scheme
    /// `at` and `net::check_scheme` refuses it (the DID form does not parse at
    /// all). The row could only fail, every tick, forever, and be published in
    /// the `fetch` bucket as an unreachable publisher. Storing a non-canonical
    /// spelling is separately refused, because `feeds.url` is UNIQUE.
    pub fn of(url: &str) -> Self {
        match crate::atproto::strip_at_prefix(url) {
            // **Only a URI the storage guard would accept is a publication.**
            // Since publications became pollable, "it is an at-URI" is no longer
            // a safe enough reason: another collection would be polled, fail,
            // and back off forever while reading as an unreachable publisher.
            // The canonical lowercase scheme too, for the same reason: storage
            // refuses `At://` (#183), and a legacy row spelled that way would
            // otherwise be polled and fail its parse every tick.
            Some(rest) if url.starts_with("at://") && is_storable_publication_uri(rest) => {
                FeedKind::Publication
            }
            Some(_) => FeedKind::Unsupported,
            None => FeedKind::Rss,
        }
    }
}

/// Apply a [`PollOutcome`] to the feed's row: settle the error columns AND
/// reschedule it. **Both halves, always, from one place.**
///
/// The scheduler did this inline. `web::add_subscription` then copied only the
/// first half, so a poll taken off the scheduler could clear a stale failure's
/// COUNT while leaving the feed parked on its stale backoff HORIZON — reported
/// healthy, not polled for up to 24h. And its failures fed `consecutive_errors`
/// with no reschedule, so repeated Subscribe clicks drove a shared feed to the
/// 24h ceiling for every subscriber. Two copies of a sequence drift; this is
/// the one copy.
///
/// `cadence` is the interval to use on success; the scheduler derives it from
/// the feed's hint, a direct caller passes the configured default. A store
/// failure is logged and the reschedule still attempted, so a hiccup writing
/// the count cannot strand the feed at a NULL `next_poll` that `due_feeds`
/// would then re-poll every tick.
pub async fn settle_poll(
    pool: &sqlx::SqlitePool,
    url: &str,
    outcome: &PollOutcome,
    cadence: Duration,
) {
    let delay = match outcome {
        // A 304 is a healthy poll: it proves the fetch worked and nothing changed.
        PollOutcome::Updated { .. } | PollOutcome::NotModified => {
            if let Err(err) = crate::store::reset_feed_errors(pool, url).await {
                tracing::warn!(feed = %url, %err, "failed to reset feed error count");
            }
            cadence
        }
        // Neither a success nor the feed's failure: leave its error count as
        // it is, and keep its ordinary schedule.
        PollOutcome::Deferred => cadence,
        PollOutcome::Failed {
            backoff,
            kind,
            detail,
        } => {
            // Recompute from the feed's REAL consecutive-error count so a
            // persistently-broken feed climbs toward the ceiling instead of
            // retrying at the floor forever; fall back to the outcome's floor.
            match crate::store::bump_feed_errors(pool, url, *kind, detail).await {
                Ok(count) => backoff_for(count.max(1) as u32),
                Err(err) => {
                    tracing::warn!(feed = %url, %err, "failed to bump feed error count; using floor backoff");
                    *backoff
                }
            }
        }
    };
    if let Err(err) = crate::store::set_next_poll(pool, url, delay).await {
        tracing::error!(feed = %url, %err, "failed to persist next_poll");
    }
}

/// Cap on a failure detail, applied where the string is BUILT.
///
/// It was originally applied only inside `store::bump_feed_errors`, which
/// bounded the database row and nothing else — and widening
/// [`PollOutcome::Failed`] with this field had quietly opened a second sink:
/// `web::add_subscription` logs `?outcome` at INFO on a user-facing request
/// path. Bounding at construction bounds every sink, including ones added
/// later by someone who never reads this comment.
pub const MAX_FAILURE_DETAIL_CHARS: usize = 300;

/// Render an error chain into a bounded [`PollOutcome::Failed`] detail.
///
/// `{e:#}` — the anyhow CHAIN, not just the outermost context. "fetching
/// https://…" alone says nothing; the cause is the part that would have named
/// the 304 bug in #159.
pub fn failure_detail(err: impl std::fmt::Display) -> String {
    let s = err.to_string();
    if s.chars().count() <= MAX_FAILURE_DETAIL_CHARS {
        return s;
    }
    s.chars().take(MAX_FAILURE_DETAIL_CHARS).collect()
}

impl FailureKind {
    /// The stable string stored in `feeds.last_error_kind` and aggregated on
    /// `/stats`. Changing one of these silently rewrites history in the
    /// aggregate, so they are spelled out rather than derived from the variant.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::Status => "status",
            Self::Body => "body",
            Self::Parse => "parse",
        }
    }

    /// Read back a persisted `last_error_kind`. `None` for anything this
    /// version does not know, so a row written by a newer build is not
    /// silently attributed to a cause this one recognises — the same contract
    /// [`crate::metrics::Backend::parse`] keeps for the same reason.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "fetch" => Some(Self::Fetch),
            "status" => Some(Self::Status),
            "body" => Some(Self::Body),
            "parse" => Some(Self::Parse),
            _ => None,
        }
    }

    /// Every variant, so a test can assert over the whole set rather than a
    /// list that drifts when a variant is added.
    pub const ALL: [Self; 4] = [Self::Fetch, Self::Status, Self::Body, Self::Parse];
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
        // Ignore ambient proxy configuration, for the same reason the pinned
        // client does: a proxied request hands the hostname to the proxy to
        // resolve, so `net`'s IP checks never see the address they are meant to
        // vet. See `net::build_pinned_client`.
        .no_proxy()
        // No auto-redirect: net::guarded_get follows + re-validates each hop.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build feed HTTP client")
}

/// Compute the backoff for the `n`th consecutive failure (1-based), clamped to
/// `BACKOFF_MAX`. Exponential in the error count so transient blips retry soon
/// while a durably-broken feed backs off toward daily.
///
/// The scheduler passes the feed's persisted `consecutive_errors` count (see
/// [`crate::store::bump_feed_errors`]) so a feed that keeps failing actually
/// climbs toward `BACKOFF_MAX` instead of retrying at the floor forever.
pub fn backoff_for(consecutive_errors: u32) -> Duration {
    let n = consecutive_errors.max(1);
    // Saturating shift: base * 2^(n-1), capped. Avoids overflow for large n.
    let factor = 1u64.checked_shl(n.saturating_sub(1)).unwrap_or(u64::MAX);
    let secs = BACKOFF_BASE
        .as_secs()
        .saturating_mul(factor)
        .min(BACKOFF_MAX.as_secs());
    Duration::from_secs(secs)
}

/// Poll one feed by **what it is**: an RSS/Atom/JSON document over HTTP, or a
/// standard.site publication read from its author's PDS.
///
/// The single entry point the scheduler calls, so the choice of reader lives
/// with [`FeedKind`] and not in the poll loop. Same contract as [`poll_feed`]:
/// `Err` is a broken local store, never a misbehaving source.
pub async fn poll_feed_by_kind(
    pool: &SqlitePool,
    client: &Client,
    config: &crate::config::Config,
    feed: &Feed,
) -> Result<PollOutcome> {
    match FeedKind::of(&feed.url) {
        FeedKind::Rss => poll_feed(pool, client, feed, config.max_entries_per_feed).await,
        FeedKind::Publication => poll_publication(pool, client, config, feed).await,
        // Never selected: `due_feeds` reads only POLLABLE kinds. A defensive
        // failure rather than a panic if a caller hands one in anyway.
        FeedKind::Unsupported => Ok(PollOutcome::Failed {
            backoff: backoff_for(1),
            kind: FailureKind::Parse,
            detail: failure_detail(format!("{} is not a feed this reader can poll", feed.url)),
        }),
    }
}

/// What a failed publication read is filed under in the cause histogram.
///
/// **`Fetch` means the request never produced a response**, so it is the
/// fallback, not the default answer: a PLC directory or PDS that answered —
/// with a 404 for a tombstoned DID, `RepoNotFound`, `RepoDeactivated` — is
/// `Status`, and an answer that was not what it claimed to be is `Parse`. Filed
/// as `Fetch`, a deleted account read as its server being down (found in
/// review).
fn publication_failure_kind(err: &anyhow::Error) -> FailureKind {
    use crate::atproto::{AtProtoError, DidResolutionCause};
    for cause in err.chain() {
        if cause.is::<crate::standard_site::NotAPublication>() || cause.is::<serde_json::Error>() {
            return FailureKind::Parse;
        }
        match cause.downcast_ref::<AtProtoError>() {
            Some(AtProtoError::Xrpc { .. }) => return FailureKind::Status,
            Some(AtProtoError::DidResolution { cause, .. }) => {
                return match cause {
                    DidResolutionCause::Status => FailureKind::Status,
                    DidResolutionCause::UnsupportedMethod | DidResolutionCause::NoPdsEndpoint => {
                        FailureKind::Parse
                    }
                    DidResolutionCause::NotAPublicTarget => FailureKind::Fetch,
                }
            }
            _ => {}
        }
    }
    FailureKind::Fetch
}

/// Read a standard.site publication from its author's PDS and store it.
///
/// A source failure — an unparseable URI, an unreachable PLC directory or
/// PDS, a walk that failed — is a [`PollOutcome::Failed`] with backoff, like an
/// RSS fetch failure, so `settle_poll` and `/stats` treat both kinds alike.
/// Only a broken local store is an `Err`, which `store_publication` decides.
async fn poll_publication(
    pool: &SqlitePool,
    client: &Client,
    config: &crate::config::Config,
    feed: &Feed,
) -> Result<PollOutcome> {
    poll_publication_group(pool, client, config, std::slice::from_ref(feed))
        .await
        .pop()
        .unwrap_or_else(|| Err(anyhow::anyhow!("no outcome for {}", feed.url)))
}

/// Read several publications **from one repo** with one walk of its documents
/// (`standard_site::fetch_repo`), and store each. One outcome per feed, in
/// order. The caller groups by repo; a feed from another repo, or one whose
/// URL is not a publication URI, gets its own failure and does not affect the
/// rest.
///
/// **Why one walk:** cost scales with the repo, not the publication. Nine
/// publications in one repo were nine full walks of its documents.
pub async fn poll_publication_group(
    pool: &SqlitePool,
    client: &Client,
    config: &crate::config::Config,
    feeds: &[Feed],
) -> Vec<Result<PollOutcome>> {
    let failed = |kind: FailureKind, detail: String| -> Result<PollOutcome> {
        Ok(PollOutcome::Failed {
            backoff: backoff_for(1),
            kind,
            detail: failure_detail(detail),
        })
    };
    let uris: Vec<Option<crate::standard_site::AtUri>> = feeds
        .iter()
        .map(|f| crate::standard_site::AtUri::parse(&f.url))
        .collect();
    let Some(did) = uris.iter().flatten().next().map(|u| u.authority.clone()) else {
        return feeds
            .iter()
            .map(|f| {
                failed(
                    FailureKind::Parse,
                    format!("{} is not a readable at:// URI", f.url),
                )
            })
            .collect();
    };
    // Only the feeds of that repo with a publication URI are read together.
    let readable: Vec<usize> = (0..feeds.len())
        .filter(|&i| {
            uris[i].as_ref().is_some_and(|u| {
                u.authority == did && u.collection == crate::lexicon::nsid::STANDARD_PUBLICATION
            })
        })
        .collect();
    let rkeys: Vec<String> = readable
        .iter()
        .map(|&i| uris[i].as_ref().unwrap().rkey.clone())
        .collect();

    // **One deadline for the whole read.** It is otherwise bounded only per
    // request (FETCH_TIMEOUT x MAX_LIST_PAGES): hours, against a repo that
    // pages slowly, all of it holding up the publication loop.
    let fetched = tokio::time::timeout(
        config.publication_read_deadline,
        crate::standard_site::fetch_repo(client, &config.oauth.plc_directory, &did, &rkeys),
    )
    .await;
    let mut reads: Vec<Option<anyhow::Result<crate::standard_site::PublicationRead>>> =
        feeds.iter().map(|_| None).collect();
    let repo_failure = match fetched {
        Ok(Ok(per)) => {
            for (slot, read) in readable.iter().zip(per) {
                reads[*slot] = Some(read);
            }
            None
        }
        Ok(Err(err)) => Some((publication_failure_kind(&err), format!("{err:#}"))),
        Err(_) => Some((
            FailureKind::Fetch,
            format!(
                "the read did not finish within {:?}",
                config.publication_read_deadline
            ),
        )),
    };

    let (retention_days, retention_hard_days) = config.retention_for(FeedKind::Publication);
    let mut out = Vec::with_capacity(feeds.len());
    for (i, feed) in feeds.iter().enumerate() {
        let outcome = match (reads[i].take(), &repo_failure) {
            (Some(Ok(read)), _) => {
                crate::standard_site::store_publication(
                    pool,
                    &feed.url,
                    read,
                    config.max_entries_per_feed,
                    retention_days,
                    retention_hard_days,
                )
                .await
            }
            (Some(Err(err)), _) => failed(publication_failure_kind(&err), format!("{err:#}")),
            (None, Some((kind, detail))) if readable.contains(&i) => failed(*kind, detail.clone()),
            (None, _) => failed(
                FailureKind::Parse,
                format!("{} is not a publication in {did}", feed.url),
            ),
        };
        out.push(outcome);
    }
    out
}

/// How long one entry's sanitize may run before the poll gives up on it (#226).
///
/// **Seconds, not milliseconds, on purpose.** Real bodies sanitize in about
/// 3.5 ms at most on an M-series Mac (production's largest body is 87 KB), so
/// 5 s is over 1,000x that: a much slower shared Fly vCPU, or one busy with
/// four polls at once, still never trips it on a real article. What it does
/// catch is the super-linear inputs ammonia has — 2 MiB of `&` runs take
/// ~2.4 s in release on that Mac, U+00A0 runs ~3.4 s, nested `<div>`s ~37 s,
/// and 8 MiB of `&` never finished in ten minutes — where the choice is
/// between waiting and giving up, and a timeout is a false positive only for
/// a body that is already nearly pathological.
pub(crate) const SANITIZE_TIMEOUT: Duration = Duration::from_secs(5);

/// How many ingest sanitizes may run at once, process-wide (#226).
///
/// The poller's default `FEATHERREADER_POLL_CONCURRENCY` (4): in ordinary
/// operation every poll in flight gets a permit and none ever waits. What it
/// bounds is the bad case. A timed-out sanitize cannot be cancelled — ammonia
/// runs to completion on its blocking thread — and its permit is held until it
/// does, so hostile feeds can tie up at most this many blocking threads (and
/// CPUs) however many of them there are. Beyond that a poll waits for a permit
/// **asynchronously**, and for at most [`SANITIZE_TIMEOUT`] — see
/// [`sanitize_off_runtime`] for why that wait is bounded too.
pub(crate) const SANITIZE_CONCURRENCY: usize = 4;

/// The permits behind [`SANITIZE_CONCURRENCY`].
static SANITIZE_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(SANITIZE_CONCURRENCY);

/// The feeds with a sanitize still running, and how many of those a poll has
/// **given up on** (#226).
///
/// **Why:** a sanitize that timed out keeps running — ammonia cannot be
/// interrupted — and the feed's next poll is a full fetch (its validators were
/// not saved). Without this, every retry started another sanitize, and one
/// hostile feed could come to hold every permit and starve every other feed.
/// With it, a feed with a sanitize still running is not given another until
/// it returns: **one feed, at most one thread**, however often it is polled.
///
/// **Counted from the start**, by a guard the blocking closure owns, and
/// released only when ammonia returns or panics. Counting only once a poll
/// gave up let overlapping polls of one feed (the scheduler and a subscribe
/// POST, which polls inline) each start one before any timed out, and never
/// counted a sanitize whose poll was dropped mid-way (a client disconnecting).
/// A feed whose running sanitize was given up on is refused as its own
/// failure ([`SanitizeGaveUp::StillRunning`]); one whose sanitize is merely
/// in progress, or orphaned by a dropped poll, defers
/// ([`SanitizeGaveUp::Busy`]).
///
/// **By feed, not by body hash:** a hash let a feed dodge the refusal by
/// serving different bytes each fetch (a nonce, or another slow entry on
/// top), and it shared one feed's timeout with every other feed carrying the
/// same article.
pub(crate) struct InFlight(std::sync::Mutex<std::collections::BTreeMap<String, Slot>>);

/// One feed's sanitizes in [`InFlight`]. Removed when both are zero.
#[derive(Default)]
pub(crate) struct Slot {
    /// Still running, given up on or not.
    running: usize,
    /// Of those, given up on by their poll.
    abandoned: usize,
}

impl InFlight {
    pub(crate) const fn new() -> Self {
        InFlight(std::sync::Mutex::new(std::collections::BTreeMap::new()))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<String, Slot>> {
        // Nothing here can leave the map inconsistent, so a poisoned lock is
        // still a usable one.
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// [`AbandonGuard::state`]: running, not given up on.
const RUNNING: u8 = 0;
/// Given up on by its poll, and counted as abandoned in [`InFlight`].
const ABANDONED: u8 = 1;
/// Returned (or panicked); never counted again.
const DONE: u8 = 2;

/// One sanitize's standing in [`InFlight`], from registration until the
/// sanitize returns. The state is only read or changed with the map locked,
/// so "give up" and "return" cannot interleave: a sanitize that has already
/// returned is never counted as abandoned, and every count is taken back
/// exactly once.
struct AbandonGuard {
    set: &'static InFlight,
    feed: String,
    state: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

impl AbandonGuard {
    /// Register a sanitize for `feed`, unless one is already running: then
    /// why not — given up on (`StillRunning`) or merely in progress (`Busy`).
    fn register(set: &'static InFlight, feed: &str) -> Result<Self, SanitizeGaveUp> {
        let mut map = set.lock();
        let slot = map.entry(feed.to_owned()).or_default();
        if slot.abandoned > 0 {
            return Err(SanitizeGaveUp::StillRunning);
        }
        if slot.running > 0 {
            return Err(SanitizeGaveUp::Busy);
        }
        slot.running = 1;
        Ok(AbandonGuard {
            set,
            feed: feed.to_owned(),
            state: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(RUNNING)),
        })
    }

    /// The poll gave up on it: count it as abandoned, if still running.
    fn abandon(set: &'static InFlight, feed: &str, state: &std::sync::atomic::AtomicU8) {
        use std::sync::atomic::Ordering::SeqCst;
        let mut map = set.lock();
        if state.load(SeqCst) == RUNNING {
            state.store(ABANDONED, SeqCst);
            map.entry(feed.to_owned()).or_default().abandoned += 1;
        }
    }
}

impl Drop for AbandonGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::SeqCst;
        let mut map = self.set.lock();
        let was = self.state.swap(DONE, SeqCst);
        if let Some(slot) = map.get_mut(&self.feed) {
            slot.running = slot.running.saturating_sub(1);
            if was == ABANDONED {
                slot.abandoned = slot.abandoned.saturating_sub(1);
            }
            if slot.running == 0 && slot.abandoned == 0 {
                map.remove(&self.feed);
            }
        }
    }
}

/// The production [`InFlight`].
static IN_FLIGHT: InFlight = InFlight::new();

/// Where and for how long [`normalize_entries`] sanitizes. Production uses
/// [`SanitizeLimits::PRODUCTION`]; tests inject a short timeout and their own
/// permits and in-flight set, so an abandoned sanitize in one test cannot hold
/// up another.
#[derive(Clone, Copy)]
pub(crate) struct SanitizeLimits {
    pub(crate) permits: &'static tokio::sync::Semaphore,
    pub(crate) in_flight: &'static InFlight,
    pub(crate) timeout: Duration,
    /// What runs on the blocking pool: [`sanitize_body`] in production. A seam
    /// for tests only — one that panics, or that takes the remaining permits
    /// mid-poll — so the paths those reach are tested deterministically.
    pub(crate) sanitize: fn(&str) -> String,
}

impl SanitizeLimits {
    /// [`SANITIZE_PERMITS`], [`IN_FLIGHT`] and [`SANITIZE_TIMEOUT`].
    pub(crate) const PRODUCTION: SanitizeLimits = SanitizeLimits {
        permits: &SANITIZE_PERMITS,
        in_flight: &IN_FLIGHT,
        timeout: SANITIZE_TIMEOUT,
        sanitize: sanitize_body,
    };
}

/// An entry body as it is stored: [`sanitize_html_bounded`] to
/// [`MAX_CONTENT_HTML_BYTES`].
fn sanitize_body(raw: &str) -> String {
    sanitize_html_bounded(raw, MAX_CONTENT_HTML_BYTES)
}

/// Why [`sanitize_off_runtime`] produced no body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SanitizeGaveUp {
    /// Every permit stayed taken for the whole timeout — by sanitizes other
    /// polls gave up on, so not the polled feed's fault.
    NoPermit,
    /// The sanitize did not finish within the timeout (or the runtime is
    /// shutting down and cancelled it before it started).
    TimedOut,
    /// A sanitize of this feed's was already given up on and is still
    /// running ([`InFlight`]); refused without starting another. The feed's
    /// fault exactly as [`SanitizeGaveUp::TimedOut`] is.
    StillRunning,
    /// A sanitize of this feed's is still running but nobody gave up on it:
    /// an overlapping poll, or one dropped mid-sanitize ([`InFlight`]). Not
    /// started, and not the feed's fault: the poll defers, as for
    /// [`SanitizeGaveUp::NoPermit`].
    Busy,
}

/// [`sanitize_html_bounded`] on the blocking pool, under a permit and a
/// timeout.
///
/// **Never on an async worker**: ammonia is super-linear on some inputs (#226),
/// and inline it stalled a tokio worker — and the poller with it — for as long
/// as it ran. The permit is acquired asynchronously and moved INTO the blocking
/// closure, so a sanitize the caller has given up on keeps it until ammonia
/// returns: the bound counts threads actually busy, not polls still waiting.
///
/// **The wait for a permit is bounded by the same timeout**, separately from
/// the sanitize. Permits held by abandoned sanitizes can stay taken for
/// minutes, and an unbounded wait would stall every poll behind them — and a
/// graceful shutdown, which drains the polls in flight, past Fly's
/// `kill_timeout`. So one entry costs a poll at most two timeouts.
///
/// **A feed with a sanitize still running is refused before any of that** —
/// no permit, no thread — until that sanitize finishes; see [`InFlight`].
async fn sanitize_off_runtime(
    feed: &str,
    raw: String,
    limits: SanitizeLimits,
) -> Result<String, SanitizeGaveUp> {
    // Registered before the permit wait, so overlapping polls of one feed
    // cannot both get past here. If the wait fails, or this future is
    // dropped before the spawn, the guard drops and the count goes with it.
    let guard = AbandonGuard::register(limits.in_flight, feed)?;
    let state = std::sync::Arc::clone(&guard.state);
    let permit = match tokio::time::timeout(limits.timeout, limits.permits.acquire()).await {
        Ok(Ok(permit)) => permit,
        // `Ok(Err(_))` is a closed semaphore, which this never does.
        Ok(Err(_)) | Err(_) => return Err(SanitizeGaveUp::NoPermit),
    };
    let sanitize = limits.sanitize;
    let task = tokio::task::spawn_blocking(move || {
        // Both released when ammonia returns — or panics — not when the poll
        // gives up.
        let _permit = permit;
        let _guard = guard;
        sanitize(&raw)
    });
    match tokio::time::timeout(limits.timeout, task).await {
        Ok(Ok(html)) => Ok(html),
        // A panic in the sanitizer propagates as it did when this ran inline.
        Ok(Err(err)) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
        Ok(Err(_)) | Err(_) => {
            // From now until it returns, this feed is refused.
            AbandonGuard::abandon(limits.in_flight, feed, &state);
            Err(SanitizeGaveUp::TimedOut)
        }
    }
}

/// Normalize a poll's entries, sanitizing each body off the async runtime
/// ([`sanitize_off_runtime`]). Returns the entries and whether a sanitize
/// timed out — or `None` when the poll should be **deferred**.
///
/// **After the first timeout no further body is sanitized in this poll**, so
/// one hostile feed costs at most one abandoned blocking thread per poll. What
/// stops the later entries is the per-feed refusal ([`InFlight`]): the
/// abandoned sanitize is still running, so [`sanitize_off_runtime`] refuses
/// each of them at once. The `timed_out` guard here is only a backup, for the
/// race in which that sanitize finishes between being given up on and the
/// next entry — without it, that entry would be sanitized after all. The
/// timed-out entry and every later entry with a body are returned with
/// `content_html: None` and `keep_stored_content: true`: an entry already
/// stored keeps the body it has, and a new one is stored without a body (the
/// reader shows its title and a link to the original). Nothing degraded is
/// ever built or stored in its place — no excerpt, no cut of the raw input.
///
/// **No permit is not a timeout.** It means other feeds' abandoned sanitizes
/// hold every permit, which says nothing about this feed, so the whole poll
/// is deferred (`None`): storing its new entries without bodies, and filing a
/// failure against it, is what let one hostile feed degrade every other one.
/// Nothing is stored, not even the entries sanitized before it — the next
/// poll is a full fetch and stores them all, with bodies.
async fn normalize_entries(
    feed_url: &str,
    raw: &[RawEntry],
    limits: SanitizeLimits,
) -> Option<(Vec<NewEntry>, bool)> {
    let mut timed_out = false;
    let mut out = Vec::with_capacity(raw.len());
    for e in raw {
        let mut entry = entry_without_body(e);
        if let Some(body) = entry_raw_body(e) {
            if timed_out {
                // Normally `sanitize_off_runtime` would refuse it anyway (the
                // abandoned sanitize is still in flight); this covers the
                // race where that sanitize has already finished.
                entry.keep_stored_content = true;
            } else {
                match sanitize_off_runtime(feed_url, body.to_owned(), limits).await {
                    Ok(html) => entry.content_html = Some(html),
                    Err(SanitizeGaveUp::NoPermit) => {
                        tracing::warn!(
                            feed = %feed_url,
                            timeout = ?limits.timeout,
                            "no sanitize permit came free in time (all held by abandoned \
                             sanitizes); deferring this feed's poll without storing it"
                        );
                        return None;
                    }
                    Err(SanitizeGaveUp::Busy) => {
                        tracing::info!(
                            feed = %feed_url,
                            "a sanitize for this feed is already running (an overlapping \
                             or dropped poll); deferring this poll without storing it"
                        );
                        return None;
                    }
                    Err(why) => {
                        tracing::warn!(
                            feed = %feed_url,
                            entry = %entry.guid,
                            raw_bytes = body.len(),
                            timeout = ?limits.timeout,
                            ?why,
                            "an entry body was not sanitized in time; this poll stores no \
                             further bodies for the feed and keeps any already stored"
                        );
                        timed_out = true;
                        entry.keep_stored_content = true;
                    }
                }
            }
        }
        out.push(entry);
    }
    Some((out, timed_out))
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
///
/// `max_entries_per_feed` caps how many entries this feed retains after insert
/// (newest N by published date); `<= 0` disables the per-feed trim.
///
/// Bodies are sanitized off the async runtime with a per-entry timeout
/// (`SANITIZE_TIMEOUT`; see `normalize_entries`). **A poll in which a sanitize
/// timed out does not save the response's `ETag` / `Last-Modified`** — the
/// next poll must get a full `200` to store the bodies this one could not, and
/// a saved validator would answer it with `304`s until the feed next changed.
/// Such a poll is reported as a [`FailureKind::Body`] failure, after storing
/// what it has, so the feed backs off and shows why in `/stats`: the body was
/// the feed's. A poll that could not get a sanitize permit at all — every one
/// held by OTHER feeds' abandoned sanitizes — stores nothing and returns
/// [`PollOutcome::Deferred`], which counts against no one.
pub async fn poll_feed(
    pool: &SqlitePool,
    client: &Client,
    feed: &Feed,
    max_entries_per_feed: i64,
) -> Result<PollOutcome> {
    poll_feed_with(
        pool,
        client,
        feed,
        max_entries_per_feed,
        SanitizeLimits::PRODUCTION,
    )
    .await
}

/// [`poll_feed`] with the sanitize limits injected.
async fn poll_feed_with(
    pool: &SqlitePool,
    client: &Client,
    feed: &Feed,
    max_entries_per_feed: i64,
    limits: SanitizeLimits,
) -> Result<PollOutcome> {
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
                kind: FailureKind::Fetch,
                detail: failure_detail(format!("{e:#}")),
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
            kind: FailureKind::Status,
            detail: failure_detail(status),
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
                kind: FailureKind::Body,
                detail: failure_detail(format!("{e:#}")),
            });
        }
    };

    // --- parse (malformed feed => log + skip, never panic) -------------------
    let parsed = match parse_feed(&body[..]) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(feed = %feed.url, error = %e, "malformed feed; skipping");
            return Ok(PollOutcome::Failed {
                backoff: backoff_for(1),
                kind: FailureKind::Parse,
                detail: failure_detail(format!("{e:#}")),
            });
        }
    };

    // --- normalize + sanitize ------------------------------------------------
    let Some((entries, sanitize_timed_out)) =
        normalize_entries(&feed.url, &parsed.entries, limits).await
    else {
        // Every permit is held by other feeds' abandoned sanitizes: store
        // nothing from this poll (not even its validators) and blame nothing.
        return Ok(PollOutcome::Deferred);
    };

    let (title, site_url) = feed_metadata(&parsed);
    // A timed-out poll keeps the validators already stored (`None` is "keep
    // current" to the upsert), so the next poll is a full fetch.
    let (etag, last_modified) = if sanitize_timed_out {
        (None, None)
    } else {
        (new_etag, new_last_modified)
    };
    let new_feed = NewFeed {
        url: feed.url.clone(),
        title,
        site_url,
        etag,
        last_modified,
        last_polled: Some(now_rfc3339()),
        next_poll: None, // the scheduler owns cadence; leave it to set next_poll.
    };

    // --- store (a store failure IS a real error) -----------------------------
    let feed_id = store::upsert_feed(pool, &new_feed)
        .await
        .with_context(|| format!("upsert_feed for {}", feed.url))?;
    let n = store::insert_entries(pool, feed_id, &entries, max_entries_per_feed)
        .await
        .with_context(|| format!("insert_entries for {}", feed.url))?;

    tracing::info!(feed = %feed.url, entries = n, "feed polled");
    if sanitize_timed_out {
        return Ok(PollOutcome::Failed {
            backoff: backoff_for(1),
            kind: FailureKind::Body,
            detail: failure_detail(format!(
                "an entry body was not sanitized within {:?}; entries were stored \
                 without new bodies",
                limits.timeout
            )),
        });
    }
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
    // `None` means "keep current" — upsert_feed COALESCEs the validators, so a
    // 304 that repeats no headers leaves the stored ones untouched. This used to
    // re-read the row and re-supply them by hand because the upsert clobbered
    // unconditionally; the read-modify-write is gone now that the upsert is
    // honest, and with it a race where a concurrent poll's validators could be
    // read here and written back stale.
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
    let title = parsed
        .title
        .as_ref()
        .map(|t| bound_text(text_plain(t), MAX_TITLE_BYTES));
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
        .map(|l| bound_text(l.href.clone(), MAX_URL_BYTES));
    (title, site_url)
}

/// Parse a feed body with feed-rs, generating ids for id-less entries the way
/// feed-rs 2.4 did.
///
/// An entry's id is its dedup key, so how feed-rs fills a missing one is part
/// of FeatherReader's storage contract. feed-rs 3.0 also puts `<comments>` and
/// `wfw:commentRss` URLs in `entry.links`, and its default generator hashes the
/// FIRST link with the title — so an id-less item listing its comments link
/// before `<link>` got a new id on upgrade, and was stored a second time. This
/// generator hashes the first link that is not a comments link, which is the
/// link 2.4 hashed, through the same public 2.4/3.0 function.
///
/// With no such link, it returns an empty id rather than feed-rs's fallback (a
/// random UUID, which made the item a new row on every poll); `normalize_entry`
/// then derives [`stable_guid`]. `parse` has no base URI, so feed-rs's
/// uri+title branch was never reached and nothing else is lost.
///
/// **A panic inside feed-rs is returned as an error.** feed-rs 3.0 panics on
/// some hostile-but-plausible input — an author address with a multi-byte
/// character beside it, e.g. `jose@example.com（José）` (its name/address
/// splitter slices on a byte that is not a character boundary). Feed bodies are
/// arbitrary web input, so any such panic is a malformed feed: it takes the
/// ordinary parse-failure path (logged, `FailureKind::Parse`, backed off) rather
/// than unwinding out of the poll task, which recorded nothing and left the
/// feed silently un-polled. Unwinding is safe here: the parser is built and
/// dropped inside the closure and touches no state of ours.
fn parse_feed(body: &[u8]) -> Result<RawFeed> {
    let parsed = std::panic::catch_unwind(|| {
        feed_rs::parser::Builder::new()
            .id_generator(entry_id)
            .build()
            .parse(body)
    });
    match parsed {
        Ok(result) => Ok(result?),
        Err(panic) => {
            let why = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic payload");
            anyhow::bail!("feed parser panicked: {why}")
        }
    }
}

/// The id generator [`parse_feed`] installs; see there.
fn entry_id(links: &[RawLink], title: &Option<Text>, _uri: Option<&str>) -> String {
    match links.iter().find(|l| is_primary_link(l)) {
        Some(link) => feed_rs::parser::generate_id_from_link_and_title(link, title),
        None => String::new(),
    }
}

/// Whether a link is one of the entry's own links rather than a pointer to its
/// comments (feed-rs 3.0's `<comments>` / `wfw:commentRss`, marked by
/// `target`). Only these are candidates for the permalink and the id, which is
/// all feed-rs 2.4 ever put in `entry.links`.
fn is_primary_link(l: &RawLink) -> bool {
    l.target.is_none()
}

/// Turn a parsed [`RawEntry`] into the store's [`NewEntry`], sanitizing HTML
/// inline. **Tests only**: the poller sanitizes off the async runtime, through
/// [`normalize_entries`]. Both are [`entry_without_body`] plus
/// [`sanitize_html_bounded`] of [`entry_raw_body`], so they store the same bytes.
#[cfg(test)]
fn normalize_entry(e: &RawEntry) -> NewEntry {
    NewEntry {
        content_html: entry_raw_body(e)
            .map(|raw| sanitize_html_bounded(raw, MAX_CONTENT_HTML_BYTES)),
        ..entry_without_body(e)
    }
}

/// The markup an entry's stored body is sanitized from: the full `content`
/// body, else the `summary`. Whichever is chosen is **always** passed through
/// [`sanitize_html_bounded`] before storage.
fn entry_raw_body(e: &RawEntry) -> Option<&str> {
    e.content
        .as_ref()
        .and_then(|c| c.body.as_deref())
        .or_else(|| e.summary.as_ref().map(|t| t.content.as_str()))
}

/// Everything about a [`RawEntry`] except its body, which is left `None` for
/// the caller to sanitize. GUID falls back to the entry link, then to a stable
/// hash of title+link, so an entry missing an `id` still deduplicates instead
/// of being re-inserted forever.
fn entry_without_body(e: &RawEntry) -> NewEntry {
    let url = entry_link(e);

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
        guid: bound_guid(guid),
        url: url.map(|u| bound_text(u, MAX_URL_BYTES)),
        title: e
            .title
            .as_ref()
            .map(|t| bound_text(text_plain(t), MAX_TITLE_BYTES)),
        author: entry_author(e).map(|a| bound_text(a, MAX_AUTHOR_BYTES)),
        published: entry_time(e),
        content_html: None,
        fetched_at: None, // store defaults to "now".
        keep_stored_content: false,
    }
}

/// The raw best-permalink URL for an entry (no scheme filtering) — used only as
/// a dedup GUID, never rendered as an href.
///
/// Comments links are never candidates (see [`is_primary_link`]).
fn raw_entry_link(e: &RawEntry) -> Option<String> {
    let mut links = e.links.iter().filter(|l| is_primary_link(l));
    links
        .clone()
        .find(|l| l.rel.as_deref() == Some("alternate") || l.rel.is_none())
        .or_else(|| links.next())
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

/// The first author's name, if it has one.
///
/// feed-rs 3.0 splits RSS's `address (Name)` into an email and a name, but
/// keeps the parentheses: `(Name)`. They are stripped here. An author given
/// only as an address has no name and no byline — the address is not shown.
/// (feed-rs 2.4 named every RSS `<author>` "author", and an Atom author with no
/// name "unknown"; those placeholders were stored as bylines.)
///
/// The byline is the first author that has a name once stripped: an item may
/// give `<author>` as a bare address and the name in `<dc:creator>`.
fn entry_author(e: &RawEntry) -> Option<String> {
    e.authors.iter().find_map(|p| {
        let name = p.name.as_deref()?.trim();
        let name = [('(', ')'), ('<', '>'), ('[', ']')]
            .iter()
            .find_map(|&(open, close)| name.strip_prefix(open)?.strip_suffix(close))
            .unwrap_or(name)
            .trim();
        (!name.is_empty()).then(|| name.to_string())
    })
}

/// Best CREDIBLE publication time (published, else updated) as an RFC3339
/// string, or `None` when neither is credible.
///
/// **A date in the future is discarded, not clamped, and not stored.** There was
/// no upper bound here, so an item dated in the year 2999 was stored verbatim
/// and became permanent: both retention sweeps test
/// `COALESCE(published, fetched_at) < cutoff` and a future date is never less
/// than either, the per-feed keep-set orders on the same expression `DESC` where
/// it is rank one forever, and every list view puts it at the top. A publisher
/// with a broken clock does that by accident; anyone wanting a permanent slot at
/// the top of a reader's list does it on purpose.
///
/// Discarded rather than clamped to now because the entry upsert refreshes
/// `published` on every poll while stamping `fetched_at` once — so a value
/// derived from the current clock is rewritten every cycle and the row can never
/// age at all. Clamping relocates the defect. Undated is the honest answer, and
/// `fetched_at` then dates the row and holds still. That is the rule the
/// publication path already follows; see `standard_site::entries_from_records`.
///
/// **Each candidate is judged separately**, so a bogus `<published>` beside a
/// credible `<updated>` keeps the good date. That helps Atom, and RSS 2 only
/// when the item carries an `<atom:updated>` (read since feed-rs 3.0):
/// otherwise `feed-rs` copies `published` into `updated` when `updated` is
/// absent (`parser/rss2/mod.rs`), so the second candidate holds the same value
/// and the fall-through is a no-op. Worth keeping where two independent dates
/// exist; worth not overstating where they do not.
///
/// **The ceiling is [`MAX_FUTURE_PUBLISHED_DAYS`], NOT the publication path's
/// clock-skew grace, and the asymmetry is deliberate.** There, a refused
/// `publishedAt` falls back to the record key's TID — the real write time, a
/// credible date — so a five-minute bound costs almost nothing. Here there is no
/// such fallback: refusing leaves the entry undated and the reader sees no date
/// at all. Five minutes is sized for skew between two clocks, while the ordinary
/// cause of a future `pubDate` is a local time stamped `+0000` (up to 14 hours
/// out, the widest real UTC offset) or a post scheduled a little ahead. Those are
/// dates worth keeping, and they stop being future on their own.
///
/// What the bound must prevent is a date that can never become past, because that
/// is what makes a row permanently unsweepable, un-evictable and first in the
/// list.
fn entry_time(e: &RawEntry) -> Option<String> {
    let ceiling = Utc::now() + chrono::Duration::days(MAX_FUTURE_PUBLISHED_DAYS);
    e.published
        .filter(|d| *d <= ceiling)
        .or_else(|| e.updated.filter(|d| *d <= ceiling))
        .map(fmt_time)
}

/// How far ahead of now a feed may date an entry before [`entry_time`] refuses
/// the date and lets `fetched_at` stand in.
///
/// Two days: the widest real UTC offset is +14:00, so a local time mislabelled as
/// UTC lands inside this, as does a post scheduled slightly ahead. Both are dates
/// worth keeping, and both stop being future without help. Anything further is
/// refused, because a date that never becomes past is what makes a row
/// permanently unsweepable and permanently first in the reading list.
pub(crate) const MAX_FUTURE_PUBLISHED_DAYS: i64 = 2;

/// Extract the plain string content of a feed [`Text`] node.
fn text_plain(t: &Text) -> String {
    t.content.trim().to_string()
}

/// Sanitize hostile feed **HTML** with ammonia's whitelist cleaner. Applied to
/// every RSS/Atom entry body unconditionally, because every one of them is
/// markup.
///
/// **Not for plain text.** An earlier version of this comment claimed it was
/// "safe on plain text too (it will simply escape/strip as needed)". It is
/// not: `clean` PARSES its input, so a bare `<` in prose swallows the rest —
/// `"if x<y then z"` comes back as `"if x"`. That sentence is how a
/// plain-text field got run through here once already. Use
/// [`plain_text_to_html`].
pub(crate) fn sanitize_html(raw: &str) -> String {
    ammonia::clean(raw)
}

/// Render **plain text** into the HTML the `content_html` column holds.
///
/// **Not [`sanitize_html`].** `ammonia::clean` parses its input as markup, so a
/// bare `<` in prose swallows the rest: measured here, `"if x<y then z"` comes
/// back as `"if x"`. That is correct for an RSS body, which IS markup, and
/// silent data loss for a field a lexicon defines as text. Escape first, then
/// add the only markup this needs — line breaks, which the column's consumer
/// renders as HTML and would otherwise collapse.
pub(crate) fn plain_text_to_html(raw: &str) -> String {
    let escaped = raw
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    // Safe by order: every `<` from the input is already `&lt;` before this
    // adds a real tag.
    escaped.replace('\n', "<br>")
}

/// **What one entry, or one feed row, may store per field (#205).**
///
/// Every field below arrives from someone else's server — an RSS document or a
/// publisher's `site.standard.document` record — and nothing between the wire
/// and SQLite used to shorten it. A title could be megabytes, then indexed, read
/// back and rendered into every list view of that feed.
///
/// Chosen from measurement, not guessed. Production's 4,389 entries on
/// 2026-10-03: title max 253 bytes (p99 148), url max 235 (p99 178), author max
/// 26, content_html max 86,969 (p99 17,535). Each bound is at least 8x the
/// largest real value, so no ordinary article is touched; `MAX_TITLE_BYTES` is
/// `site.standard.document`'s own `title.maxLength`.
///
/// **Truncated, never refused.** Dropping an article because one field is long
/// is the failure mode the retention work was careful to avoid.
pub(crate) const MAX_TITLE_BYTES: usize = 5_000;
/// See [`MAX_TITLE_BYTES`].
pub(crate) const MAX_AUTHOR_BYTES: usize = 1_000;
/// See [`MAX_TITLE_BYTES`]. A truncated URL is a broken link, which was judged
/// better than no link; at 35x the longest real one it should never happen.
pub(crate) const MAX_URL_BYTES: usize = 8_192;
/// See [`MAX_TITLE_BYTES`]. Applies to the STORED HTML, after sanitizing or
/// escaping — see [`sanitize_html_bounded`] for why that is the bound that matters.
pub(crate) const MAX_CONTENT_HTML_BYTES: usize = 2 * 1024 * 1024;
/// An entry id longer than this is replaced by a stable hash of the whole id
/// (see [`bound_guid`]): it is the dedup key, under a UNIQUE index.
pub(crate) const MAX_GUID_BYTES: usize = 2_048;

/// The largest index `<= at` that is a character boundary of `s`.
fn floor_char_boundary(s: &str, at: usize) -> usize {
    if at >= s.len() {
        return s.len();
    }
    (0..=at).rev().find(|&i| s.is_char_boundary(i)).unwrap_or(0)
}

/// `s` cut to at most `max` bytes, on a character boundary. Plain-text fields
/// only: cutting markup or an escaped string here could split a tag or an
/// entity, which is what [`sanitize_html_bounded`] and [`plain_text_to_html_bounded`] exist for.
pub(crate) fn bound_text(mut s: String, max: usize) -> String {
    let cut = floor_char_boundary(&s, max);
    s.truncate(cut);
    s
}

/// Plain text escaped into `content_html`, cut so the **output** fits `max`.
///
/// **Exact, in one pass.** Escaping is a fixed size per character (`&` is
/// five bytes, `<` and `>` four, a newline `<br>` four, anything else its UTF-8
/// length), so the longest prefix whose escaped form fits is found by adding
/// those up — no rendering, no search. Three rounds of review found bugs in a
/// generic re-render search that this replaces (#224).
pub(crate) fn plain_text_to_html_bounded(raw: &str, max: usize) -> String {
    let mut size = 0usize;
    let mut cut = raw.len();
    for (i, c) in raw.char_indices() {
        let escaped = match c {
            '&' => 5,
            '<' | '>' | '\n' => 4,
            c => c.len_utf8(),
        };
        if size + escaped > max {
            cut = i;
            break;
        }
        size += escaped;
    }
    plain_text_to_html(&raw[..cut])
}

/// Feed HTML sanitized into `content_html`, cut so the **output** fits `max`.
///
/// **Sanitize once, then cut the sanitized output, not the input.** Cutting
/// the input made the result depend on how much of it the sanitizer would
/// strip — a large `data:` image, `<style>` or unterminated comment — and the
/// searches that tried to account for that kept nothing, or ran for hours, in
/// review (#224). Sanitized HTML is already clean: cutting it on a character
/// boundary and sanitizing that prefix again only closes the tags the cut left
/// open, so the second pass usually grows it by little. The first cut leaves a
/// margin for that growth; deeply nested markup, whose closers can outgrow any
/// margin, falls through to a bounded bisection.
///
/// Cost: the first sanitize is the one every body always had; the bounded
/// passes — one, or at most 1 + [`SANITIZE_BOUND_ATTEMPTS`] — run on at most
/// `max` bytes of already-clean HTML, and only for a body over the bound.
pub(crate) fn sanitize_html_bounded(raw: &str, max: usize) -> String {
    let clean = sanitize_html(raw);
    if clean.len() <= max {
        return clean;
    }
    // First, the cut that almost always works: just under the bound, with a
    // margin for the closers the cut leaves open. When it fits, that is the
    // answer — within 1/64 of the bound, in one extra pass.
    let margin = (max / 64).max(64);
    let first = floor_char_boundary(&clean, max.saturating_sub(margin));
    let again = sanitize_html(&clean[..first]);
    if again.len() <= max {
        return again;
    }
    // **Then a bounded bisection, not a widening margin.** A closing tag is
    // longer than the tag it opens, so a cut through deeply nested markup can
    // grow past the bound by more than any fixed margin; widening the margin
    // 4x a round reached a cut of 0 and stored nothing where nearly all of it
    // fit (found in review). `lo` always fits (the empty prefix does), `hi`
    // never does, and the next probe is taken AFTER they move.
    let (mut lo, mut hi) = (0usize, first);
    let mut best = String::new();
    let resolution = (max / 1024).max(1);
    for _ in 0..SANITIZE_BOUND_ATTEMPTS {
        if hi - lo <= resolution {
            break;
        }
        let mut cut = floor_char_boundary(&clean, lo + (hi - lo) / 2);
        if cut <= lo {
            // A multi-byte character straddles the midpoint: step past it
            // rather than give up.
            cut = ceil_char_boundary(&clean, lo + 1);
            if cut >= hi {
                break;
            }
        }
        let out = sanitize_html(&clean[..cut]);
        if out.len() <= max {
            lo = cut;
            best = out;
        } else {
            hi = cut;
        }
    }
    best
}

/// The smallest index `>= at` that is a character boundary of `s`.
fn ceil_char_boundary(s: &str, at: usize) -> usize {
    (at..=s.len())
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(s.len())
}

/// The most bisection passes [`sanitize_html_bounded`] spends after its first
/// cut: enough to resolve a 2 MiB bound to about 1/1024 of it.
const SANITIZE_BOUND_ATTEMPTS: usize = 14;

/// An entry id, or a stable stand-in for one too long to index.
///
/// The id is the dedup key under `UNIQUE (feed_id, guid)`, so truncating it
/// would merge distinct entries that share a long prefix. A hash of the WHOLE
/// id keeps them apart and keeps the same entry deduplicating across polls —
/// the same construction as [`stable_guid`].
pub(crate) fn bound_guid(guid: String) -> String {
    if guid.len() <= MAX_GUID_BYTES {
        return guid;
    }
    use std::hash::{Hash, Hasher};
    let mut h = dedup_hasher();
    guid.hash(&mut h);
    format!("featherreader:long-guid:{:016x}", h.finish())
}

/// The hasher behind the stored dedup keys of [`bound_guid`] and
/// [`stable_guid`]: SipHash-1-3 with zero keys, from the `siphasher` crate.
///
/// **Not `std`'s `DefaultHasher`**, whose algorithm the standard library
/// documents as unspecified and free to change between Rust releases: a
/// toolchain bump could re-key every such entry, and each would be stored a
/// second time. `DefaultHasher` is SipHash-1-3 with zero keys today, so this
/// produces the values already stored; tests pin them.
fn dedup_hasher() -> siphasher::sip::SipHasher13 {
    siphasher::sip::SipHasher13::new_with_keys(0, 0)
}

/// Format a chrono timestamp as RFC3339 (UTC, seconds precision) to match the
/// store's string columns.
pub(crate) fn fmt_time(dt: DateTime<Utc>) -> String {
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
    let mut h = dedup_hasher();
    e.title.as_ref().map(|t| t.content.as_str()).hash(&mut h);
    e.links
        .iter()
        .find(|l| is_primary_link(l))
        .map(|l| l.href.as_str())
        .hash(&mut h);
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
/// URL and have FeatherReader find the actual feed ("subscribe by URL").
/// Returns `None` if the HTML carries no autodiscovery link.
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
                // Either way, only http(s): the href is publisher-controlled and
                // `Url::parse` accepts any scheme, so this is where an `at://`
                // (or `file:`, `javascript:`) alternate would otherwise become
                // the URL the add path stores — after its input gate has run.
                // Skip, don't stop: a later real feed link still wins.
                let resolved = match Url::parse(href) {
                    Ok(u) => Some(u),
                    Err(_) => base.and_then(|b| b.join(href).ok()),
                };
                match resolved {
                    Some(u) if matches!(u.scheme(), "http" | "https") => return Some(u),
                    _ => continue,
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

    /// [`ATOM_SAMPLE`] with the `self` link before the `alternate` one.
    const ATOM_SELF_FIRST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Example Atom Feed</title>
  <link rel="self" href="https://atom.example.com/feed.xml"/>
  <link rel="alternate" href="https://atom.example.com/"/>
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

    // ---- #205: what one entry may store, per field ----------------------

    /// An RSS document carrying one item with exactly these fields.
    fn rss_with_fields(title: &str, link: &str, author: &str, body: &str, guid: &str) -> String {
        format!(
            r#"<?xml version="1.0"?><rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel>
<title>{title}</title><link>https://example.com/{link}</link>
<item><title>{title}</title><link>https://example.com/{link}</link><guid>{guid}</guid>
<dc:creator>{author}</dc:creator><description><![CDATA[{body}]]></description></item>
</channel></rss>"#
        )
    }

    #[test]
    fn bound_text_cuts_on_a_character_boundary() {
        // 'é' is two bytes, so an odd limit lands mid-character.
        let cut = bound_text("é".repeat(100), 51);
        assert!(cut.len() <= 51, "not bounded: {} bytes", cut.len());
        assert_eq!(cut, "é".repeat(25), "cut too short or mid-character");
        assert_eq!(
            bound_text("short".into(), 51),
            "short",
            "a short value changed"
        );
    }

    #[test]
    fn rendered_content_fits_even_when_rendering_grows_it() {
        // Escaping turns each `&` into `&amp;` — five bytes from one.
        let out = plain_text_to_html_bounded(&"&".repeat(1_000), 100);
        assert!(
            out.len() <= 100,
            "escaped output not bounded: {} bytes",
            out.len()
        );
        assert!(!out.is_empty(), "bounded to nothing");
        assert_eq!(
            out.matches("&amp;").count() * 5,
            out.len(),
            "cut mid-entity: {out}"
        );
    }

    #[test]
    fn an_rss_items_text_fields_are_bounded() {
        let big = "x".repeat(100_000);
        let xml = rss_with_fields(&big, &big, &big, "body", "id-1");
        let parsed = parse_feed(xml.as_bytes()).unwrap();
        let e = normalize_entry(&parsed.entries[0]);
        assert!(e.title.as_ref().unwrap().len() <= MAX_TITLE_BYTES, "title");
        assert!(e.url.as_ref().unwrap().len() <= MAX_URL_BYTES, "url");
        assert!(
            e.author.as_ref().unwrap().len() <= MAX_AUTHOR_BYTES,
            "author"
        );
        let (title, site) = feed_metadata(&parsed);
        assert!(title.unwrap().len() <= MAX_TITLE_BYTES, "feed title");
        assert!(site.unwrap().len() <= MAX_URL_BYTES, "feed site url");
    }

    #[test]
    fn an_rss_body_is_bounded_and_still_well_formed() {
        // Long enough to need cutting, with markup straddling the cut.
        let body = format!("<p>{}<b>tail</b></p>", "a".repeat(MAX_CONTENT_HTML_BYTES));
        let xml = rss_with_fields("t", "l", "a", &body, "id-2");
        let parsed = parse_feed(xml.as_bytes()).unwrap();
        let html = normalize_entry(&parsed.entries[0]).content_html.unwrap();
        assert!(
            html.len() <= MAX_CONTENT_HTML_BYTES,
            "body not bounded: {}",
            html.len()
        );
        assert_eq!(
            sanitize_html(&html),
            html,
            "the stored body is not well-formed sanitized HTML"
        );
    }

    /// Review of #224: cutting the INPUT first threw away content that would
    /// have fit. A large inline `data:` image, which ammonia strips anyway,
    /// ahead of the article left the cut ending inside the image tag, and the
    /// article was stored as an empty body.
    #[test]
    fn content_the_sanitizer_strips_does_not_count_against_the_bound() {
        const MAX: usize = 64 * 1024;
        let body = format!(
            r#"<p><img src="data:image/png;base64,{}"></p><p>the article</p>"#,
            "A".repeat(MAX + 16 * 1024)
        );
        let html = sanitize_html_bounded(&body, MAX);
        assert!(
            html.contains("the article"),
            "the article was cut away: {} bytes kept",
            html.len()
        );
        assert!(html.len() <= MAX);
    }

    /// Review of #224 (second round): the re-cut loop shrank its input by a
    /// few bytes a round when the bytes beyond the cut were ones the sanitizer
    /// strips anyway — measured at ~32 bytes/round, hours for one entry, on the
    /// poller's async task. The number of renders must be bounded.
    /// Review of #224: a cut into bytes the sanitizer strips anyway (here an
    /// unterminated comment) crept a few bytes a round, for hours. Bounding
    /// works on the SANITIZED output now, so stripped input costs nothing.
    #[test]
    fn content_cut_beside_stripped_bytes_still_keeps_what_fits() {
        const MAX: usize = 64 * 1024;
        let body = format!("<p>{}</p><!--{}", "a".repeat(MAX + 8), "x".repeat(16 * MAX));
        let html = sanitize_html_bounded(&body, MAX);
        assert!(html.len() <= MAX);
        assert!(
            html.len() > MAX - MAX / 16,
            "kept far less than fits: {}",
            html.len()
        );
    }

    /// Also from that review: a cut landing inside a stripped prefix stored an
    /// empty body when an article that fits followed it.
    /// Also from review: a cut landing inside a stripped prefix stored an
    /// empty body when an article that fits followed it.
    #[test]
    fn a_stripped_prefix_does_not_leave_an_empty_body() {
        const MAX: usize = 64 * 1024;
        let body = format!(
            r#"<p><img src="data:image/png;base64,{}"></p><p>{}</p>"#,
            "A".repeat(3 * MAX),
            "&".repeat(MAX)
        );
        let html = sanitize_html_bounded(&body, MAX);
        assert!(html.len() <= MAX);
        assert!(
            html.len() > MAX - MAX / 16,
            "nothing like what fits was kept: {} bytes",
            html.len()
        );
    }

    /// Third review: a multi-byte character where the search's stale probe
    /// landed ended it early, keeping 0 bytes where ~2 MiB fit.
    #[test]
    fn a_stripped_multibyte_prefix_does_not_leave_an_empty_body() {
        const MAX: usize = 64 * 1024;
        let body = format!(
            "<!--{}--><p>{}</p>",
            "漢".repeat(MAX),
            "&".repeat(MAX * 3 / 10)
        );
        let html = sanitize_html_bounded(&body, MAX);
        assert!(html.len() <= MAX);
        assert!(
            html.len() > MAX - MAX / 16,
            "kept {} of ~{MAX} that fits",
            html.len()
        );
    }

    /// Fourth review of #224: a closing tag is longer than the tag it closes,
    /// so a cut through nested markup grew past the bound on re-sanitizing,
    /// and the widening margin jumped straight to a cut of 0 — an empty body
    /// where nearly all of it fit.
    #[test]
    fn nested_markup_is_cut_not_emptied() {
        const MAX: usize = 64 * 1024;
        let html = sanitize_html_bounded(&"<span>".repeat(16_384), MAX);
        assert!(html.len() <= MAX);
        assert!(
            html.len() > MAX / 3,
            "kept {} of ~{MAX} that fits",
            html.len()
        );

        let mixed = format!("{}{}", "t".repeat(MAX * 3 / 4), "<span>".repeat(MAX / 8));
        let html = sanitize_html_bounded(&mixed, MAX);
        assert!(html.len() <= MAX);
        assert!(
            html.len() > MAX - MAX / 16,
            "kept {} of ~{MAX} that fits",
            html.len()
        );
    }

    /// The plain-text bound is exact: escaping is linear, so the longest
    /// fitting prefix is found in one pass, never by search.
    #[test]
    fn the_plain_text_bound_is_exact() {
        const MAX: usize = 64 * 1024;
        let raw = format!("{}{}", "漢".repeat(MAX / 4), "&".repeat(MAX / 10));
        let out = plain_text_to_html_bounded(&raw, MAX);
        assert!(out.len() <= MAX);
        // The next character would not have fitted: '&' escapes to 5 bytes.
        assert!(out.len() > MAX - 5, "kept {} of {MAX}", out.len());
        assert!(
            raw.starts_with(&out.replace("&amp;", "&")),
            "not a prefix of the input"
        );
    }

    #[test]
    fn an_overlong_rss_guid_becomes_a_stable_short_one() {
        let long = "g".repeat(10_000);
        let xml = rss_with_fields("t", "l", "a", "b", &long);
        let parsed = parse_feed(xml.as_bytes()).unwrap();
        let a = normalize_entry(&parsed.entries[0]).guid;
        let b = normalize_entry(&parsed.entries[0]).guid;
        assert!(a.len() <= MAX_GUID_BYTES, "guid not bounded: {}", a.len());
        assert_eq!(
            a, b,
            "the stand-in is not stable, so the entry would duplicate"
        );
        let other = rss_with_fields("t", "l", "a", "b", &format!("{long}h"));
        let other = parse_feed(other.as_bytes()).unwrap();
        assert_ne!(
            a,
            normalize_entry(&other.entries[0]).guid,
            "two ids collapsed into one"
        );
    }

    #[test]
    fn an_ordinary_long_article_is_untouched() {
        // The largest body production held on 2026-10-03 was 86,969 bytes.
        let body = format!("<p>{}</p>", "word ".repeat(18_000));
        let xml = rss_with_fields(
            "A normal title",
            "post",
            "Author",
            &body,
            "https://example.com/post",
        );
        let parsed = parse_feed(xml.as_bytes()).unwrap();
        let e = normalize_entry(&parsed.entries[0]);
        assert_eq!(e.content_html.unwrap(), sanitize_html(&body));
        assert_eq!(e.title.as_deref(), Some("A normal title"));
        assert_eq!(e.guid, "https://example.com/post");
    }

    /// **A stated date in the future is discarded, not stored and not clamped.**
    ///
    /// `entry_time` was `e.published.or(e.updated)` with no ceiling, so an item
    /// dated in the year 2999 was stored verbatim and then became permanent:
    /// both retention sweeps test `COALESCE(published, fetched_at) < cutoff` and
    /// a future date is never less than either; the per-feed keep-set orders on
    /// the same expression `DESC`, where it is rank one forever; and every list
    /// view orders on `published DESC`, where it sits at the top. One item in one
    /// feed, there for good. A publisher with a broken clock does this by
    /// accident.
    ///
    /// Discarded rather than clamped to now, which is the rule `#186`
    /// established on the atproto side and the reasoning transfers exactly: the
    /// entry upsert refreshes `published` on every poll but stamps `fetched_at`
    /// once, so a value derived from the current clock is rewritten every cycle
    /// and the row can never age at all. Clamping moves the defect. Falling back
    /// to undated lets `fetched_at` date it, and that holds still.
    ///
    /// The ceiling is [`MAX_FUTURE_PUBLISHED_DAYS`] (two days), deliberately
    /// looser than the publication path's five-minute grace: a publication can
    /// fall back to its record key's TID, and a feed has no such fallback.
    #[test]
    fn a_future_dated_rss_item_is_stored_undated_rather_than_dated_in_2999() {
        let future = r#"<?xml version="1.0"?>
<rss version="2.0"><channel><title>Clock</title><link>https://clock.example/</link>
<item><title>From the future</title><link>https://clock.example/1</link>
<guid>https://clock.example/1</guid>
<pubDate>Sat, 01 Jan 2999 00:00:00 GMT</pubDate></item>
</channel></rss>"#;
        let parsed = parse_feed(future.as_bytes()).expect("should parse");
        // The fixture is only meaningful if feed-rs actually read the date.
        assert!(
            parsed.entries[0].published.is_some(),
            "the fixture's pubDate did not parse, so this test proves nothing",
        );

        let e = normalize_entry(&parsed.entries[0]);
        assert_eq!(
            e.published, None,
            "a year-2999 date was stored, which makes the row unsweepable, \
             un-evictable and permanently first in the reading list",
        );

        // And the other direction: an ordinary past date must survive, or this
        // would be satisfied by discarding every date.
        let past = future.replace("01 Jan 2999", "01 Jan 2020");
        let parsed = parse_feed(past.as_bytes()).expect("should parse");
        let e = normalize_entry(&parsed.entries[0]);
        assert!(
            e.published
                .as_deref()
                .is_some_and(|p| p.starts_with("2020")),
            "an ordinary past date was discarded: {:?}",
            e.published,
        );

        // **A merely MISLABELLED date must survive.** The ordinary cause of a
        // future `pubDate` is a local time stamped `+0000` — up to 14 hours out,
        // not a clock a few minutes fast. Refusing those would leave real
        // articles undated and dateless on screen, which is why the bound is two
        // days rather than the publication path's five-minute skew grace.
        let soon = (Utc::now() + chrono::Duration::hours(14)).to_rfc2822();
        let near = future.replace("Sat, 01 Jan 2999 00:00:00 GMT", &soon);
        let parsed = parse_feed(near.as_bytes()).expect("should parse");
        assert!(
            parsed.entries[0].published.is_some(),
            "the mislabelled-date fixture did not parse",
        );
        let e = normalize_entry(&parsed.entries[0]);
        assert!(
            e.published.is_some(),
            "a date 14 hours ahead — the widest real UTC offset — was refused, \
             so a timezone-mislabelled article loses its date entirely",
        );

        // And the bound still bounds: a month out is refused.
        let far = (Utc::now() + chrono::Duration::days(30)).to_rfc2822();
        let month = future.replace("Sat, 01 Jan 2999 00:00:00 GMT", &far);
        let parsed = parse_feed(month.as_bytes()).expect("should parse");
        let e = normalize_entry(&parsed.entries[0]);
        assert_eq!(
            e.published, None,
            "a date a month ahead was kept, so the row leads the list for a month",
        );

        // **Each candidate is judged separately, not the winner of `or`.**
        //
        // Atom specifically: for RSS 2 `feed-rs` copies `published` into
        // `updated` when `updated` is absent, so the second candidate holds the
        // same bogus value and the fall-through cannot help. Only a format
        // carrying two independent dates exercises this.
        let both = r#"<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Clock</title>
<entry><title>Mixed</title><id>https://clock.example/2</id>
<link href="https://clock.example/2"/>
<published>2999-01-01T00:00:00Z</published>
<updated>2020-06-01T00:00:00Z</updated></entry></feed>"#;
        let parsed = parse_feed(both.as_bytes()).expect("should parse");
        assert!(
            parsed.entries[0].published.is_some() && parsed.entries[0].updated.is_some(),
            "the fixture needs BOTH dates parsed for this case to mean anything",
        );
        let e = normalize_entry(&parsed.entries[0]);
        assert!(
            e.published
                .as_deref()
                .is_some_and(|p| p.starts_with("2020")),
            "a credible `updated` was discarded along with a bogus `published`, \
             leaving the entry undated: {:?}",
            e.published,
        );
    }

    /// Parse a static RSS sample through feed-rs + our normalize/sanitize path
    /// (no network) and assert the entries come out sanitized and well-shaped.
    #[test]
    fn rss_parses_and_sanitizes() {
        let parsed = parse_feed(RSS_SAMPLE.as_bytes()).expect("RSS should parse");
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
    /// **`rel="alternate"` is preferred over a `rel="self"` listed FIRST.** In
    /// `ATOM_SAMPLE` the alternate link is already first, so "prefer alternate"
    /// and "take the first link" were indistinguishable; the selection could
    /// be replaced by `links.first()` with the suite green. A feed listing
    /// `self` first — very common in Atom — would store the feed XML URL as
    /// the subscription's `siteUrl`, published to the reader's PDS.
    #[test]
    fn atom_prefers_alternate_over_a_self_link_listed_first() {
        let parsed = parse_feed(ATOM_SELF_FIRST.as_bytes()).expect("Atom should parse");
        let (title, site) = feed_metadata(&parsed);
        assert_eq!(title.as_deref(), Some("Example Atom Feed"));
        // alternate link preferred over rel="self".
        assert_eq!(site.as_deref(), Some("https://atom.example.com/"));
    }

    #[test]
    fn atom_parses_and_sanitizes() {
        let parsed = parse_feed(ATOM_SAMPLE.as_bytes()).expect("Atom should parse");
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

    /// **The rkey obeys all of atproto's record-key rules, not just the
    /// charset.** `.` and `..` are reserved and the length is 1..=512; the
    /// charset alone admitted both and a 10 000-character key, into a UNIQUE
    /// column and the user's public PDS. The rule is the one the repo's own
    /// TID tests already state.
    #[test]
    fn an_rkey_must_obey_atprotos_length_and_dot_rules() {
        let uri = |rkey: &str| {
            format!("at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/{rkey}")
        };
        assert!(
            !is_storable_feed_url(&uri("."), true),
            "`.` is a reserved rkey"
        );
        assert!(
            !is_storable_feed_url(&uri(".."), true),
            "`..` is a reserved rkey"
        );
        assert!(
            !is_storable_feed_url(&uri(&"a".repeat(513)), true),
            "an rkey over 512 bytes was accepted"
        );
        assert!(
            is_storable_feed_url(&uri(&"a".repeat(512)), true),
            "an rkey of exactly 512 bytes is valid"
        );
        assert!(is_storable_feed_url(&uri("3lab2c4d5e6f7g8h"), true));
    }

    /// **Every `KNOWN_PROVIDERS` row is pinned by its own reason.**
    ///
    /// The provider test used URLs that the generic heuristics catch on their
    /// own — Substack's `/feed/private/` is also a path marker, Patreon's
    /// `?auth=…` an opaque secret key — and never asserted the reason. With
    /// 17 of 18 rows deleted, the suite stayed green. The provider layer runs
    /// FIRST so its specific reason wins; asserting the reason pins each row
    /// even where a generic rule would still refuse the URL. Values are kept
    /// short and plain so the generic query rule (`value_is_opaque`) does not
    /// fire — most of these are refused by the provider row alone.
    #[test]
    fn each_known_provider_is_caught_by_its_own_row() {
        for (url, reason) in [
            (
                "https://author.substack.com/feed/private/x",
                "Substack private feed",
            ),
            (
                "https://www.patreon.com/rss/creator?auth=ab",
                "Patreon member feed",
            ),
            ("https://blog.ghost.io/rss/?uuid=x", "Ghost members feed"),
            (
                "https://buttondown.email/me/rss?token=x",
                "Buttondown premium feed",
            ),
            (
                "https://buttondown.com/me/rss?token=x",
                "Buttondown premium feed",
            ),
            (
                "https://rss.beehiiv.com/feeds/x.xml?token=x",
                "Beehiiv premium feed",
            ),
            (
                "https://example.memberful.com/feed",
                "Memberful members feed",
            ),
            ("https://example.pico.link/feed", "Pico member feed"),
            ("https://steadyhq.com/rss/example", "Steady member feed"),
            (
                "https://example.supercast.com/feed",
                "Supercast private podcast",
            ),
            (
                "https://example.supercast.tech/feed",
                "Supercast private podcast",
            ),
            (
                "https://example.supportingcast.fm/feed",
                "Supporting Cast private podcast",
            ),
            (
                "https://feeds.redcircle.com/x?private=1",
                "RedCircle private podcast",
            ),
            (
                "https://feeds.megaphone.fm/x?token=x",
                "Megaphone private podcast",
            ),
            (
                "https://feeds.acast.com/public/shows/x?token=x",
                "Acast+ private podcast",
            ),
            (
                "https://omny.fm/shows/x/playlists/podcast.rss?token=x",
                "Omny private podcast",
            ),
            (
                "https://podcasts.apple.com/feed/x?token=x",
                "Apple subscriber podcast",
            ),
            (
                "https://anchor.spotify.com/s/x/podcast/rss?token=x",
                "Spotify subscriber podcast",
            ),
        ] {
            match classify_feed_privacy(url) {
                FeedPrivacy::Private(r) => {
                    assert_eq!(r, reason, "{url} was refused by another rule")
                }
                FeedPrivacy::Public => panic!("{url} was not refused at all"),
            }
        }
    }

    /// **Plain text is escaped, not sanitised.** `ammonia::clean` parses its
    /// input as markup, so a `<` in prose swallows everything after it:
    /// measured in this tree, `"if x<y then z"` becomes `"if x"`. That is the
    /// right function for an RSS body (which IS markup) and exactly the wrong
    /// one for a field the lexicon defines as plain text — it silently deletes
    /// the reader's content.
    #[test]
    fn plain_text_is_escaped_rather_than_swallowed() {
        assert_eq!(
            plain_text_to_html("Vec<String> is a type"),
            "Vec&lt;String&gt; is a type"
        );
        assert_eq!(plain_text_to_html("if x<y then z"), "if x&lt;y then z");
        assert_eq!(plain_text_to_html("a & b"), "a &amp; b");
        // Line structure survives into a field rendered as HTML.
        assert_eq!(plain_text_to_html("one\ntwo"), "one<br>two");
        // And it is still safe: the escaping happens before any markup is added.
        let hostile = plain_text_to_html("<script>alert(1)</script>");
        assert!(!hostile.contains("<script"), "{hostile}");
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

    /// **Autodiscovery only ever yields an http(s) URL.**
    ///
    /// The href is publisher-controlled and `Url::parse` accepts any scheme, so
    /// a page could hand the add path an `at://` publication URI (or anything
    /// else) that the user never typed — and the add path's input gate has
    /// already run by then. A non-http(s) alternate is skipped, not returned,
    /// so a later real feed link still wins.
    #[test]
    fn discover_skips_a_non_http_alternate() {
        let at_link = r#"<link rel="alternate" type="application/rss+xml" href="at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab2c4d5e6f7g8h">"#;
        assert!(
            discover_feed(&format!("<head>{at_link}</head>"), None).is_none(),
            "an at:// alternate was handed back as a feed URL"
        );
        let ftp_link =
            r#"<link rel="alternate" type="application/atom+xml" href="ftp://x.example/atom">"#;
        assert!(discover_feed(&format!("<head>{ftp_link}</head>"), None).is_none());

        let real =
            r#"<link rel="alternate" type="application/atom+xml" href="https://x.example/atom">"#;
        let found = discover_feed(&format!("<head>{at_link}{real}</head>"), None)
            .expect("the http(s) link after a skipped one must still be found");
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
        // An item with neither guid nor link: `parse_feed` leaves its id empty
        // (feed-rs's own fallback is a random UUID). Clearing id and links
        // anyway keeps this a test of *our* synthetic fallback alone.
        let xml = r#"<?xml version="1.0"?><rss version="2.0"><channel>
            <title>t</title>
            <item><title>only a title</title><description>body</description></item>
        </channel></rss>"#;
        let mut parsed = parse_feed(xml.as_bytes()).expect("parse");
        parsed.entries[0].id.clear();
        parsed.entries[0].links.clear();
        let g1 = normalize_entry(&parsed.entries[0]).guid;
        let g2 = normalize_entry(&parsed.entries[0]).guid;
        assert_eq!(g1, g2);
        assert!(g1.starts_with("featherreader:synthetic:"));
    }

    // ---- feed-rs 3.0: entry identity and links held to their 2.4 values ----
    //
    // The guid is the dedup key under `UNIQUE (feed_id, guid)`. If a parser
    // upgrade changes it, every reader gets every live entry of that feed a
    // second time. The pinned ids below are what feed-rs 2.4.0 generated for
    // these exact bytes.

    /// An id-less item with an ordinary link keeps the id 2.4 generated.
    #[test]
    fn a_generated_entry_id_is_the_one_feed_rs_2_4_produced() {
        let xml = r#"<?xml version="1.0"?><rss version="2.0"><channel><title>t</title><item><title>No guid here</title><link>https://n.example/post</link></item></channel></rss>"#;
        let e = normalize_entry(&parse_feed(xml.as_bytes()).expect("parse").entries[0]);
        assert_eq!(e.guid, "5813b43a0512aaef2750311bf4d978a");
        assert_eq!(e.url.as_deref(), Some("https://n.example/post"));
    }

    /// **feed-rs 3.0 adds `<comments>` and `wfw:commentRss` to `entry.links`.**
    /// Listed before `<link>`, the comments URL became the entry's permalink,
    /// and for an id-less item it was hashed into the generated id, so the
    /// same item got a new guid after the upgrade: a duplicate in every
    /// reader's list.
    #[test]
    fn a_comments_link_listed_first_is_neither_the_permalink_nor_the_id() {
        let xml = r#"<?xml version="1.0"?>
<rss version="2.0" xmlns:wfw="http://wellformedweb.org/CommentAPI/"><channel><title>c</title><link>https://c.example/</link>
<item><title>Comments listed first, no guid</title><comments>https://c.example/1#comments</comments><link>https://c.example/1</link><wfw:commentRss>https://c.example/1/feed</wfw:commentRss></item>
<item><title>Comments first, guid present</title><comments>https://c.example/6#comments</comments><link>https://c.example/6</link><guid>c6</guid></item>
</channel></rss>"#;
        let parsed = parse_feed(xml.as_bytes()).expect("parse");
        let e0 = normalize_entry(&parsed.entries[0]);
        assert_eq!(
            e0.guid, "cd0017f2746ee934cf45ca0125100796",
            "the generated id moved, so this item would be stored twice"
        );
        assert_eq!(e0.url.as_deref(), Some("https://c.example/1"));
        let e1 = normalize_entry(&parsed.entries[1]);
        assert_eq!(e1.guid, "c6");
        assert_eq!(e1.url.as_deref(), Some("https://c.example/6"));
    }

    /// The same for Atom, where 3.0 also reads `wfw:commentRss`.
    #[test]
    fn an_atom_comment_feed_link_is_neither_the_permalink_nor_the_id() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:wfw="http://wellformedweb.org/CommentAPI/"><title>a</title>
<entry><title>commentRss before link, no id</title><wfw:commentRss>https://a.example/1/feed</wfw:commentRss><link href="https://a.example/1"/><updated>2020-06-01T00:00:00Z</updated></entry>
</feed>"#;
        let e = normalize_entry(&parse_feed(xml.as_bytes()).expect("parse").entries[0]);
        assert_eq!(e.guid, "5148a3d11836efc42f82a7b25a38383d");
        assert_eq!(e.url.as_deref(), Some("https://a.example/1"));
    }

    /// **An item with no guid and no permalink gets a guid that holds still.**
    /// feed-rs's default generator falls back to a random UUID when an entry
    /// has no link, so such an item was a new row on every poll (in 2.4 as in
    /// 3.0). It now falls through to [`stable_guid`]. A comments link is not a
    /// permalink, so an item carrying only one is in the same position — and
    /// is not given the comments page as its URL.
    #[test]
    fn an_item_without_guid_or_permalink_dedups_across_polls() {
        let xml = r#"<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>only a title</title><description>body</description></item>
<item><title>Only a comments link</title><comments>https://c.example/2#comments</comments></item>
</channel></rss>"#;
        let first = parse_feed(xml.as_bytes()).expect("parse");
        let second = parse_feed(xml.as_bytes()).expect("parse");
        for i in 0..2 {
            let a = normalize_entry(&first.entries[i]);
            let b = normalize_entry(&second.entries[i]);
            assert_eq!(
                a.guid, b.guid,
                "entry {i}'s guid changed between two parses"
            );
            assert!(a.guid.starts_with("featherreader:synthetic:"), "{}", a.guid);
            assert_eq!(a.url, None, "entry {i}");
        }
    }

    /// **The author is the person's name.** feed-rs 2.4 named every RSS
    /// `<author>` "author" (the element name; the text went to `email`) and an
    /// Atom author with an empty `<name>` "unknown", and FeatherReader stored
    /// those words as the byline. 3.0 splits name from address but leaves the
    /// `(Name)` of the RSS `address (Name)` form in its parentheses.
    #[test]
    fn the_author_is_the_name_not_the_element_or_the_address() {
        let xml = r#"<?xml version="1.0"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><title>p</title>
<item><title>a1</title><guid>a1</guid><author>alice@example.com (Alice Example)</author></item>
<item><title>a2</title><guid>a2</guid><author>bob@example.com</author></item>
<item><title>a3</title><guid>a3</guid><author>Carol</author></item>
<item><title>a4</title><guid>a4</guid><dc:creator>Dave &lt;dave@example.com&gt;</dc:creator></item>
<item><title>a5</title><guid>a5</guid><author>erin@example.com ()</author></item>
</channel></rss>"#;
        let parsed = parse_feed(xml.as_bytes()).expect("parse");
        let authors: Vec<Option<String>> = parsed
            .entries
            .iter()
            .map(|e| normalize_entry(e).author)
            .collect();
        assert_eq!(
            authors,
            vec![
                Some("Alice Example".to_string()),
                None,
                Some("Carol".to_string()),
                Some("Dave".to_string()),
                None,
            ]
        );

        let atom = r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>a</title>
<entry><id>x1</id><title>t</title><author><name></name></author></entry>
<entry><id>x2</id><title>t</title><author><name>Bob</name></author></entry>
</feed>"#;
        let parsed = parse_feed(atom.as_bytes()).expect("parse");
        assert_eq!(normalize_entry(&parsed.entries[0]).author, None);
        assert_eq!(
            normalize_entry(&parsed.entries[1]).author.as_deref(),
            Some("Bob")
        );
    }

    /// **The byline is the first author that HAS a name.** An item giving
    /// `<author>` as a bare address and the name in `<dc:creator>` has two
    /// people, and the first has no name; taking only the first lost the byline.
    #[test]
    fn the_byline_is_the_first_author_with_a_name() {
        let xml = r#"<?xml version="1.0"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><title>p</title>
<item><title>b1</title><guid>b1</guid><author>bob@example.com</author><dc:creator>Bob Smith</dc:creator></item>
<item><title>b2</title><guid>b2</guid><author>erin@example.com ()</author><dc:creator>Erin</dc:creator></item>
<item><title>b3</title><guid>b3</guid><author>only@example.com</author></item>
</channel></rss>"#;
        let parsed = parse_feed(xml.as_bytes()).expect("parse");
        let authors: Vec<Option<String>> = parsed
            .entries
            .iter()
            .map(|e| normalize_entry(e).author)
            .collect();
        assert_eq!(
            authors,
            vec![
                Some("Bob Smith".to_string()),
                Some("Erin".to_string()),
                None
            ]
        );
    }

    /// Author strings that make feed-rs 3.0 panic: its name/address splitter
    /// (`parser/util/mod.rs`, `parse_person_name_email`) slices one byte either
    /// side of the address, which is not a character boundary when a multi-byte
    /// character touches it.
    const PANICKING_AUTHORS: [&str; 3] = [
        "jose@example.com（José）",
        "«zoe@example.com» Zoë Long Name Here",
        "Zoë Long Name «zoe@example.com»",
    ];

    /// Every place feed-rs runs that splitter, as a whole document around `v`.
    fn documents_with_author(v: &str) -> Vec<(&'static str, String)> {
        vec![
            (
                "rss author",
                format!(
                    r#"<?xml version="1.0"?><rss version="2.0"><channel><title>t</title><item><title>x</title><guid>g</guid><author>{v}</author></item></channel></rss>"#
                ),
            ),
            (
                "rss dc:creator",
                format!(
                    r#"<?xml version="1.0"?><rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><title>t</title><item><title>x</title><guid>g</guid><dc:creator>{v}</dc:creator></item></channel></rss>"#
                ),
            ),
            (
                "rss managingEditor",
                format!(
                    r#"<?xml version="1.0"?><rss version="2.0"><channel><title>t</title><managingEditor>{v}</managingEditor><item><title>x</title><guid>g</guid></item></channel></rss>"#
                ),
            ),
            (
                "rss webMaster",
                format!(
                    r#"<?xml version="1.0"?><rss version="2.0"><channel><title>t</title><webMaster>{v}</webMaster><item><title>x</title><guid>g</guid></item></channel></rss>"#
                ),
            ),
            (
                "rss1 dc:creator",
                format!(
                    r#"<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><title>t</title></channel><item><title>x</title><link>https://e.example/1</link><dc:creator>{v}</dc:creator></item></rdf:RDF>"#
                ),
            ),
            (
                "json author",
                format!(
                    r#"{{"version":"https://jsonfeed.org/version/1.1","title":"t","items":[{{"id":"1","content_text":"x","authors":[{{"name":"{v}"}}]}}]}}"#
                ),
            ),
        ]
    }

    /// **A parser panic is a parse failure, not a crash.** feed-rs 3.0 panics
    /// on [`PANICKING_AUTHORS`]. Uncaught, the panic escaped `poll_feed`, killed
    /// the poll task after the scheduler had already moved `next_poll`, and
    /// recorded no failure — the feed stopped updating with nothing to say why.
    #[test]
    fn a_feed_rs_panic_is_returned_as_an_error() {
        for v in PANICKING_AUTHORS {
            for (slot, doc) in documents_with_author(v) {
                let err = match parse_feed(doc.as_bytes()) {
                    Ok(_) => {
                        panic!("{slot} {v:?}: parsed; the fixture no longer reaches the panic")
                    }
                    Err(e) => format!("{e:#}"),
                };
                assert!(err.contains("panicked"), "{slot} {v:?}: {err}");
            }
        }
        // The same slots with an ASCII neighbour parse normally.
        for (slot, doc) in documents_with_author("jose@example.com (Jose)") {
            assert!(parse_feed(doc.as_bytes()).is_ok(), "{slot}");
        }
    }

    /// End to end: a poll of a feed that panics the parser reports
    /// `FailureKind::Parse`, so it is backed off and its `last_error` says why.
    #[tokio::test]
    async fn a_poll_of_a_feed_that_panics_the_parser_is_a_parse_failure() {
        let doc = &documents_with_author(PANICKING_AUTHORS[0])[0].1;
        let base = crate::net::tests::serve_body(doc.as_bytes().to_vec()).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "panicking-author.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let url = format!("http://panicking-author.test:{port}/feed.xml");
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::upsert_feed(
            &pool,
            &crate::store::NewFeed {
                url: url.clone(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let feed = crate::store::get_feed_by_url(&pool, &url)
            .await
            .unwrap()
            .unwrap();
        let client = build_client().unwrap();
        let outcome = poll_feed(&pool, &client, &feed, 0)
            .await
            .expect("a parser panic surfaced as a store error");
        match outcome {
            PollOutcome::Failed {
                kind: FailureKind::Parse,
                detail,
                ..
            } => assert!(detail.contains("panicked"), "{detail}"),
            other => panic!("expected a parse failure, got {other:?}"),
        }
    }

    // ---- dedup-key hashes are fixed across toolchains -------------------
    //
    // `stable_guid` and `bound_guid` are stored dedup keys. They were built on
    // `std`'s `DefaultHasher`, whose algorithm the standard library documents
    // as unspecified and subject to change between releases; a toolchain bump
    // could have re-keyed every such entry and duplicated it. The values below
    // were produced by that `DefaultHasher` code, so they also prove the
    // replacement hashes identically today.

    #[test]
    fn a_synthetic_guid_is_the_value_already_stored() {
        let xml = r#"<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>only a title</title><description>body</description></item>
<item><description>no title either</description></item>
<item><title>Tïtle wíth ünïcode</title></item>
</channel></rss>"#;
        let parsed = parse_feed(xml.as_bytes()).expect("parse");
        let guids: Vec<String> = parsed
            .entries
            .iter()
            .map(|e| normalize_entry(e).guid)
            .collect();
        assert_eq!(
            guids,
            vec![
                "featherreader:synthetic:964034cf9a24b551".to_string(),
                "featherreader:synthetic:baa7c19198c76b30".into(),
                "featherreader:synthetic:34b72cc7fa0a59ac".into(),
            ]
        );
    }

    #[test]
    fn a_long_guid_is_the_value_already_stored() {
        let a = bound_guid("g".repeat(MAX_GUID_BYTES + 1));
        let b = bound_guid(format!(
            "https://long.example/{}",
            "ü".repeat(MAX_GUID_BYTES)
        ));
        assert_eq!(
            (a.as_str(), b.as_str()),
            (
                "featherreader:long-guid:966404db20ef8f05",
                "featherreader:long-guid:a1d631602455ace4",
            )
        );
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
        let parsed = parse_feed(xml.as_bytes()).expect("parse");
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
        let parsed2 = parse_feed(xml2.as_bytes()).expect("parse");
        let e2 = normalize_entry(&parsed2.entries[0]);
        assert_eq!(e2.url, None);

        // A normal https link survives.
        let xml3 = r#"<?xml version="1.0"?><rss version="2.0"><channel>
            <title>t</title>
            <item><title>ok</title><link>https://ok.example/post</link><guid>ok1</guid></item>
        </channel></rss>"#;
        let parsed3 = parse_feed(xml3.as_bytes()).expect("parse");
        let e3 = normalize_entry(&parsed3.entries[0]);
        assert_eq!(e3.url.as_deref(), Some("https://ok.example/post"));
    }

    #[test]
    fn classify_privacy_flags_secret_urls_across_providers() {
        // --- Known providers: newsletters ---
        // Substack private feed path.
        assert!(
            classify_feed_privacy("https://author.substack.com/feed/private/deadbeefcafe1234")
                .is_private()
        );
        // Patreon ?auth= member feed.
        assert!(classify_feed_privacy(
            "https://www.patreon.com/rss/author?auth=Zm9vYmFyc2VjcmV0dG9rZW4"
        )
        .is_private());
        // Ghost members feed via ?uuid=.
        assert!(classify_feed_privacy(
            "https://blog.ghost.io/rss/?uuid=1f2e3d4c-5b6a-7089-90ab-cdef01234567"
        )
        .is_private());

        // --- Known providers: private podcasts ---
        // Supporting Cast tokened podcast feed.
        assert!(classify_feed_privacy(
            "https://feeds.supportingcast.fm/show/abcdef0123456789abcdef01"
        )
        .is_private());
        // Supercast private podcast (host alone is enough).
        assert!(classify_feed_privacy("https://feeds.supercast.com/12345/rss").is_private());

        // --- Generic, provider-agnostic heuristic ---
        // Named credential query params with an opaque value.
        assert!(
            classify_feed_privacy("https://example.com/feed?token=Zm9vYmFyc2VjcmV0").is_private()
        );
        assert!(
            classify_feed_privacy("https://example.com/feed?key=Zm9vYmFyc2VjcmV0").is_private()
        );
        assert!(
            classify_feed_privacy("https://example.com/feed?secret=Zm9vYmFyc2VjcmV0").is_private()
        );
        // Userinfo credentials in the authority.
        assert!(classify_feed_privacy("https://user:pass@example.com/feed").is_private());
        // A `/private/` path segment on an unknown host.
        assert!(classify_feed_privacy("https://blog.example.com/private/rss").is_private());
        // `/members/` path convention.
        assert!(classify_feed_privacy("https://news.example.com/members/feed.xml").is_private());
        // A high-entropy opaque token embedded in the path with no telltale name.
        assert!(
            classify_feed_privacy("https://feeds.example.com/aB3xK9zQ7mP2rT5wL8nD4vF6")
                .is_private()
        );
        // A bare UUID path segment (many tokened feeds).
        assert!(classify_feed_privacy(
            "https://feeds.example.com/1f2e3d4c-5b6a-7089-90ab-cdef01234567"
        )
        .is_private());
    }

    /// The dominant real-world private-podcast shape delivers the token as a
    /// FILENAME (`<token>.rss` / `<token>.xml`) or affixed inside a larger
    /// segment (`feed-<uuid>`). Named providers are caught by their host rule;
    /// these are UNKNOWN-provider CDNs that must still be caught by the generic
    /// backstop, so the secret is never fetched or stored.
    #[test]
    fn classify_privacy_catches_tokened_filenames_on_unknown_hosts() {
        // **A stem only the extension-strip branch can see.** Every other case
        // here is also caught by the sub-part scan (branch 3) or the UUID scan,
        // so deleting the strip left the suite green — `FEED_EXTENSIONS` was
        // effectively dead. This stem's `-`-separated parts are each too short
        // to look like a secret on their own, and the whole segment fails on
        // the `.` — only stripping `.rss` and re-testing the 26-char stem sees
        // it. That is exactly the shape a hyphen-bearing base64url token
        // filename takes.
        assert!(
            classify_feed_privacy("https://cdn.example/feeds/aB3xK9pQ-7mZ2vN8w-Qr5tYuW.rss")
                .is_private(),
            "a token stem visible only after stripping the extension was not caught"
        );
        // hex-32 token as an .xml filename.
        assert!(classify_feed_privacy(
            "https://cdn.somepod.io/f/a1b2c3d4e5f60718293a4b5c6d7e8f90.xml"
        )
        .is_private());
        // hex-32 token as a .rss filename on an unknown CDN.
        assert!(classify_feed_privacy(
            "https://dcs.megaphone.example/network/a1b2c3d4e5f60718293a4b5c6d7e8f90.rss"
        )
        .is_private());
        // UUID + .xml filename.
        assert!(classify_feed_privacy(
            "https://brandnew.example/feed/1f2e3d4c-5b6a-7089-90ab-cdef01234567.xml"
        )
        .is_private());
        // UUID affixed with a prefix (`feed-<uuid>`) — split can't see it, the
        // UUID-substring scan must.
        assert!(classify_feed_privacy(
            "https://x.example/feed-1f2e3d4c-5b6a-7089-90ab-cdef01234567"
        )
        .is_private());
        // UUID + .rss suffix.
        assert!(classify_feed_privacy(
            "https://x.example/1f2e3d4c-5b6a-7089-90ab-cdef01234567.rss"
        )
        .is_private());
        // hex-16 token as an .xml filename.
        assert!(classify_feed_privacy("https://x.example/feed/9f8e7d6c5b4a3928.xml").is_private());
        // A base64url token with `=` padding as a clean path segment.
        assert!(
            classify_feed_privacy("https://cdn.pod.io/f/YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnc=")
                .is_private()
        );
    }

    /// YouTube channel/playlist RSS feeds are FULLY PUBLIC (the id is a public
    /// handle, not a secret) and are the standard way to subscribe to a channel —
    /// they must NOT be false-blocked by the generic entropy heuristic.
    #[test]
    fn classify_privacy_allows_public_youtube_feeds() {
        assert_eq!(
            classify_feed_privacy(
                "https://www.youtube.com/feeds/videos.xml?channel_id=UC-lHJZR3Gqxm24_Vd_AJ5Yw"
            ),
            FeedPrivacy::Public
        );
        assert_eq!(
            classify_feed_privacy(
                "https://www.youtube.com/feeds/videos.xml?playlist_id=PLFgquLnL59alCl_2TQvOiD5Vgm1hCaGSI"
            ),
            FeedPrivacy::Public
        );
        // Bare host form too.
        assert_eq!(
            classify_feed_privacy(
                "https://youtube.com/feeds/videos.xml?channel_id=UC-lHJZR3Gqxm24_Vd_AJ5Yw"
            ),
            FeedPrivacy::Public
        );
        // The allowlist is narrow: a `token=` on the YouTube feeds path still
        // classifies private (can't smuggle a credential through the allowlist).
        assert!(classify_feed_privacy(
            "https://www.youtube.com/feeds/videos.xml?token=Zm9vYmFyc2VjcmV0dG9rZW4"
        )
        .is_private());
    }

    #[test]
    fn classify_privacy_leaves_normal_public_feeds_public() {
        // Plain feed documents.
        assert_eq!(
            classify_feed_privacy("https://example.com/feed.xml"),
            FeedPrivacy::Public
        );
        assert_eq!(
            classify_feed_privacy("https://blog.example.com/rss"),
            FeedPrivacy::Public
        );
        assert_eq!(
            classify_feed_privacy("https://blog.example.com/rss.xml"),
            FeedPrivacy::Public
        );
        // A Substack PUBLIC feed (`/feed`, not `/feed/private/`) stays public.
        assert_eq!(
            classify_feed_privacy("https://author.substack.com/feed"),
            FeedPrivacy::Public
        );
        // A WordPress `/feed` endpoint.
        assert_eq!(
            classify_feed_privacy("https://wordpress.example.com/feed/"),
            FeedPrivacy::Public
        );
        // A plain Atom feed.
        assert_eq!(
            classify_feed_privacy("https://example.org/atom.xml"),
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
        // A short, non-opaque value on a named key (e.g. an enum) is not a secret.
        assert_eq!(
            classify_feed_privacy("https://example.com/feed?p=2"),
            FeedPrivacy::Public
        );
        // An empty credential value is not a secret.
        assert_eq!(
            classify_feed_privacy("https://example.com/feed?token="),
            FeedPrivacy::Public
        );
        // A hyphenated slug ending in a feed extension must NOT be seen as a
        // tokened filename (the stem is short dictionary words, not a blob).
        assert_eq!(
            classify_feed_privacy("https://example.com/my-first-long-blog-post.xml"),
            FeedPrivacy::Public
        );
        // A short hex episode id in an .xml filename (< 16 chars) is not a secret.
        assert_eq!(
            classify_feed_privacy("https://example.com/episodes/ab12cd.xml"),
            FeedPrivacy::Public
        );
        // A dotted host-style filename slug stays public.
        assert_eq!(
            classify_feed_privacy("https://example.com/category/tech-news/feed.xml"),
            FeedPrivacy::Public
        );
        // Unparseable URL: treated as Public (add path rejects it downstream).
        assert_eq!(classify_feed_privacy("not a url"), FeedPrivacy::Public);
    }

    /// **The detail is bounded where it is CONSTRUCTED, not only where it is
    /// stored.**
    ///
    /// Review found that widening `PollOutcome::Failed` with this field opened a
    /// second sink nobody looked at: `web.rs`'s `add_subscription` logs
    /// `?outcome` at INFO on a user-facing request path, so the whole
    /// untruncated anyhow chain — redirect-hop URLs, the SSRF guard's refusal
    /// text naming a resolved internal address — went to the access log.
    ///
    /// Bounding inside `bump_feed_errors` protected the database and nothing
    /// else. Bounding at construction protects every sink, including the ones
    /// added later.
    #[test]
    fn a_failure_detail_is_bounded_at_construction() {
        let huge = "x".repeat(10_000);
        let outcome = PollOutcome::Failed {
            backoff: BACKOFF_BASE,
            kind: FailureKind::Fetch,
            detail: failure_detail(&huge),
        };
        let PollOutcome::Failed { detail, .. } = &outcome else {
            panic!("wrong variant");
        };
        assert!(
            detail.chars().count() <= MAX_FAILURE_DETAIL_CHARS,
            "detail was {} chars",
            detail.chars().count(),
        );
        // And the Debug rendering — which is what actually reached the log — is
        // bounded with it.
        assert!(format!("{outcome:?}").len() < 1_000);
    }

    /// **Every failure kind has its own label, and they round-trip.**
    ///
    /// Review found that collapsing all four `as_str` arms to `"fetch"` left
    /// the whole suite green: every test of these columns passed string
    /// literals, so nothing tied a variant to its label. A histogram whose
    /// buckets all say the same thing is worse than no histogram — it reports a
    /// single confident cause for four different failures.
    ///
    /// Asserted over `ALL` rather than a hand-written list, so adding a variant
    /// without a label fails here instead of silently sharing one.
    #[test]
    fn every_failure_kind_has_a_distinct_round_tripping_label() {
        let mut seen = std::collections::BTreeSet::new();
        for kind in FailureKind::ALL {
            let label = kind.as_str();
            assert!(
                seen.insert(label),
                "{label:?} is used by more than one FailureKind",
            );
            assert_eq!(
                FailureKind::parse(label),
                Some(kind),
                "{label:?} does not read back as the kind that wrote it",
            );
        }
        assert_eq!(seen.len(), FailureKind::ALL.len());
        // A label from a newer build is not attributed to a cause this one
        // knows — the `metrics::Backend::parse` contract.
        assert_eq!(FailureKind::parse("quota"), None);
    }

    /// **Escalation reaches `settle_poll`.** `backoff_for` grows with the
    /// count and is tested alone; nothing asserted that the poll path passes
    /// the COUNT in. `backoff_for(1)` in its place left the whole suite green
    /// — a permanently dead feed retrying forever at the first-failure floor,
    /// which the comment on that line says must not happen.
    #[tokio::test]
    async fn backoff_escalates_with_consecutive_failures() -> anyhow::Result<()> {
        let pool = crate::store::init_url("sqlite::memory:").await?;
        let url = "https://dead.example/feed.xml";
        crate::store::upsert_feed(
            &pool,
            &crate::store::NewFeed {
                url: url.to_string(),
                ..Default::default()
            },
        )
        .await?;
        for _ in 0..5 {
            crate::store::bump_feed_errors(&pool, url, FailureKind::Fetch, "down").await?;
        }
        let before = chrono::Utc::now();
        settle_poll(
            &pool,
            url,
            &PollOutcome::Failed {
                backoff: Duration::from_secs(300),
                kind: FailureKind::Fetch,
                detail: "still down".to_string(),
            },
            Duration::from_secs(3600),
        )
        .await;
        let next: String = sqlx::query_scalar("SELECT next_poll FROM feeds WHERE url = ?1")
            .bind(url)
            .fetch_one(&pool)
            .await?;
        let next = chrono::DateTime::parse_from_rfc3339(&next)?.with_timezone(&chrono::Utc);
        let delay = (next - before).num_seconds();
        let expected = backoff_for(6).as_secs() as i64;
        assert!(
            (delay - expected).abs() <= 60,
            "sixth failure scheduled {delay}s out; escalation says {expected}s"
        );
        assert!(
            delay > backoff_for(1).as_secs() as i64 + 60,
            "the sixth failure landed on the first-failure floor"
        );
        Ok(())
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(backoff_for(1), BACKOFF_BASE);
        assert!(backoff_for(2) > backoff_for(1));
        assert_eq!(backoff_for(100), BACKOFF_MAX);
    }

    /// **Storable and pollable are ONE decision.**
    ///
    /// Review found the sequencing error this closes: making `at://` storable
    /// while nothing can poll it does not leave the feature dormant, it creates
    /// permanent failures that the cause histogram then publishes as
    /// unreachable publishers — the exact conflation it exists to end.
    #[test]
    fn an_at_uri_is_not_storable_while_standard_site_is_off() {
        let uri = "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab";
        assert!(
            !is_storable_feed_url(uri, false),
            "stored a feed nothing can poll"
        );
        assert!(is_storable_feed_url(uri, true));
        assert!(is_storable_feed_url("https://example.com/feed.xml", false));
        assert!(is_storable_feed_url("https://example.com/feed.xml", true));
    }

    /// **A non-canonical scheme spelling is recognised and refused.** URL
    /// schemes are case-insensitive, so `At://` names the same thing as
    /// `at://` — but `feeds.url` is UNIQUE, so accepting both is two rows for
    /// one publication. Recognised (not passed through to the generic checks
    /// as if it were an ordinary URL), then refused for the spelling.
    /// Since publications are polled, only a URI the storage guard accepts is
    /// a publication. Any other at-URI is Unsupported, which no poller reads.
    #[test]
    fn only_a_storable_publication_uri_is_a_publication() {
        let did = "did:plc:ohutz6x5acjmpuulp3x7wxxc";
        let pubn = crate::lexicon::nsid::STANDARD_PUBLICATION;
        assert_eq!(
            FeedKind::of(&format!("at://{did}/{pubn}/3lab")),
            FeedKind::Publication
        );
        for unsupported in [
            format!("at://{did}/app.bsky.feed.post/3lab"),
            format!("At://{did}/{pubn}/3lab"),
            format!("at://alice.example.com/{pubn}/3lab"),
            format!("at://did:plc:short/{pubn}/3lab"),
        ] {
            assert_eq!(
                FeedKind::of(&unsupported),
                FeedKind::Unsupported,
                "{unsupported}"
            );
        }
        assert_eq!(FeedKind::of("https://example.com/feed.xml"), FeedKind::Rss);
        assert!(!FeedKind::POLLABLE.contains(&FeedKind::Unsupported));
        assert_eq!(FeedKind::parse("unsupported"), Some(FeedKind::Unsupported));
    }

    #[test]
    fn a_non_canonical_at_uri_spelling_is_recognised_and_refused() {
        for odd in [
            "At://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab",
            "AT://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab",
        ] {
            assert!(!is_storable_feed_url(odd, true), "stored {odd:?}");
            // Fails CLOSED: it is an at-URI this reader will not store, not an
            // unparseable string that the `Err(_) => Public` arm waves through.
            assert!(
                classify_feed_privacy(odd).is_private(),
                "{odd:?} was declared publishable"
            );
        }
    }

    /// **The handle form is not storable — the DID form is the identity.**
    ///
    /// `feeds.url` is UNIQUE; a handle and its DID would be two rows for one
    /// publication, and a handle can change hands. Every spelling is refused,
    /// canonical or not; resolving one to a DID is the input path's job.
    #[test]
    fn a_handle_form_publication_uri_is_not_storable() {
        for authority in [
            "alice.example.com",
            "EXAMPLE.COM",
            "169.254.169.254",
            "pds.internal",
            "printer.local",
            "host:8080",
            "-.-",
            "a b.c",
        ] {
            let uri = format!("at://{authority}/site.standard.publication/3lab");
            assert!(
                !is_storable_feed_url(&uri, true),
                "accepted authority {authority:?}"
            );
        }
    }

    /// A control character or space in the at-URI is refused: `scheduler.rs`
    /// logs `%feed.url` with Display, and `feeds.url` is UNIQUE.
    #[test]
    fn an_at_uri_with_control_characters_is_not_storable() {
        for bad in [
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab\n",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab ",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3l\tab",
        ] {
            assert!(!is_storable_feed_url(bad, true), "accepted {bad:?}");
        }
    }

    /// **The `at://` exemption is a REGRESSION unless it is narrow.**
    ///
    /// Fan-out review found the arm I added was a bare prefix match, so *any*
    /// attacker-chosen string starting `at://` was declared safe to publish —
    /// skipping the userinfo check, the known-provider table, the private-path
    /// markers, the secret-query keys and the entropy heuristics. Measured
    /// against `main`, these three went from `Private` to `Public`.
    ///
    /// That matters because `rename_subscription` caches the URL AND rewrites
    /// the user's PUBLIC PDS record, with `classify_feed_privacy` as its only
    /// gate.
    #[test]
    fn a_credential_bearing_at_uri_is_still_private() {
        for hostile in [
            "at://user:pass@private.example.com/feed/private/TOKEN?apikey=deadbeefdeadbeef",
            "at://patreon.com/rss/12345?auth=deadbeefdeadbeefdeadbeef",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab?apikey=sekrit",
        ] {
            assert!(
                matches!(classify_feed_privacy(hostile), FeedPrivacy::Private(_)),
                "declared public: {hostile}"
            );
        }
    }

    /// An rkey is `[A-Za-z0-9._:~-]` per atproto. Without that, a query string
    /// or path fragment smuggled into the rkey satisfies the three-segment
    /// check — which is what the exemption above keys off.
    #[test]
    fn an_rkey_outside_the_atproto_charset_is_not_storable() {
        for bad in [
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab?apikey=sekrit",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab#frag",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab%2Fevil",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/caf\u{e9}",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab\u{202e}x",
        ] {
            assert!(!is_storable_feed_url(bad, true), "accepted rkey in {bad:?}");
        }
        // The legitimate charset still passes.
        for good in [
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab2c4d5e6f7g8h",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/a.b_c~d-e",
        ] {
            assert!(is_storable_feed_url(good, true), "refused {good:?}");
        }
    }

    /// **A real rkey is a TID, and a TID looks exactly like a secret.**
    ///
    /// Without an explicit `at://` arm, `classify_feed_privacy` runs the generic
    /// "high-entropy token in path" heuristic over the rkey. Measured: a
    /// realistic 16-char rkey on a handle-form at-URI is classified PRIVATE and
    /// the subscription REFUSED. The DID form escaped only because it fails to
    /// parse as a `Url` at all — so the bug was invisible from that side.
    ///
    /// The first version of this test used the rkey `3lab`, which is too short
    /// to trip the heuristic, so it passed with and without the fix.
    #[test]
    fn a_realistic_at_uri_rkey_is_not_mistaken_for_a_secret() {
        for uri in [
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab2c4d5e6f7g8h",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/aB3xK9pQ7mZ2vN8w",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab2c4d5e6f7g8h",
        ] {
            assert_eq!(
                classify_feed_privacy(uri),
                FeedPrivacy::Public,
                "a publication rkey was mistaken for a credential: {uri}"
            );
        }
    }

    /// **The DID form is the one that matters, and the one `Url::parse` cannot
    /// read.**
    ///
    /// `Url::parse("at://did:plc:…/…")` fails with *invalid port number* — the
    /// colons in the DID are taken as a port separator. So the obvious
    /// implementation, adding `"at"` to the `matches!` on `u.scheme()`, silently
    /// rejects every DID-based at-URI while appearing to work: the handle form
    /// (`at://alice.example.com/…`) parses fine and would pass such a test.
    ///
    /// All 19 at-URI rows in production are the DID form. A test written with a
    /// handle would have passed against an implementation that cannot store a
    /// single one of them.
    #[test]
    fn a_did_form_publication_uri_is_storable() {
        assert!(is_storable_feed_url(
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab",
            true
        ));
    }

    /// **An allowlist entry, not a loosening.** `at://` is accepted for exactly
    /// one foreign collection. Any other collection is somebody else's lexicon
    /// arriving through a path (`resolve_subscriptions`, OPML import) that takes
    /// records from outside with no add-path to reject them.
    #[test]
    fn an_at_uri_for_another_collection_is_not_storable() {
        assert!(!is_storable_feed_url(
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/community.lexicon.rss.subscription/3lab",
            true
        ));
        assert!(!is_storable_feed_url(
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/app.bsky.feed.post/3lab",
            true
        ));
    }

    /// The malformed shapes, each of which a naive `split('/')` would accept.
    #[test]
    fn a_malformed_at_uri_is_not_storable() {
        for bad in [
            "at://",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/",
            "at:///site.standard.publication/3lab",
            "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab/extra",
            "at://not-a-did-or-handle/site.standard.publication/3lab",
            "at://did:plc:TOOSHORT/site.standard.publication/3lab",
        ] {
            assert!(!is_storable_feed_url(bad, true), "accepted {bad:?}");
        }
    }

    /// **The reason the function exists, unchanged.** Mutating the new branch to
    /// accept any scheme makes this fail while the at-URI tests keep passing —
    /// that asymmetry is what says the change was an allowlist entry.
    #[test]
    fn the_refused_schemes_are_still_refused() {
        for bad in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,<script>",
            "ftp://example.com/feed.xml",
            "at:did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab",
        ] {
            assert!(!is_storable_feed_url(bad, true), "accepted {bad:?}");
        }
        // A hostless http(s) URL is a PARSE error, not a parsed URL with no
        // host — `https:///feed.xml` even parses as host `feed.xml`. What
        // refuses these is the `Err` arm, so that is what this pins.
        for hostless in ["http://", "https://?q=1", "http:///"] {
            assert!(
                !is_storable_feed_url(hostless, true),
                "a hostless URL {hostless:?} was storable"
            );
        }
        assert!(is_storable_feed_url("https://example.com/feed.xml", true));
        assert!(is_storable_feed_url("http://example.com/feed.xml", true));
    }

    /// **What re-cleaning a stored body at render costs (#151).** Not a test: a
    /// measurement, kept so the numbers in the PR and CHANGELOG can be
    /// reproduced.
    ///
    /// ```text
    /// FEATHER_BENCH_FEEDS=/path/to/dir/of/feed/files \
    ///   cargo test --release --lib render_reclean_cost -- --ignored --nocapture
    /// ```
    ///
    /// 1. Typical bodies: real feed documents from that directory, put through
    ///    `normalize_entry` so each is exactly what ingest would store, then
    ///    re-cleaned with `SanitizedHtml::clean`. Also counts bodies the
    ///    re-clean changed.
    /// 2. Pathological bodies: #226's quadratic inputs in their stored
    ///    (fixed-point) form, up to the 2 MiB stored bound, through the bare
    ///    sanitizer. A hostile feed can make ingest store these (#226); they
    ///    are what the renderer's permits, single flight and cache are sized
    ///    against.
    ///    `FEATHER_BENCH_UNCAPPED_MAX=<bytes>` skips the larger sizes (2 MiB of
    ///    nesting takes ~37 s).
    #[test]
    #[ignore = "benchmark; see the doc comment"]
    fn render_reclean_cost() {
        use crate::sanitized_html::SanitizedHtml;
        use std::time::{Duration, Instant};

        fn pct(sorted: &[Duration], p: f64) -> Duration {
            sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
        }

        if let Ok(dir) = std::env::var("FEATHER_BENCH_FEEDS") {
            let mut times = Vec::new();
            let mut sizes = Vec::new();
            let (mut changed, mut files) = (0usize, 0usize);
            for path in std::fs::read_dir(&dir).unwrap() {
                let bytes = std::fs::read(path.unwrap().path()).unwrap();
                let Ok(parsed) = parse_feed(&bytes) else {
                    continue;
                };
                files += 1;
                for e in &parsed.entries {
                    let Some(stored) = normalize_entry(e).content_html else {
                        continue;
                    };
                    // Best of three, to take scheduler noise out of a small body.
                    let mut best = Duration::MAX;
                    let mut out = None;
                    for _ in 0..3 {
                        let t = Instant::now();
                        out = Some(SanitizedHtml::clean(&stored));
                        best = best.min(t.elapsed());
                    }
                    let out = out.unwrap();
                    changed += usize::from(out.as_str() != stored);
                    times.push(best);
                    sizes.push(stored.len());
                }
            }
            times.sort();
            sizes.sort();
            println!(
                "real feeds: {files} files, {} bodies; size p50 {} B, p99 {} B, max {} B",
                times.len(),
                sizes[sizes.len() / 2],
                sizes[((sizes.len() - 1) as f64 * 0.99).round() as usize],
                sizes[sizes.len() - 1],
            );
            println!(
                "  re-clean p50 {:?}, p99 {:?}, max {:?}; changed by re-cleaning: {changed}",
                pct(&times, 0.5),
                pct(&times, 0.99),
                times[times.len() - 1],
            );
        }

        let bound = MAX_CONTENT_HTML_BYTES;
        let uncapped_max = std::env::var("FEATHER_BENCH_UNCAPPED_MAX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(bound);
        for size in [bound / 8, bound / 4, bound / 2, bound] {
            if size > uncapped_max {
                continue;
            }
            let depth = size / 11;
            for (name, stored) in [
                (
                    "'&' run",
                    format!("<p>{}</p>", "&amp;".repeat((size - 7) / 5)),
                ),
                (
                    "U+00A0 run",
                    format!("<p>{}</p>", "&nbsp;".repeat((size - 7) / 6)),
                ),
                (
                    "nested <div>",
                    format!("{}{}", "<div>".repeat(depth), "</div>".repeat(depth)),
                ),
                ("plain text", format!("<p>{}</p>", "a".repeat(size - 7))),
            ] {
                let t = Instant::now();
                let out = sanitize_html(&stored);
                println!(
                    "pathological {name:>13} {:>8} B: {:?} (fixed point: {})",
                    stored.len(),
                    t.elapsed(),
                    out == stored
                );
            }
        }
    }
}

/// #226: ingest sanitizing runs off the async runtime, under a permit and a
/// per-entry timeout, and a timed-out poll neither loses a stored body nor
/// saves the validators that would turn the next poll into a `304`.
#[cfg(test)]
mod sanitize_off_runtime_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use tokio::sync::Semaphore;

    /// A body ammonia is super-linear on: one text node of `&`. 48 Ki of them
    /// take ~2.5 s to sanitize in a debug build on an M-series Mac (32 Ki
    /// measured 1.1 s, 64 Ki 4.5 s) — far past [`SHORT`], short enough that the
    /// abandoned thread finishes soon after the test.
    fn slow_body() -> String {
        format!("<p>{}</p>", "&".repeat(48 * 1024))
    }

    /// The injected timeout for a poll that must give up on [`slow_body`].
    const SHORT: Duration = Duration::from_millis(100);

    /// Generous enough that [`slow_body`] always finishes in a debug build.
    const GENEROUS: Duration = Duration::from_secs(120);

    const ETAG_V1: &str = "\"v1\"";
    const LAST_MODIFIED_V1: &str = "Tue, 06 Oct 2026 08:00:00 GMT";

    /// Permits of the test's own, so an abandoned sanitize here never holds up
    /// another test's poll (the production semaphore is process-wide).
    fn permits(n: usize) -> &'static Semaphore {
        Box::leak(Box::new(Semaphore::new(n)))
    }

    /// `permits` and `timeout`, with an in-flight set of the call's own.
    fn limits(permits: &'static Semaphore, timeout: Duration) -> SanitizeLimits {
        SanitizeLimits {
            permits,
            in_flight: Box::leak(Box::new(InFlight::new())),
            timeout,
            sanitize: sanitize_body,
        }
    }

    const ORDINARY_A: &str = "<p>Before the slow one <script>x()</script><em>kept</em>.</p>";
    const ORDINARY_B: &str = "<p>After the slow one, <b>bold</b>.</p>";

    /// An RSS document: `a` (ordinary), `slow` (the given body), `b` (ordinary),
    /// `bare` (no body at all).
    fn rss(slow: &str) -> String {
        let item = |guid: &str, body: Option<&str>| {
            let desc = body
                .map(|b| format!("<description><![CDATA[{b}]]></description>"))
                .unwrap_or_default();
            format!(
                "<item><title>{guid}</title><link>https://slow.example/{guid}</link>\
                 <guid>urn:{guid}</guid>{desc}</item>"
            )
        };
        format!(
            r#"<?xml version="1.0"?><rss version="2.0"><channel><title>Slow</title>
<link>https://slow.example/</link>{}{}{}{}</channel></rss>"#,
            item("a", Some(ORDINARY_A)),
            item("slow", Some(slow)),
            item("b", Some(ORDINARY_B)),
            item("bare", None),
        )
    }

    /// Serve `body` with `ETag` / `Last-Modified`, and answer `304` to a
    /// request that presents the `ETag` — as a real server would, which is what
    /// makes a wrongly saved validator visible: the next poll gets no bodies.
    async fn serve_with_validators(body: Arc<Mutex<Vec<u8>>>) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let body = body.lock().unwrap().clone();
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => req.extend_from_slice(&buf[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&req).to_ascii_lowercase();
                    let not_modified =
                        head.contains(&format!("if-none-match: {}", ETAG_V1.to_lowercase()));
                    let reply = if not_modified {
                        format!("HTTP/1.1 304 Not Modified\r\nETag: {ETAG_V1}\r\nConnection: close\r\n\r\n")
                            .into_bytes()
                    } else {
                        let mut r = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/rss+xml\r\nETag: {ETAG_V1}\r\n\
                             Last-Modified: {LAST_MODIFIED_V1}\r\nContent-Length: {}\r\n\
                             Connection: close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        r.extend_from_slice(&body);
                        r
                    };
                    let _ = sock.write_all(&reply).await;
                    let _ = sock.flush().await;
                });
            }
        });
        port
    }

    /// A store with one feed row for `host`, served by a fixture with `body`.
    async fn fixture(host: &str, body: String) -> (SqlitePool, Feed, Arc<Mutex<Vec<u8>>>) {
        let body = Arc::new(Mutex::new(body.into_bytes()));
        let port = serve_with_validators(Arc::clone(&body)).await;
        crate::net::test_host_override(host, std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        let url = format!("http://{host}:{port}/feed.xml");
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::upsert_feed(
            &pool,
            &NewFeed {
                url: url.clone(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let feed = crate::store::get_feed_by_url(&pool, &url)
            .await
            .unwrap()
            .unwrap();
        (pool, feed, body)
    }

    async fn bodies(pool: &SqlitePool) -> Vec<(String, Option<String>)> {
        sqlx::query_as("SELECT guid, content_html FROM entries ORDER BY guid")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    async fn validators(pool: &SqlitePool, url: &str) -> (Option<String>, Option<String>) {
        let f = crate::store::get_feed_by_url(pool, url)
            .await
            .unwrap()
            .unwrap();
        (f.etag, f.last_modified)
    }

    fn clean(raw: &str) -> Option<String> {
        Some(sanitize_html_bounded(raw, MAX_CONTENT_HTML_BYTES))
    }

    /// The red test for #226. On a current-thread runtime a sanitize run
    /// inline stops every timer until it returns; off the runtime, a ticker
    /// keeps firing throughout the poll, and the poll ends at the timeout.
    #[tokio::test(flavor = "current_thread")]
    async fn a_slow_body_is_sanitized_off_the_runtime_and_the_poll_gives_up_on_it() {
        let (pool, feed, _) = fixture("slow-body.test", rss(&slow_body())).await;

        // The largest gap between consecutive ticks while the poll runs.
        let done = Arc::new(AtomicBool::new(false));
        let ticker = {
            let done = Arc::clone(&done);
            tokio::spawn(async move {
                let mut last = Instant::now();
                let mut worst = Duration::ZERO;
                while !done.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    worst = worst.max(last.elapsed());
                    last = Instant::now();
                }
                worst
            })
        };
        tokio::task::yield_now().await;

        let client = build_client().unwrap();
        let started = Instant::now();
        let outcome = poll_feed_with(&pool, &client, &feed, 0, limits(permits(4), SHORT))
            .await
            .unwrap();
        let took = started.elapsed();
        done.store(true, Ordering::SeqCst);
        let worst_gap = ticker.await.unwrap();

        assert!(
            worst_gap < Duration::from_millis(700),
            "the runtime stalled for {worst_gap:?} during the poll: the sanitize ran on it"
        );
        // Tight enough that a sanitize timeout a few times `SHORT` fails it
        // (vacuous-test hunt of #274: `< 1 s` let an 8x timeout through;
        // 6x leaves a loaded CI runner room).
        assert!(
            took < SHORT * 6,
            "the poll took {took:?}; it should end at the {SHORT:?} timeout"
        );
        assert!(
            matches!(
                outcome,
                PollOutcome::Failed {
                    kind: FailureKind::Body,
                    ..
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(
            bodies(&pool).await,
            vec![
                // Before the slow entry: sanitized and stored as always.
                ("urn:a".to_string(), clean(ORDINARY_A)),
                // After it: refused while the slow entry's abandoned sanitize
                // runs (the per-feed refusal; `timed_out` backs it up), so
                // stored without a body.
                ("urn:b".to_string(), None),
                ("urn:bare".to_string(), None),
                // The slow entry itself: no body, and nothing degraded instead.
                ("urn:slow".to_string(), None),
            ]
        );
        assert_eq!(
            validators(&pool, &feed.url).await,
            (None, None),
            "a timed-out poll saved its validators: the next poll would be a 304"
        );
    }

    /// A re-poll that times out keeps every body already stored, and saves no
    /// validator; the next poll that can sanitize stores the real bodies
    /// (rather than being answered `304` forever).
    #[tokio::test]
    async fn a_timed_out_repoll_keeps_stored_bodies_and_the_next_poll_stores_real_ones() {
        let slow = slow_body();
        let (pool, feed, _) = fixture("slow-repoll.test", rss(&slow)).await;
        let feed_id = feed.id;
        let stored = |guid: &str, body: &str| NewEntry {
            guid: guid.to_string(),
            content_html: Some(body.to_string()),
            ..Default::default()
        };
        crate::store::insert_entries(
            &pool,
            feed_id,
            &[
                stored("urn:slow", "<p>old slow</p>"),
                stored("urn:b", "<p>old b</p>"),
            ],
            0,
        )
        .await
        .unwrap();

        let client = build_client().unwrap();
        let sem = permits(2);
        poll_feed_with(&pool, &client, &feed, 0, limits(sem, SHORT))
            .await
            .unwrap();
        assert_eq!(
            bodies(&pool).await,
            vec![
                ("urn:a".to_string(), clean(ORDINARY_A)),
                ("urn:b".to_string(), Some("<p>old b</p>".to_string())),
                ("urn:bare".to_string(), None),
                ("urn:slow".to_string(), Some("<p>old slow</p>".to_string())),
            ],
            "a timed-out poll changed a stored body"
        );
        assert_eq!(validators(&pool, &feed.url).await, (None, None));

        // The next poll — same server, same document — with time to finish.
        let feed = crate::store::get_feed_by_url(&pool, &feed.url)
            .await
            .unwrap()
            .unwrap();
        let outcome = poll_feed_with(&pool, &client, &feed, 0, limits(sem, GENEROUS))
            .await
            .unwrap();
        assert!(
            matches!(outcome, PollOutcome::Updated { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            bodies(&pool).await,
            vec![
                ("urn:a".to_string(), clean(ORDINARY_A)),
                ("urn:b".to_string(), clean(ORDINARY_B)),
                ("urn:bare".to_string(), None),
                ("urn:slow".to_string(), clean(&slow)),
            ]
        );
        assert_eq!(
            validators(&pool, &feed.url).await,
            (
                Some(ETAG_V1.to_string()),
                Some(LAST_MODIFIED_V1.to_string())
            )
        );

        // And the fixture does honour them, so the check above is meaningful.
        let feed = crate::store::get_feed_by_url(&pool, &feed.url)
            .await
            .unwrap()
            .unwrap();
        let outcome = poll_feed_with(&pool, &client, &feed, 0, limits(sem, GENEROUS))
            .await
            .unwrap();
        assert!(matches!(outcome, PollOutcome::NotModified), "{outcome:?}");
    }

    /// Ordinary bodies are stored exactly as the inline path (#224's
    /// `sanitize_html_bounded`, which `normalize_entry` and its tests pin)
    /// produces them.
    #[tokio::test]
    async fn ordinary_bodies_are_stored_byte_identical_to_the_inline_path() {
        let big = format!("<p>{}</p>", "word ".repeat(18_000));
        let doc = rss(&big);
        let (pool, feed, _) = fixture("ordinary-bodies.test", doc.clone()).await;
        let client = build_client().unwrap();
        let outcome = poll_feed_with(&pool, &client, &feed, 0, limits(permits(4), GENEROUS))
            .await
            .unwrap();
        assert!(
            matches!(outcome, PollOutcome::Updated { .. }),
            "{outcome:?}"
        );

        let mut inline: Vec<(String, Option<String>)> = parse_feed(doc.as_bytes())
            .unwrap()
            .entries
            .iter()
            .map(normalize_entry)
            .map(|e| (e.guid, e.content_html))
            .collect();
        inline.sort();
        assert_eq!(bodies(&pool).await, inline);
        assert_eq!(
            validators(&pool, &feed.url).await,
            (
                Some(ETAG_V1.to_string()),
                Some(LAST_MODIFIED_V1.to_string())
            )
        );
    }

    /// With every permit held, a poll waits for one **asynchronously**: other
    /// work on the same current-thread runtime goes on, and the poll finishes
    /// once a permit is free.
    ///
    /// A wait that blocks the runtime would never let the test release the
    /// permit, so it would hang rather than fail; a timeout on that same
    /// runtime could never fire. So the runtime runs on a thread of its own,
    /// and the test fails if it has not finished in 10 s (vacuous-test hunt of
    /// #274).
    #[test]
    fn a_poll_waits_for_a_permit_without_blocking_the_runtime() {
        use std::sync::mpsc::RecvTimeoutError;
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let runtime = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(poll_waits_for_a_permit());
            let _ = done_tx.send(());
        });
        match done_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(()) => runtime.join().unwrap(),
            // The body panicked: fail with its panic.
            Err(RecvTimeoutError::Disconnected) => {
                std::panic::resume_unwind(runtime.join().unwrap_err())
            }
            Err(RecvTimeoutError::Timeout) => {
                panic!("the poll blocked the runtime while waiting for a permit")
            }
        }
    }

    async fn poll_waits_for_a_permit() {
        let (pool, feed, _) = fixture("permit-wait.test", rss(ORDINARY_B)).await;
        let sem = permits(1);
        let held = sem.acquire().await.unwrap();

        let poll = tokio::spawn(async move {
            let client = build_client().unwrap();
            let outcome = poll_feed_with(&pool, &client, &feed, 0, limits(sem, GENEROUS))
                .await
                .unwrap();
            (outcome, bodies(&pool).await)
        });
        // Timers still fire on this runtime while the poll waits.
        let started = Instant::now();
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!poll.is_finished(), "the poll did not wait for a permit");

        drop(held);
        let (outcome, stored) = poll.await.unwrap();
        assert!(
            matches!(outcome, PollOutcome::Updated { .. }),
            "{outcome:?}"
        );
        assert!(stored.contains(&("urn:slow".to_string(), clean(ORDINARY_B))));
    }

    /// **Permits held elsewhere are not this feed's fault** (review of #274).
    ///
    /// When every permit is held — by sanitizes other feeds' polls gave up on
    /// — a poll waits at most the timeout and then defers: nothing stored (no
    /// bodiless new entries, no validators), no failure recorded, the error
    /// count untouched, the next poll on the ordinary cadence. Filed as a
    /// `Body` failure, one hostile feed had turned every healthy feed's poll
    /// into a failure, backing them off toward 24 h.
    #[tokio::test]
    async fn a_poll_starved_of_permits_defers_without_blaming_the_feed() {
        let (pool, feed, _) = fixture("permit-starved.test", rss(ORDINARY_B)).await;
        // An earlier, unrelated failure, which a deferral must leave as it is.
        crate::store::bump_feed_errors(&pool, &feed.url, FailureKind::Fetch, "earlier")
            .await
            .unwrap();
        let sem = permits(1);
        let _held = sem.acquire().await.unwrap();

        let client = build_client().unwrap();
        let started = Instant::now();
        let outcome = poll_feed_with(&pool, &client, &feed, 0, limits(sem, SHORT))
            .await
            .unwrap();
        // It waited the timeout for a permit, and not much more (vacuous-test
        // hunt of #274: `< 2 s` let a 15x permit wait through; 10x leaves a
        // loaded CI runner room).
        let took = started.elapsed();
        assert!(took >= SHORT && took < SHORT * 10, "{took:?}");
        assert_eq!(outcome, PollOutcome::Deferred);
        let cadence = Duration::from_secs(3600);
        settle_poll(&pool, &feed.url, &outcome, cadence).await;

        assert_eq!(bodies(&pool).await, vec![], "stored entries without bodies");
        assert_eq!(validators(&pool, &feed.url).await, (None, None));
        let after = crate::store::get_feed_by_url(&pool, &feed.url)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.consecutive_errors, 1,
            "the deferral changed the error count"
        );
        let next = DateTime::parse_from_rfc3339(after.next_poll.as_deref().unwrap()).unwrap();
        let in_secs = (next.with_timezone(&Utc) - Utc::now()).num_seconds();
        assert!(
            (3500..=3600).contains(&in_secs),
            "next poll in {in_secs}s, not on the {cadence:?} cadence"
        );
    }

    /// Wait (bounded) until every one of `sem`'s `n` permits is free again —
    /// i.e. every abandoned sanitize holding one has finished.
    async fn wait_for_permits(sem: &Semaphore, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(120);
        while sem.available_permits() < n {
            assert!(
                Instant::now() < deadline,
                "an abandoned sanitize never finished"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// **One hostile feed, at most one thread** (review of #274). A re-poll
    /// while the feed's abandoned sanitize is still running starts no second
    /// sanitize and takes no permit, whatever body it now serves: it is
    /// refused at once, as timed out. Once that sanitize finishes, the feed is
    /// released and its body is sanitized again. (Renamed in the vacuous-test
    /// hunt of #274: it dated from when the refusal was keyed by body hash.)
    #[tokio::test]
    async fn a_feed_is_refused_until_its_abandoned_sanitize_finishes() {
        let slow = slow_body();
        let (pool, feed, served) = fixture("abandoned-body.test", rss(&slow)).await;
        let client = build_client().unwrap();
        let sem = permits(4);
        let set: &'static InFlight = Box::leak(Box::new(InFlight::new()));
        let short = SanitizeLimits {
            permits: sem,
            in_flight: set,
            timeout: SHORT,
            sanitize: sanitize_body,
        };

        poll_feed_with(&pool, &client, &feed, 0, short)
            .await
            .unwrap();
        assert_eq!(
            sem.available_permits(),
            3,
            "the first poll abandoned one sanitize"
        );

        // Re-polls while it runs, each serving a changed body: each refused
        // at once, no permit taken.
        for nonce in 0..3 {
            *served.lock().unwrap() = rss(&format!("{slow}<!-- {nonce} -->")).into_bytes();
            let started = Instant::now();
            let outcome = poll_feed_with(&pool, &client, &feed, 0, short)
                .await
                .unwrap();
            assert!(
                matches!(
                    outcome,
                    PollOutcome::Failed {
                        kind: FailureKind::Body,
                        ..
                    }
                ),
                "{outcome:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "{:?}",
                started.elapsed()
            );
        }
        assert_eq!(
            sem.available_permits(),
            3,
            "a re-poll started another sanitize for a feed already abandoned"
        );

        // Once the abandoned sanitize returns, the feed is no longer refused.
        *served.lock().unwrap() = rss(&slow).into_bytes();
        wait_for_permits(sem, 4).await;
        let outcome = poll_feed_with(
            &pool,
            &client,
            &feed,
            0,
            SanitizeLimits {
                timeout: GENEROUS,
                ..short
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, PollOutcome::Updated { .. }),
            "{outcome:?}"
        );
        assert!(bodies(&pool)
            .await
            .contains(&("urn:slow".to_string(), clean(&slow))));
    }

    /// **One hostile feed, at most one thread — whatever bytes it serves**
    /// (second review of #274). Tracking by body hash let a feed dodge the
    /// refusal by changing its slow body each fetch (a nonce, or another slow
    /// entry on top), leaving one more uncancellable sanitize behind per poll
    /// until it held every permit. Tracked by feed, any body from a feed with
    /// an abandoned sanitize still running is refused, without a permit.
    #[tokio::test]
    async fn a_feed_cannot_dodge_the_refusal_by_changing_its_body() {
        let sem = permits(4);
        let short = limits(sem, SHORT);
        let slow = slow_body();
        let first = sanitize_off_runtime("https://hostile.test/feed", slow.clone(), short).await;
        assert_eq!(first, Err(SanitizeGaveUp::TimedOut));
        for nonce in 0..3 {
            let changed = format!("{slow}<!-- {nonce} -->");
            let started = Instant::now();
            let again = sanitize_off_runtime("https://hostile.test/feed", changed, short).await;
            assert_eq!(again, Err(SanitizeGaveUp::StillRunning));
            assert!(started.elapsed() < Duration::from_secs(1));
        }
        assert_eq!(
            sem.available_permits(),
            3,
            "a changed body from the same feed started another sanitize"
        );
        wait_for_permits(sem, 4).await;
    }

    /// **Another feed's timeout is not this feed's** (second review of #274).
    /// Shared by body hash, one feed's abandoned sanitize refused every other
    /// feed carrying the same article, as a `Body` failure of their own. Now
    /// another feed is sanitized as usual, and a feed with an ordinary body
    /// is never held up by a hostile one.
    #[tokio::test]
    async fn one_feeds_abandoned_sanitize_does_not_refuse_another_feed() {
        let sem = permits(4);
        let short = limits(sem, SHORT);
        let slow = slow_body();
        assert_eq!(
            sanitize_off_runtime("https://hostile.test/feed", slow.clone(), short).await,
            Err(SanitizeGaveUp::TimedOut)
        );
        // The same article in another feed: its own attempt, not a refusal.
        assert_eq!(
            sanitize_off_runtime("https://mirror.test/feed", slow, short).await,
            Err(SanitizeGaveUp::TimedOut)
        );
        assert_eq!(
            sanitize_off_runtime("https://ordinary.test/feed", ORDINARY_B.to_string(), short).await,
            Ok(clean(ORDINARY_B).unwrap())
        );
        wait_for_permits(sem, 4).await;
    }

    /// The **content** body is stored, not the summary, and a body that
    /// sanitizes past [`MAX_CONTENT_HTML_BYTES`] is stored within it — with
    /// literal expectations, not ones built from the functions under test
    /// (vacuous-test hunt of #274: the poll path could have read the summary
    /// only, or dropped the bound, and the byte-identical test still passed).
    #[tokio::test]
    async fn the_content_body_is_stored_over_the_summary_and_within_the_bound() {
        let huge = format!("<p>{}<b>tail</b></p>", "a".repeat(MAX_CONTENT_HTML_BYTES));
        let item = |guid: &str, content: &str, summary: &str| {
            format!(
                "<item><title>{guid}</title><link>https://content.example/{guid}</link>\
                 <guid>urn:{guid}</guid>\
                 <description><![CDATA[{summary}]]></description>\
                 <content:encoded><![CDATA[{content}]]></content:encoded></item>"
            )
        };
        let doc = format!(
            r#"<?xml version="1.0"?><rss version="2.0"
xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><title>Content</title>
<link>https://content.example/</link>{}{}</channel></rss>"#,
            item(
                "full",
                "<p>The <b>full</b> body.<script>x()</script></p>",
                "<p>Only the teaser.</p>"
            ),
            item("huge", &huge, "<p>Short.</p>"),
        );
        let (pool, feed, _) = fixture("content-body.test", doc).await;
        let client = build_client().unwrap();
        let outcome = poll_feed_with(&pool, &client, &feed, 0, limits(permits(4), GENEROUS))
            .await
            .unwrap();
        assert!(
            matches!(outcome, PollOutcome::Updated { .. }),
            "{outcome:?}"
        );
        let stored = bodies(&pool).await;
        assert_eq!(
            stored[0],
            (
                "urn:full".to_string(),
                Some("<p>The <b>full</b> body.</p>".to_string())
            )
        );
        let (guid, body) = &stored[1];
        assert_eq!(guid, "urn:huge");
        let len = body.as_deref().map_or(0, str::len);
        assert!(
            (MAX_CONTENT_HTML_BYTES / 2..=MAX_CONTENT_HTML_BYTES).contains(&len),
            "stored {len} bytes against a bound of {MAX_CONTENT_HTML_BYTES}"
        );
    }

    /// Two permits, emptied mid-poll by [`sanitize_then_starve`].
    static STARVE: Semaphore = Semaphore::const_new(2);
    static STARVE_RAN: AtomicBool = AtomicBool::new(false);

    /// [`sanitize_body`], which first — while its own sanitize holds one of
    /// [`STARVE`]'s permits — queues a task for both, so it takes the other
    /// now and this one as soon as it is released, and keeps them. The poll's
    /// next entry then finds no permit, deterministically.
    fn sanitize_then_starve(raw: &str) -> String {
        tokio::runtime::Handle::current()
            .spawn(async { STARVE.acquire_many(2).await.unwrap().forget() });
        let deadline = Instant::now() + Duration::from_secs(10);
        while STARVE.available_permits() > 0 {
            assert!(Instant::now() < deadline, "the starving task never queued");
            std::thread::sleep(Duration::from_millis(1));
        }
        STARVE_RAN.store(true, Ordering::SeqCst);
        sanitize_body(raw)
    }

    /// **No permit after earlier entries were sanitized still defers the
    /// whole poll**: the bodies already sanitized are not stored, no entry is
    /// stored without its body, no validator is saved and no failure is
    /// filed (vacuous-test hunt of #274: every starved-poll test starved the
    /// first entry, so storing the part already done went unnoticed).
    #[tokio::test]
    async fn a_poll_starved_after_its_first_entry_still_stores_nothing() {
        let (pool, feed, _) = fixture("starved-midway.test", rss(ORDINARY_B)).await;
        let client = build_client().unwrap();
        let outcome = poll_feed_with(
            &pool,
            &client,
            &feed,
            0,
            SanitizeLimits {
                sanitize: sanitize_then_starve,
                ..limits(&STARVE, SHORT)
            },
        )
        .await
        .unwrap();
        assert!(
            STARVE_RAN.load(Ordering::SeqCst),
            "the first entry was not sanitized"
        );
        assert_eq!(outcome, PollOutcome::Deferred);
        assert_eq!(
            bodies(&pool).await,
            vec![],
            "stored part of a deferred poll"
        );
        assert_eq!(validators(&pool, &feed.url).await, (None, None));
    }

    fn sanitize_panics(_: &str) -> String {
        panic!("the sanitizer panicked")
    }

    /// A panic in the sanitizer propagates to the poll, as it did when the
    /// sanitize ran inline — not swallowed as a timeout (vacuous-test hunt of
    /// #274: the `resume_unwind` arm had no test).
    #[tokio::test]
    async fn a_sanitizer_panic_propagates_to_the_poll() {
        let limits = SanitizeLimits {
            sanitize: sanitize_panics,
            ..limits(permits(1), GENEROUS)
        };
        let joined = tokio::spawn(async move {
            sanitize_off_runtime("https://panics.test/feed", ORDINARY_B.to_string(), limits).await
        })
        .await;
        let err = joined.expect_err("the panic did not propagate");
        assert_eq!(
            err.into_panic().downcast_ref::<&str>(),
            Some(&"the sanitizer panicked")
        );
    }

    /// **Counted from the start, not from the timeout** (third review of
    /// #274). A sanitize counted against its feed only once a poll gave up
    /// on it left two ways for one feed to take every permit: overlapping
    /// polls (the scheduler, and a subscribe POST, which polls inline) all
    /// passed the check before any of them timed out; and a poll dropped
    /// mid-sanitize (a client disconnecting from the subscribe request)
    /// never counted its sanitize at all. Now a feed with any sanitize still
    /// running is not given another: a poll that finds one in flight defers
    /// (`Busy`), without a permit.
    #[tokio::test]
    async fn a_feed_with_a_sanitize_in_flight_is_not_given_another() {
        let sem = permits(4);
        let set: &'static InFlight = Box::leak(Box::new(InFlight::new()));
        let generous = SanitizeLimits {
            permits: sem,
            in_flight: set,
            timeout: GENEROUS,
            sanitize: sanitize_body,
        };
        let feed = "https://hostile.test/feed";

        // Overlapping: one poll's sanitize is running, not yet given up on.
        let first = tokio::spawn(sanitize_off_runtime(feed, slow_body(), generous));
        while sem.available_permits() == 4 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let started = Instant::now();
        assert_eq!(
            sanitize_off_runtime(feed, slow_body(), generous).await,
            Err(SanitizeGaveUp::Busy)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            sem.available_permits(),
            3,
            "an overlapping poll of the same feed started a second sanitize"
        );

        // Dropped: the poll goes away mid-sanitize; the sanitize runs on and
        // still counts.
        first.abort();
        let _ = first.await;
        assert_eq!(
            sanitize_off_runtime(feed, slow_body(), generous).await,
            Err(SanitizeGaveUp::Busy)
        );
        assert_eq!(
            sem.available_permits(),
            3,
            "a dropped poll's sanitize was not counted against its feed"
        );

        // Once it returns, the feed is sanitized as usual.
        wait_for_permits(sem, 4).await;
        assert_eq!(
            sanitize_off_runtime(feed, ORDINARY_B.to_string(), generous).await,
            Ok(clean(ORDINARY_B).unwrap())
        );
        assert!(set.lock().is_empty(), "the registry kept a finished feed");
    }
}
