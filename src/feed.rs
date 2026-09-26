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
/// 2. **Known private-feed path markers** — [`PRIVATE_PATH_MARKERS`]
///    (`/feed/private/`, `/members/`, `/subscriber/`, …).
/// 3. **Credential query parameters** — a query key in [`SECRET_QUERY_KEYS`] with
///    a long/opaque value (Patreon `?auth=`, Ghost `?uuid=`, `?token=`, …).
/// 4. **High-entropy opaque token segments** — a long opaque blob (hex ≥ 16,
///    base64url ≥ 16, or a UUID) anywhere in the path or a query value, even
///    without a telltale name.
/// 5. **Known providers** — [`KNOWN_PROVIDERS`] host (+ optional marker) match.
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
    /// An `at://…/site.standard.publication/…` record pair in somebody's PDS.
    /// Storable behind `FEATHERREADER_STANDARD_SITE`; **not yet pollable**, so
    /// [`FeedKind::POLLABLE`] excludes it. Wiring the reader is what moves it.
    Publication,
}

impl FeedKind {
    /// The kinds the scheduler may select. The single place that changes when
    /// the standard.site reader is wired to the poller.
    ///
    /// **This is the canonical home of the at:// exclusion; the other sites
    /// point here.** It used to be a SQL string predicate in `store`, carrying
    /// its own copy of the rule — which is how one reader (`count_feeds`) came
    /// to drift from it unnoticed.
    ///
    /// Why an unpollable kind is skipped rather than failed: `poll_feed`
    /// reaches `net::guarded_get`, whose `check_scheme` refuses any non-http(s)
    /// scheme, and the standard.site reader is not yet wired to the scheduler.
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
    pub const POLLABLE: &'static [FeedKind] = &[FeedKind::Rss];

    /// The column value. Stable — it is persisted.
    pub fn as_str(self) -> &'static str {
        match self {
            FeedKind::Rss => "rss",
            FeedKind::Publication => "publication",
        }
    }

    /// A closed vocabulary on the way back in: a kind written by a newer build
    /// is not silently read as one this build knows.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "rss" => Some(FeedKind::Rss),
            "publication" => Some(FeedKind::Publication),
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
        if crate::atproto::strip_at_prefix(url).is_some() {
            FeedKind::Publication
        } else {
            FeedKind::Rss
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
/// [`BACKOFF_MAX`]. Exponential in the error count so transient blips retry soon
/// while a durably-broken feed backs off toward daily.
///
/// The scheduler passes the feed's persisted `consecutive_errors` count (see
/// [`crate::store::bump_feed_errors`]) so a feed that keeps failing actually
/// climbs toward [`BACKOFF_MAX`] instead of retrying at the floor forever.
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
pub async fn poll_feed(
    pool: &SqlitePool,
    client: &Client,
    feed: &Feed,
    max_entries_per_feed: i64,
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
    let parsed = match feed_rs::parser::parse(&body[..]) {
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
    let (title, site_url) = feed_metadata(&parsed);
    let new_feed = NewFeed {
        url: feed.url.clone(),
        title,
        site_url,
        etag: new_etag,
        last_modified: new_last_modified,
        last_polled: Some(now_rfc3339()),
        next_poll: None, // the scheduler owns cadence; leave it to set next_poll.
    };

    let entries: Vec<NewEntry> = parsed.entries.iter().map(normalize_entry).collect();

    // --- store (a store failure IS a real error) -----------------------------
    let feed_id = store::upsert_feed(pool, &new_feed)
        .await
        .with_context(|| format!("upsert_feed for {}", feed.url))?;
    let n = store::insert_entries(pool, feed_id, &entries, max_entries_per_feed)
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
    /// **`rel="alternate"` is preferred over a `rel="self"` listed FIRST.** In
    /// `ATOM_SAMPLE` the alternate link is already first, so "prefer alternate"
    /// and "take the first link" were indistinguishable; the selection could
    /// be replaced by `links.first()` with the suite green. A feed listing
    /// `self` first — very common in Atom — would store the feed XML URL as
    /// the subscription's `siteUrl`, published to the reader's PDS.
    #[test]
    fn atom_prefers_alternate_over_a_self_link_listed_first() {
        let parsed = feed_rs::parser::parse(ATOM_SELF_FIRST.as_bytes()).expect("Atom should parse");
        let (title, site) = feed_metadata(&parsed);
        assert_eq!(title.as_deref(), Some("Example Atom Feed"));
        // alternate link preferred over rel="self".
        assert_eq!(site.as_deref(), Some("https://atom.example.com/"));
    }

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
}
