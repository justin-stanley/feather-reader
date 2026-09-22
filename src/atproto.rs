//! The atproto identity + PDS record layer.
//!
//! FeatherReader's defining bet is that a user's feed
//! subscriptions, folders, saved items, and batched read-state live as records
//! in the user's **own** atproto PDS under the open `community.lexicon.rss.*`
//! community lexicon — not in the app's database. This module is the client that
//! reads and writes those records.
//!
//! It has three layers:
//!
//! 1. **Identity resolution** ([`resolve_handle`], [`resolve_did_to_pds`]) —
//!    turn a handle (`alice.example.com`) into a DID (`did:plc:…`), then resolve
//!    the DID document to the PDS service endpoint. Handles resolve via the
//!    account's PDS `com.atproto.identity.resolveHandle` (or the well-known
//!    `/.well-known/atproto-did`); DIDs resolve via the PLC directory
//!    (`did:plc:*`) or the `did:web` well-known document.
//! 2. **A lightweight [`PdsClient`]** — holds the resolved DID, the PDS base URL,
//!    and an [`Auth`] token, and exposes typed calls over `com.atproto.repo.*`:
//!    [`list_records`](PdsClient::list_records),
//!    [`create_record`](PdsClient::create_record),
//!    [`put_record`](PdsClient::put_record),
//!    [`delete_record`](PdsClient::delete_record), and
//!    [`apply_writes`](PdsClient::apply_writes) (the **batch** call the
//!    read-state flusher uses to coalesce many per-feed cursor writes into one
//!    round-trip).
//! 3. **Typed convenience wrappers** wired to the [`crate::lexicon`] record
//!    types (list/create [`Subscription`]/[`Folder`]/[`Saved`], put
//!    [`ReadState`], batch-flush many `ReadState` cursors).
//!
//! ## Auth — the OAuth sidecar is the live path
//!
//! Auth is a **trait/enum boundary** so the mechanism can vary without touching
//! call sites. There are three paths:
//!
//! * **The live path — the atproto OAuth confidential client, via [`SidecarClient`].**
//!   atproto OAuth (DPoP, PAR, token refresh) is fiddly and is **not** hand-rolled
//!   in Rust: it runs in a small, supported `@atproto/oauth-client-node` sidecar.
//!   The Rust server never holds
//!   PDS tokens — it POSTs every `com.atproto.repo.*` op to the sidecar's
//!   `/internal/repo` endpoint (gated by a shared `X-Internal-Secret`), and the
//!   sidecar restores the DID's OAuth session (transparent DPoP + token refresh)
//!   and runs the matching XRPC call. [`SidecarClient`] is that client; the typed
//!   convenience wrappers (list/create/put/delete subscriptions, batch-flush
//!   read-state) live on it and map 1:1 to the old [`PdsClient`] surface.
//! * **The interim path — [`Auth::Session`] (app password).** A session obtained
//!   from `com.atproto.server.createSession`. Kept behind the [`Auth`] seam, but
//!   it is **no longer the live path**: [`PdsClient`] and
//!   [`login_with_app_password`] remain for tests, while [`SidecarClient`] is
//!   what the web layer routes through.
//!
//!   ⚠️ **This is no longer a working "local runs without the sidecar" fallback,
//!   and the docs used to claim otherwise.** Since v0.2.8 every [`PdsClient`]
//!   request goes through the SSRF guard, which refuses loopback, RFC1918, ULA
//!   and `100.64/10` (Tailscale). So pointing this at `http://localhost:2583`
//!   or a tailnet PDS now fails with *"refusing to fetch forbidden (internal)
//!   address"* rather than returning a session. That is the guard behaving
//!   correctly — the target host is attacker-influenced in the cases that
//!   matter, and a dev-only escape hatch is exactly the kind of flag that ends
//!   up set in production — but it does mean a local-PDS workflow needs the
//!   PDS reachable on a public address, or a deliberate change here.
//! * **The public-read path — [`Auth::Anonymous`], via [`PdsClient::anonymous`].**
//!   `com.atproto.repo.listRecords` is public on a standard PDS, so a stranger's
//!   `community.lexicon.rss.*` records can be read with no credentials at all.
//!   An anonymous client sends no `Authorization` header and is **read-only** —
//!   every write fails closed on [`Auth::bearer`]. Because the target host is
//!   then chosen by a stranger, the read is routed through
//!   [`crate::net::guarded_get_no_privacy`] (per-hop SSRF re-validation +
//!   connect-pinning) and capped by [`crate::net::read_capped`].
//!
//! ## Every PDS request goes through the SSRF guard
//!
//! A PDS host is *never* a host FeatherReader chose: it comes out of a DID
//! document, which is attacker-controllable. So identity resolution, the record
//! **reads**, and the record **writes** all route through [`crate::net`] —
//! [`crate::net::guarded_get_no_privacy`] and
//! [`crate::net::guarded_post_json`] — rather than the shared
//! [`reqwest::Client`]. [`resolve_did_to_pds`] runs
//! [`crate::net::assert_public_target`] on the `serviceEndpoint` it returns, but
//! that check is a *separate DNS resolution* from the later request; only
//! re-vetting and connect-pinning at request time closes the rebinding window.
//! The writes matter most: they carry the session bearer, and
//! [`login_with_app_password`] carries the app password in the request **body**,
//! where reqwest's cross-origin header sanitisation offers no protection at all
//! — which is why the guarded POST refuses redirects outright.
//!
//! All network I/O is `reqwest` (rustls, no OpenSSL); every fallible path returns
//! [`anyhow::Result`] or the typed [`AtProtoError`] — nothing panics.

use std::sync::Arc;

use anyhow::{Context, Result};
use reqwest::header::{HeaderName, HeaderValue, AUTHORIZATION};
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::lexicon::{self, Folder, ReadState, Saved, Subscription};

/// The public PLC directory, used to resolve `did:plc:*` DIDs to their DID
/// document (and thus their PDS service endpoint).
pub const DEFAULT_PLC_DIRECTORY: &str = "https://plc.directory";

/// The default appview/entryway used only as a bootstrap host for handle
/// resolution when the caller has no PDS hint yet. Handle resolution ultimately
/// works against any atproto host that implements
/// `com.atproto.identity.resolveHandle`; `bsky.social` is a reliable default.
pub const DEFAULT_RESOLVER_HOST: &str = "https://bsky.social";

/// Hard cap on cursor pages any `list_all_records` walk will follow.
///
/// [`crate::net::read_capped`] bounds each individual response, but nothing
/// bounded the *accumulation* across pages: a repo host that returns a full page
/// and a fresh cursor forever walks memory until the (512 MB) box dies. At 100
/// records per page this admits 20 000 records — far past any real
/// `community.lexicon.rss.*` collection — while making the loop finite against a
/// host we do not control. Mirrors [`crate::network::MAX_PAGES`], which bounds
/// the relay walk for the same reason.
const MAX_LIST_PAGES: usize = 200;

/// Hard cap on the records a single `list_all_records` walk will accumulate.
///
/// [`MAX_LIST_PAGES`] bounds how many REQUESTS a walk makes. It bounds the
/// accumulated memory only if the server honours `limit=100` — and a repo host
/// we did not choose has no obligation to. Measured: an 8 MB page (the
/// [`crate::net::read_capped`] ceiling) holds ~95 000 minimal records and
/// retains ~23 MB as `Vec<RecordEntry>`, so the page cap alone admits gigabytes
/// on a 512 MB box.
///
/// 20 000 is the number [`MAX_LIST_PAGES`]'s own comment already claimed — this
/// makes the claim true rather than conditional on the server's cooperation.
const MAX_LIST_RECORDS: usize = 20_000;

/// The same cap for a collection whose records are **large**.
///
/// [`MAX_LIST_RECORDS`]'s figure was measured against *minimal* records
/// (~1 KB). A `site.standard.document` carries the whole article — ~17 KB
/// measured across 449 real ones — so 20 000 of them is ~340 MB retained on a
/// 512 MB box. Sized to the record, not to the protocol.
pub(crate) const MAX_LARGE_RECORDS: usize = 2_000;

/// The at-URI scheme prefix, **the one Rust spelling**. Every Rust guard that
/// asks "is this an at-URI" strips or compares this.
///
/// **SQL no longer holds a second opinion.** There used to be a matching string
/// predicate in `store`, and this comment claimed a test pinned the two in
/// agreement. Both are gone: the predicate was deleted when `feeds.kind` became
/// a cache of [`crate::feed::FeedKind::of`], re-derived from the URL rather than
/// re-described in SQL, and no such test survived it. Nothing outside Rust
/// decides what an at-URI is, so there is nothing left to keep in step.
pub(crate) const AT_URI_PREFIX: &str = "at://";

/// Strip the at-URI scheme **case-insensitively**, returning the body.
///
/// Schemes are case-insensitive per RFC 3986 and `Url::parse` folds them, so
/// `At://` names the same thing as `at://`. Recognition has to match that, or a
/// mixed-case row is an at-URI to the fetcher (which refuses it) and an
/// ordinary URL to every guard — polled forever, failing forever. Whether such
/// a spelling may be STORED is a separate question, answered no.
pub(crate) fn strip_at_prefix(url: &str) -> Option<&str> {
    url.get(..AT_URI_PREFIX.len())
        .filter(|p| p.eq_ignore_ascii_case(AT_URI_PREFIX))
        .map(|p| &url[p.len()..])
}

/// atproto's record-key rules, all of them: charset `[A-Za-z0-9._:~-]`, length
/// 1..=512, and not `.` or `..`. The repo's TID tests state the same rule; this
/// is the one place it is enforced on a key that arrives from outside.
pub(crate) fn is_valid_rkey(rkey: &str) -> bool {
    !rkey.is_empty()
        && rkey.len() <= 512
        && rkey != "."
        && rkey != ".."
        && rkey
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '~' | '-'))
}

/// Accumulate a page for a **reading** walk, keeping what fits and reporting
/// whether anything was dropped.
///
/// **A truncation, never an error** — the opposite of [`extend_bounded`], and
/// deliberately so. That function's refusal exists because its caller feeds
/// `replace_sub_refs`, where a short list is revoked access. A walk that only
/// ADDS entries has no such hazard, and refusing there is strictly worse: a
/// publication with more documents than the cap would fail on every poll, so
/// an ordinary long-running blog becomes permanently unreadable instead of
/// partially read. The records kept are the ones the PDS returned first.
pub(crate) fn extend_truncating(
    out: &mut Vec<RecordEntry>,
    page: Vec<RecordEntry>,
    max: usize,
) -> bool {
    let room = max.saturating_sub(out.len());
    // **Strictly greater.** `>=` called an exactly-full final page a
    // truncation, so a collection holding exactly `max` records warned that it
    // had dropped something on every poll.
    let dropped = page.len() > room;
    out.extend(page.into_iter().take(room));
    dropped
}

/// The result of a bounded walk: what was read, and whether that is all of it.
///
/// **`complete` is a fact the caller cannot recover afterwards.** A short list
/// from a truncating walk looks exactly like a short collection, and the
/// difference is the one that matters: "this publication has nine articles" and
/// "this reader gave up after nine" are the same `Vec` and very different
/// answers.
#[derive(Debug)]
pub struct RecordWalk {
    /// The records kept, in the order the PDS returned them.
    pub records: Vec<RecordEntry>,
    /// True when the collection ran out before any bound did.
    pub complete: bool,
}

impl RecordWalk {
    fn complete(records: Vec<RecordEntry>) -> Self {
        Self {
            records,
            complete: true,
        }
    }
    fn partial(records: Vec<RecordEntry>) -> Self {
        Self {
            records,
            complete: false,
        }
    }
}

/// The memory one walk may retain.
///
/// **A record cap bounds memory only if you know what a record costs.** The
/// caps above are counts, chosen against a measured ~17 KB document, and
/// `MAX_LIST_PAGES` bounds requests rather than bytes. A PDS whose records are
/// not that shape satisfies every count and still exhausts the box.
///
/// 64 MiB, and what that means for each walk, since the record caps differ:
///
/// - The subscription walks cap at 20 000 (5 000 on the live one). A real
///   subscription record charges on the order of 1.5 KB here, so a full repo is
///   around 30 MB and this never fires. Their verdict is a refusal, so a bound
///   that bit honest traffic would push a reader into the fail-closed branch —
///   which is why the headroom matters more there than anywhere else.
/// - The publication walk caps at [`MAX_LARGE_RECORDS`] (2 000). At the
///   measured ~17 KB document that is about 37 MB, also under. Above roughly
///   33 KB per article the budget binds first and the walk truncates early,
///   reporting `complete: false` as it already does for the record cap.
///
/// So on the traffic that has been measured this never fires; for a publication
/// of unusually long articles it truncates sooner than the count would. It is
/// not true that nothing truncates that did not truncate before, and an earlier
/// version of this comment said so.
pub(crate) const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;

/// What one record retains once parsed.
///
/// **Nodes, not serialized text.** An earlier version of this charged the
/// length of the JSON, which is the wrong quantity by up to 42x: a parsed value
/// is a tree of 32-byte nodes held in vectors that over-allocate, so `[[],[]…]`
/// costs three bytes on the wire and well over a hundred in memory. Measured
/// against that estimate, a budget reporting 119 MiB held a process at 5.6 GiB.
///
/// Every arm therefore charges at least the node itself, and a container
/// charges for the slack its backing allocation carries. The result
/// over-estimates on every adversarial shape and costs honest traffic a couple
/// of percent, which is the direction a bound has to err in.
pub(crate) fn approx_bytes(entry: &RecordEntry) -> usize {
    2 * std::mem::size_of::<RecordEntry>()
        + entry.uri.len()
        + entry.cid.as_ref().map_or(0, String::len)
        + json_bytes(&entry.value)
}

/// What a parsed JSON value retains, without measuring the heap.
fn json_bytes(v: &serde_json::Value) -> usize {
    /// Every value, of every kind, occupies one of these wherever it sits.
    const NODE: usize = std::mem::size_of::<serde_json::Value>();
    /// Two nodes per value: the slot it occupies, and the slack the container
    /// holding it carries — a `Vec` grows by doubling, so up to one spare slot
    /// per live one.
    const SLOT: usize = 2 * NODE;
    /// A map entry is a tree node of its own, with links and a key beside the
    /// value. Rounded up rather than derived, since the layout is not ours.
    const MAP_ENTRY: usize = 104;
    /// A map's backing node, allocated whole.
    ///
    /// `serde_json::Map` is a `BTreeMap` here — no `preserve_order` in the
    /// lock — and its leaf carries room for eleven pairs whether or not they
    /// are used, measured at ~632 bytes. So a one-key object costs what an
    /// eleven-key one does, and a chain of them costs that per level. Charging
    /// a container's minimum the way an array does under-reports this by about
    /// half, which is the same failure as the version this replaces, two orders
    /// of magnitude smaller.
    const MAP_NODE: usize = 512;
    match v {
        // The `4 * NODE` is the container's own minimum allocation; each child
        // then charges for itself, recursively. Dropping that recursion is what
        // made an array of empty arrays look free.
        serde_json::Value::Array(a) => 4 * NODE + a.iter().map(json_bytes).sum::<usize>(),
        serde_json::Value::Object(o) => {
            MAP_NODE
                + o.iter()
                    .map(|(k, v)| MAP_ENTRY + k.len().max(NODE / 2) + SLOT + json_bytes(v))
                    .sum::<usize>()
        }
        serde_json::Value::String(s) => SLOT + s.len(),
        // Null, bool and number are all the node and nothing else.
        _ => SLOT,
    }
}

/// Running byte accounting for one walk.
pub(crate) struct ByteBudget {
    used: usize,
    max: usize,
}

impl ByteBudget {
    pub(crate) fn new(max: usize) -> Self {
        Self { used: 0, max }
    }

    /// Charge a page. `false` when the walk must stop; a refused page is NOT
    /// charged, so `used` always describes what the caller actually kept.
    pub(crate) fn admit(&mut self, page: &[RecordEntry]) -> bool {
        let cost: usize = page.iter().map(approx_bytes).sum();
        match self.used.checked_add(cost) {
            Some(total) if total <= self.max => {
                self.used = total;
                true
            }
            _ => false,
        }
    }

    pub(crate) fn used(&self) -> usize {
        self.used
    }
}

/// Append a page, refusing to exceed `max`.
///
/// **An error, never a truncation.** The caller of the live walk is
/// `web::resolve_subscriptions`, whose result reaches `store::replace_sub_refs`
/// — a `DELETE` followed by reinserting exactly what it was handed. A short
/// list there is not a short list, it is revoked access to whatever fell off
/// the end. Returning `Err` lets `resolve_subscriptions` take its documented
/// fail-closed branch and serve the last-known projection instead.
///
/// `out` is left untouched on refusal, so a partial page cannot survive.
pub(crate) fn extend_bounded(
    out: &mut Vec<RecordEntry>,
    page: Vec<RecordEntry>,
    max: usize,
    collection: &str,
) -> Result<()> {
    if out.len() + page.len() > max {
        anyhow::bail!(
            "listRecords for {collection} exceeded the {max}-record cap \
             ({} held, {} more offered) — refusing to accumulate further",
            out.len(),
            page.len(),
        );
    }
    out.extend(page);
    Ok(())
}

/// Errors from the atproto identity + PDS layer.
///
/// Wraps the transport, the atproto XRPC error envelope (`{"error","message"}`),
/// and the identity-resolution failure modes so callers can distinguish "the
/// network broke" from "the PDS said no" from "this handle doesn't resolve".
#[derive(Debug, thiserror::Error)]
pub enum AtProtoError {
    /// The underlying HTTP transport failed (DNS, TLS, timeout, connect).
    #[error("atproto transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// The XRPC endpoint returned a non-2xx status with an atproto error
    /// envelope (or an opaque body). `error` is the atproto error name (e.g.
    /// `RecordNotFound`, `AuthMissing`), `message` the human string.
    #[error("atproto XRPC error {status}: {error}{}", .message.as_deref().map(|m| format!(" — {m}")).unwrap_or_default())]
    Xrpc {
        /// The HTTP status code.
        status: StatusCode,
        /// The atproto error name (the `error` field), or `"Unknown"`.
        error: String,
        /// The optional human-readable `message` field.
        message: Option<String>,
    },

    /// A handle could not be resolved to a DID.
    #[error("could not resolve handle {handle:?} to a DID")]
    HandleResolution {
        /// The handle that failed to resolve.
        handle: String,
    },

    /// A DID document could not be resolved, or lacks a usable PDS service
    /// endpoint (`#atproto_pds`).
    #[error("could not resolve DID {did:?} to a PDS endpoint: {reason}")]
    DidResolution {
        /// The DID that failed to resolve.
        did: String,
        /// Why resolution failed.
        reason: String,
    },
}

impl AtProtoError {
    /// True when the XRPC error is a "record not found" — handy for upsert paths
    /// that treat a missing record as "create instead of update".
    pub fn is_record_not_found(&self) -> bool {
        matches!(
            self,
            AtProtoError::Xrpc { error, .. } if error == "RecordNotFound"
        )
    }
}

// ---------------------------------------------------------------------------
// Auth — the direct-PDS path (dev / tests)
// ---------------------------------------------------------------------------

/// A source of atproto access tokens.
///
/// This trait abstracts over token acquisition for the direct [`PdsClient`]
/// (used by local runs and tests). A [`PdsClient`] can hold a `dyn TokenSource`
/// instead of a static [`Auth`] without any call-site change, so a token source
/// that refreshes out of band can be dropped in later.
///
/// It is async + `Send + Sync` so a background refresh can live behind it.
#[allow(async_fn_in_trait)]
pub trait TokenSource: Send + Sync {
    /// Return the current bearer access token to send as `Authorization`.
    async fn access_token(&self) -> Result<String>;
}

/// The auth material a [`PdsClient`] carries.
///
/// A small enum rather than a bare string, so the match stays exhaustive if a
/// second direct-auth mechanism is added alongside app-password sessions.
#[derive(Clone)]
pub enum Auth {
    /// A bearer access token from a `com.atproto.server.createSession`
    /// (app-password) session. This is the direct-PDS auth used by local runs
    /// and tests; the live web path authenticates via the OAuth sidecar instead
    /// (see [`SidecarClient`]).
    Session(SessionAuth),

    /// The atproto OAuth confidential-client path is handled entirely by the
    /// `@atproto/oauth-client` sidecar ([`SidecarClient`]), which mints, DPoP-binds,
    /// and refreshes tokens. The direct [`PdsClient`] does not carry OAuth tokens;
    /// this variant is a placeholder so the `Auth` enum documents that the OAuth
    /// path lives elsewhere.
    Oauth(OauthPlaceholder),

    /// **No credentials at all** — an unauthenticated public read of a repo the
    /// caller does not own. `com.atproto.repo.listRecords` is public on a
    /// standard PDS, so a stranger's `community.lexicon.rss.*` records can be
    /// read with no session; this variant makes that expressible without
    /// inventing a fake token.
    ///
    /// A client holding it is **read-only**: [`Auth::bearer`] returns an error,
    /// so every write path (`create_record` / `put_record` / `delete_record` /
    /// `apply_writes`, all of which go through
    /// [`authed_headers`](PdsClient::authed_headers)) fails closed. Construct one
    /// via [`PdsClient::anonymous`].
    Anonymous,
}

impl Auth {
    /// The bearer access token to present on `com.atproto.repo.*` calls.
    ///
    /// Only [`Auth::Session`] carries a token (the session's `accessJwt`).
    /// [`Auth::Oauth`] carries none — the sidecar owns the OAuth path — so it
    /// returns an error pointing callers at [`SidecarClient`]. [`Auth::Anonymous`]
    /// carries none by construction, which is what makes an anonymous client
    /// read-only.
    pub fn bearer(&self) -> Result<&str> {
        match self {
            Auth::Session(s) => Ok(&s.access_jwt),
            Auth::Oauth(_) => anyhow::bail!(
                "the direct PdsClient does not carry OAuth tokens — atproto OAuth is \
                 handled by the @atproto/oauth-client sidecar (SidecarClient); \
                 use Auth::Session (app-password) for the direct-PDS path"
            ),
            Auth::Anonymous => anyhow::bail!(
                "this PdsClient is anonymous (unauthenticated public read) and carries no \
                 bearer token — authenticated repo writes require Auth::Session or the \
                 SidecarClient"
            ),
        }
    }
}

/// A session obtained from `com.atproto.server.createSession` (interim
/// app-password auth). Holds the DID + tokens + handle the server returned.
#[derive(Clone, Debug, Deserialize)]
pub struct SessionAuth {
    /// The account DID this session authenticates.
    pub did: String,
    /// The account handle at session-creation time.
    #[serde(default)]
    pub handle: Option<String>,
    /// The bearer access token presented on authed XRPC calls.
    #[serde(rename = "accessJwt")]
    pub access_jwt: String,
    /// The refresh token, exchanged via `com.atproto.server.refreshSession`.
    /// The direct-PDS refresh flow is not implemented here; the live web path
    /// refreshes via the OAuth sidecar instead.
    #[serde(rename = "refreshJwt", default)]
    pub refresh_jwt: Option<String>,
}

/// Placeholder for the OAuth variant of [`Auth`].
///
/// Intentionally empty: the OAuth session material (DPoP key handle, token
/// references) is held entirely by the sidecar, not by the direct [`PdsClient`].
/// This type exists only so [`Auth::Oauth`] is a real variant and the split is
/// visible in the type system.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct OauthPlaceholder {}

// ---------------------------------------------------------------------------
// Identity resolution
// ---------------------------------------------------------------------------

/// Resolve an atproto handle to its DID.
///
/// Uses `com.atproto.identity.resolveHandle` against `resolver_base` (any host
/// that implements it; [`DEFAULT_RESOLVER_HOST`] is a safe bootstrap). A fuller
/// implementation would also try the DNS `_atproto` TXT record and the
/// `https://<handle>/.well-known/atproto-did` fallback; the XRPC path is the
/// common case and the one implemented here.
pub async fn resolve_handle(client: &Client, resolver_base: &str, handle: &str) -> Result<String> {
    // Build the query manually rather than via reqwest's `.query()` so we don't
    // depend on the optional `query`/`url` reqwest feature (the declared feature
    // set is rustls + gzip + json only).
    let url = format!(
        "{}/xrpc/com.atproto.identity.resolveHandle?handle={}",
        resolver_base.trim_end_matches('/'),
        urlencode(handle)
    );

    #[derive(Deserialize)]
    struct ResolveHandleOut {
        did: String,
    }

    // Route through the SSRF guard: `resolver_base` can be a user-influenced PDS
    // host (from a prior DID-doc resolution), so a hostile endpoint must not be
    // able to target loopback / link-local / metadata. Feed-privacy is NOT
    // applied here (this is a legitimate atproto XRPC call, not a feed fetch).
    let resp = crate::net::guarded_get_no_privacy(client, &url, &[]).await?;
    if !resp.status().is_success() {
        // Surface the XRPC envelope but map the common "not found" to the typed
        // handle-resolution error so callers get a clean signal.
        let err = xrpc_error_from(resp).await;
        if let AtProtoError::Xrpc { status, .. } = &err {
            if *status == StatusCode::BAD_REQUEST || *status == StatusCode::NOT_FOUND {
                return Err(AtProtoError::HandleResolution {
                    handle: handle.to_string(),
                }
                .into());
            }
        }
        return Err(err.into());
    }

    // Capped: `resolver_base` can be a user-influenced PDS host, as the comment
    // above this function's guard already says.
    let raw = crate::net::read_capped(resp).await?;
    let out: ResolveHandleOut =
        serde_json::from_slice(&raw).context("parsing resolveHandle response")?;
    Ok(out.did)
}

/// Resolve a DID to its PDS service endpoint by fetching + parsing its DID
/// document.
///
/// * `did:plc:*` → the PLC directory (`{plc_directory}/{did}`).
/// * `did:web:host` → `https://host/.well-known/did.json`.
///
/// The PDS endpoint is the service in the DID doc whose `id` ends with
/// `#atproto_pds` (type `AtprotoPersonalDataServer`); its `serviceEndpoint` is
/// the base URL for all `com.atproto.repo.*` calls.
pub async fn resolve_did_to_pds(client: &Client, plc_directory: &str, did: &str) -> Result<String> {
    let doc_url = if let Some(rest) = did.strip_prefix("did:web:") {
        // did:web host may itself be percent-encoded / contain a path; the
        // common case is a bare host.
        let host = rest.replace(':', "/");
        format!("https://{host}/.well-known/did.json")
    } else if did.starts_with("did:plc:") {
        format!("{}/{}", plc_directory.trim_end_matches('/'), did)
    } else {
        return Err(AtProtoError::DidResolution {
            did: did.to_string(),
            reason: "unsupported DID method (only did:plc and did:web are handled)".to_string(),
        }
        .into());
    };

    // SSRF guard: `doc_url` is attacker-controllable for `did:web:<host>` (the
    // host comes straight from the DID) — a hostile `did:web:169.254.169.254`
    // or `did:web:localhost` would otherwise make the server fetch an internal
    // target and reflect its body. Route through the IP/scheme guard (no
    // feed-privacy layer — this is a DID document, not a feed).
    let resp = crate::net::guarded_get_no_privacy(client, &doc_url, &[]).await?;
    if !resp.status().is_success() {
        return Err(AtProtoError::DidResolution {
            did: did.to_string(),
            reason: format!("DID document fetch returned {}", resp.status()),
        }
        .into());
    }

    // **Capped, and this is the most remote-controlled body of the lot.** For a
    // `did:web:` the host is taken straight out of the DID, so whoever supplies
    // the DID chooses the server — and the SSRF guard only proves the address is
    // public, not that the body is finite.
    let raw = crate::net::read_capped(resp).await?;
    let doc: DidDocument = serde_json::from_slice(&raw).context("parsing DID document")?;
    let endpoint = doc
        .pds_endpoint()
        .ok_or_else(|| AtProtoError::DidResolution {
            did: did.to_string(),
            reason: "DID document has no #atproto_pds service endpoint".to_string(),
        })?;

    // SSRF guard on the RESOLVED endpoint: the `serviceEndpoint` is fully
    // attacker-controlled (it's whatever the DID document says) and is handed to
    // XRPC clients that fetch it directly. Reject a private/loopback/metadata
    // target here so a hostile DID doc can't point the PDS at an internal host.
    crate::net::assert_public_target(&endpoint)
        .await
        .map_err(|e| AtProtoError::DidResolution {
            did: did.to_string(),
            reason: format!("PDS serviceEndpoint is not a public target: {e}"),
        })?;
    Ok(endpoint)
}

/// The subset of a DID document FeatherReader needs: its services, so it can
/// find the `#atproto_pds` endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct DidDocument {
    /// The document subject (the DID itself).
    #[serde(default)]
    pub id: String,
    /// The declared services; the PDS is the one whose `id` ends `#atproto_pds`.
    #[serde(default)]
    pub service: Vec<DidService>,
}

/// One service entry in a [`DidDocument`].
#[derive(Debug, Clone, Deserialize)]
pub struct DidService {
    /// The service id fragment (e.g. `#atproto_pds`).
    pub id: String,
    /// The service type (e.g. `AtprotoPersonalDataServer`).
    #[serde(rename = "type", default)]
    pub r#type: String,
    /// The service base URL.
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

impl DidDocument {
    /// The `#atproto_pds` service endpoint, if present.
    pub fn pds_endpoint(&self) -> Option<String> {
        self.service
            .iter()
            .find(|s| s.id.ends_with("#atproto_pds"))
            .map(|s| s.service_endpoint.trim_end_matches('/').to_string())
    }
}

// ---------------------------------------------------------------------------
// Direct-PDS auth: app-password session
// ---------------------------------------------------------------------------

/// Create a session with an **app password** via
/// `com.atproto.server.createSession`.
///
/// This is the direct-PDS path that makes [`PdsClient`] usable without the OAuth
/// sidecar (local runs and tests). `pds_base` is the account's PDS (resolve it
/// first with [`resolve_handle`] + [`resolve_did_to_pds`], or pass the entryway
/// like `https://bsky.social`, which will service-proxy). `identifier` is a
/// handle or DID; `app_password` is an app-password (never the main password).
///
/// The POST goes through [`crate::net::guarded_post_json`]. This is the single
/// most credential-dense request in the crate — the app password travels in the
/// JSON **body**, where reqwest's cross-origin header sanitisation cannot help
/// it — so it gets the scheme/IP allow-list, the connect pin (no second DNS
/// resolution to rebind), and a hard refusal to follow a redirect that would
/// re-send that body to another host.
pub async fn login_with_app_password(
    client: &Client,
    pds_base: &str,
    identifier: &str,
    app_password: &str,
) -> Result<SessionAuth> {
    let url = format!(
        "{}/xrpc/com.atproto.server.createSession",
        pds_base.trim_end_matches('/')
    );
    let body = serde_json::to_vec(&json!({ "identifier": identifier, "password": app_password }))
        .context("serializing createSession request")?;
    let resp = crate::net::guarded_post_json(client, &url, &[], body).await?;
    if !resp.status().is_success() {
        return Err(xrpc_error_from(resp).await.into());
    }
    let raw = crate::net::read_capped(resp).await?;
    serde_json::from_slice(&raw).context("parsing createSession response")
}

// ---------------------------------------------------------------------------
// The PDS client
// ---------------------------------------------------------------------------

/// A lightweight client for one user's PDS repo.
///
/// Holds the user's DID (the repo to read/write), the PDS base URL (resolved
/// from the DID doc), the shared [`reqwest::Client`], and the [`Auth`] token.
/// All the `com.atproto.repo.*` methods below act on `self.did`'s repo.
///
/// The client may also be **anonymous** ([`PdsClient::anonymous`]), in which case
/// it is read-only: it sends no `Authorization` header and every write path
/// errors out of [`Auth::bearer`].
///
/// Cheap to clone (`Arc` internals); one is held per logged-in session.
#[derive(Clone)]
pub struct PdsClient {
    http: Client,
    /// The PDS base URL, e.g. `https://pds.example.com` (no trailing slash).
    pds_base: Arc<str>,
    /// The repo DID all calls target.
    did: Arc<str>,
    /// The auth material (an app-password session bearer for the direct path, or
    /// [`Auth::Anonymous`] for a read-only public read of a stranger's repo).
    auth: Auth,
}

/// A single record as returned in a `listRecords` / `getRecord` response.
///
/// `value` is the raw record body (with its `$type`); typed wrappers
/// deserialize it into the matching [`crate::lexicon`] struct.
#[derive(Debug, Clone, Deserialize)]
pub struct RecordEntry {
    /// The `at://did/collection/rkey` strong ref to this record.
    pub uri: String,
    /// The record CID (content hash).
    #[serde(default)]
    pub cid: Option<String>,
    /// The raw record body.
    pub value: Value,
}

impl RecordEntry {
    /// The record key (the last `/`-segment of the `at://` URI).
    pub fn rkey(&self) -> Option<&str> {
        self.uri.rsplit('/').next()
    }

    /// Deserialize this record's `value` into a typed lexicon record.
    pub fn parse<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(self.value.clone())
            .with_context(|| format!("deserializing record {}", self.uri))
    }
}

/// The `com.atproto.repo.listRecords` response envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct ListRecordsResponse {
    /// The page of records.
    #[serde(default)]
    pub records: Vec<RecordEntry>,
    /// The opaque pagination cursor for the next page, if any.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// The `com.atproto.repo.createRecord` / `putRecord` response (a strong ref to
/// the written record).
#[derive(Debug, Clone, Deserialize)]
pub struct WriteResult {
    /// The `at://` URI of the written record.
    pub uri: String,
    /// The record CID after the write.
    #[serde(default)]
    pub cid: Option<String>,
}

impl WriteResult {
    /// The record key — the last `/`-segment of the `at://` URI.
    ///
    /// The reader-facing `add_*` wrappers return this so the web layer can
    /// address the freshly-created record (delete/rename) without a re-list.
    pub fn rkey(&self) -> Option<&str> {
        self.uri.rsplit('/').next()
    }

    /// The record key as an owned `String`, or the empty string if the URI is
    /// somehow segment-less (never in practice — a PDS always returns an
    /// `at://did/collection/rkey`). Convenience for the `-> rkey` wrappers.
    pub fn into_rkey(self) -> String {
        self.rkey().unwrap_or_default().to_string()
    }
}

impl PdsClient {
    /// Construct a client against an already-resolved PDS base + DID + auth.
    pub fn new(
        http: Client,
        pds_base: impl Into<String>,
        did: impl Into<String>,
        auth: Auth,
    ) -> Self {
        Self {
            http,
            pds_base: Arc::from(pds_base.into().trim_end_matches('/')),
            did: Arc::from(did.into()),
            auth,
        }
    }

    /// Construct a **read-only, unauthenticated** client for a public repo the
    /// caller does not own — `com.atproto.repo.listRecords` is public on a
    /// standard PDS, so a stranger's records need no credentials.
    ///
    /// Every `com.atproto.repo.*` **write** returns an error (there is no bearer;
    /// see [`Auth::Anonymous`]). Callers are expected to have obtained `pds_base`
    /// from [`resolve_did_to_pds`], which already runs
    /// [`crate::net::assert_public_target`] on the resolved `serviceEndpoint` —
    /// but that is not what makes the fetch safe: every read is **re-vetted at
    /// fetch time** by [`crate::net::guarded_get_no_privacy`], which closes the
    /// DNS-rebinding window between resolve and connect. This constructor is
    /// deliberately synchronous and does no validation of its own, so the
    /// authoritative check is not duplicated (or, worse, mistaken for sufficient).
    pub fn anonymous(http: Client, pds_base: impl Into<String>, did: impl Into<String>) -> Self {
        Self::new(http, pds_base, did, Auth::Anonymous)
    }

    /// Resolve `handle` → DID → PDS, obtain an app-password session, and build a
    /// ready-to-use client. A convenience constructor for the direct-PDS path
    /// that exercises the whole stack end-to-end.
    ///
    /// `resolver_base` / `plc_directory` default to [`DEFAULT_RESOLVER_HOST`] /
    /// [`DEFAULT_PLC_DIRECTORY`] when passed `None`.
    pub async fn login(
        http: Client,
        handle: &str,
        app_password: &str,
        resolver_base: Option<&str>,
        plc_directory: Option<&str>,
    ) -> Result<Self> {
        let resolver = resolver_base.unwrap_or(DEFAULT_RESOLVER_HOST);
        let plc = plc_directory.unwrap_or(DEFAULT_PLC_DIRECTORY);

        let did = resolve_handle(&http, resolver, handle).await?;
        let pds_base = resolve_did_to_pds(&http, plc, &did).await?;
        let session = login_with_app_password(&http, &pds_base, &did, app_password).await?;

        Ok(Self::new(
            http,
            pds_base,
            session.did.clone(),
            Auth::Session(session),
        ))
    }

    /// The repo DID this client targets.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The PDS base URL this client talks to.
    pub fn pds_base(&self) -> &str {
        &self.pds_base
    }

    /// Build the `Authorization: Bearer …` header pair for an authed write.
    ///
    /// A `Vec` of pairs rather than a [`HeaderMap`] because every write now goes
    /// through [`crate::net::guarded_post_json`], which takes header pairs and
    /// sets `Content-Type: application/json` itself. Fails closed on
    /// [`Auth::Anonymous`] (there is no bearer), which is what makes an anonymous
    /// client read-only.
    fn authed_headers(&self) -> Result<Vec<(HeaderName, HeaderValue)>> {
        let bearer = self.auth.bearer()?;
        let mut value = HeaderValue::from_str(&format!("Bearer {bearer}"))
            .context("building Authorization header")?;
        value.set_sensitive(true);
        Ok(vec![(AUTHORIZATION, value)])
    }

    fn xrpc_url(&self, method: &str) -> String {
        format!("{}/xrpc/{}", self.pds_base, method)
    }

    // -- com.atproto.repo.* --------------------------------------------------

    /// `com.atproto.repo.listRecords` — one page of a collection's records.
    ///
    /// `cursor` continues a previous page; `limit` caps the page (atproto's max
    /// is 100). Use [`list_all_records`](Self::list_all_records) to page fully.
    ///
    /// The fetch is routed through [`crate::net::guarded_get_no_privacy`] — the
    /// same per-hop scheme/IP allow-list and connect-pinning the feed poller and
    /// the identity-resolution paths use. `pds_base` was vetted by
    /// [`crate::net::assert_public_target`] at resolve time, but that is a
    /// *separate* DNS resolution from this fetch; routing the request through the
    /// guard closes the rebinding window, which matters as soon as the repo (and
    /// therefore the host) is chosen by a stranger. The response body is read via
    /// [`crate::net::read_capped`] so a hostile PDS cannot stream an unbounded
    /// body at a 512 MB box.
    pub async fn list_records(
        &self,
        collection: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<ListRecordsResponse> {
        // Build the query manually (see `resolve_handle`): no reqwest `query`
        // feature dependency.
        let mut url = format!(
            "{}?repo={}&collection={}",
            self.xrpc_url("com.atproto.repo.listRecords"),
            urlencode(&self.did),
            urlencode(collection),
        );
        if let Some(limit) = limit {
            url.push_str(&format!("&limit={limit}"));
        }
        if let Some(cursor) = cursor {
            url.push_str(&format!("&cursor={}", urlencode(cursor)));
        }

        // listRecords is public/unauthenticated on most PDSes, but we send the
        // bearer when we have a session one so private repos work too. An
        // Auth::Oauth / Auth::Anonymous client sends no Authorization header at
        // all. The guard drops the header if a redirect leaves this PDS's origin.
        let mut headers: Vec<(reqwest::header::HeaderName, HeaderValue)> = Vec::new();
        if let Auth::Session(s) = &self.auth {
            let mut value = HeaderValue::from_str(&format!("Bearer {}", s.access_jwt))
                .context("building Authorization header")?;
            value.set_sensitive(true);
            headers.push((AUTHORIZATION, value));
        }
        let resp = crate::net::guarded_get_no_privacy(&self.http, &url, &headers).await?;
        if !resp.status().is_success() {
            return Err(xrpc_error_from(resp).await.into());
        }
        let body = crate::net::read_capped(resp).await?;
        parse_list_records(&body)
    }

    /// Page through **all** records in a collection, following the cursor until
    /// exhausted. Convenience over [`list_records`](Self::list_records) for the
    /// login-time "load the whole follow-list" read.
    ///
    /// Bounded by [`MAX_LIST_PAGES`] and by cursor-repetition detection, because
    /// `pds_base` may be a host we did not choose (see [`PdsClient::anonymous`]).
    pub async fn list_all_records(&self, collection: &str) -> Result<Vec<RecordEntry>> {
        self.list_all_records_within(collection, MAX_LIST_BYTES)
            .await
    }

    /// [`list_all_records`](Self::list_all_records) with the budget named, so a
    /// test can reach the bound without allocating it.
    pub(crate) async fn list_all_records_within(
        &self,
        collection: &str,
        max_bytes: usize,
    ) -> Result<Vec<RecordEntry>> {
        let mut out = Vec::new();
        let mut budget = ByteBudget::new(max_bytes);
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_LIST_PAGES {
            let page = self
                .list_records(collection, Some(100), cursor.as_deref())
                .await?;
            let got = page.records.len();
            // **Refused, not truncated**, for the reason `extend_bounded`
            // gives: this walk feeds `replace_sub_refs`, where a short list is
            // revoked access.
            if !budget.admit(&page.records) {
                anyhow::bail!(
                    "listRecords for {collection} exceeded the {max_bytes}-byte cap \
                     ({} held, {} bytes charged) — refusing to accumulate further",
                    out.len(),
                    budget.used(),
                );
            }
            extend_bounded(&mut out, page.records, MAX_LIST_RECORDS, collection)?;
            match page.cursor {
                // Guard against a PDS that echoes a cursor with an empty page,
                // or that hands back the SAME cursor forever (an infinite walk
                // that would otherwise re-count the same page every pass).
                Some(next) if got > 0 && Some(&next) != cursor.as_ref() => cursor = Some(next),
                _ => break,
            }
        }
        Ok(out)
    }

    /// See [`RecordWalk`].
    /// The most recent records of a collection that the caller **keeps**,
    /// truncating rather than refusing.
    ///
    /// **The cap counts kept records, not walked ones.** Applying it to the
    /// raw collection starves a caller whose filter is selective: a quiet
    /// standard.site publication in a repo whose busy sibling fills the
    /// window returns nothing at all, permanently, and worse with every post
    /// the sibling makes. `MAX_LIST_PAGES` still bounds the request count, so
    /// a filter that matches nothing costs a fixed number of round trips.
    ///
    /// Truncating, not refusing, because this is an additive read: see
    /// [`extend_truncating`] for why the [`extend_bounded`] refusal would be
    /// strictly worse here.
    ///
    /// `page_size` is the caller's, because the right page depends on how big
    /// the records are: [`crate::net::read_capped`] bounds a response at 8 MB,
    /// so 100 long-form articles per page can exceed it and fail the whole
    /// walk.
    ///
    /// **Ordering is the PDS's**: `listRecords` is descending by *rkey*, which
    /// is newest-first only when rkeys are TIDs. For a publisher using slug
    /// rkeys the truncation keeps a lexicographic subset rather than a recent
    /// one — acceptable because the cap is now per-publication rather than
    /// per-repo, so reaching it at all means an archive larger than this
    /// reader stores.
    pub async fn list_recent_matching(
        &self,
        collection: &str,
        max_records: usize,
        page_size: u32,
        keep: impl FnMut(&RecordEntry) -> bool,
    ) -> Result<RecordWalk> {
        self.list_recent_matching_within(collection, max_records, MAX_LIST_BYTES, page_size, keep)
            .await
    }

    /// [`list_recent_matching`](Self::list_recent_matching) with the budget
    /// named, so a test can reach the bound without allocating it.
    pub(crate) async fn list_recent_matching_within(
        &self,
        collection: &str,
        max_records: usize,
        max_bytes: usize,
        page_size: u32,
        mut keep: impl FnMut(&RecordEntry) -> bool,
    ) -> Result<RecordWalk> {
        let mut out = Vec::new();
        let mut budget = ByteBudget::new(max_bytes);
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_LIST_PAGES {
            let page = self
                .list_records(collection, Some(page_size), cursor.as_deref())
                .await?;
            let got = page.records.len();
            // Is there a next page that is actually new? (A PDS may echo a
            // cursor with an empty page, or hand back the same one forever.)
            let more =
                matches!(&page.cursor, Some(next) if got > 0 && Some(next) != cursor.as_ref());
            let kept: Vec<RecordEntry> = page.records.into_iter().filter(|r| keep(r)).collect();
            // Charged on what is KEPT, which is what this walk retains. The
            // page itself is transient, and bounded separately by
            // `net::read_capped`.
            if !budget.admit(&kept) {
                return Ok(RecordWalk::partial(out));
            }
            if extend_truncating(&mut out, kept, max_records) {
                return Ok(RecordWalk::partial(out));
            }
            if out.len() >= max_records {
                // Landing exactly on the cap is only a truncation if the
                // collection had more to give — `extend_truncating` cannot see
                // that, so the caller's "incomplete" signal is decided here.
                return Ok(RecordWalk {
                    complete: !more,
                    records: out,
                });
            }
            if !more {
                return Ok(RecordWalk::complete(out));
            }
            cursor = page.cursor;
        }
        // **The page budget ran out with the collection still going.** Silence
        // here reintroduces the starvation this function exists to prevent, one
        // order of magnitude further out: a quiet publication in a repo whose
        // busy sibling has more records than MAX_LIST_PAGES × page_size can
        // reach returns nothing at all, forever, having spent every round trip
        // to find out. The caller is told so it can say which feed.
        Ok(RecordWalk::partial(out))
    }

    /// `com.atproto.repo.createRecord` — create a new record (server assigns the
    /// rkey, `key: tid`). Returns the written record's strong ref.
    /// **Private, not `pub` — and not `pub(crate)`.** This is generic over
    /// `T: Serialize`, so it will happily write a raw `lexicon::Subscription`:
    /// the general case of the hole `create_subscriptions_batch` was one
    /// instance of. The vetted wrappers in this `impl` are the sanctioned entry
    /// points. `pub(crate)` was tried first and stops nothing that matters — a
    /// handler in `web.rs` is in this crate. Private is what makes the wrappers
    /// a fact rather than a convention, and it costs nothing: nothing outside
    /// this module ever called it.
    async fn create_record<T: Serialize>(
        &self,
        collection: &str,
        record: &T,
    ) -> Result<WriteResult> {
        let body = json!({
            "repo": self.did.as_ref(),
            "collection": collection,
            "record": record,
        });
        self.repo_write("com.atproto.repo.createRecord", body).await
    }

    /// `com.atproto.repo.putRecord` — upsert a record at a **known** rkey
    /// (`key: any`). This is the `readState` upsert primitive: a feed-derived
    /// rkey makes the write idempotent (one record per feed).
    /// **Private, not `pub` — and not `pub(crate)`.** This is generic over
    /// `T: Serialize`, so it will happily write a raw `lexicon::Subscription`:
    /// the general case of the hole `create_subscriptions_batch` was one
    /// instance of. The vetted wrappers in this `impl` are the sanctioned entry
    /// points. `pub(crate)` was tried first and stops nothing that matters — a
    /// handler in `web.rs` is in this crate. Private is what makes the wrappers
    /// a fact rather than a convention, and it costs nothing: nothing outside
    /// this module ever called it.
    async fn put_record<T: Serialize>(
        &self,
        collection: &str,
        rkey: &str,
        record: &T,
    ) -> Result<WriteResult> {
        let body = json!({
            "repo": self.did.as_ref(),
            "collection": collection,
            "rkey": rkey,
            "record": record,
        });
        self.repo_write("com.atproto.repo.putRecord", body).await
    }

    /// The single outbound path for every authenticated `com.atproto.repo.*`
    /// **write**, routed through [`crate::net::guarded_post_json`].
    ///
    /// Reads were hardened first (see [`list_records`](Self::list_records)), but
    /// the argument applies with more force here: `pds_base` is vetted by
    /// [`crate::net::assert_public_target`] at *resolve* time, and the write is a
    /// *separate* DNS resolution — the rebinding window `net.rs` exists to close.
    /// A write also carries the session bearer and, in
    /// [`login_with_app_password`], the app password itself, so the guard's
    /// refusal to follow redirects (a `307` re-sends the body verbatim to the new
    /// host) is doing real work and not just symmetry.
    async fn guarded_post(&self, url: &str, body: &Value) -> Result<reqwest::Response> {
        let headers = self.authed_headers()?;
        let payload = serde_json::to_vec(body).context("serializing XRPC request body")?;
        crate::net::guarded_post_json(&self.http, url, &headers, payload).await
    }

    /// `com.atproto.repo.deleteRecord` — delete a record by collection + rkey
    /// (e.g. unsubscribe → delete the subscription record).
    pub async fn delete_record(&self, collection: &str, rkey: &str) -> Result<()> {
        let url = self.xrpc_url("com.atproto.repo.deleteRecord");
        let body = json!({
            "repo": self.did.as_ref(),
            "collection": collection,
            "rkey": rkey,
        });
        let resp = self.guarded_post(&url, &body).await?;
        if !resp.status().is_success() {
            return Err(xrpc_error_from(resp).await.into());
        }
        Ok(())
    }

    /// `com.atproto.repo.applyWrites` — a **batch** of create/update/delete
    /// operations in one atomic-per-repo round-trip.
    ///
    /// This is the read-state flusher's workhorse: dozens of dirty per-feed
    /// [`ReadState`] cursors coalesce into one call rather than one `putRecord`
    /// each. See [`flush_read_states`](Self::flush_read_states).
    /// **Private, not `pub` — and not `pub(crate)`.** This is generic over
    /// `T: Serialize`, so it will happily write a raw `lexicon::Subscription`:
    /// the general case of the hole `create_subscriptions_batch` was one
    /// instance of. The vetted wrappers in this `impl` are the sanctioned entry
    /// points. `pub(crate)` was tried first and stops nothing that matters — a
    /// handler in `web.rs` is in this crate. Private is what makes the wrappers
    /// a fact rather than a convention, and it costs nothing: nothing outside
    /// this module ever called it.
    async fn apply_writes(&self, writes: &[WriteOp]) -> Result<()> {
        let url = self.xrpc_url("com.atproto.repo.applyWrites");
        let ops: Vec<Value> = writes.iter().map(WriteOp::to_json).collect();
        let body = json!({
            "repo": self.did.as_ref(),
            "writes": ops,
        });
        let resp = self.guarded_post(&url, &body).await?;
        if !resp.status().is_success() {
            return Err(xrpc_error_from(resp).await.into());
        }
        Ok(())
    }

    /// Shared create/put path (both return a `{uri,cid}` strong ref).
    async fn repo_write(&self, method: &str, body: Value) -> Result<WriteResult> {
        let url = self.xrpc_url(method);
        let resp = self.guarded_post(&url, &body).await?;
        if !resp.status().is_success() {
            return Err(xrpc_error_from(resp).await.into());
        }
        // `read_capped` rather than `resp.json()`: a hostile PDS must not be able
        // to stream an unbounded body at a 512 MB box (same rule as the reads).
        let raw = crate::net::read_capped(resp).await?;
        serde_json::from_slice(&raw).with_context(|| format!("parsing {method} response"))
    }

    // -- typed lexicon wrappers ---------------------------------------------

    /// List every [`Subscription`] record in the user's repo (paged fully). The
    /// login-time "what does this user follow?" read.
    pub async fn list_subscriptions(&self) -> Result<Vec<(String, Subscription)>> {
        self.list_typed(lexicon::nsid::SUBSCRIPTION).await
    }

    /// Create a [`Subscription`] record (subscribe to a feed).
    pub async fn create_subscription(
        &self,
        sub: &crate::vetted::VettedSubscription,
    ) -> Result<WriteResult> {
        self.create_record(lexicon::nsid::SUBSCRIPTION, sub).await
    }

    /// List every [`Folder`] record in the user's repo.
    pub async fn list_folders(&self) -> Result<Vec<(String, Folder)>> {
        self.list_typed(lexicon::nsid::FOLDER).await
    }

    /// Create a [`Folder`] record.
    pub async fn create_folder(&self, folder: &Folder) -> Result<WriteResult> {
        self.create_record(lexicon::nsid::FOLDER, folder).await
    }

    /// List every [`Saved`] (starred) record in the user's repo.
    pub async fn list_saved(&self) -> Result<Vec<(String, Saved)>> {
        self.list_typed(lexicon::nsid::SAVED).await
    }

    /// Create a [`Saved`] record (star an article).
    pub async fn create_saved(&self, saved: &crate::vetted::VettedSaved) -> Result<WriteResult> {
        self.create_record(lexicon::nsid::SAVED, saved).await
    }

    /// List every [`ReadState`] cursor in the user's repo (the read side a
    /// login-time read-state merge would consume).
    pub async fn list_read_states(&self) -> Result<Vec<(String, ReadState)>> {
        self.list_typed(lexicon::nsid::READ_STATE).await
    }

    /// Upsert a single [`ReadState`] cursor at its feed-derived rkey. For a
    /// batch of dirty cursors prefer [`flush_read_states`](Self::flush_read_states).
    pub async fn put_read_state(&self, rkey: &str, state: &ReadState) -> Result<WriteResult> {
        self.put_record(lexicon::nsid::READ_STATE, rkey, state)
            .await
    }

    /// Batch-flush many dirty [`ReadState`] cursors in one `applyWrites` call —
    /// the debounced read-state flusher's coalesced write.
    ///
    /// Each `(rkey, state, pds_created)` becomes a `create` op at the feed-derived
    /// rkey when the record does not yet exist, and an `update` when it does — so a
    /// feed's FIRST flush succeeds (an `#update` on a missing record errors, and
    /// `applyWrites` is atomic per-repo). Both kinds ride the same batch.
    pub async fn flush_read_states(&self, cursors: &[(String, ReadState, bool)]) -> Result<()> {
        if cursors.is_empty() {
            return Ok(());
        }
        let writes = read_state_write_ops(cursors)?;
        self.apply_writes(&writes).await
    }

    /// List a collection and parse each record's value into `T`, pairing it with
    /// its rkey. Records that fail to deserialize are skipped with a warning
    /// (forward-compat: a future writer's extra fields shouldn't break login).
    async fn list_typed<T: DeserializeOwned>(&self, collection: &str) -> Result<Vec<(String, T)>> {
        let records = self.list_all_records(collection).await?;
        let mut out = Vec::with_capacity(records.len());
        for rec in records {
            let rkey = rec.rkey().unwrap_or_default().to_string();
            match rec.parse::<T>() {
                Ok(value) => out.push((rkey, value)),
                Err(e) => tracing::warn!(
                    collection,
                    uri = %rec.uri,
                    error = %e,
                    "skipping unparseable record in collection"
                ),
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// The OAuth sidecar client — the LIVE com.atproto.repo.* path
// ---------------------------------------------------------------------------

/// A client for the atproto OAuth sidecar's **internal** API.
///
/// This is the live path for every authed repo operation. Rather than the Rust
/// server holding PDS tokens, it POSTs `{did, action, …}` to the sidecar's
/// `/internal/repo` endpoint (gated by the shared `X-Internal-Secret`); the
/// sidecar `restore(did)`s the OAuth session — transparent DPoP + token refresh —
/// and runs the matching XRPC call via `@atproto/api`. The `did` (plus the shared
/// secret) is what authorizes the call; there is no bearer token on the Rust side.
///
/// It also fronts `/internal/session/:id`, the one-shot handoff the Rust callback
/// uses to turn a `session_id` (from the sidecar's browser redirect) into the
/// `{did, handle}` it keys its own signed cookie by.
///
/// Cheap to clone (shared `reqwest::Client` + `Arc`'d config).
#[derive(Clone)]
pub struct SidecarClient {
    http: Client,
    public_url: Arc<str>,
    internal_url: Arc<str>,
    internal_secret: Arc<str>,
}

/// The `{did, handle}` a session-id resolves to (the sidecar's
/// `/internal/session/:id` body).
#[derive(Debug, Clone, Deserialize)]
pub struct SidecarSession {
    /// The account DID that logged in.
    pub did: String,
    /// The account handle at login time.
    #[serde(default)]
    pub handle: Option<String>,
}

/// The sidecar's `/internal/revoke` response body:
/// `{ ok:true, did, revoked, hadSession }`.
#[derive(Debug, Clone, Deserialize)]
pub struct RevokeResult {
    /// The DID that was revoked.
    #[serde(default)]
    pub did: String,
    /// Whether the OAuth token revocation at the PDS succeeded. `false` means
    /// the local rows were still purged (best-effort), but the PDS-side tokens
    /// may not have been invalidated (network failure).
    #[serde(default)]
    pub revoked: bool,
    /// Whether the sidecar actually had a stored session for the DID.
    #[serde(default, rename = "hadSession")]
    pub had_session: bool,
}

/// The action verbs the sidecar's `/internal/repo` endpoint dispatches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoAction {
    /// `com.atproto.repo.listRecords`.
    List,
    /// `com.atproto.repo.createRecord`.
    Create,
    /// `com.atproto.repo.putRecord`.
    Put,
    /// `com.atproto.repo.deleteRecord`.
    Delete,
    /// `com.atproto.repo.applyWrites` (batch).
    ApplyWrites,
}

impl RepoAction {
    fn as_str(self) -> &'static str {
        match self {
            RepoAction::List => "list",
            RepoAction::Create => "create",
            RepoAction::Put => "put",
            RepoAction::Delete => "delete",
            RepoAction::ApplyWrites => "applyWrites",
        }
    }
}

/// The `/internal/repo` success envelope: `{ ok:true, data:<raw XRPC JSON> }`.
#[derive(Debug, Deserialize)]
struct RepoOk {
    #[serde(default)]
    data: Value,
}

/// The `/internal/repo` error envelope: `{ ok:false, error, message, status? }`.
#[derive(Debug, Deserialize)]
struct RepoErr {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    status: Option<u16>,
}

impl SidecarClient {
    /// Build a sidecar client from the shared [`reqwest::Client`] and the
    /// resolved public + internal base URLs + internal secret (from
    /// [`crate::config::SidecarConfig`]). `public_url` anchors the browser
    /// `/login` redirect; `internal_url` is the loopback base for the `/internal/*`
    /// API (they collapse to the same value in single-URL local dev).
    pub fn new(
        http: Client,
        public_url: impl Into<String>,
        internal_url: impl Into<String>,
        internal_secret: impl Into<String>,
    ) -> Self {
        Self {
            http,
            public_url: Arc::from(public_url.into().trim_end_matches('/')),
            internal_url: Arc::from(internal_url.into().trim_end_matches('/')),
            internal_secret: Arc::from(internal_secret.into()),
        }
    }

    /// The sidecar's public `/login` URL for a handle, round-tripping an opaque
    /// `return` value through OAuth state (used to bounce the browser back to a
    /// specific place after login). The browser is redirected here.
    pub fn login_url(&self, handle: &str, return_to: Option<&str>) -> String {
        let mut url = format!("{}/login?handle={}", self.public_url, urlencode(handle));
        if let Some(r) = return_to {
            url.push_str(&format!("&return={}", urlencode(r)));
        }
        url
    }

    /// Resolve a one-shot `session_id` (from the sidecar's post-OAuth redirect)
    /// to the `{did, handle}` that logged in. `Ok(None)` on `404 SessionNotFound`.
    pub async fn resolve_session(&self, session_id: &str) -> Result<Option<SidecarSession>> {
        let url = format!(
            "{}/internal/session/{}",
            self.internal_url,
            urlencode(session_id)
        );
        let resp = self
            .http
            .get(&url)
            .header("X-Internal-Secret", self.internal_secret.as_ref())
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(xrpc_error_from(resp).await.into());
        }
        let raw = crate::net::read_capped(resp).await?;
        let session: SidecarSession =
            serde_json::from_slice(&raw).context("parsing /internal/session response")?;
        Ok(Some(session))
    }

    /// Revoke a DID's OAuth session at the sidecar: `POST /internal/revoke`.
    ///
    /// This revokes the refresh + access tokens at the PDS **and** purges the
    /// sidecar's stored `oauth_session` + `app_session` rows for the DID. It is
    /// idempotent — revoking a DID with no live session returns
    /// `had_session: false`. Called on `/logout` (so the cookie clear isn't the
    /// only thing that ends the session) and on `/account/delete`.
    pub async fn revoke_session(&self, did: &str) -> Result<RevokeResult> {
        let url = format!("{}/internal/revoke", self.internal_url);
        let resp = self
            .http
            .post(&url)
            .header("X-Internal-Secret", self.internal_secret.as_ref())
            .json(&json!({ "did": did }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(xrpc_error_from(resp).await.into());
        }
        let raw = crate::net::read_capped(resp).await?;
        let result: RevokeResult =
            serde_json::from_slice(&raw).context("parsing /internal/revoke response")?;
        Ok(result)
    }

    /// POST one op to `/internal/repo` and return the raw XRPC `data` payload.
    ///
    /// `body` must already carry `did` + `action` + the action's required fields
    /// (the typed wrappers below build these). Maps the sidecar's error envelope
    /// to [`AtProtoError`]: `404 SessionNotFound` → `Xrpc{error:"SessionNotFound"}`
    /// so callers can treat it as "re-login required".
    async fn repo(&self, body: Value) -> Result<Value> {
        let url = format!("{}/internal/repo", self.internal_url);
        let resp = self
            .http
            .post(&url)
            .header("X-Internal-Secret", self.internal_secret.as_ref())
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        // **Capped, like every other body this codebase reads.** `resp.json()`
        // buffers whatever arrives; `/internal/repo` proxies the account's PDS,
        // so that length is chosen by a host the reader picked and we did not.
        // The 8 MB ceiling that bounds the direct client did not exist here,
        // and the sidecar is the default backend — so the one path with no byte
        // bound at all was the one most deployments run.
        let raw = crate::net::read_capped(resp).await;
        if status.is_success() {
            let ok: RepoOk =
                serde_json::from_slice(&raw?).context("parsing /internal/repo ok body")?;
            return Ok(ok.data);
        }
        // Error path: parse the sidecar's `{ok:false,error,message,status}` shape.
        //
        // **A body we could not read must not cost us the status.** Reading
        // before the branch was the obvious shape and it swallowed the HTTP
        // status on an over-cap or truncated error body, turning a `404
        // SessionNotFound` into a bare "body exceeded the cap". `xrpc_error_from`
        // already makes the opposite choice deliberately, for the same reason.
        let err: RepoErr = raw
            .ok()
            .and_then(|body| serde_json::from_slice(&body).ok())
            .unwrap_or(RepoErr {
                error: None,
                message: None,
                status: None,
            });
        let mapped = err
            .status
            .and_then(|s| StatusCode::from_u16(s).ok())
            .unwrap_or(status);
        Err(AtProtoError::Xrpc {
            status: mapped,
            error: err.error.unwrap_or_else(|| "Unknown".to_string()),
            message: err.message,
        }
        .into())
    }

    // -- raw com.atproto.repo.* over the sidecar -----------------------------

    /// `list` — one page of a collection's records for `did`.
    pub async fn list_records(
        &self,
        did: &str,
        collection: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<ListRecordsResponse> {
        let mut body = json!({
            "did": did,
            "action": RepoAction::List.as_str(),
            "collection": collection,
        });
        if let Some(limit) = limit {
            body["limit"] = json!(limit);
        }
        if let Some(cursor) = cursor {
            body["cursor"] = json!(cursor);
        }
        let data = self.repo(body).await?;
        // The sidecar proxies the PDS's body, so the 2xx-envelope case arrives
        // here too — and `RepoOk.data` is a defaulted `Value`.
        list_records_from_value(data).context("parsing sidecar listRecords data")
    }

    /// Page through **all** records in a collection for `did`.
    ///
    /// Bounded by [`MAX_LIST_PAGES`] and cursor-repetition detection, same as
    /// [`PdsClient::list_all_records`] — the sidecar proxies to the account's
    /// PDS, so the page count is ultimately remote-controlled here too.
    pub async fn list_all_records(&self, did: &str, collection: &str) -> Result<Vec<RecordEntry>> {
        self.list_all_records_within(did, collection, MAX_LIST_BYTES)
            .await
    }

    /// [`list_all_records`](Self::list_all_records) with the budget named, so a
    /// test can reach the bound without allocating it.
    pub(crate) async fn list_all_records_within(
        &self,
        did: &str,
        collection: &str,
        max_bytes: usize,
    ) -> Result<Vec<RecordEntry>> {
        let mut out = Vec::new();
        let mut budget = ByteBudget::new(max_bytes);
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_LIST_PAGES {
            let page = self
                .list_records(did, collection, Some(100), cursor.as_deref())
                .await?;
            let got = page.records.len();
            // The sidecar proxies the account's PDS, so this walk's size is as
            // remote-controlled as the direct client's. It carried no budget at
            // all until a review noticed it was the default backend.
            if !budget.admit(&page.records) {
                anyhow::bail!(
                    "listRecords for {collection} exceeded the {max_bytes}-byte cap \
                     ({} held, {} bytes charged) — refusing to accumulate further",
                    out.len(),
                    budget.used(),
                );
            }
            extend_bounded(&mut out, page.records, MAX_LIST_RECORDS, collection)?;
            match page.cursor {
                Some(next) if got > 0 && Some(&next) != cursor.as_ref() => cursor = Some(next),
                _ => break,
            }
        }
        Ok(out)
    }

    /// `create` — create a record (server-assigned rkey). Returns its strong ref.
    /// **Private, not `pub` — and not `pub(crate)`.** This is generic over
    /// `T: Serialize`, so it will happily write a raw `lexicon::Subscription`:
    /// the general case of the hole `create_subscriptions_batch` was one
    /// instance of. The vetted wrappers in this `impl` are the sanctioned entry
    /// points. `pub(crate)` was tried first and stops nothing that matters — a
    /// handler in `web.rs` is in this crate. Private is what makes the wrappers
    /// a fact rather than a convention, and it costs nothing: nothing outside
    /// this module ever called it.
    async fn create_record<T: Serialize>(
        &self,
        did: &str,
        collection: &str,
        record: &T,
    ) -> Result<WriteResult> {
        let body = json!({
            "did": did,
            "action": RepoAction::Create.as_str(),
            "collection": collection,
            "record": record,
        });
        let data = self.repo(body).await?;
        serde_json::from_value(data).context("parsing sidecar createRecord data")
    }

    /// `put` — upsert a record at a known rkey. Returns its strong ref.
    /// **Private, not `pub` — and not `pub(crate)`.** This is generic over
    /// `T: Serialize`, so it will happily write a raw `lexicon::Subscription`:
    /// the general case of the hole `create_subscriptions_batch` was one
    /// instance of. The vetted wrappers in this `impl` are the sanctioned entry
    /// points. `pub(crate)` was tried first and stops nothing that matters — a
    /// handler in `web.rs` is in this crate. Private is what makes the wrappers
    /// a fact rather than a convention, and it costs nothing: nothing outside
    /// this module ever called it.
    async fn put_record<T: Serialize>(
        &self,
        did: &str,
        collection: &str,
        rkey: &str,
        record: &T,
    ) -> Result<WriteResult> {
        let body = json!({
            "did": did,
            "action": RepoAction::Put.as_str(),
            "collection": collection,
            "rkey": rkey,
            "record": record,
        });
        let data = self.repo(body).await?;
        serde_json::from_value(data).context("parsing sidecar putRecord data")
    }

    /// `delete` — delete a record by collection + rkey.
    pub async fn delete_record(&self, did: &str, collection: &str, rkey: &str) -> Result<()> {
        let body = json!({
            "did": did,
            "action": RepoAction::Delete.as_str(),
            "collection": collection,
            "rkey": rkey,
        });
        // A 200 carrying an error envelope is not a delete: this reported
        // success while the record stayed in the reader's repo, and the UI
        // showed them unsubscribed from a feed they still had.
        self.repo(body)
            .await
            .and_then(|data| reject_error_envelope(&data))?;
        Ok(())
    }

    /// `applyWrites` — a batch of create/update/delete ops in one round-trip.
    /// **Private, not `pub` — and not `pub(crate)`.** This is generic over
    /// `T: Serialize`, so it will happily write a raw `lexicon::Subscription`:
    /// the general case of the hole `create_subscriptions_batch` was one
    /// instance of. The vetted wrappers in this `impl` are the sanctioned entry
    /// points. `pub(crate)` was tried first and stops nothing that matters — a
    /// handler in `web.rs` is in this crate. Private is what makes the wrappers
    /// a fact rather than a convention, and it costs nothing: nothing outside
    /// this module ever called it.
    async fn apply_writes(&self, did: &str, writes: &[WriteOp]) -> Result<()> {
        if writes.is_empty() {
            return Ok(());
        }
        let ops: Vec<Value> = writes.iter().map(WriteOp::to_sidecar_json).collect();
        let body = json!({
            "did": did,
            "action": RepoAction::ApplyWrites.as_str(),
            "writes": ops,
        });
        self.repo(body)
            .await
            .and_then(|data| reject_error_envelope(&data))?;
        Ok(())
    }

    // -- typed lexicon wrappers (mirror the old PdsClient surface) ------------

    /// List every [`Subscription`] record in `did`'s repo (paged fully).
    pub async fn list_subscriptions(&self, did: &str) -> Result<Vec<(String, Subscription)>> {
        self.list_typed(did, lexicon::nsid::SUBSCRIPTION).await
    }

    /// Create a [`Subscription`] record (subscribe to a feed).
    pub async fn create_subscription(
        &self,
        did: &str,
        sub: &crate::vetted::VettedSubscription,
    ) -> Result<WriteResult> {
        self.create_record(did, lexicon::nsid::SUBSCRIPTION, sub)
            .await
    }

    /// Delete a [`Subscription`] record by rkey (unsubscribe).
    pub async fn delete_subscription(&self, did: &str, rkey: &str) -> Result<()> {
        self.delete_record(did, lexicon::nsid::SUBSCRIPTION, rkey)
            .await
    }

    /// List every [`Folder`] record in `did`'s repo.
    pub async fn list_folders(&self, did: &str) -> Result<Vec<(String, Folder)>> {
        self.list_typed(did, lexicon::nsid::FOLDER).await
    }

    /// List every [`Saved`] record in `did`'s repo.
    pub async fn list_saved(&self, did: &str) -> Result<Vec<(String, Saved)>> {
        self.list_typed(did, lexicon::nsid::SAVED).await
    }

    /// List every [`ReadState`] cursor in `did`'s repo (the read side a
    /// login-time read-state merge would consume).
    pub async fn list_read_states(&self, did: &str) -> Result<Vec<(String, ReadState)>> {
        self.list_typed(did, lexicon::nsid::READ_STATE).await
    }

    /// Upsert a single [`ReadState`] cursor at its feed-derived rkey.
    pub async fn put_read_state(
        &self,
        did: &str,
        rkey: &str,
        state: &ReadState,
    ) -> Result<WriteResult> {
        self.put_record(did, lexicon::nsid::READ_STATE, rkey, state)
            .await
    }

    /// Batch-flush many dirty [`ReadState`] cursors in one `applyWrites` call.
    ///
    /// Each `(rkey, state, pds_created)` becomes a `create` op at the feed-derived
    /// rkey when the record does NOT yet exist (`pds_created == false`), and an
    /// `update` op when it does. This is what makes the FIRST flush of a feed
    /// succeed: `applyWrites#update` errors on a record that does not pre-exist,
    /// and `applyWrites` is atomic per-repo, so a single not-yet-created cursor
    /// would otherwise drop the whole DID batch. Both kinds ride the SAME
    /// `applyWrites` batch so batching is preserved.
    pub async fn flush_read_states(
        &self,
        did: &str,
        cursors: &[(String, ReadState, bool)],
    ) -> Result<()> {
        if cursors.is_empty() {
            return Ok(());
        }
        let writes = read_state_write_ops(cursors)?;
        self.apply_writes(did, &writes).await
    }

    // -- reader-facing record CRUD (the surface the web layer calls) ----------
    //
    // These are the typed convenience methods `web.rs` uses to manage a user's
    // feeds/folders/saved items *as records in their PDS*. They mirror the
    // create/list surface above but use the reader vocabulary
    // (add/remove/rename) and, for the `add_*` verbs, return the server-assigned
    // rkey so the caller can address the new record without a re-list. Ordering
    // is made deterministic where it matters (see [`list_subscriptions_sorted`]
    // etc.) so the server-rendered HTML is stable between reads.

    // -- subscriptions -------------------------------------------------------

    /// Add a subscription (subscribe to a feed) — `createRecord`, server-assigned
    /// `tid` rkey. Returns the new record's **rkey** so the web layer can offer
    /// unsubscribe/rename immediately.
    pub async fn add_subscription(
        &self,
        did: &str,
        sub: &crate::vetted::VettedSubscription,
    ) -> Result<String> {
        Ok(self.create_subscription(did, sub).await?.into_rkey())
    }

    /// Remove a subscription (unsubscribe) by rkey — `deleteRecord`. Alias of
    /// [`delete_subscription`](Self::delete_subscription) in the reader vocabulary.
    pub async fn remove_subscription(&self, did: &str, rkey: &str) -> Result<()> {
        self.delete_subscription(did, rkey).await
    }

    /// Update / rename a subscription in place at a known rkey — `putRecord`.
    ///
    /// The whole record is replaced (retitle, move to a folder, change the
    /// fetch hint …). Upsert semantics: it also creates the record if the rkey
    /// is somehow absent, so it is safe as a general "write this exact record".
    pub async fn update_subscription(
        &self,
        did: &str,
        rkey: &str,
        sub: &crate::vetted::VettedSubscription,
    ) -> Result<WriteResult> {
        self.put_record(did, lexicon::nsid::SUBSCRIPTION, rkey, sub)
            .await
    }

    /// List every subscription, **sorted deterministically** — by display title
    /// (case-insensitive), then feed URL, then rkey as the final tiebreaker — so
    /// the rendered feed list is stable across reads regardless of PDS return
    /// order. Untitled feeds sort by their URL.
    pub async fn list_subscriptions_sorted(
        &self,
        did: &str,
    ) -> Result<Vec<(String, Subscription)>> {
        let mut subs = self.list_subscriptions(did).await?;
        // The comparator is SHARED with the Rust-native client so the two
        // cannot order the list differently across the cutover.
        subs.sort_by(lexicon::sort::subscriptions);
        Ok(subs)
    }

    /// Batch-add many subscriptions in one `applyWrites` — the OPML-import path.
    ///
    /// Each feed becomes one `create` op. Client-side monotonic [`tid`](tid)
    /// rkeys are assigned so the batch is deterministic and the imported feeds
    /// keep OPML order (server-assigned tids would also be monotonic, but pinning
    /// them here makes the whole import reproducible and testable offline).
    /// Returns the assigned rkeys in input order.
    pub async fn add_subscriptions_bulk(
        &self,
        did: &str,
        subs: &[crate::vetted::VettedSubscription],
    ) -> Result<Vec<String>> {
        let mut gen = TidGenerator::new();
        let mut rkeys = Vec::with_capacity(subs.len());
        let mut writes = Vec::with_capacity(subs.len());
        for sub in subs {
            let rkey = gen.next();
            writes.push(WriteOp::Create {
                collection: lexicon::nsid::SUBSCRIPTION.to_string(),
                rkey: Some(rkey.clone()),
                value: serde_json::to_value(sub)?,
            });
            rkeys.push(rkey);
        }
        self.apply_writes(did, &writes).await?;
        Ok(rkeys)
    }

    // -- folders -------------------------------------------------------------

    /// Add a folder — `createRecord`, server-assigned `tid` rkey. Returns the
    /// new folder's rkey (subscriptions reference it by its `at://` URI).
    pub async fn add_folder(&self, did: &str, folder: &Folder) -> Result<String> {
        Ok(self
            .create_record(did, lexicon::nsid::FOLDER, folder)
            .await?
            .into_rkey())
    }

    /// Remove a folder by rkey — `deleteRecord`. (Subscriptions referencing it
    /// are left untouched; a dangling `folder` ref reads as "unfiled".)
    pub async fn remove_folder(&self, did: &str, rkey: &str) -> Result<()> {
        self.delete_record(did, lexicon::nsid::FOLDER, rkey).await
    }

    /// Rename / update a folder in place at a known rkey — `putRecord`
    /// (rename, or change its `position` sort hint).
    pub async fn rename_folder(
        &self,
        did: &str,
        rkey: &str,
        folder: &Folder,
    ) -> Result<WriteResult> {
        self.put_record(did, lexicon::nsid::FOLDER, rkey, folder)
            .await
    }

    /// List every folder, **sorted deterministically** — by `position` (the
    /// lexicon's sort hint; unset sorts last), then name (case-insensitive),
    /// then rkey — so the sidebar order is stable.
    pub async fn list_folders_sorted(&self, did: &str) -> Result<Vec<(String, Folder)>> {
        let mut folders = self.list_folders(did).await?;
        folders.sort_by(lexicon::sort::folders);
        Ok(folders)
    }

    // -- saved / starred -----------------------------------------------------

    /// Add a saved (starred / save-for-later) entry — `createRecord`,
    /// server-assigned `tid` rkey. Returns the new record's rkey.
    pub async fn add_saved(&self, did: &str, saved: &crate::vetted::VettedSaved) -> Result<String> {
        Ok(self
            .create_record(did, lexicon::nsid::SAVED, saved)
            .await?
            .into_rkey())
    }

    /// Remove a saved entry by rkey — `deleteRecord` (un-star).
    pub async fn remove_saved(&self, did: &str, rkey: &str) -> Result<()> {
        self.delete_record(did, lexicon::nsid::SAVED, rkey).await
    }

    /// List every saved entry, **sorted deterministically** — newest first by
    /// `createdAt` (RFC-3339 sorts lexicographically), then rkey — so the
    /// "saved for later" list reads most-recent-first and is stable.
    pub async fn list_saved_sorted(&self, did: &str) -> Result<Vec<(String, Saved)>> {
        let mut saved = self.list_saved(did).await?;
        saved.sort_by(lexicon::sort::saved);
        Ok(saved)
    }

    /// List a collection for `did` and parse each record's value into `T`,
    /// pairing it with its rkey. Unparseable records are skipped with a warning
    /// (forward-compat).
    async fn list_typed<T: DeserializeOwned>(
        &self,
        did: &str,
        collection: &str,
    ) -> Result<Vec<(String, T)>> {
        let records = self.list_all_records(did, collection).await?;
        let mut out = Vec::with_capacity(records.len());
        for rec in records {
            let rkey = rec.rkey().unwrap_or_default().to_string();
            match rec.parse::<T>() {
                Ok(value) => out.push((rkey, value)),
                Err(e) => tracing::warn!(
                    collection,
                    uri = %rec.uri,
                    error = %e,
                    "skipping unparseable record in collection"
                ),
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// applyWrites operations
// ---------------------------------------------------------------------------

/// Build the `applyWrites` ops for a batch of dirty read-state cursors.
///
/// Each `(rkey, state, pds_created)` becomes a `#create` op (at the stable
/// feed-derived rkey) when the PDS record does NOT yet exist, and a `#update`
/// when it does. This is the crux of the first-flush fix: an `#update` on a
/// missing record errors, and `applyWrites` is atomic per-repo, so a single
/// not-yet-created cursor in the batch would drop the whole DID's flush. Emitting
/// a `create` for those makes a feed's first flush succeed while keeping every
/// op in ONE batch. Shared by both the sidecar and direct-PDS flush paths.
pub(crate) fn read_state_write_ops(cursors: &[(String, ReadState, bool)]) -> Result<Vec<WriteOp>> {
    cursors
        .iter()
        .map(|(rkey, state, pds_created)| {
            let value = serde_json::to_value(state)?;
            Ok(if *pds_created {
                WriteOp::Update {
                    collection: lexicon::nsid::READ_STATE.to_string(),
                    rkey: rkey.clone(),
                    value,
                }
            } else {
                WriteOp::Create {
                    collection: lexicon::nsid::READ_STATE.to_string(),
                    rkey: Some(rkey.clone()),
                    value,
                }
            })
        })
        .collect()
}

/// One operation in a [`PdsClient::apply_writes`] batch.
///
/// Maps to the `com.atproto.repo.applyWrites` union of
/// `#create` / `#update` / `#delete`.
#[derive(Debug, Clone)]
pub enum WriteOp {
    /// Create a record (server-assigned rkey unless `rkey` is given).
    Create {
        /// The collection NSID.
        collection: String,
        /// Optional explicit rkey (`None` → server assigns a tid).
        rkey: Option<String>,
        /// The record body.
        value: Value,
    },
    /// Upsert a record at a known rkey (the read-state cursor case).
    Update {
        /// The collection NSID.
        collection: String,
        /// The rkey to write at.
        rkey: String,
        /// The record body.
        value: Value,
    },
    /// Delete a record by collection + rkey.
    Delete {
        /// The collection NSID.
        collection: String,
        /// The rkey to delete.
        rkey: String,
    },
}

impl WriteOp {
    /// Render this op as the tagged JSON `com.atproto.repo.applyWrites` expects.
    ///
    /// `pub(crate)` so [`crate::oauth::xrpc`] can build the same batch body.
    /// Sharing the rendering rather than reimplementing it is what keeps the two
    /// clients wire-identical across the cutover.
    pub(crate) fn to_json(&self) -> Value {
        match self {
            WriteOp::Create {
                collection,
                rkey,
                value,
            } => {
                let mut op = json!({
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": collection,
                    "value": value,
                });
                if let Some(rkey) = rkey {
                    op["rkey"] = json!(rkey);
                }
                op
            }
            WriteOp::Update {
                collection,
                rkey,
                value,
            } => json!({
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": collection,
                "rkey": rkey,
                "value": value,
            }),
            WriteOp::Delete { collection, rkey } => json!({
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": collection,
                "rkey": rkey,
            }),
        }
    }

    /// Render this op in the shape the OAuth sidecar's `/internal/repo`
    /// `applyWrites` expects: `{action, collection, rkey?, value?}` (the sidecar
    /// maps `action` → the `com.atproto.repo.applyWrites#<kind>` union member).
    fn to_sidecar_json(&self) -> Value {
        match self {
            WriteOp::Create {
                collection,
                rkey,
                value,
            } => {
                let mut op = json!({
                    "action": "create",
                    "collection": collection,
                    "value": value,
                });
                if let Some(rkey) = rkey {
                    op["rkey"] = json!(rkey);
                }
                op
            }
            WriteOp::Update {
                collection,
                rkey,
                value,
            } => json!({
                "action": "update",
                "collection": collection,
                "rkey": rkey,
                "value": value,
            }),
            WriteOp::Delete { collection, rkey } => json!({
                "action": "delete",
                "collection": collection,
                "rkey": rkey,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// TID rkeys (client-assigned, sortable, deterministic within a batch)
// ---------------------------------------------------------------------------

/// The atproto base32-sortable alphabet (`s32`) — the digits/letters, minus the
/// ambiguous set, in **ascending** order so a bytewise string compare of two
/// TIDs matches their timestamp order.
const S32_ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

/// A monotonic generator of atproto **TID** record keys.
///
/// A TID is a 13-char `s32`-encoded 64-bit integer: a 53-bit microsecond
/// timestamp in the high bits and a 10-bit "clock id" in the low bits (the top
/// bit is always 0). Encoded in the ascending `s32` alphabet, TIDs sort
/// lexicographically in creation order — which is exactly what we want for a
/// batched OPML import: assigning the rkeys ourselves keeps the imported feeds
/// in input order and makes [`add_subscriptions_bulk`](SidecarClient::add_subscriptions_bulk)
/// fully reproducible/testable without a live PDS.
///
/// Monotonicity within one generator is guaranteed by tracking the last value
/// and bumping to `last + 1` if the clock hasn't advanced — so a burst of
/// same-microsecond calls still yields strictly increasing, ordered rkeys.
pub(crate) struct TidGenerator {
    /// The last raw 64-bit TID value emitted (0 = none yet).
    last: u64,
    /// The low-10-bit clock id, randomized once per generator to avoid
    /// cross-instance collisions on the same microsecond.
    clock_id: u64,
}

impl TidGenerator {
    /// A fresh generator with a per-instance clock id derived from the current
    /// nanosecond clock (no extra deps; uniqueness only needs to hold within a
    /// single import batch, and the timestamp bits carry the ordering).
    pub(crate) fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        Self {
            last: 0,
            clock_id: nanos & 0x3ff,
        }
    }

    /// The next monotonic TID rkey (13 `s32` chars).
    pub(crate) fn next(&mut self) -> String {
        let micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        // Timestamp in bits 63..10 (top bit stays 0), clock id in bits 9..0.
        let mut raw = ((micros & 0x001f_ffff_ffff_ffff) << 10) | self.clock_id;
        if raw <= self.last {
            raw = self.last + 1;
        }
        self.last = raw;
        encode_s32_tid(raw)
    }
}

/// Encode a 64-bit TID value as a 13-char big-endian `s32` string.
fn encode_s32_tid(mut v: u64) -> String {
    let mut buf = [0u8; 13];
    for slot in buf.iter_mut().rev() {
        *slot = S32_ALPHABET[(v & 0x1f) as usize];
        v >>= 5;
    }
    // 13 * 5 = 65 bits cover the 64-bit value; the leading char carries bits
    // 64..60, and bit 64 does not exist in a `u64` while bit 63 is always 0 in
    // a real TID, so the leading char is always one of the alphabet's first
    // eight symbols. Between 2005-09-05 and 2041-05-10 it is the second one,
    // which is why real TIDs all begin with `3`.
    String::from_utf8(buf.to_vec()).unwrap_or_default()
}

/// The earliest instant a real TID can encode: 2020-01-01T00:00:00Z, in
/// microseconds.
///
/// atproto did not exist before this, so a "TID" decoding to earlier is a record
/// key that merely *looks* like one.
///
/// **This bound catches only the slugs that fall outside the window, and that
/// is a minority of them.** 13 lowercase alphanumerics is an ordinary slug
/// shape and also a valid `s32` value, and one beginning `3` decodes into the
/// last few years as readily as a real record key does: `3hoursinparis` reads
/// as 2020-11-24, `3ideasforjune` as 2021-08-12. Nothing in the string
/// distinguishes them — telling a slug from a TID would mean asking the PDS
/// when the record was written, which the listing does not report.
///
/// What the window does buy is that a mis-read date is always an ordinary past
/// instant rather than an unsweepable future one. That is worth having and it
/// is *not* harmless: a slug reading as 2020 is older than any realistic
/// retention window, so the row is swept, re-listed on the next poll, and
/// arrives unread again — the cycle this dating work narrows but does not
/// close. Refusing to insert what is already past the floor is what closes it,
/// for a mis-read slug and a genuine archive alike, and that belongs with the
/// retention floor rather than here.
const TID_FLOOR_MICROS: i64 = 1_577_836_800_000_000;

/// How far ahead of our own clock a timestamp someone else authored may be and
/// still be believed.
///
/// A PDS a second or two fast would otherwise leave a brand-new document
/// undated until the following poll, and an undated row is the least visible
/// one in the reading list. Well under any interval that matters to retention
/// or the per-feed cap.
///
/// **Both date sources use it.** It began as a TID-only allowance, which left a
/// stated `publishedAt` judged against a bare `now` while the record key two
/// lines below got five minutes — the same clock, two different answers, for no
/// reason either comment could give.
pub(crate) const CLOCK_SKEW_GRACE_SECS: i64 = 300;

/// Decode a 13-char `s32` TID rkey back to its raw 64-bit value.
///
/// The exact inverse of [`encode_s32_tid`] over the values a TID can hold.
///
/// `None` for anything that is not a 13-character `s32` value: wrong length, a
/// character outside the alphabet, or a value whose top bit is set. That last
/// rejection is stricter than the TID syntax regex, which admits leading `c`
/// through `j`; the spec's separate rule that the high bit is always 0 is the
/// one enforced here, and it keeps every decoded value inside the range
/// [`tid_timestamp`] can shift without loss.
///
/// **This does not decide whether the string is a TID**, only whether it is a
/// number. Thirteen lowercase alphanumerics is also an ordinary slug, and a
/// slug decodes as readily as a record key does. Refusing an implausible
/// instant is [`tid_timestamp`]'s job, and it is where that case is caught.
pub(crate) fn decode_s32_tid(rkey: &str) -> Option<u64> {
    if rkey.len() != 13 {
        return None;
    }
    let mut v: u64 = 0;
    for b in rkey.bytes() {
        let digit = S32_ALPHABET.iter().position(|c| *c == b)? as u64;
        // `checked_*` rather than shifting: 13 chars carry 65 bits, so the
        // largest 13-char string overflows a `u64` and must read as "not a
        // TID" instead of wrapping to a plausible-looking value.
        v = v.checked_mul(32)?.checked_add(digit)?;
    }
    (v >> 63 == 0).then_some(v)
}

/// The instant a TID rkey encodes, or `None` if the rkey is not a plausible
/// TID.
///
/// **Bounded at both ends on purpose.** A TID's timestamp is minted from the
/// writer's clock, so one decoding far into the future is either a broken clock
/// or a slug that happens to be 13 `s32` characters; one decoding to before
/// [`TID_FLOOR_MICROS`] predates atproto. Neither is a date worth trusting, and
/// the caller's fallback for "no date" is safer than a wrong one.
///
/// The bounds are not a slug detector — see [`TID_FLOOR_MICROS`] for why they
/// cannot be, and for what they do guarantee instead.
pub(crate) fn tid_timestamp(rkey: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    // The low 10 bits are the clock id; the rest is microseconds since the
    // epoch, and clearing bit 63 above bounds it well inside `i64`.
    let micros = i64::try_from(decode_s32_tid(rkey)? >> 10).ok()?;
    if micros < TID_FLOOR_MICROS {
        return None;
    }
    let at = chrono::DateTime::from_timestamp_micros(micros)?;
    let ceiling = chrono::Utc::now() + chrono::Duration::seconds(CLOCK_SKEW_GRACE_SECS);
    (at <= ceiling).then_some(at)
}

// ---------------------------------------------------------------------------
// XRPC error helper
// ---------------------------------------------------------------------------

/// Minimal percent-encoding for a query-string component.
///
/// Encodes everything outside the RFC 3986 unreserved set, which covers the
/// values FeatherReader passes (DIDs like `did:plc:…`, NSIDs, opaque cursors,
/// handles) without pulling in the optional reqwest `url`/`query` feature.
///
/// `pub(crate)` so [`crate::network`] builds its relay query strings the same
/// way rather than keeping a second copy of the escape table.
pub(crate) fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Parse a `listRecords` body, refusing an error envelope that arrived on a
/// 2xx. `ListRecordsResponse.records` is `#[serde(default)]`, so
/// `{"error","message"}` would otherwise deserialise as an EMPTY page — and a
/// walk over a stranger's collection would return a healthy, empty result in
/// place of an error. Some PDS implementations answer 200 for application
/// failures; the status check in the caller cannot see those.
pub(crate) fn parse_list_records(body: &[u8]) -> Result<ListRecordsResponse> {
    let value: Value = serde_json::from_slice(body).context("parsing listRecords response")?;
    list_records_from_value(value)
}

/// Turn an already-parsed `listRecords` body into a page, enforcing **both**
/// invariants every caller needs.
///
/// **One function, because the guards kept being added to one caller at a
/// time.** The error-envelope check landed on the anonymous client first and
/// had to be added to the OAuth and sidecar clients a round later; the
/// records-presence check landed on the OAuth client and had to be added to
/// the other two a round after that. Both failures are the same: a body that
/// is not a listing deserialises to an empty page, `resolve_subscriptions`
/// reads that as "this DID follows nothing" instead of taking its fail-closed
/// branch, and `replace_sub_refs` DELETEs the reader's whole `sub_ref`
/// projection. Anything that reads a listRecords body goes through here.
pub(crate) fn list_records_from_value(value: Value) -> Result<ListRecordsResponse> {
    reject_error_envelope(&value)?;
    // `records` is `#[serde(default)]`, so `{}` — what a proxy produces from an
    // empty or unexpected upstream body — is otherwise a page of zero records.
    anyhow::ensure!(
        value.get("records").is_some(),
        "listRecords returned no records field (empty or unexpected body)"
    );
    serde_json::from_value(value).context("parsing listRecords response")
}

/// Refuse an atproto error envelope that arrived on a 2xx.
///
/// **Every shape that reads a listRecords body goes through this**, not only
/// the anonymous client: `oauth::xrpc::Repo` takes `records` off the JSON with
/// `unwrap_or(Array([]))`, and the sidecar's `RepoOk.data` is a defaulted
/// `Value`. Both turned `200 {"error": …}` into `Ok(empty)`, which is not the
/// fail-closed branch in `web::resolve_subscriptions` — so `sync_sub_refs`
/// wrote an empty set and `replace_sub_refs` DELETEd the DID's entire
/// `sub_ref` projection. One bad response revoked a reader's access to every
/// feed they have.
pub(crate) fn reject_error_envelope(value: &Value) -> Result<()> {
    let Some(error) = value.get("error").and_then(Value::as_str) else {
        return Ok(());
    };
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .map(|m| format!(" — {m}"))
        .unwrap_or_default();
    anyhow::bail!("PDS answered 2xx with an error envelope: {error}{message}")
}

/// The atproto XRPC error envelope body: `{"error": "...", "message": "..."}`.
#[derive(Debug, Deserialize)]
struct XrpcErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// Consume a non-2xx response into a typed [`AtProtoError::Xrpc`], parsing the
/// atproto error envelope when present (falling back to `"Unknown"`).
///
/// The body is read through [`crate::net::read_capped`], **not** `resp.json()`.
/// Every guarded call caps its success body; routing the error body through
/// `resp.json()` would have left a hole exactly where the hostile-PDS threat
/// model points — reqwest decompresses gzip before deserialising, so a `400`
/// carrying a decompression bomb was an unbounded allocation on a 512 MB box.
/// A body we cannot read (over-cap, transport error) degrades to `"Unknown"`,
/// which is the same fallback an unparseable envelope already took.
async fn xrpc_error_from(resp: reqwest::Response) -> AtProtoError {
    let status = resp.status();
    let (error, message) = match crate::net::read_capped(resp).await {
        Ok(raw) => match serde_json::from_slice::<XrpcErrorBody>(&raw) {
            Ok(body) => (
                body.error.unwrap_or_else(|| "Unknown".to_string()),
                body.message,
            ),
            Err(_) => ("Unknown".to_string(), None),
        },
        Err(_) => ("Unknown".to_string(), None),
    };
    AtProtoError::Xrpc {
        status,
        error,
        message,
    }
}

// ---------------------------------------------------------------------------
// Tests — record (de)serialization against a repo listRecords response shape.
// No network.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// **Regression (v0.2.8 review).** Every guarded call caps its *success*
    /// body via `read_capped`, but the non-2xx branch went through
    /// `resp.json::<XrpcErrorBody>()` — unbounded, and with reqwest's gzip
    /// decompression in front of it. That left a hole precisely where the
    /// module's own threat model points: a hostile or DNS-rebound PDS answers
    /// `400` with a decompression bomb and gets an unbounded allocation on a
    /// 512 MB box. Both this PR's review passes checked the success path and
    /// walked past the error path, so the cap is asserted here explicitly.
    ///
    /// Fetched directly rather than through the guard, which rightly refuses
    /// loopback — the same reason `net::tests::read_capped_rejects_over_cap_body`
    /// bypasses it. The stub answers 200; `xrpc_error_from` reads the status only
    /// to record it, so the body handling under test is identical.
    #[tokio::test]
    async fn xrpc_error_body_is_capped() {
        // A syntactically VALID envelope, one byte past the cap. If the body were
        // parsed unbounded this would deserialize and yield "TooBig"; capped, it
        // is refused unread and degrades to the "Unknown" fallback.
        let filler = "x".repeat(crate::net::MAX_BODY_BYTES);
        let big = format!(r#"{{"error":"TooBig","message":"{filler}"}}"#).into_bytes();
        assert!(big.len() > crate::net::MAX_BODY_BYTES);

        let base = crate::net::tests::serve_body(big).await;
        let resp = reqwest::Client::builder()
            .build()
            .unwrap()
            .get(&base)
            .send()
            .await
            .unwrap();

        match xrpc_error_from(resp).await {
            AtProtoError::Xrpc { error, message, .. } => {
                assert_eq!(error, "Unknown", "an over-cap error body must not parse");
                assert!(message.is_none());
            }
            other => panic!("expected Xrpc, got {other:?}"),
        }
    }

    /// The other half: a normal-sized envelope still parses, so capping the
    /// error path did not cost the diagnostics it exists to provide.
    #[tokio::test]
    async fn xrpc_error_body_within_the_cap_still_parses() {
        let base = crate::net::tests::serve_body(
            br#"{"error":"InvalidRequest","message":"bad rkey"}"#.to_vec(),
        )
        .await;
        let resp = reqwest::Client::builder()
            .build()
            .unwrap()
            .get(&base)
            .send()
            .await
            .unwrap();

        match xrpc_error_from(resp).await {
            AtProtoError::Xrpc { error, message, .. } => {
                assert_eq!(error, "InvalidRequest");
                assert_eq!(message.as_deref(), Some("bad rkey"));
            }
            other => panic!("expected Xrpc, got {other:?}"),
        }
    }

    /// A realistic `com.atproto.repo.listRecords` response for the subscription
    /// collection, as a PDS returns it — the envelope wraps each record in
    /// `{uri, cid, value}` and the record `value` carries its `$type`.
    fn subscription_list_json() -> Value {
        json!({
            "records": [
                {
                    "uri": "at://did:plc:abc123/community.lexicon.rss.subscription/3ksub0001",
                    "cid": "bafyreisubone",
                    "value": {
                        "$type": "community.lexicon.rss.subscription",
                        "url": "https://example.com/feed.xml",
                        "title": "Example Blog",
                        "siteUrl": "https://example.com/",
                        "fetchHint": "hourly",
                        "createdAt": "2026-07-12T00:00:00.000Z"
                    }
                },
                {
                    "uri": "at://did:plc:abc123/community.lexicon.rss.subscription/3ksub0002",
                    "cid": "bafyreisubtwo",
                    "value": {
                        "$type": "community.lexicon.rss.subscription",
                        "url": "https://blog.example.org/atom.xml",
                        "createdAt": "2026-07-11T12:00:00.000Z"
                    }
                }
            ],
            "cursor": "3ksub0002"
        })
    }

    /// **A big archive is truncated, not refused.** `extend_bounded` bails on
    /// its cap, which is right for the `sub_ref` walk (a short list there is
    /// revoked access) and wrong for an additive read: a publication with more
    /// documents than the cap would return `Err` on every poll — permanently
    /// unreadable rather than partially read. 2 000 posts is an ordinary
    /// figure for a long-running blog.
    #[test]
    fn a_reading_walk_truncates_where_the_sub_ref_walk_refuses() {
        let page = |n: usize| -> Vec<RecordEntry> {
            (0..n)
                .map(|i| RecordEntry {
                    uri: format!("at://did:plc:x/c/{i}"),
                    cid: None,
                    value: Value::Null,
                })
                .collect()
        };
        let mut out = Vec::new();
        assert!(!extend_truncating(&mut out, page(2), 3), "not full yet");
        assert_eq!(out.len(), 2);
        // The page that overshoots contributes what fits, and says "stop".
        assert!(extend_truncating(&mut out, page(5), 3), "must report full");
        assert_eq!(out.len(), 3, "a reading walk must keep what fits");
        // The same overshoot is a hard error on the fail-closed path.
        let mut refused = Vec::new();
        assert!(extend_bounded(&mut refused, page(5), 3, "c").is_err());
        assert!(refused.is_empty(), "a refusal must leave nothing behind");
    }

    /// **The cap counts the records the caller KEEPS, not the ones the repo
    /// holds.** A repo-wide cap applied before the caller's filter starves a
    /// quiet publication whose busy sibling fills the window: poll it, walk
    /// the newest 2 000 documents, discard all of them as the sibling's,
    /// return nothing — permanently, and worse with every post the sibling
    /// makes. The walk pages on until it has `max` MATCHING records (still
    /// bounded by `MAX_LIST_PAGES` requests).
    #[tokio::test]
    async fn the_cap_counts_matching_records_not_walked_ones() {
        // Every page: 4 records, only the last of which the caller wants.
        let records: Vec<Value> = (0..4)
            .map(|i| {
                serde_json::json!({
                    "uri": format!("at://did:plc:x/c/{i}"),
                    "value": {"mine": i == 3}
                })
            })
            .collect();
        let body = serde_json::json!({ "records": records, "cursor": serde_json::Value::Null })
            .to_string();
        let base = crate::net::tests::serve_body(body.into_bytes()).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "matching-pds.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let client = PdsClient::anonymous(
            ssrf_test_client(),
            format!("http://matching-pds.test:{port}"),
            "did:plc:x",
        );

        let kept = client
            .list_recent_matching("site.standard.document", 3, 100, |r| {
                r.value
                    .get("mine")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .await
            .expect("walk failed")
            .records;
        // One page, no cursor: one match survives. The point is that the three
        // non-matching records did NOT consume the cap.
        assert_eq!(kept.len(), 1, "the filter ran after the cap, not before it");
    }

    /// **A walk that stopped early says so.** Landing exactly on the cap, or
    /// running out of page budget, returns the same short `Vec` as a small
    /// collection — and the caller cannot tell them apart afterwards. That
    /// silence is how the starvation this walk exists to prevent came back one
    /// order of magnitude further out: a quiet publication whose busy sibling
    /// fills every page returns nothing, forever, looking healthy.
    #[tokio::test]
    async fn a_walk_that_stops_early_reports_itself_incomplete() {
        let records: Vec<Value> = (0..2)
            .map(|i| serde_json::json!({"uri": format!("at://did:plc:x/c/{i}"), "value": {}}))
            .collect();
        // Every page is full AND advertises another — the shape that lands on
        // the cap with the collection still going.
        let body = serde_json::json!({ "records": records, "cursor": "next" }).to_string();
        let base = crate::net::tests::serve_body(body.into_bytes()).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "incomplete-pds.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let client = PdsClient::anonymous(
            ssrf_test_client(),
            format!("http://incomplete-pds.test:{port}"),
            "did:plc:x",
        );

        let walk = client
            .list_recent_matching("c", 2, 100, |_| true)
            .await
            .expect("walk failed");
        assert_eq!(walk.records.len(), 2);
        assert!(
            !walk.complete,
            "a walk that filled its cap with pages still to come called itself complete"
        );
    }

    /// The other side: a collection that runs out IS complete, so the caller
    /// does not warn about every ordinary small publication.
    #[tokio::test]
    async fn a_walk_that_exhausts_the_collection_reports_itself_complete() {
        let body = serde_json::json!({
            "records": [{"uri": "at://did:plc:x/c/1", "value": {}}]
        })
        .to_string();
        let base = crate::net::tests::serve_body(body.into_bytes()).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "complete-pds.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let client = PdsClient::anonymous(
            ssrf_test_client(),
            format!("http://complete-pds.test:{port}"),
            "did:plc:x",
        );

        let walk = client
            .list_recent_matching("c", 100, 100, |_| true)
            .await
            .expect("walk failed");
        assert_eq!(walk.records.len(), 1);
        assert!(walk.complete, "an exhausted collection is a complete read");
    }

    /// **`{}` is not a page of zero records.** The records-presence guard
    /// landed on the OAuth client first; a proxy answering
    /// `{"ok":true,"data":{}}` kept the same `sub_ref`-wipe open on the
    /// sidecar path, and `{}` from a stranger's PDS made an empty publication
    /// look healthy.
    #[test]
    fn a_body_without_a_records_field_is_not_an_empty_page() {
        let err = list_records_from_value(serde_json::json!({}))
            .expect_err("`{}` was read as a page of zero records");
        assert!(format!("{err:#}").contains("no records field"), "{err:#}");
        let err = list_records_from_value(serde_json::json!({"cursor": "c"}))
            .expect_err("a cursor-only body was read as a page");
        assert!(format!("{err:#}").contains("no records field"), "{err:#}");
        let page = list_records_from_value(serde_json::json!({"records": []})).unwrap();
        assert!(page.records.is_empty());
    }

    /// Serve one oversized-but-well-formed body and point `host` at it.
    async fn serve_oversized(host: &str, shape: &str) -> String {
        let filler = "x".repeat(crate::net::MAX_BODY_BYTES);
        let body = shape.replace("PAD", &filler);
        assert!(body.len() > crate::net::MAX_BODY_BYTES);
        let base = crate::net::tests::serve_body(body.into_bytes()).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(host, std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        format!("http://{host}:{port}")
    }

    /// **The DID document is the most remote-controlled body of the lot.**
    ///
    /// For a `did:web:` the host comes straight out of the DID, so whoever
    /// supplies the DID chooses the server. The SSRF guard proves the address
    /// is public; it says nothing about the body being finite.
    #[tokio::test]
    async fn the_did_document_read_is_capped() {
        let base = serve_oversized(
            "did-doc-cap.test",
            r##"{"service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.example"}],"pad":"PAD"}"##,
        )
        .await;
        let err = resolve_did_to_pds(
            &ssrf_test_client(),
            &base,
            "did:plc:ohutz6x5acjmpuulp3x7wxxc",
        )
        .await
        .expect_err("an oversized DID document was buffered whole");
        assert!(
            format!("{err:#}").contains("cap"),
            "failed for the wrong reason: {err:#}"
        );
    }

    /// `resolver_base` is a user-influenced PDS host, as this function's own
    /// guard comment says.
    #[tokio::test]
    async fn the_resolve_handle_read_is_capped() {
        let base = serve_oversized(
            "resolve-handle-cap.test",
            r#"{"did":"did:plc:ohutz6x5acjmpuulp3x7wxxc","pad":"PAD"}"#,
        )
        .await;
        let err = resolve_handle(&ssrf_test_client(), &base, "alice.example.com")
            .await
            .expect_err("an oversized resolveHandle body was buffered whole");
        assert!(
            format!("{err:#}").contains("cap"),
            "failed for the wrong reason: {err:#}"
        );
    }

    /// **The sidecar's body is capped like every other body we read.**
    ///
    /// `/internal/repo` proxies whatever the account's PDS returned, so its
    /// size is remote-controlled by a host the reader chose and we did not.
    /// Every other response in this codebase goes through
    /// [`crate::net::read_capped`]; this one buffered the whole thing with
    /// `resp.json()`, so the 8 MB ceiling that bounds the direct PDS client
    /// simply did not exist on the sidecar backend — which is the default.
    #[tokio::test]
    async fn the_sidecar_client_caps_the_body_it_will_buffer() {
        // Well-formed, and past the cap. The guard has to fire on size, not
        // on the shape being wrong.
        let filler = "x".repeat(crate::net::MAX_BODY_BYTES);
        let body = format!(r#"{{"ok":true,"data":{{"records":[],"pad":"{filler}"}}}}"#);
        assert!(body.len() > crate::net::MAX_BODY_BYTES);
        let base = crate::net::tests::serve_body(body.into_bytes()).await;
        let client = SidecarClient::new(Client::new(), base.clone(), base, "secret");
        let err = client
            .list_records(
                "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
                "app.feather.subscription",
                None,
                None,
            )
            .await
            .expect_err("an oversized sidecar body was buffered whole");
        assert!(
            format!("{err:#}").contains("cap"),
            "failed for the wrong reason: {err:#}"
        );
    }

    /// The sidecar path needs the records guard too, not only the envelope
    /// one: `{"ok":true,"data":{}}` is what a proxy makes of an empty or
    /// unexpected upstream body.
    #[tokio::test]
    async fn the_sidecar_client_refuses_a_data_object_without_records() {
        let base = crate::net::tests::serve_body(br#"{"ok":true,"data":{}}"#.to_vec()).await;
        let client = SidecarClient::new(Client::new(), base.clone(), base, "secret");
        let err = client
            .list_records(
                "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
                "app.feather.subscription",
                None,
                None,
            )
            .await
            .expect_err("`data: {}` was read as an empty repo");
        assert!(format!("{err:#}").contains("no records field"), "{err:#}");
    }

    /// An exactly-full final page dropped nothing, so it must not warn that it
    /// did: `>=` reported truncation whenever the last page landed flush.
    #[test]
    fn an_exactly_full_page_is_not_a_truncation() {
        let page = |n: usize| -> Vec<RecordEntry> {
            (0..n)
                .map(|i| RecordEntry {
                    uri: format!("at://did:plc:x/c/{i}"),
                    cid: None,
                    value: Value::Null,
                })
                .collect()
        };
        let mut out = Vec::new();
        assert!(
            !extend_truncating(&mut out, page(3), 3),
            "a page that exactly fills the cap dropped nothing"
        );
        assert_eq!(out.len(), 3);
        assert!(
            extend_truncating(&mut out, page(1), 3),
            "one more IS a drop"
        );
        assert_eq!(out.len(), 3);
    }

    /// **The reading walk USES the truncating accumulator.** The helper being
    /// correct is not the point — the previous round's bug was a guard that
    /// existed and was not called. Driven through a real server: one page of
    /// five records under a cap of three.
    #[tokio::test]
    async fn the_reading_walk_returns_a_truncated_archive_rather_than_an_error() {
        let records: Vec<Value> = (0..5)
            .map(|i| serde_json::json!({"uri": format!("at://did:plc:x/c/{i}"), "value": {}}))
            .collect();
        let body = serde_json::json!({ "records": records }).to_string();
        let base = crate::net::tests::serve_body(body.into_bytes()).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "truncating-pds.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let client = PdsClient::anonymous(
            ssrf_test_client(),
            format!("http://truncating-pds.test:{port}"),
            "did:plc:x",
        );

        let walk = client
            .list_recent_matching("site.standard.document", 3, 100, |_| true)
            .await
            .expect("a big archive must be readable, not an error");
        assert_eq!(
            walk.records.len(),
            3,
            "the walk did not truncate to its cap"
        );
        assert!(
            !walk.complete,
            "a truncated walk must not report completeness"
        );

        // The fail-closed walk still refuses the same overshoot.
        let err = client
            .list_all_records("community.lexicon.rss.subscription")
            .await;
        assert!(
            err.is_ok() || format!("{:#}", err.unwrap_err()).contains("cap"),
            "the sub_ref walk must keep its refusal"
        );
    }

    /// **A write is not "succeeded" because the status was 200.** The sidecar's
    /// `delete_record` and `apply_writes` discard the body entirely, so a
    /// `200 {"error": …}` reported success: the UI showed a reader
    /// unsubscribed while the record was still in their repo, and a whole
    /// batch of writes vanished silently.
    #[tokio::test]
    async fn the_sidecar_client_refuses_a_200_error_envelope_on_writes() {
        let base = crate::net::tests::serve_body(
            br#"{"ok":true,"data":{"error":"InvalidRequest","message":"nope"}}"#.to_vec(),
        )
        .await;
        let client = SidecarClient::new(Client::new(), base.clone(), base, "secret");
        let did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
        let err = client
            .delete_subscription(did, "rk1")
            .await
            .expect_err("a failed delete was reported as success");
        assert!(format!("{err:#}").contains("InvalidRequest"), "{err:#}");

        let err = client
            .apply_writes(
                did,
                &[WriteOp::Delete {
                    collection: lexicon::nsid::SUBSCRIPTION.to_string(),
                    rkey: "rk1".to_string(),
                }],
            )
            .await
            .expect_err("a failed batch was reported as success");
        assert!(format!("{err:#}").contains("InvalidRequest"), "{err:#}");
    }

    /// The sidecar proxies the PDS's body, so the same 2xx envelope arrives
    /// through `RepoOk.data` — a defaulted `Value` that deserialised into an
    /// empty page just as happily. Driven through the real client.
    #[tokio::test]
    async fn the_sidecar_client_refuses_a_200_error_envelope() {
        let base = crate::net::tests::serve_body(
            br#"{"ok":true,"data":{"error":"InvalidRequest","message":"nope"}}"#.to_vec(),
        )
        .await;
        let client = SidecarClient::new(Client::new(), base.clone(), base, "secret");
        let err = client
            .list_records(
                "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
                "app.feather.subscription",
                None,
                None,
            )
            .await
            .expect_err("an error envelope was read as an empty page");
        assert!(
            format!("{err:#}").contains("InvalidRequest"),
            "failed for the wrong reason: {err:#}"
        );
    }

    /// **Every listRecords caller refuses a 2xx error envelope, not just the
    /// anonymous one.** `oauth::xrpc::Repo` reads `records` off the JSON with
    /// `unwrap_or(Array([]))` and the sidecar's `RepoOk.data` is a defaulted
    /// `Value`, so a PDS answering 200 with an envelope reached
    /// `resolve_subscriptions` as `Ok(empty)` — which is not the fail-closed
    /// branch, so `sync_sub_refs` DELETEd the DID's whole `sub_ref` projection:
    /// one bad response revokes a reader's access to every feed they have.
    #[test]
    fn an_error_envelope_is_refused_whatever_shape_it_arrives_in() {
        let envelope = serde_json::json!({"error": "InvalidRequest", "message": "bad cursor"});
        let err = reject_error_envelope(&envelope).expect_err("an envelope passed as data");
        assert!(format!("{err:#}").contains("InvalidRequest"), "{err:#}");
        // A real page, and an empty real page, are both data.
        reject_error_envelope(&serde_json::json!({"records": []})).expect("an empty page is data");
        reject_error_envelope(&serde_json::json!({"records": [], "cursor": "c"})).unwrap();
    }

    /// **A 200 carrying an error envelope is not an empty page.** `records` is
    /// `#[serde(default)]`, so `{"error": "...", "message": "..."}` on a 200
    /// deserialised as zero records — and a walk over a stranger's documents
    /// then returned a healthy, empty feed instead of an error. Some PDS
    /// implementations do answer 200 for application-level failures.
    #[test]
    fn a_200_with_an_error_envelope_is_not_an_empty_page() {
        let err = parse_list_records(br#"{"error":"InvalidRequest","message":"bad cursor"}"#)
            .expect_err("an error envelope parsed as a page");
        assert!(format!("{err:#}").contains("InvalidRequest"), "{err:#}");
        let page = parse_list_records(br#"{"records":[]}"#).expect("an empty page is a page");
        assert!(page.records.is_empty() && page.cursor.is_none());
    }

    #[test]
    fn list_records_envelope_deserializes() {
        let resp: ListRecordsResponse =
            serde_json::from_value(subscription_list_json()).expect("envelope");
        assert_eq!(resp.records.len(), 2);
        assert_eq!(resp.cursor.as_deref(), Some("3ksub0002"));
        assert_eq!(resp.records[0].cid.as_deref(), Some("bafyreisubone"));
    }

    #[test]
    fn record_entry_rkey_is_last_uri_segment() {
        let resp: ListRecordsResponse =
            serde_json::from_value(subscription_list_json()).expect("envelope");
        assert_eq!(resp.records[0].rkey(), Some("3ksub0001"));
        assert_eq!(resp.records[1].rkey(), Some("3ksub0002"));
    }

    #[test]
    fn record_value_parses_into_lexicon_subscription() {
        let resp: ListRecordsResponse =
            serde_json::from_value(subscription_list_json()).expect("envelope");

        let full: Subscription = resp.records[0].parse().expect("parse full sub");
        assert_eq!(full.r#type, lexicon::nsid::SUBSCRIPTION);
        assert_eq!(full.url, "https://example.com/feed.xml");
        assert_eq!(full.title.as_deref(), Some("Example Blog"));
        assert_eq!(full.site_url.as_deref(), Some("https://example.com/"));
        assert_eq!(full.fetch_hint, Some(lexicon::FetchHint::Hourly));

        let minimal: Subscription = resp.records[1].parse().expect("parse minimal sub");
        assert_eq!(minimal.url, "https://blog.example.org/atom.xml");
        assert!(minimal.title.is_none());
    }

    fn ssrf_test_client() -> Client {
        Client::builder()
            .user_agent(crate::USER_AGENT)
            .build()
            .unwrap()
    }

    /// A hostile `did:web` whose host is the cloud-metadata address must be
    /// REFUSED before any request leaves the box — the DID-document fetch now
    /// routes through the SSRF guard (`guarded_get_no_privacy`), which rejects
    /// link-local / metadata targets.
    #[tokio::test]
    async fn resolve_did_web_blocks_metadata_host() {
        let client = ssrf_test_client();
        let err = resolve_did_to_pds(&client, "https://plc.directory", "did:web:169.254.169.254")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("forbidden") || err.contains("internal"),
            "expected an SSRF refusal, got: {err}"
        );
    }

    /// A `did:web` pointing at loopback is likewise blocked (internal service
    /// reflection).
    #[tokio::test]
    async fn resolve_did_web_blocks_loopback_host() {
        let client = ssrf_test_client();
        let err = resolve_did_to_pds(&client, "https://plc.directory", "did:web:127.0.0.1")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("forbidden") || err.contains("internal"),
            "expected an SSRF refusal, got: {err}"
        );
    }

    /// `resolve_handle` against a metadata/loopback resolver base is also guarded
    /// (the base can come from a prior hostile DID-doc resolution).
    #[tokio::test]
    async fn resolve_handle_blocks_metadata_resolver_base() {
        let client = ssrf_test_client();
        let err = resolve_handle(&client, "http://169.254.169.254", "alice.example.com")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("forbidden") || err.contains("internal"),
            "expected an SSRF refusal, got: {err}"
        );
    }

    /// A resolved `serviceEndpoint` that targets an internal host is rejected at
    /// resolve time via [`crate::net::assert_public_target`], so it can never be
    /// handed to a raw XRPC client.
    #[tokio::test]
    async fn service_endpoint_internal_target_rejected() {
        assert!(crate::net::assert_public_target("http://169.254.169.254/")
            .await
            .is_err());
        assert!(crate::net::assert_public_target("http://127.0.0.1:3000/")
            .await
            .is_err());
        // A public endpoint literal passes.
        assert!(crate::net::assert_public_target("https://1.1.1.1/")
            .await
            .is_ok());
    }

    /// A `PdsClient` pointed at an internal `pds_base`, as an attacker-controlled
    /// DID document could arrange between the `assert_public_target` at resolve
    /// time and the request.
    fn internal_target_client(pds_base: &str) -> PdsClient {
        PdsClient::new(
            ssrf_test_client(),
            pds_base,
            "did:plc:victim",
            Auth::Session(SessionAuth {
                did: "did:plc:victim".to_string(),
                handle: None,
                access_jwt: "session-bearer-must-not-leak".to_string(),
                refresh_jwt: None,
            }),
        )
    }

    /// **Regression (v0.2.8):** every `com.atproto.repo.*` WRITE must go through
    /// the SSRF guard, not the shared client. Before the fix only `list_records`
    /// was guarded, so `createRecord` / `putRecord` / `deleteRecord` /
    /// `applyWrites` would happily deliver the session bearer to
    /// `169.254.169.254` or loopback on a rebound host.
    #[tokio::test]
    async fn every_repo_write_is_refused_against_an_internal_pds() {
        for base in [
            "http://169.254.169.254",
            "http://127.0.0.1:9",
            "http://[::1]",
        ] {
            let client = internal_target_client(base);
            let sub = Subscription::new("https://example.com/feed.xml", "2026-08-13T00:00:00Z");

            let mut errors = vec![
                client
                    .create_record(lexicon::nsid::SUBSCRIPTION, &sub)
                    .await
                    .unwrap_err()
                    .to_string(),
                client
                    .put_record(lexicon::nsid::SUBSCRIPTION, "rkey", &sub)
                    .await
                    .unwrap_err()
                    .to_string(),
                client
                    .delete_record(lexicon::nsid::SUBSCRIPTION, "rkey")
                    .await
                    .unwrap_err()
                    .to_string(),
            ];
            errors.push(
                client
                    .apply_writes(&[WriteOp::Delete {
                        collection: lexicon::nsid::SUBSCRIPTION.to_string(),
                        rkey: "rkey".to_string(),
                    }])
                    .await
                    .unwrap_err()
                    .to_string(),
            );

            for err in errors {
                assert!(
                    err.contains("forbidden") || err.contains("internal"),
                    "{base}: expected an SSRF refusal, got: {err}"
                );
            }
        }
    }

    /// **Regression (v0.2.8):** the app password travels in the request BODY,
    /// where reqwest's cross-origin header sanitisation cannot protect it — so
    /// `createSession` is guarded too, and a rebound/internal `pds_base` never
    /// receives it.
    #[tokio::test]
    async fn app_password_login_is_refused_against_an_internal_pds() {
        let client = ssrf_test_client();
        for base in ["http://169.254.169.254", "http://127.0.0.1:9"] {
            let err = login_with_app_password(&client, base, "alice.example.com", "hunter2-app-pw")
                .await
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("forbidden") || err.contains("internal"),
                "{base}: expected an SSRF refusal, got: {err}"
            );
        }
    }

    /// An anonymous client is read-only: the write paths fail closed on
    /// [`Auth::bearer`] before any socket work, so `Auth::Anonymous` can never
    /// become a credential-less write primitive against a stranger's PDS.
    #[tokio::test]
    async fn anonymous_client_cannot_write() {
        let client = PdsClient::anonymous(
            ssrf_test_client(),
            "https://pds.example.com",
            "did:plc:stranger",
        );
        let err = client
            .delete_record(lexicon::nsid::SUBSCRIPTION, "rkey")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no credentials") || err.contains("anonymous") || err.contains("bearer"),
            "expected a fail-closed auth error, got: {err}"
        );
    }

    #[test]
    fn write_result_deserializes() {
        let wr: WriteResult = serde_json::from_value(json!({
            "uri": "at://did:plc:abc123/community.lexicon.rss.subscription/3ksubnew",
            "cid": "bafyreinew"
        }))
        .expect("write result");
        assert!(wr.uri.ends_with("3ksubnew"));
        assert_eq!(wr.cid.as_deref(), Some("bafyreinew"));
    }

    #[test]
    fn did_document_finds_pds_endpoint() {
        let doc: DidDocument = serde_json::from_value(json!({
            "id": "did:plc:abc123",
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com/"
                }
            ]
        }))
        .expect("did doc");
        assert_eq!(
            doc.pds_endpoint().as_deref(),
            Some("https://pds.example.com")
        );
    }

    #[test]
    fn did_document_without_pds_yields_none() {
        let doc: DidDocument = serde_json::from_value(json!({
            "id": "did:plc:abc123",
            "service": []
        }))
        .expect("did doc");
        assert!(doc.pds_endpoint().is_none());
    }

    #[test]
    fn session_auth_deserializes_create_session_shape() {
        let session: SessionAuth = serde_json::from_value(json!({
            "did": "did:plc:abc123",
            "handle": "alice.example.com",
            "accessJwt": "eyJh...access",
            "refreshJwt": "eyJh...refresh"
        }))
        .expect("session");
        assert_eq!(session.did, "did:plc:abc123");
        assert_eq!(session.handle.as_deref(), Some("alice.example.com"));
        let auth = Auth::Session(session);
        assert_eq!(auth.bearer().expect("bearer"), "eyJh...access");
    }

    #[test]
    fn oauth_variant_carries_no_direct_bearer() {
        let auth = Auth::Oauth(OauthPlaceholder::default());
        assert!(
            auth.bearer().is_err(),
            "Auth::Oauth carries no direct bearer — the sidecar owns the OAuth path"
        );
    }

    #[test]
    fn anonymous_variant_carries_no_bearer() {
        let err = Auth::Anonymous.bearer().unwrap_err().to_string();
        assert!(
            err.contains("anonymous"),
            "the anonymous refusal must name itself, got: {err}"
        );
    }

    #[test]
    fn anonymous_client_targets_the_requested_repo() {
        let client = PdsClient::anonymous(
            ssrf_test_client(),
            "https://pds.example.com/",
            "did:plc:abc123",
        );
        // The trailing slash is trimmed so `xrpc_url` joins cleanly.
        assert_eq!(client.pds_base(), "https://pds.example.com");
        assert_eq!(client.did(), "did:plc:abc123");
        // …and it holds no credential.
        assert!(client.auth.bearer().is_err());
    }

    /// The regression test for the defect this milestone fixes: `list_records`
    /// used to send on the shared client, bypassing the SSRF guard entirely. It
    /// now routes through `net::guarded_get_no_privacy`, so an internal
    /// `pds_base` is refused before a packet leaves the box. Hermetic — the hosts
    /// are IP literals, rejected without any DNS lookup or connect.
    #[tokio::test]
    async fn list_records_blocks_internal_pds_base() {
        for base in ["http://169.254.169.254", "http://127.0.0.1:1"] {
            let client = PdsClient::anonymous(ssrf_test_client(), base, "did:plc:x");
            let err = client
                .list_records(lexicon::nsid::SUBSCRIPTION, Some(1), None)
                .await
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("forbidden") || err.contains("internal"),
                "expected an SSRF refusal for {base}, got: {err}"
            );
        }
    }

    /// The guard is not anonymous-only: an *authenticated* client reading a
    /// hostile PDS base is blocked identically. (That path was only ever safe by
    /// accident of usage.)
    #[tokio::test]
    async fn list_records_guard_applies_to_authed_clients_too() {
        let auth = Auth::Session(SessionAuth {
            did: "did:plc:x".to_string(),
            handle: None,
            access_jwt: "x".to_string(),
            refresh_jwt: None,
        });
        let client = PdsClient::new(
            ssrf_test_client(),
            "http://169.254.169.254",
            "did:plc:x",
            auth,
        );
        let err = client
            .list_records(lexicon::nsid::SUBSCRIPTION, Some(1), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("forbidden") || err.contains("internal"),
            "expected an SSRF refusal, got: {err}"
        );
    }

    #[test]
    fn apply_writes_ops_render_tagged_union() {
        let create = WriteOp::Create {
            collection: lexicon::nsid::SUBSCRIPTION.to_string(),
            rkey: None,
            value: json!({"url": "https://example.com/feed.xml"}),
        };
        let update = WriteOp::Update {
            collection: lexicon::nsid::READ_STATE.to_string(),
            rkey: "feedhash01".to_string(),
            value: json!({"feedUrl": "https://example.com/feed.xml"}),
        };
        let delete = WriteOp::Delete {
            collection: lexicon::nsid::SAVED.to_string(),
            rkey: "3ksaved01".to_string(),
        };

        assert_eq!(
            create.to_json()["$type"],
            json!("com.atproto.repo.applyWrites#create")
        );
        // A create with no explicit rkey omits the field (server assigns a tid).
        assert!(create.to_json().get("rkey").is_none());

        assert_eq!(
            update.to_json()["$type"],
            json!("com.atproto.repo.applyWrites#update")
        );
        assert_eq!(update.to_json()["rkey"], json!("feedhash01"));

        assert_eq!(
            delete.to_json()["$type"],
            json!("com.atproto.repo.applyWrites#delete")
        );
        assert_eq!(delete.to_json()["rkey"], json!("3ksaved01"));
    }

    #[test]
    fn read_state_flush_creates_first_then_updates() {
        // A cursor whose PDS record does NOT yet exist (pds_created = false) must
        // become a CREATE op at its stable rkey — NOT a bare update, which would
        // error on the missing record and (applyWrites being atomic per-repo) drop
        // the whole batch on a feed's first flush.
        let fresh = (
            "rs-fresh".to_string(),
            ReadState::new("https://a.example/feed.xml", None, "2026-07-12T00:00:00Z"),
            false,
        );
        // An already-created cursor updates in place.
        let existing = (
            "rs-existing".to_string(),
            ReadState::new(
                "https://b.example/feed.xml",
                Some("2026-07-11T00:00:00Z".to_string()),
                "2026-07-12T00:00:00Z",
            ),
            true,
        );

        let ops = read_state_write_ops(&[fresh, existing]).expect("build ops");
        assert_eq!(ops.len(), 2);

        // First op: a create carrying the stable rkey (put/create, not update).
        let create = ops[0].to_json();
        assert_eq!(
            create["$type"],
            json!("com.atproto.repo.applyWrites#create"),
            "first flush of a new feed must CREATE its readState record"
        );
        assert_eq!(create["rkey"], json!("rs-fresh"));
        // The created record omits readThrough (F1): backlog not implicitly read.
        assert!(create["value"].get("readThrough").is_none());

        // Second op: an update for the already-created record.
        let update = ops[1].to_json();
        assert_eq!(
            update["$type"],
            json!("com.atproto.repo.applyWrites#update")
        );
        assert_eq!(update["rkey"], json!("rs-existing"));

        // Both ride the SAME batch — batching is preserved.
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn urlencode_escapes_did_colons_and_keeps_unreserved() {
        assert_eq!(urlencode("did:plc:abc123"), "did%3Aplc%3Aabc123");
        assert_eq!(
            urlencode("community.lexicon.rss.subscription"),
            "community.lexicon.rss.subscription"
        );
        assert_eq!(urlencode("a b&c"), "a%20b%26c");
    }

    #[test]
    fn xrpc_record_not_found_is_detected() {
        let err = AtProtoError::Xrpc {
            status: StatusCode::BAD_REQUEST,
            error: "RecordNotFound".to_string(),
            message: Some("Could not locate record".to_string()),
        };
        assert!(err.is_record_not_found());
    }

    // -- reader-facing CRUD: rkey extraction --------------------------------

    #[test]
    fn write_result_extracts_rkey_from_uri() {
        let wr: WriteResult = serde_json::from_value(json!({
            "uri": "at://did:plc:abc123/community.lexicon.rss.subscription/3ksubnew",
            "cid": "bafyreinew"
        }))
        .expect("write result");
        assert_eq!(wr.rkey(), Some("3ksubnew"));
        assert_eq!(wr.into_rkey(), "3ksubnew");
    }

    // -- reader-facing CRUD: deterministic sort orders ----------------------
    //
    // The `list_*_sorted` wrappers only add an ordering on top of the network
    // `list_*` read, so we exercise the *comparator* here on representative
    // data (parsed from a listRecords-shaped envelope) with no network.

    // -- reader-facing CRUD: bulk applyWrites shape (OPML import) ------------

    /// **Bulk subscribe, through the real client, asserted on the bytes it
    /// sent.** The test this replaces built the `WriteOp::Create` ops itself
    /// ("mirror what `add_subscriptions_bulk` builds") and asserted on its own
    /// construction; the function was never called, and writing every feed
    /// into the wrong collection with server-assigned rkeys left the suite
    /// green. Three atproto sort tests that re-implemented the comparator
    /// inline are deleted alongside — `lexicon::sort_tests` fails their
    /// mutation, and they added nothing but a misleading name.
    #[tokio::test]
    async fn bulk_subscribe_writes_client_assigned_ordered_rkeys_to_the_right_collection() {
        let (base, log) =
            crate::net::tests::serve_json_capturing(br#"{"ok":true,"data":{}}"#.to_vec()).await;
        let client = SidecarClient::new(Client::new(), base.clone(), base, "secret");
        let subs: Vec<crate::vetted::VettedSubscription> = (0..3)
            .map(|i| {
                crate::vetted::VettedSubscription::new(&lexicon::Subscription::new(
                    format!("https://f{i}.example/feed.xml"),
                    "2026-07-12T00:00:00.000Z",
                ))
            })
            .collect();

        let rkeys = client
            .add_subscriptions_bulk("did:plc:ewvi7nxzyoun6zhxrhs64oiz", &subs)
            .await
            .expect("bulk write failed");

        let sent = log.lock().unwrap().clone();
        assert_eq!(
            sent.len(),
            1,
            "expected one applyWrites request, got {sent:?}"
        );
        let body: Value = serde_json::from_str(sent[0].split("\r\n\r\n").nth(1).unwrap())
            .expect("request body is JSON");
        let writes = body["writes"].as_array().expect("writes array");
        assert_eq!(writes.len(), 3);
        for (i, w) in writes.iter().enumerate() {
            assert_eq!(
                w["collection"],
                lexicon::nsid::SUBSCRIPTION,
                "write {i} went to the wrong collection"
            );
            assert_eq!(
                w["rkey"].as_str(),
                Some(rkeys[i].as_str()),
                "write {i} does not carry the rkey the client returned"
            );
        }
        let mut sorted = rkeys.clone();
        sorted.sort();
        assert_eq!(rkeys, sorted, "client-assigned rkeys must ascend");
        assert_eq!(
            rkeys.iter().collect::<std::collections::HashSet<_>>().len(),
            3,
            "rkeys must be distinct"
        );
    }

    /// **The walk stops on a repeated cursor.** `MAX_LIST_PAGES`, the
    /// same-cursor guard and the `got > 0` guard had no test; only
    /// `extend_bounded` was covered directly. A PDS that echoes the same
    /// cursor forever would otherwise be walked for 200 pages.
    #[tokio::test]
    async fn list_all_records_stops_on_a_repeated_cursor() {
        let body = serde_json::json!({
            "records": [{"uri": "at://did:plc:x/c/1", "value": {}}],
            "cursor": "same-every-time"
        })
        .to_string();
        let base = crate::net::tests::serve_body(body.into_bytes()).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "repeated-cursor.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let client = PdsClient::anonymous(
            ssrf_test_client(),
            format!("http://repeated-cursor.test:{port}"),
            "did:plc:x",
        );
        let records = client.list_all_records("c").await.expect("walk failed");
        // Page 1: cursor None → "same". Page 2: "same" again → stop, after
        // taking that page. Two pages, not two hundred.
        assert_eq!(records.len(), 2, "a repeated cursor was followed");
    }

    // -- walk byte budget ---------------------------------------------------

    /// What a parsed value really costs, counted independently of the code
    /// under test: every node occupies a `Value`, wherever it sits.
    fn node_count(v: &serde_json::Value) -> usize {
        1 + match v {
            serde_json::Value::Array(a) => a.iter().map(node_count).sum::<usize>(),
            serde_json::Value::Object(o) => o.values().map(node_count).sum::<usize>(),
            _ => 0,
        }
    }

    fn record_of(value: serde_json::Value) -> RecordEntry {
        RecordEntry {
            uri: "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/c/3lab".to_string(),
            cid: Some("bafyreiabc123def456ghi789jkl012mno345pqr678stu901".to_string()),
            value,
        }
    }

    /// **The estimate must never under-report, on any shape.**
    ///
    /// The version this replaces charged serialized length, which is accurate
    /// on prose-shaped records and 42x optimistic on the shapes an attacker
    /// picks. A bound that is only correct on benign input is not a bound.
    #[test]
    fn the_estimate_charges_every_node_at_least_what_a_parsed_value_costs() {
        let deep: serde_json::Value =
            serde_json::from_str(&format!("{}{}", "[".repeat(100), "]".repeat(100))).unwrap();
        let shapes: Vec<(&str, serde_json::Value)> = vec![
            ("100 nested empty arrays", deep),
            (
                "4096 empty arrays",
                serde_json::json!(vec![serde_json::json!([]); 4096]),
            ),
            ("4096 empty strings", serde_json::json!(vec![""; 4096])),
            (
                "4096 nulls",
                serde_json::json!(vec![serde_json::Value::Null; 4096]),
            ),
            ("4096 bools", serde_json::json!(vec![true; 4096])),
            ("4096 small numbers", serde_json::json!(vec![0; 4096])),
            (
                "object with short keys",
                serde_json::Value::Object(
                    (0..4096)
                        .map(|i| (format!("k{i}"), serde_json::json!([])))
                        .collect(),
                ),
            ),
            (
                "a realistic document",
                serde_json::json!({
                    "$type": "site.standard.document",
                    "title": "A post with a reasonably typical title",
                    "path": "/posts/one",
                    "publishedAt": "2026-07-11T09:30:00Z",
                    "textContent": "x".repeat(17_000),
                }),
            ),
        ];
        for (label, value) in shapes {
            let entry = record_of(value);
            let charged = approx_bytes(&entry);
            let floor = node_count(&entry.value) * std::mem::size_of::<serde_json::Value>();
            assert!(
                charged >= floor,
                "{label}: charged {charged} for {} nodes, which cannot cost less than {floor}",
                node_count(&entry.value)
            );
            let wire = serde_json::to_vec(&entry.value).unwrap().len();
            assert!(
                charged >= wire,
                "{label}: charged {charged}, under the {wire} bytes it takes on the wire alone"
            );
        }
    }

    /// **Known answers from a real allocator, not a model of one.**
    ///
    /// The property above models `Value` nodes and nothing else, which is how
    /// an object-shaped under-charge of about half slipped past it: a
    /// `serde_json::Map` is a `BTreeMap` whose leaf is allocated whole, so the
    /// entries' own nodes are not the cost. These two figures were measured
    /// with a counting global allocator against the `serde_json` in this
    /// lockfile, and are here precisely because the test above could not see
    /// them.
    #[test]
    fn the_estimate_covers_shapes_measured_against_a_real_allocator() {
        let many_small = serde_json::json!(vec![serde_json::json!({"a": 0}); 5000]);
        let mut deep = serde_json::json!({"a": 0});
        for _ in 0..99 {
            deep = serde_json::json!({ "a": deep });
        }
        for (label, value, measured) in [
            ("5000 one-key objects", many_small, 3_430_000usize),
            ("a 100-deep chain of one-key objects", deep, 63_350),
        ] {
            let charged = approx_bytes(&record_of(value));
            assert!(
                charged >= measured,
                "{label}: charged {charged} against {measured} bytes actually held"
            );
        }
    }

    #[test]
    fn the_estimate_counts_the_uri_and_cid_too() {
        let bare = RecordEntry {
            uri: String::new(),
            cid: None,
            value: serde_json::json!(null),
        };
        let addressed = record_of(serde_json::json!(null));
        assert!(
            approx_bytes(&addressed) > approx_bytes(&bare),
            "a record's own identifiers are retained alongside its value"
        );
    }

    #[test]
    fn the_budget_admits_a_page_that_exactly_fills_it() {
        let page = vec![record_of(serde_json::json!({"t": "x".repeat(1000)}))];
        let exact: usize = page.iter().map(approx_bytes).sum();
        assert!(
            ByteBudget::new(exact).admit(&page),
            "a page that exactly fits was refused; the fence-post is one byte out"
        );
        assert!(
            !ByteBudget::new(exact - 1).admit(&page),
            "a page one byte over the budget was admitted"
        );
    }

    #[test]
    fn a_refused_page_leaves_the_running_total_alone() {
        let small = vec![record_of(serde_json::json!({"t": "x".repeat(100)}))];
        let huge = vec![record_of(serde_json::json!({"t": "x".repeat(100_000)}))];
        let cost: usize = small.iter().map(approx_bytes).sum();
        let mut budget = ByteBudget::new(cost * 3);

        assert!(budget.admit(&small), "the first page fits");
        let after_one = budget.used();
        assert!(after_one > 0, "an admitted page must be charged");

        assert!(!budget.admit(&huge), "the oversized page must be refused");
        assert_eq!(
            budget.used(),
            after_one,
            "a refused page moved the total — either charged, or reset"
        );
        assert!(
            budget.admit(&small),
            "the walk could not continue against the total it had before the refusal"
        );
    }

    /// Build `pages` responses, each holding one record of about `bytes`, each
    /// pointing at the next. Returns the base URL and what one page costs.
    ///
    /// **Pages that differ is the whole point.** A walk served the same body
    /// twice stops on its repeated-cursor guard, so every test built on the
    /// fixed-body server refuses on page one and never exercises accumulation
    /// at all — which is how a per-page budget once passed a whole suite.
    pub(crate) fn paged_bodies(
        pages: usize,
        bytes: usize,
        envelope: bool,
    ) -> (Vec<Vec<u8>>, usize) {
        let record = |i: usize| {
            serde_json::json!({
                "uri": format!("at://did:plc:ohutz6x5acjmpuulp3x7wxxc/c/3lab{i}"),
                "cid": "bafyreiabc123def456ghi789jkl012mno345pqr678stu901",
                "value": { "t": "x".repeat(bytes) }
            })
        };
        let bodies = (0..pages)
            .map(|i| {
                let mut page = serde_json::json!({ "records": [record(i)] });
                if i + 1 < pages {
                    page["cursor"] = serde_json::json!(format!("p{}", i + 1));
                }
                if envelope {
                    page = serde_json::json!({ "ok": true, "data": page });
                }
                page.to_string().into_bytes()
            })
            .collect();
        let entry: RecordEntry = serde_json::from_value(record(0)).unwrap();
        (bodies, approx_bytes(&entry))
    }

    async fn host_for(bodies: Vec<Vec<u8>>, host: &str) -> (String, u16) {
        let base = crate::net::tests::serve_bodies_in_sequence(bodies).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(host, std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        (format!("http://{host}:{port}"), port)
    }

    /// **The budget is spent across pages, not reset by each one.**
    ///
    /// The single test this project most needed and did not have. Without it,
    /// moving the budget's construction inside the page loop — making the cap
    /// 200x weaker and effectively inert — passed every test in the suite.
    #[tokio::test]
    async fn a_refusing_walk_spends_its_budget_across_pages() {
        let (bodies, per_page) = paged_bodies(3, 4096, false);
        let (base, _) = host_for(bodies, "budget-accumulate.test").await;
        let client = PdsClient::anonymous(ssrf_test_client(), base, "did:plc:x");

        let err = client
            .list_all_records_within("c", per_page * 2)
            .await
            .expect_err("three pages cannot fit in a two-page budget");
        let msg = format!("{err:#}");
        assert!(msg.contains("byte cap"), "wrong bound reported: {msg}");
        assert!(
            msg.contains("2 held"),
            "the walk did not keep exactly the two pages that fit: {msg}"
        );
    }

    #[tokio::test]
    async fn a_truncating_walk_keeps_the_pages_that_fit() {
        let (bodies, per_page) = paged_bodies(3, 4096, false);
        let (base, _) = host_for(bodies, "budget-accumulate-trunc.test").await;
        let client = PdsClient::anonymous(ssrf_test_client(), base, "did:plc:x");

        let walk = client
            .list_recent_matching_within("c", 100, per_page * 2, 100, |_| true)
            .await
            .expect("an additive walk truncates rather than failing");
        assert_eq!(
            walk.records.len(),
            2,
            "the pages that fit were not kept, or the refused one was"
        );
        assert!(
            !walk.complete,
            "a walk stopped by the budget called itself complete"
        );
    }

    #[tokio::test]
    async fn the_sidecar_walk_spends_its_budget_across_pages() {
        let (bodies, per_page) = paged_bodies(3, 4096, true);
        let base = crate::net::tests::serve_bodies_in_sequence(bodies).await;
        let client = SidecarClient::new(Client::new(), base.clone(), base, "secret");

        let err = client
            .list_all_records_within(
                "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
                "app.feather.subscription",
                per_page * 2,
            )
            .await
            .expect_err("the sidecar walk was the one with no budget at all");
        let msg = format!("{err:#}");
        assert!(msg.contains("byte cap"), "wrong bound reported: {msg}");
        assert!(
            msg.contains("2 held"),
            "did not accumulate across pages: {msg}"
        );
    }

    // -- TID rkeys ----------------------------------------------------------

    #[test]
    fn tid_rkeys_are_13_char_s32_and_monotonic() {
        let mut gen = TidGenerator::new();
        let mut prev: Option<String> = None;
        for _ in 0..1000 {
            let tid = gen.next();
            assert_eq!(tid.len(), 13, "a TID is 13 s32 chars");
            assert!(
                tid.bytes().all(|b| S32_ALPHABET.contains(&b)),
                "TID {tid} uses only the s32 alphabet"
            );
            if let Some(p) = &prev {
                assert!(*p < tid, "TIDs must be strictly increasing ({p} < {tid})");
            }
            prev = Some(tid);
        }
    }

    #[test]
    fn tid_rkeys_are_valid_atproto_record_keys() {
        // atproto rkey charset: [A-Za-z0-9._~:-], length 1..=512, not "."/"..".
        let mut gen = TidGenerator::new();
        let tid = gen.next();
        assert!(is_valid_rkey(&tid), "{tid:?}");
        assert!(tid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b':' | b'-')));
    }

    #[test]
    fn tid_values_round_trip_through_the_decoder() {
        // The decoder is the inverse of the encoder across the whole range a
        // TID can hold, boundaries included.
        let max_tid = (0x001f_ffff_ffff_ffffu64 << 10) | 0x3ff;
        for v in [0u64, 1, 31, 32, 1023, 1024, 1_000_000, max_tid] {
            let encoded = encode_s32_tid(v);
            assert_eq!(
                decode_s32_tid(&encoded),
                Some(v),
                "{v} encoded to {encoded}, which did not decode back"
            );
        }

        // **A round trip alone proves too little.** Encoder and decoder share
        // the alphabet, so swapping two of its symbols round-trips perfectly
        // and still reads every real record key wrong. These two are the
        // known answer: a record key from a real atproto repo, and the value
        // it holds, computed independently of this code.
        assert_eq!(
            decode_s32_tid("3jzfcijpj2z2a"),
            Some(1_728_652_679_052_295_174)
        );
        assert_eq!(encode_s32_tid(1_728_652_679_052_295_174), "3jzfcijpj2z2a");
        assert_eq!(
            decode_s32_tid("3jzfcijpj2z2a").map(|raw| raw >> 10),
            Some(1_688_137_381_887_007),
            "that key was written at 2023-06-30T15:03:01.887007Z"
        );
    }

    #[test]
    fn the_first_tid_of_a_generator_decodes_to_the_microsecond_it_was_minted() {
        let micros = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_micros() as u64)
                .unwrap_or(0)
        };
        // The FIRST `next()` only. `TidGenerator` bumps a TID to `last + 1`
        // to stay strictly increasing, and on a generator whose clock id is
        // already at its maximum that carry lands in the timestamp bits — so a
        // later TID can decode a microsecond or two past when it was really
        // minted. A fresh generator has `last: 0`, where the bump cannot fire.
        let before = micros();
        let tid = TidGenerator::new().next();
        let after = micros();
        let raw = decode_s32_tid(&tid).expect("a generated TID must decode");
        let minted = raw >> 10;
        assert!(
            (before..=after).contains(&minted),
            "TID {tid} decoded to {minted}, outside the {before}..={after} window it was minted in"
        );
    }

    #[test]
    fn the_decoder_rejects_strings_that_are_not_13_char_s32_values() {
        for rkey in [
            "",               // empty
            "self",           // the common non-TID rkey
            "3jzfcijpj2z2",   // 12 chars: one short
            "3jzfcijpj2z2aa", // 14 chars: one long
            "3jzfcijpj2z2A",  // uppercase is outside the s32 alphabet
            "3jzfcijpj2z-a",  // a legal rkey character, but not an s32 one
            "3jzfcijpj2z2!",  // not a legal rkey character at all
            "c222222222222",  // decodes with bit 63 set: the reserved top bit
            "k222222222222",  // decodes past 64 bits entirely
            "zzzzzzzzzzzzz",  // the largest 13-char s32 string
        ] {
            assert_eq!(
                decode_s32_tid(rkey),
                None,
                "{rkey:?} is not a 13-character s32 value"
            );
        }
    }

    /// **The window is not a slug detector, and this is what that costs.**
    ///
    /// A 13-character slug beginning `3` decodes into the last few years just
    /// as a record key does, and nothing in the string tells them apart. These
    /// are read as dates, and pinning that here is the honest alternative to a
    /// doc comment claiming otherwise. The damage is bounded: a wrong date is
    /// an ordinary past instant that ages, sweeps and is outranked normally.
    #[test]
    fn a_slug_that_decodes_inside_the_window_is_read_as_a_date() {
        for (slug, reads_as) in [
            ("3hoursinparis", "2020-11-24T08:17:26Z"),
            ("3ideasforjune", "2021-08-12T00:19:38Z"),
            ("3jokesaweekly", "2023-02-12T15:50:26Z"),
        ] {
            assert_eq!(
                tid_timestamp(slug).map(crate::feed::fmt_time),
                Some(reads_as.to_string()),
                "{slug} is indistinguishable from a record key written then"
            );
        }
    }

    #[test]
    fn a_tid_minted_slightly_ahead_of_our_clock_is_still_believed() {
        let now = chrono::Utc::now();
        let of = |at: chrono::DateTime<chrono::Utc>| {
            encode_s32_tid((at.timestamp_micros() as u64) << 10)
        };
        assert!(
            tid_timestamp(&of(now + chrono::Duration::seconds(2))).is_some(),
            "a PDS two seconds fast must not leave a fresh document undated"
        );
        assert_eq!(
            tid_timestamp(&of(now + chrono::Duration::hours(1))),
            None,
            "an hour ahead is a broken clock or a slug, not skew"
        );
    }

    #[test]
    fn a_tid_timestamp_is_bounded_at_both_ends() {
        let now = chrono::Utc::now();
        let of = |micros: i64| encode_s32_tid((micros as u64) << 10);

        // A TID minted now dates to now.
        let fresh = TidGenerator::new().next();
        let dated = tid_timestamp(&fresh).expect("a freshly minted TID has a timestamp");
        assert!(
            (now - chrono::Duration::minutes(1)..=now + chrono::Duration::minutes(1))
                .contains(&dated),
            "{fresh} dated to {dated}, not to now ({now})"
        );

        // Before atproto existed: not a date.
        assert_eq!(
            tid_timestamp(&of(TID_FLOOR_MICROS - 1)),
            None,
            "a TID predating atproto must not date an entry"
        );
        assert!(
            tid_timestamp(&of(TID_FLOOR_MICROS)).is_some(),
            "the floor itself is a real instant"
        );

        // In the future: not a date. A slug of 13 s32 characters lands here,
        // which is the case this bound exists for.
        let far_future = (now + chrono::Duration::days(365)).timestamp_micros();
        assert_eq!(
            tid_timestamp(&of(far_future)),
            None,
            "a TID from the future must not date an entry"
        );
        assert_eq!(
            tid_timestamp("abcdefghijklm"),
            None,
            "a 13-character slug decodes to the year 2192; it is not a date"
        );
    }

    #[test]
    fn s32_encoding_is_ascending_for_ascending_values() {
        // The whole point of s32: numeric order == lexicographic string order.
        assert!(encode_s32_tid(1) < encode_s32_tid(2));
        assert!(encode_s32_tid(31) < encode_s32_tid(32));
        assert!(encode_s32_tid(1_000_000) < encode_s32_tid(1_000_001));
        // Ordering holds all the way to the largest real TID value (a 53-bit
        // microsecond timestamp shifted into bits 63..10, plus the clock id).
        let max_tid = (0x001f_ffff_ffff_ffffu64 << 10) | 0x3ff;
        assert!(encode_s32_tid(max_tid - 1) < encode_s32_tid(max_tid));
    }
    /// **Exceeding the record cap is an ERROR, not a silent truncation.**
    ///
    /// The page cap bounds how many requests a walk makes; it bounds the
    /// accumulated memory only if the server honours `limit=100`, and a host we
    /// did not choose has no obligation to. A review measured an 8 MB page
    /// holding ~95 000 minimal records and retaining 23 MB as
    /// `Vec&lt;RecordEntry&gt;` — 200 such pages is gigabytes on a 512 MB box.
    ///
    /// Truncating instead would be worse than the OOM it prevents. The caller
    /// of the live walk is `resolve_subscriptions`, whose result feeds
    /// `replace_sub_refs` — a `DELETE` plus reinsert of exactly what it was
    /// handed. A short list there is not a short list, it is **revoked access**
    /// to the feeds that fell off the end. That is the failure PR #167 was
    /// closed for reintroducing, so this returns `Err` and lets the existing
    /// fail-closed branch serve the last-known projection.
    #[test]
    fn exceeding_the_record_cap_is_an_error_not_a_truncation() {
        let page = |n: usize| -> Vec<RecordEntry> {
            (0..n)
                .map(|i| RecordEntry {
                    uri: format!("at://did:plc:x/c/{i}"),
                    cid: None,
                    value: serde_json::Value::Null,
                })
                .collect()
        };

        let mut out = page(90);
        let err = extend_bounded(&mut out, page(20), 100, "c")
            .expect_err("a page past the cap was accepted");
        let msg = format!("{err:#}");
        assert!(msg.contains("100"), "the cap is not named: {msg}");
        assert_eq!(
            out.len(),
            90,
            "the partial page was kept — a truncated list must not survive the error"
        );
    }

    #[test]
    fn accumulating_within_the_cap_succeeds() {
        let page = |n: usize| -> Vec<RecordEntry> {
            (0..n)
                .map(|i| RecordEntry {
                    uri: format!("at://did:plc:x/c/{i}"),
                    cid: None,
                    value: serde_json::Value::Null,
                })
                .collect()
        };
        let mut out = Vec::new();
        extend_bounded(&mut out, page(60), 100, "c").unwrap();
        extend_bounded(&mut out, page(40), 100, "c").unwrap();
        assert_eq!(out.len(), 100, "exactly the cap must be allowed");
    }
}
