//! A tiny atproto XRPC client over `reqwest` — just the calls the bot needs.
//!
//! Every call targets the account's OWN PDS (`config.pds_host`), so this works
//! for a SELF-HOSTED PDS (`pds.justin-stanley.com`), not only `bsky.social`:
//! `createSession` mints a session on that PDS, and `getFollowers` /
//! `createRecord` run against it. A self-hosted PDS serves the `app.bsky.*`
//! app-view reads by proxying to the network, so `getFollowers` resolves there
//! too.
//!
//! Session reuse: `createSession` is called ONCE (a PDS rate-limits logins to
//! ~300/day/account, and a 5-min poll would otherwise burn ~288 of them). The
//! session's `accessJwt`+`refreshJwt` are held and reused; on a 401 the client
//! calls `com.atproto.server.refreshSession`, falling back to a fresh
//! `createSession` only if refresh itself fails.

use std::sync::Arc;
use tokio::sync::Mutex;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::json;

use crate::messages::RenderedPost;

/// The kind of public post being created, used to derive a DETERMINISTIC rkey per
/// follower per post-type so a post-then-crash retry hits "record already exists"
/// (treated as delivered) instead of duplicating the skeet. The two kinds get
/// distinct rkeys so a follower's waitlist-welcome and later claim post are
/// separate records that never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostKind {
    /// The claim-link post (seat available).
    Claim,
    /// The waitlist-welcome post (beta full), posted once.
    Waitlist,
}

impl PostKind {
    /// Short rkey prefix (kept within the atproto rkey charset).
    fn prefix(self) -> &'static str {
        match self {
            PostKind::Claim => "clm",
            PostKind::Waitlist => "wl",
        }
    }
}

/// Credentials held for reuse across poll cycles (see the module note on session
/// reuse). Wrapped in a `Mutex` so a refresh can rotate them in place.
#[derive(Clone)]
struct Tokens {
    access_jwt: String,
    refresh_jwt: String,
}

/// An authenticated XRPC session against the account's PDS. Long-lived: created
/// once and reused; it refreshes its own access token on expiry.
pub struct Session {
    http: reqwest::Client,
    pds_host: String,
    did: String,
    /// The account handle — needed to re-`createSession` if a refresh ever fails.
    identifier: String,
    app_password: String,
    tokens: Arc<Mutex<Tokens>>,
}

/// One follower as returned by `app.bsky.graph.getFollowers`.
#[derive(Debug, Clone, Deserialize)]
pub struct Follower {
    pub did: String,
    #[serde(default)]
    pub handle: Option<String>,
}

#[derive(Deserialize)]
struct CreateSessionResp {
    #[serde(rename = "accessJwt")]
    access_jwt: String,
    #[serde(rename = "refreshJwt")]
    refresh_jwt: String,
    did: String,
}

/// `com.atproto.server.refreshSession` returns a fresh access + refresh JWT.
#[derive(Deserialize)]
struct RefreshSessionResp {
    #[serde(rename = "accessJwt")]
    access_jwt: String,
    #[serde(rename = "refreshJwt")]
    refresh_jwt: String,
}

#[derive(Deserialize)]
struct FollowersResp {
    #[serde(default)]
    followers: Vec<Follower>,
    #[serde(default)]
    cursor: Option<String>,
}

impl Session {
    /// Log in with an app password (`com.atproto.server.createSession`) against
    /// the account's PDS. The identifier is the handle; the password MUST be a
    /// dedicated app password with write scope (enforced by the caller's config).
    pub async fn login(
        http: reqwest::Client,
        pds_host: &str,
        identifier: &str,
        app_password: &str,
    ) -> Result<Self> {
        let s = create_session(&http, pds_host, identifier, app_password).await?;
        Ok(Self {
            http,
            pds_host: pds_host.to_string(),
            did: s.did,
            identifier: identifier.to_string(),
            app_password: app_password.to_string(),
            tokens: Arc::new(Mutex::new(Tokens {
                access_jwt: s.access_jwt,
                refresh_jwt: s.refresh_jwt,
            })),
        })
    }

    /// The logged-in DID (sanity-check against the configured bot DID).
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The current access JWT (snapshot).
    async fn access_jwt(&self) -> String {
        self.tokens.lock().await.access_jwt.clone()
    }

    /// Refresh the access token via `com.atproto.server.refreshSession`; on refresh
    /// failure, fall back to a full `createSession`. Rotates the held tokens in
    /// place so the next request uses the fresh access JWT. Idempotent to call from
    /// multiple request paths (the mutex serialises the rotation).
    async fn refresh(&self) -> Result<()> {
        let refresh_jwt = self.tokens.lock().await.refresh_jwt.clone();
        let url = format!("{}/xrpc/com.atproto.server.refreshSession", self.pds_host);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&refresh_jwt)
            .send()
            .await
            .context("refreshSession request failed")?;
        if resp.status().is_success() {
            let r: RefreshSessionResp =
                resp.json().await.context("parse refreshSession response")?;
            let mut t = self.tokens.lock().await;
            t.access_jwt = r.access_jwt;
            t.refresh_jwt = r.refresh_jwt;
            return Ok(());
        }
        // Refresh failed (expired/rotated refresh JWT) → re-login from scratch.
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        tracing::warn!(%status, %body, "refreshSession failed; re-creating session");
        let s = create_session(
            &self.http,
            &self.pds_host,
            &self.identifier,
            &self.app_password,
        )
        .await
        .context("createSession fallback after refresh failure")?;
        let mut t = self.tokens.lock().await;
        t.access_jwt = s.access_jwt;
        t.refresh_jwt = s.refresh_jwt;
        Ok(())
    }

    /// Fetch one page of followers for `actor`, newest-first, via
    /// `app.bsky.graph.getFollowers`. Returns the page + the next cursor. The
    /// poll loop only needs the first page(s) — it stops once it hits an
    /// already-handled DID.
    pub async fn get_followers(
        &self,
        actor: &str,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<(Vec<Follower>, Option<String>)> {
        let mut url = format!(
            "{}/xrpc/app.bsky.graph.getFollowers?actor={}&limit={}",
            self.pds_host,
            urlencode(actor),
            limit.clamp(1, 100)
        );
        if let Some(c) = cursor {
            url.push_str(&format!("&cursor={}", urlencode(c)));
        }
        // One retry after a token refresh if the access JWT has expired (401).
        let mut refreshed = false;
        loop {
            let resp = self
                .http
                .get(&url)
                .bearer_auth(&self.access_jwt().await)
                .send()
                .await
                .context("getFollowers request failed")?;
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED && !refreshed {
                refreshed = true;
                self.refresh()
                    .await
                    .context("refresh before getFollowers retry")?;
                continue;
            }
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                bail!("getFollowers returned {status}: {body}");
            }
            let r: FollowersResp = resp.json().await.context("parse getFollowers response")?;
            return Ok((r.followers, r.cursor));
        }
    }

    /// Post a public skeet with a single `@`-mention facet, via
    /// `com.atproto.repo.createRecord` on the account's own repo. Returns the
    /// created record's `at://` URI.
    ///
    /// The facet turns the rendered `@handle` byte range into an
    /// `app.bsky.richtext.facet#mention` so the follower is actually notified
    /// (a plain-text `@handle` is NOT a notification).
    ///
    /// IDEMPOTENT: the record's rkey is DETERMINISTIC in the follower DID + the
    /// `kind` (see [`rkey_for`]), and the request sets `swapCommit`-free
    /// create-only semantics, so a post-then-crash RETRY re-issues the SAME rkey.
    /// The PDS answers the duplicate with `InvalidSwap`/"record already exists",
    /// which this treats as DELIVERED (returning the deterministic `at://` URI)
    /// rather than posting a second skeet. The `Claim` and `Waitlist` kinds get
    /// distinct rkeys, so a follower can receive both over time without collision.
    pub async fn post_with_mention(
        &self,
        post: &RenderedPost,
        mention_did: &str,
        kind: PostKind,
    ) -> Result<String> {
        let rkey = rkey_for(mention_did, kind);
        let record = build_post_record(post, mention_did);
        let url = format!("{}/xrpc/com.atproto.repo.createRecord", self.pds_host);
        let deterministic_uri = format!("at://{}/app.bsky.feed.post/{}", self.did, rkey);

        // One retry after a token refresh on 401.
        let mut refreshed = false;
        loop {
            let resp = self
                .http
                .post(&url)
                .bearer_auth(&self.access_jwt().await)
                .json(&json!({
                    "repo": self.did,
                    "collection": "app.bsky.feed.post",
                    "rkey": rkey,
                    "record": record,
                }))
                .send()
                .await
                .context("createRecord request failed")?;
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED && !refreshed {
                refreshed = true;
                self.refresh()
                    .await
                    .context("refresh before createRecord retry")?;
                continue;
            }
            if resp.status().is_success() {
                #[derive(Deserialize)]
                struct CreateRecordResp {
                    uri: String,
                }
                let r: CreateRecordResp =
                    resp.json().await.context("parse createRecord response")?;
                return Ok(r.uri);
            }
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // A duplicate rkey (the record already exists from a prior, interrupted
            // run) is SUCCESS for our purposes: the skeet was already delivered.
            if record_already_exists(&body) {
                // S1 — dead-link-after-remint. The rkey is deterministic per
                // (kind, DID) FOREVER, so if the bot state DB is lost and a fresh
                // code is minted (new claim URL), a naive "already exists → done"
                // would re-post nothing and leave the OLD, now-dead link live. So
                // before treating it as delivered, fetch the existing record and,
                // if its text no longer matches the CURRENT post (a stale claim
                // URL), `putRecord`-update it in place (same rkey) so the follower
                // sees the working link. If it already matches, it's a true no-op.
                match self.reconcile_stale_record(&rkey, post, mention_did).await {
                    Ok(uri) => {
                        tracing::info!(
                            %uri,
                            "createRecord: record already exists; reconciled to current claim link"
                        );
                        return Ok(uri);
                    }
                    Err(err) => {
                        // Reconciliation is best-effort: if the get/put path fails,
                        // fall back to treating the existing record as delivered
                        // (the old behaviour) rather than failing the whole cycle.
                        tracing::warn!(
                            %err,
                            %deterministic_uri,
                            "createRecord: record exists but reconcile failed; treating as delivered"
                        );
                        return Ok(deterministic_uri);
                    }
                }
            }
            bail!("createRecord returned {status}: {body}");
        }
    }

    /// S1 helper: fetch the existing `app.bsky.feed.post` at `rkey` and, if its
    /// text differs from `post` (a stale claim URL after a re-mint), overwrite it
    /// with `putRecord` (same rkey → same at:// URI, so no duplicate skeet). Returns
    /// the record's `at://` URI. A matching record is left untouched.
    async fn reconcile_stale_record(
        &self,
        rkey: &str,
        post: &RenderedPost,
        mention_did: &str,
    ) -> Result<String> {
        let deterministic_uri = format!("at://{}/app.bsky.feed.post/{}", self.did, rkey);

        // 1. getRecord — read the existing post's text (with a 401 refresh retry).
        let get_url = format!(
            "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=app.bsky.feed.post&rkey={}",
            self.pds_host,
            urlencode(&self.did),
            urlencode(rkey),
        );
        #[derive(Deserialize)]
        struct ExistingPost {
            #[serde(default)]
            text: String,
        }
        #[derive(Deserialize)]
        struct GetRecordResp {
            #[serde(default)]
            value: Option<ExistingPost>,
        }
        let existing_text = {
            let mut refreshed = false;
            loop {
                let resp = self
                    .http
                    .get(&get_url)
                    .bearer_auth(&self.access_jwt().await)
                    .send()
                    .await
                    .context("getRecord request failed")?;
                if resp.status() == reqwest::StatusCode::UNAUTHORIZED && !refreshed {
                    refreshed = true;
                    self.refresh()
                        .await
                        .context("refresh before getRecord retry")?;
                    continue;
                }
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    bail!("getRecord returned {status}: {body}");
                }
                let r: GetRecordResp = resp.json().await.context("parse getRecord response")?;
                break r.value.map(|v| v.text).unwrap_or_default();
            }
        };

        // 2. Already current → nothing to do (the common case: a genuine retry of
        //    the SAME code, not a re-mint).
        if existing_text == post.text {
            return Ok(deterministic_uri);
        }

        // 3. Stale → overwrite in place with putRecord (same rkey), rebuilding the
        //    record (text + fresh mention facet) exactly as createRecord would.
        let record = build_post_record(post, mention_did);
        let put_url = format!("{}/xrpc/com.atproto.repo.putRecord", self.pds_host);
        let mut refreshed = false;
        loop {
            let resp = self
                .http
                .post(&put_url)
                .bearer_auth(&self.access_jwt().await)
                .json(&json!({
                    "repo": self.did,
                    "collection": "app.bsky.feed.post",
                    "rkey": rkey,
                    "record": record,
                }))
                .send()
                .await
                .context("putRecord request failed")?;
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED && !refreshed {
                refreshed = true;
                self.refresh()
                    .await
                    .context("refresh before putRecord retry")?;
                continue;
            }
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                bail!("putRecord returned {status}: {body}");
            }
            #[derive(Deserialize)]
            struct PutRecordResp {
                uri: String,
            }
            let r: PutRecordResp = resp.json().await.context("parse putRecord response")?;
            return Ok(r.uri);
        }
    }
}

/// Build the `app.bsky.feed.post` record JSON (text + a single `@`-mention facet)
/// for `post`, mentioning `mention_did`. Shared by `createRecord` and the S1
/// `putRecord` reconcile so both emit an identical record shape.
fn build_post_record(post: &RenderedPost, mention_did: &str) -> serde_json::Value {
    json!({
        "$type": "app.bsky.feed.post",
        "text": post.text,
        "createdAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "facets": [{
            "index": {
                "byteStart": post.mention.byte_start,
                "byteEnd": post.mention.byte_end,
            },
            "features": [{
                "$type": "app.bsky.richtext.facet#mention",
                "did": mention_did,
            }],
        }],
    })
}

/// A DETERMINISTIC, syntactically-valid **TID** record key for `did` + `kind`.
///
/// `app.bsky.feed.post` declares `record: { key: "tid" }` in its lexicon, so the
/// PDS rejects any rkey that is not a valid TID with
/// `InvalidRequest: Invalid TID string` — a generic sanitised-DID rkey (the old
/// behaviour) is refused and the claim skeet never posts. A TID is 13 characters
/// of the sortable base32 alphabet (`234567abcdefghijklmnopqrstuvwxyz`) encoding a
/// 63-bit big-endian integer (top bit 0).
///
/// The rkey MUST stay deterministic per `(kind, did)` so a post-then-crash retry
/// reuses the same rkey and is deduped server-side (`RecordAlreadyExists`) instead
/// of double-posting. So rather than a clock, we derive the 63-bit value from a
/// stable FNV-1a hash of `<prefix>-<did>` and s32-encode it: same follower + kind →
/// the same TID forever, and `Claim`/`Waitlist` differ by the hashed prefix.
/// Cross-`(kind, did)` collisions are ~1/2^63.
fn rkey_for(did: &str, kind: PostKind) -> String {
    const S32: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    // FNV-1a (64-bit) over `<prefix>-<did>`.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in kind
        .prefix()
        .bytes()
        .chain(std::iter::once(b'-'))
        .chain(did.bytes())
    {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // TIDs are 63-bit, big-endian, with the top bit always 0.
    h &= 0x7fff_ffff_ffff_ffff;
    let mut out = [0u8; 13];
    for slot in out.iter_mut().rev() {
        *slot = S32[(h & 0x1f) as usize];
        h >>= 5;
    }
    // Every byte is from S32, which is ASCII.
    String::from_utf8(out.to_vec()).expect("s32 output is ASCII")
}

/// The XRPC error envelope: `{ "error": "<Name>", "message": "..." }`.
#[derive(Deserialize)]
struct XrpcError {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// Whether a `createRecord` error body indicates the record already exists — a
/// duplicate rkey. (S2) We parse the XRPC JSON envelope and match the error NAME
/// EXACTLY (`InvalidSwap` / `RecordAlreadyExists`) rather than substring-scanning
/// the whole body: a lenient `body.contains("already exists")` would misread an
/// unrelated "already exists" (a proxy/HTML error page, a different PDS failure)
/// as "delivered" and silently drop a real post. If the body isn't a JSON XRPC
/// envelope, this is NOT a record-exists error (it's some other failure — surface
/// it), except that we still accept a `message` whose EXACT text is the canonical
/// "Could not add record: already exists" a few PDS builds return with an empty
/// `error` name.
fn record_already_exists(body: &str) -> bool {
    let Ok(env) = serde_json::from_str::<XrpcError>(body) else {
        return false;
    };
    if let Some(name) = env.error.as_deref() {
        // The error NAME, matched exactly (case-insensitive to tolerate a PDS that
        // varies the casing, but it's the whole token — not a substring of prose).
        if name.eq_ignore_ascii_case("InvalidSwap")
            || name.eq_ignore_ascii_case("RecordAlreadyExists")
        {
            return true;
        }
    }
    // Some PDS builds return the duplicate as a bare `message` (empty/absent
    // `error` name). Accept ONLY the exact canonical phrasing, not any substring.
    matches!(
        env.message.as_deref(),
        Some("Could not add record: already exists")
    )
}

/// Call `com.atproto.server.createSession` and return the parsed tokens + DID.
/// Factored out so both the initial [`Session::login`] and the refresh-failure
/// fallback re-login share one implementation.
async fn create_session(
    http: &reqwest::Client,
    pds_host: &str,
    identifier: &str,
    app_password: &str,
) -> Result<CreateSessionResp> {
    let url = format!("{pds_host}/xrpc/com.atproto.server.createSession");
    let resp = http
        .post(&url)
        .json(&json!({ "identifier": identifier, "password": app_password }))
        .send()
        .await
        .context("createSession request failed")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("createSession returned {status}: {body}");
    }
    resp.json().await.context("parse createSession response")
}

/// Minimal RFC-3986 query-value percent-encoding (keep unreserved).
fn urlencode(s: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_keeps_unreserved_escapes_rest() {
        assert_eq!(urlencode("feather-reader.com"), "feather-reader.com");
        assert_eq!(urlencode("did:plc:abc"), "did%3Aplc%3Aabc");
    }

    /// A syntactically valid atproto TID: 13 chars of sortable-base32, with the
    /// first char restricted (it carries only the 63-bit value's top 3 bits).
    fn is_valid_tid(s: &str) -> bool {
        const FIRST: &[u8] = b"234567abcdefghij";
        const REST: &[u8] = b"234567abcdefghijklmnopqrstuvwxyz";
        let b = s.as_bytes();
        b.len() == 13 && FIRST.contains(&b[0]) && b[1..].iter().all(|c| REST.contains(c))
    }

    #[test]
    fn rkey_is_a_deterministic_valid_tid_distinct_per_kind() {
        let did = "did:plc:abc123";
        let claim = rkey_for(did, PostKind::Claim);
        let wl = rkey_for(did, PostKind::Waitlist);
        // Deterministic: same input → same rkey (the idempotency guarantee).
        assert_eq!(claim, rkey_for(did, PostKind::Claim));
        // The two post kinds NEVER collide for the same follower.
        assert_ne!(claim, wl);
        // Both MUST be valid TIDs — `app.bsky.feed.post` requires `key: tid`, and a
        // non-TID rkey is rejected with `InvalidRequest: Invalid TID string`.
        assert!(is_valid_tid(&claim), "claim rkey not a valid TID: {claim}");
        assert!(is_valid_tid(&wl), "waitlist rkey not a valid TID: {wl}");
    }

    #[test]
    fn rkey_is_a_fixed_length_tid_regardless_of_did() {
        // A TID is always 13 chars, however long the DID.
        let long_did = format!("did:plc:{}", "x".repeat(1000));
        let rk = rkey_for(&long_did, PostKind::Claim);
        assert_eq!(rk.len(), 13);
        assert!(is_valid_tid(&rk));
    }

    #[test]
    fn record_already_exists_matches_exact_xrpc_error_names() {
        // The real PDS duplicate-rkey response: an XRPC envelope naming InvalidSwap.
        assert!(record_already_exists(
            r#"{"error":"InvalidSwap","message":"Record already exists"}"#
        ));
        // The alternate canonical name.
        assert!(record_already_exists(
            r#"{"error":"RecordAlreadyExists","message":"..."}"#
        ));
        // Case-insensitive on the NAME token.
        assert!(record_already_exists(r#"{"error":"invalidswap"}"#));
        // A bare-message PDS build, EXACT phrasing only.
        assert!(record_already_exists(
            r#"{"message":"Could not add record: already exists"}"#
        ));

        // S2: an UNRELATED error whose prose happens to contain "already exists"
        // must NOT be misread as delivered (this is the whole point of the fix).
        assert!(!record_already_exists(
            r#"{"error":"InvalidRequest","message":"the collection already exists elsewhere"}"#
        ));
        // A non-JSON proxy/HTML page mentioning "already exists" is NOT a match.
        assert!(!record_already_exists(
            "<html>the resource already exists</html>"
        ));
        // Other real XRPC errors are not matches.
        assert!(!record_already_exists(
            r#"{"error":"RateLimitExceeded","message":"slow down"}"#
        ));
        assert!(!record_already_exists(
            r#"{"error":"ExpiredToken","message":"token has expired"}"#
        ));
        // A near-miss message (not the exact canonical phrasing) is not a match.
        assert!(!record_already_exists(
            r#"{"message":"record already exists in the repo"}"#
        ));
    }

    #[test]
    fn build_post_record_text_tracks_the_claim_url() {
        // S1's stale-detection compares the existing record's `text` to the current
        // post's `text`; a re-mint changes the URL, so the rendered text (and thus
        // the record text) must differ — which is what triggers the putRecord update.
        use crate::messages::render;
        let old = render("claim @{handle}: {url}", "z.test", "https://x/claim?t=OLD");
        let new = render("claim @{handle}: {url}", "z.test", "https://x/claim?t=NEW");
        let rec_old = build_post_record(&old, "did:plc:z");
        let rec_new = build_post_record(&new, "did:plc:z");
        // A changed URL → different record text (stale → reconcile fires).
        assert_ne!(rec_old["text"], rec_new["text"]);
        // Same URL → identical text (no-op, reconcile is skipped).
        let new_again = render("claim @{handle}: {url}", "z.test", "https://x/claim?t=NEW");
        assert_eq!(
            build_post_record(&new_again, "did:plc:z")["text"],
            rec_new["text"]
        );
        // The mention facet targets the follower DID.
        assert_eq!(rec_new["facets"][0]["features"][0]["did"], "did:plc:z");
    }

    #[test]
    fn followers_response_parses_partial_json() {
        let json = r#"{"followers":[{"did":"did:plc:a","handle":"a.test"},{"did":"did:plc:b"}],"cursor":"c1"}"#;
        let r: FollowersResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.followers.len(), 2);
        assert_eq!(r.followers[0].handle.as_deref(), Some("a.test"));
        assert!(r.followers[1].handle.is_none());
        assert_eq!(r.cursor.as_deref(), Some("c1"));
    }
}
