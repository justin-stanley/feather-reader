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
        let record = json!({
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
        });
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
                tracing::info!(
                    %deterministic_uri,
                    "createRecord: record already exists (prior post); treating as delivered"
                );
                return Ok(deterministic_uri);
            }
            bail!("createRecord returned {status}: {body}");
        }
    }
}

/// A DETERMINISTIC atproto record key for `did` + `kind`. atproto rkeys must match
/// `[A-Za-z0-9._~-]{1,512}` and not be `.`/`..`; a DID contains `:` (e.g.
/// `did:plc:abc`), which is NOT in that set, so we sanitise every out-of-charset
/// byte to `-`. Prefixing with the post-kind + `did-` keeps `Claim` and `Waitlist`
/// rkeys for the same follower distinct and well under the 512-char cap.
fn rkey_for(did: &str, kind: PostKind) -> String {
    let mut s = String::with_capacity(did.len() + 8);
    s.push_str(kind.prefix());
    s.push('-');
    for b in did.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'~' | b'-' => {
                s.push(b as char)
            }
            _ => s.push('-'),
        }
    }
    s.truncate(512);
    s
}

/// Whether a `createRecord` error body indicates the record already exists — the
/// PDS reports a duplicate rkey as an `InvalidSwap` / "could not... already exists"
/// error. We match leniently (the exact wording varies across PDS versions).
fn record_already_exists(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    b.contains("already exists") || b.contains("invalidswap") || b.contains("record already")
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

    #[test]
    fn rkey_is_deterministic_charset_safe_and_kind_distinct() {
        let did = "did:plc:abc123";
        let claim = rkey_for(did, PostKind::Claim);
        let wl = rkey_for(did, PostKind::Waitlist);
        // Deterministic: same input → same rkey (the idempotency guarantee).
        assert_eq!(claim, rkey_for(did, PostKind::Claim));
        // The two post kinds NEVER collide for the same follower.
        assert_ne!(claim, wl);
        // Colons (illegal in an rkey) are sanitised; only the legal charset remains.
        assert!(!claim.contains(':'));
        assert!(claim
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-')));
        assert!(claim.starts_with("clm-"));
        assert!(wl.starts_with("wl-"));
    }

    #[test]
    fn rkey_is_capped_at_512() {
        let long_did = format!("did:plc:{}", "x".repeat(1000));
        assert!(rkey_for(&long_did, PostKind::Claim).len() <= 512);
    }

    #[test]
    fn record_already_exists_matches_pds_wordings() {
        assert!(record_already_exists(
            "Could not add record: already exists"
        ));
        assert!(record_already_exists("InvalidSwap"));
        assert!(record_already_exists("Record already exists in the repo"));
        assert!(!record_already_exists("RateLimitExceeded"));
        assert!(!record_already_exists("some other error"));
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
