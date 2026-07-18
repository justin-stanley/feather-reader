//! A tiny atproto XRPC client over `reqwest` — just the three calls the bot needs.
//!
//! Every call targets the account's OWN PDS (`config.pds_host`), so this works
//! for a SELF-HOSTED PDS (`pds.justin-stanley.com`), not only `bsky.social`:
//! `createSession` mints a session on that PDS, and `getFollowers` /
//! `createRecord` run against it. A self-hosted PDS serves the `app.bsky.*`
//! app-view reads by proxying to the network, so `getFollowers` resolves there
//! too.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::json;

use crate::messages::RenderedPost;

/// An authenticated XRPC session against the account's PDS.
pub struct Session {
    http: reqwest::Client,
    pds_host: String,
    did: String,
    access_jwt: String,
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
    did: String,
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
        let s: CreateSessionResp = resp.json().await.context("parse createSession response")?;
        Ok(Self {
            http,
            pds_host: pds_host.to_string(),
            did: s.did,
            access_jwt: s.access_jwt,
        })
    }

    /// The logged-in DID (sanity-check against the configured bot DID).
    pub fn did(&self) -> &str {
        &self.did
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
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.access_jwt)
            .send()
            .await
            .context("getFollowers request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("getFollowers returned {status}: {body}");
        }
        let r: FollowersResp = resp.json().await.context("parse getFollowers response")?;
        Ok((r.followers, r.cursor))
    }

    /// Post a public skeet with a single `@`-mention facet, via
    /// `com.atproto.repo.createRecord` on the account's own repo. Returns the
    /// created record's `at://` URI.
    ///
    /// The facet turns the rendered `@handle` byte range into an
    /// `app.bsky.richtext.facet#mention` so the follower is actually notified
    /// (a plain-text `@handle` is NOT a notification).
    pub async fn post_with_mention(
        &self,
        post: &RenderedPost,
        mention_did: &str,
    ) -> Result<String> {
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
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.access_jwt)
            .json(&json!({
                "repo": self.did,
                "collection": "app.bsky.feed.post",
                "record": record,
            }))
            .send()
            .await
            .context("createRecord request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("createRecord returned {status}: {body}");
        }
        #[derive(Deserialize)]
        struct CreateRecordResp {
            uri: String,
        }
        let r: CreateRecordResp = resp.json().await.context("parse createRecord response")?;
        Ok(r.uri)
    }
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
    fn followers_response_parses_partial_json() {
        let json = r#"{"followers":[{"did":"did:plc:a","handle":"a.test"},{"did":"did:plc:b"}],"cursor":"c1"}"#;
        let r: FollowersResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.followers.len(), 2);
        assert_eq!(r.followers[0].handle.as_deref(), Some("a.test"));
        assert!(r.followers[1].handle.is_none());
        assert_eq!(r.cursor.as_deref(), Some("c1"));
    }
}
