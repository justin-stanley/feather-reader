//! Client for the FeatherReader app's shared-secret mint endpoint.
//!
//! `POST {app_base}/bot/claims` with `X-Bot-Secret: <shared secret>` and a JSON
//! body `{did, handle}` mints (or idempotently returns) a claim link for that
//! follower. Passing the DID makes the APP the authoritative deduper — a bot-host
//! state loss cannot re-mint or re-post per follower:
//!   * `200 {status:"minted"}`   — a fresh code (post the claim link),
//!   * `200 {status:"existing"}` — this DID already had an outstanding claim; the
//!     SAME code/url is returned (safe to re-post),
//!   * `200 {status:"already_seated"}` — this DID already holds beta access; post
//!     NOTHING,
//!   * `409 {"error":"full"}`     — the beta is full; waitlist this follower.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// The outcome of a mint request.
#[derive(Debug)]
pub enum MintOutcome {
    /// A fresh claim was minted; post its `url` (never the raw `code`).
    Minted(Claim),
    /// This DID already had an outstanding claim; the SAME claim is returned. Safe
    /// to (re-)post — the app deduped, not the bot.
    Existing(Claim),
    /// This DID already holds a beta seat. Post NOTHING; mark handled.
    AlreadySeated,
    /// The beta is at capacity — waitlist the follower, retry a later cycle.
    Full,
}

/// A minted claim as returned by the app.
#[derive(Debug, Clone, Deserialize)]
pub struct Claim {
    /// The raw invite code — for the bot's own records only; NEVER post it.
    pub code: String,
    /// The opaque claim token (the code wrapped + signed).
    #[allow(dead_code)]
    pub token: String,
    /// The public claim URL to put in the skeet.
    pub url: String,
}

/// The raw JSON shape the app returns on a 200.
#[derive(Debug, Deserialize)]
struct BotClaimResponse {
    status: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    url: String,
}

/// Client bound to the app base URL + shared bot secret.
pub struct AppClient {
    http: reqwest::Client,
    base: String,
    secret: String,
}

impl AppClient {
    pub fn new(http: reqwest::Client, base: &str, secret: &str) -> Self {
        Self {
            http,
            base: base.trim_end_matches('/').to_string(),
            secret: secret.to_string(),
        }
    }

    /// Mint (or idempotently fetch) a claim FOR the follower `did` (+ advisory
    /// `handle`). `409` → [`MintOutcome::Full`]; any other non-2xx is an error (so
    /// a misconfigured secret / down app surfaces loudly rather than being silently
    /// treated as "full").
    pub async fn mint_claim(&self, did: &str, handle: Option<&str>) -> Result<MintOutcome> {
        let url = format!("{}/bot/claims", self.base);
        let resp = self
            .http
            .post(&url)
            .header("X-Bot-Secret", &self.secret)
            .json(&serde_json::json!({ "did": did, "handle": handle }))
            .send()
            .await
            .context("POST /bot/claims request failed")?;
        let status = resp.status();
        if status == reqwest::StatusCode::CONFLICT {
            return Ok(MintOutcome::Full);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("POST /bot/claims returned {status}: {body}");
        }
        let r: BotClaimResponse = resp.json().await.context("parse /bot/claims response")?;
        match r.status.as_str() {
            "already_seated" => Ok(MintOutcome::AlreadySeated),
            "existing" => Ok(MintOutcome::Existing(Claim {
                code: r.code,
                token: r.token,
                url: r.url,
            })),
            "minted" => Ok(MintOutcome::Minted(Claim {
                code: r.code,
                token: r.token,
                url: r.url,
            })),
            other => bail!("POST /bot/claims returned unknown status {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_response_parses() {
        let json = r#"{"status":"minted","code":"FEATHER-ABCDWXYZ","token":"dG9r.sig","url":"https://feather-reader.com/claim?t=dG9r.sig"}"#;
        let r: BotClaimResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.status, "minted");
        assert_eq!(r.code, "FEATHER-ABCDWXYZ");
        assert!(r.url.contains("/claim?t="));
    }

    #[test]
    fn already_seated_response_parses_with_empty_fields() {
        let json = r#"{"status":"already_seated","code":"","token":"","url":""}"#;
        let r: BotClaimResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.status, "already_seated");
        assert!(r.code.is_empty());
    }
}
