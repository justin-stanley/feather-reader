//! Client for the FeatherReader app's shared-secret mint endpoint.
//!
//! `POST {app_base}/bot/claims` with `X-Bot-Secret: <shared secret>` mints a
//! claim code and returns `{code, token, url}`. The endpoint is cap-aware: it
//! answers `409 Conflict` with `{"error":"full"}` when the beta is full, which
//! the bot treats as "waitlist this follower" rather than an error.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// The outcome of a mint request.
#[derive(Debug)]
pub enum MintOutcome {
    /// A claim was minted; post its `url` (never the raw `code`).
    Claim(Claim),
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

    /// Mint a claim. `409` → [`MintOutcome::Full`]; any other non-2xx is an error
    /// (so a misconfigured secret / down app surfaces loudly rather than being
    /// silently treated as "full").
    pub async fn mint_claim(&self) -> Result<MintOutcome> {
        let url = format!("{}/bot/claims", self.base);
        let resp = self
            .http
            .post(&url)
            .header("X-Bot-Secret", &self.secret)
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
        let claim: Claim = resp.json().await.context("parse /bot/claims response")?;
        Ok(MintOutcome::Claim(claim))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_parses() {
        let json = r#"{"code":"FEATHER-ABCDWXYZ","token":"dG9r.sig","url":"https://feather-reader.com/claim?t=dG9r.sig"}"#;
        let c: Claim = serde_json::from_str(json).unwrap();
        assert_eq!(c.code, "FEATHER-ABCDWXYZ");
        assert!(c.url.contains("/claim?t="));
    }
}
