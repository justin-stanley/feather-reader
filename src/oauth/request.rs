//! DPoP-authenticated form POSTs, with nonce persistence and a bounded retry.
//!
//! Every OAuth POST this client makes goes through here: PAR, token exchange,
//! refresh. Three behaviours matter and all three are easy to get subtly wrong:
//!
//! * **The nonce is persisted per origin and harvested from EVERY response**,
//!   including successes. Using one only for an immediate retry means every
//!   request pays a wasted round trip.
//! * **The retry is bounded at one.** A server that answers every request with
//!   `use_dpop_nonce` would otherwise spin forever.
//! * **The endpoint kind is passed, not inferred.** The authorization server
//!   signals a nonce requirement with `400` + a JSON body; a resource server
//!   uses `401` + `WWW-Authenticate`. Reading only one of those misses every
//!   challenge from the other.

use anyhow::{Context as _, Result};
use reqwest::Client;
use sqlx::SqlitePool;

use super::discovery::origin_of;
use super::dpop::{self, Endpoint};
use super::keys::SigningKey;
use super::store;
use crate::net;

/// A completed request: what the server said, and what it said it with.
pub struct PostOutcome {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Hand-written, NOT derived. A token-endpoint body holds the access and refresh
/// tokens; a derived `Debug` would put them into any log line, panic message or
/// `{:?}` that ever touches this value.
impl std::fmt::Debug for PostOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostOutcome")
            .field("status", &self.status)
            .field(
                "body",
                &format_args!("<{} bytes redacted>", self.body.len()),
            )
            .finish()
    }
}

impl PostOutcome {
    /// Parse the body as JSON, with the status in the error if it is not.
    pub fn json(&self) -> Result<serde_json::Value> {
        serde_json::from_slice(&self.body).with_context(|| {
            format!(
                "response (status {}) is not valid JSON: {}",
                self.status,
                String::from_utf8_lossy(&self.body)
                    .chars()
                    .take(200)
                    .collect::<String>()
            )
        })
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// POST a form to an OAuth endpoint with a DPoP proof, retrying once if the
/// server demands a nonce.
///
/// `access_token` binds the proof via `ath` and is supplied for resource
/// requests; the authorization-server endpoints pass `None`.
pub async fn post_form_with_dpop(
    client: &Client,
    pool: &SqlitePool,
    endpoint: Endpoint,
    url: &str,
    key: &SigningKey,
    access_token: Option<&str>,
    params: &[(&str, &str)],
) -> Result<PostOutcome> {
    let origin = origin_of(url)?;
    let mut nonce = store::get_nonce(pool, &origin).await?;

    for attempt in 0..2 {
        let proof = dpop::proof(key, "POST", url, access_token, nonce.as_deref())?;
        let headers = [(
            reqwest::header::HeaderName::from_static("dpop"),
            reqwest::header::HeaderValue::from_str(&proof)
                .context("DPoP proof is not a valid header value")?,
        )];

        let response = net::guarded_post_form(client, url, &headers, params)
            .await
            .with_context(|| format!("posting to {url}"))?;

        let status = response.status().as_u16();
        let www_authenticate = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        // Harvest from EVERY response, success included: the server rotates
        // nonces, and carrying the newest one forward is what keeps the retry
        // exceptional rather than routine.
        let offered = response
            .headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let body = net::read_capped(response)
            .await
            .with_context(|| format!("reading the response from {url}"))?;

        if let Some(offered) = &offered {
            if Some(offered) != nonce.as_ref() {
                store::put_nonce(pool, &origin, offered).await?;
            }
        }

        // Only the first attempt may retry; a server that always demands a
        // nonce must not spin.
        if attempt == 0 {
            if let Some(fresh) = dpop::nonce_challenge(
                endpoint,
                status,
                www_authenticate.as_deref(),
                &body,
                offered.as_deref(),
            ) {
                nonce = Some(fresh);
                continue;
            }
        }
        return Ok(PostOutcome { status, body });
    }
    unreachable!("the loop returns on its second pass")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Like every other outbound path, this must fail closed on an internal
    /// target — asserted on the guard's own error, not merely `is_err()`.
    #[tokio::test]
    async fn a_dpop_post_fails_closed_on_an_internal_target() {
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");

        let err = post_form_with_dpop(
            &Client::new(),
            &pool,
            Endpoint::AuthorizationServer,
            "http://127.0.0.1/oauth/token",
            &key,
            None,
            &[("grant_type", "refresh_token")],
        )
        .await
        .expect_err("must refuse a loopback token endpoint");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("forbidden (internal) address"),
            "failed for the wrong reason: {rendered}"
        );
    }

    #[test]
    fn a_non_json_body_reports_the_status_and_a_bounded_excerpt() {
        let outcome = PostOutcome {
            status: 502,
            body: b"<html>".repeat(500).to_vec(),
        };
        let rendered = format!("{:#}", outcome.json().unwrap_err());
        assert!(rendered.contains("502"));
        assert!(rendered.len() < 400, "error echoed an unbounded body");
    }
}
