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
    /// The raw body. **Public, so the `Debug` impl below is a default rather
    /// than a barrier**: `{:?}` on this field prints everything. On a success
    /// this holds the access and refresh tokens, so it must not be logged,
    /// formatted into an error, or echoed on any path that is not already known
    /// to be a failure response.
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
    /// Parse the body as JSON.
    ///
    /// The body is NEVER echoed into the error, not even an excerpt. This is
    /// called on the SUCCESSFUL token response, so a 200 that fails to parse —
    /// truncated by a proxy, a WAF interstitial appended to JSON — would
    /// otherwise put the access and refresh tokens into whatever logs the error.
    /// Status and length carry the same diagnostic value.
    pub fn json(&self) -> Result<serde_json::Value> {
        serde_json::from_slice(&self.body).with_context(|| {
            format!(
                "response (status {}, {} bytes) is not valid JSON",
                self.status,
                self.body.len()
            )
        })
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Whether this request may be repeated if the server demands a nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// Safe to repeat: PAR, refresh, resource reads.
    Allowed,
    /// **Must not be repeated.** The authorization-code exchange: re-POSTing
    /// the same `code` can burn it, and the login then fails AFTER the user has
    /// already approved.
    Forbidden,
}

/// The nonce to retry with, or `None` to stop.
///
/// Pure so the policy is testable: the SSRF guard forbids pointing any of this
/// at a loopback test server, so the round trip itself cannot be exercised.
fn next_nonce(
    attempt: usize,
    retry: Retry,
    challenge: Option<String>,
    already_sent: Option<&str>,
) -> Option<String> {
    if attempt != 0 || retry == Retry::Forbidden {
        return None;
    }
    let fresh = challenge?;
    // Retrying with the nonce we already sent is a guaranteed-wasted round trip.
    if Some(fresh.as_str()) == already_sent {
        return None;
    }
    Some(fresh)
}

/// The headers for one attempt.
///
/// A resource request carries BOTH the proof and the token. The proof's `ath`
/// binds to an access token the server never sees otherwise, so omitting the
/// `Authorization` header makes the request unauthenticated — and the resulting
/// 401 carries no `use_dpop_nonce`, so the retry cannot recover it either. The
/// scheme is `DPoP`, not `Bearer`: presenting a DPoP-bound token as a bearer
/// token discards the binding.
fn request_headers(
    proof: &str,
    access_token: Option<&str>,
) -> Result<Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>> {
    let mut headers = vec![(
        reqwest::header::HeaderName::from_static("dpop"),
        reqwest::header::HeaderValue::from_str(proof)
            .context("DPoP proof is not a valid header value")?,
    )];
    if let Some(token) = access_token {
        headers.push((
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("DPoP {token}"))
                .context("access token is not a valid header value")?,
        ));
    }
    Ok(headers)
}

/// One DPoP-authenticated form POST.
///
/// Grouped rather than passed positionally so a call site reads as a
/// description of the request — `Retry::Forbidden` next to the code exchange is
/// the kind of thing that should be visible at the call, not buried in an
/// argument list.
pub struct DpopPost<'a> {
    pub endpoint: Endpoint,
    pub url: &'a str,
    /// The session's DPoP key — the same one used from PAR onward.
    pub key: &'a SigningKey,
    /// Binds the proof via `ath` and is sent as `Authorization: DPoP …`.
    /// `None` for the authorization-server endpoints.
    pub access_token: Option<&'a str>,
    pub params: &'a [(&'a str, &'a str)],
    pub retry: Retry,
}

/// POST a form with a DPoP proof, retrying once if the server demands a nonce
/// and [`Retry`] permits it.
pub async fn post_form_with_dpop(
    client: &Client,
    pool: &SqlitePool,
    request: &DpopPost<'_>,
) -> Result<PostOutcome> {
    let DpopPost {
        endpoint,
        url,
        key,
        access_token,
        params,
        retry,
    } = *request;
    let origin = origin_of(url)?;
    let mut nonce = store::get_nonce(pool, &origin).await?;

    for attempt in 0..2 {
        let proof = dpop::proof(key, "POST", url, access_token, nonce.as_deref())?;
        let headers = request_headers(&proof, access_token)?;

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

        let challenge = dpop::nonce_challenge(
            endpoint,
            status,
            www_authenticate.as_deref(),
            &body,
            offered.as_deref(),
        );
        if let Some(fresh) = next_nonce(attempt, retry, challenge, nonce.as_deref()) {
            nonce = Some(fresh);
            continue;
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
            &DpopPost {
                endpoint: Endpoint::AuthorizationServer,
                url: "http://127.0.0.1/oauth/token",
                key: &key,
                access_token: None,
                params: &[("grant_type", "refresh_token")],
                retry: Retry::Allowed,
            },
        )
        .await
        .expect_err("must refuse a loopback token endpoint");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("forbidden (internal) address"),
            "failed for the wrong reason: {rendered}"
        );
    }

    /// **The body must never reach an error message.** `json()` is called on the
    /// SUCCESSFUL token response, so a 200 whose body fails to parse — truncated
    /// by a proxy, a WAF interstitial appended to JSON — would put
    /// `{"access_token":"eyJ…` into whatever logs the error. That is exactly the
    /// disclosure the hand-written `Debug` exists to prevent, and echoing an
    /// "excerpt" reopens it through a different door.
    #[test]
    fn a_non_json_body_is_never_echoed_into_the_error() {
        let outcome = PostOutcome {
            status: 200,
            body: br#"{"access_token":"eyJhbGciOiJFUzI1NiJ9.SECRET-TOKEN-VALUE"#.to_vec(),
        };
        let rendered = format!("{:#}", outcome.json().unwrap_err());
        assert!(rendered.contains("200"), "status is the useful diagnostic");
        assert!(
            !rendered.contains("SECRET-TOKEN-VALUE") && !rendered.contains("eyJhbGciOiJ"),
            "the body leaked into the error: {rendered}"
        );
    }

    // ── the retry decision ───────────────────────────────────────────────────

    #[test]
    fn a_nonce_challenge_on_the_first_attempt_is_retried() {
        assert_eq!(
            next_nonce(0, Retry::Allowed, Some("fresh".into()), None).as_deref(),
            Some("fresh")
        );
    }

    /// Bounded at one. A server answering every request with `use_dpop_nonce`
    /// must not make this spin.
    #[test]
    fn a_second_attempt_never_retries() {
        assert!(next_nonce(1, Retry::Allowed, Some("fresh".into()), None).is_none());
    }

    /// **The code exchange must not be retried.** Plan §11 and the reference
    /// both refuse it: re-POSTing `grant_type=authorization_code` can burn the
    /// authorization code, and the login then dies AFTER the user approved,
    /// presenting as intermittent "login just doesn't work".
    #[test]
    fn a_request_that_must_not_repeat_is_never_retried() {
        assert!(next_nonce(0, Retry::Forbidden, Some("fresh".into()), None).is_none());
    }

    /// Retrying with the nonce we already sent is a guaranteed-wasted round
    /// trip; the reference short-circuits it too.
    #[test]
    fn an_unchanged_nonce_is_not_worth_retrying() {
        assert!(next_nonce(0, Retry::Allowed, Some("same".into()), Some("same")).is_none());
        assert_eq!(
            next_nonce(0, Retry::Allowed, Some("new".into()), Some("old")).as_deref(),
            Some("new")
        );
    }

    #[test]
    fn no_challenge_means_no_retry() {
        assert!(next_nonce(0, Retry::Allowed, None, None).is_none());
    }

    // ── headers ──────────────────────────────────────────────────────────────

    /// **`ath` without the token is useless.** The proof binds to an access
    /// token the server never receives, so a resource request arrives
    /// unauthenticated — and the resulting 401 carries no `use_dpop_nonce`, so
    /// even the retry cannot recover it.
    #[test]
    fn a_resource_request_carries_the_token_as_well_as_the_proof() {
        let headers = request_headers("the-proof", Some("the-token")).unwrap();
        let names: Vec<String> = headers.iter().map(|(n, _)| n.to_string()).collect();
        assert!(names.contains(&"dpop".to_string()));
        assert!(names.contains(&"authorization".to_string()));

        let auth = headers
            .iter()
            .find(|(n, _)| n.as_str() == "authorization")
            .map(|(_, v)| v.to_str().unwrap().to_string())
            .unwrap();
        // The scheme is DPoP, not Bearer: a DPoP-bound token presented as a
        // bearer token is a downgrade the server should reject.
        assert_eq!(auth, "DPoP the-token");
    }

    #[test]
    fn an_authorization_server_request_carries_only_the_proof() {
        let headers = request_headers("the-proof", None).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_str(), "dpop");
    }

    /// A token with a newline would otherwise split the header.
    #[test]
    fn a_malformed_token_is_rejected_rather_than_injected() {
        assert!(request_headers("proof", Some("tok\r\nX-Evil: 1")).is_err());
        assert!(request_headers("pro\nof", None).is_err());
    }
}
