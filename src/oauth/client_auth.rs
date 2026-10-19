//! How this client authenticates to the authorization server.
//!
//! Two shapes, and which one applies is not a detail:
//!
//! * **`none`** — the localhost development client. Credentials are *just* the
//!   `client_id`; there is no assertion, because a public client has no key
//!   registered to sign one with.
//! * **`private_key_jwt`** — production. A short-lived ES256 assertion signed
//!   with the confidential client's key.
//!
//! Sending an assertion unconditionally would make every dev login fail at PAR
//! (a public client presenting credentials it never registered), leaving the
//! flow only exercisable against production. Sending none in production is a
//! silent downgrade to an unauthenticated client. So the method is negotiated,
//! stored in the state row, and re-checked at token time.

use anyhow::{bail, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::json;

use super::jwt;
use super::keys::SigningKey;

/// RFC 7523's assertion type for a JWT client credential.
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// How long a client assertion is valid. Matches the reference's `now + 60`;
/// an assertion is used immediately, so a short life bounds replay.
const ASSERTION_LIFETIME_SECS: i64 = 60;

/// The client-authentication method in use for a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// Public client (localhost development). No assertion.
    None,
    /// Confidential client. ES256 assertion signed with the client's key.
    PrivateKeyJwt,
}

impl AuthMethod {
    /// Which method this client shape uses.
    ///
    /// Must agree with the `token_endpoint_auth_method` published by
    /// [`super::metadata`], or the authorization server is told one thing and
    /// sent another.
    pub fn negotiate(dev: bool) -> Self {
        if dev {
            AuthMethod::None
        } else {
            AuthMethod::PrivateKeyJwt
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::None => "none",
            AuthMethod::PrivateKeyJwt => "private_key_jwt",
        }
    }
}

/// Parse the wire name, for reading back the method stored in a state row.
impl std::str::FromStr for AuthMethod {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "none" => Ok(AuthMethod::None),
            "private_key_jwt" => Ok(AuthMethod::PrivateKeyJwt),
            other => bail!("unsupported client-auth method {other:?}"),
        }
    }
}

/// The client-credential form parameters for a request.
///
/// A public client sends only its `client_id` — attaching an assertion it never
/// registered is what makes every dev login fail at PAR. A confidential client
/// that somehow has no assertion is an error rather than a silently
/// unauthenticated request.
pub fn credential_params(
    method: AuthMethod,
    client_id: &str,
    assertion: Option<&str>,
) -> Result<Vec<(&'static str, String)>> {
    let mut params = vec![("client_id", client_id.to_string())];
    if method == AuthMethod::PrivateKeyJwt {
        let Some(assertion) = assertion else {
            bail!("private_key_jwt requires a client assertion, but none was supplied");
        };
        params.push(("client_assertion_type", JWT_BEARER.to_string()));
        params.push(("client_assertion", assertion.to_string()));
    }
    Ok(params)
}

/// Mint a `private_key_jwt` client assertion.
///
/// `aud` is the **issuer**, not the token endpoint. RFC 7523 permits either
/// reading; atproto settles it — *"the `aud` claim of the client assertion JWT
/// must be the Authorization Server's `issuer`"* — which also means one audience
/// covers PAR, token, refresh and revocation alike.
///
/// A fresh `jti` per call, because that claim exists to stop replay.
///
/// **But NOT per retry.** The nonce-challenge retry in
/// [`super::request::send_with_dpop`] re-sends the identical form body and
/// re-mints only the DPoP proof, so the assertion — and its `jti` — is replayed
/// verbatim. This matches the reference client, which does the same, but an
/// authorization server that enforces single-use `jti` on client assertions
/// would answer the retry with `invalid_client` and turn a recoverable nonce
/// challenge into a failed login.
///
/// This comment previously claimed the opposite. It was wrong, and the retry
/// path is structurally unable to reach the assertion builder.
///
/// The header carries `kid` and nothing else beyond `alg` (which
/// [`super::jwt::sign`] owns). The reference sends no `typ` here, and keeping it
/// absent leaves `typ` meaningful where it IS load-bearing — `dpop+jwt` on a
/// DPoP proof. `nbf` is not required and is not sent.
pub fn client_assertion(
    key: &SigningKey,
    client_id: &str,
    issuer: &str,
    now: i64,
) -> Result<String> {
    let mut jti = [0u8; 16];
    getrandom::fill(&mut jti).expect("OS CSPRNG unavailable; refusing to mint a client assertion");

    jwt::sign(
        key,
        &json!({ "kid": key.kid() }),
        &json!({
            "iss": client_id,
            "sub": client_id,
            "aud": issuer,
            "jti": URL_SAFE_NO_PAD.encode(jti),
            "iat": now,
            "exp": now + ASSERTION_LIFETIME_SECS,
        }),
    )
}

/// What a request's client authentication was, read from the form it sent:
/// the method, and the assertion TYPE (never the assertion).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAuthEvidence<'a> {
    /// `private_key_jwt` when the form carries an assertion type, else `none`.
    pub method: &'static str,
    /// The `client_assertion_type` sent, if any.
    pub assertion_type: Option<&'a str>,
}

/// [`ClientAuthEvidence`] for a form about to be sent. Read from the form
/// itself, not from the configured method, so the evidence is what went on
/// the wire (#262).
pub fn evidence<'a>(params: &'a [(&str, String)]) -> ClientAuthEvidence<'a> {
    let assertion_type = params
        .iter()
        .find(|(k, _)| *k == "client_assertion_type")
        .map(|(_, v)| v.as_str());
    ClientAuthEvidence {
        method: if assertion_type.is_some() {
            AuthMethod::PrivateKeyJwt.as_str()
        } else {
            AuthMethod::None.as_str()
        },
        assertion_type,
    }
}

/// Log a client-authenticated request's evidence and the status it got (#262).
///
/// **Why:** a login that succeeds does not show that `private_key_jwt` was the
/// method used (design/ROLLOUT-0.3.0.md, Stage 4), and revocation logged only
/// its failures, so neither could be shown from production. This line is the
/// evidence: the method and assertion type sent, the endpoint's host, and the
/// status the server answered. A `2xx` with `private_key_jwt` means the
/// server fetched our client metadata and JWKS and verified the assertion.
///
/// **No secret is logged:** not the assertion, the code, the verifier, a
/// token, or the DPoP key; only the host of the endpoint, never its path or
/// query.
pub fn log_evidence(step: &'static str, evidence: ClientAuthEvidence<'_>, url: &str, status: u16) {
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();
    tracing::info!(
        step,
        client_auth = evidence.method,
        assertion_type = evidence.assertion_type.unwrap_or("-"),
        endpoint_host = %host,
        status,
        "oauth client authentication"
    );
    #[cfg(test)]
    EVIDENCE_SEEN.with(|seen| {
        if let Some(seen) = seen.borrow_mut().as_mut() {
            seen.push(LoggedEvidence {
                step,
                client_auth: evidence.method,
                assertion_type: evidence.assertion_type.map(str::to_owned),
                endpoint_host: host.clone(),
                status,
            });
        }
    });
}

/// One [`log_evidence`] call's fields, exactly as logged: what a test reads
/// back through [`record_evidence`].
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoggedEvidence {
    pub step: &'static str,
    pub client_auth: &'static str,
    pub assertion_type: Option<String>,
    pub endpoint_host: String,
    pub status: u16,
}

#[cfg(test)]
thread_local! {
    static EVIDENCE_SEEN: std::cell::RefCell<Option<Vec<LoggedEvidence>>> =
        const { std::cell::RefCell::new(None) };
}

/// Record every [`log_evidence`] call on this thread while `f` runs, and
/// return them with `f`'s output.
///
/// **Not a tracing subscriber**: `tracing` caches, per call site and
/// process-wide, whether anyone listens, and other tests reaching the same line
/// on threads with no subscriber made a thread-local capture see nothing in CI
/// (it passed locally). This sees exactly the calls the code made, on this
/// thread, which a `#[tokio::test]` (current-thread) runtime keeps every task
/// on.
#[cfg(test)]
pub(crate) async fn record_evidence<F: std::future::Future>(
    f: F,
) -> (F::Output, Vec<LoggedEvidence>) {
    EVIDENCE_SEEN.with(|seen| *seen.borrow_mut() = Some(Vec::new()));
    let out = f.await;
    let seen = EVIDENCE_SEEN.with(|seen| seen.borrow_mut().take().unwrap_or_default());
    (out, seen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const CLIENT_ID: &str = "https://feather-reader.com/oauth/client-metadata.json";
    const ISSUER: &str = "https://auth.example.com";
    const KID: &str = "featherreader-oauth-1";
    const NOW: i64 = 1_700_000_000;

    fn part(jws: &str, index: usize) -> Value {
        let raw = URL_SAFE_NO_PAD
            .decode(jws.split('.').nth(index).unwrap())
            .unwrap();
        serde_json::from_slice(&raw).unwrap()
    }

    // ── negotiation ──────────────────────────────────────────────────────────

    /// Must agree with what `metadata.rs` publishes as
    /// `token_endpoint_auth_method`, or the AS is told one thing and sent
    /// another.
    #[test]
    fn the_method_follows_the_client_shape() {
        assert_eq!(AuthMethod::negotiate(true), AuthMethod::None);
        assert_eq!(AuthMethod::negotiate(false), AuthMethod::PrivateKeyJwt);
        assert_eq!(AuthMethod::None.as_str(), "none");
        assert_eq!(AuthMethod::PrivateKeyJwt.as_str(), "private_key_jwt");
    }

    #[test]
    fn the_method_round_trips_through_its_wire_name() {
        for method in [AuthMethod::None, AuthMethod::PrivateKeyJwt] {
            assert_eq!(method.as_str().parse::<AuthMethod>().unwrap(), method);
        }
        assert!("client_secret_basic".parse::<AuthMethod>().is_err());
        assert!("".parse::<AuthMethod>().is_err());
    }

    // ── credential parameters ────────────────────────────────────────────────

    /// A public client sends ONLY its id. Attaching an assertion it cannot
    /// register is what makes a dev login fail at PAR.
    #[test]
    fn a_public_client_sends_only_its_client_id() {
        let params = credential_params(AuthMethod::None, CLIENT_ID, None).unwrap();
        assert_eq!(params, vec![("client_id", CLIENT_ID.to_string())]);

        // Even if an assertion is offered, `none` must not send one.
        let params = credential_params(AuthMethod::None, CLIENT_ID, Some("jws")).unwrap();
        assert_eq!(params.len(), 1);
        assert!(!params
            .iter()
            .any(|(k, _)| k.starts_with("client_assertion")));
    }

    #[test]
    fn a_confidential_client_sends_the_assertion_and_its_type() {
        let params =
            credential_params(AuthMethod::PrivateKeyJwt, CLIENT_ID, Some("the-jws")).unwrap();
        assert_eq!(
            params,
            vec![
                ("client_id", CLIENT_ID.to_string()),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string()
                ),
                ("client_assertion", "the-jws".to_string()),
            ]
        );
    }

    /// Failing loudly beats silently sending an unauthenticated request that
    /// the AS would reject with a less legible error.
    #[test]
    fn a_confidential_client_without_an_assertion_is_an_error() {
        assert!(credential_params(AuthMethod::PrivateKeyJwt, CLIENT_ID, None).is_err());
    }

    // ── the assertion ────────────────────────────────────────────────────────

    #[test]
    fn the_assertion_carries_the_required_claims() {
        let key = SigningKey::generate(KID);
        let jws = client_assertion(&key, CLIENT_ID, ISSUER, NOW).unwrap();
        let claims = part(&jws, 1);

        // RFC 7523 §3: iss, sub, aud, exp are REQUIRED. atproto additionally
        // requires iat and jti.
        assert_eq!(claims["iss"], CLIENT_ID);
        assert_eq!(claims["sub"], CLIENT_ID);
        assert_eq!(claims["iat"], NOW);
        assert_eq!(claims["exp"], NOW + 60);
        assert!(claims["jti"].as_str().is_some_and(|j| j.len() >= 22));
    }

    /// **`aud` is the ISSUER, not the token endpoint.** RFC 7523 permits either
    /// reading; atproto settles it — "the `aud` claim of the client assertion
    /// JWT must be the Authorization Server's `issuer`". The same audience is
    /// therefore used for PAR, token, refresh and revocation.
    #[test]
    fn the_audience_is_the_issuer() {
        let key = SigningKey::generate(KID);
        let claims = part(&client_assertion(&key, CLIENT_ID, ISSUER, NOW).unwrap(), 1);
        assert_eq!(claims["aud"], ISSUER);
    }

    /// `nbf` is not required and the reference does not send it; a header `typ`
    /// is likewise absent there. Keeping the header minimal also keeps `typ`
    /// meaningful where it IS load-bearing — `dpop+jwt` on a DPoP proof.
    #[test]
    fn the_header_carries_kid_and_alg_and_nothing_else() {
        let key = SigningKey::generate(KID);
        let jws = client_assertion(&key, CLIENT_ID, ISSUER, NOW).unwrap();
        let header = part(&jws, 0);

        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], KID);
        assert!(header.get("typ").is_none(), "header should carry no typ");
        assert_eq!(header.as_object().unwrap().len(), 2);
        assert!(part(&jws, 1).get("nbf").is_none());
    }

    /// `jti` exists to stop replay, so it must be fresh per assertion — every
    /// request mints a new one, including the retry after a nonce challenge.
    #[test]
    fn every_assertion_gets_a_fresh_jti() {
        let key = SigningKey::generate(KID);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let claims = part(&client_assertion(&key, CLIENT_ID, ISSUER, NOW).unwrap(), 1);
            let jti = claims["jti"].as_str().unwrap().to_string();
            assert!(seen.insert(jti), "jti repeated across assertions");
        }
    }

    #[test]
    fn the_assertion_verifies_under_the_clients_key() {
        let key = SigningKey::generate(KID);
        let jws = client_assertion(&key, CLIENT_ID, ISSUER, NOW).unwrap();
        assert!(jwt::verify(&key, &jws).is_ok());
        assert!(jwt::verify(&SigningKey::generate(KID), &jws).is_err());
    }

    /// The `kid` must name a key in the published JWKS, or the AS cannot select
    /// one to verify with.
    #[test]
    fn the_header_kid_matches_the_signing_key() {
        let key = SigningKey::generate("some-other-kid");
        let jws = client_assertion(&key, CLIENT_ID, ISSUER, NOW).unwrap();
        assert_eq!(part(&jws, 0)["kid"], "some-other-kid");
        assert_eq!(part(&jws, 0)["kid"], key.kid());
    }

    /// The evidence is read from the form: an assertion type means
    /// `private_key_jwt`, its absence `none`, and the assertion itself is not
    /// part of it.
    #[test]
    fn evidence_is_read_from_the_form_sent() {
        let jwt = credential_params(AuthMethod::PrivateKeyJwt, CLIENT_ID, Some("the-jws")).unwrap();
        let e = evidence(&jwt);
        assert_eq!(e.method, "private_key_jwt");
        assert_eq!(e.assertion_type, Some(JWT_BEARER));
        assert!(
            !format!("{e:?}").contains("the-jws"),
            "the assertion leaked into the evidence"
        );

        let public = credential_params(AuthMethod::None, CLIENT_ID, None).unwrap();
        assert_eq!(
            evidence(&public),
            ClientAuthEvidence {
                method: "none",
                assertion_type: None
            }
        );
    }
}
