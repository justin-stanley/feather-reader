//! The login flow's decisions: PKCE, browser binding, PAR, and the callback.
//!
//! Everything here is pure — parameters in, parameters out — so it can be tested
//! without a network. The SSRF guard forbids pointing any of this at a loopback
//! test server, so decisions that live inside an HTTP round trip are effectively
//! untestable; keeping them out here is deliberate.
//!
//! The security-critical piece is [`verify_callback`]. A server-side client
//! stores `state` in a table that is global to the process, not per-browser, so
//! an unguessable single-use `state` is **not** sufficient on its own: an
//! attacker can start a login with their own account and induce a victim's
//! browser to fetch the resulting callback URL, and the victim ends up holding a
//! session for the attacker's account — reading their feeds, writing into their
//! repo. The browser-binding cookie is what closes that.

use anyhow::{bail, Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest::{digest, SHA256};
use serde_json::Value;
use subtle::ConstantTimeEq;

/// 32 CSPRNG bytes as unpadded base64url is 43 characters — the minimum RFC 7636
/// permits, and the standard choice.
const VERIFIER_BYTES: usize = 32;

/// Draw `N` CSPRNG bytes as unpadded base64url.
fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("OS CSPRNG unavailable; refusing to mint an OAuth secret");
    URL_SAFE_NO_PAD.encode(&buf)
}

/// A fresh PKCE code verifier.
///
/// The spec requires a NEW challenge for every authorization request, so this is
/// never cached or reused — not even across retries of the same login.
pub fn new_pkce_verifier() -> String {
    random_token(VERIFIER_BYTES)
}

/// The S256 challenge for a verifier: `base64url(sha256(ascii(verifier)))`.
///
/// `plain` is not merely unused — atproto forbids it — so there is no method
/// parameter here to get wrong.
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()).as_ref())
}

/// A fresh browser-binding token, to be set as a cookie before the redirect.
pub fn new_binding_token() -> String {
    random_token(VERIFIER_BYTES)
}

/// The value stored in the state row: the hash, never the token itself.
pub fn binding_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, token.as_bytes()).as_ref())
}

/// Whether the cookie presented at the callback is the one this flow issued.
///
/// **An absent cookie never matches.** A callback with no cookie is, by
/// definition, not the browser that started the flow — treating that as "no
/// binding recorded, allow" would remove the protection entirely for exactly the
/// request it exists to stop. An empty stored hash does not become a wildcard
/// either.
pub fn binding_matches(stored_hash: &str, presented: Option<&str>) -> bool {
    let Some(presented) = presented.filter(|t| !t.is_empty()) else {
        return false;
    };
    if stored_hash.is_empty() {
        return false;
    }
    let computed = binding_hash(presented);
    computed.len() == stored_hash.len()
        && bool::from(computed.as_bytes().ct_eq(stored_hash.as_bytes()))
}

/// The inputs to a pushed authorization request.
pub struct ParRequest<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub state: &'a str,
    pub code_challenge: &'a str,
    /// The account identifier the user typed. A courtesy to the authorization
    /// server, never a security control — the AS only *should* honour it.
    pub login_hint: Option<&'a str>,
}

/// The non-credential half of a PAR body. Client credentials are appended by
/// [`super::client_auth::credential_params`], since they depend on the
/// negotiated method.
pub fn par_params(request: &ParRequest<'_>) -> Vec<(&'static str, String)> {
    let mut params = vec![
        ("response_type", "code".to_string()),
        ("code_challenge", request.code_challenge.to_string()),
        // A constant: `plain` is not allowed, so there is nothing to choose.
        ("code_challenge_method", "S256".to_string()),
        ("state", request.state.to_string()),
        ("redirect_uri", request.redirect_uri.to_string()),
        ("scope", request.scope.to_string()),
    ];
    if let Some(hint) = request.login_hint {
        params.push(("login_hint", hint.to_string()));
    }
    params
}

/// A validated PAR response.
pub struct ParResponse {
    pub request_uri: String,
    /// Bounds how long the pending-login row is worth keeping.
    pub expires_in: i64,
}

/// Validate a PAR response before building an authorize URL from it.
///
/// Without this, a missing `request_uri` produces an authorize URL containing
/// the string `undefined` and the failure surfaces at the authorization server
/// rather than here.
pub fn parse_par_response(body: &Value) -> Result<ParResponse> {
    let request_uri = body
        .get("request_uri")
        .and_then(Value::as_str)
        .context("PAR response has no `request_uri`")?;
    if request_uri.is_empty() {
        bail!("PAR response `request_uri` is empty");
    }
    let expires_in = body
        .get("expires_in")
        .and_then(Value::as_i64)
        .context("PAR response has no integer `expires_in`")?;
    if expires_in <= 0 {
        bail!("PAR response `expires_in` must be positive, got {expires_in}");
    }
    Ok(ParResponse {
        request_uri: request_uri.to_string(),
        expires_in,
    })
}

/// The URL to send the browser to after a successful PAR.
///
/// Only `client_id` and `request_uri` — everything else was already pushed, and
/// repeating parameters here is what PAR exists to avoid. Both are appended by
/// the serializer rather than interpolated: a `client_id` is itself a URL, and a
/// raw `&` in either value would splice in a parameter.
pub fn authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    request_uri: &str,
) -> Result<String> {
    let mut url = url::Url::parse(authorization_endpoint).with_context(|| {
        format!("authorization_endpoint {authorization_endpoint:?} is not a URL")
    })?;
    if url.scheme() != "https" {
        bail!("authorization_endpoint must be https, got {authorization_endpoint:?}");
    }
    url.query_pairs_mut()
        .clear()
        .append_pair("client_id", client_id)
        .append_pair("request_uri", request_uri);
    Ok(url.to_string())
}

/// What the authorization server sent back to the redirect URI.
#[derive(Debug, Default, Clone)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub iss: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    /// JARM. Unsupported, and its presence is a refusal rather than a parse.
    pub response: Option<String>,
}

/// Validate a callback and return the authorization code.
///
/// `iss` is **required**, not merely checked when present. atproto mandates
/// `authorization_response_iss_parameter_supported: true`, so a conformant
/// server always sends it — which means accepting a response without one lets an
/// attacker bypass the check by simply omitting the parameter. That is the
/// mix-up attack RFC 9207 exists to stop.
///
/// This does NOT check `state` or the browser binding: those need the stored row,
/// and the row must be consumed atomically first. See
/// [`super::store::take_pending`] and [`binding_matches`].
pub fn verify_callback(params: &CallbackParams, expected_issuer: &str) -> Result<String> {
    if params.response.is_some() {
        bail!("authorization response uses JARM, which is not supported");
    }
    // A `state` is needed to find the flow at all, so its absence is a rejection
    // rather than something to report against a flow we cannot identify.
    let state = params.state.as_deref().unwrap_or_default();
    if state.is_empty() {
        bail!("authorization response carries no `state`");
    }
    // An error wins over a code: a response carrying both is not one to
    // interpret.
    if let Some(error) = params.error.as_deref() {
        let description = params.error_description.as_deref().unwrap_or("");
        bail!("authorization server returned error {error:?} {description:?}");
    }

    let iss = params
        .iss
        .as_deref()
        .context("authorization response carries no `iss` (RFC 9207); refusing it")?;
    if iss != expected_issuer {
        bail!("authorization response `iss` is {iss:?}, expected {expected_issuer:?}");
    }

    let code = params.code.as_deref().unwrap_or_default();
    if code.is_empty() {
        bail!("authorization response carries no `code`");
    }
    Ok(code.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://auth.example.com";

    // ── PKCE ─────────────────────────────────────────────────────────────────

    /// RFC 7636 §4.1: 43–128 characters from the unreserved set.
    #[test]
    fn a_pkce_verifier_is_within_the_unreserved_alphabet_and_length() {
        for _ in 0..32 {
            let verifier = new_pkce_verifier();
            assert!(
                (43..=128).contains(&verifier.len()),
                "length {} out of range",
                verifier.len()
            );
            assert!(
                verifier
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')),
                "verifier outside the unreserved set: {verifier}"
            );
        }
    }

    /// Spec: "Clients must generate new, unique, random challenges for every
    /// authorization request" — so no reuse, even across retries of one login.
    #[test]
    fn every_pkce_verifier_is_fresh() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            assert!(seen.insert(new_pkce_verifier()), "verifier repeated");
        }
    }

    /// S256 is `base64url(sha256(ascii(verifier)))`, unpadded.
    #[test]
    fn the_challenge_is_the_s256_of_the_verifier() {
        // RFC 7636 Appendix B's worked example.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_challenge_is_unpadded_base64url() {
        let challenge = pkce_challenge(&new_pkce_verifier());
        assert_eq!(URL_SAFE_NO_PAD.decode(&challenge).unwrap().len(), 32);
        assert!(!challenge.contains('=') && !challenge.contains('+') && !challenge.contains('/'));
    }

    // ── browser binding ──────────────────────────────────────────────────────

    #[test]
    fn a_binding_token_is_fresh_and_unguessable() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let token = new_binding_token();
            assert!(token.len() >= 22, "token too short: {token}");
            assert!(seen.insert(token), "binding token repeated");
        }
    }

    #[test]
    fn a_binding_token_matches_only_its_own_hash() {
        let token = new_binding_token();
        let hash = binding_hash(&token);
        assert!(binding_matches(&hash, Some(&token)));
        assert!(!binding_matches(&hash, Some(&new_binding_token())));
        assert!(!binding_matches(&hash, Some("")));
    }

    /// **A callback with no cookie is by definition not the browser that started
    /// the flow.** This is the case the whole mechanism exists for, so it must
    /// reject rather than fall through to "no binding recorded, allow".
    #[test]
    fn a_missing_cookie_never_matches() {
        let hash = binding_hash(&new_binding_token());
        assert!(!binding_matches(&hash, None));
        // And an empty stored hash must not become a wildcard either.
        assert!(!binding_matches("", None));
        assert!(!binding_matches("", Some("anything")));
    }

    // ── PAR request ──────────────────────────────────────────────────────────

    fn par_input() -> ParRequest<'static> {
        ParRequest {
            client_id: "https://feather-reader.com/oauth/client-metadata.json",
            redirect_uri: "https://feather-reader.com/oauth/callback",
            scope: "atproto transition:generic",
            state: "state-value",
            code_challenge: "challenge-value",
            login_hint: Some("alice.bsky.social"),
        }
    }

    #[test]
    fn the_par_request_carries_the_required_parameters() {
        let params = par_params(&par_input());
        let get = |k: &str| {
            params
                .iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("response_type").as_deref(), Some("code"));
        assert_eq!(get("code_challenge_method").as_deref(), Some("S256"));
        assert_eq!(get("code_challenge").as_deref(), Some("challenge-value"));
        assert_eq!(get("state").as_deref(), Some("state-value"));
        assert_eq!(
            get("redirect_uri").as_deref(),
            Some("https://feather-reader.com/oauth/callback")
        );
        assert_eq!(get("scope").as_deref(), Some("atproto transition:generic"));
        assert_eq!(get("login_hint").as_deref(), Some("alice.bsky.social"));
    }

    /// `plain` is not allowed, so the method is a constant rather than a choice.
    #[test]
    fn the_challenge_method_is_always_s256() {
        let params = par_params(&par_input());
        assert!(!params.iter().any(|(_, v)| v == "plain"));
    }

    #[test]
    fn login_hint_is_omitted_when_absent_rather_than_sent_empty() {
        let mut input = par_input();
        input.login_hint = None;
        let params = par_params(&input);
        assert!(!params.iter().any(|(name, _)| *name == "login_hint"));
    }

    // ── PAR response ─────────────────────────────────────────────────────────

    #[test]
    fn a_valid_par_response_yields_its_request_uri_and_lifetime() {
        let body = serde_json::json!({
            "request_uri": "urn:ietf:params:oauth:request_uri:abc",
            "expires_in": 60
        });
        let parsed = parse_par_response(&body).unwrap();
        assert_eq!(parsed.request_uri, "urn:ietf:params:oauth:request_uri:abc");
        assert_eq!(parsed.expires_in, 60);
    }

    /// Without this, the authorize URL is built with `request_uri=undefined` and
    /// the failure surfaces at the authorization server instead of here.
    #[test]
    fn a_malformed_par_response_is_rejected() {
        for body in [
            serde_json::json!({}),
            serde_json::json!({ "expires_in": 60 }),
            serde_json::json!({ "request_uri": "urn:x" }),
            serde_json::json!({ "request_uri": 42, "expires_in": 60 }),
            serde_json::json!({ "request_uri": "urn:x", "expires_in": 0 }),
            serde_json::json!({ "request_uri": "urn:x", "expires_in": -1 }),
            serde_json::json!({ "request_uri": "", "expires_in": 60 }),
        ] {
            assert!(parse_par_response(&body).is_err(), "accepted {body}");
        }
    }

    // ── authorize redirect ───────────────────────────────────────────────────

    #[test]
    fn the_authorize_url_carries_only_client_id_and_request_uri() {
        let url = authorize_url(
            "https://auth.example.com/authorize",
            "https://feather-reader.com/oauth/client-metadata.json",
            "urn:ietf:params:oauth:request_uri:abc",
        )
        .unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        let names: Vec<String> = parsed.query_pairs().map(|(k, _)| k.into_owned()).collect();
        assert_eq!(names, vec!["client_id", "request_uri"]);
    }

    /// Both values contain characters that are not query-safe, so they must be
    /// encoded rather than interpolated.
    #[test]
    fn the_authorize_url_percent_encodes_its_parameters() {
        let url = authorize_url(
            "https://auth.example.com/authorize",
            "https://x.example/m.json?a=1&b=2",
            "urn:oauth:uri:with spaces",
        )
        .unwrap();
        assert!(
            url.contains("%3A%2F%2F"),
            "scheme separator unencoded: {url}"
        );
        assert!(!url.contains("with spaces"));
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(
            parsed.query_pairs().count(),
            2,
            "extra parameters spliced in"
        );
    }

    #[test]
    fn a_non_https_authorization_endpoint_is_refused() {
        assert!(authorize_url("http://auth.example.com/authorize", "cid", "uri").is_err());
        assert!(authorize_url("not a url", "cid", "uri").is_err());
    }

    // ── callback ─────────────────────────────────────────────────────────────

    fn ok_params() -> CallbackParams {
        CallbackParams {
            code: Some("the-code".into()),
            state: Some("state-value".into()),
            iss: Some(ISSUER.into()),
            error: None,
            error_description: None,
            response: None,
        }
    }

    #[test]
    fn a_well_formed_callback_is_accepted() {
        assert_eq!(verify_callback(&ok_params(), ISSUER).unwrap(), "the-code");
    }

    /// **RFC 9207 and atproto together make `iss` mandatory.** atproto requires
    /// `authorization_response_iss_parameter_supported: true`, so a conformant
    /// server always sends it — which means a MISSING `iss` must be rejected,
    /// not waved through. Checking only for a mismatch is bypassed by omitting
    /// the parameter, which is the whole mix-up attack.
    #[test]
    fn a_callback_without_iss_is_rejected() {
        let mut params = ok_params();
        params.iss = None;
        assert!(verify_callback(&params, ISSUER).is_err());
    }

    #[test]
    fn a_callback_from_the_wrong_issuer_is_rejected() {
        let mut params = ok_params();
        params.iss = Some("https://evil.example.com".into());
        assert!(verify_callback(&params, ISSUER).is_err());
    }

    /// The authorization server's deny path. Must be reported, not treated as a
    /// malformed request.
    #[test]
    fn an_error_response_is_surfaced_as_such() {
        let mut params = ok_params();
        params.code = None;
        params.error = Some("access_denied".into());
        let err = verify_callback(&params, ISSUER).unwrap_err();
        assert!(format!("{err:#}").contains("access_denied"));
    }

    /// An `error` wins even when a `code` is also present: a response carrying
    /// both is not one we should try to make sense of.
    #[test]
    fn an_error_takes_precedence_over_a_code() {
        let mut params = ok_params();
        params.error = Some("invalid_request".into());
        assert!(verify_callback(&params, ISSUER).is_err());
    }

    /// JARM is not supported; a `response` parameter means the server answered
    /// in a form this code does not parse, and guessing would be worse.
    #[test]
    fn a_jarm_response_is_refused() {
        let mut params = ok_params();
        params.response = Some("signed-jwt".into());
        assert!(verify_callback(&params, ISSUER).is_err());
    }

    #[test]
    fn a_callback_without_a_code_is_rejected() {
        let mut params = ok_params();
        params.code = None;
        assert!(verify_callback(&params, ISSUER).is_err());
        params.code = Some(String::new());
        assert!(verify_callback(&params, ISSUER).is_err());
    }

    #[test]
    fn a_callback_without_a_state_is_rejected() {
        let mut params = ok_params();
        params.state = None;
        assert!(verify_callback(&params, ISSUER).is_err());
    }
}
