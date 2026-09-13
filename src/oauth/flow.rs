//! The login flow's decisions: PKCE, browser binding, PAR, and the callback.
//!
//! Everything here is pure — parameters in, parameters out — so it can be tested
//! without a network. The SSRF guard forbids pointing any of this at a loopback
//! test server, so decisions that live inside an HTTP round trip are effectively
//! untestable; keeping them out here is deliberate.
//!
//! The security-critical piece is [`complete_callback`]. A server-side client
//! stores `state` in a table that is global to the process, not per-browser, so
//! an unguessable single-use `state` is **not** sufficient on its own: an
//! attacker can start a login with their own account and induce a victim's
//! browser to fetch the resulting callback URL, and the victim ends up holding a
//! session for the attacker's account — reading their feeds, writing into their
//! repo. The browser-binding cookie is what closes that, and
//! [`complete_callback`] exists so the check cannot be left out — it consumes
//! the pending row, verifies the binding, and validates the response as one
//! operation, rather than three functions a caller must remember to chain.

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

/// A fresh `state`.
///
/// Unguessable is not optional: the spec requires that it "can not be forged or
/// guessed by an untrusted party", and it is also the row key the at-rest AAD
/// binds against, so its entropy is load-bearing in two places.
pub fn new_state() -> String {
    random_token(VERIFIER_BYTES)
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
        // Explicit, not left to the server. A server-side handler cannot read a
        // fragment, so `response_mode=fragment` makes the callback structurally
        // invisible -- the flow fails with "no state" and the code that would
        // explain it never reaches us.
        ("response_mode", "query".to_string()),
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

/// OAuth error codes we will echo verbatim. Anything else is reduced, because
/// the `error` parameter is server-controlled free text like any other.
const KNOWN_ERRORS: [&str; 11] = [
    "access_denied",
    "consent_required",
    "interaction_required",
    "invalid_grant",
    "invalid_request",
    "invalid_scope",
    "login_required",
    "server_error",
    "temporarily_unavailable",
    "unauthorized_client",
    "unsupported_response_type",
];

/// Reduce a server-supplied error code to a known slug.
fn known_error_slug(raw: &str) -> &'static str {
    KNOWN_ERRORS
        .iter()
        .find(|known| **known == raw)
        .copied()
        .unwrap_or("unrecognized_error")
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
    // `iss` is validated BEFORE any error is reported. RFC 9207 §2.4: "For error
    // responses, clients MUST NOT assume that the error originates from the
    // intended authorization server." Reporting first would let anyone able to
    // make a browser fetch this URL tell the user their own server denied them.
    let iss = params
        .iss
        .as_deref()
        .context("authorization response carries no `iss` (RFC 9207); refusing it")?;
    if iss != expected_issuer {
        bail!("authorization response `iss` is {iss:?}, expected {expected_issuer:?}");
    }

    // An error wins over a code: a response carrying both is not one to
    // interpret. Only a KNOWN code is echoed, and the free-form
    // `error_description` is dropped entirely -- both are server-controlled
    // text, and whatever the caller does with an error message should not
    // inherit an injection surface from them.
    if let Some(error) = params.error.as_deref() {
        bail!(
            "authorization server returned error {:?}",
            known_error_slug(error)
        );
    }

    let code = params.code.as_deref().unwrap_or_default();
    if code.is_empty() {
        bail!("authorization response carries no `code`");
    }
    Ok(code.to_string())
}

/// Consume the pending login, check the browser binding, and validate the
/// callback — in that order, as one operation.
///
/// These three steps were previously three free functions with nothing forcing
/// the middle one to happen. That matters more than it sounds: the binding check
/// is the single control standing between a server-global `state` table and a
/// login-CSRF that hands a victim a session for the attacker's account. A caller
/// that forgot it would still compile, still pass every test, and still work
/// perfectly for every non-malicious login. Returning the code only from here
/// makes the omission unrepresentable rather than merely discouraged.
///
/// The row is consumed **whatever happens next**, including a binding failure —
/// so a mismatched cookie cannot simply be retried.
pub async fn complete_callback(
    pool: &sqlx::SqlitePool,
    codec: &super::crypto::Codec,
    params: &CallbackParams,
    presented_cookie: Option<&str>,
    now: i64,
) -> Result<(super::store::PendingAuth, String)> {
    if params.response.is_some() {
        bail!("authorization response uses JARM, which is not supported");
    }
    let state = params.state.as_deref().unwrap_or_default();
    if state.is_empty() {
        bail!("authorization response carries no `state`");
    }

    let pending = super::store::take_pending(pool, codec, state, now)
        .await?
        .context("no pending login for that `state` (unknown, expired, or already used)")?;

    if !binding_matches(&pending.browser_binding_hash, presented_cookie) {
        bail!(
            "the callback did not present the browser-binding cookie for this login; \
             refusing to complete a flow this browser did not start"
        );
    }

    let code = verify_callback(params, &pending.issuer)?;
    Ok((pending, code))
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

    /// Asserts the ACTUAL length, not a lower bound a regression could slip
    /// under: 32 CSPRNG bytes is 43 base64url characters, and a `>= 22` bound
    /// would have accepted a silent drop to 16 bytes.
    #[test]
    fn a_binding_token_is_fresh_and_unguessable() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let token = new_binding_token();
            assert_eq!(token.len(), 43, "binding token is not 32 bytes: {token}");
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

    /// A prefix of the real hash must not match — a `starts_with` comparison
    /// would let a one-character stored value accept everything.
    #[test]
    fn a_truncated_stored_hash_does_not_match() {
        let token = new_binding_token();
        let hash = binding_hash(&token);
        for len in [1, 8, hash.len() - 1] {
            assert!(
                !binding_matches(&hash[..len], Some(&token)),
                "a {len}-character prefix matched"
            );
        }
    }

    /// **The mistake the hash-vs-raw design exists to prevent.** If the stored
    /// value were the token itself rather than its hash, a database read would
    /// yield a directly replayable cookie. Storing the raw token must therefore
    /// NOT authenticate.
    #[test]
    fn a_raw_token_stored_as_the_hash_does_not_match() {
        let token = new_binding_token();
        assert!(!binding_matches(&token, Some(&token)));
    }

    /// A state value must be unguessable and fresh; it is also the row key that
    /// the AAD binds against, so its entropy is load-bearing twice over.
    #[test]
    fn every_state_is_fresh_and_full_length() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let state = new_state();
            assert_eq!(state.len(), 43, "state is not 32 bytes of base64url");
            assert!(seen.insert(state), "state repeated");
        }
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

    /// **`response_mode=query` must be explicit.** A server-side handler cannot
    /// read a fragment at all: with `fragment`, the browser lands on
    /// `/oauth/callback#code=…` and the server sees no parameters whatsoever.
    /// The flow then dies with "no state", and the one diagnostic that would
    /// explain it is structurally invisible. The atproto spec does not
    /// constrain the AS's default, so nothing but this parameter does.
    #[test]
    fn the_response_mode_is_pinned_to_query() {
        let params = par_params(&par_input());
        assert_eq!(
            params
                .iter()
                .find(|(name, _)| *name == "response_mode")
                .map(|(_, v)| v.as_str()),
            Some("query")
        );
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

    /// **RFC 9207 §2.4: "For error responses, clients MUST NOT assume that the
    /// error originates from the intended authorization server."** So `iss` is
    /// validated BEFORE an error is reported — otherwise anyone who can make a
    /// browser fetch the callback URL can tell the user their own server denied
    /// them, having proved nothing.
    #[test]
    fn an_error_from_the_wrong_issuer_is_reported_as_a_mismatch() {
        let mut params = ok_params();
        params.code = None;
        params.error = Some("access_denied".into());
        params.iss = Some("https://evil.example.com".into());
        let rendered = format!("{:#}", verify_callback(&params, ISSUER).unwrap_err());
        assert!(
            rendered.contains("iss"),
            "reported the error before checking who sent it: {rendered}"
        );
        assert!(!rendered.contains("access_denied"));
    }

    /// The free-form `error_description` is server-controlled text. Passing it
    /// through means whatever the orchestration layer does with an error message
    /// inherits an injection surface, so it is dropped at this boundary and the
    /// code is reduced to a known slug.
    #[test]
    fn server_supplied_error_text_is_not_passed_through() {
        let mut params = ok_params();
        params.code = None;
        params.error = Some("access_denied".into());
        params.error_description = Some("<img src=x onerror=alert(1)>".into());
        let rendered = format!("{:#}", verify_callback(&params, ISSUER).unwrap_err());
        assert!(
            !rendered.contains("<img"),
            "raw description leaked: {rendered}"
        );
        assert!(!rendered.contains("onerror"));
    }

    /// An unrecognized error code is itself free-form, so it is reduced too
    /// rather than echoed.
    #[test]
    fn an_unknown_error_code_is_reduced_to_a_slug() {
        let mut params = ok_params();
        params.code = None;
        params.error = Some("<script>alert(1)</script>".into());
        let rendered = format!("{:#}", verify_callback(&params, ISSUER).unwrap_err());
        assert!(
            !rendered.contains("<script>"),
            "raw code leaked: {rendered}"
        );
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

    // ── complete_callback: the three steps as one ────────────────────────────

    async fn pending_db(cookie_hash: &str) -> (sqlx::SqlitePool, crate::oauth::crypto::Codec) {
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::oauth::store::init_schema(&pool).await.unwrap();
        let codec = crate::oauth::crypto::Codec::new(Some("a".repeat(43).as_str())).unwrap();
        let pending = crate::oauth::store::PendingAuth {
            state: "state-value".into(),
            browser_binding_hash: cookie_hash.into(),
            pkce_verifier: "verifier".into(),
            dpop_key_jwk: "{}".into(),
            issuer: ISSUER.into(),
            pds_url: "https://pds.example.com".into(),
            did: "did:plc:ewvi7nxzyoun6zhxrhs64oiz".into(),
            auth_method: "private_key_jwt".into(),
            auth_kid: None,
            redirect_uri: "https://feather-reader.com/oauth/callback".into(),
            requested_scope: "atproto".into(),
            request_uri: "urn:x".into(),
            app_return_to: None,
            expires_at: 2_000_000_000,
        };
        crate::oauth::store::put_pending(&pool, &codec, &pending)
            .await
            .unwrap();
        (pool, codec)
    }

    #[tokio::test]
    async fn complete_callback_returns_the_code_for_the_right_browser() {
        let cookie = new_binding_token();
        let (pool, codec) = pending_db(&binding_hash(&cookie)).await;
        let (pending, code) =
            complete_callback(&pool, &codec, &ok_params(), Some(&cookie), 1_700_000_000)
                .await
                .unwrap();
        assert_eq!(code, "the-code");
        assert_eq!(pending.pkce_verifier, "verifier");
    }

    /// **The login-CSRF case.** Another browser fetching the callback URL has no
    /// cookie, so it must not complete the flow -- and the row must be gone, so
    /// the real browser cannot be raced afterwards either.
    #[tokio::test]
    async fn complete_callback_refuses_a_browser_that_did_not_start_the_flow() {
        let cookie = new_binding_token();
        for presented in [None, Some(new_binding_token())] {
            let (pool, codec) = pending_db(&binding_hash(&cookie)).await;
            assert!(complete_callback(
                &pool,
                &codec,
                &ok_params(),
                presented.as_deref(),
                1_700_000_000
            )
            .await
            .is_err());

            // Consumed regardless, so a mismatched cookie cannot be retried.
            assert!(
                complete_callback(&pool, &codec, &ok_params(), Some(&cookie), 1_700_000_000)
                    .await
                    .is_err(),
                "the pending row survived a failed binding check"
            );
        }
    }

    /// **The expected issuer comes from the PENDING ROW, not from the callback.**
    ///
    /// Every existing test here stores `issuer: ISSUER` and sends
    /// `iss: Some(ISSUER)` — the same constant on both sides, so none of them
    /// can tell which one the check actually used. A mutation validating `iss`
    /// against ITSELF passed all of them, which would defeat RFC 9207 entirely:
    /// the point of the parameter is to notice that the response came from a
    /// different authorization server than the one the request was pushed to.
    #[tokio::test]
    async fn complete_callback_validates_iss_against_the_stored_issuer() {
        let cookie = new_binding_token();
        let (pool, codec) = pending_db(&binding_hash(&cookie)).await;

        // The row was pushed to ISSUER; the callback claims a different one.
        let impostor = CallbackParams {
            iss: Some("https://evil.example".into()),
            ..ok_params()
        };
        let err = complete_callback(&pool, &codec, &impostor, Some(&cookie), 1_700_000_000)
            .await
            .expect_err("an `iss` from another authorization server must be refused");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("evil.example") || rendered.contains("iss"),
            "failed for the wrong reason: {rendered}"
        );
    }

    #[tokio::test]
    async fn complete_callback_rejects_an_unknown_or_expired_state() {
        let cookie = new_binding_token();
        let (pool, codec) = pending_db(&binding_hash(&cookie)).await;

        let mut unknown = ok_params();
        unknown.state = Some("never-existed".into());
        assert!(
            complete_callback(&pool, &codec, &unknown, Some(&cookie), 1_700_000_000)
                .await
                .is_err()
        );

        // Expired: `now` past the row's expiry.
        assert!(
            complete_callback(&pool, &codec, &ok_params(), Some(&cookie), 2_000_000_001)
                .await
                .is_err()
        );
    }

    /// The binding is checked BEFORE the code is returned, so a wrong issuer or
    /// an error response cannot be used to probe with the wrong cookie either.
    #[tokio::test]
    async fn complete_callback_checks_the_binding_before_anything_else_about_the_response() {
        let cookie = new_binding_token();
        let (pool, codec) = pending_db(&binding_hash(&cookie)).await;

        let mut denied = ok_params();
        denied.code = None;
        denied.error = Some("access_denied".into());
        let rendered = format!(
            "{:#}",
            complete_callback(&pool, &codec, &denied, None, 1_700_000_000)
                .await
                .unwrap_err()
        );
        assert!(
            rendered.contains("browser-binding"),
            "reported the response before checking the browser: {rendered}"
        );
    }
}
