//! Token exchange, refresh, and what a token response has to prove.
//!
//! The validation here is stricter than "did it parse", because several fields
//! are load-bearing in ways that fail silently if waved through:
//!
//! * `token_type` must be exactly `DPoP`. Accepting `Bearer` discards the
//!   proof-of-possession binding — the only thing making a stolen access token
//!   useless.
//! * `scope` must contain `atproto`, and the **granted** scope is what gets
//!   stored. Recording the requested scope instead means a narrowed grant is
//!   discovered as a mystery failure much later.
//! * `sub` must be a well-formed atproto DID before it becomes a database key.
//! * `id_token` must be absent — its presence means the server thinks it is
//!   doing OIDC, and nothing good follows from proceeding.
//! * `expires_in` is **optional**; a missing one means no proactive refresh, not
//!   a fabricated expiry.

use anyhow::{bail, Context as _, Result};
use serde_json::Value;

use super::identity::is_atproto_did;

/// The scope atproto requires every session to hold.
const ATPROTO_SCOPE: &str = "atproto";

/// Largest `expires_in` a token response may claim: one year.
///
/// An upper bound exists because the value is added to the current time. Real
/// atproto access tokens last an hour, so anything near this is already absurd;
/// the cap only has to be low enough that `now + seconds` cannot overflow.
const MAX_EXPIRES_IN_SECS: i64 = 365 * 24 * 60 * 60;

/// Refresh at least this far ahead of expiry.
pub const MIN_REFRESH_MARGIN_SECS: i64 = 10;

/// Extra, randomized margin on top of [`MIN_REFRESH_MARGIN_SECS`].
///
/// Not decoration: without it, every instance holding the same session decides
/// to refresh in the same second, and a single-use refresh token turns that into
/// a race where all but one lose.
pub const REFRESH_JITTER_SECS: i64 = 30;

/// Form parameters for the authorization-code exchange.
///
/// Client credentials come from [`super::client_auth::credential_params`]; they
/// depend on the negotiated method and are not this function's business.
pub fn token_request_params(
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Vec<(&'static str, String)> {
    vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        // Must be byte-identical to the value sent in PAR.
        ("redirect_uri", redirect_uri.to_string()),
        ("code_verifier", code_verifier.to_string()),
    ]
}

/// Form parameters for a refresh.
///
/// No `scope`: the reference sends none, and offering one invites the server to
/// re-scope a grant that is already settled.
pub fn refresh_request_params(refresh_token: &str) -> Vec<(&'static str, String)> {
    vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
    ]
}

/// A validated token response.
pub struct TokenResponse {
    pub access_token: String,
    /// Absent on a refresh that does not rotate; the caller keeps the old one.
    pub refresh_token: Option<String>,
    pub token_type: String,
    /// The **granted** scope. Never the requested one — a narrowed grant must be
    /// visible now rather than as a mystery write failure later.
    pub granted_scope: String,
    pub sub: String,
    /// Optional. Absent means no proactive refresh, not a fabricated expiry.
    pub expires_in: Option<i64>,
}

/// Validate a token response before anything is stored or sent.
///
/// Does **not** compare `sub` against the DID the login started from. That is
/// deliberate: `login_hint` is only a *should*, so a user who typed handle A may
/// legitimately be signed in to the authorization server as account B, and
/// hard-failing would break a normal case. The caller must instead verify
/// independently that this issuer is authoritative for the returned `sub`.
pub fn parse_token_response(body: &Value) -> Result<TokenResponse> {
    let field = |name: &str| body.get(name).and_then(Value::as_str);

    if body.get("id_token").is_some() {
        bail!("token response carries an `id_token`; this is not an OIDC client");
    }

    let token_type = field("token_type").context("token response has no `token_type`")?;
    if token_type != "DPoP" {
        bail!(
            "token_type must be exactly \"DPoP\", got {token_type:?} — accepting \
             anything else would discard the proof-of-possession binding"
        );
    }

    let granted_scope = field("scope").context("token response has no `scope`")?;
    if !granted_scope
        .split_ascii_whitespace()
        .any(|s| s == ATPROTO_SCOPE)
    {
        bail!("granted scope {granted_scope:?} does not include {ATPROTO_SCOPE:?}");
    }

    let sub = field("sub").context("token response has no `sub`")?;
    if !is_atproto_did(sub) {
        bail!("token response `sub` {sub:?} is not a well-formed atproto DID");
    }

    let access_token = field("access_token").context("token response has no `access_token`")?;
    if access_token.is_empty() {
        bail!("token response `access_token` is empty");
    }

    let expires_in = match body.get("expires_in") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let seconds = value
                .as_i64()
                .with_context(|| format!("`expires_in` is not an integer: {value}"))?;
            if seconds <= 0 {
                bail!("`expires_in` must be positive, got {seconds}");
            }
            // **And bounded.** Both consumers compute `now + seconds`. With
            // overflow checks off — which is every release build, since the
            // crate declares no `[profile]` — `i64::MAX` wraps to a large
            // NEGATIVE expiry, `is_stale` becomes permanently true, and every
            // subsequent request performs a full refresh round trip to the
            // server that sent it.
            if seconds > MAX_EXPIRES_IN_SECS {
                bail!(
                    "`expires_in` of {seconds}s is beyond anything a session should claim \
                     (cap {MAX_EXPIRES_IN_SECS}s)"
                );
            }
            Some(seconds)
        }
    };

    Ok(TokenResponse {
        access_token: access_token.to_string(),
        // An EMPTY refresh token is absent, not a value. `access_token` is
        // already checked for emptiness; this one was not, and only *absent*
        // means "keep the one we have" downstream. So a server answering
        // `"refresh_token": ""` replaced a live token with nothing, the next
        // refresh was rejected as `invalid_grant`, and the session was deleted —
        // exactly the spurious logout the refresh code is written to avoid.
        refresh_token: field("refresh_token")
            .filter(|t| !t.is_empty())
            .map(str::to_string),
        token_type: token_type.to_string(),
        granted_scope: granted_scope.to_string(),
        sub: sub.to_string(),
        expires_in,
    })
}

/// Whether a session should be refreshed now, against an explicit margin.
pub fn is_stale_with_margin(expires_at: Option<i64>, now: i64, margin: i64) -> bool {
    // No recorded expiry: never proactively refreshed. The PDS rejecting the
    // token is what triggers a refresh in that case.
    let Some(expires_at) = expires_at else {
        return false;
    };
    expires_at <= now + margin
}

/// A jittered refresh margin.
pub fn refresh_margin() -> i64 {
    let mut byte = [0u8; 4];
    getrandom::fill(&mut byte).expect("OS CSPRNG unavailable");
    let jitter = i64::from(u32::from_be_bytes(byte) % (REFRESH_JITTER_SECS as u32 + 1));
    MIN_REFRESH_MARGIN_SECS + jitter
}

/// Whether a session should be refreshed now.
pub fn is_stale(expires_at: Option<i64>, now: i64) -> bool {
    is_stale_with_margin(expires_at, now, refresh_margin())
}

/// What a failed refresh means for the stored session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshFailure {
    /// The grant is dead. Delete the session and require a fresh login.
    SessionInvalid,
    /// Anything else — network, 5xx, a nonce challenge. Leave the stored tokens
    /// untouched and fail this request.
    Transient,
}

/// Classify a failed refresh.
///
/// **Only `400` + `invalid_grant` invalidates.** Deleting on a network blip or a
/// 5xx would log people out for a server hiccup; treating a genuinely dead grant
/// as transient means retrying forever and never prompting a re-login.
pub fn classify_refresh_failure(status: u16, body: &[u8]) -> RefreshFailure {
    if status != 400 {
        return RefreshFailure::Transient;
    }
    let is_invalid_grant = serde_json::from_slice::<Value>(body)
        .ok()
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(Value::as_str)
        == Some("invalid_grant");
    if is_invalid_grant {
        RefreshFailure::SessionInvalid
    } else {
        RefreshFailure::Transient
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    const NOW: i64 = 1_700_000_000;

    fn token_body() -> serde_json::Value {
        json!({
            "access_token": "access-abc",
            "refresh_token": "refresh-xyz",
            "token_type": "DPoP",
            "scope": "atproto transition:generic",
            "sub": DID,
            "expires_in": 3600
        })
    }

    // ── request bodies ───────────────────────────────────────────────────────

    #[test]
    fn the_code_exchange_sends_the_grant_code_redirect_and_verifier() {
        let params = token_request_params("the-code", "https://x.example/cb", "the-verifier");
        let get = |k: &str| {
            params
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("grant_type"), Some("authorization_code"));
        assert_eq!(get("code"), Some("the-code"));
        assert_eq!(get("redirect_uri"), Some("https://x.example/cb"));
        assert_eq!(get("code_verifier"), Some("the-verifier"));
    }

    #[test]
    fn the_refresh_sends_only_the_grant_and_token() {
        let params = refresh_request_params("refresh-xyz");
        assert_eq!(
            params,
            vec![
                ("grant_type", "refresh_token".to_string()),
                ("refresh_token", "refresh-xyz".to_string()),
            ]
        );
    }

    /// The reference sends no `scope` on refresh, and sending one invites the
    /// server to re-scope a grant that is already settled.
    #[test]
    fn the_refresh_does_not_send_a_scope() {
        assert!(!refresh_request_params("t")
            .iter()
            .any(|(n, _)| *n == "scope"));
    }

    // ── response validation ──────────────────────────────────────────────────

    #[test]
    fn a_well_formed_token_response_parses() {
        let parsed = parse_token_response(&token_body()).unwrap();
        assert_eq!(parsed.access_token, "access-abc");
        assert_eq!(parsed.refresh_token.as_deref(), Some("refresh-xyz"));
        assert_eq!(parsed.sub, DID);
        assert_eq!(parsed.granted_scope, "atproto transition:generic");
        assert_eq!(parsed.expires_in, Some(3600));
    }

    /// **Accepting `Bearer` would discard the proof-of-possession binding** —
    /// the entire reason a stolen access token is useless on its own. The check
    /// is exact and case-sensitive.
    #[test]
    fn only_a_dpop_token_type_is_accepted() {
        for bad in ["Bearer", "bearer", "dpop", "DPoP ", "", "MAC"] {
            let mut body = token_body();
            body["token_type"] = json!(bad);
            assert!(parse_token_response(&body).is_err(), "accepted {bad:?}");
        }
    }

    /// Spec: clients should reject a response whose `scope` does not contain
    /// `atproto`. It must be a whole space-separated value, not a substring —
    /// `atproto-ish` is a different scope.
    #[test]
    fn the_granted_scope_must_contain_atproto_as_a_whole_value() {
        for bad in ["transition:generic", "atproto-ish", "notatproto", ""] {
            let mut body = token_body();
            body["scope"] = json!(bad);
            assert!(
                parse_token_response(&body).is_err(),
                "accepted scope {bad:?}"
            );
        }
        for good in [
            "atproto",
            "atproto transition:generic",
            "transition:generic atproto",
        ] {
            let mut body = token_body();
            body["scope"] = json!(good);
            assert!(
                parse_token_response(&body).is_ok(),
                "rejected scope {good:?}"
            );
        }
    }

    #[test]
    fn a_missing_scope_is_rejected() {
        let mut body = token_body();
        body.as_object_mut().unwrap().remove("scope");
        assert!(parse_token_response(&body).is_err());
    }

    /// `sub` becomes a database key and is fed back into identity resolution, so
    /// it must be a well-formed atproto DID first.
    #[test]
    fn the_subject_must_be_a_well_formed_atproto_did() {
        for bad in [
            "not-a-did",
            "did:example:123",
            "did:plc:tooshort",
            "did:web:evil.com/path",
            "",
        ] {
            let mut body = token_body();
            body["sub"] = json!(bad);
            assert!(parse_token_response(&body).is_err(), "accepted sub {bad:?}");
        }
    }

    /// A server sending `id_token` thinks it is doing OIDC. Cheap to catch,
    /// and nothing good follows from proceeding.
    #[test]
    fn an_id_token_is_rejected() {
        let mut body = token_body();
        body["id_token"] = json!("eyJ...");
        assert!(parse_token_response(&body).is_err());
    }

    /// `expires_in` is optional. Absent means "no proactive refresh", NOT a
    /// fabricated expiry — inventing one was a real bug in the earlier sidecar
    /// replacement attempt.
    #[test]
    fn a_response_without_expires_in_is_valid_and_has_no_expiry() {
        let mut body = token_body();
        body.as_object_mut().unwrap().remove("expires_in");
        assert_eq!(parse_token_response(&body).unwrap().expires_in, None);
    }

    #[test]
    fn a_nonsensical_expires_in_is_rejected() {
        for bad in [json!(0), json!(-1), json!("3600"), json!(3600.5)] {
            let mut body = token_body();
            body["expires_in"] = bad.clone();
            assert!(parse_token_response(&body).is_err(), "accepted {bad}");
        }
    }

    /// Rotation: a refresh response may omit `refresh_token`, in which case the
    /// caller keeps the old one. Absent is not an error.
    #[test]
    fn a_response_without_a_refresh_token_is_valid() {
        let mut body = token_body();
        body.as_object_mut().unwrap().remove("refresh_token");
        assert_eq!(parse_token_response(&body).unwrap().refresh_token, None);
    }

    #[test]
    fn a_response_without_an_access_token_is_rejected() {
        let mut body = token_body();
        body.as_object_mut().unwrap().remove("access_token");
        assert!(parse_token_response(&body).is_err());
    }

    // ── staleness ────────────────────────────────────────────────────────────

    /// A session with no recorded expiry is never proactively refreshed; it is
    /// refreshed reactively when the PDS rejects the token.
    #[test]
    fn a_session_without_an_expiry_is_never_stale() {
        assert!(!is_stale_with_margin(None, NOW, 30));
    }

    #[test]
    fn staleness_is_measured_against_the_margin() {
        assert!(!is_stale_with_margin(Some(NOW + 100), NOW, 30));
        assert!(is_stale_with_margin(Some(NOW + 29), NOW, 30));
        assert!(is_stale_with_margin(Some(NOW - 1), NOW, 30));
        // At exactly the margin the token is treated as stale: refreshing a
        // second early is free, using an expired token is not.
        assert!(is_stale_with_margin(Some(NOW + 30), NOW, 30));
    }

    /// The margin is randomized so that concurrent instances do not all decide
    /// to refresh the same session in the same second.
    #[test]
    fn the_refresh_margin_is_jittered_within_its_band() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let margin = refresh_margin();
            assert!(
                (MIN_REFRESH_MARGIN_SECS..=MIN_REFRESH_MARGIN_SECS + REFRESH_JITTER_SECS)
                    .contains(&margin),
                "margin {margin} outside its band"
            );
            seen.insert(margin);
        }
        assert!(seen.len() > 1, "the margin is not actually jittered");
    }

    // ── refresh failure classification ───────────────────────────────────────

    /// **Only `400` + `invalid_grant` invalidates a session.** Deleting on a
    /// network blip or a 5xx would log users out for a server hiccup; keeping a
    /// genuinely dead grant means retrying forever.
    #[test]
    fn only_invalid_grant_invalidates_the_session() {
        assert_eq!(
            classify_refresh_failure(400, br#"{"error":"invalid_grant"}"#),
            RefreshFailure::SessionInvalid
        );
        for (status, body) in [
            (400u16, &br#"{"error":"invalid_request"}"#[..]),
            (400, br#"{"error":"use_dpop_nonce"}"#),
            (400, b"not json"),
            (401, br#"{"error":"invalid_grant"}"#),
            (500, br#"{"error":"invalid_grant"}"#),
            (503, b""),
        ] {
            assert_eq!(
                classify_refresh_failure(status, body),
                RefreshFailure::Transient,
                "status {status} wrongly invalidated the session"
            );
        }
    }
}
