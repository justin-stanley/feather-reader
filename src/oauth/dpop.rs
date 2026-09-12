//! DPoP (RFC 9449) — proof-of-possession for the per-session key.
//!
//! Every OAuth request carries a fresh `DPoP` proof: a short-lived JWS, signed
//! by the session's own key, binding the request to that key. The access token
//! is issued bound to the key's RFC 7638 thumbprint (`jkt`), so a stolen bearer
//! token is useless without the private half.
//!
//! Two details are easy to get wrong and are pinned by tests here:
//!
//! * **`htu` is the request URI with query and fragment removed** (RFC 9449
//!   §4.2). Leaving the query on means the proof does not match what the server
//!   canonicalizes, and every request is rejected.
//! * **the embedded `jwk` is the PUBLIC key only.** It is transmitted in the
//!   clear in the JWS header; a private member here would publish the session's
//!   signing key to the PDS and to anything on the path.
//!
//! The server may demand a nonce at any time, answering `4xx` with
//! `DPoP-Nonce` and `WWW-Authenticate: DPoP …error="use_dpop_nonce"`. That is
//! normal operation, not an error: the caller retries once with the supplied
//! nonce. See [`wants_new_nonce`].

use anyhow::{Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value};

use super::jwt;
use super::keys::SigningKey;

/// The DPoP challenges that mean "retry with a nonce", not "you failed".
const RETRYABLE_DPOP_ERRORS: [&str; 2] = ["use_dpop_nonce", "invalid_dpop_proof"];

/// A fresh, unguessable `jti`. 16 bytes of CSPRNG output is 22 base64url
/// characters — well past what a replay cache needs to be collision-free.
fn new_jti() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable; refusing to mint a DPoP proof");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The `htu` claim: the request URI with query and fragment removed, per
/// RFC 9449 §4.2. Anything else fails to match the server's canonical form.
fn htu(url: &str) -> Result<String> {
    let mut parsed = url::Url::parse(url).with_context(|| format!("not a valid URL {url:?}"))?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

/// The public key as RFC 9449 wants it embedded: the required members only.
///
/// `public_jwk` also carries `kid`/`alg`/`use`, which are meaningful in a JWKS
/// but not here, and some servers are strict about extras. Building a fresh map
/// from the four required members also means a private member cannot reach this
/// header by construction, not merely by remembering to strip it.
fn embedded_public_jwk(key: &SigningKey) -> Result<Value> {
    let full = key.public_jwk()?;
    let mut minimal = Map::new();
    for name in ["kty", "crv", "x", "y"] {
        let value = full
            .get(name)
            .cloned()
            .with_context(|| format!("public JWK is missing `{name}`"))?;
        minimal.insert(name.to_string(), value);
    }
    Ok(Value::Object(minimal))
}

/// Build a DPoP proof for one request.
///
/// `access_token` binds the proof to that token via `ath`; pass it for every
/// resource request. Without it a captured proof can be replayed alongside a
/// different token.
///
/// `nonce` is the value from a previous `DPoP-Nonce` response header, supplied
/// on the retry after a [`wants_new_nonce`] challenge.
pub fn proof(
    key: &SigningKey,
    method: &str,
    url: &str,
    access_token: Option<&str>,
    nonce: Option<&str>,
) -> Result<String> {
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": embedded_public_jwk(key)?,
    });

    let mut claims = Map::new();
    claims.insert("jti".into(), json!(new_jti()));
    claims.insert("htm".into(), json!(method.to_ascii_uppercase()));
    claims.insert("htu".into(), json!(htu(url)?));
    claims.insert("iat".into(), json!(chrono::Utc::now().timestamp()));
    if let Some(token) = access_token {
        let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
        claims.insert("ath".into(), json!(URL_SAFE_NO_PAD.encode(digest.as_ref())));
    }
    if let Some(nonce) = nonce {
        claims.insert("nonce".into(), json!(nonce));
    }

    jwt::sign(key, &header, &Value::Object(claims))
}

/// Extract an auth-param from a `WWW-Authenticate` value.
///
/// Deliberately a small scanner rather than a substring search: the value can
/// carry an `error_description` whose free text mentions a challenge name, and
/// matching that would send us into a pointless retry. Commas inside quoted
/// strings are respected so a description containing one cannot split a segment.
fn auth_param(header: &str, name: &str) -> Option<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for c in header.chars() {
        match c {
            '"' if !escaped => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ',' if !in_quotes => segments.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
        escaped = c == '\\' && !escaped;
    }
    segments.push(current);

    for segment in segments {
        let segment = segment.trim();
        // The first segment is prefixed with the auth scheme (`DPoP error=…`);
        // drop a leading bare word so the parameter is what gets matched.
        let candidate = match segment.split_once(char::is_whitespace) {
            Some((first, rest)) if !first.contains('=') => rest.trim(),
            _ => segment,
        };
        if let Some((key, value)) = candidate.split_once('=') {
            if key.trim().eq_ignore_ascii_case(name) {
                return Some(value.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

/// Whether a `WWW-Authenticate` value is the server asking us to retry with a
/// nonce, rather than reporting a real failure.
///
/// Callers must bound the retry at ONE. A server that answers every request
/// with `use_dpop_nonce` would otherwise spin forever.
pub fn wants_new_nonce(www_authenticate: &str) -> bool {
    auth_param(www_authenticate, "error")
        .is_some_and(|err| RETRYABLE_DPOP_ERRORS.contains(&err.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::jwt::verify;

    const KID: &str = "dpop-1";

    fn parts(jws: &str) -> (Value, Value) {
        let seg: Vec<&str> = jws.split('.').collect();
        (
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(seg[0]).unwrap()).unwrap(),
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(seg[1]).unwrap()).unwrap(),
        )
    }

    // ── header ───────────────────────────────────────────────────────────────

    #[test]
    fn the_proof_header_is_a_dpop_jwt_with_an_embedded_public_key() {
        let key = SigningKey::generate(KID);
        let proof = proof(&key, "POST", "https://bsky.social/oauth/token", None, None).unwrap();
        let (header, _) = parts(&proof);
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["jwk"]["kty"], "EC");
        assert_eq!(header["jwk"]["crv"], "P-256");
        assert!(header["jwk"]["x"].is_string());
        assert!(header["jwk"]["y"].is_string());
    }

    /// **The leak that would matter most.** The header `jwk` travels in the
    /// clear to the PDS. A `d` member here publishes the session's private key.
    #[test]
    fn the_embedded_jwk_never_carries_the_private_scalar() {
        let key = SigningKey::generate(KID);
        let proof = proof(&key, "GET", "https://bsky.social/xrpc/x", None, None).unwrap();
        let (header, _) = parts(&proof);
        assert!(
            header["jwk"].get("d").is_none(),
            "private scalar in DPoP header"
        );
        let rendered = serde_json::to_string(&header).unwrap();
        assert!(
            !rendered.contains("\"d\""),
            "private scalar in header: {rendered}"
        );
    }

    /// RFC 9449 embeds only the public key members; `kid`/`alg`/`use` are not
    /// wanted here and some servers are strict about extras.
    #[test]
    fn the_embedded_jwk_is_the_minimal_public_key() {
        let key = SigningKey::generate(KID);
        let (header, _) = parts(&proof(&key, "GET", "https://x.example/a", None, None).unwrap());
        let members: Vec<&String> = header["jwk"].as_object().unwrap().keys().collect();
        assert_eq!(members.len(), 4, "unexpected members: {members:?}");
    }

    // ── claims ───────────────────────────────────────────────────────────────

    /// RFC 9449 §4.2: `htu` is the request URI WITHOUT query or fragment.
    #[test]
    fn htu_strips_the_query_and_fragment() {
        let key = SigningKey::generate(KID);
        for (url, want) in [
            (
                "https://bsky.social/oauth/token?a=1&b=2",
                "https://bsky.social/oauth/token",
            ),
            (
                "https://bsky.social/xrpc/get#frag",
                "https://bsky.social/xrpc/get",
            ),
            ("https://bsky.social/x?q=1#f", "https://bsky.social/x"),
            ("https://bsky.social/plain", "https://bsky.social/plain"),
        ] {
            let (_, claims) = parts(&proof(&key, "GET", url, None, None).unwrap());
            assert_eq!(claims["htu"], want, "for {url}");
        }
    }

    #[test]
    fn htm_carries_the_method_and_iat_is_current() {
        let key = SigningKey::generate(KID);
        let (_, claims) = parts(&proof(&key, "POST", "https://x.example/t", None, None).unwrap());
        assert_eq!(claims["htm"], "POST");
        let now = chrono::Utc::now().timestamp();
        let iat = claims["iat"].as_i64().unwrap();
        assert!((now - iat).abs() < 5, "iat {iat} is not close to {now}");
    }

    /// `jti` is the server's replay defence; it must be unpredictable and fresh
    /// per proof. Note this also means proofs are NOT deterministic even though
    /// the underlying ES256 signature is.
    #[test]
    fn every_proof_gets_a_fresh_unpredictable_jti() {
        let key = SigningKey::generate(KID);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let (_, claims) =
                parts(&proof(&key, "GET", "https://x.example/a", None, None).unwrap());
            let jti = claims["jti"].as_str().unwrap().to_string();
            assert!(jti.len() >= 22, "jti too short to be unguessable: {jti}");
            assert!(seen.insert(jti), "jti repeated");
        }
    }

    // ── access-token binding ─────────────────────────────────────────────────

    /// When a request carries an access token, the proof must bind to it with
    /// `ath` = base64url(SHA-256(token)). Omitting it on a resource request
    /// lets a captured proof be replayed with a different token.
    #[test]
    fn ath_is_the_base64url_sha256_of_the_access_token_when_present() {
        let key = SigningKey::generate(KID);
        let token = "an-access-token";
        let (_, claims) =
            parts(&proof(&key, "GET", "https://x.example/a", Some(token), None).unwrap());

        let want = URL_SAFE_NO_PAD
            .encode(ring::digest::digest(&ring::digest::SHA256, token.as_bytes()).as_ref());
        assert_eq!(claims["ath"], want);
    }

    #[test]
    fn ath_is_absent_when_there_is_no_access_token() {
        let key = SigningKey::generate(KID);
        let (_, claims) = parts(&proof(&key, "POST", "https://x.example/t", None, None).unwrap());
        assert!(claims.get("ath").is_none());
    }

    #[test]
    fn the_nonce_claim_appears_only_when_the_server_supplied_one() {
        let key = SigningKey::generate(KID);
        let (_, without) = parts(&proof(&key, "POST", "https://x.example/t", None, None).unwrap());
        assert!(without.get("nonce").is_none());

        let (_, with) =
            parts(&proof(&key, "POST", "https://x.example/t", None, Some("srv-nonce")).unwrap());
        assert_eq!(with["nonce"], "srv-nonce");
    }

    #[test]
    fn a_proof_verifies_against_its_own_key() {
        let key = SigningKey::generate(KID);
        let p = proof(&key, "POST", "https://x.example/t", None, None).unwrap();
        assert!(verify(&key, &p).is_ok());
        assert!(verify(&SigningKey::generate(KID), &p).is_err());
    }

    #[test]
    fn an_unparseable_target_url_is_an_error_not_a_panic() {
        let key = SigningKey::generate(KID);
        assert!(proof(&key, "GET", "not a url", None, None).is_err());
        assert!(proof(&key, "GET", "", None, None).is_err());
    }

    // ── nonce negotiation ────────────────────────────────────────────────────

    /// A `use_dpop_nonce` challenge is normal operation — the server is telling
    /// us to retry with its nonce, not reporting a failure.
    #[test]
    fn wants_new_nonce_recognises_the_dpop_challenges() {
        for header in [
            r#"DPoP error="use_dpop_nonce", error_description="Authorization server requires nonce in DPoP proof""#,
            r#"DPoP algs="ES256", error="use_dpop_nonce""#,
            r#"DPoP error="invalid_dpop_proof""#,
            r#"dpop error="use_dpop_nonce""#,
        ] {
            assert!(wants_new_nonce(header), "should match: {header}");
        }
    }

    #[test]
    fn wants_new_nonce_ignores_unrelated_challenges() {
        for header in [
            r#"Bearer error="invalid_token""#,
            r#"DPoP error="invalid_grant""#,
            r#"DPoP algs="ES256""#,
            "",
            "garbage",
            // Must not fire on a mere substring in an unrelated field.
            r#"DPoP error="x", error_description="do not use_dpop_nonce here""#,
        ] {
            assert!(!wants_new_nonce(header), "should not match: {header}");
        }
    }
}
