//! DPoP (RFC 9449) — proof-of-possession for the per-session key.
//!
//! Every OAuth request carries a fresh `DPoP` proof: a short-lived JWS, signed
//! by the session's own key, binding the request to that key. The access token
//! is issued bound to the key's RFC 7638 thumbprint (`jkt`), so a stolen bearer
//! token is useless without the private half.
//!
//! Three details are easy to get wrong and are pinned by tests here:
//!
//! * **`htu` is the request URI with userinfo, query and fragment removed**
//!   (RFC 9449 §4.2). Leaving any of them on means the proof does not match what
//!   the server canonicalizes, and every request is rejected — and userinfo
//!   would additionally sign a password into a claim sent in the clear.
//! * **the embedded `jwk` is the PUBLIC key only.** It is transmitted in the
//!   clear in the JWS header; a private member here would publish the session's
//!   signing key to the PDS and to anything on the path.
//! * **a challenge belongs to its own scheme.** RFC 9449 §7.2 has a resource
//!   server returning a `Bearer` and a `DPoP` challenge in ONE header, so
//!   reading the first `error=` found attributes one scheme's error to the
//!   other.
//!
//! The server may demand a nonce at any time. That is normal operation, not an
//! error: the caller retries ONCE with the supplied nonce.
//!
//! It is signalled two different ways depending on which endpoint answered —
//! the authorization server uses a `400` and a JSON body, the resource server a
//! `401` and a `WWW-Authenticate` header. Handling only the header misses every
//! challenge from PAR, token and refresh, which is everything this client talks
//! to first. See [`nonce_challenge`].

use anyhow::{anyhow, bail, Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value};

use super::jwt;
use super::keys::SigningKey;

/// The one challenge that means "retry with a nonce".
///
/// `invalid_dpop_proof` is deliberately NOT here. RFC 9449 registers it (§12.2)
/// for a proof rejected on its merits against the §4.3 checks — bad `htu`, clock
/// skew, an unacceptable `alg`. Retrying spends the single permitted attempt
/// replaying an equivalent proof and reports the failure as a nonce problem,
/// hiding the real cause.
const NONCE_CHALLENGE: &str = "use_dpop_nonce";

/// A fresh, unguessable `jti`. 16 bytes of CSPRNG output is 22 base64url
/// characters — well past what a replay cache needs to be collision-free.
fn new_jti() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable; refusing to mint a DPoP proof");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Every character legal in an HTTP method, per RFC 9110's `token` rule.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The `htu` claim: the request URI with **userinfo**, query and fragment
/// removed, per RFC 9449 §4.2.
///
/// Userinfo matters beyond tidiness. RFC 9110 §7.1 target URIs have no userinfo
/// component, so a server comparing `htu` against the target could never match
/// one — and since the proof is transmitted in the clear, leaving it in would
/// sign a password into a claim on the wire.
///
/// The scheme is checked here rather than assumed: a `file:` or `data:` target
/// cannot be a real HTTP request, and would be signed verbatim into a claim.
fn htu(url: &str) -> Result<String> {
    let mut parsed = url::Url::parse(url).with_context(|| format!("not a valid URL {url:?}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!("DPoP target must be http(s), got {:?}", parsed.scheme());
    }
    parsed
        .set_username("")
        .map_err(|()| anyhow!("cannot strip userinfo from the DPoP target"))?;
    parsed
        .set_password(None)
        .map_err(|()| anyhow!("cannot strip userinfo from the DPoP target"))?;
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
/// on the retry after a [`nonce_challenge`].
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

    if method.is_empty() || !method.bytes().all(is_tchar) {
        bail!("{method:?} is not a valid HTTP method token");
    }

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

/// One parsed `WWW-Authenticate` challenge.
struct Challenge {
    scheme: String,
    params: Vec<(String, String)>,
}

/// Split a header value on commas that are OUTSIDE a quoted string.
///
/// Returns `None` for a malformed value — specifically an unterminated quoted
/// string, which would un-protect every following comma and let server-supplied
/// free text splice in a challenge that was never sent.
fn split_segments(header: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = header.chars();
    let mut in_quotes = false;

    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                // A quoted-pair escapes the next character, whatever it is.
                '\\' => {
                    current.push('\\');
                    current.push(chars.next()?);
                }
                '"' => {
                    in_quotes = false;
                    current.push(c);
                }
                _ => current.push(c),
            }
        } else {
            match c {
                '"' => {
                    in_quotes = true;
                    current.push(c);
                }
                ',' => out.push(std::mem::take(&mut current)),
                _ => current.push(c),
            }
        }
    }
    if in_quotes {
        return None;
    }
    out.push(current);
    Some(out)
}

/// Byte index of the first `=` outside a quoted string.
fn first_unquoted_eq(s: &str) -> Option<usize> {
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if in_quotes {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_quotes = false;
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == '=' {
            return Some(i);
        }
    }
    None
}

/// Decode an auth-param value: either a quoted-string (unescaping quoted-pairs)
/// or a bare token. `None` if it is neither.
fn unquote(raw: &str) -> Option<String> {
    let Some(inner) = raw.strip_prefix('"') else {
        // A bare token: no quotes, no whitespace, not empty.
        if raw.is_empty() || raw.contains('"') || raw.chars().any(char::is_whitespace) {
            return None;
        }
        return Some(raw.to_string());
    };
    let inner = inner.strip_suffix('"')?;
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?),
            // A bare quote inside the string means the quoting is not what it
            // appears to be; refuse rather than guess.
            '"' => return None,
            _ => out.push(c),
        }
    }
    Some(out)
}

/// Parse a `WWW-Authenticate` value into its challenges.
///
/// Scheme tracking is the point. RFC 9449 §7.2 has a resource server returning
/// a `Bearer` **and** a `DPoP` challenge in one header, so a parser that just
/// hunts for the first `error=` will attribute one scheme's error to the other
/// — either missing the nonce handshake entirely, or inventing one.
///
/// A segment is a new challenge when the text before its `=` is two tokens
/// (`DPoP error=…`), and a continuation of the current one when it is a single
/// token (`algs=…`). RFC 7235 allows bad whitespace around the `=`, so the
/// split is on the `=` rather than on the first space.
///
/// `None` means malformed; callers must treat that as "no challenge".
fn parse_challenges(header: &str) -> Option<Vec<Challenge>> {
    let mut challenges: Vec<Challenge> = Vec::new();

    for segment in split_segments(header)? {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let Some(eq) = first_unquoted_eq(segment) else {
            // A bare token: a challenge carrying no parameters.
            challenges.push(Challenge {
                scheme: segment.to_string(),
                params: Vec::new(),
            });
            continue;
        };
        let left = segment[..eq].trim();
        let Some(value) = unquote(segment[eq + 1..].trim()) else {
            // An unreadable VALUE is not grounds to discard the header. The
            // common cause is `token68`, which RFC 9110 §11.6.1 permits in place
            // of auth-params and which ends in `=` — so `Negotiate YII=` looks
            // like a parameter with an empty value.
            //
            // The asymmetry with `split_segments` returning `None` is
            // deliberate, and the direction is the reason: an unbalanced quote
            // can manufacture a challenge that was never sent (a FALSE
            // POSITIVE), so it fails closed; skipping a segment we cannot read
            // can only ever miss one (a FALSE NEGATIVE), so it degrades to
            // "this challenge has no readable parameters" and leaves the others
            // intact.
            if let Some((scheme, _)) = left.split_once(char::is_whitespace) {
                challenges.push(Challenge {
                    scheme: scheme.trim().to_string(),
                    params: Vec::new(),
                });
            }
            continue;
        };

        match left.split_once(char::is_whitespace) {
            Some((scheme, name)) => challenges.push(Challenge {
                scheme: scheme.trim().to_string(),
                params: vec![(name.trim().to_ascii_lowercase(), value)],
            }),
            // A parameter before any scheme has been named is malformed.
            None => challenges
                .last_mut()?
                .params
                .push((left.to_ascii_lowercase(), value)),
        }
    }
    Some(challenges)
}

/// Which kind of endpoint produced a response.
///
/// Passed in rather than inferred: we always know which we called, and the two
/// signal a nonce requirement completely differently (see [`nonce_challenge`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// PAR, token and refresh — RFC 9449 §8.
    AuthorizationServer,
    /// The PDS's XRPC endpoints — RFC 9449 §9.
    ResourceServer,
}

/// Largest error body we will parse looking for a nonce challenge.
///
/// A `use_dpop_nonce` error is a few dozen bytes. Matching the reference
/// client's 10 KiB peek bounds what a server can make us deserialize on a path
/// that runs for every failed request.
const MAX_ERROR_BODY: usize = 10 * 1024;

/// Whether an authorization-server error body is a nonce challenge.
fn body_asks_for_nonce(body: &[u8]) -> bool {
    if body.is_empty() || body.len() > MAX_ERROR_BODY {
        return false;
    }
    serde_json::from_slice::<Value>(body)
        .ok()
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(Value::as_str)
        == Some(NONCE_CHALLENGE)
}

/// Whether a `WWW-Authenticate` value carries a **DPoP** nonce challenge.
fn header_asks_for_nonce(www_authenticate: &str) -> bool {
    let Some(challenges) = parse_challenges(www_authenticate) else {
        return false;
    };
    challenges.iter().any(|c| {
        c.scheme.eq_ignore_ascii_case("DPoP")
            && c.params
                .iter()
                .any(|(name, value)| name == "error" && value == NONCE_CHALLENGE)
    })
}

/// The nonce to retry the request with, or `None` if this is not a nonce
/// challenge.
///
/// **RFC 9449 signals this two different ways**, and which one applies depends
/// on the endpoint, not on what happens to be in the response:
///
/// * **Authorization server** (§8) — PAR, token, refresh. `400` with an
///   RFC 6749 §5.2 JSON body `{"error":"use_dpop_nonce"}`, and typically NO
///   `WWW-Authenticate` header at all.
/// * **Resource server** (§9) — the PDS's XRPC endpoints. `401` with
///   `WWW-Authenticate: DPoP …error="use_dpop_nonce"`.
///
/// Reading only the header would miss every challenge on the authorization
/// server — which is the first thing this client talks to — and the token
/// exchange would fail permanently. `@atproto/oauth-client`'s
/// `isUseDpopNonceError` branches on the same distinction.
///
/// A `DPoP-Nonce` must also actually be present: without one there is nothing to
/// retry *with*, so retrying would replay an equivalent proof and report the
/// wrong cause.
///
/// Callers must bound the retry at ONE. A server answering every request with
/// `use_dpop_nonce` would otherwise spin forever.
pub fn nonce_challenge(
    endpoint: Endpoint,
    status: u16,
    www_authenticate: Option<&str>,
    body: &[u8],
    dpop_nonce: Option<&str>,
) -> Option<String> {
    let nonce = dpop_nonce.filter(|n| !n.is_empty())?;
    let asked = match endpoint {
        Endpoint::AuthorizationServer => status == 400 && body_asks_for_nonce(body),
        Endpoint::ResourceServer => {
            status == 401 && www_authenticate.is_some_and(header_asks_for_nonce)
        }
    };
    asked.then(|| nonce.to_string())
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

    /// A non-http(s) target has no business in a DPoP proof, and the request it
    /// describes could not go through the SSRF guard anyway.
    #[test]
    fn a_non_http_scheme_is_rejected() {
        let key = SigningKey::generate(KID);
        for url in [
            "file:///etc/passwd",
            "ftp://x.example/a",
            "data:text/plain,x",
        ] {
            assert!(
                proof(&key, "GET", url, None, None).is_err(),
                "allowed {url}"
            );
        }
    }

    /// `htm` is an HTTP method token. An empty or non-token method would be
    /// signed verbatim into a claim the server compares literally.
    #[test]
    fn a_non_token_method_is_rejected() {
        let key = SigningKey::generate(KID);
        for method in ["", "gé t", "GET POST", "GET\n", "GE\tT"] {
            assert!(
                proof(&key, method, "https://x.example/a", None, None).is_err(),
                "allowed method {method:?}"
            );
        }
    }

    /// **Credentials must not be signed into a transmitted claim.** RFC 9110
    /// target URIs have no userinfo component, so RFC 9449 §4.3's comparison
    /// could never match one either — this is both a leak and a conformance break.
    #[test]
    fn htu_strips_userinfo() {
        let key = SigningKey::generate(KID);
        let (_, claims) = parts(
            &proof(
                &key,
                "POST",
                "https://Alice:s3cr3t@PDS.Example.COM:443/oauth/token?a=1#f",
                None,
                None,
            )
            .unwrap(),
        );
        let htu = claims["htu"].as_str().unwrap();
        assert_eq!(htu, "https://pds.example.com/oauth/token");
        assert!(!htu.contains("s3cr3t"), "password leaked into htu: {htu}");
        assert!(!htu.contains("Alice"), "username leaked into htu: {htu}");
    }

    /// The signature is worthless if the key advertised in the header is not the
    /// key that signed (RFC 9449 §4.3 step 6). Nothing else pins this.
    #[test]
    fn the_embedded_jwk_is_the_key_that_actually_signed() {
        let key = SigningKey::generate(KID);
        let p = proof(&key, "POST", "https://x.example/t", None, None).unwrap();
        let (header, _) = parts(&p);
        let embedded = serde_json::to_string(&header["jwk"]).unwrap();
        assert_eq!(
            SigningKey::public_thumbprint_of(&embedded).unwrap(),
            key.thumbprint().unwrap(),
            "the embedded jwk is not the signing key"
        );
    }

    #[test]
    fn htm_is_upcased() {
        let key = SigningKey::generate(KID);
        for (given, want) in [("get", "GET"), ("Post", "POST"), ("delete", "DELETE")] {
            let (_, claims) =
                parts(&proof(&key, given, "https://x.example/a", None, None).unwrap());
            assert_eq!(claims["htm"], want, "for {given}");
        }
    }

    // ── nonce negotiation ────────────────────────────────────────────────────

    /// Shorthand for the RESOURCE-server signalling path, which is what the
    /// `WWW-Authenticate` parser tests below exercise.
    fn rs(www_authenticate: &str, nonce: Option<&str>) -> Option<String> {
        nonce_challenge(
            Endpoint::ResourceServer,
            401,
            Some(www_authenticate),
            b"",
            nonce,
        )
    }

    /// **RFC 9449 signals a nonce two different ways, and the authorization
    /// server's way is the one this client hits first.**
    ///
    /// §8 (AS): `400` with an RFC 6749 §5.2 JSON body `{"error":"use_dpop_nonce"}`
    /// and NO `WWW-Authenticate` at all. §9 (RS): `401` with the header.
    ///
    /// PAR, token exchange and refresh all go to the authorization server, so an
    /// implementation that reads only `WWW-Authenticate` never sees the
    /// challenge and the token exchange fails permanently. Cross-checked against
    /// `@atproto/oauth-client`'s `isUseDpopNonceError`, which branches on
    /// exactly this.
    #[test]
    fn the_authorization_server_signals_with_a_400_and_a_json_body() {
        assert_eq!(
            nonce_challenge(
                Endpoint::AuthorizationServer,
                400,
                None,
                br#"{"error":"use_dpop_nonce"}"#,
                Some("n1"),
            )
            .as_deref(),
            Some("n1")
        );
        // With the description RFC 6749 §5.2 allows alongside it.
        assert_eq!(
            nonce_challenge(
                Endpoint::AuthorizationServer,
                400,
                None,
                br#"{"error":"use_dpop_nonce","error_description":"nonce required"}"#,
                Some("n1"),
            )
            .as_deref(),
            Some("n1")
        );
    }

    #[test]
    fn the_authorization_server_path_ignores_other_errors_and_statuses() {
        for (status, body) in [
            (400u16, &br#"{"error":"invalid_grant"}"#[..]),
            (400, br#"{"error":"invalid_dpop_proof"}"#),
            (400, b"not json"),
            (400, b""),
            (400, br#"{"error":123}"#),
            (400, br#"[]"#),
            // Right error, wrong status.
            (401, br#"{"error":"use_dpop_nonce"}"#),
            (200, br#"{"error":"use_dpop_nonce"}"#),
            (500, br#"{"error":"use_dpop_nonce"}"#),
        ] {
            assert!(
                nonce_challenge(
                    Endpoint::AuthorizationServer,
                    status,
                    None,
                    body,
                    Some("n1")
                )
                .is_none(),
                "acted on status {status} body {:?}",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// The two paths must not bleed into each other: the AS path does not read
    /// `WWW-Authenticate`, and the RS path does not read the body.
    #[test]
    fn the_two_signalling_paths_are_independent() {
        // AS status/body are wrong, but a resource-server-shaped header is set.
        assert!(nonce_challenge(
            Endpoint::AuthorizationServer,
            400,
            Some(r#"DPoP error="use_dpop_nonce""#),
            br#"{"error":"invalid_grant"}"#,
            Some("n1"),
        )
        .is_none());

        // RS header is absent, but an AS-shaped body is present.
        assert!(nonce_challenge(
            Endpoint::ResourceServer,
            401,
            None,
            br#"{"error":"use_dpop_nonce"}"#,
            Some("n1"),
        )
        .is_none());
    }

    /// The resource-server path requires 401 specifically.
    #[test]
    fn the_resource_server_path_requires_a_401() {
        for status in [400u16, 403, 200, 500] {
            assert!(
                nonce_challenge(
                    Endpoint::ResourceServer,
                    status,
                    Some(r#"DPoP error="use_dpop_nonce""#),
                    b"",
                    Some("n1"),
                )
                .is_none(),
                "acted on status {status}"
            );
        }
    }

    /// **Differential against the reference client.** Each expectation below is
    /// what `@atproto/oauth-client`'s `isUseDpopNonceError` returns for the same
    /// response, captured by running that function verbatim out of
    /// `oauth-sidecar/node_modules/@atproto/oauth-client/dist/fetch-dpop.js`.
    ///
    /// This is the check that would have caught the original defect: the
    /// implementation read only `WWW-Authenticate`, so every authorization-server
    /// case here (the first nine) was wrong, and no amount of reading the parser
    /// would have shown it.
    #[test]
    fn agrees_with_the_reference_client_on_nonce_detection() {
        use Endpoint::{AuthorizationServer as As, ResourceServer as Rs};
        /// (endpoint, status, WWW-Authenticate, body, reference verdict)
        type Case = (Endpoint, u16, Option<&'static str>, &'static [u8], bool);
        let cases: &[Case] = &[
            (As, 400, None, br#"{"error":"use_dpop_nonce"}"#, true),
            (
                As,
                400,
                None,
                br#"{"error":"use_dpop_nonce","error_description":"x"}"#,
                true,
            ),
            (As, 400, None, br#"{"error":"invalid_grant"}"#, false),
            (As, 400, None, br#"{"error":"invalid_dpop_proof"}"#, false),
            (As, 400, None, b"not json", false),
            (As, 400, None, b"", false),
            (As, 401, None, br#"{"error":"use_dpop_nonce"}"#, false),
            (As, 200, None, br#"{"error":"use_dpop_nonce"}"#, false),
            (
                As,
                400,
                Some(r#"DPoP error="use_dpop_nonce""#),
                br#"{"error":"invalid_grant"}"#,
                false,
            ),
            (Rs, 401, Some(r#"DPoP error="use_dpop_nonce""#), b"", true),
            (
                Rs,
                401,
                Some(r#"DPoP algs="ES256", error="use_dpop_nonce""#),
                b"",
                true,
            ),
            (
                Rs,
                401,
                Some(r#"Bearer error="use_dpop_nonce""#),
                b"",
                false,
            ),
            (
                Rs,
                401,
                Some(r#"DPoP error="invalid_dpop_proof""#),
                b"",
                false,
            ),
            (Rs, 400, Some(r#"DPoP error="use_dpop_nonce""#), b"", false),
            (Rs, 401, None, br#"{"error":"use_dpop_nonce"}"#, false),
        ];

        for (i, (endpoint, status, header, body, expected)) in cases.iter().enumerate() {
            let got = nonce_challenge(*endpoint, *status, *header, body, Some("n1")).is_some();
            assert_eq!(
                got, *expected,
                "case {i} ({endpoint:?}, {status}, {header:?}) disagrees with the reference"
            );
        }
    }

    /// An oversized body is not parsed. A `use_dpop_nonce` error is a few dozen
    /// bytes; anything large is a different response, and parsing it would let a
    /// server spend our memory on every failed request.
    #[test]
    fn an_oversized_error_body_is_not_parsed() {
        let mut body = br#"{"error":"use_dpop_nonce","pad":""#.to_vec();
        body.extend(std::iter::repeat_n(b'a', 32 * 1024));
        body.extend(br#""}"#);
        assert!(
            nonce_challenge(Endpoint::AuthorizationServer, 400, None, &body, Some("n1")).is_none()
        );
    }

    /// A `use_dpop_nonce` challenge is normal operation — the server is telling
    /// us to retry with its nonce, not reporting a failure.
    #[test]
    fn a_dpop_nonce_challenge_yields_the_nonce_to_retry_with() {
        for header in [
            r#"DPoP error="use_dpop_nonce", error_description="Authorization server requires nonce in DPoP proof""#,
            r#"DPoP algs="ES256", error="use_dpop_nonce""#,
            r#"dpop error="use_dpop_nonce""#,
            // RFC 7235 permits bad whitespace around `=`.
            r#"DPoP algs="ES256", error = "use_dpop_nonce""#,
            r#"DPoP error	=	"use_dpop_nonce""#,
        ] {
            assert_eq!(
                rs(header, Some("n1")).as_deref(),
                Some("n1"),
                "should match: {header}"
            );
        }
    }

    /// **RFC 9449 §7.2.** A resource server supporting both schemes returns both
    /// challenges in ONE header. Attributing the wrong scheme's `error` either
    /// misses the nonce handshake entirely (every request then fails forever) or
    /// invents one that was never asked for.
    #[test]
    fn challenges_are_matched_to_their_own_scheme() {
        // The DPoP challenge is present but not first: must still be found.
        assert_eq!(
            rs(
                r#"Bearer error="invalid_token", DPoP error="use_dpop_nonce", algs="ES256""#,
                Some("n1")
            )
            .as_deref(),
            Some("n1")
        );
        // A `use_dpop_nonce` on a NON-DPoP scheme is not ours to act on.
        assert!(rs(r#"Bearer error="use_dpop_nonce""#, Some("n1")).is_none());
        assert!(rs(
            r#"Basic realm="r", Bearer error="use_dpop_nonce""#,
            Some("n1")
        )
        .is_none());
        // Params after a scheme belong to that scheme, not the previous one.
        assert!(rs(
            r#"DPoP algs="ES256", Bearer error="use_dpop_nonce""#,
            Some("n1")
        )
        .is_none());
    }

    /// **RFC 9449 §7.1**: `invalid_dpop_proof` means the proof was rejected on
    /// its merits (bad `htu`, clock skew, unacceptable `alg`) — a real failure,
    /// not a request to retry. Retrying burns the one attempt and reports the
    /// wrong cause.
    #[test]
    fn invalid_dpop_proof_is_a_failure_not_a_rs() {
        assert!(rs(r#"DPoP error="invalid_dpop_proof""#, Some("n1")).is_none());
    }

    /// Without a nonce there is nothing to retry WITH; retrying would replay the
    /// same proof and mask the real error.
    #[test]
    fn no_retry_without_a_supplied_nonce() {
        assert!(rs(r#"DPoP error="use_dpop_nonce""#, None).is_none());
        assert!(rs(r#"DPoP error="use_dpop_nonce""#, Some("")).is_none());
    }

    #[test]
    fn unrelated_challenges_do_not_trigger_a_retry() {
        for header in [
            r#"Bearer error="invalid_token""#,
            r#"DPoP error="invalid_grant""#,
            r#"DPoP algs="ES256""#,
            "",
            "garbage",
            // Must not fire on a mere substring in an unrelated field.
            r#"DPoP error="x", error_description="do not use_dpop_nonce here""#,
        ] {
            assert!(
                rs(header, Some("n1")).is_none(),
                "should not match: {header}"
            );
        }
    }

    /// **A `token68` challenge must not poison the rest of the header.**
    /// RFC 9110 §11.6.1 allows `challenge = auth-scheme [ 1*SP ( token68 /
    /// #auth-param ) ]`, and `token68` ends with `*"="` — so `Negotiate YII=`
    /// parses as a parameter with an empty value. Discarding the whole header
    /// over that would silently drop a valid DPoP nonce challenge sitting
    /// beside it, which is the same permanent-failure shape as reading the
    /// wrong scheme's error.
    #[test]
    fn a_token68_challenge_does_not_discard_the_other_challenges() {
        for header in [
            r#"DPoP error="use_dpop_nonce", Negotiate YII="#,
            r#"Negotiate YII=, DPoP error="use_dpop_nonce""#,
            r#"Basic realm=x, Negotiate abc==, DPoP error="use_dpop_nonce""#,
            // A parameter we cannot read must not sink its own challenge either.
            r#"DPoP foo=, error="use_dpop_nonce""#,
            r#"DPoP error="use_dpop_nonce", bad="#,
        ] {
            assert_eq!(
                rs(header, Some("n1")).as_deref(),
                Some("n1"),
                "token68 or unreadable param discarded the header: {header}"
            );
        }
    }

    /// Skipping an unreadable segment can only ever cause a FALSE NEGATIVE.
    /// An unbalanced quote is different in kind — it can manufacture a
    /// challenge that was never sent — so that still fails closed.
    #[test]
    fn a_token68_challenge_cannot_manufacture_a_rs() {
        for header in [
            r#"Negotiate YII="#,
            r#"Basic realm=x, Negotiate abc=="#,
            r#"Bearer error="use_dpop_nonce", Negotiate YII="#,
        ] {
            assert!(
                rs(header, Some("n1")).is_none(),
                "invented a challenge from: {header}"
            );
        }
    }

    /// A malformed header must fail CLOSED. An unbalanced quote un-protects the
    /// commas that follow, letting server free text splice in a challenge that
    /// was never sent.
    #[test]
    fn a_malformed_header_does_not_trigger_a_retry() {
        for header in [
            r#"DPoP error_description="he said "x, junk error="use_dpop_nonce""#,
            r#"DPoP realm="r", error_description="unbalanced " here, y error="use_dpop_nonce""#,
            r#"DPoP error="use_dpop_nonce"#,
            r#"DPoP error=""use_dpop_nonce"""#,
        ] {
            assert!(
                rs(header, Some("n1")).is_none(),
                "malformed header was acted on: {header}"
            );
        }
    }

    /// A quoted value may legally contain a comma and escaped quotes; neither
    /// may split a segment or corrupt the value.
    #[test]
    fn quoted_values_may_contain_commas_and_escaped_quotes() {
        assert_eq!(
            rs(
                r#"DPoP error_description="one, two, three", error="use_dpop_nonce""#,
                Some("n1")
            )
            .as_deref(),
            Some("n1")
        );
        assert_eq!(
            rs(
                r#"DPoP error_description="he said \"hi\", ok", error="use_dpop_nonce""#,
                Some("n1")
            )
            .as_deref(),
            Some("n1")
        );
    }

    /// An unquoted token value is legal per RFC 7235.
    #[test]
    fn an_unquoted_token_value_is_accepted() {
        assert_eq!(
            rs(r#"DPoP error=use_dpop_nonce"#, Some("n1")).as_deref(),
            Some("n1")
        );
    }

    /// Pathological input must terminate, not hang.
    #[test]
    fn a_pathological_header_terminates() {
        let big = format!("DPoP error=\"{}", "a,".repeat(20_000));
        assert!(rs(&big, Some("n1")).is_none());
        let quotes = "\"".repeat(20_000);
        assert!(rs(&quotes, Some("n1")).is_none());
    }
}
