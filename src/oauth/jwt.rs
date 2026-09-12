//! ES256 JWS signing — the one signing primitive the OAuth flow needs.
//!
//! Two things are signed with the confidential client's key:
//!
//! * the **client assertion** (`private_key_jwt`), proving to the PDS's token
//!   endpoint that we are the client named by `client_id`, and
//! * **DPoP proofs**, proving possession of the per-session DPoP key.
//!
//! Both are compact JWS: `base64url(header) . base64url(payload) . base64url(sig)`.
//!
//! The detail worth stating, because getting it wrong produces a signature that
//! verifies nowhere: JOSE ECDSA signatures are the **fixed-width `r || s`**
//! form (64 bytes for P-256), *not* ASN.1 DER. A DER signature is the default
//! output of many ECDSA APIs and is silently accepted by nothing.

use anyhow::{anyhow, bail, Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey as EcdsaSigningKey, VerifyingKey};
use serde_json::Value;

use super::keys::SigningKey;

/// The JOSE signing input: `base64url(header) . base64url(payload)`.
fn signing_input(header: &Value, claims: &Value) -> Result<String> {
    let header = serde_json::to_vec(header).context("serializing the JWS header")?;
    let claims = serde_json::to_vec(claims).context("serializing the JWS claims")?;
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    ))
}

/// Sign `header`/`claims` as a compact ES256 JWS.
///
/// `p256`'s `Signature` is the fixed-width `r || s` form that JOSE requires, so
/// `to_bytes()` is 64 bytes. Reaching for `to_der()` here would produce a
/// signature no verifier accepts — see the module docs.
///
/// Signing is deterministic (RFC 6979): the nonce `k` is derived from the key
/// and the message rather than drawn from an RNG, so there is no nonce-reuse
/// failure mode here of the kind AES-GCM has.
pub fn sign(key: &SigningKey, header: &Value, claims: &Value) -> Result<String> {
    let input = signing_input(header, claims)?;
    let signer = EcdsaSigningKey::from(key.secret());
    let signature: Signature = signer.sign(input.as_bytes());
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

/// Verify a compact ES256 JWS against `key`'s public half.
///
/// Used by the tests and available for verifying anything we minted; the PDS
/// verifies our assertions itself via the published JWKS.
pub fn verify(key: &SigningKey, jws: &str) -> Result<()> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        bail!("malformed JWS: expected 3 segments, got {}", parts.len());
    }
    let raw = URL_SAFE_NO_PAD
        .decode(parts[2])
        .context("signature is not valid base64url")?;
    let signature =
        Signature::from_slice(&raw).map_err(|err| anyhow!("not a valid P-256 signature: {err}"))?;

    let input = format!("{}.{}", parts[0], parts[1]);
    let verifier = VerifyingKey::from(key.secret().public_key());
    verifier
        .verify(input.as_bytes(), &signature)
        .map_err(|_| anyhow!("JWS signature does not verify"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KID: &str = "featherreader-oauth-1";

    fn decode_part(part: &str) -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    #[test]
    fn a_signed_jws_has_three_base64url_segments() {
        let key = SigningKey::generate(KID);
        let jws = sign(&key, &json!({"alg": "ES256"}), &json!({"iss": "x"})).unwrap();
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        for p in &parts {
            assert!(!p.is_empty());
            assert!(!p.contains('='), "base64url in JOSE is unpadded: {p}");
            assert!(!p.contains('+') && !p.contains('/'), "not url-safe: {p}");
        }
    }

    #[test]
    fn the_header_and_payload_round_trip_verbatim() {
        let key = SigningKey::generate(KID);
        let header = json!({"alg": "ES256", "typ": "JWT", "kid": KID});
        let claims = json!({"iss": "https://x.example", "jti": "abc", "iat": 1_700_000_000});
        let jws = sign(&key, &header, &claims).unwrap();
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(decode_part(parts[0]), header);
        assert_eq!(decode_part(parts[1]), claims);
    }

    /// **The classic ES256 bug.** A DER-encoded ECDSA signature is variable
    /// length (~70-72 bytes) and is what many ECDSA APIs return by default.
    /// JOSE requires the fixed-width r||s concatenation — exactly 64 bytes for
    /// P-256. A DER signature here would be rejected by every verifier.
    #[test]
    fn the_signature_is_fixed_width_r_s_not_der() {
        let key = SigningKey::generate(KID);
        for _ in 0..16 {
            let jws = sign(&key, &json!({"alg": "ES256"}), &json!({"n": 1})).unwrap();
            let sig = URL_SAFE_NO_PAD
                .decode(jws.split('.').nth(2).unwrap())
                .unwrap();
            assert_eq!(sig.len(), 64, "not a fixed-width P-256 JOSE signature");
            // A DER signature would start with the SEQUENCE tag 0x30.
            assert_ne!(sig[0], 0x30, "looks like DER");
        }
    }

    #[test]
    fn a_signature_verifies_against_the_signing_keys_public_half() {
        let key = SigningKey::generate(KID);
        let jws = sign(&key, &json!({"alg": "ES256"}), &json!({"sub": "did:plc:x"})).unwrap();
        assert!(verify(&key, &jws).is_ok());
    }

    #[test]
    fn a_signature_from_a_different_key_does_not_verify() {
        let a = SigningKey::generate(KID);
        let b = SigningKey::generate(KID);
        let jws = sign(&a, &json!({"alg": "ES256"}), &json!({"sub": "x"})).unwrap();
        assert!(verify(&b, &jws).is_err());
    }

    #[test]
    fn tampering_with_the_payload_invalidates_the_signature() {
        let key = SigningKey::generate(KID);
        let jws = sign(&key, &json!({"alg": "ES256"}), &json!({"amount": 1})).unwrap();
        let parts: Vec<&str> = jws.split('.').collect();
        let forged = URL_SAFE_NO_PAD.encode(br#"{"amount":1000000}"#);
        let tampered = format!("{}.{}.{}", parts[0], forged, parts[2]);
        assert!(verify(&key, &tampered).is_err());
    }

    #[test]
    fn a_malformed_jws_is_rejected_rather_than_panicking() {
        let key = SigningKey::generate(KID);
        for bad in [
            "",
            "onlyonepart",
            "two.parts",
            "a.b.c.d",
            "...",
            "!!!.@@@.###",
            "a.b.",
        ] {
            assert!(verify(&key, bad).is_err(), "should reject {bad:?}");
        }
    }

    /// Two signatures over the same input must not be byte-identical unless the
    /// scheme is deliberately deterministic. Either is acceptable for ES256
    /// (RFC 6979 is deterministic); this pins WHICH one we get, so a future
    /// dependency change that flips it is visible rather than silent.
    #[test]
    fn signing_is_deterministic_rfc6979() {
        let key = SigningKey::generate(KID);
        let a = sign(&key, &json!({"alg": "ES256"}), &json!({"x": 1})).unwrap();
        let b = sign(&key, &json!({"alg": "ES256"}), &json!({"x": 1})).unwrap();
        assert_eq!(a, b, "p256 signs deterministically per RFC 6979");
    }
}
