//! The OAuth confidential-client signing key, and the documents derived from it.
//!
//! A production atproto OAuth client is a *confidential* client: it authenticates
//! to the PDS with `private_key_jwt`, signing a client assertion with a long-lived
//! ES256 key. That key must
//!
//! * survive restarts (it anchors `client_id`, so regenerating it invalidates
//!   in-flight authorizations),
//! * be published in public form at `jwks_uri` so the PDS can verify assertions,
//! * and never sit on disk in the clear.
//!
//! So it is persisted as a JWK, AEAD-encrypted with [`super::crypto`]. The JWK
//! *format* is deliberately the same one the Node sidecar writes, so a rollback
//! to the sidecar can still read a key this module created, and vice versa.
//!
//! The thumbprint is RFC 7638 and is computed over the PUBLIC members only
//! (`crv`, `kty`, `x`, `y`) in lexicographic order — never over the raw JWK
//! text, and never including `d`.

use anyhow::{anyhow, bail, Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::SecretKey;
use ring::digest::{digest, SHA256};
use serde_json::{json, Value};
use std::fs;
use std::io::Write as _;
use std::path::Path;

use super::crypto::{Aead, Codec};

/// The JOSE algorithm this client signs assertions with. atproto's OAuth profile
/// requires ES256 for `private_key_jwt`.
const ALG: &str = "ES256";

/// Extract a required string member from a JWK object.
fn member<'a>(jwk: &'a Value, name: &str) -> Result<&'a str> {
    jwk.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("JWK is missing the required `{name}` member"))
}

/// RFC 7638 thumbprint of an EC JWK.
///
/// The construction is the whole point: take ONLY the required members for the
/// key type (`crv`, `kty`, `x`, `y` for EC), emit them as compact JSON in
/// lexicographic order, SHA-256 that, base64url-encode without padding.
///
/// Hashing the raw JWK text instead would make the value depend on whitespace,
/// member order and any extra members, and would fold in the private `d` — it
/// would never match what the PDS computes.
fn thumbprint_of_members(jwk: &Value) -> Result<String> {
    let (crv, kty, x, y) = (
        member(jwk, "crv")?,
        member(jwk, "kty")?,
        member(jwk, "x")?,
        member(jwk, "y")?,
    );
    if kty != "EC" {
        bail!("unsupported JWK key type {kty:?}; expected EC");
    }
    // Built by hand rather than via a map: serde_json's default map preserves
    // insertion order, and the lexicographic ordering here is normative.
    let canonical = format!(r#"{{"crv":"{crv}","kty":"{kty}","x":"{x}","y":"{y}"}}"#);
    Ok(URL_SAFE_NO_PAD.encode(digest(&SHA256, canonical.as_bytes()).as_ref()))
}

/// The confidential client's long-lived ES256 signing key.
pub struct SigningKey {
    secret: SecretKey,
    kid: String,
}

impl SigningKey {
    /// Generate a fresh P-256 key.
    ///
    /// Draws from the OS CSPRNG via `getrandom`, the same source as the rest of
    /// the app, rather than pulling in a second RNG stack. A uniformly random
    /// 32-byte value is a valid P-256 scalar with overwhelming probability; the
    /// retry covers the ~2^-32 case where it lands outside the curve order.
    pub fn generate(kid: &str) -> Self {
        for _ in 0..8 {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes)
                .expect("OS CSPRNG unavailable; refusing to generate a signing key");
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                return Self {
                    secret,
                    kid: kid.to_string(),
                };
            }
        }
        unreachable!("8 consecutive invalid P-256 scalars is not physically plausible")
    }

    /// Parse a JWK, tolerating the extra members (`kid`, `alg`, `use`) that both
    /// this module and the sidecar attach.
    pub fn from_jwk_json(jwk_json: &str, kid: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(jwk_json).context("key file is not valid JSON")?;
        if v.get("d").is_none() {
            bail!("JWK has no `d` member; a signing key must be a private key");
        }
        // Hand p256 only the members it defines, so an unexpected extra member
        // can never make a valid key fail to parse.
        let minimal = json!({
            "kty": member(&v, "kty")?,
            "crv": member(&v, "crv")?,
            "x": member(&v, "x")?,
            "y": member(&v, "y")?,
            "d": member(&v, "d")?,
        });
        let secret = SecretKey::from_jwk_str(&minimal.to_string())
            .map_err(|err| anyhow!("not a valid P-256 private JWK: {err}"))?;
        // Prefer the kid already in the file: it is what a PDS may have cached
        // against the published JWKS.
        let kid = v
            .get("kid")
            .and_then(Value::as_str)
            .unwrap_or(kid)
            .to_string();
        Ok(Self { secret, kid })
    }

    /// The PRIVATE JWK, for persistence. Carries `kid`/`alg`/`use` so a rollback
    /// to the sidecar finds the key under the same identifier.
    pub fn to_jwk_json(&self) -> Result<String> {
        let mut v: Value =
            serde_json::to_value(self.secret.to_jwk()).context("serializing the private JWK")?;
        let obj = v
            .as_object_mut()
            .ok_or_else(|| anyhow!("JWK did not serialize to an object"))?;
        obj.insert("kid".into(), json!(self.kid));
        obj.insert("alg".into(), json!(ALG));
        obj.insert("use".into(), json!("sig"));
        serde_json::to_string(&v).context("rendering the private JWK")
    }

    /// The PUBLIC JWK — what `/jwks.json` serves. Never contains `d`.
    pub fn public_jwk(&self) -> Result<Value> {
        let mut v: Value = serde_json::to_value(self.secret.public_key().to_jwk())
            .context("serializing the public JWK")?;
        let obj = v
            .as_object_mut()
            .ok_or_else(|| anyhow!("JWK did not serialize to an object"))?;
        // Defensive: the public JWK must never carry the private scalar, whatever
        // the upstream serializer does.
        obj.remove("d");
        obj.insert("kid".into(), json!(self.kid));
        obj.insert("alg".into(), json!(ALG));
        obj.insert("use".into(), json!("sig"));
        Ok(v)
    }

    /// The document served at `jwks_uri`, so the PDS can verify our assertions.
    pub fn jwks_document(&self) -> Result<Value> {
        Ok(json!({ "keys": [self.public_jwk()?] }))
    }

    /// RFC 7638 thumbprint of this key's public half.
    pub fn thumbprint(&self) -> Result<String> {
        thumbprint_of_members(&self.public_jwk()?)
    }

    /// RFC 7638 thumbprint of an arbitrary EC JWK document.
    pub fn public_thumbprint_of(jwk_json: &str) -> Result<String> {
        let v: Value = serde_json::from_str(jwk_json).context("not valid JSON")?;
        thumbprint_of_members(&v)
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }
}

/// Write `contents` to `path` with owner-only permissions.
///
/// `create_new` is an EXCLUSIVE create: if the file appeared since we looked
/// (a racing process generated a key), this fails rather than clobbering a key
/// that may already be published in a JWKS and in use.
fn write_new_owner_only(path: &Path, contents: &str) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating the signing-key file at {}", path.display()))?;
    f.write_all(contents.as_bytes())
        .context("writing the signing-key file")?;
    Ok(())
}

/// Overwrite an EXISTING key file in place, keeping owner-only permissions.
fn rewrite_owner_only(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents)
        .with_context(|| format!("rewriting the signing-key file at {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .context("tightening permissions on the signing-key file")?;
    }
    Ok(())
}

/// Load the signing key from `path`, generating and persisting one if absent.
///
/// A file that exists but cannot be decrypted or parsed is a hard ERROR, never a
/// silent regeneration: the key anchors `client_id`, so quietly replacing it
/// would invalidate every in-flight authorization and every cached JWKS entry.
/// Refusing to boot is the safer failure.
///
/// Migrate-on-read: a legacy PLAINTEXT key file is loaded and immediately
/// re-written encrypted, without changing the key.
pub fn load_or_create(path: &Path, codec: &Codec, kid: &str) -> Result<SigningKey> {
    // Read directly rather than exists()-then-read: a check-then-use pair is a
    // filesystem race. A missing file surfaces as NotFound.
    let raw = match fs::read_to_string(path) {
        Ok(raw) => Some(raw),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err)
                .with_context(|| format!("reading the signing-key file at {}", path.display()))
        }
    };

    if let Some(raw) = raw {
        let raw = raw.trim();
        let plaintext = codec.maybe_decrypt(raw).with_context(|| {
            format!(
                "decrypting the signing-key file at {} -- refusing to generate a \
                 replacement, since that would rotate the client's identity",
                path.display()
            )
        })?;
        let key = SigningKey::from_jwk_json(&plaintext, kid)?;
        if !Aead::is_ciphertext(raw) {
            // Upgrade a pre-encryption file in place.
            rewrite_owner_only(path, &codec.encrypt(&plaintext))?;
        }
        return Ok(key);
    }

    let key = SigningKey::generate(kid);
    write_new_owner_only(path, &codec.encrypt(&key.to_jwk_json()?))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::crypto::{Aead, Codec};

    const KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KID: &str = "featherreader-oauth-1";

    /// A P-256 keypair and its RFC 7638 thumbprint, generated by `jose` 5.10 —
    /// an INDEPENDENT implementation, not this one. Regenerate with:
    /// ```text
    /// node --input-type=module -e 'import {generateKeyPair,exportJWK,calculateJwkThumbprint} from "jose";
    ///   const {publicKey,privateKey}=await generateKeyPair("ES256",{extractable:true});
    ///   console.log(JSON.stringify({pub:await exportJWK(publicKey),
    ///     priv:await exportJWK(privateKey),
    ///     tp:await calculateJwkThumbprint(await exportJWK(publicKey),"sha256")}))'
    /// ```
    const JOSE_PRIVATE_JWK: &str = r#"{
        "kty": "EC",
        "x": "HWngJQsJ6v606UgaeEf0Xv_Fe3c4MwChe3ouzCDZf3I",
        "y": "wwvoKJJUKd57bdQ3f3GpVuW-0-1MI_FhMt86Q9M95Ig",
        "crv": "P-256",
        "d": "ltBp9dkK7xkLm9VXOd6CMiLdFRKWQwVrN0Vf8QwC3a4"
    }"#;
    const JOSE_THUMBPRINT: &str = "nfjQX8hSYRpE05ADhZk6PVsPatJ6MqzqvzYxlL-kMC8";

    // ── thumbprint ───────────────────────────────────────────────────────────

    /// **The property the earlier WIP got wrong.** It hashed the raw JWK *string*,
    /// which depends on whitespace, member order and any extra members, and would
    /// happily include the private `d`. RFC 7638 hashes canonical JSON of exactly
    /// {crv, kty, x, y}. A value that does not match this is rejected by every PDS.
    #[test]
    fn thumbprint_matches_an_independent_rfc7638_implementation() {
        let key = SigningKey::from_jwk_json(JOSE_PRIVATE_JWK, KID).unwrap();
        assert_eq!(key.thumbprint().unwrap(), JOSE_THUMBPRINT);
    }

    /// The thumbprint identifies the PUBLIC key, so the private JWK and the
    /// public JWK of the same keypair must produce the same value.
    #[test]
    fn thumbprint_is_identical_for_the_private_and_public_halves() {
        let key = SigningKey::from_jwk_json(JOSE_PRIVATE_JWK, KID).unwrap();
        let public_only = serde_json::to_string(&key.public_jwk().unwrap()).unwrap();
        let reloaded = SigningKey::public_thumbprint_of(&public_only).unwrap();
        assert_eq!(reloaded, key.thumbprint().unwrap());
        assert_eq!(reloaded, JOSE_THUMBPRINT);
    }

    /// Canonicalization means member order and whitespace in the INPUT cannot
    /// change the output — the failure mode of hashing the raw string.
    #[test]
    fn thumbprint_ignores_member_order_and_whitespace() {
        let reordered = r#"{"y":"wwvoKJJUKd57bdQ3f3GpVuW-0-1MI_FhMt86Q9M95Ig","d":"ltBp9dkK7xkLm9VXOd6CMiLdFRKWQwVrN0Vf8QwC3a4","crv":"P-256","kty":"EC","x":"HWngJQsJ6v606UgaeEf0Xv_Fe3c4MwChe3ouzCDZf3I"}"#;
        let key = SigningKey::from_jwk_json(reordered, KID).unwrap();
        assert_eq!(key.thumbprint().unwrap(), JOSE_THUMBPRINT);
    }

    // ── generation and round-trip ────────────────────────────────────────────

    #[test]
    fn generate_produces_distinct_keys() {
        let a = SigningKey::generate(KID);
        let b = SigningKey::generate(KID);
        assert_ne!(a.thumbprint().unwrap(), b.thumbprint().unwrap());
    }

    #[test]
    fn a_generated_key_round_trips_through_its_jwk() {
        let key = SigningKey::generate(KID);
        let json = key.to_jwk_json().unwrap();
        let back = SigningKey::from_jwk_json(&json, KID).unwrap();
        assert_eq!(back.thumbprint().unwrap(), key.thumbprint().unwrap());
    }

    /// The persisted JWK is the PRIVATE one (it has to be — it is the signing
    /// key), and it carries the kid so a rollback to the sidecar finds it.
    #[test]
    fn the_persisted_jwk_carries_the_private_scalar_and_the_kid() {
        let key = SigningKey::generate(KID);
        let v: serde_json::Value = serde_json::from_str(&key.to_jwk_json().unwrap()).unwrap();
        assert!(
            v.get("d").is_some(),
            "the signing key must persist its scalar"
        );
        assert_eq!(v["kid"], KID);
        assert_eq!(v["kty"], "EC");
        assert_eq!(v["crv"], "P-256");
    }

    // ── what gets published ──────────────────────────────────────────────────

    /// The single most important leak to not have: `d` must never reach the
    /// JWKS endpoint.
    #[test]
    fn the_public_jwk_and_jwks_never_contain_the_private_scalar() {
        let key = SigningKey::generate(KID);
        let public = key.public_jwk().unwrap();
        assert!(public.get("d").is_none());

        let jwks = key.jwks_document().unwrap();
        let rendered = serde_json::to_string(&jwks).unwrap();
        assert!(
            !rendered.contains("\"d\""),
            "JWKS leaked the private scalar: {rendered}"
        );
        assert!(!rendered.contains("ltBp9dkK7xkLm9VXOd6CMiLdFRKWQwVrN0Vf8QwC3a4"));
    }

    #[test]
    fn the_jwks_document_is_a_keys_array_with_the_verification_metadata() {
        let key = SigningKey::from_jwk_json(JOSE_PRIVATE_JWK, KID).unwrap();
        let jwks = key.jwks_document().unwrap();
        let entry = &jwks["keys"][0];
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
        assert_eq!(entry["kty"], "EC");
        assert_eq!(entry["crv"], "P-256");
        assert_eq!(entry["kid"], KID);
        assert_eq!(entry["alg"], "ES256");
        assert_eq!(entry["use"], "sig");
        assert_eq!(entry["x"], "HWngJQsJ6v606UgaeEf0Xv_Fe3c4MwChe3ouzCDZf3I");
    }

    // ── persistence ──────────────────────────────────────────────────────────

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("fr-oauth-key-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn load_or_create_generates_once_then_reloads_the_same_key() {
        let path = tmp_path("reload");
        let codec = Codec::new(Some(KEY)).unwrap();

        let first = load_or_create(&path, &codec, KID).unwrap();
        let second = load_or_create(&path, &codec, KID).unwrap();
        assert_eq!(
            first.thumbprint().unwrap(),
            second.thumbprint().unwrap(),
            "a restart must not rotate the client's signing key"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_key_file_is_encrypted_at_rest() {
        let path = tmp_path("encrypted");
        let codec = Codec::new(Some(KEY)).unwrap();
        let key = load_or_create(&path, &codec, KID).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(Aead::is_ciphertext(raw.trim()), "key file is not encrypted");
        assert!(!raw.contains("\"d\""), "plaintext JWK leaked to disk");
        // And it really is the same key underneath.
        let plain = codec.maybe_decrypt(raw.trim()).unwrap();
        let same = SigningKey::from_jwk_json(&plain, KID).unwrap();
        assert_eq!(same.thumbprint().unwrap(), key.thumbprint().unwrap());
        let _ = std::fs::remove_file(&path);
    }

    /// Migrate-on-read: a key file written before encryption was switched on is
    /// loaded as plaintext and re-written encrypted, without changing the key.
    #[test]
    fn a_legacy_plaintext_key_file_is_migrated_to_ciphertext_in_place() {
        let path = tmp_path("migrate");
        let codec = Codec::new(Some(KEY)).unwrap();

        let original = SigningKey::generate(KID);
        std::fs::write(&path, original.to_jwk_json().unwrap()).unwrap();

        let loaded = load_or_create(&path, &codec, KID).unwrap();
        assert_eq!(
            loaded.thumbprint().unwrap(),
            original.thumbprint().unwrap(),
            "migration must not rotate the key"
        );
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            Aead::is_ciphertext(raw.trim()),
            "file was not upgraded to ciphertext"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A key written by the sidecar (a bare jose JWK, no kid) must load, since
    /// that is the rollback/rollforward path.
    #[test]
    fn a_key_file_written_by_the_node_sidecar_loads() {
        let path = tmp_path("sidecar");
        let codec = Codec::new(Some(KEY)).unwrap();
        std::fs::write(&path, codec.encrypt(JOSE_PRIVATE_JWK)).unwrap();

        let loaded = load_or_create(&path, &codec, KID).unwrap();
        assert_eq!(loaded.thumbprint().unwrap(), JOSE_THUMBPRINT);
        let _ = std::fs::remove_file(&path);
    }

    /// A corrupt or wrong-key file must fail LOUDLY. Silently generating a
    /// replacement would rotate the client's identity and invalidate every
    /// in-flight authorization, which is far worse than refusing to boot.
    #[test]
    fn an_undecryptable_key_file_is_an_error_not_a_silent_regeneration() {
        let path = tmp_path("corrupt");
        let codec = Codec::new(Some(KEY)).unwrap();
        let other = Codec::new(Some("a-completely-different-passphrase")).unwrap();
        std::fs::write(&path, other.encrypt(JOSE_PRIVATE_JWK)).unwrap();

        assert!(load_or_create(&path, &codec, KID).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_garbage_key_file_is_an_error() {
        let path = tmp_path("garbage");
        let codec = Codec::new(Some(KEY)).unwrap();
        std::fs::write(&path, codec.encrypt("{\"kty\":\"EC\",\"crv\":\"P-256\"}")).unwrap();
        assert!(load_or_create(&path, &codec, KID).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn a_created_key_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("mode");
        let codec = Codec::new(Some(KEY)).unwrap();
        load_or_create(&path, &codec, KID).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file mode was {mode:o}, want 600");
        let _ = std::fs::remove_file(&path);
    }
}
