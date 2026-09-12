//! The OAuth confidential-client signing key, and the documents derived from it.
//!
//! A production atproto OAuth client is a *confidential* client: it authenticates
//! to the PDS with `private_key_jwt`, signing a client assertion with a long-lived
//! ES256 key. That key must
//!
//! * survive restarts (it anchors `client_id`, so regenerating it invalidates
//!   in-flight authorizations),
//! * be published in public form at `jwks_uri` so the PDS can verify assertions,
//! * and not sit on disk in the clear **whenever a codec key is configured**.
//!
//! So it is persisted as a JWK, AEAD-encrypted with [`super::crypto`]. The JWK
//! *format* is deliberately the same one the Node sidecar writes, so a rollback
//! to the sidecar can still read a key this module created, and vice versa.
//!
//! That third requirement is conditional, and the condition is load-bearing:
//! [`super::crypto::Codec::Null`] is a pass-through, so a deployment with no key
//! configured writes the private JWK as plaintext. The sidecar refuses to boot
//! in production without a key; the equivalent guard for this path belongs in
//! config validation at cutover, and until then `Codec::Null` is a dev-only
//! arrangement rather than an enforced one.
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
    if crv != "P-256" {
        bail!("unsupported JWK curve {crv:?}; only P-256 is supported");
    }
    // `x`/`y` are unpadded base64url in a well-formed EC JWK. The check is on
    // the ALPHABET, which is all that is needed for the property that matters
    // here: no member can require JSON escaping, so the canonical form is
    // unambiguous. It is not a validity check — length and decodability are not
    // verified, and do not need to be, since the caller either supplies our own
    // key or is about to hand the JWK to `p256` anyway.
    for (name, value) in [("x", x), ("y", y)] {
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!("JWK member `{name}` is not unpadded base64url");
        }
    }
    // Serialized, not interpolated, so the escaping is the serializer's job.
    // The literal below is also WRITTEN in lexicographic order, so the output is
    // RFC-canonical whether `serde_json::Map` is a `BTreeMap` (the default) or
    // an insertion-ordered map (were `preserve_order` ever pulled in by feature
    // unification elsewhere in the graph).
    let canonical = serde_json::to_string(&json!({"crv": crv, "kty": kty, "x": x, "y": y}))
        .context("serializing the canonical JWK")?;
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

    /// Parse a JWK, tolerating the extra members (`kid`, `alg`, `key_ops`,
    /// `use`) that both this module and the sidecar attach.
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

    /// The PRIVATE JWK, for persistence. Carries `kid`/`alg`/`key_ops` so a
    /// rollback to the sidecar finds the key under the same identifier.
    pub fn to_jwk_json(&self) -> Result<String> {
        let mut v: Value =
            serde_json::to_value(self.secret.to_jwk()).context("serializing the private JWK")?;
        let obj = v
            .as_object_mut()
            .ok_or_else(|| anyhow!("JWK did not serialize to an object"))?;
        obj.insert("kid".into(), json!(self.kid));
        obj.insert("alg".into(), json!(ALG));
        // `key_ops`, not `use`, on the PRIVATE JWK: `jose` warns that a private
        // JWK carrying `use` will be rejected in a future release, which would
        // break the rollback path this shared format exists to preserve.
        //
        // (The sidecar writes NEITHER — `JoseKey.generate(...).privateJwk` is
        // just `{kty, kid, crv, x, y, d}`. An earlier version of this comment
        // claimed `key_ops` matched the sidecar; it does not. The change stands
        // on the deprecation alone, and jwk-jose loads the result warning-free.)
        obj.insert("key_ops".into(), json!(["sign"]));
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

    /// The raw secret, for [`super::jwt`] to sign with. Deliberately
    /// `pub(crate)`: nothing outside this crate should be able to reach the
    /// private scalar, and nothing outside [`super::jwt`] needs to.
    pub(crate) fn secret(&self) -> &SecretKey {
        &self.secret
    }
}

/// A staged temp file that deletes itself on drop unless told not to.
///
/// Without this, any failure between creating the temp and linking it into
/// place leaves the file behind until some later write happens to clear it.
struct Staged {
    path: std::path::PathBuf,
    keep: bool,
}

impl Staged {
    /// Write `contents` to a **uniquely named** sibling of `near`, fsynced.
    ///
    /// The name carries the pid and CSPRNG bytes deliberately. A shared,
    /// predictable temp path lets two processes interleave `remove` and
    /// `create` such that one renames the other's empty file into place —
    /// producing exactly the zero-length key file this staging exists to
    /// prevent. A unique name makes the collision impossible instead of
    /// unlikely, and removes any need to clear a stale temp first (which is
    /// what opened the window).
    fn write(near: &Path, contents: &str) -> Result<Self> {
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).expect("OS CSPRNG unavailable; refusing to stage a key");
        let mut name = near.as_os_str().to_os_string();
        name.push(format!(
            ".{}.{}.tmp",
            std::process::id(),
            suffix
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let path = std::path::PathBuf::from(name);

        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&path)
            .with_context(|| format!("staging a key write at {}", path.display()))?;
        let staged = Self { path, keep: false };

        file.write_all(contents.as_bytes())
            .context("writing the staged signing-key file")?;
        // Durable BEFORE it is linked into place, so the final link can never
        // expose a file whose contents have not reached disk.
        file.sync_all().context("flushing the staged key file")?;
        Ok(staged)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// The staged file has become the real one; stop tracking it.
    fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Create the key file **atomically**, refusing to clobber an existing one.
///
/// Stage, then `hard_link` into place. `hard_link` is the reason this is not a
/// `rename`: it fails with `EEXIST` if the destination exists, which preserves
/// the no-clobber guard against a racing process that already generated and
/// published a key — a guard a `rename` would silently discard.
///
/// A plain `create_new` + `write` is NOT equivalent: it is atomic with respect
/// to *existence* but not to *content*, so a crash between the open and the
/// write leaves a zero-length file, and an unreadable key file is deliberately
/// a hard error (see [`load_or_create`]).
/// Returns `Ok(false)` when the file already exists — someone else won the race
/// and their key is the one to use.
fn write_new_owner_only(path: &Path, contents: &str) -> Result<bool> {
    let staged = Staged::write(path, contents)?;
    if let Err(err) = fs::hard_link(staged.path(), path) {
        // EEXIST is not a failure, it is the outcome of a race we can lose
        // safely: the file now at `path` is exactly the thing we wanted. Two
        // replicas starting together both take the NotFound branch, both
        // generate a key, and both link; treating the loser's EEXIST as fatal
        // meant every replica but one refused to boot, and a scheduler
        // restarting them together could flap indefinitely.
        //
        // A dangling SYMLINK lands here too — `read_to_string` follows it and
        // reports NotFound, while `hard_link` does not follow it and reports
        // EEXIST — so the retry path must be able to say "still not readable"
        // rather than loop.
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            return Ok(false);
        }
        return Err(err)
            .with_context(|| format!("creating the signing-key file at {}", path.display()));
    }
    // The contents now live at `path`; dropping `staged` unlinks only the
    // temporary second name for the same inode.
    drop(staged);
    sync_parent_dir(path);
    Ok(true)
}

/// Replace an EXISTING key file **atomically**, keeping owner-only permissions.
///
/// Symlinks are resolved first so the rename replaces the **target** rather than
/// the link. Renaming over the link itself would break an operator's deliberate
/// indirection and — worse during a plaintext migration — leave the unencrypted
/// private JWK sitting at the old target.
fn rewrite_owner_only(path: &Path, contents: &str) -> Result<()> {
    let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let staged = Staged::write(&target, contents)?;
    fs::rename(staged.path(), &target)
        .with_context(|| format!("replacing the signing-key file at {}", target.display()))?;
    // The temp name no longer exists; the rename consumed it.
    staged.keep();
    sync_parent_dir(&target);
    Ok(())
}

/// Best-effort fsync of the containing directory, so a rename survives a crash.
/// Failure is not fatal — the data is already durable, only the link is at risk.
fn sync_parent_dir(path: &Path) {
    if let Some(dir) = path.parent() {
        if let Ok(handle) = fs::File::open(dir) {
            let _ = handle.sync_all();
        }
    }
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
        return adopt_existing(path, &raw, codec, kid);
    }

    let key = SigningKey::generate(kid);
    if write_new_owner_only(path, &codec.encrypt(&key.to_jwk_json()?))? {
        return Ok(key);
    }

    // Someone else created the file between our read and our link. Their key is
    // the one on disk and therefore the one the JWKS will publish, so read it
    // rather than returning the one we generated and threw away — two replicas
    // holding different keys under the same `kid` is precisely the split this
    // no-clobber guard exists to prevent.
    //
    // This goes through the SAME adoption path as a first read, deliberately. A
    // second copy of that logic drifted immediately: it lost the `trim` that
    // tolerates a hand-written file, so a winner's file with a trailing newline
    // failed to boot — but only for whoever lost the race, making it
    // non-deterministic — and it lost the plaintext re-encryption, so a legacy
    // key file adopted this way stayed in plaintext on disk despite a configured
    // encryption key.
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        // `read_to_string` follows a symlink and `hard_link` does not, so a
        // DANGLING SYMLINK at `path` reaches this branch: NotFound on the read,
        // EEXIST on the link. Naming the race here would be a lie.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "the signing-key path {} exists but cannot be read; it is most likely a \
                 dangling symlink, which must be removed or repointed by hand",
                path.display()
            )
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "re-reading the signing-key file at {} after losing the creation race",
                    path.display()
                )
            })
        }
    };
    adopt_existing(path, &raw, codec, kid)
}

/// Adopt a signing key that already exists on disk.
///
/// The single place a stored key becomes a usable one, so the first-read path
/// and the lost-race path cannot diverge in what they tolerate or what they
/// migrate.
fn adopt_existing(path: &Path, raw: &str, codec: &Codec, kid: &str) -> Result<SigningKey> {
    // Trimmed because a key file is something an operator may have written by
    // hand or with `echo`, and a trailing newline is not a corrupt key.
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
        // Upgrade a pre-encryption file in place. Reached for a key the Node
        // sidecar wrote, which is plaintext.
        rewrite_owner_only(path, &codec.encrypt(&plaintext))?;
    }
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

    /// The canonical form must be real JSON with real escaping. Building it by
    /// string interpolation produced invalid JSON — and therefore a thumbprint
    /// no other implementation reproduces — for any member containing a quote,
    /// a backslash or a control character.
    ///
    /// Such members cannot occur in a well-formed EC JWK (`x`/`y` are base64url),
    /// so the fix is to reject them rather than hash them. That matters because
    /// this function takes JWKs from REMOTE parties.
    #[test]
    fn public_thumbprint_of_rejects_members_that_are_not_base64url() {
        for x in [r#"A\"A"#, r#"A\\A"#, "A A", "A+A", "A/A", "AAA=", "", "é"] {
            let jwk = serde_json::json!({"kty":"EC","crv":"P-256","x":x,"y":"BBB"});
            assert!(
                SigningKey::public_thumbprint_of(&jwk.to_string()).is_err(),
                "accepted a non-base64url x: {x:?}"
            );
        }
    }

    #[test]
    fn public_thumbprint_of_rejects_malformed_or_non_ec_jwks() {
        for jwk in [
            r#"{"kty":"RSA","crv":"P-256","x":"AAA","y":"BBB"}"#,
            r#"{"kty":"EC","crv":"P-521","x":"AAA","y":"BBB"}"#,
            r#"{"kty":"EC","crv":"P-256","x":"AAA"}"#,
            r#"{"kty":"EC","crv":"P-256"}"#,
            r#"{"kty":"EC","crv":"P-256","x":123,"y":"BBB"}"#,
            "not json",
            "[]",
        ] {
            assert!(
                SigningKey::public_thumbprint_of(jwk).is_err(),
                "accepted {jwk}"
            );
        }
    }

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
        // Assert the SCALAR is absent, not the string `"d"`: the file is
        // base64url, which can never contain a quote, so checking for `"d"`
        // would pass even with no encryption at all.
        let scalar = serde_json::from_str::<serde_json::Value>(&key.to_jwk_json().unwrap())
            .unwrap()["d"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!raw.contains(&scalar), "private scalar found on disk");
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
        let on_disk = other.encrypt(JOSE_PRIVATE_JWK);
        std::fs::write(&path, &on_disk).unwrap();

        assert!(load_or_create(&path, &codec, KID).is_err());
        // And the unreadable key is LEFT ALONE. Replacing or deleting it would
        // discard a key that is merely locked behind the wrong passphrase.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            on_disk,
            "the key file was modified on a decrypt failure"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The persisted private JWK must use `key_ops`, not `use`. The sidecar
    /// writes `key_ops: ["sign"]`, and `jose` already warns that a private JWK
    /// carrying `use` will be rejected in future — which would break the
    /// rollback path this format exists to preserve.
    #[test]
    fn the_private_jwk_uses_key_ops_rather_than_use() {
        let key = SigningKey::generate(KID);
        let v: serde_json::Value = serde_json::from_str(&key.to_jwk_json().unwrap()).unwrap();
        assert_eq!(v["key_ops"], serde_json::json!(["sign"]));
        assert!(
            v.get("use").is_none(),
            "private JWK carries `use`, which jose deprecates"
        );
        // The PUBLIC half is a JWKS entry, where `use: sig` is the norm.
        assert_eq!(key.public_jwk().unwrap()["use"], "sig");
    }

    /// Migration rewrites an existing file. Doing that with truncate-then-write
    /// leaves a zero-length file if the process dies in between — and since an
    /// unreadable key file is deliberately a hard error, that would be a
    /// permanent boot failure. A temp file plus rename makes it atomic.
    #[test]
    fn migration_leaves_no_temporary_file_behind() {
        let path = tmp_path("atomic");
        let codec = Codec::new(Some(KEY)).unwrap();
        let original = SigningKey::generate(KID);
        std::fs::write(&path, original.to_jwk_json().unwrap()).unwrap();

        load_or_create(&path, &codec, KID).unwrap();

        let dir = path.parent().unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| {
                n.starts_with(path.file_name().unwrap().to_str().unwrap())
                    && n != path.file_name().unwrap().to_str().unwrap()
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
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

    /// **A symlinked key path must survive migration.** Replacing the link with
    /// a regular file breaks the operator's indirection AND strands the
    /// unencrypted private JWK at the old target — the exact opposite of what
    /// migrating to ciphertext is for.
    #[cfg(unix)]
    #[test]
    fn migrating_through_a_symlink_rewrites_the_target_not_the_link() {
        let target = tmp_path("symlink-target");
        let link = tmp_path("symlink-link");
        let _ = std::fs::remove_file(&link);
        let codec = Codec::new(Some(KEY)).unwrap();

        let original = SigningKey::generate(KID);
        std::fs::write(&target, original.to_jwk_json().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let loaded = load_or_create(&link, &codec, KID).unwrap();
        assert_eq!(loaded.thumbprint().unwrap(), original.thumbprint().unwrap());

        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink was replaced by a regular file"
        );
        let target_contents = std::fs::read_to_string(&target).unwrap();
        assert!(
            Aead::is_ciphertext(target_contents.trim()),
            "the real target still holds plaintext after migration"
        );
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
    }

    /// Two rewrites in a row must not collide on a shared temp path, and must
    /// leave nothing behind.
    #[cfg(unix)]
    #[test]
    fn repeated_migrations_leave_no_temporary_files() {
        let path = tmp_path("repeat");
        let codec = Codec::new(Some(KEY)).unwrap();
        let original = SigningKey::generate(KID);

        for _ in 0..3 {
            // Force the migrate-on-read path each time by writing plaintext.
            std::fs::write(&path, original.to_jwk_json().unwrap()).unwrap();
            let loaded = load_or_create(&path, &codec, KID).unwrap();
            assert_eq!(loaded.thumbprint().unwrap(), original.thumbprint().unwrap());
        }

        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(&name) && *n != name)
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn a_created_key_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("mode");
        let codec = Codec::new(Some(KEY)).unwrap();
        load_or_create(&path, &codec, KID).unwrap();

        // Assert no group/other bits rather than an exact 0600: `OpenOptions::mode`
        // is masked by umask, so a umask of 0o177 legitimately yields 0o400.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "key file mode {mode:o} is group/world readable"
        );
        let _ = std::fs::remove_file(&path);
    }
}
