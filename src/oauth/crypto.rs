//! Application-layer at-rest encryption for the OAuth secrets.
//!
//! Everything security-sensitive that is persisted — the atproto OAuth
//! access/refresh tokens, the per-DID DPoP key material, the short-lived
//! per-auth-request state, and the confidential-client signing JWK — is
//! AEAD-encrypted *before* it touches the SQLite volume (or, for the JWK, the
//! disk file). The key comes only from the process environment, never from the
//! volume, so a raw volume/snapshot read is useless without the running
//! process's environment.
//!
//! Construction throughout: AES-256-GCM, random 96-bit nonce per record,
//! 128-bit auth tag, serialized as a self-describing string. There are **two
//! formats**, differing only in what is authenticated alongside the ciphertext:
//!
//! ```text
//! enc.v1.gcm.<b64url(nonce)>.<b64url(tag)>.<b64url(ct)>    AAD = empty
//! enc.v2.gcm.<b64url(nonce)>.<b64url(tag)>.<b64url(ct)>    AAD = binding context
//! ```
//!
//! **v1 is byte-identical to the Node sidecar's `crypto.ts`**, and must stay
//! that way: it is what lets this implementation read what the sidecar wrote,
//! which is what makes the cutover reversible. The cross-implementation test at
//! the bottom of this file pins that against ciphertext from the real sidecar.
//! It is used for the signing-key file, the one artefact a rollback must read.
//!
//! **v2 binds a record to where it lives.** The AAD names the row and column, so
//! a ciphertext lifted into a different row fails to authenticate rather than
//! decrypting into the wrong place. Without it, anything able to write the
//! database could graft one login flow's DPoP key or issuer onto another flow's
//! state row. The OAuth state and session tables are new, so the bound form can
//! be *required* there from the start — and it is: [`Aead::decrypt_bound`]
//! rejects a v1 token, because accepting one would make the binding opt-out.
//!
//! The prefix also lets [`Aead::maybe_decrypt`] do migrate-on-read: a stored
//! value with NEITHER prefix is treated as legacy plaintext and returned as-is,
//! so a file written before encryption was enabled keeps working and is
//! transparently re-encrypted on the next write.

use anyhow::{bail, Context as _, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::digest::SHA256;

/// Unbound records: AAD is empty. **The sidecar-compatible format** — used for
/// the signing-key file, where a rollback to the Node sidecar must still be able
/// to read what we wrote.
const PREFIX_V1: &str = "enc.v1.gcm.";

/// Bound records: AAD is a binding context naming the row and column the
/// ciphertext belongs to, so it authenticates nowhere else.
///
/// Introduced for the OAuth state and session tables. Those are new, so there
/// are no legacy rows to tolerate and the bound form can be *required* from the
/// start — which is the whole point. Accepting a [`PREFIX_V1`] token where a
/// bound one is expected would make the binding opt-out: anything able to write
/// the row would simply store the unbound form instead.
const PREFIX_V2: &str = "enc.v2.gcm.";

/// AES-256 key length.
const KEY_LEN: usize = 32;

/// AES-GCM authentication tag length.
const TAG_LEN: usize = 16;

/// Domain separator for the passphrase path. Part of the on-disk contract —
/// changing it silently invalidates every stored ciphertext.
const PASSPHRASE_DOMAIN: &str = "featherreader-sidecar-enc:v1:";

/// If `raw` is EXACTLY a 32-byte key encoded as hex or canonical
/// base64/base64url, return those bytes; otherwise `None`.
///
/// Base64 decoding is lenient in many implementations (the sidecar's `Buffer`
/// silently drops invalid characters), so a passphrase that merely *happens* to
/// be base64-shaped could decode to 32 bytes and be mistaken for a key. The
/// guard is a round-trip: the decoded bytes must RE-ENCODE to exactly the input,
/// which is only true if it really was a canonical 32-byte key.
fn decode_exact_key(raw: &str) -> Option<[u8; KEY_LEN]> {
    let mut out = [0u8; KEY_LEN];

    if raw.len() == KEY_LEN * 2 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).ok()?;
        }
        return Some(out);
    }

    // Standard base64 (padded or not) and base64url are the three canonical
    // spellings the sidecar accepts. Requiring a clean round-trip through one of
    // them is equivalent to its `raw === std || raw === std-no-pad || raw === url`
    // check, without inheriting the lenient decode.
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(raw) {
            if bytes.len() == KEY_LEN && engine.encode(&bytes) == raw {
                out.copy_from_slice(&bytes);
                return Some(out);
            }
        }
    }
    None
}

/// Derive the 32-byte AES key from the raw configured value.
///
/// A value that is EXACTLY a 32-byte key (hex or canonical base64/base64url) is
/// used directly; anything else is treated as a passphrase and hashed with a
/// domain-separated SHA-256. Deterministic — the same input always maps to the
/// same key, so restarts and rolling deploys decrypt existing rows.
pub fn derive_key(raw: &str) -> [u8; KEY_LEN] {
    if let Some(exact) = decode_exact_key(raw) {
        return exact;
    }
    let mut ctx = ring::digest::Context::new(&SHA256);
    ctx.update(PASSPHRASE_DOMAIN.as_bytes());
    ctx.update(raw.as_bytes());
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// A bound encryptor/decryptor holding the derived key.
pub struct Aead {
    key: LessSafeKey,
}

impl Aead {
    /// Build a codec from the raw configured key value (see [`derive_key`]).
    pub fn new(raw_key: &str) -> Result<Self> {
        let key = UnboundKey::new(&AES_256_GCM, &derive_key(raw_key))
            .map_err(|_| anyhow::anyhow!("failed to build an AES-256-GCM key"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
        })
    }

    /// True if `value` is one of our ciphertext tokens, in EITHER format (vs.
    /// legacy plaintext).
    ///
    /// Recognising both matters: if this matched only v1, then
    /// [`Aead::maybe_decrypt`] would classify a bound token as legacy plaintext
    /// and hand the raw ciphertext back to the caller as though it were the
    /// value.
    pub fn is_ciphertext(value: &str) -> bool {
        value.starts_with(PREFIX_V1) || value.starts_with(PREFIX_V2)
    }

    /// Encrypt into an unbound `enc.v1.gcm.…` token (AAD empty).
    ///
    /// **Panics if the OS CSPRNG is unavailable.** This is a deliberate
    /// divergence from [`crate::new_session_id`], which falls back to a weak
    /// entropy mix: a guessable session id is bad, but a REPEATED GCM nonce is
    /// catastrophic — it leaks the XOR of two plaintexts and enables tag
    /// forgery. There is no safe degraded mode here, so this fails loudly.
    pub fn encrypt(&self, plaintext: &str) -> String {
        self.seal(plaintext, PREFIX_V1, b"")
    }

    /// Encrypt into a **bound** `enc.v2.gcm.…` token.
    ///
    /// `aad` names the row and column this ciphertext belongs to, so it
    /// authenticates nowhere else — moving it to another row makes it
    /// undecryptable rather than silently valid.
    pub fn encrypt_bound(&self, plaintext: &str, aad: &[u8]) -> String {
        self.seal(plaintext, PREFIX_V2, aad)
    }

    fn seal(&self, plaintext: &str, prefix: &str, aad: &[u8]) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .expect("OS CSPRNG unavailable; refusing to encrypt with a non-random GCM nonce");

        let mut in_out = plaintext.as_bytes().to_vec();
        let tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut in_out,
            )
            .expect("AES-256-GCM sealing cannot fail for a well-formed key and nonce");

        format!(
            "{prefix}{}.{}.{}",
            URL_SAFE_NO_PAD.encode(nonce),
            URL_SAFE_NO_PAD.encode(tag.as_ref()),
            URL_SAFE_NO_PAD.encode(&in_out),
        )
    }

    /// Decrypt an UNBOUND `enc.v1.gcm.…` token. A bound token is rejected here:
    /// reading one through this path would drop the binding check silently.
    pub fn decrypt(&self, token: &str) -> Result<String> {
        self.open(token, PREFIX_V1, b"")
    }

    /// Decrypt a **bound** `enc.v2.gcm.…` token, requiring `aad` to match the
    /// binding it was sealed under.
    ///
    /// An unbound v1 token is REJECTED rather than accepted-without-checking:
    /// otherwise the binding is opt-out and anything able to write the row would
    /// simply store the unbound form.
    pub fn decrypt_bound(&self, token: &str, aad: &[u8]) -> Result<String> {
        self.open(token, PREFIX_V2, aad)
    }

    fn open(&self, token: &str, prefix: &str, aad: &[u8]) -> Result<String> {
        let rest = token
            .strip_prefix(prefix)
            .with_context(|| format!("not an {}ciphertext token", &prefix[..7]))?;

        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() != 3 {
            bail!(
                "malformed ciphertext token: expected 3 segments, got {}",
                parts.len()
            );
        }
        let nonce = URL_SAFE_NO_PAD
            .decode(parts[0])
            .context("bad nonce encoding")?;
        let tag = URL_SAFE_NO_PAD
            .decode(parts[1])
            .context("bad tag encoding")?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(parts[2])
            .context("bad ciphertext encoding")?;

        // Check lengths before handing anything to the AEAD, so a truncated
        // token is a clear error rather than an opaque decrypt failure.
        if nonce.len() != NONCE_LEN {
            bail!("bad nonce length: {} (want {NONCE_LEN})", nonce.len());
        }
        if tag.len() != TAG_LEN {
            bail!("bad tag length: {} (want {TAG_LEN})", tag.len());
        }
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&nonce);

        // ring's `open_in_place` expects ciphertext||tag contiguously.
        let mut in_out = ciphertext;
        in_out.extend_from_slice(&tag);

        let plaintext = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad),
                &mut in_out,
            )
            .map_err(|_| anyhow::anyhow!("ciphertext failed authentication"))?;

        String::from_utf8(plaintext.to_vec()).context("decrypted bytes are not valid UTF-8")
    }

    /// Migrate-on-read: decrypt if the value is one of our tokens, otherwise
    /// treat it as legacy plaintext and return it unchanged. Callers re-encrypt
    /// on the next write, transparently upgrading old rows.
    pub fn maybe_decrypt(&self, value: &str) -> Result<String> {
        if Self::is_ciphertext(value) {
            self.decrypt(value)
        } else {
            Ok(value.to_string())
        }
    }
}

/// The codec actually installed: real AEAD, or a pass-through used only on a
/// localhost dev stack where no key is configured. Production refuses to boot
/// without a real key, so [`Codec::Null`] never runs there.
pub enum Codec {
    /// Boxed: ring's expanded AES key schedule makes [`Aead`] ~544 bytes, and an
    /// enum sized to its largest variant would be paid for by every `Null` too.
    Aead(Box<Aead>),
    Null,
}

impl Codec {
    /// Build the codec for a configured key, or the pass-through when none is
    /// set. Production validates that a key IS set before calling this.
    pub fn new(raw_key: Option<&str>) -> Result<Self> {
        match raw_key {
            Some(raw) => Ok(Codec::Aead(Box::new(Aead::new(raw)?))),
            None => Ok(Codec::Null),
        }
    }

    pub fn encrypt(&self, plaintext: &str) -> String {
        match self {
            Codec::Aead(a) => a.encrypt(plaintext),
            Codec::Null => plaintext.to_string(),
        }
    }

    /// Encrypt bound to `aad` — see [`Aead::encrypt_bound`].
    ///
    /// [`Codec::Null`] passes through, so a dev stack with no key configured gets
    /// no binding either. That is the same trade the unbound path already makes,
    /// and production is required to configure a key.
    pub fn encrypt_bound(&self, plaintext: &str, aad: &[u8]) -> String {
        match self {
            Codec::Aead(a) => a.encrypt_bound(plaintext, aad),
            Codec::Null => plaintext.to_string(),
        }
    }

    /// Decrypt a bound record — see [`Aead::decrypt_bound`].
    pub fn decrypt_bound(&self, token: &str, aad: &[u8]) -> Result<String> {
        match self {
            Codec::Aead(a) => a.decrypt_bound(token, aad),
            Codec::Null => Ok(token.to_string()),
        }
    }

    pub fn maybe_decrypt(&self, value: &str) -> Result<String> {
        match self {
            Codec::Aead(a) => a.maybe_decrypt(value),
            Codec::Null => Ok(value.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 43 base64url chars. This decodes to 32 bytes but does NOT re-encode back
    /// to the input, so it must take the PASSPHRASE path, not the raw-key path.
    /// The sidecar's own test suite uses this exact value.
    const KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // ── derive_key ───────────────────────────────────────────────────────────

    #[test]
    fn derive_key_uses_an_exact_32_byte_base64_value_directly() {
        let raw = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(derive_key(&raw), [7u8; 32]);
    }

    #[test]
    fn derive_key_uses_a_64_char_hex_value_directly() {
        let raw = "ab".repeat(32);
        assert_eq!(derive_key(&raw), [0xabu8; 32]);
    }

    #[test]
    fn derive_key_uses_an_exact_32_byte_base64url_value_directly() {
        // base64url of 0xFB… contains the url-safe `-` and `_` characters.
        let raw = "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s";
        assert!(raw.contains('-') && raw.contains('_'));
        assert_eq!(derive_key(raw), [0xfbu8; 32]);
    }

    /// Not canonical hex/base64 of a 32-byte key, so it is hashed -- with the
    /// domain separator. Asserting the exact expected digest rather than merely
    /// "not the raw bytes": the weaker form passes for any hash, including one
    /// with the separator dropped, which would silently invalidate every stored
    /// ciphertext.
    #[test]
    fn derive_key_hashes_a_human_passphrase_with_the_domain_separator() {
        let pass = "correct horse battery staple pad!";
        let mut ctx = ring::digest::Context::new(&SHA256);
        ctx.update(b"featherreader-sidecar-enc:v1:");
        ctx.update(pass.as_bytes());
        let expected: [u8; 32] = ctx.finish().as_ref().try_into().unwrap();

        assert_eq!(derive_key(pass), expected);
        assert_ne!(derive_key(pass), pass.as_bytes()[..32]);
        // A bare SHA-256 with no domain separation must NOT be what we produce.
        let undomained = ring::digest::digest(&SHA256, pass.as_bytes());
        assert_ne!(derive_key(pass).as_slice(), undomained.as_ref());
    }

    #[test]
    fn derive_key_is_deterministic_and_distinguishes_passphrases() {
        let a = derive_key("some-long-passphrase-value");
        assert_eq!(a, derive_key("some-long-passphrase-value"));
        assert_ne!(a, derive_key("different"));
    }

    /// A base64-SHAPED value that is not a canonical 32-byte key must take the
    /// passphrase path.
    ///
    /// Asserted as an EQUALITY against the domain-separated digest, not as a
    /// `!=` against some value we guess a broken implementation would return.
    /// Two earlier versions of this test guessed wrong: `[b'a'; 32]` (the ASCII
    /// bytes) and then `69 A6 9A…` (the lenient decode Node's `Buffer` would
    /// produce). base64 0.22's engines are strict and reject `"a"×43` outright
    /// — `InvalidPadding` / `InvalidLastSymbol` — so neither value is reachable
    /// and both assertions held for the wrong reason.
    ///
    /// Which also means: with these strict engines, a successful decode already
    /// implies canonicality, so `decode_exact_key`'s re-encode check is
    /// belt-and-braces rather than load-bearing. It is kept because it is the
    /// property we actually want to hold, independent of how strict the decoder
    /// happens to be.
    #[test]
    fn a_non_canonical_base64_lookalike_takes_the_passphrase_path() {
        let mut ctx = ring::digest::Context::new(&SHA256);
        ctx.update(PASSPHRASE_DOMAIN.as_bytes());
        ctx.update(KEY.as_bytes());
        let expected: [u8; 32] = ctx.finish().as_ref().try_into().unwrap();
        assert_eq!(derive_key(KEY), expected, "not the passphrase path");

        // And the raw-key path is still taken for a genuinely canonical value,
        // so the two are distinguished rather than everything being hashed.
        let canonical = URL_SAFE_NO_PAD.encode([0x11u8; 32]);
        assert_eq!(derive_key(&canonical), [0x11u8; 32]);
    }

    // ── round-trip ───────────────────────────────────────────────────────────

    #[test]
    fn aead_round_trips_and_produces_enc_v1_tokens() {
        let aead = Aead::new(KEY).unwrap();
        let ct = aead.encrypt("hello secret");
        assert!(ct.starts_with("enc.v1.gcm."));
        assert!(Aead::is_ciphertext(&ct));
        assert_eq!(aead.decrypt(&ct).unwrap(), "hello secret");
    }

    /// Compares the NONCE SEGMENT, not the whole token: two tokens differing
    /// only in ciphertext would satisfy a whole-token comparison while reusing
    /// the nonce, which is the catastrophic case for GCM. A counter nonce is
    /// also rejected — 32 samples must all be distinct AND not sequential.
    #[test]
    fn aead_uses_a_fresh_random_nonce_per_record() {
        let aead = Aead::new(KEY).unwrap();
        let nonce_of = |token: &str| token.split('.').nth(3).unwrap().to_string();

        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let token = aead.encrypt("same");
            let nonce = nonce_of(&token);
            assert!(seen.insert(nonce), "GCM nonce reused across records");
            assert_eq!(aead.decrypt(&token).unwrap(), "same");
        }
        // A counter would produce nonces differing only in the last bytes.
        let a = nonce_of(&aead.encrypt("x"));
        let b = nonce_of(&aead.encrypt("x"));
        let shared_prefix = a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count();
        assert!(
            shared_prefix < a.len() / 2,
            "nonces look sequential rather than random: {a} vs {b}"
        );
    }

    #[test]
    fn aead_round_trips_empty_and_non_ascii_plaintext() {
        let aead = Aead::new(KEY).unwrap();
        for pt in ["", "dídj — ünïcode ✓"] {
            let ct = aead.encrypt(pt);
            assert_eq!(aead.decrypt(&ct).unwrap(), pt);
        }
    }

    // ── authentication ───────────────────────────────────────────────────────

    #[test]
    fn aead_rejects_tampered_ciphertext() {
        let aead = Aead::new(KEY).unwrap();
        let ct = aead.encrypt("tamperme");
        let mut parts: Vec<&str> = ct.split('.').collect();
        // Flip a byte in the ciphertext segment (enc . v1 . gcm . nonce . tag . ct).
        let mut bad = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[5])
            .unwrap();
        bad[0] ^= 0xff;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bad);
        parts[5] = &encoded;
        assert!(aead.decrypt(&parts.join(".")).is_err());
    }

    #[test]
    fn aead_rejects_a_ciphertext_sealed_under_a_different_key() {
        let ct = Aead::new(KEY).unwrap().encrypt("cross-key");
        let other = Aead::new("totally-different-passphrase-here").unwrap();
        assert!(other.decrypt(&ct).is_err());
    }

    #[test]
    fn aead_rejects_malformed_tokens() {
        let aead = Aead::new(KEY).unwrap();
        for bad in [
            "enc.v1.gcm.only-two.parts",
            "enc.v1.gcm.AAAA.AAAA.AAAA.AAAA",
            "enc.v1.gcm...",
            "not-a-token",
        ] {
            assert!(aead.decrypt(bad).is_err(), "should reject {bad:?}");
        }
    }

    /// A truncated nonce or tag must be rejected on length, not fed to the AEAD.
    #[test]
    fn aead_rejects_wrong_length_nonce_and_tag() {
        let aead = Aead::new(KEY).unwrap();
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let short_nonce = format!(
            "enc.v1.gcm.{}.{}.{}",
            b64(&[0u8; 4]),
            b64(&[0u8; 16]),
            b64(b"")
        );
        let short_tag = format!(
            "enc.v1.gcm.{}.{}.{}",
            b64(&[0u8; 12]),
            b64(&[0u8; 4]),
            b64(b"")
        );
        assert!(aead.decrypt(&short_nonce).is_err());
        assert!(aead.decrypt(&short_tag).is_err());
    }

    // ── migrate-on-read ──────────────────────────────────────────────────────

    #[test]
    fn maybe_decrypt_passes_legacy_plaintext_through_unchanged() {
        let aead = Aead::new(KEY).unwrap();
        assert_eq!(
            aead.maybe_decrypt(r#"{"legacy":true}"#).unwrap(),
            r#"{"legacy":true}"#
        );
        let ct = aead.encrypt(r#"{"legacy":true}"#);
        assert_eq!(aead.maybe_decrypt(&ct).unwrap(), r#"{"legacy":true}"#);
    }

    #[test]
    fn null_codec_passes_through_in_both_directions() {
        let n = Codec::new(None).unwrap();
        assert!(matches!(n, Codec::Null));
        assert_eq!(n.encrypt("x"), "x");
        assert_eq!(n.maybe_decrypt("x").unwrap(), "x");
    }

    #[test]
    fn aead_codec_round_trips_and_still_reads_legacy_plaintext() {
        let c = Codec::new(Some(KEY)).unwrap();
        let ct = c.encrypt("secret");
        assert!(Aead::is_ciphertext(&ct));
        assert_eq!(c.maybe_decrypt(&ct).unwrap(), "secret");
        // A row written before encryption was switched on still reads back.
        assert_eq!(c.maybe_decrypt("legacy").unwrap(), "legacy");
    }

    // ── AAD-bound records (v2) ───────────────────────────────────────────────

    const STATE_AAD: &[u8] = b"oauth_state:abc123:dpop_key_jwk";
    const OTHER_AAD: &[u8] = b"oauth_state:def456:dpop_key_jwk";

    #[test]
    fn bound_records_round_trip_under_their_own_binding() {
        let aead = Aead::new(KEY).unwrap();
        let ct = aead.encrypt_bound("secret", STATE_AAD);
        assert!(ct.starts_with("enc.v2.gcm."));
        assert_eq!(aead.decrypt_bound(&ct, STATE_AAD).unwrap(), "secret");
    }

    /// **The property AAD exists for.** A ciphertext lifted out of one row must
    /// not authenticate in another. Without this, anything with DB write access
    /// can graft one login flow's DPoP key or issuer onto another flow's state.
    #[test]
    fn a_bound_record_does_not_authenticate_under_a_different_binding() {
        let aead = Aead::new(KEY).unwrap();
        let ct = aead.encrypt_bound("secret", STATE_AAD);
        assert!(
            aead.decrypt_bound(&ct, OTHER_AAD).is_err(),
            "a ciphertext moved between rows still authenticated"
        );
        assert!(aead.decrypt_bound(&ct, b"").is_err());
    }

    /// **Downgrade prevention.** If a v1 (unbound) token were accepted where a
    /// bound one is expected, the binding would be opt-out: an attacker who can
    /// write the row just stores the unbound form instead.
    #[test]
    fn an_unbound_v1_token_is_rejected_where_a_bound_one_is_expected() {
        let aead = Aead::new(KEY).unwrap();
        let v1 = aead.encrypt("secret");
        assert!(v1.starts_with("enc.v1.gcm."));
        assert!(
            aead.decrypt_bound(&v1, STATE_AAD).is_err(),
            "a v1 token was accepted as bound -- the binding is bypassable"
        );
        assert!(aead.decrypt_bound(&v1, b"").is_err());
    }

    /// And the reverse, so a bound record cannot be read by the unbound path
    /// (which would drop the binding check silently).
    #[test]
    fn a_bound_v2_token_is_rejected_by_the_unbound_path() {
        let aead = Aead::new(KEY).unwrap();
        let v2 = aead.encrypt_bound("secret", STATE_AAD);
        assert!(aead.decrypt(&v2).is_err());
        // And `maybe_decrypt` must NOT mistake it for legacy plaintext and hand
        // the raw ciphertext back to the caller as though it were the value.
        let returned = aead.maybe_decrypt(&v2);
        assert!(
            returned.is_err(),
            "v2 token was treated as legacy plaintext"
        );
    }

    #[test]
    fn is_ciphertext_recognises_both_formats() {
        let aead = Aead::new(KEY).unwrap();
        assert!(Aead::is_ciphertext(&aead.encrypt("x")));
        assert!(Aead::is_ciphertext(&aead.encrypt_bound("x", STATE_AAD)));
        assert!(!Aead::is_ciphertext("{\"legacy\":true}"));
    }

    #[test]
    fn bound_records_use_a_fresh_nonce_and_reject_tampering() {
        let aead = Aead::new(KEY).unwrap();
        let a = aead.encrypt_bound("same", STATE_AAD);
        let b = aead.encrypt_bound("same", STATE_AAD);
        assert_ne!(
            a.split('.').nth(3).unwrap(),
            b.split('.').nth(3).unwrap(),
            "GCM nonce reused"
        );

        let mut parts: Vec<&str> = a.split('.').collect();
        let mut bad = URL_SAFE_NO_PAD.decode(parts[5]).unwrap();
        bad[0] ^= 0xff;
        let encoded = URL_SAFE_NO_PAD.encode(&bad);
        parts[5] = &encoded;
        assert!(aead.decrypt_bound(&parts.join("."), STATE_AAD).is_err());
    }

    #[test]
    fn the_codec_exposes_the_bound_path_and_null_passes_through() {
        let real = Codec::new(Some(KEY)).unwrap();
        let ct = real.encrypt_bound("secret", STATE_AAD);
        assert_eq!(real.decrypt_bound(&ct, STATE_AAD).unwrap(), "secret");
        assert!(real.decrypt_bound(&ct, OTHER_AAD).is_err());

        // Dev-only: no key configured means no binding either. Documented, and
        // the same pass-through semantics the unbound path already has.
        let null = Codec::new(None).unwrap();
        assert_eq!(null.encrypt_bound("secret", STATE_AAD), "secret");
        assert_eq!(null.decrypt_bound("secret", OTHER_AAD).unwrap(), "secret");
    }

    // ── cross-implementation compatibility ───────────────────────────────────

    /// **The property that makes the cutover reversible.** These vectors were
    /// produced by the REAL Node sidecar (`oauth-sidecar/dist/crypto.js`), not
    /// by this implementation, so they fail if the Rust codec drifts from the
    /// sidecar's wire format in any way -- key derivation, nonce/tag ordering,
    /// base64url alphabet, or padding.
    ///
    /// Regenerate with:
    /// ```text
    /// node --input-type=module -e 'import {Aead} from "./dist/crypto.js"; \
    ///   console.log(new Aead("a".repeat(43)).encrypt("hello secret"))'
    /// ```
    #[test]
    fn decrypts_ciphertext_written_by_the_node_sidecar() {
        let aead = Aead::new(KEY).unwrap();
        for (ct, want) in [
            ("enc.v1.gcm.DPcybWacAm5WDhlF.j0n0Xyp9NH7ZtEmYcF9--A.OZ_jVOWQQEmIdTA2", "hello secret"),
            ("enc.v1.gcm.SmooV-sJqpA9v36g.S_xxfASFlnW0Fq0wLrCGRA.bBKUffzXmA73IEJ_ohLy", r#"{"legacy":true}"#),
            ("enc.v1.gcm.K3c6m783VlJRypbr.G7xjgmQ8vca736zsGpoTMg.", ""),
            ("enc.v1.gcm.hZNdycctWKVXf7eV.qWe0AQOCUeNKmGzoKN79gw.Btk3lyNkAHPGAx4YqxJFa3EqGnJl0Pk", "dídj — ünïcode ✓"),
        ] {
            assert_eq!(aead.decrypt(ct).unwrap(), want, "failed on {ct}");
        }
    }

    /// The derivation itself must match the sidecar's, for both the raw-key and
    /// the domain-separated passphrase paths. Expected values come from the same
    /// `deriveKey` the sidecar ships.
    #[test]
    fn derive_key_matches_the_node_sidecar() {
        let hex = |s: &str| {
            let mut out = [0u8; 32];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
            }
            out
        };
        assert_eq!(
            derive_key("some-long-passphrase-value"),
            hex("9597cec213096d8f62f3a917434421efea7b6b4be0ab623e87c72c9c96ee283b"),
        );
        assert_eq!(
            derive_key(KEY),
            hex("49dbed3b7aed2c3a965b9bae6032107cfaee9bedac29022507d39867b628155f"),
        );
    }
}
