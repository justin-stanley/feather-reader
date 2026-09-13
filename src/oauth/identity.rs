//! atproto identity resolution: handle → DID → DID document → PDS.
//!
//! The security property that matters here is **bidirectional verification**.
//! The atproto spec makes it mandatory: *"If starting with a handle, it is
//! critical (mandatory) to bidirectionally verify the handle by checking that
//! the DID document claims the handle."* A handle is a DNS name someone else
//! controls; without the back-check, whoever controls `victim.example` can point
//! it at any DID they like.
//!
//! The comparison is deliberately narrow — equality against the **first**
//! `at://` entry in `alsoKnownAs`, not membership in the array. A "is the handle
//! anywhere in the list" check reintroduces the attack, because an attacker's
//! own DID document can list the victim's handle as a secondary entry.

use anyhow::{bail, Context as _, Result};
use serde_json::Value;
use std::collections::HashSet;

/// TLDs the handle spec disallows outright.
///
/// `.local` and `.internal` are the ones that matter operationally: a handle
/// ending in either is an attempt to steer resolution at the internal network,
/// and rejecting it here means the SSRF guard is a second line of defence rather
/// than the only one.
const RESERVED_TLDS: [&str; 8] = [
    "alt",
    "arpa",
    "example",
    "internal",
    "invalid",
    "local",
    "localhost",
    "onion",
];

/// The `at://` prefix an `alsoKnownAs` handle claim carries.
const AT_URI_PREFIX: &str = "at://";

/// Normalize and validate a handle: lowercase, then check it against the
/// handle grammar and the reserved-TLD list.
///
/// Normalizing BEFORE any comparison is what makes the bidirectional check in
/// [`verify_handle_claim`] sound; comparing raw input against a raw claim would
/// make `Alice.example` and `alice.example` different handles.
pub fn normalize_handle(input: &str) -> Result<String> {
    let handle = input.trim().to_ascii_lowercase();
    if handle.is_empty() || handle.len() > 253 {
        bail!("handle {input:?} has an invalid length");
    }
    let labels: Vec<&str> = handle.split('.').collect();
    if labels.len() < 2 {
        bail!("handle {input:?} must have at least two segments");
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            bail!("handle {input:?} has an empty or over-long segment");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            bail!("handle {input:?} has a segment with illegal characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("handle {input:?} has a segment starting or ending with a hyphen");
        }
    }
    // Spec: "The last segment (the 'top level domain') can not start with a
    // numeric digit." Rejecting only ALL-numeric TLDs would let `alice.1com`
    // and `alice.4chan` through.
    let tld = labels[labels.len() - 1];
    if tld.starts_with(|c: char| c.is_ascii_digit()) {
        bail!("handle {input:?} has a TLD starting with a digit");
    }
    if RESERVED_TLDS.contains(&tld) {
        bail!("handle {input:?} uses the reserved TLD .{tld}");
    }
    Ok(handle)
}

/// Whether a `did:web` method-specific id is a bare, canonical hostname.
///
/// This is the gate that stops URL construction from being steerable. Two
/// shapes matter and neither is obvious:
///
/// * `good.com@evil.com` builds `https://good.com@evil.com/…`, whose ACTUAL
///   host is `evil.com` — the plausible-looking part is demoted to userinfo.
/// * `evil.com/x` is a straight path injection into the well-known path.
///
/// `:` is the did:web path separator (a port is spelled `%3A`), and atproto
/// permits neither, so any of them disqualifies the DID.
fn is_bare_did_web_host(host: &str) -> bool {
    if host.is_empty() || host != host.to_ascii_lowercase() {
        return false;
    }
    // Explicitly, rather than relying on the URL parser to object: these are
    // the characters that change what the host IS.
    if host.bytes().any(|b| {
        matches!(b, b':' | b'/' | b'@' | b'%' | b'?' | b'#' | b'\\') || b.is_ascii_whitespace()
    }) {
        return false;
    }
    if !host.contains('.') {
        return false; // a bare token is not a resolvable host
    }
    // The SAME reserved-TLD policy handles are held to. `normalize_handle`
    // applies it and this did not, so `did:web:printer.local` and
    // `did:web:pds.internal` were accepted and fetched. The SSRF guard does stop
    // them — but the rule this module states for handles is that rejecting here
    // makes the guard a SECOND line of defence rather than the only one, and for
    // `did:web` it was the only one.
    if let Some(tld) = host.rsplit('.').next() {
        if RESERVED_TLDS.contains(&tld) {
            return false;
        }
    }
    // An IP literal is not a name, and `did:web:169.254.169.254` is a cloud
    // metadata endpoint. A dotted-quad passes the label rules below, so it has
    // to be refused explicitly.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    // `IpAddr` only parses the CANONICAL spelling, while the URL parser the
    // fetch path uses accepts far more: `127.1`, `0177.0.0.1` and `0x7f.0.0.1`
    // all resolve to 127.0.0.1 and all passed the check above. A real TLD is
    // never entirely numeric, so refusing a numeric final label catches every
    // such spelling without needing to reimplement the URL parser's arithmetic.
    // It is the same rule `normalize_handle` applies to handles.
    if let Some(tld) = host.rsplit('.').next() {
        if tld.starts_with(|c: char| c.is_ascii_digit()) {
            return false;
        }
    }
    // A DNS name is at most 253 bytes, and each label at most 63; anything
    // longer cannot resolve, and an unbounded one is only useful for making us
    // construct absurd URLs. Both bounds, to match what `normalize_handle`
    // enforces — the earlier version checked only the total.
    if host.len() > 253 || host.split('.').any(|label| label.len() > 63) {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Whether `did` is a DID this client can resolve: `did:plc:` or `did:web:`.
///
/// This is the ONLY validation applied to a DID arriving from a TXT record or a
/// well-known document, so anything it waves through becomes the account's
/// identity and, for `did:web`, part of a URL.
pub fn is_atproto_did(did: &str) -> bool {
    if let Some(ident) = did.strip_prefix("did:plc:") {
        // base32-SORTABLE: `[a-z2-7]`, 24 characters. Not `[a-z0-9]` — `0`,
        // `1`, `8` and `9` are not in that alphabet.
        return ident.len() == 24
            && ident
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
    }
    if let Some(host) = did.strip_prefix("did:web:") {
        return is_bare_did_web_host(host);
    }
    false
}

/// Join one TXT record's character-strings into its value.
///
/// A DNS TXT record is a SEQUENCE of strings, each at most 255 bytes, and the
/// record's value is their concatenation. A DID that crosses that boundary
/// arrives as two chunks; passing them along as two separate records produces
/// two truncated fragments, neither a valid DID, and the handle fails to resolve
/// with nothing to show for it.
///
/// `dig +short` performs this join itself, which is precisely why a shell-based
/// spike will never surface the bug.
pub fn join_txt_chunks(chunks: &[&[u8]]) -> String {
    let joined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    String::from_utf8_lossy(&joined).into_owned()
}

/// Extract the DID from a handle's `_atproto` TXT records.
///
/// `Ok(None)` means no record — a normal outcome that falls through to the
/// well-known lookup. An error means the records are present but unusable, which
/// must NOT fall through.
///
/// **Two differing records fail rather than picking one.** Spec: *"If multiple
/// valid records with different DIDs are present, resolution should fail."*
/// Taking the first would let anyone able to add a TXT record to a zone hijack a
/// handle that already resolves.
///
/// The value after `did=` is deliberately NOT trimmed, matching the spec and the
/// reference: a padded record is invalid rather than silently repaired.
pub fn did_from_txt_records(records: &[String]) -> Result<Option<String>> {
    let mut candidates: Vec<&str> = records
        .iter()
        .filter_map(|r| r.strip_prefix("did="))
        .collect();
    // **Deduplicate before counting.** The spec fails resolution when multiple
    // records name DIFFERENT DIDs; this counted RECORDS. A zone that serves the
    // same `did=` value twice — routine with split-horizon or multi-provider DNS
    // — was an unrecoverable error, and because it is an `Err` rather than
    // `Ok(None)` it does not even fall through to the well-known lookup. That
    // account simply could not log in.
    candidates.sort_unstable();
    candidates.dedup();

    match candidates.len() {
        0 => Ok(None),
        1 => {
            let did = candidates[0];
            if !is_atproto_did(did) {
                bail!("_atproto TXT record does not contain a usable DID: {did:?}");
            }
            Ok(Some(did.to_string()))
        }
        n => bail!("{n} `did=` TXT records present; resolution must fail rather than choose"),
    }
}

/// Extract the DID from a `/.well-known/atproto-did` body: first line, trimmed.
pub fn did_from_well_known(body: &str) -> Result<String> {
    let did = body.lines().next().unwrap_or_default().trim();
    if !is_atproto_did(did) {
        bail!("/.well-known/atproto-did did not contain a usable DID");
    }
    Ok(did.to_string())
}

/// Where a DID's document lives.
///
/// atproto restricts `did:web` to a bare hostname — **no path components and no
/// port** (localhost excepted, which this client has no use for). A `did:web`
/// carrying extra segments would otherwise let a DID name an arbitrary path on a
/// host, which is a needlessly large surface for something resolved from user
/// input.
pub fn did_document_url(did: &str, plc_directory: &str) -> Result<String> {
    if let Some(ident) = did.strip_prefix("did:plc:") {
        if !is_atproto_did(did) {
            bail!("{did:?} is not a well-formed did:plc identifier ({ident:?})");
        }
        return Ok(format!("{}/{did}", plc_directory.trim_end_matches('/')));
    }
    if let Some(host) = did.strip_prefix("did:web:") {
        if !is_bare_did_web_host(host) {
            bail!(
                "atproto did:web must be a bare, canonical hostname with no path, \
                 port, credentials or escapes, got {host:?}"
            );
        }
        return Ok(format!("https://{host}/.well-known/did.json"));
    }
    bail!("unsupported DID method in {did:?}; only did:plc and did:web are resolvable")
}

/// Validate a DID document against the DID that was requested.
///
/// The `id` check is the one that matters: without it, `plc.directory` — or
/// whoever answers for a `did:web` host — can return a *different account's*
/// document and every downstream decision is made about the wrong account.
pub fn validate_did_document(document: &Value, expected_did: &str) -> Result<()> {
    let id = document
        .get("id")
        .and_then(Value::as_str)
        .context("DID document has no `id`")?;
    if id != expected_did {
        bail!("DID document id {id:?} does not match the requested DID {expected_did:?}");
    }

    // Duplicate service ids make "the first #atproto_pds" depend on array order.
    //
    // Ids are NORMALIZED to absolute form before comparing: `#atproto_pds` and
    // `did:plc:xxx#atproto_pds` are two spellings of the SAME service, so a
    // raw-string dedup sees two distinct ids and lets a document list the
    // service twice with different endpoints.
    if let Some(services) = document.get("service").and_then(Value::as_array) {
        let mut seen = HashSet::new();
        for service in services {
            if let Some(sid) = service.get("id").and_then(Value::as_str) {
                let absolute = if let Some(fragment) = sid.strip_prefix('#') {
                    format!("{expected_did}#{fragment}")
                } else {
                    sid.to_string()
                };
                if !seen.insert(absolute.clone()) {
                    bail!("DID document has duplicate service id {absolute:?}");
                }
            }
        }
    }
    Ok(())
}

/// The PDS endpoint from a DID document.
///
/// Three conditions must all hold, per the reference's
/// `isAtprotoPersonalDataServerService`: the id matches `#atproto_pds` in
/// relative or absolute form, the type is exactly `AtprotoPersonalDataServer`,
/// and `serviceEndpoint` is a **string** that parses as a URL.
pub fn pds_endpoint(document: &Value, did: &str) -> Result<String> {
    let services = document
        .get("service")
        .and_then(Value::as_array)
        .context("DID document has no `service` array")?;
    let absolute = format!("{did}#atproto_pds");

    for service in services {
        let id = service
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        // EXACTLY the relative or THIS DID's absolute spelling. An `ends_with`
        // test would let a document list a decoy service -- `urn:evil#atproto_pds`,
        // or another DID's `#atproto_pds` -- ahead of the real one and win,
        // choosing the server for the entire session.
        let matches_id = id == "#atproto_pds" || id == absolute;
        let matches_type =
            service.get("type").and_then(Value::as_str) == Some("AtprotoPersonalDataServer");
        if !matches_id || !matches_type {
            continue;
        }
        let endpoint = service
            .get("serviceEndpoint")
            .and_then(Value::as_str)
            .context("#atproto_pds serviceEndpoint is not a string")?;
        let parsed = url::Url::parse(endpoint)
            .with_context(|| format!("#atproto_pds serviceEndpoint {endpoint:?} is not a URL"))?;
        if parsed.scheme() != "https" {
            // The `http`-on-loopback carve-out that used to live here was
            // unreachable: every fetch against this endpoint goes through the
            // SSRF guard, which rejects all loopback addresses unconditionally
            // with no dev flag. It could never serve the local-dev case it
            // named, and only widened what a hostile DID document could get
            // past this function.
            bail!("#atproto_pds serviceEndpoint must be https, got {endpoint:?}");
        }
        // Reject userinfo for the same reason `did:web` hosts reject `@`: the
        // plausible-looking part becomes credentials and the REAL host is
        // whatever follows. Every security decision downstream re-derives the
        // host (`origin_of` and `htu` both strip userinfo), so this is not a
        // trust bypass — but `aud` is what appears in logs and what reqwest
        // would turn into a `Basic` credential on every XRPC call.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            bail!("#atproto_pds serviceEndpoint must not carry credentials, got {endpoint:?}");
        }
        return Ok(endpoint.to_string());
    }
    bail!("DID document declares no #atproto_pds service for {did}")
}

/// The handle a DID document claims, normalized.
///
/// **The first `at://` entry only.** That entry is the document's claim; later
/// entries are not. A membership test over the whole array would let an
/// attacker's document list a victim's handle as a secondary entry and pass
/// verification for it.
pub fn declared_handle(document: &Value) -> Option<String> {
    document
        .get("alsoKnownAs")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find_map(|entry| entry.strip_prefix(AT_URI_PREFIX))
        .and_then(|handle| normalize_handle(handle).ok())
}

/// Bidirectional verification: does this DID document claim `handle`?
///
/// Mandatory when a login starts from a handle. A handle is a DNS name under
/// someone else's control, so without the back-check whoever controls
/// `victim.example` can point it at any DID at all.
pub fn verify_handle_claim(document: &Value, handle: &str) -> Result<()> {
    let wanted = normalize_handle(handle)?;
    let claimed = declared_handle(document)
        .context("DID document claims no handle; cannot verify bidirectionally")?;
    if claimed != wanted {
        bail!("DID document claims handle {claimed:?}, not {wanted:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

    // ── handle normalization ─────────────────────────────────────────────────

    #[test]
    fn handles_are_lowercased() {
        assert_eq!(
            normalize_handle("Alice.BSky.Social").unwrap(),
            "alice.bsky.social"
        );
        assert_eq!(
            normalize_handle("  bob.example.com  ").unwrap(),
            "bob.example.com"
        );
    }

    /// **SSRF-adjacent.** `.local` / `.internal` handles are an attempt to steer
    /// resolution at the internal network dressed up as a login. The spec
    /// disallows these TLDs outright.
    #[test]
    fn reserved_tlds_are_rejected() {
        for handle in [
            "alice.local",
            "alice.localhost",
            "alice.internal",
            "alice.arpa",
            "alice.invalid",
            "alice.example",
            "alice.alt",
            "alice.onion",
            "deep.sub.local",
        ] {
            assert!(normalize_handle(handle).is_err(), "accepted {handle}");
        }
    }

    #[test]
    fn malformed_handles_are_rejected() {
        for handle in [
            "",
            "alice",      // no TLD
            "alice.",     // trailing dot
            ".alice.com", // empty first label
            "alice..com", // empty middle label
            "-alice.com", // label starts with hyphen
            "alice-.com", // label ends with hyphen
            "alice.com-",
            "alice_bob.com", // underscore not allowed
            "alice.123",     // all-numeric TLD
            // Spec: "The last segment (the 'top level domain') can not start
            // with a numeric digit." Rejecting only ALL-numeric TLDs let these
            // three through.
            "alice.1com",
            "alice.4chan",
            "alice.0x",
            "al ice.com",
            "alice.com/path",
            "alice.com:443",
            "https://alice.com",
        ] {
            assert!(normalize_handle(handle).is_err(), "accepted {handle:?}");
        }
    }

    #[test]
    fn ordinary_handles_are_accepted() {
        for handle in [
            "alice.bsky.social",
            "a.co",
            "xn--80akhbyknj4f.com",
            "very-long-label-with-hyphens.example.org",
        ] {
            assert!(normalize_handle(handle).is_ok(), "rejected {handle}");
        }
    }

    // ── DNS TXT resolution ───────────────────────────────────────────────────

    /// **A DNS TXT record is a sequence of character-strings**, each capped at
    /// 255 bytes, and the record's value is their CONCATENATION. A DID that
    /// crosses that boundary arrives as two chunks; treating them as separate
    /// records yields two truncated fragments, neither a valid DID, and the
    /// handle fails to resolve for no visible reason.
    ///
    /// `dig +short` hides this by joining for you, which is exactly why the
    /// spike did not catch it.
    #[test]
    fn txt_chunks_are_joined_into_one_record_value() {
        let long = format!("did={DID}");
        let (head, tail) = long.split_at(20);
        assert_eq!(
            join_txt_chunks(&[head.as_bytes(), tail.as_bytes()]),
            long,
            "chunks were not concatenated"
        );
        assert_eq!(join_txt_chunks(&[long.as_bytes()]), long);
        assert_eq!(join_txt_chunks(&[]), "");
    }

    /// Joined chunks must then resolve exactly as a single-chunk record would.
    #[test]
    fn a_did_split_across_txt_chunks_still_resolves() {
        let long = format!("did={DID}");
        let (head, tail) = long.split_at(20);
        let joined = join_txt_chunks(&[head.as_bytes(), tail.as_bytes()]);
        assert_eq!(
            did_from_txt_records(&[joined]).unwrap().as_deref(),
            Some(DID)
        );
    }

    #[test]
    fn a_single_did_record_resolves() {
        let records = vec![format!("did={DID}")];
        assert_eq!(
            did_from_txt_records(&records).unwrap().as_deref(),
            Some(DID)
        );
    }

    #[test]
    fn unrelated_txt_records_are_ignored() {
        let records = vec![
            "v=spf1 -all".to_string(),
            format!("did={DID}"),
            "google-site-verification=abc".to_string(),
        ];
        assert_eq!(
            did_from_txt_records(&records).unwrap().as_deref(),
            Some(DID)
        );
    }

    /// Spec: *"If multiple valid records with different DIDs are present,
    /// resolution should fail."* Picking the first would let anyone who can add
    /// a TXT record to a zone hijack a handle that already has one.
    #[test]
    fn multiple_did_records_fail_rather_than_picking_one() {
        let records = vec![
            format!("did={DID}"),
            "did=did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ];
        assert!(did_from_txt_records(&records).is_err());
    }

    #[test]
    fn no_did_record_is_absent_not_an_error() {
        let records = vec!["v=spf1 -all".to_string()];
        assert_eq!(did_from_txt_records(&records).unwrap(), None);
    }

    /// The value after `did=` is NOT trimmed — deliberately, to stay consistent
    /// with the spec — so a padded record is invalid rather than silently fixed.
    #[test]
    fn a_padded_did_value_is_invalid() {
        let records = vec![format!("did= {DID}")];
        assert!(did_from_txt_records(&records).is_err());
    }

    #[test]
    fn a_non_did_value_is_rejected() {
        for value in ["did=notadid", "did=", "did=did:unknown:xyz"] {
            assert!(
                did_from_txt_records(&[value.to_string()]).is_err(),
                "accepted {value}"
            );
        }
    }

    // ── .well-known/atproto-did ──────────────────────────────────────────────

    #[test]
    fn the_well_known_body_takes_the_first_line_trimmed() {
        assert_eq!(did_from_well_known(&format!("{DID}\n")).unwrap(), DID);
        assert_eq!(did_from_well_known(&format!("  {DID}  ")).unwrap(), DID);
        assert_eq!(
            did_from_well_known(&format!("{DID}\nignored")).unwrap(),
            DID
        );
    }

    #[test]
    fn a_well_known_body_that_is_not_a_did_is_rejected() {
        for body in ["", "\n", "not a did", "<html>", "did:unknown:x"] {
            assert!(did_from_well_known(body).is_err(), "accepted {body:?}");
        }
    }

    // ── DID → document URL ───────────────────────────────────────────────────

    #[test]
    fn plc_dids_map_to_the_directory() {
        assert_eq!(
            did_document_url(DID, "https://plc.directory").unwrap(),
            format!("https://plc.directory/{DID}")
        );
    }

    #[test]
    fn did_web_maps_to_the_hosts_well_known() {
        assert_eq!(
            did_document_url("did:web:example.com", "https://plc.directory").unwrap(),
            "https://example.com/.well-known/did.json"
        );
    }

    /// atproto restricts `did:web` to a bare hostname: no path components, no
    /// port. (`:` is the path separator in a did:web method-specific id; a port
    /// is spelled `%3A`.)
    #[test]
    fn did_web_with_a_path_or_port_is_rejected() {
        for did in [
            "did:web:example.com:path",
            "did:web:example.com:8080",
            "did:web:example.com%3A8080",
            "did:web:example.com:path:to:doc",
        ] {
            assert!(
                did_document_url(did, "https://plc.directory").is_err(),
                "accepted {did}"
            );
            assert!(!is_atproto_did(did), "is_atproto_did accepted {did}");
        }
    }

    /// **Host confusion.** `did:web:good.com@evil.com` builds
    /// `https://good.com@evil.com/…`, whose ACTUAL host is `evil.com` — the
    /// plausible-looking part is demoted to userinfo. A `/` is a straight path
    /// injection. Neither may survive as far as URL construction.
    #[test]
    fn did_web_host_confusion_and_path_injection_are_rejected() {
        for did in [
            "did:web:good.com@evil.com",
            "did:web:evil.com/x",
            "did:web:evil.com/.well-known/did.json#",
            "did:web:%00",
            "did:web:%2e%2e",
            "did:web:ex ample.com",
            "did:web:",
            "did:web:.",
            "did:web:-example.com",
            "did:web:Example.com", // must be canonical lowercase
        ] {
            assert!(!is_atproto_did(did), "is_atproto_did accepted {did:?}");
            assert!(
                did_document_url(did, "https://plc.directory").is_err(),
                "built a URL for {did:?}"
            );
        }
    }

    /// `did:plc` identifiers are base32-SORTABLE: `[a-z2-7]`. `0`, `1`, `8` and
    /// `9` are not in that alphabet.
    #[test]
    fn did_plc_uses_the_base32_sortable_alphabet() {
        assert!(is_atproto_did(DID));
        for did in [
            "did:plc:aaaaaaaaaaaaaaaaaaaaaa01",
            "did:plc:aaaaaaaaaaaaaaaaaaaaaa89",
            "did:plc:AAAAAAAAAAAAAAAAAAAAAAAA",
            "did:plc:tooshort",
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(!is_atproto_did(did), "accepted {did}");
        }
    }

    #[test]
    fn unsupported_did_methods_are_rejected() {
        for did in ["did:key:z6Mk", "did:example:123", "notadid", "", "did:"] {
            assert!(
                did_document_url(did, "https://plc.directory").is_err(),
                "accepted {did}"
            );
        }
    }

    // ── DID document validation ──────────────────────────────────────────────

    fn doc() -> serde_json::Value {
        json!({
            "id": DID,
            "alsoKnownAs": ["at://alice.bsky.social"],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example.com"
            }]
        })
    }

    /// Without this, `plc.directory` — or whoever answers for a `did:web` host —
    /// can hand back a different account's document entirely.
    #[test]
    fn the_document_id_must_match_the_did_requested() {
        let mut d = doc();
        d["id"] = json!("did:plc:someoneelse00000000000");
        assert!(validate_did_document(&d, DID).is_err());
        assert!(validate_did_document(&doc(), DID).is_ok());
    }

    #[test]
    fn a_document_without_an_id_is_rejected() {
        let mut d = doc();
        d.as_object_mut().unwrap().remove("id");
        assert!(validate_did_document(&d, DID).is_err());
    }

    /// With duplicate ids, "the first `#atproto_pds`" depends on array order,
    /// which is not a property anyone should rely on.
    #[test]
    fn duplicate_service_ids_are_rejected() {
        let mut d = doc();
        d["service"] = json!([
            {"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://a.example"},
            {"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://b.example"}
        ]);
        assert!(validate_did_document(&d, DID).is_err());
    }

    // ── PDS endpoint extraction ──────────────────────────────────────────────

    #[test]
    fn the_pds_endpoint_is_extracted() {
        assert_eq!(
            pds_endpoint(&doc(), DID).unwrap(),
            "https://pds.example.com"
        );
    }

    /// The id may be relative (`#atproto_pds`) or absolute
    /// (`did:plc:xxx#atproto_pds`) — but ONLY those two spellings.
    #[test]
    fn an_absolute_service_id_is_accepted() {
        let mut d = doc();
        d["service"][0]["id"] = json!(format!("{DID}#atproto_pds"));
        assert_eq!(pds_endpoint(&d, DID).unwrap(), "https://pds.example.com");
    }

    /// **PDS steering.** Matching on "ends with `#atproto_pds`" lets a DID
    /// document put a DECOY service first whose id merely has that suffix, and
    /// win. The PDS is what discovery runs against and what every later XRPC
    /// call targets, so this chooses the server for the whole session.
    ///
    /// The decoy must be FIRST here — with a single service there is nothing to
    /// beat, which is how the original tests missed this.
    #[test]
    fn a_foreign_service_id_ending_in_atproto_pds_does_not_win() {
        let mut d = doc();
        d["service"] = json!([
            {"id": "urn:evil#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://attacker.example"},
            {"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://real-pds.example"}
        ]);
        assert_eq!(
            pds_endpoint(&d, DID).unwrap(),
            "https://real-pds.example",
            "a decoy service id steered the PDS"
        );

        // And an id belonging to a DIFFERENT DID is not ours either.
        d["service"] = json!([
            {"id": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://attacker.example"},
            {"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://real-pds.example"}
        ]);
        assert_eq!(pds_endpoint(&d, DID).unwrap(), "https://real-pds.example");
    }

    /// The relative and absolute spellings are the SAME service, so listing both
    /// is a duplicate — which the raw-string dedup did not see.
    #[test]
    fn the_relative_and_absolute_spellings_count_as_one_service() {
        let mut d = doc();
        d["service"] = json!([
            {"id": format!("{DID}#atproto_pds"), "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://attacker.example"},
            {"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://real-pds.example"}
        ]);
        assert!(
            validate_did_document(&d, DID).is_err(),
            "two spellings of the same service id were not seen as duplicates"
        );
    }

    /// A DID document is attacker-controlled in the `did:web` case, and tokens
    /// go to this host, so plaintext is refused — **including on loopback**.
    ///
    /// This previously carved out `http` on loopback "for a local dev PDS". That
    /// carve-out was unreachable: every fetch against this endpoint goes through
    /// the SSRF guard, which rejects all loopback addresses unconditionally with
    /// no dev flag and no config bypass. It could never serve the case it named,
    /// and only widened what a hostile document could get past this function.
    #[test]
    fn a_plaintext_http_pds_is_rejected_including_on_loopback() {
        let mut d = doc();
        for endpoint in [
            "http://pds.attacker.example",
            "http://10.0.0.5",
            "http://localhost:2583",
            "http://127.0.0.1:2583",
        ] {
            d["service"][0]["serviceEndpoint"] = json!(endpoint);
            assert!(pds_endpoint(&d, DID).is_err(), "accepted {endpoint}");
        }
    }

    /// **Credentials in a `serviceEndpoint` are refused.**
    ///
    /// `https://good.example@attacker.example` has real host `attacker.example`
    /// — the exact demotion this module already rejects for `did:web` hosts. The
    /// downstream security decisions re-derive the host either way, so this is
    /// not a trust bypass; but this value is `aud`, it is what appears in logs,
    /// and reqwest would turn the userinfo into a `Basic` credential on every
    /// XRPC call to the PDS.
    #[test]
    fn a_pds_endpoint_carrying_credentials_is_refused() {
        let mut d = doc();
        for endpoint in [
            "https://good.example@attacker.example",
            "https://u:p@attacker.example/x",
        ] {
            d["service"][0]["serviceEndpoint"] = json!(endpoint);
            assert!(pds_endpoint(&d, DID).is_err(), "accepted {endpoint}");
        }
    }

    /// `did:web` hosts are held to the SAME policy as handles: no reserved TLD,
    /// no IP literal. The SSRF guard blocks these at fetch time, but this module
    /// states that rejecting here is what makes the guard a second line of
    /// defence rather than the only one.
    #[test]
    fn did_web_hosts_obey_the_reserved_tld_and_ip_policy() {
        for did in [
            "did:web:169.254.169.254", // cloud metadata
            "did:web:127.0.0.1",
            "did:web:10.0.0.5",
            "did:web:pds.internal",
            "did:web:printer.local",
            "did:web:something.localhost",
            "did:web:site.onion",
        ] {
            assert!(!is_atproto_did(did), "accepted {did}");
        }
        // Non-canonical IP spellings resolve to loopback just as well, and
        // `IpAddr::parse` accepts none of them — a numeric final label does.
        for did in ["did:web:127.1", "did:web:0177.0.0.1", "did:web:0x7f.0.0.1"] {
            assert!(!is_atproto_did(did), "accepted {did}");
        }
        // Length bounds: total and per-label, matching `normalize_handle`.
        assert!(!is_atproto_did(&format!("did:web:{}.com", "a".repeat(300))));
        assert!(
            !is_atproto_did(&format!("did:web:{}.com", "a".repeat(64))),
            "a 64-byte label exceeds the DNS limit"
        );
        assert!(is_atproto_did(&format!("did:web:{}.com", "a".repeat(63))));
        // A digit-leading TLD is not a TLD.
        assert!(!is_atproto_did("did:web:foo.1com"));
        // Ordinary hosts still work.
        assert!(is_atproto_did("did:web:pds.example.com"));
    }

    /// All three conditions must hold: id, type, and a parseable endpoint.
    #[test]
    fn a_service_failing_any_condition_is_not_the_pds() {
        let cases = [
            json!({"id": "#atproto_pds", "type": "SomethingElse", "serviceEndpoint": "https://a.example"}),
            json!({"id": "#other", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://a.example"}),
            json!({"id": "urn:evil#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://a.example"}),
            json!({"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "not a url"}),
            json!({"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": ["https://a.example"]}),
            json!({"id": "#atproto_pds", "type": "AtprotoPersonalDataServer"}),
        ];
        for svc in cases {
            let mut d = doc();
            d["service"] = json!([svc.clone()]);
            assert!(pds_endpoint(&d, DID).is_err(), "accepted {svc}");
        }
    }

    #[test]
    fn a_document_with_no_services_has_no_pds() {
        let mut d = doc();
        d["service"] = json!([]);
        assert!(pds_endpoint(&d, DID).is_err());
        d.as_object_mut().unwrap().remove("service");
        assert!(pds_endpoint(&d, DID).is_err());
    }

    // ── bidirectional verification ───────────────────────────────────────────

    #[test]
    fn the_declared_handle_is_the_first_at_uri_entry_normalized() {
        let mut d = doc();
        d["alsoKnownAs"] = json!(["at://Alice.BSky.Social"]);
        assert_eq!(declared_handle(&d).as_deref(), Some("alice.bsky.social"));
    }

    /// **The attack this closes.** An attacker's DID document can list the
    /// victim's handle as a SECONDARY entry. Only the first `at://` entry is the
    /// document's claim, so a membership test would accept the attacker's
    /// document for the victim's handle.
    #[test]
    fn only_the_first_at_uri_entry_counts() {
        // Note: not `.example` — that is a reserved TLD and would be rejected by
        // `normalize_handle` before the ordering logic was ever reached.
        let mut d = doc();
        d["alsoKnownAs"] = json!(["at://attacker.com", "at://victim.com"]);
        assert_eq!(declared_handle(&d).as_deref(), Some("attacker.com"));
        assert!(verify_handle_claim(&d, "victim.com").is_err());
        assert!(verify_handle_claim(&d, "attacker.com").is_ok());
    }

    /// Non-`at://` entries are skipped when looking for the first claim.
    #[test]
    fn non_at_uri_entries_are_skipped() {
        let mut d = doc();
        d["alsoKnownAs"] = json!(["https://alice.example", "at://alice.bsky.social"]);
        assert_eq!(declared_handle(&d).as_deref(), Some("alice.bsky.social"));
    }

    #[test]
    fn a_document_claiming_no_handle_fails_verification() {
        let mut d = doc();
        d["alsoKnownAs"] = json!([]);
        assert!(verify_handle_claim(&d, "alice.bsky.social").is_err());
        d.as_object_mut().unwrap().remove("alsoKnownAs");
        assert!(verify_handle_claim(&d, "alice.bsky.social").is_err());
    }

    /// A malformed claim must not be usable as a wildcard.
    #[test]
    fn a_malformed_claimed_handle_fails_verification() {
        for claim in ["at://", "at://not a handle", "at://alice.local"] {
            let mut d = doc();
            d["alsoKnownAs"] = json!([claim]);
            assert!(
                verify_handle_claim(&d, "alice.bsky.social").is_err(),
                "accepted claim {claim}"
            );
        }
    }

    /// **A malformed FIRST claim must not fall through to the second.**
    ///
    /// The two neighbouring tests could not see this between them: this one's
    /// sibling uses single-element arrays, so "reject" and "skip to the next"
    /// look identical, and `only_the_first_at_uri_entry_counts` uses two VALID
    /// entries, so nothing forces the first to be the one that fails.
    ///
    /// A mutation turning `find_map(strip).and_then(normalize)` into
    /// `filter_map(strip).find_map(normalize)` — skip past an unusable claim —
    /// passed the whole suite. Under it, an attacker document whose first entry
    /// is junk verifies as whatever the SECOND entry says, which is precisely
    /// what "only the first entry counts" exists to stop.
    #[test]
    fn a_malformed_first_claim_does_not_fall_through_to_the_second() {
        for bad_first in ["at://", "at://not a handle", "at://alice.local"] {
            let mut d = doc();
            d["alsoKnownAs"] = json!([bad_first, "at://victim.com"]);
            assert_eq!(
                declared_handle(&d),
                None,
                "a malformed first claim ({bad_first}) was skipped and the second was taken"
            );
            assert!(
                verify_handle_claim(&d, "victim.com").is_err(),
                "({bad_first}) the second entry verified as the account's handle"
            );
        }
    }

    #[test]
    fn verification_is_case_insensitive_on_both_sides() {
        let mut d = doc();
        d["alsoKnownAs"] = json!(["at://Alice.BSky.Social"]);
        assert!(verify_handle_claim(&d, "ALICE.bsky.SOCIAL").is_ok());
    }
}
