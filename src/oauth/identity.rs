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
    let tld = labels[labels.len() - 1];
    if tld.bytes().all(|b| b.is_ascii_digit()) {
        bail!("handle {input:?} has an all-numeric TLD");
    }
    if RESERVED_TLDS.contains(&tld) {
        bail!("handle {input:?} uses the reserved TLD .{tld}");
    }
    Ok(handle)
}

/// Whether `did` is a DID this client can resolve: `did:plc:` or `did:web:`.
pub fn is_atproto_did(did: &str) -> bool {
    if let Some(ident) = did.strip_prefix("did:plc:") {
        // PLC identifiers are 24 characters of base32-sortable.
        return ident.len() == 24
            && ident
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    }
    if let Some(rest) = did.strip_prefix("did:web:") {
        return !rest.is_empty();
    }
    false
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
    let candidates: Vec<&str> = records
        .iter()
        .filter_map(|r| r.strip_prefix("did="))
        .collect();

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
        if host.is_empty() {
            bail!("did:web with no host");
        }
        if host.contains(':') {
            bail!("atproto did:web must be a bare hostname with no path or port, got {host:?}");
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
    if let Some(services) = document.get("service").and_then(Value::as_array) {
        let mut seen = HashSet::new();
        for service in services {
            if let Some(sid) = service.get("id").and_then(Value::as_str) {
                if !seen.insert(sid) {
                    bail!("DID document has duplicate service id {sid:?}");
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
pub fn pds_endpoint(document: &Value) -> Result<String> {
    let services = document
        .get("service")
        .and_then(Value::as_array)
        .context("DID document has no `service` array")?;

    for service in services {
        let id = service
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let matches_id = id == "#atproto_pds" || id.ends_with("#atproto_pds");
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
        if !matches!(parsed.scheme(), "http" | "https") {
            bail!("#atproto_pds serviceEndpoint must be http(s), got {endpoint:?}");
        }
        return Ok(endpoint.to_string());
    }
    bail!("DID document declares no #atproto_pds service")
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

    /// atproto restricts `did:web` to a bare hostname: no path components, and
    /// no port except on localhost.
    #[test]
    fn did_web_with_a_path_or_port_is_rejected() {
        for did in [
            "did:web:example.com:path",
            "did:web:example.com:8080",
            "did:web:example.com:path:to:doc",
        ] {
            assert!(
                did_document_url(did, "https://plc.directory").is_err(),
                "accepted {did}"
            );
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
        assert_eq!(pds_endpoint(&doc()).unwrap(), "https://pds.example.com");
    }

    /// The id may be relative (`#atproto_pds`) or absolute
    /// (`did:plc:xxx#atproto_pds`).
    #[test]
    fn an_absolute_service_id_is_accepted() {
        let mut d = doc();
        d["service"][0]["id"] = json!(format!("{DID}#atproto_pds"));
        assert_eq!(pds_endpoint(&d).unwrap(), "https://pds.example.com");
    }

    /// All three conditions must hold: id, type, and a parseable endpoint.
    #[test]
    fn a_service_failing_any_condition_is_not_the_pds() {
        let cases = [
            json!({"id": "#atproto_pds", "type": "SomethingElse", "serviceEndpoint": "https://a.example"}),
            json!({"id": "#other", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://a.example"}),
            json!({"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "not a url"}),
            json!({"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": ["https://a.example"]}),
            json!({"id": "#atproto_pds", "type": "AtprotoPersonalDataServer"}),
        ];
        for svc in cases {
            let mut d = doc();
            d["service"] = json!([svc.clone()]);
            assert!(pds_endpoint(&d).is_err(), "accepted {svc}");
        }
    }

    #[test]
    fn a_document_with_no_services_has_no_pds() {
        let mut d = doc();
        d["service"] = json!([]);
        assert!(pds_endpoint(&d).is_err());
        d.as_object_mut().unwrap().remove("service");
        assert!(pds_endpoint(&d).is_err());
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

    #[test]
    fn verification_is_case_insensitive_on_both_sides() {
        let mut d = doc();
        d["alsoKnownAs"] = json!(["at://Alice.BSky.Social"]);
        assert!(verify_handle_claim(&d, "ALICE.bsky.SOCIAL").is_ok());
    }
}
