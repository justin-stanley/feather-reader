//! Authorization-server discovery, and the validations that make it safe.
//!
//! The chain is: PDS → `/.well-known/oauth-protected-resource` → issuer →
//! `/.well-known/oauth-authorization-server` → endpoints.
//!
//! Every link is attacker-influenced. The PDS comes from a DID document that a
//! `did:web` host or `plc.directory` served; the issuer comes from the PDS. So
//! each document must prove it is talking about itself:
//!
//! * the protected-resource document's `resource` must equal the PDS origin,
//! * it must name exactly ONE authorization server,
//! * the authorization-server document's `issuer` must equal the URL it was
//!   fetched from — the mix-up defence, and the reason these documents must not
//!   be fetched through a redirect,
//! * and if the AS lists `protected_resources`, the PDS must appear in it.
//!
//! The last one closes the loop in the other direction: without it a PDS can
//! unilaterally name an authorization server that has never heard of it.

use anyhow::{bail, Context as _, Result};
use serde_json::Value;

/// The only DPoP signing algorithm this client has.
const ES256: &str = "ES256";

/// The endpoints a validated authorization server offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationServer {
    pub issuer: String,
    pub par_endpoint: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

/// Resolve a PDS to its authorization server, both fetches and both validations.
///
/// Shared by the login path and the refresh path so the two cannot disagree
/// about which server they are talking to. The order is not arbitrary: the
/// protected-resource document names the issuer, and the issuer's own metadata
/// is then required to agree — an authorization server that claims a different
/// issuer than the one that pointed at it is the mix-up attack RFC 9207 exists
/// for.
pub async fn discover(
    http: &reqwest::Client,
    pds_url: &str,
    auth_method: &str,
) -> Result<AuthorizationServer> {
    let prm_url = format!(
        "{}/.well-known/oauth-protected-resource",
        origin_of(pds_url)?
    );
    let prm = super::fetch::get_json(http, &prm_url, super::fetch::JSON)
        .await
        .with_context(|| format!("fetching {prm_url}"))?;
    let issuer = validate_protected_resource(&prm, pds_url)?;

    let asm_url = format!("{issuer}/.well-known/oauth-authorization-server");
    let asm = super::fetch::get_json(http, &asm_url, super::fetch::JSON)
        .await
        .with_context(|| format!("fetching {asm_url}"))?;
    validate_authorization_server(&asm, &issuer, pds_url, auth_method)
}

/// The origin of a URL: scheme + host + non-default port, and nothing else.
///
/// Built from the parsed components rather than sliced out of the input, so
/// userinfo cannot survive into it — `https://u:p@host/x` has origin
/// `https://host`, and a slice would have kept the credentials. Both sides of
/// the RFC 9728 `resource` comparison are attacker-influenced, so this needs to
/// be an origin in fact and not just in name.
pub fn origin_of(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url).with_context(|| format!("{url:?} is not a URL"))?;
    let host = parsed
        .host_str()
        .with_context(|| format!("{url:?} has no host"))?;
    Ok(match parsed.port() {
        // `Url::port` is None for the scheme's default, so 443 drops out here.
        Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
        None => format!("{}://{host}", parsed.scheme()),
    })
}

/// An issuer identifier must be canonical before it can be compared.
///
/// The mix-up defence rests on `metadata.issuer == the URL we fetched from`
/// being an exact string comparison. If either side could carry a path, a
/// trailing slash or userinfo, that comparison would be ambiguous — and an
/// ambiguous security check is one that eventually passes when it should not.
pub fn validate_issuer_form(issuer: &str) -> Result<()> {
    let parsed = url::Url::parse(issuer)
        .with_context(|| format!("issuer {issuer:?} is not an absolute URL"))?;
    if parsed.scheme() != "https" {
        bail!("issuer {issuer:?} must be https");
    }
    if !parsed.has_host() {
        bail!("issuer {issuer:?} has no host");
    }
    if parsed.path() != "" && parsed.path() != "/" {
        bail!("issuer {issuer:?} must have no path");
    }
    if issuer.ends_with('/') {
        bail!("issuer {issuer:?} must not have a trailing slash");
    }
    if parsed.query().is_some() {
        bail!("issuer {issuer:?} must have no query string");
    }
    if parsed.fragment().is_some() {
        bail!("issuer {issuer:?} must have no fragment");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("issuer {issuer:?} must not carry credentials");
    }
    // The catch-all, and the one that actually makes the comparison sound: the
    // issuer must be spelled EXACTLY as its own origin. That covers a default
    // port (the spec forbids `:443`), host casing, and percent-escapes in one
    // check, rather than enumerating normalizations and missing some.
    let canonical = origin_of(issuer)?;
    if issuer != canonical {
        bail!("issuer {issuer:?} is not in canonical form (expected {canonical:?})");
    }
    Ok(())
}

/// Validate `/.well-known/oauth-protected-resource` and return its issuer.
///
/// Two checks, both required:
///
/// * `resource` must equal the PDS **origin** (RFC 9728 §3.3). Without it, a
///   document served by one host can claim to describe another.
/// * `authorization_servers` must hold **exactly one** entry. atproto requires
///   one and only one; taking `[0]` would silently accept a hostile document
///   advertising several and pick whichever the PDS listed first, turning a
///   document that should fail closed into attacker-chosen AS selection.
pub fn validate_protected_resource(metadata: &Value, pds_url: &str) -> Result<String> {
    let expected = origin_of(pds_url)?;
    let resource = metadata
        .get("resource")
        .and_then(Value::as_str)
        .context("protected-resource metadata has no `resource`")?;
    if resource != expected {
        bail!(
            "protected-resource `resource` is {resource:?}, expected the PDS origin {expected:?}"
        );
    }

    let servers = metadata
        .get("authorization_servers")
        .and_then(Value::as_array)
        .context("protected-resource metadata has no `authorization_servers`")?;
    if servers.len() != 1 {
        bail!(
            "atproto requires exactly one authorization server, found {}",
            servers.len()
        );
    }
    let issuer = servers[0]
        .as_str()
        .context("`authorization_servers` entry is not a string")?;
    validate_issuer_form(issuer)?;
    Ok(issuer.to_string())
}

/// Require an array-valued metadata field to contain `wanted`.
fn require_listed(metadata: &Value, field: &str, wanted: &str) -> Result<()> {
    let values = metadata
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("authorization-server metadata has no `{field}`"))?;
    if !values.iter().filter_map(Value::as_str).any(|v| v == wanted) {
        bail!("authorization-server `{field}` does not include {wanted:?}");
    }
    Ok(())
}

/// Require an array-valued metadata field NOT to contain `forbidden`.
fn require_absent(metadata: &Value, field: &str, forbidden: &str) -> Result<()> {
    if let Some(values) = metadata.get(field).and_then(Value::as_array) {
        if values
            .iter()
            .filter_map(Value::as_str)
            .any(|v| v == forbidden)
        {
            bail!("authorization-server `{field}` includes {forbidden:?}, which is not allowed");
        }
    }
    Ok(())
}

/// Read a required endpoint, requiring an absolute https URL.
fn require_endpoint(metadata: &Value, field: &str) -> Result<String> {
    let raw = metadata
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("authorization-server metadata has no `{field}`"))?;
    let parsed = url::Url::parse(raw)
        .with_context(|| format!("`{field}` {raw:?} is not an absolute URL"))?;
    if parsed.scheme() != "https" {
        bail!("`{field}` must be https, got {raw:?}");
    }
    Ok(raw.to_string())
}

/// Validate `/.well-known/oauth-authorization-server` and return its endpoints.
///
/// `issuer` is the URL the document was fetched from; `pds_url` the PDS that
/// named it; `auth_method` the client-authentication method we intend to use
/// (`none` for the localhost dev client, `private_key_jwt` in production).
pub fn validate_authorization_server(
    metadata: &Value,
    issuer: &str,
    pds_url: &str,
    auth_method: &str,
) -> Result<AuthorizationServer> {
    // The mix-up defence. RFC 8414 §3.3: the document must claim the identity it
    // was served under, or a hostile PDS can name an authorization server whose
    // metadata declares somebody else's issuer.
    let declared = metadata
        .get("issuer")
        .and_then(Value::as_str)
        .context("authorization-server metadata has no `issuer`")?;
    if declared != issuer {
        bail!("authorization-server declares issuer {declared:?} but was fetched from {issuer:?}");
    }

    // And the other direction: a PDS cannot unilaterally name an authorization
    // server that has never heard of it. Only checked when the AS declares the
    // list — absent means "not stated", not "not protected".
    if let Some(resources) = metadata
        .get("protected_resources")
        .and_then(Value::as_array)
    {
        let pds_origin = origin_of(pds_url)?;
        if !resources
            .iter()
            .filter_map(Value::as_str)
            .any(|r| r == pds_origin)
        {
            bail!("PDS {pds_origin:?} is not listed in the authorization server's protected_resources");
        }
    }

    // Capability preflight: fail here, with a legible reason, rather than
    // several requests later with a protocol error.
    if metadata
        .get("client_id_metadata_document_supported")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("authorization server does not support client-id metadata documents");
    }
    // atproto mandates PAR, and mandates that the AS advertises it.
    if metadata
        .get("require_pushed_authorization_requests")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("authorization server does not require pushed authorization requests");
    }
    // Mandated `true` by atproto, and load-bearing downstream: the callback
    // treats a MISSING `iss` as a rejection (RFC 9207), which is only sound
    // because a conformant server always sends one. Checking it here turns a
    // post-approval failure into a preflight one.
    if metadata
        .get("authorization_response_iss_parameter_supported")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("authorization server does not send the `iss` response parameter");
    }

    require_listed(metadata, "code_challenge_methods_supported", "S256")?;
    // `plain` is not merely "not required" -- the spec says it "is not allowed".
    require_absent(metadata, "code_challenge_methods_supported", "plain")?;
    require_listed(metadata, "dpop_signing_alg_values_supported", ES256)?;
    require_listed(metadata, "response_types_supported", "code")?;
    require_listed(metadata, "grant_types_supported", "authorization_code")?;
    require_listed(metadata, "grant_types_supported", "refresh_token")?;
    require_listed(
        metadata,
        "token_endpoint_auth_methods_supported",
        auth_method,
    )?;
    require_listed(metadata, "scopes_supported", "atproto")?;

    // An ABSENT signing-alg list means ES256, not "unknown". The spec says
    // clients and servers "currently must support the ES256 cryptographic
    // system", so bailing here would reject conformant servers.
    if metadata
        .get("token_endpoint_auth_signing_alg_values_supported")
        .is_some()
    {
        require_listed(
            metadata,
            "token_endpoint_auth_signing_alg_values_supported",
            ES256,
        )?;
        // The spec forbids `none` here outright.
        require_absent(
            metadata,
            "token_endpoint_auth_signing_alg_values_supported",
            "none",
        )?;
    }

    Ok(AuthorizationServer {
        issuer: issuer.to_string(),
        par_endpoint: require_endpoint(metadata, "pushed_authorization_request_endpoint")?,
        authorization_endpoint: require_endpoint(metadata, "authorization_endpoint")?,
        token_endpoint: require_endpoint(metadata, "token_endpoint")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PDS: &str = "https://pds.example.com";
    const ISS: &str = "https://auth.example.com";

    fn protected_resource() -> serde_json::Value {
        json!({ "resource": PDS, "authorization_servers": [ISS] })
    }

    fn as_metadata() -> serde_json::Value {
        json!({
            "issuer": ISS,
            "pushed_authorization_request_endpoint": format!("{ISS}/par"),
            "authorization_endpoint": format!("{ISS}/authorize"),
            "token_endpoint": format!("{ISS}/token"),
            "client_id_metadata_document_supported": true,
            "require_pushed_authorization_requests": true,
            "code_challenge_methods_supported": ["S256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "scopes_supported": ["atproto", "transition:generic"],
            "authorization_response_iss_parameter_supported": true
        })
    }

    // ── issuer form ──────────────────────────────────────────────────────────

    #[test]
    fn a_well_formed_issuer_is_accepted() {
        assert!(validate_issuer_form("https://auth.example.com").is_ok());
        assert!(validate_issuer_form("https://auth.example.com:8443").is_ok());
    }

    /// A non-canonical issuer would make the `issuer == fetched-from` comparison
    /// ambiguous, which is the comparison the mix-up defence rests on.
    #[test]
    fn a_non_canonical_issuer_is_rejected() {
        for issuer in [
            "http://auth.example.com",       // not https
            "https://auth.example.com/",     // trailing slash
            "https://auth.example.com/path", // path
            "https://auth.example.com?a=1",  // query
            "https://auth.example.com#f",    // fragment
            "https://u:p@auth.example.com",  // userinfo
            "auth.example.com",              // not absolute
            "",
            // Spec: "a default port (443 for HTTPS) must not be included".
            "https://auth.example.com:443",
            // Case and percent-escapes get normalized by any URL parser, so an
            // un-normalized spelling would compare unequal to itself.
            "https://AUTH.example.com",
            "https://auth%2eexample.com",
        ] {
            assert!(validate_issuer_form(issuer).is_err(), "accepted {issuer:?}");
        }
    }

    /// An origin is scheme + host + port. Userinfo is not part of it, and
    /// leaving it in would make the RFC 9728 `resource` comparison compare
    /// something that is not an origin.
    #[test]
    fn origin_of_drops_userinfo_path_query_and_default_ports() {
        assert_eq!(origin_of("https://u:p@pds.example.com/x").unwrap(), PDS);
        assert_eq!(origin_of("https://pds.example.com/a/b?c=1#d").unwrap(), PDS);
        assert_eq!(origin_of("https://pds.example.com:443").unwrap(), PDS);
        assert_eq!(
            origin_of("https://pds.example.com:8443").unwrap(),
            "https://pds.example.com:8443"
        );
    }

    // ── protected-resource metadata ──────────────────────────────────────────

    #[test]
    fn a_valid_protected_resource_document_yields_its_issuer() {
        assert_eq!(
            validate_protected_resource(&protected_resource(), PDS).unwrap(),
            ISS
        );
    }

    /// RFC 9728 §3.3. Without it, a document served by one host can claim to
    /// describe another.
    #[test]
    fn the_resource_must_equal_the_pds_origin() {
        let mut doc = protected_resource();
        doc["resource"] = json!("https://other.example.com");
        assert!(validate_protected_resource(&doc, PDS).is_err());
    }

    /// The comparison is against the ORIGIN, so a path on the PDS URL is
    /// discarded rather than causing a spurious mismatch.
    #[test]
    fn the_resource_comparison_uses_the_origin_of_the_pds_url() {
        assert!(
            validate_protected_resource(&protected_resource(), "https://pds.example.com/xrpc")
                .is_ok()
        );
        assert!(
            validate_protected_resource(&protected_resource(), "https://pds.example.com/").is_ok()
        );
    }

    /// **atproto requires exactly one.** Taking `[0]` would silently accept a
    /// malformed or hostile document advertising several and pick whichever the
    /// PDS listed first — turning a document that should fail closed into
    /// attacker-chosen AS selection.
    #[test]
    fn exactly_one_authorization_server_is_required() {
        let mut doc = protected_resource();
        doc["authorization_servers"] = json!([ISS, "https://evil.example.com"]);
        assert!(validate_protected_resource(&doc, PDS).is_err());

        doc["authorization_servers"] = json!([]);
        assert!(validate_protected_resource(&doc, PDS).is_err());

        doc.as_object_mut().unwrap().remove("authorization_servers");
        assert!(validate_protected_resource(&doc, PDS).is_err());
    }

    #[test]
    fn the_named_issuer_must_itself_be_well_formed() {
        let mut doc = protected_resource();
        doc["authorization_servers"] = json!(["https://auth.example.com/path"]);
        assert!(validate_protected_resource(&doc, PDS).is_err());
    }

    // ── authorization-server metadata ────────────────────────────────────────

    #[test]
    fn a_valid_as_document_yields_its_endpoints() {
        let server =
            validate_authorization_server(&as_metadata(), ISS, PDS, "private_key_jwt").unwrap();
        assert_eq!(server.issuer, ISS);
        assert_eq!(server.par_endpoint, format!("{ISS}/par"));
        assert_eq!(server.authorization_endpoint, format!("{ISS}/authorize"));
        assert_eq!(server.token_endpoint, format!("{ISS}/token"));
    }

    /// **The mix-up defence.** RFC 8414 §3.3; the reference comments this
    /// "Validate the issuer (MIX-UP attacks)". A hostile PDS names an AS whose
    /// metadata declares someone else's issuer; without this check we would hold
    /// a token set labelled with an issuer that never minted it.
    #[test]
    fn the_documents_issuer_must_equal_the_url_it_came_from() {
        let mut doc = as_metadata();
        doc["issuer"] = json!("https://someone-else.example.com");
        assert!(validate_authorization_server(&doc, ISS, PDS, "private_key_jwt").is_err());
    }

    /// Closes the loop the other way: a PDS cannot unilaterally name an AS that
    /// has never heard of it.
    #[test]
    fn a_declared_protected_resources_list_must_contain_the_pds() {
        let mut doc = as_metadata();
        doc["protected_resources"] = json!(["https://other.example.com"]);
        assert!(validate_authorization_server(&doc, ISS, PDS, "private_key_jwt").is_err());

        doc["protected_resources"] = json!([PDS]);
        assert!(validate_authorization_server(&doc, ISS, PDS, "private_key_jwt").is_ok());
    }

    /// Absent is fine — the check only applies when the AS declares the list.
    #[test]
    fn an_absent_protected_resources_list_is_not_an_error() {
        let doc = as_metadata();
        assert!(doc.get("protected_resources").is_none());
        assert!(validate_authorization_server(&doc, ISS, PDS, "private_key_jwt").is_ok());
    }

    // ── capability preflight ─────────────────────────────────────────────────

    #[test]
    fn required_capabilities_are_enforced() {
        let cases: &[(&str, serde_json::Value)] = &[
            ("client_id_metadata_document_supported", json!(false)),
            ("code_challenge_methods_supported", json!(["plain"])),
            ("dpop_signing_alg_values_supported", json!(["ES384"])),
            ("response_types_supported", json!(["token"])),
            ("grant_types_supported", json!(["authorization_code"])),
            (
                "token_endpoint_auth_methods_supported",
                json!(["client_secret_basic"]),
            ),
            (
                "token_endpoint_auth_signing_alg_values_supported",
                json!(["RS256"]),
            ),
            // --- the four the fixture carried but nothing asserted ---
            ("scopes_supported", json!(["transition:generic"])),
            ("require_pushed_authorization_requests", json!(false)),
            (
                "authorization_response_iss_parameter_supported",
                json!(false),
            ),
            // `plain` is forbidden outright, not merely "S256 must also be there".
            ("code_challenge_methods_supported", json!(["S256", "plain"])),
            // The spec forbids `none` in the signing-alg list.
            (
                "token_endpoint_auth_signing_alg_values_supported",
                json!(["ES256", "none"]),
            ),
        ];
        for (field, bad) in cases {
            let mut doc = as_metadata();
            doc[*field] = bad.clone();
            assert!(
                validate_authorization_server(&doc, ISS, PDS, "private_key_jwt").is_err(),
                "accepted {field} = {bad}"
            );
        }
    }

    /// **Every field the fixture carries must be load-bearing.** Four spec-`must`
    /// checks were missing precisely because the fixture supplied them and no
    /// test ever varied them -- the fixture manufactured the appearance of
    /// coverage. Removing any field must now break something, so a check that
    /// silently disappears shows up here.
    #[test]
    fn every_field_in_the_fixture_is_load_bearing() {
        // The single deliberate exception: an absent signing-alg list means
        // ES256 rather than "unknown", so removing it MUST still validate. It is
        // named here rather than skipped silently, so the exemption is a
        // decision on the record instead of a gap.
        const OPTIONAL: &str = "token_endpoint_auth_signing_alg_values_supported";

        let base = as_metadata();
        for field in base.as_object().unwrap().keys() {
            let mut doc = base.clone();
            doc.as_object_mut().unwrap().remove(field);
            let result = validate_authorization_server(&doc, ISS, PDS, "private_key_jwt");
            if field == OPTIONAL {
                assert!(result.is_ok(), "`{field}` is documented as optional");
            } else {
                assert!(
                    result.is_err(),
                    "removing `{field}` changed nothing -- it is unchecked, or it \
                     does not belong in the fixture"
                );
            }
        }
    }

    #[test]
    fn a_missing_required_endpoint_is_rejected() {
        for field in [
            "pushed_authorization_request_endpoint",
            "authorization_endpoint",
            "token_endpoint",
        ] {
            let mut doc = as_metadata();
            doc.as_object_mut().unwrap().remove(field);
            assert!(
                validate_authorization_server(&doc, ISS, PDS, "private_key_jwt").is_err(),
                "accepted a document with no {field}"
            );
        }
    }

    /// Spec: clients and servers "currently must support the ES256
    /// cryptographic system", so an absent list means ES256 rather than
    /// "unknown" — bailing here would reject conformant servers.
    #[test]
    fn an_absent_signing_alg_list_defaults_to_es256_rather_than_failing() {
        let mut doc = as_metadata();
        doc.as_object_mut()
            .unwrap()
            .remove("token_endpoint_auth_signing_alg_values_supported");
        assert!(validate_authorization_server(&doc, ISS, PDS, "private_key_jwt").is_ok());
    }

    /// The negotiated method must be checked against what the AS accepts —
    /// the dev client authenticates with `none`, production with
    /// `private_key_jwt`, and an AS supporting only one of them must fail
    /// loudly rather than at PAR.
    #[test]
    fn the_negotiated_auth_method_must_be_supported() {
        let mut doc = as_metadata();
        doc["token_endpoint_auth_methods_supported"] = json!(["private_key_jwt"]);
        assert!(validate_authorization_server(&doc, ISS, PDS, "none").is_err());
        assert!(validate_authorization_server(&doc, ISS, PDS, "private_key_jwt").is_ok());

        doc["token_endpoint_auth_methods_supported"] = json!(["none"]);
        assert!(validate_authorization_server(&doc, ISS, PDS, "none").is_ok());
        assert!(validate_authorization_server(&doc, ISS, PDS, "private_key_jwt").is_err());
    }

    /// Endpoints must be absolute https URLs — a relative or http endpoint
    /// would be a redirect target we hand the browser, or a credential-bearing
    /// POST in the clear.
    #[test]
    fn endpoints_must_be_absolute_https_urls() {
        for field in [
            "pushed_authorization_request_endpoint",
            "authorization_endpoint",
            "token_endpoint",
        ] {
            for bad in ["/par", "http://auth.example.com/par", "not a url"] {
                let mut doc = as_metadata();
                doc[field] = json!(bad);
                assert!(
                    validate_authorization_server(&doc, ISS, PDS, "private_key_jwt").is_err(),
                    "accepted {field} = {bad}"
                );
            }
        }
    }
    /// **Against a REAL PDS.** These are the documents `pds.justin-stanley.com`
    /// actually served on 2026-09-12, captured verbatim.
    ///
    /// The preflight in this module is deliberately strict, and the failure mode
    /// of strictness is rejecting a conformant server — which unit tests built
    /// from a hand-written fixture cannot detect, because the fixture is written
    /// to pass. This one was written by somebody else's implementation.
    ///
    /// It also carries fields this module does not look at
    /// (`request_object_signing_alg_values_supported`, `ui_locales_supported`,
    /// and others), confirming that unknown members are ignored rather than
    /// tripping anything.
    #[test]
    fn a_real_pds_passes_the_preflight() {
        const REAL_PROTECTED_RESOURCE: &str = r#"{"resource":"https://pds.justin-stanley.com","authorization_servers":["https://pds.justin-stanley.com"],"scopes_supported":[],"bearer_methods_supported":["header"],"resource_documentation":"https://atproto.com"}"#;
        const REAL_AUTHORIZATION_SERVER: &str = r#"{"issuer":"https://pds.justin-stanley.com","request_parameter_supported":true,"request_uri_parameter_supported":true,"require_request_uri_registration":true,"scopes_supported":["atproto","transition:email","transition:generic","transition:chat.bsky"],"subject_types_supported":["public"],"response_types_supported":["code"],"response_modes_supported":["query","fragment","form_post"],"grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],"ui_locales_supported":["en-US"],"display_values_supported":["page","popup","touch"],"request_object_signing_alg_values_supported":["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512","none"],"authorization_response_iss_parameter_supported":true,"request_object_encryption_alg_values_supported":[],"request_object_encryption_enc_values_supported":[],"jwks_uri":"https://pds.justin-stanley.com/oauth/jwks","authorization_endpoint":"https://pds.justin-stanley.com/oauth/authorize","token_endpoint":"https://pds.justin-stanley.com/oauth/token","token_endpoint_auth_methods_supported":["none","private_key_jwt"],"token_endpoint_auth_signing_alg_values_supported":["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512"],"revocation_endpoint":"https://pds.justin-stanley.com/oauth/revoke","pushed_authorization_request_endpoint":"https://pds.justin-stanley.com/oauth/par","require_pushed_authorization_requests":true,"dpop_signing_alg_values_supported":["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512"],"protected_resources":["https://pds.justin-stanley.com"],"client_id_metadata_document_supported":true,"prompt_values_supported":["none","login","consent","select_account","create"]}"#;
        let pds = "https://pds.justin-stanley.com";

        let prm: Value = serde_json::from_str(REAL_PROTECTED_RESOURCE).unwrap();
        let issuer = validate_protected_resource(&prm, pds).unwrap();
        assert_eq!(issuer, pds);

        let asm: Value = serde_json::from_str(REAL_AUTHORIZATION_SERVER).unwrap();
        // Both client shapes must be accepted: the localhost dev client
        // authenticates with `none`, production with `private_key_jwt`.
        for method in ["none", "private_key_jwt"] {
            let server = validate_authorization_server(&asm, &issuer, pds, method)
                .unwrap_or_else(|e| panic!("a real PDS was rejected for {method}: {e:#}"));
            assert_eq!(
                server.par_endpoint,
                "https://pds.justin-stanley.com/oauth/par"
            );
            assert_eq!(
                server.authorization_endpoint,
                "https://pds.justin-stanley.com/oauth/authorize"
            );
            assert_eq!(
                server.token_endpoint,
                "https://pds.justin-stanley.com/oauth/token"
            );
        }
    }
}
