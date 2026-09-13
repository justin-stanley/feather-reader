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
    /// RFC 7009 revocation. **Optional** — RFC 8414 does not require it, and a
    /// server without one simply cannot be told about a sign-out. Absent rather
    /// than an error, because refusing to log a user in over a missing LOGOUT
    /// endpoint would be the wrong trade.
    pub revocation_endpoint: Option<String>,
}

/// Resolve a PDS to its authorization server, both fetches and both validations.
///
/// Shared by the login path and the refresh path so the two cannot disagree
/// about which server they are talking to. The order is not arbitrary: the
/// protected-resource document names the issuer, and the issuer's own metadata
/// is then required to agree — an authorization server that claims a different
/// issuer than the one that pointed at it is the mix-up attack RFC 9207 exists
/// for.
///
/// `expected_issuer` is a REQUIRED parameter, not an optional one, and that is
/// the point.
///
/// The check it performs — that the re-discovered issuer is the one a grant
/// already belongs to — was a free function every caller had to remember. It was
/// applied to the callback and the refresh paths and forgotten on revocation,
/// where the body carries the REFRESH TOKEN. A caller with no prior issuer must
/// now say so explicitly with `None`, which cannot be done by accident.
pub async fn discover(
    http: &reqwest::Client,
    pds_url: &str,
    auth_method: &str,
    expected_issuer: Option<&str>,
) -> Result<AuthorizationServer> {
    discover_with(
        |url| async move {
            super::fetch::get_json(http, &url, super::fetch::JSON)
                .await
                .with_context(|| format!("fetching {url}"))
        },
        pds_url,
        auth_method,
        expected_issuer,
    )
    .await
}

/// [`discover`] with the fetch injected.
///
/// The orchestration — which URL each document is fetched from, and which value
/// is carried forward as the expected issuer — is where the mix-up defence
/// actually lives, and it was untested because testing it appeared to need a
/// network: the SSRF guard rejects loopback, so there is no mock server to point
/// at. Taking the fetch as an argument removes that obstacle without putting a
/// test-only bypass inside the guard, which would weaken the very control these
/// tests exist to protect.
///
/// `fetch` is called with the FULL url, so a test can assert on which locations
/// were asked for — the thing a fixture handed two documents cannot see.
pub async fn discover_with<F, Fut>(
    fetch: F,
    pds_url: &str,
    auth_method: &str,
    expected_issuer: Option<&str>,
) -> Result<AuthorizationServer>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    let prm_url = protected_resource_url(pds_url)?;
    let prm = fetch(prm_url).await?;

    // The issuer named by the PDS decides where the second document comes from.
    let issuer = validate_protected_resource(&prm, pds_url)?;
    let asm_url = authorization_server_url(&issuer);
    let asm = fetch(asm_url.clone()).await?;

    let server = resolve_documents(&prm, &asm, &asm_url, pds_url, auth_method)?;

    // Enforced HERE rather than in `discover` so it is reachable with an
    // injected fetch. Putting it in `discover` would have made the check
    // untestable for exactly the reason this module was split up in the first
    // place: `discover` needs a network, and the SSRF guard rejects loopback.
    if let Some(expected) = expected_issuer {
        super::session::same_issuer(&server.issuer, expected)?;
    }
    Ok(server)
}

/// Where a PDS's protected-resource document lives.
pub fn protected_resource_url(pds_url: &str) -> Result<String> {
    Ok(format!(
        "{}/.well-known/oauth-protected-resource",
        origin_of(pds_url)?
    ))
}

/// Where an issuer's authorization-server metadata lives.
///
/// Derived from the ISSUER, never from the PDS. The mix-up defence is
/// `metadata.issuer == the URL we fetched from`; fetch from anywhere else and
/// that comparison is checking a document against a location it did not come
/// from.
pub fn authorization_server_url(issuer: &str) -> String {
    format!("{issuer}/.well-known/oauth-authorization-server")
}

/// Validate an already-fetched pair of discovery documents.
///
/// The decision half of [`discover`], split out because the WIRING is where the
/// mix-up defence actually lives and it had no coverage: two mutations passed
/// the whole suite — one feeding the authorization server's own `issuer` claim
/// in as the expected value (so the check became `declared == declared`), and
/// one fetching the second document from the PDS instead of the issuer.
///
/// `asm_fetched_from` is required rather than assumed: the comparison only means
/// anything if the document really came from the issuer's own well-known
/// location, so that precondition is checked here instead of trusted.
pub fn resolve_documents(
    prm: &Value,
    asm: &Value,
    asm_fetched_from: &str,
    pds_url: &str,
    auth_method: &str,
) -> Result<AuthorizationServer> {
    let issuer = validate_protected_resource(prm, pds_url)?;

    let expected = authorization_server_url(&issuer);
    if asm_fetched_from != expected {
        bail!(
            "the authorization-server metadata was fetched from {asm_fetched_from:?}, not from \
             the issuer's own {expected:?}; the issuer comparison would be meaningless"
        );
    }

    // The expected issuer comes from the PROTECTED-RESOURCE document — i.e. the
    // URL this metadata was fetched from — never from the metadata's own claim.
    validate_authorization_server(asm, &issuer, pds_url, auth_method)
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
fn require_endpoint(metadata: &Value, field: &str, issuer: &str) -> Result<String> {
    let raw = metadata
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("authorization-server metadata has no `{field}`"))?;
    let parsed = url::Url::parse(raw)
        .with_context(|| format!("`{field}` {raw:?} is not an absolute URL"))?;
    if parsed.scheme() != "https" {
        bail!("`{field}` must be https, got {raw:?}");
    }
    // **Endpoints must live on the issuer's own origin.**
    //
    // RFC 8414 does not require co-location, so this is a hardening choice
    // rather than a conformance check — and it is made deliberately, because
    // `authorization_endpoint` is a URL this app 303s a browser to from its own
    // `/login`. Without it, anyone who can start a login with a `did:web` they
    // control turns `/login` into an arbitrary-https-redirect on our origin: the
    // chain is self-consistent, every other discovery check passes, and the
    // endpoint points wherever they like.
    //
    // The atproto profile co-locates these in practice — the frozen real-PDS
    // fixture in the tests below is the evidence, as is the entryway/PDS split
    // where the PDS is `*.host.bsky.network` and the issuer and its endpoints
    // are all `bsky.social` — so the cost is refusing a server that is unusual
    // rather than one that is wrong.
    //
    // Note what this does NOT do: an attacker who controls the `did:web` chain
    // controls the issuer origin too, so `/login` can still redirect to any
    // origin they can serve two self-consistent documents from. This narrows
    // the target to origins that look like authorization servers; it does not
    // remove the redirect.
    let origin = origin_of(raw)?;
    if origin != issuer {
        bail!(
            "`{field}` {raw:?} is on {origin:?}, not the issuer's own origin {issuer:?}; \
             refusing to treat it as part of this authorization server"
        );
    }
    Ok(raw.to_string())
}

/// The same validation for a field that may legitimately be absent.
///
/// Present-but-unusable is still an ERROR: a `revocation_endpoint` of
/// `http://…` or a relative path is a broken document, and silently treating it
/// as absent would turn a misconfigured server into a silent no-op sign-out.
fn optional_endpoint(metadata: &Value, field: &str, issuer: &str) -> Result<Option<String>> {
    match metadata.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => require_endpoint(metadata, field, issuer).map(Some),
    }
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
        par_endpoint: require_endpoint(metadata, "pushed_authorization_request_endpoint", issuer)?,
        authorization_endpoint: require_endpoint(metadata, "authorization_endpoint", issuer)?,
        token_endpoint: require_endpoint(metadata, "token_endpoint", issuer)?,
        revocation_endpoint: optional_endpoint(metadata, "revocation_endpoint", issuer)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// **An endpoint on a foreign origin is refused.**
    ///
    /// `authorization_endpoint` is a URL the app 303s a browser to from its own
    /// `/login`. Left unconstrained, anyone who can start a login with a
    /// `did:web` they control turns `/login` into an arbitrary-https-redirect on
    /// our origin — every other discovery check passes, because the hostile
    /// documents are self-consistent.
    ///
    /// RFC 8414 permits co-location to be absent, so this refuses a server that
    /// is unusual rather than one that is wrong. The real-PDS fixture below is
    /// the evidence that atproto co-locates in practice.
    #[test]
    fn an_endpoint_on_a_foreign_origin_is_refused() {
        for field in [
            "pushed_authorization_request_endpoint",
            "authorization_endpoint",
            "token_endpoint",
            "revocation_endpoint",
        ] {
            let mut asm = as_metadata();
            asm[field] = json!("https://totally-other.example/authorize");
            let err = match validate_authorization_server(&asm, ISS, PDS, "none") {
                Err(err) => err,
                Ok(_) => panic!("accepted a foreign-origin {field}"),
            };
            let rendered = format!("{err:#}");
            assert!(
                rendered.contains("issuer's own origin"),
                "{field} failed for the wrong reason: {rendered}"
            );
        }
    }

    /// An ABSENT `revocation_endpoint` is absent, not an error. RFC 8414 does
    /// not require one, and refusing to log a user in because a server offers no
    /// way to log them out later would be the wrong trade.
    #[test]
    fn an_absent_revocation_endpoint_is_tolerated() {
        assert_eq!(
            optional_endpoint(
                &json!({}),
                "revocation_endpoint",
                "https://auth.example.com"
            )
            .unwrap(),
            None
        );
        assert_eq!(
            optional_endpoint(
                &json!({ "revocation_endpoint": null }),
                "revocation_endpoint",
                "https://auth.example.com"
            )
            .unwrap(),
            None
        );
    }

    /// **Present but unusable is an ERROR, not "absent".**
    ///
    /// Folding a broken value into `None` would turn a misconfigured server into
    /// a silent no-op sign-out: revocation would be skipped, the local row would
    /// still be deleted, and the logout would look entirely successful while the
    /// refresh token stayed live at the PDS.
    #[test]
    fn a_malformed_revocation_endpoint_is_an_error_rather_than_absent() {
        let plain_http = json!({ "revocation_endpoint": "http://auth.example.com/revoke" });
        let err = optional_endpoint(
            &plain_http,
            "revocation_endpoint",
            "https://auth.example.com",
        )
        .expect_err("plain http must be refused");
        assert!(format!("{err:#}").contains("must be https"));

        let relative = json!({ "revocation_endpoint": "/revoke" });
        assert!(
            optional_endpoint(&relative, "revocation_endpoint", "https://auth.example.com")
                .is_err()
        );

        let wrong_type = json!({ "revocation_endpoint": 42 });
        assert!(optional_endpoint(
            &wrong_type,
            "revocation_endpoint",
            "https://auth.example.com"
        )
        .is_err());
    }

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
            // The real PDS advertises revocation, so sign-out can actually reach
            // it. Asserted against the frozen real document rather than assumed:
            // an optional field that happens to be absent everywhere we deploy
            // would make the revocation path dead code that still passes its own
            // unit tests.
            assert_eq!(
                server.revocation_endpoint.as_deref(),
                Some("https://pds.justin-stanley.com/oauth/revoke")
            );
        }
    }

    // ── the WIRING, which is where the mix-up defence actually lives ─────────

    fn prm_naming(issuer: &str) -> serde_json::Value {
        json!({ "resource": PDS, "authorization_servers": [issuer] })
    }

    /// **The expected issuer comes from the PDS's document, never from the
    /// authorization server's own claim.**
    ///
    /// Feeding the AS document's `issuer` in as the expected value turns the
    /// mix-up check into `declared == declared` — and that mutation passed all
    /// 575 tests, because every test of the check sat on
    /// `validate_authorization_server` and nothing exercised how `discover`
    /// called it.
    #[test]
    fn the_expected_issuer_comes_from_the_protected_resource_document() {
        // The PDS names ISS. The metadata claims to be a DIFFERENT issuer — and
        // is internally consistent about it, endpoints and all.
        let other = "https://evil.example";
        let mut asm = as_metadata();
        asm["issuer"] = json!(other);
        for field in [
            "pushed_authorization_request_endpoint",
            "authorization_endpoint",
            "token_endpoint",
        ] {
            asm[field] = json!(format!("{other}/x"));
        }

        let err = match resolve_documents(
            &prm_naming(ISS),
            &asm,
            &authorization_server_url(ISS),
            PDS,
            "none",
        ) {
            Err(err) => err,
            Ok(_) => panic!("a self-consistent impostor was accepted"),
        };
        assert!(
            format!("{err:#}").contains("issuer"),
            "failed for the wrong reason: {err:#}"
        );
    }

    /// **The metadata must have been fetched from the issuer's own location.**
    ///
    /// `metadata.issuer == the URL we fetched from` is only a defence if the
    /// second fetch really went to the issuer. Building that URL from the PDS
    /// instead passed the whole suite.
    #[test]
    fn metadata_fetched_from_the_wrong_place_is_refused() {
        let err = match resolve_documents(
            &prm_naming(ISS),
            &as_metadata(),
            // What the mutation did: derive it from the PDS.
            &authorization_server_url(PDS),
            PDS,
            "none",
        ) {
            Err(err) => err,
            Ok(_) => panic!("metadata from the wrong origin was accepted"),
        };
        assert!(format!("{err:#}").contains("issuer's own"), "{err:#}");

        // Fetched from the right place: accepted.
        resolve_documents(
            &prm_naming(ISS),
            &as_metadata(),
            &authorization_server_url(ISS),
            PDS,
            "none",
        )
        .expect("the honest pair must resolve");
    }

    /// The second URL is built from the ISSUER, and the first from the PDS.
    #[test]
    fn the_discovery_urls_come_from_the_right_inputs() {
        assert_eq!(
            protected_resource_url("https://pds.example.com/xrpc/x").unwrap(),
            "https://pds.example.com/.well-known/oauth-protected-resource"
        );
        assert_eq!(
            authorization_server_url(ISS),
            format!("{ISS}/.well-known/oauth-authorization-server")
        );
    }

    // ── the full discovery orchestration, with the fetch injected ────────────

    /// Serve documents by URL and record every URL asked for.
    struct Fetcher {
        docs: std::collections::HashMap<String, serde_json::Value>,
        asked: std::sync::Mutex<Vec<String>>,
    }

    impl Fetcher {
        fn new(pairs: &[(&str, serde_json::Value)]) -> Self {
            Self {
                docs: pairs
                    .iter()
                    .map(|(u, d)| ((*u).to_string(), d.clone()))
                    .collect(),
                asked: std::sync::Mutex::new(Vec::new()),
            }
        }

        async fn get(&self, url: String) -> Result<serde_json::Value> {
            self.asked.lock().unwrap().push(url.clone());
            self.docs
                .get(&url)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("nothing served at {url}"))
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
    }

    /// **The metadata is fetched from the ISSUER, not from the PDS.**
    ///
    /// This is the mutation that survived even after `resolve_documents` gained
    /// its origin check: the check made the mistake fail closed at runtime, but
    /// nothing exercised the code that chooses the URL. Now the fetcher records
    /// what was asked for, so a wrong derivation is visible directly.
    #[tokio::test]
    async fn the_metadata_is_fetched_from_the_issuers_own_location() {
        let fetcher = Fetcher::new(&[
            (
                &protected_resource_url(PDS).unwrap(),
                json!({ "resource": PDS, "authorization_servers": [ISS] }),
            ),
            (&authorization_server_url(ISS), as_metadata()),
        ]);

        let server = discover_with(|url| fetcher.get(url), PDS, "none", None)
            .await
            .expect("the honest pair must resolve");
        assert_eq!(server.issuer, ISS);

        assert_eq!(
            fetcher.asked(),
            vec![
                protected_resource_url(PDS).unwrap(),
                authorization_server_url(ISS),
            ],
            "discovery asked for the wrong locations, or in the wrong order"
        );
    }

    /// A PDS that repoints an EXISTING grant at a new authorization server is
    /// refused — the check the revocation path did not have.
    ///
    /// Every other validation passes here: the pair is entirely self-consistent,
    /// `resource` equals the PDS origin, exactly one AS is named, and the
    /// metadata's `issuer` matches the location it was served from. The only
    /// thing wrong is that it is not the issuer the grant belongs to, and the
    /// only check that notices is this one.
    ///
    /// Why it mattered most on revocation: `revoke_params` prefers the REFRESH
    /// token, and `bounded_then_delete` drops the local row whether or not the
    /// revocation succeeded — so a repointed PDS would receive the refresh token
    /// while the real authorization server was never told, leaving a live grant
    /// that the app can no longer revoke. "Sign out everywhere" would silently
    /// mean the opposite.
    #[tokio::test]
    async fn a_repointed_pds_cannot_move_an_existing_grant() {
        // A FULLY self-consistent impostor: the attacker hosts every endpoint on
        // its own origin, which is what the co-location check requires. Moving
        // only `issuer` would be caught by a different check and would prove
        // nothing about this one.
        let attacker = "https://as.attacker.example";
        let mut moved = as_metadata();
        moved["issuer"] = json!(attacker);
        moved["pushed_authorization_request_endpoint"] = json!(format!("{attacker}/par"));
        moved["authorization_endpoint"] = json!(format!("{attacker}/authorize"));
        moved["token_endpoint"] = json!(format!("{attacker}/token"));
        moved["revocation_endpoint"] = json!(format!("{attacker}/revoke"));

        let fetcher = Fetcher::new(&[
            (
                &protected_resource_url(PDS).unwrap(),
                json!({ "resource": PDS, "authorization_servers": [attacker] }),
            ),
            (&authorization_server_url(attacker), moved),
        ]);

        // Sanity: with no prior issuer (a first login) this pair is legitimate.
        discover_with(|url| fetcher.get(url), PDS, "none", None)
            .await
            .expect("a self-consistent pair must resolve when there is no grant yet");

        let err = discover_with(|url| fetcher.get(url), PDS, "none", Some(ISS))
            .await
            .expect_err("a grant issued by ISS must not follow the PDS to a new issuer");
        let msg = err.to_string();
        assert!(
            msg.contains(ISS) || msg.contains(attacker),
            "the error should name the issuers it compared, got: {msg}"
        );
    }

    /// A PDS that names someone else's authorization server gets that server's
    /// document fetched — and the issuer carried forward is the one the PDS
    /// named, not the one the document claims.
    #[tokio::test]
    async fn the_issuer_carried_forward_is_the_one_the_pds_named() {
        let other = "https://other.example";
        let mut impostor = as_metadata();
        impostor["issuer"] = json!(other);

        let fetcher = Fetcher::new(&[
            (
                &protected_resource_url(PDS).unwrap(),
                json!({ "resource": PDS, "authorization_servers": [ISS] }),
            ),
            // Served at the URL derived from the issuer the PDS named, but
            // claiming to be a different issuer.
            (&authorization_server_url(ISS), impostor),
        ]);

        let err = match discover_with(|url| fetcher.get(url), PDS, "none", None).await {
            Err(err) => err,
            Ok(_) => panic!("a document claiming a different issuer was accepted"),
        };
        assert!(format!("{err:#}").contains("issuer"), "{err:#}");
    }

    /// A fetch failure on either document fails the discovery rather than
    /// proceeding with half a picture.
    #[tokio::test]
    async fn a_missing_document_fails_the_discovery() {
        // Only the protected-resource document exists.
        let fetcher = Fetcher::new(&[(
            &protected_resource_url(PDS).unwrap(),
            json!({ "resource": PDS, "authorization_servers": [ISS] }),
        )]);
        assert!(discover_with(|url| fetcher.get(url), PDS, "none", None)
            .await
            .is_err());

        // Neither exists.
        let empty = Fetcher::new(&[]);
        assert!(discover_with(|url| empty.get(url), PDS, "none", None)
            .await
            .is_err());
    }
}
