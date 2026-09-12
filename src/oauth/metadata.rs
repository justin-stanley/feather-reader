//! The OAuth client-identity documents: `client-metadata.json` and the
//! `client_id` derived from it.
//!
//! Two client shapes, chosen by [`ClientConfig::dev`]:
//!
//! * **dev / localhost** — atproto's special *localhost development client*.
//!   The `client_id` is `http://localhost` with `redirect_uri` and `scope`
//!   encoded as query parameters; no JWKS and no published metadata document
//!   are required, so a dev stack boots with zero PKI.
//!
//! * **production** — a confidential client with a real, edge-reachable
//!   metadata document, a published JWKS, and `private_key_jwt` authentication
//!   using the key from [`super::keys`].
//!
//! **The external URLs deliberately match the sidecar's.** `client_id` is not
//! merely a config value — it IS the client's identity, and a PDS stores it
//! against every existing grant. The sidecar is mounted at `/oauth` by the edge
//! proxy, so its metadata document is externally `…/oauth/client-metadata.json`
//! and its callback `…/oauth/callback`. Serving those same paths from the Rust
//! app keeps `client_id` stable across the cutover, so existing authorizations
//! survive and a rollback does not strand them either.

use anyhow::{bail, Context as _, Result};
use serde_json::{json, Value};

/// Everything the client documents are derived from.
///
/// Fields are private and the only constructor is [`ClientConfig::new`], so a
/// `ClientConfig` that exists has been validated. Leaving them public would
/// make the validation advisory, and the value it guards — `client_id` — is the
/// client's identity rather than a request parameter.
pub struct ClientConfig {
    /// Public base URL of the app, e.g. `https://feather-reader.com`.
    public_url: String,
    /// The OAuth scope string requested at authorize time.
    scope: String,
    /// Localhost development client (no PKI) rather than a confidential client.
    dev: bool,
}

impl ClientConfig {
    /// Build a validated config.
    ///
    /// `public_url` must be an absolute `http(s)` URL with **no path**, and must
    /// be `https` outside dev. The path rule is the one that bites: the sidecar
    /// is mounted under `/oauth`, so `SIDECAR_PUBLIC_URL` is documented as
    /// `https://feather-reader.com/oauth` — and reusing that value here would
    /// produce `…/oauth/oauth/client-metadata.json`, which the edge proxy does
    /// not route, 404ing a `client_id` the PDS has already cached.
    ///
    /// Validated at construction rather than at use because `client_id` is the
    /// client's identity: a wrong one is not a bad request, it is a different
    /// client, and it is discovered only after users cannot log in.
    pub fn new(public_url: &str, scope: &str, dev: bool) -> Result<Self> {
        let parsed = url::Url::parse(public_url)
            .with_context(|| format!("public_url {public_url:?} is not an absolute URL"))?;

        match parsed.scheme() {
            "https" => {}
            "http" if dev => {}
            "http" => bail!("public_url must be https outside dev, got {public_url:?}"),
            other => bail!("public_url must be http(s), got scheme {other:?}"),
        }
        if !parsed.has_host() {
            bail!("public_url {public_url:?} has no host");
        }
        if parsed.path() != "/" && !parsed.path().is_empty() {
            bail!(
                "public_url must be an origin with no path, got {public_url:?} \
                 (path {:?}) — the /oauth prefix is added by this module, so \
                 including it would publish a doubled client_id",
                parsed.path()
            );
        }
        // Query, fragment and userinfo are rejected rather than ignored: the
        // stored value is concatenated with `/oauth/...`, so a query would
        // produce `https://host?x=1/oauth/client-metadata.json`, and userinfo
        // would publish credentials inside the client's identity and in every
        // `redirect_uris` entry.
        if parsed.query().is_some() {
            bail!("public_url must not carry a query string, got {public_url:?}");
        }
        if parsed.fragment().is_some() {
            bail!("public_url must not carry a fragment, got {public_url:?}");
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            bail!("public_url must not carry credentials, got {public_url:?}");
        }

        // Store the PARSED origin, not the input string: `Url` has already
        // lowercased the scheme and host and dropped a default port, so the
        // published `client_id` is stable however it was spelled in config.
        let origin = parsed[..url::Position::AfterPort].to_string();
        Ok(Self {
            public_url: origin,
            scope: scope.to_string(),
            dev,
        })
    }

    /// The requested scope, as sent in PAR and stored on the pending row.
    pub fn scope_str(&self) -> &str {
        &self.scope
    }

    /// The public base URL without a trailing slash, so the path joins below
    /// cannot produce a `//`.
    fn base(&self) -> &str {
        self.public_url.trim_end_matches('/')
    }
}

/// Where the browser is sent back to after the PDS authorizes (or denies).
pub fn redirect_uri(cfg: &ClientConfig) -> String {
    format!("{}/oauth/callback", cfg.base())
}

/// Where the published JWKS lives. Production only — the localhost dev client
/// does not use one.
pub fn jwks_uri(cfg: &ClientConfig) -> String {
    format!("{}/oauth/jwks.json", cfg.base())
}

/// The client's identity.
///
/// In production this is the URL of the metadata document itself, which the PDS
/// fetches. In dev it is atproto's localhost development client: the literal
/// `http://localhost` with the redirect and scope in the query string.
///
/// Both query parameters are percent-encoded by the serializer rather than
/// interpolated. `redirect_uri` contains `:` and `/`, and any `&` or `?` in a
/// configured value would otherwise splice additional parameters into the
/// client_id — a config value must never be able to redefine the redirect.
pub fn client_id(cfg: &ClientConfig) -> String {
    if !cfg.dev {
        return format!("{}/oauth/client-metadata.json", cfg.base());
    }
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("redirect_uri", &redirect_uri(cfg))
        .append_pair("scope", &cfg.scope)
        .finish();
    format!("http://localhost?{query}")
}

/// The `client-metadata.json` document.
pub fn client_metadata(cfg: &ClientConfig) -> Value {
    let mut doc = json!({
        "client_id": client_id(cfg),
        "client_name": if cfg.dev { "FeatherReader (dev)" } else { "FeatherReader" },
        "redirect_uris": [redirect_uri(cfg)],
        "scope": cfg.scope,
        // `refresh_token` is required: without it the client cannot refresh and
        // every session dies at access-token expiry.
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "application_type": "web",
        "dpop_bound_access_tokens": true,
    });

    let obj = doc.as_object_mut().expect("built from a json! object");
    if cfg.dev {
        // The localhost dev client publishes no JWKS and authenticates with
        // nothing; advertising a jwks_uri we do not serve would make the PDS
        // fetch a 404.
        obj.insert("token_endpoint_auth_method".into(), json!("none"));
    } else {
        obj.insert("client_uri".into(), json!(cfg.base()));
        obj.insert(
            "token_endpoint_auth_method".into(),
            json!("private_key_jwt"),
        );
        obj.insert("token_endpoint_auth_signing_alg".into(), json!("ES256"));
        obj.insert("jwks_uri".into(), json!(jwks_uri(cfg)));
    }
    doc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prod() -> ClientConfig {
        ClientConfig::new(
            "https://feather-reader.com",
            "atproto transition:generic",
            false,
        )
        .unwrap()
    }

    fn dev() -> ClientConfig {
        ClientConfig::new("http://127.0.0.1:8080", "atproto transition:generic", true).unwrap()
    }

    // ── configuration validation ─────────────────────────────────────────────

    /// **The misconfiguration that is waiting to happen.** `SIDECAR_PUBLIC_URL`
    /// is documented as `https://feather-reader.com/oauth`, because the sidecar
    /// is mounted under that prefix — so that is exactly the value an operator
    /// reaches for. Carrying the path through would yield
    /// `…/oauth/oauth/client-metadata.json`; Caddy strips ONE `/oauth` prefix,
    /// so the request 404s, every login breaks, and the PDS has already cached
    /// that `client_id`.
    #[test]
    fn a_public_url_carrying_a_path_is_rejected() {
        for url in [
            "https://feather-reader.com/oauth",
            "https://feather-reader.com/a/b",
            "https://feather-reader.com/oauth/",
        ] {
            let cfg = ClientConfig::new(url, "atproto", false);
            assert!(cfg.is_err(), "accepted a public_url with a path: {url}");
        }
    }

    /// Checking only the path let these through, and the raw string was then
    /// concatenated, so `client_id` came out as
    /// `https://feather-reader.com?x=1/oauth/client-metadata.json` — or, worse,
    /// published credentials inside the client's identity.
    #[test]
    fn a_public_url_carrying_a_query_fragment_or_credentials_is_rejected() {
        for url in [
            "https://feather-reader.com?x=1",
            "https://feather-reader.com#frag",
            "https://u:p@feather-reader.com",
            "https://u@feather-reader.com",
        ] {
            assert!(
                ClientConfig::new(url, "atproto", false).is_err(),
                "accepted {url}"
            );
        }
    }

    /// The stored value is the PARSED origin, so casing is normalized and the
    /// published `client_id` is stable regardless of how it was configured.
    #[test]
    fn the_origin_is_normalized_rather_than_echoed_back() {
        let cfg = ClientConfig::new("HTTPS://Feather-Reader.COM", "atproto", false).unwrap();
        assert_eq!(
            client_id(&cfg),
            "https://feather-reader.com/oauth/client-metadata.json"
        );
    }

    #[test]
    fn a_public_url_must_be_an_absolute_http_url() {
        for url in [
            "feather-reader.com",
            "",
            "/////",
            "not a url",
            "ftp://x.example",
        ] {
            assert!(
                ClientConfig::new(url, "atproto", false).is_err(),
                "accepted {url:?}"
            );
        }
    }

    /// Production `client_id` must be https — a PDS will not accept a plaintext
    /// client identity. Dev runs on loopback http, which is the documented
    /// exception.
    #[test]
    fn plain_http_is_rejected_in_production_but_allowed_in_dev() {
        assert!(ClientConfig::new("http://feather-reader.com", "atproto", false).is_err());
        assert!(ClientConfig::new("http://127.0.0.1:8080", "atproto", true).is_ok());
    }

    #[test]
    fn a_valid_public_url_is_accepted_with_or_without_a_trailing_slash() {
        assert!(ClientConfig::new("https://feather-reader.com", "atproto", false).is_ok());
        assert!(ClientConfig::new("https://feather-reader.com/", "atproto", false).is_ok());
    }

    // ── the URLs that must not change ────────────────────────────────────────

    /// `client_id` is the client's identity: a PDS stores it against every
    /// existing grant. These are the paths the sidecar is reachable on today
    /// (it is mounted at `/oauth` by the edge proxy), so keeping them keeps
    /// existing authorizations valid across the cutover.
    #[test]
    fn the_production_urls_match_the_paths_the_sidecar_serves_today() {
        let cfg = prod();
        assert_eq!(
            client_id(&cfg),
            "https://feather-reader.com/oauth/client-metadata.json"
        );
        assert_eq!(
            redirect_uri(&cfg),
            "https://feather-reader.com/oauth/callback"
        );
        assert_eq!(jwks_uri(&cfg), "https://feather-reader.com/oauth/jwks.json");
    }

    #[test]
    fn a_trailing_slash_on_the_public_url_is_normalized_away() {
        let cfg = ClientConfig {
            public_url: "https://feather-reader.com/".into(),
            ..prod()
        };
        assert_eq!(
            client_id(&cfg),
            "https://feather-reader.com/oauth/client-metadata.json"
        );
        assert_eq!(
            redirect_uri(&cfg),
            "https://feather-reader.com/oauth/callback"
        );
    }

    // ── production document ──────────────────────────────────────────────────

    #[test]
    fn the_production_document_is_a_dpop_bound_confidential_client() {
        let doc = client_metadata(&prod());
        assert_eq!(doc["client_id"], client_id(&prod()));
        assert_eq!(doc["redirect_uris"][0], redirect_uri(&prod()));
        assert_eq!(doc["jwks_uri"], jwks_uri(&prod()));
        assert_eq!(doc["token_endpoint_auth_method"], "private_key_jwt");
        assert_eq!(doc["token_endpoint_auth_signing_alg"], "ES256");
        assert_eq!(doc["dpop_bound_access_tokens"], true);
        assert_eq!(doc["application_type"], "web");
        assert_eq!(doc["response_types"][0], "code");
        let grants: Vec<&str> = doc["grant_types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g.as_str().unwrap())
            .collect();
        assert!(grants.contains(&"authorization_code"));
        assert!(
            grants.contains(&"refresh_token"),
            "without refresh_token the client cannot refresh and sessions die at token expiry"
        );
    }

    // ── dev document ─────────────────────────────────────────────────────────

    /// The localhost dev client needs NO published metadata and NO JWKS — that
    /// is the whole point of it. Advertising a `jwks_uri` we do not serve would
    /// make the PDS fetch a 404.
    #[test]
    fn the_dev_document_declares_no_jwks_and_no_client_authentication() {
        let doc = client_metadata(&dev());
        assert!(doc.get("jwks_uri").is_none());
        assert_eq!(doc["token_endpoint_auth_method"], "none");
        assert_eq!(doc["dpop_bound_access_tokens"], true);
    }

    /// The dev `client_id` carries redirect_uri and scope in its QUERY STRING,
    /// so both must be percent-encoded. Interpolating them raw would splice the
    /// `:` and `/` of the redirect and, worse, let any `&` or `?` in a
    /// configured value inject further parameters.
    #[test]
    fn the_dev_client_id_percent_encodes_its_query_parameters() {
        let id = client_id(&dev());
        assert!(id.starts_with("http://localhost?"), "got {id}");
        assert!(
            id.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Foauth%2Fcallback"),
            "redirect_uri was not percent-encoded: {id}"
        );
        // The space in "atproto transition:generic" must be encoded too.
        assert!(
            id.contains("scope=atproto+transition%3Ageneric")
                || id.contains("scope=atproto%20transition%3Ageneric"),
            "scope was not percent-encoded: {id}"
        );
        assert!(
            !id.contains(' '),
            "a raw space would make an invalid URL: {id}"
        );
    }

    /// A hostile or fat-fingered config value must not be able to add
    /// parameters to the dev client_id.
    #[test]
    fn a_query_delimiter_in_the_scope_cannot_inject_extra_parameters() {
        let cfg = ClientConfig {
            scope: "atproto&redirect_uri=https://evil.example".into(),
            ..dev()
        };
        let id = client_id(&cfg);
        assert_eq!(
            id.matches("redirect_uri=").count(),
            1,
            "scope injected a second redirect_uri: {id}"
        );
        assert!(id.contains("%26"), "the `&` was not encoded: {id}");
    }

    #[test]
    fn the_dev_document_and_client_id_agree_on_the_redirect_uri() {
        let doc = client_metadata(&dev());
        assert_eq!(doc["redirect_uris"][0], redirect_uri(&dev()));
        assert_eq!(doc["client_id"], client_id(&dev()));
    }
}
