//! The Rust OAuth client's long-lived state, assembled once at startup.
//!
//! Everything here is expensive to build, unsafe to rebuild per request, or
//! both: the signing key anchors `client_id` and must be the same key across
//! every request; the refresh locks are only useful if every caller shares one
//! map; the DNS resolver holds the host's configuration.

use std::path::Path;

use anyhow::{Context as _, Result};

use super::client_auth::AuthMethod;
use super::crypto::Codec;
use super::keys::SigningKey;
use super::metadata::ClientConfig;
use super::session::RefreshLocks;

/// The `kid` for the client's signing key.
///
/// Published in the JWKS and echoed in every client assertion's header, so a
/// server that has cached our JWKS looks the key up by this. It matches the
/// sidecar's so a rollback finds the same key under the same name.
pub const CLIENT_KID: &str = "featherreader-oauth-1";

/// Everything the Rust OAuth client needs that outlives a request.
pub struct OauthRuntime {
    /// At-rest encryption for sessions and the signing key.
    pub codec: Codec,
    /// The validated client identity.
    pub client: ClientConfig,
    /// `client_id`, precomputed — it is derived, and recomputing it per request
    /// invites a divergence between what we send and what we publish.
    pub client_id: String,
    /// The ES256 client key. `None` for the dev client, which authenticates as
    /// a public client and publishes no JWKS.
    pub client_key: Option<SigningKey>,
    /// How this client authenticates to the authorization server.
    pub auth_method: AuthMethod,
    /// Per-subject refresh serialization. One map process-wide, or the locking
    /// does nothing.
    pub locks: RefreshLocks,
    /// The PLC directory for `did:plc` resolution.
    pub plc_directory: String,
    /// The system DNS resolver, for handle → DID.
    pub resolver: hickory_resolver::TokioResolver,
}

impl OauthRuntime {
    /// Build the runtime from configuration.
    ///
    /// **Dev is inferred from the public URL, exactly as the sidecar infers it**,
    /// so the two agree on which client identity they present. A localhost
    /// public URL means atproto's localhost development client: a public client
    /// with no JWKS.
    ///
    /// The signing key is loaded (or created) ONLY for a confidential client.
    /// Creating one in dev would write a key file that is never used and never
    /// published, which later reads as "the key exists, so it must be in play".
    pub fn new(cfg: &crate::config::Config) -> Result<Self> {
        let dev = is_loopback_url(&cfg.public_url);
        let client = ClientConfig::new(&cfg.public_url, &cfg.oauth.scope, dev)
            .context("building the OAuth client identity")?;
        let client_id = super::metadata::client_id(&client);
        let auth_method = AuthMethod::negotiate(dev);
        let codec = Codec::new(cfg.oauth.encryption_key.as_deref())
            .context("building the at-rest encryption codec")?;

        let client_key = match auth_method {
            AuthMethod::PrivateKeyJwt => Some(
                super::keys::load_or_create(Path::new(&cfg.oauth.key_path), &codec, CLIENT_KID)
                    .with_context(|| {
                        format!(
                            "loading the OAuth signing key at {}",
                            cfg.oauth.key_path.display()
                        )
                    })?,
            ),
            AuthMethod::None => None,
        };

        Ok(Self {
            codec,
            client,
            client_id,
            client_key,
            auth_method,
            locks: RefreshLocks::default(),
            plc_directory: cfg.oauth.plc_directory.clone(),
            resolver: super::resolve::resolver()?,
        })
    }
}

/// Whether a public URL names the local machine.
///
/// The sidecar infers its dev mode the same way (`SIDECAR_DEV` defaults to "the
/// public URL is localhost"). Matching that inference matters because dev and
/// production publish DIFFERENT `client_id`s — disagreeing would mean the two
/// implementations present themselves as different clients from identical
/// configuration.
fn is_loopback_url(public_url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(public_url) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Domain(host)) => host == "localhost" || host.ends_with(".localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dev inference must match the sidecar's, because the two publish
    /// different `client_id`s in the two modes. If they disagreed, identical
    /// configuration would produce two different clients and the cutover would
    /// invalidate every grant.
    #[test]
    fn dev_is_inferred_from_a_loopback_public_url() {
        assert!(is_loopback_url("http://localhost:8080"));
        assert!(is_loopback_url("http://127.0.0.1:8080"));
        assert!(is_loopback_url("http://[::1]:8080"));
        assert!(is_loopback_url("http://app.localhost:8080"));

        assert!(!is_loopback_url("https://feather-reader.com"));
        assert!(!is_loopback_url("https://localhost.evil.com"));
    }

    /// A host merely CONTAINING "localhost" is not loopback. `localhost.evil.com`
    /// resolving as dev would hand the production deployment the dev client
    /// identity — a public client with no client authentication at all.
    #[test]
    fn a_hostname_containing_localhost_is_not_loopback() {
        assert!(!is_loopback_url("https://localhost.evil.com"));
        assert!(!is_loopback_url("https://notlocalhost"));
        assert!(!is_loopback_url("https://mylocalhost.net"));
    }

    /// An unparseable URL is NOT dev. Failing open here would drop client
    /// authentication on a malformed production config.
    #[test]
    fn an_unparseable_url_is_not_treated_as_dev() {
        assert!(!is_loopback_url("not a url"));
        assert!(!is_loopback_url(""));
    }
}

#[cfg(test)]
mod default_config_tests {
    /// **A default local run must be a PUBLIC client and write no key file.**
    ///
    /// Observed: a bare `./featherreader` left an ES256 private key at
    /// `oauth-signing-key.json` in the working directory. That is the
    /// confidential-client path, so a default local run was presenting a
    /// different client identity than intended — and dropping a private key into
    /// whatever directory it was started from, which for a clone is the repo
    /// root.
    #[test]
    fn the_default_config_is_a_public_client_with_no_key_file() {
        let cfg = crate::config::Config::default();
        let runtime = super::OauthRuntime::new(&cfg).expect("the default config must build");
        assert_eq!(
            runtime.auth_method,
            crate::oauth::client_auth::AuthMethod::None,
            "a loopback public_url must negotiate a PUBLIC client"
        );
        assert!(
            runtime.client_key.is_none(),
            "a public client must hold no signing key"
        );
        assert!(
            !std::path::Path::new(&cfg.oauth.key_path).exists(),
            "building the runtime wrote a private key file at {}",
            cfg.oauth.key_path.display()
        );
    }
}
