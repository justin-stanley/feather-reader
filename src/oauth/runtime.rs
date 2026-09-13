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
    /// The ES256 client key. `None` for the dev client, which is a public
    /// client and publishes no JWKS — and for a confidential client whose
    /// backend is not selected and which has no key file yet, since creating one
    /// it will never use is key material at rest for nothing.
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
    /// The signing key is loaded (or created) only for a confidential client
    /// **that is actually going to use it** — i.e. when the Rust backend is the
    /// selected one. Two reasons, and the second is the one that bit:
    ///
    /// * a dev client is public, so a key there is never used and never
    ///   published, and later reads as "the key exists, so it must be in play";
    /// * the runtime is built on EVERY start so configuration errors surface
    ///   early, including when the sidecar is serving. Creating the key as part
    ///   of that validation meant a sidecar deployment wrote an ES256 private
    ///   key it would never use — key material at rest, for nothing. In tests it
    ///   also meant any `AppState` built with a production-like `public_url`
    ///   dropped a private key into the working directory.
    pub fn new(cfg: &crate::config::Config) -> Result<Self> {
        let dev = is_loopback_url(&cfg.public_url);
        let client = ClientConfig::new(&cfg.public_url, &cfg.oauth.scope, dev)
            .context("building the OAuth client identity")?;
        let client_id = super::metadata::client_id(&client);
        let auth_method = AuthMethod::negotiate(dev);
        let codec = Codec::new(cfg.oauth.encryption_key.as_deref())
            .context("building the at-rest encryption codec")?;

        // CREATION is gated on the backend; LOADING is not.
        //
        // Gating both was wrong, and dangerously so: `revoke_everywhere` signs a
        // user out of BOTH backends on purpose, because after a flip their
        // tokens can be in either store. With the sidecar selected and a key
        // already on disk from a previous rust deployment, refusing to load it
        // left `auth_method` as `private_key_jwt` with no key — so revocation
        // bailed while the local row was deleted anyway, and the PDS-side
        // refresh token stayed live forever with no local record left to retry
        // from. An in-flight rust login completing after a flip died the same
        // way.
        //
        // So: create a key only for the backend that will use it, but adopt one
        // that already exists whatever the backend.
        let creates_key = cfg.repo_backend == crate::metrics::Backend::Rust;
        let key_exists = cfg.oauth.key_path.exists();
        let client_key = match auth_method {
            AuthMethod::PrivateKeyJwt if creates_key || key_exists => Some(
                super::keys::load_or_create(Path::new(&cfg.oauth.key_path), &codec, CLIENT_KID)
                    .with_context(|| {
                        format!(
                            "loading the OAuth signing key at {}",
                            cfg.oauth.key_path.display()
                        )
                    })?,
            ),
            // Either a public client, or a confidential one whose backend is not
            // selected AND which has no key on disk to adopt.
            AuthMethod::PrivateKeyJwt | AuthMethod::None => None,
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
mod key_creation_tests {
    use super::*;

    fn cfg(
        backend: crate::metrics::Backend,
        public_url: &str,
        key_path: &std::path::Path,
    ) -> crate::config::Config {
        crate::config::Config {
            repo_backend: backend,
            public_url: public_url.to_string(),
            oauth: crate::config::OauthConfig {
                key_path: key_path.to_path_buf(),
                ..crate::config::OauthConfig::default()
            },
            ..crate::config::Config::default()
        }
    }

    fn temp_key_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("fr-test-key-{name}-{}.json", std::process::id()))
    }

    /// **Building the runtime must not write a key the deployment will not use.**
    ///
    /// The runtime is constructed on every start, whatever the backend, so
    /// configuration errors surface early. Creating the signing key as part of
    /// that meant a SIDECAR deployment — the default — wrote an ES256 private
    /// key it never touches: key material at rest for nothing.
    ///
    /// It surfaced as a unit test dropping a private key into the repo root,
    /// because any `AppState` built with a production-like `public_url` did it.
    #[test]
    fn the_sidecar_backend_writes_no_signing_key() {
        let path = temp_key_path("sidecar");
        let _ = std::fs::remove_file(&path);

        let runtime = OauthRuntime::new(&cfg(
            crate::metrics::Backend::Sidecar,
            "https://feather-reader.com",
            &path,
        ))
        .expect("must build");

        assert!(runtime.client_key.is_none());
        assert!(
            !path.exists(),
            "the sidecar backend wrote a signing key it will never use"
        );
    }

    /// The Rust backend on a production URL DOES need the key, and creates it.
    #[test]
    fn the_rust_backend_creates_its_signing_key() {
        let path = temp_key_path("rust");
        let _ = std::fs::remove_file(&path);

        let runtime = OauthRuntime::new(&cfg(
            crate::metrics::Backend::Rust,
            "https://feather-reader.com",
            &path,
        ))
        .expect("must build");

        assert!(
            runtime.client_key.is_some(),
            "a confidential client needs its key"
        );
        assert!(path.exists(), "the key was not persisted");
        let _ = std::fs::remove_file(&path);
    }

    /// **An EXISTING key is adopted even when the backend will not create one.**
    ///
    /// This is the flip-back case. `revoke_everywhere` signs a user out of both
    /// backends deliberately, because after a flip their tokens can be in either
    /// store. Refusing to load a key that is already on disk left the sidecar
    /// deployment with `private_key_jwt` and no key, so revocation bailed while
    /// the local row was deleted regardless — the PDS-side refresh token then
    /// stayed live with nothing left to retry from.
    #[test]
    fn an_existing_key_is_adopted_on_the_sidecar_backend() {
        let path = temp_key_path("adopt");
        let _ = std::fs::remove_file(&path);

        // A previous rust deployment left a key behind.
        OauthRuntime::new(&cfg(
            crate::metrics::Backend::Rust,
            "https://feather-reader.com",
            &path,
        ))
        .expect("must build");
        assert!(path.exists(), "precondition: the key was created");

        // Flip back to the sidecar. The key must still be loaded.
        let runtime = OauthRuntime::new(&cfg(
            crate::metrics::Backend::Sidecar,
            "https://feather-reader.com",
            &path,
        ))
        .expect("must build");
        assert!(
            runtime.client_key.is_some(),
            "an existing key was ignored, so rust sessions could never be revoked"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A loopback deployment is a PUBLIC client: no key, on either backend.
    #[test]
    fn a_loopback_deployment_is_public_and_keyless() {
        let path = temp_key_path("dev");
        let _ = std::fs::remove_file(&path);

        let runtime = OauthRuntime::new(&cfg(
            crate::metrics::Backend::Rust,
            "http://localhost:8080",
            &path,
        ))
        .expect("must build");

        assert_eq!(runtime.auth_method, AuthMethod::None);
        assert!(runtime.client_key.is_none());
        assert!(!path.exists(), "a public client wrote a signing key");
    }
}
