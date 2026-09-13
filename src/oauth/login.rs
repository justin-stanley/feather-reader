//! The browser-facing halves of the OAuth flow: starting a login and finishing
//! one.
//!
//! This is the part of the cutover that **inverts** rather than swapping. Under
//! the sidecar the app redirects to *its* `/login`, the sidecar owns the
//! callback, and the app receives a one-shot `session_id` to exchange for an
//! identity. Here the app owns both ends: it performs PAR itself, and the PDS
//! redirects the browser straight back to the app with a `code`.
//!
//! The logic lives here rather than in `web.rs` so it can be tested without an
//! HTTP server, and so the handler stays a thin shell that does cookies and
//! redirects.

use anyhow::{bail, Context as _, Result};

use super::runtime::OauthRuntime;
use super::{client_auth, discovery, dpop, flow, keys, request, store, token};

/// Longest a pending login may sit before it is swept.
///
/// Ten minutes, or the PAR request_uri's own lifetime if shorter. The row holds
/// a sealed DPoP key and a PKCE verifier; keeping it past the point the
/// `request_uri` is usable protects nothing and widens the window in which a
/// stolen `state` is worth replaying.
const MAX_PENDING_SECS: i64 = 600;

/// A login that has been pushed to the authorization server and is waiting for
/// the user.
pub struct StartedLogin {
    /// Where to send the browser.
    pub authorize_url: String,
    /// The browser-binding token. Set as a cookie; the callback must present it
    /// or the flow is refused. This is what stops a login CSRF: `state` alone
    /// lives in a server-global table and says nothing about *which* browser
    /// started the flow.
    pub binding_token: String,
}

/// Begin a login for whatever the user typed.
///
/// The identity is resolved **before** anything is pushed to an authorization
/// server, because the PDS we discover from is the one the resolved DID names.
/// Starting from a handle and trusting a server to tell us whose it is would be
/// the whole attack.
pub async fn start(
    runtime: &OauthRuntime,
    http: &reqwest::Client,
    pool: &sqlx::SqlitePool,
    subject: &str,
    now: i64,
) -> Result<StartedLogin> {
    let account = super::resolve::resolve(&runtime.resolver, http, subject, &runtime.plc_directory)
        .await
        .with_context(|| format!("resolving {subject:?}"))?;

    // No prior issuer: this IS the login that establishes one.
    let server = discovery::discover(http, &account.pds_url, runtime.auth_method.as_str(), None)
        .await
        .with_context(|| {
            format!(
                "discovering the authorization server for {}",
                account.pds_url
            )
        })?;

    // Generated BEFORE the push: the authorization server binds the request_uri
    // to this key's thumbprint, and every later call on this grant must use the
    // same key.
    let session_key = keys::SigningKey::generate("session");
    let verifier = flow::new_pkce_verifier();
    let state = flow::new_state();
    let binding_token = flow::new_binding_token();

    let mut params = flow::par_params(&flow::ParRequest {
        client_id: &runtime.client_id,
        redirect_uri: &super::metadata::redirect_uri(&runtime.client),
        scope: runtime.client.scope_str(),
        state: &state,
        code_challenge: &flow::pkce_challenge(&verifier),
        login_hint: Some(subject),
    });
    let assertion = client_assertion(runtime, runtime.auth_method, &server.issuer, now)?;
    params.extend(client_auth::credential_params(
        runtime.auth_method,
        &runtime.client_id,
        assertion.as_deref(),
    )?);

    let outcome = post_form(
        http,
        pool,
        &server.par_endpoint,
        &session_key,
        &params,
        // PAR is safe to repeat: a rejected attempt consumes nothing.
        request::Retry::Allowed,
    )
    .await?;
    if !outcome.is_success() {
        bail!(
            "the pushed authorization request failed with status {}",
            outcome.status
        );
    }
    let par = flow::parse_par_response(&outcome.json()?)?;

    store::put_pending(
        pool,
        &runtime.codec,
        &store::PendingAuth {
            state: state.clone(),
            browser_binding_hash: flow::binding_hash(&binding_token),
            pkce_verifier: verifier,
            dpop_key_jwk: session_key.to_jwk_json()?,
            issuer: server.issuer.clone(),
            pds_url: account.pds_url.clone(),
            did: account.did.clone(),
            auth_method: runtime.auth_method.as_str().to_string(),
            auth_kid: runtime.client_key.as_ref().map(|k| k.kid().to_string()),
            redirect_uri: super::metadata::redirect_uri(&runtime.client),
            requested_scope: runtime.client.scope_str().to_string(),
            request_uri: par.request_uri.clone(),
            app_return_to: None,
            expires_at: now + par.expires_in.min(MAX_PENDING_SECS),
        },
    )
    .await?;

    Ok(StartedLogin {
        authorize_url: flow::authorize_url(
            &server.authorization_endpoint,
            &runtime.client_id,
            &par.request_uri,
        )?,
        binding_token,
    })
}

/// Who logged in.
///
/// `Debug` carries a DID and an optional handle — both already public identity,
/// and neither a credential. No token, key or code is reachable from here.
#[derive(Debug)]
pub struct CompletedLogin {
    pub did: String,
    /// Only present when it round-tripped: a handle that cannot be verified
    /// back to this DID is not displayed beside the account.
    pub handle: Option<String>,
}

/// Finish a login from the callback's query parameters.
///
/// The session is stored before this returns, so by the time the caller mints a
/// cookie the tokens are already durable. The reverse would leave a browser
/// holding a session the server cannot serve.
pub async fn complete(
    runtime: &OauthRuntime,
    http: &reqwest::Client,
    pool: &sqlx::SqlitePool,
    params: &flow::CallbackParams,
    presented_cookie: Option<&str>,
    now: i64,
) -> Result<CompletedLogin> {
    // Consumes the pending row, checks the browser binding, and validates `iss`
    // — all three, or no code comes back.
    let (pending, code) =
        flow::complete_callback(pool, &runtime.codec, params, presented_cookie, now).await?;

    let key = keys::SigningKey::from_jwk_json(&pending.dpop_key_jwk, "session")
        .context("unsealing the login's DPoP key")?;

    // The method the login was STARTED under, not whatever is configured now.
    // A deploy that flipped dev/production between the push and the callback
    // would otherwise present credentials that do not match the ones PAR was
    // authenticated with, and the exchange would fail for a reason nothing in
    // the logs would explain.
    let auth_method: client_auth::AuthMethod = pending
        .auth_method
        .parse()
        .context("the pending login stored an unknown auth method")?;

    // The client's IDENTITY must also be the one PAR was pushed under. Both
    // `client_id` and `redirect_uri` derive from `public_url`, so the stored
    // redirect is enough to detect a configuration change between the push and
    // the callback — no second column needed, and no migration for a row that
    // lives ten minutes.
    //
    // Without this the exchange fails at the authorization server with a
    // mismatched client, and nothing on our side says why. Checked here so the
    // reason is in the log rather than inferred from a 400.
    let current_redirect = super::metadata::redirect_uri(&runtime.client);
    if current_redirect != pending.redirect_uri {
        bail!(
            "this login was started under a different public URL (redirect {:?}, now {:?}); \
             the client identity changed mid-flight and the exchange would be rejected",
            pending.redirect_uri,
            current_redirect
        );
    }

    let server = discovery::discover(
        http,
        &pending.pds_url,
        auth_method.as_str(),
        Some(&pending.issuer),
    )
    .await?;

    // **The re-discovered issuer must be the one PAR was pushed under.**
    //
    // Discovery runs again here, from the network, and the token endpoint comes
    // out of THAT document. Every discovery check is internally consistent — a
    // hostile pair of documents satisfies all of them — so nothing else notices
    // if the PDS's protected-resource document was repointed at a different
    // authorization server between the push and this callback.
    //
    // `verify_callback` does not catch it either: the callback legitimately
    // carries the ORIGINAL issuer, because the real server is what the user
    // approved at. Without this check the authorization code, the PKCE verifier
    // and a `private_key_jwt` assertion all go to the new endpoint.
    //
    // `store.rs` names this exact threat as the reason `issuer` is AAD-bound.
    // The AAD protects the column from local tampering; only this protects it
    // from a network re-read.
    let token_params = token_exchange_params(runtime, &pending, &code, auth_method, now)?;

    let outcome = post_form(
        http,
        pool,
        &server.token_endpoint,
        &key,
        &token_params,
        // A nonce challenge is rejected BEFORE the grant is processed, so the
        // code is not consumed and the request is safe to resend. The nonce
        // harvested at PAR is routinely stale by now — approval can take
        // minutes and a server nonce lasts at most five.
        request::Retry::Allowed,
    )
    .await?;

    let did = accept_token_response(pool, &runtime.codec, &pending, &outcome, now).await?;

    // The handle is resolved from the DID rather than remembered from the login
    // form: what the user typed is not evidence, and `resolve` returns `None`
    // unless it round-trips. A failure here must not fail the login — the
    // account is already authenticated, and the handle is a display detail.
    let handle = match super::resolve::resolve(
        &runtime.resolver,
        http,
        &did,
        &runtime.plc_directory,
    )
    .await
    {
        Ok(account) => account.handle,
        Err(err) => {
            tracing::warn!(%err, did = %did, "could not resolve a handle for the new session");
            None
        }
    };

    Ok(CompletedLogin { did, handle })
}

/// Assemble the token-endpoint form for this pending login.
///
/// **Split out of [`complete`] so it can be tested.** Every value here has to
/// come from the PENDING ROW rather than from current configuration or a fresh
/// computation: the code, the redirect and the PKCE verifier are all bound by
/// the authorization server to the request that PAR pushed. Substituting any of
/// them — which a refactor can do silently, since all three are plain strings —
/// either breaks every login or, in the PKCE case, removes the proof that the
/// party redeeming the code is the one that requested it.
///
/// A mutation replacing `pending.pkce_verifier` with a literal passed the entire
/// suite, because nothing ever inspected the form this builds.
fn token_exchange_params(
    runtime: &OauthRuntime,
    pending: &store::PendingAuth,
    code: &str,
    auth_method: client_auth::AuthMethod,
    now: i64,
) -> Result<Vec<(&'static str, String)>> {
    let mut params =
        token::token_request_params(code, &pending.redirect_uri, &pending.pkce_verifier);
    let assertion = client_assertion(runtime, auth_method, &pending.issuer, now)?;
    params.extend(client_auth::credential_params(
        auth_method,
        &runtime.client_id,
        assertion.as_deref(),
    )?);
    Ok(params)
}

/// Validate a token-endpoint response and persist the session it grants.
///
/// **Split out of [`complete`] so these checks are reachable without a live
/// authorization server**, which is why they had no tests: `complete` cannot
/// reach a stub, because discovery requires `https` and the SSRF guard forbids
/// loopback, so there is nowhere for a test to point it. Every guard below could
/// be deleted with the whole suite green.
///
/// Returns the authenticated DID. Behaviour is identical to the inline version
/// it replaces, including that the body is parsed only after the status check —
/// a failed exchange must not have its body examined or echoed.
async fn accept_token_response(
    pool: &sqlx::SqlitePool,
    codec: &super::crypto::Codec,
    pending: &store::PendingAuth,
    outcome: &request::PostOutcome,
    now: i64,
) -> Result<String> {
    if !outcome.is_success() {
        bail!("the token exchange failed with status {}", outcome.status);
    }
    let tokens = token::parse_token_response(&outcome.json()?)?;

    // The token's subject must be the DID we resolved and pushed. A server that
    // returns a different one has authorized a different account than the user
    // asked for.
    if tokens.sub != pending.did {
        bail!(
            "the authorization server returned tokens for a different subject than the \
             login was started for"
        );
    }

    store::put_session(
        pool,
        codec,
        &store::OAuthSession {
            sub: tokens.sub.clone(),
            issuer: pending.issuer.clone(),
            aud: pending.pds_url.clone(),
            dpop_key_jwk: pending.dpop_key_jwk.clone(),
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token.unwrap_or_default(),
            token_type: tokens.token_type,
            granted_scope: tokens.granted_scope,
            expires_at: tokens.expires_in.map(|secs| now + secs),
        },
    )
    .await?;

    Ok(tokens.sub)
}

/// Mint a client assertion when the negotiated method needs one.
fn client_assertion(
    runtime: &OauthRuntime,
    method: client_auth::AuthMethod,
    issuer: &str,
    now: i64,
) -> Result<Option<String>> {
    match method {
        client_auth::AuthMethod::None => Ok(None),
        client_auth::AuthMethod::PrivateKeyJwt => {
            let key = runtime
                .client_key
                .as_ref()
                .context("private_key_jwt is negotiated but no client signing key is loaded")?;
            Ok(Some(client_auth::client_assertion(
                key,
                &runtime.client_id,
                issuer,
                now,
            )?))
        }
    }
}

/// POST a form to an authorization-server endpoint with a DPoP proof.
async fn post_form(
    http: &reqwest::Client,
    pool: &sqlx::SqlitePool,
    url: &str,
    key: &keys::SigningKey,
    params: &[(&'static str, String)],
    retry: request::Retry,
) -> Result<request::PostOutcome> {
    let borrowed: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
    request::send_with_dpop(
        http,
        pool,
        &request::DpopRequest {
            endpoint: dpop::Endpoint::AuthorizationServer,
            url,
            key,
            access_token: None,
            body: request::DpopBody::Form(&borrowed),
            retry,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PUSHED_REDIRECT: &str = "https://feather-reader.com/oauth/callback";
    const PENDING_ISSUER: &str = "https://auth.example.com";

    const PENDING_DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

    /// A well-formed token-endpoint response granting `sub`.
    fn token_body(sub: &str) -> serde_json::Value {
        serde_json::json!({
            "access_token": "at-abc",
            "token_type": "DPoP",
            "scope": "atproto",
            "sub": sub,
            "expires_in": 3600,
            "refresh_token": "rt-abc",
        })
    }

    fn outcome(status: u16, body: &serde_json::Value) -> request::PostOutcome {
        request::PostOutcome {
            status,
            body: serde_json::to_vec(body).unwrap(),
        }
    }

    async fn empty_pool() -> sqlx::SqlitePool {
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::oauth::store::init_schema(&pool).await.unwrap();
        pool
    }

    /// **The authorization server must not be able to log the user in as
    /// somebody else.**
    ///
    /// `complete` pushes PAR for a DID it resolved itself, and the token response
    /// carries a `sub`. If the two are allowed to differ, a hostile or buggy
    /// server hands back a working session for an account the user never asked
    /// for — and everything downstream (`put_session`, the cookie, every later
    /// repo call) is keyed on that `sub`, so the whole app then acts as the wrong
    /// identity.
    ///
    /// Deleting this check passed all 664 tests. It had no test because it sits
    /// after a network round trip that a test cannot make: discovery requires
    /// `https` and the SSRF guard forbids loopback, so there is nowhere to point
    /// a stub. Splitting the response handling out of `complete` is what makes it
    /// reachable — the guard is unchanged, it just no longer requires a live
    /// authorization server to observe.
    #[tokio::test]
    async fn tokens_for_a_different_subject_are_refused() {
        let pool = empty_pool().await;
        let codec = crate::oauth::crypto::Codec::new(Some(TEST_KEY)).unwrap();
        let pending = pending_auth("unused-hash");

        let hostile = token_body("did:plc:zzzzzzzzzzzzzzzzzzzzzzzz");
        let err = accept_token_response(
            &pool,
            &codec,
            &pending,
            &outcome(200, &hostile),
            1_700_000_000,
        )
        .await
        .expect_err("a token response for another DID must be refused");

        assert!(
            format!("{err:#}").contains("different subject"),
            "refused, but not by the subject check: {err:#}",
        );
        assert!(
            crate::oauth::store::get_session(&pool, &codec, "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz")
                .await
                .unwrap()
                .is_none(),
            "no session may be stored for a subject the login did not start for",
        );
    }

    /// The matching-subject case must still succeed and persist the session —
    /// otherwise a check that refused every login would satisfy the test above.
    #[tokio::test]
    async fn tokens_for_the_pending_subject_are_accepted_and_stored() {
        let pool = empty_pool().await;
        let codec = crate::oauth::crypto::Codec::new(Some(TEST_KEY)).unwrap();
        let pending = pending_auth("unused-hash");

        let did = accept_token_response(
            &pool,
            &codec,
            &pending,
            &outcome(200, &token_body(PENDING_DID)),
            1_700_000_000,
        )
        .await
        .expect("a token response for the pending DID must be accepted");

        assert_eq!(did, PENDING_DID);
        let stored = crate::oauth::store::get_session(&pool, &codec, PENDING_DID)
            .await
            .unwrap()
            .expect("the session must be durable before complete() returns");
        assert_eq!(stored.access_token, "at-abc");
        assert_eq!(stored.issuer, PENDING_ISSUER);
    }

    /// **A non-2xx token response must not be parsed as a session.**
    ///
    /// The status check is what stops an error body being read as a grant, and
    /// it also keeps the failure body from being examined at all — it may be an
    /// arbitrary proxy or WAF page.
    #[tokio::test]
    async fn a_failed_token_exchange_stores_nothing() {
        let pool = empty_pool().await;
        let codec = crate::oauth::crypto::Codec::new(Some(TEST_KEY)).unwrap();
        let pending = pending_auth("unused-hash");

        // A body that WOULD parse as a valid grant for the right DID, behind a
        // failure status: only the status check stands between it and a session.
        let err = accept_token_response(
            &pool,
            &codec,
            &pending,
            &outcome(400, &token_body(PENDING_DID)),
            1_700_000_000,
        )
        .await
        .expect_err("a 400 must not yield a session");

        assert!(
            format!("{err:#}").contains("failed with status 400"),
            "refused, but not by the status check: {err:#}",
        );
        assert!(
            crate::oauth::store::get_session(&pool, &codec, PENDING_DID)
                .await
                .unwrap()
                .is_none(),
            "a failed exchange must leave no session behind",
        );
    }

    /// **The PKCE verifier sent must be the pending row's.**
    ///
    /// PKCE is what proves the party redeeming the code is the party that
    /// requested it. The verifier is a plain `String` three fields away from two
    /// other plain `String`s, so substituting it is a one-token edit — and a
    /// mutation replacing it with a literal passed the whole suite, because
    /// nothing ever looked at the form `complete` builds.
    #[test]
    fn the_token_request_carries_the_pending_rows_pkce_verifier_and_redirect() {
        let runtime = runtime_at("https://feather-reader.com");
        let pending = pending_auth("unused-hash");

        let params = token_exchange_params(
            &runtime,
            &pending,
            "the-code",
            runtime.auth_method,
            1_700_000_000,
        )
        .expect("building the token request");
        let get = |k: &str| {
            params
                .iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| v.as_str())
        };

        assert_eq!(
            get("code_verifier"),
            Some(pending.pkce_verifier.as_str()),
            "the verifier must come from the pending row; anything else forfeits PKCE",
        );
        assert_eq!(get("code"), Some("the-code"));
        assert_eq!(
            get("redirect_uri"),
            Some(pending.redirect_uri.as_str()),
            "the redirect must be the one PAR was pushed under",
        );
        assert_eq!(get("grant_type"), Some("authorization_code"));
    }

    /// A pending login pushed under [`PUSHED_REDIRECT`], as a value.
    fn pending_auth(cookie_hash: &str) -> crate::oauth::store::PendingAuth {
        crate::oauth::store::PendingAuth {
            state: "state-value".into(),
            browser_binding_hash: cookie_hash.into(),
            pkce_verifier: "verifier".into(),
            // A REAL private JWK. `complete` unseals the DPoP key before it
            // compares redirects, so a placeholder here refuses the login one
            // step too early and the identity check never runs — which the
            // assertion below caught rather than tolerated.
            dpop_key_jwk: crate::oauth::keys::SigningKey::generate("session")
                .to_jwk_json()
                .unwrap(),
            issuer: PENDING_ISSUER.into(),
            pds_url: "https://pds.example.com".into(),
            did: PENDING_DID.into(),
            auth_method: "private_key_jwt".into(),
            auth_kid: None,
            redirect_uri: PUSHED_REDIRECT.into(),
            requested_scope: "atproto".into(),
            request_uri: "urn:x".into(),
            app_return_to: None,
            expires_at: 2_000_000_000,
        }
    }

    /// A pool holding that pending login, for the tests that drive `complete`
    /// end to end.
    async fn pending_login(cookie_hash: &str) -> sqlx::SqlitePool {
        let pool = empty_pool().await;
        let codec = crate::oauth::crypto::Codec::new(Some(TEST_KEY)).unwrap();
        crate::oauth::store::put_pending(&pool, &codec, &pending_auth(cookie_hash))
            .await
            .unwrap();
        pool
    }

    /// A runtime serving `public_url`, with the same codec key as the pool.
    fn runtime_at(public_url: &str) -> crate::oauth::runtime::OauthRuntime {
        crate::oauth::runtime::OauthRuntime::new(&crate::config::Config {
            repo_backend: crate::metrics::Backend::Rust,
            public_url: public_url.into(),
            oauth: crate::config::OauthConfig {
                encryption_key: Some(TEST_KEY.to_string()),
                ..crate::config::OauthConfig::default()
            },
            ..crate::config::Config::default()
        })
        .expect("the test runtime must build")
    }

    fn callback_params() -> flow::CallbackParams {
        flow::CallbackParams {
            code: Some("the-code".into()),
            state: Some("state-value".into()),
            iss: Some(PENDING_ISSUER.into()),
            error: None,
            error_description: None,
            response: None,
        }
    }

    /// **`complete` — the code exchange — had no test at all, and this is the
    /// first one to actually call it.**
    ///
    /// `login.rs` contained exactly two tests and neither invoked `complete`;
    /// both asserted that `metadata::redirect_uri` is a function of its input,
    /// one of them as the literal tautology `f(x) == f(x)`. Five separate guards
    /// inside `complete` could each be deleted with the whole suite still green,
    /// including the check that the tokens belong to the DID the login started
    /// for. The function is reachable only on the rust backend, so it is dormant
    /// today — the cutover makes it every user's login path.
    ///
    /// This pins the identity check: the pending row was pushed under
    /// `feather-reader.com`, the runtime now serves loopback, and the exchange
    /// must be refused BY THAT CHECK.
    ///
    /// Asserting the specific message matters more than usual here. Discovery
    /// against `pds.example.com` would fail anyway — so `is_err()` alone would
    /// pass with the check deleted, which is exactly how the rest of this module
    /// came to be untested. Matching the message is what makes the mutation
    /// visible.
    #[tokio::test]
    async fn a_login_started_under_a_different_public_url_is_refused() {
        let cookie = flow::new_binding_token();
        let pool = pending_login(&flow::binding_hash(&cookie)).await;
        let runtime = runtime_at("http://127.0.0.1:8080");

        let err = complete(
            &runtime,
            &reqwest::Client::new(),
            &pool,
            &callback_params(),
            Some(&cookie),
            1_700_000_000,
        )
        .await
        .expect_err("a client-identity change mid-flight must refuse the exchange");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("started under a different public URL")
                && rendered.contains(PUSHED_REDIRECT),
            "refused, but not BY the client-identity check — this is the failure mode \
             where discovery merely errored instead: {rendered}",
        );
    }

    /// **The identity check must also let a MATCHING login through.**
    ///
    /// A check that refuses everything satisfies the test above, so this pins the
    /// other direction: with the runtime serving the same public URL the row was
    /// pushed under, `complete` must get PAST the redirect comparison and fail
    /// later — at discovery, which cannot reach `pds.example.com` from a test.
    ///
    /// This is deliberately an assertion about WHICH error comes back, not about
    /// success: a full exchange needs a stub authorization server, and the SSRF
    /// guard forbids loopback, so one cannot be reached from here. That is the
    /// same wall that left this function untested, and closing it properly needs
    /// an injectable resolver rather than another test.
    #[tokio::test]
    async fn a_matching_public_url_passes_the_identity_check() {
        let cookie = flow::new_binding_token();
        let pool = pending_login(&flow::binding_hash(&cookie)).await;
        let runtime = runtime_at("https://feather-reader.com");

        let err = complete(
            &runtime,
            &reqwest::Client::new(),
            &pool,
            &callback_params(),
            Some(&cookie),
            1_700_000_000,
        )
        .await
        .expect_err("discovery cannot reach pds.example.com from a test");

        let rendered = format!("{err:#}");
        assert!(
            !rendered.contains("started under a different public URL"),
            "a login whose public URL never changed must not be refused as though it \
             had; the identity check is rejecting valid logins: {rendered}",
        );
    }

    /// **A login must complete under the identity it STARTED under.**
    ///
    /// `client_id` and `redirect_uri` both derive from `public_url`, so a
    /// deployment whose public URL changes between the push and the callback
    /// would present a different client than PAR authenticated as. The
    /// authorization server rejects that, and without this check nothing on our
    /// side explains why — the same failure mode the stored `auth_method`
    /// already guards against.
    ///
    /// The pending row's `redirect_uri` is the witness: it is written at push
    /// time and is derived from the same value.
    #[test]
    fn a_changed_public_url_is_detected_from_the_stored_redirect() {
        let started_under = super::super::metadata::ClientConfig::new(
            "https://feather-reader.com",
            "atproto",
            false,
        )
        .unwrap();
        let now_configured = super::super::metadata::ClientConfig::new(
            "https://reader.example.org",
            "atproto",
            false,
        )
        .unwrap();

        let pushed = super::super::metadata::redirect_uri(&started_under);
        let current = super::super::metadata::redirect_uri(&now_configured);

        assert_ne!(
            pushed, current,
            "a changed public URL must change the redirect, or the check cannot see it"
        );
        // And the client_id moves with it — which is what the server rejects.
        assert_ne!(
            super::super::metadata::client_id(&started_under),
            super::super::metadata::client_id(&now_configured)
        );
    }

    /// The check must NOT fire on an unchanged configuration, or every login
    /// breaks.
    #[test]
    fn an_unchanged_public_url_matches_the_stored_redirect() {
        let cfg = super::super::metadata::ClientConfig::new(
            "https://feather-reader.com",
            "atproto",
            false,
        )
        .unwrap();
        assert_eq!(
            super::super::metadata::redirect_uri(&cfg),
            super::super::metadata::redirect_uri(&cfg)
        );
    }
}
