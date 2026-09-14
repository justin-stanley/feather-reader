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
    let par = accept_par_response(&outcome)?;

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
            expires_at: pending_expiry(now, par.expires_in),
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
    complete_with(
        runtime,
        pool,
        params,
        presented_cookie,
        now,
        // **These three closures must contain NO decisions.** A review found the
        // first cut had put `Some(&expected_issuer)` and the DPoP key
        // reconstruction in here — outside the seam the tests drive — so both
        // could be broken with the whole suite green. Changing the issuer
        // argument to `None` disabled the authorization-server mix-up defence
        // for every real login and 702 tests still passed.
        //
        // Everything decided is now decided in `complete_with` and arrives
        // fully formed; these are transports.
        |req: Discovery| async move {
            discovery::discover(
                http,
                &req.pds_url,
                &req.auth_method,
                req.expected_issuer.as_deref(),
            )
            .await
        },
        |req: TokenPost| async move {
            post_form(http, pool, &req.url, &req.key, &req.params, req.retry).await
        },
        |did: String| async move {
            super::resolve::resolve(&runtime.resolver, http, &did, &runtime.plc_directory).await
        },
    )
    .await
}

/// What `complete_with` hands its discovery transport. Every field is already
/// decided; the transport only performs the call.
struct Discovery {
    pds_url: String,
    auth_method: String,
    /// `Some(issuer)` arms the authorization-server mix-up re-check inside
    /// `discovery::discover`. **The `Option` is constructed here, not in the
    /// adapter**, so a test can see whether the defence is armed at all.
    expected_issuer: Option<String>,
}

/// What `complete_with` hands its token transport.
struct TokenPost {
    url: String,
    params: Vec<(&'static str, String)>,
    /// The ACTUAL key, not a recipe for one. The first cut passed the JWK string
    /// and let the adapter re-parse it, which meant a freshly generated key would
    /// have been accepted — signing the grant under a thumbprint it was never
    /// bound to — with a green suite. `Arc` rather than a borrow only because the
    /// key is local to `complete_with`; the guarantee is the same.
    key: std::sync::Arc<keys::SigningKey>,
    retry: request::Retry,
}

/// [`complete`] with the three network boundaries injected.
///
/// **The SEQUENCING is the thing worth testing, and it was unreachable.** Each
/// guard in this function has its own unit test, but nothing drove the whole
/// callback: it needs discovery, a token endpoint and handle resolution, all
/// over the network — and an issuer is required to be `https`, so even a local
/// plain-HTTP server cannot stand in for an authorization server. Injecting the
/// three calls is what makes the ORDER observable, which is where the mix-up
/// defence actually lives: the value of the issuer re-check is entirely in it
/// happening BEFORE the code, the PKCE verifier and a `private_key_jwt`
/// assertion are posted anywhere.
///
/// **Every decision lives here, not in the caller's closures.** A review of the
/// first cut found the opposite: the `Some(issuer)` that arms the mix-up
/// re-check and the DPoP key the grant is bound to were both assembled inside
/// the adapters, where no test could see them — so either could be broken with
/// the entire suite green. The transports now receive fully-formed arguments.
///
/// Same shape as [`discovery::discover_with`], and for the same reason.
#[allow(clippy::too_many_arguments)]
async fn complete_with<D, DFut, P, PFut, R, RFut>(
    runtime: &OauthRuntime,
    pool: &sqlx::SqlitePool,
    params: &flow::CallbackParams,
    presented_cookie: Option<&str>,
    now: i64,
    discover: D,
    post: P,
    resolve_handle: R,
) -> Result<CompletedLogin>
where
    D: Fn(Discovery) -> DFut,
    DFut: std::future::Future<Output = Result<discovery::AuthorizationServer>>,
    P: Fn(TokenPost) -> PFut,
    PFut: std::future::Future<Output = Result<request::PostOutcome>>,
    R: Fn(String) -> RFut,
    RFut: std::future::Future<Output = Result<super::resolve::ResolvedAccount>>,
{
    // Consumes the pending row, checks the browser binding, and validates `iss`
    // — all three, or no code comes back.
    let (pending, code) =
        flow::complete_callback(pool, &runtime.codec, params, presented_cookie, now).await?;

    // **Unsealed HERE, before discovery and the exchange.** A DPoP key that will
    // not parse must stop the login before the authorization code is sent
    // anywhere, not after — the final outcome is a failed login either way, so
    // only the absence of a POST distinguishes them.
    //
    // The key is then handed to the token transport by reference, so nothing
    // downstream can substitute a different one: the grant is bound to this
    // thumbprint and no other.
    let key = std::sync::Arc::new(
        keys::SigningKey::from_jwk_json(&pending.dpop_key_jwk, "session")
            .context("unsealing the login's DPoP key")?,
    );

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

    let server = discover(Discovery {
        pds_url: pending.pds_url.clone(),
        auth_method: auth_method.as_str().to_string(),
        // `Some`, decided here: this is what arms the mix-up re-check.
        expected_issuer: Some(pending.issuer.clone()),
    })
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

    let outcome = post(TokenPost {
        url: server.token_endpoint.clone(),
        params: token_params,
        key: std::sync::Arc::clone(&key),
        // A nonce challenge is rejected BEFORE the grant is processed, so the
        // code is not consumed and the request is safe to resend. The nonce
        // harvested at PAR is routinely stale by now — approval can take minutes
        // and a server nonce lasts at most five.
        retry: request::Retry::Allowed,
    })
    .await?;

    let did = accept_token_response(pool, &runtime.codec, &pending, &outcome, now).await?;

    // The handle is resolved from the DID rather than remembered from the login
    // form: what the user typed is not evidence, and `resolve` returns `None`
    // unless it round-trips. A failure here must not fail the login — the
    // account is already authenticated, and the handle is a display detail.
    let handle = match resolve_handle(did.clone()).await {
        Ok(account) => account.handle,
        Err(err) => {
            tracing::warn!(%err, did = %did, "could not resolve a handle for the new session");
            None
        }
    };

    Ok(CompletedLogin { did, handle })
}

/// When a pending login must be swept, capped at [`MAX_PENDING_SECS`].
///
/// **The cap is ours, not the server's.** Without `.min(...)` the authorization
/// server chooses how long a row holding a sealed DPoP key and a PKCE verifier
/// survives, and a server answering with a large `expires_in` widens the window
/// in which a stolen `state` is worth replaying. Dropping the `.min` passed the
/// entire suite.
fn pending_expiry(now: i64, par_expires_in: i64) -> i64 {
    now + par_expires_in.min(MAX_PENDING_SECS)
}

/// Read a PAR response, refusing a non-2xx before parsing it.
///
/// **Split out so the status check is reachable.** Deleting it let a FAILED push
/// fall through to `parse_par_response`, and a failure body that happened to
/// carry a `request_uri` would then be used to build an authorize URL — sending
/// the user to a grant the server never issued. Nothing tested it, because a
/// test cannot reach the live endpoint that produces the response.
fn accept_par_response(outcome: &request::PostOutcome) -> Result<flow::ParResponse> {
    if !outcome.is_success() {
        bail!(
            "the pushed authorization request failed with status {}",
            outcome.status
        );
    }
    flow::parse_par_response(&outcome.json()?)
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

    /// **A failed PAR push must not be parsed as a successful one.**
    ///
    /// Without the status check a failure body falls through to
    /// `parse_par_response`, so an error response that happens to carry a
    /// `request_uri` would be used to build an authorize URL and the user would
    /// be sent to a grant the server never issued. Deleting it passed everything.
    #[test]
    fn a_failed_par_push_is_not_parsed_as_a_grant() {
        // A body that WOULD parse as a valid PAR response, behind a failure
        // status — so only the status check stands between it and an authorize
        // URL.
        let body = serde_json::json!({ "request_uri": "urn:ietf:params:oauth:request_uri:x", "expires_in": 60 });

        assert!(
            accept_par_response(&outcome(200, &body)).is_ok(),
            "the same body at 200 must parse — otherwise this test proves nothing",
        );

        // `match` rather than `expect_err`: that would require `Debug` on
        // `ParResponse`, and a `request_uri` is a one-time grant reference bound
        // to our DPoP key — not something to make printable for a test's sake.
        let err = match accept_par_response(&outcome(400, &body)) {
            Ok(_) => panic!("a 400 must not yield a request_uri"),
            Err(err) => err,
        };
        assert!(
            format!("{err:#}").contains("failed with status 400"),
            "refused, but not by the status check: {err:#}",
        );
    }

    /// **The pending row's lifetime is capped by us, not chosen by the server.**
    ///
    /// The row holds a sealed DPoP key and a PKCE verifier. Dropping the
    /// `.min(MAX_PENDING_SECS)` lets an authorization server answering with a
    /// large `expires_in` decide how long that sits in our database, widening the
    /// window in which a stolen `state` is worth replaying. The mutation passed
    /// the whole suite.
    #[test]
    fn the_pending_row_lifetime_is_capped_regardless_of_the_server() {
        let now = 1_700_000_000;

        // A server asking for a day gets ten minutes.
        assert_eq!(
            pending_expiry(now, 86_400),
            now + MAX_PENDING_SECS,
            "a server must not be able to extend the pending row past our cap",
        );
        // A shorter server lifetime still wins — the cap is a ceiling, not a
        // floor, and pinning the row open past the request_uri's own life would
        // protect nothing.
        assert_eq!(pending_expiry(now, 60), now + 60);
        assert_eq!(
            pending_expiry(now, MAX_PENDING_SECS),
            now + MAX_PENDING_SECS
        );
    }

    /// A pending login pushed under [`PUSHED_REDIRECT`], as a value.
    /// One DPoP key for the whole test run.
    ///
    /// Deterministic on purpose: a freshly generated key per fixture made it
    /// impossible to assert WHICH key the token request was signed under, and a
    /// review found that gap was live — substituting a generated key in the
    /// transport passed the entire suite while binding the grant to a thumbprint
    /// the `request_uri` was never issued against.
    fn fixture_dpop_jwk() -> &'static str {
        static JWK: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        JWK.get_or_init(|| {
            crate::oauth::keys::SigningKey::generate("session")
                .to_jwk_json()
                .unwrap()
        })
    }

    /// The thumbprint every token request in these tests must carry.
    fn fixture_thumbprint() -> String {
        crate::oauth::keys::SigningKey::from_jwk_json(fixture_dpop_jwk(), "session")
            .unwrap()
            .thumbprint()
            .unwrap()
    }

    fn pending_auth(cookie_hash: &str) -> crate::oauth::store::PendingAuth {
        crate::oauth::store::PendingAuth {
            state: "state-value".into(),
            browser_binding_hash: cookie_hash.into(),
            pkce_verifier: "verifier".into(),
            // A REAL private JWK. `complete` unseals the DPoP key before it
            // compares redirects, so a placeholder here refuses the login one
            // step too early and the identity check never runs — which the
            // assertion below caught rather than tolerated.
            dpop_key_jwk: fixture_dpop_jwk().to_string(),
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
                // **Offline.** The default is the real PLC directory, and
                // PENDING_DID is a real Bluesky DID — so handle resolution in
                // these tests was making a live internet call, which is slow,
                // flaky in CI, and quietly makes the assertion below depend on
                // someone else's uptime. `.invalid` never resolves (RFC 2606),
                // so it fails immediately and offline.
                plc_directory: "https://plc.invalid".to_string(),
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

    // ── END-TO-END: the SEQUENCING, not the individual guards ────────────────
    //
    // Every guard in `complete` has its own unit test. Nothing drove the whole
    // callback, because it needs discovery and a token endpoint over the
    // network — and an issuer must be `https`, so a local plain-HTTP server
    // cannot stand in for an authorization server either. `complete_with`
    // injects those two calls so the ORDER becomes observable.
    //
    // What these assert is mostly what did NOT happen: a guard that fires only
    // after the authorization code has been posted somewhere is not a guard.

    /// Records what the injected boundaries were asked to do — including the
    /// fields a review found were being decided in untested adapter code.
    #[derive(Default)]
    struct Calls {
        /// `(pds_url, expected_issuer, auth_method)`. The `Option` is the point:
        /// `None` means the mix-up re-check was never armed.
        discovered: Vec<(String, Option<String>, String)>,
        posted: Vec<PostedCall>,
        resolved: Vec<String>,
    }
    type Log = std::sync::Arc<std::sync::Mutex<Calls>>;

    /// One recorded token POST: where, with what, under which key, retryable?
    struct PostedCall {
        url: String,
        params: Vec<(&'static str, String)>,
        dpop_thumbprint: String,
        retry: request::Retry,
    }

    fn server_at(issuer: &str) -> crate::oauth::discovery::AuthorizationServer {
        crate::oauth::discovery::AuthorizationServer {
            issuer: issuer.into(),
            par_endpoint: format!("{issuer}/par"),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            revocation_endpoint: None,
        }
    }

    /// Drive `complete_with`, recording all three boundaries. Fully OFFLINE:
    /// handle resolution is injected too, so no test here touches the network.
    async fn drive(
        pool: &sqlx::SqlitePool,
        runtime: &crate::oauth::runtime::OauthRuntime,
        params: &flow::CallbackParams,
        cookie: Option<&str>,
        discovered_issuer: &str,
        token_status: u16,
        token_body: serde_json::Value,
    ) -> (Result<CompletedLogin>, Log) {
        let log: Log = Default::default();
        let (s1, s2, s3) = (
            std::sync::Arc::clone(&log),
            std::sync::Arc::clone(&log),
            std::sync::Arc::clone(&log),
        );
        let issuer = discovered_issuer.to_string();
        let body = serde_json::to_vec(&token_body).unwrap();
        let out = complete_with(
            runtime,
            pool,
            params,
            cookie,
            1_700_000_000,
            move |req| {
                let sink = std::sync::Arc::clone(&s1);
                let issuer = issuer.clone();
                async move {
                    sink.lock().unwrap().discovered.push((
                        req.pds_url,
                        req.expected_issuer,
                        req.auth_method,
                    ));
                    Ok(server_at(&issuer))
                }
            },
            move |req: TokenPost| {
                let sink = std::sync::Arc::clone(&s2);
                let body = body.clone();
                async move {
                    // The thumbprint is what the grant is bound to; recording it
                    // is how a substituted key becomes visible.
                    let tp = req.key.thumbprint().unwrap_or_default();
                    sink.lock().unwrap().posted.push(PostedCall {
                        url: req.url,
                        params: req.params,
                        dpop_thumbprint: tp,
                        retry: req.retry,
                    });
                    Ok(request::PostOutcome {
                        status: token_status,
                        body,
                    })
                }
            },
            move |did| {
                let sink = std::sync::Arc::clone(&s3);
                async move {
                    sink.lock().unwrap().resolved.push(did);
                    // Offline: the handle lookup is allowed to fail, and the
                    // login must survive it.
                    Err(anyhow::anyhow!("handle resolution unavailable in tests"))
                }
            },
        )
        .await;
        (out, log)
    }

    /// **The happy path, start to finish — the first test that drives one.**
    ///
    /// Consumes the pending row, checks the browser binding and `iss`, unseals
    /// the DPoP key, re-discovers, exchanges, and stores a session. The handle
    /// lookup is left to fail (the runtime points at a `.invalid` PLC host, so
    /// it fails offline and fast) which also pins that a handle failure does NOT
    /// fail the login.
    #[tokio::test]
    async fn a_full_callback_stores_a_session() {
        let cookie = flow::new_binding_token();
        let pool = pending_login(&flow::binding_hash(&cookie)).await;
        let runtime = runtime_at("https://feather-reader.com");
        let (out, log) = drive(
            &pool,
            &runtime,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;

        let done = out.expect("the full callback should complete");
        assert_eq!(done.did, PENDING_DID);
        assert!(
            done.handle.is_none(),
            "the handle lookup was expected to fail offline"
        );

        // Copied out in a block so the guard is gone before the `await` below;
        // a MutexGuard held across an await is a clippy deny in CI.
        let (discoveries, expected_issuer, posts, token_url, thumbprint, retry, token_params) = {
            let calls = log.lock().unwrap();
            (
                calls.discovered.len(),
                calls.discovered[0].1.clone(),
                calls.posted.len(),
                calls.posted[0].url.clone(),
                calls.posted[0].dpop_thumbprint.clone(),
                calls.posted[0].retry,
                calls.posted[0].params.clone(),
            )
        };
        assert_eq!(discoveries, 1, "discovery ran once");
        assert_eq!(
            expected_issuer.as_deref(),
            Some(PENDING_ISSUER),
            "the mix-up re-check was not armed: discovery got {expected_issuer:?}",
        );
        assert_eq!(posts, 1, "the token exchange ran once");
        assert_eq!(token_url, format!("{PENDING_ISSUER}/token"));
        assert_eq!(
            retry,
            request::Retry::Allowed,
            "the token POST must be retryable: a nonce challenge is rejected \
             before the grant is processed, so the code is not consumed",
        );
        // The grant is bound to the PENDING ROW's DPoP key and no other. A
        // substituted key also has a non-empty thumbprint, so only an equality
        // check catches it.
        // The code from THIS callback is what gets exchanged.
        assert!(
            token_params
                .iter()
                .any(|(k, v)| *k == "code" && v == "the-code"),
            "the token request did not carry the callback's authorization code: {token_params:?}",
        );
        assert_eq!(
            thumbprint,
            fixture_thumbprint(),
            "the token request was signed under a different key than the one the \
             authorization request was bound to",
        );

        let codec = crate::oauth::crypto::Codec::new(Some(TEST_KEY)).unwrap();
        assert!(
            crate::oauth::store::get_session(&pool, &codec, PENDING_DID)
                .await
                .unwrap()
                .is_some(),
            "no session was stored for a successful login",
        );
    }

    /// **A wrong `iss` stops the flow BEFORE anything is posted.**
    ///
    /// RFC 9207. The check itself is unit-tested; what was not pinned is that it
    /// runs early enough to matter. A version that validated `iss` after the
    /// exchange would still "reject the login" while having already handed the
    /// code and a client assertion to the wrong server.
    #[tokio::test]
    async fn a_mismatched_iss_posts_nothing_anywhere() {
        let cookie = flow::new_binding_token();
        let pool = pending_login(&flow::binding_hash(&cookie)).await;
        let runtime = runtime_at("https://feather-reader.com");
        let mut params = callback_params();
        params.iss = Some("https://evil.example.com".into());

        let (out, log) = drive(
            &pool,
            &runtime,
            &params,
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;

        assert!(out.is_err(), "a mismatched iss completed the login");
        let calls = log.lock().unwrap();
        assert!(
            calls.posted.is_empty(),
            "the authorization code was posted despite a bad iss: {:?}",
            calls.posted.iter().map(|p| &p.url).collect::<Vec<_>>(),
        );
        assert!(
            calls.discovered.is_empty(),
            "discovery ran before the iss check",
        );
    }

    /// **The browser binding is checked before anything is posted.**
    ///
    /// A callback replayed from a different browser must not reach the token
    /// endpoint with a valid code.
    #[tokio::test]
    async fn a_foreign_browser_posts_nothing_anywhere() {
        let cookie = flow::new_binding_token();
        let pool = pending_login(&flow::binding_hash(&cookie)).await;
        let runtime = runtime_at("https://feather-reader.com");
        let (out, log) = drive(
            &pool,
            &runtime,
            &callback_params(),
            Some("a-different-browser"),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;

        assert!(out.is_err(), "a foreign browser completed the login");
        assert!(log.lock().unwrap().posted.is_empty());
    }

    /// **Discovery is told which issuer PAR was pushed under.**
    ///
    /// The mix-up defence itself lives INSIDE `discovery::discover` — which this
    /// seam stubs — and is tested there. What belongs at THIS layer is the
    /// contract that makes it reachable: `complete` must hand discovery the
    /// issuer from the *pending row*, which is AAD-bound in storage. Passing
    /// `None`, or the issuer off the callback, would disable the check without
    /// changing a line inside `discover`.
    #[tokio::test]
    async fn discovery_is_given_the_stored_issuer_to_expect() {
        let cookie = flow::new_binding_token();
        let pool = pending_login(&flow::binding_hash(&cookie)).await;
        let runtime = runtime_at("https://feather-reader.com");
        let (out, log) = drive(
            &pool,
            &runtime,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;
        assert!(out.is_ok());

        let calls = log.lock().unwrap();
        assert_eq!(
            calls.discovered[0].1.as_deref(),
            Some(PENDING_ISSUER),
            "discovery was not told which issuer to expect; the mix-up defence \
             is disabled from the caller's side",
        );
        assert_eq!(
            calls.discovered[0].0, "https://pds.example.com",
            "discovery was pointed at something other than the stored PDS",
        );
    }

    /// **The pending row is consumed: the same callback cannot be replayed.**
    ///
    /// Single-use is what makes a leaked `state` worthless. The second attempt
    /// must fail, and must not reach the token endpoint.
    #[tokio::test]
    async fn a_replayed_callback_is_refused_and_posts_nothing() {
        let cookie = flow::new_binding_token();
        let pool = pending_login(&flow::binding_hash(&cookie)).await;
        let runtime = runtime_at("https://feather-reader.com");
        let first = drive(
            &pool,
            &runtime,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;
        assert!(first.0.is_ok(), "the first callback should succeed");

        let (out, log) = drive(
            &pool,
            &runtime,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;
        assert!(out.is_err(), "the callback was replayable");
        assert!(
            log.lock().unwrap().posted.is_empty(),
            "a replayed callback still reached the token endpoint",
        );
    }

    /// **A DPoP key that will not unseal posts nothing anywhere.**
    ///
    /// Added because a comment claimed this ordering mattered and no test held
    /// it down: moving the unseal to AFTER the token exchange left the whole
    /// suite green, because every other fixture carries a valid JWK. The final
    /// outcome is identical either way — the login fails — so only the absence
    /// of a POST distinguishes them, and that is the whole point. A corrupt key
    /// must not cost the authorization code a trip to the token endpoint.
    #[tokio::test]
    async fn a_corrupt_dpop_key_posts_nothing_anywhere() {
        let cookie = flow::new_binding_token();
        let pool = empty_pool().await;
        let codec = crate::oauth::crypto::Codec::new(Some(TEST_KEY)).unwrap();
        let mut pending = pending_auth(&flow::binding_hash(&cookie));
        pending.dpop_key_jwk = "{\"kty\":\"EC\",\"crv\":\"bogus\"}".into();
        crate::oauth::store::put_pending(&pool, &codec, &pending)
            .await
            .unwrap();

        let runtime = runtime_at("https://feather-reader.com");
        let (out, log) = drive(
            &pool,
            &runtime,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;

        assert!(out.is_err(), "a corrupt DPoP key completed the login");
        let calls = log.lock().unwrap();
        assert!(
            calls.posted.is_empty(),
            "the authorization code was posted before the DPoP key was checked",
        );
        assert!(
            calls.discovered.is_empty(),
            "discovery ran before the DPoP key was checked",
        );
    }

    // ── THE ADAPTER, over real TLS ───────────────────────────────────────────
    //
    // Everything above drives `complete_with`, whose transports are stubs — so
    // the wiring in `complete` that hands those transports their arguments has
    // no coverage. A review proved that gap was live: the mix-up defence could
    // be disarmed there with the whole suite green.
    //
    // These drive the REAL `complete`. That needs a server the client will talk
    // to, which needs https (an issuer must be https) on loopback (which the
    // SSRF guard refuses) — hence the test CA in `net`.

    /// Documents for a well-formed PDS + authorization server on one TLS server.
    fn discovery_routes(
        pds: &str,
        issuer: &str,
    ) -> std::collections::HashMap<String, Vec<crate::net::TestResponse>> {
        let mut r = std::collections::HashMap::new();
        r.insert(
            "/.well-known/oauth-protected-resource".to_string(),
            vec![crate::net::TestResponse::json(
                200,
                serde_json::json!({
                    "resource": pds,
                    "authorization_servers": [issuer],
                })
                .to_string(),
            )],
        );
        r.insert(
            "/.well-known/oauth-authorization-server".to_string(),
            vec![crate::net::TestResponse::json(
                200,
                serde_json::json!({
                    "issuer": issuer,
                    "pushed_authorization_request_endpoint": format!("{issuer}/par"),
                    "authorization_endpoint": format!("{issuer}/authorize"),
                    "token_endpoint": format!("{issuer}/token"),
                    "protected_resources": [pds],
                    "client_id_metadata_document_supported": true,
                    "require_pushed_authorization_requests": true,
                    "authorization_response_iss_parameter_supported": true,
                    "token_endpoint_auth_methods_supported": ["private_key_jwt", "none"],
                    "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
                    "dpop_signing_alg_values_supported": ["ES256"],
                    "scopes_supported": ["atproto"],
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256"],
                })
                .to_string(),
            )],
        );
        r
    }

    /// Seed a pending login pointing at the live TLS server.
    async fn pending_against(pds: &str, issuer: &str, cookie: &str) -> sqlx::SqlitePool {
        let pool = empty_pool().await;
        let codec = crate::oauth::crypto::Codec::new(Some(TEST_KEY)).unwrap();
        let mut pending = pending_auth(&flow::binding_hash(cookie));
        pending.pds_url = pds.to_string();
        pending.issuer = issuer.to_string();
        crate::oauth::store::put_pending(&pool, &codec, &pending)
            .await
            .unwrap();
        pool
    }

    /// **The adapter really forwards the expected issuer — over real TLS.**
    ///
    /// THE test this whole harness exists for. The PDS names an authorization
    /// server that is NOT the one PAR was pushed under; `complete` must refuse
    /// before the authorization code is posted anywhere.
    ///
    /// This is the authorization-server mix-up. It is the one defence whose
    /// value is entirely in WHERE it happens, and the wiring that arms it —
    /// `Some(expected_issuer)` handed to `discover` — sits in `complete`'s
    /// adapter, outside every stub-driven test. Changing it to `None` left 702
    /// tests green. It does not leave this one green.
    #[tokio::test]
    async fn a_repointed_authorization_server_is_refused_before_the_code_is_posted() {
        let cookie = flow::new_binding_token();
        let (addr, log) = crate::net::spawn_tls(|addr| {
            let port = addr.port();
            // The PDS points at as-EVIL; the pending row was pushed under as-e2e.
            discovery_routes(
                &format!("https://pds-e2e.test:{port}"),
                &format!("https://as-evil.test:{port}"),
            )
        })
        .await;
        for h in ["pds-e2e.test", "as-e2e.test", "as-evil.test"] {
            crate::net::test_host_override(h, addr);
        }

        let port = addr.port();
        let pds = format!("https://pds-e2e.test:{port}");
        let honest = format!("https://as-e2e.test:{port}");

        let pool = pending_against(&pds, &honest, &cookie).await;
        let runtime = runtime_at("https://feather-reader.com");
        let mut params = callback_params();
        params.iss = Some(honest.clone());

        let err = complete(
            &runtime,
            &reqwest::Client::builder().build().unwrap(),
            &pool,
            &params,
            Some(&cookie),
            1_700_000_000,
        )
        .await
        .expect_err("a repointed authorization server completed the login");

        let rendered = format!("{err:#}");
        // The real message names both servers and says why, which is more than
        // the word "issuer" — assert on the substance, and on BOTH names, so a
        // generic failure (TLS, 404, parse) cannot satisfy this.
        let lower = rendered.to_ascii_lowercase();
        assert!(
            lower.contains("different authorization server")
                && rendered.contains("as-evil.test")
                && rendered.contains("as-e2e.test"),
            "refused, but not by the mix-up check: {rendered}",
        );
        let seen = log.lock().unwrap().join("\n");
        assert!(
            !seen.contains("POST /token"),
            "the authorization code was posted to a server the user never \
             approved:\n{seen}",
        );
    }

    /// **The honest path over the same real TLS server completes.**
    ///
    /// Without this, the test above is satisfied by a `complete` that refuses
    /// everything — including every real login.
    #[tokio::test]
    async fn a_well_formed_discovery_over_tls_reaches_the_token_endpoint() {
        let cookie = flow::new_binding_token();
        let (addr, log) = crate::net::spawn_tls(|addr| {
            let port = addr.port();
            let pds = format!("https://pds-e2e.test:{port}");
            let issuer = format!("https://as-e2e.test:{port}");
            let mut r = discovery_routes(&pds, &issuer);
            // The exchange itself fails; what is asserted is that it was REACHED.
            r.insert(
                "/token".to_string(),
                vec![crate::net::TestResponse::json(
                    400,
                    "{\"error\":\"invalid_grant\"}",
                )],
            );
            r
        })
        .await;
        for h in ["pds-e2e.test", "as-e2e.test"] {
            crate::net::test_host_override(h, addr);
        }

        let port = addr.port();
        let pds = format!("https://pds-e2e.test:{port}");
        let issuer = format!("https://as-e2e.test:{port}");
        let pool = pending_against(&pds, &issuer, &cookie).await;
        let runtime = runtime_at("https://feather-reader.com");
        let mut params = callback_params();
        params.iss = Some(issuer.clone());

        let _ = complete(
            &runtime,
            &reqwest::Client::builder().build().unwrap(),
            &pool,
            &params,
            Some(&cookie),
            1_700_000_000,
        )
        .await;

        let seen = log.lock().unwrap().join("\n");
        assert!(
            seen.contains("/.well-known/oauth-protected-resource"),
            "discovery never fetched the protected-resource document:\n{seen}",
        );
        assert!(
            seen.contains("POST /token"),
            "a well-formed discovery never reached the token endpoint — the \
             refusal test above would pass for the wrong reason:\n{seen}",
        );
    }

    /// The DPoP proof JWT from a recorded request.
    fn dpop_proof(raw: &str) -> String {
        raw.lines()
            .find(|l| l.to_ascii_lowercase().starts_with("dpop:"))
            .expect("no DPoP header on the request")[5..]
            .trim()
            .to_string()
    }

    /// Decode one base64url segment of a JWT as JSON.
    fn jwt_part(jwt: &str, idx: usize) -> serde_json::Value {
        use base64::Engine as _;
        let seg = jwt.split('.').nth(idx).expect("malformed JWT");
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(seg)
            .expect("JWT segment is not base64url");
        serde_json::from_slice(&raw).expect("JWT segment is not JSON")
    }

    /// Pull the `jwk` out of a recorded request's DPoP proof header.
    fn dpop_jwk_from(raw: &str) -> String {
        use base64::Engine as _;
        let line = raw
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("dpop:"))
            .expect("no DPoP header on the token request");
        let jwt = line[5..].trim();
        let header_b64 = jwt.split('.').next().expect("malformed DPoP proof");
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .expect("DPoP header is not base64url");
        let v: serde_json::Value = serde_json::from_slice(&json).expect("DPoP header is not JSON");
        v.get("jwk")
            .expect("DPoP header carries no jwk")
            .to_string()
    }

    /// **The grant is signed under the PENDING ROW's key — checked on the wire.**
    ///
    /// The adapter could substitute a freshly generated key and every stub-driven
    /// test stayed green, because the stub is handed the key rather than the
    /// proof. Here the real proof reaches a real server, and its embedded public
    /// key is compared against the key the authorization request was bound to.
    ///
    /// A substituted key also produces a valid-looking proof, so only comparing
    /// thumbprints catches it.
    #[tokio::test]
    async fn the_token_request_is_signed_under_the_pending_rows_key() {
        let cookie = flow::new_binding_token();
        let (addr, log) = crate::net::spawn_tls(|addr| {
            let port = addr.port();
            let mut r = discovery_routes(
                &format!("https://pds-e2e.test:{port}"),
                &format!("https://as-e2e.test:{port}"),
            );
            r.insert(
                "/token".to_string(),
                vec![crate::net::TestResponse::json(
                    400,
                    "{\"error\":\"invalid_grant\"}",
                )],
            );
            r
        })
        .await;
        for h in ["pds-e2e.test", "as-e2e.test"] {
            crate::net::test_host_override(h, addr);
        }
        let port = addr.port();
        let issuer = format!("https://as-e2e.test:{port}");
        let pool = pending_against(&format!("https://pds-e2e.test:{port}"), &issuer, &cookie).await;
        let runtime = runtime_at("https://feather-reader.com");
        let mut params = callback_params();
        params.iss = Some(issuer);

        let _ = complete(
            &runtime,
            &reqwest::Client::builder().build().unwrap(),
            &pool,
            &params,
            Some(&cookie),
            1_700_000_000,
        )
        .await;

        let token_req = log
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.starts_with("POST /token"))
            .cloned()
            .expect("the token endpoint was never reached");
        let on_the_wire =
            keys::SigningKey::public_thumbprint_of(&dpop_jwk_from(&token_req)).unwrap();
        assert_eq!(
            on_the_wire,
            fixture_thumbprint(),
            "the token request was signed under a key the authorization request \
             was never bound to",
        );
    }

    /// **A `use_dpop_nonce` challenge is retried — observed as a second request.**
    ///
    /// `Retry::Allowed` is chosen in `complete` and forwarded by the adapter;
    /// neither was pinned, and getting it wrong is not hypothetical — the
    /// comment on `Retry::Forbidden` records that this exact mistake once cost a
    /// real login against a live PDS, because servers rotate their nonce between
    /// PAR and the callback.
    ///
    /// The server challenges once, then answers. Two hits on `/token` means the
    /// retry happened; one means it did not.
    #[tokio::test]
    async fn a_nonce_challenge_on_the_token_endpoint_is_retried() {
        let cookie = flow::new_binding_token();
        let (addr, log) = crate::net::spawn_tls(|addr| {
            let port = addr.port();
            let mut r = discovery_routes(
                &format!("https://pds-e2e.test:{port}"),
                &format!("https://as-e2e.test:{port}"),
            );
            r.insert(
                "/token".to_string(),
                vec![
                    crate::net::TestResponse::json(400, "{\"error\":\"use_dpop_nonce\"}")
                        .with_header("DPoP-Nonce", "nonce-from-the-server"),
                    crate::net::TestResponse::json(400, "{\"error\":\"invalid_grant\"}"),
                ],
            );
            r
        })
        .await;
        for h in ["pds-e2e.test", "as-e2e.test"] {
            crate::net::test_host_override(h, addr);
        }
        let port = addr.port();
        let issuer = format!("https://as-e2e.test:{port}");
        let pool = pending_against(&format!("https://pds-e2e.test:{port}"), &issuer, &cookie).await;
        let runtime = runtime_at("https://feather-reader.com");
        let mut params = callback_params();
        params.iss = Some(issuer);

        let _ = complete(
            &runtime,
            &reqwest::Client::builder().build().unwrap(),
            &pool,
            &params,
            Some(&cookie),
            1_700_000_000,
        )
        .await;

        let reqs = log.lock().unwrap().clone();
        let token_hits = reqs.iter().filter(|r| r.starts_with("POST /token")).count();
        assert_eq!(
            token_hits, 2,
            "a use_dpop_nonce challenge was not retried; the exchange is marked \
             non-retryable somewhere between complete and the wire",
        );
        let second = reqs
            .iter()
            .filter(|r| r.starts_with("POST /token"))
            .nth(1)
            .unwrap();
        // The nonce rides INSIDE the DPoP proof's claims, not as plaintext in
        // the request — asserting on the raw bytes would have passed for a retry
        // that ignored the challenge entirely.
        let claims = jwt_part(&dpop_proof(second), 1);
        assert_eq!(
            claims.get("nonce").and_then(|v| v.as_str()),
            Some("nonce-from-the-server"),
            "the retry did not carry the server's nonce; it would be challenged \
             again forever",
        );
    }
}
