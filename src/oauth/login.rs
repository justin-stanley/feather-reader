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
    start_with(
        runtime,
        pool,
        subject,
        now,
        |subject| async move {
            super::resolve::resolve(&runtime.resolver, http, &subject, &runtime.plc_directory).await
        },
        |pds_url, auth_method, expected_issuer| async move {
            discovery::discover(http, &pds_url, auth_method, expected_issuer.as_deref()).await
        },
        |req: ParPost| async move {
            post_form(http, pool, &req.url, &req.key, &req.params, req.retry).await
        },
    )
    .await
}

/// What [`start_with`] hands its PAR transport: a fully-formed request.
///
/// Mirrors [`TokenPost`] deliberately, and for the same reason it exists — a
/// transport that receives ingredients instead of a request lets the decision
/// be wrong where no test can see it.
struct ParPost {
    url: String,
    params: Vec<(&'static str, String)>,
    /// The ACTUAL key the push is signed under, so a test can compare its
    /// thumbprint against the one the pending row stores. Passing a JWK string
    /// and re-parsing it inside the adapter would let a freshly generated key
    /// be accepted — the authorization server binds `request_uri` to this
    /// key's thumbprint, so a different one stored means every login fails at
    /// the token endpoint with a binding error nothing explains.
    key: std::sync::Arc<keys::SigningKey>,
    retry: request::Retry,
}

/// [`start`] with its three network boundaries injected.
///
/// **Nothing drove `start` at all.** Every guard in `complete` had a test and
/// the whole callback got one; this half had neither, because it needs handle
/// resolution, discovery and a PAR endpoint, all over the network. Five
/// decisions made here were therefore unfalsifiable, and each is a silent
/// production failure rather than a loud one:
///
/// - `client_id` — PAR pushed under a foreign client identity
/// - `code_challenge` — derived from a different verifier than the one stored,
///   so PKCE fails at the exchange
/// - the assertion's audience — RFC 7523 requires the issuer, not the PDS
/// - `browser_binding_hash` — hashing a token other than the one returned
///   defeats the login-CSRF binding
/// - `dpop_key_jwk` — storing a key other than the one PAR was signed under
///
/// **Every decision lives here, not in the caller's closures**, which is the
/// lesson a review of `complete_with`'s first cut paid for: arguments assembled
/// inside an adapter are invisible to a test, so they can be wrong with the
/// suite green. The transports receive fully-formed values.
#[allow(clippy::too_many_arguments)]
async fn start_with<R, RFut, D, DFut, P, PFut>(
    runtime: &OauthRuntime,
    pool: &sqlx::SqlitePool,
    subject: &str,
    now: i64,
    resolve: R,
    discover: D,
    push: P,
) -> Result<StartedLogin>
where
    R: FnOnce(String) -> RFut,
    RFut: std::future::Future<Output = Result<super::resolve::ResolvedAccount>>,
    D: FnOnce(String, &'static str, Option<String>) -> DFut,
    DFut: std::future::Future<Output = Result<discovery::AuthorizationServer>>,
    P: FnOnce(ParPost) -> PFut,
    PFut: std::future::Future<Output = Result<request::PostOutcome>>,
{
    let account = resolve(subject.to_string())
        .await
        .with_context(|| format!("resolving {subject:?}"))?;

    // No prior issuer: this IS the login that establishes one. Passed
    // explicitly so the `None` is visible to a test rather than buried in an
    // adapter — the mix-up re-check on the callback side is armed by the
    // mirror-image argument, and that one was wrong in review.
    let server = discover(account.pds_url.clone(), runtime.auth_method.as_str(), None)
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

    // `Arc` so the transport can be handed the real key rather than a recipe
    // for one, while `put_pending` below still stores from the same value.
    let session_key = std::sync::Arc::new(session_key);
    let outcome = push(ParPost {
        url: server.par_endpoint.clone(),
        params,
        key: std::sync::Arc::clone(&session_key),
        // PAR is safe to repeat: a rejected attempt consumes nothing.
        retry: request::Retry::Allowed,
    })
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

    // ── `start`: the half that had no test at all ───────────────────────────

    const START_PDS: &str = "https://pds.example.com";
    const START_ISSUER: &str = "https://auth.example.com";

    fn started_account() -> crate::oauth::resolve::ResolvedAccount {
        crate::oauth::resolve::ResolvedAccount {
            did: PENDING_DID.into(),
            pds_url: START_PDS.into(),
            handle: Some("alice.example.com".into()),
        }
    }

    fn started_server() -> discovery::AuthorizationServer {
        discovery::AuthorizationServer {
            issuer: START_ISSUER.into(),
            par_endpoint: format!("{START_ISSUER}/par"),
            authorization_endpoint: format!("{START_ISSUER}/authorize"),
            token_endpoint: format!("{START_ISSUER}/token"),
            revocation_endpoint: None,
        }
    }

    fn par_ok() -> request::PostOutcome {
        request::PostOutcome {
            status: 201,
            body: br#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}"#
                .to_vec(),
        }
    }

    /// Drive `start_with` against a CHOSEN authorization server and PAR
    /// response, capturing the request it pushed.
    ///
    /// [`run_start`] is this with a well-behaved counterparty. The adversarial
    /// tests vary the two, because everything `start` consumes after the push
    /// is bytes from a remote party: the tests above prove `start` says the
    /// right things, and these prove it survives being lied to.
    async fn run_start_against(
        runtime: &crate::oauth::runtime::OauthRuntime,
        pool: &sqlx::SqlitePool,
        now: i64,
        server: discovery::AuthorizationServer,
        par: request::PostOutcome,
    ) -> (
        Result<StartedLogin>,
        std::sync::Arc<std::sync::Mutex<Vec<ParPost>>>,
    ) {
        let pushed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&pushed);
        let r = start_with(
            runtime,
            pool,
            "alice.example.com",
            now,
            |_subject| async move { Ok(started_account()) },
            move |_pds, _method, expected| async move {
                // The mirror image of the callback's mix-up re-check: this side
                // must pass `None`, because this IS the login that establishes
                // the issuer. Asserted here so a `Some(..)` cannot creep in.
                assert!(
                    expected.is_none(),
                    "the initial push must not claim a prior issuer, got {expected:?}"
                );
                Ok(server)
            },
            move |req: ParPost| {
                let sink = std::sync::Arc::clone(&sink);
                async move {
                    sink.lock().unwrap().push(req);
                    Ok(par)
                }
            },
        )
        .await;
        (r, pushed)
    }

    /// Drive `start_with` against a well-behaved counterparty.
    async fn run_start(
        runtime: &crate::oauth::runtime::OauthRuntime,
        pool: &sqlx::SqlitePool,
        now: i64,
    ) -> (
        Result<StartedLogin>,
        std::sync::Arc<std::sync::Mutex<Vec<ParPost>>>,
    ) {
        run_start_against(runtime, pool, now, started_server(), par_ok()).await
    }

    /// A PAR response with a chosen status and raw body.
    fn par_body(status: u16, body: &str) -> request::PostOutcome {
        request::PostOutcome {
            status,
            body: body.as_bytes().to_vec(),
        }
    }

    /// The `state` the push carried — the key the pending row is stored under,
    /// so a test can ask whether one exists without knowing it in advance.
    fn pushed_state(captured: &std::sync::Mutex<Vec<ParPost>>) -> String {
        let c = captured.lock().unwrap();
        assert_eq!(c.len(), 1, "PAR must be pushed exactly once");
        param(&c[0].params, "state")
            .expect("state in the push")
            .to_string()
    }

    /// Assert the login failed AND left no pending row behind.
    ///
    /// Both halves matter. A row written for a grant the server never issued
    /// strands a sealed DPoP key and PKCE verifier in the database, and the
    /// error alone does not prove one was not written.
    async fn assert_refused_without_storing(
        pool: &sqlx::SqlitePool,
        runtime: &crate::oauth::runtime::OauthRuntime,
        now: i64,
        started: Result<StartedLogin>,
        captured: &std::sync::Mutex<Vec<ParPost>>,
        what: &str,
    ) -> Result<()> {
        assert!(started.is_err(), "{what} must fail the login");
        let state = pushed_state(captured);
        assert!(
            crate::oauth::store::take_pending(pool, &runtime.codec, &state, now)
                .await?
                .is_none(),
            "{what} left a pending row behind",
        );
        Ok(())
    }

    fn param<'a>(params: &'a [(&'static str, String)], k: &str) -> Option<&'a str> {
        params
            .iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| v.as_str())
    }

    /// **The PAR push carries this client's identity, and the pending row is
    /// written from the same values.**
    ///
    /// Five decisions in `start` were unfalsifiable before this test existed —
    /// see `start_with`. Each is silent in production: the login simply fails
    /// later, at the authorization server, for a reason nothing local explains.
    #[tokio::test]
    async fn a_start_pushes_this_clients_identity_and_stores_what_it_pushed() -> Result<()> {
        let pool = empty_pool().await;
        let runtime = runtime_at("https://app.example.com");
        let now = 1_700_000_000;

        let (started, pushed) = run_start(&runtime, &pool, now).await;
        let started = started?;
        // Copy what the assertions need and DROP the guard: everything below
        // awaits, and holding a `std::sync::MutexGuard` across an await point
        // is a deadlock waiting for a multi-threaded runtime (clippy's
        // `await_holding_lock`, which CI treats as an error).
        let (url, params, pushed_key_jwk, retry_allowed) = {
            let pushed = pushed.lock().unwrap();
            assert_eq!(pushed.len(), 1, "PAR must be pushed exactly once");
            let r = &pushed[0];
            (
                r.url.clone(),
                r.params.clone(),
                r.key.to_jwk_json()?,
                matches!(r.retry, request::Retry::Allowed),
            )
        };
        let req = &params;

        assert_eq!(url, format!("{START_ISSUER}/par"), "wrong PAR endpoint");
        assert_eq!(
            param(req, "client_id"),
            Some(runtime.client_id.as_str()),
            "PAR was pushed under a client_id that is not ours",
        );
        assert_eq!(
            param(req, "redirect_uri"),
            Some(crate::oauth::metadata::redirect_uri(&runtime.client).as_str()),
        );
        assert!(
            retry_allowed,
            "PAR consumes nothing on rejection and must stay retryable",
        );

        // **The client assertion is addressed to the AUTHORIZATION SERVER.**
        //
        // RFC 7523 §3: `aud` is the server the assertion is presented to, and
        // `iss` = `sub` = the client. Pointing `aud` at the PDS instead — the
        // other URL in scope here, one line away in this function — survived
        // every other assertion in this test, because nothing looked inside the
        // JWT. A wrong audience is rejected by the server as an invalid client
        // assertion, so the login fails with nothing local explaining why.
        let assertion = param(req, "client_assertion").expect("a client assertion");
        let claims: serde_json::Value = {
            use base64::Engine as _;
            let payload = assertion.split('.').nth(1).expect("a JWT payload segment");
            serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(payload)
                    .expect("the payload must be base64url"),
            )
            .expect("the payload must be JSON")
        };
        assert_eq!(
            claims["aud"].as_str(),
            Some(START_ISSUER),
            "the client assertion is addressed to the wrong audience: {claims}",
        );
        assert_eq!(
            claims["iss"].as_str(),
            Some(runtime.client_id.as_str()),
            "the client assertion's issuer is not this client",
        );
        assert_eq!(
            claims["sub"].as_str(),
            Some(runtime.client_id.as_str()),
            "the client assertion's subject is not this client",
        );
        assert_eq!(
            claims["iat"].as_i64(),
            Some(now),
            "iat is not the passed now"
        );
        assert!(
            claims["exp"]
                .as_i64()
                .is_some_and(|e| e > now && e <= now + 300),
            "exp must be ahead of iat and short-lived: {claims}",
        );

        // The row `complete` will read back.
        let pending = crate::oauth::store::take_pending(
            &pool,
            &runtime.codec,
            param(req, "state").expect("state in the push"),
            now,
        )
        .await?
        .expect("the pending row must exist");

        // **PKCE: the challenge pushed must derive from the verifier stored.**
        // A fresh verifier on either side compiles and fails only at the
        // exchange, with `invalid_grant` and nothing pointing here.
        assert_eq!(
            param(req, "code_challenge"),
            Some(flow::pkce_challenge(&pending.pkce_verifier).as_str()),
            "the pushed PKCE challenge does not match the stored verifier",
        );

        // **DPoP: the key stored must be the key the push was signed under.**
        // The authorization server binds `request_uri` to this thumbprint.
        assert_eq!(
            pending.dpop_key_jwk, pushed_key_jwk,
            "the pending row stores a different DPoP key than PAR was signed under",
        );

        // **Browser binding: the hash stored must be of the token returned.**
        // Hashing anything else leaves the cookie check unable to match, which
        // is a login-CSRF defence that silently never fires.
        assert_eq!(
            pending.browser_binding_hash,
            flow::binding_hash(&started.binding_token),
            "the stored binding hash is not of the token handed to the browser",
        );

        assert_eq!(pending.issuer, START_ISSUER);
        assert_eq!(pending.pds_url, START_PDS);
        assert_eq!(pending.did, PENDING_DID);
        assert_eq!(pending.request_uri, "urn:ietf:params:oauth:request_uri:abc");
        assert_eq!(
            pending.redirect_uri,
            crate::oauth::metadata::redirect_uri(&runtime.client)
        );
        assert_eq!(pending.requested_scope, runtime.client.scope_str());

        // The browser is sent to the discovered endpoint, carrying the
        // request_uri the server just issued.
        assert!(
            started
                .authorize_url
                .starts_with(&format!("{START_ISSUER}/authorize")),
            "authorize_url does not point at the discovered endpoint: {}",
            started.authorize_url,
        );
        assert!(
            started
                .authorize_url
                .contains("urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc")
                || started
                    .authorize_url
                    .contains("request_uri=urn:ietf:params:oauth:request_uri:abc"),
            "authorize_url does not carry the issued request_uri: {}",
            started.authorize_url,
        );
        Ok(())
    }

    /// **A failed PAR push stores nothing.**
    ///
    /// A pending row written before the server accepted would leave a sealed
    /// DPoP key and PKCE verifier for a grant that does not exist, and the
    /// row's expiry is derived from the PAR response.
    #[tokio::test]
    async fn a_rejected_par_push_stores_no_pending_row() -> Result<()> {
        let pool = empty_pool().await;
        let runtime = runtime_at("https://app.example.com");

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&captured);
        let r = start_with(
            &runtime,
            &pool,
            "alice.example.com",
            1_700_000_000,
            |_s| async move { Ok(started_account()) },
            |_p, _m, _e| async move { Ok(started_server()) },
            move |req: ParPost| {
                let sink = std::sync::Arc::clone(&sink);
                async move {
                    sink.lock().unwrap().push(req);
                    Ok(request::PostOutcome {
                        status: 400,
                        body: br#"{"error":"invalid_request"}"#.to_vec(),
                    })
                }
            },
        )
        .await;

        assert!(r.is_err(), "a 400 from PAR must fail the login");
        let state = {
            let c = captured.lock().unwrap();
            param(&c[0].params, "state").expect("state").to_string()
        };
        assert!(
            crate::oauth::store::take_pending(&pool, &runtime.codec, &state, 1_700_000_000)
                .await?
                .is_none(),
            "a rejected push left a pending row behind",
        );
        Ok(())
    }

    // ── `start` against a hostile counterparty ──────────────────────────────
    //
    // Everything `start` consumes after the push is bytes chosen by a remote
    // party. The tests above drive a cooperative server and prove `start` says
    // the right things; these drive a lying one and prove what it refuses.

    /// **A `request_uri` cannot smuggle extra parameters into the authorize
    /// URL.**
    ///
    /// This value is the one place in `start` where a remote party's bytes are
    /// echoed into a URL we hand the user's browser. Built by string formatting
    /// rather than a query serializer, a `request_uri` carrying
    /// `&redirect_uri=…` appends a SECOND `redirect_uri` to the authorization
    /// request — the classic parameter-injection shape, and on this endpoint it
    /// is an attempt to redirect the grant somewhere the client never
    /// registered.
    #[tokio::test]
    async fn a_hostile_request_uri_cannot_smuggle_parameters_into_the_authorize_url() -> Result<()>
    {
        const SMUGGLED: &str =
            "urn:ietf:params:oauth:request_uri:abc&redirect_uri=https://evil.example.com";
        let pool = empty_pool().await;
        let runtime = runtime_at("https://app.example.com");
        let body = serde_json::json!({ "request_uri": SMUGGLED, "expires_in": 60 });
        let (started, _) = run_start_against(
            &runtime,
            &pool,
            1_700_000_000,
            started_server(),
            par_body(201, &body.to_string()),
        )
        .await;

        let url = url::Url::parse(&started?.authorize_url)?;
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            pairs.len(),
            2,
            "the authorize URL gained a parameter from the server's bytes: {pairs:?}",
        );
        assert_eq!(
            pairs
                .iter()
                .find(|(k, _)| k == "request_uri")
                .map(|(_, v)| v.as_str()),
            Some(SMUGGLED),
            "the request_uri must survive as ONE opaque value, not be split",
        );
        assert!(
            !pairs.iter().any(|(k, _)| k == "redirect_uri"),
            "a redirect_uri was smuggled into the authorize URL: {pairs:?}",
        );
        Ok(())
    }

    /// **A 2xx that is not a grant stores nothing.**
    ///
    /// `a_rejected_par_push_stores_no_pending_row` covers a 400. A server that
    /// answers 200 with an error body gets PAST the status check and reaches
    /// the parser — a different path, and the one a misbehaving (rather than
    /// refusing) server takes.
    #[tokio::test]
    async fn a_par_success_carrying_no_grant_stores_nothing() -> Result<()> {
        let pool = empty_pool().await;
        let runtime = runtime_at("https://app.example.com");
        let now = 1_700_000_000;
        let (started, captured) = run_start_against(
            &runtime,
            &pool,
            now,
            started_server(),
            par_body(200, r#"{"error":"invalid_request"}"#),
        )
        .await;
        assert_refused_without_storing(
            &pool,
            &runtime,
            now,
            started,
            &captured,
            "a 200 with no request_uri",
        )
        .await
    }

    /// **A body that is not JSON at all stores nothing.**
    ///
    /// An HTML error page from a proxy in front of the authorization server is
    /// the realistic shape here, and it arrives with a 200.
    #[tokio::test]
    async fn a_par_response_that_is_not_json_stores_nothing() -> Result<()> {
        let pool = empty_pool().await;
        let runtime = runtime_at("https://app.example.com");
        let now = 1_700_000_000;
        let (started, captured) = run_start_against(
            &runtime,
            &pool,
            now,
            started_server(),
            par_body(200, "<html><body>502 Bad Gateway</body></html>"),
        )
        .await;
        assert_refused_without_storing(
            &pool,
            &runtime,
            now,
            started,
            &captured,
            "a non-JSON PAR body",
        )
        .await
    }

    /// **A non-positive `expires_in` is refused rather than stored.**
    ///
    /// Stored as given, a zero or negative lifetime writes a row that is
    /// already expired — the login cannot be completed and the failure surfaces
    /// at the callback as a missing state, which reads like a browser problem
    /// rather than a server one.
    #[tokio::test]
    async fn a_non_positive_par_lifetime_is_refused_rather_than_stored() -> Result<()> {
        let runtime = runtime_at("https://app.example.com");
        let now = 1_700_000_000;
        for expires_in in ["0", "-1"] {
            let pool = empty_pool().await;
            let body = format!(
                r#"{{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":{expires_in}}}"#
            );
            let (started, captured) =
                run_start_against(&runtime, &pool, now, started_server(), par_body(201, &body))
                    .await;
            assert_refused_without_storing(
                &pool,
                &runtime,
                now,
                started,
                &captured,
                &format!("expires_in={expires_in}"),
            )
            .await?;
        }
        Ok(())
    }

    /// **A server cannot pin a pending login open beyond our own cap.**
    ///
    /// The row holds a sealed DPoP key and PKCE verifier. An authorization
    /// server answering `expires_in: 10^9` would otherwise keep that material
    /// alive for thirty years, and the lifetime of our secrets is not the
    /// counterparty's to choose. `pending_expiry` has a unit test; this is the
    /// one that proves `start` actually routes the server's number through it.
    #[tokio::test]
    async fn a_server_cannot_pin_a_pending_login_beyond_the_cap() -> Result<()> {
        let pool = empty_pool().await;
        let runtime = runtime_at("https://app.example.com");
        let now = 1_700_000_000;
        let (started, captured) = run_start_against(
            &runtime,
            &pool,
            now,
            started_server(),
            par_body(
                201,
                r#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":1000000000}"#,
            ),
        )
        .await;
        started?;

        let state = pushed_state(&captured);
        let pending = crate::oauth::store::take_pending(&pool, &runtime.codec, &state, now)
            .await?
            .expect("the pending row must exist");
        assert_eq!(
            pending.expires_at,
            now + MAX_PENDING_SECS,
            "the server's lifetime was accepted instead of our cap",
        );
        Ok(())
    }

    /// **A non-https authorization endpoint fails the login.**
    ///
    /// `discovery` already requires https on every endpoint it returns, so this
    /// is the second layer rather than the first — it holds even if a future
    /// change to discovery, or a different path into `start_with`, hands one
    /// through. Downgrading this URL puts the authorization request, and the
    /// user's credentials at the other end of it, on the wire in clear.
    #[tokio::test]
    async fn a_non_https_authorization_endpoint_fails_the_login() -> Result<()> {
        let pool = empty_pool().await;
        let runtime = runtime_at("https://app.example.com");
        let downgraded = discovery::AuthorizationServer {
            authorization_endpoint: "http://auth.example.com/authorize".into(),
            ..started_server()
        };
        let (started, _) = run_start_against(
            &runtime,
            &pool,
            1_700_000_000,
            downgraded,
            par_body(
                201,
                r#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}"#,
            ),
        )
        .await;
        // Destructured rather than `expect_err`, which would need
        // `StartedLogin: Debug` — and that type holds `binding_token`. It is
        // deliberately not `Debug`, so a panic message can never print it.
        let Err(err) = started else {
            panic!("an http authorization endpoint must fail the login")
        };
        assert!(
            format!("{err:#}").contains("https"),
            "the failure should name the scheme, got: {err:#}",
        );
        Ok(())
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
