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

    let server = discovery::discover(http, &account.pds_url, runtime.auth_method.as_str())
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

    let server = discovery::discover(http, &pending.pds_url, auth_method.as_str()).await?;

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
    // Shared with the refresh path so the two cannot disagree about what
    // "same authorization server" means, and so it is testable — see
    // `session::same_issuer`.
    super::session::same_issuer(&server.issuer, &pending.issuer)?;
    let mut token_params =
        token::token_request_params(&code, &pending.redirect_uri, &pending.pkce_verifier);
    let assertion = client_assertion(runtime, auth_method, &pending.issuer, now)?;
    token_params.extend(client_auth::credential_params(
        auth_method,
        &runtime.client_id,
        assertion.as_deref(),
    )?);

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
        &runtime.codec,
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

    // The handle is resolved from the DID rather than remembered from the login
    // form: what the user typed is not evidence, and `resolve` returns `None`
    // unless it round-trips. A failure here must not fail the login — the
    // account is already authenticated, and the handle is a display detail.
    let handle = match super::resolve::resolve(
        &runtime.resolver,
        http,
        &tokens.sub,
        &runtime.plc_directory,
    )
    .await
    {
        Ok(account) => account.handle,
        Err(err) => {
            tracing::warn!(%err, did = %tokens.sub, "could not resolve a handle for the new session");
            None
        }
    };

    Ok(CompletedLogin {
        did: tokens.sub,
        handle,
    })
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
