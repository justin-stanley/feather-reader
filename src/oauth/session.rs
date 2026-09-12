//! Holding a session valid: refresh-on-read, rotation, and what a failure means.
//!
//! Three things here are easy to get wrong and all three present as *random*
//! logouts rather than as a bug:
//!
//! * **Refresh tokens rotate and are single-use.** The new one must be stored
//!   atomically with the new access token, and a response that omits it means
//!   keep the old one — not store an empty string.
//! * **Concurrent refreshes must be serialized.** Two readers of the same
//!   session both presenting the same single-use token means the second gets
//!   `invalid_grant`, and most authorization servers revoke the first one's
//!   freshly issued tokens along with it. The scheduler plus one user request is
//!   already enough concurrency.
//! * **Only `invalid_grant` invalidates.** Deleting on a network blip or a 5xx
//!   logs people out for a server hiccup; treating a dead grant as transient
//!   retries forever and never prompts a re-login.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use super::store::OAuthSession;
use super::token::TokenResponse;

/// Fold a refresh response into the stored session.
///
/// Pure, so the rotation rules are testable without a server — which matters,
/// because every one of them fails as a mysterious logout rather than as an
/// error anyone can trace.
pub fn apply_refresh(
    session: &OAuthSession,
    response: &TokenResponse,
    now: i64,
) -> Result<OAuthSession> {
    // A refresh must never be able to move a session to another account.
    if response.sub != session.sub {
        bail!(
            "refresh returned subject {:?}, expected {:?}; refusing to rebind the session",
            response.sub,
            session.sub
        );
    }

    Ok(OAuthSession {
        access_token: response.access_token.clone(),
        // Rotation is expected but not guaranteed. Storing an empty string when
        // the server omits it would destroy the session on the next refresh,
        // with nothing to indicate why.
        refresh_token: response
            .refresh_token
            .clone()
            .unwrap_or_else(|| session.refresh_token.clone()),
        token_type: response.token_type.clone(),
        // The GRANTED scope, which the server may have narrowed. Keeping the old
        // value would make later write failures unexplainable.
        granted_scope: response.granted_scope.clone(),
        expires_at: response.expires_in.map(|seconds| now + seconds),
        // Properties of the session, not of any one token response.
        sub: session.sub.clone(),
        issuer: session.issuer.clone(),
        aud: session.aud.clone(),
        dpop_key_jwk: session.dpop_key_jwk.clone(),
    })
}

/// Per-subject refresh locks.
///
/// Two concurrent refreshes of one session both present the same single-use
/// refresh token; the loser gets `invalid_grant`, and most authorization servers
/// revoke the winner's freshly issued tokens along with it. The symptom is
/// random, unreproducible logouts. The scheduler plus a single user request is
/// already enough concurrency to hit this.
///
/// **In-process only.** A second process — the invite bot, a rolling deploy —
/// is not covered, which is why the refresh path also re-reads the stored
/// session on `invalid_grant` before concluding the grant is dead.
#[derive(Default, Clone)]
pub struct RefreshLocks {
    locks: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

impl RefreshLocks {
    /// Acquire the lock for one subject. Unrelated subjects never contend.
    pub async fn lock(&self, sub: &str) -> OwnedMutexGuard<()> {
        let entry = {
            let mut locks = self.locks.lock().expect("refresh lock map poisoned");
            Arc::clone(locks.entry(sub.to_string()).or_default())
        };
        entry.lock_owned().await
    }
}

/// What a refresh needs beyond the session itself.
pub struct RefreshContext<'a> {
    pub token_endpoint: &'a str,
    pub client_id: &'a str,
    pub auth_method: super::client_auth::AuthMethod,
    /// The confidential client's signing key. Required for `private_key_jwt`,
    /// unused by the localhost dev client.
    pub client_key: Option<&'a super::keys::SigningKey>,
}

/// Read a session, refreshing it first if it is close to expiry.
///
/// **Do not wrap this in a timeout.** Once the refresh request is in flight the
/// authorization server has consumed the single-use refresh token; abandoning
/// the future means the replacement is never stored and the session is dead.
/// The reference carries the same warning for the same reason.
pub async fn valid_session(
    pool: &sqlx::SqlitePool,
    codec: &super::crypto::Codec,
    http: &reqwest::Client,
    locks: &RefreshLocks,
    sub: &str,
    ctx: &RefreshContext<'_>,
    now: i64,
) -> Result<OAuthSession> {
    let session = super::store::get_session(pool, codec, sub)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no session for {sub}"))?;
    if !super::token::is_stale(session.expires_at, now) {
        return Ok(session);
    }

    let _guard = locks.lock(sub).await;

    // Re-read AFTER acquiring the lock: whoever held it may have refreshed while
    // we waited, and presenting the token they just replaced would burn it.
    let session = super::store::get_session(pool, codec, sub)
        .await?
        .ok_or_else(|| anyhow::anyhow!("session for {sub} disappeared while waiting to refresh"))?;
    if !super::token::is_stale(session.expires_at, now) {
        return Ok(session);
    }

    refresh_locked(pool, codec, http, &session, ctx, now).await
}

/// The refresh itself. Called with the subject's lock held.
async fn refresh_locked(
    pool: &sqlx::SqlitePool,
    codec: &super::crypto::Codec,
    http: &reqwest::Client,
    session: &OAuthSession,
    ctx: &RefreshContext<'_>,
    now: i64,
) -> Result<OAuthSession> {
    let key = super::keys::SigningKey::from_jwk_json(&session.dpop_key_jwk, "session-dpop")?;

    let assertion = match ctx.auth_method {
        super::client_auth::AuthMethod::PrivateKeyJwt => {
            let client_key = ctx
                .client_key
                .ok_or_else(|| anyhow::anyhow!("private_key_jwt refresh needs the client key"))?;
            Some(super::client_auth::client_assertion(
                client_key,
                ctx.client_id,
                &session.issuer,
                now,
            )?)
        }
        super::client_auth::AuthMethod::None => None,
    };

    let mut params = super::token::refresh_request_params(&session.refresh_token);
    params.extend(super::client_auth::credential_params(
        ctx.auth_method,
        ctx.client_id,
        assertion.as_deref(),
    )?);
    let borrowed: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let outcome = super::request::send_with_dpop(
        http,
        pool,
        &super::request::DpopRequest {
            endpoint: super::dpop::Endpoint::AuthorizationServer,
            url: ctx.token_endpoint,
            key: &key,
            access_token: None,
            body: super::request::DpopBody::Form(&borrowed),
            // A refresh is safe to repeat on a nonce challenge: unlike the code
            // exchange, a rejected attempt consumes nothing.
            retry: super::request::Retry::Allowed,
        },
    )
    .await?;

    if outcome.is_success() {
        let response = super::token::parse_token_response(&outcome.json()?)?;
        let updated = apply_refresh(session, &response, now)?;
        super::store::put_session(pool, codec, &updated).await?;
        return Ok(updated);
    }

    match super::token::classify_refresh_failure(outcome.status, &outcome.body) {
        super::token::RefreshFailure::Transient => {
            // Network, 5xx, anything unrecognised: leave the stored tokens
            // exactly as they are and fail THIS request. Deleting here would log
            // someone out for a server hiccup.
            bail!(
                "refresh for {} failed transiently (status {}); the session is left intact",
                session.sub,
                outcome.status
            )
        }
        super::token::RefreshFailure::SessionInvalid => {
            // Before concluding the grant is dead, check whether another PROCESS
            // refreshed it while we held only an in-process lock. If the stored
            // refresh token has changed, ours was simply stale and theirs is
            // live — use it rather than deleting a working session.
            if let Some(current) = super::store::get_session(pool, codec, &session.sub).await? {
                if current.refresh_token != session.refresh_token {
                    return Ok(current);
                }
            }
            super::store::delete_session(pool, &session.sub).await?;
            bail!(
                "refresh for {} was rejected as invalid_grant; the session has been \
                 removed and the user must log in again",
                session.sub
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    const NOW: i64 = 1_700_000_000;

    fn session() -> OAuthSession {
        OAuthSession {
            sub: DID.into(),
            issuer: "https://auth.example.com".into(),
            aud: "https://pds.example.com".into(),
            dpop_key_jwk: r#"{"kty":"EC","d":"k"}"#.into(),
            access_token: "old-access".into(),
            refresh_token: "old-refresh".into(),
            token_type: "DPoP".into(),
            granted_scope: "atproto transition:generic".into(),
            expires_at: Some(NOW + 60),
        }
    }

    fn response() -> TokenResponse {
        TokenResponse {
            access_token: "new-access".into(),
            refresh_token: Some("new-refresh".into()),
            token_type: "DPoP".into(),
            granted_scope: "atproto transition:generic".into(),
            sub: DID.into(),
            expires_in: Some(3600),
        }
    }

    #[test]
    fn a_refresh_replaces_both_tokens_and_the_expiry() {
        let updated = apply_refresh(&session(), &response(), NOW).unwrap();
        assert_eq!(updated.access_token, "new-access");
        assert_eq!(updated.refresh_token, "new-refresh");
        assert_eq!(updated.expires_at, Some(NOW + 3600));
    }

    /// **Rotation is expected but not guaranteed.** A response omitting
    /// `refresh_token` means keep the one we have — storing an empty string
    /// would destroy the session on the next refresh with no way to tell why.
    #[test]
    fn an_omitted_refresh_token_keeps_the_existing_one() {
        let mut response = response();
        response.refresh_token = None;
        let updated = apply_refresh(&session(), &response, NOW).unwrap();
        assert_eq!(updated.refresh_token, "old-refresh");
        assert_eq!(
            updated.access_token, "new-access",
            "the access token still rotates"
        );
    }

    /// `expires_in` is optional, and absent means no proactive refresh rather
    /// than an invented deadline.
    #[test]
    fn an_omitted_expiry_clears_rather_than_invents_one() {
        let mut response = response();
        response.expires_in = None;
        assert_eq!(
            apply_refresh(&session(), &response, NOW)
                .unwrap()
                .expires_at,
            None
        );
    }

    /// **A refresh must not be able to move a session to another account.**
    /// The reference re-checks `sub` on the refresh response for this reason.
    #[test]
    fn a_refresh_for_a_different_subject_is_rejected() {
        let mut response = response();
        response.sub = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into();
        assert!(apply_refresh(&session(), &response, NOW).is_err());
    }

    /// A narrowed grant must be recorded, not silently kept at the old value —
    /// otherwise writes start failing with nothing to explain it.
    #[test]
    fn the_granted_scope_is_taken_from_the_response() {
        let mut response = response();
        response.granted_scope = "atproto".into();
        assert_eq!(
            apply_refresh(&session(), &response, NOW)
                .unwrap()
                .granted_scope,
            "atproto"
        );
    }

    /// The DPoP key and the PDS are properties of the session, not of any one
    /// token response; a refresh must leave them alone.
    #[test]
    fn a_refresh_preserves_the_session_key_and_audience() {
        let updated = apply_refresh(&session(), &response(), NOW).unwrap();
        assert_eq!(updated.dpop_key_jwk, session().dpop_key_jwk);
        assert_eq!(updated.aud, session().aud);
        assert_eq!(updated.issuer, session().issuer);
        assert_eq!(updated.sub, session().sub);
    }

    // ── the per-subject lock ─────────────────────────────────────────────────

    /// Two concurrent refreshes of the SAME subject must not overlap: both would
    /// present the same single-use refresh token, and the loser's
    /// `invalid_grant` typically revokes the winner's new tokens too.
    #[tokio::test]
    async fn the_same_subject_is_serialized() {
        let locks = RefreshLocks::default();
        let held = locks.lock(DID).await;

        let second = locks.lock(DID);
        tokio::pin!(second);
        assert!(
            futures_lite_poll_pending(&mut second),
            "a second holder acquired the lock while the first held it"
        );
        drop(held);
        // Once released, the waiter proceeds.
        let _ = second.await;
    }

    /// Different subjects must NOT block each other, or one slow refresh stalls
    /// every other account.
    #[tokio::test]
    async fn different_subjects_do_not_block_each_other() {
        let locks = RefreshLocks::default();
        let _a = locks.lock(DID).await;
        let b = locks.lock("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
        tokio::pin!(b);
        assert!(
            !futures_lite_poll_pending(&mut b),
            "an unrelated subject was blocked"
        );
    }

    /// Poll a future once; true if it is still pending.
    fn futures_lite_poll_pending<F: std::future::Future>(fut: &mut std::pin::Pin<&mut F>) -> bool {
        use std::task::{Context, Poll, Waker};
        let mut cx = Context::from_waker(Waker::noop());
        matches!(fut.as_mut().poll(&mut cx), Poll::Pending)
    }
}
