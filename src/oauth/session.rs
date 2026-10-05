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
            // Recover rather than panic: this gates every token refresh, so a
            // poisoned lock here would lock every user out until a restart.
            let mut locks = self.locks.lock().unwrap_or_else(|p| p.into_inner());
            Arc::clone(locks.entry(sub.to_string()).or_default())
        };
        entry.lock_owned().await
    }
}

/// Refuse a re-discovered issuer that is not the one the grant belongs to.
///
/// Discovery runs again from the network on both the callback and the refresh
/// path, and the token endpoint comes out of THAT document. Every discovery
/// check is internally consistent, so a hostile pair of documents satisfies all
/// of them; only this comparison notices that the pair describes a different
/// authorization server than the one that issued the grant.
///
/// A free function so it is reachable from a test. The refresh path's copy was
/// written inline, and deleting it — the single most serious defect found in
/// this branch, on the path that carries the REFRESH TOKEN — passed every test.
pub fn same_issuer(discovered: &str, expected: &str) -> Result<()> {
    if discovered != expected {
        anyhow::bail!(
            "the PDS now names a different authorization server ({discovered:?}) than this \
             grant was issued by ({expected:?}); refusing to send credentials to it"
        );
    }
    Ok(())
}

/// What a refresh needs beyond the session itself.
pub struct RefreshContext<'a> {
    pub token_endpoint: &'a str,
    pub client_id: &'a str,
    pub auth_method: super::client_auth::AuthMethod,
    /// The confidential client's signing key. Required for `private_key_jwt`,
    /// unused by the localhost dev client.
    pub client_key: Option<&'a super::keys::SigningKey>,
    /// From the same discovery as `token_endpoint`. Used only when a refresh
    /// finds its session was signed out while it ran: the tokens it just
    /// obtained belong to no one, and are revoked rather than left live.
    pub revocation_endpoint: Option<&'a str>,
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
    let (session, version) = super::store::get_session_versioned(pool, codec, sub)
        .await?
        .ok_or_else(|| anyhow::anyhow!("session for {sub} disappeared while waiting to refresh"))?;
    if !super::token::is_stale(session.expires_at, now) {
        return Ok(session);
    }

    // NOT timed here. `oauth_refresh` wraps this call AND the discovery that
    // precedes it, in `Repo::session` — a review found that timing only this
    // line missed every refresh that failed in discovery, which is where the two
    // likeliest failures live (an unreachable PDS, and the issuer-mismatch
    // check). See the span in `repo.rs`.
    refresh_locked(pool, codec, http, &session, &version, ctx, now).await
}

/// A refresh succeeded at the server, but the row it started from is no longer
/// on record. Two cases:
///
/// * **Rewritten** by another writer (another process's refresh, a re-login):
///   theirs is the session on record, so it is returned and ours is NOT
///   written over it. Our tokens are not revoked: from a single-use rotation
///   they may share a grant with theirs, and revoking ours could end both.
/// * **Gone**: it was signed out while we refreshed. We now hold a live token
///   set for a session that no longer exists; it is revoked (best-effort,
///   bounded) instead of being written back, and the caller gets the same
///   "no session" error a signed-out user gets.
async fn lost_the_row(
    pool: &sqlx::SqlitePool,
    codec: &super::crypto::Codec,
    http: &reqwest::Client,
    ctx: &RefreshContext<'_>,
    obtained: &OAuthSession,
    now: i64,
) -> Result<OAuthSession> {
    if let Some(current) = super::store::get_session(pool, codec, &obtained.sub).await? {
        return Ok(current);
    }
    let outcome = super::revoke::revoke_orphaned(
        pool,
        http,
        &super::revoke::RevokeContext {
            revocation_endpoint: ctx.revocation_endpoint,
            client_id: ctx.client_id,
            auth_method: ctx.auth_method,
            client_key: ctx.client_key,
            deadline: super::revoke::ORPHAN_REVOKE_DEADLINE,
        },
        obtained,
        now,
    )
    .await;
    if let super::revoke::Revocation::Failed(reason) = &outcome {
        tracing::warn!(
            sub = %obtained.sub,
            %reason,
            "a session signed out during its refresh: the new tokens could not be revoked"
        );
    }
    bail!(
        "no session for {}: it was signed out while being refreshed (the new tokens were \
         not stored{})",
        obtained.sub,
        if outcome == super::revoke::Revocation::Revoked {
            ", and were revoked"
        } else {
            ""
        }
    )
}

/// The refresh itself. Called with the subject's lock held; `version` is the
/// stored form of `session` as read under that lock.
async fn refresh_locked(
    pool: &sqlx::SqlitePool,
    codec: &super::crypto::Codec,
    http: &reqwest::Client,
    session: &OAuthSession,
    version: &super::store::SessionVersion,
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
        // **Conditional on the row we started from — never an upsert.** The
        // lock above is in-process; a sign-out (`/logout`, account deletion,
        // the operator's revoke-all in another process) does not take it. An
        // upsert landing after such a sign-out's delete RESURRECTED the
        // session with these fresh tokens, after it had been reported signed
        // out.
        if !super::store::update_session_if_unchanged(pool, codec, &updated, version).await? {
            return lost_the_row(pool, codec, http, ctx, &updated, now).await;
        }
        // Logged because a refresh is otherwise INVISIBLE: it rotates both
        // tokens and is the one path that can silently end a session, but it
        // happens inside an ordinary page load and the metrics record that call
        // no differently. Without this line, "everyone was logged out overnight"
        // has nothing to correlate against. No token material is logged — only
        // that it happened, and when the replacement expires.
        tracing::info!(
            sub = %updated.sub,
            expires_at = ?updated.expires_at,
            "refreshed the OAuth session"
        );
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

    /// **The re-discovered issuer must be the one the grant belongs to.**
    ///
    /// This was written inline on both the callback and the refresh path, and
    /// deleting the refresh copy — which sends the REFRESH TOKEN, the credential
    /// that mints every other one — passed all 575 tests. A hostile pair of
    /// documents satisfies every discovery check, because those checks only ask
    /// whether the documents agree with each other.
    #[test]
    fn a_re_discovered_issuer_must_match_the_grants_own() {
        same_issuer("https://pds.example.com", "https://pds.example.com")
            .expect("the same issuer must pass");

        let err = same_issuer("https://evil.example", "https://pds.example.com")
            .expect_err("a different authorization server must be refused");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("evil.example") && rendered.contains("pds.example.com"),
            "the error must name both, or an operator cannot tell what moved: {rendered}"
        );
    }

    /// Exact comparison. Issuers are canonicalised by `validate_issuer_form`
    /// before they are ever stored, so a trailing slash or a case difference is
    /// a DIFFERENT issuer, not a spelling of the same one.
    #[test]
    fn the_issuer_comparison_is_exact() {
        assert!(same_issuer("https://pds.example.com/", "https://pds.example.com").is_err());
        assert!(same_issuer("https://PDS.example.com", "https://pds.example.com").is_err());
        assert!(same_issuer("", "https://pds.example.com").is_err());
    }

    // ── the refresh's write vs a concurrent sign-out ─────────────────────────

    const KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// An authorization server over real TLS whose `/token` rotates to
    /// `rotated-refresh` and whose `/revoke` accepts.
    async fn token_server() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let (addr, log) = crate::net::spawn_tls(|_| {
            let mut r = std::collections::HashMap::new();
            r.insert(
                "/token".to_string(),
                vec![crate::net::TestResponse::json(
                    200,
                    serde_json::json!({
                        "access_token": "rotated-access",
                        "refresh_token": "rotated-refresh",
                        "token_type": "DPoP",
                        "scope": "atproto",
                        "sub": DID,
                        "expires_in": 3600,
                    })
                    .to_string(),
                )],
            );
            r.insert(
                "/revoke".to_string(),
                vec![crate::net::TestResponse::json(200, "{}")],
            );
            r
        })
        .await;
        crate::net::test_host_override("as-e2e.test", addr);
        (format!("https://as-e2e.test:{}", addr.port()), log)
    }

    /// An expired session stored under a real codec, and the version read back.
    async fn stored_stale() -> (
        sqlx::SqlitePool,
        crate::oauth::crypto::Codec,
        OAuthSession,
        crate::oauth::store::SessionVersion,
    ) {
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        let codec = crate::oauth::crypto::Codec::new(Some(KEY)).unwrap();
        let stale = OAuthSession {
            dpop_key_jwk: crate::oauth::keys::SigningKey::generate("session-dpop")
                .to_jwk_json()
                .unwrap(),
            expires_at: Some(NOW - 1),
            ..session()
        };
        crate::oauth::store::put_session(&pool, &codec, &stale)
            .await
            .unwrap();
        let (read, version) = crate::oauth::store::get_session_versioned(&pool, &codec, DID)
            .await
            .unwrap()
            .unwrap();
        (pool, codec, read, version)
    }

    fn ctx<'a>(token: &'a str, revoke: &'a str) -> RefreshContext<'a> {
        RefreshContext {
            token_endpoint: token,
            client_id: "http://localhost",
            auth_method: super::super::client_auth::AuthMethod::None,
            client_key: None,
            revocation_endpoint: Some(revoke),
        }
    }

    /// **A refresh must not resurrect a session signed out while it ran.**
    ///
    /// The refresh lock is in-process; a sign-out does not take it (and the
    /// operator's revoke-all runs in another process). The refresh's write was
    /// an upsert, so a sign-out that deleted the row while the token request
    /// was in flight was undone: the session came back holding the fresh
    /// tokens, after being reported signed out — and on Fly no later pass
    /// would ever see it. The fresh tokens belong to no one, so they are
    /// revoked instead.
    #[tokio::test]
    async fn a_refresh_does_not_resurrect_a_session_signed_out_mid_refresh() {
        let (base, log) = token_server().await;
        let (token, revoke) = (format!("{base}/token"), format!("{base}/revoke"));
        let (pool, codec, session, version) = stored_stale().await;

        // The sign-out lands while the refresh is in flight.
        crate::oauth::store::delete_session(&pool, DID)
            .await
            .unwrap();

        let result = refresh_locked(
            &pool,
            &codec,
            &reqwest::Client::new(),
            &session,
            &version,
            &ctx(&token, &revoke),
            NOW,
        )
        .await;

        assert!(
            crate::oauth::store::get_session(&pool, &codec, DID)
                .await
                .unwrap()
                .is_none(),
            "the refresh RESURRECTED a signed-out session"
        );
        let err = result.expect_err("a signed-out session must not be handed back");
        assert!(
            format!("{err:#}").contains("signed out while being refreshed"),
            "{err:#}"
        );
        let seen = log.lock().unwrap().join("\n---\n");
        assert!(
            seen.contains("POST /revoke") && seen.contains("token=rotated-refresh"),
            "the orphaned fresh token was left live:\n{seen}"
        );
    }

    /// **No lost update:** a row another writer rotated while this refresh ran
    /// is kept, not overwritten — and theirs is what the caller gets.
    #[tokio::test]
    async fn a_refresh_does_not_overwrite_a_concurrent_rotation() {
        let (base, log) = token_server().await;
        let (token, revoke) = (format!("{base}/token"), format!("{base}/revoke"));
        let (pool, codec, session, version) = stored_stale().await;

        let theirs = OAuthSession {
            refresh_token: "their-refresh".into(),
            access_token: "their-access".into(),
            expires_at: Some(NOW + 3600),
            ..session.clone()
        };
        crate::oauth::store::put_session(&pool, &codec, &theirs)
            .await
            .unwrap();

        let got = refresh_locked(
            &pool,
            &codec,
            &reqwest::Client::new(),
            &session,
            &version,
            &ctx(&token, &revoke),
            NOW,
        )
        .await
        .expect("a concurrent rotation is not an error");

        let stored = crate::oauth::store::get_session(&pool, &codec, DID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.refresh_token, "their-refresh",
            "the other writer's rotation was overwritten"
        );
        assert_eq!(got.refresh_token, "their-refresh");
        assert!(
            !log.lock()
                .unwrap()
                .iter()
                .any(|r| r.starts_with("POST /revoke")),
            "revoked a token that may share a grant with the live one"
        );
    }

    /// The ordinary refresh still writes.
    #[tokio::test]
    async fn an_uncontested_refresh_stores_the_rotated_tokens() {
        let (base, _log) = token_server().await;
        let (token, revoke) = (format!("{base}/token"), format!("{base}/revoke"));
        let (pool, codec, session, version) = stored_stale().await;

        let got = refresh_locked(
            &pool,
            &codec,
            &reqwest::Client::new(),
            &session,
            &version,
            &ctx(&token, &revoke),
            NOW,
        )
        .await
        .expect("refresh");
        assert_eq!(got.refresh_token, "rotated-refresh");
        assert_eq!(
            crate::oauth::store::get_session(&pool, &codec, DID)
                .await
                .unwrap()
                .unwrap()
                .refresh_token,
            "rotated-refresh"
        );
    }
}
