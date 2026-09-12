//! RFC 7009 token revocation — what "log out" actually means at the PDS.
//!
//! Without this, signing out only drops the local row: the refresh token stays
//! live at the authorization server until it expires on its own, so a stolen
//! copy of the database still yields a working session long after the user
//! believes they are out. The sidecar revoked; the Rust path has to as well.

use anyhow::Result;

use super::client_auth::AuthMethod;
use super::store::OAuthSession;

/// What happened at the authorization server. Never an `Err` at the call site:
/// the caller has already decided to sign the user out, and the question is only
/// whether the server was told too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revocation {
    /// The server accepted the revocation.
    Revoked,
    /// There was no session to revoke — logout is idempotent.
    NoSession,
    /// The attempt failed. The local row is gone regardless.
    Failed(String),
}

/// Which of a session's two tokens to present, and its `token_type_hint`.
///
/// **The refresh token, whenever there is one.** RFC 7009 §2.1: revoking a
/// refresh token SHOULD also invalidate every access token issued under the same
/// grant, so one call ends the whole thing. Revoking the access token alone
/// leaves the refresh token live, and a refresh token is precisely what turns a
/// stale database dump back into a working session.
///
/// The reference is split on this — `oauth-session.js` `signOut()` revokes the
/// access token while `session-getter.js` revokes `refresh_token ?? access_token`
/// — and this follows the stronger of the two.
pub fn token_to_revoke(session: &OAuthSession) -> (&str, &'static str) {
    if session.refresh_token.is_empty() {
        (&session.access_token, "access_token")
    } else {
        (&session.refresh_token, "refresh_token")
    }
}

/// The form body for a revocation request, client credentials included.
///
/// No `token_type_hint` is sent, matching the reference. It is optional in RFC
/// 7009, and a server that cannot find the token under the hinted type MUST
/// search the other — so the hint can only save the server a lookup, never
/// change the outcome.
pub fn revoke_params(
    method: AuthMethod,
    client_id: &str,
    assertion: Option<&str>,
    token: &str,
) -> Result<Vec<(&'static str, String)>> {
    let mut params = vec![("token", token.to_string())];
    params.extend(super::client_auth::credential_params(
        method, client_id, assertion,
    )?);
    Ok(params)
}

/// What a revocation needs beyond the session itself. Mirrors
/// [`super::session::RefreshContext`]; `aud` is the issuer for both.
pub struct RevokeContext<'a> {
    /// From the authorization server's metadata. Absent when the server
    /// advertises none, which is itself a reason revocation cannot happen.
    pub revocation_endpoint: Option<&'a str>,
    pub client_id: &'a str,
    pub auth_method: AuthMethod,
    /// The confidential client's signing key; unused by the dev client.
    pub client_key: Option<&'a super::keys::SigningKey>,
}

/// Sign a subject out: tell the authorization server, then drop the local row.
///
/// **The local row goes regardless of what the server says.** The user asked to
/// be logged out; a server that is down, slow, or has already forgotten the
/// grant must not leave a usable session sitting in our database. The reference
/// encodes the same ordering as `try { revoke } finally { delStored }`, and the
/// failure it guards against is the worse one: reporting an error to the user
/// while their credentials stay live locally.
///
/// Revocation is attempted FIRST, because it needs the tokens the delete
/// destroys.
pub async fn sign_out(
    pool: &sqlx::SqlitePool,
    codec: &super::crypto::Codec,
    http: &reqwest::Client,
    ctx: &RevokeContext<'_>,
    sub: &str,
    now: i64,
) -> Revocation {
    let outcome = match super::store::get_session(pool, codec, sub).await {
        Ok(Some(session)) => revoke_tokens(pool, http, ctx, &session, now).await,
        Ok(None) => Revocation::NoSession,
        Err(err) => Revocation::Failed(format!("reading the session: {err:#}")),
    };

    // Unconditional, and its own failure is reported without masking the above.
    if let Err(err) = super::store::delete_session(pool, sub).await {
        return Revocation::Failed(format!("deleting the local session: {err:#}"));
    }
    outcome
}

/// The revocation request itself. Errors become [`Revocation::Failed`] rather
/// than propagating: every caller has already committed to signing out.
async fn revoke_tokens(
    pool: &sqlx::SqlitePool,
    http: &reqwest::Client,
    ctx: &RevokeContext<'_>,
    session: &OAuthSession,
    now: i64,
) -> Revocation {
    match try_revoke(pool, http, ctx, session, now).await {
        Ok(()) => Revocation::Revoked,
        Err(err) => Revocation::Failed(format!("{err:#}")),
    }
}

async fn try_revoke(
    pool: &sqlx::SqlitePool,
    http: &reqwest::Client,
    ctx: &RevokeContext<'_>,
    session: &OAuthSession,
    now: i64,
) -> Result<()> {
    let endpoint = ctx.revocation_endpoint.ok_or_else(|| {
        anyhow::anyhow!("the authorization server advertises no revocation endpoint")
    })?;

    let (token, _hint) = token_to_revoke(session);
    let assertion = match ctx.auth_method {
        AuthMethod::PrivateKeyJwt => {
            let key = ctx.client_key.ok_or_else(|| {
                anyhow::anyhow!("private_key_jwt requires the client signing key")
            })?;
            Some(super::client_auth::client_assertion(
                key,
                ctx.client_id,
                &session.issuer,
                now,
            )?)
        }
        AuthMethod::None => None,
    };
    let params = revoke_params(ctx.auth_method, ctx.client_id, assertion.as_deref(), token)?;
    let form: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();

    // The session's own DPoP key, as for every other call on this grant: the
    // reference routes revocation through the same `dpopFetch`.
    let key = super::keys::SigningKey::from_jwk_json(&session.dpop_key_jwk, "session")?;
    let outcome = super::request::send_with_dpop(
        http,
        pool,
        &super::request::DpopRequest {
            endpoint: super::dpop::Endpoint::AuthorizationServer,
            url: endpoint,
            key: &key,
            access_token: None,
            body: super::request::DpopBody::Form(&form),
            retry: super::request::Retry::Allowed,
        },
    )
    .await?;

    // RFC 7009 §2.2: a 200 also means "we did not recognise that token", which
    // is success for our purposes — the grant is not usable either way.
    if !(200..300).contains(&outcome.status) {
        anyhow::bail!("the revocation endpoint returned status {}", outcome.status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(access: &str, refresh: &str) -> OAuthSession {
        OAuthSession {
            sub: "did:plc:ewvi7nxzyoun6zhxrhs64oiz".into(),
            issuer: "https://pds.example.com".into(),
            aud: "https://pds.example.com".into(),
            dpop_key_jwk: r#"{"kty":"EC"}"#.into(),
            access_token: access.into(),
            refresh_token: refresh.into(),
            token_type: "DPoP".into(),
            granted_scope: "atproto".into(),
            expires_at: Some(1_700_000_000),
        }
    }

    /// **The refresh token is the one that matters.**
    ///
    /// Revoking the access token alone ends a session that was going to expire
    /// within the hour anyway, and leaves live the one credential that can mint
    /// replacements indefinitely. RFC 7009 §2.1 makes revoking the refresh token
    /// cover both.
    #[test]
    fn the_refresh_token_is_preferred_over_the_access_token() {
        let session = session("access-abc", "refresh-xyz");
        let (token, hint) = token_to_revoke(&session);
        assert_eq!(
            token, "refresh-xyz",
            "revoked the access token, leaving the refresh token live"
        );
        assert_eq!(hint, "refresh_token");
    }

    /// A token response may omit `refresh_token` entirely. Then the access token
    /// is all there is, and revoking it is better than revoking nothing.
    #[test]
    fn an_absent_refresh_token_falls_back_to_the_access_token() {
        let session = session("access-abc", "");
        let (token, hint) = token_to_revoke(&session);
        assert_eq!(token, "access-abc");
        assert_eq!(hint, "access_token");
    }

    /// A public client sends `client_id` and no assertion — the same rule the
    /// rest of the client-auth surface follows.
    #[test]
    fn a_public_client_sends_the_token_and_its_client_id() {
        let params = revoke_params(AuthMethod::None, "http://localhost", None, "refresh-xyz")
            .expect("a public client needs no assertion");
        assert!(params.contains(&("token", "refresh-xyz".to_string())));
        assert!(params.contains(&("client_id", "http://localhost".to_string())));
        assert!(
            !params
                .iter()
                .any(|(k, _)| k.starts_with("client_assertion")),
            "a public client must not send an assertion it never registered: {params:?}"
        );
    }

    /// A confidential client carries its assertion, so revocation authenticates
    /// the same way PAR and token do.
    #[test]
    fn a_confidential_client_carries_its_assertion() {
        let params = revoke_params(
            AuthMethod::PrivateKeyJwt,
            "https://feather-reader.com/oauth/client-metadata.json",
            Some("the.assertion.jwt"),
            "refresh-xyz",
        )
        .expect("an assertion was supplied");
        assert!(params.contains(&("client_assertion", "the.assertion.jwt".to_string())));
    }

    /// Revocation must not authenticate as an unauthenticated request when the
    /// assertion is missing — that would silently fail at the server and report
    /// success locally.
    #[test]
    fn a_confidential_client_without_an_assertion_is_an_error() {
        let err = revoke_params(AuthMethod::PrivateKeyJwt, "https://client", None, "tok")
            .expect_err("must not send an unauthenticated revocation");
        assert!(format!("{err:#}").contains("requires a client assertion"));
    }

    // ---- the sign-out invariant -------------------------------------------

    const KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    const NOW: i64 = 1_700_000_000;

    async fn db() -> (sqlx::SqlitePool, super::super::crypto::Codec) {
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        super::super::store::init_schema(&pool).await.unwrap();
        (pool, super::super::crypto::Codec::new(Some(KEY)).unwrap())
    }

    /// A real session row, with a real DPoP key so the request gets as far as
    /// the network rather than failing on key parsing.
    async fn stored(pool: &sqlx::SqlitePool, codec: &super::super::crypto::Codec) -> OAuthSession {
        let key = super::super::keys::SigningKey::generate("session");
        let session = OAuthSession {
            dpop_key_jwk: key.to_jwk_json().unwrap(),
            ..session("access-abc", "refresh-xyz")
        };
        super::super::store::put_session(pool, codec, &session)
            .await
            .unwrap();
        session
    }

    fn ctx(endpoint: Option<&str>) -> RevokeContext<'_> {
        RevokeContext {
            revocation_endpoint: endpoint,
            client_id: "http://localhost",
            auth_method: AuthMethod::None,
            client_key: None,
        }
    }

    /// **The session must be gone even when the server could not be told.**
    ///
    /// This is the whole reason the delete is unconditional. If revocation
    /// failing aborted the sign-out, then a PDS that is down — or simply slow —
    /// would leave a fully usable session in the database of a user who has been
    /// shown a "signed out" page. The loopback endpoint here is refused by the
    /// SSRF guard, which is a revocation failure that needs no network.
    #[tokio::test]
    async fn signing_out_deletes_the_local_session_even_when_revocation_fails() {
        let (pool, codec) = db().await;
        stored(&pool, &codec).await;

        let outcome = sign_out(
            &pool,
            &codec,
            &reqwest::Client::new(),
            &ctx(Some("http://127.0.0.1/oauth/revoke")),
            DID,
            NOW,
        )
        .await;

        match &outcome {
            Revocation::Failed(reason) => assert!(
                reason.contains("forbidden (internal) address"),
                "failed BEFORE reaching the network, so this proves nothing about a \
                 revocation failure: {reason}"
            ),
            other => panic!("the loopback endpoint must not report success: {other:?}"),
        }
        assert!(
            super::super::store::get_session(&pool, &codec, DID)
                .await
                .unwrap()
                .is_none(),
            "THE SESSION SURVIVED A FAILED REVOCATION — a signed-out user still has live credentials"
        );
    }

    /// A server with no `revocation_endpoint` cannot be told, but the user is
    /// still signed out locally.
    #[tokio::test]
    async fn a_server_without_a_revocation_endpoint_still_signs_out_locally() {
        let (pool, codec) = db().await;
        stored(&pool, &codec).await;

        let outcome = sign_out(&pool, &codec, &reqwest::Client::new(), &ctx(None), DID, NOW).await;

        match &outcome {
            Revocation::Failed(reason) => assert!(
                reason.contains("no revocation endpoint"),
                "failed for the wrong reason: {reason}"
            ),
            other => panic!("expected a failure, got {other:?}"),
        }
        assert!(super::super::store::get_session(&pool, &codec, DID)
            .await
            .unwrap()
            .is_none());
    }

    /// Logging out twice is not an error. The second call has nothing to revoke
    /// and says so, rather than reporting a failure the caller would log.
    #[tokio::test]
    async fn signing_out_without_a_session_is_idempotent() {
        let (pool, codec) = db().await;
        let outcome = sign_out(
            &pool,
            &codec,
            &reqwest::Client::new(),
            &ctx(Some("https://pds.example.com/oauth/revoke")),
            DID,
            NOW,
        )
        .await;
        assert_eq!(outcome, Revocation::NoSession);
    }
}
