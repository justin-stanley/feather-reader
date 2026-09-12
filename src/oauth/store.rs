//! Persistence for in-flight logins, authenticated sessions, and DPoP nonces.
//!
//! Two properties here are security-relevant and neither is obvious from the
//! SQL:
//!
//! * **`state` is consumed atomically.** A `SELECT` followed by a `DELETE` lets
//!   two concurrent callbacks both pass and both exchange the same `code` —
//!   and the authorization server is entitled to revoke *"any outstanding
//!   sessions and tokens associated with the earlier use of the `code`"*, so the
//!   loser destroys the winner's session. One statement, `RETURNING`, zero rows
//!   means rejected.
//!
//! * **Secret columns are AAD-bound to their row.** Each ciphertext is sealed
//!   against `oauth_state:<state>:<column>` (or `oauth_session:<sub>:<column>`),
//!   so a value lifted into another row — or another column of the same row —
//!   fails to authenticate rather than decrypting into the wrong place. See
//!   [`super::crypto`]; the unbound `enc.v1` form is rejected outright here.

use anyhow::{Context as _, Result};
use sqlx::SqlitePool;

use super::crypto::Codec;

/// Tables for the OAuth flow. `CREATE TABLE IF NOT EXISTS`, matching the
/// convention in [`crate::store`].
const SCHEMA: &str = r#"
-- One row per in-flight login. Short-lived and single-use; see `take_pending`.
CREATE TABLE IF NOT EXISTS oauth_state (
    state                TEXT PRIMARY KEY NOT NULL,
    -- SHA-256 of the cookie value set before the redirect. The callback must
    -- present the cookie; without it a callback URL fired by any other browser
    -- would complete the login and hand out the session.
    browser_binding_hash TEXT NOT NULL,
    pkce_verifier        TEXT NOT NULL,   -- AAD-bound
    dpop_key_jwk         TEXT NOT NULL,   -- AAD-bound
    issuer               TEXT NOT NULL,
    pds_url              TEXT NOT NULL,
    did                  TEXT NOT NULL,
    -- The negotiated client-auth method is stored so the callback re-creates the
    -- same client rather than re-negotiating against possibly-changed metadata.
    auth_method          TEXT NOT NULL,
    auth_kid             TEXT,
    -- The EXACT redirect_uri sent in PAR; it must match byte-for-byte at the
    -- token endpoint.
    redirect_uri         TEXT NOT NULL,
    requested_scope      TEXT NOT NULL,
    request_uri          TEXT NOT NULL,
    app_return_to        TEXT,
    expires_at           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_state_expires_at ON oauth_state(expires_at);

-- One row per authenticated account.
CREATE TABLE IF NOT EXISTS oauth_session (
    sub            TEXT PRIMARY KEY NOT NULL,
    issuer         TEXT NOT NULL,
    -- The PDS. Every XRPC request is built against this rather than re-derived,
    -- so it belongs to the token set.
    aud            TEXT NOT NULL,
    dpop_key_jwk   TEXT NOT NULL,   -- AAD-bound
    access_token   TEXT NOT NULL,   -- AAD-bound
    refresh_token  TEXT NOT NULL,   -- AAD-bound
    token_type     TEXT NOT NULL,
    granted_scope  TEXT NOT NULL,
    -- NULL is legitimate: `expires_in` is optional in a token response.
    expires_at     INTEGER
);

-- Server-issued DPoP nonces, per origin. Persisted rather than used once,
-- because a nonce is expected on every subsequent request to that origin.
CREATE TABLE IF NOT EXISTS oauth_nonce (
    origin     TEXT PRIMARY KEY NOT NULL,
    nonce      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
"#;

/// Create the OAuth tables.
pub async fn init_schema(pool: &SqlitePool) -> Result<()> {
    sqlx::query(SCHEMA)
        .execute(pool)
        .await
        .context("creating the OAuth tables")?;
    Ok(())
}

/// The AAD a state-row secret is sealed against.
fn state_aad(state: &str, column: &str) -> Vec<u8> {
    format!("oauth_state:{state}:{column}").into_bytes()
}

/// The AAD a session-row secret is sealed against.
fn session_aad(sub: &str, column: &str) -> Vec<u8> {
    format!("oauth_session:{sub}:{column}").into_bytes()
}

/// An in-flight login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuth {
    pub state: String,
    pub browser_binding_hash: String,
    pub pkce_verifier: String,
    pub dpop_key_jwk: String,
    pub issuer: String,
    pub pds_url: String,
    pub did: String,
    pub auth_method: String,
    pub auth_kid: Option<String>,
    pub redirect_uri: String,
    pub requested_scope: String,
    pub request_uri: String,
    pub app_return_to: Option<String>,
    pub expires_at: i64,
}

/// Row shape for `oauth_state`, secrets still sealed.
#[derive(sqlx::FromRow)]
struct PendingRow {
    state: String,
    browser_binding_hash: String,
    pkce_verifier: String,
    dpop_key_jwk: String,
    issuer: String,
    pds_url: String,
    did: String,
    auth_method: String,
    auth_kid: Option<String>,
    redirect_uri: String,
    requested_scope: String,
    request_uri: String,
    app_return_to: Option<String>,
    expires_at: i64,
}

/// Record an in-flight login.
pub async fn put_pending(pool: &SqlitePool, codec: &Codec, auth: &PendingAuth) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO oauth_state (
            state, browser_binding_hash, pkce_verifier, dpop_key_jwk, issuer,
            pds_url, did, auth_method, auth_kid, redirect_uri, requested_scope,
            request_uri, app_return_to, expires_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
    )
    .bind(&auth.state)
    .bind(&auth.browser_binding_hash)
    .bind(codec.encrypt_bound(
        &auth.pkce_verifier,
        &state_aad(&auth.state, "pkce_verifier"),
    ))
    .bind(codec.encrypt_bound(&auth.dpop_key_jwk, &state_aad(&auth.state, "dpop_key_jwk")))
    .bind(&auth.issuer)
    .bind(&auth.pds_url)
    .bind(&auth.did)
    .bind(&auth.auth_method)
    .bind(&auth.auth_kid)
    .bind(&auth.redirect_uri)
    .bind(&auth.requested_scope)
    .bind(&auth.request_uri)
    .bind(&auth.app_return_to)
    .bind(auth.expires_at)
    .execute(pool)
    .await
    .context("recording the pending login")?;
    Ok(())
}

/// **Consume** an in-flight login: return it and delete it, atomically.
///
/// One statement, so two concurrent callbacks cannot both succeed. A
/// `SELECT` then `DELETE` would let both pass and both exchange the same
/// `code` — and the authorization server is entitled to revoke every session
/// associated with the earlier use, so the loser destroys the winner's session.
///
/// An EXPIRED row is deleted as well and reported absent, so it cannot be
/// probed for existence after the fact.
pub async fn take_pending(
    pool: &SqlitePool,
    codec: &Codec,
    state: &str,
    now: i64,
) -> Result<Option<PendingAuth>> {
    let row: Option<PendingRow> = sqlx::query_as(
        r#"
        DELETE FROM oauth_state WHERE state = ?1
        RETURNING state, browser_binding_hash, pkce_verifier, dpop_key_jwk,
                  issuer, pds_url, did, auth_method, auth_kid, redirect_uri,
                  requested_scope, request_uri, app_return_to, expires_at
        "#,
    )
    .bind(state)
    .fetch_optional(pool)
    .await
    .context("consuming the pending login")?;

    let Some(row) = row else { return Ok(None) };
    if row.expires_at < now {
        // Deleted above regardless; an expired flow is simply gone.
        return Ok(None);
    }

    Ok(Some(PendingAuth {
        pkce_verifier: codec
            .decrypt_bound(&row.pkce_verifier, &state_aad(&row.state, "pkce_verifier"))
            .context("decrypting the stored PKCE verifier")?,
        dpop_key_jwk: codec
            .decrypt_bound(&row.dpop_key_jwk, &state_aad(&row.state, "dpop_key_jwk"))
            .context("decrypting the stored DPoP key")?,
        state: row.state,
        browser_binding_hash: row.browser_binding_hash,
        issuer: row.issuer,
        pds_url: row.pds_url,
        did: row.did,
        auth_method: row.auth_method,
        auth_kid: row.auth_kid,
        redirect_uri: row.redirect_uri,
        requested_scope: row.requested_scope,
        request_uri: row.request_uri,
        app_return_to: row.app_return_to,
        expires_at: row.expires_at,
    }))
}

/// An authenticated account's tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthSession {
    pub sub: String,
    pub issuer: String,
    pub aud: String,
    pub dpop_key_jwk: String,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub granted_scope: String,
    pub expires_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    sub: String,
    issuer: String,
    aud: String,
    dpop_key_jwk: String,
    access_token: String,
    refresh_token: String,
    token_type: String,
    granted_scope: String,
    expires_at: Option<i64>,
}

/// Store or REPLACE a session.
///
/// An upsert, not an insert: logging in again is normal (a second browser, or
/// re-auth after expiry), and a plain insert would fail on the primary key and
/// 500 every subsequent login.
pub async fn put_session(pool: &SqlitePool, codec: &Codec, session: &OAuthSession) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO oauth_session (
            sub, issuer, aud, dpop_key_jwk, access_token, refresh_token,
            token_type, granted_scope, expires_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ON CONFLICT(sub) DO UPDATE SET
            issuer        = excluded.issuer,
            aud           = excluded.aud,
            dpop_key_jwk  = excluded.dpop_key_jwk,
            access_token  = excluded.access_token,
            refresh_token = excluded.refresh_token,
            token_type    = excluded.token_type,
            granted_scope = excluded.granted_scope,
            expires_at    = excluded.expires_at
        "#,
    )
    .bind(&session.sub)
    .bind(&session.issuer)
    .bind(&session.aud)
    .bind(codec.encrypt_bound(
        &session.dpop_key_jwk,
        &session_aad(&session.sub, "dpop_key_jwk"),
    ))
    .bind(codec.encrypt_bound(
        &session.access_token,
        &session_aad(&session.sub, "access_token"),
    ))
    .bind(codec.encrypt_bound(
        &session.refresh_token,
        &session_aad(&session.sub, "refresh_token"),
    ))
    .bind(&session.token_type)
    .bind(&session.granted_scope)
    .bind(session.expires_at)
    .execute(pool)
    .await
    .context("storing the OAuth session")?;
    Ok(())
}

/// Read a session by subject DID.
pub async fn get_session(
    pool: &SqlitePool,
    codec: &Codec,
    sub: &str,
) -> Result<Option<OAuthSession>> {
    let row: Option<SessionRow> = sqlx::query_as(
        r#"
        SELECT sub, issuer, aud, dpop_key_jwk, access_token, refresh_token,
               token_type, granted_scope, expires_at
        FROM oauth_session WHERE sub = ?1
        "#,
    )
    .bind(sub)
    .fetch_optional(pool)
    .await
    .context("reading the OAuth session")?;

    let Some(row) = row else { return Ok(None) };
    Ok(Some(OAuthSession {
        dpop_key_jwk: codec
            .decrypt_bound(&row.dpop_key_jwk, &session_aad(&row.sub, "dpop_key_jwk"))
            .context("decrypting the session DPoP key")?,
        access_token: codec
            .decrypt_bound(&row.access_token, &session_aad(&row.sub, "access_token"))
            .context("decrypting the stored access token")?,
        refresh_token: codec
            .decrypt_bound(&row.refresh_token, &session_aad(&row.sub, "refresh_token"))
            .context("decrypting the stored refresh token")?,
        sub: row.sub,
        issuer: row.issuer,
        aud: row.aud,
        token_type: row.token_type,
        granted_scope: row.granted_scope,
        expires_at: row.expires_at,
    }))
}

/// Delete a session. `true` if one existed.
pub async fn delete_session(pool: &SqlitePool, sub: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM oauth_session WHERE sub = ?1")
        .bind(sub)
        .execute(pool)
        .await
        .context("deleting the OAuth session")?;
    Ok(result.rows_affected() > 0)
}

/// The stored DPoP nonce for an origin, if any.
pub async fn get_nonce(pool: &SqlitePool, origin: &str) -> Result<Option<String>> {
    sqlx::query_scalar("SELECT nonce FROM oauth_nonce WHERE origin = ?1")
        .bind(origin)
        .fetch_optional(pool)
        .await
        .context("reading the stored DPoP nonce")
}

/// Record the latest DPoP nonce for an origin. Servers rotate nonces, so a
/// later value replaces the earlier one.
pub async fn put_nonce(pool: &SqlitePool, origin: &str, nonce: &str) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO oauth_nonce (origin, nonce, updated_at) VALUES (?1, ?2, ?3)
        ON CONFLICT(origin) DO UPDATE SET
            nonce = excluded.nonce, updated_at = excluded.updated_at
        "#,
    )
    .bind(origin)
    .bind(nonce)
    .bind(chrono::Utc::now().timestamp())
    .execute(pool)
    .await
    .context("storing the DPoP nonce")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::init_url;

    const KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    const NOW: i64 = 1_700_000_000;

    async fn db() -> (sqlx::SqlitePool, Codec) {
        let pool = init_url("sqlite::memory:").await.unwrap();
        init_schema(&pool).await.unwrap();
        (pool, Codec::new(Some(KEY)).unwrap())
    }

    fn pending(state: &str) -> PendingAuth {
        PendingAuth {
            state: state.to_string(),
            browser_binding_hash: "hash-of-cookie".into(),
            pkce_verifier: "verifier-secret".into(),
            dpop_key_jwk: r#"{"kty":"EC","d":"secret"}"#.into(),
            issuer: "https://auth.example.com".into(),
            pds_url: "https://pds.example.com".into(),
            did: DID.into(),
            auth_method: "private_key_jwt".into(),
            auth_kid: Some("featherreader-oauth-1".into()),
            redirect_uri: "https://feather-reader.com/oauth/callback".into(),
            requested_scope: "atproto transition:generic".into(),
            request_uri: "urn:ietf:params:oauth:request_uri:abc".into(),
            app_return_to: Some("/reader".into()),
            expires_at: NOW + 600,
        }
    }

    // ── the atomic consume ───────────────────────────────────────────────────

    #[tokio::test]
    async fn a_pending_login_round_trips() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        let want = pending("state-1");
        put_pending(&pool, &codec, &want).await?;

        let got = take_pending(&pool, &codec, "state-1", NOW).await?.unwrap();
        assert_eq!(got, want);
        Ok(())
    }

    /// **Single use.** The second arrival must find nothing, so it is rejected
    /// before any token call — a replayed `code` exchange can make the
    /// authorization server revoke the session the first one just created.
    #[tokio::test]
    async fn a_pending_login_can_only_be_taken_once() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_pending(&pool, &codec, &pending("state-1")).await?;

        assert!(take_pending(&pool, &codec, "state-1", NOW).await?.is_some());
        assert!(take_pending(&pool, &codec, "state-1", NOW).await?.is_none());
        Ok(())
    }

    /// The consume is one statement, so concurrent callbacks cannot both win.
    #[tokio::test]
    async fn concurrent_takes_yield_exactly_one_winner() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_pending(&pool, &codec, &pending("race")).await?;

        // Concurrent futures interleave at every `.await`, which is exactly
        // where a SELECT-then-DELETE would let two callers both see the row.
        let (a, b, c, d) = tokio::join!(
            take_pending(&pool, &codec, "race", NOW),
            take_pending(&pool, &codec, "race", NOW),
            take_pending(&pool, &codec, "race", NOW),
            take_pending(&pool, &codec, "race", NOW),
        );
        let winners = [a?, b?, c?, d?].iter().filter(|r| r.is_some()).count();
        assert_eq!(winners, 1, "more than one caller consumed the same state");
        Ok(())
    }

    /// An expired row is not returned — and is consumed anyway, so it cannot be
    /// probed for existence afterwards.
    #[tokio::test]
    async fn an_expired_pending_login_is_rejected_and_removed() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_pending(&pool, &codec, &pending("stale")).await?;

        let after_expiry = NOW + 601;
        assert!(take_pending(&pool, &codec, "stale", after_expiry)
            .await?
            .is_none());
        // Gone even at a time when it would have been valid.
        assert!(take_pending(&pool, &codec, "stale", NOW).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn an_unknown_state_is_simply_absent() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        assert!(take_pending(&pool, &codec, "never-existed", NOW)
            .await?
            .is_none());
        Ok(())
    }

    // ── AAD binding, end to end ──────────────────────────────────────────────

    /// The secrets must not be readable from the database itself.
    #[tokio::test]
    async fn secret_columns_are_stored_encrypted() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_pending(&pool, &codec, &pending("state-1")).await?;

        let (verifier, jwk): (String, String) =
            sqlx::query_as("SELECT pkce_verifier, dpop_key_jwk FROM oauth_state WHERE state = ?")
                .bind("state-1")
                .fetch_one(&pool)
                .await?;
        for stored in [&verifier, &jwk] {
            assert!(stored.starts_with("enc.v2.gcm."), "not bound: {stored}");
        }
        assert!(!verifier.contains("verifier-secret"));
        assert!(!jwk.contains("secret"));
        Ok(())
    }

    /// **The reason AAD was pulled forward.** Anything able to write the
    /// database must not be able to graft one login flow's DPoP key onto
    /// another flow's state row.
    #[tokio::test]
    async fn a_secret_moved_between_rows_does_not_decrypt() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_pending(&pool, &codec, &pending("victim")).await?;
        let mut attacker = pending("attacker");
        attacker.dpop_key_jwk = r#"{"kty":"EC","d":"attacker-key"}"#.into();
        put_pending(&pool, &codec, &attacker).await?;

        // Lift the attacker's sealed DPoP key into the victim's row.
        let stolen: String =
            sqlx::query_scalar("SELECT dpop_key_jwk FROM oauth_state WHERE state = ?")
                .bind("attacker")
                .fetch_one(&pool)
                .await?;
        sqlx::query("UPDATE oauth_state SET dpop_key_jwk = ? WHERE state = ?")
            .bind(&stolen)
            .bind("victim")
            .execute(&pool)
            .await?;

        assert!(
            take_pending(&pool, &codec, "victim", NOW).await.is_err(),
            "a grafted ciphertext decrypted in the wrong row"
        );
        Ok(())
    }

    /// And between COLUMNS of the same row — the binding names the column too.
    #[tokio::test]
    async fn a_secret_moved_between_columns_does_not_decrypt() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_pending(&pool, &codec, &pending("state-1")).await?;

        let verifier: String =
            sqlx::query_scalar("SELECT pkce_verifier FROM oauth_state WHERE state = ?")
                .bind("state-1")
                .fetch_one(&pool)
                .await?;
        sqlx::query("UPDATE oauth_state SET dpop_key_jwk = ? WHERE state = ?")
            .bind(&verifier)
            .bind("state-1")
            .execute(&pool)
            .await?;

        assert!(take_pending(&pool, &codec, "state-1", NOW).await.is_err());
        Ok(())
    }

    /// An UNBOUND `enc.v1` value must be refused where a bound one is expected,
    /// or the binding is opt-out for anyone who can write the row.
    #[tokio::test]
    async fn an_unbound_ciphertext_is_refused() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_pending(&pool, &codec, &pending("state-1")).await?;

        sqlx::query("UPDATE oauth_state SET pkce_verifier = ? WHERE state = ?")
            .bind(codec.encrypt("verifier-secret"))
            .bind("state-1")
            .execute(&pool)
            .await?;

        assert!(take_pending(&pool, &codec, "state-1", NOW).await.is_err());
        Ok(())
    }

    // ── sessions ─────────────────────────────────────────────────────────────

    fn session() -> OAuthSession {
        OAuthSession {
            sub: DID.into(),
            issuer: "https://auth.example.com".into(),
            aud: "https://pds.example.com".into(),
            dpop_key_jwk: r#"{"kty":"EC","d":"session-key"}"#.into(),
            access_token: "access-abc".into(),
            refresh_token: "refresh-xyz".into(),
            token_type: "DPoP".into(),
            granted_scope: "atproto transition:generic".into(),
            expires_at: Some(NOW + 3600),
        }
    }

    #[tokio::test]
    async fn a_session_round_trips() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_session(&pool, &codec, &session()).await?;
        assert_eq!(get_session(&pool, &codec, DID).await?.unwrap(), session());
        Ok(())
    }

    /// Logging in again must REPLACE the session, not fail on the primary key.
    /// A plain INSERT here is the bug that 500s every second login.
    #[tokio::test]
    async fn re_login_replaces_the_existing_session() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_session(&pool, &codec, &session()).await?;

        let mut second = session();
        second.access_token = "access-second".into();
        second.refresh_token = "refresh-second".into();
        put_session(&pool, &codec, &second).await?;

        let got = get_session(&pool, &codec, DID).await?.unwrap();
        assert_eq!(got.access_token, "access-second");
        assert_eq!(got.refresh_token, "refresh-second");
        Ok(())
    }

    /// `expires_in` is optional in a token response, so the column is nullable
    /// and a session without one must survive the round trip.
    #[tokio::test]
    async fn a_session_without_an_expiry_round_trips() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        let mut s = session();
        s.expires_at = None;
        put_session(&pool, &codec, &s).await?;
        assert_eq!(
            get_session(&pool, &codec, DID).await?.unwrap().expires_at,
            None
        );
        Ok(())
    }

    #[tokio::test]
    async fn session_tokens_are_bound_to_their_subject() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_session(&pool, &codec, &session()).await?;

        let other = OAuthSession {
            sub: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            access_token: "access-other".into(),
            ..session()
        };
        put_session(&pool, &codec, &other).await?;

        let stolen: String =
            sqlx::query_scalar("SELECT access_token FROM oauth_session WHERE sub = ?")
                .bind(&other.sub)
                .fetch_one(&pool)
                .await?;
        sqlx::query("UPDATE oauth_session SET access_token = ? WHERE sub = ?")
            .bind(&stolen)
            .bind(DID)
            .execute(&pool)
            .await?;

        assert!(get_session(&pool, &codec, DID).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn a_deleted_session_is_gone() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_session(&pool, &codec, &session()).await?;
        assert!(delete_session(&pool, DID).await?);
        assert!(get_session(&pool, &codec, DID).await?.is_none());
        assert!(!delete_session(&pool, DID).await?);
        Ok(())
    }

    // ── DPoP nonces ──────────────────────────────────────────────────────────

    /// Nonces are per-ORIGIN and persist between requests: using one only for an
    /// immediate retry means every request pays a wasted round trip.
    #[tokio::test]
    async fn nonces_are_stored_and_replaced_per_origin() -> anyhow::Result<()> {
        let (pool, _) = db().await;
        assert_eq!(get_nonce(&pool, "https://a.example").await?, None);

        put_nonce(&pool, "https://a.example", "n1").await?;
        put_nonce(&pool, "https://b.example", "n2").await?;
        assert_eq!(
            get_nonce(&pool, "https://a.example").await?.as_deref(),
            Some("n1")
        );
        assert_eq!(
            get_nonce(&pool, "https://b.example").await?.as_deref(),
            Some("n2")
        );

        // Rotation: servers rotate nonces, so a later value replaces the earlier.
        put_nonce(&pool, "https://a.example", "n3").await?;
        assert_eq!(
            get_nonce(&pool, "https://a.example").await?.as_deref(),
            Some("n3")
        );
        Ok(())
    }
}
