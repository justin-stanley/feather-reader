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
//! * **Secrets are AAD-bound to their row, column, AND destinations.** Binding
//!   only the secrets is not enough: the declared adversary is anything able to
//!   write the database, and against that adversary a plain unauthenticated
//!   `aud` or `issuer` column defeats the scheme without touching a ciphertext
//!   at all — repoint the PDS and a live DPoP-bound token is sent to the
//!   attacker's host, with everything still decrypting perfectly. So the AAD
//!   covers the destinations too, and is length-prefixed rather than
//!   delimiter-joined so no rearrangement of fields can collide. See
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

/// Build an AAD from a table name and a list of fields, **length-prefixed**.
///
/// Not delimiter-joined. A `table:field:field` encoding is only unambiguous
/// while no field can contain the delimiter, and the fields here include
/// `did:web:…` subjects and URL issuers — precisely the inputs that erode that
/// assumption. Length prefixes make the encoding injective unconditionally,
/// rather than by an invariant nobody is enforcing.
fn structured_aad(table: &str, fields: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in std::iter::once(&table).chain(fields.iter()) {
        out.extend_from_slice(&(field.len() as u64).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

/// The AAD a state-row secret is sealed against.
///
/// It covers the **destinations**, not just the row and column. Binding only the
/// secrets leaves `issuer`/`pds_url`/`did`/`redirect_uri` as plain
/// unauthenticated columns — and against the declared adversary (anything able
/// to write the database) the scheme is then defeated without touching a
/// ciphertext at all: repoint the issuer and we mint a client assertion for the
/// attacker's server and neutralise the `iss` check, while every secret still
/// decrypts perfectly.
///
/// `browser_binding_hash` is in here for the same reason — it is the only thing
/// standing between a server-global state table and a login-CSRF, so it must not
/// be swappable either.
/// Every non-secret column of a state row, so the AAD covers the whole row.
///
/// A struct rather than a long argument list: the failure mode here is a field
/// that nobody remembered to bind, and a struct makes adding a column without
/// binding it a visible omission rather than an invisible one.
struct StateBinding<'a> {
    state: &'a str,
    issuer: &'a str,
    pds_url: &'a str,
    did: &'a str,
    redirect_uri: &'a str,
    browser_binding_hash: &'a str,
    auth_method: &'a str,
    auth_kid: Option<&'a str>,
    requested_scope: &'a str,
    request_uri: &'a str,
    app_return_to: Option<&'a str>,
    expires_at: i64,
}

fn state_aad(binding: &StateBinding<'_>, column: &str) -> Vec<u8> {
    let expires_at = binding.expires_at.to_string();
    structured_aad(
        "oauth_state",
        &[
            binding.state,
            column,
            binding.issuer,
            binding.pds_url,
            binding.did,
            binding.redirect_uri,
            binding.browser_binding_hash,
            binding.auth_method,
            // `auth_kid` selects which client key signs the assertion; stored
            // and never re-verified, so it is bound rather than trusted.
            binding.auth_kid.unwrap_or(""),
            binding.requested_scope,
            binding.request_uri,
            // Declared as a post-login redirect target. Nothing writes it yet,
            // which is exactly why binding it now costs nothing — unbound, it
            // becomes an open redirect the day it is wired up.
            binding.app_return_to.unwrap_or(""),
            // **The row's own lifetime is a destination too.** Both the expiry
            // check and the sweeper filter on this column, so leaving it
            // unauthenticated let anyone who can write the database keep a
            // pending login — and its sealed DPoP key and PKCE verifier — alive
            // indefinitely, defeating the cap whose stated purpose is narrowing
            // the window in which a stolen `state` is worth replaying.
            &expires_at,
        ],
    )
}

/// The AAD a session-row secret is sealed against.
///
/// `aud` is the PDS every subsequent request is built against, so it is bound:
/// repointing it would otherwise ship a live DPoP-bound access token to a host
/// of the attacker's choosing, with the tokens decrypting perfectly.
fn session_aad(
    sub: &str,
    column: &str,
    issuer: &str,
    aud: &str,
    token_type: &str,
    granted_scope: &str,
    expires_at: Option<i64>,
) -> Vec<u8> {
    // `None` and `0` must not collide, so an absent expiry gets its own marker
    // rather than a numeric stand-in.
    let expires_at = expires_at.map_or_else(|| "none".to_string(), |secs| secs.to_string());
    structured_aad(
        "oauth_session",
        &[
            sub,
            column,
            issuer,
            aud,
            // Enforced strictly on the wire (`Bearer` is refused outright) and
            // previously neither authenticated nor re-checked on read.
            token_type,
            granted_scope,
            // Clearing this to NULL made `is_stale` permanently false, so the
            // session was never proactively refreshed.
            &expires_at,
        ],
    )
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
    let binding = StateBinding {
        state: &auth.state,
        issuer: &auth.issuer,
        pds_url: &auth.pds_url,
        did: &auth.did,
        redirect_uri: &auth.redirect_uri,
        browser_binding_hash: &auth.browser_binding_hash,
        auth_method: &auth.auth_method,
        auth_kid: auth.auth_kid.as_deref(),
        requested_scope: &auth.requested_scope,
        request_uri: &auth.request_uri,
        app_return_to: auth.app_return_to.as_deref(),
        expires_at: auth.expires_at,
    };

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
    .bind(codec.encrypt_bound(&auth.pkce_verifier, &state_aad(&binding, "pkce_verifier")))
    .bind(codec.encrypt_bound(&auth.dpop_key_jwk, &state_aad(&binding, "dpop_key_jwk")))
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
    // Expired AT `expires_at`, not one second later.
    if row.expires_at <= now {
        // Deleted above regardless; an expired flow is simply gone.
        return Ok(None);
    }

    // The AAD is rebuilt from the STORED destinations, so any edit to them
    // makes the secrets undecryptable rather than merely unnoticed.
    let binding = StateBinding {
        state: &row.state,
        issuer: &row.issuer,
        pds_url: &row.pds_url,
        did: &row.did,
        redirect_uri: &row.redirect_uri,
        browser_binding_hash: &row.browser_binding_hash,
        auth_method: &row.auth_method,
        auth_kid: row.auth_kid.as_deref(),
        requested_scope: &row.requested_scope,
        request_uri: &row.request_uri,
        app_return_to: row.app_return_to.as_deref(),
        expires_at: row.expires_at,
    };
    let aad = |column: &str| state_aad(&binding, column);
    Ok(Some(PendingAuth {
        pkce_verifier: codec
            .decrypt_bound(&row.pkce_verifier, &aad("pkce_verifier"))
            .context("decrypting the stored PKCE verifier (or its bound context was altered)")?,
        dpop_key_jwk: codec
            .decrypt_bound(&row.dpop_key_jwk, &aad("dpop_key_jwk"))
            .context("decrypting the stored DPoP key (or its bound context was altered)")?,
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
        &session_aad(
            &session.sub,
            "dpop_key_jwk",
            &session.issuer,
            &session.aud,
            &session.token_type,
            &session.granted_scope,
            session.expires_at,
        ),
    ))
    .bind(codec.encrypt_bound(
        &session.access_token,
        &session_aad(
            &session.sub,
            "access_token",
            &session.issuer,
            &session.aud,
            &session.token_type,
            &session.granted_scope,
            session.expires_at,
        ),
    ))
    .bind(codec.encrypt_bound(
        &session.refresh_token,
        &session_aad(
            &session.sub,
            "refresh_token",
            &session.issuer,
            &session.aud,
            &session.token_type,
            &session.granted_scope,
            session.expires_at,
        ),
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
    let aad = |column: &str| {
        session_aad(
            &row.sub,
            column,
            &row.issuer,
            &row.aud,
            &row.token_type,
            &row.granted_scope,
            row.expires_at,
        )
    };
    Ok(Some(OAuthSession {
        dpop_key_jwk: codec
            .decrypt_bound(&row.dpop_key_jwk, &aad("dpop_key_jwk"))
            .context("decrypting the session DPoP key (or its bound context was altered)")?,
        access_token: codec
            .decrypt_bound(&row.access_token, &aad("access_token"))
            .context("decrypting the stored access token (or its bound context was altered)")?,
        refresh_token: codec
            .decrypt_bound(&row.refresh_token, &aad("refresh_token"))
            .context("decrypting the stored refresh token (or its bound context was altered)")?,
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

/// Delete every pending login that has expired. Returns how many went.
///
/// An abandoned login -- the user is redirected and closes the tab -- leaves a
/// row holding a sealed DPoP key and is never consumed by `take_pending`, which
/// only runs when a callback arrives. Without this they accumulate forever, and
/// on a publicly reachable login form that is an unbounded write primitive
/// against the volume.
pub async fn sweep_expired_pending(pool: &SqlitePool, now: i64) -> Result<u64> {
    let result = sqlx::query("DELETE FROM oauth_state WHERE expires_at <= ?1")
        .bind(now)
        .execute(pool)
        .await
        .context("sweeping expired pending logins")?;
    Ok(result.rows_affected())
}

/// Delete DPoP nonces untouched since `cutoff`. Returns how many went.
///
/// The origins come from whatever handle a visitor typed into the login form,
/// and `put_nonce` runs during PAR — before any authentication. So this is a
/// pre-auth write primitive against the volume, the same argument that
/// justifies sweeping abandoned logins, applied to the one table that had no
/// sweeper. A nonce is also worthless once stale: the server issues a new one
/// with the next challenge.
pub async fn sweep_stale_nonces(pool: &SqlitePool, cutoff: i64) -> Result<u64> {
    let result = sqlx::query("DELETE FROM oauth_nonce WHERE updated_at <= ?1")
        .bind(cutoff)
        .execute(pool)
        .await
        .context("sweeping stale DPoP nonces")?;
    Ok(result.rows_affected())
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

    /// `sqlx::query` demands a `&'static str`, so a test that varies a COLUMN
    /// name has to leak. Test-only, bounded by the fixed column lists below.
    fn leak(sql: String) -> &'static str {
        Box::leak(sql.into_boxed_str())
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

    /// **Binding the secrets is not enough: the DESTINATIONS must be bound too.**
    ///
    /// The declared adversary is anything able to write the database. Against
    /// that adversary, leaving `issuer`/`pds_url`/`did`/`redirect_uri` as plain
    /// unauthenticated columns defeats the whole scheme without touching a
    /// ciphertext — repoint the issuer and we mint a client assertion for the
    /// attacker's server and neutralise the RFC 9207 `iss` check, while every
    /// secret still decrypts perfectly.
    #[tokio::test]
    async fn tampering_with_a_pending_logins_destinations_breaks_it() -> anyhow::Result<()> {
        for column in [
            "issuer",
            "pds_url",
            "did",
            "redirect_uri",
            "browser_binding_hash",
            "auth_method",
            // Added after a cold review found each of these tamperable while
            // every ciphertext still verified:
            //
            // `auth_kid` selects the signing key and is never re-verified;
            // `requested_scope` and `request_uri` describe the grant being
            // completed; `app_return_to` is a declared post-login redirect
            // target, so unbound it becomes an open redirect the day it is
            // wired up — binding it now costs nothing.
            "auth_kid",
            "requested_scope",
            "request_uri",
            "app_return_to",
        ] {
            let (pool, codec) = db().await;
            put_pending(&pool, &codec, &pending("state-1")).await?;
            sqlx::query(leak(format!(
                "UPDATE oauth_state SET {column} = ? WHERE state = ?"
            )))
            .bind("https://evil.example")
            .bind("state-1")
            .execute(&pool)
            .await?;
            assert!(
                take_pending(&pool, &codec, "state-1", NOW).await.is_err(),
                "tampering with `{column}` went undetected"
            );
        }
        Ok(())
    }

    /// The session's `aud` IS the PDS every later request is sent to, so
    /// repointing it would ship a live DPoP-bound access token to the attacker's
    /// host. It must break the tokens, not travel alongside them.
    #[tokio::test]
    async fn tampering_with_a_sessions_destinations_breaks_it() -> anyhow::Result<()> {
        for column in [
            "aud",
            "issuer",
            // `token_type` is refused outright on the wire if it is not `DPoP`,
            // but the stored copy was neither authenticated nor re-checked.
            "token_type",
            "granted_scope",
        ] {
            let (pool, codec) = db().await;
            put_session(&pool, &codec, &session()).await?;
            sqlx::query(leak(format!(
                "UPDATE oauth_session SET {column} = ? WHERE sub = ?"
            )))
            .bind("https://evil.example")
            .bind(DID)
            .execute(&pool)
            .await?;
            assert!(
                get_session(&pool, &codec, DID).await.is_err(),
                "tampering with `{column}` went undetected"
            );
        }
        Ok(())
    }

    /// **A row's own lifetime is a destination.**
    ///
    /// Both the expiry check in `take_pending` and `sweep_expired_pending`
    /// filter on `expires_at`. While it was outside the AAD, anyone who could
    /// write the database could push it a year out and keep a pending login —
    /// with its sealed DPoP key and PKCE verifier — alive indefinitely, which is
    /// exactly what the ten-minute cap exists to prevent. Every ciphertext still
    /// verified.
    #[tokio::test]
    async fn extending_a_pending_logins_expiry_breaks_it() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_pending(&pool, &codec, &pending("state-1")).await?;
        sqlx::query("UPDATE oauth_state SET expires_at = ? WHERE state = ?")
            .bind(NOW + 31_536_000)
            .bind("state-1")
            .execute(&pool)
            .await?;
        assert!(
            take_pending(&pool, &codec, "state-1", NOW).await.is_err(),
            "the expiry was extended without breaking the row"
        );
        Ok(())
    }

    /// Clearing a session's expiry made `is_stale` permanently false, so the
    /// session was never proactively refreshed — behaviour steered by an
    /// unauthenticated column while every token decrypted cleanly.
    #[tokio::test]
    async fn clearing_a_sessions_expiry_breaks_it() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_session(&pool, &codec, &session()).await?;
        sqlx::query("UPDATE oauth_session SET expires_at = NULL WHERE sub = ?")
            .bind(DID)
            .execute(&pool)
            .await?;
        assert!(
            get_session(&pool, &codec, DID).await.is_err(),
            "the expiry was cleared without breaking the row"
        );
        Ok(())
    }

    /// The AAD is length-prefixed, so no rearrangement of field boundaries can
    /// produce the same bytes. A delimiter-joined encoding is only safe while no
    /// field can contain the delimiter — and `did:web:…` subjects and URL
    /// issuers are exactly the inputs that erode that assumption.
    #[test]
    fn the_aad_encoding_is_unambiguous_across_field_boundaries() {
        assert_ne!(
            structured_aad("t", &["ab", "c"]),
            structured_aad("t", &["a", "bc"])
        );
        assert_ne!(
            structured_aad("t", &["a:b"]),
            structured_aad("t", &["a", "b"])
        );
        assert_ne!(
            structured_aad("t", &["a", ""]),
            structured_aad("t", &["", "a"])
        );
        assert_ne!(structured_aad("t1", &["a"]), structured_aad("t2", &["a"]));
    }

    /// Both nullable columns must survive the round trip as `None`.
    #[tokio::test]
    async fn a_pending_login_round_trips_with_its_optional_fields_absent() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        let mut want = pending("state-1");
        want.auth_kid = None;
        want.app_return_to = None;
        put_pending(&pool, &codec, &want).await?;
        assert_eq!(
            take_pending(&pool, &codec, "state-1", NOW).await?.unwrap(),
            want
        );
        Ok(())
    }

    /// A row is expired AT `expires_at`, not one second later. The earlier test
    /// probed `expires_at + 1`, which cannot tell `<` from `<=`.
    #[tokio::test]
    async fn a_pending_login_is_expired_at_exactly_its_expiry() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_pending(&pool, &codec, &pending("edge")).await?;
        assert!(take_pending(&pool, &codec, "edge", NOW + 600)
            .await?
            .is_none());

        let (pool, codec) = db().await;
        put_pending(&pool, &codec, &pending("edge")).await?;
        assert!(take_pending(&pool, &codec, "edge", NOW + 599)
            .await?
            .is_some());
        Ok(())
    }

    /// An abandoned login — the user closes the tab after being redirected —
    /// leaves a row holding a sealed DPoP key. Without a sweep those accumulate
    /// forever, and on a publicly reachable login form that is an unbounded
    /// write primitive against the volume.
    #[tokio::test]
    async fn expired_pending_logins_are_swept() -> anyhow::Result<()> {
        let (pool, codec) = db().await;
        put_pending(&pool, &codec, &pending("old")).await?;
        let mut fresh = pending("fresh");
        fresh.expires_at = NOW + 3600;
        put_pending(&pool, &codec, &fresh).await?;

        assert_eq!(sweep_expired_pending(&pool, NOW + 700).await?, 1);
        assert!(take_pending(&pool, &codec, "old", NOW).await?.is_none());
        assert!(take_pending(&pool, &codec, "fresh", NOW).await?.is_some());
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

    /// The same downgrade check for sessions, which hold the LONG-LIVED tokens.
    /// Covering only `oauth_state` would leave an implementation that used
    /// `decrypt` instead of `decrypt_bound` here passing the whole suite.
    #[tokio::test]
    async fn an_unbound_session_ciphertext_is_refused() -> anyhow::Result<()> {
        for column in ["access_token", "refresh_token", "dpop_key_jwk"] {
            let (pool, codec) = db().await;
            put_session(&pool, &codec, &session()).await?;
            sqlx::query(leak(format!(
                "UPDATE oauth_session SET {column} = ? WHERE sub = ?"
            )))
            .bind(codec.encrypt("some-value"))
            .bind(DID)
            .execute(&pool)
            .await?;
            assert!(
                get_session(&pool, &codec, DID).await.is_err(),
                "an unbound value was accepted in `{column}`"
            );
        }
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
