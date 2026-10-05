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

/// Longest a sign-out will wait on the authorization server.
///
/// Sign-out is a foreground action a user is watching. Revocation is
/// best-effort by design, so the local delete must not be held behind an
/// unbounded wait on a server that may be down.
const REVOKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

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
    /// Longest to wait on the authorization server before giving up and signing
    /// out locally. Injectable so the deadline can be TESTED without a
    /// five-second test.
    pub deadline: std::time::Duration,
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
/// destroys — but it is BOUNDED. The whole design already treats a failed
/// revocation as acceptable, so making the user wait out a dead PDS's timeouts
/// to reach a delete that happens regardless is the wrong trade. Past the
/// deadline the attempt is abandoned and the local session goes.
pub async fn sign_out(
    pool: &sqlx::SqlitePool,
    codec: &super::crypto::Codec,
    http: &reqwest::Client,
    ctx: &RevokeContext<'_>,
    sub: &str,
    now: i64,
) -> Revocation {
    sign_out_with(pool, codec, sub, ctx.deadline, |session| async move {
        revoke_tokens(pool, http, ctx, &session, now).await
    })
    .await
}

/// [`sign_out`] with the revocation injected, so a row rotated mid-sign-out
/// can be simulated deterministically.
async fn sign_out_with<F, Fut>(
    pool: &sqlx::SqlitePool,
    codec: &super::crypto::Codec,
    sub: &str,
    deadline: std::time::Duration,
    mut revoke: F,
) -> Revocation
where
    F: FnMut(OAuthSession) -> Fut,
    Fut: std::future::Future<Output = Revocation>,
{
    // The outcome of the last attempt whose row then changed under it.
    let mut previous: Option<Revocation> = None;
    for _ in 0..MAX_SIGN_OUT_ATTEMPTS {
        let (session, version) = match super::store::get_session_versioned(pool, codec, sub).await {
            Ok(Some(read)) => read,
            // Gone — first time round, there was nothing to sign out; after
            // a `Changed`, someone else (a concurrent `/logout`) deleted it
            // once we had revoked what we read, so report that revocation.
            Ok(None) => return previous.unwrap_or(Revocation::NoSession),
            Err(err) => {
                // Still delete: an unreadable row is exactly the state a
                // sign-out should clear, and leaving it wedges every later
                // request. No refresh can rotate a row nothing can read.
                let _ = super::store::delete_session(pool, sub).await;
                return Revocation::Failed(format!("reading the session: {err:#}"));
            }
        };

        match bounded_then_delete(pool, sub, &version, deadline, revoke(session)).await {
            Attempt::Done(outcome) => return outcome,
            // Rotated (or removed) while we revoked: read again and revoke the
            // tokens that are actually on record now.
            Attempt::Changed(outcome) => previous = Some(outcome),
        }
    }
    // Still rotating. Leave the newest tokens IN PLACE — deleting them would
    // drop a live token unrevoked with no record left to retry from — and say
    // so, so the operator's sweep (or the user's next sign-out) can finish it.
    Revocation::Failed(format!(
        "the session kept changing while it was being signed out ({MAX_SIGN_OUT_ATTEMPTS} \
         attempts, each overtaken by a refresh); its newest tokens were left in place"
    ))
}

/// Revoke a token set that has NO local row to delete — bounded by
/// `ctx.deadline`, best-effort, never touching the store's sessions.
///
/// For tokens obtained for a session that was signed out while they were being
/// obtained: a refresh that finds its row deleted holds a live grant nobody
/// will ever use, and dropping it would leave it live at the PDS until expiry.
pub(crate) async fn revoke_orphaned(
    pool: &sqlx::SqlitePool,
    http: &reqwest::Client,
    ctx: &RevokeContext<'_>,
    session: &OAuthSession,
    now: i64,
) -> Revocation {
    match tokio::time::timeout(ctx.deadline, revoke_tokens(pool, http, ctx, session, now)).await {
        Ok(outcome) => outcome,
        Err(_) => Revocation::Failed(format!(
            "revocation did not finish within {:?}",
            ctx.deadline
        )),
    }
}

/// The deadline a background revocation (not a user's sign-out) waits for.
pub(crate) const ORPHAN_REVOKE_DEADLINE: std::time::Duration = REVOKE_DEADLINE;

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

/// Sign out, discovering the revocation endpoint from the session itself.
///
/// The endpoint lives in the authorization server's metadata, which is not
/// stored on the session — so it has to be fetched. That fetch is done only when
/// there IS a session to revoke: discovering first and finding nothing to do
/// would put a network round trip on every logout of a dev-DID or an
/// already-expired account.
///
/// A discovery failure is not fatal. It means the server cannot be told, which
/// is exactly the case [`sign_out`] already handles by deleting locally anyway.
pub async fn sign_out_discovering(
    runtime: &super::runtime::OauthRuntime,
    http: &reqwest::Client,
    pool: &sqlx::SqlitePool,
    sub: &str,
    now: i64,
) -> Revocation {
    let session = match super::store::get_session(pool, &runtime.codec, sub).await {
        Ok(Some(session)) => session,
        Ok(None) => return Revocation::NoSession,
        Err(err) => {
            // **Delete it anyway.** This early return used to skip the delete,
            // and `sign_out` was fixed for exactly that while this sibling was
            // not — the same one-instance-fixed, sibling-missed pattern twice
            // over.
            //
            // An unreadable row is not hypothetical: it is what every row
            // written before this branch's AAD change now is, and what rotating
            // `FEATHERREADER_OAUTH_ENCRYPTION_KEY` produces. Leaving it wedges
            // the account — every repo call reads the same row — and because
            // `purge_did_data` does not touch the OAuth tables, `POST
            // /account/delete` relies on this path to clear it. Returning early
            // here made "delete my account" leave the tokens behind.
            let _ = super::store::delete_session(pool, sub).await;
            return Revocation::Failed(format!("reading the session: {err:#}"));
        }
    };

    // **Discovery is bounded too**, and separately.
    //
    // Bounding only the revocation request left the real wait unbounded:
    // `discover` makes two guarded fetches, each with its own 30-second timeout,
    // so an unreachable PDS held a user's sign-out for a minute before the
    // five-second deadline even began.
    //
    // Bounded HERE rather than by wrapping the whole operation, so this function
    // still ENDS in a call to `sign_out` — which owns the contract that matters
    // (a bounded attempt, then a local delete whatever the server said) and is
    // where that contract is tested. Wrapping instead meant production stopped going
    // through `sign_out` at all, leaving three invariant tests aimed at a
    // function nothing called. Worst case is two deadlines, one per phase, which
    // is what independently bounding each phase costs.
    let endpoint = match tokio::time::timeout(
        REVOKE_DEADLINE,
        // **The missed sibling.** This posts the REFRESH TOKEN to whatever
        // `revocation_endpoint` comes back, and had no issuer check at all —
        // while the callback and refresh paths both had one, and the comment
        // that added them counted "the two instances" of a hole that had three.
        // A repointed PDS could take the refresh token AND leave the real grant
        // live, because the local row is deleted either way.
        super::discovery::discover(
            http,
            &session.aud,
            runtime.auth_method.as_str(),
            Some(&session.issuer),
        ),
    )
    .await
    {
        Ok(Ok(server)) => server.revocation_endpoint,
        Ok(Err(err)) => {
            tracing::warn!(%err, %sub, "could not discover the revocation endpoint");
            None
        }
        Err(_) => {
            tracing::warn!(%sub, "discovering the revocation endpoint timed out");
            None
        }
    };

    sign_out(
        pool,
        &runtime.codec,
        http,
        &RevokeContext {
            revocation_endpoint: endpoint.as_deref(),
            client_id: &runtime.client_id,
            auth_method: runtime.auth_method,
            client_key: runtime.client_key.as_ref(),
            deadline: REVOKE_DEADLINE,
        },
        sub,
        now,
    )
    .await
}

/// What an operator revoke-all did, per subject DID.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevokeAllReport {
    /// Revoked at the authorization server, and the local row deleted.
    pub revoked: Vec<String>,
    /// Listed, but gone by the time it was signed out (a concurrent `/logout`).
    pub no_session: Vec<String>,
    /// The server could not be told, with the reason. The local row is deleted
    /// regardless, so these tokens may stay live at the PDS until they expire.
    pub failed: Vec<(String, String)>,
    /// Subjects ABSENT from the first listing and found by a re-list — sessions
    /// created while the walk ran (a login on the still-serving app). A row
    /// that was there from the start and merely retried is not one of these.
    /// Each was signed out too; its outcome is in the lists above, which hold
    /// ONE final outcome per DID (a later pass overwrites an earlier one).
    pub late: Vec<String>,
}

/// Sign EVERY stored session out — the operator's fleet-wide revoke (#257).
///
/// Before this existed, a teardown on the `rust` backend wiped
/// `FEATHERREADER_DB` and with it every refresh token, unrevoked, leaving each
/// live at its PDS until it expired. This walks the store and runs each subject
/// through [`sign_out_discovering`] — the same function `/logout` and
/// `/account/delete` use, so it inherits that function's contract: a bounded
/// attempt at the server, then a local delete (of the version it revoked)
/// whatever the server said, including for a row that no longer decrypts.
///
/// **A failure does not stop the walk.** Every later session would otherwise be
/// left neither revoked nor deleted. Failures are collected with their reasons
/// so the operator can see which tokens may still be live.
///
/// Sequential on purpose: each sign-out is already deadline-bounded, and this
/// runs once, at a teardown, where a predictable request rate against each PDS
/// matters more than finishing a few seconds sooner.
///
/// Only listing the sessions can fail as a whole — in which case nothing has
/// been revoked or deleted, and the caller must not proceed to a wipe.
pub async fn revoke_all(
    runtime: &super::runtime::OauthRuntime,
    http: &reqwest::Client,
    pool: &sqlx::SqlitePool,
    clock: impl FnMut() -> i64,
) -> Result<RevokeAllReport> {
    revoke_all_with(pool, clock, |sub, now| async move {
        sign_out_discovering(runtime, http, pool, &sub, now).await
    })
    .await
}

/// Whether `runtime` is the production client — the only one that can revoke
/// production's sessions. The first check [`preflight`] makes.
///
/// An incomplete environment does not fail to build a runtime; it builds the
/// WRONG one. Without `FEATHERREADER_PUBLIC_URL`, `Config` falls back to
/// localhost, which is not production-like, so the production checks
/// (encryption key included) never run and the runtime comes up as atproto's
/// public dev client — possibly with the pass-through `Null` codec. Revoking
/// with that sends every token under the wrong `client_id` or fails to decrypt
/// every row, and each sign-out deletes its row anyway. So a run that will
/// touch stored sessions requires all three: the confidential client (a
/// non-loopback public URL), a real encryption codec, and the loaded key.
///
/// The `Null` codec needs its own check: it "decrypts" a ciphertext by
/// returning it unchanged, so the decrypt pre-flight would count production's
/// encrypted rows as readable.
pub fn fit_to_revoke(runtime: &super::runtime::OauthRuntime) -> Result<()> {
    let mut missing = Vec::new();
    if runtime.auth_method != AuthMethod::PrivateKeyJwt {
        missing.push(
            "the confidential client (FEATHERREADER_PUBLIC_URL is loopback or unset, so this \
             would revoke as the public dev client)",
        );
    }
    if matches!(runtime.codec, super::crypto::Codec::Null) {
        missing.push("an encryption key (FEATHERREADER_OAUTH_ENCRYPTION_KEY is unset)");
    }
    if runtime.client_key.is_none() {
        missing.push("the signing key (FEATHERREADER_OAUTH_KEY_PATH)");
    }
    if missing.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "not the production OAuth client — missing {}. Run this inside the app's own \
             environment",
            missing.join("; ")
        )
    }
}

/// Prove, BEFORE anything is signed out, that this process holds the
/// production client's real secrets — not merely a codec and a key file.
///
/// Every sign-out deletes its row whatever the PDS says, so a run with the
/// wrong secrets does not fail safe: it deletes every row unrevoked.
///
/// * **The encryption key.** A wrong or rotated
///   `FEATHERREADER_OAUTH_ENCRYPTION_KEY` decrypts nothing. If there are rows
///   and NONE decrypts, refuse. (Some readable and some not is a real store
///   with some unreadable rows; those cannot be revoked by anyone, and are
///   reported as failed by the walk.)
/// * **The signing key.** A relative `FEATHERREADER_OAUTH_KEY_PATH` run from
///   the wrong directory can load SOME key — one no PDS has. Its public half
///   must be in the JWKS the app actually serves at `jwks_url`. A mismatch
///   always refuses. A JWKS that cannot be fetched refuses too, except on the
///   post-stop `sweep`, where the app is stopped and cannot serve it.
///
/// With no sessions stored there is nothing to protect, and no check (or
/// network request) is made.
pub async fn preflight(
    runtime: &super::runtime::OauthRuntime,
    http: &reqwest::Client,
    pool: &sqlx::SqlitePool,
    jwks_url: &str,
    sweep: bool,
) -> Result<()> {
    let subs = super::store::list_session_subs(pool).await?;
    if subs.is_empty() {
        return Ok(());
    }

    // The client: confidential, a real codec, a loaded key.
    fit_to_revoke(runtime)?;

    // The encryption key: at least one row must decrypt.
    let mut readable = 0usize;
    for sub in &subs {
        if matches!(
            super::store::get_session(pool, &runtime.codec, sub).await,
            Ok(Some(_))
        ) {
            readable += 1;
        }
    }
    if readable == 0 {
        anyhow::bail!(
            "none of the {} stored session(s) decrypts with this \
             FEATHERREADER_OAUTH_ENCRYPTION_KEY — it is not the key the app wrote them \
             with (wrong, or rotated). Signing out would delete every row unrevoked",
            subs.len()
        );
    }

    // The signing key: its public half must be what the app serves.
    let key = runtime
        .client_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no client signing key is loaded"))?;
    let ours = key.thumbprint()?;
    let served = match super::fetch::get_json(http, jwks_url, super::fetch::JSON).await {
        Ok(doc) => doc,
        Err(err) if sweep => {
            tracing::warn!(
                %err,
                "sweep: the app's JWKS is unreachable (expected once the app is stopped); \
                 the signing key was checked on the main pass"
            );
            return Ok(());
        }
        Err(err) => {
            return Err(err.context(format!(
                "could not fetch the app's JWKS at {jwks_url} to confirm the signing key. \
                 The main pass runs while the app is serving, so this should be reachable; \
                 refusing rather than signing with a key no PDS may know"
            )));
        }
    };
    let matches = served
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .any(|jwk| {
            jwk.get("kid").and_then(serde_json::Value::as_str) == Some(key.kid())
                && super::keys::SigningKey::public_thumbprint_of(&jwk.to_string()).ok()
                    == Some(ours.clone())
        });
    if !matches {
        anyhow::bail!(
            "the loaded signing key (FEATHERREADER_OAUTH_KEY_PATH, kid {:?}) is not the key \
             the app serves at {jwks_url}. Every client assertion would be rejected and every \
             row deleted unrevoked. Point FEATHERREADER_OAUTH_KEY_PATH at the app's own key",
            key.kid()
        );
    }
    Ok(())
}

/// [`revoke_all`] with the per-session sign-out injected, so sessions that
/// appear DURING the walk can be simulated.
async fn revoke_all_with<S, Fut>(
    pool: &sqlx::SqlitePool,
    mut clock: impl FnMut() -> i64,
    mut sign_out: S,
) -> Result<RevokeAllReport>
where
    S: FnMut(String, i64) -> Fut,
    Fut: std::future::Future<Output = Revocation>,
{
    // The FINAL outcome per DID, in first-seen order: a later pass overwrites
    // an earlier one, so a DID that failed (left in place) and was then revoked
    // by the re-list is reported revoked — once — and not also failed.
    let mut order: Vec<String> = Vec::new();
    let mut outcomes: std::collections::HashMap<String, Revocation> = Default::default();
    // DIDs absent from the first listing: these appeared DURING the walk.
    let mut late: Vec<String> = Vec::new();

    let mut subs = super::store::list_session_subs(pool).await?;
    let initial: std::collections::HashSet<String> = subs.iter().cloned().collect();
    // The first walk, then up to RE_LIST_PASSES more over whatever is stored
    // AFTER it: sessions created (a login on the still-serving app) or left in
    // place (one that kept rotating) while the walk ran. Defence in depth — the
    // refresh no longer resurrects a deleted row, but a login legitimately
    // creates one.
    for pass in 0..=RE_LIST_PASSES {
        for sub in subs {
            if !outcomes.contains_key(&sub) {
                order.push(sub.clone());
                if !initial.contains(&sub) {
                    late.push(sub.clone());
                }
            }
            // Read the clock PER SESSION. `now` becomes the client assertion's
            // `iat`, and an assertion lives only 60 s: one timestamp taken at
            // the start would be expired for every session reached after the
            // first minute, so those revocations would all be rejected.
            let now = clock();
            let outcome = sign_out(sub.clone(), now).await;
            outcomes.insert(sub, outcome);
        }
        subs = super::store::list_session_subs(pool).await?;
        if subs.is_empty() {
            break;
        }
        if pass == RE_LIST_PASSES {
            // Out of passes and the store is still not empty: these sessions
            // are still on record, and possibly live, whatever the last
            // attempt said. A failure keeps its own reason.
            for sub in subs {
                if !outcomes.contains_key(&sub) {
                    order.push(sub.clone());
                }
                let entry = outcomes.entry(sub).or_insert(Revocation::NoSession);
                if !matches!(entry, Revocation::Failed(_)) {
                    *entry = Revocation::Failed(format!(
                        "still stored after {} passes (a login or refresh keeps \
                         re-creating it); not signed out",
                        RE_LIST_PASSES + 1
                    ));
                }
            }
            break;
        }
    }

    let mut report = RevokeAllReport {
        late,
        ..RevokeAllReport::default()
    };
    for sub in order {
        match outcomes.remove(&sub) {
            Some(Revocation::Revoked) => report.revoked.push(sub),
            Some(Revocation::NoSession) | None => report.no_session.push(sub),
            Some(Revocation::Failed(reason)) => report.failed.push((sub, reason)),
        }
    }
    Ok(report)
}

/// Extra walks [`revoke_all`] makes over sessions that appeared during the
/// previous one.
const RE_LIST_PASSES: usize = 2;

/// How many times a sign-out re-reads and re-revokes a session that a
/// concurrent refresh keeps rotating, before giving up and leaving the newest
/// tokens on record.
const MAX_SIGN_OUT_ATTEMPTS: usize = 3;

/// What one bounded attempt ended in.
#[derive(Debug)]
enum Attempt {
    /// The row that was revoked has been deleted (or the delete failed, which
    /// is reported in the outcome). Final.
    Done(Revocation),
    /// The row was rewritten or removed after it was read, so the revoked token
    /// was not the one on record. Nothing was deleted.
    Changed(Revocation),
}

/// Run `attempt` under `deadline`, then delete the local session — **whatever
/// the server said**, including when the deadline expired — provided the row
/// still holds the `version` that was revoked.
///
/// The single implementation of the sign-out contract, so there is no second
/// copy to drift. Separated out from [`sign_out`] so the bound can be tested
/// against a future that never resolves, rather than against a network address
/// that may be refused instantly in one environment and hang in another.
///
/// **Compare-and-delete, not delete.** A refresh can rotate the row between
/// the read and here (the live app refreshes under an in-process lock that
/// neither the operator's revoke-all nor a racing `/logout` holds). An
/// unconditional delete then removed the ROTATED token, which was never
/// revoked; the caller now re-reads and revokes that one instead.
async fn bounded_then_delete<F>(
    pool: &sqlx::SqlitePool,
    sub: &str,
    version: &super::store::SessionVersion,
    deadline: std::time::Duration,
    attempt: F,
) -> Attempt
where
    F: std::future::Future<Output = Revocation>,
{
    let outcome = match tokio::time::timeout(deadline, attempt).await {
        Ok(outcome) => outcome,
        Err(_) => Revocation::Failed(format!(
            "revocation did not finish within {deadline:?}; signing out locally anyway"
        )),
    };

    // Unconditional on the OUTCOME — the user asked to be logged out — but
    // conditional on the row being the one whose tokens were just revoked.
    match super::store::delete_session_if_unchanged(pool, sub, version).await {
        Ok(true) => Attempt::Done(outcome),
        Ok(false) => Attempt::Changed(outcome),
        Err(err) => Attempt::Done(Revocation::Failed(format!(
            "deleting the local session: {err:#}"
        ))),
    }
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

    /// A short deadline: the property under test is that the wait is BOUNDED,
    /// and proving that with the production five seconds would make the whole
    /// suite ten times slower for one assertion.
    const TEST_DEADLINE: std::time::Duration = std::time::Duration::from_millis(250);

    fn ctx(endpoint: Option<&str>) -> RevokeContext<'_> {
        RevokeContext {
            revocation_endpoint: endpoint,
            client_id: "http://localhost",
            auth_method: AuthMethod::None,
            client_key: None,
            deadline: TEST_DEADLINE,
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

    /// **A dead authorization server must not hold a sign-out open — and the
    /// bound must cover DISCOVERY, not just the revocation request.**
    ///
    /// Bounding only the request left the real wait unbounded: discovery makes
    /// two guarded fetches with a 30-second timeout each, so an unreachable PDS
    /// held the sign-out for a minute before the deadline began. The earlier
    /// version of this test missed that by exercising `sign_out` rather than the
    /// function production calls, and it reached the network to do it — so where
    /// outbound was refused it passed instantly, proving nothing.
    ///
    /// Exercised against a future that never resolves, with a short deadline:
    /// deterministic, no network, and it proves the bound rather than observing
    /// how long a particular host happens to take to refuse a connection.
    #[tokio::test]
    async fn a_hanging_attempt_does_not_hold_the_sign_out_open() {
        let (pool, codec) = db().await;
        stored(&pool, &codec).await;

        let (_, version) = super::super::store::get_session_versioned(&pool, &codec, DID)
            .await
            .unwrap()
            .unwrap();
        let started = std::time::Instant::now();
        let attempt = super::bounded_then_delete(
            &pool,
            DID,
            &version,
            std::time::Duration::from_millis(50),
            std::future::pending::<Revocation>(),
        )
        .await;
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the bound did not fire"
        );

        let Attempt::Done(outcome) = attempt else {
            panic!("the unchanged row was not deleted: {attempt:?}");
        };
        match &outcome {
            Revocation::Failed(reason) => assert!(
                reason.contains("did not finish within"),
                "failed for the wrong reason: {reason}"
            ),
            other => panic!("a never-resolving attempt must time out, got {other:?}"),
        }
        assert!(
            super::super::store::get_session(&pool, &codec, DID)
                .await
                .unwrap()
                .is_none(),
            "the session survived a timed-out revocation"
        );
    }

    /// **An UNREADABLE session row is still deleted.**
    ///
    /// A row whose bound context was altered no longer decrypts, so
    /// `get_session` returns an error. Returning early without deleting left
    /// that row in place — and because every repo call reads it, the account
    /// then failed on every page load with no way out but a sign-out that had
    /// just refused to clear it.
    #[tokio::test]
    async fn an_unreadable_session_is_still_signed_out() {
        let (pool, codec) = db().await;
        stored(&pool, &codec).await;

        // Break the AAD binding the way a tampered row would.
        sqlx::query("UPDATE oauth_session SET issuer = ? WHERE sub = ?")
            .bind("https://evil.example")
            .bind(DID)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            super::super::store::get_session(&pool, &codec, DID)
                .await
                .is_err(),
            "precondition: the row must be unreadable"
        );

        let outcome = sign_out(
            &pool,
            &codec,
            &reqwest::Client::new(),
            &ctx(Some("https://pds.example.com/oauth/revoke")),
            DID,
            NOW,
        )
        .await;
        assert!(matches!(outcome, Revocation::Failed(_)), "got {outcome:?}");

        let still_there: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oauth_session WHERE sub = ?")
                .bind(DID)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            still_there, 0,
            "an unreadable row survived a sign-out, so the account stays wedged"
        );
    }

    // ── the function production actually calls ───────────────────────────────

    /// A runtime whose codec matches the test database's, so a stored session is
    /// readable. Loopback public URL => a public client, so no key file.
    fn runtime() -> super::super::runtime::OauthRuntime {
        super::super::runtime::OauthRuntime::new(&crate::config::Config {
            repo_backend: crate::metrics::Backend::Rust,
            public_url: "http://127.0.0.1:8080".into(),
            oauth: crate::config::OauthConfig {
                encryption_key: Some(KEY.to_string()),
                ..crate::config::OauthConfig::default()
            },
            ..crate::config::Config::default()
        })
        .expect("the test runtime must build")
    }

    /// **`sign_out_discovering` is what `/logout` and `/account/delete` call,
    /// and it had no test of its own at all.**
    ///
    /// A mutation replacing this entire function with `return NoSession` — never
    /// revoking, never deleting — passed all 575 tests. Every sign-out invariant
    /// was pinned one layer below, on `sign_out`, which production reaches only
    /// through this wrapper.
    ///
    /// The PDS here is unreachable (loopback, refused by the SSRF guard), which
    /// is the case that matters: the local row must go even when the server
    /// cannot be told.
    #[tokio::test]
    async fn the_production_sign_out_deletes_the_session() {
        let (pool, codec) = db().await;
        stored(&pool, &codec).await;

        let outcome =
            sign_out_discovering(&runtime(), &reqwest::Client::new(), &pool, DID, NOW).await;

        assert!(
            matches!(outcome, Revocation::Failed(_)),
            "an unreachable PDS must not report success: {outcome:?}"
        );
        assert!(
            super::super::store::get_session(&pool, &codec, DID)
                .await
                .unwrap()
                .is_none(),
            "the production sign-out left the session behind"
        );
    }

    /// **An unreadable row is deleted by the production path too.**
    ///
    /// `sign_out` was fixed for this; its caller was not. The row is what every
    /// pre-AAD-change row now is, and what rotating the encryption key produces
    /// — and since `purge_did_data` does not touch the OAuth tables, `POST
    /// /account/delete` depends on this path to clear it.
    #[tokio::test]
    async fn the_production_sign_out_deletes_an_unreadable_session() {
        let (pool, codec) = db().await;
        stored(&pool, &codec).await;
        sqlx::query("UPDATE oauth_session SET issuer = ? WHERE sub = ?")
            .bind("https://evil.example")
            .bind(DID)
            .execute(&pool)
            .await
            .unwrap();

        let outcome =
            sign_out_discovering(&runtime(), &reqwest::Client::new(), &pool, DID, NOW).await;
        assert!(matches!(outcome, Revocation::Failed(_)), "got {outcome:?}");

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_session WHERE sub = ?")
            .bind(DID)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "account deletion would leave live tokens behind");
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

    // ── the operator revoke-all ──────────────────────────────────────────────

    /// The three subjects the revoke-all tests store, in the order
    /// `list_session_subs` returns them (sorted), which is the order the
    /// revocation requests are made in.
    const SUBS: [&str; 3] = [
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
        "did:plc:cccccccccccccccccccccccc",
    ];

    /// A PDS + authorization server on one real-TLS loopback server, whose
    /// metadata advertises `/revoke`, answering successive revocations with
    /// `revoke_replies` in turn (the last repeats).
    async fn revoking_server(
        revoke_replies: Vec<crate::net::TestResponse>,
    ) -> (
        String,
        String,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        let (addr, log) = crate::net::spawn_tls(move |addr| {
            let port = addr.port();
            let pds = format!("https://pds-e2e.test:{port}");
            let issuer = format!("https://as-e2e.test:{port}");
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
                        "revocation_endpoint": format!("{issuer}/revoke"),
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
            r.insert("/revoke".to_string(), revoke_replies);
            r
        })
        .await;
        for h in ["pds-e2e.test", "as-e2e.test"] {
            crate::net::test_host_override(h, addr);
        }
        let port = addr.port();
        (
            format!("https://pds-e2e.test:{port}"),
            format!("https://as-e2e.test:{port}"),
            log,
        )
    }

    /// Store one readable session per subject in [`SUBS`], against `pds`/`issuer`.
    async fn store_sessions(
        pool: &sqlx::SqlitePool,
        codec: &super::super::crypto::Codec,
        pds: &str,
        issuer: &str,
    ) {
        for sub in SUBS {
            let key = super::super::keys::SigningKey::generate("session");
            let session = OAuthSession {
                sub: sub.into(),
                issuer: issuer.into(),
                aud: pds.into(),
                dpop_key_jwk: key.to_jwk_json().unwrap(),
                ..session("access-abc", &format!("refresh-{sub}"))
            };
            super::super::store::put_session(pool, codec, &session)
                .await
                .unwrap();
        }
    }

    async fn session_rows(pool: &sqlx::SqlitePool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_session")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    fn revoke_requests(log: &std::sync::Mutex<Vec<String>>) -> Vec<String> {
        log.lock()
            .unwrap()
            .iter()
            .filter(|r| r.starts_with("POST /revoke"))
            .cloned()
            .collect()
    }

    /// **Every stored session is revoked at its server, and every row goes.**
    ///
    /// The operator path a teardown runs before wiping the database. Each
    /// revocation must actually reach the server — a revoke-all that only
    /// deleted rows would leave every refresh token live at the PDS, which is
    /// the bug this exists to close (#257).
    #[tokio::test]
    async fn revoke_all_revokes_every_session_at_its_server() {
        let (pool, codec) = db().await;
        let (pds, issuer, log) =
            revoking_server(vec![crate::net::TestResponse::json(200, "{}")]).await;
        store_sessions(&pool, &codec, &pds, &issuer).await;

        let report = revoke_all(&runtime(), &reqwest::Client::new(), &pool, || NOW)
            .await
            .expect("listing the sessions");

        let requests = revoke_requests(&log);
        assert_eq!(
            requests.len(),
            3,
            "one revocation request per session:\n{requests:#?}"
        );
        for sub in SUBS {
            assert!(
                requests
                    .iter()
                    .any(|r| r.contains(&format!("token=refresh-{}", sub.replace(':', "%3A")))),
                "{sub}'s refresh token was never presented:\n{requests:#?}"
            );
        }
        assert_eq!(report.revoked, SUBS.map(String::from).to_vec());
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert!(report.no_session.is_empty());
        assert_eq!(session_rows(&pool).await, 0, "rows survived a revoke-all");
    }

    /// **One server failing does not stop the rest — and its row still goes.**
    ///
    /// Aborting at the first failure would leave every later session neither
    /// revoked nor deleted. The failure is reported with its reason so the
    /// operator knows which tokens may still be live.
    #[tokio::test]
    async fn one_failed_revocation_is_reported_and_the_rest_still_revoked() {
        let (pool, codec) = db().await;
        let (pds, issuer, log) = revoking_server(vec![
            crate::net::TestResponse::json(200, "{}"),
            crate::net::TestResponse::json(500, "{}"),
            crate::net::TestResponse::json(200, "{}"),
        ])
        .await;
        store_sessions(&pool, &codec, &pds, &issuer).await;

        let report = revoke_all(&runtime(), &reqwest::Client::new(), &pool, || NOW)
            .await
            .expect("listing the sessions");

        assert_eq!(revoke_requests(&log).len(), 3, "a failure stopped the walk");
        assert!(
            report.late.is_empty(),
            "the first walk missed sessions a re-list had to find: {:?}",
            report.late
        );
        assert_eq!(
            report.revoked,
            vec![SUBS[0].to_string(), SUBS[2].to_string()]
        );
        assert_eq!(report.failed.len(), 1, "{:?}", report.failed);
        assert_eq!(report.failed[0].0, SUBS[1]);
        assert!(
            report.failed[0].1.contains("status 500"),
            "the reason was lost: {}",
            report.failed[0].1
        );
        assert_eq!(
            session_rows(&pool).await,
            0,
            "the failed session's row survived — the wipe would be the only thing removing it"
        );
    }

    /// An unreadable row is reported as a failure AND deleted; an empty store
    /// is an empty report.
    #[tokio::test]
    async fn an_unreadable_row_fails_and_is_deleted_and_an_empty_store_is_empty() {
        let (pool, codec) = db().await;
        let report = revoke_all(&runtime(), &reqwest::Client::new(), &pool, || NOW)
            .await
            .unwrap();
        assert_eq!(report, RevokeAllReport::default());

        stored(&pool, &codec).await;
        sqlx::query("UPDATE oauth_session SET issuer = ? WHERE sub = ?")
            .bind("https://evil.example")
            .bind(DID)
            .execute(&pool)
            .await
            .unwrap();

        let report = revoke_all(&runtime(), &reqwest::Client::new(), &pool, || NOW)
            .await
            .unwrap();
        assert!(report.revoked.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, DID);
        assert!(
            report.failed[0].1.contains("reading the session"),
            "{}",
            report.failed[0].1
        );
        assert_eq!(session_rows(&pool).await, 0, "the unreadable row survived");
    }

    /// A CONFIDENTIAL client runtime (non-loopback public URL), with its
    /// signing key in a per-test temp file rather than the working directory.
    fn confidential_runtime(tag: &str) -> super::super::runtime::OauthRuntime {
        super::super::runtime::OauthRuntime::new(&crate::config::Config {
            repo_backend: crate::metrics::Backend::Rust,
            public_url: "https://feather-reader.com".into(),
            oauth: crate::config::OauthConfig {
                encryption_key: Some(KEY.to_string()),
                key_path: std::env::temp_dir().join(format!(
                    "fr-revoke-test-key-{}-{tag}.json",
                    std::process::id()
                )),
                plc_directory: "https://plc.invalid".to_string(),
                ..crate::config::OauthConfig::default()
            },
            ..crate::config::Config::default()
        })
        .expect("the confidential test runtime must build")
    }

    /// The `iat` of the client assertion in one recorded revocation request.
    fn assertion_iat(raw: &str) -> i64 {
        use base64::Engine as _;
        let body = raw.split("\r\n\r\n").nth(1).expect("no request body");
        let jwt = body
            .split('&')
            .find_map(|kv| kv.strip_prefix("client_assertion="))
            .unwrap_or_else(|| panic!("no client_assertion in {body}"));
        let payload = jwt.split('.').nth(1).expect("malformed assertion");
        let json: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .expect("assertion payload is not base64url"),
        )
        .expect("assertion payload is not JSON");
        json["iat"].as_i64().expect("assertion has no iat")
    }

    /// **Each revocation's client assertion is minted at ITS OWN time.**
    ///
    /// A client assertion lives 60 s (`exp = iat + 60`). Taking one `now` at
    /// the start of the walk and reusing it meant that once the walk passed a
    /// minute — a few hundred sessions, or a handful of slow PDSes at the
    /// five-second deadline — every later assertion was already expired when
    /// sent. Each of those revocations is rejected as `invalid_client`, the row
    /// is deleted anyway, and the teardown proceeds over live tokens.
    ///
    /// The clock here advances 100 s per reading, so a stale `now` shows up as
    /// three identical `iat`s.
    #[tokio::test]
    async fn each_revocation_takes_the_time_afresh() {
        let (pool, codec) = db().await;
        let (pds, issuer, log) =
            revoking_server(vec![crate::net::TestResponse::json(200, "{}")]).await;
        store_sessions(&pool, &codec, &pds, &issuer).await;

        let mut tick = 0;
        let clock = || {
            let t = NOW + tick * 100;
            tick += 1;
            t
        };
        let report = revoke_all(
            &confidential_runtime("clock"),
            &reqwest::Client::new(),
            &pool,
            clock,
        )
        .await
        .expect("listing the sessions");
        assert_eq!(report.revoked.len(), 3, "{report:?}");

        let iats: Vec<i64> = revoke_requests(&log)
            .iter()
            .map(|r| assertion_iat(r))
            .collect();
        assert_eq!(
            iats,
            vec![NOW, NOW + 100, NOW + 200],
            "the assertions reused one timestamp — later ones would be expired on arrival"
        );
    }

    // ── a refresh racing the sign-out ────────────────────────────────────────

    /// Store a session with refresh token `refresh` under a fresh codec — what
    /// the live app's refresh does, from its own process, with the same key.
    async fn rotate_to(pool: &sqlx::SqlitePool, refresh: &str) {
        let codec = super::super::crypto::Codec::new(Some(KEY)).unwrap();
        let key = super::super::keys::SigningKey::generate("session");
        let session = OAuthSession {
            dpop_key_jwk: key.to_jwk_json().unwrap(),
            ..session("access-rotated", refresh)
        };
        super::super::store::put_session(pool, &codec, &session)
            .await
            .unwrap();
    }

    type Seen = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

    /// **A refresh that rotates the row mid-sign-out gets ITS token revoked
    /// too — and the new token's row is never deleted unrevoked.**
    ///
    /// The live app refreshes under an in-process lock the operator's
    /// revoke-all (a separate process) cannot take. The sign-out read R1; the
    /// app rotated to R2; the PDS answers 200 for the already-rotated R1; and
    /// an unconditional delete then removed the row holding R2 — reported as
    /// revoked, never revoked, and gone from the record the post-stop sweep
    /// reads. The same interleaving reaches `/logout` against a request's
    /// background refresh, which takes that lock while `/logout` does not.
    #[tokio::test]
    async fn a_session_rotated_mid_sign_out_has_the_new_token_revoked_too() {
        let (pool, codec) = db().await;
        stored(&pool, &codec).await;
        let seen: Seen = Default::default();

        let outcome = sign_out_with(&pool, &codec, DID, TEST_DEADLINE, |s| {
            let (pool, seen) = (pool.clone(), seen.clone());
            async move {
                let first = {
                    let mut v = seen.lock().unwrap();
                    v.push(s.refresh_token.clone());
                    v.len() == 1
                };
                if first {
                    // The app's refresh lands between our read and our delete.
                    rotate_to(&pool, "refresh-R2").await;
                }
                Revocation::Revoked
            }
        })
        .await;

        assert_eq!(
            *seen.lock().unwrap(),
            vec!["refresh-xyz".to_string(), "refresh-R2".to_string()],
            "the rotated token was never presented for revocation"
        );
        assert_eq!(outcome, Revocation::Revoked);
        assert!(
            super::super::store::get_session(&pool, &codec, DID)
                .await
                .unwrap()
                .is_none(),
            "the session survived a sign-out that revoked every version of it"
        );
    }

    /// A row that keeps rotating is given up on after a bounded number of
    /// attempts — reported as a failure, and the LATEST token left on record
    /// (so a later pass can revoke it) rather than deleted unrevoked.
    #[tokio::test]
    async fn a_session_that_keeps_rotating_is_reported_and_left_in_place() {
        let (pool, codec) = db().await;
        stored(&pool, &codec).await;
        let seen: Seen = Default::default();

        let outcome = sign_out_with(&pool, &codec, DID, TEST_DEADLINE, |s| {
            let (pool, seen) = (pool.clone(), seen.clone());
            async move {
                let n = {
                    let mut v = seen.lock().unwrap();
                    v.push(s.refresh_token.clone());
                    v.len()
                };
                rotate_to(&pool, &format!("refresh-R{}", n + 1)).await;
                Revocation::Revoked
            }
        })
        .await;

        let attempts = seen.lock().unwrap().len();
        assert_eq!(attempts, 3, "the retries were not bounded at 3");
        match &outcome {
            Revocation::Failed(reason) => assert!(
                reason.contains("kept changing"),
                "failed for the wrong reason: {reason}"
            ),
            other => panic!("a still-rotating session must not report success: {other:?}"),
        }
        let left = super::super::store::get_session(&pool, &codec, DID)
            .await
            .unwrap()
            .expect("the newest token was deleted unrevoked");
        assert_eq!(left.refresh_token, "refresh-R4");
    }

    // ── sessions that appear during the walk ─────────────────────────────────

    async fn insert_raw(pool: &sqlx::SqlitePool, sub: &str) {
        sqlx::query(
            "INSERT OR REPLACE INTO oauth_session (sub, issuer, aud, dpop_key_jwk, \
             access_token, refresh_token, token_type, granted_scope, expires_at) \
             VALUES (?, 'https://as.invalid', 'https://pds.invalid', 'x', 'x', 'x', \
             'DPoP', 'atproto', NULL)",
        )
        .bind(sub)
        .execute(pool)
        .await
        .unwrap();
    }

    /// **A session created during the walk is found and signed out too.**
    ///
    /// The main pass runs while the app still serves (it must — the PDSes
    /// fetch our client metadata to authenticate the revocation), so a login
    /// can land behind the walk's cursor. Defence in depth: after the walk the
    /// store is listed again, and anything new is walked as well.
    #[tokio::test]
    async fn a_session_created_during_the_walk_is_signed_out_by_a_re_list() {
        let (pool, _) = db().await;
        insert_raw(&pool, SUBS[0]).await;
        let calls: Seen = Default::default();

        let report = revoke_all_with(
            &pool,
            || NOW,
            |sub, _| {
                let (pool, calls) = (pool.clone(), calls.clone());
                async move {
                    let first = {
                        let mut c = calls.lock().unwrap();
                        c.push(sub.clone());
                        c.len() == 1
                    };
                    if first {
                        // A user logs in while the first session is revoked.
                        insert_raw(&pool, SUBS[1]).await;
                    }
                    super::super::store::delete_session(&pool, &sub)
                        .await
                        .unwrap();
                    Revocation::Revoked
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(
            *calls.lock().unwrap(),
            vec![SUBS[0].to_string(), SUBS[1].to_string()],
            "the session created mid-walk was never signed out"
        );
        assert_eq!(report.late, vec![SUBS[1].to_string()]);
        assert_eq!(report.revoked.len(), 2);
        assert_eq!(session_rows(&pool).await, 0);
    }

    /// The re-list is bounded: a store that keeps refilling is walked at most
    /// twice more, and what remains is reported as FAILED (so the exit code
    /// and the teardown say so) rather than looping forever.
    #[tokio::test]
    async fn the_re_list_is_bounded_and_reports_what_remains() {
        let (pool, _) = db().await;
        insert_raw(&pool, SUBS[0]).await;
        let calls: Seen = Default::default();

        let report = revoke_all_with(
            &pool,
            || NOW,
            |sub, _| {
                let calls = calls.clone();
                async move {
                    calls.lock().unwrap().push(sub);
                    // Never removed: it keeps coming back.
                    Revocation::Revoked
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(
            calls.lock().unwrap().len(),
            3,
            "not bounded at 1 + 2 passes"
        );
        let still = report
            .failed
            .iter()
            .find(|(sub, _)| sub == SUBS[0])
            .expect("a session still stored after every pass was not reported");
        assert!(still.1.contains("still stored"), "{}", still.1);
        assert_eq!(
            report.failed.len(),
            1,
            "one entry per DID: {:?}",
            report.failed
        );
        assert!(
            report.revoked.is_empty(),
            "a DID still stored at the end was ALSO reported revoked: {:?}",
            report.revoked
        );
        assert!(
            report.late.is_empty(),
            "a row present from the start is not one that appeared during the walk"
        );
    }

    /// **The report is the FINAL outcome per DID.** A session that fails in
    /// the first pass (left in place — it kept rotating) and is revoked by the
    /// re-list is revoked: reporting it as failed too made the run exit 3 and
    /// warn that its tokens "may stay live" when they had been revoked. And a
    /// row there from the start is not "late".
    #[tokio::test]
    async fn a_did_that_fails_then_succeeds_is_reported_revoked_only() {
        let (pool, _) = db().await;
        insert_raw(&pool, SUBS[0]).await;
        let calls: Seen = Default::default();

        let report = revoke_all_with(
            &pool,
            || NOW,
            |sub, _| {
                let (pool, calls) = (pool.clone(), calls.clone());
                async move {
                    let n = {
                        let mut c = calls.lock().unwrap();
                        c.push(sub.clone());
                        c.len()
                    };
                    if n == 1 {
                        // Kept rotating: left in place, reported failed.
                        return Revocation::Failed("kept changing".into());
                    }
                    super::super::store::delete_session(&pool, &sub)
                        .await
                        .unwrap();
                    Revocation::Revoked
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(calls.lock().unwrap().len(), 2);
        assert_eq!(report.revoked, vec![SUBS[0].to_string()]);
        assert!(
            report.failed.is_empty(),
            "a DID revoked by the re-list is still reported failed: {:?}",
            report.failed
        );
        assert!(
            report.late.is_empty(),
            "mislabelled as late: {:?}",
            report.late
        );
    }

    /// **One failure does not end the first walk.** Each failing session here
    /// is still deleted (as a real sign-out does), so a walk that stopped at
    /// the first failure and left the rest to the re-list would get through
    /// only three of four sessions before running out of passes — and report
    /// the fourth "still stored", never attempted.
    #[tokio::test]
    async fn every_session_is_attempted_in_the_first_walk_despite_failures() {
        let (pool, _) = db().await;
        let subs = [
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
            "did:plc:cccccccccccccccccccccccc",
            "did:plc:dddddddddddddddddddddddd",
        ];
        for sub in subs {
            insert_raw(&pool, sub).await;
        }

        let report = revoke_all_with(
            &pool,
            || NOW,
            |sub, _| {
                let pool = pool.clone();
                async move {
                    super::super::store::delete_session(&pool, &sub)
                        .await
                        .unwrap();
                    Revocation::Failed("the PDS said no".into())
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(report.failed.len(), 4, "{:?}", report.failed);
        assert!(
            report
                .failed
                .iter()
                .all(|(_, reason)| reason == "the PDS said no"),
            "a session was never attempted: {:?}",
            report.failed
        );
    }

    /// A DID that fails in every pass is ONE failed entry, with the last
    /// reason — not one per pass.
    #[tokio::test]
    async fn a_did_that_fails_every_pass_is_one_failed_entry() {
        let (pool, _) = db().await;
        insert_raw(&pool, SUBS[0]).await;

        let report = revoke_all_with(
            &pool,
            || NOW,
            |_, _| async { Revocation::Failed("kept changing".into()) },
        )
        .await
        .unwrap();

        assert_eq!(
            report.failed.len(),
            1,
            "the same DID was counted once per pass: {:?}",
            report.failed
        );
        assert_eq!(report.failed[0].0, SUBS[0]);
        assert!(report.revoked.is_empty() && report.late.is_empty());
    }

    /// A row that disappears mid-sign-out (a concurrent `/logout`) is not an
    /// error and not retried: the token that was read has been revoked, and
    /// there is nothing left to delete.
    #[tokio::test]
    async fn a_session_deleted_mid_sign_out_reports_the_revocation() {
        let (pool, codec) = db().await;
        stored(&pool, &codec).await;
        let seen: Seen = Default::default();

        let outcome = sign_out_with(&pool, &codec, DID, TEST_DEADLINE, |s| {
            let (pool, seen) = (pool.clone(), seen.clone());
            async move {
                seen.lock().unwrap().push(s.refresh_token.clone());
                super::super::store::delete_session(&pool, DID)
                    .await
                    .unwrap();
                Revocation::Revoked
            }
        })
        .await;
        assert_eq!(outcome, Revocation::Revoked);
        assert_eq!(seen.lock().unwrap().len(), 1, "retried a row that was gone");
    }

    // ── the pre-flight: the secrets are the production ones ──────────────────

    /// A JWKS server over real TLS serving `doc` at `/oauth/jwks.json` (or
    /// nothing, when `doc` is `None`). Returns the URL to check.
    async fn jwks_server(doc: Option<String>) -> String {
        let (addr, _log) = crate::net::spawn_tls(move |_| {
            let mut r = std::collections::HashMap::new();
            if let Some(doc) = doc {
                r.insert(
                    "/oauth/jwks.json".to_string(),
                    vec![crate::net::TestResponse::json(200, doc)],
                );
            }
            r
        })
        .await;
        crate::net::test_host_override("pds-e2e.test", addr);
        format!("https://pds-e2e.test:{}/oauth/jwks.json", addr.port())
    }

    async fn pool_with_readable_session(codec_key: &str) -> sqlx::SqlitePool {
        let (pool, _) = db().await;
        let codec = super::super::crypto::Codec::new(Some(codec_key)).unwrap();
        stored(&pool, &codec).await;
        pool
    }

    /// **A wrong (or rotated) encryption key is refused before anything is
    /// signed out.** It decrypts nothing, so every sign-out would hit an
    /// unreadable row — and delete it. The run "completed", the teardown
    /// wiped, and every token was dropped unrevoked.
    #[tokio::test]
    async fn a_wrong_encryption_key_is_refused_by_the_preflight() {
        let rt = confidential_runtime("wrongenc");
        let other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let pool = pool_with_readable_session(other).await;
        let url = jwks_server(Some(
            rt.client_key
                .as_ref()
                .unwrap()
                .jwks_document()
                .unwrap()
                .to_string(),
        ))
        .await;

        let err = preflight(&rt, &reqwest::Client::new(), &pool, &url, false)
            .await
            .expect_err("a key that decrypts nothing was accepted");
        assert!(format!("{err:#}").contains("ENCRYPTION_KEY"), "{err:#}");
        assert_eq!(
            session_rows(&pool).await,
            1,
            "the preflight deleted something"
        );
    }

    /// Some rows readable and some not is a real store with a few unreadable
    /// rows (which the walk reports as failed) — not a wrong key.
    #[tokio::test]
    async fn some_unreadable_rows_do_not_fail_the_preflight() {
        let rt = confidential_runtime("someunread");
        let pool = pool_with_readable_session(KEY).await;
        insert_raw(&pool, SUBS[1]).await;
        let url = jwks_server(Some(
            rt.client_key
                .as_ref()
                .unwrap()
                .jwks_document()
                .unwrap()
                .to_string(),
        ))
        .await;
        preflight(&rt, &reqwest::Client::new(), &pool, &url, false)
            .await
            .expect("one readable row proves the key");
    }

    /// The loaded signing key must be the one the app SERVES. A different
    /// key — a relative key path resolved in the wrong directory — signs
    /// assertions no PDS can verify, and every row would be deleted unrevoked.
    /// Refused on the sweep too: a fetched mismatch is never "expected".
    #[tokio::test]
    async fn a_signing_key_the_app_does_not_serve_is_refused() {
        let rt = confidential_runtime("wrongsig");
        let pool = pool_with_readable_session(KEY).await;
        let stranger = super::super::keys::SigningKey::generate(super::super::runtime::CLIENT_KID);
        let url = jwks_server(Some(stranger.jwks_document().unwrap().to_string())).await;

        for sweep in [false, true] {
            let err = preflight(&rt, &reqwest::Client::new(), &pool, &url, sweep)
                .await
                .expect_err("a signing key the PDSes have never seen was accepted");
            assert!(format!("{err:#}").contains("not the key"), "{err:#}");
        }
        assert_eq!(session_rows(&pool).await, 1);
    }

    /// The matching key passes.
    #[tokio::test]
    async fn the_served_signing_key_passes_the_preflight() {
        let rt = confidential_runtime("rightsig");
        let pool = pool_with_readable_session(KEY).await;
        let url = jwks_server(Some(
            rt.client_key
                .as_ref()
                .unwrap()
                .jwks_document()
                .unwrap()
                .to_string(),
        ))
        .await;
        preflight(&rt, &reqwest::Client::new(), &pool, &url, false)
            .await
            .expect("the served key was refused");
    }

    /// An unreachable JWKS refuses the main pass (the app is meant to be up)
    /// but not the post-stop sweep (it is meant to be down).
    #[tokio::test]
    async fn an_unreachable_jwks_refuses_the_main_pass_but_not_the_sweep() {
        let rt = confidential_runtime("nojwks");
        let pool = pool_with_readable_session(KEY).await;
        let url = jwks_server(None).await;

        let err = preflight(&rt, &reqwest::Client::new(), &pool, &url, false)
            .await
            .expect_err("an unverifiable signing key was accepted on the main pass");
        assert!(format!("{err:#}").contains("could not fetch"), "{err:#}");
        preflight(&rt, &reqwest::Client::new(), &pool, &url, true)
            .await
            .expect("the sweep cannot reach a stopped app's JWKS, and must not need to");
    }

    /// **The `Null` codec is refused even though everything else passes.** It
    /// "decrypts" by returning the stored value unchanged, so every row looks
    /// readable to the decrypt check; the served key matches. Only the fitness
    /// check stands between it and revoking with ciphertext for tokens.
    #[tokio::test]
    async fn a_null_codec_runtime_is_refused_even_when_the_rest_passes() {
        let rt = super::super::runtime::OauthRuntime::new(&crate::config::Config {
            repo_backend: crate::metrics::Backend::Rust,
            public_url: "https://feather-reader.com".into(),
            oauth: crate::config::OauthConfig {
                encryption_key: None,
                key_path: std::env::temp_dir().join(format!(
                    "fr-revoke-test-key-{}-nullcodec.json",
                    std::process::id()
                )),
                plc_directory: "https://plc.invalid".to_string(),
                ..crate::config::OauthConfig::default()
            },
            ..crate::config::Config::default()
        })
        .unwrap();
        assert!(matches!(rt.codec, super::super::crypto::Codec::Null));
        let (pool, _) = db().await;
        stored(&pool, &rt.codec).await;
        let url = jwks_server(Some(
            rt.client_key
                .as_ref()
                .unwrap()
                .jwks_document()
                .unwrap()
                .to_string(),
        ))
        .await;

        let err = preflight(&rt, &reqwest::Client::new(), &pool, &url, false)
            .await
            .expect_err("the Null codec was accepted");
        assert!(format!("{err:#}").contains("encryption key"), "{err:#}");
    }

    /// With nothing stored there is nothing to protect: no check, no request.
    #[tokio::test]
    async fn an_empty_store_needs_no_preflight() {
        let rt = confidential_runtime("emptypre");
        let (pool, _) = db().await;
        preflight(
            &rt,
            &reqwest::Client::new(),
            &pool,
            "https://unreachable.invalid/oauth/jwks.json",
            false,
        )
        .await
        .expect("an empty store was refused");
    }
}
