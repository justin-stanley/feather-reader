//! DPoP-bound `com.atproto.repo.*` calls against the user's PDS.
//!
//! The layer the 31-method reader surface is built on. It returns the same
//! [`RecordEntry`] / [`WriteResult`] / [`WriteOp`] types the existing
//! [`crate::atproto`] client does, so the typed wrappers above it (subscriptions,
//! folders, saved, read-state) transfer at cutover rather than being rewritten.
//!
//! Two properties that are not obvious from the call shapes:
//!
//! * **The PDS comes from the session's `aud`**, never re-derived per call. It
//!   is a property of the token set — a token is valid at one PDS — and it is
//!   AAD-bound in the session row precisely so it cannot be repointed.
//! * **Every request carries both the proof and the token.** A resource request
//!   is `Authorization: DPoP <token>` plus a `DPoP` proof whose `ath` binds to
//!   that token; either alone is useless.

use anyhow::{bail, Context as _, Result};
use reqwest::Client;
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::SqlitePool;

use crate::atproto::{RecordEntry, WriteOp, WriteResult};

use super::dpop::Endpoint;
use super::keys::SigningKey;
use super::request::{self, DpopBody, DpopRequest, Retry};
use super::store::OAuthSession;

/// Cap on how many pages `list_all_records` will walk.
///
/// The same bound the existing client uses: a repo is user-controlled, and an
/// unbounded walk is a denial-of-service against ourselves.
const MAX_LIST_PAGES: usize = 50;

/// An authenticated handle on one account's repo.
pub struct Repo<'a> {
    pub http: &'a Client,
    pub pool: &'a SqlitePool,
    pub session: &'a OAuthSession,
    /// The session's DPoP key, already unsealed.
    pub key: &'a SigningKey,
}

impl Repo<'_> {
    /// The XRPC endpoint for a method, on THIS session's PDS.
    fn url(&self, nsid: &str) -> String {
        format!("{}/xrpc/{nsid}", self.session.aud.trim_end_matches('/'))
    }

    /// Send, and fail loudly on a non-2xx with the XRPC error if there is one.
    async fn send(&self, url: &str, body: DpopBody<'_>, nsid: &str) -> Result<Value> {
        let outcome = request::send_with_dpop(
            self.http,
            self.pool,
            &DpopRequest {
                endpoint: Endpoint::ResourceServer,
                url,
                key: self.key,
                access_token: Some(&self.session.access_token),
                body,
                // A repo call is safe to repeat on a nonce challenge: the PDS
                // has not acted on a request it answered with a challenge.
                retry: Retry::Allowed,
            },
        )
        .await?;

        if !outcome.is_success() {
            bail!(
                "{nsid} failed: {}",
                xrpc_error(&outcome.body, outcome.status)
            );
        }
        // A 200 with an empty body is legitimate for deleteRecord/applyWrites.
        if outcome.body.is_empty() {
            return Ok(Value::Null);
        }
        outcome.json()
    }

    /// Render an XRPC error body for a message.
    ///
    /// Only ever called on a NON-success, where the body is an error document
    /// rather than a token or a record — and even then only the `error` and
    /// `message` fields, never the raw bytes.
    fn error_fields(body: &[u8]) -> Option<String> {
        let value: Value = serde_json::from_slice(body).ok()?;
        let kind = value.get("error").and_then(Value::as_str)?;
        match value.get("message").and_then(Value::as_str) {
            Some(message) => Some(format!("{kind}: {message}")),
            None => Some(kind.to_string()),
        }
    }

    /// One page of a collection.
    pub async fn list_records(
        &self,
        collection: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<(Vec<RecordEntry>, Option<String>)> {
        let mut url = url::Url::parse(&self.url("com.atproto.repo.listRecords"))
            .context("building the listRecords URL")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("repo", &self.session.sub);
            query.append_pair("collection", collection);
            if let Some(limit) = limit {
                query.append_pair("limit", &limit.to_string());
            }
            if let Some(cursor) = cursor {
                query.append_pair("cursor", cursor);
            }
        }

        let value = self
            .send(
                url.as_str(),
                DpopBody::Query,
                "com.atproto.repo.listRecords",
            )
            .await?;
        let records: Vec<RecordEntry> = serde_json::from_value(
            value
                .get("records")
                .cloned()
                .unwrap_or(Value::Array(vec![])),
        )
        .context("listRecords returned records this client cannot parse")?;
        let cursor = value
            .get("cursor")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok((records, cursor))
    }

    /// Every record in a collection, following the cursor.
    ///
    /// Bounded at [`MAX_LIST_PAGES`]: the repo is user-controlled, so an
    /// unbounded walk is a denial-of-service against ourselves. A cursor that
    /// does not advance also terminates the walk rather than spinning.
    pub async fn list_all_records(&self, collection: &str) -> Result<Vec<RecordEntry>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;

        for _ in 0..MAX_LIST_PAGES {
            let (page, next) = self
                .list_records(collection, Some(100), cursor.as_deref())
                .await?;
            out.extend(page);
            match next {
                // A server that repeats a cursor would otherwise loop forever.
                Some(next) if Some(&next) != cursor.as_ref() => cursor = Some(next),
                _ => return Ok(out),
            }
        }
        Ok(out)
    }

    /// Create a record, letting the PDS assign the key.
    pub async fn create_record<T: Serialize>(
        &self,
        collection: &str,
        record: &T,
    ) -> Result<WriteResult> {
        self.write(
            "com.atproto.repo.createRecord",
            json!({ "repo": self.session.sub, "collection": collection, "record": record }),
        )
        .await
    }

    /// Create or replace a record at a known key.
    pub async fn put_record<T: Serialize>(
        &self,
        collection: &str,
        rkey: &str,
        record: &T,
    ) -> Result<WriteResult> {
        self.write(
            "com.atproto.repo.putRecord",
            json!({
                "repo": self.session.sub,
                "collection": collection,
                "rkey": rkey,
                "record": record,
            }),
        )
        .await
    }

    pub async fn delete_record(&self, collection: &str, rkey: &str) -> Result<()> {
        let body = json!({ "repo": self.session.sub, "collection": collection, "rkey": rkey });
        self.send(
            &self.url("com.atproto.repo.deleteRecord"),
            DpopBody::Json(serde_json::to_vec(&body)?),
            "com.atproto.repo.deleteRecord",
        )
        .await?;
        Ok(())
    }

    /// A batch of writes in one round trip.
    pub async fn apply_writes(&self, writes: &[WriteOp]) -> Result<()> {
        if writes.is_empty() {
            return Ok(());
        }
        let ops: Vec<Value> = writes.iter().map(WriteOp::to_json).collect();
        let body = json!({ "repo": self.session.sub, "writes": ops });
        self.send(
            &self.url("com.atproto.repo.applyWrites"),
            DpopBody::Json(serde_json::to_vec(&body)?),
            "com.atproto.repo.applyWrites",
        )
        .await?;
        Ok(())
    }

    async fn write(&self, nsid: &str, body: Value) -> Result<WriteResult> {
        let value = self
            .send(
                &self.url(nsid),
                DpopBody::Json(serde_json::to_vec(&body)?),
                nsid,
            )
            .await?;
        serde_json::from_value(value).with_context(|| format!("{nsid} returned no usable result"))
    }
}

/// Format an XRPC failure for an error message.
fn xrpc_error(body: &[u8], status: u16) -> String {
    match Repo::error_fields(body) {
        Some(detail) => format!("status {status} ({detail})"),
        None => format!("status {status}"),
    }
}

/// The reader's typed surface, over [`Repo`].
///
/// Deliberately thin: each method is one repo call plus a parse, and the
/// orderings come from [`crate::lexicon::sort`], SHARED with the sidecar client
/// so the two cannot disagree across the cutover. A divergence there would not
/// be subtle — it would reorder the user's feed list the moment the
/// implementation swapped.
impl Repo<'_> {
    /// List a collection and parse each record into `T`, paired with its rkey.
    ///
    /// An unparseable record is SKIPPED with a warning rather than failing the
    /// list. Records are written by other clients and by future versions of this
    /// one; one record this build cannot read must not black out the whole feed
    /// list.
    async fn list_typed<T: serde::de::DeserializeOwned>(
        &self,
        collection: &str,
    ) -> Result<Vec<(String, T)>> {
        let records = self.list_all_records(collection).await?;
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            let rkey = record.rkey().unwrap_or_default().to_string();
            match record.parse::<T>() {
                Ok(value) => out.push((rkey, value)),
                Err(err) => tracing::warn!(
                    collection,
                    uri = %record.uri,
                    error = %err,
                    "skipping unparseable record in collection"
                ),
            }
        }
        Ok(out)
    }

    // ── subscriptions ────────────────────────────────────────────────────────

    pub async fn list_subscriptions(&self) -> Result<Vec<(String, crate::lexicon::Subscription)>> {
        self.list_typed(crate::lexicon::nsid::SUBSCRIPTION).await
    }

    /// Every subscription, in the reader's deterministic order.
    pub async fn list_subscriptions_sorted(
        &self,
    ) -> Result<Vec<(String, crate::lexicon::Subscription)>> {
        let mut subs = self.list_subscriptions().await?;
        subs.sort_by(crate::lexicon::sort::subscriptions);
        Ok(subs)
    }

    /// Subscribe to a feed. Returns the new record's rkey so the caller can
    /// address it (rename, delete) without re-listing.
    pub async fn add_subscription(&self, sub: &crate::lexicon::Subscription) -> Result<String> {
        Ok(self
            .create_record(crate::lexicon::nsid::SUBSCRIPTION, sub)
            .await?
            .into_rkey())
    }

    pub async fn remove_subscription(&self, rkey: &str) -> Result<()> {
        self.delete_record(crate::lexicon::nsid::SUBSCRIPTION, rkey)
            .await
    }

    /// Replace a subscription in place — retitle, refile, change cadence.
    pub async fn update_subscription(
        &self,
        rkey: &str,
        sub: &crate::lexicon::Subscription,
    ) -> Result<()> {
        self.put_record(crate::lexicon::nsid::SUBSCRIPTION, rkey, sub)
            .await?;
        Ok(())
    }

    /// Batch-add many subscriptions in one `applyWrites` — the OPML-import path.
    ///
    /// One round trip rather than N: an import of several hundred feeds is the
    /// case this exists for.
    pub async fn add_subscriptions_bulk(
        &self,
        subs: &[crate::lexicon::Subscription],
    ) -> Result<()> {
        let writes: Vec<WriteOp> = subs
            .iter()
            .map(|sub| WriteOp::Create {
                collection: crate::lexicon::nsid::SUBSCRIPTION.to_string(),
                rkey: None,
                value: serde_json::to_value(sub).unwrap_or(Value::Null),
            })
            .collect();
        self.apply_writes(&writes).await
    }

    // ── folders ──────────────────────────────────────────────────────────────

    pub async fn list_folders(&self) -> Result<Vec<(String, crate::lexicon::Folder)>> {
        self.list_typed(crate::lexicon::nsid::FOLDER).await
    }

    pub async fn list_folders_sorted(&self) -> Result<Vec<(String, crate::lexicon::Folder)>> {
        let mut folders = self.list_folders().await?;
        folders.sort_by(crate::lexicon::sort::folders);
        Ok(folders)
    }

    pub async fn add_folder(&self, folder: &crate::lexicon::Folder) -> Result<String> {
        Ok(self
            .create_record(crate::lexicon::nsid::FOLDER, folder)
            .await?
            .into_rkey())
    }

    /// Delete a folder. Subscriptions referencing it are left alone; a dangling
    /// reference reads as "unfiled", which is the same behaviour the sidecar
    /// client has.
    pub async fn remove_folder(&self, rkey: &str) -> Result<()> {
        self.delete_record(crate::lexicon::nsid::FOLDER, rkey).await
    }

    pub async fn rename_folder(&self, rkey: &str, folder: &crate::lexicon::Folder) -> Result<()> {
        self.put_record(crate::lexicon::nsid::FOLDER, rkey, folder)
            .await?;
        Ok(())
    }

    // ── saved ────────────────────────────────────────────────────────────────

    pub async fn list_saved(&self) -> Result<Vec<(String, crate::lexicon::Saved)>> {
        self.list_typed(crate::lexicon::nsid::SAVED).await
    }

    /// Saved entries, newest first.
    pub async fn list_saved_sorted(&self) -> Result<Vec<(String, crate::lexicon::Saved)>> {
        let mut saved = self.list_saved().await?;
        saved.sort_by(crate::lexicon::sort::saved);
        Ok(saved)
    }

    pub async fn add_saved(&self, saved: &crate::lexicon::Saved) -> Result<String> {
        Ok(self
            .create_record(crate::lexicon::nsid::SAVED, saved)
            .await?
            .into_rkey())
    }

    pub async fn remove_saved(&self, rkey: &str) -> Result<()> {
        self.delete_record(crate::lexicon::nsid::SAVED, rkey).await
    }

    // ── read state ───────────────────────────────────────────────────────────

    pub async fn list_read_states(&self) -> Result<Vec<(String, crate::lexicon::ReadState)>> {
        self.list_typed(crate::lexicon::nsid::READ_STATE).await
    }

    /// Upsert one read cursor at its feed-derived rkey.
    pub async fn put_read_state(
        &self,
        rkey: &str,
        state: &crate::lexicon::ReadState,
    ) -> Result<()> {
        self.put_record(crate::lexicon::nsid::READ_STATE, rkey, state)
            .await?;
        Ok(())
    }

    /// Flush many dirty read cursors in one `applyWrites`.
    ///
    /// Read state changes on nearly every page view, so this is the hottest
    /// write path in the app; one round trip per flush rather than per feed is
    /// the whole point.
    pub async fn flush_read_states(
        &self,
        states: &[(String, crate::lexicon::ReadState)],
    ) -> Result<()> {
        let writes: Vec<WriteOp> = states
            .iter()
            .map(|(rkey, state)| WriteOp::Create {
                collection: crate::lexicon::nsid::READ_STATE.to_string(),
                rkey: Some(rkey.clone()),
                value: serde_json::to_value(state).unwrap_or(Value::Null),
            })
            .collect();
        self.apply_writes(&writes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> OAuthSession {
        OAuthSession {
            sub: "did:plc:ewvi7nxzyoun6zhxrhs64oiz".into(),
            issuer: "https://pds.example.com".into(),
            aud: "https://pds.example.com".into(),
            dpop_key_jwk: "{}".into(),
            access_token: "tok".into(),
            refresh_token: "ref".into(),
            token_type: "DPoP".into(),
            granted_scope: "atproto".into(),
            expires_at: None,
        }
    }

    fn repo<'a>(
        http: &'a Client,
        pool: &'a SqlitePool,
        session: &'a OAuthSession,
        key: &'a SigningKey,
    ) -> Repo<'a> {
        Repo {
            http,
            pool,
            session,
            key,
        }
    }

    /// **The PDS comes from the session**, so a call cannot be pointed at
    /// another host by a caller who passes the wrong base.
    #[tokio::test]
    async fn endpoints_are_built_from_the_sessions_audience() {
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = "https://pds.example.com/".into();
        let repo = repo(&http, &pool, &s, &key);
        assert_eq!(
            repo.url("com.atproto.repo.listRecords"),
            "https://pds.example.com/xrpc/com.atproto.repo.listRecords",
            "a trailing slash on the audience must not double the separator"
        );
    }

    /// An XRPC error document is summarised by its `error`/`message` fields
    /// only — never by echoing the raw body, which on other paths holds tokens.
    #[test]
    fn an_xrpc_error_is_summarised_not_echoed() {
        let body = br#"{"error":"InvalidRequest","message":"unknown collection"}"#;
        let rendered = xrpc_error(body, 400);
        assert!(rendered.contains("InvalidRequest"));
        assert!(rendered.contains("unknown collection"));

        // A body that is not an XRPC error contributes nothing but the status.
        let opaque = xrpc_error(br#"{"access_token":"SECRET"}"#, 500);
        assert_eq!(opaque, "status 500");
        assert!(!opaque.contains("SECRET"));
        assert_eq!(xrpc_error(b"<html>oops</html>", 502), "status 502");
    }

    /// Every repo call must fail closed on an internal target, like every other
    /// outbound path — asserted on the guard's own error.
    #[tokio::test]
    async fn repo_calls_fail_closed_on_an_internal_pds() {
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        super::super::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = "http://127.0.0.1:2583".into();
        let repo = repo(&http, &pool, &s, &key);

        let err = repo
            .list_records("app.feather.subscription", None, None)
            .await
            .expect_err("must refuse a loopback PDS");
        assert!(
            format!("{err:#}").contains("forbidden (internal) address"),
            "failed for the wrong reason: {err:#}"
        );
    }

    /// An empty batch must not produce a request at all — an `applyWrites` with
    /// no writes is a round trip that can only fail.
    #[tokio::test]
    async fn an_empty_batch_is_not_sent() {
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        // A target that would fail loudly if it were ever contacted.
        s.aud = "http://127.0.0.1:2583".into();
        let repo = repo(&http, &pool, &s, &key);
        assert!(repo.apply_writes(&[]).await.is_ok());
    }
}
