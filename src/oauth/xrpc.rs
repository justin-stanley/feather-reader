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

use anyhow::{Context as _, Result};
use reqwest::Client;
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

/// Hard cap on records accumulated by one walk — 50 pages x the 100 we request.
/// See [`crate::atproto::extend_bounded`] for why exceeding it is an error
/// rather than a truncation.
const MAX_LIST_RECORDS: usize = 5_000;

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
    async fn send_raw(
        &self,
        url: &str,
        body: DpopBody<'_>,
        nsid: &str,
    ) -> Result<request::PostOutcome> {
        let outcome = request::send_with_dpop(
            self.http,
            self.pool,
            &DpopRequest {
                endpoint: Endpoint::ResourceServer,
                url,
                key: self.key,
                access_token: Some(&self.session.access_token),
                body,
                // A repo call is repeated on a nonce challenge, on the
                // ASSUMPTION that a PDS answering with a challenge has not acted
                // on the request. That is how conformant servers behave and what
                // the reference relies on, but it is not a guarantee we can
                // verify: a PDS or intermediary that emitted `use_dpop_nonce`
                // after a write committed would yield a duplicate record from
                // `createRecord` or `applyWrites`, both of which are
                // non-idempotent here.
                retry: Retry::Allowed,
            },
        )
        .await?;

        if !outcome.is_success() {
            // **The rejection as a value, under the same sentence as before.**
            // The sidecar client already surfaces an `AtProtoError::Xrpc`; this
            // one only said it in a string, so a caller that has to tell "the
            // PDS refused this" from "the network broke" — the read-state
            // reconcile (#241) — could match on nothing sturdier than wording.
            // The context keeps `Display` byte-for-byte what it was.
            let rejection = Self::rejection(&outcome.body, outcome.status);
            return Err(anyhow::Error::new(rejection).context(format!(
                "{nsid} failed: {}",
                xrpc_error(&outcome.body, outcome.status)
            )));
        }
        Ok(outcome)
    }

    /// A non-2xx answer as the [`crate::atproto::AtProtoError::Xrpc`] the
    /// sidecar client produces for the same answer, so one matcher serves both.
    ///
    /// The same length bound as [`Self::error_fields`] before any parse, and the
    /// same `"Unknown"` fallback `atproto::xrpc_error_from` uses for a body that
    /// is not an error document.
    fn rejection(body: &[u8], status: u16) -> crate::atproto::AtProtoError {
        #[derive(serde::Deserialize)]
        struct Fields {
            error: Option<String>,
            message: Option<String>,
        }
        let fields = super::error_body_worth_parsing(body)
            .then(|| serde_json::from_slice::<Fields>(body).ok())
            .flatten();
        let (error, message) = match fields {
            Some(Fields {
                error: Some(error),
                message,
            }) => (error, message),
            _ => ("Unknown".to_string(), None),
        };
        crate::atproto::AtProtoError::Xrpc {
            status: reqwest::StatusCode::from_u16(status)
                // Unreachable: reqwest already parsed this status. Not a 500,
                // so it can never read as the reference PDS's mismatch.
                .unwrap_or(reqwest::StatusCode::BAD_GATEWAY),
            error,
            message,
        }
    }

    /// [`send_raw`](Self::send_raw), then the body as JSON.
    ///
    /// Every call that wants a `Value` goes through here; `listRecords` does
    /// not, because turning its body into a `Value` and then into a page
    /// materialises the records twice.
    async fn send(&self, url: &str, body: DpopBody<'_>, nsid: &str) -> Result<Value> {
        let outcome = self.send_raw(url, body, nsid).await?;
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
    ///
    /// **Bounded by length before it is parsed.** This is the error twin of
    /// `send`, whose success branch goes through `PostOutcome::json` and its node
    /// guard — so without this a hostile PDS answering **500** instead of 200 got
    /// the whole amplification the guard exists to stop, on every write and on
    /// every listing failure. An error document is a few dozen bytes; see
    /// [`super::MAX_ERROR_BODY`].
    fn error_fields(body: &[u8]) -> Option<String> {
        if !super::error_body_worth_parsing(body) {
            return None;
        }
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
        let page = self.list_records_page(collection, limit, cursor).await?;
        Ok((page.records, page.cursor))
    }

    /// [`Self::list_records`] with the whole page, including how many records
    /// were malformed and left out (#177) — which the tuple form cannot carry.
    pub(crate) async fn list_records_page(
        &self,
        collection: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<crate::atproto::ListRecordsResponse> {
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

        // **Raw bytes, parsed once.** This is the live backend's list walk, the
        // largest body this client reads, and routing it through `Value` first
        // held two copies of every page at the same time.
        let outcome = self
            .send_raw(
                url.as_str(),
                DpopBody::Query,
                "com.atproto.repo.listRecords",
            )
            .await?;
        // A 2xx carrying an error envelope is NOT an empty page: `records`
        // defaulting to `[]` turned a PDS failure into `Ok(vec![])`, which
        // `resolve_subscriptions` reads as "this DID follows nothing" and
        // `sync_sub_refs` then writes through, revoking every `sub_ref`.
        // Both invariants, through the one function every listRecords caller
        // shares — this check was added here first and had to be fitted to the
        // other two clients a round later. It reads bytes now rather than a
        // `Value`; the invariants are the same ones, expressed as fields.
        crate::atproto::parse_list_records(&outcome.body)
    }

    /// Every record in a collection, following the cursor.
    ///
    /// Bounded at `MAX_LIST_PAGES`: the repo is user-controlled, so an
    /// unbounded walk is a denial-of-service against ourselves. A cursor that
    /// does not advance also terminates the walk rather than spinning.
    pub async fn list_all_records(&self, collection: &str) -> Result<Vec<RecordEntry>> {
        self.list_all_records_within(
            collection,
            &mut crate::atproto::ByteBudget::new(crate::atproto::MAX_LIST_BYTES),
        )
        .await
    }

    /// [`list_all_records`](Self::list_all_records) against a caller's budget.
    pub(crate) async fn list_all_records_within(
        &self,
        collection: &str,
        budget: &mut crate::atproto::ByteBudget,
    ) -> Result<Vec<RecordEntry>> {
        let mut out = Vec::new();
        let max_bytes = budget.max();
        let mut cursor: Option<String> = None;
        let mut more_offered = false;

        for _ in 0..MAX_LIST_PAGES {
            let listed = self
                .list_records_page(collection, Some(100), cursor.as_deref())
                .await?;
            // This walk is the live backend's, and its result reaches
            // `replace_sub_refs`: a skipped record is a dropped subscription.
            crate::atproto::refuse_malformed(&listed, collection)?;
            let (page, next) = (listed.records, listed.cursor);
            let got = page.len();
            // Same cap, same reason as `atproto::extend_bounded`: MAX_LIST_PAGES
            // bounds requests, not memory, unless the server honours our limit.
            // This is the LIVE walk on `backend=rust` — its result reaches
            // `replace_sub_refs`, so a truncation here is revoked access.
            if !budget.admit(&page) {
                anyhow::bail!(
                    "listRecords for {collection} exceeded the {max_bytes}-byte cap \
                     ({} held, {} bytes charged) — refusing to accumulate further",
                    out.len(),
                    budget.used(),
                );
            }
            crate::atproto::extend_bounded(&mut out, page, MAX_LIST_RECORDS, collection)?;
            match next {
                // `got > 0` is not defensive tidiness -- it is a whole round
                // trip. This project's own PDS returns a cursor ALONGSIDE a
                // short page, so without it every list fetches a second, empty
                // page before stopping. Both of the other clients have this
                // guard; measured, its absence was most of the remaining gap
                // against the sidecar.
                //
                // The cursor-repeat check is the separate concern: a server that
                // hands back the same cursor forever would otherwise loop.
                Some(next) if got > 0 && Some(&next) != cursor.as_ref() => {
                    cursor = Some(next);
                    more_offered = true;
                }
                _ => {
                    // `break` with the flag cleared, rather than an early
                    // `return`: an early return makes the post-loop check
                    // unreachable, so the flag reads as dead state and a
                    // reviewer hunts for the case that clears it. It also left
                    // the "every walk refuses" mutation alive here.
                    more_offered = false;
                    break;
                }
            }
        }
        // **Running out of pages is a refusal, not a short answer.** Falling out
        // of the loop used to return `Ok(out)`, so a repo bigger than the page
        // budget produced a truncated list indistinguishable from a complete
        // one — and `resolve_subscriptions` needs an `Err` for its fail-closed
        // branch. Given `Ok`, it hands the short list to `replace_sub_refs`,
        // which DELETEs the reader's whole `sub_ref` projection and reinserts
        // only what it was given. `extend_bounded` cannot catch this either:
        // `MAX_LIST_PAGES` x the 100 we request is `MAX_LIST_RECORDS`, so against
        // a server that honours our limit the page budget runs out first.
        //
        // **The cap is on REQUESTS, though, so the record count it bites at is
        // the server's page size x the budget — not a number our constants fix.**
        // A PDS answering 50 a page reaches half as far; one answering more than
        // asked trips `extend_bounded` instead. And the last allowed page is a
        // FALSE refusal: terminating costs one extra request when a short page
        // still carries a cursor, so a walk holding every record it will ever
        // hold still refuses on a cursor it never followed.
        //
        // This client's caps are a QUARTER of the direct client's (50 pages,
        // 5 000 records), so with `limit=100` honoured the same reader refuses
        // here at ~4 900 records and works to ~19 900 on the sidecar. `Saved`
        // walks this too, one record per starred article, where 4 900 is a
        // plausible number for a real reader.
        if more_offered {
            anyhow::bail!(
                "listRecords for {collection} did not finish within {MAX_LIST_PAGES} pages \
                 ({} held, and the PDS still offered more) — refusing a short list",
                out.len(),
            );
        }
        Ok(out)
    }

    /// Create a record, letting the PDS assign the key.
    pub async fn create_record<T: crate::vetted::WritableRecord>(
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
    ///
    /// `swap_record` is the CID the caller read the record at, sent as
    /// `swapRecord`, so a record another client wrote in between is refused
    /// with `InvalidSwap` instead of overwritten (#149); recognise that with
    /// [`crate::atproto::is_invalid_swap`]. `None` omits the field.
    pub async fn put_record<T: crate::vetted::WritableRecord>(
        &self,
        collection: &str,
        rkey: &str,
        record: &T,
        swap_record: Option<&str>,
    ) -> Result<WriteResult> {
        let mut body = json!({
            "repo": self.session.sub,
            "collection": collection,
            "rkey": rkey,
            "record": record,
        });
        if let Some(cid) = swap_record {
            body["swapRecord"] = json!(cid);
        }
        self.write("com.atproto.repo.putRecord", body).await
    }

    pub async fn delete_record(&self, collection: &str, rkey: &str) -> Result<()> {
        let body = json!({ "repo": self.session.sub, "collection": collection, "rkey": rkey });
        self.send(
            &self.url("com.atproto.repo.deleteRecord"),
            DpopBody::Json(serde_json::to_vec(&body)?),
            "com.atproto.repo.deleteRecord",
        )
        .await
        .and_then(|v| crate::atproto::reject_error_envelope(&v))?;
        Ok(())
    }

    /// A batch of writes, in as few round trips as the PDS's limits allow.
    ///
    /// Chunked by `crate::atproto::apply_writes_chunked`, which says what a
    /// failure part-way means: the batch is atomic per CALL, not as a whole.
    pub async fn apply_writes(&self, writes: &[WriteOp]) -> Result<()> {
        crate::atproto::apply_writes_chunked(writes, |chunk| self.apply_writes_once(chunk)).await
    }

    /// One `applyWrites` call, unchunked. Private: an oversized call is a
    /// refused call, so nothing reaches this except through
    /// [`apply_writes`](Self::apply_writes).
    async fn apply_writes_once(&self, writes: &[WriteOp]) -> Result<()> {
        let ops: Vec<Value> = writes.iter().map(WriteOp::to_json).collect();
        let body = json!({ "repo": self.session.sub, "writes": ops });
        self.send(
            &self.url("com.atproto.repo.applyWrites"),
            DpopBody::Json(serde_json::to_vec(&body)?),
            "com.atproto.repo.applyWrites",
        )
        .await
        .and_then(|v| crate::atproto::reject_error_envelope(&v))?;
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
        Ok(self
            .list_typed_with_cids(collection)
            .await?
            .into_iter()
            .map(|(rkey, _cid, value)| (rkey, value))
            .collect())
    }

    /// [`list_typed`](Self::list_typed), keeping the CID each record was
    /// listed at — the value a compare-and-swap write names (#149). One parse
    /// path for both, so the CID listing skips exactly what the plain one does.
    async fn list_typed_with_cids<T: serde::de::DeserializeOwned>(
        &self,
        collection: &str,
    ) -> Result<Vec<(String, Option<String>, T)>> {
        let records = self.list_all_records(collection).await?;
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            let rkey = record.rkey().unwrap_or_default().to_string();
            match record.parse::<T>() {
                Ok(value) => out.push((rkey, record.cid, value)),
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

    /// Every subscription with the CID it was listed at, unsorted — the read
    /// half of a read-modify-write that puts with `swapRecord` (#149).
    pub async fn list_subscriptions_with_cids(
        &self,
    ) -> Result<Vec<(String, Option<String>, crate::lexicon::Subscription)>> {
        self.list_typed_with_cids(crate::lexicon::nsid::SUBSCRIPTION)
            .await
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
    pub async fn add_subscription(
        &self,
        sub: &crate::vetted::VettedSubscription,
    ) -> Result<String> {
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
    /// Returns the [`WriteResult`] rather than discarding it: the caller logs
    /// the resulting record URI, and a `()` here would have silently dropped
    /// that field from the log line after the cutover.
    pub async fn update_subscription(
        &self,
        rkey: &str,
        sub: &crate::vetted::VettedSubscription,
        swap_record: Option<&str>,
    ) -> Result<WriteResult> {
        self.put_record(crate::lexicon::nsid::SUBSCRIPTION, rkey, sub, swap_record)
            .await
    }

    /// Batch-add many subscriptions via `applyWrites` (chunked) — the OPML-import path.
    ///
    /// One round trip per 200 feeds rather than one per feed: an import of
    /// several hundred feeds is the case this exists for. More than one call
    /// means the import can part-land; on an error,
    /// [`crate::atproto::ApplyWritesIncomplete::of`] gives `landed`, and the
    /// first `landed` of `subs` are in the repo.
    /// Returns the new rkeys, which are assigned HERE rather than by the server:
    /// client-side TIDs keep the imported feeds in input order and make the
    /// batch reproducible. The sidecar client does the same, with the same
    /// generator.
    pub async fn add_subscriptions_bulk(
        &self,
        subs: &[crate::vetted::VettedSubscription],
    ) -> Result<Vec<String>> {
        let mut gen = crate::atproto::TidGenerator::new();
        let mut rkeys = Vec::with_capacity(subs.len());
        let mut writes = Vec::with_capacity(subs.len());
        for sub in subs {
            let rkey = gen.next();
            writes.push(WriteOp::Create {
                collection: crate::lexicon::nsid::SUBSCRIPTION.to_string(),
                rkey: Some(rkey.clone()),
                // Propagated, NOT defaulted: `unwrap_or(Value::Null)` here would
                // write a null record into the user's repo on a serialization
                // failure rather than failing the import.
                value: serde_json::to_value(sub)?,
            });
            rkeys.push(rkey);
        }
        self.apply_writes(&writes).await?;
        Ok(rkeys)
    }

    // ── folders ──────────────────────────────────────────────────────────────

    pub async fn list_folders(&self) -> Result<Vec<(String, crate::lexicon::Folder)>> {
        self.list_typed(crate::lexicon::nsid::FOLDER).await
    }

    /// Every folder with the CID it was listed at, unsorted (#268).
    pub async fn list_folders_with_cids(
        &self,
    ) -> Result<Vec<(String, Option<String>, crate::lexicon::Folder)>> {
        self.list_typed_with_cids(crate::lexicon::nsid::FOLDER)
            .await
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

    /// Returns the [`WriteResult`], matching the sidecar client — the caller
    /// logs the record URI from it. `swap_record` is the CID the folder was
    /// read at, so a write by another client since is refused rather than
    /// overwritten (#268).
    pub async fn rename_folder(
        &self,
        rkey: &str,
        folder: &crate::lexicon::Folder,
        swap_record: Option<&str>,
    ) -> Result<WriteResult> {
        self.put_record(crate::lexicon::nsid::FOLDER, rkey, folder, swap_record)
            .await
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

    pub async fn add_saved(&self, saved: &crate::vetted::VettedSaved) -> Result<String> {
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
        self.put_record(crate::lexicon::nsid::READ_STATE, rkey, state, None)
            .await?;
        Ok(())
    }

    /// Flush many dirty read cursors via `applyWrites` (chunked).
    ///
    /// Read state changes on nearly every page view, so this is the hottest
    /// write path in the app; one round trip per flush rather than per feed is
    /// the whole point. A flush past the op or byte bound is several calls,
    /// and a failure part-way leaves the first
    /// [`landed`](crate::atproto::ApplyWritesIncomplete::landed) cursors
    /// written — see `crate::atproto::apply_writes_chunked`.
    /// The `bool` is whether the record already exists in the PDS. It is not
    /// optional bookkeeping: an `#update` on a missing record ERRORS, and
    /// `applyWrites` is atomic per repo, so one not-yet-created cursor in the
    /// batch would drop the whole DID's flush. The op builder is shared with the
    /// sidecar client so the two cannot decide create-vs-update differently.
    pub async fn flush_read_states(
        &self,
        cursors: &[(String, crate::lexicon::ReadState, bool)],
    ) -> Result<()> {
        if cursors.is_empty() {
            return Ok(());
        }
        let writes = crate::atproto::read_state_write_ops(cursors)?;
        self.apply_writes(&writes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Both clients must build the SAME write ops.**
    ///
    /// `flush_read_states` is the hottest write path in the app, and the
    /// create-vs-update choice is the one part of it that cannot be got wrong
    /// quietly: an `#update` on a record that does not exist errors, and
    /// `applyWrites` is atomic per repo, so a single first-flush cursor in the
    /// batch takes the whole DID's flush down with it.
    ///
    /// The first version of this method here ignored the flag and emitted
    /// `#create` unconditionally, which would have broken every feed's first
    /// flush after the cutover. Sharing the builder is what makes that
    /// impossible rather than merely fixed.
    #[test]
    fn read_state_writes_choose_create_or_update_per_cursor() {
        let state = crate::lexicon::ReadState::new(
            "https://example.com/feed",
            Some("2026-01-01T00:00:00Z".to_string()),
            "2026-01-01T00:00:00Z",
        );
        let cursors = vec![
            ("existing".to_string(), state.clone(), true),
            ("brand-new".to_string(), state.clone(), false),
        ];

        let ops = crate::atproto::read_state_write_ops(&cursors).expect("ops build");
        assert_eq!(ops.len(), 2);

        let rendered: Vec<Value> = ops.iter().map(|op| op.to_json()).collect();
        assert_eq!(
            rendered[0]["$type"], "com.atproto.repo.applyWrites#update",
            "an existing record must be UPDATED, not re-created"
        );
        assert_eq!(
            rendered[1]["$type"], "com.atproto.repo.applyWrites#create",
            "a first flush must CREATE, or the whole atomic batch fails"
        );
    }

    /// **Bulk import, through the real `Repo`, asserted on the bytes.** The
    /// test this replaces exercised `TidGenerator` directly and never called
    /// `add_subscriptions_bulk`; the function could stop assigning rkeys and
    /// return garbage with the suite green.
    #[tokio::test]
    async fn bulk_subscribe_writes_client_assigned_ordered_rkeys_to_the_right_collection() {
        let (base, log) = crate::net::tests::serve_json_capturing(b"{}".to_vec()).await;
        let port: u16 = base.rsplit(':').next().unwrap().parse().unwrap();
        crate::net::test_host_override(
            "bulk-pds.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://bulk-pds.test:{port}");
        let repo = repo(&http, &pool, &s, &key);
        let subs: Vec<crate::vetted::VettedSubscription> = (0..3)
            .map(|i| {
                crate::vetted::VettedSubscription::new(&crate::lexicon::Subscription::new(
                    format!("https://f{i}.example/feed.xml"),
                    "2026-07-12T00:00:00.000Z",
                ))
            })
            .collect();

        let rkeys = repo
            .add_subscriptions_bulk(&subs)
            .await
            .expect("bulk write failed");

        let sent = log.lock().unwrap().clone();
        assert_eq!(
            sent.len(),
            1,
            "expected one applyWrites request, got {sent:?}"
        );
        let body: Value = serde_json::from_str(sent[0].split("\r\n\r\n").nth(1).unwrap())
            .expect("request body is JSON");
        let writes = body["writes"].as_array().expect("writes array");
        assert_eq!(writes.len(), 3);
        for (i, w) in writes.iter().enumerate() {
            assert_eq!(w["collection"], crate::lexicon::nsid::SUBSCRIPTION);
            assert_eq!(w["rkey"].as_str(), Some(rkeys[i].as_str()));
        }
        let mut sorted = rkeys.clone();
        sorted.sort();
        assert_eq!(rkeys, sorted, "client-assigned rkeys must ascend");
    }

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

    /// **A 200 carrying an error envelope must not read as an empty repo.**
    ///
    /// `records` was taken off the JSON with `unwrap_or(Array([]))`, so a PDS
    /// answering `200 {"error": …}` produced `Ok(vec![])`. That is not the
    /// fail-closed branch in `web::resolve_subscriptions`: `sync_sub_refs`
    /// writes the empty set through and `replace_sub_refs` DELETEs the DID's
    /// entire `sub_ref` projection — one bad response revokes the reader's
    /// access to every feed they have. Driven through the real client against
    /// a real server, because the bug was the missing CALL, not the check.
    #[tokio::test]
    async fn a_200_error_envelope_is_not_an_empty_repo() {
        let base = crate::net::tests::serve_body(
            br#"{"error":"InvalidRequest","message":"bad cursor"}"#.to_vec(),
        )
        .await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "envelope-pds.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );

        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://envelope-pds.test:{port}");
        let repo = repo(&http, &pool, &s, &key);

        let err = repo
            .list_records("app.feather.subscription", None, None)
            .await
            .expect_err("an error envelope was read as an empty page");
        assert!(
            format!("{err:#}").contains("InvalidRequest"),
            "failed for the wrong reason: {err:#}"
        );
    }

    /// **The live walk spends its budget across pages too.**
    ///
    /// This is the `backend=rust` walk whose result reaches `replace_sub_refs`,
    /// so a bound that silently failed to accumulate here would revoke a
    /// reader's access to every feed past the cut. Three pages, a two-page
    /// budget: the walk must refuse, and must say it kept two.
    #[tokio::test]
    async fn the_live_walk_spends_its_budget_across_pages() {
        let (bodies, per_page) = crate::atproto::tests::paged_bodies(3, 4096, false);
        let base = crate::net::tests::serve_bodies_in_sequence(bodies).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "live-budget-pages.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );

        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://live-budget-pages.test:{port}");
        let repo = repo(&http, &pool, &s, &key);

        let err = repo
            .list_all_records_within(
                "app.feather.subscription",
                &mut crate::atproto::ByteBudget::new(per_page * 2),
            )
            .await
            .expect_err("three pages cannot fit in a two-page budget");
        let msg = format!("{err:#}");
        assert!(msg.contains("byte cap"), "wrong bound reported: {msg}");
        assert!(
            msg.contains("2 held"),
            "the live walk did not accumulate across pages: {msg}"
        );
    }

    /// **The live walk refuses a short list.** Its result reaches
    /// `replace_sub_refs`, so returning a truncated list as a complete one
    /// deletes every subscription past the page budget.
    #[tokio::test]
    async fn the_live_walk_that_runs_out_of_pages_refuses() {
        let bodies: Vec<Vec<u8>> = (0..MAX_LIST_PAGES + 1)
            .map(|i| {
                serde_json::json!({
                    "records": [{ "uri": format!("at://did:plc:x/c/3lab{i}"), "value": {} }],
                    "cursor": format!("p{}", i + 1),
                })
                .to_string()
                .into_bytes()
            })
            .collect();
        let base = crate::net::tests::serve_bodies_in_sequence(bodies).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "pages-exhausted-live.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://pages-exhausted-live.test:{port}");
        let repo = repo(&http, &pool, &s, &key);

        let err = repo
            .list_all_records("app.feather.subscription")
            .await
            .expect_err("a truncated list was returned as a complete one");
        assert!(
            format!("{err:#}").contains("did not finish"),
            "failed for the wrong reason: {err:#}"
        );
    }

    /// #177 on the live backend: a malformed record in the reader's own repo
    /// refuses the walk, by type, rather than dropping that subscription.
    #[tokio::test]
    async fn the_live_walk_refuses_a_page_with_a_malformed_record() {
        let body = serde_json::json!({ "records": [
            { "uri": "at://did:plc:x/c/3labGOOD", "value": {} },
            { "cid": "bafy", "value": {} },
        ]})
        .to_string()
        .into_bytes();
        let base = crate::net::tests::serve_bodies_in_sequence(vec![body]).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "malformed-live.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://malformed-live.test:{port}");
        let repo = repo(&http, &pool, &s, &key);
        let err = repo
            .list_all_records("app.feather.subscription")
            .await
            .expect_err("a page with a malformed record was accepted");
        assert!(
            err.downcast_ref::<crate::atproto::MalformedRecords>()
                .is_some(),
            "refused for the wrong reason: {err:#}"
        );
    }

    /// The live walk's clean finish must still be a success — see the sidecar's
    /// twin for why this direction is the dangerous one.
    #[tokio::test]
    async fn the_live_walk_that_finishes_cleanly_returns_the_records() {
        let mut bodies: Vec<Vec<u8>> = (0..3)
            .map(|i| {
                serde_json::json!({
                    "records": [{ "uri": format!("at://did:plc:x/c/3lab{i}"), "value": {} }],
                    "cursor": format!("p{}", i + 1),
                })
                .to_string()
                .into_bytes()
            })
            .collect();
        // **The terminator CARRIES a record**, because a real PDS ends on a
        // partial page and those are the records an off-by-one loses. Ending on
        // an empty page kept "drop the last page's records" alive: the count
        // below was right either way.
        bodies.push(
            serde_json::json!({
                "records": [{ "uri": "at://did:plc:x/c/3labLAST", "value": {} }]
            })
            .to_string()
            .into_bytes(),
        );
        let base = crate::net::tests::serve_bodies_in_sequence(bodies).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "clean-finish-live.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://clean-finish-live.test:{port}");
        let repo = repo(&http, &pool, &s, &key);

        let records = repo
            .list_all_records("app.feather.subscription")
            .await
            .expect("a walk that ran out of records is not a short list");
        assert_eq!(records.len(), 4);
        assert!(
            records.iter().any(|r| r.uri.ends_with("3labLAST")),
            "the LAST page's records were dropped: {:?}",
            records.iter().map(|r| r.uri.as_str()).collect::<Vec<_>>(),
        );
    }

    /// **The page cap is pinned exactly, not to within one.**
    ///
    /// `the_live_walk_that_runs_out_of_pages_refuses` serves `MAX_LIST_PAGES + 1`
    /// pages, so a budget one page SHORT refuses too and that mutation survives
    /// it. A walk whose last allowed request is the terminating one must come
    /// back `Ok` — and on this backend an `Err` is `replace_sub_refs` never
    /// running, which is the direction that costs a reader their subscriptions.
    #[tokio::test]
    async fn a_live_walk_that_terminates_on_its_last_allowed_page_succeeds() {
        let mut bodies: Vec<Vec<u8>> = (0..MAX_LIST_PAGES - 1)
            .map(|i| {
                serde_json::json!({
                    "records": [{ "uri": format!("at://did:plc:x/c/3lab{i}"), "value": {} }],
                    "cursor": format!("p{}", i + 1),
                })
                .to_string()
                .into_bytes()
            })
            .collect();
        bodies.push(
            serde_json::json!({
                "records": [{ "uri": "at://did:plc:x/c/3labLAST", "value": {} }]
            })
            .to_string()
            .into_bytes(),
        );
        assert_eq!(bodies.len(), MAX_LIST_PAGES);
        let base = crate::net::tests::serve_bodies_in_sequence(bodies).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "last-allowed-page-live.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://last-allowed-page-live.test:{port}");
        let repo = repo(&http, &pool, &s, &key);

        let records = repo
            .list_all_records("app.feather.subscription")
            .await
            .expect("a walk that terminated inside its budget is not a short list");
        assert_eq!(
            records.len(),
            MAX_LIST_PAGES,
            "a walk that used its whole page budget and finished lost records",
        );
    }

    /// **The ERROR twin of `send`, which a review found unguarded.**
    ///
    /// `send`'s success branch goes through `PostOutcome::json` and its cap; its
    /// failure branch goes to `xrpc_error` → `error_fields`, which deserialised the
    /// whole body. So a hostile PDS answering **500** instead of 200 with the same
    /// explosion got the full amplification on every write and on every listing
    /// failure — the guard bypassed by a status code.
    ///
    /// Both directions: a small error body still yields its reason, because that
    /// string is what a reader's log needs to tell "your PDS said no" from "we
    /// broke".
    #[test]
    fn an_oversized_error_body_is_not_parsed_for_its_reason() {
        let small = br#"{"error":"InvalidSwap","message":"record changed"}"#;
        assert_eq!(
            Repo::error_fields(small).as_deref(),
            Some("InvalidSwap: record changed"),
            "a real error body must still render its reason",
        );

        let mut huge = String::from(r#"{"error":"InvalidSwap","pad":["#);
        while huge.len() < crate::oauth::MAX_ERROR_BODY + 1_024 {
            huge.push_str("{},");
        }
        huge.push_str("{}]}");
        assert!(huge.len() > crate::oauth::MAX_ERROR_BODY);
        assert_eq!(
            Repo::error_fields(huge.as_bytes()),
            None,
            "an oversized error body was deserialised to fish out one string",
        );
    }

    /// **A PDS rejection is structured, not only a sentence (#241).**
    ///
    /// The read-state flusher has to tell "the PDS refused this batch" from "the
    /// network broke", and the sidecar client already said so with
    /// [`crate::atproto::AtProtoError::Xrpc`]. This client only said it in a
    /// string, so the one backend production runs could be matched on nothing
    /// sturdier than its wording. The rendered message must not change: it is
    /// what every existing log line and assertion reads.
    #[tokio::test]
    async fn a_rejected_write_carries_the_status_and_error_name() {
        use axum::response::IntoResponse as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let host = format!("rejecting-{}.xrpc.test", addr.port());
        crate::net::test_host_override(&host, addr);
        let app = axum::Router::new().fallback(|| async {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(
                    json!({ "error": "InternalServerError", "message": "Internal Server Error" }),
                ),
            )
                .into_response()
        });
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://{host}:{}", addr.port());
        let repo = repo(&http, &pool, &s, &key);

        let err = repo
            .apply_writes(&[WriteOp::Delete {
                collection: crate::lexicon::nsid::READ_STATE.into(),
                rkey: "rs-0".into(),
            }])
            .await
            .expect_err("a 500 is a failure");
        assert_eq!(
            err.to_string(),
            "com.atproto.repo.applyWrites failed: status 500 \
             (InternalServerError: Internal Server Error)",
            "the rendered message changed",
        );
        let xrpc = err
            .chain()
            .find_map(|cause| cause.downcast_ref::<crate::atproto::AtProtoError>());
        match xrpc {
            Some(crate::atproto::AtProtoError::Xrpc { status, error, .. }) => {
                assert_eq!(status.as_u16(), 500);
                assert_eq!(error, "InternalServerError");
            }
            other => panic!("no structured XRPC error in the chain: {other:?}"),
        }
    }

    /// **The write path parses a PDS body too, and it had no bound before the
    /// parse.**
    ///
    /// `listRecords` is guarded by `parse_list_records`; every OTHER body this
    /// client turns into a `Value` goes through `PostOutcome::json` — the repo
    /// writers' responses, the PAR response, the token response, the session
    /// refresh. `read_capped` bounds the WIRE at 8 MB, which is the *input* to the
    /// amplification rather than a limit on it: 8 MB of the cheapest node shape
    /// measured 824 MB retained on a 512 MB box.
    ///
    /// Drives `delete_record`, which is the shortest route from a handler to
    /// `send` → `json`.
    #[tokio::test]
    async fn the_live_write_path_refuses_a_node_explosion() {
        let mut body = String::from(r#"{"uri":"at://d/c/r","value":["#);
        for _ in 0..1_200_000 {
            body.push_str("{},");
        }
        body.push_str("{}]}");
        assert!(
            crate::atproto::count_structural_chars(body.as_bytes())
                > crate::atproto::MAX_LIST_STRUCTURAL_CHARS,
            "the probe body is not over the cap, so this test proves nothing",
        );
        let base = crate::net::tests::serve_body(body.into_bytes()).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "write-explosion.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://write-explosion.test:{port}");
        let repo = repo(&http, &pool, &s, &key);

        let err = repo
            .delete_record("c", "r")
            .await
            .expect_err("a node explosion on the write path was parsed rather than refused");
        assert!(
            format!("{err:#}").contains("structural characters"),
            "failed for the wrong reason: {err:#}"
        );
    }

    /// The other direction: an ordinary write response still parses. Without this
    /// a guard that refused every body would pass the test above.
    #[tokio::test]
    async fn the_live_write_path_accepts_an_ordinary_response() {
        let base =
            crate::net::tests::serve_body(br#"{"commit":{"cid":"bafy","rev":"3lab"}}"#.to_vec())
                .await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "write-ordinary.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://write-ordinary.test:{port}");
        let repo = repo(&http, &pool, &s, &key);

        repo.delete_record("c", "r")
            .await
            .expect("an ordinary write response was refused");
    }

    /// **A duplicated `records` key must not be able to empty a page.**
    ///
    /// This is the live `backend=rust` walk, so an empty page here reaches
    /// `replace_sub_refs` and deletes the reader's subscriptions. serde refuses
    /// a repeated field outright; a `serde_json::Value` takes the last one
    /// silently, so routing this body through a `Value` first turns a smuggled
    /// second key into a successful, empty listing. The test exists to pin
    /// which of the two this client uses.
    #[tokio::test]
    async fn the_live_walk_refuses_a_duplicated_records_key() {
        let base = crate::net::tests::serve_body(
            br#"{"records":[{"uri":"at://d/c/r","value":{}}],"records":[]}"#.to_vec(),
        )
        .await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "dup-records.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );

        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://dup-records.test:{port}");
        let repo = repo(&http, &pool, &s, &key);

        let err = repo
            .list_records("app.feather.subscription", None, None)
            .await
            .expect_err("a duplicated records key was read as an empty page");
        assert!(
            format!("{err:#}").contains("duplicate"),
            "failed for the wrong reason: {err:#}"
        );
    }

    /// **An empty 2xx body is not an empty repo either.** `send` maps a
    /// zero-length 2xx to `Value::Null` — deliberately, for `deleteRecord` and
    /// `applyWrites` — and while `listRecords` still went through it, that
    /// slipped past the envelope guard
    /// and `records.unwrap_or(Array([]))` produced `Ok(vec![])`: the same
    /// `sub_ref` wipe the guard was added to prevent, through the sibling door.
    #[tokio::test]
    async fn an_empty_200_body_is_not_an_empty_repo() {
        let base = crate::net::tests::serve_body(Vec::new()).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "empty-body.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://empty-body.test:{port}");
        let repo = repo(&http, &pool, &s, &key);

        let err = repo
            .list_records("app.feather.subscription", None, None)
            .await
            .expect_err("an empty body was read as an empty repo");
        assert!(
            format!("{err:#}").contains("no records"),
            "failed for the wrong reason: {err:#}"
        );
    }

    /// The write paths discarded the body too: `delete_record` and
    /// `apply_writes` are `send(..).await?; Ok(())`, so a 200 carrying an
    /// error envelope reported success for a delete that did not happen.
    #[tokio::test]
    async fn a_200_error_envelope_is_not_a_successful_write() {
        let base = crate::net::tests::serve_body(
            br#"{"error":"InvalidRequest","message":"nope"}"#.to_vec(),
        )
        .await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        crate::net::test_host_override(
            "envelope-write.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("http://envelope-write.test:{port}");
        let repo = repo(&http, &pool, &s, &key);

        let err = repo
            .delete_record("app.feather.subscription", "rk1")
            .await
            .expect_err("a failed delete was reported as success");
        assert!(format!("{err:#}").contains("InvalidRequest"), "{err:#}");

        let err = repo
            .apply_writes(&[crate::atproto::WriteOp::Delete {
                collection: "app.feather.subscription".to_string(),
                rkey: "rk1".to_string(),
            }])
            .await
            .expect_err("a failed batch was reported as success");
        assert!(format!("{err:#}").contains("InvalidRequest"), "{err:#}");
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

    // ── applyWrites chunking (#240) ──────────────────────────────────────────
    //
    // This is the production backend, so the chunking is asserted here on the
    // bytes it sends to a fake PDS that refuses what the reference PDS refuses
    // (see `crate::atproto::tests::serve_apply_writes`).

    /// A session pointed at the strict fake, reached through a per-port host
    /// override (the override table is process-wide and tests run in parallel).
    async fn strict_pds(
        fail_call: Option<usize>,
    ) -> (
        OAuthSession,
        SqlitePool,
        crate::atproto::tests::ApplyWritesLog,
    ) {
        let (base, log) = crate::atproto::tests::serve_apply_writes(fail_call).await;
        let port: u16 = base.rsplit(':').next().unwrap().parse().unwrap();
        let host = format!("chunk-oauth-{port}.test");
        crate::net::test_host_override(&host, std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let mut s = session();
        s.aud = format!("http://{host}:{port}");
        (s, pool, log)
    }

    fn subs(n: usize) -> Vec<crate::vetted::VettedSubscription> {
        (0..n)
            .map(|i| {
                crate::vetted::VettedSubscription::new(&crate::lexicon::Subscription::new(
                    format!("https://f{i}.example/feed.xml"),
                    "2026-07-12T00:00:00.000Z",
                ))
            })
            .collect()
    }

    /// **An OPML import of 201 feeds is two calls, 200 then 1, in order** — on
    /// the backend production runs. One call of 201 is what the reference PDS
    /// refuses with `Too many writes. Max: 200`.
    #[tokio::test]
    async fn bulk_subscribe_of_201_is_two_calls_in_order() {
        let (s, pool, log) = strict_pds(None).await;
        let (http, key) = (Client::new(), SigningKey::generate("k"));
        let rkeys = repo(&http, &pool, &s, &key)
            .add_subscriptions_bulk(&subs(201))
            .await
            .expect("a 201-feed import must succeed against a PDS that caps at 200");
        assert_eq!(crate::atproto::tests::call_sizes(&log), vec![200, 1]);
        assert_eq!(
            crate::atproto::tests::sent_rkeys(&log),
            rkeys,
            "every feed, once, in input order"
        );
    }

    /// 500 feeds — the default per-DID cap — are three calls; exactly 200 is one.
    #[tokio::test]
    async fn bulk_subscribe_splits_at_200_and_not_before() {
        for (n, want) in [(500, vec![200, 200, 100]), (200, vec![200])] {
            let (s, pool, log) = strict_pds(None).await;
            let (http, key) = (Client::new(), SigningKey::generate("k"));
            repo(&http, &pool, &s, &key)
                .add_subscriptions_bulk(&subs(n))
                .await
                .expect("bulk write");
            assert_eq!(crate::atproto::tests::call_sizes(&log), want, "{n} feeds");
        }
    }

    /// **A failed chunk stops the run**, and chunk 3 is never sent.
    #[tokio::test]
    async fn bulk_subscribe_stops_at_the_first_failed_chunk() {
        let (s, pool, log) = strict_pds(Some(2)).await;
        let (http, key) = (Client::new(), SigningKey::generate("k"));
        let err = repo(&http, &pool, &s, &key)
            .add_subscriptions_bulk(&subs(500))
            .await
            .expect_err("a failed chunk must fail the call");
        assert_eq!(
            crate::atproto::tests::call_sizes(&log),
            vec![200, 200],
            "chunk 3 must NOT be sent"
        );
        assert!(format!("{err:#}").contains("boom"), "{err:#}");
    }

    /// **The byte bound splits a read-state flush well under 200 ops.** Ten
    /// cursors at the lexicon's 1,000-id cap are ~500 KB — one call of that is
    /// refused by every reference PDS older than atproto#4989.
    #[tokio::test]
    async fn read_state_flush_splits_on_bytes_under_200_ops() {
        let (s, pool, log) = strict_pds(None).await;
        let (http, key) = (Client::new(), SigningKey::generate("k"));
        let cursors: Vec<(String, crate::lexicon::ReadState, bool)> = (0..10)
            .map(|i| {
                let mut state = crate::lexicon::ReadState::new(
                    format!("https://f{i}.example/feed.xml"),
                    None,
                    "2026-07-12T00:00:00.000Z",
                );
                state.read_ids = (0..crate::lexicon::ReadState::MAX_IDS)
                    .map(|j| format!("https://f{i}.example/posts/{j:04}/an-entry-permalink"))
                    .collect();
                (format!("rk{i:04}"), state, false)
            })
            .collect();
        repo(&http, &pool, &s, &key)
            .flush_read_states(&cursors)
            .await
            .expect("a byte-heavy flush must succeed in chunks");
        let sizes = crate::atproto::tests::call_sizes(&log);
        assert!(sizes.len() > 1, "one call for ~500 KB: {sizes:?}");
        let want: Vec<String> = cursors.iter().map(|(rkey, _, _)| rkey.clone()).collect();
        assert_eq!(crate::atproto::tests::sent_rkeys(&log), want);
    }

    // -- #149: compare-and-swap putRecord ------------------------------------

    /// A session whose audience is `pds` — the one place this client takes
    /// its host from.
    fn session_at(pds: &str) -> OAuthSession {
        let mut s = session();
        s.aud = pds.to_string();
        s
    }

    /// **`swapRecord` is on the wire when given, and absent when not** — the
    /// live backend's half of the CAS. Asserted on the request body the PDS
    /// received, since a parameter accepted and then dropped is exactly what
    /// a happy-path test cannot see.
    #[tokio::test]
    async fn put_record_sends_swap_record_only_when_given() {
        use crate::atproto::tests::{serve_status_json, swap_sub, write_ok, OLD_CID};
        let (_, pds, log) = serve_status_json(200, write_ok()).await;
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let s = session_at(&pds);
        let repo = repo(&http, &pool, &s, &key);

        repo.update_subscription("rk", &swap_sub(), Some(OLD_CID))
            .await
            .expect("put with a swap");
        repo.update_subscription("rk", &swap_sub(), None)
            .await
            .expect("put without a swap");

        let sent = log.lock().unwrap().clone();
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert_eq!(sent[0]["rkey"], "rk", "captured no usable body: {sent:?}");
        assert_eq!(
            sent[0]["swapRecord"], OLD_CID,
            "the CID the caller read never reached the PDS: {}",
            sent[0]
        );
        assert_eq!(sent[1]["rkey"], "rk");
        assert!(
            sent[1].get("swapRecord").is_none(),
            "no swap was asked for, so none may be sent: {}",
            sent[1]
        );
    }

    /// The PDS's `InvalidSwap`, as this client reports it, is recognised —
    /// and a different 400 from the same client is not.
    #[tokio::test]
    async fn an_invalid_swap_from_the_pds_is_recognised() {
        use crate::atproto::tests::{invalid_swap_xrpc, serve_status_json, swap_sub, OLD_CID};
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");

        let (_, pds, _) = serve_status_json(400, invalid_swap_xrpc()).await;
        let s = session_at(&pds);
        let err = repo(&http, &pool, &s, &key)
            .update_subscription("rk", &swap_sub(), Some(OLD_CID))
            .await
            .expect_err("the PDS refused the swap");
        assert!(crate::atproto::is_invalid_swap(&err), "{err:#}");

        let (_, pds, _) = serve_status_json(
            400,
            serde_json::json!({ "error": "InvalidRequest", "message": "bad record" }),
        )
        .await;
        let s = session_at(&pds);
        let err = repo(&http, &pool, &s, &key)
            .update_subscription("rk", &swap_sub(), Some(OLD_CID))
            .await
            .expect_err("refused");
        assert!(!crate::atproto::is_invalid_swap(&err), "{err:#}");
    }

    /// The folder CID listing pairs each folder with the CID it was listed at
    /// (#268).
    #[tokio::test]
    async fn list_folders_with_cids_keeps_each_records_cid() {
        use crate::atproto::tests::{
            assert_folders_listed_with_cids, serve_status_json, two_folders_page,
        };
        let (_, pds, _) = serve_status_json(200, two_folders_page()).await;
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let s = session_at(&pds);
        let listed = repo(&http, &pool, &s, &key)
            .list_folders_with_cids()
            .await
            .expect("listing");
        assert_folders_listed_with_cids(&listed);
    }

    /// The CID listing pairs each record with the CID it was listed at.
    #[tokio::test]
    async fn list_subscriptions_with_cids_keeps_each_records_cid() {
        use crate::atproto::tests::{assert_listed_with_cids, serve_status_json, two_subs_page};
        let (_, pds, _) = serve_status_json(200, two_subs_page()).await;
        let http = Client::new();
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::init_schema(&pool).await.unwrap();
        let key = SigningKey::generate("k");
        let s = session_at(&pds);
        let listed = repo(&http, &pool, &s, &key)
            .list_subscriptions_with_cids()
            .await
            .expect("listing");
        assert_listed_with_cids(&listed);
    }
}
