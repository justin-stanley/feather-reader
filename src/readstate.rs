//! Read-state flushing — turning dirty local cursors into `readState` records
//! in the user's own PDS.
//!
//! **In the LIB, not the binary's `scheduler`, because two callers need it.**
//! The background flusher is one. Sign-out is the other: it must flush before
//! revoking the session, or the reads are stranded with nothing able to send
//! them (#117). `scheduler` keeps the *scheduling* — the interval loop and the
//! DID selection; this module owns the domain logic.

use std::collections::{BTreeMap, HashSet};

use anyhow::Context as _;
use tracing::{info, warn};

use crate::atproto::AtProtoError;
use crate::lexicon::ReadState;
use crate::store::{self, ReadCursor};
use crate::AppState;

/// Flush a single DID's dirty cursors in one batched `applyWrites`, then clear
/// the `dirty` flag for the cursors that were included.
pub async fn flush_did(state: &AppState, did: &str) -> anyhow::Result<()> {
    let cursors = store::dirty_cursors(&state.db, did).await?;
    if cursors.is_empty() {
        return Ok(());
    }

    // Build (rkey, ReadState) pairs, deduping on rkey so two rows that hash to
    // the same feed-key don't produce two ops in one batch (applyWrites rejects
    // duplicate writes to the same key). Deterministic order for stable batches.
    let mut batch: Batch = BTreeMap::new();
    for cursor in cursors {
        // **Compact before capping.**
        //
        // `read_ids` grows one id per article read and is bounded only by
        // `max_entries_per_feed` (2000), while `cap` below truncates the record
        // at `ReadState::MAX_IDS` (1000) keeping the TAIL. Past 1000 read
        // articles in one feed the oldest read-state silently stopped syncing,
        // and those articles came back UNREAD in every other atproto reader —
        // the one thing the shared lexicon exists to prevent.
        //
        // `store::compact_cursor` folds the covered ids into the `read_through`
        // high-water-mark, which is the field that exists for exactly this and
        // was never being computed. Done here rather than on every mark-read
        // because this is the moment the size actually matters, and it is per
        // dirty cursor per flush rather than per click.
        let cursor = compact_if_large(state, did, cursor).await;
        let rkey = read_state_rkey(&cursor.feed_url);
        let record = read_state_record(&cursor);
        batch.insert(rkey, (record, cursor));
    }

    // ONE applyWrites round-trip for all of this DID's dirty feeds.
    let ops = batch_ops(&batch);
    if let Err(err) = state.repo().flush_read_states(did, &ops).await {
        // **A flag that disagrees with the PDS wedged this DID forever (#241).**
        //
        // `pds_created` picks create-vs-update and is learned only from a
        // success. A success whose answer was lost, or a fresh or restored
        // database against a repo that already holds these stable rkeys, leaves
        // it false over a record that exists; a record deleted elsewhere leaves
        // it true over one that does not. Either way one op fails, applyWrites
        // is atomic, the whole batch fails — and the next flush sends the same
        // batch. Nothing ever corrected the flag.
        //
        // So on a failure that COULD be that, ask the PDS once what exists, and
        // retry once if the answer changes anything. Never in a loop: a retry
        // that fails again is returned like any other failure, and the corrected
        // flags it leaves behind make the next round an ordinary flush.
        //
        // Not ALSO proactively, on each DID's first flush after startup: that
        // costs every healthy DID a listing per restart to save a wedged one a
        // single failed applyWrites, since this path converges inside the same
        // flush — and it would not cover a success lost mid-process anyway.
        if !may_be_existence_mismatch(&err) {
            return Err(err);
        }
        let corrected = reconcile_pds_created(state, did, &mut batch).await;
        match corrected {
            Ok(0) => return Err(err),
            Ok(fixed) => {
                info!(%did, fixed, "read-state flusher: pds_created disagreed with the PDS; reconciled, retrying once");
            }
            Err(list_err) => {
                warn!(%did, err = %list_err, "read-state flusher: could not list readState records to reconcile");
                return Err(err);
            }
        }
        let ops = batch_ops(&batch);
        state
            .repo()
            .flush_read_states(did, &ops)
            .await
            .context("read-state flush failed again after reconciling pds_created")?;
    }

    // Success — for each flushed cursor: mark its PDS record as created (so future
    // flushes emit an update), then clear `dirty` but ONLY if its `updated_at`
    // still matches the snapshot we just flushed. A mark-read that landed DURING
    // the in-flight PDS write bumped `updated_at` and re-dirtied the row; the
    // conditional clear leaves that row dirty so its new reads re-flush next
    // round instead of being silently dropped.
    let flushed = batch.len();
    for (_rkey, (_record, cursor)) in batch {
        // Flip the created flag first: the record now exists in the PDS regardless
        // of whether the dirty-clear below is a no-op due to a concurrent bump.
        if !cursor.pds_created {
            if let Err(err) = store::mark_cursor_pds_created(&state.db, did, &cursor.feed_url).await
            {
                warn!(%did, feed = %cursor.feed_url, %err, "failed to mark cursor pds_created");
            }
        }
        if let Err(err) =
            store::clear_cursor_dirty(&state.db, did, &cursor.feed_url, &cursor.updated_at).await
        {
            // The PDS write already landed; a failure to clear the local flag
            // just means we harmlessly re-flush this cursor next round.
            warn!(%did, feed = %cursor.feed_url, %err, "failed to clear cursor dirty flag");
        }
    }

    info!(%did, feeds = flushed, "read-state flusher: flushed dirty cursors");
    Ok(())
}

/// One flush's cursors, by rkey: the record to write and the row it came from.
type Batch = BTreeMap<String, (ReadState, ReadCursor)>;

/// The `(rkey, record, pds_created)` ops for a batch.
///
/// Each op carries whether its PDS record already exists: a not-yet-created
/// cursor becomes an applyWrites#create (not an #update, which would error and,
/// since applyWrites is atomic-per-repo, drop the whole DID batch on a feed's
/// first flush). All create + update ops ride ONE batch.
fn batch_ops(batch: &Batch) -> Vec<(String, ReadState, bool)> {
    batch
        .iter()
        .map(|(rkey, (record, cursor))| (rkey.clone(), record.clone(), cursor.pds_created))
        .collect()
}

/// Whether a failed flush may have been refused for a create/update mismatch —
/// `#create` at an rkey that exists, or `#update` at one that does not.
///
/// **Matched on the structured rejection, and it cannot be narrower than
/// this.** Both backends surface a PDS refusal as [`AtProtoError::Xrpc`] with
/// the status and error name; anything else — a transport failure, a missing
/// session, a body we could not read — is not a refusal at all, and is not
/// reconciled.
///
/// What the reference PDS sends for a mismatch was read from its source, not
/// guessed: `applyWrites` checks nothing per op without a `swapRecord`, so the
/// collision surfaces in `@atproto/repo`'s MST, whose `add` throws `There is
/// already a value at key` and whose `update` throws `Could not find a record
/// with key` — plain `Error`s, which xrpc-server answers as **500
/// `InternalServerError`**, message replaced by "Internal Server Error". There
/// is no more specific signal to match. A mismatch-shaped 500 is therefore
/// ambiguous by construction, which is why the reconcile retries only when the
/// listing actually finds a flag to correct.
///
/// A 400 or 409 naming a conflict is what a PDS that checks explicitly would
/// send (`InvalidSwap` is the reference's own name for a swap mismatch), so
/// those are included. NOT included: 401/403 (auth — a listing would fail the
/// same way), 429, and 502/503/504, which say the request may not have been
/// processed at all — a reconcile there would add a repo walk per DID per
/// round to a PDS that is already struggling. If such a write did land, the
/// next round's create meets the record and reconciles then.
fn may_be_existence_mismatch(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| match cause.downcast_ref::<AtProtoError>() {
            Some(AtProtoError::Xrpc { status, error, .. }) => match status.as_u16() {
                500 => error == "InternalServerError",
                400 => matches!(
                    error.as_str(),
                    "InvalidRequest" | "InvalidSwap" | "RecordNotFound"
                ),
                409 => true,
                _ => false,
            },
            _ => false,
        })
}

/// Set each batch cursor's `pds_created` to whether its record exists on the
/// PDS, locally and in memory. Returns how many flags changed.
///
/// **One listing of the collection, not a `getRecord` per rkey.** The sidecar
/// has no `get` action, so per-rkey reads would mean new surface on a backend
/// being retired; and a listing answers for every cursor in the batch at once,
/// which matters when the batch is hundreds of feeds — including ones a
/// partially-landed chunked batch (#240) created. It is the existing bounded
/// walk: a repo past its page cap REFUSES rather than answering short, and a
/// refusal here just returns the original error, which is the pre-#241
/// behaviour rather than a wrong flag.
///
/// Raw records, not [`crate::repo::Repo::list_read_states`]: that skips a record
/// it cannot parse, and a skipped record would read as a missing one and send
/// `#create` straight back into the collision.
///
/// The corrected flag is persisted even if the retry then fails, because it is
/// what the PDS holds either way — and it makes the next round a plain flush.
async fn reconcile_pds_created(
    state: &AppState,
    did: &str,
    batch: &mut Batch,
) -> anyhow::Result<usize> {
    let existing: HashSet<String> = state
        .repo()
        .list_all_records(did, crate::lexicon::nsid::READ_STATE)
        .await?
        .iter()
        .filter_map(|record| record.rkey().map(str::to_string))
        .collect();
    let mut fixed = 0;
    for (rkey, (_record, cursor)) in batch.iter_mut() {
        let exists = existing.contains(rkey);
        if cursor.pds_created == exists {
            continue;
        }
        cursor.pds_created = exists;
        fixed += 1;
        if let Err(err) =
            store::set_cursor_pds_created(&state.db, did, &cursor.feed_url, exists).await
        {
            // The in-memory flag still drives the retry. The row keeps the
            // stale flag — the success path only marks rows it believes it
            // CREATED — so the next flush meets the same mismatch and
            // reconciles again: one more listing, not a wedge.
            warn!(%did, feed = %cursor.feed_url, %err, "failed to record reconciled pds_created");
        }
    }
    Ok(fixed)
}

/// `read_ids` length at which a cursor is compacted before flushing.
///
/// Half of [`ReadState::MAX_IDS`], so compaction happens well before the cap
/// truncates anything, and the common cursor — a handful of ids — never pays for
/// the two extra queries.
const COMPACT_READ_IDS_THRESHOLD: usize = ReadState::MAX_IDS / 2;

/// Fold covered ids into the `read_through` water-mark when the exception set has
/// grown enough to matter, and return the rewritten cursor.
///
/// On ANY failure this returns the cursor it was given. Flushing an uncompacted
/// cursor is the behaviour that shipped for months — a compaction problem must
/// not become a read-state-sync problem.
async fn compact_if_large(state: &AppState, did: &str, cursor: ReadCursor) -> ReadCursor {
    if parse_id_array(&cursor.read_ids).len() < COMPACT_READ_IDS_THRESHOLD {
        return cursor;
    }
    match store::compact_cursor(&state.db, did, &cursor.feed_url).await {
        Ok(Some(watermark)) => {
            // Re-read: `compact_cursor` rewrote the row, and the flusher's
            // conditional dirty-clear compares `updated_at` against the version
            // it flushed. Carrying the pre-compaction snapshot forward would
            // clear a flag for a row that has since changed.
            match store::get_cursor(&state.db, did, &cursor.feed_url).await {
                Ok(Some(fresh)) => {
                    info!(
                        %did,
                        feed = %cursor.feed_url,
                        %watermark,
                        before = parse_id_array(&cursor.read_ids).len(),
                        after = parse_id_array(&fresh.read_ids).len(),
                        "read-state compacted into readThrough"
                    );
                    fresh
                }
                Ok(None) => cursor,
                Err(err) => {
                    warn!(%err, %did, feed = %cursor.feed_url, "could not re-read a compacted cursor");
                    cursor
                }
            }
        }
        Ok(None) => cursor,
        Err(err) => {
            warn!(%err, %did, feed = %cursor.feed_url, "read-state compaction failed; flushing uncompacted");
            cursor
        }
    }
}

/// Turn a local [`ReadCursor`] row into the PDS [`ReadState`] lexicon record.
///
/// The store keeps `read_ids` / `unread_ids` as JSON arrays of ids; the lexicon
/// wants string arrays. `read_through` is optional both locally AND in the
/// record: when the cursor has no local high-water-mark we pass `None` so the
/// record OMITS `readThrough` entirely. This is the conservative behaviour —
/// `readThrough` is a "everything seen/published `<=` this is read" water-mark,
/// so synthesizing a flush-time (`≈ now`) value for a cursor that has none would
/// assert the whole unread backlog is read. With `None` only the explicit
/// `read_ids` mark entries read. Both id-sets are capped at [`ReadState::MAX_IDS`]
/// to respect the lexicon bound.
fn read_state_record(cursor: &ReadCursor) -> ReadState {
    let read_ids = parse_id_array(&cursor.read_ids);
    let unread_ids = parse_id_array(&cursor.unread_ids);

    // Do NOT synthesize a water-mark from `updated_at`: an unset local
    // `read_through` means "no high-water-mark", which the record represents by
    // omitting `readThrough` (None), not by back-dating it to flush time.
    let mut record = ReadState::new(
        &cursor.feed_url,
        cursor.read_through.clone(),
        &cursor.updated_at,
    );
    record.read_ids = cap(read_ids, ReadState::MAX_IDS);
    record.unread_ids = cap(unread_ids, ReadState::MAX_IDS);
    record
}

/// Parse a stored JSON id-array into `Vec<String>`, tolerating both string and
/// numeric ids (the store keeps entry ids). A malformed/empty value yields an
/// empty set rather than an error — read-state must never fail to flush over a
/// cosmetic parse issue.
fn parse_id_array(raw: &str) -> Vec<String> {
    if raw.trim().is_empty() {
        return Vec::new();
    }
    match serde_json::from_str::<Vec<serde_json::Value>>(raw) {
        Ok(vals) => vals
            .into_iter()
            .map(|v| match v {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            })
            .collect(),
        Err(err) => {
            warn!(%err, raw, "read-state flusher: unparseable id array; treating as empty");
            Vec::new()
        }
    }
}

/// Truncate a set to `max`, keeping the most recent (tail) ids — the lexicon's
/// hard cap, and the LAST line of defence rather than the only one.
///
/// This used to be the only one, under the stated assumption that "the exception
/// sets are expected to stay well under the cap in normal use". Against a 2000
/// entry per-feed ceiling and one id per article read, that did not hold: past
/// 1000 read articles in a feed this silently dropped the oldest read-state, and
/// those articles came back UNREAD in every other atproto reader.
///
/// [`compact_if_large`] now folds covered ids into `read_through` before a cursor
/// gets here, so reaching this truncation means compaction could not advance the
/// water-mark — which happens only when the feed's oldest entry is genuinely
/// unread. Losing the tail is still wrong in that case, but it is now a rare
/// shape rather than the ordinary consequence of reading a busy feed.
fn cap(mut ids: Vec<String>, max: usize) -> Vec<String> {
    if ids.len() > max {
        let drop = ids.len() - max;
        warn!(
            dropped = drop,
            kept = max,
            "read-state id set exceeded the lexicon cap even after compaction; \
             the oldest marks will not sync"
        );
        ids.drain(0..drop);
    }
    ids
}

/// Derive the deterministic, stable rkey for a feed's read-state record from its
/// URL, so there is exactly **one record per feed** (a fixed key, not a fresh tid
/// per flush).
///
/// atproto record keys must match `[A-Za-z0-9._~:-]{1,512}` (and not be `.`/`..`).
/// A lowercase-hex FNV-1a-64 digest of the feed URL satisfies that, is stable
/// across restarts and instances, and collides only on genuine hash collision
/// (astronomically unlikely at feed scale; the flusher additionally dedups by
/// rkey within a batch as a belt-and-braces guard).
///
/// The stable rkey is what makes create-then-update work: a feed's FIRST flush
/// emits an `applyWrites#create` at this key (tracked by `read_cursor.pds_created`)
/// and every subsequent flush an `#update` at the same key, so there is exactly
/// one record per feed and the first flush never fails on a missing record.
pub fn read_state_rkey(feed_url: &str) -> String {
    format!("rs-{:016x}", fnv1a_64(feed_url.as_bytes()))
}

/// FNV-1a 64-bit — a tiny, dependency-free stable hash for the feed-key.
///
/// `pub` because `scheduler::jittered` seeds its per-feed jitter from the same
/// hash. Two unrelated uses of one generic utility; exported rather than copied,
/// since two drifting implementations of a stable key hash would be worse than
/// the slightly odd home.
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rkey_is_stable_and_valid() {
        let a = read_state_rkey("https://example.com/feed.xml");
        let b = read_state_rkey("https://example.com/feed.xml");
        assert_eq!(a, b, "rkey must be deterministic");
        assert_ne!(a, read_state_rkey("https://other.example/feed.xml"));
        // Valid atproto rkey: charset, length and the reserved names, as the
        // one shared rule states them.
        assert!(crate::atproto::is_valid_rkey(&a), "{a:?}");
    }
    #[test]
    fn parse_id_array_tolerates_shapes() {
        assert_eq!(parse_id_array(""), Vec::<String>::new());
        assert_eq!(parse_id_array("[]"), Vec::<String>::new());
        assert_eq!(parse_id_array(r#"["a","b"]"#), vec!["a", "b"]);
        assert_eq!(parse_id_array("[1,2,3]"), vec!["1", "2", "3"]);
        assert_eq!(parse_id_array("not json"), Vec::<String>::new());
    }
    #[test]
    fn cap_keeps_tail_within_bound() {
        let ids: Vec<String> = (0..10).map(|i| i.to_string()).collect();
        let capped = cap(ids, 3);
        assert_eq!(capped, vec!["7", "8", "9"]);
    }
    /// **The cap is APPLIED, not just correct.** `cap` had its own unit test
    /// and every record-building test used 1–3 ids, so `read_state_record`
    /// could stop calling it with the suite green — and the flusher would
    /// publish id arrays past the lexicon's bound, the PDS would reject the
    /// atomic batch, and every feed's read-state would stop syncing.
    #[test]
    fn read_state_record_applies_the_id_cap() {
        let ids: Vec<String> = (0..ReadState::MAX_IDS + 5).map(|i| i.to_string()).collect();
        let json = serde_json::to_string(&ids).unwrap();
        let cursor = crate::store::ReadCursor {
            did: "did:plc:x".into(),
            feed_url: "https://example.com/feed.xml".into(),
            read_through: None,
            read_ids: json.clone(),
            unread_ids: json,
            dirty: true,
            pds_created: false,
            updated_at: "2026-07-12T00:00:00Z".into(),
        };
        let rec = read_state_record(&cursor);
        assert_eq!(
            rec.read_ids.len(),
            ReadState::MAX_IDS,
            "read_ids not capped"
        );
        assert_eq!(
            rec.unread_ids.len(),
            ReadState::MAX_IDS,
            "unread_ids not capped"
        );
    }

    #[test]
    fn record_maps_cursor_fields() {
        let cursor = ReadCursor {
            did: "did:plc:abc".into(),
            feed_url: "https://example.com/feed.xml".into(),
            read_through: Some("2026-07-12T00:00:00Z".into()),
            read_ids: r#"["10","11"]"#.into(),
            unread_ids: "[]".into(),
            dirty: true,
            pds_created: false,
            updated_at: "2026-07-12T01:00:00Z".into(),
        };
        let rec = read_state_record(&cursor);
        assert_eq!(rec.feed_url, "https://example.com/feed.xml");
        assert_eq!(rec.read_through.as_deref(), Some("2026-07-12T00:00:00Z"));
        assert_eq!(rec.read_ids, vec!["10", "11"]);
        assert!(rec.unread_ids.is_empty());
        assert_eq!(rec.updated_at, "2026-07-12T01:00:00Z");
    }
    #[test]
    fn read_through_omitted_when_local_unset() {
        // A cursor with no local high-water-mark must NOT synthesize one from
        // `updated_at` (≈ now) — doing so would mark the whole backlog read. The
        // record omits `readThrough` (None) so only explicit read_ids apply.
        let cursor = ReadCursor {
            did: "did:plc:abc".into(),
            feed_url: "https://example.com/feed.xml".into(),
            read_through: None,
            read_ids: r#"["42"]"#.into(),
            unread_ids: "[]".into(),
            dirty: true,
            pds_created: false,
            updated_at: "2026-07-12T01:00:00Z".into(),
        };
        let rec = read_state_record(&cursor);
        assert_eq!(
            rec.read_through, None,
            "no local water-mark => readThrough absent (backlog not implicitly read)"
        );
        // The explicit read_ids still carry through.
        assert_eq!(rec.read_ids, vec!["42"]);
        // Serialized form must not carry a readThrough field at all.
        let json = serde_json::to_value(&rec).expect("serialize");
        assert!(json.get("readThrough").is_none());
    }
    #[test]
    fn read_through_present_when_local_high_water_mark_exists() {
        // A real high-water-mark IS written through unchanged.
        let cursor = ReadCursor {
            did: "did:plc:abc".into(),
            feed_url: "https://example.com/feed.xml".into(),
            read_through: Some("2026-07-11T00:00:00Z".into()),
            read_ids: "[]".into(),
            unread_ids: "[]".into(),
            dirty: true,
            pds_created: false,
            updated_at: "2026-07-12T01:00:00Z".into(),
        };
        let rec = read_state_record(&cursor);
        assert_eq!(rec.read_through.as_deref(), Some("2026-07-11T00:00:00Z"));
    }
    #[test]
    fn flush_with_only_read_ids_sets_no_read_through() {
        // The core F1 guarantee: a flush whose cursor carries only explicit
        // read_ids (and no water-mark) emits a record WITHOUT readThrough, so the
        // user's PDS never asserts the backlog is read.
        let cursor = ReadCursor {
            did: "did:plc:abc".into(),
            feed_url: "https://example.com/feed.xml".into(),
            read_through: None,
            read_ids: r#"["100","101","102"]"#.into(),
            unread_ids: "[]".into(),
            dirty: true,
            pds_created: false,
            updated_at: "2026-07-12T02:00:00Z".into(),
        };
        let rec = read_state_record(&cursor);
        assert_eq!(rec.read_through, None);
        assert_eq!(rec.read_ids, vec!["100", "101", "102"]);
        let json = serde_json::to_value(&rec).expect("serialize");
        assert!(json.get("readThrough").is_none());
        assert_eq!(json["readIds"], serde_json::json!(["100", "101", "102"]));
    }

    // ── #241: a pds_created flag that disagrees with the PDS ─────────────────
    //
    // Driven end to end through `flush_did` against a STATEFUL fake repo,
    // because the bug is the interaction: the flag picks create-vs-update, the
    // PDS refuses the whole atomic batch, and nothing ever corrects the flag.
    // The fixed-body servers in `net::tests` answer every request identically,
    // so they cannot model "the second applyWrites succeeds because the listing
    // changed what was sent".

    use std::sync::{Arc, Mutex};

    use crate::metrics::Backend;

    const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

    /// An applyWrites failure the fake answers with.
    #[derive(Clone, Copy, Debug)]
    struct Fail {
        status: u16,
        error: &'static str,
    }

    /// What the reference PDS answers to `#create` on an existing rkey AND to
    /// `#update` on a missing one: `@atproto/repo`'s MST `add`/`update` throw a
    /// plain `Error`, which xrpc-server turns into a 500 whose message it strips.
    const MISMATCH: Fail = Fail {
        status: 500,
        error: "InternalServerError",
    };

    /// One account's `readState` collection, with the reference PDS's
    /// create/update semantics and atomicity, and counters for what was asked.
    #[derive(Default)]
    struct FakeRepo {
        records: BTreeMap<String, serde_json::Value>,
        apply_calls: usize,
        /// listRecords requests with no cursor — one per walk, however many
        /// pages that walk turns out to need.
        list_walks: usize,
        /// Fail every applyWrites with this, whatever its ops.
        always_fail: Option<Fail>,
        /// Land the first N ops of the next applyWrites, then answer 503 — a
        /// later chunk failing after an earlier one committed (#240).
        partial_then_503: Option<usize>,
        /// Answer every listRecords with a 503.
        list_fails: bool,
    }

    impl FakeRepo {
        fn op(w: &serde_json::Value) -> (String, String, serde_json::Value) {
            // The sidecar spells the action out; XRPC tags the union member.
            let action = w["action"].as_str().map(str::to_string).unwrap_or_else(|| {
                w["$type"]
                    .as_str()
                    .and_then(|t| t.rsplit('#').next())
                    .unwrap_or_default()
                    .to_string()
            });
            assert_eq!(w["collection"], crate::lexicon::nsid::READ_STATE);
            let rkey = w["rkey"].as_str().expect("readState ops carry an rkey");
            (action, rkey.to_string(), w["value"].clone())
        }

        fn apply(&mut self, writes: &[serde_json::Value]) -> Result<(), Fail> {
            self.apply_calls += 1;
            if let Some(fail) = self.always_fail {
                return Err(fail);
            }
            if let Some(landed) = self.partial_then_503.take() {
                for w in writes.iter().take(landed) {
                    let (_, rkey, value) = Self::op(w);
                    self.records.insert(rkey, value);
                }
                return Err(Fail {
                    status: 503,
                    error: "PartitionUnavailable",
                });
            }
            // All or nothing, like the reference: every op is checked before
            // any lands.
            for w in writes {
                let (action, rkey, _) = Self::op(w);
                let exists = self.records.contains_key(&rkey);
                if (action == "create" && exists) || (action == "update" && !exists) {
                    return Err(MISMATCH);
                }
            }
            for w in writes {
                let (_, rkey, value) = Self::op(w);
                self.records.insert(rkey, value);
            }
            Ok(())
        }

        fn page(&mut self, limit: Option<usize>, cursor: Option<&str>) -> serde_json::Value {
            if cursor.is_none() {
                self.list_walks += 1;
            }
            let limit = limit.unwrap_or(50);
            let after: Vec<_> = self
                .records
                .iter()
                .filter(|(rkey, _)| cursor.is_none_or(|c| rkey.as_str() > c))
                .collect();
            let page: Vec<_> = after.iter().take(limit).collect();
            let records: Vec<serde_json::Value> = page
                .iter()
                .map(|(rkey, value)| {
                    serde_json::json!({
                        "uri": format!("at://{DID}/{}/{rkey}", crate::lexicon::nsid::READ_STATE),
                        "cid": "bafyreigh2akiscaildc",
                        "value": value,
                    })
                })
                .collect();
            let mut body = serde_json::json!({ "records": records });
            if after.len() > limit {
                body["cursor"] = serde_json::json!(page.last().unwrap().0);
            }
            body
        }
    }

    /// Serve `fake` as BOTH a sidecar (`/internal/repo`) and a PDS (`/xrpc/*`),
    /// so one fixture drives either backend. Returns the sidecar base URL and
    /// the PDS audience a session should carry.
    async fn serve_fake(fake: Arc<Mutex<FakeRepo>>) -> (String, String) {
        use axum::http::StatusCode;
        use axum::response::IntoResponse as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        // Unique per server: the override table is process-wide.
        let host = format!("pds-{port}.readstate.test");
        crate::net::test_host_override(&host, addr);

        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let fake = Arc::clone(&fake);
            async move {
                let (parts, body) = req.into_parts();
                let raw = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                let query: std::collections::HashMap<String, String> =
                    url::form_urlencoded::parse(parts.uri.query().unwrap_or("").as_bytes())
                        .into_owned()
                        .collect();
                let reply = |status: u16, body: serde_json::Value| {
                    (StatusCode::from_u16(status).unwrap(), axum::Json(body)).into_response()
                };
                let mut fake = fake.lock().unwrap();
                match parts.uri.path() {
                    "/internal/repo" => {
                        let req: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                        match req["action"].as_str() {
                            Some("list") => {
                                let page = fake.page(
                                    req["limit"].as_u64().map(|l| l as usize),
                                    req["cursor"].as_str(),
                                );
                                if fake.list_fails {
                                    return reply(
                                        503,
                                        serde_json::json!({ "ok": false, "error": "PartitionUnavailable", "status": 503 }),
                                    );
                                }
                                reply(200, serde_json::json!({ "ok": true, "data": page }))
                            }
                            Some("applyWrites") => {
                                match fake.apply(req["writes"].as_array().unwrap()) {
                                    Ok(()) => {
                                        reply(200, serde_json::json!({ "ok": true, "data": {} }))
                                    }
                                    // The sidecar's envelope, carrying the PDS's
                                    // status and error name through.
                                    Err(f) => reply(
                                        f.status,
                                        serde_json::json!({
                                            "ok": false,
                                            "error": f.error,
                                            "message": "Internal Server Error",
                                            "status": f.status,
                                        }),
                                    ),
                                }
                            }
                            other => panic!("unexpected sidecar action {other:?}"),
                        }
                    }
                    "/xrpc/com.atproto.repo.listRecords" => {
                        let page = fake.page(
                            query.get("limit").and_then(|l| l.parse().ok()),
                            query.get("cursor").map(String::as_str),
                        );
                        if fake.list_fails {
                            return reply(503, serde_json::json!({ "error": "PartitionUnavailable" }));
                        }
                        reply(200, page)
                    }
                    "/xrpc/com.atproto.repo.applyWrites" => {
                        let req: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                        match fake.apply(req["writes"].as_array().unwrap()) {
                            Ok(()) => reply(200, serde_json::json!({ "results": [] })),
                            Err(f) => reply(
                                f.status,
                                serde_json::json!({
                                    "error": f.error,
                                    "message": "Internal Server Error",
                                }),
                            ),
                        }
                    }
                    other => panic!("unexpected request to {other}"),
                }
            }
        });
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), format!("http://{host}:{port}"))
    }

    /// An `AppState` on `backend`, pointed at the fake — the sidecar through its
    /// internal URL, the Rust client through a live session whose `aud` is it.
    async fn state_on(backend: Backend, fake: &Arc<Mutex<FakeRepo>>) -> AppState {
        let (sidecar, aud) = serve_fake(Arc::clone(fake)).await;
        let db = store::init_url("sqlite::memory:").await.unwrap();
        let state = AppState::new(
            crate::config::Config {
                repo_backend: backend,
                public_url: "http://localhost:8080".into(),
                sidecar: crate::config::SidecarConfig {
                    public_url: sidecar.clone(),
                    internal_url: sidecar,
                    internal_secret: "test-secret".into(),
                },
                oauth: crate::config::OauthConfig {
                    // Per test, never the relative default — see `repo::tests`.
                    key_path: std::env::temp_dir().join(format!(
                        "fr-readstate-oauth-key-{}-{:p}.json",
                        std::process::id(),
                        &db as *const _
                    )),
                    encryption_key: Some("a".repeat(43)),
                    ..crate::config::OauthConfig::default()
                },
                ..crate::config::Config::default()
            },
            db,
        )
        .unwrap();
        if backend == Backend::Rust {
            let runtime = state.oauth.as_deref().expect("oauth runtime");
            crate::oauth::store::put_session(
                &state.db,
                &runtime.codec,
                &crate::oauth::store::OAuthSession {
                    sub: DID.into(),
                    issuer: "https://auth.invalid".into(),
                    aud,
                    dpop_key_jwk: crate::oauth::keys::SigningKey::generate("session-dpop")
                        .to_jwk_json()
                        .unwrap(),
                    access_token: "at".into(),
                    refresh_token: "rt".into(),
                    token_type: "DPoP".into(),
                    granted_scope: "atproto".into(),
                    expires_at: Some(store::now_unix() + 3600),
                },
            )
            .await
            .unwrap();
        }
        state
    }

    fn feed(i: usize) -> String {
        format!("https://f{i}.example/feed.xml")
    }

    /// A dirty cursor for feed `i`, as a mark-read leaves it. `updated_at`
    /// differs per call so the conditional dirty-clear sees a new snapshot.
    async fn mark_read(state: &AppState, i: usize, id: &str) {
        static TICK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let tick = TICK.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        store::upsert_cursor(
            &state.db,
            &ReadCursor {
                did: DID.into(),
                feed_url: feed(i),
                read_through: None,
                read_ids: format!("[\"{id}\"]"),
                unread_ids: "[]".into(),
                dirty: true,
                pds_created: false,
                updated_at: format!(
                    "2026-10-04T{:02}:{:02}:{:02}Z",
                    tick / 3600 % 24,
                    tick / 60 % 60,
                    tick % 60
                ),
            },
        )
        .await
        .unwrap();
    }

    /// A record already in the fake repo for feed `i`, from some earlier flush.
    fn existing(fake: &Arc<Mutex<FakeRepo>>, i: usize) {
        let record = ReadState::new(feed(i), None, "2026-01-01T00:00:00Z");
        fake.lock().unwrap().records.insert(
            read_state_rkey(&feed(i)),
            serde_json::to_value(record).unwrap(),
        );
    }

    async fn cursor(state: &AppState, i: usize) -> ReadCursor {
        store::get_cursor(&state.db, DID, &feed(i))
            .await
            .unwrap()
            .expect("cursor row")
    }

    fn read_ids_on_pds(fake: &Arc<Mutex<FakeRepo>>, i: usize) -> serde_json::Value {
        fake.lock().unwrap().records[&read_state_rkey(&feed(i))]["readIds"].clone()
    }

    const BACKENDS: [Backend; 2] = [Backend::Sidecar, Backend::Rust];

    /// **(1) A lost success response converges.** The applyWrites that created
    /// the record landed, but its answer never arrived, so `pds_created` is still
    /// false and every later flush sends `#create` at an rkey that exists. Before
    /// the fix that batch failed forever and took the DID's whole read-state
    /// sync with it.
    #[tokio::test]
    async fn a_lost_create_response_converges_on_the_next_flush() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            existing(&fake, 1);
            mark_read(&state, 1, "42").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: the flush stayed wedged: {e:#}"));

            let c = cursor(&state, 1).await;
            assert!(c.pds_created, "{backend:?}: pds_created was not corrected");
            assert!(!c.dirty, "{backend:?}: the cursor is still dirty");
            assert_eq!(
                read_ids_on_pds(&fake, 1),
                serde_json::json!(["42"]),
                "{backend:?}"
            );
            {
                let f = fake.lock().unwrap();
                assert_eq!(
                    f.list_walks, 1,
                    "{backend:?}: expected exactly one reconcile"
                );
                assert_eq!(
                    f.apply_calls, 2,
                    "{backend:?}: the failed batch, then the retry"
                );
            }

            // Steady state again: the next flush is a plain update, no listing.
            mark_read(&state, 1, "43").await;
            flush_did(&state, DID).await.expect("steady-state flush");
            let f = fake.lock().unwrap();
            assert_eq!(f.list_walks, 1, "{backend:?}: a healthy flush reconciled");
            assert_eq!(f.apply_calls, 3, "{backend:?}");
        }
    }

    /// **(2) A fresh or restored database against a repo that already holds
    /// the records.** Several feeds among records of others, more than one
    /// listing page of them, so the reconcile has to walk.
    #[tokio::test]
    async fn a_fresh_database_converges_against_existing_records() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            for i in 0..150 {
                existing(&fake, i);
            }
            for i in [3, 77, 149] {
                mark_read(&state, i, "7").await;
            }

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            for i in [3, 77, 149] {
                let c = cursor(&state, i).await;
                assert!(
                    c.pds_created && !c.dirty,
                    "{backend:?}: feed {i} did not converge"
                );
                assert_eq!(
                    read_ids_on_pds(&fake, i),
                    serde_json::json!(["7"]),
                    "{backend:?}"
                );
            }
            let f = fake.lock().unwrap();
            assert_eq!(f.list_walks, 1, "{backend:?}");
            assert_eq!(f.apply_calls, 2, "{backend:?}");
            assert_eq!(
                f.records.len(),
                150,
                "{backend:?}: a record was duplicated or lost"
            );
        }
    }

    /// **(3) The mirror: `pds_created` is set but the record was deleted
    /// elsewhere** (another client, a repo reset). `#update` on a missing rkey
    /// fails the same way, and converges by creating it.
    #[tokio::test]
    async fn a_deleted_record_converges_by_creating_it() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            mark_read(&state, 1, "9").await;
            store::mark_cursor_pds_created(&state.db, DID, &feed(1))
                .await
                .unwrap();

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            let c = cursor(&state, 1).await;
            assert!(c.pds_created && !c.dirty, "{backend:?}");
            assert_eq!(
                read_ids_on_pds(&fake, 1),
                serde_json::json!(["9"]),
                "{backend:?}"
            );
            let f = fake.lock().unwrap();
            assert_eq!((f.list_walks, f.apply_calls), (1, 2), "{backend:?}");
        }
    }

    /// **(4) Part of a batch landed.** With applyWrites chunked (#240), a later
    /// chunk can fail after an earlier one committed — exactly this issue's
    /// state for every cursor in the landed chunk. That first failure is a 503,
    /// which is NOT reconciled; the next flush meets the half-landed batch, mixed
    /// with a flag that is wrong the other way, and converges in one reconcile.
    #[tokio::test]
    async fn a_partially_landed_batch_converges() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            for i in 1..=4 {
                mark_read(&state, i, "5").await;
            }
            // Feed 4 claims a record that is not there.
            store::mark_cursor_pds_created(&state.db, DID, &feed(4))
                .await
                .unwrap();
            fake.lock().unwrap().partial_then_503 = Some(2);

            flush_did(&state, DID)
                .await
                .expect_err("the 503 must surface as a failure");
            {
                let f = fake.lock().unwrap();
                assert_eq!(
                    f.list_walks, 0,
                    "{backend:?}: a 503 is not a mismatch and must not reconcile"
                );
                assert_eq!(f.records.len(), 2, "{backend:?}: fixture");
            }

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            for i in 1..=4 {
                let c = cursor(&state, i).await;
                assert!(c.pds_created && !c.dirty, "{backend:?}: feed {i}");
                assert_eq!(
                    read_ids_on_pds(&fake, i),
                    serde_json::json!(["5"]),
                    "{backend:?}"
                );
            }
            let f = fake.lock().unwrap();
            assert_eq!(f.list_walks, 1, "{backend:?}");
            assert_eq!(f.apply_calls, 3, "{backend:?}: 503, mismatch, retry");
        }
    }

    /// **(5) An unrelated failure behaves exactly as before:** the error comes
    /// back, the cursors stay dirty, and nothing is listed. A reconcile on every
    /// outage would add a repo walk per DID per minute to a PDS that is already
    /// struggling.
    #[tokio::test]
    async fn an_unrelated_failure_is_returned_without_a_reconcile() {
        for backend in BACKENDS {
            for fail in [
                Fail {
                    status: 503,
                    error: "PartitionUnavailable",
                },
                Fail {
                    status: 502,
                    error: "UpstreamFailure",
                },
                Fail {
                    status: 401,
                    error: "AuthRequired",
                },
                Fail {
                    status: 429,
                    error: "RateLimitExceeded",
                },
            ] {
                let fake = Arc::new(Mutex::new(FakeRepo::default()));
                let state = state_on(backend, &fake).await;
                // A real mismatch is present too, so a reconcile WOULD find
                // something to fix — what is under test is that it is not tried.
                existing(&fake, 1);
                mark_read(&state, 1, "1").await;
                fake.lock().unwrap().always_fail = Some(fail);

                flush_did(&state, DID)
                    .await
                    .expect_err("the failure must be returned");

                let c = cursor(&state, 1).await;
                assert!(c.dirty, "{backend:?} {fail:?}: the reads were dropped");
                assert!(!c.pds_created, "{backend:?} {fail:?}: the flag moved");
                let f = fake.lock().unwrap();
                assert_eq!(
                    f.list_walks, 0,
                    "{backend:?} {fail:?}: reconciled an unrelated failure"
                );
                assert_eq!(
                    f.apply_calls, 1,
                    "{backend:?} {fail:?}: retried an unrelated failure"
                );
            }
        }
    }

    /// **(6) At most one reconcile per flush — never a loop.** The PDS refuses
    /// every write with the mismatch-shaped error, so the retry fails too: the
    /// flush must give up after one listing and one retry, keep the cursor
    /// dirty, and still record the truth it learned.
    #[tokio::test]
    async fn a_flush_reconciles_at_most_once() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            existing(&fake, 1);
            mark_read(&state, 1, "1").await;
            fake.lock().unwrap().always_fail = Some(MISMATCH);

            flush_did(&state, DID)
                .await
                .expect_err("a retry that fails again is a failure");

            let c = cursor(&state, 1).await;
            assert!(c.dirty, "{backend:?}: the reads were dropped");
            assert!(
                c.pds_created,
                "{backend:?}: the truth the listing found was not kept"
            );
            let f = fake.lock().unwrap();
            assert_eq!(f.list_walks, 1, "{backend:?}: reconciled more than once");
            assert_eq!(f.apply_calls, 2, "{backend:?}: retried more than once");
        }
    }

    /// **Which refusals earn a reconcile, pinned per arm.** The end-to-end tests
    /// above use the reference PDS's 500 and four unrelated statuses; the 400
    /// and 409 arms, and the rule that only a STRUCTURED rejection counts, are
    /// asserted here.
    #[test]
    fn only_a_structured_conflict_shaped_rejection_may_be_a_mismatch() {
        let xrpc = |status: u16, error: &str| -> anyhow::Error {
            AtProtoError::Xrpc {
                status: reqwest::StatusCode::from_u16(status).unwrap(),
                error: error.into(),
                message: None,
            }
            .into()
        };
        for (status, error) in [
            (500, "InternalServerError"),
            (400, "InvalidRequest"),
            (400, "InvalidSwap"),
            (400, "RecordNotFound"),
            (409, "Conflict"),
        ] {
            assert!(
                may_be_existence_mismatch(&xrpc(status, error)),
                "{status} {error} should reconcile"
            );
            // Through a context layer, as the Rust client wraps it.
            assert!(
                may_be_existence_mismatch(&xrpc(status, error).context("applyWrites failed")),
                "{status} {error} behind a context should reconcile"
            );
        }
        for (status, error) in [
            (500, "Unknown"),
            (400, "ExpiredToken"),
            (401, "AuthRequired"),
            (403, "CollectionNotAllowed"),
            (404, "SessionNotFound"),
            (429, "RateLimitExceeded"),
            (502, "UpstreamFailure"),
            (503, "StoreUnavailable"),
            (504, "UpstreamTimeout"),
        ] {
            assert!(
                !may_be_existence_mismatch(&xrpc(status, error)),
                "{status} {error} must not reconcile"
            );
        }
        // Words are not a rejection: only the structured error counts.
        assert!(!may_be_existence_mismatch(&anyhow::anyhow!(
            "applyWrites failed: status 500 (InternalServerError)"
        )));
    }

    /// **A reconcile that cannot list gives up, and says what the WRITE said.**
    /// The listing is the only evidence a retry would be different; without it
    /// the batch is not resent, the cursor stays dirty, and the error returned
    /// is the applyWrites failure, not the listing's.
    #[tokio::test]
    async fn a_reconcile_that_cannot_list_returns_the_original_error() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            existing(&fake, 1);
            mark_read(&state, 1, "1").await;
            fake.lock().unwrap().list_fails = true;

            let err = flush_did(&state, DID)
                .await
                .expect_err("an unreconciled mismatch is still a failure");
            assert!(
                may_be_existence_mismatch(&err),
                "{backend:?}: returned the listing's error, not the write's: {err:#}"
            );
            let c = cursor(&state, 1).await;
            assert!(c.dirty && !c.pds_created, "{backend:?}");
            let f = fake.lock().unwrap();
            assert_eq!((f.list_walks, f.apply_calls), (1, 1), "{backend:?}");
        }
    }

    /// **A 500 the listing cannot explain is not retried.** The reference PDS
    /// reports a mismatch as a bare 500, so a 500 earns one listing — but when
    /// every flag already matches the repo, resending the identical batch could
    /// only fail the same way, so the original error comes back unchanged.
    #[tokio::test]
    async fn a_500_with_no_mismatch_is_not_retried() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            // pds_created=false and no record: the flag is already right.
            mark_read(&state, 1, "1").await;
            fake.lock().unwrap().always_fail = Some(MISMATCH);

            flush_did(&state, DID)
                .await
                .expect_err("the 500 must be returned");

            let c = cursor(&state, 1).await;
            assert!(c.dirty && !c.pds_created, "{backend:?}");
            let f = fake.lock().unwrap();
            assert_eq!((f.list_walks, f.apply_calls), (1, 1), "{backend:?}");
        }
    }
}
