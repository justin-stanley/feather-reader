//! Read-state flushing — turning dirty local cursors into `readState` records
//! in the user's own PDS.
//!
//! **In the LIB, not the binary's `scheduler`, because two callers need it.**
//! The background flusher is one. Sign-out is the other: it must flush before
//! revoking the session, or the reads are stranded with nothing able to send
//! them (#117). `scheduler` keeps the *scheduling* — the interval loop and the
//! DID selection; this module owns the domain logic.

use std::collections::BTreeMap;

use tracing::{info, warn};

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
    let mut batch: BTreeMap<String, (ReadState, ReadCursor)> = BTreeMap::new();
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

    // Each op carries whether its PDS record already exists: a not-yet-created
    // cursor becomes an applyWrites#create (not an #update, which would error and,
    // since applyWrites is atomic-per-repo, drop the whole DID batch on a feed's
    // first flush). All create + update ops ride ONE batch.
    let ops: Vec<(String, ReadState, bool)> = batch
        .iter()
        .map(|(rkey, (record, cursor))| (rkey.clone(), record.clone(), cursor.pds_created))
        .collect();

    // ONE applyWrites round-trip for all of this DID's dirty feeds.
    state.repo().flush_read_states(did, &ops).await?;

    // Success — for each flushed cursor: mark its PDS record as created (so future
    // flushes emit an update), then clear `dirty` but ONLY if its `updated_at`
    // still matches the snapshot we just flushed. A mark-read that landed DURING
    // the in-flight PDS write bumped `updated_at` and re-dirtied the row; the
    // conditional clear leaves that row dirty so its new reads re-flush next
    // round instead of being silently dropped.
    let flushed = ops.len();
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
}
