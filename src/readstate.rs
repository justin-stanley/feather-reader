//! Read-state flushing — turning dirty local cursors into `readState` records
//! in the user's own PDS.
//!
//! **In the LIB, not the binary's `scheduler`, because two callers need it.**
//! The background flusher is one. Sign-out is the other: it must flush before
//! revoking the session, or the reads are stranded with nothing able to send
//! them (#117). `scheduler` keeps the *scheduling* — the interval loop and the
//! DID selection; this module owns the domain logic.

use std::collections::{BTreeMap, HashMap, HashSet};

use tracing::{info, warn};

use crate::atproto::AtProtoError;
use crate::lexicon::ReadState;
use crate::store::{self, ReadCursor};
use crate::AppState;

/// Flush a single DID's dirty cursors in one batched `applyWrites`, then clear
/// the `dirty` flag for the cursors that were included.
///
/// **Read, merge, write (#246).** A flush used to write the local cursor over
/// whatever the PDS held, so a fresh or restored database — or this instance
/// after another client marked something read — erased read state recorded
/// elsewhere. Now, before writing, the DID's `readState` records are listed
/// ONCE and each dirty cursor is merged with its own record (see
/// `merge_remote`): remote reads of entries this instance has are imported
/// into `entry_state`, every remote GUID that did not lose a conflict is
/// carried into the written record, and `readThrough` is the later of the
/// two. The same listing
/// sets each cursor's `pds_created`, so a fresh database's first flush is an
/// `#update` rather than a refused `#create`.
///
/// A listing that fails does not block the flush, but nothing that exists is
/// overwritten without it: only cursors whose record is believed not to exist
/// (`pds_created` false) are written, and the rest stay dirty for the next
/// round.
pub async fn flush_did(state: &AppState, did: &str) -> anyhow::Result<()> {
    let cursors = store::dirty_cursors(&state.db, did).await?;
    if cursors.is_empty() {
        return Ok(());
    }

    let (remote, cursors) = match state
        .repo()
        .list_all_records(did, crate::lexicon::nsid::READ_STATE)
        .await
    {
        Ok(records) => (Some(Remote::from_listing(&records)), cursors),
        Err(err) => {
            // **Without the listing, only records believed not to exist are
            // written.** Writing local state over one that does, unmerged,
            // erases what other clients put in it and can move its
            // `readThrough` backwards — #246 itself. A `#create` cannot erase
            // anything: if the record exists after all, the PDS refuses it and
            // the reconcile below takes over.
            let (new, held): (Vec<_>, Vec<_>) = cursors.into_iter().partition(|c| !c.pds_created);
            warn!(
                %did,
                err = %err,
                writing = new.len(),
                held = held.len(),
                "read-state flusher: could not list readState records; writing only new records, leaving existing ones dirty for the next round"
            );
            (None, new)
        }
    };
    if let Some(remote) = &remote {
        import_into_clean_cursors(state, did, remote).await;
    }

    // Build (rkey, ReadState) pairs, deduping on rkey so two rows that hash to
    // the same feed-key don't produce two ops in one batch (applyWrites rejects
    // duplicate writes to the same key). Deterministic order for stable batches.
    let mut batch: Batch = BTreeMap::new();
    for mut cursor in cursors {
        let rkey = read_state_rkey(&cursor.feed_url);
        let mut theirs = None;
        if let Some(remote) = &remote {
            learn_pds_created(state, did, &mut cursor, remote.rkeys.contains(&rkey)).await;
            theirs = remote.record_for(&rkey, &cursor.feed_url);
        }
        let mut carry = Carry::default();
        if let Some(theirs) = theirs {
            (cursor, carry) = merge_remote(state, did, cursor, theirs).await;
        }
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
        //
        // AFTER the merge: the import changes `entry_state`, which is what
        // compaction reads, and an entry read elsewhere can be what lets the
        // water-mark advance.
        let cursor = compact_if_large(state, did, cursor).await;
        let record = match read_state_record(
            state,
            &cursor,
            theirs.and_then(|t| t.read_through.as_deref()),
            &carry,
        )
        .await
        {
            Ok(record) => record,
            Err(err) => {
                // Without the GUIDs there is nothing correct to write; the
                // cursor stays dirty and goes again next round.
                warn!(%did, feed = %cursor.feed_url, %err, "read-state flusher: could not map entry ids to GUIDs; skipping this feed this round");
                continue;
            }
        };
        batch.insert(rkey, (record, cursor));
    }
    if batch.is_empty() {
        return Ok(());
    }

    // ONE applyWrites batch for all of this DID's dirty feeds — sent as several
    // calls past the PDS's per-call limits (#240), in rkey order.
    let ops = batch_ops(&batch);
    if let Err(err) = state.repo().flush_read_states(did, &ops).await {
        // **What landed is settled first, whatever went wrong after it.** A
        // split batch commits call by call, so a failure in call 2 can follow a
        // call 1 that created its records. Left dirty with `pds_created` false,
        // those cursors went out again next round as `#create` on keys that now
        // exist, the PDS refused, the run stopped at that call — and because the
        // order is fixed, every cursor sorted after them starved, every round.
        settle_landed(state, did, &mut batch, &err).await;

        // **A flag that disagrees with the PDS wedged this DID forever (#241).**
        //
        // `pds_created` picks create-vs-update. Since #246 it is set from the
        // listing at the top of every flush, but that listing can fail (then
        // only cursors stored as not created are sent, as `#create`, and one
        // may collide), and a record can be created or deleted by another
        // client between the listing and the write. Either
        // way one op fails, applyWrites is atomic, the whole call fails.
        //
        // So on a failure that COULD be that, ask the PDS once what exists, and
        // retry what did not land, once, if the answer changes anything. Never
        // in a loop: a retry that fails again is returned like any other
        // failure, and the corrected flags it leaves behind make the next round
        // an ordinary flush.
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
        if let Err(retry_err) = state.repo().flush_read_states(did, &ops).await {
            // The retry can split and part-land too.
            settle_landed(state, did, &mut batch, &retry_err).await;
            // **The reason goes IN the message, not only under it.** Both
            // callers log `%err`, which prints an anyhow context's outermost
            // message alone, so a bare "failed again" dropped the PDS's status
            // and error name from the log. Switching the callers to `{:#}`
            // instead would print the reason twice on every flush failure:
            // the Rust client's rejection, and `ApplyWritesIncomplete`, both
            // already repeat their cause in their own message. The chain is
            // kept, so `ApplyWritesIncomplete::of` still reads the progress.
            let context =
                format!("read-state flush failed again after reconciling pds_created: {retry_err}");
            return Err(retry_err.context(context));
        }
    }

    let flushed = batch.len();
    for (_rkey, (_record, cursor)) in batch {
        settle(state, did, &cursor).await;
    }

    info!(%did, feeds = flushed, "read-state flusher: flushed dirty cursors");
    Ok(())
}

/// One listing of a DID's `readState` collection, as the merge needs it.
struct Remote {
    /// Every rkey that exists — including records that did not parse, so a
    /// record this instance cannot read is still never sent a `#create`.
    rkeys: HashSet<String>,
    /// The records that parsed, by rkey.
    records: HashMap<String, ReadState>,
}

impl Remote {
    fn from_listing(records: &[crate::atproto::RecordEntry]) -> Self {
        let mut rkeys = HashSet::new();
        let mut parsed = HashMap::new();
        for record in records {
            let Some(rkey) = record.rkey() else { continue };
            rkeys.insert(rkey.to_string());
            match record.parse::<ReadState>() {
                Ok(rs) => {
                    parsed.insert(rkey.to_string(), rs);
                }
                Err(err) => {
                    warn!(uri = %record.uri, %err, "read-state flusher: unparseable readState record; not merged");
                }
            }
        }
        Self {
            rkeys,
            records: parsed,
        }
    }

    /// The record at `rkey`, if it is about `feed_url` — a hash collision
    /// between two feeds' rkeys must not merge one feed's reads into another.
    fn record_for(&self, rkey: &str, feed_url: &str) -> Option<&ReadState> {
        self.records.get(rkey).filter(|r| r.feed_url == feed_url)
    }
}

/// Set `cursor.pds_created` to what the listing says, persisting a change.
///
/// A failure to persist is logged: the in-memory flag still drives this
/// flush, and the next flush lists again.
async fn learn_pds_created(state: &AppState, did: &str, cursor: &mut ReadCursor, exists: bool) {
    if cursor.pds_created == exists {
        return;
    }
    cursor.pds_created = exists;
    if let Err(err) = store::set_cursor_pds_created(&state.db, did, &cursor.feed_url, exists).await
    {
        warn!(%did, feed = %cursor.feed_url, %err, "failed to record pds_created from the listing");
    }
}

/// Remote GUIDs carried into the written record so they are not erased: every
/// one the remote record lists, except those that lost a conflict to this
/// instance's newer state.
///
/// Not only the ones with no local entry. A GUID whose entry is read here can
/// still be missing from the cursor's `read_ids` — compaction folds it into
/// `readThrough`, which no other instance applies to its entries — and one in
/// a feed the reader has left is refused by the import. Either way the local
/// sets alone would drop it.
///
/// Each set is split by how far this instance can vouch for a GUID, which is
/// the order the caps drop them in ([`cap_merged`], [`fit_record_bytes`]):
/// GUIDs with no local entry first, then GUIDs this instance has, each in the
/// remote record's order — oldest first.
///
/// `updated_at` is the merged record's `updatedAt`, set whenever a GUID record
/// was merged: the written record carries its state, so it must not claim to
/// be older than it ([`build_record`]).
#[derive(Default, Debug)]
struct Carry {
    read: Carried,
    unread: Carried,
    updated_at: Option<String>,
}

/// One id set's carried remote GUIDs, by tier (see [`Carry`]).
#[derive(Default, Debug, Clone)]
struct Carried {
    /// No local entry: this instance cannot vouch for them, and a GUID it once
    /// wrote and has since swept looks exactly like one. Dropped first.
    unresolved: Vec<String>,
    /// A local entry, but no id in the local set (folded into `readThrough`,
    /// or in a feed the reader has left). Dropped second.
    resolved: Vec<String>,
}

impl Carried {
    fn len(&self) -> usize {
        self.unresolved.len() + self.resolved.len()
    }
}

/// Whether timestamp `a` is strictly later than `b`, compared as instants.
///
/// Parsed, not string-compared: this instance writes UTC seconds `...Z`, but
/// `updatedAt` / `readThrough` come from any client, with any offset or
/// precision. An unparseable side is never the later one.
fn later(a: &str, b: &str) -> bool {
    match (
        chrono::DateTime::parse_from_rfc3339(a),
        chrono::DateTime::parse_from_rfc3339(b),
    ) {
        (Ok(a), Ok(b)) => a > b,
        (Ok(_), Err(_)) => true,
        _ => false,
    }
}

/// Merge `theirs` — the PDS record at this cursor's rkey — into the local
/// state, and return the (re-read) cursor and the remote GUIDs to carry.
///
/// The rules:
/// - **A legacy record** (no `idType`) holds another database's row ids: its
///   id arrays are ignored entirely. Its `readThrough` still merges, in
///   [`read_state_record`].
/// - **A remote item id with a local entry** (matched by guid, or by link for
///   a row whose guid FeatherReader synthesized — `store::entries_for_guids`)
///   is imported into `entry_state`
///   unless it conflicts: read there and explicitly unread here (in the
///   cursor's `unread_ids`), or unread there and read here. Then the side with
///   the newer `updatedAt` wins, and a tie goes to local.
/// - **Every remote GUID that did not lose that conflict** is carried into the
///   record (see [`Carry`]), whether or not it has a local entry.
///
/// Remote `readThrough` is NOT applied to local entries: undated entries
/// compare by `fetched_at`, which is instance-local, so the same water-mark
/// would mark different entries read on different instances.
///
/// Any failure is logged and leaves the cursor as given with nothing carried
/// — the pre-#246 behaviour for that one feed, not a failed flush.
async fn merge_remote(
    state: &AppState,
    did: &str,
    cursor: ReadCursor,
    theirs: &ReadState,
) -> (ReadCursor, Carry) {
    if theirs.id_type.as_deref() != Some(ReadState::ID_TYPE_GUID) {
        return (cursor, Carry::default());
    }
    match merge_guid_record(state, did, &cursor, theirs).await {
        Ok((Some(fresh), carry)) => (fresh, carry),
        Ok((None, carry)) => (cursor, carry),
        Err(err) => {
            warn!(%did, feed = %cursor.feed_url, %err, "read-state flusher: could not merge the PDS record; writing local state");
            (cursor, Carry::default())
        }
    }
}

/// [`merge_remote`] for a GUID record. Returns the re-read cursor when the
/// import changed it.
async fn merge_guid_record(
    state: &AppState,
    did: &str,
    cursor: &ReadCursor,
    theirs: &ReadState,
) -> anyhow::Result<(Option<ReadCursor>, Carry)> {
    let plan = plan_guid_merge(state, did, cursor, theirs).await?;
    let imported = apply_guid_merge(state, did, &cursor.feed_url, &plan).await?;
    if imported == 0 {
        return Ok((None, plan.carry));
    }
    info!(%did, feed = %cursor.feed_url, imported, "read-state flusher: imported read state from the PDS");
    // Re-read: the import rewrote the row — and may have moved `updated_at`,
    // which the conditional dirty-clear compares against.
    Ok((
        store::get_cursor(&state.db, did, &cursor.feed_url).await?,
        plan.carry,
    ))
}

/// What [`merge_guid_record`] decided, before any of it is applied.
#[derive(Debug)]
struct MergePlan {
    /// Remote GUIDs to carry into the written record.
    carry: Carry,
    /// Local entries to mark read, as they were when the decision was made.
    to_read: Vec<store::GuidEntry>,
    /// Local entries to mark unread, likewise.
    to_unread: Vec<store::GuidEntry>,
    /// The remote record's `updatedAt`.
    remote_updated_at: String,
}

/// Decide, from the local state as it is now, what of `theirs` to import and
/// what to carry. Writes nothing.
async fn plan_guid_merge(
    state: &AppState,
    did: &str,
    cursor: &ReadCursor,
    theirs: &ReadState,
) -> anyhow::Result<MergePlan> {
    // A GUID in both of the remote's own sets is unread: a writer must not
    // list one in both (docs/lexicon.md), and when an older one did, the
    // unread is the reader keeping something, so it is the safer reading.
    let unread_set: HashSet<&String> = theirs.unread_ids.iter().collect();
    let remote_read: Vec<String> = dedup(
        theirs
            .read_ids
            .iter()
            .filter(|g| !unread_set.contains(g))
            .cloned(),
    );
    let remote_unread: Vec<String> = dedup(theirs.unread_ids.iter().cloned());

    let all: Vec<String> = remote_read.iter().chain(&remote_unread).cloned().collect();
    let local = store::entries_for_guids(&state.db, did, &cursor.feed_url, &all).await?;
    // **The cursor is re-read AFTER `entry_state`**, so the two are one
    // snapshot as far as the import's re-check can tell. The flush's cursor
    // was read before its listing — a PDS round trip earlier — and a mark in
    // that window is in `entry_state` but not in it: the entry looked plainly
    // unread rather than explicitly unread, and the older remote read was
    // imported over it. Read in this order, a mark before the entries read is
    // in both, and one after it fails the import's re-check.
    let fresh = store::get_cursor(&state.db, did, &cursor.feed_url).await?;
    let cursor = fresh.as_ref().unwrap_or(cursor);
    let local_unread: HashSet<i64> = parse_id_array(&cursor.unread_ids)
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let remote_wins = later(&theirs.updated_at, &cursor.updated_at);

    let mut carry = Carry {
        updated_at: Some(theirs.updated_at.clone()),
        ..Carry::default()
    };
    let (mut to_read, mut to_unread) = (Vec::new(), Vec::new());
    for guid in remote_read {
        match local.get(&guid) {
            None => carry.read.unresolved.push(guid),
            Some(rows) => {
                // Several rows can share a link (a title edit on an id-less
                // item); the id is explicitly unread here if any of them is.
                let explicitly_unread = rows.iter().any(|e| local_unread.contains(&e.id));
                if explicitly_unread && !remote_wins {
                    // Lost to the newer local unread: neither imported nor
                    // carried.
                    continue;
                }
                for e in rows {
                    if !e.read || local_unread.contains(&e.id) {
                        to_read.push(e.clone());
                    }
                }
                carry.read.resolved.push(guid);
            }
        }
    }
    for guid in remote_unread {
        match local.get(&guid) {
            None => carry.unread.unresolved.push(guid),
            Some(rows) => {
                if rows.iter().any(|e| e.read) && !remote_wins {
                    continue;
                }
                for e in rows {
                    // Into `unread_ids` even when it is already unread here, or
                    // the record would drop it — and below a `readThrough`, a
                    // missing unread id reads as read.
                    if e.read || !local_unread.contains(&e.id) {
                        to_unread.push(e.clone());
                    }
                }
                carry.unread.resolved.push(guid);
            }
        }
    }
    Ok(MergePlan {
        carry,
        to_read,
        to_unread,
        remote_updated_at: theirs.updated_at.clone(),
    })
}

/// Apply a [`MergePlan`]'s imports. Returns how many entries were written.
///
/// An entry whose `entry_state` changed since the plan was made is skipped
/// ([`store::import_remote_read_state`]): the change is the reader's, and
/// newer than the remote record.
async fn apply_guid_merge(
    state: &AppState,
    did: &str,
    feed_url: &str,
    plan: &MergePlan,
) -> anyhow::Result<usize> {
    store::import_remote_read_state(
        &state.db,
        did,
        feed_url,
        &plan.to_read,
        &plan.to_unread,
        &plan.remote_updated_at,
    )
    .await
}

/// Import remote reads into the DID's CLEAN cursors, from the listing this
/// flush already made.
///
/// Only when the remote record is newer than the cursor: that is the record
/// another client changed since this instance last wrote or imported it. The
/// import never dirties the cursor ([`store::import_remote_read_state`]), so it
/// costs no write; the carried GUIDs are irrelevant here — nothing is written.
///
/// **A subscribed feed with a record and no cursor gets one** — clean,
/// `pds_created`, stamped with the record's `updatedAt` — and imports into it.
/// On a fresh database only the feeds read here have cursors; without this
/// every other feed's PDS reads stayed invisible until the reader marked
/// something in that feed. Only GUID records, and only feeds the DID
/// subscribes to ([`store::create_clean_cursor`]).
///
/// It runs only on rounds that list anyway, i.e. when the DID has some dirty
/// cursor: a reader who reads only elsewhere sees those reads arrive here the
/// next time they read anything here.
async fn import_into_clean_cursors(state: &AppState, did: &str, remote: &Remote) {
    let clean = match store::clean_cursors(&state.db, did).await {
        Ok(clean) => clean,
        Err(err) => {
            warn!(%did, %err, "read-state flusher: could not load clean cursors to import into");
            return;
        }
    };
    for cursor in clean {
        let rkey = read_state_rkey(&cursor.feed_url);
        let Some(theirs) = remote.record_for(&rkey, &cursor.feed_url) else {
            continue;
        };
        if !later(&theirs.updated_at, &cursor.updated_at) {
            continue;
        }
        let _ = merge_remote(state, did, cursor, theirs).await;
    }

    for (rkey, theirs) in &remote.records {
        if theirs.id_type.as_deref() != Some(ReadState::ID_TYPE_GUID)
            || read_state_rkey(&theirs.feed_url) != *rkey
        {
            continue;
        }
        let feed = &theirs.feed_url;
        match store::create_clean_cursor(&state.db, did, feed, &theirs.updated_at).await {
            Ok(true) => {}
            // Already has a cursor (handled above, or dirty and merged by the
            // flush), not subscribed, or no usable `updatedAt`.
            Ok(false) => continue,
            Err(err) => {
                warn!(%did, %feed, %err, "read-state flusher: could not create a cursor to import into");
                continue;
            }
        }
        match store::get_cursor(&state.db, did, feed).await {
            Ok(Some(cursor)) => {
                let _ = merge_remote(state, did, cursor, theirs).await;
            }
            Ok(None) => {}
            Err(err) => {
                warn!(%did, %feed, %err, "read-state flusher: could not read a new cursor back");
            }
        }
    }
}

/// `ids` in first-seen order, without repeats.
fn dedup(ids: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    ids.filter(|id| seen.insert(id.clone())).collect()
}

/// Record that `cursor`'s write landed: mark its PDS record as created (so
/// future flushes emit an update), then clear `dirty` but ONLY if its
/// `updated_at` still matches the snapshot that was flushed. A mark-read that
/// landed DURING the in-flight PDS write bumped `updated_at` and re-dirtied the
/// row; the conditional clear leaves that row dirty so its new reads re-flush
/// next round instead of being silently dropped.
async fn settle(state: &AppState, did: &str, cursor: &ReadCursor) {
    // Flip the created flag first: the record now exists in the PDS regardless
    // of whether the dirty-clear below is a no-op due to a concurrent bump.
    if !cursor.pds_created {
        if let Err(err) = store::mark_cursor_pds_created(&state.db, did, &cursor.feed_url).await {
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

/// Settle, and take out of `batch`, the cursors a failed flush DID write.
///
/// A chunked `applyWrites` stops at the first failing call, so what landed is
/// a prefix of the ops — and the ops are `batch` in its own (rkey) order, so
/// it is a prefix of `batch` too. [`crate::atproto::ApplyWritesIncomplete`]
/// says how long. The failed call's own writes are in doubt and stay in the
/// batch, dirty: a later round, or the reconcile, finds out which landed.
async fn settle_landed(state: &AppState, did: &str, batch: &mut Batch, err: &anyhow::Error) {
    let landed = crate::atproto::ApplyWritesIncomplete::of(err).map_or(0, |p| p.landed);
    let keys: Vec<String> = batch.keys().take(landed).cloned().collect();
    for key in keys {
        if let Some((_record, cursor)) = batch.remove(&key) {
            settle(state, did, &cursor).await;
        }
    }
    if landed > 0 {
        info!(%did, landed, "read-state flusher: a split flush failed part-way; settled what landed");
    }
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
    // **The chunked write's own cause is walked too, explicitly.** Every flush
    // error now arrives wrapped in `ApplyWritesIncomplete`, whose `source()`
    // continues from its cause's SOURCE (so `{:#}` does not print the PDS's
    // message twice). On the sidecar client the cause IS the `AtProtoError`,
    // so `err.chain()` skips it — measured: every sidecar reconcile test went
    // red on the merge with #240 until this was added.
    let wrapped = crate::atproto::ApplyWritesIncomplete::of(err).map(|p| p.cause().chain());
    err.chain()
        .chain(wrapped.into_iter().flatten())
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

/// Turn a local [`ReadCursor`] row into the PDS [`ReadState`] lexicon record,
/// with its row ids translated to entry GUIDs (see [`build_record`]).
async fn read_state_record(
    state: &AppState,
    cursor: &ReadCursor,
    remote_read_through: Option<&str>,
    carry: &Carry,
) -> anyhow::Result<ReadState> {
    let ids: Vec<i64> = parse_id_array(&cursor.read_ids)
        .iter()
        .chain(&parse_id_array(&cursor.unread_ids))
        .filter_map(|s| s.parse().ok())
        .collect();
    let guids = store::guids_for_entry_ids(&state.db, &cursor.did, &cursor.feed_url, &ids).await?;
    Ok(build_record(cursor, &guids, remote_read_through, carry))
}

/// Build the record from a cursor, the GUIDs of its ids, the remote
/// `readThrough` and the remote GUIDs to carry.
///
/// **Ids are item ids (`docs/lexicon.md`), and the record says so**
/// (`idType: "guid"`, the lexicon's historical name for them): the stored
/// guid, or the link for a row whose guid FeatherReader synthesized
/// (`store::guids_for_entry_ids`). A row id with no item id — its entry was
/// swept, or it is an item with neither an id nor a link — drops out.
///
/// `read_through` is optional both locally AND in the record: when neither
/// side has a high-water-mark the record OMITS `readThrough` entirely. This is
/// the conservative behaviour — `readThrough` is a "everything seen/published
/// `<=` this is read" water-mark, so synthesizing a flush-time (`≈ now`) value
/// for a cursor that has none would assert the whole unread backlog is read.
/// When both sides have one, the later wins: neither side's water-mark is
/// ever moved backwards by the other.
///
/// Both id-sets are capped at [`ReadState::MAX_IDS`] to respect the lexicon
/// bound, dropping carried remote GUIDs first (see [`cap_merged`]), and the
/// record at [`READ_STATE_RECORD_MAX_BYTES`] in the same order
/// ([`fit_record_bytes`]).
///
/// `updatedAt` is the cursor's `updated_at`, or the merged record's when that
/// is later (see [`Carry`]).
fn build_record(
    cursor: &ReadCursor,
    guids: &HashMap<i64, store::ItemRef>,
    remote_read_through: Option<&str>,
    carry: &Carry,
) -> ReadState {
    // Each side's item ids, deduplicated, with the latest time the reader
    // marked any row that maps to it. Rows can share an item id (a title edit
    // on an id-less item makes a second row with the same link).
    let to_items = |raw: &str| -> Vec<(String, Option<String>)> {
        let mut out: Vec<(String, Option<String>)> = Vec::new();
        for r in parse_id_array(raw)
            .iter()
            .filter_map(|s| s.parse::<i64>().ok())
            .filter_map(|id| guids.get(&id))
        {
            match out.iter_mut().find(|(g, _)| *g == r.id) {
                None => out.push((r.id.clone(), r.marked_at.clone())),
                Some((_, at)) => {
                    let newer = match (at.as_deref(), r.marked_at.as_deref()) {
                        (None, Some(_)) => true,
                        (Some(a), Some(b)) => later(b, a),
                        _ => false,
                    };
                    if newer {
                        *at = r.marked_at.clone();
                    }
                }
            }
        }
        out
    };
    let (read_items, unread_items) = (to_items(&cursor.read_ids), to_items(&cursor.unread_ids));
    // **An item id is on one side.** Several rows can share an item id, and
    // the reader can have marked one read and another unread; the id stays on
    // the side marked most recently. A tie, or a row with no mark time, goes
    // to unread: an unread is the reader keeping something, and the wrong
    // answer there is a lost item rather than a redundant one.
    let read_wins = |g: &str, read_at: &Option<String>| -> bool {
        match (
            read_at.as_deref(),
            unread_items.iter().find(|(u, _)| u == g),
        ) {
            (_, None) => true,
            (Some(r), Some((_, Some(u)))) => later(r, u),
            _ => false,
        }
    };
    let read_ids: Vec<String> = read_items
        .iter()
        .filter(|(g, at)| read_wins(g, at))
        .map(|(g, _)| g.clone())
        .collect();
    let unread_ids: Vec<String> = unread_items
        .iter()
        .filter(|(g, _)| !read_ids.contains(g))
        .map(|(g, _)| g.clone())
        .collect();

    let read_through = match (cursor.read_through.as_deref(), remote_read_through) {
        (Some(local), Some(remote)) if later(remote, local) => Some(remote.to_string()),
        (Some(local), _) => Some(local.to_string()),
        (None, remote) => remote
            .filter(|r| chrono::DateTime::parse_from_rfc3339(r).is_ok())
            .map(str::to_string),
    };

    // Do NOT synthesize a water-mark from `updated_at`: an unset
    // `read_through` means "no high-water-mark", which the record represents
    // by omitting `readThrough` (None), not by back-dating it to flush time.
    // **`updatedAt` never goes backwards.** A merged record's state is in this
    // one, so it is stamped no earlier than the record it merged: B's read at
    // 05:00, carried by an instance whose cursor last changed at 03:00 and
    // stamped 03:00, would lose to a third instance's 04:00 unread. Only the
    // record is stamped; the cursor's own `updated_at` moves only when its
    // content does (an import), since carrying changes nothing local.
    let updated_at = match carry.updated_at.as_deref() {
        Some(remote) => store::later_timestamp(&cursor.updated_at, remote),
        None => cursor.updated_at.clone(),
    };
    let mut record = ReadState::new(&cursor.feed_url, read_through, &updated_at);
    record.id_type = Some(ReadState::ID_TYPE_GUID.to_string());
    // A carried GUID already in a local set is local: written once, and on the
    // side the local state says. With the rule above (an item id on one side,
    // the most recently marked, a tie to unread) the two sets never overlap.
    let local: HashSet<&String> = read_ids.iter().chain(&unread_ids).collect();
    let carried = |c: &Carried| -> Carried {
        let keep = |ids: &[String]| -> Vec<String> {
            ids.iter().filter(|g| !local.contains(g)).cloned().collect()
        };
        Carried {
            unresolved: keep(&c.unresolved),
            resolved: keep(&c.resolved),
        }
    };
    let (carry_read, carry_unread) = (carried(&carry.read), carried(&carry.unread));
    let mut read = cap_merged(carry_read, read_ids, ReadState::MAX_IDS);
    let mut unread = cap_merged(carry_unread, unread_ids, ReadState::MAX_IDS);
    fit_record_bytes(&record, &mut read, &mut unread, READ_STATE_RECORD_MAX_BYTES);
    record.read_ids = read.into_ids();
    record.unread_ids = unread.into_ids();
    record
}

/// One id set as the caps see it: carried remote GUIDs by tier, then local.
struct Merged {
    carried: Carried,
    local: Vec<String>,
}

impl Merged {
    /// The set as written: carried, then local.
    fn into_ids(self) -> Vec<String> {
        let mut ids = self.carried.unresolved;
        ids.extend(self.carried.resolved);
        ids.extend(self.local);
        ids
    }
}

/// Most bytes one `readState` record may serialize to.
///
/// **The id cap alone does not bound a record's size.** GUIDs run up to
/// `MAX_GUID_BYTES` (2048) and are often 80–200 bytes, so 1,000 carried ids
/// can make one record 150 KiB or more. [`crate::atproto::chunk_writes`] sends
/// an op larger than [`crate::atproto::APPLY_WRITES_MAX_BYTES`] alone, a PDS
/// still on the 150 KiB `jsonLimit` refuses it, the chunked write stops there
/// — and the cursor fails every round while every feed sorted after it
/// starves.
///
/// 64 KiB is half the per-call budget: with the op's own wrapper (collection,
/// rkey, action — around 150 bytes) it always fits one call with room for
/// another such op, and it is under the 150 KiB `jsonLimit` with more than
/// 80 KiB to spare for the request envelope. It still holds the full 1,000-id
/// cap of GUIDs averaging ~60 bytes, so it binds only on long GUIDs.
const READ_STATE_RECORD_MAX_BYTES: usize = 64 * 1024;

/// Trim `read` and `unread` until the record serializes to at most `max`
/// bytes, in the count cap's order across both sets: carried GUIDs with no
/// local entry, then carried GUIDs this instance has, then local GUIDs —
/// oldest first within each, read before unread. `record` is the record with
/// its id sets still empty.
///
/// The size is the serialized JSON's: each id costs its JSON string plus a
/// comma, on top of the empty record and both arrays' keys — an over-estimate
/// by at most a comma per set.
fn fit_record_bytes(record: &ReadState, read: &mut Merged, unread: &mut Merged, max: usize) {
    let cost = |id: &String| serde_json::to_string(id).map_or(id.len() * 6 + 2, |j| j.len()) + 1;
    let base = serde_json::to_vec(record).map_or(0, |v| v.len())
        + r#","readIds":[]"#.len()
        + r#","unreadIds":[]"#.len();
    let ids = |m: &Merged| {
        m.carried
            .unresolved
            .iter()
            .chain(&m.carried.resolved)
            .chain(&m.local)
            .map(cost)
            .sum::<usize>()
    };
    let mut size = base + ids(read) + ids(unread);
    if size <= max {
        return;
    }
    let before = size;
    let mut dropped = 0;
    for tier in [
        &mut read.carried.unresolved,
        &mut unread.carried.unresolved,
        &mut read.carried.resolved,
        &mut unread.carried.resolved,
        &mut read.local,
        &mut unread.local,
    ] {
        let mut n = 0;
        while size > max && n < tier.len() {
            size -= cost(&tier[n]);
            n += 1;
        }
        tier.drain(0..n);
        dropped += n;
        if size <= max {
            break;
        }
    }
    warn!(
        feed = %record.feed_url,
        dropped,
        before,
        after = size,
        max,
        "read-state record over the byte budget; dropped the oldest ids, remote GUIDs with no local entry first"
    );
}

/// Fit carried remote GUIDs plus local GUIDs into `max`, dropping carried ones
/// first: the unresolved tier, then the resolved one, each from the front
/// (see [`Carry`] for the order).
///
/// GUIDs with no local entry go first: this instance cannot vouch for them,
/// and a GUID it once wrote and has since swept looks exactly like one. Then
/// remote GUIDs it has an entry for but no id in its sets for (folded into its
/// `readThrough`, or in a feed it has left) — entries it still holds, so
/// closer to what it knows. Within each, the remote record's oldest first.
/// Local GUIDs go last, and only through the ordinary tail-keeping [`cap`].
fn cap_merged(mut carried: Carried, local: Vec<String>, max: usize) -> Merged {
    let total = carried.len();
    let over = (total + local.len()).saturating_sub(max);
    if over > 0 && total > 0 {
        let drop = over.min(total);
        warn!(
            dropped = drop,
            kept = total - drop,
            "read-state record over the lexicon cap; dropping the oldest remote GUIDs with no local entry"
        );
        let first = drop.min(carried.unresolved.len());
        carried.unresolved.drain(0..first);
        carried.resolved.drain(0..drop - first);
    }
    Merged {
        carried,
        local: cap(local, max),
    }
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
pub(crate) mod tests {
    use super::*;

    /// [`build_record`] for a cursor whose ids are their own GUIDs, with no
    /// remote record — the shape the pre-#246 unit tests assert on.
    fn record_of(cursor: &ReadCursor) -> ReadState {
        let guids = parse_id_array(&cursor.read_ids)
            .into_iter()
            .chain(parse_id_array(&cursor.unread_ids))
            .filter_map(|s| {
                Some((
                    s.parse().ok()?,
                    store::ItemRef {
                        id: s,
                        marked_at: None,
                    },
                ))
            })
            .collect();
        build_record(cursor, &guids, None, &Carry::default())
    }

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
        let rec = record_of(&cursor);
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
        let rec = record_of(&cursor);
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
        let rec = record_of(&cursor);
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
        let rec = record_of(&cursor);
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
        let rec = record_of(&cursor);
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

    pub(crate) const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

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
    pub(crate) struct FakeRepo {
        pub(crate) records: BTreeMap<String, serde_json::Value>,
        pub(crate) apply_calls: usize,
        /// listRecords requests with no cursor — one per walk, however many
        /// pages that walk turns out to need.
        pub(crate) list_walks: usize,
        /// Fail every applyWrites with this, whatever its ops.
        always_fail: Option<Fail>,
        /// Land the first N ops of the next applyWrites, then answer 503 — a
        /// later chunk failing after an earlier one committed (#240).
        partial_then_503: Option<usize>,
        /// Answer every listRecords with a 503.
        list_fails: bool,
        /// Answer the next N listing WALKS with a 503 — the pre-write listing
        /// failing, so the flush falls back to its stored `pds_created` flags
        /// and the #241 reconcile is what corrects them.
        pub(crate) fail_lists: usize,
        /// Drop the connection, unanswered, on this applyWrites call (1-based)
        /// — a transport failure after the earlier calls committed.
        pub(crate) drop_call: Option<usize>,
        /// Refuse an applyWrites whose serialized `writes` exceed this many
        /// bytes, as a PDS with a `jsonLimit` does (413).
        json_limit: Option<usize>,
        /// Delete this rkey right after the next listing walk has seen it —
        /// another client deleting the record between the listing and the
        /// write.
        delete_after_list: Option<String>,
    }

    /// Not an answer: the fake hangs up instead of replying.
    const HANG_UP: Fail = Fail {
        status: 0,
        error: "connection dropped",
    };

    impl FakeRepo {
        /// Whether this listRecords request is answered with a 503.
        fn list_refused(&mut self, cursor: Option<&str>) -> bool {
            if self.list_fails {
                return true;
            }
            if cursor.is_none() && self.fail_lists > 0 {
                self.fail_lists -= 1;
                return true;
            }
            false
        }

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
            if self.drop_call == Some(self.apply_calls) {
                return Err(HANG_UP);
            }
            // The reference PDS's per-call cap, which #240 chunks under.
            if writes.len() > crate::atproto::APPLY_WRITES_MAX_OPS {
                return Err(Fail {
                    status: 400,
                    error: "InvalidRequest",
                });
            }
            if let Some(limit) = self.json_limit {
                if serde_json::to_string(writes).unwrap().len() > limit {
                    return Err(Fail {
                        status: 413,
                        error: "PayloadTooLarge",
                    });
                }
            }
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
            if let Some(rkey) = self.delete_after_list.take() {
                self.records.remove(&rkey);
            }
            body
        }
    }

    /// Abandon the request mid-flight, so the client sees the connection close
    /// with no response — a transport failure, not an answer. Unwinding the
    /// handler drops hyper's connection task; `resume_unwind` skips the panic
    /// hook, so it does not read as a test failure in the output. The caller
    /// releases the fake's lock first, or the unwind would poison it.
    fn hang_up() -> axum::response::Response {
        std::panic::resume_unwind(Box::new("fake PDS hung up"))
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
                                if fake.list_refused(req["cursor"].as_str()) {
                                    return reply(
                                        503,
                                        serde_json::json!({ "ok": false, "error": "PartitionUnavailable", "status": 503 }),
                                    );
                                }
                                reply(200, serde_json::json!({ "ok": true, "data": page }))
                            }
                            Some("applyWrites") => {
                                match fake.apply(req["writes"].as_array().unwrap()) {
                                    Err(f) if f.status == HANG_UP.status => {
                                        drop(fake);
                                        hang_up()
                                    }
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
                        if fake.list_refused(query.get("cursor").map(String::as_str)) {
                            return reply(503, serde_json::json!({ "error": "PartitionUnavailable" }));
                        }
                        reply(200, page)
                    }
                    "/xrpc/com.atproto.repo.applyWrites" => {
                        let req: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                        match fake.apply(req["writes"].as_array().unwrap()) {
                            Err(f) if f.status == HANG_UP.status => {
                                drop(fake);
                                hang_up()
                            }
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
    pub(crate) async fn state_on(backend: Backend, fake: &Arc<Mutex<FakeRepo>>) -> AppState {
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

    pub(crate) fn feed(i: usize) -> String {
        format!("https://f{i}.example/feed.xml")
    }

    /// Feed `i` holds an entry with `guid`, published at `published`, and
    /// [`DID`] subscribes to the feed. Returns the entry's LOCAL row id.
    pub(crate) async fn entry_at(state: &AppState, i: usize, guid: &str, published: &str) -> i64 {
        let feed_id = store::upsert_feed(
            &state.db,
            &store::NewFeed {
                url: feed(i),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        store::insert_entries(
            &state.db,
            feed_id,
            &[store::NewEntry {
                guid: guid.into(),
                published: Some(published.into()),
                ..Default::default()
            }],
            0,
        )
        .await
        .unwrap();
        sqlx::query("INSERT OR IGNORE INTO sub_ref (did, feed_id) VALUES (?1, ?2)")
            .bind(DID)
            .bind(feed_id)
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query_scalar("SELECT id FROM entries WHERE feed_id = ?1 AND guid = ?2")
            .bind(feed_id)
            .bind(guid)
            .fetch_one(&state.db)
            .await
            .unwrap()
    }

    /// Like [`entry_at`], but the row's guid is a FeatherReader stand-in and
    /// the item is named by `url` (which may be absent) in a record.
    pub(crate) async fn synthesized_entry(
        state: &AppState,
        i: usize,
        guid: &str,
        url: Option<&str>,
    ) -> i64 {
        let feed_id = store::upsert_feed(
            &state.db,
            &store::NewFeed {
                url: feed(i),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        store::insert_entries(
            &state.db,
            feed_id,
            &[store::NewEntry {
                guid: guid.into(),
                url: url.map(str::to_string),
                published: Some("2026-01-01T00:00:00Z".into()),
                guid_synthesized: true,
                ..Default::default()
            }],
            0,
        )
        .await
        .unwrap();
        sqlx::query("INSERT OR IGNORE INTO sub_ref (did, feed_id) VALUES (?1, ?2)")
            .bind(DID)
            .bind(feed_id)
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query_scalar("SELECT id FROM entries WHERE feed_id = ?1 AND guid = ?2")
            .bind(feed_id)
            .bind(guid)
            .fetch_one(&state.db)
            .await
            .unwrap()
    }

    pub(crate) async fn entry(state: &AppState, i: usize, guid: &str) -> i64 {
        entry_at(state, i, guid, "2026-01-01T00:00:00Z").await
    }

    /// The reader marks the entry `guid` of feed `i` read here, through the
    /// real mark-read path: `entry_state`, projected into a dirty cursor.
    pub(crate) async fn mark_read(state: &AppState, i: usize, guid: &str) -> i64 {
        let id = entry(state, i, guid).await;
        assert!(store::mark_read(&state.db, DID, id, true).await.unwrap());
        id
    }

    /// Whether [`DID`] has entry `id` read locally — `entry_state`, which is
    /// what every local view reads.
    async fn is_read(state: &AppState, id: i64) -> bool {
        sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE((SELECT read FROM entry_state WHERE did = ?1 AND entry_id = ?2), 0)",
        )
        .bind(DID)
        .bind(id)
        .fetch_one(&state.db)
        .await
        .unwrap()
            == 1
    }

    /// Put `record` (raw JSON, as any client could have written it) in the
    /// fake repo at feed `i`'s rkey.
    fn put_remote(fake: &Arc<Mutex<FakeRepo>>, i: usize, record: serde_json::Value) {
        fake.lock()
            .unwrap()
            .records
            .insert(read_state_rkey(&feed(i)), record);
    }

    /// A `readState` record another client wrote, in the GUID format.
    fn remote_guid_record(
        i: usize,
        read: &[&str],
        unread: &[&str],
        updated_at: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "$type": crate::lexicon::nsid::READ_STATE,
            "feedUrl": feed(i),
            "idType": "guid",
            "readIds": read,
            "unreadIds": unread,
            "updatedAt": updated_at,
        })
    }

    fn pds_record(fake: &Arc<Mutex<FakeRepo>>, i: usize) -> serde_json::Value {
        fake.lock().unwrap().records[&read_state_rkey(&feed(i))].clone()
    }

    fn id_set(record: &serde_json::Value, field: &str) -> std::collections::BTreeSet<String> {
        record[field]
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
            .unwrap_or_default()
    }

    fn set_of(ids: &[&str]) -> std::collections::BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    /// A record already in the fake repo for feed `i`, from some earlier flush.
    fn existing(fake: &Arc<Mutex<FakeRepo>>, i: usize) {
        let record = ReadState::new(feed(i), None, "2026-01-01T00:00:00Z");
        fake.lock().unwrap().records.insert(
            read_state_rkey(&feed(i)),
            serde_json::to_value(record).unwrap(),
        );
    }

    pub(crate) async fn cursor(state: &AppState, i: usize) -> ReadCursor {
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
    ///
    /// Since #246 the pre-write listing corrects the flag before the write, so
    /// this drives the case where that listing failed: the stored flag is
    /// used, the write is refused, and the reconcile converges it.
    #[tokio::test]
    async fn a_lost_create_response_converges_on_the_next_flush() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            existing(&fake, 1);
            mark_read(&state, 1, "42").await;
            fake.lock().unwrap().fail_lists = 1;

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
                    f.list_walks, 2,
                    "{backend:?}: the failed pre-write listing, then exactly one reconcile"
                );
                assert_eq!(
                    f.apply_calls, 2,
                    "{backend:?}: the failed batch, then the retry"
                );
            }

            // Steady state again: the next flush lists once (#246) and is a
            // plain update — no reconcile.
            mark_read(&state, 1, "43").await;
            flush_did(&state, DID).await.expect("steady-state flush");
            let f = fake.lock().unwrap();
            assert_eq!(f.list_walks, 3, "{backend:?}: a healthy flush reconciled");
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
            // The pre-write listing (#246) would set the flags itself; this
            // drives the reconcile that covers its failure.
            fake.lock().unwrap().fail_lists = 1;

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
            assert_eq!(f.list_walks, 2, "{backend:?}");
            assert_eq!(f.apply_calls, 2, "{backend:?}");
            assert_eq!(
                f.records.len(),
                150,
                "{backend:?}: a record was duplicated or lost"
            );
        }
    }

    /// **(3) The mirror: `pds_created` is set but the record was deleted
    /// elsewhere** (another client, a repo reset) — after the pre-write
    /// listing saw it. `#update` on a missing rkey fails the same way, and
    /// converges by creating it.
    ///
    /// (A failed listing no longer gets here: a cursor whose record exists is
    /// not written without one.)
    #[tokio::test]
    async fn a_deleted_record_converges_by_creating_it() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            existing(&fake, 1);
            mark_read(&state, 1, "9").await;
            store::mark_cursor_pds_created(&state.db, DID, &feed(1))
                .await
                .unwrap();
            fake.lock().unwrap().delete_after_list = Some(read_state_rkey(&feed(1)));

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
            assert_eq!((f.list_walks, f.apply_calls), (2, 2), "{backend:?}");
        }
    }

    /// **(4) Part of a batch landed.** With applyWrites chunked (#240), a later
    /// chunk can fail after an earlier one committed — exactly this issue's
    /// state for every cursor in the landed chunk. That first failure is a 503,
    /// which is NOT reconciled; the next flush meets the half-landed batch and
    /// converges in one reconcile.
    ///
    /// Feed 4's flag is wrong the other way — it claims a record that is not
    /// there. While the listings fail it is not written at all (a cursor whose
    /// record exists is never written unmerged); the first round whose listing
    /// works corrects the flag and creates it.
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
            {
                let mut f = fake.lock().unwrap();
                f.partial_then_503 = Some(2);
                // Both flushes' pre-write listings fail, so the stale flags
                // are what is sent and the reconcile is what converges.
                f.fail_lists = 2;
            }

            flush_did(&state, DID)
                .await
                .expect_err("the 503 must surface as a failure");
            {
                let f = fake.lock().unwrap();
                assert_eq!(
                    f.list_walks, 1,
                    "{backend:?}: a 503 is not a mismatch and must not reconcile"
                );
                assert_eq!(f.records.len(), 2, "{backend:?}: fixture");
            }

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            for i in 1..=3 {
                let c = cursor(&state, i).await;
                assert!(c.pds_created && !c.dirty, "{backend:?}: feed {i}");
                assert_eq!(
                    read_ids_on_pds(&fake, i),
                    serde_json::json!(["5"]),
                    "{backend:?}"
                );
            }
            {
                let f = fake.lock().unwrap();
                assert_eq!(f.list_walks, 3, "{backend:?}");
                assert_eq!(f.apply_calls, 3, "{backend:?}: 503, mismatch, retry");
                assert!(
                    !f.records.contains_key(&read_state_rkey(&feed(4))),
                    "{backend:?}: feed 4 was written without a listing"
                );
            }
            assert!(cursor(&state, 4).await.dirty, "{backend:?}: feed 4");

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            let c = cursor(&state, 4).await;
            assert!(c.pds_created && !c.dirty, "{backend:?}: feed 4");
            assert_eq!(
                read_ids_on_pds(&fake, 4),
                serde_json::json!(["5"]),
                "{backend:?}"
            );
            let f = fake.lock().unwrap();
            assert_eq!(f.list_walks, 4, "{backend:?}");
            assert_eq!(f.apply_calls, 4, "{backend:?}: plus feed 4's create");
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
                {
                    let mut f = fake.lock().unwrap();
                    f.always_fail = Some(fail);
                    // Keep the stale flag: the pre-write listing would fix it.
                    f.fail_lists = 1;
                }

                flush_did(&state, DID)
                    .await
                    .expect_err("the failure must be returned");

                let c = cursor(&state, 1).await;
                assert!(c.dirty, "{backend:?} {fail:?}: the reads were dropped");
                assert!(!c.pds_created, "{backend:?} {fail:?}: the flag moved");
                let f = fake.lock().unwrap();
                assert_eq!(
                    f.list_walks, 1,
                    "{backend:?} {fail:?}: reconciled an unrelated failure (only the pre-write listing)"
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
            {
                let mut f = fake.lock().unwrap();
                f.always_fail = Some(MISMATCH);
                f.fail_lists = 1;
            }

            let err = flush_did(&state, DID)
                .await
                .expect_err("a retry that fails again is a failure");
            // Both callers log `%err` — the plain Display, which for an anyhow
            // context is the OUTERMOST message only. The PDS's reason for the
            // second refusal must be in it, or the log says "failed again"
            // and nothing about why.
            let shown = err.to_string();
            assert!(
                shown.contains("after reconciling")
                    && shown.contains("500")
                    && shown.contains("InternalServerError"),
                "{backend:?}: the logged line lost the PDS's reason: {shown}"
            );

            let c = cursor(&state, 1).await;
            assert!(c.dirty, "{backend:?}: the reads were dropped");
            assert!(
                c.pds_created,
                "{backend:?}: the truth the listing found was not kept"
            );
            let f = fake.lock().unwrap();
            assert_eq!(
                f.list_walks, 2,
                "{backend:?}: reconciled more than once (the first walk is the failed pre-write listing)"
            );
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
            // The pre-write listing and the reconcile's, both refused.
            assert_eq!((f.list_walks, f.apply_calls), (2, 1), "{backend:?}");
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
            // The pre-write listing, then the reconcile's.
            assert_eq!((f.list_walks, f.apply_calls), (2, 1), "{backend:?}");
        }
    }

    // ── #240 × #241: a flush split into several applyWrites calls ────────────

    /// Feeds `0..n` in the order the flush sends them: the batch is keyed by
    /// rkey, so a split's first call holds the lowest rkeys.
    pub(crate) fn send_order(n: usize) -> Vec<usize> {
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&i| read_state_rkey(&feed(i)));
        order
    }

    /// **(a) Call 1 lands, call 2 hits a transport failure.** Call 1's creates
    /// are committed, so its cursors must be marked created and clean NOW. Left
    /// as they were, the next round re-sends them as `#create`, the PDS refuses,
    /// and — the calls stop at the first failure, in a fixed rkey order — every
    /// cursor sorted after them starves, every round. A transport failure is not
    /// a mismatch, so nothing is listed; the next flush sends only what did not
    /// land, plus a re-dirtied landed cursor as an UPDATE.
    #[tokio::test]
    async fn a_split_flush_keeps_what_landed_when_a_later_call_fails() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            for i in 0..250 {
                mark_read(&state, i, "1").await;
            }
            fake.lock().unwrap().drop_call = Some(2);

            let err = flush_did(&state, DID)
                .await
                .expect_err("the second call failed");
            // What callers log (`%err`) says how far the split got.
            assert!(
                err.to_string().contains("200 of 250 writes had landed"),
                "{backend:?}: the logged line lost the progress: {err}"
            );

            let order = send_order(250);
            let (landed, rest) = order.split_at(crate::atproto::APPLY_WRITES_MAX_OPS);
            for &i in landed {
                let c = cursor(&state, i).await;
                assert!(
                    c.pds_created && !c.dirty,
                    "{backend:?}: feed {i} landed in call 1 but was not settled"
                );
            }
            for &i in rest {
                let c = cursor(&state, i).await;
                assert!(
                    c.dirty && !c.pds_created,
                    "{backend:?}: feed {i} never landed"
                );
            }
            {
                let f = fake.lock().unwrap();
                assert_eq!(f.records.len(), 200, "{backend:?}: fixture");
                // One pre-write listing; no reconcile.
                assert_eq!((f.list_walks, f.apply_calls), (1, 2), "{backend:?}");
            }

            // A landed feed is read again: it must go as #update now — the
            // fake refuses a #create on an existing key.
            mark_read(&state, landed[0], "2").await;
            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: the remainder did not flush: {e:#}"));
            for i in 0..250 {
                let c = cursor(&state, i).await;
                assert!(c.pds_created && !c.dirty, "{backend:?}: feed {i}");
            }
            assert_eq!(
                read_ids_on_pds(&fake, landed[0]),
                serde_json::json!(["1", "2"]),
                "{backend:?}"
            );
            let f = fake.lock().unwrap();
            assert_eq!(f.records.len(), 250, "{backend:?}");
            assert_eq!(
                (f.list_walks, f.apply_calls),
                (2, 3),
                "{backend:?}: 51 writes are one call, and nothing needed a reconcile"
            );
        }
    }

    /// **(b) Call 1 lands, call 2 meets records that already exist.** The
    /// mismatch arrives wrapped in the chunked write's progress error, and must
    /// still be recognised: one listing, the flags corrected, and ONE retry of
    /// what did not land — not of the 200 that did.
    #[tokio::test]
    async fn a_mismatch_in_a_later_call_reconciles_and_retries_only_the_rest() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let order = send_order(250);
            for &i in &order[240..] {
                existing(&fake, i);
            }
            for i in 0..250 {
                mark_read(&state, i, "3").await;
            }
            fake.lock().unwrap().fail_lists = 1;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: did not converge: {e:#}"));

            for i in 0..250 {
                let c = cursor(&state, i).await;
                assert!(c.pds_created && !c.dirty, "{backend:?}: feed {i}");
                assert_eq!(
                    read_ids_on_pds(&fake, i),
                    serde_json::json!(["3"]),
                    "{backend:?}: feed {i}"
                );
            }
            let f = fake.lock().unwrap();
            assert_eq!(f.records.len(), 250, "{backend:?}");
            assert_eq!(
                f.list_walks, 2,
                "{backend:?}: the failed pre-write listing, then one reconcile"
            );
            assert_eq!(
                f.apply_calls, 3,
                "{backend:?}: call 1, call 2 refused, then one retry of the 50 left"
            );
        }
    }

    /// **The classifier sees through the chunked write's progress error.**
    /// `ApplyWritesIncomplete::source` continues from its cause's SOURCE, so a
    /// cause that IS the `AtProtoError` — the sidecar client's shape — does not
    /// appear in `err.chain()` at all. Both shapes, through the real wrapper.
    #[tokio::test]
    async fn a_mismatch_is_recognised_inside_a_chunked_write_error() {
        let op = crate::atproto::WriteOp::Delete {
            collection: crate::lexicon::nsid::READ_STATE.into(),
            rkey: "rs-0".into(),
        };
        let mismatch = || AtProtoError::Xrpc {
            status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            error: "InternalServerError".into(),
            message: None,
        };
        // Sidecar shape: the cause is the AtProtoError itself.
        let bare = crate::atproto::apply_writes_chunked(std::slice::from_ref(&op), |_| async {
            Err(mismatch().into())
        })
        .await
        .unwrap_err();
        assert!(
            crate::atproto::ApplyWritesIncomplete::of(&bare).is_some(),
            "fixture: not wrapped"
        );
        assert!(may_be_existence_mismatch(&bare), "sidecar shape: {bare:#}");
        // Rust-client shape: the AtProtoError behind a context.
        let wrapped = crate::atproto::apply_writes_chunked(std::slice::from_ref(&op), |_| async {
            Err(anyhow::Error::new(mismatch()).context("applyWrites failed"))
        })
        .await
        .unwrap_err();
        assert!(
            may_be_existence_mismatch(&wrapped),
            "rust shape: {wrapped:#}"
        );
        // And an unrelated failure, wrapped, is still unrelated.
        let transport =
            crate::atproto::apply_writes_chunked(std::slice::from_ref(&op), |_| async {
                Err(anyhow::anyhow!("connection reset"))
            })
            .await
            .unwrap_err();
        assert!(!may_be_existence_mismatch(&transport));
    }

    /// **The retry can part-land too.** Call 1 is refused outright (it meets
    /// records that exist), the reconcile corrects them, and the retry — 250
    /// writes, so two calls — loses its second call's connection. The retry's
    /// landed prefix must be settled exactly like the first attempt's, or its
    /// 190 fresh creates go out as `#create` again next round.
    #[tokio::test]
    async fn a_retry_that_part_lands_settles_what_it_landed() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let order = send_order(250);
            for &i in &order[..10] {
                existing(&fake, i);
            }
            for i in 0..250 {
                mark_read(&state, i, "4").await;
            }
            // Call 1 refused (mismatch), call 2 is the retry's first, call 3
            // the retry's second.
            {
                let mut f = fake.lock().unwrap();
                f.drop_call = Some(3);
                f.fail_lists = 1;
            }

            let err = flush_did(&state, DID)
                .await
                .expect_err("the retry's second call failed");
            assert!(
                err.to_string().contains("after reconciling"),
                "{backend:?}: {err}"
            );

            let (landed, rest) = order.split_at(crate::atproto::APPLY_WRITES_MAX_OPS);
            for &i in landed {
                let c = cursor(&state, i).await;
                assert!(
                    c.pds_created && !c.dirty,
                    "{backend:?}: feed {i} landed in the retry but was not settled"
                );
            }
            for &i in rest {
                let c = cursor(&state, i).await;
                assert!(c.dirty && !c.pds_created, "{backend:?}: feed {i}");
            }
            let f = fake.lock().unwrap();
            assert_eq!((f.list_walks, f.apply_calls), (2, 3), "{backend:?}");
        }
    }

    // ── #246: read, merge, write ─────────────────────────────────────────────
    //
    // A flush used to write the local cursor over whatever the PDS held, and
    // its ids were this instance's SQLite row ids. Now the ids are GUIDs and a
    // flush lists the DID's records once, merges, and then writes.

    /// **A fresh database against a PDS record with other reads.** The record
    /// must end up holding the union, written as `#update` straight away. The
    /// `pds_created` flag is learned from the listing, so it is not a failed
    /// `#create` and then a reconcile.
    #[tokio::test]
    async fn a_fresh_database_merges_into_the_existing_record_as_an_update() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &["g-remote"], &[], "2026-01-01T00:00:00Z"),
            );
            mark_read(&state, 1, "g-local").await;
            assert!(!cursor(&state, 1).await.pds_created, "fixture: a fresh DB");

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            let rec = pds_record(&fake, 1);
            assert_eq!(rec["idType"], "guid", "{backend:?}: {rec}");
            assert_eq!(
                id_set(&rec, "readIds"),
                set_of(&["g-local", "g-remote"]),
                "{backend:?}: {rec}"
            );
            let c = cursor(&state, 1).await;
            assert!(c.pds_created && !c.dirty, "{backend:?}");
            let f = fake.lock().unwrap();
            assert_eq!(
                f.apply_calls, 1,
                "{backend:?}: expected one #update, not #create then a retry"
            );
        }
    }

    /// **Another client's reads between two flushes survive the second.**
    #[tokio::test]
    async fn another_clients_reads_between_flushes_survive() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            mark_read(&state, 1, "g1").await;
            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            assert_eq!(
                id_set(&pds_record(&fake, 1), "readIds"),
                set_of(&["g1"]),
                "{backend:?}"
            );

            // Another client adds a read to the same record.
            {
                let mut f = fake.lock().unwrap();
                let rec = f.records.get_mut(&read_state_rkey(&feed(1))).unwrap();
                rec["readIds"]
                    .as_array_mut()
                    .unwrap()
                    .push("g-other".into());
                rec["updatedAt"] = "2099-01-01T00:00:00Z".into();
            }

            mark_read(&state, 1, "g2").await;
            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            assert_eq!(
                id_set(&pds_record(&fake, 1), "readIds"),
                set_of(&["g1", "g2", "g-other"]),
                "{backend:?}: another client's read was overwritten"
            );
        }
    }

    /// **A remote GUID with no local entry is carried, not dropped.** Not
    /// stored locally (there is nothing to store it against), but written
    /// back: dropping it erases another instance's read.
    #[tokio::test]
    async fn a_remote_guid_with_no_local_entry_survives_a_write() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            put_remote(
                &fake,
                1,
                remote_guid_record(
                    1,
                    &["elsewhere-read"],
                    &["elsewhere-unread"],
                    "2026-01-01T00:00:00Z",
                ),
            );
            mark_read(&state, 1, "g1").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            let rec = pds_record(&fake, 1);
            assert_eq!(
                id_set(&rec, "readIds"),
                set_of(&["g1", "elsewhere-read"]),
                "{backend:?}: {rec}"
            );
            assert_eq!(
                id_set(&rec, "unreadIds"),
                set_of(&["elsewhere-unread"]),
                "{backend:?}: {rec}"
            );
            let known: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM entries WHERE guid LIKE 'elsewhere-%'")
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert_eq!(known, 0, "{backend:?}: fixture");
        }
    }

    /// **Remote reads of entries this instance has are imported** into
    /// `entry_state`, which is what the reader sees. And it converges: a second
    /// flush with no new local reads writes nothing at all.
    #[tokio::test]
    async fn remote_reads_of_local_entries_are_imported_and_converge() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let a = entry(&state, 1, "g-a").await;
            let b = entry(&state, 1, "g-b").await;
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &["g-a", "g-b"], &[], "2026-01-01T00:00:00Z"),
            );
            mark_read(&state, 1, "g-c").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            assert!(
                is_read(&state, a).await && is_read(&state, b).await,
                "{backend:?}: not imported"
            );
            assert_eq!(
                id_set(&pds_record(&fake, 1), "readIds"),
                set_of(&["g-a", "g-b", "g-c"]),
                "{backend:?}"
            );
            assert!(
                !cursor(&state, 1).await.dirty,
                "{backend:?}: the import left the cursor dirty"
            );

            let before = {
                let f = fake.lock().unwrap();
                (f.list_walks, f.apply_calls)
            };
            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            let f = fake.lock().unwrap();
            assert_eq!(
                (f.list_walks, f.apply_calls),
                before,
                "{backend:?}: the import did not converge"
            );
        }
    }

    /// **A CLEAN feed imports too**, from the listing a flush of another feed
    /// already made, without being dirtied — so without a write of its own.
    #[tokio::test]
    async fn a_clean_feed_imports_newer_remote_reads_without_being_written() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            mark_read(&state, 1, "g1").await;
            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            assert!(!cursor(&state, 1).await.dirty, "fixture");

            // Another client reads an entry of feed 1 that this instance has.
            let other = entry(&state, 1, "g-other").await;
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &["g1", "g-other"], &[], "2099-01-01T00:00:00Z"),
            );
            let before = pds_record(&fake, 1);

            // A read in feed 2 is what makes this round flush.
            mark_read(&state, 2, "g2").await;
            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            assert!(
                is_read(&state, other).await,
                "{backend:?}: the clean feed did not import"
            );
            assert!(
                !cursor(&state, 1).await.dirty,
                "{backend:?}: the import dirtied a clean cursor"
            );
            assert_eq!(
                pds_record(&fake, 1),
                before,
                "{backend:?}: the clean feed was written"
            );
        }
    }

    /// **A legacy record — no `idType` — has instance-local row ids.** They
    /// are ignored, never imported and never written back; its `readThrough`
    /// is a timestamp and still merges.
    #[tokio::test]
    async fn a_legacy_records_ids_are_ignored_but_its_read_through_merges() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let a = entry(&state, 1, "g-a").await;
            let b = entry(&state, 1, "g-b").await;
            put_remote(
                &fake,
                1,
                serde_json::json!({
                    "$type": crate::lexicon::nsid::READ_STATE,
                    "feedUrl": feed(1),
                    "readThrough": "2026-05-01T00:00:00Z",
                    "readIds": [a.to_string(), b.to_string()],
                    "updatedAt": "2099-01-01T00:00:00Z",
                }),
            );
            mark_read(&state, 1, "g-c").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            assert!(
                !is_read(&state, a).await && !is_read(&state, b).await,
                "{backend:?}: legacy ids imported"
            );
            let rec = pds_record(&fake, 1);
            assert_eq!(
                id_set(&rec, "readIds"),
                set_of(&["g-c"]),
                "{backend:?}: {rec}"
            );
            assert_eq!(
                rec["readThrough"], "2026-05-01T00:00:00Z",
                "{backend:?}: {rec}"
            );
            assert_eq!(rec["idType"], "guid", "{backend:?}: {rec}");
        }
    }

    /// **An all-digit GUID in a GUID record is a GUID**, not a row id.
    #[tokio::test]
    async fn an_all_digit_guid_is_honoured() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let digits = entry(&state, 1, "12345").await;
            assert_ne!(
                digits, 12345,
                "fixture: the GUID must not be its own row id"
            );
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &["12345", "67890"], &[], "2026-01-01T00:00:00Z"),
            );
            mark_read(&state, 1, "g1").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            assert!(
                is_read(&state, digits).await,
                "{backend:?}: the all-digit GUID was not imported"
            );
            assert_eq!(
                id_set(&pds_record(&fake, 1), "readIds"),
                set_of(&["g1", "12345", "67890"]),
                "{backend:?}"
            );
        }
    }

    /// **Read on one side, unread on the other: the newer `updatedAt` wins**,
    /// in both directions and for both states.
    #[tokio::test]
    async fn a_read_unread_conflict_goes_to_the_newer_side() {
        const NEWER: &str = "2099-01-01T00:00:00Z";
        const OLDER: &str = "2000-01-01T00:00:00Z";
        for backend in BACKENDS {
            // (local read?, remote updatedAt) → expected final read state.
            for (local_read, remote_at, want_read) in [
                (false, NEWER, true),
                (false, OLDER, false),
                (true, NEWER, false),
                (true, OLDER, true),
            ] {
                let fake = Arc::new(Mutex::new(FakeRepo::default()));
                let state = state_on(backend, &fake).await;
                let x = mark_read(&state, 1, "x").await;
                if !local_read {
                    store::mark_read(&state.db, DID, x, false).await.unwrap();
                }
                let remote = if local_read {
                    remote_guid_record(1, &[], &["x"], remote_at)
                } else {
                    remote_guid_record(1, &["x"], &[], remote_at)
                };
                put_remote(&fake, 1, remote);

                flush_did(&state, DID)
                    .await
                    .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

                let case = format!("{backend:?}: local read={local_read}, remote at {remote_at}");
                assert_eq!(is_read(&state, x).await, want_read, "{case}: local state");
                let rec = pds_record(&fake, 1);
                let (yes, no) = if want_read {
                    ("readIds", "unreadIds")
                } else {
                    ("unreadIds", "readIds")
                };
                assert!(id_set(&rec, yes).contains("x"), "{case}: {rec}");
                assert!(!id_set(&rec, no).contains("x"), "{case}: {rec}");
            }
        }
    }

    /// **The record stays inside the lexicon's bound, and what goes first is
    /// what this instance cannot vouch for:** remote GUIDs it has no entry for.
    #[tokio::test]
    async fn at_the_cap_unresolved_remote_guids_are_dropped_first() {
        let fake = Arc::new(Mutex::new(FakeRepo::default()));
        let state = state_on(Backend::Sidecar, &fake).await;
        let remote: Vec<String> = (0..ReadState::MAX_IDS)
            .map(|i| format!("r-{i:04}"))
            .collect();
        let remote: Vec<&str> = remote.iter().map(String::as_str).collect();
        put_remote(
            &fake,
            1,
            remote_guid_record(1, &remote, &[], "2026-01-01T00:00:00Z"),
        );
        // Dated in the future, so compaction cannot fold them away... and one
        // older unread entry keeps the water-mark from passing them.
        entry_at(&state, 1, "old-unread", "2025-01-01T00:00:00Z").await;
        for i in 0..5 {
            mark_read(&state, 1, &format!("l-{i}")).await;
        }

        flush_did(&state, DID).await.unwrap();

        let ids = id_set(&pds_record(&fake, 1), "readIds");
        assert_eq!(ids.len(), ReadState::MAX_IDS);
        for i in 0..5 {
            assert!(
                ids.contains(&format!("l-{i}")),
                "a local read was dropped before a remote GUID"
            );
        }
        for i in 0..5 {
            assert!(
                !ids.contains(&format!("r-{i:04}")),
                "the oldest remote GUIDs go first"
            );
        }
    }

    /// **Compaction still bounds the record**: past the threshold, local reads
    /// fold into `readThrough`, and remote GUIDs are still carried beside it.
    #[tokio::test]
    async fn compaction_still_bounds_a_merged_record() {
        let fake = Arc::new(Mutex::new(FakeRepo::default()));
        let state = state_on(Backend::Sidecar, &fake).await;
        put_remote(
            &fake,
            1,
            remote_guid_record(1, &["elsewhere"], &[], "2026-01-01T00:00:00Z"),
        );
        for i in 0..COMPACT_READ_IDS_THRESHOLD + 10 {
            let day = format!("2026-01-01T00:{:02}:{:02}Z", i / 60, i % 60);
            let id = entry_at(&state, 1, &format!("l-{i:04}"), &day).await;
            store::mark_read(&state.db, DID, id, true).await.unwrap();
        }

        flush_did(&state, DID).await.unwrap();

        let rec = pds_record(&fake, 1);
        assert!(
            rec["readThrough"].is_string(),
            "not compacted: {}",
            rec["readThrough"]
        );
        assert_eq!(id_set(&rec, "readIds"), set_of(&["elsewhere"]));
    }

    /// **A listing that fails does not block a new record**: a feed with no
    /// record yet is created from local state — GUIDs, `idType` and all —
    /// since there is nothing on the PDS for it to erase.
    #[tokio::test]
    async fn a_listing_failure_still_creates_a_new_record() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            fake.lock().unwrap().list_fails = true;
            mark_read(&state, 1, "g1").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            let rec = pds_record(&fake, 1);
            assert_eq!(
                id_set(&rec, "readIds"),
                set_of(&["g1"]),
                "{backend:?}: {rec}"
            );
            assert_eq!(rec["idType"], "guid", "{backend:?}: {rec}");
            assert!(!cursor(&state, 1).await.dirty, "{backend:?}");
        }
    }

    // ── #246 review: timestamps, carrying, fresh cursors ─────────────────────

    /// Pin feed `i`'s cursor `updated_at` — when its content last changed —
    /// so a test can say "at 10:00" while the import runs at the real now.
    async fn set_updated_at(state: &AppState, i: usize, at: &str) {
        let n =
            sqlx::query("UPDATE read_cursor SET updated_at = ?3 WHERE did = ?1 AND feed_url = ?2")
                .bind(DID)
                .bind(feed(i))
                .bind(at)
                .execute(&state.db)
                .await
                .unwrap()
                .rows_affected();
        assert_eq!(n, 1, "fixture: no cursor for feed {i}");
    }

    /// Another client adds `guid` to the record's `readIds` at `at`.
    fn remote_reads(fake: &Arc<Mutex<FakeRepo>>, i: usize, guid: &str, at: &str) {
        let mut f = fake.lock().unwrap();
        let rec = f.records.get_mut(&read_state_rkey(&feed(i))).unwrap();
        rec["readIds"].as_array_mut().unwrap().push(guid.into());
        rec["updatedAt"] = at.into();
    }

    /// **An import does not make older state look newer.** A read x at 09:00;
    /// B marked x unread at 10:00 and has not flushed. Then A's flush — at the
    /// real now, long after 10:00 — imports another client's 09:30 read. The
    /// record A writes must not say "now": nothing in it is newer than 09:30,
    /// and B's later unread must still win when B flushes.
    #[tokio::test]
    async fn an_import_does_not_let_an_older_read_beat_a_newer_unread() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let a = state_on(backend, &fake).await;
            let b = state_on(backend, &fake).await;
            mark_read(&a, 1, "x").await;
            set_updated_at(&a, 1, "2026-01-01T09:00:00Z").await;
            flush_did(&a, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            let bx = mark_read(&b, 1, "x").await;
            store::mark_read(&b.db, DID, bx, false).await.unwrap();
            set_updated_at(&b, 1, "2026-01-01T10:00:00Z").await;

            entry(&a, 1, "z").await;
            remote_reads(&fake, 1, "z", "2026-01-01T09:30:00Z");
            mark_read(&a, 1, "w").await;
            set_updated_at(&a, 1, "2026-01-01T09:05:00Z").await;
            flush_did(&a, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            flush_did(&b, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            let rec = pds_record(&fake, 1);
            assert!(
                !is_read(&b, bx).await,
                "{backend:?}: B's newer unread lost to A's older read: {rec}"
            );
            assert!(
                id_set(&rec, "unreadIds").contains("x"),
                "{backend:?}: {rec}"
            );
            assert!(!id_set(&rec, "readIds").contains("x"), "{backend:?}: {rec}");
        }
    }

    /// **An import does not hide a later remote change.** A clean-imports a
    /// 09:30 record; B then flushes an unread it made at 10:00. On A's next
    /// round that record is newer than anything A holds, so A imports it.
    #[tokio::test]
    async fn a_clean_import_does_not_hide_a_later_remote_unread() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let a = state_on(backend, &fake).await;
            let b = state_on(backend, &fake).await;
            let ax = mark_read(&a, 1, "x").await;
            set_updated_at(&a, 1, "2026-01-01T09:00:00Z").await;
            flush_did(&a, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            // Another client reads z at 09:30; A imports it, clean.
            let az = entry(&a, 1, "z").await;
            remote_reads(&fake, 1, "z", "2026-01-01T09:30:00Z");
            mark_read(&a, 2, "a2").await;
            flush_did(&a, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            assert!(is_read(&a, az).await, "{backend:?}: fixture: z imported");

            // B marks x unread at 10:00 and flushes it.
            let bx = mark_read(&b, 1, "x").await;
            store::mark_read(&b.db, DID, bx, false).await.unwrap();
            set_updated_at(&b, 1, "2026-01-01T10:00:00Z").await;
            flush_did(&b, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            assert!(
                id_set(&pds_record(&fake, 1), "unreadIds").contains("x"),
                "{backend:?}: fixture: B's unread is on the PDS"
            );

            mark_read(&a, 2, "a3").await;
            flush_did(&a, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            assert!(
                !is_read(&a, ax).await,
                "{backend:?}: A skipped B's later unread"
            );
        }
    }

    /// **A remote read this instance has folded into its water-mark stays in
    /// the record.** Other instances never apply a remote `readThrough` to
    /// their entries, so the GUID is the only way they learn it.
    #[tokio::test]
    async fn a_remote_read_compacted_here_stays_in_the_record() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &["l-0000", "elsewhere"], &[], "2026-01-01T00:00:00Z"),
            );
            for i in 0..COMPACT_READ_IDS_THRESHOLD + 10 {
                let day = format!("2026-01-01T00:{:02}:{:02}Z", i / 60, i % 60);
                let id = entry_at(&state, 1, &format!("l-{i:04}"), &day).await;
                store::mark_read(&state.db, DID, id, true).await.unwrap();
            }

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            let rec = pds_record(&fake, 1);
            assert!(
                rec["readThrough"].is_string(),
                "{backend:?}: fixture: {rec}"
            );
            assert_eq!(
                id_set(&rec, "readIds"),
                set_of(&["l-0000", "elsewhere"]),
                "{backend:?}: a remote read vanished from the record"
            );
        }
    }

    /// **A subscribed feed with a PDS record and no local cursor imports it.**
    /// On a fresh database only feeds read here have cursors; the rest must
    /// still pick up their reads — without being written. A feed the reader
    /// does not subscribe to gets nothing.
    #[tokio::test]
    async fn a_subscribed_feed_with_no_cursor_imports_its_record() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let a = entry(&state, 1, "g-a").await;
            let b = entry(&state, 1, "g-b").await;
            let c = entry(&state, 1, "g-c").await;
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &["g-a", "g-b"], &[], "2026-01-01T00:00:00Z"),
            );
            // Feed 3: an entry, a record, but no subscription.
            let gone = entry(&state, 3, "g-gone").await;
            sqlx::query(
                "DELETE FROM sub_ref WHERE did = ?1 AND feed_id = (SELECT id FROM feeds WHERE url = ?2)",
            )
            .bind(DID)
            .bind(feed(3))
            .execute(&state.db)
            .await
            .unwrap();
            put_remote(
                &fake,
                3,
                remote_guid_record(3, &["g-gone"], &[], "2026-01-01T00:00:00Z"),
            );
            assert!(
                store::get_cursor(&state.db, DID, &feed(1))
                    .await
                    .unwrap()
                    .is_none(),
                "fixture: a fresh database"
            );
            let before = pds_record(&fake, 1);

            mark_read(&state, 2, "g2").await;
            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            assert!(
                is_read(&state, a).await && is_read(&state, b).await,
                "{backend:?}: the record was not imported"
            );
            assert!(!is_read(&state, c).await, "{backend:?}");
            let cur = cursor(&state, 1).await;
            assert!(!cur.dirty && cur.pds_created, "{backend:?}: {cur:?}");
            assert_eq!(
                pds_record(&fake, 1),
                before,
                "{backend:?}: feed 1 was written"
            );
            assert!(
                !is_read(&state, gone).await,
                "{backend:?}: unsubscribed feed imported"
            );
            assert!(
                store::get_cursor(&state.db, DID, &feed(3))
                    .await
                    .unwrap()
                    .is_none(),
                "{backend:?}: a cursor for a feed the reader does not subscribe to"
            );
        }
    }

    /// **A remote read of an entry in a feed the reader has left survives a
    /// write.** The import refuses it (no `sub_ref`), so it must be carried.
    #[tokio::test]
    async fn a_remote_read_in_an_unsubscribed_feed_survives_a_write() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            entry(&state, 1, "g-x").await;
            mark_read(&state, 1, "g1").await;
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &["g-x"], &[], "2026-01-01T00:00:00Z"),
            );
            sqlx::query("DELETE FROM sub_ref WHERE did = ?1")
                .bind(DID)
                .execute(&state.db)
                .await
                .unwrap();

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            assert_eq!(
                id_set(&pds_record(&fake, 1), "readIds"),
                set_of(&["g1", "g-x"]),
                "{backend:?}: the remote read was erased"
            );
        }
    }

    // ── #246 second review: size, timestamps, failed listings, races ─────────

    /// A GUID of about 200 bytes, distinct per `tag` and `i` — a long
    /// publisher id, well under `MAX_GUID_BYTES`.
    fn long_guid(tag: &str, i: usize) -> String {
        format!("{tag}-{i:04}-{}", "x".repeat(190))
    }

    /// **A record over the byte budget is trimmed under it**, and what goes
    /// first is what the count cap drops first: carried GUIDs with no local
    /// entry, oldest first. 900 ids is under the 1000-id cap, so only the byte
    /// budget can act here.
    #[test]
    fn an_oversized_record_is_trimmed_carried_unresolved_guids_first() {
        let unresolved: Vec<String> = (0..900).map(|i| long_guid("u", i)).collect();
        let resolved: Vec<String> = (0..5).map(|i| long_guid("h", i)).collect();
        let local: Vec<String> = (0..5).map(|i| long_guid("l", i)).collect();
        let cursor = ReadCursor {
            did: DID.into(),
            feed_url: feed(1),
            read_through: None,
            read_ids: "[1,2,3,4,5]".into(),
            unread_ids: "[]".into(),
            dirty: true,
            pds_created: true,
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let guids: HashMap<i64, store::ItemRef> = (1..=5)
            .zip(local.iter().cloned())
            .map(|(i, id)| {
                (
                    i,
                    store::ItemRef {
                        id,
                        marked_at: None,
                    },
                )
            })
            .collect();
        let carry = Carry {
            read: Carried {
                unresolved: unresolved.clone(),
                resolved: resolved.clone(),
            },
            ..Carry::default()
        };

        let rec = build_record(&cursor, &guids, None, &carry);

        let size = serde_json::to_vec(&rec).unwrap().len();
        assert!(
            size <= READ_STATE_RECORD_MAX_BYTES,
            "{size} bytes, over the {READ_STATE_RECORD_MAX_BYTES}-byte budget"
        );
        for g in local.iter().chain(&resolved) {
            assert!(
                rec.read_ids.contains(g),
                "{g:.8}: dropped before the unresolved GUIDs"
            );
        }
        assert!(
            !rec.read_ids.contains(&unresolved[0]),
            "the oldest unresolved GUID is dropped first"
        );
        assert!(
            rec.read_ids.contains(&unresolved[899]),
            "trimmed further than the budget needs"
        );
    }

    /// **One oversized record does not starve the feeds sorted after it.** A
    /// PDS with a 150 KiB `jsonLimit` refuses a ~180 KB record outright; the
    /// chunked write stops at the refused call, and every later feed never
    /// went out — every round. Trimmed to the budget, both land.
    #[tokio::test]
    async fn an_oversized_record_does_not_starve_the_feeds_after_it() {
        let (big, small) = if read_state_rkey(&feed(1)) < read_state_rkey(&feed(2)) {
            (1, 2)
        } else {
            (2, 1)
        };
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo {
                json_limit: Some(150 * 1024),
                ..FakeRepo::default()
            }));
            let state = state_on(backend, &fake).await;
            let remote: Vec<String> = (0..900).map(|i| long_guid("u", i)).collect();
            let remote: Vec<&str> = remote.iter().map(String::as_str).collect();
            put_remote(
                &fake,
                big,
                remote_guid_record(big, &remote, &[], "2026-01-01T00:00:00Z"),
            );
            mark_read(&state, big, "g-big").await;
            mark_read(&state, small, "g-small").await;

            let res = flush_did(&state, DID).await;

            let landed = fake
                .lock()
                .unwrap()
                .records
                .get(&read_state_rkey(&feed(small)))
                .cloned();
            assert!(
                landed.is_some_and(|r| id_set(&r, "readIds") == set_of(&["g-small"])),
                "{backend:?}: the feed after the oversized record starved: {res:?}"
            );
            res.unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            let rec = pds_record(&fake, big);
            assert!(
                id_set(&rec, "readIds").contains("g-big"),
                "{backend:?}: the local read was dropped"
            );
            assert!(
                serde_json::to_vec(&rec).unwrap().len() <= READ_STATE_RECORD_MAX_BYTES,
                "{backend:?}"
            );
            for i in [big, small] {
                assert!(!cursor(&state, i).await.dirty, "{backend:?}: feed {i}");
            }
        }
    }

    /// **Carrying a remote record never moves `updatedAt` backwards.** B wrote
    /// a read at 05:00; A, whose cursor last changed at 03:00, carries it and
    /// rewrites the record. Stamped 03:00, a third instance whose 04:00 unread
    /// conflicts would now look newer than the record and win against B's
    /// later read. The record keeps the later stamp — normalised to UTC — and
    /// A's own cursor, which imported nothing, keeps its own.
    #[tokio::test]
    async fn a_carried_record_never_moves_updated_at_backwards() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &["g-b"], &[], "2026-01-01T06:00:00+01:00"),
            );
            mark_read(&state, 1, "g-a").await;
            set_updated_at(&state, 1, "2026-01-01T03:00:00Z").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            let rec = pds_record(&fake, 1);
            assert_eq!(
                id_set(&rec, "readIds"),
                set_of(&["g-a", "g-b"]),
                "{backend:?}: fixture: {rec}"
            );
            assert_eq!(
                rec["updatedAt"], "2026-01-01T05:00:00Z",
                "{backend:?}: updatedAt went backwards: {rec}"
            );
            let c = cursor(&state, 1).await;
            assert_eq!(
                c.updated_at, "2026-01-01T03:00:00Z",
                "{backend:?}: a pure carry moved the local cursor"
            );
            assert!(!c.dirty, "{backend:?}");
        }
    }

    /// **A failed listing does not overwrite a record that exists.** Without
    /// the listing there is nothing to merge, and writing local state over the
    /// record erases what other clients put there — #246 itself. The cursor
    /// waits, dirty, for a round whose listing works; a feed with no record
    /// yet still flushes, since there is nothing to erase.
    #[tokio::test]
    async fn a_listing_failure_does_not_overwrite_an_existing_record() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &["g-elsewhere"], &[], "2026-01-01T00:00:00Z"),
            );
            mark_read(&state, 1, "g1").await;
            store::mark_cursor_pds_created(&state.db, DID, &feed(1))
                .await
                .unwrap();
            mark_read(&state, 2, "g2").await;
            let before = pds_record(&fake, 1);
            fake.lock().unwrap().list_fails = true;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            assert_eq!(
                pds_record(&fake, 1),
                before,
                "{backend:?}: an existing record was overwritten unmerged"
            );
            assert!(cursor(&state, 1).await.dirty, "{backend:?}: feed 1");
            assert_eq!(
                id_set(&pds_record(&fake, 2), "readIds"),
                set_of(&["g2"]),
                "{backend:?}: the new record was not created"
            );
            assert!(!cursor(&state, 2).await.dirty, "{backend:?}: feed 2");

            // The next round lists, merges and writes it.
            fake.lock().unwrap().list_fails = false;
            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            assert_eq!(
                id_set(&pds_record(&fake, 1), "readIds"),
                set_of(&["g1", "g-elsewhere"]),
                "{backend:?}"
            );
            assert!(!cursor(&state, 1).await.dirty, "{backend:?}");
        }
    }

    /// The remote record for feed `i`, parsed as the flusher parses it.
    fn parsed(record: serde_json::Value) -> ReadState {
        serde_json::from_value(record).unwrap()
    }

    /// **A local mark between the merge's decision and its import survives.**
    /// The decision reads `entry_state`; the import writes it in a later
    /// transaction. The reader marking x unread in between is newer than the
    /// remote's read, and must not be overwritten by it.
    #[tokio::test]
    async fn a_local_mark_between_the_decision_and_the_import_survives() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let x = entry(&state, 1, "x").await;
            mark_read(&state, 1, "other").await;
            let theirs = parsed(remote_guid_record(1, &["x"], &[], "2026-01-01T00:00:00Z"));
            let plan = plan_guid_merge(&state, DID, &cursor(&state, 1).await, &theirs)
                .await
                .unwrap();
            assert_eq!(plan.to_read.len(), 1, "{backend:?}: fixture");

            assert!(store::mark_read(&state.db, DID, x, false).await.unwrap());
            apply_guid_merge(&state, DID, &feed(1), &plan)
                .await
                .unwrap();

            assert!(
                !is_read(&state, x).await,
                "{backend:?}: the import overwrote a newer local unread"
            );
            assert!(
                parse_id_array(&cursor(&state, 1).await.unread_ids).contains(&x.to_string()),
                "{backend:?}"
            );
        }
    }

    /// **The same, with the mark during the listing**: the flush's cursor
    /// snapshot is older than the mark, `entry_state` is not. The decision
    /// must not mix the two.
    #[tokio::test]
    async fn a_local_mark_during_the_listing_survives_the_import() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let x = entry(&state, 1, "x").await;
            mark_read(&state, 1, "other").await;
            let stale = cursor(&state, 1).await;
            let theirs = parsed(remote_guid_record(1, &["x"], &[], "2026-01-01T00:00:00Z"));

            assert!(store::mark_read(&state.db, DID, x, false).await.unwrap());
            let _ = merge_remote(&state, DID, stale, &theirs).await;

            assert!(
                !is_read(&state, x).await,
                "{backend:?}: the import overwrote a newer local unread"
            );
        }
    }

    // ── #287: the item-id rule ───────────────────────────────────────────────

    /// **An item with no publisher id is written as its link**, not as the
    /// hash FeatherReader made up for it.
    #[tokio::test]
    async fn a_link_only_item_is_written_as_its_link() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let hash = "5813b43a0512aaef2750311bf4d978a";
            let id = synthesized_entry(&state, 1, hash, Some("https://n.example/post")).await;
            assert!(store::mark_read(&state.db, DID, id, true).await.unwrap());
            mark_read(&state, 1, "pub-1").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            let rec = pds_record(&fake, 1);
            assert_eq!(
                id_set(&rec, "readIds"),
                set_of(&["https://n.example/post", "pub-1"]),
                "{backend:?}: {rec}"
            );
        }
    }

    /// **An item with neither an id nor a link has no portable name**, so it is
    /// left out of the record; the cursor still holds its row id.
    #[tokio::test]
    async fn an_item_with_neither_id_nor_link_is_not_written() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let id = synthesized_entry(&state, 1, "featherreader:synthetic:deadbeef", None).await;
            assert!(store::mark_read(&state.db, DID, id, true).await.unwrap());
            mark_read(&state, 1, "pub-1").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            let rec = pds_record(&fake, 1);
            assert_eq!(
                id_set(&rec, "readIds"),
                set_of(&["pub-1"]),
                "{backend:?}: {rec}"
            );
            let c = cursor(&state, 1).await;
            assert_eq!(parse_id_array(&c.read_ids).len(), 2, "{backend:?}");
            assert!(!c.dirty, "{backend:?}");
        }
    }

    /// **A remote link id marks the link-only item read here.**
    #[tokio::test]
    async fn a_remote_link_id_marks_a_link_only_item_read() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let b = synthesized_entry(&state, 1, "hash-b", Some("https://n.example/b")).await;
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &["https://n.example/b"], &[], "2026-01-01T00:00:00Z"),
            );
            mark_read(&state, 1, "pub-1").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            assert!(
                is_read(&state, b).await,
                "{backend:?}: the link did not resolve"
            );
            assert_eq!(
                id_set(&pds_record(&fake, 1), "readIds"),
                set_of(&["https://n.example/b", "pub-1"]),
                "{backend:?}"
            );
        }
    }

    /// **A record written by a build before #287 still resolves**: it holds the
    /// feed-rs hash, which is still the row's guid.
    #[tokio::test]
    async fn a_record_written_with_a_feed_rs_hash_still_resolves() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let hash = "5813b43a0512aaef2750311bf4d978a";
            let b = synthesized_entry(&state, 1, hash, Some("https://n.example/post")).await;
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &[hash], &[], "2026-01-01T00:00:00Z"),
            );
            mark_read(&state, 1, "pub-1").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            assert!(
                is_read(&state, b).await,
                "{backend:?}: the hash did not resolve"
            );
            let ids = id_set(&pds_record(&fake, 1), "readIds");
            for want in ["https://n.example/post", "pub-1", hash] {
                assert!(
                    ids.contains(want),
                    "{backend:?}: {want} missing from {ids:?}"
                );
            }
        }
    }

    /// **Two rows sharing a link are both imported, and named once.**
    #[tokio::test]
    async fn two_rows_sharing_a_link_are_both_marked_read() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let u = "https://n.example/edited";
            let b1 = synthesized_entry(&state, 1, "hash-old-title", Some(u)).await;
            let b2 = synthesized_entry(&state, 1, "hash-new-title", Some(u)).await;
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &[u], &[], "2026-01-01T00:00:00Z"),
            );
            mark_read(&state, 1, "pub-1").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            assert!(
                is_read(&state, b1).await && is_read(&state, b2).await,
                "{backend:?}: only one of the two rows was imported"
            );
            assert_eq!(
                id_set(&pds_record(&fake, 1), "readIds"),
                set_of(&[u, "pub-1"]),
                "{backend:?}"
            );
        }
    }

    /// **An explicit unread on ANY row sharing the link blocks an older
    /// remote read.**
    #[tokio::test]
    async fn a_shared_link_explicitly_unread_on_one_row_blocks_the_import() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let u = "https://n.example/edited";
            let b1 = synthesized_entry(&state, 1, "hash-old-title", Some(u)).await;
            let b2 = synthesized_entry(&state, 1, "hash-new-title", Some(u)).await;
            assert!(store::mark_read(&state.db, DID, b2, true).await.unwrap());
            assert!(store::mark_read(&state.db, DID, b2, false).await.unwrap());
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &[u], &[], "2000-01-01T00:00:00Z"),
            );

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            assert!(
                !is_read(&state, b1).await && !is_read(&state, b2).await,
                "{backend:?}: an older remote read beat a newer local unread"
            );
            let rec = pds_record(&fake, 1);
            assert!(!id_set(&rec, "readIds").contains(u), "{backend:?}: {rec}");
            assert!(id_set(&rec, "unreadIds").contains(u), "{backend:?}: {rec}");
        }
    }

    /// Stamp `entry_state.updated_at` for a row, so a test controls which
    /// mark is the later one (two marks in one second otherwise tie).
    async fn stamp(state: &AppState, id: i64, at: &str) {
        sqlx::query("UPDATE entry_state SET updated_at = ?1 WHERE did = ?2 AND entry_id = ?3")
            .bind(at)
            .bind(DID)
            .bind(id)
            .execute(&state.db)
            .await
            .unwrap();
    }

    /// Two rows share a link; `b1` is marked read and `b2` read then unread,
    /// stamped as given. The flushed record, per backend.
    async fn shared_link_record(
        read_at: &str,
        unread_at: &str,
    ) -> Vec<(Backend, serde_json::Value)> {
        let mut out = Vec::new();
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let u = "https://n.example/edited";
            let b1 = synthesized_entry(&state, 1, "hash-old-title", Some(u)).await;
            let b2 = synthesized_entry(&state, 1, "hash-new-title", Some(u)).await;
            assert!(store::mark_read(&state.db, DID, b1, true).await.unwrap());
            assert!(store::mark_read(&state.db, DID, b2, true).await.unwrap());
            assert!(store::mark_read(&state.db, DID, b2, false).await.unwrap());
            stamp(&state, b1, read_at).await;
            stamp(&state, b2, unread_at).await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));
            out.push((backend, pds_record(&fake, 1)));
        }
        out
    }

    /// **An item id is on one side of the record**: rows sharing a link, one
    /// read earlier and one unread later, name it in `unreadIds` only.
    #[tokio::test]
    async fn a_shared_link_read_earlier_and_unread_later_is_only_unread() {
        let u = "https://n.example/edited";
        for (backend, rec) in
            shared_link_record("2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z").await
        {
            assert!(!id_set(&rec, "readIds").contains(u), "{backend:?}: {rec}");
            assert!(id_set(&rec, "unreadIds").contains(u), "{backend:?}: {rec}");
        }
    }

    /// The reverse order: unread earlier, read later, is only read.
    #[tokio::test]
    async fn a_shared_link_unread_earlier_and_read_later_is_only_read() {
        let u = "https://n.example/edited";
        for (backend, rec) in
            shared_link_record("2026-03-02T00:00:00Z", "2026-03-01T00:00:00Z").await
        {
            assert!(id_set(&rec, "readIds").contains(u), "{backend:?}: {rec}");
            assert!(!id_set(&rec, "unreadIds").contains(u), "{backend:?}: {rec}");
        }
    }

    /// A tie goes to unread.
    #[tokio::test]
    async fn a_shared_link_marked_at_the_same_instant_is_unread() {
        let u = "https://n.example/edited";
        for (backend, rec) in
            shared_link_record("2026-03-01T00:00:00Z", "2026-03-01T00:00:00Z").await
        {
            assert!(!id_set(&rec, "readIds").contains(u), "{backend:?}: {rec}");
            assert!(id_set(&rec, "unreadIds").contains(u), "{backend:?}: {rec}");
        }
    }

    /// **A remote record listing one id in both sets** (an older writer) is
    /// read as unread, not read.
    #[tokio::test]
    async fn a_remote_id_in_both_sets_is_imported_as_unread() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let u = "https://n.example/post";
            let b = synthesized_entry(&state, 1, "hash-b", Some(u)).await;
            put_remote(
                &fake,
                1,
                remote_guid_record(1, &[u], &[u], "2999-01-01T00:00:00Z"),
            );
            mark_read(&state, 1, "pub-1").await;

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            assert!(!is_read(&state, b).await, "{backend:?}: imported as read");
            let rec = pds_record(&fake, 1);
            assert!(!id_set(&rec, "readIds").contains(u), "{backend:?}: {rec}");
            assert!(id_set(&rec, "unreadIds").contains(u), "{backend:?}: {rec}");
        }
    }

    /// **An explicit unread below a LATER remote mark stays in the record**:
    /// the record carries the later `readThrough`, so the exception is what
    /// keeps the entry unread everywhere. Compaction used to drop it.
    #[tokio::test]
    async fn an_explicit_unread_below_a_later_remote_mark_stays_in_the_record() {
        for backend in BACKENDS {
            let fake = Arc::new(Mutex::new(FakeRepo::default()));
            let state = state_on(backend, &fake).await;
            let x = entry_at(&state, 1, "x", "2026-05-01T00:00:00Z").await;
            assert!(store::mark_read(&state.db, DID, x, true).await.unwrap());
            assert!(store::mark_read(&state.db, DID, x, false).await.unwrap());
            for i in 0..COMPACT_READ_IDS_THRESHOLD + 10 {
                let day = format!("2026-01-01T00:{:02}:{:02}Z", i / 60, i % 60);
                let id = entry_at(&state, 1, &format!("l-{i:04}"), &day).await;
                store::mark_read(&state.db, DID, id, true).await.unwrap();
            }
            put_remote(
                &fake,
                1,
                serde_json::json!({
                    "$type": crate::lexicon::nsid::READ_STATE,
                    "feedUrl": feed(1),
                    "idType": "guid",
                    "readThrough": "2026-12-31T00:00:00Z",
                    "updatedAt": "2000-01-01T00:00:00Z",
                }),
            );

            flush_did(&state, DID)
                .await
                .unwrap_or_else(|e| panic!("{backend:?}: {e:#}"));

            let rec = pds_record(&fake, 1);
            assert_eq!(
                rec["readThrough"], "2026-12-31T00:00:00Z",
                "{backend:?}: {rec}"
            );
            assert!(
                id_set(&rec, "unreadIds").contains("x"),
                "{backend:?}: {rec}"
            );
            assert!(!id_set(&rec, "readIds").contains("x"), "{backend:?}: {rec}");
            assert!(!is_read(&state, x).await, "{backend:?}");
        }
    }
}
