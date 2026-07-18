//! The bot's local idempotency store — one SQLite file on the bot host.
//!
//! Keyed on the follower DID so unfollow→refollow never re-posts (the DID, not
//! the follow event, is the unit of work). The mint+post step records INTENT
//! FIRST (`status='minting'`) so a crash mid-way resumes delivery on the next
//! poll rather than minting a second code / posting a second skeet.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};

/// Lifecycle of a handled follower.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Intent recorded; code not yet minted (crash-recovery resumes here).
    Minting,
    /// Claim minted AND the public skeet posted — terminal success.
    Delivered,
    /// The app signalled the beta is full; nothing minted. NON-terminal, so the
    /// poll loop retries this DID on a later cycle once seats free up — but the
    /// row PERSISTS (unlike a forget) so operators can enumerate who is pending.
    Waitlisted,
    /// Deliberately skipped (already a member, the bot itself, etc.).
    Skipped,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Minting => "minting",
            Status::Delivered => "delivered",
            Status::Waitlisted => "waitlisted",
            Status::Skipped => "skipped",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "minting" => Status::Minting,
            "delivered" => Status::Delivered,
            "waitlisted" => Status::Waitlisted,
            "skipped" => Status::Skipped,
            _ => return None,
        })
    }
}

/// The bot's SQLite idempotency store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) the store at `path` and ensure the schema.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("open bot state db {path}"))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("enable WAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)
            .context("set busy_timeout")?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS handled (
                did          TEXT PRIMARY KEY,
                handle       TEXT,
                status       TEXT NOT NULL,
                code         TEXT,
                claim_url    TEXT,
                post_uri     TEXT,
                -- 1 once the waitlist-welcome skeet has been posted for this DID,
                -- so a follower who stays `waitlisted` across many cycles is NOT
                -- re-welcomed every cycle (post-once semantics).
                welcomed     INTEGER NOT NULL DEFAULT 0,
                created_at   INTEGER NOT NULL,
                delivered_at INTEGER
            );
            "#,
        )
        .context("create bot schema")?;
        conn.execute_batch(
            r#"
            -- One row per FRESH claim mint, for the global daily mint budget (the
            -- sybil brake). Idempotent re-posts / waitlist-welcomes are NOT logged
            -- here, so the budget only meters genuinely-new seats handed out.
            CREATE TABLE IF NOT EXISTS mint_log (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                did      TEXT NOT NULL,
                minted_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_mint_log_time ON mint_log (minted_at);
            "#,
        )
        .context("create bot mint_log schema")?;
        // Additive migration for an OLD bot DB that predates `welcomed`. SQLite has
        // no `ADD COLUMN IF NOT EXISTS`, so probe `table_info` first.
        Self::ensure_welcomed_column(&conn)?;
        Ok(Self { conn })
    }

    /// Add the `welcomed` column to an existing `handled` table if it is missing.
    fn ensure_welcomed_column(conn: &Connection) -> Result<()> {
        let present: bool = {
            let mut stmt = conn.prepare("PRAGMA table_info(handled)")?;
            let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
            let mut found = false;
            for c in cols {
                if c? == "welcomed" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !present {
            conn.execute(
                "ALTER TABLE handled ADD COLUMN welcomed INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .context("add handled.welcomed column")?;
        }
        Ok(())
    }

    /// Whether this DID has reached a TERMINAL state (`delivered` or `skipped`) —
    /// i.e. there is nothing left to do for it. The poll loop treats a terminal
    /// DID as "caught up"; a non-terminal `minting` row is deliberately NOT
    /// terminal, so a follower whose mint/post was interrupted is picked up again
    /// and resumed (rather than silently stranded forever).
    pub fn is_terminal(&self, did: &str) -> Result<bool> {
        // S7: `.optional()` maps a MISSING row to `None`; any OTHER rusqlite error
        // (a locked/corrupt DB, an I/O fault) PROPAGATES rather than being swallowed
        // as "no row". A silent error here would make an already-delivered follower
        // look un-handled → a duplicate mint/post.
        let status: Option<String> = self
            .conn
            .query_row("SELECT status FROM handled WHERE did = ?1", [did], |r| {
                r.get(0)
            })
            .optional()
            .with_context(|| format!("is_terminal query for {did}"))?;
        Ok(matches!(
            status.as_deref().and_then(Status::parse),
            Some(Status::Delivered) | Some(Status::Skipped)
        ))
    }

    /// The claim `(code, url)` already minted for a DID, if the mint completed
    /// before an interruption. `Some((code, url))` means "resume by re-posting, do
    /// NOT mint again"; `None` means "no code yet — mint". Both columns must be
    /// present (a half-written row falls back to a re-mint).
    pub fn resume_claim(&self, did: &str) -> Result<Option<(String, String)>> {
        let row: Option<(Option<String>, Option<String>)> = self
            .conn
            .query_row(
                "SELECT code, claim_url FROM handled WHERE did = ?1",
                [did],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            // S7: distinguish "no row" (→ None → mint) from a real DB error (→
            // propagate). Swallowing an error as None would re-mint a code that
            // was already minted+stored, stranding the first.
            .optional()
            .with_context(|| format!("resume_claim query for {did}"))?;
        Ok(match row {
            Some((Some(code), Some(url))) => Some((code, url)),
            _ => None,
        })
    }

    /// The current status of a handled DID, if any.
    pub fn status_of(&self, did: &str) -> Result<Option<Status>> {
        let row: Option<String> = self
            .conn
            .query_row("SELECT status FROM handled WHERE did = ?1", [did], |r| {
                r.get(0)
            })
            // S7: real DB errors propagate; only a missing row is `None`.
            .optional()
            .with_context(|| format!("status_of query for {did}"))?;
        Ok(row.and_then(|s| Status::parse(&s)))
    }

    /// Record INTENT to handle `did` before any external side effect (mint /
    /// post). Idempotent: if the DID already has a row this leaves it untouched
    /// (so a crash-recovery pass doesn't reset a `delivered` row to `minting`).
    /// Returns true if a NEW intent row was inserted.
    pub fn record_intent(&self, did: &str, handle: Option<&str>) -> Result<bool> {
        let changed = self.conn.execute(
            "INSERT INTO handled (did, handle, status, created_at)
             VALUES (?1, ?2, 'minting', ?3)
             ON CONFLICT(did) DO NOTHING",
            rusqlite::params![did, handle, now()],
        )?;
        Ok(changed > 0)
    }

    /// Persist the minted claim `code` + `claim_url` on a `minting` row BEFORE
    /// posting the skeet. If the post then fails and the run is interrupted, the
    /// next cycle sees the stored code and re-posts rather than minting a second
    /// code (which would strand the first). Leaves the status at `minting`.
    pub fn record_minted_code(&self, did: &str, code: &str, claim_url: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE handled SET code=?2, claim_url=?3 WHERE did=?1",
            rusqlite::params![did, code, claim_url],
        )?;
        Ok(())
    }

    /// Mark a DID delivered after the claim was minted AND the skeet posted.
    pub fn mark_delivered(
        &self,
        did: &str,
        code: &str,
        claim_url: &str,
        post_uri: &str,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE handled
             SET status='delivered', code=?2, claim_url=?3, post_uri=?4, delivered_at=?5
             WHERE did=?1",
            rusqlite::params![did, code, claim_url, post_uri, now()],
        )?;
        Ok(())
    }

    /// Mark a DID as skipped (member/self/etc.) with a terminal status.
    pub fn mark_status(&self, did: &str, handle: Option<&str>, status: Status) -> Result<()> {
        self.conn.execute(
            "INSERT INTO handled (did, handle, status, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(did) DO UPDATE SET status=excluded.status, handle=COALESCE(excluded.handle, handled.handle)",
            rusqlite::params![did, handle, status.as_str(), now()],
        )?;
        Ok(())
    }

    /// Whether the waitlist-welcome skeet has already been posted for `did`. The
    /// welcome is posted ONCE; a follower who stays `waitlisted` across many cycles
    /// must not be re-welcomed every cycle.
    pub fn was_welcomed(&self, did: &str) -> Result<bool> {
        let flag: Option<i64> = self
            .conn
            .query_row("SELECT welcomed FROM handled WHERE did = ?1", [did], |r| {
                r.get(0)
            })
            // S7: a real DB error must NOT read as "not welcomed" (which would
            // re-post the welcome every cycle) — propagate it; only a missing row
            // is the legitimate `None` → not welcomed.
            .optional()
            .with_context(|| format!("was_welcomed query for {did}"))?;
        Ok(flag.unwrap_or(0) != 0)
    }

    /// Record that the waitlist-welcome skeet has been posted for `did` (creating
    /// or updating the row, leaving status/handle intact). Idempotent.
    pub fn mark_welcomed(&self, did: &str, handle: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO handled (did, handle, status, welcomed, created_at)
             VALUES (?1, ?2, 'waitlisted', 1, ?3)
             ON CONFLICT(did) DO UPDATE SET
                 welcomed=1,
                 handle=COALESCE(excluded.handle, handled.handle)",
            rusqlite::params![did, handle, now()],
        )?;
        Ok(())
    }

    /// Record a FRESH claim mint for the global daily budget (the sybil brake).
    /// Call this ONLY when the app returns a freshly-minted claim — not on an
    /// idempotent re-post of an existing one, so the budget meters real new seats.
    pub fn record_mint(&self, did: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO mint_log (did, minted_at) VALUES (?1, ?2)",
            rusqlite::params![did, now()],
        )?;
        Ok(())
    }

    /// Count fresh mints in the rolling window `[now - window_secs, now]` — the
    /// figure the poll loop checks against `max_daily_mints` before minting more.
    pub fn count_mints_since(&self, window_secs: i64) -> Result<usize> {
        let cutoff = now() - window_secs;
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM mint_log WHERE minted_at >= ?1",
            [cutoff],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    /// Whether the store has NO handled rows yet — i.e. this is a FIRST RUN (fresh
    /// state DB / persistent volume). The poll loop uses this to do a FULL-history
    /// follower backfill on the first cycle (S5): the normal `MAX_PAGES` cap would
    /// otherwise never reach a follower beyond the newest ~300, stranding an
    /// existing backlog on a freshly-deployed bot until each old follower happened
    /// to re-follow. Propagates a real DB error (S7).
    pub fn is_empty(&self) -> Result<bool> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM handled", [], |r| r.get(0))
            .context("counting handled rows")?;
        Ok(n == 0)
    }

    /// Enumerate the DIDs currently `waitlisted` (with their stored handle), so the
    /// poll loop can RETRY their mint each cycle INDEPENDENT of follower paging —
    /// a waitlisted follower who scrolled off the first `MAX_PAGES` of getFollowers
    /// would otherwise be stranded until they happened to be re-seen. Bounded by the
    /// caller (`max_per_cycle`); ordered oldest-first (FIFO fairness).
    pub fn waitlisted_dids(&self, limit: usize) -> Result<Vec<(String, Option<String>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT did, handle FROM handled
             WHERE status = 'waitlisted'
             ORDER BY created_at ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Store {
        // A file in a tempdir (rusqlite :memory: is per-connection; a temp file
        // keeps the WAL/pragma path identical to production).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let s = Store::open(path.to_str().unwrap()).unwrap();
        // Leak the tempdir so the file outlives the test body.
        std::mem::forget(dir);
        s
    }

    #[test]
    fn intent_is_idempotent_on_did() {
        let s = mem();
        assert!(s.record_intent("did:plc:a", Some("a.test")).unwrap());
        // Second call is a no-op (refollow must not re-post).
        assert!(!s.record_intent("did:plc:a", Some("a.test")).unwrap());
        assert_eq!(s.status_of("did:plc:a").unwrap(), Some(Status::Minting));
        // A `minting` row is NOT terminal — it must be resumed, not skipped.
        assert!(!s.is_terminal("did:plc:a").unwrap());
    }

    #[test]
    fn minting_is_not_terminal_so_interrupted_followers_resume() {
        let s = mem();
        s.record_intent("did:plc:m", Some("m.test")).unwrap();
        // No code stored yet → resume by minting.
        assert_eq!(s.resume_claim("did:plc:m").unwrap(), None);
        assert!(!s.is_terminal("did:plc:m").unwrap());
        // After minting (but before a failed post), the code is persisted so the
        // resume path re-posts instead of minting a SECOND code.
        s.record_minted_code("did:plc:m", "FEATHER-YY", "https://x/claim?t=2")
            .unwrap();
        assert_eq!(
            s.resume_claim("did:plc:m").unwrap(),
            Some(("FEATHER-YY".to_string(), "https://x/claim?t=2".to_string()))
        );
        assert!(!s.is_terminal("did:plc:m").unwrap());
        // Only once delivered is it terminal.
        s.mark_delivered("did:plc:m", "FEATHER-YY", "https://x/claim?t=2", "at://p")
            .unwrap();
        assert!(s.is_terminal("did:plc:m").unwrap());
    }

    #[test]
    fn deliver_transitions_status() {
        let s = mem();
        s.record_intent("did:plc:b", None).unwrap();
        s.mark_delivered(
            "did:plc:b",
            "FEATHER-XX",
            "https://x/claim?t=1",
            "at://post",
        )
        .unwrap();
        assert_eq!(s.status_of("did:plc:b").unwrap(), Some(Status::Delivered));
        assert!(s.is_terminal("did:plc:b").unwrap());
        // A re-handle (crash recovery) does NOT reset a delivered row.
        assert!(!s.record_intent("did:plc:b", None).unwrap());
        assert_eq!(s.status_of("did:plc:b").unwrap(), Some(Status::Delivered));
    }

    #[test]
    fn skip_and_waitlist() {
        let s = mem();
        s.mark_status("did:plc:self", Some("me"), Status::Skipped)
            .unwrap();
        assert_eq!(s.status_of("did:plc:self").unwrap(), Some(Status::Skipped));
        // Skipped is terminal (the poll loop treats it as caught up).
        assert!(s.is_terminal("did:plc:self").unwrap());
        s.mark_status("did:plc:w", None, Status::Waitlisted)
            .unwrap();
        assert_eq!(s.status_of("did:plc:w").unwrap(), Some(Status::Waitlisted));
        // A waitlisted row PERSISTS but is NON-terminal, so a later cycle retries
        // it (the poll loop keeps collecting it) while operators can still see it.
        assert!(!s.is_terminal("did:plc:w").unwrap());
    }

    #[test]
    fn welcome_is_posted_once_per_waitlisted_did() {
        let s = mem();
        // Not welcomed until marked.
        assert!(!s.was_welcomed("did:plc:w").unwrap());
        s.mark_welcomed("did:plc:w", Some("w.test")).unwrap();
        assert!(s.was_welcomed("did:plc:w").unwrap());
        // Marking is idempotent and keeps the waitlisted status (non-terminal).
        s.mark_welcomed("did:plc:w", Some("w.test")).unwrap();
        assert!(s.was_welcomed("did:plc:w").unwrap());
        assert_eq!(s.status_of("did:plc:w").unwrap(), Some(Status::Waitlisted));
        assert!(!s.is_terminal("did:plc:w").unwrap());
        // A later delivery (seat freed) clears the pipeline without disturbing the
        // welcomed flag (the follower already got their welcome post).
        s.record_minted_code("did:plc:w", "FEATHER-ZZ", "https://x/claim?t=9")
            .unwrap();
        s.mark_delivered("did:plc:w", "FEATHER-ZZ", "https://x/claim?t=9", "at://p")
            .unwrap();
        assert_eq!(s.status_of("did:plc:w").unwrap(), Some(Status::Delivered));
        assert!(s.was_welcomed("did:plc:w").unwrap());
    }

    #[test]
    fn waitlisted_dids_enumerates_for_retry_bounded_and_fifo() {
        let s = mem();
        // Two waitlisted, one delivered, one skipped — only the waitlisted appear.
        s.mark_status("did:plc:w1", Some("w1"), Status::Waitlisted)
            .unwrap();
        s.mark_status("did:plc:w2", Some("w2"), Status::Waitlisted)
            .unwrap();
        s.record_intent("did:plc:d", Some("d")).unwrap();
        s.mark_delivered("did:plc:d", "c", "u", "p").unwrap();
        s.mark_status("did:plc:s", None, Status::Skipped).unwrap();

        let all = s.waitlisted_dids(10).unwrap();
        assert_eq!(all.len(), 2);
        let dids: Vec<&str> = all.iter().map(|(d, _)| d.as_str()).collect();
        assert!(dids.contains(&"did:plc:w1"));
        assert!(dids.contains(&"did:plc:w2"));
        // The bound is honoured.
        assert_eq!(s.waitlisted_dids(1).unwrap().len(), 1);
    }

    #[test]
    fn store_reads_propagate_real_db_errors_not_no_row() {
        // S7: a REAL DB error (here: the `handled` table dropped out from under the
        // reads) must PROPAGATE as Err, not be swallowed as "no row" (which would
        // re-welcome / re-mint / re-post a follower). A genuinely-missing row still
        // returns Ok(None)/Ok(false) (covered by the other tests).
        let s = mem();
        s.record_intent("did:plc:x", Some("x.test")).unwrap();
        // Break the table the reads depend on.
        s.conn.execute_batch("DROP TABLE handled;").unwrap();

        assert!(
            s.status_of("did:plc:x").is_err(),
            "status_of must propagate a table-missing error"
        );
        assert!(
            s.is_terminal("did:plc:x").is_err(),
            "is_terminal must propagate a table-missing error"
        );
        assert!(
            s.was_welcomed("did:plc:x").is_err(),
            "was_welcomed must propagate a table-missing error"
        );
        assert!(
            s.resume_claim("did:plc:x").is_err(),
            "resume_claim must propagate a table-missing error"
        );
    }

    #[test]
    fn is_empty_flips_after_first_handled_row() {
        // S5: a fresh store is empty (drives the first-run full backfill); once any
        // row exists it's no longer a first run.
        let s = mem();
        assert!(s.is_empty().unwrap(), "a fresh store is a first run");
        s.record_intent("did:plc:first", Some("f.test")).unwrap();
        assert!(
            !s.is_empty().unwrap(),
            "after the first handled row it is no longer a first run"
        );
    }

    #[test]
    fn mint_log_counts_within_window() {
        let s = mem();
        assert_eq!(s.count_mints_since(86_400).unwrap(), 0);
        s.record_mint("did:plc:a").unwrap();
        s.record_mint("did:plc:b").unwrap();
        assert_eq!(s.count_mints_since(86_400).unwrap(), 2);
        // A zero-width window (cutoff == now) still counts mints stamped this second.
        assert_eq!(s.count_mints_since(0).unwrap(), 2);
    }
}
