//! The bot's local idempotency store — one SQLite file on the bot host.
//!
//! Keyed on the follower DID so unfollow→refollow never re-posts (the DID, not
//! the follow event, is the unit of work). The mint+post step records INTENT
//! FIRST (`status='minting'`) so a crash mid-way resumes delivery on the next
//! poll rather than minting a second code / posting a second skeet.

use anyhow::{Context, Result};
use rusqlite::Connection;

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
                created_at   INTEGER NOT NULL,
                delivered_at INTEGER
            );
            "#,
        )
        .context("create bot schema")?;
        Ok(Self { conn })
    }

    /// Whether this DID has reached a TERMINAL state (`delivered` or `skipped`) —
    /// i.e. there is nothing left to do for it. The poll loop treats a terminal
    /// DID as "caught up"; a non-terminal `minting` row is deliberately NOT
    /// terminal, so a follower whose mint/post was interrupted is picked up again
    /// and resumed (rather than silently stranded forever).
    pub fn is_terminal(&self, did: &str) -> Result<bool> {
        let status: Option<String> = self
            .conn
            .query_row("SELECT status FROM handled WHERE did = ?1", [did], |r| {
                r.get(0)
            })
            .ok();
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
            .ok();
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
            .ok();
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
}
