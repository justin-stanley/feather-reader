//! SQLite persistence layer (via `sqlx`, runtime queries).
//!
//! FeatherReader keeps the source of truth for *what a user follows* and *their
//! read-position* in the user's own atproto PDS (see the design doc,
//! `community.lexicon.rss.*`). This module is the **local per-DID cache + debounce
//! buffer**: a single SQLite file that holds
//!
//! * `feeds` + `entries` — a shared cache of feed metadata and articles, keyed by
//!   feed URL / feed-native GUID and **shared across every DID** that follows the
//!   same feed (many users on one instance don't multiply fetch load), and
//! * `entry_state` + `read_cursor` — per-DID read/star state and the per-feed
//!   read cursor that the (v1.1) batched flusher syncs up to the PDS.
//!
//! All queries here are **runtime** queries (`sqlx::query` / `sqlx::query_as`),
//! not the compile-time `query!` macros — so the crate builds with no
//! `DATABASE_URL` and no offline metadata. Schema creation is idempotent
//! (`CREATE TABLE IF NOT EXISTS`) and runs inside [`init`].
//!
//! Errors propagate as [`anyhow::Result`]; nothing in the non-test paths panics.

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::{ConnectOptions, FromRow, Row};
use std::str::FromStr;

use crate::config::Config;

/// The SQLite connection pool type the rest of the crate refers to as
/// [`Pool`]. A thin alias over [`SqlitePool`] so [`crate::AppState`] and the web
/// layer name one stable type; if the backend ever changes, this is the single
/// place to swap it.
pub type Pool = SqlitePool;

/// A cached syndication feed, shared across all DIDs that subscribe to its URL.
///
/// This mirrors the PDS-side `community.lexicon.rss.subscription.url`; the row is
/// created/updated by the poller, never owned by a single user.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct Feed {
    pub id: i64,
    pub url: String,
    pub title: Option<String>,
    pub site_url: Option<String>,
    /// HTTP `ETag` from the last successful fetch, for conditional GET.
    pub etag: Option<String>,
    /// HTTP `Last-Modified` from the last successful fetch, for conditional GET.
    pub last_modified: Option<String>,
    /// When we last polled this feed (RFC3339), or `None` if never.
    pub last_polled: Option<String>,
    /// When this feed is next due to be polled (RFC3339), or `None`.
    pub next_poll: Option<String>,
}

/// A cached article/item belonging to a [`Feed`]. Shared cache (not per-DID).
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct Entry {
    pub id: i64,
    pub feed_id: i64,
    /// Feed-native GUID/id, unique within a feed (used for dedup on re-fetch).
    pub guid: String,
    pub url: Option<String>,
    pub title: Option<String>,
    pub author: Option<String>,
    /// Publication time as reported by the feed (RFC3339), or `None`.
    pub published: Option<String>,
    /// Article body HTML, **already sanitized** (ammonia) before it reaches here.
    pub content_html: Option<String>,
    /// When FeatherReader first fetched/stored this entry (RFC3339).
    pub fetched_at: String,
}

/// Per-`(did, entry)` read/star state — the fast in-session working copy that the
/// batched flusher later syncs to the PDS as a per-feed read cursor.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct EntryState {
    pub did: String,
    pub entry_id: i64,
    pub read: bool,
    pub starred: bool,
    pub updated_at: String,
}

/// Per-`(did, feed_url)` read cursor — the local mirror of the PDS
/// `community.lexicon.rss.readState` record plus flush bookkeeping.
///
/// `read_ids` / `unread_ids` are stored as JSON arrays of entry ids (the two
/// bounded exception sets around the `read_through` high-water-mark); `dirty`
/// marks that local `entry_state` has changed since the last PDS flush.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct ReadCursor {
    pub did: String,
    pub feed_url: String,
    /// High-water-mark (RFC3339): every entry seen/published `<=` this is read.
    pub read_through: Option<String>,
    /// JSON array of entry ids newer than `read_through` that are also read.
    pub read_ids: String,
    /// JSON array of entry ids older than `read_through` explicitly kept unread.
    pub unread_ids: String,
    /// Set when `entry_state` changed since the last flush (debounce trigger).
    pub dirty: bool,
    pub updated_at: String,
}

/// New-feed payload for [`upsert_feed`] (id is assigned by SQLite).
#[derive(Debug, Clone, Default)]
pub struct NewFeed {
    pub url: String,
    pub title: Option<String>,
    pub site_url: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub last_polled: Option<String>,
    pub next_poll: Option<String>,
}

/// New-entry payload for [`insert_entries`] (id is assigned by SQLite,
/// `fetched_at` defaults to "now" when not supplied).
#[derive(Debug, Clone, Default)]
pub struct NewEntry {
    pub guid: String,
    pub url: Option<String>,
    pub title: Option<String>,
    pub author: Option<String>,
    pub published: Option<String>,
    /// Already-sanitized HTML.
    pub content_html: Option<String>,
    /// Optional explicit fetch time (RFC3339); defaults to now if `None`.
    pub fetched_at: Option<String>,
}

/// The SQLite schema. Idempotent — safe to run on every startup.
///
/// `feeds`/`entries` are the shared cache; `entry_state`/`read_cursor` are
/// per-DID. Indices cover the scheduler's due-feed query, the read/unread list
/// query, and the flusher's dirty-cursor scan.
const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS feeds (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT NOT NULL UNIQUE,
    title         TEXT,
    site_url      TEXT,
    etag          TEXT,
    last_modified TEXT,
    last_polled   TEXT,
    next_poll     TEXT
);
CREATE INDEX IF NOT EXISTS idx_feeds_next_poll ON feeds (next_poll);

CREATE TABLE IF NOT EXISTS entries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_id      INTEGER NOT NULL REFERENCES feeds (id) ON DELETE CASCADE,
    guid         TEXT NOT NULL,
    url          TEXT,
    title        TEXT,
    author       TEXT,
    published    TEXT,
    content_html TEXT,
    fetched_at   TEXT NOT NULL,
    UNIQUE (feed_id, guid)
);
CREATE INDEX IF NOT EXISTS idx_entries_feed_published ON entries (feed_id, published);

CREATE TABLE IF NOT EXISTS entry_state (
    did        TEXT NOT NULL,
    entry_id   INTEGER NOT NULL REFERENCES entries (id) ON DELETE CASCADE,
    read       INTEGER NOT NULL DEFAULT 0,
    starred    INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (did, entry_id)
);
CREATE INDEX IF NOT EXISTS idx_entry_state_did_read ON entry_state (did, read);

CREATE TABLE IF NOT EXISTS read_cursor (
    did          TEXT NOT NULL,
    feed_url     TEXT NOT NULL,
    read_through TEXT,
    read_ids     TEXT NOT NULL DEFAULT '[]',
    unread_ids   TEXT NOT NULL DEFAULT '[]',
    dirty        INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (did, feed_url)
);
CREATE INDEX IF NOT EXISTS idx_read_cursor_dirty ON read_cursor (did, dirty);
"#;

/// RFC3339 timestamp for "now" (UTC, seconds precision), used as the default for
/// `*_at` columns. Uses `chrono` to match the shape written by [`crate::feed`]
/// and [`crate::web`] (one timestamp format across the whole crate).
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Open the per-DID SQLite cache described by [`Config`] (its `db_path`), run
/// schema creation, and return the pool.
///
/// This is the entrypoint `main` calls: it derives the sqlx SQLite URL from the
/// configured filesystem path and delegates to [`init_url`]. Kept separate from
/// [`init_url`] so tests can open an in-memory database directly.
pub async fn init(config: &Config) -> Result<Pool> {
    // sqlx wants a `sqlite://<path>` URL; build it from the configured path.
    let db_url = format!("sqlite://{}", config.db_path.display());
    init_url(&db_url).await
}

/// Open (creating if needed) the SQLite database at `db_url`, run schema
/// creation, and return a connection pool.
///
/// `db_url` is a sqlx SQLite URL, e.g. `sqlite://featherreader.db` or
/// `sqlite::memory:` for an ephemeral in-memory database. The file is created
/// if it does not exist; WAL journaling is enabled for on-disk databases and
/// foreign keys are enforced on every connection.
pub async fn init_url(db_url: &str) -> Result<Pool> {
    let mut opts = SqliteConnectOptions::from_str(db_url)
        .with_context(|| format!("invalid sqlite url: {db_url}"))?
        .create_if_missing(true)
        .foreign_keys(true);
    // WAL is a no-op / unsupported for :memory:, so only request it on-disk.
    if !db_url.contains(":memory:") {
        opts = opts.journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    }
    // Quiet sqlx's per-statement query logging.
    opts = opts.log_statements(tracing::log::LevelFilter::Debug);

    let pool = SqlitePoolOptions::new()
        // Keep at least one connection alive so an in-memory DB isn't dropped
        // (each `:memory:` connection is a *separate* database otherwise).
        .min_connections(1)
        .max_connections(5)
        .connect_with(opts)
        .await
        .with_context(|| format!("failed to open sqlite pool: {db_url}"))?;

    init_schema(&pool).await?;
    Ok(pool)
}

/// Run the idempotent schema creation. Split out so callers/tests can (re)apply
/// it against an already-open pool.
pub async fn init_schema(pool: &SqlitePool) -> Result<()> {
    // `execute` runs the multi-statement batch (sqlite allows this).
    sqlx::query(SCHEMA)
        .execute(pool)
        .await
        .context("failed to create schema")?;
    Ok(())
}

/// Insert a feed by URL, or update its metadata if the URL already exists.
/// Returns the feed's row id (existing or newly assigned).
pub async fn upsert_feed(pool: &SqlitePool, feed: &NewFeed) -> Result<i64> {
    let row = sqlx::query(
        r#"
        INSERT INTO feeds (url, title, site_url, etag, last_modified, last_polled, next_poll)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT (url) DO UPDATE SET
            title         = COALESCE(excluded.title, feeds.title),
            site_url      = COALESCE(excluded.site_url, feeds.site_url),
            etag          = excluded.etag,
            last_modified = excluded.last_modified,
            last_polled   = COALESCE(excluded.last_polled, feeds.last_polled),
            next_poll     = COALESCE(excluded.next_poll, feeds.next_poll)
        RETURNING id
        "#,
    )
    .bind(&feed.url)
    .bind(&feed.title)
    .bind(&feed.site_url)
    .bind(&feed.etag)
    .bind(&feed.last_modified)
    .bind(&feed.last_polled)
    .bind(&feed.next_poll)
    .fetch_one(pool)
    .await
    .with_context(|| format!("upsert_feed failed for {}", feed.url))?;

    Ok(row.get::<i64, _>("id"))
}

/// Fetch a feed by its URL, if present.
pub async fn get_feed_by_url(pool: &SqlitePool, url: &str) -> Result<Option<Feed>> {
    let feed = sqlx::query_as::<_, Feed>("SELECT * FROM feeds WHERE url = ?1")
        .bind(url)
        .fetch_optional(pool)
        .await
        .with_context(|| format!("get_feed_by_url failed for {url}"))?;
    Ok(feed)
}

/// The scheduler's hot query: feeds whose `next_poll` is due (`<= as_of`, or
/// never polled), oldest-due first. `as_of` is an RFC3339 timestamp.
pub async fn due_feeds(pool: &SqlitePool, as_of: &str, limit: i64) -> Result<Vec<Feed>> {
    let feeds = sqlx::query_as::<_, Feed>(
        r#"
        SELECT * FROM feeds
        WHERE next_poll IS NULL OR next_poll <= ?1
        ORDER BY next_poll IS NOT NULL, next_poll ASC
        LIMIT ?2
        "#,
    )
    .bind(as_of)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("due_feeds failed")?;
    Ok(feeds)
}

/// Insert a batch of entries for `feed_id`, deduping on `(feed_id, guid)`.
///
/// On a GUID collision the existing entry is updated in place (title/url/body
/// may have changed on re-fetch) rather than duplicated. Runs in one
/// transaction. Returns the number of rows processed.
pub async fn insert_entries(pool: &SqlitePool, feed_id: i64, entries: &[NewEntry]) -> Result<u64> {
    let mut tx = pool.begin().await.context("begin insert_entries tx")?;
    let mut count: u64 = 0;
    for e in entries {
        let fetched_at = e.fetched_at.clone().unwrap_or_else(now_rfc3339);
        let res = sqlx::query(
            r#"
            INSERT INTO entries
                (feed_id, guid, url, title, author, published, content_html, fetched_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT (feed_id, guid) DO UPDATE SET
                url          = excluded.url,
                title        = excluded.title,
                author       = excluded.author,
                published    = excluded.published,
                content_html = excluded.content_html
            "#,
        )
        .bind(feed_id)
        .bind(&e.guid)
        .bind(&e.url)
        .bind(&e.title)
        .bind(&e.author)
        .bind(&e.published)
        .bind(&e.content_html)
        .bind(&fetched_at)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("insert entry {} failed", e.guid))?;
        count += res.rows_affected();
    }
    tx.commit().await.context("commit insert_entries tx")?;
    Ok(count)
}

/// All entries for a feed, newest-published first.
pub async fn entries_for_feed(pool: &SqlitePool, feed_id: i64) -> Result<Vec<Entry>> {
    let entries = sqlx::query_as::<_, Entry>(
        "SELECT * FROM entries WHERE feed_id = ?1 ORDER BY published DESC, id DESC",
    )
    .bind(feed_id)
    .fetch_all(pool)
    .await
    .context("entries_for_feed failed")?;
    Ok(entries)
}

/// Mark a single entry read/unread for a DID, upserting the per-DID state row
/// and stamping `updated_at`. Preserves any existing `starred` bit.
pub async fn mark_read(pool: &SqlitePool, did: &str, entry_id: i64, read: bool) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO entry_state (did, entry_id, read, starred, updated_at)
        VALUES (?1, ?2, ?3, 0, ?4)
        ON CONFLICT (did, entry_id) DO UPDATE SET
            read       = excluded.read,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(did)
    .bind(entry_id)
    .bind(read)
    .bind(now_rfc3339())
    .execute(pool)
    .await
    .with_context(|| format!("mark_read failed for {did}/{entry_id}"))?;
    Ok(())
}

/// Star/unstar a single entry for a DID (upsert, preserving `read`).
pub async fn mark_starred(
    pool: &SqlitePool,
    did: &str,
    entry_id: i64,
    starred: bool,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO entry_state (did, entry_id, read, starred, updated_at)
        VALUES (?1, ?2, 0, ?3, ?4)
        ON CONFLICT (did, entry_id) DO UPDATE SET
            starred    = excluded.starred,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(did)
    .bind(entry_id)
    .bind(starred)
    .bind(now_rfc3339())
    .execute(pool)
    .await
    .with_context(|| format!("mark_starred failed for {did}/{entry_id}"))?;
    Ok(())
}

/// Mark every entry of a feed read (or unread) for a DID in one statement —
/// backs the "mark-all-read (per feed)" action.
pub async fn mark_feed_read(pool: &SqlitePool, did: &str, feed_id: i64, read: bool) -> Result<u64> {
    let now = now_rfc3339();
    let res = sqlx::query(
        r#"
        INSERT INTO entry_state (did, entry_id, read, starred, updated_at)
        SELECT ?1, e.id, ?2, 0, ?3 FROM entries e WHERE e.feed_id = ?4
        ON CONFLICT (did, entry_id) DO UPDATE SET
            read       = excluded.read,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(did)
    .bind(read)
    .bind(&now)
    .bind(feed_id)
    .execute(pool)
    .await
    .with_context(|| format!("mark_feed_read failed for {did}/feed {feed_id}"))?;
    Ok(res.rows_affected())
}

/// Unread entries for a DID: entries with no `entry_state` row for that DID, or
/// one where `read = 0`. Newest-published first. This is the daily-driver list
/// query, so it's a `LEFT JOIN` (an entry with no state row is unread).
pub async fn get_unread_for_did(pool: &SqlitePool, did: &str) -> Result<Vec<Entry>> {
    let entries = sqlx::query_as::<_, Entry>(
        r#"
        SELECT e.*
        FROM entries e
        LEFT JOIN entry_state s ON s.entry_id = e.id AND s.did = ?1
        WHERE COALESCE(s.read, 0) = 0
        ORDER BY e.published DESC, e.id DESC
        "#,
    )
    .bind(did)
    .fetch_all(pool)
    .await
    .with_context(|| format!("get_unread_for_did failed for {did}"))?;
    Ok(entries)
}

/// Starred entries for a DID, newest-published first.
pub async fn get_starred_for_did(pool: &SqlitePool, did: &str) -> Result<Vec<Entry>> {
    let entries = sqlx::query_as::<_, Entry>(
        r#"
        SELECT e.*
        FROM entries e
        JOIN entry_state s ON s.entry_id = e.id AND s.did = ?1
        WHERE s.starred = 1
        ORDER BY e.published DESC, e.id DESC
        "#,
    )
    .bind(did)
    .fetch_all(pool)
    .await
    .with_context(|| format!("get_starred_for_did failed for {did}"))?;
    Ok(entries)
}

/// Insert or update a per-`(did, feed_url)` read cursor, stamping `updated_at`.
/// Used both by the local mark-read path and by reconcile-on-login.
pub async fn upsert_cursor(pool: &SqlitePool, cursor: &ReadCursor) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO read_cursor
            (did, feed_url, read_through, read_ids, unread_ids, dirty, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT (did, feed_url) DO UPDATE SET
            read_through = excluded.read_through,
            read_ids     = excluded.read_ids,
            unread_ids   = excluded.unread_ids,
            dirty        = excluded.dirty,
            updated_at   = excluded.updated_at
        "#,
    )
    .bind(&cursor.did)
    .bind(&cursor.feed_url)
    .bind(&cursor.read_through)
    .bind(&cursor.read_ids)
    .bind(&cursor.unread_ids)
    .bind(cursor.dirty)
    .bind(&cursor.updated_at)
    .execute(pool)
    .await
    .with_context(|| {
        format!(
            "upsert_cursor failed for {}/{}",
            cursor.did, cursor.feed_url
        )
    })?;
    Ok(())
}

/// Fetch a single read cursor, if present.
pub async fn get_cursor(
    pool: &SqlitePool,
    did: &str,
    feed_url: &str,
) -> Result<Option<ReadCursor>> {
    let cursor = sqlx::query_as::<_, ReadCursor>(
        "SELECT * FROM read_cursor WHERE did = ?1 AND feed_url = ?2",
    )
    .bind(did)
    .bind(feed_url)
    .fetch_optional(pool)
    .await
    .context("get_cursor failed")?;
    Ok(cursor)
}

/// The flusher's hot query: every cursor with `dirty = 1` for a DID — the ones
/// whose read-state changed since the last batched PDS flush.
pub async fn dirty_cursors(pool: &SqlitePool, did: &str) -> Result<Vec<ReadCursor>> {
    let cursors =
        sqlx::query_as::<_, ReadCursor>("SELECT * FROM read_cursor WHERE did = ?1 AND dirty = 1")
            .bind(did)
            .fetch_all(pool)
            .await
            .with_context(|| format!("dirty_cursors failed for {did}"))?;
    Ok(cursors)
}

/// Clear the `dirty` flag on a cursor after a successful PDS flush.
pub async fn clear_cursor_dirty(pool: &SqlitePool, did: &str, feed_url: &str) -> Result<()> {
    sqlx::query("UPDATE read_cursor SET dirty = 0 WHERE did = ?1 AND feed_url = ?2")
        .bind(did)
        .bind(feed_url)
        .execute(pool)
        .await
        .context("clear_cursor_dirty failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Init an in-memory SQLite, insert a feed + entries, read them back.
    #[tokio::test]
    async fn init_insert_readback() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;

        // Insert a feed.
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://example.com/feed.xml".to_string(),
                title: Some("Example".to_string()),
                site_url: Some("https://example.com".to_string()),
                next_poll: Some("2026-07-12T00:00:00Z".to_string()),
                ..Default::default()
            },
        )
        .await?;
        assert!(feed_id > 0);

        // Read the feed back by URL.
        let feed = get_feed_by_url(&pool, "https://example.com/feed.xml")
            .await?
            .expect("feed should exist");
        assert_eq!(feed.id, feed_id);
        assert_eq!(feed.title.as_deref(), Some("Example"));
        assert_eq!(feed.site_url.as_deref(), Some("https://example.com"));

        // Upsert on the same URL updates rather than duplicating.
        let feed_id2 = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://example.com/feed.xml".to_string(),
                title: Some("Example (renamed)".to_string()),
                ..Default::default()
            },
        )
        .await?;
        assert_eq!(feed_id, feed_id2, "same URL must reuse the same row");

        // Insert two entries.
        let n = insert_entries(
            &pool,
            feed_id,
            &[
                NewEntry {
                    guid: "guid-1".to_string(),
                    url: Some("https://example.com/a".to_string()),
                    title: Some("First".to_string()),
                    published: Some("2026-07-10T08:00:00Z".to_string()),
                    content_html: Some("<p>hello</p>".to_string()),
                    ..Default::default()
                },
                NewEntry {
                    guid: "guid-2".to_string(),
                    url: Some("https://example.com/b".to_string()),
                    title: Some("Second".to_string()),
                    published: Some("2026-07-11T08:00:00Z".to_string()),
                    ..Default::default()
                },
            ],
        )
        .await?;
        assert_eq!(n, 2);

        // Read entries back (newest-published first).
        let entries = entries_for_feed(&pool, feed_id).await?;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].guid, "guid-2");
        assert_eq!(entries[1].guid, "guid-1");
        assert_eq!(entries[1].content_html.as_deref(), Some("<p>hello</p>"));

        // Re-inserting the same GUID dedups (updates in place, no new row).
        let n2 = insert_entries(
            &pool,
            feed_id,
            &[NewEntry {
                guid: "guid-1".to_string(),
                title: Some("First (edited)".to_string()),
                ..Default::default()
            }],
        )
        .await?;
        assert_eq!(n2, 1);
        assert_eq!(entries_for_feed(&pool, feed_id).await?.len(), 2);

        // --- per-DID read state ---
        let did = "did:plc:abc123";
        let e1 = entries.iter().find(|e| e.guid == "guid-1").unwrap().id;

        // Both entries start unread.
        assert_eq!(get_unread_for_did(&pool, did).await?.len(), 2);

        // Mark one read; unread count drops to 1.
        mark_read(&pool, did, e1, true).await?;
        let unread = get_unread_for_did(&pool, did).await?;
        assert_eq!(unread.len(), 1);
        assert_eq!(unread[0].guid, "guid-2");

        // Star it; it shows in the starred list.
        mark_starred(&pool, did, e1, true).await?;
        let starred = get_starred_for_did(&pool, did).await?;
        assert_eq!(starred.len(), 1);
        assert_eq!(starred[0].id, e1);

        // Mark-all-read clears the remaining unread.
        mark_feed_read(&pool, did, feed_id, true).await?;
        assert_eq!(get_unread_for_did(&pool, did).await?.len(), 0);

        // --- read cursor (batched-sync bookkeeping) ---
        let cursor = ReadCursor {
            did: did.to_string(),
            feed_url: "https://example.com/feed.xml".to_string(),
            read_through: Some("2026-07-11T08:00:00Z".to_string()),
            read_ids: "[]".to_string(),
            unread_ids: "[]".to_string(),
            dirty: true,
            updated_at: now_rfc3339(),
        };
        upsert_cursor(&pool, &cursor).await?;

        let fetched = get_cursor(&pool, did, "https://example.com/feed.xml")
            .await?
            .expect("cursor should exist");
        assert_eq!(
            fetched.read_through.as_deref(),
            Some("2026-07-11T08:00:00Z")
        );
        assert!(fetched.dirty);

        // The flusher sees exactly one dirty cursor.
        let dirty = dirty_cursors(&pool, did).await?;
        assert_eq!(dirty.len(), 1);

        // After a flush, clearing dirty removes it from the flusher's view.
        clear_cursor_dirty(&pool, did, "https://example.com/feed.xml").await?;
        assert_eq!(dirty_cursors(&pool, did).await?.len(), 0);

        Ok(())
    }
}
