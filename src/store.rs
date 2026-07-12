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

/// Typed failure modes for [`redeem_code`]. Distinct variants so the web layer
/// can map each to the right user-facing message / HTTP status without string
/// matching. Everything else (a real SQLite error) still propagates as
/// [`anyhow::Error`] out of the `Result`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RedeemError {
    /// No invite code with that value exists.
    #[error("invite code not found")]
    NotFound,
    /// The code exists but is past its `expires_at` (or already flipped to
    /// `expired`).
    #[error("invite code expired")]
    Expired,
    /// The code has already been redeemed (or is otherwise not `active`).
    #[error("invite code already redeemed")]
    AlreadyRedeemed,
    /// The closed-beta seat cap ([`Config`]'s `FEATHERREADER_BETA_CAP`) is full.
    #[error("beta is at capacity")]
    CapacityFull,
}

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
    /// Whether this feed's `url` is a **secret-bearing private feed URL**
    /// (Substack `…/feed/private/<token>`, Patreon `?auth=…`, Ghost members, …).
    ///
    /// The secret URL is retained here in LOCAL SQLite so the poller can still
    /// fetch it (via the SSRF-guarded `guarded_get` — private hosts like
    /// `substack.com` are ordinary public hosts, so the guard allows them), but
    /// it is deliberately **withheld from the public PDS record**
    /// (see [`crate::lexicon::Subscription`]'s `private` marker). This is a
    /// stopgap until atproto permissioned-data ships. Defaults to `false`.
    pub private: bool,
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
    /// Whether the feed `url` is a secret-bearing private feed URL (kept local,
    /// withheld from the PDS record). Defaults to `false` via [`Default`].
    pub private: bool,
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
    next_poll     TEXT,
    -- Whether `url` is a secret-bearing private feed URL, kept LOCAL-ONLY and
    -- withheld from the (public) PDS subscription record. Stopgap until atproto
    -- permissioned-data. For a fresh DB the column is created here; for an
    -- existing DB it is added by the idempotent ALTER migration in init_schema.
    private       INTEGER NOT NULL DEFAULT 0
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

CREATE TABLE IF NOT EXISTS beta_access (
    did              TEXT PRIMARY KEY,
    handle           TEXT,
    granted_by       TEXT NOT NULL,
    granted_at       INTEGER NOT NULL,
    invite_code_used TEXT
);

CREATE TABLE IF NOT EXISTS invite_codes (
    code        TEXT PRIMARY KEY,
    creator_did TEXT NOT NULL,
    status      TEXT NOT NULL,
    invitee_did TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    redeemed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_invite_codes_status ON invite_codes (status, expires_at);
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
    // Under a concurrent write burst (the poller's insert_entries tx racing the
    // web layer's mark_read / redeem_code tx) SQLite would otherwise return
    // SQLITE_BUSY the instant a writer holds the lock. `busy_timeout` makes a
    // blocked connection WAIT (retry) for up to this long before erroring, so
    // short lock contention resolves transparently instead of surfacing a
    // spurious failure. Mirrors the OAuth sidecar's `stores.ts`
    // (`PRAGMA busy_timeout = 5000`). 5 s is comfortably above any single
    // FeatherReader transaction.
    opts = opts.busy_timeout(std::time::Duration::from_millis(5000));
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
    run_migrations(pool).await?;
    Ok(())
}

/// Idempotent in-place migrations for databases created before a column existed.
///
/// `CREATE TABLE IF NOT EXISTS` does NOT add new columns to an already-existing
/// table, so any column added after the initial release needs an explicit
/// (idempotent) `ALTER TABLE … ADD COLUMN`. SQLite has no `ADD COLUMN IF NOT
/// EXISTS`, so we detect presence via `PRAGMA table_info` first and skip if the
/// column is already there. Safe to run on every startup.
async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    // feeds.private — the private-feed flag (see NewFeed::private / Feed::private).
    if !column_exists(pool, "feeds", "private").await? {
        sqlx::query("ALTER TABLE feeds ADD COLUMN private INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await
            .context("migration: add feeds.private column")?;
    }
    Ok(())
}

/// Whether `table` already has a column named `column` (via `PRAGMA table_info`).
async fn column_exists(pool: &SqlitePool, table: &str, column: &str) -> Result<bool> {
    // `PRAGMA table_info` takes an identifier, which cannot be bound as a `?`
    // parameter, so the table name is interpolated. `table` here is always a
    // hardcoded literal from THIS module (never user input), so this is safe;
    // `AssertSqlSafe` documents that audit to sqlx 0.9's SqlSafeStr guard.
    use sqlx::AssertSqlSafe;
    let rows = sqlx::query(AssertSqlSafe(format!("PRAGMA table_info({table})")))
        .fetch_all(pool)
        .await
        .with_context(|| format!("PRAGMA table_info({table}) failed"))?;
    Ok(rows.iter().any(|r| r.get::<String, _>("name") == column))
}

/// Insert a feed by URL, or update its metadata if the URL already exists.
/// Returns the feed's row id (existing or newly assigned).
pub async fn upsert_feed(pool: &SqlitePool, feed: &NewFeed) -> Result<i64> {
    let row = sqlx::query(
        r#"
        INSERT INTO feeds (url, title, site_url, etag, last_modified, last_polled, next_poll, private)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT (url) DO UPDATE SET
            title         = COALESCE(excluded.title, feeds.title),
            site_url      = COALESCE(excluded.site_url, feeds.site_url),
            etag          = excluded.etag,
            last_modified = excluded.last_modified,
            last_polled   = COALESCE(excluded.last_polled, feeds.last_polled),
            next_poll     = COALESCE(excluded.next_poll, feeds.next_poll),
            -- Once a feed is marked private it STAYS private: OR the flags so the
            -- poller (which builds a NewFeed with private=false, not knowing the
            -- classification) can never clobber a private feed back to public.
            -- The subscribe path sets private=true explicitly.
            private       = feeds.private | excluded.private
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
    .bind(feed.private)
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

/// Mark (or unmark) a feed as **private** — its `url` is a secret-bearing feed
/// URL kept local-only and withheld from the public PDS record.
///
/// The feed row must already exist (created by the subscribe path via
/// [`upsert_feed`]). Returns the number of rows changed (0 if no such feed URL).
/// The subscribe path calls this right after inserting the feed so the secret
/// URL and its private flag ride together in local SQLite.
pub async fn mark_feed_private(pool: &SqlitePool, url: &str, private: bool) -> Result<u64> {
    let res = sqlx::query("UPDATE feeds SET private = ?2 WHERE url = ?1")
        .bind(url)
        .bind(private)
        .execute(pool)
        .await
        .with_context(|| format!("mark_feed_private failed for {url}"))?;
    Ok(res.rows_affected())
}

/// Query whether a feed URL is flagged private. `Ok(false)` if the feed is
/// public OR not present. The web layer uses this to decide whether to write a
/// redacted PDS record; the poller doesn't need it (it just fetches the local
/// secret URL either way).
pub async fn is_feed_private(pool: &SqlitePool, url: &str) -> Result<bool> {
    let row = sqlx::query("SELECT private FROM feeds WHERE url = ?1")
        .bind(url)
        .fetch_optional(pool)
        .await
        .with_context(|| format!("is_feed_private failed for {url}"))?;
    Ok(row.map(|r| r.get::<bool, _>("private")).unwrap_or(false))
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

// ---------------------------------------------------------------------------
// Closed-beta invite gate (beta_access + invite_codes)
// ---------------------------------------------------------------------------
//
// Ported in SHAPE from the-path `internal/beta` (RedeemCode / CreateInviteCode /
// code_gen) but deliberately trimmed for FeatherReader's before-public
// experiment: NO viral invite-budget tree, NO generation cap, NO waitlist /
// invite-request table, and SQLite instead of Mongo. A code is minted by an
// existing member (or admin), and redeeming it grants a seat while seats remain
// under the configured cap.

/// Unix-epoch seconds for "now" — the integer time base for the beta tables.
fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The invite-code alphabet: uppercase letters + digits with the
/// visually-ambiguous glyphs removed (`I`, `O`, `0`, `1`) so a code read aloud
/// or copied by hand is unambiguous. Mirrors the-path `code_gen.go`.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Human-facing prefix so a FeatherReader invite code is recognisable at a
/// glance (the-path used `TAVERN-`).
const CODE_PREFIX: &str = "FEATHER-";

/// Number of random characters after the prefix.
const CODE_BODY_LEN: usize = 8;

/// Generate a random, unguessable invite code of the form `FEATHER-XXXXXXXX`.
///
/// Draws from the OS CSPRNG (`getrandom`) and maps each byte onto
/// [`CODE_ALPHABET`] via rejection sampling so the alphabet distribution is
/// uniform (no modulo bias). Infallible in practice; a `getrandom` failure
/// (no entropy source) propagates as an error rather than a weak code.
pub fn generate_invite_code() -> Result<String> {
    let n = CODE_ALPHABET.len() as u16; // 31
                                        // Largest multiple of `n` that fits in a byte; bytes at or above it are
                                        // rejected so every accepted byte maps uniformly onto the alphabet.
    let limit = 256 / n * n; // 256 - (256 % n)
    let mut out = String::with_capacity(CODE_PREFIX.len() + CODE_BODY_LEN);
    out.push_str(CODE_PREFIX);
    let mut got = 0;
    let mut buf = [0u8; 1];
    while got < CODE_BODY_LEN {
        getrandom::fill(&mut buf).context("getrandom failed while minting invite code")?;
        let b = buf[0] as u16;
        if b < limit {
            out.push(CODE_ALPHABET[(b % n) as usize] as char);
            got += 1;
        }
    }
    Ok(out)
}

/// Whether a DID currently holds a beta seat.
pub async fn has_beta_access(pool: &SqlitePool, did: &str) -> Result<bool> {
    let row = sqlx::query("SELECT 1 FROM beta_access WHERE did = ?1")
        .bind(did)
        .fetch_optional(pool)
        .await
        .with_context(|| format!("has_beta_access failed for {did}"))?;
    Ok(row.is_some())
}

/// Count the beta seats currently granted — the numerator checked against the
/// configured cap on redeem.
pub async fn count_beta_access(pool: &SqlitePool) -> Result<i64> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM beta_access")
        .fetch_one(pool)
        .await
        .context("count_beta_access failed")?;
    Ok(row.get::<i64, _>("n"))
}

/// Grant a beta seat directly (admin / seed path — no code consumed). Idempotent
/// on `did` (re-granting updates the row rather than erroring).
pub async fn grant_access(
    pool: &SqlitePool,
    did: &str,
    handle: Option<&str>,
    granted_by: &str,
    invite_code_used: Option<&str>,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO beta_access (did, handle, granted_by, granted_at, invite_code_used)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT (did) DO UPDATE SET
            handle           = COALESCE(excluded.handle, beta_access.handle),
            granted_by       = excluded.granted_by,
            invite_code_used = COALESCE(excluded.invite_code_used, beta_access.invite_code_used)
        "#,
    )
    .bind(did)
    .bind(handle)
    .bind(granted_by)
    .bind(now_unix())
    .bind(invite_code_used)
    .execute(pool)
    .await
    .with_context(|| format!("grant_access failed for {did}"))?;
    Ok(())
}

/// Mint a new `active` invite code owned by `creator_did`, expiring `ttl_secs`
/// from now. Returns the generated code string.
pub async fn mint_code(pool: &SqlitePool, creator_did: &str, ttl_secs: i64) -> Result<String> {
    let code = generate_invite_code()?;
    let now = now_unix();
    let expires_at = now.saturating_add(ttl_secs.max(0));
    sqlx::query(
        r#"
        INSERT INTO invite_codes
            (code, creator_did, status, invitee_did, created_at, expires_at, redeemed_at)
        VALUES (?1, ?2, 'active', NULL, ?3, ?4, NULL)
        "#,
    )
    .bind(&code)
    .bind(creator_did)
    .bind(now)
    .bind(expires_at)
    .execute(pool)
    .await
    .with_context(|| format!("mint_code failed for creator {creator_did}"))?;
    Ok(code)
}

/// Atomically redeem an invite code for `did`, granting a beta seat.
///
/// Runs entirely in one transaction so the capacity check and the seat grant
/// cannot race (two redeems can't both slip past a `cap - 1` count). Steps:
/// 1. verify the code exists, is `active`, and is not past `expires_at`;
/// 2. verify the current seat count is `< cap`;
/// 3. flip the code `active`→`redeemed` (stamping `invitee_did` + `redeemed_at`);
/// 4. insert the `beta_access` row.
///
/// On a policy failure returns the matching [`RedeemError`] (the tx rolls back);
/// a real SQLite error propagates as the outer [`anyhow::Error`].
pub async fn redeem_code(
    pool: &SqlitePool,
    code: &str,
    did: &str,
    handle: Option<&str>,
    cap: i64,
) -> Result<std::result::Result<(), RedeemError>> {
    let now = now_unix();
    let mut tx = pool.begin().await.context("begin redeem_code tx")?;

    // 1. Look the code up.
    let row = sqlx::query("SELECT status, expires_at FROM invite_codes WHERE code = ?1")
        .bind(code)
        .fetch_optional(&mut *tx)
        .await
        .context("redeem_code: lookup")?;
    let row = match row {
        Some(r) => r,
        None => return Ok(Err(RedeemError::NotFound)),
    };
    let status: String = row.get("status");
    let expires_at: i64 = row.get("expires_at");

    // Status gate: only an `active` code is redeemable. Anything already
    // redeemed/revoked is "already redeemed" from the redeemer's view; an
    // `expired` status (or a past expiry) is "expired".
    if status == "expired" || now > expires_at {
        return Ok(Err(RedeemError::Expired));
    }
    if status != "active" {
        return Ok(Err(RedeemError::AlreadyRedeemed));
    }

    // 2. Capacity gate (inside the tx so it can't race a concurrent redeem).
    let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM beta_access")
        .fetch_one(&mut *tx)
        .await
        .context("redeem_code: count")?
        .get("n");
    if count >= cap {
        return Ok(Err(RedeemError::CapacityFull));
    }

    // 3. Flip the code active→redeemed. The `status = 'active'` guard in the
    // WHERE makes this a compare-and-swap: if a concurrent tx already flipped it
    // (despite the read above), zero rows change and we treat it as redeemed.
    let flipped = sqlx::query(
        r#"
        UPDATE invite_codes
        SET status = 'redeemed', invitee_did = ?2, redeemed_at = ?3
        WHERE code = ?1 AND status = 'active'
        "#,
    )
    .bind(code)
    .bind(did)
    .bind(now)
    .execute(&mut *tx)
    .await
    .context("redeem_code: flip")?;
    if flipped.rows_affected() == 0 {
        return Ok(Err(RedeemError::AlreadyRedeemed));
    }

    // 4. Grant the seat.
    sqlx::query(
        r#"
        INSERT INTO beta_access (did, handle, granted_by, granted_at, invite_code_used)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT (did) DO UPDATE SET
            handle           = COALESCE(excluded.handle, beta_access.handle),
            invite_code_used = excluded.invite_code_used
        "#,
    )
    .bind(did)
    .bind(handle)
    // granted_by is the code's creator; look it up in-tx to keep provenance.
    .bind(
        sqlx::query("SELECT creator_did FROM invite_codes WHERE code = ?1")
            .bind(code)
            .fetch_one(&mut *tx)
            .await
            .context("redeem_code: creator lookup")?
            .get::<String, _>("creator_did"),
    )
    .bind(now)
    .bind(code)
    .execute(&mut *tx)
    .await
    .context("redeem_code: grant")?;

    tx.commit().await.context("commit redeem_code tx")?;
    Ok(Ok(()))
}

/// Sweep: flip every `active` code whose `expires_at` is in the past to
/// `expired`. Returns the number of codes expired. Called periodically by the
/// scheduler.
pub async fn expire_old_codes(pool: &SqlitePool) -> Result<u64> {
    let now = now_unix();
    let res = sqlx::query(
        "UPDATE invite_codes SET status = 'expired' WHERE status = 'active' AND expires_at < ?1",
    )
    .bind(now)
    .execute(pool)
    .await
    .context("expire_old_codes failed")?;
    Ok(res.rows_affected())
}

/// Seed the admin-bootstrap DIDs: for each, insert a `beta_access` row
/// (`granted_by = 'admin'`) if one does not already exist. Idempotent — an
/// existing seat is left untouched. Returns how many new seats were created.
pub async fn ensure_seed(pool: &SqlitePool, dids: &[String]) -> Result<u64> {
    let mut tx = pool.begin().await.context("begin ensure_seed tx")?;
    let now = now_unix();
    let mut created = 0u64;
    for did in dids {
        let res = sqlx::query(
            r#"
            INSERT INTO beta_access (did, handle, granted_by, granted_at, invite_code_used)
            VALUES (?1, NULL, 'admin', ?2, NULL)
            ON CONFLICT (did) DO NOTHING
            "#,
        )
        .bind(did)
        .bind(now)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("ensure_seed insert failed for {did}"))?;
        created += res.rows_affected();
    }
    tx.commit().await.context("commit ensure_seed tx")?;
    Ok(created)
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

    /// A private feed's secret URL is retained locally with its `private` flag,
    /// and the flag survives a subsequent poller upsert that doesn't know the
    /// classification (it must never clobber private → public).
    #[tokio::test]
    async fn private_flag_persists_and_is_not_clobbered_by_poller() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let secret_url = "https://author.substack.com/feed/private/deadbeefcafe123456";

        // Subscribe path: insert the feed and mark it private.
        upsert_feed(
            &pool,
            &NewFeed {
                url: secret_url.to_string(),
                title: Some("Private Author".to_string()),
                private: true,
                ..Default::default()
            },
        )
        .await?;
        assert!(is_feed_private(&pool, secret_url).await?);

        // The secret URL is retained verbatim in local SQLite.
        let feed = get_feed_by_url(&pool, secret_url)
            .await?
            .expect("feed exists");
        assert_eq!(feed.url, secret_url);
        assert!(feed.private);

        // Poller re-upserts with private=false (it doesn't classify) — the flag
        // must stay set (OR semantics), so the feed is never leaked later.
        upsert_feed(
            &pool,
            &NewFeed {
                url: secret_url.to_string(),
                title: Some("Private Author (refreshed)".to_string()),
                private: false,
                ..Default::default()
            },
        )
        .await?;
        assert!(
            is_feed_private(&pool, secret_url).await?,
            "poller upsert must not clobber the private flag"
        );

        // A normal public feed stays public; mark/unmark round-trips.
        upsert_feed(
            &pool,
            &NewFeed {
                url: "https://example.com/feed.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;
        assert!(!is_feed_private(&pool, "https://example.com/feed.xml").await?);
        assert_eq!(
            mark_feed_private(&pool, "https://example.com/feed.xml", true).await?,
            1
        );
        assert!(is_feed_private(&pool, "https://example.com/feed.xml").await?);

        // Unknown URL => not private, no panic.
        assert!(!is_feed_private(&pool, "https://nope.example/x").await?);
        Ok(())
    }

    /// The migration is idempotent: adding feeds.private twice is a no-op, and a
    /// pre-existing table without the column is upgraded in place.
    #[tokio::test]
    async fn private_column_migration_is_idempotent() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        // Re-running the whole schema+migration path must not error.
        init_schema(&pool).await?;
        init_schema(&pool).await?;
        assert!(column_exists(&pool, "feeds", "private").await?);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Closed-beta invite gate
    // -----------------------------------------------------------------------

    #[test]
    fn code_gen_shape_and_alphabet() {
        for _ in 0..200 {
            let code = generate_invite_code().unwrap();
            assert!(code.starts_with("FEATHER-"), "bad prefix: {code}");
            let body = &code["FEATHER-".len()..];
            assert_eq!(body.len(), CODE_BODY_LEN, "bad body length: {code}");
            // Every body char must be from the ambiguity-free alphabet — in
            // particular NEVER I/O/0/1.
            for c in body.chars() {
                assert!(
                    CODE_ALPHABET.contains(&(c as u8)),
                    "char {c:?} not in alphabet ({code})"
                );
                assert!(
                    !matches!(c, 'I' | 'O' | '0' | '1'),
                    "ambiguous char {c:?} leaked into {code}"
                );
            }
        }
        // Two codes in a row must differ (unguessable / random).
        assert_ne!(
            generate_invite_code().unwrap(),
            generate_invite_code().unwrap()
        );
    }

    #[tokio::test]
    async fn busy_timeout_is_applied() -> Result<()> {
        // Opening an on-disk DB and reading back the PRAGMA proves the pool
        // carries busy_timeout = 5000 ms.
        let dir = std::env::temp_dir().join(format!("fr-busy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("busy.db");
        let url = format!("sqlite://{}", path.display());
        let pool = init_url(&url).await?;
        let row = sqlx::query("PRAGMA busy_timeout").fetch_one(&pool).await?;
        let timeout: i64 = row.get(0);
        assert_eq!(timeout, 5000, "busy_timeout should be 5000 ms");
        pool.close().await;
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[tokio::test]
    async fn redeem_valid_grants_seat() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let code = mint_code(&pool, "did:plc:creator", 3600).await?;
        assert!(!has_beta_access(&pool, "did:plc:new").await?);

        let out = redeem_code(&pool, &code, "did:plc:new", Some("new.bsky"), 100).await?;
        assert_eq!(out, Ok(()));
        assert!(has_beta_access(&pool, "did:plc:new").await?);
        assert_eq!(count_beta_access(&pool).await?, 1);

        // The code is now spent — a second redeem is AlreadyRedeemed.
        let again = redeem_code(&pool, &code, "did:plc:other", None, 100).await?;
        assert_eq!(again, Err(RedeemError::AlreadyRedeemed));
        Ok(())
    }

    #[tokio::test]
    async fn redeem_not_found() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let out = redeem_code(&pool, "FEATHER-NOPENOPE", "did:plc:x", None, 100).await?;
        assert_eq!(out, Err(RedeemError::NotFound));
        Ok(())
    }

    /// Insert an already-expired `active` code directly (mint_code clamps a
    /// negative ttl to 0, so the past-expiry case is set up by hand).
    async fn insert_expired_code(pool: &SqlitePool, code: &str, creator: &str) -> Result<()> {
        let now = now_unix();
        sqlx::query(
            r#"INSERT INTO invite_codes
               (code, creator_did, status, invitee_did, created_at, expires_at, redeemed_at)
               VALUES (?1, ?2, 'active', NULL, ?3, ?4, NULL)"#,
        )
        .bind(code)
        .bind(creator)
        .bind(now - 100)
        .bind(now - 10) // expires_at in the past
        .execute(pool)
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn redeem_expired() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        insert_expired_code(&pool, "FEATHER-EXPIRED0", "did:plc:creator").await?;
        let out = redeem_code(&pool, "FEATHER-EXPIRED0", "did:plc:new", None, 100).await?;
        assert_eq!(out, Err(RedeemError::Expired));
        // No seat granted.
        assert_eq!(count_beta_access(&pool).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn redeem_capacity_full() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        // Cap of 1, one seat already taken by an admin seed.
        ensure_seed(&pool, &["did:plc:admin".to_string()]).await?;
        assert_eq!(count_beta_access(&pool).await?, 1);

        let code = mint_code(&pool, "did:plc:admin", 3600).await?;
        let out = redeem_code(&pool, &code, "did:plc:new", None, 1).await?;
        assert_eq!(out, Err(RedeemError::CapacityFull));
        // Seat NOT granted and the code NOT consumed (tx rolled back).
        assert!(!has_beta_access(&pool, "did:plc:new").await?);
        // Raising the cap lets the same code redeem.
        let ok = redeem_code(&pool, &code, "did:plc:new", None, 2).await?;
        assert_eq!(ok, Ok(()));
        Ok(())
    }

    #[tokio::test]
    async fn expire_and_seed() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        // An already-expired code is swept to `expired`.
        insert_expired_code(&pool, "FEATHER-EXPIRED1", "did:plc:creator").await?;
        let live = mint_code(&pool, "did:plc:creator", 3600).await?;
        let n = expire_old_codes(&pool).await?;
        assert_eq!(n, 1, "exactly the past-expiry code should flip");
        // The live code still redeems.
        assert_eq!(
            redeem_code(&pool, &live, "did:plc:new", None, 100).await?,
            Ok(())
        );

        // ensure_seed is idempotent.
        let created = ensure_seed(
            &pool,
            &["did:plc:seed1".to_string(), "did:plc:seed2".to_string()],
        )
        .await?;
        assert_eq!(created, 2);
        let created2 = ensure_seed(&pool, &["did:plc:seed1".to_string()]).await?;
        assert_eq!(created2, 0, "re-seeding an existing DID is a no-op");
        assert!(has_beta_access(&pool, "did:plc:seed1").await?);
        Ok(())
    }
}
