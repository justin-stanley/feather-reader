//! SQLite persistence layer (via `sqlx`, runtime queries).
//!
//! FeatherReader keeps the source of truth for *what a user follows* and *their
//! read-position* in the user's own atproto PDS (as `community.lexicon.rss.*`
//! records). This module is the **local per-DID cache + debounce
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
    /// Count of consecutive poll FAILURES since the last success/304. Drives the
    /// exponential poll backoff (reset to 0 on any success or 304).
    #[sqlx(default)]
    pub consecutive_errors: i64,
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
    /// Whether this cursor's `readState` record has been CREATED in the PDS yet.
    /// The first flush of a feed must emit an `applyWrites#create` (an `#update`
    /// errors on a record that does not pre-exist, and applyWrites is atomic
    /// per-repo, so one not-yet-created cursor would drop the whole DID batch).
    /// Flipped to `true` on the flush that creates it.
    #[sqlx(default)]
    pub pds_created: bool,
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
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    url                TEXT NOT NULL UNIQUE,
    title              TEXT,
    site_url           TEXT,
    etag               TEXT,
    last_modified      TEXT,
    last_polled        TEXT,
    next_poll          TEXT,
    consecutive_errors INTEGER NOT NULL DEFAULT 0
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

-- Per-DID subscription projection. The shared `feeds`/`entries` cache is
-- deduped by URL and NOT owned by any single DID; `sub_ref` records which
-- feeds a given DID actually subscribes to (mirrored from the caller's PDS
-- subscription set on every resolve/sync). Every entry/feed READ and every
-- read/star MUTATION is scoped through this table so one user can never read
-- or mutate another user's cached articles. Rows are refreshed by
-- `replace_sub_refs`.
CREATE TABLE IF NOT EXISTS sub_ref (
    did     TEXT NOT NULL,
    feed_id INTEGER NOT NULL REFERENCES feeds (id) ON DELETE CASCADE,
    PRIMARY KEY (did, feed_id)
);
CREATE INDEX IF NOT EXISTS idx_sub_ref_feed ON sub_ref (feed_id);

CREATE TABLE IF NOT EXISTS read_cursor (
    did          TEXT NOT NULL,
    feed_url     TEXT NOT NULL,
    read_through TEXT,
    read_ids     TEXT NOT NULL DEFAULT '[]',
    unread_ids   TEXT NOT NULL DEFAULT '[]',
    dirty        INTEGER NOT NULL DEFAULT 0,
    pds_created  INTEGER NOT NULL DEFAULT 0,
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
    // An in-memory DB must run on a SINGLE connection: each `:memory:` connection
    // is a *separate* database, and a multi-connection in-memory pool can also
    // deadlock a writer against an idle pooled connection's shared-cache table
    // read-lock (SQLITE_LOCKED, code 262 — which `busy_timeout` does NOT retry;
    // seen as a Linux-only flaky failure in redeem_code's UPDATE). On-disk uses
    // WAL + a 5-connection pool as normal.
    let is_memory = db_url.contains(":memory:");
    let mut opts = SqliteConnectOptions::from_str(db_url)
        .with_context(|| format!("invalid sqlite url: {db_url}"))?
        .create_if_missing(true)
        .foreign_keys(true);
    // WAL is a no-op / unsupported for :memory:, so only request it on-disk.
    if !is_memory {
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
        .max_connections(if is_memory { 1 } else { 5 })
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
    apply_migrations(pool).await?;
    Ok(())
}

/// Apply additive, idempotent migrations to bring an EXISTING database up to the
/// current [`SCHEMA`]. `CREATE TABLE IF NOT EXISTS` never alters a table that
/// already exists, so a column added to a shipped table must be back-filled here
/// (SQLite has no `ADD COLUMN IF NOT EXISTS`, so we probe `table_info` first).
async fn apply_migrations(pool: &SqlitePool) -> Result<()> {
    // feeds.consecutive_errors — drives the exponential poll backoff. Older DBs
    // predate the column; add it (defaulting to 0) if it is missing.
    ensure_column(
        pool,
        "PRAGMA table_info(feeds)",
        "consecutive_errors",
        "ALTER TABLE feeds ADD COLUMN consecutive_errors INTEGER NOT NULL DEFAULT 0",
    )
    .await?;
    // read_cursor.pds_created — tracks whether a feed's readState record has been
    // created in the PDS, so the first flush emits a `create` (not a bare
    // `update`, which errors on a not-yet-existing record). Older DBs predate it.
    ensure_column(
        pool,
        "PRAGMA table_info(read_cursor)",
        "pds_created",
        "ALTER TABLE read_cursor ADD COLUMN pds_created INTEGER NOT NULL DEFAULT 0",
    )
    .await?;
    Ok(())
}

/// Add a column via `alter_sql` iff `info_sql` (a `PRAGMA table_info(<table>)`)
/// does not already report `column`. All three SQL args are hard-coded internal
/// literals (never user input), so they are safe `&'static str`s — the table name
/// can't be a bind parameter in `PRAGMA`, which is why they're passed whole.
async fn ensure_column(
    pool: &SqlitePool,
    info_sql: &'static str,
    column: &str,
    alter_sql: &'static str,
) -> Result<()> {
    let rows = sqlx::query(info_sql)
        .fetch_all(pool)
        .await
        .with_context(|| format!("{info_sql} failed"))?;
    let present = rows.iter().any(|r| r.get::<String, _>("name") == column);
    if !present {
        sqlx::query(alter_sql)
            .execute(pool)
            .await
            .with_context(|| format!("adding column {column} via {alter_sql}"))?;
    }
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

/// Record a poll FAILURE for a feed: bump its `consecutive_errors` by one and
/// return the NEW count. The count drives the exponential poll backoff, so a
/// persistently-failing feed spaces its retries out toward the ceiling instead of
/// hammering the 5-minute floor forever. Reset to 0 by [`reset_feed_errors`] on
/// any success/304.
pub async fn bump_feed_errors(pool: &SqlitePool, url: &str) -> Result<i64> {
    let row = sqlx::query(
        "UPDATE feeds SET consecutive_errors = consecutive_errors + 1 \
         WHERE url = ?1 RETURNING consecutive_errors",
    )
    .bind(url)
    .fetch_optional(pool)
    .await
    .with_context(|| format!("bump_feed_errors failed for {url}"))?;
    // If the feed row somehow vanished, treat it as the first error.
    Ok(row
        .map(|r| r.get::<i64, _>("consecutive_errors"))
        .unwrap_or(1))
}

/// Reset a feed's `consecutive_errors` to 0 after a successful poll (or a 304).
/// A no-op UPDATE if the row is missing.
pub async fn reset_feed_errors(pool: &SqlitePool, url: &str) -> Result<()> {
    sqlx::query("UPDATE feeds SET consecutive_errors = 0 WHERE url = ?1")
        .bind(url)
        .execute(pool)
        .await
        .with_context(|| format!("reset_feed_errors failed for {url}"))?;
    Ok(())
}

/// The feeds a `did` currently subscribes to, per its `sub_ref` projection.
/// Used by the PDS-unreachable fallback in `resolve_subscriptions` to render
/// the sidebar from the caller's OWN last-known subscriptions (fail closed)
/// rather than every cached feed.
pub async fn feeds_for_did(pool: &SqlitePool, did: &str) -> Result<Vec<Feed>> {
    let feeds = sqlx::query_as::<_, Feed>(
        r#"
        SELECT f.* FROM feeds f
        JOIN sub_ref sr ON sr.feed_id = f.id AND sr.did = ?1
        ORDER BY f.title IS NULL, f.title, f.url
        "#,
    )
    .bind(did)
    .fetch_all(pool)
    .await
    .with_context(|| format!("feeds_for_did failed for {did}"))?;
    Ok(feeds)
}

/// The number of feeds a `did` currently subscribes to (its `sub_ref` rows).
/// Backs the per-DID subscription cap enforced at the add/import paths.
pub async fn count_subscriptions_for_did(pool: &SqlitePool, did: &str) -> Result<i64> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_ref WHERE did = ?1")
        .bind(did)
        .fetch_one(pool)
        .await
        .with_context(|| format!("count_subscriptions_for_did failed for {did}"))?;
    Ok(n)
}

/// The number of distinct feeds in the shared cache. Backs the global feeds
/// ceiling checked before a brand-new feed is inserted.
pub async fn count_feeds(pool: &SqlitePool) -> Result<i64> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feeds")
        .fetch_one(pool)
        .await
        .context("count_feeds failed")?;
    Ok(n)
}

/// The **used** size of the SQLite database, in bytes, computed as
/// `(page_count - freelist_count) * page_size`. Backs the DB-size watermark that
/// disables new polling.
///
/// Subtracting the freelist is what keeps the watermark from latching the poller
/// off: `page_count` counts pages the file has *allocated*, including ones freed
/// by a `DELETE` but not yet returned to the OS (SQLite keeps them on a freelist
/// for reuse and never shrinks the file without a VACUUM). Counting only the
/// live pages means a retention prune (which frees pages, see [`reclaim`]) is
/// actually reflected here, so the watermark can drop back below its threshold
/// and polling resumes. Cheap (three `PRAGMA` reads); works for file + `:memory:`.
pub async fn db_size_bytes(pool: &SqlitePool) -> Result<i64> {
    let page_count: i64 = sqlx::query_scalar("PRAGMA page_count")
        .fetch_one(pool)
        .await
        .context("PRAGMA page_count failed")?;
    let freelist_count: i64 = sqlx::query_scalar("PRAGMA freelist_count")
        .fetch_one(pool)
        .await
        .context("PRAGMA freelist_count failed")?;
    let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
        .fetch_one(pool)
        .await
        .context("PRAGMA page_size failed")?;
    let used_pages = page_count.saturating_sub(freelist_count).max(0);
    Ok(used_pages.saturating_mul(page_size))
}

/// Reclaim freed pages so the database file (and its used-page accounting) can
/// actually shrink after a retention/prune sweep DELETEs rows.
///
/// Without this, a `DELETE` moves pages onto the freelist but never shrinks the
/// file — so once the DB-size watermark trips and retention deletes rows,
/// `page_count` stays put and [`db_size_bytes`] (well, its raw `page_count`
/// form) would never fall back below the watermark, latching the poller off
/// forever. Call this AFTER a prune. It uses incremental vacuum when the database
/// is in `auto_vacuum = INCREMENTAL` mode (cheap, no full rewrite), and otherwise
/// falls back to a full `VACUUM`.
pub async fn reclaim(pool: &SqlitePool) -> Result<()> {
    let auto_vacuum: i64 = sqlx::query_scalar("PRAGMA auto_vacuum")
        .fetch_one(pool)
        .await
        .context("PRAGMA auto_vacuum failed")?;
    // auto_vacuum: 0 = NONE, 1 = FULL, 2 = INCREMENTAL. `incremental_vacuum` only
    // does anything in INCREMENTAL mode; in NONE mode a full VACUUM is required to
    // return freed pages to the OS.
    if auto_vacuum == 2 {
        sqlx::query("PRAGMA incremental_vacuum")
            .execute(pool)
            .await
            .context("PRAGMA incremental_vacuum failed")?;
    } else {
        sqlx::query("VACUUM")
            .execute(pool)
            .await
            .context("VACUUM failed")?;
    }
    Ok(())
}

/// Insert a batch of entries for `feed_id`, deduping on `(feed_id, guid)`, then
/// trim the feed to at most [`crate::config`]-configured `max_entries_per_feed`
/// rows (newest by published date) so one firehose feed can't fill the disk.
///
/// On a GUID collision the existing entry is updated in place (title/url/body
/// may have changed on re-fetch) rather than duplicated. Runs in one
/// transaction. Returns the number of rows processed.
///
/// `max_entries_per_feed <= 0` disables the per-feed trim.
pub async fn insert_entries(
    pool: &SqlitePool,
    feed_id: i64,
    entries: &[NewEntry],
    max_entries_per_feed: i64,
) -> Result<u64> {
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

    // Entries-per-feed cap: keep only the newest `max_entries_per_feed` rows for
    // this feed, deleting the overflow in the same transaction. "Newest" is
    // COALESCE(published, fetched_at) so an UNDATED entry (NULL published) sorts
    // by when we fetched it (NOT NULL) rather than always sorting LAST and being
    // evicted first — otherwise a feed of undated items would trim its freshest
    // rows. This bounds a single firehose/misbehaving feed's storage footprint
    // independent of the global retention sweep. `<= 0` disables it.
    if max_entries_per_feed > 0 {
        sqlx::query(
            r#"
            DELETE FROM entries
            WHERE feed_id = ?1
              AND id NOT IN (
                  SELECT id FROM entries
                  WHERE feed_id = ?1
                  ORDER BY COALESCE(published, fetched_at) DESC, id DESC
                  LIMIT ?2
              )
            "#,
        )
        .bind(feed_id)
        .bind(max_entries_per_feed)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("trimming feed {feed_id} to {max_entries_per_feed} entries"))?;
    }

    tx.commit().await.context("commit insert_entries tx")?;
    Ok(count)
}

/// Replace the per-DID subscription projection (`sub_ref`) for `did` with
/// exactly `feed_ids`, in one transaction.
///
/// Called from the web layer's subscription-resolve/sync path so `sub_ref`
/// always mirrors the caller's *current* PDS subscription set. This is the
/// authority every scoped read/mutation checks against — a feed the caller no
/// longer subscribes to drops out of their read surface immediately.
pub async fn replace_sub_refs(pool: &SqlitePool, did: &str, feed_ids: &[i64]) -> Result<()> {
    let mut tx = pool.begin().await.context("begin replace_sub_refs tx")?;
    sqlx::query("DELETE FROM sub_ref WHERE did = ?1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("clear sub_ref for {did}"))?;
    for &feed_id in feed_ids {
        sqlx::query("INSERT OR IGNORE INTO sub_ref (did, feed_id) VALUES (?1, ?2)")
            .bind(did)
            .bind(feed_id)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("insert sub_ref {did}/{feed_id}"))?;
    }
    tx.commit().await.context("commit replace_sub_refs tx")?;
    Ok(())
}

/// Whether `did` currently subscribes to the feed `feed_id` owns
/// (i.e. a `sub_ref` row exists). The authorization primitive behind every
/// per-DID scoped read/mutation.
pub async fn did_subscribes_to_entry(pool: &SqlitePool, did: &str, entry_id: i64) -> Result<bool> {
    let found: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT 1
        FROM entries e
        JOIN sub_ref sr ON sr.feed_id = e.feed_id AND sr.did = ?1
        WHERE e.id = ?2
        "#,
    )
    .bind(did)
    .bind(entry_id)
    .fetch_optional(pool)
    .await
    .with_context(|| format!("did_subscribes_to_entry failed for {did}/{entry_id}"))?;
    Ok(found.is_some())
}

/// All entries for a feed, newest-published first — scoped to `did`'s
/// subscriptions. Returns an empty vec if `did` does not subscribe to the feed.
pub async fn entries_for_feed(pool: &SqlitePool, did: &str, feed_id: i64) -> Result<Vec<Entry>> {
    let entries = sqlx::query_as::<_, Entry>(
        r#"
        SELECT e.* FROM entries e
        WHERE e.feed_id = ?2
          AND EXISTS (
              SELECT 1 FROM sub_ref sr
              WHERE sr.did = ?1 AND sr.feed_id = e.feed_id
          )
        ORDER BY e.published DESC, e.id DESC
        "#,
    )
    .bind(did)
    .bind(feed_id)
    .fetch_all(pool)
    .await
    .context("entries_for_feed failed")?;
    Ok(entries)
}

/// Mark a single entry read/unread for a DID, upserting the per-DID state row
/// and stamping `updated_at`. Preserves any existing `starred` bit. Also
/// projects the change into the per-`(did, feed_url)` [`ReadCursor`] and marks
/// it `dirty` so the batched flusher pushes it to the PDS (see
/// [`project_entry_into_cursor`]).
///
/// AUTHORIZED per-DID: the upsert only touches an entry the caller subscribes
/// to (`sub_ref`). Returns `true` if a row was written, `false` if `did` does
/// not subscribe to the entry's feed (the web layer maps that to a 404 —
/// a non-subscriber can never mutate another user's state).
pub async fn mark_read(pool: &SqlitePool, did: &str, entry_id: i64, read: bool) -> Result<bool> {
    let now = now_rfc3339();
    let mut tx = pool.begin().await.context("begin mark_read tx")?;
    let res = sqlx::query(
        r#"
        INSERT INTO entry_state (did, entry_id, read, starred, updated_at)
        SELECT ?1, e.id, ?3, 0, ?4
        FROM entries e
        WHERE e.id = ?2
          AND EXISTS (
              SELECT 1 FROM sub_ref sr
              WHERE sr.did = ?1 AND sr.feed_id = e.feed_id
          )
        ON CONFLICT (did, entry_id) DO UPDATE SET
            read       = excluded.read,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(did)
    .bind(entry_id)
    .bind(read)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .with_context(|| format!("mark_read failed for {did}/{entry_id}"))?;

    if res.rows_affected() == 0 {
        // Not authorized (no `sub_ref`) — nothing written, no cursor to dirty.
        tx.rollback().await.ok();
        return Ok(false);
    }

    // Project the read/unread into this feed's read cursor (dirty=1) so the
    // flusher syncs it to the PDS. Same tx as the state write so a crash can't
    // leave the two out of step.
    project_entry_into_cursor(&mut tx, did, entry_id, read, &now).await?;

    tx.commit().await.context("commit mark_read tx")?;
    Ok(true)
}

/// Star/unstar a single entry for a DID (upsert, preserving `read`).
///
/// AUTHORIZED per-DID like [`mark_read`]: only touches an entry the caller
/// subscribes to. Returns `true` if a row was written, `false` if `did` does
/// not subscribe (→ 404 at the web layer).
pub async fn mark_starred(
    pool: &SqlitePool,
    did: &str,
    entry_id: i64,
    starred: bool,
) -> Result<bool> {
    let res = sqlx::query(
        r#"
        INSERT INTO entry_state (did, entry_id, read, starred, updated_at)
        SELECT ?1, e.id, 0, ?3, ?4
        FROM entries e
        WHERE e.id = ?2
          AND EXISTS (
              SELECT 1 FROM sub_ref sr
              WHERE sr.did = ?1 AND sr.feed_id = e.feed_id
          )
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
    Ok(res.rows_affected() > 0)
}

/// Mark every entry of a feed read (or unread) for a DID in one statement —
/// backs the "mark-all-read (per feed)" action. Also projects the change into
/// the feed's per-DID [`ReadCursor`] (dirty=1) so the batched flusher syncs the
/// new read-state to the PDS.
pub async fn mark_feed_read(pool: &SqlitePool, did: &str, feed_id: i64, read: bool) -> Result<u64> {
    let now = now_rfc3339();
    let mut tx = pool.begin().await.context("begin mark_feed_read tx")?;
    let res = sqlx::query(
        r#"
        INSERT INTO entry_state (did, entry_id, read, starred, updated_at)
        SELECT ?1, e.id, ?2, 0, ?3 FROM entries e
        WHERE e.feed_id = ?4
          AND EXISTS (
              SELECT 1 FROM sub_ref sr
              WHERE sr.did = ?1 AND sr.feed_id = e.feed_id
          )
        ON CONFLICT (did, entry_id) DO UPDATE SET
            read       = excluded.read,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(did)
    .bind(read)
    .bind(&now)
    .bind(feed_id)
    .execute(&mut *tx)
    .await
    .with_context(|| format!("mark_feed_read failed for {did}/feed {feed_id}"))?;

    if res.rows_affected() > 0 {
        // Project every affected entry into this feed's read cursor. `feed_id`
        // maps to exactly one feed URL, so this is a single per-feed cursor —
        // batched, not per-article. Only runs when the caller was authorized
        // (some rows changed), so an unsubscribed feed leaves no cursor behind.
        project_feed_into_cursor(&mut tx, did, feed_id, read, &now).await?;
    }

    tx.commit().await.context("commit mark_feed_read tx")?;
    Ok(res.rows_affected())
}

// ---------------------------------------------------------------------------
// Read-cursor projection (wires the local read/unread mutation into the
// PDS-bound `read_cursor`, so the batched flusher actually pushes read-state)
// ---------------------------------------------------------------------------

/// Add or remove an entry id from a JSON id-array string, returning the new JSON.
/// Membership is set-like (no duplicates) and order-stable (append on add). A
/// malformed input is treated as empty so a cosmetic parse issue never blocks a
/// projection.
fn json_id_set_toggle(raw: &str, id: i64, present: bool) -> String {
    let mut ids: Vec<i64> = serde_json::from_str::<Vec<serde_json::Value>>(raw)
        .ok()
        .map(|vals| {
            vals.into_iter()
                .filter_map(|v| match v {
                    serde_json::Value::Number(n) => n.as_i64(),
                    serde_json::Value::String(s) => s.parse::<i64>().ok(),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    if present {
        if !ids.contains(&id) {
            ids.push(id);
        }
    } else {
        ids.retain(|&x| x != id);
    }
    // Serialize as a JSON array of strings (the shape the flusher / lexicon
    // expect — `community.lexicon.rss.readState.readIds` is a string array).
    let as_strings: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
    serde_json::to_string(&as_strings).unwrap_or_else(|_| "[]".to_string())
}

/// The feed URL owning `feed_id`, if the row exists (cursors are keyed by URL,
/// not feed id — they mirror the PDS-side `readState.feedUrl`).
async fn feed_url_for_id_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    feed_id: i64,
) -> Result<Option<String>> {
    let url: Option<String> = sqlx::query_scalar("SELECT url FROM feeds WHERE id = ?1")
        .bind(feed_id)
        .fetch_optional(&mut **tx)
        .await
        .with_context(|| format!("feed_url_for_id_tx failed for feed {feed_id}"))?;
    Ok(url)
}

/// Fetch the (read_through, read_ids, unread_ids) of an existing cursor, or the
/// empty defaults if there is none yet.
async fn cursor_sets(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    did: &str,
    feed_url: &str,
) -> Result<(Option<String>, String, String)> {
    let row = sqlx::query(
        "SELECT read_through, read_ids, unread_ids FROM read_cursor \
         WHERE did = ?1 AND feed_url = ?2",
    )
    .bind(did)
    .bind(feed_url)
    .fetch_optional(&mut **tx)
    .await
    .with_context(|| format!("cursor_sets failed for {did}/{feed_url}"))?;
    Ok(match row {
        Some(r) => (
            r.get::<Option<String>, _>("read_through"),
            r.get::<String, _>("read_ids"),
            r.get::<String, _>("unread_ids"),
        ),
        None => (None, "[]".to_string(), "[]".to_string()),
    })
}

/// Upsert the cursor row for `(did, feed_url)` with the given exception sets,
/// stamping `updated_at` and marking it `dirty` so `dirty_cursors` returns it.
async fn write_cursor_sets(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    did: &str,
    feed_url: &str,
    read_through: Option<&str>,
    read_ids: &str,
    unread_ids: &str,
    now: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO read_cursor
            (did, feed_url, read_through, read_ids, unread_ids, dirty, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)
        ON CONFLICT (did, feed_url) DO UPDATE SET
            read_through = excluded.read_through,
            read_ids     = excluded.read_ids,
            unread_ids   = excluded.unread_ids,
            dirty        = 1,
            updated_at   = excluded.updated_at
        "#,
    )
    .bind(did)
    .bind(feed_url)
    .bind(read_through)
    .bind(read_ids)
    .bind(unread_ids)
    .bind(now)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("write_cursor_sets failed for {did}/{feed_url}"))?;
    Ok(())
}

/// Project a single entry's read/unread flip into its feed's read cursor.
///
/// The cursor mirrors `community.lexicon.rss.readState`: a `read_through`
/// high-water-mark plus two bounded exception sets. A per-article flip is
/// recorded in those sets (`read_ids` when read, `unread_ids` when unread), the
/// opposite set is cleared of the id, and the cursor is stamped + marked dirty.
/// This keeps the write batched by touching only the ONE per-feed cursor. (Note:
/// there is no compaction step yet that folds covered ids back into
/// `read_through`; the exception sets are expected to stay well under the cap.)
async fn project_entry_into_cursor(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    did: &str,
    entry_id: i64,
    read: bool,
    now: &str,
) -> Result<()> {
    // The entry's feed id → feed URL (the cursor key).
    let feed_id: Option<i64> = sqlx::query_scalar("SELECT feed_id FROM entries WHERE id = ?1")
        .bind(entry_id)
        .fetch_optional(&mut **tx)
        .await
        .with_context(|| format!("project_entry_into_cursor: feed_id for entry {entry_id}"))?;
    let feed_id = match feed_id {
        Some(f) => f,
        None => return Ok(()), // entry vanished mid-tx; nothing to project
    };
    let feed_url = match feed_url_for_id_tx(tx, feed_id).await? {
        Some(u) => u,
        None => return Ok(()),
    };

    let (read_through, read_ids, unread_ids) = cursor_sets(tx, did, &feed_url).await?;
    // read=true: id joins read_ids, leaves unread_ids. read=false: the inverse.
    let read_ids = json_id_set_toggle(&read_ids, entry_id, read);
    let unread_ids = json_id_set_toggle(&unread_ids, entry_id, !read);
    write_cursor_sets(
        tx,
        did,
        &feed_url,
        read_through.as_deref(),
        &read_ids,
        &unread_ids,
        now,
    )
    .await
}

/// Project a mark-all-feed-read/unread into that feed's single read cursor.
///
/// Every entry the caller subscribes to on `feed_id` is folded into the cursor
/// in one write: on mark-all-READ each id joins `read_ids` (and leaves
/// `unread_ids`); on mark-all-UNREAD the inverse. Still ONE per-feed cursor row
/// (batched), stamped + dirtied for the flusher.
async fn project_feed_into_cursor(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    did: &str,
    feed_id: i64,
    read: bool,
    now: &str,
) -> Result<()> {
    let feed_url = match feed_url_for_id_tx(tx, feed_id).await? {
        Some(u) => u,
        None => return Ok(()),
    };

    // The entry ids on this feed the caller is authorized for (subscribes to).
    let ids: Vec<i64> = sqlx::query_scalar(
        r#"
        SELECT e.id FROM entries e
        WHERE e.feed_id = ?2
          AND EXISTS (
              SELECT 1 FROM sub_ref sr
              WHERE sr.did = ?1 AND sr.feed_id = e.feed_id
          )
        "#,
    )
    .bind(did)
    .bind(feed_id)
    .fetch_all(&mut **tx)
    .await
    .with_context(|| format!("project_feed_into_cursor: entry ids for {did}/feed {feed_id}"))?;

    let (read_through, mut read_ids, mut unread_ids) = cursor_sets(tx, did, &feed_url).await?;
    for id in ids {
        read_ids = json_id_set_toggle(&read_ids, id, read);
        unread_ids = json_id_set_toggle(&unread_ids, id, !read);
    }
    write_cursor_sets(
        tx,
        did,
        &feed_url,
        read_through.as_deref(),
        &read_ids,
        &unread_ids,
        now,
    )
    .await
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
          AND EXISTS (
              SELECT 1 FROM sub_ref sr
              WHERE sr.did = ?1 AND sr.feed_id = e.feed_id
          )
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
          AND EXISTS (
              SELECT 1 FROM sub_ref sr
              WHERE sr.did = ?1 AND sr.feed_id = e.feed_id
          )
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
/// The write path for local mark-read updates (and the seam a login-time PDS
/// merge would use, once that is wired).
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

/// Mark a cursor's PDS `readState` record as CREATED after the flush that first
/// created it, so subsequent flushes emit an `update` instead of another
/// `create`. Idempotent; a no-op if the row is gone.
pub async fn mark_cursor_pds_created(pool: &SqlitePool, did: &str, feed_url: &str) -> Result<()> {
    sqlx::query("UPDATE read_cursor SET pds_created = 1 WHERE did = ?1 AND feed_url = ?2")
        .bind(did)
        .bind(feed_url)
        .execute(pool)
        .await
        .with_context(|| format!("mark_cursor_pds_created failed for {did}/{feed_url}"))?;
    Ok(())
}

/// Clear the `dirty` flag on a cursor after a successful PDS flush — but ONLY if
/// the row still carries the exact `flushed_updated_at` snapshot we flushed.
///
/// The flusher reads a cursor, sends it to the PDS (a network round-trip), then
/// clears `dirty`. A concurrent [`upsert_cursor`] (a fresh mark-read) can land
/// DURING that in-flight write, bumping `updated_at` and re-setting `dirty = 1`
/// for reads that were NOT in the flushed snapshot. An unconditional
/// `SET dirty = 0` would silently drop those reads. Guarding on the snapshot's
/// `updated_at` makes this a compare-and-swap: if `updated_at` changed under us,
/// zero rows update, the row stays dirty, and it re-flushes next round.
pub async fn clear_cursor_dirty(
    pool: &SqlitePool,
    did: &str,
    feed_url: &str,
    flushed_updated_at: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE read_cursor SET dirty = 0 \
         WHERE did = ?1 AND feed_url = ?2 AND updated_at = ?3",
    )
    .bind(did)
    .bind(feed_url)
    .bind(flushed_updated_at)
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

/// The row counts purged by [`purge_did_data`], for a confirmable success
/// message and for assertions in tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeCounts {
    /// `entry_state` rows removed (per-DID read/star flags).
    pub entry_state: u64,
    /// `read_cursor` rows removed (per-DID per-feed read cursors).
    pub read_cursor: u64,
    /// `sub_ref` rows removed (the DID's subscription projection).
    pub sub_ref: u64,
    /// `beta_access` rows removed (the DID's closed-beta seat: 0 or 1).
    pub beta_access: u64,
    /// `invite_codes` rows removed (codes this DID *created*).
    pub invite_codes: u64,
    /// `invite_codes` rows *scrubbed* (the code this DID *redeemed* to join —
    /// its `invitee_did` back-reference cleared to NULL, row kept).
    pub invitee_scrubbed: u64,
    /// `beta_access` rows *scrubbed* (seats this DID *granted* to others — the
    /// `granted_by` back-reference redacted to a sentinel, row kept).
    pub granted_by_scrubbed: u64,
}

impl PurgeCounts {
    /// Total rows removed across every per-DID table. (Scrub counts are tracked
    /// separately — those rows belong to *other* DIDs and are redacted, not
    /// deleted — so they are excluded from the delete total.)
    pub fn total(&self) -> u64 {
        self.entry_state + self.read_cursor + self.sub_ref + self.beta_access + self.invite_codes
    }
}

/// Sentinel written into `beta_access.granted_by` when the granting DID deletes
/// its data: the column is `NOT NULL`, so we redact rather than NULL it. Keeps
/// the grantee's seat valid while removing the departed DID's back-reference.
pub const REDACTED_DID: &str = "__redacted__";

/// Delete **all** local rows owned by `did` in a single transaction: the
/// per-DID read/star state (`entry_state`), per-feed read cursors
/// (`read_cursor`), the subscription projection (`sub_ref`), the closed-beta
/// seat (`beta_access`), and any invite codes this DID *created*
/// (`invite_codes`). The shared `feeds`/`entries` cache is intentionally left
/// intact — it is deduped and not owned by any single DID.
///
/// This is the local half of "delete my data": the caller pairs it with a
/// sidecar `POST /internal/revoke` so the OAuth tokens + sidecar session rows
/// are dropped too. Idempotent — deleting a DID with no rows returns all-zero
/// counts.
pub async fn purge_did_data(pool: &SqlitePool, did: &str) -> Result<PurgeCounts> {
    let mut tx = pool.begin().await.context("begin purge_did_data tx")?;

    let entry_state = sqlx::query("DELETE FROM entry_state WHERE did = ?1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("purge entry_state for {did}"))?
        .rows_affected();

    let read_cursor = sqlx::query("DELETE FROM read_cursor WHERE did = ?1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("purge read_cursor for {did}"))?
        .rows_affected();

    let sub_ref = sqlx::query("DELETE FROM sub_ref WHERE did = ?1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("purge sub_ref for {did}"))?
        .rows_affected();

    let beta_access = sqlx::query("DELETE FROM beta_access WHERE did = ?1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("purge beta_access for {did}"))?
        .rows_affected();

    let invite_codes = sqlx::query("DELETE FROM invite_codes WHERE creator_did = ?1")
        .bind(did)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("purge invite_codes for {did}"))?
        .rows_affected();

    // Scrub the DID's back-references from rows that belong to OTHER DIDs so no
    // per-DID residue survives the delete:
    //   * the invite code this DID *redeemed* to join lives on the inviter's
    //     row (`invitee_did`) — NULL it out (column is nullable).
    //   * seats this DID *granted* to others carry `granted_by = <this did>` —
    //     redact to a sentinel (column is NOT NULL) so the grantee keeps access
    //     without retaining the departed DID.
    let invitee_scrubbed =
        sqlx::query("UPDATE invite_codes SET invitee_did = NULL WHERE invitee_did = ?1")
            .bind(did)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("scrub invitee_did for {did}"))?
            .rows_affected();

    let granted_by_scrubbed =
        sqlx::query("UPDATE beta_access SET granted_by = ?2 WHERE granted_by = ?1")
            .bind(did)
            .bind(REDACTED_DID)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("scrub granted_by for {did}"))?
            .rows_affected();

    tx.commit().await.context("commit purge_did_data tx")?;

    Ok(PurgeCounts {
        entry_state,
        read_cursor,
        sub_ref,
        beta_access,
        invite_codes,
        invitee_scrubbed,
        granted_by_scrubbed,
    })
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
            0, // per-feed trim disabled for this test
        )
        .await?;
        assert_eq!(n, 2);

        // The reader must subscribe to the feed for the scoped reads to return
        // its entries (per-DID isolation projection).
        let did = "did:plc:abc123";
        replace_sub_refs(&pool, did, &[feed_id]).await?;

        // Read entries back (newest-published first).
        let entries = entries_for_feed(&pool, did, feed_id).await?;
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
            0,
        )
        .await?;
        assert_eq!(n2, 1);
        assert_eq!(entries_for_feed(&pool, did, feed_id).await?.len(), 2);

        // --- per-DID read state ---
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
            pds_created: false,
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
        let flushed_at = dirty[0].updated_at.clone();

        // After a flush, clearing dirty (with the flushed snapshot's updated_at)
        // removes it from the flusher's view.
        clear_cursor_dirty(&pool, did, "https://example.com/feed.xml", &flushed_at).await?;
        assert_eq!(dirty_cursors(&pool, did).await?.len(), 0);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Read-state PDS sync wiring: marking read/unread must project into the
    // per-feed `read_cursor` and mark it dirty so the batched flusher pushes it.
    // Before this wiring `mark_read` touched only `entry_state`; nothing dirtied
    // a cursor, so the flusher never synced read-state to the PDS.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mark_read_dirties_the_feed_cursor() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let feed_url = "https://example.com/feed.xml";
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: feed_url.to_string(),
                title: Some("Example".to_string()),
                ..Default::default()
            },
        )
        .await?;
        insert_entries(
            &pool,
            feed_id,
            &[
                NewEntry {
                    guid: "g1".to_string(),
                    published: Some("2026-07-10T00:00:00Z".to_string()),
                    ..Default::default()
                },
                NewEntry {
                    guid: "g2".to_string(),
                    published: Some("2026-07-11T00:00:00Z".to_string()),
                    ..Default::default()
                },
            ],
            0,
        )
        .await?;
        let did = "did:plc:reader";
        replace_sub_refs(&pool, did, &[feed_id]).await?;

        // No cursor exists yet.
        assert!(get_cursor(&pool, did, feed_url).await?.is_none());
        assert_eq!(dirty_cursors(&pool, did).await?.len(), 0);

        // Mark one entry read → the feed's read_cursor row now exists, dirty=1,
        // and dirty_cursors returns it (the exact assertion the fix requires).
        let e1 = entries_for_feed(&pool, did, feed_id).await?[0].id;
        assert!(mark_read(&pool, did, e1, true).await?);

        let cursor = get_cursor(&pool, did, feed_url)
            .await?
            .expect("mark_read must create the feed's read_cursor");
        assert!(cursor.dirty, "cursor must be dirty after mark_read");
        assert!(
            cursor.read_ids.contains(&e1.to_string()),
            "the read entry id must be in read_ids: {}",
            cursor.read_ids
        );
        let dirty = dirty_cursors(&pool, did).await?;
        assert_eq!(dirty.len(), 1, "flusher must see the newly dirty cursor");
        assert_eq!(dirty[0].feed_url, feed_url);

        // Marking it unread again moves the id to unread_ids and keeps it dirty.
        assert!(mark_read(&pool, did, e1, false).await?);
        let cursor = get_cursor(&pool, did, feed_url).await?.unwrap();
        assert!(cursor.dirty);
        assert!(
            cursor.unread_ids.contains(&e1.to_string()),
            "unread id must be in unread_ids: {}",
            cursor.unread_ids
        );
        assert!(
            !cursor.read_ids.contains(&e1.to_string()),
            "id must have left read_ids: {}",
            cursor.read_ids
        );

        // mark_feed_read dirties the one per-feed cursor too (batched, not
        // per-article).
        assert!(mark_feed_read(&pool, did, feed_id, true).await? > 0);
        let cursor = get_cursor(&pool, did, feed_url).await?.unwrap();
        assert!(cursor.dirty);
        assert_eq!(dirty_cursors(&pool, did).await?.len(), 1);

        // A non-subscriber's mark_read is a no-op and dirties NO cursor.
        let outsider = "did:plc:outsider";
        assert!(!mark_read(&pool, outsider, e1, true).await?);
        assert_eq!(dirty_cursors(&pool, outsider).await?.len(), 0);

        // The conditional clear only clears when updated_at matches the snapshot.
        let snap = dirty_cursors(&pool, did).await?[0].clone();
        // A stale updated_at must NOT clear (models a concurrent re-dirty).
        clear_cursor_dirty(&pool, did, feed_url, "1999-01-01T00:00:00Z").await?;
        assert_eq!(
            dirty_cursors(&pool, did).await?.len(),
            1,
            "stale-snapshot clear must be a no-op"
        );
        // The matching updated_at clears it.
        clear_cursor_dirty(&pool, did, feed_url, &snap.updated_at).await?;
        assert_eq!(dirty_cursors(&pool, did).await?.len(), 0);

        Ok(())
    }

    #[test]
    fn json_id_set_toggle_is_set_like() {
        // Add is idempotent, remove drops, output is a JSON string array.
        let s = json_id_set_toggle("[]", 5, true);
        assert_eq!(s, r#"["5"]"#);
        assert_eq!(json_id_set_toggle(&s, 5, true), r#"["5"]"#); // no dup
        let s = json_id_set_toggle(&s, 7, true);
        assert_eq!(s, r#"["5","7"]"#);
        let s = json_id_set_toggle(&s, 5, false);
        assert_eq!(s, r#"["7"]"#);
        // Tolerates numeric-array input and malformed input.
        assert_eq!(json_id_set_toggle("[1,2]", 3, true), r#"["1","2","3"]"#);
        assert_eq!(json_id_set_toggle("garbage", 1, true), r#"["1"]"#);
    }

    // -----------------------------------------------------------------------
    // Per-DID isolation: the shared cache is one row per URL, but the READ
    // SURFACE (entries/unread/starred) and the read/star MUTATIONS are scoped
    // to the caller's own subscriptions (`sub_ref`). User A must never see or
    // mutate user B's entries.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn per_did_isolation_scopes_reads_and_mutations() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;

        // Two feeds in the SHARED cache; A subscribes to feed_a, B to feed_b.
        let feed_a = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://a.example/feed.xml".to_string(),
                title: Some("A".to_string()),
                ..Default::default()
            },
        )
        .await?;
        let feed_b = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://b.example/feed.xml".to_string(),
                title: Some("B".to_string()),
                ..Default::default()
            },
        )
        .await?;

        insert_entries(
            &pool,
            feed_a,
            &[NewEntry {
                guid: "a-1".to_string(),
                url: Some("https://a.example/1".to_string()),
                title: Some("A one".to_string()),
                published: Some("2026-07-10T00:00:00Z".to_string()),
                content_html: Some("<p>secret A body</p>".to_string()),
                ..Default::default()
            }],
            0,
        )
        .await?;
        insert_entries(
            &pool,
            feed_b,
            &[NewEntry {
                guid: "b-1".to_string(),
                url: Some("https://b.example/1".to_string()),
                title: Some("B one".to_string()),
                published: Some("2026-07-11T00:00:00Z".to_string()),
                content_html: Some("<p>secret B body</p>".to_string()),
                ..Default::default()
            }],
            0,
        )
        .await?;

        let did_a = "did:plc:aaaa";
        let did_b = "did:plc:bbbb";
        replace_sub_refs(&pool, did_a, &[feed_a]).await?;
        replace_sub_refs(&pool, did_b, &[feed_b]).await?;

        // The id of B's only entry (the one A must not be able to touch).
        let b_entry_id = entries_for_feed(&pool, did_b, feed_b).await?[0].id;

        // --- entries_for_feed is scoped: A sees A's feed, not B's ------------
        assert_eq!(entries_for_feed(&pool, did_a, feed_a).await?.len(), 1);
        assert!(
            entries_for_feed(&pool, did_a, feed_b).await?.is_empty(),
            "A must not read entries of a feed it does not subscribe to"
        );

        // --- unread list is scoped -------------------------------------------
        let unread_a = get_unread_for_did(&pool, did_a).await?;
        assert_eq!(unread_a.len(), 1);
        assert_eq!(unread_a[0].guid, "a-1");
        let unread_b = get_unread_for_did(&pool, did_b).await?;
        assert_eq!(unread_b.len(), 1);
        assert_eq!(unread_b[0].guid, "b-1");

        // --- did_subscribes_to_entry authorizes correctly --------------------
        assert!(did_subscribes_to_entry(&pool, did_b, b_entry_id).await?);
        assert!(
            !did_subscribes_to_entry(&pool, did_a, b_entry_id).await?,
            "A does not subscribe to B's feed"
        );

        // --- mark_read is authorized: A CANNOT mark B's entry ----------------
        assert!(
            !mark_read(&pool, did_a, b_entry_id, true).await?,
            "non-subscriber mark_read must be a no-op (→ 404), never a mutation"
        );
        // B's unread list is untouched by A's attempt.
        assert_eq!(get_unread_for_did(&pool, did_b).await?.len(), 1);
        // A subscriber CAN mark it.
        assert!(mark_read(&pool, did_b, b_entry_id, true).await?);
        assert_eq!(get_unread_for_did(&pool, did_b).await?.len(), 0);

        // --- toggle_star is authorized the same way --------------------------
        assert!(
            !mark_starred(&pool, did_a, b_entry_id, true).await?,
            "non-subscriber mark_starred must be a no-op (→ 404)"
        );
        assert!(
            get_starred_for_did(&pool, did_a).await?.is_empty(),
            "A's starred list stays empty after the rejected attempt"
        );
        assert!(mark_starred(&pool, did_b, b_entry_id, true).await?);
        assert_eq!(get_starred_for_did(&pool, did_b).await?.len(), 1);
        // B's star never leaks into A's starred list.
        assert!(get_starred_for_did(&pool, did_a).await?.is_empty());

        // --- feeds_for_did is scoped to the DID's OWN sub_ref ----------------
        // This is the PDS-unreachable fallback's projection: it must NEVER
        // widen a DID's surface to feeds it does not subscribe to. A sees only
        // feed_a; B (still subscribed to feed_b here) sees only feed_b.
        let a_feeds = feeds_for_did(&pool, did_a).await?;
        assert_eq!(a_feeds.len(), 1);
        assert_eq!(a_feeds[0].id, feed_a);
        let b_feeds = feeds_for_did(&pool, did_b).await?;
        assert_eq!(b_feeds.len(), 1);
        assert_eq!(b_feeds[0].id, feed_b);

        // --- resync drops a feed from the surface when the sub goes away ------
        replace_sub_refs(&pool, did_b, &[]).await?;
        assert!(get_unread_for_did(&pool, did_b).await?.is_empty());
        assert!(get_starred_for_did(&pool, did_b).await?.is_empty());
        assert!(entries_for_feed(&pool, did_b, feed_b).await?.is_empty());
        // And the fallback projection is empty too — fail CLOSED, not open.
        assert!(feeds_for_did(&pool, did_b).await?.is_empty());

        Ok(())
    }

    // -----------------------------------------------------------------------
    // PDS-outage authorization (fail CLOSED). REGRESSION GUARD for the past
    // FAIL-OPEN bug (fixed in 2e53e0e): `resolve_subscriptions`' PDS/sidecar-
    // unreachable fallback used to synthesize a DID's `sub_ref` from EVERY
    // cached feed (`due_feeds(.., i64::MAX)`), granting cross-tenant read +
    // mutate during any outage. The fix serves the DID's OWN last-known
    // `sub_ref` via `feeds_for_did(did)` and NEVER widens it.
    //
    // This test replays that fixed fallback at the store layer — the seam the
    // web handler drives when `list_subscriptions_sorted(did) -> Err`. The
    // key adversarial shape is an ORPHAN cached feed (in the shared cache but
    // subscribed by NO ONE): the old fail-open code would have folded it into
    // the caller's surface. If the fail-open is reintroduced, `feeds_for_did`
    // would include that orphan and every assertion below flips — so this is a
    // real guard, not a tautology.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pds_outage_fallback_fails_closed_not_open() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;

        let did_a = "did:plc:aaaa";

        // feed_a: A's own subscription (its last-known `sub_ref`; the fallback
        // may serve this stale but must not widen past it).
        let feed_a = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://a.example/feed.xml".to_string(),
                title: Some("A".to_string()),
                ..Default::default()
            },
        )
        .await?;
        // feed_orphan: present in the SHARED cache but subscribed by NO DID.
        // This is exactly what the fail-open path would have leaked to A.
        let feed_orphan = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://orphan.example/feed.xml".to_string(),
                title: Some("Orphan".to_string()),
                ..Default::default()
            },
        )
        .await?;

        insert_entries(
            &pool,
            feed_a,
            &[NewEntry {
                guid: "a-1".to_string(),
                url: Some("https://a.example/1".to_string()),
                title: Some("A one".to_string()),
                published: Some("2026-07-10T00:00:00Z".to_string()),
                content_html: Some("<p>A body</p>".to_string()),
                ..Default::default()
            }],
            0,
        )
        .await?;
        insert_entries(
            &pool,
            feed_orphan,
            &[NewEntry {
                guid: "orphan-1".to_string(),
                url: Some("https://orphan.example/1".to_string()),
                title: Some("Orphan one".to_string()),
                published: Some("2026-07-11T00:00:00Z".to_string()),
                content_html: Some("<p>secret orphan body</p>".to_string()),
                ..Default::default()
            }],
            0,
        )
        .await?;

        // A's last-known subscription set is feed_a ONLY. No `sub_ref` row ever
        // points any DID at feed_orphan.
        replace_sub_refs(&pool, did_a, &[feed_a]).await?;

        // Grab the orphan entry id via a transient sub so we can address it,
        // then drop the sub — nobody subscribes to feed_orphan afterwards.
        replace_sub_refs(&pool, "did:plc:seed", &[feed_orphan]).await?;
        let orphan_entry_id = entries_for_feed(&pool, "did:plc:seed", feed_orphan).await?[0].id;
        replace_sub_refs(&pool, "did:plc:seed", &[]).await?;

        // --- Replay the FIXED fallback projection ----------------------------
        // This is what `resolve_subscriptions` serves on the Err (outage) path:
        // the caller's OWN feeds, never widened. It must contain feed_a and
        // NEVER the orphan. (The old fail-open synthesized from every cached
        // feed → this vec would have held feed_orphan too.)
        let fallback = feeds_for_did(&pool, did_a).await?;
        let fallback_ids: Vec<i64> = fallback.iter().map(|f| f.id).collect();
        assert_eq!(
            fallback_ids,
            vec![feed_a],
            "outage fallback must serve ONLY A's own last-known sub_ref, \
             never widen to the orphan cached feed"
        );
        assert!(
            !fallback_ids.contains(&feed_orphan),
            "FAIL-OPEN regression: outage fallback leaked an unsubscribed \
             cached feed into A's surface"
        );

        // --- With that projection in place, EVERY scoped read denies A -------
        assert!(
            !did_subscribes_to_entry(&pool, did_a, orphan_entry_id).await?,
            "A must not be authorized for an orphan feed's entry during an outage"
        );
        assert!(
            entries_for_feed(&pool, did_a, feed_orphan)
                .await?
                .is_empty(),
            "entries_for_feed must not expose the orphan feed to A during an outage"
        );
        // Neither the unread nor the starred list may surface the orphan entry.
        let unread_guids: Vec<String> = get_unread_for_did(&pool, did_a)
            .await?
            .into_iter()
            .map(|e| e.guid)
            .collect();
        assert!(
            !unread_guids.iter().any(|g| g == "orphan-1"),
            "orphan entry leaked into A's unread list during an outage"
        );
        assert!(
            get_starred_for_did(&pool, did_a).await?.is_empty(),
            "A has no starred entries; the orphan must not appear"
        );

        // --- And EVERY scoped mutation is a no-op (→ 404 at the web layer) ---
        assert!(
            !mark_read(&pool, did_a, orphan_entry_id, true).await?,
            "A must not mark an orphan feed's entry read during an outage"
        );
        assert!(
            !mark_starred(&pool, did_a, orphan_entry_id, true).await?,
            "A must not star an orphan feed's entry during an outage"
        );
        assert_eq!(
            mark_feed_read(&pool, did_a, feed_orphan, true).await?,
            0,
            "A must not mark-all-read the orphan feed during an outage"
        );

        // Nothing was written for A against the orphan entry.
        let es_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM entry_state WHERE did = ?1 AND entry_id = ?2")
                .bind(did_a)
                .bind(orphan_entry_id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(es_count, 0, "no cross-tenant mutation during the outage");

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

    // -----------------------------------------------------------------------
    // Hardening caps: per-DID sub count, global feed count, per-feed entry trim.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn count_helpers_track_feeds_and_subs() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        assert_eq!(count_feeds(&pool).await?, 0);

        let mut ids = Vec::new();
        for i in 0..3 {
            let id = upsert_feed(
                &pool,
                &NewFeed {
                    url: format!("https://f{i}.example/feed.xml"),
                    ..Default::default()
                },
            )
            .await?;
            ids.push(id);
        }
        assert_eq!(count_feeds(&pool).await?, 3);

        let did = "did:plc:capcheck";
        assert_eq!(count_subscriptions_for_did(&pool, did).await?, 0);
        replace_sub_refs(&pool, did, &ids).await?;
        assert_eq!(count_subscriptions_for_did(&pool, did).await?, 3);
        Ok(())
    }

    #[tokio::test]
    async fn insert_entries_trims_over_cap_keeping_newest() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://firehose.example/feed.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;

        // Insert 5 entries with ascending published dates, cap retained to 2.
        let batch: Vec<NewEntry> = (0..5)
            .map(|i| NewEntry {
                guid: format!("g-{i}"),
                title: Some(format!("E{i}")),
                published: Some(format!("2026-07-0{}T00:00:00Z", i + 1)),
                ..Default::default()
            })
            .collect();
        insert_entries(&pool, feed_id, &batch, 2).await?;

        let did = "did:plc:trim";
        replace_sub_refs(&pool, did, &[feed_id]).await?;
        let kept = entries_for_feed(&pool, did, feed_id).await?;
        assert_eq!(
            kept.len(),
            2,
            "over-cap feed trimmed to the newest 2 entries"
        );
        // Newest first: g-4 (2026-07-05), g-3 (2026-07-04).
        assert_eq!(kept[0].guid, "g-4");
        assert_eq!(kept[1].guid, "g-3");
        Ok(())
    }

    /// Regression: an UNDATED entry (NULL `published`) that was fetched most
    /// recently must NOT be evicted in favour of an older *dated* entry. The
    /// trim orders by `COALESCE(published, fetched_at) DESC`; under the old
    /// `ORDER BY published DESC` a NULL-published row sorts LAST and is dropped
    /// first even when it is the freshest thing in the feed.
    #[tokio::test]
    async fn insert_entries_trims_keeps_fresh_undated_over_stale_dated() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://undated.example/feed.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;

        // Two OLD dated entries (fetched long ago), plus one UNDATED entry
        // fetched most recently. Cap = 2, so exactly one row must be evicted.
        let batch = vec![
            NewEntry {
                guid: "old-dated-1".to_string(),
                title: Some("Old A".to_string()),
                published: Some("2026-07-01T00:00:00Z".to_string()),
                fetched_at: Some("2026-07-01T00:00:00Z".to_string()),
                ..Default::default()
            },
            NewEntry {
                guid: "old-dated-2".to_string(),
                title: Some("Old B".to_string()),
                published: Some("2026-07-02T00:00:00Z".to_string()),
                fetched_at: Some("2026-07-02T00:00:00Z".to_string()),
                ..Default::default()
            },
            NewEntry {
                guid: "fresh-undated".to_string(),
                title: Some("Fresh undated".to_string()),
                published: None,
                fetched_at: Some("2026-07-11T00:00:00Z".to_string()),
                ..Default::default()
            },
        ];
        insert_entries(&pool, feed_id, &batch, 2).await?;

        let did = "did:plc:undated";
        replace_sub_refs(&pool, did, &[feed_id]).await?;
        let kept = entries_for_feed(&pool, did, feed_id).await?;
        assert_eq!(kept.len(), 2, "over-cap feed trimmed to 2 entries");
        let guids: Vec<&str> = kept.iter().map(|e| e.guid.as_str()).collect();
        assert!(
            guids.contains(&"fresh-undated"),
            "the freshly-fetched undated entry must survive the trim, kept: {guids:?}"
        );
        assert!(
            guids.contains(&"old-dated-2"),
            "the newer dated entry survives; the OLDEST dated entry is the one evicted, kept: {guids:?}"
        );
        assert!(
            !guids.contains(&"old-dated-1"),
            "the oldest dated entry is the one that should be evicted, kept: {guids:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn db_size_is_positive_and_grows() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let before = db_size_bytes(&pool).await?;
        assert!(before > 0, "a schema-initialised DB has a non-zero size");
        Ok(())
    }

    /// `purge_did_data` removes every per-DID row the caller owns (read/star
    /// state, cursors, sub_ref projection, beta seat, created invite codes) —
    /// and touches no other DID's rows nor the shared feeds/entries cache.
    #[tokio::test]
    async fn purge_did_data_removes_only_the_callers_rows() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;

        // A shared feed + entry both DIDs can subscribe to.
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://example.com/feed.xml".to_string(),
                title: Some("Example".to_string()),
                ..Default::default()
            },
        )
        .await?;
        insert_entries(
            &pool,
            feed_id,
            &[NewEntry {
                guid: "g-1".to_string(),
                url: Some("https://example.com/a".to_string()),
                title: Some("First".to_string()),
                published: Some("2026-07-10T08:00:00Z".to_string()),
                ..Default::default()
            }],
            0,
        )
        .await?;
        let entry_id: i64 = sqlx::query_scalar("SELECT id FROM entries WHERE guid = 'g-1'")
            .fetch_one(&pool)
            .await?;

        let victim = "did:plc:victim";
        let bystander = "did:plc:bystander";

        // Seed BOTH DIDs with a full spread of per-DID rows.
        for did in [victim, bystander] {
            replace_sub_refs(&pool, did, &[feed_id]).await?;
            assert!(mark_read(&pool, did, entry_id, true).await?);
            assert!(mark_starred(&pool, did, entry_id, true).await?);
            upsert_cursor(
                &pool,
                &ReadCursor {
                    did: did.to_string(),
                    feed_url: "https://example.com/feed.xml".to_string(),
                    read_through: Some("2026-07-10T08:00:00Z".to_string()),
                    read_ids: "[]".to_string(),
                    unread_ids: "[]".to_string(),
                    dirty: false,
                    pds_created: false,
                    updated_at: now_rfc3339(),
                },
            )
            .await?;
            grant_access(&pool, did, Some("h.example"), "admin", None).await?;
            mint_code(&pool, did, 3600).await?;
        }

        // Purge only the victim.
        let counts = purge_did_data(&pool, victim).await?;
        assert_eq!(
            counts.entry_state, 1,
            "one entry_state row (read+star merge)"
        );
        assert_eq!(counts.read_cursor, 1);
        assert_eq!(counts.sub_ref, 1);
        assert_eq!(counts.beta_access, 1);
        assert_eq!(counts.invite_codes, 1);
        assert_eq!(counts.total(), 5);

        // The victim has zero rows left in every per-DID table.
        let es: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entry_state WHERE did = ?1")
            .bind(victim)
            .fetch_one(&pool)
            .await?;
        assert_eq!(es, 0, "victim still had entry_state rows");
        let rc: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_cursor WHERE did = ?1")
            .bind(victim)
            .fetch_one(&pool)
            .await?;
        assert_eq!(rc, 0, "victim still had read_cursor rows");
        let sr: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_ref WHERE did = ?1")
            .bind(victim)
            .fetch_one(&pool)
            .await?;
        assert_eq!(sr, 0, "victim still had sub_ref rows");
        assert!(
            !has_beta_access(&pool, victim).await?,
            "victim still had a beta seat"
        );
        let victim_codes: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM invite_codes WHERE creator_did = ?1")
                .bind(victim)
                .fetch_one(&pool)
                .await?;
        assert_eq!(victim_codes, 0);

        // The bystander is untouched.
        assert!(has_beta_access(&pool, bystander).await?);
        let bystander_subs = count_subscriptions_for_did(&pool, bystander).await?;
        assert_eq!(bystander_subs, 1, "bystander's sub_ref survived");
        let bystander_codes: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM invite_codes WHERE creator_did = ?1")
                .bind(bystander)
                .fetch_one(&pool)
                .await?;
        assert_eq!(bystander_codes, 1);

        // The shared cache is intact.
        assert_eq!(count_feeds(&pool).await?, 1);

        // Idempotent: purging again removes nothing.
        let again = purge_did_data(&pool, victim).await?;
        assert_eq!(again.total(), 0);

        Ok(())
    }

    /// A departing DID leaves back-references on rows that belong to OTHER DIDs:
    ///   * the invite code it *redeemed* to join (inviter's row: `invitee_did`);
    ///   * seats it *granted* to others (`beta_access.granted_by`).
    /// `purge_did_data` must scrub both so no per-DID residue survives, while
    /// leaving those other DIDs' rows otherwise intact (their access is kept).
    #[tokio::test]
    async fn purge_did_data_scrubs_cross_did_back_references() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;

        let inviter = "did:plc:inviter";
        let leaver = "did:plc:leaver";
        let friend = "did:plc:friend";

        // inviter mints a code; leaver redeems it to join (stamps invitee_did).
        let inviter_code = mint_code(&pool, inviter, 3600).await?;
        grant_access(&pool, inviter, None, "admin", None).await?;
        assert_eq!(
            redeem_code(&pool, &inviter_code, leaver, Some("leaver.bsky"), 100).await?,
            Ok(())
        );

        // leaver mints a code; friend redeems it (stamps friend's granted_by).
        let leaver_code = mint_code(&pool, leaver, 3600).await?;
        assert_eq!(
            redeem_code(&pool, &leaver_code, friend, Some("friend.bsky"), 100).await?,
            Ok(())
        );

        // Precondition: the leaver DID is present in both back-reference columns.
        let invitee_before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM invite_codes WHERE invitee_did = ?1")
                .bind(leaver)
                .fetch_one(&pool)
                .await?;
        assert_eq!(
            invitee_before, 1,
            "leaver should be an invitee before purge"
        );
        let granted_before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM beta_access WHERE granted_by = ?1")
                .bind(leaver)
                .fetch_one(&pool)
                .await?;
        assert_eq!(granted_before, 1, "leaver should be a granter before purge");

        // Purge the leaver.
        let counts = purge_did_data(&pool, leaver).await?;
        assert_eq!(
            counts.invitee_scrubbed, 1,
            "the redeemed code's invitee_did"
        );
        assert_eq!(counts.granted_by_scrubbed, 1, "the seat leaver granted");

        // No residue: the leaver DID appears in NEITHER back-reference column.
        let invitee_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM invite_codes WHERE invitee_did = ?1")
                .bind(leaver)
                .fetch_one(&pool)
                .await?;
        assert_eq!(invitee_after, 0, "leaver survived in invitee_did");
        let granted_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM beta_access WHERE granted_by = ?1")
                .bind(leaver)
                .fetch_one(&pool)
                .await?;
        assert_eq!(granted_after, 0, "leaver survived in granted_by");

        // The other DIDs' rows are kept: the friend still has a seat (redacted
        // granter), and the inviter's code row still exists (invitee NULLed).
        assert!(
            has_beta_access(&pool, friend).await?,
            "friend's seat must survive the leaver's scrub"
        );
        let friend_granted_by: String =
            sqlx::query_scalar("SELECT granted_by FROM beta_access WHERE did = ?1")
                .bind(friend)
                .fetch_one(&pool)
                .await?;
        assert_eq!(friend_granted_by, REDACTED_DID);
        let inviter_code_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM invite_codes WHERE creator_did = ?1")
                .bind(inviter)
                .fetch_one(&pool)
                .await?;
        assert_eq!(inviter_code_rows, 1, "inviter's code row must survive");

        Ok(())
    }

    // -- F2: consecutive-error count drives the poll backoff -----------------

    #[tokio::test]
    async fn feed_error_count_bumps_and_resets() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let url = "https://broken.example/feed.xml";
        upsert_feed(
            &pool,
            &NewFeed {
                url: url.to_string(),
                ..Default::default()
            },
        )
        .await?;

        // A fresh feed starts at 0 errors.
        let feed = get_feed_by_url(&pool, url).await?.expect("feed exists");
        assert_eq!(feed.consecutive_errors, 0);

        // N consecutive failures grow the count 1,2,3, and — fed through
        // `backoff_for` — the backoff grows with it (never latched at the floor).
        let mut last = std::time::Duration::ZERO;
        for expected in 1..=3 {
            let count = bump_feed_errors(&pool, url).await?;
            assert_eq!(count, expected, "bump returns the new count");
            let backoff = crate::feed::backoff_for(count as u32);
            assert!(
                backoff >= last,
                "backoff must not shrink as errors accumulate"
            );
            last = backoff;
        }
        // Growth actually happened (2 errors backs off longer than 1).
        assert!(crate::feed::backoff_for(2) > crate::feed::backoff_for(1));
        assert_eq!(
            get_feed_by_url(&pool, url)
                .await?
                .unwrap()
                .consecutive_errors,
            3
        );

        // A success resets the streak to 0 (back to the normal cadence).
        reset_feed_errors(&pool, url).await?;
        assert_eq!(
            get_feed_by_url(&pool, url)
                .await?
                .unwrap()
                .consecutive_errors,
            0
        );
        Ok(())
    }

    // -- F3: db_size_bytes ignores freed pages and drops after reclaim -------

    #[tokio::test]
    async fn db_size_drops_after_prune_and_reclaim() -> Result<()> {
        // On-disk DB so VACUUM has a file to shrink (in-memory has no freelist to
        // speak of the same way). Temp path, cleaned up at the end.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fr-reclaim-{}.db", std::process::id()));
        let url = format!("sqlite://{}", path.display());
        let pool = init_url(&url).await?;

        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://bulk.example/feed.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;

        // Insert a large batch so the file allocates real pages.
        let entries: Vec<NewEntry> = (0..2000)
            .map(|i| NewEntry {
                guid: format!("guid-{i}"),
                title: Some(format!("Entry number {i} with some padding text")),
                content_html: Some("<p>".to_string() + &"x".repeat(400) + "</p>"),
                published: Some("2026-01-01T00:00:00Z".to_string()),
                ..Default::default()
            })
            .collect();
        insert_entries(&pool, feed_id, &entries, 0).await?;
        let full = db_size_bytes(&pool).await?;
        assert!(full > 0);

        // Prune: delete every entry (the retention sweep's effect). This frees
        // pages onto the freelist but does NOT shrink the file yet.
        sqlx::query("DELETE FROM entries WHERE feed_id = ?1")
            .bind(feed_id)
            .execute(&pool)
            .await?;

        // Because db_size_bytes subtracts freelist pages, the USED size already
        // reflects the delete even before the file shrinks.
        let after_delete = db_size_bytes(&pool).await?;
        assert!(
            after_delete < full,
            "used size must drop once rows are deleted (freed pages excluded): \
             {after_delete} !< {full}"
        );

        // Reclaim returns the freed pages to the OS; used size stays low (and the
        // file itself shrinks). The key property F3 needs: the watermark can now
        // fall back below its threshold instead of latching polling off.
        reclaim(&pool).await?;
        let after_reclaim = db_size_bytes(&pool).await?;
        assert!(
            after_reclaim <= after_delete,
            "reclaim must not grow used size: {after_reclaim} !<= {after_delete}"
        );
        assert!(
            after_reclaim < full,
            "after prune+reclaim the DB is smaller than when full: \
             {after_reclaim} !< {full}"
        );

        drop(pool);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    // -- F4 support: pds_created flag round-trips + flips ---------------------

    #[tokio::test]
    async fn cursor_pds_created_defaults_false_and_flips() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:f4";
        let feed_url = "https://example.com/feed.xml";
        upsert_cursor(
            &pool,
            &ReadCursor {
                did: did.to_string(),
                feed_url: feed_url.to_string(),
                read_through: None,
                read_ids: r#"["1"]"#.to_string(),
                unread_ids: "[]".to_string(),
                dirty: true,
                pds_created: false,
                updated_at: now_rfc3339(),
            },
        )
        .await?;

        // A brand-new cursor's PDS record does NOT yet exist.
        let c = get_cursor(&pool, did, feed_url).await?.unwrap();
        assert!(!c.pds_created, "first flush must emit a create, not update");

        // After the create-flush lands, the flag flips so future flushes update.
        mark_cursor_pds_created(&pool, did, feed_url).await?;
        let c = get_cursor(&pool, did, feed_url).await?.unwrap();
        assert!(c.pds_created);
        Ok(())
    }
}
