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

/// One row of a LIST view — deliberately **without** `content_html`.
///
/// The list queries used to be `SELECT e.*` into [`Entry`], which carries the
/// sanitized article body. The body is essentially the whole of a cached entry
/// (measured: 11.9 KB/entry), and no list surface has ever rendered it — the
/// reader's `EntryRow` reads id, title, feed title, date, read, starred and
/// link, and nothing else. So every article on every page load was read off
/// disk, allocated, and dropped unexamined. On a 512 MB box with 250 concurrent
/// requests permitted, one reader with a large backlog could ask for hundreds of
/// megabytes in a single handler, and the resulting OOM/restart looked like a
/// healthy machine that simply fell over.
///
/// `read` / `starred` come from the same `LEFT JOIN` that filters the view, so a
/// caller does not have to fetch the whole unread or starred set a second time
/// just to decorate the rows it is showing.
///
/// [`Entry`] is still the right type for the single-entry reader, which is the
/// one surface that genuinely needs the body.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct EntryListRow {
    pub id: i64,
    pub feed_id: i64,
    /// Feed-native GUID — used to match a cached entry against a PDS saved record.
    pub guid: String,
    pub url: Option<String>,
    pub title: Option<String>,
    pub published: Option<String>,
    /// This DID's read bit. `false` when there is no `entry_state` row at all.
    pub read: bool,
    /// This DID's star bit. `false` when there is no `entry_state` row at all.
    pub starred: bool,
}

/// Which list [`list_entries`] (and its siblings) is producing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListView {
    /// No `entry_state` row for this DID, or one with `read = 0`.
    Unread,
    /// An `entry_state` row with `starred = 1`.
    Starred,
    /// Every subscribed entry, read or not.
    All,
}

impl ListView {
    /// The `WHERE` fragment that selects this view, given `s` as the per-DID
    /// `entry_state` LEFT JOIN alias.
    fn predicate(self) -> &'static str {
        match self {
            // An entry with no state row is unread — hence LEFT JOIN + COALESCE
            // rather than a join that would drop never-touched entries.
            ListView::Unread => "COALESCE(s.read, 0) = 0",
            ListView::Starred => "COALESCE(s.starred, 0) = 1",
            ListView::All => "1 = 1",
        }
    }
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

/// The `network_stat` key the relay adoption probe writes under.
///
/// Lives here, beside [`NetworkStat`], because **both** the writer (the
/// scheduler's probe, compiled into the binary) and the reader (`web::about`,
/// compiled into the library) name it — a literal in either place would be two
/// strings free to drift apart.
pub const ADOPTION_STAT_KEY: &str = "adoption.subscription";

/// One relay's observation of how many repos hold a collection
/// (`design/NETWORK-SPEC.md` §4.3). A projection: droppable, rebuildable from
/// the network, and never read by anything on the reading path.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct NetworkStat {
    /// The metric key, e.g. [`ADOPTION_STAT_KEY`].
    pub key: String,
    /// The relay base URL the number came from.
    pub source: String,
    /// The observed count.
    pub value: i64,
    /// Set when the probe hit its page cap: the value is a floor, not a count.
    pub truncated: bool,
    /// When the observation was taken (RFC3339, UTC).
    pub observed_at: String,
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
-- The FK child key. `entry_id` is the TRAILING column of the primary key, so
-- without this index it is not the leading column of anything and SQLite must
-- FULL SCAN entry_state for EVERY row deleted from `entries` to service
-- ON DELETE CASCADE.
--
-- That is not theoretical. Measured on 600k entry_state rows: 500 deletes took
-- 10.3s and 2,000 took 38.3s, against a busy_timeout of 5s — so any retention
-- sweep removing more than roughly 260 entries made every concurrent writer
-- (star, mark-read, OAuth session write) fail with SQLITE_BUSY. With this index
-- the same 32,850-row delete goes from ~10 minutes to 0.7s.
--
-- It also fixes the per-feed trim, whose starred-sparing subquery scans
-- entry_state on every poll of every feed and scales with TOTAL rows across all
-- users rather than with the feed being trimmed (2ms -> 21ms at 1M rows).
CREATE INDEX IF NOT EXISTS idx_entry_state_entry_id ON entry_state (entry_id);

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
-- The (did, feed_url) PRIMARY KEY can't serve a feed_url-only lookup (did is the
-- leading column). The retention path's orphan-cursor cleanup filters cursors by
-- feed_url alone, so give it an index.
CREATE INDEX IF NOT EXISTS idx_read_cursor_feed_url ON read_cursor (feed_url);

CREATE TABLE IF NOT EXISTS beta_access (
    did              TEXT PRIMARY KEY,
    handle           TEXT,
    granted_by       TEXT NOT NULL,
    granted_at       INTEGER NOT NULL,
    invite_code_used TEXT
);

CREATE TABLE IF NOT EXISTS invite_codes (
    code         TEXT PRIMARY KEY,
    creator_did  TEXT NOT NULL,
    status       TEXT NOT NULL,
    invitee_did  TEXT,
    -- The follower DID a bot-minted claim was minted FOR (recorded at mint time,
    -- distinct from `invitee_did` which is stamped at redeem). This is the
    -- server-side idempotency key: a second `POST /bot/claims` for a DID that
    -- already holds an outstanding active code returns the SAME code instead of
    -- minting a duplicate, so a bot-host state loss cannot re-mint per follower.
    intended_did TEXT,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    redeemed_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_invite_codes_status ON invite_codes (status, expires_at);
-- NOTE: the `intended_did` indexes are created in `apply_migrations`, AFTER the
-- `intended_did` column is ensured. They MUST NOT live in this base SCHEMA batch:
-- on an existing pre-0.2.2 volume the `CREATE TABLE IF NOT EXISTS invite_codes`
-- above is a no-op (the table already exists without `intended_did`), so a
-- `CREATE INDEX ... (intended_did, ...)` here would fail with "no such column"
-- and crash-loop the boot before migrations ever run.

-- Network-observation counters (v0.2.8, design/NETWORK-SPEC.md §4.3). One row
-- per (metric, relay): the adoption probe records how many repos a given relay
-- has INDEXED as holding a collection. We store the COUNT, never the DID list —
-- persisting the DIDs would build a durable register of "accounts that use an
-- RSS reader" on our disk for a feature whose only output is an integer. This
-- table is a PROJECTION, not a source of truth: `DROP TABLE` it and the next
-- probe rebuilds it, and nothing in the reader path reads it. Bounded forever at
-- (metrics × relays) rows, so it never interacts with the DB-size watermark.
CREATE TABLE IF NOT EXISTS network_stat (
    key         TEXT NOT NULL,   -- e.g. 'adoption.subscription'
    source      TEXT NOT NULL,   -- the relay host the number came from
    value       INTEGER NOT NULL,
    truncated   INTEGER NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (key, source)
);
-- Repo-operation timings, for comparing the two backends across a CUTOVER.
--
-- Persisted rather than held in memory because flipping the backend requires a
-- restart, and an in-memory table would lose the outgoing backend's numbers at
-- exactly the moment they became worth comparing against. These rows are the
-- only reason a "side by side" table can show two backends at once.
--
-- `repo_timing` is a bounded window of recent samples (pruned per backend+op);
-- `repo_timing_total` carries the all-time counts, which must survive that
-- pruning or a long-running backend would appear to have served fewer calls
-- than a fresh one.
CREATE TABLE IF NOT EXISTS repo_timing (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    backend  TEXT    NOT NULL,
    op       TEXT    NOT NULL,
    micros   INTEGER NOT NULL,
    ok       INTEGER NOT NULL,
    at       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_repo_timing_key ON repo_timing(backend, op, id);

CREATE TABLE IF NOT EXISTS repo_timing_total (
    backend    TEXT    NOT NULL,
    op         TEXT    NOT NULL,
    ok_count   INTEGER NOT NULL DEFAULT 0,
    err_count  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (backend, op)
);

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
/// Ceiling the WAL is truncated back to at each checkpoint.
///
/// The WAL lives on the same volume as the database and counts against the same
/// 1 GB, but nothing bounded it: SQLite grows the WAL to fit the largest
/// transaction it has ever seen and never shrinks it again without this limit.
const WAL_SIZE_LIMIT_BYTES: i64 = 64 * 1024 * 1024;

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
        // **Incremental auto-vacuum, set at CREATION.**
        //
        // `auto_vacuum` was read by `reclaim` and never set anywhere, so every
        // database ran in SQLite's default NONE mode and `reclaim` always took
        // its full-`VACUUM` branch — daily, and again after every prune. A full
        // VACUUM needs free disk roughly equal to the live database because it
        // writes a whole new file, which is exactly what is scarce under the
        // disk pressure that triggers a sweep; on a ~700 MiB database on a 1 GB
        // volume it cannot complete at all.
        //
        // This pragma only takes effect on a database with no tables yet, so it
        // fixes NEW instances permanently and does nothing to existing ones —
        // deliberately. Changing it on a populated database requires running the
        // very full VACUUM that is unsafe here, so that is a separate,
        // operator-invoked step: see [`migrate_to_incremental_vacuum`].
        opts = opts.auto_vacuum(sqlx::sqlite::SqliteAutoVacuum::Incremental);
        // Truncate the WAL back down at checkpoints. Without a limit, a WAL
        // grown once by a single large transaction stays that size for the life
        // of the file — permanently occupying volume the watermark is trying to
        // protect. The batched retention deletes keep transactions small now, so
        // in practice the WAL should rarely approach this; the limit is what
        // makes that a guarantee rather than a hope.
        opts = opts.pragma("journal_size_limit", WAL_SIZE_LIMIT_BYTES.to_string());
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
    // The Rust OAuth client's tables live in the same database. Created
    // UNCONDITIONALLY, not only when that backend is selected: the tables are
    // empty and harmless under the sidecar, whereas creating them lazily would
    // make the first request after a cutover flip fail with "no such table" --
    // at the one moment nobody wants to discover a migration was missed.
    crate::oauth::store::init_schema(pool)
        .await
        .context("failed to create the OAuth schema")?;
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
    // invite_codes.intended_did — the follower DID a bot claim was minted for, the
    // server-side idempotency key for `POST /bot/claims`. Older DBs (before the
    // follow→invite bot) predate it; it is nullable (browser/admin-minted codes
    // leave it NULL).
    ensure_column(
        pool,
        "PRAGMA table_info(invite_codes)",
        "intended_did",
        "ALTER TABLE invite_codes ADD COLUMN intended_did TEXT",
    )
    .await?;
    // Indexes on `intended_did` are created HERE (not in the base SCHEMA batch)
    // because they reference a column that only exists after the migration above.
    // On an existing pre-0.2.2 DB the `invite_codes` CREATE TABLE is a no-op, so
    // an index on `intended_did` in SCHEMA would fail before this migration ran
    // (that was blocker B1). All are `IF NOT EXISTS`, so re-running is a no-op.
    //
    // Look up an outstanding active claim by the DID it was minted for (bot dedupe).
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_invite_codes_intended \
         ON invite_codes (intended_did, status)",
    )
    .execute(pool)
    .await
    .context("creating idx_invite_codes_intended")?;
    // Enforce at MOST one outstanding active claim per intended DID. This makes
    // the bot's dedupe check-then-mint race-safe: two concurrent `POST /bot/claims`
    // for the same follower can no longer both insert an active code (the second
    // INSERT hits this unique constraint). Partial so it only constrains active
    // bot-minted rows — redeemed/expired rows and NULL-intended (admin/browser)
    // codes are unconstrained. (Blocker/should-fix S4.)
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_invite_codes_intended_active \
         ON invite_codes (intended_did) \
         WHERE intended_did IS NOT NULL AND status = 'active'",
    )
    .execute(pool)
    .await
    .context("creating idx_invite_codes_intended_active")?;
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
///
/// EVERY updatable column is COALESCE'd, so `None` means "leave alone" for all
/// of them and a partial upsert cannot clobber a field it never mentioned.
///
/// `etag`/`last_modified` were the exception until now, and the exception was
/// silently disabling conditional GET for the entire instance. `set_next_poll`
/// in the scheduler supplies only `url` + `next_poll` after every single poll,
/// which wrote both validators back to NULL — so `304 Not Modified` was
/// unreachable and every feed was re-downloaded, re-parsed, re-sanitised and
/// re-inserted in full, hourly, forever. `feed::touch_polled` had discovered the
/// same trap earlier and worked around it in its own caller by re-reading the
/// row first; that local fix is what let the next caller walk into it.
///
/// A stale validator is not a hazard: if the origin no longer issues one it
/// ignores our `If-None-Match` and returns `200`, and if it still matches then
/// `304` was the correct answer anyway.
pub async fn upsert_feed(pool: &SqlitePool, feed: &NewFeed) -> Result<i64> {
    let row = sqlx::query(
        r#"
        INSERT INTO feeds (url, title, site_url, etag, last_modified, last_polled, next_poll)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT (url) DO UPDATE SET
            title         = COALESCE(excluded.title, feeds.title),
            site_url      = COALESCE(excluded.site_url, feeds.site_url),
            etag          = COALESCE(excluded.etag, feeds.etag),
            last_modified = COALESCE(excluded.last_modified, feeds.last_modified),
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

/// The feed ids a `did` currently subscribes to (its `sub_ref` rows). Bounded by
/// the per-DID subscription cap, so callers can safely iterate it — e.g. the
/// global "mark all read" path fans out over feeds (bounded) rather than over
/// unread entries (unbounded).
pub async fn subscribed_feed_ids(pool: &SqlitePool, did: &str) -> Result<Vec<i64>> {
    let ids: Vec<i64> = sqlx::query_scalar("SELECT feed_id FROM sub_ref WHERE did = ?1")
        .bind(did)
        .fetch_all(pool)
        .await
        .with_context(|| format!("subscribed_feed_ids failed for {did}"))?;
    Ok(ids)
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
///
/// **The WAL counts too.** This is the number the DB-size watermark compares
/// against a VOLUME size, and in WAL mode the `-wal` sidecar sits on that same
/// volume — so leaving it out understated exactly the quantity the watermark
/// exists to bound. It is added back below, best-effort: a WAL that cannot be
/// stat'd contributes zero rather than failing the check, since a watermark that
/// errors is worse than one that is slightly optimistic.
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
    Ok(used_pages
        .saturating_mul(page_size)
        .saturating_add(wal_bytes(pool).await))
}

/// Bytes the write-ahead log currently occupies on the database's volume, or 0
/// when there is no WAL (`:memory:`, non-WAL journal modes) or it cannot be
/// stat'd. Best-effort by design — see [`db_size_bytes`].
async fn wal_bytes(pool: &SqlitePool) -> i64 {
    // `database_list` gives the main database's file path; empty for :memory:.
    let path: Option<String> = sqlx::query_scalar(
        "SELECT file FROM pragma_database_list WHERE name = 'main' AND file <> ''",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    let Some(path) = path else { return 0 };
    std::fs::metadata(format!("{path}-wal"))
        .map(|m| i64::try_from(m.len()).unwrap_or(i64::MAX))
        .unwrap_or(0)
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
    match auto_vacuum_mode(pool).await? {
        AutoVacuum::Incremental => {
            sqlx::query("PRAGMA incremental_vacuum")
                .execute(pool)
                .await
                .context("PRAGMA incremental_vacuum failed")?;
        }
        // SQLite already returns freed pages at every commit in this mode.
        // Nothing to do, and a VACUUM would be pure cost.
        AutoVacuum::Full => {}
        // **Deliberately a no-op, where this used to run a full VACUUM.**
        //
        // Nothing ever set `auto_vacuum`, so NONE was the mode every database
        // actually ran in — which made the full-VACUUM branch the one that
        // always executed, daily and after every prune. A full VACUUM writes a
        // complete second copy of the database, so it needs free disk roughly
        // equal to the live file; that is precisely what is missing under the
        // disk pressure that triggers a retention sweep. `poll_due_once` already
        // carries a comment explaining this danger and removed VACUUM from the
        // poll path — while leaving it in the retention path that runs under the
        // same pressure.
        //
        // Skipping it does NOT latch the DB-size watermark, which is the failure
        // this branch was written to prevent: `db_size_bytes` subtracts the
        // freelist, so a DELETE lowers the measured size with no VACUUM at all.
        // What is lost is the FILE shrinking, and the fix for that is to get the
        // database into INCREMENTAL mode — see `migrate_to_incremental_vacuum`,
        // which is operator-invoked precisely because it needs the one operation
        // that is unsafe to attempt automatically.
        AutoVacuum::None => {
            tracing::warn!(
                "auto_vacuum=NONE: skipping reclaim. Freed pages stay allocated and \
                 the file will not shrink. Run `featherreader --migrate-auto-vacuum` \
                 once, while the volume has headroom, to move this database to \
                 INCREMENTAL mode."
            );
        }
    }

    // Truncate the WAL as well. It lives on the same volume and is counted by
    // `db_size_bytes`, so reclaiming database pages while leaving a WAL grown by
    // the sweep that just ran would give back part of the space and hold the
    // rest. Worth doing even in the NONE branch above, where it is the only
    // space this function can return at all.
    //
    // Best-effort: a TRUNCATE checkpoint yields to active readers rather than
    // blocking them, and reports that as a row, not an error. A skipped
    // checkpoint just means the next one does the work.
    if let Err(err) = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(pool)
        .await
    {
        tracing::debug!(%err, "wal checkpoint after reclaim did not run");
    }
    Ok(())
}

/// A database's `auto_vacuum` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoVacuum {
    /// 0 — freed pages stay on the freelist; only a full `VACUUM` returns them.
    None,
    /// 1 — SQLite returns freed pages at every commit.
    Full,
    /// 2 — freed pages are returned on demand by `PRAGMA incremental_vacuum`.
    Incremental,
}

/// Read the database's `auto_vacuum` mode.
pub async fn auto_vacuum_mode(pool: &SqlitePool) -> Result<AutoVacuum> {
    let mode: i64 = sqlx::query_scalar("PRAGMA auto_vacuum")
        .fetch_one(pool)
        .await
        .context("PRAGMA auto_vacuum failed")?;
    Ok(match mode {
        1 => AutoVacuum::Full,
        2 => AutoVacuum::Incremental,
        _ => AutoVacuum::None,
    })
}

/// What [`migrate_to_incremental_vacuum`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VacuumMigration {
    /// Already in a mode that reclaims; nothing was run.
    NotNeeded(AutoVacuum),
    /// Refused: not enough free space on the volume to hold the rebuilt file.
    RefusedNoHeadroom { needed: u64, available: u64 },
    /// Ran the pragma + full VACUUM; the database is now INCREMENTAL.
    Migrated { bytes_before: i64, bytes_after: i64 },
}

/// Move a populated database from `auto_vacuum = NONE` to `INCREMENTAL`.
///
/// **Why this cannot happen at boot.** SQLite ignores `PRAGMA auto_vacuum` on a
/// database that already has tables unless it is followed by a full `VACUUM`,
/// which rebuilds the file. So the migration off the dangerous mode requires the
/// exact operation that is dangerous — a genuine chicken-and-egg, and the reason
/// this is an explicit operator step run when the volume has headroom rather
/// than something attempted lazily on a machine that is already under pressure.
///
/// Doing it automatically would also reintroduce the failure shape T2.1 just
/// removed: a boot-time VACUUM that cannot complete on a full volume, on a
/// supervisor that restarts the machine whenever a child exits, is a crash loop.
///
/// `available_bytes` is the caller's measurement of free space on the database's
/// volume (`None` where the platform cannot report it). The check is a refusal,
/// not a warning: starting a VACUUM that cannot finish wastes I/O on a box that
/// has none to spare. `VACUUM` itself is atomic — an interrupted one leaves the
/// original database intact — so the risk being managed here is wasted work and
/// a long write-lock hold, not corruption.
pub async fn migrate_to_incremental_vacuum(
    pool: &SqlitePool,
    available_bytes: Option<u64>,
) -> Result<VacuumMigration> {
    let mode = auto_vacuum_mode(pool).await?;
    if mode != AutoVacuum::None {
        return Ok(VacuumMigration::NotNeeded(mode));
    }

    // The rebuild needs room for a whole second copy. Ask for that plus a
    // margin, since the WAL grows alongside it.
    let bytes_before = db_size_bytes(pool).await?;
    let needed = (bytes_before.max(0) as u64).saturating_mul(2);
    if let Some(available) = available_bytes {
        if available < needed {
            return Ok(VacuumMigration::RefusedNoHeadroom { needed, available });
        }
    }

    // Order matters: the pragma records the INTENT, and the VACUUM is what
    // actually rewrites the file in the new mode. Reversed, the VACUUM would
    // rebuild in NONE mode and the pragma would then be ignored again.
    sqlx::query("PRAGMA auto_vacuum = INCREMENTAL")
        .execute(pool)
        .await
        .context("PRAGMA auto_vacuum = INCREMENTAL failed")?;
    sqlx::query("VACUUM")
        .execute(pool)
        .await
        .context("VACUUM failed during the auto_vacuum migration")?;

    let after = auto_vacuum_mode(pool).await?;
    anyhow::ensure!(
        after == AutoVacuum::Incremental,
        "the auto_vacuum migration ran but the database is still in {after:?} mode"
    );
    Ok(VacuumMigration::Migrated {
        bytes_before,
        bytes_after: db_size_bytes(pool).await?,
    })
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
    //
    // The bound is `2 * max_entries_per_feed`, not `max_entries_per_feed`: the
    // newest N by date, plus up to N starred. See the sparing subquery below.
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
              -- Starred entries survive the per-feed trim, exactly as they
              -- survive the retention sweep. This predicate was added to the
              -- sweep and NOT here, which left the documented guarantee
              -- ("starred entries are never evicted") false — and made this
              -- path, which runs on every poll of every feed rather than daily,
              -- the main producer of the very "starred but not cached" case the
              -- saved-record rendering exists to paper over.
              --
              -- The sparing is BOUNDED and SCOPED, and both matter:
              --
              -- Bounded, because the first version spared every starred row
              -- without limit, which did not weaken the cap so much as remove
              -- it — measured at cap=5 with 50 starred rows, 55 survived, 11x
              -- the cap. That is the same unbounded-sparing mistake the
              -- retention hard ceiling was added to fix, reintroduced in the
              -- other sweep. Worst case is now cap + cap.
              --
              -- Scoped, because `SELECT entry_id FROM entry_state WHERE
              -- starred = 1` reads EVERY starred row on the instance, for every
              -- poll of every feed — cost scaling with total users rather than
              -- with the feed being trimmed.
              AND id NOT IN (
                  SELECT e2.id FROM entries e2
                  WHERE e2.feed_id = ?1
                    AND EXISTS (
                        SELECT 1 FROM entry_state s
                        WHERE s.entry_id = e2.id AND s.starred = 1
                    )
                  ORDER BY COALESCE(e2.published, e2.fetched_at) DESC, e2.id DESC
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

    // Per-feed trim above may have DELETEd entries; their ids can linger in the
    // read_cursor exception sets (read_ids/unread_ids have no FK to entries), so
    // scrub the orphaned ids out of THIS feed's cursors in the same transaction.
    // Bounds id-set growth and keeps the flushed PDS record from referencing
    // entries that no longer exist. Scoped to the one feed for cheapness.
    if max_entries_per_feed > 0 {
        prune_orphan_cursor_ids_tx(&mut tx, Some(feed_id)).await?;
    }

    tx.commit().await.context("commit insert_entries tx")?;
    Ok(count)
}

/// Make a feed due for polling on the next tick.
///
/// Used when a saved article is missing from the cache: if the reader still
/// subscribes to the feed, the poller may be able to bring the article back on
/// its own. Clearing `next_poll` is the whole mechanism — `due_feeds` treats
/// NULL as due — so this adds no synthetic rows and no special-case fetch path.
///
/// **Rate-limited by `not_polled_since`**, and that is not a nicety.
///
/// `due_feeds` treats a NULL `next_poll` as due immediately, so clearing it
/// unconditionally from a page handler meant every reload of the starred view
/// made those feeds due again — bypassing the poll interval entirely. That is
/// outbound amplification against third-party feed origins, and it lets one
/// reader's feeds monopolise a poll budget that is shared and already the
/// binding constraint on how many readers an instance can serve.
///
/// A feed polled within the window is left alone: if the article was not in the
/// feed a minute ago, another fetch now will not find it either. The nudge is
/// therefore worth at most one extra poll per feed per interval, which is the
/// cadence the poller already targets.
///
/// A no-op if the URL is not a known feed.
pub async fn mark_feed_due(
    pool: &SqlitePool,
    feed_url: &str,
    not_polled_since: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE feeds SET next_poll = NULL \
         WHERE url = ?1 AND (last_polled IS NULL OR last_polled < ?2)",
    )
    .bind(feed_url)
    .bind(not_polled_since)
    .execute(pool)
    .await
    .context("marking a feed due")?;
    Ok(())
}

/// Delete entries whose age exceeds the retention window — the shared cache's
/// **rolling window** — except those a reader has starred or not yet read. "Age" is `COALESCE(published, fetched_at)` so an UNDATED
/// entry falls back to when it was fetched (never NULL) rather than being treated
/// as infinitely old. `entry_state` cascades via its `ON DELETE CASCADE` FK.
///
/// After the delete, orphaned entry ids are scrubbed out of every affected feed's
/// `read_cursor` exception sets (which have no FK to `entries`) so the id-sets do
/// not grow without bound and the flushed PDS record never references a vanished
/// entry. The caller (the retention sweep) should follow a non-zero return with
/// [`reclaim`] so freed pages return to the OS.
///
/// The two knobs are **independent**. `days == 0` disables the rolling window and
/// nothing else; `hard_days == 0` disables the ceiling and nothing else. Only
/// when both are off is this a no-op. Returns the number of entry rows deleted.
pub async fn prune_old_entries(pool: &SqlitePool, days: i64, hard_days: i64) -> Result<u64> {
    let now = chrono::Utc::now();
    let at = |d: i64| {
        (now - chrono::Duration::days(d)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };

    let cutoff = (days > 0).then(|| at(days));
    // The ceiling only means anything if it is STRICTLY OLDER than the window.
    // At `0 < hard_days <= days` the two cutoffs coincide, and since the hard
    // delete spares nothing, it would delete exactly the rows the soft delete
    // exists to spare — turning the whole starred/unread exception into a no-op.
    // With no window at all (`days <= 0`) there is nothing to be inside of, so a
    // positive ceiling stands on its own.
    //
    // This used to be `hard_days.max(days)`, which clamps the wrong way: it made
    // `0` — the value an operator reaches for to turn a ceiling OFF, and the
    // documented "disabled" value for `RETENTION_DAYS` one line above it in the
    // same table — the single most destructive setting available, silently
    // purging starred and unread entries at the soft window. Measured: with
    // `days=14`, `hard=0` deleted a 30-day starred entry and a 30-day unread one.
    //
    // `<= 0` now means disabled, consistently with `days`. A contradictory
    // positive value is refused rather than reinterpreted downward.
    //
    // The ceiling is deliberately NOT gated on the window being enabled. It used
    // to be — this function returned on `days <= 0` before the ceiling was even
    // computed — which made `RETENTION_DAYS=0` mean "no window AND no ceiling":
    // the one configuration with no bound on the shared cache whatsoever. That
    // became load-bearing when the per-feed trim started sparing starred entries.
    // Before, the trim was a backstop for them; now nothing was. "I don't want a
    // rolling window" and "I don't want any ceiling at all" are different
    // statements, and are now configured separately.
    let hard_cutoff = if hard_days > 0 && (days <= 0 || hard_days > days) {
        Some(at(hard_days))
    } else {
        if hard_days > 0 {
            tracing::warn!(
                hard_days,
                days,
                "retention hard ceiling is not older than the retention window; \
                 ignoring it — set it above the window or to 0 to disable"
            );
        }
        None
    };

    if cutoff.is_none() && hard_cutoff.is_none() {
        return Ok(0);
    }

    // **The hard ceiling — the bound that sparing would otherwise remove.**
    //
    // Sparing `read = 0` is not a small exception: "mark unread" is a one-click
    // UI control, and `entries` is SHARED across every reader on the instance.
    // Without a ceiling, one person can pin unbounded rows, and the pins are
    // permanent.
    //
    // That matters beyond disk. `poll_due_once` stops ALL polling once the
    // database crosses `db_size_watermark_bytes`, and the retention DELETE is
    // the documented release valve. Pinned rows can hold the valve shut
    // forever, so the failure mode is: one reader pins enough content, the DB
    // latches above the watermark, and polling stops for EVERY reader with no
    // self-healing path. The window used to be an unconditional bound; sparing
    // removed it, and this restores it.
    //
    // Starred entries go too at this age, and that is now safe: a saved record
    // whose entry is gone renders from the PDS record as a link card, so the
    // reader keeps the article's identity even when the cache does not keep its
    // text.
    let hard_deleted = match &hard_cutoff {
        Some(cutoff) => {
            delete_in_batches(
                pool,
                "SELECT id FROM entries WHERE COALESCE(published, fetched_at) < ?1",
                cutoff,
                "hard ceiling",
            )
            .await?
        }
        None => 0,
    };
    // **Entries a reader has DELIBERATELY marked are kept, whatever their age.**
    //
    // Precisely: an entry is spared when some DID has an `entry_state` row for
    // it with `starred = 1` or `read = 0`. An entry nobody has ever touched has
    // no `entry_state` row at all and is NOT spared, even though every read path
    // treats "no row" as unread.
    //
    // That asymmetry is deliberate and load-bearing. Sparing every never-touched
    // entry would spare essentially the whole table — almost no entry is ever
    // interacted with — which would make the window a no-op and leave the hard
    // ceiling as the only bound. The window is for evicting cache nobody claimed;
    // the exception is for the things a reader acted on.
    //
    // This comment used to read "starred and unread entries are kept", which is
    // the reading that would motivate exactly that change.
    //
    // The window is a cache eviction policy, not a data-retention policy. The
    // PDS is the source of truth for what a reader CHOSE — subscriptions,
    // folders, stars, read-state — but the entry CONTENT was never there. It
    // exists here and at the origin feed, and a feed typically serves only its
    // last few dozen items, so a pruned article is usually unrecoverable.
    //
    // Deleting indiscriminately therefore lost two things a reader would notice:
    // a starred article vanished from the starred view entirely (the view joins
    // `entries`, and `entry_state` cascades on the delete, so the star went with
    // it), and anything still unread disappeared before it was ever read. Both
    // are the opposite of a cache.
    //
    // This is what the documentation has always described; the query did not
    // implement it.
    let soft_deleted = match &cutoff {
        Some(cutoff) => {
            delete_in_batches(
                pool,
                "SELECT id FROM entries \
                 WHERE COALESCE(published, fetched_at) < ?1 \
                   AND id NOT IN ( \
                       SELECT entry_id FROM entry_state \
                       WHERE starred = 1 OR read = 0 \
                   )",
                cutoff,
                "window",
            )
            .await?
        }
        None => 0,
    };
    let deleted = soft_deleted + hard_deleted;

    // Only touch cursors when rows actually went away — and OUTSIDE the deletes.
    //
    // This used to run inside the one transaction that wrapped both deletes,
    // which made the whole sweep a single write-lock hold: load every
    // `read_cursor` row, then issue a fresh per-cursor `SELECT … JOIN … WHERE
    // f.url = ?` returning up to `max_entries_per_feed` ids, all before the
    // commit. SQLite is single-writer and `busy_timeout` is 5 s, so for that
    // whole span every mark-read, every login write and every cursor flush
    // failed.
    //
    // Correctness survives the move because the scrub is idempotent — it
    // computes each cursor's surviving ids from what is in `entries` NOW, and
    // rewrites only cursors that actually change. If the process dies between
    // the deletes and the scrub, the next sweep finishes the job, and in the
    // meantime a stale id in an exception set is inert: the flusher sends it,
    // and it names an entry nobody can reach.
    if deleted > 0 {
        if let Err(err) = prune_orphan_cursor_ids(pool, None).await {
            // The deletes already committed and are the point of this call.
            // A failed scrub leaves stale ids to be cleaned up next sweep.
            tracing::warn!(%err, "retention sweep: cursor id scrub failed after the deletes");
        }
    }

    Ok(deleted)
}

/// Rows deleted per statement by [`delete_in_batches`].
///
/// Small enough that one batch — including its `entry_state` FK cascade — is a
/// short lock hold, large enough that a big sweep is tens of statements rather
/// than thousands.
const PRUNE_BATCH: i64 = 1_000;

/// Backstop against a delete loop that never drains. `rows_affected == 0` is the
/// real terminator; this only bounds the damage if a future predicate change
/// makes that untrue. At [`PRUNE_BATCH`] this is 10M rows, far past anything a
/// 1 GB volume holds.
const PRUNE_MAX_BATCHES: usize = 10_000;

/// Delete every entry matched by `select_ids` (a `SELECT id FROM entries …`
/// bound to one `?1` cutoff), in bounded batches, **one implicit transaction per
/// batch**.
///
/// The retention sweep used to be a single `DELETE` inside one explicit
/// transaction. On a populated instance that is one unbroken write-lock hold
/// covering tens of thousands of row deletes plus their `entry_state` cascades —
/// measured at ~10 minutes before `idx_entry_state_entry_id` existed, and still
/// a single indivisible span after it. Everything else that writes (mark-read,
/// login, cursor flush) has a 5 s `busy_timeout` and simply fails for the
/// duration.
///
/// Batching does not make the total work smaller; it makes it INTERRUPTIBLE. A
/// writer waiting on the lock gets in between batches instead of timing out, and
/// the short sleep below guarantees that window actually exists rather than
/// leaving it to chance against a tight loop.
///
/// A partial sweep is safe: each batch commits on its own, and the predicate is
/// a fixed cutoff, so a crash mid-sweep leaves fewer rows deleted and the next
/// run finishes the job.
async fn delete_in_batches(
    pool: &SqlitePool,
    select_ids: &str,
    cutoff: &str,
    label: &str,
) -> Result<u64> {
    let sql = format!("DELETE FROM entries WHERE id IN ({select_ids} LIMIT {PRUNE_BATCH})");
    let mut total: u64 = 0;
    for batch in 0..PRUNE_MAX_BATCHES {
        let n = sqlx::query(sqlx::AssertSqlSafe(sql.clone()))
            .bind(cutoff)
            .execute(pool)
            .await
            .with_context(|| format!("prune_old_entries {label} (cutoff {cutoff})"))?
            .rows_affected();
        total += n;
        if n == 0 {
            return Ok(total);
        }
        // Hand the write lock over. Without this the loop can re-acquire it
        // immediately and a waiting writer still starves — batching would then
        // be bookkeeping rather than a fix. At `PRUNE_BATCH` rows per batch this
        // adds ~10 ms per 1,000 deleted rows to a sweep that runs once a day.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        if batch + 1 == PRUNE_MAX_BATCHES {
            tracing::warn!(
                label,
                total,
                "retention sweep hit its batch backstop; the rest waits for the next run"
            );
        }
    }
    Ok(total)
}

/// Scrub entry ids that no longer exist out of `read_cursor.read_ids` /
/// `unread_ids`. `read_cursor` is keyed by `(did, feed_url)` and its id-sets have
/// NO foreign key to `entries`, so a prune/trim that deletes entries would
/// otherwise leave dangling ids that (a) grow the sets without bound and (b) get
/// flushed to the PDS as references to vanished entries.
///
/// When `feed_id` is `Some`, only that feed's cursors are examined (the cheap
/// path used right after a per-feed trim); `None` scans every cursor (the
/// retention sweep, which can delete across many feeds at once). A cursor whose
/// sets actually change is rewritten and marked `dirty` so the flusher resyncs
/// it; unchanged cursors are left untouched (no spurious dirtying / PDS writes).
/// Returns the number of cursor rows modified.
///
/// This is the TRANSACTIONAL variant, used by the per-feed trim inside
/// `insert_entries`: it is scoped to one feed, examines that feed's cursors
/// only, and genuinely wants to land atomically with the trim that created the
/// orphans. The retention sweep uses [`prune_orphan_cursor_ids`] instead —
/// global scope inside one transaction is what made the sweep a multi-minute
/// write-lock hold.
async fn prune_orphan_cursor_ids_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    feed_id: Option<i64>,
) -> Result<u64> {
    // The set of live entry ids we prune against. Scope to the feed's URL when a
    // feed_id is given so we filter only that feed's cursors against that feed's
    // entries; otherwise consider all cursors / all entries.
    let feed_url = match feed_id {
        Some(fid) => match feed_url_for_id_tx(tx, fid).await? {
            Some(u) => Some(u),
            None => return Ok(0), // feed vanished mid-tx; nothing to prune
        },
        None => None,
    };

    // Load the (did, feed_url, read_ids, unread_ids) of the candidate cursors.
    let cursors: Vec<(String, String, String, String)> = match &feed_url {
        Some(url) => sqlx::query(
            "SELECT did, feed_url, read_ids, unread_ids FROM read_cursor WHERE feed_url = ?1",
        )
        .bind(url)
        .fetch_all(&mut **tx)
        .await
        .context("prune_orphan_cursor_ids: load feed cursors")?,
        None => sqlx::query("SELECT did, feed_url, read_ids, unread_ids FROM read_cursor")
            .fetch_all(&mut **tx)
            .await
            .context("prune_orphan_cursor_ids: load all cursors")?,
    }
    .into_iter()
    .map(|r| {
        (
            r.get::<String, _>("did"),
            r.get::<String, _>("feed_url"),
            r.get::<String, _>("read_ids"),
            r.get::<String, _>("unread_ids"),
        )
    })
    .collect();

    if cursors.is_empty() {
        return Ok(0);
    }

    let now = now_rfc3339();
    let mut changed: u64 = 0;
    for (did, curl, read_ids, unread_ids) in cursors {
        // The live entry ids for THIS cursor's feed (join by URL — the cursor key).
        let live: std::collections::HashSet<i64> = sqlx::query_scalar::<_, i64>(
            "SELECT e.id FROM entries e JOIN feeds f ON f.id = e.feed_id WHERE f.url = ?1",
        )
        .bind(&curl)
        .fetch_all(&mut **tx)
        .await
        .with_context(|| format!("prune_orphan_cursor_ids: live ids for {curl}"))?
        .into_iter()
        .collect();

        let new_read = filter_id_set_to_live(&read_ids, &live);
        let new_unread = filter_id_set_to_live(&unread_ids, &live);
        if new_read == read_ids && new_unread == unread_ids {
            continue; // nothing orphaned — leave the cursor (and its dirty flag) alone
        }
        sqlx::query(
            "UPDATE read_cursor SET read_ids = ?3, unread_ids = ?4, dirty = 1, updated_at = ?5 \
             WHERE did = ?1 AND feed_url = ?2",
        )
        .bind(&did)
        .bind(&curl)
        .bind(&new_read)
        .bind(&new_unread)
        .bind(&now)
        .execute(&mut **tx)
        .await
        .with_context(|| format!("prune_orphan_cursor_ids: rewrite cursor {did}/{curl}"))?;
        changed += 1;
    }
    Ok(changed)
}

/// [`prune_orphan_cursor_ids_tx`] over the pool — **no enclosing transaction**.
///
/// Same result, different locking. Each statement commits on its own, so the
/// single write lock is taken for one cursor rewrite at a time and released
/// between them, and the reads in between block nothing at all in WAL mode.
/// That matters because this is the global pass: the retention sweep's version
/// loads EVERY `read_cursor` row and then issues one live-ids query per cursor,
/// and holding all of that inside a transaction is what made a daily sweep look
/// like an outage to every writer on the instance.
///
/// **Each cursor's read-modify-write is one short transaction**, and that is not
/// optional. The first version of this loaded every cursor into a snapshot, then
/// walked them issuing an unguarded `UPDATE` per cursor from that snapshot. A
/// `mark_read` landing during the walk — seconds, on a global pass — had its new
/// id silently overwritten by the stale set, and the rewrite set `dirty = 1`, so
/// the flusher then pushed the truncated set to the PDS as authoritative. Local
/// `entry_state` still said read, so the loss was invisible here and visible
/// only in every OTHER atproto client. The transactional predecessor did not
/// have that bug: it held the write lock across the whole pass, so a concurrent
/// `mark_read` blocked and applied on top.
///
/// So the lock is not eliminated, it is SCOPED: one cursor's live-ids query plus
/// its update, rather than every cursor's. That keeps what T2.2 was for (a daily
/// sweep must not look like an outage) without trading it for lost writes.
///
/// Re-running is still safe — surviving ids are recomputed from the current
/// contents of `entries` — so dying partway just means the next sweep finishes.
///
/// `feed_id = Some(..)` scopes to one feed; `None` scans every cursor. Returns
/// the number of cursor rows modified.
async fn prune_orphan_cursor_ids(pool: &SqlitePool, feed_id: Option<i64>) -> Result<u64> {
    let feed_url = match feed_id {
        Some(fid) => match sqlx::query_scalar::<_, String>("SELECT url FROM feeds WHERE id = ?1")
            .bind(fid)
            .fetch_optional(pool)
            .await
            .context("prune_orphan_cursor_ids: feed url")?
        {
            Some(u) => Some(u),
            None => return Ok(0),
        },
        None => None,
    };

    // Only the KEYS come from this snapshot. The id-sets are deliberately not
    // read here — they are re-read inside each cursor's own transaction below,
    // because anything read out here is stale by the time it is written back.
    let keys: Vec<(String, String)> = match &feed_url {
        Some(url) => sqlx::query_as("SELECT did, feed_url FROM read_cursor WHERE feed_url = ?1")
            .bind(url)
            .fetch_all(pool)
            .await
            .context("prune_orphan_cursor_ids: load feed cursors")?,
        None => sqlx::query_as("SELECT did, feed_url FROM read_cursor")
            .fetch_all(pool)
            .await
            .context("prune_orphan_cursor_ids: load all cursors")?,
    };

    let mut changed: u64 = 0;
    for (did, curl) in keys {
        // A cursor that vanished between the key snapshot and now is simply
        // skipped; a cursor that APPEARED is missed until the next sweep. Both
        // are fine — the scrub is housekeeping, not a correctness barrier.
        match scrub_one_cursor(pool, &did, &curl).await {
            Ok(true) => changed += 1,
            Ok(false) => {}
            // One bad cursor must not abandon the rest of the pass.
            Err(err) => tracing::warn!(%err, %did, feed = %curl, "cursor id scrub failed"),
        }
    }
    Ok(changed)
}

/// Scrub one cursor's id-sets inside its own transaction. Returns whether the
/// row changed.
///
/// The read of the id-sets, the live-ids query and the write all happen under
/// one transaction, so a `mark_read` that lands mid-sweep either goes first (and
/// is included) or waits (and applies on top). Reading the sets outside and
/// writing them back later is the lost-update shape this function exists to
/// avoid — see [`prune_orphan_cursor_ids`].
async fn scrub_one_cursor(pool: &SqlitePool, did: &str, feed_url: &str) -> Result<bool> {
    let mut tx = pool.begin().await.context("begin scrub_one_cursor tx")?;

    let (_, read_ids, unread_ids) = cursor_sets(&mut tx, did, feed_url).await?;
    // An empty exception set has nothing to orphan, and skipping it avoids the
    // live-ids query entirely — the dominant cost of this pass, and the common
    // case for a cursor sitting at its high-water mark.
    if is_empty_id_set(&read_ids) && is_empty_id_set(&unread_ids) {
        return Ok(false);
    }

    let live: std::collections::HashSet<i64> = sqlx::query_scalar::<_, i64>(
        "SELECT e.id FROM entries e JOIN feeds f ON f.id = e.feed_id WHERE f.url = ?1",
    )
    .bind(feed_url)
    .fetch_all(&mut *tx)
    .await
    .with_context(|| format!("prune_orphan_cursor_ids: live ids for {feed_url}"))?
    .into_iter()
    .collect();

    let new_read = filter_id_set_to_live(&read_ids, &live);
    let new_unread = filter_id_set_to_live(&unread_ids, &live);
    if new_read == read_ids && new_unread == unread_ids {
        return Ok(false); // nothing orphaned — leave the cursor (and its dirty flag) alone
    }
    sqlx::query(
        "UPDATE read_cursor SET read_ids = ?3, unread_ids = ?4, dirty = 1, updated_at = ?5 \
         WHERE did = ?1 AND feed_url = ?2",
    )
    .bind(did)
    .bind(feed_url)
    .bind(&new_read)
    .bind(&new_unread)
    .bind(now_rfc3339())
    .execute(&mut *tx)
    .await
    .with_context(|| format!("prune_orphan_cursor_ids: rewrite cursor {did}/{feed_url}"))?;
    tx.commit().await.context("commit scrub_one_cursor tx")?;
    Ok(true)
}

/// Whether a stored id-set is *textually* empty — `[]` or blank.
///
/// Deliberately NOT a parse: this is a fast pre-filter, and
/// [`filter_id_set_to_live`] remains the authority on what a set contains. An
/// unparseable value returns `false` here, so it goes through the full path and
/// gets canonicalised to `[]` rather than being skipped — the pre-filter fails
/// toward doing the work, which is the safe direction.
fn is_empty_id_set(raw: &str) -> bool {
    let t = raw.trim();
    t.is_empty() || t == "[]"
}

/// Filter a JSON id-array string down to only ids present in `live`, returning
/// the canonical JSON-array-of-strings form (matching [`json_id_set_toggle`]). A
/// malformed input yields `[]`.
fn filter_id_set_to_live(raw: &str, live: &std::collections::HashSet<i64>) -> String {
    let ids: Vec<i64> = serde_json::from_str::<Vec<serde_json::Value>>(raw)
        .ok()
        .map(|vals| {
            vals.into_iter()
                .filter_map(|v| match v {
                    serde_json::Value::Number(n) => n.as_i64(),
                    serde_json::Value::String(s) => s.parse::<i64>().ok(),
                    _ => None,
                })
                .filter(|id| live.contains(id))
                .collect()
        })
        .unwrap_or_default();
    let as_strings: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
    serde_json::to_string(&as_strings).unwrap_or_else(|_| "[]".to_string())
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

/// The shared body of every list query: the per-DID `entry_state` LEFT JOIN, the
/// `sub_ref` authorization predicate, the view predicate and the optional
/// feed-id restriction. `projection` is spliced in as the `SELECT` list.
///
/// Returns the SQL plus the number of feed-id placeholders emitted, so the
/// caller knows where its own `LIMIT`/`OFFSET` placeholders start. `?1` is
/// always the DID; feed ids are `?2..`.
///
/// **Why the callers may assert this is SQL-safe.** Only three things vary, and
/// none is caller data: `projection` and [`ListView::predicate`] are `&'static
/// str` written in this file, and the feed-id restriction contributes only a
/// COUNT — the ids themselves are bound, never formatted in. Every runtime value
/// (the DID, the ids, the limit, the offset) reaches SQLite as a bind parameter.
fn list_query_sql(
    projection: &'static str,
    view: ListView,
    feed_ids: Option<&[i64]>,
) -> (String, usize) {
    let n = feed_ids.map_or(0, <[i64]>::len);
    let mut sql = format!(
        "SELECT {projection} \
         FROM entries e \
         LEFT JOIN entry_state s ON s.entry_id = e.id AND s.did = ?1 \
         WHERE {} \
           AND EXISTS ( \
               SELECT 1 FROM sub_ref sr \
               WHERE sr.did = ?1 AND sr.feed_id = e.feed_id \
           )",
        view.predicate()
    );
    if n > 0 {
        // Ids are i64 read out of this same database, so the risk here is
        // shape, not injection — they still go through placeholders.
        let placeholders = (2..2 + n).map(|i| format!("?{i}")).collect::<Vec<_>>();
        sql.push_str(&format!(" AND e.feed_id IN ({})", placeholders.join(",")));
    }
    (sql, n)
}

/// Bind the DID and the optional feed-id restriction, in the order
/// [`list_query_sql`] emits them.
fn bind_list_scope<'q, O>(
    q: sqlx::query::QueryAs<'q, sqlx::Sqlite, O, sqlx::sqlite::SqliteArguments>,
    did: &'q str,
    feed_ids: Option<&[i64]>,
) -> sqlx::query::QueryAs<'q, sqlx::Sqlite, O, sqlx::sqlite::SqliteArguments> {
    let mut q = q.bind(did);
    for id in feed_ids.unwrap_or(&[]) {
        q = q.bind(*id);
    }
    q
}

/// One page of a list view, newest-published first, scoped to `did`'s
/// subscriptions (`sub_ref`) and optionally narrowed to `feed_ids`.
///
/// **`limit` is a required parameter, not a convenience.** This function
/// replaced three `SELECT e.*` queries that had no `LIMIT` at all and pulled the
/// article body they never used; leaving an unbounded variant next to the
/// bounded one would just be the same trap with a longer name. If a caller wants
/// "everything", it has to say how much everything is allowed to be. See
/// [`EntryListRow`] for what the projection deliberately omits and why.
///
/// `feed_ids = Some(&[])` means "no feeds in scope" and returns empty without
/// touching the database — distinct from `None`, which means "every feed this
/// DID subscribes to".
pub async fn list_entries(
    pool: &SqlitePool,
    did: &str,
    view: ListView,
    feed_ids: Option<&[i64]>,
    limit: i64,
    offset: i64,
) -> Result<Vec<EntryListRow>> {
    if feed_ids.is_some_and(<[i64]>::is_empty) || limit <= 0 {
        return Ok(Vec::new());
    }
    let (mut sql, n) = list_query_sql(
        "e.id, e.feed_id, e.guid, e.url, e.title, e.published, \
         COALESCE(s.read, 0) AS read, COALESCE(s.starred, 0) AS starred",
        view,
        feed_ids,
    );
    sql.push_str(&format!(
        " ORDER BY e.published DESC, e.id DESC LIMIT ?{} OFFSET ?{}",
        n + 2,
        n + 3
    ));
    let q = sqlx::query_as::<_, EntryListRow>(sqlx::AssertSqlSafe(sql));
    let rows = bind_list_scope(q, did, feed_ids)
        .bind(limit)
        .bind(offset.max(0))
        .fetch_all(pool)
        .await
        .with_context(|| format!("list_entries({view:?}) failed for {did}"))?;
    Ok(rows)
}

/// How many entries the same scope + view would return, unpaged. Used for the
/// "N entries" heading and to decide whether a next-page link is warranted —
/// both of which used to read `entries.len()` off a fully materialized list.
pub async fn count_entries_for_view(
    pool: &SqlitePool,
    did: &str,
    view: ListView,
    feed_ids: Option<&[i64]>,
) -> Result<i64> {
    if feed_ids.is_some_and(<[i64]>::is_empty) {
        return Ok(0);
    }
    let (sql, _) = list_query_sql("COUNT(*)", view, feed_ids);
    // `query_as` over a 1-tuple keeps one binding helper for both shapes.
    let q = sqlx::query_as::<_, (i64,)>(sqlx::AssertSqlSafe(sql));
    let (n,) = bind_list_scope(q, did, feed_ids)
        .fetch_one(pool)
        .await
        .with_context(|| format!("count_entries_for_view({view:?}) failed for {did}"))?;
    Ok(n)
}

/// The ordered entry ids for a scope + view — the same ordering [`list_entries`]
/// renders, used for the reader's prev/next links.
///
/// Ids only: this one genuinely spans the whole list rather than a page (prev/next
/// needs the reader's position in it), so it is the one query where row COUNT can
/// still be large. An id is 8 bytes against the 11.9 KB row this used to fetch,
/// and `limit` bounds it regardless. Past the limit, prev/next simply stops
/// finding neighbours — the article still opens.
pub async fn list_entry_ids(
    pool: &SqlitePool,
    did: &str,
    view: ListView,
    feed_ids: Option<&[i64]>,
    limit: i64,
) -> Result<Vec<i64>> {
    if feed_ids.is_some_and(<[i64]>::is_empty) || limit <= 0 {
        return Ok(Vec::new());
    }
    let (mut sql, n) = list_query_sql("e.id", view, feed_ids);
    sql.push_str(&format!(
        " ORDER BY e.published DESC, e.id DESC LIMIT ?{}",
        n + 2
    ));
    let q = sqlx::query_as::<_, (i64,)>(sqlx::AssertSqlSafe(sql));
    let rows = bind_list_scope(q, did, feed_ids)
        .bind(limit)
        .fetch_all(pool)
        .await
        .with_context(|| format!("list_entry_ids({view:?}) failed for {did}"))?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Unread counts per `feed_id` for a DID — the sidebar's per-feed badges.
///
/// Counted in SQL. The sidebar used to fetch every unread entry (bodies and all)
/// and count them in Rust, on every page with chrome, which is the single most
/// frequent instance of the projection problem [`EntryListRow`] describes.
pub async fn unread_counts_by_feed(
    pool: &SqlitePool,
    did: &str,
) -> Result<std::collections::HashMap<i64, i64>> {
    let (sql, _) = list_query_sql("e.feed_id, COUNT(*)", ListView::Unread, None);
    let rows =
        sqlx::query_as::<_, (i64, i64)>(sqlx::AssertSqlSafe(format!("{sql} GROUP BY e.feed_id")))
            .bind(did)
            .fetch_all(pool)
            .await
            .with_context(|| format!("unread_counts_by_feed failed for {did}"))?;
    Ok(rows.into_iter().collect())
}

/// The `(url, guid)` identity pairs of every cached starred entry for a DID.
///
/// The starred view matches PDS saved records against these to decide which
/// records the cache can render itself. It must span the whole starred set, not
/// the visible page: a record that looks uncached gets an un-save button that
/// deletes the PDS RECORD rather than un-starring the entry, so narrowing this
/// set changes what a click destroys. Identity strings only — no bodies.
pub async fn starred_identities(
    pool: &SqlitePool,
    did: &str,
    limit: i64,
) -> Result<Vec<(Option<String>, String)>> {
    let (mut sql, _) = list_query_sql("e.url, e.guid", ListView::Starred, None);
    sql.push_str(" LIMIT ?2");
    let rows = sqlx::query_as::<_, (Option<String>, String)>(sqlx::AssertSqlSafe(sql))
        .bind(did)
        .bind(limit)
        .fetch_all(pool)
        .await
        .with_context(|| format!("starred_identities failed for {did}"))?;
    Ok(rows)
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

/// Fold ids already covered by a high-water-mark into `read_through`, so the
/// exception set stops growing. Returns the new `read_through` when it advanced.
///
/// **What was wrong.** `read_through` was never COMPUTED — `project_entry_into_cursor`
/// only carried an existing value through, and it starts NULL, so in practice it
/// was always NULL. That left `read_ids` as the sole mechanism, growing one id
/// per article read, bounded only by `max_entries_per_feed` (2000) — while the
/// flusher caps the record at `ReadState::MAX_IDS` (1000) keeping the TAIL, with
/// no log line. Past 1000 read articles in one feed, the oldest read-state
/// silently stopped syncing, and those articles came back UNREAD in any other
/// atproto reader. The `cap` helper's own comment assumed "the exception sets
/// are expected to stay well under the cap in normal use"; against a 2000-entry
/// per-feed ceiling that does not hold.
///
/// **The rule.** `read_through` means "every entry at or before this time is
/// read". So it may advance only to a point with no unread entry at or before
/// it. That point is computed here as the newest entry timestamp STRICTLY OLDER
/// than the oldest unread entry — strictly, because entries can share a
/// timestamp, and a watermark equal to an unread entry's time would assert that
/// entry is read.
///
/// Once the watermark moves, every `read_ids` entry at or before it is
/// redundant and is dropped — that is the compaction. `unread_ids` is filtered
/// the same way; by construction nothing unread sits at or below the new
/// watermark, so it empties, but the filter is written rather than assumed so it
/// stays correct if that invariant ever shifts.
///
/// Timestamps compare lexicographically because every writer normalises to UTC
/// `...Z` at seconds precision (`feed::fmt_time`, `now_rfc3339`) — the same
/// assumption `poll_health` and the retention window already make.
pub async fn compact_cursor(
    pool: &SqlitePool,
    did: &str,
    feed_url: &str,
) -> Result<Option<String>> {
    let mut tx = pool.begin().await.context("begin compact_cursor tx")?;
    let (read_through, read_ids, unread_ids) = cursor_sets(&mut tx, did, feed_url).await?;

    // The oldest entry on this feed that `did` has NOT read. `NULL` = nothing
    // unread, in which case the watermark can cover the whole feed.
    let oldest_unread: Option<String> = sqlx::query_scalar(
        r#"
        SELECT MIN(COALESCE(e.published, e.fetched_at))
        FROM entries e
        JOIN feeds f ON f.id = e.feed_id
        LEFT JOIN entry_state s ON s.entry_id = e.id AND s.did = ?1
        WHERE f.url = ?2 AND COALESCE(s.read, 0) = 0
        "#,
    )
    .bind(did)
    .bind(feed_url)
    .fetch_one(&mut *tx)
    .await
    .with_context(|| format!("compact_cursor: oldest unread for {did}/{feed_url}"))?;

    let watermark: Option<String> = match &oldest_unread {
        Some(oldest) => sqlx::query_scalar(
            r#"
            SELECT MAX(COALESCE(e.published, e.fetched_at))
            FROM entries e JOIN feeds f ON f.id = e.feed_id
            WHERE f.url = ?1 AND COALESCE(e.published, e.fetched_at) < ?2
            "#,
        )
        .bind(feed_url)
        .bind(oldest)
        .fetch_one(&mut *tx)
        .await
        .with_context(|| format!("compact_cursor: watermark for {did}/{feed_url}"))?,
        None => sqlx::query_scalar(
            r#"
            SELECT MAX(COALESCE(e.published, e.fetched_at))
            FROM entries e JOIN feeds f ON f.id = e.feed_id
            WHERE f.url = ?1
            "#,
        )
        .bind(feed_url)
        .fetch_one(&mut *tx)
        .await
        .with_context(|| format!("compact_cursor: watermark for {did}/{feed_url}"))?,
    };

    // Nothing to cover, or the watermark is already at least this far along.
    // Never move it BACKWARDS: that would re-assert articles as unread.
    let Some(watermark) = watermark else {
        return Ok(None);
    };
    if read_through
        .as_deref()
        .is_some_and(|rt| rt >= &watermark[..])
    {
        return Ok(None);
    }

    let keep_above = ids_published_after(&mut tx, feed_url, &read_ids, &watermark).await?;
    let keep_unread =
        ids_published_at_or_before(&mut tx, feed_url, &unread_ids, &watermark).await?;

    write_cursor_sets(
        &mut tx,
        did,
        feed_url,
        Some(&watermark),
        &keep_above,
        &keep_unread,
        &now_rfc3339(),
    )
    .await?;
    tx.commit().await.context("commit compact_cursor tx")?;
    Ok(Some(watermark))
}

/// The subset of `ids` whose entries are published strictly AFTER `watermark`,
/// as the canonical JSON array-of-strings the cursor stores.
async fn ids_published_after(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    feed_url: &str,
    ids: &str,
    watermark: &str,
) -> Result<String> {
    let live = ids_matching_watermark(tx, feed_url, watermark, true).await?;
    Ok(filter_id_set_to_live(ids, &live))
}

/// The subset of `ids` whose entries are published at or BEFORE `watermark`.
async fn ids_published_at_or_before(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    feed_url: &str,
    ids: &str,
    watermark: &str,
) -> Result<String> {
    let live = ids_matching_watermark(tx, feed_url, watermark, false).await?;
    Ok(filter_id_set_to_live(ids, &live))
}

/// Entry ids on `feed_url` on one side of `watermark`. `after = true` selects
/// strictly newer; `false` selects at-or-older.
async fn ids_matching_watermark(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    feed_url: &str,
    watermark: &str,
    after: bool,
) -> Result<std::collections::HashSet<i64>> {
    let sql = if after {
        "SELECT e.id FROM entries e JOIN feeds f ON f.id = e.feed_id \
         WHERE f.url = ?1 AND COALESCE(e.published, e.fetched_at) > ?2"
    } else {
        "SELECT e.id FROM entries e JOIN feeds f ON f.id = e.feed_id \
         WHERE f.url = ?1 AND COALESCE(e.published, e.fetched_at) <= ?2"
    };
    Ok(sqlx::query_scalar::<_, i64>(sql)
        .bind(feed_url)
        .bind(watermark)
        .fetch_all(&mut **tx)
        .await
        .context("compact_cursor: ids on one side of the watermark")?
        .into_iter()
        .collect())
}

/// Clear `did`'s star on any cached entry matching `url` or `guid`, **ignoring
/// the subscription projection**. Returns the number of `entry_state` rows
/// changed.
///
/// This closes a desync between the two places a star lives. The starred view
/// matches PDS saved records against cached entries through `sub_ref`, so an
/// entry that is cached AND starred in a feed the reader has since UNSUBSCRIBED
/// from does not match: it renders as an uncached row whose button is
/// `POST /saved/{rkey}/delete`. That deletes the PDS record and used to leave
/// `entry_state.starred = 1` behind — invisible, because the starred list is
/// `sub_ref`-scoped too, until the reader resubscribes and the star reappears
/// with no record backing it.
///
/// **Why omitting `sub_ref` is safe here, when it is the per-DID isolation hook
/// everywhere else.** Every row this can touch is keyed by `did` and this writes
/// only `starred = 0`. The worst a caller can do with it is clear one of their
/// OWN stars — which is what they just asked for. The predicate that matters for
/// isolation is the `did` in the `WHERE`, and it is not optional.
///
/// Matching on `url` OR `guid` mirrors how the view decides a record is already
/// cached, so the removal path and the render path agree on what "the same
/// article" means.
pub async fn clear_star_by_identity(
    pool: &SqlitePool,
    did: &str,
    url: Option<&str>,
    guid: Option<&str>,
) -> Result<u64> {
    // Neither identifier present: nothing to match on. Running the statement
    // would compare NULL to NULL and match nothing, but returning early says so.
    if url.is_none_or(str::is_empty) && guid.is_none_or(str::is_empty) {
        return Ok(0);
    }
    let res = sqlx::query(
        r#"
        UPDATE entry_state
        SET starred = 0, updated_at = ?4
        WHERE did = ?1
          AND starred = 1
          AND entry_id IN (
              SELECT id FROM entries
              WHERE (?2 IS NOT NULL AND url = ?2)
                 OR (?3 IS NOT NULL AND guid = ?3)
          )
        "#,
    )
    .bind(did)
    .bind(url.filter(|u| !u.is_empty()))
    .bind(guid.filter(|g| !g.is_empty()))
    .bind(now_rfc3339())
    .execute(pool)
    .await
    .with_context(|| format!("clear_star_by_identity failed for {did}"))?;
    Ok(res.rows_affected())
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

/// Test-only unbounded convenience wrappers over [`list_entries`].
///
/// Production code passes an explicit `limit`, because that is the whole point
/// of the change these replaced. Fixtures hold a handful of rows and asserting
/// on "the whole list" is what the tests actually mean, so they get a helper
/// with a stated ceiling instead of each spelling one out — and the ceiling is
/// high enough that a test hitting it is a broken fixture, not a truncation.
#[cfg(test)]
mod test_helpers {
    use super::*;

    /// Far above any fixture; a test that reaches it has a bug of its own.
    const FIXTURE_MAX: i64 = 10_000;

    pub(crate) async fn entries_for_feed(
        pool: &SqlitePool,
        did: &str,
        feed_id: i64,
    ) -> Result<Vec<EntryListRow>> {
        list_entries(pool, did, ListView::All, Some(&[feed_id]), FIXTURE_MAX, 0).await
    }

    pub(crate) async fn get_unread_for_did(
        pool: &SqlitePool,
        did: &str,
    ) -> Result<Vec<EntryListRow>> {
        list_entries(pool, did, ListView::Unread, None, FIXTURE_MAX, 0).await
    }

    pub(crate) async fn get_starred_for_did(
        pool: &SqlitePool,
        did: &str,
    ) -> Result<Vec<EntryListRow>> {
        list_entries(pool, did, ListView::Starred, None, FIXTURE_MAX, 0).await
    }
}

#[cfg(test)]
pub(crate) use test_helpers::{entries_for_feed, get_starred_for_did, get_unread_for_did};

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

// ---------------------------------------------------------------------------
// Network observations (the adoption probe's projection)
// ---------------------------------------------------------------------------

/// Record one relay's observation, keyed by `(key, source)` so each relay's
/// number is kept separately (non-archival relays legitimately disagree).
///
/// A plain upsert: the table is bounded forever at (metrics × relays) rows — two
/// today — so this can never grow the DB. It must stay a plain upsert and never
/// become a per-DID insert.
pub async fn record_network_stat(pool: &SqlitePool, stat: &NetworkStat) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO network_stat (key, source, value, truncated, observed_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT (key, source) DO UPDATE SET
            value       = excluded.value,
            truncated   = excluded.truncated,
            observed_at = excluded.observed_at
        "#,
    )
    .bind(&stat.key)
    .bind(&stat.source)
    .bind(stat.value)
    .bind(stat.truncated)
    .bind(&stat.observed_at)
    .execute(pool)
    .await
    .with_context(|| {
        format!(
            "record_network_stat failed for {}/{}",
            stat.key, stat.source
        )
    })?;
    Ok(())
}

/// The highest observation for `key` across every relay — the number to surface
/// (`design/NETWORK-SPEC.md` §4.1: relays disagree; show the max). `None` when no
/// probe has ever succeeded.
pub async fn latest_network_stat(pool: &SqlitePool, key: &str) -> Result<Option<NetworkStat>> {
    let stat = sqlx::query_as::<_, NetworkStat>(
        "SELECT key, source, value, truncated, observed_at FROM network_stat \
         WHERE key = ?1 ORDER BY value DESC, observed_at DESC LIMIT 1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await
    .with_context(|| format!("latest_network_stat failed for {key}"))?;
    Ok(stat)
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
// Ported in SHAPE from a prior Go beta-gate (RedeemCode / CreateInviteCode /
// code_gen) but deliberately trimmed for FeatherReader's before-public
// experiment: NO viral invite-budget tree, NO generation cap, NO waitlist /
// invite-request table, and SQLite instead of Mongo. A code is minted by an
// existing member (or admin), and redeeming it grants a seat while seats remain
// under the configured cap.

/// Unix-epoch seconds for "now" — the integer time base for the beta tables.
pub(crate) fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The invite-code alphabet: uppercase letters + digits with the
/// visually-ambiguous glyphs removed (`I`, `O`, `0`, `1`) so a code read aloud
/// or copied by hand is unambiguous.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Human-facing prefix so a FeatherReader invite code is recognisable at a
/// glance.
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

/// Count `active`, unexpired invite codes — the outstanding-but-unredeemed seats
/// a bot has already promised. Added to [`count_beta_access`] this is the "seats
/// committed" figure the bot mint path (`POST /bot/claims`) checks against the
/// cap, so it doesn't over-promise more claims than seats remain (the redeem-time
/// cap in [`redeem_code`] is the hard backstop; this avoids telling a follower
/// "you're in" for a seat that will be full by the time they claim it).
pub async fn count_active_codes(pool: &SqlitePool) -> Result<i64> {
    let now = now_unix();
    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM invite_codes WHERE status = 'active' AND expires_at >= ?1",
    )
    .bind(now)
    .fetch_one(pool)
    .await
    .context("count_active_codes failed")?;
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
/// from now. Returns the generated code string. The browser/admin path leaves the
/// bot idempotency key (`intended_did`) NULL; see [`mint_code_for_did`] for the
/// bot path that records the target follower.
pub async fn mint_code(pool: &SqlitePool, creator_did: &str, ttl_secs: i64) -> Result<String> {
    mint_code_inner(pool, creator_did, ttl_secs, None).await
}

/// Like [`mint_code`] but records the follower `intended_did` the code is minted
/// FOR, so a later `POST /bot/claims` for the same DID can return the SAME code
/// (see [`find_active_code_for_did`]) rather than minting a duplicate. This is the
/// app-side idempotency backstop that survives a bot-host state loss.
pub async fn mint_code_for_did(
    pool: &SqlitePool,
    creator_did: &str,
    ttl_secs: i64,
    intended_did: &str,
) -> Result<String> {
    mint_code_inner(pool, creator_did, ttl_secs, Some(intended_did)).await
}

async fn mint_code_inner(
    pool: &SqlitePool,
    creator_did: &str,
    ttl_secs: i64,
    intended_did: Option<&str>,
) -> Result<String> {
    let code = generate_invite_code()?;
    let now = now_unix();
    let expires_at = now.saturating_add(ttl_secs.max(0));
    sqlx::query(
        r#"
        INSERT INTO invite_codes
            (code, creator_did, status, invitee_did, intended_did, created_at, expires_at, redeemed_at)
        VALUES (?1, ?2, 'active', NULL, ?3, ?4, ?5, NULL)
        "#,
    )
    .bind(&code)
    .bind(creator_did)
    .bind(intended_did)
    .bind(now)
    .bind(expires_at)
    .execute(pool)
    .await
    .with_context(|| format!("mint_code failed for creator {creator_did}"))?;
    Ok(code)
}

/// Does this error chain represent the partial-unique-index conflict raised when
/// a SECOND active claim is minted for a DID that already has one
/// (`idx_invite_codes_intended_active`)? The web layer uses this to recover from a
/// lost mint race (S4): on a conflict it re-reads the winner's code instead of
/// 500-ing. Matches on the sqlx `Database` error's UNIQUE-constraint code (SQLite
/// 2067 / primary 19) AND the offending COLUMN in the message
/// (`invite_codes.intended_did` — SQLite names the column(s), not the index), so an
/// unrelated constraint violation (e.g. the `code` PRIMARY KEY) is NOT swallowed.
pub fn is_intended_active_conflict(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(sqlx::Error::Database(db)) = cause.downcast_ref::<sqlx::Error>() {
            let msg = db.message();
            // SQLite reports UNIQUE violations with (primary) code 19 /
            // (extended) 2067; the message names the offending column(s), e.g.
            // "UNIQUE constraint failed: invite_codes.intended_did".
            let is_unique = db.code().as_deref() == Some("2067")
                || db.code().as_deref() == Some("19")
                || msg.contains("UNIQUE constraint failed");
            // Scope to the intended_did index specifically. Only that index and the
            // `code` PRIMARY KEY can raise a UNIQUE error here; the partial unique
            // index is the only one over `intended_did`, so the column reference
            // uniquely identifies it.
            if is_unique && msg.contains("invite_codes.intended_did") {
                return true;
            }
        }
    }
    false
}

/// The `code` of an outstanding (`active`, unexpired) invite minted FOR the
/// follower `intended_did`, if one exists — the app-side idempotency lookup for
/// `POST /bot/claims`. `Some(code)` means "return this existing code, do NOT mint
/// a second"; `None` means "no live code for this DID — mint one".
///
/// S3 — this lookup ONLY returns `active`, UNEXPIRED codes; once a code passes
/// `expires_at` (or `expire_old_codes` flips it to `expired`) this returns `None`,
/// so the next `POST /bot/claims` MINTS A FRESH code for the DID. There is no
/// in-place "refresh" of an expired code (the partial-unique index only constrains
/// `active` rows, so a fresh mint after expiry is allowed). The bot then re-posts:
/// its record rkey is deterministic per DID, so the existing skeet is UPDATED in
/// place with the new claim URL (see the bot's `reconcile_stale_record`, S1) rather
/// than a second skeet being posted. NOTE: a bot-`delivered` follower whose link
/// expired UNCLAIMED is only re-minted if the bot re-processes that DID (a re-seen
/// follow, a `waitlisted` retry, or a bot-store reset); manual recovery is to clear
/// the bot's `handled` row for that DID so the next cycle re-mints + re-posts.
/// If several live codes somehow exist (a race), the soonest-expiring is returned.
pub async fn find_active_code_for_did(
    pool: &SqlitePool,
    intended_did: &str,
) -> Result<Option<String>> {
    let now = now_unix();
    let row = sqlx::query(
        "SELECT code FROM invite_codes
         WHERE intended_did = ?1 AND status = 'active' AND expires_at >= ?2
         ORDER BY expires_at ASC
         LIMIT 1",
    )
    .bind(intended_did)
    .bind(now)
    .fetch_optional(pool)
    .await
    .with_context(|| format!("find_active_code_for_did failed for {intended_did}"))?;
    Ok(row.map(|r| r.get::<String, _>("code")))
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

    // Take the write lock at the START of the transaction. sqlx issues a plain
    // deferred BEGIN, so without this the capacity SELECT below runs under a read
    // snapshot: two concurrent redeems could both pass the gate, and the loser's
    // later UPDATE would fail with SQLITE_BUSY_SNAPSHOT (which busy_timeout does
    // NOT retry) — an opaque error instead of a clean CapacityFull. A leading
    // no-op write against the target row acquires the RESERVED lock immediately
    // (SQLite locks on any write statement, even one matching zero rows), so the
    // second redeem blocks on the first, then reads the post-commit seat count
    // and returns CapacityFull. (The cap already held via snapshot isolation;
    // this upgrades the failure mode from a hard error to the right one.)
    sqlx::query("UPDATE invite_codes SET status = status WHERE code = ?1")
        .bind(code)
        .execute(&mut *tx)
        .await
        .context("redeem_code: acquire write lock")?;

    // 1. Look the code up.
    let row =
        sqlx::query("SELECT status, expires_at, intended_did FROM invite_codes WHERE code = ?1")
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
    let intended_did: Option<String> = row.get("intended_did");

    // DID-binding gate (blocker B2). A bot-minted claim link is posted PUBLICLY
    // with a non-confidential token, so anyone who sees a follower's reply could
    // redeem it with a throwaway account — defeating the follow-gate, the daily
    // sybil budget, and the rate limit. When the code was minted FOR a specific
    // follower (`intended_did IS NOT NULL`), only that DID may redeem it; anyone
    // else gets a `NotFound` (indistinguishable from a bad code — no oracle).
    // Codes with a NULL `intended_did` (admin/browser-minted) stay open, as
    // before — those are meant to be sharable.
    if let Some(bound) = intended_did.as_deref() {
        if bound != did {
            return Ok(Err(RedeemError::NotFound));
        }
    }

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

    // A departing DID may also be the TARGET of an outstanding bot claim
    // (`intended_did`, minted for them before they joined/left) — NULL it so no
    // per-DID residue survives. We ALSO expire the orphaned code in the same tx:
    // once `intended_did` is NULLed, an `active` row would otherwise keep counting
    // against the daily mint cap for its full 14-day TTL (and a re-follow would
    // double-count it), so `expired` it now. `redeemed`/already-`expired` rows are
    // untouched (the WHERE only matches `active`). (Cheap nit — purge orphan.)
    sqlx::query(
        "UPDATE invite_codes \
         SET intended_did = NULL, \
             status = CASE WHEN status = 'active' THEN 'expired' ELSE status END \
         WHERE intended_did = ?1",
    )
    .bind(did)
    .execute(&mut *tx)
    .await
    .with_context(|| format!("scrub intended_did for {did}"))?;

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

/// Aggregate poll health, for the public stats page.
///
/// **Deliberately aggregate-only.** No user counts, no error rates, no per-feed
/// detail: this is published to anyone, and a reader does not need to know how
/// many people use an instance or which feeds are failing. What it does answer
/// is the only question the page exists for — is the poller keeping up?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollHealth {
    /// Distinct feeds the poller is responsible for.
    pub feeds_tracked: i64,
    /// How many were polled within the last hour.
    pub polled_last_hour: i64,
    /// Feeds whose `next_poll` has passed — the backlog. A healthy instance
    /// clears this every tick; a growing number is the signal that the poller
    /// cannot keep up with the feed count.
    pub overdue: i64,
    /// Seconds since the most recent poll of any feed. `None` before the first.
    pub last_poll_secs_ago: Option<i64>,
    /// Seconds since the LEAST recently polled feed was polled — the worst
    /// staleness any reader is currently seeing.
    ///
    /// `None` when any feed has NEVER been polled, because that is a worse
    /// staleness than any finite age and reporting the finite one would make
    /// the page read healthiest exactly when it is least healthy.
    pub oldest_poll_secs_ago: Option<i64>,
    /// How many feeds have never been polled at all.
    pub never_polled: i64,
    /// Feeds currently in error backoff (`consecutive_errors > 0`).
    ///
    /// One of the two states that stop feeds updating, and previously visible
    /// nowhere: `consecutive_errors` was written by `bump_feed_errors` and read
    /// by nothing outside the backoff calculation — no page, no endpoint. Worse,
    /// a feed in backoff is NOT counted in `overdue`, because backoff is applied
    /// by pushing `next_poll` forward. So the one number a reader might have
    /// checked moved the wrong way: a feed failing every fetch made `overdue`
    /// look BETTER.
    pub in_backoff: i64,
    /// Of those, how many have failed enough times to be at or near the backoff
    /// ceiling — the ones that will not recover on their own.
    pub badly_broken: i64,
}

/// `consecutive_errors` at or above which a feed counts as `badly_broken`.
///
/// Chosen to mean "this is not a transient blip": `feed::backoff_for` climbs
/// exponentially, so by this many consecutive failures a feed is being retried
/// hours apart and is almost certainly gone rather than flaky.
const BADLY_BROKEN_ERRORS: i64 = 6;

/// Compute [`PollHealth`] as of `now` (RFC3339, seconds precision — the same
/// format the scheduler writes, so the comparisons are lexicographic).
pub async fn poll_health(pool: &SqlitePool, now: &str, hour_ago: &str) -> Result<PollHealth> {
    #[allow(clippy::type_complexity)]
    let row: (i64, i64, i64, Option<String>, Option<String>, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*),
            COALESCE(SUM(CASE WHEN last_polled IS NOT NULL AND last_polled >= ?2 THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN next_poll IS NULL OR next_poll <= ?1 THEN 1 ELSE 0 END), 0),
            MAX(last_polled),
            -- NULL-AWARE. `MIN` skips NULLs, so an instance where most feeds
            -- had NEVER been polled reported the freshest of the few that had —
            -- the figure read healthiest in the most degraded state, which is
            -- the opposite of what a health page is for. A never-polled feed IS
            -- the worst staleness, so it wins outright.
            CASE WHEN SUM(CASE WHEN last_polled IS NULL THEN 1 ELSE 0 END) > 0
                 THEN NULL ELSE MIN(last_polled) END,
            SUM(CASE WHEN last_polled IS NULL THEN 1 ELSE 0 END),
            COALESCE(SUM(CASE WHEN consecutive_errors > 0 THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN consecutive_errors >= ?3 THEN 1 ELSE 0 END), 0)
        FROM feeds
        "#,
    )
    .bind(now)
    .bind(hour_ago)
    .bind(BADLY_BROKEN_ERRORS)
    .fetch_one(pool)
    .await
    .context("computing poll health")?;

    Ok(PollHealth {
        feeds_tracked: row.0,
        polled_last_hour: row.1,
        overdue: row.2,
        last_poll_secs_ago: secs_between(row.3.as_deref(), now),
        oldest_poll_secs_ago: secs_between(row.4.as_deref(), now),
        never_polled: row.5,
        in_backoff: row.6,
        badly_broken: row.7,
    })
}

/// Whole seconds from `then` to `now`, or `None` if `then` is absent or
/// unparseable. Never negative: a clock skew that puts a poll in the future
/// reads as "just now" rather than as a negative age.
fn secs_between(then: Option<&str>, now: &str) -> Option<i64> {
    let then = chrono::DateTime::parse_from_rfc3339(then?).ok()?;
    let now = chrono::DateTime::parse_from_rfc3339(now).ok()?;
    Some((now - then).num_seconds().max(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A partial upsert must not erase the conditional-GET validators.
    ///
    /// `set_next_poll` supplies only `url` + `next_poll` and runs after EVERY
    /// poll of EVERY feed. While `upsert_feed` assigned etag/last_modified
    /// unconditionally, that call wrote both back to NULL, so `If-None-Match`
    /// was never sent, `304` was unreachable, and every feed was re-downloaded
    /// and re-parsed in full on every cycle. Nothing failed; it was invisible.
    #[tokio::test]
    async fn validators_survive_a_partial_upsert() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let url = "https://example.com/feed.xml";

        upsert_feed(
            &pool,
            &NewFeed {
                url: url.to_string(),
                etag: Some("\"abc123\"".to_string()),
                last_modified: Some("Wed, 01 Jan 2026 00:00:00 GMT".to_string()),
                ..Default::default()
            },
        )
        .await?;

        // Exactly what `scheduler::set_next_poll` sends.
        upsert_feed(
            &pool,
            &NewFeed {
                url: url.to_string(),
                next_poll: Some("2026-07-12T00:00:00Z".to_string()),
                ..Default::default()
            },
        )
        .await?;

        let feed = get_feed_by_url(&pool, url).await?.expect("feed");
        assert_eq!(
            feed.etag.as_deref(),
            Some("\"abc123\""),
            "a partial upsert erased the ETag, disabling conditional GET"
        );
        assert_eq!(
            feed.last_modified.as_deref(),
            Some("Wed, 01 Jan 2026 00:00:00 GMT"),
            "a partial upsert erased Last-Modified"
        );
        assert_eq!(feed.next_poll.as_deref(), Some("2026-07-12T00:00:00Z"));
        Ok(())
    }

    /// A hard ceiling that is not strictly older than the window is IGNORED.
    ///
    /// `hard_days.max(days)` made `0` — the obvious "off" value, and the
    /// documented disable value for `RETENTION_DAYS` — collapse the ceiling onto
    /// the soft window, where the delete spares nothing. The starred and unread
    /// rows the window exists to protect were purged at `retention_days`.
    #[tokio::test]
    async fn a_ceiling_inside_the_window_is_ignored_not_applied() -> Result<()> {
        for hard in [0_i64, 1, 7, 14] {
            let pool = init_url("sqlite::memory:").await?;
            let feed_id = upsert_feed(
                &pool,
                &NewFeed {
                    url: "https://example.com/f.xml".to_string(),
                    ..Default::default()
                },
            )
            .await?;
            let old = (chrono::Utc::now() - chrono::Duration::days(30))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            insert_entries(
                &pool,
                feed_id,
                &[
                    NewEntry {
                        guid: "starred-30d".to_string(),
                        published: Some(old.clone()),
                        ..Default::default()
                    },
                    NewEntry {
                        guid: "unread-30d".to_string(),
                        published: Some(old.clone()),
                        ..Default::default()
                    },
                ],
                0,
            )
            .await?;
            // Both need an explicit `entry_state` row: sparing keys off a
            // DELIBERATE mark, and an entry with no row at all is unclaimed
            // cache that the window is supposed to evict.
            sqlx::query(
                "INSERT INTO entry_state (did, entry_id, read, starred, updated_at)
                 SELECT 'did:plc:x', id, 1, 1, '2026-01-01T00:00:00Z'
                 FROM entries WHERE guid = 'starred-30d'",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO entry_state (did, entry_id, read, starred, updated_at)
                 SELECT 'did:plc:x', id, 0, 0, '2026-01-01T00:00:00Z'
                 FROM entries WHERE guid = 'unread-30d'",
            )
            .execute(&pool)
            .await?;

            prune_old_entries(&pool, 14, hard).await?;

            let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
                .fetch_one(&pool)
                .await?;
            assert_eq!(
                left, 2,
                "hard_days={hard} destroyed starred/unread rows at the soft window"
            );
        }
        Ok(())
    }

    /// Turning the rolling window off must NOT also turn the ceiling off.
    ///
    /// `prune_old_entries` used to return on `days <= 0` before the ceiling was
    /// even computed, so `RETENTION_DAYS=0` — advertised as "disables eviction" —
    /// meant no window AND no ceiling. That is the one configuration with no
    /// bound on the shared cache at all, and it stopped being survivable when the
    /// per-feed trim started sparing starred entries: nothing was left to catch
    /// them. The two knobs are independent now.
    #[tokio::test]
    async fn a_disabled_window_does_not_disable_the_ceiling() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://example.com/f.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;
        let age = |d: i64| {
            (chrono::Utc::now() - chrono::Duration::days(d))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        };
        insert_entries(
            &pool,
            feed_id,
            &[
                NewEntry {
                    guid: "starred-400d".to_string(),
                    published: Some(age(400)),
                    ..Default::default()
                },
                NewEntry {
                    guid: "starred-30d".to_string(),
                    published: Some(age(30)),
                    ..Default::default()
                },
            ],
            0,
        )
        .await?;
        // Star both, so only the ceiling can remove either one — the soft
        // window's exception would spare them both even if it did run.
        sqlx::query(
            "INSERT INTO entry_state (did, entry_id, read, starred, updated_at)
             SELECT 'did:plc:x', id, 1, 1, '2026-01-01T00:00:00Z' FROM entries",
        )
        .execute(&pool)
        .await?;

        // No rolling window; a 180-day ceiling.
        let deleted = prune_old_entries(&pool, 0, 180).await?;

        assert_eq!(
            deleted, 1,
            "retention_days=0 skipped the hard ceiling, leaving the cache unbounded"
        );
        let left: Vec<String> = sqlx::query_scalar("SELECT guid FROM entries ORDER BY guid")
            .fetch_all(&pool)
            .await?;
        assert_eq!(
            left,
            vec!["starred-30d".to_string()],
            "the ceiling removed the wrong rows with the window disabled"
        );
        Ok(())
    }

    /// With BOTH knobs off, nothing is deleted — that is the documented
    /// "no eviction at all" configuration, and it must stay a true no-op rather
    /// than falling through to one of the two deletes with a degenerate cutoff.
    #[tokio::test]
    async fn both_knobs_off_deletes_nothing() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://example.com/f.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;
        insert_entries(
            &pool,
            feed_id,
            &[NewEntry {
                guid: "ancient".to_string(),
                published: Some(
                    (chrono::Utc::now() - chrono::Duration::days(9999))
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                ),
                ..Default::default()
            }],
            0,
        )
        .await?;

        assert_eq!(prune_old_entries(&pool, 0, 0).await?, 0);
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(&pool)
            .await?;
        assert_eq!(left, 1);
        Ok(())
    }

    /// Starred sparing must not remove the per-feed cap.
    ///
    /// The first version spared every starred row without limit: at cap=5 with
    /// 50 starred entries, 55 survived — 11x the cap, i.e. no cap at all.
    #[tokio::test]
    async fn per_feed_trim_stays_bounded_when_everything_is_starred() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://example.com/f.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;
        let entries: Vec<NewEntry> = (0..100)
            .map(|i| NewEntry {
                guid: format!("g-{i}"),
                published: Some(format!("2026-01-{:02}T00:00:00Z", (i % 28) + 1)),
                ..Default::default()
            })
            .collect();
        insert_entries(&pool, feed_id, &entries, 0).await?;
        sqlx::query(
            "INSERT INTO entry_state (did, entry_id, read, starred, updated_at)
             SELECT 'did:plc:x', id, 0, 1, '2026-01-01T00:00:00Z'
             FROM entries LIMIT 50",
        )
        .execute(&pool)
        .await?;

        // Re-run the trim with cap = 5.
        insert_entries(&pool, feed_id, &[], 5).await?;

        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(&pool)
            .await?;
        assert!(
            left <= 10,
            "per-feed trim kept {left} rows for a cap of 5; sparing removed the bound"
        );
        Ok(())
    }

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
        // The body is stored, but it is NOT in the list projection — that is the
        // point of `EntryListRow`. Read it the way the single-entry reader does.
        let body: Option<String> =
            sqlx::query_scalar("SELECT content_html FROM entries WHERE guid = 'guid-1'")
                .fetch_one(&pool)
                .await?;
        assert_eq!(body.as_deref(), Some("<p>hello</p>"));

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
    // The bounded, body-free list projection.
    //
    // The three queries these replaced were `SELECT e.*` with no `LIMIT`. Both
    // halves of that are load-bearing on a 512 MB box: the projection dragged
    // an ~11.9 KB article body per row that no list surface reads, and the
    // missing bound let one reader's backlog decide how much a handler
    // allocates.
    // -----------------------------------------------------------------------

    /// Seed `count` entries in one feed, each with a large body, subscribed by
    /// `did`. Returns the feed id.
    async fn seed_big_entries(pool: &SqlitePool, did: &str, count: usize) -> Result<i64> {
        let feed_id = upsert_feed(
            pool,
            &NewFeed {
                url: "https://example.com/big.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;
        let body = "x".repeat(20_000);
        let entries: Vec<NewEntry> = (0..count)
            .map(|i| NewEntry {
                guid: format!("guid-{i:04}"),
                url: Some(format!("https://example.com/a/{i}")),
                title: Some(format!("Article {i}")),
                // Descending guid order matches descending published order, so
                // assertions can name the rows they expect.
                published: Some(format!("2026-01-{:02}T00:00:00Z", (i % 28) + 1)),
                content_html: Some(body.clone()),
                ..Default::default()
            })
            .collect();
        insert_entries(pool, feed_id, &entries, 0).await?;
        replace_sub_refs(pool, did, &[feed_id]).await?;
        Ok(feed_id)
    }

    /// `limit` is honoured, and `offset` walks the same ordering without gaps or
    /// repeats. Against the unbounded originals the first assertion returned all
    /// 250 rows.
    #[tokio::test]
    async fn list_entries_is_bounded_and_pages_without_overlap() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:pager";
        seed_big_entries(&pool, did, 250).await?;

        let page1 = list_entries(&pool, did, ListView::All, None, 100, 0).await?;
        assert_eq!(page1.len(), 100, "limit was not applied");
        let page2 = list_entries(&pool, did, ListView::All, None, 100, 100).await?;
        let page3 = list_entries(&pool, did, ListView::All, None, 100, 200).await?;
        assert_eq!(page3.len(), 50, "the last page should be the remainder");

        let walked: Vec<i64> = page1
            .iter()
            .chain(&page2)
            .chain(&page3)
            .map(|e| e.id)
            .collect();
        let unique: std::collections::HashSet<i64> = walked.iter().copied().collect();
        assert_eq!(unique.len(), 250, "paging repeated or skipped rows");

        // And the walk is the same order an unpaged read would produce.
        let whole = list_entries(&pool, did, ListView::All, None, 1_000, 0).await?;
        assert_eq!(
            walked,
            whole.iter().map(|e| e.id).collect::<Vec<_>>(),
            "paging changed the ordering"
        );

        assert_eq!(
            count_entries_for_view(&pool, did, ListView::All, None).await?,
            250,
            "the unpaged count must survive paging"
        );
        Ok(())
    }

    /// The list projection must not read `content_html`.
    ///
    /// A type-level fact — `EntryListRow` has no body field — so the test proves
    /// it the only way that survives a refactor: by asking SQLite what the query
    /// it runs actually names. `SELECT e.*` would list every column.
    #[tokio::test]
    async fn the_list_projection_does_not_name_the_body_column() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:projection";
        seed_big_entries(&pool, did, 3).await?;

        // Ask the engine directly: EXPLAIN the query and read back its output
        // column names.
        let (sql, _) = list_query_sql(
            "e.id, e.feed_id, e.guid, e.url, e.title, e.published, \
             COALESCE(s.read, 0) AS read, COALESCE(s.starred, 0) AS starred",
            ListView::All,
            None,
        );
        assert!(
            !sql.contains("content_html") && !sql.contains("e.*"),
            "the list query reads the article body: {sql}"
        );

        // And the rows really do come back without it, which is what bounds the
        // per-request allocation.
        let rows = list_entries(&pool, did, ListView::All, None, 10, 0).await?;
        assert_eq!(rows.len(), 3);
        let widest = rows
            .iter()
            .map(|r| {
                r.guid.len()
                    + r.url.as_deref().map_or(0, str::len)
                    + r.title.as_deref().map_or(0, str::len)
            })
            .max()
            .unwrap_or(0);
        assert!(
            widest < 1_000,
            "a list row carries {widest} bytes of text; the 20,000-byte body leaked in"
        );
        Ok(())
    }

    /// Scope is applied INSIDE the query, so a page is a page of rows the reader
    /// will see. Filtering after the `LIMIT` (what the handler used to do) made
    /// pages arbitrarily short for any narrowed scope.
    #[tokio::test]
    async fn a_feed_scope_narrows_the_query_not_the_page() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:scope";
        let wanted = seed_big_entries(&pool, did, 10).await?;

        let other = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://other.example/f.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;
        let noise: Vec<NewEntry> = (0..40)
            .map(|i| NewEntry {
                guid: format!("noise-{i}"),
                // Newer than everything in `wanted`, so an unscoped query would
                // fill the whole page with these.
                published: Some("2027-01-01T00:00:00Z".to_string()),
                ..Default::default()
            })
            .collect();
        insert_entries(&pool, other, &noise, 0).await?;
        replace_sub_refs(&pool, did, &[wanted, other]).await?;

        let scoped = list_entries(&pool, did, ListView::All, Some(&[wanted]), 10, 0).await?;
        assert_eq!(
            scoped.len(),
            10,
            "the scoped page came back short — the filter ran after the LIMIT"
        );
        assert!(scoped.iter().all(|e| e.feed_id == wanted));

        // An EMPTY scope means "no feeds in scope", not "every feed".
        assert!(list_entries(&pool, did, ListView::All, Some(&[]), 10, 0)
            .await?
            .is_empty());
        assert_eq!(
            count_entries_for_view(&pool, did, ListView::All, Some(&[])).await?,
            0
        );
        Ok(())
    }

    /// The per-row `read` / `starred` bits come off the row's own join, matching
    /// what the separate full-set queries used to compute — including the
    /// "no `entry_state` row means unread" rule the views depend on.
    #[tokio::test]
    async fn list_rows_carry_their_own_read_and_star_bits() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:bits";
        seed_big_entries(&pool, did, 3).await?;
        let ids: Vec<i64> = list_entries(&pool, did, ListView::All, None, 10, 0)
            .await?
            .iter()
            .map(|e| e.id)
            .collect();

        mark_read(&pool, did, ids[0], true).await?;
        mark_starred(&pool, did, ids[1], true).await?;

        let all = list_entries(&pool, did, ListView::All, None, 10, 0).await?;
        let by_id = |id: i64| all.iter().find(|e| e.id == id).expect("row present");
        assert!(by_id(ids[0]).read && !by_id(ids[0]).starred);
        assert!(!by_id(ids[1]).read && by_id(ids[1]).starred);
        // Never touched: no state row at all, which must read as unread.
        assert!(!by_id(ids[2]).read && !by_id(ids[2]).starred);

        // And the view predicates agree with the bits.
        let unread = list_entries(&pool, did, ListView::Unread, None, 10, 0).await?;
        assert_eq!(unread.len(), 2);
        assert!(unread.iter().all(|e| !e.read));
        let starred = list_entries(&pool, did, ListView::Starred, None, 10, 0).await?;
        assert_eq!(starred.len(), 1);
        assert_eq!(starred[0].id, ids[1]);
        Ok(())
    }

    /// The sidebar's per-feed unread badges, counted in SQL rather than by
    /// materializing every unread entry and filtering in Rust.
    #[tokio::test]
    async fn unread_counts_are_per_feed_and_exclude_read_rows() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:counts";
        let a = seed_big_entries(&pool, did, 5).await?;
        let b = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://b.example/f.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;
        insert_entries(
            &pool,
            b,
            &[
                NewEntry {
                    guid: "b-1".to_string(),
                    ..Default::default()
                },
                NewEntry {
                    guid: "b-2".to_string(),
                    ..Default::default()
                },
            ],
            0,
        )
        .await?;
        replace_sub_refs(&pool, did, &[a, b]).await?;

        let first_a = list_entries(&pool, did, ListView::All, Some(&[a]), 1, 0).await?[0].id;
        mark_read(&pool, did, first_a, true).await?;

        let counts = unread_counts_by_feed(&pool, did).await?;
        assert_eq!(counts.get(&a).copied(), Some(4));
        assert_eq!(counts.get(&b).copied(), Some(2));

        // A feed the DID does not subscribe to contributes nothing.
        replace_sub_refs(&pool, did, &[b]).await?;
        let counts = unread_counts_by_feed(&pool, did).await?;
        assert_eq!(counts.get(&a), None);
        assert_eq!(counts.get(&b).copied(), Some(2));
        Ok(())
    }

    /// **Read-state compaction: the water-mark must absorb the id set.**
    ///
    /// `read_through` was never computed, so `read_ids` was the only mechanism
    /// and grew one id per article read against a 2000-entry per-feed ceiling —
    /// while the flusher truncates the record at 1000, keeping the tail. Past
    /// 1000 read articles in a feed, the oldest read-state stopped syncing and
    /// those articles came back UNREAD in every other atproto reader.
    #[tokio::test]
    async fn compaction_folds_read_ids_into_the_water_mark() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:compact";
        let feed_url = "https://compact.example/f.xml";
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: feed_url.to_string(),
                ..Default::default()
            },
        )
        .await?;
        // 40 entries, oldest first by published date.
        let entries: Vec<NewEntry> = (0..40)
            .map(|i| NewEntry {
                guid: format!("c-{i:03}"),
                published: Some(format!("2026-01-{:02}T00:00:00Z", i + 1)),
                ..Default::default()
            })
            .collect();
        insert_entries(&pool, feed_id, &entries, 0).await?;
        replace_sub_refs(&pool, did, &[feed_id]).await?;

        let all = list_entries(&pool, did, ListView::All, None, 100, 0).await?;
        // Oldest first, so the read prefix is contiguous from the start.
        let mut oldest_first = all.clone();
        oldest_first.reverse();
        for row in oldest_first.iter().take(30) {
            mark_read(&pool, did, row.id, true).await?;
        }

        let before = get_cursor(&pool, did, feed_url).await?.expect("cursor");
        assert!(before.read_through.is_none(), "read_through starts unset");
        let before_ids: Vec<String> = serde_json::from_str(&before.read_ids)?;
        assert_eq!(before_ids.len(), 30, "every read is its own exception");

        let watermark = compact_cursor(&pool, did, feed_url)
            .await?
            .expect("the water-mark must advance");

        let after = get_cursor(&pool, did, feed_url).await?.expect("cursor");
        assert_eq!(after.read_through.as_deref(), Some(watermark.as_str()));
        let after_ids: Vec<String> = serde_json::from_str(&after.read_ids)?;
        assert!(
            after_ids.is_empty(),
            "a contiguous read prefix must fold entirely into the water-mark, left {after_ids:?}"
        );
        // The 30th entry is read and the 31st is not, so the mark sits on the
        // 30th — STRICTLY below the oldest unread, never equal to it.
        assert_eq!(watermark, "2026-01-30T00:00:00Z");
        assert!(after.dirty, "a rewritten cursor must be re-flushed");
        Ok(())
    }

    /// The water-mark may never cover an unread entry, and may never move
    /// backwards. Both would re-assert articles as read that are not.
    #[tokio::test]
    async fn compaction_stops_below_the_oldest_unread_entry() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:gap";
        let feed_url = "https://gap.example/f.xml";
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: feed_url.to_string(),
                ..Default::default()
            },
        )
        .await?;
        let entries: Vec<NewEntry> = (0..10)
            .map(|i| NewEntry {
                guid: format!("g-{i:02}"),
                published: Some(format!("2026-02-{:02}T00:00:00Z", i + 1)),
                ..Default::default()
            })
            .collect();
        insert_entries(&pool, feed_id, &entries, 0).await?;
        replace_sub_refs(&pool, did, &[feed_id]).await?;

        let mut oldest_first = list_entries(&pool, did, ListView::All, None, 100, 0).await?;
        oldest_first.reverse();
        // Read everything EXCEPT the third-oldest: a hole at 2026-02-03.
        for (i, row) in oldest_first.iter().enumerate() {
            if i != 2 {
                mark_read(&pool, did, row.id, true).await?;
            }
        }

        let watermark = compact_cursor(&pool, did, feed_url)
            .await?
            .expect("advances");
        assert_eq!(
            watermark, "2026-02-02T00:00:00Z",
            "the water-mark jumped the unread hole"
        );
        let after = get_cursor(&pool, did, feed_url).await?.expect("cursor");
        let kept: Vec<String> = serde_json::from_str(&after.read_ids)?;
        assert_eq!(
            kept.len(),
            7,
            "the 7 reads ABOVE the hole must stay as explicit exceptions"
        );
        // The unread hole is above the water-mark, so it needs no unread
        // exception — everything above the mark is unread by default.
        let unread: Vec<String> = serde_json::from_str(&after.unread_ids)?;
        assert!(
            unread.is_empty(),
            "redundant unread exceptions survived: {unread:?}"
        );

        // Idempotent, and never backwards: re-running changes nothing.
        assert_eq!(
            compact_cursor(&pool, did, feed_url).await?,
            None,
            "a second compaction moved a water-mark that was already correct"
        );
        Ok(())
    }

    /// Nothing read yet, or nothing in the feed: compaction must be a no-op
    /// rather than inventing a water-mark that asserts the backlog is read.
    #[tokio::test]
    async fn compaction_never_invents_a_water_mark() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:none";
        let feed_url = "https://none.example/f.xml";
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: feed_url.to_string(),
                ..Default::default()
            },
        )
        .await?;
        replace_sub_refs(&pool, did, &[feed_id]).await?;

        // Empty feed: no entries at all.
        assert_eq!(compact_cursor(&pool, did, feed_url).await?, None);

        insert_entries(
            &pool,
            feed_id,
            &[
                NewEntry {
                    guid: "n-1".to_string(),
                    published: Some("2026-03-01T00:00:00Z".to_string()),
                    ..Default::default()
                },
                NewEntry {
                    guid: "n-2".to_string(),
                    published: Some("2026-03-02T00:00:00Z".to_string()),
                    ..Default::default()
                },
            ],
            0,
        )
        .await?;

        // Nothing read: the OLDEST entry is unread, so there is no timestamp
        // strictly below it and the mark cannot move at all.
        assert_eq!(
            compact_cursor(&pool, did, feed_url).await?,
            None,
            "a water-mark appeared with nothing read — that asserts the backlog is read"
        );
        Ok(())
    }

    /// **The unsave desync: clearing a star must work for an UNSUBSCRIBED feed.**
    ///
    /// That is the whole case. Every other starred path is `sub_ref`-scoped, so
    /// an entry that is cached AND starred in a feed the reader has since
    /// unsubscribed from is invisible to all of them — including the starred
    /// list itself. Its PDS record therefore renders as "not cached", and the
    /// button on that row deletes the record. If clearing the local star were
    /// `sub_ref`-scoped too, it would silently do nothing, and the star would
    /// reappear with no record behind it the moment the reader resubscribed.
    #[tokio::test]
    async fn a_star_can_be_cleared_after_unsubscribing_from_its_feed() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:unsub";
        let feed_id = seed_big_entries(&pool, did, 3).await?;
        let rows = list_entries(&pool, did, ListView::All, None, 10, 0).await?;
        let target = rows[0].clone();
        mark_starred(&pool, did, target.id, true).await?;
        assert_eq!(get_starred_for_did(&pool, did).await?.len(), 1);

        // Unsubscribe. The entry stays cached and stays starred, but every
        // sub_ref-scoped read now skips it.
        replace_sub_refs(&pool, did, &[]).await?;
        assert!(
            get_starred_for_did(&pool, did).await?.is_empty(),
            "fixture precondition: the star must be invisible to the scoped read"
        );
        assert!(
            starred_identities(&pool, did, 1_000).await?.is_empty(),
            "fixture precondition: the identity lookup must miss it too"
        );
        let still_starred: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM entry_state WHERE did = ?1 AND starred = 1")
                .bind(did)
                .fetch_one(&pool)
                .await?;
        assert_eq!(
            still_starred, 1,
            "the star is still there, just unreachable"
        );

        // The removal path must reach it anyway.
        let cleared =
            clear_star_by_identity(&pool, did, target.url.as_deref(), Some(&target.guid)).await?;
        assert_eq!(cleared, 1, "the star survived the unsave");
        let after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM entry_state WHERE did = ?1 AND starred = 1")
                .bind(did)
                .fetch_one(&pool)
                .await?;
        assert_eq!(after, 0);

        // Resubscribing must NOT bring it back.
        replace_sub_refs(&pool, did, &[feed_id]).await?;
        assert!(
            get_starred_for_did(&pool, did).await?.is_empty(),
            "the star came back after resubscribing — the desync is still there"
        );
        Ok(())
    }

    /// It clears only the CALLER's star, and only for the matching article.
    ///
    /// Omitting `sub_ref` is safe precisely because `did` is not optional; this
    /// pins that, and that a non-matching identity is a no-op rather than a
    /// wildcard.
    #[tokio::test]
    async fn clearing_a_star_touches_only_that_did_and_that_article() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let mine = "did:plc:mine";
        let theirs = "did:plc:theirs";
        let feed_id = seed_big_entries(&pool, mine, 3).await?;
        replace_sub_refs(&pool, theirs, &[feed_id]).await?;
        let rows = list_entries(&pool, mine, ListView::All, None, 10, 0).await?;

        for r in &rows {
            mark_starred(&pool, mine, r.id, true).await?;
            mark_starred(&pool, theirs, r.id, true).await?;
        }

        let target = &rows[1];
        assert_eq!(
            clear_star_by_identity(&pool, mine, target.url.as_deref(), Some(&target.guid)).await?,
            1
        );

        let count = |did: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM entry_state WHERE did = ?1 AND starred = 1",
                )
                .bind(did)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        assert_eq!(count(mine).await, 2, "it cleared more than the one article");
        assert_eq!(count(theirs).await, 3, "it cleared another DID's stars");

        // An identity that matches nothing is a no-op, not a wildcard.
        assert_eq!(
            clear_star_by_identity(&pool, mine, Some("https://nope.example/x"), Some("nope"))
                .await?,
            0
        );
        assert_eq!(count(mine).await, 2);
        // And neither identifier present does nothing at all.
        assert_eq!(clear_star_by_identity(&pool, mine, None, None).await?, 0);
        assert_eq!(
            clear_star_by_identity(&pool, mine, Some(""), Some("")).await?,
            0
        );
        assert_eq!(count(mine).await, 2);
        Ok(())
    }

    /// `starred_identities` must span the WHOLE starred set, not a page.
    ///
    /// The starred view matches PDS saved records against it; a cached article
    /// missing from the set renders as "not cached", and that row's button
    /// deletes the PDS RECORD instead of un-starring the entry. Narrowing this
    /// set changes what a click destroys.
    #[tokio::test]
    async fn starred_identities_span_the_whole_set() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:ident";
        seed_big_entries(&pool, did, 150).await?;
        for row in list_entries(&pool, did, ListView::All, None, 1_000, 0).await? {
            mark_starred(&pool, did, row.id, true).await?;
        }

        let identities = starred_identities(&pool, did, 20_000).await?;
        assert_eq!(
            identities.len(),
            150,
            "the identity set was truncated to a page"
        );
        assert!(identities
            .iter()
            .all(|(url, guid)| url.is_some() && !guid.is_empty()));
        Ok(())
    }

    /// Prev/next ids are bounded too, and keep the list's ordering.
    #[tokio::test]
    async fn entry_ids_are_ordered_and_capped() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:ids";
        seed_big_entries(&pool, did, 60).await?;

        let capped = list_entry_ids(&pool, did, ListView::All, None, 25).await?;
        assert_eq!(capped.len(), 25);

        let rows = list_entries(&pool, did, ListView::All, None, 25, 0).await?;
        assert_eq!(
            capped,
            rows.iter().map(|e| e.id).collect::<Vec<_>>(),
            "the id list and the row list disagree on ordering"
        );
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
    async fn count_active_codes_excludes_expired_and_redeemed() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        assert_eq!(count_active_codes(&pool).await?, 0);

        // Two live codes.
        let a = mint_code(&pool, "did:plc:bot", 3600).await?;
        let _b = mint_code(&pool, "did:plc:bot", 3600).await?;
        assert_eq!(count_active_codes(&pool).await?, 2);

        // An expired code doesn't count.
        insert_expired_code(&pool, "FEATHER-EXPIRED0", "did:plc:bot").await?;
        assert_eq!(count_active_codes(&pool).await?, 2);

        // Redeeming one drops the active count.
        let out = redeem_code(&pool, &a, "did:plc:new", None, 100).await?;
        assert_eq!(out, Ok(()));
        assert_eq!(count_active_codes(&pool).await?, 1);
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

    /// A new on-disk database must be created in INCREMENTAL mode.
    ///
    /// This is the whole fix for new instances: `auto_vacuum` was read by
    /// `reclaim` and set nowhere, so every database ran in NONE and `reclaim`
    /// always took its full-`VACUUM` branch — the one that cannot complete on a
    /// volume under the pressure that triggered the sweep. The pragma only binds
    /// on a database with no tables yet, so "at creation" is the load-bearing
    /// part, not "somewhere in init".
    #[tokio::test]
    async fn a_new_database_is_created_in_incremental_vacuum_mode() -> Result<()> {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fr-autovac-{}.db", std::process::id()));
        for p in [
            path.display().to_string(),
            format!("{}-wal", path.display()),
            format!("{}-shm", path.display()),
        ] {
            std::fs::remove_file(&p).ok();
        }
        let pool = init_url(&format!("sqlite://{}", path.display())).await?;

        assert_eq!(
            auto_vacuum_mode(&pool).await?,
            AutoVacuum::Incremental,
            "a fresh database is still in the mode where reclaim needs a full VACUUM"
        );
        // And the WAL is bounded rather than growing to its high-water mark
        // forever.
        let limit: i64 = sqlx::query_scalar("PRAGMA journal_size_limit")
            .fetch_one(&pool)
            .await?;
        assert_eq!(
            limit, WAL_SIZE_LIMIT_BYTES,
            "journal_size_limit not applied"
        );

        // Being INCREMENTAL, the migration is a no-op — which is what makes the
        // flag safe for an operator to run without checking first.
        assert_eq!(
            migrate_to_incremental_vacuum(&pool, None).await?,
            VacuumMigration::NotNeeded(AutoVacuum::Incremental)
        );

        pool.close().await;
        for p in [
            path.display().to_string(),
            format!("{}-wal", path.display()),
            format!("{}-shm", path.display()),
        ] {
            std::fs::remove_file(&p).ok();
        }
        Ok(())
    }

    /// The migration refuses itself when the volume cannot hold the rebuild.
    ///
    /// A full `VACUUM` writes a complete second copy, so attempting one without
    /// headroom burns I/O on a box that has none and finishes nothing. Refusing
    /// is the entire reason this is an operator step rather than something
    /// `reclaim` does on its own.
    #[tokio::test]
    async fn the_vacuum_migration_refuses_without_headroom() -> Result<()> {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fr-autovac-none-{}.db", std::process::id()));
        for p in [
            path.display().to_string(),
            format!("{}-wal", path.display()),
            format!("{}-shm", path.display()),
        ] {
            std::fs::remove_file(&p).ok();
        }
        // Build a database the way one that predates this change looks: create
        // the file in NONE mode explicitly, then populate it.
        let url = format!("sqlite://{}", path.display());
        let opts = SqliteConnectOptions::from_str(&url)?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .auto_vacuum(sqlx::sqlite::SqliteAutoVacuum::None);
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect_with(opts)
            .await?;
        init_schema(&pool).await?;
        assert_eq!(auto_vacuum_mode(&pool).await?, AutoVacuum::None);

        // Zero free space: refused, and the mode is untouched.
        let refused = migrate_to_incremental_vacuum(&pool, Some(0)).await?;
        assert!(
            matches!(refused, VacuumMigration::RefusedNoHeadroom { .. }),
            "expected a refusal, got {refused:?}"
        );
        assert_eq!(
            auto_vacuum_mode(&pool).await?,
            AutoVacuum::None,
            "a refused migration must not have changed the mode"
        );

        // With headroom it runs, and the database ends up INCREMENTAL — which is
        // what makes `reclaim` cheap from then on.
        let done = migrate_to_incremental_vacuum(&pool, Some(u64::MAX)).await?;
        assert!(
            matches!(done, VacuumMigration::Migrated { .. }),
            "expected a migration, got {done:?}"
        );
        assert_eq!(auto_vacuum_mode(&pool).await?, AutoVacuum::Incremental);

        pool.close().await;
        for p in [
            path.display().to_string(),
            format!("{}-wal", path.display()),
            format!("{}-shm", path.display()),
        ] {
            std::fs::remove_file(&p).ok();
        }
        Ok(())
    }

    /// `reclaim` must NOT run a full VACUUM in NONE mode — the branch that used
    /// to be the only one that ever executed, and the one that cannot finish on
    /// a volume under the pressure that triggers a sweep.
    ///
    /// Observable without timing a VACUUM: a full VACUUM returns freed pages to
    /// the OS, so `page_count` falls. Skipping it leaves the allocation in
    /// place — while `db_size_bytes`, which subtracts the freelist, still drops.
    /// That pairing is the actual claim: the watermark does not latch even
    /// though the file does not shrink.
    #[tokio::test]
    async fn reclaim_does_not_full_vacuum_in_none_mode() -> Result<()> {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fr-noneclaim-{}.db", std::process::id()));
        for p in [
            path.display().to_string(),
            format!("{}-wal", path.display()),
            format!("{}-shm", path.display()),
        ] {
            std::fs::remove_file(&p).ok();
        }
        let url = format!("sqlite://{}", path.display());
        let opts = SqliteConnectOptions::from_str(&url)?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .auto_vacuum(sqlx::sqlite::SqliteAutoVacuum::None);
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect_with(opts)
            .await?;
        init_schema(&pool).await?;

        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://none.example/f.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;
        let entries: Vec<NewEntry> = (0..1500)
            .map(|i| NewEntry {
                guid: format!("n-{i}"),
                content_html: Some("x".repeat(800)),
                ..Default::default()
            })
            .collect();
        insert_entries(&pool, feed_id, &entries, 0).await?;
        // Fold the WAL in so the "full" baseline is file pages, not WAL churn.
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&pool)
            .await?;
        let used_full = db_size_bytes(&pool).await?;

        sqlx::query("DELETE FROM entries").execute(&pool).await?;
        let pages_before: i64 = sqlx::query_scalar("PRAGMA page_count")
            .fetch_one(&pool)
            .await?;

        reclaim(&pool).await?;

        let pages_after: i64 = sqlx::query_scalar("PRAGMA page_count")
            .fetch_one(&pool)
            .await?;
        assert_eq!(
            pages_after, pages_before,
            "reclaim shrank the file in NONE mode, so it ran the full VACUUM this \
             branch exists to avoid"
        );
        // …and the watermark still falls, which is what makes skipping safe.
        // `db_size_bytes` subtracts the freelist, so the delete alone lowers it
        // even though the file kept every page it had allocated.
        let used_after = db_size_bytes(&pool).await?;
        assert!(
            used_after < used_full,
            "used size did not fall after the delete ({used_after} !< {used_full}); \
             without a VACUUM the DB-size watermark would latch the poller off"
        );

        pool.close().await;
        for p in [
            path.display().to_string(),
            format!("{}-wal", path.display()),
            format!("{}-shm", path.display()),
        ] {
            std::fs::remove_file(&p).ok();
        }
        Ok(())
    }

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

    // -- STORAGE HYGIENE: retention prune + orphan-id scrub -------------------

    /// Count entries currently in the cache.
    async fn count_entries(pool: &SqlitePool) -> Result<i64> {
        Ok(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM entries")
            .fetch_one(pool)
            .await?)
    }

    #[tokio::test]
    async fn prune_old_entries_deletes_only_old_and_cascades_entry_state() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://ret.example/feed.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;

        let recent = now_rfc3339();
        let ancient = (chrono::Utc::now() - chrono::Duration::days(365))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        // One fresh (published now), one ancient (published a year ago), and one
        // UNDATED-but-freshly-fetched (published NULL, fetched_at now) — the last
        // must survive because COALESCE falls back to fetched_at, not to "old".
        insert_entries(
            &pool,
            feed_id,
            &[
                NewEntry {
                    guid: "fresh".into(),
                    published: Some(recent.clone()),
                    fetched_at: Some(recent.clone()),
                    ..Default::default()
                },
                NewEntry {
                    guid: "ancient".into(),
                    published: Some(ancient.clone()),
                    fetched_at: Some(ancient.clone()),
                    ..Default::default()
                },
                NewEntry {
                    guid: "undated-fresh".into(),
                    published: None,
                    fetched_at: Some(recent.clone()),
                    ..Default::default()
                },
            ],
            0,
        )
        .await?;
        assert_eq!(count_entries(&pool).await?, 3);
        // Subscribe so mark_read is authorized to write an entry_state row.
        replace_sub_refs(&pool, "did:plc:reader", &[feed_id]).await?;

        // Give the ancient entry an entry_state row so we can prove the FK cascade.
        let ancient_id: i64 = sqlx::query_scalar("SELECT id FROM entries WHERE guid = 'ancient'")
            .fetch_one(&pool)
            .await?;
        let wrote = mark_read(&pool, "did:plc:reader", ancient_id, true).await?;
        assert!(wrote, "mark_read must write with a sub_ref in place");
        let state_before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM entry_state WHERE entry_id = ?1")
                .bind(ancient_id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(state_before, 1);

        // Prune at a 90-day window: only the ancient entry is old.
        let deleted = prune_old_entries(&pool, 90, 3650).await?;
        assert_eq!(deleted, 1, "only the year-old entry should be pruned");
        assert_eq!(
            count_entries(&pool).await?,
            2,
            "fresh + undated-fresh survive"
        );

        // The surviving guids are exactly the two fresh ones.
        let surviving: Vec<String> = sqlx::query_scalar("SELECT guid FROM entries ORDER BY guid")
            .fetch_all(&pool)
            .await?;
        assert_eq!(surviving, vec!["fresh", "undated-fresh"]);

        // entry_state for the deleted entry cascaded away via the FK.
        let state_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM entry_state WHERE entry_id = ?1")
                .bind(ancient_id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(state_after, 0, "entry_state must cascade on entry delete");

        // days == 0 disables the rolling WINDOW. The 3650-day ceiling still runs
        // (see `a_disabled_window_does_not_disable_the_ceiling`); it deletes
        // nothing here because both survivors are fresh.
        assert_eq!(prune_old_entries(&pool, 0, 3650).await?, 0);
        assert_eq!(count_entries(&pool).await?, 2);
        Ok(())
    }

    #[tokio::test]
    async fn prune_removes_orphan_ids_from_read_cursor() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:reader";
        let feed_url = "https://orphan.example/feed.xml";
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: feed_url.to_string(),
                ..Default::default()
            },
        )
        .await?;
        // Caller subscribes so mark-read is authorized to project into the cursor.
        replace_sub_refs(&pool, did, &[feed_id]).await?;

        let ancient = (chrono::Utc::now() - chrono::Duration::days(365))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let recent = now_rfc3339();
        insert_entries(
            &pool,
            feed_id,
            &[
                NewEntry {
                    guid: "old".into(),
                    published: Some(ancient.clone()),
                    fetched_at: Some(ancient.clone()),
                    ..Default::default()
                },
                NewEntry {
                    guid: "new".into(),
                    published: Some(recent.clone()),
                    fetched_at: Some(recent.clone()),
                    ..Default::default()
                },
            ],
            0,
        )
        .await?;
        let old_id: i64 = sqlx::query_scalar("SELECT id FROM entries WHERE guid = 'old'")
            .fetch_one(&pool)
            .await?;
        let new_id: i64 = sqlx::query_scalar("SELECT id FROM entries WHERE guid = 'new'")
            .fetch_one(&pool)
            .await?;

        // Mark BOTH read — the cursor's read_ids now references both entry ids.
        mark_read(&pool, did, old_id, true).await?;
        mark_read(&pool, did, new_id, true).await?;
        let before = get_cursor(&pool, did, feed_url).await?.unwrap();
        let ids_before: Vec<String> = serde_json::from_str(&before.read_ids)?;
        assert!(ids_before.contains(&old_id.to_string()));
        assert!(ids_before.contains(&new_id.to_string()));

        // Prune the old entry — its id must be scrubbed from the cursor's id-set.
        let deleted = prune_old_entries(&pool, 90, 3650).await?;
        assert_eq!(deleted, 1);
        let after = get_cursor(&pool, did, feed_url).await?.unwrap();
        let ids_after: Vec<String> = serde_json::from_str(&after.read_ids)?;
        assert_eq!(
            ids_after,
            vec![new_id.to_string()],
            "orphaned (deleted) entry id must be removed; live id kept"
        );
        // The scrub re-dirties the cursor so the flusher resyncs the PDS record.
        assert!(
            after.dirty,
            "cursor must be marked dirty after orphan scrub"
        );
        Ok(())
    }

    #[tokio::test]
    async fn insert_entries_trim_scrubs_orphan_cursor_ids() -> Result<()> {
        // The per-feed max_entries trim path must ALSO scrub orphaned cursor ids.
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:reader";
        let feed_url = "https://trim.example/feed.xml";
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: feed_url.to_string(),
                ..Default::default()
            },
        )
        .await?;
        replace_sub_refs(&pool, did, &[feed_id]).await?;

        // Two entries, cap of 2 for now (no trim yet).
        insert_entries(
            &pool,
            feed_id,
            &[
                NewEntry {
                    guid: "a".into(),
                    published: Some("2026-01-01T00:00:00Z".into()),
                    ..Default::default()
                },
                NewEntry {
                    guid: "b".into(),
                    published: Some("2026-01-02T00:00:00Z".into()),
                    ..Default::default()
                },
            ],
            2,
        )
        .await?;
        let a_id: i64 = sqlx::query_scalar("SELECT id FROM entries WHERE guid = 'a'")
            .fetch_one(&pool)
            .await?;
        mark_read(&pool, did, a_id, true).await?;

        // Insert a newer entry with cap=1 → the oldest ('a') is trimmed away.
        insert_entries(
            &pool,
            feed_id,
            &[NewEntry {
                guid: "c".into(),
                published: Some("2026-01-03T00:00:00Z".into()),
                ..Default::default()
            }],
            1,
        )
        .await?;
        // 'a' is gone.
        let a_still: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries WHERE guid = 'a'")
            .fetch_one(&pool)
            .await?;
        assert_eq!(a_still, 0, "oldest entry trimmed by the per-feed cap");

        // The cursor no longer references the trimmed id.
        let cursor = get_cursor(&pool, did, feed_url).await?.unwrap();
        let ids: Vec<String> = serde_json::from_str(&cursor.read_ids)?;
        assert!(
            !ids.contains(&a_id.to_string()),
            "trimmed entry id must be scrubbed from the cursor"
        );
        Ok(())
    }

    /// A sweep spanning several batches must still delete everything.
    ///
    /// The batching exists to make the write-lock hold interruptible, not to
    /// make the sweep partial — so the obvious way to get it wrong is an
    /// off-by-one that leaves a batch behind, or a loop that exits on the first
    /// short batch instead of the first empty one.
    #[tokio::test]
    async fn a_sweep_larger_than_one_batch_still_drains() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://bulk.example/f.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;
        let old = (chrono::Utc::now() - chrono::Duration::days(400))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        // Deliberately not a multiple of PRUNE_BATCH, so the final batch is
        // short and the loop has to keep going to the empty one.
        let count = (PRUNE_BATCH * 2 + 137) as usize;
        let entries: Vec<NewEntry> = (0..count)
            .map(|i| NewEntry {
                guid: format!("bulk-{i}"),
                published: Some(old.clone()),
                ..Default::default()
            })
            .collect();
        insert_entries(&pool, feed_id, &entries, 0).await?;
        assert_eq!(count_entries(&pool).await? as usize, count);

        let deleted = prune_old_entries(&pool, 30, 180).await?;
        assert_eq!(deleted as usize, count, "the sweep left rows behind");
        assert_eq!(count_entries(&pool).await?, 0);
        Ok(())
    }

    /// **The sweep must not lock other writers out for its duration.**
    ///
    /// The whole sweep used to be one transaction — both deletes plus a global
    /// cursor scrub that loads every `read_cursor` row and then issues a
    /// per-cursor live-ids query. SQLite is single-writer with a 5 s
    /// `busy_timeout`, so every mark-read, login write and cursor flush failed
    /// for that whole span.
    ///
    /// On-disk (WAL, 5 connections) because the in-memory pool is deliberately
    /// single-connection, which would make a concurrency test meaningless.
    #[tokio::test]
    async fn a_writer_gets_through_while_the_sweep_runs() -> Result<()> {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fr-sweeplock-{}.db", std::process::id()));
        std::fs::remove_file(&path).ok();
        let url = format!("sqlite://{}", path.display());
        let pool = init_url(&url).await?;

        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: "https://lock.example/f.xml".to_string(),
                ..Default::default()
            },
        )
        .await?;
        let old = (chrono::Utc::now() - chrono::Duration::days(400))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let entries: Vec<NewEntry> = (0..(PRUNE_BATCH * 10) as usize)
            .map(|i| NewEntry {
                guid: format!("lock-{i}"),
                published: Some(old.clone()),
                ..Default::default()
            })
            .collect();
        insert_entries(&pool, feed_id, &entries, 0).await?;

        // The discriminating measurement is LATENCY, not success. With only ten
        // thousand rows the old single-transaction sweep would finish inside the
        // 5 s `busy_timeout`, so the interleaved writes would still eventually
        // land — they would just each have waited for the ENTIRE sweep. So the
        // writer records the worst single-write wait, and the assertion is that
        // no write waited for more than a fraction of the sweep.
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer_done = std::sync::Arc::clone(&done);
        let writer_pool = pool.clone();
        let writer = tokio::spawn(async move {
            let mut wrote = 0_u32;
            let mut worst = std::time::Duration::ZERO;
            while !writer_done.load(std::sync::atomic::Ordering::Relaxed) {
                let t0 = std::time::Instant::now();
                grant_access(
                    &writer_pool,
                    &format!("did:plc:writer{wrote}"),
                    None,
                    "sweep-test",
                    None,
                )
                .await?;
                worst = worst.max(t0.elapsed());
                wrote += 1;
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            Ok::<(u32, std::time::Duration), anyhow::Error>((wrote, worst))
        });

        let t0 = std::time::Instant::now();
        let deleted = prune_old_entries(&pool, 30, 180).await?;
        let sweep = t0.elapsed();
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        let (wrote, worst) = writer.await??;

        assert_eq!(deleted as usize, entries.len());
        // Sanity: the sweep has to take long enough for "was a writer blocked
        // for it" to be a meaningful question. Ten batches of inter-batch
        // hand-off put this comfortably past the floor.
        assert!(
            sweep > std::time::Duration::from_millis(50),
            "the sweep finished in {sweep:?}; too fast for this test to mean anything"
        );
        // The real property. Note this is asserted BEFORE the throughput check
        // below: when the sweep does hold the lock, the writer is starved, so
        // both assertions fail — and this one names the actual cause.
        assert!(
            worst * 3 < sweep,
            "a single write waited {worst:?} of a {sweep:?} sweep ({wrote} writes \
             landed) — the sweep is holding the write lock ACROSS batches rather \
             than releasing it between them"
        );
        assert!(
            wrote > 5,
            "only {wrote} writes ran alongside a {sweep:?} sweep"
        );

        pool.close().await;
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(format!("{}-wal", path.display())).ok();
        std::fs::remove_file(format!("{}-shm", path.display())).ok();
        Ok(())
    }

    /// **A mark-read landing during the scrub must not be overwritten.**
    ///
    /// Moving the scrub out of the sweep's transaction removed a multi-minute
    /// write-lock hold and introduced a lost update in its place: the id-sets
    /// were read into a snapshot up front and written back unguarded, so a
    /// `mark_read` arriving mid-pass had its id silently dropped — and the
    /// rewrite set `dirty = 1`, so the flusher pushed the truncated set to the
    /// PDS as authoritative. Local `entry_state` still said read, so the loss was
    /// invisible here and visible only in every other atproto client.
    ///
    /// The race is a few milliseconds wide, so this does not try to hit it.
    /// Instead it pins the property that makes it impossible: the scrub reads the
    /// id-sets itself, inside the same transaction that writes them, so a set
    /// written after the pass began is the one that gets filtered.
    #[tokio::test]
    async fn the_cursor_scrub_reads_the_ids_it_writes() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:race";
        let feed_url = "https://race.example/f.xml";
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: feed_url.to_string(),
                ..Default::default()
            },
        )
        .await?;
        insert_entries(
            &pool,
            feed_id,
            &[
                NewEntry {
                    guid: "live".to_string(),
                    ..Default::default()
                },
                NewEntry {
                    guid: "doomed".to_string(),
                    ..Default::default()
                },
            ],
            0,
        )
        .await?;
        replace_sub_refs(&pool, did, &[feed_id]).await?;
        let live_id: i64 = sqlx::query_scalar("SELECT id FROM entries WHERE guid = 'live'")
            .fetch_one(&pool)
            .await?;
        let doomed_id: i64 = sqlx::query_scalar("SELECT id FROM entries WHERE guid = 'doomed'")
            .fetch_one(&pool)
            .await?;

        // A cursor holding only the id that is about to be deleted.
        upsert_cursor(
            &pool,
            &ReadCursor {
                did: did.to_string(),
                feed_url: feed_url.to_string(),
                read_through: None,
                read_ids: format!("[\"{doomed_id}\"]"),
                unread_ids: "[]".to_string(),
                dirty: false,
                pds_created: false,
                updated_at: now_rfc3339(),
            },
        )
        .await?;
        sqlx::query("DELETE FROM entries WHERE guid = 'doomed'")
            .execute(&pool)
            .await?;

        // Now a reader marks the surviving entry read — the write that the old
        // snapshot-then-write shape would have clobbered. It lands BEFORE the
        // scrub, which is the deterministic stand-in for landing during it: a
        // scrub that reads its own input sees it, one that reuses a snapshot
        // taken earlier does not.
        mark_read(&pool, did, live_id, true).await?;

        assert_eq!(prune_orphan_cursor_ids(&pool, None).await?, 1);

        let cursor = get_cursor(&pool, did, feed_url).await?.expect("cursor");
        let ids: Vec<String> = serde_json::from_str(&cursor.read_ids)?;
        assert_eq!(
            ids,
            vec![live_id.to_string()],
            "the scrub dropped a mark-read that landed after the pass began"
        );
        assert!(
            !ids.contains(&doomed_id.to_string()),
            "the orphaned id survived the scrub"
        );
        Ok(())
    }

    /// The cursor scrub still happens — it just no longer rides inside the
    /// delete transaction. Moving it out is only safe because it is idempotent;
    /// this pins that it still runs at all, which is the thing a "move it out"
    /// refactor can silently drop.
    #[tokio::test]
    async fn the_sweep_still_scrubs_orphaned_cursor_ids() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let did = "did:plc:scrub";
        let feed_url = "https://scrub.example/f.xml";
        let feed_id = upsert_feed(
            &pool,
            &NewFeed {
                url: feed_url.to_string(),
                ..Default::default()
            },
        )
        .await?;
        let old = (chrono::Utc::now() - chrono::Duration::days(400))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        insert_entries(
            &pool,
            feed_id,
            &[NewEntry {
                guid: "doomed".to_string(),
                published: Some(old),
                ..Default::default()
            }],
            0,
        )
        .await?;
        let doomed = entries_for_feed(&pool, did, feed_id).await;
        // `entries_for_feed` is sub_ref-scoped; read the id directly instead.
        drop(doomed);
        let doomed_id: i64 = sqlx::query_scalar("SELECT id FROM entries WHERE guid = 'doomed'")
            .fetch_one(&pool)
            .await?;

        upsert_cursor(
            &pool,
            &ReadCursor {
                did: did.to_string(),
                feed_url: feed_url.to_string(),
                read_through: None,
                read_ids: format!("[\"{doomed_id}\"]"),
                unread_ids: "[]".to_string(),
                dirty: false,
                pds_created: false,
                updated_at: now_rfc3339(),
            },
        )
        .await?;

        assert_eq!(prune_old_entries(&pool, 30, 180).await?, 1);

        let cursor = get_cursor(&pool, did, feed_url).await?.expect("cursor");
        let ids: Vec<String> = serde_json::from_str(&cursor.read_ids)?;
        assert!(
            ids.is_empty(),
            "the deleted entry's id survived in the cursor: {ids:?}"
        );
        assert!(cursor.dirty, "a rewritten cursor must be re-flushed");
        Ok(())
    }

    #[tokio::test]
    async fn prune_and_reclaim_drops_db_size() -> Result<()> {
        // On-disk DB so VACUUM has a file to shrink.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fr-prune-{}.db", std::process::id()));
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
        let ancient = (chrono::Utc::now() - chrono::Duration::days(365))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let entries: Vec<NewEntry> = (0..2000)
            .map(|i| NewEntry {
                guid: format!("guid-{i}"),
                content_html: Some("<p>".to_string() + &"x".repeat(400) + "</p>"),
                published: Some(ancient.clone()),
                fetched_at: Some(ancient.clone()),
                ..Default::default()
            })
            .collect();
        insert_entries(&pool, feed_id, &entries, 0).await?;
        let full = db_size_bytes(&pool).await?;
        assert!(full > 0);

        // A retention sweep prunes every (year-old) entry, then reclaim shrinks.
        let deleted = prune_old_entries(&pool, 90, 3650).await?;
        assert_eq!(deleted, 2000);
        reclaim(&pool).await?;
        let after = db_size_bytes(&pool).await?;
        assert!(
            after < full,
            "prune + reclaim must shrink db_size_bytes: {after} !< {full}"
        );

        drop(pool);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    // ---- B1: an existing PRE-0.2.2 invite_codes table (no intended_did) must
    // migrate cleanly, not crash-loop boot. ----------------------------------

    #[tokio::test]
    async fn migrates_pre_intended_did_invite_codes_table() -> Result<()> {
        // Build an on-disk DB whose `invite_codes` table has the OLD 0.2.1 shape
        // (NO `intended_did` column, and therefore no `intended_did` index), then
        // run init_schema/migrations against it — this is exactly the existing-prod
        // volume that blocker B1 crash-looped (the SCHEMA's `CREATE INDEX ...
        // (intended_did, ...)` fired before the ALTER TABLE added the column).
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fr-b1-{}.db", std::process::id()));
        let url = format!("sqlite://{}", path.display());

        // Open a raw pool WITHOUT init_schema and hand-build the old table shape.
        let opts = SqliteConnectOptions::from_str(&url)?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect_with(opts)
            .await?;
        sqlx::query(
            r#"CREATE TABLE invite_codes (
                code         TEXT PRIMARY KEY,
                creator_did  TEXT NOT NULL,
                status       TEXT NOT NULL,
                invitee_did  TEXT,
                created_at   INTEGER NOT NULL,
                expires_at   INTEGER NOT NULL,
                redeemed_at  INTEGER
            );"#,
        )
        .execute(&pool)
        .await?;
        // Seed a legacy active code so the migration runs against real data.
        sqlx::query(
            "INSERT INTO invite_codes (code, creator_did, status, created_at, expires_at) \
             VALUES ('FEATHER-LEGACY00', 'did:plc:old', 'active', 1, 9999999999)",
        )
        .execute(&pool)
        .await?;

        // The column is genuinely absent to start with (pre-condition of B1).
        let cols: Vec<String> = sqlx::query("PRAGMA table_info(invite_codes)")
            .fetch_all(&pool)
            .await?
            .iter()
            .map(|r| r.get::<String, _>("name"))
            .collect();
        assert!(
            !cols.iter().any(|c| c == "intended_did"),
            "pre-condition: legacy table must lack intended_did"
        );

        // THE FIX: init_schema must succeed (not error with "no such column").
        init_schema(&pool)
            .await
            .expect("init_schema on a pre-0.2.2 invite_codes table must not crash");

        // Post-condition: the column now exists, both indexes were created, and the
        // legacy row is intact.
        let cols: Vec<String> = sqlx::query("PRAGMA table_info(invite_codes)")
            .fetch_all(&pool)
            .await?
            .iter()
            .map(|r| r.get::<String, _>("name"))
            .collect();
        assert!(cols.iter().any(|c| c == "intended_did"));
        let idx: Vec<String> = sqlx::query(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='invite_codes'",
        )
        .fetch_all(&pool)
        .await?
        .iter()
        .map(|r| r.get::<String, _>("name"))
        .collect();
        assert!(idx.iter().any(|n| n == "idx_invite_codes_intended"));
        assert!(idx.iter().any(|n| n == "idx_invite_codes_intended_active"));

        // Idempotent: running it again is a no-op, not an error.
        init_schema(&pool)
            .await
            .expect("re-running init_schema must be idempotent");

        // **The OAuth tables must exist too.** They live in this database, and
        // creating them only when the Rust backend is selected would make the
        // first request after a cutover flip fail with "no such table" -- at the
        // one moment nobody wants to find out a migration was missed. They are
        // empty and harmless while the sidecar is serving.
        let tables: Vec<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table'")
                .fetch_all(&pool)
                .await
                .unwrap();
        for table in ["oauth_state", "oauth_session", "oauth_nonce"] {
            assert!(
                tables.iter().any(|t| t == table),
                "{table} is missing, so the rust backend would fail on its first request: {tables:?}"
            );
        }

        // The legacy code still redeems (NULL intended_did → open, as before).
        let out = redeem_code(&pool, "FEATHER-LEGACY00", "did:plc:new", None, 100).await?;
        assert_eq!(out, Ok(()));

        drop(pool);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        Ok(())
    }

    // ---- B2: a code minted FOR a specific DID is redeemable ONLY by that DID. --

    #[tokio::test]
    async fn redeem_enforces_intended_did_binding() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        // Mint a claim FOR did:plc:A (the follower the bot posted the link to).
        let code = mint_code_for_did(&pool, "did:bot:fr", 3600, "did:plc:A").await?;

        // A DIFFERENT DID (a throwaway that stole the public link) is refused as if
        // the code didn't exist — no seat granted, code still active.
        let stolen = redeem_code(&pool, &code, "did:plc:B", Some("thief.bsky"), 100).await?;
        assert_eq!(stolen, Err(RedeemError::NotFound));
        assert!(!has_beta_access(&pool, "did:plc:B").await?);
        assert_eq!(count_active_codes(&pool).await?, 1, "code must stay active");

        // The INTENDED DID redeems successfully.
        let ok = redeem_code(&pool, &code, "did:plc:A", Some("alice.bsky"), 100).await?;
        assert_eq!(ok, Ok(()));
        assert!(has_beta_access(&pool, "did:plc:A").await?);

        // A NULL-intended (admin/browser) code stays open to anyone (unchanged).
        let open = mint_code(&pool, "did:plc:admin", 3600).await?;
        let anyone = redeem_code(&pool, &open, "did:plc:C", None, 100).await?;
        assert_eq!(anyone, Ok(()));
        assert!(has_beta_access(&pool, "did:plc:C").await?);
        Ok(())
    }

    // ---- S4: at most one ACTIVE code per intended DID; a concurrent second mint
    // hits the partial-unique index, and is_intended_active_conflict recognises it.

    #[tokio::test]
    async fn intended_active_partial_unique_index_blocks_double_mint() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        // First mint for the DID succeeds.
        mint_code_for_did(&pool, "did:bot:fr", 3600, "did:plc:dup").await?;
        // A SECOND active mint for the SAME DID violates the partial unique index.
        let err = mint_code_for_did(&pool, "did:bot:fr", 3600, "did:plc:dup")
            .await
            .expect_err("second active mint for the same DID must fail the unique index");
        assert!(
            is_intended_active_conflict(&err),
            "the conflict must be recognised so the web layer can recover: {err:?}"
        );
        // Still exactly one active code for the DID.
        assert!(find_active_code_for_did(&pool, "did:plc:dup")
            .await?
            .is_some());

        // Once the first code is redeemed (no longer active), a fresh mint for the
        // DID is allowed again (partial index only constrains active rows).
        let existing = find_active_code_for_did(&pool, "did:plc:dup")
            .await?
            .unwrap();
        redeem_code(&pool, &existing, "did:plc:dup", None, 100).await??;
        mint_code_for_did(&pool, "did:bot:fr", 3600, "did:plc:dup")
            .await
            .expect("a new mint is allowed after the prior one is redeemed");

        // And the conflict helper does NOT fire on an unrelated error (a PRIMARY KEY
        // clash on `code`, i.e. a different constraint).
        sqlx::query(
            "INSERT INTO invite_codes (code, creator_did, status, created_at, expires_at) \
             VALUES ('FEATHER-DUPEKEY0', 'did:x', 'active', 1, 9999999999)",
        )
        .execute(&pool)
        .await?;
        let pk_err = sqlx::query(
            "INSERT INTO invite_codes (code, creator_did, status, created_at, expires_at) \
             VALUES ('FEATHER-DUPEKEY0', 'did:x', 'active', 1, 9999999999)",
        )
        .execute(&pool)
        .await
        .expect_err("duplicate PRIMARY KEY must error");
        let as_anyhow = anyhow::Error::new(pk_err);
        assert!(
            !is_intended_active_conflict(&as_anyhow),
            "a non-intended-index conflict must NOT be mistaken for the recover-able one"
        );
        Ok(())
    }

    #[tokio::test]
    async fn purge_expires_orphaned_active_intended_code() -> Result<()> {
        // Cheap nit: purging a DID that is the TARGET of an active claim must both
        // NULL intended_did AND expire the (now orphaned) active code, so it stops
        // counting against the mint cap for its full TTL.
        let pool = init_url("sqlite::memory:").await?;
        let code = mint_code_for_did(&pool, "did:bot:fr", 3600, "did:plc:leaver").await?;
        assert_eq!(count_active_codes(&pool).await?, 1);

        purge_did_data(&pool, "did:plc:leaver").await?;

        // The code is no longer active (expired), so it no longer counts.
        assert_eq!(
            count_active_codes(&pool).await?,
            0,
            "orphaned code must be expired by purge, not left active"
        );
        // And intended_did was scrubbed.
        let intended: Option<String> =
            sqlx::query("SELECT intended_did FROM invite_codes WHERE code = ?1")
                .bind(&code)
                .fetch_one(&pool)
                .await?
                .get("intended_did");
        assert!(intended.is_none(), "intended_did must be NULLed");
        Ok(())
    }

    /// A `(key, source)` observation upserts in place: two writes for the same
    /// relay leave ONE row, carrying the newer value.
    #[tokio::test]
    async fn network_stat_upserts_per_source() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let mut stat = NetworkStat {
            key: ADOPTION_STAT_KEY.to_string(),
            source: "https://relay1.us-west.bsky.network".to_string(),
            value: 1,
            truncated: false,
            observed_at: "2026-08-12T00:00:00Z".to_string(),
        };
        record_network_stat(&pool, &stat).await?;
        stat.value = 4;
        stat.observed_at = "2026-08-13T00:00:00Z".to_string();
        record_network_stat(&pool, &stat).await?;

        let rows: i64 = sqlx::query("SELECT COUNT(*) AS n FROM network_stat")
            .fetch_one(&pool)
            .await?
            .get("n");
        assert_eq!(rows, 1, "the same relay must update, not duplicate");
        let latest = latest_network_stat(&pool, ADOPTION_STAT_KEY)
            .await?
            .expect("a stat");
        assert_eq!(latest.value, 4);
        assert_eq!(latest.observed_at, "2026-08-13T00:00:00Z");
        Ok(())
    }

    /// Relays disagree by design (non-archival indexes); the max is surfaced.
    #[tokio::test]
    async fn latest_network_stat_picks_the_max_across_sources() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        for (source, value, truncated) in [
            ("https://relay1.us-west.bsky.network", 2i64, false),
            ("https://relay1.us-east.bsky.network", 40i64, true),
        ] {
            record_network_stat(
                &pool,
                &NetworkStat {
                    key: ADOPTION_STAT_KEY.to_string(),
                    source: source.to_string(),
                    value,
                    truncated,
                    observed_at: "2026-08-13T00:00:00Z".to_string(),
                },
            )
            .await?;
        }
        let latest = latest_network_stat(&pool, ADOPTION_STAT_KEY)
            .await?
            .expect("a stat");
        assert_eq!(latest.value, 40);
        assert_eq!(latest.source, "https://relay1.us-east.bsky.network");
        // `truncated` round-trips as a bool.
        assert!(latest.truncated);
        Ok(())
    }

    #[tokio::test]
    async fn latest_network_stat_is_none_on_an_empty_table() -> Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        assert!(latest_network_stat(&pool, ADOPTION_STAT_KEY)
            .await?
            .is_none());
        Ok(())
    }

    // ── poll health (the public stats page) ─────────────────────────────────

    async fn feed_polled(
        pool: &SqlitePool,
        url: &str,
        last_polled: Option<&str>,
        next_poll: Option<&str>,
    ) {
        sqlx::query("INSERT INTO feeds (url, last_polled, next_poll) VALUES (?1, ?2, ?3)")
            .bind(url)
            .bind(last_polled)
            .bind(next_poll)
            .execute(pool)
            .await
            .unwrap();
    }

    /// The numbers on the public page must describe the poller's actual state.
    #[tokio::test]
    async fn poll_health_counts_tracked_recent_and_overdue() -> anyhow::Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let now = "2026-01-01T12:00:00Z";
        let hour_ago = "2026-01-01T11:00:00Z";

        // Polled 10 minutes ago, due in 50 minutes: healthy.
        feed_polled(
            &pool,
            "https://a.example/f",
            Some("2026-01-01T11:50:00Z"),
            Some("2026-01-01T12:50:00Z"),
        )
        .await;
        // Polled 3 hours ago and overdue: the backlog case.
        feed_polled(
            &pool,
            "https://b.example/f",
            Some("2026-01-01T09:00:00Z"),
            Some("2026-01-01T10:00:00Z"),
        )
        .await;
        // Never polled: counts as overdue (next_poll IS NULL), and must not
        // corrupt the "oldest poll" figure with a NULL.
        feed_polled(&pool, "https://c.example/f", None, None).await;

        let h = poll_health(&pool, now, hour_ago).await?;
        assert_eq!(h.feeds_tracked, 3);
        assert_eq!(
            h.polled_last_hour, 1,
            "only the 11:50 poll is within the hour"
        );
        assert_eq!(h.overdue, 2, "the stale feed and the never-polled one");
        assert_eq!(
            h.last_poll_secs_ago,
            Some(600),
            "most recent poll was 10 minutes ago"
        );
        // **A never-polled feed IS the worst staleness.**
        //
        // This originally asserted `Some(10_800)` — the oldest FINITE age — and
        // in doing so pinned a defect: `MIN` skips NULLs, so the page reported
        // "3h ago" while a quarter of the feeds had never been fetched at all.
        // The figure read healthiest in the most degraded state, which is the
        // opposite of what a health page is for.
        assert_eq!(
            h.oldest_poll_secs_ago, None,
            "a never-polled feed must outrank any finite age"
        );
        assert_eq!(h.never_polled, 1);

        // With every feed polled, the finite worst case is reported again.
        sqlx::query("UPDATE feeds SET last_polled = ?1 WHERE last_polled IS NULL")
            .bind("2026-01-01T09:00:00Z")
            .execute(&pool)
            .await?;
        let h = poll_health(&pool, now, hour_ago).await?;
        assert_eq!(h.never_polled, 0);
        assert_eq!(h.oldest_poll_secs_ago, Some(10_800));
        Ok(())
    }

    /// A fresh instance has no polls yet. The page must say so rather than
    /// rendering a zero that reads as "polled just now".
    #[tokio::test]
    async fn poll_health_on_an_empty_instance_reports_no_polls() -> anyhow::Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let h = poll_health(&pool, "2026-01-01T12:00:00Z", "2026-01-01T11:00:00Z").await?;
        assert_eq!(h.feeds_tracked, 0);
        assert_eq!(h.last_poll_secs_ago, None);
        assert_eq!(h.oldest_poll_secs_ago, None);
        Ok(())
    }

    /// A poll timestamped in the future — clock skew, or a restored backup —
    /// reads as "just now", never as a negative age.
    #[tokio::test]
    async fn a_future_poll_timestamp_does_not_go_negative() -> anyhow::Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        feed_polled(
            &pool,
            "https://a.example/f",
            Some("2026-01-01T13:00:00Z"),
            None,
        )
        .await;
        let h = poll_health(&pool, "2026-01-01T12:00:00Z", "2026-01-01T11:00:00Z").await?;
        assert_eq!(h.last_poll_secs_ago, Some(0));
        Ok(())
    }

    // ── retention is a CACHE policy, not a data-retention policy ────────────

    async fn aged_entry(pool: &SqlitePool, url: &str, days_old: i64) -> i64 {
        let when = (chrono::Utc::now() - chrono::Duration::days(days_old))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        sqlx::query("INSERT INTO feeds (url) VALUES (?1) ON CONFLICT(url) DO NOTHING")
            .bind("https://f.example/feed")
            .execute(pool)
            .await
            .unwrap();
        let feed_id: i64 = sqlx::query_scalar("SELECT id FROM feeds WHERE url = ?1")
            .bind("https://f.example/feed")
            .fetch_one(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO entries (feed_id, guid, url, title, published, fetched_at) VALUES (?1,?2,?3,'t',?4,?4)")
            .bind(feed_id).bind(url).bind(url).bind(&when)
            .execute(pool).await.unwrap();
        sqlx::query_scalar("SELECT id FROM entries WHERE guid = ?1")
            .bind(url)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn mark(pool: &SqlitePool, entry_id: i64, read: i64, starred: i64) {
        sqlx::query("INSERT INTO entry_state (did, entry_id, read, starred, updated_at) VALUES ('did:plc:x',?1,?2,?3,'2026-01-01T00:00:00Z')")
            .bind(entry_id).bind(read).bind(starred)
            .execute(pool).await.unwrap();
    }

    /// **A STARRED article is never evicted, however old.**
    ///
    /// The starred view joins `entries`, and `entry_state` cascades on delete,
    /// so pruning a starred entry removed it from the starred list entirely —
    /// and the content is not recoverable, because a feed serves only its last
    /// few dozen items. The PDS keeps the saved RECORD; it has never held the
    /// article.
    #[tokio::test]
    async fn retention_keeps_starred_and_unread_entries() -> anyhow::Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let old_read = aged_entry(&pool, "old-read", 30).await;
        let old_starred = aged_entry(&pool, "old-starred", 30).await;
        let old_unread = aged_entry(&pool, "old-unread", 30).await;
        let recent_read = aged_entry(&pool, "recent-read", 1).await;
        mark(&pool, old_read, 1, 0).await;
        mark(&pool, old_starred, 1, 1).await; // read AND starred
        mark(&pool, old_unread, 0, 0).await;
        mark(&pool, recent_read, 1, 0).await;

        let deleted = prune_old_entries(&pool, 14, 3650).await?;
        assert_eq!(deleted, 1, "only the old, read, unstarred entry should go");

        let left: Vec<String> = sqlx::query_scalar("SELECT guid FROM entries ORDER BY guid")
            .fetch_all(&pool)
            .await?;
        assert_eq!(left, vec!["old-starred", "old-unread", "recent-read"]);
        Ok(())
    }

    /// An entry nobody has interacted with at all — no `entry_state` row — is
    /// still evicted once it ages out. Otherwise the cache never shrinks, since
    /// most entries are never opened.
    #[tokio::test]
    async fn retention_evicts_entries_with_no_reader_state() -> anyhow::Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        aged_entry(&pool, "untouched-old", 30).await;
        aged_entry(&pool, "untouched-new", 1).await;
        assert_eq!(prune_old_entries(&pool, 14, 3650).await?, 1);
        Ok(())
    }

    /// **A recently-polled feed is NOT made due again.**
    ///
    /// `due_feeds` treats NULL as due immediately, so an unbounded nudge from a
    /// page handler turned every reload of the starred view into another poll of
    /// those feeds — outbound amplification against third-party origins, and one
    /// reader monopolising a poll budget that is shared and already the binding
    /// constraint on user count.
    #[tokio::test]
    async fn a_recently_polled_feed_is_not_nudged_again() -> anyhow::Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let recent = "2026-01-01T11:59:00Z";
        let stale_before = "2026-01-01T11:00:00Z"; // one hour before "now"

        sqlx::query("INSERT INTO feeds (url, last_polled, next_poll) VALUES (?1, ?2, ?3)")
            .bind("https://fresh.example/f")
            .bind(recent)
            .bind("2026-01-01T12:59:00Z")
            .execute(&pool)
            .await?;
        // Polled long ago: this one SHOULD be nudged.
        sqlx::query("INSERT INTO feeds (url, last_polled, next_poll) VALUES (?1, ?2, ?3)")
            .bind("https://stale.example/f")
            .bind("2026-01-01T06:00:00Z")
            .bind("2026-01-01T07:00:00Z")
            .execute(&pool)
            .await?;

        mark_feed_due(&pool, "https://fresh.example/f", stale_before).await?;
        mark_feed_due(&pool, "https://stale.example/f", stale_before).await?;

        let fresh: Option<String> =
            sqlx::query_scalar("SELECT next_poll FROM feeds WHERE url = 'https://fresh.example/f'")
                .fetch_one(&pool)
                .await?;
        let stale: Option<String> =
            sqlx::query_scalar("SELECT next_poll FROM feeds WHERE url = 'https://stale.example/f'")
                .fetch_one(&pool)
                .await?;

        assert!(
            fresh.is_some(),
            "a feed polled a minute ago was made due again — a reload loop is an \
             amplification vector"
        );
        assert!(stale.is_none(), "a long-unpolled feed should be nudged");
        Ok(())
    }

    /// A feed that has never been polled is always nudgeable — there is no
    /// recent fetch to argue it would be wasted.
    #[tokio::test]
    async fn a_never_polled_feed_is_nudged() -> anyhow::Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        sqlx::query("INSERT INTO feeds (url, last_polled, next_poll) VALUES (?1, NULL, ?2)")
            .bind("https://new.example/f")
            .bind("2026-01-01T12:59:00Z")
            .execute(&pool)
            .await?;
        mark_feed_due(&pool, "https://new.example/f", "2026-01-01T11:00:00Z").await?;
        let next: Option<String> =
            sqlx::query_scalar("SELECT next_poll FROM feeds WHERE url = 'https://new.example/f'")
                .fetch_one(&pool)
                .await?;
        assert!(next.is_none());
        Ok(())
    }

    /// **The hard ceiling is the bound that sparing would otherwise remove.**
    ///
    /// "Mark unread" is a one-click control and `entries` is shared across every
    /// reader, so an unbounded `read = 0` exception lets one person pin rows
    /// permanently — and since the poller stops entirely above
    /// `db_size_watermark_bytes` with this DELETE as its only release valve,
    /// those pins could stop polling for everyone.
    #[tokio::test]
    async fn the_hard_ceiling_evicts_even_starred_and_unread() -> anyhow::Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let ancient_starred = aged_entry(&pool, "ancient-starred", 400).await;
        let ancient_unread = aged_entry(&pool, "ancient-unread", 400).await;
        let recent_starred = aged_entry(&pool, "recent-starred", 30).await;
        mark(&pool, ancient_starred, 1, 1).await;
        mark(&pool, ancient_unread, 0, 0).await;
        mark(&pool, recent_starred, 1, 1).await;

        // 14-day soft window, 180-day hard ceiling.
        prune_old_entries(&pool, 14, 180).await?;

        let left: Vec<String> = sqlx::query_scalar("SELECT guid FROM entries ORDER BY guid")
            .fetch_all(&pool)
            .await?;
        assert_eq!(
            left,
            vec!["recent-starred"],
            "past the ceiling nothing is pinned — otherwise one reader can stall the poller \
             for every reader"
        );
        Ok(())
    }

    /// The per-feed trim spares starred entries too. It was fixed in the
    /// retention sweep and NOT here, which left the documented guarantee false —
    /// and this path runs on every poll of every feed rather than daily.
    #[tokio::test]
    async fn the_per_feed_trim_spares_starred_entries() -> anyhow::Result<()> {
        let pool = init_url("sqlite::memory:").await?;
        let old_starred = aged_entry(&pool, "old-starred", 5).await;
        mark(&pool, old_starred, 1, 1).await;
        for i in 0..5 {
            aged_entry(&pool, &format!("filler-{i}"), 1).await;
        }
        let feed_id: i64 = sqlx::query_scalar("SELECT id FROM feeds LIMIT 1")
            .fetch_one(&pool)
            .await?;

        // Trim hard enough that the older starred entry would be cut. The trim
        // runs inside `insert_entries`, so drive it the way production does.
        insert_entries(&pool, feed_id, &[], 2).await?;

        let left: Vec<String> =
            sqlx::query_scalar("SELECT guid FROM entries WHERE guid = 'old-starred'")
                .fetch_all(&pool)
                .await?;
        assert_eq!(
            left,
            vec!["old-starred"],
            "the per-feed trim evicted a starred entry"
        );
        Ok(())
    }
}
