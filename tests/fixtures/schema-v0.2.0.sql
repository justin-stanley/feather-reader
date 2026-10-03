-- The schema a v0.2.0 binary creates on an empty database: booted until it
-- logged `listening`, then dumped with `sqlite3 <db> .schema` (v0.2.0 has no
-- --migrate-auto-vacuum). The OLDEST released shape: feeds has no
-- last_error_kind, last_error or kind, and invite_codes has no intended_did.
-- Do not edit by hand: regenerate from the tagged binary.
CREATE TABLE feeds (
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
CREATE INDEX idx_feeds_next_poll ON feeds (next_poll);
CREATE TABLE entries (
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
CREATE INDEX idx_entries_feed_published ON entries (feed_id, published);
CREATE TABLE entry_state (
    did        TEXT NOT NULL,
    entry_id   INTEGER NOT NULL REFERENCES entries (id) ON DELETE CASCADE,
    read       INTEGER NOT NULL DEFAULT 0,
    starred    INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (did, entry_id)
);
CREATE INDEX idx_entry_state_did_read ON entry_state (did, read);
CREATE TABLE sub_ref (
    did     TEXT NOT NULL,
    feed_id INTEGER NOT NULL REFERENCES feeds (id) ON DELETE CASCADE,
    PRIMARY KEY (did, feed_id)
);
CREATE INDEX idx_sub_ref_feed ON sub_ref (feed_id);
CREATE TABLE read_cursor (
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
CREATE INDEX idx_read_cursor_dirty ON read_cursor (did, dirty);
CREATE INDEX idx_read_cursor_feed_url ON read_cursor (feed_url);
CREATE TABLE beta_access (
    did              TEXT PRIMARY KEY,
    handle           TEXT,
    granted_by       TEXT NOT NULL,
    granted_at       INTEGER NOT NULL,
    invite_code_used TEXT
);
CREATE TABLE invite_codes (
    code        TEXT PRIMARY KEY,
    creator_did TEXT NOT NULL,
    status      TEXT NOT NULL,
    invitee_did TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    redeemed_at INTEGER
);
CREATE INDEX idx_invite_codes_status ON invite_codes (status, expires_at);
