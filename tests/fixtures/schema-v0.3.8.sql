-- The schema a v0.3.8 binary creates on an empty database, dumped with
-- `sqlite3 <db> .schema` after `featherreader --migrate-auto-vacuum`.
-- Upgrade tests load this and run the CURRENT init_schema over it. Do not
-- edit by hand: regenerate from the tagged binary.
CREATE TABLE feeds (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    url                TEXT NOT NULL UNIQUE,
    title              TEXT,
    site_url           TEXT,
    etag               TEXT,
    last_modified      TEXT,
    last_polled        TEXT,
    next_poll          TEXT,
    consecutive_errors INTEGER NOT NULL DEFAULT 0,
    last_error_kind    TEXT,
    last_error         TEXT
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
CREATE INDEX idx_entry_state_entry_id ON entry_state (entry_id);
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
CREATE INDEX idx_invite_codes_status ON invite_codes (status, expires_at);
CREATE TABLE network_stat (
    key         TEXT NOT NULL,   -- e.g. 'adoption.subscription'
    source      TEXT NOT NULL,   -- the relay host the number came from
    value       INTEGER NOT NULL,
    truncated   INTEGER NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (key, source)
);
CREATE TABLE repo_timing (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    backend  TEXT    NOT NULL,
    op       TEXT    NOT NULL,
    micros   INTEGER NOT NULL,
    ok       INTEGER NOT NULL,
    at       INTEGER NOT NULL
);
CREATE INDEX idx_repo_timing_key ON repo_timing(backend, op, id);
CREATE TABLE repo_timing_total (
    backend    TEXT    NOT NULL,
    op         TEXT    NOT NULL,
    ok_count   INTEGER NOT NULL DEFAULT 0,
    err_count  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (backend, op)
);
CREATE INDEX idx_invite_codes_intended ON invite_codes (intended_did, status);
CREATE UNIQUE INDEX idx_invite_codes_intended_active ON invite_codes (intended_did) WHERE intended_did IS NOT NULL AND status = 'active';
CREATE TABLE oauth_state (
    state                TEXT PRIMARY KEY NOT NULL,
    -- SHA-256 of the cookie value set before the redirect. The callback must
    -- present the cookie; without it a callback URL fired by any other browser
    -- would complete the login and hand out the session.
    browser_binding_hash TEXT NOT NULL,
    pkce_verifier        TEXT NOT NULL,   -- AAD-bound
    dpop_key_jwk         TEXT NOT NULL,   -- AAD-bound
    issuer               TEXT NOT NULL,
    pds_url              TEXT NOT NULL,
    did                  TEXT NOT NULL,
    -- The negotiated client-auth method is stored so the callback re-creates the
    -- same client rather than re-negotiating against possibly-changed metadata.
    auth_method          TEXT NOT NULL,
    auth_kid             TEXT,
    -- The EXACT redirect_uri sent in PAR; it must match byte-for-byte at the
    -- token endpoint.
    redirect_uri         TEXT NOT NULL,
    requested_scope      TEXT NOT NULL,
    request_uri          TEXT NOT NULL,
    app_return_to        TEXT,
    expires_at           INTEGER NOT NULL
);
CREATE INDEX oauth_state_expires_at ON oauth_state(expires_at);
CREATE TABLE oauth_session (
    sub            TEXT PRIMARY KEY NOT NULL,
    issuer         TEXT NOT NULL,
    -- The PDS. Every XRPC request is built against this rather than re-derived,
    -- so it belongs to the token set.
    aud            TEXT NOT NULL,
    dpop_key_jwk   TEXT NOT NULL,   -- AAD-bound
    access_token   TEXT NOT NULL,   -- AAD-bound
    refresh_token  TEXT NOT NULL,   -- AAD-bound
    token_type     TEXT NOT NULL,
    granted_scope  TEXT NOT NULL,
    -- NULL is legitimate: `expires_in` is optional in a token response.
    expires_at     INTEGER
);
CREATE TABLE oauth_nonce (
    origin     TEXT PRIMARY KEY NOT NULL,
    nonce      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
