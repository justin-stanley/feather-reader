/**
 * SQLite-backed persistence for the atproto OAuth client and the sidecar's own
 * session-id ⇄ DID handoff.
 *
 * The `@atproto/oauth-client-node` `NodeOAuthClient` needs two stores:
 *
 *  - a **state store** (`NodeSavedStateStore`) — short-lived per-authorization
 *    request state, keyed by the PAR/`state` value; written at `/login`, read +
 *    deleted at `/callback`.
 *  - a **session store** (`NodeSavedSessionStore`) — the durable per-DID OAuth
 *    session (tokens + DPoP key material). The client reads/writes this on every
 *    `restore(did)`; token refresh is handled *inside* the library and persisted
 *    back here, which is why restoring a session across sidecar restarts "just
 *    works".
 *
 * On top of those we keep our own tiny **`session_id` table**: `/callback` mints
 * an opaque session id and maps it to the logged-in DID+handle, and hands that id
 * back to the Rust app. The Rust app then uses the id to (a) ask "who is this?"
 * (`GET /internal/session/:id`) and to key its own signed cookie by DID.
 */

import { DatabaseSync } from 'node:sqlite';
import type {
  NodeSavedSession,
  NodeSavedSessionStore,
  NodeSavedState,
  NodeSavedStateStore,
} from '@atproto/oauth-client-node';
import type { Codec } from './crypto.js';
import { NullCodec } from './crypto.js';

export interface SessionRow {
  id: string;
  did: string;
  handle: string | null;
  createdAt: number;
}

/** TTL thresholds used by the reaper (absolute + idle, in ms). */
export interface SessionTtls {
  absoluteMs: number;
  idleMs: number;
}

export class SqliteStores {
  readonly db: DatabaseSync;
  /** AEAD codec for at-rest encryption of state/session values. */
  private readonly codec: Codec;

  constructor(dbPath: string, codec: Codec = new NullCodec()) {
    this.db = new DatabaseSync(dbPath);
    this.codec = codec;
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA busy_timeout = 5000');
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS oauth_state (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS oauth_session (
        did   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS app_session (
        id         TEXT PRIMARY KEY,
        did        TEXT NOT NULL,
        handle     TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS app_session_did ON app_session(did);
    `);
    // TTL bookkeeping for oauth_session: add created_at / last_used_at if an
    // older DB predates them. `ALTER TABLE ADD COLUMN` is idempotent-guarded by
    // a pragma check so re-running migrate() is safe.
    const cols = new Set(
      (this.db.prepare(`PRAGMA table_info(oauth_session)`).all() as Array<{ name: string }>).map(
        (c) => c.name,
      ),
    );
    if (!cols.has('created_at')) {
      this.db.exec(`ALTER TABLE oauth_session ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0`);
    }
    if (!cols.has('last_used_at')) {
      this.db.exec(`ALTER TABLE oauth_session ADD COLUMN last_used_at INTEGER NOT NULL DEFAULT 0`);
    }
  }

  /** The `@atproto/oauth-client-node` state store (per-auth-request state). */
  stateStore(): NodeSavedStateStore {
    const db = this.db;
    const codec = this.codec;
    return {
      async set(key: string, value: NodeSavedState): Promise<void> {
        db.prepare('INSERT OR REPLACE INTO oauth_state (key, value) VALUES (?, ?)').run(
          key,
          codec.encrypt(JSON.stringify(value)),
        );
      },
      async get(key: string): Promise<NodeSavedState | undefined> {
        const row = db.prepare('SELECT value FROM oauth_state WHERE key = ?').get(key) as
          | { value: string }
          | undefined;
        // Migrate-on-read: `maybeDecrypt` passes through legacy plaintext rows.
        return row ? (JSON.parse(codec.maybeDecrypt(row.value)) as NodeSavedState) : undefined;
      },
      async del(key: string): Promise<void> {
        db.prepare('DELETE FROM oauth_state WHERE key = ?').run(key);
      },
    };
  }

  /** The `@atproto/oauth-client-node` session store (durable per-DID session). */
  sessionStore(): NodeSavedSessionStore {
    const db = this.db;
    const codec = this.codec;
    return {
      async set(sub: string, session: NodeSavedSession): Promise<void> {
        const now = Date.now();
        const enc = codec.encrypt(JSON.stringify(session));
        // Preserve the original created_at across refresh-driven rewrites so the
        // absolute-TTL clock starts at first login, not at the last refresh.
        db.prepare(
          `INSERT INTO oauth_session (did, value, created_at, last_used_at)
             VALUES (?, ?, ?, ?)
           ON CONFLICT(did) DO UPDATE SET
             value        = excluded.value,
             last_used_at = excluded.last_used_at,
             created_at   = CASE WHEN oauth_session.created_at = 0
                                 THEN excluded.created_at ELSE oauth_session.created_at END`,
        ).run(sub, enc, now, now);
      },
      async get(sub: string): Promise<NodeSavedSession | undefined> {
        const row = db.prepare('SELECT value FROM oauth_session WHERE did = ?').get(sub) as
          | { value: string }
          | undefined;
        if (!row) return undefined;
        // Touch idle-TTL clock on every restore/read.
        db.prepare('UPDATE oauth_session SET last_used_at = ? WHERE did = ?').run(Date.now(), sub);
        return JSON.parse(codec.maybeDecrypt(row.value)) as NodeSavedSession;
      },
      async del(sub: string): Promise<void> {
        db.prepare('DELETE FROM oauth_session WHERE did = ?').run(sub);
      },
    };
  }

  // -- our own session-id ⇄ DID handoff -----------------------------------

  /** Mint (or replace) an app-session-id → {did, handle} mapping. */
  putAppSession(id: string, did: string, handle: string | null): void {
    this.db
      .prepare('INSERT OR REPLACE INTO app_session (id, did, handle, created_at) VALUES (?, ?, ?, ?)')
      .run(id, did, handle, Date.now());
  }

  getAppSession(id: string): SessionRow | undefined {
    const row = this.db
      .prepare('SELECT id, did, handle, created_at AS createdAt FROM app_session WHERE id = ?')
      .get(id) as SessionRow | undefined;
    return row;
  }

  deleteAppSession(id: string): void {
    this.db.prepare('DELETE FROM app_session WHERE id = ?').run(id);
  }

  /** True if the sidecar holds a restorable OAuth session for this DID. */
  hasOauthSession(did: string): boolean {
    const row = this.db.prepare('SELECT 1 FROM oauth_session WHERE did = ?').get(did);
    return row !== undefined;
  }

  // -- revocation + TTL reaper ---------------------------------------------

  /**
   * Delete every stored trace of a DID's session: the durable OAuth session row
   * (tokens + DPoP key) AND all app_session handoff ids pointing at it. Returns
   * whether an OAuth session row was actually removed. Token *revocation* at the
   * PDS is done by the caller (via the atproto client) before/after this.
   */
  purgeDid(did: string): boolean {
    const info = this.db.prepare('DELETE FROM oauth_session WHERE did = ?').run(did);
    this.db.prepare('DELETE FROM app_session WHERE did = ?').run(did);
    return info.changes > 0;
  }

  /**
   * Return the DIDs whose sessions have exceeded either TTL as of `now`.
   * A row with `created_at`/`last_used_at` == 0 (a pre-migration legacy row that
   * has not been rewritten yet) is left alone until it is next used, at which
   * point the timestamps get populated.
   */
  expiredDids(ttls: SessionTtls, now: number = Date.now()): string[] {
    const rows = this.db
      .prepare(
        `SELECT did FROM oauth_session
          WHERE created_at > 0
            AND ( (? - created_at)   >= ?
               OR (? - last_used_at)  >= ? )`,
      )
      .all(now, ttls.absoluteMs, now, ttls.idleMs) as Array<{ did: string }>;
    return rows.map((r) => r.did);
  }

  /**
   * Sweep expired sessions. For each expired DID, `onReap` is invoked (e.g. to
   * revoke tokens at the PDS) before the row is purged; a throwing `onReap` does
   * not block the purge. Returns the DIDs reaped.
   */
  async reap(
    ttls: SessionTtls,
    onReap?: (did: string) => Promise<void> | void,
    now: number = Date.now(),
  ): Promise<string[]> {
    const dids = this.expiredDids(ttls, now);
    for (const did of dids) {
      if (onReap) {
        try {
          await onReap(did);
        } catch {
          /* best-effort revocation; purge regardless */
        }
      }
      this.purgeDid(did);
    }
    return dids;
  }

  close(): void {
    this.db.close();
  }
}
