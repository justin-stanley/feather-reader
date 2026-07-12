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

export interface SessionRow {
  id: string;
  did: string;
  handle: string | null;
  createdAt: number;
}

export class SqliteStores {
  readonly db: DatabaseSync;

  constructor(dbPath: string) {
    this.db = new DatabaseSync(dbPath);
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
  }

  /** The `@atproto/oauth-client-node` state store (per-auth-request state). */
  stateStore(): NodeSavedStateStore {
    const db = this.db;
    return {
      async set(key: string, value: NodeSavedState): Promise<void> {
        db.prepare('INSERT OR REPLACE INTO oauth_state (key, value) VALUES (?, ?)').run(
          key,
          JSON.stringify(value),
        );
      },
      async get(key: string): Promise<NodeSavedState | undefined> {
        const row = db.prepare('SELECT value FROM oauth_state WHERE key = ?').get(key) as
          | { value: string }
          | undefined;
        return row ? (JSON.parse(row.value) as NodeSavedState) : undefined;
      },
      async del(key: string): Promise<void> {
        db.prepare('DELETE FROM oauth_state WHERE key = ?').run(key);
      },
    };
  }

  /** The `@atproto/oauth-client-node` session store (durable per-DID session). */
  sessionStore(): NodeSavedSessionStore {
    const db = this.db;
    return {
      async set(sub: string, session: NodeSavedSession): Promise<void> {
        db.prepare('INSERT OR REPLACE INTO oauth_session (did, value) VALUES (?, ?)').run(
          sub,
          JSON.stringify(session),
        );
      },
      async get(sub: string): Promise<NodeSavedSession | undefined> {
        const row = db.prepare('SELECT value FROM oauth_session WHERE did = ?').get(sub) as
          | { value: string }
          | undefined;
        return row ? (JSON.parse(row.value) as NodeSavedSession) : undefined;
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

  close(): void {
    this.db.close();
  }
}
