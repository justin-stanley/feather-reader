import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { SqliteStores, StoreError } from '../src/stores.js';
import { Aead } from '../src/crypto.js';

const ENC_KEY = 'stores-test-passphrase-value-32b!';

function tmpDb(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'sidecar-stores-'));
  const path = join(dir, 'test.db');
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('session values are AEAD-encrypted at rest', async () => {
  const { path, cleanup } = tmpDb();
  try {
    const aead = new Aead(ENC_KEY);
    const stores = new SqliteStores(path, aead);
    const ss = stores.sessionStore();
    const secret = { tokenSet: { access_token: 'super-secret-token' } } as never;
    await ss.set('did:plc:alice', secret);

    // Raw column must be ciphertext, must NOT contain the plaintext token.
    const raw = new DatabaseSync(path).prepare('SELECT value FROM oauth_session WHERE did = ?').get(
      'did:plc:alice',
    ) as { value: string };
    assert.ok(Aead.isCiphertext(raw.value));
    assert.ok(!raw.value.includes('super-secret-token'));

    // Round-trips through get().
    const got = (await ss.get('did:plc:alice')) as { tokenSet: { access_token: string } };
    assert.equal(got.tokenSet.access_token, 'super-secret-token');
    stores.close();
  } finally {
    cleanup();
  }
});

test('migrate-on-read: legacy plaintext session row still readable, re-encrypted on write', async () => {
  const { path, cleanup } = tmpDb();
  try {
    // Seed a plaintext row the way the OLD code would have.
    const seed = new DatabaseSync(path);
    seed.exec(
      'CREATE TABLE oauth_session (did TEXT PRIMARY KEY, value TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT 0, last_used_at INTEGER NOT NULL DEFAULT 0)',
    );
    seed.prepare('INSERT INTO oauth_session (did, value) VALUES (?, ?)').run(
      'did:plc:bob',
      JSON.stringify({ tokenSet: { access_token: 'legacy-plain' } }),
    );
    seed.close();

    const stores = new SqliteStores(path, new Aead(ENC_KEY));
    const ss = stores.sessionStore();
    const got = (await ss.get('did:plc:bob')) as { tokenSet: { access_token: string } };
    assert.equal(got.tokenSet.access_token, 'legacy-plain');

    // Re-write → should now be ciphertext.
    await ss.set('did:plc:bob', { tokenSet: { access_token: 'legacy-plain' } } as never);
    const raw = new DatabaseSync(path).prepare('SELECT value FROM oauth_session WHERE did = ?').get(
      'did:plc:bob',
    ) as { value: string };
    assert.ok(Aead.isCiphertext(raw.value));
    stores.close();
  } finally {
    cleanup();
  }
});

test('purgeDid removes oauth_session + app_session rows', async () => {
  const { path, cleanup } = tmpDb();
  try {
    const stores = new SqliteStores(path, new Aead(ENC_KEY));
    await stores.sessionStore().set('did:plc:carol', { tokenSet: {} } as never);
    stores.putAppSession('sid-1', 'did:plc:carol', 'carol.example');
    assert.ok(stores.hasOauthSession('did:plc:carol'));
    assert.ok(stores.getAppSession('sid-1'));

    assert.equal(stores.purgeDid('did:plc:carol'), true);
    assert.equal(stores.hasOauthSession('did:plc:carol'), false);
    assert.equal(stores.getAppSession('sid-1'), undefined);
    assert.equal(stores.purgeDid('did:plc:carol'), false); // idempotent
    stores.close();
  } finally {
    cleanup();
  }
});

test('deleteAppSession consumes one handoff id without touching others', () => {
  const { path, cleanup } = tmpDb();
  try {
    const stores = new SqliteStores(path, new Aead(ENC_KEY));
    stores.putAppSession('sid-1', 'did:plc:carol', 'carol.example');
    stores.putAppSession('sid-2', 'did:plc:dave', 'dave.example');

    // A resolve of sid-1 must be single-use: after delete it's gone...
    assert.ok(stores.getAppSession('sid-1'));
    stores.deleteAppSession('sid-1');
    assert.equal(stores.getAppSession('sid-1'), undefined);
    // ...while an unrelated handoff id is untouched.
    assert.ok(stores.getAppSession('sid-2'));

    // getAppSession exposes createdAt so the handler can enforce a freshness TTL.
    const row = stores.getAppSession('sid-2');
    assert.equal(typeof row?.createdAt, 'number');
    stores.close();
  } finally {
    cleanup();
  }
});

test('reaper: expires by absolute and idle TTL, calls onReap, preserves fresh', async () => {
  const { path, cleanup } = tmpDb();
  try {
    const stores = new SqliteStores(path, new Aead(ENC_KEY));
    const ss = stores.sessionStore();
    await ss.set('did:plc:fresh', { tokenSet: {} } as never);
    await ss.set('did:plc:old', { tokenSet: {} } as never);
    await ss.set('did:plc:idle', { tokenSet: {} } as never);

    // Backdate created_at (absolute breach) and last_used_at (idle breach).
    const db = new DatabaseSync(path);
    db.prepare('UPDATE oauth_session SET created_at = ? WHERE did = ?').run(1, 'did:plc:old');
    db.prepare('UPDATE oauth_session SET last_used_at = ? WHERE did = ?').run(1, 'did:plc:idle');
    db.close();

    const reaped: string[] = [];
    const dids = await stores.reap(
      { absoluteMs: 1000, idleMs: 1000 },
      (did) => {
        reaped.push(did);
      },
      Date.now(),
    );

    assert.deepEqual(new Set(dids), new Set(['did:plc:old', 'did:plc:idle']));
    assert.deepEqual(new Set(reaped), new Set(['did:plc:old', 'did:plc:idle']));
    assert.ok(stores.hasOauthSession('did:plc:fresh'));
    assert.equal(stores.hasOauthSession('did:plc:old'), false);
    assert.equal(stores.hasOauthSession('did:plc:idle'), false);
    stores.close();
  } finally {
    cleanup();
  }
});

test('reaper: leaves un-timestamped legacy rows (created_at=0) alone', async () => {
  const { path, cleanup } = tmpDb();
  try {
    const seed = new DatabaseSync(path);
    seed.exec(
      'CREATE TABLE oauth_session (did TEXT PRIMARY KEY, value TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT 0, last_used_at INTEGER NOT NULL DEFAULT 0)',
    );
    seed.prepare('INSERT INTO oauth_session (did, value) VALUES (?, ?)').run('did:plc:legacy', '{}');
    seed.close();

    const stores = new SqliteStores(path, new Aead(ENC_KEY));
    const dids = await stores.reap({ absoluteMs: 1, idleMs: 1 }, undefined, Date.now());
    assert.deepEqual(dids, []);
    assert.ok(stores.hasOauthSession('did:plc:legacy'));
    stores.close();
  } finally {
    cleanup();
  }
});

// ─── StoreError (issue #77) ──────────────────────────────────────────────────
//
// `@atproto-labs/simple-store@0.5` made `CachedGetter` propagate store errors
// instead of swallowing them. These pin the marker type the /internal/repo
// handler relies on to tell "the store broke" (503, retryable) apart from
// "there is no session" (404, re-login).

test('StoreError: a failed session-store read is tagged op=get, not reported as a miss', async () => {
  const { path, cleanup } = tmpDb();
  try {
    const stores = new SqliteStores(path, new Aead(ENC_KEY));
    const ss = stores.sessionStore();
    await ss.set('did:plc:alice', { tokenSet: { access_token: 't' } } as never);

    // Closing the handle makes every subsequent statement throw, standing in for
    // a SQLITE_BUSY/IO fault.
    stores.close();

    await assert.rejects(
      async () => void (await ss.get('did:plc:alice')),
      (err: unknown) => {
        assert.ok(err instanceof StoreError, `expected StoreError, got ${String(err)}`);
        assert.equal(err.store, 'session');
        assert.equal(err.op, 'get');
        assert.ok(err.cause, 'underlying cause is preserved');
        return true;
      },
    );
  } finally {
    cleanup();
  }
});

test('StoreError: an undecryptable session row surfaces as op=get rather than a raw parse error', async () => {
  const { path, cleanup } = tmpDb();
  try {
    const stores = new SqliteStores(path, new Aead(ENC_KEY));
    await stores.sessionStore().set('did:plc:alice', { tokenSet: {} } as never);
    stores.close();

    // Re-open under a *different* key: the ciphertext can no longer be read.
    const rotated = new SqliteStores(path, new Aead('a-totally-different-passphrase!!'));
    await assert.rejects(
      async () => void (await rotated.sessionStore().get('did:plc:alice')),
      (err: unknown) => err instanceof StoreError && err.op === 'get',
    );
    rotated.close();
  } finally {
    cleanup();
  }
});

test('StoreError: write and delete failures are tagged too, and still propagate', async () => {
  const { path, cleanup } = tmpDb();
  try {
    const stores = new SqliteStores(path, new Aead(ENC_KEY));
    const ss = stores.sessionStore();
    const st = stores.stateStore();
    stores.close();

    await assert.rejects(
      async () => void (await ss.set('did:plc:alice', { tokenSet: {} } as never)),
      (err: unknown) => err instanceof StoreError && err.store === 'session' && err.op === 'set',
    );
    await assert.rejects(
      async () => void (await ss.del('did:plc:alice')),
      (err: unknown) => err instanceof StoreError && err.op === 'del',
    );
    await assert.rejects(
      async () => void (await st.get('some-state-key')),
      (err: unknown) => err instanceof StoreError && err.store === 'state' && err.op === 'get',
    );
  } finally {
    cleanup();
  }
});

test('StoreError: a genuinely absent row is still a plain miss, not an error', async () => {
  const { path, cleanup } = tmpDb();
  try {
    const stores = new SqliteStores(path, new Aead(ENC_KEY));
    assert.equal(await stores.sessionStore().get('did:plc:nobody'), undefined);
    assert.equal(await stores.stateStore().get('no-such-key'), undefined);
    stores.close();
  } finally {
    cleanup();
  }
});
