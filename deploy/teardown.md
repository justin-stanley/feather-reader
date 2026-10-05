# FeatherReader — pause / kill teardown runbook

FeatherReader is an experiment and the UI promises it "may pause at any time."
This runbook is what makes that promise **operationally real**: how an operator
wipes every scrap of user state, revokes every live OAuth session at users' PDSes,
and stops the service cleanly.

There are two related but distinct wipes:

| Layer | What it holds | Wiped by |
|---|---|---|
| **Rust app** (`featherreader`) | The SQLite cache: `entry_state`, `read_cursor`, `sub_ref`, `beta_access`, `invite_codes`, the shared `feeds`/`entries` cache, and operational tables (`network_stat`, `repo_timing`, `repo_timing_total`, `ballast`). Signed session cookies are keyed by DID but hold no server secret beyond the cookie HMAC. | Deleting `FEATHERREADER_DB` (+ `-wal`/`-shm`). |
| **Rust OAuth client** (`FEATHERREADER_REPO_BACKEND=rust`) | Per-DID OAuth tokens (refresh + access) and the session DPoP key, in the app's own SQLite (`FEATHERREADER_DB`, tables `oauth_session` / `oauth_state` / `oauth_nonce`), AEAD-encrypted at rest under `FEATHERREADER_OAUTH_ENCRYPTION_KEY`. | Per user: their own `POST /logout` or `POST /account/delete`. Fleet-wide: `featherreader --revoke-all-sessions`, which revokes every row at its PDS via RFC 7009 **and** drops it (the script runs it for you). Then deleting `FEATHERREADER_DB` and the signing key at `FEATHERREADER_OAUTH_KEY_PATH`. |
| **OAuth sidecar** (`oauth-sidecar`) | Per-DID OAuth tokens (refresh + access, DPoP keys) and the `session_id` handoff rows, in its own SQLite (`SIDECAR_DB`), AEAD-encrypted at rest. Plus the confidential-client signing JWK at `${SIDECAR_DB}.jwk.json`. | `POST /internal/revoke` per DID (revokes at the PDS **and** drops the row), then deleting `SIDECAR_DB`. |

A user-initiated `POST /account/delete` already does the per-user version of both
(purge that DID's app rows + revoke at the PDS through the sidecar **and** the
Rust client, whichever holds tokens). `/logout` does the revoke half. This
runbook is the **fleet-wide** version.

### Revoking the `rust` backend's sessions

The hosted instance has run `FEATHERREADER_REPO_BACKEND=rust` since 2026-09-13.
Its tokens live in `FEATHERREADER_DB`, and the operator command that revokes
them is the app binary itself:

```bash
featherreader --revoke-all-sessions
```

It must run with the **app's own environment**: `FEATHERREADER_DB`,
`FEATHERREADER_OAUTH_ENCRYPTION_KEY`, `FEATHERREADER_PUBLIC_URL`,
`FEATHERREADER_OAUTH_KEY_PATH` and the secrets `Config` insists on in
production. For every row of `oauth_session` it runs the same sign-out that
`/logout` uses: it discovers the PDS's revocation endpoint, revokes the refresh
token there (RFC 7009), and deletes the row **whatever the PDS says**, including
rows that no longer decrypt. Sign-outs run one at a time, and each is
deadline-bounded. Each sign-out reads the clock afresh, because its client
assertion is valid for only 60 s. A long walk therefore never sends an expired
assertion.

It prints a line per DID, a summary, and, **last**, a sentinel line:

```text
revoke-all-sessions: revoked=N no_session=M failed=K
```

It then exits with:

| Exit | Meaning | `teardown.sh` does |
|---|---|---|
| `0` + sentinel with `failed=0` | Every session revoked, or none stored. | Continues. |
| `3` + sentinel with `failed>0` | Some revocations failed. **Every row is still deleted.** Those tokens may stay live at their PDS until they expire. | Warns and continues. |
| `2`, no sentinel | Nothing was done and **nothing deleted**; fix the cause and run it again. See the list below. | Aborts before the wipe. |
| anything else, or a missing or contradictory sentinel | Not a completed revoke-all. | Aborts before the wipe. |

What makes it exit `2`:

- bad configuration;
- no database at `FEATHERREADER_DB` (it will not create one and report "0 sessions" about the wrong file);
- an unreadable store;
- a missing signing key at `FEATHERREADER_OAUTH_KEY_PATH` (it will not create one);
- the Rust OAuth client cannot be built while sessions are stored.

The last two only stop it when sessions are stored. A missing key matters
because a freshly created key is one no PDS can verify: every revocation would
fail, and the rows would be deleted anyway.

Partial failure is `3` rather than `1` because `1` is what everything else
exits with. That includes an **older `featherreader`** (0.4.4 or earlier),
which ignores this flag, tries to start a server, and exits 1 when the port is
taken, and wrappers like `docker compose exec` or `fly ssh console` when they
fail. The sentinel covers what the exit code cannot: only this command, run to
completion, prints it.

> An older binary on the **sweep**, after the app has stopped, finds the port
> free and starts serving. The teardown then hangs rather than wiping. Stop it
> and use a binary that has this flag.

It is safe to run against a **live** app's database, which is what the Fly
procedure does. The pool uses WAL and the app's 5 s `busy_timeout`, so a
concurrent app write makes it wait instead of failing. Each sign-out deletes
its row in a single statement, so no lock is held across a network call. A
delete that still cannot get the lock is reported as that DID's failure; it
does not crash the run.

> **Revoke while the app is still serving.** A PDS authenticates a
> confidential client before it honours a revocation
> (`@atproto/oauth-provider` 0.23.1: `revoke()` calls `authenticateClient`
> first). To do that it needs our `/oauth/client-metadata.json` and
> `/oauth/jwks.json`, which the app itself serves (`src/web.rs`). PDSes cache
> those for only 600 s (`clientMetadataCache` / `clientJwksCache`). Revoke
> after the stop, and every PDS whose cache has expired rejects the
> revocation, leaving that token live. So the main pass runs **before** the
> stop, and a second pass after the stop catches the few sessions created in
> between.

> Order matters. Revoke at the PDS *before* deleting either database. Once the
> encrypted token rows are gone you can no longer ask the PDS to invalidate
> them, and stale refresh tokens would live out their natural TTL on the PDS
> side.

---

## A. Pause (reversible) — stop serving, keep data

Use this for a maintenance window or a temporary pause where you intend to come
back. It does **not** revoke tokens or delete anything.

The commands below assume you run the app and sidecar as two services named
`featherreader` and `oauth-sidecar`; adjust to your setup. For the supplied
container image (one container, all state under `/data`; on Fly, the
`featherreader_data` volume), stop the container or machine instead, and the
files to wipe are `/data/featherreader.db*`, `/data/oauth-sidecar.db*`,
`/data/oauth-sidecar.db.jwk.json` and `/data/oauth-signing-key.json`.

```bash
# systemd
sudo systemctl stop featherreader oauth-sidecar

# or docker/compose
docker compose stop featherreader oauth-sidecar
```

Sessions resume when you start the services again. Nothing is destroyed.

---

## B. Kill (irreversible) — wipe volume + revoke ALL sessions + clean WAL flush

This is the "pause forever / take it down" path. Run `deploy/teardown.sh`, or do
the steps by hand below. **This deletes all user data and signs everyone out.**

### One-shot script (self-hosted)

The script runs, in order:

1. The sidecar revoke.
2. The Rust revoke (main pass), while the app is still serving.
3. `FR_STOP_CMD`.
4. The Rust revoke again (sweep).
5. The wipe: both SQLite volumes with a clean WAL checkpoint, the sidecar JWK,
   and the Rust signing key.

A Rust pass counts as done only if it ends with the sentinel line and exits
`0` or `3` (see the table above); anything else aborts before the wipe. It
prompts for confirmation unless `FR_TEARDOWN_YES=1`.

```bash
# rust backend (production). The revoke command needs the app's environment —
# here, the same EnvironmentFile the service uses.
sudo -E FEATHERREADER_DB=/var/lib/featherreader/featherreader.db \
        FEATHERREADER_REPO_BACKEND=rust \
        FEATHERREADER_OAUTH_KEY_PATH=/var/lib/featherreader/oauth-signing-key.json \
        FR_REVOKE_CMD='set -a; . /etc/featherreader/env; set +a; /usr/local/bin/featherreader --revoke-all-sessions' \
        FR_STOP_CMD="systemctl stop featherreader" \
        deploy/teardown.sh

# sidecar backend: as before, plus FR_REVOKE_CMD if FEATHERREADER_DB holds any
# Rust sessions (e.g. from an earlier rust deployment).
sudo -E FEATHERREADER_DB=/var/lib/featherreader/featherreader.db \
        SIDECAR_DB=/var/lib/featherreader/oauth-sidecar.db \
        SIDECAR_PUBLIC_URL=http://127.0.0.1:8081 \
        SIDECAR_INTERNAL_SECRET="$(cat /etc/featherreader/internal_secret)" \
        FR_STOP_CMD="systemctl stop featherreader oauth-sidecar" \
        deploy/teardown.sh
```

- **`FR_REVOKE_CMD`** defaults to `featherreader --revoke-all-sessions` when
  `featherreader` is on `PATH`. It runs with the script's environment, and
  `FEATHERREADER_DB` is exported to it, so it revokes the file that is about to
  be wiped.
- **The script refuses** (exit 2, before anything irreversible) when the
  backend is `rust`, or `FEATHERREADER_DB` holds Rust sessions, and there is no
  revoke command.
- **The `SIDECAR_*` variables** are optional on the `rust` backend when no
  `SIDECAR_DB` file exists.
- **`FR_STOP_CMD`** stops the services between the two Rust passes. Without it
  the script assumes they are already stopped, and then the "main pass" is
  really the post-stop sweep, with the metadata-cache caveat above.

### Fly (the hosted instance)

`teardown.sh` does not fit Fly: the database is on the machine's volume, and
the command has to run inside the machine. By hand:

```bash
# 1. While the machine is RUNNING (the PDSes must be able to fetch our client
#    metadata to accept the revocations), revoke every session:
fly ssh console -C "/app/featherreader --revoke-all-sessions"
#    Go on ONLY if the last line is "revoke-all-sessions: revoked=… failed=…".
#    Exit 0 = done. Exit 3 = some failed (rows deleted anyway, listed by DID).
#    Exit 2 = nothing done: read the message, fix it, run again.
#    Anything else, or no such line (an image older than this flag starts a
#    server instead), means nothing was revoked: do not go on.

# 2. IMMEDIATELY stop the machine. The gap between step 1 and this is the
#    residual risk: a user who logs in during it keeps an unrevoked session.
fly machine stop <machine-id>

# 3. Destroy the machine, then its volume (the database, its -wal/-shm, and
#    the signing key all live on it). A volume still attached to a machine
#    cannot be destroyed.
fly machine destroy <machine-id>
fly volumes destroy <volume-id>
```

On Fly there is **no post-stop sweep**. A stopped machine cannot run
`fly ssh console`, and starting it again would serve logins again. Keep the
gap between steps 1 and 2 short, by running them back to back. If you want to
check that nothing slipped through, run step 1 a second time just before
step 2; it should report `0 revoked`.

### Manual steps (what the script does)

1. **Revoke every live OAuth session at its PDS.** The sidecar has no bulk-revoke
   endpoint by design (a leaked internal secret shouldn't be able to nuke every
   user in one call), so enumerate the DIDs from the sidecar's own store and call
   `/internal/revoke` for each. This revokes the refresh + access tokens at each
   user's PDS *and* drops the sidecar's row:

   ```bash
   sqlite3 "$SIDECAR_DB" 'SELECT did FROM oauth_session;' | while read -r did; do
     curl -fsS -X POST "$SIDECAR_PUBLIC_URL/internal/revoke" \
       -H "X-Internal-Secret: $SIDECAR_INTERNAL_SECRET" \
       -H 'content-type: application/json' \
       -d "{\"did\":\"$did\"}" && echo "  revoked $did"
   done
   ```

   Do this **while the sidecar is still running** — `/internal/revoke` needs the
   live process to reach the PDS.

2. **Revoke every Rust-backend session, while the app is still serving** (see
   [above](#revoking-the-rust-backends-sessions) for why it must be running):

   ```bash
   featherreader --revoke-all-sessions   # app's env; go on only on exit 0/3 + its last line
   ```

3. **Stop the services** so nothing writes to the DBs mid-wipe:

   ```bash
   sudo systemctl stop featherreader oauth-sidecar   # or: docker compose stop …
   ```

4. **Sweep**: run `featherreader --revoke-all-sessions` once more, for any
   session created between step 2 and the stop. It normally reports
   `0 revoked`.

5. **Clean WAL flush, then delete both SQLite volumes and the signing keys.** A `wal_checkpoint(TRUNCATE)`
   folds the write-ahead log back into the main file so a snapshot/backup taken
   before this can't be resurrected from a stray `-wal`; then remove every file:

   ```bash
   for db in "$FEATHERREADER_DB" "$SIDECAR_DB"; do
     [ -f "$db" ] && sqlite3 "$db" 'PRAGMA wal_checkpoint(TRUNCATE);' || true
     rm -f "$db" "$db-wal" "$db-shm"
   done
   # The sidecar's confidential-client signing key lives beside its DB:
   rm -f "$SIDECAR_DB.jwk.json"
   # The Rust client's signing key:
   rm -f "$FEATHERREADER_OAUTH_KEY_PATH"
   ```

6. **(If containerised) remove the volume** so a restart can't rehydrate old data:

   ```bash
   docker compose down -v        # -v drops the named volumes
   ```

7. **Take down the edge** (optional but recommended for a real pause): stop the
   reverse proxy / DNS record for `feather-reader.com` so nobody hits a
   half-torn-down instance. `client-metadata.json` / `jwks.json` no longer need to
   be reachable once every session is revoked.

### Verify

```bash
# Run BEFORE the wipe: the Rust store is empty after the revoke.
sqlite3 "$FEATHERREADER_DB" 'SELECT COUNT(*) FROM oauth_session;'   # expect 0
# No sessions remain in the sidecar store (file is gone → this errors, which is fine).
sqlite3 "$SIDECAR_DB" 'SELECT COUNT(*) FROM oauth_session;' 2>/dev/null || echo "sidecar DB gone ✓"
# App cache is gone.
[ -f "$FEATHERREADER_DB" ] && echo "app DB STILL PRESENT ✗" || echo "app DB gone ✓"
```

Users' subscription/folder/saved **records live in their own PDS** and are
untouched by any of this — that is by design (their data on their server). Only
the tokens *we* held and the caches *we* built are destroyed.
