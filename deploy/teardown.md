# FeatherReader — pause / kill teardown runbook

FeatherReader is an experiment and the UI promises it "may pause at any time."
This runbook is what makes that promise **operationally real**: how an operator
wipes every scrap of user state, revokes every live OAuth session at users' PDSes,
and stops the service cleanly.

There are two related but distinct wipes:

| Layer | What it holds | Wiped by |
|---|---|---|
| **Rust app** (`featherreader`) | The SQLite cache: `entry_state`, `read_cursor`, `sub_ref`, `beta_access`, `invite_codes`, the shared `feeds`/`entries` cache, and operational tables (`network_stat`, `repo_timing`, `repo_timing_total`, `ballast`). Signed session cookies are keyed by DID but hold no server secret beyond the cookie HMAC. | Deleting `FEATHERREADER_DB` (+ `-wal`/`-shm`). |
| **Rust OAuth client** | Per-DID OAuth tokens (refresh + access) and the session DPoP key, in the app's own SQLite (`FEATHERREADER_DB`, tables `oauth_session` / `oauth_state` / `oauth_nonce`), AEAD-encrypted at rest under `FEATHERREADER_OAUTH_ENCRYPTION_KEY`. | Per user: their own `POST /logout` or `POST /account/delete`. Fleet-wide: `featherreader --revoke-all-sessions`, which revokes every row at its PDS via RFC 7009 **and** drops it (the script runs it for you). Then deleting `FEATHERREADER_DB` and the signing key at `FEATHERREADER_OAUTH_KEY_PATH`. |
| **Leftover sidecar store** (0.4.x upgrades only) | The Node OAuth sidecar was removed in 0.5.0. An instance upgraded from 0.4.x may still have its SQLite store (`SIDECAR_DB`, by default `oauth-sidecar.db` beside `FEATHERREADER_DB`): per-DID OAuth tokens (refresh + access, DPoP keys) and `session_id` handoff rows, AEAD-encrypted at rest, plus the sidecar's signing JWK at `<that file>.jwk.json`. Nothing in 0.5.0 can read or revoke these sessions: they stay live at their PDSes until they expire. | Deleted by the teardown (the DB, its `-wal`/`-shm`, and the `.jwk.json`), with a warning. Never revoked. |

A user-initiated `POST /account/delete` already does the per-user version
(purge that DID's app rows + revoke at the PDS through the Rust client).
`/logout` does the revoke half. This runbook is the **fleet-wide** version.

### Revoking the sessions

Since 0.5.0 the Rust client is the only OAuth client. Its tokens live in
`FEATHERREADER_DB`, and the operator command that revokes them is the app
binary itself:

```bash
featherreader --revoke-all-sessions
```

**Run it inside the app's own environment.** Use one of:

- `fly ssh console -C`;
- `docker compose exec featherreader …`;
- the service's systemd `EnvironmentFile`, sourced:
  `set -a; . /etc/featherreader/env; set +a`.

Don't rebuild that environment by hand. It needs the app's **full** runtime
environment:

- `FEATHERREADER_DB`;
- `FEATHERREADER_PUBLIC_URL` (the real, non-loopback URL);
- `FEATHERREADER_OAUTH_ENCRYPTION_KEY`;
- `FEATHERREADER_OAUTH_KEY_PATH`, pointing at the **existing** key;
- the secrets `Config` requires on a production-like instance
  (`FEATHERREADER_COOKIE_SECRET`, …).

An incomplete environment does not fail to start; it starts as the **wrong
client**. Without `FEATHERREADER_PUBLIC_URL`, the config falls back to
localhost, so it would revoke as atproto's public dev client. Without the
encryption key, it can't read a single row. Either way every revocation fails
and every row is deleted anyway. So while sessions are stored, it refuses with
exit 2 and deletes nothing unless it is the production client: confidential,
with a real encryption key and the existing signing key.

For every row of `oauth_session` it runs the same sign-out that `/logout`
uses: it discovers the PDS's revocation endpoint, revokes the refresh token
there (RFC 7009), and deletes the row **whatever the PDS says**, including rows
that no longer decrypt. Sign-outs run one at a time, and each is
deadline-bounded.

- **Clock per session.** Each sign-out reads the clock afresh, because its
  client assertion is valid for only 60 s. A long walk therefore never sends an
  expired assertion.
- **Rotation during sign-out.** The delete is a **compare-and-delete**. If the
  live app rotated the session's tokens while it was being revoked, the row is
  read again and the new tokens are revoked too. After 3 such attempts it gives
  up: the newest tokens are left on record and the DID is reported as failed.
  Each token goes **only** to the revocation endpoint discovered for its own
  `(aud, issuer)`. A row that comes back at a different issuer (a re-login
  after a PDS migration) is re-discovered first. Its token is never posted to
  the old authorization server.
- **No resurrection.** The app's own refresh no longer writes back a session
  that was signed out while it ran. It revokes the tokens it just obtained
  instead. It does the same when another writer (a re-login) replaced the row
  meanwhile: theirs is kept, and our unstored tokens from the old grant are
  revoked.
- **Re-list.** After the walk, the store is listed again. Sessions that
  appeared meanwhile (a login on the still-serving app) are walked too, for up
  to two extra passes. Anything still stored after that is reported as failed.

It prints a line per DID, a summary, and, **last**, a sentinel line:

```text
revoke-all-sessions: revoked=N no_session=M failed=K
```

It then exits with:

| Exit | Meaning | `teardown.sh` does |
|---|---|---|
| `0` + sentinel with `failed=0` | Every session revoked, or none stored. | Continues. |
| `3` + sentinel with `failed>0` | Some revocations failed. Those rows are still deleted, except a session that kept rotating or kept reappearing, which is left on record. Those tokens may stay live at their PDS until they expire. | Warns and continues. |
| `2`, no sentinel | Nothing was done and **nothing deleted**; fix the cause and run it again. See the list below. | Aborts before the wipe. |
| anything else, or a missing or contradictory sentinel | Not a completed revoke-all. | Aborts before the wipe. |

What makes it exit `2`:

- bad configuration;
- no database at `FEATHERREADER_DB` (it will not create one and report "0 sessions" about the wrong file);
- an unreadable store;
- a missing signing key at `FEATHERREADER_OAUTH_KEY_PATH` (it will not create one);
- the Rust OAuth client cannot be built while sessions are stored;
- the client is not the production one while sessions are stored: a loopback
  or unset public URL, no encryption key, or no signing key;
- **the encryption key is the wrong one**: rows are stored and *none* of them
  decrypts. Some readable and some not passes; the unreadable ones are
  reported as failed. See `--accept-unreadable` below for a store that is
  legitimately all unreadable;
- **the signing key is not the one the app serves**: its public half is not in
  `{FEATHERREADER_PUBLIC_URL}/oauth/jwks.json`. That URL is fetched with a
  plain client, not the SSRF guard, because it is your own configuration: a
  split-horizon or LAN address works. It must be https, with no redirects, a
  10 s timeout and a 64 KiB cap;
- **that JWKS could not be fetched**, on the main pass only. The app is meant
  to be up then. The post-stop sweep (`--revoke-all-sessions --sweep`, which
  `teardown.sh` passes) tolerates an unreachable JWKS, but still refuses a key
  it fetches and that does not match.

**`--accept-unreadable`** (in `teardown.sh`: `FR_ACCEPT_UNREADABLE=1`) is the
way out when *no* stored row decrypts and you know why. Two legitimate cases:

- the only rows are from before the AAD change;
- the encryption key was rotated on purpose and nobody has logged in since.

It relaxes **only** that check; the client and signing-key checks still apply.
The unreadable rows are deleted and reported as failed, and the run exits 3.
**Their tokens cannot be revoked by anyone**, since nothing can read them, and
stay live at their PDS until they expire. Don't use it to get past a key you
merely *think* is right: a wrong key looks exactly the same.

All but the first three only stop it when sessions are stored, and all of
them are checked **before the first sign-out**, so nothing is deleted.

The checks are about *which* secrets the command holds, not just *whether* it
holds them. With the wrong secrets, every sign-out "works": the revocation
fails, the row is deleted anyway, and the run used to exit 3 and let the
teardown wipe. A freshly created signing key is the same problem: no PDS can
verify it.

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

> Order matters. Revoke at the PDS *before* deleting the database. Once the
> encrypted token rows are gone you can no longer ask the PDS to invalidate
> them, and stale refresh tokens would live out their natural TTL on the PDS
> side.

---

## A. Pause (reversible) — stop serving, keep data

Use this for a maintenance window or a temporary pause where you intend to come
back. It does **not** revoke tokens or delete anything.

The commands below assume you run the app as a service named `featherreader`;
adjust to your setup. For the supplied container image (one container running
the app and Caddy, all state under `/data`; on Fly, the `featherreader_data`
volume), stop the container or machine instead, and the files to wipe are
`/data/featherreader.db*` and `/data/oauth-signing-key.json`, plus, on an
instance upgraded from 0.4.x, any leftover `/data/oauth-sidecar.db*` and
`/data/oauth-sidecar.db.jwk.json`.

```bash
# systemd
sudo systemctl stop featherreader

# or docker/compose
docker compose stop featherreader
```

Sessions resume when you start the services again. Nothing is destroyed.

---

## B. Kill (irreversible) — wipe volume + revoke ALL sessions + clean WAL flush

This is the "pause forever / take it down" path. Run `deploy/teardown.sh`, or do
the steps by hand below. **This deletes all user data and signs everyone out.**

### One-shot script (self-hosted)

The script runs, in order:

1. The Rust revoke (main pass), while the app is still serving.
2. `FR_STOP_CMD`.
3. The Rust revoke again (sweep), **only if** `FEATHERREADER_DB` still holds
   sessions. The script counts them directly with `sqlite3`, so this step
   needs no running service. The sweep uses `FR_SWEEP_CMD` when it is set.
4. The wipe: `FEATHERREADER_DB` with a clean WAL checkpoint, the signing key
   at `FEATHERREADER_OAUTH_KEY_PATH`, and a leftover sidecar store if there is
   one (below).

A Rust pass counts as done only if it ends with the sentinel line and exits
`0` or `3` (see the table above); anything else aborts before the wipe. It
prompts for confirmation unless `FR_TEARDOWN_YES=1`.

```bash
# systemd (production). The revoke command needs the app's environment —
# here, the same EnvironmentFile the service uses.
sudo -E FEATHERREADER_DB=/var/lib/featherreader/featherreader.db \
        FEATHERREADER_OAUTH_KEY_PATH=/var/lib/featherreader/oauth-signing-key.json \
        FR_REVOKE_CMD='set -a; . /etc/featherreader/env; set +a; /usr/local/bin/featherreader --revoke-all-sessions' \
        FR_STOP_CMD="systemctl stop featherreader" \
        deploy/teardown.sh

# Docker Compose (data on the host at /srv/featherreader/data).
# The main pass runs INSIDE the running container (`exec`); the sweep runs
# after the stop, when there is no container to exec into, so it uses a
# one-off container from the same image and env (`run --rm`). `-T`: no TTY.
sudo -E FEATHERREADER_DB=/srv/featherreader/data/featherreader.db \
        FEATHERREADER_OAUTH_KEY_PATH=/srv/featherreader/data/oauth-signing-key.json \
        FR_REVOKE_CMD='docker compose exec -T featherreader featherreader --revoke-all-sessions' \
        FR_SWEEP_CMD='docker compose run --rm -T featherreader featherreader --revoke-all-sessions' \
        FR_STOP_CMD="docker compose stop featherreader" \
        deploy/teardown.sh
```

- **`FR_REVOKE_CMD`** defaults to `featherreader --revoke-all-sessions` when
  `featherreader` is on `PATH`.
  - It runs with the script's environment, and `FEATHERREADER_DB` is exported
    to it.
  - Make it source the app's own environment, as above. The script's handful
    of variables is **not** enough: see
    [the full list](#revoking-the-sessions).
  - If the env file also sets `FEATHERREADER_DB`, it must name the same file
    the script will wipe.
- **`FR_SWEEP_CMD`** is the post-stop sweep's command and defaults to
  `FR_REVOKE_CMD`.
  - The script **appends ` --sweep`** to it, so it must end with the
    `featherreader --revoke-all-sessions` invocation. `--sweep` lets the
    stopped app's JWKS be unreachable; a mismatched key still refuses.
  - Set it whenever `FR_REVOKE_CMD` needs the running service
    (`docker compose exec`): after the stop, that command fails.
  - The sweep runs only if sessions are left, so with nothing left a
    failing wrapper is never invoked.
  - If sessions *are* left and the sweep fails, the script aborts before the
    wipe and names `FR_SWEEP_CMD`. The services are already stopped then, so
    re-running the teardown with it set is safe.
  - In the paths above, `FEATHERREADER_DB` and `FEATHERREADER_OAUTH_KEY_PATH`
    are **host** paths: the script counts rows and wipes files from the host.
- **The script refuses** (exit 2, before anything irreversible) when there is
  no revoke command: neither `FR_REVOKE_CMD` nor `featherreader` on `PATH`.
- **`FEATHERREADER_REPO_BACKEND=sidecar` is refused** (exit 2, before
  anything). 0.5.0 removed the sidecar and cannot revoke its sessions. An
  instance still on that backend is running 0.4.x: run `deploy/teardown.sh`
  from that release instead, which revokes through the running sidecar's
  `/internal/revoke`. Unset or `rust` proceeds; any other value is refused.
- **A leftover sidecar store** from 0.4.x (`SIDECAR_DB` if set, else
  `oauth-sidecar.db` beside `FEATHERREADER_DB`) is wiped along with its
  `.jwk.json`, and the script prints a WARNING first: its sessions cannot be
  revoked by anyone (the sidecar is gone) and stay live at their PDSes until
  they expire. `SIDECAR_PUBLIC_URL` and `SIDECAR_INTERNAL_SECRET` are no longer
  used. (The 0.5.0 app no longer requires `SIDECAR_INTERNAL_SECRET` either; it
  warns at boot if any `SIDECAR_*` variable is still set.)
- **TTY wrappers.** A revoke command run through one (`docker compose exec`
  from a terminal, `ssh -t`) produces CRLF output. The script strips the `\r`
  before it reads the sentinel.
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

> A 0.4.x instance still on the sidecar backend should use the 0.4.x version
> of this runbook instead:
> <https://github.com/justin-stanley/feather-reader/blob/v0.4.10/deploy/teardown.md>.
> The steps below are for 0.5.0 and later.

1. **Revoke every session, while the app is still serving** (see
   [above](#revoking-the-sessions) for why it must be running):

   ```bash
   featherreader --revoke-all-sessions   # app's env; go on only on exit 0/3 + its last line
   ```

2. **Stop the service** so nothing writes to the DB mid-wipe:

   ```bash
   sudo systemctl stop featherreader   # or: docker compose stop featherreader
   ```

3. **Sweep** if anything is left. Check
   `sqlite3 "$FEATHERREADER_DB" 'SELECT COUNT(*) FROM oauth_session;'`.
   If the count is not 0, run `featherreader --revoke-all-sessions --sweep`
   once more for the sessions created between step 1 and the stop. Run it
   without the stopped service: the binary directly, or
   `docker compose run --rm …`, not `exec`.

4. **Clean WAL flush, then delete the SQLite files and the signing key.** A `wal_checkpoint(TRUNCATE)`
   folds the write-ahead log back into the main file so a snapshot/backup taken
   before this can't be resurrected from a stray `-wal`; then remove every file.
   `LEFTOVER` is the sidecar store a 0.4.x upgrade may have left behind; its
   sessions cannot be revoked (see the table at the top), only deleted:

   ```bash
   LEFTOVER="${SIDECAR_DB:-$(dirname "$FEATHERREADER_DB")/oauth-sidecar.db}"
   for db in "$FEATHERREADER_DB" "$LEFTOVER"; do
     [ -f "$db" ] && sqlite3 "$db" 'PRAGMA wal_checkpoint(TRUNCATE);' || true
     rm -f "$db" "$db-wal" "$db-shm"
   done
   rm -f "$LEFTOVER.jwk.json"
   # The Rust client's signing key:
   rm -f "$FEATHERREADER_OAUTH_KEY_PATH"
   ```

5. **(If containerised) remove the volume** so a restart can't rehydrate old data:

   ```bash
   docker compose down -v        # -v drops the named volumes
   ```

6. **Take down the edge** (optional but recommended for a real pause): stop the
   reverse proxy / DNS record for `feather-reader.com` so nobody hits a
   half-torn-down instance. `client-metadata.json` / `jwks.json` no longer need to
   be reachable once every session is revoked.

### Verify

```bash
# Run BEFORE the wipe: the Rust store is empty after the revoke.
sqlite3 "$FEATHERREADER_DB" 'SELECT COUNT(*) FROM oauth_session;'   # expect 0
# The leftover sidecar store, if there was one, is gone.
LEFTOVER="${SIDECAR_DB:-$(dirname "$FEATHERREADER_DB")/oauth-sidecar.db}"
[ -e "$LEFTOVER" ] || [ -e "$LEFTOVER.jwk.json" ] && echo "leftover sidecar store STILL PRESENT ✗" || echo "no sidecar store ✓"
# App cache is gone.
[ -f "$FEATHERREADER_DB" ] && echo "app DB STILL PRESENT ✗" || echo "app DB gone ✓"
```

Users' subscription/folder/saved **records live in their own PDS** and are
untouched by any of this — that is by design (their data on their server). Only
the tokens *we* held and the caches *we* built are destroyed.
