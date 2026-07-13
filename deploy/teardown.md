# FeatherReader — pause / kill teardown runbook

FeatherReader is an experiment and the UI promises it "may pause at any time."
This runbook is what makes that promise **operationally real**: how an operator
wipes every scrap of user state, revokes every live OAuth session at users' PDSes,
and stops the service cleanly.

There are two related but distinct wipes:

| Layer | What it holds | Wiped by |
|---|---|---|
| **Rust app** (`featherreader`) | The SQLite cache: `entry_state`, `read_cursor`, `sub_ref`, `beta_access`, `invite_codes`, plus the shared `feeds`/`entries` cache. Signed session cookies are keyed by DID but hold no server secret beyond the cookie HMAC. | Deleting `FEATHERREADER_DB` (+ `-wal`/`-shm`). |
| **OAuth sidecar** (`oauth-sidecar`) | Per-DID OAuth tokens (refresh + access, DPoP keys) and the `session_id` handoff rows, in its own SQLite (`SIDECAR_DB`), AEAD-encrypted at rest. Plus the confidential-client signing JWK at `${SIDECAR_DB}.jwk.json`. | `POST /internal/revoke` per DID (revokes at the PDS **and** drops the row), then deleting `SIDECAR_DB`. |

A user-initiated `POST /account/delete` already does the per-user version of both
(purge that DID's app rows + sidecar `/internal/revoke`). `/logout` does the
sidecar-revoke half. This runbook is the **fleet-wide** version.

> Order matters. Revoke at the PDS *before* deleting the sidecar DB — once the
> encrypted token rows are gone you can no longer ask the PDS to invalidate them,
> and stale refresh tokens would live out their natural TTL on the PDS side.

---

## A. Pause (reversible) — stop serving, keep data

Use this for a maintenance window or a temporary pause where you intend to come
back. It does **not** revoke tokens or delete anything.

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

### One-shot script

```bash
# Revokes every DID at its PDS, then wipes both SQLite volumes with a clean
# WAL checkpoint. Prompts for confirmation unless FR_TEARDOWN_YES=1.
sudo -E FEATHERREADER_DB=/var/lib/featherreader/featherreader.db \
        SIDECAR_DB=/var/lib/featherreader/oauth-sidecar.db \
        SIDECAR_PUBLIC_URL=http://127.0.0.1:8081 \
        SIDECAR_INTERNAL_SECRET="$(cat /etc/featherreader/internal_secret)" \
        deploy/teardown.sh
```

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

2. **Stop the services** so nothing writes to the DBs mid-wipe:

   ```bash
   sudo systemctl stop featherreader oauth-sidecar   # or: docker compose stop …
   ```

3. **Clean WAL flush, then delete both SQLite volumes.** A `wal_checkpoint(TRUNCATE)`
   folds the write-ahead log back into the main file so a snapshot/backup taken
   before this can't be resurrected from a stray `-wal`; then remove every file:

   ```bash
   for db in "$FEATHERREADER_DB" "$SIDECAR_DB"; do
     [ -f "$db" ] && sqlite3 "$db" 'PRAGMA wal_checkpoint(TRUNCATE);' || true
     rm -f "$db" "$db-wal" "$db-shm"
   done
   # The sidecar's confidential-client signing key lives beside its DB:
   rm -f "$SIDECAR_DB.jwk.json"
   ```

4. **(If containerised) remove the volume** so a restart can't rehydrate old data:

   ```bash
   docker compose down -v        # -v drops the named volumes
   ```

5. **Take down the edge** (optional but recommended for a real pause): stop the
   reverse proxy / DNS record for `reader.justin-stanley.com` so nobody hits a
   half-torn-down instance. `client-metadata.json` / `jwks.json` no longer need to
   be reachable once every session is revoked.

### Verify

```bash
# No sessions remain in the sidecar store (file is gone → this errors, which is fine).
sqlite3 "$SIDECAR_DB" 'SELECT COUNT(*) FROM oauth_session;' 2>/dev/null || echo "sidecar DB gone ✓"
# App cache is gone.
[ -f "$FEATHERREADER_DB" ] && echo "app DB STILL PRESENT ✗" || echo "app DB gone ✓"
```

Users' subscription/folder/saved **records live in their own PDS** and are
untouched by any of this — that is by design (their data on their server). Only
the tokens *we* held and the caches *we* built are destroyed.
