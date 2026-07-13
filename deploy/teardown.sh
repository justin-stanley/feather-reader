#!/usr/bin/env bash
#
# FeatherReader kill/teardown: revoke ALL live OAuth sessions at their PDSes,
# then wipe both SQLite volumes with a clean WAL checkpoint.
#
# This makes the UI's "experimental, may pause at any time" promise operationally
# real. It is IRREVERSIBLE — all user caches are deleted and everyone is signed
# out. Users' subscription records live in their own PDS and are NOT touched.
#
# See deploy/teardown.md for the annotated manual steps and the reversible
# "pause" (no revoke, no delete) path.
#
# Required env:
#   FEATHERREADER_DB          path to the Rust app's SQLite cache
#   SIDECAR_DB                path to the sidecar's SQLite store
#   SIDECAR_PUBLIC_URL        base URL of the (still-running) sidecar
#   SIDECAR_INTERNAL_SECRET   the shared X-Internal-Secret
# Optional:
#   FR_TEARDOWN_YES=1         skip the interactive confirmation
#   FR_STOP_CMD="..."         command to stop the services before the wipe
#                             (e.g. "systemctl stop featherreader oauth-sidecar")
set -euo pipefail

need() { [ -n "${!1:-}" ] || { echo "FATAL: \$$1 is required" >&2; exit 2; }; }
need FEATHERREADER_DB
need SIDECAR_DB
need SIDECAR_PUBLIC_URL
need SIDECAR_INTERNAL_SECRET

command -v sqlite3 >/dev/null || { echo "FATAL: sqlite3 not found" >&2; exit 2; }
command -v curl    >/dev/null || { echo "FATAL: curl not found" >&2; exit 2; }

echo "FeatherReader TEARDOWN — this deletes ALL user data and revokes ALL sessions."
echo "  app DB      : $FEATHERREADER_DB"
echo "  sidecar DB  : $SIDECAR_DB"
echo "  sidecar URL : $SIDECAR_PUBLIC_URL"
if [ "${FR_TEARDOWN_YES:-}" != "1" ]; then
  printf 'Type EXACTLY "wipe" to proceed: '
  read -r reply
  [ "$reply" = "wipe" ] || { echo "aborted."; exit 1; }
fi

# 1. Revoke every DID at its PDS (needs the sidecar still running).
echo "==> Revoking all sessions at their PDSes…"
revoked=0
if [ -f "$SIDECAR_DB" ]; then
  while IFS= read -r did; do
    [ -n "$did" ] || continue
    if curl -fsS -X POST "$SIDECAR_PUBLIC_URL/internal/revoke" \
         -H "X-Internal-Secret: $SIDECAR_INTERNAL_SECRET" \
         -H 'content-type: application/json' \
         -d "{\"did\":\"$did\"}" >/dev/null; then
      echo "    revoked $did"
      revoked=$((revoked + 1))
    else
      echo "    WARN: revoke failed for $did (continuing)" >&2
    fi
  done < <(sqlite3 "$SIDECAR_DB" 'SELECT did FROM oauth_session;')
else
  echo "    (sidecar DB not found — nothing to revoke)"
fi
echo "==> Revoked $revoked session(s)."

# 2. Stop the services so nothing writes mid-wipe.
if [ -n "${FR_STOP_CMD:-}" ]; then
  echo "==> Stopping services: $FR_STOP_CMD"
  eval "$FR_STOP_CMD" || echo "    WARN: stop command returned non-zero (continuing)" >&2
else
  echo "==> No FR_STOP_CMD set — assuming services are already stopped."
fi

# 3. Clean WAL flush + delete both volumes (and the sidecar signing key).
echo "==> Wiping SQLite volumes with a clean WAL checkpoint…"
for db in "$FEATHERREADER_DB" "$SIDECAR_DB"; do
  if [ -f "$db" ]; then
    sqlite3 "$db" 'PRAGMA wal_checkpoint(TRUNCATE);' >/dev/null 2>&1 || true
  fi
  rm -f "$db" "$db-wal" "$db-shm"
  echo "    removed $db (+ -wal/-shm)"
done
rm -f "$SIDECAR_DB.jwk.json" && echo "    removed $SIDECAR_DB.jwk.json"

echo "==> Teardown complete. If containerised, also run: docker compose down -v"
