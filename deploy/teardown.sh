#!/usr/bin/env bash
#
# FeatherReader kill/teardown: revoke ALL live OAuth sessions at their PDSes,
# then wipe the SQLite volumes (and signing keys) with a clean WAL checkpoint.
#
# This makes the UI's "experimental, may pause at any time" promise operationally
# real. It is IRREVERSIBLE — all user caches are deleted and everyone is signed
# out. Users' subscription records live in their own PDS and are NOT touched.
#
# See deploy/teardown.md for the annotated manual steps, the Fly procedure, and
# the reversible "pause" (no revoke, no delete) path.
#
# Both OAuth backends are revoked:
#   * sidecar: DIDs read from SIDECAR_DB, each POSTed to the running sidecar's
#     /internal/revoke;
#   * rust (production): FR_REVOKE_CMD, by default
#     `featherreader --revoke-all-sessions`, which revokes every row of
#     FEATHERREADER_DB's oauth_session at its PDS (RFC 7009) and deletes it.
#
# Order, and why:
#   1. sidecar revoke      — needs the sidecar process running.
#   2. rust revoke (main)  — while the app is still SERVING. The PDS
#      authenticates a confidential client before honouring a revocation
#      (@atproto/oauth-provider 0.23.1, `revoke()` -> `authenticateClient`),
#      which needs our client-metadata.json / jwks.json — served by the app
#      itself (src/web.rs). PDSes cache those for only 600 s, so revoking after
#      the stop would fail at most PDSes and leave those tokens live.
#   3. stop the services   — nothing writes mid-wipe, and no new logins.
#   4. rust revoke (sweep) — catches sessions created between 2 and 3. Runs
#      ONLY if FEATHERREADER_DB still holds Rust sessions (counted directly
#      with sqlite3), and with FR_SWEEP_CMD if set: the services are stopped
#      now, so a wrapper that needs them (docker compose exec) cannot run it.
#      A session found here may fail to revoke (metadata now offline), but its
#      row is still deleted and the failure reported.
#   5. wipe.
# Each Rust pass must end with the binary's summary line
# (`revoke-all-sessions: revoked=N no_session=M failed=K`) and exit 0 (all
# revoked) or 3 (some failed; rows deleted anyway — warns and continues).
# Anything else — 2 (nothing done), 1 (an older binary that ignored the flag, a
# failing wrapper), or no summary line — aborts BEFORE the wipe.
#
# Required env:
#   FEATHERREADER_DB          path to the Rust app's SQLite cache
#   SIDECAR_DB                path to the sidecar's SQLite store         [1]
#   SIDECAR_PUBLIC_URL        base URL of the (still-running) sidecar    [1]
#   SIDECAR_INTERNAL_SECRET   the shared X-Internal-Secret               [1]
#   [1] Optional when FEATHERREADER_REPO_BACKEND=rust and no SIDECAR_DB file
#       exists; required on the sidecar backend.
# Optional:
#   FEATHERREADER_REPO_BACKEND  `rust` or `sidecar` (the app's default)
#   FEATHERREADER_OAUTH_KEY_PATH  the Rust client's signing key; removed if set
#   FR_REVOKE_CMD="..."       the Rust revoke. Default:
#                             `featherreader --revoke-all-sessions` when
#                             `featherreader` is on PATH. Required (the script
#                             refuses without it) on the rust backend, or
#                             whenever FEATHERREADER_DB holds Rust sessions; on
#                             the sidecar backend it runs ONLY if there are.
#                             It needs the app's FULL runtime environment — the
#                             same one the serving app has: FEATHERREADER_DB,
#                             FEATHERREADER_PUBLIC_URL (non-loopback),
#                             FEATHERREADER_OAUTH_ENCRYPTION_KEY,
#                             FEATHERREADER_OAUTH_KEY_PATH (the existing key),
#                             FEATHERREADER_REPO_BACKEND, and the secrets
#                             Config requires on a production-like instance
#                             (FEATHERREADER_COOKIE_SECRET,
#                             SIDECAR_INTERNAL_SECRET, …). Run it INSIDE that
#                             environment — e.g. sourcing the systemd
#                             EnvironmentFile, `docker compose exec featherreader
#                             …`, or `fly ssh console -C` — not by re-typing
#                             variables here. With sessions stored it refuses
#                             (exit 2, nothing deleted) unless it is the
#                             production client: confidential, a real encryption
#                             key that DECRYPTS the stored rows, and the signing
#                             key the app SERVES at /oauth/jwks.json.
#   FR_SWEEP_CMD="..."        the post-stop sweep's command, if FR_REVOKE_CMD
#                             needs the running service. Default: FR_REVOKE_CMD.
#                             For Docker: FR_REVOKE_CMD='docker compose exec -T
#                             featherreader featherreader --revoke-all-sessions'
#                             and FR_SWEEP_CMD='docker compose run --rm -T
#                             featherreader featherreader --revoke-all-sessions'.
#                             The script APPENDS ` --sweep` (the app's JWKS is
#                             unreachable once it is stopped), so the command
#                             must end with the featherreader invocation.
#   FR_ACCEPT_UNREADABLE=1    pass --accept-unreadable to both Rust passes: go
#                             on when NO stored Rust session decrypts (only
#                             pre-AAD rows; key rotated with no logins since).
#                             Those tokens cannot be revoked by anyone. See
#                             teardown.md before using it.
#   FR_TEARDOWN_YES=1         skip the interactive confirmation
#   FR_STOP_CMD="..."         command to stop the services before the wipe
#                             (e.g. "systemctl stop featherreader oauth-sidecar")
set -euo pipefail

need() { [ -n "${!1:-}" ] || { echo "FATAL: \$$1 is required" >&2; exit 2; }; }
need FEATHERREADER_DB
export FEATHERREADER_DB

command -v sqlite3 >/dev/null || { echo "FATAL: sqlite3 not found" >&2; exit 2; }

backend="${FEATHERREADER_REPO_BACKEND:-sidecar}"

# The sidecar step runs unless this is the rust backend with no sidecar store.
sidecar_step=1
if [ "$backend" = "rust" ] && { [ -z "${SIDECAR_DB:-}" ] || [ ! -f "$SIDECAR_DB" ]; }; then
  sidecar_step=0
fi
if [ "$sidecar_step" = 1 ]; then
  need SIDECAR_DB
  need SIDECAR_PUBLIC_URL
  need SIDECAR_INTERNAL_SECRET
  command -v curl >/dev/null || { echo "FATAL: curl not found" >&2; exit 2; }
fi

# Rust session rows in FEATHERREADER_DB, read directly — no service needed.
# 0 only when there is no file; "unknown" whenever sqlite3 cannot answer
# (corrupt, locked, unreadable, no such table). Unknown is NEVER read as 0:
# that would skip the Rust step and wipe whatever tokens the file holds.
count_rust_rows() {
  if [ ! -e "$FEATHERREADER_DB" ]; then
    echo 0
    return
  fi
  sqlite3 "$FEATHERREADER_DB" 'SELECT COUNT(*) FROM oauth_session;' 2>/dev/null || echo unknown
}

# Rust sessions present? Anything but a definite 0 runs the Rust step.
rust_rows="$(count_rust_rows)"

# Decide the Rust revoke command up front: refusing must happen BEFORE anything
# irreversible (the sidecar revoke signs people out), not halfway through.
revoke_cmd="${FR_REVOKE_CMD:-}"
if [ -z "$revoke_cmd" ] && command -v featherreader >/dev/null; then
  revoke_cmd="featherreader --revoke-all-sessions"
fi
# Runs on the rust backend, or wherever FEATHERREADER_DB holds Rust sessions —
# and NOT merely because a revoke command is available: on the sidecar backend
# with no app DB, the binary would (rightly) refuse with "no database" and
# abort a teardown that has nothing Rust to revoke.
rust_step=0
if [ "$backend" = "rust" ] || [ "${rust_rows:-0}" != "0" ]; then
  rust_step=1
  if [ -z "$revoke_cmd" ]; then
    echo "FATAL: the Rust OAuth client holds sessions (backend=$backend, $rust_rows stored)," >&2
    echo "       and there is no revoke command. Wiping now would drop every token" >&2
    echo "       UNREVOKED. Set FR_REVOKE_CMD (e.g. \"/usr/local/bin/featherreader" >&2
    echo "       --revoke-all-sessions\") or put featherreader on PATH. See" >&2
    echo "       deploy/teardown.md. Nothing has been changed." >&2
    exit 2
  fi
fi

echo "FeatherReader TEARDOWN — this deletes ALL user data and revokes ALL sessions."
echo "  backend     : $backend"
echo "  app DB      : $FEATHERREADER_DB ($rust_rows Rust session(s))"
if [ "$sidecar_step" = 1 ]; then
  echo "  sidecar DB  : $SIDECAR_DB"
  echo "  sidecar URL : $SIDECAR_PUBLIC_URL"
fi
if [ "$rust_step" = 1 ]; then echo "  rust revoke : $revoke_cmd"; fi
# FR_ACCEPT_UNREADABLE=1: pass --accept-unreadable to both Rust passes. Only
# for a store that is legitimately ALL unreadable (see teardown.md).
accept_flag=""
if [ "${FR_ACCEPT_UNREADABLE:-}" = "1" ]; then
  accept_flag=" --accept-unreadable"
  echo "  WARNING     : FR_ACCEPT_UNREADABLE=1 — if NO stored Rust session decrypts," >&2
  echo "                every row is deleted UNREVOKED: those tokens cannot be revoked" >&2
  echo "                by anyone and stay live at their PDS until they expire." >&2
fi
if [ "${FR_TEARDOWN_YES:-}" != "1" ]; then
  printf 'Type EXACTLY "wipe" to proceed: '
  read -r reply
  [ "$reply" = "wipe" ] || { echo "aborted."; exit 1; }
fi

# Run the Rust revoke. Proceed ONLY on the binary's own proof of completion:
# its last stdout line is the sentinel
#   revoke-all-sessions: revoked=N no_session=M failed=K
# and the exit code agrees with it — 0 with failed=0, or 3 with failed>0 (some
# revocations failed; rows deleted anyway). Anything else aborts before the
# wipe: 2 is the binary's "nothing done", and an exit code without the sentinel
# is not this command at all — an older featherreader ignores the unknown flag,
# tries to start a server and exits 1 when the port is taken, and a wrapper
# (docker compose exec, ssh) fails with 1 too.
#   $1 the pass ("main pass" / "sweep"), $2 the command to run.
rust_revoke() {
  echo "==> Revoking all Rust-backend sessions ($1): $2"
  local rc=0 out last failed
  out="$(mktemp "${TMPDIR:-/tmp}/fr-revoke.XXXXXX")"
  eval "$2" >"$out" || rc=$?
  cat "$out"
  # `tr -d '\r'`: a TTY wrapper (docker compose exec from a terminal, ssh -t,
  # fly ssh console) turns every \n into \r\n, and a trailing \r would make the
  # sentinel never match — failing safe, but a teardown that can never finish.
  last="$(tr -d '\r' <"$out" | grep -v '^[[:space:]]*$' | tail -n 1 || true)"
  rm -f "$out"
  failed=""
  if [[ "$last" =~ ^revoke-all-sessions:\ revoked=[0-9]+\ no_session=[0-9]+\ failed=([0-9]+)$ ]]; then
    failed="${BASH_REMATCH[1]}"
  fi
  if [ "$rc" = 0 ] && [ "$failed" = 0 ]; then
    echo "==> Rust revoke ($1) complete."
  elif [ "$rc" = 3 ] && [ -n "$failed" ] && [ "$failed" != 0 ]; then
    echo "    WARN: $failed Rust revocation(s) FAILED (rows deleted anyway; those" >&2
    echo "          tokens may stay live at their PDS until they expire). Continuing." >&2
  else
    echo "FATAL: the Rust revoke ($1) exited $rc with last line \"$last\" —" >&2
    echo "       not a completed --revoke-all-sessions (exit 0 or 3 plus its" >&2
    echo "       summary line)." >&2
    if [ "$rc" = 2 ]; then
      echo "       It REFUSED and deleted nothing; its reason is printed above" >&2
      echo "       (usually an incomplete environment)." >&2
    else
      echo "       Is the binary older than this script, or did a wrapper fail?" >&2
    fi
    if [ "$1" = "sweep" ] && [ -z "${FR_SWEEP_CMD:-}" ]; then
      echo "       The sweep runs AFTER the stop, so a command that needs the" >&2
      echo "       running service (docker compose exec, fly ssh console) cannot" >&2
      echo "       work here. Set FR_SWEEP_CMD to one that runs without it, e.g." >&2
      echo "       FR_SWEEP_CMD='docker compose run --rm featherreader featherreader --revoke-all-sessions'" >&2
      echo "       — the services are stopped; re-running the teardown is safe." >&2
    fi
    echo "       ABORTING before the wipe; see deploy/teardown.md." >&2
    exit 2
  fi
}

# 1. Revoke every sidecar DID at its PDS (needs the sidecar still running).
if [ "$sidecar_step" = 1 ]; then
  echo "==> Revoking all sidecar sessions at their PDSes…"
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
  echo "==> Revoked $revoked sidecar session(s)."
fi

# 2. Rust revoke, main pass — while the app still serves its client metadata.
if [ "$rust_step" = 1 ]; then rust_revoke "main pass" "$revoke_cmd$accept_flag"; fi

# 3. Stop the services so nothing writes mid-wipe.
if [ -n "${FR_STOP_CMD:-}" ]; then
  echo "==> Stopping services: $FR_STOP_CMD"
  eval "$FR_STOP_CMD" || echo "    WARN: stop command returned non-zero (continuing)" >&2
else
  echo "==> No FR_STOP_CMD set — assuming services are already stopped."
fi

# 4. Rust revoke, sweep — sessions created between the main pass and the stop.
#    Only if any are left: counted straight from the file, because the usual
#    main-pass command (`docker compose exec`, `fly ssh console`) needs the
#    service this step runs after stopping. A teardown whose main pass emptied
#    the store must not be wedged by a sweep that cannot start.
if [ "$rust_step" = 1 ]; then
  left="$(count_rust_rows)"
  if [ "$left" = 0 ]; then
    echo "==> No Rust sessions left after the stop — sweep skipped."
  else
    echo "==> $left Rust session(s) left after the stop — sweeping."
    # `--sweep`, appended (so the command must END with the featherreader
    # invocation): the app is stopped, so its /oauth/jwks.json cannot be
    # fetched for the signing-key check — expected here, and only here. A
    # key that is fetched and does not match still refuses.
    rust_revoke "sweep" "${FR_SWEEP_CMD:-$revoke_cmd}$accept_flag --sweep"
  fi
fi

# 5. Clean WAL flush + delete the volumes and the signing keys.
echo "==> Wiping SQLite volumes with a clean WAL checkpoint…"
dbs=("$FEATHERREADER_DB")
[ -n "${SIDECAR_DB:-}" ] && dbs+=("$SIDECAR_DB")
for db in "${dbs[@]}"; do
  if [ -f "$db" ]; then
    sqlite3 "$db" 'PRAGMA wal_checkpoint(TRUNCATE);' >/dev/null 2>&1 || true
  fi
  rm -f "$db" "$db-wal" "$db-shm"
  echo "    removed $db (+ -wal/-shm)"
done
if [ -n "${SIDECAR_DB:-}" ]; then
  rm -f "$SIDECAR_DB.jwk.json" && echo "    removed $SIDECAR_DB.jwk.json"
fi
if [ -n "${FEATHERREADER_OAUTH_KEY_PATH:-}" ]; then
  rm -f "$FEATHERREADER_OAUTH_KEY_PATH" && echo "    removed $FEATHERREADER_OAUTH_KEY_PATH"
fi

echo "==> Teardown complete. If containerised, also run: docker compose down -v"
