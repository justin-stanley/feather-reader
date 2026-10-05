#!/usr/bin/env bash
#
# Tests for deploy/teardown.sh, run against throwaway SQLite files in a temp
# directory. Nothing real is touched: the sidecar is a `curl` stub on PATH, the
# Rust revoke is a stub FR_REVOKE_CMD, and the stop command only logs.
#
# What is pinned (issue #257):
#   * the order: sidecar revoke -> Rust revoke (app still running) -> stop ->
#     Rust revoke sweep -> wipe;
#   * on the rust backend (or with Rust sessions stored) and no revoke command,
#     the script refuses BEFORE doing anything irreversible;
#   * the wipe proceeds only after a revoke that exited 0 or 3 AND printed the
#     binary's sentinel line, agreeing with the exit code (3 warns). Anything
#     else — 2, 1 (an older binary ignoring the flag, a failing wrapper), or a
#     missing/contradictory sentinel — aborts with every file still present;
#   * the sidecar variables are optional on the rust backend.
#
# Usage: bash scripts/test-teardown.sh   (needs bash and sqlite3)
#
# The `check` conditions are single-quoted on purpose: they are eval'd after
# each run, so they must not expand at the call site (SC2016), and CODE is read
# inside them (SC2034).
# shellcheck disable=SC2016,SC2034,SC2001
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEARDOWN="$ROOT/deploy/teardown.sh"
command -v sqlite3 >/dev/null || { echo "FATAL: sqlite3 not found" >&2; exit 2; }
SQLITE3="$(command -v sqlite3)"

pass=0
fail=0
T=""

ok()   { pass=$((pass + 1)); echo "  ok   - $1"; }
bad()  { fail=$((fail + 1)); echo "  FAIL - $1"; [ -n "${OUT:-}" ] && sed 's/^/         | /' <<<"$OUT"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# A fresh sandbox: an app DB with Rust sessions, a sidecar DB with sidecar
# sessions, the sidecar JWK, the Rust signing key, and the stubs.
setup() {
  T="$(mktemp -d "${TMPDIR:-/tmp}/fr-teardown-test.XXXXXX")"
  mkdir -p "$T/bin"
  LOG="$T/log"
  : >"$LOG"
  APP_DB="$T/featherreader.db"
  SC_DB="$T/oauth-sidecar.db"
  KEY="$T/oauth-signing-key.json"
  "$SQLITE3" "$APP_DB" "CREATE TABLE oauth_session (sub TEXT PRIMARY KEY);
                        INSERT INTO oauth_session VALUES ('did:plc:rust1');"
  "$SQLITE3" "$SC_DB" "CREATE TABLE oauth_session (did TEXT PRIMARY KEY);
                       INSERT INTO oauth_session VALUES ('did:plc:side1');"
  echo '{}' >"$SC_DB.jwk.json"
  echo '{}' >"$KEY"

  # The sidecar's /internal/revoke, as seen through curl.
  cat >"$T/bin/curl" <<EOF
#!/usr/bin/env bash
body=""
while [ \$# -gt 0 ]; do
  case "\$1" in -d) body="\$2"; shift ;; esac
  shift
done
echo "sidecar-revoke \$body" >>"$LOG"
EOF
  # The Rust revoke. Successive calls take successive lines of $T/revoke-exits
  # (the last repeats), each "CODE SENTINEL":
  #   CODE      the exit code;
  #   SENTINEL  `-` print none (an older binary, a failing wrapper), or `fN`
  #             print the real binary's last line with failed=N.
  # It records whether the app DB was still there and which FEATHERREADER_DB it
  # was handed, so the test can prove it ran before the wipe on the right file.
  cat >"$T/bin/revoke-stub" <<EOF
#!/usr/bin/env bash
n=\$(grep -c '^rust-revoke' "$LOG")
line=\$(sed -n "\$((n + 1))p" "$T/revoke-exits" 2>/dev/null)
[ -n "\$line" ] || line=\$(tail -n 1 "$T/revoke-exits" 2>/dev/null)
read -r code sentinel <<<"\$line"
[ -f "\$FEATHERREADER_DB" ] && present=db-present || present=db-absent
echo "rust-revoke \$present \$FEATHERREADER_DB" >>"$LOG"
echo "    revoked did:plc:rust1"
case "\$sentinel" in
  f*) echo "revoke-all-sessions: revoked=1 no_session=0 failed=\${sentinel#f}" ;;
esac
exit "\${code:-0}"
EOF
  chmod +x "$T/bin/curl" "$T/bin/revoke-stub"
  echo "0 f0" >"$T/revoke-exits"
}

teardown_sandbox() { [ -n "$T" ] && rm -rf "$T"; T=""; }

# Run teardown.sh with a minimal PATH (the stubs, then the system), so neither
# a real curl nor an installed `featherreader` can be reached.
run() {
  OUT="$(env -i HOME="$T" PATH="$T/bin:/usr/bin:/bin" FR_TEARDOWN_YES=1 \
           FEATHERREADER_DB="$APP_DB" "$@" bash "$TEARDOWN" 2>&1)"
  CODE=$?
}

# The `kind` of each log line, in order: sidecar-revoke / rust-revoke / stop.
order() { awk '{print $1}' "$LOG" | uniq | paste -sd' ' -; }
all_present() { [ -f "$APP_DB" ] && [ -f "$SC_DB" ] && [ -f "$SC_DB.jwk.json" ] && [ -f "$KEY" ]; }
none_present() { [ ! -e "$APP_DB" ] && [ ! -e "$SC_DB" ] && [ ! -e "$SC_DB.jwk.json" ] && [ ! -e "$KEY" ]; }

sidecar_env() { SIDECAR=(SIDECAR_DB="$SC_DB" SIDECAR_PUBLIC_URL=http://127.0.0.1:9 SIDECAR_INTERNAL_SECRET=s); }

echo "== rust backend: sidecar revoke -> rust revoke -> stop -> rust sweep -> wipe"
setup; sidecar_env
run FEATHERREADER_REPO_BACKEND=rust "${SIDECAR[@]}" FEATHERREADER_OAUTH_KEY_PATH="$KEY" \
    FR_STOP_CMD="echo stop >>'$LOG'" FR_REVOKE_CMD="$T/bin/revoke-stub"
check "exits 0" '[ "$CODE" = 0 ]'
check "order is sidecar-revoke rust-revoke stop rust-revoke (got: $(order))" \
      '[ "$(order)" = "sidecar-revoke rust-revoke stop rust-revoke" ]'
check "the sidecar DID was revoked" 'grep -q "did:plc:side1" "$LOG"'
check "both rust passes ran before the wipe, against FEATHERREADER_DB" \
      '[ "$(grep -c "^rust-revoke db-present $APP_DB\$" "$LOG")" = 2 ]'
check "every file is wiped, the Rust signing key included" 'none_present'
teardown_sandbox

echo "== rust backend, no revoke command available: refuse before anything"
setup; sidecar_env
run FEATHERREADER_REPO_BACKEND=rust "${SIDECAR[@]}" FEATHERREADER_OAUTH_KEY_PATH="$KEY" \
    FR_STOP_CMD="echo stop >>'$LOG'"
check "exits non-zero" '[ "$CODE" != 0 ]'
check "every file is still present" 'all_present'
check "nothing was revoked or stopped (log: $(order))" '[ ! -s "$LOG" ]'
check "the refusal points at teardown.md" 'grep -q "teardown.md" <<<"$OUT"'
teardown_sandbox

echo "== sidecar backend, but Rust sessions stored and no revoke command: refuse"
setup; sidecar_env
run FEATHERREADER_REPO_BACKEND=sidecar "${SIDECAR[@]}" FR_STOP_CMD="echo stop >>'$LOG'"
check "exits non-zero" '[ "$CODE" != 0 ]'
check "every file is still present" 'all_present'
teardown_sandbox

echo "== sidecar backend, no Rust sessions, no revoke command: proceeds"
setup; sidecar_env
"$SQLITE3" "$APP_DB" "DELETE FROM oauth_session;"
run FEATHERREADER_REPO_BACKEND=sidecar "${SIDECAR[@]}" FR_STOP_CMD="echo stop >>'$LOG'"
check "exits 0" '[ "$CODE" = 0 ]'
check "order is sidecar-revoke stop (got: $(order))" '[ "$(order)" = "sidecar-revoke stop" ]'
check "both DBs are wiped" '[ ! -e "$APP_DB" ] && [ ! -e "$SC_DB" ]'
teardown_sandbox

# Outcomes of the FIRST pass that must abort with nothing stopped or wiped.
# Only (0 + sentinel failed=0) and (3 + sentinel failed>0) may proceed.
#   "2 -"  the binary's own "nothing done"
#   "1 -"  an OLDER binary that ignores the flag and fails to bind, or a
#          wrapper (docker compose exec, ssh) failing
#   "1 f1" exit 1 even with a sentinel: 1 is no longer the partial-failure code
#   "0 -"  success with no sentinel: something that is not this command
#   "3 -"  partial failure with no sentinel
#   "0 f1" exit and sentinel disagree (success claimed, failures counted)
#   "3 f0" exit and sentinel disagree (failure claimed, none counted)
for outcome in "2 -" "1 -" "1 f1" "0 -" "3 -" "0 f1" "3 f0"; do
  echo "== rust revoke outcome \"$outcome\" on the first pass: abort, nothing stopped or wiped"
  setup; sidecar_env
  echo "$outcome" >"$T/revoke-exits"
  run FEATHERREADER_REPO_BACKEND=rust "${SIDECAR[@]}" FEATHERREADER_OAUTH_KEY_PATH="$KEY" \
      FR_STOP_CMD="echo stop >>'$LOG'" FR_REVOKE_CMD="$T/bin/revoke-stub"
  check "exits non-zero" '[ "$CODE" != 0 ]'
  check "every file is still present" 'all_present'
  check "the services were not stopped (got: $(order))" '! grep -q "^stop" "$LOG"'
  teardown_sandbox
done

echo "== rust revoke exits 2 on the sweep: abort before the wipe"
setup; sidecar_env
printf '0 f0\n2 -\n' >"$T/revoke-exits"
run FEATHERREADER_REPO_BACKEND=rust "${SIDECAR[@]}" FEATHERREADER_OAUTH_KEY_PATH="$KEY" \
    FR_STOP_CMD="echo stop >>'$LOG'" FR_REVOKE_CMD="$T/bin/revoke-stub"
check "exits non-zero" '[ "$CODE" != 0 ]'
check "the app DB and key are still present" '[ -f "$APP_DB" ] && [ -f "$KEY" ]'
teardown_sandbox

echo "== an older binary on the sweep (exit 1, no sentinel): abort before the wipe"
setup; sidecar_env
printf '0 f0\n1 -\n' >"$T/revoke-exits"
run FEATHERREADER_REPO_BACKEND=rust "${SIDECAR[@]}" FEATHERREADER_OAUTH_KEY_PATH="$KEY" \
    FR_STOP_CMD="echo stop >>'$LOG'" FR_REVOKE_CMD="$T/bin/revoke-stub"
check "exits non-zero" '[ "$CODE" != 0 ]'
check "the app DB and key are still present" '[ -f "$APP_DB" ] && [ -f "$KEY" ]'
teardown_sandbox

echo "== rust revoke exits 3 with its sentinel (some failures): warn and wipe"
setup; sidecar_env
echo "3 f1" >"$T/revoke-exits"
run FEATHERREADER_REPO_BACKEND=rust "${SIDECAR[@]}" FEATHERREADER_OAUTH_KEY_PATH="$KEY" \
    FR_STOP_CMD="echo stop >>'$LOG'" FR_REVOKE_CMD="$T/bin/revoke-stub"
check "exits 0" '[ "$CODE" = 0 ]'
check "warns about the failures" 'grep -qi "warn" <<<"$OUT"'
check "the revoke output is shown to the operator" 'grep -q "revoked did:plc:rust1" <<<"$OUT"'
check "every file is wiped" 'none_present'
teardown_sandbox

echo "== rust backend with no sidecar variables at all: they are optional"
setup
rm -f "$SC_DB" "$SC_DB.jwk.json"
run FEATHERREADER_REPO_BACKEND=rust FEATHERREADER_OAUTH_KEY_PATH="$KEY" \
    FR_STOP_CMD="echo stop >>'$LOG'" FR_REVOKE_CMD="$T/bin/revoke-stub"
check "exits 0" '[ "$CODE" = 0 ]'
check "order is rust-revoke stop rust-revoke (got: $(order))" \
      '[ "$(order)" = "rust-revoke stop rust-revoke" ]'
check "the app DB and key are wiped" '[ ! -e "$APP_DB" ] && [ ! -e "$KEY" ]'
teardown_sandbox

echo "== sidecar backend still requires the sidecar variables"
setup
run FEATHERREADER_REPO_BACKEND=sidecar FR_REVOKE_CMD="$T/bin/revoke-stub"
check "exits non-zero" '[ "$CODE" != 0 ]'
check "names the missing variable" 'grep -q "SIDECAR_DB" <<<"$OUT"'
check "every file is still present" '[ -f "$APP_DB" ] && [ -f "$SC_DB" ]'
teardown_sandbox

echo "== the default revoke command is featherreader --revoke-all-sessions on PATH"
setup
rm -f "$SC_DB" "$SC_DB.jwk.json"
cat >"$T/bin/featherreader" <<EOF
#!/usr/bin/env bash
echo "rust-revoke db-present args=\$*" >>"$LOG"
echo "revoke-all-sessions: revoked=0 no_session=0 failed=0"
EOF
chmod +x "$T/bin/featherreader"
run FEATHERREADER_REPO_BACKEND=rust FR_STOP_CMD="echo stop >>'$LOG'"
check "exits 0" '[ "$CODE" = 0 ]'
check "ran featherreader --revoke-all-sessions twice" \
      '[ "$(grep -c "args=--revoke-all-sessions\$" "$LOG")" = 2 ]'
teardown_sandbox

echo
echo "teardown tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
