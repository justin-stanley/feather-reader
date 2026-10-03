#!/usr/bin/env bash
# Upgrade-boot gate: does a candidate image start against a database the
# PREVIOUS release created, and does the previous release still start after it?
#
#   ./scripts/upgrade-boot.sh <previous-image> <candidate-image>
#   ./scripts/upgrade-boot.sh ghcr.io/justin-stanley/feather-reader:"$(cat deploy/upgrade-from)" feather-reader:candidate
#
# Why it exists: 0.3.9 passed fmt, clippy, the rustdoc gate, 963 tests and a
# review, was tagged, published, and crash-looped production on its first boot
# with "no such column: kind". Every test started from an EMPTY database, where
# the column is in the CREATE TABLE and statement order cannot matter. This runs
# the real previous binary to make the database, so the old schema can never
# drift from what users actually have.
#
# Steps, each a hard failure:
#   1. previous image creates the schema on an empty volume (--migrate-auto-vacuum)
#   2. seed rows the way the previous release stored them (an RSS feed and an
#      at:// publication, without `kind`), so backfills run on real data
#   3. candidate migrates that volume
#   4. candidate boots fully (scheduler off, no network) and answers /health
#   5. previous image boots fully again on the migrated volume and answers
#      /health (rollback)
#
# Needs only docker. Runs as root inside the container with --network none.
set -euo pipefail

prev="${1:?usage: upgrade-boot.sh <previous-image> <candidate-image>}"
cand="${2:?usage: upgrade-boot.sh <previous-image> <candidate-image>}"

vol="fr-upgrade-boot-$$"
box="fr-upgrade-boot-$$"
cleanup() {
  docker rm -f "$box" >/dev/null 2>&1 || true
  docker volume rm -f "$vol" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker volume create "$vol" >/dev/null

# The image bakes FEATHERREADER_ENV=prod, which refuses to start without the
# production secrets. dev skips that; the schema path is identical.
run() { # image, then args for the binary
  local image="$1"
  shift
  docker run --rm --network none -v "$vol:/data" \
    -e FEATHERREADER_ENV=dev -e FEATHERREADER_DB=/data/featherreader.db \
    --entrypoint /app/featherreader "$image" "$@"
}

step() { echo "==> $*"; }
fail() {
  echo "::error title=upgrade-boot::$*"
  echo "FAIL: $*" >&2
  exit 1
}

step "1/5 previous release creates the database ($prev)"
run "$prev" --migrate-auto-vacuum || fail "the previous release could not create a database"

step "2/5 seed rows the way the previous release stored them"
docker run --rm --network none -v "$vol:/data" --entrypoint node "$prev" -e '
  const { DatabaseSync } = require("node:sqlite");
  const db = new DatabaseSync("/data/featherreader.db");
  const add = db.prepare("INSERT INTO feeds (url) VALUES (?)");
  add.run("https://example.com/feed.xml");
  add.run("at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab");
' || fail "could not seed the previous release's database"

step "3/5 candidate migrates it ($cand)"
run "$cand" --migrate-auto-vacuum || fail "the candidate could not migrate a database the previous release created"

# A full boot — not just the schema path — that must answer /health with 200.
boot_and_check_health() { # image, label
  local image="$1" label="$2" health=""
  docker run -d --name "$box" --network none -v "$vol:/data" \
    -e FEATHERREADER_ENV=dev -e FEATHERREADER_DB=/data/featherreader.db \
    -e FEATHERREADER_BIND=127.0.0.1:8082 -e FEATHERREADER_DISABLE_SCHEDULER=1 \
    --entrypoint /app/featherreader "$image" >/dev/null
  for _ in $(seq 1 30); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$box" 2>/dev/null)" != "true" ]; then
      docker logs "$box" 2>&1 | tail -20 >&2
      fail "the $label exited during boot"
    fi
    health="$(docker exec "$box" node -e '
      fetch("http://127.0.0.1:8082/health")
        .then(async r => { process.stdout.write(r.status + " " + await r.text()); })
        .catch(() => process.exit(1));' 2>/dev/null || true)"
    [ -n "$health" ] && break
    sleep 1
  done
  case "$health" in
    "200 ok"*) echo "$health" | head -2 ;;
    *) docker logs "$box" 2>&1 | tail -20 >&2; fail "the $label did not report healthy: ${health:-no answer}" ;;
  esac
  docker rm -f "$box" >/dev/null
}

step "4/5 candidate boots and answers /health"
boot_and_check_health "$cand" candidate

# Not just the schema path: a candidate can leave the database in a shape the
# previous release's schema setup accepts but its startup or /health does not,
# and only a full boot finds that. Rollback is a deploy of the previous image,
# so the check is a boot of the previous image.
step "5/5 previous release boots again on the migrated database (rollback)"
boot_and_check_health "$prev" "previous release, after the candidate migrated (rollback is broken)"

echo "upgrade-boot: OK ($prev -> $cand -> $prev)"
