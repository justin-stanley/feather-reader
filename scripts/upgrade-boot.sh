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
#   2. seed rows the way the previous release stored them (an RSS feed, an
#      at:// publication without `kind`, and an entry without
#      `guid_synthesized`), so backfills run on real data
#   3. candidate migrates that volume
#   4. candidate boots fully (scheduler off, no network), answers /health,
#      and renders two stored bodies (below)
#   5. previous image boots fully again on the migrated volume, answers
#      /health, and renders the same two bodies (rollback)
#
# The bodies (#336): a plain one seeded in step 2, as every release before
# 0.5.2 stored it, and a compressed-only one planted after step 3, as 0.5.2
# stores it (tag byte 2, then raw deflate). Booting proves the schema; only
# rendering proves a rolled-back release can still READ what the candidate
# wrote. The page is fetched as FEATHERREADER_DEV_DID, which needs that DID in
# beta_access and a sub_ref row for the feed (with no network the PDS listing
# fails and the cached sub_refs are used). Needs python3 for the deflate.
#
# Needs docker, and sqlite3 on the host. **Nothing runs Node in an image**: the
# database is a host directory bind-mounted at /data, seeded with the host's
# sqlite3, and /health is read with bash's /dev/tcp inside the container. Both
# used `node` from the images until 0.5.0 removed Node from them (#311): a
# Node-free candidate failed step 4, and a Node-free PREVIOUS release (0.5.0,
# once it is the one upgraded from) would have failed step 2. Containers run as
# the invoking user with --network none, so the host can write the files they
# create.
set -euo pipefail

prev="${1:?usage: upgrade-boot.sh <previous-image> <candidate-image>}"
cand="${2:?usage: upgrade-boot.sh <previous-image> <candidate-image>}"

command -v sqlite3 >/dev/null || { echo "upgrade-boot.sh: needs sqlite3 on the host" >&2; exit 2; }
command -v python3 >/dev/null || { echo "upgrade-boot.sh: needs python3 on the host" >&2; exit 2; }

data="$(mktemp -d)"
box="fr-upgrade-boot-$$"
cleanup() {
  docker rm -f "$box" >/dev/null 2>&1 || true
  rm -rf "$data"
}
trap cleanup EXIT
db="$data/featherreader.db"
as_me=(--user "$(id -u):$(id -g)")

# The image bakes FEATHERREADER_ENV=prod, which refuses to start without the
# production secrets. dev skips that; the schema path is identical.
run() { # image, then args for the binary
  local image="$1"
  shift
  docker run --rm --network none "${as_me[@]}" -v "$data:/data" \
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
# The columns named are ones every release since 0.2.0 has, so the seed does not
# depend on which release is "previous"; the backfills fill the rest.
sqlite3 "$db" <<'SQL' || fail "could not seed the previous release's database"
INSERT INTO feeds (url) VALUES ('https://example.com/feed.xml');
INSERT INTO feeds (url) VALUES ('at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab');
-- An entry row as 0.4.8 stored it: no guid_synthesized column (#287).
INSERT INTO entries (feed_id, guid, url, fetched_at)
  SELECT id, '5813b43a0512aaef2750311bf4d978a', 'https://n.example/post', '2026-01-01T00:00:00Z'
  FROM feeds WHERE url = 'https://example.com/feed.xml';
-- A body as every release before 0.5.2 stored it: plain, in content_html.
INSERT INTO entries (feed_id, guid, url, fetched_at, content_html)
  SELECT id, 'upgrade-boot-plain', 'https://n.example/plain', '2026-01-01T00:00:00Z',
         '<p>upgrade-boot-plain-body</p>'
  FROM feeds WHERE url = 'https://example.com/feed.xml';
SQL
seeded="$(sqlite3 "$db" "SELECT (SELECT COUNT(*) FROM feeds) || ' ' || (SELECT COUNT(*) FROM entries)")"
[ "$seeded" = "2 2" ] || fail "the seed did not land (feeds, entries: ${seeded:-none})"

step "3/5 candidate migrates it ($cand)"
run "$cand" --migrate-auto-vacuum || fail "the candidate could not migrate a database the previous release created"

# A body as 0.5.2 stores it: compressed only (tag 2 = the only copy, then raw
# deflate, RFC 1951), content_html NULL. Planted after the migration because
# content_z only exists from 0.5.1. Plus what DEV_DID needs to read both.
dev_did="did:plc:upgradeboot"
sole_hex="$(python3 -c 'import zlib; c = zlib.compressobj(6, zlib.DEFLATED, -15); print((bytes([2]) + c.compress(b"<p>upgrade-boot-sole-body</p>") + c.flush()).hex())')"
sqlite3 "$db" <<SQL || fail "could not plant the compressed-only body"
INSERT INTO entries (feed_id, guid, url, fetched_at, content_html, content_z)
  SELECT id, 'upgrade-boot-sole', 'https://n.example/sole', '2026-01-01T00:00:00Z', NULL, X'$sole_hex'
  FROM feeds WHERE url = 'https://example.com/feed.xml';
INSERT INTO beta_access (did, granted_by, granted_at) VALUES ('$dev_did', 'upgrade-boot', 0);
INSERT INTO sub_ref (did, feed_id) SELECT '$dev_did', id FROM feeds WHERE url = 'https://example.com/feed.xml';
SQL
plain_id="$(sqlite3 "$db" "SELECT id FROM entries WHERE guid = 'upgrade-boot-plain'")"
sole_id="$(sqlite3 "$db" "SELECT id FROM entries WHERE guid = 'upgrade-boot-sole'")"
[ -n "$plain_id" ] && [ -n "$sole_id" ] || fail "the body rows are missing after the migration"

# A full boot — not just the schema path — that must answer /health with 200.
boot_and_check_health() { # image, label
  local image="$1" label="$2" health=""
  docker run -d --name "$box" --network none "${as_me[@]}" -v "$data:/data" \
    -e FEATHERREADER_ENV=dev -e FEATHERREADER_DB=/data/featherreader.db \
    -e FEATHERREADER_BIND=127.0.0.1:8082 -e FEATHERREADER_DISABLE_SCHEDULER=1 \
    -e FEATHERREADER_DEV_DID="$dev_did" \
    --entrypoint /app/featherreader "$image" >/dev/null
  for _ in $(seq 1 30); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$box" 2>/dev/null)" != "true" ]; then
      docker logs "$box" 2>&1 | tail -20 >&2
      fail "the $label exited during boot"
    fi
    # An HTTP/1.0 GET over bash's /dev/tcp, printed as "<status> <body>", the
    # shape the case below matches. bash is in every release's image.
    health="$(docker exec "$box" bash -c '
      exec 3<>/dev/tcp/127.0.0.1/8082 || exit 1
      printf "GET /health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n" >&3
      IFS=" " read -r _ status _ <&3 || exit 1
      while IFS= read -r line <&3 && [ "${line%$'"'"'\r'"'"'}" != "" ]; do :; done
      printf "%s " "$status"; cat <&3' 2>/dev/null || true)"
    [ -n "$health" ] && break
    sleep 1
  done
  case "$health" in
    "200 ok"*) echo "$health" | head -2 ;;
    *) docker logs "$box" 2>&1 | tail -20 >&2; fail "the $label did not report healthy: ${health:-no answer}" ;;
  esac
  # Each stored body must render on its entry page.
  local id marker page
  for pair in "$plain_id:upgrade-boot-plain-body" "$sole_id:upgrade-boot-sole-body"; do
    id="${pair%%:*}" marker="${pair#*:}"
    page="$(docker exec "$box" bash -c '
      exec 3<>/dev/tcp/127.0.0.1/8082 || exit 1
      printf "GET /entries/'"$id"' HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n" >&3
      cat <&3' 2>/dev/null || true)"
    case "$page" in
      "HTTP/1."?" 200"*) ;;
      *) docker logs "$box" 2>&1 | tail -20 >&2; fail "the $label did not serve entry $id: $(printf '%s' "$page" | head -1)" ;;
    esac
    grep -q "$marker" <<<"$page" || { docker logs "$box" 2>&1 | tail -20 >&2; fail "the $label served entry $id without its body ($marker)"; }
    echo "entry $id renders its body ($marker)"
  done
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
