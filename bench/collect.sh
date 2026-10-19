#!/usr/bin/env bash
# Sample a FeatherReader container under load, one CSV row per interval (#263).
#
#   bench/collect.sh CONTAINER DB_PATH SYNTH_URL [INTERVAL_SECS] > run.csv
#
# Runs on the host that runs the container (apps, for staging). Reads:
#   - `docker stats` for the container's memory and CPU;
#   - the SQLite file at DB_PATH, READ-ONLY (`sqlite3 -readonly`), for poll and
#     size figures: the app is never asked for anything, so sampling adds no
#     load to what is measured;
#   - SYNTH_URL/stats (synthfeeds' counters) for what was served.
# Stop with Ctrl-C. Needs: docker, sqlite3, curl, jq.
set -euo pipefail

container=${1:?container name}
db=${2:?path to the app database file}
synth=${3:?synthfeeds base URL, e.g. http://127.0.0.1:8263}
interval=${4:-15}

for tool in docker sqlite3 curl jq; do
  command -v "$tool" >/dev/null || { echo "collect.sh: needs $tool" >&2; exit 1; }
done
[ -r "$db" ] || { echo "collect.sh: cannot read $db" >&2; exit 1; }

echo "ts,mem_bytes,mem_limit_bytes,cpu_pct,db_bytes,wal_bytes,feeds,due_overdue_5m,ok_polled_10m,erroring,entries,synth_requests,synth_ok,synth_304,synth_errors,synth_bytes"

to_bytes() {
  # docker stats prints e.g. "212.3MiB"; normalise to bytes.
  awk -v v="$1" 'BEGIN {
    n = v + 0; u = v; sub(/^[0-9.]+/, "", u)
    m = (u == "KiB") ? 1024 : (u == "MiB") ? 1048576 : (u == "GiB") ? 1073741824 : (u == "kB") ? 1000 : (u == "MB") ? 1000000 : (u == "GB") ? 1000000000 : 1
    printf "%d", n * m }'
}

while :; do
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  # Every read falls back to empty fields: one failed sample (the container
  # restarting, SQLITE_BUSY through a checkpoint) must not end the whole run
  # under `set -e` (found in review).
  stats=$(docker stats --no-stream --format '{{.MemUsage}} {{.CPUPerc}}' "$container" 2>/dev/null \
    | awk '{ print $1 "|" $3, $4 }' || true)
  if [ -n "$stats" ]; then
    read -r mem cpu <<<"$stats"
    used=$(to_bytes "${mem%%|*}")
    limit=$(to_bytes "${mem##*|}")
    cpu=${cpu%\%}
  else
    used= limit= cpu=
  fi
  db_bytes=$(stat -c %s "$db" 2>/dev/null || echo "")
  wal_bytes=$(stat -c %s "$db-wal" 2>/dev/null || echo 0)
  # `ok_polled_10m` counts polls that succeeded (200 or 304), the only ones that
  # stamp `last_polled`; failures don't. Throughput is the change in
  # `synth_requests` between rows (found in review).
  sql=$(sqlite3 -readonly -cmd '.timeout 5000' -separator , "$db" "
    SELECT
      (SELECT COUNT(*) FROM feeds),
      (SELECT COUNT(*) FROM feeds WHERE next_poll IS NOT NULL
         AND next_poll < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-5 minutes')),
      (SELECT COUNT(*) FROM feeds WHERE last_polled >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-10 minutes')),
      (SELECT COUNT(*) FROM feeds WHERE consecutive_errors > 0),
      (SELECT COUNT(*) FROM entries);" 2>/dev/null || echo ",,,,")
  synth_csv=$(curl -fsS --max-time 5 "$synth/stats" \
    | jq -r '[.requests, .ok, .not_modified, .errors, .bytes] | @csv' 2>/dev/null || echo ",,,,")
  echo "$ts,$used,$limit,$cpu,$db_bytes,$wal_bytes,$sql,$synth_csv"
  sleep "$interval"
done
