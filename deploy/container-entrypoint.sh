#!/bin/bash
# FeatherReader in-container supervisor.
#
# Runs under bash (installed in the image) — NOT the Debian default /bin/sh
# (dash), because the first-child-exit wait below uses bash's `wait -n`, which
# dash does not support (it errors "Illegal option -n" and returns immediately,
# which would tear the container down on boot).
#
# Two-phase startup:
#   PHASE 1 (ROOT): fix ownership of the /data volume. A fresh Fly volume mounts
#     at /data owned root:root at RUNTIME, masking the image's build-time chown.
#     The three children run as the unprivileged `app` user (uid 10001) and each
#     open files under /data (the Rust DB, the sidecar DB + signing JWK, Caddy's
#     XDG_DATA_HOME). Without this chown they get EACCES on a virgin volume and
#     crash-loop. We do it ONCE as root, then drop privileges.
#   PHASE 2 (app via gosu): run under tini (PID1), which reaps zombies and
#     forwards SIGTERM/SIGINT to us; we fan those out to the three children.
#
# This is a deliberate, tiny alternative to s6-overlay/supervisord: for this app
# a dead proxy, dead poller, or dead OAuth sidecar all mean "broken", so the
# correct behaviour is to bring the WHOLE container down and let Fly restart the
# machine (min_machines_running=1) rather than serve a half-dead instance.
#
# Processes (ports chosen so only Caddy is reachable off-loopback):
#   caddy         :8080          public edge (= Fly internal_port)
#   featherreader 127.0.0.1:8082 Rust app (loopback only)
#   node sidecar  127.0.0.1:8081 OAuth sidecar (loopback only; /internal/* here)
set -eu

DATA_DIR="${DATA_DIR:-/data}"
APP_USER="${APP_USER:-app}"

# ── PHASE 1: as root, fix the mounted-volume ownership, then re-exec as `app`. ──
# `id -u` == 0 only on the first (root) pass; after gosu re-exec we are `app` and
# skip straight to PHASE 2. Do NOT swallow errors here — a real chmod/chown
# failure must surface loudly, not be masked by `|| true`.
if [ "$(id -u)" = "0" ]; then
    mkdir -p "${DATA_DIR}" "${DATA_DIR}/caddy"
    chown -R "${APP_USER}:${APP_USER}" "${DATA_DIR}"
    # Re-exec THIS script as the app user (still under tini as PID1).
    exec gosu "${APP_USER}" "$0" "$@"
fi

# ── PHASE 2: unprivileged supervisor. ──────────────────────────────────────
pids=""
term() {
    # Forward the stop signal to every child, then wait them out.
    for p in ${pids}; do kill -TERM "${p}" 2>/dev/null || true; done
}
trap term TERM INT

# --- Rust app -------------------------------------------------------------
# Runs from /app so its relative `ServeDir::new("static")` resolves /app/static.
cd /app
./featherreader &
fr_pid=$!
pids="${pids} ${fr_pid}"

# --- OAuth sidecar --------------------------------------------------------
# Node 24: `node:sqlite` is stable + flagless, so no --experimental-sqlite here.
node /app/oauth-sidecar/dist/server.js &
sc_pid=$!
pids="${pids} ${sc_pid}"

# --- Caddy (public edge) --------------------------------------------------
caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &
cy_pid=$!
pids="${pids} ${cy_pid}"

# Block until the FIRST child exits. `wait -n` returns that child's status.
set +e
wait -n
first_status=$?
set -e

# One child is gone => the instance is broken. Signal the survivors, drain, and
# exit non-zero so the platform recreates the machine.
term
wait 2>/dev/null || true
echo "[entrypoint] a supervised process exited (status ${first_status}); shutting down container" 1>&2
exit "${first_status}"

