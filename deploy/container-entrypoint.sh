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
#     The children run as the unprivileged `app` user (uid 10001) and each
#     open files under /data (the Rust DB, the sidecar DB + signing JWK, Caddy's
#     XDG_DATA_HOME). Without this chown they get EACCES on a virgin volume and
#     crash-loop. We do it ONCE as root, then drop privileges.
#   PHASE 2 (app via gosu): run under tini (PID1), which reaps zombies and
#     forwards SIGTERM/SIGINT to us; we fan those out to the supervised children.
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
#                                — ONLY on FEATHERREADER_REPO_BACKEND=sidecar.
#                                The rust backend runs two processes, not three.
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
# Set by the trap below, so the exit log can tell a stop WE asked for from a
# child dying on its own. Nothing else may set it.
stopping=0

term() {
    stopping=1
    # Forward the stop signal to every child, then wait them out.
    for p in ${pids}; do kill -TERM "${p}" 2>/dev/null || true; done
}
trap term TERM INT

# --- Which OAuth backend? -------------------------------------------------
# Resolved ONCE, up front, because it decides two things that must agree: which
# processes run, and how Caddy routes /oauth/*. Deciding them separately is how
# they drift.
#
# An unrecognised value is fatal, matching the Rust side: silently defaulting to
# the sidecar while the app served the rust backend would break every login, and
# the symptom would look like a PDS outage.
backend="${FEATHERREADER_REPO_BACKEND:-sidecar}"
case "${backend}" in
    sidecar) oauth_routes=/etc/caddy/caddy-oauth-sidecar.conf ;;
    rust)    oauth_routes=/etc/caddy/caddy-oauth-rust.conf ;;
    *)
        echo "[entrypoint] FEATHERREADER_REPO_BACKEND must be 'sidecar' or 'rust', got '${backend}'" 1>&2
        exit 64
        ;;
esac

# --- Rust app -------------------------------------------------------------
# Runs from /app so its relative `ServeDir::new("static")` resolves /app/static.
cd /app
./featherreader &
fr_pid=$!
pids="${pids} ${fr_pid}"

# --- OAuth sidecar (only on the sidecar backend) --------------------------
# NOT started on the rust backend. Leaving it running there would keep a second
# process alive holding its own SQLite of PDS tokens and serving its /internal
# API on loopback -- an idle store of live credentials and an attack surface, for
# a component nothing routes to. It would also make the supervisor treat that
# unused process's death as a reason to tear the container down.
#
# Node 24: `node:sqlite` is stable + flagless, so no --experimental-sqlite here.
if [ "${backend}" = "sidecar" ]; then
    node /app/oauth-sidecar/dist/server.js &
    sc_pid=$!
    pids="${pids} ${sc_pid}"
else
    echo "[entrypoint] rust OAuth backend: not starting the Node sidecar" 1>&2
fi

# --- OAuth edge routing: pick the file matching the selected backend -------
# The two backends cannot share /oauth/callback: the PDS redirects to it with
# identical `?code=&state=&iss=` in both cases, so the edge cannot tell them
# apart and one process has to own the path. The flag and the routing therefore
# have to agree, and they are made to agree HERE rather than by hand.
#
# An unrecognised value is fatal, matching the Rust side: silently defaulting to
# the sidecar routing while the app served the Rust backend would break every
# login, and the symptom would look like a PDS outage.
cp "${oauth_routes}" /etc/caddy/oauth-routes.conf
echo "[entrypoint] oauth routing: $(basename "${oauth_routes}")" 1>&2

# --- Caddy (public edge) --------------------------------------------------
# Validated before `run`: a bad adapt here would otherwise take the whole
# container down on boot with the failure buried among three children's output.
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &
cy_pid=$!
pids="${pids} ${cy_pid}"

# Block until the FIRST child exits. `wait -n` returns that child's status.
set +e
wait -n
first_status=$?
set -e

# Snapshot the flag BEFORE the fan-out below, because `term` is both the trap
# handler AND called directly on this path — so calling it first would set
# `stopping=1` unconditionally and make every exit, crash included, report itself
# as a requested stop. The branch would be dead and the log would be wrong in
# exactly the direction the previous version was.
requested_stop="${stopping}"

# One child is gone => the instance is broken. Signal the survivors, drain, and
# exit non-zero so the platform recreates the machine.
term
wait 2>/dev/null || true
# Distinguish a stop WE were asked to make from a child dying on its own. Both
# take the container down, but only one is news: a normal `fly deploy` sends
# SIGTERM, the children exit 143, and this line used to report that in the same
# words as a real failure — so anyone alerting on the string paged on every
# deploy.
#
# The test is `${stopping}`, NOT "the status looks like a signal". A shell
# reports ANY signalled child as 128 + signum, so `status > 128` also covers 137
# (SIGKILL — the OOM killer, which on a 512 MB box is a leading failure mode) and
# 139 (SIGSEGV) and 134 (abort). Calling those "normal" would hide exactly the
# crashes this line exists to surface — the inverse of the problem being fixed.
# Only the trap can attest that the stop was requested — hence the snapshot
# above, taken before this path calls `term` itself.
if [ "${requested_stop}" -eq 1 ]; then
    echo "[entrypoint] stop requested (child status ${first_status}); shutting down container normally" 1>&2
else
    if [ "${first_status}" -gt 128 ]; then
        echo "[entrypoint] a supervised process was KILLED by signal $((first_status - 128)) (status ${first_status}); shutting down container" 1>&2
    else
        echo "[entrypoint] a supervised process CRASHED (exit ${first_status}); shutting down container" 1>&2
    fi
fi
exit "${first_status}"

