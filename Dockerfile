# syntax=docker/dockerfile:1.7
#
# FeatherReader — single-container image: Caddy (public edge) + the Rust
# `featherreader` app + the Node atproto OAuth sidecar, under tini as PID1.
#
# Grounded in the source tree (read, not guessed):
#   * Rust bin is `featherreader` (Cargo.toml [[bin]]), edition 2021 / rust 1.82.
#     sqlx `sqlite-bundled` + `tls-rustls-ring` and reqwest `rustls` mean NO
#     system libsqlite3 / OpenSSL are needed at runtime.
#   * The DB schema is EMBEDDED in the binary (src/store.rs) — there is no
#     migrations/ directory to ship.
#   * askama templates are compiled into the binary, BUT `static/` is served at
#     RUNTIME via `ServeDir::new("static")` — a RELATIVE path (src/web.rs). So the
#     runtime WORKDIR MUST contain `static/`. (Miss this and every /static/* 404s.)
#   * The sidecar imports Node's built-in `node:sqlite` (oauth-sidecar/src/
#     stores.ts `import { DatabaseSync } from 'node:sqlite'`). That module is
#     STABLE + FLAGLESS from Node 24 (on Node 22 it needs --experimental-sqlite
#     and throws ERR_UNKNOWN_BUILTIN_MODULE without it). => the runtime base is
#     Node 24, and package.json engines is >=24. CI runs `npm test` on Node 24 so
#     a node:sqlite load failure is caught before release.
#   * The sidecar is run as `node dist/server.js` (built to dist/).
#
# Runtime base is `node:24-bookworm-slim` (glibc), NOT bare debian-slim: it gives
# a supported, correctly-linked `node` (no fragile hand-copy of the node binary
# or its libstdc++6/libgcc-s1 deps into a bare base), and its glibc ABI matches
# the rust:1.82-bookworm builder so the Rust binary + the (static) Caddy binary
# both run on it unchanged.
#
# Base images are pinned by @sha256. Digests are the multi-arch INDEX digests and
# drift as upstream republishes tags; re-resolve with e.g.
# `docker buildx imagetools inspect node:24-bookworm-slim` if a pull ever fails
# the digest check.

# ---------------------------------------------------------------------------
# Stage 1 — Rust builder: compile the `featherreader` binary.
# ---------------------------------------------------------------------------
FROM rust:1.82-bookworm@sha256:d9c3c6f1264a547d84560e06ffd79ed7a799ce0bff0980b26cf10d29af888377 AS rust-build

# PART C toggle: when ENABLE_SBOM=1 the binary is built with `cargo auditable`,
# which embeds the exact dependency graph into the ELF so `cargo audit bin` (and
# the release workflow's SBOM/attestation) can read it back from the shipped
# binary. Default (0) is a plain `cargo build` — no extra tooling in the image.
ARG ENABLE_SBOM=0

WORKDIR /build

# Cache deps: copy manifests first so the registry-fetch layer caches independent
# of source edits, and so `--locked` has the lockfile it must not touch.
COPY Cargo.toml Cargo.lock ./

# Full source (respect .dockerignore — target/, node_modules/, .git/ excluded).
COPY src ./src
COPY templates ./templates
COPY static ./static

# Build. `--locked` refuses to touch Cargo.lock (reproducible, audited deps).
# cargo-auditable is installed ONLY on the ENABLE_SBOM path.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    set -eux; \
    if [ "$ENABLE_SBOM" = "1" ]; then \
        cargo install cargo-auditable --locked --version ^0.6; \
        cargo auditable build --release --locked --bin featherreader; \
    else \
        cargo build --release --locked --bin featherreader; \
    fi; \
    # Copy the artifact out of the cache mount so it survives into the next layer.
    cp target/release/featherreader /build/featherreader; \
    strip /build/featherreader

# ---------------------------------------------------------------------------
# Stage 2 — Node builder: compile the TypeScript OAuth sidecar to dist/.
# ---------------------------------------------------------------------------
FROM node:24-bookworm-slim@sha256:cb4e8f7c443347358b7875e717c29e27bf9befc8f5a26cf18af3c3dec80e58c5 AS node-build

WORKDIR /sidecar

# `npm ci` needs the lockfile + manifest; copy them first for layer caching.
COPY oauth-sidecar/package.json oauth-sidecar/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci

# Build TS -> dist/ (tsconfig outDir=dist). Then prune to production deps so
# only what `node dist/server.js` needs is carried into the runtime.
COPY oauth-sidecar/tsconfig.json ./
COPY oauth-sidecar/src ./src
RUN set -eux; \
    npm run build; \
    npm prune --omit=dev

# ---------------------------------------------------------------------------
# Stage 3 — Caddy binary source (static CGO_ENABLED=0 Go binary; libc-agnostic).
# ---------------------------------------------------------------------------
FROM caddy:2-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648 AS caddy-src

# ---------------------------------------------------------------------------
# Stage 4 — Runtime: node:24-bookworm-slim (glibc; supported node interpreter).
# ---------------------------------------------------------------------------
FROM node:24-bookworm-slim@sha256:cb4e8f7c443347358b7875e717c29e27bf9befc8f5a26cf18af3c3dec80e58c5 AS runtime

# tini for correct PID1 semantics (zombie reaping + signal forwarding);
# ca-certificates for outbound HTTPS (feed fetch + atproto — rustls ships its own
# TLS stack but still needs the system trust roots to validate feed hosts);
# gosu to drop from root to `app` AFTER the entrypoint fixes the mounted-volume
# ownership (see below).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends tini ca-certificates gosu; \
    rm -rf /var/lib/apt/lists/*

# Caddy (single static binary). Smoke-test it at build time so a future non-static
# / CGO Caddy variant fails HERE (build) rather than at container boot.
COPY --from=caddy-src /usr/bin/caddy /usr/local/bin/caddy
RUN /usr/local/bin/caddy version

# Non-root runtime identity. Fixed high uid/gid so the entrypoint can chown the
# mounted /data volume to it deterministically on first boot.
RUN set -eux; \
    groupadd --gid 10001 app; \
    useradd --uid 10001 --gid 10001 --home-dir /app --shell /usr/sbin/nologin app; \
    mkdir -p /app /data; \
    chown -R app:app /app /data

WORKDIR /app

# --- App payload ----------------------------------------------------------
# The Rust binary + its RUNTIME assets. `static/` MUST sit in the WORKDIR the
# binary runs from (ServeDir::new("static") is relative). templates/ is compiled
# into the binary and is NOT needed at runtime — deliberately not copied.
COPY --from=rust-build --chown=app:app /build/featherreader /app/featherreader
COPY --chown=app:app static /app/static

# The sidecar: dist/ + its pruned production node_modules + manifest.
COPY --from=node-build --chown=app:app /sidecar/dist /app/oauth-sidecar/dist
COPY --from=node-build --chown=app:app /sidecar/node_modules /app/oauth-sidecar/node_modules
COPY --from=node-build --chown=app:app /sidecar/package.json /app/oauth-sidecar/package.json

# Caddy config + the multi-process supervisor.
COPY --chown=app:app deploy/Caddyfile /etc/caddy/Caddyfile
COPY --chown=app:app deploy/container-entrypoint.sh /usr/local/bin/container-entrypoint.sh
RUN chmod 0755 /usr/local/bin/container-entrypoint.sh

# --- Runtime env (NON-secret defaults only; secrets come from `fly secrets`) --
# In-container wiring: Caddy owns the single public port 8080; the Rust app and
# the sidecar bind loopback-only, so /internal/* is physically unreachable from
# outside the container even before Caddy's routing rules.
#
# SIDECAR_INTERNAL_URL is the loopback base the Rust app uses for /internal/*
# (session/revoke/repo). It is DISTINCT from SIDECAR_PUBLIC_URL, which in prod is
# the edge value (https://feather-reader.com/oauth) delivered via
# `fly secrets` and used only for the browser /login + OAuth client_id/redirect_uri.
# Baking the loopback INTERNAL url here keeps server-to-server calls off the edge.
ENV FEATHERREADER_BIND=127.0.0.1:8082 \
    FEATHERREADER_DB=/data/featherreader.db \
    FEATHERREADER_ENV=prod \
    FEATHERREADER_TRUSTED_IP_HEADER=cf-connecting-ip \
    SIDECAR_HOST=127.0.0.1 \
    SIDECAR_PORT=8081 \
    SIDECAR_INTERNAL_URL=http://127.0.0.1:8081 \
    SIDECAR_DB=/data/oauth-sidecar.db \
    RUST_LOG=info \
    XDG_DATA_HOME=/data/caddy \
    XDG_CONFIG_HOME=/data/caddy
#
# NOT set here (delivered at runtime via `fly secrets set`, never baked):
#   FEATHERREADER_COOKIE_SECRET, SIDECAR_INTERNAL_SECRET, SIDECAR_ENC_KEY,
#   FEATHERREADER_PUBLIC_URL, SIDECAR_PUBLIC_URL (prod .../oauth — browser-facing),
#   SIDECAR_APP_CALLBACK_URL, FEATHERREADER_ALLOWED_DIDS, etc.
# config.rs::validate_secrets() and the sidecar's config.ts FAIL LOUD at boot if
# the required secrets are missing/weak on a non-loopback (prod) instance.
#
# NOTE: SIDECAR_PUBLIC_URL is deliberately NOT baked. The sidecar auto-infers its
# `dev` client shape from a localhost PUBLIC_URL; baking a loopback default here
# would mask the missing-prod-config error instead of failing it loudly.

# Caddy is the only listener bound off-loopback; it is the Fly internal_port.
EXPOSE 8080

# tini as PID1 -> the supervisor. The entrypoint starts as ROOT (to chown the
# Fly volume that overlays /data at runtime) and then drops to `app` via gosu
# before launching the three children (see deploy/container-entrypoint.sh).
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/container-entrypoint.sh"]

