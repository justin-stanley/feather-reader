# syntax=docker/dockerfile:1.7
#
# FeatherReader — single-container image: Caddy (public edge) + the Rust
# `featherreader` app, under tini as PID1. (The Node atproto OAuth sidecar was
# removed in 0.5.0, #311; Rust is the only OAuth client.)
#
# Grounded in the source tree (read, not guessed):
#   * Rust bin is `featherreader` (Cargo.toml [[bin]]), edition 2021. MSRV is
#     1.94 (Cargo.toml `rust-version`: sqlx 0.9 requires rustc 1.94 and askama
#     0.16 requires 1.88 — a 1.82 builder can't even parse askama's
#     `edition2024` manifest). The builder below is current stable instead
#     (1.99), matching ci.yml's `@stable`, so the shipped binary is built by the
#     compiler CI tests with. Dependabot's docker ecosystem keeps it moving.
#     sqlx `sqlite-bundled` + `tls-rustls-ring` and reqwest `rustls` mean NO
#     system libsqlite3 / OpenSSL are needed at runtime.
#   * The DB schema is EMBEDDED in the binary (src/store.rs) — there is no
#     migrations/ directory to ship.
#   * askama templates are compiled into the binary, BUT `static/` is served at
#     RUNTIME via `ServeDir::new("static")` — a RELATIVE path (src/web.rs). So the
#     runtime WORKDIR MUST contain `static/`. (Miss this and every /static/* 404s.)
#
# Runtime base is `debian:bookworm-slim` (glibc): the same Debian release as the
# rust:1.99-bookworm builder, so the Rust binary + the (static) Caddy binary run
# on it unchanged. It was `node:24-bookworm-slim` — itself Debian bookworm —
# until 0.5.0 removed the Node sidecar; nothing else in the image needs Node.
#
# Base images are pinned by @sha256. Digests are the multi-arch INDEX digests and
# drift as upstream republishes tags; re-resolve with e.g.
# `docker buildx imagetools inspect debian:bookworm-slim` if a pull ever fails
# the digest check.

# ---------------------------------------------------------------------------
# Stage 1 — Rust builder: compile the `featherreader` binary.
# ---------------------------------------------------------------------------
FROM rust:1.99-bookworm@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS rust-build

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
# Stage 2 — Caddy binary source (static CGO_ENABLED=0 Go binary; libc-agnostic).
# ---------------------------------------------------------------------------
FROM caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f AS caddy-src

# ---------------------------------------------------------------------------
# Stage 3 — Runtime: debian:bookworm-slim (glibc, matching the builder).
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime

# tini for correct PID1 semantics (zombie reaping + signal forwarding);
# ca-certificates for outbound HTTPS (feed fetch + atproto — rustls ships its own
# TLS stack but still needs the system trust roots to validate feed hosts);
# gosu to drop from root to `app` AFTER the entrypoint fixes the mounted-volume
# ownership (see below); bash because the entrypoint supervisor uses `wait -n`
# (first-child-exit), which the Debian default /bin/sh (dash) does not support.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends tini ca-certificates gosu bash; \
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

# Caddy config + the multi-process supervisor.
COPY --chown=app:app deploy/Caddyfile /etc/caddy/Caddyfile
COPY --chown=app:app deploy/container-entrypoint.sh /usr/local/bin/container-entrypoint.sh
RUN chmod 0755 /usr/local/bin/container-entrypoint.sh

# --- Runtime env (NON-secret defaults only; secrets come from `fly secrets`) --
# In-container wiring: Caddy owns the single public port 8080; the Rust app
# binds loopback-only.
#
# No SIDECAR_* is baked: the app does not read them since 0.5.0 removed the
# sidecar (#311), and warns at boot when one is set.
#
# FEATHERREADER_OAUTH_KEY_PATH MUST be on the volume. Its default is the
# RELATIVE path `oauth-signing-key.json`, and the entrypoint runs the app from
# /app — the image's ephemeral layer. Unset, the client's ES256 key is therefore
# destroyed by every redeploy, and the app would mint a FRESH client key on
# each one: the published JWKS changes, and every grant a PDS holds against the
# old key stops verifying.
ENV FEATHERREADER_BIND=127.0.0.1:8082 \
    FEATHERREADER_DB=/data/featherreader.db \
    FEATHERREADER_OAUTH_KEY_PATH=/data/oauth-signing-key.json \
    FEATHERREADER_ENV=prod \
    FEATHERREADER_TRUSTED_IP_HEADER=cf-connecting-ip \
    RUST_LOG=info \
    XDG_DATA_HOME=/data/caddy \
    XDG_CONFIG_HOME=/data/caddy
#
# NOT set here (delivered at runtime via `fly secrets set`, never baked):
#   FEATHERREADER_COOKIE_SECRET,
#   FEATHERREADER_OAUTH_ENCRYPTION_KEY (without it the stored access tokens,
#     refresh tokens and DPoP keys are plaintext, and validate_secrets() refuses
#     to boot),
#   FEATHERREADER_PUBLIC_URL, FEATHERREADER_ALLOWED_DIDS, etc.
# config.rs::validate_secrets() FAILS LOUD at boot if the required secrets are
# missing/weak on a non-loopback (prod) instance.

# Caddy is the only listener bound off-loopback; it is the Fly internal_port.
EXPOSE 8080

# tini as PID1 -> the supervisor. The entrypoint starts as ROOT (to chown the
# Fly volume that overlays /data at runtime) and then drops to `app` via gosu
# before launching the two children (see deploy/container-entrypoint.sh).
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/container-entrypoint.sh"]

