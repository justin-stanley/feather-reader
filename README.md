# FeatherReader 🪶

[![CI](https://github.com/justin-stanley/feather-reader/actions/workflows/ci.yml/badge.svg)](https://github.com/justin-stanley/feather-reader/actions/workflows/ci.yml)
[![CodeQL](https://github.com/justin-stanley/feather-reader/actions/workflows/codeql.yml/badge.svg)](https://github.com/justin-stanley/feather-reader/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://github.com/justin-stanley/feather-reader/actions/workflows/scorecard.yml/badge.svg)](https://github.com/justin-stanley/feather-reader/actions/workflows/scorecard.yml)
[![crates.io](https://img.shields.io/crates/v/feather-reader.svg)](https://crates.io/crates/feather-reader)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

**A minimalist, atproto-native RSS/Atom reader — written in Rust.**

FeatherReader is a calm, typography-first feed reader for people who left
algorithmic feeds on purpose. Its defining idea: **your subscriptions, folders,
stars, and read-state live as records in your own [atproto](https://atproto.com)
PDS** — not in the app's database. You sign in with your atproto identity, and
your reading list follows you across *any* reader that speaks the same open
lexicon. You own your data; the app just holds a cache and a login session.

Hosted at **[feather-reader.com](https://feather-reader.com)**, and
trivial to self-host.

> **Status: experimental / pre-1.0.** The core is built and usable, but the
> project is early, the on-disk formats and the lexicon may still change, and a
> closed invite-beta is planned before any wider launch. Treat it as something to
> try, not something to depend on.

---

## Why FeatherReader

- **Own your data — as an open standard.** Subscriptions, folders, saved items,
  and read-state are written as `community.lexicon.rss.*` records in *your* PDS.
  There's no signup and no password database: your atproto handle **is** your
  account. Because the records use a shared, vendor-neutral schema, your feed
  list is portable across *readers*, not just across FeatherReader instances.
- **Minimalist by design.** A single sorted list, a distraction-free reading
  view, keyboard flow, dark mode. No ads, no tracking, no telemetry, no
  algorithm, no "discover" tab. Every feature has to earn its place against
  "does this make the calm reading experience better, or just bigger?"
- **Single binary, self-hostable.** Rust + an embedded SQLite cache (no Postgres
  to run). Since 0.3.0 the atproto OAuth client is built in, so a self-host can
  be **one process** — or keep the Node sidecar if you prefer. Easy to run
  yourself either way.

## The `community.lexicon.rss.*` standard

Most readers own your account and your export format. FeatherReader holds
neither. Your data is stored under a **neutral, community-owned lexicon** that any
atproto RSS reader can adopt — the same way `community.lexicon.calendar.event`
lets any atproto calendar app read the same events. Log in anywhere with your
handle and your feeds are already there. If you switch readers, there's nothing
to export: the records are a shared standard.

The record types:

- `community.lexicon.rss.subscription` — a subscribed feed
- `community.lexicon.rss.folder` — a lightweight grouping
- `community.lexicon.rss.saved` — a starred / saved item
- `community.lexicon.rss.readState` — a compact per-feed read cursor

## Architecture

Two views — **where your data lives** and **how the running system is wired**.
Both diagrams adapt to your light/dark theme.

**Data ownership — your PDS is the source of truth**

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="design/architecture/ownership-dark.png">
    <img alt="You read through FeatherReader, which fetches your feeds into a disposable local SQLite cache, while your subscriptions, folders, stars, and read-state live as community.lexicon.rss.* records in your own atproto PDS — portable to any other atproto reader." src="design/architecture/ownership-light.png" width="820">
  </picture>
</p>

Your subscriptions and read-state are records in **your** PDS, so the local cache
is throwaway and your reading list follows you to any reader that speaks the same
lexicon.

**Runtime — one container, two or three processes**

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="design/architecture/runtime-dark.png">
    <img alt="Runtime: the browser reaches Cloudflare (proxy, cache, origin lock), which forwards to a single Fly.io container running Caddy on :8080 as the edge. Caddy sends everything to the Rust axum app on :8082, which holds a disposable SQLite cache on /data, makes SSRF-guarded conditional-GET fetches to feed origins, and makes com.atproto.repo.* calls to your atproto PDS. The OAuth handshake is handled either by the app itself (FEATHERREADER_REPO_BACKEND=rust, one process) or by a Node OAuth sidecar on :8081 that Caddy routes /oauth/* to (the sidecar backend, the default, two processes); exactly one of the two is live." src="design/architecture/runtime-light.png" width="620">
  </picture>
</p>

Caddy fronts everything on a single port — routing `/oauth/*` to whichever
process owns the OAuth flow and the rest to the Rust server. The SQLite cache on
the mounted volume is disposable; all durable state lives in your PDS. An
[optional follow→invite bot](#invite-bot-optional) runs *outside* this container
and reaches the app over `POST /bot/claims`; it isn't part of the core app.

The dashed links are the Node sidecar, used only on the default `sidecar`
backend. On `FEATHERREADER_REPO_BACKEND=rust` the app owns the OAuth flow itself,
those links do not exist, and the `:8081` process is not started — see
[Choosing an OAuth backend](#choosing-an-oauth-backend).

So the container runs **three** processes on the `sidecar` backend and **two** on
`rust`. That count includes Caddy, which runs either way; [Build &
run](#build--run) counts only the application processes behind it, and so says
one or two for the same two topologies.

<sub>Diagram sources + rendered images live in [`design/architecture/`](design/architecture).</sub>

## Features

- **A clean list + a distraction-free reader view** — the headline feature.
- **Star / save-for-later** and **folders** for lightweight organisation.
- **OPML import / export** — the migration on-ramp and off-ramp. Import creates a
  subscription record per feed in your PDS; export reads them back out.
- **Subscribe by URL** — paste a feed URL *or a site URL* and autodiscovery finds
  the feed.
- **Keyboard navigation** — `j`/`k` move, `o`/Enter open, `m` toggle read,
  `s` star, `A` mark-all-read, `?` for the shortcuts overlay, `Esc` to close.
- **Dark mode** — system-preference-aware, with a manual toggle.
- **No-JS friendly** — server-rendered HTML with a dash of htmx; every action also
  works as a plain form POST.
- **Polite fetching** — conditional GET (ETag / Last-Modified), backoff, and an
  SSRF guard on every feed and identity fetch.

## Known limitation: private / paid feeds

FeatherReader stores your subscriptions in your **public** PDS. Because those
records are public, a secret-bearing feed URL (private Substack, Patreon, private
podcast feeds, etc.) would leak its secret if written there. So for now
FeatherReader **supports public feeds only** — a private/paid feed's URL is never
saved, fetched, or sent anywhere; it is refused at submission with a clear
message. Private-feed support is deliberately deferred until atproto's
permissioned ("private") records ship.

## Build & run

FeatherReader runs as **one or two processes**, depending on which OAuth backend
you choose (see [Choosing an OAuth backend](#choosing-an-oauth-backend)):

- **`sidecar`** (the default) — the Rust server plus a small **Node OAuth
  sidecar** that owns the atproto OAuth flow, so the Rust side never holds PDS
  tokens.
- **`rust`** — the Rust server alone, using its own built-in atproto OAuth
  client. No Node.

**Prerequisites:** a recent stable Rust toolchain (see `rust-version` in
`Cargo.toml`), plus Node.js **24 or newer only if** you run the sidecar backend
(it uses the built-in `node:sqlite`, which is stable and flagless from 24).

```sh
# 1. Build the server (always)
cargo build --release          # -> target/release/featherreader

# 2. Build the OAuth sidecar (only for FEATHERREADER_REPO_BACKEND=sidecar)
cd oauth-sidecar
npm ci
npm run build
```

Both processes are configured entirely through environment variables — there is
no config file. Every knob has a sensible default, so a bare run boots and works.

- The **server** reads `FEATHERREADER_*` variables (bind address, database path,
  poll interval, …), plus the `SIDECAR_*` URL and shared-secret pair it needs to
  reach the sidecar. See the table at the top of
  [`src/config.rs`](src/config.rs).
- The **sidecar** reads `SIDECAR_*` variables (its public URL, storage path, the
  at-rest token-encryption key, the shared internal secret, …). See
  [`oauth-sidecar/.env.example`](oauth-sidecar/.env.example). Not used on the
  `rust` backend.

In production the sidecar requires a real at-rest encryption key and a strong
shared internal secret, and refuses to boot without them. **Never commit secret
values** — the example files ship placeholders only.

## Choosing an OAuth backend

`FEATHERREADER_REPO_BACKEND` selects which implementation performs the atproto
OAuth handshake and every `com.atproto.repo.*` call:

| | `sidecar` (default) | `rust` |
|---|---|---|
| Processes | Rust server + Node sidecar | Rust server only |
| OAuth client | `@atproto/oauth-client-node` | built in |
| Runtime deps | Node.js | none |
| Needs | `SIDECAR_*` | `FEATHERREADER_OAUTH_ENCRYPTION_KEY` |

**Upgrading to 0.3.0 changes nothing.** The default is `sidecar`, so an existing
deployment keeps the topology it already has until you choose otherwise.

### Measured in production

One deployment — a single 512 MB `shared-cpu-1x` machine in Fly's `ord`, talking
to one PDS. Latencies are milliseconds from `/admin/metrics`; `n` is the number
of successful calls each percentile is drawn from.

| operation | `rust` p50 / p95 | n | `sidecar` p50 / p95 | n |
|---|---|---|---|---|
| `list_folders_sorted` | **61.3** / **78.0** | 48 | 253.3 / 274.3 | 6 |
| `list_subscriptions_sorted` | **125.5** / **299.3** | 76 | 259.9 / 537.2 | 9 |
| `flush_read_states` | 968.7 / **1569.3** | 15 | **849.1** / 3267.3 | 12 |

**Read these as indicative, not as a benchmark.** The two backends were not
measured concurrently: the `sidecar` figures accumulated before the 2026-09-13
cutover and the `rust` ones after it, so they cover different weeks, a different
cache size, and whatever the network was doing at the time. The samples are small
and unequal, and a p50 over six calls is barely a median.

What they are good for is ruling out the thing worth ruling out — the Rust client
is not slower in a way that would argue against it. On the read paths it is
comfortably faster; on `flush_read_states` it trades a slightly worse median for
less than half the tail latency.

The comparison is trustworthy in one narrow respect that is easy to lose:
`FEATHERREADER_REPO_BACKEND` fails startup on an unrecognised value rather than
falling back, so a row labelled `sidecar` was always really the sidecar, and the
two columns are never the same implementation measured twice.

`flush_read_states` on `rust` also carries 100 errors against those 15 successes.
Nearly all are one signed-out account's read-state being retried every 60 s until
#117 added parking in 0.3.4 — a scheduler bug, on shared code that runs
identically under either backend, not a difference between them. Every other
operation in the table has recorded zero errors on both.

### Switching

```sh
FEATHERREADER_REPO_BACKEND=rust
FEATHERREADER_OAUTH_ENCRYPTION_KEY=<random, >=32 bytes>   # required in production
```

The server **refuses to start** if you select `rust` on a production-like
instance without an encryption key. That table holds every user's access token,
refresh token and DPoP private key; without a key they would sit in plaintext in
SQLite, on the same volume as the feed cache and in every backup of it. An
unrecognised backend name is also a startup failure rather than a silent
fallback.

**Put the signing key somewhere persistent.** `FEATHERREADER_OAUTH_KEY_PATH`
defaults to the *relative* `oauth-signing-key.json`, which is fine for a local
run and a trap in a container: the key lands in the working directory, is lost on
every redeploy, and a new one is generated in its place. Your published JWKS then
changes on each deploy, which breaks `private_key_jwt` against any authorization
server still holding the old one. The supplied image already points it at the
persistent volume; a custom image or bare-binary deployment must do the same:

```sh
FEATHERREADER_OAUTH_KEY_PATH=/data/oauth-signing-key.json
```

### What switching costs

- **Everyone signs in again — in both directions.** The two backends keep
  separate session stores, and separate is literal: nothing under `src/` reads
  `SIDECAR_DB`, because the Rust backend keeps its own `oauth_session` table
  inside `FEATHERREADER_DB`, apart from the sidecar's own database. No access
  token, refresh token or DPoP key crosses the flip, so every signed-in reader is
  logged out by it — and **rolling back logs them out a second time**, off a
  sidecar store that has gone stale in the meantime. Browser sessions are
  in-memory and already end on restart, so nothing is lost; it is one login per
  flip, which is worth timing for low traffic and telling people about.
- **Unverified, but worth knowing:** the two backends publish JWKS from different
  signing keys, so if a PDS caches our JWKS across the flip, the first login
  after it may fail for that reason rather than because of a bug in the new path.
  This has not been observed or reproduced — it is a thing to rule out before
  concluding the backend is broken.
- **`/oauth/*` routing must match the backend.** The two cannot share
  `/oauth/callback`: your PDS redirects there with identical
  `?code=&state=&iss=` in both cases, so nothing in the request distinguishes
  them and one process has to own the path. The supplied container handles this
  — the entrypoint installs the matching Caddy routing from the same environment
  variable. **A bare-binary deployment must route `/oauth/*` itself:** to the app
  on `rust`, to the sidecar on `sidecar`.
- **Rolling back is unsetting the variable and restarting.** Nothing is migrated
  or destroyed by the switch, and both Caddy routings ship in every image, so a
  rollback needs no rebuild. Cheap operationally — but not free for your readers,
  who log in again (see above).

### Which should you run?

`sidecar` is the default and the option with production time behind it — it is
what the hosted instance runs today. `rust` shipped in 0.3.0, but it has **no
production time at all** yet: its login path is now covered by tests (the code
exchange itself, and each of the security guards around it, are pinned by them),
and that is a different claim from having been exercised against real PDSes under
real traffic. `private_key_jwt` client authentication and RFC 7009 revocation in
particular are implemented and unit-tested on the Rust path but have not run
against a production PDS.

So: if you want the smaller deployment — one process, no Node — and are content
to be early, start fresh on `rust` and watch your logs through the first logins.
Otherwise run the default. If you already have a working `sidecar` deployment,
there is no urgency to move.

The choice is **transitional**. Maintaining two implementations of the same
surface has a real cost, and the intent is to remove the sidecar in a later
release once the Rust path has enough production time. `sidecar` will be
announced as deprecated before it is removed.

## Self-hosting

FeatherReader is designed to be run by anyone: a single static Rust binary
(optionally plus the Node sidecar), an embedded SQLite cache, and no external
database. Front it with your own reverse proxy / TLS. Teardown and
data-ownership notes live in [`deploy/`](deploy/).

`GET /health` is the unauthenticated liveness endpoint, and it reports machine
facts only — no user counts, no DIDs, no feed URLs. The first token of the body
is the state: `ok`, `unknown` or `FAIL`. Only a *measured* database failure is a
failure (`FAIL`, HTTP 503); `unknown` means no probe has completed yet, which
happens briefly at boot and is not an outage — so match the state token, not just
the status code. The remaining lines (`db:`, `uptime:`, `poller:`,
`polling-paused:`, `backend:`, `oauth-runtime:`) never change the status code, on
the grounds that a stale poller can still serve pages while an unreadable
database cannot. Alert on the body if you want to hear about those.

## Invite bot (optional)

The repo also ships a small, **optional** follow→invite bot in [`bot/`](bot/) — a
tool for running a closed invite-beta, **not** needed to self-host the reader. It's
a standalone Rust crate (its own workspace, deliberately **not** built by the app's
`cargo build`) that watches an atproto account's followers and, for each new one,
calls the app's `POST /bot/claims` to mint a single-use invite, then posts a public
claim link. That endpoint stays disabled unless `FEATHERREADER_BOT_SECRET` is set,
so the core app runs fine without the bot. Details + configuration in
[`bot/README.md`](bot/README.md).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for how
to build, run the checks (`./scripts/ci.sh`), and open a pull request. Bug reports
and design discussion via issues are equally welcome.

## License

[AGPL-3.0-only](./LICENSE). The AGPL is deliberate: it keeps hosted forks open, so
improvements to a network-served reader flow back to everyone.
