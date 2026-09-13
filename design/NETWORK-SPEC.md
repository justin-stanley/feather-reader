# FeatherReader — Network Spec

> **the network is public; the reader is quiet.** This document is the design
> authority for everything FeatherReader does that reads the *rest of the atproto
> network* rather than one user's own PDS: the adoption metric, the portability
> test, the `community.lexicon.rss.subscription` projection, and the social-join
> capability we are **not** building yet.
>
> Companion to [`DESIGN.md`](./DESIGN.md) (the UI design authority) and to the
> architecture diagrams in [`architecture/`](./architecture/). Where the two
> disagree about a *surface*, `DESIGN.md` wins.

**Status:** proposed. Nothing in this document is implemented as of `v0.2.7`.

---

## 1. Motivation

FeatherReader's defining claim is on the tin of every page:

> Your subscriptions, folders, stars, and read-state are written as open-standard
> `community.lexicon.rss.*` records in **your own PDS** — not on this server.
> — [`templates/privacy.html`](../templates/privacy.html)

That claim is currently **asserted, not demonstrated**. The code that makes it
true is real — [`src/lexicon.rs`](../src/lexicon.rs) defines the records,
[`SidecarClient::add_subscription`](../src/atproto.rs) writes them, and
[`resolve_subscriptions`](../src/web.rs) treats the PDS as the source of truth on
every request with the local cache as a fail-closed fallback — but nothing in the
repo ever *reads a subscription record it did not write*. There is no test that
proves a second implementation could pick these records up, and no number
anywhere that says how many accounts on the network hold them.

Meanwhile atproto ships four free, no-signup services FeatherReader has never
touched:

| Service | Endpoint | What it gives us |
|---|---|---|
| **Relay** | `wss://bsky.network` → `relay1.us-{west,east}.bsky.network` | `com.atproto.sync.listReposByCollection` — *who on the network holds a collection* |
| **Jetstream** | `wss://jetstream.us-east.bsky.network/subscribe` | a JSON firehose filterable by `wantedCollections` / `wantedDids` |
| **AppView** | `public.api.bsky.app` | the Bluesky social graph (`app.bsky.graph.*`) |
| **SDKs** | — | not used; see §9.1 |

There is **no streaming or websocket client anywhere in the tree** today — no
`tungstenite`, no `jetstream`, no `subscribeRepos` in `src/`, `bot/src/`,
`oauth-sidecar/src/`, or either `Cargo.toml`. Every network call FeatherReader
makes is a request/response HTTP GET or POST.

This spec proposes three capabilities, in priority order, and resolves them
against the product's hard constraints (§2).

### 1.1 The uncomfortable number

A live, unauthenticated probe of
`com.atproto.sync.listReposByCollection?collection=community.lexicon.rss.subscription`
on `relay1.us-west.bsky.network` returns **exactly one repo network-wide**:
`did:plc:ohutz6x5acjmpuulp3x7wxxc` — the author's own account. For comparison,
`community.lexicon.calendar.event` returns 20+ (page limit).

So the portability claim is **architecturally true and empirically untested**.
That asymmetry is the single strongest argument for Capability 1 and the single
strongest argument for *deferring* Capabilities 2 and 3: a discovery projection
over one repo is a mirror, and a social join over one repo is a mirror with a
frame around it.

---

## 2. Hard constraints (the tests every proposal below must pass)

These are quoted from `README.md` and `templates/privacy.html`, which are the
public promises, not aspirations:

1. **"No ads, no tracking, no telemetry, no algorithm, no 'discover' tab. Every
   feature has to earn its place against *does this make the calm reading
   experience better, or just bigger?*"** (`README.md`)
2. **"There are no analytics, no advertising networks, no third-party trackers,
   and no telemetry."** (`privacy.html`)
3. **"Single binary, self-hostable. Rust + an embedded SQLite cache (no Postgres
   to run), plus a small Node OAuth sidecar."** (`README.md`)
4. **"No-JS friendly — server-rendered HTML with a dash of htmx; every action
   also works as a plain form POST."** (`README.md`)
5. **Public feeds only.** A secret-bearing feed URL is refused at the add
   boundary by [`feed::classify_feed_privacy`](../src/feed.rs), *and*
   re-validated on every redirect hop inside
   [`net::guarded_get`](../src/net.rs), because "atproto PDS records are
   **public**" ([`lexicon.rs`](../src/lexicon.rs) type docs).
6. **A 1 GB Fly volume and a 512 MB VM.** `fly.toml` sets
   `FEATHERREADER_DB_SIZE_WATERMARK_BYTES = "805306368"` (**768 MiB**, against
   the 1 GB volume) and `[[vm]] memory = "512mb"`. Above the watermark the
   poller stops fetching new content — see `poll_due_once` in
   [`src/scheduler.rs`](../src/scheduler.rs) and `check_watermark_vs_disk` in
   [`src/main.rs`](../src/main.rs). Both numbers bind everything in §5.
7. **The self-hoster must never be forced to run any of this.**

Constraint 1 is not decoration. It is the reason §7 recommends cutting one of
the three capabilities outright.

### 2.1 Two operational constraints the implementation must not break

- **`/health` is load-bearing twice over.** It is the **only** path exempted
  from the Caddy origin-lock so Fly's internal probe can reach it
  ([`deploy/Caddyfile`](../deploy/Caddyfile)), and `fly.toml` health-checks it
  every 15 s with a 3 s timeout, so a slow `/health` flaps the machine.
  **No capability in this spec may add a field to, reformat, or slow down
  `/health`.** Network state gets its own surface (§4.4).

  *Superseded in part (T3.1).* This bullet described `/health` as returning the
  literal string `ok featherreader/{VERSION}`, and that is no longer true: it now
  probes the database and reports the poll heartbeat, the fetch-pause state and
  the live OAuth backend. The change was made against this constraint knowingly,
  because the constraint's own premise had been overtaken — a probe that touched
  no database, no pool and no scheduler state, while being the *only* automated
  signal in `fly.toml`, proved the HTTP listener was up and nothing else.

  The parts of the constraint that were actually load-bearing are unchanged and
  now enforced deliberately: the probe reads one real page (a bare `SELECT 1`
  emits no `OpenRead` and so cannot detect a broken database), under a 2 s timeout
  that fires inside Fly's 3 s; and **only** a measured database failure can change
  the status code.

  *Second correction, from research rather than reading.* The original reasoning
  here was "Fly restarts on a failed check, and restarting fixes neither". That is
  **false**: Fly's docs state three times that a failing service check does not
  restart or stop a Machine — the proxy simply stops routing to it, and
  re-registers automatically once the check passes. The restart-on-check
  capability existed on Apps V1 (`restart_limit`) and has no successor on
  Machines. The conclusion survives on a better premise: with ONE Machine a 503 is
  not a failover but a total outage for the duration, and it additionally fails a
  `fly deploy` with no auto-rollback. So the status code answers "can this process
  serve a useful request at all", not "would a restart help".

  The rule this bullet was written to protect still stands for capabilities in
  this spec: **network state does not belong in `/health`** (§4.4). And the
  origin-lock exemption bounds the body to machine facts of the class `/stats`
  already publishes.

  *Correction to a premise this spec was drafted against:* there is **no
  automated `/health`-equals-version gate and no auto-rollback** in the repo.
  `grep -rni rollback` matches exactly one line, `src/store.rs:984
  tx.rollback().await.ok();` — a SQL transaction. What the release train
  actually enforces is **deploy-by-digest with a fail-closed attestation
  check**: `release-image.yml` prints, and the (unversioned, not-in-repo) deploy
  runbook runs, `gh attestation verify oci://…@<digest>` followed by
  `fly deploy -i …@<digest>`. The version check is a human reading `/health`
  after the deploy. See §10.1.
- **The in-container supervisor kills the container when any child exits.**
  [`deploy/container-entrypoint.sh`](../deploy/container-entrypoint.sh) runs
  `wait -n` over `featherreader`, the Node sidecar, and Caddy, and on the first
  child exit tears the whole container down so Fly recreates the machine. That
  design is correct for three processes that are each individually load-bearing.
  It is **actively hostile to a fourth process whose upstream is a websocket
  that disconnects routinely.** This single fact decides §6.

---

## 3. Locked decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Capability 1 (adoption metric + portability test) ships first, and ships **on by default**. | One unauthenticated GET per day. Holds no personal data. Turns the headline claim into a passing test. |
| D2 | Capability 2 (Jetstream projection) ships **compiled behind a cargo feature and disabled by default**. | Constraint 7. A self-hoster's `cargo build` must not pull a websocket stack or silently make them an aggregator. |
| D3 | Capability 3 (social join against `app.bsky.graph.follow`) is **not built**. | §7. It is a recommendation engine, it needs a data flow the privacy page forbids, and with N=1 it has nothing to say. |
| D4 | The Jetstream consumer runs as a **`tokio` task inside the existing Rust process**, registered in `scheduler::spawn` — not a fourth supervised process, not a separate crate. | §2.1 (the `wait -n` supervisor) and §6. |
| D5 | **Nothing derived from the network is a source of truth.** Every network table is a projection, droppable with `DROP TABLE`, rebuildable from the network, and subordinate to the reader cache under disk pressure. | The same rule the local SQLite cache already lives under. |
| D6 | The network projection **never appears in the reading list, the rail, or any default view.** | Constraint 1. The reader you open every morning must not change at all. |
| D7 | **Opt-out requires no login; opt-in (attribution) requires a session.** | The only thing an unauthenticated opt-out can do is *remove* data. Making removal harder than inclusion is the wrong asymmetry. |
| D8 | Backfill reads arbitrary third-party PDS hosts and **must** route through `net::guarded_get_no_privacy`. | §8. The existing `PdsClient::list_records` does not, which is safe only under today's constrained usage. |
| D9 | Jetstream is used **without** zstd compression. | Avoids a `zstd` dependency for a stream measured in events-per-day. |
| D10 | We do **not** consume the relay firehose (`com.atproto.sync.subscribeRepos`). | It is DAG-CBOR + CAR blocks + MST validation (and MST validation is about to get stricter). Jetstream gives us the same records as plain JSON. §9.2. |

---

## 4. Capability 1 — adoption metric + portability CI test

**One sentence:** a scheduled, unauthenticated relay query that counts the repos
on the network holding `community.lexicon.rss.subscription`, plus a CI job that
reads a known DID's subscription records *straight off the network* and proves a
clean FeatherReader instance reconstructs them.

### 4.1 The call

```
GET https://relay1.us-west.bsky.network/xrpc/com.atproto.sync.listReposByCollection
      ?collection=community.lexicon.rss.subscription
      &limit=500
      &cursor=<opaque>
```

Unauthenticated. Response is `{ repos: [{ did }], cursor?: string }`.

**Pagination.** Page until the response has no `cursor`, mirroring the guard
already in [`PdsClient::list_all_records`](../src/atproto.rs): *stop if the page
was empty even when a cursor came back*, so a relay that echoes a cursor forever
cannot spin the loop. Additionally cap at `MAX_PAGES = 50` (25 000 repos at
`limit=500`); hitting the cap is logged at `warn` and recorded as
`truncated = true` on the observation, because at that point the number is a
floor, not a count.

**Politeness.** Once per `FEATHERREADER_ADOPTION_INTERVAL_SECS` (default
`86400`, with ±10% jitter so many self-hosted instances do not synchronise), 1
second between pages, `crate::USER_AGENT` on every request (already
`featherreader/<ver> (+https://feather-reader.com)`), and honour `429` /
`Retry-After` by aborting the run — never by retrying tighter. A run that fails
leaves the previous observation in place.

**The non-archival caveat, stated plainly.** Since sync v1.1 relays are
**non-archival**: they no longer mirror full repo data, and a relay's index only
covers hosts it actually crawls. Therefore:

- The number is a **lower bound on network adoption**, not a census. A PDS that
  no relay crawls is invisible to it.
- It is a count of *repos the relay has indexed as holding the collection*,
  which may include repos whose records were since deleted (atproto retains
  tombstoned records; the relay index is not a liveness signal).
- Two relays can disagree. We therefore query **every** host in
  `FEATHERREADER_RELAY_HOSTS` (default
  `relay1.us-west.bsky.network,relay1.us-east.bsky.network`) and record each
  observation separately, surfacing the **max**. Disagreement between relays is
  itself worth logging.

Legacy `bsky.network` sequence numbers (~8.4 B) and the new relays' (starting at
20 B) are **not** comparable; this capability does not use sequence numbers at
all, but the Jetstream cursor in §5 must not be confused with them.

### 4.2 Where it lives

New library module **`src/network.rs`** (added to the module tree in
[`src/lib.rs`](../src/lib.rs) alongside `net`), containing:

- `pub struct RelayClient` — thin wrapper over the shared `reqwest::Client`,
  every request routed through `net::guarded_get_no_privacy` (the relay host is
  operator-configurable, so it is user-influenced input by the same argument
  that guards `resolve_handle`).
- `pub async fn count_repos_with_collection(&self, collection: &str) -> Result<AdoptionObservation>`
- `pub struct AdoptionObservation { pub source: String, pub collection: String, pub repos: u64, pub truncated: bool, pub observed_at: String }`

New scheduler task **`run_adoption_probe`** in
[`src/scheduler.rs`](../src/scheduler.rs), added to the `spawn` vector next to
`run_poller` / `run_code_sweeper` / `run_retention_sweeper` / `run_flusher`, and
inheriting their shape exactly: `interval` + `MissedTickBehavior::Skip` +
`tokio::select!` on the shared `watch` shutdown receiver, errors logged and never
propagated out of the loop.

### 4.3 State

One new table, deliberately tiny, in the existing `SCHEMA` const in
[`src/store.rs`](../src/store.rs):

```sql
CREATE TABLE IF NOT EXISTS network_stat (
    key         TEXT NOT NULL,   -- e.g. 'adoption.subscription'
    source      TEXT NOT NULL,   -- the relay host the number came from
    value       INTEGER NOT NULL,
    truncated   INTEGER NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (key, source)
);
```

**We store the count, not the DIDs.** Persisting the DID list would create a
durable, network-wide register of "accounts that use an RSS reader" on our disk
— the exact thing §7.2 objects to — for a feature whose only output is an
integer. Capability 2 has a reason to hold DIDs; Capability 1 does not.

### 4.4 Where the number surfaces

- **Always:** an `info!` log line per run — `adoption.subscription`, `source`,
  `repos`, `truncated`. This is the operator-facing metric. FeatherReader has no
  `/metrics` endpoint and this spec does not add one.
- **Optionally:** one quiet line at the bottom of `GET /about`
  ([`templates/about.html`](../templates/about.html)), rendered only when
  `FEATHERREADER_SHOW_ADOPTION` is truthy — **default off**. Copy: *"N accounts
  on the atproto network hold `community.lexicon.rss.subscription` records, as
  of <date>."* Prose, one line, no chart, no badge.
- **Never:** `/health` (§2.1), `/`, or the rail.

The default-off is not shyness about the number; it is that a number which is
`1` reads as a status claim rather than a fact, and the honest place for it today
is the log.

### 4.5 The portability test

This is the half of Capability 1 that changes what the project can *claim*.

**Goal:** turn *"your feeds follow you anywhere"* from marketing copy into a
green check.

**What is provable headlessly, and what is not.** Login identity resolution is
owned by the sidecar's `@atproto/oauth-client-node`, and the OAuth handshake
requires a browser and a human consent screen. A fully end-to-end "clean
instance login" is therefore **not** achievable in CI, and this spec does not
pretend otherwise. What *is* achievable, and is the substance of the claim:

`tests/portability.rs` (a new integration test, `#[ignore]`d by default so
`cargo test` stays hermetic):

1. Resolve `FEATHERREADER_PORTABILITY_DID` (default the known test DID) to its
   PDS via the existing `atproto::resolve_did_to_pds` — which already fetches
   the DID doc through `net::guarded_get_no_privacy` and runs
   `net::assert_public_target` on the resolved `serviceEndpoint`.
2. Read `community.lexicon.rss.subscription` from that PDS
   **unauthenticated**, paging with `com.atproto.repo.listRecords`.
3. Assert ≥ 1 record, and that every record deserialises into
   `lexicon::Subscription` with a non-empty `url` and a parseable `createdAt`.
   *This is the real portability assertion:* a foreign implementation reading
   only the public lexicon gets usable data.
4. Assert the relay's `listReposByCollection` result contains that DID —
   i.e. the records are discoverable by a stranger who was not told where to
   look.
5. Boot a **clean instance**: `store::init_url("sqlite::memory:")`, a fresh
   `AppState`, and `web::router`, with the `SidecarClient` pointed at a
   **stub sidecar** — a local `tokio::net::TcpListener` that implements
   `/internal/session` (returning the test DID) and `/internal/repo` for
   `RepoAction::ListRecords` by proxying to the real PDS unauthenticated. Drive
   `GET /` through `tower::ServiceExt::oneshot` (already a dev-dependency, used
   by the existing web tests) and assert the rendered HTML contains every feed
   URL from step 2.

Step 5 is the honest version of "a clean instance login reconstructs them": it
exercises the real router, the real `resolve_subscriptions`, the real
`sub_ref` projection and the real templates, with only the OAuth handshake
stubbed. The test must assert on **feed URLs present in the HTML**, not on a
count, so a template regression that silently drops feeds fails it.

**Where it runs.** A **new, separate** workflow
`.github/workflows/portability.yml` — `schedule:` nightly plus
`workflow_dispatch:` — running `cargo test --test portability -- --ignored`.

It does **not** go in `ci.yml`. `grep -rni "bsky\.network"` returns zero hits in
the repo today, and `ci.yml`'s six jobs (`rust`, `cargo-deny`, `cargo-audit`,
`sidecar`, `bot`, `secrets`) need only crates.io, npmjs, the gitleaks release
tarball, and the Actions cache. (One nuance: `cargo test` *can* attempt a single
outbound call — `login_without_invite_redirects_to_beta_redeem` exercises
`may_start_oauth` → `atproto::resolve_handle` against the default
`https://bsky.social`. The invite gate is fail-closed, so the assertion holds
offline; that is a pattern worth preserving, not extending.)

A network flake must never red-X a pull request that changed a CSS token. The
nightly job failing is a *signal about the network*, which is exactly what we
want to learn.

### 4.6 Failure modes

| Failure | Behaviour |
|---|---|
| Relay unreachable / DNS fails | `warn!`, keep the previous `network_stat` row, retry next interval. Never fatal. |
| Relay returns 429 | Abort the run, `warn!` with `Retry-After` if present. No tighter retry. |
| Relay returns a malformed body | `warn!` with the parse error; no row written. |
| Page cap hit | Row written with `truncated = 1`; surfaces as "at least N". |
| SQLite write fails | `warn!` only; the probe is never allowed to affect the reader. |
| Nightly portability job fails | Nightly is red; PRs are unaffected. Triage is: did the test DID's records change, did the PDS move, or did the relay stop indexing us? |

---

## 5. Capability 2 — a Jetstream consumer for `community.lexicon.rss.subscription`

**One sentence:** hold a filtered websocket open to Jetstream for exactly one
collection, project the resulting public records into a bounded, rebuildable
local table, and derive from it two facts — *recently subscribed* and
*most-subscribed feeds* — that appear nowhere near the reading experience.

`community.lexicon.rss.subscription` is a **trickle**. That is the whole
economic argument: the collection that makes a follow-graph consumer
prohibitive (millions of events/day) is, for this collection, a handful of
events per day today and plausibly thousands per day at the largest adoption
this project could realistically reach. It is cheap to hold, cheap to store, and
cheap to throw away.

### 5.1 Connection

```
wss://jetstream.us-east.bsky.network/subscribe
    ?wantedCollections=community.lexicon.rss.subscription
    &cursor=<time_us>
```

- `wantedCollections` filtering happens **server-side**; we receive only this
  collection. No `wantedDids` filter — we want the whole (tiny) network.
- **No compression.** Jetstream offers optional zstd; we decline (D9).
- Configurable host list `FEATHERREADER_JETSTREAM_HOSTS`. *Uncertain:* the
  public instances appear to be named `jetstream1`/`jetstream2` in
  `us-east`/`us-west`; the default should be verified against Bluesky's docs at
  implementation time rather than taken from this document. Treat the value
  above as the one we have actually probed.

**Reconnect.** Exponential backoff `1s → 2 → 4 … → 60s` with ±25% jitter,
unbounded retries, every failure logged at `warn` and none fatal. On a clean
connect the backoff resets. There is no "give up" state: the consumer is a
best-effort tail, and the reader does not depend on it.

**Cursor.** Jetstream cursors are microsecond timestamps (`time_us`). We persist
the last processed `time_us` and reconnect at `last - 5_000_000` (a five-second
replay overlap) so a frame lost in a half-open socket is re-delivered. Replay is
harmless because every write is an upsert keyed by `(did, rkey)` (§5.3). The
cursor is persisted **at most once per second**, batched with the writes, not
per-event.

`cursor` is written to `network_state` (§5.3) as a string; it is unrelated to
relay sequence numbers and must not be compared against them.

### 5.2 Backpressure

One reader task, one writer task, a `tokio::sync::mpsc` channel bounded at
**1024** events between them. The writer coalesces into a single SQLite
transaction every **1 second or 500 events**, whichever comes first — the same
"one transaction per batch" discipline `insert_entries` already uses, which
matters because a poller write and a network write now contend for the same
`busy_timeout(5s)` connection pool.

**When the channel is full we disconnect** rather than block the socket read or
grow memory: drop the connection, keep the persisted cursor, reconnect with
backoff, and let Jetstream replay. This is the right trade because the reader's
SQLite pool is the scarce resource and Jetstream is the replayable one. A full
channel is logged at `warn` with a counter — sustained fullness is the signal to
turn the consumer off, not to tune it.

Additionally the consumer **stops writing and disconnects** whenever
`store::db_size_bytes` is at or above `config.db_size_watermark_bytes` — the
same watermark that already pauses the poller in `poll_due_once`. It re-checks
every 60 s and reconnects when the retention sweep brings the file back under.
**The reader always wins the disk.**

### 5.3 Data model

Three new tables, all in the existing SQLite file, all droppable:

```sql
-- One indexed subscription record from the public network.
CREATE TABLE IF NOT EXISTS net_subscription (
    did        TEXT NOT NULL,
    rkey       TEXT NOT NULL,
    feed_url   TEXT NOT NULL,
    created_at TEXT,             -- the record's own createdAt
    indexed_at TEXT NOT NULL,    -- when WE saw it (drives eviction)
    PRIMARY KEY (did, rkey)
);
CREATE INDEX IF NOT EXISTS idx_net_sub_feed    ON net_subscription (feed_url);
CREATE INDEX IF NOT EXISTS idx_net_sub_indexed ON net_subscription (indexed_at);

-- Derived rollup; a materialised GROUP BY, rebuilt from net_subscription.
CREATE TABLE IF NOT EXISTS net_feed_rollup (
    feed_url         TEXT PRIMARY KEY,
    subscriber_count INTEGER NOT NULL,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL
);

-- Cursors + backfill checkpoints + anything else the network tasks must remember.
CREATE TABLE IF NOT EXISTS network_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- DIDs that have asked not to be indexed (§7.2). Honoured at index AND display.
CREATE TABLE IF NOT EXISTS net_optout (
    did        TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);
```

**We store `feed_url` but never the subscription `title`, `siteUrl`, `folder`,
or `fetchHint`.** Those are the user's annotations of their own reading; the URL
is the only field the aggregate needs, and a folder name ("Job hunt", "Therapy")
is far more revealing than the feed itself.

**Size budget.** A `net_subscription` row is roughly 150–250 bytes including
index overhead. The hard cap `FEATHERREADER_NET_MAX_ROWS` defaults to
**200 000** rows (≈ 40–60 MB), which is comfortably inside the headroom between
a working reader cache and the **768 MiB** production watermark, and is
~200 000× today's actual network. Over the cap, the oldest `indexed_at` rows are evicted
in the same transaction as the insert. The retention sweeper
(`run_retention_sweeper`) gains a **prune-network-first** step: under disk
pressure it deletes from `net_subscription` before it touches `entries`, because
`entries` is what the user is reading and `net_subscription` is what a stranger
subscribed to.

Delete events (`commit.operation == "delete"`) remove the `(did, rkey)` row.
This matters: a user who unsubscribes must disappear from the aggregate, and
because the projection is keyed by rkey we can honour that exactly.

### 5.4 Rebuild from empty

The projection must be reconstructible from zero with no operator archaeology.
The procedure, run by the `run_network_backfill` task:

1. Enumerate DIDs via `listReposByCollection` — the **same call as Capability
   1**, which is why Capability 1 ships first and this reuses
   `network::RelayClient`.
2. For each DID, resolve its PDS (`atproto::resolve_did_to_pds`) and page
   `com.atproto.repo.listRecords` unauthenticated for the collection.
3. Checkpoint after each DID into `network_state` (`backfill.cursor` = the last
   completed DID; `backfill.started_at`), so a restart resumes rather than
   restarts.
4. **Record the Jetstream `time_us` cursor *before* step 1 begins.** When
   backfill completes, connect Jetstream at that pre-backfill cursor. Ordering
   it this way guarantees no gap; the overlap is free because writes are
   idempotent upserts.

**The relay cannot bootstrap this.** Sync v1.1 relays are non-archival — they no
longer mirror full repo data, so there is no `getRepo`-from-relay shortcut. The
enumerate-hosts → per-PDS `listRecords` walk is the *only* backfill path, and it
scales with the number of adopting accounts, not the size of the network. At
N=1 it is one HTTP call.

**Triggering a rebuild** is an operator action, not a route: set
`FEATHERREADER_NET_REBUILD=1` and restart. On boot the app truncates
`net_subscription` / `net_feed_rollup`, clears the `backfill.*` and
`jetstream.cursor` keys, logs loudly, and proceeds. No new authenticated
endpoint, no admin UI, no chance of a stray POST wiping the projection.

### 5.5 Degradation — the reader must not notice

This is the acceptance criterion for the whole capability:

- Every reader path (`/`, `/entries/{id}`, `/manage`, `/opml/export`, the rail,
  mark-read, star) must be **completely independent** of the network tables. No
  handler outside the network surfaces may `SELECT` from `net_*`.
- The 512 MB VM is the memory budget. The bounded channel (1024 events) plus the
  batch buffer (500 events) is the entire in-flight footprint by construction;
  nothing accumulates in a `Vec` that grows with the stream.
- If Jetstream is unreachable, the consumer loops in backoff and logs. Nothing
  else changes.
- If the network surface (§5.6) is reached while the projection is empty or
  stale, it renders a plain sentence — *"Nothing to show yet."* — and a
  last-updated timestamp. It does not spin, retry, or error.
- Compiled without the `jetstream` feature, the tables still exist (they are in
  `SCHEMA`, which is cheap and keeps the migration story trivial) and simply
  stay empty; the surface stays behind its config flag.
- A test asserts the router builds and `/` renders with all `net_*` tables
  empty, and again with the feature disabled.

### 5.6 The surface, and why it is not a discover tab

Constraint 1 says "no 'discover' tab as historically framed". The distinction
this spec draws — and it must be argued, not assumed — is:

> A **discover tab** ranks content for *you*, personalised, in the path you walk
> every day, optimised for engagement. What Capability 2 produces is a
> **deterministic public count** — how many accounts on a public network hold a
> record pointing at a feed URL — ordered by that count, identical for every
> viewer, reachable only if you go looking for it. That is a library catalogue,
> not a feed.

The rules that make that distinction real, and which are part of the spec rather
than good intentions:

1. **Placement.** A single page `GET /network`, linked **only** from `/about`.
   Not in the rail. Not on `/`. Not in the topbar. Never a redirect target.
2. **Off by default.** `FEATHERREADER_NETWORK_PAGE` defaults false, including on
   feather-reader.com, until the consent model (§7.2) has shipped *and* the
   adoption number is large enough that the page says something (§7.3 sets the
   gate).
3. **Deterministic ordering only.** `ORDER BY subscriber_count DESC, feed_url
   ASC`. No recency decay, no personalisation, no scoring, no ML, no A/B, no
   "for you". Two viewers loading the page in the same second see byte-identical
   HTML.
4. **k-anonymity floor.** A feed with fewer than `FEATHERREADER_NET_K` (default
   **5**) indexed subscribers is **not shown at all**. A count of 1 is a
   deanonymisation, not a statistic.
5. **No attribution without opt-in.** The page shows *feed URLs and counts*. It
   never shows which accounts subscribe to what, unless those accounts have
   explicitly opted in (§7.2).
6. **No-JS.** Server-rendered askama template, plain links, one optional
   `<form method="post">` for the opt-out. No htmx required, in keeping with
   "every action also works as a plain form POST".
7. **Two sections, both prose-first**, matching `DESIGN.md`'s components: a
   "recently added" list (feed title where the cache knows it, else the URL,
   with a `<time datetime>`), and a "most subscribed" list. Both capped at 25
   rows. No cards, no images, no counts rendered as badges (`DESIGN.md` §4.1:
   "plain text, never a pill").
8. **One line on the add-feed card.** The discovered-feed card in
   `templates/manage.html` may gain, at most, one muted line: *"14 accounts on
   the network subscribe to this feed."* Shown only above the k-floor and only
   when the page flag is on. This is the one place the projection touches a path
   the user actually walks, and it is a fact about the feed they already chose,
   not a suggestion of a different one.

**The honest counter-argument**, recorded so a future reader can reweigh it: the
project's stated test is "does this make the calm reading experience better, or
just bigger?" and Capability 2 makes it *bigger*. It adds a page, a websocket, a
dependency, four tables, and a privacy surface, in exchange for a fact most
users will never look up. It survives only because (a) it is the mechanism that
makes the lexicon's portability visible to newcomers, which is the project's
actual thesis, and (b) it is entirely optional and entirely off the reading
path. If in review it starts acquiring a second page, a sort control, or a
"recommended for you" section, that is the signal it failed the test and should
be removed.

---

## 6. Deployment shape

**Decision (D4): a `tokio` task in the existing `featherreader` process,
registered in `scheduler::spawn`, behind a cargo feature `jetstream` (default
off) *and* a runtime flag `FEATHERREADER_NETWORK_INDEX` (default off).**

The three options, weighed:

| Option | Verdict |
|---|---|
| **A fourth process in the container** | **Rejected.** `deploy/container-entrypoint.sh` uses `wait -n` and tears the container down when *any* child exits, on the sound reasoning that a dead Caddy / dead sidecar / dead app all mean "broken". A websocket consumer's normal life includes disconnects and, on a bad day, a panic. Wiring it into that supervisor makes an optional, best-effort feature able to bounce the machine and drop every reader's session (`SessionRegistry` is in-memory and cleared on restart). Relaxing `wait -n` to exempt one child would weaken a deliberate safety property for a feature nobody needs. |
| **A separate optional crate, like `bot/`** | **Rejected, with regret.** `bot/` is the right pattern for a component that talks to the app over HTTP and owns its own SQLite file. But this projection must be *read* by the web layer, so it would either need a second process writing the reader's SQLite file on a Fly volume — contending with a 5-connection pool that already sets `busy_timeout(5000)` on the reader's hot path — or a new HTTP API and its own storage, which is a second deployable for a page that is off by default. Neither earns its place. |
| **In-process `tokio` task** | **Chosen.** `scheduler.rs` already runs four long-lived, shutdown-aware, failure-tolerant loops with exactly the required shape. Adding a fifth costs one entry in the `spawn` vector. Crucially the whole module is already gated by `FEATHERREADER_DISABLE_SCHEDULER`, so an operator has a pre-existing kill switch. |

The self-hosting story is preserved by the **cargo feature**, not by process
separation: `cargo install feather-reader` builds no websocket code, links no
websocket code, and runs no network indexing. That is a stronger guarantee than
"there's a second binary you can choose not to run", because it also keeps the
default `Cargo.lock` audit surface honest for anyone who never wants this.

**Revisit trigger:** if the projection ever needs more disk than the reader can
spare, the answer is to split it into its own crate *with its own volume*, not
to shrink the reader cache. That is a different product (an AppView), and it
should be a different repo.

---

## 7. Capability 3 — social discovery via `app.bsky.graph.follow`

**Recommendation: do not build this. Not in the 0.3.x line, and not until the
gate in §7.3 is met.**

The idea is genuinely the one thing a conventional RSS reader structurally
cannot do: join `community.lexicon.rss.subscription` against the Bluesky social
graph to answer *"people you follow also read X"*. It is the most interesting
capability of the three. It is also the one that fails the most tests.

### 7.1 Why not — on the merits

**It is an algorithm, by the product's own definition.** "People you follow also
read X" is a personalised ranking of content the user has not chosen, computed
from their social graph. That is the recommendation engine the README defines
the product *against*. Capability 2 survives because its output is identical for
every viewer; Capability 3's output is different for every viewer by
construction. There is no framing that makes it not personalised — that is the
entire feature.

**Both data paths are unacceptable, for different reasons.**

- *Path A — index the follow graph.* Subscribe to `app.bsky.graph.follow` on
  Jetstream. This is precisely the cost already rejected for the invite bot
  (§9.1): Jetstream filters by collection and author DID, not by follow
  *subject*, so there is no cheap way to watch a slice. It means ingesting the
  network's entire follow firehose — millions of events per day — onto a 1 GB
  volume with a 768 MiB watermark. Arithmetically impossible, and it would
  starve the reader cache long before it was useful.
- *Path B — query on demand.* Call `app.bsky.graph.getFollows` on
  `public.api.bsky.app` for the logged-in user, cache it, intersect against
  `net_subscription`. Bounded and affordable. But it means the **server makes a
  third-party request carrying an identified user's DID, on their behalf, as a
  side effect of reading feeds** — a new category of data flow for a product
  whose privacy page says, in bold, "no third-party trackers". Bluesky's AppView
  would learn which FeatherReader users are active and when. That is not
  catastrophic; it is exactly the kind of thing this project has chosen not to
  do quietly.

**It has nothing to say.** With one repo on the network, the honest render of
"people you follow also read this" is "you do". The feature cannot be evaluated,
tuned, or even meaningfully tested until Capability 2 has been running long
enough for N to be non-trivial. Building it now is building against a fixture.

### 7.2 Privacy and the consent model

This section is binding on Capability 2 as well, and it is the part of this spec
most likely to be got wrong by being reasonable about it.

**The argument to reject.** *"These are public records on a public network;
anyone can read them; indexing them is not a privacy question."* That is true
about *access* and false about *expectation*. The codebase already reasons this
way in the other direction: `lexicon.rs` refuses private feeds because "writing
that URL here would leak paid / members-only access to the whole network", and
`privacy.html` tells the user their records are portable and under their
control. Nobody was told "and a reader will aggregate them into a leaderboard".
A reading list is inference-dense — health, politics, sexuality, employer,
job-hunting, recovery — and aggregation changes the practical exposure even when
it does not change the legal one. **Technically public ≠ expected to be
aggregated.**

**The lexicon gives us nothing to lean on.** `community.lexicon.rss.subscription`
has no visibility field. The only related field is `private`, which
`lexicon.rs` documents as a **reserved marker with no runtime behaviour**,
meaning "this feed's URL is a secret" — a different concept entirely, and
reusing it for "don't index me" would corrupt a field reserved for the eventual
permissioned-records migration.

**The consent model, as specified:**

| Action | Who can do it | Effect |
|---|---|---|
| **Opt out of indexing** | **Anyone, unauthenticated**, via `GET/POST /network/opt-out` with a handle | Resolve handle → DID, insert into `net_optout`, **delete every existing `net_subscription` row for that DID in the same transaction**, and skip that DID at index time forever. |
| **Opt in to attribution** | A logged-in session only | Adds the DID to an `attributable` set; only then may the network page ever name the account next to a feed. |
| **Aggregate counts** | — | Computed over non-opted-out DIDs, displayed only above the k-floor (§5.6 rule 4). |

D7 is deliberate: an unauthenticated opt-out can be abused only to *remove* a
stranger's row from our projection, which costs them nothing and costs us
nothing — the record still exists in their PDS, and Capability 1's count is
unaffected because it counts repos at the relay, not our table. Requiring a login
to be *left alone* would be the wrong asymmetry. Opt-*in* is authenticated
because being named is the direction that can harm.

Rate-limit both routes: add `/network/opt-out` to `is_rate_limited_path` in
[`src/web.rs`](../src/web.rs) — it resolves a handle, i.e. makes an outbound
call, exactly like `/login`.

**Should the default be opt-in rather than opt-out?** For *attribution*, yes,
and it is (D7). For *aggregate counting*, an opt-in default would make the
feature dead on arrival — no one would ever opt in to a page they cannot see —
and the aggregate is anonymous above a k-floor of 5. This spec therefore lands
on: **anonymous aggregation is opt-out; any naming is opt-in; and a self-hosted
instance indexes nothing at all unless its operator turns it on
(`FEATHERREADER_NETWORK_INDEX`, default false).** That last clause matters most:
without it, every self-hoster silently becomes an aggregator of strangers'
reading lists, which is the worst outcome available.

**`privacy.html` must change.** It currently says "there is very little of your
data for it to hold" and enumerates what the server holds; that enumeration
becomes false the moment `net_subscription` has rows. A new section, in the
existing plain-language voice, must be added between "What this server does
hold" and "Network and logs" — draft copy:

> ### Public records from the wider network
>
> `community.lexicon.rss.subscription` records are public: anyone on the atproto
> network can read them, including us. When network indexing is enabled, this
> instance keeps a **cache of those public records** — an account's DID and the
> feed URLs it subscribes to — so it can show how many accounts subscribe to a
> given feed. It does not store your folders, titles, stars, or read-state from
> anyone else's PDS, and it never shows which account subscribes to which feed
> unless that account has opted in.
>
> Counts are only shown for feeds with at least five subscribers, so a count can
> never point at one person. If you would rather not be included, **[opt
> out](/network/opt-out)** — no account needed. We delete your rows and skip you
> from then on. Your records in your own PDS are unaffected; this only controls
> what this instance caches.

And the "What this server does hold" list gains one bullet for the projection.

**A discoverability problem the opt-out inherits.** `/privacy` and `/terms` are
linked only from `templates/footer.html`, which is `{% include %}`d by
`about.html`, `index.html`, `manage.html`, `entry.html`, `privacy.html` and
`terms.html` — but **not** by `landing.html` (the signed-out `/`) or
`login.html`. So the two legal pages are unreachable by link from the signed-out
entry surfaces. Since the opt-out is explicitly for people who have **no account
here** (D7), shipping it behind a link that only logged-in users can find would
make the consent model theatre. `landing.html` must gain the footer include (or
at minimum the `/privacy` link) in the same release as the first indexing. This
is a pre-existing gap that Capability 2 turns into a defect.

**Is a lexicon change warranted?** A `discoverable: bool` field on
`community.lexicon.rss.subscription` (absent = no opinion) would be a
machine-readable signal any reader could honour. Assessment:

- *Cost:* `community.lexicon.*` is a **shared community lexicon** governed by
  Lexicon Community, not by us. A field addition is a public PR plus consensus
  with other adopters, on a schema FeatherReader does not own. It is also
  **unenforceable** — a determined aggregator ignores it, and it appears at the
  wrong granularity (per-subscription rather than per-account, so a user would
  have to set it on every record).
- *Benefit:* real but modest — it is signalling, and it standardises the
  question for the next implementation.
- *Timing:* FeatherReader is currently the **only** implementation with records
  on the network. A schema change is cheaper today than it will ever be again.
- **Recommendation:** file the proposal, do not block on it, do not treat its
  absence as consent, and keep the local `net_optout` table as the enforcement
  mechanism regardless of the outcome. If it lands, honour it *in addition to*
  the opt-out table.

### 7.3 The gate for revisiting Capability 3

Reopen this only when **all** of:

1. `network_stat['adoption.subscription']` ≥ **50** repos, sustained a month.
2. Capability 2 has run in production for ≥ 3 months with no privacy complaint
   and no disk incident.
3. Someone writes the paragraph that explains, to a user who came here to escape
   algorithmic feeds, why this specific feature is not one — and it survives
   review.

If it is ever built, the only shape this spec would sanction: **not** a tab,
**not** a ranked list, **not** on `/`. One deterministic, alphabetically-ordered
line on the existing subscribe-confirmation card in `manage.html` — *"Also
subscribed: @alice.example, @bob.example"* — computed at request time from a
cached follow list via Path B, shown only to users who explicitly opted in to
the social join, naming only accounts that opted in to attribution (§7.2), and
never, under any circumstance, used to reorder anything the user already reads.

---

## 8. Security: SSRF and the third-party PDS problem

The codebase already has a strong SSRF story: `net::guarded_get` /
`guarded_get_no_privacy` do scheme allow-listing, IP allow-listing (loopback,
link-local, RFC1918, ULA, CGNAT, metadata), **per-hop re-validation with manual
redirect following**, and **connect-pinning to the vetted IP** to close the
DNS-rebinding TOCTOU. `resolve_did_to_pds` runs `assert_public_target` on the
resolved `serviceEndpoint` before returning it. Reuse all of it — this spec adds
no new fetch primitive.

But backfill (§5.4) changes the threat model in a way worth stating explicitly.
Today the only PDS hosts FeatherReader talks to are those of accounts that
successfully logged in. Backfill talks to the PDS of **any DID the relay names**
— i.e. a host chosen by an adversary who need only publish one
`community.lexicon.rss.subscription` record to get us to fetch their endpoint.

Two consequences:

1. **`PdsClient::list_records` bypasses the guard.** It sends via
   `self.http.get(&url)` on the shared client, not through
   `guarded_get_no_privacy`. That is *currently* safe because `pds_base` was
   vetted by `assert_public_target` at resolve time — but that vetting is a
   separate DNS resolution from the fetch, which is exactly the rebinding window
   `net.rs` was written to close for feeds. Any backfill path **must** route
   through `net::guarded_get_no_privacy` (D8). Retrofitting the existing
   `PdsClient` methods is the cleaner fix and is scheduled in §10.
2. **`Auth` has no unauthenticated variant.** `atproto::Auth` is
   `Session(SessionAuth) | Oauth(OauthPlaceholder)`, and `PdsClient` requires
   one. Public reads of a stranger's repo need neither. The enum's own doc
   anticipates this ("so the match stays exhaustive if a second direct-auth
   mechanism is added"); add `Auth::Anonymous`, whose `bearer()` returns an
   error and which causes `list_records` to omit the `Authorization` header
   entirely.

Additional rules for the network paths:

- Cap the response body via the existing `net::read_capped` (8 MiB) — a hostile
  PDS can otherwise stream forever.
- Cap records per DID during backfill (`FEATHERREADER_NET_MAX_RECORDS_PER_DID`,
  default 5 000) so one repo cannot fill the projection.
- Global concurrency 2, ≤ 1 request/second per host, hard timeout per DID; a DID
  that errors or times out is skipped and checkpointed as done rather than
  retried in a loop.
- `feed_url` values arriving from strangers' records are **untrusted display
  input**: run them through `net::safe_link` before rendering an `href`, and
  never fetch them as a side effect of indexing. Indexing a URL must not
  subscribe anyone to it.
- Jetstream's `wss://` host is operator-configurable, so it is subject to the
  same allow-list reasoning; validate it with `net::assert_public_target` at
  startup before the first connect.

---

## 9. Rejected alternatives

### 9.1 Jetstream for the invite bot — rejected

The follow→invite bot ([`bot/src/main.rs`](../bot/src/main.rs)) polls
`app.bsky.graph.getFollowers` every `BOT_POLL_INTERVAL_SECS` (default 300).
Moving it to Jetstream looks natural and is **not** happening.

Jetstream filters by **collection** and by **author DID** — not by follow
*subject*. A follow record is authored by the follower, so watching
`@feather-reader.com`'s followers via Jetstream means subscribing to
`app.bsky.graph.follow` for the *entire network* and discarding ~100% of it. That
is millions of events per day, an unbounded stream, and a websocket to keep alive
— to replace one cheap paginated GET every five minutes against an endpoint
purpose-built for the question. The polling loop is correct. Decision recorded;
not to be re-litigated.

### 9.2 The relay firehose (`com.atproto.sync.subscribeRepos`) — rejected

The relay would give us the same records, but as DAG-CBOR frames carrying CAR
blocks that must be walked as an MST to extract record values, with commit
signature verification to be worth anything. Sync v1.1 also changed `#commit`'s
schema, removed `#handle`/`#migration`/`#tombstone` in favour of
`#identity`/`#account`, added `#sync`, and **stricter MST validation is coming
that will reject invalid `#commit` messages** — i.e. this surface is moving.
Jetstream delivers the same information as plain JSON with server-side
collection filtering, from a service explicitly offered for this purpose.
Rejected on dependency cost (`serde_ipld_dagcbor` + a CAR reader + MST code) and
on churn risk.

### 9.3 An atproto client SDK — rejected

`bot/Cargo.toml` documents the house position: *"The bot speaks atproto XRPC
directly over reqwest … Talking raw XRPC — rather than pulling a heavy client
SDK — keeps the dependency/audit surface small."* Everything in this spec is
either a plain GET with query parameters (`listReposByCollection`,
`listRecords`) or a JSON websocket. Neither needs an SDK. The one exception in
the repo — `@atproto/oauth-client-node` in the sidecar — exists because
DPoP/PAR/token-refresh is genuinely too subtle to hand-roll. Nothing here is.

### 9.4 A `/metrics` endpoint — rejected

Capability 1 produces one integer per relay per day. A Prometheus surface for it
would be more infrastructure than the metric. Logs plus one optional line on
`/about`.

### 9.5 Storing the adopter DID list for Capability 1 — rejected

See §4.3. Capability 1's output is a count; holding the DIDs would create a
durable register of "accounts that use an RSS reader" for no benefit. Capability
2 holds DIDs because it has to, and pays for that with §7.2.

### 9.6 Putting network state in a second database — rejected

A separate SQLite file would isolate the projection from the reader cache, which
is superficially attractive. But both files live on the same 1 GB volume, so it
buys no disk safety; it doubles the pool/backup/migration surface; and it
breaks the single-file "the cache is disposable, delete it" story. One file, one
watermark, one prune order (§5.3).

---

## 10. Testing, CI, and the release train

### 10.1 What the release train actually is

Recorded here because the implementation plan must target the real mechanism,
not the assumed one:

1. Work lands on a topic branch (`app-dev/…`, `feat/…`, `fix/…`, `ci/…`) and
   merges to `main` via PR. `ci.yml` gates it.
2. A release bumps `version` in `Cargo.toml` on an `app-dev/release-X.Y.Z`
   branch, merges, and is tagged `vX.Y.Z`.
3. The tag fires two workflows:
   - **`release-crate.yml`** — hard-verifies **tag == `Cargo.toml` version**
     (`::error::` + exit 1 on mismatch), then `cargo publish --locked` via
     crates.io Trusted Publishing (OIDC, no stored token).
   - **`release-image.yml`** — builds and pushes to
     `ghcr.io/justin-stanley/feather-reader`, tagged by `docker/metadata-action`
     as `{{version}}` (**without** the `v`), `{{major}}.{{minor}}`, `sha-<short>`,
     and `latest` only for the highest semver; then
     `actions/attest-build-provenance` with `push-to-registry: true`, and
     optionally a CycloneDX SBOM attested against the same digest
     (`ENABLE_SBOM=1`).
4. **Deploy is manual and by digest**, per the printed contract:
   `gh attestation verify oci://…@<digest> --repo justin-stanley/feather-reader`
   (fail-closed) then `fly deploy -i …@<digest>`. There is no automated deploy,
   no automated `/health` version assertion, and no auto-rollback; the only
   rollback semantics available are Fly recreating a machine when the entrypoint
   exits, and `latest=auto` preventing a hotfix on an older line from repointing
   `:latest` backward.

**Implication for this spec:** every milestone in the plan must be safe to leave
running in production for the length of a human deploy loop, because nothing
will pull it back automatically. That is a further argument for D2 (default-off)
and §5.5 (the reader must not notice).

### 10.2 Testing strategy

**Unit (in-module `#[cfg(test)]`, matching the repo's convention — there is no
`tests/` directory today and 190+ unit tests live beside their code):**

- `network`: relay response parsing; pagination termination on absent cursor
  **and** on an empty page with a cursor present (the `list_all_records` guard);
  page-cap → `truncated`; `Retry-After` handling.
- `network`: Jetstream frame parsing over fixtures — `commit` create / update /
  delete, plus `identity` and `account` frames which must be ignored without
  error; unknown fields must not fail deserialisation (forward compatibility,
  the same discipline `FetchHint::Other` already applies).
- `store`: `net_subscription` upsert idempotence over a replayed cursor window;
  delete removes the row; row-cap eviction drops oldest `indexed_at` first;
  `net_optout` insert deletes existing rows for that DID; rollup recomputation
  matches a direct `GROUP BY`.
- `web`: k-anonymity floor hides a feed with 4 subscribers and shows it at 5;
  the network page renders with empty tables; `/network/opt-out` is present in
  `is_rate_limited_path`; `/` and `/manage` render identically with the network
  tables full and empty (the D6 assertion).
- `net`: existing guard tests extended to cover the anonymous `list_records`
  path.

**Integration:**

- `tests/portability.rs` — §4.5, `#[ignore]`d, nightly workflow only.
- A stub Jetstream server for the transport loop: a local `TcpListener` speaking
  websocket via `tokio-tungstenite`'s server side as a **dev-dependency**,
  asserting reconnect-with-cursor after a forced close. The event-application
  logic is factored into a pure `apply_event(&Pool, JetstreamEvent)` so the bulk
  of the coverage needs no socket at all.

**CI changes:**

- `ci.yml`'s `rust` job gains one build leg: `cargo build --features jetstream
  --locked` and `cargo test --features jetstream --locked`, so the feature-gated
  code cannot rot. Everything stays hermetic.
- `cargo-deny` / `cargo-audit` see the new optional dependency in `Cargo.lock`
  regardless of the feature flag — that is a real (small) cost of D2 and is
  accepted knowingly.
- New `portability.yml`: `schedule` + `workflow_dispatch`, never on `pull_request`.

---

## 11. Configuration

All new knobs follow the existing `FEATHERREADER_*` convention and default to
the least-surprising value. Defaults are chosen so that **an unmodified
self-hosted instance behaves exactly as it does today**, except for one
unauthenticated GET per day.

| Variable | Default | Purpose |
|---|---|---|
| `FEATHERREADER_RELAY_HOSTS` | `relay1.us-west.bsky.network,relay1.us-east.bsky.network` | Relays queried for the adoption count. |
| `FEATHERREADER_ADOPTION_INTERVAL_SECS` | `86400` | Adoption probe cadence (±10% jitter). `0` disables. |
| `FEATHERREADER_SHOW_ADOPTION` | `false` | Render the adoption line on `/about`. |
| `FEATHERREADER_PORTABILITY_DID` | the known test DID | Subject of the nightly portability test. |
| `FEATHERREADER_NETWORK_INDEX` | `false` | Master switch: run backfill + Jetstream at all. |
| `FEATHERREADER_JETSTREAM_HOSTS` | `jetstream.us-east.bsky.network` | Jetstream endpoints, tried in order. |
| `FEATHERREADER_NET_MAX_ROWS` | `200000` | Hard cap on `net_subscription`; oldest evicted. |
| `FEATHERREADER_NET_MAX_RECORDS_PER_DID` | `5000` | Per-repo backfill cap. |
| `FEATHERREADER_NET_K` | `5` | k-anonymity floor for any displayed count. |
| `FEATHERREADER_NETWORK_PAGE` | `false` | Serve `GET /network`. |
| `FEATHERREADER_NET_REBUILD` | `false` | One-shot: truncate the projection and re-backfill on boot. |

The existing `FEATHERREADER_DISABLE_SCHEDULER` remains the blunt kill switch for
every background task including these.

---

## 12. Open questions

1. **The Jetstream host list.** The endpoint probed for this spec is
   `wss://jetstream.us-east.bsky.network/subscribe`. Public instances appear to
   be named `jetstream1`/`jetstream2` per region; the default list must be
   verified against Bluesky's documentation at implementation time rather than
   copied from here.
2. **Jetstream's cursor retention window.** Reconnect-with-cursor only works
   inside whatever backlog Jetstream keeps; a disconnect longer than that window
   silently becomes a gap. The spec's answer — fall back to a full backfill when
   the cursor is older than `FEATHERREADER_NET_STALE_CURSOR_SECS` — needs a real
   number, and this document does not have one.
3. **Does `listReposByCollection` count tombstoned repos or deleted records?**
   The count's precise semantics ("has ever held" vs "currently holds") are
   unverified. This affects only how §4.4's copy is worded, but it should be
   worded correctly.
4. **Feed-URL canonicalisation across repos.** Two accounts can subscribe to the
   same feed with URLs differing by trailing slash, scheme, `www.`, or tracking
   parameters, and the rollup would count them as two feeds. The reader already
   has canonicalisation logic in `feed.rs`; reusing it for the projection is
   probably right, but it changes the primary key semantics of
   `net_feed_rollup` and needs a decision before the first rollup is built.
5. **Should the network projection respect private-feed classification?** If a
   stranger writes a secret-bearing URL into their public subscription record
   (which FeatherReader refuses to do but another implementation might not), we
   would index and potentially *display* their secret. The conservative answer
   is to run `feed::classify_feed_privacy` at index time and drop anything
   classified private — which is cheap, uses existing code, and is almost
   certainly the right call. Confirm and make it a rule.
6. **Handle rendering.** The network page shows feed URLs. Should it resolve and
   show feed *titles* from the local cache when available? Nicer to read, but it
   means the page's content depends on which feeds this instance happens to have
   polled, making it non-deterministic across instances. Leaning: URLs plus
   cached title where present, with the URL always shown.
7. **`GET /network` and the Caddy origin lock.** Every path except `/health` is
   gated on Cloudflare's `X-Origin-Auth`. Nothing about the network page needs
   an exemption, but confirm the CDN cache rules treat it as cacheable
   (`public, max-age=300` via the existing `cache_control` middleware) since it
   is identical for every viewer — it is the one page in the app that genuinely
   is.
