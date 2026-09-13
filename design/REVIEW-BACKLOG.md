# Review backlog — the findings not yet fixed

Source: three independent reviewers (security SME, regression, operator) over
`feat/rust-oauth-phase1` at `af2c4df`, plus leftovers from the preceding round.
The blockers from that sweep are fixed in `d67e7b9`. This file is what remains.

Every item below was re-verified against the tree at `d67e7b9` before being
written down — three of the reviewers' line numbers had already moved, and one
finding (`display_date`) was fixed in the interim. Claims here are things I
looked at, not things I inherited.

**Sequencing note.** Tier 1 is what stands between here and a deploy. Tiers 2–3
are the difference between an instance that fails loudly and one that fails at
3am in a way nobody can attribute. Tier 4 is real but survivable.

**Status.** All four tiers are done — T1.2/T1.3 in `ba9951a`, T1.1 in
`1cfae77`, T2.1/T2.2/T2.4/T2.5 in `1831bba`, T2.3 in `75f1c53`, T3.1/T3.2 in
`5f0b2c1`, and T4.1–T4.5 in the commit that updated this line. T4.6 is 0.4.0
work and is recorded, not code.

A second cold-review round over `efb1d3f..5f0b2c1` ran while Tier 4 was being
written; its findings are NOT folded in here and are triaged separately. Completed entries are kept below rather than deleted, because
each states a failure mode its fix now has to keep closed, and that is worth
having written down next to the tiers that are still open.

---

## Tier 1 — before 0.3.0 ships — **DONE**

### T1.1 The list queries are unbounded and select the article body — FIXED

`get_unread_for_did` (`store.rs:1571`), `get_starred_for_did` (`:1593`) and
`entries_for_feed` (`:1210`) all do `SELECT e.*` with **no `LIMIT`**. Verified:
zero `LIMIT` tokens across all three. `e.*` includes `content_html`, which is
essentially all of the measured 11.9 KB/entry.

`EntryRow` (`web.rs:760`) is `{id, title, feed_title, published, read, starred,
link, cached}` — **it never reads the body**. So the body is loaded, allocated,
and then dropped, on every page load. `GET /` calls the first two and then
`.cloned()`s the filtered result, a second full copy. `?view=all` loops every
subscribed feed and appends each feed's entire entry set (up to
`max_entries_per_feed`) into one `Vec`.

On a 512 MB box where Node already holds 134–172 MB and Caddy 30 MB, with
`hard_limit = 250` concurrent requests, one reader with a large backlog can ask
for hundreds of MB in a single handler. The symptom is a container restart —
Rust OOMs, `wait -n` fires, Fly restarts — and the cause is invisible, because
the machine looks healthy and the trigger is one person's inbox size.

**Fix.** A dedicated list projection (`SELECT e.id, e.title, e.published, …`)
into a `EntryListRow` struct, plus a `LIMIT` with an offset/cursor for paging.
Keep `SELECT e.*` only on the single-entry reader path, which genuinely needs
the body.

**Verify.** A test that inserts N entries with large `content_html` and asserts
the list query's returned rows carry no body; a second asserting the row count
is capped. Both fail against today's code.

**Cost.** Three queries, one new struct, one handler, and the paging control in
the template. The largest item in this file and the one the operator singled out
as the one change it would want before deploying.

**Done.** The three queries collapsed into one `store::list_entries` over a
body-free `EntryListRow`, with `limit`/`offset` as required parameters — the same
"make the guard structural" move `discover(expected_issuer)` got in `d67e7b9`,
so there is no unbounded variant left to reach for. Scope moved inside the query
(filtering after a `LIMIT` would have produced arbitrarily short pages), the
sidebar counts in SQL instead of materializing every unread entry, prev/next
fetches ids rather than rows, and `GET /` pages at 100. The single-entry reader
keeps `SELECT e.*`, which is what it is for.

### T1.2 `fly.toml` does not list the secret that gates the cutover — FIXED

`config.rs:629-640` refuses to boot when `FEATHERREADER_REPO_BACKEND=rust` on a
prod-like instance without `FEATHERREADER_OAUTH_ENCRYPTION_KEY`. Verified:
`fly.toml` (107 lines) never mentions that variable, in either its REQUIRED or
OPTIONAL SECRETS block.

An operator following `fly.toml` to throw the 0.3.0 switch gets an immediate,
permanent boot loop — recoverable in seconds once understood, but it lands at
the exact moment of the cutover, which is the worst time to be reading source to
find out why. The Dockerfile comment documents it; the file operators actually
follow does not.

**Fix.** Add it to the REQUIRED block with a one-line note that it is required
only on the `rust` backend. Doc-only.

**Cost.** Minutes. Highest consequence-to-effort ratio in the file.

**Done** in `ba9951a`, with a BACKEND CUTOVER block stating both halves of the
flip and their order, and `FEATHERREADER_REPO_BACKEND` now spelled out in `[env]`
at its existing default so the live backend is visible in the file.

### T1.3 `retention_days = 0` disables the hard ceiling too — FIXED

`prune_old_entries` returns on `days <= 0` **before** the ceiling is computed
(verified at `store.rs`), and `run_retention_sweeper` returns before starting a
ticker. So on `FEATHERREADER_RETENTION_DAYS=0` — a setting the env table still
advertises as "disables eviction" — there is no eviction *and* no ceiling.

That combination is now strictly worse than before this branch: the per-feed
trim used to catch starred entries and no longer does (it spares up to `2 ×
cap`), so a `retention_days=0` instance has **no bound on starred entries at
all**. The prose added in the last commit — "this is the bound", "the retention
DELETE is its only release valve" — is false for exactly that configuration.

**Fix.** Make the ceiling independent of the window: run the hard delete
whenever `hard_days > 0`, regardless of `days`. "I don't want a cache window"
and "I don't want any ceiling" are different statements and should be
configured separately. Then the claim is true again for every configuration.

**Verify.** Extend `a_ceiling_inside_the_window_is_ignored_not_applied` with a
`days = 0, hard = 180` case asserting a 400-day-old starred entry is removed.

**Done** in `ba9951a`. The two knobs are independent, the sweeper runs if either
is on, and the both-off log line now states outright that the cache is unbounded
in that configuration. Verified by restoring the `days <= 0` early return and
confirming `a_disabled_window_does_not_disable_the_ceiling` fails against it.

---

## Tier 2 — availability, fast follow — **DONE**

### T2.1 A process-killing feed is a permanent crash loop — FIXED

Nothing is written to the feed row *before* the fetch: `bump_feed_errors` and
`set_next_poll` both run only after `poll_feed` returns. `due_feeds` orders by
`next_poll ASC`, and the poller's interval fires its first tick immediately. So
a feed whose fetch or parse takes the process down is re-selected **first** on
every restart, forever, and escape requires manual DB surgery.

The trigger is plausible here: `MAX_BODY_BYTES` is 8 MiB × concurrency 4 = 32
MiB of raw bodies, and `feed_rs` builds an in-memory model several times the
wire size alongside the sanitized `Vec<NewEntry>`.

`run_adoption_probe` already reasons about precisely this hazard — its doc
comment notes that the supervisor turns "once per boot" into "once per
crash-loop restart" — and adds a startup delay. The poller, the retention
sweeper and the code sweeper all still fire immediately.

**Fix.** Two parts, and the second is the real one:
1. A startup delay with seed-stable jitter on the three loops, mirroring the
   adoption probe.
2. Push `next_poll` forward *before* the fetch, not after. Then a feed that kills
   the process goes to the back of the queue instead of the front, and the loop
   self-heals. This is the part that converts "permanent" into "one restart".

**Verify.** A test asserting `next_poll` has moved after a `poll_feed` that
returns `Err` — and, more to the point, after one that never returns at all
(simulate by asserting the write happens before the fetch is invoked, using the
same dependency-injection shape the OAuth orchestrators now use).

**Done** in `1831bba`, both parts. The lease is the cadence the feed would have
got had the poll succeeded, so a returning poll overwrites it and the common case
is unchanged. Startup delays went on FIVE loops, not three: `run_pending_sweeper`
also fired immediately and the review did not name it. Fixed distinct offsets
rather than jitter — one machine, no fleet to de-synchronise, and fixed values
stay reproducible in a test.

### T2.2 The retention sweep holds the single write lock too long — FIXED

`prune_old_entries` opens one transaction and calls `prune_orphan_cursor_ids_tx`,
which loads every `read_cursor` row and then issues a fresh per-cursor `SELECT
… JOIN … WHERE f.url = ?` returning up to `max_entries_per_feed` ids — all
inside that transaction. SQLite is single-writer and `busy_timeout` is 5 s, so
for the duration every mark-read, every login write and every cursor flush
fails.

The new `idx_entry_state_entry_id` index (in `d67e7b9`) fixes the FK cascade
half of this — measured 32,850 deletes from ~10 minutes to 0.7 s. The
per-cursor loop is untouched and is now the dominant term.

**Fix.** Chunk the delete (bounded batches, committing between them) and move
the cursor scrub out of the delete transaction. Correctness is preserved
because the scrub is idempotent and already gated on rows having changed.

**Done** in `1831bba`. One detail the plan missed: batching alone is not enough —
without an explicit hand-off between batches the loop re-acquires the write lock
immediately and a waiting writer still starves, so the fix would have been
bookkeeping. The test measures LATENCY rather than success, because at realistic
test sizes the old shape still finished inside `busy_timeout` and the writes
would have landed — each having waited for the entire sweep.

### T2.3 `reclaim()` runs a full `VACUUM`, and always will — FIXED

`store.rs:731-741` uses `PRAGMA incremental_vacuum` only when `PRAGMA
auto_vacuum == 2`. Verified: `auto_vacuum` is **read** there and **never set**
anywhere in the tree, so SQLite's default (NONE = 0) applies and the
full-`VACUUM` branch is the one that actually runs — daily, and after a prune.

A full VACUUM needs free disk roughly equal to the live DB, which is exactly
what is scarce under the disk pressure that triggered the sweep; in WAL mode it
writes the whole new database through the WAL. On a ~700 MiB DB on a 1 GB
volume it cannot complete. `poll_due_once` carries a comment explaining this
danger and removes VACUUM from the poll path, while leaving it in the retention
path that runs under the same pressure.

**Gotcha that shapes the fix.** `auto_vacuum` cannot be changed on a populated
database by setting the pragma alone — it requires setting it *and then running
a full VACUUM*. So the migration needs the very operation that is unsafe under
pressure. It must be a deliberate one-time step taken while the volume has
headroom, not something done lazily at boot.

**Fix.** Set `auto_vacuum = INCREMENTAL` at database *creation* so new instances
never have the problem; add an explicit, operator-invoked migration path for
existing ones; and make the daily reclaim a no-op rather than a full VACUUM when
the mode is NONE. Also set `journal_size_limit` (a WAL grown once by a large
transaction is never truncated today) and make `db_size_bytes` account for the
WAL's share of the volume, which it currently ignores.

**Done**, all five parts. The migration is a CLI flag
(`featherreader --migrate-auto-vacuum`) rather than a boot step, because a
boot-time VACUUM that cannot complete on a full volume, under a supervisor that
restarts on any child exit, is precisely the crash-loop shape T2.1 just removed;
it refuses itself when the volume lacks headroom, and is a no-op on an
already-migrated database so it is safe to run blindly. Skipping the VACUUM in
NONE mode does NOT latch the watermark — `db_size_bytes` subtracts the freelist,
so a DELETE lowers it with no VACUUM at all; what is lost is only the file
shrinking. Counting the WAL then surfaced that `reclaim` was giving back database
pages while leaving a WAL the sweep had just grown, so it now truncates the WAL
too — the only space it can return at all in NONE mode.

### T2.4 The rate-limit map is unbounded with O(n) eviction per request — FIXED

`web.rs` keeps `HashMap<IpAddr, Bucket>` with a 1-hour idle eviction and **no
size cap**, and calls `map.retain(…)` across the whole map on every guarded
request. Contrast `MAX_PINNED_CLIENTS = 256` in `net.rs`, where the same author
did bound the equivalent structure. `GET /login` and `GET /claim` are guarded
and unauthenticated, so distinct source IPs accumulate for an hour each while
every request re-scans all of them — wrong on both memory and CPU for 512 MB
and one shared core.

**Fix.** Cap the map (evict oldest past the cap, as the pinned-client cache
does) and amortize the sweep — only `retain` every N seconds, not per request.

**Done** in `1831bba`. LRU eviction is what makes a size cap safe rather than a
bypass: an attacker cannot evict their own throttled bucket, because it is by
definition the most recently touched entry. Writing that test surfaced that a
millisecond clock step let the token REFILL hand back a token and masquerade as
an eviction bypass; it steps in nanoseconds now.

### T2.5 Pinned clients have unbounded idle connection pools — FIXED

`build_pinned_client` sets neither `pool_max_idle_per_host` nor
`pool_idle_timeout` (verified: neither appears in `net.rs`). With up to 256
cached clients against a 300 s TTL and a poller touching up to 50 distinct hosts
per minute, steady state sits near the cap with each entry holding live
keep-alive TLS connections. The measured "Rust app ~20 MB" likely predates a
populated cache.

**Fix.** Set both on the builder. Two lines.

**Done** in `1831bba`, plus a test that the idle timeout stays under the client
TTL — the reverse ordering makes every cached client pay socket rent for the tail
of its life.

---

## Tier 3 — diagnosability — **DONE**

The operator's framing: the two states that actually stop feeds from updating
produce no operator-facing signal, so every degraded-but-running state presents
as a green machine.

### T3.1 `/health` proves only that the process is alive — FIXED

It returns a constant string, touching no DB, no pool and no scheduler state —
and it is the only automated signal in `fly.toml`. The supervisor's only other
failure detector is a child *exiting*.

**Fix.** Have it check what would actually be broken: a DB ping and a scheduler
heartbeat timestamp. Deliberately keep it cheap and avoid making it flap — a
health check that fails on transient load turns a degradation into an outage,
which is worse than the problem.

**Done**, with the anti-flap requirement taken literally: **only the database can
change the status code.** The probe is one `SELECT 1`, which no writer can block
in WAL mode, under a 2 s timeout inside Fly's 3 s — so a wedged pool yields a 503
the app chose, with a reason, rather than a timeout Fly inferred. The heartbeat,
the fetch-pause state and the live backend are reported in the body and never
fail the check, because Fly restarts on failure and a restart fixes none of them.

Two documents had to be corrected rather than quietly broken. `NETWORK-SPEC.md`
§2.1 stated `/health` returns a literal string and that nothing may add a field
to it; that bullet is now marked superseded, with the parts of it that were
actually load-bearing (fast, non-flapping, network state stays out) restated and
enforced. `deploy/Caddyfile` justified exempting `/health` from the origin lock
on the grounds that it "only returns a static string" — the exemption now
explicitly BOUNDS what the body may contain, which is why the measured database
size was dropped from it.

### T3.2 Nothing surfaces the two states that stop polling — FIXED

`feeds.consecutive_errors` is written and read by nothing outside the backoff
calculation — it appears on no page and no endpoint. The watermark pause emits a
per-tick `warn!` and nothing else. `/stats` shows `overdue` and
`polled_last_hour`, which move in *both* states and distinguish neither; a feed
in backoff is not even counted as overdue, because its `next_poll` was pushed
forward. And `/admin/metrics` requires a live admin **session**, making it
unreachable during exactly the OAuth outage you would want it for.

When a reader reports "my feeds stopped updating", the operator has `fly logs`
and nothing else.

**Fix.** Surface both states as aggregate counts on `/stats` — feeds in backoff,
and whether the watermark pause is currently engaged. Both are machine facts,
not user data, so they fit the page's stated "no user counts, no per-feed
detail" contract. Add a non-session diagnostic for the OAuth-outage case.

**Done.** `/stats` gains a "Failing (backing off)" count — with a second figure
for feeds deep enough into backoff to be effectively dead — and a "Fetching:
running / paused" row. The prose explains the inversion that made this
invisible: backoff is applied by pushing `next_poll` forward, so a feed that
breaks DROPS OUT of `overdue` and makes the page read healthier. A new
`runtime_health` module holds the two things SQLite cannot answer (the poll
heartbeat and the pause verdict); it is deliberately process-local and lossy,
since the question is "what is the loop doing right now". The non-session
OAuth diagnostic is `/health` reporting the live backend and whether the OAuth
runtime built — reachable with `curl` at exactly the moment the session-gated
`/admin/metrics` is not.

---

## Tier 4 — correctness and papercuts — **DONE**

### T4.1 `starred` is scoped by subscription, so the unsave desync survives — FIXED

**Done** at the DESTRUCTIVE end rather than the rendering end. `unsave_record`
now reads the record's identity before deleting it and clears any local star for
the same article (`store::clear_star_by_identity`, which deliberately omits the
`sub_ref` predicate — every row it can touch is keyed by the caller's own DID and
it only ever writes `starred = 0`).

Dropping `sub_ref` from the RENDER path instead would have been wrong: the row
would then link to `/entries/{id}`, which is `sub_ref`-scoped and would 404. An
article in a feed you no longer follow genuinely is "held by the PDS record, not
by any feed you read" — that rendering is correct, and what needed fixing was
that removing it only removed half of it.

**Still open after T1.1** — the identity lookup moved to
`store::starred_identities`, but it shares `list_query_sql`, which carries the
same `sub_ref` predicate. Unchanged in substance; only the function name below
is now stale.

`get_starred_for_did` requires `EXISTS (SELECT 1 FROM sub_ref …)`. An entry that
is cached *and* starred, in a feed the reader has since unsubscribed from, is
absent from `starred`, so it still renders as "not cached" and its button is
still `POST /saved/{rkey}/delete` — which deletes the PDS record and leaves
`entry_state.starred = 1` behind. `toggle_star` does both. The last round's fix
narrowed this case rather than closing it, and its comment ("match against ALL
cached starred entries") is inaccurate as written.

### T4.2 The `safe_link` skip is silent and in the wrong order — FIXED

**Done**, with one correction to the finding. The ordering was not exploitable:
the nudge keys on `feed_url`, not on the `item.url` being rejected, and is
already gated on the reader subscribing to that feed — so an unusable URL never
reached it. The check moved above the nudge anyway as ordering hygiene.

The real defect was the `continue`: the row vanished, and because the un-save
button lives ON the row, the record became unremovable from this client. It now
renders without an anchor and with an "unusable link" badge, and the title falls
back to the rkey rather than to the URL `safe_link` just rejected.

An unusable saved-record URL makes the row vanish entirely — no badge, no count,
and the `tracing::debug!` is below any realistic filter — so the record can then
only be removed from another client. Worse, the `mark_feed_due` nudge runs
**before** the `safe_link` check, so an unusable record still triggers an
outbound poll nudge on every render.

**Fix.** Reorder so the check precedes the nudge, and render the row without an
anchor rather than dropping it, so it stays unsave-able.

### T4.3 Server-controlled `error_description` is logged verbatim — FIXED

**Done**, and the finding understated it: the raw `error` also went into the
RENDERED login page (`login_error(&format!("Login failed: {err}"))`), so an
attacker who could make a browser fetch the callback chose copy shown in the
product's own voice. `known_error_slug` is now `pub(crate)` and both the log and
the page carry only a `&'static str` from the fixed list; the description is
dropped, keeping only its length.

`web.rs:2839` logs it at `warn!`. `oauth/flow.rs:186-199` deliberately reduces
the callback `error` to a known slug and drops the description for precisely
this reason; the older arm in `web.rs` never got the same treatment.
Attacker-controlled free text, including newlines, into the log stream.

**Fix.** Apply the same reduction `flow.rs` already implements.

### T4.4 Six swallowed errors that change what the user sees — FIXED

**Done.** Three now log with context (both `upsert_feed` sites, the
`feeds_for_did` sidebar fallback), and three stopped reporting success for work
that did not happen: a failed PDS `update_subscription` flashes instead of
redirecting as though the rename landed; a failed OPML batch write returns
"nothing was imported" rather than "Imported N feeds"; and an OPML PARSE failure
is now distinguished from a valid-but-empty file, which used to be reported as
"No feeds found in that OPML" and sent the reader looking for feeds that were
right there in the export.

One existing test asserted the rename handler redirects to `/` — which only held
because the PDS failure was hidden, and there is no PDS in that test. It now
asserts the property it was actually written for (not refused by the feed cap).

`unwrap_or_default()` / `let _ =` on paths where failure is silent and
user-visible. Two are literal support tickets: `let _ = store::upsert_feed(…)`
(verified at `web.rs:1219`, `:2411`, `:3956`) means a subscription can exist in
the PDS and never be polled — "I added a feed and it never updates" — and
`feeds_for_did(…).unwrap_or_default()` renders an empty sidebar on a DB error:
"all my feeds vanished". Also: a failed PDS `update_subscription` is a `warn!`
while the handler still redirects as if it succeeded, and a failed OPML parse is
reported to the user as "No feeds found in that OPML".

**Fix.** Log every one of them with context; correct the two that report success
for work that did not happen.

### T4.5 Read-state above 1000 ids per feed is silently discarded — FIXED

**Done** as the finding prescribed: `store::compact_cursor` computes the
water-mark `read_through` always lacked. The rule is that it may only advance to
a point with no unread entry at or before it — implemented as the newest entry
timestamp STRICTLY older than the oldest unread one, strictly because entries can
share a timestamp and an equal water-mark would assert an unread entry is read.

Run from the flusher once `read_ids` passes half the lexicon cap, so the common
cursor never pays for it. `cap` remains as the last line of defence and now warns
when it fires, which after compaction means only that the feed's oldest entry is
genuinely unread.

`read_through` is never *computed* — `project_entry_into_cursor` only carries an
existing value through, and it starts NULL (verified: the only non-test
assignment in `src/` is a `.clone()` of the existing value). So `read_ids` is the
sole mechanism and grows one id per article read, bounded only by
`max_entries_per_feed` (2000), while the flusher caps at `MAX_IDS = 1000`
keeping the tail — with no log line. Past 1000 read articles in a feed, the
oldest read-state stops syncing and those articles come back unread in any other
atproto reader. The code comment assumes "the exception sets stay well under the
cap"; against a 2000-entry per-feed ceiling that does not hold.

**Fix.** Implement the compaction the comment describes — advance `read_through`
to a high-water mark and drop the ids below it. That is what the field is for.

### T4.6 Capacity constants do not match the machine

`max_feeds_global = 10_000` against a poller that manages 50 feeds per 60 s tick
= **3,000 feeds/hour** at `poll_interval = 3600 s`. The global ceiling is 3.3×
what the poller can ever service; past ~3,000 feeds the instance falls
permanently behind with no signal beyond a slowly rising `overdue`. On disk,
11.9 KB/entry against the 768 MiB watermark is ~67,000 entries — a single user
at the 500-feed cap can plausibly reach that and pause polling for everyone.

This is already 0.4.0 work (tasks #17 and #19: measure, then raise throughput,
then open registration). Recorded here so the numbers live next to the findings
that motivate them.

---

## The structural theme, and the one piece of work that addresses it

The security reviewer's judgement is the most useful output of the whole sweep,
and it is not about any individual bug:

> Where a guard is *structurally unavoidable* it is applied perfectly. Where a
> guard is a *free function the caller must remember to call*, it drifts, every
> time.

Five for five, with the project's own comments as evidence:

| guard | applied | missed |
|---|---|---|
| `safe_link` | `feed.rs` | the saved-record path |
| `classify_feed_privacy` | 4 call sites | `resolve_subscriptions` |
| `is_rate_limited_path` | most routes | `/saved/`, then `/oauth/callback` + `/logout` |
| `same_issuer` | callback, refresh | **revocation** |
| capacity ceilings | add, import | `resolve_subscriptions` |

Nothing can reach the network except through `net.rs`, because those helpers own
client construction, content type, redirect policy and body cap. That single
decision is why two of this round's findings were Medium rather than critical —
the unguarded subscription URL and the unguarded OPML URL both still failed
closed at the fetch.

`d67e7b9` applied that lesson once: `discover` now *takes* the expected issuer
as a required parameter instead of trusting callers to call `same_issuer`. T1.1
applied it a second time: `list_entries` *takes* `limit` and `offset`, and the
three unbounded functions it replaced were deleted rather than kept alongside it
— an unbounded variant left in place is the same trap with a longer name. The
remaining two are worth doing for the same reason:

- **`upsert_feed` should take a validated newtype** that only
  `classify_feed_privacy` + a URL check can mint. Two of its three non-test
  callers were fixed in `d67e7b9` by adding checks; the trap itself is still
  there for caller four.
- **`is_rate_limited_path` should invert** into a per-route opt-out declared at
  the router, so adding a route forces a decision instead of defaulting to
  unguarded. Its current test asserts coverage only for routes already in the
  list, which is why two misses sat there undetected.

Without these, expect a sixth instance. That prediction is the reviewer's, and
on the evidence it is a good one.

---

## Still unverified for 0.3.0 (not code — validation)

- `private_key_jwt` against production.
- Revocation against a live PDS.
- The full container has never been started.
