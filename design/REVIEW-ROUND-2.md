# Review round 2 — the tier work, reviewed cold

Three independent reviewers (security SME, regression, operator) over
`efb1d3f..5f0b2c1` — the five commits that closed Tiers 1–3. The
confirmed-serious half is fixed in `1881b48`. This file is the rest, plus the
loop that runs until a review pass comes back clean.

**Every claim here I verified against the code myself**, empirically where the
claim was empirical. Two reviewer findings were wrong or overstated and are
recorded as such rather than silently dropped — see "Not defects" at the bottom.

**The pattern worth naming.** Round 1 fixed a lot and introduced three new bugs
in the process: a lost update (fixed in `1881b48`), a probe that proved nothing
(fixed), and a config pair that removes the only bound on the cache (fixed). The
project's own history says later passes find bugs in earlier passes' fixes, and
it did again. That is why this file ends in a loop rather than a list.

---

## R1 — `starred_identities` truncation fails OPEN, toward deleting PDS records

`store.rs` — `LIMIT ?2` with **no `ORDER BY`**, and `web.rs` checks only
`!identities.is_empty()`.

The function's own doc says it must span the whole starred set, because a record
that looks uncached gets an un-save button that deletes the PDS RECORD rather
than un-starring the entry. The `LIMIT 20_000` backstop violates exactly that
invariant when it fires, and nothing detects it: `identities_ok` never compares
`identities.len()` against the cap. With no `ORDER BY`, the surviving subset is
arbitrary, so an arbitrary cached starred article renders with a
record-destroying button.

**Fix.** Detect the truncation (`len >= cap` ⇒ treat as failed, same fail-closed
path as an error) and add a deterministic `ORDER BY` so the set is at least
stable across renders. The cap stays as a memory backstop; what changes is that
hitting it stops pointing at the destructive outcome.

## R2 — the `total == 0` escape hatch compares a scoped count to an unscoped set

`web.rs` — `identities_ok = !identities.is_empty() || total == 0`.

`total` is `count_entries_for_view(…, scope_ids)` — narrowed by `?feed=` /
`?folder=`. `identities` is `starred_identities(…)`, which passes `None` and
spans every feed. The two are not comparable, so `total == 0` can wave through
the fail-closed condition an empty `identities` was supposed to trip.

Reachable when the identity query errors AND the scope is narrow: the record
renders uncached, and its button deletes the PDS record for an article that is
cached and starred. Narrower than R1, same class.

**Fix.** Compare like with like: the escape hatch should ask whether this DID has
any cached starred entry AT ALL, not whether the current scope does.

## R3 — the starred pager advertises a page the clamp can never reach

`web.rs` — `last_page` and the page clamp come from the CACHED total; `total` is
then inflated by the uncached PDS rows, and `page_count` / `next_href` are
computed from the inflated number.

250 cached + 80 uncached: `/?view=starred&page=3` renders the last page, reports
"Page 3 of 4", and offers "Older →" to `page=4` — which clamps straight back to
3 and renders the same thing, still offering the link. Reachable whenever
`(cached % 100) + uncached > 100`.

**Fix.** Derive the pager from the same total the clamp uses.

## R4 — `PRAGMA auto_vacuum` and `VACUUM` can land on different connections

`store.rs::migrate_to_incremental_vacuum` issues both against `&SqlitePool`.
`PRAGMA auto_vacuum` on a populated database is connection-scoped INTENT that
only takes effect when the SAME connection runs the VACUUM. Nothing pins them
together.

The `ensure!` afterwards catches the failure, so it is loud rather than silent —
but the operator has then paid a whole-file rebuild for nothing, on a box chosen
for being under disk pressure.

**Fix.** `pool.acquire()` once and run both on that connection.

## R5 — `reclaim()` hands back the batching it just won

`store.rs` — `PRAGMA incremental_vacuum` with **no page argument** reclaims the
entire freelist in ONE transaction, immediately after the retention sweep that
was carefully batched to avoid exactly that. Confirmed: the call site passes no
argument.

**Fix.** `incremental_vacuum(N)` in a loop with the same inter-batch hand-off the
deletes use.

## R6 — every delete batch re-scans `entry_state`

The operator ran `EXPLAIN QUERY PLAN` on the statement `delete_in_batches`
builds: the soft-delete's inner subquery does `SCAN entries` (the `COALESCE` is
non-sargable against `idx_entries_feed_published`) plus `SCAN entry_state` (the
`starred = 1 OR read = 0` matches no index). Every batch pays both.

Steady state is a few thousand rows and fine. The sweep that matters — first run
after this ships, or the first ceiling pass on a legacy database — is ~10⁵ rows
and hundreds of batches, each carrying a full `entry_state` scan.

**Fix.** Measure first. Then either an index that serves the predicate, or hoist
the spare-set into a temp table computed once per sweep rather than per batch.

## R7 — `/stats` says "Fetching: running" on an instance where nothing polls

`web.rs` — `polling_paused` is the only input to that row. With
`FEATHERREADER_DISABLE_SCHEDULER`, or before the poller's now-delayed first tick,
the atomic is `false`, so the page the commit added for this exact question
reports healthy. `/health` distinguishes these; `/stats` does not.

**Fix.** Give the row the same three-way reading `/health` has.

## R8 — `HEALTH_TICK_STALE_SECS` is hardcoded against a configurable tick

15 minutes, not derived from `FEATHERREADER_POLL_TICK_SECS`. An operator who
raises the tick above 900 s gets a permanent `poller: stale` in the body the
deployment docs now tell them to alert on.

**Fix.** Derive it from the configured tick with a floor.

## R9 — the migration reports roughly double the real size

`db_size_bytes` now adds the WAL, and a `VACUUM` in WAL mode writes the whole
rebuilt database through the WAL, which keeps that high-water size until a
truncating checkpoint. Measured by the reviewer: before `db=43,233,280 wal=0`;
immediately after `db=43,286,528 wal=43,540,192`. So `--migrate-auto-vacuum`
logs "bytes_after ≈ 2× bytes_before" — reads as "the migration doubled my
database", and it is the only feedback the command gives.

**Fix.** Checkpoint before measuring.

## R10 — the headroom check measures the wrong filesystem

`VACUUM` copies into a temporary database whose location follows
`temp_store` / `SQLITE_TMPDIR`. Confirmed: neither is set anywhere in `src/`,
`Dockerfile` or `deploy/`. So the temp copy lands on the container rootfs, while
`available_disk_bytes` statvfs's `/data`. The check can pass and the VACUUM still
fail — or fill the rootfs out from under Caddy.

**Fix.** Point SQLite's temp storage at the data volume for the migration, so the
space checked is the space used.

## R11 — `bytes_before` will not match what the operator sees

It is freelist-subtracted, and the population this targets is exactly
`auto_vacuum=NONE` with a large freelist — so the on-disk file is materially
bigger than the number in the refusal message. An operator comparing it to
`ls -l` will not trust it.

**Fix.** Report the file size alongside the live size in the refusal.

## R12 — `--migrate-auto-vacuum` is matched against all of `argv`

Including `argv[0]`, with no positional parsing and no `--` handling. Not
remotely reachable, so not a security defect. The operational hazard is real
though: if the flag ever reaches the container `CMD`, the process migrates and
returns, the entrypoint tears the machine down on child exit, Fly restarts — a
full VACUUM per restart.

**Fix.** Parse it as an argument, not a substring of the command line.

## R13 — the adoption probe ignores the startup-delay override

Its ticker is built raw, so `FEATHERREADER_STARTUP_DELAY_SECS=0` still waits five
minutes — contradicting the constant's own doc ("scales all of them") and a test
that asserts over a set including `ADOPTION_STARTUP_DELAY`.

**Fix.** Route it through `startup_delay` like its siblings.

## R14 — the one new operator knob is documented nowhere operators look

`FEATHERREADER_STARTUP_DELAY_SECS` appears only in `scheduler.rs`. Not in
`README.md`, not in `fly.toml`, not in `deploy/`. It is also a CEILING, which is
a good design and a surprising one: setting it to 300 changes nothing and says
nothing.

**Fix.** Document it, and log when the override is clamped.

## R15 — the unbounded `IN` list, and a doc comment that licensed it

`scoped_feed_ids` emits one placeholder per subscribed feed with no cap. The
count comes from the PDS, bounded only by `MAX_LIST_PAGES` (200) × 100 =
**20,000 records**. `max_subs_per_did` (500) is enforced on the ADD and OPML
paths only, never on read.

Confirmed: `subscribed_feed_ids`'s doc says "Bounded by the per-DID subscription
cap, so callers can safely iterate it" — which is **false**, and is the premise
that licensed the unbounded `IN` list. The comment predates this work; the
dependency on it does not.

**Fix.** Bound the resolved subscription set on the READ path, and correct the
doc. This is the same structural lesson as everything else in this round: a claim
in a comment is not a bound.

## R16 — the starred view's uncached rows bypass paging entirely

`uncached` is built from `list_saved_sorted` (same 20,000 bound) and appended
whole on the last page. `ENTRIES_PER_PAGE` does not bound that response.

**Fix.** Page them, or bound them explicitly and say so.

## R17 — the premise the whole `/health` design rests on is unverified

`fly.toml`, the handler doc and the backlog all assert "Fly restarts the machine
on a failed check". On Fly Machines, `[[http_service.checks]]` failures govern
proxy routing and deploy gating; restarts come from the restart policy on process
exit. There is no `[[restart]]` block.

If the assertion is wrong, the consequence inverts: with `min_machines_running =
1`, a 503 pulls the ONLY machine from rotation and nothing brings it back. The
design choice "only the database may fail the check" was made to avoid
restart-thrash; if there is no restart, it should arguably fail on more.

**This is a question for the operator, not a code change.** Flagged, not fixed.

## R18 — a `set_var` data race in the test binary

`the_startup_delay_override_is_a_ceiling` is the only `std::env::set_var` in
`src/`, in a 650-test multithreaded binary where ~39 sites call `std::env::var`.
Latent today because nothing else reads that key; a flaky crash the moment
another env-reading test lands.

**Fix.** Make the override injectable so the test needs no environment.

## R19 — the batch backstop warns on a sweep that finished

`batch + 1 == PRUNE_MAX_BATCHES` is the correct off-by-one, but the warn is
unconditional on the final iteration: if that batch drains the last rows, it
still logs "the rest waits for the next run" when nothing is left.

**Fix.** Warn only if the following batch would have had work.

## R20 — the entrypoint logs an error string on every normal deploy

On SIGTERM `wait -n` returns 143 and the script logs "a supervised process exited
(status 143); shutting down container". Anyone alerting on that string pages on
every deploy.

**Fix.** Distinguish a signal-initiated exit from a crash in the log line.

---

## Not defects

- **The `safe_link` ordering (T4.2).** The finding said an unusable saved-record
  URL triggered an outbound poll nudge on every render. It did not: the nudge
  keys on `feed_url`, not the rejected `item.url`, and is gated on the reader
  subscribing to that feed. The reorder was still made, as ordering hygiene.
- **The lease vs. `upsert_feed` (regression item 7).** Checked in detail and
  clean: `poll_feed` reads the in-memory `&Feed` captured before the lease,
  `upsert_feed` COALESCEs every field the lease omits, and `mark_feed_due` gates
  on `last_polled`, which the lease does not touch.

## Adjacent, out of range

`upsert_feed`'s `etag = COALESCE(excluded.etag, feeds.etag)` means a success path
can never CLEAR a validator: an origin that once sent an `ETag` and stops keeps
receiving `If-None-Match` forever. Same for restoring `next_poll` to NULL through
the upsert. Predates this work, and the lease's correctness argument leans on the
first one — so it is written down here rather than left implicit.

---

## The loop

Fix in batches, then review the batch COLD — a reviewer that has not seen the
fix, given the diff and told to assume the previous pass introduced something.
Repeat until a pass comes back with nothing. Round 1 justified this: it closed
twelve findings and introduced three, one of which was silent data loss.

Ordering within a round is by what a wrong fix would cost, not by severity of the
original finding — the destructive-path items (R1, R2, R3) go first because
that is where a mistake deletes a reader's data.
