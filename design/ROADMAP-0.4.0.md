# FeatherReader 0.4.0 — plan

> **The goal is still open registration.** What changed is what stands in the
> way of it.

Supersedes the 0.4.0 roadmap drafted during 0.3.0 (on `feat/0.4.0`, never
merged). That draft's causal chain was: remove Node → spend the freed memory on
poller throughput → raise the cap → open up. Three of its premises no longer
hold, and the live instance says the binding constraint is somewhere else
entirely.

**Every number here was read from production or the tree on 2026-09-20.**

> **Revised twice the same day.** Step 1 was an investigation; it came back with
> a defect (#159 — a `304 Not Modified` read as a malformed redirect), which
> explains most of the failure numbers below. That fix **shipped in v0.3.7 and is
> live in production as of 2026-09-20 03:57Z**, and the failure count is now
> falling. The original framing is kept rather than rewritten, because *what the
> instrument said before the fix* is the part worth not forgetting: the dashboard
> looked healthier the worse the bug got.
>
> The second revision also settles a question the first one left open — whether
> the fix reopens the capacity argument. It does not. See step 5.

---

## What changed since that draft

**1. The memory is already free.** The draft treated the sidecar's 134–172 MB as
something the decommission would recover. It was recovered by the 2026-09-13
cutover: on `FEATHERREADER_REPO_BACKEND=rust` the entrypoint never starts the
sidecar, and the machine runs `tini`, `featherreader` and `caddy` — no `node`.
Deleting the code is a simplification, not a capacity unlock. **Poller work is
therefore not blocked on the decommission**, which is the draft's main
sequencing claim and it is no longer true.

**2. The poller is not the binding constraint at this scale.** `/stats`, live:
backlog **0**, most recent poll **15 s ago**. The 3,000-feeds-per-hour ceiling is
real arithmetic but it is nowhere near being tested by 111 feeds and three
readers.

**3. The standard.site blocker is answered.** The draft parked it because "the
docs do not say how a reader enumerates documents for a publication", and said
that question blocked any estimate. `STANDARD-SITE-0.4.0.md` answered it by
measurement: `listRecords site.standard.document`, filtered client-side on
`site`. 449 documents, 17 of 17 publishers reachable, ~3.7 MB, ~35 requests for
a full sweep.

---

## The constraint, re-measured

`/stats` for this instance, 2026-09-20:

| | |
|---|---|
| Feeds tracked | 111 |
| **Waiting to be polled (backlog)** | **0** |
| Polled in the last hour | 43 (38%) |
| **Failing (backing off)** | **68 — 64 badly** |
| Never polled | 26 |
| **Least recent poll** | **never** |

**61% of tracked feeds are failing.** 19 of those are the `at://` rows that
cannot succeed by construction — `check_scheme` allows `http`/`https` only, so
they fail before a request is made. Subtracting them leaves roughly **49 of 92
real HTTP feeds failing — 53%**. (That subtraction is an inference: the 111 and
92 figures agree with `STANDARD-SITE-0.4.0.md`'s count, but nothing here
confirms all 19 land in the 68.)

The stats page's own copy says *"Least recent poll … reads `never` if any feed
has never been fetched, because that is worse than any number."* By the
instrument this project built to answer "is the poller keeping up", the instance
is in its worst reportable state — while the backlog reads zero, because a
failing feed backs off and leaves the backlog looking *better*.

**So the constraint on opening registration is not capacity. It is that the
product does not visibly work for the three readers it already has.** Capacity is
a problem you earn the right to have. Opening registration against a 53% feed
failure rate would multiply the experience, not the value.

> **That table is the PRE-FIX snapshot, and it is already history.** #159 shipped
> in v0.3.7 on 2026-09-20 and the numbers are moving:
>
> | time | failing | badly | polled last hour |
> |---|---|---|---|
> | 03:55Z (pre-deploy) | 67 | 65 | 44 (39%) |
> | 04:23Z | 66 | 65 | 45 (40%) |
> | 04:33Z | 65 | 64 | 46 (41%) |
>
> Read the table above as the *symptom*, not a baseline — in particular its
> backlog of 0 was not evidence of headroom, because most of those feeds were
> not being polled at all.
>
> **Recovery runs on each feed's own clock.** Backoff is
> `min(5m × 2^(n−1), 24h)` (`feed::backoff_for`), `BADLY_BROKEN_ERRORS = 6`, and
> a feed resets to zero on its first *successful* poll. Crucially the windows
> count from each feed's last failure, not from the deploy, so many were already
> part-elapsed — recovery is running ahead of a naive from-deploy estimate. The
> tail is feeds at the 24h cap.
>
> **The floor is not zero — expect ~19 + genuinely-dead feeds.** The 19 `at://`
> rows fail before a request is made (`check_scheme` allows `http`/`https`
> only), so #159 does nothing for them; they need step 3. For the same reason
> **`Least recent poll` stays pinned at `never`** through all of this, which is a
> limit of the indicator rather than of the repair.

---

## Sequence

### 1. Why half the HTTP feeds fail — **answered: a 304 was read as a redirect**

This step asked for a breakdown by cause, and said *"anything systematic … is
the real content of 0.4.0"*. It is systematic.

`guarded_get_inner` gated its redirect branch on `is_redirection()`, which is
`300..=399` and so includes **`304 Not Modified`**. A 304 carries no `Location`
by definition, so every conditional GET that correctly answered "unchanged"
failed with *"redirect response without a usable Location header"* — and
`feed.rs`'s own 304 branch, which is correct, was unreachable. The poller
therefore recorded **"nothing new" as a failure**, bumping `consecutive_errors`
and backing the feed off exponentially. The feeds punished hardest were the ones
implementing conditional GET *properly*.

Found in the production log against **9to5mac.com**, **proton.me** and
**kodi.tv** — all live. Re-running the poller's own conditional GET by hand
returns `HTTP 304` with zero `Location` headers. Fix and regression test in
**#159**; mutating the guard back fails the new test and nothing else, so this
had no coverage at all.

The stats copy asserting that badly-failing feeds are *"usually gone rather than
flaky"* was the hypothesis that stopped anyone looking. It is wrong and should
change.

**Shipped.** #159 is in **v0.3.7**, deployed 2026-09-20 03:57Z. `/health` reports
`ok featherreader/0.3.7`; the log has recorded **zero** further "usable Location
header" errors since, against three in a comparable window before it.

**What is still open on this step:** the residual number. The failing count is
falling (67 → 65 in the first 36 minutes) but the tail runs ~24h, and the
interesting figure is where it *stops*. Subtract the ~19 `at://` rows and what
remains is the genuine dead-feed population — measured rather than assumed, which
is what this step asked for in the first place.

A per-feed census would still be better than an aggregate, and still is not
possible: `fly ssh` times out from at least one workstation while `fly doctor`
passes WireGuard, so `flyctl ssh sftp get /data/featherreader.db` cannot run.
Storing the error text (step 1b) would make the aggregate sufficient and the
census unnecessary.

**Exit, revised:** re-read `/stats` once the count stops falling — call it 24h
after the deploy.

### 1b. Make this class diagnosable, and stop the copy that hid it

Both cheap, both follow directly from the above.

- **`feeds` stores an error count and no error text** (`consecutive_errors`, and
  nothing else). That is why a systematic failure across 60-odd feeds looked
  identical to sixty dead blogs. Storing the last error — and surfacing it —
  would have made this visible from `/stats` alone.
- **Fix the `/stats` copy.** "Usually gone rather than flaky" is an assertion the
  instance had never tested, and it actively discouraged investigation.

*(Related and already done: `deploy/Caddyfile` is now validated in CI against
both OAuth routings, #161 — a `docs/sustaining-plan.md` Part 2 item that this
release's own deploy work made urgent.)*

### 2. Tell the affected reader about the 19 `at://` rows

`STANDARD-SITE-0.4.0.md`'s open question 3. One reader has 19 subscriptions that
have never delivered anything and **nothing in the UI says why**; they sit at 35
consecutive errors each. Either fix them (step 3) or say so in the interface.
Either beats silence, and the say-so is hours of work rather than days.

### 3. standard.site support

Now the best-specified work in the repo — the design is measured, the scope
decided, and the traps already found. Take it as written in
`STANDARD-SITE-0.4.0.md`; the notes that matter for sequencing:

- **Answer open question 1 first**: is an unauthenticated XRPC GET reachable in
  the current code? The pieces look present but the traced path is
  authenticated. It sets the shape of the work.
- `feed::is_storable_feed_url` still rejects everything but `http`/`https`
  (`feed.rs:271`). It must learn `at://` as an **allowlist entry**, not be
  loosened — it exists to keep `javascript:`, `file:` and token-bearing URLs out
  of the shared `feeds` table, and those reasons are unchanged.
- Render `textContent` / `description` only. **Not** `content`: 6 wrappers and 22
  block types across 5 vendor namespaces, growing with every platform that
  adopts the lexicon, and dragging an HTML-sanitisation surface over foreign
  input — the category of bug this codebase has spent the most effort on.
- The measured traps are load-bearing: send a real `User-Agent` (4 of 19
  endpoints 403 without one, intermittently, looking exactly like the host being
  down), terminate paging on an **empty record set** rather than cursor absence,
  and treat a zero-document publication as normal.

It also costs nothing against the poller budget, which is the draft's own reason
for caring — and it turns 19 permanently-broken subscriptions into working ones,
which is step 1's problem seen from the other side.

### 4. Decommission the sidecar

Unchanged in content, but re-justified. It is no longer a capacity unlock; it is
worth doing because the tree carries two implementations of one capability —
~10,600 lines, a whole CI job, a Node base image — and because it closes the SSRF
asymmetry, where the sidecar guarded only handle resolution and used bare
`globalThis.fetch` for `did:web`, discovery, PAR, token and repo calls.

**Still gated on the soak, which has not passed.** `rust`/`oauth_refresh` reads
8 ok / 1 err, the error at 6444 ms against a 1429 ms success p95 — a timeout
shape, not a rejection shape. See `docs/sustaining-plan.md` (#153, not yet
merged) for the corrected gate procedure, and why the criterion should be a
count rather than a week.

After it lands, the README's two-backend comparison and its conditional process
count both collapse to one topology.

### 5. Poller throughput, then open registration

**Unblocked from step 4** — see the memory note above — but deliberately placed
after step 1: raising throughput against a 53% failure rate optimises the wrong
number, and would make the backlog metric look better while nothing improves.

> **Settled by arithmetic, now that #159 has shipped.** The previous revision
> said the fix might reopen the old roadmap's "the poller is the limit" claim,
> because the backlog of 0 had been manufactured by the bug. It does not, and the
> numbers say so without waiting for recovery to finish:
>
> | | |
> |---|---|
> | ceiling | `DEFAULT_POLL_BATCH` 50 per `DEFAULT_POLL_TICK` 60 s = **3,000 feeds/hour** |
> | demand at 100% feed health | 111 feeds on the 1 h default interval = **111 feeds/hour** |
> | utilisation | **3.7%** |
>
> Full recovery roughly doubles real poll load — from ~46 feeds/hour to ~111 —
> and lands at under four percent of the measured ceiling. The poller does not
> bind until roughly **3,000 distinct feeds**, which at this instance's ~37
> feeds per reader is on the order of **80–140 readers**. That is the old
> roadmap's own estimate, and it was right; it simply is not a constraint at
> three readers.
>
> So the knobs below are **not** 0.4.0 work. They are what step 5 does *after*
> the cap is raised, not a precondition for raising it.

- The knobs exist: `FEATHERREADER_POLL_TICK_SECS`, `_POLL_BATCH`,
  `_POLL_CONCURRENCY`, `_POLL_STAGGER_MS` (`scheduler.rs`). Raise, then measure
  the backlog again rather than assuming it helped.
- Grow the volume 1 GB → 3 GB. Cheap, and the largest single disk lever — though
  **disk is not currently pressing**: the DB is ~10 MB after the 2026-09-13
  `auto_vacuum` migration, against a 750 MiB watermark.
- Consider adaptive cadence: a feed unchanged in a month does not need hourly
  polling, and conditional GET already makes the check cheap.
- **Then** raise `FEATHERREADER_BETA_CAP` in steps and watch, rather than
  removing the gate in one move.

**Exit:** backlog near zero at the new cap, and the residual failure rate from
step 1 not regressing as feeds are added. Given the 3.7% figure above, the first
cap raise should need no throughput work at all — if it does, something other
than arithmetic is wrong and that is the finding.

---

## Carried over from 0.3.0 — mostly closed now

The draft listed four items that "only a deploy can settle". Three are settled:

| item | status |
|---|---|
| revocation never exercised against a live PDS | **closed** — `rust`/`oauth_revoke` 1 ok at 798 ms, 2026-09-20 |
| production `private_key_jwt` never run | **closed** — 8 successful refreshes on the rust backend |
| the full container never started | **closed** — in production since 2026-09-13 |
| `valid_session`'s refresh lock untested | **open** — the last surviving mutation from the 0.3.0 hunt |

The remaining one is a test gap, not a deployment unknown. Proving serialisation
needs two concurrent refreshes against a controllable token endpoint; the
injection pattern `start_with` established in #135 is the model.

---

## Not in 0.4.0, on purpose

- Rendering any `content` wrapper (above). Full-text for the two markdown
  wrappers — 79 documents, 18% — is a plausible later refinement.
- `site.standard.graph.subscription`. standard.site has its own subscription
  lexicon; whether to read or write it is a separate question.
- Publishing. FeatherReader reads.
- Splitting `web.rs`, and anything else in Part 1 of `docs/sustaining-plan.md`
  (#153, not yet merged) — that document owns the structural work, this one owns
  the release.
