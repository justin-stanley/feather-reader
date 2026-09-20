# FeatherReader 0.4.0 — plan

> **The goal is still open registration.** What changed is what stands in the
> way of it.

Supersedes the 0.4.0 roadmap drafted during 0.3.0 (on `feat/0.4.0`, never
merged). That draft's causal chain was: remove Node → spend the freed memory on
poller throughput → raise the cap → open up. Three of its premises no longer
hold, and the live instance says the binding constraint is somewhere else
entirely.

**Every number here was read from production or the tree on 2026-09-20.**

> **Revised the same day.** Step 1 was an investigation; it came back with a
> defect (#159 — a `304 Not Modified` read as a malformed redirect), which
> explains most of the failure numbers below and invalidates the capacity
> baseline they were taken against. The original framing is kept rather than
> rewritten, with the finding folded in where it lands, because *what the
> instrument said before the fix* is the part worth not forgetting: the
> dashboard looked healthier the worse the bug got.

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

> **Since drafted: step 1 has been answered, and these numbers are mostly a
> bug.** See below and #159. The table above should be read as the *symptom*,
> not the baseline — in particular the backlog of 0 is not evidence of headroom,
> because most of those 68 feeds were not being polled at all.

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

**What is still open on this step:** *how much* of the 68 is this bug. That
needs the prod DB (`flyctl ssh sftp get /data/featherreader.db`), and `fly ssh`
currently times out from at least one workstation while `fly doctor` passes
WireGuard — so the census has not been done. Four failures in a 100-line log
window, three of them this, is strong but is not a count.

**Exit, revised:** ship #159, then re-read `/stats`. The failing count should
fall sharply. Whatever remains after that *is* the genuine dead-feed population,
and it is measured rather than assumed.

### 1b. Make this class diagnosable, and stop the copy that hid it

Both cheap, both follow directly from the above.

- **`feeds` stores an error count and no error text** (`consecutive_errors`, and
  nothing else). That is why a systematic failure across 60-odd feeds looked
  identical to sixty dead blogs. Storing the last error — and surfacing it —
  would have made this visible from `/stats` alone.
- **Fix the `/stats` copy.** "Usually gone rather than flaky" is an assertion the
  instance had never tested, and it actively discouraged investigation.

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

> **Every capacity number in this document predates #159 and must be re-taken
> after it deploys.** The backlog of 0 was measured while roughly 60 feeds were
> backed off and effectively not being polled. Fixing the 304 returns all of
> them to normal cadence, so **real poll load goes up sharply** the moment it
> ships — this release's first act increases the work the poller does, and the
> honest baseline does not exist yet.
>
> That cuts both ways and is the more interesting half: the draft roadmap's
> "poller is the limit" claim was dismissed above on a backlog of 0 that the bug
> manufactured. It may turn out to be right after all. Re-measure before
> concluding either way.

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

**Exit:** backlog near zero at the new cap **against post-#159 numbers**, and the
residual failure rate from step 1 not regressing as feeds are added.

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
