# Post-cutover plan

Where things stand after 2026-09-13, and what to do next in what order.

**Shipped today:** v0.3.0 → v0.3.2, the `auto_vacuum` migration, the backend
cutover to `rust`, and the origin-secret leak closed and rotated.

**Live now:** v0.3.2, `backend: rust`, `auto_vacuum=INCREMENTAL`, DB 22 MB → 10 MB.
(The 10 MB is measured; the 22 MB pre-value is from memory — the logs have rolled
and the nearest independent record is the wiki's "It is **21 MB**" note.)

> **`#NN` in this document means a task in the internal tracker, NOT a GitHub
> issue or PR.** They collide: GitHub #16–#20 are unrelated merged PRs (canonical
> domain, landing page, container build, the v0.2.0 bump, SIGTERM). `design/
> REVIEW-BACKLOG.md` uses the same convention. GitHub references are written
> `PR #NN` or `issue #NN` throughout.

> **The `href` defence is NOT in the "shipped" list, though an earlier draft said
> it was.** PR #111 merged 43 minutes *after* this document was opened, and is
> **still undeployed** — the machine last updated at the cutover. Issue #115 also
> records it as partial: `entry.html`'s two hrefs are still raw `String`.

---

## 0. The soak is the gating item

Task #16's exit criterion is not "the cutover deployed" — it is **a week on `rust`
with no refresh or revocation failures**. Nothing else in 0.4.0 is safe to reason
about until that passes, because the sidecar is no longer there to fall back to
quietly.

**Baseline, cumulative `rust` counts at 2026-09-13 19:52:26Z** — 90 seconds before
this document was opened, and reconstructible at any time from the timestamped
per-call samples in `repo_timing`:

| backend | op | ok | err |
|---|---|---|---|
| rust | `add_saved` | 1 | 0 |
| rust | `flush_read_states` | 2 | 0 |
| rust | `list_folders_sorted` | 15 | 0 |
| rust | `list_subscriptions_sorted` | 27 | 0 |

`add_saved` succeeding matters more than the count: it is a `createRecord`
(`com.atproto.repo.createRecord`) **write** to a real PDS through the Rust path.
(`putRecord` is the separate method read-state uses.)

### How to check it (no login needed)

`/admin/metrics` is session-gated, so the cheap check is the database:

```bash
for f in "" "-wal"; do
  flyctl ssh sftp get "/data/featherreader.db$f" "./soak.db$f" -a featherreader
done
sqlite3 soak.db "SELECT backend, op, ok_count, err_count FROM repo_timing_total
                 WHERE backend='rust' ORDER BY op;"
rm -f soak.db*
```

**Pull the `-wal` too.** Without it you are reading a stale snapshot and recent
writes are invisible. Measured 2026-09-13, same instant, `.db` alone vs `.db` +
`-wal`: `list_subscriptions_sorted` 34 vs **45**, `entries` 5000 vs **5072**. Copy
the `.db` aside *before* opening it — opening the WAL-mode copy read-write
checkpoints it and destroys the comparison.

**Do not pull `-shm`.** An earlier version of this recipe did. It is unnecessary —
SQLite rebuilds the index — and a stale `-shm` copied from a live writer is a
hazard for no benefit. `.db` + `-wal` gives the identical correct answer.

**Pass:** `err_count` stays 0 across a week, and at least one **refresh** has
happened (the first access token must age out for that path to run at all).

Two properties of `err_count` bound what that claim can mean:

- **It is all-time cumulative, not windowed.** A time-bounded claim needs a
  baseline diff against the table above. That works today only because the `rust`
  rows start at the cutover.
- **It does not separate a client defect from a grant that ended normally.** A user
  revoking access in their PDS settings yields `invalid_grant`, counted identically
  to an unreachable PDS. A strict "zero failures" criterion becomes unsatisfiable
  once that happens even once, so read a non-zero count before concluding from it.

### Known observability gaps

**Both are addressed by PR #113, which was not yet open when this was written.**
Described as they stood on `main` at the cutover:

- **A refresh failure is only visible indirectly** — it surfaces as an error on the
  enclosing repo call, so it lands in `err_count` for whichever op triggered it,
  not as a refresh counter of its own.
- **A revocation failure is not counted at all.** `Revocation::Failed` is consumed
  in exactly one place — `web.rs::revoke_everywhere` — which emits `tracing::warn!`
  and nothing else; `metrics.rs` has no revoke op. (`revoke.rs` itself *returns* the
  outcome; its own two warnings are about discovery failing.) If `/account/delete`
  stops revoking, the only trace is a log line nobody is watching.

---

## 1. Parallel work — safe during the soak

Ordered by value. None of these touch the OAuth path in production.

### 1a. The SSRF enforcement seam *(highest remaining security value)*

`is_forbidden_ip` is well covered; everything that carries its verdict to the
socket is not. Two of four gaps were closed on 2026-09-13 (the `.resolve()` connect
pin and `redirect::Policy::none()`). Three remain, all needing the same change:

- **per-hop re-validation** in `guarded_get_inner` — the marquee SSRF property;
  nothing follows a redirect through the guard today
- **cross-origin credential stripping** — `hop_headers` is tested as a pure
  function; its wiring is not
- **multi-answer DNS** — `resolve_and_check` checks every answer, but nothing
  exercises more than one. Within `net.rs`'s own 35 tests every case passes an IP
  literal, so the `Host::Domain` branch is not entered there; three tests elsewhere
  in the suite do enter it, which is why the narrower framing in an earlier draft
  was wrong. The gap is real either way — see the mutation below.

Each was confirmed by mutation against `main` on 2026-09-13; all three mutations
leave the suite **fully green** (679 passed):

| mutation | result |
|---|---|
| validate only the first hop; resolve redirect targets with a bare `lookup_host` | 679 pass |
| replace `hop_headers` with `extra_headers` — credentials never stripped | 679 pass |
| `resolve_and_check` checks only the first DNS answer | 679 pass |

The reason is visible in the code: `guarded_get_refuses_private_redirect_target`
builds a 302 stub and then discards it (`let _ = addr;`), asserting on a private URL
passed in directly. Nothing drives a redirect through `guarded_get_inner` at all.

All three need an **injectable resolver** in `guarded_get_inner`: a private
function parameter defaulting to `resolve_and_check`, so tests can point at a local
stub. No env var, no feature flag, nothing outside the module can pass a different
resolver — the "no runtime bypass" property is preserved.

Give this the same treatment PR #107 got — verified by running it, not by reading
it — because it modifies the guard. (#107 itself was the Caddy origin lock, not a
change to this guard; it is the precedent for the method, not the subject.)

### 1b. End-to-end login test

`login::complete`'s individual guards are pinned; their **sequencing** is not.
Nothing drives a full login. This is more pressing than it was, because that path
is now live. Depends on the same seam as 1a.

### 1c. The remaining bad tests

Roughly ten confirmed by mutation on 2026-09-13 and not yet fixed. Mechanical;
each has a known failing mutation already identified:

- `the_list_projection_does_not_name_the_body_column` — asserts on a hand-typed
  copy of the projection, not the one `list_entries` runs
- `db_size_is_positive_and_grows` — never measures growth; there is no second
  measurement
- `the_cursor_scrub_reads_the_ids_it_writes` — the stated discriminator does not
  discriminate; the write lands before the scrub starts
- `the_startup_delays_are_distinct` — de-dupes five constants; no call site is
  involved, so pointing all five loops at `POLLER_STARTUP_DELAY` (every scheduler
  firing at the same instant) leaves the suite green
- `stats_distinguishes_backoff_from_a_watermark_pause` — **already fixed**, and
  re-confirmed: forcing `in_backoff`/`badly_broken` to `0` now fails it
- plus the `web.rs` set: the adoption-line pair, the list-view row render, the
  detached health probe, `/stats` privacy, the OPML under-cap case, and the bot
  claim cookie

Three of these are worse than "weak", and the specifics are the fix instructions:

- `db_size_is_positive_and_grows` has a three-line body asserting only `before > 0`.
  `db_size_bytes → 1` passes. The name is a lie.
- `the_health_probe_opens_a_real_table` `EXPLAIN`s a hand-typed
  `"SELECT 1 FROM feeds LIMIT 1"` — never the string `/health` runs. Degrading the
  real probe to `SELECT 1` leaves it green.
- `about_renders_adoption_line_when_enabled` asserts `body.contains("4")`, satisfied
  by the colophon's `width="44"` whatever the count is. Note the mutation is caught
  by `about_adoption_line_is_singular_at_one`, which is *not* on this list — so the
  coverage exists, just not where the name promises.

### 1d. The `at://` feeds

19 of 111 feeds are `at://did:plc:…/site.standard.publication/…` — **never once
polled**, each at exactly 35 consecutive errors, one subscriber each (a single DID
accounts for all 19). `check_scheme` allows `http`/`https` only, so they can never
be fetched. They are not broken feeds; they are a capability the UI accepts and the
poller cannot speak.

They are **19 of the 29** feeds behind the "29 failing, 29 badly" on `/stats` at the
time of writing, not all of them — an earlier draft said they were the cause. The
other 10 are ordinary dead HTTP feeds. The figure also drifts: a later cluster of 30
feeds crossing the 6-error `badly_broken` threshold moved it to "63 failing, 59
badly" the same afternoon. Separately, 26 feeds have never been polled, not 19.

This is task #20 (the standard.site discovery question) surfacing as production
noise. Decide: support `at://` publications, or refuse them at subscribe time so a
reader is not silently subscribed to something that will never deliver.

---

## 2. After the soak passes

**#18 — decommission the Node sidecar.** It has been dead weight in the image since
the cutover — `/app/oauth-sidecar` is **72 MB** on the running machine. Deleting it
removes **~1,735 lines of TS** (2,734 with its tests), the Node build stage, the six
npm CI steps, the dependabot npm group, and one of the two Caddy routings — which
also removes the deploy-time login-routing caveat.

**It also closes a real SSRF gap.** The sidecar guards **nothing** — an earlier draft
said it guarded handle resolution, which overstates it. `buildOAuthClient` passes
`NodeOAuthClient` no `fetch` override at all, so `did:web`, discovery, PAR, token and
repo calls all fall through to the library's default `globalThis.fetch`. Handle
resolution is merely *pointed* at a fixed configured host
(`SIDECAR_HANDLE_RESOLVER`, default `https://bsky.social`) — pinned, not guarded.
That gap existed in production until the cutover and still exists in the image.

**#17 — measure before changing anything**, then **#19 — poller throughput, then
open registration.** In that order; #19's whole premise is that the poller can take
the load, which #17 establishes.

---

## 3. Small, opportunistic

- **`purge_did_data` does not clear `oauth_state`.** It deletes `entry_state`,
  `read_cursor`, `sub_ref`, `beta_access` and `invite_codes` only, and `oauth_state`
  carries a `did` column — so that is genuine per-DID residue. The tokens themselves
  *are* handled: `/account/delete` reaches them through the revoke path, which
  `revoke.rs` documents explicitly. So this is residue, not retained credentials.
  (An earlier draft paired `oauth_nonce` with it. That half is vacuous —
  `oauth_nonce` is keyed by **origin** and has no DID column, so there is nothing
  DID-scoped in it to clear.)
- **One place in the wiki credits `min_machines_running` for machine recovery**
  while `fly.toml` says it is inert under `auto_stop_machines = "off"`: the
  `container-entrypoint.sh` section of `/runbooks/featherreader-deploy` ("exit
  non-zero so Fly recreates the machine (`min_machines_running=1`)"). An earlier
  draft said three places attribute it wrongly — the page mentions the knob three
  times, but the other two are merely descriptive, and the page **already carries
  the correction** under its `fly.toml` excerpt ("inert … documentation of intent,
  not a safety net"). So this is one stale sentence, not a drifted page. Still
  uncorrected because nobody has *measured* what recreates the machine — and
  guessing is how it drifted in the first place.
- **Revoke the one-time Cloudflare Transform Rules token** if not already done, and
  confirm the 2026-07-06 cache-rules token's revocation, which the wiki still
  records as unverified.

---

## Method note

The recurring failure this release surfaced is worth keeping in front of the next
one: **every significant bug found was a claim with no evidence behind it.** A
retention benchmark measured against a fixture that could not distinguish the
hypotheses. Tests asserting that *something* failed rather than that the right
thing caused it. A `caddy validate` that passed while the config leaked a secret.
A fail-closed comment that was false for months, in a file whose trust model
depended on it.

The thing that found them was not reading more carefully. It was running the
mutation and watching what happened.

**This document was then fact-checked the same way, and six of its claims were
wrong** — `putRecord` for `createRecord`, the sidecar's line count, what the sidecar
guards, the `at://` share of the failing feeds, the `href` defence listed as shipped
when it merged 43 minutes later and is still undeployed, and the wiki's
`min_machines_running` attribution. Every one is now corrected above. None was a
typo; each was a plausible thing asserted without checking, written by someone who
had spent the day finding exactly that failure in other people's work.

So: the same standard applies to plans. A claim in a planning document is load-
bearing precisely because nothing downstream re-derives it.
