# Post-cutover plan

Where things stand after 2026-09-13, and what to do next in what order.

**Shipped today:** v0.3.0 → v0.3.2, the `auto_vacuum` migration, the backend
cutover to `rust`, the origin-secret leak closed and rotated, and the `href`
defence made structural.

**Live now:** v0.3.2, `backend: rust`, `auto_vacuum=INCREMENTAL`, DB 22 MB → 10 MB.

---

## 0. The soak is the gating item

Task #16's exit criterion is not "the cutover deployed" — it is **a week on `rust`
with no refresh or revocation failures**. Nothing else in 0.4.0 is safe to reason
about until that passes, because the sidecar is no longer there to fall back to
quietly.

**Baseline, taken 2026-09-13 shortly after the cutover:**

| backend | op | ok | err |
|---|---|---|---|
| rust | `add_saved` | 1 | 0 |
| rust | `flush_read_states` | 2 | 0 |
| rust | `list_folders_sorted` | 15 | 0 |
| rust | `list_subscriptions_sorted` | 27 | 0 |

`add_saved` succeeding matters more than the count: it is a `putRecord` **write**
to a real PDS through the Rust path.

### How to check it (no login needed)

`/admin/metrics` is session-gated, so the cheap check is the database:

```bash
for f in "" "-wal" "-shm"; do
  flyctl ssh sftp get "/data/featherreader.db$f" "./soak.db$f" -a featherreader
done
sqlite3 soak.db "SELECT backend, op, ok_count, err_count FROM repo_timing_total
                 WHERE backend='rust' ORDER BY op;"
rm -f soak.db*
```

**Pull the `-wal` too.** Without it you are reading a stale snapshot and recent
writes are invisible — this produced a false "zero sessions" reading on the day of
the cutover.

**Pass:** `err_count` stays 0 across a week, and at least one **refresh** has
happened (the first access token must age out for that path to run at all).

### Known observability gaps

- **A refresh failure is only visible indirectly** — it surfaces as an error on the
  enclosing repo call, so it lands in `err_count` for whichever op triggered it,
  not as a refresh counter of its own.
- **A revocation failure is not counted at all.** `revoke.rs` emits `tracing::warn!`
  and nothing else. If `/account/delete` stops revoking, the only trace is a log
  line nobody is watching. Worth a small instrumentation PR if the soak is to mean
  what it claims.

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
- **multi-answer DNS** — `resolve_and_check` checks every answer, and every test
  passes an IP literal, so the `Host::Domain` branch is never entered

All three need an **injectable resolver** in `guarded_get_inner`: a private
function parameter defaulting to `resolve_and_check`, so tests can point at a local
stub. No env var, no feature flag, nothing outside the module can pass a different
resolver — the "no runtime bypass" property is preserved.

Treat this like PR #107: it modifies the guard, so it wants an adversarial review
before merge.

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
  involved, so a loop using the wrong constant passes
- `stats_distinguishes_backoff_from_a_watermark_pause` — **already fixed**
- plus the `web.rs` set: the adoption-line pair, the list-view row render, the
  detached health probe, `/stats` privacy, the OPML under-cap case, and the bot
  claim cookie

### 1d. The `at://` feeds

19 of 111 feeds are `at://did:plc:…/site.standard.publication/…` — **never once
polled**, each at 35 consecutive errors, one subscriber. `check_scheme` allows
`http`/`https` only, so they can never be fetched. They are not broken feeds; they
are a capability the UI accepts and the poller cannot speak, and they are why
`/stats` reads "29 failing, 29 badly".

This is task #20 (the standard.site discovery question) surfacing as production
noise. Decide: support `at://` publications, or refuse them at subscribe time so a
reader is not silently subscribed to something that will never deliver.

---

## 2. After the soak passes

**#18 — decommission the Node sidecar.** It has been dead weight in the image since
the cutover. Deleting it removes ~1,550 lines of TS, the Node build stage, the npm
CI steps, the dependabot npm group, and one of the two Caddy routings — which also
removes the deploy-time login-routing caveat.

**It also closes a real SSRF gap.** The sidecar guards only handle resolution; its
`did:web`, discovery, PAR, token and repo calls all use bare `globalThis.fetch`.
That gap existed in production until the cutover and still exists in the image.

**#17 — measure before changing anything**, then **#19 — poller throughput, then
open registration.** In that order; #19's whole premise is that the poller can take
the load, which #17 establishes.

---

## 3. Small, opportunistic

- **`purge_did_data` does not clear `oauth_state` / `oauth_nonce`.** The tokens
  themselves *are* handled — `/account/delete` reaches them through the revoke
  path, which `revoke.rs` documents explicitly — so this is residue, not retained
  credentials. Still worth closing.
- **The wiki credits `min_machines_running` for machine recovery in three places**
  while `fly.toml` says it is inert under `auto_stop_machines = "off"`. With
  `auto_start_machines = true` now the actual recovery path, all three attribute
  the behaviour to the wrong knob. Not corrected yet because nobody has *measured*
  what recreates the machine — and guessing is how the page drifted.
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
