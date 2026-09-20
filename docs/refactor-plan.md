# Refactor plan — handoff

**Status:** proposal, not yet approved. Nothing here is started.
**Audience:** whoever picks up the operational side of the cutover.
**Basis:** measurement of the tree at `5fd0cd1` (2026-09-20). Every number below
was measured, not estimated; the commands are given so you can re-run them.

---

## TL;DR

The obvious refactor — "`web.rs` is 10,000 lines, split it" — is **not** the one
worth doing, and the measurements say why.

The debt that matters is that the repository ships **two complete
implementations of the same capability**: the Node OAuth sidecar and the
Rust-native client. Production flipped to Rust on 2026-09-13 (#110, "config, not
code"). The code still defaults to the sidecar, still builds it, still tests it
in CI, and still carries a macro whose only job is to fork between them.

The stated exit criterion was *"a week with no refresh or revocation failures."*
That week elapsed on 2026-09-20. **Reading that number is Phase 0 and it gates
everything else.** It is the one task in this document that needs production
access, which is why this is a handoff rather than a PR.

---

## Phase 0 — read the gate (blocking; needs production access)

### Where

`GET /admin/metrics` on the live deployment.

Gated on a live session cookie whose DID is in `config.admin_seed_dids()`
(`ALLOWED_DIDS`). Not public, deliberately — `src/web.rs:4221` explains that the
table "names every operation the reader performs and how often each fails, which
is an operational picture rather than public information." There is no token or
header that bypasses it; you need an admin sign-in.

### What you get

Plain text, one row per `(backend, operation)`:

```
live backend: rust
parked read-state DIDs: N

backend  operation                      ok   p50ms   p95ms    err  errp50ms
rust     oauth_refresh                 ...     ...     ...      0         -
rust     oauth_revoke                  ...     ...     ...      0         -
```

The six instrumented operations are `add_saved`, `add_subscription`,
`add_subscriptions_bulk`, `update_subscription` (via the `dispatch!` macro in
`src/repo.rs`), plus `oauth_refresh` (`src/repo.rs:122`) and `oauth_revoke`
(`src/web.rs:3889`).

### How to read it — one subtlety that matters

The `ok` and `err` columns come from `repo_timing_total`, which is **all-time and
pruning-proof**. The percentile columns come from `repo_timing`, which is capped
at `WINDOW = 1024` samples per `(backend, op, ok)`. See
`metrics::persisted_rows` (`src/metrics.rs:301`) and the comment in
`metrics::flush` — the totals are kept in a separate table specifically so the
window's pruning cannot lose them.

Consequence for the gate:

- **`err == 0` for `rust` / `oauth_refresh` and `rust` / `oauth_revoke` → the
  gate passes outright.** All-time zero means zero this week too. No second
  reading needed.
- **`err > 0` does not by itself fail the gate.** The count is cumulative since
  the table came into existence, so it may be entirely from the first hours
  after the flip. To resolve: record the value now, read again in a few days,
  and judge on the delta. A flat delta over a quiet week is a pass.

A `-` in a latency column means no data, not zero — `render_micros` uses a dash
deliberately, because "a zero reads as the fastest row in the table."

### Decision

| reading | action |
|---|---|
| both `err` counts zero | proceed to Phase 1 |
| non-zero, delta flat over several days | proceed to Phase 1 |
| delta moving | **stop.** The dual path is doing its job. Nothing below starts. |

---

## Phase 1 — delete the losing backend (~10,600 lines)

Only after Phase 0 passes.

| to remove | size |
|---|---|
| `oauth-sidecar/` (13 TypeScript files) | 2,734 lines |
| `src/atproto.rs` — the sidecar client | 1,802 prod lines |
| the `dispatch!` macro fork, `src/repo.rs:192` | — |
| `metrics::Backend` and the dual-backend timing | — |
| the "OAuth sidecar" CI job, `.github/workflows/ci.yml:136` | a whole job |
| `SIDECAR_*` config surface and the Caddy routing branch | — |

Sequencing, which matters:

1. **Flip `repo_backend`'s default from `sidecar` to `rust`** as its own commit.
   `src/config.rs:151` currently defaults to the sidecar. One revertible step.
2. **Then** the deletions, in a PR containing nothing else, so the diff reads as
   "removed, unchanged" rather than mixing removal with edits.

Two things to know going in:

- `config.rs:35` documents that an unrecognised `FEATHERREADER_REPO_BACKEND`
  **fails startup** rather than defaulting, "since a silent fallback would make
  every side-by-side measurement a comparison of the sidecar with itself." When
  the sidecar goes, decide whether the variable stays as a no-op or is removed —
  and if removed, the container entrypoint reads it too, so the two must agree.
- This closes a security residual by subtraction. `src/repo.rs:199-206` records
  that `Repo` is "the vetted path, not the only possible path", because
  `AppState.sidecar` is a `pub` field exposing its own `add_subscription`.
  Deleting the sidecar client deletes that bypass. (#140 closed the typed half;
  this closes the rest.)

---

## Phase 2 — `store.rs`'s undivided head

`store.rs` is 3,770 production lines. The last ~1,100 carry section banners; the
**first 2,665 do not**, and hold 31 public functions with no internal
structure. This is the one place in the repository where size and
disorganisation actually coincide.

Split by table, following the banner convention the file already uses in its
own later sections: feeds, entries, `sub_ref`, `entry_state`, read-cursor.

Low risk: these are query functions. Unlike `web.rs` (below) there are no
private-field invariants to lose.

---

## Phase 3 — extract infrastructure from `web.rs`, narrowly

Three sections of `web.rs` are not HTTP concerns and are close to decoupled:

| section | lines | coupling |
|---|---|---|
| Signed session cookie (HMAC-SHA256), L5046 | 384 | **zero** — grepped for `state`, `AppState`, `Config`, `store::`, `crate::`, `self.`: no hits. Pure crypto. |
| Per-IP rate limiting (token bucket), L322 | 268 | self-contained |
| Signed short-lived invite cookie, L4654 | 57 | reuses the session HMAC |

~709 lines out. For these the encapsulation argument runs *in favour*: putting
the cookie-signing key behind a module boundary is the `safe_link.rs` argument
applied to a secret.

---

## Phase 4 — explicitly NOT recommended: splitting the `web.rs` handlers

Recorded here so it is not re-proposed as an obvious win.

`web.rs` is 5,540 production lines across **19 sections the author already drew
by hand**. That is organisation, not sprawl. And two arguments run against
splitting it:

**The usual justification is absent.** Measured on this tree:

```
cargo check --locked --all-targets   # 7s incremental
cargo test  --locked --quiet         # 14s warm, 746 lib + 16 bin
```

There is no build- or feedback-latency problem to solve.

**Splitting would weaken a guarantee that took three PRs to land.** `SafeLink`
and the `Vetted*` types live in their own modules *precisely because a private
field is private to the module* — stated in the doc comments of both
`src/safe_link.rs` and `src/vetted.rs`, and established only after two
independent reviews falsified the first attempt (#111), then again at #140/#142.
Splitting `web.rs` into submodules converts a large number of currently-`private`
items into `pub(crate)` ones, because handlers and their helpers would no longer
share a module. That is a net **loss** of encapsulation applied to the exact file
whose encapsulation was hard-won.

Revisit only if incremental check crosses ~30s.

---

## Health baseline (so a later reader can tell what changed)

Measured at `5fd0cd1`:

| | |
|---|---|
| `src/` | 48,128 lines — 24,949 production, 23,179 test (ratio 0.93) |
| `web.rs` | 9,997 total / 5,540 prod, 19 sections |
| `store.rs` | 8,523 total / 3,770 prod, 3 sections |
| `oauth/` | 6,124 prod across 20 files |
| lints | clean under `cargo clippy --all-targets --locked -- -D warnings` |
| pedantic + nursery | ~95% cosmetic (230 missing `# Errors` docs, 136 backticks, 74 literal separators) |
| dependencies | 28 direct, 369 resolved |
| `AppState` | 8 fields, each documented |

This is a well-maintained codebase. The refactor case rests on *duplication of a
subsystem*, not on decay.

---

## Scope limits of this analysis

- **Structure was measured; behaviour was not.** Nobody has verified that the
  Rust OAuth client is functionally complete against the sidecar. The soak
  metrics are the evidence for that, and Phase 0 is where it gets checked.
- The pedantic-lint sweep found ~30 numeric-cast warnings (`i64`→`usize`,
  `u64`→`i64`, `u128`→`u64`) that were not individually reviewed. They are
  nursery-level and mostly in metrics and store contexts, but "not reviewed" is
  not "benign".
- PR #152 touches `web.rs`. Land or close it before Phase 3 to avoid conflicting
  against a file being restructured.
