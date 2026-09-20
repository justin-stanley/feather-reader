# Sustaining plan — fast, organized, resilient

**Status:** proposal, not yet approved. Nothing here is started.
**Audience:** whoever picks up the operational side of the cutover.
**Basis:** the tree at `5fd0cd1`; production read live 2026-09-20. Every figure
below was produced by running the stated command at that commit, not recalled.

> **This replaces the four-phase refactor plan this PR opened with.** That draft
> agreed with this one on code structure and got three things wrong: it aimed
> every phase at the healthiest part of the system, its central gate instruction
> reproduced a blind spot the code already documents, and one of its
> justifications had been obsolete since before its own base commit. What changed
> and why is recorded in **Appendix — what the first draft got wrong**, so the
> corrections are reviewable rather than silent.

---

## Where the risk actually is

| property | state | evidence |
|---|---|---|
| **fast** | healthy | 2.3 s incremental `cargo check --all-targets` after touching `web.rs`; 11.8 s warm `cargo test` (745 lib + 16 bin); slowest CI job 61 s |
| **organized** | one real defect | `store.rs`'s first 2,665 lines are undivided and hold 31 public functions. `web.rs` is 9,839 lines across 19 hand-drawn sections — organization, not sprawl |
| **resilient** | **the exposure** | prod ran v0.3.4 from 2026-09-13 while the repo sat at v0.3.6 with three further commits unreleased |

The first draft aimed all four of its phases at code structure. Code structure is
the healthiest of the three properties. The delivery path is where the unmanaged
risk sits, and it got no phase at all.

Four resilience defects, each observed rather than hypothesised:

1. **Release drift.** v0.3.5 and v0.3.6 were tagged and imaged, never deployed.
   *(Closed 2026-09-20 — see S0.)*
2. **The rollback table is hand-maintained** in a wiki page, and was two releases
   stale until corrected on 2026-09-20.
3. **The riskiest documented deploy step re-derives what the build already had.**
   `release-image.yml` computes `steps.build.outputs.digest` and prints it; the
   runbook's step 5c has a human re-resolve that same digest through the GHCR
   token API — a procedure whose earlier form silently returned empty and
   produced a malformed deploy argument on the v0.3.0 deploy.
4. **The cutover gate is read once, by hand, by a procedure that omitted a row
   the code itself warns about.**

---

## Part 1 — sequence

### S0. Close the drift before deleting anything — ✅ DONE 2026-09-20

Deploy v0.3.6 and let production come current.

Going straight to deleting ~10,600 lines while prod is two releases behind puts
the accumulated releases *and* the removal of the fallback into one deploy — on
one machine, with no on-call, where a failed health check hangs the edge ~40 s
per request before it 503s.

**Deploying first does not cost the gate.** Verified before deploying:

- `ok`/`err` live in `repo_timing_total` in SQLite on the `/data` volume, which
  survives a deploy.
- Both gated paths are unchanged v0.3.4 → v0.3.6: `src/oauth/session.rs`
  (refresh) untouched, `revoke_everywhere` byte-identical.

Also verified beforehand: no schema migrations in the range, and `fly.toml`
unchanged since v0.3.4, so nothing rode along with the image.

Shipping v0.3.6 was independently worth it. It carries **#132** — ambient proxy
config silently disabling the SSRF guard — and **rustls bumped for
RUSTSEC-2026-0285**, both of which prod was running without. It also carries
#122 and #135, which put the live login path behind an injectable seam and added
tests for five decisions the code comment describes as previously unfalsifiable,
each a silent production failure rather than a loud one: `client_id`,
`code_challenge`, the assertion's audience, `browser_binding_hash`, and
`dpop_key_jwk`.

Outcome: `/health` → `ok featherreader/0.3.6`, `db: ok`, `backend: rust`, clean
boot logs, origin lock re-verified (direct `*.fly.dev` → 403, `/health` → 200 by
the documented exemption). Existing sessions survived — a refresh succeeded on a
pre-deploy session minutes later — confirming the deploy logged nobody out.

One rollback nuance the later deletion introduces: image-digest rollback keeps
working after the sidecar leaves the tree, because older images still contain
it — but rolling back to a sidecar image logs every user out a second time,
against a token store that has gone stale meanwhile. The practical rollback
window closes at deletion regardless of what the code looks like.

Remaining: cut v0.3.7 for the three post-tag commits, at leisure.

### S1. Read the gate — corrected procedure

Two corrections to the first draft's procedure, both load-bearing:

- **Read the `sidecar` row, not only `rust`.** `web.rs:3858-3866` records that a
  review already caught this: recording only the rust arm let `oauth_revoke`
  "report a clean success while every sidecar revocation failed", because for
  anyone who logged in before the cutover the sidecar store is the only one that
  held tokens — so the rust arm returns `NoSession` and the metric reads
  all-clear. Prod carries the corrected metric (landed #113, first released in
  v0.3.3).
- **Require `ok > 0`, not only `err == 0`.** The first draft's table said "both
  `err` counts zero → proceed". A missing row presents as zero.

**First reading, 2026-09-20 — the gate does NOT pass:**

| row | reading |
|---|---|
| `rust` / `oauth_refresh` | **8 ok, 1 err** — err p50 **6444 ms** against a 1020 ms success p50 and 1429 ms p95 |
| `rust` / `oauth_revoke` | **absent entirely** on the first read |

The revoke row being *absent* is exactly the failure the `ok > 0` correction
exists to catch: revocation had never executed in production, and the first
draft's table would have passed the gate on it. A deliberate sign-out then
produced `rust` / `oauth_revoke` = **1 ok, 0 err** at 798 ms, and
`sidecar` / `oauth_revoke` = **0 ok, 1 err at 0.2 ms** — the `web.rs:3858`
scenario inverted, expected for a post-cutover session, and the reason both arms
must be read.

The 6444 ms refresh error is a **timeout shape, not a rejection shape** — an
`invalid_grant` returns fast. `session.rs:160` notes that `oauth_refresh`
deliberately spans discovery as well as the refresh, naming "an unreachable PDS"
as one of the two likeliest failures. Consistent with a reachability blip; not
established.

**Verdict: refresh leg open.** Record 8/1 as the baseline; re-read in a few days.
`err` flat while `ok` climbs = blip, pass. `err` tracking `ok` = stop.

> **The criterion itself needs restating.** 8 refreshes and 1 revocation over six
> days is thin. "A week with no failures" assumes enough traffic for
> absence-of-failure to mean something, and at beta volume it does not — the gate
> can be satisfied by nothing happening. Specify it as a **count**: *N*
> successful rust refreshes and *M* successful rust revocations with no
> unexplained errors. Otherwise it measures how quiet the beta is, not whether
> the client works.

### S2. Delete the duplicate backend (~10,600 lines)

Only after S1 passes. Flip `repo_backend`'s default as its own revertible commit,
then the deletions in a PR containing nothing else.

| to remove | size |
|---|---|
| `oauth-sidecar/` (13 TypeScript files) | 2,734 lines |
| `src/atproto.rs` — the sidecar client | 1,802 prod lines |
| the `dispatch!` fork, `src/repo.rs:192` | — |
| `metrics::Backend` and the dual-backend timing | — |
| the "OAuth sidecar" CI job | a whole job |
| `SIDECAR_*` config surface and the Caddy routing branch | — |

`config.rs:35` documents that an unrecognised `FEATHERREADER_REPO_BACKEND` fails
startup rather than defaulting. When the sidecar goes, decide whether the
variable stays as a no-op or is removed — the container entrypoint reads it too,
so the two must agree.

**The security rationale from the first draft is dropped.** It justified this
partly as closing the `AppState.sidecar` bypass. #150 already closed it, and #150
is in this branch's own base commit: the low-level writers take
`&vetted::VettedSubscription` / `&vetted::VettedSaved`, whose inner fields are
private to `src/vetted.rs` with vetting constructors. The field is still `pub`;
the unvetted write no longer type-checks. The duplication is the whole case and
it is enough. *(The stale comment that claim rested on is fixed in #154.)*

Note also that deleting the sidecar removes the *other* column of the
side-by-side latency comparison now published in the README. Capture any
measurement worth keeping before it goes.

### S3. `store.rs`'s undivided head

Split by table, following the banner convention the file already uses in its own
later sections: feeds, entries, `sub_ref`, `entry_state`, read-cursor. Low risk —
query functions, no private-field invariants to lose.

### S4. Extract infrastructure from `web.rs`, narrowly

| section | lines | coupling |
|---|---|---|
| Signed session cookie (HMAC-SHA256) | 384 | **zero** — verified independently at `5fd0cd1`: no `AppState`, `state`, `Config`, `store::`, `crate::` or `self.` in its code lines |
| Per-IP rate limiting (token bucket) | 268 | self-contained |
| Signed short-lived invite cookie | 57 | reuses the session HMAC |

~709 lines out. Here encapsulation runs *in favour*: a signing key behind a
module boundary is the `safe_link.rs` argument applied to a secret.

PR #152 touches `web.rs` — land or close it first.

### Not doing: splitting the `web.rs` handlers

`web.rs` is 5,540 production lines across 19 sections the author already drew by
hand. That is organisation, not sprawl, and the usual justification is absent:

```
cargo check --locked --all-targets   # 2.3s incremental after touching web.rs
cargo test  --locked --quiet         # 11.8s warm, 745 lib + 16 bin
```

Splitting would convert a large number of currently-`private` items into
`pub(crate)`, because handlers and their helpers would stop sharing a module.

**One correction to how the first draft argued this.** It claimed splitting would
weaken the `SafeLink` / `Vetted` guarantee. It would not — those guarantees live
in `safe_link.rs` and `vetted.rs` and hold however `web.rs` is arranged. What
splitting exposes is `web.rs`'s *own* private helpers. The conclusion stands on
the build numbers and that real `pub(crate)` cost; the reason needed restating.

Revisit only if incremental check crosses ~30 s.

---

## Part 2 — the standing regime

The first draft was a demolition plan: it ended when its phases ended. *Keeping*
the three properties needs mechanism. Each item closes a failure observed above.

**1. `scripts/baseline.sh` — measurement with provenance.**
Emit the health table stamped with `git rev-parse HEAD`. The first draft's
baseline was labelled "measured at `5fd0cd1`" but its `src/` total (48,128) and
`web.rs` (9,997) are PR #152's tree; `5fd0cd1` is 47,950 and 9,839. A script that
prints its own commit makes that class of error impossible. Run it in CI on
`main`.

**2. Tripwires that actually trip.**
"Revisit if incremental check crosses ~30 s" is a threshold nothing measures.
Three cheap assertions in `scripts/ci.sh`:

- incremental `cargo check --all-targets` > 30 s
- `cargo test` > 60 s
- any single file > 10,000 lines

The third fires on `web.rs` (9,839) within a few PRs. That is the point: it
forces the split-or-don't decision deliberately instead of letting the file drift
past the threshold unnoticed.

**3. Generate the rollback table.**
`release-image.yml` already holds `steps.build.outputs.digest`. Have it emit the
row. This removes the hand-maintained wiki table, the step-5c re-derivation, and
the empty-digest footgun in one change — the highest value-to-size item here.

**4. A drift check.**
Compare `/health`'s reported version against the newest tag; report when they
differ by more than one release. Drift is the condition that made S0 necessary,
and nothing currently notices it.

**5. Move the gate-reading rule next to the metric.**
Have `/admin/metrics` print both backends' rows for the OAuth operations and
carry the caveat inline. The blind spot was documented in `web.rs` and still did
not reach the plan that had to act on it. Output gets read; a comment three
thousand lines away does not.

**6. Validate `deploy/Caddyfile` in CI.**
Nothing does today. A syntax error there crash-loops the container, because the
entrypoint brings the whole box down when any child dies. `caddy validate` at the
pinned version, with a stub for the entrypoint-installed import.

**7. Flag comments citing closed issues.**
18 issue references in `src/`; `#140` was stale until #154. ~15 lines in
`scripts/ci.sh`.

---

## Part 3 — explicitly not doing

- Splitting the `web.rs` handlers (above).
- A second machine or HA. Single-machine with `auto_start_machines` is a
  documented, deliberate trade for a lab service with no on-call.
- The pedantic/nursery lint sweep — ~95% cosmetic. **Except** the ~30 numeric
  casts (`i64`→`usize`, `u64`→`i64`, `u128`→`u64`), which the first draft rightly
  flagged as "not reviewed is not benign". Review once, then silence the lint.

---

## Scope limits

- **Structure was measured; behaviour was not.** Nobody has verified the Rust
  OAuth client is functionally complete against the sidecar. The soak metrics are
  that evidence, and S1 is where it gets checked — currently with a sample of 8
  refreshes and 1 revocation, which is thin.
- The ~30 numeric-cast warnings were not individually reviewed.

---

## Appendix — what the first draft got wrong

Kept so the corrections are reviewable, and so none is re-proposed.

| # | claim | correction |
|---|---|---|
| 1 | Deleting the sidecar "closes a security residual" — `AppState.sidecar` is a `pub` bypass, "Tracked in #140" | #150 closed it, and #150 is in this branch's own base commit. The writers demand the `Vetted*` newtypes; the unvetted write does not type-check. The quoted comment was stale, not the code. |
| 2 | Gate passes when `rust`/`oauth_refresh` and `rust`/`oauth_revoke` both show `err == 0` | Reads only the `rust` arm, which `web.rs:3858` records a review already catching; and a missing row presents as zero. On the real reading `oauth_revoke` was **absent** — the table would have passed on an operation that had never run. |
| 3 | Baseline "measured at `5fd0cd1`" | `src/` 48,128 and `web.rs` 9,997 are PR #152's tree; `5fd0cd1` is 47,950 and 9,839. No conclusion changes, but a baseline exists to be compared against later. |
| 4 | Splitting `web.rs` would weaken `SafeLink` / `Vetted` | It would not — those hold in their own modules. It exposes `web.rs`'s own helpers. Same conclusion, different reason. |
| 5 | "That week elapsed on 2026-09-20" | By machine uptime the v0.3.4 boot was ≈2026-09-13 22:53Z, so the window closed ≈22:53Z that day — stated in the past tense roughly a day early. |
| 6 | Four phases, all aimed at code structure | Code structure was the healthiest of the three properties; the delivery path carried the unmanaged risk and had no phase. Hence S0 and Part 2. |

Build-latency figures in the first draft (7 s check, 14 s tests) were
*conservative* — measured here at 2.3 s and 11.8 s. Its Phase 3 zero-coupling
claim and its `store.rs`, `oauth-sidecar/` and `dispatch!` figures all verified
exactly.
