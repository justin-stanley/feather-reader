# FeatherReader 0.4.0 — plan

> **The goal is open registration.** Everything here either removes a thing
> standing in the way of that, or is deliberately deferred until it does.

0.3.0 made the Rust OAuth client selectable. 0.4.0 is about making it the only
one, and then spending what that frees on the constraint that actually caps user
count.

---

## The constraint, measured

From the 0.3.0 capacity work, against the live `fly.toml` (`shared-cpu-1x`,
512 MB, 1 GB volume, 768 MiB watermark):

| resource | measured | binds? |
|---|---|---|
| memory | Rust 15–20 MB, Caddy ~30 MB, **Node 134–172 MB** | no — ~450 MB spare |
| poller | 50 feeds/tick ÷ 60 s = **3,000 feeds/hour** | **yes** |
| disk | 11,878 bytes/entry measured; 768 MiB budget | not since retention went to 14 days |

Two conclusions that shape this release:

1. **Memory was never the limit.** Dropping Node frees a third of the box, but
   that alone does not admit one extra reader.
2. **The poller is the limit**, and the freed memory is exactly what buys more
   of it. That is the whole causal chain of this release: remove Node → spend
   the memory on poller throughput → raise the cap.

Estimated ceiling today: **~90–140 readers**, which is roughly where
`beta_cap = 100` already sits.

---

## Sequence

Ordered by dependency, not by appeal. Each step's evidence comes from the one
before it.

### 1. Ship 0.3.0 and soak on the Rust backend

Nothing below is safe to reason about while the sidecar is still serving.

- merge, tag `v0.3.0`, deploy with `FEATHERREADER_REPO_BACKEND=sidecar`
- flip to `rust`, confirm `/admin/metrics` shows the Rust rows and no error column
- **soak until a token has refreshed in production** — refresh is proven against
  a live PDS but never in the deployed container

Exit: a week on the Rust backend with no revocation or refresh failures.

### 2. Measure, before changing anything

`/stats` exists and has never run against real data. The numbers that decide
step 4 are the ones it reports.

- record distinct feed count and the overdue backlog daily
- add DB size and entry count to `/stats` so the disk side is measured rather
  than modelled
- add poll **lag** — how far past `next_poll` the backlog is running — which is
  the number that says whether the poller is keeping up, and is not yet recorded

Exit: a week of real numbers. If the backlog sits near zero, there is headroom
and step 4 is mostly a config change.

### 3. Decommission the sidecar

Deferred from 0.3.0 deliberately: while it exists, rollback is a config flip;
once deleted it is a revert. Only after step 1 has soaked.

- delete `oauth-sidecar/` (1,552 lines of TS), `SidecarClient` from `atproto.rs`,
  the npm steps in `scripts/ci.sh` and `ci.yml`, the dependabot npm group
- collapse the two Caddy OAuth routings back to one; `/oauth/callback` no longer
  needs a deploy-time choice, which removes the one caveat on the 0.3.0 switch
- drop the Node stage from the `Dockerfile` and the runtime base can stop being
  `node:24-bookworm-slim`
- README, SECURITY, NETWORK-SPEC, `teardown.md`, and the runtime diagram — which
  should go back to one topology
- `FEATHERREADER_REPO_BACKEND` becomes vestigial; either remove it or keep it
  refusing `sidecar` with a message pointing at 0.3.x

**Also in scope:** the SSRF asymmetry this removes. The sidecar only guarded
handle resolution (`safeFetchWrap` inside `handle-resolver-node`); its `did:web`
document fetch, discovery, PAR, token, and repo calls all used bare
`globalThis.fetch`. Removing it closes that gap rather than merely tidying up.

### 4. Raise poller throughput, then open registration

Only meaningful with step 2's numbers in hand.

- raise `FEATHERREADER_POLL_BATCH` / `_CONCURRENCY` into the memory Node freed,
  and measure the backlog again rather than assuming it helped
- grow the volume (1 GB → 3 GB is a few dollars and `fly volumes extend`) —
  cheaper than any code change here and the single biggest lever on disk
- consider adaptive cadence: a feed that has not changed in a month does not
  need hourly polling, and conditional GET already makes the check cheap
- **then** remove the beta gate, or raise `beta_cap` in steps and watch

Exit: backlog stays near zero at the new cap.

---

## Parallel exploration: standard.site

Not on the critical path. Evaluated during 0.3.0 (see the Bluesky thread with
@sammyshear.com) and parked here on purpose.

**Why it is interesting:** the `site.standard.*` lexicons map almost one-to-one
onto the existing model — `publication` ≈ feed, `document` ≈ entry,
`graph.subscription` ≈ `community.lexicon.rss.subscription`. A `document` carries
the article (`title`, `publishedAt`, `textContent`, a `content` union), not a
link to it.

**Why it matters for this release in particular:** documents live in PDSes, so
they are read with `listRecords` or consumed from jetstream — they cost
**nothing against the 3,000-feeds-per-hour poller budget**. A reader that mixes
RSS and standard.site scales very differently on the standard.site half. That is
a direct answer to the constraint this whole release is about.

**The open question, which blocks any estimate:** the docs do not say how a
reader enumerates documents for a publication. If it is "list records from the
author's repo", it is straightforward and reuses the identity resolution and
`xrpc` layers already built (with an unauthenticated read path added). If it
depends on an aggregator that does not exist yet, then the honest answer to
"does something exist to aggregate these?" is no, and this becomes building the
aggregator.

**First step if picked up:** answer the discovery question, then render
`textContent` only. That is a working reader for standard.site publications
without touching the `content` open union, which is per-platform and would
otherwise mean a renderer per producer.

---

## Carried over from 0.3.0

Small, known, and none of them blocking:

- `valid_session`'s refresh lock is still untested — the last surviving mutation
  from the hunt. Proving serialisation needs two concurrent refreshes against a
  controllable token endpoint; the injection pattern used for `discover_with`
  would work.
- production `private_key_jwt` has never run: all live testing used the
  localhost dev client, which is a public client and signs no assertions.
- revocation has never been exercised against a live PDS.
- the full container has never been started; Caddy routing was proven against
  fake upstreams.

The first is a test gap. The other three are things only a deploy can settle,
which is why step 1 leads.
