# Roadmap

> **As of 2026-10-24.** Latest release: **0.5.1** (2026-10-20). Replaces any earlier roadmap notes:
> 0.4.0 was Standard.site support, 0.5.0 was Rust-only, and opening registration was never part of
> either.

Each release ships the way 0.5.x did: an `-rc.N` tag soaks on staging (#294); the upgrade is tested
from a **released** database, not only a fresh one; review passes repeat until they find nothing;
and production deploys only on the owner's go.

## At a glance

| When | What | Issues | Decision needed |
|---|---|---|---|
| **Now** | **0.5.2**: bodies stored compressed only, older rows swept | #336 (PR #344) | — |
| **Now, outside a release** | A FeatherReader Standard.site publication | #349 | hosting (see below) |
| **Next** | **0.6, daily driver**: the list keeps its place; an All view | #345, #346, #347 | the All view's mark-all-read scope |
| **Gate** | **Registration (D4)**: raise the beta cap or not | #263 | the owner's, after 0.5.2 and 0.6 |
| **Then** | **0.7, Atmosphere**: Standard.site subscriptions | #348 | ownership field on `rss.subscription`; per-reader opt-in |
| **Ongoing** | Spec · hardening · network indexer · private data | #287, #327, #295 | the NSID authority (#287) |

---

## Now — 0.5.2: finish compression (#336, step 2)

PR #344 is open with all 13 checks green and is waiting on review. 0.5.1 writes each body twice;
0.5.2 reads and writes only the compressed copy and sweeps older rows. That's about 2.8× smaller
bodies, and roughly 1.9× more feeds per GB.

- Review until a pass finds nothing. Then `v0.5.2-rc.1` on staging, with the upgrade from a copy of a
  **0.5.1 production volume** and the rollback story written in the upgrade notes. This step drops
  the plain copy, so check whether 0.5.1 can still boot on the result.
- After it runs in production: **re-measure** database size per feed with the #263 method. That
  number feeds the registration gate.
- **#327** (cancellable ingest sanitizer) ships in 0.5.2 if it's ready. It doesn't block.

## Now, outside a release — a FeatherReader publication (#349)

This needs no FeatherReader code in its recommended form, so it doesn't wait for a release. It's
worth doing **before Bluesky's Atmosphere beta**, which features Standard.site publications and
renders rich cards for their links.

- **Recommended hosting:** `news.feather-reader.com` on the existing Hugo + Sequoia pipeline (the one
  `justin-stanley.com` uses, whose deploy already checks the `.well-known` path and the `<link rel>`
  tags). The alternatives are serving it from FeatherReader itself (B1 in the design: new
  markdown/sanitiser/CSP surface on the production app), or Leaflet/pckt (B2).
- **The owner creates the publication record** on @feather-reader.com (the credential is human-gated).
- First post: **"0.5: Rust-only"**. Don't republish the launch post; link to it.

## Next — 0.6: daily driver (#345, #346, #347)

The first invited users are moving in from other readers (#345–#347 come from someone trying it as a
replacement for CommaFeed, in their first hour). The gaps they hit are about the list losing its place, not about
features. Fix those before more people arrive.

1. **The list keeps its place (#345, #347).** Every click reloads the whole page, so the rail's
   scroll and open folders reset, and "mark all read" navigates away. Stay server-rendered: use htmx
   (already shipped, plus `keyboard.js`) to swap the main pane only (`hx-boost` or `hx-target` on
   rail links, with `hx-preserve` on the rail), and make mark-all-read an in-place swap. **No-JS
   behaviour stays exactly as it is today** (`design/DESIGN.md`: every action is a real link or form).
2. **An All view (#346).** One river across every feed, with "mark all read" over it. The
   import-then-catch-up case in #346 is the reason for it. The cost: mark-all-read across N feeds is
   N `readState` watermarks, so write them in one `applyWrites` batch (chunked at the PDS limit),
   not N calls. **Decision:** whether All's mark-all-read covers only what's loaded, or everything
   up to now.
3. **Ask the reporter** what else stopped them in their first week, before 0.6 freezes.

## Gate — registration (D4)

D4 was deliberately left out of 0.5.0, and it stays the owner's decision. The inputs:

- **Capacity at the shipped defaults:** about **1,500 feeds** of production's mix before the
  768 MiB watermark pauses polling, and about 3,000 polls an hour (#263). Compression (0.5.2) should
  roughly double the feeds per GB; measure it after 0.5.2 rather than assuming it.
- **Raising the watermark means raising the volume**, keeping the headroom the boot-time
  watermark-vs-free-space check expects.
- **Order:** after 0.5.2's measurement and after 0.6, so new readers don't land on the gaps in
  #345–#347.

## Then — 0.7: Atmosphere (#348)

Write `site.standard.graph.subscription` for publication subscriptions, so a FeatherReader
subscription counts in the publication's subscriber count and subscriber list in Bluesky's
AppView, and in every Standard.site app. Design: `design/ATMOSPHERE-STANDARD-SITE.md` (branch
`docs/atmosphere-standard-site`), with these settled first:

- **Never touch another app's records** (decided).
- **Ownership survives a lost local database** (owner decision): store the at-uri of the record
  FeatherReader created in an optional field on the reader's own `community.lexicon.rss.subscription`.
  This changes the owner's lexicon, so it lands with #287's Lexicon JSON. The local table is only a
  cache.
- **Per-reader opt-in**, off by default (recommended over an instance flag alone). The AppView shows
  subscribers' profiles, and the backfill would publish records nobody chose.
- Follow-ups in later releases: **import** of other apps' subscriptions (a one-click offer on
  `/manage`), then **`site.standard.graph.recommend`** as an explicit Recommend action, separate from
  the star.

Why not sooner: 0.6 fixes problems current readers have now. The Atmosphere screen is still
unfinished and behind a flag, while the publication (#349) covers the time-sensitive part.

---

## Ongoing tracks

- **Spec (#287).** PR 1 is the Lexicon JSON for `subscription`, `folder`, `saved` and `readState`, with
  tests that validate records against it. Open: undated-item ids, what `readThrough` is compared
  against, and **the NSID authority**: `community.lexicon.rss` sits under Lexicon Community, and
  `_lexicon.rss.lexicon.community` has no DNS record, so the lexicon doesn't resolve. 0.7's
  ownership field depends on PR 1.
- **Hardening.** #327, plus whatever review rounds turn up. Every release keeps the rule of testing
  the upgrade from the released schema.
- **Network indexer experiment (#295).** A standalone crate on the `bot/` pattern, scoped to one DID,
  that measures Jetstream cursor and backfill behaviour before NETWORK-SPEC Capability 2. Not tied to
  a release; Capability 2 itself waits on the consent model.
- **Private data (watch).** atproto has no stable private records yet (Spaces is in alpha;
  Atmospheric Groups build on it). When Spaces is stable, re-evaluate moving `readState` and `saved`
  into a space. That's the launch post's promise ("once atproto's private/permissioned data lands").
  Groups could later carry shared reading lists. Check each quarter; don't build on the alpha.

## Not on the roadmap

- **Read-aloud (TTS):** the owner's personal tool on one homelab worker; not a FeatherReader feature.
- **Opening registration** before the D4 gate.

## Decisions for the owner

1. #349 hosting: Hugo subdomain (recommended), FeatherReader-served, or Leaflet/pckt.
2. 0.6: the All view's mark-all-read scope.
3. D4: the beta cap after the 0.5.2 measurement.
4. 0.7: the ownership field on `rss.subscription`; per-reader opt-in vs the instance flag.
5. #287: approach Lexicon Community about publishing `community.lexicon.rss`.
