# Implementation plan: the roadmap, PR by PR

> **As of 2026-10-24, against `origin/main` @ `d809794`** (0.5.1). Companion to
> [`ROADMAP.md`](ROADMAP.md). References are `file:line` on that commit. Every PR follows the
> house rules: review passes repeat until one finds nothing; schema changes are tested by upgrading
> from a **released** database (fixtures in `tests/fixtures/schema-v*.sql`, plus
> `scripts/upgrade-boot.sh`); a release is an `-rc.N` on staging for ≥ 24 h, then the final tag on
> the same commit (#294); production deploys only on the owner's go.

## Order

| # | PR | Release | Size | Depends on |
|---|---|---|---|---|
| 1 | Review and land #344 (compression, step 2) | 0.5.2 | review only | — |
| 2 | Fix: folder-scoped "Mark all read" marks every feed | 0.5.2 | S | — |
| 3 | Document the rc step (#294's last to-do) | — | XS | — |
| 4 | Mark-all-read marks only what the reader saw | 0.6 | S | 2 |
| 5 | Scope-preserving redirects for read / star / mark-all (no-JS) | 0.6 | S | 2 |
| 6 | Navigation keeps the rail: htmx-boosted main pane | 0.6 | M | 5 |
| 7 | Live rail counts (DESIGN §6 item 8, never built) | 0.6 | S | 6 |
| 8 | "All feeds" in the rail (#346) | 0.6 | XS | 4 |
| 9 | Reader settings table + /manage "Sharing" | 0.7 | S | — |
| 10 | `site.standard.graph.subscription` record type + ownership field | 0.7 | S | owner decision |
| 11 | Write and delete graph subscriptions | 0.7 | M | 9, 10 |
| 12 | Opt-in backfill and opt-out cleanup | 0.7 | S | 11 |
| 13 | Close out #287 | — | XS | 10 |
| 14 | #327, cancellable sanitizer | 0.6.x / 0.7 | M | owner picks the approach |

---

## 0.5.2

### 1. Land #344

PR #344 has **no reviews yet**; all 13 checks pass. To do before the rc:

- Run review passes until one finds nothing. Focus on `run_body_compaction` (one shot, 3 min after
  boot, batches of 200, an id cursor, `WHERE content_html = <value read>` so a concurrent poll wins)
  and rollback: **0.5.1, not 0.5.0**, once the sweep has run (0.5.0 would show swept bodies as
  missing until they're re-polled). The upgrade notes must say this plainly.
- **Check #336's `/stats` progress item.** The PR touches `src/web.rs` (+14), but its description
  doesn't say what that change is. Either it shows sweep progress, or #336 needs a follow-up.
- After it's live: #336 step 3, re-run the #263 bench (batch 200) on staging and record database size
  per feed. That number feeds D4.

### 2. Fix: folder-scoped "Mark all read" marks every feed

**Bug.** In a folder view, the mark-all form posts with no scope. `index.html:49` uses only
`feed_scope`, which is set only for a feed (`web.rs:2788`), and `mark_all_read` (`web.rs:3498`)
with no `feed` loops **every** subscribed feed. So "Mark all read" in a folder marks everything.

- `ReadAllQuery` (`web.rs:3491`): add `folder: Option<String>`. Resolve it through the same
  `scope_urls_for` / `scoped_feed_ids` path the index uses (`web.rs:2954`, `:3259`), so the two
  can't disagree.
- `index.html:48-51`: post `?folder=…` when the view is a folder.
- Tests (there's **no handler test that POSTs `/read-all` today**): feed scope marks one feed; folder
  scope marks only that folder's feeds and leaves another folder's unread count untouched; no scope
  marks all.
- Ship in 0.5.2 if #344 is still in review; otherwise as 0.5.3.

### 3. Document the rc step

`README.md` "Releasing" (`:354`) and `CONTRIBUTING.md` never mention rc tags or the soak. Add the
#294 procedure (the final version in `Cargo.toml`; `vX.Y.Z-rc.N`, a ≥ 24 h soak, the final tag on
the same commit; bump `deploy/upgrade-from` only after the final is live), and point to the guards
in `release-crate.yml:76-81`, `release-image.yml:236` and `github-release.yml:16`. Then close #294.

---

## 0.6: daily driver

What exists: htmx **2.0.4** (`static/htmx.min.js`), loaded with `keyboard.js` in `base.html:38-39`.
hx-* is used only for row actions (`entry_row.html`, `entry_actionbar.html`). There's no
`hx-boost`, no `hx-push-url`, and no `HX-*` response headers. The CSP is `script-src 'self'`
(`web.rs:146-155`), so **htmx configuration goes in a `<meta name="htmx-config">`, never an inline
script**. The rail (`rail.html`) has no collapse state; what "resets" is its **scroll position**
(`.rail-scroll`, `style.css:473`), plus the mobile drawer (`.rail-open`). The DESIGN rule stands:
**no SPA; every action is a real link or form; htmx is strictly additive** (`DESIGN.md:258`).

### 4. Mark-all-read marks only what the reader saw

Today `mark_feed_read` (`store.rs:3562`) marks every entry of each feed, including ones that
arrived after the page was rendered.

- The index renders a hidden `through=<the newest entry id in scope when the page was built>` into the
  mark-all form. `mark_all_read` passes it to `mark_feed_read(…, max_entry_id)`, which marks only
  `e.id <= through`. With no `through` (an old page, or a hand-made POST), today's behaviour stands.
- `project_feed_into_cursor` (`store.rs:3764`) is unchanged: ids go into `read_ids`, and
  `compact_if_large` folds them into `readThrough` at ≥ 500 (`readstate.rs:812`).
- PDS cost: one dirty `readState` per feed, flushed by the existing per-DID `applyWrites` within
  the 60 s debounce. 30 feeds is 30 ops, one chunk. No new write path.
- This settles the roadmap question about All's mark-all-read scope: **everything listed up to the
  moment of rendering**, whatever page is showing.
- Tests: an entry inserted after rendering stays unread; `through` absent means today's behaviour.

### 5. Scope-preserving redirects (no-JS)

Without htmx, `/entries/{id}/read` and `/star` redirect to `/` (`web.rs:3298`, `:3365`), and
`/read-all` drops `view`. That loses the reader's place even with JavaScript off.

- Add a `back` form field holding the page's own path + query (`nav.scope_qs` plus `view` and
  `page`). Redirect to it only if it's a **same-origin relative path** (`/` followed by anything
  except a second `/` or `\`). Otherwise use `/`. Reuse `back_qs` from the entry view (`web.rs:3103`).
- Tests: the redirect keeps feed, folder, view and page; `back=//evil.example` falls back to `/`.

### 6. Navigation keeps the rail (#345, #347)

**Approach: boost the links, swap only `#content`.** The rail is never re-rendered on navigation,
so its scroll position, its DOM and the drawer state survive.

- `<meta name="htmx-config" content='{"historyCacheSize": 20, "scrollIntoViewOnBoost": false}'>`
  in `base.html`.
- `index.html` / `entry.html`: on `.shell`, set `hx-boost="true" hx-target="#content"
  hx-select="#content" hx-swap="outerHTML show:#content:top"`. That covers the rail links
  (`feed_item.html:4`, folders and filters), the pager (`index.html:73-87`) and entry links. Each
  response is still the **full page** the server renders today: no new routes, and no-JS gets
  exactly what it gets now. htmx pushes the URL, so Back and Forward work. Boosting is a GET, so it
  isn't rate-limited (`web.rs:398-419`).
- **Mark all read (#347):** the form is boosted in the same way. The handler sees `HX-Request` and
  answers with the redirect target's page (or `HX-Location`) instead of a 303, so the main pane
  swaps and the rail stays.
- Exclusions with `hx-boost="false"`: sign-out, `/manage` (its forms do multipart OPML upload),
  `/login`, external links, and anything with `target`.
- `keyboard.js`:
  - On `htmx:afterSettle`, set `aria-current` on the rail link that matches `location`, and close
    the mobile drawer (`.rail-open`) after a navigation from it.
  - Re-run the j/k cursor setup for the new list. The `A` shortcut keeps clicking `.js-mark-all`,
    which is now boosted.
- Focus and accessibility: after a swap, move focus to `#content`'s heading (`tabindex="-1"`) and
  announce it (`aria-live` on a visually hidden status). A full page load does this for free; a swap
  must do it on purpose.
- Tests (Rust, via `oneshot`): the boosted page's `#content` is self-contained, with its flash,
  heading, count, mark-all form and pager inside it. `HX-Request` on `/read-all` returns 200 with
  the page (or `HX-Location`), not a 303. Without `HX-Request`, every route behaves exactly as
  today. Do a **manual browser pass** on desktop and mobile: rail scroll survives 20 clicks;
  Back/Forward; drawer; keyboard shortcuts; screen-reader announcement.

### 7. Live rail counts

Unread counts in the rail don't change after a read, a star swap or a boosted navigation (DESIGN
`:297-299` planned an OOB update; it was never built).

- Give each count in `feed_item.html` and on each folder a stable id (`count-f<feed_id>`,
  `count-d<folder>`). On boosted responses, and on the row read fragments, the server appends the
  changed counts as `hx-swap-oob="outerHTML"` spans. `build_sidebar` (`web.rs:2979`) already
  computes them (`unread_counts_by_feed`).
- For boosted pages, `hx-select-oob="#rail-counts"` picks up one hidden block that holds every count.
  It costs one query that the page already runs.
- Tests: a read fragment carries an OOB count for its feed; the boosted page carries `#rail-counts`.

### 8. "All feeds" in the rail (#346)

**This already exists**: `/` with no feed or folder is unscoped across every subscribed feed
(`scoped_feed_ids` → `None`). What's missing is a rail entry and a heading.

- `rail.html`: an "All feeds" link at the top of the feed list (`/?view={{ nav.view }}`), with
  `aria-current` when nothing is scoped.
- The index heading for the unscoped view: "All feeds · Unread" (or "· All"/"· Starred") instead of
  the bare view name (`web.rs:2780-2786`).
- Mark all read there works through PR 4's `through`.
- Reply on #346 when it ships: the river and global mark-all existed, but nothing pointed to them.

**Then:** `v0.6.0-rc.1` on staging. Ask the #345/#346/#347 reporter to try staging before the final tag.

---

## 0.7: Atmosphere (#348)

**This rests on owner decision 4** (see the roadmap): the ownership field on
`community.lexicon.rss.subscription`. If the owner declines, swap PR 10's field for a local
`(did, rss_rkey, graph_rkey)` table and accept that a lost local DB orphans our records. The
other PRs are unchanged.

What exists: `Subscription` (`lexicon.rs:118-205`) keeps unknown fields in `extra` (#272), so an
older build preserves a new field on rename. Writes accept only types sealed in `writable!`
(`vetted.rs:62-90`). The scope is `transition:generic` (`config.rs:257`), so readers don't need
to sign in again. There's **no per-reader settings storage** anywhere, **no `getRecord`**, and
**no post-login task**. `delete_subscription` (`web.rs:3794`) knows only the rss rkey.

### 9. Reader settings + /manage "Sharing"

- New table `reader_settings (did TEXT PRIMARY KEY, share_standard_graph INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT)` in `SCHEMA` (`store.rs:423`, `CREATE TABLE IF NOT EXISTS`). It's a new table, so
  the previous binary ignores it (the upgrade-boot gate rolls back to 0.6.x).
- Add it to `purge_did_data` (`store.rs:4968`) and `PurgeCounts` (`:4915`); extend the tests at
  `store.rs:8237` and `:8385`.
- `/manage`: a "Sharing" section with a toggle form, `POST /settings/sharing` (rate-limited by
  default under #261's inverted rule). Copy: *"Share your Standard.site subscriptions with other
  apps. Publications and other apps, including Bluesky, can show you as a subscriber."*
- Instance flag `FEATHERREADER_STANDARD_SITE_GRAPH` via `parse_bool` (`config.rs:834`), off by
  default. The toggle is visible only when this flag and `standard_site` are both on.
- Add a fixture `tests/fixtures/schema-v0.6.0.sql` when 0.6 ships, and a shape test from it.

### 10. Record type and ownership field

- `lexicon.rs`: `nsid::STANDARD_GRAPH_SUBSCRIPTION = "site.standard.graph.subscription"`, beside
  `STANDARD_PUBLICATION` (`:46`). Add `GraphSubscription { publication, created_at }`, with
  `publication` checked as a **DID-form** `at://did/site.standard.publication/rkey` (with
  `standard_site::AtUri::parse`). Bluesky's AppView matches it by exact string
  (`record.publication === uri`), so the DID form is what makes it count. Add it to `writable!`.
- `Subscription`: add `standard_site_subscription: Option<String>` (`rename =
  "standardSiteSubscription"`, `skip_serializing_if`), the at-uri of the graph record **FeatherReader
  created** for it. Update `lexicons/community/lexicon/rss/subscription.json` and `docs/lexicon.md`.
  The JSON test (`lexicon.rs:1057`) covers the round trip.
- Add a JSON copy of the Standard.site schema in a test fixture (read from
  `did:plc:re3ebnp5v7ffagz6rb6xfei4`), and a test that our record validates against it.

### 11. Write and delete

**Subscribe** (`web.rs:3783`, when `publication_url.is_some()`, both flags on, and the reader opted in):

1. `list_all_records(graph)` (`repo.rs:438`). If any record's `publication` equals ours, **another
   app's or an orphan's**, create nothing and leave the field unset.
2. Otherwise `create_record(graph)` → its at-uri, then create the rss subscription **with the field
   set**: one write each, no update. If the graph write fails, write the rss record without the
   field, the same as today's failure handling (`warn!`, keep the local row).

**Unsubscribe** (`web.rs:3794`): `list_subscriptions_with_cids` (`repo.rs:274`) to find the rss
record by rkey and read its field. Delete the graph record it names (if that record exists, still
names the same publication and is in this reader's repo), then delete the rss record. **A graph
record not named by one of our rss records is never deleted.** If the reader still has another
app's record for the publication, the redirect flash says *"Still subscribed through another
Standard.site app."*

**OPML** (`import_opml`, `web.rs:5989`): for at:// rows, pre-assign graph TIDs (`TidGenerator`,
as `add_subscriptions_bulk` does at `xrpc.rs:550`) and send the graph creates **first**, as their
own `applyWrites` run. The rss creates then set the field only for graph writes in
`ApplyWritesIncomplete::landed`. An in-doubt chunk gets no field, so at worst it leaves an orphan
we'll never delete, which the rule makes the safe failure. Document it.

Tests (`spawn_logging_pds`, `web.rs:11885`, records every write):
- flag off or opt-in off → zero `site.standard.*` writes;
- subscribe → graph create then an rss create carrying the at-uri;
- an existing foreign record → no graph create, no field;
- unsubscribe deletes exactly our record and **never a foreign one**;
- a failed graph write still writes rss;
- OPML partial landing sets fields only for the graph records that landed.

### 12. Opt-in backfill, opt-out cleanup

There's no post-login task, so these run **from the settings handler**: a bounded background task,
`tokio::spawn`, with progress in the flash.

- **Opt in:** for each publication rss subscription without the field, if no graph record for that
  publication exists, create one and `update_subscription` (`repo.rs:324`, with `swapRecord`, so a
  concurrent rename is refused rather than lost) to set the field. Idempotent: rerunning finds the
  fields set.
- **Opt out:** delete every graph record named by our fields, then clear the fields. Foreign records
  are untouched.
- Verify on staging with the test account: subscribe to a publication, call
  `app.bsky.embed.getEmbedExternalView` for it, and see `subscriptionCount` rise and the test profile
  among `subscribers`; opt out and see both fall.
- `/privacy`: add the sharing paragraph.

**Follow-ups (later 0.7.x):** importing other apps' subscriptions (a one-click offer on `/manage`;
the feed caps apply), then `site.standard.graph.recommend` as an explicit Recommend action.

---

## Housekeeping

### 13. Close out #287

PRs 1–3 merged (#288, #289, #321) and #290 is closed (#322). The Lexicon JSON exists for all four
records, with validation tests (`lexicon.rs:950-1140`). What's left are `docs/lexicon.md:235+`'s
open questions:
- the NSID authority (Lexicon Community);
- unknown-field preservation on `saved` and `readState`, which `subscription` and `folder` already
  have;
- `maxLength` on `subscription.title`, `folder.name` and `saved.title`.

Close #287 and file those as three issues.

### 14. #327: cancellable sanitizer

The goal: a timed-out sanitize really frees its thread and permit. Ammonia can't be interrupted, so
today's guard is the #326 reserve (`feed.rs:1427-1439`), sized against the worst shapes found.

**Recommended: option (a)**, a subprocess. The same binary runs a hidden `sanitize` subcommand that
reads stdin; it's killed at `SANITIZE_TIMEOUT` (5 s, `feed.rs:1384`). Run one child per poll's
batch of bodies, to amortise the spawn. It plugs in behind `SanitizeLimits` (`feed.rs:~1629`, which
already has a `sanitize` fn seam) and `sanitize_off_runtime` (`:1710`).

Acceptance (from the issue): a **real-path** test, not the seam, where a body that never finishes
times out and its permit is free at once; then decide whether the #326 reserve stays as a second
line.

**Watch the memory:** a child per poll on the 512 MB machine. Measure the RSS of a warm child first.
If it's heavy, use a small persistent pool of children instead. Owner decides the approach.

---

## Decisions this plan needs

| PR | Decision | Recommendation |
|---|---|---|
| 4 | Scope of mark-all in All | everything listed at render (`through`) |
| 10 | Ownership field on `rss.subscription` | yes: it survives a lost local DB |
| 9 | Per-reader opt-in vs the instance flag alone | both: the flag gates the instance, the toggle the reader |
| 14 | Sanitizer approach | (a) subprocess, after measuring child memory |
