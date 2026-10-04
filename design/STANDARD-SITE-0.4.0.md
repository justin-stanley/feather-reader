# 0.4.0 — standard.site support

Subscribing to `at://…/site.standard.publication/…` the way FeatherReader
already subscribes to an RSS feed.

**This is the whole of 0.4.0.** Opening registration is not part of it; earlier
drafts that framed 0.4.0 that way (PR #158, closed) are superseded.

**Every number here was measured against the 17 real publishers already
subscribed in production on 2026-09-13, not estimated.** Where something was not
measured, it says so. The status sections were revised against `main` and
production on 2026-10-03, after 0.3.10.

---

## Status, 2026-10-03

**Status as of step 3: publications are read, polled, and subscribable from
the form.** What remains is step 4 (display edge cases, #213) and step 5
(turning the flag on in production). The status table below was written at the
start of the work and is kept current per row.

| Piece | State | Where |
|---|---|---|
| Unauthenticated fetch, paged to an empty page, real `User-Agent` | **built** | `standard_site::fetch`, `atproto::PdsClient::anonymous` |
| Read `textContent` / `description` only, escaped; ignore `content` | **built** | `standard_site.rs` (module doc, `entries_from_documents`) |
| Store a read, with the poll semantics review found | **built** (#202) | `standard_site::store_publication` |
| Retention by count, not age | **built** (#206) | `FeedKind::AGED`, `Config::retention_for` |
| Stable dates from the record key; future dates discarded | **built** (#186) | `standard_site.rs` |
| `feeds.kind`, re-derived from the URL on every start | **built** (#184, #189), upgrade-safe since 0.3.10 (#219) | `feed::FeedKind`, `store.rs` |
| `at://` storable, as an allowlist entry behind a flag | **built** (#183) | `feed::is_storable_feed_url(url, allow_at_uri)` |
| **Polling** | **built** (#225) | its own loop, `scheduler::run_publication_poller`, one repo read at a time; a subscribe from the form reads once more, inline, alongside it; `publication_read_deadline` 30 s |
| **One walk per repo per tick** | **built** (step 2b) | `standard_site::fetch_repo`, `feed::poll_publication_group`; up to 16 publications of one repo per read |
| **Subscribe form** | **built** (step 3) | DID and handle forms, behind the flag; `web::publication_url_from_paste` |
| **Flag on in production** | **off** | `FEATHERREADER_STANDARD_SITE` unset |

### Why it matters, now

19 feed rows are `at://did:plc:…/site.standard.publication/…`, across **17
distinct publishers**, all belonging to **one** of the instance's readers. None
has ever delivered anything.

Since 0.3.9 they are classified `publication`, skipped by kind instead of failed,
and their error counts cleared. So they no longer distort `/stats` — which
reported 61% of feeds failing on 2026-09-20 and reports 9 of 92 on 2026-10-03,
with these rows excluded. The cost of that honesty is that they are now
**invisible**: the reader still sees 19 silent subscriptions, and no surface says
why. That is the user-facing problem this release exists to end.

---

## The shape of the data

Two collections matter. Both were read from live repos.

### `site.standard.publication` — a pointer, not a feed

```
name         "Scan's Lab"
url          https://scanash.com
preferences  { showInDiscover }
```

No entries. This is the thing a reader subscribes to, and it supplies the
publication's title and the base URL for article links.

### `site.standard.document` — the entries

Field presence across **449 documents** from all 17 publishers:

| field | present | maps to |
|---|---|---|
| `title` | **449 / 449** | `entries.title` |
| `publishedAt` | **449 / 449** | `entries.published` |
| `path` | **449 / 449** | `entries.url`, joined onto the publication's `url` |
| `site` | **449 / 449** | the join key — an `at://` URI naming its publication |
| `content` | 331 | **see below — do not use** |
| `textContent` | 321 | body / summary |
| `description` | 223 | summary |
| `updatedAt` | 62 | — |
| `canonicalUrl` | 35 | — |

The four fields the reader actually needs are on **100%** of documents. That is
the whole reason this is tractable.

`site` is load-bearing: a repo can hold several publications (measured — some do),
so documents must be filtered by it rather than assumed to belong to the
publication being polled.

---

## The decision that shapes the release: do not render `content`

`content` is **not a standard**. Each publishing platform writes its own format
into that field. Measured across the same 449 documents:

**6 distinct content wrappers** (the table has seven rows; one is the *absence* of a wrapper)

| count | `$type` |
|---|---|
| 148 | `pub.leaflet.content` |
| 118 | *(no content field at all)* |
| 84 | `app.offprint.content` |
| 63 | `at.markpub.markdown` |
| 17 | `blog.pckt.content` |
| 16 | `com.scanash.content.markdown` |
| 3 | `app.greengale.document#contentRef` |

**22 distinct block types** beneath them — `app.offprint.block.text`,
`blog.pckt.block.blueskyEmbed`, `blog.pckt.block.iframe`,
`app.offprint.block.image`, `blog.pckt.block.table`, and so on, from five
different vendor namespaces.

Rendering `content` means implementing six formats and twenty-two block types,
and that set **grows with every new platform that adopts the lexicon** — the work
is unbounded and the cost lands on us, not on the publishers. It also drags in an
HTML-sanitisation surface (`iframe`, `website`, `blueskyEmbed` blocks) on
foreign input, which is the category of bug this codebase has spent the most
effort on.

### What to use instead

`textContent` (71%) and `description` (49%). **Documents with neither: 37 of 449
(8%).** Those render as a title, a date and a link — which is exactly what an RSS
reader does for a title-only feed, and is not a failure state.

This is the atproto-native equivalent of a summary feed. Full-text rendering of
one or two of the markdown wrappers (`at.markpub.markdown`,
`com.scanash.content.markdown` — 79 documents, 18%) is a plausible **later**
refinement, and deliberately out of scope here.

---

## Fetch path

```
at://<did>/site.standard.publication/<rkey>
  │
  ├─ resolve <did> → PDS            (oauth::resolve / identity, already exists)
  ├─ getRecord  publication         → name, url
  └─ listRecords site.standard.document, paged
       └─ keep documents whose `site` == this publication's at:// URI
            └─ entry { title, published: publishedAt,
                       url: publication.url + path,
                       summary: description ?? textContent,
                       guid: the document's at:// URI }
```

Unauthenticated reads of another repo — no session, no tokens. That is a
different path from `oauth::xrpc::Repo`, which is built around the *reader's own*
authenticated repo. **Answered: it is reachable**, via
`atproto::PdsClient::anonymous`, which `standard_site::fetch` uses (see the
re-measurement below).

---

## Cost — measured, and it is small

| | |
|---|---|
| publishers reachable | **17 / 17** |
| documents, all publishers | **449** |
| median per publisher | **13** |
| largest publisher | **152** |
| full payload, everything | **~3.7 MB** |
| requests for a full sweep | ~35 (1–3 pages each at `limit=100`) |

The existing poller already handles 92 HTTP feeds — 111 total minus the 19
`at://` rows it cannot poll, which are the subject of this document. This is
smaller. **No
server-side filtering is needed and none is available** — `listRecords` cannot
filter by field, so `site` is matched client-side.

Size skew is the only thing worth watching: one publisher is 1.7 MB for 97
documents (~17 KB each) while another is 11 KB for 21. Per-entry retention
matters more than request count.

### Re-measured 2026-09-27, through the real code path

Three publications, read through `standard_site::fetch` + `store_publication`
with a counting allocator (`$SCRATCHPAD/publication_probe.rs`):

| | docs | fetch cold | warm | retained | peak | stored @ 14/180 | @ no floor |
|---|---|---|---|---|---|---|---|
| Standard.site (own repo) | 11 | 0.58 s | 0.32 s | 133 kB | 231 kB | **0** | 11 |
| Annotated (18 of 38, 9-publication repo) | 18 | 2.13 s | 1.17 s | 63 kB | 4.8 MB | **0** | 18 |
| minus listens (1 of 38, same repo) | 1 | 1.23 s | 1.21 s | 0 kB | 4.6 MB | **0** | 1 |

Four things this settles, and the first is the one that decided a release step:

**Retention by age stores NOTHING.** The newest documents were 131, 109 and 241
days old; the default window is 14. "Per-entry retention matters more than request
count" was right, and the answer is that publications are bounded by count
(`max_entries_per_feed`) with a generous absolute ceiling, not by the rolling
window. Implemented; see `FeedKind::AGED` and `Config::retention_for`.

**Peak is bounded by page size, not by archive size.** 4.8 MB peak against 63 kB
retained is `DOCUMENT_PAGE_SIZE = 25` at a ~15 kB median with ~7x wire-to-`Value`
amplification. At poll concurrency 4 that is ~19 MB — safe on a 512 MB box.

**Cost scales with the REPO, not the publication.** "minus listens" retains 0 kB
and peaks 4.6 MB to deliver one article, because the walk reads all 38 documents in
the repo to find its one. Nine publications in one repo cost nine such walks an
hour. Per-repo de-duplication within a tick is therefore the cheapest cadence win
available, ahead of any rev/high-water-mark scheme.

**Open question 1 is answered: yes.** An unauthenticated XRPC GET is reachable —
`atproto::PdsClient::anonymous` is exactly that path, it is what `fetch` uses, and
it succeeded against three real PDSes (`bsky.network`, `eurosky.social`) with no
session. The `User-Agent` trap above is also already handled: `net`'s client sets
one, and these reads go through it.

One more real-world shape worth recording: of nine publications in that repo, one
carries a **slug** rkey (`blento.self`) rather than a TID, and one document names
its `site` as a bare DID rather than a publication at-URI. Both are handled —
`tid_timestamp` returns `None` for a non-TID rkey, and the canonical-URI filter
drops the malformed document — but neither case is hypothetical.

---

## Traps found while measuring

**Send a real `User-Agent`.** A first pass using Python's default UA got HTTP
403 from 4 of 19 endpoints, and nearly went into this document as "some PDSes
refuse anonymous enumeration". They do not — the same requests via `curl`
returned 200. A fetch path that does not set a UA will fail against roughly a
fifth of publishers, intermittently, looking exactly like those hosts being down.
`net.rs`'s client already sets one; a new XRPC helper must not bypass it.

**`listRecords` returns a cursor on the final page.** Paging must terminate on an
empty record set, not on cursor absence, or every poll loops.

**A publication with zero documents is normal.** Two of the 17 currently have
none. Not an error, and not a reason to mark the feed broken.

---

## What is left — the 0.4.0 work, in order

### 0. Release safety (before anything that touches the schema)

0.3.9 crash-looped production because a schema change passed every check and
still failed against an existing database. 0.3.10 added upgrade tests from the
v0.2.0 and v0.3.8 schemas (#219). Wiring polling is likely to touch the schema
again, so first:

- **A CI `upgrade-boot` job**: boot the previous release's real image on an
  empty volume, then the candidate on that volume, then the previous image
  again. It uses real binaries, so it cannot drift the way a hand-maintained
  fixture can.
- **Gate the release workflows on it.** Today a tag publishes to crates.io and
  moves `:latest` before anything boots the image. A failed boot must publish
  nothing.

### 1. Bound foreign input (before it arrives on a schedule)

Polling makes other people's records an hourly input. Two open issues become
live the day it lands:

- **#205** — publisher strings are stored unbounded; one document can carry an
  8 MB title. Bound `title`, `url`, `author` and the summary per field, for RSS
  and publications alike.
- **#177** — one malformed record envelope fails a whole `listRecords` page. On
  the publication path that stalls a publication's updates, every tick, on one
  bad document. Parse per record and skip the bad one.

Also from the 0.3.9 notes: **the walk budget is per walk, and walks nest.**
Polling runs walks concurrently; check the peak against the measured ~4.8 MB
per walk at concurrency 4 before relying on it.

### 2. Polling

- Add `FeedKind::Publication` to `POLLABLE`. The scheduler calls
  `standard_site::fetch` then `store_publication` for these rows; success and
  failure settle through `feed::settle_poll`, the path RSS uses, so
  `/stats` and backoff behave the same.
- **Stagger the admitted rows.** `POLLABLE`'s own doc warns that admitting a kind
  makes every row of it due at once, ahead of every dated feed. Seed `next_poll`
  across an interval for the rows the change admits. Harmless at 19; the point
  is not to need to remember it at 1,900.
- **One walk per repo per tick** (was open question 2). Cost scales with the
  repo, not the publication: nine publications in one repo are nine full walks.
  Group due publications by DID, walk the repo's documents once, and split by
  `site`. This is the cheapest cadence win measured; a `rev`-based "has anything
  changed" check is still not measured and stays out of scope.

**Decided in review of #225: a publication read has a 30 s deadline, and a read
that misses it stores nothing.** That keeps the read in flight at shutdown
inside Fly's 45 s `kill_timeout`. The cost: a publication that needs on the
order of 80 sequential pages (about 2,000 documents) would fail every poll.
Today's largest measured publisher is 152 documents (about 7 pages). If a
subscribed publication ever approaches the limit, keep the partial read on
timeout instead of raising the deadline.

**Decided in review of step 2b: a one-repo group shares one read, one 30 s
deadline and one byte budget.** Each publication in a group has its own document cap, so a big sibling cannot
starve a quiet one of records. The byte budget is shared, so in principle a big
sibling can starve a quiet one of BYTES (#229, not reachable at measured scale;
a static per-publication share was tried and removed for being worse). The group still finishes when its slowest member
does, and the DB-size watermark is checked once per group, so a group can store
up to 16 publications past it. Neither bites at measured scale (the largest
repo's nine publications hold 38 documents, two pages); revisit if a member's
own reads approach 2,000 documents.

### 3. Subscribe form

Accept a publication URI in the form, behind the same flag. Two spellings reach
it: the DID form, which is stored as-is, and a handle form
(`at://alice.example/…`), which must be resolved to the DID before storage — a
handle is a mutable name, and only the DID form is stored (README, "standard.site
publications"). A non-canonical spelling is refused, as #183 already does for
storage.

### 4. Display and edge cases

Entries render through the existing entry views, and the summary is already
escaped at ingest. What needs checking rather than building:

- a document with neither `textContent` nor `description` (8%) renders as title,
  date and link, not as an error;
- a publication with zero documents (2 of 17) reads as empty, not broken;
- undated and future-dated entries order correctly — #187, #188, and **#213**,
  which reworks entry dating and carries its own index change, so it lands
  through step 0's gate.

### 5. Turn it on

Set `FEATHERREADER_STANDARD_SITE=true` in production with the release that
carries steps 2–4. The 19 existing rows start delivering on their staggered
schedule. That answers open question 3 by fixing it rather than explaining it.

**Exit:** the 19 production subscriptions deliver entries, `/stats` counts them
as pollable and healthy, and a reader can subscribe to a new publication from the
form.

## Out of scope, on purpose

- Rendering any `content` wrapper (see above)
- `site.standard.graph.subscription` — standard.site has its own subscription
  lexicon; whether to read or write it is a separate question
- Publishing. FeatherReader reads.
- Opening registration or raising the beta cap. Not a 0.4.0 goal.
- Removing the Node sidecar, and poller throughput work. Separate tracks; the
  poller runs at a few percent of its ceiling at this scale.
- Full-text rendering of the two markdown wrappers (79 documents, 18%) — a
  plausible later refinement.

---

## Open questions

1. ~~Is an unauthenticated XRPC GET reachable in the current code?~~
   **Answered: yes** — `atproto::PdsClient::anonymous`. See "Re-measured
   2026-09-27".
2. **Poll cadence.** Partly answered: one walk per repo per tick is the measured
   win, and is step 2. Whether a cheap "has anything changed" check exists
   (repo `rev`, `listRecords` ordering) is **still not measured**, and not
   needed for 0.4.0.
3. **What the affected reader sees today**: 19 silent subscriptions, and since
   0.3.9 not even a failure count. Resolved by step 5 rather than by a message;
   if step 5 slips, a one-line notice on the subscription list is the stopgap.
