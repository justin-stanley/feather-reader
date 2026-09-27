# 0.4.0 — standard.site support

Subscribing to `at://…/site.standard.publication/…` the way FeatherReader
already subscribes to an RSS feed.

**Every number here was measured against the 17 real publishers already
subscribed in production on 2026-09-13, not estimated.** Where something was not
measured, it says so.

---

## Why now

19 feed rows are `at://did:plc:…/site.standard.publication/…`, across **17
distinct publishers**, all belonging to **one** of the instance's three readers.
None has ever been polled: `check_scheme` allows `http`/`https` only, so they
fail before a request is made, and they sit at 35 consecutive errors each.

That reader has 19 subscriptions that have never delivered anything, and nothing
in the UI says why.

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
authenticated repo. **Not yet traced: whether an unauthenticated XRPC GET is
reachable without a session in the current code.** That is the first thing to
check when implementation starts.

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

## What has to change in existing code

**`feed::is_storable_feed_url` currently blocks this.** It rejects any
non-`http(s)` scheme on the PDS-sync path and landed in v0.3.0 (`d7d97bf`,
2026-09-13) — which is why no *new* `at://` feed can be cached, and why the 19
existing rows are legacy. It must learn `at://` as an **allowlist entry**, not be
loosened: it exists to keep `javascript:`, `file:` and private-token URLs out of
the shared `feeds` table, and those reasons are unchanged.

`net::check_scheme` stays as it is. `at://` is never fetched over HTTP; it is
resolved to an https PDS first, and that request goes through the existing guard.

---

## Out of scope, on purpose

- Rendering any `content` wrapper (see above)
- `site.standard.graph.subscription` — standard.site has its own subscription
  lexicon; whether to read or write it is a separate question
- Publishing. FeatherReader reads.

---

## Open questions

1. **Is an unauthenticated XRPC GET reachable in the current code?** The pieces
   look present (`oauth::resolve` for DID→PDS, `net::guarded_get` for the
   request) but the traced path is authenticated. Check first — it sets the
   shape of the work.
2. **Poll cadence.** Documents carry `publishedAt`/`updatedAt` but the repo has a
   `rev`; whether a cheap "has anything changed" check exists (repo `rev`,
   `listRecords` ordering) was **not measured**.
3. **What the affected reader sees today**, and whether to tell them before the
   feature lands.
