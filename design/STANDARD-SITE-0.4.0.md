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

## Open question 1 — ANSWERED (2026-09-20): a new module, not an `xrpc` refactor

*Is an unauthenticated XRPC GET reachable in the current code?* **No — but the
gap is small, and it is the easier of the two outcomes this document
anticipated.** Traced against the tree:

| piece | reusable |
|---|---|
| `oauth::resolve::resolve()` → `ResolvedAccount { did, pds_url, handle }` | **yes, as-is** — takes a resolver + HTTP client, no session |
| `net::guarded_get_no_privacy` | **yes** — documented for "non-feed atproto identity fetches", which is what a PDS XRPC endpoint is. The privacy classifier is about token-bearing *feed* URLs and does not apply |
| `oauth::xrpc::Repo::list_records` | **no** |

`Repo` is session-bound three separate ways — base URL from the session's PDS,
`repo` hardcoded to `self.session.sub`, and every `send()` DPoP-signed. None of
that survives "read someone else's repo with no session".

So the work is a **new small module**, not a refactor of `xrpc`, and
`net::check_scheme` genuinely does stay as it is: `at://` is resolved to an
`https` PDS before anything is fetched, so the guard never sees the scheme it
would reject.

---

## Rollout

Five steps, each shippable. **The blast radius is one reader by construction** —
all 19 `at://` rows belong to a single account, so step 4 is self-canarying and
no flag-scoping work is needed; the data already scopes it.

Tests are written **red first**, and each stub below names the mutation it is
meant to survive. A test whose name does not correspond to something that can
actually break is the failure mode this repo has repeatedly found in its own
suite.

### 1. The reader, standalone

`at://did/site.standard.publication/rkey` → resolve → `getRecord` the
publication → paged `listRecords` of `site.standard.document`, filtered on
`site`. No poller wiring, no DB writes.

```rust
// RED: no module yet.
a_publication_uri_resolves_to_its_pds_and_returns_the_publication
    // GREEN when: resolve() → pds_url → getRecord returns { name, url }.
    // Mutation: point getRecord at the wrong DID → must fail, not return empty.

documents_are_filtered_by_their_site_field
    // A repo can hold SEVERAL publications — measured, some do.
    // Fixture: one repo, two publications, documents interleaved.
    // Mutation: drop the `site` filter → the other publication's documents
    // appear. Without this test that mutation is invisible.

paging_terminates_on_an_empty_record_set_not_on_cursor_absence
    // MEASURED TRAP: listRecords returns a cursor on the FINAL page.
    // Mutation: loop `while cursor.is_some()` → hangs / loops forever.
    // Assert the request COUNT, not just the result — a correct result can be
    // reached by a loop that ran one page too many.

a_publication_with_zero_documents_is_not_an_error
    // MEASURED: 2 of 17 currently have none. Must not mark the feed broken.

every_request_carries_a_real_user_agent
    // MEASURED TRAP: 4 of 19 endpoints 403 a default UA, intermittently,
    // looking exactly like the host being down.
    // Assert against the captured request head, like net.rs's spawn_http tests.
    // Mutation: build a bare client instead of going through the shared one.

a_document_with_neither_textContent_nor_description_still_yields_an_entry
    // MEASURED: 37 of 449 (8%). Title + date + link is a summary feed, not a
    // failure state. Mutation: `?` on the summary → 8% of entries vanish.
```

### 2. Make `at://` storable

`feed::is_storable_feed_url` (`feed.rs:271`) learns `at://` as an **allowlist
entry**, not a loosening. Nothing polls it yet — this only stops *new* `at://`
subscriptions being refused.

```rust
an_at_uri_is_storable
    // GREEN when: is_storable_feed_url("at://did:plc:x/site.standard.publication/y")

a_javascript_or_file_url_is_still_refused
    // The reason the function exists. Mutation: widen to "any scheme" → this
    // fails, the one above still passes. That asymmetry IS the test.

check_scheme_still_rejects_at_uris
    // net.rs is deliberately NOT changed. at:// is resolved to https first.
    // Mutation: add "at" to check_scheme → this fails, and the SSRF guard has
    // quietly grown a scheme it cannot resolve or pin.
```

### 3. Wire into the poller behind a flag, defaulting off

Same shape as `FEATHERREADER_REPO_BACKEND` in 0.3.0 — the house pattern, and it
lets the 19 existing rows be exercised in production with nothing visible to
anyone.

```rust
an_at_uri_feed_is_skipped_when_the_flag_is_off
    // Mutation: ignore the flag → the 19 rows start polling on deploy rather
    // than when someone decides.

an_unrecognised_flag_value_fails_startup
    // Matching config.rs:35's existing rule: a silent fallback makes every
    // side-by-side measurement a comparison of the default with itself.
```

### 4. Flip it on

Map to entries: `title`; `publishedAt` → `published`; publication `url` + `path`
→ `entries.url`; `description ?? textContent` → summary; the document's `at://`
URI → `guid`.

```rust
an_at_uri_feed_polls_and_stores_entries_end_to_end
    // Through the real poller path, against a stub PDS — the equivalent of
    // net.rs's two-server redirect test.

a_second_poll_of_unchanged_documents_adds_no_entries
    // guid is the document's at:// URI; dedup is UNIQUE (feed_id, guid).
    // Mutation: derive guid from `path` instead → a publication that moves a
    // path duplicates its whole archive.

a_failing_publisher_does_not_stall_the_other_sixteen
    // poll_feed already promises this for HTTP feeds. Same promise, new path.
```

### 5. Retire step 2 of the 0.4.0 roadmap

"Tell the affected reader why their 19 subscriptions are dead" is moot once they
work. If steps 1–4 slip, that step comes back — it is hours, not days.

### What this rollout does NOT prove

`caddy validate`-style scope honesty, applied here: these tests drive stub PDSes.
They establish that the client speaks the protocol correctly and handles the
measured traps. They do **not** establish that all 17 real publishers behave as
the 449-document sample did, and nothing short of step 4 will.

---

## Open questions
1. **Poll cadence.** Documents carry `publishedAt`/`updatedAt` but the repo has a
   `rev`; whether a cheap "has anything changed" check exists (repo `rev`,
   `listRecords` ordering) was **not measured**. Worst case is a full
   `listRecords` sweep per publisher per interval, which the cost figures above
   say is affordable regardless — so this is an optimisation, not a blocker.
2. **Size skew and retention.** One publisher is 1.7 MB for 97 documents
   (~17 KB each), another 11 KB for 21. Per-entry retention matters more than
   request count; worth checking the 14-day interaction before step 4, not
   before step 1.
3. **What the affected reader sees today** — superseded by rollout step 5 if
   steps 1–4 land.
