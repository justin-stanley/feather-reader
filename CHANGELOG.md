# Changelog

Engineering detail for the 0.3.x line, newest first. Covers everything since
0.3.0. Work that has landed on `main` but is not yet tagged appears under
**Unreleased**, when there is any.

Each entry says what changed, the mechanism, and — where a defect is involved —
how it was established rather than assumed. Several entries record that a test
passed while proving less than its name; those are noted, because the
measurement is the load-bearing part.

Versions are git tags (`vX.Y.Z`). A tag publishes to crates.io and ghcr.io;
deploying is separate.

---

## Unreleased

### Fixed

- **A certificate test stopped failing when the machine was busy, and the cause
  was not the machine being busy.** `the_test_ca_is_trusted_and_still_validates_hostnames`
  asserts the test CA is trusted and that a host outside the leaf's SAN list is
  still refused. It failed on the first run after a full recompile, three times
  out of three, and not under CPU load alone — which is what made it look random.

  Measured by timing the phases: building the client takes microseconds, building
  the per-hop client takes 600 microseconds, and **the first request takes 11.7
  seconds while the second takes 3 milliseconds**. The cost is
  `rustls_platform_verifier`'s first verification loading the macOS system trust
  store, which reqwest switches to as soon as an extra root is present — and the
  test CA is added under `cfg(test)`, so this is a test-only path that production
  never takes.

  The fix pays that cost once, in the helper every TLS test goes through, using a
  client with its own generous deadline. Production bounds are untouched.

  **An earlier attempt raised the per-read timeout under `cfg(test)` instead, and
  it was wrong three ways**, each found by review: the production constant became
  invisible to every test, so the assertion said to protect it protected nothing
  and setting it to an hour left the suite green; the effective relaxation was 30
  seconds rather than the 120 claimed, because the total request timeout caps it;
  and it accommodated an 11.7-second warm-up rather than accounting for it.
  Filed as #195.


### Security

- **A `listRecords` page is parsed once, not twice.** The body went through
  `serde_json::Value` and then into the typed struct, and `from_value` rebuilds
  rather than moves — so both copies are live at the same time.

  Measured on this branch with a counting allocator, before and after, on two
  8 MB pages. A page of 480 prose articles: peak 8.5 MB before, 8.2 MB after —
  a 4% saving, because long strings dominate and the wire size and the tree size
  are nearly the same. A page whose bulk is structure rather than text: peak
  256.0 MB before, 128.0 MB after — **exactly halved**, and the retained figure
  is 128 MB either way.

  So this buys almost nothing on honest traffic and halves the transient peak on
  the shapes an attacker picks, which is the only place it was ever needed.

  This is the one allocation a byte budget cannot cover, because the budget is
  charged on records that exist only once the body has already been parsed. The
  all three clients deserialise straight from the bytes, the sidecar included:
  its page arrives nested inside an envelope, so the envelope is typed too rather
  than read as a `Value`.

  The two invariants move with it rather than being dropped: an `error` present
  on a 2xx is a failure and not an empty page, and `records` **absent** is not
  `records` empty. They live in one function over one wire struct, which all
  three clients now deserialise into — the sidecar included, which means it is
  no longer the odd one out. That also makes them stricter: a duplicated
  `records` key, which a `Value` resolves last-wins and could therefore use to
  smuggle an empty page past a proxy, is a hard refusal everywhere.

  An empty body is refused with one reason across all three callers. An earlier
  draft of this entry said "the same reason it always carried", which was true
  only of the OAuth client; the direct client used to say "EOF while parsing".
  It is a unification, not a preservation.

- **The envelope guard fired only on a string `error`.** So a PDS answering
  `{"error":404,"records":[]}` walked past it and read as a healthy empty page —
  the exact shape that makes `replace_sub_refs` delete every `sub_ref` a reader
  has. Any type is an envelope now, and the field is typed as a `Value` so the
  refusal reports as an envelope rather than as "invalid type", which is the
  right reason for the one shape this guard exists for.

  Absent, `null`, `false` and `0` are the four spellings of "no error". The last
  two are a proxy convention, and treating them as envelopes would fail a good
  page of a thousand records outright. The name is also truncated before it
  reaches a log, because the PDS chooses it and the log already carries the DID.


- **Every response body in the atproto layer is now capped. Five were not.**
  `SidecarClient::repo` buffered `/internal/repo` with `resp.json()`,
  which reads whatever arrives. That endpoint proxies the account's PDS, so the
  length is chosen by a host the reader picked and we did not, and the sidecar
  is the default backend — so the one path with no byte bound of any kind was
  the one most deployments run. Both the success and error paths now go through
  `net::read_capped`, the same 8 MB ceiling the direct client has always had.
  Found by review of a change that set out to bound the *record walks* and
  missed the transport underneath one of them.

  Review of **that** fix then found four more of the same shape, two of them on
  hosts an attacker picks rather than merely influences: the DID document, whose
  host for a `did:web:` comes straight out of the DID, so whoever supplies the
  DID chooses the server; `resolveHandle`, against a resolver base this code's
  own comment calls user-influenced; and the sidecar's two session reads. The
  SSRF guard covers where those requests go, not how much comes back.

  The original entry claimed the sidecar body was capped "like every other body
  this codebase reads" and the pull request said the same of that client's
  siblings. Neither was true when written; both are now.
- **A sidecar error whose body cannot be read keeps its HTTP status.** Reading
  the body before branching on the status was the obvious shape and it swallowed
  the status on an over-cap or truncated error body, turning a `404` into a bare
  "body exceeded the cap". `xrpc_error_from` already makes the opposite choice
  deliberately, for this reason.
- **A record walk is bounded in retained bytes, across all four walks.** Every
  walk capped how many records it would accumulate, against a measured ~17 KB
  document, and `MAX_LIST_PAGES` bounds requests rather than memory. A PDS whose
  records are not that shape satisfies every count and still exhausts the box.

  The bound charges what a parsed value **retains**, not what it takes on the
  wire. A first attempt charged serialized length and was wrong by up to 42x: a
  parsed value is a tree of 32-byte nodes in vectors that over-allocate, so
  `[[],[],…]` costs three bytes of JSON and well over a hundred in memory.
  Measured against that estimate, a budget reporting 119 MiB held a process at
  5.6 GiB. Every arm now charges at least the node itself, and an object charges
  for its backing node — `serde_json::Map` is a `BTreeMap` whose leaf carries
  room for eleven pairs and is allocated whole, so a one-key object costs what
  an eleven-key one does. Charging it as an ordinary container under-reported
  object-shaped records by about half: the same failure two orders of magnitude
  smaller, caught by a later review round.

  **128 MiB of accumulation per read, which is not 128 MiB of memory.** Every
  charge is taken after the page is already built, so the true peak is the ceiling
  plus one page's tree — and a page's tree is not small: an 8 MB response of
  one-key objects retains 824 MB, 98x its wire size. A bound consulted after the
  allocation cannot prevent it. What it does prevent is accumulation across pages
  and across the walks of one read. The single-page case needs a smaller wire cap
  or a counting parser, and is filed as #197 rather than implied here.

  A caller passes one budget into every walk it makes, so a publication read —
  which runs a second walk while still holding the first's records — is bounded
  once rather than twice; two independent ceilings put about 384 MB of
  accumulation in flight. Only that one caller threads it today and it has no
  production entry point yet, so every live read still builds a ceiling per walk
  and nothing bounds concurrent requests.

  The figure differs in effect per walk, because the record caps do. The
  subscription walks cap at 20 000 records and a real subscription charges
  2 188 bytes here — 2 764 with a folder and a fetch hint — so a full repo is 42
  to 53 MB and the count binds first. That matters most on those walks because
  their verdict is a refusal, which drops the reader into the fail-closed branch.
  The publication walk caps at 2 000 documents, about 37 MB at the measured ~17 KB
  article; above roughly 66 KB per article the budget binds first and the walk
  truncates early. So it is not true that nothing truncates that did not truncate
  before, and an earlier draft of this entry said so — as it also said 64 MiB,
  30 MB and 33 KB, all of which this work has since corrected.

  The two verdicts differ. The three walks feeding `replace_sub_refs` refuse,
  since a short list there is revoked access. The publication read truncates and
  reports `complete: false`, which it already models.

### Fixed

- **Publication entries get a stable date instead of one that resets itself.** `site.standard.document`
  makes `publishedAt` optional, and an entry stored without a date takes
  `fetched_at` at insertion instead. Retention and the per-feed cap both order on
  `COALESCE(published, fetched_at)`, so an undated entry is swept once it is
  `retention_days` old, re-inserted by the next poll with a fresh `fetched_at`
  and a new `entries.id`, loses its read state to the cascade, and comes back
  unread — on that cycle, indefinitely. A document with no usable `publishedAt`
  is now dated from the TID in its record key, which is the microsecond the
  record was written.

  **This narrows the cycle; it does not end it.** A date that no longer resets
  itself is a precondition for ending it, not a cure: for a document whose write
  time is already older than the retention window, a fixed date is permanently
  past the cutoff, so it is swept on every sweep and re-listed on every poll —
  faster than before, not slower. What ends it is refusing to insert what is
  already past the floor, which belongs with the retention floor still to come.
  Nothing stores publication entries yet, so the order of the two changes is a
  sequencing requirement rather than a live defect.
- **A stated date in the future is discarded, not used.** Retention deletes rows
  older than the cutoff and the cap keeps the newest, so a document claiming the
  year 2999 was never swept and permanently held the top of the reading list.
- **`feeds.kind` is re-derived from the URL rather than translated once.** The
  column is a cache of `FeedKind::of`, and it was populated by a one-time SQL
  `UPDATE` carrying its own copy of the rule as a string predicate. That
  translated `rss` to `publication` and never the reverse, so a row whose stored
  kind disagreed with its URL in the other direction stayed wrong permanently:
  an http feed marked as a publication is excluded from every poll, forever,
  and nothing re-reads it. The classification is now asked of the Rust function
  on every start, in both directions, and `upsert_feed`'s conflict clause
  carries `kind` so re-subscribing re-derives it too.
- **Taking a feed out of the poller now clears the poll state it orphans.** A
  backoff horizon and an error count belong to a row the scheduler selects; on
  one it will never select again they are hidden from `/stats` and the cause
  histogram, which filter on kind, so they rot unseen — and a later rule change
  that readmits the row resumes it at a backoff earned under a classification
  that no longer applies. Seven prior errors meant a first retry ten hours out
  instead of five minutes.
- **An unreadable `feeds` row no longer stops the process from starting.** The
  re-derivation runs on the boot path, and reading `url` as text turns a row the
  old SQL predicate evaluated happily into a hard startup failure — trading a
  wedged poller for a site that will not come up, and on a deploy, a failed
  health gate. Such a row is skipped with a warning instead. Nothing this
  codebase writes can produce one; reaching it means the file was edited by
  hand, which is precisely when refusing to boot helps least.
- The string predicate is gone. It agreed with `FeedKind::of` on the day it was
  written and had no way to notice if it stopped — which is how one reader came
  to drift from it unnoticed, recorded in this file at the time. Its reasoning
  moved onto `FeedKind`, which is where the question is now asked.

### Added

- `atproto::decode_s32_tid`, the inverse of the existing encoder, and
  `tid_timestamp`, which refuses a TID decoding far into the future or to before
  atproto existed, with five minutes of grace for a PDS whose clock runs ahead
  of ours.
- Those bounds are **not** a slug detector, and a test now says so by name.
  Thirteen lowercase alphanumerics is an ordinary filename shape and also a
  valid `s32` value, so `3hoursinparis` reads as 2020-11-24 and `3ideasforjune`
  as 2021-08-12, indistinguishable from record keys written then. Telling them
  apart would mean asking the PDS when the record was written, which the listing
  does not report. What the bounds do guarantee is that a mis-read date is an
  ordinary past instant rather than an unsweepable future one — worth having,
  and not harmless: a slug reading as 2020 is older than any realistic retention
  window, so the row is swept, re-listed on the next poll, and arrives unread
  again. That is the cycle the retention floor closes, for a mis-read slug and a
  genuine archive alike.

### Tests

- **Dating**: fourteen, each mutation-checked, taking the library suite from 859
  tests to 873. One of them pins a store invariant the change rests on: an
  upsert refreshes `published` from every poll but never refreshes `fetched_at`.
  It was not pinned before, and it is the reason the fix is what it is.
- **Classifier**: six more, all mutation-checked, two of them red first — a kind that
  disagrees with its URL is corrected in either direction, and a second
  subscription to the same URL re-derives rather than preserving. Four mutations
  (reverting to a one-directional back-fill, disabling the write, dropping
  `kind` from the conflict clause, and preserving the stored value there), each
  killed by one of them. Four more for the operational findings: leaving
  orphaned poll state, keeping `next_poll` on an unpollable row, aborting the
  boot on an unreadable row, and abandoning the pass at one.
- The suite stands at **906 tests**: 903 pass, two are ignored, and one is the
  load-sensitive TLS failure filed as #195. Measured on the merged branch, not
  carried forward — drafts of this line have said 877, 884, 885, 888, 889, 891
  and 893, none of them measured when written.


- **A mock that serves a different body per request**, which this suite did not
  have. The fixed-body servers answer every request identically, so a paging
  walk sees the same cursor twice and its repeat-detection guard stops it at two
  pages — which makes anything that only happens *across* pages unreachable.
  That is how a cap that was per-page rather than per-walk, and therefore 200x
  weaker, once passed an entire suite unnoticed.
- Eleven for the walk budget, each mutation-checked. One asserts against heap
  figures that were taken with a counting allocator, which is what catches an
  under-charge the node-count property cannot see — but it hardcodes them rather
  than measuring, so it is a tripwire for the estimate changing and not for the
  real cost changing. Another computes that a full subscription repo fits the
  budget twice over, which is the calculation a reviewer found stated wrongly in
  a comment because nothing computed it.
  Twenty mutations, all killed by a named test — including the five from the
  second review round and the two from the third. One is not: `standard_site::fetch`
  passing a single budget to both its walks is unpinned, because reaching it needs
  a mock serving the PLC directory and two collections. The sharing mechanism is
  pinned; that one call site is not. The rest: the per-page budget in each of the four walks, dropping the
  recursion into arrays and into objects, charging scalars nothing, the
  exact-fit fence-post, a refusal resetting the running total, an uncharged uri
  and cid, removing the check from the live walk entirely, charging a map as an
  ordinary container, and halving its backing node.

### Corrected in review

Four defects in the first version of this change, all found by review before it
merged and all recorded here rather than quietly rewritten.

- **The first fix clamped a future date to "now". That was wrong**, and the
  reason is the invariant above: `published` is rewritten on every poll, so a
  clamped row is re-dated to the current hour forever. It can never age past the
  retention cutoff, can never be outranked in the per-feed cap, and sits at the
  top of the reading list showing today's date. Clamping moved the defect and
  made it harder to see — the literal `2999` was at least a visible symptom.
  A non-credible date is now discarded like an unparseable one, falling through
  to the record key and then to undated; every one of those values holds still.
- **Two tests named for the rkey fallback passed with the fallback deleted.**
  Both minted a fresh TID and asserted the result was "about now", which any
  source of the current time satisfies — including a fallback replaced outright
  by `Utc::now()`. Both now use a fixed record key from a real repo and assert
  the exact instant it decodes to. Three further mutations that survived the
  original tests die against the new ones.
- **A round-trip test cannot catch a consistently wrong alphabet.** Swapping two
  `s32` symbols round-trips perfectly and misreads every real record key. The
  decoder is now pinned to a known answer computed outside this code.
- **`the_decoder_rejects_rkeys_that_are_not_tids` claimed more than it proved.**
  The decoder accepts any 13-character `s32` string, slugs included; refusing an
  implausible instant is `tid_timestamp`'s job. Renamed, and the function's own
  doc comment corrected to match. The end-to-end test now covers a slug-shaped
  key as well as a punctuated one, so the bound is exercised through the mapper
  and not only as a unit.

Two wrong numbers in the first draft of this entry, both since computed rather
than estimated: the slug `abcdefghijklm` decodes to 2192, not 2183, and a TID's
leading character is `3` between 2005-09-05 and 2041-05-10, not 2004 and 2038.

### Corrected in a second review round

A cold pass over the corrections above — the one commit nobody had read — found
four more. The first version of this entry claimed the slug bound stopped slugs
from being read as dates; it stops only those landing outside 2020-to-now, which
is a minority of them. It claimed publication entries "stop resurrecting"; for a
document older than the retention window the cycle gets faster, not slower. A
doc comment for an unrelated store test was captured by the test inserted above
it, leaving that test undocumented and this one described by a paragraph about
`If-None-Match`. And `Entry.published`'s own field comment still described the
old rule, in a change whose review discipline is precisely that.

### Corrected in a third review round

- **One clock, two answers.** The five-minute skew allowance was written for the
  record key only, so a stated `publishedAt` was judged against a bare `now`. A
  publisher whose clock runs a few seconds ahead had a perfectly good date
  discarded, and with a slug-shaped record key the entry was then stored
  undated — which, ordered on a bare `published DESC`, buries the newest post at
  the bottom of the list. Both sources now share one ceiling, and the constant
  is no longer named after TIDs.
- **A comment contradicted the entry above it.** `TID_FLOOR_MICROS` claimed a
  mis-read date "costs a reader ordering and nothing worse", which is false for
  exactly the slugs the same comment says will be misread: one reading as 2020
  is past any realistic retention window, so it costs repeated loss of read
  state. The changelog said as much two paragraphs away. The in-code comment is
  the one a future reader consults when deciding whether the floor is still
  needed, so it was the more damaging of the two.

### Considered and declined

A third finding asked for a lower bound on stated dates, since `1970-01-01` is a
routine "missing date" default from static-site generators and lands permanently
past the retention cutoff. Declined: the cycle it describes is driven by the date
being older than the retention window, not by it being wrong, so a floor would
have to reject genuine archive content to catch the garbage — trading a known
limitation for real data loss, and making the rejected entries undated and
therefore invisible. The ingest floor closes both cases at once and is the right
place for it.

### Known, not fixed here

- **The walk budget is per-walk, and walks nest.** `standard_site::fetch` holds
  the publication walk's records alive while the document walk runs, and the
  login path runs four list walks and retains all four results, so the real
  process ceiling is a multiple of one walk's budget. The constant's own doc
  calls it "the memory one walk may retain", which is accurate and easy to
  over-trust.
- **A page is charged only after it has been materialised.** The refusing walks
  charge the whole page and the truncating walk now refuses any single page
  larger than the budget, so the transient is bounded — but it is bounded after
  the allocation, not before it. Bounding it earlier means not parsing the page
  until its size is known, which is a change to the transport rather than to the
  walk.

- Admitting a new kind to `FeedKind::POLLABLE` makes a whole population of rows
  due at once: `due_feeds` sorts unscheduled rows ahead of every scheduled one,
  and rows that were never pollable have no schedule. Measured at a batch of
  fifty, a block of N such rows outranks every regular feed for `ceil(N / 50)`
  ticks while `/stats` shows a climbing backlog and nothing logs why. Bounded
  and harmless at ninety feeds, not at ten thousand. A note on `POLLABLE` says
  so; seeding or staggering `next_poll` belongs with the change that admits the
  kind.

- An undated entry is the newest row in the feed to the per-feed cap and the
  oldest to the reading list, which orders on bare `published DESC` where SQLite
  sorts NULL last. It is therefore safe from eviction and invisible to the
  reader at the same time. Pre-existing, affects RSS equally, filed as #187.
- The same future-date hole is still open for RSS, where `feed::entry_time` has
  no upper bound at all. The guard landed in the atproto mapper rather than in
  the shared layer that would cover both paths. Filed as #188.

---

## 0.3.8 — 2026-09-20

Fourteen PRs. Two additive nullable columns, no `fly.toml` change, one new
config flag (`FEATHERREADER_STANDARD_SITE`, off by default, gating storage
only).

**The headline is not a feature.** Six of the fourteen changed no behaviour at
all: they replaced 35 tests that stayed green with the code they named deleted,
each found by mutating the implementation and watching the suite pass. A
seventh added CI validation, and an eighth changed only a type bound.

This file's preamble says entries should record where a test proved
less than its name; most of this release is that.

### Security

**A vacuous test is a guard nobody would notice breaking.** Each of these
stayed green against the *whole* suite with the code it names removed:

| guard | the mutation that passed | what it hid |
|---|---|---|
| `guarded_get_no_redirect` | follow `MAX_REDIRECTS` instead of `0` | OAuth metadata, `plc.directory` and `did:web` documents read from wherever a `302` points, while `issuer` is compared against the URL that was asked for — the authorization-server mix-up defence |
| per-hop privacy re-check | check the first hop only | a public feed `30x`-ing to a tokened Substack/Patreon URL is fetched and streamed into the UI before storage refuses it |
| add-path privacy gate | *(no test existed)* | a token-bearing URL reaches the network on subscribe |
| rate limiter | key on `X-Forwarded-For` | unlimited `/login` and `/beta/redeem` by rotating one header value |
| CSP | `default-src * 'unsafe-inline'` | the XSS backstop gutted |
| `mark_cursor_pds_created` | delete its `WHERE` | every DID's cursors flagged as created, so their readState records are never created and every later flush updates nothing |
| session AAD | drop the column from the binding | `access_token` ↔ `refresh_token` swapped inside one row, both still authenticating |

Each is now driven through the real route or client and asserts on something
the mutation changes — a request log that must be empty, the bytes a client
sent, a bystander row that must not move (#170, #171, #172, #173).

**The generic write primitives are private, and the 0.3.7 entry below
overclaimed.** That entry says "the eight low-level writers across both backends
demand the vetted type" and backs it with three compiled bypasses. Two things
were wrong with it when it shipped, and they are corrected here rather than
edited there, because the shipped record should show what was believed at the
time.

First, there were nine writers, not eight: `SidecarClient::create_subscriptions_batch`
took a raw `&[Subscription]` straight into `applyWrites`. It had no callers and
so drew no attention. Deleted (#169).

Second — and this is the general case the first was one instance of —
`create_record`, `put_record` and `apply_writes` are generic over
`T: Serialize`, and `lexicon::Subscription` derives `Serialize`. Any handler
holding `state.sidecar` could write an unvetted record through them with no
more effort than the deleted function required. Verified by compiling it.

Those three are now **private** on `PdsClient` and `SidecarClient`. Not
`pub(crate)` — that was the first attempt, and a self-review caught it stopping
nothing that mattered: a handler in `web.rs` is in this crate. Both were
verified by compiling a probe from `web.rs`:

```
pub(crate)   builds clean          — the handler can still write unvetted
private      3 "private method" errors
```

The three on `oauth::xrpc::Repo` stay `pub`: `examples/oauth_spike.rs` is a
separate crate target and drives them against a scratch collection. So a
handler in this crate can still write an unvetted record through the OAuth repo.
**Narrower than before, not absent.** Ending the class means removing
`Serialize` from `lexicon::Subscription`; that needs a hand-written impl for
the `#[serde(transparent)]` `VettedSubscription` plus a wire-format test, and
was tracked rather than done — **closed later in this release by #178**, which
gets the same guarantee from a sealed trait instead, leaving the derive alone.

The claim "there is nothing to hand them that skipped the check" has now been
wrong in three consecutive corrections. Each enumerated what was in front of it
and described the result as the population.

**An unvetted record no longer type-checks** (#178). The 0.3.7 entry below
claimed this; the correction under it narrowed the claim to "narrower than
before, not absent" and named removing `Serialize` from `lexicon::Subscription`
as the way to end the class — then recorded that as blocked, because
`VettedSubscription` is `#[serde(transparent)]` over it and a hand-written impl
could silently migrate every reader's repo.

`vetted::WritableRecord` is a **sealed** marker trait: implementing it requires
a trait private to that module, so its implementors are the whole list — the
vetted wrappers, plus `Folder` and `ReadState`, which carry no field rendered as
an href. `create_record` and `put_record` take that bound, so
`create_record(nsid::SUBSCRIPTION, &raw_subscription)` no longer compiles, and
the wire format still comes from one derive.

The evidence is a `compile_fail` doctest, which CI runs. A `compile_fail` that
passes for the wrong reason is the trap here, so it is mutation-checked: adding
`Subscription` to the implementor list makes its snippet compile and the doctest
fails.

`apply_writes` stays reachable — `WriteOp::Create.value` is a
`serde_json::Value`, so a hand-built record goes through. That is a deliberate
two-step rather than an accidental one-liner, and `repo.rs` now names it instead
of implying the class is closed.

**The OPML upload cap is the route's own** (#176). `OPML_BODY_LIMIT` was exactly
2 MiB — axum's `DefaultBodyLimit` — so the route's layer was a no-op, and the
test named for it was really testing axum. Lowered to 1 MiB, which is the
direction that makes the layer mean something: raising it above the default
would have made it testable by *weakening* the bound. One outline is ~92 bytes,
so 1 MiB carries ~11 000 of them against a per-DID cap of 500 the import trims
to anyway. A compile-time assertion keeps it under the framework default.

### Added

**`/stats` says WHY feeds are failing, and `/admin/metrics` says which**
(#166). `feeds` recorded `consecutive_errors` and nothing else, so a systematic
defect across sixty feeds was indistinguishable from sixty dead blogs — which is
exactly what 0.3.7's #159 was. `PollOutcome::Failed` now carries a closed
`FailureKind` (`fetch | status | body | parse`) and a detail capped at 300
characters, in two additive nullable columns.

The public page gets a cause histogram: counts only, never which feed and never
whose. Had it existed, #159 would have read `60 fetch` on a page anyone could
load. Rows that predate the columns, or carry a kind this build does not know,
fold into `unknown` rather than vanishing — so the breakdown always sums to the
`Failing` figure beside it. `/admin/metrics` (ALLOWED_DIDS only) names the
failing feeds with kind, detail and count.

**standard.site publications, dormant** (#164, #165). `FEATHERREADER_STANDARD_SITE`
(default off) lets an `at://…/site.standard.publication/…` subscription be
**stored** — one arriving by OPML import or written by another client. The
subscribe form cannot take one: the add path must fetch what is pasted and
nothing fetches `at://`.

Nothing polls one either, and that is by exclusion rather than by the flag:
`due_feeds`, `/stats`, the admin list and a boot-time clearing all share one
predicate, so an `at://` row is **skipped, not failed**. Handing one to the
poller would manufacture a permanent failure per row and publish it as an
unreachable publisher — the conflation the cause histogram exists to end. The
19 such rows on this instance predate the scheme check and are cleared by a step
that touches only rows never polled successfully.

`src/standard_site.rs` reads a publication and its documents (#165), reusing
everything that makes the fetch safe rather than rebuilding it. Only
`textContent` / `description` are read — `content` is an open union, six
wrappers and twenty-two block types across 449 measured documents — and they are
**escaped, not sanitised**: both are plain text, and `ammonia::clean` parses its
input as markup, so `"if x<y then z"` comes back as `"if x"`. Documents are
filtered by the URI the PDS minted, the guid is the record URI rather than the
mutable `path`, and a walk that stops early says so. **Not wired to the poller**
— that is the next release.

### Fixed

**A feed failing its first fetch is now backed off** (#166). The scheduler
bumped the error count *and* wrote `next_poll`; the direct poll on subscribe did
only the first, so the backoff the counter implied was never applied — the
scheduler picked the feed up on the next tick anyway, because a NULL `next_poll`
is due. Both callers go through one settle path.

**A `listRecords` walk is bounded by records, not just pages** (#168). The page
cap bounded requests; a server ignoring `limit=100` could still return
gigabytes. `extend_bounded` refuses past 20 000 records rather than truncating,
because its caller feeds `replace_sub_refs` — where a short list is revoked
access, not a short list.

**A 2xx carrying an error envelope is not an empty page** (#165). `records` is
`#[serde(default)]`, so `{"error": …}` on a 200 deserialised as zero records —
and on the OAuth path that reaches `resolve_subscriptions` as "this DID follows
nothing", which `sync_sub_refs` writes through, deleting the reader's whole
`sub_ref` projection. One shared parse now enforces both invariants (no error
envelope, `records` present) for all three clients, and the four write paths
refuse an envelope too. An empty body is refused for the same reason.

### Tests

Thirty-five vacuous tests replaced or retired across #170–#175, each proven by
breaking the implementation and showing the suite still passed. Besides the
security guards above: six `store.rs` queries that passed with their `WHERE` or
`ORDER BY` deleted — including a starred-entry trim that, with its ordering
flipped, spares the *oldest* starred articles and evicts the newest on every
poll; bulk-write tests that built the `applyWrites` ops themselves and never
called the function; a `ReadState` cap that was unit-tested but never proven to
be applied; OPML escaping exercised only on the display label.

Three pieces of dead code were deleted rather than tested: a `did:web`
IP-literal branch whose every case the numeric-TLD rule already refused, a host
conjunct in `is_storable_feed_url` that no input could reach, and two sort
helpers left behind by tautological tests. Two of the hunt's own findings were
wrong, and saying so is the point: both were verified by probe before anything
was removed.

### CI

`deploy/Caddyfile` is validated against both OAuth routings (#161), so a syntax
error or a routing change that breaks one of them fails the build rather than
the deploy.

---

## 0.3.7 — 2026-09-19

Eight PRs. No features, no schema change, no `fly.toml` change. One config
change — the Caddy log filter — which is baked into the image and so takes
effect on deploy, not on the running machine.

**The headline is #159:** the poller was recording "nothing new" as a failure,
which is most of why 68 of 111 feeds read as failing on `/stats`.

### Security

**The unvetted record write no longer type-checks** (#150, closes #140 and
#142). 0.3.6 routed every subscription write through a vet and made the
macro-generated writers private, but the layer below stayed reachable:
`AppState.sidecar` is a `pub` field and both `SidecarClient` and
`oauth::xrpc::Repo` expose their own writers. The 0.3.6 entry below records that
honestly as "the vetted path, not the only possible path" — a convention, and
#138's own argument is that conventions are worth what their tests measure.

`src/vetted.rs` now holds `VettedSubscription` and `VettedSaved`, in their own
module for the `safe_link.rs` reason: a private field is private to the MODULE,
and `repo.rs` is where every record write is assembled, so a type declared beside
its own constructor would be forgeable again. The eight low-level writers across
both backends demand the vetted type.

Verified by writing the bypass out and compiling it:

```
before                                      after
state.sidecar.add_subscription(did, sub)    error: expected `&VettedSubscription`
state.sidecar.add_saved(did, saved)         error: expected `&VettedSaved`
xrpc_repo.add_subscription(sub)             error: expected `&VettedSubscription`
```

`VettedSaved` is fallible where `VettedSubscription` is not, and the asymmetry is
forced: `url` is required on `community.lexicon.rss.saved`, so unlike an optional
`siteUrl` there is no honest resting place for a rejected value.

**The reader view's two `href`s take a checked type** (#152, closes #115).
`EntryTemplate.url` was a raw `Option<String>` assigned straight off the
`entries.url` column — a remote feed's `<link>`.

```
before   url: Option<String>     any non-empty string reaches both `href`s
after    url: Option<SafeLink>   http/https only; None takes the no-link branch
```

Not a live hole — `feed.rs`'s `entry_link` scheme-checks at ingest, and that
wiring is tested. What made it worth doing is that the guard is procedural and
sits a long way from the `href`: it holds only while every future writer to
`entries.url` remembers to route through `feed.rs`, which is the same shape of
defence that, on the saved-record row, turned out to be deletable with a green
suite.

One user-visible narrowing, deliberate: a stored URL with any other scheme now
loses its link, relative URLs included. `feed.rs:707` is the only production
writer to that column and there is no `UPDATE` touching it, so only a pre-0.2.7
row can be affected — and a stored `/foo` used to render as a same-origin link
into the reader app rather than to the article, so the refusal is a fix.

Established by mutation: `external_opt` forced to `Some`, forced to `None`, and
the whole wiring reverted — each in isolation, each `745 passed; 1 failed`, the
single failure being the new test every time. The render side had no other
coverage, which is the issue's claim, now measured rather than asserted.

**The OAuth authorization code and `state` are redacted from the access log**
(#155). The Caddy log filter redacted two headers and left `uri` alone, so every
`/oauth/callback` line carried the PDS's single-use `code` and the `state` that
binds it to the pending row, verbatim — into `fly logs`, any drain, and the
scrollback of anyone tailing the app.

```
before   "uri": "/oauth/callback?state=SENTINEL_STATE_VALUE&code=SENTINEL_CODE_VALUE"
after    "uri": "/oauth/callback?code=REDACTED&iss=https%3A%2F%2F…&state=REDACTED"
```

Not an open hole: the code is one-shot and the exchange also demands the PKCE
verifier, a DPoP proof and `private_key_jwt`, so a reader of the logs cannot
replay it. But the argument for redacting `X-Origin-Auth` — already made at
length in that file — is the argument for redacting these.

`replace` rather than `delete`, matching the existing reasoning: the field
survives with its value gone, so a failed callback still shows which parameters
arrived. `iss`, `error` and `error_description` are deliberately untouched —
they are not secrets and are most of the diagnostic value of those lines.
Applied to **both** log blocks, because `origin_errors` is a separate logger that
inherits nothing from the site log.

Verified against caddy v2.11.4 — the version the pinned `caddy:2-alpine` digest
resolves to, read from the image config blob — by running the config and probing
the callback with sentinel values, with a negative control confirming the probe
can fail.

### Fixes

**A `304 Not Modified` was read as a malformed redirect, failing every unchanged
feed** (#159). `guarded_get_inner` gated its redirect branch on
`is_redirection()` — `300..=399`, which includes 304. A 304 carries no
`Location` by definition, so it fell through to *"redirect response without a
usable Location header"* and failed the whole fetch. `feed.rs` sends
`If-None-Match`/`If-Modified-Since` on every poll and has a correct 304 branch
that was therefore **unreachable**.

The effect: "nothing new" became a recorded failure. `consecutive_errors`
bumped, `touch_polled` never ran, the feed backed off exponentially — so the
feeds punished hardest were the ones implementing conditional GET *properly*,
and the quieter a feed was the more it was ignored.

```
before   9to5mac.com/feed/ -> HTTP 304 -> "redirect response without a usable
                                           Location header" -> error, backoff
after    9to5mac.com/feed/ -> HTTP 304 -> PollOutcome::NotModified, normal cadence
```

Found from production logs, against `9to5mac.com`, `proton.me` and `kodi.tv` —
all live and serving. `/stats` reported 68 of 111 feeds failing while its own
copy explained them away as "usually gone rather than flaky". **The metric had
inverted:** a backing-off feed leaves the backlog smaller, so the dashboard
improved as the bug spread, which is why it went unexamined for so long.

Only 304 is carved out; every other `3xx` stays inside the branch, because
`guarded_get_no_redirect` documents that it "refuses redirects outright" and the
OAuth mix-up defence rests on that. Of the relocating statuses only
`301|302|303|307|308` are followed — the rest are **refused rather than
returned**, since `web::resolve_feed_url` reads the body straight into feed
autodiscovery without checking the status, so a `305` error page carrying a
`<link rel="alternate">` could otherwise have become a subscription. That also
makes `305` stricter than before: it carries a `Location`, so it used to be
*followed*, routing the request through a proxy the response chose.

Confirmed red first and again after review restructured it: mutating the guard
back to a bare `is_redirection()` fails the new 304 test and nothing else — 44
passed, 1 failed — so this path had no coverage at all. The test asserts the hop
count as well as the status, because returning the 304 while still looping would
satisfy a status-only assertion and re-fetch every unchanged feed.

**Not fixed here:** `feeds` stores `consecutive_errors` and no error text, which
is why a systematic failure across sixty feeds was indistinguishable from sixty
dead blogs.

**A rename no longer destroys four fields of the subscription record** (#147,
closes #141). `update_subscription` is a `putRecord`, and a putRecord replaces
the whole record. The handler built a fresh
`Subscription::new(feed_url, now_rfc3339())`, so every field the form does not
carry was written back as its default — and `manage_row.html` posts `url`,
`title` and `folder`, nothing else.

```
field        stored value                    after a rename, before this fix
siteUrl      whatever the feed advertised    gone
fetchHint    as set                          gone
private      as set                          gone
createdAt    original subscribe time         reset to now
```

Four fields, not the three #141 names — `private` is the one the issue missed,
because `Subscription::new` sets it to `None` and the handler never assigns it.
`createdAt` is the worst of them: it is the reader's subscribe time, the sort key
for "when did I subscribe", it lives in *their* repo rather than our cache, and
once overwritten it is gone with nothing in the UI to say so.

Now a read-modify-write. There is no single-record read on `Repo`, so this lists
and filters by rkey; a `get_subscription` drops in behind the same handler logic
if it ever measures badly.

### Test and CI integrity

**Three capture-based tests now mean what their names say** (#148, closes #144
and #146). Test-only; no production behaviour changed.

- `spawn_http` reads to content-length instead of a single 8 KB read, so the
  negative assertions over the capture can no longer be satisfied by truncation.
  A positive anchor on the cross-origin credential test makes an empty capture
  fail loudly.
- A contended sweep is reported as `Contended` rather than an error, matching
  what `scheduler.rs` already does in production. `is_sqlite_busy` masks with
  `& 0xFF` so the WAL extended codes (261/517/773) classify correctly, and
  `a_non_busy_sweep_error_still_fails` stops the tolerance widening again.
- `the_public_jwk_and_jwks_never_contain_the_private_scalar` asserted against a
  literal from a *different* key, so it could never match; now derived from the
  key under test.

### Documentation

- **The comment describing the unvetted-write bypass is corrected** (#154). It
  still said `Repo` is "the vetted path, not the only possible path" and pointed
  at #140 as open, after #150 had closed it — directing a reader to guard
  something the compiler already guards, and advertising a surface that no longer
  exists. Also corrects `AppState.sidecar`'s field doc, which called the sidecar
  "the live repo-op path" after the 2026-09-13 cutover selected `rust`.
- **`Choosing an OAuth backend` gains the measured comparison, and the process
  count is made honest** (#156). Production `/admin/metrics` latencies for the
  three operations both backends have run, stated with their limits: the two were
  measured *sequentially*, not side by side — `sidecar` before the cutover,
  `rust` after — over different weeks and a different cache size, with small and
  unequal samples. Separately, the runtime heading said "three processes"
  unconditionally, which has been false on `rust` since the cutover, and
  contradicted "Build & run"'s "one or two" eleven lines later; the two counted
  Caddy differently and neither said so. The diagram itself needed nothing —
  `runtime.mmd` was updated at the cutover and already marks the sidecar
  conditional.

---

## 0.3.6 — 2026-09-19

Four commits. No features, no schema change, no config change.

### Security

**`siteUrl` stored-XSS class, closed at both boundaries.** The two halves
landed separately and neither is sufficient alone.

- **Write side** (#138, closes #114). `siteUrl` reached the
  `community.lexicon.rss.subscription` record on the user's PDS with no scheme
  check. This was never an XSS against our own UI — nothing in `templates/`
  renders the field. The exposure is that we are the *writer*: a feed serving
  `<link>javascript:alert(1)</link>` got that string published into the user's
  own repo, under their authorship, into a field the lexicon invites other
  clients to render as a link.

  The check sits at the write boundary rather than at each ingest. That is a
  trade, not a free win — a guard at ingest is safe against every future sink
  and exposed to a new ingest; a guard at the exit is the mirror image. The
  writers are enumerable and closed, the ingests are open-ended.

  The three writers are private `*_unvetted` methods behind wrappers of the
  same name. That makes `Repo` the vetted path, not the only possible path:
  `AppState.sidecar` is a `pub` field and the low-level writers are public, so
  a handler can still take the short path. Nothing does. #140 tracks the type
  that would make it a guarantee.

- **Read side** (#143, closes #139). OPML export emitted `htmlUrl` XML-escaped
  but not scheme-checked, from records read back from the PDS — so a hostile
  record written by any other atproto client became a `javascript:` URL in a
  file the user downloads and imports into some other reader. We were still the
  publisher of that file. A `deserialize_with` on the field closes it at the
  point a record crosses into the process, which also cleans the `feeds` cache
  row fed from the same read.

Together: a `Subscription` that entered this process from outside cannot carry
a `javascript:` URL, and one leaving for the PDS cannot either.

Still uncovered, deliberately: `feeds.site_url` written by the poller
(`feed.rs`), which builds `NewFeed` straight from `feed_metadata` and never
constructs a `Subscription`. Not a sink today — verified, no template
references it — so hygiene rather than exposure.

### Behaviour changes

- **A scheme-less `siteUrl` is now dropped rather than published.**
  `net::safe_link` requires an absolute URL, so `htmlUrl="www.example.com/blog"`
  — not unusual in OPML exported by other readers — becomes `None` on import.
  Consistent with how entry links have always been treated; the alternative
  invents a scheme the file did not carry.
- **Round-trip fidelity is deliberately lost.** Reading a record holding a
  hostile `siteUrl` and re-putting it rewrites it cleaned rather than
  preserving another client's payload. That heals the user's repo instead of
  propagating someone else's script URL.

### Tests

- **A TLS test CA, closing an adapter gap in the login callback** (#122). The
  OAuth issuer must be `https` and the SSRF guard refuses loopback, so nothing
  could drive the real `login::complete` against a local server — the wiring
  between its tested core and the network had no coverage at all, and all three
  forwarding steps survived mutation with a green suite. The
  authorization-server mix-up defence could be disarmed by editing one line in
  `complete`.

  A test CA *satisfies* the `https` rule rather than suspending it. No
  `danger_accept_invalid_certs`; one root is **added** under `#[cfg(test)]`,
  built-in roots stay, chains validate, hostnames match SANs. `test_pki()` is
  itself `#[cfg(test)]`, so removing the attribute fails to compile rather than
  silently trusting an extra root. `rcgen` is absent from the production
  dependency graph.

### Dependencies

- `base64` 0.22.1 → 0.23.1 (#124).

---

## 0.3.5 — 2026-09-17

Fifteen commits. No features, no schema change, no config change.

### Security

- **The SSRF guard could be bypassed by ambient proxy configuration** (#132).
  reqwest defaults `auto_sys_proxy: true` and no client in this repo called
  `.no_proxy()`. With `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` in the
  environment, requests went to a proxy — absolute-form `GET http://host/path`,
  or `CONNECT host:443` — for the *proxy* to resolve the hostname.

  Measured before the fix: vetted pinned server 0 requests, proxy received the
  request, result `Ok(200)`. It failed **open**, silently, on both schemes.

  Precisely what breaks: `resolve_and_check` still runs its own lookup and
  still rejects forbidden IPs — the check is not skipped. What a proxy destroys
  is the *binding* between the vetted address and the connection, because the
  proxy re-resolves the name on its own network. DNS rebinding, split-horizon
  DNS and anything reachable from the proxy all come back.

  `.no_proxy()` on all four production clients. The `AppState` one is
  load-bearing on its own — hyper-util's matcher has no localhost exemption, so
  an ambient proxy would have shipped `SIDECAR_INTERNAL_SECRET` to it on every
  sidecar call.

- `rustls` 0.23.45 for RUSTSEC-2026-0285.

- `fastify` 5.12.3 and the atproto client packages (#125), clearing four
  published high-severity advisories including an auth bypass. `npm audit`
  reported zero at every severity throughout, because those advisories live
  only in GitHub's repo-level database.

### Fixes

- **An equal-valued truncated observation must not downgrade the row** (#136).
  The upsert guard used a strict `<`, so a truncated observation whose value
  merely *equalled* the stored one still rewrote the row, flipping `truncated`
  from 0 to 1. A complete walk recording 2 000 followed by a budget-truncated
  walk that also counted 2 000 degraded `/about` from "2 000" to "at least
  2 000" with no change in actual adoption. `<=` is what the doc comment
  directly above already promised. Verified by reverting only the SQL and
  watching the new equal-case assertion fail, not by reading it.

### Test and CI integrity

No runtime behaviour change in this section, but the measurements are the point.

- **The sidecar's 71 tests gated nothing** (#134). Every other CI job runs its
  suite; the sidecar job went install → build → typecheck → lint → format →
  audit. An `npm test` failure could not fail a PR, and had not been able to
  for as long as the job existed. Those tests cover the parts with no other
  safety net: session-store encryption and the plaintext migrate-on-read path,
  the reaper's TTLs, `StoreError` op tagging, and `purgeDid`. The same change
  stops reading a green `npm audit` as an all-clear.

- **`login::start` had no test** (#135). Every guard in `complete` had one; this
  half had none, because it needs handle resolution, discovery and a PAR
  endpoint over the network. Five decisions were unfalsifiable and every one
  fails *silently* — the login breaks later, at the authorization server, for a
  reason nothing local explains. `start_with` injects the three boundaries, and
  every decision is made in `start_with` rather than in the caller's closures,
  because an argument assembled inside an adapter is invisible to a test.

- **Mutation-confirmed bad tests, and the scheduler seams behind them** (#127).
  Tests that passed while proving less than their names, each confirmed by a
  mutation that left the whole suite green. The blocker found by cold review:
  `spawn_starts_every_registered_loop` never called `spawn` — filtering
  `PendingSweep` out of the callback passed 697 lib + 13 bin tests and clippy
  while the pending-login sweeper never started and nonce rows grew unbounded.
  The fourth form of that file's recurring defect, added by the round that
  closed the third.

- **Three SSRF enforcement gaps** (#120). The guard's *decision*
  (`is_forbidden_ip`) was well covered; what carries that verdict to the socket
  was not. Per-hop revalidation, cross-origin credential stripping and
  multi-answer DNS each had a mutation that left 679 tests green. None was
  testable end to end because a local test server is on loopback, which the
  guard correctly refuses. The seam is a `#[cfg(test)]` host override — not a
  parameter, env var or feature flag, so the compiler removes it and there is
  no runtime bypass to reason about.

- **Two flaky tests fixed by measuring the right thing**, not by loosening
  thresholds:
  - the sweep-lock test counted refusals against attempts rather than elapsed
    wall-clock (#130). Under 4× CPU saturation the writer task simply did not
    run for 320 ms and the old wall-clock form counted that as a held lock —
    622 of 626 attempts had actually landed. A starved writer makes no
    attempts; a held lock refuses them.
  - the invite bot's mint-window test read the clock twice (#133). `now()` is
    whole seconds; `record_mint` stamped at one instant and `count_mints_since`
    computed its cutoff at a later one, so crossing a second boundary between
    them dropped rows written moments earlier. It failed CI on a base64 bump
    that cannot touch it — the bot is a separate workspace.

### Dependencies

- `reqwest` 0.13.5, `askama` 0.16.1 (#123); Swatinem/rust-cache (#99); the
  actions-minor-patch group (#126).

---

## 0.3.4 — 2026-09-13

- **Park unflushable read-state instead of retrying it forever** (#118, closes
  #117). A dirty `read_cursor` whose DID has no `oauth_session` was re-attempted
  every round forever — no cap, no backoff, no terminal state. That produced 20
  failures in 20 minutes in production and would have masked real failures for
  the whole soak window.

  Landed as a characterization test first, which **passed on the unfixed code**:
  it pins the defect's exact shape rather than the fix's, and the fix inverts
  its assertions. A second test established that sign-out can strand unflushed
  read-state — `revoke_everywhere` deletes the `oauth_session` unconditionally,
  with no flush first and no clearing of dirty flags that can no longer be acted
  on — which moved that path from hypothesis to reachable. Whether it is what
  happened in production remains unknown; the log buffer had rolled past the
  window.

---

## 0.3.3 — 2026-09-13

- **OAuth backend flipped to Rust** (#110). The in-process Rust atproto OAuth
  client takes over `/oauth/*` and every `com.atproto.repo.*` call; the Node
  sidecar is no longer started. Config, not code — both Caddy routings ship in
  the image and the entrypoint picks one, so this deploys the existing v0.3.2
  digest with new `[env]`. Every signed-in reader is logged out: nothing under
  `src/` reads `SIDECAR_DB`, so no token crosses the flip.

- **The `href` defence made structural rather than procedural** (#111).
  `EntryRow.link` was a `String` and the XSS defence was "remember to call
  `net::safe_link` before assigning it" — deleting that call left all 679 tests
  passing. The saved-record URL is attacker-controlled (any atproto client can
  write the record) and Askama escapes HTML metacharacters but not *schemes*,
  so `javascript:` survived escaping intact.

  Now a `SafeLink` newtype in its own module — its own module because a private
  field is private to the *module*, and `web.rs` is 9 000 lines. Two independent
  reviews falsified the first attempt, both finding the guard was legibility
  rather than structure. Four mutation classes are now blocked, two by the
  compiler (`E0061`, `E0423`) and two by a wiring test that renders the real row
  through the real handler from a hostile record.

- **OAuth refresh and revocation are counted** (#113). The soak criterion for
  the cutover was "a week with no refresh or revocation failures", and neither
  was observable — a refresh failure surfaced only as an error on whatever repo
  call happened to trigger it, and a revocation failure left exactly one
  `tracing::warn!`. "No failures this week" was a statement about nobody having
  looked. `oauth_refresh` is timed around `refresh_locked` specifically, not
  around `valid_session`, which runs on every repo call and would bury a rare
  failure under thousands of no-op successes.

- **Origin-secret rotation scripted across Cloudflare and Fly** (#109).
  Rotation moves two sides that must agree; while they disagree every non-
  `/health` request 403s, and because `/health` is exempt from the lock, Fly
  reports the machine healthy throughout and nothing alerts. Dry run is the
  default; preflight refuses to start unless the lock is already healthy.
  Failure states are distinguished — a Cloudflare failure leaves Fly untouched,
  a Fly failure after Cloudflare moved says so loudly, because that is the state
  where the site is already down. Used in production 2026-09-13.

---

## 0.3.2 — 2026-09-13

- **The origin-lock secret was logged in full, and the lock did not fail
  closed** (#107). `X-Origin-Auth` — the shared secret that *is* the origin lock
  — was written to every Caddy access-log line. Caddy redacts the standard
  credential headers by default, which is exactly why a custom name slipped
  through. Found while reading logs for an unrelated feed investigation.

  A site-level filter alone was not enough: a site `log` directive covers
  `http.log.access.*`, but errors during handling come from
  `http.log.error.*`. `caddy validate` passed identically before and after; only
  running it showed the difference.

  Adversarial review then found the lock **did not fail closed**, contrary to
  what both `deploy/Caddyfile` and `oauth-sidecar/src/client-ip.ts` asserted.
  With the secret unset the matcher compared against `""`, which an
  empty-valued header satisfies — measured: no header 403, junk 403, header
  sent empty **admitted**. Pre-existing, and in scope because the
  `cf-connecting-ip` trust model rests on that property and the redaction made
  the bypass log byte-identically to a legitimate request.

- The sweep-lock test measures shape rather than throughput (#106). CI went red
  with "only 4 writes landed during a 443 ms sweep" — an assertion that counted
  writes per unit time measures the runner as much as the lock. Now counts
  writes whose *completion* falls inside the sweep window: categorical, not a
  rate.

---

## 0.3.1 — 2026-09-13

- Stats page prose cut 394 → 225 words with every load-bearing fact kept (#104).
  The cut broke `stats_distinguishes_backoff_from_a_watermark_pause`, and the
  break was correct — that test had never verified its own name. `test_state`
  leaves `schedulers_enabled` false, so every render reported "off"; both
  assertions passed anyway because `contains("running")` matched inside "the
  poller is not running on this instance" and `contains("paused")` matched the
  static prose rather than the rendered row. Verified by mutation: deleting the
  `watermark_paused` arm now fails the test, which it did not before.

- README backend guidance and costs corrected after 0.3.0 shipped (#103).
