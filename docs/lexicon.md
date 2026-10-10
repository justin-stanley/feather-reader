# The `community.lexicon.rss.*` records

This is the specification FeatherReader implements for the four record types it
writes to a reader's PDS. The Lexicon JSON is under
[`lexicons/community/lexicon/rss/`](../lexicons/community/lexicon/rss/); the
serde types are [`src/lexicon.rs`](../src/lexicon.rs), and a test keeps the two
from drifting (`lexicon::lexicon_json_tests`). FeatherReader is the only known
implementation. The aim of this document is that a second implementation,
written from it alone, agrees with FeatherReader about what every record means.

## Conventions

- **Timestamps** (`createdAt`, `updatedAt`, `readThrough`) are RFC 3339
  strings. FeatherReader writes UTC at seconds precision (`2026-10-08T12:00:00Z`)
  and reads any offset or precision; comparisons are made as instants, never as
  strings, except where this document says the value has been normalised first.
- **`$type`** is the record's NSID. A record missing it is read as if it carried
  the collection's NSID.
- **Unknown fields.** A folder record written back by FeatherReader keeps every
  field it did not understand (`Folder::extra`). Subscription, saved and
  readState records are rewritten from the fields FeatherReader knows; a field
  another client added to those is not preserved. (Open question below.)
- **Records are public.** Anyone can read them without a session, and a PDS
  retains deleted records in its history. Nothing secret goes into any of them.

## `community.lexicon.rss.subscription`

One followed feed. Key: `tid`. `url` and `createdAt` are required.

- `url` is the feed document's URL, or, for a standard.site publication, the
  `at://did/site.standard.publication/rkey` URI (DID form, not handle form).
- Only public feeds are written. A URL that carries a token, key or other
  credential (a private Substack or Patreon feed) is refused before any record
  is made; `private` is reserved for a future permissioned-data mechanism and
  has no behaviour today.
- `siteUrl` is rendered as a link, so a reader must drop a value whose scheme is
  not `http` or `https` when it reads the record.
- `folder` is an `at://` URI string (not a `com.atproto.repo.strongRef`
  object) naming a `folder` record in the same repo. FeatherReader cannot read
  a subscription whose `folder` is an object.
- `fetchHint` is an open enum; an unknown value must not break a reader.

## `community.lexicon.rss.folder`

A named grouping. Key: `tid`. `name` and `createdAt` are required; `position` is
a sort hint, unset sorting last. A writer that rewrites a folder record (a
rename) must write back fields it does not know.

## `community.lexicon.rss.saved`

An item kept for later. Key: `tid`. `url` and `createdAt` are required. `url` is
the permalink; `feedUrl` and `entryId` are soft references that let a reader
match the record to a cached item (FeatherReader matches on `url` or `entryId`).
`entryId` is meant to follow the item-id rule below.

**Status in FeatherReader.** FeatherReader writes `entryId` as its stored
entry id, which for an item with no publisher id is its own stand-in (a hash,
or `featherreader:synthetic:…`) rather than the link. A reader matching saved
records by `entryId` will not match those items; match on `url` instead.

## `community.lexicon.rss.readState`

A reader's read state for one feed. Key: `any`; FeatherReader uses `rs-`
followed by the FNV-1a-64 hash of the UTF-8 bytes of `feedUrl`, written as
**16 lowercase hex digits, zero-padded** (offset basis `0xcbf29ce484222325`,
prime `0x100000001b3`), so there is exactly
one record per feed and a writer can find it without listing. A second
implementation that wants to share records with FeatherReader must use the same
key. FeatherReader ignores a `readState` record at any other key: it neither
merges nor imports it, and writes its own record for that feed at its own key,
so the feed's read state would be split across two records.

`feedUrl` and `updatedAt` are required.

### What a record asserts

For the feed `feedUrl`, an item is **read** if either:

1. its id is in `readIds`; or
2. it has a publication date at or before `readThrough`, and its id is not in
   `unreadIds`.

Otherwise it is unread. An id in both arrays is **unread** (see Item ids). An
item with no publication date is covered only by `readIds`.

### Item ids (`idType: "guid"`)

The strings in `readIds` and `unreadIds` name items by this rule, in order:

1. **The publisher's id**, trimmed of surrounding whitespace: RSS `<guid>`,
   Atom `<id>`, JSON Feed `id`.
2. Else, for a standard.site document, **its `at://` URI**
   (`at://did/site.standard.document/rkey`).
3. Else **the item's link URL**: the entry's `rel="alternate"` or rel-less
   link, else its first link that is not a comments link, as the feed gives it,
   trimmed, with no other normalisation. It must parse as an **absolute
   `http` or `https` URL**; a relative or other-scheme link gives the item no
   link id. A link over 8192 bytes is cut to its longest prefix of at most
   8192 bytes that ends on a UTF-8 character boundary. Compared exactly, byte
   for byte.

Ids are scoped to the record's `feedUrl`: the same string in two records names
two items.

A writer must not list an id in both `readIds` and `unreadIds`; a reader that
sees one in both treats it as unread. Several local items can share one id (two
entries with the same link, after a title edit): a writer that has such items
on both sides lists the id in the array of the side whose read or unread mark
is **most recent**. A tie, or a mark with no known time, goes to `unreadIds`.
FeatherReader keeps the time of each read/unread mark (not of a star) for this.

An item with neither an id nor a link has no item id. It is never written to
either array; it is covered by `readThrough` when it has a publication date,
and otherwise its read state is not portable.

**Long ids.** An id over 2048 bytes (rule 1) is replaced by the string
`featherreader:long-guid:` followed by 16 lowercase hex digits: the 64-bit
SipHash-1-3 with both keys zero of the id's UTF-8 bytes followed by one `0xFF`
byte (the Rust standard library's `str` hashing). A link URL (rule 3) is not
re-bounded; FeatherReader stores at most 8192 bytes of it.

**`idType` is literally `"guid"`** for historical reasons; it means "item ids
by the rule above", not "RSS guid". A record **without `idType`** was written
by FeatherReader before 0.4.9 and holds that instance's private row ids: a
reader must ignore its id arrays entirely. Its `readThrough` is still an
instant and still merges.

**Status in FeatherReader.** Implemented from 0.4.9. Before it, an item with no
publisher id was written as a hash FeatherReader computed from its link and
title (`5813b43a0512aaef2750311bf4d978a` is one). From 0.4.9 it is written as
its link, and on read an incoming id is matched against both the stored id and,
for such items, the link, so a record written by an earlier build still
resolves. An item whose only link is not `http(s)` has no portable id, like an
item with no link.

### `readThrough`

An RFC 3339 instant. It is compared against the item's **publication date**:
RSS `pubDate` / Atom `published`, else Atom `updated`; for a standard.site
document `publishedAt`, else the instant encoded in the record key's TID.

A date implausibly far in the future is not trusted. FeatherReader treats a
feed item's date more than two days ahead as absent, and falls back from a
standard.site `publishedAt` more than five minutes ahead to the record key's
TID instant. A second implementation should apply the same two limits, or the
two will disagree about which items a `readThrough` covers.

The date a reader first fetched an item is never the basis: it differs between
instances, so a mark computed from it would mean something different everywhere.

A writer **omits** `readThrough` until it has a real mark; it never synthesizes
one from the current time, which would assert the whole backlog read. A writer
advances it only to an instant with no unread dated item at or before it, and
never moves it backwards: when merging, the later of the two marks is kept.

**Status in FeatherReader.** Before PR #287-3, FeatherReader's own compaction
compared against `published`, else the fetch time, and never applied a record's
`readThrough` to its local items. From that PR the basis is `published` only,
undated reads stay in `readIds`, and a record's `readThrough` marks the reader's
dated local items read, except items in `unreadIds` and items the reader marked
unread more recently than the record's `updatedAt`.

### Caps

Each array holds at most **1000** ids, and a record serialises to at most
**64 KiB** of JSON. A writer over either cap drops ids, oldest first, preferring
to drop ids it carried from the previous record over ids it holds itself, and
ids it cannot resolve to an item over ids it can. Compaction into `readThrough`
is what keeps a busy feed under the caps; a feed whose items carry no dates
cannot be compacted and loses its oldest reads past the cap.

### `updatedAt` and conflicts

`updatedAt` is when the record's **content** last changed, not when it was last
written: carrying another writer's ids unchanged does not move it, and a merge
stamps the result no earlier than the record it merged.

When two sides disagree about one item — read on one, explicitly unread on the
other — the side with the later `updatedAt` wins; a tie goes to the writer's
own state. The rule is per record, not per item: a record has one `updatedAt`.

### Expected writer behaviour: read, merge, write

A writer must not replace a record with its own state. Before writing it reads
the existing record and:

- takes the later `readThrough`;
- unions `readIds` and `unreadIds`, settling an item that is in one side's
  `readIds` and the other side's `unreadIds` by `updatedAt`;
- keeps ids it cannot resolve to an item it knows (another reader's items, or
  items it has since discarded), dropping them first if a cap binds;
- applies the merged record's `readThrough` and ids to its own items, so the
  two converge.

FeatherReader lists the whole collection once per flush round rather than
reading one record at a time, and writes with `applyWrites`. There is no
compare-and-swap: a write by another client between the read and the write is
lost until that client next merges.

## Open questions

- **NSID authority.** `community.lexicon.rss` is under Lexicon Community's
  authority. Whether to propose it there or move to a domain the author
  controls is undecided; nothing here depends on the answer, and no record
  changes until it is made.
- **Unknown fields** on subscription, saved and readState records are not
  preserved by FeatherReader (folder records are).
- **String bounds.** `subscription.title`, `folder.name` and `saved.title` have
  no `maxLength` because FeatherReader does not bound them on write.
