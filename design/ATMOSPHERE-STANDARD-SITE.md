# Atmosphere: Standard.site subscriptions and a FeatherReader publication

> **Status: proposed (2026-10-23).** Two pieces of work, each tracked in its own issue:
> **A** writes `site.standard.graph.subscription` records, and **B** gives FeatherReader its own
> Standard.site publication. Neither changes `community.lexicon.rss.*`.

## Why now

Bluesky is building an **Atmosphere** destination into its app. It has a "Beta" tag, an Activity tab
and an Explore tab, and it shows featured articles, publications, photos and apps from the wider
network. Eric (@esb.lol, Bluesky) posted a work-in-progress preview on 2026-10-23. He said it will
reach beta testers soon, and that it starts with "only a handful of lexicons", with the
architecture built to add more quickly.

What's in the public code (`bluesky-social/social-app`, read 2026-10-23):

- **The screen is a shell behind a feature flag.** `src/screens/Atmosphere.tsx` has the Activity
  and Explore tabs and is gated on `atmosphere_explore:enable` (PR #11877, merged 2026-10-06). PR #12110
  (merged 2026-10-21) gave it its own tab and the `bluesky://atmosphere` deep link. The Explore
  content (what is featured, and how it's picked) **isn't public yet**.
- **The layer it builds on is Standard.site.** `app.bsky.embed.external` gained `associatedRefs`
  (strongRefs to "the Atmosphere records that backed this view") and a `source` with publication
  name, icon and theme. `app.bsky.embed.getEmbedExternalView` turns up to four at-uris (a
  `site.standard.document`, and optionally its `site.standard.publication`) into a rich card, and
  returns `{}` when the records don't back the URL. The link-meta proxy finds those at-uris on the
  page. `StandardSiteEmbed/utils.ts` recognises any `site.standard.*` collection.
- **The preview screenshots** feature Standard.site articles and publications (with a "Subscribe on
  Leaflet" button) and grain.social photos.

**FeatherReader reads Standard.site (0.4.0) but writes nothing the Atmosphere reads.** Everything it
writes is `community.lexicon.rss.*`. The two changes below put FeatherReader into the lexicons Bluesky
has adopted first. A makes FeatherReader one of the apps where people subscribe to Standard.site
publications. B gives the project content that can be featured and that shows as a rich card when
shared.

Not known, and not assumed here: how Explore picks what is featured, what the Activity tab
shows, and how the "apps" section is filled. (The project account already has an ATStore listing:
`fyi.atstore.listing.detail` on @feather-reader.com.)

---

## A. Write `site.standard.graph.subscription`

### The record

Published by Standard.site (`did:plc:re3ebnp5v7ffagz6rb6xfei4`, `com.atproto.lexicon.schema`
rkey `site.standard.graph.subscription`, read 2026-10-23):

```
key: tid
publication  at-uri    required  the site.standard.publication being subscribed to
createdAt    datetime
```

This is the record that Leaflet's and pckt's Subscribe buttons write. Its sibling
`site.standard.graph.recommend` (`document` + `createdAt`) is out of scope here; see
[Not in this change](#not-in-this-change).

### Behaviour

`community.lexicon.rss.subscription` **stays FeatherReader's source of truth**: it carries the folder
and the title, and every existing reader of it keeps working. For publications, FeatherReader
**also** writes the Standard.site record: one record per subscription, kept in step with it.

| Event | Today | With A |
|---|---|---|
| Subscribe to a publication (form, `POST /subscriptions`) | writes `rss.subscription` with `url = at://did/site.standard.publication/rkey` | then, if no `graph.subscription` for that publication exists in the reader's repo, creates one |
| OPML import containing at:// publication URLs | `applyWrites`, 200 per call | the `graph.subscription` creates go in the same batches |
| Unsubscribe (`POST /subscriptions/{rkey}/delete`) | deletes the `rss.subscription` | also deletes **every** `graph.subscription` in the reader's repo for that publication (see the decision below) |
| Rename / re-folder | `putRecord` with `swapRecord` | no change |
| Account delete (`POST /account/delete`) | purges local rows; PDS records stay | unchanged: the `graph.subscription` records stay with the user, the same as `rss.*` |
| Existing publication subscriptions (19 rows in production, one reader, as of 0.4.0) | — | **backfill** on the reader's next sign-in: create the missing `graph.subscription` records, once, idempotently |

**A failed write doesn't fail the subscribe**, the same as the `rss.subscription` write today
(`web.rs` logs it and keeps the local row). The next sign-in's backfill pass repairs it.

**Matching a publication.** FeatherReader stores the **DID form** of the at-uri
(`docs/lexicon.md`, rule for `url`). Other apps may write the handle form. Compare after resolving
both to the DID form, using the same canonicalisation the subscribe form already uses
(`publication_url_from_paste`). Write the DID form.

**Scope and consent.** FeatherReader asks for `atproto transition:generic`
(`src/oauth/metadata.rs`), which already allows writes to any collection, so readers don't need to
sign in again. If FeatherReader moves to granular scopes, this collection has to be in the list.

**Behind a flag.** `FEATHERREADER_STANDARD_SITE_GRAPH`, off by default. Turn it on on staging first,
then in production.

### Decisions for the owner

1. **Unsubscribe deletes records FeatherReader didn't create.** The record means "this person
   subscribes to this publication" for every app that reads it. If a reader subscribed on Leaflet
   first, unsubscribing in FeatherReader deletes that record too, so they're unsubscribed on Leaflet
   as well. **Recommended: delete them all, and say so on the unsubscribe button** ("Unsubscribes
   in other Standard.site apps too"). The alternative, deleting only the records FeatherReader
   created, leaves the reader still subscribed elsewhere. Once import (below) exists, it would also
   re-add the subscription on the next sign-in.
2. **Import.** Reading the reader's existing `graph.subscription` records lets FeatherReader pick up
   subscriptions made in other apps. **Recommended: a one-click offer on `/manage`** ("Found 12
   Standard.site subscriptions from other apps — add them?") rather than a silent auto-add. Import
   adds feeds, so it has to respect the per-user and global feed caps, and adding feeds nobody
   asked for here would surprise the reader. This is a second PR after the write path.
3. **Privacy copy.** `rss.subscription` records are already public, but a `graph.subscription` record
   is in a lexicon that Bluesky's Atmosphere screen and other apps index and may display ("X
   subscribed to Y"). Say this on `/privacy` and on the subscribe form when the flag is on.

### Implementation sketch

- `lexicon.rs`: add `nsid::STANDARD_SITE_GRAPH_SUBSCRIPTION` and a `GraphSubscription { publication, created_at }`
  record type, plus a vetted wrapper like `VettedSubscription`. The vetting checks that `publication`
  is a DID-form `at://…/site.standard.publication/…`.
- `repo.rs` / `oauth/xrpc.rs`: `list_graph_subscriptions`, `add_graph_subscription`,
  `remove_graph_subscriptions_for(publication)`. Reuse the hardened `list_all_records` path (caps,
  cursor loop, 2xx error-envelope refusal).
- `web.rs`: calls these from `add_subscription`, `delete_subscription` and the OPML import, when
  the feed kind is `publication` and the flag is on.
- Backfill: run once per sign-in, after the session is established, in the background; it never
  blocks the page. A local marker (`users.graph_backfilled_at`) keeps it to one pass. The marker
  goes in a **new migration**, and that migration is tested by upgrading from the released 0.5.x
  schema, not only against a fresh database (see the 0.3.9 crash loop).
- Tests: the record shape against the published schema; matching handle-form against DID-form;
  unsubscribe deletes all matches; a failed write keeps the local row; backfill is idempotent; the
  flag off means no `site.standard.*` writes at all (fake PDS log).

---

## B. A FeatherReader publication

Readers find FeatherReader through what it publishes. A `site.standard.publication` on the project
account is the only one of these paths that can put FeatherReader content into "Featured articles /
publications". It also turns every shared link to it into a rich card today, whatever Explore
ends up doing.

### What it takes (from the Standard.site spec)

- A `site.standard.publication` record (`url`, `name` required; also `description`, a square
  `icon` ≥ 256 px, and `basicTheme`) on **@feather-reader.com**
  (`did:plc:cxauapbtkbmf7b24e5icd32j`, on `pds.justin-stanley.com`).
- `https://<publication host>/.well-known/site.standard.publication` returning that record's at-uri.
  It is **404 on feather-reader.com today**.
- On each post page: `<link rel="site.standard.document" href="at://did/site.standard.document/rkey">`,
  and a `site.standard.document` record (`site`, `path`, `title`, `publishedAt`) whose URL is the
  publication `url` + `path`.

### Two ways to host it

| | **B1. Served by FeatherReader** at `feather-reader.com/news/…` | **B2. Leaflet or pckt on a subdomain** (e.g. `news.feather-reader.com`) |
|---|---|---|
| Content lives in | the repo (`content/news/*.md`) | the platform |
| Records written by | **Sequoia**, the tool `justin-stanley.com` already uses, run as a release step with the project account's credentials (human-gated) | the platform |
| Code in FeatherReader | `/.well-known/site.standard.publication` route (at-uri from config, 404 when unset); `/news` and `/news/{slug}` rendered from markdown with the `<link rel>` tag; CSP and sanitiser review for the new pages | none; one DNS record |
| Gets the "Subscribe on Leaflet" button in Explore | no (a FeatherReader-hosted publication) | yes, if on Leaflet |
| Cost | a small feature + a review pass | ~none |

**Recommended: B1** unless speed matters more than ownership. It keeps the project's own news on
the project's own domain and in its own repo, and it uses FeatherReader's own Standard.site support
for an end-to-end check: the instance can subscribe to its own publication. B2 is the fast path if
the posts should go out before Bluesky's beta does. Check that the platform supports custom domains
before choosing B2.

### First posts

The launch post already exists on `justin-stanley.com` (`content/posts/feather-reader.md`, with its
own `site.standard.document`). **Don't republish it** under the project: two documents for one
article split recommendations and link cards. Link to it instead, and start the project publication
with posts that don't exist yet:

1. **0.5: Rust-only** — what the sidecar removal changed, for self-hosters.
2. **Standard.site in an RSS reader** — 0.4.0, and (once A ships) subscriptions that carry over to
   other apps.
3. Then **one post per minor release**, drawn from `CHANGELOG.md`.

### Steps

1. Pick B1 or B2.
2. Create the publication record: name "FeatherReader", the site's description, the feather icon,
   and a `basicTheme` from the site's palette.
3. B1: add the route and pages behind config, and deploy. B2: create the publication and set its
   domain.
4. Check: `curl https://feather-reader.com/.well-known/site.standard.publication` (B1) returns the
   at-uri; paste a post URL into Bluesky's composer and get the rich card (a valid `associatedRefs`);
   subscribe to the publication from FeatherReader staging.

---

## Not in this change

- **`site.standard.graph.recommend`** as a public "Recommend" action on Standard.site items. Keep it
  separate from the star (the star means "keep for later"; a recommendation is a public
  endorsement). Worth doing after A, with the same matching rules.
- **An optional document at-uri on `community.lexicon.rss.saved`**, so any app can render a saved
  Standard.site item as a rich card. This changes the owner's lexicon, so the owner decides.
- **Resolving `community.lexicon.rss`.** `_lexicon.rss.lexicon.community` has no DNS record today,
  so the lexicon doesn't resolve over the network. That namespace belongs to Lexicon Community, so
  fixing it means coordinating with them.

## Sources

- Eric's preview thread: `at://esb.lol/app.bsky.feed.post/3mykmj6n3222b` (2026-10-23)
- `bluesky-social/social-app`: `src/screens/Atmosphere.tsx`, PR #11877, PR #12110,
  `lexicons/app/bsky/embed/external.json`, `lexicons/app/bsky/embed/getEmbedExternalView.json`,
  `src/lib/link-meta/link-meta.ts`, `src/components/Post/Embed/StandardSiteEmbed/utils.ts`
- Standard.site schemas: `com.atproto.lexicon.schema` records in `did:plc:re3ebnp5v7ffagz6rb6xfei4`
  (resolved via `_lexicon.standard.site`)
- [standard.site](https://standard.site/): publication `.well-known` and document `<link rel>` verification
