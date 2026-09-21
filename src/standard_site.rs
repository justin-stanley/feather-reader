//! Reading `standard.site` publications as feeds.
//!
//! A publication is not a feed document — it is a record in somebody's atproto
//! repo, and its "entries" are separate records in the same repo. So this reads
//! two collections rather than fetching one URL:
//!
//! ```text
//! at://<did>/site.standard.publication/<rkey>
//!   ├─ resolve <did> → PDS
//!   ├─ getRecord   site.standard.publication  → name, url
//!   └─ listRecords site.standard.document     → paged, filtered on `site`
//! ```
//!
//! **Unauthenticated throughout.** This reads *someone else's* repo with no
//! session, which is why it cannot reuse [`crate::oauth::xrpc::Repo`]: that type
//! takes its base URL from the session's PDS, hardcodes `repo` to
//! `session.sub`, and DPoP-signs every send. None of that survives contact with
//! "read a stranger's repo".
//!
//! **Only `textContent` and `description` are read; `content` is ignored.**
//! `content` is an open union — measured across 449 real documents it carried
//! six different wrappers and twenty-two block types from five vendor
//! namespaces, growing with every platform that adopts the lexicon, and it
//! would drag an HTML-sanitisation surface over foreign input. A document with
//! neither field still yields an entry: title, date and a link is what an RSS
//! reader shows for a title-only feed, and is not a failure state.

use serde::Deserialize;

use crate::lexicon::nsid;

/// Documents per `listRecords` page.
///
/// Smaller than the protocol default of 100 because a `site.standard.document`
/// carries the whole article — ~17 KB measured, and the `content` union this
/// module ignores is still in the wire bytes — while
/// [`crate::net::read_capped`] bounds a response at 8 MB. 100 long-form
/// articles per page can exceed that and fail the walk outright.
const DOCUMENT_PAGE_SIZE: u32 = 25;

/// A parsed `at://` URI: `at://<authority>/<collection>/<rkey>`.
///
/// Parsed by hand rather than with `url::Url`, which **cannot read the form that
/// matters**: `at://did:plc:…/…` fails with *invalid port number*, because the
/// colons in the DID are taken as a port separator. The handle form parses
/// fine, which is what makes the failure easy to miss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtUri {
    pub authority: String,
    pub collection: String,
    pub rkey: String,
}

impl AtUri {
    /// Parse, or `None` if this is not a well-formed three-segment at-URI.
    pub fn parse(uri: &str) -> Option<Self> {
        let rest = uri.strip_prefix(crate::atproto::AT_URI_PREFIX)?;
        let mut parts = rest.split('/');
        let (authority, collection, rkey) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some()
            || authority.is_empty()
            || collection.is_empty()
            || rkey.is_empty()
        {
            return None;
        }
        Some(Self {
            authority: authority.to_string(),
            collection: collection.to_string(),
            rkey: rkey.to_string(),
        })
    }
}

impl std::fmt::Display for AtUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "at://{}/{}/{}",
            self.authority, self.collection, self.rkey
        )
    }
}

/// The publication record — a pointer, not a feed. Supplies the title and the
/// base URL that document `path`s are joined onto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication {
    pub name: Option<String>,
    pub url: String,
}

/// One document, mapped onto the shape the feed pipeline already stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The document's own `at://` URI.
    ///
    /// **Not derived from `path`.** `path` is mutable — a publisher who moves an
    /// article would duplicate their whole archive on the next poll, because
    /// dedup is `UNIQUE (feed_id, guid)`.
    pub guid: String,
    pub title: String,
    /// `publishedAt` parsed and re-spelled by [`crate::feed::fmt_time`], the
    /// store's one RFC3339 shape — or `None` when it does not parse. The
    /// reading order sorts on this column as a string, so a publisher's
    /// spelling cannot go in verbatim.
    pub published: Option<String>,
    /// The joined, **scheme-vetted** permalink — `None` when the document's
    /// `path` does not resolve to a safe href on the publication's origin.
    /// `Option` because the guarantee cannot be met unconditionally and the
    /// store's column is optional too; a title-only entry is not a failure.
    pub url: Option<String>,
    /// `description`, else `textContent`, escaped by
    /// [`crate::feed::plain_text_to_html`] — both are plain text in the
    /// lexicon, and the column they land in is rendered as HTML.
    pub summary: Option<String>,
}

impl From<Entry> for crate::store::NewEntry {
    /// The shape the poller stores. Kept here, next to the fields it maps,
    /// so wiring the reader to the scheduler has nothing left to decide.
    fn from(e: Entry) -> Self {
        crate::store::NewEntry {
            guid: e.guid,
            url: e.url,
            title: Some(e.title),
            author: None,
            published: e.published,
            content_html: e.summary,
            fetched_at: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct PublicationValue {
    name: Option<String>,
    url: String,
}

#[derive(Debug, Deserialize)]
struct DocumentValue {
    title: String,
    /// Optional so a document without one is an entry with no date, the same
    /// answer a garbage one gets — the strictness ran the other way, making
    /// the field this module is willing to DISCARD the one whose absence was
    /// fatal to the whole record.
    #[serde(rename = "publishedAt")]
    published_at: Option<String>,
    /// Optional for the same reason as `publishedAt`: a document with no
    /// `path` keeps its title, date and summary rather than vanishing from
    /// the feed entirely. `Entry.url` is already `Option`.
    path: Option<String>,
    /// The at-URI of the publication this document belongs to.
    ///
    /// **Load-bearing.** A repo can hold several publications — measured, some
    /// do — so documents must be filtered by this rather than assumed to belong
    /// to the one being polled.
    site: String,
    #[serde(rename = "textContent")]
    text_content: Option<String>,
    description: Option<String>,
}

/// Find the publication named by `rkey` among a repo's publication records.
///
/// Returns its **canonical** at-URI — the one the PDS itself minted — alongside
/// the record. That canonical URI is what documents reference in their `site`
/// field, so it is the key the filter uses, rather than the string the reader
/// subscribed with. Storage is DID-form only (#164), so today the two agree;
/// taking the PDS's spelling keeps them agreeing if they ever stop.
pub fn publication_from_records(
    rkey: &str,
    records: &[crate::atproto::RecordEntry],
) -> Option<(String, Publication)> {
    let entry = records
        .iter()
        .find(|r| AtUri::parse(&r.uri).is_some_and(|u| u.rkey == rkey))?;
    let value: PublicationValue = serde_json::from_value(entry.value.clone()).ok()?;
    // **The base of every Entry.url, so it is vetted as the href it becomes.**
    // `net::safe_link` is the same check the RSS entry pipeline applies at
    // `feed.rs`, and the reason `safe_link.rs` exists as a type at all: the
    // procedural version of this guarantee was deleted once with a green suite.
    let url = crate::net::safe_link(&value.url)?;
    Some((
        entry.uri.clone(),
        Publication {
            name: value.name,
            url,
        },
    ))
}

/// Map a repo's document records onto entries, keeping only those belonging to
/// `canonical_site`.
pub fn entries_from_records(
    canonical_site: &str,
    publication: &Publication,
    records: &[crate::atproto::RecordEntry],
) -> Vec<Entry> {
    // **Normalised to a directory.** `Url::join` is RFC-3986: against a base of
    // `https://example.com/blog`, a relative `posts/a` resolves to
    // `/posts/a`, silently dropping the subpath every permalink needs. A
    // trailing slash makes the base a directory, which is what a publication
    // URL means.
    let base = url::Url::parse(&publication.url).ok().map(|mut u| {
        if !u.path().ends_with('/') {
            u.set_path(&format!("{}/", u.path()));
        }
        u
    });
    records
        .iter()
        .filter_map(|record| {
            // A document that does not deserialise is SKIPPED, not fatal: one
            // malformed record must not cost a publisher its whole feed.
            let doc: DocumentValue = serde_json::from_value(record.value.clone()).ok()?;
            if doc.site != canonical_site {
                return None;
            }
            Some(Entry {
                guid: record.uri.clone(),
                title: doc.title,
                published: doc
                    .published_at
                    .as_deref()
                    .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
                    .map(|d| crate::feed::fmt_time(d.with_timezone(&chrono::Utc))),
                // `non_blank` for the same reason the summary uses it: a blank
                // path joins to the publication's own base, so a handful of
                // documents with an empty `path` became a handful of entries
                // all linking to the site root.
                url: non_blank(doc.path)
                    .as_deref()
                    .and_then(|path| join_path(base.as_ref(), path)),
                // `description` first — the authored summary — but only when it
                // actually says something: a blank one must not shadow the body.
                // Then ESCAPED, not sanitised: both fields are plain text.
                summary: non_blank(doc.description)
                    .or_else(|| non_blank(doc.text_content))
                    .map(|raw| crate::feed::plain_text_to_html(&raw)),
            })
        })
        .collect()
}

fn non_blank(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.trim().is_empty())
}

/// Join a document `path` onto the publication's base URL.
///
/// **`Url::join`, not concatenation.** Concatenating produced
/// `https://x.com/https://evil.example/a` for an absolute path and buried the
/// path inside the query for a base carrying one. `join` also keeps the result
/// on the publication's own origin for a relative path, which is the only shape
/// the lexicon describes.
fn join_path(base: Option<&url::Url>, path: &str) -> Option<String> {
    // **`safe_link` on the way out, not only on the base.** The scheme
    // guarantee used to live solely in `publication_from_records`; this
    // function and `Publication` are both `pub`, so a caller that built a
    // `Publication` some other way (the step-3 poller, from a stored row) gave
    // an unparseable base — and the no-base branch then returned the
    // document's `path` verbatim, putting `javascript:` into an entry link.
    // **No base, no URL.** This branch used to return `safe_link(path)`, which
    // vets the scheme but NOT the origin — so a caller holding a `Publication`
    // it did not build through `publication_from_records` (the step-3 poller,
    // from a stored row whose `site_url` is NULL or malformed) would publish a
    // publisher-controlled `https://evil.example/x` as a permalink under that
    // publication's name. The two branches agree now: off-origin is `None`, and
    // "no origin to be off" is also `None`.
    let base = base?;
    match base.join(path) {
        // A path that resolves off the publication's origin is not a path, it
        // is a redirect the publisher smuggled into a field we render as theirs.
        Ok(joined) if joined.origin() == base.origin() => crate::net::safe_link(joined.as_str()),
        // **No URL, not the homepage.** Falling back to the base gave every
        // affected entry the same href pointing at the site root — which is
        // what a publication on an apex domain whose documents live on `www.`
        // or a CDN would produce for its whole archive, with nothing to say
        // anything had been dropped.
        _ => None,
    }
}

/// What the document walk should do with one record.
///
/// A pure decision so it can be tested without a PDS: the walk itself is a
/// closure over the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocumentFate {
    /// Belongs to the publication being read.
    Keep,
    /// Belongs to another publication **in this repo** — normal, and the
    /// reason the `site` filter exists. Not a signal of anything.
    Sibling,
    /// References a publication this repo does not have: a `site` spelling
    /// nothing can ever match. Indistinguishable from a quiet blog without
    /// saying so, which is why it is counted.
    Orphan,
    /// Not a document this reader understands.
    Malformed,
}

fn classify_document(
    record: &crate::atproto::RecordEntry,
    canonical_site: &str,
    known: &std::collections::HashSet<&str>,
) -> DocumentFate {
    match serde_json::from_value::<DocumentValue>(record.value.clone()) {
        Ok(doc) if doc.site == canonical_site => DocumentFate::Keep,
        Ok(doc) if known.contains(doc.site.as_str()) => DocumentFate::Sibling,
        Ok(_) => DocumentFate::Orphan,
        Err(_) => DocumentFate::Malformed,
    }
}

/// What one read of a publication produced.
///
/// **`complete` is carried out, not just logged.** `RecordWalk` tracks whether
/// the document walk finished; dropping that here would leave the caller unable
/// to tell "this publication has nine articles" from "this reader gave up after
/// nine", which is the distinction the flag exists for.
#[derive(Debug)]
pub struct PublicationRead {
    pub publication: Publication,
    pub entries: Vec<Entry>,
    pub complete: bool,
}

/// Turn a read publication into stored entries, and report it as a
/// [`crate::feed::PollOutcome`] the scheduler already knows how to settle.
///
/// **The adapter, kept separate from the fetch**, for the reason the rest of
/// this module is: everything here is decidable without a network, so it is
/// testable without one. `poll_publication` is the thin half.
///
/// The store path is the RSS path — `upsert_feed` then `insert_entries` — so
/// dedup, the per-feed cap and the retention sweep treat a publication exactly
/// like a feed. Nothing here is standard.site-specific except where the values
/// came from.
pub async fn store_publication(
    pool: &sqlx::SqlitePool,
    url: &str,
    publication: &Publication,
    entries: Vec<Entry>,
    complete: bool,
    max_entries_per_feed: i64,
) -> anyhow::Result<crate::feed::PollOutcome> {
    use anyhow::Context;

    let rows: Vec<crate::store::NewEntry> = entries.into_iter().map(Into::into).collect();
    let new_feed = crate::store::NewFeed {
        url: url.to_string(),
        title: publication.name.clone(),
        site_url: Some(publication.url.clone()),
        // A publication read has no validators: there is no ETag on a
        // `listRecords` walk, so every poll is a full read. Left as-is rather
        // than invented.
        etag: None,
        last_modified: None,
        last_polled: Some(crate::store::now_rfc3339()),
        // The scheduler owns cadence.
        next_poll: None,
    };
    let feed_id = crate::store::upsert_feed(pool, &new_feed)
        .await
        .with_context(|| format!("upsert_feed for {url}"))?;
    let n = crate::store::insert_entries(pool, feed_id, &rows, max_entries_per_feed)
        .await
        .with_context(|| format!("insert_entries for {url}"))?;

    // **A partial read is not a clean poll.** `RecordWalk.complete` exists to
    // carry "I did not read all of it" out of the walk; reporting `Updated`
    // here would throw that away and leave the feed looking healthy while
    // silently missing articles. The entries it DID read are already stored —
    // a partial read is not a discarded one — but the outcome says so, which
    // puts the feed on a backoff and names the cause on `/stats`.
    if !complete {
        return Ok(crate::feed::PollOutcome::Failed {
            backoff: std::time::Duration::from_secs(0),
            kind: crate::feed::FailureKind::Body,
            detail: crate::feed::failure_detail(format!(
                "incomplete read: stored {n} entries but the document walk stopped early"
            )),
        });
    }
    Ok(crate::feed::PollOutcome::Updated { new_entries: n })
}

/// Poll one publication: read it, then store it. The scheduler's entry point.
///
/// Returns a [`crate::feed::PollOutcome`] for every path including failure, so
/// `feed::settle_poll` handles a publication exactly as it handles a feed —
/// error counting, backoff and the cause histogram all come for free. A read
/// error is a `fetch` failure with the anyhow chain as its detail, the same
/// shape `poll_feed` produces.
pub async fn poll_publication(
    pool: &sqlx::SqlitePool,
    http: &reqwest::Client,
    plc_directory: &str,
    url: &str,
    max_entries_per_feed: i64,
) -> anyhow::Result<crate::feed::PollOutcome> {
    let Some(uri) = AtUri::parse(url) else {
        return Ok(crate::feed::PollOutcome::Failed {
            backoff: std::time::Duration::from_secs(0),
            kind: crate::feed::FailureKind::Fetch,
            detail: crate::feed::failure_detail(format!("not a readable at:// URI: {url}")),
        });
    };
    let read = match fetch(http, plc_directory, &uri).await {
        Ok(read) => read,
        Err(e) => {
            return Ok(crate::feed::PollOutcome::Failed {
                backoff: std::time::Duration::from_secs(0),
                kind: crate::feed::FailureKind::Fetch,
                detail: crate::feed::failure_detail(format!("{e:#}")),
            })
        }
    };
    store_publication(
        pool,
        url,
        &read.publication,
        read.entries,
        read.complete,
        max_entries_per_feed,
    )
    .await
}

/// Read a publication and its documents through the hardened anonymous client.
///
/// **Deliberately thin.** Everything that makes this fetch safe already exists
/// in [`crate::atproto`] and is reused rather than rebuilt:
///
/// - [`crate::atproto::resolve_did_to_pds`] runs
///   [`crate::net::assert_public_target`] on the `serviceEndpoint`, which is a
///   stranger's string;
/// - every read goes through [`crate::net::guarded_get_no_privacy`], re-vetting
///   per hop and pinning the connection, which closes the rebinding window and
///   supplies the `User-Agent` that 4 of 19 measured endpoints demand;
/// - [`crate::net::read_capped`] bounds each response;
/// - [`crate::atproto::PdsClient::list_all_records`] bounds the page count AND
///   detects a repeated or absent cursor — the trap this module's first draft
///   walked into, already solved there;
/// - an XRPC error envelope surfaces as [`crate::atproto::XrpcError`] rather
///   than deserialising into an empty page.
///
/// The first draft of this module reimplemented all of that, worse. The only
/// logic left here is the part that is genuinely about standard.site.
pub async fn fetch(
    http: &reqwest::Client,
    plc_directory: &str,
    uri: &AtUri,
) -> anyhow::Result<PublicationRead> {
    use anyhow::Context;

    // The collection is part of the identity of what was subscribed to, and
    // this function is `pub`: without the check it lists publications and
    // matches on rkey alone, so `at://did/app.bsky.feed.post/<rkey>` would be
    // "read as a publication" whenever a publication shares that rkey.
    anyhow::ensure!(
        uri.collection == nsid::STANDARD_PUBLICATION,
        "{uri} is not a {} URI",
        nsid::STANDARD_PUBLICATION
    );

    let pds = crate::atproto::resolve_did_to_pds(http, plc_directory, &uri.authority)
        .await
        .with_context(|| format!("resolving the PDS for {}", uri.authority))?;
    let client = crate::atproto::PdsClient::anonymous(http.clone(), pds, uri.authority.clone());

    let publications = client
        .list_all_records(nsid::STANDARD_PUBLICATION)
        .await
        .with_context(|| format!("listing publications for {}", uri.authority))?;
    let (canonical_site, publication) = publication_from_records(&uri.rkey, &publications)
        .with_context(|| format!("{uri} is not a readable site.standard.publication"))?;

    // **Filtered inside the walk, so the cap counts THIS publication's
    // documents.** A repo-wide cap applied before the filter starves a quiet
    // publication whose busy sibling fills the window — it returns nothing,
    // permanently, and worse with every post the sibling makes.
    //
    // The page is smaller than the protocol default because a document
    // carries the whole article (~17 KB measured, and the `content` union this
    // module ignores is still on the wire): 100 long-form articles per page
    // can exceed `read_capped`'s 8 MB and fail the walk outright.
    let known: std::collections::HashSet<&str> =
        publications.iter().map(|p| p.uri.as_str()).collect();
    let mut orphaned = 0usize;
    let documents = client
        .list_recent_matching(
            nsid::STANDARD_DOCUMENT,
            crate::atproto::MAX_LARGE_RECORDS,
            DOCUMENT_PAGE_SIZE,
            // Orphans are counted while WALKING, not over the kept window: a
            // truncated slice would both miss orphans and stay silent in
            // exactly the case where the feed went empty structurally.
            |record| match classify_document(record, &canonical_site, &known) {
                DocumentFate::Keep => true,
                DocumentFate::Orphan => {
                    orphaned += 1;
                    false
                }
                DocumentFate::Sibling | DocumentFate::Malformed => false,
            },
        )
        .await
        .with_context(|| format!("listing documents for {canonical_site}"))?;
    let entries = entries_from_records(&canonical_site, &publication, &documents.records);

    // **A walk that stopped early is not a short archive.** Reading part of a
    // publication is acceptable; reporting it as the whole of one is not, and
    // when the part is empty — a quiet publication whose busy sibling fills
    // every page this reader will fetch — the feed looks healthy and stays
    // empty forever.
    if !documents.complete {
        tracing::warn!(
            site = %canonical_site,
            kept = entries.len(),
            "stopped reading this publication before its documents ran out"
        );
    }
    // **A spelling mismatch on `site` looks exactly like an empty
    // publication.** A publication with no documents is normal, so the poller
    // would call this healthy forever; if the repo HAD documents and none
    // matched, say so, because that is the shape of a bug rather than of a
    // quiet blog.
    if orphaned > 0 {
        tracing::warn!(
            site = %canonical_site,
            orphaned,
            "documents in this repo reference no publication in it — a `site` spelling nothing matches"
        );
    }
    Ok(PublicationRead {
        publication,
        entries,
        complete: documents.complete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atproto::RecordEntry;
    use serde_json::json;

    const DID: &str = "did:plc:ohutz6x5acjmpuulp3x7wxxc";

    fn rec(collection: &str, rkey: &str, value: serde_json::Value) -> RecordEntry {
        RecordEntry {
            uri: format!("at://{DID}/{collection}/{rkey}"),
            cid: None,
            value,
        }
    }

    fn publication(rkey: &str, url: &str) -> RecordEntry {
        rec(
            nsid::STANDARD_PUBLICATION,
            rkey,
            json!({ "name": "Scan's Lab", "url": url }),
        )
    }

    fn document(rkey: &str, site: &str, title: &str, path: &str) -> RecordEntry {
        rec(
            nsid::STANDARD_DOCUMENT,
            rkey,
            json!({
                "title": title,
                "publishedAt": "2026-07-11T00:00:00Z",
                "path": path,
                "site": site,
                "textContent": "body",
            }),
        )
    }

    fn canonical(rkey: &str) -> String {
        format!("at://{DID}/{}/{rkey}", nsid::STANDARD_PUBLICATION)
    }

    /// **The `site` filter keys on the URI the PDS minted, not the string the
    /// reader subscribed with.** Documents reference their publication by the
    /// canonical URI, and every measured document does. An earlier draft
    /// compared against the subscribed string; storage was then meant to admit
    /// handle-form URIs, and a handle-form subscription found nothing forever
    /// while the module declared the feed healthy. #164 made storage DID-only,
    /// so the two strings agree today — the canonical one is still the right
    /// key, and this pins it.
    #[test]
    fn the_site_filter_uses_the_uri_the_pds_minted() {
        let records = vec![publication("p", "https://scanash.com")];
        let (site, pubn) = publication_from_records("p", &records).expect("publication not found");
        assert_eq!(site, canonical("p"), "did not take the PDS's canonical URI");

        let docs = vec![document("d1", &canonical("p"), "Hello", "/hello")];
        let entries = entries_from_records(&site, &pubn, &docs);
        assert_eq!(
            entries.len(),
            1,
            "a canonical-site document was not matched"
        );
    }

    /// The mapping into the store's row is total and loses nothing the poller
    /// would need — so wiring the reader has nothing to invent.
    #[test]
    fn an_entry_maps_onto_the_stores_row() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let docs = vec![document("rk1", &site, "Hello", "/hello")];
        let row: crate::store::NewEntry = entries_from_records(&site, &pubn, &docs)
            .pop()
            .unwrap()
            .into();
        assert_eq!(
            row.guid,
            format!("at://{DID}/{}/rk1", nsid::STANDARD_DOCUMENT)
        );
        assert_eq!(row.url.as_deref(), Some("https://example.com/hello"));
        assert_eq!(row.title.as_deref(), Some("Hello"));
        assert_eq!(row.published.as_deref(), Some("2026-07-11T00:00:00Z"));
        assert_eq!(row.content_html.as_deref(), Some("body"));
        assert_eq!(row.author, None);
        assert_eq!(row.fetched_at, None);
    }

    /// A repo can hold several publications — measured, some do — and
    /// `listRecords` cannot filter server-side.
    #[test]
    fn documents_are_filtered_by_their_site_field() {
        let records = vec![publication("mine", "https://example.com")];
        let (site, pubn) = publication_from_records("mine", &records).unwrap();
        let docs = vec![
            document("a", &site, "Mine", "/a"),
            document("b", &canonical("theirs"), "Theirs", "/b"),
            document("c", &site, "Mine again", "/c"),
        ];
        let titles: Vec<String> = entries_from_records(&site, &pubn, &docs)
            .into_iter()
            .map(|e| e.title)
            .collect();
        assert_eq!(titles, ["Mine", "Mine again"]);
    }

    /// **The publication URL is a stranger's string and is vetted as one.**
    ///
    /// It becomes the base of every `Entry.url`, which is an href. This repo has
    /// `safe_link.rs` as a type with a module-private field precisely because
    /// the procedural version of this guarantee failed; #143 and #138 are this
    /// same bug class on `siteUrl`.
    #[test]
    fn a_publication_with_a_hostile_url_is_refused() {
        for hostile in [
            "javascript:alert(1)",
            "data:text/html,<script>",
            "file:///etc/passwd",
            "",
        ] {
            let records = vec![publication("p", hostile)];
            assert!(
                publication_from_records("p", &records).is_none(),
                "accepted a publication whose url is {hostile:?}",
            );
        }
    }

    /// **Entry URLs are joined, not concatenated.**
    ///
    /// String concatenation produced `https://x.com/https://evil.com/a` for an
    /// absolute `path`, and put the path inside the query string for a base
    /// carrying one.
    #[test]
    fn entry_urls_are_joined_against_the_publication_base() {
        let records = vec![publication("p", "https://example.com/blog")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let docs = vec![
            document("a", &site, "Relative", "/a"),
            document("b", &site, "Absolute-looking", "https://evil.example/x"),
        ];
        let urls: Vec<Option<String>> = entries_from_records(&site, &pubn, &docs)
            .into_iter()
            .map(|e| e.url)
            .collect();
        assert_eq!(urls[0].as_deref(), Some("https://example.com/a"));
        // Exactly the publication's base, not merely "not evil": a mutation
        // that returned the raw path, or an empty string, passed the weaker
        // negative assertion this used to be.
        // Off-origin is dropped, not rewritten to the base. This assertion has
        // moved twice: it began as "not evil" (a mutant returning the raw path
        // passed it), was tightened to the base fallback, and is now `None` —
        // the base gave every affected entry the same homepage href.
        assert_eq!(
            urls[1], None,
            "a document path that escapes its publication's origin must yield no URL"
        );
    }

    /// 8% of measured documents (37 of 449) carry neither summary field.
    #[test]
    fn a_document_with_neither_summary_field_still_yields_an_entry() {
        let records = vec![publication("p", "https://example.com/")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let bare = rec(
            nsid::STANDARD_DOCUMENT,
            "bare",
            json!({
                "title": "Bare",
                "publishedAt": "2026-07-11T00:00:00Z",
                "path": "/bare",
                "site": site,
            }),
        );
        let entries = entries_from_records(&site, &pubn, &[bare]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].summary, None);
        assert_eq!(entries[0].url.as_deref(), Some("https://example.com/bare"));
    }

    /// `description` is the authored summary; `textContent` is the whole body.
    /// An EMPTY description must not shadow a real one.
    #[test]
    fn an_empty_description_does_not_shadow_the_body() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let doc = rec(
            nsid::STANDARD_DOCUMENT,
            "d",
            json!({
                "title": "T",
                "publishedAt": "2026-07-11T00:00:00Z",
                "path": "/d",
                "site": site,
                "description": "   ",
                "textContent": "the real body",
            }),
        );
        let entries = entries_from_records(&site, &pubn, &[doc]);
        assert_eq!(entries[0].summary.as_deref(), Some("the real body"));
    }

    /// **`publishedAt` is parsed, not passed through.** The store's `published`
    /// column is the RFC3339 shape `feed::fmt_time` writes, and the reading
    /// order sorts on it as a string. A publisher's string went in verbatim —
    /// a garbage value would have sorted arbitrarily among real ones, and a
    /// valid-but-differently-spelled one (`+00:00`, fractional seconds) would
    /// not have matched the RSS path's spelling for the same instant.
    #[test]
    fn published_at_is_normalised_or_dropped() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let with = |rkey: &str, published_at: serde_json::Value| {
            rec(
                nsid::STANDARD_DOCUMENT,
                rkey,
                json!({ "title": "T", "publishedAt": published_at, "path": "/x", "site": site }),
            )
        };
        let docs = vec![
            with("a", json!("2026-07-11T09:30:00.123+02:00")),
            with("b", json!("yesterday-ish")),
            with("c", json!("2026-07-11T00:00:00Z")),
        ];
        let published: Vec<Option<String>> = entries_from_records(&site, &pubn, &docs)
            .into_iter()
            .map(|e| e.published)
            .collect();
        assert_eq!(
            published,
            vec![
                Some("2026-07-11T07:30:00Z".to_string()),
                None,
                Some("2026-07-11T00:00:00Z".to_string()),
            ],
            "publishedAt was not normalised to the store's spelling"
        );
    }

    /// **Summaries are plain text and are escaped, not sanitised.**
    ///
    /// The lexicon defines `textContent` and `description` as plain text, and
    /// the store's `content_html` is rendered as HTML, so the text must be
    /// escaped on the way in. The first version of this ran `ammonia::clean`
    /// over them — the RSS body function — which parses its input as markup
    /// and deletes everything after a bare `<`. 321 of 449 measured documents
    /// use `textContent` as their summary; any post mentioning `Vec<T>` lost
    /// the rest of its summary, silently.
    #[test]
    fn summaries_are_escaped_as_plain_text_not_sanitised_as_markup() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let doc = |rkey: &str, body: &str| {
            rec(
                nsid::STANDARD_DOCUMENT,
                rkey,
                json!({
                    "title": "T",
                    "publishedAt": "2026-07-11T00:00:00Z",
                    "path": "/d",
                    "site": site,
                    "textContent": body,
                }),
            )
        };
        let summaries: Vec<String> = entries_from_records(
            &site,
            &pubn,
            &[
                doc("a", "Vec<String> is a type"),
                doc("b", "<script>alert(1)</script>"),
            ],
        )
        .into_iter()
        .filter_map(|e| e.summary)
        .collect();
        assert_eq!(
            summaries[0], "Vec&lt;String&gt; is a type",
            "prose was eaten by an HTML parser"
        );
        assert!(
            !summaries[1].contains("<script"),
            "escaping failed: {}",
            summaries[1]
        );
    }

    /// **`Entry.url` is a vetted href or nothing.** The scheme guarantee lived
    /// only inside `publication_from_records`; `entries_from_records` and
    /// `Publication` are both `pub`, so any other constructor — step 3 building
    /// one from the stored `feeds` row, say — gave an unparseable base, and the
    /// no-base branch then emitted the document's `path` verbatim. A
    /// `javascript:` path became the entry link. This is the class `safe_link`
    /// exists for.
    #[test]
    fn an_entry_url_is_never_an_unvetted_path() {
        let pubn = Publication {
            name: None,
            // What a caller that did not go through `publication_from_records`
            // can hand this function.
            url: "not a url".to_string(),
        };
        let site = canonical("p");
        let docs = vec![
            document("a", &site, "Hostile", "javascript:alert(1)"),
            document("b", &site, "Fine", "https://example.com/ok"),
        ];
        let entries = entries_from_records(&site, &pubn, &docs);
        assert_eq!(
            entries[0].url, None,
            "an unvetted path became an entry link"
        );
        // Contract change: with no parseable base there is no origin to check,
        // so a well-formed absolute URL is refused too. `safe_link` alone vets
        // the SCHEME; it would have published a publisher-controlled host under
        // this publication's name. See `no_parseable_base_means_no_url_not_any_url`.
        assert_eq!(
            entries[1].url, None,
            "an off-origin absolute URL was published under the publication's name"
        );
    }

    /// A document with no `publishedAt` is an entry with no date — the same
    /// answer a garbage one gets. The field the module is willing to discard
    /// must not be the one whose absence is fatal.
    #[test]
    fn a_document_without_published_at_is_still_an_entry() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let doc = rec(
            nsid::STANDARD_DOCUMENT,
            "d",
            json!({ "title": "T", "path": "/d", "site": site }),
        );
        let entries = entries_from_records(&site, &pubn, &[doc]);
        assert_eq!(
            entries.len(),
            1,
            "a missing publishedAt dropped the document"
        );
        assert_eq!(entries[0].published, None);
    }

    /// **`fetch` refuses a URI naming another collection, before the network.**
    /// It lists publications and matches on rkey alone, so without this an
    /// `app.bsky.feed.post` URI would be "read as a publication" whenever a
    /// publication in that repo shares the rkey. Storage enforces the
    /// collection today, but this function is `pub`.
    #[tokio::test]
    async fn fetch_refuses_a_uri_for_another_collection() {
        let uri = AtUri::parse(&format!("at://{DID}/app.bsky.feed.post/3lab")).unwrap();
        let err = fetch(&reqwest::Client::new(), "https://plc.example", &uri)
            .await
            .expect_err("read a feed post as a publication");
        assert!(
            format!("{err:#}").contains(nsid::STANDARD_PUBLICATION),
            "failed for the wrong reason: {err:#}"
        );
    }

    /// **A read becomes entries through the same store path RSS uses.**
    /// `store_publication` is the adapter: what `fetch` returns, mapped onto
    /// `upsert_feed` + `insert_entries` and reported as a `PollOutcome` the
    /// scheduler already knows how to settle.
    #[tokio::test]
    async fn a_publication_read_stores_its_documents_as_entries() -> anyhow::Result<()> {
        let pool = crate::store::init_url("sqlite::memory:").await?;
        let uri = format!("at://{DID}/{}/p", nsid::STANDARD_PUBLICATION);
        crate::store::upsert_feed(
            &pool,
            &crate::store::NewFeed {
                url: uri.clone(),
                ..Default::default()
            },
        )
        .await?;

        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let docs = vec![
            document("d1", &site, "First", "/one"),
            document("d2", &site, "Second", "/two"),
        ];
        let entries = entries_from_records(&site, &pubn, &docs);

        let outcome = store_publication(&pool, &uri, &pubn, entries, true, 100).await?;
        assert!(
            matches!(
                outcome,
                crate::feed::PollOutcome::Updated { new_entries: 2 }
            ),
            "expected two new entries, got {outcome:?}"
        );
        // The feed row carries the publication's title, and the guids are the
        // record URIs — not the mutable paths.
        let feed = crate::store::get_feed_by_url(&pool, &uri)
            .await?
            .expect("feed row");
        assert_eq!(feed.title.as_deref(), Some("Scan's Lab"));
        let guids: Vec<String> = sqlx::query_scalar("SELECT guid FROM entries ORDER BY guid")
            .fetch_all(&pool)
            .await?;
        assert_eq!(
            guids,
            vec![
                format!("at://{DID}/{}/d1", nsid::STANDARD_DOCUMENT),
                format!("at://{DID}/{}/d2", nsid::STANDARD_DOCUMENT),
            ]
        );
        Ok(())
    }

    /// **An incomplete read is not a complete poll.** `RecordWalk.complete`
    /// exists to carry "I did not read all of it" out to the caller; settling
    /// it as a clean `Updated` throws that away, and the feed looks healthy
    /// while silently missing articles.
    #[tokio::test]
    async fn an_incomplete_read_is_not_reported_as_a_clean_poll() -> anyhow::Result<()> {
        let pool = crate::store::init_url("sqlite::memory:").await?;
        let uri = format!("at://{DID}/{}/p", nsid::STANDARD_PUBLICATION);
        crate::store::upsert_feed(
            &pool,
            &crate::store::NewFeed {
                url: uri.clone(),
                ..Default::default()
            },
        )
        .await?;
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let entries = entries_from_records(&site, &pubn, &[document("d1", &site, "One", "/one")]);

        let outcome = store_publication(&pool, &uri, &pubn, entries, false, 100).await?;
        match outcome {
            crate::feed::PollOutcome::Failed {
                kind, ref detail, ..
            } => {
                assert_eq!(kind, crate::feed::FailureKind::Body);
                assert!(detail.contains("incomplete"), "detail: {detail}");
            }
            other => panic!("an incomplete read was settled as {other:?}"),
        }
        // The entries it DID read are still stored — a partial read is not a
        // discarded one.
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(&pool)
            .await?;
        assert_eq!(n, 1, "a partial read discarded the articles it had");
        Ok(())
    }

    /// **A publication on a subpath keeps it.** `Url::join` is RFC-3986, so a
    /// relative `posts/a` against `https://example.com/blog` resolves to
    /// `/posts/a` — dropping the subpath every permalink needs, while still
    /// passing the origin check. The base is normalised to a directory.
    #[test]
    fn a_subpath_publication_keeps_its_base_path() {
        let records = vec![publication("p", "https://example.com/blog")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let docs = vec![document("a", &site, "Relative", "posts/a")];
        let urls: Vec<Option<String>> = entries_from_records(&site, &pubn, &docs)
            .into_iter()
            .map(|e| e.url)
            .collect();
        assert_eq!(urls[0].as_deref(), Some("https://example.com/blog/posts/a"));
    }

    /// With no parseable base there is no origin to check, so there is no URL
    /// — `safe_link` alone vets the scheme and would pass any absolute URL a
    /// publisher chose, under this publication's name.
    #[test]
    fn no_parseable_base_means_no_url_not_any_url() {
        let pubn = Publication {
            name: None,
            url: "not a url".to_string(),
        };
        let site = canonical("p");
        let docs = vec![document("a", &site, "Absolute", "https://evil.example/x")];
        let entries = entries_from_records(&site, &pubn, &docs);
        assert_eq!(
            entries[0].url, None,
            "an off-origin absolute URL was published"
        );
    }

    /// **An off-origin path is dropped, not rewritten to the homepage.**
    /// Returning the base gave every affected entry the SAME href pointing at
    /// the site root — realistic whenever a publication's `url` is the apex
    /// and its documents sit on `www.` or a CDN domain. `None` is the honest
    /// answer, and the template already has a no-URL branch.
    #[test]
    fn an_off_origin_path_yields_no_url_rather_than_the_homepage() {
        let records = vec![publication("p", "https://example.com/blog")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let docs = vec![
            document("a", &site, "Elsewhere", "https://www.example.com/post"),
            document("b", &site, "Home", "/ok"),
        ];
        let urls: Vec<Option<String>> = entries_from_records(&site, &pubn, &docs)
            .into_iter()
            .map(|e| e.url)
            .collect();
        assert_eq!(
            urls[0], None,
            "an off-origin path was rewritten to the base"
        );
        assert_eq!(urls[1].as_deref(), Some("https://example.com/ok"));
    }

    /// **A blank `path` is no URL, not the homepage** — the same answer the
    /// off-origin branch now gives, and for the same reason: several
    /// documents with an empty `path` otherwise became several entries all
    /// linking to the site root.
    #[test]
    fn a_blank_path_yields_no_url() {
        let records = vec![publication("p", "https://example.com/blog")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let docs = vec![
            document("a", &site, "Blank", ""),
            document("b", &site, "Spaces", "   "),
            document("c", &site, "Real", "/real"),
        ];
        let urls: Vec<Option<String>> = entries_from_records(&site, &pubn, &docs)
            .into_iter()
            .map(|e| e.url)
            .collect();
        assert_eq!(urls[0], None, "a blank path became the homepage");
        assert_eq!(urls[1], None, "a whitespace path became the homepage");
        assert_eq!(urls[2].as_deref(), Some("https://example.com/real"));
    }

    /// A document without `path` keeps its title, date and summary — the
    /// policy `publishedAt` and `Entry.url` already follow.
    #[test]
    fn a_document_without_a_path_is_still_an_entry() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let doc = rec(
            nsid::STANDARD_DOCUMENT,
            "d",
            json!({ "title": "T", "publishedAt": "2026-07-11T00:00:00Z", "site": site }),
        );
        let entries = entries_from_records(&site, &pubn, &[doc]);
        assert_eq!(
            entries.len(),
            1,
            "a missing path dropped the whole document"
        );
        assert_eq!(entries[0].title, "T");
        assert_eq!(entries[0].url, None);
    }

    /// **A sibling is not an orphan.** A repo with an empty publication A and
    /// a busy publication B is the exact shape the `site` filter exists for;
    /// treating B's documents as a signal would warn on every poll of A
    /// forever. The signal is a document referencing a publication this repo
    /// does not have — a spelling nothing can ever match.
    #[test]
    fn documents_are_classified_keep_sibling_or_orphan() {
        let pubs = [
            publication("a", "https://example.com"),
            publication("b", "https://b.example"),
        ];
        let known: std::collections::HashSet<&str> = pubs.iter().map(|p| p.uri.as_str()).collect();
        let mine = canonical("a");
        let fate = |d: &crate::atproto::RecordEntry| classify_document(d, &mine, &known);

        assert_eq!(
            fate(&document("d1", &mine, "Mine", "/1")),
            DocumentFate::Keep
        );
        assert_eq!(
            fate(&document("d2", &canonical("b"), "B's", "/2")),
            DocumentFate::Sibling,
            "a sibling publication's document is not an orphan"
        );
        assert_eq!(
            fate(&document(
                "d3",
                "at://did:plc:other/site.standard.publication/x",
                "?",
                "/3"
            )),
            DocumentFate::Orphan
        );
        assert_eq!(
            fate(&rec(
                nsid::STANDARD_DOCUMENT,
                "d4",
                json!({"title": "no rest"})
            )),
            DocumentFate::Malformed
        );
    }

    /// `AtUri` uses the crate's one spelling of the prefix.
    #[test]
    fn at_uri_parsing_uses_the_shared_prefix() {
        let uri = format!(
            "{}{DID}/{}/abc",
            crate::atproto::AT_URI_PREFIX,
            nsid::STANDARD_PUBLICATION
        );
        assert!(AtUri::parse(&uri).is_some());
    }

    /// The guid is the record's own URI. `path` is mutable; dedup is
    /// `UNIQUE (feed_id, guid)`.
    #[test]
    fn the_guid_is_the_record_uri_not_the_path() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let docs = vec![document("rk1", &site, "T", "/moved")];
        let entries = entries_from_records(&site, &pubn, &docs);
        assert_eq!(
            entries[0].guid,
            format!("at://{DID}/{}/rk1", nsid::STANDARD_DOCUMENT)
        );
    }

    /// One unreadable record must not cost a publisher the whole feed.
    #[test]
    fn a_malformed_document_is_skipped_rather_than_fatal() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let docs = vec![
            rec(
                nsid::STANDARD_DOCUMENT,
                "bad",
                json!({ "title": "no rest" }),
            ),
            document("ok", &site, "Good", "/good"),
        ];
        let entries = entries_from_records(&site, &pubn, &docs);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Good");
    }

    /// An rkey that is not in the repo is absent, not an error.
    #[test]
    fn a_missing_publication_is_none() {
        let records = vec![publication("other", "https://example.com")];
        assert!(publication_from_records("p", &records).is_none());
    }

    #[test]
    fn at_uris_parse_in_both_forms_and_reject_malformed_ones() {
        let did = AtUri::parse(&format!("at://{DID}/site.standard.publication/abc")).unwrap();
        assert_eq!(did.authority, DID);
        assert_eq!(did.rkey, "abc");
        assert_eq!(
            did.to_string(),
            format!("at://{DID}/site.standard.publication/abc")
        );
        assert!(AtUri::parse("at://alice.example.com/site.standard.publication/abc").is_some());
        for bad in [
            "at://",
            "at://only-authority",
            "at://authority/collection",
            "at://authority/collection/",
            "at:///collection/rkey",
            "at://authority/collection/rkey/extra",
            "https://example.com/feed.xml",
            "at:authority/collection/rkey",
        ] {
            assert!(AtUri::parse(bad).is_none(), "parsed {bad:?}");
        }
    }
}
