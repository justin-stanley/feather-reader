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

/// What one read of a publication produced.
///
/// **`complete` is the fact the store cannot recover afterwards.** A truncated
/// walk and a short publication return the same entries; the difference decides
/// whether an empty result is a quiet blog or a read that gave up, and the
/// caller has no other way to tell. `fetch` used to drop it on the floor after
/// logging a warning.
#[derive(Debug)]
pub struct PublicationRead {
    pub publication: Publication,
    pub entries: Vec<Entry>,
    pub complete: bool,
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
    /// When the document was published, re-spelled by `crate::feed::fmt_time`
    /// into the store's one RFC3339 shape. The reading order sorts on this
    /// column as a string, so a publisher's spelling cannot go in verbatim.
    ///
    /// Taken from `publishedAt` when it parses AND is not in the future,
    /// otherwise from the TID in the record key, otherwise `None`. See
    /// `entries_from_records` for why a future date is discarded rather than
    /// clamped, and why an undated entry is left undated.
    pub published: Option<String>,
    /// The joined, **scheme-vetted** permalink — `None` when the document's
    /// `path` does not resolve to a safe href on the publication's origin.
    /// `Option` because the guarantee cannot be met unconditionally and the
    /// store's column is optional too; a title-only entry is not a failure.
    pub url: Option<String>,
    /// `description`, else `textContent`, escaped by
    /// `crate::feed::plain_text_to_html` — both are plain text in the
    /// lexicon, and the column they land in is rendered as HTML.
    pub summary: Option<String>,
}

impl From<Entry> for crate::store::NewEntry {
    /// The shape the poller stores. Kept here, next to the fields it maps,
    /// so wiring the reader to the scheduler has nothing left to decide.
    fn from(e: Entry) -> Self {
        crate::store::NewEntry {
            // The document's URI, which the publisher's PDS chose: bounded like
            // any entry id before it reaches the UNIQUE index (found in review).
            guid: crate::feed::bound_guid(e.guid),
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
            name: value
                .name
                .map(|n| crate::feed::bound_text(n, crate::feed::MAX_TITLE_BYTES)),
            url: crate::feed::bound_text(url, crate::feed::MAX_URL_BYTES),
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
    // One "now" for the whole batch, so two documents of the same poll are
    // judged against the same instant rather than one being called credible and
    // an identical one not. (`tid_timestamp` reads the clock again for its own
    // ceiling; that only ever tightens a bound five minutes away, so it needs
    // no such agreement.)
    let now = chrono::Utc::now();
    // The SAME allowance the record-key branch gets. A publisher's clock runs
    // ahead of ours as readily as a PDS's does, and judging a stated date
    // against a bare `now` while the rkey below gets five minutes discarded a
    // perfectly good date and left the newest post undated — which, ordered on
    // a bare `published DESC`, puts it at the bottom of the list.
    let ceiling = now + chrono::Duration::seconds(crate::atproto::CLOCK_SKEW_GRACE_SECS);
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
                title: crate::feed::bound_text(doc.title, crate::feed::MAX_TITLE_BYTES),
                // **Three rules, in order: what the publisher credibly said,
                // then when the record was written, then nothing.**
                //
                // A stated date in the future is DISCARDED, not clamped to now.
                // The store refreshes `published` on every poll but stamps
                // `fetched_at` only once, so a date derived from the current
                // clock is rewritten hourly: the row stays the newest thing in
                // the feed forever, is never swept, is never evicted by the
                // per-feed cap, and sits at the top of the reading list re-dated
                // to today. Clamping moved the defect rather than fixing it.
                // Every fall-through here holds still instead — the TID is the
                // record's real write time, and an undated row is dated by
                // `fetched_at`, which never moves. An rkey that is not a TID
                // leaves the entry undated rather than inventing a date from a
                // slug.
                published: doc
                    .published_at
                    .as_deref()
                    .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
                    .map(|d| d.with_timezone(&chrono::Utc))
                    .filter(|d| *d <= ceiling)
                    .or_else(|| {
                        AtUri::parse(&record.uri)
                            .and_then(|uri| crate::atproto::tid_timestamp(&uri.rkey))
                    })
                    .map(crate::feed::fmt_time),
                // `non_blank` for the same reason the summary uses it: a blank
                // path joins to the publication's own base, so a handful of
                // documents with an empty `path` became a handful of entries
                // all linking to the site root.
                url: non_blank(doc.path)
                    .as_deref()
                    .and_then(|path| join_path(base.as_ref(), path))
                    .map(|u| crate::feed::bound_text(u, crate::feed::MAX_URL_BYTES)),
                // `description` first — the authored summary — but only when it
                // actually says something: a blank one must not shadow the body.
                // Then ESCAPED, not sanitised: both fields are plain text.
                summary: non_blank(doc.description)
                    .or_else(|| non_blank(doc.text_content))
                    .map(|raw| {
                        crate::feed::plain_text_to_html_bounded(
                            &raw,
                            crate::feed::MAX_CONTENT_HTML_BYTES,
                        )
                    }),
            })
        })
        .collect()
}

/// The ingest floor: the oldest `published` an entry may carry and still be worth
/// storing, or `None` for "store anything".
///
/// **The floor is the window the SWEEP would use, which is not the smaller of the
/// two.** `store::prune_old_entries` honours the hard ceiling only when it is
/// strictly older than the rolling window, or when there is no window at all
/// (`hard_days > 0 && (days <= 0 || hard_days > days)`); a ceiling inside the
/// window is logged and ignored there, because the hard delete spares nothing and
/// would otherwise delete exactly the rows the soft delete exists to spare.
///
/// So the earliest thing that can delete a row is `retention_days` when there is
/// a window, and the ceiling only when there is not.
///
/// **The pair comes from [`crate::config::Config::retention_for`], and for a
/// publication it is not the RSS window.** That function is the one home for which
/// window applies to which kind, precisely so this and the sweep cannot drift: a
/// publication gets `(0, publication_retention_days)` — no rolling window, and a
/// generous archive ceiling — because a 14-day window stored ZERO rows from every
/// real publication measured, their newest documents being 109 to 241 days old.
/// Fed that pair, the `days == 0` branch below falls through to the ceiling, which
/// is exactly the sweep pass that can delete such a row.
///
/// `a_publications_floor_is_its_archive_ceiling_not_the_rss_window` asserts the
/// two halves agree; it is the test that fails if either side is changed alone.
///
/// Two wrong versions, both worth naming. Keying on `retention_days` alone left
/// `retention_days = 0` unfloored while the ceiling still deleted at
/// `retention_hard_days` — the exact cycle the floor exists to prevent, and a
/// worse one, since the ceiling spares nothing and a starred entry came back
/// unstarred rather than merely unread. Reaching for the MINIMUM then
/// over-corrected: at `days = 180, hard = 30` the sweep ignores the ceiling and
/// deletes nothing before 180 days, while `min` floored ingest at 30 and silently
/// discarded five months of a publisher's archive that nothing would have deleted.
///
/// **An unrepresentable window is no floor, said directly.** `RETENTION_DAYS`
/// parses into a `u32` with no upper bound, and `u32::MAX` days is an operator
/// saying "keep everything"; both the duration and the subtraction can fail, and
/// either failure means `None` here. The previous shape fell back to a sentinel
/// instant (`MIN_UTC`) and left the outcome resting on the fact that the row
/// comparison is LEXICOGRAPHIC: `fmt_time` renders an out-of-range year with a
/// `+`/`-` sign, which sorts either side of a 4-digit year by ASCII accident
/// rather than by date. Verified: swapping that fallback to `MAX_UTC` — a floor
/// of the year 262143, which should discard every entry in existence — changed
/// nothing, because `"2026…" > "+262143…"`. With `None` the ambiguity is gone,
/// and the comparison never sees a date outside the range it can order.
///
/// `now` is a parameter so this is testable without the clock.
fn ingest_floor(
    retention_days: u32,
    retention_hard_days: u32,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<String> {
    let days = if retention_days > 0 {
        retention_days
    } else if retention_hard_days > 0 {
        retention_hard_days
    } else {
        return None;
    };
    let window = chrono::Duration::try_days(days.into())?;
    now.checked_sub_signed(window).map(crate::feed::fmt_time)
}

/// Persist one publication read, and say what the poll amounted to.
///
/// `retention_days` is the ingest floor: an entry whose stated date is already
/// older than the window is not stored, because storing it means the next sweep
/// deletes it and the next poll re-inserts it with a new row id — which loses its
/// read state and arrives unread, on that cycle, forever.
///
/// **For a publication the caller passes `Config::retention_for`'s pair, which is
/// the archive ceiling rather than the 14-day window** — so in practice almost
/// nothing is floored out here, which is the point: measured, a 14-day floor
/// dropped every document of every real publication tried. See `ingest_floor`.
///
/// **An entry with no date is stored anyway.** That is a decision, not an
/// oversight: it is dated by `fetched_at` instead, which does not move, and the
/// alternative is discarding an article the reader can never see.
///
/// Three consequences, stated because an earlier version of this comment named
/// only the first and called it "accepted":
///
/// * It resurrects once per retention window. `fetched_at` is stamped at the
///   first insert and never refreshed, so the row ages out, is swept once the
///   reader has read it, and is re-inserted unread by the next poll.
/// * Under the hard ceiling it comes back **unstarred as well**. The soft sweep
///   spares `starred = 1 OR read = 0`; the ceiling spares nothing.
/// * Until then it OUTRANKS the publication's real articles. Both the sweep and
///   the per-feed cap order on `COALESCE(published, fetched_at)`, so an undated
///   entry sorts by the moment it was fetched — that is, as the newest thing in
///   the feed — and a publication whose documents are mostly undated can push
///   dated articles out of `max_entries_per_feed`.
///
/// **`new_entries` is an upper bound, not a count of rows that survived.**
/// `insert_entries` reports what it inserted, and the per-feed cap then trims
/// within the same call, so a poll that inserted 30 rows into a feed capped at 10
/// can report 30.
pub async fn store_publication(
    pool: &sqlx::SqlitePool,
    url: &str,
    read: PublicationRead,
    max_entries_per_feed: i64,
    retention_days: u32,
    retention_hard_days: u32,
) -> anyhow::Result<crate::feed::PollOutcome> {
    let offered = read.entries.len();

    // **The failure check runs before anything is written.** Stamping the feed
    // and then returning `Failed` is the shape that makes a broken publication
    // read as freshly polled on `/stats`, and it is easy to write by accident
    // because the upsert is the natural first step.
    //
    // **Keyed on what was OFFERED, not on what survives the floor.** A truncated
    // read that produced nothing means the walk gave up before its first record.
    // A truncated read whose entries are merely older than the window is a
    // healthy poll of an old publication, and calling that a failure puts it into
    // backoff that widens forever.
    if !read.complete && offered == 0 {
        return Ok(crate::feed::PollOutcome::Failed {
            backoff: crate::feed::backoff_for(1),
            kind: crate::feed::FailureKind::Body,
            detail: crate::feed::failure_detail(
                "the publication read stopped before its first document",
            ),
        });
    }

    // See [`ingest_floor`] for which of the two windows this is, and why.
    let floor = ingest_floor(retention_days, retention_hard_days, chrono::Utc::now());
    let rows: Vec<crate::store::NewEntry> = read
        .entries
        .into_iter()
        .filter(|e| match (&floor, &e.published) {
            // Lexicographic on the store's one RFC3339 spelling, which sorts
            // chronologically by construction.
            (Some(floor), Some(published)) => published.as_str() >= floor.as_str(),
            // No floor, or no date. The undated case is the decision the doc
            // above records: kept, dated by `fetched_at`, and it resurrects once
            // per window.
            _ => true,
        })
        .map(Into::into)
        .collect();

    // **Say when the floor emptied the read.** A complete read of three
    // year-old posts and a complete read of an empty publication both return
    // `Updated { new_entries: 0 }`, stamp the feed, and look green — so a
    // subscriber to an archived blog gets a blank feed and nothing anywhere says
    // why. `offered` is already in hand.
    if offered > rows.len() {
        tracing::info!(
            feed = %url,
            offered,
            stored = rows.len(),
            "the retention floor dropped documents older than the window"
        );
    }

    let feed_id = crate::store::upsert_feed(
        pool,
        &crate::store::NewFeed {
            url: url.to_string(),
            title: read.publication.name.clone(),
            site_url: Some(read.publication.url.clone()),
            last_polled: Some(crate::feed::fmt_time(chrono::Utc::now())),
            ..Default::default()
        },
    )
    .await?;

    let new_entries =
        crate::store::insert_entries(pool, feed_id, &rows, max_entries_per_feed).await?;
    Ok(crate::feed::PollOutcome::Updated { new_entries })
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
    /// Belongs to the requested publication at this index.
    Keep(usize),
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
    wanted: &std::collections::HashMap<String, usize>,
    known: &std::collections::HashSet<&str>,
) -> DocumentFate {
    match serde_json::from_value::<DocumentValue>(record.value.clone()) {
        Ok(doc) if wanted.contains_key(&doc.site) => DocumentFate::Keep(wanted[&doc.site]),
        Ok(doc) if known.contains(doc.site.as_str()) => DocumentFate::Sibling,
        Ok(_) => DocumentFate::Orphan,
        Err(_) => DocumentFate::Malformed,
    }
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
/// - an XRPC error envelope surfaces as [`crate::atproto::AtProtoError::Xrpc`] rather
///   than deserialising into an empty page.
///
/// The first draft of this module reimplemented all of that, worse. The only
/// logic left here is the part that is genuinely about standard.site.
pub async fn fetch(
    http: &reqwest::Client,
    plc_directory: &str,
    uri: &AtUri,
) -> anyhow::Result<PublicationRead> {
    // The collection is part of the identity of what was subscribed to, and
    // this function is `pub`: without the check it lists publications and
    // matches on rkey alone, so `at://did/app.bsky.feed.post/<rkey>` would be
    // "read as a publication" whenever a publication shares that rkey.
    if uri.collection != nsid::STANDARD_PUBLICATION {
        return Err(
            NotAPublication(format!("{uri} is not a {} URI", nsid::STANDARD_PUBLICATION)).into(),
        );
    }
    fetch_repo(
        http,
        plc_directory,
        &uri.authority,
        std::slice::from_ref(&uri.rkey),
    )
    .await?
    .pop()
    .unwrap_or_else(|| Err(NotAPublication(format!("{uri} was not read")).into()))
}

/// **The repo answered, and what it holds is not this publication** — the
/// record was deleted, never existed, or is unreadable, or the URI names
/// another collection.
///
/// Typed so the poller can tell it from a network failure: filed as `Fetch`,
/// an author deleting their publication read as their server being down, in
/// the public cause histogram (found in review).
#[derive(Debug)]
pub struct NotAPublication(pub String);

impl std::fmt::Display for NotAPublication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NotAPublication {}

/// Read several publications in ONE repo with one walk of its documents.
pub async fn fetch_repo(
    http: &reqwest::Client,
    plc_directory: &str,
    did: &str,
    rkeys: &[String],
) -> anyhow::Result<Vec<anyhow::Result<PublicationRead>>> {
    fetch_repo_capped(
        http,
        plc_directory,
        did,
        rkeys,
        crate::atproto::MAX_LARGE_RECORDS,
    )
    .await
}

/// [`fetch_repo`] with the per-publication document cap passed in, so the
/// fairness between siblings is testable without 2,000 documents.
pub(crate) async fn fetch_repo_capped(
    http: &reqwest::Client,
    plc_directory: &str,
    did: &str,
    rkeys: &[String],
    per_site_cap: usize,
) -> anyhow::Result<Vec<anyhow::Result<PublicationRead>>> {
    use anyhow::Context;

    let pds = crate::atproto::resolve_did_to_pds(http, plc_directory, did)
        .await
        .with_context(|| format!("resolving the PDS for {did}"))?;
    let client = crate::atproto::PdsClient::anonymous(http.clone(), pds, did.to_string());

    // **One budget for both walks, because they nest.** The publications are
    // still held when the documents walk runs, so two ceilings would let this
    // read hold twice the bound the box was sized for.
    let mut budget = crate::atproto::ByteBudget::new(crate::atproto::MAX_LIST_BYTES);
    let (publications, skipped_publications) = client
        .list_all_records_skipping_within(nsid::STANDARD_PUBLICATION, &mut budget)
        .await
        .with_context(|| format!("listing publications for {did}"))?;
    if skipped_publications > 0 {
        tracing::warn!(
            repo = %did,
            skipped = skipped_publications,
            "skipped malformed publication records in this repo"
        );
    }

    // Each requested publication, if this repo holds it.
    let wanted: Vec<Option<(String, Publication)>> = rkeys
        .iter()
        .map(|rkey| publication_from_records(rkey, &publications))
        .collect();
    let index_of: std::collections::HashMap<String, usize> = wanted
        .iter()
        .enumerate()
        .filter_map(|(i, w)| w.as_ref().map(|(site, _)| (site.clone(), i)))
        .collect();
    let not_found = |rkey: &str| {
        anyhow::Error::new(NotAPublication(format!(
            "at://{did}/{}/{rkey} is not a readable site.standard.publication",
            nsid::STANDARD_PUBLICATION
        )))
    };
    if index_of.is_empty() {
        return Ok(rkeys.iter().map(|r| Err(not_found(r))).collect());
    }

    // **One walk of the documents for every requested publication, with a
    // cap PER publication.** Filtered inside the walk, so each cap counts
    // that publication's own documents: a shared cap would let a busy
    // publication fill the window and starve a quiet sibling — permanently,
    // and worse with every post the busy one makes.
    let known: std::collections::HashSet<&str> =
        publications.iter().map(|p| p.uri.as_str()).collect();
    let mut kept_per = vec![0usize; rkeys.len()];
    let mut capped = vec![false; rkeys.len()];
    let mut orphaned = 0usize;
    let documents = client
        .list_recent_matching_within(
            nsid::STANDARD_DOCUMENT,
            per_site_cap.saturating_mul(index_of.len()),
            &mut budget,
            DOCUMENT_PAGE_SIZE,
            |record| match classify_document(record, &index_of, &known) {
                DocumentFate::Keep(i) if kept_per[i] < per_site_cap => {
                    kept_per[i] += 1;
                    true
                }
                DocumentFate::Keep(i) => {
                    capped[i] = true;
                    false
                }
                // Orphans are counted while WALKING: a `site` spelling nothing
                // in this repo matches looks exactly like an empty publication
                // otherwise.
                DocumentFate::Orphan => {
                    orphaned += 1;
                    false
                }
                DocumentFate::Sibling | DocumentFate::Malformed => false,
            },
        )
        .await
        .with_context(|| format!("listing documents for {did}"))?;

    // Split the one walk back into one read per publication.
    let mut per_site: Vec<Vec<crate::atproto::RecordEntry>> = vec![Vec::new(); rkeys.len()];
    for record in documents.records {
        let site = serde_json::from_value::<DocumentValue>(record.value.clone()).map(|d| d.site);
        if let Some(&i) = site.ok().as_deref().and_then(|s| index_of.get(s)) {
            per_site[i].push(record);
        }
    }
    Ok(wanted
        .into_iter()
        .zip(per_site)
        .enumerate()
        .map(|(i, (w, records))| match w {
            None => Err(not_found(&rkeys[i])),
            Some((site, publication)) => {
                let walk = crate::atproto::RecordWalk {
                    records,
                    complete: documents.complete && !capped[i],
                    malformed: documents.malformed,
                };
                Ok(read_from(publication, &site, walk, orphaned))
            }
        })
        .collect())
}

/// Assemble a [`PublicationRead`] from a finished walk.
///
/// **Extracted so `complete` is testable.** It is the one fact the store cannot
/// recover afterwards, and reaching the `false` case through `fetch` needs a PLC
/// directory, a PDS, and a walk that truncates — three mocked hosts for one
/// boolean. Reaching it here needs a struct.
fn read_from(
    publication: Publication,
    canonical_site: &str,
    documents: crate::atproto::RecordWalk,
    orphaned: usize,
) -> PublicationRead {
    let entries = entries_from_records(canonical_site, &publication, &documents.records);

    // **A walk that stopped early is not a short archive.** Reading part of a
    // publication is acceptable; reporting it as the whole of one is not, and
    // when the part is empty — a quiet publication whose busy sibling fills
    // every page this reader will fetch — the feed looks healthy and stays
    // empty forever.
    // Logged AND returned. Logging it alone is how the fact that the walk gave
    // up reached nobody who could act on it: a truncated read and a short
    // publication produce the same entries, and only the caller can tell the
    // difference between "quiet blog" and "we stopped early".
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
    // **Skipped records are said out loud** (#177), for the same reason as
    // orphans below: a document we could not read looks exactly like one that
    // was never written.
    if documents.malformed > 0 {
        tracing::warn!(
            site = %canonical_site,
            skipped = documents.malformed,
            "skipped malformed document records for this publication"
        );
    }
    if orphaned > 0 {
        tracing::warn!(
            site = %canonical_site,
            orphaned,
            "documents in this repo reference no publication in it — a `site` spelling nothing matches"
        );
    }
    PublicationRead {
        publication,
        entries,
        complete: documents.complete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atproto::RecordEntry;
    use serde_json::json;

    const DID: &str = "did:plc:ohutz6x5acjmpuulp3x7wxxc";

    /// **A walk that gave up must not report itself as a whole publication.**
    ///
    /// `fetch` used to log that and return only the entries, so the fact reached
    /// nobody who could act on it — and a truncated read and a quiet blog produce
    /// exactly the same entries.
    #[test]
    fn a_read_carries_whether_the_walk_finished() {
        let publication = Publication {
            name: Some("Scan's Lab".to_string()),
            url: "https://example.com/blog/".to_string(),
        };
        for complete in [true, false] {
            let walk = crate::atproto::RecordWalk {
                records: Vec::new(),
                complete,
                malformed: 0,
            };
            let read = read_from(publication.clone(), "at://d/c/r", walk, 0);
            assert_eq!(
                read.complete, complete,
                "the walk said complete={complete} and the read said {}",
                read.complete
            );
        }
    }

    // -- storing a publication read -----------------------------------------

    fn read_of(entries: Vec<Entry>, complete: bool) -> PublicationRead {
        PublicationRead {
            publication: Publication {
                name: Some("Scan's Lab".to_string()),
                url: "https://example.com/blog/".to_string(),
            },
            entries,
            complete,
        }
    }

    fn entry_dated(guid: &str, published: Option<&str>) -> Entry {
        Entry {
            guid: guid.to_string(),
            title: "T".to_string(),
            published: published.map(str::to_string),
            url: Some("https://example.com/blog/a".to_string()),
            summary: None,
        }
    }

    fn days_ago(n: i64) -> String {
        crate::feed::fmt_time(chrono::Utc::now() - chrono::Duration::days(n))
    }

    const PUB_URL: &str = "at://did:plc:ohutz6x5acjmpuulp3x7wxxc/site.standard.publication/3lab";

    async fn pool() -> sqlx::SqlitePool {
        crate::store::init_url("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn a_complete_read_stores_its_entries_and_reports_them() {
        let pool = pool().await;
        let read = read_of(
            vec![
                entry_dated("at://d/c/1", Some(&days_ago(1))),
                entry_dated("at://d/c/2", Some(&days_ago(2))),
            ],
            true,
        );
        let outcome = store_publication(&pool, PUB_URL, read, 0, 14, 180)
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                crate::feed::PollOutcome::Updated { new_entries: 2 }
            ),
            "expected two new entries, got {outcome:?}"
        );
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 2, "the entries were not stored");
    }

    /// **Starvation is keyed on what was OFFERED, not on what was stored.**
    ///
    /// A truncated read that produced nothing is a failure: the walk gave up
    /// before the first record. But a truncated read whose entries the retention
    /// floor dropped is not — the read worked, the entries are simply older than
    /// the window, and calling that a failure puts a healthy publication into
    /// backoff forever.
    #[tokio::test]
    async fn an_incomplete_read_that_offered_nothing_is_a_failure() {
        let pool = pool().await;
        let outcome = store_publication(&pool, PUB_URL, read_of(vec![], false), 0, 14, 180)
            .await
            .unwrap();
        assert!(
            matches!(outcome, crate::feed::PollOutcome::Failed { .. }),
            "a truncated read that produced nothing is not a healthy poll: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn an_incomplete_read_whose_entries_the_floor_dropped_is_not_a_failure() {
        let pool = pool().await;
        let read = read_of(
            vec![entry_dated("at://d/c/old", Some(&days_ago(900)))],
            false,
        );
        let outcome = store_publication(&pool, PUB_URL, read, 0, 14, 180)
            .await
            .unwrap();
        assert!(
            !matches!(outcome, crate::feed::PollOutcome::Failed { .. }),
            "the read offered an entry; the floor dropping it is not a failed poll: {outcome:?}"
        );
    }

    /// A failed poll must not look like a successful one on `/stats`.
    #[tokio::test]
    async fn a_failed_read_does_not_stamp_last_polled() {
        let pool = pool().await;
        let outcome = store_publication(&pool, PUB_URL, read_of(vec![], false), 0, 14, 180)
            .await
            .unwrap();
        assert!(matches!(outcome, crate::feed::PollOutcome::Failed { .. }));
        let stamped: Option<String> =
            sqlx::query_scalar("SELECT last_polled FROM feeds WHERE url = ?1")
                .bind(PUB_URL)
                .fetch_optional(&pool)
                .await
                .unwrap()
                .flatten();
        assert_eq!(
            stamped, None,
            "a failed poll stamped last_polled, so the feed reads as freshly polled"
        );
    }

    #[tokio::test]
    async fn an_entry_already_older_than_the_window_is_not_stored() {
        let pool = pool().await;
        let read = read_of(
            vec![
                entry_dated("at://d/c/fresh", Some(&days_ago(1))),
                entry_dated("at://d/c/ancient", Some(&days_ago(900))),
            ],
            true,
        );
        store_publication(&pool, PUB_URL, read, 0, 14, 180)
            .await
            .unwrap();
        let guids: Vec<String> = sqlx::query_scalar("SELECT guid FROM entries ORDER BY guid")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(
            guids,
            vec!["at://d/c/fresh".to_string()],
            "an entry the next sweep would delete was stored anyway"
        );
    }

    /// **The floor follows whichever window actually deletes, not the rolling one.**
    ///
    /// `retention_days = 0` is a supported configuration meaning "no rolling
    /// window", and the hard ceiling stays alive independently. Keying the ingest
    /// floor on the rolling window alone let a 900-day-old entry in, which the
    /// ceiling then deleted and the next poll re-inserted — and the ceiling spares
    /// nothing, so a starred entry came back unstarred.
    #[tokio::test]
    async fn the_floor_follows_the_hard_ceiling_when_the_window_is_disabled() {
        let pool = pool().await;
        let read = read_of(
            vec![entry_dated("at://d/c/ancient", Some(&days_ago(900)))],
            true,
        );
        store_publication(&pool, PUB_URL, read, 0, 0, 180)
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            n, 0,
            "an entry the hard ceiling will delete was stored, so it will resurrect"
        );
    }

    /// **The WINDOW is the floor when there is one, because it deletes first.**
    ///
    /// With a 14-day rolling window and a 180-day ceiling, an entry 100 days old
    /// is inside the ceiling and outside the window — so the sweep takes it once
    /// it has been read and the next poll puts it back. Taking the longer of the
    /// two would store it.
    #[tokio::test]
    async fn the_floor_follows_the_window_when_both_are_set() {
        let pool = pool().await;
        let read = read_of(
            vec![entry_dated("at://d/c/hundred", Some(&days_ago(100)))],
            true,
        );
        store_publication(&pool, PUB_URL, read, 0, 14, 180)
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            n, 0,
            "an entry inside the ceiling but outside the window was stored, so it will cycle"
        );
    }

    /// With both windows off there is no floor, because nothing will delete it.
    /// **The two halves of the retention policy, asserted against each other.**
    ///
    /// `Config::retention_for` decides which window a kind gets; `ingest_floor`
    /// decides what is worth storing; `store::prune_old_entries` decides what is
    /// deleted. The first two are asserted here against the third's rule, because
    /// a drift between them is the resurrection cycle — a row the store keeps, the
    /// sweep deletes, and the next poll re-inserts unread — and nothing else in the
    /// suite would notice one side changing alone.
    ///
    /// The publication case is the one that matters: fed the RSS window a
    /// publication stores nothing at all, because a real one's newest document is
    /// months old.
    #[test]
    fn a_publications_floor_is_its_archive_ceiling_not_the_rss_window() {
        let config = crate::config::Config::default();
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-29T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let (days, hard) = config.retention_for(crate::feed::FeedKind::Publication);
        let floor = ingest_floor(days, hard, now).expect("a publication has an ingest floor");
        let expected = crate::feed::fmt_time(
            now - chrono::Duration::days(config.publication_retention_days.into()),
        );
        assert_eq!(
            floor, expected,
            "a publication's floor must be its archive ceiling ({} days), because \
             that is the only sweep pass that can delete its rows",
            config.publication_retention_days,
        );

        // And the number this rules OUT: the RSS window would drop every document
        // of every real publication measured (newest 109 to 241 days old).
        let rss_floor = ingest_floor(config.retention_days, config.retention_hard_days, now)
            .expect("an RSS feed has an ingest floor");
        assert!(
            floor < rss_floor,
            "the publication floor ({floor}) is no older than the RSS one \
             ({rss_floor}), so a months-old document would still be dropped",
        );
        let a_real_publications_newest_document =
            crate::feed::fmt_time(now - chrono::Duration::days(109));
        assert!(
            a_real_publications_newest_document.as_str() >= floor.as_str(),
            "the newest document a real publication offered would be refused at \
             ingest: {a_real_publications_newest_document} against a floor of {floor}",
        );
        assert!(
            a_real_publications_newest_document.as_str() < rss_floor.as_str(),
            "this assertion is only meaningful while the RSS window WOULD have \
             dropped it, and it no longer does",
        );
    }

    /// **The floor, all four configurations, without a database or the clock.**
    ///
    /// The end-to-end tests below observe the floor through what gets stored,
    /// which cannot see the difference between "no floor" and "a floor the
    /// lexicographic row comparison happens to sort past". This asserts the value
    /// itself.
    #[test]
    fn the_ingest_floor_is_the_window_the_sweep_would_use() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-26T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        assert_eq!(
            ingest_floor(14, 180, now).as_deref(),
            Some("2026-09-12T12:00:00Z"),
            "with both set, the floor is the WINDOW — the thing that deletes first",
        );
        assert_eq!(
            ingest_floor(180, 30, now).as_deref(),
            Some("2026-03-30T12:00:00Z"),
            "a ceiling INSIDE the window is one `prune_old_entries` ignores, so it \
             must not lower the floor — `min` here discarded five months of archive \
             that nothing would have deleted",
        );
        assert_eq!(
            ingest_floor(0, 30, now).as_deref(),
            Some("2026-08-27T12:00:00Z"),
            "with no window the ceiling stands alone, and it still deletes",
        );
        assert_eq!(
            ingest_floor(0, 0, now),
            None,
            "with no retention at all there is nothing to floor against",
        );
        // `u32::MAX` days is an operator saying "keep everything". Both the
        // duration and the subtraction fail there, and the answer is the ABSENCE
        // of a floor — not a sentinel instant whose rendering the row comparison
        // then has to sort correctly by accident.
        assert_eq!(
            ingest_floor(u32::MAX, u32::MAX, now),
            None,
            "an unrepresentable window produced a floor, so the comparison is \
             resting on how `fmt_time` renders an out-of-range year",
        );
    }

    /// **A ceiling INSIDE the window is one the sweep ignores, so the floor must
    /// ignore it too.**
    ///
    /// `prune_old_entries` honours `retention_hard_days` only when it is strictly
    /// older than `retention_days` (or when there is no window at all): a ceiling
    /// inside the window is logged and dropped, because the hard delete spares
    /// nothing and would otherwise delete exactly the rows the soft delete exists
    /// to spare. So at `days = 180, hard = 30` nothing is deleted before 180 days.
    ///
    /// An earlier version took the MINIMUM of the two, floored ingest at 30 days,
    /// and silently discarded five months of a publisher's archive that nothing
    /// would ever have deleted. The older test above passes under both rules —
    /// `min(14, 180)` and "the window" are both 14 — which is why this case is
    /// the one that had to be written.
    #[tokio::test]
    async fn a_ceiling_inside_the_window_does_not_lower_the_floor() {
        let pool = pool().await;
        let read = read_of(
            vec![entry_dated("at://d/c/hundred", Some(&days_ago(100)))],
            true,
        );
        store_publication(&pool, PUB_URL, read, 0, 180, 30)
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            n, 1,
            "an entry inside the 180-day window was dropped because of a 30-day \
             ceiling the sweep ignores — five months of archive discarded at ingest \
             that nothing would have deleted",
        );
    }

    /// **A complete read of an empty publication is a healthy poll, not a
    /// failure.** The failure branch is keyed on `!complete && offered == 0`, and
    /// dropping either half of that makes a brand-new or fully-archived
    /// publication go into backoff that widens forever.
    #[tokio::test]
    async fn a_complete_read_of_nothing_is_not_a_failure() {
        let pool = pool().await;
        let outcome = store_publication(&pool, PUB_URL, read_of(vec![], true), 0, 14, 180)
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                crate::feed::PollOutcome::Updated { new_entries: 0 }
            ),
            "a complete read of an empty publication was not a healthy poll: {outcome:?}"
        );
    }

    /// **The other half of `a_failed_read_does_not_stamp_last_polled`.** That test
    /// alone is satisfied by never stamping at all, which would leave every
    /// publication permanently due and `/stats` permanently wrong.
    #[tokio::test]
    async fn a_successful_read_stamps_last_polled() {
        let pool = pool().await;
        let read = read_of(vec![entry_dated("at://d/c/1", Some(&days_ago(1)))], true);
        store_publication(&pool, PUB_URL, read, 0, 14, 180)
            .await
            .unwrap();
        let stamped: Option<String> =
            sqlx::query_scalar("SELECT last_polled FROM feeds WHERE url = ?1")
                .bind(PUB_URL)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            stamped.is_some(),
            "a successful read left `last_polled` NULL, so the publication stays \
             due forever and `/stats` never shows it as polled",
        );
    }

    /// **The saturating window must saturate in the KEEPING direction.**
    ///
    /// `an_absurd_retention_window_does_not_panic` only asserts that it returns.
    /// A saturation that produced `DateTime::MAX` instead — or a floor of "now" —
    /// would satisfy it while silently discarding the publisher's entire archive:
    /// `u32::MAX` days is an operator saying "keep everything".
    #[tokio::test]
    async fn an_absurd_retention_window_keeps_everything_rather_than_nothing() {
        let pool = pool().await;
        let read = read_of(
            vec![entry_dated("at://d/c/ancient", Some(&days_ago(10_000)))],
            true,
        );
        store_publication(&pool, PUB_URL, read, 0, u32::MAX, u32::MAX)
            .await
            .expect("a huge window is a wide floor, not a crash");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            n, 1,
            "a window of u32::MAX days dropped a 27-year-old entry, so the \
             saturation went the wrong way",
        );
    }

    /// **`max_entries_per_feed` is passed through, and every test above passes
    /// `0`.** So a call that dropped the argument, or passed a constant, would
    /// have gone unnoticed — and this is the cap that decides which of a
    /// publisher's articles a reader keeps.
    #[tokio::test]
    async fn the_per_feed_cap_is_the_one_the_caller_passed() {
        let pool = pool().await;
        let read = read_of(
            (0..5)
                .map(|i| entry_dated(&format!("at://d/c/{i}"), Some(&days_ago(i + 1))))
                .collect(),
            true,
        );
        store_publication(&pool, PUB_URL, read, 2, 0, 0)
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            n, 2,
            "five entries under a cap of two left {n} rows, so the caller's cap is \
             not the one being applied",
        );
    }

    #[tokio::test]
    async fn no_retention_at_all_means_no_ingest_floor() {
        let pool = pool().await;
        let read = read_of(
            vec![entry_dated("at://d/c/ancient", Some(&days_ago(900)))],
            true,
        );
        store_publication(&pool, PUB_URL, read, 0, 0, 0)
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            n, 1,
            "with nothing deleting it, an old entry is worth keeping"
        );
    }

    /// A retention window near `u32::MAX` must not panic the poller.
    #[tokio::test]
    async fn an_absurd_retention_window_does_not_panic() {
        let pool = pool().await;
        let read = read_of(vec![entry_dated("at://d/c/x", Some(&days_ago(1)))], true);
        store_publication(&pool, PUB_URL, read, 0, u32::MAX, u32::MAX)
            .await
            .expect("a huge window is a wide floor, not a crash");
    }

    /// The feed row learns the publication's name and homepage — the only reason
    /// beyond the timestamp that the upsert is there at all. `upsert_feed`
    /// COALESCEs both, so dropping either is silent.
    #[tokio::test]
    async fn the_feed_row_learns_the_publications_name_and_site() {
        let pool = pool().await;
        let read = read_of(vec![entry_dated("at://d/c/1", Some(&days_ago(1)))], true);
        store_publication(&pool, PUB_URL, read, 0, 14, 180)
            .await
            .unwrap();
        let (title, site): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT title, site_url FROM feeds WHERE url = ?1")
                .bind(PUB_URL)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            title.as_deref(),
            Some("Scan's Lab"),
            "the name never reached the row"
        );
        assert_eq!(
            site.as_deref(),
            Some("https://example.com/blog/"),
            "the homepage never reached the row"
        );
    }

    /// **The undated entry is kept, deliberately.** It is dated by `fetched_at`,
    /// which holds still, and the alternative is discarding an article the reader
    /// can never see. It resurrects once per retention window; that is accepted.
    #[tokio::test]
    async fn an_undated_entry_is_stored_rather_than_dropped() {
        let pool = pool().await;
        let read = read_of(vec![entry_dated("at://d/c/undated", None)], true);
        store_publication(&pool, PUB_URL, read, 0, 14, 180)
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1, "an entry with no date was discarded");
    }

    /// A record key from a real atproto repo, and the instant it decodes to.
    ///
    /// **Fixed, not minted.** A test that mints a TID expects "about now", and
    /// "about now" is satisfied by any source of the current time — including a
    /// fallback that has had the rkey ripped out of it and returns `Utc::now()`
    /// instead. Both tests named for the rkey fallback used to survive exactly
    /// that mutation. A historical key with a stated answer cannot.
    const PAST_TID: &str = "3jzfcijpj2z2a";
    const PAST_TID_WRITTEN_AT: &str = "2023-06-30T15:03:01Z";

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

    /// A PLC directory and the author's PDS, both on one loopback port, for a
    /// repo holding `records` (`(collection, rkey, value)`; an empty rkey serves
    /// a malformed envelope with no `uri`). Each collection is
    /// served as one full page carrying a cursor, then an empty page, because a
    /// real PDS returns a cursor on its final page and the walk must stop on the
    /// empty one. Returns the PLC base URL and a count of `listRecords` calls.
    pub(crate) async fn serve_repo(
        did: &'static str,
        records: Vec<(&'static str, &'static str, serde_json::Value)>,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use axum::extract::{Query, Request};
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        // Unique per server: the override table is process-wide and tests run
        // in parallel, so a shared name would let one test reach another's.
        let (plc_host, pds_host) = (
            format!("plc-{port}.repo.test"),
            format!("pds-{port}.repo.test"),
        );
        for host in [&plc_host, &pds_host] {
            crate::net::test_host_override(host, addr);
        }
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let records = Arc::new(records);
        let app = axum::Router::new().fallback(
            move |Query(q): Query<HashMap<String, String>>, req: Request| {
                let records = Arc::clone(&records);
                let counter = Arc::clone(&counter);
                async move {
                    let path = req.uri().path().to_string();
                    if path == format!("/{did}") {
                        return axum::Json(json!({
                            "id": did,
                            "service": [{
                                "id": "#atproto_pds",
                                "type": "AtprotoPersonalDataServer",
                                "serviceEndpoint": format!("http://{pds_host}:{port}"),
                            }],
                        }));
                    }
                    assert_eq!(path, "/xrpc/com.atproto.repo.listRecords", "unexpected request");
                    counter.fetch_add(1, Ordering::SeqCst);
                    let collection = q.get("collection").cloned().unwrap_or_default();
                    if q.contains_key("cursor") {
                        return axum::Json(json!({ "records": [], "cursor": "end" }));
                    }
                    let page: Vec<_> = records
                        .iter()
                        .filter(|(c, _, _)| *c == collection)
                        .map(|(c, rkey, value)| {
                            // An empty rkey serves the #177 shape: an envelope
                            // with no `uri`, which no record can be read from.
                            if rkey.is_empty() {
                                return json!({ "cid": "bafy", "value": value });
                            }
                            json!({ "uri": format!("at://{did}/{c}/{rkey}"), "cid": "bafy", "value": value })
                        })
                        .collect();
                    axum::Json(json!({ "records": page, "cursor": "end" }))
                }
            },
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{plc_host}:{port}"), hits)
    }

    /// **The mocked repo reads through the real fetch path.** Pins that
    /// [`serve_repo`] is a faithful enough PDS for A0 and the polling tests to
    /// mean something: PLC resolution, both walks, the `site` filter and the
    /// empty-page stop all run for real.
    #[tokio::test]
    async fn fetch_reads_a_publication_from_a_mocked_repo() {
        const OWN: &str = "did:plc:fetchmock";
        let site = format!("at://{OWN}/{}/mine", nsid::STANDARD_PUBLICATION);
        let sibling = format!("at://{OWN}/{}/other", nsid::STANDARD_PUBLICATION);
        let doc = |site: &str, title: &str| {
            json!({ "title": title, "publishedAt": "2026-07-11T00:00:00Z",
                    "path": "/p", "site": site })
        };
        let (plc, hits) = serve_repo(
            OWN,
            vec![
                (
                    nsid::STANDARD_PUBLICATION,
                    "mine",
                    json!({ "name": "Mine", "url": "https://mine.example" }),
                ),
                (
                    nsid::STANDARD_PUBLICATION,
                    "other",
                    json!({ "name": "Other", "url": "https://other.example" }),
                ),
                (nsid::STANDARD_DOCUMENT, "3l2fmaaaaaa2a", doc(&site, "kept")),
                (
                    nsid::STANDARD_DOCUMENT,
                    "3l2fmaaaaaa2b",
                    doc(&sibling, "sibling's"),
                ),
            ],
        )
        .await;
        let client = crate::feed::build_client().unwrap();
        let read = fetch(&client, &plc, &AtUri::parse(&site).unwrap())
            .await
            .unwrap();
        assert!(read.complete, "the walk did not finish");
        assert_eq!(read.publication.name.as_deref(), Some("Mine"));
        let titles: Vec<&str> = read.entries.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(
            titles,
            vec!["kept"],
            "the site filter let a sibling through"
        );
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            4,
            "two collections, each a full page then an empty one"
        );
    }

    /// A read that fails — here, a DID whose PLC directory cannot be reached —
    /// is a poll FAILURE with backoff, never an `Err`: `Err` from the poll seam
    /// means the local store is broken.
    #[tokio::test]
    async fn a_failed_publication_read_is_a_poll_failure() {
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        // A VALID DID, so the row is a Publication and the failure is the
        // network's — an invalid one is Unsupported and fails for another reason.
        let url = format!(
            "at://did:plc:unreachableaaaaaaaaaaaaa/{}/x",
            nsid::STANDARD_PUBLICATION
        );
        crate::store::upsert_feed(
            &pool,
            &crate::store::NewFeed {
                url: url.clone(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let feed = crate::store::get_feed_by_url(&pool, &url)
            .await
            .unwrap()
            .unwrap();
        let mut config = crate::config::Config::default();
        config.oauth.plc_directory = "http://plc.nowhere.invalid".into();
        let client = crate::feed::build_client().unwrap();
        let outcome = crate::feed::poll_feed_by_kind(&pool, &client, &config, &feed)
            .await
            .expect("a source failure surfaced as a store error");
        assert!(
            matches!(
                outcome,
                crate::feed::PollOutcome::Failed {
                    kind: crate::feed::FailureKind::Fetch,
                    ..
                }
            ),
            "an unreachable publication was not a fetch failure: {outcome:?}"
        );
    }

    /// Review of #225: an author who deletes their publication record is not
    /// an unreachable publisher. Every fetch error used to be filed as
    /// `Fetch`, putting it in the public histogram's network bucket.
    #[tokio::test]
    async fn a_deleted_publication_record_is_not_an_unreachable_publisher() {
        const GONE: &str = "did:plc:goneaaaaaaaaaaaaaaaaaaaa";
        let site = format!("at://{GONE}/{}/deleted", nsid::STANDARD_PUBLICATION);
        // The repo answers, but holds no record with that rkey.
        let (plc, _) = serve_repo(
            GONE,
            vec![(
                nsid::STANDARD_PUBLICATION,
                "another",
                json!({ "name": "Other", "url": "https://o.example" }),
            )],
        )
        .await;
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::upsert_feed(
            &pool,
            &crate::store::NewFeed {
                url: site.clone(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let feed = crate::store::get_feed_by_url(&pool, &site)
            .await
            .unwrap()
            .unwrap();
        let mut config = crate::config::Config::default();
        config.oauth.plc_directory = plc;
        let client = crate::feed::build_client().unwrap();
        let outcome = crate::feed::poll_feed_by_kind(&pool, &client, &config, &feed)
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                crate::feed::PollOutcome::Failed {
                    kind: crate::feed::FailureKind::Parse,
                    ..
                }
            ),
            "a deleted publication was filed as a network failure: {outcome:?}"
        );
    }

    /// A PLC directory and PDS on one port that answer however the test says:
    /// the PLC lookup with `plc_status` (200 serves a DID document), and every
    /// `listRecords` with `(status, body)` after `delay` — or, when `endless`,
    /// a fresh page of one sibling document, forever.
    async fn serve_answering(
        did: &'static str,
        plc_status: u16,
        pds: (u16, &'static str),
        delay: std::time::Duration,
        endless: bool,
    ) -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let (plc_host, pds_host) = (
            format!("plc-{port}.answer.test"),
            format!("pds-{port}.answer.test"),
        );
        crate::net::test_host_override(&plc_host, addr);
        crate::net::test_host_override(&pds_host, addr);
        let pages = Arc::new(AtomicUsize::new(0));
        let endpoint = format!("http://{pds_host}:{port}");
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let pages = Arc::clone(&pages);
            let endpoint = endpoint.clone();
            async move {
                use axum::response::IntoResponse;
                if req.uri().path() == format!("/{did}") {
                    let status = axum::http::StatusCode::from_u16(plc_status).unwrap();
                    let doc = json!({ "id": did, "service": [{ "id": "#atproto_pds",
                        "type": "AtprotoPersonalDataServer", "serviceEndpoint": endpoint }] });
                    return (status, axum::Json(doc)).into_response();
                }
                tokio::time::sleep(delay).await;
                if endless {
                    let n = pages.fetch_add(1, Ordering::SeqCst);
                    let body = json!({ "records": [{
                        "uri": format!("at://{did}/{}/3lend{n:08}", nsid::STANDARD_DOCUMENT),
                        "cid": "b",
                        "value": { "title": "x", "path": "/x", "publishedAt": "2026-07-11T00:00:00Z",
                                   "site": format!("at://{did}/{}/other", nsid::STANDARD_PUBLICATION) } }],
                        "cursor": format!("c{n}") });
                    return axum::Json(body).into_response();
                }
                let status = axum::http::StatusCode::from_u16(pds.0).unwrap();
                (status, [("content-type", "application/json")], pds.1).into_response()
            }
        });
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{plc_host}:{port}")
    }

    async fn poll_publication_at(
        did: &str,
        plc: String,
        deadline: Option<std::time::Duration>,
    ) -> crate::feed::PollOutcome {
        let site = format!("at://{did}/{}/mine", nsid::STANDARD_PUBLICATION);
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::upsert_feed(
            &pool,
            &crate::store::NewFeed {
                url: site.clone(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let feed = crate::store::get_feed_by_url(&pool, &site)
            .await
            .unwrap()
            .unwrap();
        let mut config = crate::config::Config::default();
        config.oauth.plc_directory = plc;
        if let Some(d) = deadline {
            config.publication_read_deadline = d;
        }
        let client = crate::feed::build_client().unwrap();
        crate::feed::poll_feed_by_kind(&pool, &client, &config, &feed)
            .await
            .unwrap()
    }

    fn kind_of(outcome: &crate::feed::PollOutcome) -> Option<crate::feed::FailureKind> {
        match outcome {
            crate::feed::PollOutcome::Failed { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    /// Review of #225: one publication read had no overall deadline — only
    /// FETCH_TIMEOUT per request x MAX_LIST_PAGES — and the tick waited for it.
    #[tokio::test]
    async fn a_publication_read_has_an_overall_deadline() {
        const DID: &str = "did:plc:slowrepoaaaaaaaaaaaaaaaa";
        let plc = serve_answering(
            DID,
            200,
            (200, ""),
            std::time::Duration::from_millis(50),
            true,
        )
        .await;
        let started = std::time::Instant::now();
        let outcome =
            poll_publication_at(DID, plc, Some(std::time::Duration::from_millis(300))).await;
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "the read ran {:?}",
            started.elapsed()
        );
        assert_eq!(
            kind_of(&outcome),
            Some(crate::feed::FailureKind::Fetch),
            "{outcome:?}"
        );
    }

    /// Review of #225: answers that ARRIVED were filed as `Fetch` ("the request
    /// never produced a response"), putting deleted and deactivated accounts in
    /// the network bucket.
    #[tokio::test]
    async fn a_publication_failure_is_filed_under_what_happened() {
        let zero = std::time::Duration::ZERO;
        const GONE: &str = "did:plc:tombstonedaaaaaaaaaaaaaa";
        let plc = serve_answering(GONE, 404, (200, ""), zero, false).await;
        let outcome = poll_publication_at(GONE, plc, None).await;
        assert_eq!(
            kind_of(&outcome),
            Some(crate::feed::FailureKind::Status),
            "PLC 404: {outcome:?}"
        );

        const NOREPO: &str = "did:plc:norepoaaaaaaaaaaaaaaaaaa";
        let plc = serve_answering(
            NOREPO,
            200,
            (400, r#"{"error":"RepoNotFound"}"#),
            zero,
            false,
        )
        .await;
        let outcome = poll_publication_at(NOREPO, plc, None).await;
        assert_eq!(
            kind_of(&outcome),
            Some(crate::feed::FailureKind::Status),
            "RepoNotFound: {outcome:?}"
        );

        const GARBLED: &str = "did:plc:garbledaaaaaaaaaaaaaaaaa";
        let plc = serve_answering(GARBLED, 200, (200, r#"{"records":"x"}"#), zero, false).await;
        let outcome = poll_publication_at(GARBLED, plc, None).await;
        assert_eq!(
            kind_of(&outcome),
            Some(crate::feed::FailureKind::Parse),
            "garbled body: {outcome:?}"
        );
    }

    /// Two of 17 measured publications had no documents. That is a healthy,
    /// empty feed — not a failure, and not a reason to back off.
    #[tokio::test]
    async fn an_empty_publication_is_a_healthy_poll() {
        const EMPTY: &str = "did:plc:emptypubaaaaaaaaaaaaaaaa";
        let site = format!("at://{EMPTY}/{}/quiet", nsid::STANDARD_PUBLICATION);
        let (plc, _) = serve_repo(
            EMPTY,
            vec![(
                nsid::STANDARD_PUBLICATION,
                "quiet",
                json!({ "name": "Quiet", "url": "https://quiet.example" }),
            )],
        )
        .await;
        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::upsert_feed(
            &pool,
            &crate::store::NewFeed {
                url: site.clone(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let feed = crate::store::get_feed_by_url(&pool, &site)
            .await
            .unwrap()
            .unwrap();
        let mut config = crate::config::Config::default();
        config.oauth.plc_directory = plc;
        let client = crate::feed::build_client().unwrap();
        let outcome = crate::feed::poll_feed_by_kind(&pool, &client, &config, &feed)
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                crate::feed::PollOutcome::Updated { new_entries: 0 }
            ),
            "an empty publication was not a healthy poll: {outcome:?}"
        );
    }

    /// **#177 through the real fetch path.** A stranger's repo with one
    /// malformed publication record and one malformed document, each beside
    /// good ones: both are skipped, and the publication still reads.
    #[tokio::test]
    async fn fetch_skips_malformed_records_beside_good_ones() {
        const OWN: &str = "did:plc:malformedrepo";
        let site = format!("at://{OWN}/{}/mine", nsid::STANDARD_PUBLICATION);
        let doc = |title: &str| {
            json!({ "title": title, "publishedAt": "2026-07-11T00:00:00Z",
                    "path": "/p", "site": site })
        };
        let (plc, _) = serve_repo(
            OWN,
            vec![
                (
                    nsid::STANDARD_PUBLICATION,
                    "",
                    json!({ "name": "Broken", "url": "https://x.example" }),
                ),
                (
                    nsid::STANDARD_PUBLICATION,
                    "mine",
                    json!({ "name": "Mine", "url": "https://mine.example" }),
                ),
                (nsid::STANDARD_DOCUMENT, "", doc("unreadable")),
                (nsid::STANDARD_DOCUMENT, "3l2mfaaaaaa2a", doc("kept")),
            ],
        )
        .await;
        let client = crate::feed::build_client().unwrap();
        let read = fetch(&client, &plc, &AtUri::parse(&site).unwrap())
            .await
            .expect("a malformed record stalled a stranger's publication");
        assert!(read.complete);
        let titles: Vec<&str> = read.entries.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, vec!["kept"]);
    }

    // ---- 0.4.0 step 2b: one walk per repo ------------------------------------

    const SHARED: &str = "did:plc:sharedrepoaaaaaaaaaaaaaa";

    fn shared_doc(site_rkey: &str, title: &str, at: &str) -> serde_json::Value {
        json!({ "title": title, "publishedAt": at, "path": format!("/{title}"),
                "site": format!("at://{SHARED}/{}/{site_rkey}", nsid::STANDARD_PUBLICATION) })
    }

    /// Cost scales with the repo, not the publication: nine publications in one
    /// repo were nine full walks of its documents. Two due publications in one
    /// repo now cost one walk, and each still gets only its own documents.
    #[tokio::test]
    async fn two_publications_in_one_repo_cost_one_walk() {
        let (plc, hits) = serve_repo(
            SHARED,
            vec![
                (
                    nsid::STANDARD_PUBLICATION,
                    "alpha",
                    json!({ "name": "Alpha", "url": "https://alpha.example" }),
                ),
                (
                    nsid::STANDARD_PUBLICATION,
                    "beta",
                    json!({ "name": "Beta", "url": "https://beta.example" }),
                ),
                (
                    nsid::STANDARD_DOCUMENT,
                    "3l2shaaaaaa2a",
                    shared_doc("alpha", "a1", "2026-07-11T00:00:00Z"),
                ),
                (
                    nsid::STANDARD_DOCUMENT,
                    "3l2shaaaaaa2b",
                    shared_doc("beta", "b1", "2026-07-10T00:00:00Z"),
                ),
                (
                    nsid::STANDARD_DOCUMENT,
                    "3l2shaaaaaa2c",
                    shared_doc("alpha", "a2", "2026-07-09T00:00:00Z"),
                ),
            ],
        )
        .await;
        let client = crate::feed::build_client().unwrap();
        let reads = fetch_repo(
            &client,
            &plc,
            SHARED,
            &["alpha".to_string(), "beta".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            4,
            "two collections walked once each (a page then an empty page), not once per publication"
        );
        let titles = |r: &anyhow::Result<PublicationRead>| {
            let mut t: Vec<String> = r
                .as_ref()
                .unwrap()
                .entries
                .iter()
                .map(|e| e.title.clone())
                .collect();
            t.sort();
            t
        };
        assert_eq!(titles(&reads[0]), vec!["a1", "a2"]);
        assert_eq!(titles(&reads[1]), vec!["b1"]);
    }

    /// One walk for several publications must not let a busy one fill the
    /// window and starve a quiet sibling: each publication has its own cap.
    #[tokio::test]
    async fn a_busy_publication_does_not_starve_its_quiet_sibling() {
        let mut records = vec![
            (
                nsid::STANDARD_PUBLICATION,
                "busy",
                json!({ "name": "Busy", "url": "https://busy.example" }),
            ),
            (
                nsid::STANDARD_PUBLICATION,
                "quiet",
                json!({ "name": "Quiet", "url": "https://quiet.example" }),
            ),
        ];
        for (rkey, title) in [
            ("3l2bsaaaaaa2a", "b1"),
            ("3l2bsaaaaaa2b", "b2"),
            ("3l2bsaaaaaa2c", "b3"),
            ("3l2bsaaaaaa2d", "b4"),
            ("3l2bsaaaaaa2e", "b5"),
        ] {
            records.push((
                nsid::STANDARD_DOCUMENT,
                rkey,
                shared_doc("busy", title, "2026-07-11T00:00:00Z"),
            ));
        }
        records.push((
            nsid::STANDARD_DOCUMENT,
            "3l2bsaaaaaa2f",
            shared_doc("quiet", "q1", "2026-01-01T00:00:00Z"),
        ));
        let (plc, _) = serve_repo(SHARED, records).await;
        let client = crate::feed::build_client().unwrap();
        let reads = fetch_repo_capped(
            &client,
            &plc,
            SHARED,
            &["busy".to_string(), "quiet".to_string()],
            2,
        )
        .await
        .unwrap();
        let busy = reads[0].as_ref().unwrap();
        let quiet = reads[1].as_ref().unwrap();
        assert_eq!(
            busy.entries.len(),
            2,
            "the busy publication was not capped at its own cap"
        );
        assert!(!busy.complete, "a capped publication was reported complete");
        assert_eq!(quiet.entries.len(), 1, "the quiet sibling was starved");
        assert!(quiet.complete);
    }

    /// **A0 — the 0.4.0 acceptance test.** A subscribed publication is due, is
    /// polled by the standard.site reader, and its documents land as entries.
    ///
    /// It starts from the stored row the subscribe form will create; step 3 of
    /// `design/STANDARD-SITE-0.4.0.md` extends it through the form itself.
    #[tokio::test]
    async fn a_publication_subscription_delivers_entries_end_to_end() {
        const A0: &str = "did:plc:acceptanceaaaaaaaaaaaaaa";
        let site = format!("at://{A0}/{}/a0pub", nsid::STANDARD_PUBLICATION);
        let document = |title: &str, path: &str| {
            json!({ "title": title, "publishedAt": "2026-07-11T00:00:00Z",
                    "path": path, "site": site, "textContent": "body" })
        };
        let (plc, _hits) = serve_repo(
            A0,
            vec![
                (
                    nsid::STANDARD_PUBLICATION,
                    "a0pub",
                    json!({ "name": "A0 Journal", "url": "https://a0.example" }),
                ),
                (
                    nsid::STANDARD_DOCUMENT,
                    "3l2a0aaaaaa2a",
                    document("First post", "/first"),
                ),
                (
                    nsid::STANDARD_DOCUMENT,
                    "3l2a0aaaaaa2b",
                    document("Second post", "/second"),
                ),
            ],
        )
        .await;

        let pool = crate::store::init_url("sqlite::memory:").await.unwrap();
        crate::store::upsert_feed(
            &pool,
            &crate::store::NewFeed {
                url: site.clone(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        // The flag gates storing, not reading, so A0 runs with it off.
        let mut config = crate::config::Config::default();
        config.oauth.plc_directory = plc;

        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        // The publication loop's own selection, so A0 tests what runs.
        let feed =
            crate::store::due_feeds_of_kind(&pool, &now, crate::feed::FeedKind::Publication, 50)
                .await
                .unwrap()
                .into_iter()
                .find(|f| f.url == site)
                .expect("the publication is not handed to the publication poller");

        let client = crate::feed::build_client().unwrap();
        let outcome = crate::feed::poll_feed_by_kind(&pool, &client, &config, &feed)
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                crate::feed::PollOutcome::Updated { new_entries: 2 }
            ),
            "expected two new entries, got {outcome:?}"
        );
        let titles: Vec<String> =
            sqlx::query_scalar("SELECT title FROM entries WHERE feed_id = ? ORDER BY title")
                .bind(feed.id)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(titles, vec!["First post", "Second post"]);
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

    // ---- #205: a publisher's strings are bounded before they are stored ----

    #[test]
    fn a_documents_text_fields_are_bounded_before_they_are_stored() {
        let site = canonical("pub");
        let big = "x".repeat(8 * 1024 * 1024);
        let records = vec![
            publication("pub", "https://scanash.com"),
            rec(
                nsid::STANDARD_DOCUMENT,
                "3l2bigaaaaa2a",
                json!({ "title": big, "publishedAt": "2026-07-11T00:00:00Z",
                        "path": format!("/{}", "p".repeat(20_000)), "site": site,
                        "textContent": "<".repeat(3 * 1024 * 1024) }),
            ),
        ];
        let (_, publication) = publication_from_records("pub", &records).unwrap();
        let entries = entries_from_records(&site, &publication, &records);
        let e = &entries[0];
        assert!(
            e.title.len() <= crate::feed::MAX_TITLE_BYTES,
            "title: {}",
            e.title.len()
        );
        let url = e
            .url
            .as_ref()
            .expect("an overlong path is truncated, not dropped");
        assert!(
            url.len() <= crate::feed::MAX_URL_BYTES,
            "url: {}",
            url.len()
        );
        let summary = e.summary.as_ref().unwrap();
        assert!(
            summary.len() <= crate::feed::MAX_CONTENT_HTML_BYTES,
            "the ESCAPED summary is what is stored: {}",
            summary.len()
        );
    }

    /// Review of #224: the document's URI is the entry id, chosen by the
    /// publisher's PDS, and it went into the same UNIQUE-indexed column the
    /// RSS path bounds.
    #[test]
    fn a_documents_uri_is_bounded_as_an_entry_id() {
        let site = canonical("pub");
        let records = vec![
            publication("pub", "https://scanash.com"),
            rec(
                nsid::STANDARD_DOCUMENT,
                &"k".repeat(100_000),
                json!({ "title": "t", "publishedAt": "2026-07-11T00:00:00Z",
                        "path": "/p", "site": site }),
            ),
        ];
        let (_, publication) = publication_from_records("pub", &records).unwrap();
        let entries = entries_from_records(&site, &publication, &records);
        let stored: crate::store::NewEntry = entries[0].clone().into();
        assert!(
            stored.guid.len() <= crate::feed::MAX_GUID_BYTES,
            "guid: {}",
            stored.guid.len()
        );
    }

    #[test]
    fn a_publications_own_name_is_bounded() {
        let records = vec![rec(
            nsid::STANDARD_PUBLICATION,
            "pub",
            json!({ "name": "n".repeat(100_000), "url": "https://scanash.com" }),
        )];
        let (_, publication) = publication_from_records("pub", &records).unwrap();
        assert!(publication.name.unwrap().len() <= crate::feed::MAX_TITLE_BYTES);
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
        // Single-character rkeys on purpose: they are not TIDs, so the
        // rkey-derived fallback below does not apply and "unparseable" really
        // does mean undated here.
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

    /// A document with no usable `publishedAt` is dated from its rkey.
    ///
    /// **An undated entry is not merely untidy, it is immortal-and-mortal at
    /// once.** The store's retention sweep and its per-feed cap both order on
    /// `COALESCE(published, fetched_at)`, and an entry inserted with no
    /// `published` gets `fetched_at` stamped at insertion. So the sweep deletes
    /// it once it is `retention_days` old, the next poll re-inserts it with a
    /// fresh `fetched_at` and a new `entries.id`, its read state is gone with
    /// the cascade, and it arrives unread — again, on the same cycle, forever.
    /// The same reset also sorts it newest in the per-feed cap, where it evicts
    /// entries that really are newer.
    #[test]
    fn an_undated_document_is_dated_from_its_tid_rkey() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let docs = vec![rec(
            nsid::STANDARD_DOCUMENT,
            PAST_TID,
            json!({ "title": "T", "path": "/x", "site": site }),
        )];
        assert_eq!(
            entries_from_records(&site, &pubn, &docs)
                .into_iter()
                .next()
                .expect("the document is an entry")
                .published,
            Some(PAST_TID_WRITTEN_AT.to_string()),
            "the date must come from the record key, and be spelled the way the store spells dates"
        );
    }

    #[test]
    fn an_unparseable_published_at_falls_back_to_the_tid_rkey() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let docs = vec![rec(
            nsid::STANDARD_DOCUMENT,
            PAST_TID,
            json!({ "title": "T", "publishedAt": "yesterday-ish", "path": "/x", "site": site }),
        )];
        assert_eq!(
            entries_from_records(&site, &pubn, &docs)
                .into_iter()
                .next()
                .expect("the document is an entry")
                .published,
            Some(PAST_TID_WRITTEN_AT.to_string()),
            "a date the parser cannot read is no date at all, so the rkey must stand in"
        );
    }

    #[test]
    fn a_stated_date_outranks_the_rkey() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        // Both candidate dates are historical, so nothing here depends on
        // what the machine's clock reads.
        let docs = vec![rec(
            nsid::STANDARD_DOCUMENT,
            PAST_TID,
            json!({ "title": "T", "publishedAt": "2020-01-02T00:00:00Z", "path": "/x", "site": site }),
        )];
        assert_eq!(
            entries_from_records(&site, &pubn, &docs)
                .into_iter()
                .next()
                .expect("the document is an entry")
                .published,
            Some("2020-01-02T00:00:00Z".to_string()),
            "the rkey records when the file was written, which is not when the post was published"
        );
    }

    /// **A stated date in the future is discarded, not clamped.**
    ///
    /// Clamping it to "now" looks safe and is not. The store refreshes
    /// `published` on every poll, so the row would be re-dated to the current
    /// hour forever: never older than the retention cutoff, never outranked in
    /// the per-feed cap, permanently first in the reading list. The date must
    /// not depend on when the mapping ran, which is why both of these name the
    /// exact value they expect rather than comparing against the clock.
    #[test]
    fn a_future_dated_document_falls_back_to_its_rkey() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let docs = vec![rec(
            nsid::STANDARD_DOCUMENT,
            PAST_TID,
            json!({ "title": "T", "publishedAt": "2999-01-01T00:00:00Z", "path": "/x", "site": site }),
        )];
        assert_eq!(
            entries_from_records(&site, &pubn, &docs)
                .into_iter()
                .next()
                .expect("the document is an entry")
                .published,
            Some(PAST_TID_WRITTEN_AT.to_string()),
            "the date must be the record's write time, not the hour the poll happened to run"
        );
    }

    #[test]
    fn a_future_dated_document_without_a_tid_rkey_is_undated() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let docs = vec![rec(
            nsid::STANDARD_DOCUMENT,
            "self",
            json!({ "title": "T", "publishedAt": "2999-01-01T00:00:00Z", "path": "/x", "site": site }),
        )];
        assert_eq!(
            entries_from_records(&site, &pubn, &docs)
                .into_iter()
                .next()
                .expect("the document is an entry")
                .published,
            None,
            "with nothing credible to date it by, the row falls to fetched_at, which holds still"
        );
    }

    /// **A little ahead of our clock is skew, not a lie.**
    ///
    /// The rkey here is deliberately not a TID, so nothing masks a wrongly
    /// discarded date: if the stated one is thrown away the entry is undated,
    /// and an undated entry sorts to the bottom of a list ordered on a bare
    /// `published DESC`. A publisher a few seconds fast would have had their
    /// newest post buried.
    #[test]
    fn a_stated_date_a_little_ahead_of_our_clock_is_still_believed() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        let slightly_ahead =
            crate::feed::fmt_time(chrono::Utc::now() + chrono::Duration::seconds(10));
        let docs = vec![rec(
            nsid::STANDARD_DOCUMENT,
            "self",
            json!({ "title": "T", "publishedAt": slightly_ahead, "path": "/x", "site": site }),
        )];
        assert_eq!(
            entries_from_records(&site, &pubn, &docs)
                .into_iter()
                .next()
                .expect("the document is an entry")
                .published,
            Some(slightly_ahead),
            "a few seconds of clock skew must not cost the entry its date"
        );
    }

    #[test]
    fn a_document_with_neither_a_date_nor_a_tid_rkey_stays_undated() {
        let records = vec![publication("p", "https://example.com")];
        let (site, pubn) = publication_from_records("p", &records).unwrap();
        // Two shapes, rejected by two different checks. "my-first-post" is 13
        // characters but carries a `-`, so it never reaches the alphabet's
        // arithmetic at all. "abcdefghijklm" is 13 valid s32 characters and
        // decodes perfectly well — to the year 2192 — which is the case the
        // bound in `tid_timestamp` exists for, and the one a publisher naming
        // files by slug actually produces.
        let docs = vec![
            rec(
                nsid::STANDARD_DOCUMENT,
                "my-first-post",
                json!({ "title": "T", "path": "/x", "site": site }),
            ),
            rec(
                nsid::STANDARD_DOCUMENT,
                "abcdefghijklm",
                json!({ "title": "T", "path": "/y", "site": site }),
            ),
        ];
        assert_eq!(
            entries_from_records(&site, &pubn, &docs)
                .into_iter()
                .map(|e| e.published)
                .collect::<Vec<_>>(),
            vec![None, None],
            "an invented date is worse than no date; the store decides what to do with undated rows"
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
        let wanted: std::collections::HashMap<String, usize> = [(mine.clone(), 0)].into();
        let fate = |d: &crate::atproto::RecordEntry| classify_document(d, &wanted, &known);

        assert_eq!(
            fate(&document("d1", &mine, "Mine", "/1")),
            DocumentFate::Keep(0)
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
