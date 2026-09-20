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

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::lexicon::nsid;

/// One page of `listRecords`. The atproto default is 50; the measured corpus is
/// ~13 documents per publisher with one outlier at 152, so this is one request
/// for almost everyone and two for the outlier.
const PAGE_LIMIT: u32 = 100;

/// Stop after this many pages regardless of what the server says.
///
/// The cursor cannot be trusted to terminate the loop (see
/// [`fetch_documents_with`]), and a server that keeps returning full pages
/// forever would otherwise poll until the process dies. 152 documents is the
/// largest publisher measured; this allows an order of magnitude more.
const MAX_PAGES: usize = 20;

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
        let rest = uri.strip_prefix("at://")?;
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
    pub published: String,
    pub url: String,
    pub summary: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PublicationValue {
    name: Option<String>,
    url: String,
}

#[derive(Debug, Deserialize)]
struct DocumentValue {
    title: String,
    #[serde(rename = "publishedAt")]
    published_at: String,
    path: String,
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

#[derive(Debug, Deserialize)]
struct RecordEnvelope {
    uri: String,
    value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ListRecords {
    #[serde(default)]
    records: Vec<RecordEnvelope>,
    #[serde(default)]
    cursor: Option<String>,
}

fn xrpc_url(pds: &str, method: &str) -> String {
    format!("{}/xrpc/{}", pds.trim_end_matches('/'), method)
}

/// Fetch the publication record, with the JSON boundary injected.
pub async fn fetch_publication_with<G, GFut>(
    uri: &AtUri,
    pds: &str,
    get_json: G,
) -> Result<Publication>
where
    G: FnOnce(String) -> GFut,
    GFut: std::future::Future<Output = Result<serde_json::Value>>,
{
    // Built with `query_pairs_mut`, like `oauth::xrpc`, so encoding is the
    // url crate's problem rather than ours. Note this parses the PDS's *https*
    // URL — the at-URI parsing problem does not arise here.
    let mut url = url::Url::parse(&xrpc_url(pds, "com.atproto.repo.getRecord"))
        .with_context(|| format!("{pds:?} is not a usable PDS URL"))?;
    url.query_pairs_mut()
        .append_pair("repo", &uri.authority)
        .append_pair("collection", &uri.collection)
        .append_pair("rkey", &uri.rkey);
    let body = get_json(url.to_string())
        .await
        .with_context(|| format!("fetching the publication record {uri}"))?;
    let value = body
        .get("value")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let publication: PublicationValue = serde_json::from_value(value)
        .with_context(|| format!("{uri} is not a readable site.standard.publication"))?;
    Ok(Publication {
        name: publication.name,
        url: publication.url,
    })
}

/// Fetch every document belonging to `publication_uri`, with the JSON boundary
/// injected.
///
/// **Paging terminates on an empty record set, not on cursor absence.**
/// `listRecords` returns a cursor on the *final* page, so `while cursor.is_some()`
/// loops forever against a real PDS. Measured, not assumed.
pub async fn fetch_documents_with<G, GFut>(
    publication_uri: &AtUri,
    publication: &Publication,
    pds: &str,
    mut get_json: G,
) -> Result<Vec<Entry>>
where
    G: FnMut(String) -> GFut,
    GFut: std::future::Future<Output = Result<serde_json::Value>>,
{
    let want_site = publication_uri.to_string();
    let base = xrpc_url(pds, "com.atproto.repo.listRecords");
    let mut cursor: Option<String> = None;
    let mut entries = Vec::new();

    for _ in 0..MAX_PAGES {
        let mut url =
            url::Url::parse(&base).with_context(|| format!("{pds:?} is not a usable PDS URL"))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("repo", &publication_uri.authority);
            q.append_pair("collection", nsid::STANDARD_DOCUMENT);
            q.append_pair("limit", &PAGE_LIMIT.to_string());
            if let Some(c) = cursor.as_deref() {
                q.append_pair("cursor", c);
            }
        }
        let body = get_json(url.to_string())
            .await
            .with_context(|| format!("listing documents for {publication_uri}"))?;
        let page: ListRecords = serde_json::from_value(body).with_context(|| {
            format!("listRecords returned an unreadable page for {publication_uri}")
        })?;

        // The terminator. NOT `page.cursor.is_none()`.
        if page.records.is_empty() {
            break;
        }

        for record in &page.records {
            // A document that does not deserialise is SKIPPED, not fatal: one
            // malformed record must not cost a publisher its whole feed, the
            // same promise `feed::poll_feed` makes for a broken entry.
            let Ok(doc) = serde_json::from_value::<DocumentValue>(record.value.clone()) else {
                continue;
            };
            if doc.site != want_site {
                continue;
            }
            entries.push(Entry {
                guid: record.uri.clone(),
                title: doc.title,
                published: doc.published_at,
                url: join_path(&publication.url, &doc.path),
                // `description` first: it is the authored summary where both
                // exist. Neither is present on 8% of documents, which yields a
                // title-and-link entry rather than nothing.
                summary: doc.description.or(doc.text_content),
            });
        }
        cursor = page.cursor;
    }
    Ok(entries)
}

/// Join a document `path` onto the publication's base URL.
fn join_path(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::RefCell;

    const DID: &str = "did:plc:ohutz6x5acjmpuulp3x7wxxc";

    fn pub_uri(rkey: &str) -> AtUri {
        AtUri::parse(&format!("at://{DID}/{}/{rkey}", nsid::STANDARD_PUBLICATION)).unwrap()
    }

    fn doc(site: &str, title: &str, path: &str) -> serde_json::Value {
        json!({
            "title": title,
            "publishedAt": "2026-07-11T00:00:00Z",
            "path": path,
            "site": site,
            "textContent": "body",
        })
    }

    fn envelope(rkey: &str, value: serde_json::Value) -> serde_json::Value {
        json!({ "uri": format!("at://{DID}/{}/{rkey}", nsid::STANDARD_DOCUMENT), "value": value })
    }

    /// Serves each page once, then empty pages forever.
    ///
    /// **A stub that returns the same non-empty page every call is a trap**, and
    /// it caught two of these tests while they were being written: the loop
    /// correctly refuses to stop on a cursor, so it ran to `MAX_PAGES` and
    /// returned twenty copies. Any assertion indexing `[0]` passes under that;
    /// only an assertion on `len()` catches it. Both are used below.
    struct Pages(RefCell<std::collections::VecDeque<serde_json::Value>>);

    impl Pages {
        fn of(pages: Vec<serde_json::Value>) -> Self {
            Self(RefCell::new(pages.into()))
        }
        fn one(records: Vec<serde_json::Value>) -> Self {
            Self::of(vec![json!({ "records": records, "cursor": "c1" })])
        }
        fn next(&self) -> serde_json::Value {
            self.0
                .borrow_mut()
                .pop_front()
                // Every page carries a cursor, the empty one included.
                .unwrap_or_else(|| json!({ "records": [], "cursor": "final" }))
        }
    }

    /// A publication URI is read from the PDS it resolves to, and yields the
    /// name and base URL that document links are built from.
    #[tokio::test]
    async fn a_publication_uri_yields_its_name_and_base_url() {
        let uri = pub_uri("scanslab");
        let seen = RefCell::new(Vec::new());
        let got = fetch_publication_with(&uri, "https://pds.example", |url| {
            seen.borrow_mut().push(url);
            async { Ok(json!({ "value": { "name": "Scan's Lab", "url": "https://scanash.com" } })) }
        })
        .await
        .unwrap();

        assert_eq!(got.name.as_deref(), Some("Scan's Lab"));
        assert_eq!(got.url, "https://scanash.com");
        let url = &seen.borrow()[0];
        assert!(url.contains("com.atproto.repo.getRecord"), "{url}");
        assert!(url.contains("rkey=scanslab"), "{url}");
        // The DID's colons must survive as %3A, not be dropped or doubled.
        assert!(
            url.contains("did%3Aplc%3Aohutz6x5acjmpuulp3x7wxxc"),
            "{url}"
        );
    }

    /// **Documents are filtered by `site`.**
    ///
    /// A repo can hold SEVERAL publications — measured, some do — and
    /// `listRecords` cannot filter server-side, so every document in the repo
    /// comes back and the filter is ours to apply. Drop it and a reader
    /// subscribed to one publication silently receives another's articles.
    #[tokio::test]
    async fn documents_are_filtered_by_their_site_field() {
        let mine = pub_uri("mine");
        let theirs = pub_uri("theirs");
        let publication = Publication {
            name: None,
            url: "https://example.com".into(),
        };
        let pages = Pages::one(vec![
            envelope("a", doc(&mine.to_string(), "Mine", "/a")),
            envelope("b", doc(&theirs.to_string(), "Theirs", "/b")),
            envelope("c", doc(&mine.to_string(), "Mine again", "/c")),
        ]);

        let entries = fetch_documents_with(&mine, &publication, "https://pds.example", |_url| {
            let next = pages.next();
            async move { Ok(next) }
        })
        .await
        .unwrap();

        let titles: Vec<_> = entries.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(
            titles,
            ["Mine", "Mine again"],
            "the other publication leaked in"
        );
    }

    /// **Paging terminates on an empty record set, not on cursor absence.**
    ///
    /// Measured trap: `listRecords` returns a cursor on the FINAL page. A loop
    /// written `while cursor.is_some()` never ends against a real PDS.
    ///
    /// The request COUNT is asserted, not just the entries: a loop that ran one
    /// page too many still produces the right list.
    #[tokio::test]
    async fn paging_terminates_on_an_empty_record_set_not_on_cursor_absence() {
        let uri = pub_uri("p");
        let publication = Publication {
            name: None,
            url: "https://example.com".into(),
        };
        let calls = RefCell::new(0usize);
        let entries = fetch_documents_with(&uri, &publication, "https://pds.example", |_url| {
            let mut n = calls.borrow_mut();
            *n += 1;
            // EVERY page carries a cursor, the final one included.
            let body = if *n == 1 {
                json!({ "records": [envelope("a", doc(&uri.to_string(), "One", "/a"))], "cursor": "c1" })
            } else {
                json!({ "records": [], "cursor": "c2" })
            };
            async move { Ok(body) }
        })
        .await
        .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(
            *calls.borrow(),
            2,
            "expected one page of records then one empty page; a cursor-driven loop would not stop",
        );
    }

    /// Two of the seventeen measured publishers currently have none. Not an
    /// error, and not a reason to mark the feed broken.
    #[tokio::test]
    async fn a_publication_with_zero_documents_is_not_an_error() {
        let uri = pub_uri("empty");
        let publication = Publication {
            name: None,
            url: "https://example.com".into(),
        };
        let pages = Pages::of(vec![]);
        let entries = fetch_documents_with(&uri, &publication, "https://pds.example", |_url| {
            let next = pages.next();
            async move { Ok(next) }
        })
        .await
        .unwrap();
        assert!(entries.is_empty());
    }

    /// **8% of measured documents (37 of 449) carry neither `textContent` nor
    /// `description`.** They must still yield an entry — title, date and link is
    /// what a reader shows for a title-only feed. A `?` on the summary would
    /// silently drop one document in twelve.
    #[tokio::test]
    async fn a_document_with_neither_summary_field_still_yields_an_entry() {
        let uri = pub_uri("p");
        let publication = Publication {
            name: None,
            url: "https://example.com/".into(),
        };
        let bare = json!({
            "title": "Bare",
            "publishedAt": "2026-07-11T00:00:00Z",
            "path": "/bare",
            "site": uri.to_string(),
        });
        let pages = Pages::one(vec![envelope("bare", bare)]);
        let entries = fetch_documents_with(&uri, &publication, "https://pds.example", |_url| {
            let next = pages.next();
            async move { Ok(next) }
        })
        .await
        .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].summary, None);
        assert_eq!(entries[0].title, "Bare");
        // And the link is still built, with no doubled slash.
        assert_eq!(entries[0].url, "https://example.com/bare");
    }

    /// `description` wins over `textContent` where both exist — it is the
    /// authored summary, `textContent` is the whole body.
    #[tokio::test]
    async fn description_is_preferred_over_text_content() {
        let uri = pub_uri("p");
        let publication = Publication {
            name: None,
            url: "https://example.com".into(),
        };
        let both = json!({
            "title": "Both",
            "publishedAt": "2026-07-11T00:00:00Z",
            "path": "/both",
            "site": uri.to_string(),
            "textContent": "the entire body",
            "description": "the summary",
        });
        let pages = Pages::one(vec![envelope("both", both)]);
        let entries = fetch_documents_with(&uri, &publication, "https://pds.example", |_url| {
            let next = pages.next();
            async move { Ok(next) }
        })
        .await
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].summary.as_deref(), Some("the summary"));
    }

    /// **The guid is the document's at-URI, never its `path`.**
    ///
    /// Dedup is `UNIQUE (feed_id, guid)`. `path` is mutable, so a publisher who
    /// moves an article would re-insert it — and a publisher who reorganises
    /// would duplicate their whole archive on the next poll.
    #[tokio::test]
    async fn the_guid_is_the_document_uri_not_its_path() {
        let uri = pub_uri("p");
        let publication = Publication {
            name: None,
            url: "https://example.com".into(),
        };
        let pages = Pages::one(vec![envelope("rk1", doc(&uri.to_string(), "T", "/moved"))]);
        let entries = fetch_documents_with(&uri, &publication, "https://pds.example", |_url| {
            let next = pages.next();
            async move { Ok(next) }
        })
        .await
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].guid,
            format!("at://{DID}/{}/rk1", nsid::STANDARD_DOCUMENT)
        );
        assert!(!entries[0].guid.contains("/moved"));
    }

    /// One unreadable record must not cost the publisher its whole feed.
    #[tokio::test]
    async fn a_malformed_document_is_skipped_rather_than_fatal() {
        let uri = pub_uri("p");
        let publication = Publication {
            name: None,
            url: "https://example.com".into(),
        };
        let pages = Pages::one(vec![
            envelope("bad", json!({ "title": "no publishedAt, no path" })),
            envelope("ok", doc(&uri.to_string(), "Good", "/good")),
        ]);
        let entries = fetch_documents_with(&uri, &publication, "https://pds.example", |_url| {
            let next = pages.next();
            async move { Ok(next) }
        })
        .await
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Good");
    }

    #[test]
    fn at_uris_parse_in_both_forms_and_reject_malformed_ones() {
        let did = AtUri::parse(&format!("at://{DID}/site.standard.publication/abc")).unwrap();
        assert_eq!(did.authority, DID);
        assert_eq!(did.rkey, "abc");
        // Round-trips, which the `site` comparison depends on.
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
