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

/// Find the publication named by `rkey` among a repo's publication records.
///
/// Returns its **canonical** at-URI — the one the PDS itself minted, always
/// DID-form — alongside the record. That canonical URI is what documents
/// reference in their `site` field, and using it rather than the URI the reader
/// subscribed with is what makes a handle-form subscription work: the two are
/// different strings for the same publication, and only one of them appears in
/// the data.
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
    let base = url::Url::parse(&publication.url).ok();
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
                published: doc.published_at,
                url: join_path(base.as_ref(), &doc.path),
                // `description` first — the authored summary — but only when it
                // actually says something: a blank one must not shadow the body.
                summary: non_blank(doc.description).or_else(|| non_blank(doc.text_content)),
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
fn join_path(base: Option<&url::Url>, path: &str) -> String {
    let Some(base) = base else {
        return path.to_string();
    };
    match base.join(path) {
        // A path that resolves off the publication's origin is not a path, it
        // is a redirect the publisher smuggled into a field we render as theirs.
        Ok(joined) if joined.origin() == base.origin() => joined.to_string(),
        _ => base.to_string(),
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
/// - an XRPC error envelope surfaces as [`crate::atproto::XrpcError`] rather
///   than deserialising into an empty page.
///
/// The first draft of this module reimplemented all of that, worse. The only
/// logic left here is the part that is genuinely about standard.site.
pub async fn fetch(
    http: &reqwest::Client,
    plc_directory: &str,
    uri: &AtUri,
) -> anyhow::Result<(Publication, Vec<Entry>)> {
    use anyhow::Context;

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

    let documents = client
        .list_all_records(nsid::STANDARD_DOCUMENT)
        .await
        .with_context(|| format!("listing documents for {canonical_site}"))?;
    let entries = entries_from_records(&canonical_site, &publication, &documents);
    Ok((publication, entries))
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

    /// **A handle-form subscription must still match DID-form documents.**
    ///
    /// #164 deliberately admits `at://alice.example.com/...`, and getRecord and
    /// listRecords both accept a handle as `repo` — but documents reference
    /// their publication canonically, by DID, and every measured document does.
    /// Comparing against the string the reader subscribed with returned a
    /// permanently empty feed that the module then declared healthy.
    ///
    /// Taking the canonical URI from the record the PDS returned removes the
    /// skew rather than compensating for it.
    #[test]
    fn a_handle_form_subscription_matches_did_form_documents() {
        let records = vec![publication("p", "https://scanash.com")];
        let (site, pubn) = publication_from_records("p", &records).expect("publication not found");
        assert_eq!(site, canonical("p"), "did not take the PDS's canonical URI");

        let docs = vec![document("d1", &canonical("p"), "Hello", "/hello")];
        let entries = entries_from_records(&site, &pubn, &docs);
        assert_eq!(entries.len(), 1, "a handle-form subscription found nothing");
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
        let urls: Vec<String> = entries_from_records(&site, &pubn, &docs)
            .into_iter()
            .map(|e| e.url)
            .collect();
        assert_eq!(urls[0], "https://example.com/a");
        assert!(
            !urls[1].starts_with("https://evil.example"),
            "a document path escaped its publication's origin: {}",
            urls[1],
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
        assert_eq!(entries[0].url, "https://example.com/bare");
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
