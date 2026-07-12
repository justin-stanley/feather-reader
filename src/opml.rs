//! OPML import + export — the migration on-ramp and off-ramp (design §3).
//!
//! FeatherReader stores subscriptions and folders as records in the user's own
//! atproto PDS; OPML is how people *arrive* (from Miniflux / Feedly / Inoreader /
//! NetNewsWire / …) and how they trust they can *leave*. This module is pure: no
//! PDS calls, no I/O. The web layer maps a parsed [`ImportedFeed`] onto the
//! records-layer bulk-add, and hands the user's [`Subscription`]s + [`Folder`]s
//! to [`to_opml`] for a clean export.
//!
//! ## Import — [`parse_opml`]
//!
//! Real exporters emit messy, subtly-different OPML. This parser is deliberately
//! tolerant of the variants seen in the wild:
//!
//! - **Feed outlines** are `<outline>` elements carrying an `xmlUrl` attribute
//!   (the feed document). `title` / `text` give the display title (either may be
//!   present; some exporters emit only `text`), and `htmlUrl` the human site.
//! - **Folders** are `<outline>` elements *without* an `xmlUrl` — a grouping node
//!   whose `title` / `text` names the folder and whose children are the feeds in
//!   it. A feed's folder is its nearest ancestor grouping outline. Feeds at the
//!   top level (or under an unnamed grouping) have no folder.
//! - Attribute order varies, single- *or* double-quoted values appear, self-
//!   closing (`<outline … />`) and container (`<outline …> … </outline>`) forms
//!   both occur, XML entities need un-escaping, and the same feed can appear more
//!   than once (e.g. filed under two folders) — parse dedupes by feed URL,
//!   keeping the first occurrence (and thus its folder).
//!
//! The parser is a small hand-rolled scanner rather than a full XML parse: OPML
//! is a flat attribute-bearing tree and the messy real-world inputs (unescaped
//! stray `&`, missing XML declarations, BOMs) are exactly what trips strict
//! parsers, so a lenient scan is both smaller and more robust here.
//!
//! ## Export — [`to_opml`]
//!
//! [`to_opml`] serializes the user's [`Subscription`]s and [`Folder`]s back to a
//! clean, well-formed OPML 2.0 document: feeds grouped under their folder's
//! `<outline text=… title=…>` container, un-foldered feeds at the top level,
//! every attribute value properly XML-escaped.

use std::collections::HashSet;

use anyhow::Result;

use crate::lexicon::{Folder, Subscription};

/// One feed extracted from an OPML document by [`parse_opml`].
///
/// The web layer maps this onto a `community.lexicon.rss.subscription` record
/// (`feed_url` → `url`, `title` → `title`, `site_url` → `siteUrl`) plus, when
/// `folder` is set, the enclosing `community.lexicon.rss.folder`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedFeed {
    /// The feed document URL (OPML `xmlUrl`). Always present and non-empty.
    pub feed_url: String,
    /// Display title (OPML `title`, falling back to `text`), if any.
    pub title: Option<String>,
    /// The human-facing site the feed belongs to (OPML `htmlUrl`), if any.
    pub site_url: Option<String>,
    /// The name of the enclosing folder outline, if the feed was nested in one.
    pub folder: Option<String>,
}

/// Parse an OPML / XML subscription list into a deduped list of [`ImportedFeed`].
///
/// Tolerant of the variants real exporters emit (Feedly / NetNewsWire / Miniflux /
/// Inoreader); see the module docs. Nested grouping `<outline>`s (those without an
/// `xmlUrl`) become the `folder` name of the feeds inside them. Feeds are deduped
/// by URL, first occurrence winning.
///
/// Returns `Ok` with the (possibly empty) feed list. The signature is `Result`
/// for a uniform call site and forward room to reject malformed input; today it
/// never errors — an input with no feed outlines yields an empty vec.
pub fn parse_opml(xml: &str) -> Result<Vec<ImportedFeed>> {
    let mut out: Vec<ImportedFeed> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Stack of open grouping (folder) outline names — `None` for an unnamed
    // grouping node, so we don't invent a folder from a nameless container.
    let mut folder_stack: Vec<Option<String>> = Vec::new();

    let bytes = xml.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Advance to the next `<`.
        let lt = match find_from(bytes, i, b'<') {
            Some(p) => p,
            None => break,
        };

        // A closing `</outline>` pops the current grouping (if the element we
        // opened was a container grouping — tracked via `open_group`, below).
        if starts_with_ci(bytes, lt, b"</outline") {
            folder_stack.pop();
            i = find_from(bytes, lt, b'>')
                .map(|p| p + 1)
                .unwrap_or(bytes.len());
            continue;
        }

        // We only care about `<outline …>` opening tags.
        if !starts_with_ci(bytes, lt, b"<outline") {
            i = lt + 1;
            continue;
        }

        // Find the end of this tag (`>`), noting whether it self-closes (`/>`).
        let gt = match find_from(bytes, lt, b'>') {
            Some(p) => p,
            None => break,
        };
        let attr_start = lt + "<outline".len();
        let attr_end = gt; // exclusive
        let self_closing = attr_end > attr_start && bytes[attr_end - 1] == b'/';
        let attrs = &xml[attr_start..attr_end.min(xml.len())];

        let xml_url = attr(attrs, "xmlUrl").filter(|s| !s.is_empty());
        if let Some(feed_url) = xml_url {
            // A feed outline. Its folder is the nearest *named* enclosing group.
            let folder = folder_stack.iter().rev().find_map(|f| f.clone());
            if seen.insert(feed_url.clone()) {
                let title = attr(attrs, "title")
                    .or_else(|| attr(attrs, "text"))
                    .filter(|s| !s.is_empty());
                let site_url = attr(attrs, "htmlUrl").filter(|s| !s.is_empty());
                out.push(ImportedFeed {
                    feed_url,
                    title,
                    site_url,
                    folder,
                });
            }
            // A self-closing feed outline opens no scope; a container feed
            // outline (rare) still shouldn't act as a folder, so push a `None`
            // scope for its (unusual) children to keep the stack balanced.
            if !self_closing {
                folder_stack.push(None);
            }
        } else if !self_closing {
            // A grouping/container outline (no feed URL): its name is the folder
            // for the feeds nested inside it. `text`/`title` may name it.
            let name = attr(attrs, "text")
                .or_else(|| attr(attrs, "title"))
                .filter(|s| !s.is_empty());
            folder_stack.push(name);
        }
        // (A self-closing outline with no xmlUrl is an empty node — ignored.)

        i = gt + 1;
    }

    Ok(out)
}

/// Serialize the user's subscriptions + folders to a clean OPML 2.0 document.
///
/// `subs` and `folders` are `(at-uri, record)` pairs as returned by the atproto
/// layer's `list_subscriptions` / `list_folders`. A subscription's
/// [`Subscription::folder`] is an `at://` strong ref to a [`Folder`] record;
/// feeds are grouped under a `<outline>` container named for that folder, with
/// un-foldered feeds emitted at the top level. Folders that contain no feeds are
/// omitted (OPML has no notion of an empty group worth exporting), and a folder
/// ref that resolves to no known folder falls back to top-level placement.
pub fn to_opml(subs: &[(String, Subscription)], folders: &[(String, Folder)]) -> String {
    // Map folder at-uri → display name, and preserve a stable folder order
    // (by `position`, then name) for deterministic output.
    let mut folder_order: Vec<(&str, &str)> = folders
        .iter()
        .map(|(uri, f)| (uri.as_str(), f.name.as_str()))
        .collect();
    folder_order.sort_by(|a, b| {
        let pa = folders
            .iter()
            .find(|(u, _)| u == a.0)
            .and_then(|(_, f)| f.position);
        let pb = folders
            .iter()
            .find(|(u, _)| u == b.0)
            .and_then(|(_, f)| f.position);
        pa.cmp(&pb).then_with(|| a.1.cmp(b.1))
    });

    // Bucket subscriptions by their folder at-uri (None → top level). A sub whose
    // `folder` ref doesn't match any known folder is treated as top-level.
    let known: HashSet<&str> = folders.iter().map(|(u, _)| u.as_str()).collect();

    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<opml version=\"2.0\">\n");
    out.push_str("  <head>\n");
    out.push_str("    <title>FeatherReader subscriptions</title>\n");
    out.push_str("  </head>\n");
    out.push_str("  <body>\n");

    // Top-level (un-foldered) feeds first.
    for (uri, sub) in subs {
        let in_known_folder = sub
            .folder
            .as_deref()
            .map(|f| known.contains(f))
            .unwrap_or(false);
        if !in_known_folder {
            let _ = uri;
            out.push_str(&feed_outline(sub, 2));
        }
    }

    // Then each folder as a container with its feeds nested inside.
    for (folder_uri, folder_name) in &folder_order {
        let members: Vec<&Subscription> = subs
            .iter()
            .filter(|(_, s)| s.folder.as_deref() == Some(folder_uri))
            .map(|(_, s)| s)
            .collect();
        if members.is_empty() {
            continue;
        }
        let name = escape_attr(folder_name);
        out.push_str(&format!("    <outline text=\"{name}\" title=\"{name}\">\n"));
        for sub in members {
            out.push_str(&feed_outline(sub, 3));
        }
        out.push_str("    </outline>\n");
    }

    out.push_str("  </body>\n");
    out.push_str("</opml>\n");
    out
}

/// Render one feed `<outline>` line at the given indent depth (2 spaces each).
fn feed_outline(sub: &Subscription, depth: usize) -> String {
    let indent = "  ".repeat(depth);
    // OPML feed outlines use `text` for the label; carry `title` too for the
    // readers that key off it. Fall back to the feed URL when untitled.
    let label = sub.title.as_deref().unwrap_or(&sub.url);
    let label = escape_attr(label);
    let xml_url = escape_attr(&sub.url);
    let mut line = format!(
        "{indent}<outline type=\"rss\" text=\"{label}\" title=\"{label}\" xmlUrl=\"{xml_url}\""
    );
    if let Some(site) = sub.site_url.as_deref() {
        line.push_str(&format!(" htmlUrl=\"{}\"", escape_attr(site)));
    }
    line.push_str("/>\n");
    line
}

/// Read one attribute value out of an `<outline>` attribute run, accepting both
/// single- and double-quoted values and un-escaping XML entities. Matching is
/// case-sensitive on the canonical OPML attribute names but tolerant of
/// surrounding whitespace (`name = "…"`).
fn attr(attrs: &str, name: &str) -> Option<String> {
    let bytes = attrs.as_bytes();
    let nlen = name.len();
    let mut search = 0usize;
    while let Some(rel) = attrs[search..].find(name) {
        let pos = search + rel;
        // Require a word boundary before the name (start, or non-name char) so
        // `xmlUrl` doesn't match inside `someXmlUrl`.
        let boundary_ok = pos == 0 || !is_name_char(bytes[pos - 1]);
        // After the name, allow whitespace, then `=`, then whitespace, then a quote.
        let mut j = pos + nlen;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if boundary_ok && j < bytes.len() && bytes[j] == b'=' {
            j += 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b'"' || bytes[j] == b'\'') {
                let quote = bytes[j];
                let val_start = j + 1;
                if let Some(rel_close) = attrs[val_start..].find(quote as char) {
                    let val = &attrs[val_start..val_start + rel_close];
                    return Some(unescape_xml(val));
                }
            }
        }
        search = pos + nlen;
    }
    None
}

/// Is `b` a valid XML attribute-name character (used for the boundary check)?
fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b':' || b == b'.'
}

/// Find the next occurrence of `needle` in `bytes` at/after `from`.
fn find_from(bytes: &[u8], from: usize, needle: u8) -> Option<usize> {
    bytes[from..]
        .iter()
        .position(|&b| b == needle)
        .map(|p| from + p)
}

/// Case-insensitive check that `bytes[at..]` begins with `prefix`.
fn starts_with_ci(bytes: &[u8], at: usize, prefix: &[u8]) -> bool {
    if at + prefix.len() > bytes.len() {
        return false;
    }
    bytes[at..at + prefix.len()]
        .iter()
        .zip(prefix)
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Un-escape the handful of XML entities OPML exporters emit in attribute values.
fn unescape_xml(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        // `&amp;` last so a literal `&amp;lt;` doesn't double-decode.
        .replace("&amp;", "&")
}

/// Escape a string for safe inclusion in a double-quoted XML attribute value.
fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A flat NetNewsWire-style export: no folders, `text` present, some feeds
    /// self-closing, one with only `text` (no `title`), entity in a title.
    const FLAT_OPML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<opml version="1.0">
  <head><title>Subscriptions</title></head>
  <body>
    <outline text="Daring Fireball" title="Daring Fireball" type="rss"
      xmlUrl="https://daringfireball.net/feeds/main" htmlUrl="https://daringfireball.net/"/>
    <outline type="rss" text="Rust Blog &amp; News"
      xmlUrl="https://blog.rust-lang.org/feed.xml"/>
    <outline text="No Site" title="No Site" xmlUrl="https://example.com/only.xml" />
  </body>
</opml>
"#;

    /// A foldered Feedly/Inoreader-style export: two category containers, one feed
    /// duplicated across two folders (dedupe keeps the first), single-quoted attrs.
    const FOLDERED_OPML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<opml version="1.0">
  <head><title>reader export</title></head>
  <body>
    <outline text="Tech" title="Tech">
      <outline type='rss' text='Hacker News' xmlUrl='https://hnrss.org/frontpage' htmlUrl='https://news.ycombinator.com/'/>
      <outline type="rss" text="Lobsters" xmlUrl="https://lobste.rs/rss" htmlUrl="https://lobste.rs/"/>
    </outline>
    <outline text="News" title="News">
      <outline type="rss" text="Hacker News" xmlUrl="https://hnrss.org/frontpage"/>
      <outline type="rss" text="The Verge" xmlUrl="https://www.theverge.com/rss/index.xml"/>
    </outline>
    <outline type="rss" text="Top Level Feed" xmlUrl="https://example.org/feed"/>
  </body>
</opml>
"#;

    #[test]
    fn parses_flat_export() {
        let feeds = parse_opml(FLAT_OPML).expect("parse");
        assert_eq!(feeds.len(), 3);

        assert_eq!(feeds[0].feed_url, "https://daringfireball.net/feeds/main");
        assert_eq!(feeds[0].title.as_deref(), Some("Daring Fireball"));
        assert_eq!(
            feeds[0].site_url.as_deref(),
            Some("https://daringfireball.net/")
        );
        assert_eq!(feeds[0].folder, None);

        // Title falls back to `text`; the `&amp;` entity is un-escaped.
        assert_eq!(feeds[1].feed_url, "https://blog.rust-lang.org/feed.xml");
        assert_eq!(feeds[1].title.as_deref(), Some("Rust Blog & News"));
        assert_eq!(feeds[1].site_url, None);

        // Self-closing with a space before `/>`.
        assert_eq!(feeds[2].feed_url, "https://example.com/only.xml");
    }

    #[test]
    fn parses_foldered_export_with_dedupe() {
        let feeds = parse_opml(FOLDERED_OPML).expect("parse");
        // 5 outline feeds, but Hacker News is duplicated → 4 unique.
        assert_eq!(feeds.len(), 4);

        let by_url = |u: &str| feeds.iter().find(|f| f.feed_url == u).unwrap();

        // First occurrence (under "Tech") wins the folder assignment.
        let hn = by_url("https://hnrss.org/frontpage");
        assert_eq!(hn.folder.as_deref(), Some("Tech"));
        assert_eq!(
            hn.site_url.as_deref(),
            Some("https://news.ycombinator.com/")
        );

        assert_eq!(
            by_url("https://lobste.rs/rss").folder.as_deref(),
            Some("Tech")
        );
        assert_eq!(
            by_url("https://www.theverge.com/rss/index.xml")
                .folder
                .as_deref(),
            Some("News")
        );
        // The top-level feed after the two containers has no folder.
        assert_eq!(by_url("https://example.org/feed").folder, None);
    }

    #[test]
    fn empty_input_yields_no_feeds() {
        assert!(parse_opml("").expect("parse").is_empty());
        assert!(parse_opml("<opml><body></body></opml>")
            .expect("parse")
            .is_empty());
        // A grouping outline with no feed children.
        assert!(parse_opml(r#"<outline text="Empty"></outline>"#)
            .expect("parse")
            .is_empty());
    }

    #[test]
    fn export_nests_feeds_under_folders() {
        let folders = vec![
            (
                "at://did:plc:x/community.lexicon.rss.folder/tech".to_string(),
                Folder {
                    r#type: crate::lexicon::nsid::FOLDER.to_string(),
                    name: "Tech".to_string(),
                    position: Some(0),
                    created_at: "2026-07-12T00:00:00.000Z".to_string(),
                },
            ),
            (
                "at://did:plc:x/community.lexicon.rss.folder/news".to_string(),
                Folder {
                    r#type: crate::lexicon::nsid::FOLDER.to_string(),
                    name: "News".to_string(),
                    position: Some(1),
                    created_at: "2026-07-12T00:00:00.000Z".to_string(),
                },
            ),
        ];
        let mut lobsters = Subscription::new("https://lobste.rs/rss", "2026-07-12T00:00:00.000Z");
        lobsters.title = Some("Lobsters".to_string());
        lobsters.site_url = Some("https://lobste.rs/".to_string());
        lobsters.folder = Some("at://did:plc:x/community.lexicon.rss.folder/tech".to_string());

        let mut verge = Subscription::new(
            "https://www.theverge.com/rss/index.xml",
            "2026-07-12T00:00:00.000Z",
        );
        verge.title = Some("The Verge".to_string());
        verge.folder = Some("at://did:plc:x/community.lexicon.rss.folder/news".to_string());

        let mut toplevel =
            Subscription::new("https://example.org/feed", "2026-07-12T00:00:00.000Z");
        toplevel.title = Some("Top & Level".to_string());

        let subs = vec![
            (
                "at://did:plc:x/community.lexicon.rss.subscription/1".to_string(),
                lobsters,
            ),
            (
                "at://did:plc:x/community.lexicon.rss.subscription/2".to_string(),
                verge,
            ),
            (
                "at://did:plc:x/community.lexicon.rss.subscription/3".to_string(),
                toplevel,
            ),
        ];

        let opml = to_opml(&subs, &folders);

        // Well-formed shell.
        assert!(opml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(opml.contains("<opml version=\"2.0\">"));
        // Top-level feed appears before the folder containers, entity-escaped.
        assert!(opml.contains(
            "<outline type=\"rss\" text=\"Top &amp; Level\" title=\"Top &amp; Level\" xmlUrl=\"https://example.org/feed\"/>"
        ));
        // Folder containers by position order: Tech then News.
        let tech_at = opml.find("text=\"Tech\"").expect("tech folder");
        let news_at = opml.find("text=\"News\"").expect("news folder");
        assert!(tech_at < news_at);
        // Feeds nested with their htmlUrl.
        assert!(opml.contains("xmlUrl=\"https://lobste.rs/rss\" htmlUrl=\"https://lobste.rs/\"/>"));
    }

    #[test]
    fn export_import_round_trip() {
        let folders = vec![(
            "at://did:plc:x/community.lexicon.rss.folder/tech".to_string(),
            Folder {
                r#type: crate::lexicon::nsid::FOLDER.to_string(),
                name: "Tech".to_string(),
                position: Some(0),
                created_at: "2026-07-12T00:00:00.000Z".to_string(),
            },
        )];
        let mut a = Subscription::new("https://lobste.rs/rss", "2026-07-12T00:00:00.000Z");
        a.title = Some("Lobsters".to_string());
        a.site_url = Some("https://lobste.rs/".to_string());
        a.folder = Some("at://did:plc:x/community.lexicon.rss.folder/tech".to_string());

        let mut b = Subscription::new("https://example.org/feed", "2026-07-12T00:00:00.000Z");
        b.title = Some("Example".to_string());

        let subs = vec![
            (
                "at://did:plc:x/community.lexicon.rss.subscription/1".to_string(),
                a,
            ),
            (
                "at://did:plc:x/community.lexicon.rss.subscription/2".to_string(),
                b,
            ),
        ];

        let opml = to_opml(&subs, &folders);
        let parsed = parse_opml(&opml).expect("re-parse export");

        assert_eq!(parsed.len(), 2);
        let lob = parsed
            .iter()
            .find(|f| f.feed_url == "https://lobste.rs/rss")
            .unwrap();
        assert_eq!(lob.title.as_deref(), Some("Lobsters"));
        assert_eq!(lob.site_url.as_deref(), Some("https://lobste.rs/"));
        assert_eq!(lob.folder.as_deref(), Some("Tech"));

        let ex = parsed
            .iter()
            .find(|f| f.feed_url == "https://example.org/feed")
            .unwrap();
        assert_eq!(ex.title.as_deref(), Some("Example"));
        assert_eq!(ex.folder, None);
    }
}
