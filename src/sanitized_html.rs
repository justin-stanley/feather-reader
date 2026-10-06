//! The reader view's article body.
//!
//! **This is its own module because of the private fields**, for the reason
//! `safe_link.rs` gives: a private field is private to the MODULE, so a type
//! declared in `web.rs` could be built beside its own constructor there and the
//! guarantee would be a convention again.

/// Article-body HTML that has been through the sanitizer **in this process,
/// for this render** — and so can be emitted into a page without escaping.
///
/// **Why it exists (#151).** `entries.content_html` reached `entry.html` as a
/// raw `Option<String>` rendered with `|safe` — the one expression in the
/// reader that bypassed Askama's escaper. Its safety was ingest's `ammonia`
/// pass in `feed.rs`, on a different code path, holding only while every
/// future writer to the column remembered to go through it. That is the same
/// procedural guard `SafeLink` replaced for the entry's `href`s.
///
/// **The guarantee cannot ride through storage.** The column is SQLite `TEXT`,
/// so a type set at ingest means nothing by the time a row is read back. It is
/// re-established at render instead: the only constructors run the ingest
/// sanitizer, `feed::sanitize_html`, over whatever the row holds. A newtype
/// that wrapped the stored string without cleaning it was rejected in the
/// issue as a guarantee in name only.
///
/// - **One policy.** It calls ingest's function rather than holding its own
///   `ammonia` builder, so ingest and render cannot drift; a test pins them
///   byte for byte.
/// - **No change for readers.** Sanitizer output is a fixed point of the
///   sanitizer, so a body ingest stored comes back byte-identical (all 545
///   real bodies measured). Two known exceptions, both the same page to a
///   browser: a literal U+00A0 in a standard.site plain-text summary comes
///   back as `&nbsp;`, and a table whose `<tfoot>` the policy stripped gains
///   the `<tbody>` a browser would build around those rows anyway.
/// - **Bounded cost.** The sanitizer is quadratic on inputs a hostile feed can
///   store within ingest's 2 MiB bound (#226): measured, a stored 2 MiB of
///   nested `<div>`s took ~40 s to re-clean. So render cleans only the prefix
///   of the stored body within [`MAX_RENDER_HTML_BYTES`], [`MAX_RENDER_DEPTH`],
///   [`MAX_RENDER_TEXT_COST`] and [`MAX_RENDER_ATTRIBUTES`], in a shape the
///   sanitizer itself writes — worst measured case ~140 ms — and marks a body
///   it cut so the reader can point at the original. No real article measured
///   was cut.
///
/// There is no `From<String>`, no `Deref`, and no public field. A raw string
/// does not become one — not by struct literal (E0451, private field):
///
/// ```compile_fail,E0451
/// use feather_reader::sanitized_html::SanitizedHtml;
/// let _ = SanitizedHtml { html: String::from("<script>alert(1)</script>"), truncated: false };
/// ```
///
/// and not by conversion (E0277, no `From`):
///
/// ```compile_fail,E0277
/// use feather_reader::sanitized_html::SanitizedHtml;
/// let _: SanitizedHtml = String::from("<script>alert(1)</script>").into();
/// ```
///
/// Only through the cleaning constructor:
///
/// ```
/// use feather_reader::sanitized_html::SanitizedHtml;
/// let html = SanitizedHtml::clean("<p>hi</p><script>alert(1)</script>");
/// assert_eq!(html.as_str(), "<p>hi</p>");
/// ```
pub struct SanitizedHtml {
    html: String,
    truncated: bool,
}

/// The most of a stored body one page view will sanitize: ingest's own stored
/// bound, so no body ingest wrote is cut for size.
///
/// **Size alone does not bound the cost**, which is why the two budgets below
/// exist. Measured in release (`feed::tests::render_reclean_cost`): re-cleaning
/// 545 real bodies from 20 real feeds took p50 31 µs, p99 1.1 ms, max 3.5 ms
/// (a 561 KB body), none of them cut. But the sanitizer is quadratic on some inputs a hostile
/// feed can store within 2 MiB (#226) — a stored 2 MiB of nested `<div>`s
/// took ~40 s to re-clean, a 2 MiB `&` run 2.4 s, a U+00A0 run 3.4 s — and
/// even a 256 KiB cap still left 3–4.7 s for runs of opening tags. Those costs
/// come from nesting depth and from `&` inside long text, not from size.
pub const MAX_RENDER_HTML_BYTES: usize = crate::feed::MAX_CONTENT_HTML_BYTES;

/// The deepest element nesting one page view will sanitize.
///
/// The parser's work per element grows with how many elements are open around
/// it, so nesting is quadratic: 13 K nested `<div>`s took 189 ms, 52 K took
/// 3 s. Real articles nest a few dozen deep at most; this is several times
/// that. The worst case it leaves — 2 MiB of elements all nested this deep —
/// measured 70–140 ms, against 4.7 s for 256 KiB of open tags unbounded.
pub const MAX_RENDER_DEPTH: usize = 256;

/// The most text-node work one page view will sanitize, in the units below.
///
/// **Measured, the cost of a `&` (so every entity: `&amp;`, `&lt;`,
/// `&nbsp;`, `&#160;`) or a literal U+00A0 is proportional to the bytes that
/// follow it in the same text node.** 20 K `&amp;` followed by 1.9 MB of text
/// took 1.07 s; the same text followed by the same `&amp;`s took 9.7 ms; and
/// the same `&amp;`s each wrapped in their own `<p>` before the text took
/// 9.3 ms — a tag ends the text node, and with it the cost. So the cost of a
/// body is counted as, for every such character, the bytes after it up to the
/// end of its text node, summed. 3.8 × 10¹⁰ of those units took ~1.07 s; this
/// budget is ~60 ms of them. A real 100 KB article with 2,000 entities is
/// around 10⁸ — twenty times under it.
///
/// An attribute value is a run of the same kind (20 K `&amp;` then 2 MB of
/// text in one `title` took 1.1 s), so its cost counts against the same
/// budget. Only tags that really end a text node end a run — see
/// `render_cut` for why that is an allowlist.
pub const MAX_RENDER_TEXT_COST: u64 = 1 << 31;

/// The most attributes one tag may carry into the sanitizer.
///
/// The parser checks each attribute name against every one before it on the
/// same tag, so a tag's cost is quadratic in its attribute count: one `<p>`
/// with ~190 K distinct attributes took 6.6 s. The sanitizer's policy keeps
/// at most six attributes on any element (`img`: `src`, `alt`, `width`,
/// `height`, `lang`, `title`) plus the `rel` it adds to links, so nothing
/// ingest stores comes near this.
pub const MAX_RENDER_ATTRIBUTES: usize = 32;

/// Elements the serializer writes without a closing tag, so they never stay
/// open — the HTML serializer's own list.
fn is_void(name: &str) -> bool {
    matches!(
        name,
        "area"
            | "base"
            | "basefont"
            | "bgsound"
            | "br"
            | "col"
            | "embed"
            | "frame"
            | "hr"
            | "img"
            | "input"
            | "keygen"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

/// The tree builder's "special" elements, less `address`, `div` and `p`: what
/// stops its search for an open `li`, `dd` or `dt` that a new one would close.
fn stops_list_item_search(name: &str) -> bool {
    matches!(
        name,
        "applet"
            | "area"
            | "article"
            | "aside"
            | "base"
            | "basefont"
            | "bgsound"
            | "blockquote"
            | "body"
            | "br"
            | "button"
            | "caption"
            | "center"
            | "col"
            | "colgroup"
            | "dd"
            | "details"
            | "dir"
            | "dl"
            | "dt"
            | "embed"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "footer"
            | "form"
            | "frame"
            | "frameset"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "head"
            | "header"
            | "hgroup"
            | "hr"
            | "html"
            | "iframe"
            | "img"
            | "input"
            | "keygen"
            | "li"
            | "link"
            | "listing"
            | "main"
            | "marquee"
            | "menu"
            | "meta"
            | "nav"
            | "noembed"
            | "noframes"
            | "noscript"
            | "object"
            | "ol"
            | "param"
            | "plaintext"
            | "pre"
            | "script"
            | "search"
            | "section"
            | "select"
            | "source"
            | "style"
            | "summary"
            | "table"
            | "tbody"
            | "td"
            | "template"
            | "textarea"
            | "tfoot"
            | "th"
            | "thead"
            | "title"
            | "tr"
            | "track"
            | "ul"
            | "wbr"
            | "xmp"
    )
}

/// Start tags that close an open `<p>` "in button scope" — implicitly,
/// popping whatever is open inside it.
fn closes_p(name: &str) -> bool {
    matches!(
        name,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "center"
            | "details"
            | "dialog"
            | "dir"
            | "div"
            | "dl"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "footer"
            | "header"
            | "hgroup"
            | "main"
            | "menu"
            | "nav"
            | "ol"
            | "p"
            | "search"
            | "section"
            | "summary"
            | "ul"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "pre"
            | "listing"
            | "form"
            | "table"
            | "hr"
            | "xmp"
            | "plaintext"
            | "li"
            | "dd"
            | "dt"
    )
}

/// Elements that end the "button scope" search for an open `<p>`.
fn ends_button_scope(name: &str) -> bool {
    matches!(
        name,
        "applet"
            | "caption"
            | "html"
            | "table"
            | "td"
            | "th"
            | "marquee"
            | "object"
            | "template"
            | "button"
    )
}

/// Where the parser moves text and non-table elements OUT of the table
/// ("foster parenting"), onto whatever precedes it.
fn is_table_context(name: &str) -> bool {
    matches!(
        name,
        "table" | "tbody" | "thead" | "tfoot" | "tr" | "colgroup"
    )
}

fn is_heading(name: &str) -> bool {
    matches!(name, "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
}

/// The parent an element must be directly inside for the parser to insert
/// it where it stands; `None` for an element with no such rule. Table parts
/// anywhere else are dropped or moved, and ruby parts close what is open.
///
/// `<tr>` directly in `<table>` is allowed although the parser wraps it in an
/// implied `<tbody>`: the sanitizer's policy keeps `tr` but not `tfoot`, so
/// its own output has that shape (found by a fixture). The wrapper is one
/// element the scanner does not count, per table — it closes and moves
/// nothing.
fn required_parent(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        "caption" | "colgroup" | "thead" | "tbody" | "tfoot" => &["table"],
        "tr" => &["table", "tbody", "thead", "tfoot"],
        "td" | "th" => &["tr"],
        "col" => &["colgroup"],
        "rt" | "rp" => &["ruby", "rtc"],
        "rtc" => &["ruby"],
        _ => return None,
    })
}

/// One open element, with what the tree builder's scope searches would find
/// from it downward — kept per level so each search is O(1), not a walk.
#[derive(Clone, Copy, Default)]
struct Open {
    name: &'static str,
    /// A `<p>` is open "in button scope".
    p_in_scope: bool,
    /// An open `<li>` a new `<li>` would close.
    li_open: bool,
    /// An open `<dd>` or `<dt>` a new one would close.
    dd_open: bool,
    /// An open `<a>` since the last table cell or caption.
    a_open: bool,
}

impl Open {
    fn child(self, name: &'static str) -> Self {
        let lists = !stops_list_item_search(name);
        Self {
            name,
            p_in_scope: name == "p" || (!ends_button_scope(name) && self.p_in_scope),
            li_open: name == "li" || (lists && self.li_open),
            dd_open: matches!(name, "dd" | "dt") || (lists && self.dd_open),
            a_open: name == "a" || (!matches!(name, "td" | "th" | "caption") && self.a_open),
        }
    }

    /// Whether the parser, with this element on top of its stack, inserts
    /// `name` as a new element exactly here — closing nothing, moving
    /// nothing, dropping nothing. Only then does the scanner's model of the
    /// parser's stack and text nodes stay exact.
    fn inserts_in_place(self, name: &str) -> bool {
        match required_parent(name) {
            Some(parents) => return parents.contains(&self.name),
            None if is_table_context(self.name) => return false,
            None => {}
        }
        if closes_p(name) && self.p_in_scope {
            return false;
        }
        match name {
            "li" => !self.li_open,
            "dd" | "dt" => !self.dd_open,
            "a" => !self.a_open,
            h if is_heading(h) => !is_heading(self.name),
            _ => true,
        }
    }
}

/// The longest prefix of `raw` (a byte index on a character boundary) that
/// stays within [`MAX_RENDER_HTML_BYTES`], [`MAX_RENDER_DEPTH`] and
/// [`MAX_RENDER_TEXT_COST`], and that the scanner can model exactly.
///
/// **A cost estimate, not a security control.** It decides how much of `raw`
/// the sanitizer is given; the sanitizer decides what is safe, on every byte
/// it is given.
///
/// **It accepts only what ingest stores — the sanitizer's own serialized
/// output — and cuts at the first thing that is not.** The cost model needs
/// the parser's open-element stack and text nodes, and those are only
/// predictable when every tag is one the parser inserts exactly where it
/// stands. A first version reset its text-node count at any `<letter` or
/// `<!`, and review found the parser ignores some of those in body
/// (`<!DOCTYPE>`, `<body>`, `<html>`: 1.1 s uncut). Listing what the parser
/// ignores is a denylist, and the next missed entry reopens the hole. So
/// this is an allowlist:
///
/// - a tag must be one the sanitizer's policy keeps (`feed::sanitizer_tags`,
///   read from the same `ammonia` builder) — no comments, doctypes,
///   processing instructions, `<body>`, `<font>`, or bare `<`, none of which
///   the sanitizer ever writes;
/// - a start tag must not make the parser close, move or drop anything:
///   no table part outside its table part, no text or other element directly
///   in a table, no `<li>` in an open `<li>`, no block in an open `<p>`, no
///   `<a>` in an open `<a>`, no heading directly in a heading;
/// - an end tag must close the innermost open element.
///
/// Within that, every accepted tag starts or ends an element, so it ends the
/// current text node: the count resets there and nowhere else. A cut never
/// splits a tag, and never an entity. Measured on 545 real bodies, nothing
/// ingest stored was cut.
fn render_cut(raw: &str) -> usize {
    let b = raw.as_bytes();
    let limit = raw.floor_char_boundary(MAX_RENDER_HTML_BYTES);
    let allowed = crate::feed::sanitizer_tags();
    // The fragment's context element, the `<div>` the sanitizer parses into.
    let root = Open {
        name: "div",
        ..Open::default()
    };
    let mut open: Vec<Open> = Vec::new();
    // Text-node accounting: the current node's cost at byte `i` is
    // `specials * i - positions`; `done` is every finished node's.
    let (mut done, mut specials, mut positions) = (0u64, 0u64, 0u64);
    let mut node_start = 0;
    let mut i = 0;
    while i < limit {
        let current = specials * i as u64 - positions;
        if done + current > MAX_RENDER_TEXT_COST {
            return outside_entity(b, node_start, raw.floor_char_boundary(i));
        }
        let top = open.last().copied().unwrap_or(root);
        let c = b[i];
        if c != b'<' {
            if is_table_context(top.name) && !c.is_ascii_whitespace() {
                // Text directly in a table is fostered out of it.
                return i;
            }
            if c == b'&' || (c == 0xC2 && b.get(i + 1) == Some(&0xA0)) {
                specials += 1;
                positions += i as u64;
            }
            i += 1;
            continue;
        }
        let closing = b.get(i + 1) == Some(&b'/');
        let name_at = i + 1 + usize::from(closing);
        let raw_name = tag_name(b, name_at);
        // Every name the policy keeps is short; a longer one is not kept.
        let mut buf = [0u8; 16];
        let Some(lower) = buf.get_mut(..raw_name.len()) else {
            return i;
        };
        lower.copy_from_slice(raw_name);
        lower.make_ascii_lowercase();
        let Some(&name) = std::str::from_utf8(lower).ok().and_then(|n| allowed.get(n)) else {
            return i;
        };
        let Some(tag) = scan_tag(b, name_at + raw_name.len()) else {
            return i;
        };
        if tag.end > limit
            || tag.attributes > MAX_RENDER_ATTRIBUTES
            || done + current + tag.cost > MAX_RENDER_TEXT_COST
        {
            return i;
        }
        let end = tag.end;
        if closing {
            if open.last().map(|o| o.name) != Some(name) {
                // Well-formed nesting only: anything else makes the parser
                // close or re-open elements implicitly — measured, 36 KB of
                // misnested formatting expanded to 19 MB.
                return i;
            }
            open.pop();
        } else {
            if !top.inserts_in_place(name) {
                return i;
            }
            if !is_void(name) {
                if open.len() == MAX_RENDER_DEPTH {
                    return i;
                }
                open.push(top.child(name));
            }
        }
        // An element began or ended here: so did a text node.
        done += current + tag.cost;
        specials = 0;
        positions = 0;
        i = end;
        node_start = end;
    }
    outside_entity(b, node_start, limit)
}

/// `cut`, moved back to before a character reference it would split.
///
/// Cutting `&amp;` after `&am` leaves `&am`, which the sanitizer re-escapes
/// as visible text, `&amp;am`. A reference is `&`, then letters, digits or
/// `#`, then `;`, so the cut moves to the `&` of an unterminated one. The
/// longest named reference is 33 bytes, so the search is bounded.
fn outside_entity(b: &[u8], node_start: usize, cut: usize) -> usize {
    let from = cut.saturating_sub(40).max(node_start);
    match b[from..cut].iter().rposition(|&x| x == b'&') {
        Some(at)
            if b[from + at + 1..cut]
                .iter()
                .all(|x| x.is_ascii_alphanumeric() || *x == b'#') =>
        {
            from + at
        }
        _ => cut,
    }
}

/// The tag name starting at `at`: ASCII alphanumerics, `-` and `:`.
fn tag_name(b: &[u8], at: usize) -> &[u8] {
    let end = b[at..]
        .iter()
        .position(|c| !(c.is_ascii_alphanumeric() || *c == b'-' || *c == b':'))
        .map_or(b.len(), |p| at + p);
    &b[at..end]
}

/// What a tag costs the parser beyond its name.
struct Tag {
    /// The index just past its `>`.
    end: usize,
    attributes: usize,
    /// Its attribute values' cost, in [`MAX_RENDER_TEXT_COST`]'s units: each
    /// value is a run of its own, like a text node.
    cost: u64,
}

/// The tag whose attributes start at `at`, read the way the HTML tokenizer
/// reads them: a name runs to whitespace, `/`, `>` or `=`; a value is quoted
/// (to the matching quote, `>` and `<` included) or runs to whitespace or
/// `>`. `None` if the input ends inside it.
fn scan_tag(b: &[u8], mut at: usize) -> Option<Tag> {
    let skip_space = |at: &mut usize| {
        while b.get(*at).is_some_and(u8::is_ascii_whitespace) {
            *at += 1;
        }
    };
    let (mut attributes, mut cost) = (0, 0);
    loop {
        while b
            .get(at)
            .is_some_and(|c| c.is_ascii_whitespace() || *c == b'/')
        {
            at += 1;
        }
        match b.get(at)? {
            b'>' => {
                return Some(Tag {
                    end: at + 1,
                    attributes,
                    cost,
                })
            }
            _ => attributes += 1,
        }
        // The first character is part of the name even if it is `=`.
        at += 1;
        while b
            .get(at)
            .is_some_and(|c| !(c.is_ascii_whitespace() || matches!(c, b'/' | b'>' | b'=')))
        {
            at += 1;
        }
        skip_space(&mut at);
        if b.get(at) != Some(&b'=') {
            continue;
        }
        at += 1;
        skip_space(&mut at);
        let value = match *b.get(at)? {
            q @ (b'"' | b'\'') => {
                let start = at + 1;
                let stop = start + b[start..].iter().position(|&c| c == q)?;
                at = stop + 1;
                &b[start..stop]
            }
            b'>' => continue,
            _ => {
                let start = at;
                while b
                    .get(at)
                    .is_some_and(|c| !(c.is_ascii_whitespace() || *c == b'>'))
                {
                    at += 1;
                }
                &b[start..at]
            }
        };
        cost += run_cost(value);
    }
}

/// One run's cost: for every `&` or U+00A0, the bytes from it to the run's
/// end — see [`MAX_RENDER_TEXT_COST`].
fn run_cost(run: &[u8]) -> u64 {
    run.iter()
        .enumerate()
        .filter(|&(k, &c)| c == b'&' || (c == 0xC2 && run.get(k + 1) == Some(&0xA0)))
        .map(|(k, _)| (run.len() - k) as u64)
        .sum()
}

impl SanitizedHtml {
    /// Sanitize `raw` with the ingest policy. The only way to make one.
    ///
    /// Only the prefix of `raw` within the render budgets —
    /// [`MAX_RENDER_HTML_BYTES`], [`MAX_RENDER_DEPTH`],
    /// [`MAX_RENDER_TEXT_COST`], [`MAX_RENDER_ATTRIBUTES`] — and in the shape
    /// the sanitizer writes is cleaned. The cut is made BEFORE the
    /// sanitizer runs, because that is what bounds its cost; the sanitizer
    /// closes whatever the cut leaves open; and a cut body says so through
    /// [`SanitizedHtml::is_truncated`].
    ///
    /// Blocks for as long as the sanitizer runs: on an async task, use
    /// [`SanitizedHtml::clean_off_runtime`].
    pub fn clean(raw: &str) -> Self {
        let cut = render_cut(raw);
        Self {
            html: crate::feed::sanitize_html(&raw[..cut]),
            truncated: cut < raw.len(),
        }
    }

    /// [`SanitizedHtml::clean`] on tokio's blocking pool.
    ///
    /// Even within the budgets a hostile body can take ~140 ms to clean (and a
    /// real 561 KB one ~3.5 ms); off the runtime, that does not stall other
    /// requests sharing the worker. This does not make the clean cheaper — the
    /// budgets in [`SanitizedHtml::clean`] are what cap that.
    pub async fn clean_off_runtime(raw: String) -> anyhow::Result<Self> {
        tokio::task::spawn_blocking(move || Self::clean(&raw))
            .await
            .map_err(|e| anyhow::anyhow!("sanitizing an entry body failed: {e}"))
    }

    /// The cleaned markup.
    pub fn as_str(&self) -> &str {
        &self.html
    }

    /// Whether the stored body was longer than [`MAX_RENDER_HTML_BYTES`] and
    /// only its first part is here.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}

impl std::fmt::Display for SanitizedHtml {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.html)
    }
}

impl askama::filters::HtmlSafe for SanitizedHtml {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::sanitize_html;

    /// Hostile bodies, each with something the sanitizer must remove.
    const HOSTILE: &[&str] = &[
        "<p>a</p><script>alert(1)</script>",
        r#"<img src="x" onerror="alert(1)">"#,
        r#"<a href="javascript:alert(1)">x</a>"#,
        r#"<a href="  JaVaScRiPt:alert(1)">x</a>"#,
        r#"<iframe src="https://evil.example/"></iframe>"#,
        r#"<p onclick="alert(1)" style="background:url(javascript:alert(1))">x</p>"#,
        "<svg><script>alert(1)</script></svg>",
        "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        r#"<form action="https://evil.example/"><input name="pw"></form>"#,
        r#"<object data="javascript:alert(1)"></object><embed src="x.swf">"#,
        r#"<meta http-equiv="refresh" content="0;url=javascript:alert(1)">"#,
        "<base href=\"https://evil.example/\"><a href=\"/x\">x</a>",
        // Hostile attributes on tags the policy keeps, which the scanner
        // passes through to the sanitizer.
        r#"<p><img src=x onerror=alert(1)//><a href="java&#115;cript:alert(1)">x</a></p>"#,
        r#"<div onclick="alert(1)"><a href=" javascript:alert(1)" onerror="x">y</a></div>"#,
    ];

    /// **Same policy as ingest, byte for byte.** The render-time clean is not a
    /// second, independently maintained allow-list: if it were, the two would
    /// drift, and a body ingest would refuse could render, or the reverse.
    ///
    /// Whatever the scanner keeps is sanitized — a hostile raw body is usually
    /// cut at its first tag the policy does not keep, and the prefix still goes
    /// through the sanitizer. Every stored (ingest-shaped) body is kept whole.
    #[test]
    fn clean_is_the_ingest_sanitizer() {
        for raw in HOSTILE.iter().chain(ARTICLES) {
            let kept = &raw[..render_cut(raw)];
            assert_eq!(
                SanitizedHtml::clean(raw).as_str(),
                sanitize_html(kept),
                "render-time clean diverged from ingest on {raw:?}",
            );
        }
        for raw in HOSTILE.iter().chain(ARTICLES) {
            let stored = sanitize_html(raw);
            let out = SanitizedHtml::clean(&stored);
            let cut = render_cut(&stored);
            assert!(
                !out.is_truncated(),
                "an ingest-shaped body was cut at …{:?}",
                &stored[cut.saturating_sub(60)..]
            );
            assert_eq!(out.as_str(), sanitize_html(&stored));
        }
    }

    /// **Only well-formed nesting is given to the sanitizer.** Ingest stores
    /// the sanitizer's serialized output, in which every closer closes the
    /// innermost open element. A closer that does not makes the parser close
    /// and re-open elements implicitly — where its other super-linear paths
    /// are: measured, 36 KB of misnested formatting expanded to 19 MB. So the
    /// body is cut at that closer, and what precedes it is still sanitized.
    #[test]
    fn malformed_nesting_is_cut_at_the_first_misnested_closer() {
        let out = SanitizedHtml::clean("<p>a <b>b</p><script>alert(1)</script>LATER");
        assert!(out.is_truncated());
        assert_eq!(out.as_str(), "<p>a <b>b</b></p>");

        // The expansion itself: formatting elements left open inside a closed
        // `<p>` are re-opened in every later paragraph.
        let bomb = format!(
            "<p>{}</p>{}",
            (0..200)
                .map(|i| format!(r#"<b title="{i}">"#))
                .collect::<String>(),
            "<p>x</p>".repeat(1_000)
        );
        assert!(
            sanitize_html(&bomb).len() > 1_000_000,
            "the shape no longer expands; this test no longer tests anything"
        );
        let out = SanitizedHtml::clean(&bomb);
        assert!(out.is_truncated());
        assert!(out.as_str().len() < 2 * bomb.len(), "it still expanded");
    }

    #[test]
    fn clean_leaves_nothing_active() {
        for raw in HOSTILE {
            let out = SanitizedHtml::clean(raw).as_str().to_ascii_lowercase();
            for needle in [
                "<script",
                "onerror",
                "onclick",
                "javascript:",
                "<iframe",
                "<style",
                "<form",
                "<input",
                "<object",
                "<embed",
                "<meta",
                "<base",
                "<svg",
                "<math",
            ] {
                assert!(!out.contains(needle), "`{needle}` survived {raw:?}: {out}");
            }
        }
    }

    /// Representative article markup, as a feed would send it — exercising what
    /// ammonia normalizes: attribute quoting and order, `rel` on links, entities
    /// (named, numeric, and the U+00A0 it re-encodes), void elements, comments,
    /// stripped tags with kept text, and code with `<` and `&`.
    const ARTICLES: &[&str] = &[
        concat!(
            "<h1>Title</h1><h2 id=x>Sub</h2>",
            "<p>Hello&nbsp;world &copy; 2026 &#8212; caf\u{e9} \u{1f600} \u{a0}nbsp-char ",
            "<a href='https://example.com/a?b=1&c=2' title=\"t\" rel=nofollow target=_blank>link</a>",
            " <strong>b</strong> <em>i</em> <code>x &lt; y &amp;&amp; z</code></p>",
            "<!-- a comment --><br><hr/>",
            "<figure><img src=\"https://example.com/i.png\" alt=\"pic\" width=\"10\" ",
            "srcset=\"https://example.com/i2.png 2x\"><figcaption>cap</figcaption></figure>",
            "<blockquote cite=\"https://example.com\"><p>quote</p></blockquote>",
            "<pre><code class=\"language-rust\">fn main() { if a < b && c > d {} }</code></pre>",
            "<ul><li>one<li>two</ul><ol start=3><li>three</ol>",
            "<table><thead><tr><th>h</th></tr></thead><tbody><tr><td>d</td></tr></tbody></table>",
            "<div class=\"wrap\"><span style=\"color:red\">styled</span></div>",
            "<p>unclosed <b>bold <i>both</p><font color=red>font</font>",
        ),
        concat!(
            "<h2>Lists, tables, ruby</h2>",
            "<ul><li><p>para in item</p><ul><li>nested <a href=\"https://e.example/\">",
            "<img src=\"https://e.example/i.png\" alt=\"\"></a></li></ul></li><li>two</li></ul>",
            "<dl><dt>term</dt><dd>def <em>emph</em></dd><dt>t2</dt><dd>d2</dd></dl>",
            "<table><caption>cap</caption><colgroup><col><col></colgroup>",
            "<thead><tr><th>a</th><th>b</th></tr></thead>",
            "<tbody><tr><td><p>cell &amp; para</p></td><td><table><tr><td>inner</td></tr></table></td></tr>",
            "</tbody></table>",
            "<p>A<ruby>\u{6f22}<rp>(</rp><rt>kan</rt><rp>)</rp></ruby> line<br>break ",
            "x<sup>2</sup> H<sub>2</sub>O <del>old</del><ins>new</ins> <abbr title=\"t\">ab</abbr> ",
            "<q>quoted</q> <kbd>Ctrl</kbd> <mark>m</mark> <time>2026</time> <s>s</s> <u>u</u></p>",
            "<hr><details><summary>more</summary><p>hidden</p></details>",
            "<blockquote><p>q1</p><blockquote><p>q2</p></blockquote></blockquote>",
            "<h3>code</h3><pre><code>a &lt;b&gt; &amp;&amp; c\n  indented</code></pre>",
            "<div><div><span><a href=\"https://e.example/\"><b><i>deep</i></b></a></span></div></div>",
        ),
        "<p>x</p>",
        "plain text with a bare < and an & and a > and \"quotes\" and 'apostrophes'",
        "",
    ];

    /// **Re-cleaning a stored body changes nothing.** What ingest stored is
    /// already `sanitize_html` output, and that output is a fixed point — so a
    /// reader sees exactly what they saw before the render-time clean existed.
    #[test]
    fn cleaning_stored_html_is_idempotent() {
        for raw in ARTICLES.iter().chain(HOSTILE) {
            let stored = sanitize_html(raw);
            assert_eq!(
                SanitizedHtml::clean(&stored).as_str(),
                stored,
                "re-cleaning the stored form of {raw:?} changed it",
            );
        }
    }

    /// **The one exception, pinned.** standard.site summaries are stored by
    /// `plain_text_to_html`, which escapes `& < >` and adds `<br>` but leaves a
    /// literal U+00A0 alone; the sanitizer's serializer writes U+00A0 as
    /// `&nbsp;`. That is the same character to a browser, so a reader sees no
    /// change — but it is not byte-identical, and this says so. Everything
    /// else in a plain-text summary survives byte for byte.
    #[test]
    fn plain_text_summaries_differ_only_in_how_u00a0_is_spelled() {
        let text = "a < b && c > d\n\"q\" 'a' caf\u{e9} \u{1f600}\nnon\u{a0}breaking";
        let stored = crate::feed::plain_text_to_html(text);
        let cleaned = SanitizedHtml::clean(&stored);
        assert_eq!(cleaned.as_str(), stored.replace('\u{a0}', "&nbsp;"));
        let without_nbsp = crate::feed::plain_text_to_html(&text.replace('\u{a0}', " "));
        assert_eq!(SanitizedHtml::clean(&without_nbsp).as_str(), without_nbsp);
    }

    /// **The second exception, found by a fixture.** The policy keeps `tr` but
    /// not `tfoot`, so a feed table with a footer is stored with its footer
    /// rows directly in `<table>`; parsing that again wraps them in a
    /// `<tbody>` — which is what a browser builds from the stored form too, so
    /// the page is the same. The body is not cut, and a second re-clean is a
    /// fixed point. (None of the 545 real bodies measured has a `<tfoot>`.)
    #[test]
    fn a_stripped_tfoot_gains_a_tbody_and_nothing_else() {
        let stored = sanitize_html(
            "<table><tbody><tr><td>a</td></tr></tbody><tfoot><tr><td>f</td></tr></tfoot></table>",
        );
        assert_eq!(
            stored,
            "<table><tbody><tr><td>a</td></tr></tbody><tr><td>f</td></tr></table>"
        );
        let out = SanitizedHtml::clean(&stored);
        assert!(!out.is_truncated());
        assert_eq!(
            out.as_str(),
            "<table><tbody><tr><td>a</td></tr></tbody><tbody><tr><td>f</td></tr></tbody></table>"
        );
        assert_eq!(SanitizedHtml::clean(out.as_str()).as_str(), out.as_str());
    }

    /// **The size bound.** A body longer than [`MAX_RENDER_HTML_BYTES`] —
    /// ingest's own stored bound, so only a row from before it existed (#224)
    /// or a writer that skipped `feed.rs` — is cut to it BEFORE the sanitizer
    /// sees it, and marked. A body exactly at the bound is untouched.
    #[test]
    fn input_past_the_size_bound_is_cut_before_cleaning() {
        assert_eq!(MAX_RENDER_HTML_BYTES, crate::feed::MAX_CONTENT_HTML_BYTES);
        let fits = format!("<p>{}</p>", "a".repeat(MAX_RENDER_HTML_BYTES - 7));
        assert_eq!(fits.len(), MAX_RENDER_HTML_BYTES);
        let whole = SanitizedHtml::clean(&fits);
        assert_eq!(whole.as_str(), fits);
        assert!(!whole.is_truncated());

        let over = format!("{fits}<p>PAST-THE-BOUND</p>");
        let out = SanitizedHtml::clean(&over);
        assert!(
            !out.as_str().contains("PAST-THE-BOUND"),
            "input past the size bound reached the sanitizer"
        );
        assert!(out.is_truncated(), "a cut body was not marked as cut");
        assert!(
            out.as_str().starts_with("<p>aaa"),
            "the part that fits was lost"
        );
    }

    /// The size cut lands on a character boundary, never inside one.
    #[test]
    fn the_cut_respects_utf8() {
        // One byte of padding pushes the bound into the middle of a 3-byte
        // character.
        let s = format!("x{}", "\u{6f22}".repeat(MAX_RENDER_HTML_BYTES / 3 + 1));
        assert!(!s.is_char_boundary(MAX_RENDER_HTML_BYTES));
        let out = SanitizedHtml::clean(&s);
        assert!(out.as_str().len() <= MAX_RENDER_HTML_BYTES);
        assert!(out.as_str().ends_with('\u{6f22}'));
        assert!(out.is_truncated());
    }

    /// **The depth bound** — #226's worst case: nesting deeper than
    /// [`MAX_RENDER_DEPTH`] is cut where it crosses the bound, before the
    /// sanitizer runs, and the cut is marked.
    #[test]
    fn nesting_past_the_depth_bound_is_cut() {
        for open in ["<div>", "<ul><li>", "<blockquote>", r#"<b title="t">"#] {
            let raw = format!("{}DEEP", open.repeat(MAX_RENDER_DEPTH + 8));
            let out = SanitizedHtml::clean(&raw);
            assert!(out.is_truncated(), "{open} nesting was not cut");
            assert!(
                !out.as_str().contains("DEEP"),
                "{open}: past the depth bound was kept"
            );
        }
        // Exactly at the bound: kept whole.
        let at = format!(
            "{}AT{}",
            "<div>".repeat(MAX_RENDER_DEPTH),
            "</div>".repeat(MAX_RENDER_DEPTH)
        );
        let out = SanitizedHtml::clean(&at);
        assert!(!out.is_truncated());
        assert_eq!(out.as_str(), at);
    }

    /// Depth is nesting, not tag count: closed elements leave it, and void
    /// elements never enter it — so a long ordinary article is never cut.
    #[test]
    fn closed_and_void_elements_do_not_accumulate_depth() {
        let deep_then_closed = format!(
            "{}{}",
            "<div>".repeat(MAX_RENDER_DEPTH - 1),
            "</div>".repeat(MAX_RENDER_DEPTH - 1)
        );
        let siblings = format!(
            "{}<div>{}</div>",
            deep_then_closed.repeat(4),
            r#"<img src="x"><br><hr>"#.repeat(MAX_RENDER_DEPTH * 4)
        );
        let out = SanitizedHtml::clean(&siblings);
        assert!(!out.is_truncated(), "an ordinary shape was cut");
        assert_eq!(out.as_str(), sanitize_html(&siblings));
    }

    /// **The scanner cannot be talked out of the depth it sees.** A closing tag
    /// the parser would ignore (no matching open element), or one inside a
    /// quoted attribute value — which the sanitizer's own output can carry,
    /// since it does not escape `<` or `>` in attributes — must not reduce it.
    #[test]
    fn unmatched_or_quoted_closers_do_not_reduce_depth() {
        for open in [
            "<div></x>",
            r#"<div title="</div>">"#,
            "<div title='</div>'>",
            r#"<div title="a>b</div>">"#,
        ] {
            let raw = format!("{}DEEP", open.repeat(MAX_RENDER_DEPTH + 8));
            let out = SanitizedHtml::clean(&raw);
            assert!(out.is_truncated(), "{open:?} hid the nesting");
            assert!(
                !out.as_str().contains("DEEP"),
                "{open:?}: past the depth bound was kept"
            );
        }
    }

    /// **The text-node budget** — #226's other cases. Every entity starts with
    /// `&`, so this covers stored `&amp;`, `&lt;`, `&nbsp;` and numeric
    /// references, plus a literal U+00A0. 20 K of them followed by 200 KB of
    /// text in the same node is ~4 × 10⁹ units, over
    /// [`MAX_RENDER_TEXT_COST`]: cut in the text, before the sanitizer runs.
    #[test]
    fn a_text_node_over_the_cost_budget_is_cut() {
        for unit in ["&amp;", "&nbsp;", "&#160;", "&", "\u{a0}"] {
            let raw = format!("<p>{}{}DEEP</p>", unit.repeat(20_000), "a".repeat(200_000));
            let out = SanitizedHtml::clean(&raw);
            assert!(out.is_truncated(), "{unit:?} then text was not cut");
            assert!(
                !out.as_str().contains("DEEP"),
                "{unit:?}: past the budget was kept"
            );
            assert!(
                out.as_str().len() > 100_000,
                "{unit:?}: far less than the budget allows was kept"
            );
        }
    }

    /// The budget is per text node, as the cost is: the same characters and
    /// the same text, with a tag between them, are cheap and are not cut. And
    /// text BEFORE the characters costs nothing — it is what follows them.
    #[test]
    fn a_tag_ends_the_text_node_and_its_cost() {
        for unit in ["&amp;", "&nbsp;", "&#160;", "&", "\u{a0}"] {
            for raw in [
                format!(
                    "<p>{}</p><p>{}END</p>",
                    unit.repeat(20_000),
                    "a".repeat(200_000)
                ),
                format!("<p>{}{}END</p>", "a".repeat(200_000), unit.repeat(20_000)),
            ] {
                let out = SanitizedHtml::clean(&raw);
                assert!(!out.is_truncated(), "{unit:?}: a cheap shape was cut");
                assert_eq!(out.as_str(), sanitize_html(&raw));
            }
        }
    }

    /// **Review of #273: a token the parser ignores does not end a text node.**
    /// In body, html5ever drops `<!DOCTYPE>`, a second `<body>`, `<html>`,
    /// `<head>`, table parts outside a table and more — so the text either
    /// side of one is ONE node, and its `&` cost keeps growing. The scanner
    /// reset its count at every `<letter` or `<!`, so each of these bodies
    /// (the reviewer's exact three first) ran the full quadratic: ~1.1 s
    /// in release, uncut. Ingest's output contains none of them.
    #[test]
    fn separators_the_parser_ignores_do_not_reset_the_text_cost() {
        let tail = "a".repeat(2_000_000);
        for sep in ["<!DOCTYPE x>", "<body>", "<html>"] {
            for unit in ["&amp;", "\u{a0}"] {
                let raw = format!("<p>{}{sep}{tail}", unit.repeat(20_000));
                let out = SanitizedHtml::clean(&raw);
                assert!(out.is_truncated(), "{sep:?} / {unit:?} reset the text cost");
                assert!(
                    out.as_str().len() < 1_000_000,
                    "{sep:?} / {unit:?}: most of it kept"
                );
            }
        }
        // The wider set, smaller so it runs quickly in debug — and still over
        // the budget if the separator were taken as the end of the node:
        // 5,000 × 500 KB = 2.5 × 10⁹ units.
        let tail = "a".repeat(500_000);
        for sep in [
            "<!DOCTYPE x>",
            "<body>",
            "<html>",
            "<head>",
            "<!-- c -->",
            "<?pi?>",
            "<font>",
            "<frame>",
            "<frameset>",
            "<tr>",
            "<td>",
            "<th>",
            "<tbody>",
            "<caption>",
            "<col>",
            "<colgroup>",
            "<textarea>",
            "<title>",
            "<select>",
            "<svg>",
            "<math>",
            "<noscript>",
            "<image>",
            "</ x>",
            "</br>",
        ] {
            for unit in ["&amp;", "&nbsp;", "&#160;", "\u{a0}", "&"] {
                let raw = format!("<p>{}{sep}{tail}END", unit.repeat(5_000));
                let out = SanitizedHtml::clean(&raw);
                assert!(out.is_truncated(), "{sep:?} / {unit:?} was not cut");
                assert!(
                    !out.as_str().contains("END"),
                    "{sep:?} / {unit:?}: the whole body was kept"
                );
            }
        }
    }

    /// **A start tag the parser answers by closing elements implicitly** pops
    /// formatting elements off the stack without a closer the scanner can see
    /// — and the parser re-opens all of them in front of the next text. The
    /// first round's guard caught that only through a misnested CLOSER; each
    /// shape here has none, every closer matching. Ingest's serialized output
    /// never asks the parser to close anything implicitly.
    #[test]
    fn start_tags_that_close_elements_implicitly_are_cut() {
        let fmt: String = (0..200).map(|i| format!(r#"<b title="{i}">"#)).collect();
        for (name, bomb) in [
            (
                "li in li",
                format!("<ul><li>{fmt}{}", "<li>x</li>".repeat(1_000)),
            ),
            (
                "dd in dd",
                format!("<dl><dd>{fmt}{}", "<dd>x</dd>".repeat(1_000)),
            ),
            ("p in p", format!("<p>{fmt}{}", "<p>x</p>".repeat(1_000))),
            (
                "div in p",
                format!("<p>{fmt}{}", "<div>x</div>".repeat(1_000)),
            ),
            (
                "a in a",
                format!(r#"<a href="x">{fmt}{}"#, "<a>x</a>".repeat(1_000)),
            ),
        ] {
            let expanded = sanitize_html(&bomb).len();
            let out = SanitizedHtml::clean(&bomb);
            assert!(
                out.is_truncated(),
                "{name} ({expanded} B expanded) was not cut"
            );
            assert!(
                out.as_str().len() < 2 * bomb.len(),
                "{name}: it still expanded ({} B from {} B)",
                out.as_str().len(),
                bomb.len()
            );
        }
    }

    /// **Text directly inside a table is moved out of it** ("foster
    /// parenting"), onto the end of whatever text node precedes the table —
    /// so the node before the table keeps growing through it. Ingest's output
    /// never has text there.
    #[test]
    fn text_fostered_out_of_a_table_is_cut() {
        let raw = format!(
            "{}<table>{}END",
            "&amp;".repeat(20_000),
            "a".repeat(500_000)
        );
        let out = SanitizedHtml::clean(&raw);
        assert!(out.is_truncated());
        assert!(!out.as_str().contains("END"));
    }

    /// **Found while re-measuring for #273: attributes are the same two
    /// quadratics.** One `<p>` with ~190 K distinct attributes took 6.6 s
    /// (the parser checks each new name against all before it); 20 K `&amp;`
    /// followed by 2 MB of text inside one attribute value took 1.1 s, the
    /// text-node cost in another place. The scanner passed both: `<p>` is a
    /// tag the policy keeps. The sanitizer's own output carries at most a
    /// handful of attributes per tag.
    #[test]
    fn attribute_count_and_attribute_text_are_budgeted() {
        let many = format!(
            "<p{}>x</p><p>END</p>",
            (0..20_000).map(|i| format!(" a{i}")).collect::<String>()
        );
        let out = SanitizedHtml::clean(&many);
        assert!(out.is_truncated(), "20 K attributes on one tag were passed");
        assert!(!out.as_str().contains("END"));

        let at_bound = format!(
            "<p{}>x</p>",
            (0..MAX_RENDER_ATTRIBUTES)
                .map(|i| format!(" a{i}=\"v\""))
                .collect::<String>()
        );
        assert!(!SanitizedHtml::clean(&at_bound).is_truncated());

        for unit in ["&amp;", "&nbsp;", "\u{a0}", "&"] {
            for quote in ["\"", "'", ""] {
                let raw = format!(
                    "<p title={quote}{}{}{quote}>x</p><p>END</p>",
                    unit.repeat(20_000),
                    "a".repeat(500_000)
                );
                let out = SanitizedHtml::clean(&raw);
                assert!(
                    out.is_truncated(),
                    "{unit:?} in a {quote:?} value was passed"
                );
                assert!(!out.as_str().contains("END"));
            }
        }
    }

    /// **Review of #273: a cut never lands inside an entity or a tag.** A cut
    /// in `&am|p;` re-serializes as `&amp;am`, visible text in front of the
    /// truncation note. Every alignment of the cost cut against a dense run
    /// of `&amp;` is tried, and every alignment of the size cut against an
    /// entity and against a tag.
    #[test]
    fn a_cut_never_splits_an_entity_or_a_tag() {
        // The cost cut, inside a dense run.
        for pad in 0..5 {
            let raw = format!("<p>{}{}</p>", "a".repeat(pad), "&amp;".repeat(40_000));
            let cut = render_cut(&raw);
            assert!(cut < raw.len(), "pad {pad}: the run was not cut");
            let body = &raw[3 + pad..cut];
            assert!(
                body.len() % 5 == 0 && body.replace("&amp;", "").is_empty(),
                "pad {pad}: the cost cut split an entity: {:?}",
                &raw[cut.saturating_sub(8)..cut]
            );
            let out = SanitizedHtml::clean(&raw);
            assert!(
                !out.as_str().contains("&amp;a"),
                "pad {pad}: a partial entity rendered"
            );
        }
        // The size cut, against an entity and against a tag.
        for pad in 0..12 {
            for tail in ["&amp;zzzz", r#"<b title="t">zz</b>"#] {
                let raw = format!("<p>{}{tail}", "a".repeat(MAX_RENDER_HTML_BYTES - 3 - pad));
                let cut = render_cut(&raw);
                let kept = &raw[..cut];
                assert!(
                    kept.rfind('&').is_none_or(|a| kept[a..].contains(';')),
                    "pad {pad}: the size cut split an entity: {:?}",
                    &kept[kept.len().saturating_sub(8)..]
                );
                let lt = kept.rfind('<').unwrap();
                assert!(
                    kept[lt..].contains('>'),
                    "pad {pad}: the size cut split a tag: {:?}",
                    &kept[lt..]
                );
            }
        }
    }

    /// The off-runtime constructor is the same clean, not a different one.
    #[tokio::test]
    async fn cleaning_off_the_runtime_is_the_same_clean() {
        for raw in HOSTILE.iter().chain(ARTICLES) {
            let off = SanitizedHtml::clean_off_runtime(raw.to_string())
                .await
                .unwrap();
            assert_eq!(off.as_str(), SanitizedHtml::clean(raw).as_str());
        }
    }

    /// **`entry.html` has no `|safe` left at all.** The body renders through
    /// [`SanitizedHtml`]'s `HtmlSafe` impl; a `|safe` here would be the old
    /// bypass, and on a raw `String` it would still compile.
    #[test]
    fn the_reader_template_has_no_safe_filter() {
        let template = include_str!("../templates/entry.html");
        let squashed: String = template.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            !squashed.contains("|safe"),
            "templates/entry.html uses `|safe` again"
        );
    }
}
