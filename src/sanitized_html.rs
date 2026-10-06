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
///   sanitizer, so a body ingest stored comes back byte-identical. The one
///   known exception is a literal U+00A0 in a standard.site plain-text
///   summary, which comes back as `&nbsp;` — the same character.
/// - **Bounded cost.** The sanitizer is quadratic on inputs a hostile feed can
///   store within ingest's 2 MiB bound (#226): measured, a stored 2 MiB of
///   nested `<div>`s took ~40 s to re-clean. So render cleans only the prefix
///   of the stored body within [`MAX_RENDER_HTML_BYTES`], [`MAX_RENDER_DEPTH`]
///   and [`MAX_RENDER_TEXT_COST`] — worst measured case ~130 ms — and marks a
///   body it cut so the reader can point at the original. No real article
///   measured was cut.
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
/// 545 real bodies from 20 real feeds took p50 25 µs, p99 0.8 ms, max 2.9 ms
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
/// measured 65–130 ms, against 4.7 s for 256 KiB of open tags unbounded.
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
pub const MAX_RENDER_TEXT_COST: u64 = 1 << 31;

/// Elements the serializer writes without a closing tag, so they never stay
/// open — the HTML serializer's own list. Matched case-insensitively. A void
/// tag missing from here would be counted open, so its parent's closer would
/// not match and the body would be cut there: an error toward cutting, never
/// toward under-counting.
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "basefont", "bgsound", "br", "col", "embed", "frame", "hr", "img", "input",
    "keygen", "link", "meta", "param", "source", "track", "wbr",
];

/// The longest prefix of `raw` (a byte index on a character boundary) that
/// stays within [`MAX_RENDER_HTML_BYTES`], [`MAX_RENDER_DEPTH`] and
/// [`MAX_RENDER_TEXT_COST`].
///
/// **A cost estimate, not a parser, and not a security control.** It decides
/// how much of `raw` the sanitizer is given; the sanitizer decides what is
/// safe, on every byte it is given. On what ingest stores — the sanitizer's
/// own serialized output, so well-formed, every element closed in order, every
/// attribute quoted, no comments — it tracks the parser's depth and text nodes
/// exactly, and cuts nothing a real article contains (0 of 545 measured).
///
/// On anything else it errs toward cutting more, not less. It accepts only
/// well-formed nesting: the first closing tag that does not close the
/// innermost open element ends the prefix. An element the parser would close
/// implicitly (`<p>` inside `<p>`) is still counted open, so it can only
/// over-count depth. Quoted attribute values are skipped whole (the
/// serializer does not escape `<` or `>` inside them), and every `<` that
/// starts a tag ends the current text node.
fn render_cut(raw: &str) -> usize {
    let b = raw.as_bytes();
    let limit = raw.floor_char_boundary(MAX_RENDER_HTML_BYTES);
    let mut open: Vec<&[u8]> = Vec::new();
    // Text-node accounting: `cost` is every finished node's cost plus the
    // current one's, which is `specials * here - sum_of_their_positions`.
    let (mut done, mut specials, mut positions) = (0u64, 0u64, 0u64);
    let mut i = 0;
    while i < limit {
        let current = specials * i as u64 - positions;
        if done + current > MAX_RENDER_TEXT_COST {
            return raw.floor_char_boundary(i);
        }
        let c = b[i];
        if c == b'<' {
            let next = b.get(i + 1).copied().unwrap_or(0);
            let closing = next == b'/' && b.get(i + 2).is_some_and(u8::is_ascii_alphabetic);
            let markup = closing || next.is_ascii_alphabetic() || next == b'!' || next == b'?';
            if markup {
                // A tag, comment or declaration: the text node ends here.
                done += current;
                specials = 0;
                positions = 0;
            }
            if closing {
                let name = tag_name(b, i + 2);
                // Well-formed nesting only: a closer must close the innermost
                // open element. Anything else makes the parser close or
                // re-open elements implicitly, which is where its other
                // super-linear paths (formatting-element reconstruction, the
                // adoption agency) live — measured, 36 KB of that expanded
                // to 19 MB. Ingest never stores it, so stop here.
                match open.last() {
                    Some(top) if top.eq_ignore_ascii_case(name) => {
                        open.pop();
                    }
                    _ => return i,
                }
                i = skip_tag(b, i + 2 + name.len());
                continue;
            }
            if next.is_ascii_alphabetic() {
                let name = tag_name(b, i + 1);
                if !VOID_ELEMENTS
                    .iter()
                    .any(|v| v.as_bytes().eq_ignore_ascii_case(name))
                {
                    if open.len() == MAX_RENDER_DEPTH {
                        return i;
                    }
                    open.push(name);
                }
                i = skip_tag(b, i + 1 + name.len());
                continue;
            }
            if next == b'!' && b[i..].starts_with(b"<!--") {
                i = b[i + 4..]
                    .windows(3)
                    .position(|w| w == b"-->")
                    .map_or(b.len(), |p| i + 4 + p + 3);
                continue;
            }
            if markup {
                // `<!…>` or `<?…>`: a bogus comment, to the next `>`.
                i = b[i..]
                    .iter()
                    .position(|&x| x == b'>')
                    .map_or(b.len(), |p| i + p + 1);
                continue;
            }
            i += 1;
        } else if c == b'&' || (c == 0xC2 && b.get(i + 1) == Some(&0xA0)) {
            specials += 1;
            positions += i as u64;
            i += 1;
        } else {
            i += 1;
        }
    }
    limit
}

/// The tag name starting at `at`: ASCII alphanumerics, `-` and `:`.
fn tag_name(b: &[u8], at: usize) -> &[u8] {
    let end = b[at..]
        .iter()
        .position(|c| !(c.is_ascii_alphanumeric() || *c == b'-' || *c == b':'))
        .map_or(b.len(), |p| at + p);
    &b[at..end]
}

/// The index just past the `>` that ends the tag whose attributes start at
/// `at`, skipping quoted attribute values whole.
fn skip_tag(b: &[u8], mut at: usize) -> usize {
    let mut quote = None;
    while at < b.len() {
        match (quote, b[at]) {
            (None, b'>') => return at + 1,
            (None, q @ (b'"' | b'\'')) => quote = Some(q),
            (Some(q), c) if c == q => quote = None,
            _ => {}
        }
        at += 1;
    }
    b.len()
}

impl SanitizedHtml {
    /// Sanitize `raw` with the ingest policy. The only way to make one.
    ///
    /// Only the prefix of `raw` within the render budgets —
    /// [`MAX_RENDER_HTML_BYTES`], [`MAX_RENDER_DEPTH`],
    /// [`MAX_RENDER_TEXT_COST`] — is cleaned. The cut is made BEFORE the
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
    /// Even within the budgets a hostile body can take ~130 ms to clean (and a
    /// real 561 KB one ~3 ms); off the runtime, that does not stall other
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
    ];

    /// **Same policy as ingest, byte for byte.** The render-time clean is not a
    /// second, independently maintained allow-list: if it were, the two would
    /// drift, and a body ingest would refuse could render, or the reverse.
    /// (Over inputs within the render budgets, which a malformed raw article
    /// is not — see `malformed_nesting_is_cut_at_the_first_misnested_closer`.)
    #[test]
    fn clean_is_the_ingest_sanitizer() {
        let stored: Vec<String> = ARTICLES.iter().map(|a| sanitize_html(a)).collect();
        for raw in HOSTILE
            .iter()
            .copied()
            .chain(stored.iter().map(String::as_str))
        {
            let out = SanitizedHtml::clean(raw);
            assert!(!out.is_truncated(), "{raw:?} was cut");
            assert_eq!(
                out.as_str(),
                sanitize_html(raw),
                "render-time clean diverged from ingest on {raw:?}",
            );
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
            "{}<p>{}</p>",
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
