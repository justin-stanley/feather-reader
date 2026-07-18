//! Rotating claim-post copy.
//!
//! Each new follower gets a PUBLIC skeet mentioning them with their claim link.
//! We vary the wording so the timeline of posts doesn't read as identical spam —
//! it should feel like a person saying thanks, not a bot blasting a template.
//!
//! Every variant contains exactly the two placeholders — `{handle}` (rendered as
//! a real `@`-mention facet so the follower is notified) and `{url}` (the claim
//! link) — and nothing else load-bearing. Keep them warm, short, and hype-free.

/// The rotation of message templates. `{handle}` and `{url}` are substituted by
/// [`render`]. Order isn't significant (a variant is picked at random per post).
pub const TEMPLATES: &[&str] = &[
    "thanks for the follow @{handle} — here's your FeatherReader claim link: {url}",
    "@{handle} welcome aboard! grab your FeatherReader beta seat here: {url}",
    "hey @{handle}, thanks for following. your claim link for FeatherReader: {url}",
    "appreciate the follow @{handle}. here's a claim link to get into FeatherReader: {url}",
    "@{handle} you're in — claim your FeatherReader spot: {url}. enjoy the quiet reading.",
    "thanks @{handle}! here's your way into the FeatherReader beta: {url}",
    "welcome @{handle} — tap here to claim FeatherReader: {url}",
    "@{handle} thanks for the follow. your FeatherReader claim link is ready: {url}",
];

/// Where the mention starts and ends inside a rendered post — needed to build the
/// atproto `app.bsky.richtext.facet` byte range so the `@handle` is a real,
/// notifying mention rather than plain text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MentionSpan {
    /// UTF-8 byte offset of the `@` in the rendered post.
    pub byte_start: usize,
    /// UTF-8 byte offset just past the end of the handle.
    pub byte_end: usize,
}

/// A rendered post plus the mention's byte span (for the facet).
#[derive(Debug, Clone)]
pub struct RenderedPost {
    pub text: String,
    pub mention: MentionSpan,
}

/// Render `template` with the follower's `handle` and claim `url`, returning the
/// post text and the byte span of the `@handle` mention (so the caller can emit a
/// facet). `handle` is the bare handle WITHOUT a leading `@` (e.g. `alice.bsky.social`).
///
/// Substitution is done manually (not a format! with the handle) so we can record
/// the exact byte offsets of the rendered `@handle`, which the facet requires.
pub fn render(template: &str, handle: &str, url: &str) -> RenderedPost {
    // Every template writes the mention as `@{handle}`: the literal `@` is part of
    // the template text, and `{handle}` expands to the BARE handle. The mention
    // facet's byte span must cover the `@` too, so we anchor `byte_start` at the
    // `@` that immediately precedes the substituted handle. Building the string
    // incrementally keeps the offsets exact even with multibyte chars elsewhere.
    let mut text = String::with_capacity(template.len() + handle.len() + url.len());
    let mut mention = MentionSpan {
        byte_start: 0,
        byte_end: 0,
    };

    let mut rest = template;
    while let Some(idx) = rest.find('{') {
        text.push_str(&rest[..idx]);
        let after = &rest[idx..];
        if let Some(stripped) = after.strip_prefix("{handle}") {
            // Include the immediately-preceding `@` (if present) in the span so
            // the mention facet covers `@handle`, which is what Bluesky renders.
            let at_offset = if text.ends_with('@') { 1 } else { 0 };
            mention.byte_start = text.len() - at_offset;
            text.push_str(handle);
            mention.byte_end = text.len();
            rest = stripped;
        } else if let Some(stripped) = after.strip_prefix("{url}") {
            text.push_str(url);
            rest = stripped;
        } else {
            // A stray `{` that isn't one of our tokens: emit it literally.
            text.push('{');
            rest = &after[1..];
        }
    }
    text.push_str(rest);

    RenderedPost { text, mention }
}

/// Pick a template at random and render it. Kept separate from [`render`] so
/// tests can render a specific template deterministically.
pub fn render_random(handle: &str, url: &str) -> RenderedPost {
    use rand::seq::SliceRandom;
    let template = TEMPLATES
        .choose(&mut rand::thread_rng())
        .copied()
        .unwrap_or(TEMPLATES[0]);
    render(template, handle, url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_has_both_placeholders() {
        for t in TEMPLATES {
            assert!(t.contains("{handle}"), "missing {{handle}} in: {t}");
            assert!(t.contains("{url}"), "missing {{url}} in: {t}");
        }
    }

    #[test]
    fn render_substitutes_and_locates_mention() {
        let p = render(
            "thanks @{handle} — claim: {url}",
            "alice.bsky.social",
            "https://feather-reader.com/claim?t=abc",
        );
        assert_eq!(
            p.text,
            "thanks @alice.bsky.social — claim: https://feather-reader.com/claim?t=abc"
        );
        // The recorded span is exactly the `@alice.bsky.social` substring.
        assert_eq!(
            &p.text[p.mention.byte_start..p.mention.byte_end],
            "@alice.bsky.social"
        );
    }

    #[test]
    fn mention_span_is_correct_with_multibyte_before_it() {
        // An em-dash (3 UTF-8 bytes) before the mention must not shift the span.
        let p = render("— @{handle} {url}", "bob.test", "u");
        assert_eq!(
            &p.text[p.mention.byte_start..p.mention.byte_end],
            "@bob.test"
        );
    }

    #[test]
    fn render_random_always_contains_handle_and_url() {
        for _ in 0..50 {
            let p = render_random("carol.example", "https://x/claim?t=1");
            assert!(p.text.contains("@carol.example"));
            assert!(p.text.contains("https://x/claim?t=1"));
            assert_eq!(
                &p.text[p.mention.byte_start..p.mention.byte_end],
                "@carol.example"
            );
        }
    }
}
