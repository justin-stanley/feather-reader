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

/// The rotation of WAITLIST-welcome templates, posted ONCE to a follower when the
/// beta is full (no seat to mint). Each contains exactly `{handle}` (a real
/// `@`-mention facet) and NO `{url}` — there is no claim link yet; the claim-link
/// post comes later, when a seat frees and the retry mint succeeds. Keep them warm,
/// short, honest ("you're on the waitlist"), and hype-free.
pub const WAITLIST_TEMPLATES: &[&str] = &[
    "thanks for the follow @{handle} — FeatherReader's beta is full right now, so you're on the waitlist; your invite comes as soon as a seat opens 🪶",
    "@{handle} welcome! the FeatherReader beta is at capacity at the moment — you're on the waitlist and I'll send your claim link the second a seat frees up",
    "appreciate the follow @{handle}. we're full for now, so you're waitlisted — your invite will land here as soon as room opens 🪶",
    "hey @{handle}, thanks for following! FeatherReader's beta seats are all taken right now; you're on the list and next in line as they free up",
    "@{handle} you're on the FeatherReader waitlist — the beta's full for the moment, but your claim link is coming the moment a seat opens",
    "thanks @{handle}! no open seats this second, so you're waitlisted for FeatherReader — hang tight, your invite follows as soon as one frees 🪶",
    "welcome @{handle} — the beta's at capacity right now, so you're on the waitlist; I'll ping you here with a claim link when a seat opens",
    "@{handle} thanks for the follow. FeatherReader is full at the moment — you're waitlisted, and your invite comes through here as soon as there's room",
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

/// Pick a template pseudo-randomly and render it. Kept separate from [`render`]
/// so tests can render a specific template deterministically.
///
/// Message selection needs *variety*, not cryptographic randomness, so this uses
/// a cheap clock-derived index (no `rand`/`getrandom` dependency — which keeps the
/// bot's supply chain small). Consecutive posts land microseconds apart, so the
/// low bits of the nanosecond clock spread the choice across the templates well
/// enough that the timeline doesn't read as one fixed template.
pub fn render_random(handle: &str, url: &str) -> RenderedPost {
    let template = TEMPLATES[clock_index(TEMPLATES.len())];
    render(template, handle, url)
}

/// Like [`render_random`] but for the WAITLIST-welcome post (no claim link). The
/// template has no `{url}` placeholder, so the empty `url` is never substituted.
pub fn render_waitlist_random(handle: &str) -> RenderedPost {
    let template = WAITLIST_TEMPLATES[clock_index(WAITLIST_TEMPLATES.len())];
    render(template, handle, "")
}

/// A cheap clock-derived index in `0..len` for pseudo-random template variety (no
/// `rand`/`getrandom` dependency — keeps the bot's supply chain small).
fn clock_index(len: usize) -> usize {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as usize;
    nanos % len.max(1)
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
    fn every_waitlist_template_mentions_handle_and_has_no_url() {
        for t in WAITLIST_TEMPLATES {
            assert!(t.contains("{handle}"), "missing {{handle}} in: {t}");
            // A waitlist post carries NO claim link.
            assert!(!t.contains("{url}"), "waitlist template must not link: {t}");
        }
    }

    #[test]
    fn render_waitlist_random_mentions_handle_and_links_nothing() {
        for _ in 0..50 {
            let p = render_waitlist_random("dave.example");
            assert!(p.text.contains("@dave.example"));
            assert!(!p.text.contains("http"), "no link in a waitlist post");
            assert_eq!(
                &p.text[p.mention.byte_start..p.mention.byte_end],
                "@dave.example"
            );
        }
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
