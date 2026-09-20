//! The `href` type.
//!
//! **This is its own module because of the tuple field.** A private field is
//! private to the MODULE, and `web.rs` is a single ~9,000-line file holding every
//! `EntryRow` construction — so while the type lived there,
//! `SafeLink("javascript:alert(1)")` compiled and rendered verbatim into an
//! `href`. An adversarial review demonstrated exactly that, five different ways.
//! Here the field is unreachable from `web.rs`, which is what makes "no bypass"
//! structural rather than aspirational.

/// A string that is safe to place in an `href`.
///
/// **Structural, not procedural — and that distinction is the whole point.** The
/// saved-record path takes an attacker-controlled URL (any atproto client can
/// write the record), and Askama escapes HTML metacharacters but NOT schemes, so
/// `javascript:` survives escaping intact.
///
/// The defence used to be "remember to call `net::safe_link` before assigning
/// this field". A cold review measured what that was worth: deleting the call
/// left **all 679 tests passing**, because every test either exercised the helper
/// directly or never rendered this row. The control was real and completely
/// unprotected.
///
/// So the field is no longer a `String`. There is no `From<String>`, no public
/// member, and neither constructor can carry a foreign URL into an `href`:
/// [`SafeLink::external`] performs the scheme check itself, and
/// [`SafeLink::entry`] takes an `i64` and a scope query rather than a string, so
/// it cannot be handed one.
pub struct SafeLink(String);

impl SafeLink {
    /// The reader's own link to a cached entry: `/entries/{id}`, plus the
    /// list's scope query so paging back stays in the list it came from.
    ///
    /// **Takes the id and query separately and builds the path itself**, rather
    /// than accepting a ready-made `String`. A `fn internal(String)` constructor
    /// is an unrestricted `String` → `href` conduit sitting one identifier away
    /// from the single site where attacker-controlled data enters — and a review
    /// proved it, by typing `internal` where `external` was meant: the whole
    /// `javascript:` hole came back, compiled clean, and passed every test.
    ///
    /// An `i64` and a scope query cannot spell a scheme. The result always
    /// begins `/entries/`, so it is a path by construction, never a URL.
    /// `scope_qs` is percent-encoded upstream by `qenc`.
    pub fn entry(id: i64, scope_qs: &str) -> Self {
        Self(if scope_qs.is_empty() {
            format!("/entries/{id}")
        } else {
            format!("/entries/{id}?{scope_qs}")
        })
    }

    /// Attacker-controlled input. Scheme-checked; an unusable URL yields an
    /// EMPTY link, which the template renders as a row WITHOUT an anchor rather
    /// than dropping the row — a dropped row is unremovable, because the un-save
    /// button lives on it.
    pub fn external(raw: &str) -> Self {
        Self(crate::net::safe_link(raw).unwrap_or_default())
    }

    /// [`SafeLink::external`], for a template that omits the link rather than
    /// rendering it empty.
    ///
    /// The two shapes are not interchangeable, and which one a call site wants
    /// is decided by whether anything else lives on the link. The saved-record
    /// row keeps the EMPTY link because dropping the row would take the un-save
    /// button with it — the record would become unremovable from here. The
    /// reader view has no such passenger: `entry.html` already renders a
    /// disabled open-original button for an entry with no URL, so `None`
    /// selects a path that exists and is styled, and an empty `href` would only
    /// invent a third state meaning the same thing.
    ///
    /// It lives here rather than as `.filter(|l| !l.is_empty())` at the call
    /// site so that "empty means refused" stays a fact of this module. That is
    /// the same reason the field is in this file at all.
    pub fn external_opt(raw: &str) -> Option<Self> {
        let link = Self::external(raw);
        (!link.is_empty()).then_some(link)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Display for SafeLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
