//! Record types that cannot exist unvetted.
//!
//! **This is its own module because of the private field.** A private field is
//! private to the MODULE, and `repo.rs` is where every record write is
//! assembled — so a type declared there could be constructed beside its own
//! constructor, and the guarantee would be a convention again. `safe_link.rs`
//! exists for exactly this reason, after a review demonstrated five separate
//! ways to rebuild the hole it was meant to close.
//!
//! The guarantee here is narrow and worth stating precisely: **holding one of
//! these means the vet ran**. It does not mean the value is safe to render, and
//! it says nothing about records read back from the PDS — that is the read-side
//! guard on `lexicon::Subscription::site_url`.

use anyhow::{bail, Result};
use serde::Serialize;

use crate::lexicon::{Folder, ReadState, Saved, Subscription};

/// What a record-write primitive will accept.
///
/// **The bound that makes vetting unskippable.** The write primitives were
/// generic over `T: Serialize`, and `lexicon::Subscription` derives
/// `Serialize` — so `create_record(nsid::SUBSCRIPTION, &raw_subscription)`
/// compiled and wrote an unvetted record. On `oauth::xrpc::Repo` those
/// primitives are `pub` (an example drives them), so that was reachable from
/// any handler in this crate.
///
/// The obvious fix — dropping `Serialize` from `Subscription` — is the one
/// `repo.rs` recorded as blocked: [`VettedSubscription`] is
/// `#[serde(transparent)]` over it, so removing the derive forces a
/// hand-written impl, and a record-shape slip there would silently migrate
/// every reader's repo. A marker trait gets the same guarantee and cannot
/// drift, because the wire format keeps coming from one derive.
///
/// **Sealed**: implementing it requires `sealed::Sealed`, which is private to
/// this module, so the list below is the whole list — nothing elsewhere in the
/// crate can add itself. `Subscription` and [`Saved`] are deliberately absent;
/// their vetted wrappers are here instead.
///
/// A vetted record is accepted:
///
/// ```
/// use feather_reader::lexicon::Subscription;
/// use feather_reader::vetted::{VettedSubscription, WritableRecord};
/// fn writes<T: WritableRecord>(_record: &T) {}
///
/// let sub = Subscription::new("https://example.com/feed.xml", "2026-01-01T00:00:00.000Z");
/// writes(&VettedSubscription::new(&sub));
/// ```
///
/// A raw one does not compile:
///
/// ```compile_fail
/// use feather_reader::lexicon::Subscription;
/// use feather_reader::vetted::WritableRecord;
/// fn writes<T: WritableRecord>(_record: &T) {}
///
/// let sub = Subscription::new("https://example.com/feed.xml", "2026-01-01T00:00:00.000Z");
/// writes(&sub);
/// ```
pub trait WritableRecord: Serialize + sealed::Sealed {}

mod sealed {
    /// Private to this module, so [`super::WritableRecord`] can only be
    /// implemented here.
    pub trait Sealed {}
}

macro_rules! writable {
    ($($t:ty),+ $(,)?) => {$(
        impl sealed::Sealed for $t {}
        impl WritableRecord for $t {}
    )+};
}

// The vetted wrappers, plus the two lexicon records that carry nothing to vet:
// `Folder` is a name and a sort position, `ReadState` a feed URL the reader
// already holds and two id lists. Neither has a field rendered as an href,
// which is what `vet` exists to check.
writable!(
    VettedSubscription,
    VettedSaved,
    Folder,
    ReadState,
    SpikeRecord
);

/// Arbitrary JSON for `examples/oauth_spike.rs`, which round-trips a record
/// through a scratch collection to prove the OAuth write path works.
///
/// **Not for the reader itself.** It exists because that example is a separate
/// crate target driving the `pub` primitives, and the alternative was leaving
/// them generic over every `Serialize` — which is the hole this trait closes.
/// Anything the reader actually stores has a lexicon type and a vetted wrapper.
#[doc(hidden)]
#[derive(Serialize, Clone, Debug)]
#[serde(transparent)]
pub struct SpikeRecord(pub serde_json::Value);

/// A [`Subscription`] whose `siteUrl` has been scheme-checked.
///
/// `#[serde(transparent)]` so the bytes on the wire are byte-identical to
/// serializing the inner record. This type changes what the compiler permits,
/// not what the PDS receives — a record-shape change here would be a silent
/// migration of every reader's repo.
#[derive(Serialize, Clone, Debug)]
#[serde(transparent)]
pub struct VettedSubscription(Subscription);

impl VettedSubscription {
    /// Scheme-check `siteUrl` and hand back a record the writers will accept.
    ///
    /// A rejected URL becomes `None` rather than dropping the subscription: the
    /// feed is what the reader asked for, the site link is decoration. That is
    /// the same call the previous free-function `vet` made, and the reasoning is
    /// unchanged — what changes is that skipping it no longer type-checks.
    pub fn new(sub: &Subscription) -> Self {
        let mut out = sub.clone();
        out.site_url = out.site_url.as_deref().and_then(crate::net::safe_link);
        Self(out)
    }

    /// Vet a batch — the OPML-import path.
    pub fn all(subs: &[Subscription]) -> Vec<Self> {
        subs.iter().map(Self::new).collect()
    }
}

/// A [`Saved`] record whose `url` has been scheme-checked.
///
/// **Fallible, unlike [`VettedSubscription`], because `url` is required.** The
/// subscription's `siteUrl` is an `Option`, so a rejected value has an obvious
/// resting place. A saved record exists to point at something, so there is no
/// honest way to publish one whose URL we refused — an empty string would be a
/// malformed record, and dropping the field would not deserialize.
///
/// Refusing is already a handled outcome at the only call site: the star
/// handler logs a failed PDS write and keeps the local star, so the reader
/// still sees the entry starred in this reader while nothing hostile is
/// published under their authorship.
#[derive(Serialize, Clone, Debug)]
#[serde(transparent)]
pub struct VettedSaved(Saved);

impl VettedSaved {
    pub fn new(saved: &Saved) -> Result<Self> {
        let Some(url) = crate::net::safe_link(&saved.url) else {
            bail!(
                "refusing to publish a saved record whose url is not http(s); \
                 the entry stays starred locally"
            )
        };
        let mut out = saved.clone();
        out.url = url;
        Ok(Self(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hostile_site_url_becomes_none_and_the_rest_survives() {
        let mut sub = Subscription::new("https://example.com/feed.xml", "2026-01-01T00:00:00.000Z");
        sub.site_url = Some("javascript:alert(1)".into());
        sub.title = Some("Kept".into());

        let vetted = VettedSubscription::new(&sub);
        let rendered = serde_json::to_value(&vetted).unwrap();
        assert!(
            rendered.get("siteUrl").is_none(),
            "a rejected siteUrl must be omitted, not emptied: {rendered}"
        );
        assert_eq!(rendered["title"], "Kept", "the rest of the record was lost");
        assert_eq!(rendered["url"], "https://example.com/feed.xml");
    }

    #[test]
    fn a_clean_record_serializes_byte_identically_to_the_inner_one() {
        // The newtype changes what compiles, not what the PDS receives.
        let mut sub = Subscription::new("https://example.com/feed.xml", "2026-01-01T00:00:00.000Z");
        sub.site_url = Some("https://example.com/blog".into());
        assert_eq!(
            serde_json::to_string(&VettedSubscription::new(&sub)).unwrap(),
            serde_json::to_string(&sub).unwrap(),
            "the wrapper changed the wire format — that would silently migrate \
             every reader's repo"
        );
    }

    /// Ported from `repo::tests::vet_rejects_by_scheme_and_keeps_everything_else`
    /// when the free function became this type. The cases are the reasoning, so
    /// they move with it rather than being dropped.
    #[test]
    fn whitespace_is_normalised_and_absent_stays_absent() {
        let mut padded =
            Subscription::new("https://example.com/feed.xml", "2026-01-01T00:00:00.000Z");
        padded.site_url = Some("  https://example.com/blog  ".into());
        let rendered = serde_json::to_value(VettedSubscription::new(&padded)).unwrap();
        assert_eq!(
            rendered["siteUrl"], "https://example.com/blog",
            "whitespace should normalise rather than reject, as it does for entry links"
        );

        // Absent stays absent — no empty string is invented.
        let bare = Subscription::new("https://example.com/feed.xml", "2026-01-01T00:00:00.000Z");
        let rendered = serde_json::to_value(VettedSubscription::new(&bare)).unwrap();
        assert!(rendered.get("siteUrl").is_none());
    }

    /// Ported from `repo::tests::vet_all_cleans_one_bad_record_without_touching_the_rest`.
    #[test]
    fn one_bad_record_in_a_batch_is_cleaned_not_dropped() {
        let mk = |site: &str| {
            let mut s =
                Subscription::new("https://example.com/feed.xml", "2026-01-01T00:00:00.000Z");
            s.site_url = Some(site.into());
            s
        };
        let vetted =
            VettedSubscription::all(&[mk("https://a.example/"), mk("javascript:alert(1)")]);
        assert_eq!(vetted.len(), 2, "the batch lost a record");
        let first = serde_json::to_value(&vetted[0]).unwrap();
        let second = serde_json::to_value(&vetted[1]).unwrap();
        assert_eq!(first["siteUrl"], "https://a.example/");
        assert!(
            second.get("siteUrl").is_none(),
            "one bad record in a batch must be cleaned, not the whole batch dropped"
        );
    }

    #[test]
    fn a_saved_record_with_a_hostile_url_cannot_be_built() {
        for hostile in [
            "javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=",
            "vbscript:msgbox(1)",
            "not a url",
        ] {
            let saved = Saved::new(hostile, "2026-01-01T00:00:00.000Z");
            assert!(
                VettedSaved::new(&saved).is_err(),
                "{hostile:?} produced a publishable saved record"
            );
        }
    }

    #[test]
    fn a_legitimate_saved_record_survives_and_is_normalised() {
        let saved = Saved::new("  https://example.com/post  ", "2026-01-01T00:00:00.000Z");
        let vetted = VettedSaved::new(&saved).expect("a plain https url is publishable");
        let rendered = serde_json::to_value(&vetted).unwrap();
        assert_eq!(rendered["url"], "https://example.com/post");
    }
}
