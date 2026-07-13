//! Serde types for the `community.lexicon.rss.*` atproto record schemas.
//!
//! FeatherReader's defining bet is that a user's feed subscriptions, folders,
//! saved items, and batched read-state live as records in their own atproto PDS
//! under an **open, vendor-neutral community lexicon** (`community.lexicon.rss.*`)
//! rather than in the app's database — portable across any reader that adopts
//! the standard, not merely across FeatherReader instances.
//!
//! These types mirror the `community.lexicon.rss.*` schemas, authored in
//! the Lexicon Community idiom (`createdAt`/`updatedAt` as ISO-8601 datetimes,
//! `url`/`siteUrl`/`feedUrl` as URIs, `folder` as an `at://` strong ref). Each
//! record carries its `$type` NSID so it round-trips against the atproto record
//! shape returned by `com.atproto.repo.getRecord` / `listRecords`.
//!
//! Storage rules (never write these authoritatively to local SQLite):
//! - [`Subscription`] — one followed feed. `com.atproto.repo.createRecord` on
//!   subscribe; `deleteRecord` on unsubscribe. Source of truth for the follow list.
//! - [`Folder`] — a lightweight named grouping (a feed lives in one folder).
//! - [`Saved`] — a starred / save-for-later entry.
//! - [`ReadState`] — the **batched** per-feed read cursor (one record per feed,
//!   at a feed-derived rkey — never one record per article). Written by the
//!   read-state flusher; see the caveats on that flush path in
//!   [`crate::atproto`].

use serde::{Deserialize, Serialize};

/// NSID `$type` constants for the `community.lexicon.rss.*` record collections.
///
/// These double as the atproto **collection** NSIDs for `listRecords` /
/// `createRecord` / `putRecord` calls.
pub mod nsid {
    /// `community.lexicon.rss.subscription` — one followed feed.
    pub const SUBSCRIPTION: &str = "community.lexicon.rss.subscription";
    /// `community.lexicon.rss.folder` — a named grouping of subscriptions.
    pub const FOLDER: &str = "community.lexicon.rss.folder";
    /// `community.lexicon.rss.saved` — a starred / save-for-later entry.
    pub const SAVED: &str = "community.lexicon.rss.saved";
    /// `community.lexicon.rss.readState` — batched per-feed read cursor.
    pub const READ_STATE: &str = "community.lexicon.rss.readState";
}

/// Optional polling-cadence hint on a [`Subscription`]. Readers MAY honor or
/// ignore it. Mirrors the lexicon's `knownValues` for `fetchHint`.
///
/// `knownValues` in atproto is an *open* enum — an unrecognized value MUST NOT
/// break deserialization — so [`FetchHint::Other`] captures forward-compatible
/// values a future reader might write.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FetchHint {
    /// Poll as close to realtime as the reader supports.
    Realtime,
    /// Poll roughly hourly.
    Hourly,
    /// Poll roughly daily.
    Daily,
    /// Poll roughly weekly.
    Weekly,
    /// An unrecognized (forward-compatible) hint value.
    #[serde(untagged)]
    Other(String),
}

/// `community.lexicon.rss.subscription` — a subscription to a syndication feed
/// (RSS / Atom / JSON Feed). Record key: `tid`.
///
/// `url` + `createdAt` are required; everything else is optional.
///
/// ## Public feeds only (and the reserved `private` marker)
///
/// atproto PDS records are **public**: anyone can read them via unauthenticated
/// `getRecord` / `listRecords` and off the firehose, and they are retained even
/// after `deleteRecord`. A **private feed** (a Substack `…/feed/private/<token>`,
/// a Patreon `?auth=…` feed, a Ghost members `?uuid=` feed, a private-podcast
/// token feed, or any URL that carries a secret token / key / auth credential)
/// has its *secret in the URL*, so writing that URL here would leak paid /
/// members-only access to the whole network.
///
/// **Current decision: FeatherReader supports PUBLIC feeds only.** A private
/// feed is *refused* at the add / import boundary (see
/// [`crate::feed::classify_feed_privacy`]) — it is never fetched, never stored,
/// and no record (redacted or otherwise) is ever written. The server therefore
/// holds NO private secret, which keeps "your data lives in your public PDS"
/// 100% honest. Consequently every [`Subscription`] record actually written
/// carries a real, public feed `url`, and [`private`] is **always omitted**.
///
/// The [`private`] field is retained ONLY as a documented, forward-compatible
/// **reserved marker** for the eventual migration once atproto ships
/// **permissioned data / permission-sets** (early-proposal as of mid-2026,
/// bluesky-social/proposals#94). At that point a private feed's secret can live
/// in an owner-scoped, permission-gated collection and this record can reference
/// it with `private: true`. Until then the field has **no runtime behavior** —
/// nothing sets it and nothing branches on it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    /// The `$type` NSID discriminator; always [`nsid::SUBSCRIPTION`].
    #[serde(rename = "$type", default = "subscription_type")]
    pub r#type: String,

    /// Canonical feed URL (the RSS/Atom/JSON Feed document). Required.
    ///
    /// Always a real, PUBLIC feed URL: private/secret-bearing feeds are refused
    /// at the add boundary (see the type-level docs), so no record with a
    /// withheld or redacted `url` is ever written.
    pub url: String,

    /// Display title; a reader MAY override from feed metadata.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub title: Option<String>,

    /// Human-facing site the feed belongs to.
    #[serde(rename = "siteUrl", skip_serializing_if = "Option::is_none", default)]
    pub site_url: Option<String>,

    /// Optional `at://` strong ref to a [`Folder`] record.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub folder: Option<String>,

    /// Optional polling-cadence hint; readers MAY honor or ignore it.
    #[serde(rename = "fetchHint", skip_serializing_if = "Option::is_none", default)]
    pub fetch_hint: Option<FetchHint>,

    /// **Reserved** — no runtime behavior today.
    ///
    /// FeatherReader currently supports public feeds only (private/secret-bearing
    /// feeds are refused at the add boundary), so nothing sets this and every
    /// written record omits it (`None`). It is kept as a documented,
    /// forward-compatible seam for the eventual migration once atproto ships
    /// permissioned data: at that point a private feed's secret can live in an
    /// owner-scoped, permission-gated collection and this record can reference it
    /// with `private: true`. See the type-level docs.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub private: Option<bool>,

    /// Record creation time (ISO-8601 datetime). Required.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

fn subscription_type() -> String {
    nsid::SUBSCRIPTION.to_string()
}

impl Subscription {
    /// Construct a minimal subscription with only the required fields.
    pub fn new(url: impl Into<String>, created_at: impl Into<String>) -> Self {
        Self {
            r#type: nsid::SUBSCRIPTION.to_string(),
            url: url.into(),
            title: None,
            site_url: None,
            folder: None,
            fetch_hint: None,
            private: None,
            created_at: created_at.into(),
        }
    }
}

/// `community.lexicon.rss.folder` — a named folder/grouping for subscriptions.
/// Record key: `tid`.
///
/// `name` + `createdAt` are required; `position` is an optional sort hint.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Folder {
    /// The `$type` NSID discriminator; always [`nsid::FOLDER`].
    #[serde(rename = "$type", default = "folder_type")]
    pub r#type: String,

    /// Folder display name. Required.
    pub name: String,

    /// Optional sort hint among sibling folders (>= 0).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub position: Option<u64>,

    /// Record creation time (ISO-8601 datetime). Required.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

fn folder_type() -> String {
    nsid::FOLDER.to_string()
}

impl Folder {
    /// Construct a minimal folder with only the required fields.
    pub fn new(name: impl Into<String>, created_at: impl Into<String>) -> Self {
        Self {
            r#type: nsid::FOLDER.to_string(),
            name: name.into(),
            position: None,
            created_at: created_at.into(),
        }
    }
}

/// `community.lexicon.rss.saved` — an article kept for later (the reader's
/// "star"). Record key: `tid`.
///
/// `url` + `createdAt` are required; the rest aid cross-reader dedup.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Saved {
    /// The `$type` NSID discriminator; always [`nsid::SAVED`].
    #[serde(rename = "$type", default = "saved_type")]
    pub r#type: String,

    /// The article/entry permalink. Required.
    pub url: String,

    /// Display title of the saved entry.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub title: Option<String>,

    /// Feed the entry came from (soft ref; may outlive the subscription).
    #[serde(rename = "feedUrl", skip_serializing_if = "Option::is_none", default)]
    pub feed_url: Option<String>,

    /// Feed-native guid/id when present, for cross-reader dedup.
    #[serde(rename = "entryId", skip_serializing_if = "Option::is_none", default)]
    pub entry_id: Option<String>,

    /// Record creation time (ISO-8601 datetime). Required.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

fn saved_type() -> String {
    nsid::SAVED.to_string()
}

impl Saved {
    /// Construct a minimal saved entry with only the required fields.
    pub fn new(url: impl Into<String>, created_at: impl Into<String>) -> Self {
        Self {
            r#type: nsid::SAVED.to_string(),
            url: url.into(),
            title: None,
            feed_url: None,
            entry_id: None,
            created_at: created_at.into(),
        }
    }
}

/// `community.lexicon.rss.readState` — a batched read high-water-mark for a
/// single feed. Record key: `any`; the rkey is derived deterministically from the
/// feed (a hash of the feed URL), so there is one record per feed with a stable
/// key, NOT one record per article.
///
/// `feedUrl` + `updatedAt` are required; `readThrough` is OPTIONAL — it is a
/// water-mark ("every entry seen/published `<=` this is read"), so it is written
/// only once a real high-water-mark exists. Omitting it (rather than synthesizing
/// a flush-time value) means a brand-new cursor asserts nothing about the backlog:
/// only the explicit `readIds` mark entries read. The two capped id-sets carry
/// out-of-order reads and explicit mark-unread exceptions.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReadState {
    /// The `$type` NSID discriminator; always [`nsid::READ_STATE`].
    #[serde(rename = "$type", default = "read_state_type")]
    pub r#type: String,

    /// The feed this cursor covers. Required.
    #[serde(rename = "feedUrl")]
    pub feed_url: String,

    /// High-water-mark: every entry with seen/published time <= this is READ.
    /// **Optional** — omitted from the record when no local high-water-mark
    /// exists yet, so a fresh cursor never implicitly marks the backlog read.
    #[serde(
        rename = "readThrough",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub read_through: Option<String>,

    /// Entries newer than `readThrough` that are ALSO read (out-of-order reads).
    /// Capped at 1000 by the lexicon; empty sets are omitted from the record.
    #[serde(rename = "readIds", skip_serializing_if = "Vec::is_empty", default)]
    pub read_ids: Vec<String>,

    /// Entries older than `readThrough` explicitly kept UNREAD (mark-unread).
    /// Capped at 1000 by the lexicon; empty sets are omitted from the record.
    #[serde(rename = "unreadIds", skip_serializing_if = "Vec::is_empty", default)]
    pub unread_ids: Vec<String>,

    /// Last time this cursor was flushed (ISO-8601 datetime). Required. Intended
    /// as the tie-breaker for cross-device merges (newest `updatedAt` wins);
    /// a login-time reconcile that uses it is not implemented yet.
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

fn read_state_type() -> String {
    nsid::READ_STATE.to_string()
}

impl ReadState {
    /// Maximum length of the `readIds` / `unreadIds` exception sets, per the
    /// lexicon. The flusher enforces this cap before writing (see
    /// `scheduler::cap`).
    pub const MAX_IDS: usize = 1000;

    /// Construct a minimal read cursor with only the required fields.
    ///
    /// `read_through` is optional: pass `None` for a cursor that has no local
    /// high-water-mark yet, so the record omits `readThrough` entirely rather than
    /// synthesizing a flush-time value that would mark the backlog read.
    pub fn new(
        feed_url: impl Into<String>,
        read_through: Option<String>,
        updated_at: impl Into<String>,
    ) -> Self {
        Self {
            r#type: nsid::READ_STATE.to_string(),
            feed_url: feed_url.into(),
            read_through,
            read_ids: Vec::new(),
            unread_ids: Vec::new(),
            updated_at: updated_at.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn subscription_round_trips_full_record() {
        // Matches the atproto record shape returned by getRecord's `value`.
        let value = json!({
            "$type": "community.lexicon.rss.subscription",
            "url": "https://example.com/feed.xml",
            "title": "Example Blog",
            "siteUrl": "https://example.com/",
            "folder": "at://did:plc:abc123/community.lexicon.rss.folder/3kfolderrkey",
            "fetchHint": "hourly",
            "createdAt": "2026-07-12T00:00:00.000Z"
        });

        let sub: Subscription = serde_json::from_value(value.clone()).expect("deserialize");
        assert_eq!(sub.r#type, nsid::SUBSCRIPTION);
        assert_eq!(sub.url, "https://example.com/feed.xml");
        assert_eq!(sub.title.as_deref(), Some("Example Blog"));
        assert_eq!(sub.site_url.as_deref(), Some("https://example.com/"));
        assert_eq!(sub.fetch_hint, Some(FetchHint::Hourly));

        let back = serde_json::to_value(&sub).expect("serialize");
        assert_eq!(back, value);
    }

    #[test]
    fn subscription_minimal_omits_optional_fields() {
        let sub = Subscription::new("https://example.com/feed.xml", "2026-07-12T00:00:00.000Z");
        let back = serde_json::to_value(&sub).expect("serialize");
        assert_eq!(
            back,
            json!({
                "$type": "community.lexicon.rss.subscription",
                "url": "https://example.com/feed.xml",
                "createdAt": "2026-07-12T00:00:00.000Z"
            })
        );
    }

    #[test]
    fn subscription_reserved_private_marker_omitted_by_default_but_round_trips() {
        // Default construction never sets `private`; a public record omits it
        // entirely (byte-for-byte unchanged from before the reserved field).
        let public = Subscription::new("https://example.com/feed.xml", "2026-07-12T00:00:00.000Z");
        assert_eq!(public.private, None);
        let public_body = serde_json::to_value(&public).expect("serialize");
        assert!(public_body.get("private").is_none());

        // The reserved field is forward-compatible: if a future record ever
        // carries `private: true`, it (de)serializes cleanly. Nothing in the
        // current codebase sets it, but the seam must round-trip.
        let mut future =
            Subscription::new("https://example.com/feed.xml", "2026-07-12T00:00:00.000Z");
        future.private = Some(true);
        let back = serde_json::to_value(&future).expect("serialize");
        assert_eq!(back["private"], serde_json::json!(true));
        let parsed: Subscription = serde_json::from_value(back).expect("deserialize");
        assert_eq!(parsed.private, Some(true));
    }

    #[test]
    fn fetch_hint_open_enum_accepts_unknown() {
        let sub: Subscription = serde_json::from_value(json!({
            "url": "https://example.com/feed.xml",
            "fetchHint": "every-15-min",
            "createdAt": "2026-07-12T00:00:00.000Z"
        }))
        .expect("deserialize");
        assert_eq!(
            sub.fetch_hint,
            Some(FetchHint::Other("every-15-min".to_string()))
        );
        // $type defaults in when the record value omits it.
        assert_eq!(sub.r#type, nsid::SUBSCRIPTION);
    }

    #[test]
    fn folder_round_trips() {
        let value = json!({
            "$type": "community.lexicon.rss.folder",
            "name": "Tech",
            "position": 2,
            "createdAt": "2026-07-12T00:00:00.000Z"
        });
        let folder: Folder = serde_json::from_value(value.clone()).expect("deserialize");
        assert_eq!(folder.name, "Tech");
        assert_eq!(folder.position, Some(2));
        assert_eq!(serde_json::to_value(&folder).expect("serialize"), value);
    }

    #[test]
    fn saved_round_trips() {
        let value = json!({
            "$type": "community.lexicon.rss.saved",
            "url": "https://example.com/post/1",
            "title": "A kept post",
            "feedUrl": "https://example.com/feed.xml",
            "entryId": "tag:example.com,2026:1",
            "createdAt": "2026-07-12T00:00:00.000Z"
        });
        let saved: Saved = serde_json::from_value(value.clone()).expect("deserialize");
        assert_eq!(saved.url, "https://example.com/post/1");
        assert_eq!(
            saved.feed_url.as_deref(),
            Some("https://example.com/feed.xml")
        );
        assert_eq!(saved.entry_id.as_deref(), Some("tag:example.com,2026:1"));
        assert_eq!(serde_json::to_value(&saved).expect("serialize"), value);
    }

    #[test]
    fn read_state_round_trips_with_id_sets() {
        let value = json!({
            "$type": "community.lexicon.rss.readState",
            "feedUrl": "https://example.com/feed.xml",
            "readThrough": "2026-07-12T00:00:00.000Z",
            "readIds": ["entry-a", "entry-b"],
            "unreadIds": ["entry-c"],
            "updatedAt": "2026-07-12T01:00:00.000Z"
        });
        let rs: ReadState = serde_json::from_value(value.clone()).expect("deserialize");
        assert_eq!(rs.feed_url, "https://example.com/feed.xml");
        assert_eq!(rs.read_through.as_deref(), Some("2026-07-12T00:00:00.000Z"));
        assert_eq!(rs.read_ids, vec!["entry-a", "entry-b"]);
        assert_eq!(rs.unread_ids, vec!["entry-c"]);
        assert_eq!(serde_json::to_value(&rs).expect("serialize"), value);
    }

    #[test]
    fn read_state_minimal_omits_empty_id_sets() {
        let rs = ReadState::new(
            "https://example.com/feed.xml",
            Some("2026-07-12T00:00:00.000Z".to_string()),
            "2026-07-12T01:00:00.000Z",
        );
        let back = serde_json::to_value(&rs).expect("serialize");
        assert_eq!(
            back,
            json!({
                "$type": "community.lexicon.rss.readState",
                "feedUrl": "https://example.com/feed.xml",
                "readThrough": "2026-07-12T00:00:00.000Z",
                "updatedAt": "2026-07-12T01:00:00.000Z"
            })
        );
    }

    #[test]
    fn read_state_omits_read_through_when_none() {
        // A brand-new cursor with no high-water-mark must NOT synthesize one:
        // `readThrough` is absent entirely so the backlog is not implicitly read.
        let rs = ReadState::new(
            "https://example.com/feed.xml",
            None,
            "2026-07-12T01:00:00.000Z",
        );
        let back = serde_json::to_value(&rs).expect("serialize");
        assert!(back.get("readThrough").is_none());
        assert_eq!(
            back,
            json!({
                "$type": "community.lexicon.rss.readState",
                "feedUrl": "https://example.com/feed.xml",
                "updatedAt": "2026-07-12T01:00:00.000Z"
            })
        );
        // And a record without readThrough round-trips back to None.
        let parsed: ReadState = serde_json::from_value(back).expect("deserialize");
        assert_eq!(parsed.read_through, None);
    }
}
