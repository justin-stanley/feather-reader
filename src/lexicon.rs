//! Serde types for the `community.lexicon.rss.*` atproto record schemas.
//!
//! FeatherReader's defining bet is that a user's feed subscriptions, folders,
//! saved items, and batched read-state live as records in their own atproto PDS
//! under an **open, vendor-neutral community lexicon** (`community.lexicon.rss.*`)
//! rather than in the app's database — portable across any reader that adopts
//! the standard, not merely across FeatherReader instances.
//!
//! These types mirror the schemas defined in the design doc exactly, authored in
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
//!   upserted via `putRecord` with a feed-derived rkey — never one record per
//!   article).

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
/// ## The `private` marker and the withheld-URL contract
///
/// atproto PDS records are **public**: anyone can read them via unauthenticated
/// `getRecord` / `listRecords` and off the firehose, and they are retained even
/// after `deleteRecord`. That is fine for a normal feed, but a **private feed**
/// (a Substack `…/feed/private/<token>`, a Patreon `?auth=…` feed, a Ghost
/// members feed, or any URL that carries a secret token / key / auth credential)
/// has its *secret in the URL*. Writing that URL to the PDS would leak paid /
/// members-only content access to the entire network.
///
/// So for a private subscription the record is written **redacted**: [`private`]
/// is set to `true`, the real secret-bearing feed URL is **intentionally
/// withheld** (see [`url`] — a redacted record carries the public publication
/// origin, e.g. `https://author.substack.com/`, NOT the secret feed path), and
/// the secret stays **owner-held locally** (in FeatherReader's SQLite, never on
/// the PDS). `private: true` therefore means "the canonical feed URL for this
/// subscription is deliberately absent from this record; the owner holds it".
///
/// This is a **STOPGAP**. It is Option 1 (local-only secret) until atproto ships
/// **permissioned data / permission-sets** (early-proposal stage as of mid-2026,
/// bluesky-social/proposals#94, realistically late-2026+), at which point the
/// secret feed URL migrates out of local-only storage into an **owner-scoped,
/// permission-gated private collection** on the PDS and the record here can carry
/// a reference to it instead of withholding it outright. The [`private`] marker
/// is the forward-compatible seam for that migration and is part of the
/// community-lexicon design, not a FeatherReader-only field.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    /// The `$type` NSID discriminator; always [`nsid::SUBSCRIPTION`].
    #[serde(rename = "$type", default = "subscription_type")]
    pub r#type: String,

    /// Canonical feed URL (the RSS/Atom/JSON Feed document). Required.
    ///
    /// For a **private** subscription ([`private`] `== Some(true)`) this is NOT
    /// the real secret-bearing feed URL — that is withheld (see the type-level
    /// docs). Instead it carries the feed's **public publication origin** (scheme
    /// + host, or the feed's `<link>` site URL) so the record is still a usable,
    /// human-recognisable pointer without leaking the secret.
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

    /// Whether this is a **private** subscription whose real feed URL is
    /// intentionally withheld from this (public) PDS record.
    ///
    /// `Some(true)` means the secret-bearing feed URL is deliberately NOT in this
    /// record — it is held only in the owner's local store — because PDS records
    /// are public (unauth `getRecord`/`listRecords` + firehose, retained after
    /// delete). See the type-level docs: this is a **stopgap** until atproto
    /// permissioned-data / permission-sets, at which point the secret migrates to
    /// an owner-scoped private collection. Omitted (`None`) for ordinary public
    /// feeds so existing records are byte-for-byte unchanged.
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
/// single feed. Record key: `any` (rkey is derived deterministically from the
/// feed, e.g. a hash of the feed URL, so it is a stable **upsert** target —
/// one `putRecord` per feed, NOT one record per article).
///
/// `feedUrl` + `readThrough` + `updatedAt` are required; the two capped id-sets
/// carry out-of-order reads and explicit mark-unread exceptions.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReadState {
    /// The `$type` NSID discriminator; always [`nsid::READ_STATE`].
    #[serde(rename = "$type", default = "read_state_type")]
    pub r#type: String,

    /// The feed this cursor covers. Required.
    #[serde(rename = "feedUrl")]
    pub feed_url: String,

    /// High-water-mark: every entry with seen/published time <= this is READ.
    /// Required.
    #[serde(rename = "readThrough")]
    pub read_through: String,

    /// Entries newer than `readThrough` that are ALSO read (out-of-order reads).
    /// Capped at 1000 by the lexicon; empty sets are omitted from the record.
    #[serde(rename = "readIds", skip_serializing_if = "Vec::is_empty", default)]
    pub read_ids: Vec<String>,

    /// Entries older than `readThrough` explicitly kept UNREAD (mark-unread).
    /// Capped at 1000 by the lexicon; empty sets are omitted from the record.
    #[serde(rename = "unreadIds", skip_serializing_if = "Vec::is_empty", default)]
    pub unread_ids: Vec<String>,

    /// Last time this cursor was flushed (ISO-8601 datetime); the reconcile
    /// tie-breaker (newest-`updatedAt`-wins-for-unread). Required.
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

fn read_state_type() -> String {
    nsid::READ_STATE.to_string()
}

impl ReadState {
    /// Maximum length of the `readIds` / `unreadIds` exception sets, per the
    /// lexicon. The flusher must re-cap and compact into `readThrough` before
    /// writing.
    pub const MAX_IDS: usize = 1000;

    /// Construct a minimal read cursor with only the required fields.
    pub fn new(
        feed_url: impl Into<String>,
        read_through: impl Into<String>,
        updated_at: impl Into<String>,
    ) -> Self {
        Self {
            r#type: nsid::READ_STATE.to_string(),
            feed_url: feed_url.into(),
            read_through: read_through.into(),
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
    fn subscription_private_marker_round_trips_and_omits_when_none() {
        // A redacted private record: `private: true`, `url` is the PUBLIC origin
        // (no secret), and it carries no secret-bearing feed path anywhere.
        let mut sub = Subscription::new("https://author.substack.com/", "2026-07-12T00:00:00.000Z");
        sub.title = Some("Author (private)".to_string());
        sub.site_url = Some("https://author.substack.com/".to_string());
        sub.private = Some(true);

        let back = serde_json::to_value(&sub).expect("serialize");
        assert_eq!(back["private"], serde_json::json!(true));
        // The serialized body carries the public origin only — no secret token.
        let body = serde_json::to_string(&sub).expect("serialize str");
        assert!(!body.contains("/feed/private/"));
        assert!(!body.contains("secret-token"));

        // Round-trips back to the same value.
        let parsed: Subscription = serde_json::from_value(back).expect("deserialize");
        assert_eq!(parsed.private, Some(true));
        assert_eq!(parsed.url, "https://author.substack.com/");

        // A public subscription omits `private` entirely (regression: existing
        // records are byte-for-byte unchanged).
        let public = Subscription::new("https://example.com/feed.xml", "2026-07-12T00:00:00.000Z");
        let public_body = serde_json::to_value(&public).expect("serialize");
        assert!(public_body.get("private").is_none());
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
        assert_eq!(rs.read_through, "2026-07-12T00:00:00.000Z");
        assert_eq!(rs.read_ids, vec!["entry-a", "entry-b"]);
        assert_eq!(rs.unread_ids, vec!["entry-c"]);
        assert_eq!(serde_json::to_value(&rs).expect("serialize"), value);
    }

    #[test]
    fn read_state_minimal_omits_empty_id_sets() {
        let rs = ReadState::new(
            "https://example.com/feed.xml",
            "2026-07-12T00:00:00.000Z",
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
}
