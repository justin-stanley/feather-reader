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
//!
//! The Lexicon JSON is under `lexicons/community/lexicon/rss/`; the semantics are in `docs/lexicon.md`; `lexicon_json_tests` keeps the JSON and these types from drifting.

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

    /// `site.standard.publication` — a standard.site publication. NOT one of
    /// ours: it is another project's lexicon, named here because it is the only
    /// foreign collection this reader will accept as a subscribable feed.
    pub const STANDARD_PUBLICATION: &str = "site.standard.publication";

    /// `site.standard.document` — one standard.site article. Also not ours.
    pub const STANDARD_DOCUMENT: &str = "site.standard.document";
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

/// Drop a `siteUrl` this reader would refuse to render, at the point a record
/// crosses into the process.
///
/// Absent stays absent and a good URL is passed through trimmed, matching
/// [`crate::net::safe_link`]'s handling of entry links — the same allow-list, so
/// the two URL fields on a record cannot disagree about what a link is.
fn de_scheme_checked<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    Ok(raw.as_deref().and_then(crate::net::safe_link))
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
/// carries a real, public feed `url`, and [`Subscription::private`] is **always omitted**.
///
/// The [`Subscription::private`] field is retained ONLY as a documented, forward-compatible
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
    ///
    /// **Scheme-checked on the way in.** Any atproto client can write this field
    /// into the user's repo, and the lexicon invites readers to render it as a
    /// link, so a record fetched from the PDS is attacker-controlled input. The
    /// `deserialize_with` below is the read-side counterpart to the write-side
    /// vet in [`crate::repo`]: together they mean a `Subscription` that entered
    /// this process from outside cannot be carrying a `javascript:` URL, whatever
    /// it is later rendered into — an `href`, or an OPML `htmlUrl` we hand back
    /// to the user as a file.
    ///
    /// **The READ side only.** A record built in-process rather than
    /// deserialised does not pass through here — OPML import parses `htmlUrl`
    /// out of XML by hand, and the manage form assigns the field directly.
    /// Those are the write boundary's to vet, which is why both guards exist
    /// rather than either one being sufficient.
    ///
    /// A rejected value becomes `None`, so it is omitted rather than emitted
    /// empty; a consumer renders no link instead of a broken one.
    ///
    /// **Round-trip fidelity is deliberately lost.** Read a record holding a
    /// hostile `siteUrl`, re-put it, and we write it back cleaned rather than
    /// preserving what another client stored. That heals the user's repo
    /// instead of propagating someone else's script URL — but it does mean a
    /// `putRecord` following a read is not byte-identical to what was there,
    /// and that is a decision, not an accident.
    #[serde(
        rename = "siteUrl",
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "de_scheme_checked"
    )]
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

    /// Every field of the record this build does not know, kept as it was
    /// read so a put of the record writes them back (#268).
    ///
    /// The collection is shared with every other `community.lexicon.rss`
    /// client, and a rename is a `putRecord` of the WHOLE record: without
    /// this, a field another client added was erased by every rename here.
    /// The known fields above are consumed by name before anything lands in
    /// this map, so it never holds `$type`, `name`, `position` or `createdAt`
    /// and a serialized record never carries a key twice. Empty for a folder
    /// this build creates, so it adds nothing to that record.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
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
            extra: serde_json::Map::new(),
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

    /// What the strings in `readIds` / `unreadIds` are. See docs/lexicon.md for
    /// the item-id rule the value names. FeatherReader writes
    /// [`ReadState::ID_TYPE_GUID`]: each is the entry's GUID as the feed
    /// publishes it (or the stable stand-in FeatherReader derives when it does
    /// not — `feed::stable_guid` / `feed::bound_guid`, both fixed-key hashes, so
    /// every instance derives the same one), which means the same thing on any
    /// instance and in any client.
    ///
    /// **Absent means legacy.** Records written before #246 carried this
    /// instance's LOCAL SQLite row ids, which are meaningless anywhere else —
    /// including on a fresh or restored database of the same instance. A
    /// reader must ignore the id arrays of such a record; its `readThrough`
    /// is still a timestamp and still usable.
    #[serde(rename = "idType", skip_serializing_if = "Option::is_none", default)]
    pub id_type: Option<String>,

    /// Last time this cursor was changed (ISO-8601 datetime). Required. The
    /// tie-breaker for cross-instance merges: when one side lists an entry read
    /// and the other lists it unread, the newer `updatedAt` wins
    /// (`readstate::flush_did`).
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

fn read_state_type() -> String {
    nsid::READ_STATE.to_string()
}

impl ReadState {
    /// Maximum length of the `readIds` / `unreadIds` exception sets, per the
    /// lexicon. The flusher enforces this cap before writing (see
    /// `readstate::cap`).
    pub const MAX_IDS: usize = 1000;

    /// The [`ReadState::id_type`] FeatherReader writes: the id arrays hold
    /// entry GUIDs.
    pub const ID_TYPE_GUID: &'static str = "guid";

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
            id_type: None,
            updated_at: updated_at.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A record written by some other client is attacker-controlled input.
    ///
    /// Asserted through `serde_json::from_str` rather than by calling the
    /// deserialiser directly: the production path is a PDS fetch, and a test that
    /// calls the helper would pass just as happily with `deserialize_with`
    /// removed from the field.
    #[test]
    fn a_hostile_site_url_does_not_survive_deserialisation() {
        for hostile in [
            "javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=",
            "vbscript:msgbox(1)",
            "  javascript:alert(1)  ",
            "not a url at all",
        ] {
            let json = serde_json::json!({
                "$type": "community.lexicon.rss.subscription",
                "url": "https://example.com/feed.xml",
                "siteUrl": hostile,
                "createdAt": "2026-01-01T00:00:00.000Z",
            })
            .to_string();
            let sub: Subscription = serde_json::from_str(&json).expect("record should parse");
            assert_eq!(
                sub.site_url, None,
                "{hostile:?} survived into a record this reader will re-publish and export"
            );
            assert_eq!(
                sub.url, "https://example.com/feed.xml",
                "the feed URL is not the field under test and must be untouched"
            );
        }
    }

    /// The check must not eat an ordinary record, and must normalise the way the
    /// entry-link path already does.
    #[test]
    fn a_legitimate_site_url_survives_deserialisation() {
        for (stored, expected) in [
            ("https://example.com/blog", "https://example.com/blog"),
            ("http://example.com/blog", "http://example.com/blog"),
            ("  https://example.com/blog  ", "https://example.com/blog"),
        ] {
            let json = serde_json::json!({
                "$type": "community.lexicon.rss.subscription",
                "url": "https://example.com/feed.xml",
                "siteUrl": stored,
                "createdAt": "2026-01-01T00:00:00.000Z",
            })
            .to_string();
            let sub: Subscription = serde_json::from_str(&json).expect("record should parse");
            assert_eq!(sub.site_url.as_deref(), Some(expected));
        }
    }

    /// An absent `siteUrl` stays absent — no empty string is invented, and the
    /// `default` path must not trip over the custom deserialiser.
    #[test]
    fn an_absent_site_url_stays_absent() {
        let json = serde_json::json!({
            "$type": "community.lexicon.rss.subscription",
            "url": "https://example.com/feed.xml",
            "createdAt": "2026-01-01T00:00:00.000Z",
        })
        .to_string();
        let sub: Subscription = serde_json::from_str(&json).expect("record should parse");
        assert_eq!(sub.site_url, None);

        // Explicit null is the same as absent, not an error.
        let json = serde_json::json!({
            "$type": "community.lexicon.rss.subscription",
            "url": "https://example.com/feed.xml",
            "siteUrl": serde_json::Value::Null,
            "createdAt": "2026-01-01T00:00:00.000Z",
        })
        .to_string();
        let sub: Subscription = serde_json::from_str(&json).expect("explicit null should parse");
        assert_eq!(sub.site_url, None);
    }

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

    /// **A folder record keeps the fields this build does not know (#268).**
    /// Other `community.lexicon.rss` clients write the same collection, and a
    /// rename puts the whole record back: a field dropped on the way through
    /// is erased from the reader's repo.
    #[test]
    fn folder_round_trips_fields_it_does_not_know() {
        let value = json!({
            "$type": "community.lexicon.rss.folder",
            "name": "Tech",
            "position": 3,
            "createdAt": "2024-01-01T00:00:00.000Z",
            "color": "#abc",
            "nested": { "icon": "star", "tags": [1, "two", null] }
        });
        let folder: Folder = serde_json::from_value(value.clone()).expect("deserialize");
        assert_eq!(folder.name, "Tech");
        assert_eq!(folder.position, Some(3));
        assert_eq!(serde_json::to_value(&folder).expect("serialize"), value);
        // Serialized as text too: one key per field, never a duplicate.
        let text = serde_json::to_string(&folder).expect("serialize");
        for key in ["$type", "name", "position", "createdAt", "color", "nested"] {
            assert_eq!(
                text.matches(&format!("\"{key}\":")).count(),
                1,
                "{key} not emitted exactly once: {text}"
            );
        }
    }

    /// A folder this build creates carries the lexicon's fields and nothing
    /// else — no empty catch-all key, no nulls.
    #[test]
    fn a_new_folder_serializes_only_its_own_fields() {
        let folder = Folder::new("Tech", "2026-07-12T00:00:00.000Z");
        assert_eq!(
            serde_json::to_value(&folder).expect("serialize"),
            json!({
                "$type": "community.lexicon.rss.folder",
                "name": "Tech",
                "createdAt": "2026-07-12T00:00:00.000Z"
            })
        );
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

    /// `idType` round-trips, and a record without it (every pre-#246
    /// record) parses with `None` — which readers take as legacy row ids.
    #[test]
    fn read_state_id_type_round_trips_and_defaults_to_legacy() {
        let mut rs = ReadState::new("https://example.com/feed.xml", None, "2026-10-08T00:00:00Z");
        rs.id_type = Some(ReadState::ID_TYPE_GUID.to_string());
        rs.read_ids = vec!["12345".into()];
        let value = serde_json::to_value(&rs).expect("serialize");
        assert_eq!(value["idType"], "guid");
        assert_eq!(serde_json::from_value::<ReadState>(value).unwrap(), rs);

        let legacy: ReadState = serde_json::from_value(json!({
            "$type": "community.lexicon.rss.readState",
            "feedUrl": "https://example.com/feed.xml",
            "readIds": ["1"],
            "updatedAt": "2026-07-12T00:00:00Z",
        }))
        .expect("a legacy record parses");
        assert_eq!(legacy.id_type, None);
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

/// Deterministic orderings for the reader's record lists.
///
/// These live here, beside the types, and are used by **both** the sidecar
/// client and the Rust-native one. That is deliberate: the two clients coexist
/// until cutover, and a divergence in ordering would not be a subtle bug — it
/// would reorder the user's feed list the moment the implementation swapped, in
/// a way no test comparing the clients' *data* would catch.
pub mod sort {
    use super::{Folder, Saved, Subscription};
    use std::cmp::Ordering;

    /// Subscriptions: display title (case-insensitive), then URL, then rkey.
    ///
    /// An untitled feed sorts by its URL, so it lands where a reader would look
    /// for it rather than at one end of the list.
    pub fn subscriptions(
        (a_key, a): &(String, Subscription),
        (b_key, b): &(String, Subscription),
    ) -> Ordering {
        let a_title = a.title.as_deref().unwrap_or(&a.url).to_lowercase();
        let b_title = b.title.as_deref().unwrap_or(&b.url).to_lowercase();
        a_title
            .cmp(&b_title)
            .then_with(|| a.url.cmp(&b.url))
            .then_with(|| a_key.cmp(b_key))
    }

    /// Folders: `position` (the lexicon's sort hint; unset sorts LAST), then
    /// name (case-insensitive), then rkey.
    pub fn folders((a_key, a): &(String, Folder), (b_key, b): &(String, Folder)) -> Ordering {
        a.position
            .unwrap_or(u64::MAX)
            .cmp(&b.position.unwrap_or(u64::MAX))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a_key.cmp(b_key))
    }

    /// Saved entries: newest first by `createdAt` (RFC 3339 sorts
    /// lexicographically), then rkey ascending.
    pub fn saved((a_key, a): &(String, Saved), (b_key, b): &(String, Saved)) -> Ordering {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a_key.cmp(b_key))
    }
}

#[cfg(test)]
mod sort_tests {
    use super::sort;
    use super::{Folder, Saved, Subscription};

    fn sub(rkey: &str, url: &str, title: Option<&str>) -> (String, Subscription) {
        let mut s = Subscription::new(url, "2026-01-01T00:00:00Z");
        s.title = title.map(str::to_string);
        (rkey.to_string(), s)
    }

    fn folder(rkey: &str, name: &str, position: Option<u64>) -> (String, Folder) {
        let mut f = Folder::new(name, "2026-01-01T00:00:00Z");
        f.position = position;
        (rkey.to_string(), f)
    }

    fn saved(rkey: &str, url: &str, created_at: &str) -> (String, Saved) {
        (rkey.to_string(), Saved::new(url, created_at))
    }

    fn order<T>(
        mut items: Vec<(String, T)>,
        cmp: fn(&(String, T), &(String, T)) -> std::cmp::Ordering,
    ) -> Vec<String> {
        items.sort_by(cmp);
        items.into_iter().map(|(k, _)| k).collect()
    }

    /// Title first, and case must NOT split the alphabet.
    #[test]
    fn subscriptions_sort_by_title_case_insensitively() {
        let items = vec![
            sub("r1", "https://z.example/f", Some("banana")),
            sub("r2", "https://a.example/f", Some("Apple")),
            sub("r3", "https://m.example/f", Some("cherry")),
        ];
        assert_eq!(order(items, sort::subscriptions), ["r2", "r1", "r3"]);
    }

    /// An UNTITLED feed sorts by its URL, so it lands where a reader would look
    /// rather than being bunched at one end.
    #[test]
    fn an_untitled_subscription_sorts_by_its_url() {
        let items = vec![
            sub("r1", "https://zebra.example/f", Some("aardvark")),
            sub("r2", "https://bison.example/f", None),
        ];
        assert_eq!(order(items, sort::subscriptions), ["r1", "r2"]);
    }

    /// Equal titles fall to URL, then to rkey — so the order is TOTAL and a
    /// re-read cannot shuffle the list.
    #[test]
    fn subscriptions_break_ties_by_url_then_rkey() {
        let items = vec![
            sub("r2", "https://b.example/f", Some("same")),
            sub("r1", "https://b.example/f", Some("same")),
            sub("r3", "https://a.example/f", Some("same")),
        ];
        assert_eq!(order(items, sort::subscriptions), ["r3", "r1", "r2"]);
    }

    /// `position` is the lexicon's sort hint; an UNSET one sorts last rather
    /// than first, which `unwrap_or(0)` would have got backwards.
    #[test]
    fn folders_sort_by_position_with_unset_last() {
        let items = vec![
            folder("r1", "zulu", None),
            folder("r2", "alpha", Some(10)),
            folder("r3", "bravo", Some(2)),
        ];
        assert_eq!(order(items, sort::folders), ["r3", "r2", "r1"]);
    }

    #[test]
    fn folders_break_ties_by_name_then_rkey() {
        let items = vec![
            folder("r2", "Beta", Some(1)),
            folder("r1", "alpha", Some(1)),
            folder("r3", "alpha", Some(1)),
        ];
        assert_eq!(order(items, sort::folders), ["r1", "r3", "r2"]);
    }

    /// Saved entries read NEWEST FIRST -- the one ordering here that is
    /// descending, and the easiest to get backwards.
    #[test]
    fn saved_entries_are_newest_first() {
        let items = vec![
            saved("r1", "https://a.example/x", "2026-01-01T00:00:00Z"),
            saved("r2", "https://b.example/x", "2026-06-01T00:00:00Z"),
            saved("r3", "https://c.example/x", "2026-03-01T00:00:00Z"),
        ];
        assert_eq!(order(items, sort::saved), ["r2", "r3", "r1"]);
    }

    /// Same instant: rkey ASCENDING, even though the timestamp is descending.
    #[test]
    fn saved_entries_break_ties_by_ascending_rkey() {
        let items = vec![
            saved("r3", "https://c.example/x", "2026-01-01T00:00:00Z"),
            saved("r1", "https://a.example/x", "2026-01-01T00:00:00Z"),
            saved("r2", "https://b.example/x", "2026-01-01T00:00:00Z"),
        ];
        assert_eq!(order(items, sort::saved), ["r1", "r2", "r3"]);
    }
}

/// **The Lexicon JSON and the serde types cannot drift** (#287). Each record
/// type's full sample is serialized and checked against its JSON: every
/// emitted key is a declared property of the right type, every declared
/// property is emitted by the full sample, every `required` property is
/// present, and the caps and known values are the constants the code uses.
///
/// Plain `serde_json::Value` walking, no schema crate: the four files are
/// small and the checks are the ones that matter for this crate.
#[cfg(test)]
mod lexicon_json_tests {
    use super::*;
    use serde_json::{json, Value};

    const SUBSCRIPTION: &str = include_str!("../lexicons/community/lexicon/rss/subscription.json");
    const FOLDER: &str = include_str!("../lexicons/community/lexicon/rss/folder.json");
    const SAVED: &str = include_str!("../lexicons/community/lexicon/rss/saved.json");
    const READ_STATE: &str = include_str!("../lexicons/community/lexicon/rss/readState.json");

    /// The `record` object schema of a lexicon document, after checking its
    /// envelope: `lexicon: 1`, `id`, one `main` def of type `record`.
    fn record_schema(doc: &str, nsid: &str, key: &str) -> Value {
        let v: Value = serde_json::from_str(doc).expect("the lexicon file is JSON");
        assert_eq!(v["lexicon"], 1, "{nsid}: lexicon version");
        assert_eq!(v["id"], nsid, "{nsid}: id");
        let main = &v["defs"]["main"];
        assert_eq!(main["type"], "record", "{nsid}: defs.main.type");
        assert_eq!(main["key"], key, "{nsid}: defs.main.key");
        assert_eq!(
            v["defs"].as_object().map(|d| d.len()),
            Some(1),
            "{nsid}: exactly one def"
        );
        let record = main["record"].clone();
        assert_eq!(record["type"], "object", "{nsid}: record.type");
        record
    }

    /// The lexicon type name a serialized JSON value must be declared as.
    fn lexicon_type_of(v: &Value) -> &'static str {
        match v {
            Value::String(_) => "string",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "integer",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
            Value::Null => "null",
        }
    }

    /// `full` is a serialized record carrying EVERY field the Rust type can
    /// emit. Checks it against `schema` both ways.
    fn assert_matches(nsid: &str, schema: &Value, full: &Value) {
        let props = schema["properties"].as_object().expect("properties");
        let emitted = full.as_object().expect("a record is an object");
        for (key, value) in emitted {
            if key == "$type" {
                assert_eq!(value, nsid, "{nsid}: $type");
                continue;
            }
            let decl = props.get(key).unwrap_or_else(|| {
                panic!("{nsid}: the type emits `{key}`, the lexicon does not declare it")
            });
            assert_eq!(
                decl["type"],
                lexicon_type_of(value),
                "{nsid}.{key}: the lexicon declares a different type"
            );
            if let Some(items) = value.as_array() {
                for item in items {
                    assert_eq!(
                        decl["items"]["type"],
                        lexicon_type_of(item),
                        "{nsid}.{key}: item type"
                    );
                }
            }
        }
        for key in props.keys() {
            assert!(
                emitted.contains_key(key),
                "{nsid}: the lexicon declares `{key}`, the full sample does not emit it (field missing from the type, or skipped?)"
            );
        }
        for req in schema["required"].as_array().expect("required") {
            let req = req.as_str().unwrap();
            assert!(
                emitted.contains_key(req),
                "{nsid}: required `{req}` is not emitted"
            );
        }
    }

    /// A minimal record must emit exactly `$type` plus the required fields.
    fn assert_minimal(nsid: &str, schema: &Value, minimal: &Value) {
        let mut want: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        want.push("$type");
        want.sort_unstable();
        let mut got: Vec<&str> = minimal
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        got.sort_unstable();
        assert_eq!(
            got, want,
            "{nsid}: a minimal record emits more or less than the required fields"
        );
    }

    #[test]
    fn subscription_matches_its_lexicon() {
        let schema = record_schema(SUBSCRIPTION, nsid::SUBSCRIPTION, "tid");
        let mut full = Subscription::new("https://example.com/feed.xml", "2026-07-12T00:00:00Z");
        full.title = Some("Example".into());
        full.site_url = Some("https://example.com/".into());
        full.folder = Some("at://did:plc:abc/community.lexicon.rss.folder/3k".into());
        full.fetch_hint = Some(FetchHint::Hourly);
        full.private = Some(true);
        assert_matches(
            nsid::SUBSCRIPTION,
            &schema,
            &serde_json::to_value(&full).unwrap(),
        );
        let minimal = Subscription::new("https://example.com/feed.xml", "2026-07-12T00:00:00Z");
        assert_minimal(
            nsid::SUBSCRIPTION,
            &schema,
            &serde_json::to_value(&minimal).unwrap(),
        );

        // Every known fetchHint value is a variant the type names, and every
        // named variant is a known value.
        let known: Vec<&str> = schema["properties"]["fetchHint"]["knownValues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for value in &known {
            let hint: FetchHint = serde_json::from_value(json!(value)).unwrap();
            assert!(
                !matches!(hint, FetchHint::Other(_)),
                "fetchHint `{value}` is known to the lexicon but not to the type"
            );
        }
        for hint in [
            FetchHint::Realtime,
            FetchHint::Hourly,
            FetchHint::Daily,
            FetchHint::Weekly,
        ] {
            let value = serde_json::to_value(&hint).unwrap();
            assert!(
                known.contains(&value.as_str().unwrap()),
                "{value} is a variant the lexicon does not know"
            );
        }
    }

    #[test]
    fn folder_matches_its_lexicon() {
        let schema = record_schema(FOLDER, nsid::FOLDER, "tid");
        let mut full = Folder::new("Tech", "2026-07-12T00:00:00Z");
        full.position = Some(2);
        assert_matches(nsid::FOLDER, &schema, &serde_json::to_value(&full).unwrap());
        assert_minimal(
            nsid::FOLDER,
            &schema,
            &serde_json::to_value(Folder::new("Tech", "2026-07-12T00:00:00Z")).unwrap(),
        );
        assert_eq!(schema["properties"]["position"]["minimum"], 0);
    }

    #[test]
    fn saved_matches_its_lexicon() {
        let schema = record_schema(SAVED, nsid::SAVED, "tid");
        let mut full = Saved::new("https://example.com/post/1", "2026-07-12T00:00:00Z");
        full.title = Some("A kept post".into());
        full.feed_url = Some("https://example.com/feed.xml".into());
        full.entry_id = Some("tag:example.com,2026:1".into());
        assert_matches(nsid::SAVED, &schema, &serde_json::to_value(&full).unwrap());
        assert_minimal(
            nsid::SAVED,
            &schema,
            &serde_json::to_value(Saved::new(
                "https://example.com/post/1",
                "2026-07-12T00:00:00Z",
            ))
            .unwrap(),
        );
    }

    #[test]
    fn read_state_matches_its_lexicon() {
        let schema = record_schema(READ_STATE, nsid::READ_STATE, "any");
        let mut full = ReadState::new(
            "https://example.com/feed.xml",
            Some("2026-07-12T00:00:00Z".into()),
            "2026-07-12T01:00:00Z",
        );
        full.read_ids = vec!["a".into()];
        full.unread_ids = vec!["b".into()];
        full.id_type = Some(ReadState::ID_TYPE_GUID.into());
        assert_matches(
            nsid::READ_STATE,
            &schema,
            &serde_json::to_value(&full).unwrap(),
        );
        assert_minimal(
            nsid::READ_STATE,
            &schema,
            &serde_json::to_value(ReadState::new(
                "https://example.com/feed.xml",
                None,
                "2026-07-12T01:00:00Z",
            ))
            .unwrap(),
        );
        // The caps and the id type are the constants the flusher enforces.
        for set in ["readIds", "unreadIds"] {
            assert_eq!(
                schema["properties"][set]["maxLength"],
                ReadState::MAX_IDS,
                "{set}: the lexicon cap is not ReadState::MAX_IDS"
            );
        }
        assert_eq!(
            schema["properties"]["idType"]["knownValues"],
            json!([ReadState::ID_TYPE_GUID]),
            "idType: the lexicon's known values are not what the flusher writes"
        );
    }
}
