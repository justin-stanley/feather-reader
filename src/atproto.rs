//! The atproto identity + PDS record layer.
//!
//! FeatherReader's defining bet is that a user's feed
//! subscriptions, folders, saved items, and batched read-state live as records
//! in the user's **own** atproto PDS under the open `community.lexicon.rss.*`
//! community lexicon — not in the app's database. This module is the client that
//! reads and writes those records.
//!
//! It has three layers:
//!
//! 1. **Identity resolution** ([`resolve_handle`], [`resolve_did_to_pds`]) —
//!    turn a handle (`alice.example.com`) into a DID (`did:plc:…`), then resolve
//!    the DID document to the PDS service endpoint. Handles resolve via the
//!    account's PDS `com.atproto.identity.resolveHandle` (or the well-known
//!    `/.well-known/atproto-did`); DIDs resolve via the PLC directory
//!    (`did:plc:*`) or the `did:web` well-known document.
//! 2. **A lightweight [`PdsClient`]** — holds the resolved DID, the PDS base URL,
//!    and an [`Auth`] token, and exposes typed calls over `com.atproto.repo.*`:
//!    [`list_records`](PdsClient::list_records),
//!    [`create_record`](PdsClient::create_record),
//!    [`put_record`](PdsClient::put_record),
//!    [`delete_record`](PdsClient::delete_record), and
//!    [`apply_writes`](PdsClient::apply_writes) (the **batch** call the
//!    read-state flusher uses to coalesce many per-feed cursor writes into one
//!    round-trip).
//! 3. **Typed convenience wrappers** wired to the [`crate::lexicon`] record
//!    types (list/create [`Subscription`]/[`Folder`]/[`Saved`], put
//!    [`ReadState`], batch-flush many `ReadState` cursors).
//!
//! ## Auth — the OAuth sidecar is the live path
//!
//! Auth is a **trait/enum boundary** so the mechanism can vary without touching
//! call sites. There are two paths:
//!
//! * **The live path — the atproto OAuth confidential client, via [`SidecarClient`].**
//!   atproto OAuth (DPoP, PAR, token refresh) is fiddly and is **not** hand-rolled
//!   in Rust: it runs in a small, supported `@atproto/oauth-client-node` sidecar.
//!   The Rust server never holds
//!   PDS tokens — it POSTs every `com.atproto.repo.*` op to the sidecar's
//!   `/internal/repo` endpoint (gated by a shared `X-Internal-Secret`), and the
//!   sidecar restores the DID's OAuth session (transparent DPoP + token refresh)
//!   and runs the matching XRPC call. [`SidecarClient`] is that client; the typed
//!   convenience wrappers (list/create/put/delete subscriptions, batch-flush
//!   read-state) live on it and map 1:1 to the old [`PdsClient`] surface.
//! * **The interim path — [`Auth::Session`] (app password).** A session obtained
//!   from `com.atproto.server.createSession`. Kept behind the [`Auth`] seam as a
//!   fallback for local runs without the sidecar, but it is **no longer the live
//!   path**: [`PdsClient`] and [`login_with_app_password`] remain for tests and
//!   dev, while [`SidecarClient`] is what the web layer routes through.
//!
//! All network I/O is `reqwest` (rustls, no OpenSSL); every fallible path returns
//! [`anyhow::Result`] or the typed [`AtProtoError`] — nothing panics.

use std::sync::Arc;

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::lexicon::{self, Folder, ReadState, Saved, Subscription};

/// The public PLC directory, used to resolve `did:plc:*` DIDs to their DID
/// document (and thus their PDS service endpoint).
pub const DEFAULT_PLC_DIRECTORY: &str = "https://plc.directory";

/// The default appview/entryway used only as a bootstrap host for handle
/// resolution when the caller has no PDS hint yet. Handle resolution ultimately
/// works against any atproto host that implements
/// `com.atproto.identity.resolveHandle`; `bsky.social` is a reliable default.
pub const DEFAULT_RESOLVER_HOST: &str = "https://bsky.social";

/// Errors from the atproto identity + PDS layer.
///
/// Wraps the transport, the atproto XRPC error envelope (`{"error","message"}`),
/// and the identity-resolution failure modes so callers can distinguish "the
/// network broke" from "the PDS said no" from "this handle doesn't resolve".
#[derive(Debug, thiserror::Error)]
pub enum AtProtoError {
    /// The underlying HTTP transport failed (DNS, TLS, timeout, connect).
    #[error("atproto transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// The XRPC endpoint returned a non-2xx status with an atproto error
    /// envelope (or an opaque body). `error` is the atproto error name (e.g.
    /// `RecordNotFound`, `AuthMissing`), `message` the human string.
    #[error("atproto XRPC error {status}: {error}{}", .message.as_deref().map(|m| format!(" — {m}")).unwrap_or_default())]
    Xrpc {
        /// The HTTP status code.
        status: StatusCode,
        /// The atproto error name (the `error` field), or `"Unknown"`.
        error: String,
        /// The optional human-readable `message` field.
        message: Option<String>,
    },

    /// A handle could not be resolved to a DID.
    #[error("could not resolve handle {handle:?} to a DID")]
    HandleResolution {
        /// The handle that failed to resolve.
        handle: String,
    },

    /// A DID document could not be resolved, or lacks a usable PDS service
    /// endpoint (`#atproto_pds`).
    #[error("could not resolve DID {did:?} to a PDS endpoint: {reason}")]
    DidResolution {
        /// The DID that failed to resolve.
        did: String,
        /// Why resolution failed.
        reason: String,
    },
}

impl AtProtoError {
    /// True when the XRPC error is a "record not found" — handy for upsert paths
    /// that treat a missing record as "create instead of update".
    pub fn is_record_not_found(&self) -> bool {
        matches!(
            self,
            AtProtoError::Xrpc { error, .. } if error == "RecordNotFound"
        )
    }
}

// ---------------------------------------------------------------------------
// Auth — the direct-PDS path (dev / tests)
// ---------------------------------------------------------------------------

/// A source of atproto access tokens.
///
/// This trait abstracts over token acquisition for the direct [`PdsClient`]
/// (used by local runs and tests). A [`PdsClient`] can hold a `dyn TokenSource`
/// instead of a static [`Auth`] without any call-site change, so a token source
/// that refreshes out of band can be dropped in later.
///
/// It is async + `Send + Sync` so a background refresh can live behind it.
#[allow(async_fn_in_trait)]
pub trait TokenSource: Send + Sync {
    /// Return the current bearer access token to send as `Authorization`.
    async fn access_token(&self) -> Result<String>;
}

/// The auth material a [`PdsClient`] carries.
///
/// A small enum rather than a bare string, so the match stays exhaustive if a
/// second direct-auth mechanism is added alongside app-password sessions.
#[derive(Clone)]
pub enum Auth {
    /// A bearer access token from a `com.atproto.server.createSession`
    /// (app-password) session. This is the direct-PDS auth used by local runs
    /// and tests; the live web path authenticates via the OAuth sidecar instead
    /// (see [`SidecarClient`]).
    Session(SessionAuth),

    /// The atproto OAuth confidential-client path is handled entirely by the
    /// `@atproto/oauth-client` sidecar ([`SidecarClient`]), which mints, DPoP-binds,
    /// and refreshes tokens. The direct [`PdsClient`] does not carry OAuth tokens;
    /// this variant is a placeholder so the `Auth` enum documents that the OAuth
    /// path lives elsewhere.
    Oauth(OauthPlaceholder),
}

impl Auth {
    /// The bearer access token to present on `com.atproto.repo.*` calls.
    ///
    /// Only [`Auth::Session`] carries a token (the session's `accessJwt`).
    /// [`Auth::Oauth`] carries none — the sidecar owns the OAuth path — so it
    /// returns an error pointing callers at [`SidecarClient`].
    pub fn bearer(&self) -> Result<&str> {
        match self {
            Auth::Session(s) => Ok(&s.access_jwt),
            Auth::Oauth(_) => anyhow::bail!(
                "the direct PdsClient does not carry OAuth tokens — atproto OAuth is \
                 handled by the @atproto/oauth-client sidecar (SidecarClient); \
                 use Auth::Session (app-password) for the direct-PDS path"
            ),
        }
    }
}

/// A session obtained from `com.atproto.server.createSession` (interim
/// app-password auth). Holds the DID + tokens + handle the server returned.
#[derive(Clone, Debug, Deserialize)]
pub struct SessionAuth {
    /// The account DID this session authenticates.
    pub did: String,
    /// The account handle at session-creation time.
    #[serde(default)]
    pub handle: Option<String>,
    /// The bearer access token presented on authed XRPC calls.
    #[serde(rename = "accessJwt")]
    pub access_jwt: String,
    /// The refresh token, exchanged via `com.atproto.server.refreshSession`.
    /// The direct-PDS refresh flow is not implemented here; the live web path
    /// refreshes via the OAuth sidecar instead.
    #[serde(rename = "refreshJwt", default)]
    pub refresh_jwt: Option<String>,
}

/// Placeholder for the OAuth variant of [`Auth`].
///
/// Intentionally empty: the OAuth session material (DPoP key handle, token
/// references) is held entirely by the sidecar, not by the direct [`PdsClient`].
/// This type exists only so [`Auth::Oauth`] is a real variant and the split is
/// visible in the type system.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct OauthPlaceholder {}

// ---------------------------------------------------------------------------
// Identity resolution
// ---------------------------------------------------------------------------

/// Resolve an atproto handle to its DID.
///
/// Uses `com.atproto.identity.resolveHandle` against `resolver_base` (any host
/// that implements it; [`DEFAULT_RESOLVER_HOST`] is a safe bootstrap). A fuller
/// implementation would also try the DNS `_atproto` TXT record and the
/// `https://<handle>/.well-known/atproto-did` fallback; the XRPC path is the
/// common case and the one implemented here.
pub async fn resolve_handle(client: &Client, resolver_base: &str, handle: &str) -> Result<String> {
    // Build the query manually rather than via reqwest's `.query()` so we don't
    // depend on the optional `query`/`url` reqwest feature (the declared feature
    // set is rustls + gzip + json only).
    let url = format!(
        "{}/xrpc/com.atproto.identity.resolveHandle?handle={}",
        resolver_base.trim_end_matches('/'),
        urlencode(handle)
    );

    #[derive(Deserialize)]
    struct ResolveHandleOut {
        did: String,
    }

    // Route through the SSRF guard: `resolver_base` can be a user-influenced PDS
    // host (from a prior DID-doc resolution), so a hostile endpoint must not be
    // able to target loopback / link-local / metadata. Feed-privacy is NOT
    // applied here (this is a legitimate atproto XRPC call, not a feed fetch).
    let resp = crate::net::guarded_get_no_privacy(client, &url, &[]).await?;
    if !resp.status().is_success() {
        // Surface the XRPC envelope but map the common "not found" to the typed
        // handle-resolution error so callers get a clean signal.
        let err = xrpc_error_from(resp).await;
        if let AtProtoError::Xrpc { status, .. } = &err {
            if *status == StatusCode::BAD_REQUEST || *status == StatusCode::NOT_FOUND {
                return Err(AtProtoError::HandleResolution {
                    handle: handle.to_string(),
                }
                .into());
            }
        }
        return Err(err.into());
    }

    let out: ResolveHandleOut = resp
        .json()
        .await
        .context("parsing resolveHandle response")?;
    Ok(out.did)
}

/// Resolve a DID to its PDS service endpoint by fetching + parsing its DID
/// document.
///
/// * `did:plc:*` → the PLC directory (`{plc_directory}/{did}`).
/// * `did:web:host` → `https://host/.well-known/did.json`.
///
/// The PDS endpoint is the service in the DID doc whose `id` ends with
/// `#atproto_pds` (type `AtprotoPersonalDataServer`); its `serviceEndpoint` is
/// the base URL for all `com.atproto.repo.*` calls.
pub async fn resolve_did_to_pds(client: &Client, plc_directory: &str, did: &str) -> Result<String> {
    let doc_url = if let Some(rest) = did.strip_prefix("did:web:") {
        // did:web host may itself be percent-encoded / contain a path; the
        // common case is a bare host.
        let host = rest.replace(':', "/");
        format!("https://{host}/.well-known/did.json")
    } else if did.starts_with("did:plc:") {
        format!("{}/{}", plc_directory.trim_end_matches('/'), did)
    } else {
        return Err(AtProtoError::DidResolution {
            did: did.to_string(),
            reason: "unsupported DID method (only did:plc and did:web are handled)".to_string(),
        }
        .into());
    };

    // SSRF guard: `doc_url` is attacker-controllable for `did:web:<host>` (the
    // host comes straight from the DID) — a hostile `did:web:169.254.169.254`
    // or `did:web:localhost` would otherwise make the server fetch an internal
    // target and reflect its body. Route through the IP/scheme guard (no
    // feed-privacy layer — this is a DID document, not a feed).
    let resp = crate::net::guarded_get_no_privacy(client, &doc_url, &[]).await?;
    if !resp.status().is_success() {
        return Err(AtProtoError::DidResolution {
            did: did.to_string(),
            reason: format!("DID document fetch returned {}", resp.status()),
        }
        .into());
    }

    let doc: DidDocument = resp.json().await.context("parsing DID document")?;
    let endpoint = doc
        .pds_endpoint()
        .ok_or_else(|| AtProtoError::DidResolution {
            did: did.to_string(),
            reason: "DID document has no #atproto_pds service endpoint".to_string(),
        })?;

    // SSRF guard on the RESOLVED endpoint: the `serviceEndpoint` is fully
    // attacker-controlled (it's whatever the DID document says) and is handed to
    // XRPC clients that fetch it directly. Reject a private/loopback/metadata
    // target here so a hostile DID doc can't point the PDS at an internal host.
    crate::net::assert_public_target(&endpoint)
        .await
        .map_err(|e| AtProtoError::DidResolution {
            did: did.to_string(),
            reason: format!("PDS serviceEndpoint is not a public target: {e}"),
        })?;
    Ok(endpoint)
}

/// The subset of a DID document FeatherReader needs: its services, so it can
/// find the `#atproto_pds` endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct DidDocument {
    /// The document subject (the DID itself).
    #[serde(default)]
    pub id: String,
    /// The declared services; the PDS is the one whose `id` ends `#atproto_pds`.
    #[serde(default)]
    pub service: Vec<DidService>,
}

/// One service entry in a [`DidDocument`].
#[derive(Debug, Clone, Deserialize)]
pub struct DidService {
    /// The service id fragment (e.g. `#atproto_pds`).
    pub id: String,
    /// The service type (e.g. `AtprotoPersonalDataServer`).
    #[serde(rename = "type", default)]
    pub r#type: String,
    /// The service base URL.
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

impl DidDocument {
    /// The `#atproto_pds` service endpoint, if present.
    pub fn pds_endpoint(&self) -> Option<String> {
        self.service
            .iter()
            .find(|s| s.id.ends_with("#atproto_pds"))
            .map(|s| s.service_endpoint.trim_end_matches('/').to_string())
    }
}

// ---------------------------------------------------------------------------
// Direct-PDS auth: app-password session
// ---------------------------------------------------------------------------

/// Create a session with an **app password** via
/// `com.atproto.server.createSession`.
///
/// This is the direct-PDS path that makes [`PdsClient`] usable without the OAuth
/// sidecar (local runs and tests). `pds_base` is the account's PDS (resolve it
/// first with [`resolve_handle`] + [`resolve_did_to_pds`], or pass the entryway
/// like `https://bsky.social`, which will service-proxy). `identifier` is a
/// handle or DID; `app_password` is an app-password (never the main password).
pub async fn login_with_app_password(
    client: &Client,
    pds_base: &str,
    identifier: &str,
    app_password: &str,
) -> Result<SessionAuth> {
    let url = format!(
        "{}/xrpc/com.atproto.server.createSession",
        pds_base.trim_end_matches('/')
    );
    let resp = client
        .post(&url)
        .json(&json!({ "identifier": identifier, "password": app_password }))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(xrpc_error_from(resp).await.into());
    }
    let session: SessionAuth = resp
        .json()
        .await
        .context("parsing createSession response")?;
    Ok(session)
}

// ---------------------------------------------------------------------------
// The PDS client
// ---------------------------------------------------------------------------

/// A lightweight client for one user's PDS repo.
///
/// Holds the user's DID (the repo to read/write), the PDS base URL (resolved
/// from the DID doc), the shared [`reqwest::Client`], and the [`Auth`] token.
/// All the `com.atproto.repo.*` methods below act on `self.did`'s repo.
///
/// Cheap to clone (`Arc` internals); one is held per logged-in session.
#[derive(Clone)]
pub struct PdsClient {
    http: Client,
    /// The PDS base URL, e.g. `https://pds.example.com` (no trailing slash).
    pds_base: Arc<str>,
    /// The repo DID all calls target.
    did: Arc<str>,
    /// The auth material (an app-password session bearer for the direct path).
    auth: Auth,
}

/// A single record as returned in a `listRecords` / `getRecord` response.
///
/// `value` is the raw record body (with its `$type`); typed wrappers
/// deserialize it into the matching [`crate::lexicon`] struct.
#[derive(Debug, Clone, Deserialize)]
pub struct RecordEntry {
    /// The `at://did/collection/rkey` strong ref to this record.
    pub uri: String,
    /// The record CID (content hash).
    #[serde(default)]
    pub cid: Option<String>,
    /// The raw record body.
    pub value: Value,
}

impl RecordEntry {
    /// The record key (the last `/`-segment of the `at://` URI).
    pub fn rkey(&self) -> Option<&str> {
        self.uri.rsplit('/').next()
    }

    /// Deserialize this record's `value` into a typed lexicon record.
    pub fn parse<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(self.value.clone())
            .with_context(|| format!("deserializing record {}", self.uri))
    }
}

/// The `com.atproto.repo.listRecords` response envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct ListRecordsResponse {
    /// The page of records.
    #[serde(default)]
    pub records: Vec<RecordEntry>,
    /// The opaque pagination cursor for the next page, if any.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// The `com.atproto.repo.createRecord` / `putRecord` response (a strong ref to
/// the written record).
#[derive(Debug, Clone, Deserialize)]
pub struct WriteResult {
    /// The `at://` URI of the written record.
    pub uri: String,
    /// The record CID after the write.
    #[serde(default)]
    pub cid: Option<String>,
}

impl WriteResult {
    /// The record key — the last `/`-segment of the `at://` URI.
    ///
    /// The reader-facing `add_*` wrappers return this so the web layer can
    /// address the freshly-created record (delete/rename) without a re-list.
    pub fn rkey(&self) -> Option<&str> {
        self.uri.rsplit('/').next()
    }

    /// The record key as an owned `String`, or the empty string if the URI is
    /// somehow segment-less (never in practice — a PDS always returns an
    /// `at://did/collection/rkey`). Convenience for the `-> rkey` wrappers.
    pub fn into_rkey(self) -> String {
        self.rkey().unwrap_or_default().to_string()
    }
}

impl PdsClient {
    /// Construct a client against an already-resolved PDS base + DID + auth.
    pub fn new(
        http: Client,
        pds_base: impl Into<String>,
        did: impl Into<String>,
        auth: Auth,
    ) -> Self {
        Self {
            http,
            pds_base: Arc::from(pds_base.into().trim_end_matches('/')),
            did: Arc::from(did.into()),
            auth,
        }
    }

    /// Resolve `handle` → DID → PDS, obtain an app-password session, and build a
    /// ready-to-use client. A convenience constructor for the direct-PDS path
    /// that exercises the whole stack end-to-end.
    ///
    /// `resolver_base` / `plc_directory` default to [`DEFAULT_RESOLVER_HOST`] /
    /// [`DEFAULT_PLC_DIRECTORY`] when passed `None`.
    pub async fn login(
        http: Client,
        handle: &str,
        app_password: &str,
        resolver_base: Option<&str>,
        plc_directory: Option<&str>,
    ) -> Result<Self> {
        let resolver = resolver_base.unwrap_or(DEFAULT_RESOLVER_HOST);
        let plc = plc_directory.unwrap_or(DEFAULT_PLC_DIRECTORY);

        let did = resolve_handle(&http, resolver, handle).await?;
        let pds_base = resolve_did_to_pds(&http, plc, &did).await?;
        let session = login_with_app_password(&http, &pds_base, &did, app_password).await?;

        Ok(Self::new(
            http,
            pds_base,
            session.did.clone(),
            Auth::Session(session),
        ))
    }

    /// The repo DID this client targets.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The PDS base URL this client talks to.
    pub fn pds_base(&self) -> &str {
        &self.pds_base
    }

    /// Build the `Authorization: Bearer …` + JSON headers for an authed call.
    fn authed_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let bearer = self.auth.bearer()?;
        let mut value = HeaderValue::from_str(&format!("Bearer {bearer}"))
            .context("building Authorization header")?;
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
        Ok(headers)
    }

    fn xrpc_url(&self, method: &str) -> String {
        format!("{}/xrpc/{}", self.pds_base, method)
    }

    // -- com.atproto.repo.* --------------------------------------------------

    /// `com.atproto.repo.listRecords` — one page of a collection's records.
    ///
    /// `cursor` continues a previous page; `limit` caps the page (atproto's max
    /// is 100). Use [`list_all_records`](Self::list_all_records) to page fully.
    pub async fn list_records(
        &self,
        collection: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<ListRecordsResponse> {
        // Build the query manually (see `resolve_handle`): no reqwest `query`
        // feature dependency.
        let mut url = format!(
            "{}?repo={}&collection={}",
            self.xrpc_url("com.atproto.repo.listRecords"),
            urlencode(&self.did),
            urlencode(collection),
        );
        if let Some(limit) = limit {
            url.push_str(&format!("&limit={limit}"));
        }
        if let Some(cursor) = cursor {
            url.push_str(&format!("&cursor={}", urlencode(cursor)));
        }

        // listRecords is public/unauthenticated on most PDSes, but we send the
        // bearer when we have a session one so private repos work too.
        let mut req = self.http.get(&url);
        if let Auth::Session(s) = &self.auth {
            req = req.bearer_auth(&s.access_jwt);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(xrpc_error_from(resp).await.into());
        }
        resp.json().await.context("parsing listRecords response")
    }

    /// Page through **all** records in a collection, following the cursor until
    /// exhausted. Convenience over [`list_records`](Self::list_records) for the
    /// login-time "load the whole follow-list" read.
    pub async fn list_all_records(&self, collection: &str) -> Result<Vec<RecordEntry>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .list_records(collection, Some(100), cursor.as_deref())
                .await?;
            let got = page.records.len();
            out.extend(page.records);
            match page.cursor {
                // Guard against a PDS that echoes a cursor with an empty page.
                Some(next) if got > 0 => cursor = Some(next),
                _ => break,
            }
        }
        Ok(out)
    }

    /// `com.atproto.repo.createRecord` — create a new record (server assigns the
    /// rkey, `key: tid`). Returns the written record's strong ref.
    pub async fn create_record<T: Serialize>(
        &self,
        collection: &str,
        record: &T,
    ) -> Result<WriteResult> {
        let body = json!({
            "repo": self.did.as_ref(),
            "collection": collection,
            "record": record,
        });
        self.repo_write("com.atproto.repo.createRecord", body).await
    }

    /// `com.atproto.repo.putRecord` — upsert a record at a **known** rkey
    /// (`key: any`). This is the `readState` upsert primitive: a feed-derived
    /// rkey makes the write idempotent (one record per feed).
    pub async fn put_record<T: Serialize>(
        &self,
        collection: &str,
        rkey: &str,
        record: &T,
    ) -> Result<WriteResult> {
        let body = json!({
            "repo": self.did.as_ref(),
            "collection": collection,
            "rkey": rkey,
            "record": record,
        });
        self.repo_write("com.atproto.repo.putRecord", body).await
    }

    /// `com.atproto.repo.deleteRecord` — delete a record by collection + rkey
    /// (e.g. unsubscribe → delete the subscription record).
    pub async fn delete_record(&self, collection: &str, rkey: &str) -> Result<()> {
        let url = self.xrpc_url("com.atproto.repo.deleteRecord");
        let body = json!({
            "repo": self.did.as_ref(),
            "collection": collection,
            "rkey": rkey,
        });
        let resp = self
            .http
            .post(&url)
            .headers(self.authed_headers()?)
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(xrpc_error_from(resp).await.into());
        }
        Ok(())
    }

    /// `com.atproto.repo.applyWrites` — a **batch** of create/update/delete
    /// operations in one atomic-per-repo round-trip.
    ///
    /// This is the read-state flusher's workhorse: dozens of dirty per-feed
    /// [`ReadState`] cursors coalesce into one call rather than one `putRecord`
    /// each. See [`flush_read_states`](Self::flush_read_states).
    pub async fn apply_writes(&self, writes: &[WriteOp]) -> Result<()> {
        let url = self.xrpc_url("com.atproto.repo.applyWrites");
        let ops: Vec<Value> = writes.iter().map(WriteOp::to_json).collect();
        let body = json!({
            "repo": self.did.as_ref(),
            "writes": ops,
        });
        let resp = self
            .http
            .post(&url)
            .headers(self.authed_headers()?)
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(xrpc_error_from(resp).await.into());
        }
        Ok(())
    }

    /// Shared create/put path (both return a `{uri,cid}` strong ref).
    async fn repo_write(&self, method: &str, body: Value) -> Result<WriteResult> {
        let url = self.xrpc_url(method);
        let resp = self
            .http
            .post(&url)
            .headers(self.authed_headers()?)
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(xrpc_error_from(resp).await.into());
        }
        resp.json()
            .await
            .with_context(|| format!("parsing {method} response"))
    }

    // -- typed lexicon wrappers ---------------------------------------------

    /// List every [`Subscription`] record in the user's repo (paged fully). The
    /// login-time "what does this user follow?" read.
    pub async fn list_subscriptions(&self) -> Result<Vec<(String, Subscription)>> {
        self.list_typed(lexicon::nsid::SUBSCRIPTION).await
    }

    /// Create a [`Subscription`] record (subscribe to a feed).
    pub async fn create_subscription(&self, sub: &Subscription) -> Result<WriteResult> {
        self.create_record(lexicon::nsid::SUBSCRIPTION, sub).await
    }

    /// List every [`Folder`] record in the user's repo.
    pub async fn list_folders(&self) -> Result<Vec<(String, Folder)>> {
        self.list_typed(lexicon::nsid::FOLDER).await
    }

    /// Create a [`Folder`] record.
    pub async fn create_folder(&self, folder: &Folder) -> Result<WriteResult> {
        self.create_record(lexicon::nsid::FOLDER, folder).await
    }

    /// List every [`Saved`] (starred) record in the user's repo.
    pub async fn list_saved(&self) -> Result<Vec<(String, Saved)>> {
        self.list_typed(lexicon::nsid::SAVED).await
    }

    /// Create a [`Saved`] record (star an article).
    pub async fn create_saved(&self, saved: &Saved) -> Result<WriteResult> {
        self.create_record(lexicon::nsid::SAVED, saved).await
    }

    /// List every [`ReadState`] cursor in the user's repo (the read side a
    /// login-time read-state merge would consume).
    pub async fn list_read_states(&self) -> Result<Vec<(String, ReadState)>> {
        self.list_typed(lexicon::nsid::READ_STATE).await
    }

    /// Upsert a single [`ReadState`] cursor at its feed-derived rkey. For a
    /// batch of dirty cursors prefer [`flush_read_states`](Self::flush_read_states).
    pub async fn put_read_state(&self, rkey: &str, state: &ReadState) -> Result<WriteResult> {
        self.put_record(lexicon::nsid::READ_STATE, rkey, state)
            .await
    }

    /// Batch-flush many dirty [`ReadState`] cursors in one `applyWrites` call —
    /// the debounced read-state flusher's coalesced write.
    ///
    /// Each `(rkey, state, pds_created)` becomes a `create` op at the feed-derived
    /// rkey when the record does not yet exist, and an `update` when it does — so a
    /// feed's FIRST flush succeeds (an `#update` on a missing record errors, and
    /// `applyWrites` is atomic per-repo). Both kinds ride the same batch.
    pub async fn flush_read_states(&self, cursors: &[(String, ReadState, bool)]) -> Result<()> {
        if cursors.is_empty() {
            return Ok(());
        }
        let writes = read_state_write_ops(cursors)?;
        self.apply_writes(&writes).await
    }

    /// List a collection and parse each record's value into `T`, pairing it with
    /// its rkey. Records that fail to deserialize are skipped with a warning
    /// (forward-compat: a future writer's extra fields shouldn't break login).
    async fn list_typed<T: DeserializeOwned>(&self, collection: &str) -> Result<Vec<(String, T)>> {
        let records = self.list_all_records(collection).await?;
        let mut out = Vec::with_capacity(records.len());
        for rec in records {
            let rkey = rec.rkey().unwrap_or_default().to_string();
            match rec.parse::<T>() {
                Ok(value) => out.push((rkey, value)),
                Err(e) => tracing::warn!(
                    collection,
                    uri = %rec.uri,
                    error = %e,
                    "skipping unparseable record in collection"
                ),
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// The OAuth sidecar client — the LIVE com.atproto.repo.* path
// ---------------------------------------------------------------------------

/// A client for the atproto OAuth sidecar's **internal** API.
///
/// This is the live path for every authed repo operation. Rather than the Rust
/// server holding PDS tokens, it POSTs `{did, action, …}` to the sidecar's
/// `/internal/repo` endpoint (gated by the shared `X-Internal-Secret`); the
/// sidecar `restore(did)`s the OAuth session — transparent DPoP + token refresh —
/// and runs the matching XRPC call via `@atproto/api`. The `did` (plus the shared
/// secret) is what authorizes the call; there is no bearer token on the Rust side.
///
/// It also fronts `/internal/session/:id`, the one-shot handoff the Rust callback
/// uses to turn a `session_id` (from the sidecar's browser redirect) into the
/// `{did, handle}` it keys its own signed cookie by.
///
/// Cheap to clone (shared `reqwest::Client` + `Arc`'d config).
#[derive(Clone)]
pub struct SidecarClient {
    http: Client,
    public_url: Arc<str>,
    internal_url: Arc<str>,
    internal_secret: Arc<str>,
}

/// The `{did, handle}` a session-id resolves to (the sidecar's
/// `/internal/session/:id` body).
#[derive(Debug, Clone, Deserialize)]
pub struct SidecarSession {
    /// The account DID that logged in.
    pub did: String,
    /// The account handle at login time.
    #[serde(default)]
    pub handle: Option<String>,
}

/// The sidecar's `/internal/revoke` response body:
/// `{ ok:true, did, revoked, hadSession }`.
#[derive(Debug, Clone, Deserialize)]
pub struct RevokeResult {
    /// The DID that was revoked.
    #[serde(default)]
    pub did: String,
    /// Whether the OAuth token revocation at the PDS succeeded. `false` means
    /// the local rows were still purged (best-effort), but the PDS-side tokens
    /// may not have been invalidated (network failure).
    #[serde(default)]
    pub revoked: bool,
    /// Whether the sidecar actually had a stored session for the DID.
    #[serde(default, rename = "hadSession")]
    pub had_session: bool,
}

/// The action verbs the sidecar's `/internal/repo` endpoint dispatches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoAction {
    /// `com.atproto.repo.listRecords`.
    List,
    /// `com.atproto.repo.createRecord`.
    Create,
    /// `com.atproto.repo.putRecord`.
    Put,
    /// `com.atproto.repo.deleteRecord`.
    Delete,
    /// `com.atproto.repo.applyWrites` (batch).
    ApplyWrites,
}

impl RepoAction {
    fn as_str(self) -> &'static str {
        match self {
            RepoAction::List => "list",
            RepoAction::Create => "create",
            RepoAction::Put => "put",
            RepoAction::Delete => "delete",
            RepoAction::ApplyWrites => "applyWrites",
        }
    }
}

/// The `/internal/repo` success envelope: `{ ok:true, data:<raw XRPC JSON> }`.
#[derive(Debug, Deserialize)]
struct RepoOk {
    #[serde(default)]
    data: Value,
}

/// The `/internal/repo` error envelope: `{ ok:false, error, message, status? }`.
#[derive(Debug, Deserialize)]
struct RepoErr {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    status: Option<u16>,
}

impl SidecarClient {
    /// Build a sidecar client from the shared [`reqwest::Client`] and the
    /// resolved public + internal base URLs + internal secret (from
    /// [`crate::config::SidecarConfig`]). `public_url` anchors the browser
    /// `/login` redirect; `internal_url` is the loopback base for the `/internal/*`
    /// API (they collapse to the same value in single-URL local dev).
    pub fn new(
        http: Client,
        public_url: impl Into<String>,
        internal_url: impl Into<String>,
        internal_secret: impl Into<String>,
    ) -> Self {
        Self {
            http,
            public_url: Arc::from(public_url.into().trim_end_matches('/')),
            internal_url: Arc::from(internal_url.into().trim_end_matches('/')),
            internal_secret: Arc::from(internal_secret.into()),
        }
    }

    /// The sidecar's public `/login` URL for a handle, round-tripping an opaque
    /// `return` value through OAuth state (used to bounce the browser back to a
    /// specific place after login). The browser is redirected here.
    pub fn login_url(&self, handle: &str, return_to: Option<&str>) -> String {
        let mut url = format!("{}/login?handle={}", self.public_url, urlencode(handle));
        if let Some(r) = return_to {
            url.push_str(&format!("&return={}", urlencode(r)));
        }
        url
    }

    /// Resolve a one-shot `session_id` (from the sidecar's post-OAuth redirect)
    /// to the `{did, handle}` that logged in. `Ok(None)` on `404 SessionNotFound`.
    pub async fn resolve_session(&self, session_id: &str) -> Result<Option<SidecarSession>> {
        let url = format!(
            "{}/internal/session/{}",
            self.internal_url,
            urlencode(session_id)
        );
        let resp = self
            .http
            .get(&url)
            .header("X-Internal-Secret", self.internal_secret.as_ref())
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(xrpc_error_from(resp).await.into());
        }
        let session: SidecarSession = resp
            .json()
            .await
            .context("parsing /internal/session response")?;
        Ok(Some(session))
    }

    /// Revoke a DID's OAuth session at the sidecar: `POST /internal/revoke`.
    ///
    /// This revokes the refresh + access tokens at the PDS **and** purges the
    /// sidecar's stored `oauth_session` + `app_session` rows for the DID. It is
    /// idempotent — revoking a DID with no live session returns
    /// `had_session: false`. Called on `/logout` (so the cookie clear isn't the
    /// only thing that ends the session) and on `/account/delete`.
    pub async fn revoke_session(&self, did: &str) -> Result<RevokeResult> {
        let url = format!("{}/internal/revoke", self.internal_url);
        let resp = self
            .http
            .post(&url)
            .header("X-Internal-Secret", self.internal_secret.as_ref())
            .json(&json!({ "did": did }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(xrpc_error_from(resp).await.into());
        }
        let result: RevokeResult = resp
            .json()
            .await
            .context("parsing /internal/revoke response")?;
        Ok(result)
    }

    /// POST one op to `/internal/repo` and return the raw XRPC `data` payload.
    ///
    /// `body` must already carry `did` + `action` + the action's required fields
    /// (the typed wrappers below build these). Maps the sidecar's error envelope
    /// to [`AtProtoError`]: `404 SessionNotFound` → `Xrpc{error:"SessionNotFound"}`
    /// so callers can treat it as "re-login required".
    async fn repo(&self, body: Value) -> Result<Value> {
        let url = format!("{}/internal/repo", self.internal_url);
        let resp = self
            .http
            .post(&url)
            .header("X-Internal-Secret", self.internal_secret.as_ref())
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            let ok: RepoOk = resp
                .json()
                .await
                .context("parsing /internal/repo ok body")?;
            return Ok(ok.data);
        }
        // Error path: parse the sidecar's `{ok:false,error,message,status}` shape.
        let err: RepoErr = resp.json().await.unwrap_or(RepoErr {
            error: None,
            message: None,
            status: None,
        });
        let mapped = err
            .status
            .and_then(|s| StatusCode::from_u16(s).ok())
            .unwrap_or(status);
        Err(AtProtoError::Xrpc {
            status: mapped,
            error: err.error.unwrap_or_else(|| "Unknown".to_string()),
            message: err.message,
        }
        .into())
    }

    // -- raw com.atproto.repo.* over the sidecar -----------------------------

    /// `list` — one page of a collection's records for `did`.
    pub async fn list_records(
        &self,
        did: &str,
        collection: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<ListRecordsResponse> {
        let mut body = json!({
            "did": did,
            "action": RepoAction::List.as_str(),
            "collection": collection,
        });
        if let Some(limit) = limit {
            body["limit"] = json!(limit);
        }
        if let Some(cursor) = cursor {
            body["cursor"] = json!(cursor);
        }
        let data = self.repo(body).await?;
        serde_json::from_value(data).context("parsing sidecar listRecords data")
    }

    /// Page through **all** records in a collection for `did`.
    pub async fn list_all_records(&self, did: &str, collection: &str) -> Result<Vec<RecordEntry>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .list_records(did, collection, Some(100), cursor.as_deref())
                .await?;
            let got = page.records.len();
            out.extend(page.records);
            match page.cursor {
                Some(next) if got > 0 => cursor = Some(next),
                _ => break,
            }
        }
        Ok(out)
    }

    /// `create` — create a record (server-assigned rkey). Returns its strong ref.
    pub async fn create_record<T: Serialize>(
        &self,
        did: &str,
        collection: &str,
        record: &T,
    ) -> Result<WriteResult> {
        let body = json!({
            "did": did,
            "action": RepoAction::Create.as_str(),
            "collection": collection,
            "record": record,
        });
        let data = self.repo(body).await?;
        serde_json::from_value(data).context("parsing sidecar createRecord data")
    }

    /// `put` — upsert a record at a known rkey. Returns its strong ref.
    pub async fn put_record<T: Serialize>(
        &self,
        did: &str,
        collection: &str,
        rkey: &str,
        record: &T,
    ) -> Result<WriteResult> {
        let body = json!({
            "did": did,
            "action": RepoAction::Put.as_str(),
            "collection": collection,
            "rkey": rkey,
            "record": record,
        });
        let data = self.repo(body).await?;
        serde_json::from_value(data).context("parsing sidecar putRecord data")
    }

    /// `delete` — delete a record by collection + rkey.
    pub async fn delete_record(&self, did: &str, collection: &str, rkey: &str) -> Result<()> {
        let body = json!({
            "did": did,
            "action": RepoAction::Delete.as_str(),
            "collection": collection,
            "rkey": rkey,
        });
        self.repo(body).await?;
        Ok(())
    }

    /// `applyWrites` — a batch of create/update/delete ops in one round-trip.
    pub async fn apply_writes(&self, did: &str, writes: &[WriteOp]) -> Result<()> {
        if writes.is_empty() {
            return Ok(());
        }
        let ops: Vec<Value> = writes.iter().map(WriteOp::to_sidecar_json).collect();
        let body = json!({
            "did": did,
            "action": RepoAction::ApplyWrites.as_str(),
            "writes": ops,
        });
        self.repo(body).await?;
        Ok(())
    }

    // -- typed lexicon wrappers (mirror the old PdsClient surface) ------------

    /// List every [`Subscription`] record in `did`'s repo (paged fully).
    pub async fn list_subscriptions(&self, did: &str) -> Result<Vec<(String, Subscription)>> {
        self.list_typed(did, lexicon::nsid::SUBSCRIPTION).await
    }

    /// Create a [`Subscription`] record (subscribe to a feed).
    pub async fn create_subscription(&self, did: &str, sub: &Subscription) -> Result<WriteResult> {
        self.create_record(did, lexicon::nsid::SUBSCRIPTION, sub)
            .await
    }

    /// Delete a [`Subscription`] record by rkey (unsubscribe).
    pub async fn delete_subscription(&self, did: &str, rkey: &str) -> Result<()> {
        self.delete_record(did, lexicon::nsid::SUBSCRIPTION, rkey)
            .await
    }

    /// Batch-create many [`Subscription`] records in one `applyWrites` — the OPML
    /// import path (one create op per feed, server-assigned rkeys).
    pub async fn create_subscriptions_batch(&self, did: &str, subs: &[Subscription]) -> Result<()> {
        let writes: Vec<WriteOp> = subs
            .iter()
            .map(|sub| {
                Ok(WriteOp::Create {
                    collection: lexicon::nsid::SUBSCRIPTION.to_string(),
                    rkey: None,
                    value: serde_json::to_value(sub)?,
                })
            })
            .collect::<Result<_>>()?;
        self.apply_writes(did, &writes).await
    }

    /// List every [`Folder`] record in `did`'s repo.
    pub async fn list_folders(&self, did: &str) -> Result<Vec<(String, Folder)>> {
        self.list_typed(did, lexicon::nsid::FOLDER).await
    }

    /// List every [`Saved`] record in `did`'s repo.
    pub async fn list_saved(&self, did: &str) -> Result<Vec<(String, Saved)>> {
        self.list_typed(did, lexicon::nsid::SAVED).await
    }

    /// List every [`ReadState`] cursor in `did`'s repo (the read side a
    /// login-time read-state merge would consume).
    pub async fn list_read_states(&self, did: &str) -> Result<Vec<(String, ReadState)>> {
        self.list_typed(did, lexicon::nsid::READ_STATE).await
    }

    /// Upsert a single [`ReadState`] cursor at its feed-derived rkey.
    pub async fn put_read_state(
        &self,
        did: &str,
        rkey: &str,
        state: &ReadState,
    ) -> Result<WriteResult> {
        self.put_record(did, lexicon::nsid::READ_STATE, rkey, state)
            .await
    }

    /// Batch-flush many dirty [`ReadState`] cursors in one `applyWrites` call.
    ///
    /// Each `(rkey, state, pds_created)` becomes a `create` op at the feed-derived
    /// rkey when the record does NOT yet exist (`pds_created == false`), and an
    /// `update` op when it does. This is what makes the FIRST flush of a feed
    /// succeed: `applyWrites#update` errors on a record that does not pre-exist,
    /// and `applyWrites` is atomic per-repo, so a single not-yet-created cursor
    /// would otherwise drop the whole DID batch. Both kinds ride the SAME
    /// `applyWrites` batch so batching is preserved.
    pub async fn flush_read_states(
        &self,
        did: &str,
        cursors: &[(String, ReadState, bool)],
    ) -> Result<()> {
        if cursors.is_empty() {
            return Ok(());
        }
        let writes = read_state_write_ops(cursors)?;
        self.apply_writes(did, &writes).await
    }

    // -- reader-facing record CRUD (the surface the web layer calls) ----------
    //
    // These are the typed convenience methods `web.rs` uses to manage a user's
    // feeds/folders/saved items *as records in their PDS*. They mirror the
    // create/list surface above but use the reader vocabulary
    // (add/remove/rename) and, for the `add_*` verbs, return the server-assigned
    // rkey so the caller can address the new record without a re-list. Ordering
    // is made deterministic where it matters (see [`list_subscriptions_sorted`]
    // etc.) so the server-rendered HTML is stable between reads.

    // -- subscriptions -------------------------------------------------------

    /// Add a subscription (subscribe to a feed) — `createRecord`, server-assigned
    /// `tid` rkey. Returns the new record's **rkey** so the web layer can offer
    /// unsubscribe/rename immediately.
    pub async fn add_subscription(&self, did: &str, sub: &Subscription) -> Result<String> {
        Ok(self.create_subscription(did, sub).await?.into_rkey())
    }

    /// Remove a subscription (unsubscribe) by rkey — `deleteRecord`. Alias of
    /// [`delete_subscription`](Self::delete_subscription) in the reader vocabulary.
    pub async fn remove_subscription(&self, did: &str, rkey: &str) -> Result<()> {
        self.delete_subscription(did, rkey).await
    }

    /// Update / rename a subscription in place at a known rkey — `putRecord`.
    ///
    /// The whole record is replaced (retitle, move to a folder, change the
    /// fetch hint …). Upsert semantics: it also creates the record if the rkey
    /// is somehow absent, so it is safe as a general "write this exact record".
    pub async fn update_subscription(
        &self,
        did: &str,
        rkey: &str,
        sub: &Subscription,
    ) -> Result<WriteResult> {
        self.put_record(did, lexicon::nsid::SUBSCRIPTION, rkey, sub)
            .await
    }

    /// List every subscription, **sorted deterministically** — by display title
    /// (case-insensitive), then feed URL, then rkey as the final tiebreaker — so
    /// the rendered feed list is stable across reads regardless of PDS return
    /// order. Untitled feeds sort by their URL.
    pub async fn list_subscriptions_sorted(
        &self,
        did: &str,
    ) -> Result<Vec<(String, Subscription)>> {
        let mut subs = self.list_subscriptions(did).await?;
        subs.sort_by(|(a_key, a), (b_key, b)| {
            let a_title = a.title.as_deref().unwrap_or(&a.url).to_lowercase();
            let b_title = b.title.as_deref().unwrap_or(&b.url).to_lowercase();
            a_title
                .cmp(&b_title)
                .then_with(|| a.url.cmp(&b.url))
                .then_with(|| a_key.cmp(b_key))
        });
        Ok(subs)
    }

    /// Batch-add many subscriptions in one `applyWrites` — the OPML-import path.
    ///
    /// Each feed becomes one `create` op. Client-side monotonic [`tid`](tid)
    /// rkeys are assigned so the batch is deterministic and the imported feeds
    /// keep OPML order (server-assigned tids would also be monotonic, but pinning
    /// them here makes the whole import reproducible and testable offline).
    /// Returns the assigned rkeys in input order.
    pub async fn add_subscriptions_bulk(
        &self,
        did: &str,
        subs: &[Subscription],
    ) -> Result<Vec<String>> {
        let mut gen = TidGenerator::new();
        let mut rkeys = Vec::with_capacity(subs.len());
        let mut writes = Vec::with_capacity(subs.len());
        for sub in subs {
            let rkey = gen.next();
            writes.push(WriteOp::Create {
                collection: lexicon::nsid::SUBSCRIPTION.to_string(),
                rkey: Some(rkey.clone()),
                value: serde_json::to_value(sub)?,
            });
            rkeys.push(rkey);
        }
        self.apply_writes(did, &writes).await?;
        Ok(rkeys)
    }

    // -- folders -------------------------------------------------------------

    /// Add a folder — `createRecord`, server-assigned `tid` rkey. Returns the
    /// new folder's rkey (subscriptions reference it by its `at://` URI).
    pub async fn add_folder(&self, did: &str, folder: &Folder) -> Result<String> {
        Ok(self
            .create_record(did, lexicon::nsid::FOLDER, folder)
            .await?
            .into_rkey())
    }

    /// Remove a folder by rkey — `deleteRecord`. (Subscriptions referencing it
    /// are left untouched; a dangling `folder` ref reads as "unfiled".)
    pub async fn remove_folder(&self, did: &str, rkey: &str) -> Result<()> {
        self.delete_record(did, lexicon::nsid::FOLDER, rkey).await
    }

    /// Rename / update a folder in place at a known rkey — `putRecord`
    /// (rename, or change its `position` sort hint).
    pub async fn rename_folder(
        &self,
        did: &str,
        rkey: &str,
        folder: &Folder,
    ) -> Result<WriteResult> {
        self.put_record(did, lexicon::nsid::FOLDER, rkey, folder)
            .await
    }

    /// List every folder, **sorted deterministically** — by `position` (the
    /// lexicon's sort hint; unset sorts last), then name (case-insensitive),
    /// then rkey — so the sidebar order is stable.
    pub async fn list_folders_sorted(&self, did: &str) -> Result<Vec<(String, Folder)>> {
        let mut folders = self.list_folders(did).await?;
        folders.sort_by(|(a_key, a), (b_key, b)| {
            a.position
                .unwrap_or(u64::MAX)
                .cmp(&b.position.unwrap_or(u64::MAX))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a_key.cmp(b_key))
        });
        Ok(folders)
    }

    // -- saved / starred -----------------------------------------------------

    /// Add a saved (starred / save-for-later) entry — `createRecord`,
    /// server-assigned `tid` rkey. Returns the new record's rkey.
    pub async fn add_saved(&self, did: &str, saved: &Saved) -> Result<String> {
        Ok(self
            .create_record(did, lexicon::nsid::SAVED, saved)
            .await?
            .into_rkey())
    }

    /// Remove a saved entry by rkey — `deleteRecord` (un-star).
    pub async fn remove_saved(&self, did: &str, rkey: &str) -> Result<()> {
        self.delete_record(did, lexicon::nsid::SAVED, rkey).await
    }

    /// List every saved entry, **sorted deterministically** — newest first by
    /// `createdAt` (RFC-3339 sorts lexicographically), then rkey — so the
    /// "saved for later" list reads most-recent-first and is stable.
    pub async fn list_saved_sorted(&self, did: &str) -> Result<Vec<(String, Saved)>> {
        let mut saved = self.list_saved(did).await?;
        saved.sort_by(|(a_key, a), (b_key, b)| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a_key.cmp(b_key))
        });
        Ok(saved)
    }

    /// List a collection for `did` and parse each record's value into `T`,
    /// pairing it with its rkey. Unparseable records are skipped with a warning
    /// (forward-compat).
    async fn list_typed<T: DeserializeOwned>(
        &self,
        did: &str,
        collection: &str,
    ) -> Result<Vec<(String, T)>> {
        let records = self.list_all_records(did, collection).await?;
        let mut out = Vec::with_capacity(records.len());
        for rec in records {
            let rkey = rec.rkey().unwrap_or_default().to_string();
            match rec.parse::<T>() {
                Ok(value) => out.push((rkey, value)),
                Err(e) => tracing::warn!(
                    collection,
                    uri = %rec.uri,
                    error = %e,
                    "skipping unparseable record in collection"
                ),
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// applyWrites operations
// ---------------------------------------------------------------------------

/// Build the `applyWrites` ops for a batch of dirty read-state cursors.
///
/// Each `(rkey, state, pds_created)` becomes a `#create` op (at the stable
/// feed-derived rkey) when the PDS record does NOT yet exist, and a `#update`
/// when it does. This is the crux of the first-flush fix: an `#update` on a
/// missing record errors, and `applyWrites` is atomic per-repo, so a single
/// not-yet-created cursor in the batch would drop the whole DID's flush. Emitting
/// a `create` for those makes a feed's first flush succeed while keeping every
/// op in ONE batch. Shared by both the sidecar and direct-PDS flush paths.
fn read_state_write_ops(cursors: &[(String, ReadState, bool)]) -> Result<Vec<WriteOp>> {
    cursors
        .iter()
        .map(|(rkey, state, pds_created)| {
            let value = serde_json::to_value(state)?;
            Ok(if *pds_created {
                WriteOp::Update {
                    collection: lexicon::nsid::READ_STATE.to_string(),
                    rkey: rkey.clone(),
                    value,
                }
            } else {
                WriteOp::Create {
                    collection: lexicon::nsid::READ_STATE.to_string(),
                    rkey: Some(rkey.clone()),
                    value,
                }
            })
        })
        .collect()
}

/// One operation in a [`PdsClient::apply_writes`] batch.
///
/// Maps to the `com.atproto.repo.applyWrites` union of
/// `#create` / `#update` / `#delete`.
#[derive(Debug, Clone)]
pub enum WriteOp {
    /// Create a record (server-assigned rkey unless `rkey` is given).
    Create {
        /// The collection NSID.
        collection: String,
        /// Optional explicit rkey (`None` → server assigns a tid).
        rkey: Option<String>,
        /// The record body.
        value: Value,
    },
    /// Upsert a record at a known rkey (the read-state cursor case).
    Update {
        /// The collection NSID.
        collection: String,
        /// The rkey to write at.
        rkey: String,
        /// The record body.
        value: Value,
    },
    /// Delete a record by collection + rkey.
    Delete {
        /// The collection NSID.
        collection: String,
        /// The rkey to delete.
        rkey: String,
    },
}

impl WriteOp {
    /// Render this op as the tagged JSON `com.atproto.repo.applyWrites` expects.
    fn to_json(&self) -> Value {
        match self {
            WriteOp::Create {
                collection,
                rkey,
                value,
            } => {
                let mut op = json!({
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": collection,
                    "value": value,
                });
                if let Some(rkey) = rkey {
                    op["rkey"] = json!(rkey);
                }
                op
            }
            WriteOp::Update {
                collection,
                rkey,
                value,
            } => json!({
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": collection,
                "rkey": rkey,
                "value": value,
            }),
            WriteOp::Delete { collection, rkey } => json!({
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": collection,
                "rkey": rkey,
            }),
        }
    }

    /// Render this op in the shape the OAuth sidecar's `/internal/repo`
    /// `applyWrites` expects: `{action, collection, rkey?, value?}` (the sidecar
    /// maps `action` → the `com.atproto.repo.applyWrites#<kind>` union member).
    fn to_sidecar_json(&self) -> Value {
        match self {
            WriteOp::Create {
                collection,
                rkey,
                value,
            } => {
                let mut op = json!({
                    "action": "create",
                    "collection": collection,
                    "value": value,
                });
                if let Some(rkey) = rkey {
                    op["rkey"] = json!(rkey);
                }
                op
            }
            WriteOp::Update {
                collection,
                rkey,
                value,
            } => json!({
                "action": "update",
                "collection": collection,
                "rkey": rkey,
                "value": value,
            }),
            WriteOp::Delete { collection, rkey } => json!({
                "action": "delete",
                "collection": collection,
                "rkey": rkey,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// TID rkeys (client-assigned, sortable, deterministic within a batch)
// ---------------------------------------------------------------------------

/// The atproto base32-sortable alphabet (`s32`) — the digits/letters, minus the
/// ambiguous set, in **ascending** order so a bytewise string compare of two
/// TIDs matches their timestamp order.
const S32_ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

/// A monotonic generator of atproto **TID** record keys.
///
/// A TID is a 13-char `s32`-encoded 64-bit integer: a 53-bit microsecond
/// timestamp in the high bits and a 10-bit "clock id" in the low bits (the top
/// bit is always 0). Encoded in the ascending `s32` alphabet, TIDs sort
/// lexicographically in creation order — which is exactly what we want for a
/// batched OPML import: assigning the rkeys ourselves keeps the imported feeds
/// in input order and makes [`add_subscriptions_bulk`](SidecarClient::add_subscriptions_bulk)
/// fully reproducible/testable without a live PDS.
///
/// Monotonicity within one generator is guaranteed by tracking the last value
/// and bumping to `last + 1` if the clock hasn't advanced — so a burst of
/// same-microsecond calls still yields strictly increasing, ordered rkeys.
struct TidGenerator {
    /// The last raw 64-bit TID value emitted (0 = none yet).
    last: u64,
    /// The low-10-bit clock id, randomized once per generator to avoid
    /// cross-instance collisions on the same microsecond.
    clock_id: u64,
}

impl TidGenerator {
    /// A fresh generator with a per-instance clock id derived from the current
    /// nanosecond clock (no extra deps; uniqueness only needs to hold within a
    /// single import batch, and the timestamp bits carry the ordering).
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        Self {
            last: 0,
            clock_id: nanos & 0x3ff,
        }
    }

    /// The next monotonic TID rkey (13 `s32` chars).
    fn next(&mut self) -> String {
        let micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        // Timestamp in bits 63..10 (top bit stays 0), clock id in bits 9..0.
        let mut raw = ((micros & 0x001f_ffff_ffff_ffff) << 10) | self.clock_id;
        if raw <= self.last {
            raw = self.last + 1;
        }
        self.last = raw;
        encode_s32_tid(raw)
    }
}

/// Encode a 64-bit TID value as a 13-char big-endian `s32` string.
fn encode_s32_tid(mut v: u64) -> String {
    let mut buf = [0u8; 13];
    for slot in buf.iter_mut().rev() {
        *slot = S32_ALPHABET[(v & 0x1f) as usize];
        v >>= 5;
    }
    // 13 * 5 = 65 bits cover the 64-bit value; the leading char holds the top
    // (always-0) bit, so it is always the alphabet's first symbol.
    String::from_utf8(buf.to_vec()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// XRPC error helper
// ---------------------------------------------------------------------------

/// Minimal percent-encoding for a query-string component.
///
/// Encodes everything outside the RFC 3986 unreserved set, which covers the
/// values FeatherReader passes (DIDs like `did:plc:…`, NSIDs, opaque cursors,
/// handles) without pulling in the optional reqwest `url`/`query` feature.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The atproto XRPC error envelope body: `{"error": "...", "message": "..."}`.
#[derive(Debug, Deserialize)]
struct XrpcErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// Consume a non-2xx response into a typed [`AtProtoError::Xrpc`], parsing the
/// atproto error envelope when present (falling back to `"Unknown"`).
async fn xrpc_error_from(resp: reqwest::Response) -> AtProtoError {
    let status = resp.status();
    let (error, message) = match resp.json::<XrpcErrorBody>().await {
        Ok(body) => (
            body.error.unwrap_or_else(|| "Unknown".to_string()),
            body.message,
        ),
        Err(_) => ("Unknown".to_string(), None),
    };
    AtProtoError::Xrpc {
        status,
        error,
        message,
    }
}

// ---------------------------------------------------------------------------
// Tests — record (de)serialization against a repo listRecords response shape.
// No network.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic `com.atproto.repo.listRecords` response for the subscription
    /// collection, as a PDS returns it — the envelope wraps each record in
    /// `{uri, cid, value}` and the record `value` carries its `$type`.
    fn subscription_list_json() -> Value {
        json!({
            "records": [
                {
                    "uri": "at://did:plc:abc123/community.lexicon.rss.subscription/3ksub0001",
                    "cid": "bafyreisubone",
                    "value": {
                        "$type": "community.lexicon.rss.subscription",
                        "url": "https://example.com/feed.xml",
                        "title": "Example Blog",
                        "siteUrl": "https://example.com/",
                        "fetchHint": "hourly",
                        "createdAt": "2026-07-12T00:00:00.000Z"
                    }
                },
                {
                    "uri": "at://did:plc:abc123/community.lexicon.rss.subscription/3ksub0002",
                    "cid": "bafyreisubtwo",
                    "value": {
                        "$type": "community.lexicon.rss.subscription",
                        "url": "https://blog.example.org/atom.xml",
                        "createdAt": "2026-07-11T12:00:00.000Z"
                    }
                }
            ],
            "cursor": "3ksub0002"
        })
    }

    #[test]
    fn list_records_envelope_deserializes() {
        let resp: ListRecordsResponse =
            serde_json::from_value(subscription_list_json()).expect("envelope");
        assert_eq!(resp.records.len(), 2);
        assert_eq!(resp.cursor.as_deref(), Some("3ksub0002"));
        assert_eq!(resp.records[0].cid.as_deref(), Some("bafyreisubone"));
    }

    #[test]
    fn record_entry_rkey_is_last_uri_segment() {
        let resp: ListRecordsResponse =
            serde_json::from_value(subscription_list_json()).expect("envelope");
        assert_eq!(resp.records[0].rkey(), Some("3ksub0001"));
        assert_eq!(resp.records[1].rkey(), Some("3ksub0002"));
    }

    #[test]
    fn record_value_parses_into_lexicon_subscription() {
        let resp: ListRecordsResponse =
            serde_json::from_value(subscription_list_json()).expect("envelope");

        let full: Subscription = resp.records[0].parse().expect("parse full sub");
        assert_eq!(full.r#type, lexicon::nsid::SUBSCRIPTION);
        assert_eq!(full.url, "https://example.com/feed.xml");
        assert_eq!(full.title.as_deref(), Some("Example Blog"));
        assert_eq!(full.site_url.as_deref(), Some("https://example.com/"));
        assert_eq!(full.fetch_hint, Some(lexicon::FetchHint::Hourly));

        let minimal: Subscription = resp.records[1].parse().expect("parse minimal sub");
        assert_eq!(minimal.url, "https://blog.example.org/atom.xml");
        assert!(minimal.title.is_none());
    }

    fn ssrf_test_client() -> Client {
        Client::builder()
            .user_agent(crate::USER_AGENT)
            .build()
            .unwrap()
    }

    /// A hostile `did:web` whose host is the cloud-metadata address must be
    /// REFUSED before any request leaves the box — the DID-document fetch now
    /// routes through the SSRF guard (`guarded_get_no_privacy`), which rejects
    /// link-local / metadata targets.
    #[tokio::test]
    async fn resolve_did_web_blocks_metadata_host() {
        let client = ssrf_test_client();
        let err = resolve_did_to_pds(&client, "https://plc.directory", "did:web:169.254.169.254")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("forbidden") || err.contains("internal"),
            "expected an SSRF refusal, got: {err}"
        );
    }

    /// A `did:web` pointing at loopback is likewise blocked (internal service
    /// reflection).
    #[tokio::test]
    async fn resolve_did_web_blocks_loopback_host() {
        let client = ssrf_test_client();
        let err = resolve_did_to_pds(&client, "https://plc.directory", "did:web:127.0.0.1")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("forbidden") || err.contains("internal"),
            "expected an SSRF refusal, got: {err}"
        );
    }

    /// `resolve_handle` against a metadata/loopback resolver base is also guarded
    /// (the base can come from a prior hostile DID-doc resolution).
    #[tokio::test]
    async fn resolve_handle_blocks_metadata_resolver_base() {
        let client = ssrf_test_client();
        let err = resolve_handle(&client, "http://169.254.169.254", "alice.example.com")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("forbidden") || err.contains("internal"),
            "expected an SSRF refusal, got: {err}"
        );
    }

    /// A resolved `serviceEndpoint` that targets an internal host is rejected at
    /// resolve time via [`crate::net::assert_public_target`], so it can never be
    /// handed to a raw XRPC client.
    #[tokio::test]
    async fn service_endpoint_internal_target_rejected() {
        assert!(crate::net::assert_public_target("http://169.254.169.254/")
            .await
            .is_err());
        assert!(crate::net::assert_public_target("http://127.0.0.1:3000/")
            .await
            .is_err());
        // A public endpoint literal passes.
        assert!(crate::net::assert_public_target("https://1.1.1.1/")
            .await
            .is_ok());
    }

    #[test]
    fn write_result_deserializes() {
        let wr: WriteResult = serde_json::from_value(json!({
            "uri": "at://did:plc:abc123/community.lexicon.rss.subscription/3ksubnew",
            "cid": "bafyreinew"
        }))
        .expect("write result");
        assert!(wr.uri.ends_with("3ksubnew"));
        assert_eq!(wr.cid.as_deref(), Some("bafyreinew"));
    }

    #[test]
    fn did_document_finds_pds_endpoint() {
        let doc: DidDocument = serde_json::from_value(json!({
            "id": "did:plc:abc123",
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com/"
                }
            ]
        }))
        .expect("did doc");
        assert_eq!(
            doc.pds_endpoint().as_deref(),
            Some("https://pds.example.com")
        );
    }

    #[test]
    fn did_document_without_pds_yields_none() {
        let doc: DidDocument = serde_json::from_value(json!({
            "id": "did:plc:abc123",
            "service": []
        }))
        .expect("did doc");
        assert!(doc.pds_endpoint().is_none());
    }

    #[test]
    fn session_auth_deserializes_create_session_shape() {
        let session: SessionAuth = serde_json::from_value(json!({
            "did": "did:plc:abc123",
            "handle": "alice.example.com",
            "accessJwt": "eyJh...access",
            "refreshJwt": "eyJh...refresh"
        }))
        .expect("session");
        assert_eq!(session.did, "did:plc:abc123");
        assert_eq!(session.handle.as_deref(), Some("alice.example.com"));
        let auth = Auth::Session(session);
        assert_eq!(auth.bearer().expect("bearer"), "eyJh...access");
    }

    #[test]
    fn oauth_variant_carries_no_direct_bearer() {
        let auth = Auth::Oauth(OauthPlaceholder::default());
        assert!(
            auth.bearer().is_err(),
            "Auth::Oauth carries no direct bearer — the sidecar owns the OAuth path"
        );
    }

    #[test]
    fn apply_writes_ops_render_tagged_union() {
        let create = WriteOp::Create {
            collection: lexicon::nsid::SUBSCRIPTION.to_string(),
            rkey: None,
            value: json!({"url": "https://example.com/feed.xml"}),
        };
        let update = WriteOp::Update {
            collection: lexicon::nsid::READ_STATE.to_string(),
            rkey: "feedhash01".to_string(),
            value: json!({"feedUrl": "https://example.com/feed.xml"}),
        };
        let delete = WriteOp::Delete {
            collection: lexicon::nsid::SAVED.to_string(),
            rkey: "3ksaved01".to_string(),
        };

        assert_eq!(
            create.to_json()["$type"],
            json!("com.atproto.repo.applyWrites#create")
        );
        // A create with no explicit rkey omits the field (server assigns a tid).
        assert!(create.to_json().get("rkey").is_none());

        assert_eq!(
            update.to_json()["$type"],
            json!("com.atproto.repo.applyWrites#update")
        );
        assert_eq!(update.to_json()["rkey"], json!("feedhash01"));

        assert_eq!(
            delete.to_json()["$type"],
            json!("com.atproto.repo.applyWrites#delete")
        );
        assert_eq!(delete.to_json()["rkey"], json!("3ksaved01"));
    }

    #[test]
    fn read_state_flush_creates_first_then_updates() {
        // A cursor whose PDS record does NOT yet exist (pds_created = false) must
        // become a CREATE op at its stable rkey — NOT a bare update, which would
        // error on the missing record and (applyWrites being atomic per-repo) drop
        // the whole batch on a feed's first flush.
        let fresh = (
            "rs-fresh".to_string(),
            ReadState::new("https://a.example/feed.xml", None, "2026-07-12T00:00:00Z"),
            false,
        );
        // An already-created cursor updates in place.
        let existing = (
            "rs-existing".to_string(),
            ReadState::new(
                "https://b.example/feed.xml",
                Some("2026-07-11T00:00:00Z".to_string()),
                "2026-07-12T00:00:00Z",
            ),
            true,
        );

        let ops = read_state_write_ops(&[fresh, existing]).expect("build ops");
        assert_eq!(ops.len(), 2);

        // First op: a create carrying the stable rkey (put/create, not update).
        let create = ops[0].to_json();
        assert_eq!(
            create["$type"],
            json!("com.atproto.repo.applyWrites#create"),
            "first flush of a new feed must CREATE its readState record"
        );
        assert_eq!(create["rkey"], json!("rs-fresh"));
        // The created record omits readThrough (F1): backlog not implicitly read.
        assert!(create["value"].get("readThrough").is_none());

        // Second op: an update for the already-created record.
        let update = ops[1].to_json();
        assert_eq!(
            update["$type"],
            json!("com.atproto.repo.applyWrites#update")
        );
        assert_eq!(update["rkey"], json!("rs-existing"));

        // Both ride the SAME batch — batching is preserved.
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn urlencode_escapes_did_colons_and_keeps_unreserved() {
        assert_eq!(urlencode("did:plc:abc123"), "did%3Aplc%3Aabc123");
        assert_eq!(
            urlencode("community.lexicon.rss.subscription"),
            "community.lexicon.rss.subscription"
        );
        assert_eq!(urlencode("a b&c"), "a%20b%26c");
    }

    #[test]
    fn xrpc_record_not_found_is_detected() {
        let err = AtProtoError::Xrpc {
            status: StatusCode::BAD_REQUEST,
            error: "RecordNotFound".to_string(),
            message: Some("Could not locate record".to_string()),
        };
        assert!(err.is_record_not_found());
    }

    // -- reader-facing CRUD: rkey extraction --------------------------------

    #[test]
    fn write_result_extracts_rkey_from_uri() {
        let wr: WriteResult = serde_json::from_value(json!({
            "uri": "at://did:plc:abc123/community.lexicon.rss.subscription/3ksubnew",
            "cid": "bafyreinew"
        }))
        .expect("write result");
        assert_eq!(wr.rkey(), Some("3ksubnew"));
        assert_eq!(wr.into_rkey(), "3ksubnew");
    }

    // -- reader-facing CRUD: deterministic sort orders ----------------------
    //
    // The `list_*_sorted` wrappers only add an ordering on top of the network
    // `list_*` read, so we exercise the *comparator* here on representative
    // data (parsed from a listRecords-shaped envelope) with no network.

    fn parse_all<T: DeserializeOwned>(v: Value) -> Vec<(String, T)> {
        let resp: ListRecordsResponse = serde_json::from_value(v).expect("envelope");
        resp.records
            .into_iter()
            .map(|r| {
                let rkey = r.rkey().unwrap_or_default().to_string();
                (rkey, r.parse::<T>().expect("parse"))
            })
            .collect()
    }

    fn sort_subscriptions(subs: &mut [(String, Subscription)]) {
        subs.sort_by(|(a_key, a), (b_key, b)| {
            let a_title = a.title.as_deref().unwrap_or(&a.url).to_lowercase();
            let b_title = b.title.as_deref().unwrap_or(&b.url).to_lowercase();
            a_title
                .cmp(&b_title)
                .then_with(|| a.url.cmp(&b.url))
                .then_with(|| a_key.cmp(b_key))
        });
    }

    #[test]
    fn subscriptions_sort_by_title_then_url_then_rkey() {
        let mut subs: Vec<(String, Subscription)> = parse_all(json!({
            "records": [
                {
                    "uri": "at://did:plc:x/community.lexicon.rss.subscription/rk-zebra",
                    "value": { "url": "https://z.example/feed", "title": "Zebra News",
                               "createdAt": "2026-07-12T00:00:00.000Z" }
                },
                {
                    "uri": "at://did:plc:x/community.lexicon.rss.subscription/rk-untitled",
                    "value": { "url": "https://aaa.example/feed",
                               "createdAt": "2026-07-12T00:00:00.000Z" }
                },
                {
                    "uri": "at://did:plc:x/community.lexicon.rss.subscription/rk-apple",
                    "value": { "url": "https://apple.example/feed", "title": "apple blog",
                               "createdAt": "2026-07-12T00:00:00.000Z" }
                }
            ]
        }));
        sort_subscriptions(&mut subs);
        // Case-insensitive by the display key (title, or URL when untitled):
        // "apple blog" < "https://aaa.example/feed" < "zebra news".
        let order: Vec<&str> = subs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(order, vec!["rk-apple", "rk-untitled", "rk-zebra"]);
    }

    #[test]
    fn folders_sort_by_position_then_name_then_rkey() {
        let mut folders: Vec<(String, Folder)> = parse_all(json!({
            "records": [
                {
                    "uri": "at://did:plc:x/community.lexicon.rss.folder/rk-nopos",
                    "value": { "name": "Aardvark", "createdAt": "2026-07-12T00:00:00.000Z" }
                },
                {
                    "uri": "at://did:plc:x/community.lexicon.rss.folder/rk-pos2",
                    "value": { "name": "Tech", "position": 2, "createdAt": "2026-07-12T00:00:00.000Z" }
                },
                {
                    "uri": "at://did:plc:x/community.lexicon.rss.folder/rk-pos0",
                    "value": { "name": "News", "position": 0, "createdAt": "2026-07-12T00:00:00.000Z" }
                }
            ]
        }));
        folders.sort_by(|(a_key, a), (b_key, b)| {
            a.position
                .unwrap_or(u64::MAX)
                .cmp(&b.position.unwrap_or(u64::MAX))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a_key.cmp(b_key))
        });
        let order: Vec<&str> = folders.iter().map(|(k, _)| k.as_str()).collect();
        // position 0, then 2, then the unset (sorts last despite name "Aardvark").
        assert_eq!(order, vec!["rk-pos0", "rk-pos2", "rk-nopos"]);
    }

    #[test]
    fn saved_sort_newest_first_by_created_at() {
        let mut saved: Vec<(String, Saved)> = parse_all(json!({
            "records": [
                {
                    "uri": "at://did:plc:x/community.lexicon.rss.saved/rk-old",
                    "value": { "url": "https://e.example/1", "createdAt": "2026-07-10T00:00:00.000Z" }
                },
                {
                    "uri": "at://did:plc:x/community.lexicon.rss.saved/rk-new",
                    "value": { "url": "https://e.example/2", "createdAt": "2026-07-12T00:00:00.000Z" }
                }
            ]
        }));
        saved.sort_by(|(a_key, a), (b_key, b)| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a_key.cmp(b_key))
        });
        assert_eq!(saved[0].0, "rk-new");
        assert_eq!(saved[1].0, "rk-old");
    }

    // -- reader-facing CRUD: bulk applyWrites shape (OPML import) ------------

    #[test]
    fn bulk_subscription_creates_render_sidecar_applywrites_ops() {
        // Mirror what `add_subscriptions_bulk` builds: one create op per feed,
        // each with a client-assigned rkey, in the sidecar's `applyWrites` shape.
        let subs = [
            Subscription::new("https://a.example/feed", "2026-07-12T00:00:00.000Z"),
            Subscription::new("https://b.example/feed", "2026-07-12T00:00:00.000Z"),
        ];
        let mut gen = TidGenerator::new();
        let ops: Vec<Value> = subs
            .iter()
            .map(|sub| {
                WriteOp::Create {
                    collection: lexicon::nsid::SUBSCRIPTION.to_string(),
                    rkey: Some(gen.next()),
                    value: serde_json::to_value(sub).expect("value"),
                }
                .to_sidecar_json()
            })
            .collect();

        assert_eq!(ops.len(), 2);
        for op in &ops {
            assert_eq!(op["action"], json!("create"));
            assert_eq!(
                op["collection"],
                json!("community.lexicon.rss.subscription")
            );
            assert!(op["rkey"].is_string(), "bulk import pins client-side rkeys");
            assert_eq!(
                op["value"]["$type"],
                json!("community.lexicon.rss.subscription")
            );
        }
        // Distinct, ascending rkeys keep OPML order deterministic.
        let k0 = ops[0]["rkey"].as_str().unwrap();
        let k1 = ops[1]["rkey"].as_str().unwrap();
        assert!(k0 < k1, "bulk rkeys must sort in input order ({k0} < {k1})");
    }

    // -- TID rkeys ----------------------------------------------------------

    #[test]
    fn tid_rkeys_are_13_char_s32_and_monotonic() {
        let mut gen = TidGenerator::new();
        let mut prev: Option<String> = None;
        for _ in 0..1000 {
            let tid = gen.next();
            assert_eq!(tid.len(), 13, "a TID is 13 s32 chars");
            assert!(
                tid.bytes().all(|b| S32_ALPHABET.contains(&b)),
                "TID {tid} uses only the s32 alphabet"
            );
            if let Some(p) = &prev {
                assert!(*p < tid, "TIDs must be strictly increasing ({p} < {tid})");
            }
            prev = Some(tid);
        }
    }

    #[test]
    fn tid_rkeys_are_valid_atproto_record_keys() {
        // atproto rkey charset: [A-Za-z0-9._~:-], length 1..=512, not "."/"..".
        let mut gen = TidGenerator::new();
        let tid = gen.next();
        assert!(!tid.is_empty() && tid.len() <= 512);
        assert!(tid != "." && tid != "..");
        assert!(tid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b':' | b'-')));
    }

    #[test]
    fn s32_encoding_is_ascending_for_ascending_values() {
        // The whole point of s32: numeric order == lexicographic string order.
        assert!(encode_s32_tid(1) < encode_s32_tid(2));
        assert!(encode_s32_tid(31) < encode_s32_tid(32));
        assert!(encode_s32_tid(1_000_000) < encode_s32_tid(1_000_001));
        // Ordering holds all the way to the largest real TID value (a 53-bit
        // microsecond timestamp shifted into bits 63..10, plus the clock id).
        let max_tid = (0x001f_ffff_ffff_ffffu64 << 10) | 0x3ff;
        assert!(encode_s32_tid(max_tid - 1) < encode_s32_tid(max_tid));
    }
}
