//! The atproto identity + PDS record layer.
//!
//! FeatherReader's defining bet ([§4](reader design doc)) is that a user's feed
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
//!    read-state flusher uses to coalesce many per-feed cursor upserts into one
//!    round-trip).
//! 3. **Typed convenience wrappers** wired to the [`crate::lexicon`] record
//!    types (list/create [`Subscription`]/[`Folder`]/[`Saved`], upsert
//!    [`ReadState`], batch-flush many `ReadState` cursors).
//!
//! ## Auth — the OAuth sidecar is the live path
//!
//! Auth is a **trait/enum boundary** so the mechanism can vary without touching
//! call sites. There are two paths:
//!
//! * **The live path — the atproto OAuth confidential client, via [`SidecarClient`].**
//!   Per the design and the gaming-SDK prior art, atproto OAuth (DPoP, PAR, token
//!   refresh) is fiddly and is **not** hand-rolled in Rust: it runs in a small
//!   supported `@atproto/oauth-client-node` sidecar. The Rust server never holds
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
// Auth — the scaffolded seam
// ---------------------------------------------------------------------------

/// A source of atproto access tokens.
///
/// This is the **seam** the OAuth confidential-client sidecar drops into. Phase
/// 0 ships only the session-token implementation ([`Auth`] carries a static
/// bearer). The real OAuth path implements this trait over the
/// `@atproto/oauth-client` sidecar (returning fresh DPoP-bound access tokens and
/// refreshing them out of band), and [`PdsClient`] can hold a `dyn TokenSource`
/// instead of a static [`Auth`] without any call-site change.
///
/// It is async + `Send + Sync` so a background refresh can live behind it.
#[allow(async_fn_in_trait)]
pub trait TokenSource: Send + Sync {
    /// Return the current bearer access token to send as `Authorization`.
    async fn access_token(&self) -> Result<String>;
}

/// The auth material a [`PdsClient`] carries.
///
/// A small enum rather than a bare string so the OAuth variant has a home today
/// (even though it's unimplemented), making the seam explicit and the match
/// exhaustive when OAuth lands.
#[derive(Clone)]
pub enum Auth {
    /// **Phase 0 interim:** a bearer access token from a legacy
    /// `com.atproto.server.createSession` (app-password) session. Fully working;
    /// lets the client be exercised end-to-end today.
    Session(SessionAuth),

    /// **TODO (documented seam, not implemented in Phase 0):** the atproto OAuth
    /// confidential-client path. The token is minted + DPoP-bound + refreshed by
    /// the `@atproto/oauth-client` sidecar (see the module docs / gaming-SDK
    /// prior art); the Rust side only carries and presents it.
    Oauth(OauthPlaceholder),
}

impl Auth {
    /// The bearer access token to present on `com.atproto.repo.*` calls.
    ///
    /// For [`Auth::Session`] this is the session's `accessJwt`. For
    /// [`Auth::Oauth`] this is unimplemented in Phase 0 and returns an error
    /// pointing at the sidecar seam.
    pub fn bearer(&self) -> Result<&str> {
        match self {
            Auth::Session(s) => Ok(&s.access_jwt),
            Auth::Oauth(_) => anyhow::bail!(
                "atproto OAuth confidential-client auth is not wired in Phase 0 — \
                 it is a documented seam handled by the @atproto/oauth-client sidecar; \
                 use Auth::Session (app-password) for now"
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
    /// The refresh token, exchanged via `com.atproto.server.refreshSession`
    /// (refresh flow itself is out of Phase-0 scope).
    #[serde(rename = "refreshJwt", default)]
    pub refresh_jwt: Option<String>,
}

/// Placeholder for the OAuth session material.
///
/// Intentionally empty in Phase 0 — it exists only so [`Auth::Oauth`] is a real
/// variant and the OAuth seam is visible in the type system. The sidecar will
/// fill this with the DPoP key handle + token references it manages.
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
/// common case and is what Phase 0 exercises.
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

    let resp = client.get(&url).send().await?;
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
pub async fn resolve_did_to_pds(
    client: &Client,
    plc_directory: &str,
    did: &str,
) -> Result<String> {
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

    let resp = client.get(&doc_url).send().await?;
    if !resp.status().is_success() {
        return Err(AtProtoError::DidResolution {
            did: did.to_string(),
            reason: format!("DID document fetch returned {}", resp.status()),
        }
        .into());
    }

    let doc: DidDocument = resp.json().await.context("parsing DID document")?;
    doc.pds_endpoint().ok_or_else(|| {
        AtProtoError::DidResolution {
            did: did.to_string(),
            reason: "DID document has no #atproto_pds service endpoint".to_string(),
        }
        .into()
    })
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
// Interim auth: app-password session
// ---------------------------------------------------------------------------

/// Create an interim session with an **app password** via
/// `com.atproto.server.createSession` (Phase-0 auth).
///
/// This is the legacy-but-working path that makes [`PdsClient`] exercisable
/// today without the OAuth sidecar. `pds_base` is the account's PDS (resolve it
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
    /// The auth material (Phase-0 session bearer; OAuth seam for later).
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

    /// Resolve `handle` → DID → PDS, obtain an interim app-password session, and
    /// build a ready-to-use client. The Phase-0 convenience constructor that
    /// exercises the whole stack end-to-end.
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

        Ok(Self::new(http, pds_base, session.did.clone(), Auth::Session(session)))
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
        resp.json()
            .await
            .context("parsing listRecords response")
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

    /// List every [`ReadState`] cursor in the user's repo (reconcile-on-login).
    pub async fn list_read_states(&self) -> Result<Vec<(String, ReadState)>> {
        self.list_typed(lexicon::nsid::READ_STATE).await
    }

    /// Upsert a single [`ReadState`] cursor at its feed-derived rkey. For a
    /// batch of dirty cursors prefer [`flush_read_states`](Self::flush_read_states).
    pub async fn put_read_state(&self, rkey: &str, state: &ReadState) -> Result<WriteResult> {
        self.put_record(lexicon::nsid::READ_STATE, rkey, state).await
    }

    /// Batch-flush many dirty [`ReadState`] cursors in one `applyWrites` call —
    /// the debounced read-state flusher's coalesced write.
    ///
    /// Each `(rkey, state)` becomes an `update` op at the feed-derived rkey, so
    /// the whole batch is idempotent (one record per feed).
    pub async fn flush_read_states(&self, cursors: &[(String, ReadState)]) -> Result<()> {
        if cursors.is_empty() {
            return Ok(());
        }
        let writes: Vec<WriteOp> = cursors
            .iter()
            .map(|(rkey, state)| {
                Ok(WriteOp::Update {
                    collection: lexicon::nsid::READ_STATE.to_string(),
                    rkey: rkey.clone(),
                    value: serde_json::to_value(state)?,
                })
            })
            .collect::<Result<_>>()?;
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
    /// resolved base URL + internal secret (from [`crate::config::SidecarConfig`]).
    pub fn new(
        http: Client,
        public_url: impl Into<String>,
        internal_secret: impl Into<String>,
    ) -> Self {
        Self {
            http,
            public_url: Arc::from(public_url.into().trim_end_matches('/')),
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
        let url = format!("{}/internal/session/{}", self.public_url, urlencode(session_id));
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

    /// POST one op to `/internal/repo` and return the raw XRPC `data` payload.
    ///
    /// `body` must already carry `did` + `action` + the action's required fields
    /// (the typed wrappers below build these). Maps the sidecar's error envelope
    /// to [`AtProtoError`]: `404 SessionNotFound` → `Xrpc{error:"SessionNotFound"}`
    /// so callers can treat it as "re-login required".
    async fn repo(&self, body: Value) -> Result<Value> {
        let url = format!("{}/internal/repo", self.public_url);
        let resp = self
            .http
            .post(&url)
            .header("X-Internal-Secret", self.internal_secret.as_ref())
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            let ok: RepoOk = resp.json().await.context("parsing /internal/repo ok body")?;
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
    pub async fn list_all_records(
        &self,
        did: &str,
        collection: &str,
    ) -> Result<Vec<RecordEntry>> {
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
    pub async fn create_subscription(
        &self,
        did: &str,
        sub: &Subscription,
    ) -> Result<WriteResult> {
        self.create_record(did, lexicon::nsid::SUBSCRIPTION, sub).await
    }

    /// Delete a [`Subscription`] record by rkey (unsubscribe).
    pub async fn delete_subscription(&self, did: &str, rkey: &str) -> Result<()> {
        self.delete_record(did, lexicon::nsid::SUBSCRIPTION, rkey).await
    }

    /// Batch-create many [`Subscription`] records in one `applyWrites` — the OPML
    /// import path (one create op per feed, server-assigned rkeys).
    pub async fn create_subscriptions_batch(
        &self,
        did: &str,
        subs: &[Subscription],
    ) -> Result<()> {
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

    /// List every [`ReadState`] cursor in `did`'s repo (reconcile-on-login).
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
        self.put_record(did, lexicon::nsid::READ_STATE, rkey, state).await
    }

    /// Batch-flush many dirty [`ReadState`] cursors in one `applyWrites` call.
    pub async fn flush_read_states(
        &self,
        did: &str,
        cursors: &[(String, ReadState)],
    ) -> Result<()> {
        if cursors.is_empty() {
            return Ok(());
        }
        let writes: Vec<WriteOp> = cursors
            .iter()
            .map(|(rkey, state)| {
                Ok(WriteOp::Update {
                    collection: lexicon::nsid::READ_STATE.to_string(),
                    rkey: rkey.clone(),
                    value: serde_json::to_value(state)?,
                })
            })
            .collect::<Result<_>>()?;
        self.apply_writes(did, &writes).await
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
        assert_eq!(doc.pds_endpoint().as_deref(), Some("https://pds.example.com"));
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
    fn oauth_auth_is_a_documented_unimplemented_seam() {
        let auth = Auth::Oauth(OauthPlaceholder::default());
        assert!(
            auth.bearer().is_err(),
            "OAuth bearer must remain an unimplemented seam in Phase 0"
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
}
