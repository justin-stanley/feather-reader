//! The axum web layer — server-rendered HTML + a dash of htmx, **no SPA**.
//!
//! This module owns the HTTP surface: [`router`] builds an [`axum::Router`] over
//! the shared [`AppState`], wiring the store, feed, atproto, and config seams into
//! a small set of typography-first, dark-mode-ready views rendered with
//! [`askama`] templates (under `templates/`). Progressive enhancement is a single
//! vendored `htmx` script plus a tiny keyboard handler (`static/keyboard.js`);
//! every interaction also works as a plain HTML form POST, so the reader is fully
//! usable with JavaScript disabled (design §3).
//!
//! ## Reading surface (Phase 2)
//!
//! * `GET  /health` — liveness + version, as `text/plain`.
//! * `GET  /` — the reader: a folders/feeds sidebar (from the PDS records layer)
//!   plus the main article list. Query params pick the scope (`?feed=…` /
//!   `?folder=…` / all) and the view (`?view=unread|all|starred`).
//! * `GET  /entries/{id}` — the clean, distraction-free reader for one entry,
//!   with prev/next within the current list.
//! * `POST /entries/{id}/read` — mark an entry read/unread (htmx row swap).
//! * `POST /entries/{id}/star` — star/unstar; writes a
//!   `community.lexicon.rss.saved` record to the user's PDS.
//! * `POST /read-all` — mark-all-read (per feed via `?feed=…`, else everything).
//! * `POST /subscriptions` — subscribe by URL (autodiscover → PDS record).
//! * `POST /subscriptions/{rkey}/delete` — unsubscribe (delete the PDS record).
//! * `POST /subscriptions/{rkey}/rename` — retitle / move a feed to a folder.
//! * `POST /folders` — create a folder record.
//! * `POST /folders/{rkey}/rename` — rename a folder record.
//! * `POST /folders/{rkey}/delete` — delete a folder record.
//! * `POST /opml` — OPML import (multipart upload *or* pasted textarea) → bulk
//!   subscription records in the PDS.
//! * `GET  /opml/export` — OPML export (records → a downloadable document).
//! * `GET /login` + `POST /login` + `/oauth/callback` + `/logout` — the atproto
//!   OAuth seam (unchanged from Phase 1).
//!
//! ## Identity — a cookie-resolved atproto session
//!
//! Per-request identity comes from a **signed session cookie** (`fr_session`)
//! keyed by the logged-in DID, set by [`oauth_callback`] and read by
//! [`current_session`] / [`current_did`]. For local runs without the sidecar,
//! [`Config::dev_did`] (env `FEATHERREADER_DEV_DID`) supplies a fallback identity.
//! All PDS writes route through the [`crate::atproto::SidecarClient`]; a live-PDS
//! write needs a real OAuth session, but the full write path is built and unit-
//! tested to the sidecar boundary.

use askama::Template;
use axum::{
    extract::{Multipart, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::config::Config;
use crate::lexicon::{self, Folder, Saved, Subscription};
use crate::{feed, store, AppState, Session, VERSION};

// The OPML import/export module lives at `src/opml.rs` but isn't declared in the
// crate root (`lib.rs`), which is outside this phase's edit surface. Wire it in
// here via an explicit path so the reader's OPML routes can use the canonical
// `parse_opml` / `to_opml` (design §4) without duplicating that logic.
#[path = "opml.rs"]
mod opml;

/// The name of the signed session cookie.
const SESSION_COOKIE: &str = "fr_session";

/// The canonical AGPL-3.0 source repository — surfaced in the footer, the
/// sign-in pitch, and `/about` (design §4.6, cloud plan public-experiment UI).
const REPO_URL: &str = "https://github.com/justin-stanley/feather-reader";

/// The tip / support link (cloud plan public-experiment UI).
const KOFI_URL: &str = "https://ko-fi.com/justinstanley";

/// The Content-Security-Policy applied to every response.
///
/// Tuned to keep the app fully working while neutralising injected script:
/// * `default-src 'self'` — same-origin baseline.
/// * `script-src 'self'` — only our vendored `htmx.min.js` + `keyboard.js` from
///   `/static`; **no** `'unsafe-inline'`, so an injected `<script>` or a
///   `javascript:` href (F4) cannot execute. (The design's templates carry no
///   inline event handlers — every control is wired in `keyboard.js`.)
/// * `style-src 'self' 'unsafe-inline'` — the linked stylesheet plus the small
///   inline styles htmx toggles for its request indicators.
/// * `img-src 'self' https: data:` — feed content routinely embeds remote
///   images; allow https + data URIs but not other schemes.
/// * `form-action 'self'`, `base-uri 'self'`, `frame-ancestors 'none'` — lock
///   down form posts, `<base>` hijacking, and clickjacking.
/// * `object-src 'none'` — no plugins.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' https: data:; \
     font-src 'self'; \
     connect-src 'self'; \
     form-action 'self'; \
     base-uri 'self'; \
     frame-ancestors 'none'; \
     object-src 'none'";

/// The resolved identity for the current request.
///
/// `did` is the primary key for all per-user local state; `handle` is display
/// only; `sid` is the opaque server-side session id the cookie carried (needed
/// so logout can revoke exactly this session). Sourced from the signed cookie
/// (real login) or, if none, the configured dev DID fallback.
#[derive(Clone, Debug)]
struct CurrentUser {
    did: String,
    handle: Option<String>,
    /// The opaque session id, if this identity came from a real cookie session
    /// (absent for the dev-DID fallback, which has no server-side session row).
    sid: Option<String>,
}

/// Resolve the current request's session from the signed cookie, falling back to
/// the configured dev DID (env `FEATHERREADER_DEV_DID`) for local runs.
///
/// The cookie carries an opaque server-minted session id (not the DID). We
/// verify its HMAC, look the id up in the registry, and — crucially —
/// **re-check the DID against the instance allow-list on every request**, not
/// just at the OAuth callback, so revoking a DID from `ALLOWED_DIDS` takes
/// effect immediately for already-issued cookies.
fn current_session(state: &AppState, headers: &HeaderMap) -> Option<CurrentUser> {
    if let Some(sid) = cookie::verify_session(headers, &state.config.cookie_secret) {
        if let Some(session) = state.sessions.get(&sid) {
            if state.config.did_allowed(&session.did) {
                return Some(CurrentUser {
                    did: session.did,
                    handle: session.handle,
                    sid: Some(sid),
                });
            }
            // DID no longer permitted: treat as logged out (and drop the stale
            // server-side session so the dead cookie can't linger).
            state.sessions.remove(&sid);
        }
    }
    // No valid cookie: dev fallback only if explicitly configured *and* allowed.
    state
        .config
        .dev_did
        .clone()
        .filter(|did| state.config.did_allowed(did))
        .map(|did| CurrentUser {
            did,
            handle: None,
            sid: None,
        })
}

/// The current request's DID, or `None` when logged out (no cookie, no dev DID).
fn current_did(state: &AppState, headers: &HeaderMap) -> Option<String> {
    current_session(state, headers).map(|u| u.did)
}

/// Build the application router over shared [`AppState`].
///
/// Wires the reader routes, the health check, and the `/static` asset mount
/// (the stylesheet, vendored htmx, and the keyboard handler, served from
/// `static/` via [`ServeDir`]). A [`TraceLayer`] gives per-request tracing.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/about", get(about))
        .route("/manage", get(manage))
        .route("/", get(index))
        .route("/entries/{id}", get(entry_view))
        .route("/entries/{id}/read", post(mark_read))
        .route("/entries/{id}/star", post(toggle_star))
        .route("/read-all", post(mark_all_read))
        .route("/subscriptions", post(add_subscription))
        .route("/subscriptions/{rkey}/delete", post(delete_subscription))
        .route("/subscriptions/{rkey}/rename", post(rename_subscription))
        .route("/folders", post(create_folder))
        .route("/folders/{rkey}/rename", post(rename_folder))
        .route("/folders/{rkey}/delete", post(delete_folder))
        .route("/opml", post(import_opml))
        .route("/opml/export", get(export_opml))
        .route("/login", get(login_form).post(login_submit))
        .route("/oauth/callback", get(oauth_callback))
        .route("/logout", post(logout))
        .nest_service("/static", ServeDir::new("static"))
        .layer(TraceLayer::new_for_http())
        // Baseline security headers on *every* response (F4). The CSP is the
        // backstop that neutralises any XSS that slips past sanitization; the
        // others harden sniffing, framing, and referrer leakage.
        .layer(static_header_layer(
            "content-security-policy",
            CONTENT_SECURITY_POLICY,
        ))
        .layer(static_header_layer("x-content-type-options", "nosniff"))
        .layer(static_header_layer(
            "referrer-policy",
            "strict-origin-when-cross-origin",
        ))
        .layer(static_header_layer("x-frame-options", "DENY"))
        .with_state(state)
}

/// A response-header layer that sets `name: value` on every response, overriding
/// any existing header of that name. `name`/`value` must be valid static header
/// tokens (they are, for our fixed security headers).
fn static_header_layer(
    name: &'static str,
    value: &'static str,
) -> SetResponseHeaderLayer<header::HeaderValue> {
    SetResponseHeaderLayer::overriding(
        header::HeaderName::from_static(name),
        header::HeaderValue::from_static(value),
    )
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

/// `GET /health` — a cheap liveness probe returning `200 ok` + the crate version.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, format!("ok featherreader/{VERSION}\n"))
}

/// `GET /about` — the public-experiment page: the full disclaimer (experimental,
/// no SLA, may pause anytime), the OSS / self-host pitch, and the tip link. A
/// static render; readable whether or not a session exists.
async fn about() -> Response {
    render(&AboutTemplate {
        version: VERSION,
        repo_url: REPO_URL,
        kofi_url: KOFI_URL,
    })
}

// ---------------------------------------------------------------------------
// View models
// ---------------------------------------------------------------------------

/// A feed as shown in the sidebar (title + its unread count + a stable scope key
/// and the PDS subscription rkey for management actions).
struct FeedView {
    /// PDS subscription rkey — addresses the record for rename/unsubscribe.
    rkey: String,
    /// Canonical feed URL — the sidebar filter key (`?feed=<url>`).
    url: String,
    title: String,
    unread: i64,
    /// Whether this feed is the currently-selected scope.
    selected: bool,
}

/// A folder grouping in the sidebar, sourced from the PDS `folder` records.
struct FolderView {
    /// PDS folder rkey — addresses the record for rename/delete.
    rkey: String,
    /// The folder's `at://` URI — the sidebar filter key (`?folder=<uri>`).
    uri: String,
    name: String,
    feeds: Vec<FeedView>,
    /// Whether this folder is the currently-selected scope.
    selected: bool,
}

/// One entry as shown in the article list / after an htmx swap.
struct EntryRow {
    id: i64,
    title: String,
    feed_title: String,
    published: String,
    read: bool,
    starred: bool,
    /// The reader link href, already carrying the scope/view query so opening an
    /// entry and paging back stays within the list it came from.
    link: String,
}

/// A folder as an option in the "move feed to folder" select.
struct FolderOption {
    uri: String,
    name: String,
}

/// The shared navigation "rail" model (design §4.1): the same DOM element is the
/// mobile drawer and the desktop sidebar, so every chrome page (list / reader /
/// manage) renders it from this one struct. Feed management lives on `/manage`,
/// not here — the rail is navigation only.
struct Nav {
    /// `@handle` for the identity chip (falls back to the DID's tail).
    handle: String,
    /// Two-letter avatar initials for the identity chip.
    avatar: String,
    /// The active filter: `"unread" | "all" | "starred"` (drives `aria-current`).
    view: String,
    /// The scope query suffix (`feed=…` / `folder=…`) carried onto filter links,
    /// empty for the unscoped "everything" views.
    scope_qs: String,
    /// Folders (each with its feeds) then un-foldered feeds, for the rail lists.
    /// Per-feed `selected` flags drive the rail's feed `aria-current`.
    folders: Vec<FolderView>,
    loose_feeds: Vec<FeedView>,
    /// Whether the "Manage feeds" rail tool is the current page.
    manage_active: bool,
}

/// The reader index (`GET /`).
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    version: &'static str,
    repo_url: &'static str,
    kofi_url: &'static str,
    flash: String,
    /// The shared rail (drawer + desktop sidebar) navigation model.
    nav: Nav,
    /// The article list for the selected scope + view.
    entries: Vec<EntryRow>,
    /// The list heading (the selected view/feed/folder name).
    heading: String,
    /// Whether a feed scope is active (enables per-feed mark-all-read).
    feed_scope: Option<String>,
}

/// The feed-management page (`GET /manage`) — subscribe / your-feeds / OPML.
#[derive(Template)]
#[template(path = "manage.html")]
struct ManageTemplate {
    version: &'static str,
    repo_url: &'static str,
    kofi_url: &'static str,
    flash: String,
    nav: Nav,
    /// All folders as move-targets for the subscribe folder select.
    folder_options: Vec<FolderOption>,
    /// Folders (each with feeds) + loose feeds, for the "Your feeds" list.
    folders: Vec<FolderView>,
    loose_feeds: Vec<FeedView>,
}

/// The public-experiment `/about` page — disclaimer + OSS pitch + tip link.
#[derive(Template)]
#[template(path = "about.html")]
struct AboutTemplate {
    version: &'static str,
    repo_url: &'static str,
    kofi_url: &'static str,
}

/// The single-entry reader view (`GET /entries/:id`).
#[derive(Template)]
#[template(path = "entry.html")]
struct EntryTemplate {
    version: &'static str,
    repo_url: &'static str,
    kofi_url: &'static str,
    nav: Nav,
    id: i64,
    title: String,
    feed_title: String,
    author: Option<String>,
    published: String,
    url: Option<String>,
    content_html: Option<String>,
    read: bool,
    starred: bool,
    /// The query string to carry the reading context back to the list.
    back_qs: String,
    /// Prev/next entry ids within the current list, for keyboard/paging nav.
    prev_id: Option<i64>,
    next_id: Option<i64>,
}

/// The htmx swap fragment for a single entry row (`entry_row.html`).
#[derive(Template)]
#[template(path = "entry_row.html")]
struct EntryRowTemplate {
    e: EntryRow,
}

/// The login stub (`GET /login`).
#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    repo_url: &'static str,
    error: String,
}

// ---------------------------------------------------------------------------
// Rendering + error helpers
// ---------------------------------------------------------------------------

/// Render an askama template into an HTML response, mapping a render failure to
/// a `500` rather than panicking (no `unwrap` in the request path).
fn render<T: Template>(tmpl: &T) -> Response {
    match tmpl.render() {
        Ok(body) => Html(body).into_response(),
        Err(err) => {
            warn!(%err, "template render failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "template render error").into_response()
        }
    }
}

/// A minimal web error type so handlers can `?`-propagate `anyhow` failures and
/// still return an `impl IntoResponse`. Renders as a `500` with a short message.
struct WebError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for WebError {
    fn from(err: E) -> Self {
        WebError(err.into())
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        warn!(error = %self.0, "request failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
    }
}

/// A short, human display of a feed/site title for the sidebar/list, falling
/// back to the host of a URL and finally to the raw string.
fn display_title(title: Option<&str>, url: &str) -> String {
    if let Some(t) = title {
        let t = t.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string())
}

/// A display `@handle` for the identity chip: the stored handle if present,
/// else the tail of the DID so the chip is never empty.
fn display_handle(handle: Option<&str>, did: &str) -> String {
    match handle {
        Some(h) if !h.trim().is_empty() => format!("@{}", h.trim().trim_start_matches('@')),
        _ => did.rsplit(':').next().unwrap_or(did).to_string(),
    }
}

/// Two-letter, lowercase avatar initials from a handle/DID (design §4.1).
fn avatar_initials(handle: Option<&str>, did: &str) -> String {
    let source = handle
        .map(|h| h.trim().trim_start_matches('@'))
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| did.rsplit(':').next().unwrap_or(did));
    let letters: String = source
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(2)
        .collect::<String>()
        .to_lowercase();
    if letters.is_empty() {
        "fr".to_string()
    } else {
        letters
    }
}

/// Trim a stored RFC3339 timestamp down to the `YYYY-MM-DD` date for calm,
/// low-noise display. Falls back to the raw string if it doesn't look like one.
fn display_date(published: Option<&str>) -> String {
    match published {
        Some(p) if p.len() >= 10 => p[..10].to_string(),
        Some(p) => p.to_string(),
        None => String::new(),
    }
}

/// Percent-encode a value for use in a query string (RFC 3986 unreserved kept).
/// Small and dependency-free — the `url` crate's form-encoding isn't exposed for
/// a bare value, and this keeps the scope-preserving links honest.
fn qenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
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

// ---------------------------------------------------------------------------
// Reader: index
// ---------------------------------------------------------------------------

/// Query for `GET /` — the scope + view selector.
#[derive(Debug, Deserialize, Default)]
struct IndexQuery {
    /// Filter to a single feed by its canonical URL.
    #[serde(default)]
    feed: Option<String>,
    /// Filter to a folder by its `at://` URI (shows every feed in the folder).
    #[serde(default)]
    folder: Option<String>,
    /// `unread` (default) | `all` | `starred`.
    #[serde(default)]
    view: Option<String>,
    /// Optional flash message (e.g. after an action redirect).
    #[serde(default)]
    flash: Option<String>,
}

/// A subscription resolved against the local cache: the PDS record + its
/// (possibly-missing) cached feed row.
struct ResolvedSub {
    rkey: String,
    sub: Subscription,
    feed: Option<store::Feed>,
}

/// Pull the user's subscriptions (source of truth = PDS), ensure each has a
/// local cache row so unread counts work, and return them resolved. Best-effort
/// on the sidecar: a failure falls back to the local cache alone.
async fn resolve_subscriptions(state: &AppState, did: &str) -> Vec<ResolvedSub> {
    let pool = &state.db;
    let subs = match state.sidecar.list_subscriptions_sorted(did).await {
        Ok(s) => s,
        Err(err) => {
            warn!(%err, %did, "could not list PDS subscriptions; showing local cache only");
            // Fall back: synthesize subs from every cached feed.
            let feeds = store::due_feeds(pool, &now_rfc3339(), i64::MAX)
                .await
                .unwrap_or_default();
            return feeds
                .into_iter()
                .map(|f| ResolvedSub {
                    rkey: String::new(),
                    sub: Subscription::new(f.url.clone(), now_rfc3339()),
                    feed: Some(f),
                })
                .collect();
        }
    };

    let mut out = Vec::with_capacity(subs.len());
    for (rkey, sub) in subs {
        let feed = match store::get_feed_by_url(pool, &sub.url).await {
            Ok(Some(f)) => Some(f),
            Ok(None) => {
                // Upsert a cache row so the sidebar reflects the real follow-list.
                let _ = store::upsert_feed(
                    pool,
                    &store::NewFeed {
                        url: sub.url.clone(),
                        title: sub.title.clone(),
                        site_url: sub.site_url.clone(),
                        ..Default::default()
                    },
                )
                .await;
                store::get_feed_by_url(pool, &sub.url).await.ok().flatten()
            }
            Err(err) => {
                warn!(%err, url = %sub.url, "get_feed_by_url failed");
                None
            }
        };
        out.push(ResolvedSub { rkey, sub, feed });
    }
    out
}

/// `GET /` — the reader. Renders the sidebar (folders + feeds from the PDS
/// records layer) and the article list for the selected scope + view.
async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<IndexQuery>,
) -> Result<Response, WebError> {
    let user = match current_session(&state, &headers) {
        Some(u) => u,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let did = user.did.clone();
    let pool = &state.db;

    let subs = resolve_subscriptions(&state, &did).await;

    // Per-DID working sets, once.
    let unread = store::get_unread_for_did(pool, &did).await?;
    let starred = store::get_starred_for_did(pool, &did).await?;
    let starred_ids: std::collections::HashSet<i64> = starred.iter().map(|e| e.id).collect();

    // View: unread (default) | all | starred.
    let view = match q.view.as_deref() {
        Some("all") => "all",
        Some("starred") => "starred",
        _ => "unread",
    }
    .to_string();

    // Which feed URLs are in scope?
    let scope_urls = scope_urls_for(&subs, q.feed.as_deref(), q.folder.as_deref());

    // Resolve feed_id → url once for row rendering + scope filtering.
    let feed_url_by_id = |id: i64| -> Option<String> {
        subs.iter()
            .find(|s| s.feed.as_ref().map(|f| f.id) == Some(id))
            .map(|s| s.sub.url.clone())
    };
    let feed_title_by_id = |id: i64| -> String {
        subs.iter()
            .find(|s| s.feed.as_ref().map(|f| f.id) == Some(id))
            .map(|s| {
                display_title(
                    s.sub
                        .title
                        .as_deref()
                        .or(s.feed.as_ref().and_then(|f| f.title.as_deref())),
                    &s.sub.url,
                )
            })
            .unwrap_or_default()
    };

    let in_scope = |feed_id: i64| -> bool {
        match &scope_urls {
            None => true,
            Some(urls) => feed_url_by_id(feed_id)
                .map(|u| urls.contains(&u))
                .unwrap_or(false),
        }
    };

    // The source list for the chosen view.
    let source = match view.as_str() {
        "all" => {
            // All entries across in-scope feeds, newest first.
            let mut all = Vec::new();
            for s in &subs {
                if let Some(f) = &s.feed {
                    if in_scope(f.id) {
                        let mut es = store::entries_for_feed(pool, f.id)
                            .await
                            .unwrap_or_default();
                        all.append(&mut es);
                    }
                }
            }
            all.sort_by(|a, b| b.published.cmp(&a.published).then(b.id.cmp(&a.id)));
            all
        }
        "starred" => starred
            .iter()
            .filter(|e| in_scope(e.feed_id))
            .cloned()
            .collect(),
        _ => unread
            .iter()
            .filter(|e| in_scope(e.feed_id))
            .cloned()
            .collect(),
    };

    // The scope/view suffix carried onto every entry link (built once).
    let entry_scope_qs = {
        let mut parts = Vec::new();
        if let Some(f) = q.feed.as_deref() {
            parts.push(format!("feed={}", qenc(f)));
        }
        if let Some(f) = q.folder.as_deref() {
            parts.push(format!("folder={}", qenc(f)));
        }
        if view != "unread" {
            parts.push(format!("view={}", qenc(&view)));
        }
        parts.join("&")
    };
    let entry_link = |id: i64| -> String {
        if entry_scope_qs.is_empty() {
            format!("/entries/{id}")
        } else {
            format!("/entries/{id}?{entry_scope_qs}")
        }
    };

    let entries: Vec<EntryRow> = source
        .iter()
        .map(|e| EntryRow {
            id: e.id,
            title: e
                .title
                .clone()
                .filter(|t| !t.trim().is_empty())
                .unwrap_or_else(|| "(untitled)".to_string()),
            feed_title: feed_title_by_id(e.feed_id),
            published: display_date(e.published.as_deref()),
            read: view != "unread" && !unread.iter().any(|u| u.id == e.id),
            starred: starred_ids.contains(&e.id),
            link: entry_link(e.id),
        })
        .collect();

    let selected_feed = q.feed.as_deref();
    let selected_folder = q.folder.as_deref();

    // Build the shared sidebar (folders + loose feeds, with unread counts).
    let (folder_views, loose_feeds, _folder_options) =
        build_sidebar(&state, &did, &subs, selected_feed, selected_folder).await;

    // Heading + scope query-string suffix.
    let (heading, scope_qs) = if let Some(feed_url) = selected_feed {
        let name = subs
            .iter()
            .find(|s| s.sub.url == feed_url)
            .map(|s| {
                display_title(
                    s.sub
                        .title
                        .as_deref()
                        .or(s.feed.as_ref().and_then(|f| f.title.as_deref())),
                    &s.sub.url,
                )
            })
            .unwrap_or_else(|| display_title(None, feed_url));
        (name, format!("feed={}", qenc(feed_url)))
    } else if let Some(folder_uri) = selected_folder {
        let name = folder_views
            .iter()
            .find(|f| f.uri == folder_uri)
            .map(|f| f.name.clone())
            .unwrap_or_else(|| "Folder".to_string());
        (name, format!("folder={}", qenc(folder_uri)))
    } else {
        let h = match view.as_str() {
            "all" => "All",
            "starred" => "Starred",
            _ => "Unread",
        };
        (h.to_string(), String::new())
    };

    let feed_scope = selected_feed.map(str::to_string);
    let nav = build_nav(&user, &view, scope_qs, folder_views, loose_feeds, false);

    let tmpl = IndexTemplate {
        version: VERSION,
        repo_url: REPO_URL,
        kofi_url: KOFI_URL,
        flash: q.flash.unwrap_or_default(),
        nav,
        entries,
        heading,
        feed_scope,
    };
    Ok(render(&tmpl))
}

/// Query for `GET /manage` — carries an optional flash after an action redirect.
#[derive(Debug, Deserialize, Default)]
struct ManageQuery {
    #[serde(default)]
    flash: Option<String>,
}

/// `GET /manage` — the feed-management page (design §4.5). Renders the rail plus
/// the subscribe / your-feeds / OPML surfaces; the forms POST to the existing
/// Phase-2 routes unchanged (`/subscriptions`, `/folders`, `/opml`, …). A
/// read/render route only — no new mutation logic.
async fn manage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ManageQuery>,
) -> Result<Response, WebError> {
    let user = match current_session(&state, &headers) {
        Some(u) => u,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let did = user.did.clone();

    let subs = resolve_subscriptions(&state, &did).await;
    let (folder_views, loose_feeds, folder_options) =
        build_sidebar(&state, &did, &subs, None, None).await;

    // Clone the sidebar for the rail; the page body reuses folders/loose feeds.
    let nav = build_nav(
        &user,
        "unread",
        String::new(),
        folder_views.iter().map(clone_folder_view).collect(),
        loose_feeds.iter().map(clone_feed_view).collect(),
        true,
    );

    let tmpl = ManageTemplate {
        version: VERSION,
        repo_url: REPO_URL,
        kofi_url: KOFI_URL,
        flash: q.flash.unwrap_or_default(),
        nav,
        folder_options,
        folders: folder_views,
        loose_feeds,
    };
    Ok(render(&tmpl))
}

/// Shallow clone helpers so `/manage` can hand the same sidebar to both the rail
/// (`Nav`) and the page body without an extra DB round-trip.
fn clone_feed_view(f: &FeedView) -> FeedView {
    FeedView {
        rkey: f.rkey.clone(),
        url: f.url.clone(),
        title: f.title.clone(),
        unread: f.unread,
        selected: f.selected,
    }
}

fn clone_folder_view(f: &FolderView) -> FolderView {
    FolderView {
        rkey: f.rkey.clone(),
        uri: f.uri.clone(),
        name: f.name.clone(),
        feeds: f.feeds.iter().map(clone_feed_view).collect(),
        selected: f.selected,
    }
}

/// The set of feed URLs a scope covers: `Some([one url])` for a single-feed
/// scope, `Some([urls…])` for a folder (its member feeds), or `None` for the
/// unscoped "everything" view. A folder scope takes the feed scope when both are
/// somehow present (feed wins, matching the query precedence elsewhere).
fn scope_urls_for(
    subs: &[ResolvedSub],
    feed: Option<&str>,
    folder: Option<&str>,
) -> Option<Vec<String>> {
    if let Some(feed_url) = feed {
        Some(vec![feed_url.to_string()])
    } else {
        folder.map(|folder_uri| {
            subs.iter()
                .filter(|s| s.sub.folder.as_deref() == Some(folder_uri))
                .map(|s| s.sub.url.clone())
                .collect()
        })
    }
}

/// The `at://` URI for a folder record given the owner DID + rkey.
fn folder_uri(did: &str, rkey: &str) -> String {
    format!("at://{did}/{}/{rkey}", lexicon::nsid::FOLDER)
}

/// Build the sidebar folder/loose-feed views (with per-feed unread counts) for a
/// DID — the shared source for both the reader index and the rail on every
/// chrome page. `selected_feed` / `selected_folder` drive `aria-current`.
async fn build_sidebar(
    state: &AppState,
    did: &str,
    subs: &[ResolvedSub],
    selected_feed: Option<&str>,
    selected_folder: Option<&str>,
) -> (Vec<FolderView>, Vec<FeedView>, Vec<FolderOption>) {
    let pool = &state.db;
    let unread = store::get_unread_for_did(pool, did)
        .await
        .unwrap_or_default();
    let folders = state
        .sidecar
        .list_folders_sorted(did)
        .await
        .unwrap_or_default();

    let unread_count = |feed_id: Option<i64>| -> i64 {
        match feed_id {
            Some(id) => unread.iter().filter(|e| e.feed_id == id).count() as i64,
            None => 0,
        }
    };
    let mk_feed_view = |s: &ResolvedSub| FeedView {
        rkey: s.rkey.clone(),
        url: s.sub.url.clone(),
        title: display_title(
            s.sub
                .title
                .as_deref()
                .or(s.feed.as_ref().and_then(|f| f.title.as_deref())),
            &s.sub.url,
        ),
        unread: unread_count(s.feed.as_ref().map(|f| f.id)),
        selected: selected_feed == Some(s.sub.url.as_str()),
    };

    let mut folder_views = Vec::with_capacity(folders.len());
    for (rkey, folder) in &folders {
        let uri = folder_uri(did, rkey);
        let feeds: Vec<FeedView> = subs
            .iter()
            .filter(|s| s.sub.folder.as_deref() == Some(uri.as_str()))
            .map(mk_feed_view)
            .collect();
        folder_views.push(FolderView {
            rkey: rkey.clone(),
            uri: uri.clone(),
            name: folder.name.clone(),
            feeds,
            selected: selected_folder == Some(uri.as_str()),
        });
    }

    let known_uris: std::collections::HashSet<String> =
        folders.iter().map(|(r, _)| folder_uri(did, r)).collect();
    let loose_feeds: Vec<FeedView> = subs
        .iter()
        .filter(|s| {
            s.sub
                .folder
                .as_deref()
                .map(|f| !known_uris.contains(f))
                .unwrap_or(true)
        })
        .map(mk_feed_view)
        .collect();

    let folder_options: Vec<FolderOption> = folders
        .iter()
        .map(|(rkey, folder)| FolderOption {
            name: folder.name.clone(),
            uri: folder_uri(did, rkey),
        })
        .collect();

    (folder_views, loose_feeds, folder_options)
}

/// Assemble the shared rail [`Nav`] for a chrome page.
fn build_nav(
    user: &CurrentUser,
    view: &str,
    scope_qs: String,
    folders: Vec<FolderView>,
    loose_feeds: Vec<FeedView>,
    manage_active: bool,
) -> Nav {
    Nav {
        handle: display_handle(user.handle.as_deref(), &user.did),
        avatar: avatar_initials(user.handle.as_deref(), &user.did),
        view: view.to_string(),
        scope_qs,
        folders,
        loose_feeds,
        manage_active,
    }
}

// ---------------------------------------------------------------------------
// Reader: single entry
// ---------------------------------------------------------------------------

/// Query for `GET /entries/:id` — carries the reading context (scope + view) so
/// prev/next and "back" stay within the list the reader came from.
#[derive(Debug, Deserialize, Default)]
struct EntryQuery {
    #[serde(default)]
    feed: Option<String>,
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    view: Option<String>,
}

/// `GET /entries/:id` — the clean reader view for one entry, with prev/next
/// within the current reading list.
async fn entry_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<EntryQuery>,
) -> Result<Response, WebError> {
    let user = match current_session(&state, &headers) {
        Some(u) => u,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let did = user.did.clone();
    let pool = &state.db;

    let entry = match get_entry_by_id(pool, id).await? {
        Some(e) => e,
        None => return Ok((StatusCode::NOT_FOUND, "entry not found").into_response()),
    };

    let feed_title = feed_title_by_entry(pool, entry.feed_id).await;

    let read = entry_is_read(pool, &did, id).await?;
    let starred = entry_is_starred(pool, &did, id).await?;

    // Reconstruct the current list to compute prev/next, so paging in the reader
    // matches what the list showed.
    let (prev_id, next_id) = neighbors_in_scope(&state, &did, &q, id).await;

    let back_qs = scope_query(&q);

    // Rail: the same navigation as the list, in the reader's scope.
    let subs = resolve_subscriptions(&state, &did).await;
    let (folder_views, loose_feeds, _) =
        build_sidebar(&state, &did, &subs, q.feed.as_deref(), q.folder.as_deref()).await;
    let nav_view = match q.view.as_deref() {
        Some("all") => "all",
        Some("starred") => "starred",
        _ => "unread",
    };
    let nav = build_nav(
        &user,
        nav_view,
        back_qs.clone(),
        folder_views,
        loose_feeds,
        false,
    );

    let tmpl = EntryTemplate {
        version: VERSION,
        repo_url: REPO_URL,
        kofi_url: KOFI_URL,
        nav,
        id: entry.id,
        title: entry
            .title
            .clone()
            .filter(|t| !t.trim().is_empty())
            .unwrap_or_else(|| "(untitled)".to_string()),
        feed_title,
        author: entry.author.clone().filter(|a| !a.trim().is_empty()),
        published: display_date(entry.published.as_deref()),
        url: entry.url.clone().filter(|u| !u.trim().is_empty()),
        content_html: entry.content_html.clone(),
        read,
        starred,
        back_qs,
        prev_id,
        next_id,
    };
    Ok(render(&tmpl))
}

/// Compute the prev/next entry ids around `current` within the reader's current
/// scope + view, so the reader view can offer keyboard/paging navigation.
async fn neighbors_in_scope(
    state: &AppState,
    did: &str,
    q: &EntryQuery,
    current: i64,
) -> (Option<i64>, Option<i64>) {
    let idx_q = IndexQuery {
        feed: q.feed.clone(),
        folder: q.folder.clone(),
        view: q.view.clone(),
        flash: None,
    };
    let ids = list_entry_ids(state, did, &idx_q).await;
    let pos = ids.iter().position(|&x| x == current);
    match pos {
        Some(p) => {
            let prev = if p > 0 { Some(ids[p - 1]) } else { None };
            let next = ids.get(p + 1).copied();
            (prev, next)
        }
        None => (None, None),
    }
}

/// The ordered entry ids for a scope + view — the same ordering `index` renders,
/// used for reader prev/next. Best-effort; PDS failures degrade to local cache.
async fn list_entry_ids(state: &AppState, did: &str, q: &IndexQuery) -> Vec<i64> {
    let pool = &state.db;
    let subs = resolve_subscriptions(state, did).await;

    let scope_urls = scope_urls_for(&subs, q.feed.as_deref(), q.folder.as_deref());
    let feed_url_by_id = |id: i64| -> Option<String> {
        subs.iter()
            .find(|s| s.feed.as_ref().map(|f| f.id) == Some(id))
            .map(|s| s.sub.url.clone())
    };
    let in_scope = |feed_id: i64| -> bool {
        match &scope_urls {
            None => true,
            Some(urls) => feed_url_by_id(feed_id)
                .map(|u| urls.contains(&u))
                .unwrap_or(false),
        }
    };

    let view = q.view.as_deref().unwrap_or("unread");
    let entries = match view {
        "all" => {
            let mut all = Vec::new();
            for s in &subs {
                if let Some(f) = &s.feed {
                    if in_scope(f.id) {
                        let mut es = store::entries_for_feed(pool, f.id)
                            .await
                            .unwrap_or_default();
                        all.append(&mut es);
                    }
                }
            }
            all.sort_by(|a, b| b.published.cmp(&a.published).then(b.id.cmp(&a.id)));
            all
        }
        "starred" => store::get_starred_for_did(pool, did)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|e| in_scope(e.feed_id))
            .collect(),
        _ => store::get_unread_for_did(pool, did)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|e| in_scope(e.feed_id))
            .collect(),
    };
    entries.into_iter().map(|e| e.id).collect()
}

/// Build a `?…` query string that preserves the reading scope + view for links.
fn scope_query(q: &EntryQuery) -> String {
    let mut parts = Vec::new();
    if let Some(f) = q.feed.as_deref() {
        parts.push(format!("feed={}", qenc(f)));
    }
    if let Some(f) = q.folder.as_deref() {
        parts.push(format!("folder={}", qenc(f)));
    }
    if let Some(v) = q.view.as_deref() {
        if v != "unread" {
            parts.push(format!("view={}", qenc(v)));
        }
    }
    parts.join("&")
}

// ---------------------------------------------------------------------------
// Mark read / unread
// ---------------------------------------------------------------------------

/// Form body for `POST /entries/:id/read`.
#[derive(Debug, Deserialize)]
struct ReadForm {
    #[serde(default)]
    read: Option<String>,
}

/// `POST /entries/:id/read` — toggle an entry's read-state for the current DID.
async fn mark_read(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<ReadForm>,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let pool = &state.db;

    let read = matches!(
        form.read.as_deref(),
        Some("true") | Some("1") | Some("on") | None
    );
    store::mark_read(pool, &did, id, read).await?;

    if !is_htmx(&headers) {
        return Ok(Redirect::to("/").into_response());
    }

    let row = build_entry_row(pool, &did, id, Some(read)).await?;
    match row {
        Some(r) => Ok(render(&EntryRowTemplate { e: r })),
        None => Ok((StatusCode::NOT_FOUND, "entry not found").into_response()),
    }
}

// ---------------------------------------------------------------------------
// Star / save
// ---------------------------------------------------------------------------

/// Form body for `POST /entries/:id/star`.
#[derive(Debug, Deserialize)]
struct StarForm {
    #[serde(default)]
    starred: Option<String>,
}

/// `POST /entries/:id/star` — star/unstar an entry.
///
/// Sets the local `starred` bit (fast working copy) and writes/removes a
/// `community.lexicon.rss.saved` record in the user's PDS (design §3: stars are
/// worth owning). The PDS write is best-effort — the local star still lands.
async fn toggle_star(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<StarForm>,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let pool = &state.db;

    let starred = matches!(
        form.starred.as_deref(),
        Some("true") | Some("1") | Some("on") | None
    );
    store::mark_starred(pool, &did, id, starred).await?;

    // Reflect into the PDS saved-records collection.
    if let Ok(Some(entry)) = get_entry_by_id(pool, id).await {
        let entry_url = entry.url.clone().unwrap_or_default();
        if !entry_url.is_empty() {
            if starred {
                let mut saved = Saved::new(entry_url.clone(), now_rfc3339());
                saved.title = entry.title.clone();
                saved.feed_url = feed_url_for_id(pool, entry.feed_id).await;
                saved.entry_id = Some(entry.guid.clone());
                match state.sidecar.add_saved(&did, &saved).await {
                    Ok(rkey) => info!(%did, url = %entry_url, %rkey, "wrote saved record to PDS"),
                    Err(err) => warn!(%err, %did, "PDS saved write failed (starred locally)"),
                }
            } else {
                // Un-star: find and delete the matching saved record by URL.
                match state.sidecar.list_saved(&did).await {
                    Ok(records) => {
                        for (rkey, _rec) in records.iter().filter(|(_, r)| r.url == entry_url) {
                            if let Err(err) = state.sidecar.remove_saved(&did, rkey).await {
                                warn!(%err, %did, %rkey, "PDS saved delete failed");
                            }
                        }
                    }
                    Err(err) => warn!(%err, %did, "could not list saved records to un-star"),
                }
            }
        }
    }

    if !is_htmx(&headers) {
        return Ok(Redirect::to("/").into_response());
    }
    let row = build_entry_row(pool, &did, id, None).await?;
    match row {
        Some(r) => Ok(render(&EntryRowTemplate { e: r })),
        None => Ok((StatusCode::NOT_FOUND, "entry not found").into_response()),
    }
}

/// The feed URL for a cached feed id, if the row exists.
async fn feed_url_for_id(pool: &store::Pool, feed_id: i64) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT url FROM feeds WHERE id = ?1")
        .bind(feed_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

// ---------------------------------------------------------------------------
// Mark-all-read
// ---------------------------------------------------------------------------

/// Query for `POST /read-all` — an optional `?feed=<url>` scopes it to one feed;
/// absent means mark everything read.
#[derive(Debug, Deserialize, Default)]
struct ReadAllQuery {
    #[serde(default)]
    feed: Option<String>,
}

/// `POST /read-all` — mark every entry read for the current DID, optionally
/// scoped to one feed (design §3: mark-all-read per feed / global).
async fn mark_all_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReadAllQuery>,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let pool = &state.db;

    if let Some(feed_url) = q.feed.as_deref() {
        if let Ok(Some(feed)) = store::get_feed_by_url(pool, feed_url).await {
            store::mark_feed_read(pool, &did, feed.id, true).await?;
        }
        return Ok(Redirect::to(&format!("/?feed={}", qenc(feed_url))).into_response());
    }

    // Global: mark every currently-unread entry read.
    let unread = store::get_unread_for_did(pool, &did).await?;
    for e in &unread {
        store::mark_read(pool, &did, e.id, true).await?;
    }
    Ok(Redirect::to("/").into_response())
}

// ---------------------------------------------------------------------------
// Subscribe by URL
// ---------------------------------------------------------------------------

/// Form body for `POST /subscriptions`.
#[derive(Debug, Deserialize)]
struct SubscribeForm {
    url: String,
    /// Optional folder `at://` URI to file the new feed under.
    #[serde(default)]
    folder: Option<String>,
}

/// `POST /subscriptions` — subscribe by URL.
async fn add_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SubscribeForm>,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let pool = &state.db;
    let input = form.url.trim().to_string();
    if input.is_empty() {
        return Ok(Redirect::to("/").into_response());
    }

    let feed_url = match resolve_feed_url(&state.config, &input).await {
        Ok(u) => u,
        Err(err) => {
            warn!(%err, url = %input, "could not resolve a feed from the given URL");
            return Ok(Redirect::to(&format!(
                "/?flash={}",
                qenc("Couldn't find a feed at that URL")
            ))
            .into_response());
        }
    };

    store::upsert_feed(
        pool,
        &store::NewFeed {
            url: feed_url.clone(),
            ..Default::default()
        },
    )
    .await?;

    if let Ok(client) = feed::build_client() {
        if let Some(feed_row) = store::get_feed_by_url(pool, &feed_url).await? {
            match feed::poll_feed(pool, &client, &feed_row).await {
                Ok(outcome) => info!(feed = %feed_url, ?outcome, "polled new subscription"),
                Err(err) => warn!(%err, feed = %feed_url, "initial poll failed"),
            }
        }
    }

    let mut sub = Subscription::new(feed_url.clone(), now_rfc3339());
    if let Ok(Some(feed_row)) = store::get_feed_by_url(pool, &feed_url).await {
        sub.title = feed_row.title.clone();
        sub.site_url = feed_row.site_url.clone();
    }
    sub.folder = form
        .folder
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty());

    match state.sidecar.add_subscription(&did, &sub).await {
        Ok(rkey) => info!(feed = %feed_url, %rkey, %did, "wrote subscription record to PDS"),
        Err(err) => {
            warn!(%err, feed = %feed_url, %did, "PDS subscription write failed (cached locally)")
        }
    }

    Ok(Redirect::to("/").into_response())
}

/// `POST /subscriptions/:rkey/delete` — unsubscribe (delete the PDS record).
async fn delete_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rkey): Path<String>,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    match state.sidecar.remove_subscription(&did, &rkey).await {
        Ok(()) => info!(%did, %rkey, "unsubscribed (deleted PDS subscription record)"),
        Err(err) => warn!(%err, %did, %rkey, "PDS unsubscribe failed"),
    }
    Ok(Redirect::to("/").into_response())
}

/// Form body for `POST /subscriptions/:rkey/rename`.
#[derive(Debug, Deserialize)]
struct RenameSubForm {
    url: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    site_url: Option<String>,
    #[serde(default)]
    folder: Option<String>,
}

/// `POST /subscriptions/:rkey/rename` — retitle a feed and/or move it to a
/// folder, rewriting the whole subscription record via `putRecord`.
async fn rename_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rkey): Path<String>,
    Form(form): Form<RenameSubForm>,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let mut sub = Subscription::new(form.url.trim().to_string(), now_rfc3339());
    sub.title = form
        .title
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    sub.site_url = form
        .site_url
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    sub.folder = form
        .folder
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty());

    // Keep the local cache title in step for the loose-feed fallback path.
    let _ = store::upsert_feed(
        &state.db,
        &store::NewFeed {
            url: sub.url.clone(),
            title: sub.title.clone(),
            site_url: sub.site_url.clone(),
            ..Default::default()
        },
    )
    .await;

    match state.sidecar.update_subscription(&did, &rkey, &sub).await {
        Ok(res) => info!(%did, %rkey, uri = %res.uri, "renamed/moved subscription"),
        Err(err) => warn!(%err, %did, %rkey, "PDS subscription update failed"),
    }
    Ok(Redirect::to("/").into_response())
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

/// Form body for `POST /folders`.
#[derive(Debug, Deserialize)]
struct FolderForm {
    name: String,
}

/// `POST /folders` — create a folder record.
async fn create_folder(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<FolderForm>,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let name = form.name.trim();
    if name.is_empty() {
        return Ok(Redirect::to("/").into_response());
    }
    let folder = Folder::new(name.to_string(), now_rfc3339());
    match state.sidecar.add_folder(&did, &folder).await {
        Ok(rkey) => info!(%did, %rkey, name, "created folder record"),
        Err(err) => warn!(%err, %did, "PDS folder create failed"),
    }
    Ok(Redirect::to("/").into_response())
}

/// `POST /folders/:rkey/rename` — rename a folder record.
async fn rename_folder(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rkey): Path<String>,
    Form(form): Form<FolderForm>,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let name = form.name.trim();
    if name.is_empty() {
        return Ok(Redirect::to("/").into_response());
    }
    let folder = Folder::new(name.to_string(), now_rfc3339());
    match state.sidecar.rename_folder(&did, &rkey, &folder).await {
        Ok(res) => info!(%did, %rkey, uri = %res.uri, "renamed folder"),
        Err(err) => warn!(%err, %did, %rkey, "PDS folder rename failed"),
    }
    Ok(Redirect::to("/").into_response())
}

/// `POST /folders/:rkey/delete` — delete a folder record (feeds referencing it
/// simply become un-foldered).
async fn delete_folder(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rkey): Path<String>,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    match state.sidecar.remove_folder(&did, &rkey).await {
        Ok(()) => info!(%did, %rkey, "deleted folder record"),
        Err(err) => warn!(%err, %did, %rkey, "PDS folder delete failed"),
    }
    Ok(Redirect::to("/").into_response())
}

/// Resolve a user-pasted URL to a canonical feed URL: if fetching it yields a
/// feed document we take it as-is; if it yields an HTML page we run
/// autodiscovery over its `<link rel="alternate">` tags.
async fn resolve_feed_url(_config: &Config, input: &str) -> anyhow::Result<String> {
    let parsed =
        url::Url::parse(input).map_err(|e| anyhow::anyhow!("not a valid URL {input:?}: {e}"))?;

    let client = feed::build_client()?;
    // Fetch through the SSRF guard: scheme + resolved-IP checks on the URL and
    // every redirect hop, so a user-pasted URL can't reach cloud metadata /
    // loopback / private hosts.
    let resp = crate::net::guarded_get(&client, parsed.as_str(), &[]).await?;
    let final_url = resp.url().clone();
    let content_type = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    // Cap the body (streamed, aborts over 8 MiB) — never trust Content-Length,
    // gzip strips it, and this response is reflected into the UI.
    let raw = crate::net::read_capped(resp).await?;
    let body = String::from_utf8_lossy(&raw).into_owned();

    let looks_like_feed = content_type.contains("xml")
        || content_type.contains("rss")
        || content_type.contains("atom")
        || content_type.contains("application/feed+json")
        || {
            let head = body.trim_start();
            head.starts_with("<?xml")
                || head.starts_with("<rss")
                || head.starts_with("<feed")
                || head.contains("<rss")
                || head.contains("<feed")
        };
    if looks_like_feed {
        return Ok(final_url.to_string());
    }

    match feed::discover_feed(&body, Some(&final_url)) {
        Some(u) => Ok(u.to_string()),
        None => anyhow::bail!("no feed found at {input} (no autodiscovery link)"),
    }
}

// ---------------------------------------------------------------------------
// Login (atproto OAuth via the sidecar)
// ---------------------------------------------------------------------------

/// Query for `GET /login`.
#[derive(Debug, Deserialize, Default)]
struct LoginQuery {
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// `GET /login` — start the atproto OAuth flow, or render the handle form.
async fn login_form(State(state): State<AppState>, Query(q): Query<LoginQuery>) -> Response {
    if let Some(handle) = q
        .handle
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
    {
        return start_oauth(&state, &handle);
    }
    render(&LoginTemplate {
        repo_url: REPO_URL,
        error: q.error.unwrap_or_default(),
    })
}

/// `POST /login` — the handle-form submit: redirect into the sidecar OAuth flow.
async fn login_submit(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    let handle = form.handle.trim();
    if handle.is_empty() {
        return login_error("Enter your atproto handle.");
    }
    start_oauth(&state, handle)
}

/// Redirect the browser to the sidecar's public `/login` for `handle`.
fn start_oauth(state: &AppState, handle: &str) -> Response {
    let url = state.sidecar.login_url(handle, None);
    info!(%handle, "redirecting to OAuth sidecar login");
    Redirect::to(&url).into_response()
}

/// Form body for `POST /login`.
#[derive(Debug, Deserialize)]
struct LoginForm {
    handle: String,
}

/// Query for `GET /oauth/callback`.
#[derive(Debug, Deserialize, Default)]
struct CallbackQuery {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// `GET /oauth/callback` — establish the cookie session.
async fn oauth_callback(State(state): State<AppState>, Query(q): Query<CallbackQuery>) -> Response {
    if let Some(err) = q.error {
        let desc = q.error_description.unwrap_or_default();
        warn!(error = %err, desc = %desc, "OAuth callback returned an error");
        return login_error(&format!("Login failed: {err}"));
    }

    let session_id = match q.session_id {
        Some(s) if !s.is_empty() => s,
        _ => return login_error("Login failed: the callback carried no session."),
    };

    let session = match state.sidecar.resolve_session(&session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            warn!("OAuth callback session_id did not resolve (expired/unknown)");
            return login_error("Login session expired — please try again.");
        }
        Err(err) => {
            warn!(%err, "failed to resolve OAuth session via the sidecar");
            return login_error("Login failed talking to the auth service.");
        }
    };

    if !state.config.did_allowed(&session.did) {
        warn!(did = %session.did, "login rejected: DID not on the instance allow-list");
        return login_error("This instance's allow-list does not permit that account.");
    }

    // Mint an opaque, random server-side session id and store the identity under
    // it; the cookie carries the (HMAC-signed) sid, never the DID.
    let sid = state.sessions.create(Session {
        did: session.did.clone(),
        handle: session.handle.clone(),
    });
    let cookie = cookie::sign_session(&sid, &state.config.cookie_secret);
    info!(did = %session.did, handle = ?session.handle, "OAuth login OK; session cookie set");

    let mut resp = Redirect::to("/").into_response();
    set_cookie(&mut resp, &cookie);
    resp
}

/// `POST /logout` — clear the session cookie + drop the in-memory session.
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(user) = current_session(&state, &headers) {
        if let Some(sid) = user.sid {
            state.sessions.remove(&sid);
        }
    }
    let mut resp = Redirect::to("/login").into_response();
    set_cookie(
        &mut resp,
        &format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"),
    );
    resp
}

/// Re-render the login form with an error banner.
fn login_error(msg: &str) -> Response {
    render(&LoginTemplate {
        repo_url: REPO_URL,
        error: msg.to_string(),
    })
}

// ---------------------------------------------------------------------------
// OPML import + export
// ---------------------------------------------------------------------------

/// `POST /opml` — import subscriptions from an OPML document.
///
/// Accepts either a multipart file upload (field `file`) or a pasted textarea
/// (field `opml`). The parsed feeds each become a `community.lexicon.rss.folder`
/// (for any named folders) + a `community.lexicon.rss.subscription` record in the
/// user's PDS via the records layer's bulk-add (`add_subscriptions_bulk`, one
/// `applyWrites` round-trip). Feeds are also upserted into the local cache so
/// they show immediately; polling is left to the background poller.
async fn import_opml(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let pool = &state.db;

    // Collect the OPML text from whichever field carried it.
    let mut opml_text = String::new();
    while let Some(field) = multipart.next_field().await? {
        let name = field.name().unwrap_or("").to_string();
        if name == "opml" || name == "file" {
            let bytes = field.bytes().await?;
            if !bytes.is_empty() {
                opml_text = String::from_utf8_lossy(&bytes).into_owned();
                if name == "file" {
                    break;
                }
            }
        }
    }

    let feeds = opml::parse_opml(&opml_text).unwrap_or_default();
    if feeds.is_empty() {
        info!(%did, "OPML import found no feeds");
        return Ok(
            Redirect::to(&format!("/?flash={}", qenc("No feeds found in that OPML")))
                .into_response(),
        );
    }

    // Create any named folders first, mapping folder name → at:// URI so
    // subscriptions can reference them.
    let now = now_rfc3339();
    let mut folder_uris: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    // Reuse existing folders where the name already exists.
    if let Ok(existing) = state.sidecar.list_folders_sorted(&did).await {
        for (rkey, folder) in existing {
            folder_uris
                .entry(folder.name.clone())
                .or_insert_with(|| folder_uri(&did, &rkey));
        }
    }
    let mut wanted_folders: Vec<String> = feeds
        .iter()
        .filter_map(|f| f.folder.clone())
        .filter(|n| !n.is_empty())
        .collect();
    wanted_folders.sort();
    wanted_folders.dedup();
    for name in wanted_folders {
        if folder_uris.contains_key(&name) {
            continue;
        }
        let folder = Folder::new(name.clone(), now.clone());
        match state.sidecar.add_folder(&did, &folder).await {
            Ok(rkey) => {
                folder_uris.insert(name, folder_uri(&did, &rkey));
            }
            Err(err) => warn!(%err, %did, "OPML folder create failed"),
        }
    }

    // Build one subscription record per feed + upsert the local cache row.
    let mut subs = Vec::with_capacity(feeds.len());
    for f in &feeds {
        let mut sub = Subscription::new(f.feed_url.clone(), now.clone());
        sub.title = f.title.clone();
        sub.site_url = f.site_url.clone();
        sub.folder = f
            .folder
            .as_ref()
            .and_then(|name| folder_uris.get(name).cloned());
        subs.push(sub);
        let _ = store::upsert_feed(
            pool,
            &store::NewFeed {
                url: f.feed_url.clone(),
                title: f.title.clone(),
                site_url: f.site_url.clone(),
                ..Default::default()
            },
        )
        .await;
    }

    match state.sidecar.add_subscriptions_bulk(&did, &subs).await {
        Ok(rkeys) => {
            info!(%did, count = rkeys.len(), "imported OPML subscriptions to PDS (batched)")
        }
        Err(err) => warn!(%err, %did, "OPML PDS batch write failed (feeds cached locally)"),
    }

    Ok(Redirect::to(&format!(
        "/?flash={}",
        qenc(&format!("Imported {} feeds", subs.len()))
    ))
    .into_response())
}

/// `GET /opml/export` — export the user's subscriptions + folders as OPML.
async fn export_opml(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };

    let subs = state
        .sidecar
        .list_subscriptions_sorted(&did)
        .await
        .unwrap_or_default();
    let folders = state
        .sidecar
        .list_folders_sorted(&did)
        .await
        .unwrap_or_default();
    // The exporter matches a subscription's `folder` at-uri against the folder's
    // pair key; our folder pairs are keyed by rkey, so rebuild them as at-uris.
    let folder_pairs: Vec<(String, Folder)> = folders
        .into_iter()
        .map(|(rkey, f)| (folder_uri(&did, &rkey), f))
        .collect();

    let body = opml::to_opml(&subs, &folder_pairs);
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        "text/x-opml; charset=utf-8".parse().unwrap(),
    );
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        "attachment; filename=\"featherreader-subscriptions.opml\""
            .parse()
            .unwrap(),
    );
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Signed session cookie (HMAC-SHA256, dependency-free)
// ---------------------------------------------------------------------------

/// Set a `Set-Cookie` header on a response (append, so logout+redirect compose).
fn set_cookie(resp: &mut Response, cookie: &str) {
    if let Ok(value) = axum::http::HeaderValue::from_str(cookie) {
        resp.headers_mut()
            .append(axum::http::header::SET_COOKIE, value);
    }
}

/// Whether the request came from htmx (the `HX-Request` header).
fn is_htmx(headers: &HeaderMap) -> bool {
    headers
        .get("HX-Request")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"true"))
}

/// A tiny, self-contained signed-cookie layer: HMAC-SHA256 over an opaque,
/// server-minted **session id** (never the DID — so the cookie can't be forged
/// from a resolved victim DID; forging it needs the HMAC secret *and* a live
/// server-side session id).
mod cookie {
    use super::{HeaderMap, SESSION_COOKIE};

    /// Sign a session id into a `Set-Cookie` header value: `fr_session=<sid>.<sig>`.
    pub fn sign_session(sid: &str, secret: &str) -> String {
        let sig = hmac_sha256_hex(secret.as_bytes(), sid.as_bytes());
        let b64 = b64url_encode(sid.as_bytes());
        format!(
            "{SESSION_COOKIE}={b64}.{sig}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000"
        )
    }

    /// Verify the request's session cookie and return the session id it carries.
    pub fn verify_session(headers: &HeaderMap, secret: &str) -> Option<String> {
        let raw = cookie_value(headers, SESSION_COOKIE)?;
        let (b64, sig) = raw.split_once('.')?;
        let sid_bytes = b64url_decode(b64)?;
        let sid = String::from_utf8(sid_bytes).ok()?;
        let expected = hmac_sha256_hex(secret.as_bytes(), sid.as_bytes());
        if constant_time_eq(expected.as_bytes(), sig.as_bytes()) {
            Some(sid)
        } else {
            None
        }
    }

    /// Pull one cookie value out of the `Cookie` request header.
    fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
        let header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
        for part in header.split(';') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                if k == name {
                    return Some(v.to_string());
                }
            }
        }
        None
    }

    /// Constant-time byte comparison (avoid signature-timing leaks).
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    // -- URL-safe base64 (no padding), std-only --------------------------------

    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    fn b64url_encode(input: &[u8]) -> String {
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
            out.push(B64[((n >> 18) & 63) as usize] as char);
            out.push(B64[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(B64[((n >> 6) & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(B64[(n & 63) as usize] as char);
            }
        }
        out
    }

    fn b64url_decode(input: &str) -> Option<Vec<u8>> {
        fn val(c: u8) -> Option<u32> {
            match c {
                b'A'..=b'Z' => Some((c - b'A') as u32),
                b'a'..=b'z' => Some((c - b'a' + 26) as u32),
                b'0'..=b'9' => Some((c - b'0' + 52) as u32),
                b'-' => Some(62),
                b'_' => Some(63),
                _ => None,
            }
        }
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(input.len() / 4 * 3 + 2);
        for chunk in bytes.chunks(4) {
            let mut n = 0u32;
            let mut valid = 0;
            for (i, &c) in chunk.iter().enumerate() {
                n |= val(c)? << (18 - 6 * i);
                valid += 1;
            }
            out.push((n >> 16) as u8);
            if valid > 2 {
                out.push((n >> 8) as u8);
            }
            if valid > 3 {
                out.push(n as u8);
            }
        }
        Some(out)
    }

    // -- HMAC-SHA256, std-only -------------------------------------------------

    /// HMAC-SHA256(key, msg) as lowercase hex.
    fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
        const BLOCK: usize = 64;
        let mut k = [0u8; BLOCK];
        if key.len() > BLOCK {
            let d = sha256(key);
            k[..32].copy_from_slice(&d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Vec::with_capacity(BLOCK + msg.len());
        inner.extend_from_slice(&ipad);
        inner.extend_from_slice(msg);
        let inner_hash = sha256(&inner);
        let mut outer = Vec::with_capacity(BLOCK + 32);
        outer.extend_from_slice(&opad);
        outer.extend_from_slice(&inner_hash);
        let mac = sha256(&outer);
        let mut hex = String::with_capacity(64);
        for b in mac {
            hex.push_str(&format!("{b:02x}"));
        }
        hex
    }

    /// SHA-256 (FIPS 180-4), std-only.
    fn sha256(data: &[u8]) -> [u8; 32] {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let bit_len = (data.len() as u64) * 8;
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        for block in msg.chunks(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    block[i * 4],
                    block[i * 4 + 1],
                    block[i * 4 + 2],
                    block[i * 4 + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let mut a = h;
            for i in 0..64 {
                let s1 = a[4].rotate_right(6) ^ a[4].rotate_right(11) ^ a[4].rotate_right(25);
                let ch = (a[4] & a[5]) ^ ((!a[4]) & a[6]);
                let t1 = a[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a[0].rotate_right(2) ^ a[0].rotate_right(13) ^ a[0].rotate_right(22);
                let maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
                let t2 = s0.wrapping_add(maj);
                a[7] = a[6];
                a[6] = a[5];
                a[5] = a[4];
                a[4] = a[3].wrapping_add(t1);
                a[3] = a[2];
                a[2] = a[1];
                a[1] = a[0];
                a[0] = t1.wrapping_add(t2);
            }
            for i in 0..8 {
                h[i] = h[i].wrapping_add(a[i]);
            }
        }

        let mut out = [0u8; 32];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sha256_known_vector() {
            let d = sha256(b"abc");
            let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                hex,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }

        #[test]
        fn hmac_known_vector() {
            let mac = hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?");
            assert_eq!(
                mac,
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
            );
        }

        #[test]
        fn sign_verify_round_trips() {
            let secret = "test-secret";
            let sid = "9f2c-opaque-session-id";
            let cookie = sign_session(sid, secret);
            let pair = cookie.split(';').next().unwrap().to_string();
            let mut headers = HeaderMap::new();
            headers.insert(axum::http::header::COOKIE, pair.parse().unwrap());
            assert_eq!(verify_session(&headers, secret).as_deref(), Some(sid));
            // Wrong secret → rejected (an attacker without the HMAC key can't forge).
            assert!(verify_session(&headers, "other-secret").is_none());
        }

        #[test]
        fn forged_and_tampered_cookies_are_rejected() {
            let secret = "test-secret";

            // 1. A fully forged cookie: attacker knows a victim's DID/sid but not
            //    the secret, so an arbitrary signature must not verify.
            let forged = format!(
                "{SESSION_COOKIE}={}.{}",
                b64url_encode(b"attacker-chosen-sid"),
                "deadbeef".repeat(8) // 64 hex chars, wrong sig
            );
            let mut headers = HeaderMap::new();
            headers.insert(axum::http::header::COOKIE, forged.parse().unwrap());
            assert!(verify_session(&headers, secret).is_none());

            // 2. A tampered cookie: take a VALID cookie and mutate the sid while
            //    keeping the original signature — must not verify.
            let cookie = sign_session("real-sid", secret);
            let pair = cookie.split(';').next().unwrap();
            let (_b64, sig) = pair.split_once('=').unwrap().1.split_once('.').unwrap();
            let tampered = format!(
                "{SESSION_COOKIE}={}.{}",
                b64url_encode(b"different-sid"),
                sig
            );
            let mut headers2 = HeaderMap::new();
            headers2.insert(axum::http::header::COOKIE, tampered.parse().unwrap());
            assert!(verify_session(&headers2, secret).is_none());
        }

        #[test]
        fn b64url_round_trips() {
            for s in ["did:plc:abc", "", "a", "ab", "abc", "abcd"] {
                let enc = b64url_encode(s.as_bytes());
                assert_eq!(b64url_decode(&enc).unwrap(), s.as_bytes());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Small store helpers local to the web layer
// ---------------------------------------------------------------------------

/// Fetch a single cached entry by id.
async fn get_entry_by_id(pool: &store::Pool, id: i64) -> anyhow::Result<Option<store::Entry>> {
    let entry = sqlx::query_as::<_, store::Entry>("SELECT * FROM entries WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(entry)
}

/// Whether `entry_id` is marked read for `did` (absent state row = unread).
async fn entry_is_read(pool: &store::Pool, did: &str, entry_id: i64) -> anyhow::Result<bool> {
    let read: Option<bool> =
        sqlx::query_scalar("SELECT read FROM entry_state WHERE did = ?1 AND entry_id = ?2")
            .bind(did)
            .bind(entry_id)
            .fetch_optional(pool)
            .await?
            .flatten();
    Ok(read.unwrap_or(false))
}

/// Whether `entry_id` is starred for `did` (absent state row = not starred).
async fn entry_is_starred(pool: &store::Pool, did: &str, entry_id: i64) -> anyhow::Result<bool> {
    let starred: Option<bool> =
        sqlx::query_scalar("SELECT starred FROM entry_state WHERE did = ?1 AND entry_id = ?2")
            .bind(did)
            .bind(entry_id)
            .fetch_optional(pool)
            .await?
            .flatten();
    Ok(starred.unwrap_or(false))
}

/// Feed display title for one entry's feed id (via a single lookup).
async fn feed_title_by_entry(pool: &store::Pool, feed_id: i64) -> String {
    match sqlx::query_as::<_, store::Feed>("SELECT * FROM feeds WHERE id = ?1")
        .bind(feed_id)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(f)) => display_title(f.title.as_deref(), &f.url),
        _ => String::new(),
    }
}

/// Rebuild an [`EntryRow`] for an htmx swap after a read/star toggle. `read` may
/// be forced (mark-read path) or looked up (`None` — star path).
async fn build_entry_row(
    pool: &store::Pool,
    did: &str,
    id: i64,
    read: Option<bool>,
) -> anyhow::Result<Option<EntryRow>> {
    let entry = match get_entry_by_id(pool, id).await? {
        Some(e) => e,
        None => return Ok(None),
    };
    let read = match read {
        Some(r) => r,
        None => entry_is_read(pool, did, id).await?,
    };
    let starred = entry_is_starred(pool, did, id).await?;
    Ok(Some(EntryRow {
        id: entry.id,
        title: entry
            .title
            .clone()
            .filter(|t| !t.trim().is_empty())
            .unwrap_or_else(|| "(untitled)".to_string()),
        feed_title: feed_title_by_entry(pool, entry.feed_id).await,
        published: display_date(entry.published.as_deref()),
        read,
        starred,
        link: format!("/entries/{id}"),
    }))
}

/// RFC3339 "now" (UTC) — shared by handlers that stamp/compare timestamps.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qenc_encodes_reserved() {
        assert_eq!(qenc("a b"), "a%20b");
        assert_eq!(
            qenc("https://example.com/feed.xml"),
            "https%3A%2F%2Fexample.com%2Ffeed.xml"
        );
        assert_eq!(
            qenc("at://did:plc:x/c/r"),
            "at%3A%2F%2Fdid%3Aplc%3Ax%2Fc%2Fr"
        );
        // Unreserved chars pass through untouched.
        assert_eq!(qenc("A-Za-z0-9-_.~"), "A-Za-z0-9-_.~");
    }

    #[test]
    fn folder_uri_shape() {
        assert_eq!(
            folder_uri("did:plc:abc", "3kfolder"),
            "at://did:plc:abc/community.lexicon.rss.folder/3kfolder"
        );
    }

    #[test]
    fn scope_query_preserves_context() {
        let q = EntryQuery {
            feed: Some("https://example.com/feed.xml".to_string()),
            folder: None,
            view: Some("all".to_string()),
        };
        let s = scope_query(&q);
        assert!(s.contains("feed=https%3A%2F%2Fexample.com%2Ffeed.xml"));
        assert!(s.contains("view=all"));

        // Default view is omitted.
        let q2 = EntryQuery {
            feed: None,
            folder: None,
            view: Some("unread".to_string()),
        };
        assert_eq!(scope_query(&q2), "");
    }
}
