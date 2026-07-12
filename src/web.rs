//! The axum web layer — server-rendered HTML + a dash of htmx, **no SPA**.
//!
//! This module owns the HTTP surface: [`router`] builds an [`axum::Router`] over
//! the shared [`AppState`], wiring the store, feed, atproto, and config seams into
//! a small set of typography-first, dark-mode-ready views rendered with
//! [`askama`] templates (under `templates/`). Progressive enhancement is a single
//! vendored `htmx` script; every interaction also works as a plain HTML form POST,
//! so the reader is fully usable with JavaScript disabled (design §4).
//!
//! ## Phase 0 scope
//!
//! * `GET  /health` — liveness + version, as `text/plain`.
//! * `GET  /` — the reader: the current user's folders/feeds plus their unread
//!   entries, pulled from the [`crate::store`] cache.
//! * `GET  /entries/:id` — the clean, distraction-free reader view for one entry.
//! * `POST /subscriptions` — subscribe by URL: fetch/autodiscover the feed, poll
//!   it once into the cache, and write a `community.lexicon.rss.subscription`
//!   record to the user's PDS (scaffolded behind the auth seam, see below).
//! * `POST /entries/:id/read` — mark an entry read/unread via the store; returns
//!   the swapped entry row for htmx (and redirects back for the no-JS path).
//! * `GET /login` + `POST /login` — the atproto auth seam. Phase 0 exercises the
//!   **interim app-password** path (`com.atproto.server.createSession`); the real
//!   **OAuth confidential-client** flow is a documented TODO (see [`login`]).
//!
//! ## The dev identity seam
//!
//! Real per-request identity comes from an atproto session cookie once the OAuth
//! sidecar lands. Until then the reader renders for a single **dev DID**
//! ([`DEV_DID`]) so the store-backed views are exercisable end-to-end. Every
//! handler already threads the DID through [`current_did`], so swapping the dev
//! constant for a cookie-resolved session is a one-function change.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::config::Config;
use crate::lexicon::Subscription;
use crate::{feed, store, AppState, VERSION};

/// The interim single-user identity the reader renders for until the atproto
/// OAuth sidecar resolves a real session from the request cookie.
///
/// Everything in the store is keyed by DID, so this is the one place the
/// "who is the current user" seam is stubbed; [`current_did`] is the sole reader.
const DEV_DID: &str = "did:plc:featherreader-dev";

/// Resolve the DID for the current request.
///
/// **Phase 0:** returns the fixed [`DEV_DID`]. The real implementation reads the
/// signed atproto session cookie (set by the OAuth callback / interim login) and
/// resolves it to the logged-in DID + handle; the type stays `&str` so callers
/// don't change when that lands.
fn current_did(_state: &AppState) -> &'static str {
    DEV_DID
}

/// Build the application router over shared [`AppState`].
///
/// Wires the reader routes, the health check, and the `/static` asset mount
/// (the one stylesheet + vendored htmx, served from `static/` via
/// [`ServeDir`]). A [`TraceLayer`] gives per-request tracing. `main` binds and
/// serves the returned router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/", get(index))
        .route("/entries/{id}", get(entry_view))
        .route("/entries/{id}/read", post(mark_read))
        .route("/subscriptions", post(add_subscription))
        .route("/login", get(login_form).post(login))
        .nest_service("/static", ServeDir::new("static"))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

/// `GET /health` — a cheap liveness probe returning `200 ok` + the crate version.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, format!("ok featherreader/{VERSION}\n"))
}

// ---------------------------------------------------------------------------
// View models
// ---------------------------------------------------------------------------

/// A feed as shown in the sidebar (title + its unread count).
struct FeedView {
    title: String,
    unread: i64,
}

/// A folder grouping in the sidebar. Phase 0 has no folder records wired to the
/// cache yet, so the reader renders every feed loose; the shape is here so the
/// PDS-folder wiring drops in without a template change.
struct FolderView {
    name: String,
    feeds: Vec<FeedView>,
}

/// One entry as shown in the unread list / after an htmx mark-read swap.
struct EntryRow {
    id: i64,
    title: String,
    feed_title: String,
    published: String,
    read: bool,
}

/// The reader index (`GET /`).
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    version: &'static str,
    did: String,
    handle: Option<String>,
    flash: String,
    folders: Vec<FolderView>,
    loose_feeds: Vec<FeedView>,
    entries: Vec<EntryRow>,
}

/// The single-entry reader view (`GET /entries/:id`).
#[derive(Template)]
#[template(path = "entry.html")]
struct EntryTemplate {
    version: &'static str,
    did: String,
    handle: Option<String>,
    id: i64,
    title: String,
    feed_title: String,
    author: Option<String>,
    published: String,
    url: Option<String>,
    content_html: Option<String>,
    read: bool,
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
    version: &'static str,
    did: String,
    handle: Option<String>,
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
/// still return an `impl IntoResponse`. Renders as a `500` with a short message;
/// the detail goes to the log, not the user.
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

/// Trim a stored RFC3339 timestamp down to the `YYYY-MM-DD` date for calm,
/// low-noise display. Falls back to the raw string if it doesn't look like one.
fn display_date(published: Option<&str>) -> String {
    match published {
        Some(p) if p.len() >= 10 => p[..10].to_string(),
        Some(p) => p.to_string(),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Reader: index
// ---------------------------------------------------------------------------

/// `GET /` — the reader. Lists the current DID's cached feeds (with per-feed
/// unread counts) alongside the flat unread-entry timeline, newest first.
///
/// Feeds/entries come from the shared [`crate::store`] cache; read-state is the
/// per-DID working copy. Folder grouping is modelled but empty in Phase 0 (the
/// PDS `community.lexicon.rss.folder` records aren't projected into the cache
/// yet), so every feed renders loose.
async fn index(State(state): State<AppState>) -> Result<Response, WebError> {
    let did = current_did(&state).to_string();
    let pool = &state.db;

    // Unread entries for this DID (newest-published first), plus their feed
    // titles for the list rows.
    let unread = store::get_unread_for_did(pool, &did).await?;

    // Build the sidebar from every cached feed with this DID's unread count.
    let now = now_rfc3339();
    let feeds = store::due_feeds(pool, &now, i64::MAX).await.unwrap_or_default();
    let mut loose_feeds = Vec::with_capacity(feeds.len());
    for f in &feeds {
        let unread_here = unread.iter().filter(|e| e.feed_id == f.id).count() as i64;
        loose_feeds.push(FeedView {
            title: display_title(f.title.as_deref(), &f.url),
            unread: unread_here,
        });
    }

    // Map entries to rows, resolving each feed's display title once.
    let mut entries = Vec::with_capacity(unread.len());
    for e in &unread {
        let feed_title = feeds
            .iter()
            .find(|f| f.id == e.feed_id)
            .map(|f| display_title(f.title.as_deref(), &f.url))
            .unwrap_or_default();
        entries.push(EntryRow {
            id: e.id,
            title: e
                .title
                .clone()
                .filter(|t| !t.trim().is_empty())
                .unwrap_or_else(|| "(untitled)".to_string()),
            feed_title,
            published: display_date(e.published.as_deref()),
            read: false,
        });
    }

    let tmpl = IndexTemplate {
        version: VERSION,
        did,
        handle: None,
        flash: String::new(),
        folders: Vec::<FolderView>::new(),
        loose_feeds,
        entries,
    };
    Ok(render(&tmpl))
}

// ---------------------------------------------------------------------------
// Reader: single entry
// ---------------------------------------------------------------------------

/// `GET /entries/:id` — the clean reader view for one entry.
///
/// Renders just title, source, date, and the (already-sanitized) body — the
/// distraction-free reading surface that is the product (design §6). Reading an
/// entry does **not** auto-mark it read in Phase 0; that's an explicit action.
async fn entry_view(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, WebError> {
    let did = current_did(&state).to_string();
    let pool = &state.db;

    let entry = match get_entry_by_id(pool, id).await? {
        Some(e) => e,
        None => return Ok((StatusCode::NOT_FOUND, "entry not found").into_response()),
    };

    // Feed title for the byline.
    let feed_title = store::due_feeds(pool, &now_rfc3339(), i64::MAX)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|f| f.id == entry.feed_id)
        .map(|f| display_title(f.title.as_deref(), &f.url))
        .unwrap_or_default();

    let read = entry_is_read(pool, &did, id).await?;

    let tmpl = EntryTemplate {
        version: VERSION,
        did,
        handle: None,
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
    };
    Ok(render(&tmpl))
}

// ---------------------------------------------------------------------------
// Mark read / unread
// ---------------------------------------------------------------------------

/// Form body for `POST /entries/:id/read`.
#[derive(Debug, Deserialize)]
struct ReadForm {
    /// Desired read state as a string (`"true"` / `"false"`) — plain HTML forms
    /// can't send a real bool. Defaults to marking read when absent.
    #[serde(default)]
    read: Option<String>,
}

/// `POST /entries/:id/read` — toggle an entry's read-state for the current DID.
///
/// Writes through [`store::mark_read`] (the fast local working copy the v1.1
/// batched flusher later syncs to the PDS). For an htmx request (`HX-Request`
/// header) it returns the re-rendered entry row so the list updates in place;
/// for a plain form POST it redirects back to the reader.
async fn mark_read(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: axum::http::HeaderMap,
    Form(form): Form<ReadForm>,
) -> Result<Response, WebError> {
    let did = current_did(&state).to_string();
    let pool = &state.db;

    let read = matches!(form.read.as_deref(), Some("true") | Some("1") | Some("on") | None);
    store::mark_read(pool, &did, id, read).await?;

    let is_htmx = headers
        .get("HX-Request")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"true"));

    if !is_htmx {
        return Ok(Redirect::to("/").into_response());
    }

    // Re-render just this row so htmx can swap it (outerHTML).
    let entry = match get_entry_by_id(pool, id).await? {
        Some(e) => e,
        None => return Ok((StatusCode::NOT_FOUND, "entry not found").into_response()),
    };
    let feed_title = store::due_feeds(pool, &now_rfc3339(), i64::MAX)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|f| f.id == entry.feed_id)
        .map(|f| display_title(f.title.as_deref(), &f.url))
        .unwrap_or_default();

    let row = EntryRowTemplate {
        e: EntryRow {
            id: entry.id,
            title: entry
                .title
                .clone()
                .filter(|t| !t.trim().is_empty())
                .unwrap_or_else(|| "(untitled)".to_string()),
            feed_title,
            published: display_date(entry.published.as_deref()),
            read,
        },
    };
    Ok(render(&row))
}

// ---------------------------------------------------------------------------
// Subscribe by URL
// ---------------------------------------------------------------------------

/// Form body for `POST /subscriptions`.
#[derive(Debug, Deserialize)]
struct SubscribeForm {
    /// A feed URL *or* a site URL (autodiscovery finds the feed).
    url: String,
}

/// `POST /subscriptions` — subscribe by URL.
///
/// The flow (design §3/§5): (1) resolve the input to a real feed URL — if the
/// pasted page is HTML, run [`feed::discover_feed`] to find its
/// `<link rel="alternate">` feed; (2) upsert the feed into the shared cache and
/// [`feed::poll_feed`] it once so entries show immediately; (3) write a
/// `community.lexicon.rss.subscription` record to the user's PDS — the source of
/// truth for the follow-list.
///
/// **Auth seam:** step (3) needs an authenticated [`crate::atproto::PdsClient`]
/// for the current session. Phase 0 has no live session wired into [`AppState`]
/// (that arrives with the OAuth sidecar), so the PDS write is a documented TODO:
/// the subscription is cached + polled locally and the record-write is logged as
/// pending. The [`Subscription`] record is still constructed here so the shape is
/// exercised and the call site is ready.
async fn add_subscription(
    State(state): State<AppState>,
    Form(form): Form<SubscribeForm>,
) -> Result<Response, WebError> {
    let pool = &state.db;
    let input = form.url.trim().to_string();
    if input.is_empty() {
        return Ok(Redirect::to("/").into_response());
    }

    // Resolve input → canonical feed URL (autodiscovery if it's a site page).
    let feed_url = match resolve_feed_url(&state.config, &input).await {
        Ok(u) => u,
        Err(err) => {
            warn!(%err, url = %input, "could not resolve a feed from the given URL");
            return Ok(Redirect::to("/").into_response());
        }
    };

    // Cache the feed row, then poll it once so entries appear immediately.
    let feed_id = store::upsert_feed(
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

    // Construct the PDS subscription record (the source of truth).
    let sub = Subscription::new(feed_url.clone(), now_rfc3339());

    // TODO(oauth-sidecar): write `sub` to the user's PDS via an authenticated
    // atproto::PdsClient once a live session is threaded through AppState. Until
    // then the follow-list truth lives only in the local cache; the record is
    // built above so this call site is ready to drop in:
    //     pds_client.create_subscription(&sub).await?;
    let _ = (&sub, feed_id);
    info!(feed = %feed_url, "subscription cached; PDS record write pending OAuth sidecar (TODO)");

    Ok(Redirect::to("/").into_response())
}

/// Resolve a user-pasted URL to a canonical feed URL: if fetching it yields a
/// feed document we take it as-is; if it yields an HTML page we run
/// autodiscovery over its `<link rel="alternate">` tags.
///
/// Kept intentionally small (design bias: boring, small-dependency). A HEAD-less
/// GET is fine here — the body is needed for autodiscovery anyway.
async fn resolve_feed_url(_config: &Config, input: &str) -> anyhow::Result<String> {
    let parsed = url::Url::parse(input)
        .map_err(|e| anyhow::anyhow!("not a valid URL {input:?}: {e}"))?;

    let client = feed::build_client()?;
    let resp = client.get(parsed.clone()).send().await?;
    let final_url = resp.url().clone();
    let content_type = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let body = resp.text().await?;

    // If it smells like a feed already (by content-type or a leading XML/JSON
    // feed marker), use the URL as-is.
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

    // Otherwise treat it as HTML and autodiscover.
    match feed::discover_feed(&body, Some(&final_url)) {
        Some(u) => Ok(u.to_string()),
        None => anyhow::bail!("no feed found at {input} (no autodiscovery link)"),
    }
}

// ---------------------------------------------------------------------------
// Login (atproto auth seam)
// ---------------------------------------------------------------------------

/// `GET /login` — the atproto login stub.
async fn login_form(State(state): State<AppState>) -> Response {
    let _ = &state;
    render(&LoginTemplate {
        version: VERSION,
        did: DEV_DID.to_string(),
        handle: None,
        error: String::new(),
    })
}

/// Form body for `POST /login`.
#[derive(Debug, Deserialize)]
struct LoginPost {
    handle: String,
    app_password: String,
}

/// `POST /login` — the interim app-password auth path (the Phase-0 seam).
///
/// Exercises the real atproto session handshake:
/// [`crate::atproto::PdsClient::login`] resolves the handle → DID → PDS and
/// obtains a `com.atproto.server.createSession` session. On success the DID is
/// checked against the instance's [`Config::allowed_dids`] allow-list.
///
/// **What's a documented TODO, not this seam:** persisting the resulting session
/// (a signed cookie + a session registry in [`AppState`]) and, ultimately,
/// replacing app-password with the atproto **OAuth confidential-client** flow via
/// the `@atproto/oauth-client` sidecar (design §4; gaming-SDK prior art). Phase 0
/// validates the credentials and then returns to the reader; it does not yet mint
/// a durable session, so the reader continues under the dev DID.
async fn login(
    State(state): State<AppState>,
    Form(form): Form<LoginPost>,
) -> Response {
    let handle = form.handle.trim();
    let app_password = form.app_password.trim();

    let client = match feed::build_client() {
        Ok(c) => c,
        Err(err) => return login_error(&format!("could not build HTTP client: {err}")),
    };

    match crate::atproto::PdsClient::login(client, handle, app_password, None, None).await {
        Ok(pds) => {
            let did = pds.did().to_string();
            if !state.config.did_allowed(&did) {
                warn!(%did, "login rejected: DID not on the instance allow-list");
                return login_error("This instance's allow-list does not permit that account.");
            }
            info!(%did, handle, "interim app-password login OK (session persistence: TODO oauth-sidecar)");
            // TODO(oauth-sidecar): mint a signed session cookie + register the
            // PdsClient in AppState so subsequent requests act as this DID.
            Redirect::to("/").into_response()
        }
        Err(err) => {
            warn!(%err, handle, "interim login failed");
            login_error("Login failed — check the handle and app password.")
        }
    }
}

/// Re-render the login form with an error banner.
fn login_error(msg: &str) -> Response {
    render(&LoginTemplate {
        version: VERSION,
        did: DEV_DID.to_string(),
        handle: None,
        error: msg.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Small store helpers local to the web layer
// ---------------------------------------------------------------------------

/// Fetch a single cached entry by id. A thin `query_as` over the store's pool;
/// lives here (not in `store`) because it's a web-render convenience, not part of
/// the store's read/write API surface.
async fn get_entry_by_id(
    pool: &store::Pool,
    id: i64,
) -> anyhow::Result<Option<store::Entry>> {
    let entry = sqlx::query_as::<_, store::Entry>("SELECT * FROM entries WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(entry)
}

/// Whether `entry_id` is marked read for `did` (absent state row = unread).
async fn entry_is_read(pool: &store::Pool, did: &str, entry_id: i64) -> anyhow::Result<bool> {
    let read: Option<bool> = sqlx::query_scalar(
        "SELECT read FROM entry_state WHERE did = ?1 AND entry_id = ?2",
    )
    .bind(did)
    .bind(entry_id)
    .fetch_optional(pool)
    .await?
    .flatten();
    Ok(read.unwrap_or(false))
}

/// RFC3339 "now" (UTC) — shared by handlers that stamp/compare timestamps.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
