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
//! ## Identity — a cookie-resolved atproto session
//!
//! Per-request identity comes from a **signed session cookie** (`fr_session`)
//! keyed by the logged-in DID. The cookie is set by [`oauth_callback`] once the
//! OAuth sidecar resolves a one-shot `session_id` to `{did, handle}`, and read on
//! every request by [`current_session`] / [`current_did`]. For local runs without
//! the sidecar, [`Config::dev_did`] (env `FEATHERREADER_DEV_DID`) supplies a
//! fallback identity when no valid cookie is present; unset (the default) means
//! "no session → logged out".

use askama::Template;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
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
use crate::{feed, store, AppState, Session, VERSION};

/// The name of the signed session cookie.
const SESSION_COOKIE: &str = "fr_session";

/// The resolved identity for the current request.
///
/// `did` is the primary key for all per-user local state; `handle` is display
/// only. Sourced from the signed cookie (real login) or, if none, the configured
/// dev DID fallback.
#[derive(Clone, Debug)]
struct CurrentUser {
    did: String,
    handle: Option<String>,
}

/// Resolve the current request's session from the signed cookie, falling back to
/// the configured dev DID (env `FEATHERREADER_DEV_DID`) for local runs.
///
/// Verifies the cookie's HMAC signature against [`Config::cookie_secret`] and
/// looks the DID up in the [`crate::SessionRegistry`] for its handle. Returns
/// `None` when there is neither a valid cookie nor a dev fallback (logged out).
fn current_session(state: &AppState, headers: &HeaderMap) -> Option<CurrentUser> {
    if let Some(did) = cookie::verify_session(headers, &state.config.cookie_secret) {
        let handle = state.sessions.get(&did).and_then(|s| s.handle);
        return Some(CurrentUser { did, handle });
    }
    // No valid cookie: dev fallback only if explicitly configured.
    state.config.dev_did.clone().map(|did| {
        let handle = state.sessions.get(&did).and_then(|s| s.handle);
        CurrentUser { did, handle }
    })
}

/// The current request's DID, or `None` when logged out (no cookie, no dev DID).
fn current_did(state: &AppState, headers: &HeaderMap) -> Option<String> {
    current_session(state, headers).map(|u| u.did)
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
        .route("/opml", post(import_opml))
        .route("/login", get(login_form).post(login_submit))
        .route("/oauth/callback", get(oauth_callback))
        .route("/logout", post(logout))
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
async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    // Logged out → send to login.
    let user = match current_session(&state, &headers) {
        Some(u) => u,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let did = user.did.clone();
    let pool = &state.db;

    // Reconcile the user's ACTUAL subscriptions (source of truth = their PDS)
    // with the local cache: for any subscription record present in the PDS but
    // not yet cached, upsert the feed row so the sidebar reflects the real
    // follow-list even on a fresh cache. Best-effort — if the sidecar is
    // unreachable we fall back to whatever the local cache already holds.
    match state.sidecar.list_subscriptions(&did).await {
        Ok(subs) => {
            for (_rkey, sub) in &subs {
                if let Ok(None) = store::get_feed_by_url(pool, &sub.url).await {
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
                }
            }
        }
        Err(err) => warn!(%err, %did, "could not list PDS subscriptions; showing local cache only"),
    }

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
        handle: user.handle,
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
    headers: HeaderMap,
    Path(id): Path<i64>,
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
        handle: user.handle,
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
    headers: HeaderMap,
    Form(form): Form<ReadForm>,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };
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
/// Step (3) is the live path: the [`crate::atproto::SidecarClient`] POSTs a
/// `create` op to the sidecar's `/internal/repo` for the current DID, which
/// restores the OAuth session and writes the record to the user's own PDS. The
/// PDS is the source of truth; the local cache/poll is just the fast working copy.
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

    // Write the subscription record to the user's PDS (the source of truth) via
    // the OAuth sidecar. Enrich the record with the feed's own title/site once
    // the initial poll has populated the cache row.
    let mut sub = Subscription::new(feed_url.clone(), now_rfc3339());
    if let Ok(Some(feed_row)) = store::get_feed_by_url(pool, &feed_url).await {
        sub.title = feed_row.title.clone();
        sub.site_url = feed_row.site_url.clone();
    }
    let _ = feed_id;

    match state.sidecar.create_subscription(&did, &sub).await {
        Ok(res) => info!(feed = %feed_url, uri = %res.uri, %did, "wrote subscription record to PDS"),
        Err(err) => {
            // Cache/poll already succeeded locally; surface the PDS write failure
            // in the log but don't lose the local subscription.
            warn!(%err, feed = %feed_url, %did, "PDS subscription write failed (cached locally)");
        }
    }

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
// Login (atproto OAuth via the sidecar)
// ---------------------------------------------------------------------------

/// Query for `GET /login`.
#[derive(Debug, Deserialize, Default)]
struct LoginQuery {
    /// Optional handle: when present we redirect straight to the sidecar's OAuth
    /// flow. Absent → render the handle-entry form.
    #[serde(default)]
    handle: Option<String>,
    /// Optional error banner (e.g. bounced back from the callback on failure).
    #[serde(default)]
    error: Option<String>,
}

/// `GET /login` — start the atproto OAuth flow, or render the handle form.
///
/// With a `?handle=…`, redirect the browser straight to the sidecar's
/// `/login?handle=…` endpoint (resolve → PAR → PKCE → the PDS authorize page).
/// Without one, render the handle-entry form. The sidecar ultimately bounces the
/// browser back to this app's [`oauth_callback`].
async fn login_form(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<LoginQuery>,
) -> Response {
    if let Some(handle) = q.handle.map(|h| h.trim().to_string()).filter(|h| !h.is_empty()) {
        return start_oauth(&state, &handle);
    }
    render(&LoginTemplate {
        version: VERSION,
        did: String::new(),
        handle: None,
        error: q.error.unwrap_or_default(),
    })
}

/// `POST /login` — the handle-form submit: redirect into the sidecar OAuth flow.
async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Response {
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

/// Form body for `POST /login` (just the handle — no password; OAuth happens at
/// the PDS, not here).
#[derive(Debug, Deserialize)]
struct LoginForm {
    handle: String,
}

/// Query for `GET /oauth/callback` — the app's OWN callback the sidecar bounces
/// the browser to after the OAuth dance (distinct from the sidecar's PDS-facing
/// `/callback`). Carries either a one-shot `session_id` or an error.
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
///
/// The sidecar has completed OAuth and redirected here with a one-shot
/// `session_id`. We resolve it via the sidecar's `/internal/session/:id` to
/// `{did, handle}`, enforce the instance allow-list, register the session, and
/// set a signed cookie keyed by the DID. Subsequent requests act as that DID.
async fn oauth_callback(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<CallbackQuery>,
) -> Response {
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

    // Register the session (DID → handle) and set the signed cookie.
    state.sessions.insert(Session {
        did: session.did.clone(),
        handle: session.handle.clone(),
    });
    let cookie = cookie::sign_session(&session.did, &state.config.cookie_secret);
    info!(did = %session.did, handle = ?session.handle, "OAuth login OK; session cookie set");

    let mut resp = Redirect::to("/").into_response();
    set_cookie(&mut resp, &cookie);
    resp
}

/// `POST /logout` — clear the session cookie + drop the in-memory session.
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(did) = current_did(&state, &headers) {
        state.sessions.remove(&did);
    }
    let mut resp = Redirect::to("/login").into_response();
    // An expired, empty cookie clears it in the browser.
    set_cookie(
        &mut resp,
        &format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"),
    );
    resp
}

/// Re-render the login form with an error banner.
fn login_error(msg: &str) -> Response {
    render(&LoginTemplate {
        version: VERSION,
        did: String::new(),
        handle: None,
        error: msg.to_string(),
    })
}

// ---------------------------------------------------------------------------
// OPML import
// ---------------------------------------------------------------------------

/// Form body for `POST /opml` — a pasted OPML document (the migration on-ramp).
#[derive(Debug, Deserialize)]
struct OpmlForm {
    /// The raw OPML XML (from a textarea or an uploaded file's contents).
    opml: String,
}

/// `POST /opml` — import subscriptions from an OPML document.
///
/// Extracts every `xmlUrl` feed URL from the OPML `<outline>` tree and creates a
/// `community.lexicon.rss.subscription` record per feed in the user's PDS in a
/// single **batched `applyWrites`** round-trip (design §3: "OPML import creates a
/// subscription record per feed in the user's PDS"). Feeds are also upserted into
/// the local cache so they show immediately; the initial poll is left to the
/// background poller / a subsequent visit.
async fn import_opml(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<OpmlForm>,
) -> Result<Response, WebError> {
    let did = match current_did(&state, &headers) {
        Some(d) => d,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let pool = &state.db;

    let feeds = parse_opml(&form.opml);
    if feeds.is_empty() {
        info!(%did, "OPML import found no feeds");
        return Ok(Redirect::to("/").into_response());
    }

    // Build one subscription record per feed and upsert the local cache row.
    let now = now_rfc3339();
    let mut subs = Vec::with_capacity(feeds.len());
    for (url, title, site) in &feeds {
        let mut sub = Subscription::new(url.clone(), now.clone());
        sub.title = title.clone();
        sub.site_url = site.clone();
        subs.push(sub);
        let _ = store::upsert_feed(
            pool,
            &store::NewFeed {
                url: url.clone(),
                title: title.clone(),
                site_url: site.clone(),
                ..Default::default()
            },
        )
        .await;
    }

    match state.sidecar.create_subscriptions_batch(&did, &subs).await {
        Ok(()) => info!(%did, count = subs.len(), "imported OPML subscriptions to PDS (batched)"),
        Err(err) => warn!(%err, %did, "OPML PDS batch write failed (feeds cached locally)"),
    }

    Ok(Redirect::to("/").into_response())
}

/// Extract `(xmlUrl, title, htmlUrl)` triples from an OPML document.
///
/// A deliberately small, dependency-free scan of the `<outline …>` elements'
/// attributes (OPML feed outlines carry `xmlUrl`; `title`/`text` and `htmlUrl`
/// are optional). Robust enough for the common exports (Feedly, Inoreader,
/// NetNewsWire) without pulling in a full XML parser.
fn parse_opml(xml: &str) -> Vec<(String, Option<String>, Option<String>)> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<outline") {
        rest = &rest[start + "<outline".len()..];
        // The attribute run ends at the tag close.
        let end = rest.find('>').unwrap_or(rest.len());
        let attrs = &rest[..end];
        rest = &rest[end..];
        if let Some(xml_url) = opml_attr(attrs, "xmlUrl") {
            if xml_url.is_empty() {
                continue;
            }
            let title = opml_attr(attrs, "title")
                .or_else(|| opml_attr(attrs, "text"))
                .filter(|s| !s.is_empty());
            let site = opml_attr(attrs, "htmlUrl").filter(|s| !s.is_empty());
            out.push((xml_url, title, site));
        }
    }
    out
}

/// Read one double-quoted attribute value out of an OPML `<outline>` attribute
/// run, un-escaping the handful of XML entities feed exporters emit.
fn opml_attr(attrs: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let idx = attrs.find(&needle)? + needle.len();
    let tail = &attrs[idx..];
    let close = tail.find('"')?;
    Some(unescape_xml(&tail[..close]))
}

/// Minimal XML entity un-escaping for OPML attribute values.
fn unescape_xml(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
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

/// A tiny, self-contained signed-cookie layer: HMAC-SHA256 over the DID, so a
/// tampered cookie is rejected. No external crypto dependency — SHA-256 + HMAC
/// are implemented here against std only (the DID + a signature is all we store;
/// no secrets ride in the cookie).
mod cookie {
    use super::{HeaderMap, SESSION_COOKIE};

    /// Sign a DID into a `Set-Cookie` header value: `fr_session=<did>.<sig>`.
    pub fn sign_session(did: &str, secret: &str) -> String {
        let sig = hmac_sha256_hex(secret.as_bytes(), did.as_bytes());
        let b64 = b64url_encode(did.as_bytes());
        format!(
            "{SESSION_COOKIE}={b64}.{sig}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000"
        )
    }

    /// Verify the request's session cookie and return the DID it carries, or
    /// `None` if the cookie is absent, malformed, or the signature doesn't match.
    pub fn verify_session(headers: &HeaderMap, secret: &str) -> Option<String> {
        let raw = cookie_value(headers, SESSION_COOKIE)?;
        let (b64, sig) = raw.split_once('.')?;
        let did_bytes = b64url_decode(b64)?;
        let did = String::from_utf8(did_bytes).ok()?;
        let expected = hmac_sha256_hex(secret.as_bytes(), did.as_bytes());
        if constant_time_eq(expected.as_bytes(), sig.as_bytes()) {
            Some(did)
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
        let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
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
        // Normalize the key to one block.
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

        // Pad.
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
            // SHA-256("abc") — the FIPS 180-4 example.
            let d = sha256(b"abc");
            let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                hex,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }

        #[test]
        fn hmac_known_vector() {
            // RFC 4231 test case 2: key="Jefe", data="what do ya want for nothing?".
            let mac = hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?");
            assert_eq!(
                mac,
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
            );
        }

        #[test]
        fn sign_verify_round_trips() {
            let secret = "test-secret";
            let cookie = sign_session("did:plc:abc123", secret);
            // Extract just the `name=value` pair for the request-side header.
            let pair = cookie.split(';').next().unwrap().to_string();
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::COOKIE,
                pair.parse().unwrap(),
            );
            assert_eq!(
                verify_session(&headers, secret).as_deref(),
                Some("did:plc:abc123")
            );
            // Wrong secret → rejected.
            assert!(verify_session(&headers, "other-secret").is_none());
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
