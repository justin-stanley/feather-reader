//! The one place the two repo backends are chosen between, and timed.
//!
//! Every `com.atproto.repo.*` call the reader makes goes through here, so the
//! cutover is a single `match` rather than a swap at twelve call sites — and,
//! just as importantly, both backends are measured at the same boundary by the
//! same wrapper. Timers placed separately on each path would be comparing the
//! timers.
//!
//! The method list mirrors [`crate::atproto::SidecarClient`]'s reader surface
//! exactly, because that is what `web.rs` already calls. Anything that had to be
//! reshaped to fit would be a divergence between the two clients, and those
//! belong in `xrpc.rs` where both can share the fix.

use anyhow::{Context as _, Result};

use crate::lexicon::{Folder, ReadState, Saved, Subscription};
use crate::metrics::{timed, Backend};
use crate::oauth;
use crate::AppState;

/// A dispatcher bound to one request's state.
pub struct Repo<'a> {
    state: &'a AppState,
}

impl AppState {
    /// The repo client for this request, on whichever backend is configured.
    pub fn repo(&self) -> Repo<'_> {
        Repo { state: self }
    }
}

impl Repo<'_> {
    fn backend(&self) -> Backend {
        self.state.config.repo_backend
    }

    /// The Rust client's runtime, or a clear error naming what is missing.
    ///
    /// Only reachable with the Rust backend selected; startup refuses that
    /// combination when the runtime could not be built, so this is a
    /// belt-and-braces path rather than the expected failure point.
    fn rust(&self) -> Result<&oauth::runtime::OauthRuntime> {
        self.state
            .oauth
            .as_deref()
            .context("the rust repo backend is selected but its OAuth runtime is not configured")
    }

    /// Whether `did` has a session this backend could actually use.
    ///
    /// **A precondition check, not a repo operation — deliberately NOT wrapped
    /// in `timed()`.** The background flusher calls this every round for every
    /// DID holding dirty read-state; counting it would re-inflate the very
    /// `flush_read_states` error count this exists to stop polluting (#117).
    ///
    /// Existence only: no decrypt, no staleness check, no refresh. A session
    /// that is present but expired still counts as usable here, because the
    /// refresh path is exactly what `session()` will do about it. The question
    /// being answered is narrower — is there anything at all to work with, or
    /// is this DID parked until the user signs in again?
    ///
    /// **The sidecar arm answers `true` unconditionally**, preserving today's
    /// behaviour on that backend rather than guessing. The sidecar owns its own
    /// session store and answering honestly would mean a loopback round trip per
    /// DID per minute; prod runs `rust`, and that arm is deleted by #18.
    pub async fn has_session(&self, did: &str) -> Result<bool> {
        match self.backend() {
            Backend::Sidecar => Ok(true),
            Backend::Rust => {
                let found: Option<(i64,)> =
                    sqlx::query_as("SELECT 1 FROM oauth_session WHERE sub = ?1")
                        .bind(did)
                        .fetch_optional(&self.state.db)
                        .await
                        .with_context(|| format!("checking for an OAuth session for {did}"))?;
                Ok(found.is_some())
            }
        }
    }

    /// Load a usable session for `did`, refreshing only when it is actually
    /// stale.
    ///
    /// **Discovery is deferred to the refresh path.** Building the refresh
    /// context eagerly would mean an authorization-server metadata fetch on
    /// every repo call, which is both wasteful and would make the Rust backend
    /// look slow in the comparison for a reason that is an artefact of the
    /// wiring rather than the implementation. A live session needs no discovery
    /// at all.
    async fn session(&self, did: &str) -> Result<oauth::store::OAuthSession> {
        let rust = self.rust()?;
        let now = crate::store::now_unix();

        let session = oauth::store::get_session(&self.state.db, &rust.codec, did)
            .await?
            .with_context(|| format!("no OAuth session for {did}"))?;
        if !oauth::token::is_stale(session.expires_at, now) {
            return Ok(session);
        }

        // **`oauth_refresh` is timed from HERE, and that placement is the whole
        // point.** It sits after the `is_stale` early return, so it still counts
        // refreshes rather than every repo call — but it now also covers
        // DISCOVERY, which runs only on this branch and is therefore part of the
        // refresh.
        //
        // A review found the earlier placement (inside `valid_session`) missed
        // every refresh that failed in discovery: an unreachable PDS, and the
        // issuer-mismatch check below. Those are the two likeliest refresh
        // outages in production, and they recorded nothing at all — leaving
        // exactly the situation this metric exists to end, where the only trace
        // is an error on whatever repo call happened to trigger it.
        //
        // The cost is that a caller which waits behind another task's refresh
        // and then finds the session already fresh still records one. That is
        // the right trade: it did perform a discovery round trip, and
        // over-counting successes is harmless where under-counting failures is
        // not.
        let metrics = &self.state.metrics;
        crate::metrics::timed(metrics, Backend::Rust, "oauth_refresh", async {
            // Stale: now the token endpoint is genuinely needed. `valid_session`
            // re-reads under the subject lock, so a concurrent refresh that lands
            // between the check above and the lock below is handled there rather
            // than here.
            let server = oauth::discovery::discover(
                &self.state.http,
                &session.aud,
                rust.auth_method.as_str(),
                // The grant's own issuer. Checked inside `discover` now, so no
                // caller can omit it — this one and the callback remembered, and
                // revocation did not.
                Some(&session.issuer),
            )
            .await?;

            // **The re-discovered issuer must be the one this session was issued
            // by.** This is the worse of the two instances of the same hole: the
            // refresh path sends the REFRESH TOKEN — long-lived, and the credential
            // that mints every other one — to whatever endpoint discovery returns,
            // and the session's stored issuer was being compared against nothing.
            //
            // Discovery's own checks are all internally consistent, so a hostile
            // pair of documents satisfies every one of them. `store.rs` names this
            // exact threat as the reason `issuer` is AAD-bound; the AAD protects the
            // column from local tampering, and only this protects it from a network
            // re-read.
            //

            let ctx = oauth::session::RefreshContext {
                token_endpoint: &server.token_endpoint,
                client_id: &rust.client_id,
                auth_method: rust.auth_method,
                client_key: rust.client_key.as_ref(),
            };
            oauth::session::valid_session(
                &self.state.db,
                &rust.codec,
                &self.state.http,
                &rust.locks,
                did,
                &ctx,
                now,
            )
            .await
        })
        .await
    }

    /// The owned pieces an [`oauth::xrpc::Repo`] borrows.
    ///
    /// Returned owned rather than assembled here because `Repo` borrows both,
    /// and a borrow cannot outlive the call that created what it points at. The
    /// dispatch macro builds the handle in the caller's scope instead.
    async fn rust_parts(
        &self,
        did: &str,
    ) -> Result<(oauth::store::OAuthSession, oauth::keys::SigningKey)> {
        let session = self.session(did).await?;
        let key = oauth::keys::SigningKey::from_jwk_json(&session.dpop_key_jwk, "session")
            .context("unsealing the session's DPoP key")?;
        Ok((session, key))
    }
}

/// Generate a dispatch method whose two arms take the same arguments.
///
/// A macro rather than twenty hand-written matches: the point of this module is
/// that the two backends cannot drift, and a hand-written arm is exactly where
/// an argument gets dropped or reordered on one side only.
macro_rules! dispatch {
    // Explicit visibility and metric label. Used by the three subscription
    // writers, which are private here so that reaching them through `Repo` means
    // going through the vetting wrapper of the same name; the label is passed
    // explicitly so the private method's `_unvetted` suffix does not leak into
    // the metric.
    //
    // **This makes `Repo` the vetted path, not the only possible path.** The
    // layer below is still public — `AppState.sidecar` is a `pub` field and
    // `SidecarClient`/`oauth::xrpc::Repo` expose their own `add_subscription`
    // — so a handler *can* still write a record without vetting it by calling
    // one of those directly. Nothing does today, and nothing should. Making it
    // impossible rather than merely unsanctioned needs the `SafeLink` treatment
    // from `src/safe_link.rs`: a vetted-record type the low-level writers demand
    // and only one constructor can produce. Tracked in #140.
    (
        $(#[$meta:meta])*
        $vis:vis $name:ident ( $( $arg:ident : $ty:ty ),* ) -> $ret:ty,
        label: $label:expr,
        sidecar: $sidecar:ident,
        rust: $rust:ident
    ) => {
        $(#[$meta])*
        $vis async fn $name(&self, did: &str $(, $arg: $ty)*) -> Result<$ret> {
            timed(&self.state.metrics, self.backend(), $label, async {
                match self.backend() {
                    Backend::Sidecar => self.state.sidecar.$sidecar(did $(, $arg)*).await,
                    Backend::Rust => {
                        let (session, key) = self.rust_parts(did).await?;
                        let repo = oauth::xrpc::Repo {
                            http: &self.state.http,
                            pool: &self.state.db,
                            session: &session,
                            key: &key,
                        };
                        repo.$rust($($arg),*).await
                    }
                }
            })
            .await
        }
    };

    // The common case: public, and the metric label is the method name. Forwards
    // to the arm above rather than repeating the body — a second copy of the
    // match is exactly the backend drift this macro exists to prevent.
    (
        $(#[$meta:meta])*
        $name:ident ( $( $arg:ident : $ty:ty ),* ) -> $ret:ty,
        sidecar: $sidecar:ident,
        rust: $rust:ident
    ) => {
        dispatch! {
            $(#[$meta])*
            pub $name ( $( $arg : $ty ),* ) -> $ret,
            label: stringify!($name),
            sidecar: $sidecar,
            rust: $rust
        }
    };
}

/// Scheme-check the parts of a subscription record that this reader did not
/// author, immediately before it is published to the user's repo.
///
/// **Why here and not at ingest.** `siteUrl` enters from three places — a remote
/// feed's `<link>` ([`crate::feed`]), an OPML file's `htmlUrl` ([`crate::opml`]),
/// and the manage-subscription form — and a guard at each is three things to
/// remember, which is the shape of defence that issue #114's sibling (#111)
/// measured as worthless: the check was deleted and all 679 tests still passed.
/// Every write instead crosses this module, above the backend split, so one vet
/// covers both backends, all three writers, and whatever is added next.
///
/// A rejected URL becomes `None` rather than dropping the subscription — the
/// feed is what the user asked for; the site link is decoration.
///
/// **The record is what makes this worth doing.** Nothing in `templates/`
/// renders `siteUrl`, so this is not an XSS against our own UI. The lexicon
/// describes the field as the "human-facing site the feed belongs to", i.e. a
/// value other atproto clients are expected to render as a link — so publishing
/// an unchecked `javascript:` URL hands every other reader a stored XSS under
/// our user's authorship, for a string the user never typed.
fn vet(sub: &Subscription) -> Subscription {
    let mut out = sub.clone();
    out.site_url = out.site_url.as_deref().and_then(crate::net::safe_link);
    out
}

/// [`vet`] over a batch.
fn vet_all(subs: &[Subscription]) -> Vec<Subscription> {
    subs.iter().map(vet).collect()
}

impl Repo<'_> {
    // ── subscriptions ────────────────────────────────────────────────────────

    dispatch! {
        /// The reader's feed list, in display order.
        list_subscriptions_sorted() -> Vec<(String, Subscription)>,
        sidecar: list_subscriptions_sorted,
        rust: list_subscriptions_sorted
    }

    dispatch! {
        /// Raw subscribe. Private: reach it through [`Repo::add_subscription`].
        add_subscription_unvetted(sub: &Subscription) -> String,
        label: "add_subscription",
        sidecar: add_subscription,
        rust: add_subscription
    }

    /// Subscribe. Returns the new record's rkey.
    ///
    /// Vets the record first — see [`vet`].
    pub async fn add_subscription(&self, did: &str, sub: &Subscription) -> Result<String> {
        self.add_subscription_unvetted(did, &vet(sub)).await
    }

    dispatch! {
        /// Unsubscribe by rkey.
        remove_subscription(rkey: &str) -> (),
        sidecar: remove_subscription,
        rust: remove_subscription
    }

    dispatch! {
        /// Raw update. Private: reach it through [`Repo::update_subscription`].
        update_subscription_unvetted(rkey: &str, sub: &Subscription)
            -> crate::atproto::WriteResult,
        label: "update_subscription",
        sidecar: update_subscription,
        rust: update_subscription
    }

    /// Rename or re-folder a subscription.
    ///
    /// Vets the record first — see [`vet`].
    pub async fn update_subscription(
        &self,
        did: &str,
        rkey: &str,
        sub: &Subscription,
    ) -> Result<crate::atproto::WriteResult> {
        self.update_subscription_unvetted(did, rkey, &vet(sub))
            .await
    }

    dispatch! {
        /// Raw bulk add. Private: reach it through [`Repo::add_subscriptions_bulk`].
        add_subscriptions_bulk_unvetted(subs: &[Subscription]) -> Vec<String>,
        label: "add_subscriptions_bulk",
        sidecar: add_subscriptions_bulk,
        rust: add_subscriptions_bulk
    }

    /// OPML import — one `applyWrites` for the whole batch.
    ///
    /// Vets every record first — see [`vet`]. An import is the path where the
    /// URLs are least trustworthy: the file is arbitrary, and 200 of them arrive
    /// at once with nobody reading each line.
    pub async fn add_subscriptions_bulk(
        &self,
        did: &str,
        subs: &[Subscription],
    ) -> Result<Vec<String>> {
        self.add_subscriptions_bulk_unvetted(did, &vet_all(subs))
            .await
    }

    // ── folders ──────────────────────────────────────────────────────────────

    dispatch! {
        /// Folders in display order.
        list_folders_sorted() -> Vec<(String, Folder)>,
        sidecar: list_folders_sorted,
        rust: list_folders_sorted
    }

    dispatch! {
        /// Create a folder. Returns its rkey.
        add_folder(folder: &Folder) -> String,
        sidecar: add_folder,
        rust: add_folder
    }

    dispatch! {
        /// Rename a folder in place.
        rename_folder(rkey: &str, folder: &Folder) -> crate::atproto::WriteResult,
        sidecar: rename_folder,
        rust: rename_folder
    }

    dispatch! {
        /// Delete a folder.
        remove_folder(rkey: &str) -> (),
        sidecar: remove_folder,
        rust: remove_folder
    }

    // ── saved ────────────────────────────────────────────────────────────────

    dispatch! {
        /// Saved items, newest first.
        list_saved_sorted() -> Vec<(String, Saved)>,
        sidecar: list_saved_sorted,
        rust: list_saved_sorted
    }

    dispatch! {
        /// Save an entry. Returns its rkey.
        add_saved(saved: &Saved) -> String,
        sidecar: add_saved,
        rust: add_saved
    }

    dispatch! {
        /// Saved items in PDS order — the un-star path, which matches by URL and
        /// does not care about display order.
        list_saved() -> Vec<(String, Saved)>,
        sidecar: list_saved,
        rust: list_saved
    }

    dispatch! {
        /// Unsave by rkey.
        remove_saved(rkey: &str) -> (),
        sidecar: remove_saved,
        rust: remove_saved
    }

    // ── read state ───────────────────────────────────────────────────────────

    dispatch! {
        /// Every read cursor.
        list_read_states() -> Vec<(String, ReadState)>,
        sidecar: list_read_states,
        rust: list_read_states
    }

    dispatch! {
        /// Flush dirty cursors in one `applyWrites` — the hottest write path.
        flush_read_states(cursors: &[(String, ReadState, bool)]) -> (),
        sidecar: flush_read_states,
        rust: flush_read_states
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

    async fn state_with(backend: Backend, public_url: &str) -> anyhow::Result<AppState> {
        let db = crate::store::init_url("sqlite::memory:").await?;
        AppState::new(
            Config {
                repo_backend: backend,
                public_url: public_url.to_string(),
                oauth: crate::config::OauthConfig {
                    // **A unique path per test, not the default.**
                    //
                    // `key_path` defaults to the RELATIVE `oauth-signing-key.json`,
                    // so a rust-backend test run writes real (encrypted) key
                    // material into whatever the working directory happens to be
                    // — the repo root — and every later run then tries to decrypt
                    // a file written under a different key and fails to boot.
                    // Ambient filesystem state is not a thing a test should depend
                    // on, and this is the same relative-path foot-gun the README
                    // documents for containers.
                    key_path: std::env::temp_dir().join(format!(
                        "fr-test-oauth-key-{}-{:p}.json",
                        std::process::id(),
                        &db as *const _
                    )),
                    encryption_key: Some("a".repeat(43)),
                    ..crate::config::OauthConfig::default()
                },
                ..Config::default()
            },
            db,
        )
    }

    /// A state pointed at a mock sidecar, so a repo write actually goes out.
    async fn sidecar_state(internal_url: &str) -> anyhow::Result<AppState> {
        let db = crate::store::init_url("sqlite::memory:").await?;
        AppState::new(
            Config {
                repo_backend: Backend::Sidecar,
                public_url: "http://localhost:8080".to_string(),
                sidecar: crate::config::SidecarConfig {
                    public_url: internal_url.to_string(),
                    internal_url: internal_url.to_string(),
                    internal_secret: "test-secret".to_string(),
                },
                ..Config::default()
            },
            db,
        )
    }

    /// A sidecar mock that keeps the body of the first repo write it is sent.
    ///
    /// The assertion has to be made on the BYTES ON THE WIRE. Checking the
    /// `Subscription` we passed in would pass just as happily with the vet
    /// deleted — the record only becomes safe on the way out.
    async fn spawn_capturing_sidecar() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sink = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                // **Read until the body is complete, not until the first
                // syscall returns.** A single `read` gets whatever one TCP
                // segment carried; if headers and body arrive separately, the
                // "body" is empty and every `!contains(...)` assertion below
                // passes for the wrong reason — a false green in the one test
                // the mutation argument rests on.
                let mut raw: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&chunk[..n]);
                    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let (head, body) = raw.split_at(split + 4);
                    let want = String::from_utf8_lossy(head).lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    });
                    if want.is_none_or(|want| body.len() >= want) {
                        sink.lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(body).to_string());
                        break;
                    }
                }
                let body = serde_json::json!({
                    "ok": true,
                    "data": {
                        "uri": "at://did:plc:x/community.lexicon.rss.subscription/rk1",
                        "cid": "bafyreiabc"
                    }
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        (format!("http://{addr}"), seen)
    }

    fn sub_with_site(site: &str) -> Subscription {
        let mut sub = Subscription::new("https://example.com/feed.xml", "2026-01-01T00:00:00.000Z");
        sub.site_url = Some(site.to_string());
        sub
    }

    /// Every write path, against the one scheme that motivated the guard.
    ///
    /// Parameterised over the three writers rather than testing one, because the
    /// vet is applied per-wrapper: a fourth writer, or a wrapper that forgets the
    /// call, is precisely the regression this is here to catch.
    #[tokio::test]
    async fn no_writer_publishes_a_hostile_site_url() {
        for hostile in [
            "javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=",
            "  javascript:alert(1)  ",
            "vbscript:msgbox(1)",
        ] {
            let (url, seen) = spawn_capturing_sidecar().await;
            let state = sidecar_state(&url).await.expect("sidecar state");
            let sub = sub_with_site(hostile);

            let _ = state.repo().add_subscription(DID, &sub).await;
            let _ = state.repo().update_subscription(DID, "rk1", &sub).await;
            let _ = state
                .repo()
                .add_subscriptions_bulk(DID, std::slice::from_ref(&sub))
                .await;

            let bodies = seen.lock().unwrap().clone();
            assert_eq!(
                bodies.len(),
                3,
                "expected one body per writer, got {bodies:?}"
            );
            for (writer, body) in ["add", "update", "bulk"].iter().zip(&bodies) {
                // Anchor the negative assertions below: a truncated or empty
                // capture would satisfy every `!contains(...)` vacuously.
                assert!(
                    body.contains("https://example.com/feed.xml"),
                    "{writer} captured no usable body, so the assertions that \
                     follow would pass for the wrong reason: {body:?}"
                );
                assert!(
                    !body.contains("javascript:")
                        && !body.contains("data:")
                        && !body.contains("vbscript:"),
                    "{writer} published {hostile:?} to the PDS: {body}"
                );
                assert!(
                    !body.contains("siteUrl"),
                    "{writer} sent a rejected siteUrl as an empty string; it must be \
                     omitted, so other clients render no link rather than a broken one: \
                     {body}"
                );
            }
        }
    }

    /// The guard must not eat the ordinary case.
    #[tokio::test]
    async fn a_legitimate_site_url_is_published_unchanged() {
        let (url, seen) = spawn_capturing_sidecar().await;
        let state = sidecar_state(&url).await.expect("sidecar state");
        let sub = sub_with_site("https://example.com/blog");

        let _ = state.repo().add_subscription(DID, &sub).await;

        let bodies = seen.lock().unwrap().clone();
        assert_eq!(bodies.len(), 1, "expected one write, got {bodies:?}");
        assert!(
            bodies[0].contains("https://example.com/blog"),
            "a perfectly good site link was dropped: {}",
            bodies[0]
        );
    }

    #[test]
    fn vet_rejects_by_scheme_and_keeps_everything_else() {
        // Rejected -> None, and the rest of the record is untouched.
        let hostile = sub_with_site("javascript:alert(1)");
        let vetted = vet(&hostile);
        assert_eq!(vetted.site_url, None);
        assert_eq!(vetted.url, hostile.url, "the feed URL is not the target");

        // A clean record passes through untouched.
        let clean = sub_with_site("https://example.com/blog");
        assert_eq!(
            vet(&clean).site_url.as_deref(),
            Some("https://example.com/blog")
        );

        // Surrounding whitespace is normalised away rather than rejected, which
        // is what `net::safe_link` already does for entry links.
        let padded = sub_with_site("  https://example.com/blog  ");
        assert_eq!(
            vet(&padded).site_url.as_deref(),
            Some("https://example.com/blog")
        );

        // Absent stays absent — no empty string is invented.
        let bare = Subscription::new("https://example.com/feed.xml", "2026-01-01T00:00:00.000Z");
        assert_eq!(vet(&bare).site_url, None);
    }

    #[test]
    fn vet_all_cleans_one_bad_record_without_touching_the_rest() {
        let mixed = vec![
            sub_with_site("https://a.example/"),
            sub_with_site("javascript:alert(1)"),
        ];
        let vetted = vet_all(&mixed);
        assert_eq!(vetted[0].site_url.as_deref(), Some("https://a.example/"));
        assert_eq!(
            vetted[1].site_url, None,
            "one bad record in a batch must be cleaned, not the whole batch dropped"
        );
    }

    /// **Both arms must record under the SAME operation name.**
    ///
    /// The comparison is two rows in one table keyed by (backend, operation). If
    /// the arms tagged their calls differently — a rename on one side, a typo on
    /// the other — the table would show two half-populated sets of rows and no
    /// pair would ever line up. The macro derives the name from the method via
    /// `stringify!` precisely so this cannot drift, and this pins it.
    ///
    /// Neither call can succeed here (there is no sidecar and no session), which
    /// is the point: the name is recorded either way, and a failed call is what
    /// the error columns exist to show.
    #[tokio::test]
    async fn both_backends_record_under_the_same_operation_name() {
        let sidecar = state_with(Backend::Sidecar, "http://localhost:8080")
            .await
            .expect("sidecar state");
        let _ = sidecar.repo().list_subscriptions_sorted(DID).await;

        let rust = state_with(Backend::Rust, "http://localhost:8080")
            .await
            .expect("rust state");
        let _ = rust.repo().list_subscriptions_sorted(DID).await;

        let sidecar_rows = sidecar.metrics.snapshot();
        let rust_rows = rust.metrics.snapshot();
        let names: Vec<&str> = sidecar_rows
            .iter()
            .chain(rust_rows.iter())
            .map(|row| row.op.as_str())
            .collect();

        assert_eq!(
            names.len(),
            2,
            "each backend should record exactly one call"
        );
        assert_eq!(
            names[0], names[1],
            "the two backends tagged the same operation differently, so their rows \
             can never be compared"
        );
        assert_eq!(names[0], "list_subscriptions_sorted");
    }

    /// **The three hand-typed metric labels must stay what they say.**
    ///
    /// Every other method derives its label from its own name via `stringify!`,
    /// which is what makes drift impossible for them. The subscription writers
    /// cannot: the macro-generated method behind each wrapper is named
    /// `*_unvetted`, and that suffix must not reach the metrics table, so the
    /// label is passed as a literal instead. A literal is exactly the thing that
    /// can drift, so it is pinned here.
    ///
    /// Honest about the limit: this pins the labels, not the correspondence
    /// between a label and its wrapper's name. Renaming a public wrapper without
    /// touching its literal would still slip through — the residual cost of
    /// hand-typing three of the fifteen.
    ///
    /// None of the calls can succeed (no session), which is the point: the label
    /// is recorded either way.
    #[tokio::test]
    async fn the_three_hand_typed_labels_are_what_they_claim() {
        let state = state_with(Backend::Rust, "http://localhost:8080")
            .await
            .expect("rust state");
        let sub = Subscription::new("https://example.com/feed.xml", "2026-01-01T00:00:00.000Z");

        let _ = state.repo().add_subscription(DID, &sub).await;
        let _ = state.repo().update_subscription(DID, "rk1", &sub).await;
        let _ = state
            .repo()
            .add_subscriptions_bulk(DID, std::slice::from_ref(&sub))
            .await;

        let mut ops: Vec<String> = state
            .metrics
            .snapshot()
            .into_iter()
            .map(|row| row.op)
            .collect();
        ops.sort();
        assert_eq!(
            ops,
            vec![
                "add_subscription".to_string(),
                "add_subscriptions_bulk".to_string(),
                "update_subscription".to_string(),
            ],
            "a writer's metric label drifted from the operation it names, so its \
             rows can never be compared against the other backend's"
        );
    }

    /// A failed call is still recorded — as a FAILURE, not as a fast success.
    #[tokio::test]
    async fn a_failed_call_is_recorded_in_the_error_column() {
        let state = state_with(Backend::Rust, "http://localhost:8080")
            .await
            .expect("rust state");
        let result = state.repo().list_subscriptions_sorted(DID).await;
        assert!(result.is_err(), "there is no session, so this must fail");

        let snapshot = state.metrics.snapshot();
        let stats = &snapshot[0].stats;
        assert_eq!(stats.err_count, 1);
        assert_eq!(
            stats.ok_count, 0,
            "a failure was counted as a success, which is exactly the reading \
             that makes a broken backend look fast"
        );
        assert_eq!(stats.percentile(50.0), None, "no successes, so no p50");
    }

    /// **Selecting the Rust backend with an unusable OAuth config must not boot.**
    ///
    /// The alternative is a server that starts cleanly and then fails every
    /// single repo call at request time — which looks like a PDS outage rather
    /// than a configuration error, on a path the operator has just switched to.
    #[tokio::test]
    async fn the_rust_backend_refuses_to_start_on_an_unusable_oauth_config() {
        // A public URL with a path is rejected by `ClientConfig::new` (it would
        // publish a doubled client_id).
        let err = match state_with(Backend::Rust, "https://feather-reader.com/oauth").await {
            Err(err) => err,
            Ok(_) => panic!("the rust backend booted with an unusable OAuth config"),
        };
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("FEATHERREADER_REPO_BACKEND=rust"),
            "the error must name the switch that caused it: {rendered}"
        );
    }

    /// The same bad config with the SIDECAR selected still boots: the Rust
    /// runtime is unused, and refusing to start would block a rollback.
    #[tokio::test]
    async fn the_sidecar_backend_still_boots_with_an_unusable_oauth_config() {
        let state = state_with(Backend::Sidecar, "https://feather-reader.com/oauth")
            .await
            .expect("the sidecar path must not be blocked by Rust-only config");
        assert!(state.oauth.is_none());
    }
    /// **A refresh that fails in DISCOVERY must be counted.**
    ///
    /// Regression test for the defect a review found in the first version of
    /// this metric: the span sat inside `valid_session`, but `Repo::session`
    /// runs discovery BEFORE that — only on the stale branch, so discovery is
    /// part of the refresh — and a failure there propagated via `?` recording
    /// nothing at all.
    ///
    /// That silently excluded the two likeliest refresh outages: an unreachable
    /// PDS, and the issuer-mismatch check. Those are precisely the events
    /// `err_count` exists to move on, and they left the metric flat while the
    /// error surfaced only on whatever repo call happened to trigger it — the
    /// exact situation this work set out to end.
    #[tokio::test]
    async fn a_refresh_that_fails_in_discovery_is_counted() {
        let state = state_with(Backend::Rust, "https://feather-reader.com")
            .await
            .expect("state");
        let runtime = state.oauth.as_deref().expect("oauth runtime");
        let did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

        // EXPIRED, so `Repo::session` takes the stale branch and reaches
        // discovery. `pds.invalid` cannot resolve, so discovery fails.
        oauth::store::put_session(
            &state.db,
            &runtime.codec,
            &oauth::store::OAuthSession {
                sub: did.into(),
                issuer: "https://auth.invalid".into(),
                aud: "https://pds.invalid".into(),
                dpop_key_jwk: oauth::keys::SigningKey::generate("session-dpop")
                    .to_jwk_json()
                    .unwrap(),
                access_token: "at".into(),
                refresh_token: "rt".into(),
                token_type: "DPoP".into(),
                granted_scope: "atproto".into(),
                expires_at: Some(crate::store::now_unix() - 1),
            },
        )
        .await
        .unwrap();

        let err = state.repo().session(did).await;
        assert!(err.is_err(), "an unreachable PDS must fail the refresh");

        let row = state
            .metrics
            .snapshot()
            .into_iter()
            .find(|r| r.op == "oauth_refresh" && r.backend == Backend::Rust)
            .expect("a refresh that failed in discovery recorded nothing at all");
        assert_eq!(row.stats.err_count, 1);
        assert_eq!(row.stats.ok_count, 0);
    }

    /// A session that is still fresh must record NO refresh — the property that
    /// keeps the metric meaningful, since `session()` runs on every repo call.
    #[tokio::test]
    async fn a_fresh_session_records_no_refresh() {
        let state = state_with(Backend::Rust, "https://feather-reader.com")
            .await
            .expect("state");
        let runtime = state.oauth.as_deref().expect("oauth runtime");
        let did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
        oauth::store::put_session(
            &state.db,
            &runtime.codec,
            &oauth::store::OAuthSession {
                sub: did.into(),
                issuer: "https://auth.invalid".into(),
                aud: "https://pds.invalid".into(),
                dpop_key_jwk: oauth::keys::SigningKey::generate("session-dpop")
                    .to_jwk_json()
                    .unwrap(),
                access_token: "at".into(),
                refresh_token: "rt".into(),
                token_type: "DPoP".into(),
                granted_scope: "atproto".into(),
                expires_at: Some(crate::store::now_unix() + 3600),
            },
        )
        .await
        .unwrap();

        state.repo().session(did).await.expect("fresh session");
        assert!(
            state
                .metrics
                .snapshot()
                .iter()
                .all(|r| r.op != "oauth_refresh"),
            "a fresh session recorded a refresh it never performed",
        );
    }
}
