//! The one place every `com.atproto.repo.*` call the reader makes goes
//! through, and is timed.
//!
//! It chose between two backends until 0.5.0 removed the Node sidecar (#311);
//! the Rust client in `oauth::xrpc` is now the only one. The single boundary
//! stays: it is where every repo call is measured by the same wrapper, and the
//! method list is the reader surface `web.rs` calls.

use anyhow::{Context as _, Result};

use crate::lexicon::{Folder, ReadState, Saved, Subscription};
use crate::metrics::{timed, Backend};
use crate::oauth;
use crate::vetted::VettedSubscription;
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
        Backend::Rust
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
    pub async fn has_session(&self, did: &str) -> Result<bool> {
        let found: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM oauth_session WHERE sub = ?1")
            .bind(did)
            .fetch_optional(&self.state.db)
            .await
            .with_context(|| format!("checking for an OAuth session for {did}"))?;
        Ok(found.is_some())
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
                revocation_endpoint: server.revocation_endpoint.as_deref(),
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
    // **`Repo` is the vetted path. The layer below is narrower than it was,
    // and still not closed.**
    //
    // The named writers demand vetted records: `add_subscription`,
    // `update_subscription`, `add_subscriptions_bulk` and `add_saved` on both
    // backends take `&vetted::Vetted*`, whose inner field is private to
    // `src/vetted.rs` and reachable only through a constructor that vets.
    //
    // **That sentence has now been wrong twice, so read what follows as the
    // correction rather than the guarantee.** #150 closed three routes and its
    // message implied the class; #154 said "there is nothing to hand them that
    // skipped the check" and a review found a fourth,
    // `SidecarClient::create_subscriptions_batch`, taking a raw
    // `&[Subscription]`. Deleting it, this comment then said "the layer below
    // now demands vetted records too" — and a second review found the *general*
    // case the deleted function had been one instance of: `create_record`,
    // `put_record` and `apply_writes` are generic over `T: Serialize`, and
    // `lexicon::Subscription` derives `Serialize`, so any of them writes an
    // unvetted record. Verified by compiling it.
    //
    // What changed: those three are now PRIVATE on `PdsClient` and
    // `SidecarClient` — not `pub(crate)`, which was the first attempt and
    // which a self-review caught doing nothing for the actual threat: a
    // handler in `web.rs` is in this crate, so `pub(crate)` left it fully
    // able to call them. Verified both ways by compiling a probe from `web.rs`:
    // `pub(crate)` → builds clean; private → three "private method" errors.
    // The vetted wrappers sit in the same `impl` block and need no visibility.
    //
    // The three on `oauth::xrpc::Repo` remain `pub` because
    // `examples/oauth_spike.rs` is a separate crate target and drives them
    // against a scratch collection.
    //
    // They are no longer generic over every `Serialize`, though: `create_record`
    // and `put_record` take `vetted::WritableRecord`, a sealed trait whose
    // implementors are the vetted wrappers plus the two lexicon records with
    // nothing to vet. `create_record(nsid::SUBSCRIPTION, &raw_subscription)`
    // does not compile, and a `compile_fail` doctest on the trait says so.
    //
    // This comment used to name removing `Serialize` from
    // `lexicon::Subscription` as the way to end the class, and call it blocked:
    // `VettedSubscription` is `#[serde(transparent)]` over it, so removing the
    // derive forces a hand-written impl, and a record-shape slip there would
    // silently migrate every reader's repo. The trait gets the same guarantee
    // with the wire format still coming from one derive.
    //
    // What remains reachable is `apply_writes`, whose `WriteOp::Create.value`
    // is a `serde_json::Value` — a hand-built record, not an accidental
    // one-liner. Narrowed, and the remainder named rather than implied.
    (
        $(#[$meta:meta])*
        $vis:vis $name:ident ( $( $arg:ident : $ty:ty ),* ) -> $ret:ty,
        label: $label:expr,
        rust: $rust:ident
    ) => {
        $(#[$meta])*
        $vis async fn $name(&self, did: &str $(, $arg: $ty)*) -> Result<$ret> {
            timed(&self.state.metrics, self.backend(), $label, async {
                let (session, key) = self.rust_parts(did).await?;
                let repo = oauth::xrpc::Repo {
                    http: &self.state.http,
                    pool: &self.state.db,
                    session: &session,
                    key: &key,
                };
                repo.$rust($($arg),*).await
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
        rust: $rust:ident
    ) => {
        dispatch! {
            $(#[$meta])*
            pub $name ( $( $arg : $ty ),* ) -> $ret,
            label: stringify!($name),
            rust: $rust
        }
    };
}

impl Repo<'_> {
    // ── subscriptions ────────────────────────────────────────────────────────

    dispatch! {
        /// The reader's feed list, in display order.
        list_subscriptions_sorted() -> Vec<(String, Subscription)>,
        rust: list_subscriptions_sorted
    }

    dispatch! {
        /// The reader's feed list with the CID each record was listed at,
        /// unsorted — for a read-modify-write that puts with `swapRecord`
        /// (#149). `list_subscriptions_sorted` is unchanged for every caller
        /// that only displays the list.
        list_subscriptions_with_cids() -> Vec<(String, Option<String>, Subscription)>,
        rust: list_subscriptions_with_cids
    }

    dispatch! {
        /// Raw subscribe. Private: reach it through [`Repo::add_subscription`].
        add_subscription_unvetted(sub: &crate::vetted::VettedSubscription) -> String,
        label: "add_subscription",
        rust: add_subscription
    }

    /// Subscribe. Returns the new record's rkey.
    ///
    /// Vets the record first — see [`crate::vetted::VettedSubscription`].
    pub async fn add_subscription(&self, did: &str, sub: &Subscription) -> Result<String> {
        self.add_subscription_unvetted(did, &VettedSubscription::new(sub))
            .await
    }

    dispatch! {
        /// Unsubscribe by rkey.
        remove_subscription(rkey: &str) -> (),
        rust: remove_subscription
    }

    dispatch! {
        /// Raw update. Private: reach it through [`Repo::update_subscription`].
        update_subscription_unvetted(
            rkey: &str,
            sub: &crate::vetted::VettedSubscription,
            swap_record: Option<&str>
        ) -> crate::atproto::WriteResult,
        label: "update_subscription",
        rust: update_subscription
    }

    /// Rename or re-folder a subscription.
    ///
    /// Vets the record first — see [`crate::vetted::VettedSubscription`].
    pub async fn update_subscription(
        &self,
        did: &str,
        rkey: &str,
        sub: &Subscription,
        swap_record: Option<&str>,
    ) -> Result<crate::atproto::WriteResult> {
        self.update_subscription_unvetted(did, rkey, &VettedSubscription::new(sub), swap_record)
            .await
    }

    dispatch! {
        /// Raw bulk add. Private: reach it through [`Repo::add_subscriptions_bulk`].
        add_subscriptions_bulk_unvetted(subs: &[crate::vetted::VettedSubscription]) -> Vec<String>,
        label: "add_subscriptions_bulk",
        rust: add_subscriptions_bulk
    }

    /// OPML import — `applyWrites`, one call per 200 feeds. A failure part-way
    /// leaves a prefix written; see [`crate::atproto::ApplyWritesIncomplete`].
    ///
    /// Vets every record first — see [`crate::vetted::VettedSubscription::all`]. An import is the path where the
    /// URLs are least trustworthy: the file is arbitrary, and 200 of them arrive
    /// at once with nobody reading each line.
    pub async fn add_subscriptions_bulk(
        &self,
        did: &str,
        subs: &[Subscription],
    ) -> Result<Vec<String>> {
        self.add_subscriptions_bulk_unvetted(did, &VettedSubscription::all(subs))
            .await
    }

    // ── folders ──────────────────────────────────────────────────────────────

    dispatch! {
        /// Folders in display order.
        list_folders_sorted() -> Vec<(String, Folder)>,
        rust: list_folders_sorted
    }

    dispatch! {
        /// Folders with the CID each record was listed at, unsorted — the read
        /// half of a rename that puts with `swapRecord` (#268).
        list_folders_with_cids() -> Vec<(String, Option<String>, Folder)>,
        rust: list_folders_with_cids
    }

    dispatch! {
        /// Create a folder. Returns its rkey.
        add_folder(folder: &Folder) -> String,
        rust: add_folder
    }

    dispatch! {
        /// Rename a folder in place, on the condition that it is still at
        /// `swap_record` when that is given (#268).
        rename_folder(
            rkey: &str,
            folder: &Folder,
            swap_record: Option<&str>
        ) -> crate::atproto::WriteResult,
        rust: rename_folder
    }

    dispatch! {
        /// Delete a folder.
        remove_folder(rkey: &str) -> (),
        rust: remove_folder
    }

    // ── saved ────────────────────────────────────────────────────────────────

    dispatch! {
        /// Saved items, newest first.
        list_saved_sorted() -> Vec<(String, Saved)>,
        rust: list_saved_sorted
    }

    dispatch! {
        /// Raw save. Private: reach it through [`Repo::add_saved`].
        add_saved_unvetted(saved: &crate::vetted::VettedSaved) -> String,
        label: "add_saved",
        rust: add_saved
    }

    /// Save an entry. Returns its rkey.
    ///
    /// **Refuses rather than publishing a URL we would not render.** `url` is
    /// required on this record, so unlike a subscription's `siteUrl` there is no
    /// honest resting place for a rejected value — see [`crate::vetted::VettedSaved`].
    /// The only caller already treats a failed PDS write as recoverable: it logs
    /// and keeps the entry starred locally, so the reader loses nothing but the
    /// hostile record.
    pub async fn add_saved(&self, did: &str, saved: &Saved) -> Result<String> {
        self.add_saved_unvetted(did, &crate::vetted::VettedSaved::new(saved)?)
            .await
    }

    dispatch! {
        /// Saved items in PDS order — the un-star path, which matches by URL and
        /// does not care about display order.
        list_saved() -> Vec<(String, Saved)>,
        rust: list_saved
    }

    dispatch! {
        /// Unsave by rkey.
        remove_saved(rkey: &str) -> (),
        rust: remove_saved
    }

    // ── read state ───────────────────────────────────────────────────────────

    dispatch! {
        /// Every read cursor.
        list_read_states() -> Vec<(String, ReadState)>,
        rust: list_read_states
    }

    dispatch! {
        /// Every record in `collection`, unparsed — for asking which rkeys
        /// EXIST, which the typed listers cannot answer: they skip a record
        /// this build cannot parse, and a skipped record reads as a missing one.
        list_all_records(collection: &str) -> Vec<crate::atproto::RecordEntry>,
        rust: list_all_records
    }

    dispatch! {
        /// Flush dirty cursors via `applyWrites`, chunked — the hottest write path.
        /// A failure part-way leaves a prefix written; see
        /// [`crate::atproto::ApplyWritesIncomplete`].
        flush_read_states(cursors: &[(String, ReadState, bool)]) -> (),
        rust: flush_read_states
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

    async fn state_with(public_url: &str) -> anyhow::Result<AppState> {
        let db = crate::store::init_url("sqlite::memory:").await?;
        AppState::new(
            Config {
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

    /// A fake PDS that keeps the body of every repo write it is sent.
    ///
    /// The assertion has to be made on the BYTES ON THE WIRE. Checking the
    /// `Subscription` we passed in would pass just as happily with the vet
    /// deleted — the record only becomes safe on the way out. axum hands the
    /// handler the whole body, so a capture cannot be cut short by a TCP
    /// segment boundary.
    async fn spawn_capturing_pds() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use axum::response::IntoResponse as _;
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // A test hostname routed to the loopback listener: the guarded client
        // refuses loopback itself.
        let host = format!("capture-{}.repo.test", addr.port());
        crate::net::test_host_override(&host, addr);
        let app =
            axum::Router::new().fallback(move |uri: axum::http::Uri, body: axum::body::Bytes| {
                let sink = sink.clone();
                async move {
                    let reply = match uri.path().trim_start_matches("/xrpc/") {
                        "com.atproto.repo.createRecord" | "com.atproto.repo.putRecord" => {
                            serde_json::json!({
                                "uri": "at://did:plc:x/community.lexicon.rss.subscription/rk1",
                                "cid": "bafyreiabc"
                            })
                        }
                        "com.atproto.repo.applyWrites" => serde_json::json!({ "results": [] }),
                        other => panic!("the capturing PDS got an unexpected call to {other}"),
                    };
                    sink.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&body).to_string());
                    axum::Json(reply).into_response()
                }
            });
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{host}:{}", addr.port()), seen)
    }

    /// A state with a live session for [`DID`] at `pds`, so a repo write
    /// actually goes out.
    async fn pds_state(pds: &str) -> AppState {
        let state = state_with("http://localhost:8080").await.expect("state");
        let runtime = state.oauth.as_deref().expect("oauth runtime");
        crate::oauth::store::put_session(
            &state.db,
            &runtime.codec,
            &crate::oauth::store::OAuthSession {
                sub: DID.into(),
                issuer: "https://auth.invalid".into(),
                aud: pds.into(),
                dpop_key_jwk: crate::oauth::keys::SigningKey::generate("session-dpop")
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
        state
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
            let (pds, seen) = spawn_capturing_pds().await;
            let state = pds_state(&pds).await;
            let sub = sub_with_site(hostile);

            let _ = state.repo().add_subscription(DID, &sub).await;
            let _ = state
                .repo()
                .update_subscription(DID, "rk1", &sub, None)
                .await;
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

    /// **A hostile saved URL must not reach the PDS either.**
    ///
    /// `community.lexicon.rss.saved` publishes `url` into the reader's own repo,
    /// into a field `safe_link.rs` already treats as attacker-controlled on the
    /// RENDER side — that is what `SafeLink::external` exists for. The write side
    /// had no equivalent: `add_saved` went straight through `dispatch!` with no
    /// vet, so `entries.url` rows that arrived before the ingest guard existed,
    /// or by any future path that does not go through `feed.rs`, were published
    /// verbatim when the reader starred them.
    ///
    /// Asserted on the bytes on the wire, for the same reason as the
    /// subscription writers: the record only becomes unsafe on the way out.
    #[tokio::test]
    async fn starring_does_not_publish_a_hostile_url() {
        for hostile in [
            "javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=",
            "vbscript:msgbox(1)",
        ] {
            let (pds, seen) = spawn_capturing_pds().await;
            let state = pds_state(&pds).await;
            let mut saved = Saved::new(hostile, "2026-01-01T00:00:00.000Z");
            saved.title = Some("Hostile".to_string());

            let _ = state.repo().add_saved(DID, &saved).await;

            let bodies = seen.lock().unwrap().clone();
            assert!(
                !bodies.iter().any(|b| b.contains("javascript:")
                    || b.contains("data:")
                    || b.contains("vbscript:")),
                "starring published {hostile:?} to the PDS: {bodies:?}"
            );
        }
    }

    /// The guard must not eat the ordinary case.
    #[tokio::test]
    async fn a_legitimate_site_url_is_published_unchanged() {
        let (pds, seen) = spawn_capturing_pds().await;
        let state = pds_state(&pds).await;
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
        let state = state_with("http://localhost:8080")
            .await
            .expect("rust state");
        let sub = Subscription::new("https://example.com/feed.xml", "2026-01-01T00:00:00.000Z");

        let _ = state.repo().add_subscription(DID, &sub).await;
        let _ = state
            .repo()
            .update_subscription(DID, "rk1", &sub, None)
            .await;
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
        let state = state_with("http://localhost:8080")
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

    /// **An unusable OAuth config must not boot.**
    ///
    /// The alternative is a server that starts cleanly and then fails every
    /// single repo call at request time — which looks like a PDS outage rather
    /// than a configuration error, on a path the operator has just switched to.
    #[tokio::test]
    async fn an_unusable_oauth_config_refuses_to_start() {
        // A public URL with a path is rejected by `ClientConfig::new` (it would
        // publish a doubled client_id).
        let err = match state_with("https://feather-reader.com/oauth").await {
            Err(err) => err,
            Ok(_) => panic!("the server booted with an unusable OAuth config"),
        };
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("the OAuth runtime could not be built"),
            "the error must say what failed: {rendered}"
        );
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
        let state = state_with("https://feather-reader.com")
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
        let state = state_with("https://feather-reader.com")
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
