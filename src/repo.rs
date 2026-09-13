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
    (
        $(#[$meta:meta])*
        $name:ident ( $( $arg:ident : $ty:ty ),* ) -> $ret:ty,
        sidecar: $sidecar:ident,
        rust: $rust:ident
    ) => {
        $(#[$meta])*
        pub async fn $name(&self, did: &str $(, $arg: $ty)*) -> Result<$ret> {
            timed(&self.state.metrics, self.backend(), stringify!($name), async {
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
        /// Subscribe. Returns the new record's rkey.
        add_subscription(sub: &Subscription) -> String,
        sidecar: add_subscription,
        rust: add_subscription
    }

    dispatch! {
        /// Unsubscribe by rkey.
        remove_subscription(rkey: &str) -> (),
        sidecar: remove_subscription,
        rust: remove_subscription
    }

    dispatch! {
        /// Rename or re-folder a subscription.
        update_subscription(rkey: &str, sub: &Subscription) -> crate::atproto::WriteResult,
        sidecar: update_subscription,
        rust: update_subscription
    }

    dispatch! {
        /// OPML import — one `applyWrites` for the whole batch.
        add_subscriptions_bulk(subs: &[Subscription]) -> Vec<String>,
        sidecar: add_subscriptions_bulk,
        rust: add_subscriptions_bulk
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
                ..Config::default()
            },
            db,
        )
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
}
