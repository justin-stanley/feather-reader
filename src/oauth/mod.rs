//! Rust-native atproto OAuth — the replacement for the Node sidecar.
//!
//! This module is the live login and repo path when
//! `FEATHERREADER_REPO_BACKEND=rust`; [`crate::atproto::SidecarClient`] is the
//! default and serves it otherwise. Both implementations share an at-rest wire
//! format so the switch is reversible in either direction — see [`crypto`].

pub mod client_auth;
pub mod crypto;
pub mod discovery;
pub mod dpop;
pub mod fetch;
pub mod flow;
pub mod identity;
pub mod jwt;
pub mod keys;
pub mod login;
pub mod metadata;
pub mod request;
pub mod resolve;
pub mod revoke;
pub mod runtime;
pub mod session;
pub mod store;
pub mod token;
pub mod xrpc;

/// Largest error body any path here will parse looking for one field.
///
/// **An error document is a few dozen bytes; the question is what a server can
/// make us deserialise on a path that runs for every failure.** `read_capped`
/// admits 8 MB, and 8 MB of cheap JSON structure builds hundreds of megabytes of
/// `serde_json::Value` — measured, 789 MB for one 8 MB body of `{"":0}` objects.
/// Three paths peek at a failed response for a single string field, and all three
/// would otherwise pay that: the DPoP nonce challenge, an XRPC error's
/// `error`/`message`, and the refresh classifier's `invalid_grant`.
///
/// 10 KiB matches the reference client's own peek. It lived in `dpop` alone until
/// a review found the other two, which is why it lives here now: one constant, one
/// predicate, three callers.
pub(crate) const MAX_ERROR_BODY: usize = 10 * 1024;

/// Whether a failed response's body is small enough to be worth parsing for one
/// field. See [`MAX_ERROR_BODY`].
///
/// Refusing to look is always safe here: every caller is extracting a hint for a
/// decision it already has a default for — retry, transient, "no message".
pub(crate) fn error_body_worth_parsing(body: &[u8]) -> bool {
    !body.is_empty() && body.len() <= MAX_ERROR_BODY
}
