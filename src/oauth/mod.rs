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
