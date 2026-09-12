//! Rust-native atproto OAuth — the replacement for the Node sidecar.
//!
//! Built in phases; this module is NOT yet wired into the live login path.
//! [`crate::atproto::SidecarClient`] remains the live path until the cutover,
//! and both implementations share an at-rest wire format so the switch is
//! reversible. See [`crypto`] for that format.

pub mod client_auth;
pub mod crypto;
pub mod discovery;
pub mod dpop;
pub mod fetch;
pub mod identity;
pub mod jwt;
pub mod keys;
pub mod metadata;
pub mod store;
