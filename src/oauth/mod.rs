//! Rust-native atproto OAuth — the replacement for the Node sidecar.
//!
//! Built in phases; this module is NOT yet wired into the live login path.
//! [`crate::atproto::SidecarClient`] remains the live path until the cutover,
//! and both implementations share an at-rest wire format so the switch is
//! reversible. See [`crypto`] for that format.

pub mod crypto;
pub mod keys;
pub mod metadata;
