//! **FeatherReader** — a minimalist, atproto-native RSS/Atom feed reader.
//!
//! Your feed subscriptions live in your own [atproto](https://atproto.com) PDS
//! (via a community lexicon), so your reading list follows you across any
//! compatible reader — you own your data, not the app. Minimalist by design.
//!
//! **Status:** early / design stage. This `0.1.0` reserves the crate name;
//! the real implementation is in progress. See <https://reader.justin-stanley.com>.

/// The crate version — surfaced for the eventual server's `--version` / health output.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
