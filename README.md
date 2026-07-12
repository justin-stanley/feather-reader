# FeatherReader 🪶

A **minimalist, atproto-native RSS/Atom feed reader** — written in Rust.

Your feed **subscriptions live in your own [atproto](https://atproto.com) PDS** (via a community lexicon), so your reading list follows you across *any* compatible reader — you own your data, not the app. No signup, no password: your atproto identity **is** your account.

- **Minimalist by design** — a calm, fast, distraction-free reader. Does a few things well; no ads, no tracking, no algorithm.
- **Own your data** — subscriptions (plus starred items and read-state) stored as records in *your* PDS via the community `community.lexicon.rss.*` lexicon; portable across readers, not locked to one instance.
- **Single binary, self-hostable** — Rust + SQLite; trivial to run yourself.
- Hosted at **[reader.justin-stanley.com](https://reader.justin-stanley.com)**.

## Status

**Early / design stage.** This `0.1.0` reserves the name; the real implementation is in progress.

## License

[AGPL-3.0-only](./LICENSE) — the self-hosted-web-app model (keeps hosted forks open).
