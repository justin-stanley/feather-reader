# Contributing to FeatherReader

Thanks for your interest! FeatherReader is an early, experimental project, and
contributions — bug reports, fixes, docs, and design discussion — are welcome.

## Ground rules

- **Keep it minimal.** FeatherReader is deliberately small: a calm reading
  experience is the product, not a feature count. New features are weighed against
  "does this make the reading experience better, or just bigger?" If you're
  planning something substantial, please open an issue to discuss it first.
- **Own-your-data is the architecture.** Subscriptions, folders, stars, and
  read-state live in the user's atproto PDS under the `community.lexicon.rss.*`
  lexicon — not in a server-side account. Changes should preserve that.
- **Be honest in comments and docs.** Describe what the code actually does; flag
  known limitations rather than papering over them.

## Building

FeatherReader is one Rust server, including its atproto OAuth client. (A Node
OAuth sidecar could serve that until 0.5.0 removed it, #311.)

```sh
cargo build --all-targets
```

See the [README](README.md) for how it is configured (environment variables
only; no config file) and how to run it.

The repo also contains an optional standalone **`bot/`** crate — the follow→invite
bot for the closed beta. It's its **own** Cargo workspace (not built by the app's
`cargo build`) and isn't needed to build or run the reader; build/test it on its
own and see [`bot/README.md`](bot/README.md).

## Before you open a pull request

Run the local CI — it covers the core of the GitHub Actions gate and uses zero
hosted minutes:

```sh
./scripts/ci.sh
```

This runs `rustfmt --check`, a locked build, the Rust test suite, `clippy` with
`-D warnings`, and the teardown script's tests. **Please make sure
it passes before pushing.** CI also runs gates the script does not: rustdoc with
`-D warnings`, `cargo deny`, `cargo audit`, the invite bot's gates, gitleaks, the Caddyfile
validation and, for changes to the app, the upgrade-boot gate. The commands are
in the README's [Development](README.md#development) section. You can wire the
script up as a pre-push gate with:

```sh
git config core.hooksPath .githooks
```

## Pull requests

- Keep PRs focused; one logical change per PR is easiest to review.
- Include tests for behaviour changes where practical.
- Explain the *why*, not just the *what*, in the description.
- By contributing, you agree your contribution is licensed under the project's
  [AGPL-3.0-only](LICENSE) license.
