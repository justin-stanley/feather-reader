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

FeatherReader is two processes: the Rust server and a small Node OAuth sidecar.

```sh
# Rust server
cargo build --all-targets

# OAuth sidecar
cd oauth-sidecar && npm ci && npm run build
```

See the [README](README.md) for how the two are configured (environment variables
only; no config file) and how to run them.

## Before you open a pull request

Run the full local CI — it mirrors the GitHub Actions workflow and uses zero
hosted minutes:

```sh
./scripts/ci.sh
```

This runs `rustfmt --check`, a locked build, the Rust test suite, `clippy` with
`-D warnings`, and the sidecar's `npm ci` + build + typecheck. **Please make sure
it passes before pushing.** You can wire it up as a pre-push gate with:

```sh
git config core.hooksPath .githooks
```

## Pull requests

- Keep PRs focused; one logical change per PR is easiest to review.
- Include tests for behaviour changes where practical.
- Explain the *why*, not just the *what*, in the description.
- By contributing, you agree your contribution is licensed under the project's
  [AGPL-3.0-only](LICENSE) license.
