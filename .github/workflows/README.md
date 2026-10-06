# CI / Security workflows

This directory holds FeatherReader's CI + security pipeline. The repo is
**public**, so every workflow runs on **GitHub-hosted `ubuntu-latest`** runners —
free, and the `ci.yml` jobs run **in parallel**. (While the repo was private the
gate ran on a self-hosted `linux/x64` runner to spend zero hosted minutes; that's
no longer needed, and parallel hosted jobs are faster.)

| Workflow | Runner | Triggers | What it does |
|---|---|---|---|
| `ci.yml` | **GitHub-hosted** (`ubuntu-latest`, parallel jobs) | push/PR to `main`, manual | The gate. Jobs: **rust** (build/test/clippy `-D warnings`/rustfmt/rustdoc `-D warnings`), **cargo-deny** (licenses + bans + sources via `deny.toml`; advisories are the cargo-audit job's), **cargo-audit** (RustSec), **sidecar** (npm ci/build/typecheck/**test** + **oxlint** + **Prettier `--check`** + `npm audit --omit=dev`), **bot** (Invite bot: the standalone `bot/` crate — its own workspace — build + test + clippy + rustfmt + cargo-deny + cargo-audit), **secrets** (**gitleaks** tree + history via `.gitleaks.toml`), **caddyfile** (`caddy validate` of `deploy/Caddyfile` with both OAuth routings, against the Caddy digest the `Dockerfile` pins), **teardown** (`scripts/test-teardown.sh`: `deploy/teardown.sh` against throwaway SQLite files — revoke order, refusals, exit-code handling). |
| `codeql.yml` | **GitHub-hosted** (`ubuntu-latest`) | **PR to `main`** + push to `main` + weekly cron + manual | SAST for `javascript-typescript` (the OAuth sidecar). Runs on **every** PR — no `paths:` filter, so config-only PRs still get a CodeQL check-run (OSSF Scorecard's SAST check needs one on each merged PR). Rust is covered by clippy + cargo-deny + cargo-audit (CodeQL's Rust extractor errored on all files; re-add when GA'd). Results → Security tab. Free for this public repo. |
| `dependency-review.yml` | **GitHub-hosted** | pull_request to `main` | Blocks PRs that add vulnerable deps or disallowed licenses (aligned with `deny.toml`). Needs the Dependency Graph — free/on for public repos. |
| `scorecard.yml` | **GitHub-hosted** | branch-protection change + weekly cron + push `main` | OpenSSF supply-chain posture score → Security tab + public badge. |
| `upgrade-boot.yml` | **GitHub-hosted** | PR to `main` touching `src/`, `Cargo.*`, `Dockerfile`, `deploy/` or the script; push to `main`; manual | Builds the candidate image and runs `scripts/upgrade-boot.sh` against the release named in `deploy/upgrade-from`: the previous image creates and seeds a database, the candidate migrates and boots on it, then the previous image boots again (rollback). |
| `release-image.yml` | **GitHub-hosted** | tag `v*.*.*`, manual | Builds the image **once**, runs the same upgrade-boot gate on it, and only then pushes that exact image to `ghcr.io/justin-stanley/feather-reader` and signs SLSA build provenance for its digest (optional CycloneDX SBOM). On a tag push, its last job dispatches `release-crate.yml` against the tag (a manual run does not). Does not deploy: deploys are manual, by verified digest. |
| `release-crate.yml` | **GitHub-hosted** | `workflow_dispatch` only (dispatched by `release-image.yml`) | Checks the tag equals `Cargo.toml`'s version, then `cargo publish --locked` via crates.io Trusted Publishing (OIDC, no stored token). Dispatched rather than triggered by `workflow_run`, which Trusted Publishing refuses. |
| `../dependabot.yml` | n/a (GitHub-native) | weekly | Grouped minor/patch update PRs for **cargo** (`/`), **npm** (`/oauth-sidecar`) and **github-actions** (`/`). The **docker** block is commented out: the root `Dockerfile` pins its base images by digest. |

## GitHub-hosted, public-repo notes

Everything runs on GitHub-hosted runners, free for this public repo. A few
deliberate choices:

* **`ci.yml` jobs are independent and run in parallel** — rust, the sidecar, and
  the standalone invite-bot crate share no state, so they fan out across runners
  instead of serializing on one self-hosted box.
* **CodeQL runs on *every* PR to `main`** (plus push to `main` and a weekly
  cron), with **no** `paths:`/`paths-ignore:` filter. OSSF Scorecard's SAST check
  inspects recent merged PRs and wants a CodeQL check-run on each one, including
  config-only PRs — a path filter would silently skip those and regress the
  Scorecard SAST score.
* `dependency-review` and `scorecard` lean on the public dependency graph /
  public results, so they're fully effective now the repo is public.

## Local pre-push parity

`scripts/ci.sh` runs the Rust fmt/build/test/clippy steps and the sidecar's
`npm ci` + build + typecheck locally (zero Actions minutes). To also run the
rest of the gate and the security scanners locally:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo deny check bans licenses sources   # as CI; advisories are cargo-audit's
cargo audit -D warnings                  # RustSec, as CI
( cd oauth-sidecar && npm test && npm run lint && npm run format:check && npm audit --omit=dev --audit-level=high )
gitleaks git --config .gitleaks.toml --redact --exit-code 1   # same as CI: full history
```

## Config files (repo root)

* `deny.toml` — cargo-deny (AGPL-compatible license allowlist; `[advisories]
  ignore` is the documented escape hatch for un-actionable transitive vulns).
* `.gitleaks.toml` — gitleaks ruleset + false-positive allowlist (lockfiles,
  `*.example`, and the base64 `foobarsecrettoken` test fixture in the Rust
  redaction tests).
* `oauth-sidecar/.oxlintrc.json`, `.prettierrc.json`, `.prettierignore` —
  sidecar lint/format config. `npm run format:check` is scoped to the tooling
  files; the hand-authored `src/`/`test/` predate Prettier and are enforced for
  **correctness** by oxlint. `npm run format:write` is the one-time follow-up to
  Prettier-format the whole sidecar when convenient.

## Repo-settings toggles (NOT in these files — do them in the GitHub UI)

These are org/repo settings the workflows assume but cannot set:

1. **Dependabot alerts** + **Dependabot security updates** — Settings →
   Advanced Security. (Alerts free for public; security updates free for public.)
2. **Secret scanning** + **push protection** — Settings → Advanced Security.
   Native secret scanning is **free for public repos** and complements the
   gitleaks job (native = real-time on push; gitleaks = history + custom rules).
3. **Code scanning (CodeQL)** — enabling "default setup" is optional; this repo
   uses the **advanced/workflow setup** (`codeql.yml`). Free for public repos.
4. **Branch protection** on `main` (require CI + review) — also what Scorecard
   grades.
