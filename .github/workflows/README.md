# CI / Security workflows

This directory holds FeatherReader's CI + security pipeline. The guiding
principle is **spend zero GitHub-hosted Actions minutes for the everyday
build/test/lint gate** (that runs on a self-hosted `linux/x64`
runner), while using **GitHub-hosted runners only for the tools that require
them** — CodeQL, dependency review, and OSSF Scorecard. Those three are **free
once the repo is public** (this repo is flipping public); until then they cost a
small amount of hosted minutes, so their triggers are deliberately narrow.

| Workflow | Runner | Triggers | What it does |
|---|---|---|---|
| `ci.yml` | **self-hosted** | push/PR to `main`, manual | The gate. Jobs: **rust** (build/test/clippy `-D warnings`/rustfmt), **cargo-deny** (licenses + bans + advisories + sources via `deny.toml`), **cargo-audit** (RustSec), **sidecar** (npm ci/build/typecheck + **oxlint** + **Prettier `--check`** + `npm audit --omit=dev`), **secrets** (**gitleaks** tree + history via `.gitleaks.toml`). |
| `codeql.yml` | **GitHub-hosted** (`ubuntu-latest`) | **PR to `main`** + push to `main` + weekly cron + manual | SAST for `javascript-typescript` (the OAuth sidecar). Runs on **every** PR — no `paths:` filter, so config-only PRs still get a CodeQL check-run (OSSF Scorecard's SAST check needs one on each merged PR). Rust is covered by clippy + cargo-deny + cargo-audit (CodeQL's Rust extractor errored on all files; re-add when GA'd). Results → Security tab. Free once public. |
| `dependency-review.yml` | **GitHub-hosted** | pull_request to `main` | Blocks PRs that add vulnerable deps or disallowed licenses (aligned with `deny.toml`). Needs the Dependency Graph — free/on for public repos. |
| `scorecard.yml` | **GitHub-hosted** | branch-protection change + weekly cron + push `main` | OpenSSF supply-chain posture score → Security tab + public badge. Most useful once public. |
| `../dependabot.yml` | n/a (GitHub-native) | weekly | Grouped minor/patch update PRs for **cargo** (`/`), **npm** (`/oauth-sidecar`), **github-actions** (`/`), and **docker** (`/deploy`, commented until a Dockerfile lands). |

## Self-hosted vs GitHub-hosted, and the public-repo cost note

* **Self-hosted (`ci.yml`)** — the CI VM already has Rust, Node, and the
  scanners cached; running here is free of GitHub minutes and fast. `gitleaks`
  runs fine here today. This is the everyday gate.
* **GitHub-hosted (`codeql.yml`, `dependency-review.yml`, `scorecard.yml`)** —
  these tools ship in the GitHub-hosted Actions image / call GitHub-only APIs
  (dependency graph, code-scanning SARIF ingest, the Scorecard API). They are
  **free for public repositories**, which is the steady state for this repo:
  * CodeQL runs on **every PR to `main`** plus push to `main` and a weekly cron.
    Do **not** add a `paths:`/`paths-ignore:` filter — OSSF Scorecard's SAST
    check inspects recent merged PRs and wants a CodeQL check-run on each one,
    including config-only PRs. A path filter would silently skip those and
    regress the Scorecard SAST score.
  * `dependency-review` and `scorecard` are fully effective on the public repo
    (they lean on the dependency graph / public results).

## Local pre-push parity

`scripts/ci.sh` runs the Rust + sidecar build/test/lint locally (zero Actions
minutes). To also run the security scanners locally:

```sh
cargo deny check                     # licenses + bans + advisories + sources
cargo audit                          # RustSec
( cd oauth-sidecar && npm run lint && npm run format:check && npm audit --omit=dev --audit-level=high )
gitleaks dir . --config .gitleaks.toml
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
