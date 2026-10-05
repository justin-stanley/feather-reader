# Security Policy

FeatherReader handles OAuth tokens and reads/writes records in a user's own
atproto PDS, so security reports are taken seriously and handled promptly.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub's [private vulnerability
reporting](https://github.com/justin-stanley/feather-reader/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). This opens a
private advisory visible only to the maintainers.

Please include, where you can:

- a description of the issue and its impact,
- steps to reproduce (or a proof of concept),
- affected version / commit,
- any suggested remediation.

## What to expect

- **Acknowledgement:** within 5 business days.
- **Assessment & triage:** we'll confirm the issue, determine severity, and keep
  you updated on progress.
- **Fix & disclosure:** we aim to ship a fix as quickly as the severity warrants
  and will coordinate public disclosure (and credit, if you'd like) once a
  release is available.

## Scope

In scope: the FeatherReader server (Rust) — including its built-in atproto OAuth
client — and the OAuth sidecar (`oauth-sidecar/`) in this repository — e.g. authentication/session handling,
SSRF, injection, secret handling, per-user data isolation.

Out of scope: vulnerabilities in third-party dependencies (report those
upstream; we track them via Dependabot, `cargo audit`, and dependency review),
and issues that require a pre-compromised host or a self-hosted misconfiguration
the README's [Self-hosting](README.md#self-hosting) section or `fly.toml` warns against.

## Supported versions

FeatherReader is pre-1.0 and evolving; security fixes land on `main` and the
latest published release. There are no backports to older lines. Please test
against `main` before reporting.

| Version | Supported |
|---|---|
| 0.4.x (latest: 0.4.4) | yes — fixes ship in the next 0.4 patch release |
| < 0.4 | no — upgrade to the latest release (0.3.9 is also yanked: it fails to start on an existing database) |

Releases and what each one fixed are in [CHANGELOG.md](CHANGELOG.md).
