# 0.5.0 — Rust-only

> **Status: planned (2026-10-17).** Nothing here is built yet. Tracking issue:
> #311. The plan below is updated per step as work lands, as
> `STANDARD-SITE-0.4.0.md` was.

**0.5.0 removes the Node OAuth sidecar.** The Rust OAuth client and repo
backend have served production since v0.3.3 (PR #110). The sidecar still ships
in the image, is still the **default** when `FEATHERREADER_REPO_BACKEND` is
unset, and guards none of its outbound fetches (issue #258). After 0.5.0 there
is one backend, and no setting selects anything else.

The release also carries the two record-format items left from the item-id
work (#287 PR 3, #290), the capacity measurement (#263), and the small
hardening issues that are ready.

**Not in 0.5.0:** opening registration or raising the beta cap. #263 produces
the numbers for that decision, which is taken separately afterwards.

---

## Decisions (the user, 2026-10-17)

| # | Decision |
|---|---|
| D1 | 0.5.0's theme is removing the sidecar. |
| D2 | **Remove it outright**, with no deprecation release first. FeatherReader has one known operator. The README's promise of a deprecation notice before removal (README "Choosing an OAuth backend") is withdrawn; the 0.5.0 upgrade notes are the notice. |
| D3 | #287 PR 3 (`readThrough` basis) and #290 (`saved.entryId`) ship in 0.5.0. |
| D4 | Registration (the beta cap, or opening it) is a separate decision, after #263. |

---

## Behaviour after the upgrade

| Setting | 0.4.x | 0.5.0 |
|---|---|---|
| `FEATHERREADER_REPO_BACKEND` unset | sidecar | Rust (the only backend) |
| `FEATHERREADER_REPO_BACKEND=rust` | Rust | accepted, no effect |
| `FEATHERREADER_REPO_BACKEND=sidecar` | sidecar | **refuses to start**, saying the sidecar was removed in 0.5.0 and pointing at the upgrade notes |
| any other value | refuses to start | refuses to start (unchanged) |
| `SIDECAR_INTERNAL_SECRET` | required in production, even on Rust | not read; a warning at boot if set |
| `SIDECAR_PUBLIC_URL`, `SIDECAR_INTERNAL_URL`, `SIDECAR_*` | read | not read |
| `FEATHERREADER_OAUTH_ENCRYPTION_KEY` | required on Rust | required |
| `/health` `backend:` line | `sidecar` or `rust` | **kept**, always `rust`, so monitors that match it keep working |

A refusal on `=sidecar`, not a silent switch to Rust, follows the rule
`parse_repo_backend` already states: a fallback would hide that the operator's
configuration no longer means what they think.

**Who is affected:** only an instance running the sidecar backend, that is one
with the variable unset or set to `sidecar`. feather-reader.com sets `rust`
(`fly.toml`) and sees no change. Staging also runs `rust`.

**What such an instance loses:** every signed-in reader is signed out once. The
sidecar's tokens live in `/data/oauth-sidecar.db`, which nothing migrates, so the
PDS grants stay live until they expire. To revoke them first, run 0.4.x's
`deploy/teardown.sh` before upgrading. The upgrade notes say this, and that the
leftover `oauth-sidecar.db` and its `.jwk.json` can be deleted.

---

## What must NOT change (the risk list)

From the scope inventory, 2026-10-17. Each is a way the removal could break the
Rust backend it leaves behind.

1. **The encryption domain string `"featherreader-sidecar-enc:v1:"`**
   (`src/oauth/crypto.rs`). It is an input to key derivation. Renaming it makes
   every stored `oauth_session` row and the signing key undecryptable: every
   reader signed out and the client key lost. It keeps its name, with a comment
   saying why. The test vectors that came from the sidecar's `dist/crypto.js` are
   embedded, so they survive the directory's deletion.
2. **The key file format** (`src/oauth/keys.rs`) stays as it is, for the same
   reason.
3. **The callback's session type.** The Rust callback returns
   `atproto::SidecarSession`, so that type is renamed (for example
   `LoginSession`) before `SidecarClient` is deleted, not deleted with it.
4. **The upgrade-boot gate uses Node in the candidate.** `scripts/upgrade-boot.sh`
   health-checks the candidate with `docker exec … node -e fetch(…)`. A Node-free
   candidate fails the gate. The check moves to something both old and new
   images have, such as bash's `/dev/tcp`, **before** the Node runtime is
   removed. Seeding the previous release's database with `node:sqlite` in the
   *previous* image keeps working.
5. **The runtime base image.** It is `node:24-bookworm-slim` today. The
   replacement (for example `debian:bookworm-slim`) still needs tini, gosu,
   bash and ca-certificates, and the same UID/GID for `/data`.
6. **The `wait -n` supervisor** in `deploy/container-entrypoint.sh` still
   supervises Caddy and the app. Only the Node branch goes.
7. **CodeQL has nothing left to scan.** Its only leg is `javascript-typescript`,
   for the sidecar. Rust was dropped because the extractor (then in beta) failed
   on every file. OSSF Scorecard's SAST score expects a CodeQL check-run on every
   PR. **Retried 2026-10-18 (PR #313): the Rust extractor works.** On CodeQL
   2.27.2 all 47 files extract without error, 30 rules run, 0 results, about
   5.5 min per run. The Rust leg stays, and replaces the JS leg in step 4.
8. **The test harness defaults to the sidecar.** `web.rs`'s `test_state` uses
   `..Config::default()`, which is the sidecar backend, and about 87 tests use
   sidecar fakes (`/internal/repo`). Those tests cover rename, saved, export,
   malformed records, logging and flush-before-revoke. They are moved to the
   Rust backend's PDS/XRPC fakes **before** the sidecar code is deleted, so
   no coverage is lost in the deletion PR.

Fine as they are: the bot crate (app-password `createSession`, no sidecar
use); the `oauth_*` tables, already created unconditionally; the session
cookie; `client_id` URLs, which come from `FEATHERREADER_PUBLIC_URL`;
`lexicon::sort`, shared and kept.

---

## The work, in order

Each step is one PR unless it says otherwise. Steps 1–4 are the removal and go
in order; 5–7 are independent and land as they are ready.

### 1. Release safety, before anything is removed

- `scripts/upgrade-boot.sh`: health-check the candidate without Node (risk 4).
- Add a 0.4.10 schema fixture (`tests/fixtures/schema-v0.4.10.sql`) for the
  upgrade test.
- ~~Retry CodeQL's Rust extractor on a branch; record the result (risk 7).~~
  **Done** (PR #313): it works; the Rust leg is re-added.

### 2. Rust is the default; tests move to it

- `Config::default()` and the entrypoint select Rust when the variable is unset.
- Move the ~87 sidecar-faked tests to the Rust backend's fakes (risk 8). Drop
  the dual-backend fixtures to Rust only (`readstate.rs` `BACKENDS`,
  `web.rs`).
- Rename `SidecarSession` (risk 3).

No behaviour change for feather-reader.com: it already sets `rust`.

**Done** (this PR): the default, the entrypoint and teardown; the sidecar-faked
web tests on a Rust fake PDS (`spawn_pds`), the revoke paths over real TLS; the
`SidecarSession` renamed `LoginSession`. The dual-backend loops (`readstate`
`BACKENDS`, `web` `RACE_BACKENDS`) still run both while `sidecar` can be
selected; they drop to Rust in step 3, with the fixtures' sidecar halves and the
tests of sidecar code itself (its revoke arm's metric, `SidecarClient`).

### 3. Remove the sidecar from the Rust code

- Delete `SidecarClient`, `SidecarSession`'s old uses, `RevokeResult`,
  `RepoAction` and `WriteOp::to_sidecar_json` (`atproto.rs`, about 820 lines);
  the `sidecar:` arms of `repo.rs`'s `dispatch!`; `revoke_everywhere`'s sidecar
  half, `sidecar_handoff` and `CallbackQuery.session_id` (`web.rs`);
  `SidecarConfig`, the `SIDECAR_*` reads and the secret checks (`config.rs`);
  `AppState.sidecar` (`lib.rs`); `Backend::Sidecar` (`metrics.rs`, where old
  persisted `"sidecar"` rows are already skipped).
- `FEATHERREADER_REPO_BACKEND` handling as in the table above.
- Keep the encryption domain string and key format (risks 1, 2).
- Delete the sidecar-only tests (backend parsing, sidecar secret refusals,
  `SidecarClient` tests, `spawn_revoke_sidecar`).

**Done** (this PR). `Backend` is kept with one variant: it labels the metric
rows and `/health`'s `backend:` line. `oauth` on `AppState` is still an
`Option`, always `Some`, so handlers did not all change in this step. Found on
the way: with the signing key now always created for a confidential client,
three web tests on a production-like URL wrote real key material to the
relative default path; they use a temp key.

### 4. Remove it from the image, deploy and CI

- **Dockerfile:** drop the node-build stage and the sidecar copy; new runtime
  base (risk 5); drop the `SIDECAR_*` env.
- **Entrypoint:** drop backend selection, the Node start and the routing copy;
  always install the Rust routing.
- **Caddy:** delete `deploy/caddy-oauth-sidecar.conf` and the `@internal`
  block; the Caddyfile CI job validates one routing.
- **`fly.toml`:** drop `FEATHERREADER_REPO_BACKEND` and the `SIDECAR_*` env;
  rewrite the comments.
- **Teardown:** `deploy/teardown.sh`, `deploy/teardown.md` and
  `scripts/test-teardown.sh` lose the sidecar revoke path and backend default.
- **CI:** delete the `sidecar` job and the npm group in `dependabot.yml`; drop
  the npm block in `scripts/ci.sh`; drop CodeQL's `javascript-typescript` leg,
  leaving `rust` (PR #313).
- Delete `oauth-sidecar/`, and its lines in `.dockerignore`, `.gitignore` and
  `.gitleaks.toml`.
- The production secret `SIDECAR_INTERNAL_SECRET` is unset with
  `fly secrets unset` after 0.5.0 is live, not before.

### 5. Docs and copy

README (architecture, build and run, the env table, "Choosing an OAuth
backend"), CONTRIBUTING, SECURITY, `.github/workflows/README.md`, the
`templates/about.html` and `templates/terms.html` sentences about "a small OAuth
sidecar", `design/architecture/runtime.mmd` and its PNGs, and doc comments in
`src/oauth/`. Design docs that are historical keep their text and gain a
one-line status note.

### 6. Record format (#287 PR 3, #290)

- **`readThrough` basis (#287 PR 3).** `readThrough` is compared against an
  entry's published date only. `compact_cursor` drops `fetched_at`
  (`COALESCE(published, fetched_at)` becomes `published`), so an undated read
  stays an id. An import then applies a remote `readThrough` to local **dated**
  entries, except one in the record's `unreadIds` and one whose local explicit
  unread is newer than the record's `updatedAt`. That removes the #286 limit on
  compacted reads. Tests as listed in #287.
- **`saved.entryId` (#290).** Starring writes `entryId` by the item-id rule,
  with the same mapping `readstate` uses (`guid_synthesized`): the publisher
  id, the `at://` URI, else the link, and omitted for a row with no portable
  id. Matching accepts the old stand-ins too, so records already written still
  resolve. The "Status in FeatherReader" note in `docs/lexicon.md` goes. Tests
  as listed in #290.

These change what is written to readers' PDSes. They are tested against a
0.4.10 database and records written by 0.4.10.

### 7. Capacity measurement (#263)

Staging runs in a container with the same 512 MiB limit as the Fly machine
(`shared-cpu-1x`, 512 MB), so it is the test bed:

- a synthetic feed server on `apps`, serving N feeds of realistic size and
  churn;
- measure poll throughput per tick, memory per concurrent poll, and DB growth
  per feed per day, at N = 100, 1,000 and 5,000;
- set `max_feeds_global` (10,000), `FEATHERREADER_POLL_BATCH` (50) and the DB
  watermark from the numbers, and record them here.

The result goes into the registration decision (D4). Changed defaults, if any,
go in the upgrade notes.

### Hardening that lands in 0.5.0 if ready

#261 (rate-limit new routes by default), #260 (a validated feed-URL type for
`upsert_feed`), #262 (production evidence for `private_key_jwt` and RFC 7009
revocation, captured on staging with the test account), #275 (hostile feeds
holding every sanitize permit), #284 (budget charge on a page with a malformed
record), #280 (remaining refusals filed as Fetch), #272 (renames drop unknown
fields). None blocks the release.

---

## Release

- Rehearse the upgrade on a copy of a 0.4.10 production volume, and the
  rollback to 0.4.10 on the result. Rolling back is supported only if 0.5.0 adds
  no schema change; if a step adds one, its PR says whether 0.4.10 can still boot
  on it, and the upgrade-boot gate checks it.
- `v0.5.0-rc.N` soaks on staging (#294), which runs the Rust backend as
  production does. Staging's login, star, read-state flush and sign-out are
  exercised with the test account before the final tag.
- Final `v0.5.0` on the soaked commit; the GitHub release is created by CI
  (#308).
- **Upgrade notes must cover:** the sidecar's removal; the
  `FEATHERREADER_REPO_BACKEND` table above; the one-time sign-out for sidecar
  instances and how to revoke first; files that can be deleted; the new image
  base; the `readThrough` and `saved.entryId` changes; any changed capacity
  defaults.

---

## Out of scope, on purpose

- **Registration** (D4).
- **The network indexer** (#295): a standalone experiment crate, not tied to a
  release.
- **The NSID authority question** (#287): still open, decided separately.

## Open questions

1. ~~**CodeQL.**~~ Resolved: the Rust extractor works (PR #313).
2. **Image base.** `debian:bookworm-slim`, or a smaller base that still has bash
   for the entrypoint?
3. **Old variable names.** Should `SIDECAR_*` set in an environment warn once
   at boot (as planned) or be ignored silently?
