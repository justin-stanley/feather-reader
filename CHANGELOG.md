# Changelog

Engineering detail, newest first. Covers everything since
0.3.0. Work that has landed on `main` but is not yet tagged appears under
**Unreleased**, when there is any.

Each entry says what changed, the mechanism, and — where a defect is involved —
how it was established rather than assumed. Several entries record that a test
passed while proving less than its name; those are noted, because the
measurement is the load-bearing part.

Versions are git tags (`vX.Y.Z`). A tag publishes to crates.io and ghcr.io;
deploying is separate.

---

## Unreleased

### Security

- **The reader no longer renders a stored article body with `|safe` (#151).**
  `EntryTemplate.content_html` was the stored `entries.content_html` string,
  emitted into `entry.html` unescaped. It was safe only because ingest had
  run `ammonia` over it in `feed.rs` — a procedural guard on another code
  path, the same shape `SafeLink` replaced for the entry's links. Not a live
  hole: ingest is the only writer and its sanitizing is tested.

  **The type.** New module `sanitized_html` with `SanitizedHtml`: a private
  field, no `From<String>`, no `Deref`. Its only constructor runs ingest's
  own `feed::sanitize_html` (one policy, pinned byte for byte by a test), and
  it implements askama's `HtmlSafe`, so `entry.html` renders it with no
  `|safe` at all. The guarantee cannot ride through SQLite `TEXT`, so the
  handler re-cleans the stored body at render, on tokio's blocking pool. Two
  `compile_fail` doctests, pinned to E0451 and E0277, show a raw string
  cannot become one. A test that writes `<script>`, `onerror` and a
  `javascript:` link straight into the column, bypassing ingest, failed
  before the change: all three reached the page.

  **Measured cost.** On 545 real bodies from 20 public feeds (release build),
  re-cleaning took p50 31 µs, p99 1.1 ms, max 3.5 ms (a 561 KB body), and is
  idempotent on all 545: identical bytes, so readers see no change. Two
  known exceptions, both the same page to a browser, each pinned by a test:
  a literal U+00A0 in a standard.site plain-text summary comes back as
  `&nbsp;`, and a table whose `<tfoot>` the policy stripped gains the
  `<tbody>` a browser builds around those rows anyway.

  **Threat model and bounds.** A body that is expensive to clean cannot come
  from ingest, which sanitizes everything it stores; it can only come from a
  bug or from someone already able to write the database. For such a row the
  sanitizer is quadratic — measured, a stored 2 MiB of nested `<div>`s takes
  ~37 s, a 2 MiB `&` run 2.4 s. The render path (`BodyRenderer`) does not
  try to predict that cost; it caps what one row can cost everyone else:
  - **Size cap.** A stored body over the bound ingest enforces
    (`MAX_CONTENT_HTML_BYTES`, 2 MiB) is not given to the sanitizer; the
    page shows a short note and the link to the original. Ingest never
    writes such a row.
  - **Concurrency limit.** A process-wide semaphore of 2 permits around the
    clean. A request waits up to 2 s for a permit (asynchronously; no worker
    thread is blocked), then shows a "temporarily unavailable" note. Real
    cleans take microseconds, so the wait is only ever reached while two
    pathological bodies are being cleaned at once.
  - **Cache.** Cleaned output is cached in memory, keyed by the SHA-256 of
    the stored body (`ring`, already a dependency; a fast hash's collisions
    would show one entry's body on another's page), least recently used
    out first, bounded at 256 bodies and 8 MiB of output. Each body is
    cleaned once per process, not once per view.

  The worst case is therefore a pathological row's own page view: up to
  ~37 s, once, holding one of two permits, with every other page unaffected.

  **Why not a pre-scan.** Earlier revisions of this change bounded the cost
  with a linear scan in front of the sanitizer that modelled html5ever's
  open-element stack and text nodes (nesting depth, a text-cost budget for
  `&` and U+00A0, attribute limits, implicit-close rules) and cut the body
  where the model ran out. Three review rounds each found a mismatch between
  the model and the parser; the last found it cutting articles ingest
  legitimately stores: `<li>` in `<li>` after ammonia strips a `<section>`
  (and `p`/`a`/`h2` likewise), an unhighlighted `<pre><code>` XML listing
  of ~245 KB, and `<rt>` inside a `<span>` in `<ruby>`. Re-implementing the
  parser's rules in front of the parser can only reopen a slow path or
  truncate real articles, so the scan is gone and those shapes are pinned by
  a test that renders each in full.

  The other `|safe` in the templates, in `manage.html`, renders the
  compile-time constant `FEED_URL_PATTERN`, not content, and is unchanged.

---

## 0.4.6 — 2026-10-06

Renames no longer lose data. Renaming a subscription is a compare-and-swap
write that cannot erase another atproto client's concurrent edit (#149), and
renaming a folder changes only its name instead of rebuilding the record
(#268).

### Upgrade notes

- **No schema change, no new settings.** Upgrading from 0.4.5 is a deploy;
  rolling back to 0.4.5 is a redeploy.
- **Rename writes carry `swapRecord`.** A rename that races another client's
  edit is retried once against the fresh record, keeping that client's
  change, and otherwise shows "changed elsewhere … Reload and try again"
  instead of reporting success. A folder rename that fails now shows an
  error; it used to redirect as if it had worked.
- **The manage page posts the values it showed** (`seen_url`, `seen_title`,
  `seen_folder`, `seen_name`), so a change made elsewhere after the page
  loaded is detected too. A form posted without them still works.

### Fixed

- **Renaming a folder overwrote the folder record (#268).** `POST
  /folders/:rkey/rename` put `Folder::new(name, now)` over the existing
  record. Every rename reset `position` (the sort hint another
  `community.lexicon.rss` client may have set), replaced `createdAt` with the
  rename time, and dropped any field another client had added, because
  `lexicon::Folder` had no catch-all. A failed rename only logged a warning
  and redirected as if it had worked.

  **Mechanism.** `Folder` gains `extra`, a `#[serde(flatten)]` map of every
  field it does not name. The named fields are consumed first, so the map
  never holds `$type`, `name`, `position` or `createdAt`, and a serialized
  record never has a duplicate key. It is empty for a folder this build
  creates (`POST /folders`, OPML import), so those records are unchanged. A
  new `list_folders_with_cids` on the Rust client, the app-password client
  and the sidecar client, through `dispatch!`, returns each folder's CID, as
  `list_subscriptions_with_cids` does. There is no single-record `get`,
  because the sidecar has no `get` action. `rename_folder` takes
  `swap_record` on every backend.

  **The rename.** The handler reads the folder and its CID, changes only
  `name`, and writes it back with `swapRecord` set to that CID. On
  `InvalidSwap` it reads again and does a three-way merge on the name, using
  #149's retry bound. The ancestor is `seen_name`, which the manage page now
  posts and which holds the record's own name, or the first read when the
  form has no `seen_name`:
  - the reader left the name as shown: success, nothing written;
  - the record already has the reader's name (a double-submitted Save):
    success, nothing written;
  - the record still has the ancestor's name: the fresh record is renamed,
    so another client's concurrent change to `position` or anything else
    is kept;
  - someone else renamed it differently: nothing is written, and the
    reader sees "This folder was changed elsewhere … Reload and try again".

  Because `seen_name` is the exact record name, unlike a subscription's
  display title, it also catches a rename made elsewhere between page load
  and the first read. A second refusal is reported as the conflict. A folder
  that is no longer in the repo is reported as such and is not recreated:
  a put at a missing rkey would create it. A failed read or a failed write
  shows an error flash and writes nothing.

  Tested on both backends through the handler, against the swap-enforcing
  fake repo from #149: the exact record put on a rename, a concurrent
  `position` change kept across the retry, both renaming differently, both
  renaming the same, every swap refused, a 502, a missing folder, a failed
  read, the page-load window with `seen_name`, an unchanged name, the folder
  CID listing on each client, the catch-all round trip, and a new folder
  carrying no extra keys. Each test failed before the fix. All 20 mutants
  were killed, among them the record rebuilt with `Folder::new`, the
  catch-all dropped, the swap hardcoded to `None` on each backend, no retry,
  a conflict reported as success, agreement reported as a conflict, the
  error swallowed, a missing folder recreated, and the CID dropped from each
  listing.

  `Subscription` has no such catch-all either. A subscription rename keeps
  every field `Subscription` names (#147), but drops fields it does not
  name. That is left as a follow-up.

- **Renaming a subscription could erase another client's concurrent edit to
  it (#149).** Since #147 the rename handler reads the subscription record,
  applies the form's fields, and `putRecord`s the whole record back. Nothing
  tied the write to the read, so if another atproto client wrote the same
  record in between, our put replaced theirs and their change was gone with
  nothing to say so.

  **Mechanism.** `putRecord` now takes an optional `swap_record` on all three
  write paths — the Rust OAuth client, the app-password `PdsClient`, and the
  sidecar client — sent as `swapRecord` (the CID the caller read) and omitted
  when `None`. The sidecar's `put` action validates it as a CID string and
  passes it to `agent.com.atproto.repo.putRecord`. The PDS refuses a stale
  swap with `400 InvalidSwap`; `atproto::is_invalid_swap` recognises that from
  each client's structured `AtProtoError::Xrpc` by error name, including under
  a context and under `ApplyWritesIncomplete`. A new
  `list_subscriptions_with_cids` returns each record's CID, on both backends
  and through `dispatch!`; `list_subscriptions_sorted` and its callers are
  unchanged.

  **The rename.** It reads with the CID and writes with `swapRecord` set to
  it. On `InvalidSwap` it reads again and **merges**: a three-way merge of the
  form against the record as first read. The manage row always posts every
  input, so replaying the form would have put back fields the reader never
  touched — a review caught the retry repointing a record another client had
  just moved back to its old URL, and clearing that client's `siteUrl`. Now,
  per field (`url`, `title`, `folder`, and a posted `site_url`):
  - untouched by the reader: the fresh value stands;
  - changed by the reader only: their value is applied;
  - changed by both to the same value: agreement, not a conflict. When every
    change the reader made is already in the record, as with a
    double-clicked Save whose first request landed, the rename reports
    success and writes nothing;
  - changed by both, differently: nothing is written and the reader is told.

  The folder select renders only when the page has folders to list, so a
  rename posted with neither `folder` nor `seen_folder` leaves the folder
  alone. Reading that as "no folder" un-foldered every subscription retitled
  from such a page.

  #147's preservation of the other fields still holds. Whether a rename is a
  repoint, which drops the old feed's `siteUrl` and `fetchHint`, follows the
  reader's change. The gates re-run against the merged record, and the write
  goes under the new CID. A second refusal, or a field both sides changed, is
  reported as "This subscription was changed elsewhere … Reload and try
  again", never as success. Any other failure behaves as before: no retry,
  same message. A PDS that lists a record without a CID (outside the lexicon)
  gets the old unconditional write and a `warn` line.

  **What the reader changed.** The manage row now posts `seen_url`,
  `seen_title` and `seen_folder`: the values its inputs were pre-filled with.
  The title input shows a display fallback for an untitled record, so the
  record alone cannot say whether the reader edited it. With them, a field
  another client changed between page load and the first read is no longer
  mistaken for the reader's edit. Without them (a hand-made POST, or a page
  from an older build), the first read stands in. What remains: a field
  changed by both the reader and another client, where the other change
  landed before the first read, is last-writer-wins on that field. The
  conflict check compares against the first read, not the page-load record.

  **The cache follows the PDS.** The rename wrote the local `feeds` cache
  (the new title, or a new row for a repoint's URL) before the PDS write. A
  rename the PDS refused, whether a failed save or both attempts of a lost
  race, still left that behind, including a row the poller would fetch for
  no subscriber. The cache is now written only after the PDS write lands.
  Every gate on the URL still runs before it.

  **Other writers audited.** The read-state writes are blind writes, not
  read-modify-writes, so they have no CID to compare and are unchanged.
  Folder rename was a blind write too, one that rebuilt the record; the
  entry above (#268) makes it a compare-and-swap edit of the stored record. The other read-then-write paths — unstar, OPML folder
  creation, and the read-state reconcile — delete, create, or read existence
  only.

  Tested on both backends, end to end through the handler, against a fake
  repo that enforces `swapRecord` the way the reference PDS does. One case
  lands another client's edit between the read and the write: the edit
  survives and the rename lands. One refuses every swap: at most two puts,
  then the conflict message. Others cover a concurrent repoint or retitle the
  reader did not make, a title both sides changed, a repoint before the first
  read, a rename that did not land leaving the cache alone, a double-submitted
  Save, the same edit on both sides, and a page with no folder select. The
  wire tests show `swapRecord` present when given and absent otherwise on
  each client and on the sidecar. Each guard was mutated (39 mutants, including the swap
  hardcoded to `None` on each backend, the merge measured against the fresh
  record, and the cache written before the put), and every mutation failed a
  test.

## 0.4.5 — 2026-10-06

A teardown can now revoke the `rust` backend's sessions (#257): a new
`featherreader --revoke-all-sessions` signs every stored session out at its
PDS, and `deploy/teardown.sh` runs it before the wipe. Closing the races that
work exposed also changes how a token refresh and a sign-out write the session
row. Plus the documentation refresh.

### Upgrade notes

- **No schema change, no new settings.** Upgrading from 0.4.4 is a deploy;
  rolling back to 0.4.4 is a redeploy.
- **Session writes are now conditional.** A token refresh updates the session
  row only if it still holds the tokens the refresh started from, and never
  re-creates a row that a sign-out deleted. A sign-out deletes the row only if
  it is unchanged since it was read. Login still writes unconditionally. Users
  see no difference. A refresh that loses such a race revokes the tokens it
  could not store; if that revocation fails, a `warn` line says so ("a session
  changed or was signed out during its refresh").
- **`--revoke-all-sessions` is an operator tool, not a routine operation:**
  it signs every user out. See `deploy/teardown.md` for when and how to run
  it, its exit codes and its pre-flight checks.

### Security

- **A teardown now revokes the `rust` backend's sessions before the wipe
  (#257).** `deploy/teardown.sh` read DIDs only from `SIDECAR_DB`. On
  `FEATHERREADER_REPO_BACKEND=rust`, which production runs, it revoked
  nothing: wiping `FEATHERREADER_DB` dropped every refresh token unrevoked,
  live at each PDS until it expired.

  **The revoke command.** New operator flag `featherreader
  --revoke-all-sessions`, built like `--migrate-auto-vacuum`: it exits before
  binding a port or starting a scheduler, and skips `argv[0]`. It lists every
  `oauth_session` row with `oauth::store::list_session_subs`, which reads
  `sub` only, so rows that no longer decrypt are listed too. Each row goes
  through `sign_out_discovering`, the same sign-out `/logout` uses: a bounded
  RFC 7009 revocation, then a delete whatever the PDS said. A failure does not stop
  the walk. The clock is read **per session**, because each sign-out mints a
  client assertion that is valid for 60 s. A single timestamp taken at the
  start would have expired every assertion sent after the first minute, so
  those revocations would have been rejected while their rows were deleted.

  **Exit codes.** `0` means all revoked. `3` means some revocations failed;
  their rows are deleted anyway, except one that kept rotating or reappearing.
  `2` means nothing was done, and in that
  case nothing is deleted either. The causes of `2`:

  - bad configuration;
  - a missing database: it refuses rather than creating one and reporting
    "0 sessions" about the wrong file;
  - an unreadable store;
  - a missing signing key at `FEATHERREADER_OAUTH_KEY_PATH`: this mode loads
    the key and never creates one, since a fresh key is one no PDS can verify;
  - sessions stored with no buildable OAuth runtime;
  - sessions stored while the client is not the production one: a loopback
    or unset public URL, no encryption key, or no signing key. An incomplete
    environment does not fail to start; it starts as atproto's public dev
    client, or with a codec that cannot read a row. Every revocation would
    then fail while every row was deleted;
  - sessions stored while the secrets are present but **not the production
    ones**, checked in a pre-flight before the first sign-out:
    - no stored row decrypts with the encryption key (wrong or rotated);
    - the loaded signing key's thumbprint and `kid` are not in the JWKS the
      app serves at `/oauth/jwks.json`, as with a relative key path resolved
      in the wrong directory;
    - that JWKS cannot be fetched on the main pass. The post-stop
      `--revoke-all-sessions --sweep`, which `teardown.sh` appends, tolerates
      an unreachable JWKS but not a mismatch. The JWKS is the operator's own
      configuration, so it is fetched with a plain bounded client: https only,
      no redirects, 10 s, 64 KiB. Going through the SSRF guard made a
      split-horizon or LAN self-host fail the main pass every time.

    `--accept-unreadable` (`FR_ACCEPT_UNREADABLE=1` in `teardown.sh`)
    overrides only the "no row decrypts" refusal, for a store that is
    legitimately all unreadable: only pre-AAD rows, or a deliberate key
    rotation with no logins since. The unreadable rows are deleted and
    reported as failed (exit 3). Their tokens cannot be revoked by anyone.

  A completed run prints a last line,
  `revoke-all-sessions: revoked=N no_session=M failed=K`. Partial failure is
  deliberately not `1`. An older binary that ignores the flag exits 1 when its
  server fails to bind, and a failing wrapper exits 1 too; neither prints that
  line.

  **Teardown order.** The script runs: the sidecar revoke, then the Rust
  revoke **while the app still serves**, then the stop, then a Rust sweep,
  then the wipe. The wipe now also removes `FEATHERREADER_OAUTH_KEY_PATH`.
  The sweep runs only if `FEATHERREADER_DB` still holds Rust sessions, counted
  directly with `sqlite3`. It uses `FR_SWEEP_CMD` when set. A main-pass
  command that needs the running service (`docker compose exec`) cannot run
  after the stop, and used to abort every container teardown at this step;
  for Docker the sweep is `docker compose run --rm`.
  The main pass runs before the stop for a measured reason. A PDS
  authenticates a confidential client before revoking
  (`@atproto/oauth-provider` 0.23.1, `revoke()` → `authenticateClient`),
  using our `client-metadata.json` and `jwks.json`. The app serves both, and
  PDSes cache them for only 600 s, so a revocation after the stop would be
  rejected at most PDSes.

  **Refusals and failures.** The script refuses, before anything
  irreversible, when the backend is `rust` (or `FEATHERREADER_DB` holds Rust
  sessions) and there is no revoke command. A Rust pass proceeds only on exit
  `0` with `failed=0`, or exit `3` with `failed>0` (which warns), and only if
  the sentinel is the last line of output. Anything else aborts before the
  wipe. `\r` is stripped first, so a TTY wrapper's CRLF output still matches.
  The `SIDECAR_*` variables are optional on the `rust` backend when no
  `SIDECAR_DB` exists. On the `sidecar` backend the Rust step runs only if
  `FEATHERREADER_DB` holds Rust sessions, not merely because a revoke command
  is available. A DB `sqlite3` cannot read (corrupt, locked, unreadable) is
  counted as "unknown", never 0. The Rust step then runs, or the script
  refuses if there is no revoke command, instead of being silently skipped.

  **Sign-out vs. a concurrent refresh.** This changes `/logout` and
  `/account/delete` too. The app refreshes a session under an in-process lock;
  a sign-out does not take it, and the operator's revoke-all runs in another
  process. Two interleavings left a live token behind:

  - **Rotate, then delete.** The sign-out read R1. The refresh rotated the row
    to R2. The PDS answered 200 for the stale R1, and the sign-out then deleted
    the row holding R2, which was reported revoked and never revoked. The
    sign-out's delete is now a compare-and-delete (`DELETE … WHERE` the stored
    ciphertexts match what was read). On a mismatch it re-reads and revokes
    the new tokens, up to 3 attempts. Past that it reports a failure and
    **leaves** the newest tokens on record rather than deleting them unrevoked.
    Discovery follows the row: every read is revoked at the endpoint
    discovered, issuer-checked, for **its own** `(aud, issuer)`. A row
    re-read at another issuer (a re-login after a PDS migration) used to have
    its new refresh token posted to the old authorization server. That server
    answered 200 for an unknown token, so the session was reported revoked
    and its row deleted while the grant stayed live.
  - **Delete, then rotate (resurrection).** The refresh's write was an upsert,
    so a refresh in flight across a sign-out re-created the deleted session
    with fresh tokens. It is now a conditional `UPDATE` against the version
    the refresh started from. If the row is gone, the fresh tokens are revoked
    (best-effort, bounded) and the caller gets "no session". If another writer
    (a re-login: a new grant) replaced the row, theirs is kept and returned,
    so no update is lost. Our fresh tokens, from the old grant and stored
    nowhere, are revoked too. Login's write is still an upsert.

  As defence in depth, `revoke_all` lists the store again after its walk and
  walks anything new, up to 2 extra passes. Anything still stored after that
  is reported as failed. The report holds one **final** outcome per DID, so a
  DID that failed and was then revoked by the re-list is reported revoked.
  `late` lists only DIDs absent from the first listing.

  **Tests.** New `scripts/test-teardown.sh`, 83 assertions, runs the real
  script against throwaway SQLite files with stub commands. It is wired into
  CI (new `teardown` job) and `scripts/ci.sh`. Against the original script, 21
  of the first 30 failed. Each later round's cases failed first against the
  script before that round's fix: the sentinel cases (17), the sidecar-backend
  cases (6), the CRLF cases (5), the post-stop sweep cases (6), the
  unreadable-DB cases (4), `--sweep` (2) and `FR_ACCEPT_UNREADABLE` (3).

  Tests against a real-TLS fake authorization server cover:

  - revoke-all: every session revoked, one server failing, an unreadable row,
    an empty store;
  - each assertion's `iat` coming from its own clock reading;
  - a refresh against a deleted row (no resurrection, fresh token revoked) and
    against another writer's replacement (no lost update, our fresh token
    revoked, theirs not);
  - the pre-flight against a fake JWKS: matching, mismatching (main pass and
    sweep), and unreachable (main pass refused, sweep allowed). Also a wrong
    encryption key, a Null codec that passes everything else, a partly
    unreadable store, a JWKS on loopback (passes), an http JWKS URL (refused),
    and `--accept-unreadable` (passes an all-unreadable store, does not
    bypass the client or signing-key checks);
  - a session that moves issuer mid sign-out, against two fake authorization
    servers: the old one never receives the new token.

  Injected-hook tests cover a rotation between read and delete, a row that
  keeps rotating, a row deleted concurrently, sessions created during the
  walk, the bounded re-list, and one final outcome per DID (fail then succeed
  is revoked only; failing every pass is one entry). Main-binary tests cover
  the dev-client, Null-codec, keyless and wrong-encryption-key refusals,
  `--sweep` and `--accept-unreadable` parsing, and `--accept-unreadable` end
  to end (2 without it, 3 with every row deleted).

  Each new guard was broken on its own and a test failed every time (66 of
  66).
  `deploy/teardown.md` gains the procedure, including Fly's.

### Docs

- **The GitHub-facing docs describe 0.4.4.** `src/config.rs`'s settings
  table, which the README calls the complete list, was missing ten variables
  the code reads (`FEATHERREADER_ENV`, `FEATHERREADER_BETA_CAP`, and the eight
  scheduler knobs in `scheduler.rs`); they are added with the defaults the
  code uses. `deploy/teardown.md` implied the kill script revokes every
  session; on the `rust` backend it revokes none, since it reads only
  `SIDECAR_DB` and the Rust client has no fleet-wide revoke, and it now says
  so. The OAuth sidecar's README said the Rust server never does OAuth itself,
  untrue since 0.3.0. `.github/workflows/README.md` gains the three release
  and gate workflows. `ci.yml` counted five jobs (there are seven), and
  `release-image.yml`'s header stated a claim about `:latest` and then
  contradicted it. `dependabot.yml` waited for a Dockerfile under `deploy/`
  (it is at the root, digest-pinned). The README says a large read-state
  flush is split into calls of 200 writes / 128 KiB (#242). The design
  docs get status lines: standard.site shipped in 0.4.0 with the flag on in
  production, the network spec's adoption probe shipped in 0.2.8, and the
  older plans that called capacity work and open registration "0.4.0 work" are
  marked historical. `SECURITY.md` gets a supported-versions table, and
  `CONTRIBUTING.md` lists the CI gates `scripts/ci.sh` does not run.
- **Every doc audited against the code, and the open risks tracked.** Four
  audits went through every Markdown doc. `NETWORK-SPEC.md` now says what is
  built (the adoption probe, the `PdsClient` guard) and what is not; its §7.2
  privacy copy, which promised a `/network/opt-out` route that does not exist,
  is labelled a draft; and §8's claim that `PdsClient` bypasses the SSRF guard,
  false since v0.2.8, is corrected. `STANDARD-SITE-0.4.0.md` carries its final
  status and per-step PRs, `DESIGN.md` its shipped state, and every item in the
  review and rollout docs its state today, with issues #257–#263 filed for the
  open ones. The operational docs were checked by running them: a local sidecar
  needs `SIDECAR_DEV=true`; the `rust` backend still requires
  `SIDECAR_INTERNAL_SECRET` on a production-like instance; teardown needs
  `FR_STOP_CMD`, and on the `rust` backend it revokes no sessions (#257).
  `deploy/upgrade-from` is 0.4.4, and the ownership diagram is re-rendered with
  the chunked `applyWrites` flusher. A final sweep checked the numbers, line
  references and forward-looking statements in docs and comments: the scheduler
  and `main` module docs named two background tasks where there are eight; the
  `web.rs` route list lacked thirteen routes and said OAuth always goes through
  the sidecar; the `Cargo.toml` base64 note still called the second copy
  pending, though it landed with reqwest 0.13.5 and the pin is 0.23;
  `upsert_feed` has eight non-test callers, not "about 20"; the workflow
  comments still waited for the repo to go public; and stale `file:line`
  references in the review docs, the Caddy configs and two code comments now
  name the function instead (comment-only changes in code).

## 0.4.4 — 2026-10-05

The feed parser moves to feed-rs 3.0 with entry ids and permalinks unchanged,
real RSS bylines, and a parser panic contained as a parse failure; the SSRF
guard refuses the reserved and documentation ranges it missed.

### Upgrade notes

- **No schema change, no new settings.** Upgrading from 0.4.3 is a deploy;
  rolling back to 0.4.3 is a redeploy.
- **What changes on the next poll of each feed:** bylines. RSS items that
  showed "author" (or an Atom author that showed "unknown") get the real name,
  or none when only an address is given. Entry ids, titles, links, dates and
  content do not change: a differential run over 27 live feeds (774 entries)
  found no difference in any of them.
- **A feed whose author field makes feed-rs 3.0 panic** (a multi-byte
  character touching the email address) now fails as a parse error with
  backoff, until the item leaves the feed. 2.4 parsed it. None of the 27
  sampled feeds does this.
- **Dependencies:** tokio-rustls 0.26.6; sidecar `@atproto/api` 0.22 (the
  sidecar is not the production backend); CI action pins.

### Security

- **The SSRF guard refuses the reserved and documentation ranges it was
  missing** (closes #217): IPv4 `240.0.0.0/4` (RFC 1112 §4; `is_broadcast()`
  covered only its top address), `192.0.2.0/24`, `198.51.100.0/24` and
  `203.0.113.0/24` (RFC 5737), and IPv6 `fec0::/10` (RFC 3879), `100::/64`
  (RFC 6666) and `2001:db8::/32` (RFC 3849). None can host a public feed. The
  IPv4 ranges are refused inside every IPv6 form the guard already unwraps,
  because both paths call the one IPv4 check; a test wraps each in all eight
  forms so that stays true. The doc comment on `net::is_forbidden_ip` is now
  the complete list, with RFCs. Each new range was deleted in turn and a test
  failed every time. The ISATAP fixtures moved from `2001:db8::` to a real
  global prefix, since under a refused prefix they would pass without the
  ISATAP decoder.

- **A local `docker build` no longer sends the app's OAuth signing key to the
  Docker daemon** (#218). `.dockerignore` excluded the sidecar's `*.jwk.json`
  but not the Rust app's `oauth-signing-key.json`, which is gitignored and
  present in local checkouts; it now excludes `**/oauth-signing-key*.json`, and
  `.claude` (local worktree copies). Measured with a probe build that copies the
  whole context: before, the key and `.claude` were in it (50.8 MB); after,
  neither (4.0 MB). Shipped images were never affected: the Dockerfile copies
  named paths only, and release images build from a clean CI checkout.

### Changed

- **feed-rs 2.4 → 3.0, with entry ids and permalinks held to their 2.4
  values** (#249). 3.0 adds `<comments>` and `wfw:commentRss` URLs to
  `entry.links`, and its default id generator hashes the *first* link. An
  id-less item listing its comments link before `<link>` would have got a new
  guid (stored a second time for every reader) and the comments page as its
  permalink. Feeds are now parsed through `parse_feed`, whose id generator
  hashes the first non-comments link with the same feed-rs function 2.4 used,
  and comments links are never candidates for the permalink or
  `stable_guid`. An entry with no guid and no permalink used to get a random
  UUID from feed-rs, so it was a new row on every poll; it now gets the
  deterministic `stable_guid`.
  **Bylines are names.** 2.4 named every RSS `<author>` "author" and an Atom
  author with an empty `<name>` "unknown", and those words were stored as the
  byline. 3.0 separates the name from the address; FeatherReader strips the
  parentheses 3.0 leaves on the RSS `address (Name)` form, and an author given
  only as an address has no byline; the byline is the first author that has
  a name (an item may give `<author>` as an address and the name in
  `<dc:creator>`). Because the entry upsert refreshes `author`, entries still
  in a feed get the real name on their next poll.
  **A panic inside feed-rs is a parse failure.** 3.0 panics when a multi-byte
  character touches an author address (`jose@example.com（José）`,
  `Zoë «zoe@example.com»`) in RSS `<author>`, `<dc:creator>`,
  `<managingEditor>`, `<webMaster>`, RSS 1.0 `<dc:creator>` or a JSON Feed
  author: its name/address splitter slices on a byte that is not a character
  boundary. Uncaught, the panic escaped `poll_feed` and killed the poll task
  after the scheduler had moved `next_poll`, recording nothing — the feed
  stopped updating silently. `parse_feed` now catches it, and the poll
  records `FailureKind::Parse` ("feed parser panicked: …") and backs off. The
  whole feed fails until the item leaves it; none of the 27 live feeds
  triggers it.
  **Dedup-key hashes no longer depend on the Rust release.** `stable_guid` and
  `bound_guid` used std's `DefaultHasher`, whose algorithm std leaves
  unspecified, so a toolchain bump could have re-keyed those entries and
  stored each again. They use `siphasher`'s SipHash-1-3 with zero keys (a new
  direct dependency, already in the tree) — what `DefaultHasher` is today, so
  stored values are unchanged; tests pin values produced by the old code.
  feed-rs's own id generation already used fixed-key `siphasher`.
  **Measured, not assumed:** a throwaway harness parsed the same bytes with
  both versions through FeatherReader's field choices — the 10 feed fixtures
  in the tests, 11 edge-case fixtures, and 27 live feeds (RSS 2.0, RSS 1.0,
  Atom, JSON Feed; 774 entries). On the live feeds: 0 differences in guid,
  title, permalink, published/updated date, or content; 123 bylines in 6
  feeds changed, all from "author"/"unknown" to the name (or none). On edge
  fixtures 3.0 also parses `Jun 05 2020 10:00:00 GMT` dates and RSS
  `<atom:updated>`, and strips the wrapper `div` from Atom `type="xhtml"`
  text. **One regression stays:** in invalid RSS with unescaped markup inside
  `<title>`, `<description>` or `<content:encoded>`, 3.0 keeps only the text
  before the first child element (2.4 kept the markup), and an id-less item
  with such a title gets a new generated id. None of the live feeds does
  this. Ten tests pin the above. Seven failed before their fix; the three
  that passed pin values (2.4's generated id, the stored hash keys) and each
  fails when the code under it is mutated.

## 0.4.3 — 2026-10-05

Two write-path fixes that apply on any PDS: `applyWrites` is sent in calls of
at most 200 writes and 128 KiB, and a read-state flush whose local
`pds_created` flag disagrees with the PDS now reconciles instead of failing
every round. Found while evaluating vlpds.

### Upgrade notes

- **No schema change, no new settings.** Upgrading from 0.4.2 is a deploy;
  rolling back to 0.4.2 is a redeploy.
- **What to look for after deploying:** a reader whose read-state sync was
  already stuck recovers on the next flush, with one `readState` listing. An
  OPML import of more than 200 feeds now succeeds, or reports how many of them
  landed.
- **`deploy/upgrade-from` moves to `0.4.2`,** the release deployed before this
  one, so the upgrade-boot gate tests from it.

### Fixed

- **A read-state flag that disagreed with the PDS stopped a reader's
  read-state sync for good (#241).** The flusher picks `#create` or `#update`
  per feed from `read_cursor.pds_created`, which it learned only from a
  successful flush, and all of a DID's ops ride one atomic `applyWrites`. A
  success whose answer was lost, or a fresh or restored database against a
  repo already holding the records (the rkeys are stable), left the flag false
  over a record that exists; a record deleted elsewhere left it true over one
  that does not. One op failed, the batch failed, and every later flush sent
  the same batch. Now a failure that could be that triggers one listing of the
  DID's `readState` collection, sets `pds_created` to what is there, and
  retries once if anything changed — never more, and never when the listing
  fails or changes nothing. What the reference PDS sends was read from its
  source: with no `swapRecord`, the collision surfaces in `@atproto/repo`'s MST
  (`There is already a value at key` / `Could not find a record with key`), a
  plain `Error` that xrpc-server answers as **500 `InternalServerError`** with
  the message stripped, so there is no narrower signal; 400
  `InvalidRequest`/`InvalidSwap`/`RecordNotFound` and 409 are also matched,
  for a PDS that checks explicitly. Transport failures, 401/403, 429 and
  502/503/504 are returned as before, without a listing. The match is on the
  structured error, so the Rust client now attaches
  `AtProtoError::Xrpc { status, error }` to a rejection as the sidecar client
  already did; its message is unchanged. Tested end to end on both backends
  against a stateful fake repo with the reference's create/update semantics,
  including a batch that landed in part; each added guard was mutated and
  every mutation failed a test.
- **A read-state flush split by #240 that failed part-way starved every
  cursor after the failure.** The calls go in rkey order and stop at the first
  failure, but `flush_did` settled cursors only on full success, so call 1's
  committed creates stayed dirty with `pds_created` false, went out again as
  `#create`, were refused, and stopped the run at the same place every round.
  On any flush error carrying `ApplyWritesIncomplete`, the landed prefix is now
  marked created and cleaned (the same conditional `updated_at` clear as a
  success) before anything else is decided, and the reconcile retries only
  what did not land; a retry that part-lands is settled the same way. The
  mismatch match now also walks `ApplyWritesIncomplete`'s own cause, because
  that error's `source()` skips its cause's top layer — on the sidecar client
  that layer IS the `AtProtoError`, and every sidecar reconcile test went red
  on the merge until it did. A retry that fails again now carries the PDS's
  reason in its message, so the flusher's and sign-out's `%err` log lines say
  why, not only "failed again".

- **An OPML import of more than 200 feeds failed outright, and a large
  read-state flush could too (#240).** `add_subscriptions_bulk` sent one
  `applyWrites` create per feed in a single call (up to the 500-feed per-DID
  cap), and `flush_read_states` sent every dirty cursor for a DID in one call.
  The reference PDS refuses more than 200 writes a call (`Too many writes.
  Max: 200`, in `packages/pds/src/api/com/atproto/repo/applyWrites.ts`; the
  lexicon itself sets no `maxLength`), and before atproto#4989 (2026-05-21) it
  also refused an `applyWrites` body over its 150 KiB `jsonLimit`.
  `atproto::apply_writes_chunked` now sits under every client's
  `apply_writes` — OAuth, sidecar and direct — and sends calls of at most 200
  writes and 128 KiB of serialized writes, in input order, stopping at the
  first failure. A split batch is atomic per call, not as a whole, so the
  error carries `atproto::ApplyWritesIncomplete`: the first `landed` writes
  committed, the failed call's writes are in doubt, and nothing after it was
  sent. The OPML import now reports a part-landed import as "Imported 200 of
  450 feeds…" rather than "nothing was imported". The read-state flusher still
  treats any error as a failed flush; the landed prefix is there for it to use
  (#241). An empty batch on the direct client now sends nothing, as the other
  two clients already did. Established with a fake PDS that refuses what the
  reference PDS refuses, on all three clients and through `POST /opml`; the
  refusals were confirmed red before the fix, not assumed.

### Docs

- **The README describes 0.4.2.** It still described a reader of RSS feeds
  alone, said the hosted instance ran the `sidecar` OAuth backend (it has run
  `rust` since the 2026-09-13 cutover; `fly.toml` says so), promised a manual
  dark-mode toggle that no template renders, and said nothing about the
  publication poller, link cards, the upgrade-boot gate or deploying by digest.
  Rewritten against the code: standard.site publications beside RSS, the
  invite-only beta as the templates state it, a configuration table that points
  at `src/config.rs` as the source of truth, the CI gates as `ci.yml` runs them,
  and the release pipeline. The two architecture diagrams become four, drawn
  from `fly.toml`, the `Dockerfile`, the Caddyfile, `store.rs`, `scheduler.rs`,
  `standard_site.rs` and the release workflows — architecture, data ownership,
  polling, and the release pipeline (#244). They are light/dark PNGs rendered
  from `design/architecture/*.mmd` and embedded with `<picture>` (#245), not
  inline Mermaid: the GitHub mobile app and crates.io show inline Mermaid as
  raw code. Every relative link was checked to resolve.

---

## 0.4.2 — 2026-10-04

A public feature page for standard.site, a latest-releases call-out, and link
cards, so a feather-reader.com link posted to Bluesky unfurls with a
description and an image.

### Upgrade notes

- **No schema change, no new settings.** Upgrading from 0.4.1 is a deploy;
  rolling back to 0.4.1 is a redeploy.
- **Link cards build absolute URLs from `FEATHERREADER_PUBLIC_URL`**, the
  setting OAuth already uses. Left unset it is `http://localhost:8080`, and
  link cards then point there; set it to the public origin.

### Added

- **A public feature page for standard.site, at `/standard-site`.** What a
  publication is (a `site.standard.publication` record whose articles are
  `site.standard.document` records in the author's repo), what FeatherReader
  shows from one (title, date, link, plain-text summary from `description` or
  `textContent`; never the per-platform `content`), that the subscription is
  the same portable `community.lexicon.rss.subscription` record re-read on the
  same interval on its own loop, how to subscribe, and the limits: summaries
  only, public repos only, reading only (no `site.standard.graph.subscription`),
  the 30 s read deadline, and that a non-publication `at://` row is kept as
  `unsupported`. **The how-to-subscribe section is conditional on
  `FEATHERREADER_STANDARD_SITE`** exactly as the landing and about pages are
  (#234): with it off, the page says the instance isn't accepting new
  publication subscriptions and that the ones it already follows are still
  read. Public and cacheable like `/about` (`public, max-age=300`). Linked
  from the landing page's publications point, from `/about`, and from the
  shared footer. Every claim on the page was checked against
  `standard_site.rs`, `feed.rs`, `web::add_subscription` and
  `design/STANDARD-SITE-0.4.0.md`.
- **A "latest releases" call-out** on `/standard-site` and the landing page,
  summarising 0.4.1 and 0.4.0 in a sentence or two each and linking each
  GitHub release page and its CHANGELOG section. **The data lives in one
  place, `web::RELEASES`** (a `const` slice of `web::Release { version, date,
  summary }`): the two URLs are derived from `version` and `date`, and
  `templates/releases.html` renders whatever the slice holds, so announcing
  the next release is one new entry at the top. A test pins the shape (newest
  first, `YYYY-MM-DD` dates, the tag and changelog-anchor URL forms).

### Link cards for posted links

- **A feather-reader.com link now unfurls with a description and an image.**
  Measured before the change with Bluesky's own card service:
  `cardyb.bsky.app/v1/extract?url=https://feather-reader.com/` returned
  `{"title":"FeatherReader — read, quietly","description":"","image":""}`,
  because `<title>` was the only tag in `base.html` it could use. Every page
  now carries a `web::Card` — `<meta name="description">`, the Open Graph
  set (`og:type`, `og:site_name`, `og:title`, `og:description`, `og:url`,
  `og:image` with type, width, height and alt), `twitter:card`
  (`summary_large_image`) and `<link rel="canonical">`. Card fetchers read
  the initial HTML server-side, run no JS, send no cookies and resolve
  nothing relative, so `og:url` and `og:image` are absolute on
  `Config::public_url` (`FEATHERREADER_PUBLIC_URL`; production's is
  `https://feather-reader.com`). Each signed-out page — `/`, `/about`,
  `/privacy`, `/terms`, `/stats`, `/login`, `/beta/redeem` — has its own
  title and description; a page that renders a session's private view
  (`/`, `/manage`, `/entries/:id`) carries the site's generic card pointing
  at the front door, plus `noindex`, so no heading, feed name or handle
  reaches `<head>`.
- **The share image** is `static/social-card.png`, 1200×630 (the ~1.91:1
  Bluesky renders), 69 KB, served from `/static` with the same
  `public, max-age=300` as the other assets. Its source is
  `static/social-card.svg` — the favicon's feather in spruce beside the
  wordmark and tagline, in the light-scheme tokens from `style.css` — and
  `scripts/social-card.sh` regenerates the PNG with whichever of
  `rsvg-convert`, `sips` (macOS, built in) or headless Chrome is present;
  no Rust dependency, no font fetched.
- Tests (router level, each failing before the change): the landing page
  and `/about` render the card with absolute `https` URLs; the origin
  follows the configured public URL; every public page has its own
  description and `og:url`; the image is served as `image/png`, under 1 MB,
  with a PNG header whose dimensions match the tags; private views carry the
  generic card, `noindex`, and neither the handle nor the DID in `<head>`.
- Not verifiable before a deploy: the cardyb check above, re-run against
  production.

---

## 0.4.1 — 2026-10-04

The public pages say what 0.4.0 does, and the subscribe form can submit the
DID form of a publication URI, which browsers refused in 0.4.0.

### Upgrade notes

- **No schema change, no new settings.** Upgrading from 0.4.0 is a deploy;
  rolling back to 0.4.0 is a redeploy.
- **What changes depends on `FEATHERREADER_STANDARD_SITE`.** With it off, the
  subscribe input is the same as in 0.4.0 (`type="url"`, same attributes), and the landing and about pages
  describe publications and say this instance isn't accepting new publication
  subscriptions. With it on, the pages and the form say how to subscribe, and
  the subscribe input accepts `at://did:…`.

### Added

- **The website says what 0.4.0 does.** The landing page and `/about` describe
  standard.site publications beside RSS feeds — what a publication is (a
  `site.standard.publication` record whose articles are
  `site.standard.document` records in the author's repo), what is shown (title,
  date, link, plain-text summary; never the per-platform `content`), that the
  subscription is the same portable `community.lexicon.rss.subscription`
  record, and how to subscribe. The subscribe form on `/manage` gains a hint
  with both accepted spellings, `at://did:plc:…/site.standard.publication/…`
  and the handle form. **Every how-to-subscribe line is conditional on
  `FEATHERREADER_STANDARD_SITE`**: with it off, `add_subscription` refuses
  every `at://` paste, so the pages say the instance is not accepting new
  publication subscriptions instead of advertising a form that would be
  refused. The flag is threaded into `LandingTemplate`, `AboutTemplate` and
  `ManageTemplate`; `web` tests pin both states of each page.

### Fixed

- **The DID form of a publication URI could not be submitted from a browser.**
  The subscribe input was `type="url"`, which browsers validate with the WHATWG
  URL parser — and that parser rejects `at://did:plc:…/…` (the colons in the
  DID read as a port), the same failure `url::Url::parse` has that
  `feed::is_storable_feed_url` works around. So the form #230 added accepted
  the DID form on the server and refused it client-side, with no request
  sent. Established with Node's WHATWG `URL` (`ERR_INVALID_URL` for the DID
  form; the handle form parses). With the flag on the input is now
  `type="text"` with `inputmode="url"`; with it off it is unchanged. A text
  input loses the browser's scheme check, so it carries a `pattern`
  (`web::FEED_URL_PATTERN`) that still asks for `http(s)://` or `at://`, in
  any case and with surrounding whitespace allowed (a text input, unlike
  `type="url"`, does not trim before checking); otherwise `example.com/blog`
  reached the handler and came back as "Couldn't find a feed".

### CI

- **The crate publish is dispatched by `release-image`, not triggered by
  `workflow_run`.** crates.io Trusted Publishing refuses the `workflow_run`
  event ("does not support the `workflow_run` event trigger due to security
  concerns"), so the ordering #223 added failed the first real release: v0.4.0's
  automatic publish was rejected, and 0.4.0 was published by dispatching
  `release-crate.yml` against the tag by hand. `release-image` now ends with a
  job that dispatches it, after the gate passes and the image is pushed; the
  order is unchanged.

## 0.4.0 — 2026-10-03

**standard.site support.** FeatherReader now reads standard.site publications
(`site.standard.publication` / `site.standard.document` records in their
authors' atproto repos) as subscriptions, alongside RSS. The 19 publication
subscriptions already stored in production start delivering when this version
is deployed. Plan and measurements: `design/STANDARD-SITE-0.4.0.md`.

### Upgrade notes

- **No schema change.** Upgrading from 0.3.10 is a deploy. Rolling back to
  0.3.10 is safe: it re-derives `feeds.kind` from the URL at start (so the new
  `unsupported` kind becomes `publication` again, which it does not poll).
- **Two data fixes run at every start, both no-ops once done:** `feeds.kind` is
  re-derived from the URL, as since 0.3.9, now with a third kind, `unsupported`
  (below). And any entry stored with a `published` date more than two days in
  the future has that date cleared (#213).
- **A stored publication is polled whatever `FEATHERREADER_STANDARD_SITE` says.**
  The flag decides what may be STORED: with it on, a publication can also be
  pasted into the subscribe form. With it off, nothing new is stored, but the
  rows already stored are read.
- **New settings:** `FEATHERREADER_PUBLICATION_READ_DEADLINE_SECS` (default
  `30`, must be at least 1): the longest one publication read may take. It is
  kept under Fly's 45 s `kill_timeout`, so the read in flight at shutdown can
  finish.
- **Stricter settings:** `FEATHERREADER_POLL_INTERVAL=0` is now refused at
  startup. It made a healthy feed due again the moment it was read.
- **A new background loop**, the publication poller, starts 75 s after boot.
  `FEATHERREADER_STARTUP_DELAY_SECS` shortens it like the others.

### Added

- **Publications are polled** (#225). They have their own loop
  (`scheduler::run_publication_poller`), separate from the RSS poller, so a
  slow publication can never hold up RSS. It reads due publications as they
  come, checks shutdown and the DB-size watermark before each read, and reads a
  row at most once per pass.
- **Each publisher's repo is read once per pass, however many of its
  publications are due** (#228). Up to 16 per read, each with its own document
  cap, so a busy publication cannot starve a quiet sibling of documents.
- **Subscribe from the form** (#230). With the flag on, paste
  `at://did:plc:…/site.standard.publication/…` or the handle form
  `at://alice.example.com/site.standard.publication/…`. The handle is resolved
  to its DID before storing. The first poll runs at once, so articles appear
  immediately.
- **A new feed kind, `unsupported`** (#225), for any `at://` row that is not a
  well-formed publication: another collection, a handle, a non-canonical
  spelling, an invalid DID. Such rows are never polled, and are counted as
  unpollable on `/admin/metrics`.

### Security

- **Every stored field from a feed or a publication has a size bound** (#224,
  closes #205), set from production's 4,389 real entries: title 5,000 bytes,
  author 1,000, URL 8,192, stored body 2 MiB, entry id 2,048 (an over-long id
  becomes a stable hash). Over-long values are truncated, never refused. A body
  is sanitised first and bounded after, so markup the sanitiser strips never
  counts against it. Plain text is bounded exactly in one pass.
- **One malformed record no longer costs a whole page** (#224, closes #177).
  In a reader's own repo, the listing is REFUSED (skipping would silently drop a
  subscription) and the reading and manage pages show an alert. In a
  publisher's repo the record is skipped, counted, and charged to the walk's
  byte budget.
- **A publication read has an overall deadline** (#225), so a slowly paging
  repo cannot hold the publication loop for hours.

### Changed

- **Publication failures are filed under what happened** (#225). A deleted
  publication record, a tombstoned DID (PLC 404), `RepoNotFound` or
  `RepoDeactivated` is `status` or `parse`, not `fetch`, in the `/stats` cause
  histogram. `fetch` is kept for answers that never arrived.

### API (breaking, for users of the `feather-reader` crate)

- `atproto::AtProtoError::DidResolution` gains a `cause:
  atproto::DidResolutionCause` field (`#[non_exhaustive]`).
- `atproto::ListRecordsResponse` gains `malformed` and `wire_bytes`;
  `atproto::RecordWalk` gains `malformed`. Code constructing either by struct
  literal must set them.
- New: `atproto::MalformedRecords`, `standard_site::fetch_repo`,
  `standard_site::NotAPublication`, `feed::poll_feed_by_kind`,
  `feed::poll_publication_group`, `store::due_feeds_of_kind`,
  `store::stagger_unscheduled`.

### Known, not fixed here

- **#226:** ammonia's time is quadratic in some inputs (`&`, deep nesting,
  U+00A0), and sanitising runs on the poller's async task. Predates 0.4.0.
- **#227:** some answered-but-bad publication reads are still filed as `fetch`
  (an empty body, a 200 error envelope, running out of pages).
- **#229:** a one-repo group shares one byte budget, so in principle big
  siblings can starve a quiet publication of bytes. It is not reachable at
  measured scale.
- **Recorded decisions:** a group of up to 16 publications shares one 30 s
  deadline, and checks the watermark once. A publication needing ~80 pages
  (~2,000 documents) would miss the deadline; today's largest is 7.

### CI

- **An upgrade-boot gate, and nothing publishes until it passes.** 0.3.9
  passed every check, was tagged, published to crates.io and ghcr.io, and
  crash-looped production on its first boot. `scripts/upgrade-boot.sh` runs the
  real previous release's image to create and seed a database, then the
  candidate image against it (migrate, then a full boot that must answer
  `/health`), then a full boot of the previous image again to prove rollback.

  - On pull requests touching the app, `upgrade-boot.yml` builds the candidate
    and runs it.
  - In `release-image.yml` it runs **before** the push, so a failure pushes no
    image and moves no tag. The image pushed and attested is the one the gate
    tested, not a second build that matches it only on a warm cache.
  - `release-crate.yml` now runs after `release-image` succeeds for the same
    tag, instead of in parallel, so a failed gate publishes no crate either.
  - The previous release is read from `deploy/upgrade-from` (now `0.3.10`), not
    from the newest tag, which can be a yanked release. Bump it once a new
    version is deployed and healthy.

  Verified locally: `0.3.8 → 0.3.9` fails at the migrate step with `no such
  column: kind`, the production error; `0.3.8 → 0.3.10` passes all five steps.

- **The `:latest` comment in `release-image.yml` was wrong.** It said a hotfix
  on an older line could never move `:latest` backward. `latest=auto` emits
  `:latest` for every non-prerelease version tag, so it can. Corrected; deploys
  are by digest regardless.

### Fixed

- **A future-dated RSS item was unsweepable and permanently first in the reading
  list** (#188). `feed::entry_time` was `e.published.or(e.updated)` with no upper
  bound, so an item dated in the year 2999 was stored verbatim and then became
  permanent: both retention sweeps test `COALESCE(published, fetched_at) <
  cutoff` and a future date is never less than either, the per-feed keep-set
  orders on the same expression `DESC` where it is rank one forever, and every
  list view puts it at the top. One item in one feed, there for good.

  Discarded rather than clamped to now, which is the rule the publication path
  already follows (#186) and the reasoning transfers: the entry upsert refreshes
  `published` every poll but stamps `fetched_at` once, so a clock-derived value
  is rewritten every cycle and the row can never age. Undated is the honest
  answer, and `fetched_at` then dates it and holds still.

  Each candidate is judged separately rather than the winner of `or`, so a feed
  with a bogus `pubDate` beside a credible `atom:updated` keeps the good date —
  that is the ordinary shape of a broken-clock feed, not a rare one. The ceiling is two days, deliberately looser than the publication path's
  five-minute grace (see the last paragraph below).

- **An undated entry was the newest row to the cap and the oldest to the reading
  list** (#187). The per-feed keep-set and both sweeps order on
  `COALESCE(published, fetched_at)` — correctly, or a feed of undated items
  would trim its own freshest rows. `list_entries` and the id projection behind
  "mark this page read" ordered on bare `e.published DESC`, and in SQLite `NULL`
  sorts LAST under `DESC`. So one undated entry was at once safe from eviction
  and parked at the bottom of every list below years of read articles, where no
  reader would see it. `site.standard.document` makes `publishedAt` optional, so
  publication feeds reach this far more readily than RSS ever did.

  The index worry was measured on the query the app actually sends (a LEFT
  JOIN on `entry_state` and an EXISTS on `sub_ref`), and the existing
  `(feed_id, published)` index serves the new ordering as well as it served the
  old one. A `(feed_id, published, fetched_at)` replacement meant to keep the
  queries covering was tried and removed in review: the default prev/next query
  never chose it, and with the old index dropped that query ran about 3.8x
  slower (34 ms against 9 ms at 40 feeds x 1,000 entries). **No schema
  change.**

  **Rows already stored with a future date are re-dated at startup**: their
  `published` is cleared, so `fetched_at` dates them. Otherwise an item dated
  2999 that has already left its feed would never be polled again to be
  corrected, and would stay first in the list and survive the per-feed cap.

  The future-date bound is **two days**, not the publication path's five-minute
  clock-skew grace, and the asymmetry is deliberate. There a refused
  `publishedAt` falls back to the record key's TID — a real write time — so a
  tight bound costs almost nothing. In a feed there is no such fallback, and the
  ordinary cause of a future `pubDate` is a local time stamped `+0000` (up to 14
  hours out) or a post scheduled slightly ahead; refusing those would leave real
  articles with no date on screen. What the bound must prevent is a date that can
  never become past, and two days clears the whole UTC offset range while still
  refusing the year 2999 by a wide margin.

---

## 0.3.10 — 2026-10-03

**0.3.9 does not start against any existing database. 0.3.10 is 0.3.9 with
that fixed.** Upgrade from 0.3.8 or earlier straight to 0.3.10; everything
under 0.3.9 below ships here, including its schema change.

**Schema: one additive column and one index**, both from #184 and both applied
automatically at start: `feeds.kind`
(`ALTER TABLE feeds ADD COLUMN kind TEXT NOT NULL DEFAULT 'rss'`) and
`idx_feeds_kind`. Every row's `kind` is re-derived from its URL on each start.
No `fly.toml` change.

**One new optional setting:** `FEATHERREADER_PUBLICATION_RETENTION_DAYS`
(default 3650), from #206. It bounds standard.site publication entries only.

**This is the first deployable build of everything under 0.3.9.** That is 31
files, much of it on the live Rust OAuth backend and the atproto layer, so
expect these on the first boot:
- if any `at://` rows exist, one `feeds.kind re-derived` log line, with
  `to_unpollable` counting them as they move to `publication`. Without such
  rows the column is backfilled silently, and no line is NOT a failed
  migration: `PRAGMA table_info(feeds)` showing `kind` is the check;
- `/stats` counts changing for the same reason, and only on such instances;
- a reader whose repository exceeds the record-walk page budget now gets an
  error instead of a silently truncated subscription list.

**Do not deploy the 0.3.9 image** (`sha256:6a3c3996…`). It stays on ghcr.io,
because the registry has no yank and the failed Fly release references it.

Rolling back to 0.3.8 is safe. 0.3.8 never reads `kind`, and the column's
default keeps 0.3.8's inserts valid, so it runs against the migrated database
unchanged. A feed added while rolled back gets `'rss'` whatever it is, and the
next 0.3.10 start corrects it.

### Fixed

- **0.3.9 crash-looped on its first boot in production: `no such column:
  kind`** (#219). The base `SCHEMA` batch created `idx_feeds_kind ON feeds
  (kind)`. On an existing database `CREATE TABLE IF NOT EXISTS feeds` is a
  no-op, so the column is not there until `apply_migrations` adds it, and
  `apply_migrations` runs after the batch. Startup failed before it got there.
  The index is now created in `apply_migrations`, directly after the column.

  It is the 0.2.2 `intended_did` bug (B1) again, on a different table, with the
  warning about it a hundred lines further down the same string. On Fly the
  machine exhausted its restart budget and stopped. The deploy has no automatic
  rollback, so the site was down until v26 (0.3.8) was redeployed by digest.

  **The crashed boot wrote nothing.** The three statements ahead of the failing
  one are `PRAGMA foreign_keys = ON`, `CREATE TABLE IF NOT EXISTS feeds` and
  `CREATE INDEX IF NOT EXISTS idx_feeds_next_poll`. On a 0.3.8 database the
  table and index already exist, and the PRAGMA only sets the connection. The
  0.3.8 binary booted against the same volume with `db: ok`.

  A database 0.3.9 created from empty was never affected: there the column is in
  the CREATE TABLE. It upgrades to 0.3.10 as a no-op.

### Tests

- **Every test started from an empty file, so none could see this.** In a fresh
  database the column is in the CREATE TABLE, and the order of the index and the
  migration cannot matter. B1's regression test hand-built one table's old
  shape, so it guarded only that table.

  Two upgrade tests now start from schemas that released binaries created,
  dumped with `sqlite3 .schema` rather than transcribed:
  - `tests/fixtures/schema-v0.3.8.sql`, the release before the bug;
  - `tests/fixtures/schema-v0.2.0.sql`, the oldest released shape and the one
    migrations do the most work on.

  Each seeds an RSS row and an `at://` row the way the old binary inserted
  them, runs the current `init_schema`, and asserts:
  - the backfill;
  - `idx_feeds_kind` exists and is on `kind`;
  - a second run is a no-op;
  - **the upgraded schema matches a fresh one.** That means every column with
    its type, NOT NULL, default and pk, and every index with its columns. This
    also catches the other half of the bug class: a column added to a CREATE
    TABLE with no migration behind it.

  Mutation-checked:
  - 0.3.9's shape fails both tests with the production error.
  - A column added to `SCHEMA` without a migration fails both, with the diff
    naming it.
  - Dropping the `last_error_kind` migration fails only the v0.2.0 test, which
    is what the second fixture is for.

  End to end, a review built all 19 tags from v0.2.0 to v0.3.9 and had each
  create and seed a database. The 0.3.10 binary upgraded every one. As a
  control, the 0.3.9 binary failed on the v0.2.0 and v0.3.8 databases with the
  production error. A database 0.3.10 has upgraded still boots under 0.3.8.

---

## 0.3.9 — 2026-10-03 — YANKED

**Yanked: it does not start against an existing database.** See 0.3.10, which
ships everything below with the fix. The schema note for this release has moved
there.

The release commit described this release as migration-free — "no ALTER TABLE
… no schema change anywhere in it". That was wrong: the claim was checked
against the PRs listed in these notes, and #183 and #184 were missing from
them.

### Changed

- **A feed records what it IS, instead of re-deriving it from its URL each time
  it is read** (#184). "Can the poller fetch this?" was
  `lower(substr(url, 1, 5)) = 'at://'` spliced into five statements, and a
  review found a sixth reader, `count_feeds`, that had already drifted from
  them. `feed::FeedKind` now decides it once, in Rust, at insert, and the new
  `feeds.kind` column stores the answer. `due_feeds`, both `/stats` aggregates,
  `failing_feeds` and `unpollable_feeds` read that value, so SQL cannot disagree
  with the fetcher about what a row is. `FeedKind::POLLABLE` is the one list the
  scheduler selects from, and `POLLABLE_KINDS_SQL` is pinned equal to it by a
  test.

  It behaves the same: no feed changes what the poller does with it. Rows from
  before the column are backfilled from their URL. Two bugs were found while
  making it, both caught by existing tests:
  - The failure histogram's `AS kind` alias collided with the new column, so
    `GROUP BY kind` folded every failing feed into one bucket. It is
    `failure_kind` now.
  - A test helper seeded `at://` rows with the column's `'rss'` default. It now
    goes through `upsert_feed`.

- **`cargo doc` is now a CI gate, and the 45 warnings behind it are fixed**
  (#214, closing #190). This codebase puts its reasoning in doc comments and routes a reader
  between them by intra-doc link, so a dangling link is not cosmetic: it renders
  as plain text and the reference silently stops being one. #189 deleted a
  constant that four doc comments pointed at and nothing noticed, because no job
  ran `cargo doc`.

  Two families. Roughly ten were **unresolved** — items renamed or removed.
  Three of those were `[vet]` in `repo.rs`, pointing at the free function #150
  retired; they now point at `crate::vetted::VettedSubscription`, which is
  genuinely public, so the navigation is restored rather than deleted. The rest
  were fixed to their real targets (`SidecarConfig::internal_secret`,
  `Subscription::private`, and `XrpcError` re-pointed at
  `AtProtoError::Xrpc`), or demoted to prose where no linkable item exists
  (`offset_for` is historical; `tid` is an atproto concept, not an item here;
  `axum::Router` is an external crate's item and is now backticked
  instead of linked).

  The other ~33 were a **public item's docs linking to a private item**, which
  rustdoc renders as plain text. Those are unlinked, keeping the name in
  backticks — the honest shape, since that is already what the output showed.
  Visibility was NOT widened to satisfy a docs lint: in this crate `pub` is a
  guarantee (see `safe_link.rs`, `vetted.rs`), and `pub(crate)` would not
  silence the lint anyway, so the only way to keep those links would have been
  to publish internals like `resolve_and_check` and `pinned_client`.

  The gate is `cargo doc --no-deps --locked` with `RUSTDOCFLAGS="-D warnings"`,
  and it was verified to FAIL rather than merely pass: an injected dangling link
  and a re-linked private item each exit non-zero.

  **It does not catch everything, and review found where.** A reference into a
  crate that sets no `html_root_url` resolves — so the gate stays green — but
  renders with literal brackets, `[<code>reqwest::Client</code>]`, which is the
  same defect by a different door. Measured: `axum`, `reqwest`, `sqlx`,
  `ammonia` and `askama` produce zero `docs.rs` hrefs in the rendered output
  while `anyhow` produces 237. Fourteen such references are demoted to prose
  here, on the same reasoning as the private-item ones. `--extern-html-root-url`
  would make them real links instead, at the cost of one flag per dependency
  that nothing gates — worth considering separately, not silently. What remains
  in the rendered docs (`[Span]`, `[WithDispatch]`, `[Action::Follow]`) comes
  from dependencies' own doc comments via blanket trait impls, not from this
  crate.

- **A standard.site publication is retained by COUNT, not by age — because
  measurement says the age window stores nothing at all.** Read three real
  publications through `standard_site::fetch` on 2026-09-27: the newest document
  Standard.site offered was **131 days** old, Annotated's **109** (its oldest
  373), minus listens' **241**. Against the instance default `retention_days = 14`
  every one of them stored **zero rows** — a successful poll, an empty feed, and
  an info log as the only trace that anything was dropped. Long-form publishing is
  not news-paced, and an ingest floor that mirrors an age-based sweep faithfully
  reproduces that.

  So `FeedKind::AGED` now names the kinds the rolling window and the hard ceiling
  apply to (RSS), both sweep passes are scoped to it, and a publication is bounded
  by `max_entries_per_feed` in `insert_entries` instead — the newest N plus up to
  N starred, which is a real bound and the one that suits a source whose value is
  its archive.

  A third, generous ceiling (`FEATHERREADER_PUBLICATION_RETENTION_DAYS`, default
  **3650**) keeps "not aged out" from meaning "immortal": the per-feed trim only
  runs when a poll stores something, so entries of a feed nobody polls any more
  have nothing else to reap them. Ten years is longer than the protocol itself, so
  it cannot truncate an archive that exists today. It is scoped the other way
  (`kind NOT IN` the aged kinds) so that a kind added later inherits a bound
  rather than immortality — and that scoping is pinned, because dropping it left
  all 909 tests passing while quietly re-enabling age eviction for RSS on an
  instance whose operator had set both RSS knobs to zero.

  `Config::retention_for(kind)` is the single home for which window applies to
  which kind. The sweep decides what to delete and `standard_site::ingest_floor`
  decides what is worth storing; written independently they drift, and a drift
  here is the resurrection cycle — a row the store keeps, the sweep deletes, and
  the next poll re-inserts unread. Both read the same function.

  Nothing polls a publication yet, so no reader sees a difference; this is the
  retention half of that wiring, landed first because without it the feature
  demonstrably delivers empty feeds. One operator-visible change: the sweeper's
  "retention disabled entirely" early return now requires all THREE knobs to be
  zero, so an instance running `RETENTION_DAYS=0 RETENTION_HARD_DAYS=0` starts a
  daily sweeper where it previously logged and returned. On an all-RSS instance
  that sweep deletes nothing — the one pass it runs is scoped to kinds that
  instance has no rows for.


### Security

- **Two advisories in the sidecar's dependency graph, four days apart, both
  about deciding whether a target is what it looks like.**

  `ip-address` 10.4.0 → 10.7.2 (#209). A moderate GHSA: before 10.5.1 the
  classifier does not recognise the NAT64 local-use range `64:ff9b:1::/48`, so
  it answers "public" for an address that reaches the host's own network. The
  advisory's framing is SSRF and trust-boundary bypass. Transitive via
  `@fastify/rate-limit`, so lockfile-only — done with
  `npm update ip-address --package-lock-only` rather than `npm install`, which
  would have added a direct dependency on a package the sidecar does not import.
  `package.json` untouched; the diff is three lines.

  `fast-uri` 3.1.7 → 3.1.8 and 4.1.4 → 4.2.1 (#212). GHSA-hrr3-gc8f-f4qj,
  medium: inconsistent host case normalisation via percent-encoded octets.

  Neither touches `net::is_forbidden_ip`, which is Rust and uses neither
  package — the affected code is the sidecar rate limiter's view of which
  addresses are local. But checking the *class* against our own guard is what
  found the five IPv6 embedding families below, which is the half that mattered.

  Worth recording that both landed in the Node sidecar, the component production
  has not run since the 2026-09-13 cutover. It is not only dead weight; it is a
  continuing source of advisories.

- **Five families of IPv6 address that embed a forbidden IPv4 one were reaching
  the fetcher.** `net::is_forbidden_v6` unwrapped the IPv4-mapped
  (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`) forms, because that is
  where `std`'s `to_ipv4()` stops. It did not unwrap **NAT64** (`64:ff9b::/32`,
  RFC 6052's well-known prefix and RFC 8215's local-use one), **6to4**
  (`2002::/16`, RFC 3056), **IPv4-translated** (`::ffff:0:0:0/96`, RFC 2765),
  **Teredo** (`2001::/32`, RFC 4380, whose client address is obfuscated by XOR
  with all-ones) or **ISATAP** (RFC 5214).

  So `64:ff9b::a9fe:a9fe` and `2002:a9fe:a9fe::` both name the cloud metadata
  service, and both passed the guard. Verified against the shipped code before
  the fix: ten such addresses, every one allowed.

  Whether a given deployment routes them depends on a translator being on the
  path — but the attacker needs only to try, not to know, and an IPv6-only
  network with DNS64 is now ordinary rather than exotic. A hostile DNS answer for
  a subscribed feed's host is enough: `resolve_and_check` checks every answer, and
  these passed.

  Decoded rather than blanket-refused: these prefixes carry public addresses too,
  and refusing them wholesale would take out ordinary traffic —
  `allows_ipv6_that_embeds_a_public_ipv4` holds that line.

  That matters most for NAT64, where an earlier revision of this change refused
  the whole `64:ff9b::/32` and so **broke feed fetching on the very network it
  was written for.** A DNS64 resolver (RFC 6147) synthesises a
  well-known-prefix AAAA for every IPv4-only host, that synthesised address is
  the only answer there is, and `first_vetted` rejects a whole DNS answer set if
  any member is forbidden — so every IPv4-only publisher became unfetchable on
  an IPv6-only network. RFC 6052 §3.1 defines the well-known prefix as a `/96`,
  so inside it the embedded IPv4 is unambiguous and is now decoded;
  `64:ff9b::a9fe:a9fe` still refuses, because 169.254.169.254 refuses on its own
  merits. The rest of the `/32`, including RFC 8215's local-use
  `64:ff9b:1::/48`, stays refused outright: RFC 6052 §2.2 allows six embedding
  lengths, and guessing which one a local deployment used could read the wrong
  bits and render an internal target as a public-looking address.

  **ISATAP is the odd one out and was found by review**, after the first four
  landed: it has **no prefix to anchor on.** The IPv4 is the low 32 bits behind
  the IANA-reserved `00-00-5E-FE` OUI under ANY /64, so `2606:4700::5efe:c0a8:1`
  is an entirely ordinary-looking global address that names 192.168.0.1. A
  link-local ISATAP address was already refused for being `fe80::/10`; one under
  a global prefix was not refused at all. Because it matches on the interface
  identifier it reaches INSIDE the other prefixes, which is why the decoders
  accumulate candidates rather than returning the first match. An early return
  on the 6to4 arm was a live bypass found by review: 6to4 delegates
  `2002:<site-v4>::/48` to whoever owns that IPv4, so a site running ISATAP in
  its own 6to4 space produces `2002:808:808:0:0:5efe:a9fe:a9fe` — site address
  8.8.8.8 and tunnel endpoint 169.254.169.254, two readings of disjoint bits,
  both true, and only the public one was being checked. Teredo is the single
  exception and still returns, because its client address occupies the same
  groups 6-7 the identifier does, complemented, so there the two readings
  contradict rather than complement each other. Because it matches on the
  identifier it is also read LOOSELY — only the OUI is tested, not RFC 5214's
  reserved bits — because two earlier drafts tried to be spec-exact and the
  first was bypassable by setting the identifier's `g` bit, and because reading
  the marker strictly costs a total bypass against any tunnel driver more
  lenient than the RFC while reading it loosely costs nothing a real interface
  identifier would hit. And because it matches on the identifier rather than a
  prefix it can match inside another family's prefix, so it is tested **last**
  and the prefix wins — an address in IANA-assigned Teredo space is
  read as Teredo, which `a_teredo_address_is_read_as_teredo_not_as_isatap`
  pins, since the two readings disagree and refusing it would be a false
  positive.

  **Found while bumping a JavaScript dependency**, whose advisory was this exact
  class — "no classifier recognizes the NAT64 local-use range `64:ff9b:1::/48`".
  Ours did not either, and ours is the guard this project leans on hardest.

- **A record walk that runs out of pages now refuses instead of returning a
  truncated list as a success.** All three refusing walks fell out of
  `for _ in 0..MAX_LIST_PAGES` into a bare `Ok(out)`, so a repository larger than
  the page budget produced a short list indistinguishable from a complete one.
  `web::resolve_subscriptions` needs an `Err` to take its fail-closed branch;
  given `Ok` it hands the short list to `store::replace_sub_refs`, which DELETEs
  the reader's entire `sub_ref` projection and reinserts only what it was given.
  Everything past the cap was gone from their account, on an ordinary poll, with
  no attacker involved.

  `extend_bounded`'s refusal could not catch it: `MAX_LIST_PAGES` multiplied by
  the 100 records each request asks for is `MAX_LIST_RECORDS` on both clients, so
  against a server that honours the limit the page budget runs out first and that
  refusal was unreachable.

  **The cap is on requests, so the record count it bites at is the server's page
  size times the budget — not a number our constants fix.** A PDS answering 50 a
  page reaches half as far; one answering more than asked trips `extend_bounded`
  instead. And the last allowed page is a *false* refusal: terminating costs one
  extra request when a short page still carries a cursor — this project's own PDS
  does that — so a walk holding every record it was ever going to hold refuses
  anyway, on the strength of a cursor it never followed. With `limit=100` honoured
  that window is a repository of roughly 19 901 to 20 000 records. Safe direction,
  but a false refusal, and neither the clean boundary nor the fixed record window
  earlier drafts of this entry claimed. Found by a cold adversarial review of the
  walk budget, filed as #196.

  The new failure mode is a reader whose repository exceeds the budget being
  served their cached projection on every request rather than losing feeds. The
  correct direction, and worse than "stale" makes it sound: the fallback branch
  has no record keys, and the manage page gates its rename and unsubscribe forms
  on having one — so that reader loses the only in-app way to shrink the
  repository back under the cap. Recovery needs an operator or another atproto
  client. Raising the caps, or paging past them, is separate work.

  The two backends also disagree about where this bites. `backend=rust` caps at
  50 pages and 5 000 records, a quarter of the direct client's, so the same
  reader refuses at about 4 900 records there and works to about 19 900 on the
  sidecar. `Saved` walks the same path with one record per starred article, where
  4 900 is a plausible number for a real reader rather than a pathological one.

  **`Saved` should not be on this path at all, and that is filed rather than
  fixed here (#204).** Un-starring works by listing the collection to find the
  record's key, so a reader over the budget cannot see their saved records *and*
  cannot remove any — while un-starring is the only thing that lowers the count.
  The refusal is right where a short list is written back as a deletion, as
  `sub_ref` is, and wrong where it is not.

  **One caller turned the refusal into data loss and is fixed here:**
  `GET /opml/export` read both of its walks through `unwrap_or_default()`, so a
  refusal became `200 OK` carrying a zero-feed `featherreader-subscriptions.opml`
  — a blank backup, handed over at exactly the moment a locked-out reader reached
  for one, down the route this entry points them at. Both arms now refuse the
  export and say so, rather than exporting nothing and calling it a success.

- **A `listRecords` body is bounded before it is parsed, not after.** Every other
  limit is consulted once `serde_json` has already built the page, which cannot
  prevent the allocation it exists to prevent. Measured: one response of `{"":0}`
  objects at `net::MAX_BODY_BYTES` — 8 MiB, the most `read_capped` admits —
  retained **824 MB**, a 98x wire-to-heap amplification, on a 512 MB box.

  (An earlier draft of this entry said 787 MB. Both numbers are real and they
  describe the same shape at different sizes: 789 MB at 8 MB decimal, 824 MB at
  8 MiB. The figure quoted everywhere is now the second one, because 8 MiB is what
  the code actually permits.) The record cap does not see it —
  the page holds one record. The page cap does not see it — there is one request.
  The byte budget does not see it until the memory is spent.

  A cheap linear scan of the raw bytes now bounds how many nodes the body can ask
  for, counting the structural characters that introduce a value **outside
  strings**. Skipping strings is the whole difficulty: counting naively would
  refuse a legitimate article containing a million commas.

  The cap is **640 000**, from measurement: the worst shape reaches 210 bytes per
  counted character, so 640 000 is about the 128 MiB this claims. An earlier draft
  said two million on a 32-bytes-a-node model — which this same file already
  rejects two hundred lines above, where a single-entry object is charged 680
  bytes — and two million admitted **400 MB**, more than the attack it was written
  to stop. Re-measured when a review put the worst shape at 221 B instead: it does
  not reproduce. Sweeping nesting depths 10, 50, 100 and 120 against a counting
  allocator, the worst is 210.6 B per counted character and peak equals retained;
  depth cannot be pushed further to raise it, because `serde_json`'s own recursion
  limit of 128 refuses a deeper body before this guard would matter.

  Tests bracket the cap from **both** sides: the densest page the lexicons permit
  must fit, and the attack must not. The dense page is a full `readState` listing
  — 100 records each carrying `readIds` **and** `unreadIds` at
  `ReadState::MAX_IDS`, which counts about 403 000 nodes. Filling only `readIds`
  counted 203 503, so a cap as low as 300 000 passed every test while refusing the
  page the floor exists to protect; verified both ways, 300 000 and 2 000 000 now
  each fail that test.

  **Every path that turns an outside body into a `Value` is covered, and it took
  three rounds to make that sentence true.** The first round guarded the shared
  listing parse. The second added `SidecarClient::repo` — twelve lines from the
  listing path, the response for every create, put, delete and batch, where the
  identical attack retained 786 MB — and `PostOutcome::json`, the `backend=rust`
  funnel carrying the repo writers' responses, the PAR response, the token
  response and the session refresh. A third review round found **three more**, and
  they were the ones that mattered most:

  - `oauth::fetch::get_json`, which returns a `Value` from a host chosen by
    whoever typed the handle — a `did:web` document, or an authorization server's
    metadata — **before anyone is authenticated.** A stranger could spend most of
    a 512 MB box by submitting a handle. Bounded by structure, because these
    bodies are legitimately structural.
  - `xrpc::Repo::error_fields`, the ERROR twin of the `send` whose success branch
    had just been guarded: a hostile PDS answering **500** instead of 200 with the
    same explosion got the whole amplification, on every write and every listing
    failure. The guard was bypassed by a status code.
  - `token::classify_refresh_failure`, which parses a `400` body looking for
    `invalid_grant` — unattended, on every failed refresh.

  The last two are error peeks, so they take a LENGTH bound rather than a
  structural one: an error document is a few dozen bytes, and refusing to read a
  large one is fail-safe (the session stays, the request fails). `dpop` already had
  exactly that guard and exactly that reasoning for the nonce challenge; its 10 KiB
  constant now lives in `oauth` with one predicate and three callers, instead of
  being the only copy.

  **And the cap on the response funnel is now the endpoint's own.** 640 000 was
  sized by the densest page the lexicons permit, which is not what a token response
  is: at 210 B per counted character it admitted about 134 MB on a path whose
  largest legitimate body is 120 kB. Measured the real traffic — a 500-op
  `applyWrites` result counts 8 514 — and set 64 000, which is 7.5x headroom and
  ten times tighter.

  Filed as #197 from a cold adversarial review, which also established that the
  wire cap alone cannot close this — at a hundredfold amplification no single byte
  limit both permits long-form prose and bounds the attack.

  **The scanner is no longer called a node count**, because it is not one.
  `{"a":1}` counts three characters and builds two `Value`s, since a map key is a
  `String` in the map rather than a value — so the count can over-report by one per
  entry, as well as under-report by one on an array. Neither bound holds, and the
  old name (`node_lower_bound`) and error message ("would build at least N nodes")
  both claimed one did. The arithmetic is untouched: the cap is calibrated in these
  same units, 210 B per counted character, measured with this function doing the
  counting. Over-counting is also the safe direction for a guard.

  Two figures were wrong in the first draft of this entry, both found by review:
  the ordinary-traffic floor ("a page of 100 documents measures 40 000" — it counts
  **4 003**, and the test that was meant to hold it served a single record and would
  have passed with the cap at 1 000), and the 787-vs-824 MB discrepancy above.

- **A `listRecords` page is parsed once, not twice.** The body went through
  `serde_json::Value` and then into the typed struct, and `from_value` rebuilds
  rather than moves — so both copies are live at the same time.

  Measured on this branch with a counting allocator, before and after, on two
  8 MB pages. A page of 480 prose articles: peak 8.5 MB before, 8.2 MB after —
  a 4% saving, because long strings dominate and the wire size and the tree size
  are nearly the same. A page whose bulk is structure rather than text: peak
  256.0 MB before, 128.0 MB after — **exactly halved**, and the retained figure
  is 128 MB either way.

  So this buys almost nothing on honest traffic and halves the transient peak on
  the shapes an attacker picks, which is the only place it was ever needed.

  This is the one allocation a byte budget cannot cover, because the budget is
  charged on records that exist only once the body has already been parsed. The
  all three clients deserialise straight from the bytes, the sidecar included:
  its page arrives nested inside an envelope, so the envelope is typed too rather
  than read as a `Value`.

  The two invariants move with it rather than being dropped: an `error` present
  on a 2xx is a failure and not an empty page, and `records` **absent** is not
  `records` empty. They live in one function over one wire struct, which all
  three clients now deserialise into — the sidecar included, which means it is
  no longer the odd one out. That also makes them stricter: a duplicated
  `records` key, which a `Value` resolves last-wins and could therefore use to
  smuggle an empty page past a proxy, is a hard refusal everywhere.

  An empty body is refused with one reason across all three callers. An earlier
  draft of this entry said "the same reason it always carried", which was true
  only of the OAuth client; the direct client used to say "EOF while parsing".
  It is a unification, not a preservation.

- **The envelope guard fired only on a string `error`.** So a PDS answering
  `{"error":404,"records":[]}` walked past it and read as a healthy empty page —
  the exact shape that makes `replace_sub_refs` delete every `sub_ref` a reader
  has. Any type is an envelope now, and the field is typed as a `Value` so the
  refusal reports as an envelope rather than as "invalid type", which is the
  right reason for the one shape this guard exists for.

  Absent, `null`, `false` and `0` are the four spellings of "no error". The last
  two are a proxy convention, and treating them as envelopes would fail a good
  page of a thousand records outright. The name is also truncated before it
  reaches a log, because the PDS chooses it and the log already carries the DID.


- **Every response body in the atproto layer is now capped. Five were not.**
  `SidecarClient::repo` buffered `/internal/repo` with `resp.json()`,
  which reads whatever arrives. That endpoint proxies the account's PDS, so the
  length is chosen by a host the reader picked and we did not, and the sidecar
  is the default backend — so the one path with no byte bound of any kind was
  the one most deployments run. Both the success and error paths now go through
  `net::read_capped`, the same 8 MB ceiling the direct client has always had.
  Found by review of a change that set out to bound the *record walks* and
  missed the transport underneath one of them.

  Review of **that** fix then found four more of the same shape, two of them on
  hosts an attacker picks rather than merely influences: the DID document, whose
  host for a `did:web:` comes straight out of the DID, so whoever supplies the
  DID chooses the server; `resolveHandle`, against a resolver base this code's
  own comment calls user-influenced; and the sidecar's two session reads. The
  SSRF guard covers where those requests go, not how much comes back.

  The original entry claimed the sidecar body was capped "like every other body
  this codebase reads" and the pull request said the same of that client's
  siblings. Neither was true when written; both are now.
- **A sidecar error whose body cannot be read keeps its HTTP status.** Reading
  the body before branching on the status was the obvious shape and it swallowed
  the status on an over-cap or truncated error body, turning a `404` into a bare
  "body exceeded the cap". `xrpc_error_from` already makes the opposite choice
  deliberately, for this reason.
- **A record walk is bounded in retained bytes, across all four walks.** Every
  walk capped how many records it would accumulate, against a measured ~17 KB
  document, and `MAX_LIST_PAGES` bounds requests rather than memory. A PDS whose
  records are not that shape satisfies every count and still exhausts the box.

  The bound charges what a parsed value **retains**, not what it takes on the
  wire. A first attempt charged serialized length and was wrong by up to 42x: a
  parsed value is a tree of 32-byte nodes in vectors that over-allocate, so
  `[[],[],…]` costs three bytes of JSON and well over a hundred in memory.
  Measured against that estimate, a budget reporting 119 MiB held a process at
  5.6 GiB. Every arm now charges at least the node itself, and an object charges
  for its backing node — `serde_json::Map` is a `BTreeMap` whose leaf carries
  room for eleven pairs and is allocated whole, so a one-key object costs what
  an eleven-key one does. Charging it as an ordinary container under-reported
  object-shaped records by about half: the same failure two orders of magnitude
  smaller, caught by a later review round.

  **128 MiB of accumulation per read, which is not 128 MiB of memory.** Every
  charge is taken after the page is already built, so the true peak is the ceiling
  plus one page's tree — and a page's tree is not small: an 8 MB response of
  one-key objects retains 824 MB, 98x its wire size. A bound consulted after the
  allocation cannot prevent it. What it does prevent is accumulation across pages
  and across the walks of one read. The single-page case needs a smaller wire cap
  or a counting parser, and is filed as #197 rather than implied here.

  A caller passes one budget into every walk it makes, so a publication read —
  which runs a second walk while still holding the first's records — is bounded
  once rather than twice; two independent ceilings put about 384 MB of
  accumulation in flight. Only that one caller threads it today and it has no
  production entry point yet, so every live read still builds a ceiling per walk
  and nothing bounds concurrent requests.

  The figure differs in effect per walk, because the record caps do. The
  subscription walks cap at 20 000 records and a real subscription charges
  2 188 bytes here — 2 764 with a folder and a fetch hint — so a full repo is 42
  to 53 MB and the count binds first. That matters most on those walks because
  their verdict is a refusal, which drops the reader into the fail-closed branch.
  The publication walk caps at 2 000 documents, about 37 MB at the measured ~17 KB
  article; above roughly 66 KB per article the budget binds first and the walk
  truncates early. So it is not true that nothing truncates that did not truncate
  before, and an earlier draft of this entry said so — as it also said 64 MiB,
  30 MB and 33 KB, all of which this work has since corrected.

  The two verdicts differ. The three walks feeding `replace_sub_refs` refuse,
  since a short list there is revoked access. The publication read truncates and
  reports `complete: false`, which it already models.

### Fixed

- **An at-URI is recognised whatever the case of its scheme** (#183). A
  mixed-case `At://` row was handed to the poller, which could only fail on it,
  every tick, forever. It then showed up in the `/stats` `fetch` bucket as an
  unreachable publisher. URL schemes are case-insensitive, so recognition is
  now too: `atproto::strip_at_prefix` in Rust and `lower(substr(...))` in SQL.
  A non-canonical spelling is refused at storage time, because `feeds.url` is
  UNIQUE and two spellings of one publication would be two rows. Only a legacy
  row could have this shape; nothing can store one today.

  **The feed ceiling's use now shows up somewhere.** `count_feeds`
  deliberately counts unpollable rows, because the ceiling bounds storage. But
  that usage appeared nowhere, so an instance could sit at its cap refusing
  subscriptions while every public number said otherwise. `/admin/metrics` now
  shows feeds cached, the ceiling, and how many feeds are unpollable.

- **A certificate test no longer turns latency into a verdict about a
  certificate.** `the_test_ca_is_trusted_and_still_validates_hostnames` asserts
  that the test CA is trusted and that a host outside the leaf's SAN list is
  still refused. It was observed failing on the first HTTPS request in a freshly
  linked test binary — 11.7 s and 20.3 s measured on one macOS machine, against
  the 15 s per-read bound `build_pinned_client` sets.

  **The cause is not pinned, and this entry no longer claims it is.** Nine later
  attempts on the same machine, three of them under a load average of ~120,
  measured that first request at 8–17 ms. The leading candidate is CPU starvation
  with ~900 tests in flight.

  So the test asks again when the only answer is a timeout, up to three times. A
  timeout is not a verdict about a chain; a verdict is returned on the first ask,
  so a genuine validation failure is never retried or masked. No production bound
  changes.

  **Two earlier attempts were wrong, and both are worth naming.** The first
  raised the per-read timeout under `cfg(test)`: the production constant became
  invisible to every test, so the assertion said to protect it protected nothing
  and setting it to an hour left the suite green; the effective relaxation was 30
  seconds rather than the 120 claimed, because the total request timeout caps it.
  Filed as #195. The second warmed the platform verifier once per process, on the
  claim that reqwest switches to `rustls_platform_verifier` only when an extra
  root is present — **that claim is false.** reqwest builds the platform verifier
  on both arms of `if config.root_certs.is_empty()`
  (`reqwest-0.13.5/src/async_impl/client.rs:758`), so there was no test-only path
  to warm and production takes the same one. That attempt also failed silently
  (its builder and its request both discarded their outcome, and the `OnceCell`
  recorded success either way), omitted the `.no_proxy()` this module documents
  at length, and issued a real request into whichever caller's captured request
  log libtest happened to schedule first.

- **A retention window too large to be a date stopped the sweeper instead of
  being ignored.** Every retention knob parses from a `u32` with no upper bound,
  and both `chrono::Duration::days` and `DateTime - TimeDelta` panic out of range
  — measured, anything past roughly 96 million days, and `u32::MAX` is. A unit
  slip is enough to reach it: seconds or milliseconds typed into a field that
  means days.

  The failure was quiet, which is what makes it worth a line. The sweep runs in a
  spawned task, so tokio caught the panic and the retention sweeper simply stopped
  for the life of the process — silently, permanently, and taking with it the
  release valve for `db_size_watermark_bytes`, which is the one thing that stops
  polling for every reader on the instance.

  An unrepresentable window now disables the pass it belongs to and says so in a
  warning naming the knob. That is also what `standard_site::ingest_floor` already
  answered for the same input, and `Config::retention_for` exists to keep the two
  agreeing — so this ends a disagreement where unrepresentable meant "store
  everything" on one side and "panic" on the other. Found reviewing #206, which
  added the third knob and therefore a third way in.


- **Publication entries get a stable date instead of one that resets itself.** `site.standard.document`
  makes `publishedAt` optional, and an entry stored without a date takes
  `fetched_at` at insertion instead. Retention and the per-feed cap both order on
  `COALESCE(published, fetched_at)`, so an undated entry is swept once it is
  `retention_days` old, re-inserted by the next poll with a fresh `fetched_at`
  and a new `entries.id`, loses its read state to the cascade, and comes back
  unread — on that cycle, indefinitely. A document with no usable `publishedAt`
  is now dated from the TID in its record key, which is the microsecond the
  record was written.

  **This narrows the cycle; it does not end it.** A date that no longer resets
  itself is a precondition for ending it, not a cure: for a document whose write
  time is already older than the retention window, a fixed date is permanently
  past the cutoff, so it is swept on every sweep and re-listed on every poll —
  faster than before, not slower. What ends it is refusing to insert what is
  already past the floor, which belongs with the retention floor still to come.
  Nothing stores publication entries yet, so the order of the two changes is a
  sequencing requirement rather than a live defect.
- **A stated date in the future is discarded, not used.** Retention deletes rows
  older than the cutoff and the cap keeps the newest, so a document claiming the
  year 2999 was never swept and permanently held the top of the reading list.
- **`feeds.kind` is re-derived from the URL rather than translated once.** The
  column is a cache of `FeedKind::of`, and it was populated by a one-time SQL
  `UPDATE` carrying its own copy of the rule as a string predicate. That
  translated `rss` to `publication` and never the reverse, so a row whose stored
  kind disagreed with its URL in the other direction stayed wrong permanently:
  an http feed marked as a publication is excluded from every poll, forever,
  and nothing re-reads it. The classification is now asked of the Rust function
  on every start, in both directions, and `upsert_feed`'s conflict clause
  carries `kind` so re-subscribing re-derives it too.
- **Taking a feed out of the poller now clears the poll state it orphans.** A
  backoff horizon and an error count belong to a row the scheduler selects; on
  one it will never select again they are hidden from `/stats` and the cause
  histogram, which filter on kind, so they rot unseen — and a later rule change
  that readmits the row resumes it at a backoff earned under a classification
  that no longer applies. Seven prior errors meant a first retry ten hours out
  instead of five minutes.
- **An unreadable `feeds` row no longer stops the process from starting.** The
  re-derivation runs on the boot path, and reading `url` as text turns a row the
  old SQL predicate evaluated happily into a hard startup failure — trading a
  wedged poller for a site that will not come up, and on a deploy, a failed
  health gate. Such a row is skipped with a warning instead. Nothing this
  codebase writes can produce one; reaching it means the file was edited by
  hand, which is precisely when refusing to boot helps least.
- The string predicate is gone. It agreed with `FeedKind::of` on the day it was
  written and had no way to notice if it stopped — which is how one reader came
  to drift from it unnoticed, recorded in this file at the time. Its reasoning
  moved onto `FeedKind`, which is where the question is now asked.

### Added

- **`standard_site::store_publication`** — the half of 0.4.0 that was missing.
  The reader could fetch a publication and turn its documents into entries;
  nothing wrote them anywhere. Three poll semantics, each of which a reviewer of
  the abandoned first attempt had to find:
  - **Starvation is keyed on what the read OFFERED, not on what survived the
    retention floor.** A truncated read that produced nothing means the walk gave
    up before its first record, and that is a failure. A truncated read whose
    entries are merely older than the window is a healthy poll of an old
    publication; calling it a failure puts it into a backoff that widens forever.
  - **A failed poll does not stamp `last_polled`.** The natural way to write this
    upserts the feed first and returns the failure after, which makes a broken
    publication read as freshly polled on `/stats`.
  - **An entry already older than the window is not stored.** Storing it means the
    next sweep deletes it, the next poll re-inserts it with a new row id, and it
    arrives unread — on that cycle, forever.

    "The window" is the one the **sweep** would use, and getting that right took
    three attempts. Keying on the rolling window alone left a hole in a supported
    configuration, since `retention_days = 0` disables the rolling window while the
    ceiling stays alive: with 0 and 180 nothing was floored and the ceiling
    reinstated the cycle — a worse one, because the ceiling spares nothing, so a
    starred entry came back unstarred rather than merely unread. Reaching for the
    **shorter** of the two then over-corrected. `prune_old_entries` honours the
    ceiling only when it is strictly older than the window (a ceiling inside the
    window is logged and ignored there, since the hard delete would take exactly
    the rows the soft delete spares), so at `days = 180, hard = 30` nothing is
    deleted before 180 days while the floor discarded five months of a publisher's
    archive that nothing would ever have deleted. The rule is now: the window when
    there is one, the ceiling only when there is not.

    **And for a publication the pair is not the RSS window at all.** #206 landed
    `Config::retention_for(kind)`, which gives a publication `(0,
    publication_retention_days)` — no rolling window, a generous archive ceiling —
    because a 14-day window stored zero rows from every real publication measured.
    Fed that pair, the rule above falls through to the ceiling, which is exactly
    the sweep pass that can delete such a row.
    `a_publications_floor_is_its_archive_ceiling_not_the_rss_window` asserts the
    two halves agree, and fails if either is changed alone.

    An **unrepresentable** window is no floor, said directly. `RETENTION_DAYS`
    parses into a `u32` with no upper bound and `u32::MAX` days is an operator
    saying "keep everything"; the previous shape fell back to a sentinel instant
    and left the outcome resting on the row comparison being lexicographic —
    `fmt_time` renders an out-of-range year with a sign, which sorts either side of
    a 4-digit year by ASCII accident. Verified: swapping that fallback to
    `MAX_UTC`, a floor of the year 262143 that should have discarded every entry in
    existence, changed nothing at all.
- **An entry with no date is stored anyway**, which is a decision rather than an
  oversight. It is dated by `fetched_at`, which does not move, and the alternative
  is discarding an article the reader can never see. Three consequences, all
  documented on the function rather than the first one alone: it resurrects once
  per retention window; under the hard ceiling it comes back **unstarred** as well,
  because the ceiling spares nothing; and until then it **outranks** the
  publication's real articles, since both the sweep and the per-feed cap order on
  `COALESCE(published, fetched_at)` — so a publication of mostly undated documents
  can push dated articles out of `max_entries_per_feed`. `new_entries` is likewise
  an upper bound rather than a count of survivors: `insert_entries` reports what it
  inserted and the per-feed cap trims within the same call.
- The floor also logs what it dropped. A complete read of three year-old posts and
  a complete read of an empty publication both return zero new entries, stamp the
  feed and look green, so a subscriber to an archived blog got a blank feed and
  nothing said why.
- `fetch` now returns whether the walk finished instead of logging it and dropping
  it. A truncated read and a quiet blog produce identical entries, so only the
  caller can tell "this publication has nine articles" from "this reader gave up
  after nine" — and the caller was never told.

- `atproto::decode_s32_tid`, the inverse of the existing encoder, and
  `tid_timestamp`, which refuses a TID decoding far into the future or to before
  atproto existed, with five minutes of grace for a PDS whose clock runs ahead
  of ours.
- Those bounds are **not** a slug detector, and a test now says so by name.
  Thirteen lowercase alphanumerics is an ordinary filename shape and also a
  valid `s32` value, so `3hoursinparis` reads as 2020-11-24 and `3ideasforjune`
  as 2021-08-12, indistinguishable from record keys written then. Telling them
  apart would mean asking the PDS when the record was written, which the listing
  does not report. What the bounds do guarantee is that a mis-read date is an
  ordinary past instant rather than an unsweepable future one — worth having,
  and not harmless: a slug reading as 2020 is older than any realistic retention
  window, so the row is swept, re-listed on the next poll, and arrives unread
  again. That is the cycle the retention floor closes, for a mis-read slug and a
  genuine archive alike.

### Tests

- **Dating**: fourteen, each mutation-checked, taking the library suite from 859
  tests to 873. One of them pins a store invariant the change rests on: an
  upsert refreshes `published` from every poll but never refreshes `fetched_at`.
  It was not pinned before, and it is the reason the fix is what it is.
- **Classifier**: six more, all mutation-checked, two of them red first — a kind that
  disagrees with its URL is corrected in either direction, and a second
  subscription to the same URL re-derives rather than preserving. Four mutations
  (reverting to a one-directional back-fill, disabling the write, dropping
  `kind` from the conflict clause, and preserving the stored value there), each
  killed by one of them. Four more for the operational findings: leaving
  orphaned poll state, keeping `next_poll` on an unpollable row, aborting the
  boot on an unreadable row, and abandoning the pass at one.
- The suite stands at **906 tests**: 903 pass, two are ignored, and one is the
  load-sensitive TLS failure filed as #195. Measured on the merged branch, not
  carried forward — drafts of this line have said 877, 884, 885, 888, 889, 891
  and 893, none of them measured when written.


- **A mock that serves a different body per request**, which this suite did not
  have. The fixed-body servers answer every request identically, so a paging
  walk sees the same cursor twice and its repeat-detection guard stops it at two
  pages — which makes anything that only happens *across* pages unreachable.
  That is how a cap that was per-page rather than per-walk, and therefore 200x
  weaker, once passed an entire suite unnoticed.
- Eleven for the walk budget, each mutation-checked. One asserts against heap
  figures that were taken with a counting allocator, which is what catches an
  under-charge the node-count property cannot see — but it hardcodes them rather
  than measuring, so it is a tripwire for the estimate changing and not for the
  real cost changing. Another computes that a full subscription repo fits the
  budget twice over, which is the calculation a reviewer found stated wrongly in
  a comment because nothing computed it.
  Twenty mutations, all killed by a named test — including the five from the
  second review round and the two from the third. One is not: `standard_site::fetch`
  passing a single budget to both its walks is unpinned, because reaching it needs
  a mock serving the PLC directory and two collections. The sharing mechanism is
  pinned; that one call site is not. The rest: the per-page budget in each of the four walks, dropping the
  recursion into arrays and into objects, charging scalars nothing, the
  exact-fit fence-post, a refusal resetting the running total, an uncharged uri
  and cid, removing the check from the live walk entirely, charging a map as an
  ordinary container, and halving its backing node.

### Corrected in review

Four defects in the first version of this change, all found by review before it
merged and all recorded here rather than quietly rewritten.

- **The first fix clamped a future date to "now". That was wrong**, and the
  reason is the invariant above: `published` is rewritten on every poll, so a
  clamped row is re-dated to the current hour forever. It can never age past the
  retention cutoff, can never be outranked in the per-feed cap, and sits at the
  top of the reading list showing today's date. Clamping moved the defect and
  made it harder to see — the literal `2999` was at least a visible symptom.
  A non-credible date is now discarded like an unparseable one, falling through
  to the record key and then to undated; every one of those values holds still.
- **Two tests named for the rkey fallback passed with the fallback deleted.**
  Both minted a fresh TID and asserted the result was "about now", which any
  source of the current time satisfies — including a fallback replaced outright
  by `Utc::now()`. Both now use a fixed record key from a real repo and assert
  the exact instant it decodes to. Three further mutations that survived the
  original tests die against the new ones.
- **A round-trip test cannot catch a consistently wrong alphabet.** Swapping two
  `s32` symbols round-trips perfectly and misreads every real record key. The
  decoder is now pinned to a known answer computed outside this code.
- **`the_decoder_rejects_rkeys_that_are_not_tids` claimed more than it proved.**
  The decoder accepts any 13-character `s32` string, slugs included; refusing an
  implausible instant is `tid_timestamp`'s job. Renamed, and the function's own
  doc comment corrected to match. The end-to-end test now covers a slug-shaped
  key as well as a punctuated one, so the bound is exercised through the mapper
  and not only as a unit.

Two wrong numbers in the first draft of this entry, both since computed rather
than estimated: the slug `abcdefghijklm` decodes to 2192, not 2183, and a TID's
leading character is `3` between 2005-09-05 and 2041-05-10, not 2004 and 2038.

### Corrected in a second review round

A cold pass over the corrections above — the one commit nobody had read — found
four more. The first version of this entry claimed the slug bound stopped slugs
from being read as dates; it stops only those landing outside 2020-to-now, which
is a minority of them. It claimed publication entries "stop resurrecting"; for a
document older than the retention window the cycle gets faster, not slower. A
doc comment for an unrelated store test was captured by the test inserted above
it, leaving that test undocumented and this one described by a paragraph about
`If-None-Match`. And `Entry.published`'s own field comment still described the
old rule, in a change whose review discipline is precisely that.

### Corrected in a third review round

- **One clock, two answers.** The five-minute skew allowance was written for the
  record key only, so a stated `publishedAt` was judged against a bare `now`. A
  publisher whose clock runs a few seconds ahead had a perfectly good date
  discarded, and with a slug-shaped record key the entry was then stored
  undated — which, ordered on a bare `published DESC`, buries the newest post at
  the bottom of the list. Both sources now share one ceiling, and the constant
  is no longer named after TIDs.
- **A comment contradicted the entry above it.** `TID_FLOOR_MICROS` claimed a
  mis-read date "costs a reader ordering and nothing worse", which is false for
  exactly the slugs the same comment says will be misread: one reading as 2020
  is past any realistic retention window, so it costs repeated loss of read
  state. The changelog said as much two paragraphs away. The in-code comment is
  the one a future reader consults when deciding whether the floor is still
  needed, so it was the more damaging of the two.

### Considered and declined

A third finding asked for a lower bound on stated dates, since `1970-01-01` is a
routine "missing date" default from static-site generators and lands permanently
past the retention cutoff. Declined: the cycle it describes is driven by the date
being older than the retention window, not by it being wrong, so a floor would
have to reject genuine archive content to catch the garbage — trading a known
limitation for real data loss, and making the rejected entries undated and
therefore invisible. The ingest floor closes both cases at once and is the right
place for it.

### Known, not fixed here

- **The walk budget is per-walk, and walks nest.** `standard_site::fetch` holds
  the publication walk's records alive while the document walk runs, and the
  login path runs four list walks and retains all four results, so the real
  process ceiling is a multiple of one walk's budget. The constant's own doc
  calls it "the memory one walk may retain", which is accurate and easy to
  over-trust.
- **A page is charged only after it has been materialised.** The refusing walks
  charge the whole page and the truncating walk now refuses any single page
  larger than the budget, so the transient is bounded — but it is bounded after
  the allocation, not before it. Bounding it earlier means not parsing the page
  until its size is known, which is a change to the transport rather than to the
  walk.

- Admitting a new kind to `FeedKind::POLLABLE` makes a whole population of rows
  due at once: `due_feeds` sorts unscheduled rows ahead of every scheduled one,
  and rows that were never pollable have no schedule. Measured at a batch of
  fifty, a block of N such rows outranks every regular feed for `ceil(N / 50)`
  ticks while `/stats` shows a climbing backlog and nothing logs why. Bounded
  and harmless at ninety feeds, not at ten thousand. A note on `POLLABLE` says
  so; seeding or staggering `next_poll` belongs with the change that admits the
  kind.

- An undated entry is the newest row in the feed to the per-feed cap and the
  oldest to the reading list, which orders on bare `published DESC` where SQLite
  sorts NULL last. It is therefore safe from eviction and invisible to the
  reader at the same time. Pre-existing, affects RSS equally, filed as #187.
- The same future-date hole is still open for RSS, where `feed::entry_time` has
  no upper bound at all. The guard landed in the atproto mapper rather than in
  the shared layer that would cover both paths. Filed as #188.

---

## 0.3.8 — 2026-09-20

Fourteen PRs. Two additive nullable columns, no `fly.toml` change, one new
config flag (`FEATHERREADER_STANDARD_SITE`, off by default, gating storage
only).

**The headline is not a feature.** Six of the fourteen changed no behaviour at
all: they replaced 35 tests that stayed green with the code they named deleted,
each found by mutating the implementation and watching the suite pass. A
seventh added CI validation, and an eighth changed only a type bound.

This file's preamble says entries should record where a test proved
less than its name; most of this release is that.

### Security

**A vacuous test is a guard nobody would notice breaking.** Each of these
stayed green against the *whole* suite with the code it names removed:

| guard | the mutation that passed | what it hid |
|---|---|---|
| `guarded_get_no_redirect` | follow `MAX_REDIRECTS` instead of `0` | OAuth metadata, `plc.directory` and `did:web` documents read from wherever a `302` points, while `issuer` is compared against the URL that was asked for — the authorization-server mix-up defence |
| per-hop privacy re-check | check the first hop only | a public feed `30x`-ing to a tokened Substack/Patreon URL is fetched and streamed into the UI before storage refuses it |
| add-path privacy gate | *(no test existed)* | a token-bearing URL reaches the network on subscribe |
| rate limiter | key on `X-Forwarded-For` | unlimited `/login` and `/beta/redeem` by rotating one header value |
| CSP | `default-src * 'unsafe-inline'` | the XSS backstop gutted |
| `mark_cursor_pds_created` | delete its `WHERE` | every DID's cursors flagged as created, so their readState records are never created and every later flush updates nothing |
| session AAD | drop the column from the binding | `access_token` ↔ `refresh_token` swapped inside one row, both still authenticating |

Each is now driven through the real route or client and asserts on something
the mutation changes — a request log that must be empty, the bytes a client
sent, a bystander row that must not move (#170, #171, #172, #173).

**The generic write primitives are private, and the 0.3.7 entry below
overclaimed.** That entry says "the eight low-level writers across both backends
demand the vetted type" and backs it with three compiled bypasses. Two things
were wrong with it when it shipped, and they are corrected here rather than
edited there, because the shipped record should show what was believed at the
time.

First, there were nine writers, not eight: `SidecarClient::create_subscriptions_batch`
took a raw `&[Subscription]` straight into `applyWrites`. It had no callers and
so drew no attention. Deleted (#169).

Second — and this is the general case the first was one instance of —
`create_record`, `put_record` and `apply_writes` are generic over
`T: Serialize`, and `lexicon::Subscription` derives `Serialize`. Any handler
holding `state.sidecar` could write an unvetted record through them with no
more effort than the deleted function required. Verified by compiling it.

Those three are now **private** on `PdsClient` and `SidecarClient`. Not
`pub(crate)` — that was the first attempt, and a self-review caught it stopping
nothing that mattered: a handler in `web.rs` is in this crate. Both were
verified by compiling a probe from `web.rs`:

```
pub(crate)   builds clean          — the handler can still write unvetted
private      3 "private method" errors
```

The three on `oauth::xrpc::Repo` stay `pub`: `examples/oauth_spike.rs` is a
separate crate target and drives them against a scratch collection. So a
handler in this crate can still write an unvetted record through the OAuth repo.
**Narrower than before, not absent.** Ending the class means removing
`Serialize` from `lexicon::Subscription`; that needs a hand-written impl for
the `#[serde(transparent)]` `VettedSubscription` plus a wire-format test, and
was tracked rather than done — **closed later in this release by #178**, which
gets the same guarantee from a sealed trait instead, leaving the derive alone.

The claim "there is nothing to hand them that skipped the check" has now been
wrong in three consecutive corrections. Each enumerated what was in front of it
and described the result as the population.

**An unvetted record no longer type-checks** (#178). The 0.3.7 entry below
claimed this; the correction under it narrowed the claim to "narrower than
before, not absent" and named removing `Serialize` from `lexicon::Subscription`
as the way to end the class — then recorded that as blocked, because
`VettedSubscription` is `#[serde(transparent)]` over it and a hand-written impl
could silently migrate every reader's repo.

`vetted::WritableRecord` is a **sealed** marker trait: implementing it requires
a trait private to that module, so its implementors are the whole list — the
vetted wrappers, plus `Folder` and `ReadState`, which carry no field rendered as
an href. `create_record` and `put_record` take that bound, so
`create_record(nsid::SUBSCRIPTION, &raw_subscription)` no longer compiles, and
the wire format still comes from one derive.

The evidence is a `compile_fail` doctest, which CI runs. A `compile_fail` that
passes for the wrong reason is the trap here, so it is mutation-checked: adding
`Subscription` to the implementor list makes its snippet compile and the doctest
fails.

`apply_writes` stays reachable — `WriteOp::Create.value` is a
`serde_json::Value`, so a hand-built record goes through. That is a deliberate
two-step rather than an accidental one-liner, and `repo.rs` now names it instead
of implying the class is closed.

**The OPML upload cap is the route's own** (#176). `OPML_BODY_LIMIT` was exactly
2 MiB — axum's `DefaultBodyLimit` — so the route's layer was a no-op, and the
test named for it was really testing axum. Lowered to 1 MiB, which is the
direction that makes the layer mean something: raising it above the default
would have made it testable by *weakening* the bound. One outline is ~92 bytes,
so 1 MiB carries ~11 000 of them against a per-DID cap of 500 the import trims
to anyway. A compile-time assertion keeps it under the framework default.

### Added

**`/stats` says WHY feeds are failing, and `/admin/metrics` says which**
(#166). `feeds` recorded `consecutive_errors` and nothing else, so a systematic
defect across sixty feeds was indistinguishable from sixty dead blogs — which is
exactly what 0.3.7's #159 was. `PollOutcome::Failed` now carries a closed
`FailureKind` (`fetch | status | body | parse`) and a detail capped at 300
characters, in two additive nullable columns.

The public page gets a cause histogram: counts only, never which feed and never
whose. Had it existed, #159 would have read `60 fetch` on a page anyone could
load. Rows that predate the columns, or carry a kind this build does not know,
fold into `unknown` rather than vanishing — so the breakdown always sums to the
`Failing` figure beside it. `/admin/metrics` (ALLOWED_DIDS only) names the
failing feeds with kind, detail and count.

**standard.site publications, dormant** (#164, #165). `FEATHERREADER_STANDARD_SITE`
(default off) lets an `at://…/site.standard.publication/…` subscription be
**stored** — one arriving by OPML import or written by another client. The
subscribe form cannot take one: the add path must fetch what is pasted and
nothing fetches `at://`.

Nothing polls one either, and that is by exclusion rather than by the flag:
`due_feeds`, `/stats`, the admin list and a boot-time clearing all share one
predicate, so an `at://` row is **skipped, not failed**. Handing one to the
poller would manufacture a permanent failure per row and publish it as an
unreachable publisher — the conflation the cause histogram exists to end. The
19 such rows on this instance predate the scheme check and are cleared by a step
that touches only rows never polled successfully.

`src/standard_site.rs` reads a publication and its documents (#165), reusing
everything that makes the fetch safe rather than rebuilding it. Only
`textContent` / `description` are read — `content` is an open union, six
wrappers and twenty-two block types across 449 measured documents — and they are
**escaped, not sanitised**: both are plain text, and `ammonia::clean` parses its
input as markup, so `"if x<y then z"` comes back as `"if x"`. Documents are
filtered by the URI the PDS minted, the guid is the record URI rather than the
mutable `path`, and a walk that stops early says so. **Not wired to the poller**
— that is the next release.

### Fixed

**A feed failing its first fetch is now backed off** (#166). The scheduler
bumped the error count *and* wrote `next_poll`; the direct poll on subscribe did
only the first, so the backoff the counter implied was never applied — the
scheduler picked the feed up on the next tick anyway, because a NULL `next_poll`
is due. Both callers go through one settle path.

**A `listRecords` walk is bounded by records, not just pages** (#168). The page
cap bounded requests; a server ignoring `limit=100` could still return
gigabytes. `extend_bounded` refuses past 20 000 records rather than truncating,
because its caller feeds `replace_sub_refs` — where a short list is revoked
access, not a short list.

**A 2xx carrying an error envelope is not an empty page** (#165). `records` is
`#[serde(default)]`, so `{"error": …}` on a 200 deserialised as zero records —
and on the OAuth path that reaches `resolve_subscriptions` as "this DID follows
nothing", which `sync_sub_refs` writes through, deleting the reader's whole
`sub_ref` projection. One shared parse now enforces both invariants (no error
envelope, `records` present) for all three clients, and the four write paths
refuse an envelope too. An empty body is refused for the same reason.

### Tests

Thirty-five vacuous tests replaced or retired across #170–#175, each proven by
breaking the implementation and showing the suite still passed. Besides the
security guards above: six `store.rs` queries that passed with their `WHERE` or
`ORDER BY` deleted — including a starred-entry trim that, with its ordering
flipped, spares the *oldest* starred articles and evicts the newest on every
poll; bulk-write tests that built the `applyWrites` ops themselves and never
called the function; a `ReadState` cap that was unit-tested but never proven to
be applied; OPML escaping exercised only on the display label.

Three pieces of dead code were deleted rather than tested: a `did:web`
IP-literal branch whose every case the numeric-TLD rule already refused, a host
conjunct in `is_storable_feed_url` that no input could reach, and two sort
helpers left behind by tautological tests. Two of the hunt's own findings were
wrong, and saying so is the point: both were verified by probe before anything
was removed.

### CI

`deploy/Caddyfile` is validated against both OAuth routings (#161), so a syntax
error or a routing change that breaks one of them fails the build rather than
the deploy.

---

## 0.3.7 — 2026-09-19

Eight PRs. No features, no schema change, no `fly.toml` change. One config
change — the Caddy log filter — which is baked into the image and so takes
effect on deploy, not on the running machine.

**The headline is #159:** the poller was recording "nothing new" as a failure,
which is most of why 68 of 111 feeds read as failing on `/stats`.

### Security

**The unvetted record write no longer type-checks** (#150, closes #140 and
#142). 0.3.6 routed every subscription write through a vet and made the
macro-generated writers private, but the layer below stayed reachable:
`AppState.sidecar` is a `pub` field and both `SidecarClient` and
`oauth::xrpc::Repo` expose their own writers. The 0.3.6 entry below records that
honestly as "the vetted path, not the only possible path" — a convention, and
#138's own argument is that conventions are worth what their tests measure.

`src/vetted.rs` now holds `VettedSubscription` and `VettedSaved`, in their own
module for the `safe_link.rs` reason: a private field is private to the MODULE,
and `repo.rs` is where every record write is assembled, so a type declared beside
its own constructor would be forgeable again. The eight low-level writers across
both backends demand the vetted type.

Verified by writing the bypass out and compiling it:

```
before                                      after
state.sidecar.add_subscription(did, sub)    error: expected `&VettedSubscription`
state.sidecar.add_saved(did, saved)         error: expected `&VettedSaved`
xrpc_repo.add_subscription(sub)             error: expected `&VettedSubscription`
```

`VettedSaved` is fallible where `VettedSubscription` is not, and the asymmetry is
forced: `url` is required on `community.lexicon.rss.saved`, so unlike an optional
`siteUrl` there is no honest resting place for a rejected value.

**The reader view's two `href`s take a checked type** (#152, closes #115).
`EntryTemplate.url` was a raw `Option<String>` assigned straight off the
`entries.url` column — a remote feed's `<link>`.

```
before   url: Option<String>     any non-empty string reaches both `href`s
after    url: Option<SafeLink>   http/https only; None takes the no-link branch
```

Not a live hole — `feed.rs`'s `entry_link` scheme-checks at ingest, and that
wiring is tested. What made it worth doing is that the guard is procedural and
sits a long way from the `href`: it holds only while every future writer to
`entries.url` remembers to route through `feed.rs`, which is the same shape of
defence that, on the saved-record row, turned out to be deletable with a green
suite.

One user-visible narrowing, deliberate: a stored URL with any other scheme now
loses its link, relative URLs included. `feed.rs:707` is the only production
writer to that column and there is no `UPDATE` touching it, so only a pre-0.2.7
row can be affected — and a stored `/foo` used to render as a same-origin link
into the reader app rather than to the article, so the refusal is a fix.

Established by mutation: `external_opt` forced to `Some`, forced to `None`, and
the whole wiring reverted — each in isolation, each `745 passed; 1 failed`, the
single failure being the new test every time. The render side had no other
coverage, which is the issue's claim, now measured rather than asserted.

**The OAuth authorization code and `state` are redacted from the access log**
(#155). The Caddy log filter redacted two headers and left `uri` alone, so every
`/oauth/callback` line carried the PDS's single-use `code` and the `state` that
binds it to the pending row, verbatim — into `fly logs`, any drain, and the
scrollback of anyone tailing the app.

```
before   "uri": "/oauth/callback?state=SENTINEL_STATE_VALUE&code=SENTINEL_CODE_VALUE"
after    "uri": "/oauth/callback?code=REDACTED&iss=https%3A%2F%2F…&state=REDACTED"
```

Not an open hole: the code is one-shot and the exchange also demands the PKCE
verifier, a DPoP proof and `private_key_jwt`, so a reader of the logs cannot
replay it. But the argument for redacting `X-Origin-Auth` — already made at
length in that file — is the argument for redacting these.

`replace` rather than `delete`, matching the existing reasoning: the field
survives with its value gone, so a failed callback still shows which parameters
arrived. `iss`, `error` and `error_description` are deliberately untouched —
they are not secrets and are most of the diagnostic value of those lines.
Applied to **both** log blocks, because `origin_errors` is a separate logger that
inherits nothing from the site log.

Verified against caddy v2.11.4 — the version the pinned `caddy:2-alpine` digest
resolves to, read from the image config blob — by running the config and probing
the callback with sentinel values, with a negative control confirming the probe
can fail.

### Fixes

**A `304 Not Modified` was read as a malformed redirect, failing every unchanged
feed** (#159). `guarded_get_inner` gated its redirect branch on
`is_redirection()` — `300..=399`, which includes 304. A 304 carries no
`Location` by definition, so it fell through to *"redirect response without a
usable Location header"* and failed the whole fetch. `feed.rs` sends
`If-None-Match`/`If-Modified-Since` on every poll and has a correct 304 branch
that was therefore **unreachable**.

The effect: "nothing new" became a recorded failure. `consecutive_errors`
bumped, `touch_polled` never ran, the feed backed off exponentially — so the
feeds punished hardest were the ones implementing conditional GET *properly*,
and the quieter a feed was the more it was ignored.

```
before   9to5mac.com/feed/ -> HTTP 304 -> "redirect response without a usable
                                           Location header" -> error, backoff
after    9to5mac.com/feed/ -> HTTP 304 -> PollOutcome::NotModified, normal cadence
```

Found from production logs, against `9to5mac.com`, `proton.me` and `kodi.tv` —
all live and serving. `/stats` reported 68 of 111 feeds failing while its own
copy explained them away as "usually gone rather than flaky". **The metric had
inverted:** a backing-off feed leaves the backlog smaller, so the dashboard
improved as the bug spread, which is why it went unexamined for so long.

Only 304 is carved out; every other `3xx` stays inside the branch, because
`guarded_get_no_redirect` documents that it "refuses redirects outright" and the
OAuth mix-up defence rests on that. Of the relocating statuses only
`301|302|303|307|308` are followed — the rest are **refused rather than
returned**, since `web::resolve_feed_url` reads the body straight into feed
autodiscovery without checking the status, so a `305` error page carrying a
`<link rel="alternate">` could otherwise have become a subscription. That also
makes `305` stricter than before: it carries a `Location`, so it used to be
*followed*, routing the request through a proxy the response chose.

Confirmed red first and again after review restructured it: mutating the guard
back to a bare `is_redirection()` fails the new 304 test and nothing else — 44
passed, 1 failed — so this path had no coverage at all. The test asserts the hop
count as well as the status, because returning the 304 while still looping would
satisfy a status-only assertion and re-fetch every unchanged feed.

**Not fixed here:** `feeds` stores `consecutive_errors` and no error text, which
is why a systematic failure across sixty feeds was indistinguishable from sixty
dead blogs.

**A rename no longer destroys four fields of the subscription record** (#147,
closes #141). `update_subscription` is a `putRecord`, and a putRecord replaces
the whole record. The handler built a fresh
`Subscription::new(feed_url, now_rfc3339())`, so every field the form does not
carry was written back as its default — and `manage_row.html` posts `url`,
`title` and `folder`, nothing else.

```
field        stored value                    after a rename, before this fix
siteUrl      whatever the feed advertised    gone
fetchHint    as set                          gone
private      as set                          gone
createdAt    original subscribe time         reset to now
```

Four fields, not the three #141 names — `private` is the one the issue missed,
because `Subscription::new` sets it to `None` and the handler never assigns it.
`createdAt` is the worst of them: it is the reader's subscribe time, the sort key
for "when did I subscribe", it lives in *their* repo rather than our cache, and
once overwritten it is gone with nothing in the UI to say so.

Now a read-modify-write. There is no single-record read on `Repo`, so this lists
and filters by rkey; a `get_subscription` drops in behind the same handler logic
if it ever measures badly.

### Test and CI integrity

**Three capture-based tests now mean what their names say** (#148, closes #144
and #146). Test-only; no production behaviour changed.

- `spawn_http` reads to content-length instead of a single 8 KB read, so the
  negative assertions over the capture can no longer be satisfied by truncation.
  A positive anchor on the cross-origin credential test makes an empty capture
  fail loudly.
- A contended sweep is reported as `Contended` rather than an error, matching
  what `scheduler.rs` already does in production. `is_sqlite_busy` masks with
  `& 0xFF` so the WAL extended codes (261/517/773) classify correctly, and
  `a_non_busy_sweep_error_still_fails` stops the tolerance widening again.
- `the_public_jwk_and_jwks_never_contain_the_private_scalar` asserted against a
  literal from a *different* key, so it could never match; now derived from the
  key under test.

### Documentation

- **The comment describing the unvetted-write bypass is corrected** (#154). It
  still said `Repo` is "the vetted path, not the only possible path" and pointed
  at #140 as open, after #150 had closed it — directing a reader to guard
  something the compiler already guards, and advertising a surface that no longer
  exists. Also corrects `AppState.sidecar`'s field doc, which called the sidecar
  "the live repo-op path" after the 2026-09-13 cutover selected `rust`.
- **`Choosing an OAuth backend` gains the measured comparison, and the process
  count is made honest** (#156). Production `/admin/metrics` latencies for the
  three operations both backends have run, stated with their limits: the two were
  measured *sequentially*, not side by side — `sidecar` before the cutover,
  `rust` after — over different weeks and a different cache size, with small and
  unequal samples. Separately, the runtime heading said "three processes"
  unconditionally, which has been false on `rust` since the cutover, and
  contradicted "Build & run"'s "one or two" eleven lines later; the two counted
  Caddy differently and neither said so. The diagram itself needed nothing —
  `runtime.mmd` was updated at the cutover and already marks the sidecar
  conditional.

---

## 0.3.6 — 2026-09-19

Four commits. No features, no schema change, no config change.

### Security

**`siteUrl` stored-XSS class, closed at both boundaries.** The two halves
landed separately and neither is sufficient alone.

- **Write side** (#138, closes #114). `siteUrl` reached the
  `community.lexicon.rss.subscription` record on the user's PDS with no scheme
  check. This was never an XSS against our own UI — nothing in `templates/`
  renders the field. The exposure is that we are the *writer*: a feed serving
  `<link>javascript:alert(1)</link>` got that string published into the user's
  own repo, under their authorship, into a field the lexicon invites other
  clients to render as a link.

  The check sits at the write boundary rather than at each ingest. That is a
  trade, not a free win — a guard at ingest is safe against every future sink
  and exposed to a new ingest; a guard at the exit is the mirror image. The
  writers are enumerable and closed, the ingests are open-ended.

  The three writers are private `*_unvetted` methods behind wrappers of the
  same name. That makes `Repo` the vetted path, not the only possible path:
  `AppState.sidecar` is a `pub` field and the low-level writers are public, so
  a handler can still take the short path. Nothing does. #140 tracks the type
  that would make it a guarantee.

- **Read side** (#143, closes #139). OPML export emitted `htmlUrl` XML-escaped
  but not scheme-checked, from records read back from the PDS — so a hostile
  record written by any other atproto client became a `javascript:` URL in a
  file the user downloads and imports into some other reader. We were still the
  publisher of that file. A `deserialize_with` on the field closes it at the
  point a record crosses into the process, which also cleans the `feeds` cache
  row fed from the same read.

Together: a `Subscription` that entered this process from outside cannot carry
a `javascript:` URL, and one leaving for the PDS cannot either.

Still uncovered, deliberately: `feeds.site_url` written by the poller
(`feed.rs`), which builds `NewFeed` straight from `feed_metadata` and never
constructs a `Subscription`. Not a sink today — verified, no template
references it — so hygiene rather than exposure.

### Behaviour changes

- **A scheme-less `siteUrl` is now dropped rather than published.**
  `net::safe_link` requires an absolute URL, so `htmlUrl="www.example.com/blog"`
  — not unusual in OPML exported by other readers — becomes `None` on import.
  Consistent with how entry links have always been treated; the alternative
  invents a scheme the file did not carry.
- **Round-trip fidelity is deliberately lost.** Reading a record holding a
  hostile `siteUrl` and re-putting it rewrites it cleaned rather than
  preserving another client's payload. That heals the user's repo instead of
  propagating someone else's script URL.

### Tests

- **A TLS test CA, closing an adapter gap in the login callback** (#122). The
  OAuth issuer must be `https` and the SSRF guard refuses loopback, so nothing
  could drive the real `login::complete` against a local server — the wiring
  between its tested core and the network had no coverage at all, and all three
  forwarding steps survived mutation with a green suite. The
  authorization-server mix-up defence could be disarmed by editing one line in
  `complete`.

  A test CA *satisfies* the `https` rule rather than suspending it. No
  `danger_accept_invalid_certs`; one root is **added** under `#[cfg(test)]`,
  built-in roots stay, chains validate, hostnames match SANs. `test_pki()` is
  itself `#[cfg(test)]`, so removing the attribute fails to compile rather than
  silently trusting an extra root. `rcgen` is absent from the production
  dependency graph.

### Dependencies

- `base64` 0.22.1 → 0.23.1 (#124).

---

## 0.3.5 — 2026-09-17

Fifteen commits. No features, no schema change, no config change.

### Security

- **The SSRF guard could be bypassed by ambient proxy configuration** (#132).
  reqwest defaults `auto_sys_proxy: true` and no client in this repo called
  `.no_proxy()`. With `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` in the
  environment, requests went to a proxy — absolute-form `GET http://host/path`,
  or `CONNECT host:443` — for the *proxy* to resolve the hostname.

  Measured before the fix: vetted pinned server 0 requests, proxy received the
  request, result `Ok(200)`. It failed **open**, silently, on both schemes.

  Precisely what breaks: `resolve_and_check` still runs its own lookup and
  still rejects forbidden IPs — the check is not skipped. What a proxy destroys
  is the *binding* between the vetted address and the connection, because the
  proxy re-resolves the name on its own network. DNS rebinding, split-horizon
  DNS and anything reachable from the proxy all come back.

  `.no_proxy()` on all four production clients. The `AppState` one is
  load-bearing on its own — hyper-util's matcher has no localhost exemption, so
  an ambient proxy would have shipped `SIDECAR_INTERNAL_SECRET` to it on every
  sidecar call.

- `rustls` 0.23.45 for RUSTSEC-2026-0285.

- `fastify` 5.12.3 and the atproto client packages (#125), clearing four
  published high-severity advisories including an auth bypass. `npm audit`
  reported zero at every severity throughout, because those advisories live
  only in GitHub's repo-level database.

### Fixes

- **An equal-valued truncated observation must not downgrade the row** (#136).
  The upsert guard used a strict `<`, so a truncated observation whose value
  merely *equalled* the stored one still rewrote the row, flipping `truncated`
  from 0 to 1. A complete walk recording 2 000 followed by a budget-truncated
  walk that also counted 2 000 degraded `/about` from "2 000" to "at least
  2 000" with no change in actual adoption. `<=` is what the doc comment
  directly above already promised. Verified by reverting only the SQL and
  watching the new equal-case assertion fail, not by reading it.

### Test and CI integrity

No runtime behaviour change in this section, but the measurements are the point.

- **The sidecar's 71 tests gated nothing** (#134). Every other CI job runs its
  suite; the sidecar job went install → build → typecheck → lint → format →
  audit. An `npm test` failure could not fail a PR, and had not been able to
  for as long as the job existed. Those tests cover the parts with no other
  safety net: session-store encryption and the plaintext migrate-on-read path,
  the reaper's TTLs, `StoreError` op tagging, and `purgeDid`. The same change
  stops reading a green `npm audit` as an all-clear.

- **`login::start` had no test** (#135). Every guard in `complete` had one; this
  half had none, because it needs handle resolution, discovery and a PAR
  endpoint over the network. Five decisions were unfalsifiable and every one
  fails *silently* — the login breaks later, at the authorization server, for a
  reason nothing local explains. `start_with` injects the three boundaries, and
  every decision is made in `start_with` rather than in the caller's closures,
  because an argument assembled inside an adapter is invisible to a test.

- **Mutation-confirmed bad tests, and the scheduler seams behind them** (#127).
  Tests that passed while proving less than their names, each confirmed by a
  mutation that left the whole suite green. The blocker found by cold review:
  `spawn_starts_every_registered_loop` never called `spawn` — filtering
  `PendingSweep` out of the callback passed 697 lib + 13 bin tests and clippy
  while the pending-login sweeper never started and nonce rows grew unbounded.
  The fourth form of that file's recurring defect, added by the round that
  closed the third.

- **Three SSRF enforcement gaps** (#120). The guard's *decision*
  (`is_forbidden_ip`) was well covered; what carries that verdict to the socket
  was not. Per-hop revalidation, cross-origin credential stripping and
  multi-answer DNS each had a mutation that left 679 tests green. None was
  testable end to end because a local test server is on loopback, which the
  guard correctly refuses. The seam is a `#[cfg(test)]` host override — not a
  parameter, env var or feature flag, so the compiler removes it and there is
  no runtime bypass to reason about.

- **Two flaky tests fixed by measuring the right thing**, not by loosening
  thresholds:
  - the sweep-lock test counted refusals against attempts rather than elapsed
    wall-clock (#130). Under 4× CPU saturation the writer task simply did not
    run for 320 ms and the old wall-clock form counted that as a held lock —
    622 of 626 attempts had actually landed. A starved writer makes no
    attempts; a held lock refuses them.
  - the invite bot's mint-window test read the clock twice (#133). `now()` is
    whole seconds; `record_mint` stamped at one instant and `count_mints_since`
    computed its cutoff at a later one, so crossing a second boundary between
    them dropped rows written moments earlier. It failed CI on a base64 bump
    that cannot touch it — the bot is a separate workspace.

### Dependencies

- `reqwest` 0.13.5, `askama` 0.16.1 (#123); Swatinem/rust-cache (#99); the
  actions-minor-patch group (#126).

---

## 0.3.4 — 2026-09-13

- **Park unflushable read-state instead of retrying it forever** (#118, closes
  #117). A dirty `read_cursor` whose DID has no `oauth_session` was re-attempted
  every round forever — no cap, no backoff, no terminal state. That produced 20
  failures in 20 minutes in production and would have masked real failures for
  the whole soak window.

  Landed as a characterization test first, which **passed on the unfixed code**:
  it pins the defect's exact shape rather than the fix's, and the fix inverts
  its assertions. A second test established that sign-out can strand unflushed
  read-state — `revoke_everywhere` deletes the `oauth_session` unconditionally,
  with no flush first and no clearing of dirty flags that can no longer be acted
  on — which moved that path from hypothesis to reachable. Whether it is what
  happened in production remains unknown; the log buffer had rolled past the
  window.

---

## 0.3.3 — 2026-09-13

- **OAuth backend flipped to Rust** (#110). The in-process Rust atproto OAuth
  client takes over `/oauth/*` and every `com.atproto.repo.*` call; the Node
  sidecar is no longer started. Config, not code — both Caddy routings ship in
  the image and the entrypoint picks one, so this deploys the existing v0.3.2
  digest with new `[env]`. Every signed-in reader is logged out: nothing under
  `src/` reads `SIDECAR_DB`, so no token crosses the flip.

- **The `href` defence made structural rather than procedural** (#111).
  `EntryRow.link` was a `String` and the XSS defence was "remember to call
  `net::safe_link` before assigning it" — deleting that call left all 679 tests
  passing. The saved-record URL is attacker-controlled (any atproto client can
  write the record) and Askama escapes HTML metacharacters but not *schemes*,
  so `javascript:` survived escaping intact.

  Now a `SafeLink` newtype in its own module — its own module because a private
  field is private to the *module*, and `web.rs` is 9 000 lines. Two independent
  reviews falsified the first attempt, both finding the guard was legibility
  rather than structure. Four mutation classes are now blocked, two by the
  compiler (`E0061`, `E0423`) and two by a wiring test that renders the real row
  through the real handler from a hostile record.

- **OAuth refresh and revocation are counted** (#113). The soak criterion for
  the cutover was "a week with no refresh or revocation failures", and neither
  was observable — a refresh failure surfaced only as an error on whatever repo
  call happened to trigger it, and a revocation failure left exactly one
  `tracing::warn!`. "No failures this week" was a statement about nobody having
  looked. `oauth_refresh` is timed around `refresh_locked` specifically, not
  around `valid_session`, which runs on every repo call and would bury a rare
  failure under thousands of no-op successes.

- **Origin-secret rotation scripted across Cloudflare and Fly** (#109).
  Rotation moves two sides that must agree; while they disagree every non-
  `/health` request 403s, and because `/health` is exempt from the lock, Fly
  reports the machine healthy throughout and nothing alerts. Dry run is the
  default; preflight refuses to start unless the lock is already healthy.
  Failure states are distinguished — a Cloudflare failure leaves Fly untouched,
  a Fly failure after Cloudflare moved says so loudly, because that is the state
  where the site is already down. Used in production 2026-09-13.

---

## 0.3.2 — 2026-09-13

- **The origin-lock secret was logged in full, and the lock did not fail
  closed** (#107). `X-Origin-Auth` — the shared secret that *is* the origin lock
  — was written to every Caddy access-log line. Caddy redacts the standard
  credential headers by default, which is exactly why a custom name slipped
  through. Found while reading logs for an unrelated feed investigation.

  A site-level filter alone was not enough: a site `log` directive covers
  `http.log.access.*`, but errors during handling come from
  `http.log.error.*`. `caddy validate` passed identically before and after; only
  running it showed the difference.

  Adversarial review then found the lock **did not fail closed**, contrary to
  what both `deploy/Caddyfile` and `oauth-sidecar/src/client-ip.ts` asserted.
  With the secret unset the matcher compared against `""`, which an
  empty-valued header satisfies — measured: no header 403, junk 403, header
  sent empty **admitted**. Pre-existing, and in scope because the
  `cf-connecting-ip` trust model rests on that property and the redaction made
  the bypass log byte-identically to a legitimate request.

- The sweep-lock test measures shape rather than throughput (#106). CI went red
  with "only 4 writes landed during a 443 ms sweep" — an assertion that counted
  writes per unit time measures the runner as much as the lock. Now counts
  writes whose *completion* falls inside the sweep window: categorical, not a
  rate.

---

## 0.3.1 — 2026-09-13

- Stats page prose cut 394 → 225 words with every load-bearing fact kept (#104).
  The cut broke `stats_distinguishes_backoff_from_a_watermark_pause`, and the
  break was correct — that test had never verified its own name. `test_state`
  leaves `schedulers_enabled` false, so every render reported "off"; both
  assertions passed anyway because `contains("running")` matched inside "the
  poller is not running on this instance" and `contains("paused")` matched the
  static prose rather than the rendered row. Verified by mutation: deleting the
  `watermark_paused` arm now fails the test, which it did not before.

- README backend guidance and costs corrected after 0.3.0 shipped (#103).
