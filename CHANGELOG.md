# Changelog

Engineering detail for the 0.3.x line, newest first. Covers everything since
0.3.0, including work that has landed on `main` but is not yet tagged — see
**Unreleased**.

Each entry says what changed, the mechanism, and — where a defect is involved —
how it was established rather than assumed. Several entries record that a test
passed while proving less than its name; those are noted, because the
measurement is the load-bearing part.

Versions are git tags (`vX.Y.Z`). A tag publishes to crates.io and ghcr.io;
deploying is separate.

---

## Unreleased

Seven PRs on `main` since the `v0.3.6` tag. No features, no schema change, no
`fly.toml` change. One config change — the Caddy log filter — which is baked into
the image and so takes effect at the next build and deploy, not on the running
machine.

Production still runs **0.3.4** as of the v0.3.6 deploy on 2026-09-20; none of
this is live until a tag is cut and deployed.

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
