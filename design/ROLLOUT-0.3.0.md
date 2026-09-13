# 0.3.0 rollout plan

Prod is **0.2.8 on the sidecar backend** (`curl https://feather-reader.com/health`
→ `ok featherreader/0.2.8`, checked 2026-09-13). `main` is 76 commits behind this
branch. `Cargo.toml` and `Cargo.lock` are both already at `0.3.0`.

This is the largest release the project has shipped: Tier 1–4 of the review
backlog plus three cold-review rounds. It is therefore split into **three
separately-revertible deploys** rather than one. Companion to the wiki runbook
`/runbooks/featherreader-deploy` — that page is the steady-state loop, this is
the plan for this particular release.

---

## Rollback digests

Resolved from GHCR 2026-09-13 and verified: the `v0.2.6` row matches the wiki's
recorded digest exactly.

| Version | Digest |
|---|---|
| `v0.2.8` (**live**) | `sha256:fae4710dd595b37fdc6b813c62995ec8ca2f1785ef4a509691ef8b849f902481` |
| `v0.2.7` | `sha256:1ee77065fdbd4ec104298f0ca572aa44e375361091744cb6b0cdf53e5ed9dc9f` |
| `v0.2.6` | `sha256:636e8e1dd190e96c620a803e72a4d496a385df8cc1177e437ad6aecf957c105b` |

> **The runbook's digest-resolution command returns EMPTY for these images.** Step
> 5c sends `Accept: application/vnd.oci.image.index.v1+json` only. These are
> single-arch **OCI image manifests**, not indexes, so GHCR does not match that
> media type and the `docker-content-digest` header never arrives — `$digest`
> comes back empty and the `fly deploy -i ...@` that follows is malformed. This is
> the same empty-result trap the runbook warns about two paragraphs earlier, now
> living inside the recommended command. Send all four media types:
>
> ```bash
> ACC="application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
> tok=$(curl -s "https://ghcr.io/token?scope=repository:justin-stanley/feather-reader:pull" \
>   | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
> digest=$(curl -sI -H "Authorization: Bearer $tok" -H "Accept: $ACC" \
>   "https://ghcr.io/v2/justin-stanley/feather-reader/manifests/0.3.0" \
>   | grep -i '^docker-content-digest:' | tr -d '\r' | awk '{print $2}')
> [ -n "$digest" ] || { echo "EMPTY DIGEST — do not deploy"; exit 1; }
> ```
>
> Note the non-empty guard. An unchecked empty digest is the failure mode worth
> engineering against here, because it fails *after* the attestation gate has
> already been passed on a different string.

---

## Blockers

**None outstanding.** The one that was open — `login::complete` having no tests —
is cleared; see Stage 3.

**Cleared 2026-09-13:**

- `flyctl` is authenticated, and the machine is `started` with its check passing.
- `gh attestation verify` works — a dry run against the live 0.2.8 digest returns
  exit 0, so the fail-closed gate is functional before we need it.
- **The Cloudflare origin lock is LIVE.** The wiki lists this as the one remaining
  pre-launch gate, unchecked, and an earlier version of this document repeated
  that. Measured instead:

  | path | direct `featherreader.fly.dev` | via `feather-reader.com` |
  |---|---|---|
  | `/about` | **403** | 200 |
  | `/stats` | **403** | — |
  | `/health` | 200 | 200 |

  `/health` answering directly is correct, not a leak — it is the single
  documented exemption, because Fly's own check must reach it without transiting
  Cloudflare. So `FEATHERREADER_TRUSTED_IP_HEADER = "cf-connecting-ip"` rests on
  something real, and 0.3.0's rate limiter can trust it. `FEATHERREADER_ORIGIN_SECRET`
  is set as a Fly secret, which is the mechanism. **The wiki's step-10 checkbox
  should be ticked.**

---

## Stage 1 — ship 0.3.0 on the sidecar backend

**No OAuth change.** `fly.toml` keeps `FEATHERREADER_REPO_BACKEND = "sidecar"`, so
this deploy carries the Tier 1–4 and review-round fixes and nothing else. Verified
safe: `config.rs:672` gates `FEATHERREADER_OAUTH_ENCRYPTION_KEY` on the rust
backend only, and `config::tests::the_sidecar_backend_boots_without_an_oauth_encryption_key`
pins it. The key does **not** need to be set for this stage.

1. Cut the release PR from an isolated clone, squash-merge to `main` (5 checks).
2. `git tag -a v0.3.0 -m "Release v0.3.0" && git push origin v0.3.0`
3. Resolve the digest with the **corrected** command above; refuse on empty.
4. `gh attestation verify "oci://ghcr.io/justin-stanley/feather-reader@${digest}" --repo justin-stanley/feather-reader` — fail closed.
5. `flyctl deploy -c fly.toml -i "ghcr.io/justin-stanley/feather-reader@${digest}" -a featherreader --ha=false`

### First-boot effects on the prod volume

Additive only, all `IF NOT EXISTS`: two new tables (`repo_timing`,
`repo_timing_total`) and two new indexes. The one with a build cost is
`idx_entry_state_entry_id` over the existing `entry_state` table — it is the index
the retention rewrite probes, so it is required, but expect the first boot to be
slower than usual while it builds.

`fly.toml` also changes `kill_timeout` 5s → 45s and `auto_start_machines`
false → **true**. The second is a deliberate, documented trade (see the fly.toml
comment): it means anyone who can reach `featherreader.fly.dev` can force a
machine start, which is another reason the origin lock matters.

### Gate

```bash
curl -s https://feather-reader.com/health     # must report 0.3.0
curl -s https://feather-reader.com/about -o /dev/null -w '%{http_code}\n'
```

`/health`'s body is **richer in 0.3.0** than the `ok featherreader/0.2.8` string
above — it now also reports uptime, the poll heartbeat, the watermark state and
the live OAuth backend. The first token is still the state. Match `^ok`, and note
that `unknown` is a real third state at boot and is **not** a failure.

**Watch for 30–90 minutes before Stage 2.** The background loops are staggered
30/45/60/90 s and the relay probe 5 min, so the first retention sweep and the
first reclaim happen after the deploy gate passes, not during it. The retention
sweep is the single most behaviour-changed path in this release.

**Rollback:** redeploy the `v0.2.8` digest. The new tables and indexes are
additive and 0.2.8 ignores them, so rollback is clean.

---

## Stage 2 — the one-time auto_vacuum migration

The prod database predates 0.3.0, so it is in SQLite's default `auto_vacuum=NONE`,
where freed pages are never returned and the file only grows. Databases created
from 0.3.0 on are already `INCREMENTAL`.

**Confirmed by measurement, not inferred from the version.** SQLite header offset
52 (largest root b-tree page, big-endian) reads `0 0 0 0` on the live file, and
that field is non-zero if and only if auto-vacuum or incremental-vacuum is on:

```
$ fly ssh console -a featherreader -C "od -An -tu1 -j52 -N4 /data/featherreader.db"
   0   0   0   0
```

(Read offset 52 **big-endian**; an earlier attempt at this in a different context
read it little-endian and drew the opposite conclusion.)

**The migration is low-risk here.** The live database is 21 MB with 879 MB free on
the 1 GB volume, so the full VACUUM's "needs free space roughly equal to the live
file" requirement is met roughly forty times over:

```
/dev/vdc  974M  29M  879M  4% /data
-rw-r--r-- 1 app app 21815296 featherreader.db
-rw-r--r-- 1 app app  4177712 featherreader.db-wal
```

**Run this only after Stage 1 has soaked**, with the 0.3.0 image deployed — the
runbook requires the migration run from the same image version that is live, and
`--migrate-auto-vacuum` is new in this release.

```bash
fly ssh console -C "/app/featherreader --migrate-auto-vacuum"
```

**Run it with the app stopped.** The full VACUUM holds an exclusive lock for
minutes and the app's `busy_timeout` is 5 s, so writes do not queue, they **fail**:
mark-read and star return errors and OAuth session writes fail, so **logins break**
for the duration. `/health` keeps returning 200 throughout, because its probe is a
read — do not use it to decide the migration is done.

It needs free disk roughly equal to the live database. It refuses itself if the
headroom is not there, and exits 0 doing nothing if already migrated, so it is
safe to run blindly. Check the volume first:

```bash
fly ssh console -C "df -h /data"
fly ssh console -C "ls -l /data/featherreader.db"
```

---

## Stage 3 — the backend cutover (sidecar → rust)

**This is the risky one and it is separately revertible. Do not combine it with
Stage 1.**

### CLEARED: the login path had no tests, and now has them

`src/oauth/login.rs` contained exactly two tests and **neither called `complete`**
— the function that performs the authorization-code exchange. It is reachable only
on the rust backend (`web.rs:3449` gates it on `repo_backend`), so it was dormant
in production, but flipping to `rust` makes it every user's login path.

Seven guards could each be deleted with the entire suite green. All seven now fail
on that same mutation:

| Guard | Was | Now |
|---|---|---|
| `tokens.sub != pending.did` — server may return tokens for **another account** | 664 pass | **fails** |
| the PKCE verifier actually sent is the pending row's | 664 pass | **fails** |
| the redirect/client-identity check | 664 pass | **fails** |
| token-exchange failure status not parsed as a grant | 664 pass | **fails** |
| PAR failure not parsed as a grant | 664 pass | **fails** |
| the 10-minute `MAX_PENDING_SECS` cap on the pending row | 664 pass | **fails** |
| `jwt.rs` exact segment count, and the algorithm-confusion guard | 664 pass | **fails** |

**Why they were untestable, and what changed.** These guards sit after a network
round trip a test cannot make: discovery requires `https` and the SSRF guard
forbids loopback, so there is nowhere to point a stub. The alternative was a TLS
stub plus an address bypass — two test-only hooks into production networking.
Instead `complete`/`start` now delegate to `token_exchange_params`,
`accept_token_response`, `accept_par_response` and `pending_expiry`, with
behaviour unchanged, including that a response body is still parsed only after its
status is checked. The guards did not move or weaken; they stopped requiring a
live authorization server to observe.

Note this is also why the Stage 4 prod tests could never have covered the gap: a
successful login exercises the happy path, and every guard above fires only
against a hostile or broken authorization server.

**Still thin:** `start` and `complete` have no end-to-end test — nothing drives a
full login. The individual guards are pinned; their *sequencing* is not. A
follow-up wanting that needs the injectable-resolver work this deliberately
avoided.

### It logs every user out

Verified, and **not currently documented anywhere**: nothing under `src/` reads
`SIDECAR_DB`. The Rust backend keeps its own `oauth_session` table inside
`FEATHERREADER_DB`, entirely separate from the sidecar's `/data/oauth-sidecar.db`.
No access token, refresh token or DPoP key carries across the flip, so **every
logged-in reader must sign in again**. `fly.toml` documents forced re-login for
encryption-key *rotation* but says nothing about the cutover itself.

Consequences to decide on before flipping:
- Beta users get an unexplained logout. Worth a heads-up post, or timing the flip
  for low traffic.
- Rolling back to `sidecar` logs everyone out *again*, since the sidecar store is
  the one that went stale in the meantime.
- The published JWKS is served by a different implementation with its own signing
  key. Whether a PDS caches the old JWKS across the flip is **unverified** — treat
  a first-login failure after cutover as possibly this, not as a code bug.

### Both parts must land together

1. `fly secrets set FEATHERREADER_OAUTH_ENCRYPTION_KEY="$(openssl rand -base64 32)"`
   **FIRST.** Flipping without it is an immediate, permanent boot loop —
   `validate_secrets()` refuses to boot, and with `auto_start_machines = true` it
   will retry at request rate. Back the value up where the other homelab secrets
   live *before* deploying; losing it strands every session.
2. Edit `FEATHERREADER_REPO_BACKEND` to `"rust"` in `[env]`, commit, deploy.

It must be `[env]` and not a secret: the container entrypoint reads the same
variable to choose the Caddy OAuth routing (`deploy/caddy-oauth-rust.conf` vs
`deploy/caddy-oauth-sidecar.conf`) and to decide whether to start the Node sidecar
at all. The two routings cannot share `/oauth/callback`, and a mismatch breaks
every login.

**Rollback:** the same edit in reverse. The encryption key can stay set — the
sidecar path never reads it.

---

## Stage 4 — prod tests

These are the two claims that have been unverifiable from a dev box all along,
because both require a real PDS to fetch our client metadata at the real
`client_id` URL. **They can only run after Stage 3.**

| # | Test | Why it needs prod |
|---|---|---|
| 1 | **`private_key_jwt` client authentication** (RFC 7523) | The PDS fetches `https://feather-reader.com/oauth/client-metadata.json` and the JWKS server-side, then verifies our assertion against the published key. Nothing local can stand in for that fetch. |
| 2 | **RFC 7009 revocation** | Justin's PDS advertises `/oauth/revoke`. Exercised by `/account/delete`. Optional in RFC 8414 and the code tolerates it being absent — so absence must not be mistaken for a pass. |
| 3 | **PAR + PKCE + DPoP full login** | The wiki's go-live gate. Manual and Justin-only per runbook step 8. |
| 4 | **The `iss` check (RFC 9207) and mix-up defence** | Already exercised against the live PDS by the `#[ignore]`d `oauth::discovery::live_pds` tests, which now assert `same_issuer`'s specific refusal rather than bare `is_err()`. Re-run post-cutover. |
| 5 | **Subscription write + read-state sync** | Runbook step 8: create a subscription, confirm it writes to the PDS; mark read, confirm the batched `readState` record lands. |

For 1 and 2, record the *evidence*, not the outcome — a login that succeeds does
not by itself prove `private_key_jwt` was the authentication method used, and the
whole point of these tests is to distinguish that. Capture the token-endpoint
request's `client_assertion_type` and the revocation endpoint's response status.
This release has already produced five tests that passed for the wrong reason; a
prod check that only asserts "it worked" would be the sixth.

Never print access tokens, refresh tokens, authorization codes, PKCE verifiers or
DPoP private keys into logs, notes, or this repo.

---

## Follow-ups this plan surfaced

- The wiki runbook's rollback table stops at `v0.2.6` while prod runs `0.2.8`, and
  its release train text calls `v0.2.6` current. Needs `v0.2.7`, `v0.2.8`, `v0.3.0`
  added and the step-5c `Accept` header fixed.
- `fly.toml` should state that the cutover forces a re-login, next to where it
  already says key rotation does.
