# FeatherReader follow→invite bot

A small always-on poller that turns a **follow of `@feather-reader.com`** into a
**public claim-link skeet** for the FeatherReader closed beta.

Every ~5 minutes it (reusing one long-lived PDS session across cycles):

1. logs in to the account's **own PDS** (`pds.justin-stanley.com`) with a
   dedicated app password ONCE, then reuses/refreshes that session,
2. fetches `app.bsky.graph.getFollowers(actor="feather-reader.com")`, newest
   first, and diffs against a local SQLite `handled(did)` store,
3. for each **new** follower: records intent first (crash-safe, keyed on DID) →
   calls the app's `POST /bot/claims` (passing the follower DID, so the app is the
   authoritative deduper) →
   - **seat available** → posts a **public** skeet mentioning the follower with a
     rotating warm message + the claim URL,
   - **beta full** → posts a **one-time public waitlist-welcome** (mention, no
     link) and retries the mint on later cycles until a seat frees, then posts the
     claim link,
   - **already seated** → posts nothing,
4. then **retries any waitlisted followers** directly from the store (independent
   of follower paging), so a follower who scrolled off the recent pages isn't
   stranded.

Delivery is a **public post, never a DM**. A claim post carries the claim **link**
(never the raw `FEATHER-…` code); a waitlist-welcome carries no link. Posts within a
cycle are spaced by a jittered 30–60s to avoid a burst pattern.

This crate is **standalone** — deliberately NOT part of the app's Cargo build (the
repo root has no `[workspace]`; this dir is its own workspace root). That keeps the
app's `Cargo.lock` and its `cargo deny` / `cargo audit` CI gates free of the bot's
dependency tree. Build/test it on its own:

```sh
cd bot
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

## The claim flow (app side)

The bot depends on two routes added to the app (`src/web.rs`):

- **`POST /bot/claims`** — shared-secret mint. Auth is `X-Bot-Secret: <secret>`
  (== the app's `FEATHERREADER_BOT_SECRET`). The JSON body carries the follower
  `{ "did", "handle" }`, which makes the APP the authoritative per-DID deduper (so
  a bot-host state loss can't re-mint / re-post). It returns
  `{ "status", "code", "token", "url" }` where `status` is:
  - `"minted"` — a fresh `active` invite code (long TTL,
    `FEATHERREADER_CLAIM_TTL_SECS`, default 14d) recorded FOR that DID — post the
    claim link;
  - `"existing"` — this DID already had an outstanding active claim; the SAME
    `code`/`token`/`url` is returned (idempotent — never a second mint);
  - `"already_seated"` — this DID already holds a beta seat; `code`/`token`/`url`
    are empty and the bot posts NOTHING.

  Cap-aware: returns `409 {"error":"full"}` when
  `beta_access + outstanding active codes >= FEATHERREADER_BETA_CAP` (the cap-count
  queries FAIL CLOSED — a DB error is a `500`, never a silent mint past the cap).
  Returns `503` when `FEATHERREADER_BOT_SECRET` is unset (endpoint disabled).
- **`GET /claim?t=<token>`** — the public claim link. The token is
  `b64url(code).<sig>` — the code half is **trivially decodable** (base64, no
  secret), so it is NOT confidential; the security is **single-use + HMAC integrity
  + per-IP rate-limit**, not secrecy of the code. On a still-redeemable code it sets
  the reserving `fr_invite` cookie and redirects to `/login`, so the visitor flows
  through OAuth exactly like a pasted invite and the callback atomically consumes
  the code.

> **Rotating `FEATHERREADER_COOKIE_SECRET` invalidates every outstanding claim
> link.** The claim token's HMAC keys on the app's cookie secret, so rotating it
> makes all previously-minted `/claim?t=…` links fail signature verification (they
> bounce to the invite page). Re-mint after a rotation.

## Configuration / secrets

All config is env-driven; **secrets are Vaultwarden-injected at runtime, never
baked** into an image or committed.

| Variable                     | Where set | Required | Default | Meaning |
|------------------------------|-----------|----------|---------|---------|
| `BOT_APP_PASSWORD`           | bot host env (Vaultwarden) | **yes** | — | Dedicated atproto **app password** with **write** scope for `@feather-reader.com`. NOT the primary account password. |
| `FEATHERREADER_BOT_SECRET`   | bot host env (Vaultwarden) **and** the app as a Fly secret | **yes** | — | Shared bearer for `POST /bot/claims`. Must match the app's value exactly. |
| `BOT_PDS_HOST`               | bot host env | no | `https://pds.justin-stanley.com` | The account's **own PDS**. Every XRPC call targets it (self-hosted-PDS safe). |
| `BOT_HANDLE`                 | bot host env | no | `feather-reader.com` | Login identifier + `getFollowers` actor. |
| `BOT_DID`                    | bot host env | no | `did:plc:cxauapbtkbmf7b24e5icd32j` | Account DID (createRecord repo + skip-self). |
| `FEATHERREADER_APP_BASE`     | bot host env | no | `https://feather-reader.com` | App base URL the bot mints against. |
| `BOT_STATE_DB`               | bot host env | no | `invite-bot.db` | Local SQLite idempotency store. **MUST be an ABSOLUTE path on a PERSISTENT volume in production** — a relative or ephemeral (`/tmp/…`) path means a restart re-processes every follower (the app-side per-DID idempotency is the backstop, but a lost store still causes needless re-posting/churn). The bot logs a loud warning if the path is relative or under a temp dir. |
| `BOT_POLL_INTERVAL_SECS`     | bot host env | no | `300` | Poll cadence. |
| `BOT_MAX_PER_CYCLE`          | bot host env | no | `10` | Max followers processed per cycle — new + waitlist-retries combined (blunts a follow spike). |
| `BOT_MAX_DAILY_MINTS`        | bot host env | no | `50` | Global daily budget on FRESH claim mints across ALL cycles (sybil brake). Over budget, followers are deferred to the waitlist; idempotent re-posts / waitlist-welcomes don't count. |
| `RUST_LOG`                   | bot host env | no | `info` | Tracing filter. |

On the **app** side, set the shared secret as a Fly secret (see `fly.toml`):

```sh
fly secrets set FEATHERREADER_BOT_SECRET="$(openssl rand -base64 48)"
# optional: fly secrets set FEATHERREADER_CLAIM_TTL_SECS="1209600"
```

The **app password** must be created in the account's PDS settings with the
**"Allow access to ..."** write scope; a read-only app password can't post.

## Where it runs

An always-on poller belongs on the homelab (the apps VM or the ci VM) as a small
systemd/Docker service with Vaultwarden-injected env, tailnet egress to Bluesky +
to the app's `/bot/claims`. It is NOT co-located with the Fly app.

## Open risks

- **Public-link grabbability.** The claim token is in a public URL and the code it
  wraps is only base64-obscured (NOT confidential — see the claim-flow section). It
  is single-use (consumed at OAuth redeem) and `/claim` re-checks
  active/unexpired/seat-free, so a replayed link past the first successful claim
  is refused — but within the live window whoever completes OAuth first wins the
  seat. The app rate-limits `/claim` per-IP.
- **Sybil / follow-farming.** Delivery is triggered by a FOLLOW, so a flood of
  throwaway accounts could try to drain beta seats. Defenses: the global daily mint
  budget (`BOT_MAX_DAILY_MINTS`, default 50) caps fresh mints across all cycles so a
  one-day flood can't empty the beta; the per-cycle cap (`BOT_MAX_PER_CYCLE`) blunts
  bursts; the app's hard `FEATHERREADER_BETA_CAP` is the ultimate ceiling; and
  per-DID idempotency means unfollow→refollow never re-mints. A cheap account-age /
  has-posts heuristic on the follower is a possible future add (NOT implemented —
  the daily budget is the primary brake).
- **Public-mention timeline noise.** Every new follower produces a public skeet
  (a claim link, or a one-time waitlist-welcome when full). The rotating copy
  reduces the "spam" read; posts are spaced by a jittered 30–60s within a cycle to
  avoid the burst pattern spam-mod flags, and `BOT_MAX_PER_CYCLE` caps the burst.
- **Cap / waitlist UX.** When the app signals `full`, the bot posts a ONE-TIME
  public "you're on the waitlist" skeet (mention, no link — tracked by a `welcomed`
  flag so a long-waitlisted follower isn't re-welcomed every cycle), records the
  follower as `waitlisted` (persisted, non-terminal), and RETRIES the mint every
  cycle — enumerated directly from the store (`status='waitlisted'`), independent of
  whether the follower is still on the first pages of `getFollowers`. When a seat
  frees, the retry mints and posts the claim link — so a follower may receive two
  posts over time (waitlist-welcome, then the claim). Operators can list pending
  followers by querying the state DB for `status='waitlisted'`.
- **Cap self-starvation (by design).** `POST /bot/claims` counts
  `beta_access + outstanding active codes` against the cap, so unredeemed claim
  codes (14-day TTL) hold seats and can make the endpoint report `full` before all
  real seats are used. This is the intended conservative trade-off (never promise a
  seat that won't exist) — raise `FEATHERREADER_BETA_CAP` or shorten
  `FEATHERREADER_CLAIM_TTL_SECS` if outstanding codes starve the pipeline.
- **Interrupted delivery resumes, never double-mints / double-posts.** The minted
  code+URL is persisted on the follower's row BEFORE the skeet is posted, and a
  `minting` row is non-terminal, so a crash between mint and post is resumed by
  re-posting the SAME code. The public post's rkey is DETERMINISTIC in the follower
  DID + post-kind (claim vs waitlist), so a post-then-crash retry re-issues the same
  rkey; the PDS answers "record already exists", which the bot treats as delivered
  (never a duplicate skeet). The claim and waitlist posts get distinct rkeys, so a
  follower can receive both over time without collision. The app's per-DID
  idempotency is the authoritative backstop even if the local store is lost.
- **Session reuse (login rate limit).** A PDS rate-limits `createSession` to
  ~300/day/account; the bot logs in ONCE and reuses the session, refreshing the
  access token via `refreshSession` on a 401 and only re-creating the session if the
  refresh itself fails — so a 5-min poll cadence doesn't exhaust the login budget.
- **Self-hosted-PDS posting.** The posting path targets the account's own PDS;
  smoke-test `createSession` + `createRecord` against `pds.justin-stanley.com`
  before the first run.
