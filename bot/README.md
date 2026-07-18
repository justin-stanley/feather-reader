# FeatherReader follow→invite bot

A small always-on poller that turns a **follow of `@feather-reader.com`** into a
**public claim-link skeet** for the FeatherReader closed beta.

Every ~5 minutes it:

1. logs in to the account's **own PDS** (`pds.justin-stanley.com`) with a
   dedicated app password,
2. fetches `app.bsky.graph.getFollowers(actor="feather-reader.com")`, newest
   first, and diffs against a local SQLite `handled(did)` store,
3. for each **new** follower: records intent first (crash-safe, keyed on DID) →
   calls the app's `POST /bot/claims` to mint a claim link → posts a **public**
   skeet mentioning the follower (a real `@`-mention facet, so they're notified)
   with a rotating warm message + the claim URL.

Delivery is a **public post, never a DM**, and the post carries the claim **link**
— never the raw `FEATHER-…` code.

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
  (== the app's `FEATHERREADER_BOT_SECRET`). Mints an `active` invite code with a
  long TTL (`FEATHERREADER_CLAIM_TTL_SECS`, default 14d) and returns
  `{ "code", "token", "url" }`. Cap-aware: returns `409 {"error":"full"}` when
  `beta_access + outstanding active codes >= FEATHERREADER_BETA_CAP`. Returns
  `503` when `FEATHERREADER_BOT_SECRET` is unset (endpoint disabled).
- **`GET /claim?t=<token>`** — the public claim link. The token wraps the invite
  code (HMAC-signed; the raw code is never in the URL). On a still-redeemable code
  it sets the reserving `fr_invite` cookie and redirects to `/login`, so the
  visitor flows through OAuth exactly like a pasted invite and the callback
  atomically consumes the code.

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
| `BOT_STATE_DB`               | bot host env | no | `invite-bot.db` | Local SQLite idempotency store. |
| `BOT_POLL_INTERVAL_SECS`     | bot host env | no | `300` | Poll cadence. |
| `BOT_MAX_PER_CYCLE`          | bot host env | no | `10` | Max new followers processed per cycle (blunts a follow spike). |
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

- **Public-link grabbability.** The claim token is in a public URL. The code it
  wraps is single-use (consumed at OAuth redeem) and `/claim` re-checks
  active/unexpired/seat-free, so a replayed link past the first successful claim
  is refused — but within the live window whoever completes OAuth first wins the
  seat. The app rate-limits `/claim` per-IP.
- **Public-mention timeline noise.** Every new follower produces a public skeet.
  The rotating copy reduces the "spam" read, but a follow spike is still visible.
  `BOT_MAX_PER_CYCLE` caps the burst.
- **Cap / waitlist UX.** When the app signals `full`, the bot records the follower
  as `waitlisted` (a persisted, non-terminal row) and retries the mint on later
  cycles once seats free up. There is no explicit "you're waitlisted" post today
  (silent retry); operators can enumerate pending followers by querying the state
  DB for `status='waitlisted'`.
- **Cap self-starvation (by design).** `POST /bot/claims` counts
  `beta_access + outstanding active codes` against the cap, so unredeemed claim
  codes (14-day TTL) hold seats and can make the endpoint report `full` before all
  real seats are used. This is the intended conservative trade-off (never promise a
  seat that won't exist) — raise `FEATHERREADER_BETA_CAP` or shorten
  `FEATHERREADER_CLAIM_TTL_SECS` if outstanding codes starve the pipeline.
- **Interrupted delivery resumes, never double-mints.** The minted code+URL is
  persisted on the follower's row BEFORE the skeet is posted, and a `minting` row
  is non-terminal, so a crash/failure between mint and post is resumed on the next
  cycle by re-posting the SAME code (not minting a second one that would strand).
- **Self-hosted-PDS posting.** The posting path targets the account's own PDS;
  smoke-test `createSession` + `createRecord` against `pds.justin-stanley.com`
  before the first run.
