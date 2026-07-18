//! FeatherReader follow→invite bot.
//!
//! Every ~5 minutes: fetch `@feather-reader.com`'s followers, diff against a
//! local handled-DID store, and for each NEW follower:
//!   1. record intent FIRST (crash-safe idempotency, keyed on DID),
//!   2. call the app's `POST /bot/claims` to mint a claim link (cap-aware),
//!   3. post a PUBLIC skeet mentioning the follower with a rotating message +
//!      the claim URL (a real `@`-mention facet, so they're notified).
//!
//! Delivery is a PUBLIC POST (Justin's decision), never a DM, and the post
//! carries the claim LINK, never the raw code.

mod app;
mod atproto;
mod config;
mod messages;
mod store;

use anyhow::{Context, Result};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::app::{AppClient, MintOutcome};
use crate::atproto::{PostKind, Session};
use crate::config::Config;
use crate::store::{Status, Store};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let config = Config::from_env().context("loading bot configuration")?;
    info!(
        handle = %config.handle,
        pds = %config.pds_host,
        app = %config.app_base,
        interval_secs = config.poll_interval_secs,
        "starting feather-reader invite bot"
    );

    let store = Store::open(&config.state_db).context("opening bot state db")?;
    let http = reqwest::Client::builder()
        .user_agent(concat!(
            "feather-reader-invite-bot/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .context("building HTTP client")?;
    let app = AppClient::new(http.clone(), &config.app_base, &config.bot_secret);

    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(config.poll_interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Create the PDS session ONCE and reuse it across cycles (the session refreshes
    // its own access token on expiry). A PDS rate-limits `createSession` to
    // ~300/day/account, so logging in every 5-min cycle would burn ~96% of that
    // budget; a single long-lived session avoids it. If the session ever fails
    // hard, the next cycle re-creates it.
    let mut session: Option<Session> = None;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if session.is_none() {
                    match Session::login(
                        http.clone(),
                        &config.pds_host,
                        &config.handle,
                        &config.app_password,
                    )
                    .await
                    {
                        Ok(s) => {
                            if s.did() != config.did {
                                warn!(
                                    logged_in = %s.did(),
                                    configured = %config.did,
                                    "logged-in DID differs from BOT_DID; continuing with the logged-in DID"
                                );
                            }
                            session = Some(s);
                        }
                        Err(err) => {
                            error!(%err, "login failed; will retry next interval");
                            continue;
                        }
                    }
                }
                let sess = session.as_ref().expect("session set above");
                if let Err(err) = run_cycle(&config, &store, sess, &app).await {
                    // A cycle failure (PDS 5xx, a follower's post 400) must not kill
                    // the bot; log and retry next tick. Only DROP the session (forcing
                    // a fresh createSession next cycle) on an AUTH-shaped failure —
                    // the Session already self-refreshes on a 401, so a flaky
                    // getFollowers/createRecord 5xx should NOT burn a login. (Nit:
                    // indiscriminate session-nulling put needless pressure on the
                    // ~300/day createSession budget.)
                    if is_auth_failure(&err) {
                        error!(%err, "poll cycle failed (auth); re-authenticating next interval");
                        session = None;
                    } else {
                        error!(%err, "poll cycle failed (transient); keeping session, retry next interval");
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received; exiting");
                break;
            }
        }
    }
    Ok(())
}

/// One poll cycle: page followers newest-first, process the new ones, THEN retry
/// any waitlisted followers (independent of paging). Uses the reused `session`.
async fn run_cycle(
    config: &Config,
    store: &Store,
    session: &Session,
    app: &AppClient,
) -> Result<()> {
    // Collect NEW followers newest-first, stopping once we hit a handled DID.
    // getFollowers ordering isn't strictly guaranteed monotonic, so we don't
    // break the WHOLE scan on the first handled DID — we scan a bounded number of
    // pages and let the handled-set filter. But the common case (a handled DID
    // near the top) short-circuits cheaply.
    let mut new_followers: Vec<atproto::Follower> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    // S5 — on the FIRST run (empty state DB) page the FULL follower history so an
    // existing backlog beyond the newest ~300 is reached and backfilled; the
    // steady-state cap (`MAX_PAGES` × 100) is fine thereafter because a handled DID
    // near the top short-circuits paging. `FIRST_RUN_MAX_PAGES` is a generous safety
    // bound so a pathological account can't page unbounded. (Per-cycle post volume
    // is still capped by `max_per_cycle` — the backfill only COLLECTS here; it
    // doesn't post them all at once.)
    let first_run = store.is_empty().context("checking first-run state")?;
    const MAX_PAGES: usize = 3;
    const FIRST_RUN_MAX_PAGES: usize = 500; // up to ~50k followers on a cold start
    let max_pages = if first_run {
        info!("first run (empty state db): full-history follower backfill");
        FIRST_RUN_MAX_PAGES
    } else {
        MAX_PAGES
    };
    'paging: loop {
        let (page, next) = session
            .get_followers(&config.handle, 100, cursor.as_deref())
            .await
            .context("fetching followers page")?;
        let mut hit_handled = false;
        for f in page {
            // A DID in a TERMINAL state (delivered/skipped) is caught up. A DID
            // stuck in `minting` (an interrupted mint/post) or `waitlisted` is NOT
            // terminal — the former is RESUMED by handle_follower, the latter is
            // retried below (and here if re-seen), so neither is stranded.
            if store.is_terminal(&f.did)? {
                hit_handled = true;
                continue;
            }
            new_followers.push(f);
        }
        pages += 1;
        // Stop paging once a page was fully handled (caught up) or we hit the
        // page/collect bounds. On a first-run backfill, `hit_handled` is never true
        // (the store is empty) so paging continues to `next.is_none()` (the true end
        // of the follower list) or the generous `FIRST_RUN_MAX_PAGES` safety bound.
        if hit_handled || next.is_none() || pages >= max_pages {
            break 'paging;
        }
        cursor = next;
    }

    // Oldest-first among the new ones so a spike is processed in follow order, and
    // cap the per-cycle count to blunt a follow flood.
    new_followers.reverse();
    let take = new_followers.len().min(config.max_per_cycle);
    if !new_followers.is_empty() {
        info!(
            new = new_followers.len(),
            processing = take,
            "new followers detected"
        );
    } else {
        info!("no new followers this cycle");
    }

    // How many posts we've emitted this cycle — used to jitter-sleep BETWEEN posts
    // (not before the first), so a batch doesn't burst all at once (S5).
    let mut posts_this_cycle = 0usize;

    for f in new_followers.into_iter().take(take) {
        match handle_follower(config, store, session, app, &f, &mut posts_this_cycle).await {
            Ok(()) => {}
            Err(err) => {
                // One follower failing (e.g. their post 400s) must not abort the batch.
                warn!(did = %f.did, %err, "failed to handle follower; leaving for retry");
            }
        }
    }

    // B2 — retry WAITLISTED followers directly from the store, independent of
    // follower paging: a waitlisted DID that scrolled past MAX_PAGES would
    // otherwise be stranded until re-seen. Safe to call repeatedly now that
    // /bot/claims is idempotent per DID. Bounded by the remaining per-cycle budget.
    let remaining = config.max_per_cycle.saturating_sub(take);
    if remaining > 0 {
        let waitlisted = store
            .waitlisted_dids(remaining)
            .context("enumerating waitlisted followers")?;
        if !waitlisted.is_empty() {
            info!(count = waitlisted.len(), "retrying waitlisted followers");
        }
        for (did, handle) in waitlisted {
            let follower = atproto::Follower { did, handle };
            if let Err(err) = handle_follower(
                config,
                store,
                session,
                app,
                &follower,
                &mut posts_this_cycle,
            )
            .await
            {
                warn!(did = %follower.did, %err, "waitlist retry failed; will retry next cycle");
            }
        }
    }

    Ok(())
}

/// Sleep a jittered 30–60s between posts within a cycle to avoid the burst pattern
/// Bluesky's spam-moderation flags (S5). `posts_this_cycle` is the count of posts
/// ALREADY made this cycle: the first post (count 0) doesn't wait; each subsequent
/// one does. Uses a clock-derived jitter (no `rand`/`getrandom` dep).
async fn jitter_between_posts(posts_this_cycle: usize) {
    if posts_this_cycle == 0 {
        return;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // 30s base + [0, 30)s jitter → 30..60s.
    let jitter_ms = 30_000 + (u64::from(nanos) % 30_000);
    info!(
        delay_ms = jitter_ms,
        "pausing before next post (anti-burst)"
    );
    tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
}

/// Process one new (or resumed / waitlisted) follower: intent → mint → post.
///
/// Crash-safe on the DID: intent is recorded before any side effect, the minted
/// code is persisted before posting, and a `delivered` row is never re-processed.
/// If a prior run minted a code but the post failed, this RESUMES from the stored
/// code (re-posting) instead of minting a second one. The APP is the authoritative
/// deduper (B1): it returns `already_seated` (post nothing) or an `existing` claim
/// (same code) so a bot-store loss cannot re-mint/re-post. When the beta is full,
/// a ONE-TIME public waitlist-welcome is posted, then the follower is retried on
/// later cycles until a seat frees.
///
/// `posts_this_cycle` is incremented on every public post and used to jitter-sleep
/// between posts (S5 anti-burst).
async fn handle_follower(
    config: &Config,
    store: &Store,
    session: &Session,
    app: &AppClient,
    follower: &atproto::Follower,
    posts_this_cycle: &mut usize,
) -> Result<()> {
    // Skip the bot's own account (a self-follow edge).
    if follower.did == config.did || follower.did == session.did() {
        store.mark_status(&follower.did, follower.handle.as_deref(), Status::Skipped)?;
        return Ok(());
    }

    // Record intent FIRST (idempotent on DID). If this DID is already delivered,
    // record_intent is a no-op and status_of tells us to skip.
    store.record_intent(&follower.did, follower.handle.as_deref())?;
    if store.status_of(&follower.did)? == Some(Status::Delivered) {
        return Ok(());
    }

    // A handle is required to render a working @mention. If the follower has no
    // handle (rare), skip rather than post a broken mention.
    let handle = match follower.handle.as_deref() {
        Some(h) if !h.is_empty() && h != "handle.invalid" => h,
        _ => {
            warn!(did = %follower.did, "follower has no usable handle; skipping");
            store.mark_status(&follower.did, None, Status::Skipped)?;
            return Ok(());
        }
    };

    // Resume: if a code was already minted for this DID (a prior run got past the
    // mint but not the post), re-post it. The rkey is deterministic per DID, so a
    // duplicate post is caught server-side and treated as delivered — never a
    // second skeet. Otherwise consult the app (the authoritative deduper).
    let (code, url) = match store.resume_claim(&follower.did)? {
        Some(pair) => {
            info!(%handle, "resuming a previously-minted claim (re-posting)");
            pair
        }
        None => match mint(
            config,
            app,
            store,
            &follower.did,
            handle,
            posts_this_cycle,
            session,
        )
        .await?
        {
            Some(pair) => pair,
            None => return Ok(()), // already_seated, full+welcomed, or budget-deferred
        },
    };

    // Post the public claim skeet with a rotating message + mention facet. The rkey
    // is deterministic (PostKind::Claim + DID), so a post-then-crash retry is
    // deduped server-side rather than double-posting.
    jitter_between_posts(*posts_this_cycle).await;
    let post = messages::render_random(handle, &url);
    let post_uri = session
        .post_with_mention(&post, &follower.did, PostKind::Claim)
        .await
        .context("posting claim skeet")?;
    *posts_this_cycle += 1;
    store.mark_delivered(&follower.did, &code, &url, &post_uri)?;
    info!(%handle, %post_uri, "posted claim link");
    Ok(())
}

/// Ask the app (authoritative deduper) to mint/return a claim for `did`, persisting
/// the code+url on the row BEFORE returning so a later post failure resumes from
/// the stored code rather than re-minting. Returns:
///   * `Some((code, url))` — post the claim link (fresh or app-deduped existing),
///   * `None` — nothing to post (already seated; beta full → waitlist-welcomed;
///     or the local daily mint budget is exhausted → deferred to a later cycle).
#[allow(clippy::too_many_arguments)]
async fn mint(
    config: &Config,
    app: &AppClient,
    store: &Store,
    did: &str,
    handle: &str,
    posts_this_cycle: &mut usize,
    session: &Session,
) -> Result<Option<(String, String)>> {
    // S3 — global daily mint BUDGET (sybil brake). Before requesting a FRESH mint,
    // check the rolling-24h fresh-mint count. Over budget → defer (treat like full:
    // waitlist + one-time welcome) so a follow flood can't drain the beta in a day.
    // (Idempotent existing-claim returns and re-posts don't consume the budget.)
    const DAY_SECS: i64 = 24 * 60 * 60;
    if store.count_mints_since(DAY_SECS)? >= config.max_daily_mints {
        warn!(
            %handle,
            budget = config.max_daily_mints,
            "daily mint budget reached; deferring follower (queue)"
        );
        // S6 — the budget defer is NOT "beta full": use the neutral QUEUE copy so
        // we don't tell a follower the beta is full when it may not be.
        waitlist_and_welcome(
            store,
            session,
            did,
            handle,
            posts_this_cycle,
            DeferReason::Budget,
        )
        .await?;
        return Ok(None);
    }

    match app.mint_claim(did, Some(handle)).await? {
        MintOutcome::AlreadySeated => {
            // The app says this DID already holds a seat (e.g. they redeemed a link
            // out-of-band, or the bot store was lost). Post NOTHING; mark handled.
            info!(%handle, "app reports DID already seated; skipping (no post)");
            store.mark_status(did, Some(handle), Status::Skipped)?;
            Ok(None)
        }
        MintOutcome::Full => {
            // Beta full: post a ONE-TIME public waitlist-welcome, then waitlist for
            // a later retry once seats free up.
            waitlist_and_welcome(
                store,
                session,
                did,
                handle,
                posts_this_cycle,
                DeferReason::Full,
            )
            .await?;
            Ok(None)
        }
        MintOutcome::Minted(claim) => {
            // A genuinely-new seat: count it against the daily budget, persist the
            // code BEFORE posting so an interrupted post never strands it.
            store.record_mint(did)?;
            store.record_minted_code(did, &claim.code, &claim.url)?;
            Ok(Some((claim.code, claim.url)))
        }
        MintOutcome::Existing(claim) => {
            // The app deduped: this DID already had an outstanding claim (the
            // backstop that survives a bot-store loss). Re-post the SAME code; do
            // NOT charge the budget (no new seat was handed out).
            info!(%handle, "app returned an existing outstanding claim; re-posting");
            store.record_minted_code(did, &claim.code, &claim.url)?;
            Ok(Some((claim.code, claim.url)))
        }
    }
}

/// Why a follower is being deferred (which drives the one-time welcome copy, S6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeferReason {
    /// The beta is at capacity (the app returned `full`). Copy: "you're waitlisted".
    Full,
    /// The daily mint BUDGET is exhausted (sybil brake), not necessarily full.
    /// Copy: neutral "you're in the queue" — must NOT claim the beta is full.
    Budget,
}

/// Waitlist a follower and, if not already welcomed, post a ONE-TIME public
/// welcome skeet (mention, no claim link). The `welcomed` flag makes this
/// post-once: a follower who stays waitlisted across many cycles is welcomed only
/// on the first. The welcome post's rkey is deterministic (PostKind::Waitlist +
/// DID) and distinct from the later claim post, so a crash never double-posts and
/// the two never collide. `reason` selects the copy (S6): `Full` → "beta's full,
/// you're waitlisted"; `Budget` → neutral "you're in the queue".
async fn waitlist_and_welcome(
    store: &Store,
    session: &Session,
    did: &str,
    handle: &str,
    posts_this_cycle: &mut usize,
    reason: DeferReason,
) -> Result<()> {
    // Persist the waitlisted row first (non-terminal → retried later cycles).
    store.mark_status(did, Some(handle), Status::Waitlisted)?;

    if store.was_welcomed(did)? {
        return Ok(());
    }
    let post = match reason {
        DeferReason::Full => {
            info!(%handle, "beta full; posting one-time waitlist-welcome");
            messages::render_waitlist_random(handle)
        }
        DeferReason::Budget => {
            info!(%handle, "mint budget paced; posting one-time queue welcome");
            messages::render_queue_random(handle)
        }
    };
    jitter_between_posts(*posts_this_cycle).await;
    let post_uri = session
        .post_with_mention(&post, did, PostKind::Waitlist)
        .await
        .context("posting waitlist-welcome skeet")?;
    *posts_this_cycle += 1;
    // Mark welcomed only AFTER the post succeeds (a failure retries next cycle). The
    // deterministic rkey makes a duplicate a no-op even if the mark is interrupted.
    store.mark_welcomed(did, Some(handle))?;
    info!(%handle, %post_uri, "posted waitlist-welcome");
    Ok(())
}

/// Whether a `run_cycle` error is AUTH-shaped — i.e. the session itself is
/// unusable and a fresh `createSession` is warranted next cycle. The `Session`
/// transparently refreshes its access token on a 401 and, if refresh fails, falls
/// back to a full re-login; it only surfaces an error to us when BOTH the refresh
/// AND that fallback createSession failed (its context strings mention
/// `createSession`/`refreshSession`). A plain getFollowers/createRecord 5xx/4xx is
/// NOT auth-shaped and must not drop the session (which would waste a login from
/// the ~300/day budget). Matches on the anyhow context chain.
fn is_auth_failure(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let m = cause.to_string();
        m.contains("createSession") || m.contains("refreshSession")
    })
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();
}
