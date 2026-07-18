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
use crate::atproto::Session;
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

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(err) = run_cycle(&config, &store, &http, &app).await {
                    // A cycle failure (login blip, PDS 5xx) must not kill the bot;
                    // log and retry next tick.
                    error!(%err, "poll cycle failed; will retry next interval");
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

/// One poll cycle: log in, page followers newest-first, process the new ones.
async fn run_cycle(
    config: &Config,
    store: &Store,
    http: &reqwest::Client,
    app: &AppClient,
) -> Result<()> {
    let session = Session::login(
        http.clone(),
        &config.pds_host,
        &config.handle,
        &config.app_password,
    )
    .await
    .context("logging in to the account PDS")?;

    if session.did() != config.did {
        warn!(
            logged_in = %session.did(),
            configured = %config.did,
            "logged-in DID differs from BOT_DID; continuing with the logged-in DID"
        );
    }

    // Collect NEW followers newest-first, stopping once we hit a handled DID.
    // getFollowers ordering isn't strictly guaranteed monotonic, so we don't
    // break the WHOLE scan on the first handled DID — we scan a bounded number of
    // pages and let the handled-set filter. But the common case (a handled DID
    // near the top) short-circuits cheaply.
    let mut new_followers: Vec<atproto::Follower> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    const MAX_PAGES: usize = 3;
    'paging: loop {
        let (page, next) = session
            .get_followers(&config.handle, 100, cursor.as_deref())
            .await
            .context("fetching followers page")?;
        let mut hit_handled = false;
        for f in page {
            // A DID in a TERMINAL state (delivered/skipped) is caught up. A DID
            // stuck in `minting` (an interrupted mint/post) is NOT terminal, so it
            // is collected again and RESUMED by handle_follower rather than
            // stranded — the crash-safe-resume guarantee.
            if store.is_terminal(&f.did)? {
                hit_handled = true;
                continue;
            }
            new_followers.push(f);
        }
        pages += 1;
        // Stop paging once a page was fully handled (caught up) or we hit the
        // page/collect bounds.
        if hit_handled || next.is_none() || pages >= MAX_PAGES {
            break 'paging;
        }
        cursor = next;
    }

    if new_followers.is_empty() {
        info!("no new followers this cycle");
        return Ok(());
    }

    // Oldest-first among the new ones so a spike is processed in follow order, and
    // cap the per-cycle count to blunt a follow flood.
    new_followers.reverse();
    let take = new_followers.len().min(config.max_per_cycle);
    info!(
        new = new_followers.len(),
        processing = take,
        "new followers detected"
    );

    for f in new_followers.into_iter().take(take) {
        if let Err(err) = handle_follower(config, store, &session, app, &f).await {
            // One follower failing (e.g. their post 400s) must not abort the batch.
            warn!(did = %f.did, %err, "failed to handle follower; leaving as minting for retry");
        }
    }
    Ok(())
}

/// Process one new (or resumed) follower: intent → mint → post.
///
/// Crash-safe on the DID: intent is recorded before any side effect, the minted
/// code is persisted before posting, and a `delivered` row is never re-processed.
/// If a prior run minted a code but the post failed, this RESUMES from the stored
/// code (re-posting) instead of minting a second one — so an interrupted follower
/// is completed, never stranded, and never double-minted.
async fn handle_follower(
    config: &Config,
    store: &Store,
    session: &Session,
    app: &AppClient,
    follower: &atproto::Follower,
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
    // mint but not the post), re-use it. Otherwise mint a fresh one (cap-aware).
    let (code, url) = match store.resume_claim(&follower.did)? {
        Some(pair) => {
            info!(%handle, "resuming a previously-minted claim (re-posting)");
            pair
        }
        None => match mint(app, store, &follower.did, handle).await? {
            Some(pair) => pair,
            None => return Ok(()), // full → waitlisted
        },
    };

    // Post the public claim skeet with a rotating message + mention facet.
    let post = messages::render_random(handle, &url);
    let post_uri = session
        .post_with_mention(&post, &follower.did)
        .await
        .context("posting claim skeet")?;
    store.mark_delivered(&follower.did, &code, &url, &post_uri)?;
    info!(%handle, %post_uri, "posted claim link");
    Ok(())
}

/// Mint a claim for `did` (cap-aware) and persist the code+url on the row BEFORE
/// returning, so a subsequent post failure resumes from the stored code rather
/// than minting again. Returns `None` when the app signals the beta is full — the
/// DID's row is marked `waitlisted` (non-terminal), so a later cycle retries the
/// mint once seats free up.
async fn mint(
    app: &AppClient,
    store: &Store,
    did: &str,
    handle: &str,
) -> Result<Option<(String, String)>> {
    match app.mint_claim().await? {
        MintOutcome::Full => {
            // Persist a WAITLISTED row (non-terminal). The poll loop keeps seeing
            // this DID as needing work and retries the mint on later cycles once
            // seats free up; the persisted row also lets an operator enumerate who
            // is pending on capacity.
            info!(%handle, "beta full; waitlisting follower for a later cycle");
            store.mark_status(did, Some(handle), Status::Waitlisted)?;
            Ok(None)
        }
        MintOutcome::Claim(claim) => {
            // Persist BEFORE posting so an interrupted post never strands the code.
            store.record_minted_code(did, &claim.code, &claim.url)?;
            Ok(Some((claim.code, claim.url)))
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();
}
