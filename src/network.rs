//! Read-only queries against the **public atproto network**.
//!
//! Where [`crate::atproto`] reads and writes *one user's own* PDS repo, this
//! module asks the public relays a single question: **how many repos on the
//! network hold a given collection?** Today that collection is
//! `community.lexicon.rss.subscription`, and the answer is FeatherReader's
//! adoption metric — the one number that says whether the portability claim on
//! every page is being exercised by anybody but us.
//!
//! Three properties are load-bearing, and each is a rule rather than an
//! intention (`design/NETWORK-SPEC.md` §4):
//!
//! 1. **It is never a source of truth.** The result is a projection: drop the
//!    `network_stat` table and the next probe rebuilds it. Nothing in the reader
//!    path reads it, and no reader surface may depend on it.
//! 2. **It counts, it does not collect.** The relay answers with a list of DIDs;
//!    we read `repos.len()` and drop the page. Persisting the DID list would
//!    build a durable register of "accounts that use an RSS reader" on our disk,
//!    for a feature whose entire output is an integer.
//! 3. **The number is a LOWER BOUND, not a census.** Since sync v1.1 relays are
//!    **non-archival**: a relay's index only covers hosts it actually crawls, so
//!    a PDS no relay crawls is invisible to it. Two relays can therefore
//!    disagree; we query every configured host, record each observation
//!    separately, surface the max, and log the disagreement. Any copy derived
//!    from this number must say "at least", never "exactly".
//!
//! **Why the SSRF guard, when the relay host is operator-configured?** Not
//! because the operator is the threat — they can already edit the code. It earns
//! its place for three other reasons. The shared [`reqwest::Client`] has *no*
//! timeouts, so a hung relay would pin a background task forever, while
//! [`crate::net`]'s per-hop pinned client bounds both the total request and the
//! idle read. The shared client also follows up to ten redirects with no
//! re-validation, whereas [`crate::net::guarded_get_no_privacy`] follows at most
//! five and re-checks scheme + resolved IP on each — a relay that `302`s (DNS
//! takeover, a misconfigured proxy, a captive portal on a self-hoster's network)
//! is the realistic rebinding path. And it is the coherent choice: the same
//! milestone that routes `PdsClient::list_records` through the guard should not
//! open a fresh unguarded `http.get()` next door. It is free besides —
//! [`crate::USER_AGENT`] and the body cap come along with it.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, RETRY_AFTER};
use reqwest::StatusCode;
use serde::Deserialize;

use crate::atproto::urlencode;

/// The relay XRPC method that answers "which repos hold this collection?".
pub const LIST_REPOS_BY_COLLECTION: &str = "com.atproto.sync.listReposByCollection";

/// The public Bluesky relays queried by default, in order. Lives here (mirroring
/// [`crate::atproto::DEFAULT_PLC_DIRECTORY`]) so [`crate::config`] imports the
/// network fact rather than re-typing the hostnames.
pub const DEFAULT_RELAY_HOSTS: [&str; 2] =
    ["relay1.us-west.bsky.network", "relay1.us-east.bsky.network"];

/// Repos requested per page. The relay's documented ceiling is 1000; 500 keeps a
/// page body small (~30 KB) while making the whole current network one page.
pub const DEFAULT_PAGE_LIMIT: u32 = 500;

/// Hard cap on pages walked per host: 25 000 repos at [`DEFAULT_PAGE_LIMIT`],
/// i.e. ~25 000× today's network. Hitting it means something went wrong (a
/// cursor loop, a wrong collection) — the run is recorded as `truncated`, so the
/// number reads as "at least N".
pub const MAX_PAGES: usize = 50;

/// Floor for the page limit. This is not defensive decoration: the live relay
/// answers `limit=0` with **one** repo *and* a cursor, so a zero would burn the
/// whole page budget one repo at a time.
const MIN_PAGE_LIMIT: u32 = 1;

/// Ceiling for the page limit (the relay's own maximum).
const MAX_PAGE_LIMIT: u32 = 1000;

/// Politeness delay between pages against one host.
const DEFAULT_PAGE_DELAY: Duration = Duration::from_secs(1);

/// Wall-clock budget for one host's whole walk. [`crate::net`] bounds each *hop*
/// (30 s total, 15 s idle) but nothing bounds the walk: 50 pages × up to 5
/// redirect hops × 30 s plus 49 s of inter-page sleep is a worst case near two
/// hours. This is what keeps a slow relay from leaving a detached task alive
/// across the next daily tick.
///
/// This is a **soft** budget, checked between pages by [`RelayClient::walk_pages`],
/// which stops and returns what it has with `truncated = true`. It is
/// deliberately NOT sized to let the full [`MAX_PAGES`] budget run: 50 pages ×
/// ([`DEFAULT_PAGE_DELAY`] + [`crate::net::FETCH_TIMEOUT`]) is ~26 minutes, far
/// too long to hold a background task for an optional metric. The two limits
/// bound different things — `MAX_PAGES` bounds a *pathological* relay,
/// this bounds a merely *slow* one — and whichever binds first, the result is a
/// recorded lower bound rather than a lost run.
const DEFAULT_HOST_BUDGET: Duration = Duration::from_secs(120);

/// Slack added to [`DEFAULT_HOST_BUDGET`] to form the **hard** deadline that
/// wraps the whole walk.
///
/// The soft budget can only be observed *between* pages, so a request already
/// in flight when it expires still gets its full [`crate::net::FETCH_TIMEOUT`].
/// The hard deadline must therefore sit at least one request beyond the soft
/// one, or it would fire first and throw away the partial count the soft path
/// exists to preserve — which is exactly the bug this replaced: a merely-slow
/// relay produced `TimedOut` and NO observation, every run, forever.
const HARD_DEADLINE_SLACK: Duration = Duration::from_secs(10);

/// How much of a non-2xx body is quoted back in the error (the atproto envelope
/// `{"error","message"}` is short; a hostile body must not fill the log).
const ERROR_SNIPPET_CHARS: usize = 200;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The `com.atproto.sync.listReposByCollection` response envelope.
///
/// Deliberately **not** `deny_unknown_fields`: the same forward-compatibility
/// discipline [`crate::lexicon::FetchHint::Other`] applies, so a field added to
/// the relay's response never breaks the probe.
#[derive(Debug, Clone, Deserialize)]
struct ListReposByCollectionOut {
    /// One entry per repo the relay has indexed as holding the collection.
    /// `#[serde(default)]` even though every observed response includes it.
    #[serde(default)]
    repos: Vec<RepoRef>,
    /// The pagination cursor. MUST be optional: the final page omits the key
    /// entirely rather than sending `null`.
    #[serde(default)]
    cursor: Option<String>,
}

/// One repo in a [`ListReposByCollectionOut`] page.
///
/// The DID is parsed but **never returned, accumulated, or persisted** — only
/// `repos.len()` is read, and the page is dropped at the end of the iteration
/// that produced it (see the module doc, rule 2).
#[derive(Debug, Clone, Deserialize)]
struct RepoRef {
    #[allow(dead_code)]
    #[serde(default)]
    did: String,
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// One relay's answer to "how many repos hold this collection?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptionObservation {
    /// The normalized relay base URL this number came from (the
    /// `network_stat.source` column).
    pub source: String,
    /// The collection NSID that was counted.
    pub collection: String,
    /// Repos the relay has **indexed** as holding the collection — a lower
    /// bound on network adoption, not a census (module doc, rule 3). Whether the
    /// relay's index counts a repo that has since deleted its records is
    /// unverified, which is why this says "indexed as holding" and not "holds".
    pub repos: u64,
    /// The [`MAX_PAGES`] cap was hit, so `repos` is a floor of a lower bound:
    /// read it as "at least N".
    pub truncated: bool,
    /// When the observation was taken (RFC3339, UTC, seconds precision —
    /// the same shape every other TEXT timestamp in the DB uses).
    pub observed_at: String,
}

/// One relay that did not answer, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFailure {
    /// The normalized relay base URL.
    pub host: String,
    /// The rendered [`RelayError`] — a log line, not a machine-readable code.
    pub reason: String,
}

/// The outcome of one probe run across **every** configured relay.
///
/// Partial success is a real outcome (one relay up, one down), which a single
/// `Result<AdoptionObservation>` cannot express — so this is not a `Result`, and
/// the caller needs no error handling beyond [`succeeded`](Self::succeeded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptionReport {
    /// The collection that was counted.
    pub collection: String,
    /// One observation per host that answered, in configured order.
    pub observations: Vec<AdoptionObservation>,
    /// One entry per host that did not answer, in configured order.
    pub failures: Vec<RelayFailure>,
}

impl AdoptionReport {
    /// Whether any relay answered at all. A run where nothing answered leaves
    /// the previous stored observation in place.
    pub fn succeeded(&self) -> bool {
        !self.observations.is_empty()
    }

    /// The observation to surface: the **highest** count, ties resolved to the
    /// first configured host. Deterministic, so two instances with the same
    /// config log the same number.
    pub fn best(&self) -> Option<&AdoptionObservation> {
        self.observations.iter().fold(None, |best, obs| match best {
            Some(b) if b.repos >= obs.repos => Some(b),
            _ => Some(obs),
        })
    }

    /// Whether two relays disagree about the count — itself worth logging, since
    /// non-archival relays index different host sets.
    pub fn disagrees(&self) -> bool {
        let mut counts = self.observations.iter().map(|o| o.repos);
        match counts.next() {
            Some(first) => counts.any(|n| n != first),
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a relay query failed. Every variant carries `host`, so a fan-out failure
/// is attributable without the caller threading context back in.
///
/// Note the deliberate absence of a field named `source`: `thiserror` treats
/// that name as `#[source]`, which requires `std::error::Error + 'static` —
/// which `anyhow::Error` (what [`crate::net::guarded_get_no_privacy`] returns)
/// does not implement. Transport failures are therefore flattened to a `String`
/// built with anyhow's alternate formatter, which preserves the whole context
/// chain in the one place it is consumed: the log line.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// The configured host is not a usable `http(s)` target.
    #[error("relay host {host:?} is not a usable http(s) target: {reason}")]
    BadHost {
        /// The offending configured value.
        host: String,
        /// Why it was rejected.
        reason: String,
    },

    /// The request never produced a response (DNS, TLS, connect, SSRF refusal).
    #[error("relay request to {host:?} failed: {reason}")]
    Transport {
        /// The relay base URL.
        host: String,
        /// The flattened `anyhow` context chain.
        reason: String,
    },

    /// The relay answered with a non-2xx status.
    #[error("relay {host:?} returned HTTP {status}: {error}")]
    Http {
        /// The relay base URL.
        host: String,
        /// The HTTP status.
        status: StatusCode,
        /// A short snippet of the body (the atproto error envelope, usually).
        error: String,
    },

    /// The relay rate-limited us. Distinct from [`RelayError::Http`] because the
    /// required behaviour differs: abort the run, log `Retry-After`, never retry
    /// tighter.
    ///
    /// `retry_after` is rendered INTO the `Display` string rather than only held
    /// as a field. The scheduler logs `err.to_string()`, so a field the message
    /// omits is unreachable — the value was parsed, stored, and then silently
    /// dropped, leaving the operator with no idea how long to back off and
    /// NETWORK-SPEC §4.6 ("`warn!` with `Retry-After` if present") unmet.
    #[error("relay {host:?} rate-limited the probe (429){}",
        match retry_after {
            Some(secs) => format!(", Retry-After: {secs}s"),
            None => String::new(),
        })]
    RateLimited {
        /// The relay base URL.
        host: String,
        /// `Retry-After` in seconds, when the delta-seconds form was sent.
        /// `None` covers both "absent" and "sent as an HTTP-date", which is
        /// deliberately not parsed — see [`retry_after_secs`].
        retry_after: Option<u64>,
    },

    /// The body was not the expected JSON envelope.
    #[error("relay {host:?} returned an unparseable body: {reason}")]
    Malformed {
        /// The relay base URL.
        host: String,
        /// The serde error.
        reason: String,
    },

    /// The whole walk against one host blew its deadline.
    #[error("relay {host:?} did not answer within {after:?}")]
    TimedOut {
        /// The relay base URL.
        host: String,
        /// The deadline that was exceeded.
        after: Duration,
    },
}

// ---------------------------------------------------------------------------
// Host normalization
// ---------------------------------------------------------------------------

/// Normalize one configured relay host into an origin URL.
///
/// `FEATHERREADER_RELAY_HOSTS` is documented as a **bare-hostname** list
/// (`relay1.us-west.bsky.network,…`) while the spec's prose example is a full
/// `https://` URL — both must work, so a value with no `://` gets `https://`.
/// Any path/query/fragment is stripped, so a stray `https://host/xrpc/` in
/// config cannot produce `…/xrpc/xrpc/…`.
pub fn normalize_relay_host(raw: &str) -> Result<String, RelayError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(RelayError::BadHost {
            host: raw.to_string(),
            reason: "empty".to_string(),
        });
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let url = url::Url::parse(&candidate).map_err(|err| RelayError::BadHost {
        host: raw.to_string(),
        reason: err.to_string(),
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(RelayError::BadHost {
            host: raw.to_string(),
            reason: format!("scheme {:?} is not http(s)", url.scheme()),
        });
    }
    let host = url.host_str().ok_or_else(|| RelayError::BadHost {
        host: raw.to_string(),
        reason: "no host component".to_string(),
    })?;
    let mut origin = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        origin.push_str(&format!(":{port}"));
    }
    Ok(origin)
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// A thin, read-only client over the public relays.
///
/// Holds the shared [`reqwest::Client`] (never builds its own — one connection
/// pool for the whole 512 MB box) and the normalized host list. Every request
/// goes through [`crate::net::guarded_get_no_privacy`]; see the module doc for
/// why.
#[derive(Debug, Clone)]
pub struct RelayClient {
    http: reqwest::Client,
    hosts: Vec<String>,
    page_limit: u32,
    max_pages: usize,
    page_delay: Duration,
    /// Soft, checked between pages; see [`DEFAULT_HOST_BUDGET`].
    host_budget: Duration,
}

impl RelayClient {
    /// Build a client over `hosts` (bare hostnames or full URLs; see
    /// [`normalize_relay_host`]), deduped with configured order preserved.
    ///
    /// An **empty** host list is `Ok` and yields `is_enabled() == false` — that
    /// is the operator's second off-switch, alongside an interval of `0`, and
    /// must not be an error. A *malformed* host, by contrast, fails loud: a typo
    /// should be visible, not silently probed forever.
    pub fn new(http: reqwest::Client, hosts: &[String]) -> Result<Self, RelayError> {
        let mut normalized: Vec<String> = Vec::with_capacity(hosts.len());
        for raw in hosts {
            let host = normalize_relay_host(raw)?;
            if !normalized.contains(&host) {
                normalized.push(host);
            }
        }
        Ok(Self {
            http,
            hosts: normalized,
            page_limit: DEFAULT_PAGE_LIMIT,
            max_pages: MAX_PAGES,
            page_delay: DEFAULT_PAGE_DELAY,
            host_budget: DEFAULT_HOST_BUDGET,
        })
    }

    /// Override the per-page repo limit, clamped into the relay's usable range.
    /// The seam a future config knob would use; the clamp is what stops a `0`
    /// (which the live relay answers with one repo *and* a cursor) from burning
    /// the whole page budget.
    pub fn with_page_limit(mut self, limit: u32) -> Self {
        self.page_limit = limit.clamp(MIN_PAGE_LIMIT, MAX_PAGE_LIMIT);
        self
    }

    /// The hard per-host deadline: the soft budget plus enough slack for one
    /// in-flight request to hit its own [`crate::net::FETCH_TIMEOUT`].
    ///
    /// Derived rather than configured, so the invariant "hard > soft + one
    /// request" cannot be broken by tuning one of them in isolation. If they
    /// ever crossed, the hard timeout would pre-empt the soft path and discard
    /// the partial count instead of recording it.
    fn hard_deadline(&self) -> Duration {
        self.host_budget + crate::net::FETCH_TIMEOUT + HARD_DEADLINE_SLACK
    }

    /// The normalized relay base URLs this client will query, in order.
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// Whether there is anything to query at all.
    pub fn is_enabled(&self) -> bool {
        !self.hosts.is_empty()
    }

    /// Count the repos holding `collection` on **every** configured relay.
    ///
    /// Hosts are queried **sequentially**, in configured order: the politeness
    /// budget is per-run, both default relays are operated by the same party,
    /// and sequential keeps peak memory at one page while making `observations`
    /// deterministically ordered. A `429` from any host aborts the whole run
    /// (both defaults sit behind one operator's rate limiter, so hammering the
    /// next one after the first says "slow down" is the impolite reading).
    ///
    /// Never returns `Err`: a failure is data, recorded per-host on the report.
    pub async fn count_repos_with_collection(&self, collection: &str) -> AdoptionReport {
        let mut observations = Vec::new();
        let mut failures = Vec::new();

        for host in &self.hosts {
            // The HARD backstop. Normally the soft budget inside `walk_pages`
            // fires first and yields a truncated-but-RECORDED observation; this
            // only catches a request still hanging past its own FETCH_TIMEOUT,
            // where there is genuinely nothing to record.
            match tokio::time::timeout(self.hard_deadline(), self.count_on_host(host, collection))
                .await
            {
                Ok(Ok(obs)) => observations.push(obs),
                Ok(Err(err)) => {
                    let rate_limited = matches!(err, RelayError::RateLimited { .. });
                    failures.push(RelayFailure {
                        host: host.clone(),
                        reason: err.to_string(),
                    });
                    if rate_limited {
                        break;
                    }
                }
                Err(_) => failures.push(RelayFailure {
                    host: host.clone(),
                    reason: RelayError::TimedOut {
                        host: host.clone(),
                        after: self.hard_deadline(),
                    }
                    .to_string(),
                }),
            }
        }

        AdoptionReport {
            collection: collection.to_string(),
            observations,
            failures,
        }
    }

    /// Walk one host's pages and return its observation.
    async fn count_on_host(
        &self,
        host: &str,
        collection: &str,
    ) -> Result<AdoptionObservation, RelayError> {
        let (repos, truncated) = self
            .walk_pages(host, |cursor| self.fetch_page(host, collection, cursor))
            .await?;
        Ok(self.observe(host, collection, repos, truncated))
    }

    /// The pagination driver, generic over how a page is obtained so the
    /// termination rules (absent cursor, empty page, page cap) are testable
    /// without a socket — which matters because the SSRF guard rightly refuses a
    /// loopback stub server, so an end-to-end fixture is not available.
    ///
    /// Returns `(repos, truncated)` — `truncated` is set by EITHER bound: the
    /// [`MAX_PAGES`] cap or the [`DEFAULT_HOST_BUDGET`] wall-clock budget. Both
    /// mean the same thing to the caller ("this count is a floor"), so they
    /// share one flag and the `/about` copy reads "at least N" either way.
    async fn walk_pages<F, Fut>(&self, host: &str, mut fetch: F) -> Result<(u64, bool), RelayError>
    where
        F: FnMut(Option<String>) -> Fut,
        Fut: std::future::Future<Output = Result<ListReposByCollectionOut, RelayError>>,
    {
        let started = tokio::time::Instant::now();
        let mut repos: u64 = 0;
        let mut cursor: Option<String> = None;
        for page_no in 0..self.max_pages {
            // The SOFT budget, checked before spending more time rather than
            // after. A slow relay used to blow the outer hard timeout and yield
            // NO observation at all — every run, forever — because the timeout
            // wrapped the whole walk and discarded its partial result. Stopping
            // here keeps what we already counted and marks it truncated.
            if page_no > 0 && started.elapsed() >= self.host_budget {
                return Ok((repos, true));
            }
            // Politeness: one second between pages against the same host.
            if page_no > 0 && !self.page_delay.is_zero() {
                tokio::time::sleep(self.page_delay).await;
            }
            let sent = cursor.take();
            let page = fetch(sent.clone()).await?;
            // `repos` is fed by an untrusted peer; never panic on overflow.
            repos = repos.saturating_add(page.repos.len() as u64);
            match advance(&page) {
                // A relay that hands back the SAME cursor it was just given is
                // not paginating. Following it would re-count the identical page
                // up to `max_pages` times and publish the sum as "at least N" —
                // inflating, in the UNSAFE direction, the one number this whole
                // feature exists to state. Refuse the walk rather than record a
                // count we already know is wrong.
                PageStep::Continue(next) if Some(&next) == sent.as_ref() => {
                    return Err(RelayError::Malformed {
                        host: host.to_string(),
                        reason: format!(
                            "repeated cursor {next:?} at page {page_no} instead of advancing"
                        ),
                    })
                }
                PageStep::Continue(next) => cursor = Some(next),
                PageStep::Done => return Ok((repos, false)),
            }
        }
        // Fell out of the loop: the cap was hit, so the count is a floor.
        Ok((repos, true))
    }

    /// Fetch and parse one page.
    async fn fetch_page(
        &self,
        host: &str,
        collection: &str,
        cursor: Option<String>,
    ) -> Result<ListReposByCollectionOut, RelayError> {
        let url = self.page_url(host, collection, cursor.as_deref());
        let resp = crate::net::guarded_get_no_privacy(
            &self.http,
            &url,
            &[(ACCEPT, HeaderValue::from_static("application/json"))],
        )
        .await
        .map_err(|err| RelayError::Transport {
            host: host.to_string(),
            reason: format!("{err:#}"),
        })?;

        // The 429 check MUST precede the generic non-2xx check, or RateLimited
        // is unreachable.
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(RelayError::RateLimited {
                host: host.to_string(),
                retry_after: retry_after_secs(resp.headers()),
            });
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let snippet = crate::net::read_capped(resp)
                .await
                .ok()
                .map(|body| {
                    String::from_utf8_lossy(&body)
                        .chars()
                        .take(ERROR_SNIPPET_CHARS)
                        .collect::<String>()
                })
                .unwrap_or_default();
            return Err(RelayError::Http {
                host: host.to_string(),
                status,
                error: snippet,
            });
        }

        // `read_capped` (streamed, 8 MiB, aborts mid-body) rather than
        // `resp.json()`, which buffers a hostile body without bound. Peak memory
        // for the whole probe is one page — O(1) in the size of the network.
        let body = crate::net::read_capped(resp)
            .await
            .map_err(|err| RelayError::Transport {
                host: host.to_string(),
                reason: format!("{err:#}"),
            })?;
        serde_json::from_slice(&body).map_err(|err| RelayError::Malformed {
            host: host.to_string(),
            reason: err.to_string(),
        })
    }

    /// The page URL. Pure — no I/O — so the query shape is unit-testable.
    ///
    /// Built with `format!` + [`urlencode`] because the declared `reqwest`
    /// feature set is `rustls + gzip + json` (no `query` feature), exactly as
    /// [`crate::atproto::resolve_handle`] does it. The `cursor` genuinely needs
    /// encoding: live values are base64url, and a standard-base64 variant
    /// carrying `+`, `/`, or `=` would silently corrupt the query.
    fn page_url(&self, host: &str, collection: &str, cursor: Option<&str>) -> String {
        let mut url = format!(
            "{}/xrpc/{}?collection={}&limit={}",
            host.trim_end_matches('/'),
            LIST_REPOS_BY_COLLECTION,
            urlencode(collection),
            self.page_limit,
        );
        if let Some(cursor) = cursor {
            url.push_str(&format!("&cursor={}", urlencode(cursor)));
        }
        url
    }

    /// Stamp an observation. One place mints the timestamp so the two exits of
    /// [`walk_pages`](Self::walk_pages) cannot drift in format.
    fn observe(
        &self,
        host: &str,
        collection: &str,
        repos: u64,
        truncated: bool,
    ) -> AdoptionObservation {
        AdoptionObservation {
            source: host.to_string(),
            collection: collection.to_string(),
            repos,
            truncated,
            observed_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// What to do after a page.
#[derive(Debug, PartialEq, Eq)]
enum PageStep {
    /// Continue with this cursor.
    Continue(String),
    /// Stop.
    Done,
}

/// Termination rules, mirroring the guard already in
/// [`crate::atproto::PdsClient::list_all_records`]: stop when the cursor is
/// absent (the normal end — the final page omits the key), **and** stop when a
/// cursor came back with an empty page, so a relay that echoes a cursor forever
/// cannot spin the loop.
///
/// A malformed cursor is not an error case here: the live relay answers a
/// garbage cursor with `200 {"repos":[]}` and no cursor, which terminates
/// cleanly through the same rule.
fn advance(page: &ListReposByCollectionOut) -> PageStep {
    match &page.cursor {
        Some(next) if !page.repos.is_empty() => PageStep::Continue(next.clone()),
        _ => PageStep::Done,
    }
}

/// `Retry-After` in seconds, for the log line. The HTTP-date form returns
/// `None` rather than pulling a date parse in for a value we never compute with.
fn retry_after_secs(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

// ---------------------------------------------------------------------------
// Tests — all pure. No socket: `net::guarded_get_no_privacy` refuses loopback by
// design, so a local stub server cannot exercise the fetch path (net.rs's own
// tests hit the same wall). Every decision is therefore factored into a pure
// function and tested here; the fetch itself is `guarded_get_no_privacy` +
// `read_capped`, both covered in `net.rs`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client() -> RelayClient {
        RelayClient::new(
            reqwest::Client::builder().build().unwrap(),
            &[DEFAULT_RELAY_HOSTS[0].to_string()],
        )
        .unwrap()
    }

    /// A client whose page delay is zero, so the pagination tests don't sleep.
    fn instant_client(max_pages: usize) -> RelayClient {
        let mut c = test_client();
        c.max_pages = max_pages;
        c.page_delay = Duration::ZERO;
        c
    }

    fn parse(body: &str) -> ListReposByCollectionOut {
        serde_json::from_str(body).expect("relay body")
    }

    fn obs(source: &str, repos: u64) -> AdoptionObservation {
        AdoptionObservation {
            source: source.to_string(),
            collection: crate::lexicon::nsid::SUBSCRIPTION.to_string(),
            repos,
            truncated: false,
            observed_at: "2026-08-13T00:00:00Z".to_string(),
        }
    }

    // -- host normalization ------------------------------------------------

    #[test]
    fn normalize_defaults_bare_host_to_https() {
        assert_eq!(
            normalize_relay_host("relay1.us-west.bsky.network").unwrap(),
            "https://relay1.us-west.bsky.network"
        );
        assert_eq!(
            normalize_relay_host("  relay1.us-east.bsky.network  ").unwrap(),
            "https://relay1.us-east.bsky.network"
        );
    }

    #[test]
    fn normalize_strips_trailing_slash_and_path() {
        assert_eq!(
            normalize_relay_host("https://relay.example/").unwrap(),
            "https://relay.example"
        );
        assert_eq!(
            normalize_relay_host("https://relay.example/xrpc/whatever?x=1#f").unwrap(),
            "https://relay.example"
        );
        // An explicit port survives (a self-hosted relay may use one).
        assert_eq!(
            normalize_relay_host("http://relay.example:8080/").unwrap(),
            "http://relay.example:8080"
        );
    }

    #[test]
    fn normalize_rejects_bad_schemes_and_empties() {
        for bad in ["wss://relay.example", "file:///etc/passwd", "", "   "] {
            assert!(
                normalize_relay_host(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    // -- URL shape ---------------------------------------------------------

    #[test]
    fn page_url_without_cursor_is_exact() {
        let c = test_client();
        assert_eq!(
            c.page_url(
                "https://relay1.us-west.bsky.network",
                crate::lexicon::nsid::SUBSCRIPTION,
                None
            ),
            "https://relay1.us-west.bsky.network/xrpc/com.atproto.sync.listReposByCollection\
             ?collection=community.lexicon.rss.subscription&limit=500"
        );
    }

    #[test]
    fn page_url_percent_encodes_the_cursor() {
        let c = test_client();
        let url = c.page_url("https://relay.example", "a.b.c", Some("aa+bb/cc=="));
        assert!(
            url.ends_with("&cursor=aa%2Bbb%2Fcc%3D%3D"),
            "cursor must be percent-encoded, got: {url}"
        );
        // The NSID is unreserved, so it passes through readable.
        assert!(url.contains("?collection=a.b.c&limit=500"), "{url}");
    }

    #[test]
    fn page_limit_is_clamped() {
        assert_eq!(test_client().with_page_limit(0).page_limit, MIN_PAGE_LIMIT);
        assert_eq!(
            test_client().with_page_limit(99_999).page_limit,
            MAX_PAGE_LIMIT
        );
        assert_eq!(test_client().with_page_limit(200).page_limit, 200);
    }

    // -- wire parsing (bodies captured live from relay1.us-west) ------------

    #[test]
    fn parses_the_live_single_repo_terminal_page() {
        let page = parse(r#"{"repos":[{"did":"did:plc:ohutz6x5acjmpuulp3x7wxxc"}]}"#);
        assert_eq!(page.repos.len(), 1);
        assert_eq!(page.cursor, None);
    }

    #[test]
    fn parses_a_cursor_first_paged_body() {
        let page = parse(
            r#"{"cursor":"QQAAAGsAAAGVmhd3TGRpZDpwbGM6dGxkYW91amwzNzZ6dTV3ZXphem54ZmV2AA",
                "repos":[{"did":"did:plc:qw4uaobncdi5ijsj4mthdboq"},
                         {"did":"did:plc:tldaoujl376zu5wezaznxfev"}]}"#,
        );
        assert_eq!(page.repos.len(), 2);
        assert!(page.cursor.is_some());
    }

    #[test]
    fn parses_empty_absent_and_unknown_field_bodies() {
        let empty = parse(r#"{"repos":[]}"#);
        assert_eq!(empty.repos.len(), 0);
        assert_eq!(empty.cursor, None);
        // Missing `repos` entirely — `#[serde(default)]`.
        assert_eq!(parse("{}").repos.len(), 0);
        // Forward compatibility: an added field must not fail the parse.
        let future = parse(r#"{"repos":[{"did":"did:web:lexicon.store","note":1}],"total":7}"#);
        assert_eq!(future.repos.len(), 1);
        assert_eq!(future.repos[0].did, "did:web:lexicon.store");
    }

    // -- pagination termination -------------------------------------------

    #[test]
    fn advance_stops_without_a_cursor() {
        assert_eq!(
            advance(&parse(r#"{"repos":[{"did":"a"}]}"#)),
            PageStep::Done
        );
    }

    #[test]
    fn advance_continues_on_a_cursor_with_rows() {
        assert_eq!(
            advance(&parse(r#"{"repos":[{"did":"a"}],"cursor":"c1"}"#)),
            PageStep::Continue("c1".to_string())
        );
    }

    #[test]
    fn advance_stops_on_an_empty_page_even_with_a_cursor() {
        // The echo guard: a relay that returns a cursor forever cannot spin us.
        assert_eq!(
            advance(&parse(r#"{"repos":[],"cursor":"c1"}"#)),
            PageStep::Done
        );
    }

    #[tokio::test]
    async fn walk_pages_follows_the_cursor_then_stops() {
        let c = instant_client(MAX_PAGES);
        let pages = [
            r#"{"repos":[{"did":"a"},{"did":"b"}],"cursor":"c1"}"#,
            r#"{"repos":[{"did":"c"}]}"#,
        ];
        let mut seen_cursors: Vec<Option<String>> = Vec::new();
        let mut n = 0usize;
        let (repos, truncated) = c
            .walk_pages("https://relay.example", |cursor| {
                seen_cursors.push(cursor);
                let body = pages[n];
                n += 1;
                async move { Ok(parse(body)) }
            })
            .await
            .unwrap();
        assert_eq!(repos, 3);
        assert!(!truncated);
        assert_eq!(seen_cursors, vec![None, Some("c1".to_string())]);
    }

    #[tokio::test]
    async fn walk_pages_stops_at_the_page_cap_and_marks_truncated() {
        let c = instant_client(3);
        // A relay that always returns a full-ish page and a genuinely FRESH
        // cursor each time (a repeated one is refused — see the test below).
        let mut n = 0usize;
        let (repos, truncated) = c
            .walk_pages("https://relay.example", |_| {
                n += 1;
                let body = format!(r#"{{"repos":[{{"did":"a"}},{{"did":"b"}}],"cursor":"c{n}"}}"#);
                async move { Ok(parse(&body)) }
            })
            .await
            .unwrap();
        assert_eq!(repos, 6, "3 pages × 2 repos");
        assert!(truncated, "hitting the cap makes the count a floor");
    }

    /// **Regression (v0.2.9 review).** A merely-SLOW relay used to produce no
    /// observation at all: the hard `tokio::time::timeout` wrapped the entire
    /// walk, so hitting it discarded every page already counted — and since the
    /// deadline was reached the same way on every run, that host contributed
    /// nothing, forever. The soft budget now stops between pages and keeps the
    /// partial count, flagged `truncated` so it reads as "at least N".
    ///
    /// `start_paused` drives tokio's clock, so the simulated 6 s pages cost no
    /// real time and the arithmetic is exact rather than timing-dependent.
    #[tokio::test(start_paused = true)]
    async fn walk_pages_keeps_a_partial_count_when_the_budget_runs_out() {
        let mut c = instant_client(50);
        c.host_budget = Duration::from_secs(10);

        let mut n = 0usize;
        let (repos, truncated) = c
            .walk_pages("https://relay.example", |_| {
                n += 1;
                let body = format!(r#"{{"repos":[{{"did":"a"}},{{"did":"b"}}],"cursor":"c{n}"}}"#);
                async move {
                    // A slow relay: each page costs 6 s of the 10 s budget.
                    tokio::time::sleep(Duration::from_secs(6)).await;
                    Ok(parse(&body))
                }
            })
            .await
            .unwrap();

        // Two pages fit (6 s, 12 s); the third is refused before it is spent.
        assert_eq!(repos, 4, "2 pages × 2 repos survive the budget");
        assert!(
            truncated,
            "a budget stop makes the count a floor, not a loss"
        );
        assert_eq!(n, 2, "the walk stopped instead of paying for a third page");
    }

    /// The hard backstop must sit at least one full request beyond the soft
    /// budget. If they ever crossed, the hard timeout would pre-empt the soft
    /// path and throw away the partial count it exists to preserve — silently
    /// reintroducing the bug the test above pins down.
    #[test]
    fn the_hard_deadline_leaves_room_for_one_in_flight_request() {
        let c = test_client();
        assert!(
            c.hard_deadline() >= c.host_budget + crate::net::FETCH_TIMEOUT,
            "hard {:?} must exceed soft {:?} by at least one FETCH_TIMEOUT",
            c.hard_deadline(),
            c.host_budget
        );
    }

    /// **Regression (v0.2.9 review).** `Retry-After` was parsed into the error
    /// and then unreachable: the scheduler logs `err.to_string()`, and the
    /// `Display` string omitted the field. NETWORK-SPEC §4.6 requires it be
    /// warned with, so it has to survive rendering, not just parsing.
    #[test]
    fn rate_limited_display_carries_retry_after() {
        let with = RelayError::RateLimited {
            host: "https://relay.example".to_string(),
            retry_after: Some(120),
        }
        .to_string();
        assert!(with.contains("Retry-After: 120s"), "{with}");

        let without = RelayError::RateLimited {
            host: "https://relay.example".to_string(),
            retry_after: None,
        }
        .to_string();
        assert!(!without.contains("Retry-After"), "{without}");
        assert!(without.contains("rate-limited"), "{without}");
    }

    #[tokio::test]
    async fn walk_pages_refuses_a_relay_that_repeats_its_cursor() {
        // The failure this guards: a relay stuck on one page would otherwise be
        // followed to the cap, summing the SAME page every pass and publishing
        // "at least 2 × max_pages" for what is really 2 repos — inflating the
        // number in the unsafe direction. No observation is better than a wrong
        // one, so the walk errors instead of returning a count.
        let c = instant_client(50);
        let err = c
            .walk_pages("https://relay.example", |_| async {
                Ok(parse(
                    r#"{"repos":[{"did":"a"},{"did":"b"}],"cursor":"stuck"}"#,
                ))
            })
            .await
            .unwrap_err();
        match err {
            RelayError::Malformed { host, reason } => {
                assert_eq!(host, "https://relay.example");
                assert!(reason.contains("repeated cursor"), "reason was {reason:?}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn walk_pages_propagates_a_page_error() {
        let c = instant_client(MAX_PAGES);
        let err = c
            .walk_pages("https://relay.example", |_| async {
                Err(RelayError::Malformed {
                    host: "https://relay.example".to_string(),
                    reason: "expected value".to_string(),
                })
            })
            .await
            .unwrap_err();
        assert!(matches!(err, RelayError::Malformed { .. }));
    }

    // -- Retry-After -------------------------------------------------------

    #[test]
    fn retry_after_reads_delta_seconds_only() {
        let mut h = HeaderMap::new();
        assert_eq!(retry_after_secs(&h), None);
        h.insert(RETRY_AFTER, HeaderValue::from_static("120"));
        assert_eq!(retry_after_secs(&h), Some(120));
        h.insert(RETRY_AFTER, HeaderValue::from_static("  120 "));
        assert_eq!(retry_after_secs(&h), Some(120));
        // The HTTP-date form is deliberately not parsed.
        h.insert(
            RETRY_AFTER,
            HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"),
        );
        assert_eq!(retry_after_secs(&h), None);
    }

    // -- client construction ----------------------------------------------

    #[test]
    fn empty_host_list_is_ok_but_disabled() {
        let c = RelayClient::new(reqwest::Client::builder().build().unwrap(), &[]).unwrap();
        assert!(!c.is_enabled());
        assert!(c.hosts().is_empty());
    }

    #[test]
    fn hosts_are_normalized_and_deduped_in_order() {
        let c = RelayClient::new(
            reqwest::Client::builder().build().unwrap(),
            &[
                "relay1.us-west.bsky.network".to_string(),
                "https://relay1.us-west.bsky.network/".to_string(),
                "relay1.us-east.bsky.network".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(
            c.hosts(),
            [
                "https://relay1.us-west.bsky.network",
                "https://relay1.us-east.bsky.network"
            ]
        );
        assert!(c.is_enabled());
    }

    #[test]
    fn one_bad_host_fails_loud() {
        let err = RelayClient::new(
            reqwest::Client::builder().build().unwrap(),
            &[
                "relay1.us-west.bsky.network".to_string(),
                "wss://relay1.us-east.bsky.network".to_string(),
            ],
        )
        .unwrap_err();
        assert!(matches!(err, RelayError::BadHost { .. }), "{err}");
    }

    // -- report arithmetic -------------------------------------------------

    #[test]
    fn report_surfaces_the_max_and_flags_disagreement() {
        let report = AdoptionReport {
            collection: crate::lexicon::nsid::SUBSCRIPTION.to_string(),
            observations: vec![obs("https://west", 2), obs("https://east", 40)],
            failures: Vec::new(),
        };
        assert!(report.succeeded());
        assert_eq!(report.best().unwrap().repos, 40);
        assert!(report.disagrees());
    }

    #[test]
    fn report_ties_resolve_to_the_first_configured_host() {
        let report = AdoptionReport {
            collection: "c".to_string(),
            observations: vec![obs("https://west", 7), obs("https://east", 7)],
            failures: Vec::new(),
        };
        assert_eq!(report.best().unwrap().source, "https://west");
        assert!(!report.disagrees());
    }

    #[test]
    fn report_with_only_failures_did_not_succeed() {
        let report = AdoptionReport {
            collection: "c".to_string(),
            observations: Vec::new(),
            failures: vec![RelayFailure {
                host: "https://west".to_string(),
                reason: "boom".to_string(),
            }],
        };
        assert!(!report.succeeded());
        assert!(report.best().is_none());
        assert!(!report.disagrees());
    }

    // -- the guard is really in the path -----------------------------------

    /// A relay host that resolves to an internal address is refused by the SSRF
    /// guard before any packet leaves the box (IP literal ⇒ no DNS, no connect).
    #[tokio::test]
    async fn internal_relay_host_is_refused_by_the_guard() {
        let c = RelayClient::new(
            reqwest::Client::builder().build().unwrap(),
            &["http://169.254.169.254".to_string()],
        )
        .unwrap();
        let report = c
            .count_repos_with_collection(crate::lexicon::nsid::SUBSCRIPTION)
            .await;
        assert!(!report.succeeded());
        assert_eq!(report.failures.len(), 1);
        let reason = &report.failures[0].reason;
        assert!(
            reason.contains("forbidden") || reason.contains("internal"),
            "expected an SSRF refusal, got: {reason}"
        );
    }
}
