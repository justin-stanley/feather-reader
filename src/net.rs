//! Hardened outbound HTTP for **untrusted, user-supplied feed URLs**.
//!
//! A feed reader fetches arbitrary URLs on behalf of its users: the add-feed
//! flow, the background poller, and OPML import all hand a *user-controlled*
//! host to `reqwest`. Left unguarded that is a textbook **SSRF** primitive — a
//! subscribed feed can `302` to `http://169.254.169.254/` (cloud metadata) or
//! `http://127.0.0.1:<port>/` (an internal service), and because the body is
//! reflected back into the reader UI the exfiltration is *non-blind*.
//!
//! This module centralises the defence so every fetch path shares one guard:
//!
//! 1. **Scheme allow-list** — only `http` / `https`. No `file:`, `gopher:`, …
//! 2. **IP allow-list** — the target host is resolved to IP(s) and rejected if
//!    *any* resolved address is loopback, link-local (`169.254.0.0/16`,
//!    `fe80::/10`), private (`10/8`, `172.16/12`, `192.168/16`), ULA
//!    (`fc00::/7`), multicast, unspecified, or broadcast.
//! 3. **Per-hop re-validation** — auto-redirect is disabled and redirects are
//!    followed manually, re-running (1) and (2) on **every** hop, so a benign
//!    first host cannot bounce us onto an internal one.
//! 4. **Capped streaming body** — the response body is streamed and aborted the
//!    moment it exceeds [`MAX_BODY_BYTES`], so a gzip decompression bomb cannot
//!    materialise gigabytes before a post-hoc size check (a Content-Length
//!    guard is useless once gzip strips the header).
//!
//! Resolution happens immediately before each request. The vetted IP is then
//! **pinned** onto the connection (reqwest `.resolve(host, addr)`), so `connect`
//! reuses the exact address that passed [`is_forbidden_ip`] rather than doing an
//! independent second DNS lookup. That closes the DNS-rebinding TOCTOU window: an
//! attacker-controlled resolver cannot answer "public IP" for the check and
//! "127.0.0.1" for the connect, because there is no second resolution.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use reqwest::header::{
    HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE, COOKIE, PROXY_AUTHORIZATION,
    WWW_AUTHENTICATE,
};
use reqwest::{Client, Response};
use url::{Host, Url};

/// Cap on how many bytes we will read from any body, streamed. 8 MiB is
/// comfortably above any sane feed; a body that exceeds it is aborted mid-stream
/// (never fully buffered), which is what defeats a gzip decompression bomb.
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Total per-request timeout for a guarded fetch. Matches
/// [`crate::feed::build_client`]'s `FETCH_TIMEOUT` so the poller's per-hop
/// pinned client is bounded the same way the feed client is — an unattended
/// poll can't hang forever on a slow/silent upstream.
///
/// `pub(crate)` so a caller that wraps a *multi-request* walk in its own
/// deadline can size that deadline against this per-request bound rather than
/// hardcoding a second copy of the number — see [`crate::network::RelayClient`].
pub(crate) const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-read idle timeout: cap the wait for the *next* body chunk, so a server
/// that trickles bytes forever (slowloris) can't tie up a fetch under the total
/// timeout. Matches [`crate::feed::build_client`]'s `READ_TIMEOUT`.
const READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum number of redirect hops we will follow (each re-validated).
///
/// `pub(crate)` alongside [`FETCH_TIMEOUT`] because the two together give the
/// real worst-case cost of ONE guarded request: the redirect loop runs
/// `0..=MAX_REDIRECTS`, and every hop builds a fresh [`pinned_client`] carrying
/// its own full [`FETCH_TIMEOUT`]. A caller that wraps a guarded request in an
/// outer deadline must budget `(MAX_REDIRECTS + 1) * FETCH_TIMEOUT`, not one
/// `FETCH_TIMEOUT` — getting that wrong silently pre-empts the inner logic.
pub(crate) const MAX_REDIRECTS: usize = 5;

/// Worst-case wall-clock cost of a single guarded request, redirects included.
/// The number an outer deadline has to respect; see [`MAX_REDIRECTS`].
pub(crate) const WORST_CASE_REQUEST: Duration =
    Duration::from_secs(FETCH_TIMEOUT.as_secs() * (MAX_REDIRECTS as u64 + 1));

/// Whether an already-resolved IP address is one we must never connect to on
/// behalf of an untrusted URL (SSRF sinks): loopback, link-local, private,
/// ULA, multicast, unspecified, or broadcast.
pub fn is_forbidden_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => is_forbidden_v6(v6),
    }
}

fn is_forbidden_v4(ip: &Ipv4Addr) -> bool {
    ip.is_loopback()            // 127.0.0.0/8
        || ip.is_private()      // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()   // 169.254.0.0/16 (cloud metadata)
        || ip.is_unspecified()  // 0.0.0.0
        || ip.is_broadcast()    // 255.255.255.255
        || ip.is_multicast()    // 224.0.0.0/4
        // Carrier-grade NAT / "this-host" / benchmarking ranges — not routable
        // to a legitimate public feed, but reachable internally.
        || matches!(ip.octets(), [0, ..])
        || matches!(ip.octets(), [100, b, ..] if (64..=127).contains(&b)) // 100.64/10 CGNAT (also used by overlay VPNs)
        || matches!(ip.octets(), [192, 0, 0, _])
        || matches!(ip.octets(), [198, 18..=19, _, _])
}

fn is_forbidden_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    // Unwrap IPv4-mapped / -compatible addresses and re-check against the v4
    // rules, so `::ffff:127.0.0.1` and friends can't slip past.
    if let Some(v4) = ip.to_ipv4() {
        return is_forbidden_v4(&v4);
    }
    let seg = ip.segments();
    // fe80::/10 link-local (incl. RFC-4291 metadata equivalents).
    let link_local = (seg[0] & 0xffc0) == 0xfe80;
    // fc00::/7 unique-local addresses.
    let ula = (seg[0] & 0xfe00) == 0xfc00;
    link_local || ula
}

/// Validate a URL's scheme (http/https only). Returns the host as a string.
fn check_scheme(url: &Url) -> Result<()> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        other => bail!("refusing non-http(s) URL scheme {other:?}"),
    }
}

/// Resolve a URL's host to socket addresses, reject if *any* resolved IP is a
/// forbidden (SSRF) target, and return the **vetted** `SocketAddr` to pin the
/// connection to.
///
/// An IP literal host is checked directly (no DNS); a named host is resolved via
/// the async resolver and *every* answer must pass — but the returned address is
/// the specific one `connect` must use, so no independent second resolution can
/// slip a rebound IP past the check (DNS-rebinding TOCTOU). Handles both IPv4 and
/// IPv6 answers.
async fn resolve_and_check(url: &Url) -> Result<SocketAddr> {
    let host = url.host().context("URL has no host")?;
    let port = url
        .port_or_known_default()
        .context("URL has no usable port")?;

    match host {
        Host::Ipv4(ip) => {
            if is_forbidden_ip(&IpAddr::V4(ip)) {
                bail!("refusing to fetch forbidden (internal) address {ip}");
            }
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        Host::Ipv6(ip) => {
            if is_forbidden_ip(&IpAddr::V6(ip)) {
                bail!("refusing to fetch forbidden (internal) address {ip}");
            }
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        Host::Domain(name) => {
            // **Test seam — `#[cfg(test)]`, so it does not exist in a release
            // build at all.** Not a parameter, not an env var, not a feature
            // flag: the compiler removes it, so there is no runtime bypass to
            // reason about. It exists because the guard is otherwise untestable
            // end-to-end — a local test server lives on loopback, which
            // `is_forbidden_ip` correctly refuses, so nothing could ever drive a
            // real redirect through this function. See `test_host_override`.
            #[cfg(test)]
            if let Some(addr) = test_override_for(name, port) {
                return Ok(addr);
            }
            let addrs = tokio::net::lookup_host((name, port))
                .await
                .with_context(|| format!("resolving host {name:?}"))?;
            first_vetted(name, addrs)
        }
    }
}

/// Pick the address to pin to from a host's DNS answers, rejecting the whole
/// set if ANY answer is forbidden.
///
/// **Extracted so it can be tested.** Inline in the resolver it was unreachable
/// without real DNS returning a mixed answer set, and a mutation that checked
/// only the FIRST answer left the entire suite green — a DNS-rebinding style
/// attack that publishes `1.2.3.4, 127.0.0.1` would have been accepted on the
/// strength of the first record.
///
/// Rejecting wholesale rather than filtering is deliberate: a host that resolves
/// to any internal address is not a host we want to talk to, even on the answers
/// that look fine.
fn first_vetted(name: &str, addrs: impl Iterator<Item = SocketAddr>) -> Result<SocketAddr> {
    let mut vetted: Option<SocketAddr> = None;
    for sa in addrs {
        let ip = sa.ip();
        if is_forbidden_ip(&ip) {
            bail!("refusing to fetch {name:?}: resolves to forbidden address {ip}");
        }
        // Keep the FIRST vetted answer as the address to pin the connect to.
        // Every answer is still checked (the loop continues), so a mixed A/AAAA
        // set with any forbidden entry is rejected wholesale.
        if vetted.is_none() {
            vetted = Some(sa);
        }
    }
    vetted.ok_or_else(|| anyhow::anyhow!("host {name:?} did not resolve to any address"))
}

/// Test-only host→address overrides, consulted by [`resolve_and_check`] before
/// real DNS. Keyed by host so tests using distinct hostnames never collide, and
/// gone entirely from a release build.
#[cfg(test)]
static TEST_HOSTS: std::sync::Mutex<Option<std::collections::HashMap<String, SocketAddr>>> =
    std::sync::Mutex::new(None);

/// The TEST certificate authority, and the leaf it issues for test hostnames.
///
/// **Why this exists at all.** An OAuth issuer is required to be `https`
/// (`discovery::validate_issuer_form`), so a plain-HTTP loopback server cannot
/// stand in for an authorization server — which meant the real `login::complete`
/// could never be driven end to end, and the wiring between its tested core and
/// the network had no coverage. A review proved that gap was live: the
/// authorization-server mix-up defence could be disabled in that wiring with the
/// whole suite green.
///
/// **Why a CA rather than relaxing the rule.** The alternative was a test-only
/// escape from the https requirement. That would *suspend* a security rule; this
/// *satisfies* it — the server really presents a certificate and the client
/// really validates the chain. It also keeps the existing tests that assert
/// `http` issuers are REJECTED meaningful, which a blanket relaxation would not.
///
/// Generated once per process. `#[cfg(test)]`, so none of it — not the trust
/// decision, not the key material — exists in a release build.
#[cfg(test)]
pub(crate) struct TestPki {
    /// PEM of the CA certificate, for `reqwest`'s root store.
    pub ca_pem: String,
    /// PEM of the leaf certificate chain, for the server.
    pub leaf_pem: String,
    /// PEM of the leaf private key, for the server.
    pub leaf_key_pem: String,
}

#[cfg(test)]
pub(crate) fn test_pki() -> &'static TestPki {
    static PKI: std::sync::OnceLock<TestPki> = std::sync::OnceLock::new();
    PKI.get_or_init(|| {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
        };

        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "featherreader test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = KeyPair::generate().expect("test CA key");
        let ca_cert = ca_params
            .clone()
            .self_signed(&ca_key)
            .expect("test CA cert");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        // SANs for the hostnames the tests register with `test_host_override`.
        // A wildcard would not cover the multi-label names, so they are listed.
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "featherreader test leaf");
        leaf_params.subject_alt_names = TEST_TLS_HOSTS
            .iter()
            .map(|h| SanType::DnsName((*h).try_into().expect("test SAN")))
            .collect();
        let leaf_key = KeyPair::generate().expect("test leaf key");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("test leaf cert");

        TestPki {
            ca_pem: ca_cert.pem(),
            leaf_pem: leaf_cert.pem(),
            leaf_key_pem: leaf_key.serialize_pem(),
        }
    })
}

#[cfg(test)]
/// A loopback HTTPS server presenting the test CA's leaf, routing by path.
///
/// The point of the TLS is not TLS: it is that an OAuth issuer must be
/// `https`, so nothing could drive the real `login::complete` against a
/// local server. The client validates this chain for real — no invalid-cert
/// acceptance anywhere.
///
/// `routes` maps a path to a canned `(status, body)`. Unknown paths 404.
/// Every request line is recorded.
pub(crate) async fn spawn_tls<F>(
    build_routes: F,
) -> (SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<String>>>)
where
    F: FnOnce(SocketAddr) -> std::collections::HashMap<String, Vec<TestResponse>>,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

    // Both `ring` and `aws-lc-rs` are reachable in this tree, so rustls refuses
    // to guess a process-level provider for the SERVER side here. Install ring.
    //
    // **Two earlier versions of this comment were wrong in opposite directions;
    // this is what reqwest 0.13 actually does** (`async_impl/client.rs`):
    //
    //     let provider = rustls::crypto::CryptoProvider::get_default()
    //         .map(|arc| arc.clone())
    //         .unwrap_or_else(default_rustls_crypto_provider);
    //
    // So it READS the process default and falls back to aws-lc-rs. Installing
    // ring here therefore DOES affect reqwest clients built afterwards in the
    // same test binary — which makes the client's provider depend on whether any
    // test called `spawn_tls` first. Benign (ring and aws-lc-rs interoperate),
    // and absent from release builds, where nothing installs a default and
    // production is genuinely aws-lc-rs. Recorded precisely because two previous
    // attempts at this comment stated a checkable fact without checking it.
    //
    // `install_default` errors if something got there first, which is fine.
    static PROVIDER: std::sync::Once = std::sync::Once::new();
    PROVIDER.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });

    let pki = test_pki();
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile_certs(pki.leaf_pem.as_bytes());
    let key: PrivateKeyDer<'static> = rustls_pemfile_key(pki.leaf_key_pem.as_bytes());

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("test server TLS config");
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Routes are built from the bound address: the documents have to name their
    // own port, and the port is not known until the listener exists.
    let routes = build_routes(addr);
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&log);
    let hits: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>> =
        Default::default();

    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let routes = routes.clone();
            let sink = std::sync::Arc::clone(&sink);
            let hits = std::sync::Arc::clone(&hits);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                // **The head, and the body when `content-length` says how
                // much — before replying.**
                //
                // A single `read` is what the capturing sidecar on the #138
                // branch did, and the review of that branch found the trap: if
                // the head and the body land in separate segments, the capture
                // holds only the head, and every `contains` assertion over it
                // then passes for the wrong reason.
                //
                // Nothing here asserts on a body today — the assertions are the
                // request line and the DPoP header, and both panic loudly when
                // absent rather than passing — so that false green is not live
                // in this harness. It is the NEXT body assertion that would
                // inherit one, which is the whole reason the same shape was
                // worth fixing there.
                //
                // **A chunked body is NOT drained.** With no `content-length`
                // there is nothing to wait for, so this stops after the head —
                // exactly what the single read did. Every request this harness
                // sees is a GET or a reqwest-buffered form and carries a length,
                // but nothing here enforces that, so a future chunked request
                // would be captured short and quietly. Said plainly rather than
                // left inside a claim to have read "the whole request".
                //
                // Draining also stops the reply being written while the client
                // is still sending, which would make a split request a broken
                // pipe rather than a response.
                let mut raw: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = tls.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&chunk[..n]);
                    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let (head, body) = raw.split_at(split + 4);
                    let want = String::from_utf8_lossy(head).lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    });
                    if want.is_none_or(|want| body.len() >= want) {
                        break;
                    }
                }
                let req = String::from_utf8_lossy(&raw).to_string();
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                sink.lock().unwrap().push(req);
                // Nth hit on this path picks the Nth canned reply; the last one
                // repeats. That is what lets a route answer a nonce challenge
                // once and something else afterwards — the only way to observe
                // whether a request was RETRIED.
                let n = {
                    let mut c = hits.lock().unwrap();
                    let e = c.entry(path.clone()).or_insert(0usize);
                    let n = *e;
                    *e += 1;
                    n
                };
                let reply = routes
                    .get(&path)
                    .and_then(|v| v.get(n.min(v.len().saturating_sub(1))))
                    .cloned()
                    .unwrap_or_else(|| TestResponse::json(404, "not found"));
                let extra: String = reply
                    .headers
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}\r\n"))
                    .collect();
                let (status, body) = (reply.status, reply.body);
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{extra}\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, log)
}

#[cfg(test)]
fn rustls_pemfile_certs(
    pem: &[u8],
) -> Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>> {
    // Minimal PEM splitter — avoids another dependency for two blocks.
    decode_pem_blocks(pem, "CERTIFICATE")
        .into_iter()
        .map(Into::into)
        .collect()
}

#[cfg(test)]
fn rustls_pemfile_key(pem: &[u8]) -> tokio_rustls::rustls::pki_types::PrivateKeyDer<'static> {
    let der = decode_pem_blocks(pem, "PRIVATE KEY")
        .into_iter()
        .next()
        .expect("a private key block");
    tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(der).into()
}

#[cfg(test)]
fn decode_pem_blocks(pem: &[u8], label: &str) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    let text = String::from_utf8_lossy(pem);
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(i) = rest.find(&begin) {
        let after = &rest[i + begin.len()..];
        let Some(j) = after.find(&end) else { break };
        let b64: String = after[..j].chars().filter(|c| !c.is_whitespace()).collect();
        out.push(
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .expect("valid base64 in test PEM"),
        );
        rest = &after[j + end.len()..];
    }
    out
}

/// One canned reply from the TLS test server.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestResponse {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

#[cfg(test)]
impl TestResponse {
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            headers: Vec::new(),
        }
    }

    pub fn with_header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }
}

/// Hostnames the test leaf is valid for. Adding a new `.test` host to a test
/// means adding it here, which is deliberate friction: the certificate is
/// supposed to be narrow.
#[cfg(test)]
pub(crate) const TEST_TLS_HOSTS: &[&str] = &[
    "pds-e2e.test",
    "as-e2e.test",
    "feed-tls.test",
    "hop-tls.test",
    "as-evil.test",
];

/// Point `host` at `addr` for the rest of the process, bypassing DNS **and** the
/// forbidden-IP check for that host only.
///
/// **Registrations are process-global and last-write-wins.** Several tests
/// register the SAME hostnames to different servers concurrently. What keeps
/// them apart is not the host key — an earlier comment claimed it was — but that
/// reqwest's `.resolve()` ignores the port, so every registration collapses to
/// `127.0.0.1` and each test's URL port routes it back to its own listener. That
/// is incidental, and would break the moment a test server bound anything other
/// than loopback.
///
/// Bypassing the IP check is the entire point: the test server is on loopback,
/// which the guard is right to refuse. Only the registered host is exempt —
/// anything else in the same test, including every redirect target, still goes
/// through the real check. That is what makes a redirect test meaningful.
#[cfg(test)]
pub(crate) fn test_host_override(host: &str, addr: SocketAddr) {
    TEST_HOSTS
        .lock()
        .unwrap()
        .get_or_insert_with(Default::default)
        .insert(host.to_string(), addr);
}

#[cfg(test)]
fn test_override_for(name: &str, port: u16) -> Option<SocketAddr> {
    let guard = TEST_HOSTS.lock().unwrap();
    let map = guard.as_ref()?;
    map.get(name)
        .copied()
        .or_else(|| map.get(&format!("{name}:{port}")).copied())
}

/// How long an idle pinned client may be kept before it is rebuilt.
///
/// Not a security boundary — the address is re-resolved and re-checked on every
/// single request, and a changed address misses the cache by construction. This
/// only bounds how long a pooled connection to a once-vetted address may live,
/// and keeps the map from holding entries for hosts nobody fetches any more.
const PINNED_CLIENT_TTL: Duration = Duration::from_secs(300);

/// Most distinct (host, address) pairs kept. A bound, not a target: the reader
/// talks to one PDS, while the poller talks to as many hosts as there are feeds.
const MAX_PINNED_CLIENTS: usize = 256;

/// How long a pinned client may hold an IDLE socket open.
///
/// Deliberately shorter than [`PINNED_CLIENT_TTL`] so a client releases its
/// sockets before the cache releases the client — otherwise the last minute of
/// an entry's life is pure socket rent. See [`build_pinned_client`] for why the
/// pool needs bounding at all.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Pinned clients, keyed by the **vetted address** they are pinned to.
///
/// ## Why this is safe to reuse
///
/// Building a fresh client per request meant a fresh connection pool, so every
/// PDS call paid a full TCP + TLS handshake: measured at 91 ms against this
/// project's PDS versus 30 ms on a warm connection. That is most of why the
/// Rust repo backend measured ~3x slower than the Node sidecar, which pools.
///
/// Reuse does NOT weaken the DNS-rebinding defence, because the defence does not
/// live in the client's lifetime:
///
/// * every request still resolves the host and runs [`is_forbidden_ip`] over
///   EVERY answer before this cache is consulted — a host that now resolves to
///   an internal address is refused before a pooled client could be returned;
/// * the key includes the vetted [`SocketAddr`], so a host that legitimately
///   moves to a different address MISSES the cache and gets a client pinned to
///   the new one. A pooled connection can only ever be reused for an address
///   that was just re-vetted this request.
struct PinnedClients {
    entries: Mutex<HashMap<(String, SocketAddr), (Client, Instant)>>,
    /// How many clients have actually been constructed. Test-only bookkeeping:
    /// it is the only way to observe that a hit avoided a rebuild, since
    /// `reqwest::Client` exposes no identity.
    builds: AtomicUsize,
}

impl PinnedClients {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            builds: AtomicUsize::new(0),
        }
    }

    /// A client pinned to `addr` for `host`, reusing a pooled one when the
    /// address is unchanged and the entry is fresh.
    fn get(&self, host: &str, addr: SocketAddr, now: Instant) -> Result<Client> {
        let key = (host.to_string(), addr);
        // A poisoned lock here is NOT fatal and must not be treated as fatal: the
        // guard is held across a fallible builder, so one panic inside it would
        // otherwise make EVERY subsequent outbound request panic, forever, with a
        // live-looking process and a green /health. Recover the data like the rate
        // limiter already does — a torn entry is a cache entry, worst case a rebuild.
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());

        if let Some((client, last_used)) = entries.get_mut(&key) {
            if now.duration_since(*last_used) < PINNED_CLIENT_TTL {
                *last_used = now;
                // Cloning a `reqwest::Client` shares its connection pool, which
                // is the entire point — a clone is a handle, not a new pool.
                return Ok(client.clone());
            }
        }

        let client = build_pinned_client(host, addr)?;
        self.builds.fetch_add(1, Ordering::Relaxed);

        // Drop anything idle past the TTL before considering the bound, so a
        // burst of one-off hosts does not evict the PDS client we use constantly.
        entries.retain(|_, (_, last_used)| now.duration_since(*last_used) < PINNED_CLIENT_TTL);
        if entries.len() >= MAX_PINNED_CLIENTS {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, (_, last_used))| *last_used)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, (client.clone(), now));
        Ok(client)
    }
}

static PINNED_CLIENTS: LazyLock<PinnedClients> = LazyLock::new(PinnedClients::new);

/// Build a per-hop client that **pins** DNS for `host` to the already-vetted
/// `addr`, so reqwest's `connect` reuses the exact IP that passed the SSRF check
/// instead of doing its own second resolution (the DNS-rebinding fix). The pin is
/// scoped to `host`, keyed to the address family of `addr` (works for both IPv4
/// and IPv6). Mirrors [`crate::feed::build_client`]'s policy: the same total
/// [`FETCH_TIMEOUT`] + per-read [`READ_TIMEOUT`] (so the unattended poller keeps
/// its slowloris / slow-upstream defence even though each hop is a freshly built
/// client), and auto-redirect off — [`guarded_get`] follows + re-validates each
/// hop itself.
fn build_pinned_client(host: &str, addr: SocketAddr) -> Result<Client> {
    let builder = Client::builder()
        .user_agent(crate::USER_AGENT)
        // Bound each hop the same way the feed client is bounded: a total
        // request timeout plus a per-read idle timeout. Without these the
        // per-hop client the poller actually connects through had NO timeouts,
        // leaving the unattended poll with no defence against a slowloris /
        // never-finishing upstream.
        .timeout(FETCH_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        // Bound the idle connection pool too.
        //
        // These clients are CACHED — up to `MAX_PINNED_CLIENTS` of them, each
        // holding its own pool — and every entry keeps live keep-alive TLS
        // connections open until it is evicted. With reqwest's defaults
        // (unlimited idle per host, no idle timeout) a poller touching many
        // distinct feed hosts drives the cache toward its bound and each entry
        // toward an unbounded number of sockets, on a 512 MB box with one shared
        // core. The cache was given a size bound for the same reason; its pools
        // were not.
        //
        // One idle connection per host is the right number here: reuse across
        // the ~300 s TTL is what the cache exists for (measured 91 ms cold
        // versus 30 ms warm), and nothing in this codebase issues concurrent
        // requests to the SAME host through one client — `guarded_get` walks
        // redirect hops sequentially, and the poller's concurrency is across
        // DIFFERENT feeds. The idle timeout is well under the cache TTL so
        // sockets are released before the client itself is.
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        // **Ignore ambient proxy configuration.** reqwest defaults
        // `auto_sys_proxy: true`, so `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`
        // in the process environment silently route every request through a
        // proxy — and a proxied request is sent in absolute form for the PROXY
        // to resolve the hostname. That defeats the two mechanisms this whole
        // module rests on at once: the `.resolve()` pin below never sees the
        // connection, and `is_forbidden_ip` never sees the address, because we
        // no longer do the resolving.
        //
        // Measured before this line existed, with `HTTP_PROXY` set: the vetted
        // address received ZERO requests, the proxy received
        // `GET http://pinned.invalid/feed HTTP/1.1`, and the call returned
        // `Ok(200)`. It failed OPEN and silently.
        //
        // Not remotely triggerable — it needs a proxy variable in the server's
        // own environment — but that is one `fly secrets set`, one debugging
        // session, or one base image away, and nothing would have reported the
        // guard had stopped working.
        .no_proxy()
        // Override reqwest's resolver for this host only: connect goes straight
        // to the vetted socket address — no independent re-resolution.
        .resolve(host, addr)
        // No auto-redirect: guarded_get follows + re-validates each hop.
        .redirect(reqwest::redirect::Policy::none());

    // **The TEST certificate authority — `#[cfg(test)]`, so a release build has
    // neither this call nor the certificate.**
    //
    // This is the one test seam in this file that touches TLS TRUST, so it is
    // worth being exact about what it does and does not do. It ADDS one root:
    // the built-in roots stay, nothing is disabled, and `danger_accept_invalid_
    // certs` is NOT used — a server still has to present a chain that validates,
    // and a hostname still has to match a SAN. What it buys is that a loopback
    // test server can hold a certificate the client will accept, which is what
    // makes it possible to drive the real `login::complete` (and the real
    // redirect path) against a server at all: the OAuth issuer must be `https`.
    //
    // `test_pki()` is itself `#[cfg(test)]`, so removing the attribute here
    // fails to compile rather than silently trusting an extra root in prod.
    #[cfg(test)]
    let builder = builder.add_root_certificate(
        reqwest::Certificate::from_pem(test_pki().ca_pem.as_bytes())
            .context("parsing the test CA")?,
    );

    builder
        .build()
        .context("failed to build IP-pinned fetch client")
}

/// The per-hop client for an already-vetted `(host, addr)`, pooled.
///
/// Callers must have run [`resolve_and_check`] for THIS request before calling
/// this — the cache trusts its key, and the key is only as good as the check
/// that produced it.
fn pinned_client(host: &str, addr: SocketAddr) -> Result<Client> {
    PINNED_CLIENTS.get(host, addr, Instant::now())
}

/// Fetch a user-supplied URL through the full SSRF guard: scheme + IP checks on
/// the initial URL and on **every** redirect hop, following redirects manually.
///
/// The passed `client` is used only as a policy reference; each hop is actually
/// sent through a freshly-built [`pinned_client`] whose DNS for the target host
/// is pinned to the exact IP that just passed [`resolve_and_check`] — so the
/// connect can't be rebound onto an internal address between the check and the
/// TCP handshake.
///
/// `extra_headers` are applied to every hop (e.g. the conditional-GET
/// `If-None-Match` / `If-Modified-Since` validators) — **except** credential
/// headers (`Authorization`, `Cookie`, …), which are dropped the moment a
/// redirect leaves the original origin, mirroring what reqwest's own redirect
/// policy does for the shared client (see [`hop_headers`]). Returns the final
/// [`Response`] (headers only; the body is read separately via [`read_capped`]).
/// `Err` on a blocked scheme/address, an exhausted redirect budget, or a
/// transport error.
pub async fn guarded_get(
    client: &Client,
    url: &str,
    extra_headers: &[(HeaderName, HeaderValue)],
) -> Result<Response> {
    guarded_get_inner(client, url, extra_headers, true, MAX_REDIRECTS).await
}

/// The SSRF core of [`guarded_get`] **without** the feed-privacy layer: scheme +
/// IP allow-list, connect-pinning, and per-hop re-validation, but no
/// `classify_feed_privacy` check.
///
/// This is the entry point for **non-feed** fetches of *user-influenced* URLs —
/// notably atproto identity resolution (a handle's PDS host, a `did:web`
/// well-known document, and a DID document's `serviceEndpoint`). Those are
/// legitimate atproto XRPC / DID-doc requests, so the feed-privacy heuristic
/// (which flags Substack/Patreon-style token URLs) must not apply — but the SSRF
/// guard absolutely must, since a hostile `did:web` or `serviceEndpoint` can
/// otherwise point the server at `169.254.169.254`, loopback, or a private host.
pub async fn guarded_get_no_privacy(
    client: &Client,
    url: &str,
    extra_headers: &[(HeaderName, HeaderValue)],
) -> Result<Response> {
    guarded_get_inner(client, url, extra_headers, false, MAX_REDIRECTS).await
}

/// Like [`guarded_get_no_privacy`] but **refuses redirects outright**.
///
/// For the OAuth discovery and DID documents, following a redirect is not a
/// convenience — it is a hole. The mix-up defence rests on comparing a
/// document's `issuer` against *the URL it was fetched from*; if a `302` can move
/// the fetch to another origin, that comparison is against the original URL while
/// the bytes came from somewhere else, and the check silently stops meaning
/// anything. The reference client sets `redirect: 'manual'`/`'error'` on every
/// one of these fetches for the same reason.
///
/// Applies to: `/.well-known/oauth-protected-resource`,
/// `/.well-known/oauth-authorization-server`, `plc.directory/<did>`, `did:web`
/// `did.json`, and the client-metadata self-fetch. It deliberately does NOT
/// apply to `/.well-known/atproto-did`, where the handle spec explicitly permits
/// redirects.
pub async fn guarded_get_no_redirect(
    client: &Client,
    url: &str,
    extra_headers: &[(HeaderName, HeaderValue)],
) -> Result<Response> {
    guarded_get_inner(client, url, extra_headers, false, 0).await
}

/// Whether a header carries credentials that must never follow a redirect onto a
/// different origin. Mirrors reqwest's own `redirect::remove_sensitive_headers`
/// set (`Authorization`, `Cookie`, `Cookie2`, `Proxy-Authorization`,
/// `WWW-Authenticate`), which the shared client applies automatically — and which
/// [`guarded_get_inner`] must reimplement because it disables auto-redirect and
/// re-applies `extra_headers` by hand on every manually-followed hop.
fn is_sensitive_header(name: &HeaderName) -> bool {
    name == AUTHORIZATION
        || name == COOKIE
        || name == PROXY_AUTHORIZATION
        || name == WWW_AUTHENTICATE
        || name.as_str() == "cookie2"
}

/// Same-origin in the web sense: identical scheme, host, and effective port.
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// The headers to apply on THIS hop: all of `extra` while we are still on the
/// original origin, otherwise only the non-sensitive ones.
///
/// The comparison base is the **original** URL rather than the previous hop (what
/// reqwest does). That is strictly stricter: an `a → b → a` redirect chain never
/// re-attaches the credential, at the cost of a small, deliberate divergence from
/// the stock client's behaviour.
fn hop_headers<'a>(
    original: &Url,
    current: &Url,
    extra: &'a [(HeaderName, HeaderValue)],
) -> Vec<&'a (HeaderName, HeaderValue)> {
    let cross_origin = !same_origin(original, current);
    extra
        .iter()
        .filter(|(name, _)| !(cross_origin && is_sensitive_header(name)))
        .collect()
}

async fn guarded_get_inner(
    client: &Client,
    url: &str,
    extra_headers: &[(HeaderName, HeaderValue)],
    check_privacy: bool,
    max_redirects: usize,
) -> Result<Response> {
    // `client` is retained in the signature for API stability + as the policy
    // template; the actual send goes through a per-hop IP-pinned client.
    let _ = client;
    let mut current = Url::parse(url).with_context(|| format!("not a valid URL {url:?}"))?;
    // The origin the caller's credentials belong to; a hop off it drops them.
    let original = current.clone();

    for _ in 0..=max_redirects {
        check_scheme(&current)?;
        // Re-validate PRIVACY on EVERY hop: a public URL can `30x` to a
        // secret-bearing private feed (Substack/Patreon/tokened podcast). Without
        // this, the private target would be fetched — its body streamed and
        // reflected into the UI — before storage is refused, violating the
        // "never fetched" half of the public-feeds-only guarantee. Classify the
        // resolved target BEFORE the request and abort the whole fetch if private.
        // (Skipped for non-feed atproto identity fetches — see
        // [`guarded_get_no_privacy`].)
        if check_privacy {
            if let crate::feed::FeedPrivacy::Private(reason) =
                crate::feed::classify_feed_privacy(current.as_str())
            {
                bail!("refusing to fetch private/paid feed URL (redirect target): {reason}");
            }
        }
        // Re-validate on EVERY hop and capture the vetted address to pin to.
        let vetted = resolve_and_check(&current).await?;
        let host = current
            .host_str()
            .context("URL lost its host between hops")?
            .to_string();
        let hop_client = pinned_client(&host, vetted)?;

        let mut req = hop_client.get(current.clone());
        // Sensitive headers (Authorization / Cookie / …) are applied only while
        // the hop is still on the ORIGINAL origin: a hostile upstream must not be
        // able to `302` a caller's bearer token onto a host it controls.
        for (name, value) in hop_headers(&original, &current, extra_headers) {
            req = req.header(name.clone(), value.clone());
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("fetching {current}"))?;

        // **Only the statuses that actually relocate — NOT all of `3xx`.**
        //
        // `is_redirection()` is `300..=399`, which swallows `304 Not Modified`.
        // A 304 carries no `Location` *by definition*, so it fell into the
        // branch below and failed the whole fetch with "redirect response
        // without a usable Location header". `feed.rs` sends `If-None-Match` /
        // `If-Modified-Since` on every poll and has a correct 304 branch — which
        // could therefore never be reached. The effect was that "nothing new"
        // became a recorded failure plus exponential backoff, punishing exactly
        // the feeds that implement conditional GET properly. Observed in
        // production against 9to5mac.com, proton.me and kodi.tv, all live.
        //
        // **304 is the ONLY status carved out.** Everything else in `3xx`
        // relocates in some sense, and stays inside this branch — because
        // `guarded_get_no_redirect` documents that it "refuses redirects
        // outright", and the OAuth mix-up defence rests on that holding for all
        // of them, not just the five we would otherwise follow.
        if resp.status() != reqwest::StatusCode::NOT_MODIFIED && resp.status().is_redirection() {
            if max_redirects == 0 {
                bail!(
                    "refusing to follow a {} redirect while fetching {url:?} \u{2014} \
                     this document's origin is load-bearing and must not be moved",
                    resp.status()
                );
            }
            // Of the relocating statuses, only these five name a single target
            // worth following. `300 Multiple Choices` names no one target, and
            // `305 Use Proxy` names a PROXY — following it would route the
            // request through a host the RESPONSE chose.
            //
            // **Refused, not returned.** Handing one back would be worse than
            // erroring: callers do not uniformly check the status.
            // `web::resolve_feed_url` reads the body straight into feed
            // autodiscovery, so a `305` whose error page carries a
            // `<link rel="alternate">` would become a subscription.
            if !matches!(resp.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                bail!(
                    "refusing to act on a {} response while fetching {url:?} \u{2014} \
                     it names no single target that can be followed safely",
                    resp.status()
                );
            }
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .context("redirect response without a usable Location header")?;
            // Resolve the (possibly relative) Location against the current URL,
            // then loop to re-validate the new hop before touching it.
            current = current
                .join(location)
                .with_context(|| format!("resolving redirect Location {location:?}"))?;
            continue;
        }

        return Ok(resp);
    }

    bail!("too many redirects (> {max_redirects}) while fetching {url:?}")
}

/// POST a JSON body to a **user-influenced** URL through the SSRF guard.
///
/// The write-side counterpart to [`guarded_get_no_privacy`], and the only way
/// [`crate::atproto::PdsClient`] is allowed to reach a PDS host it did not
/// choose. It runs the same scheme allow-list, the same IP allow-list, and the
/// same connect-pinning (via [`pinned_client`]), so the DNS-rebinding window
/// between "`assert_public_target` said this host is public" and "the TCP
/// handshake happens" is closed for writes exactly as it is for reads.
///
/// `Content-Type: application/json` is set here rather than by the caller, so
/// the one header the XRPC wire format requires cannot be forgotten; the caller
/// passes only its credential header(s).
///
/// **Redirects are refused, not followed** — the single deliberate divergence
/// from [`guarded_get`]. A `307`/`308` re-sends the method *and the body*
/// verbatim, and reqwest's cross-origin header sanitisation only strips
/// **headers**: an app password or a record body lives in the JSON payload, so a
/// hostile PDS answering `307 Location: https://evil.example/collect` would
/// exfiltrate it however carefully the headers were handled. There is no
/// legitimate reason for a PDS to redirect an `com.atproto.repo.*` write, so the
/// safe behaviour and the correct behaviour coincide: `Err`, loudly.
pub async fn guarded_post_json(
    client: &Client,
    url: &str,
    extra_headers: &[(HeaderName, HeaderValue)],
    body: Vec<u8>,
) -> Result<Response> {
    guarded_post(client, url, extra_headers, PostBody::Json(body)).await
}

/// A request body together with the content type that describes it.
///
/// The two travel as ONE value deliberately. Passing the content type alongside
/// the bytes made it possible to send a JSON body labelled as a form, or the
/// reverse — a swap no test could see without a live server, and the SSRF guard
/// forbids pointing one of these at loopback. Deriving the header from the same
/// value that produces the bytes removes the failure mode instead of watching
/// for it.
pub(crate) enum PostBody<'a> {
    Json(Vec<u8>),
    Form(&'a [(&'a str, &'a str)]),
}

impl PostBody<'_> {
    fn content_type(&self) -> HeaderValue {
        match self {
            PostBody::Json(_) => HeaderValue::from_static("application/json"),
            PostBody::Form(_) => HeaderValue::from_static("application/x-www-form-urlencoded"),
        }
    }

    /// Every form value goes through the serializer rather than string
    /// interpolation: an OAuth form carries the authorization code, the PKCE
    /// verifier and the client assertion, and a raw `&` or `=` in any of them
    /// would otherwise splice an extra parameter into the request.
    fn into_bytes(self) -> Vec<u8> {
        match self {
            PostBody::Json(bytes) => bytes,
            PostBody::Form(params) => {
                let mut ser = url::form_urlencoded::Serializer::new(String::new());
                for (k, v) in params {
                    ser.append_pair(k, v);
                }
                ser.finish().into_bytes()
            }
        }
    }
}

/// POST a form-encoded body to a **user-influenced** URL through the SSRF guard.
///
/// The OAuth counterpart to [`guarded_post_json`]: PAR, token exchange and
/// refresh are all `application/x-www-form-urlencoded`. It matters more here
/// than anywhere else that the guard applies — these are the requests that
/// carry the client assertion and the authorization code, so an issuer URL
/// that resolves to loopback or RFC1918 has to fail closed *before* the
/// credential leaves the process.
///
/// Redirects are refused for the same reason as [`guarded_post_json`], and more
/// acutely: a `307` would re-send the assertion and code to the new host.
pub async fn guarded_post_form(
    client: &Client,
    url: &str,
    extra_headers: &[(HeaderName, HeaderValue)],
    params: &[(&str, &str)],
) -> Result<Response> {
    guarded_post(client, url, extra_headers, PostBody::Form(params)).await
}

/// The shared body of [`guarded_post_json`] and [`guarded_post_form`]. Kept as
/// one function so the guard cannot drift between the two content types.
async fn guarded_post(
    client: &Client,
    url: &str,
    extra_headers: &[(HeaderName, HeaderValue)],
    body: PostBody<'_>,
) -> Result<Response> {
    let content_type = body.content_type();
    let body = body.into_bytes();
    // As in `guarded_get_inner`: `client` is the policy template; the send goes
    // through a freshly built, IP-pinned client.
    let _ = client;
    let target = Url::parse(url).with_context(|| format!("not a valid URL {url:?}"))?;
    check_scheme(&target)?;
    let vetted = resolve_and_check(&target).await?;
    let host = target.host_str().context("URL has no host")?.to_string();
    let hop_client = pinned_client(&host, vetted)?;

    let mut req = hop_client
        .post(target.clone())
        .header(CONTENT_TYPE, content_type)
        .body(body);
    for (name, value) in extra_headers {
        req = req.header(name.clone(), value.clone());
    }
    let resp = req
        .send()
        .await
        .with_context(|| format!("posting to {target}"))?;

    // Unlike the GET path this refuses the WHOLE of `3xx`, `304` included, and
    // that is deliberate: nothing here sends `If-None-Match`/`If-Modified-Since`,
    // so a 304 to a POST is a server protocol violation rather than a
    // conditional-GET success, and there is no sane way to act on it.
    //
    // It is worded separately all the same. Calling a 304 "a redirect we refused
    // to follow" is the same misattribution that made the GET bug take a
    // production investigation to find — the message should not send the next
    // reader looking for a `Location` that was never supposed to exist.
    if resp.status().is_redirection() {
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            bail!(
                "a POST to {url:?} answered 304 Not Modified, which is not a valid \
                 response to a request carrying no conditional headers"
            );
        }
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<none>");
        bail!(
            "refusing to follow a {} redirect on a POST to {url:?} (Location: {location}) — \
             a 307/308 would re-send the request body to the new host",
            resp.status()
        );
    }

    Ok(resp)
}

/// Read a response body, streaming chunk-by-chunk and **aborting** the moment
/// the accumulated size would exceed [`MAX_BODY_BYTES`]. Never trusts
/// `Content-Length` (gzip strips it) and never fully buffers an over-cap body —
/// this is the decompression-bomb / OOM guard.
pub async fn read_capped(mut resp: Response) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    while let Some(chunk) = resp.chunk().await.context("reading response body chunk")? {
        if buf.len() + chunk.len() > MAX_BODY_BYTES {
            bail!(
                "response body exceeded the {} byte cap; aborting",
                MAX_BODY_BYTES
            );
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Validate that a URL is safe to use as an outbound target: `http`/`https`
/// scheme AND every resolved IP passes the SSRF allow-list. Returns `Ok(())` for
/// a public target, `Err` for a forbidden one (loopback / link-local / private /
/// ULA / CGNAT / metadata) or a bad scheme.
///
/// Use this to vet a URL *before* it is stashed and later fetched by a client
/// that does not itself route through [`guarded_get`] — notably an atproto PDS
/// `serviceEndpoint` resolved out of a (hostile-controllable) DID document, so a
/// `serviceEndpoint: "http://169.254.169.254/"` is rejected at resolve time
/// rather than reaching a raw XRPC client.
pub async fn assert_public_target(url: &str) -> Result<()> {
    let parsed = Url::parse(url).with_context(|| format!("not a valid URL {url:?}"))?;
    check_scheme(&parsed)?;
    resolve_and_check(&parsed).await?;
    Ok(())
}

/// Scheme-allow-list a URL destined to be rendered as an `href` (an entry's
/// "View original" link, a feed's site link). Accepts only `http`/`https`;
/// anything else (notably `javascript:` / `data:` — stored-XSS vectors that
/// survive HTML escaping) yields `None` so the caller drops the link.
pub fn safe_link(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match Url::parse(trimmed) {
        Ok(u) if matches!(u.scheme(), "http" | "https") => Some(trimmed.to_string()),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn forbids_loopback_and_link_local_and_private_v4() {
        for ip in [
            "127.0.0.1",
            "127.1.2.3",
            "169.254.169.254", // cloud metadata
            "10.0.0.5",
            "172.16.9.9",
            "192.168.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "100.64.0.1", // 100.64/10 CGNAT range (also overlay VPNs)
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_forbidden_ip(&ip), "{ip} should be forbidden");
        }
    }

    #[test]
    fn allows_public_v4() {
        for ip in ["1.1.1.1", "8.8.8.8", "93.184.216.34"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!is_forbidden_ip(&ip), "{ip} should be allowed");
        }
    }

    #[test]
    fn forbids_internal_v6() {
        for ip in [
            "::1",
            "fe80::1",
            "fc00::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_forbidden_ip(&ip), "{ip} should be forbidden");
        }
    }

    #[test]
    fn allows_public_v6() {
        let ip: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        assert!(!is_forbidden_ip(&ip));
    }

    #[tokio::test]
    async fn resolve_and_check_rejects_ip_literals() {
        for bad in [
            "http://127.0.0.1/feed.xml",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:80/x",
            "http://192.168.0.1/",
        ] {
            let u = Url::parse(bad).unwrap();
            assert!(
                resolve_and_check(&u).await.is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn resolve_and_check_allows_public_ip_literal() {
        let u = Url::parse("http://1.1.1.1/").unwrap();
        let addr = resolve_and_check(&u).await.unwrap();
        // The vetted address is pinned back verbatim (IP literal, no DNS).
        assert_eq!(addr, "1.1.1.1:80".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn resolve_and_check_pins_public_ipv6_literal() {
        let u = Url::parse("http://[2606:4700:4700::1111]:443/").unwrap();
        let addr = resolve_and_check(&u).await.unwrap();
        assert_eq!(
            addr,
            "[2606:4700:4700::1111]:443".parse::<SocketAddr>().unwrap()
        );
    }

    // ── the pinned-client cache ──────────────────────────────────────────────

    const V4: &str = "93.184.216.34:443";
    const V4_OTHER: &str = "93.184.216.35:443";

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    /// A repeat request to the same vetted address REUSES the client, so the
    /// connection pool survives and the TLS handshake is paid once.
    ///
    /// Measured motivation: a fresh connection to this project's PDS costs 91 ms
    /// against 30 ms warm, which was most of the ~3x gap between the Rust repo
    /// backend and the Node sidecar.
    #[test]
    fn the_same_vetted_address_reuses_one_client() {
        let cache = PinnedClients::new();
        let now = Instant::now();
        let addr: SocketAddr = V4.parse().unwrap();

        for i in 0..5 {
            cache.get("example.com", addr, at(now, i)).unwrap();
        }
        assert_eq!(
            cache.builds.load(Ordering::Relaxed),
            1,
            "each request rebuilt the client, so every call pays a TLS handshake"
        );
    }

    /// **A CHANGED ADDRESS MUST NOT REUSE THE POOL.**
    ///
    /// This is the property that makes the cache safe. The DNS-rebinding defence
    /// is that we connect only to an address vetted for THIS request; a cache
    /// keyed on the host alone would hand back a connection pinned to an address
    /// vetted minutes ago, quietly undoing it. The key includes the address, so
    /// a move is a miss.
    #[test]
    fn a_changed_address_does_not_reuse_the_pooled_client() {
        let cache = PinnedClients::new();
        let now = Instant::now();

        cache.get("example.com", V4.parse().unwrap(), now).unwrap();
        cache
            .get("example.com", V4_OTHER.parse().unwrap(), at(now, 1))
            .unwrap();

        assert_eq!(
            cache.builds.load(Ordering::Relaxed),
            2,
            "the same host at a DIFFERENT address reused a connection pinned to the old one"
        );
        assert_eq!(cache.entries.lock().unwrap().len(), 2);
    }

    /// Two hosts that happen to resolve to the same address still get their own
    /// clients — the pin is per host, and SNI/Host differ.
    #[test]
    fn different_hosts_at_one_address_are_separate_clients() {
        let cache = PinnedClients::new();
        let now = Instant::now();
        let addr: SocketAddr = V4.parse().unwrap();

        cache.get("a.example.com", addr, now).unwrap();
        cache.get("b.example.com", addr, now).unwrap();
        assert_eq!(cache.builds.load(Ordering::Relaxed), 2);
    }

    /// An entry idle past the TTL is rebuilt, bounding how long a pooled
    /// connection to a once-vetted address can live.
    #[test]
    fn an_idle_entry_is_rebuilt_after_the_ttl() {
        let cache = PinnedClients::new();
        let now = Instant::now();
        let addr: SocketAddr = V4.parse().unwrap();

        cache.get("example.com", addr, now).unwrap();
        cache
            .get(
                "example.com",
                addr,
                now + PINNED_CLIENT_TTL + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(cache.builds.load(Ordering::Relaxed), 2);
    }

    /// Use keeps an entry alive: a client fetched every minute must not be
    /// rebuilt just because it was first created more than a TTL ago. The TTL is
    /// idle time, not total age — otherwise the busiest client in the process
    /// would be the one thrown away on a schedule.
    #[test]
    fn continued_use_keeps_an_entry_alive() {
        let cache = PinnedClients::new();
        let now = Instant::now();
        let addr: SocketAddr = V4.parse().unwrap();

        for minute in 0..20 {
            cache
                .get("example.com", addr, at(now, minute * 60))
                .unwrap();
        }
        assert_eq!(
            cache.builds.load(Ordering::Relaxed),
            1,
            "a continuously-used client was expired by age rather than idleness"
        );
    }

    /// A client must release its idle sockets BEFORE the cache releases the
    /// client. The other way round, every entry spends the tail of its life
    /// holding connections nothing will reuse — which is the whole cost the pool
    /// bound exists to avoid.
    #[test]
    fn idle_sockets_are_released_before_their_client_is() {
        assert!(
            POOL_IDLE_TIMEOUT < PINNED_CLIENT_TTL,
            "pool idle timeout {POOL_IDLE_TIMEOUT:?} is not shorter than the \
             client TTL {PINNED_CLIENT_TTL:?}"
        );
    }

    /// The map is bounded. The poller talks to as many hosts as there are feeds,
    /// so an unbounded map would be a slow leak of connection pools.
    #[test]
    fn the_cache_is_bounded() {
        let cache = PinnedClients::new();
        let now = Instant::now();
        for i in 0..(MAX_PINNED_CLIENTS + 50) {
            let addr: SocketAddr = format!("93.184.216.34:{}", 1024 + i).parse().unwrap();
            cache.get(&format!("h{i}.example.com"), addr, now).unwrap();
        }
        assert!(
            cache.entries.lock().unwrap().len() <= MAX_PINNED_CLIENTS,
            "the cache grew past its bound"
        );
    }

    #[test]
    fn pinned_client_builds_for_both_families() {
        // Both address families must produce a usable pinned client.
        assert!(pinned_client("example.com", "93.184.216.34:80".parse().unwrap()).is_ok());
        assert!(
            pinned_client("example.com", "[2606:4700:4700::1111]:443".parse().unwrap()).is_ok()
        );
    }

    #[test]
    fn scheme_allowlist_rejects_non_http() {
        assert!(check_scheme(&Url::parse("http://example.com/").unwrap()).is_ok());
        assert!(check_scheme(&Url::parse("https://example.com/").unwrap()).is_ok());
        // url::Url::parse rejects `javascript:` as opaque, but file/ftp parse.
        assert!(check_scheme(&Url::parse("file:///etc/passwd").unwrap()).is_err());
        assert!(check_scheme(&Url::parse("ftp://example.com/").unwrap()).is_err());
    }

    /// A raw HTTP server on loopback that answers every request with `body`
    /// (fixed Content-Length). Returns its `http://127.0.0.1:port/` base URL.
    /// Used to exercise [`read_capped`] against a real reqwest `Response`.
    pub(crate) async fn serve_body(body: Vec<u8>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let body = body.clone();
                tokio::spawn(async move {
                    // Drain the request headers (best-effort) then reply.
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(header.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                    let _ = sock.flush().await;
                });
            }
        });
        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn read_capped_rejects_over_cap_body() {
        // A body one byte over the cap must be rejected (and never fully
        // buffered past the cap). Fetch directly (bypassing the SSRF guard, which
        // rightly forbids loopback) to exercise read_capped on a real Response.
        let big = vec![b'x'; MAX_BODY_BYTES + 1];
        let base = serve_body(big).await;
        let client = reqwest::Client::builder().build().unwrap();
        let resp = client.get(&base).send().await.unwrap();
        let err = read_capped(resp).await.unwrap_err().to_string();
        assert!(err.contains("exceeded"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn read_capped_accepts_small_body() {
        let base = serve_body(b"hello world".to_vec()).await;
        let client = reqwest::Client::builder().build().unwrap();
        let resp = client.get(&base).send().await.unwrap();
        let body = read_capped(resp).await.unwrap();
        assert_eq!(body, b"hello world");
    }

    /// A raw HTTP server on loopback that answers `/final` with `200 arrived`
    /// and **everything else** with `302 Location: /final`. Returns its bound
    /// address, so a caller can pin a client to it by address rather than name.
    ///
    /// This is the fixture the two tests below need and that the module did not
    /// previously have. Note it returns the `SocketAddr`, not a URL: the whole
    /// point is to reach it under a hostname that does not resolve.
    pub(crate) async fn serve_redirect_to_final() -> SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let resp = if req.starts_with("GET /final") {
                        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\narrived"
                    } else {
                        "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\
                         Connection: close\r\n\r\n"
                    };
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });
        addr
    }

    /// **The connect goes to the address the guard vetted — enforcement, not
    /// decision.**
    ///
    /// `resolve_and_check` vets an address and `build_pinned_client` then
    /// `.resolve()`s the host to exactly that address, so the TCP connect cannot
    /// be rebound onto an internal one in the window between the two. That is
    /// the DNS-rebinding defence the module doc spends 25 lines on.
    ///
    /// **Nothing observed it.** Deleting `.resolve(host, addr)` left all 659
    /// tests green, because every other test either passes an IP literal — where
    /// a second resolution is a no-op — or asserts on `is_forbidden_ip`
    /// directly. `is_forbidden_ip` is thoroughly tested; what carries its verdict
    /// to the socket was not tested at all.
    ///
    /// This pins it in the one way that cannot silently stop discriminating: the
    /// host **resolves nowhere**. `.invalid` is reserved by RFC 2606 and is
    /// guaranteed never to exist, so the only route to the stub is the pin. Drop
    /// `.resolve()` and the client falls back to real DNS and cannot connect —
    /// which is also why this test needs no network.
    #[tokio::test]
    async fn the_connect_is_pinned_to_the_vetted_address() {
        let addr = serve_redirect_to_final().await;
        let host = "pinned-target.invalid";
        let client = pinned_client(host, addr).expect("building a pinned client");

        let resp = client
            .get(format!("http://{host}:{}/final", addr.port()))
            .send()
            .await
            .expect(
                "a pinned host must reach the vetted address without consulting DNS — \
                 if this failed to connect, the `.resolve()` pin is gone",
            );
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "arrived");
    }

    /// **The per-hop client must not follow redirects on its own.**
    ///
    /// `guarded_get_inner` follows redirects *manually* so it can re-run the
    /// scheme check, the privacy check and `resolve_and_check` on every hop, and
    /// so it can strip credential headers when a hop leaves the original origin.
    /// All of that is bypassed if reqwest follows the redirect internally: the
    /// connect to hop 2 happens inside reqwest, against an address nothing
    /// vetted. For `guarded_post` it is worse still — reqwest would re-send a
    /// `307`'s BODY (a client assertion, an auth code) to the new origin before
    /// `guarded_post`'s own 3xx refusal ever ran.
    ///
    /// Flipping `Policy::none()` to `Policy::limited(10)` left all 659 tests
    /// green. The existing redirect test could not catch it: it builds a 302 stub
    /// and then discards the address with `let _ = addr`, because the guard
    /// forbids loopback and the stub was therefore unreachable *through* the
    /// guard. It asserts on a private URL passed directly in, so no redirect ever
    /// occurs in it.
    ///
    /// Pinning by address sidesteps that — `pinned_client` does not consult the
    /// guard, so the stub is reachable — and the assertion is on the status the
    /// caller receives: `302`, handed back for the loop to re-validate, not the
    /// `200` that reqwest would return after quietly following it.
    #[tokio::test]
    async fn the_pinned_client_does_not_follow_redirects_itself() {
        let addr = serve_redirect_to_final().await;
        let host = "redirector.invalid";
        let client = pinned_client(host, addr).expect("building a pinned client");

        let resp = client
            .get(format!("http://{host}:{}/start", addr.port()))
            .send()
            .await
            .expect("the stub must answer the first hop");

        assert_eq!(
            resp.status(),
            302,
            "the per-hop client must hand the 30x BACK to guarded_get_inner for \
             re-validation; a 200 here means reqwest followed it internally and the \
             second hop was connected to without passing resolve_and_check",
        );
        assert_eq!(
            resp.headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/final"),
            "the Location must reach the caller — it is what the next hop re-validates",
        );
    }

    /// **Every branch of the v4/v6 blocklist is load-bearing.**
    ///
    /// Four branches were unreachable from the existing tests: `is_multicast()`
    /// on both families, `192.0.0.0/24` ("this host on this network", IETF
    /// protocol assignments) and `198.18.0.0/15` (benchmarking). Deleting all
    /// four at once left the suite green, so a quarter of the blocklist could
    /// have been dropped in a refactor without a single failure.
    ///
    /// These are not decorative: multicast to an internal group and the
    /// benchmarking range are both reachable on a real network and neither can
    /// host a legitimate public feed.
    #[test]
    fn every_blocklist_branch_is_load_bearing() {
        for ip in [
            "224.0.0.1",       // v4 multicast, all-systems group
            "239.255.255.250", // v4 multicast, SSDP — a real LAN discovery target
            "192.0.0.1",       // 192.0.0.0/24, IETF protocol assignments
            "192.0.0.171",     // same /24
            "198.18.0.1",      // 198.18/15 benchmarking
            "198.19.255.255",  // top of the benchmarking range
            "0.0.0.0",         // unspecified
            "0.1.2.3",         // rest of 0/8
            "255.255.255.255", // broadcast
            "100.64.0.1",      // CGNAT floor
            "100.127.255.255", // CGNAT ceiling
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(is_forbidden_ip(&parsed), "{ip} must be forbidden");
        }
        for ip in [
            "ff02::1",                // v6 multicast, all-nodes
            "::1",                    // v6 loopback
            "::",                     // v6 unspecified
            "fe80::1",                // v6 link-local
            "fc00::1",                // v6 ULA
            "fd00::1",                // v6 ULA
            "::ffff:127.0.0.1",       // v4-mapped loopback
            "::ffff:169.254.169.254", // v4-mapped cloud metadata
            "::ffff:10.0.0.1",        // v4-mapped RFC1918
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(is_forbidden_ip(&parsed), "{ip} must be forbidden");
        }
    }

    /// **The blocklist must not over-block, and only boundaries can show that.**
    ///
    /// A guard that refuses everything passes every all-negative test, and the
    /// existing positive cases (`1.1.1.1`, `8.8.8.8`, `93.184.216.34`) sit
    /// nowhere near a blocked range, so none of them would notice. Widening
    /// `172.16/12` to all of `172/8` and `100.64/10` to all of `100/8` — which
    /// would silently refuse Google and AWS address space — left the suite green.
    ///
    /// Each address here is the one immediately OUTSIDE a blocked range, so an
    /// off-by-one in any CIDR boundary fails this test and nothing else.
    #[test]
    fn the_blocklist_does_not_over_block_adjacent_public_space() {
        for ip in [
            "9.255.255.255",   // just below 10/8
            "11.0.0.0",        // just above 10/8
            "172.15.255.255",  // just below 172.16/12
            "172.32.0.0",      // just above 172.16/12 (172.217.x is Google)
            "192.167.255.255", // just below 192.168/16
            "192.169.0.0",     // just above 192.168/16
            "169.253.255.255", // just below 169.254/16
            "169.255.0.0",     // just above 169.254/16
            "126.255.255.255", // just below 127/8
            "128.0.0.0",       // just above 127/8
            "100.63.255.255",  // just below 100.64/10 CGNAT
            "100.128.0.0",     // just above 100.64/10 (100.20.x is AWS)
            "192.0.1.0",       // just above 192.0.0.0/24
            "198.17.255.255",  // just below 198.18/15
            "198.20.0.0",      // just above 198.18/15
            "223.255.255.255", // just below 224/4 multicast
            "1.0.0.0",         // just above 0/8
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(
                !is_forbidden_ip(&parsed),
                "{ip} is public and adjacent to a blocked range — refusing it means a \
                 CIDR boundary is wrong and real feeds are unreachable",
            );
        }
        for ip in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(
                !is_forbidden_ip(&parsed),
                "{ip} is public and must be allowed"
            );
        }
    }

    /// **Regression (v0.2.8):** the write-side guard must refuse the same targets
    /// the read-side one does — loopback, cloud metadata, RFC1918, ULA — *before*
    /// the connect, so a rebound PDS host never receives a request body carrying
    /// an app password or a session bearer.
    ///
    /// (The companion rule — a `307`/`308` is refused rather than followed,
    /// because a redirect re-sends the BODY and reqwest only sanitises headers —
    /// is not exercised here for the same reason `read_capped`'s stub is fetched
    /// unguarded: the guard forbids loopback, so a local stub server can never be
    /// reached through it. It is enforced by construction in `guarded_post_json`.)
    #[tokio::test]
    async fn guarded_post_refuses_internal_targets() {
        let client = Client::builder().build().unwrap();
        for url in [
            "http://127.0.0.1:9/xrpc/com.atproto.server.createSession",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/xrpc/com.atproto.repo.applyWrites",
            "http://[::1]/xrpc/com.atproto.repo.deleteRecord",
        ] {
            let err = guarded_post_json(&client, url, &[], b"{}".to_vec())
                .await
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("forbidden") || err.contains("internal"),
                "{url}: expected an SSRF refusal, got: {err}"
            );
        }
    }

    /// A non-http(s) scheme is refused on the write path too.
    #[tokio::test]
    async fn guarded_post_refuses_bad_schemes() {
        let client = Client::builder().build().unwrap();
        for url in ["file:///etc/passwd", "gopher://example.com/1"] {
            let err = guarded_post_json(&client, url, &[], b"{}".to_vec())
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("scheme"), "{url}: got: {err}");
        }
    }

    /// A public first hop that `30x`-redirects to a private, secret-bearing feed
    /// URL must be REFUSED before the private target is ever fetched — the
    /// per-hop privacy re-check in [`guarded_get`]. We serve a `302` on loopback
    /// pointing at a private URL and assert the guard aborts with a privacy
    /// reason (not merely the SSRF/loopback rejection).
    #[tokio::test]
    async fn guarded_get_refuses_private_redirect_target() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let resp = "HTTP/1.1 302 Found\r\nLocation: https://author.substack.com/feed/private/deadbeefcafe1234\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        // Fetch the loopback URL directly. The FIRST hop is loopback, which the
        // SSRF guard already forbids — so to isolate the privacy check we assert
        // on the private URL passed straight in instead.
        let _ = addr; // (loopback first hop is SSRF-blocked; see direct check below)
        let client = Client::builder().build().unwrap();
        let err = guarded_get(
            &client,
            "https://author.substack.com/feed/private/deadbeefcafe1234",
            &[],
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("private/paid feed"),
            "expected privacy refusal, got: {err}"
        );
    }

    /// Header names/values for the hop-header tests: one credential, one benign
    /// conditional-GET validator.
    fn hop_fixture() -> Vec<(HeaderName, HeaderValue)> {
        vec![
            (AUTHORIZATION, HeaderValue::from_static("Bearer secret")),
            (
                reqwest::header::IF_NONE_MATCH,
                HeaderValue::from_static("\"etag\""),
            ),
        ]
    }

    #[test]
    fn sensitive_header_set() {
        assert!(is_sensitive_header(&AUTHORIZATION));
        assert!(is_sensitive_header(&COOKIE));
        assert!(is_sensitive_header(&PROXY_AUTHORIZATION));
        assert!(is_sensitive_header(&WWW_AUTHENTICATE));
        assert!(is_sensitive_header(&HeaderName::from_static("cookie2")));
        assert!(!is_sensitive_header(&reqwest::header::IF_NONE_MATCH));
        assert!(!is_sensitive_header(&reqwest::header::IF_MODIFIED_SINCE));
        assert!(!is_sensitive_header(&reqwest::header::ACCEPT));
    }

    #[test]
    fn hop_headers_keeps_all_on_same_origin() {
        let extra = hop_fixture();
        let original = Url::parse("https://pds.example.com/xrpc/x").unwrap();
        // The very first hop (identical URL) keeps everything…
        assert_eq!(hop_headers(&original, &original, &extra).len(), 2);
        // …and so does a same-origin path change (a `302 /a → /b` on one host).
        let same = Url::parse("https://pds.example.com/other/path?q=1").unwrap();
        assert_eq!(hop_headers(&original, &same, &extra).len(), 2);
    }

    #[test]
    fn hop_headers_strips_authorization_cross_host() {
        let extra = hop_fixture();
        let original = Url::parse("https://pds.example.com/x").unwrap();
        let evil = Url::parse("https://evil.example.net/y").unwrap();
        let kept = hop_headers(&original, &evil, &extra);
        assert_eq!(kept.len(), 1, "the bearer must not follow a cross-host 302");
        assert_eq!(kept[0].0, reqwest::header::IF_NONE_MATCH);
    }

    #[test]
    fn hop_headers_strips_on_port_and_scheme_change() {
        let extra = hop_fixture();
        let original = Url::parse("https://a.example/x").unwrap();
        for downgraded in ["http://a.example/x", "https://a.example:8443/x"] {
            let current = Url::parse(downgraded).unwrap();
            let kept = hop_headers(&original, &current, &extra);
            assert_eq!(kept.len(), 1, "{downgraded} must drop the credential");
            assert_eq!(kept[0].0, reqwest::header::IF_NONE_MATCH);
        }
        // The default port spelled explicitly is still the same origin.
        let explicit = Url::parse("https://a.example:443/x").unwrap();
        assert_eq!(hop_headers(&original, &explicit, &extra).len(), 2);
    }

    #[test]
    fn safe_link_allowlist() {
        assert_eq!(
            safe_link("https://ok.example/x").as_deref(),
            Some("https://ok.example/x")
        );
        assert_eq!(
            safe_link("  http://ok.example/  ").as_deref(),
            Some("http://ok.example/")
        );
        assert_eq!(safe_link("javascript:alert(document.domain)"), None);
        assert_eq!(safe_link("data:text/html,<script>alert(1)</script>"), None);
        assert_eq!(safe_link(""), None);
        assert_eq!(safe_link("   "), None);
        // A relative/naked path isn't an absolute http(s) URL → dropped.
        assert_eq!(safe_link("/relative/path"), None);
    }

    /// The OAuth token/PAR calls are form POSTs carrying a client assertion and,
    /// on the token call, the authorization code. They must go through the SAME
    /// SSRF guard as everything else: a PDS or issuer URL that resolves to
    /// loopback/RFC1918 has to fail closed BEFORE the credential is sent.
    #[tokio::test]
    async fn guarded_post_form_fails_closed_on_a_forbidden_target() {
        let client = Client::new();
        for url in [
            "http://127.0.0.1:2583/oauth/token",
            "http://[::1]:2583/oauth/token",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/oauth/token",
        ] {
            let err = guarded_post_form(&client, url, &[], &[("grant_type", "authorization_code")])
                .await
                .expect_err("must refuse {url}");
            let msg = err.to_string().to_lowercase();
            assert!(
                msg.contains("forbidden") || msg.contains("refus") || msg.contains("resolve"),
                "unexpected error for {url}: {err:#}"
            );
        }
    }

    /// A non-http(s) scheme must be rejected before any DNS work.
    #[tokio::test]
    async fn guarded_post_form_rejects_non_http_schemes() {
        let client = Client::new();
        assert!(
            guarded_post_form(&client, "file:///etc/passwd", &[], &[("a", "b")])
                .await
                .is_err()
        );
    }

    /// OAuth metadata and DID documents must be fetched WITHOUT following
    /// redirects, and still through the SSRF guard.
    /// Asserts on the GUARD's error, not merely `is_err()`. Connecting to
    /// `127.0.0.1` fails anyway (refused, or a slow timeout for an unrouted
    /// RFC1918 address), so an `is_err()`-only assertion passes with
    /// `resolve_and_check` deleted and proves nothing.
    #[tokio::test]
    async fn guarded_get_no_redirect_still_fails_closed_on_forbidden_targets() {
        let client = Client::new();
        for url in [
            "http://127.0.0.1/.well-known/oauth-authorization-server",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.1.1/.well-known/did.json",
            "http://[::1]/.well-known/did.json",
        ] {
            let err = guarded_get_no_redirect(&client, url, &[])
                .await
                .expect_err("must refuse");
            let rendered = format!("{err:#}");
            assert!(
                rendered.contains("forbidden (internal) address"),
                "{url} failed for the wrong reason: {rendered}"
            );
        }
        // And the scheme check, which is a different branch entirely.
        let err = guarded_get_no_redirect(&client, "file:///etc/passwd", &[])
            .await
            .expect_err("must refuse");
        assert!(format!("{err:#}").contains("non-http(s) URL scheme"));
    }

    /// The content type must follow the body it describes. Because both come
    /// from the same value, a JSON body can never be labelled as a form.
    #[test]
    fn the_content_type_follows_the_body_kind() {
        assert_eq!(
            PostBody::Json(b"{}".to_vec()).content_type(),
            "application/json"
        );
        assert_eq!(
            PostBody::Form(&[("a", "b")]).content_type(),
            "application/x-www-form-urlencoded"
        );
        // And the bytes are encoded to match.
        assert_eq!(
            PostBody::Json(b"{\"a\":1}".to_vec()).into_bytes(),
            b"{\"a\":1}"
        );
        assert_eq!(PostBody::Form(&[("a", "b c")]).into_bytes(), b"a=b+c");
    }

    /// Form encoding must percent-encode values; a value containing `&` or `=`
    /// must not be able to inject an extra parameter into the body.
    #[test]
    fn form_body_percent_encodes_and_cannot_inject_parameters() {
        let body = PostBody::Form(&[
            ("grant_type", "authorization_code"),
            ("code", "abc&scope=evil"),
            ("redirect_uri", "https://x.example/oauth/callback"),
        ])
        .into_bytes();
        let s = String::from_utf8(body).unwrap();
        assert!(s.contains("grant_type=authorization_code"));
        assert!(
            s.matches("scope=").count() == 0,
            "a `&` in a value injected a parameter: {s}"
        );
        assert!(s.contains("%26"), "the `&` was not encoded: {s}");
        assert!(s.contains("%3A%2F%2F"), "the `://` was not encoded: {s}");
    }

    // ── SSRF ENFORCEMENT (not just the decision) ─────────────────────────────
    //
    // Everything below drives a REAL redirect through `guarded_get_inner`
    // against a real HTTP server. None of it was possible before the
    // `test_host_override` seam: the guard correctly refuses loopback, so a
    // local test server was unreachable through it, and three enforcement
    // properties had no coverage at all. Each had a mutation that left the
    // whole suite green.

    /// A tiny HTTP server that replays canned responses and records every raw
    /// request it received. Returns its address and the request log.
    async fn spawn_http(
        responses: Vec<String>,
    ) -> (SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&log);
        tokio::spawn(async move {
            let mut i = 0usize;
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                // **The whole request, not the first 8 KB of it.**
                //
                // This used to be one `read` into a fixed buffer. Anything past
                // it was never captured, and the assertions over this log are
                // NEGATIVE — `!seen.contains("authorization:")` in the
                // cross-origin credential test — so a short capture satisfies
                // them exactly as well as a stripped header does. The two are
                // indistinguishable, and only one of them means the guard works.
                //
                // Same shape as `spawn_tls`, deliberately: three test servers
                // that read alike means the next one copied from any of them
                // starts correct. And the same limit applies — with no
                // `content-length` there is nothing to wait for, so a chunked
                // body stops after the head.
                let mut raw: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    // **A read error DISCARDS the connection rather than logging
                    // what arrived so far.** Breaking here and pushing the
                    // partial would put a truncated request in the log — the
                    // exact thing this change exists to stop, arriving by a
                    // different door. `spawn_tls` returns for the same reason.
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&chunk[..n]);
                    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let (head, body) = raw.split_at(split + 4);
                    let want = String::from_utf8_lossy(head).lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    });
                    if want.is_none_or(|want| body.len() >= want) {
                        break;
                    }
                }
                if raw.is_empty() {
                    continue;
                }
                sink.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&raw).to_string());
                let body = responses
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| responses.last().cloned().unwrap_or_default());
                i += 1;
                let _ = sock.write_all(body.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        (addr, log)
    }

    /// **The SSRF guard must ignore ambient proxy configuration.**
    ///
    /// reqwest defaults `auto_sys_proxy: true`. With `HTTP_PROXY` set in the
    /// process environment, a request is sent to the proxy in ABSOLUTE form —
    /// `GET http://host/path` — and over https as `CONNECT host:443`, for the
    /// PROXY to resolve the hostname.
    ///
    /// Precisely what breaks: `resolve_and_check` still runs its own lookup and
    /// still rejects forbidden IPs, so it is not that the check is skipped. It
    /// is that the checked address is no longer the address connected to — the
    /// proxy re-resolves the name on its own network, so the vetted result is
    /// decorative. DNS rebinding, split-horizon DNS and anything reachable from
    /// the proxy but not from here all come back. And the call returns 200, so
    /// it fails OPEN.
    ///
    /// Measured before `.no_proxy()` existed: vetted server 0 requests, proxy
    /// received `GET http://pin-vs-proxy.invalid/feed HTTP/1.1`, result
    /// `Ok(200)`.
    ///
    /// **Why this re-execs itself.** reqwest reads the proxy environment when
    /// the client is BUILT, so the variable has to be present before the
    /// builder runs. `set_var` is a data race against the ~39 `env::var` reads
    /// in this binary and is the one thing this codebase refuses to do in
    /// tests. So the parent owns both servers, and the child inherits
    /// `HTTP_PROXY` from birth — no mutation of a live environment anywhere.
    #[tokio::test]
    async fn the_pinned_client_ignores_ambient_proxy_configuration() {
        const VETTED: &str = "FR_AMBIENT_PROXY_VETTED";
        const HOST: &str = "ambient-proxy-probe.invalid";

        if let Ok(vetted) = std::env::var(VETTED) {
            // ── child: HTTP_PROXY is already in our environment ──
            let addr: SocketAddr = vetted.parse().unwrap();
            let client = build_pinned_client(HOST, addr).expect("client");
            let _ = client.get(format!("http://{HOST}/probe")).send().await;
            return;
        }

        // ── parent: owns both servers, so it can see who was contacted ──
        let (vetted_addr, vetted_log) = spawn_http(vec![ok_200()]).await;
        let (proxy_addr, proxy_log) = spawn_http(vec![ok_200()]).await;

        // `tokio::process`, NOT `std::process`: a blocking `output()` here
        // would hold this single-threaded runtime, so the servers above could
        // never accept the child's connection — and the test would fail with
        // "did not reach the vetted address" for a reason that has nothing to
        // do with proxies. That exact false failure happened while writing it.
        let out = tokio::process::Command::new(std::env::current_exe().unwrap())
            // FULL path: `--exact` matches the whole test name including the
            // module. With the bare function name the child matched nothing,
            // ran zero tests, and exited 0 — so the parent saw a "successful"
            // child that had done nothing, and blamed the pin. The
            // `1 test` assertion below is there so that can never pass silently
            // again.
            .args([
                "net::tests::the_pinned_client_ignores_ambient_proxy_configuration",
                "--exact",
                "--test-threads=1",
            ])
            // **Clear the inherited proxy KILL-SWITCHES.**
            //
            // The child inherits this process's environment, and two inherited
            // values make the whole test vacuous — it passes with `.no_proxy()`
            // DELETED. Verified: `NO_PROXY='*'` and `REQUEST_METHOD=GET`
            // (hyper-util treats the latter as a CGI context and disables proxy
            // env entirely) each turn a genuine failure into `1 passed`.
            //
            // GitHub-hosted runners set none of these, so the gap was invisible
            // here — a self-hosted or corporate runner would have silently
            // neutered the regression test while it kept reporting success.
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env_remove("REQUEST_METHOD")
            .env(VETTED, vetted_addr.to_string())
            .env("HTTP_PROXY", format!("http://{proxy_addr}"))
            .env("HTTPS_PROXY", format!("http://{proxy_addr}"))
            .env("ALL_PROXY", format!("http://{proxy_addr}"))
            .output()
            .await
            .expect("re-exec the test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "child run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("1 passed"),
            "the child ran no test, so this proves nothing about proxies — \
             check the --exact filter. Child stdout:\n{stdout}"
        );

        let proxied = proxy_log.lock().unwrap().clone();
        let direct = vetted_log.lock().unwrap().len();
        assert!(
            proxied.is_empty(),
            "the pinned client used an ambient proxy, so the connect pin and \
             `is_forbidden_ip` were both bypassed — the proxy resolves the \
             hostname itself. Proxy saw: {proxied:?}"
        );
        assert_eq!(
            direct, 1,
            "the pinned client did not reach the vetted address it was pinned to",
        );
    }

    fn ok_200() -> String {
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi".to_string()
    }
    fn redirect_to(loc: &str) -> String {
        format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    }
    /// No `Location` and no body — which is what a 304 *is*, not a stub of one.
    fn not_modified_304() -> String {
        "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n".to_string()
    }
    /// `305 Use Proxy` — a relocating 3xx that names a PROXY, WITH a `Location`,
    /// so it would have been followed before the narrowing.
    fn use_proxy_305(loc: &str) -> String {
        format!("HTTP/1.1 305 Use Proxy\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    }

    /// **An unfollowable 3xx is refused, not handed back.**
    ///
    /// Narrowing the follow set to `301|302|303|307|308` left a choice for the
    /// rest: return them, or refuse. Returning is the worse one, because callers
    /// do not uniformly check the status — `web::resolve_feed_url` reads the body
    /// straight into feed autodiscovery, so a `305` whose error page carries a
    /// `<link rel="alternate">` would quietly become a subscription.
    ///
    /// A 305 also carries a `Location`, so before the narrowing it was FOLLOWED:
    /// the request went through a proxy the response chose. Refusing is the
    /// stricter behaviour in both directions.
    #[tokio::test]
    async fn an_unfollowable_3xx_is_refused_rather_than_returned() {
        let (addr, log) = spawn_http(vec![use_proxy_305("http://proxy.invalid:3128/")]).await;
        test_host_override("use-proxy.test", addr);

        let err = guarded_get(
            &reqwest::Client::builder().build().unwrap(),
            &format!("http://use-proxy.test:{}/feed.xml", addr.port()),
            &[],
        )
        .await
        .expect_err("a 305 was returned to the caller instead of refused");

        let msg = format!("{err:#}");
        assert!(
            msg.contains("305") && msg.contains("no single target"),
            "refused, but not as an unfollowable status: {msg}",
        );
        // Refused at the first hop: the proxy it named was never contacted.
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    /// **A `304 Not Modified` must reach the caller, not be read as a redirect.**
    ///
    /// `is_redirection()` is `300..=399`, so 304 — which carries no `Location`
    /// by definition — fell into the redirect branch and failed the whole fetch
    /// with "redirect response without a usable Location header". `feed.rs`
    /// sends `If-None-Match`/`If-Modified-Since` on every poll and has a correct
    /// 304 branch (`feed.rs`, `status == StatusCode::NOT_MODIFIED`) that could
    /// never be reached, so every feed answering "unchanged" was recorded as a
    /// failure and backed off exponentially.
    ///
    /// This was not theoretical: production logged it against `9to5mac.com`,
    /// `proton.me` and `kodi.tv`, and `/stats` reported 68 of 111 feeds failing
    /// while its own copy explained them away as "usually gone rather than
    /// flaky". Re-running the poller's conditional GET by hand returned
    /// `HTTP 304` with zero `Location` headers.
    ///
    /// The hop count is asserted too: a 304 must not provoke a second request.
    /// Returning the response but still looping would satisfy a status-only
    /// assertion while re-fetching every unchanged feed.
    #[tokio::test]
    async fn a_304_reaches_the_caller_instead_of_being_read_as_a_redirect() {
        let (addr, log) = spawn_http(vec![not_modified_304()]).await;
        test_host_override("not-modified.test", addr);

        let resp = guarded_get(
            &reqwest::Client::builder().build().unwrap(),
            &format!("http://not-modified.test:{}/feed.xml", addr.port()),
            &[],
        )
        .await
        .expect("a 304 was treated as a redirect");

        assert_eq!(
            resp.status(),
            reqwest::StatusCode::NOT_MODIFIED,
            "the 304 did not survive the guard intact",
        );
        assert_eq!(
            log.lock().unwrap().len(),
            1,
            "a 304 caused more than one request — it was followed, not returned",
        );
    }

    /// **A real redirect is still followed** — the other half of the narrowing
    /// above, which would otherwise be satisfied by never following anything.
    #[tokio::test]
    async fn a_302_is_still_followed_after_the_304_narrowing() {
        let (b_addr, _b_log) = spawn_http(vec![ok_200()]).await;
        test_host_override("still-follows-b.test", b_addr);
        let (a_addr, a_log) = spawn_http(vec![redirect_to(&format!(
            "http://still-follows-b.test:{}/final",
            b_addr.port()
        ))])
        .await;
        test_host_override("still-follows-a.test", a_addr);

        let resp = guarded_get(
            &reqwest::Client::builder().build().unwrap(),
            &format!("http://still-follows-a.test:{}/feed.xml", a_addr.port()),
            &[],
        )
        .await
        .expect("the 302 was not followed");

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(a_log.lock().unwrap().len(), 1);
    }

    /// **A redirect to a forbidden address is refused — the marquee SSRF
    /// property, and until now it had no end-to-end test.**
    ///
    /// `guarded_get_refuses_private_redirect_target` builds a 302 stub and then
    /// throws it away (`let _ = addr;`), asserting on a private URL passed in
    /// directly. Nothing drove a redirect through the guard, and a mutation that
    /// validated only the first hop — resolving redirect targets with a bare
    /// `lookup_host` and no `is_forbidden_ip` — left all 679 tests passing.
    ///
    /// Here a real server really 302s to the cloud metadata endpoint. Only the
    /// test server's own host is exempted from the IP check; the redirect target
    /// is an IP literal and goes through the real one.
    #[tokio::test]
    async fn a_redirect_to_a_forbidden_address_is_refused() {
        let (addr, log) = spawn_http(vec![redirect_to(
            "http://169.254.169.254/latest/meta-data/",
        )])
        .await;
        test_host_override("hop-forbidden.test", addr);

        let err = guarded_get(
            &reqwest::Client::builder().build().unwrap(),
            &format!("http://hop-forbidden.test:{}/feed.xml", addr.port()),
            &[],
        )
        .await
        .expect_err("a 302 to the metadata endpoint was followed");

        let msg = format!("{err:#}");
        assert!(
            msg.contains("169.254.169.254") && msg.contains("forbidden"),
            "refused, but not by the address check: {msg}",
        );
        // The hop happened; the SECOND hop is what was stopped.
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    /// **Credentials do not follow a redirect off the original origin.**
    ///
    /// `hop_headers` is tested as a pure function; nothing tested that
    /// `guarded_get_inner` actually calls it. Swapping the call for a plain
    /// `extra_headers` — so a bearer token rides to whatever host an upstream
    /// names — left the whole suite green.
    ///
    /// Two real servers on two hosts. The first 302s to the second; the second
    /// records what it was sent.
    #[tokio::test]
    async fn credentials_are_dropped_when_a_redirect_leaves_the_origin() {
        let (b_addr, b_log) = spawn_http(vec![ok_200()]).await;
        test_host_override("cred-b.test", b_addr);
        let (a_addr, _a_log) = spawn_http(vec![redirect_to(&format!(
            "http://cred-b.test:{}/next",
            b_addr.port()
        ))])
        .await;
        test_host_override("cred-a.test", a_addr);

        let resp = guarded_get(
            &reqwest::Client::builder().build().unwrap(),
            &format!("http://cred-a.test:{}/feed.xml", a_addr.port()),
            &[(
                HeaderName::from_static("authorization"),
                HeaderValue::from_static("Bearer super-secret"),
            )],
        )
        .await
        .expect("the cross-origin hop should still succeed, just without the token");
        assert!(resp.status().is_success());

        let seen = b_log.lock().unwrap().join("\n").to_ascii_lowercase();
        // **Anchor the two negatives below.** `!contains` is satisfied by the
        // header being absent OR by the capture being short, and those are
        // indistinguishable from here. Asserting the hop was recorded at all
        // means an empty or truncated capture fails loudly instead of reading
        // as a pass — which, for a check about not leaking a bearer token
        // across origins, is the difference that matters.
        assert!(
            seen.contains("get /next"),
            "hop B recorded no request, so the assertions below prove nothing:\n{seen}",
        );
        assert!(
            !seen.contains("super-secret"),
            "the bearer token was forwarded across origins:\n{seen}",
        );
        assert!(
            !seen.contains("authorization:"),
            "the Authorization header survived a cross-origin redirect:\n{seen}",
        );
    }

    /// **...but they DO survive a same-origin redirect.**
    ///
    /// The other direction, without which the test above is satisfied by a guard
    /// that strips every header always — which would quietly break every
    /// authenticated fetch in the app.
    ///
    /// A RELATIVE `Location` keeps the hop on the same origin without the
    /// response needing to know its own port.
    #[tokio::test]
    async fn credentials_survive_a_same_origin_redirect() {
        let (addr, log) = spawn_http(vec![redirect_to("/second"), ok_200()]).await;
        test_host_override("cred-same.test", addr);

        let resp = guarded_get(
            &reqwest::Client::builder().build().unwrap(),
            &format!("http://cred-same.test:{}/feed.xml", addr.port()),
            &[(
                HeaderName::from_static("authorization"),
                HeaderValue::from_static("Bearer keep-me"),
            )],
        )
        .await
        .expect("a same-origin redirect should be followed");
        assert!(resp.status().is_success());

        let reqs = log.lock().unwrap().clone();
        assert_eq!(reqs.len(), 2, "the redirect was not followed");
        assert!(
            reqs[1].to_ascii_lowercase().contains("keep-me"),
            "the token was stripped on a SAME-origin redirect — over-stripping \
             would break every authenticated fetch:\n{}",
            reqs[1],
        );
    }

    /// **Every DNS answer is checked, not just the first.**
    ///
    /// A host that publishes `1.2.3.4, 127.0.0.1` must be rejected wholesale.
    /// Checking only the first answer left the suite green, because nothing
    /// exercised a multi-answer set — real DNS in a test cannot be made to
    /// return one.
    #[test]
    fn a_mixed_dns_answer_set_is_rejected_wholesale() {
        let public: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let private: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let link_local: SocketAddr = "169.254.169.254:80".parse().unwrap();

        // All public: the first is pinned.
        assert_eq!(
            first_vetted(
                "ok.example",
                [public, "5.6.7.8:80".parse().unwrap()].into_iter()
            )
            .unwrap(),
            public,
        );
        // A forbidden answer ANYWHERE rejects the set — including last, which is
        // exactly what a first-answer-only check would miss.
        for bad in [private, link_local] {
            assert!(
                first_vetted("evil.example", [public, bad].into_iter()).is_err(),
                "{bad} in the answer set was accepted because a good answer came first",
            );
            assert!(first_vetted("evil.example", [bad, public].into_iter()).is_err());
        }
        // No answers at all is an error, not a silent pass.
        assert!(first_vetted("empty.example", std::iter::empty()).is_err());
    }

    /// **The capture must hold the whole request, not the first 8 KB of it.**
    ///
    /// `spawn_http` recorded one `sock.read()` into a fixed 8 KB buffer and
    /// treated that as the request. Anything past it was never captured — and
    /// never seen by the assertions that read the capture.
    ///
    /// That matters because the assertions downstream are NEGATIVE:
    /// `credentials_are_dropped_when_a_redirect_leaves_the_origin` checks
    /// `!seen.contains("authorization:")`. A short capture satisfies that exactly
    /// as well as a stripped header does, and the two are indistinguishable.
    ///
    /// A body larger than the buffer makes the truncation deterministic rather
    /// than waiting on TCP segmentation, which is why this test can go red at
    /// all.
    #[tokio::test]
    async fn the_request_capture_is_not_truncated_at_the_buffer_size() {
        let (addr, log) = spawn_http(vec![ok_200()]).await;
        test_host_override("big-body.test", addr);

        // Comfortably past the old 8 KB read, with a sentinel at the very end.
        let filler = "x".repeat(32 * 1024);
        let body = format!("{{\"pad\":\"{filler}\",\"tail\":\"THE-LAST-BYTES\"}}");

        // Not `let _ =`: a refused POST leaves the capture empty, and
        // "captured no request at all" would be the only symptom with the
        // cause thrown away.
        guarded_post_json(
            &reqwest::Client::builder().build().unwrap(),
            &format!("http://big-body.test:{}/ingest", addr.port()),
            &[],
            body.into_bytes(),
        )
        .await
        .expect("the POST to the test server failed before anything was captured");

        let seen = log.lock().unwrap().join("\n");
        // Positive anchor first: without it, the tail assertion below could pass
        // vacuously on an empty capture in some future refactor.
        assert!(
            seen.contains("POST /ingest"),
            "the server captured no request at all: {} bytes",
            seen.len()
        );
        assert!(
            seen.contains("THE-LAST-BYTES"),
            "the capture stops short of the request's end, so every negative \
             assertion over it — including the one about not leaking an \
             Authorization header across origins — can pass for the wrong \
             reason. captured {} bytes",
            seen.len()
        );
    }

    // ── TLS test server ──────────────────────────────────────────────────────

    /// **The chain really validates — no invalid-cert acceptance anywhere.**
    ///
    /// The foundation every test below rests on. If this passed because
    /// validation were disabled rather than because the CA is trusted, none of
    /// the others would mean anything, so it is asserted directly: a host the
    /// leaf has NO SAN for must still fail.
    #[tokio::test]
    async fn the_test_ca_is_trusted_and_still_validates_hostnames() {
        let (addr, _log) = spawn_tls(|_| {
            let mut r = std::collections::HashMap::new();
            r.insert("/ok".to_string(), vec![TestResponse::json(200, "{}")]);
            r
        })
        .await;
        test_host_override("feed-tls.test", addr);
        // Registered, resolvable — but NOT in the leaf's SAN list.
        test_host_override("not-in-san.test", addr);

        let client = reqwest::Client::builder().build().unwrap();
        let ok = guarded_get(
            &client,
            &format!("https://feed-tls.test:{}/ok", addr.port()),
            &[],
        )
        .await
        .expect("a SAN-matching https host should be accepted");
        assert!(ok.status().is_success());

        let err = guarded_get(
            &client,
            &format!("https://not-in-san.test:{}/ok", addr.port()),
            &[],
        )
        .await
        .expect_err("a host with no SAN must still fail: validation is NOT disabled");
        // **Assert the CERTIFICATE reason, not merely that it failed.**
        //
        // An earlier version accepted `msg.contains("name")`, which the DNS error
        // `nodename nor servname provided` also satisfies — so deleting the
        // `test_host_override` line above made this pass while proving nothing
        // about SAN validation. Verified: it did.
        let msg = format!("{err:#}").to_ascii_lowercase();
        assert!(
            msg.contains("notvalidforname") || msg.contains("invalid peer certificate"),
            "failed, but not because the certificate is invalid for this name — a \
             DNS or connect failure would prove nothing here: {msg}",
        );
    }
}
