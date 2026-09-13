//! Turning what a user typed into a DID, a DID document, and a PDS.
//!
//! The I/O half of [`super::identity`], which holds the decisions. Split that
//! way because the decisions are where the security properties live and they
//! are testable; this is sequencing and network calls, which are not.
//!
//! **DNS takes precedence over HTTP.** The handle spec: *"When both methods
//! return results, the DNS TXT result should be preferred."* It is not a
//! tie-break rule in practice — a real handle was found during the live spike
//! whose `/.well-known/atproto-did` returns 404 and which resolves by TXT
//! alone, so an HTTP-first implementation simply fails on it.

use anyhow::{Context as _, Result};
use hickory_resolver::TokioResolver;
use reqwest::Client;

use super::{fetch, identity};
use crate::net;

/// A resolved account: who they are and where their repo lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAccount {
    pub did: String,
    pub pds_url: String,
    /// The handle, only when it was verified bidirectionally. `None` for a
    /// DID-first login whose handle did not round-trip — it must not be
    /// displayed as though it were confirmed.
    pub handle: Option<String>,
}

/// Build the DNS resolver from the host's own configuration.
pub fn resolver() -> Result<TokioResolver> {
    let builder = TokioResolver::builder_tokio().context("reading the system DNS configuration")?;
    builder.build().context("building the DNS resolver")
}

/// Look up `_atproto.<handle>` and return the DID it claims.
///
/// `Ok(None)` means no usable record, which falls through to the well-known
/// lookup. An error means records exist but are unusable — two different `did=`
/// values, say — which must NOT fall through, because resolving a handle two
/// ways and taking whichever answers is how you resolve to the wrong account.
/// Whether a resolver error means "this name has no such record", as opposed to
/// a failure to find out which.
fn is_no_records(err: &hickory_resolver::net::NetError) -> bool {
    matches!(
        err,
        hickory_resolver::net::NetError::Dns(hickory_resolver::net::DnsError::NoRecordsFound(_))
    )
}

/// The name to query, **fully qualified**.
///
/// The trailing dot is load-bearing. hickory's `build_names` short-circuits only
/// on `is_fqdn()`; without it, the host's `search` domains are appended and
/// `_atproto.victim.example` is also queried as
/// `_atproto.victim.example.<search-domain>`. Whoever controls that domain can
/// then answer for any handle that has no TXT record of its own — and because
/// DNS is tried first, the well-known lookup never runs, so the substitution is
/// total. Kubernetes always sets a search domain; so do most LANs.
///
/// Node's `dns.resolveTxt` issues the name as given (c-ares does not apply the
/// search list), which is why the reference implementation never needed this.
fn txt_query_name(handle: &str) -> String {
    format!("_atproto.{}.", handle.trim_end_matches('.'))
}

pub async fn did_from_dns(resolver: &TokioResolver, handle: &str) -> Result<Option<String>> {
    let name = txt_query_name(handle);
    let lookup = match resolver.txt_lookup(&name).await {
        Ok(lookup) => lookup,
        // ONLY "no records" is absence. Everything else — SERVFAIL, timeout,
        // refused, a name too long to construct — is a failure and must NOT
        // fall through to the well-known path: an attacker who can induce a
        // resolver error would otherwise choose which of the two mechanisms
        // answers, and the HTTP one is the weaker.
        Err(err) if is_no_records(&err) => return Ok(None),
        Err(err) => {
            return Err(anyhow::Error::new(err))
                .with_context(|| format!("resolving the {name} TXT record"))
        }
    };

    // One joined value per RECORD. A record's character-strings concatenate;
    // flattening them into separate records would split a long DID in half.
    let records: Vec<String> = lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::TXT(txt) => Some(txt),
            _ => None,
        })
        .map(|txt| {
            let chunks: Vec<&[u8]> = txt.txt_data.iter().map(|c| c.as_ref()).collect();
            identity::join_txt_chunks(&chunks)
        })
        .collect();

    identity::did_from_txt_records(&records)
        .with_context(|| format!("reading the {name} TXT record"))
}

/// Look up `/.well-known/atproto-did`.
///
/// The one fetch in this module where redirects ARE permitted: the handle spec
/// allows them explicitly, unlike the metadata and DID documents.
async fn did_from_well_known(http: &Client, handle: &str) -> Result<String> {
    let url = format!("https://{handle}/.well-known/atproto-did");
    let response = net::guarded_get_no_privacy(http, &url, &[])
        .await
        .with_context(|| format!("fetching {url}"))?;
    let status = response.status().as_u16();
    if status != 200 {
        anyhow::bail!("{url} returned status {status}");
    }
    let body = net::read_capped(response).await?;
    identity::did_from_well_known(&String::from_utf8_lossy(&body))
        .with_context(|| format!("reading {url}"))
}

/// Resolve a handle to a DID: DNS first, then well-known.
pub async fn did_for_handle(
    resolver: &TokioResolver,
    http: &Client,
    handle: &str,
) -> Result<String> {
    let dns = did_from_dns(resolver, handle).await?;
    prefer_dns(dns, || did_from_well_known(http, handle)).await
}

/// Apply the precedence rule: DNS wins, and the well-known lookup runs **only**
/// when DNS returned no record at all.
///
/// `well_known` is a closure rather than a value so the property that matters is
/// observable: that it is never CALLED when DNS answered. With the two lookups
/// inline, swapping their order passed the whole suite — the rule was documented
/// in the module header and pinned by nothing.
///
/// Note what the caller has already done: `did_from_dns` returns `Err` for a
/// resolver FAILURE and `Ok(None)` only for a genuine absence, so the `?` above
/// means a SERVFAIL never reaches this fallback. An attacker who can induce a
/// resolver error must not get to choose the weaker mechanism.
pub async fn prefer_dns<F, Fut>(dns: Option<String>, well_known: F) -> Result<String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    match dns {
        Some(did) => Ok(did),
        None => well_known().await,
    }
}

/// Fetch and validate a DID document.
pub async fn did_document(
    http: &Client,
    did: &str,
    plc_directory: &str,
) -> Result<serde_json::Value> {
    let url = identity::did_document_url(did, plc_directory)?;
    let document = fetch::get_json(http, &url, fetch::DID_JSON).await?;
    identity::validate_did_document(&document, did)?;
    Ok(document)
}

/// Resolve whatever the user typed into an account.
///
/// From a HANDLE, the DID document must claim that handle back — the spec calls
/// this mandatory, and without it whoever controls a DNS name can point it at
/// any DID at all.
///
/// From a DID, the document's claimed handle is only trustworthy if re-resolving
/// it returns the same DID; when it does not, the handle is reported as `None`
/// rather than displayed beside an account it may not belong to.
pub async fn resolve(
    resolver: &TokioResolver,
    http: &Client,
    subject: &str,
    plc_directory: &str,
) -> Result<ResolvedAccount> {
    if identity::is_atproto_did(subject) {
        let document = did_document(http, subject, plc_directory).await?;
        // The reverse round trip is I/O; deciding what it MEANS is not.
        let reverse = match identity::declared_handle(&document) {
            Some(handle) => did_for_handle(resolver, http, &handle).await.ok(),
            None => None,
        };
        return account_from_did(&document, subject, reverse.as_deref());
    }

    let handle = identity::normalize_handle(subject)?;
    let did = did_for_handle(resolver, http, &handle).await?;
    let document = did_document(http, &did, plc_directory).await?;
    account_from_handle(&document, &handle, &did)
}

/// The decision half of a HANDLE-first resolution.
///
/// Split out from the I/O so it can be tested: with the fetching inline, a
/// mutation that dropped the `?` from `verify_handle_claim` — deleting the
/// verification the spec calls mandatory — passed the entire suite, because
/// every test of that rule sat one layer below on `verify_handle_claim` itself
/// and nothing proved `resolve` called it.
pub fn account_from_handle(
    document: &serde_json::Value,
    handle: &str,
    did: &str,
) -> Result<ResolvedAccount> {
    // MANDATORY. Without it, whoever controls a DNS name can point it at any
    // DID at all and we would serve that account under this handle.
    identity::verify_handle_claim(document, handle)?;
    Ok(ResolvedAccount {
        pds_url: identity::pds_endpoint(document, did)?,
        did: did.to_string(),
        handle: Some(handle.to_string()),
    })
}

/// The decision half of a DID-first resolution.
///
/// `reverse` is the DID that re-resolving the document's claimed handle
/// returned, or `None` if there was no claim or the lookup failed. The handle is
/// reported ONLY when that round trip came back to the same DID — a document can
/// claim any handle it likes, and only the handle's own DNS or well-known record
/// can confirm it.
pub fn account_from_did(
    document: &serde_json::Value,
    did: &str,
    reverse: Option<&str>,
) -> Result<ResolvedAccount> {
    let claimed = identity::declared_handle(document);
    let handle = match (&claimed, reverse) {
        (Some(_), Some(back)) if back == did => claimed.clone(),
        // Claimed but unconfirmed, or never claimed: absent, not "probably
        // right". An unverified handle displayed beside an account is a lie
        // with a UI around it.
        _ => None,
    };
    Ok(ResolvedAccount {
        pds_url: identity::pds_endpoint(document, did)?,
        did: did.to_string(),
        handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The query name must be FULLY QUALIFIED.**
    ///
    /// Without the trailing dot, hickory appends the host's `search` domains
    /// (`build_names` short-circuits only on `is_fqdn()`), so
    /// `_atproto.victim.example` is ALSO queried as
    /// `_atproto.victim.example.<search-domain>`. Whoever controls that domain
    /// then answers for any handle lacking a TXT record — and since DNS is tried
    /// first, the well-known lookup never runs. Kubernetes always has a search
    /// domain; so do most corporate and home LANs.
    ///
    /// Node's `dns.resolveTxt` goes through c-ares, which issues the name as
    /// given, so the reference implementation never had this and the port
    /// acquired it silently.
    #[test]
    fn the_txt_query_name_is_fully_qualified() {
        let name = txt_query_name("alice.example.com");
        assert!(
            name.ends_with('.'),
            "not an FQDN, so the DNS search list applies: {name}"
        );
        assert_eq!(name, "_atproto.alice.example.com.");
        assert!(!name.contains(".."), "double dot in {name}");
    }

    /// A handle that does not exist must be reported as absent, not as an
    /// error — the well-known route is the documented fallback and has to be
    /// reachable.
    #[tokio::test]
    async fn a_missing_txt_record_is_absent_rather_than_an_error() {
        let resolver = resolver().unwrap();
        let result = did_from_dns(&resolver, "nonexistent-handle.invalid").await;
        assert!(matches!(result, Ok(None)), "got {result:?}");
    }

    /// **A resolver FAILURE is not "no record".** Treating every error as absent
    /// silently downgrades resolution to the HTTP path, which is the weaker of
    /// the two — and an off-path attacker who can force SERVFAIL or a timeout
    /// gets to choose that downgrade.
    ///
    /// This case needs no network manipulation: a 251-character handle passes
    /// `normalize_handle` (every label is within 63 bytes) but `_atproto.` + 251
    /// exceeds the 255-byte DNS name limit, so name construction fails before a
    /// query is ever issued.
    #[tokio::test]
    async fn a_resolver_failure_is_an_error_rather_than_absence() {
        let label = "a".repeat(60);
        let handle = format!("{label}.{label}.{label}.{label}.com");
        assert!(handle.len() > 240 && handle.len() <= 253);
        assert!(
            identity::normalize_handle(&handle).is_ok(),
            "the handle itself must be valid, or the test proves nothing"
        );

        let resolver = resolver().unwrap();
        let result = did_from_dns(&resolver, &handle).await;
        assert!(
            result.is_err(),
            "a name-construction failure was reported as 'no record': {result:?}"
        );
    }

    /// The well-known fallback still goes through the SSRF guard, asserted on
    /// the guard's own error rather than merely `is_err()`.
    #[tokio::test]
    async fn the_well_known_fallback_fails_closed_on_an_internal_host() {
        let err = did_from_well_known(&Client::new(), "127.0.0.1")
            .await
            .expect_err("must refuse a loopback handle host");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("forbidden (internal) address"),
            "failed for the wrong reason: {rendered}"
        );
    }

    /// Reserved TLDs are rejected before any lookup happens, so a `.internal`
    /// handle never becomes a DNS query at all.
    #[tokio::test]
    async fn a_reserved_tld_handle_is_refused_before_any_lookup() {
        let resolver = resolver().unwrap();
        let err = resolve(
            &resolver,
            &Client::new(),
            "alice.internal",
            "https://plc.directory",
        )
        .await
        .expect_err("must refuse a reserved TLD");
        assert!(format!("{err:#}").contains("reserved TLD"));
    }

    // ── the decisions `resolve` makes, now that they are reachable ───────────

    const SUBJECT_DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

    fn doc_claiming(handle: &str) -> serde_json::Value {
        serde_json::json!({
            "id": SUBJECT_DID,
            "alsoKnownAs": [format!("at://{handle}")],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example.com"
            }]
        })
    }

    /// **The document must claim the handle we started from.**
    ///
    /// Dropping the `?` from `verify_handle_claim` inside `resolve` passed the
    /// entire suite: every test of that rule sat on `verify_handle_claim`
    /// itself, and nothing proved the resolution path called it. Without it,
    /// whoever controls a DNS name can point it at any DID at all.
    #[test]
    fn a_handle_the_document_does_not_claim_is_refused() {
        let document = doc_claiming("someone-else.com");
        let err = account_from_handle(&document, "victim.com", SUBJECT_DID)
            .expect_err("a document that claims a different handle must be refused");
        assert!(
            format!("{err:#}").contains("victim.com"),
            "failed for the wrong reason: {err:#}"
        );

        // The matching claim still resolves.
        let ok = account_from_handle(&doc_claiming("alice.com"), "alice.com", SUBJECT_DID)
            .expect("a matching claim must resolve");
        assert_eq!(ok.handle.as_deref(), Some("alice.com"));
        assert_eq!(ok.pds_url, "https://pds.example.com");
    }

    /// **A DID-first handle is reported only when it round-trips back.**
    ///
    /// Relaxing the comparison to accept ANY reverse result passed the suite. A
    /// handle shown beside an account it does not belong to is a lie with a UI
    /// around it.
    #[test]
    fn a_did_first_handle_must_round_trip_to_the_same_did() {
        let document = doc_claiming("alice.com");

        // Came back to us: reported.
        let ok = account_from_did(&document, SUBJECT_DID, Some(SUBJECT_DID)).unwrap();
        assert_eq!(ok.handle.as_deref(), Some("alice.com"));

        // Came back to someone ELSE: withheld.
        let other = account_from_did(
            &document,
            SUBJECT_DID,
            Some("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .unwrap();
        assert_eq!(
            other.handle, None,
            "a handle that resolves to a DIFFERENT did was reported as verified"
        );

        // Did not come back at all: withheld.
        let none = account_from_did(&document, SUBJECT_DID, None).unwrap();
        assert_eq!(none.handle, None);

        // Every case still yields the PDS — withholding the handle must not
        // break the login.
        assert_eq!(none.pds_url, "https://pds.example.com");
    }

    /// **DNS wins, and the well-known lookup is not even attempted.**
    ///
    /// Swapping the order passed the whole suite. The rule is not a tie-break:
    /// a real handle was found during the live spike whose
    /// `/.well-known/atproto-did` 404s and which resolves by TXT alone, so an
    /// HTTP-first implementation simply fails on it — and the weaker mechanism
    /// must never be reachable while the stronger one has answered.
    #[tokio::test]
    async fn dns_wins_and_the_well_known_lookup_is_never_called() {
        let called = std::sync::atomic::AtomicUsize::new(0);

        let did = prefer_dns(Some(SUBJECT_DID.to_string()), || async {
            called.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_string())
        })
        .await
        .unwrap();

        assert_eq!(did, SUBJECT_DID, "the DNS answer must win");
        assert_eq!(
            called.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the well-known lookup ran even though DNS had answered"
        );
    }

    /// And it IS called when DNS found nothing — the fallback has to work.
    #[tokio::test]
    async fn the_well_known_lookup_runs_when_dns_has_no_record() {
        let did = prefer_dns(None, || async { Ok(SUBJECT_DID.to_string()) })
            .await
            .unwrap();
        assert_eq!(did, SUBJECT_DID);
    }
}
