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
pub async fn did_from_dns(resolver: &TokioResolver, handle: &str) -> Result<Option<String>> {
    let name = format!("_atproto.{handle}");
    let lookup = match resolver.txt_lookup(&name).await {
        Ok(lookup) => lookup,
        // NXDOMAIN and friends are "no record", not a failure: the well-known
        // route is the documented alternative.
        Err(_) => return Ok(None),
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
    if let Some(did) = did_from_dns(resolver, handle).await? {
        return Ok(did);
    }
    did_from_well_known(http, handle).await
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
        let claimed = identity::declared_handle(&document);
        // The reverse round trip. A document can claim any handle; only the
        // handle's own DNS/well-known record can confirm it.
        let handle = match &claimed {
            Some(handle) => match did_for_handle(resolver, http, handle).await {
                Ok(did) if did == subject => claimed.clone(),
                _ => None,
            },
            None => None,
        };
        return Ok(ResolvedAccount {
            pds_url: identity::pds_endpoint(&document, subject)?,
            did: subject.to_string(),
            handle,
        });
    }

    let handle = identity::normalize_handle(subject)?;
    let did = did_for_handle(resolver, http, &handle).await?;
    let document = did_document(http, &did, plc_directory).await?;
    // Mandatory: the document must claim the handle we started from.
    identity::verify_handle_claim(&document, &handle)?;
    Ok(ResolvedAccount {
        pds_url: identity::pds_endpoint(&document, &did)?,
        did,
        handle: Some(handle),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A handle that does not exist must be reported as absent, not as an
    /// error — the well-known route is the documented fallback and has to be
    /// reachable.
    #[tokio::test]
    async fn a_missing_txt_record_is_absent_rather_than_an_error() {
        let resolver = resolver().unwrap();
        let result = did_from_dns(&resolver, "nonexistent-handle.invalid").await;
        assert!(matches!(result, Ok(None)), "got {result:?}");
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
}
