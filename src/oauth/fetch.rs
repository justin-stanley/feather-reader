//! Fetching the JSON documents OAuth discovery depends on.
//!
//! Three rules apply to every document here, and each exists because the
//! reference client enforces it:
//!
//! * **No redirects.** The mix-up defence compares a document's `issuer` against
//!   the URL it was fetched from; a `302` would make that comparison meaningless
//!   while still appearing to pass. See [`crate::net::guarded_get_no_redirect`].
//! * **Status exactly 200.** Not "2xx", not "whatever parsed". A `204` or a `206`
//!   is not a metadata document.
//! * **Content type must be JSON.** A server answering `text/html` is not
//!   serving the document we asked for, whatever the bytes happen to parse as.
//!
//! On top of the SSRF guard and the body cap those bring with them.

use anyhow::{bail, Context as _, Result};
use reqwest::Client;
use serde_json::Value;

use crate::net;

/// Content types accepted for OAuth metadata documents.
pub const JSON: &[&str] = &["application/json"];

/// Content types accepted for DID documents. `did+ld+json` is what
/// `plc.directory` actually serves.
pub const DID_JSON: &[&str] = &[
    "application/json",
    "application/did+ld+json",
    "application/did+json",
];

/// Validate a response's status and content type before its body is trusted.
///
/// Split out from the fetch so it is testable without a network: this is the
/// part with the rules in it.
fn check_meta(status: u16, content_type: Option<&str>, allowed: &[&str]) -> Result<()> {
    if status != 200 {
        bail!("expected status 200, got {status}");
    }
    let Some(raw) = content_type else {
        bail!("response has no Content-Type; refusing to parse it as JSON");
    };
    // `application/json; charset=utf-8` — compare only the media type, and
    // case-insensitively (RFC 9110 §8.3.1 makes it case-insensitive).
    let media = raw
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !allowed.iter().any(|a| *a == media) {
        bail!("unexpected Content-Type {media:?}; expected one of {allowed:?}");
    }
    Ok(())
}

/// Fetch a JSON document, requiring 200 and an acceptable content type.
pub async fn get_json(client: &Client, url: &str, allowed: &[&str]) -> Result<Value> {
    get_json_optional(client, url, allowed)
        .await?
        .with_context(|| format!("document not found at {url}"))
}

/// As [`get_json`], but a `404` means **absent** rather than failed.
///
/// `/.well-known/oauth-protected-resource` legitimately does not exist on some
/// hosts, and "absent" is a different answer from "the fetch went wrong".
pub async fn get_json_optional(
    client: &Client,
    url: &str,
    allowed: &[&str],
) -> Result<Option<Value>> {
    let resp = net::guarded_get_no_redirect(client, url, &[])
        .await
        .with_context(|| format!("fetching {url}"))?;

    let status = resp.status().as_u16();
    if status == 404 {
        return Ok(None);
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    check_meta(status, content_type.as_deref(), allowed)
        .with_context(|| format!("fetching {url}"))?;

    let body = net::read_capped(resp)
        .await
        .with_context(|| format!("reading {url}"))?;
    let value =
        serde_json::from_slice(&body).with_context(|| format!("{url} is not valid JSON"))?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_200_with_json_is_accepted() {
        assert!(check_meta(200, Some("application/json"), JSON).is_ok());
    }

    /// Parameters and casing are both legal on a real content type.
    #[test]
    fn the_media_type_is_compared_without_parameters_or_case() {
        for ct in [
            "application/json; charset=utf-8",
            "application/json;charset=UTF-8",
            "APPLICATION/JSON",
            "  application/json  ",
        ] {
            assert!(check_meta(200, Some(ct), JSON).is_ok(), "rejected {ct:?}");
        }
    }

    /// A server answering HTML is not serving the document we asked for, even if
    /// the bytes would happen to parse.
    #[test]
    fn a_non_json_content_type_is_rejected() {
        for ct in [
            "text/html",
            "text/plain",
            "application/xml",
            "application/jsonp",
            "application/json-seq",
        ] {
            assert!(check_meta(200, Some(ct), JSON).is_err(), "accepted {ct:?}");
        }
    }

    #[test]
    fn a_missing_content_type_is_rejected() {
        assert!(check_meta(200, None, JSON).is_err());
    }

    /// Exactly 200 — a redirect reaching here at all would mean the no-redirect
    /// guard failed, and 2xx-but-not-200 is not a metadata document.
    #[test]
    fn only_status_200_is_accepted() {
        for status in [201u16, 204, 206, 301, 302, 400, 401, 403, 500] {
            assert!(
                check_meta(status, Some("application/json"), JSON).is_err(),
                "accepted status {status}"
            );
        }
    }

    /// DID documents are served as `did+ld+json` by plc.directory; metadata
    /// documents must NOT be.
    #[test]
    fn the_allowed_set_is_per_document_kind() {
        assert!(check_meta(200, Some("application/did+ld+json"), DID_JSON).is_ok());
        assert!(check_meta(200, Some("application/json"), DID_JSON).is_ok());
        assert!(check_meta(200, Some("application/did+ld+json"), JSON).is_err());
    }

    /// These fetches must fail closed on an internal target like every other
    /// outbound call.
    ///
    /// Asserts on the GUARD's error rather than `is_err()`: connecting to
    /// `127.0.0.1` fails regardless, so an `is_err()`-only assertion would pass
    /// with the SSRF guard removed entirely.
    #[tokio::test]
    async fn discovery_fetches_fail_closed_on_internal_targets() {
        let client = Client::new();
        for url in [
            "http://127.0.0.1/.well-known/oauth-authorization-server",
            "http://169.254.169.254/.well-known/oauth-protected-resource",
            "http://10.1.2.3/did.json",
        ] {
            for rendered in [
                format!(
                    "{:#}",
                    get_json(&client, url, JSON).await.expect_err("allowed")
                ),
                format!(
                    "{:#}",
                    get_json_optional(&client, url, JSON)
                        .await
                        .expect_err("allowed")
                ),
            ] {
                assert!(
                    rendered.contains("forbidden (internal) address"),
                    "{url} failed for the wrong reason: {rendered}"
                );
            }
        }
    }
}
