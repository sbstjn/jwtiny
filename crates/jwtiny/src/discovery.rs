//! OIDC Discovery module
//!
//! This module provides functionality for OpenID Connect Discovery as defined
//! in the [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
//! specification. It fetches issuer metadata and resolves JWKS URIs from
//! `/.well-known/openid-configuration` endpoints.

use crate::error::{Error, Result};
use crate::jwks::fetch_url;
use crate::limits::MAX_DISCOVERY_RESPONSE_SIZE;
use crate::url::{validate_issuer_url, validate_jwks_uri};
use miniserde::Deserialize;

/// Minimal OIDC discovery document containing the JWKS URI
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OidcDiscovery {
    /// The JWKS URI from the discovery document
    #[serde(rename = "jwks_uri")]
    pub jwks_uri: String,
}

/// Build the URL to the discovery document from an issuer string
fn build_well_known_url(issuer: &str) -> Result<String> {
    let base = issuer.trim_end_matches('/');

    if base.is_empty() {
        return Err(Error::RemoteError("discovery: empty issuer".into()));
    }

    Ok(format!("{base}/.well-known/openid-configuration"))
}

/// Discover the JWKS URI using the OIDC well-known configuration
///
/// This function does not cache results. Caching is handled at the public key level
/// in the resolver, so discovery only happens when a cached key is missing or expired.
pub(crate) async fn discover_jwks_uri(issuer: &str, client: &reqwest::Client) -> Result<String> {
    // Validate issuer URL before fetching to prevent SSRF attacks
    validate_issuer_url(issuer)?;

    let url = build_well_known_url(issuer)?;
    let bytes = fetch_url(client, &url).await?;

    // Validate response size before parsing to prevent resource exhaustion
    if bytes.len() > MAX_DISCOVERY_RESPONSE_SIZE {
        return Err(Error::RemoteResponseTooLarge {
            size: bytes.len(),
            max: MAX_DISCOVERY_RESPONSE_SIZE,
        });
    }

    let body = std::str::from_utf8(&bytes)
        .map_err(|e| Error::RemoteError(format!("discovery: utf8 decode failed: {e}")))?;

    let doc: OidcDiscovery = miniserde::json::from_str(body)
        .map_err(|_| Error::RemoteError("discovery: invalid discovery json".into()))?;

    if doc.jwks_uri.trim().is_empty() {
        return Err(Error::RemoteError(
            "discovery: missing or empty jwks_uri".into(),
        ));
    }

    // Check if JWKS URI is valid and within bounds
    validate_jwks_uri(&doc.jwks_uri)?;

    Ok(doc.jwks_uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_build_well_known_url() {
        assert_eq!(
            build_well_known_url("https://issuer.example"),
            Ok("https://issuer.example/.well-known/openid-configuration".to_string())
        );
        assert_eq!(
            build_well_known_url("https://issuer.example/"),
            Ok("https://issuer.example/.well-known/openid-configuration".to_string())
        );
        assert!(build_well_known_url("").is_err());
    }

    #[tokio::test]
    async fn test_discover_jwks_uri() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_body(r#"{ "jwks_uri": "https://issuer.example/.well-known/jwks.json" }"#)
            .create();

        let client = reqwest::Client::new();
        let issuer = server.url();

        let uri = discover_jwks_uri(&issuer, &client).await.expect("discover");
        assert_eq!(uri, "https://issuer.example/.well-known/jwks.json");
        mock.assert();
    }

    #[tokio::test]
    async fn test_discover_jwks_uri_empty() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_body(r#"{ "jwks_uri": "" }"#)
            .create();

        let client = reqwest::Client::new();
        let issuer = server.url();

        let result = discover_jwks_uri(&issuer, &client).await;
        assert!(
            matches!(result, Err(Error::RemoteError(msg)) if msg.contains("missing or empty jwks_uri"))
        );
    }

    #[tokio::test]
    async fn test_discover_jwks_uri_invalid_json() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_body(b"{ invalid json }")
            .create();

        let client = reqwest::Client::new();
        let issuer = server.url();

        let result = discover_jwks_uri(&issuer, &client).await;
        assert!(
            matches!(result, Err(Error::RemoteError(msg)) if msg.contains("discovery: invalid discovery json"))
        );
    }

    #[tokio::test]
    async fn test_discover_jwks_uri_oversized_response() {
        use crate::limits::MAX_DISCOVERY_RESPONSE_SIZE;

        let mut server = mockito::Server::new_async().await;
        let oversized_response = "a".repeat(MAX_DISCOVERY_RESPONSE_SIZE + 1);
        let _mock = server
            .mock("GET", "/.well-known/openid-configuration")
            .with_status(200)
            .with_body(oversized_response)
            .create();

        let client = reqwest::Client::new();
        let issuer = server.url();

        let result = discover_jwks_uri(&issuer, &client).await;
        assert!(matches!(
            result,
            Err(Error::RemoteResponseTooLarge { size, max }) if size > max && max == MAX_DISCOVERY_RESPONSE_SIZE
        ));
    }

    #[tokio::test]
    async fn test_discover_jwks_uri_invalid_url() {
        let client = reqwest::Client::new();

        // Test with invalid URL (trailing slash) - should be rejected by validation
        let issuer_with_slash = "https://example.com/";
        let result = discover_jwks_uri(issuer_with_slash, &client).await;
        assert!(matches!(result, Err(Error::RemoteError(msg)) if msg.contains("trailing slash")));

        // Test with URL that's too long
        use crate::limits::MAX_ISSUER_URL_LENGTH;
        let long_url = format!("https://example.com/{}", "a".repeat(MAX_ISSUER_URL_LENGTH));
        let result = discover_jwks_uri(&long_url, &client).await;
        assert!(matches!(result, Err(Error::RemoteUrlTooLong { .. })));
    }
}
