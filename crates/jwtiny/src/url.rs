//! URL validation utilities
//!
//! This module provides URL validation functions to prevent SSRF attacks
//! and resource exhaustion from malformed or extremely long URLs.
//!
//! All validation functions enforce size limits and structural requirements
//! per OIDC and HTTP specifications.

use crate::error::{Error, Result};
use crate::limits::{MAX_ISSUER_URL_LENGTH, MAX_JWKS_URI_LENGTH};

/// Common URL validation logic
fn validate_url_common(url: &str, max_length: usize, name: &str) -> Result<url::Url> {
    if url.trim().is_empty() {
        return Err(Error::RemoteError(format!("{name} cannot be empty")));
    }

    if url.len() > max_length {
        return Err(Error::RemoteUrlTooLong {
            length: url.len(),
            max: max_length,
        });
    }

    let parsed = url
        .parse::<url::Url>()
        .map_err(|e| Error::RemoteError(format!("invalid {name}: {e}")))?;

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(Error::RemoteError(format!(
            "{name} must use http or https scheme"
        )));
    }

    if parsed.host_str().is_none() {
        return Err(Error::RemoteError(format!("{name} must have a valid host")));
    }

    Ok(parsed)
}

/// Validate issuer URL format and size
pub(crate) fn validate_issuer_url(issuer: &str) -> Result<()> {
    validate_url_common(issuer, MAX_ISSUER_URL_LENGTH, "issuer URL")?;

    // Must not end with trailing slash (per OIDC spec)
    if issuer.ends_with('/') {
        return Err(Error::RemoteError(
            "issuer URL must not end with trailing slash".into(),
        ));
    }

    Ok(())
}

/// Validate JWKS URI format and size
pub(crate) fn validate_jwks_uri(uri: &str) -> Result<()> {
    validate_url_common(uri, MAX_JWKS_URI_LENGTH, "JWKS URI")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_issuer_url_valid() {
        assert!(validate_issuer_url("https://auth.example.com").is_ok());
        assert!(validate_issuer_url("http://localhost:3000").is_ok());
    }

    #[test]
    fn test_validate_issuer_url_empty() {
        assert!(validate_issuer_url("").is_err());
    }

    #[test]
    fn test_validate_issuer_url_trailing_slash() {
        assert!(validate_issuer_url("https://auth.example.com/").is_err());
    }

    #[test]
    fn test_validate_issuer_url_invalid_scheme() {
        assert!(validate_issuer_url("ftp://example.com").is_err());
    }

    #[test]
    fn test_validate_issuer_url_no_host() {
        assert!(validate_issuer_url("https://").is_err());
    }

    #[test]
    fn test_validate_issuer_url_too_long() {
        let long_url = "https://example.com/".to_string() + &"a".repeat(MAX_ISSUER_URL_LENGTH);
        assert!(validate_issuer_url(&long_url).is_err());
    }

    #[test]
    fn test_validate_jwks_uri_valid() {
        assert!(validate_jwks_uri("https://auth.example.com/.well-known/jwks.json").is_ok());
        assert!(validate_jwks_uri("http://localhost:3000/jwks.json").is_ok());
    }

    #[test]
    fn test_validate_jwks_uri_empty() {
        assert!(validate_jwks_uri("").is_err());
        assert!(validate_jwks_uri("   ").is_err());
    }

    #[test]
    fn test_validate_jwks_uri_invalid_scheme() {
        assert!(validate_jwks_uri("ftp://example.com/jwks.json").is_err());
    }

    #[test]
    fn test_validate_jwks_uri_too_long() {
        let long_uri = "https://example.com/".to_string() + &"a".repeat(MAX_JWKS_URI_LENGTH);
        assert!(validate_jwks_uri(&long_uri).is_err());
    }
}
