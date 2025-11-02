//! Helper functions for resolving keys from JWKS

#[cfg(feature = "remote")]
use crate::algorithm::AlgorithmId;
#[cfg(feature = "remote")]
use crate::discovery::{discover_jwks_uri, discover_jwks_uri_cached};
#[cfg(feature = "remote")]
use crate::error::{Error, Result};
#[cfg(feature = "remote")]
use crate::jwks::{fetch_jwks, fetch_jwks_cached, find_key_by_kid, JwkSet};
#[cfg(feature = "remote")]
use crate::keys::Key;
#[cfg(feature = "remote")]
use crate::remote::http::HttpClient;

/// Resolve a key from an issuer using OIDC discovery and JWKS fetching
///
/// This is a convenience function that combines the separate steps:
/// 1. Discover JWKS URI via OIDC discovery
/// 2. Fetch JWKS document
/// 3. Find key by kid (if present in token header)
/// 4. Convert JWK to Key
///
/// Users can also call these steps separately for more control (Q16-B).
///
/// # Arguments
///
/// * `client` - HTTP client for fetching
/// * `issuer` - The issuer URL
/// * `algorithm` - The algorithm from the token header
/// * `kid` - Optional key ID from the token header
/// * `use_cache` - Whether to use cached discovery and JWKS documents
///
/// # Errors
///
/// Returns `Error::RemoteError` with component-prefixed messages.
///
/// # Example
///
/// ```ignore
/// use jwtiny::jwks::resolve_key_from_issuer;
/// use jwtiny::remote::HttpClient;
///
/// let client = /* your HTTP client */;
/// let key = resolve_key_from_issuer(
///     &client,
///     "https://auth.example.com",
///     &AlgorithmId::RS256,
///     Some("key-id"),
///     true
/// ).await?;
/// ```
#[cfg(feature = "remote")]
pub async fn resolve_key_from_issuer(
    client: &HttpClient,
    issuer: &str,
    algorithm: &AlgorithmId,
    kid: Option<&str>,
    use_cache: bool,
) -> Result<Key> {
    // Step 1: Discover JWKS URI
    let jwks_uri = if use_cache {
        discover_jwks_uri_cached(issuer, client).await?
    } else {
        discover_jwks_uri(issuer, client).await?
    };

    // Step 2: Fetch JWKS
    let jwks: JwkSet = if use_cache {
        fetch_jwks_cached(client, &jwks_uri).await?
    } else {
        fetch_jwks(client, &jwks_uri).await?
    };

    // Step 3: Find key by kid
    let jwk = find_key_by_kid(&jwks, kid)
        .ok_or_else(|| Error::RemoteError("jwks: no matching key found".to_string()))?;

    // Step 4: Convert to Key
    jwk.to_key(algorithm)
}
