//! Helper functions for resolving keys from JWKS

use crate::algorithm::AlgorithmType;
use crate::discovery::discover_jwks_uri;
use crate::error::Result;
use crate::jwks::{JwkSet, fetch_jwks, find_key_by_kid};
use crate::utils::bounds::is_valid_cache_key;
use moka::future::Cache;
use std::sync::Arc;

/// Resolve a key from an issuer using OIDC discovery and JWKS fetching
pub(crate) async fn resolve_key_from_issuer(
    client: &reqwest::Client,
    issuer: &str,
    algorithm: &AlgorithmType,
    kid: Option<&str>,
    cache: Option<Arc<Cache<String, Vec<u8>>>>,
) -> Result<Vec<u8>> {
    // Build cache key once if caching is enabled and issuer is valid
    let cache_key = if cache.is_some() && is_valid_cache_key(issuer) {
        Some(format!(
            "{}|{}|{}",
            issuer,
            algorithm.as_str(),
            kid.unwrap_or("")
        ))
    } else {
        None
    };

    // Check cache first if provided
    if let (Some(cache_ref), Some(key)) = (&cache, &cache_key) {
        if let Some(cached_key) = cache_ref.get(key).await {
            return Ok(cached_key);
        }
    }

    // Cache miss: discover JWKS URI
    let jwks_uri = discover_jwks_uri(issuer, client).await?;

    // Fetch JWKS
    let jwks: JwkSet = fetch_jwks(client, &jwks_uri).await?;

    // Find key by kid
    let jwk = find_key_by_kid(&jwks, kid)?;

    // Convert to DER-encoded RSA public key
    let key_der = jwk.to_key(algorithm, true)?;

    // Cache the final result if cache is provided
    if let (Some(cache_ref), Some(key)) = (&cache, cache_key) {
        cache_ref.insert(key, key_der.clone()).await;
    }

    Ok(key_der)
}
