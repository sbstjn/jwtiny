//! OIDC Discovery implementation

#[cfg(feature = "remote")]
use crate::error::{Error, Result};
#[cfg(feature = "remote")]
use crate::remote::config::DISCOVERY_TTL;
#[cfg(feature = "remote")]
use crate::remote::http::HttpClient;
#[cfg(feature = "remote")]
use miniserde::Deserialize;
#[cfg(feature = "remote")]
use std::collections::HashMap;
#[cfg(feature = "remote")]
use std::sync::{Mutex, OnceLock};
#[cfg(feature = "remote")]
use std::time::Instant;

/// Minimal OIDC discovery document containing the JWKS URI
#[derive(Debug, Clone, Deserialize)]
#[cfg(feature = "remote")]
pub struct OidcDiscovery {
    /// The JWKS URI from the discovery document
    #[serde(rename = "jwks_uri")]
    pub jwks_uri: String,
}

/// Build the URL to the discovery document from an issuer string
#[cfg(feature = "remote")]
fn well_known_url_for_issuer(issuer: &str) -> Result<String> {
    // Basic normalization: trim trailing '/'
    let base = issuer.trim_end_matches('/');
    if base.is_empty() {
        return Err(Error::RemoteError("discovery: empty issuer".to_string()));
    }
    Ok(format!("{base}/.well-known/openid-configuration"))
}

/// Discover the JWKS URI using the OIDC well-known configuration
///
/// This function fetches the OIDC discovery document from the issuer's
/// well-known endpoint and extracts the JWKS URI.
///
/// # Arguments
///
/// * `issuer` - The issuer URL (e.g., `<https://auth.example.com>`)
/// * `client` - The HTTP client to use for fetching
///
/// # Errors
///
/// Returns `Error::RemoteError` with component-prefixed messages:
/// - `"discovery: ..."` for discovery-specific errors
/// - `"network: ..."` for network errors (from HTTP client)
///
/// # Example
///
/// ```ignore
/// use jwtiny::discovery::discover_jwks_uri;
/// use jwtiny::remote::HttpClient;
///
/// let client = /* your HTTP client */;
/// let jwks_uri = discover_jwks_uri("https://auth.example.com", &client).await?;
/// ```
#[cfg(feature = "remote")]
pub async fn discover_jwks_uri(issuer: &str, client: &dyn HttpClient) -> Result<String> {
    let url = well_known_url_for_issuer(issuer)?;
    let bytes = client.fetch(&url).await?;

    let body = std::str::from_utf8(&bytes)
        .map_err(|e| Error::RemoteError(format!("discovery: utf8 decode failed: {e}")))?;

    let doc: OidcDiscovery = miniserde::json::from_str(body)
        .map_err(|_| Error::RemoteError("discovery: invalid discovery json".to_string()))?;

    if doc.jwks_uri.trim().is_empty() {
        return Err(Error::RemoteError(
            "discovery: missing or empty jwks_uri".to_string(),
        ));
    }

    Ok(doc.jwks_uri)
}

// Simple in-memory cache for discovery results (per-issuer, fixed TTL)
#[cfg(feature = "remote")]
static DISCOVERY_CACHE: OnceLock<Mutex<HashMap<String, (Instant, String)>>> = OnceLock::new();

#[cfg(feature = "remote")]
fn discovery_cache() -> &'static Mutex<HashMap<String, (Instant, String)>> {
    DISCOVERY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Cached variant of `discover_jwks_uri` with a simple in-memory TTL cache
///
/// This function caches discovery results per issuer with a fixed TTL (300 seconds).
/// If a cached result exists and hasn't expired, it returns immediately.
/// Otherwise, it fetches the discovery document and caches the result.
///
/// # Arguments
///
/// * `issuer` - The issuer URL (e.g., `<https://auth.example.com>`)
/// * `client` - The HTTP client to use for fetching
///
/// # Errors
///
/// Same as `discover_jwks_uri()`
#[cfg(feature = "remote")]
pub async fn discover_jwks_uri_cached(issuer: &str, client: &dyn HttpClient) -> Result<String> {
    // Check cache first (per-issuer)
    if let Some(entry) = discovery_cache().lock().ok().and_then(|mut map| {
        if let Some((ts, val)) = map.get(issuer).cloned() {
            if ts.elapsed() < DISCOVERY_TTL {
                return Some(val);
            }
            // expired -> remove
            map.remove(issuer);
        }
        None
    }) {
        return Ok(entry);
    }

    // Fetch and cache
    let jwks_uri = discover_jwks_uri(issuer, client).await?;

    // Update cache, ignoring lock errors
    if let Ok(mut map) = discovery_cache().lock() {
        map.insert(issuer.to_string(), (Instant::now(), jwks_uri.clone()));
    }

    Ok(jwks_uri)
}

#[cfg(all(test, feature = "remote"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_well_known_url_for_issuer() {
        assert_eq!(
            well_known_url_for_issuer("https://issuer.example"),
            Ok("https://issuer.example/.well-known/openid-configuration".to_string())
        );
        assert_eq!(
            well_known_url_for_issuer("https://issuer.example/"),
            Ok("https://issuer.example/.well-known/openid-configuration".to_string())
        );
        assert!(well_known_url_for_issuer("").is_err());
    }

    struct MockHttpClient {
        response: &'static str,
    }

    impl HttpClient for MockHttpClient {
        fn fetch(
            &self,
            url: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + '_>> {
            assert!(url.contains("/.well-known/openid-configuration"));
            let response = self.response.as_bytes().to_vec();
            Box::pin(async move { Ok(response) })
        }
    }

    #[tokio::test]
    async fn test_discover_jwks_uri() {
        let client = MockHttpClient {
            response: r#"{ "jwks_uri": "https://issuer.example/.well-known/jwks.json" }"#,
        };

        let uri = discover_jwks_uri("https://issuer.example", &client)
            .await
            .expect("discover");
        assert_eq!(uri, "https://issuer.example/.well-known/jwks.json");
    }

    struct EmptyJwksUriMockClient;

    impl HttpClient for EmptyJwksUriMockClient {
        fn fetch(
            &self,
            _url: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + '_>> {
            let body = r#"{ "jwks_uri": "" }"#;
            Box::pin(async move { Ok(body.as_bytes().to_vec()) })
        }
    }

    #[tokio::test]
    async fn test_discover_jwks_uri_empty() {
        let client = EmptyJwksUriMockClient;

        let result = discover_jwks_uri("https://issuer.example", &client).await;
        assert!(
            matches!(result, Err(Error::RemoteError(msg)) if msg.contains("missing or empty jwks_uri"))
        );
    }

    #[tokio::test]
    async fn test_discover_jwks_uri_cached() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingHttpClient {
            count: Arc<AtomicU32>,
        }

        impl HttpClient for CountingHttpClient {
            fn fetch(
                &self,
                _url: &str,
            ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + '_>> {
                let count = self.count.clone();
                Box::pin(async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let body = r#"{ "jwks_uri": "https://issuer.example/.well-known/jwks.json" }"#;
                    Ok(body.as_bytes().to_vec())
                })
            }
        }

        let fetch_count = Arc::new(AtomicU32::new(0));
        let client = CountingHttpClient {
            count: fetch_count.clone(),
        };

        // First fetch - should make HTTP request
        let uri1 = discover_jwks_uri_cached("https://issuer.example", &client)
            .await
            .expect("discover");
        assert_eq!(uri1, "https://issuer.example/.well-known/jwks.json");
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);

        // Second fetch - should use cache
        let uri2 = discover_jwks_uri_cached("https://issuer.example", &client)
            .await
            .expect("discover");
        assert_eq!(uri2, "https://issuer.example/.well-known/jwks.json");
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1); // Still 1, used cache
    }

    struct InvalidJsonMockClient;

    impl HttpClient for InvalidJsonMockClient {
        fn fetch(
            &self,
            _url: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + '_>> {
            Box::pin(async move { Ok(b"{ invalid json }".to_vec()) })
        }
    }

    #[tokio::test]
    async fn test_discover_jwks_uri_invalid_json() {
        let client = InvalidJsonMockClient;

        let result = discover_jwks_uri("https://issuer.example", &client).await;
        assert!(
            matches!(result, Err(Error::RemoteError(msg)) if msg.contains("discovery: invalid discovery json"))
        );
    }
}
