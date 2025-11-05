//! JWKS (JSON Web Key Set) fetching and parsing

#[cfg(feature = "remote")]
use crate::error::{Error, Result};
#[cfg(feature = "remote")]
use crate::jwks::Jwk;
#[cfg(feature = "remote")]
use crate::remote::config::JWKS_TTL;
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

/// JSON Web Key Set (JWKS)
#[derive(Debug, Clone, Deserialize)]
#[cfg(feature = "remote")]
pub struct JwkSet {
    /// The keys in the set
    pub keys: Vec<Jwk>,
}

/// Fetch and parse a JWKS document from the given URI using the provided HTTP client
///
/// # Arguments
///
/// * `client` - The HTTP client to use for fetching
/// * `jwks_uri` - The URI of the JWKS document
///
/// # Errors
///
/// Returns `Error::RemoteError` with component-prefixed messages:
/// - `"jwks: ..."` for JWKS-specific errors
/// - `"network: ..."` for network errors (from HTTP client)
///
/// # Example
///
/// ```ignore
/// use jwtiny::jwks::fetch_jwks;
/// use jwtiny::remote::HttpClient;
///
/// let client = /* your HTTP client */;
/// let jwk_set = fetch_jwks(&client, "https://auth.example.com/.well-known/jwks.json").await?;
/// ```
#[cfg(feature = "remote")]
pub async fn fetch_jwks(client: &impl HttpClient, jwks_uri: &str) -> Result<JwkSet> {
    if jwks_uri.trim().is_empty() {
        return Err(Error::RemoteError("jwks: empty jwks_uri".to_string()));
    }

    let bytes = client.fetch(jwks_uri).await?;

    let body = std::str::from_utf8(&bytes)
        .map_err(|e| Error::RemoteError(format!("jwks: utf8 decode failed: {e}")))?;

    let set: JwkSet = miniserde::json::from_str(body)
        .map_err(|_| Error::RemoteError("jwks: invalid jwks json".to_string()))?;

    Ok(set)
}

// Simple in-memory cache for JWKS (per-URI, fixed TTL)
#[cfg(feature = "remote")]
static JWKS_CACHE: OnceLock<Mutex<HashMap<String, (Instant, JwkSet)>>> = OnceLock::new();

#[cfg(feature = "remote")]
fn jwks_cache() -> &'static Mutex<HashMap<String, (Instant, JwkSet)>> {
    JWKS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Cached variant of `fetch_jwks` with a simple in-memory TTL cache
///
/// This function caches JWKS documents per URI with a fixed TTL (300 seconds).
/// If a cached result exists and hasn't expired, it returns immediately.
/// Otherwise, it fetches the JWKS document and caches the result.
///
/// # Arguments
///
/// * `client` - The HTTP client to use for fetching
/// * `jwks_uri` - The URI of the JWKS document
///
/// # Errors
///
/// Same as `fetch_jwks()`
#[cfg(feature = "remote")]
pub async fn fetch_jwks_cached(client: &impl HttpClient, jwks_uri: &str) -> Result<JwkSet> {
    // Check cache first (per-URI)
    if let Some(entry) = jwks_cache().lock().ok().and_then(|mut map| {
        if let Some((ts, val)) = map.get(jwks_uri).cloned() {
            if ts.elapsed() < JWKS_TTL {
                return Some(val);
            }
            // expired -> remove
            map.remove(jwks_uri);
        }
        None
    }) {
        return Ok(entry);
    }

    // Fetch and cache
    let set = fetch_jwks(client, jwks_uri).await?;

    // Update cache, ignoring lock errors
    if let Ok(mut map) = jwks_cache().lock() {
        map.insert(jwks_uri.to_string(), (Instant::now(), set.clone()));
    }

    Ok(set)
}

#[cfg(all(test, feature = "remote"))]
mod tests {
    use super::*;

    struct MockHttpClient {
        response: &'static str,
    }

    impl HttpClient for MockHttpClient {
        fn fetch(&self, _url: &str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + '_>> {
            let response = self.response.as_bytes().to_vec();
            Box::pin(async move { Ok(response) })
        }
    }

    #[tokio::test]
    async fn test_fetch_jwks() {
        let client = MockHttpClient {
            response: r#"{
                "keys": [
                    {"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"},
                    {"kty":"EC","kid":"k2","crv":"P-256","x":"xx","y":"yy"}
                ]
            }"#,
        };

        let set = fetch_jwks(&client, "https://issuer.example/jwks.json")
            .await
            .expect("jwks parse");
        assert_eq!(set.keys.len(), 2);
        assert_eq!(set.keys[0].kid.as_deref(), Some("k1"));
        assert_eq!(set.keys[1].kid.as_deref(), Some("k2"));
    }

    #[tokio::test]
    async fn test_fetch_jwks_empty_uri() {
        let client = MockHttpClient { response: "" };

        let result = fetch_jwks(&client, "").await;
        assert!(
            matches!(result, Err(Error::RemoteError(msg)) if msg.contains("jwks: empty jwks_uri"))
        );
    }

    #[tokio::test]
    async fn test_fetch_jwks_invalid_json() {
        let client = MockHttpClient {
            response: "{ invalid json }",
        };

        let result = fetch_jwks(&client, "https://issuer.example/jwks.json").await;
        assert!(
            matches!(result, Err(Error::RemoteError(msg)) if msg.contains("jwks: invalid jwks json"))
        );
    }

    #[tokio::test]
    async fn test_fetch_jwks_cached() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        struct CountingHttpClient {
            count: Arc<AtomicU32>,
        }

        impl HttpClient for CountingHttpClient {
            fn fetch(&self, _url: &str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + '_>> {
                let count = self.count.clone();
                Box::pin(async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let jwks_json = r#"{"keys": [{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}"#;
                    Ok(jwks_json.as_bytes().to_vec())
                })
            }
        }

        let fetch_count = Arc::new(AtomicU32::new(0));
        let client = CountingHttpClient {
            count: fetch_count.clone(),
        };

        let uri = "https://issuer.example/jwks.json";

        // First fetch - should make HTTP request
        let set1 = fetch_jwks_cached(&client, uri).await.expect("fetch");
        assert_eq!(set1.keys.len(), 1);
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);

        // Second fetch - should use cache
        let set2 = fetch_jwks_cached(&client, uri).await.expect("fetch");
        assert_eq!(set2.keys.len(), 1);
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1); // Still 1, used cache
    }

    #[tokio::test]
    async fn test_jwk_optional_fields() {
        let client = MockHttpClient {
            response: r#"{"keys": [{"kty":"RSA"}]}"#,
        };

        let set = fetch_jwks(&client, "https://issuer.example/jwks.json")
            .await
            .expect("fetch");
        assert_eq!(set.keys.len(), 1);
        assert_eq!(set.keys[0].kty.as_deref(), Some("RSA"));
        assert_eq!(set.keys[0].kid, None); // Optional field missing
        assert_eq!(set.keys[0].n, None); // Optional field missing
    }
}
