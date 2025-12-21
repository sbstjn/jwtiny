//! JSON Web Key Set (JWKS) module
pub(crate) mod caching;
pub(crate) mod jwk;

/// Cache key type for storing resolved keys in moka caches
use crate::error::{Error, Result};
use crate::jwks::jwk::Jwk;
use crate::limits::MAX_JWKS_RESPONSE_SIZE;
use crate::url::validate_jwks_uri;
use miniserde::Deserialize;

/// Fetch data from a URL using reqwest
pub(crate) async fn fetch_url(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::RemoteError(format!("network: {e}")))?;

    if !response.status().is_success() {
        return Err(Error::RemoteError(format!(
            "http: status {}",
            response.status()
        )));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| Error::RemoteError(format!("network: {e}")))?
        .to_vec();

    Ok(bytes)
}

/// JSON Web Key Set (JWKS)
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct JwkSet {
    /// The keys in the set
    pub keys: Vec<Jwk>,
}

/// Fetch and parse a JWKS document from the given URI using the provided HTTP client
pub(crate) async fn fetch_jwks(client: &reqwest::Client, jwks_uri: &str) -> Result<JwkSet> {
    // Validate JWKS URI before fetching to prevent SSRF attacks
    validate_jwks_uri(jwks_uri)?;

    let bytes = fetch_url(client, jwks_uri).await?;

    // Validate response size before parsing to prevent resource exhaustion
    if bytes.len() > MAX_JWKS_RESPONSE_SIZE {
        return Err(Error::RemoteResponseTooLarge {
            size: bytes.len(),
            max: MAX_JWKS_RESPONSE_SIZE,
        });
    }

    let body = std::str::from_utf8(&bytes)
        .map_err(|e| Error::RemoteError(format!("jwks: utf8 decode failed: {e}")))?;

    let set: JwkSet = miniserde::json::from_str(body)
        .map_err(|_| Error::RemoteError("jwks: invalid jwks json".to_string()))?;

    Ok(set)
}

/// Find a key in a JWKS by key ID (kid) matching
///
/// Returns an error if:
/// - Multiple keys match the same kid (ambiguous)
/// - No kid is provided but the JWKS contains multiple keys (ambiguous)
pub(crate) fn find_key_by_kid<'a>(jwks: &'a JwkSet, kid: Option<&str>) -> Result<&'a Jwk> {
    if let Some(kid) = kid {
        // Find all keys matching this kid
        let matches: Vec<_> = jwks
            .keys
            .iter()
            .filter(|k| k.kid.as_deref() == Some(kid))
            .collect();

        if matches.is_empty() {
            Err(Error::RemoteError("jwks: no matching key found".into()))
        } else if matches.len() > 1 {
            // Multiple keys with same kid - ambiguous, fail verification
            Err(Error::MultipleKeysFound {
                kid: kid.into(),
                count: matches.len(),
            })
        } else {
            Ok(matches[0])
        }
    } else {
        // No kid specified
        let key_count = jwks.keys.len();
        if key_count == 0 {
            Err(Error::RemoteError("jwks: no keys in set".into()))
        } else if key_count == 1 {
            // Single key without kid - safe fallback
            Ok(&jwks.keys[0])
        } else {
            // Multiple keys without kid - ambiguous, require explicit kid
            Err(Error::KeyIdRequired { key_count })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_jwks() {
        let mut server = mockito::Server::new_async().await;
        let jwks_json = r#"{
            "keys": [
                {"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"},
                {"kty":"EC","kid":"k2","crv":"P-256","x":"xx","y":"yy"}
            ]
        }"#;
        let _mock = server
            .mock("GET", "/jwks.json")
            .with_status(200)
            .with_body(jwks_json)
            .create();

        let client = reqwest::Client::new();
        let uri = format!("{}/jwks.json", server.url());

        let set = fetch_jwks(&client, &uri).await.expect("jwks parse");
        assert_eq!(set.keys.len(), 2);
        assert_eq!(set.keys[0].kid.as_deref(), Some("k1"));
        assert_eq!(set.keys[1].kid.as_deref(), Some("k2"));
    }

    #[tokio::test]
    async fn test_fetch_jwks_empty_uri() {
        let client = reqwest::Client::new();

        let result = fetch_jwks(&client, "").await;
        // Empty URI is now caught by validate_jwks_uri which returns RemoteError
        assert!(result.is_err());
        assert!(
            matches!(result, Err(Error::RemoteError(msg)) if msg.contains("JWKS URI cannot be empty"))
        );
    }

    #[tokio::test]
    async fn test_fetch_jwks_invalid_json() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/jwks.json")
            .with_status(200)
            .with_body(b"{ invalid json }")
            .create();

        let client = reqwest::Client::new();
        let uri = format!("{}/jwks.json", server.url());

        let result = fetch_jwks(&client, &uri).await;
        assert!(
            matches!(result, Err(Error::RemoteError(msg)) if msg.contains("jwks: invalid jwks json"))
        );
    }

    #[tokio::test]
    async fn test_jwk_optional_fields() {
        let mut server = mockito::Server::new_async().await;
        let jwks_json = r#"{"keys": [{"kty":"RSA"}]}"#;
        let _mock = server
            .mock("GET", "/jwks.json")
            .with_status(200)
            .with_body(jwks_json)
            .create();

        let client = reqwest::Client::new();
        let uri = format!("{}/jwks.json", server.url());

        let set = fetch_jwks(&client, &uri).await.expect("fetch");
        assert_eq!(set.keys.len(), 1);
        assert_eq!(set.keys[0].kty.as_deref(), Some("RSA"));
        assert_eq!(set.keys[0].kid, None); // Optional field missing
        assert_eq!(set.keys[0].n, None); // Optional field missing
    }

    #[tokio::test]
    async fn test_fetch_jwks_oversized_response() {
        use crate::limits::MAX_JWKS_RESPONSE_SIZE;

        let mut server = mockito::Server::new_async().await;
        let oversized_response = "a".repeat(MAX_JWKS_RESPONSE_SIZE + 1);
        let _mock = server
            .mock("GET", "/jwks.json")
            .with_status(200)
            .with_body(oversized_response)
            .create();

        let client = reqwest::Client::new();
        let uri = format!("{}/jwks.json", server.url());

        let result = fetch_jwks(&client, &uri).await;
        assert!(matches!(
            result,
            Err(Error::RemoteResponseTooLarge { size, max }) if size > max && max == MAX_JWKS_RESPONSE_SIZE
        ));
    }

    #[tokio::test]
    async fn test_fetch_jwks_invalid_uri() {
        let mut server = mockito::Server::new_async().await;
        let jwks_json = r#"{"keys": [{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}"#;
        let _mock = server
            .mock("GET", "/jwks.json")
            .with_status(200)
            .with_body(jwks_json)
            .create();

        let client = reqwest::Client::new();

        // Test with invalid URI (trailing slash in issuer context, but URI itself should be validated)
        let result = fetch_jwks(&client, "").await;
        assert!(result.is_err());

        // Test with URI that's too long
        use crate::limits::MAX_JWKS_URI_LENGTH;
        let long_uri = format!("https://example.com/{}", "a".repeat(MAX_JWKS_URI_LENGTH));
        let result = fetch_jwks(&client, &long_uri).await;
        assert!(matches!(result, Err(Error::RemoteUrlTooLong { .. })));
    }

    #[test]
    fn test_find_key_by_kid() {
        let jwk1 = Jwk {
            kty: Some("RSA".to_string()),
            kid: Some("key1".to_string()),
            alg: None,
            key_use: None,
            n: Some("n1".to_string()),
            e: Some("e1".to_string()),
            crv: None,
            x: None,
            y: None,
        };

        let jwk2 = Jwk {
            kty: Some("RSA".to_string()),
            kid: Some("key2".to_string()),
            alg: None,
            key_use: None,
            n: Some("n2".to_string()),
            e: Some("e2".to_string()),
            crv: None,
            x: None,
            y: None,
        };

        let jwk_set = JwkSet {
            keys: vec![jwk1.clone(), jwk2.clone()],
        };

        // Find by kid
        let found = find_key_by_kid(&jwk_set, Some("key1"));
        assert!(found.is_ok());
        assert_eq!(found.unwrap().kid.as_deref(), Some("key1"));

        // Find by different kid
        let found = find_key_by_kid(&jwk_set, Some("key2"));
        assert!(found.is_ok());
        assert_eq!(found.unwrap().kid.as_deref(), Some("key2"));

        // No match
        let found = find_key_by_kid(&jwk_set, Some("key3"));
        assert!(found.is_err());
        assert!(matches!(found, Err(Error::RemoteError(_))));

        // No kid specified with multiple keys - should error
        let found = find_key_by_kid(&jwk_set, None);
        assert!(found.is_err());
        assert!(matches!(found, Err(Error::KeyIdRequired { key_count: 2 })));
    }

    #[test]
    fn test_find_key_by_kid_single_key_no_kid() {
        let jwk1 = Jwk {
            kty: Some("RSA".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: Some("n1".to_string()),
            e: Some("e1".to_string()),
            crv: None,
            x: None,
            y: None,
        };

        let jwk_set = JwkSet {
            keys: vec![jwk1.clone()],
        };

        // No kid specified with single key - should succeed
        let found = find_key_by_kid(&jwk_set, None);
        assert!(found.is_ok());
        assert_eq!(found.unwrap().n.as_deref(), Some("n1"));
    }

    #[test]
    fn test_find_key_by_kid_multiple_matches() {
        let jwk1 = Jwk {
            kty: Some("RSA".to_string()),
            kid: Some("same".to_string()),
            alg: None,
            key_use: None,
            n: Some("n1".to_string()),
            e: Some("e1".to_string()),
            crv: None,
            x: None,
            y: None,
        };

        let jwk2 = Jwk {
            kty: Some("RSA".to_string()),
            kid: Some("same".to_string()),
            alg: None,
            key_use: None,
            n: Some("n2".to_string()),
            e: Some("e2".to_string()),
            crv: None,
            x: None,
            y: None,
        };

        let jwk_set = JwkSet {
            keys: vec![jwk1.clone(), jwk2.clone()],
        };

        // Multiple keys with same kid - should error
        let found = find_key_by_kid(&jwk_set, Some("same"));
        assert!(found.is_err());
        assert!(matches!(
            found,
            Err(Error::MultipleKeysFound { kid, count: 2 }) if kid == "same"
        ));
    }
}
