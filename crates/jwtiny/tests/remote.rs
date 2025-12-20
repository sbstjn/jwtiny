//! Remote JWKS integration tests
//!
//! These tests validate jwtiny against a live jwkserve instance,
//! testing real JWKS flows, custom claims, and error handling.
//!
//! Prerequisites: jwkserve running on localhost:3000
//!
//! ```bash
//! docker run -it -p 3000:3000 sbstjn/jwkserve:latest
//! ```

mod parity;

use std::time::Duration;

use base64::Engine;
use jwtiny::{AlgorithmPolicy, ClaimsValidation, RemoteCacheKey, TokenValidator, claims};
use moka::future::Cache;
use parity::token_gen::{Algorithm, TokenBuilder};
use serde_json::json;

const BASE_URL: &str = "http://localhost:3000";

#[tokio::test]
async fn test_remote_machine() {
    let now = parity::token_gen::now();

    let token_str = TokenBuilder::new(BASE_URL, Algorithm::RS512)
        .audience("my-app")
        .subject("user-12345")
        .issued_at(now - 60)
        .not_before(now)
        .expiration(now + 60)
        .generate()
        .await
        .expect("Failed to generate token");

    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let client = reqwest::Client::new();

    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::rs512_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .cache(cache)
        .jwks(client);

    let result = validator.verify(&token_str).await;

    assert!(
        result.is_ok(),
        "Failed to validate token: {}",
        result.err().unwrap()
    );
}

#[claims]
struct CustomClaims {
    #[serde(rename = "email")]
    pub email: Option<String>,
    #[serde(rename = "role")]
    pub role: Option<String>,
    #[serde(rename = "permission_list")]
    pub permissions: Option<Vec<String>>,
}

#[tokio::test]
async fn test_remote_machine_with_custom_claims() {
    let now = parity::token_gen::now();

    let token_str = TokenBuilder::new(BASE_URL, Algorithm::RS512)
        .audience("my-app")
        .subject("user-12345")
        .issued_at(now - 60)
        .not_before(now)
        .expiration(now + 60)
        .custom_claim("email", json!("user@example.com"))
        .custom_claim("role", json!("admin"))
        .custom_claim("permission_list", json!(["read", "write", "delete"]))
        .generate()
        .await
        .expect("Failed to generate token");

    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let client = reqwest::Client::new();

    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::rs512_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .cache(cache)
        .jwks(client);

    let result = validator
        .verify_with_custom::<CustomClaims>(&token_str)
        .await;

    assert!(
        result.is_ok(),
        "Failed to validate token: {}",
        result.err().unwrap()
    );

    let claims = result.unwrap();
    assert_eq!(claims.email, Some("user@example.com".to_string()));
    assert_eq!(claims.role, Some("admin".to_string()));
    assert_eq!(
        claims.permissions,
        Some(vec![
            "read".to_string(),
            "write".to_string(),
            "delete".to_string()
        ])
    );
    assert_eq!(claims.subject.as_deref(), Some("user-12345"));
}

#[tokio::test]
async fn test_remote_ecdsa_es256() {
    let token_str = TokenBuilder::new(BASE_URL, Algorithm::ES256)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate ES256 token");

    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let client = reqwest::Client::new();

    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::es256_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .cache(cache)
        .jwks(client);

    let result = validator.verify(&token_str).await;

    assert!(
        result.is_ok(),
        "Failed to validate ES256 token: {}",
        result.err().unwrap()
    );
}

#[tokio::test]
async fn test_remote_ecdsa_es384() {
    let token_str = TokenBuilder::new(BASE_URL, Algorithm::ES384)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate ES384 token");

    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let client = reqwest::Client::new();

    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::es384_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .cache(cache)
        .jwks(client);

    let result = validator.verify(&token_str).await;

    assert!(
        result.is_ok(),
        "Failed to validate ES384 token: {}",
        result.err().unwrap()
    );
}

#[tokio::test]
async fn test_remote_ecdsa_es512() {
    let token_str = TokenBuilder::new(BASE_URL, Algorithm::ES512)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate ES512 token");

    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let client = reqwest::Client::new();

    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::es512_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .cache(cache)
        .jwks(client);

    let result = validator.verify(&token_str).await;

    assert!(
        result.is_ok(),
        "Failed to validate ES512 token: {}",
        result.err().unwrap()
    );
}

// ============================================================================
// JWKS Error Handling Tests
// ============================================================================

/// Test that validator handles invalid JWKS JSON gracefully
#[tokio::test]
async fn test_jwks_invalid_json() {
    let mut server = mockito::Server::new_async().await;
    let base_url = server.url();

    // Mock JWKS endpoint returning invalid JSON
    let _mock = server
        .mock("GET", "/.well-known/jwks.json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{ invalid json }")
        .create_async()
        .await;

    // Generate valid token from real jwkserve
    let token_str = TokenBuilder::new(BASE_URL, Algorithm::RS256)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate token");

    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let client = reqwest::Client::new();

    // Configure validator to use mock server for JWKS (token still has real issuer)
    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::rs256_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .cache(cache)
        .jwks(client);

    // Modify token issuer to point to mock server
    let parts: Vec<&str> = token_str.split('.').collect();
    let header = parts[0];
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap();
    let mut payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["iss"] = json!(base_url);
    let modified_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&payload).unwrap());
    let modified_token = format!("{}.{}.{}", header, modified_payload, parts[2]);

    let result = validator.verify(&modified_token).await;

    // Should fail with RemoteError due to invalid JSON
    assert!(
        result.is_err(),
        "Expected validation to fail with invalid JWKS JSON"
    );
    match result {
        Err(jwtiny::Error::RemoteError(_)) => (),
        Err(e) => panic!("Expected RemoteError, got: {:?}", e),
        Ok(_) => panic!("Expected validation to fail"),
    }
}

/// Test that validator handles missing keys array in JWKS
#[tokio::test]
async fn test_jwks_missing_keys_array() {
    let mut server = mockito::Server::new_async().await;
    let base_url = server.url();

    // Mock JWKS endpoint with valid JSON but no keys array
    let _mock = server
        .mock("GET", "/.well-known/jwks.json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"invalid": "structure"}"#)
        .create_async()
        .await;

    let token_str = TokenBuilder::new(BASE_URL, Algorithm::RS256)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate token");

    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let client = reqwest::Client::new();

    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::rs256_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .cache(cache)
        .jwks(client);

    // Modify token issuer to point to mock server
    let parts: Vec<&str> = token_str.split('.').collect();
    let header = parts[0];
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap();
    let mut payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["iss"] = json!(base_url);
    let modified_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&payload).unwrap());
    let modified_token = format!("{}.{}.{}", header, modified_payload, parts[2]);

    let result = validator.verify(&modified_token).await;

    assert!(
        result.is_err(),
        "Expected validation to fail with missing keys array"
    );
}

/// Test that validator handles key not found (kid mismatch)
#[tokio::test]
async fn test_jwks_key_not_found() {
    let mut server = mockito::Server::new_async().await;
    let base_url = server.url();

    // Mock JWKS endpoint with valid structure but different key IDs
    let _mock = server
        .mock("GET", "/.well-known/jwks.json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "wrong-key-id",
                    "use": "sig",
                    "n": "dummy",
                    "e": "AQAB"
                }
            ]
        }"#,
        )
        .create_async()
        .await;

    let token_str = TokenBuilder::new(BASE_URL, Algorithm::RS256)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate token");

    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let client = reqwest::Client::new();

    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::rs256_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .cache(cache)
        .jwks(client);

    // Modify token issuer to point to mock server
    let parts: Vec<&str> = token_str.split('.').collect();
    let header = parts[0];
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap();
    let mut payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["iss"] = json!(base_url);
    let modified_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&payload).unwrap());
    let modified_token = format!("{}.{}.{}", header, modified_payload, parts[2]);

    let result = validator.verify(&modified_token).await;

    assert!(
        result.is_err(),
        "Expected validation to fail when key not found"
    );
}

/// Test that validator handles JWKS endpoint returning 404
#[tokio::test]
async fn test_jwks_endpoint_not_found() {
    let mut server = mockito::Server::new_async().await;
    let base_url = server.url();

    // Mock JWKS endpoint returning 404
    let _mock = server
        .mock("GET", "/.well-known/jwks.json")
        .with_status(404)
        .create_async()
        .await;

    let token_str = TokenBuilder::new(BASE_URL, Algorithm::RS256)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate token");

    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let client = reqwest::Client::new();

    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::rs256_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .cache(cache)
        .jwks(client);

    // Modify token issuer to point to mock server
    let parts: Vec<&str> = token_str.split('.').collect();
    let header = parts[0];
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap();
    let mut payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["iss"] = json!(base_url);
    let modified_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&payload).unwrap());
    let modified_token = format!("{}.{}.{}", header, modified_payload, parts[2]);

    let result = validator.verify(&modified_token).await;

    assert!(
        result.is_err(),
        "Expected validation to fail with 404 JWKS endpoint"
    );
    match result {
        Err(jwtiny::Error::RemoteError(_)) => (),
        Err(e) => panic!("Expected RemoteError, got: {:?}", e),
        Ok(_) => panic!("Expected validation to fail"),
    }
}

/// Test that validator handles network timeout gracefully
#[tokio::test]
async fn test_jwks_network_timeout() {
    let mut server = mockito::Server::new_async().await;
    let base_url = server.url();

    // Mock JWKS endpoint with delayed response (simulating timeout)
    let _mock = server
        .mock("GET", "/.well-known/jwks.json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body_from_request(|_| {
            std::thread::sleep(Duration::from_secs(5));
            r#"{"keys": []}"#.into()
        })
        .create_async()
        .await;

    let token_str = TokenBuilder::new(BASE_URL, Algorithm::RS256)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate token");

    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    // Create client with short timeout
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();

    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::rs256_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .cache(cache)
        .jwks(client);

    // Modify token issuer to point to mock server
    let parts: Vec<&str> = token_str.split('.').collect();
    let header = parts[0];
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap();
    let mut payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["iss"] = json!(base_url);
    let modified_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&payload).unwrap());
    let modified_token = format!("{}.{}.{}", header, modified_payload, parts[2]);

    let result = validator.verify(&modified_token).await;

    assert!(
        result.is_err(),
        "Expected validation to fail with network timeout"
    );
    match result {
        Err(jwtiny::Error::RemoteError(_)) => (),
        Err(e) => panic!("Expected RemoteError, got: {:?}", e),
        Ok(_) => panic!("Expected validation to fail"),
    }
}
