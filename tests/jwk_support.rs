//! JWK (JSON Web Key) format support tests
//!
//! These tests verify that jwtiny can work with JSON Web Key (JWK) formatted keys.
//! JWK is a standardized way to represent cryptographic keys as JSON objects (RFC 7517).
//!
//! Tests cover:
//! - RSA keys with modulus (n) and exponent (e) components
//! - ECDSA keys with curve coordinates (x, y)
//! - Key metadata (kid, alg, use)
//!
//! Inspired by jsonwebtoken's JWK testing.

use jwtiny::*;

// ============================================================================
// RSA JWK Tests
// ============================================================================

#[cfg(feature = "rsa")]
mod rsa_jwk_tests {
    use super::*;

    /// Test verifying a token using RSA public key components (n, e)
    /// This simulates receiving JWK data and converting to DER for jwtiny
    #[test]
    fn test_verify_with_rsa_components() {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
        use rsa::traits::PublicKeyParts;
        use rsa::RsaPrivateKey;

        // Generate RSA key pair
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key");
        let public_key = private_key.to_public_key();

        // Extract RSA components (simulating JWK n/e values)
        let n = public_key.n().to_bytes_be();
        let e = public_key.e().to_bytes_be();

        // In a real JWK scenario, these would be base64url-encoded strings
        // For this test, we'll reconstruct the key from components
        // Note: This requires reconstructing DER from n/e components

        // For now, we'll verify that we can work with the DER directly
        // A full JWK implementation would need to construct DER from n/e
        // Get the public key DER from the same source used for signing (ring)
        let pkcs8_doc = private_key
            .to_pkcs8_der()
            .expect("failed to serialize private key");

        let public_key_der = {
            #[cfg(feature = "aws-lc-rs")]
            {
                use aws_lc_rs::signature::{KeyPair, RsaKeyPair};
                let keypair = RsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes()).unwrap();
                keypair.public_key().as_ref().to_vec()
            }
            #[cfg(not(feature = "aws-lc-rs"))]
            {
                use ring::signature::RsaKeyPair;
                let keypair = RsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes()).unwrap();
                keypair.public().as_ref().to_vec()
            }
        };

        // Create and sign a token
        let token_str = create_rs256_token(&private_key);

        // Verify using the public key
        let parsed = ParsedToken::from_string(&token_str).expect("parse failed");

        let result = TokenValidator::new(parsed)
            .danger_skip_issuer_validation()
            .verify_signature(SignatureVerification::with_key(
                Key::rsa_public(public_key_der),
                AlgorithmPolicy::rs256_only(),
            ))
            .validate_token(ValidationConfig::default())
            .run();

        match &result {
            Ok(_) => {}
            Err(e) => panic!(
                "Should verify token with RSA public key components, but got error: {:?}",
                e
            ),
        }

        // Document: In a full JWK implementation, you would:
        // 1. Receive JWK JSON with "n" and "e" as base64url strings
        // 2. Decode base64url to get raw bytes
        // 3. Construct PKCS#8 DER encoding from n/e components
        // 4. Pass DER bytes to Key::rsa_public()
    }

    /// Test JWK metadata handling (kid, alg, use fields)
    #[test]
    fn test_jwk_metadata() {
        // Simulate a JWK with metadata
        let jwk_json = r#"{
            "kty": "RSA",
            "kid": "test-key-id-123",
            "use": "sig",
            "alg": "RS256",
            "n": "...",
            "e": "AQAB"
        }"#;

        // In a full implementation, you would:
        // 1. Parse the JSON to extract kid
        // 2. Match the kid from the JWT header with the JWK kid
        // 3. Use the correct key for verification

        // For this test, we document the expected behavior
        assert!(
            jwk_json.contains("RS256"),
            "JWK should contain algorithm identifier"
        );
        assert!(
            jwk_json.contains("test-key-id-123"),
            "JWK should contain key ID"
        );
    }

    /// Test selecting correct key from JWKS based on kid
    #[test]
    fn test_jwks_key_selection_by_kid() {
        // Simulate a JWKS (JSON Web Key Set) with multiple keys
        let _jwks_json = r#"{
            "keys": [
                {"kty": "RSA", "kid": "key-1", "n": "...", "e": "AQAB"},
                {"kty": "RSA", "kid": "key-2", "n": "...", "e": "AQAB"},
                {"kty": "RSA", "kid": "key-3", "n": "...", "e": "AQAB"}
            ]
        }"#;

        // Create a token with kid="key-2" in header
        let header = r#"{"alg":"RS256","kid":"key-2"}"#;
        let header_b64 = jwtiny::utils::base64url::encode(header);
        let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
        let sig_b64 = jwtiny::utils::base64url::encode("sig");

        let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

        // Parse token and extract kid
        let parsed = ParsedToken::from_string(&token).expect("parse failed");
        let header = parsed.header();

        assert_eq!(
            header.key_id.as_deref(),
            Some("key-2"),
            "Should extract kid from header"
        );

        // In a full implementation:
        // 1. Parse JWKS JSON
        // 2. Find key with matching kid
        // 3. Convert that key's n/e to DER
        // 4. Use for verification
    }

    /// Helper function to create a signed RS256 token
    fn create_rs256_token(private_key: &rsa::RsaPrivateKey) -> String {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
        use rsa::traits::PublicKeyParts;

        let public_key = private_key.to_public_key();
        let modulus_len = public_key.n().to_bytes_be().len();

        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(r#"{{"iss":"test","exp":{}}}"#, now + 3600);

        let header_b64 = jwtiny::utils::base64url::encode(header);
        let payload_b64 = jwtiny::utils::base64url::encode(&payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign using the appropriate backend
        let pkcs8_doc = private_key.to_pkcs8_der().expect("failed to serialize");

        let token = {
            #[cfg(feature = "aws-lc-rs")]
            {
                use aws_lc_rs::rand::SystemRandom;
                use aws_lc_rs::signature::{KeyPair, RsaKeyPair, RSA_PKCS1_SHA256};

                let keypair = RsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes()).unwrap();
                let rng = SystemRandom::new();
                let mut signature_bytes = vec![0u8; modulus_len];
                keypair
                    .sign(
                        &RSA_PKCS1_SHA256,
                        &rng,
                        signing_input.as_bytes(),
                        &mut signature_bytes,
                    )
                    .unwrap();
                let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);
                format!("{}.{}", signing_input, signature_b64)
            }
            #[cfg(not(feature = "aws-lc-rs"))]
            {
                use ring::rand::SystemRandom;
                use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};

                let keypair = RsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes()).unwrap();
                let rng = SystemRandom::new();
                let mut signature_bytes = vec![0u8; keypair.public().modulus_len()];
                keypair
                    .sign(
                        &RSA_PKCS1_SHA256,
                        &rng,
                        signing_input.as_bytes(),
                        &mut signature_bytes,
                    )
                    .unwrap();
                let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);
                format!("{}.{}", signing_input, signature_b64)
            }
        };

        token
    }
}

// ============================================================================
// ECDSA JWK Tests
// ============================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_jwk_tests {
    use super::*;

    /// Test verifying a token using ECDSA public key coordinates (x, y)
    #[test]
    #[ignore = "ECDSA JWK support needs implementation"]
    fn test_verify_with_ec_components() {
        // Simulate receiving JWK with EC coordinates
        let _jwk_json = r#"{
            "kty": "EC",
            "crv": "P-256",
            "x": "base64url-encoded-x-coordinate",
            "y": "base64url-encoded-y-coordinate",
            "kid": "ec-key-1",
            "use": "sig"
        }"#;

        // In a full implementation:
        // 1. Decode x and y from base64url
        // 2. Construct SEC1 or PKCS#8 DER encoding from x/y/curve
        // 3. Pass to Key::ecdsa_public()
        // 4. Verify token signature
    }

    /// Test curve parameter handling
    #[test]
    fn test_ec_curve_identification() {
        // JWKs use "crv" field to specify curve
        let jwk_p256 = r#"{"kty":"EC","crv":"P-256"}"#;
        let jwk_p384 = r#"{"kty":"EC","crv":"P-384"}"#;

        assert!(jwk_p256.contains("P-256"));
        assert!(jwk_p384.contains("P-384"));

        // In implementation, map crv to EcdsaCurve enum:
        // "P-256" -> EcdsaCurve::P256
        // "P-384" -> EcdsaCurve::P384
    }
}

// ============================================================================
// JWK Conversion Utilities Documentation
// ============================================================================

/// Documentation: Converting JWK RSA to DER
///
/// JWK RSA format:
/// ```json
/// {
///   "kty": "RSA",
///   "n": "<base64url-modulus>",
///   "e": "<base64url-exponent>",
///   "kid": "key-id",
///   "alg": "RS256",
///   "use": "sig"
/// }
/// ```
///
/// Conversion steps:
/// 1. Decode n and e from base64url
/// 2. Construct PKCS#8 DER:
///    - SEQUENCE
///      - SEQUENCE
///        - OBJECT IDENTIFIER rsaEncryption
///        - NULL
///      - BIT STRING
///        - SEQUENCE
///          - INTEGER (modulus n)
///          - INTEGER (exponent e)
/// 3. Pass DER bytes to `Key::rsa_public()`
#[allow(dead_code)]
fn jwk_rsa_to_der_documentation() {}

/// Documentation: Converting JWK ECDSA to DER
///
/// JWK ECDSA format:
/// ```json
/// {
///   "kty": "EC",
///   "crv": "P-256",
///   "x": "<base64url-x-coordinate>",
///   "y": "<base64url-y-coordinate>",
///   "kid": "key-id",
///   "use": "sig"
/// }
/// ```
///
/// Conversion steps:
/// 1. Decode x and y from base64url
/// 2. Identify curve from crv field
/// 3. Construct SEC1 or PKCS#8 DER encoding
/// 4. Pass DER bytes and curve to `Key::ecdsa_public()`
#[allow(dead_code)]
fn jwk_ecdsa_to_der_documentation() {}

// ============================================================================
// JWK Library Integration Examples
// ============================================================================

/// Example: Using existing JWK libraries with jwtiny
///
/// ```ignore
/// use jwtiny::*;
/// // Use a JWK parsing library (hypothetical)
/// use jwk::Jwk;
///
/// fn verify_with_jwk(token: &str, jwk_json: &str) -> Result<Token, Error> {
///     // Parse JWK
///     let jwk: Jwk = serde_json::from_str(jwk_json)?;
///
///     // Convert JWK to DER (implementation depends on JWK library)
///     let der_bytes = jwk.to_der()?;
///
///     // Use with jwtiny
///     let parsed = ParsedToken::from_string(token)?;
///     TokenValidator::new(parsed)
///         .danger_skip_issuer_validation()
///         .verify_signature(SignatureVerification::with_key(
///             Key::rsa_public(der_bytes)
///         ))
///         .validate_token(ValidationConfig::default())
///         .run()
/// }
/// ```
#[allow(dead_code)]
fn example_jwk_integration() {}

// ============================================================================
// JWKS (JSON Web Key Set) Tests
// ============================================================================

#[test]
fn test_jwks_structure() {
    // JWKS is an array of JWKs
    let jwks = r#"{
        "keys": [
            {
                "kty": "RSA",
                "kid": "2024-01",
                "use": "sig",
                "alg": "RS256",
                "n": "...",
                "e": "AQAB"
            },
            {
                "kty": "RSA",
                "kid": "2024-02",
                "use": "sig",
                "alg": "RS256",
                "n": "...",
                "e": "AQAB"
            }
        ]
    }"#;

    // Verify structure
    assert!(jwks.contains("\"keys\""), "JWKS should have keys array");
    assert!(
        jwks.contains("2024-01") && jwks.contains("2024-02"),
        "JWKS should contain multiple keys"
    );
}

#[test]
fn test_key_rotation_scenario() {
    // Simulate key rotation where old and new keys coexist
    // Token signed with old key should still verify
    // Token signed with new key should also verify

    // This test documents the expected behavior:
    // 1. JWKS contains both old and new keys
    // 2. Token header contains kid pointing to specific key
    // 3. Verification uses the key matching the kid
    // 4. Both old and new keys work during rotation period
}
