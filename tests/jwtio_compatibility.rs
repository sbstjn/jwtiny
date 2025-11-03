//! JWT.io reference implementation compatibility tests
//!
//! These tests verify that jwtiny can correctly handle tokens created by jwt.io
//! and other standard JWT implementations. This ensures interoperability.
//!
//! Tests use real tokens from jwt.io's examples and documentation.
//!
//! Inspired by jsonwebtoken's jwt.io compatibility testing.

use jwtiny::*;

// ============================================================================
// JWT.io Example Tokens - HMAC
// ============================================================================

mod jwtio_hmac_tests {
    use super::*;

    /// Test with the canonical JWT.io HS256 example
    #[test]
    fn test_jwtio_hs256_example() {
        // This is the example token from jwt.io with secret "your-256-bit-secret"
        // Header: {"alg":"HS256","typ":"JWT"}
        // Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let secret = b"your-256-bit-secret";

        // Parse the token
        let parsed = ParsedToken::from_string(token).expect("should parse jwt.io example");

        // Verify header
        let header = parsed.header();
        assert_eq!(header.algorithm_str(), "HS256");
        assert_eq!(header.token_type.as_deref(), Some("JWT"));

        // For tokens without an issuer field, we need to use the lower-level API
        // The builder API expects an issuer to be present
        let trusted = parsed.danger_trust_without_issuer_check();
        let key = Key::symmetric(secret);
        let verified = trusted
            .verify_signature(&key)
            .expect("signature verification should pass");

        let config = ValidationConfig::default().skip_all();
        let validated = verified
            .validate(&config)
            .expect("claims validation should pass");

        assert_eq!(validated.subject(), Some("1234567890"));
    }

    /// Test creating a token compatible with jwt.io
    #[test]
    fn test_create_jwtio_compatible_token() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Create the exact same token as jwt.io example
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let payload = r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#;
        let secret = b"your-256-bit-secret";

        let header_b64 = jwtiny::utils::base64url::encode(header);
        let payload_b64 = jwtiny::utils::base64url::encode(payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign with HMAC-SHA256
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);

        let our_token = format!("{}.{}", signing_input, signature_b64);

        // This should match jwt.io's output
        let expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        assert_eq!(
            our_token, expected_token,
            "Our token should match jwt.io's output exactly"
        );
    }

    /// Test with a token that has no typ field (optional field)
    #[test]
    fn test_jwtio_token_without_typ() {
        // Header without typ field
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let header = r#"{"alg":"HS256"}"#;
        let payload = r#"{"sub":"user123","name":"Test User"}"#;
        let secret = b"secret";

        let header_b64 = jwtiny::utils::base64url::encode(header);
        let payload_b64 = jwtiny::utils::base64url::encode(payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);

        let token = format!("{}.{}", signing_input, signature_b64);

        // Should parse and verify even without typ
        let parsed = ParsedToken::from_string(&token).expect("should parse without typ");

        // Use lower-level API for tokens without issuer
        let trusted = parsed.danger_trust_without_issuer_check();
        let key = Key::symmetric(secret);
        let verified = trusted
            .verify_signature(&key)
            .expect("signature should verify");
        let validated = verified
            .validate(&ValidationConfig::default().skip_all())
            .expect("validation should pass");

        assert_eq!(validated.subject(), Some("user123"));
    }
}

// ============================================================================
// JWT.io Example Tokens - RSA
// ============================================================================

#[cfg(feature = "rsa")]
mod jwtio_rsa_tests {
    use super::*;

    /// Test parsing jwt.io RS256 example structure
    #[test]
    fn test_jwtio_rs256_token_structure() {
        // Example RS256 token from jwt.io (signature won't verify without the actual key)
        // Header: {"alg":"RS256","typ":"JWT"}
        // Payload: {"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";

        // Should parse successfully
        let parsed = ParsedToken::from_string(token).expect("should parse jwt.io RS256 token");

        // Verify header
        let header = parsed.header();
        assert_eq!(header.algorithm_str(), "RS256");
        assert_eq!(header.token_type.as_deref(), Some("JWT"));

        // Note: We can't verify the signature without the public key,
        // but we can verify the structure is correct
    }

    /// Test that jwt.io-compatible RS256 tokens can be created and verified
    #[test]
    fn test_rs256_round_trip_jwtio_format() {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
        use rsa::{traits::PublicKeyParts, RsaPrivateKey};

        // Generate key pair
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key");
        let public_key = private_key.to_public_key();
        let modulus_len = public_key.n().to_bytes_be().len();

        // Create token in jwt.io format
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let payload = r#"{"sub":"1234567890","name":"John Doe","admin":true}"#;

        let header_b64 = jwtiny::utils::base64url::encode(header);
        let payload_b64 = jwtiny::utils::base64url::encode(payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign using appropriate backend
        let pkcs8_doc = private_key.to_pkcs8_der().expect("failed to serialize");

        let (signature_b64, public_key_der) = {
            #[cfg(feature = "aws-lc-rs")]
            {
                use aws_lc_rs::rand::SystemRandom;
                use aws_lc_rs::signature::{KeyPair, RsaKeyPair, RSA_PKCS1_SHA256};

                let keypair = RsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes()).unwrap();
                let public_key_der = keypair.public_key().as_ref().to_vec();

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
                (signature_b64, public_key_der)
            }
            #[cfg(not(feature = "aws-lc-rs"))]
            {
                use ring::rand::SystemRandom;
                use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};

                let keypair = RsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes()).unwrap();
                let public_key_der = keypair.public().as_ref().to_vec();

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
                (signature_b64, public_key_der)
            }
        };

        let token = format!("{}.{}", signing_input, signature_b64);

        // Verify the token
        let parsed = ParsedToken::from_string(&token).expect("should parse");

        // RSA tokens need to be verified using the lower-level API if they don't have an issuer
        let trusted = parsed.danger_trust_without_issuer_check();
        let key = Key::rsa_public(public_key_der);
        let verified = trusted
            .verify_signature(&key)
            .expect("RS256 signature should verify");
        let result = verified.validate(&ValidationConfig::default().skip_all());

        assert!(
            result.is_ok(),
            "should verify jwt.io-format RS256 token, got error: {:?}",
            result.err()
        );
    }
}

// ============================================================================
// Cross-Implementation Compatibility
// ============================================================================

#[test]
fn test_base64url_encoding_compatibility() {
    // JWT uses base64url encoding (RFC 4648 Section 5)
    // - Uses - instead of +
    // - Uses _ instead of /
    // - No padding (no =)

    let test_data = "Hello, World!";
    let encoded = jwtiny::utils::base64url::encode(test_data);

    // Should not contain +, /, or =
    assert!(!encoded.contains('+'), "base64url should not contain +");
    assert!(!encoded.contains('/'), "base64url should not contain /");
    assert!(
        !encoded.contains('='),
        "base64url should not contain padding ="
    );

    // Decode should work
    let decoded = jwtiny::utils::base64url::decode(&encoded).expect("should decode base64url");
    assert_eq!(decoded, test_data, "round-trip should preserve data");
}

#[test]
fn test_json_field_ordering_compatibility() {
    // Different libraries may produce JSON with different field ordering
    // This should not affect token validity

    let header1 = r#"{"alg":"HS256","typ":"JWT"}"#;
    let header2 = r#"{"typ":"JWT","alg":"HS256"}"#;

    let h1_b64 = jwtiny::utils::base64url::encode(header1);
    let h2_b64 = jwtiny::utils::base64url::encode(header2);

    // Different field order produces different base64 encoding
    assert_ne!(h1_b64, h2_b64, "field order affects encoding");

    // But both should parse to equivalent headers
    let token1 = format!("{}.{}.{}", h1_b64, "eyJpc3MiOiJ0ZXN0In0", "sig");
    let token2 = format!("{}.{}.{}", h2_b64, "eyJpc3MiOiJ0ZXN0In0", "sig");

    let parsed1 = ParsedToken::from_string(&token1).unwrap();
    let parsed2 = ParsedToken::from_string(&token2).unwrap();

    // Both should have same semantic content
    assert_eq!(parsed1.header().algorithm_str(), "HS256");
    assert_eq!(parsed2.header().algorithm_str(), "HS256");
    assert_eq!(parsed1.header().token_type.as_deref(), Some("JWT"));
    assert_eq!(parsed2.header().token_type.as_deref(), Some("JWT"));
}

// ============================================================================
// Standard Claims Compatibility
// ============================================================================

#[test]
fn test_standard_claims_parsing() {
    // Test that we correctly parse standard JWT claims as defined in RFC 7519

    let claims_with_all_standard = r#"{
        "iss": "https://issuer.example.com",
        "sub": "user@example.com",
        "aud": "https://app.example.com",
        "exp": 1735689600,
        "nbf": 1704067200,
        "iat": 1704067200,
        "jti": "unique-token-id-123"
    }"#;

    let header_b64 = jwtiny::utils::base64url::encode(r#"{"alg":"HS256"}"#);
    let payload_b64 = jwtiny::utils::base64url::encode(claims_with_all_standard);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    // Should parse successfully
    let parsed = ParsedToken::from_string(&token).expect("should parse standard claims");

    // Access through validated token would require signature verification
    // For now, verify that parsing succeeds
    assert!(parsed.header().algorithm_str() == "HS256");
}

#[test]
fn test_numeric_date_format() {
    // JWT uses NumericDate format (seconds since epoch)
    // Test various numeric date formats

    let test_cases: Vec<(i64, &str)> = vec![
        (0, "Unix epoch"),
        (1516239022, "jwt.io example"),
        (2147483647, "32-bit max (2038)"),
        (9999999999, "Far future"),
    ];

    for (timestamp, description) in test_cases {
        let payload = format!(r#"{{"exp":{}}}"#, timestamp);
        let header_b64 = jwtiny::utils::base64url::encode(r#"{"alg":"HS256"}"#);
        let payload_b64 = jwtiny::utils::base64url::encode(&payload);
        let sig_b64 = jwtiny::utils::base64url::encode("sig");

        let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

        let parsed = ParsedToken::from_string(&token).unwrap_or_else(|_| {
            panic!(
                "should parse token with exp={} ({})",
                timestamp, description
            )
        });

        assert!(
            parsed.header().algorithm_str() == "HS256",
            "{}",
            description
        );
    }
}

// ============================================================================
// Interoperability Edge Cases
// ============================================================================

#[test]
fn test_minimal_valid_token() {
    // Absolute minimal valid JWT structure
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let header = r#"{"alg":"HS256"}"#;
    let payload = r#"{}"#; // Empty claims
    let secret = b"secret";

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(signing_input.as_bytes());
    let signature_bytes = mac.finalize().into_bytes();
    let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);

    let token = format!("{}.{}", signing_input, signature_b64);

    // Should parse and verify minimal token
    let parsed = ParsedToken::from_string(&token).expect("should parse minimal token");

    // Use lower-level API for tokens without issuer
    let trusted = parsed.danger_trust_without_issuer_check();
    let key = Key::symmetric(secret);
    let verified = trusted
        .verify_signature(&key)
        .expect("signature should verify");
    let result = verified.validate(&ValidationConfig::default().skip_all());

    assert!(result.is_ok(), "should verify minimal valid token");
}

// ============================================================================
// Documentation and Examples
// ============================================================================

/// Example: Verifying a token from an external service
///
/// ```ignore
/// use jwtiny::*;
///
/// // Token received from Auth0, Google, AWS Cognito, etc.
/// let external_token = "eyJhbGc...";
///
/// // Public key obtained from the service's JWKS endpoint
/// let public_key_der = fetch_public_key_from_jwks(issuer).await?;
///
/// // Verify the token
/// let parsed = ParsedToken::from_string(external_token)?;
/// let token = TokenValidator::new(parsed)
///     .ensure_issuer(|iss| {
///         // Verify issuer matches expected service
///         if iss == "https://accounts.google.com" {
///             Ok(())
///         } else {
///             Err(Error::IssuerNotTrusted(iss.to_string()))
///         }
///     })
///     .verify_signature(SignatureVerification::with_key(
///         Key::rsa_public(public_key_der)
///     ))
///     .validate_token(ValidationConfig::default())
///     .run()?;
///
/// println!("Verified user: {}", token.subject().unwrap());
/// ```
#[allow(dead_code)]
fn example_external_token_verification() {}
