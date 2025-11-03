//! Key format compatibility tests
//!
//! These tests verify that jwtiny can handle various key encoding formats:
//! - PKCS#1 (RSA-specific format)
//! - PKCS#8 (generic format for all algorithms)
//! - DER (binary encoding)
//! - PEM (base64-encoded with headers)
//!
//! Inspired by jsonwebtoken's comprehensive key format testing.

use jwtiny::*;

// ============================================================================
// RSA Key Format Tests
// ============================================================================

#[cfg(feature = "rsa")]
mod rsa_key_formats {
    // Note: These tests require rsa crate version alignment with sha2
    // Currently disabled pending dependency resolution
    use super::*;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pkcs8::EncodePublicKey;
    use sha2::Sha256;

    /// Generate a test RSA key pair
    fn generate_rsa_keypair() -> RsaPrivateKey {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key")
    }

    /// Create and sign a test JWT token
    fn create_signed_token(private_key: &RsaPrivateKey, alg: &str) -> String {
        use rsa::signature::{RandomizedSigner, SignatureEncoding};

        let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(
            r#"{{"iss":"https://test.com","sub":"user","exp":{}}}"#,
            now + 3600
        );

        let header_b64 = jwtiny::utils::base64url::encode(&header);
        let payload_b64 = jwtiny::utils::base64url::encode(&payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign based on algorithm
        let signature_bytes = match alg {
            "RS256" => {
                let mut rng = rand::thread_rng();
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<Sha256>::new_unprefixed(private_key.clone());
                let signature = signing_key.sign_with_rng(&mut rng, signing_input.as_bytes());
                signature.to_bytes()
            }
            _ => panic!("Unsupported algorithm for test: {}", alg),
        };

        let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);
        format!("{}.{}", signing_input, signature_b64)
    }

    #[test]
    #[ignore = "RSA key format testing needs rsa/sha2 version alignment"]
    fn test_rsa_pkcs8_der_public_key() {
        // PKCS#8 is the modern standard format for keys
        let private_key = generate_rsa_keypair();
        let public_key = private_key.to_public_key();

        // Encode public key in PKCS#8 DER format
        let public_key_der = public_key
            .to_public_key_der()
            .expect("failed to encode public key");

        // Create a signed token
        let token_str = create_signed_token(&private_key, "RS256");

        // Verify with PKCS#8 DER public key
        let parsed = ParsedToken::from_string(&token_str).expect("parse failed");

        let result = TokenValidator::new(parsed)
            .ensure_issuer(|iss| {
                if iss == "https://test.com" {
                    Ok(())
                } else {
                    Err(Error::IssuerNotTrusted(iss.to_string()))
                }
            })
            .verify_signature(SignatureVerification::with_key(
                Key::rsa_public(public_key_der.as_bytes()),
                AlgorithmPolicy::rs256_only(),
            ))
            .validate_token(ValidationConfig::default())
            .run();

        assert!(
            result.is_ok(),
            "Should verify token with PKCS#8 DER public key"
        );
    }

    #[test]
    #[ignore = "RSA key format testing needs rsa/sha2 version alignment"]
    fn test_rsa_pkcs1_der_public_key() {
        // PKCS#1 is the older RSA-specific format
        let private_key = generate_rsa_keypair();
        let public_key = private_key.to_public_key();

        // Encode public key in PKCS#1 DER format
        let public_key_pkcs1_der = public_key
            .to_pkcs1_der()
            .expect("failed to encode public key in PKCS#1");

        // Create a signed token
        let token_str = create_signed_token(&private_key, "RS256");

        // Verify with PKCS#1 DER public key
        let parsed = ParsedToken::from_string(&token_str).expect("parse failed");

        let result = TokenValidator::new(parsed)
            .ensure_issuer(|iss| {
                if iss == "https://test.com" {
                    Ok(())
                } else {
                    Err(Error::IssuerNotTrusted(iss.to_string()))
                }
            })
            .verify_signature(SignatureVerification::with_key(
                Key::rsa_public(public_key_pkcs1_der.as_bytes()),
                AlgorithmPolicy::rs256_only(),
            ))
            .validate_token(ValidationConfig::default())
            .run();

        assert!(
            result.is_ok(),
            "Should verify token with PKCS#1 DER public key"
        );
    }

    #[test]
    #[ignore = "RSA key format testing needs rsa/sha2 version alignment"]
    fn test_rsa_pkcs8_pem_public_key() {
        // PEM is base64-encoded DER with "BEGIN/END" markers
        let private_key = generate_rsa_keypair();
        let public_key = private_key.to_public_key();

        // Encode public key in PKCS#8 PEM format
        let public_key_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("failed to encode public key in PEM");

        // Create a signed token
        let token_str = create_signed_token(&private_key, "RS256");

        // Parse PEM to get DER bytes (jwtiny expects DER)
        // In real usage, users would parse PEM using their preferred PEM parser
        let der_bytes = parse_pem_to_der(&public_key_pem);

        // Verify with PEM-sourced public key
        let parsed = ParsedToken::from_string(&token_str).expect("parse failed");

        let result = TokenValidator::new(parsed)
            .ensure_issuer(|iss| {
                if iss == "https://test.com" {
                    Ok(())
                } else {
                    Err(Error::IssuerNotTrusted(iss.to_string()))
                }
            })
            .verify_signature(SignatureVerification::with_key(
                Key::rsa_public(der_bytes),
                AlgorithmPolicy::rs256_only(),
            ))
            .validate_token(ValidationConfig::default())
            .run();

        assert!(
            result.is_ok(),
            "Should verify token with PKCS#8 PEM public key (converted to DER)"
        );
    }

    #[test]
    #[ignore = "RSA key format testing needs rsa/sha2 version alignment"]
    fn test_rsa_pkcs1_pem_public_key() {
        // PKCS#1 PEM format
        let private_key = generate_rsa_keypair();
        let public_key = private_key.to_public_key();

        // Encode public key in PKCS#1 PEM format
        let public_key_pem = public_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("failed to encode public key in PKCS#1 PEM");

        // Create a signed token
        let token_str = create_signed_token(&private_key, "RS256");

        // Parse PEM to get DER bytes
        let der_bytes = parse_pem_to_der(&public_key_pem);

        // Verify with PEM-sourced public key
        let parsed = ParsedToken::from_string(&token_str).expect("parse failed");

        let result = TokenValidator::new(parsed)
            .ensure_issuer(|iss| {
                if iss == "https://test.com" {
                    Ok(())
                } else {
                    Err(Error::IssuerNotTrusted(iss.to_string()))
                }
            })
            .verify_signature(SignatureVerification::with_key(
                Key::rsa_public(der_bytes),
                AlgorithmPolicy::rs256_only(),
            ))
            .validate_token(ValidationConfig::default())
            .run();

        assert!(
            result.is_ok(),
            "Should verify token with PKCS#1 PEM public key (converted to DER)"
        );
    }

    #[test]
    #[ignore = "RSA key format testing needs rsa/sha2 version alignment"]
    fn test_rsa_multiple_formats_same_key() {
        // Verify that the same logical key works in different encodings
        let private_key = generate_rsa_keypair();
        let public_key = private_key.to_public_key();

        // Create a signed token
        let token_str = create_signed_token(&private_key, "RS256");

        // Get key in multiple formats
        let pkcs8_der = public_key.to_public_key_der().unwrap();
        let pkcs1_der = public_key.to_pkcs1_der().unwrap();

        // Verify with PKCS#8 DER
        let parsed1 = ParsedToken::from_string(&token_str).unwrap();
        let result1 = TokenValidator::new(parsed1)
            .danger_skip_issuer_validation()
            .verify_signature(SignatureVerification::with_key(
                Key::rsa_public(pkcs8_der.as_bytes()),
                AlgorithmPolicy::rs256_only(),
            ))
            .validate_token(ValidationConfig::default())
            .run();

        // Verify with PKCS#1 DER
        let parsed2 = ParsedToken::from_string(&token_str).unwrap();
        let result2 = TokenValidator::new(parsed2)
            .danger_skip_issuer_validation()
            .verify_signature(SignatureVerification::with_key(
                Key::rsa_public(pkcs1_der.as_bytes()),
                AlgorithmPolicy::rs256_only(),
            ))
            .validate_token(ValidationConfig::default())
            .run();

        assert!(result1.is_ok(), "PKCS#8 DER verification should succeed");
        assert!(result2.is_ok(), "PKCS#1 DER verification should succeed");

        // Both should produce the same verified token
        let token1 = result1.unwrap();
        let token2 = result2.unwrap();

        assert_eq!(token1.subject(), token2.subject());
        assert_eq!(token1.issuer(), token2.issuer());
    }

    /// Simple PEM to DER parser for tests
    /// In production, use a proper PEM parsing library
    fn parse_pem_to_der(pem: &str) -> Vec<u8> {
        let lines: Vec<&str> = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let base64_str = lines.join("");
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD
            .decode(&base64_str)
            .expect("failed to decode base64")
    }
}

// ============================================================================
// ECDSA Key Format Tests
// ============================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_key_formats {
    use super::*;

    // Note: ECDSA key format testing requires proper key generation utilities
    // These tests are placeholders and should be implemented with proper ECDSA support

    #[test]
    #[ignore = "requires ECDSA key generation utilities"]
    fn test_ecdsa_pkcs8_der_public_key() {
        // TODO: Implement ECDSA PKCS#8 DER key format test
        // Similar to RSA tests but with ECDSA P-256/P-384 keys
    }

    #[test]
    #[ignore = "requires ECDSA key generation utilities"]
    fn test_ecdsa_sec1_der_public_key() {
        // TODO: Implement ECDSA SEC1 DER key format test
        // SEC1 is the ECDSA-specific format (similar to PKCS#1 for RSA)
    }

    #[test]
    #[ignore = "requires ECDSA key generation utilities"]
    fn test_ecdsa_pem_public_key() {
        // TODO: Implement ECDSA PEM key format test
    }
}

// ============================================================================
// Key Format Error Handling Tests
// ============================================================================

#[cfg(feature = "rsa")]
mod key_format_errors {
    use super::*;

    #[test]
    #[ignore = "RSA key format testing needs rsa/sha2 version alignment"]
    fn test_invalid_der_encoding() {
        // Test that invalid DER encoding is rejected
        let invalid_der = vec![0xFF, 0xFE, 0xFD, 0xFC]; // Invalid DER

        let header_b64 = jwtiny::utils::base64url::encode(r#"{"alg":"RS256"}"#);
        let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
        let sig = jwtiny::utils::base64url::encode("sig");
        let token = format!("{}.{}.{}", header_b64, payload_b64, sig);

        let parsed = ParsedToken::from_string(&token).unwrap();
        let trusted = parsed.danger_trust_without_issuer_check();

        // Try to create key with invalid DER
        let key = Key::rsa_public(invalid_der);
        let result = trusted.verify_signature(&key);

        // Should fail with an error (likely during key parsing or signature verification)
        assert!(result.is_err(), "Should reject invalid DER encoding");
    }

    #[test]
    #[ignore = "RSA key format testing needs rsa/sha2 version alignment"]
    fn test_empty_key_data() {
        // Test that empty key data is rejected
        let empty_der: Vec<u8> = vec![];

        let header_b64 = jwtiny::utils::base64url::encode(r#"{"alg":"RS256"}"#);
        let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
        let sig = jwtiny::utils::base64url::encode("sig");
        let token = format!("{}.{}.{}", header_b64, payload_b64, sig);

        let parsed = ParsedToken::from_string(&token).unwrap();
        let trusted = parsed.danger_trust_without_issuer_check();

        // Try to create key with empty data
        let key = Key::rsa_public(empty_der);
        let result = trusted.verify_signature(&key);

        // Should fail
        assert!(result.is_err(), "Should reject empty key data");
    }

    #[test]
    #[ignore = "RSA key format testing needs rsa/sha2 version alignment"]
    fn test_truncated_der_encoding() {
        // Test that truncated DER encoding is rejected
        // Start of a valid DER structure but incomplete
        let truncated_der = vec![0x30, 0x82]; // Start of SEQUENCE but incomplete

        let header_b64 = jwtiny::utils::base64url::encode(r#"{"alg":"RS256"}"#);
        let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
        let sig = jwtiny::utils::base64url::encode("sig");
        let token = format!("{}.{}.{}", header_b64, payload_b64, sig);

        let parsed = ParsedToken::from_string(&token).unwrap();
        let trusted = parsed.danger_trust_without_issuer_check();

        // Try to create key with truncated DER
        let key = Key::rsa_public(truncated_der);
        let result = trusted.verify_signature(&key);

        // Should fail
        assert!(result.is_err(), "Should reject truncated DER encoding");
    }
}

// ============================================================================
// Documentation Tests
// ============================================================================

/// Example: Using PKCS#8 DER public key for verification
///
/// ```ignore
/// use jwtiny::*;
///
/// // Assume we have a public key in PKCS#8 DER format
/// let public_key_der: &[u8] = &[/* DER bytes */];
///
/// let parsed = ParsedToken::from_string(token_str)?;
/// let token = TokenValidator::new(parsed)
///     .ensure_issuer(|iss| Ok(iss == "https://trusted.com"))
///     .verify_signature(SignatureVerification::with_key(
///         Key::rsa_public(public_key_der)
///     ))
///     .validate_token(ValidationConfig::default())
///     .run()?;
/// ```
#[allow(dead_code)]
fn example_pkcs8_usage() {}

/// Example: Converting PEM to DER for use with jwtiny
///
/// ```ignore
/// // Read PEM file
/// let pem_str = std::fs::read_to_string("public_key.pem")?;
///
/// // Parse PEM to DER (using a PEM parsing library)
/// let der_bytes = parse_pem_to_der(&pem_str);
///
/// // Use with jwtiny
/// let key = Key::rsa_public(&der_bytes);
/// ```
#[allow(dead_code)]
fn example_pem_to_der() {}
