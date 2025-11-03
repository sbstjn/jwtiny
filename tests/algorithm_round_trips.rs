//! Per-algorithm round-trip tests
//!
//! These tests verify that each supported algorithm can successfully:
//! 1. Sign/encode a token
//! 2. Verify/decode the token
//! 3. Preserve all claims through the round-trip
//!
//! Inspired by jsonwebtoken's comprehensive per-algorithm testing.

use jwtiny::*;

// ============================================================================
// HMAC Algorithm Round-Trips (HS256, HS384, HS512)
// ============================================================================

mod hmac_tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha384, Sha512};

    #[test]
    fn round_trip_hs256() {
        let secret = b"test-secret-hs256-key";
        let alg = "HS256";

        // Create a token
        let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(
            r#"{{"iss":"https://example.com","sub":"test-user","aud":"test-app","exp":{},"iat":{}}}"#,
            now + 3600,
            now
        );

        let header_b64 = jwtiny::utils::base64url::encode(&header);
        let payload_b64 = jwtiny::utils::base64url::encode(&payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign with HMAC-SHA256
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);

        let token_str = format!("{}.{}", signing_input, signature_b64);

        // Parse and verify through full pipeline
        let parsed = ParsedToken::from_string(&token_str).expect("parse failed");

        let token = TokenValidator::new(parsed)
            .ensure_issuer(|iss| {
                if iss == "https://example.com" {
                    Ok(())
                } else {
                    Err(Error::IssuerNotTrusted(iss.to_string()))
                }
            })
            .verify_signature(SignatureVerification::with_secret(secret, AlgorithmPolicy::hs256_only()))
            .validate_token(ValidationConfig::default())
            .run()
            .expect("verification failed");

        // Verify all claims preserved
        assert_eq!(token.issuer(), Some("https://example.com"));
        assert_eq!(token.subject(), Some("test-user"));
        assert_eq!(token.header().algorithm_str(), alg);
    }

    #[test]
    fn round_trip_hs384() {
        let secret = b"test-secret-hs384-key-needs-to-be-longer";
        let alg = "HS384";

        let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(
            r#"{{"iss":"https://example.com","sub":"test-user","exp":{},"iat":{}}}"#,
            now + 3600,
            now
        );

        let header_b64 = jwtiny::utils::base64url::encode(&header);
        let payload_b64 = jwtiny::utils::base64url::encode(&payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign with HMAC-SHA384
        let mut mac = Hmac::<Sha384>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);

        let token_str = format!("{}.{}", signing_input, signature_b64);

        let parsed = ParsedToken::from_string(&token_str).expect("parse failed");

        let token = TokenValidator::new(parsed)
            .ensure_issuer(|iss| {
                if iss == "https://example.com" {
                    Ok(())
                } else {
                    Err(Error::IssuerNotTrusted(iss.to_string()))
                }
            })
            .verify_signature(SignatureVerification::with_secret(secret, AlgorithmPolicy::hs384_only()))
            .validate_token(ValidationConfig::default())
            .run()
            .expect("verification failed");

        assert_eq!(token.issuer(), Some("https://example.com"));
        assert_eq!(token.subject(), Some("test-user"));
        assert_eq!(token.header().algorithm_str(), alg);
    }

    #[test]
    fn round_trip_hs512() {
        let secret = b"test-secret-hs512-key-needs-to-be-even-longer-for-512-bits";
        let alg = "HS512";

        let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(
            r#"{{"iss":"https://example.com","sub":"test-user","exp":{},"iat":{}}}"#,
            now + 3600,
            now
        );

        let header_b64 = jwtiny::utils::base64url::encode(&header);
        let payload_b64 = jwtiny::utils::base64url::encode(&payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign with HMAC-SHA512
        let mut mac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);

        let token_str = format!("{}.{}", signing_input, signature_b64);

        let parsed = ParsedToken::from_string(&token_str).expect("parse failed");

        let token = TokenValidator::new(parsed)
            .ensure_issuer(|iss| {
                if iss == "https://example.com" {
                    Ok(())
                } else {
                    Err(Error::IssuerNotTrusted(iss.to_string()))
                }
            })
            .verify_signature(SignatureVerification::with_secret(secret, AlgorithmPolicy::hs512_only()))
            .validate_token(ValidationConfig::default())
            .run()
            .expect("verification failed");

        assert_eq!(token.issuer(), Some("https://example.com"));
        assert_eq!(token.subject(), Some("test-user"));
        assert_eq!(token.header().algorithm_str(), alg);
    }
}

// ============================================================================
// RSA Algorithm Round-Trips (RS256, RS384, RS512)
// ============================================================================

#[cfg(feature = "rsa")]
mod rsa_tests {
    use super::*;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::RsaPrivateKey;

    #[test]
    fn round_trip_rs256() {
        test_rsa_round_trip_hs256();
    }

    #[test]
    #[ignore = "RSA test infrastructure needs sha2/rsa version alignment"]
    fn round_trip_rs384() {
        // TODO: Implement after resolving rsa crate version compatibility
    }

    #[test]
    #[ignore = "RSA test infrastructure needs sha2/rsa version alignment"]
    fn round_trip_rs512() {
        // TODO: Implement after resolving rsa crate version compatibility
    }

    fn test_rsa_round_trip_hs256() {
        let alg = "RS256";
        use rand::thread_rng;
        use rsa::traits::PublicKeyParts;

        // Generate RSA key pair using rsa crate
        let mut rng = thread_rng();
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate key");
        let public_key = private_key.to_public_key();
        let modulus_len = public_key.n().to_bytes_be().len();

        // Convert to backend format for signing (creates properly formatted PKCS#1 v1.5 signatures with OID)
        let pkcs8_doc = private_key
            .to_pkcs8_der()
            .expect("failed to serialize private key");

        // Create token
        let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(
            r#"{{"iss":"https://example.com","sub":"test-user","exp":{},"iat":{}}}"#,
            now + 3600,
            now
        );

        let header_b64 = jwtiny::utils::base64url::encode(&header);
        let payload_b64 = jwtiny::utils::base64url::encode(&payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign with appropriate backend (creates properly formatted PKCS#1 v1.5 signatures with OID)
        let (signature_b64, public_key_der) = {
            #[cfg(feature = "aws-lc-rs")]
            {
                use aws_lc_rs::rand::SystemRandom;
                use aws_lc_rs::signature::{KeyPair, RsaKeyPair, RSA_PKCS1_SHA256};

                let ring_keypair = RsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes())
                    .expect("failed to create aws-lc-rs RsaKeyPair");
                let public_key_der = ring_keypair.public_key().as_ref().to_vec();

                let rng = SystemRandom::new();
                let mut signature_bytes = vec![0u8; modulus_len];
                ring_keypair
                    .sign(
                        &RSA_PKCS1_SHA256,
                        &rng,
                        signing_input.as_bytes(),
                        &mut signature_bytes,
                    )
                    .expect("failed to sign");
                let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);
                (signature_b64, public_key_der)
            }
            #[cfg(not(feature = "aws-lc-rs"))]
            {
                use ring::rand::SystemRandom;
                use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};

                let ring_keypair = RsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes())
                    .expect("failed to create ring RsaKeyPair");
                let public_key_der = ring_keypair.public().as_ref().to_vec();

                let rng = SystemRandom::new();
                let mut signature_bytes = vec![0u8; ring_keypair.public().modulus_len()];
                ring_keypair
                    .sign(
                        &RSA_PKCS1_SHA256,
                        &rng,
                        signing_input.as_bytes(),
                        &mut signature_bytes,
                    )
                    .expect("failed to sign");
                let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);
                (signature_b64, public_key_der)
            }
        };

        let token_str = format!("{}.{}", signing_input, signature_b64);

        // Parse and verify
        let parsed = ParsedToken::from_string(&token_str).expect("parse failed");

        let token = TokenValidator::new(parsed)
            .ensure_issuer(|iss| {
                if iss == "https://example.com" {
                    Ok(())
                } else {
                    Err(Error::IssuerNotTrusted(iss.to_string()))
                }
            })
            .verify_signature(SignatureVerification::with_key(Key::rsa_public(
                public_key_der,
            )))
            .validate_token(ValidationConfig::default())
            .run()
            .expect("verification failed");

        // Verify claims
        assert_eq!(token.issuer(), Some("https://example.com"));
        assert_eq!(token.subject(), Some("test-user"));
        assert_eq!(token.header().algorithm_str(), alg);
    }
}

// ============================================================================
// ECDSA Algorithm Round-Trips (ES256, ES384)
// ============================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_tests {
    use super::*;

    // Note: ECDSA testing requires generating keys and signing tokens.
    // For now, we'll add placeholder tests that will be implemented
    // once we have proper ECDSA key generation utilities.

    #[test]
    #[ignore = "requires ECDSA key generation utilities"]
    fn round_trip_es256() {
        // TODO: Implement with proper ECDSA P-256 key generation
        // Similar to RSA tests but with ECDSA signing
    }

    #[test]
    #[ignore = "requires ECDSA key generation utilities"]
    fn round_trip_es384() {
        // TODO: Implement with proper ECDSA P-384 key generation
    }
}

// ============================================================================
// Cross-Algorithm Verification Tests
// ============================================================================

#[cfg(feature = "rsa")]
mod cross_algorithm_tests {
    use super::*;

    #[test]
    fn verify_multiple_algorithms_with_policy() {
        // This test verifies that algorithm policy correctly restricts which algorithms are accepted
        // We'll create tokens with different algorithms and verify policy enforcement
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = b"test-secret";

        // Create HS256 token
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(r#"{{"iss":"test","exp":{}}}"#, now + 3600);

        let header_b64 = jwtiny::utils::base64url::encode(header);
        let payload_b64 = jwtiny::utils::base64url::encode(&payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);

        let token_str = format!("{}.{}", signing_input, signature_b64);

        // Should succeed with HS256 in allow list
        let parsed = ParsedToken::from_string(&token_str).unwrap();
        let result = TokenValidator::new(parsed)
            .danger_skip_issuer_validation()
            .verify_signature(
                SignatureVerification::with_secret(secret)
                    .allow_algorithms(AlgorithmPolicy::allow_only(vec![AlgorithmId::HS256])),
            )
            .validate_token(ValidationConfig::default())
            .run();
        assert!(result.is_ok(), "Should accept HS256 when in allow list");

        // Should fail with only HS384 in allow list
        let parsed = ParsedToken::from_string(&token_str).unwrap();
        let result = TokenValidator::new(parsed)
            .danger_skip_issuer_validation()
            .verify_signature(
                SignatureVerification::with_secret(secret)
                    .allow_algorithms(AlgorithmPolicy::allow_only(vec![AlgorithmId::HS384])),
            )
            .validate_token(ValidationConfig::default())
            .run();
        assert!(
            matches!(result, Err(Error::AlgorithmNotAllowed { .. })),
            "Should reject HS256 when not in allow list"
        );
    }
}
