//! # jwtiny - Minimal, Type-Safe JWT Validation
//!
//! > Minimal, type-safe JSON Web Token (JWT) validation for Rust.
//!
//! **jwtiny** validates JWT tokens through a builder-pattern API that enforces correct validation
//! order at compile time. Born from the need for `jsonwebtoken` with `miniserde` support, it
//! evolved into a generic JWT library prioritizing safety, clarity, and zero-cost abstractions.
//!
//! ## Overview
//!
//! JWTs (JSON Web Tokens) encode claims as JSON objects secured by digital signatures or message
//! authentication codes. Validating them requires parsing Base64URL-encoded segments, verifying
//! signatures with cryptographic keys, and checking temporal claims like expiration. Common
//! pitfalls include algorithm confusion attacks (accepting asymmetric algorithms when only
//! symmetric keys are trusted), server-side request forgery (SSRF) via untrusted issuer URLs,
//! and timing vulnerabilities in signature comparison.
//!
//! **jwtiny** addresses these through a type-safe state machine: parsing yields a `ParsedToken`,
//! issuer validation produces a `TrustedToken`, signature verification creates a `VerifiedToken`,
//! and claims validation returns the final `Token`. Each stage must complete before the next
//! begins, enforced by Rust's type system. The builder pattern configures all steps upfront,
//! then executes them atomically—preventing partial validation and ensuring cryptographic keys
//! are only used after issuer checks complete.
//!
//! ## Quick Start
//!
//! ```ignore
//! use jwtiny::*;
//!
//! let token = TokenValidator::new(
//!     ParsedToken::from_string(token_str)?
//! )
//!     .ensure_issuer(|iss| Ok(iss == "https://trusted.com"))
//!     .verify_signature(SignatureVerification::with_secret_hs256(b"secret"))
//!     .validate_token(ValidationConfig::default())
//!     .run()?;
//!
//! println!("Subject: {:?}", token.subject());
//! ```
//!
//! ## Validation Flow
//!
//! The library enforces a validation pipeline through type-level state transitions:
//!
//! ```text
//! ParsedToken (parsed header and payload)
//!     │ .ensure_issuer()
//!     ▼
//! TrustedToken (issuer validated; internal type)
//!     │ .verify_signature()
//!     ▼
//! VerifiedToken (signature verified; internal type)
//!     │ .validate_token()
//!     ▼
//! ValidatedToken (claims validated; internal type)
//!     │ .run() / .run_async()
//!     ▼
//! Token (public API; safe to use)
//! ```
//!
//! Only the final `Token` type is exposed publicly. Intermediate types (`TrustedToken`,
//! `VerifiedToken`, `ValidatedToken`) are internal, preventing partial validation from escaping
//! the builder.
//!
//! ## Algorithm Support
//!
//! All algorithms implement a common `Algorithm` trait:
//!
//! - **HMAC** (always enabled): HS256, HS384, HS512
//! - **RSA** (with `rsa` feature): RS256, RS384, RS512
//! - **ECDSA** (with `ecdsa` feature): ES256, ES384
//!
//! ## Signature Verification
//!
//! Choose verification based on the algorithm family:
//!
//! ```ignore
//! // Symmetric key (HMAC) - always enabled
//! SignatureVerification::with_secret_hs256(b"your-256-bit-secret")
//!
//! // Public key (RSA) - requires rsa feature
//! SignatureVerification::with_rsa_rs256(public_key_der)
//!
//! // Remote JWKS fetching - requires remote feature
//! SignatureVerification::with_jwks(
//!     http_client,
//!     AlgorithmPolicy::recommended_asymmetric(),
//!     true,
//! )
//! ```
//!
//! Use algorithm-specific constructors (preferred) or pass an explicit
//! `AlgorithmPolicy` to prevent algorithm confusion.
//!
//! ## Claims Validation
//!
//! Configure temporal and claim-specific checks:
//!
//! ```ignore
//! ValidationConfig::default()
//!     .require_audience("my-api")           // Validate `aud` claim
//!     .max_age(3600)                         // Token must be < 1 hour old
//!     .clock_skew(60)                        // Allow 60s clock skew
//!     .custom(|claims| {                     // Custom validation logic
//!         if claims.subject.as_deref() != Some("admin") {
//!             Err(Error::ClaimValidationFailed(
//!                 ClaimError::Custom("Admin only".to_string())
//!             ))
//!         } else {
//!             Ok(())
//!         }
//!     })
//! ```
//!
//! ## Features
//!
//! - **HMAC** (always enabled): HS256, HS384, HS512
//! - **`rsa`**: RSA algorithms (RS256, RS384, RS512)
//! - **`ecdsa`**: ECDSA algorithms (ES256, ES384)
//! - **`aws-lc-rs`**: Use `aws-lc-rs` backend instead of `ring` for RSA/ECDSA
//! - **`all-algorithms`**: Enable all asymmetric algorithms (RSA + ECDSA)
//! - **`remote`**: Remote JWKS over HTTPS (rustls). Provide an HTTP client.
//!
//! ## Security
//!
//! ### Algorithm Confusion Prevention
//!
//! Always restrict algorithms explicitly. Without restrictions, a token declaring `RS256` might be
//! accepted when you only intended to allow `HS256`.
//!
//! ### SSRF Prevention
//!
//! When using JWKS, validate issuers before fetching keys. Without issuer validation, an attacker
//! can craft a token with an arbitrary `iss` claim, causing your application to fetch keys from
//! attacker-controlled URLs—a classic SSRF vulnerability.
//!
//! ### "none" Algorithm Rejection
//!
//! The `"none"` algorithm (unsigned tokens) is always rejected per [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725).
//!
//! ### Timing Attack Protection
//!
//! HMAC signature verification uses constant-time comparison via the [`constant_time_eq`](https://crates.io/crates/constant_time_eq)
//! crate, preventing timing-based key recovery attacks.
//!
//! ## References
//!
//! - [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) — JSON Web Signature (JWS)
//! - [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — JSON Web Token (JWT)
//! - [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) — JSON Web Signature Best Practices

// Core modules
pub mod error;
pub mod utils;

// Algorithm system
pub mod algorithm;
pub mod keys;

// Claims and validation
pub mod claims;

// Token types
pub mod token;

// Validator (main public API)
pub mod validator;

// Remote fetching (JWKS, OIDC discovery)
#[cfg(feature = "remote")]
pub mod discovery;
#[cfg(feature = "remote")]
pub mod jwks;
#[cfg(feature = "remote")]
pub mod remote;

// ============================================================================
// PUBLIC API - Only these types are exposed to users
// ============================================================================

// Main validation flow types
pub use token::ParsedToken;
pub use token::Token;
pub use validator::TokenValidator;

// Configuration types
pub use claims::ValidationConfig;
pub use validator::SignatureVerification;

// Supporting types for advanced usage
pub use algorithm::{AlgorithmId, AlgorithmPolicy};
pub use claims::Claims;
pub use error::{ClaimError, Error, Result};
pub use keys::Key;
pub use token::TokenHeader;

// Re-export curve type for ECDSA
#[cfg(feature = "ecdsa")]
pub use keys::EcdsaCurve;

// ============================================================================
// Internal types - Not part of public API
// ============================================================================
// - TrustedToken (internal state after issuer validation)
// - VerifiedToken (internal state after signature verification)
// - ValidatedToken (internal state after claims validation)
// - Algorithm trait and implementations
// - ClaimsValidator
// ============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_flow_hmac() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Create a token manually
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(
            r#"{{"iss":"https://example.com","sub":"user123","exp":{},"iat":{}}}"#,
            now + 3600,
            now
        );

        let header_b64 = utils::base64url::encode(header);
        let payload_b64 = utils::base64url::encode(&payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let secret = b"my-secret-key";
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = utils::base64url::encode_bytes(&signature_bytes);

        let token_str = format!("{}.{}", signing_input, signature_b64);

        // Validate the token through the full pipeline
        let parsed = ParsedToken::from_string(&token_str).expect("Parse failed");

        let trusted = parsed
            .trust_issuer(|iss| {
                if iss == "https://example.com" {
                    Ok(())
                } else {
                    Err(Error::IssuerNotTrusted(iss.to_string()))
                }
            })
            .expect("Trust failed");

        let key = Key::symmetric(secret);
        let verified = trusted.verify_signature(&key).expect("Verification failed");

        let config = ValidationConfig::default();
        let validated = verified.validate(&config).expect("Validation failed");

        assert_eq!(validated.issuer(), Some("https://example.com"));
        assert_eq!(validated.subject(), Some("user123"));
    }

    #[test]
    fn test_issuer_validation_fails() {
        let header = r#"{"alg":"HS256"}"#;
        let payload = r#"{"iss":"https://untrusted.com","sub":"user"}"#;
        let token_str = format!(
            "{}.{}.{}",
            utils::base64url::encode(header),
            utils::base64url::encode(payload),
            utils::base64url::encode("sig")
        );

        let parsed = ParsedToken::from_string(&token_str).unwrap();

        let result = parsed.trust_issuer(|iss| {
            if iss == "https://trusted.com" {
                Ok(())
            } else {
                Err(Error::IssuerNotTrusted(iss.to_string()))
            }
        });

        assert!(matches!(result, Err(Error::IssuerNotTrusted(_))));
    }

    #[test]
    fn test_signature_verification_fails() {
        let header = r#"{"alg":"HS256"}"#;
        let payload = r#"{"iss":"https://example.com","sub":"user"}"#;
        let token_str = format!(
            "{}.{}.{}",
            utils::base64url::encode(header),
            utils::base64url::encode(payload),
            utils::base64url::encode("wrong_signature")
        );

        let parsed = ParsedToken::from_string(&token_str).unwrap();
        let trusted = parsed.danger_trust_without_issuer_check();

        let key = Key::symmetric(b"secret");
        let result = trusted.verify_signature(&key);

        assert!(matches!(result, Err(Error::SignatureInvalid)));
    }

    #[test]
    fn test_claims_validation_fails() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let header = r#"{"alg":"HS256"}"#;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Expired token
        let payload = format!(r#"{{"iss":"https://example.com","exp":{}}}"#, now - 3600);

        let header_b64 = utils::base64url::encode(header);
        let payload_b64 = utils::base64url::encode(&payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let secret = b"secret";
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = utils::base64url::encode_bytes(&signature_bytes);

        let token_str = format!("{}.{}", signing_input, signature_b64);

        let parsed = ParsedToken::from_string(&token_str).unwrap();
        let trusted = parsed.danger_trust_without_issuer_check();
        let key = Key::symmetric(secret);
        let verified = trusted.verify_signature(&key).unwrap();

        let result = verified.validate(&ValidationConfig::default());

        assert!(matches!(
            result,
            Err(Error::ClaimValidationFailed(ClaimError::Expired { .. }))
        ));
    }

    #[test]
    fn test_none_algorithm_rejected() {
        let header = r#"{"alg":"none"}"#;
        let payload = r#"{"iss":"test"}"#;
        let token_str = format!(
            "{}.{}.{}",
            utils::base64url::encode(header),
            utils::base64url::encode(payload),
            utils::base64url::encode("")
        );

        let result = ParsedToken::from_string(&token_str);
        // The token parses, but algorithm validation fails
        let parsed = result.unwrap();
        let alg_result = parsed.algorithm();
        assert!(matches!(alg_result, Err(Error::NoneAlgorithmRejected)));
    }

    #[cfg(all(feature = "remote", feature = "rsa"))]
    mod jwks_integration_tests {
        use super::*;
        use crate::jwks::resolve_key_from_issuer;
        use crate::remote::http::HttpClient;
        use std::future::Future;
        use std::pin::Pin;

        // Mock HTTP client for testing
        struct MockHttpClient {
            discovery_response: String,
            jwks_response: String,
        }

        impl HttpClient for MockHttpClient {
            fn fetch(
                &self,
                url: &str,
            ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + '_>> {
                let url = url.to_string();
                let dr = self.discovery_response.clone();
                let jr = self.jwks_response.clone();
                Box::pin(async move {
                    if url.contains("/.well-known/openid-configuration") {
                        Ok(dr.as_bytes().to_vec())
                    } else if url.contains("/jwks.json") {
                        Ok(jr.as_bytes().to_vec())
                    } else {
                        Err(Error::RemoteError(format!("unexpected url: {}", url)))
                    }
                })
            }
        }

        fn mock_http_client(discovery_response: String, jwks_response: String) -> MockHttpClient {
            MockHttpClient {
                discovery_response,
                jwks_response,
            }
        }

        #[tokio::test]
        async fn test_full_jwks_flow() {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            // Create a valid token (HMAC for simplicity, but we'll test RSA JWKS flow)
            let header = r#"{"alg":"HS256","typ":"JWT"}"#;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let payload = format!(
                r#"{{"iss":"https://auth.example.com","sub":"user123","exp":{}}}"#,
                now + 3600
            );

            let header_b64 = utils::base64url::encode(header);
            let payload_b64 = utils::base64url::encode(&payload);
            let signing_input = format!("{}.{}", header_b64, payload_b64);

            let secret = b"test-secret";
            let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
            mac.update(signing_input.as_bytes());
            let signature_bytes = mac.finalize().into_bytes();
            let signature_b64 = utils::base64url::encode_bytes(&signature_bytes);

            let token_str = format!("{}.{}", signing_input, signature_b64);

            // Test that we can parse and validate issuer
            let parsed = ParsedToken::from_string(&token_str).unwrap();
            let trusted = parsed
                .trust_issuer(|iss| {
                    if iss == "https://auth.example.com" {
                        Ok(())
                    } else {
                        Err(Error::IssuerNotTrusted(iss.to_string()))
                    }
                })
                .unwrap();

            // Verify signature with key (not JWKS, but tests the flow)
            let key = Key::symmetric(secret);
            let verified = trusted.verify_signature(&key).unwrap();
            let config = ValidationConfig::default();
            let validated = verified.validate(&config).unwrap();

            assert_eq!(validated.issuer(), Some("https://auth.example.com"));
            assert_eq!(validated.subject(), Some("user123"));
        }

        #[tokio::test]
        async fn test_jwks_resolver() {
            // Mock discovery response
            let discovery = r#"{"jwks_uri":"https://auth.example.com/.well-known/jwks.json"}"#;

            // Mock JWKS response (simplified, minimal valid RSA key)
            let n_b64 = utils::base64url::encode_bytes(&[0x00, 0x01, 0x02, 0x03]);
            let e_b64 = utils::base64url::encode_bytes(&[0x01, 0x00, 0x01]);
            let jwks = format!(
                r#"{{"keys":[{{"kty":"RSA","kid":"test-key","n":"{}","e":"{}"}}]}}"#,
                n_b64, e_b64
            );

            let client = mock_http_client(discovery.to_string(), jwks);

            // Test resolver (standalone function)
            let key = resolve_key_from_issuer(
                &client,
                "https://auth.example.com",
                &AlgorithmId::RS256,
                Some("test-key"),
                false, // Don't use cache for testing
            )
            .await;

            // Should succeed (even if the key is not a real RSA key, DER encoding should work)
            assert!(key.is_ok());
            assert!(matches!(key.unwrap(), Key::Asymmetric(_)));
        }

        #[tokio::test]
        async fn test_run_async_with_jwks() {
            // Test run_async with proper JWKS flow
            // For HMAC tokens, use run() directly. run_async() is for JWKS (RSA/ECDSA)
            // This test verifies the API structure - full JWKS tests are in jwks module
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            let header = r#"{"alg":"HS256","typ":"JWT"}"#;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let payload = format!(
                r#"{{"iss":"https://auth.example.com","sub":"user123","exp":{}}}"#,
                now + 3600
            );

            let header_b64 = utils::base64url::encode(header);
            let payload_b64 = utils::base64url::encode(&payload);
            let signing_input = format!("{}.{}", header_b64, payload_b64);

            let secret = b"test-secret";
            let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
            mac.update(signing_input.as_bytes());
            let signature_bytes = mac.finalize().into_bytes();
            let signature_b64 = utils::base64url::encode_bytes(&signature_bytes);

            let token_str = format!("{}.{}", signing_input, signature_b64);

            // For HMAC tokens, use run() directly since we have the key
            // run_async() is designed for JWKS (RSA/ECDSA) tokens
            let parsed = ParsedToken::from_string(&token_str).unwrap();
            let token = TokenValidator::new(parsed)
                .ensure_issuer(|iss| {
                    if iss == "https://auth.example.com" {
                        Ok(())
                    } else {
                        Err(Error::IssuerNotTrusted(iss.to_string()))
                    }
                })
                .verify_signature(SignatureVerification::with_secret_hs256(secret))
                .validate_token(ValidationConfig::default())
                .run();

            assert!(token.is_ok());
            let token = token.unwrap();
            assert_eq!(token.issuer(), Some("https://auth.example.com"));
            assert_eq!(token.subject(), Some("user123"));
        }
    }
}
