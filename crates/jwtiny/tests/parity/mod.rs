//! Parity test harness for ensuring compatibility between jwtiny and jsonwebtoken
//!
//! This module provides a generic test framework that validates both libraries
//! produce identical results for the same JWT tokens. All tokens are generated
//! by jwkserve (localhost:3000) to ensure cryptographic validity.
//!
//! # Architecture

#![allow(dead_code)]
//!
//! ```text
//! ┌─────────────────┐
//! │  jwkserve:3000  │  ← Authoritative token source
//! └────────┬────────┘
//!          │
//!          ├─→ Generate cryptographically valid JWTs
//!          └─→ Serve JWKS endpoints
//!          
//! ┌─────────────────────────────────────────┐
//! │         Parity Test Harness             │
//! │  ┌──────────────┐  ┌─────────────────┐ │
//! │  │   jwtiny     │  │  jsonwebtoken   │ │
//! │  │  Validator   │  │   Validator     │ │
//! │  └──────┬───────┘  └────────┬────────┘ │
//! │         │                   │          │
//! │         └──────┬────────────┘          │
//! │                ▼                        │
//! │         Assert Parity                   │
//! │    (both agree on outcome)              │
//! └─────────────────────────────────────────┘
//! ```
//!
//! # Design Principles
//!
//! 1. **Identical Inputs**: Both validators receive byte-identical tokens
//! 2. **Normalized Errors**: Map library errors to semantic `ValidationOutcome`
//! 3. **Real Crypto**: jwkserve generates valid signatures, no hand-crafted vectors
//! 4. **Production Fidelity**: Use real JWKS HTTP endpoints, not mocks
//! 5. **Fail Together**: Both libraries must agree when validation fails
//!
//! # Usage
//!
//! ```rust,no_run
//! use parity::token_gen::{Algorithm, TokenBuilder};
//! use parity::validators::{create_jwtiny_validator, create_jsonwebtoken_validator};
//! use parity::{assert_both_succeed, run_parity_test};
//!
//! # async fn example() {
//! // Generate token via jwkserve
//! let token = TokenBuilder::new("http://localhost:3000", Algorithm::RS256)
//!     .standard_valid_claims()
//!     .generate()
//!     .await
//!     .unwrap();
//!
//! // Create validators
//! let jwtiny = create_jwtiny_validator("http://localhost:3000",
//!                                        jwtiny::AlgorithmPolicy::rs256_only());
//! let jsonwebtoken = create_jsonwebtoken_validator("http://localhost:3000",
//!                                                    jsonwebtoken::Algorithm::RS256);
//!
//! // Run parity test
//! let result = run_parity_test(&token, &jwtiny, &jsonwebtoken).await;
//! assert_both_succeed(&result);
//! # }
//! ```
//!
//! See [`signature_parity.rs`](../../signature_parity.rs) for comprehensive examples.

pub mod token_gen;
pub mod validators;

use std::fmt;

/// Normalized validation result for comparing library outcomes
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationOutcome {
    /// Token validated successfully
    Success,
    /// Token signature is invalid
    InvalidSignature,
    /// Token format is malformed
    InvalidFormat,
    /// Algorithm not allowed by policy
    AlgorithmNotAllowed,
    /// Network or JWKS fetch error
    NetworkError,
    /// Required claim is missing
    MissingClaim(String),
    /// Claim validation failed
    InvalidClaim(String),
}

impl fmt::Display for ValidationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::InvalidSignature => write!(f, "InvalidSignature"),
            Self::InvalidFormat => write!(f, "InvalidFormat"),
            Self::AlgorithmNotAllowed => write!(f, "AlgorithmNotAllowed"),
            Self::NetworkError => write!(f, "NetworkError"),
            Self::MissingClaim(claim) => write!(f, "MissingClaim({claim})"),
            Self::InvalidClaim(claim) => write!(f, "InvalidClaim({claim})"),
        }
    }
}

/// Parity test result containing outcomes from both validators
#[derive(Debug)]
pub struct ParityResult {
    pub jwtiny_outcome: ValidationOutcome,
    pub jsonwebtoken_outcome: ValidationOutcome,
}

impl ParityResult {
    /// Check if both validators agree on the outcome
    pub fn is_parity(&self) -> bool {
        self.jwtiny_outcome == self.jsonwebtoken_outcome
    }
}

/// Run a parity test with both validators
///
/// # Arguments
/// * `token` - The JWT token to validate
/// * `jwtiny_validator` - Configured jwtiny validator
/// * `jsonwebtoken_validator` - Configured jsonwebtoken validator
///
/// # Returns
/// A `ParityResult` containing outcomes from both validators
pub async fn run_parity_test<J, T>(
    token: &str,
    jwtiny_validator: &J,
    jsonwebtoken_validator: &T,
) -> ParityResult
where
    J: validators::JwtinyValidatorTrait,
    T: validators::JsonwebtokenValidatorTrait,
{
    let jwtiny_outcome = jwtiny_validator.validate(token).await;
    let jsonwebtoken_outcome = jsonwebtoken_validator.validate(token).await;

    ParityResult {
        jwtiny_outcome,
        jsonwebtoken_outcome,
    }
}

/// Assert that both validators have parity (same outcome)
///
/// This is the primary assertion used in parity tests.
/// Panics with a descriptive message if validators disagree.
pub fn assert_parity(result: &ParityResult) {
    assert!(
        result.is_parity(),
        "Parity test failed!\n  jwtiny: {}\n  jsonwebtoken: {}",
        result.jwtiny_outcome,
        result.jsonwebtoken_outcome
    );
}

/// Assert that both validators succeed
pub fn assert_both_succeed(result: &ParityResult) {
    assert!(
        result.jwtiny_outcome == ValidationOutcome::Success,
        "jwtiny validation failed: {}",
        result.jwtiny_outcome
    );
    assert!(
        result.jsonwebtoken_outcome == ValidationOutcome::Success,
        "jsonwebtoken validation failed: {}",
        result.jsonwebtoken_outcome
    );
    assert_parity(result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_outcome_equality() {
        assert_eq!(ValidationOutcome::Success, ValidationOutcome::Success);
        assert_eq!(
            ValidationOutcome::InvalidSignature,
            ValidationOutcome::InvalidSignature
        );
        assert_ne!(
            ValidationOutcome::Success,
            ValidationOutcome::InvalidSignature
        );
    }

    #[test]
    fn test_parity_result_is_parity() {
        let result = ParityResult {
            jwtiny_outcome: ValidationOutcome::Success,
            jsonwebtoken_outcome: ValidationOutcome::Success,
        };
        assert!(result.is_parity());

        let result = ParityResult {
            jwtiny_outcome: ValidationOutcome::Success,
            jsonwebtoken_outcome: ValidationOutcome::InvalidSignature,
        };
        assert!(!result.is_parity());
    }
}
