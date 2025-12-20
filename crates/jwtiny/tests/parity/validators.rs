//! Validator wrappers that normalize results from jwtiny and jsonwebtoken
//!
//! This module provides wrapper types that normalize validation results from both
//! libraries into a common `ValidationOutcome` enum, enabling semantic comparison.
//!
//! # Error Normalization

#![allow(dead_code)]
//!
//! Each library has distinct error types. We map them to semantic categories:
//!
//! | Category | jwtiny Error | jsonwebtoken Error |
//! |----------|--------------|-------------------|
//! | `InvalidSignature` | `SignatureInvalid` | `InvalidSignature` |
//! | `InvalidFormat` | `FormatInvalid` | `InvalidToken` |
//! | `Expired` | `TokenExpired` | `ExpiredSignature` |
//! | `NotYetValid` | `TokenNotYetValid` | `ImmatureSignature` |
//! | `AlgorithmNotAllowed` | `AlgorithmNotAllowed` | `InvalidAlgorithm` |
//!
//! # Usage
//!
//! ```rust,no_run
//! use parity::validators::{create_jwtiny_validator, create_jsonwebtoken_validator};
//! use jwtiny::AlgorithmPolicy;
//! use jsonwebtoken::Algorithm;
//!
//! let jwtiny = create_jwtiny_validator("http://localhost:3000",
//!                                        AlgorithmPolicy::rs256_only());
//! let jsonwebtoken = create_jsonwebtoken_validator("http://localhost:3000",
//!                                                    Algorithm::RS256);
//! ```

use super::ValidationOutcome;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use jwtiny::{AlgorithmPolicy, ClaimsValidation, TokenValidator};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

/// Trait for jwtiny validators
#[async_trait::async_trait]
pub trait JwtinyValidatorTrait: Send + Sync {
    async fn validate(&self, token: &str) -> ValidationOutcome;
}

/// Trait for jsonwebtoken validators
#[async_trait::async_trait]
pub trait JsonwebtokenValidatorTrait: Send + Sync {
    async fn validate(&self, token: &str) -> ValidationOutcome;
}

/// Standard claims structure for jsonwebtoken
#[derive(Debug, Serialize, Deserialize)]
struct StandardClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
}

/// Wrapper for jwtiny TokenValidator
pub struct JwtinyValidator {
    validator: TokenValidator,
}

impl JwtinyValidator {
    /// Create a new jwtiny validator with JWKS support
    pub fn with_jwks(
        base_url: String,
        algorithm_policy: AlgorithmPolicy,
        claims_validation: ClaimsValidation,
    ) -> Self {
        let cache = Cache::<String, Vec<u8>>::builder()
            .time_to_live(Duration::from_secs(300))
            .max_capacity(1000)
            .build();

        let client = reqwest::Client::new();

        let validator = TokenValidator::new()
            .algorithms(algorithm_policy)
            .issuer(move |iss| iss.starts_with(&base_url))
            .validate(claims_validation)
            .cache(cache)
            .jwks(client);

        Self { validator }
    }

    /// Create a validator with a static key
    pub fn with_static_key(
        key_der: Vec<u8>,
        algorithm_policy: AlgorithmPolicy,
        claims_validation: ClaimsValidation,
    ) -> Self {
        let validator = TokenValidator::new()
            .algorithms(algorithm_policy)
            .validate(claims_validation)
            .key(Arc::new(key_der));

        Self { validator }
    }

    /// Map jwtiny error to normalized outcome
    fn map_error(error: jwtiny::Error) -> ValidationOutcome {
        match error {
            jwtiny::Error::SignatureInvalid => ValidationOutcome::InvalidSignature,
            jwtiny::Error::FormatInvalid
            | jwtiny::Error::FormatInvalidJson(_)
            | jwtiny::Error::FormatInvalidBase64(_)
            | jwtiny::Error::TokenTooLarge { .. }
            | jwtiny::Error::SignatureB64TooLarge { .. } => ValidationOutcome::InvalidFormat,
            jwtiny::Error::ClaimMissingField(field) => {
                ValidationOutcome::MissingClaim(field.clone())
            }
            jwtiny::Error::TokenInvalidClaim(msg) => ValidationOutcome::InvalidClaim(msg.clone()),
            jwtiny::Error::AlgorithmNotAllowed { .. } => ValidationOutcome::AlgorithmNotAllowed,
            jwtiny::Error::RemoteError(_)
            | jwtiny::Error::RemoteUrlTooLong { .. }
            | jwtiny::Error::RemoteResponseTooLarge { .. }
            | jwtiny::Error::RemoteJwkSetTooLarge { .. }
            | jwtiny::Error::ConfigurationInvalid(_) => ValidationOutcome::NetworkError,
            _ => ValidationOutcome::InvalidFormat,
        }
    }
}

#[async_trait::async_trait]
impl JwtinyValidatorTrait for JwtinyValidator {
    async fn validate(&self, token: &str) -> ValidationOutcome {
        match self.validator.verify(token).await {
            Ok(_) => ValidationOutcome::Success,
            Err(e) => Self::map_error(e),
        }
    }
}

/// Wrapper for jsonwebtoken decoder
pub struct JsonwebtokenValidator {
    base_url: String,
    algorithm: Algorithm,
    validation_config: Validation,
}

impl JsonwebtokenValidator {
    /// Create a new jsonwebtoken validator with JWKS support
    pub fn with_jwks(
        base_url: String,
        algorithm: Algorithm,
        mut validation_config: Validation,
    ) -> Self {
        validation_config.algorithms = vec![algorithm];
        Self {
            base_url,
            algorithm,
            validation_config,
        }
    }

    /// Create a validator with a static key
    pub fn with_static_key(
        _key_der: Vec<u8>,
        algorithm: Algorithm,
        mut validation_config: Validation,
    ) -> Self {
        validation_config.algorithms = vec![algorithm];
        Self {
            base_url: String::new(),
            algorithm,
            validation_config,
        }
    }

    /// Fetch key from JWKS
    async fn fetch_key(&self, kid: &str) -> Result<DecodingKey, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let url = format!("{}/.well-known/jwks.json", self.base_url);

        let response = client.get(&url).send().await?;
        let jwks: Value = response.json().await?;

        let keys = jwks["keys"]
            .as_array()
            .ok_or("Invalid JWKS: missing keys array")?;

        for key in keys {
            if let Some(key_id) = key["kid"].as_str() {
                if key_id == kid {
                    return self.jwk_to_decoding_key(key);
                }
            }
        }

        Err(format!("Key with kid {kid} not found").into())
    }

    /// Convert JWK to DecodingKey based on algorithm
    fn jwk_to_decoding_key(&self, jwk: &Value) -> Result<DecodingKey, Box<dyn std::error::Error>> {
        match self.algorithm {
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                let n = jwk["n"].as_str().ok_or("Missing RSA modulus (n) in JWK")?;
                let e = jwk["e"].as_str().ok_or("Missing RSA exponent (e) in JWK")?;
                Ok(DecodingKey::from_rsa_components(n, e)?)
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                let x = jwk["x"]
                    .as_str()
                    .ok_or("Missing ECDSA x-coordinate in JWK")?;
                let y = jwk["y"]
                    .as_str()
                    .ok_or("Missing ECDSA y-coordinate in JWK")?;
                Ok(DecodingKey::from_ec_components(x, y)?)
            }
            _ => Err("Unsupported algorithm".into()),
        }
    }

    /// Map jsonwebtoken error to normalized outcome
    fn map_error(error: jsonwebtoken::errors::Error) -> ValidationOutcome {
        use jsonwebtoken::errors::ErrorKind;

        match error.kind() {
            ErrorKind::InvalidSignature => ValidationOutcome::InvalidSignature,
            ErrorKind::InvalidToken
            | ErrorKind::InvalidEcdsaKey
            | ErrorKind::InvalidRsaKey(_)
            | ErrorKind::Base64(_)
            | ErrorKind::Json(_)
            | ErrorKind::Utf8(_) => ValidationOutcome::InvalidFormat,
            ErrorKind::InvalidIssuer => ValidationOutcome::InvalidClaim("iss".to_string()),
            ErrorKind::InvalidAudience => ValidationOutcome::InvalidClaim("aud".to_string()),
            ErrorKind::InvalidSubject => ValidationOutcome::InvalidClaim("sub".to_string()),
            ErrorKind::InvalidAlgorithm => ValidationOutcome::AlgorithmNotAllowed,
            ErrorKind::MissingRequiredClaim(claim) => {
                ValidationOutcome::MissingClaim(claim.clone())
            }
            _ => ValidationOutcome::InvalidFormat,
        }
    }
}

#[async_trait::async_trait]
impl JsonwebtokenValidatorTrait for JsonwebtokenValidator {
    async fn validate(&self, token: &str) -> ValidationOutcome {
        // Decode header to get kid
        let header = match decode_header(token) {
            Ok(h) => h,
            Err(e) => return Self::map_error(e),
        };

        let kid = match header.kid {
            Some(k) => k,
            None => return ValidationOutcome::MissingClaim("kid".to_string()),
        };

        // Fetch key from JWKS
        let key = match self.fetch_key(&kid).await {
            Ok(k) => k,
            Err(_) => return ValidationOutcome::NetworkError,
        };

        // Validate token
        match decode::<StandardClaims>(token, &key, &self.validation_config) {
            Ok(_) => ValidationOutcome::Success,
            Err(e) => Self::map_error(e),
        }
    }
}

/// Helper to create a jwtiny validator for a specific algorithm
pub fn create_jwtiny_validator(
    base_url: &str,
    algorithm_policy: AlgorithmPolicy,
) -> JwtinyValidator {
    JwtinyValidator::with_jwks(
        base_url.to_string(),
        algorithm_policy,
        ClaimsValidation::default()
            .no_exp_validation()
            .no_nbf_validation()
            .no_iat_validation(),
    )
}

/// Helper to create a jsonwebtoken validator for a specific algorithm
/// Returns None if the algorithm is not supported by jsonwebtoken
pub fn create_jsonwebtoken_validator(
    base_url: &str,
    algorithm: Algorithm,
) -> JsonwebtokenValidator {
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;

    JsonwebtokenValidator::with_jwks(base_url.to_string(), algorithm, validation)
}

/// Helper to check if an algorithm is supported by jsonwebtoken
pub fn is_jsonwebtoken_supported(alg: super::token_gen::Algorithm) -> bool {
    to_jsonwebtoken_algorithm(alg).is_some()
}

/// Convert our Algorithm enum to jsonwebtoken Algorithm
/// Note: ES512 is not supported by jsonwebtoken (ring doesn't support P-521)
pub fn to_jsonwebtoken_algorithm(
    alg: super::token_gen::Algorithm,
) -> Option<jsonwebtoken::Algorithm> {
    match alg {
        super::token_gen::Algorithm::RS256 => Some(Algorithm::RS256),
        super::token_gen::Algorithm::RS384 => Some(Algorithm::RS384),
        super::token_gen::Algorithm::RS512 => Some(Algorithm::RS512),
        super::token_gen::Algorithm::ES256 => Some(Algorithm::ES256),
        super::token_gen::Algorithm::ES384 => Some(Algorithm::ES384),
        super::token_gen::Algorithm::ES512 => None, // Not supported by ring/jsonwebtoken
    }
}

/// Convert our Algorithm enum to jwtiny AlgorithmPolicy
pub fn to_jwtiny_policy(alg: super::token_gen::Algorithm) -> AlgorithmPolicy {
    match alg {
        super::token_gen::Algorithm::RS256 => AlgorithmPolicy::rs256_only(),
        super::token_gen::Algorithm::RS384 => AlgorithmPolicy::rs384_only(),
        super::token_gen::Algorithm::RS512 => AlgorithmPolicy::rs512_only(),
        super::token_gen::Algorithm::ES256 => AlgorithmPolicy::es256_only(),
        super::token_gen::Algorithm::ES384 => AlgorithmPolicy::es384_only(),
        super::token_gen::Algorithm::ES512 => AlgorithmPolicy::es512_only(),
    }
}
