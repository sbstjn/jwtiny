//! Token validator with builder pattern
//!
//! This module provides a builder-pattern API for JWT validation that enforces
//! the correct validation order at compile time. All validation steps are
//! configured upfront via the builder, then executed atomically when `run()`
//! or `run_async()` is called.
//!
//! The builder pattern prevents partial validation by ensuring all required steps
//! are configured before execution begins. This eliminates common mistakes like
//! skipping signature verification or forgetting to validate the issuer before
//! fetching keys from JWKS endpoints.

use crate::algorithm::AlgorithmPolicy;
use crate::claims::ValidationConfig;
use crate::error::{Error, Result};
use crate::keys::Key;
use crate::token::{ParsedToken, Token};

#[cfg(feature = "remote")]
use std::sync::Arc;

/// Options for signature verification
///
/// Configures how the token signature should be verified. Choose one of:
/// - **Symmetric key** (for HMAC algorithms: HS256, HS384, HS512)
/// - **Asymmetric public key** (for RSA/ECDSA algorithms: RS256, ES256, etc.)
/// - **HTTP client for JWKS fetching** (for RSA/ECDSA with remote keys)
///
/// Algorithm restrictions are recommended to prevent algorithm confusion
/// attacks. See [`allow_algorithms`](Self::allow_algorithms) for details.
#[derive(Clone)]
pub struct SignatureVerification {
    key: Option<Key>,
    algorithm_policy: Option<AlgorithmPolicy>,
    #[cfg(feature = "remote")]
    http_client: Option<Arc<crate::remote::http::HttpClient>>,
    #[cfg(feature = "remote")]
    use_cache: bool,
}

impl SignatureVerification {
    /// Verify using a symmetric key (HMAC algorithms)
    pub fn with_secret(secret: &[u8]) -> Self {
        Self {
            key: Some(Key::symmetric(secret)),
            algorithm_policy: None,
            #[cfg(feature = "remote")]
            http_client: None,
            #[cfg(feature = "remote")]
            use_cache: true,
        }
    }

    /// Verify using a public key (RSA/ECDSA algorithms)
    pub fn with_key(key: Key) -> Self {
        Self {
            key: Some(key),
            algorithm_policy: None,
            #[cfg(feature = "remote")]
            http_client: None,
            #[cfg(feature = "remote")]
            use_cache: true,
        }
    }

    /// Verify using JWKS (automatic key fetching from remote issuer)
    ///
    /// This configures signature verification to use JWKS fetching.
    /// The HTTP client will be used to fetch keys from the issuer's JWKS endpoint.
    ///
    /// # Arguments
    ///
    /// * `client` - HTTP client for fetching JWKS (must implement `HttpClient` trait)
    /// * `use_cache` - Whether to use cached discovery and JWKS documents (default: `true`)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let token = TokenValidator::new(parsed)
    ///     .verify_signature(
    ///         SignatureVerification::with_jwks(http_client, true)
    ///     )
    ///     .run_async()
    ///     .await?;
    /// ```
    #[cfg(feature = "remote")]
    pub fn with_jwks(client: crate::remote::http::HttpClient, use_cache: bool) -> Self {
        Self {
            key: None,
            algorithm_policy: None,
            http_client: Some(Arc::new(client)),
            use_cache,
        }
    }

    /// Restrict which algorithms are allowed (recommended)
    ///
    /// This prevents algorithm confusion attacks by only allowing algorithms you
    /// explicitly trust. Without restrictions, a token declaring `RS256` might be
    /// accepted when you only intended to allow `HS256`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// SignatureVerification::with_secret(b"secret")
    ///     .allow_algorithms(AlgorithmPolicy::allow_only(vec![AlgorithmId::HS256]))
    /// ```
    pub fn allow_algorithms(mut self, policy: AlgorithmPolicy) -> Self {
        self.algorithm_policy = Some(policy);
        self
    }

    /// Get the key for verification (direct key, not JWKS)
    fn key(&self) -> Result<&Key> {
        self.key
            .as_ref()
            .ok_or_else(|| Error::MissingField("signature verification key".to_string()))
    }

    /// Get the algorithm policy
    fn policy(&self) -> Option<&AlgorithmPolicy> {
        self.algorithm_policy.as_ref()
    }

    /// Check if JWKS is configured (has HTTP client)
    #[cfg(feature = "remote")]
    fn has_jwks(&self) -> bool {
        self.http_client.is_some()
    }

    /// Get HTTP client for JWKS (if configured)
    #[cfg(feature = "remote")]
    fn http_client(&self) -> Option<&crate::remote::http::HttpClient> {
        self.http_client.as_ref().map(|arc| arc.as_ref())
    }

    /// Get cache setting for JWKS
    #[cfg(feature = "remote")]
    fn use_cache(&self) -> bool {
        self.use_cache
    }
}

impl Default for SignatureVerification {
    fn default() -> Self {
        Self {
            key: None,
            algorithm_policy: None,
            #[cfg(feature = "remote")]
            http_client: None,
            #[cfg(feature = "remote")]
            use_cache: true,
        }
    }
}

/// JWT token validator with builder pattern
///
/// This validator collects all validation configuration upfront, then executes
/// the validation steps in the correct order when `run()` is called.
///
/// # Validation Flow
///
/// 1. Parse token (done before creating validator)
/// 2. Check basic integrity (header format, algorithm)
/// 3. Validate issuer (prevent SSRF)
/// 4. Verify signature (cryptographic verification)
/// 5. Validate claims (exp, nbf, iat, aud, etc.)
///
/// # Example
///
/// ```ignore
/// use jwtiny::*;
///
/// let token = ParsedToken::from_string("eyJ...")?;
///
/// let validated = TokenValidator::new(token)
///     .ensure_issuer(|iss| {
///         if iss == "https://trusted.com" {
///             Ok(())
///         } else {
///             Err(Error::IssuerNotTrusted(iss.to_string()))
///         }
///     })
///     .verify_signature(
///         SignatureVerification::with_secret(b"my-secret")
///     )
///     .validate_token(
///         ValidationConfig::default()
///             .require_audience("my-api")
///     )
///     .run()?;
///
/// println!("Subject: {:?}", validated.subject());
/// ```
pub struct TokenValidator {
    parsed: ParsedToken,
    #[allow(clippy::type_complexity)]
    issuer_validator: Option<Box<dyn Fn(&str) -> Result<()> + Send + Sync>>,
    signature_verification: Option<SignatureVerification>,
    claims_validation: Option<ValidationConfig>,
}

impl TokenValidator {
    /// Create a new validator from a parsed token
    ///
    /// # Example
    ///
    /// ```ignore
    /// let token = ParsedToken::from_string("eyJ...")?;
    /// let validator = TokenValidator::new(token);
    /// ```
    pub fn new(parsed: ParsedToken) -> Self {
        Self {
            parsed,
            issuer_validator: None,
            signature_verification: None,
            claims_validation: None,
        }
    }

    /// Ensure the issuer is trusted
    ///
    /// Validates the `iss` claim before proceeding with signature verification.
    /// **Critical for preventing SSRF attacks** when using JWKS fetching: an
    /// attacker can craft a token with an arbitrary `iss` claim, causing your
    /// application to fetch keys from attacker-controlled URLs.
    ///
    /// The validator function receives the issuer string and should return:
    /// - `Ok(())` if the issuer is trusted
    /// - `Err(...)` if the issuer is not trusted
    ///
    /// # Note
    ///
    /// The validator function must be `Fn` (not `FnOnce`) and should not mutate
    /// captured state. This allows the validator to be used multiple times if needed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// validator.ensure_issuer(|iss| {
    ///     if iss == "https://auth.example.com" {
    ///         Ok(())
    ///     } else {
    ///         Err(Error::IssuerNotTrusted(iss.to_string()))
    ///     }
    /// })
    /// ```
    pub fn ensure_issuer<F>(mut self, validator: F) -> Self
    where
        F: Fn(&str) -> Result<()> + Send + Sync + 'static,
    {
        self.issuer_validator = Some(Box::new(validator));
        self
    }

    /// Skip issuer validation (use with caution!)
    ///
    /// Skips the issuer validation step. Only use this if:
    /// - You're providing the signing key directly (not fetching from JWKS)
    /// - You're validating the issuer through other means
    ///
    /// **Never skip issuer validation when using JWKS**, as this enables SSRF
    /// attacks. For JWKS-based validation, you MUST use `ensure_issuer()`.
    pub fn skip_issuer_check(mut self) -> Self {
        self.issuer_validator = Some(Box::new(|_| Ok(())));
        self
    }

    /// Configure signature verification
    ///
    /// This specifies how the token signature should be verified. Options:
    /// - Symmetric key (HMAC algorithms)
    /// - Asymmetric public key (RSA/ECDSA algorithms)
    /// - HTTP client for JWKS fetching (future feature)
    ///
    /// # Example
    ///
    /// ```ignore
    /// // With symmetric key (HMAC)
    /// validator.verify_signature(
    ///     SignatureVerification::with_secret(b"my-secret")
    /// )
    ///
    /// // With public key (RSA)
    /// validator.verify_signature(
    ///     SignatureVerification::with_key(Key::rsa_public(der_bytes))
    /// )
    ///
    /// // With algorithm restrictions
    /// validator.verify_signature(
    ///     SignatureVerification::with_secret(b"secret")
    ///         .allow_algorithms(AlgorithmPolicy::allow_only(&[AlgorithmId::HS256]))
    /// )
    /// ```
    pub fn verify_signature(mut self, verification: SignatureVerification) -> Self {
        self.signature_verification = Some(verification);
        self
    }

    /// Configure claims validation
    ///
    /// This specifies how the token claims should be validated. You can:
    /// - Validate time-based claims (exp, nbf, iat)
    /// - Validate audience (aud)
    /// - Set clock skew tolerance
    /// - Add custom validation logic
    ///
    /// # Example
    ///
    /// ```ignore
    /// validator.validate_token(
    ///     ValidationConfig::default()
    ///         .require_audience("my-api")
    ///         .max_age(3600)
    ///         .clock_skew(60)
    /// )
    /// ```
    pub fn validate_token(mut self, config: ValidationConfig) -> Self {
        self.claims_validation = Some(config);
        self
    }

    /// Skip claims validation (use with caution!)
    ///
    /// This skips the claims validation step. Only use this if you're
    /// performing custom validation on the claims yourself.
    pub fn skip_claims_validation(mut self) -> Self {
        self.claims_validation = Some(ValidationConfig::default().skip_all());
        self
    }

    /// Run the validation pipeline
    ///
    /// This executes all validation steps in the correct order:
    /// 1. Check basic integrity (algorithm validation)
    /// 2. Validate issuer (if configured)
    /// 3. Verify signature (if configured)
    /// 4. Validate claims (if configured)
    ///
    /// Returns a fully validated `Token` that is safe to use.
    ///
    /// # Errors
    ///
    /// Returns an error if any validation step fails:
    /// - `Error::UnsupportedAlgorithm` - Invalid or unsupported algorithm
    /// - `Error::IssuerNotTrusted` - Issuer validation failed
    /// - `Error::SignatureInvalid` - Signature verification failed
    /// - `Error::ClaimValidationFailed` - Claims validation failed
    /// - `Error::MissingKey` - No key provided for signature verification
    ///
    /// # Example
    ///
    /// ```ignore
    /// let token = validator.run()?;
    /// println!("Token validated! Subject: {:?}", token.subject());
    /// ```
    pub fn run(self) -> Result<Token> {
        // Step 1: Validate algorithm policy (if configured)
        if let Some(ref verification) = self.signature_verification {
            if let Some(policy) = verification.policy() {
                let algorithm = self.parsed.algorithm()?;
                policy.validate(&algorithm)?;
            }

            // Check if JWKS is configured - if so, must use run_async()
            #[cfg(feature = "remote")]
            if verification.has_jwks() {
                return Err(Error::InvalidConfiguration(
                    "JWKS-based signature verification requires run_async(), not run()".to_string(),
                ));
            }
        }

        // Step 2: Validate issuer
        let trusted = if let Some(ref validator) = self.issuer_validator {
            self.parsed.trust_issuer(|iss| validator(iss))?
        } else {
            // If no issuer validator is provided, require explicit skip
            return Err(Error::MissingField(
                "issuer validator (use ensure_issuer() or skip_issuer_check())".to_string(),
            ));
        };

        // Step 3: Verify signature
        let verified = if let Some(ref verification) = self.signature_verification {
            let key = verification.key()?;
            trusted.verify_signature(key)?
        } else {
            return Err(Error::MissingField(
                "signature verification (use verify_signature())".to_string(),
            ));
        };

        // Step 4: Validate claims
        let validated = if let Some(ref config) = self.claims_validation {
            verified.validate(config)?
        } else {
            // Default: require explicit validation or skip
            verified.validate_default()?
        };

        // Step 5: Convert to public Token type
        Ok(Token::from_validated(validated))
    }

    /// Run the validation pipeline (async version for JWKS)
    ///
    /// This is the async version of `run()` that is used when JWKS-based signature
    /// verification is configured. If no JWKS is configured, it falls back to `run()`.
    /// All validation steps are executed in the correct order.
    ///
    /// # Arguments
    ///
    /// None - all configuration is gathered upfront via the builder pattern.
    ///
    /// # Errors
    ///
    /// Same as `run()`, plus any errors from JWKS fetching and key resolution.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use jwtiny::*;
    /// use jwtiny::remote::HttpClient;
    ///
    /// let client = /* your HTTP client */;
    /// let token = TokenValidator::new(parsed)
    ///     .ensure_issuer(|iss| Ok(iss == "https://auth.example.com"))
    ///     .verify_signature(SignatureVerification::with_jwks(client, true))
    ///     .validate_token(ValidationConfig::default())
    ///     .run_async()
    ///     .await?;
    /// ```
    #[cfg(feature = "remote")]
    pub async fn run_async(self) -> Result<Token> {
        // Check if JWKS is configured
        let has_jwks = self
            .signature_verification
            .as_ref()
            .map(|v| v.has_jwks())
            .unwrap_or(false);

        if !has_jwks {
            // No JWKS configured - fall back to sync path
            return self.run();
        }

        // Step 1: Validate algorithm policy (if configured)
        if let Some(ref verification) = self.signature_verification {
            if let Some(policy) = verification.policy() {
                let algorithm = self.parsed.algorithm()?;
                policy.validate(&algorithm)?;
            }
        }

        // Step 2: Validate issuer
        let trusted = if let Some(ref validator) = self.issuer_validator {
            self.parsed.trust_issuer(|iss| validator(iss))?
        } else {
            return Err(Error::MissingField(
                "issuer validator (use ensure_issuer() or skip_issuer_check())".to_string(),
            ));
        };

        // Step 3: Resolve key from JWKS (async) and verify signature
        let algorithm = trusted.algorithm()?;
        let kid = trusted.header().key_id.as_deref();

        // Get issuer from TrustedToken (already validated and stored)
        let issuer = trusted.issuer();

        // Get HTTP client from SignatureVerification
        let verification = self
            .signature_verification
            .as_ref()
            .ok_or_else(|| Error::MissingField("signature verification".to_string()))?;
        let client = verification.http_client().ok_or_else(|| {
            Error::InvalidConfiguration("HTTP client not configured for JWKS".to_string())
        })?;
        let use_cache = verification.use_cache();

        // Automatically resolve key from JWKS
        use crate::jwks::resolve_key_from_issuer;
        let key = resolve_key_from_issuer(client, issuer, &algorithm, kid, use_cache).await?;

        // Verify signature
        let verified = trusted.verify_signature(&key)?;

        // Step 4: Validate claims
        let validated = if let Some(ref config) = self.claims_validation {
            verified.validate(config)?
        } else {
            // Default: require explicit validation or skip
            verified.validate_default()?
        };

        // Step 5: Convert to public Token type
        Ok(Token::from_validated(validated))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::base64url;

    fn create_test_token() -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(
            r#"{{"iss":"https://example.com","sub":"user123","exp":{}}}"#,
            now + 3600
        );

        let header_b64 = base64url::encode(header);
        let payload_b64 = base64url::encode(&payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let secret = b"test-secret";
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = base64url::encode_bytes(&signature_bytes);

        format!("{}.{}", signing_input, signature_b64)
    }

    #[test]
    fn test_full_validation_flow() {
        let token_str = create_test_token();
        let parsed = ParsedToken::from_string(&token_str).unwrap();

        let result = TokenValidator::new(parsed)
            .ensure_issuer(|iss| {
                if iss == "https://example.com" {
                    Ok(())
                } else {
                    Err(Error::IssuerNotTrusted(iss.to_string()))
                }
            })
            .verify_signature(SignatureVerification::with_secret(b"test-secret"))
            .validate_token(ValidationConfig::default())
            .run();

        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.issuer(), Some("https://example.com"));
        assert_eq!(token.subject(), Some("user123"));
    }

    #[test]
    fn test_issuer_validation_fails() {
        let token_str = create_test_token();
        let parsed = ParsedToken::from_string(&token_str).unwrap();

        let result = TokenValidator::new(parsed)
            .ensure_issuer(|iss| {
                if iss == "https://trusted.com" {
                    Ok(())
                } else {
                    Err(Error::IssuerNotTrusted(iss.to_string()))
                }
            })
            .verify_signature(SignatureVerification::with_secret(b"test-secret"))
            .validate_token(ValidationConfig::default())
            .run();

        assert!(matches!(result, Err(Error::IssuerNotTrusted(_))));
    }

    #[test]
    fn test_signature_verification_fails() {
        let token_str = create_test_token();
        let parsed = ParsedToken::from_string(&token_str).unwrap();

        let result = TokenValidator::new(parsed)
            .ensure_issuer(|_| Ok(()))
            .verify_signature(SignatureVerification::with_secret(b"wrong-secret"))
            .validate_token(ValidationConfig::default())
            .run();

        assert!(matches!(result, Err(Error::SignatureInvalid)));
    }

    #[test]
    fn test_algorithm_policy() {
        use crate::algorithm::AlgorithmId;

        let token_str = create_test_token();
        let parsed = ParsedToken::from_string(&token_str).unwrap();

        // Should succeed with HS256 allowed
        let result = TokenValidator::new(parsed)
            .ensure_issuer(|_| Ok(()))
            .verify_signature(
                SignatureVerification::with_secret(b"test-secret")
                    .allow_algorithms(AlgorithmPolicy::allow_only(vec![AlgorithmId::HS256])),
            )
            .validate_token(ValidationConfig::default())
            .run();

        assert!(result.is_ok());
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn test_algorithm_policy_fails() {
        use crate::algorithm::AlgorithmId;

        let token_str = create_test_token();
        let parsed = ParsedToken::from_string(&token_str).unwrap();

        // Should fail with only RS256 allowed
        let result = TokenValidator::new(parsed)
            .ensure_issuer(|_| Ok(()))
            .verify_signature(
                SignatureVerification::with_secret(b"test-secret")
                    .allow_algorithms(AlgorithmPolicy::allow_only(vec![AlgorithmId::RS256])),
            )
            .validate_token(ValidationConfig::default())
            .run();

        assert!(matches!(result, Err(Error::AlgorithmNotAllowed { .. })));
    }

    #[test]
    fn test_missing_issuer_validator() {
        let token_str = create_test_token();
        let parsed = ParsedToken::from_string(&token_str).unwrap();

        // Should fail without issuer validator
        let result = TokenValidator::new(parsed)
            .verify_signature(SignatureVerification::with_secret(b"test-secret"))
            .validate_token(ValidationConfig::default())
            .run();

        assert!(matches!(result, Err(Error::MissingField(_))));
    }

    #[test]
    fn test_missing_signature_verification() {
        let token_str = create_test_token();
        let parsed = ParsedToken::from_string(&token_str).unwrap();

        // Should fail without signature verification
        let result = TokenValidator::new(parsed)
            .ensure_issuer(|_| Ok(()))
            .validate_token(ValidationConfig::default())
            .run();

        assert!(matches!(result, Err(Error::MissingField(_))));
    }

    #[test]
    fn test_skip_issuer_check() {
        let token_str = create_test_token();
        let parsed = ParsedToken::from_string(&token_str).unwrap();

        let result = TokenValidator::new(parsed)
            .skip_issuer_check()
            .verify_signature(SignatureVerification::with_secret(b"test-secret"))
            .validate_token(ValidationConfig::default())
            .run();

        assert!(result.is_ok());
    }
}
