use crate::AlgorithmType;
use crate::algorithm::AlgorithmPolicy;
use crate::claims::StandardClaims;
use crate::claims::{ClaimsValidation, validate_claims};
use crate::error::{Error, Result};
use crate::header::TokenHeader;
use crate::jwks::caching::resolve_key_from_issuer;
use crate::limits::{
    MAX_DECODED_HEADER_SIZE, MAX_DECODED_PAYLOAD_SIZE, MAX_KID_LENGTH, MAX_SIGNATURE_B64_SIZE,
    MAX_TOKEN_LENGTH,
};
use crate::url::validate_issuer_url;
use crate::utils::base64url;
use moka::future::Cache;
use std::borrow::Cow;
use std::sync::Arc;

/// Validator function for issuer validation
///
/// Returns `true` if the issuer is valid, `false` otherwise.
#[allow(clippy::type_complexity)]
pub(crate) type IssuerValidator = Arc<dyn Fn(&str) -> bool + Send + Sync + 'static>;

/// JWT validator
///
/// Configure once at application startup, then reuse for multiple verifications.
/// The claim type is specified when calling `verify`.
#[derive(Clone)]
pub struct TokenValidator {
    config_issuer: IssuerValidator,
    config_algorithms: AlgorithmPolicy,
    config_claims: ClaimsValidation,
    config_key: Option<Arc<Vec<u8>>>,
    config_cache: Option<Arc<Cache<String, Vec<u8>>>>,
    config_jwks: Option<reqwest::Client>,
}

impl TokenValidator {
    /// Create a new validator with secure defaults
    pub fn new() -> Self {
        Self {
            config_issuer: Arc::new(|_: &str| false),
            config_algorithms: AlgorithmPolicy::rs256_only(),
            config_claims: ClaimsValidation::default(),
            config_key: None,
            config_cache: None,
            config_jwks: None,
        }
    }

    /// Configure the algorithm policy
    pub fn algorithms(mut self, policy: AlgorithmPolicy) -> Self {
        self.config_algorithms = policy;
        self
    }

    /// Configure issuer validation
    ///
    /// The validator function receives the issuer string and returns `true` if valid,
    /// `false` otherwise. Invalid issuers result in a `TokenInvalidClaim` error.
    pub fn issuer<F>(mut self, validator: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.config_issuer = Arc::new(validator);
        self
    }

    /// Configure claims validation
    pub fn validate(mut self, config: ClaimsValidation) -> Self {
        self.config_claims = config;
        self
    }

    /// Configure a static verification key
    ///
    /// Accepts `Arc<Vec<u8>>` for efficient sharing. If you have a slice or owned Vec,
    /// wrap it in `Arc::new()` before passing.
    ///
    /// The key must be DER-encoded SubjectPublicKeyInfo format.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::sync::Arc;
    /// use jwtiny::{AlgorithmPolicy, TokenValidator};
    ///
    /// // From owned Vec (moves Vec into Arc)
    /// let validator = TokenValidator::new()
    ///     .key(Arc::new(vec![1u8, 2, 3]))
    ///     .algorithms(AlgorithmPolicy::rs256_only());
    ///
    /// // From existing Arc (most efficient: just reference count increment)
    /// let shared_key = Arc::new(vec![1u8, 2, 3]);
    /// let validator = TokenValidator::new()
    ///     .key(shared_key.clone())  // Clone Arc, not the Vec data
    ///     .algorithms(AlgorithmPolicy::rs256_only());
    /// ```
    pub fn key(mut self, key_der: Arc<Vec<u8>>) -> Self {
        self.config_key = Some(key_der);
        self
    }

    /// Configure JWKS cache
    ///
    /// The cache is wrapped internally in `Arc` to allow sharing across validator clones.
    /// Keys are cached by issuer and key ID (kid) to avoid redundant fetches.
    pub fn cache(mut self, cache: Cache<String, Vec<u8>>) -> Self {
        self.config_cache = Some(Arc::new(cache));
        self
    }

    /// Configure JWKS client for remote key fetching
    ///
    /// The client is used to fetch keys from JWKS endpoints. Issuer validation
    /// must be configured separately using `issuer()`.
    pub fn jwks(mut self, client: reqwest::Client) -> Self {
        self.config_jwks = Some(client);
        self
    }
}

impl TokenValidator {
    /// Verify a JWT
    ///
    /// Returns parsed and validated claims if verification succeeds.
    /// Uses the default `Claims` type.
    pub async fn verify(&self, token: &str) -> Result<crate::claims::Claims> {
        self.verify_with_custom::<crate::claims::Claims>(token)
            .await
    }

    /// Verify a JWT with a custom claim type
    ///
    /// Returns parsed and validated claims if verification succeeds.
    /// The claim type `C` must implement `miniserde::Deserialize` and `StandardClaims`.
    pub async fn verify_with_custom<C>(&self, token: &str) -> Result<C>
    where
        C: miniserde::Deserialize + StandardClaims + Send + Sync + 'static,
    {
        // 1-4. Parse token parts (header, payload, signature)
        let (header_b64, payload_b64, signature_b64, header, algorithm, payload) =
            Self::parse_token_parts::<C>(token, &self.config_algorithms)?;

        // 5. Resolve verification key (from JWKS or static key)
        let key = self
            .resolve_verification_key(&header, &algorithm, &payload)
            .await?;

        // 6. Verify signature
        // Construct signing input as bytes to avoid String allocation
        let signing_input_len = header_b64.len() + 1 + payload_b64.len();
        let mut signing_input_bytes = Vec::with_capacity(signing_input_len);
        signing_input_bytes.extend_from_slice(header_b64.as_bytes());
        signing_input_bytes.push(b'.');
        signing_input_bytes.extend_from_slice(payload_b64.as_bytes());
        algorithm.verify_signature(&signing_input_bytes, signature_b64, key.as_ref())?;

        // 7. Validate claims (using StandardClaims trait, not generic type)
        validate_claims(&payload, &self.config_claims)?;

        Ok(payload)
    }

    /// Parse token into component parts with validation
    ///
    /// Validates token length, splits into parts, decodes and parses header/payload,
    /// and validates algorithm policy.
    fn parse_token_parts<'a, C>(
        token: &'a str,
        algorithm_policy: &AlgorithmPolicy,
    ) -> Result<(&'a str, &'a str, &'a str, TokenHeader, AlgorithmType, C)>
    where
        C: miniserde::Deserialize + StandardClaims + Send + Sync + 'static,
    {
        // 1. Validate token string length
        if token.len() > MAX_TOKEN_LENGTH {
            return Err(Error::TokenTooLarge {
                size: token.len(),
                max: MAX_TOKEN_LENGTH,
            });
        }

        // 2. Check token format (header, payload, signature)
        let mut parts = token.split('.');
        let header_b64 = parts.next().ok_or(Error::FormatInvalid)?;
        let payload_b64 = parts.next().ok_or(Error::FormatInvalid)?;
        let signature_b64 = parts.next().ok_or(Error::FormatInvalid)?;
        if parts.next().is_some() {
            return Err(Error::FormatInvalid);
        }

        // Validate signature Base64URL size before decoding
        if signature_b64.len() > MAX_SIGNATURE_B64_SIZE {
            return Err(Error::SignatureB64TooLarge {
                size: signature_b64.len(),
                max: MAX_SIGNATURE_B64_SIZE,
            });
        }

        // Decode header with size limit
        let header_json = base64url::decode_string(header_b64, MAX_DECODED_HEADER_SIZE)?;

        let header = TokenHeader::from_json_str(&header_json)?;

        // Validate header field sizes to prevent DoS
        if let Some(kid) = &header.key_id {
            crate::utils::bounds::validate_field_size("kid", kid, MAX_KID_LENGTH)?;
        }

        // 3. Check algorithms (always enforced - default is RS256-only)
        algorithm_policy.validate(&header.algorithm)?;

        // 4. Parse payload with size limit
        let payload_json = base64url::decode_string(payload_b64, MAX_DECODED_PAYLOAD_SIZE)?;

        let payload: C = miniserde::json::from_str(&payload_json)
            .map_err(|e| Error::FormatInvalidJson(format!("Failed to parse payload: {e}")))?;

        let algorithm = header.algorithm; // Copy enum (Copy trait)
        Ok((
            header_b64,
            payload_b64,
            signature_b64,
            header,
            algorithm,
            payload,
        ))
    }

    /// Resolve verification key from JWKS or static key configuration
    ///
    /// Returns a `Cow<'static, [u8]>` to avoid copying when possible.
    /// For cached keys from JWKS, the key is owned (Cow::Owned).
    /// For static keys, we clone the Arc (cheap - reference count only) and convert to Vec
    /// only when we have the sole reference (via try_unwrap). Otherwise we copy.
    async fn resolve_verification_key(
        &self,
        header: &TokenHeader,
        algorithm: &AlgorithmType,
        payload: &impl StandardClaims,
    ) -> Result<Cow<'static, [u8]>> {
        // Validate configuration: cannot have both key and jwks
        if self.config_key.is_some() && self.config_jwks.is_some() {
            return Err(Error::ConfigurationInvalid(
                "Cannot configure key AND jwks".into(),
            ));
        }

        if let Some(jwks_client) = &self.config_jwks {
            let issuer = payload
                .issuer()
                .ok_or(Error::ClaimMissingField("iss".into()))?;

            // Validate issuer URL format FIRST (before custom validator) to prevent SSRF
            // This ensures custom validators never see malformed URLs
            validate_issuer_url(issuer)?;

            // Then run custom issuer validator (business logic validation)
            if !(self.config_issuer)(issuer) {
                return Err(Error::TokenInvalidClaim(format!(
                    "Issuer validation failed for: {issuer}"
                )));
            }

            // Fetch key from jwks (using cache if configured)
            // Cached keys are already owned Vec<u8>
            resolve_key_from_issuer(
                jwks_client,
                issuer,
                algorithm,
                header.key_id.as_deref(),
                self.config_cache.clone(),
            )
            .await
            .map(Cow::Owned)
        } else if let Some(key) = &self.config_key {
            // Try to unwrap Arc if we have sole ownership of this clone (no copy needed)
            // This happens when validator hasn't been cloned
            match Arc::try_unwrap(key.clone()) {
                Ok(key_data) => {
                    // Successfully unwrapped - we now own the Vec, no copy needed
                    Ok(Cow::Owned(key_data))
                }
                Err(arc_key) => {
                    // Multiple references exist (validator was cloned) - must copy
                    Ok(Cow::Owned(arc_key.as_ref().clone()))
                }
            }
        } else {
            Err(Error::ConfigurationInvalid(
                "Must configure key OR jwks".into(),
            ))
        }
    }
}

impl Default for TokenValidator {
    fn default() -> Self {
        Self::new()
    }
}
