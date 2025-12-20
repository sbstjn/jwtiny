use crate::AlgorithmType;
use crate::algorithm::AlgorithmPolicy;
use crate::claims::StandardClaims;
use crate::claims::{ClaimsValidation, validate_claims};
use crate::error::{Error, Result};
use crate::header::TokenHeader;
use crate::jwks::RemoteCacheKey;
use crate::jwks::caching::resolve_key_from_issuer;
use crate::limits::{
    MAX_ALG_LENGTH, MAX_DECODED_HEADER_SIZE, MAX_DECODED_PAYLOAD_SIZE, MAX_KID_LENGTH,
    MAX_SIGNATURE_B64_SIZE, MAX_TOKEN_LENGTH,
};
use crate::url::validate_issuer_url;
use crate::utils::base64url;
use moka::future::Cache;
use std::sync::Arc;

/// Validator function for issuer validation
///
/// Returns `true` if the issuer is valid, `false` otherwise.
#[allow(clippy::type_complexity)]
pub(crate) type IssuerValidator = Arc<dyn Fn(&str) -> bool + Send + Sync + 'static>;

/// JWT token validator
///
/// The validator is configured once and can be reused for multiple token verifications.
/// The claim type is specified when calling `verify`.
#[derive(Clone)]
pub struct TokenValidator {
    config_issuer: IssuerValidator,
    config_algorithms: AlgorithmPolicy,
    config_claims: ClaimsValidation,
    config_key: Option<Arc<[u8]>>,
    config_cache: Option<Arc<Cache<RemoteCacheKey, Vec<u8>>>>,
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
    pub fn algorithms(&mut self, policy: AlgorithmPolicy) -> &mut Self {
        self.config_algorithms = policy;
        self
    }

    /// Configure issuer validation
    ///
    /// The validator function receives the issuer string and returns `true` if valid,
    /// `false` otherwise. Invalid issuers will result in a `TokenInvalidClaim` error.
    pub fn issuer<F>(&mut self, validator: F) -> &mut Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.config_issuer = Arc::new(validator);
        self
    }

    /// Configure claims validation
    pub fn validate(&mut self, config: ClaimsValidation) -> &mut Self {
        self.config_claims = config;
        self
    }

    /// Configure a static verification key
    pub fn key(&mut self, key_der: &[u8]) -> &mut Self {
        self.config_key = Some(key_der.into());
        self
    }

    /// Configure JWKS cache
    ///
    /// The cache is wrapped internally in `Arc` to allow sharing across validator clones.
    pub fn cache(&mut self, cache: Cache<RemoteCacheKey, Vec<u8>>) -> &mut Self {
        self.config_cache = Some(Arc::new(cache));
        self
    }

    /// Configure JWKS client for remote key fetching
    pub fn jwks(&mut self, client: reqwest::Client) -> &mut Self {
        self.config_jwks = Some(client);
        self
    }

    /// Configure JWKS cache
    pub fn build(&mut self) -> Self {
        self.clone()
    }
}

impl TokenValidator {
    /// Verify a JWT token string
    ///
    /// Returns the parsed and validated claims if verification succeeds.
    /// Uses the default `Claims` type.
    pub async fn verify(&self, token: &str) -> Result<crate::claims::Claims> {
        self.verify_with_custom::<crate::claims::Claims>(token)
            .await
    }

    /// Verify a JWT token string with a custom claim type
    ///
    /// Returns the parsed and validated claims if verification succeeds.
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
        let signing_input = format!("{header_b64}.{payload_b64}");
        algorithm.verify_signature(&signing_input, signature_b64, &key)?;

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

        let header: TokenHeader = miniserde::json::from_str(&header_json)
            .map_err(|e| Error::FormatInvalidJson(format!("Failed to parse header: {e}")))?;

        // Validate header field sizes to prevent DoS
        crate::utils::bounds::validate_field_size("alg", &header.algorithm, MAX_ALG_LENGTH)?;
        if let Some(kid) = &header.key_id {
            crate::utils::bounds::validate_field_size("kid", kid, MAX_KID_LENGTH)?;
        }

        // 3. Check algorithms (always enforced - default is RS256-only)
        let algorithm = AlgorithmType::from_str(&header.algorithm)?;
        algorithm_policy.validate(&algorithm)?;

        // 4. Parse payload with size limit
        let payload_json = base64url::decode_string(payload_b64, MAX_DECODED_PAYLOAD_SIZE)?;

        let payload: C = miniserde::json::from_str(&payload_json)
            .map_err(|e| Error::FormatInvalidJson(format!("Failed to parse payload: {e}")))?;

        // Validate claim string lengths to prevent DoS
        ClaimsValidation::validate_string_lengths(&payload)?;

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
    async fn resolve_verification_key(
        &self,
        header: &TokenHeader,
        algorithm: &AlgorithmType,
        payload: &impl StandardClaims,
    ) -> Result<Vec<u8>> {
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
            resolve_key_from_issuer(
                jwks_client,
                issuer,
                algorithm,
                header.key_id.as_deref(),
                self.config_cache.clone(),
            )
            .await
        } else if let Some(key) = &self.config_key {
            Ok(key.as_ref().to_vec())
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
