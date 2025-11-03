use crate::algorithm::AlgorithmId;
use crate::claims::{Claims, ClaimsValidator, ValidationConfig};
use crate::error::{Error, Result};
use crate::token::{ParsedToken, TokenHeader, ValidatedToken};

/// A JWT token whose signature has been cryptographically verified
///
/// This is the third stage in the token validation pipeline.
/// At this stage:
/// - The token has been parsed
/// - The issuer has been validated
/// - The signature has been cryptographically verified
/// - The payload can now be safely parsed and accessed
///
/// Next step: ValidatedToken (after claims validation)
pub struct VerifiedToken {
    header: TokenHeader,
    algorithm: AlgorithmId,
    raw_payload: String,
}

impl VerifiedToken {
    pub(crate) fn new(parsed: ParsedToken, algorithm: AlgorithmId) -> Self {
        Self {
            header: parsed.header().clone(),
            algorithm,
            raw_payload: parsed.raw_payload().to_string(),
        }
    }

    /// Get the token header
    pub fn header(&self) -> &TokenHeader {
        &self.header
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> &AlgorithmId {
        &self.algorithm
    }

    /// Get the raw payload JSON
    ///
    /// The payload is now safe to parse since the signature has been verified.
    pub fn raw_payload(&self) -> &str {
        &self.raw_payload
    }

    /// Parse the payload as JSON claims
    ///
    /// This parses the standard JWT claims (iss, sub, aud, exp, etc.)
    /// but does NOT validate them yet.
    pub fn parse_claims(&self) -> Result<Claims> {
        miniserde::json::from_str(&self.raw_payload)
            .map_err(|e| Error::InvalidJson(format!("Failed to parse claims: {e}")))
    }

    /// Parse payload as custom type
    ///
    /// Use this if you have custom claims beyond the standard ones.
    pub fn parse_payload<T>(&self) -> Result<T>
    where
        T: miniserde::Deserialize,
    {
        miniserde::json::from_str(&self.raw_payload)
            .map_err(|e| Error::InvalidJson(format!("Failed to parse payload: {e}")))
    }

    /// Validate claims and move to ValidatedToken state
    ///
    /// This performs time-based validation (exp, nbf, iat) and audience validation.
    ///
    /// # Arguments
    /// * `config` - Validation configuration
    ///
    /// # Example
    /// ```ignore
    /// let config = ValidationConfig::default()
    ///     .require_audience("my-api")
    ///     .max_age(3600);
    ///
    /// let validated = verified.validate(&config)?;
    /// ```
    pub fn validate(self, config: &ValidationConfig) -> Result<ValidatedToken> {
        let claims = self.parse_claims()?;

        // Validate claims
        ClaimsValidator::validate(&claims, config)?;

        // Move to ValidatedToken state
        Ok(ValidatedToken::new(self.header, self.algorithm, claims))
    }

    /// Validate with default configuration
    pub fn validate_default(self) -> Result<ValidatedToken> {
        self.validate(&ValidationConfig::default())
    }

    /// Skip claims validation and access the payload directly
    ///
    /// WARNING: Only use this if you're doing custom validation!
    /// The standard validate() method should be preferred.
    pub fn skip_validation(self) -> Result<ValidatedToken> {
        let claims = self.parse_claims()?;
        Ok(ValidatedToken::new(self.header, self.algorithm, claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::ParsedToken;
    use crate::utils::base64url;

    fn create_verified_token(payload: &str) -> VerifiedToken {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let header = r#"{"alg":"HS256"}"#;
        let secret = b"secret";

        let header_b64 = base64url::encode(header);
        let payload_b64 = base64url::encode(payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = base64url::encode_bytes(&signature_bytes);

        let token_str = format!("{}.{}", signing_input, signature_b64);
        let parsed = ParsedToken::from_string(&token_str).unwrap();
        let trusted = parsed.danger_trust_without_issuer_check();
        let key = crate::keys::Key::symmetric(secret);
        trusted.verify_signature(&key).unwrap()
    }

    #[test]
    fn test_parse_claims() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(r#"{{"iss":"test","sub":"user","exp":{}}}"#, now + 3600);
        let verified = create_verified_token(&payload);

        let claims = verified.parse_claims().unwrap();
        assert_eq!(claims.issuer.as_deref(), Some("test"));
        assert_eq!(claims.subject.as_deref(), Some("user"));
    }

    #[test]
    fn test_validate_success() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(
            r#"{{"iss":"test","sub":"user","exp":{},"iat":{}}}"#,
            now + 3600,
            now
        );
        let verified = create_verified_token(&payload);

        let config = ValidationConfig::default();
        let result = verified.validate(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_expired() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(r#"{{"iss":"test","sub":"user","exp":{}}}"#, now - 3600);
        let verified = create_verified_token(&payload);

        let config = ValidationConfig::default();
        let result = verified.validate(&config);
        assert!(result.is_err());
    }
}
