use crate::claims::Claims;
use crate::error::{ClaimError, Error, Result};
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for claims validation
pub struct ValidationConfig {
    /// Validate expiration time (exp claim)
    pub validate_exp: bool,

    /// Validate not-before time (nbf claim)
    pub validate_nbf: bool,

    /// Validate issued-at time (iat claim)
    pub validate_iat: bool,

    /// Clock skew tolerance in seconds (default: 60)
    pub clock_skew_seconds: u64,

    /// Maximum age of token in seconds (default: 86400 = 24 hours)
    /// Only applies if validate_iat is true
    pub max_age_seconds: Option<u64>,

    /// Required audience value
    pub required_audience: Option<String>,

    /// Custom validation function
    #[allow(clippy::type_complexity)]
    pub custom_validator: Option<Box<dyn Fn(&Claims) -> Result<()> + Send + Sync>>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            validate_exp: true,
            validate_nbf: true,
            validate_iat: true,
            clock_skew_seconds: 60,
            max_age_seconds: Some(86400), // 24 hours
            required_audience: None,
            custom_validator: None,
        }
    }
}

impl ValidationConfig {
    /// Create a new validation config with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set clock skew tolerance
    pub fn clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew_seconds = seconds;
        self
    }

    /// Set maximum token age
    pub fn max_age(mut self, seconds: u64) -> Self {
        self.max_age_seconds = Some(seconds);
        self
    }

    /// Require a specific audience
    pub fn require_audience(mut self, audience: impl Into<String>) -> Self {
        self.required_audience = Some(audience.into());
        self
    }

    /// Disable expiration validation
    pub fn no_exp_validation(mut self) -> Self {
        self.validate_exp = false;
        self
    }

    /// Disable not-before validation
    pub fn no_nbf_validation(mut self) -> Self {
        self.validate_nbf = false;
        self
    }

    /// Disable issued-at validation
    pub fn no_iat_validation(mut self) -> Self {
        self.validate_iat = false;
        self
    }

    /// Skip all validation (use with extreme caution!)
    ///
    /// This disables all built-in validations (exp, nbf, iat, audience).
    /// Only use this if you're performing custom validation yourself.
    pub fn skip_all(mut self) -> Self {
        self.validate_exp = false;
        self.validate_nbf = false;
        self.validate_iat = false;
        self.required_audience = None;
        self
    }

    /// Add custom validation function
    pub fn custom<F>(mut self, validator: F) -> Self
    where
        F: Fn(&Claims) -> Result<()> + Send + Sync + 'static,
    {
        self.custom_validator = Some(Box::new(validator));
        self
    }
}

/// Claims validator
pub struct ClaimsValidator;

impl ClaimsValidator {
    /// Validate claims according to configuration
    pub fn validate(claims: &Claims, config: &ValidationConfig) -> Result<()> {
        let now = Self::current_timestamp();

        // Validate expiration
        if config.validate_exp {
            if let Some(exp) = claims.expiration {
                if now > exp + config.clock_skew_seconds as i64 {
                    return Err(Error::ClaimValidationFailed(ClaimError::Expired {
                        expired_at: exp,
                        now,
                        skew: config.clock_skew_seconds,
                    }));
                }
            }
        }

        // Validate not-before
        if config.validate_nbf {
            if let Some(nbf) = claims.not_before {
                if now < nbf - config.clock_skew_seconds as i64 {
                    return Err(Error::ClaimValidationFailed(ClaimError::NotYetValid {
                        not_before: nbf,
                        now,
                        skew: config.clock_skew_seconds,
                    }));
                }
            }
        }

        // Validate issued-at
        if config.validate_iat {
            if let Some(iat) = claims.issued_at {
                // Check if issued in the future
                if iat > now + config.clock_skew_seconds as i64 {
                    return Err(Error::ClaimValidationFailed(ClaimError::IssuedInFuture {
                        issued_at: iat,
                        now,
                        skew: config.clock_skew_seconds,
                    }));
                }

                // Check max age
                if let Some(max_age) = config.max_age_seconds {
                    if now > iat + max_age as i64 {
                        return Err(Error::ClaimValidationFailed(ClaimError::TooOld {
                            issued_at: iat,
                            now,
                            max_age,
                        }));
                    }
                }
            }
        }

        // Validate audience
        if let Some(required_aud) = &config.required_audience {
            match &claims.audience {
                Some(aud) => {
                    if aud != required_aud {
                        return Err(Error::ClaimValidationFailed(ClaimError::AudienceMismatch {
                            expected: required_aud.clone(),
                            found: vec![aud.clone()],
                        }));
                    }
                }
                None => {
                    return Err(Error::ClaimValidationFailed(ClaimError::MissingClaim(
                        "aud".to_string(),
                    )));
                }
            }
        }

        // Run custom validation
        if let Some(validator) = &config.custom_validator {
            validator(claims)?;
        }

        Ok(())
    }

    /// Get current Unix timestamp
    fn current_timestamp() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time is before Unix epoch")
            .as_secs() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claims(exp: Option<i64>, nbf: Option<i64>, iat: Option<i64>) -> Claims {
        Claims {
            expiration: exp,
            not_before: nbf,
            issued_at: iat,
            ..Default::default()
        }
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn test_valid_token() {
        let claims = make_claims(Some(now() + 3600), Some(now() - 60), Some(now()));
        let config = ValidationConfig::default();
        assert!(ClaimsValidator::validate(&claims, &config).is_ok());
    }

    #[test]
    fn test_expired_token() {
        let claims = make_claims(Some(now() - 120), None, None);
        let config = ValidationConfig::default();
        let result = ClaimsValidator::validate(&claims, &config);
        assert!(matches!(
            result,
            Err(Error::ClaimValidationFailed(ClaimError::Expired { .. }))
        ));
    }

    #[test]
    fn test_not_yet_valid() {
        let claims = make_claims(None, Some(now() + 120), None);
        let config = ValidationConfig::default();
        let result = ClaimsValidator::validate(&claims, &config);
        assert!(matches!(
            result,
            Err(Error::ClaimValidationFailed(ClaimError::NotYetValid { .. }))
        ));
    }

    #[test]
    fn test_issued_in_future() {
        let claims = make_claims(None, None, Some(now() + 120));
        let config = ValidationConfig::default();
        let result = ClaimsValidator::validate(&claims, &config);
        assert!(matches!(
            result,
            Err(Error::ClaimValidationFailed(
                ClaimError::IssuedInFuture { .. }
            ))
        ));
    }

    #[test]
    fn test_too_old() {
        let claims = make_claims(Some(now() + 3600), None, Some(now() - 90000));
        let config = ValidationConfig::default().max_age(86400);
        let result = ClaimsValidator::validate(&claims, &config);
        assert!(matches!(
            result,
            Err(Error::ClaimValidationFailed(ClaimError::TooOld { .. }))
        ));
    }

    #[test]
    fn test_clock_skew() {
        // Token expired 30 seconds ago, but within 60-second skew
        let claims = make_claims(Some(now() - 30), None, None);
        let config = ValidationConfig::default().clock_skew(60);
        assert!(ClaimsValidator::validate(&claims, &config).is_ok());

        // Token expired 90 seconds ago, outside 60-second skew
        let claims = make_claims(Some(now() - 90), None, None);
        let config = ValidationConfig::default().clock_skew(60);
        assert!(ClaimsValidator::validate(&claims, &config).is_err());
    }

    #[test]
    fn test_audience_validation() {
        let mut claims = Claims::default();
        claims.audience = Some("api.example.com".to_string());

        let config = ValidationConfig::default().require_audience("api.example.com");
        assert!(ClaimsValidator::validate(&claims, &config).is_ok());

        let config = ValidationConfig::default().require_audience("other.example.com");
        let result = ClaimsValidator::validate(&claims, &config);
        assert!(matches!(
            result,
            Err(Error::ClaimValidationFailed(
                ClaimError::AudienceMismatch { .. }
            ))
        ));
    }

    #[test]
    fn test_custom_validator() {
        let mut claims = Claims::default();
        claims.subject = Some("user123".to_string());

        let config = ValidationConfig::default().custom(|claims| {
            if claims.subject.as_deref() == Some("user123") {
                Ok(())
            } else {
                Err(Error::ClaimValidationFailed(ClaimError::Custom(
                    "Invalid subject".to_string(),
                )))
            }
        });

        assert!(ClaimsValidator::validate(&claims, &config).is_ok());

        claims.subject = Some("user456".to_string());
        assert!(ClaimsValidator::validate(&claims, &config).is_err());
    }
}
