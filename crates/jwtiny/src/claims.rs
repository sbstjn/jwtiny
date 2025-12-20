//! Claims validation for JWT tokens
//!
//! This module provides JWT claims parsing and validation functionality,
//! including temporal claim validation (exp, nbf, iat) and audience validation.

use crate::claims;
use crate::error::{Error, Result};
use crate::limits::{MAX_CLAIM_STRING_LENGTH, MAX_CLOCK_SKEW_SECONDS, MAX_MAX_AGE_SECONDS};
use crate::utils::bounds::apply_clock_skew;
use std::time::{SystemTime, UNIX_EPOCH};

// Alias to allow macro-generated code to reference jwtiny::StandardClaims within this crate
use crate as jwtiny;

/// The `StandardClaims` trait defines the standard JWT claims.
pub trait StandardClaims {
    /// Issuer (iss) - identifies the principal that issued the JWT
    fn issuer(&self) -> Option<&str>;
    /// Subject (sub) - identifies the principal that is the subject of the JWT
    fn subject(&self) -> Option<&str>;
    /// Audience (aud) - identifies the recipients that the JWT is intended for
    fn audience(&self) -> Option<&str>;
    /// Expiration Time (exp) - identifies the expiration time (seconds since Unix epoch)
    fn expiration(&self) -> Option<i64>;
    /// Not Before (nbf) - identifies the time before which the JWT MUST NOT be accepted
    fn not_before(&self) -> Option<i64>;
    /// Issued At (iat) - identifies the time at which the JWT was issued
    fn issued_at(&self) -> Option<i64>;
    /// JWT ID (jti) - provides a unique identifier for the JWT
    fn jwt_id(&self) -> Option<&str>;
}

#[claims]
pub struct Claims {}

/// Configuration for claims validation
pub struct ClaimsValidation {
    validate_exp: bool,
    validate_nbf: bool,
    validate_iat: bool,
    clock_skew_seconds: u64,
    max_age_seconds: Option<u64>,
    required_audience: Option<String>,
}

impl Clone for ClaimsValidation {
    fn clone(&self) -> Self {
        Self {
            validate_exp: self.validate_exp,
            validate_nbf: self.validate_nbf,
            validate_iat: self.validate_iat,
            clock_skew_seconds: self.clock_skew_seconds,
            max_age_seconds: self.max_age_seconds,
            required_audience: self.required_audience.clone(),
        }
    }
}

impl Default for ClaimsValidation {
    fn default() -> Self {
        Self {
            validate_exp: true,
            validate_nbf: true,
            validate_iat: true,
            clock_skew_seconds: 0,
            max_age_seconds: Some(1800), // 30 minutes
            required_audience: None,
        }
    }
}

impl ClaimsValidation {
    /// Create a new validation config with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set clock skew tolerance
    ///
    /// # Security
    /// Clock skew is limited to prevent effectively disabling expiration checks.
    /// Maximum allowed value is 300 seconds (5 minutes).
    /// Values exceeding the limit will be rejected during validation.
    pub fn clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew_seconds = seconds;
        self
    }

    /// Set maximum token age
    ///
    /// # Security
    /// Max age is limited to prevent effectively disabling age checks.
    /// Maximum allowed value is 31,536,000 seconds (1 year).
    /// Values exceeding the limit will be rejected during validation.
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

    /// Validate claim string lengths to prevent DoS attacks
    pub(crate) fn validate_string_lengths(claims: &impl StandardClaims) -> Result<()> {
        if let Some(iss) = claims.issuer() {
            Self::validate_claim_string(iss, "iss")?;
        }

        if let Some(sub) = claims.subject() {
            Self::validate_claim_string(sub, "sub")?;
        }

        if let Some(aud) = claims.audience() {
            Self::validate_claim_string(aud, "aud")?;
        }

        if let Some(jti) = claims.jwt_id() {
            Self::validate_claim_string(jti, "jti")?;
        }

        Ok(())
    }

    /// Helper to validate a single claim string length
    fn validate_claim_string(value: &str, claim_name: &str) -> Result<()> {
        if value.len() > MAX_CLAIM_STRING_LENGTH {
            return Err(Error::ClaimStringTooLong {
                claim: claim_name.into(),
                length: value.len(),
                max: MAX_CLAIM_STRING_LENGTH,
            });
        }
        Ok(())
    }
}

/// Validate claims according to configuration
pub(crate) fn validate_claims(
    claims: &impl StandardClaims,
    config: &ClaimsValidation,
) -> Result<()> {
    // Validate configuration bounds to prevent security bypass
    if config.clock_skew_seconds > MAX_CLOCK_SKEW_SECONDS {
        return Err(Error::ClockSkewTooLarge {
            value: config.clock_skew_seconds,
            max: MAX_CLOCK_SKEW_SECONDS,
        });
    }
    if let Some(max_age) = config.max_age_seconds {
        if max_age > MAX_MAX_AGE_SECONDS {
            return Err(Error::MaxAgeTooLarge {
                value: max_age,
                max: MAX_MAX_AGE_SECONDS,
            });
        }
    }

    let now = current_timestamp();

    // Validate timestamp bounds
    if let Some(exp) = claims.expiration() {
        crate::utils::bounds::validate_timestamp_bounds(exp)?;
    }

    if let Some(nbf) = claims.not_before() {
        crate::utils::bounds::validate_timestamp_bounds(nbf)?;
    }

    if let Some(iat) = claims.issued_at() {
        crate::utils::bounds::validate_timestamp_bounds(iat)?;
    }

    // Validate expiration with checked arithmetic
    if config.validate_exp {
        if let Some(exp) = claims.expiration() {
            let exp_with_skew = apply_clock_skew(exp, config.clock_skew_seconds, true)?;
            if now > exp_with_skew {
                return Err(Error::TokenExpired {
                    expired_at: exp,
                    now,
                    skew: config.clock_skew_seconds,
                });
            }
        }
    }

    // Validate not-before with checked arithmetic
    if config.validate_nbf {
        if let Some(nbf) = claims.not_before() {
            let nbf_with_skew = apply_clock_skew(nbf, config.clock_skew_seconds, false)?;
            if now < nbf_with_skew {
                return Err(Error::TokenNotYetValid {
                    not_before: nbf,
                    now,
                    skew: config.clock_skew_seconds,
                });
            }
        }
    }

    // Validate issued-at with checked arithmetic
    if config.validate_iat {
        if let Some(iat) = claims.issued_at() {
            // Check if issued in the future
            let now_with_skew = apply_clock_skew(now, config.clock_skew_seconds, true)?;
            if iat > now_with_skew {
                return Err(Error::TokenIssuedInFuture {
                    issued_at: iat,
                    now,
                    skew: config.clock_skew_seconds,
                });
            }

            // Check max age with checked arithmetic
            if let Some(max_age) = config.max_age_seconds {
                let max_age_i64 = max_age as i64;
                let iat_plus_max_age = iat
                    .checked_add(max_age_i64)
                    .ok_or(Error::TimestampOverflow)?;
                if now > iat_plus_max_age {
                    return Err(Error::TokenTooOld {
                        issued_at: iat,
                        now,
                        max_age,
                    });
                }
            }
        }
    }

    // Validate audience
    if let Some(required_aud) = &config.required_audience {
        match claims.audience() {
            Some(aud) => {
                if aud != required_aud.as_str() {
                    return Err(Error::TokenAudienceMismatch {
                        expected: required_aud.to_string(),
                        found: vec![aud.to_string()],
                    });
                }
            }
            None => {
                return Err(Error::TokenMissingClaim("aud".into()));
            }
        }
    }

    Ok(())
}

/// Get current Unix timestamp
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::Claims;
    use crate::error::Error;

    fn make_claims(exp: Option<i64>, nbf: Option<i64>, iat: Option<i64>) -> Claims {
        Claims {
            issuer: None,
            subject: None,
            audience: None,
            expiration: exp,
            not_before: nbf,
            issued_at: iat,
            jwt_id: None,
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
        let config = ClaimsValidation::default();
        assert!(validate_claims(&claims, &config).is_ok());
    }

    #[test]
    fn test_expired_token() {
        let claims = make_claims(Some(now() - 120), None, None);
        let config = ClaimsValidation::default();
        let result = validate_claims(&claims, &config);
        assert!(matches!(result, Err(Error::TokenExpired { .. })));
    }

    #[test]
    fn test_not_yet_valid() {
        let claims = make_claims(None, Some(now() + 120), None);
        let config = ClaimsValidation::default();
        let result = validate_claims(&claims, &config);
        assert!(matches!(result, Err(Error::TokenNotYetValid { .. })));
    }

    #[test]
    fn test_issued_in_future() {
        let claims = make_claims(None, None, Some(now() + 120));
        let config = ClaimsValidation::default();
        let result = validate_claims(&claims, &config);
        assert!(matches!(result, Err(Error::TokenIssuedInFuture { .. })));
    }

    #[test]
    fn test_too_old() {
        let claims = make_claims(Some(now() + 3600), None, Some(now() - 90000));
        let config = ClaimsValidation::default().max_age(86400);
        let result = validate_claims(&claims, &config);
        assert!(matches!(result, Err(Error::TokenTooOld { .. })));
    }

    #[test]
    fn test_clock_skew() {
        // Token expired 30 seconds ago, but within 60-second skew
        let claims = make_claims(Some(now() - 30), None, None);
        let config = ClaimsValidation::default().clock_skew(60);
        assert!(validate_claims(&claims, &config).is_ok());

        // Token expired 90 seconds ago, outside 60-second skew
        let claims = make_claims(Some(now() - 90), None, None);
        let config = ClaimsValidation::default().clock_skew(60);
        assert!(validate_claims(&claims, &config).is_err());
    }

    #[test]
    fn test_audience_validation() {
        let claims = Claims {
            issuer: None,
            subject: None,
            audience: Some("api.example.com".to_string()),
            expiration: None,
            not_before: None,
            issued_at: None,
            jwt_id: None,
        };

        let config = ClaimsValidation::default().require_audience("api.example.com");
        assert!(validate_claims(&claims, &config).is_ok());

        let config = ClaimsValidation::default().require_audience("other.example.com");
        let result = validate_claims(&claims, &config);
        assert!(matches!(result, Err(Error::TokenAudienceMismatch { .. })));
    }
}
