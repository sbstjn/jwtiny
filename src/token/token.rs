//! Public Token type for validated JWT tokens
//!
//! This module provides the `Token` type—the only token type exposed in the public
//! API. It represents a fully validated JWT that has passed all validation steps:
//! parsing, issuer validation, signature verification, and claims validation.

use crate::algorithm::AlgorithmId;
use crate::claims::Claims;
use crate::token::{TokenHeader, ValidatedToken};

/// A fully validated JWT token
///
/// This is the final result of the validation pipeline. By the time you receive
/// a `Token`, all validation steps have completed successfully:
///
/// - **Parsing**: Header and payload have been parsed from Base64URL-encoded
///   segments
/// - **Issuer validation**: The `iss` claim has been validated (or explicitly
///   skipped for same-service tokens)
/// - **Signature verification**: The cryptographic signature has been verified
///   against the provided key
/// - **Claims validation**: Time-based claims (`exp`, `nbf`, `iat`) have been
///   validated, audience (`aud`) has been checked (if required), and any custom
///   validation logic has been executed
///
/// The token is now fully trusted and safe to use. All claims can be accessed
/// without additional validation checks.
///
/// # Examples
///
/// Accessing claims from a validated token:
///
/// ```ignore
/// use jwtiny::*;
///
/// // After validation, access claims through the Token
/// let token = TokenValidator::new(parsed)
///     .ensure_issuer(|iss| Ok(iss == "https://trusted.com"))
///     .verify_signature(SignatureVerification::with_secret_hs256(b"secret"))
///     .validate_token(ValidationConfig::default())
///     .run()?;
///
/// // Access standard claims
/// println!("Subject: {:?}", token.subject());
/// println!("Issuer: {:?}", token.issuer());
/// println!("Expiration: {:?}", token.expiration());
///
/// // Or access the full claims struct
/// let claims = token.claims();
/// println!("All claims: {:?}", claims);
/// ```
pub struct Token {
    header: TokenHeader,
    algorithm: AlgorithmId,
    claims: Claims,
}

impl Token {
    /// Create from a validated token (internal use)
    pub(crate) fn from_validated(validated: ValidatedToken) -> Self {
        Self {
            header: validated.header().clone(),
            algorithm: validated.algorithm().clone(),
            claims: validated.claims().clone(),
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

    /// Get all claims
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// Get the issuer (iss claim)
    pub fn issuer(&self) -> Option<&str> {
        self.claims.issuer.as_deref()
    }

    /// Get the subject (sub claim)
    pub fn subject(&self) -> Option<&str> {
        self.claims.subject.as_deref()
    }

    /// Get the audience (aud claim)
    pub fn audience(&self) -> Option<&str> {
        self.claims.audience.as_deref()
    }

    /// Get the expiration time (exp claim) as Unix timestamp
    pub fn expiration(&self) -> Option<i64> {
        self.claims.expiration
    }

    /// Get the not-before time (nbf claim) as Unix timestamp
    pub fn not_before(&self) -> Option<i64> {
        self.claims.not_before
    }

    /// Get the issued-at time (iat claim) as Unix timestamp
    pub fn issued_at(&self) -> Option<i64> {
        self.claims.issued_at
    }

    /// Get the JWT ID (jti claim)
    pub fn jwt_id(&self) -> Option<&str> {
        self.claims.jwt_id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_getters() {
        let header = TokenHeader {
            algorithm: "HS256".to_string(),
            token_type: Some("JWT".to_string()),
            key_id: None,
        };

        let algorithm = AlgorithmId::HS256;

        let claims = Claims {
            issuer: Some("https://example.com".to_string()),
            subject: Some("user123".to_string()),
            audience: Some("api.example.com".to_string()),
            expiration: Some(1234567890),
            not_before: Some(1234567800),
            issued_at: Some(1234567800),
            jwt_id: Some("unique-id".to_string()),
        };

        let validated = ValidatedToken::new(header, algorithm, claims);
        let token = Token::from_validated(validated);

        assert_eq!(token.issuer(), Some("https://example.com"));
        assert_eq!(token.subject(), Some("user123"));
        assert_eq!(token.audience(), Some("api.example.com"));
        assert_eq!(token.expiration(), Some(1234567890));
        assert_eq!(token.not_before(), Some(1234567800));
        assert_eq!(token.issued_at(), Some(1234567800));
        assert_eq!(token.jwt_id(), Some("unique-id"));
    }
}
