use crate::algorithm::AlgorithmId;
use crate::claims::Claims;
use crate::token::TokenHeader;

/// A fully validated JWT token
///
/// This is the final stage in the token validation pipeline.
/// At this stage:
/// - The token has been parsed
/// - The issuer has been validated
/// - The signature has been cryptographically verified
/// - All time-based claims have been validated (exp, nbf, iat)
/// - Audience has been validated (if required)
/// - Custom validation has been performed (if configured)
///
/// The token is now fully trusted and safe to use.
pub struct ValidatedToken {
    header: TokenHeader,
    algorithm: AlgorithmId,
    claims: Claims,
}

impl ValidatedToken {
    pub(crate) fn new(header: TokenHeader, algorithm: AlgorithmId, claims: Claims) -> Self {
        Self {
            header,
            algorithm,
            claims,
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

    /// Get the validated claims
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

    /// Get the expiration time (exp claim)
    pub fn expiration(&self) -> Option<i64> {
        self.claims.expiration
    }

    /// Get the not-before time (nbf claim)
    pub fn not_before(&self) -> Option<i64> {
        self.claims.not_before
    }

    /// Get the issued-at time (iat claim)
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
    fn test_validated_token_getters() {
        let header = crate::token::TokenHeader {
            algorithm: "HS256".to_string(),
            token_type: Some("JWT".to_string()),
            key_id: None,
        };

        let algorithm = crate::algorithm::AlgorithmId::HS256;

        let claims = Claims {
            issuer: Some("https://example.com".to_string()),
            subject: Some("user123".to_string()),
            audience: Some("api.example.com".to_string()),
            expiration: Some(1234567890),
            not_before: Some(1234567800),
            issued_at: Some(1234567800),
            jwt_id: Some("unique-id".to_string()),
        };

        let token = ValidatedToken::new(header, algorithm, claims);

        assert_eq!(token.issuer(), Some("https://example.com"));
        assert_eq!(token.subject(), Some("user123"));
        assert_eq!(token.audience(), Some("api.example.com"));
        assert_eq!(token.expiration(), Some(1234567890));
        assert_eq!(token.not_before(), Some(1234567800));
        assert_eq!(token.issued_at(), Some(1234567800));
        assert_eq!(token.jwt_id(), Some("unique-id"));
    }
}
