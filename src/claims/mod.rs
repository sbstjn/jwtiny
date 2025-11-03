mod validator;

pub use validator::{ClaimsValidator, ValidationConfig};

use miniserde::Deserialize;

/// Standard JWT claims as defined in RFC 7519 Section 4.1
///
/// This struct represents the standard JWT claims from [RFC 7519 Section 4.1](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1).
/// Claims are typically accessed through a validated [`Token`](crate::Token) after successful validation.
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
/// let claims = token.claims();
/// println!("Issuer: {:?}", claims.issuer);
/// println!("Subject: {:?}", claims.subject);
/// println!("Audience: {:?}", claims.audience);
/// ```
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Claims {
    /// Issuer (iss) - identifies the principal that issued the JWT
    #[serde(rename = "iss")]
    pub issuer: Option<String>,

    /// Subject (sub) - identifies the principal that is the subject of the JWT
    #[serde(rename = "sub")]
    pub subject: Option<String>,

    /// Audience (aud) - identifies the recipients that the JWT is intended for
    /// Note: We parse this as a string for simplicity. In a full implementation,
    /// you would handle both string and array formats per RFC 7519.
    #[serde(rename = "aud")]
    pub audience: Option<String>,

    /// Expiration Time (exp) - identifies the expiration time (seconds since Unix epoch)
    #[serde(rename = "exp")]
    pub expiration: Option<i64>,

    /// Not Before (nbf) - identifies the time before which the JWT MUST NOT be accepted
    #[serde(rename = "nbf")]
    pub not_before: Option<i64>,

    /// Issued At (iat) - identifies the time at which the JWT was issued
    #[serde(rename = "iat")]
    pub issued_at: Option<i64>,

    /// JWT ID (jti) - provides a unique identifier for the JWT
    #[serde(rename = "jti")]
    pub jwt_id: Option<String>,
}
