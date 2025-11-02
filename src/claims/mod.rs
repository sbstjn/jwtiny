mod validator;

pub use validator::{ClaimsValidator, ValidationConfig};

use miniserde::Deserialize;

/// Standard JWT claims as defined in RFC 7519 Section 4.1
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
