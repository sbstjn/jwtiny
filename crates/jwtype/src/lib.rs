//! JWTiny Types
//!
//! This crate provides the `StandardClaims` trait.

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
