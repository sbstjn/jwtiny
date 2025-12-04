//! Errors for jwtiny

use thiserror::Error;

/// JWTiny Errors
#[derive(Error, Debug, Clone, PartialEq)]
pub enum Error {
    #[error("Token too large: {size} bytes (maximum: {max} bytes)")]
    TokenTooLarge { size: usize, max: usize },

    // ============================================================================
    // Format Errors
    // ============================================================================
    #[error("Invalid JWT format: expected three parts separated by '.'")]
    FormatInvalid,

    #[error("Base64URL decoding failed: {0}")]
    FormatInvalidBase64(String),

    #[error("JSON parsing failed: {0}")]
    FormatInvalidJson(String),

    #[error("Signature Base64URL string too large: {size} bytes (maximum: {max} bytes)")]
    SignatureB64TooLarge { size: usize, max: usize },

    // ============================================================================
    // Algorithm Errors
    // ============================================================================
    #[error("Algorithm '{0}' is not supported or not enabled")]
    AlgorithmUnsupported(String),

    #[error("The 'none' algorithm is rejected for security reasons (RFC 8725)")]
    AlgorithmNoneRejected,

    #[error("Algorithm '{found}' not allowed. Allowed: {allowed:?}")]
    AlgorithmNotAllowed { found: String, allowed: Vec<String> },

    // ============================================================================
    // Signature Errors
    // ============================================================================
    #[error("Signature verification failed")]
    SignatureInvalid,

    // ============================================================================
    // Configuration Errors
    // ============================================================================
    #[error("Missing required field: {0}")]
    ClaimMissingField(String),

    #[error("Invalid configuration: {0}")]
    ConfigurationInvalid(String),

    // ============================================================================
    // Token Errors
    // ============================================================================
    #[error("Token expired at {expired_at} (now: {now}, skew: {skew}s)")]
    TokenExpired {
        expired_at: i64,
        now: i64,
        skew: u64,
    },

    #[error("Token not valid until {not_before} (now: {now}, skew: {skew}s)")]
    TokenNotYetValid {
        not_before: i64,
        now: i64,
        skew: u64,
    },

    #[error("Token issued in future at {issued_at} (now: {now}, skew: {skew}s)")]
    TokenIssuedInFuture { issued_at: i64, now: i64, skew: u64 },

    #[error("Token too old: issued at {issued_at}, max age {max_age}s (now: {now})")]
    TokenTooOld {
        issued_at: i64,
        now: i64,
        max_age: u64,
    },

    #[error("Token audience mismatch: expected '{expected}', found {found:?}")]
    TokenAudienceMismatch {
        expected: String,
        found: Vec<String>,
    },

    #[error("Required token claim '{0}' is missing")]
    TokenMissingClaim(String),

    #[error("Token claim validation failed: {0}")]
    TokenInvalidClaim(String),

    // ============================================================================
    // Remote/JWKS Errors
    // ============================================================================
    #[error("Remote error: {0}")]
    RemoteError(String),

    #[error("Remote URL too long: {length} characters (maximum: {max} characters)")]
    RemoteUrlTooLong { length: usize, max: usize },

    #[error("Remote response too large: {size} bytes (maximum: {max} bytes)")]
    RemoteResponseTooLarge { size: usize, max: usize },

    #[error("Remote JWK set too large: {key_count} keys (maximum: {max} keys)")]
    RemoteJwkSetTooLarge { key_count: usize, max: usize },

    #[error("Multiple keys found with kid '{kid}' ({count} matches)")]
    MultipleKeysFound { kid: String, count: usize },

    #[error("Key ID (kid) required: JWKS contains {key_count} keys")]
    KeyIdRequired { key_count: usize },

    #[error(
        "JWK algorithm mismatch: JWK alg '{jwk_alg}' doesn't match token algorithm '{token_alg}'"
    )]
    JwkAlgorithmMismatch { jwk_alg: String, token_alg: String },

    #[error("JWK field '{field}' too large: {size} bytes (maximum: {max} bytes)")]
    JwkFieldTooLarge {
        field: String,
        size: usize,
        max: usize,
    },

    #[error("Claim '{claim}' too long: {length} bytes (maximum: {max} bytes)")]
    ClaimStringTooLong {
        claim: String,
        length: usize,
        max: usize,
    },

    #[error("Timestamp out of bounds: {value} (valid range: {min} to {max})")]
    TimestampOutOfBounds { value: i64, min: i64, max: i64 },

    #[error("Integer overflow in timestamp arithmetic")]
    TimestampOverflow,

    #[error("Header field '{field}' too long: {length} bytes (maximum: {max} bytes)")]
    HeaderFieldTooLong {
        field: String,
        length: usize,
        max: usize,
    },

    #[error("Clock skew too large: {value} seconds (maximum: {max} seconds)")]
    ClockSkewTooLarge { value: u64, max: u64 },

    #[error("Max age too large: {value} seconds (maximum: {max} seconds)")]
    MaxAgeTooLarge { value: u64, max: u64 },
}

/// Result type alias for JWTiny operations
pub type Result<T> = std::result::Result<T, Error>;
