//! Error types for JWT processing
//!
//! This module defines error types that can occur during JWT parsing, validation,
//! and verification. All errors implement `std::error::Error` and provide
//! descriptive messages for debugging and error handling.

/// Errors that can occur during JWT processing
///
/// This enum covers all error cases in the validation pipeline:
/// - Parsing errors (format, Base64URL, JSON)
/// - Algorithm errors (unsupported, rejected, not allowed)
/// - Security errors (issuer not trusted, signature invalid, key mismatch)
/// - Claims validation errors (expired, not yet valid, audience mismatch, etc.)
/// - Configuration errors (missing fields, invalid settings)
/// - Remote fetching errors (network, parsing failures)
///
/// Each variant includes relevant context for error handling and debugging.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Invalid JWT format (not three Base64URL parts)
    InvalidFormat,

    /// Base64URL decoding failed
    InvalidBase64(String),

    /// JSON parsing failed
    InvalidJson(String),

    /// Missing required field in header or payload
    MissingField(String),

    /// Algorithm not supported or not enabled via feature flag
    UnsupportedAlgorithm(String),

    /// The "none" algorithm is explicitly rejected for security
    ///
    /// The unsigned `"none"` algorithm is always rejected per
    /// [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725).
    NoneAlgorithmRejected,

    /// Algorithm in token doesn't match allowed algorithms
    AlgorithmNotAllowed { found: String, allowed: Vec<String> },

    /// Issuer validation failed
    IssuerNotTrusted(String),

    /// Signature verification failed
    SignatureInvalid,

    /// Key type doesn't match algorithm requirements
    KeyTypeMismatch {
        algorithm: String,
        expected_key_type: String,
        actual_key_type: String,
    },

    /// Claim validation error
    ClaimValidationFailed(ClaimError),

    /// Invalid configuration (e.g., using sync method with async config)
    InvalidConfiguration(String),

    /// Remote fetching error (network, parsing, etc.)
    #[cfg(feature = "remote")]
    RemoteError(String),
}

/// Specific claim validation errors
#[derive(Debug, Clone, PartialEq)]
pub enum ClaimError {
    /// Token has expired (exp claim)
    Expired {
        expired_at: i64,
        now: i64,
        skew: u64,
    },

    /// Token not yet valid (nbf claim)
    NotYetValid {
        not_before: i64,
        now: i64,
        skew: u64,
    },

    /// Token issued in the future (iat claim)
    IssuedInFuture { issued_at: i64, now: i64, skew: u64 },

    /// Token is too old based on max_age setting
    TooOld {
        issued_at: i64,
        now: i64,
        max_age: u64,
    },

    /// Audience doesn't match expected value
    AudienceMismatch {
        expected: String,
        found: Vec<String>,
    },

    /// Required claim is missing
    MissingClaim(String),

    /// Custom validation failed
    Custom(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidFormat => write!(
                f,
                "Invalid JWT format: expected three Base64URL parts separated by '.'"
            ),
            Error::InvalidBase64(msg) => write!(f, "Base64URL decoding failed: {msg}"),
            Error::InvalidJson(msg) => write!(f, "JSON parsing failed: {msg}"),
            Error::MissingField(field) => write!(f, "Missing required field: {field}"),
            Error::UnsupportedAlgorithm(alg) => {
                write!(f, "Algorithm '{alg}' is not supported or not enabled")
            }
            Error::NoneAlgorithmRejected => write!(
                f,
                "The 'none' algorithm is rejected for security reasons (RFC 8725)"
            ),
            Error::AlgorithmNotAllowed { found, allowed } => {
                write!(f, "Algorithm '{found}' not allowed. Allowed: {allowed:?}")
            }
            Error::IssuerNotTrusted(iss) => write!(f, "Issuer '{iss}' is not trusted"),
            Error::SignatureInvalid => write!(f, "Signature verification failed"),
            Error::KeyTypeMismatch {
                algorithm,
                expected_key_type,
                actual_key_type,
            } => {
                write!(
                    f,
                    "Key type mismatch for algorithm '{algorithm}': expected {expected_key_type}, got {actual_key_type}"
                )
            }
            Error::ClaimValidationFailed(claim_err) => {
                write!(f, "Claim validation failed: {claim_err}")
            }
            Error::InvalidConfiguration(msg) => {
                write!(f, "Invalid configuration: {msg}")
            }
            #[cfg(feature = "remote")]
            Error::RemoteError(msg) => write!(f, "Remote error: {msg}"),
        }
    }
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimError::Expired {
                expired_at,
                now,
                skew,
            } => {
                write!(
                    f,
                    "Token expired at {expired_at} (now: {now}, skew: {skew}s)"
                )
            }
            ClaimError::NotYetValid {
                not_before,
                now,
                skew,
            } => {
                write!(
                    f,
                    "Token not valid until {not_before} (now: {now}, skew: {skew}s)"
                )
            }
            ClaimError::IssuedInFuture {
                issued_at,
                now,
                skew,
            } => {
                write!(
                    f,
                    "Token issued in future at {issued_at} (now: {now}, skew: {skew}s)"
                )
            }
            ClaimError::TooOld {
                issued_at,
                now,
                max_age,
            } => {
                write!(
                    f,
                    "Token too old: issued at {issued_at}, max age {max_age}s (now: {now})"
                )
            }
            ClaimError::AudienceMismatch { expected, found } => {
                write!(
                    f,
                    "Audience mismatch: expected '{expected}', found {found:?}"
                )
            }
            ClaimError::MissingClaim(claim) => {
                write!(f, "Required claim '{claim}' is missing")
            }
            ClaimError::Custom(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {}
impl std::error::Error for ClaimError {}

/// Result type alias for jwtiny operations
pub type Result<T> = std::result::Result<T, Error>;
