//! Size limit constants for input validation

/// Maximum length for a JWT token string (64KB)
pub(crate) const MAX_TOKEN_LENGTH: usize = 64 * 1024;

/// Maximum length for issuer URLs (2048 characters)
pub(crate) const MAX_ISSUER_URL_LENGTH: usize = 2048;

/// Maximum length for JWKS URIs (2048 characters)
pub(crate) const MAX_JWKS_URI_LENGTH: usize = 2048;

/// Maximum size for OIDC discovery response (64KB)
pub(crate) const MAX_DISCOVERY_RESPONSE_SIZE: usize = 64 * 1024;

/// Maximum size for JWKS response (512KB)
pub(crate) const MAX_JWKS_RESPONSE_SIZE: usize = 512 * 1024;

/// Maximum number of keys in a JWK set (100 keys)
pub(crate) const MAX_JWK_SET_SIZE: usize = 100;

// ============================================================================
// Decoded payload size limits (P0 - Critical)
// ============================================================================

/// Maximum size for decoded JWT header JSON (8KB)
/// Headers are typically small (< 1KB), but we allow reasonable margin
pub(crate) const MAX_DECODED_HEADER_SIZE: usize = 8 * 1024;

/// Maximum size for decoded JWT payload JSON (64KB)
/// Payloads can contain custom claims, but must be bounded to prevent DoS
pub(crate) const MAX_DECODED_PAYLOAD_SIZE: usize = 64 * 1024;

/// Maximum size for decoded signature bytes (1KB)
/// RSA signatures are typically 256-512 bytes, but we allow margin for larger keys
pub(crate) const MAX_DECODED_SIGNATURE_SIZE: usize = 1024;

/// Maximum size for Base64URL-encoded signature string (1.5KB)
/// Base64URL encoding adds ~33% overhead, so 1KB decoded ≈ 1.3KB encoded
pub(crate) const MAX_SIGNATURE_B64_SIZE: usize = 1536;

// ============================================================================
// JWK field size limits (P0 - Critical)
// ============================================================================

/// Maximum size for Base64URL-encoded RSA modulus (n) field (12KB)
/// 8192-byte modulus (65536 bits) encodes to ~10.9KB Base64URL
pub(crate) const MAX_JWK_N_SIZE: usize = 12 * 1024;

/// Maximum size for Base64URL-encoded RSA exponent (e) field (64 bytes)
/// Standard exponent 65537 (0x010001) encodes to 4 bytes, but we allow margin
pub(crate) const MAX_JWK_E_SIZE: usize = 64;

/// Maximum size for JWK key ID (kid) field (256 bytes)
/// Key IDs are typically short identifiers, but must be bounded
pub(crate) const MAX_JWK_KID_SIZE: usize = 256;

/// Maximum size for JWK algorithm (alg) field (16 bytes)
/// Algorithm names are short (e.g., "RS256", "RS384", "RS512")
pub(crate) const MAX_JWK_ALG_SIZE: usize = 16;

// ============================================================================
// Claim string length limits (P0 - Critical)
// ============================================================================

/// Maximum length for claim string values (2048 bytes)
/// Applies to iss, sub, aud, jti claims
pub(crate) const MAX_CLAIM_STRING_LENGTH: usize = 2048;

// ============================================================================
// Timestamp bounds (P0 - Critical)
// ============================================================================

/// Minimum valid Unix timestamp (1970-01-01 00:00:00 UTC)
pub(crate) const MIN_TIMESTAMP: i64 = 0;

/// Maximum valid Unix timestamp (2100-01-01 00:00:00 UTC)
/// 4102444800 seconds since Unix epoch
pub(crate) const MAX_TIMESTAMP: i64 = 4_102_444_800;

// ============================================================================
// Header field size limits (P1 - High Priority)
// ============================================================================

/// Maximum length for algorithm (alg) field in JWT header (16 bytes)
/// Algorithm names are short (e.g., "RS256", "RS384", "RS512")
pub(crate) const MAX_ALG_LENGTH: usize = 16;

/// Maximum length for key ID (kid) field in JWT header (256 bytes)
/// Key IDs are typically short identifiers, but must be bounded
pub(crate) const MAX_KID_LENGTH: usize = 256;

// ============================================================================
// Validation bounds (P1 - High Priority)
// ============================================================================

/// Maximum clock skew tolerance (300 seconds = 5 minutes)
/// Prevents clock skew from effectively disabling expiration checks
pub(crate) const MAX_CLOCK_SKEW_SECONDS: u64 = 300;

/// Maximum token age (1 year = 31,536,000 seconds)
/// Prevents max_age from effectively disabling age checks
pub(crate) const MAX_MAX_AGE_SECONDS: u64 = 86400 * 365;

// ============================================================================
// JSON parsing limits (P2 - Medium Priority)
// ============================================================================
