//! Base64URL encoding/decoding per RFC 4648
//!
//! This module provides a thin wrapper around the `base64` crate with
//! size limit validation for security.

use crate::error::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Decode Base64URL string to bytes with maximum size limit
pub(crate) fn decode_bytes(input: &str, max_size: usize) -> Result<Vec<u8>> {
    let result = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| Error::FormatInvalidBase64(format!("Base64URL decode failed: {e}")))?;

    // Validate decoded size to prevent DoS attacks
    if result.len() > max_size {
        return Err(Error::FormatInvalidBase64(format!(
            "Decoded size exceeds limit: {} bytes (max: {})",
            result.len(),
            max_size
        )));
    }

    Ok(result)
}

/// Decode Base64URL string to UTF-8 string with size limit
pub(crate) fn decode_string(input: &str, max_size: usize) -> Result<String> {
    decode_bytes(input, max_size).and_then(|bytes| {
        String::from_utf8(bytes)
            .map_err(|e| Error::FormatInvalidBase64(format!("Invalid UTF-8: {e}")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_invalid() {
        assert!(decode_bytes("!!!", 1000).is_err());
        // Base64 crate handles incomplete data differently, so we test valid cases
        assert!(decode_bytes("SGVsbG8=", 1000).is_err()); // Standard base64 with padding (should fail for URL_SAFE_NO_PAD)
    }

    #[test]
    fn test_decode_valid() {
        // Valid Base64URL (no padding)
        let result = decode_bytes("SGVsbG8", 1000).unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_decode_with_limit() {
        // Within limit
        let result = decode_bytes("SGVsbG8", 10).unwrap();
        assert_eq!(result, b"Hello");

        // Exceeds limit
        assert!(decode_bytes("SGVsbG8", 3).is_err());
    }

    #[test]
    fn test_decode_empty() {
        assert_eq!(decode_bytes("", 1000).unwrap(), Vec::<u8>::new());
        assert_eq!(decode_bytes("", 10).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_decode_string() {
        let result = decode_string("SGVsbG8", 10).unwrap();
        assert_eq!(result, "Hello");
        assert!(decode_string("SGVsbG8", 3).is_err());
    }
}
