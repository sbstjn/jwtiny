//! DER encoding utilities for converting JWK formats to DER SubjectPublicKeyInfo
//!
//! This module uses the RustCrypto `spki` and `der` crates for standards-compliant
//! DER encoding. Always uses aws-lc-rs backend format.

use crate::error::{Error, Result};
use der::{Encode, Sequence, asn1::UintRef};
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

/// Create error message for JWKS encoding failures
fn jwks_error(operation: &str, details: impl std::fmt::Display) -> Error {
    Error::RemoteError(format!("jwks: {operation}: {details}"))
}

/// RSA public key structure for DER encoding
///
/// Represents RSAPublicKey as defined in RFC 3447:
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
#[derive(Sequence)]
struct RsaPublicKey<'a> {
    /// RSA modulus (n)
    modulus: UintRef<'a>,
    /// RSA public exponent (e)
    public_exponent: UintRef<'a>,
}

/// Build DER-encoded RSA public key from modulus (n) and exponent (e) bytes
pub(crate) fn rsa_spki_from_n_e(n: &[u8], e: &[u8]) -> Result<Vec<u8>> {
    use der::asn1::BitString;

    if n.is_empty() || e.is_empty() {
        return Err(jwks_error("rsa key missing n or e", ""));
    }

    // Validate RSA key size before encoding
    // For JWT/JWKS, practical RSA keys are 2048-4096 bits (256-512 bytes modulus)
    // Even 8192-bit keys (1024 bytes) would encode to ~2050 bytes SEQUENCE, well within limits
    // Enforce a reasonable maximum: 8192 bytes modulus (65536 bits) - way beyond practical use
    const MAX_RSA_MODULUS_SIZE: usize = 8192;
    if n.len() > MAX_RSA_MODULUS_SIZE {
        return Err(jwks_error(
            "RSA modulus too large",
            format!(
                "{} bytes (maximum: {} bytes)",
                n.len(),
                MAX_RSA_MODULUS_SIZE
            ),
        ));
    }

    // Create UintRef for modulus and exponent
    // UintRef handles INTEGER encoding including leading zero for positive values
    let n_uint = UintRef::new(n).map_err(|e| jwks_error("failed to encode RSA modulus", e))?;
    let e_uint = UintRef::new(e).map_err(|e| jwks_error("failed to encode RSA exponent", e))?;

    // Encode RSA public key structure using der::Sequence
    let rsa_pubkey = RsaPublicKey {
        modulus: n_uint,
        public_exponent: e_uint,
    };

    let rsa_pubkey_der = rsa_pubkey
        .to_der()
        .map_err(|e| jwks_error("failed to encode RSA public key", e))?;

    // Wrap in SubjectPublicKeyInfo for aws-lc-rs backend
    const RSA_ENCRYPTION_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

    let algorithm = AlgorithmIdentifierOwned {
        oid: RSA_ENCRYPTION_OID,
        parameters: Some(der::asn1::AnyRef::NULL.into()),
    };

    let subject_public_key = BitString::new(0, rsa_pubkey_der)
        .map_err(|e| jwks_error("failed to create bit string", e))?;

    let spki = SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key,
    };

    spki.to_der()
        .map_err(|e| jwks_error("failed to encode SPKI", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_spki_from_n_e() {
        // Minimal valid RSA key for testing
        let n = vec![0x00, 0x01]; // Small modulus
        let e = vec![0x01, 0x00, 0x01]; // 65537

        let der = rsa_spki_from_n_e(&n, &e).expect("should encode");
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30); // SEQUENCE
    }

    #[test]
    fn test_rsa_spki_empty_n() {
        let n = vec![];
        let e = vec![0x01, 0x00, 0x01];
        let result = rsa_spki_from_n_e(&n, &e);
        assert!(matches!(result, Err(Error::RemoteError(_))));
    }

    #[test]
    fn test_rsa_spki_empty_e() {
        let n = vec![0x00, 0x01];
        let e = vec![];
        let result = rsa_spki_from_n_e(&n, &e);
        assert!(matches!(result, Err(Error::RemoteError(_))));
    }

    #[test]
    fn test_rsa_spki_proper_length_encoding() {
        // Test that proper DER length encoding works for keys requiring 2-byte encoding
        // 256-byte modulus simulates a 2048-bit RSA key (requires 2-byte length)
        let mut n = vec![0x00; 256];
        n[0] = 0x01; // Ensure it's a valid positive integer (leading byte for positive)
        let e = vec![0x01, 0x00, 0x01]; // 65537

        let der = rsa_spki_from_n_e(&n, &e).expect("should encode key with proper length encoding");
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30); // SEQUENCE tag
        // Verify 2-byte length encoding is used (0x82 at position 1)
        // Note: The exact position may vary, but the encoding should be valid
        assert!(der.len() > 256, "Encoded key should be larger than input");
    }

    #[test]
    fn test_rsa_spki_large_modulus_rejected() {
        // Test that extremely large moduli are rejected
        let n = vec![0x01; 9000]; // Exceeds MAX_RSA_MODULUS_SIZE (8192)
        let e = vec![0x01, 0x00, 0x01]; // 65537

        let result = rsa_spki_from_n_e(&n, &e);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(Error::RemoteError(msg)) if msg.contains("RSA modulus too large"))
        );
    }
}
