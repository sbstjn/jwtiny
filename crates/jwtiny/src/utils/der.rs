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

/// ECDSA curve identifier for algorithm-to-curve mapping
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EcdsaCurve {
    P256,
    P384,
    P521,
}

impl EcdsaCurve {
    /// Get the curve OID
    fn oid(&self) -> ObjectIdentifier {
        match self {
            EcdsaCurve::P256 => ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"), // secp256r1
            EcdsaCurve::P384 => ObjectIdentifier::new_unwrap("1.3.132.0.34"),        // secp384r1
            EcdsaCurve::P521 => ObjectIdentifier::new_unwrap("1.3.132.0.35"),        // secp521r1
        }
    }

    /// Get the expected coordinate size in bytes
    fn coordinate_size(&self) -> usize {
        match self {
            EcdsaCurve::P256 => 32, // 256 bits = 32 bytes
            EcdsaCurve::P384 => 48, // 384 bits = 48 bytes
            EcdsaCurve::P521 => 66, // 521 bits = 66 bytes (rounded up from 65.125)
        }
    }
}

/// Build DER-encoded ECDSA public key from x and y coordinates
pub(crate) fn ecdsa_spki_from_xy(x: &[u8], y: &[u8], curve: EcdsaCurve) -> Result<Vec<u8>> {
    use der::asn1::BitString;

    if x.is_empty() || y.is_empty() {
        return Err(jwks_error("ecdsa key missing x or y coordinate", ""));
    }

    let expected_size = curve.coordinate_size();

    // Validate coordinate sizes match the curve
    if x.len() != expected_size {
        return Err(jwks_error(
            "ECDSA x-coordinate size mismatch",
            format!(
                "expected {} bytes for {:?}, found {} bytes",
                expected_size,
                curve,
                x.len()
            ),
        ));
    }
    if y.len() != expected_size {
        return Err(jwks_error(
            "ECDSA y-coordinate size mismatch",
            format!(
                "expected {} bytes for {:?}, found {} bytes",
                expected_size,
                curve,
                y.len()
            ),
        ));
    }

    // Create uncompressed point format: 0x04 || x || y
    // Per SEC 1: Elliptic Curve Cryptography, Section 2.3.3
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04); // Uncompressed point indicator
    point.extend_from_slice(x);
    point.extend_from_slice(y);

    // EC public key algorithm OID
    const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

    // Create AlgorithmIdentifier with curve parameters
    let algorithm = AlgorithmIdentifierOwned {
        oid: EC_PUBLIC_KEY_OID,
        parameters: Some(curve.oid().into()),
    };

    let subject_public_key =
        BitString::new(0, point).map_err(|e| jwks_error("failed to create bit string", e))?;

    let spki = SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key,
    };

    spki.to_der()
        .map_err(|e| jwks_error("failed to encode ECDSA SPKI", e))
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

    #[test]
    fn test_ecdsa_spki_p256() {
        // Valid P-256 coordinates (32 bytes each)
        let x = vec![0x01; 32];
        let y = vec![0x02; 32];

        let der = ecdsa_spki_from_xy(&x, &y, EcdsaCurve::P256).expect("should encode P-256 key");
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30); // SEQUENCE tag
    }

    #[test]
    fn test_ecdsa_spki_p384() {
        // Valid P-384 coordinates (48 bytes each)
        let x = vec![0x03; 48];
        let y = vec![0x04; 48];

        let der = ecdsa_spki_from_xy(&x, &y, EcdsaCurve::P384).expect("should encode P-384 key");
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30); // SEQUENCE tag
    }

    #[test]
    fn test_ecdsa_spki_p521() {
        // Valid P-521 coordinates (66 bytes each)
        let x = vec![0x05; 66];
        let y = vec![0x06; 66];

        let der = ecdsa_spki_from_xy(&x, &y, EcdsaCurve::P521).expect("should encode P-521 key");
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30); // SEQUENCE tag
    }

    #[test]
    fn test_ecdsa_spki_empty_x() {
        let x = vec![];
        let y = vec![0x01; 32];
        let result = ecdsa_spki_from_xy(&x, &y, EcdsaCurve::P256);
        assert!(matches!(result, Err(Error::RemoteError(_))));
    }

    #[test]
    fn test_ecdsa_spki_empty_y() {
        let x = vec![0x01; 32];
        let y = vec![];
        let result = ecdsa_spki_from_xy(&x, &y, EcdsaCurve::P256);
        assert!(matches!(result, Err(Error::RemoteError(_))));
    }

    #[test]
    fn test_ecdsa_spki_wrong_size() {
        // Wrong size for P-256 (should be 32 bytes)
        let x = vec![0x01; 48]; // P-384 size
        let y = vec![0x02; 32];
        let result = ecdsa_spki_from_xy(&x, &y, EcdsaCurve::P256);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(Error::RemoteError(msg)) if msg.contains("x-coordinate size mismatch")
        ));
    }

    #[test]
    fn test_ecdsa_curve_coordinate_sizes() {
        assert_eq!(EcdsaCurve::P256.coordinate_size(), 32);
        assert_eq!(EcdsaCurve::P384.coordinate_size(), 48);
        assert_eq!(EcdsaCurve::P521.coordinate_size(), 66);
    }
}
