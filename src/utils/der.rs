//! SPKI (SubjectPublicKeyInfo) encoding for converting JWK formats to DER
//!
//! This module uses the `spki` crate from RustCrypto for safe, standards-compliant
//! SPKI encoding instead of hand-rolling DER encoding.

#[cfg(any(
    all(feature = "rsa", feature = "remote"),
    all(feature = "ecdsa", feature = "remote")
))]
use crate::error::{Error, Result};

#[cfg(all(feature = "ecdsa", feature = "remote"))]
use crate::keys::EcdsaCurve;

/// Build SubjectPublicKeyInfo DER for RSA from modulus (n) and exponent (e) bytes
///
/// This function constructs a DER-encoded SubjectPublicKeyInfo structure
/// suitable for use with ring's or aws-lc-rs's RSA verification functions.
///
/// Uses the `spki` crate for safe, standards-compliant encoding.
///
/// # Arguments
///
/// * `n` - RSA modulus bytes (big-endian, unsigned integer)
/// * `e` - RSA exponent bytes (big-endian, unsigned integer)
///
/// # Errors
///
/// Returns `Error::RemoteError` if n or e is empty, or if encoding fails.
///
/// # Example
///
/// ```ignore
/// use jwtiny::utils::der::rsa_spki_from_n_e;
///
/// let n = /* modulus bytes */;
/// let e = /* exponent bytes */;
/// let der = rsa_spki_from_n_e(&n, &e)?;
/// ```
#[cfg(all(feature = "rsa", feature = "remote"))]
pub fn rsa_spki_from_n_e(n: &[u8], e: &[u8]) -> Result<Vec<u8>> {
    use spki::der::{Encode, Writer, asn1::UintRef};
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

    if n.is_empty() || e.is_empty() {
        return Err(Error::RemoteError(
            "jwks: rsa key missing n or e".to_string(),
        ));
    }

    // RSA encryption OID: 1.2.840.113549.1.1.1
    const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";

    // Build RSAPublicKey SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    // We need to encode this as a DER sequence manually since spki expects the full key
    let n_uint = UintRef::new(n)
        .map_err(|e| Error::RemoteError(format!("jwks: invalid RSA modulus: {e}")))?;
    let e_uint = UintRef::new(e)
        .map_err(|e| Error::RemoteError(format!("jwks: invalid RSA exponent: {e}")))?;

    // Encode the RSAPublicKey as a SEQUENCE
    let rsa_public_key = {
        use spki::der::SliceWriter;

        // Calculate size needed
        let n_der = n_uint
            .to_der()
            .map_err(|e| Error::RemoteError(format!("jwks: failed to encode modulus: {e}")))?;
        let e_der = e_uint
            .to_der()
            .map_err(|e| Error::RemoteError(format!("jwks: failed to encode exponent: {e}")))?;

        // Build SEQUENCE containing both INTEGERs
        let total_len = n_der.len() + e_der.len() + 10; // +10 for SEQUENCE header overhead
        let mut buf = vec![0u8; total_len];
        let mut writer = SliceWriter::new(&mut buf);

        // SEQUENCE tag
        writer
            .write(&[0x30])
            .map_err(|e| Error::RemoteError(format!("jwks: encoding error: {e}")))?;

        // Length
        let content_len = n_der.len() + e_der.len();
        if content_len < 0x80 {
            writer
                .write(&[content_len as u8])
                .map_err(|e| Error::RemoteError(format!("jwks: encoding error: {e}")))?;
        } else {
            let len_bytes = if content_len <= 0xFF {
                vec![0x81, content_len as u8]
            } else if content_len <= 0xFFFF {
                vec![0x82, (content_len >> 8) as u8, (content_len & 0xFF) as u8]
            } else {
                return Err(Error::RemoteError("jwks: RSA key too large".to_string()));
            };
            writer
                .write(&len_bytes)
                .map_err(|e| Error::RemoteError(format!("jwks: encoding error: {e}")))?;
        }

        // Content
        writer
            .write(&n_der)
            .map_err(|e| Error::RemoteError(format!("jwks: encoding error: {e}")))?;
        writer
            .write(&e_der)
            .map_err(|e| Error::RemoteError(format!("jwks: encoding error: {e}")))?;

        let written = writer
            .finish()
            .map_err(|e| Error::RemoteError(format!("jwks: encoding error: {e}")))?;
        buf.truncate(written.len());
        buf
    };

    // Create AlgorithmIdentifier with RSA OID and NULL parameters
    let algorithm = AlgorithmIdentifierOwned {
        oid: RSA_ENCRYPTION_OID
            .parse()
            .map_err(|e| Error::RemoteError(format!("jwks: invalid OID: {e}")))?,
        parameters: Some(spki::der::asn1::AnyRef::from(spki::der::asn1::Null).into()),
    };

    // Create SubjectPublicKeyInfo with owned BitString
    let subject_public_key = spki::der::asn1::BitString::new(0, rsa_public_key)
        .map_err(|e| Error::RemoteError(format!("jwks: failed to create bit string: {e}")))?;

    let spki = SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key,
    };

    // Encode to DER
    spki.to_der()
        .map_err(|e| Error::RemoteError(format!("jwks: failed to encode SPKI: {e}")))
}

/// Build SubjectPublicKeyInfo DER for ECDSA from x and y coordinates
///
/// This function constructs a DER-encoded SubjectPublicKeyInfo structure
/// suitable for use with ring's or aws-lc-rs's ECDSA verification functions.
///
/// Uses the `spki` crate for safe, standards-compliant encoding.
///
/// # Arguments
///
/// * `x` - ECDSA x coordinate bytes (big-endian)
/// * `y` - ECDSA y coordinate bytes (big-endian)
/// * `curve` - The ECDSA curve (P256 or P384)
///
/// # Errors
///
/// Returns `Error::RemoteError` if x or y is empty, has wrong length, or if encoding fails.
///
/// # Note
///
/// The point is encoded in uncompressed format: 04 || x || y
#[cfg(all(feature = "ecdsa", feature = "remote"))]
pub fn ecdsa_spki_from_x_y(x: &[u8], y: &[u8], curve: EcdsaCurve) -> Result<Vec<u8>> {
    use spki::der::{Decode, Encode};
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

    if x.is_empty() || y.is_empty() {
        return Err(Error::RemoteError(
            "jwks: ecdsa key missing x or y".to_string(),
        ));
    }

    // Expected coordinate lengths for each curve
    let expected_len = match curve {
        EcdsaCurve::P256 => 32,
        EcdsaCurve::P384 => 48,
    };

    // Normalize coordinates (remove leading zeros, pad if needed)
    let normalize = |mut bytes: Vec<u8>| -> Result<Vec<u8>> {
        // Remove leading zeros
        while bytes.len() > expected_len && bytes[0] == 0 {
            bytes.remove(0);
        }
        // Pad with zeros if too short
        while bytes.len() < expected_len {
            bytes.insert(0, 0);
        }
        if bytes.len() != expected_len {
            return Err(Error::RemoteError(format!(
                "jwks: ecdsa coordinates have wrong length for curve {curve:?}"
            )));
        }
        Ok(bytes)
    };

    let x_norm = normalize(x.to_vec())?;
    let y_norm = normalize(y.to_vec())?;

    // Build uncompressed point: 04 || x || y
    let mut point = Vec::with_capacity(1 + x_norm.len() + y_norm.len());
    point.push(0x04); // Uncompressed point marker
    point.extend_from_slice(&x_norm);
    point.extend_from_slice(&y_norm);

    // EC public key OID: 1.2.840.10045.2.1
    const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";

    // Curve OIDs
    let curve_oid = match curve {
        // P-256 (secp256r1): 1.2.840.10045.3.1.7
        EcdsaCurve::P256 => "1.2.840.10045.3.1.7",
        // P-384 (secp384r1): 1.3.132.0.34
        EcdsaCurve::P384 => "1.3.132.0.34",
    };

    // Create AlgorithmIdentifier with EC OID and curve OID as parameter
    let curve_oid_parsed = curve_oid
        .parse()
        .map_err(|e| Error::RemoteError(format!("jwks: invalid curve OID: {e}")))?;
    let curve_oid_der = spki::der::asn1::ObjectIdentifier::to_der(&curve_oid_parsed)
        .map_err(|e| Error::RemoteError(format!("jwks: failed to encode curve OID: {e}")))?;

    let algorithm = AlgorithmIdentifierOwned {
        oid: EC_PUBLIC_KEY_OID
            .parse()
            .map_err(|e| Error::RemoteError(format!("jwks: invalid EC OID: {e}")))?,
        parameters: Some(
            spki::der::Any::from_der(&curve_oid_der)
                .map_err(|e| Error::RemoteError(format!("jwks: failed to parse curve OID: {e}")))?,
        ),
    };

    // Create SubjectPublicKeyInfo with owned BitString
    let subject_public_key = spki::der::asn1::BitString::new(0, point)
        .map_err(|e| Error::RemoteError(format!("jwks: failed to create bit string: {e}")))?;

    let spki = SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key,
    };

    // Encode to DER
    spki.to_der()
        .map_err(|e| Error::RemoteError(format!("jwks: failed to encode SPKI: {e}")))
}

#[cfg(all(test, feature = "rsa", feature = "remote"))]
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
}
