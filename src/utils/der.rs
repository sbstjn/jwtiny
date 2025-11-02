//! DER encoding utilities for converting JWK formats to DER SubjectPublicKeyInfo

#[cfg(all(any(feature = "rsa", feature = "ecdsa"), feature = "remote"))]
use crate::error::{Error, Result};

#[cfg(all(feature = "ecdsa", feature = "remote"))]
use crate::keys::EcdsaCurve;

#[cfg(all(any(feature = "rsa", feature = "ecdsa"), feature = "remote"))]
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut tmp = Vec::new();
        let mut n = len;
        while n > 0 {
            tmp.push((n & 0xFF) as u8);
            n >>= 8;
        }
        tmp.reverse();
        let mut v = Vec::with_capacity(1 + tmp.len());
        v.push(0x80 | (tmp.len() as u8));
        v.extend_from_slice(&tmp);
        v
    }
}

#[cfg(all(feature = "rsa", feature = "remote"))]
fn der_integer(mut bytes: Vec<u8>) -> Vec<u8> {
    // Ensure positive INTEGER: if MSB set, prepend 0x00
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        let mut prefixed = Vec::with_capacity(bytes.len() + 1);
        prefixed.push(0x00);
        prefixed.extend_from_slice(&bytes);
        bytes = prefixed;
    }
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.push(0x02);
    out.extend_from_slice(&der_len(bytes.len()));
    out.extend_from_slice(&bytes);
    out
}

#[cfg(all(any(feature = "rsa", feature = "ecdsa"), feature = "remote"))]
fn der_sequence(children: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + children.len());
    out.push(0x30);
    out.extend_from_slice(&der_len(children.len()));
    out.extend_from_slice(children);
    out
}

#[cfg(all(any(feature = "rsa", feature = "ecdsa"), feature = "remote"))]
fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + bytes.len());
    out.push(0x03);
    out.extend_from_slice(&der_len(bytes.len() + 1));
    out.push(0x00); // 0 unused bits
    out.extend_from_slice(bytes);
    out
}

/// Build SubjectPublicKeyInfo DER for RSA from modulus (n) and exponent (e) bytes
///
/// This function constructs a DER-encoded SubjectPublicKeyInfo structure
/// suitable for use with ring's RSA verification functions.
///
/// # Arguments
///
/// * `n` - RSA modulus bytes (big-endian)
/// * `e` - RSA exponent bytes (big-endian)
///
/// # Errors
///
/// Returns `Error::RemoteError` if n or e is empty.
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
    if n.is_empty() || e.is_empty() {
        return Err(Error::RemoteError(
            "jwks: rsa key missing n or e".to_string(),
        ));
    }

    // RSAPublicKey = SEQUENCE { n INTEGER, e INTEGER }
    let n_int = der_integer(n.to_vec());
    let e_int = der_integer(e.to_vec());
    let mut rsapk = Vec::with_capacity(n_int.len() + e_int.len() + 10);
    rsapk.extend_from_slice(&n_int);
    rsapk.extend_from_slice(&e_int);
    let rsapk_seq = der_sequence(&rsapk);

    // AlgorithmIdentifier for rsaEncryption OID 1.2.840.113549.1.1.1 with NULL params
    const RSA_ENC_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    const NULL_PARAM: &[u8] = &[0x05, 0x00];
    let mut alg_seq_children = Vec::with_capacity(RSA_ENC_OID.len() + NULL_PARAM.len());
    alg_seq_children.extend_from_slice(RSA_ENC_OID);
    alg_seq_children.extend_from_slice(NULL_PARAM);
    let alg_id = der_sequence(&alg_seq_children);

    // SubjectPublicKey BIT STRING of RSAPublicKey DER
    let spk_bitstr = der_bit_string(&rsapk_seq);

    // SubjectPublicKeyInfo = SEQUENCE { AlgorithmIdentifier, SubjectPublicKey }
    let mut spki_children = Vec::with_capacity(alg_id.len() + spk_bitstr.len());
    spki_children.extend_from_slice(&alg_id);
    spki_children.extend_from_slice(&spk_bitstr);
    Ok(der_sequence(&spki_children))
}

/// Build SubjectPublicKeyInfo DER for ECDSA from x and y coordinates
///
/// This function constructs a DER-encoded SubjectPublicKeyInfo structure
/// suitable for use with ring's ECDSA verification functions.
///
/// # Arguments
///
/// * `x` - ECDSA x coordinate bytes (big-endian)
/// * `y` - ECDSA y coordinate bytes (big-endian)
/// * `curve` - The ECDSA curve (P256 or P384)
///
/// # Errors
///
/// Returns `Error::RemoteError` if x or y is empty or has wrong length.
///
/// # Note
///
/// The point is encoded in uncompressed format: 04 || x || y
#[cfg(all(feature = "ecdsa", feature = "remote"))]
pub fn ecdsa_spki_from_x_y(x: &[u8], y: &[u8], curve: EcdsaCurve) -> Result<Vec<u8>> {
    if x.is_empty() || y.is_empty() {
        return Err(Error::RemoteError(
            "jwks: ecdsa key missing x or y".to_string(),
        ));
    }

    // Normalize coordinate lengths (should be 32 bytes for P-256, 48 for P-384)
    let expected_len = match curve {
        EcdsaCurve::P256 => 32,
        EcdsaCurve::P384 => 48,
    };

    let mut x_norm = x.to_vec();
    let mut y_norm = y.to_vec();

    // Remove leading zeros if present
    while x_norm.len() > expected_len && x_norm[0] == 0 {
        x_norm.remove(0);
    }
    while y_norm.len() > expected_len && y_norm[0] == 0 {
        y_norm.remove(0);
    }

    // Pad with zeros if too short
    while x_norm.len() < expected_len {
        x_norm.insert(0, 0);
    }
    while y_norm.len() < expected_len {
        y_norm.insert(0, 0);
    }

    if x_norm.len() != expected_len || y_norm.len() != expected_len {
        return Err(Error::RemoteError(format!(
            "jwks: ecdsa coordinates have wrong length for curve {curve:?}"
        )));
    }

    // Uncompressed point: 04 || x || y
    let mut point = Vec::with_capacity(1 + x_norm.len() + y_norm.len());
    point.push(0x04); // Uncompressed point marker
    point.extend_from_slice(&x_norm);
    point.extend_from_slice(&y_norm);

    // EC OID and curve OID
    // EC OID: 1.2.840.10045.2.1
    const EC_OID: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

    let curve_oid: &[u8] = match curve {
        // P-256 OID: 1.2.840.10045.3.1.7
        EcdsaCurve::P256 => &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        // P-384 OID: 1.3.132.0.34
        EcdsaCurve::P384 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
    };

    // AlgorithmIdentifier: SEQUENCE { EC OID, curve OID }
    let mut alg_id_children = Vec::with_capacity(EC_OID.len() + curve_oid.len());
    alg_id_children.extend_from_slice(EC_OID);
    alg_id_children.extend_from_slice(curve_oid);
    let alg_id = der_sequence(&alg_id_children);

    // SubjectPublicKey: BIT STRING of point
    let spk_bitstr = der_bit_string(&point);

    // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, SubjectPublicKey }
    let mut spki_children = Vec::with_capacity(alg_id.len() + spk_bitstr.len());
    spki_children.extend_from_slice(&alg_id);
    spki_children.extend_from_slice(&spk_bitstr);
    Ok(der_sequence(&spki_children))
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
