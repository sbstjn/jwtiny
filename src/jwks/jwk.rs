//! JWK (JSON Web Key) struct and conversion

#[cfg(feature = "remote")]
use crate::algorithm::AlgorithmId;
#[cfg(feature = "remote")]
use crate::error::{Error, Result};
#[cfg(feature = "remote")]
use crate::keys::Key;
#[cfg(feature = "remote")]
#[allow(unused_imports)]
use crate::utils::base64url;
#[cfg(feature = "remote")]
use miniserde::Deserialize;

/// JSON Web Key (JWK) structure
///
/// All fields are optional to handle various JWK formats gracefully.
/// Validation happens during conversion to `Key`, not during parsing.
#[derive(Debug, Clone, Deserialize)]
#[cfg(feature = "remote")]
pub struct Jwk {
    /// Key type (e.g., "RSA", "EC")
    pub kty: Option<String>,
    /// Key ID
    pub kid: Option<String>,
    /// Algorithm
    pub alg: Option<String>,
    /// Key use
    #[serde(rename = "use")]
    #[allow(dead_code)]
    pub key_use: Option<String>,
    // RSA fields
    /// RSA modulus (Base64URL-encoded)
    pub n: Option<String>,
    /// RSA exponent (Base64URL-encoded)
    pub e: Option<String>,
    // ECDSA fields
    /// ECDSA curve name
    pub crv: Option<String>,
    /// ECDSA x coordinate (Base64URL-encoded)
    pub x: Option<String>,
    /// ECDSA y coordinate (Base64URL-encoded)
    pub y: Option<String>,
    // X.509 certificate chain (if present)
    #[allow(dead_code)]
    pub x5c: Option<Vec<String>>,
}

#[cfg(feature = "remote")]
impl Jwk {
    /// Convert JWK to Key enum
    ///
    /// Validates that the JWK matches the expected algorithm's key type requirements.
    /// This is where validation happens - parsing accepts all JWK formats.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm from the token header (source of truth)
    ///
    /// # Errors
    ///
    /// Returns `Error::RemoteError` with component-prefixed messages:
    /// - `"jwks: ..."` for JWK-specific errors
    ///
    /// # Warnings
    ///
    /// If the JWK's `alg` field doesn't match the algorithm parameter,
    /// a warning is logged but conversion continues (Q14-B).
    pub fn to_key(&self, algorithm: &AlgorithmId) -> Result<Key> {
        // Validate kty matches algorithm requirements (Q10-A)
        // First, check if algorithm is supported for JWK conversion
        // Note: expected_kty may be unused when no algorithm features are enabled
        #[allow(unreachable_code, unused_variables)]
        let expected_kty: &str = match algorithm {
            #[cfg(feature = "rsa")]
            AlgorithmId::RS256 | AlgorithmId::RS384 | AlgorithmId::RS512 => "RSA",
            #[cfg(feature = "ecdsa")]
            AlgorithmId::ES256 | AlgorithmId::ES384 => "EC",
            #[cfg(not(any(feature = "rsa", feature = "ecdsa")))]
            _ => {
                return Err(Error::RemoteError(format!(
                    "jwks: unsupported algorithm for JWK conversion: {}. Enable at least one of: rsa, ecdsa",
                    algorithm.as_str()
                )));
            }
            #[cfg(any(feature = "rsa", feature = "ecdsa"))]
            _ => {
                return Err(Error::RemoteError(format!(
                    "jwks: unsupported algorithm for JWK conversion: {}",
                    algorithm.as_str()
                )));
            }
        };

        // Check kty matches expected (Q10-A)
        // Note: This code may be unreachable when no algorithm features are enabled,
        // but it's needed when algorithm features are present
        #[allow(unreachable_code)]
        {
            if let Some(kty) = &self.kty {
                if kty != expected_kty {
                    return Err(Error::RemoteError(format!(
                        "jwks: key type mismatch: expected {expected_kty}, found {kty}"
                    )));
                }
            } else {
                return Err(Error::RemoteError(
                    "jwks: missing key type (kty)".to_string(),
                ));
            }
        }

        // Warn if alg doesn't match (but continue) - Q14-B
        if let Some(alg) = &self.alg {
            let alg_str = algorithm.as_str();
            if alg != alg_str {
                // Note: In production, this would use a logging framework
                // For now, we'll continue without logging as Rust doesn't have a standard logger
                // The warning is documented in the API
                eprintln!(
                    "jwks: warning: JWK alg field '{alg}' doesn't match token algorithm '{alg_str}'"
                );
            }
        }

        // Convert based on algorithm
        match algorithm {
            #[cfg(feature = "rsa")]
            AlgorithmId::RS256 | AlgorithmId::RS384 | AlgorithmId::RS512 => self.to_rsa_key(),
            #[cfg(feature = "ecdsa")]
            AlgorithmId::ES256 | AlgorithmId::ES384 => self.to_ecdsa_key(algorithm),
            _ => Err(Error::RemoteError(format!(
                "jwks: unsupported algorithm: {}",
                algorithm.as_str()
            ))),
        }
    }

    /// Convert JWK to RSA Key
    #[cfg(all(feature = "remote", feature = "rsa"))]
    fn to_rsa_key(&self) -> Result<Key> {
        // Extract and decode n and e
        let n = self
            .n
            .as_deref()
            .ok_or_else(|| Error::RemoteError("jwks: rsa key missing n (modulus)".to_string()))?;
        let e = self
            .e
            .as_deref()
            .ok_or_else(|| Error::RemoteError("jwks: rsa key missing e (exponent)".to_string()))?;

        // Decode Base64URL-encoded values
        let n_bytes = base64url::decode_bytes(n)
            .map_err(|e| Error::RemoteError(format!("jwks: failed to decode n: {e}")))?;
        let e_bytes = base64url::decode_bytes(e)
            .map_err(|e| Error::RemoteError(format!("jwks: failed to decode e: {e}")))?;

        // Convert to DER SubjectPublicKeyInfo
        let der = crate::utils::der::rsa_spki_from_n_e(&n_bytes, &e_bytes)?;

        // Create RSA public key
        Ok(Key::rsa_public(der))
    }

    /// Convert JWK to ECDSA Key
    #[cfg(all(feature = "remote", feature = "ecdsa"))]
    fn to_ecdsa_key(&self, algorithm: &AlgorithmId) -> Result<Key> {
        use crate::keys::EcdsaCurve;

        // Determine curve from algorithm
        let curve = match algorithm {
            AlgorithmId::ES256 => EcdsaCurve::P256,
            AlgorithmId::ES384 => EcdsaCurve::P384,
            _ => {
                return Err(Error::RemoteError(format!(
                    "jwks: unsupported ecdsa algorithm: {}",
                    algorithm.as_str()
                )));
            }
        };

        // Normalize curve name from JWK (Q12-A)
        let expected_crv = match curve {
            EcdsaCurve::P256 => ["P-256", "P256", "p-256", "p256"],
            EcdsaCurve::P384 => ["P-384", "P384", "p-384", "p384"],
        };

        if let Some(crv) = &self.crv {
            let normalized = crv.trim();
            if !expected_crv.contains(&normalized) {
                return Err(Error::RemoteError(format!(
                    "jwks: curve mismatch: expected one of {expected_crv:?}, found {crv}"
                )));
            }
        } else {
            return Err(Error::RemoteError(
                "jwks: ecdsa key missing crv".to_string(),
            ));
        }

        // Extract and decode x and y
        let x = self
            .x
            .as_deref()
            .ok_or_else(|| Error::RemoteError("jwks: ecdsa key missing x".to_string()))?;
        let y = self
            .y
            .as_deref()
            .ok_or_else(|| Error::RemoteError("jwks: ecdsa key missing y".to_string()))?;

        // Decode Base64URL-encoded values
        let x_bytes = base64url::decode_bytes(x)
            .map_err(|e| Error::RemoteError(format!("jwks: failed to decode x: {e}")))?;
        let y_bytes = base64url::decode_bytes(y)
            .map_err(|e| Error::RemoteError(format!("jwks: failed to decode y: {e}")))?;

        // Convert to DER SubjectPublicKeyInfo
        let der = crate::utils::der::ecdsa_spki_from_x_y(&x_bytes, &y_bytes, curve)?;

        // Create ECDSA public key
        Ok(Key::ecdsa_public(der, curve))
    }
}

/// Find a key in a JWKS by kid matching
///
/// This function searches for a key in the JWKS that matches the provided kid.
/// If multiple keys match, it uses the first match and logs a warning (Q13-B).
///
/// # Arguments
///
/// * `jwks` - The JWKS to search
/// * `kid` - The key ID to match (if None, returns first key)
///
/// # Returns
///
/// Returns `Some(&Jwk)` if a matching key is found, `None` otherwise.
///
/// # Warnings
///
/// If multiple keys have the same kid, a warning is logged but the first match is returned.
#[cfg(feature = "remote")]
pub fn find_key_by_kid<'a>(jwks: &'a crate::jwks::JwkSet, kid: Option<&str>) -> Option<&'a Jwk> {
    match kid {
        Some(kid) => {
            // Find all keys matching this kid
            let matches: Vec<_> = jwks
                .keys
                .iter()
                .filter(|k| k.kid.as_deref() == Some(kid))
                .collect();

            if matches.is_empty() {
                None
            } else {
                // If multiple matches, warn (Q13-B)
                if matches.len() > 1 {
                    eprintln!(
                        "jwks: warning: multiple keys found with kid '{kid}', using first match"
                    );
                }
                Some(matches[0])
            }
        }
        None => {
            // No kid specified, return first key
            jwks.keys.first()
        }
    }
}

#[cfg(all(test, feature = "remote", feature = "rsa"))]
mod tests {
    use super::*;
    use crate::algorithm::AlgorithmId;

    #[test]
    fn test_jwk_to_rsa_key() {
        // Create a test RSA JWK with minimal valid values
        let jwk = Jwk {
            kty: Some("RSA".to_string()),
            kid: Some("test-key".to_string()),
            alg: Some("RS256".to_string()),
            key_use: None,
            n: Some(base64url::encode_bytes(&[0x00, 0x01, 0x02, 0x03])),
            e: Some(base64url::encode_bytes(&[0x01, 0x00, 0x01])), // 65537
            crv: None,
            x: None,
            y: None,
            x5c: None,
        };

        let key = jwk.to_key(&AlgorithmId::RS256);
        assert!(key.is_ok());
        let key = key.unwrap();
        assert!(matches!(key, Key::Asymmetric(_)));
    }

    #[test]
    fn test_jwk_to_rsa_key_missing_n() {
        let jwk = Jwk {
            kty: Some("RSA".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: None,
            e: Some(base64url::encode_bytes(&[0x01, 0x00, 0x01])),
            crv: None,
            x: None,
            y: None,
            x5c: None,
        };

        let result = jwk.to_key(&AlgorithmId::RS256);
        assert!(matches!(result, Err(Error::RemoteError(msg)) if msg.contains("missing n")));
    }

    #[test]
    fn test_jwk_to_rsa_key_missing_kty() {
        let jwk = Jwk {
            kty: None,
            kid: None,
            alg: None,
            key_use: None,
            n: Some(base64url::encode_bytes(&[0x01])),
            e: Some(base64url::encode_bytes(&[0x01])),
            crv: None,
            x: None,
            y: None,
            x5c: None,
        };

        let result = jwk.to_key(&AlgorithmId::RS256);
        assert!(matches!(result, Err(Error::RemoteError(msg)) if msg.contains("missing key type")));
    }

    #[test]
    fn test_jwk_to_rsa_key_wrong_kty() {
        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: Some(base64url::encode_bytes(&[0x01])),
            e: Some(base64url::encode_bytes(&[0x01])),
            crv: None,
            x: None,
            y: None,
            x5c: None,
        };

        let result = jwk.to_key(&AlgorithmId::RS256);
        assert!(
            matches!(result, Err(Error::RemoteError(msg)) if msg.contains("key type mismatch"))
        );
    }

    #[test]
    fn test_find_key_by_kid() {
        use crate::jwks::JwkSet;

        let jwk1 = Jwk {
            kty: Some("RSA".to_string()),
            kid: Some("key1".to_string()),
            alg: None,
            key_use: None,
            n: Some("n1".to_string()),
            e: Some("e1".to_string()),
            crv: None,
            x: None,
            y: None,
            x5c: None,
        };

        let jwk2 = Jwk {
            kty: Some("RSA".to_string()),
            kid: Some("key2".to_string()),
            alg: None,
            key_use: None,
            n: Some("n2".to_string()),
            e: Some("e2".to_string()),
            crv: None,
            x: None,
            y: None,
            x5c: None,
        };

        let jwks = JwkSet {
            keys: vec![jwk1.clone(), jwk2.clone()],
        };

        // Find by kid
        let found = find_key_by_kid(&jwks, Some("key1"));
        assert!(found.is_some());
        assert_eq!(found.unwrap().kid.as_deref(), Some("key1"));

        // Find by different kid
        let found = find_key_by_kid(&jwks, Some("key2"));
        assert!(found.is_some());
        assert_eq!(found.unwrap().kid.as_deref(), Some("key2"));

        // No match
        let found = find_key_by_kid(&jwks, Some("key3"));
        assert!(found.is_none());

        // No kid specified - should return first
        let found = find_key_by_kid(&jwks, None);
        assert!(found.is_some());
        assert_eq!(found.unwrap().kid.as_deref(), Some("key1"));
    }

    #[test]
    fn test_find_key_by_kid_multiple_matches() {
        use crate::jwks::JwkSet;

        let jwk1 = Jwk {
            kty: Some("RSA".to_string()),
            kid: Some("same".to_string()),
            alg: None,
            key_use: None,
            n: Some("n1".to_string()),
            e: Some("e1".to_string()),
            crv: None,
            x: None,
            y: None,
            x5c: None,
        };

        let jwk2 = Jwk {
            kty: Some("RSA".to_string()),
            kid: Some("same".to_string()),
            alg: None,
            key_use: None,
            n: Some("n2".to_string()),
            e: Some("e2".to_string()),
            crv: None,
            x: None,
            y: None,
            x5c: None,
        };

        let jwks = JwkSet {
            keys: vec![jwk1.clone(), jwk2.clone()],
        };

        // Should find first match and warn
        let found = find_key_by_kid(&jwks, Some("same"));
        assert!(found.is_some());
        assert_eq!(found.unwrap().n.as_deref(), Some("n1")); // First match
    }
}

#[cfg(all(test, feature = "remote", feature = "ecdsa"))]
mod ecdsa_tests {
    use super::*;
    use crate::algorithm::AlgorithmId;

    #[test]
    fn test_jwk_to_ecdsa_key() {
        // Create a test ECDSA JWK (P-256)
        let x_bytes = vec![0x01; 32]; // 32 bytes for P-256
        let y_bytes = vec![0x02; 32];

        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: Some("test-key".to_string()),
            alg: Some("ES256".to_string()),
            key_use: None,
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: Some(base64url::encode_bytes(&x_bytes)),
            y: Some(base64url::encode_bytes(&y_bytes)),
            x5c: None,
        };

        let key = jwk.to_key(&AlgorithmId::ES256);
        assert!(key.is_ok());
        let key = key.unwrap();
        assert!(matches!(key, Key::Asymmetric(_)));
    }

    #[test]
    fn test_jwk_to_ecdsa_key_curve_normalization() {
        // Test curve name normalization (Q12-A)
        let x_bytes = vec![0x01; 32];
        let y_bytes = vec![0x02; 32];

        for crv in ["P-256", "P256", "p-256", "p256"] {
            let jwk = Jwk {
                kty: Some("EC".to_string()),
                kid: None,
                alg: None,
                key_use: None,
                n: None,
                e: None,
                crv: Some(crv.to_string()),
                x: Some(base64url::encode_bytes(&x_bytes)),
                y: Some(base64url::encode_bytes(&y_bytes)),
                x5c: None,
            };

            let result = jwk.to_key(&AlgorithmId::ES256);
            assert!(result.is_ok(), "Failed for curve name: {}", crv);
        }
    }

    #[test]
    fn test_jwk_to_ecdsa_key_missing_x() {
        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: None,
            y: Some(base64url::encode_bytes(&[0x02; 32])),
            x5c: None,
        };

        let result = jwk.to_key(&AlgorithmId::ES256);
        assert!(matches!(result, Err(Error::RemoteError(msg)) if msg.contains("missing x")));
    }

    #[test]
    fn test_jwk_to_ecdsa_key_missing_crv() {
        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: None,
            e: None,
            crv: None,
            x: Some(base64url::encode_bytes(&[0x01; 32])),
            y: Some(base64url::encode_bytes(&[0x02; 32])),
            x5c: None,
        };

        let result = jwk.to_key(&AlgorithmId::ES256);
        assert!(matches!(result, Err(Error::RemoteError(msg)) if msg.contains("missing crv")));
    }

    #[test]
    fn test_jwk_to_ecdsa_key_wrong_curve() {
        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: None,
            e: None,
            crv: Some("P-384".to_string()), // Wrong curve for ES256
            x: Some(base64url::encode_bytes(&[0x01; 32])),
            y: Some(base64url::encode_bytes(&[0x02; 32])),
            x5c: None,
        };

        let result = jwk.to_key(&AlgorithmId::ES256);
        assert!(matches!(result, Err(Error::RemoteError(msg)) if msg.contains("curve mismatch")));
    }

    #[test]
    fn test_jwk_to_ecdsa_key_p384() {
        let x_bytes = vec![0x01; 48]; // 48 bytes for P-384
        let y_bytes = vec![0x02; 48];

        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: None,
            alg: Some("ES384".to_string()),
            key_use: None,
            n: None,
            e: None,
            crv: Some("P-384".to_string()),
            x: Some(base64url::encode_bytes(&x_bytes)),
            y: Some(base64url::encode_bytes(&y_bytes)),
            x5c: None,
        };

        let key = jwk.to_key(&AlgorithmId::ES384);
        assert!(key.is_ok());
    }
}
