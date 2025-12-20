//! JWK (JSON Web Key) struct and conversion

use crate::algorithm::AlgorithmType;
use crate::error::{Error, Result};
use crate::limits::{
    MAX_JWK_ALG_SIZE, MAX_JWK_CRV_SIZE, MAX_JWK_E_SIZE, MAX_JWK_KID_SIZE, MAX_JWK_N_SIZE,
    MAX_JWK_X_SIZE, MAX_JWK_Y_SIZE,
};
use crate::utils::base64url;
use miniserde::Deserialize;

/// JSON Web Key (JWK) structure
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Jwk {
    /// Key type (e.g., "RSA")
    pub kty: Option<String>,
    /// Key ID
    pub kid: Option<String>,
    /// Algorithm (advisory field per RFC 7517)
    /// Used in `validate_jwk_algorithm()` for strict algorithm matching
    pub alg: Option<String>,
    /// Key use (RFC 7517 Section 4.2)
    ///
    /// Indicates the intended use of the key:
    /// - "sig" for signature verification
    /// - "enc" for encryption
    ///
    /// If absent, the key may be used for any purpose.
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    // RSA fields
    /// RSA modulus (Base64URL-encoded)
    pub n: Option<String>,
    /// RSA exponent (Base64URL-encoded)
    pub e: Option<String>,
    // ECDSA fields
    /// Elliptic curve name (e.g., "P-256", "P-384", "P-521")
    pub crv: Option<String>,
    /// ECDSA x-coordinate (Base64URL-encoded)
    pub x: Option<String>,
    /// ECDSA y-coordinate (Base64URL-encoded)
    pub y: Option<String>,
}

impl Jwk {
    /// Convert JWK to DER-encoded public key
    ///
    /// # Arguments
    /// * `algorithm` - The algorithm from the token header
    /// * `strict_algorithm` - If true, require JWK `alg` field to match token algorithm
    ///
    /// # Returns
    /// DER-encoded SubjectPublicKeyInfo bytes
    pub(crate) fn to_key(
        &self,
        algorithm: &AlgorithmType,
        strict_algorithm: bool,
    ) -> Result<Vec<u8>> {
        self.validate_jwk_structure(algorithm)?;
        self.validate_jwk_algorithm(algorithm, strict_algorithm)?;
        // Convert based on algorithm
        match algorithm {
            AlgorithmType::RS256 | AlgorithmType::RS384 | AlgorithmType::RS512 => self.to_rsa_key(),
            AlgorithmType::ES256 | AlgorithmType::ES384 | AlgorithmType::ES512 => {
                self.to_ecdsa_key(algorithm)
            }
        }
    }

    /// Validate JWK structure: key type, key use, and field sizes
    fn validate_jwk_structure(&self, algorithm: &AlgorithmType) -> Result<()> {
        let expected_kty = match algorithm {
            AlgorithmType::RS256 | AlgorithmType::RS384 | AlgorithmType::RS512 => "RSA",
            AlgorithmType::ES256 | AlgorithmType::ES384 | AlgorithmType::ES512 => "EC",
        };

        // Check kty matches expected
        if let Some(kty) = &self.kty {
            if kty != expected_kty {
                return Err(Error::RemoteError(format!(
                    "jwks: key type mismatch: expected {expected_kty}, found {kty}"
                )));
            }
        } else {
            return Err(Error::RemoteError("jwks: missing key type (kty)".into()));
        }

        // Check key use (RFC 7517 Section 4.2)
        // If present, must be "sig" for signature verification
        // "enc" indicates encryption keys, which should not be used for signing
        if let Some(use_val) = &self.key_use {
            if use_val != "sig" {
                return Err(Error::RemoteError(format!(
                    "jwks: key use mismatch: expected 'sig' for signature verification, found '{use_val}'"
                )));
            }
        }

        // Validate algorithm field size
        if let Some(alg) = &self.alg {
            if alg.len() > MAX_JWK_ALG_SIZE {
                return Err(Error::JwkFieldTooLarge {
                    field: "alg".into(),
                    size: alg.len(),
                    max: MAX_JWK_ALG_SIZE,
                });
            }
        }

        // Validate kid field size
        if let Some(kid) = &self.kid {
            if kid.len() > MAX_JWK_KID_SIZE {
                return Err(Error::JwkFieldTooLarge {
                    field: "kid".into(),
                    size: kid.len(),
                    max: MAX_JWK_KID_SIZE,
                });
            }
        }

        // Validate ECDSA-specific fields
        if matches!(
            algorithm,
            AlgorithmType::ES256 | AlgorithmType::ES384 | AlgorithmType::ES512
        ) {
            if let Some(crv) = &self.crv {
                if crv.len() > MAX_JWK_CRV_SIZE {
                    return Err(Error::JwkFieldTooLarge {
                        field: "crv".into(),
                        size: crv.len(),
                        max: MAX_JWK_CRV_SIZE,
                    });
                }
            }
            if let Some(x) = &self.x {
                if x.len() > MAX_JWK_X_SIZE {
                    return Err(Error::JwkFieldTooLarge {
                        field: "x".into(),
                        size: x.len(),
                        max: MAX_JWK_X_SIZE,
                    });
                }
            }
            if let Some(y) = &self.y {
                if y.len() > MAX_JWK_Y_SIZE {
                    return Err(Error::JwkFieldTooLarge {
                        field: "y".into(),
                        size: y.len(),
                        max: MAX_JWK_Y_SIZE,
                    });
                }
            }
        }

        Ok(())
    }

    /// Validate JWK algorithm field against token algorithm
    ///
    /// When strict_algorithm is false, JWK alg field is advisory per RFC 7517.
    /// The token algorithm from the header is authoritative.
    fn validate_jwk_algorithm(
        &self,
        algorithm: &AlgorithmType,
        strict_algorithm: bool,
    ) -> Result<()> {
        if strict_algorithm {
            if let Some(jwk_alg) = &self.alg {
                let token_alg = algorithm.as_str();
                if jwk_alg != token_alg {
                    return Err(Error::JwkAlgorithmMismatch {
                        jwk_alg: jwk_alg.to_string(),
                        token_alg: token_alg.to_string(),
                    });
                }
            }
            // In strict mode, alg field must be present
            if self.alg.is_none() {
                return Err(Error::RemoteError(
                    "jwks: strict algorithm mode requires JWK alg field".into(),
                ));
            }
        }
        Ok(())
    }

    /// Convert JWK to DER-encoded RSA public key
    fn to_rsa_key(&self) -> Result<Vec<u8>> {
        // Base64URL: 4 chars → 3 bytes, so max_decoded = (max_encoded * 3) / 4
        // For n: 12KB encoded → 9KB decoded (conservative: 12KB * 3 / 4 = 9KB)
        // For e: 64 bytes encoded → 48 bytes decoded (64 * 3 / 4 = 48)
        const MAX_DECODED_JWK_N: usize = (MAX_JWK_N_SIZE * 3) / 4;
        const MAX_DECODED_JWK_E: usize = (MAX_JWK_E_SIZE * 3) / 4;

        // Extract and validate field sizes before decoding
        let n = self
            .n
            .as_deref()
            .ok_or_else(|| Error::RemoteError("jwks: rsa key missing n (modulus)".into()))?;
        let e = self
            .e
            .as_deref()
            .ok_or_else(|| Error::RemoteError("jwks: rsa key missing e (exponent)".into()))?;

        // Validate Base64URL-encoded field sizes before decoding
        if n.len() > MAX_JWK_N_SIZE {
            return Err(Error::JwkFieldTooLarge {
                field: "n".into(),
                size: n.len(),
                max: MAX_JWK_N_SIZE,
            });
        }
        if e.len() > MAX_JWK_E_SIZE {
            return Err(Error::JwkFieldTooLarge {
                field: "e".into(),
                size: e.len(),
                max: MAX_JWK_E_SIZE,
            });
        }

        let n_bytes = base64url::decode_bytes(n, MAX_DECODED_JWK_N)
            .map_err(|e| Error::RemoteError(format!("jwks: failed to decode n: {e}")))?;
        let e_bytes = base64url::decode_bytes(e, MAX_DECODED_JWK_E)
            .map_err(|e| Error::RemoteError(format!("jwks: failed to decode e: {e}")))?;

        // Convert to DER SubjectPublicKeyInfo
        crate::utils::der::rsa_spki_from_n_e(&n_bytes, &e_bytes)
    }

    /// Convert JWK to DER-encoded ECDSA public key
    fn to_ecdsa_key(&self, algorithm: &AlgorithmType) -> Result<Vec<u8>> {
        use crate::utils::der::{EcdsaCurve, ecdsa_spki_from_xy};

        // Base64URL: 4 chars → 3 bytes
        // For P-521: 66 bytes raw → ~88 bytes Base64URL
        const MAX_DECODED_JWK_X: usize = (MAX_JWK_X_SIZE * 3) / 4;
        const MAX_DECODED_JWK_Y: usize = (MAX_JWK_Y_SIZE * 3) / 4;

        // Determine curve from algorithm
        let curve = match algorithm {
            AlgorithmType::ES256 => EcdsaCurve::P256,
            AlgorithmType::ES384 => EcdsaCurve::P384,
            AlgorithmType::ES512 => EcdsaCurve::P521,
            _ => {
                return Err(Error::RemoteError(format!(
                    "jwks: algorithm {} is not an ECDSA algorithm",
                    algorithm
                )));
            }
        };

        // Validate curve matches JWK crv field if present
        if let Some(crv) = &self.crv {
            let expected_crv = match curve {
                EcdsaCurve::P256 => "P-256",
                EcdsaCurve::P384 => "P-384",
                EcdsaCurve::P521 => "P-521",
            };
            if crv != expected_crv {
                return Err(Error::RemoteError(format!(
                    "jwks: curve mismatch: {} requires {}, found {}",
                    algorithm, expected_crv, crv
                )));
            }
        } else {
            return Err(Error::RemoteError("jwks: missing curve (crv) field".into()));
        }

        // Extract x and y coordinates
        let x = self
            .x
            .as_deref()
            .ok_or_else(|| Error::RemoteError("jwks: ecdsa key missing x coordinate".into()))?;
        let y = self
            .y
            .as_deref()
            .ok_or_else(|| Error::RemoteError("jwks: ecdsa key missing y coordinate".into()))?;

        let x_bytes = base64url::decode_bytes(x, MAX_DECODED_JWK_X)
            .map_err(|e| Error::RemoteError(format!("jwks: failed to decode x: {e}")))?;
        let y_bytes = base64url::decode_bytes(y, MAX_DECODED_JWK_Y)
            .map_err(|e| Error::RemoteError(format!("jwks: failed to decode y: {e}")))?;

        // Convert to DER SubjectPublicKeyInfo
        ecdsa_spki_from_xy(&x_bytes, &y_bytes, curve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::AlgorithmType;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn test_jwk_to_rsa_key() {
        // Create a test RSA JWK with minimal valid values
        let jwk = Jwk {
            kty: Some("RSA".to_string()),
            kid: Some("test-key".to_string()),
            alg: Some("RS256".to_string()),
            key_use: None,
            n: Some(URL_SAFE_NO_PAD.encode([0x00, 0x01, 0x02, 0x03])),
            e: Some(URL_SAFE_NO_PAD.encode([0x01, 0x00, 0x01])), // 65537
            crv: None,
            x: None,
            y: None,
        };

        let key = jwk.to_key(&AlgorithmType::RS256, false);
        assert!(key.is_ok());
        let key = key.unwrap();
        // Key should be RSA public key
        assert!(!key.is_empty());
    }

    #[test]
    fn test_jwk_to_rsa_key_missing_n() {
        let jwk = Jwk {
            kty: Some("RSA".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: None,
            e: Some(URL_SAFE_NO_PAD.encode([0x01, 0x00, 0x01])),
            crv: None,
            x: None,
            y: None,
        };

        let result = jwk.to_key(&AlgorithmType::RS256, false);
        assert!(matches!(result, Err(Error::RemoteError(msg)) if msg.contains("missing n")));
    }

    #[test]
    fn test_jwk_to_rsa_key_missing_kty() {
        let jwk = Jwk {
            kty: None,
            kid: None,
            alg: None,
            key_use: None,
            n: Some(URL_SAFE_NO_PAD.encode([0x01])),
            e: Some(URL_SAFE_NO_PAD.encode([0x01])),
            crv: None,
            x: None,
            y: None,
        };

        let result = jwk.to_key(&AlgorithmType::RS256, false);
        assert!(matches!(result, Err(Error::RemoteError(msg)) if msg.contains("missing key type")));
    }

    #[test]
    fn test_jwk_to_rsa_key_wrong_kty() {
        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: Some(URL_SAFE_NO_PAD.encode([0x01])),
            e: Some(URL_SAFE_NO_PAD.encode([0x01])),
            crv: None,
            x: None,
            y: None,
        };

        let result = jwk.to_key(&AlgorithmType::RS256, false);
        assert!(
            matches!(result, Err(Error::RemoteError(msg)) if msg.contains("key type mismatch"))
        );
    }

    #[test]
    fn test_jwk_key_use_sig() {
        // Key with use="sig" should be accepted
        let jwk = Jwk {
            kty: Some("RSA".to_string()),
            kid: None,
            alg: None,
            key_use: Some("sig".to_string()),
            n: Some(URL_SAFE_NO_PAD.encode([0x00, 0x01, 0x02, 0x03])),
            e: Some(URL_SAFE_NO_PAD.encode([0x01, 0x00, 0x01])),
            crv: None,
            x: None,
            y: None,
        };

        let result = jwk.to_key(&AlgorithmType::RS256, false);
        assert!(result.is_ok(), "Key with use='sig' should be accepted");
    }

    #[test]
    fn test_jwk_key_use_enc() {
        // Key with use="enc" should be rejected (wrong purpose)
        let jwk = Jwk {
            kty: Some("RSA".to_string()),
            kid: None,
            alg: None,
            key_use: Some("enc".to_string()),
            n: Some(URL_SAFE_NO_PAD.encode([0x00, 0x01, 0x02, 0x03])),
            e: Some(URL_SAFE_NO_PAD.encode([0x01, 0x00, 0x01])),
            crv: None,
            x: None,
            y: None,
        };

        let result = jwk.to_key(&AlgorithmType::RS256, false);
        assert!(
            matches!(result, Err(Error::RemoteError(msg)) if msg.contains("key use mismatch")),
            "Key with use='enc' should be rejected"
        );
    }

    #[test]
    fn test_jwk_key_use_missing() {
        // Key with use missing should be accepted (optional field)
        let jwk = Jwk {
            kty: Some("RSA".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: Some(URL_SAFE_NO_PAD.encode([0x00, 0x01, 0x02, 0x03])),
            e: Some(URL_SAFE_NO_PAD.encode([0x01, 0x00, 0x01])),
            crv: None,
            x: None,
            y: None,
        };

        let result = jwk.to_key(&AlgorithmType::RS256, false);
        assert!(result.is_ok(), "Key with use missing should be accepted");
    }

    #[test]
    fn test_jwk_strict_algorithm_match() {
        // Key with matching alg should succeed in strict mode
        let jwk = Jwk {
            kty: Some("RSA".to_string()),
            kid: None,
            alg: Some("RS256".to_string()),
            key_use: None,
            n: Some(URL_SAFE_NO_PAD.encode([0x00, 0x01, 0x02, 0x03])),
            e: Some(URL_SAFE_NO_PAD.encode([0x01, 0x00, 0x01])),
            crv: None,
            x: None,
            y: None,
        };

        let result = jwk.to_key(&AlgorithmType::RS256, true);
        assert!(
            result.is_ok(),
            "Key with matching alg should succeed in strict mode"
        );
    }

    #[test]
    fn test_jwk_strict_algorithm_mismatch() {
        // Key with mismatched alg should fail in strict mode
        let jwk = Jwk {
            kty: Some("RSA".to_string()),
            kid: None,
            alg: Some("RS384".to_string()),
            key_use: None,
            n: Some(URL_SAFE_NO_PAD.encode([0x00, 0x01, 0x02, 0x03])),
            e: Some(URL_SAFE_NO_PAD.encode([0x01, 0x00, 0x01])),
            crv: None,
            x: None,
            y: None,
        };

        let result = jwk.to_key(&AlgorithmType::RS256, true);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(Error::JwkAlgorithmMismatch {
                jwk_alg,
                token_alg
            }) if jwk_alg == "RS384" && token_alg == "RS256"
        ));
    }

    #[test]
    fn test_jwk_strict_algorithm_missing() {
        // Key without alg should fail in strict mode
        let jwk = Jwk {
            kty: Some("RSA".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: Some(URL_SAFE_NO_PAD.encode([0x00, 0x01, 0x02, 0x03])),
            e: Some(URL_SAFE_NO_PAD.encode([0x01, 0x00, 0x01])),
            crv: None,
            x: None,
            y: None,
        };

        let result = jwk.to_key(&AlgorithmType::RS256, true);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(Error::RemoteError(msg)) if msg.contains("strict algorithm mode requires JWK alg field")
        ));
    }

    #[test]
    fn test_jwk_non_strict_algorithm_mismatch_allowed() {
        // Key with mismatched alg should succeed in non-strict mode (advisory field)
        let jwk = Jwk {
            kty: Some("RSA".to_string()),
            kid: None,
            alg: Some("RS384".to_string()),
            key_use: None,
            n: Some(URL_SAFE_NO_PAD.encode([0x00, 0x01, 0x02, 0x03])),
            e: Some(URL_SAFE_NO_PAD.encode([0x01, 0x00, 0x01])),
            crv: None,
            x: None,
            y: None,
        };

        let result = jwk.to_key(&AlgorithmType::RS256, false);
        assert!(
            result.is_ok(),
            "Key with mismatched alg should succeed in non-strict mode"
        );
    }

    #[test]
    fn test_jwk_to_ecdsa_key_p256() {
        // Create a test ECDSA JWK for P-256
        let x = vec![0x01; 32];
        let y = vec![0x02; 32];
        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: Some("test-ec-key".to_string()),
            alg: Some("ES256".to_string()),
            key_use: None,
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(&x)),
            y: Some(URL_SAFE_NO_PAD.encode(&y)),
        };

        let key = jwk.to_key(&AlgorithmType::ES256, false);
        assert!(key.is_ok(), "Valid P-256 key should encode successfully");
        assert!(!key.unwrap().is_empty());
    }

    #[test]
    fn test_jwk_to_ecdsa_key_p384() {
        // Create a test ECDSA JWK for P-384
        let x = vec![0x03; 48];
        let y = vec![0x04; 48];
        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: None,
            alg: Some("ES384".to_string()),
            key_use: None,
            n: None,
            e: None,
            crv: Some("P-384".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(&x)),
            y: Some(URL_SAFE_NO_PAD.encode(&y)),
        };

        let key = jwk.to_key(&AlgorithmType::ES384, false);
        assert!(key.is_ok(), "Valid P-384 key should encode successfully");
        assert!(!key.unwrap().is_empty());
    }

    #[test]
    fn test_jwk_to_ecdsa_key_p521() {
        // Create a test ECDSA JWK for P-521
        let x = vec![0x05; 66];
        let y = vec![0x06; 66];
        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: None,
            alg: Some("ES512".to_string()),
            key_use: None,
            n: None,
            e: None,
            crv: Some("P-521".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(&x)),
            y: Some(URL_SAFE_NO_PAD.encode(&y)),
        };

        let key = jwk.to_key(&AlgorithmType::ES512, false);
        assert!(key.is_ok(), "Valid P-521 key should encode successfully");
        assert!(!key.unwrap().is_empty());
    }

    #[test]
    fn test_jwk_to_ecdsa_key_missing_crv() {
        let x = vec![0x01; 32];
        let y = vec![0x02; 32];
        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: None,
            e: None,
            crv: None,
            x: Some(URL_SAFE_NO_PAD.encode(&x)),
            y: Some(URL_SAFE_NO_PAD.encode(&y)),
        };

        let result = jwk.to_key(&AlgorithmType::ES256, false);
        assert!(matches!(
            result,
            Err(Error::RemoteError(msg)) if msg.contains("missing curve")
        ));
    }

    #[test]
    fn test_jwk_to_ecdsa_key_wrong_crv() {
        let x = vec![0x01; 32];
        let y = vec![0x02; 32];
        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: None,
            e: None,
            crv: Some("P-384".to_string()), // Wrong curve for ES256
            x: Some(URL_SAFE_NO_PAD.encode(&x)),
            y: Some(URL_SAFE_NO_PAD.encode(&y)),
        };

        let result = jwk.to_key(&AlgorithmType::ES256, false);
        assert!(matches!(
            result,
            Err(Error::RemoteError(msg)) if msg.contains("curve mismatch")
        ));
    }

    #[test]
    fn test_jwk_to_ecdsa_key_missing_x() {
        let y = vec![0x02; 32];
        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: None,
            y: Some(URL_SAFE_NO_PAD.encode(&y)),
        };

        let result = jwk.to_key(&AlgorithmType::ES256, false);
        assert!(matches!(
            result,
            Err(Error::RemoteError(msg)) if msg.contains("missing x")
        ));
    }

    #[test]
    fn test_jwk_to_ecdsa_key_missing_y() {
        let x = vec![0x01; 32];
        let jwk = Jwk {
            kty: Some("EC".to_string()),
            kid: None,
            alg: None,
            key_use: None,
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(&x)),
            y: None,
        };

        let result = jwk.to_key(&AlgorithmType::ES256, false);
        assert!(matches!(
            result,
            Err(Error::RemoteError(msg)) if msg.contains("missing y")
        ));
    }
}
