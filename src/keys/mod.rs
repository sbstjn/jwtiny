/// Key types for JWT signature verification
///
/// This module provides a type-safe abstraction over different key types:
/// - Symmetric keys (for HMAC algorithms)
/// - Asymmetric public keys (for RSA/ECDSA algorithms)
use crate::error::{Error, Result};

/// A key that can be used for JWT signature verification
#[derive(Debug, Clone)]
pub enum Key {
    /// Symmetric key for HMAC algorithms
    Symmetric(SymmetricKey),

    /// Asymmetric public key for RSA/ECDSA algorithms
    Asymmetric(AsymmetricKey),
}

impl Key {
    /// Create a symmetric key from bytes
    pub fn symmetric(secret: impl Into<Vec<u8>>) -> Self {
        Key::Symmetric(SymmetricKey::new(secret.into()))
    }

    /// Create an RSA public key from DER-encoded SubjectPublicKeyInfo
    #[cfg(feature = "rsa")]
    pub fn rsa_public(der: impl Into<Vec<u8>>) -> Self {
        Key::Asymmetric(AsymmetricKey::Rsa(RsaPublicKey::new(der.into())))
    }

    /// Create an ECDSA public key from DER-encoded SubjectPublicKeyInfo
    #[cfg(feature = "ecdsa")]
    pub fn ecdsa_public(der: impl Into<Vec<u8>>, curve: EcdsaCurve) -> Self {
        Key::Asymmetric(AsymmetricKey::Ecdsa(EcdsaPublicKey::new(der.into(), curve)))
    }

    /// Get key type name for error messages
    pub fn key_type(&self) -> &'static str {
        match self {
            Key::Symmetric(_) => "Symmetric",
            #[cfg(feature = "rsa")]
            Key::Asymmetric(AsymmetricKey::Rsa(_)) => "RSA",
            #[cfg(feature = "ecdsa")]
            Key::Asymmetric(AsymmetricKey::Ecdsa(_)) => "ECDSA",
            #[cfg(not(any(feature = "rsa", feature = "ecdsa")))]
            Key::Asymmetric(_) => unreachable!("No asymmetric key types enabled"),
        }
    }

    /// Get as symmetric key or return error
    pub fn as_symmetric(&self) -> Result<&SymmetricKey> {
        match self {
            Key::Symmetric(key) => Ok(key),
            _ => Err(Error::KeyTypeMismatch {
                algorithm: "HMAC".to_string(),
                expected_key_type: "Symmetric".to_string(),
                actual_key_type: self.key_type().to_string(),
            }),
        }
    }

    /// Get as RSA public key or return error
    #[cfg(feature = "rsa")]
    pub fn as_rsa_public(&self) -> Result<&RsaPublicKey> {
        match self {
            Key::Asymmetric(AsymmetricKey::Rsa(key)) => Ok(key),
            _ => Err(Error::KeyTypeMismatch {
                algorithm: "RSA".to_string(),
                expected_key_type: "RSA".to_string(),
                actual_key_type: self.key_type().to_string(),
            }),
        }
    }

    /// Get as ECDSA public key or return error
    #[cfg(feature = "ecdsa")]
    pub fn as_ecdsa_public(&self) -> Result<&EcdsaPublicKey> {
        match self {
            Key::Asymmetric(AsymmetricKey::Ecdsa(key)) => Ok(key),
            _ => Err(Error::KeyTypeMismatch {
                algorithm: "ECDSA".to_string(),
                expected_key_type: "ECDSA".to_string(),
                actual_key_type: self.key_type().to_string(),
            }),
        }
    }
}

/// Symmetric key for HMAC algorithms
#[derive(Debug, Clone)]
pub struct SymmetricKey {
    secret: Vec<u8>,
}

impl SymmetricKey {
    /// Create a new symmetric key
    pub fn new(secret: Vec<u8>) -> Self {
        Self { secret }
    }

    /// Get the secret bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }
}

impl From<Vec<u8>> for SymmetricKey {
    fn from(secret: Vec<u8>) -> Self {
        Self::new(secret)
    }
}

impl From<&[u8]> for SymmetricKey {
    fn from(secret: &[u8]) -> Self {
        Self::new(secret.to_vec())
    }
}

impl From<String> for SymmetricKey {
    fn from(secret: String) -> Self {
        Self::new(secret.into_bytes())
    }
}

impl From<&str> for SymmetricKey {
    fn from(secret: &str) -> Self {
        Self::new(secret.as_bytes().to_vec())
    }
}

/// Asymmetric public key for RSA/ECDSA algorithms
#[derive(Debug, Clone)]
pub enum AsymmetricKey {
    /// RSA public key
    #[cfg(feature = "rsa")]
    Rsa(RsaPublicKey),

    /// ECDSA public key
    #[cfg(feature = "ecdsa")]
    Ecdsa(EcdsaPublicKey),
}

/// RSA public key (DER-encoded SubjectPublicKeyInfo)
#[cfg(feature = "rsa")]
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    der: Vec<u8>,
}

#[cfg(feature = "rsa")]
impl RsaPublicKey {
    /// Create a new RSA public key from DER bytes
    pub fn new(der: Vec<u8>) -> Self {
        Self { der }
    }

    /// Get the DER-encoded key bytes
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}

/// ECDSA curve identifier
#[cfg(feature = "ecdsa")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaCurve {
    /// P-256 (secp256r1) curve
    P256,
    /// P-384 (secp384r1) curve
    P384,
}

/// ECDSA public key (DER-encoded SubjectPublicKeyInfo)
#[cfg(feature = "ecdsa")]
#[derive(Debug, Clone)]
pub struct EcdsaPublicKey {
    der: Vec<u8>,
    curve: EcdsaCurve,
}

#[cfg(feature = "ecdsa")]
impl EcdsaPublicKey {
    /// Create a new ECDSA public key from DER bytes
    pub fn new(der: Vec<u8>, curve: EcdsaCurve) -> Self {
        Self { der, curve }
    }

    /// Get the DER-encoded key bytes
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// Get the curve
    pub fn curve(&self) -> EcdsaCurve {
        self.curve
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_key_conversions() {
        let key1 = SymmetricKey::from("secret");
        assert_eq!(key1.as_bytes(), b"secret");

        let key2 = SymmetricKey::from("secret".to_string());
        assert_eq!(key2.as_bytes(), b"secret");

        let key3 = SymmetricKey::from(vec![1, 2, 3]);
        assert_eq!(key3.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_key_type_checking() {
        let sym_key = Key::symmetric(b"secret");
        assert!(sym_key.as_symmetric().is_ok());

        #[cfg(feature = "rsa")]
        assert!(sym_key.as_rsa_public().is_err());

        #[cfg(feature = "ecdsa")]
        assert!(sym_key.as_ecdsa_public().is_err());
    }

    #[test]
    fn test_key_type_names() {
        let sym_key = Key::symmetric(b"secret");
        assert_eq!(sym_key.key_type(), "Symmetric");

        #[cfg(feature = "rsa")]
        {
            let rsa_key = Key::rsa_public(vec![1, 2, 3]);
            assert_eq!(rsa_key.key_type(), "RSA");
        }

        #[cfg(feature = "ecdsa")]
        {
            let ec_key = Key::ecdsa_public(vec![1, 2, 3], EcdsaCurve::P256);
            assert_eq!(ec_key.key_type(), "ECDSA");
        }
    }
}
