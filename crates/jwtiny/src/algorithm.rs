//! Algorithm support for JWT validation
use crate::error::{Error, Result};
use crate::limits::{MAX_ALG_LENGTH, MAX_DECODED_SIGNATURE_SIZE};
use crate::utils::base64url;

use aws_lc_rs::signature::{self, UnparsedPublicKey};

/// Algorithm identifier from JWT header
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmType {
    /// RSA with SHA-256
    RS256,
    /// RSA with SHA-384
    RS384,
    /// RSA with SHA-512
    RS512,
    /// ECDSA with P-256 and SHA-256
    ES256,
    /// ECDSA with P-384 and SHA-384
    ES384,
    /// ECDSA with P-521 and SHA-512
    ES512,
}

impl AlgorithmType {
    pub(crate) fn from_str(s: &str) -> Result<Self> {
        // Validate algorithm string length before parsing
        if s.len() > MAX_ALG_LENGTH {
            return Err(Error::AlgorithmUnsupported(format!(
                "Algorithm string too long: {} bytes (maximum: {} bytes)",
                s.len(),
                MAX_ALG_LENGTH
            )));
        }

        // https://datatracker.ietf.org/doc/html/rfc8725#section-3
        match s {
            "none" => Err(Error::AlgorithmNoneRejected),
            "RS256" => Ok(AlgorithmType::RS256),
            "RS384" => Ok(AlgorithmType::RS384),
            "RS512" => Ok(AlgorithmType::RS512),
            "ES256" => Ok(AlgorithmType::ES256),
            "ES384" => Ok(AlgorithmType::ES384),
            "ES512" => Ok(AlgorithmType::ES512),
            _ => Err(Error::AlgorithmUnsupported(s.into())),
        }
    }

    /// Convert AlgorithmType to string representation
    pub const fn as_str(&self) -> &'static str {
        match self {
            AlgorithmType::RS256 => "RS256",
            AlgorithmType::RS384 => "RS384",
            AlgorithmType::RS512 => "RS512",
            AlgorithmType::ES256 => "ES256",
            AlgorithmType::ES384 => "ES384",
            AlgorithmType::ES512 => "ES512",
        }
    }

    /// Get the verification algorithm for signature verification
    ///
    /// JWT ECDSA signatures use IEEE P1363 format (fixed-length R||S)
    /// not ASN.1 DER encoding, as per RFC 7518 Section 3.4.
    fn verification_algorithm(&self) -> &'static dyn signature::VerificationAlgorithm {
        match self {
            AlgorithmType::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            AlgorithmType::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            AlgorithmType::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            AlgorithmType::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
            AlgorithmType::ES384 => &signature::ECDSA_P384_SHA384_FIXED,
            AlgorithmType::ES512 => &signature::ECDSA_P521_SHA512_FIXED,
        }
    }

    /// Verify a signature using the algorithm
    ///
    /// # Arguments
    /// * `signing_input` - The data that was signed (header.payload) as bytes
    /// * `signature` - The Base64URL-encoded signature
    /// * `key_der` - The DER-encoded public key (SubjectPublicKeyInfo)
    pub(crate) fn verify_signature(
        &self,
        signing_input: &[u8],
        signature: &str,
        key_der: &[u8],
    ) -> Result<()> {
        let signature_bytes = base64url::decode_bytes(signature, MAX_DECODED_SIGNATURE_SIZE)?;
        let public_key = UnparsedPublicKey::new(self.verification_algorithm(), key_der);

        public_key
            .verify(signing_input, &signature_bytes)
            .map_err(|_| Error::SignatureInvalid)
    }
}

impl std::fmt::Display for AlgorithmType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for AlgorithmType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Configure accepted JWT signature algorithms
#[derive(Debug, Clone)]
pub struct AlgorithmPolicy {
    allowed: Vec<AlgorithmType>,
}

impl AlgorithmPolicy {
    /// Only accept RS256
    pub fn rs256_only() -> Self {
        Self::allow_only([AlgorithmType::RS256])
    }

    /// Only accept RS384
    pub fn rs384_only() -> Self {
        Self::allow_only([AlgorithmType::RS384])
    }

    /// Only accept RS512
    pub fn rs512_only() -> Self {
        Self::allow_only([AlgorithmType::RS512])
    }

    /// Accept all RSA algorithms (RS256, RS384, RS512)
    pub fn rsa_all() -> Self {
        Self::allow_only([
            AlgorithmType::RS256,
            AlgorithmType::RS384,
            AlgorithmType::RS512,
        ])
    }

    /// Only accept ES256
    pub fn es256_only() -> Self {
        Self::allow_only([AlgorithmType::ES256])
    }

    /// Only accept ES384
    pub fn es384_only() -> Self {
        Self::allow_only([AlgorithmType::ES384])
    }

    /// Only accept ES512
    pub fn es512_only() -> Self {
        Self::allow_only([AlgorithmType::ES512])
    }

    /// Accept all ECDSA algorithms (ES256, ES384, ES512)
    pub fn ecdsa_all() -> Self {
        Self::allow_only([
            AlgorithmType::ES256,
            AlgorithmType::ES384,
            AlgorithmType::ES512,
        ])
    }

    /// Accept only specific algorithms
    ///
    /// Accepts an array of algorithms directly for zero-allocation construction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use jwtiny::{AlgorithmPolicy, AlgorithmType};
    ///
    /// let policy = AlgorithmPolicy::allow_only([AlgorithmType::RS256, AlgorithmType::RS384]);
    /// ```
    pub fn allow_only<const N: usize>(algorithms: [AlgorithmType; N]) -> Self {
        Self {
            allowed: algorithms.into_iter().collect(),
        }
    }

    /// Validate algorithm against policy
    pub(crate) fn validate(&self, algorithm: &AlgorithmType) -> Result<()> {
        if self.is_allowed(algorithm) {
            Ok(())
        } else {
            Err(Error::AlgorithmNotAllowed {
                found: algorithm.to_string(),
                allowed: self.allowed.iter().map(ToString::to_string).collect(),
            })
        }
    }

    /// Check if an algorithm is allowed
    fn is_allowed(&self, algorithm: &AlgorithmType) -> bool {
        self.allowed.contains(algorithm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn test_algorithm_from_str() {
        assert!(matches!(
            AlgorithmType::from_str("none"),
            Err(Error::AlgorithmNoneRejected)
        ));

        assert!(matches!(
            AlgorithmType::from_str("HS256"),
            Err(Error::AlgorithmUnsupported(_))
        ));
        assert!(matches!(
            AlgorithmType::from_str("HS384"),
            Err(Error::AlgorithmUnsupported(_))
        ));
        assert!(matches!(
            AlgorithmType::from_str("HS512"),
            Err(Error::AlgorithmUnsupported(_))
        ));
        assert!(matches!(
            AlgorithmType::from_str("UNKNOWN"),
            Err(Error::AlgorithmUnsupported(_))
        ));

        assert_eq!(
            AlgorithmType::from_str("RS256").unwrap(),
            AlgorithmType::RS256
        );
        assert_eq!(
            AlgorithmType::from_str("RS384").unwrap(),
            AlgorithmType::RS384
        );
        assert_eq!(
            AlgorithmType::from_str("RS512").unwrap(),
            AlgorithmType::RS512
        );
        assert_eq!(
            AlgorithmType::from_str("ES256").unwrap(),
            AlgorithmType::ES256
        );
        assert_eq!(
            AlgorithmType::from_str("ES384").unwrap(),
            AlgorithmType::ES384
        );
        assert_eq!(
            AlgorithmType::from_str("ES512").unwrap(),
            AlgorithmType::ES512
        );
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(format!("{}", AlgorithmType::RS256), "RS256");
        assert_eq!(format!("{}", AlgorithmType::RS384), "RS384");
        assert_eq!(format!("{}", AlgorithmType::RS512), "RS512");
        assert_eq!(format!("{}", AlgorithmType::ES256), "ES256");
        assert_eq!(format!("{}", AlgorithmType::ES384), "ES384");
        assert_eq!(format!("{}", AlgorithmType::ES512), "ES512");
    }

    #[test]
    fn test_algorithm_as_str() {
        assert_eq!(AlgorithmType::RS256.as_str(), "RS256");
        assert_eq!(AlgorithmType::RS384.as_str(), "RS384");
        assert_eq!(AlgorithmType::RS512.as_str(), "RS512");
        assert_eq!(AlgorithmType::ES256.as_str(), "ES256");
        assert_eq!(AlgorithmType::ES384.as_str(), "ES384");
        assert_eq!(AlgorithmType::ES512.as_str(), "ES512");
    }

    #[test]
    fn test_verify_signature_rs256() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
        use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey};

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate key");
        let pkcs8_doc = private_key
            .to_pkcs8_der()
            .expect("Failed to serialize to PKCS#8");
        let keypair = RsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes()).unwrap();
        let public_key_der = keypair.public_key().as_ref().to_vec();

        let signing_input = "test_data";
        let rng = SystemRandom::new();
        let mut signature_bytes = vec![0u8; keypair.public_modulus_len()];
        keypair
            .sign(
                &RSA_PKCS1_SHA256,
                &rng,
                signing_input.as_bytes(),
                &mut signature_bytes,
            )
            .unwrap();

        let signature = URL_SAFE_NO_PAD.encode(&signature_bytes);

        let result = AlgorithmType::RS256.verify_signature(
            signing_input.as_bytes(),
            &signature,
            &public_key_der,
        );
        assert!(result.is_ok(), "Valid RS256 signature should verify");
    }

    #[test]
    fn test_verify_signature_invalid() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
        use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey};

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate key");
        let pkcs8_doc = private_key
            .to_pkcs8_der()
            .expect("Failed to serialize to PKCS#8");
        let keypair = RsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes()).unwrap();
        let public_key_der = keypair.public_key().as_ref().to_vec();

        let signing_input = "test_data";
        let wrong_signing_input = "wrong_data";
        let rng = SystemRandom::new();
        let mut signature_bytes = vec![0u8; keypair.public_modulus_len()];
        keypair
            .sign(
                &RSA_PKCS1_SHA256,
                &rng,
                signing_input.as_bytes(),
                &mut signature_bytes,
            )
            .unwrap();
        let signature = URL_SAFE_NO_PAD.encode(&signature_bytes);

        // Verify with wrong signing input (signature won't match)
        let result = AlgorithmType::RS256.verify_signature(
            wrong_signing_input.as_bytes(),
            &signature,
            &public_key_der,
        );
        assert!(matches!(result, Err(Error::SignatureInvalid)));
    }
}
