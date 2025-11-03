mod traits;

pub mod hmac;

#[cfg(feature = "rsa")]
pub mod rsa;

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

pub use traits::{get_verifier, Algorithm, SignatureVerifier};

use crate::error::{Error, Result};

/// Algorithm identifier from JWT header
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmId {
    /// HMAC with SHA-256
    HS256,

    /// HMAC with SHA-384
    HS384,

    /// HMAC with SHA-512
    HS512,

    /// RSA with SHA-256
    #[cfg(feature = "rsa")]
    RS256,

    /// RSA with SHA-384
    #[cfg(feature = "rsa")]
    RS384,

    /// RSA with SHA-512
    #[cfg(feature = "rsa")]
    RS512,

    /// ECDSA with P-256 and SHA-256
    #[cfg(feature = "ecdsa")]
    ES256,

    /// ECDSA with P-384 and SHA-384
    #[cfg(feature = "ecdsa")]
    ES384,
}

impl AlgorithmId {
    /// Parse algorithm string from JWT header
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "none" => Err(Error::NoneAlgorithmRejected),

            "HS256" => Ok(AlgorithmId::HS256),
            "HS384" => Ok(AlgorithmId::HS384),
            "HS512" => Ok(AlgorithmId::HS512),

            #[cfg(feature = "rsa")]
            "RS256" => Ok(AlgorithmId::RS256),
            #[cfg(feature = "rsa")]
            "RS384" => Ok(AlgorithmId::RS384),
            #[cfg(feature = "rsa")]
            "RS512" => Ok(AlgorithmId::RS512),

            #[cfg(feature = "ecdsa")]
            "ES256" => Ok(AlgorithmId::ES256),
            #[cfg(feature = "ecdsa")]
            "ES384" => Ok(AlgorithmId::ES384),

            "ES512" => Err(Error::UnsupportedAlgorithm(
                "ES512 (P-521) is not supported due to library limitations".to_string(),
            )),

            _ => Err(Error::UnsupportedAlgorithm(s.to_string())),
        }
    }

    /// Convert to string representation
    #[allow(unreachable_patterns)]
    pub fn as_str(&self) -> &'static str {
        match self {
            AlgorithmId::HS256 => "HS256",
            AlgorithmId::HS384 => "HS384",
            AlgorithmId::HS512 => "HS512",

            #[cfg(feature = "rsa")]
            AlgorithmId::RS256 => "RS256",
            #[cfg(feature = "rsa")]
            AlgorithmId::RS384 => "RS384",
            #[cfg(feature = "rsa")]
            AlgorithmId::RS512 => "RS512",

            #[cfg(feature = "ecdsa")]
            AlgorithmId::ES256 => "ES256",
            #[cfg(feature = "ecdsa")]
            AlgorithmId::ES384 => "ES384",

            #[cfg(not(any(feature = "rsa", feature = "ecdsa")))]
            _ => unreachable!("At least one asymmetric algorithm feature must be enabled for this variant to exist"),
        }
    }

    /// Check if algorithm is HMAC-based (symmetric)
    pub fn is_symmetric(&self) -> bool {
        matches!(
            self,
            AlgorithmId::HS256 | AlgorithmId::HS384 | AlgorithmId::HS512
        )
    }

    /// Check if algorithm is asymmetric (RSA/ECDSA)
    pub fn is_asymmetric(&self) -> bool {
        !self.is_symmetric()
    }
}

impl std::fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Policy for allowed algorithms
#[derive(Debug, Clone)]
pub struct AlgorithmPolicy {
    allowed: Vec<AlgorithmId>,
}

impl AlgorithmPolicy {
    /// Create a policy that allows only specific algorithms
    pub fn allow_only(algorithms: Vec<AlgorithmId>) -> Self {
        Self {
            allowed: algorithms,
        }
    }

    /// Create a policy that allows all enabled algorithms
    pub fn allow_all() -> Self {
        let mut allowed = Vec::new();

        allowed.push(AlgorithmId::HS256);
        allowed.push(AlgorithmId::HS384);
        allowed.push(AlgorithmId::HS512);

        #[cfg(feature = "rsa")]
        {
            allowed.push(AlgorithmId::RS256);
            allowed.push(AlgorithmId::RS384);
            allowed.push(AlgorithmId::RS512);
        }

        #[cfg(feature = "ecdsa")]
        {
            allowed.push(AlgorithmId::ES256);
            allowed.push(AlgorithmId::ES384);
        }

        Self { allowed }
    }

    /// Policy that allows only HS256
    ///
    /// This is the recommended policy for HMAC-based validation when you control
    /// the signing key and algorithm.
    pub fn hs256_only() -> Self {
        Self::allow_only(vec![AlgorithmId::HS256])
    }

    /// Policy that allows only HS384
    pub fn hs384_only() -> Self {
        Self::allow_only(vec![AlgorithmId::HS384])
    }

    /// Policy that allows only HS512
    pub fn hs512_only() -> Self {
        Self::allow_only(vec![AlgorithmId::HS512])
    }

    /// Policy that allows any HMAC algorithm (HS256, HS384, HS512)
    ///
    /// # Security Warning
    ///
    /// Using multiple HMAC variants with the same key is not recommended.
    /// Prefer algorithm-specific policies like [`hs256_only()`](Self::hs256_only).
    pub fn hmac_any() -> Self {
        Self::allow_only(vec![
            AlgorithmId::HS256,
            AlgorithmId::HS384,
            AlgorithmId::HS512,
        ])
    }

    /// Policy that allows only RS256
    ///
    /// This is the recommended policy for RSA-based validation.
    #[cfg(feature = "rsa")]
    pub fn rs256_only() -> Self {
        Self::allow_only(vec![AlgorithmId::RS256])
    }

    /// Policy that allows only RS384
    #[cfg(feature = "rsa")]
    pub fn rs384_only() -> Self {
        Self::allow_only(vec![AlgorithmId::RS384])
    }

    /// Policy that allows only RS512
    #[cfg(feature = "rsa")]
    pub fn rs512_only() -> Self {
        Self::allow_only(vec![AlgorithmId::RS512])
    }

    /// Policy that allows any RSA algorithm (RS256, RS384, RS512)
    #[cfg(feature = "rsa")]
    pub fn rsa_any() -> Self {
        Self::allow_only(vec![
            AlgorithmId::RS256,
            AlgorithmId::RS384,
            AlgorithmId::RS512,
        ])
    }

    /// Policy that allows only ES256 (ECDSA with P-256)
    ///
    /// This is the recommended policy for ECDSA-based validation with P-256 curve.
    #[cfg(feature = "ecdsa")]
    pub fn es256_only() -> Self {
        Self::allow_only(vec![AlgorithmId::ES256])
    }

    /// Policy that allows only ES384 (ECDSA with P-384)
    #[cfg(feature = "ecdsa")]
    pub fn es384_only() -> Self {
        Self::allow_only(vec![AlgorithmId::ES384])
    }

    /// Policy that allows any ECDSA algorithm (ES256, ES384)
    #[cfg(feature = "ecdsa")]
    pub fn ecdsa_any() -> Self {
        Self::allow_only(vec![AlgorithmId::ES256, AlgorithmId::ES384])
    }

    /// Policy that allows recommended asymmetric algorithms (RS256 + ES256)
    ///
    /// This is a good default for services that need to support both RSA and ECDSA
    /// but want to restrict to the most common, well-supported algorithms.
    #[cfg(any(feature = "rsa", feature = "ecdsa"))]
    pub fn recommended_asymmetric() -> Self {
        let algorithms = vec![
            #[cfg(feature = "rsa")]
            AlgorithmId::RS256,
            #[cfg(feature = "ecdsa")]
            AlgorithmId::ES256,
        ];

        Self::allow_only(algorithms)
    }

    /// Check if an algorithm is allowed
    pub fn is_allowed(&self, algorithm: &AlgorithmId) -> bool {
        self.allowed.contains(algorithm)
    }

    /// Validate algorithm against policy
    pub fn validate(&self, algorithm: &AlgorithmId) -> Result<()> {
        if self.is_allowed(algorithm) {
            Ok(())
        } else {
            Err(Error::AlgorithmNotAllowed {
                found: algorithm.to_string(),
                allowed: self.allowed.iter().map(|a| a.to_string()).collect(),
            })
        }
    }

    /// Get list of allowed algorithms
    pub fn allowed_algorithms(&self) -> &[AlgorithmId] {
        &self.allowed
    }
}

impl Default for AlgorithmPolicy {
    fn default() -> Self {
        Self::allow_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_from_str() {
        assert!(matches!(
            AlgorithmId::from_str("none"),
            Err(Error::NoneAlgorithmRejected)
        ));
        assert!(matches!(
            AlgorithmId::from_str("ES512"),
            Err(Error::UnsupportedAlgorithm(_))
        ));
        assert!(matches!(
            AlgorithmId::from_str("UNKNOWN"),
            Err(Error::UnsupportedAlgorithm(_))
        ));

        assert_eq!(AlgorithmId::from_str("HS256").unwrap(), AlgorithmId::HS256);
        assert_eq!(AlgorithmId::from_str("HS384").unwrap(), AlgorithmId::HS384);
        assert_eq!(AlgorithmId::from_str("HS512").unwrap(), AlgorithmId::HS512);

        #[cfg(feature = "rsa")]
        {
            assert_eq!(AlgorithmId::from_str("RS256").unwrap(), AlgorithmId::RS256);
        }

        #[cfg(feature = "ecdsa")]
        {
            assert_eq!(AlgorithmId::from_str("ES256").unwrap(), AlgorithmId::ES256);
        }
    }

    #[test]
    fn test_algorithm_policy() {
        let policy = AlgorithmPolicy::allow_only(vec![AlgorithmId::HS256]);
        assert!(policy.is_allowed(&AlgorithmId::HS256));
        assert!(!policy.is_allowed(&AlgorithmId::HS384));
        assert!(policy.validate(&AlgorithmId::HS256).is_ok());
        assert!(policy.validate(&AlgorithmId::HS384).is_err());

        let policy_all = AlgorithmPolicy::allow_all();
        assert!(!policy_all.allowed_algorithms().is_empty());
    }
}
