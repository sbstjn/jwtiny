use crate::error::Result;
use crate::keys::Key;

/// Core algorithm trait that all JWT signature algorithms implement
///
/// This trait defines the contract for signature verification.
/// Different algorithm families (HMAC, RSA, ECDSA) implement this trait.
pub trait Algorithm {
    /// The algorithm identifier (e.g., "HS256", "RS256")
    fn name(&self) -> &'static str;

    /// Verify a signature
    ///
    /// # Arguments
    /// * `signing_input` - The data that was signed (header.payload)
    /// * `signature` - The Base64URL-encoded signature
    /// * `key` - The key to use for verification
    fn verify(&self, signing_input: &str, signature: &str, key: &Key) -> Result<()>;
}

/// Type alias for boxed algorithm trait objects
pub type SignatureVerifier = Box<dyn Algorithm + Send + Sync>;

/// Get a signature verifier for the given algorithm ID
#[allow(unreachable_patterns)]
pub fn get_verifier(algorithm: &super::AlgorithmId) -> SignatureVerifier {
    match algorithm {
        super::AlgorithmId::HS256 => Box::new(super::hmac::HS256),
        super::AlgorithmId::HS384 => Box::new(super::hmac::HS384),
        super::AlgorithmId::HS512 => Box::new(super::hmac::HS512),

        #[cfg(feature = "rsa")]
        super::AlgorithmId::RS256 => Box::new(super::rsa::RS256),
        #[cfg(feature = "rsa")]
        super::AlgorithmId::RS384 => Box::new(super::rsa::RS384),
        #[cfg(feature = "rsa")]
        super::AlgorithmId::RS512 => Box::new(super::rsa::RS512),

        #[cfg(feature = "ecdsa")]
        super::AlgorithmId::ES256 => Box::new(super::ecdsa::ES256),
        #[cfg(feature = "ecdsa")]
        super::AlgorithmId::ES384 => Box::new(super::ecdsa::ES384),

        #[cfg(not(any(feature = "rsa", feature = "ecdsa")))]
        _ => unreachable!(
            "At least one asymmetric algorithm feature must be enabled for this variant to exist"
        ),
    }
}
