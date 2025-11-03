use crate::algorithm::Algorithm;
use crate::error::{Error, Result};
use crate::keys::Key;
use crate::utils::base64url;

use constant_time_eq::constant_time_eq;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

/// HS256 algorithm (HMAC with SHA-256)
pub struct HS256;

/// HS384 algorithm (HMAC with SHA-384)
pub struct HS384;

/// HS512 algorithm (HMAC with SHA-512)
pub struct HS512;

impl Algorithm for HS256 {
    fn name(&self) -> &'static str {
        "HS256"
    }

    fn verify(&self, signing_input: &str, signature: &str, key: &Key) -> Result<()> {
        let symmetric_key = key.as_symmetric()?;
        verify_hs256(signing_input, signature, symmetric_key.as_bytes())
    }
}

impl Algorithm for HS384 {
    fn name(&self) -> &'static str {
        "HS384"
    }

    fn verify(&self, signing_input: &str, signature: &str, key: &Key) -> Result<()> {
        let symmetric_key = key.as_symmetric()?;
        verify_hs384(signing_input, signature, symmetric_key.as_bytes())
    }
}

impl Algorithm for HS512 {
    fn name(&self) -> &'static str {
        "HS512"
    }

    fn verify(&self, signing_input: &str, signature: &str, key: &Key) -> Result<()> {
        let symmetric_key = key.as_symmetric()?;
        verify_hs512(signing_input, signature, symmetric_key.as_bytes())
    }
}

/// Verify HS256 signature with constant-time comparison
fn verify_hs256(signing_input: &str, signature: &str, secret: &[u8]) -> Result<()> {
    let provided_signature = base64url::decode_bytes(signature)?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| Error::SignatureInvalid)?;
    mac.update(signing_input.as_bytes());
    let expected_signature = mac.finalize().into_bytes();

    if provided_signature.len() != expected_signature.len() {
        return Err(Error::SignatureInvalid);
    }

    if constant_time_eq(&provided_signature, &expected_signature) {
        Ok(())
    } else {
        Err(Error::SignatureInvalid)
    }
}

/// Verify HS384 signature with constant-time comparison
fn verify_hs384(signing_input: &str, signature: &str, secret: &[u8]) -> Result<()> {
    let provided_signature = base64url::decode_bytes(signature)?;

    let mut mac = Hmac::<Sha384>::new_from_slice(secret).map_err(|_| Error::SignatureInvalid)?;
    mac.update(signing_input.as_bytes());
    let expected_signature = mac.finalize().into_bytes();

    if provided_signature.len() != expected_signature.len() {
        return Err(Error::SignatureInvalid);
    }

    if constant_time_eq(&provided_signature, &expected_signature) {
        Ok(())
    } else {
        Err(Error::SignatureInvalid)
    }
}

/// Verify HS512 signature with constant-time comparison
fn verify_hs512(signing_input: &str, signature: &str, secret: &[u8]) -> Result<()> {
    let provided_signature = base64url::decode_bytes(signature)?;

    let mut mac = Hmac::<Sha512>::new_from_slice(secret).map_err(|_| Error::SignatureInvalid)?;
    mac.update(signing_input.as_bytes());
    let expected_signature = mac.finalize().into_bytes();

    if provided_signature.len() != expected_signature.len() {
        return Err(Error::SignatureInvalid);
    }

    if constant_time_eq(&provided_signature, &expected_signature) {
        Ok(())
    } else {
        Err(Error::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compute_hs256_signature(signing_input: &str, secret: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        base64url::encode_bytes(&signature_bytes)
    }

    fn compute_hs384_signature(signing_input: &str, secret: &[u8]) -> String {
        let mut mac = Hmac::<Sha384>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        base64url::encode_bytes(&signature_bytes)
    }

    fn compute_hs512_signature(signing_input: &str, secret: &[u8]) -> String {
        let mut mac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        base64url::encode_bytes(&signature_bytes)
    }

    #[test]
    fn test_hs256_valid_signature() {
        let signing_input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let secret = b"your-256-bit-secret";
        let signature = compute_hs256_signature(signing_input, secret);

        let key = Key::symmetric(secret.to_vec());
        let result = HS256.verify(signing_input, &signature, &key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hs256_invalid_signature() {
        let signing_input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let secret = b"your-256-bit-secret";
        let key = Key::symmetric(secret.to_vec());

        let wrong_signature = base64url::encode("wrong");
        let result = HS256.verify(signing_input, &wrong_signature, &key);
        assert!(matches!(result, Err(Error::SignatureInvalid)));
    }

    #[test]
    fn test_hs256_wrong_secret() {
        let signing_input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let secret = b"your-256-bit-secret";
        let wrong_secret = b"wrong-secret";

        let signature = compute_hs256_signature(signing_input, secret);
        let key = Key::symmetric(wrong_secret.to_vec());

        let result = HS256.verify(signing_input, &signature, &key);
        assert!(matches!(result, Err(Error::SignatureInvalid)));
    }

    #[test]
    fn test_hs384_valid_signature() {
        let signing_input = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let secret = b"your-384-bit-secret-needs-to-be-longer";
        let signature = compute_hs384_signature(signing_input, secret);

        let key = Key::symmetric(secret.to_vec());
        let result = HS384.verify(signing_input, &signature, &key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hs512_valid_signature() {
        let signing_input = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let secret = b"your-512-bit-secret-needs-to-be-even-longer-than-384-bit";
        let signature = compute_hs512_signature(signing_input, secret);

        let key = Key::symmetric(secret.to_vec());
        let result = HS512.verify(signing_input, &signature, &key);
        assert!(result.is_ok());
    }

    #[test]
    #[allow(unused_variables)]
    fn test_wrong_key_type() {
        let signing_input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let signature = "signature";

        // Try with RSA key (wrong type)
        #[cfg(feature = "rsa")]
        {
            let rsa_key = Key::rsa_public(vec![1, 2, 3]);
            let result = HS256.verify(signing_input, signature, &rsa_key);
            assert!(matches!(result, Err(Error::KeyTypeMismatch { .. })));
        }
    }
}
