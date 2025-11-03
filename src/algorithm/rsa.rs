use crate::algorithm::Algorithm;
use crate::error::{Error, Result};
use crate::keys::Key;
use crate::utils::base64url;

// Select crypto backend based on features
#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs::signature::{self, UnparsedPublicKey};
#[cfg(not(feature = "aws-lc-rs"))]
use ring::signature::{self, UnparsedPublicKey};

/// RS256 algorithm (RSA with SHA-256)
pub struct RS256;

/// RS384 algorithm (RSA with SHA-384)
pub struct RS384;

/// RS512 algorithm (RSA with SHA-512)
pub struct RS512;

impl Algorithm for RS256 {
    fn name(&self) -> &'static str {
        "RS256"
    }

    fn verify(&self, signing_input: &str, signature: &str, key: &Key) -> Result<()> {
        let rsa_key = key.as_rsa_public()?;
        verify_rsa(
            signing_input,
            signature,
            rsa_key.as_der(),
            &signature::RSA_PKCS1_2048_8192_SHA256,
        )
    }
}

impl Algorithm for RS384 {
    fn name(&self) -> &'static str {
        "RS384"
    }

    fn verify(&self, signing_input: &str, signature: &str, key: &Key) -> Result<()> {
        let rsa_key = key.as_rsa_public()?;
        verify_rsa(
            signing_input,
            signature,
            rsa_key.as_der(),
            &signature::RSA_PKCS1_2048_8192_SHA384,
        )
    }
}

impl Algorithm for RS512 {
    fn name(&self) -> &'static str {
        "RS512"
    }

    fn verify(&self, signing_input: &str, signature: &str, key: &Key) -> Result<()> {
        let rsa_key = key.as_rsa_public()?;
        verify_rsa(
            signing_input,
            signature,
            rsa_key.as_der(),
            &signature::RSA_PKCS1_2048_8192_SHA512,
        )
    }
}

/// Generic RSA signature verification
fn verify_rsa(
    signing_input: &str,
    signature: &str,
    public_key_der: &[u8],
    algorithm: &'static dyn signature::VerificationAlgorithm,
) -> Result<()> {
    // Decode the signature from Base64URL
    let signature_bytes = base64url::decode_bytes(signature)?;

    // Create an unparsed public key from DER
    let public_key = UnparsedPublicKey::new(algorithm, public_key_der);

    // Verify the signature
    public_key
        .verify(signing_input.as_bytes(), &signature_bytes)
        .map_err(|_| Error::SignatureInvalid)
}

#[cfg(all(test, feature = "rsa"))]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RsaKeyPair};

    // Helper to generate RSA key pair for testing
    fn generate_rsa_keypair() -> (Vec<u8>, RsaKeyPair) {
        use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey};

        let mut rng = rand::thread_rng();
        let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate key");

        let pkcs8_doc = rsa_private_key
            .to_pkcs8_der()
            .expect("Failed to serialize to PKCS#8");
        let pkcs8_der = pkcs8_doc.as_bytes().to_vec();

        let ring_keypair =
            RsaKeyPair::from_pkcs8(&pkcs8_der).expect("Failed to create ring RsaKeyPair");
        let public_key_der = ring_keypair.public().as_ref().to_vec();

        (public_key_der, ring_keypair)
    }

    fn sign_rsa(
        data: &[u8],
        keypair: &RsaKeyPair,
        algorithm: &'static dyn ring::signature::RsaEncoding,
    ) -> Vec<u8> {
        let rng = SystemRandom::new();
        let mut signature = vec![0u8; keypair.public().modulus_len()];
        keypair
            .sign(algorithm, &rng, data, &mut signature)
            .expect("Signing failed");
        signature
    }

    #[test]
    fn test_rs256_valid_signature() {
        let signing_input = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let (public_key_der, ring_keypair) = generate_rsa_keypair();

        let signature_bytes = sign_rsa(signing_input.as_bytes(), &ring_keypair, &RSA_PKCS1_SHA256);
        let signature = base64url::encode_bytes(&signature_bytes);

        let key = Key::rsa_public(public_key_der);
        let result = RS256.verify(signing_input, &signature, &key);
        assert!(result.is_ok(), "Valid RS256 signature should verify");
    }

    #[test]
    fn test_rs256_invalid_signature() {
        let signing_input = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let (public_key_der, _) = generate_rsa_keypair();

        let wrong_signature = base64url::encode("wrong_signature");
        let key = Key::rsa_public(public_key_der);

        let result = RS256.verify(signing_input, &wrong_signature, &key);
        assert!(matches!(result, Err(Error::SignatureInvalid)));
    }

    #[test]
    fn test_rs256_wrong_key() {
        let signing_input = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let (_, signing_keypair) = generate_rsa_keypair();
        let (wrong_public_key_der, _) = generate_rsa_keypair();

        let signature_bytes = sign_rsa(
            signing_input.as_bytes(),
            &signing_keypair,
            &RSA_PKCS1_SHA256,
        );
        let signature = base64url::encode_bytes(&signature_bytes);

        let key = Key::rsa_public(wrong_public_key_der);
        let result = RS256.verify(signing_input, &signature, &key);
        assert!(matches!(result, Err(Error::SignatureInvalid)));
    }

    #[test]
    fn test_rs384_valid_signature() {
        let signing_input = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let (public_key_der, ring_keypair) = generate_rsa_keypair();

        let signature_bytes = sign_rsa(signing_input.as_bytes(), &ring_keypair, &RSA_PKCS1_SHA384);
        let signature = base64url::encode_bytes(&signature_bytes);

        let key = Key::rsa_public(public_key_der);
        let result = RS384.verify(signing_input, &signature, &key);
        assert!(result.is_ok(), "Valid RS384 signature should verify");
    }

    #[test]
    fn test_rs512_valid_signature() {
        let signing_input = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let (public_key_der, ring_keypair) = generate_rsa_keypair();

        let signature_bytes = sign_rsa(signing_input.as_bytes(), &ring_keypair, &RSA_PKCS1_SHA512);
        let signature = base64url::encode_bytes(&signature_bytes);

        let key = Key::rsa_public(public_key_der);
        let result = RS512.verify(signing_input, &signature, &key);
        assert!(result.is_ok(), "Valid RS512 signature should verify");
    }

    #[test]
    fn test_wrong_key_type() {
        let signing_input = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let signature = "signature";

        // Try with symmetric key (wrong type)
        let sym_key = Key::symmetric(b"secret");
        let result = RS256.verify(signing_input, signature, &sym_key);
        assert!(matches!(result, Err(Error::KeyTypeMismatch { .. })));
    }
}
