use crate::algorithm::Algorithm;
use crate::error::{Error, Result};
use crate::keys::{EcdsaCurve, Key};
use crate::utils::base64url;

// Select crypto backend based on features
#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs::signature::{self, UnparsedPublicKey};
#[cfg(not(feature = "aws-lc-rs"))]
use ring::signature::{self, UnparsedPublicKey};

/// ES256 algorithm (ECDSA with P-256 and SHA-256)
pub struct ES256;

/// ES384 algorithm (ECDSA with P-384 and SHA-384)
pub struct ES384;

impl Algorithm for ES256 {
    fn name(&self) -> &'static str {
        "ES256"
    }

    fn verify(&self, signing_input: &str, signature: &str, key: &Key) -> Result<()> {
        let ecdsa_key = key.as_ecdsa_public()?;

        // Verify curve matches algorithm
        if ecdsa_key.curve() != EcdsaCurve::P256 {
            return Err(Error::KeyTypeMismatch {
                algorithm: "ES256".to_string(),
                expected_key_type: "ECDSA P-256".to_string(),
                actual_key_type: format!("ECDSA {:?}", ecdsa_key.curve()),
            });
        }

        verify_ecdsa(
            signing_input,
            signature,
            ecdsa_key.as_der(),
            &signature::ECDSA_P256_SHA256_ASN1,
        )
    }
}

impl Algorithm for ES384 {
    fn name(&self) -> &'static str {
        "ES384"
    }

    fn verify(&self, signing_input: &str, signature: &str, key: &Key) -> Result<()> {
        let ecdsa_key = key.as_ecdsa_public()?;

        // Verify curve matches algorithm
        if ecdsa_key.curve() != EcdsaCurve::P384 {
            return Err(Error::KeyTypeMismatch {
                algorithm: "ES384".to_string(),
                expected_key_type: "ECDSA P-384".to_string(),
                actual_key_type: format!("ECDSA {:?}", ecdsa_key.curve()),
            });
        }

        verify_ecdsa(
            signing_input,
            signature,
            ecdsa_key.as_der(),
            &signature::ECDSA_P384_SHA384_ASN1,
        )
    }
}

/// Generic ECDSA signature verification
fn verify_ecdsa(
    signing_input: &str,
    signature: &str,
    public_key_der: &[u8],
    algorithm: &'static dyn signature::VerificationAlgorithm,
) -> Result<()> {
    // Decode the signature from Base64URL
    let signature_bytes = base64url::decode_bytes(signature)?;

    // Create an unparsed public key
    let public_key = UnparsedPublicKey::new(algorithm, public_key_der);

    // Verify the signature
    public_key
        .verify(signing_input.as_bytes(), &signature_bytes)
        .map_err(|_| Error::SignatureInvalid)
}

#[cfg(all(test, feature = "ecdsa"))]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    };

    fn generate_ecdsa_keypair(curve: EcdsaCurve) -> (Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let alg = match curve {
            EcdsaCurve::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            EcdsaCurve::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
        };

        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(alg, &rng).expect("Failed to generate key");
        let key_pair =
            EcdsaKeyPair::from_pkcs8(alg, pkcs8_bytes.as_ref(), &rng).expect("Failed to parse key");

        let public_key_der = key_pair.public_key().as_ref().to_vec();
        (public_key_der, pkcs8_bytes.as_ref().to_vec())
    }

    fn sign_ecdsa(data: &[u8], private_key_der: &[u8], curve: EcdsaCurve) -> Vec<u8> {
        let rng = SystemRandom::new();
        let alg = match curve {
            EcdsaCurve::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            EcdsaCurve::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
        };

        let key_pair =
            EcdsaKeyPair::from_pkcs8(alg, private_key_der, &rng).expect("Failed to load key");
        let signature = key_pair.sign(&rng, data).expect("Signing failed");
        signature.as_ref().to_vec()
    }

    #[test]
    fn test_es256_valid_signature() {
        let signing_input = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let (public_key_der, private_key_der) = generate_ecdsa_keypair(EcdsaCurve::P256);

        let signature_bytes =
            sign_ecdsa(signing_input.as_bytes(), &private_key_der, EcdsaCurve::P256);
        let signature = base64url::encode_bytes(&signature_bytes);

        let key = Key::ecdsa_public(public_key_der, EcdsaCurve::P256);
        let result = ES256.verify(signing_input, &signature, &key);
        assert!(result.is_ok(), "Valid ES256 signature should verify");
    }

    #[test]
    fn test_es256_invalid_signature() {
        let signing_input = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let (public_key_der, _) = generate_ecdsa_keypair(EcdsaCurve::P256);

        let wrong_signature = base64url::encode("wrong_signature");
        let key = Key::ecdsa_public(public_key_der, EcdsaCurve::P256);

        let result = ES256.verify(signing_input, &wrong_signature, &key);
        assert!(matches!(result, Err(Error::SignatureInvalid)));
    }

    #[test]
    fn test_es256_wrong_key() {
        let signing_input = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let (_, private_key_der) = generate_ecdsa_keypair(EcdsaCurve::P256);
        let (wrong_public_key_der, _) = generate_ecdsa_keypair(EcdsaCurve::P256);

        let signature_bytes =
            sign_ecdsa(signing_input.as_bytes(), &private_key_der, EcdsaCurve::P256);
        let signature = base64url::encode_bytes(&signature_bytes);

        let key = Key::ecdsa_public(wrong_public_key_der, EcdsaCurve::P256);
        let result = ES256.verify(signing_input, &signature, &key);
        assert!(matches!(result, Err(Error::SignatureInvalid)));
    }

    #[test]
    fn test_es256_wrong_curve() {
        let signing_input = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let (public_key_der, _) = generate_ecdsa_keypair(EcdsaCurve::P384);

        let signature = base64url::encode("signature");
        let key = Key::ecdsa_public(public_key_der, EcdsaCurve::P384);

        let result = ES256.verify(signing_input, &signature, &key);
        assert!(matches!(result, Err(Error::KeyTypeMismatch { .. })));
    }

    #[test]
    fn test_es384_valid_signature() {
        let signing_input = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let (public_key_der, private_key_der) = generate_ecdsa_keypair(EcdsaCurve::P384);

        let signature_bytes =
            sign_ecdsa(signing_input.as_bytes(), &private_key_der, EcdsaCurve::P384);
        let signature = base64url::encode_bytes(&signature_bytes);

        let key = Key::ecdsa_public(public_key_der, EcdsaCurve::P384);
        let result = ES384.verify(signing_input, &signature, &key);
        assert!(result.is_ok(), "Valid ES384 signature should verify");
    }

    #[test]
    fn test_es384_wrong_curve() {
        let signing_input = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let (public_key_der, _) = generate_ecdsa_keypair(EcdsaCurve::P256);

        let signature = base64url::encode("signature");
        let key = Key::ecdsa_public(public_key_der, EcdsaCurve::P256);

        let result = ES384.verify(signing_input, &signature, &key);
        assert!(matches!(result, Err(Error::KeyTypeMismatch { .. })));
    }

    #[test]
    fn test_wrong_key_type() {
        let signing_input = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let signature = "signature";

        // Try with symmetric key (wrong type)
        let sym_key = Key::symmetric(b"secret");
        let result = ES256.verify(signing_input, signature, &sym_key);
        assert!(matches!(result, Err(Error::KeyTypeMismatch { .. })));
    }
}
