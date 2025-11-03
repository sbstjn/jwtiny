//! Multi-algorithm example demonstrating algorithm abstraction
//!
//! This example demonstrates how the algorithm trait system enables handling
//! different algorithms (HMAC, RSA, ECDSA) with the same validation code.
//! It also shows how to use algorithm policies to restrict which algorithms
//! are accepted for a given key.

use jwtiny::*;

fn main() -> Result<()> {
    println!("=== jwtiny Multi-Algorithm Example ===\n");

    // Test different algorithms
    test_hmac()?;
    test_rsa()?;
    test_ecdsa()?;

    // Test algorithm policy
    test_algorithm_policy()?;

    println!("\n✅ All algorithms tested successfully!");

    Ok(())
}

fn test_hmac() -> Result<()> {
    println!("--- Testing HMAC Algorithms ---");

    let secret = b"your-secret-key";
    let key = Key::symmetric(secret);

    for alg in &["HS256", "HS384", "HS512"] {
        let token = create_hmac_token(alg, secret);
        validate_token(&token, &key, alg)?;
    }

    println!();
    Ok(())
}

#[cfg(feature = "rsa")]
fn test_rsa() -> Result<()> {
    use ring::signature::RsaKeyPair;
    use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};

    println!("--- Testing RSA Algorithms ---");

    // Generate RSA key pair
    let mut rng = rand::thread_rng();
    let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pkcs8_doc = rsa_private_key.to_pkcs8_der().unwrap();
    let pkcs8_der = pkcs8_doc.as_bytes();

    let ring_keypair = RsaKeyPair::from_pkcs8(pkcs8_der).unwrap();
    let public_key_der = ring_keypair.public().as_ref().to_vec();

    let key = Key::rsa_public(public_key_der);

    for alg in &["RS256", "RS384", "RS512"] {
        let token = create_rsa_token(alg, &ring_keypair);
        validate_token(&token, &key, alg)?;
    }

    println!();
    Ok(())
}

#[cfg(not(feature = "rsa"))]
fn test_rsa() -> Result<()> {
    println!("--- RSA Tests Skipped (feature not enabled) ---\n");
    Ok(())
}

#[cfg(feature = "ecdsa")]
fn test_ecdsa() -> Result<()> {
    use ring::rand::SystemRandom;
    use ring::signature::{
        EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
    };

    println!("--- Testing ECDSA Algorithms ---");

    // Test ES256 (P-256)
    {
        let rng = SystemRandom::new();
        let pkcs8_bytes =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .unwrap();
        let public_key_der = key_pair.public_key().as_ref().to_vec();

        let key = Key::ecdsa_public(public_key_der, EcdsaCurve::P256);
        let token = create_ecdsa_token("ES256", &key_pair, &rng);
        validate_token(&token, &key, "ES256")?;
    }

    // Test ES384 (P-384)
    {
        let rng = SystemRandom::new();
        let pkcs8_bytes =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .unwrap();
        let public_key_der = key_pair.public_key().as_ref().to_vec();

        let key = Key::ecdsa_public(public_key_der, EcdsaCurve::P384);
        let token = create_ecdsa_token("ES384", &key_pair, &rng);
        validate_token(&token, &key, "ES384")?;
    }

    println!();
    Ok(())
}

#[cfg(not(feature = "ecdsa"))]
fn test_ecdsa() -> Result<()> {
    println!("--- ECDSA Tests Skipped (feature not enabled) ---\n");
    Ok(())
}

fn test_algorithm_policy() -> Result<()> {
    println!("--- Testing Algorithm Policy ---");

    // Create a policy that only allows HS256
    let policy = AlgorithmPolicy::allow_only(vec![AlgorithmId::HS256]);

    // This should succeed
    let token_hs256 = create_hmac_token("HS256", b"secret");
    let parsed = ParsedToken::from_string(&token_hs256)?;
    let result = parsed.validate_algorithm(&policy);
    println!("  ✓ HS256 allowed by policy: {:?}", result.is_ok());

    // This should fail
    let token_hs384 = create_hmac_token("HS384", b"secret");
    let parsed = ParsedToken::from_string(&token_hs384)?;
    let result = parsed.validate_algorithm(&policy);
    println!("  ✓ HS384 blocked by policy: {:?}", result.is_err());

    println!();
    Ok(())
}

fn validate_token(token_str: &str, key: &Key, expected_alg: &str) -> Result<()> {
    let parsed = ParsedToken::from_string(token_str)?;

    let trusted = parsed.danger_trust_without_issuer_check();
    let verified = trusted.verify_signature(key)?;
    let validated = verified.validate(&ValidationConfig::default().no_iat_validation())?;

    println!("  ✓ {} token validated successfully", expected_alg);
    assert_eq!(validated.algorithm().as_str(), expected_alg);

    Ok(())
}

fn create_hmac_token(alg: &str, secret: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha384, Sha512};

    let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let payload = format!(r#"{{"iss":"test","exp":{}}}"#, now + 3600);

    let header_b64 = jwtiny::utils::base64url::encode(&header);
    let payload_b64 = jwtiny::utils::base64url::encode(&payload);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature_bytes = match alg {
        "HS256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "HS384" => {
            let mut mac = Hmac::<Sha384>::new_from_slice(secret).unwrap();
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "HS512" => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        _ => panic!("Unknown algorithm"),
    };

    let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);
    format!("{}.{}", signing_input, signature_b64)
}

#[cfg(feature = "rsa")]
fn create_rsa_token(alg: &str, keypair: &ring::signature::RsaKeyPair) -> String {
    use ring::rand::SystemRandom;
    use ring::signature::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512};

    let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let payload = format!(r#"{{"iss":"test","exp":{}}}"#, now + 3600);

    let header_b64 = jwtiny::utils::base64url::encode(&header);
    let payload_b64 = jwtiny::utils::base64url::encode(&payload);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let rng = SystemRandom::new();
    let mut signature = vec![0u8; keypair.public().modulus_len()];

    let signing_alg = match alg {
        "RS256" => &RSA_PKCS1_SHA256,
        "RS384" => &RSA_PKCS1_SHA384,
        "RS512" => &RSA_PKCS1_SHA512,
        _ => panic!("Unknown algorithm"),
    };

    keypair
        .sign(signing_alg, &rng, signing_input.as_bytes(), &mut signature)
        .unwrap();

    let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature);
    format!("{}.{}", signing_input, signature_b64)
}

#[cfg(feature = "ecdsa")]
fn create_ecdsa_token(
    alg: &str,
    keypair: &ring::signature::EcdsaKeyPair,
    rng: &ring::rand::SystemRandom,
) -> String {
    let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let payload = format!(r#"{{"iss":"test","exp":{}}}"#, now + 3600);

    let header_b64 = jwtiny::utils::base64url::encode(&header);
    let payload_b64 = jwtiny::utils::base64url::encode(&payload);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature = keypair.sign(rng, signing_input.as_bytes()).unwrap();
    let signature_b64 = jwtiny::utils::base64url::encode_bytes(signature.as_ref());

    format!("{}.{}", signing_input, signature_b64)
}
