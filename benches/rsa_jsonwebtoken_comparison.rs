use criterion::{criterion_group, criterion_main, Criterion};
use jwtiny::*;

#[cfg(feature = "rsa")]
mod helpers {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::RsaPrivateKey;

    /// Helper to generate a valid RS256 JWT token
    pub fn generate_rs256_token(header: &str, payload: &str) -> (String, Vec<u8>) {
        // Generate RSA key pair
        let mut rng = rand::thread_rng();
        let rsa_private_key =
            RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key pair");
        let pkcs8_doc = rsa_private_key
            .to_pkcs8_der()
            .expect("Failed to serialize private key");
        let ring_keypair =
            RsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes()).expect("Failed to create ring RsaKeyPair");
        let public_key_der = ring_keypair.public().as_ref().to_vec();

        // Encode header and payload
        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");

        // Sign
        let rng = SystemRandom::new();
        let mut signature_bytes = vec![0u8; ring_keypair.public().modulus_len()];
        ring_keypair
            .sign(
                &RSA_PKCS1_SHA256,
                &rng,
                signing_input.as_bytes(),
                &mut signature_bytes,
            )
            .expect("Failed to sign");
        let signature = URL_SAFE_NO_PAD.encode(&signature_bytes);

        let token = format!("{header_b64}.{payload_b64}.{signature}");

        (token, public_key_der)
    }
}

#[cfg(feature = "rsa")]
use helpers::generate_rs256_token;
#[cfg(feature = "rsa")]
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

#[cfg(feature = "rsa")]
fn bench_parse_only(c: &mut Criterion) {
    let header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"user123","iat":1516239022,"exp":9999999999}"#;
    let (token, _) = generate_rs256_token(header, payload);

    let mut group = c.benchmark_group("parse_only");

    group.bench_function("jwtiny", |b| {
        b.iter(|| {
            let _ = ParsedToken::from_string(&token);
        });
    });

    group.finish();
}

#[cfg(not(feature = "rsa"))]
fn bench_parse_only(_c: &mut Criterion) {}

#[cfg(feature = "rsa")]
fn bench_verification(c: &mut Criterion) {
    let header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"user123","iat":1516239022,"exp":9999999999}"#;
    let (token, public_key_der) = generate_rs256_token(header, payload);

    let mut group = c.benchmark_group("rs256_verification");

    // Benchmark jwtiny
    group.bench_function("jwtiny", |b| {
        let pub_key = Key::rsa_public(public_key_der.clone());
        b.iter(|| {
            let parsed = ParsedToken::from_string(&token).unwrap();
            let _ = TokenValidator::new(parsed)
                .danger_skip_issuer_validation()
                .verify_signature(SignatureVerification::with_key(
                    pub_key.clone(),
                    AlgorithmPolicy::rs256_only(),
                ))
                .validate_token(ValidationConfig::default().skip_all())
                .run();
        });
    });

    // Benchmark jsonwebtoken
    group.bench_function("jsonwebtoken", |b| {
        let decoding_key = DecodingKey::from_rsa_der(&public_key_der);
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;

        b.iter(|| {
            let _ = decode::<serde_json::Value>(&token, &decoding_key, &validation);
        });
    });

    group.finish();
}

#[cfg(not(feature = "rsa"))]
fn bench_verification(_c: &mut Criterion) {}

criterion_group!(benches, bench_parse_only, bench_verification);
criterion_main!(benches);
