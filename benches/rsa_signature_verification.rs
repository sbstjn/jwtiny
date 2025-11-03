use criterion::{Criterion, criterion_group, criterion_main};
use jwtiny::*;
use std::env;
use std::fs;

/// Benchmark RS256 signature verification
#[cfg(feature = "rsa")]
fn bench_rs256_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("rs256_verification");

    // Get token and public key from environment variables (optional)
    let (token_str, pub_der) = match (env::var("RSA_JWT").ok(), env::var("RSA_PUB_DER_PATH").ok()) {
        (Some(token), Some(path)) => {
            let der = fs::read(&path).expect("Failed to read public key DER");
            (token, der)
        }
        _ => {
            // Generate token and key on the fly for benchmarks
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use ring::rand::SystemRandom;
            use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
            use rsa::RsaPrivateKey;
            use rsa::pkcs8::EncodePrivateKey;

            let header = r#"{"alg":"RS256","typ":"JWT"}"#;
            let payload = r#"{"sub":"user123","iat":1516239022,"exp":9999999999}"#;

            // Generate RSA key pair
            let mut rng = rand::thread_rng();
            let rsa_private_key =
                RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key pair");
            let pkcs8_doc = rsa_private_key
                .to_pkcs8_der()
                .expect("Failed to serialize private key");
            let ring_keypair = RsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes())
                .expect("Failed to create ring RsaKeyPair");
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
    };

    let pub_key = Key::rsa_public(pub_der.clone());

    group.bench_function("rs256_verify", |b| {
        b.iter(|| {
            let parsed = ParsedToken::from_string(&token_str).unwrap();
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

    group.finish();
}

#[cfg(not(feature = "rsa"))]
fn bench_rs256_verification(_c: &mut Criterion) {
    // No-op when RSA feature is disabled
}

criterion_group!(benches, bench_rs256_verification);
criterion_main!(benches);
