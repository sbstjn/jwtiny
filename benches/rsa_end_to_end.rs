use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jwtiny::*;

/// Helper function to generate a valid RS256 token
#[cfg(feature = "rsa")]
fn generate_rs256_token() -> (String, Key) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::RsaPrivateKey;

    let header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let payload =
        r#"{"sub":"user123","iss":"https://example.com","iat":1516239022,"exp":9999999999}"#;

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
    let key = Key::rsa_public(public_key_der);

    (token, key)
}

#[cfg(feature = "rsa")]
fn bench_rsa_end_to_end(c: &mut Criterion) {
    let (token_str, pub_key) = generate_rs256_token();

    let mut group = c.benchmark_group("rsa_end_to_end");

    group.bench_function("parse_only", |b| {
        b.iter(|| {
            let _ = ParsedToken::from_string(black_box(&token_str));
        });
    });

    group.bench_function("parse_and_verify", |b| {
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

    group.bench_function("full_verification_with_claims", |b| {
        b.iter(|| {
            let parsed = ParsedToken::from_string(&token_str).unwrap();
            let _ = TokenValidator::new(parsed)
                .danger_skip_issuer_validation()
                .verify_signature(SignatureVerification::with_key(
                    pub_key.clone(),
                    AlgorithmPolicy::rs256_only(),
                ))
                .validate_token(
                    ValidationConfig::default()
                        .clock_skew(60)
                        .require_audience("test-api"),
                )
                .run();
        });
    });

    group.finish();
}

#[cfg(not(feature = "rsa"))]
fn bench_rsa_end_to_end(_c: &mut Criterion) {
    // No-op when RSA feature is disabled
}

criterion_group!(benches, bench_rsa_end_to_end);
criterion_main!(benches);
