//! Algorithm selection and policy benchmarks
//!
//! Benchmarks the overhead of algorithm policy enforcement
//! and algorithm selection logic.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jwtiny::*;

/// Helper to generate tokens with different algorithms
mod helpers {
    use hmac::{Hmac, Mac};
    use jwtiny::utils::base64url;
    use sha2::{Sha256, Sha384, Sha512};

    pub fn generate_token(secret: &[u8], alg: &str) -> String {
        let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let payload = format!(
            r#"{{"sub":"user123","iss":"https://example.com","iat":{},"exp":{}}}"#,
            now,
            now + 3600
        );

        let header_b64 = base64url::encode(&header);
        let payload_b64 = base64url::encode(&payload);
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
            _ => panic!("Unsupported algorithm: {}", alg),
        };

        let signature_b64 = base64url::encode_bytes(&signature_bytes);
        format!("{}.{}", signing_input, signature_b64)
    }
}

fn bench_algorithm_policy(c: &mut Criterion) {
    use helpers::generate_token;

    let secret = b"test-secret-key";
    let mut group = c.benchmark_group("algorithm_policy");

    // No policy (all algorithms allowed)
    {
        let token = generate_token(secret, "HS256");

        group.bench_function("no_policy", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .skip_issuer_check()
                    .verify_signature(SignatureVerification::with_secret(secret))
                    .validate_token(ValidationConfig::default().skip_all())
                    .run();
            });
        });
    }

    // Single algorithm allowed
    {
        let token = generate_token(secret, "HS256");

        group.bench_function("single_allowed", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .skip_issuer_check()
                    .verify_signature(
                        SignatureVerification::with_secret(secret).allow_algorithms(
                            AlgorithmPolicy::allow_only(vec![AlgorithmId::HS256]),
                        ),
                    )
                    .validate_token(ValidationConfig::default().skip_all())
                    .run();
            });
        });
    }

    // Multiple algorithms allowed
    {
        let token = generate_token(secret, "HS256");

        group.bench_function("multiple_allowed", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .skip_issuer_check()
                    .verify_signature(SignatureVerification::with_secret(secret).allow_algorithms(
                        AlgorithmPolicy::allow_only(vec![
                            AlgorithmId::HS256,
                            AlgorithmId::HS384,
                            AlgorithmId::HS512,
                        ]),
                    ))
                    .validate_token(ValidationConfig::default().skip_all())
                    .run();
            });
        });
    }

    // Algorithm rejection (wrong algorithm)
    {
        let token = generate_token(secret, "HS384");

        group.bench_function("algorithm_rejected", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .skip_issuer_check()
                    .verify_signature(
                        SignatureVerification::with_secret(secret).allow_algorithms(
                            AlgorithmPolicy::allow_only(vec![AlgorithmId::HS256]),
                        ),
                    )
                    .validate_token(ValidationConfig::default().skip_all())
                    .run();
            });
        });
    }

    group.finish();
}

fn bench_algorithm_detection(c: &mut Criterion) {
    use helpers::generate_token;

    let secret = b"test-secret-key";
    let mut group = c.benchmark_group("algorithm_detection");

    let algorithms = vec!["HS256", "HS384", "HS512"];

    for alg in algorithms {
        let token = generate_token(secret, alg);
        group.bench_function(format!("detect_{}", alg), |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(black_box(&token)).unwrap();
                let _ = parsed.header().parse_algorithm();
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_algorithm_policy, bench_algorithm_detection);
criterion_main!(benches);
