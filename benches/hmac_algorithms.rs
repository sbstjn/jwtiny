//! HMAC algorithm benchmarks (HS256, HS384, HS512)
//!
//! Benchmarks the performance of different HMAC algorithms
//! to compare hash function overhead.

use criterion::{criterion_group, criterion_main, Criterion};
use jwtiny::*;

/// Helper to generate HMAC-signed tokens
mod helpers {
    use hmac::{Hmac, Mac};
    use jwtiny::utils::base64url;
    use sha2::{Sha256, Sha384, Sha512};

    pub fn generate_hmac_token(secret: &[u8], alg: &str) -> (String, Vec<u8>) {
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
        let token = format!("{}.{}", signing_input, signature_b64);

        (token, secret.to_vec())
    }
}

fn bench_hmac_verification(c: &mut Criterion) {
    use helpers::generate_hmac_token;

    let mut group = c.benchmark_group("hmac_verification");

    // HS256
    {
        let secret = b"test-secret-key-for-hs256";
        let (token, _) = generate_hmac_token(secret, "HS256");

        group.bench_function("HS256", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .danger_skip_issuer_validation()
                    .verify_signature(SignatureVerification::with_secret_hs256(secret))
                    .validate_token(ValidationConfig::default().skip_all())
                    .run();
            });
        });
    }

    // HS384
    {
        let secret = b"test-secret-key-for-hs384-needs-to-be-longer";
        let (token, _) = generate_hmac_token(secret, "HS384");

        group.bench_function("HS384", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .danger_skip_issuer_validation()
                    .verify_signature(SignatureVerification::with_secret_hs384(secret))
                    .validate_token(ValidationConfig::default().skip_all())
                    .run();
            });
        });
    }

    // HS512
    {
        let secret = b"test-secret-key-for-hs512-needs-to-be-even-longer-for-512-bits";
        let (token, _) = generate_hmac_token(secret, "HS512");

        group.bench_function("HS512", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .danger_skip_issuer_validation()
                    .verify_signature(SignatureVerification::with_secret_hs512(secret))
                    .validate_token(ValidationConfig::default().skip_all())
                    .run();
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_hmac_verification);
criterion_main!(benches);
