//! Claims validation performance benchmarks
//!
//! Benchmarks the performance of different claims validation
//! operations (exp, nbf, iat, aud, iss, etc.)

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jwtiny::*;

/// Helper to generate HMAC tokens with specific claims
mod helpers {
    use hmac::{Hmac, Mac};
    use jwtiny::utils::base64url;
    use sha2::Sha256;

    pub fn generate_token_with_claims(secret: &[u8], claims: &str) -> String {
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let header_b64 = base64url::encode(header);
        let payload_b64 = base64url::encode(claims);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = base64url::encode_bytes(&signature_bytes);

        format!("{}.{}", signing_input, signature_b64)
    }
}

fn bench_exp_validation(c: &mut Criterion) {
    use helpers::generate_token_with_claims;

    let secret = b"test-secret-key";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut group = c.benchmark_group("claims_exp");

    // Valid token (not expired)
    {
        let claims = format!(r#"{{"sub":"user123","exp":{}}}"#, now + 3600);
        let token = generate_token_with_claims(secret, &claims);

        group.bench_function("valid_not_expired", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .skip_issuer_check()
                    .verify_signature(SignatureVerification::with_secret(secret))
                    .validate_token(ValidationConfig::default())
                    .run();
            });
        });
    }

    // Expired token
    {
        let claims = format!(r#"{{"sub":"user123","exp":{}}}"#, now - 3600);
        let token = generate_token_with_claims(secret, &claims);

        group.bench_function("invalid_expired", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .skip_issuer_check()
                    .verify_signature(SignatureVerification::with_secret(secret))
                    .validate_token(ValidationConfig::default())
                    .run();
            });
        });
    }

    // Token with clock skew
    {
        let claims = format!(r#"{{"sub":"user123","exp":{}}}"#, now - 30); // 30 seconds expired
        let token = generate_token_with_claims(secret, &claims);

        group.bench_function("expired_with_clock_skew", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .skip_issuer_check()
                    .verify_signature(SignatureVerification::with_secret(secret))
                    .validate_token(ValidationConfig::default().clock_skew(60))
                    .run();
            });
        });
    }

    group.finish();
}

fn bench_nbf_validation(c: &mut Criterion) {
    use helpers::generate_token_with_claims;

    let secret = b"test-secret-key";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut group = c.benchmark_group("claims_nbf");

    // Valid token (nbf in past)
    {
        let claims = format!(r#"{{"sub":"user123","nbf":{}}}"#, now - 3600);
        let token = generate_token_with_claims(secret, &claims);

        group.bench_function("valid_nbf_past", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .skip_issuer_check()
                    .verify_signature(SignatureVerification::with_secret(secret))
                    .validate_token(ValidationConfig::default())
                    .run();
            });
        });
    }

    // Invalid token (nbf in future)
    {
        let claims = format!(r#"{{"sub":"user123","nbf":{}}}"#, now + 3600);
        let token = generate_token_with_claims(secret, &claims);

        group.bench_function("invalid_nbf_future", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .skip_issuer_check()
                    .verify_signature(SignatureVerification::with_secret(secret))
                    .validate_token(ValidationConfig::default())
                    .run();
            });
        });
    }

    group.finish();
}

fn bench_aud_validation(c: &mut Criterion) {
    use helpers::generate_token_with_claims;

    let secret = b"test-secret-key";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut group = c.benchmark_group("claims_aud");

    // Single audience
    {
        let claims = format!(r#"{{"sub":"user123","aud":"api","exp":{}}}"#, now + 3600);
        let token = generate_token_with_claims(secret, &claims);

        group.bench_function("single_audience", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .skip_issuer_check()
                    .verify_signature(SignatureVerification::with_secret(secret))
                    .validate_token(
                        ValidationConfig::default()
                            .require_audience("api")
                            .clock_skew(60),
                    )
                    .run();
            });
        });
    }

    // Multiple audiences
    {
        let claims = format!(
            r#"{{"sub":"user123","aud":["api","mobile"],"exp":{}}}"#,
            now + 3600
        );
        let token = generate_token_with_claims(secret, &claims);

        group.bench_function("multiple_audiences", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .skip_issuer_check()
                    .verify_signature(SignatureVerification::with_secret(secret))
                    .validate_token(
                        ValidationConfig::default()
                            .require_audience("api")
                            .clock_skew(60),
                    )
                    .run();
            });
        });
    }

    group.finish();
}

fn bench_iss_validation(c: &mut Criterion) {
    use helpers::generate_token_with_claims;

    let secret = b"test-secret-key";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut group = c.benchmark_group("claims_iss");

    // Valid issuer
    {
        let claims = format!(
            r#"{{"sub":"user123","iss":"https://auth.example.com","exp":{}}}"#,
            now + 3600
        );
        let token = generate_token_with_claims(secret, &claims);

        group.bench_function("valid_issuer", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .ensure_issuer(|iss| {
                        if iss == "https://auth.example.com" {
                            Ok(())
                        } else {
                            Err(Error::IssuerNotTrusted(iss.to_string()))
                        }
                    })
                    .verify_signature(SignatureVerification::with_secret(secret))
                    .validate_token(ValidationConfig::default().clock_skew(60))
                    .run();
            });
        });
    }

    // Invalid issuer
    {
        let claims = format!(
            r#"{{"sub":"user123","iss":"https://evil.com","exp":{}}}"#,
            now + 3600
        );
        let token = generate_token_with_claims(secret, &claims);

        group.bench_function("invalid_issuer", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .ensure_issuer(|iss| {
                        if iss == "https://auth.example.com" {
                            Ok(())
                        } else {
                            Err(Error::IssuerNotTrusted(iss.to_string()))
                        }
                    })
                    .verify_signature(SignatureVerification::with_secret(secret))
                    .validate_token(ValidationConfig::default().clock_skew(60))
                    .run();
            });
        });
    }

    group.finish();
}

fn bench_full_validation(c: &mut Criterion) {
    use helpers::generate_token_with_claims;

    let secret = b"test-secret-key";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut group = c.benchmark_group("claims_full");

    // All claims validation
    {
        let claims = format!(
            r#"{{"sub":"user123","iss":"https://auth.example.com","aud":"api","iat":{},"nbf":{},"exp":{}}}"#,
            now - 60,
            now - 60,
            now + 3600
        );
        let token = generate_token_with_claims(secret, &claims);

        group.bench_function("all_claims", |b| {
            b.iter(|| {
                let parsed = ParsedToken::from_string(&token).unwrap();
                let _ = TokenValidator::new(parsed)
                    .ensure_issuer(|iss| {
                        if iss == "https://auth.example.com" {
                            Ok(())
                        } else {
                            Err(Error::IssuerNotTrusted(iss.to_string()))
                        }
                    })
                    .verify_signature(SignatureVerification::with_secret(secret))
                    .validate_token(
                        ValidationConfig::default()
                            .require_audience("api")
                            .clock_skew(60),
                    )
                    .run();
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_exp_validation,
    bench_nbf_validation,
    bench_aud_validation,
    bench_iss_validation,
    bench_full_validation
);
criterion_main!(benches);
