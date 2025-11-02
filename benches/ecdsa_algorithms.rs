//! ECDSA algorithm benchmarks (ES256, ES384)
//!
//! Benchmarks the performance of ECDSA algorithms using
//! either ring or aws-lc-rs backend.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jwtiny::*;

/// Helper to generate ECDSA-signed tokens
#[cfg(feature = "ecdsa")]
mod helpers {
    use jwtiny::utils::base64url;

    pub fn generate_ecdsa_token(alg: &str, private_key_pem: &str) -> (String, Vec<u8>) {
        // This is a placeholder - ECDSA key generation and signing
        // would require proper key generation utilities
        // For now, we'll create a minimal token structure

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

        // Note: Actual ECDSA signing would require proper key handling
        // This is a placeholder structure for benchmarking
        let signature_b64 = base64url::encode("placeholder_signature");
        let token = format!("{}.{}", signing_input, signature_b64);

        // Placeholder public key DER
        let public_key_der = private_key_pem.as_bytes().to_vec();

        (token, public_key_der)
    }
}

#[cfg(feature = "ecdsa")]
fn bench_ecdsa_verification(c: &mut Criterion) {
    // Note: ECDSA benchmarks require proper key generation
    // This is a placeholder structure that can be implemented
    // when ECDSA key generation utilities are available

    let mut group = c.benchmark_group("ecdsa_verification");

    // ES256 placeholder
    group.bench_function("ES256", |b| {
        b.iter(|| {
            // Placeholder for ES256 verification benchmark
            black_box(());
        });
    });

    // ES384 placeholder
    group.bench_function("ES384", |b| {
        b.iter(|| {
            // Placeholder for ES384 verification benchmark
            black_box(());
        });
    });

    group.finish();
}

criterion_group!(benches, bench_ecdsa_verification);
criterion_main!(benches);
