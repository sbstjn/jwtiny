//! Token parsing performance benchmarks
//!
//! Benchmarks the token parsing performance with different
//! token sizes and structures.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use jwtiny::*;

/// Helper to generate test tokens of different sizes
mod helpers {
    use hmac::{Hmac, Mac};
    use jwtiny::utils::base64url;
    use sha2::Sha256;

    pub fn generate_token_with_payload_size(secret: &[u8], payload_size: usize) -> String {
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;

        // Create payload with specified size
        let mut payload =
            r#"{"sub":"user123","iss":"https://example.com","iat":1516239022,"exp":9999999999"#
                .to_string();
        let extra_size = payload_size.saturating_sub(payload.len());
        if extra_size > 0 {
            payload.push_str(",\"data\":\"");
            payload.push_str(&"x".repeat(extra_size.saturating_sub(10))); // Account for quotes and closing
            payload.push_str("\"}");
        } else {
            payload.push('}');
        }

        let header_b64 = base64url::encode(header);
        let payload_b64 = base64url::encode(&payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = base64url::encode_bytes(&signature_bytes);

        format!("{}.{}", signing_input, signature_b64)
    }
}

fn bench_parsing_by_size(c: &mut Criterion) {
    use helpers::generate_token_with_payload_size;

    let secret = b"test-secret-key";
    let sizes = vec![64, 256, 1024, 4096, 16384];

    let mut group = c.benchmark_group("parse_by_size");

    for size in sizes {
        let token = generate_token_with_payload_size(secret, size);
        let size_throughput = Throughput::Bytes(token.len() as u64);

        group.throughput(size_throughput);
        group.bench_function(format!("size_{}", size), |b| {
            b.iter(|| {
                let _ = ParsedToken::from_string(black_box(&token));
            });
        });
    }

    group.finish();
}

fn bench_parsing_stages(c: &mut Criterion) {
    use helpers::generate_token_with_payload_size;

    let secret = b"test-secret-key";
    let token = generate_token_with_payload_size(secret, 256);

    let mut group = c.benchmark_group("parse_stages");

    // Full parsing
    group.bench_function("full_parse", |b| {
        b.iter(|| {
            let _ = ParsedToken::from_string(black_box(&token));
        });
    });

    // Base64URL decoding only
    group.bench_function("base64url_decode", |b| {
        let parts: Vec<&str> = token.split('.').collect();
        b.iter(|| {
            let _ = jwtiny::utils::base64url::decode(black_box(parts[0]));
            let _ = jwtiny::utils::base64url::decode(black_box(parts[1]));
            let _ = jwtiny::utils::base64url::decode(black_box(parts[2]));
        });
    });

    // JSON parsing only (header + payload)
    group.bench_function("json_parse", |b| {
        let parts: Vec<&str> = token.split('.').collect();
        let header_str = jwtiny::utils::base64url::decode(parts[0]).unwrap();
        let payload_str = jwtiny::utils::base64url::decode(parts[1]).unwrap();

        b.iter(|| {
            use jwtiny::token::TokenHeader;
            use miniserde::Deserialize;

            #[derive(miniserde::Deserialize)]
            struct SimplePayload {
                sub: Option<String>,
                iss: Option<String>,
                exp: Option<i64>,
            }

            let _: TokenHeader = miniserde::json::from_str(black_box(&header_str)).unwrap();
            let _: SimplePayload = miniserde::json::from_str(black_box(&payload_str)).unwrap();
        });
    });

    group.finish();
}

fn bench_invalid_tokens(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_invalid");

    // Missing parts
    group.bench_function("missing_parts", |b| {
        let invalid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        b.iter(|| {
            let _ = ParsedToken::from_string(black_box(invalid));
        });
    });

    // Invalid base64
    group.bench_function("invalid_base64", |b| {
        let invalid = "invalid.base64.signature!!!";
        b.iter(|| {
            let _ = ParsedToken::from_string(black_box(invalid));
        });
    });

    // Invalid JSON
    group.bench_function("invalid_json", |b| {
        let invalid = "eyJpbnZhbGlkX2pzb24.Invalid.Signature";
        b.iter(|| {
            let _ = ParsedToken::from_string(black_box(invalid));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parsing_by_size,
    bench_parsing_stages,
    bench_invalid_tokens
);
criterion_main!(benches);
