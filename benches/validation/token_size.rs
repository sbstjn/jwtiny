use criterion::{Criterion, black_box, criterion_group};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use jwtiny::{AlgorithmPolicy, AlgorithmType, ClaimsValidation, TokenValidator};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
};
use serde_json::json;
use std::sync::{Arc, Mutex, OnceLock};

#[path = "../report.rs"]
mod report;
use report::{calculate_ops_per_sec, create_row, write_report};

static RESULTS: OnceLock<Mutex<Vec<(String, String, u64)>>> = OnceLock::new();

fn get_results() -> &'static Mutex<Vec<(String, String, u64)>> {
    RESULTS.get_or_init(|| Mutex::new(Vec::new()))
}

fn load_private_key_2048() -> RsaPrivateKey {
    let key_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../benches/validation/fixtures/private_key_2048.pem"
    );
    let pem = std::fs::read_to_string(key_path)
        .expect("Failed to read private key file. Run: jwkserve keygen -t rsa -s 2048 -o benches/validation/fixtures/private_key_2048.pem");
    RsaPrivateKey::from_pkcs8_pem(&pem).expect("Failed to parse private key")
}

fn extract_public_key_der(private_key: &RsaPrivateKey) -> Vec<u8> {
    let public_key = RsaPublicKey::from(private_key);
    public_key
        .to_public_key_der()
        .expect("Failed to encode public key as DER")
        .to_vec()
}

/// Generate a token with a specific target total token size
fn generate_token_with_size(
    algorithm: Algorithm,
    private_key: &RsaPrivateKey,
    target_token_size: usize,
) -> String {
    let encoding_key = EncodingKey::from_rsa_pem(
        private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to encode private key")
            .as_bytes(),
    )
    .expect("Failed to create encoding key");

    let mut header = Header::new(algorithm);
    header.typ = Some("JWT".to_string());

    // Start with minimal claims
    let mut claims = json!({
        "sub": "benchmark-user",
        "iss": "benchmark-issuer",
    });

    // Generate baseline token to measure overhead
    let baseline_token =
        encode(&header, &claims, &encoding_key).expect("Failed to encode baseline token");
    let baseline_size = baseline_token.len();

    // If target is smaller or equal to baseline, return baseline
    if target_token_size <= baseline_size {
        return baseline_token;
    }

    // Calculate how much we need to grow the token
    let size_increase_needed = target_token_size - baseline_size;

    // Estimate payload size increase needed
    // Base64URL encoding adds ~33% overhead, so payload increase ≈ token increase / 1.33
    // But we also need to account for JSON structure overhead
    let estimated_payload_increase = (size_increase_needed as f64 / 1.33) as usize;

    // Add padding data field
    // JSON overhead: "data":"..." adds ~10 bytes
    let data_padding = estimated_payload_increase.saturating_sub(10);
    let padding_string = "x".repeat(data_padding);
    claims["data"] = json!(padding_string);

    // Generate token and adjust if needed
    let mut token =
        encode(&header, &claims, &encoding_key).expect("Failed to encode token with padding");

    // If we're still too small, add more padding iteratively
    while token.len() < target_token_size && token.len() < 64 * 1024 {
        let current_size = token.len();
        let still_needed = target_token_size - current_size;
        let additional_padding = (still_needed as f64 * 1.33) as usize;

        // Append to existing data field
        if let Some(existing_data) = claims["data"].as_str() {
            let new_data = format!("{}{}", existing_data, "x".repeat(additional_padding));
            claims["data"] = json!(new_data);
        } else {
            claims["data"] = json!("x".repeat(additional_padding));
        }

        token = encode(&header, &claims, &encoding_key).expect("Failed to encode adjusted token");

        // Prevent infinite loop
        if token.len() >= target_token_size || token.len() == current_size {
            break;
        }
    }

    token
}

/// Get baseline token size (default token)
fn get_baseline_token_size(algorithm: Algorithm, private_key: &RsaPrivateKey) -> usize {
    let token = generate_token_with_size(algorithm, private_key, 0);
    token.len()
}

fn create_validator(algorithm: AlgorithmType, public_key_der: Vec<u8>) -> TokenValidator {
    let policy = match algorithm {
        AlgorithmType::RS256 => AlgorithmPolicy::rs256_only(),
        AlgorithmType::RS384 => AlgorithmPolicy::rs384_only(),
        AlgorithmType::RS512 => AlgorithmPolicy::rs512_only(),
        _ => panic!("Unsupported algorithm"),
    };

    TokenValidator::new()
        .algorithms(policy)
        .validate(
            ClaimsValidation::default()
                .no_exp_validation()
                .no_iat_validation()
                .no_nbf_validation(),
        )
        .key(Arc::new(public_key_der))
}

/// Percentage size multipliers to test
const SIZE_MULTIPLIERS: &[f64] = &[
    0.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 1500.0, 2000.0, 2500.0, 5000.0, 10000.0,
];

/// Format size label for benchmark name
fn format_size_label(multiplier: f64) -> String {
    if multiplier == 0.0 {
        "default".to_string()
    } else {
        format!("+{}%", multiplier as u64)
    }
}

/// Generate benchmark for a specific algorithm and size multiplier
fn benchmark_algorithm_size(
    c: &mut Criterion,
    algorithm: Algorithm,
    algorithm_type: AlgorithmType,
    size_multiplier: f64,
) {
    let private_key = load_private_key_2048();
    let public_key_der = extract_public_key_der(&private_key);
    let baseline_size = get_baseline_token_size(algorithm, &private_key);

    // Calculate target token size
    let target_token_size = (baseline_size as f64 * (1.0 + size_multiplier / 100.0)) as usize;

    // Generate token with target total size
    let token = generate_token_with_size(algorithm, &private_key, target_token_size);
    let validator = create_validator(algorithm_type, public_key_der);

    let algorithm_name = match algorithm {
        Algorithm::RS256 => "SHA-256",
        Algorithm::RS384 => "SHA-384",
        Algorithm::RS512 => "SHA-512",
        _ => unreachable!(),
    };

    let size_label = format_size_label(size_multiplier);
    let bench_name = format!(
        "jwtiny-rsa-2048-{}-validation-{}",
        algorithm_name, size_label
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("token_size");
    group.bench_function(&bench_name, |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            for _ in 0..iters {
                rt.block_on(validator.verify(black_box(&token))).unwrap();
            }
            let elapsed = start.elapsed();
            let nanos_per_iter = elapsed.as_nanos() as f64 / iters as f64;
            let ops = calculate_ops_per_sec(nanos_per_iter);
            let size_label = format_size_label(size_multiplier);
            get_results()
                .lock()
                .unwrap()
                .push((algorithm_name.to_string(), size_label, ops));
            elapsed
        });
    });
    group.finish();
}

/// Generate all benchmarks for a specific algorithm
fn benchmark_algorithm(c: &mut Criterion, algorithm: Algorithm, algorithm_type: AlgorithmType) {
    for &multiplier in SIZE_MULTIPLIERS {
        benchmark_algorithm_size(c, algorithm, algorithm_type, multiplier);
    }
}

fn benches(c: &mut Criterion) {
    benchmark_algorithm(c, Algorithm::RS256, AlgorithmType::RS256);
    benchmark_algorithm(c, Algorithm::RS384, AlgorithmType::RS384);
    benchmark_algorithm(c, Algorithm::RS512, AlgorithmType::RS512);
}

criterion_group!(benches_group, benches);

fn main() {
    benches_group();

    // Export results
    let results = get_results().lock().unwrap();
    let header = "library, type, keysize, algorithm, tokensize, ops";
    let mut rows = Vec::new();

    for (algorithm, tokensize, ops) in results.iter() {
        rows.push(create_row(&[
            "jwtiny",
            "rsa",
            "2048",
            algorithm,
            tokensize,
            &ops.to_string(),
        ]));
    }

    write_report("token_size.txt", header, &rows);
}
