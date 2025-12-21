use criterion::{Criterion, black_box, criterion_group};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use jwtiny::{AlgorithmPolicy, AlgorithmType, ClaimsValidation, TokenValidator};
use rsa::{
    RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey, pkcs8::EncodePrivateKey,
    pkcs8::EncodePublicKey,
};
use serde_json::json;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};

#[path = "../report.rs"]
mod report;
use report::{calculate_ops_per_sec, create_row, write_report};

static RESULTS: OnceLock<Mutex<Vec<(String, u64)>>> = OnceLock::new();

fn get_results() -> &'static Mutex<Vec<(String, u64)>> {
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

fn generate_token(algorithm: Algorithm, private_key: &RsaPrivateKey) -> String {
    let claims = json!({
        "sub": "benchmark-user",
        "iss": "benchmark-issuer",
    });

    let encoding_key = EncodingKey::from_rsa_pem(
        private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to encode private key")
            .as_bytes(),
    )
    .expect("Failed to create encoding key");

    let mut header = Header::new(algorithm);
    header.typ = Some("JWT".to_string());

    encode(&header, &claims, &encoding_key).expect("Failed to encode token")
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

fn benchmark_rsa_2048_sha_256(c: &mut Criterion) {
    let private_key = load_private_key_2048();
    let public_key_der = extract_public_key_der(&private_key);
    let token = generate_token(Algorithm::RS256, &private_key);
    let validator = create_validator(AlgorithmType::RS256, public_key_der);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("rsa_validation");

    group.bench_function("jwtiny-rsa-2048-SHA-256-validation", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            for _ in 0..iters {
                rt.block_on(validator.verify(black_box(&token))).unwrap();
            }
            let elapsed = start.elapsed();
            let nanos_per_iter = elapsed.as_nanos() as f64 / iters as f64;
            let ops = calculate_ops_per_sec(nanos_per_iter);
            get_results()
                .lock()
                .unwrap()
                .push(("SHA-256".to_string(), ops));
            elapsed
        });
    });
    group.finish();
}

fn benchmark_rsa_2048_sha_384(c: &mut Criterion) {
    let private_key = load_private_key_2048();
    let public_key_der = extract_public_key_der(&private_key);
    let token = generate_token(Algorithm::RS384, &private_key);
    let validator = create_validator(AlgorithmType::RS384, public_key_der);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("rsa_validation");

    group.bench_function("jwtiny-rsa-2048-SHA-384-validation", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            for _ in 0..iters {
                rt.block_on(validator.verify(black_box(&token))).unwrap();
            }
            let elapsed = start.elapsed();
            let nanos_per_iter = elapsed.as_nanos() as f64 / iters as f64;
            let ops = calculate_ops_per_sec(nanos_per_iter);
            get_results()
                .lock()
                .unwrap()
                .push(("SHA-384".to_string(), ops));
            elapsed
        });
    });
    group.finish();
}

fn benchmark_rsa_2048_sha_512(c: &mut Criterion) {
    let private_key = load_private_key_2048();
    let public_key_der = extract_public_key_der(&private_key);
    let token = generate_token(Algorithm::RS512, &private_key);
    let validator = create_validator(AlgorithmType::RS512, public_key_der);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("rsa_validation");

    group.bench_function("jwtiny-rsa-2048-SHA-512-validation", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            for _ in 0..iters {
                rt.block_on(validator.verify(black_box(&token))).unwrap();
            }
            let elapsed = start.elapsed();
            let nanos_per_iter = elapsed.as_nanos() as f64 / iters as f64;
            let ops = calculate_ops_per_sec(nanos_per_iter);
            get_results()
                .lock()
                .unwrap()
                .push(("SHA-512".to_string(), ops));
            elapsed
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_rsa_2048_sha_256,
    benchmark_rsa_2048_sha_384,
    benchmark_rsa_2048_sha_512
);

fn main() {
    benches();

    // Export results
    let results = get_results().lock().unwrap();
    let header = "library, type, keysize, algorithm, ops";
    let mut rows = Vec::new();

    for (algorithm, ops) in results.iter() {
        rows.push(create_row(&[
            "jwtiny",
            "rsa",
            "2048",
            algorithm,
            &ops.to_string(),
        ]));
    }

    write_report("rsa_validation.txt", header, &rows);
}
