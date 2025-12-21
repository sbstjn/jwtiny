use criterion::{Criterion, black_box, criterion_group};
use jwtiny::{AlgorithmPolicy, ClaimsValidation, TokenValidator};
use moka::future::Cache;
use serde_json::json;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

#[path = "../report.rs"]
mod report;
use report::{calculate_ops_per_sec, create_row, write_report};

static RESULTS: OnceLock<Mutex<Vec<(String, String, u64)>>> = OnceLock::new();

fn get_results() -> &'static Mutex<Vec<(String, String, u64)>> {
    RESULTS.get_or_init(|| Mutex::new(Vec::new()))
}

const JWKSERVE_URL: &str = "http://127.0.0.1:3000";
const ISSUER: &str = "http://127.0.0.1:3000";

/// Generate a JWT token using jwkserve's /sign endpoint with the specified algorithm
async fn generate_token(algorithm: &str) -> String {
    let client = reqwest::Client::new();
    let claims = json!({
        "sub": "benchmark-user",
        "aud": "my-api",
        "iss": ISSUER,
    });

    let response = client
        .post(format!("{}/sign/{}", JWKSERVE_URL, algorithm))
        .json(&claims)
        .send()
        .await
        .expect("Failed to connect to jwkserve. Ensure it's running on http://127.0.0.1:3000");

    if !response.status().is_success() {
        panic!("jwkserve returned error: {}", response.status());
    }

    let body: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse jwkserve response");

    body.get("token")
        .and_then(|t| t.as_str())
        .expect("Missing token in jwkserve response")
        .to_string()
}

/// Create a validator without caching (fresh JWKS fetch on each validation)
fn create_validator_without_cache(policy: AlgorithmPolicy) -> TokenValidator {
    let client = reqwest::Client::new();

    TokenValidator::new()
        .algorithms(policy)
        .issuer(|iss| iss == ISSUER)
        .validate(ClaimsValidation::default().require_audience("my-api"))
        .jwks(client)
}

/// Create a validator with caching (JWKS keys cached for 300 seconds)
fn create_validator_with_cache(policy: AlgorithmPolicy) -> TokenValidator {
    let client = reqwest::Client::new();
    let cache = Cache::<String, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    TokenValidator::new()
        .algorithms(policy)
        .issuer(|iss| iss == ISSUER)
        .validate(ClaimsValidation::default().require_audience("my-api"))
        .jwks(client)
        .cache(cache)
}

fn benchmark_jwks_sha_256_without_cache(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let token = rt.block_on(generate_token("RS256"));
    let validator = create_validator_without_cache(AlgorithmPolicy::rs256_only());

    let mut group = c.benchmark_group("jwks_validation");
    group.bench_function("jwtiny-jwks-SHA-256-validation-without-cache", |b| {
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
                .push(("SHA-256".to_string(), "no".to_string(), ops));
            elapsed
        });
    });
    group.finish();
}

fn benchmark_jwks_sha_256_with_cache(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let token = rt.block_on(generate_token("RS256"));
    let validator = create_validator_with_cache(AlgorithmPolicy::rs256_only());

    let mut group = c.benchmark_group("jwks_validation");
    group.bench_function("jwtiny-jwks-SHA-256-validation-with-cache", |b| {
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
                .push(("SHA-256".to_string(), "yes".to_string(), ops));
            elapsed
        });
    });
    group.finish();
}

fn benchmark_jwks_sha_384_without_cache(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let token = rt.block_on(generate_token("RS384"));
    let validator = create_validator_without_cache(AlgorithmPolicy::rs384_only());

    let mut group = c.benchmark_group("jwks_validation");
    group.bench_function("jwtiny-jwks-SHA-384-validation-without-cache", |b| {
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
                .push(("SHA-384".to_string(), "no".to_string(), ops));
            elapsed
        });
    });
    group.finish();
}

fn benchmark_jwks_sha_384_with_cache(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let token = rt.block_on(generate_token("RS384"));
    let validator = create_validator_with_cache(AlgorithmPolicy::rs384_only());

    let mut group = c.benchmark_group("jwks_validation");
    group.bench_function("jwtiny-jwks-SHA-384-validation-with-cache", |b| {
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
                .push(("SHA-384".to_string(), "yes".to_string(), ops));
            elapsed
        });
    });
    group.finish();
}

fn benchmark_jwks_sha_512_without_cache(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let token = rt.block_on(generate_token("RS512"));
    let validator = create_validator_without_cache(AlgorithmPolicy::rs512_only());

    let mut group = c.benchmark_group("jwks_validation");
    group.bench_function("jwtiny-jwks-SHA-512-validation-without-cache", |b| {
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
                .push(("SHA-512".to_string(), "no".to_string(), ops));
            elapsed
        });
    });
    group.finish();
}

fn benchmark_jwks_sha_512_with_cache(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let token = rt.block_on(generate_token("RS512"));
    let validator = create_validator_with_cache(AlgorithmPolicy::rs512_only());

    let mut group = c.benchmark_group("jwks_validation");
    group.bench_function("jwtiny-jwks-SHA-512-validation-with-cache", |b| {
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
                .push(("SHA-512".to_string(), "yes".to_string(), ops));
            elapsed
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_jwks_sha_256_without_cache,
    benchmark_jwks_sha_256_with_cache,
    benchmark_jwks_sha_384_without_cache,
    benchmark_jwks_sha_384_with_cache,
    benchmark_jwks_sha_512_without_cache,
    benchmark_jwks_sha_512_with_cache
);

fn main() {
    benches();

    // Export results
    let results = get_results().lock().unwrap();
    let header = "library, type, keysize, algorithm, caching, ops";
    let mut rows = Vec::new();

    for (algorithm, caching, ops) in results.iter() {
        rows.push(create_row(&[
            "jwtiny",
            "rsa",
            "2048",
            algorithm,
            caching,
            &ops.to_string(),
        ]));
    }

    write_report("jwks_validation.txt", header, &rows);
}
