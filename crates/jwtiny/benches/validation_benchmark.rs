//! JWT validation benchmark comparing jwtiny vs jsonwebtoken
//!
//! Measures throughput (tokens/second) for all RS* and ES* algorithms
//! across different key sizes. Results are exported to stats.txt for
//! visualization with YouPlot.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

mod fixtures;
use fixtures::{BenchFixtures, Scenario};

/// Benchmark results
struct BenchmarkResult {
    scenario: Scenario,
    library: String,
    throughput: f64, // tokens per second
}

/// Run benchmarks and export results
fn run_benchmarks(c: &mut Criterion) {
    let fixtures = BenchFixtures::load();
    let mut results = Vec::new();

    // Benchmark all scenarios
    for scenario in fixtures.tokens.keys() {
        let token = fixtures.tokens.get(scenario).unwrap();
        let scenario_name = scenario.name();

        // Benchmark jwtiny
        if let Some(public_key_der) = fixtures.get_public_key_der(scenario) {
            let key_der = Arc::new(public_key_der);
            let validator = create_jwtiny_validator(scenario, key_der.clone());
            let token_clone = token.clone();

            let throughput = benchmark_jwtiny(c, &scenario_name, &token_clone, validator);
            results.push(BenchmarkResult {
                scenario: scenario.clone(),
                library: "jwtiny".to_string(),
                throughput,
            });
        }

        // Benchmark jsonwebtoken (skip ES512 - not supported)
        if scenario.curve.is_none() || scenario.curve != Some(fixtures::EcdsaCurve::P521) {
            if let Some(decoding_key) = fixtures.get_decoding_key(scenario) {
                let token_clone = token.clone();
                let throughput =
                    benchmark_jsonwebtoken(c, &scenario_name, &token_clone, scenario, decoding_key);
                results.push(BenchmarkResult {
                    scenario: scenario.clone(),
                    library: "jsonwebtoken".to_string(),
                    throughput,
                });
            }
        }
    }

    // Export results to stats.txt
    export_results(&results);
}

fn create_jwtiny_validator(scenario: &Scenario, key_der: Arc<Vec<u8>>) -> jwtiny::TokenValidator {
    use jwtiny::{AlgorithmPolicy, ClaimsValidation, TokenValidator};

    let policy = match scenario.algorithm.as_str() {
        "RS256" => AlgorithmPolicy::rs256_only(),
        "RS384" => AlgorithmPolicy::rs384_only(),
        "RS512" => AlgorithmPolicy::rs512_only(),
        "ES256" => AlgorithmPolicy::es256_only(),
        "ES384" => AlgorithmPolicy::es384_only(),
        _ => panic!("Unsupported algorithm: {}", scenario.algorithm),
    };

    TokenValidator::new()
        .algorithms(policy)
        .key(key_der)
        .validate(
            ClaimsValidation::default()
                .no_exp_validation()
                .no_iat_validation()
                .no_nbf_validation(),
        )
}

fn benchmark_jwtiny(
    c: &mut Criterion,
    name: &str,
    token: &str,
    validator: jwtiny::TokenValidator,
) -> f64 {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let validator = Arc::new(validator);
    let token = token.to_string();

    let mut group = c.benchmark_group("jwtiny");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    let bench_id = format!("jwtiny-{}", name);
    let validator_clone = validator.clone();
    let token_clone = token.clone();
    group.bench_function(&bench_id, |b| {
        b.iter(|| {
            rt.block_on(async {
                validator_clone
                    .verify(black_box(&token_clone))
                    .await
                    .unwrap();
            });
        });
    });

    // Calculate throughput: run for fixed time and count iterations
    let start = std::time::Instant::now();
    let duration = Duration::from_secs(2);
    let mut count = 0u64;

    while start.elapsed() < duration {
        rt.block_on(async {
            validator.verify(black_box(&token)).await.unwrap();
        });
        count += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    count as f64 / elapsed
}

fn benchmark_jsonwebtoken(
    c: &mut Criterion,
    name: &str,
    token: &str,
    scenario: &Scenario,
    decoding_key: jsonwebtoken::DecodingKey,
) -> f64 {
    use jsonwebtoken::{Algorithm, Validation};

    let algorithm = match scenario.algorithm.as_str() {
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        _ => panic!("Unsupported algorithm: {}", scenario.algorithm),
    };

    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;

    let mut group = c.benchmark_group("jsonwebtoken");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    let bench_id = format!("jsonwebtoken-{}", name);
    let decoding_key_clone = decoding_key.clone();
    let validation_clone = validation.clone();
    let token_clone = token.to_string();

    group.bench_function(&bench_id, |b| {
        b.iter(|| {
            jsonwebtoken::decode::<serde_json::Value>(
                black_box(&token_clone),
                &decoding_key_clone,
                &validation_clone,
            )
            .unwrap();
        });
    });

    // Calculate throughput: run for fixed time and count iterations
    let start = std::time::Instant::now();
    let duration = Duration::from_secs(2);
    let mut count = 0u64;

    while start.elapsed() < duration {
        jsonwebtoken::decode::<serde_json::Value>(black_box(token), &decoding_key, &validation)
            .unwrap();
        count += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    count as f64 / elapsed
}

fn export_results(results: &[BenchmarkResult]) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/jwtiny
    path.pop(); // crates
    path.pop(); // jwtiny root
    path.push("stats.txt");

    let mut output = String::from("algorithm\tlibrary\tthroughput\n");

    for result in results {
        output.push_str(&format!(
            "{}\t{}\t{:.2}\n",
            result.scenario.name(),
            result.library,
            result.throughput
        ));
    }

    fs::write(&path, output).expect("Failed to write stats.txt");
    println!("Results exported to: {:?}", path);
}

criterion_group!(benches, run_benchmarks);
criterion_main!(benches);
