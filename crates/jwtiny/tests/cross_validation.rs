//! Cross-validation smoke tests between jwtiny and jsonwebtoken
//!
//! These tests serve as high-level integration tests to ensure basic
//! compatibility between both libraries. For comprehensive signature
//! validation testing, see signature_parity.rs.

mod parity;

use parity::token_gen::{Algorithm, TokenBuilder};
use parity::validators::{
    create_jsonwebtoken_validator, create_jwtiny_validator, is_jsonwebtoken_supported,
    to_jsonwebtoken_algorithm, to_jwtiny_policy,
};
use parity::{assert_both_succeed, run_parity_test};

const BASE_URL: &str = "http://localhost:3000";

/// Helper to run a basic smoke test for an algorithm
async fn smoke_test_algorithm(algorithm: Algorithm) {
    // Skip if jsonwebtoken doesn't support this algorithm (e.g., ES512)
    if !is_jsonwebtoken_supported(algorithm) {
        eprintln!("SKIPPED: {algorithm:?} not supported by jsonwebtoken");
        return;
    }

    let token = TokenBuilder::new(BASE_URL, algorithm)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate token");

    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(algorithm));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(algorithm).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&token, &jwtiny_validator, &jsonwebtoken_validator).await;
    assert_both_succeed(&result);
}

#[tokio::test]
async fn test_cross_validate_rs256() {
    smoke_test_algorithm(Algorithm::RS256).await;
}

#[tokio::test]
async fn test_cross_validate_rs384() {
    smoke_test_algorithm(Algorithm::RS384).await;
}

#[tokio::test]
async fn test_cross_validate_rs512() {
    smoke_test_algorithm(Algorithm::RS512).await;
}

#[tokio::test]
async fn test_cross_validate_es256() {
    smoke_test_algorithm(Algorithm::ES256).await;
}

#[tokio::test]
async fn test_cross_validate_es384() {
    smoke_test_algorithm(Algorithm::ES384).await;
}

#[tokio::test]
async fn test_cross_validate_es512() {
    // ES512 not supported by jsonwebtoken - test skipped
    smoke_test_algorithm(Algorithm::ES512).await;
}

/// Test that all algorithms work in a single test run
#[tokio::test]
async fn test_all_algorithms_smoke() {
    for algorithm in Algorithm::all() {
        eprintln!("Smoke testing {algorithm:?}...");
        smoke_test_algorithm(algorithm).await;
    }
}
