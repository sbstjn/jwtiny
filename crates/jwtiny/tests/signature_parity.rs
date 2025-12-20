//! Signature validation parity tests between jwtiny and jsonwebtoken
//!
//! These tests ensure both libraries handle signature validation identically
//! across all supported algorithms (RS256/384/512, ES256/384/512).

mod parity;

use parity::token_gen::{Algorithm, TokenBuilder};
use parity::validators::{
    create_jsonwebtoken_validator, create_jwtiny_validator, is_jsonwebtoken_supported,
    to_jsonwebtoken_algorithm, to_jwtiny_policy,
};
use parity::{assert_both_succeed, assert_parity, run_parity_test};

const BASE_URL: &str = "http://localhost:3000";

/// Test valid signature for a specific algorithm
async fn test_valid_signature_for_algorithm(algorithm: Algorithm) {
    // Skip if jsonwebtoken doesn't support this algorithm
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

/// Test corrupted signature for a specific algorithm
async fn test_corrupted_signature_for_algorithm(algorithm: Algorithm) {
    // Skip if jsonwebtoken doesn't support this algorithm
    if !is_jsonwebtoken_supported(algorithm) {
        eprintln!("SKIPPED: {algorithm:?} not supported by jsonwebtoken");
        return;
    }

    let token = TokenBuilder::new(BASE_URL, algorithm)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate token");

    let corrupted = parity::token_gen::corrupt_signature(&token);

    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(algorithm));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(algorithm).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&corrupted, &jwtiny_validator, &jsonwebtoken_validator).await;

    // Both should reject with InvalidSignature or InvalidFormat
    // (Corrupted base64 might fail at different stages)
    assert_parity(&result);
}

/// Test missing signature for a specific algorithm
async fn test_missing_signature_for_algorithm(algorithm: Algorithm) {
    // Skip if jsonwebtoken doesn't support this algorithm
    if !is_jsonwebtoken_supported(algorithm) {
        eprintln!("SKIPPED: {algorithm:?} not supported by jsonwebtoken");
        return;
    }

    let token = TokenBuilder::new(BASE_URL, algorithm)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate token");

    let no_sig = parity::token_gen::remove_signature(&token);

    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(algorithm));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(algorithm).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&no_sig, &jwtiny_validator, &jsonwebtoken_validator).await;

    // Both should fail with InvalidFormat
    assert_parity(&result);
}

/// Test empty signature for a specific algorithm
async fn test_empty_signature_for_algorithm(algorithm: Algorithm) {
    // Skip if jsonwebtoken doesn't support this algorithm
    if !is_jsonwebtoken_supported(algorithm) {
        eprintln!("SKIPPED: {algorithm:?} not supported by jsonwebtoken");
        return;
    }

    let token = TokenBuilder::new(BASE_URL, algorithm)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate token");

    let empty_sig = parity::token_gen::empty_signature(&token);

    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(algorithm));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(algorithm).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&empty_sig, &jwtiny_validator, &jsonwebtoken_validator).await;

    // Both should fail
    assert_parity(&result);
}

// ============================================================================
// RS256 Tests
// ============================================================================

#[tokio::test]
async fn test_rs256_valid_signature() {
    test_valid_signature_for_algorithm(Algorithm::RS256).await;
}

#[tokio::test]
async fn test_rs256_corrupted_signature() {
    test_corrupted_signature_for_algorithm(Algorithm::RS256).await;
}

#[tokio::test]
async fn test_rs256_missing_signature() {
    test_missing_signature_for_algorithm(Algorithm::RS256).await;
}

#[tokio::test]
async fn test_rs256_empty_signature() {
    test_empty_signature_for_algorithm(Algorithm::RS256).await;
}

#[tokio::test]
async fn test_rs256_with_custom_claims() {
    let token = TokenBuilder::new(BASE_URL, Algorithm::RS256)
        .standard_valid_claims()
        .custom_claim("email", serde_json::json!("user@example.com"))
        .custom_claim("role", serde_json::json!("admin"))
        .generate()
        .await
        .expect("Failed to generate token");

    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(Algorithm::RS256));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(Algorithm::RS256).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&token, &jwtiny_validator, &jsonwebtoken_validator).await;
    assert_both_succeed(&result);
}

// ============================================================================
// RS384 Tests
// ============================================================================

#[tokio::test]
async fn test_rs384_valid_signature() {
    test_valid_signature_for_algorithm(Algorithm::RS384).await;
}

#[tokio::test]
async fn test_rs384_corrupted_signature() {
    test_corrupted_signature_for_algorithm(Algorithm::RS384).await;
}

#[tokio::test]
async fn test_rs384_missing_signature() {
    test_missing_signature_for_algorithm(Algorithm::RS384).await;
}

#[tokio::test]
async fn test_rs384_empty_signature() {
    test_empty_signature_for_algorithm(Algorithm::RS384).await;
}

#[tokio::test]
async fn test_rs384_with_custom_claims() {
    let token = TokenBuilder::new(BASE_URL, Algorithm::RS384)
        .standard_valid_claims()
        .custom_claim("department", serde_json::json!("engineering"))
        .generate()
        .await
        .expect("Failed to generate token");

    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(Algorithm::RS384));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(Algorithm::RS384).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&token, &jwtiny_validator, &jsonwebtoken_validator).await;
    assert_both_succeed(&result);
}

// ============================================================================
// RS512 Tests
// ============================================================================

#[tokio::test]
async fn test_rs512_valid_signature() {
    test_valid_signature_for_algorithm(Algorithm::RS512).await;
}

#[tokio::test]
async fn test_rs512_corrupted_signature() {
    test_corrupted_signature_for_algorithm(Algorithm::RS512).await;
}

#[tokio::test]
async fn test_rs512_missing_signature() {
    test_missing_signature_for_algorithm(Algorithm::RS512).await;
}

#[tokio::test]
async fn test_rs512_empty_signature() {
    test_empty_signature_for_algorithm(Algorithm::RS512).await;
}

#[tokio::test]
async fn test_rs512_with_all_standard_claims() {
    let now = parity::token_gen::now();

    let token = TokenBuilder::new(BASE_URL, Algorithm::RS512)
        .issuer(BASE_URL)
        .subject("test-user-123")
        .audience("test-app")
        .issued_at(now - 60)
        .not_before(now - 60)
        .expiration(now + 3600)
        .generate()
        .await
        .expect("Failed to generate token");

    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(Algorithm::RS512));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(Algorithm::RS512).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&token, &jwtiny_validator, &jsonwebtoken_validator).await;
    assert_both_succeed(&result);
}

// ============================================================================
// ES256 Tests
// ============================================================================

#[tokio::test]
async fn test_es256_valid_signature() {
    test_valid_signature_for_algorithm(Algorithm::ES256).await;
}

#[tokio::test]
async fn test_es256_corrupted_signature() {
    test_corrupted_signature_for_algorithm(Algorithm::ES256).await;
}

#[tokio::test]
async fn test_es256_missing_signature() {
    test_missing_signature_for_algorithm(Algorithm::ES256).await;
}

#[tokio::test]
async fn test_es256_empty_signature() {
    test_empty_signature_for_algorithm(Algorithm::ES256).await;
}

#[tokio::test]
async fn test_es256_with_custom_claims() {
    let token = TokenBuilder::new(BASE_URL, Algorithm::ES256)
        .standard_valid_claims()
        .custom_claim("scope", serde_json::json!("read write"))
        .generate()
        .await
        .expect("Failed to generate token");

    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(Algorithm::ES256));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(Algorithm::ES256).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&token, &jwtiny_validator, &jsonwebtoken_validator).await;
    assert_both_succeed(&result);
}

// ============================================================================
// ES384 Tests
// ============================================================================

#[tokio::test]
async fn test_es384_valid_signature() {
    test_valid_signature_for_algorithm(Algorithm::ES384).await;
}

#[tokio::test]
async fn test_es384_corrupted_signature() {
    test_corrupted_signature_for_algorithm(Algorithm::ES384).await;
}

#[tokio::test]
async fn test_es384_missing_signature() {
    test_missing_signature_for_algorithm(Algorithm::ES384).await;
}

#[tokio::test]
async fn test_es384_empty_signature() {
    test_empty_signature_for_algorithm(Algorithm::ES384).await;
}

#[tokio::test]
async fn test_es384_with_custom_claims() {
    let token = TokenBuilder::new(BASE_URL, Algorithm::ES384)
        .standard_valid_claims()
        .custom_claim("tenant_id", serde_json::json!("acme-corp"))
        .generate()
        .await
        .expect("Failed to generate token");

    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(Algorithm::ES384));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(Algorithm::ES384).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&token, &jwtiny_validator, &jsonwebtoken_validator).await;
    assert_both_succeed(&result);
}

// ============================================================================
// ES512 Tests - SKIPPED
// ============================================================================
// Note: ES512 (P-521 curve) is not supported by jsonwebtoken/ring.
// These tests are skipped automatically when running parity tests.
// ES512 is still tested in jwtiny's own test suite (remote.rs).

#[tokio::test]
async fn test_es512_valid_signature() {
    // ES512 not supported by jsonwebtoken - test skipped
    test_valid_signature_for_algorithm(Algorithm::ES512).await;
}

#[tokio::test]
async fn test_es512_corrupted_signature() {
    // ES512 not supported by jsonwebtoken - test skipped
    test_corrupted_signature_for_algorithm(Algorithm::ES512).await;
}

#[tokio::test]
async fn test_es512_missing_signature() {
    // ES512 not supported by jsonwebtoken - test skipped
    test_missing_signature_for_algorithm(Algorithm::ES512).await;
}

#[tokio::test]
async fn test_es512_empty_signature() {
    // ES512 not supported by jsonwebtoken - test skipped
    test_empty_signature_for_algorithm(Algorithm::ES512).await;
}

// ============================================================================
// Cross-Algorithm Tests
// ============================================================================

#[tokio::test]
async fn test_algorithm_mismatch_rs256_token_with_es256_validator() {
    // Generate RS256 token
    let token = TokenBuilder::new(BASE_URL, Algorithm::RS256)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate RS256 token");

    // Validate with ES256 policy (should fail)
    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(Algorithm::ES256));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(Algorithm::ES256).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&token, &jwtiny_validator, &jsonwebtoken_validator).await;

    // Both should fail (jwtiny: AlgorithmNotAllowed, jsonwebtoken: NetworkError or InvalidSignature)
    // Different failure modes are acceptable - both correctly reject the token
    assert!(
        result.jwtiny_outcome != parity::ValidationOutcome::Success,
        "jwtiny should reject algorithm mismatch"
    );
    assert!(
        result.jsonwebtoken_outcome != parity::ValidationOutcome::Success,
        "jsonwebtoken should reject algorithm mismatch"
    );
}

#[tokio::test]
async fn test_algorithm_mismatch_es384_token_with_rs384_validator() {
    // Generate ES384 token
    let token = TokenBuilder::new(BASE_URL, Algorithm::ES384)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate ES384 token");

    // Validate with RS384 policy (should fail)
    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(Algorithm::RS384));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(Algorithm::RS384).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&token, &jwtiny_validator, &jsonwebtoken_validator).await;

    // Both should fail (jwtiny: AlgorithmNotAllowed, jsonwebtoken: NetworkError or InvalidSignature)
    // Different failure modes are acceptable - both correctly reject the token
    assert!(
        result.jwtiny_outcome != parity::ValidationOutcome::Success,
        "jwtiny should reject algorithm mismatch"
    );
    assert!(
        result.jsonwebtoken_outcome != parity::ValidationOutcome::Success,
        "jsonwebtoken should reject algorithm mismatch"
    );
}

// ============================================================================
// Malformed Token Tests
// ============================================================================

#[tokio::test]
async fn test_malformed_base64_in_signature() {
    let token = TokenBuilder::new(BASE_URL, Algorithm::RS256)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate token");

    // Replace signature with invalid base64 (contains invalid chars)
    let parts: Vec<&str> = token.split('.').collect();
    let malformed = format!("{}.{}.invalid@@@base64!!!", parts[0], parts[1]);

    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(Algorithm::RS256));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(Algorithm::RS256).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&malformed, &jwtiny_validator, &jsonwebtoken_validator).await;

    // Both should fail with InvalidFormat or InvalidSignature
    assert_parity(&result);
}

#[tokio::test]
async fn test_too_many_segments() {
    let token = TokenBuilder::new(BASE_URL, Algorithm::RS256)
        .standard_valid_claims()
        .generate()
        .await
        .expect("Failed to generate token");

    // Add extra segment
    let malformed = format!("{token}.extra");

    let jwtiny_validator = create_jwtiny_validator(BASE_URL, to_jwtiny_policy(Algorithm::RS256));
    let jsonwebtoken_alg = to_jsonwebtoken_algorithm(Algorithm::RS256).unwrap();
    let jsonwebtoken_validator = create_jsonwebtoken_validator(BASE_URL, jsonwebtoken_alg);

    let result = run_parity_test(&malformed, &jwtiny_validator, &jsonwebtoken_validator).await;

    // Both should fail with InvalidFormat
    assert_parity(&result);
}

// ============================================================================
// Summary Test - Run all algorithms
// ============================================================================

#[tokio::test]
async fn test_all_algorithms_valid_signatures() {
    for algorithm in Algorithm::all() {
        eprintln!("Testing {algorithm:?} valid signature...");
        test_valid_signature_for_algorithm(algorithm).await;
    }
}

#[tokio::test]
async fn test_all_algorithms_corrupted_signatures() {
    for algorithm in Algorithm::all() {
        eprintln!("Testing {algorithm:?} corrupted signature...");
        test_corrupted_signature_for_algorithm(algorithm).await;
    }
}
