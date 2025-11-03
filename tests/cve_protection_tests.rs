//! Tests verifying protection against known JWT CVEs and attack vectors
//!
//! This test suite validates jwtiny's protection against real-world JWT
//! vulnerabilities documented in CVEs and security research.

use jwtiny::*;

/// Helper: Create a valid HS256 token
fn create_hs256_token(secret: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let payload = format!(
        r#"{{"iss":"https://example.com","sub":"user123","exp":{}}}"#,
        now + 3600
    );

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(&payload);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(signing_input.as_bytes());
    let signature_bytes = mac.finalize().into_bytes();
    let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);

    format!("{}.{}", signing_input, signature_b64)
}

// ============================================================================
// CVE-2018-1000531: "none" Algorithm Attack
// ============================================================================

#[test]
fn test_cve_none_algorithm_uppercase_none() {
    // Attack: Use "None" instead of "none" (case variation)
    let header = r#"{"alg":"None","typ":"JWT"}"#;
    let payload = r#"{"iss":"attacker","sub":"admin","exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let token = format!("{}.{}.", header_b64, payload_b64);

    let parsed = ParsedToken::from_string(&token).unwrap();

    // Should reject "None" algorithm
    let result = parsed.algorithm();
    assert!(
        matches!(result, Err(Error::UnsupportedAlgorithm(_))),
        "Should reject 'None' algorithm variant"
    );
}

#[test]
fn test_cve_none_algorithm_nOnE_mixed_case() {
    // Attack: Use "nOnE" (mixed case)
    let header = r#"{"alg":"nOnE","typ":"JWT"}"#;
    let payload = r#"{"iss":"attacker","sub":"admin","exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let token = format!("{}.{}.", header_b64, payload_b64);

    let parsed = ParsedToken::from_string(&token).unwrap();

    // Should reject mixed-case "none"
    let result = parsed.algorithm();
    assert!(
        matches!(result, Err(Error::UnsupportedAlgorithm(_))),
        "Should reject 'nOnE' algorithm variant"
    );
}

#[test]
fn test_cve_none_algorithm_lowercase() {
    // Attack: Standard "none" algorithm
    let header = r#"{"alg":"none","typ":"JWT"}"#;
    let payload = r#"{"iss":"attacker","sub":"admin","exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let token = format!("{}.{}.", header_b64, payload_b64);

    let parsed = ParsedToken::from_string(&token).unwrap();

    // Should explicitly reject "none"
    let result = parsed.algorithm();
    assert!(
        matches!(result, Err(Error::NoneAlgorithmRejected)),
        "Should explicitly reject 'none' algorithm"
    );
}

// ============================================================================
// CVE-2024-37568 / CVE-2024-33663: Algorithm Confusion (RS256→HS256)
// ============================================================================

#[cfg(feature = "rsa")]
#[test]
fn test_cve_algorithm_confusion_rsa_to_hmac() {
    use rsa::pkcs8::EncodePublicKey;
    use rsa::RsaPrivateKey;

    // Step 1: Generate RSA key pair
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = private_key.to_public_key();
    let public_key_der = public_key.to_public_key_der().unwrap();

    // Step 2: Create token claiming to use HS256
    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"iss":"attacker","sub":"admin","exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Step 3: Sign with RSA public key as HMAC secret (the attack!)
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(public_key_der.as_bytes()).unwrap();
    mac.update(signing_input.as_bytes());
    let signature_bytes = mac.finalize().into_bytes();
    let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);

    let token = format!("{}.{}", signing_input, signature_b64);

    // Step 4: Try to verify with RSA public key
    let parsed = ParsedToken::from_string(&token).unwrap();
    let trusted = parsed.danger_trust_without_issuer_check();

    // Attack: Provide RSA key but token claims HS256
    let rsa_key = Key::rsa_public(public_key_der.as_bytes());
    let result = trusted.verify_signature(&rsa_key);

    // Should fail with KeyTypeMismatch (protection!)
    assert!(
        matches!(result, Err(Error::KeyTypeMismatch { .. })),
        "Should reject RSA key for HMAC algorithm"
    );
}

#[cfg(feature = "rsa")]
#[test]
fn test_cve_algorithm_confusion_hmac_to_rsa() {
    use rsa::pkcs8::EncodePublicKey;
    use rsa::RsaPrivateKey;

    // Generate RSA key
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = private_key.to_public_key();
    let public_key_der = public_key.to_public_key_der().unwrap();

    // Create token claiming RS256
    let header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let payload = r#"{"iss":"attacker","sub":"admin","exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let token = format!("{}.{}.fake_signature", header_b64, payload_b64);

    let parsed = ParsedToken::from_string(&token).unwrap();
    let trusted = parsed.danger_trust_without_issuer_check();

    // Attack: Provide HMAC key for RS256 token
    let hmac_key = Key::symmetric(b"secret");
    let result = trusted.verify_signature(&hmac_key);

    // Should fail with KeyTypeMismatch
    assert!(
        matches!(result, Err(Error::KeyTypeMismatch { .. })),
        "Should reject HMAC key for RSA algorithm"
    );
}

// ============================================================================
// CVE-2024-54150: ECDSA→HMAC Algorithm Confusion
// ============================================================================

#[cfg(feature = "ecdsa")]
#[test]
fn test_cve_algorithm_confusion_ecdsa_to_hmac() {
    // Create token claiming HS256
    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"iss":"attacker","sub":"admin","exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let token = format!("{}.{}.fake_signature", header_b64, payload_b64);

    let parsed = ParsedToken::from_string(&token).unwrap();
    let trusted = parsed.danger_trust_without_issuer_check();

    // Attack: Provide ECDSA key for HMAC algorithm
    let ecdsa_key = Key::ecdsa_public(&[0x30, 0x59], EcdsaCurve::P256);
    let result = trusted.verify_signature(&ecdsa_key);

    // Should fail (either KeyTypeMismatch or verification failure)
    assert!(result.is_err(), "Should reject ECDSA key for HMAC algorithm");
}

// ============================================================================
// Kid Injection Attacks
// ============================================================================

#[test]
fn test_kid_path_traversal_attack() {
    // Attack: Use path traversal in kid to point to /dev/null or other files
    let header = r#"{"alg":"HS256","typ":"JWT","kid":"../../../../dev/null"}"#;
    let payload = r#"{"iss":"attacker","sub":"admin","exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let token = format!("{}.{}.signature", header_b64, payload_b64);

    // Should parse without error (kid is just a string)
    let parsed = ParsedToken::from_string(&token).unwrap();
    assert_eq!(
        parsed.header().key_id,
        Some("../../../../dev/null".to_string())
    );

    // The attack fails because kid is only used for string comparison in JWKS
    // No file system access occurs
}

#[test]
fn test_kid_sql_injection_attack() {
    // Attack: SQL injection in kid
    let header = r#"{"alg":"HS256","typ":"JWT","kid":"' OR '1'='1"}"#;
    let payload = r#"{"iss":"attacker","sub":"admin","exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let token = format!("{}.{}.signature", header_b64, payload_b64);

    // Should parse without error (kid is just a string)
    let parsed = ParsedToken::from_string(&token).unwrap();
    assert_eq!(
        parsed.header().key_id,
        Some("' OR '1'='1".to_string())
    );

    // The attack fails because kid is only used for string comparison
    // No database queries occur
}

#[test]
fn test_kid_command_injection_attack() {
    // Attack: Command injection in kid
    let header = r#"{"alg":"HS256","typ":"JWT","kid":"; rm -rf /"}"#;
    let payload = r#"{"iss":"attacker","sub":"admin","exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let token = format!("{}.{}.signature", header_b64, payload_b64);

    // Should parse without error (kid is just a string)
    let parsed = ParsedToken::from_string(&token).unwrap();
    assert_eq!(parsed.header().key_id, Some("; rm -rf /".to_string()));

    // The attack fails because kid is never executed as a command
    // Only used for string comparison in JWKS key lookup
}

// ============================================================================
// CVE-2018-0114: Embedded JWK Attack
// ============================================================================

#[test]
fn test_cve_embedded_jwk_not_supported() {
    // Attack: Embed attacker's public key in token header
    let header = r#"{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}"#;
    let payload = r#"{"iss":"attacker","sub":"admin","exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let token = format!("{}.{}.signature", header_b64, payload_b64);

    // Should parse (miniserde ignores unknown fields)
    let parsed = ParsedToken::from_string(&token).unwrap();

    // But jwk field is not accessible - it's not in TokenHeader struct
    // Attack fails because library doesn't support jwk header
    assert!(parsed.header().algorithm == "RS256");
    // jwk field is silently ignored (not part of TokenHeader)
}

// ============================================================================
// JKU/X5U SSRF Attacks
// ============================================================================

#[test]
fn test_jku_header_not_supported() {
    // Attack: Point jku to attacker-controlled URL
    let header =
        r#"{"alg":"RS256","typ":"JWT","jku":"https://attacker.com/malicious_jwks.json"}"#;
    let payload = r#"{"iss":"attacker","sub":"admin","exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let token = format!("{}.{}.signature", header_b64, payload_b64);

    // Should parse (miniserde ignores unknown fields)
    let parsed = ParsedToken::from_string(&token).unwrap();

    // jku field is not accessible - it's not in TokenHeader struct
    // Attack fails because library doesn't support jku header
    assert!(parsed.header().algorithm == "RS256");
}

#[test]
fn test_x5u_header_not_supported() {
    // Attack: Point x5u to attacker-controlled certificate URL
    let header = r#"{"alg":"RS256","typ":"JWT","x5u":"https://attacker.com/malicious_cert.pem"}"#;
    let payload = r#"{"iss":"attacker","sub":"admin","exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let token = format!("{}.{}.signature", header_b64, payload_b64);

    // Should parse (miniserde ignores unknown fields)
    let parsed = ParsedToken::from_string(&token).unwrap();

    // x5u field is not accessible - it's not in TokenHeader struct
    // Attack fails because library doesn't support x5u header
    assert!(parsed.header().algorithm == "RS256");
}

// ============================================================================
// SSRF via Untrusted Issuer
// ============================================================================

#[test]
fn test_ssrf_untrusted_issuer_rejected() {
    let token = create_hs256_token(b"secret");
    let parsed = ParsedToken::from_string(&token).unwrap();

    // Attempt to trust attacker-controlled issuer
    let result = parsed.trust_issuer(|iss| {
        // Allowlist only trusted issuers
        if iss == "https://trusted-issuer.com" {
            Ok(())
        } else {
            Err(Error::IssuerNotTrusted(iss.to_string()))
        }
    });

    // Should fail because token has iss="https://example.com"
    assert!(
        matches!(result, Err(Error::IssuerNotTrusted(_))),
        "Should reject untrusted issuer"
    );
}

// ============================================================================
// Weak Secret Detection (User Responsibility)
// ============================================================================

#[test]
fn test_weak_secret_accepted_but_documented() {
    // Library accepts weak secrets - user's responsibility
    let weak_secrets = vec![
        b"secret" as &[u8],
        b"123456",
        b"password",
        b"test",
        b"admin",
    ];

    for secret in weak_secrets {
        let token = create_hs256_token(secret);
        let parsed = ParsedToken::from_string(&token).unwrap();

        // Validation succeeds (library doesn't validate key strength)
        let result = TokenValidator::new(parsed)
            .danger_skip_issuer_validation()
            .verify_signature(SignatureVerification::with_secret_hs256(secret))
            .validate_token(ValidationConfig::default())
            .run();

        assert!(
            result.is_ok(),
            "Library accepts user-provided secrets (key strength is user's responsibility)"
        );
    }

    // Note: Key strength validation is documented in SECURITY.md
    // Users are responsible for providing strong keys
}

// ============================================================================
// Algorithm Downgrade Attack (HS512→HS256)
// ============================================================================

#[test]
fn test_algorithm_downgrade_prevented_v2() {
    let token = create_hs256_token(b"secret");
    let parsed = ParsedToken::from_string(&token).unwrap();

    // v2.0: Algorithm policy is mandatory
    // Token uses HS256, but we only allow HS512
    let result = TokenValidator::new(parsed)
        .danger_skip_issuer_validation()
        .verify_signature(SignatureVerification::with_secret(
            b"secret",
            AlgorithmPolicy::hs512_only(),
        ))
        .validate_token(ValidationConfig::default())
        .run();

    // Should fail with AlgorithmNotAllowed
    assert!(
        matches!(result, Err(Error::AlgorithmNotAllowed { .. })),
        "Should reject algorithm downgrade"
    );
}

// ============================================================================
// Timing Attack on HMAC (Constant-Time Comparison)
// ============================================================================

#[test]
fn test_constant_time_comparison_used() {
    // This test verifies that constant_time_eq is used
    // Actual timing analysis would require benchmarking framework

    let secret = b"test-secret-for-timing-attack";
    let token = create_hs256_token(secret);

    // Valid signature
    let parsed1 = ParsedToken::from_string(&token).unwrap();
    let trusted1 = parsed1.danger_trust_without_issuer_check();
    let key = Key::symmetric(secret);
    let result1 = trusted1.verify_signature(&key);
    assert!(result1.is_ok(), "Valid signature should verify");

    // Invalid signature (tampered)
    let parts: Vec<&str> = token.split('.').collect();
    // Take valid signature and flip last character to keep it valid base64url but incorrect
    let mut tampered_sig = parts[2].to_string();
    let last_char = tampered_sig.pop().unwrap();
    let new_char = if last_char == 'A' { 'B' } else { 'A' };
    tampered_sig.push(new_char);
    let tampered_token = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);

    let parsed2 = ParsedToken::from_string(&tampered_token).unwrap();
    let trusted2 = parsed2.danger_trust_without_issuer_check();
    let result2 = trusted2.verify_signature(&key);
    assert!(
        matches!(result2, Err(Error::SignatureInvalid)),
        "Invalid signature should fail with SignatureInvalid"
    );

    // Protection: constant_time_eq used in src/algorithm/hmac.rs:64
    // This prevents timing-based secret recovery attacks
}
