//! Custom header field preservation tests
//!
//! These tests verify that jwtiny correctly handles JWT headers with custom fields
//! beyond the standard "alg" and "typ" fields.
//!
//! JWT headers can contain additional fields like:
//! - kid (Key ID) - identifies which key was used
//! - jku (JWK Set URL) - URL for the key set
//! - jwk (JSON Web Key) - embedded public key
//! - x5u, x5c, x5t, x5t#S256 - X.509 certificate chain fields
//! - crit (Critical) - extensions that must be understood
//! - Custom application-specific fields
//!
//! Inspired by jsonwebtoken's custom header testing.

use jwtiny::*;

// ============================================================================
// Single Custom Header Field Tests
// ============================================================================

#[test]
fn test_header_with_kid() {
    // kid (Key ID) is a standard optional header field
    let header = r#"{"alg":"HS256","typ":"JWT","kid":"key-123"}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    // Parse token
    let parsed = ParsedToken::from_string(&token).expect("should parse token with kid");

    // Verify kid is accessible
    let header = parsed.header();
    assert_eq!(
        header.key_id.as_deref(),
        Some("key-123"),
        "Should preserve kid field"
    );
    assert_eq!(header.algorithm_str(), "HS256");
    assert_eq!(header.token_type.as_deref(), Some("JWT"));
}

#[test]
fn test_header_with_typ() {
    // typ (Type) field
    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let parsed = ParsedToken::from_string(&token).expect("should parse token with typ");
    let header = parsed.header();

    assert_eq!(header.token_type.as_deref(), Some("JWT"));
}

#[test]
fn test_header_without_optional_fields() {
    // Minimal header with only required alg field
    let header = r#"{"alg":"HS256"}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let parsed = ParsedToken::from_string(&token).expect("should parse minimal header");
    let header = parsed.header();

    assert_eq!(header.algorithm_str(), "HS256");
    assert_eq!(
        header.token_type, None,
        "typ should be None when not present"
    );
    assert_eq!(header.key_id, None, "kid should be None when not present");
}

// ============================================================================
// Multiple Custom Header Fields Tests
// ============================================================================

#[test]
fn test_header_with_multiple_standard_fields() {
    // Header with alg, typ, and kid
    let header = r#"{"alg":"RS256","typ":"JWT","kid":"2024-key-001"}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let parsed = ParsedToken::from_string(&token).expect("should parse");
    let header = parsed.header();

    assert_eq!(header.algorithm_str(), "RS256");
    assert_eq!(header.token_type.as_deref(), Some("JWT"));
    assert_eq!(header.key_id.as_deref(), Some("2024-key-001"));
}

#[test]
fn test_header_with_unknown_fields_ignored() {
    // JWT spec allows headers to have additional fields
    // Our parser should ignore unknown fields (using miniserde's behavior)
    let header = r#"{"alg":"HS256","typ":"JWT","kid":"key-1","custom":"value","app_data":"test"}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    // Should parse successfully, ignoring unknown fields
    let parsed = ParsedToken::from_string(&token).expect("should parse with unknown fields");
    let header = parsed.header();

    // Known fields should be preserved
    assert_eq!(header.algorithm_str(), "HS256");
    assert_eq!(header.token_type.as_deref(), Some("JWT"));
    assert_eq!(header.key_id.as_deref(), Some("key-1"));

    // Note: Unknown fields are not accessible through TokenHeader struct
    // This is expected behavior - we only expose standard fields
}

// ============================================================================
// Header Field Order Tests
// ============================================================================

#[test]
fn test_header_field_order_invariant() {
    // JSON object field order shouldn't matter
    let header1 = r#"{"alg":"HS256","typ":"JWT","kid":"key-1"}"#;
    let header2 = r#"{"kid":"key-1","typ":"JWT","alg":"HS256"}"#;
    let header3 = r#"{"typ":"JWT","kid":"key-1","alg":"HS256"}"#;

    let headers = vec![header1, header2, header3];

    for header_json in headers {
        let header_b64 = jwtiny::utils::base64url::encode(header_json);
        let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
        let sig_b64 = jwtiny::utils::base64url::encode("sig");
        let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

        let parsed =
            ParsedToken::from_string(&token).expect("should parse regardless of field order");
        let header = parsed.header();

        // All should produce the same result
        assert_eq!(header.algorithm_str(), "HS256");
        assert_eq!(header.token_type.as_deref(), Some("JWT"));
        assert_eq!(header.key_id.as_deref(), Some("key-1"));
    }
}

// ============================================================================
// Special Header Values Tests
// ============================================================================

#[test]
fn test_header_with_empty_kid() {
    // kid with empty string value
    let header = r#"{"alg":"HS256","kid":""}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let parsed = ParsedToken::from_string(&token).expect("should parse with empty kid");
    let header = parsed.header();

    // Empty string should be preserved
    assert_eq!(header.key_id.as_deref(), Some(""));
}

#[test]
fn test_header_with_numeric_kid() {
    // kid can be any string, including numeric strings
    let header = r#"{"alg":"HS256","kid":"12345"}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let parsed = ParsedToken::from_string(&token).expect("should parse with numeric kid");
    let header = parsed.header();

    assert_eq!(header.key_id.as_deref(), Some("12345"));
}

#[test]
fn test_header_with_special_characters_in_kid() {
    // kid can contain special characters
    let header = r#"{"alg":"HS256","kid":"key:2024-01@prod"}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let parsed = ParsedToken::from_string(&token).expect("should parse with special chars in kid");
    let header = parsed.header();

    assert_eq!(header.key_id.as_deref(), Some("key:2024-01@prod"));
}

#[test]
fn test_header_with_unicode_in_kid() {
    // kid can contain Unicode characters
    let header = r#"{"alg":"HS256","kid":"密鑰-2024"}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let parsed = ParsedToken::from_string(&token).expect("should parse with unicode kid");
    let header = parsed.header();

    assert_eq!(header.key_id.as_deref(), Some("密鑰-2024"));
}

// ============================================================================
// typ (Type) Header Variations
// ============================================================================

#[test]
fn test_header_typ_variations() {
    // typ can have different values
    let variations = vec![
        ("JWT", "Standard JWT type"),
        ("application/jwt", "JOSE media type"),
        ("JOSE", "Alternative type"),
        ("custom", "Custom type"),
    ];

    for (typ_value, description) in variations {
        let header = format!(r#"{{"alg":"HS256","typ":"{}"}}"#, typ_value);
        let header_b64 = jwtiny::utils::base64url::encode(&header);
        let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
        let sig_b64 = jwtiny::utils::base64url::encode("sig");

        let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

        let parsed = ParsedToken::from_string(&token)
            .unwrap_or_else(|_| panic!("should parse with typ={} ({})", typ_value, description));
        let header = parsed.header();

        assert_eq!(
            header.token_type.as_deref(),
            Some(typ_value),
            "{}",
            description
        );
    }
}

// ============================================================================
// Header Whitespace Handling
// ============================================================================

#[test]
fn test_header_with_whitespace() {
    // JSON can have whitespace which should be handled correctly
    let header_with_spaces = r#"{
        "alg": "HS256",
        "typ": "JWT",
        "kid": "key-1"
    }"#;

    let header_b64 = jwtiny::utils::base64url::encode(header_with_spaces);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let parsed = ParsedToken::from_string(&token).expect("should parse with whitespace");
    let header = parsed.header();

    assert_eq!(header.algorithm_str(), "HS256");
    assert_eq!(header.token_type.as_deref(), Some("JWT"));
    assert_eq!(header.key_id.as_deref(), Some("key-1"));
}

// ============================================================================
// Real-World Header Examples
// ============================================================================

#[test]
fn test_auth0_style_header() {
    // Auth0-style JWT header
    let header = r#"{"alg":"RS256","typ":"JWT","kid":"MjExODU5NTYyMjU1NTAzNzg1Nw"}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"https://example.auth0.com/"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let parsed = ParsedToken::from_string(&token).expect("should parse Auth0-style header");
    let header = parsed.header();

    assert_eq!(header.algorithm_str(), "RS256");
    assert_eq!(header.token_type.as_deref(), Some("JWT"));
    assert_eq!(header.key_id.as_deref(), Some("MjExODU5NTYyMjU1NTAzNzg1Nw"));
}

#[test]
fn test_google_style_header() {
    // Google-style JWT header
    let header = r#"{"alg":"RS256","kid":"a1b2c3d4e5f6","typ":"JWT"}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"https://accounts.google.com"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let parsed = ParsedToken::from_string(&token).expect("should parse Google-style header");
    let header = parsed.header();

    assert_eq!(header.algorithm_str(), "RS256");
    assert_eq!(header.key_id.as_deref(), Some("a1b2c3d4e5f6"));
}

#[test]
fn test_aws_cognito_style_header() {
    // AWS Cognito-style JWT header
    let header = r#"{"kid":"abcdefghijklmnopqrstuv1234567890","alg":"RS256"}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(
        r#"{"iss":"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE"}"#,
    );
    let sig_b64 = jwtiny::utils::base64url::encode("sig");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let parsed = ParsedToken::from_string(&token).expect("should parse AWS Cognito-style header");
    let header = parsed.header();

    assert_eq!(header.algorithm_str(), "RS256");
    assert_eq!(
        header.key_id.as_deref(),
        Some("abcdefghijklmnopqrstuv1234567890")
    );
}

// ============================================================================
// Header-Only Parsing Tests
// ============================================================================

#[test]
fn test_parse_header_without_full_validation() {
    // Should be able to parse and access header without verifying signature
    let header = r#"{"alg":"RS256","kid":"key-123","typ":"JWT"}"#;
    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(r#"{"iss":"test"}"#);
    let sig_b64 = jwtiny::utils::base64url::encode("invalid-signature");

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    // Parsing should succeed even with invalid signature
    let parsed = ParsedToken::from_string(&token).expect("should parse");
    let header = parsed.header();

    // Header fields should be accessible before verification
    assert_eq!(header.algorithm_str(), "RS256");
    assert_eq!(header.key_id.as_deref(), Some("key-123"));

    // This allows looking up the correct key based on kid before verification
}

// ============================================================================
// Documentation Examples
// ============================================================================

/// Example: Using kid to select verification key
///
/// ```ignore
/// use jwtiny::*;
///
/// fn verify_with_key_rotation(token_str: &str, keys: &HashMap<String, Vec<u8>>) -> Result<Token, Error> {
///     // Parse token to get header
///     let parsed = ParsedToken::from_string(token_str)?;
///
///     // Extract kid from header
///     let kid = parsed.header().key_id.as_deref()
///         .ok_or(Error::InvalidFormat)?;
///
///     // Look up the correct key
///     let key_der = keys.get(kid)
///         .ok_or(Error::InvalidFormat)?;
///
///     // Verify with the correct key
///     TokenValidator::new(parsed)
///         .ensure_issuer(|iss| Ok(iss == "https://trusted.com"))
///         .verify_signature(SignatureVerification::with_key(
///             Key::rsa_public(key_der)
///         ))
///         .validate_token(ValidationConfig::default())
///         .run()
/// }
/// ```
#[allow(dead_code)]
fn example_kid_based_key_selection() {}
