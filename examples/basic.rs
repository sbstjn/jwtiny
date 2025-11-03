//! Basic example demonstrating the builder pattern API
//!
//! This example demonstrates the `TokenValidator` builder pattern for JWT validation:
//! 1. Parse the token string into a `ParsedToken`
//! 2. Configure validation steps (issuer validation, signature verification, claims validation)
//! 3. Execute the validation pipeline atomically via `.run()`
//! 4. Access the fully validated `Token` and its claims

use jwtiny::*;

fn main() -> Result<()> {
    println!("=== jwtiny - Basic Example ===\n");

    // In a real application, you would receive this token from a client
    let token_string = create_sample_token();
    println!("Token: {}\n", token_string);

    // Step 1: Parse the token
    println!("Step 1: Parsing token...");
    let parsed = ParsedToken::from_string(&token_string)?;
    println!("  ✓ Algorithm: {}", parsed.header().algorithm_str());
    println!("  ✓ Token type: {:?}\n", parsed.header().token_type);

    // Step 2-5: Build validation pipeline and run
    println!("Step 2: Building validation pipeline...");

    let token = TokenValidator::new(parsed)
        // Validate issuer (prevents SSRF attacks)
        .ensure_issuer(|iss| {
            println!("  → Validating issuer: {}", iss);
            if iss == "https://example.com" {
                println!("  ✓ Issuer is trusted");
                Ok(())
            } else {
                Err(Error::IssuerNotTrusted(iss.to_string()))
            }
        })
        // Configure signature verification
        .verify_signature(SignatureVerification::with_secret_hs256(
            b"your-256-bit-secret-key-here!",
        ))
        // Configure claims validation
        .validate_token(
            ValidationConfig::default()
                .clock_skew(60) // Allow 60 seconds of clock skew
                .max_age(86400) // Token must be less than 24 hours old
                .no_iat_validation(), // Skip iat validation for this example
        )
        // Execute validation pipeline
        .run()?;

    println!("  ✓ Signature verified");
    println!("  ✓ Claims validated\n");

    // Access the validated claims
    println!("=== Validated Token Data ===");
    println!("Algorithm: {}", token.algorithm());
    println!("Issuer: {:?}", token.issuer());
    println!("Subject: {:?}", token.subject());
    println!("Expires at: {:?}", token.expiration());
    println!("Issued at: {:?}", token.issued_at());

    println!("\n✅ Token is fully validated and safe to use!");

    Ok(())
}

/// Helper function to create a sample JWT token
fn create_sample_token() -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;

    // Create a token that expires in 1 hour
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

    // Sign with HMAC-SHA256
    let secret = b"your-256-bit-secret-key-here!";
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(signing_input.as_bytes());
    let signature_bytes = mac.finalize().into_bytes();
    let signature_b64 = jwtiny::utils::base64url::encode_bytes(&signature_bytes);

    format!("{}.{}", signing_input, signature_b64)
}
