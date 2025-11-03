use jwtiny::*;

// Multi-audience array should not deserialize into current Claims (String audience)
#[test]
fn audience_array_is_rejected() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"iss":"test","sub":"user","aud":["a","b"],"exp":9999999999}"#;

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(payload);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let secret = b"secret";
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(signing_input.as_bytes());
    let sig_b64 = jwtiny::utils::base64url::encode_bytes(&mac.finalize().into_bytes());

    let token = format!("{}.{}", signing_input, sig_b64);
    let parsed = ParsedToken::from_string(&token).unwrap();
    let trusted = parsed.danger_trust_without_issuer_check();
    let key = Key::symmetric(secret);
    let verified = trusted.verify_signature(&key).unwrap();

    // Claims parsing should fail due to audience type mismatch
    let result = verified.validate(&ValidationConfig::default());
    assert!(matches!(result, Err(Error::InvalidJson(_))));
}

// Pathological Base64URL input should return InvalidBase64
#[test]
fn invalid_base64url_segments_are_rejected() {
    // invalid header (contains '!')
    let token = "!!!.abc.def";
    let result = ParsedToken::from_string(token);
    assert!(matches!(result, Err(Error::InvalidBase64(_))));
}

// Extreme clock skew boundary check for nbf
#[test]
fn extreme_clock_skew_boundary_nbf() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload_future = format!(r#"{{"iss":"test","nbf":{}}}"#, now + 600);

    let header_b64 = jwtiny::utils::base64url::encode(header);
    let payload_b64 = jwtiny::utils::base64url::encode(&payload_future);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let secret = b"secret";
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(signing_input.as_bytes());
    let sig_b64 = jwtiny::utils::base64url::encode_bytes(&mac.finalize().into_bytes());
    let token = format!("{}.{}", signing_input, sig_b64);

    let parsed = ParsedToken::from_string(&token).unwrap();
    let trusted = parsed.danger_trust_without_issuer_check();
    let key = Key::symmetric(secret);
    let verified = trusted.verify_signature(&key).unwrap();

    // With zero skew, should fail (nbf in future)
    let cfg_fail = ValidationConfig::default().clock_skew(0);
    assert!(matches!(
        verified.validate(&cfg_fail),
        Err(Error::ClaimValidationFailed(_))
    ));

    // Recreate verified and validate with 600s skew, should pass
    let mut mac2 = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac2.update(signing_input.as_bytes());
    let sig_b64_2 = jwtiny::utils::base64url::encode_bytes(&mac2.finalize().into_bytes());
    let token2 = format!("{}.{}", signing_input, sig_b64_2);
    let parsed2 = ParsedToken::from_string(&token2).unwrap();
    let trusted2 = parsed2.danger_trust_without_issuer_check();
    let verified2 = trusted2.verify_signature(&key).unwrap();
    let cfg_ok = ValidationConfig::default().clock_skew(600);
    assert!(verified2.validate(&cfg_ok).is_ok());
}
