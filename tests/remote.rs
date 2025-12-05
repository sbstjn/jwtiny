use std::time::Duration;

use jwtiny::{AlgorithmPolicy, ClaimsValidation, RemoteCacheKey, TokenValidator, claims};
use moka::future::Cache;
use serde_json::json;

async fn generate_token_via_jwkserve(
    base_url: &str,
    claims: serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let url = format!("{base_url}/sign/RS512");

    let json_body = serde_json::to_string(&claims)?;
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(json_body)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("HTTP error: {}", response.status()).into());
    }

    let body = response.text().await?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    let token = json
        .get("token")
        .and_then(|t| t.as_str())
        .ok_or("Missing token in response")?;

    Ok(token.to_string())
}

#[tokio::test]
async fn test_remote_machine() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let iat = now - 60;
    let exp = now + 60;
    let nbf = now;

    let token_str = generate_token_via_jwkserve(
        "http://localhost:3000",
        json!({
            "aud": "my-app",
            "exp": exp,
            "iat": iat,
            "nbf": nbf,
            "sub": "user-12345"
        }),
    )
    .await
    .expect("Failed to generate token");

    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let client = reqwest::Client::new();

    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::rs512_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .cache(cache)
        .jwks(client);

    let result = validator.verify(&token_str).await;

    assert!(
        result.is_ok(),
        "Failed to validate token: {}",
        result.err().unwrap()
    );
}

#[claims]
struct CustomClaims {
    #[serde(rename = "email")]
    pub email: Option<String>,
    #[serde(rename = "role")]
    pub role: Option<String>,
    #[serde(rename = "permission_list")]
    pub permissions: Option<Vec<String>>,
}

#[tokio::test]
async fn test_remote_machine_with_custom_claims() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let iat = now - 60;
    let exp = now + 60;
    let nbf = now;

    let token_str = generate_token_via_jwkserve(
        "http://localhost:3000",
        json!( {
            "aud": "my-app",
            "exp": exp,
            "iat": iat,
            "nbf": nbf,
            "sub": "user-12345",
            "email": "user@example.com",
            "role": "admin",
            "permission_list": ["read", "write", "delete"]
        }),
    )
    .await
    .expect("Failed to generate token");

    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let client = reqwest::Client::new();

    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::rs512_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .cache(cache)
        .jwks(client);

    let result = validator.verify_with_custom::<CustomClaims>(&token_str).await;

    assert!(
        result.is_ok(),
        "Failed to validate token: {}",
        result.err().unwrap()
    );

    let claims = result.unwrap();
    assert_eq!(claims.email, Some("user@example.com".to_string()));
    assert_eq!(claims.role, Some("admin".to_string()));
    assert_eq!(
        claims.permissions,
        Some(vec![
            "read".to_string(),
            "write".to_string(),
            "delete".to_string()
        ])
    );
    assert_eq!(claims.subject.as_deref(), Some("user-12345"));
}
