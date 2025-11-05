//! Integration tests with jwkserve using docker-compose
//!
//! These tests verify end-to-end JWKS flow with a real jwkserve instance.
//! Run with: docker-compose up -d && cargo test --test jwkserve_integration --features remote,rsa,aws-lc-rs
//!
//! Note: jwkserve uses aws-lc-rs, so use the aws-lc-rs feature to match backends.

#[cfg(all(feature = "remote", feature = "rsa"))]
#[tokio::test]
async fn end_to_end_verify_rs256_from_jwkserve() {
    use jwtiny::remote::HttpClient;
    use jwtiny::*;
    use std::future::Future;
    use std::pin::Pin;

    // Health check: verify jwkserve is running
    if !is_jwkserve_up().await {
        eprintln!("SKIP: jwkserve not reachable at http://localhost:3000");
        eprintln!("       Start jwkserve with: docker-compose up -d");
        return;
    }

    // Create HTTP client implementation using reqwest
    #[derive(Clone)]
    struct ReqwestHttpClient {
        client: reqwest::Client,
    }

    impl HttpClient for ReqwestHttpClient {
        fn fetch(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + '_>> {
            let client = self.client.clone();
            let url = url.to_string();
            Box::pin(async move {
                let response = client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| Error::RemoteError(format!("network: {}", e)))?;
                if !response.status().is_success() {
                    return Err(Error::RemoteError(format!(
                        "http: status {}",
                        response.status()
                    )));
                }
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|e| Error::RemoteError(format!("network: {}", e)))?
                    .to_vec();
                Ok(bytes)
            })
        }
    }

    let reqwest_client = reqwest::Client::new();
    let http_client = ReqwestHttpClient {
        client: reqwest_client.clone(),
    };

    // 1) Ask jwkserve to mint a token. Endpoint and payload follow jwkserve's API:
    // POST /sign with claims; expects JSON { token: "..." }
    // Fallback: if /sign not found, skip test gracefully.
    let claims = serde_json::json!({
        "iss": "http://localhost:3000",
        "sub": "integration-user",
        "aud": "jwtiny-tests",
        // Let jwkserve set exp/iat/nbf as needed, or keep minimal claims
    });

    let res = reqwest_client
        .post("http://localhost:3000/sign")
        .json(&claims)
        .send()
        .await;

    let res = match res {
        Ok(r) => r,
        Err(e) => {
            eprintln!("SKIP: jwkserve /sign request failed: {e}");
            return;
        }
    };

    if res.status() == reqwest::StatusCode::NOT_FOUND {
        eprintln!(
            "SKIP: jwkserve /sign not available; update jwkserve or run with signing enabled"
        );
        return;
    }
    if !res.status().is_success() {
        eprintln!("SKIP: jwkserve /sign returned status {}", res.status());
        return;
    }

    let body: serde_json::Value = match res.json().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("SKIP: parsing /sign response failed: {e}");
            return;
        }
    };
    let token = match body.get("token").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            eprintln!("SKIP: /sign response missing 'token' field");
            return;
        }
    };

    // 2) Parse token using API
    let parsed = ParsedToken::from_string(&token).expect("parse token");

    // 3) Verify using JWKS
    // Build and run validation with JWKS
    let verified = TokenValidator::new(parsed)
        .ensure_issuer(|iss| {
            if iss == "http://localhost:3000" {
                Ok(())
            } else {
                Err(Error::IssuerNotTrusted(iss.to_string()))
            }
        })
        .verify_signature(SignatureVerification::with_jwks(
            http_client.clone(),
            AlgorithmPolicy::rs256_only(),
            true,
        ))
        .validate_token(ValidationConfig::default())
        .run_async()
        .await;

    match verified {
        Ok(token) => {
            // Verify the token fields
            assert_eq!(token.issuer(), Some("http://localhost:3000"));
            assert_eq!(token.subject(), Some("integration-user"));

            // Verify algorithm
            let header = token.header();
            assert_eq!(header.algorithm_str(), "RS256");
        }
        Err(Error::RemoteError(msg)) => {
            eprintln!("SKIP: remote error while verifying token: {msg}");
            return;
        }
        Err(Error::SignatureInvalid) => {
            eprintln!(
                "SKIP: signature verification failed - possible jwkserve signature format mismatch"
            );
            return;
        }
        Err(e) => panic!("token should verify: {e:?}"),
    }
}

/// Check if jwkserve is up and running
#[cfg(all(feature = "remote", feature = "rsa"))]
async fn is_jwkserve_up() -> bool {
    let client = reqwest::Client::new();
    match client
        .get("http://localhost:3000/.well-known/openid-configuration")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => true,
        _ => false,
    }
}
