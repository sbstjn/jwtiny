//! Token generation utilities using jwkserve
//!
//! This module provides a fluent API for generating JWT tokens via jwkserve,
//! supporting all 6 algorithms (RS256/384/512, ES256/384/512).
//!
//! # Examples

#![allow(dead_code)]
//!
//! ```rust,no_run
//! use parity::token_gen::{Algorithm, TokenBuilder};
//!
//! # async fn example() {
//! // Generate RS256 token with standard claims
//! let token = TokenBuilder::new("http://localhost:3000", Algorithm::RS256)
//!     .standard_valid_claims()
//!     .generate()
//!     .await
//!     .unwrap();
//!
//! // Generate ES256 token with custom claims
//! let token = TokenBuilder::new("http://localhost:3000", Algorithm::ES256)
//!     .subject("user-123")
//!     .audience("my-app")
//!     .custom_claim("role", serde_json::json!("admin"))
//!     .generate()
//!     .await
//!     .unwrap();
//! # }
//! ```
//!
//! # Corrupting Tokens for Error Tests
//!
//! ```rust
//! use parity::token_gen::corrupt_signature;
//!
//! let valid_token = "header.payload.signature";
//! let invalid_token = corrupt_signature(valid_token);
//! // invalid_token now has corrupted signature bytes
//! ```

use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

/// JWT algorithm types supported by jwkserve
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Algorithm {
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
}

impl Algorithm {
    /// Get the algorithm name for jwkserve endpoint
    pub fn name(&self) -> &'static str {
        match self {
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
        }
    }

    /// All supported algorithms
    pub fn all() -> Vec<Self> {
        vec![
            Self::RS256,
            Self::RS384,
            Self::RS512,
            Self::ES256,
            Self::ES384,
            Self::ES512,
        ]
    }
}

/// Builder for generating JWT tokens via jwkserve
#[derive(Debug)]
pub struct TokenBuilder {
    base_url: String,
    algorithm: Algorithm,
    claims: Value,
}

impl TokenBuilder {
    /// Create a new token builder
    ///
    /// # Arguments
    /// * `base_url` - jwkserve base URL (typically "http://localhost:3000")
    /// * `algorithm` - JWT signing algorithm
    pub fn new(base_url: impl Into<String>, algorithm: Algorithm) -> Self {
        Self {
            base_url: base_url.into(),
            algorithm,
            claims: json!({}),
        }
    }

    /// Set the issuer claim
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.claims["iss"] = json!(iss.into());
        self
    }

    /// Set the subject claim
    pub fn subject(mut self, sub: impl Into<String>) -> Self {
        self.claims["sub"] = json!(sub.into());
        self
    }

    /// Set the audience claim
    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.claims["aud"] = json!(aud.into());
        self
    }

    /// Set the expiration time (Unix timestamp)
    pub fn expiration(mut self, exp: u64) -> Self {
        self.claims["exp"] = json!(exp);
        self
    }

    /// Set the issued at time (Unix timestamp)
    pub fn issued_at(mut self, iat: u64) -> Self {
        self.claims["iat"] = json!(iat);
        self
    }

    /// Set the not before time (Unix timestamp)
    pub fn not_before(mut self, nbf: u64) -> Self {
        self.claims["nbf"] = json!(nbf);
        self
    }

    /// Build standard valid claims (valid for 1 hour from now)
    pub fn standard_valid_claims(mut self) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.claims = json!({
            "iss": self.base_url.clone(),
            "sub": "test-user",
            "aud": "test-app",
            "iat": now - 60,
            "nbf": now - 60,
            "exp": now + 3600,
        });
        self
    }

    /// Generate the token by calling jwkserve
    pub async fn generate(self) -> Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let url = format!("{}/sign/{}", self.base_url, self.algorithm.name());

        let json_body = serde_json::to_string(&self.claims)?;
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
        let json: Value = serde_json::from_str(&body)?;
        let token = json
            .get("token")
            .and_then(|t| t.as_str())
            .ok_or("Missing token in response")?;

        Ok(token.to_string())
    }

    /// Set a custom claim
    pub fn custom_claim(mut self, key: impl Into<String>, value: Value) -> Self {
        self.claims[key.into()] = value;
        self
    }
}

/// Helper to get current Unix timestamp
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Create a token with an invalid signature by corrupting the last byte
pub fn corrupt_signature(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return token.to_string();
    }

    let mut sig_bytes = parts[2].as_bytes().to_vec();
    if !sig_bytes.is_empty() {
        // Flip the last byte to corrupt the signature
        let last_idx = sig_bytes.len() - 1;
        sig_bytes[last_idx] ^= 0xFF;
    }

    let corrupted_sig = String::from_utf8_lossy(&sig_bytes).to_string();
    format!("{}.{}.{corrupted_sig}", parts[0], parts[1])
}

/// Remove the signature from a token
pub fn remove_signature(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return token.to_string();
    }
    format!("{}.{}", parts[0], parts[1])
}

/// Replace signature with empty string
pub fn empty_signature(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return token.to_string();
    }
    format!("{}.{}.", parts[0], parts[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_names() {
        assert_eq!(Algorithm::RS256.name(), "RS256");
        assert_eq!(Algorithm::ES384.name(), "ES384");
        assert_eq!(Algorithm::RS512.name(), "RS512");
    }

    #[test]
    fn test_corrupt_signature() {
        let token = "header.payload.signature";
        let corrupted = corrupt_signature(token);
        assert_ne!(token, corrupted);
        assert!(corrupted.starts_with("header.payload."));
    }

    #[test]
    fn test_remove_signature() {
        let token = "header.payload.signature";
        let removed = remove_signature(token);
        assert_eq!(removed, "header.payload");
    }

    #[test]
    fn test_empty_signature() {
        let token = "header.payload.signature";
        let empty = empty_signature(token);
        assert_eq!(empty, "header.payload.");
    }
}
