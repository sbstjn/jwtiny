use crate::algorithm::AlgorithmId;
use crate::error::Result;
use miniserde::Deserialize;

/// JWT header structure
#[derive(Debug, Clone, Deserialize)]
pub struct TokenHeader {
    /// Algorithm used for signing
    #[serde(rename = "alg")]
    pub algorithm: String,

    /// Token type (typically "JWT")
    #[serde(rename = "typ")]
    pub token_type: Option<String>,

    /// Key ID (for JWKS key selection)
    #[serde(rename = "kid")]
    pub key_id: Option<String>,
}

impl TokenHeader {
    /// Parse algorithm from header
    pub fn parse_algorithm(&self) -> Result<AlgorithmId> {
        AlgorithmId::from_str(&self.algorithm)
    }

    /// Get algorithm as string
    pub fn algorithm_str(&self) -> &str {
        &self.algorithm
    }

    /// Get key ID if present
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}
