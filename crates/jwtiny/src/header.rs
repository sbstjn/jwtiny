use crate::algorithm::AlgorithmType;
use crate::error::{Error, Result};
use crate::limits::MAX_ALG_LENGTH;
use crate::utils::bounds::validate_field_size;
use miniserde::Deserialize;

/// JWT header containing algorithm and key ID
#[derive(Debug, Clone)]
pub(crate) struct TokenHeader {
    /// Algorithm used for signing
    pub algorithm: AlgorithmType,

    /// Key ID (for JWKS key selection)
    pub key_id: Option<String>,
}

impl TokenHeader {
    /// Deserialize from JSON string, converting algorithm string to AlgorithmType
    pub(crate) fn from_json_str(json: &str) -> Result<Self> {
        // Deserialize to intermediate struct with String
        #[derive(Deserialize)]
        struct TokenHeaderIntermediate {
            #[serde(rename = "alg")]
            algorithm: String,
            #[serde(rename = "kid")]
            key_id: Option<String>,
        }

        let intermediate: TokenHeaderIntermediate = miniserde::json::from_str(json)
            .map_err(|e| Error::FormatInvalidJson(format!("Failed to parse header: {e}")))?;

        // Validate algorithm string length before parsing
        validate_field_size("alg", &intermediate.algorithm, MAX_ALG_LENGTH)?;

        // Convert string to AlgorithmType
        let algorithm = AlgorithmType::from_str(&intermediate.algorithm)?;

        Ok(Self {
            algorithm,
            key_id: intermediate.key_id,
        })
    }
}
