use miniserde::Deserialize;

/// JWT header structure
///
/// Represents the JWT header containing algorithm and key ID.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TokenHeader {
    /// Algorithm used for signing
    #[serde(rename = "alg")]
    pub algorithm: String,

    /// Key ID (for JWKS key selection)
    #[serde(rename = "kid")]
    pub key_id: Option<String>,
}
