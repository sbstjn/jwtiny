use crate::algorithm::{AlgorithmId, AlgorithmPolicy};
use crate::error::{Error, Result};
use crate::token::{TokenHeader, TrustedToken};
use crate::utils::base64url;

/// A JWT token that has been parsed but not yet validated
///
/// This is the first stage in the token validation pipeline.
/// At this stage, we have:
/// - Split the token into three parts (header, payload, signature)
/// - Decoded and parsed the header JSON
/// - Decoded the payload JSON
/// - Identified the algorithm
///
/// Next step: TrustedToken (after issuer validation)
pub struct ParsedToken {
    header: TokenHeader,
    header_b64: String,
    payload_b64: String,
    signature_b64: String,
    raw_payload: String,
}

impl ParsedToken {
    /// Parse a JWT token from a string
    ///
    /// # Arguments
    /// * `token` - The JWT string in format "header.payload.signature"
    ///
    /// # Example
    /// ```ignore
    /// let token = ParsedToken::from_string("eyJ...").unwrap();
    /// ```
    pub fn from_string(token: &str) -> Result<Self> {
        // Split into three parts
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidFormat);
        }

        let header_b64 = parts[0].to_string();
        let payload_b64 = parts[1].to_string();
        let signature_b64 = parts[2].to_string();

        // Decode and parse header
        let header_json = base64url::decode(&header_b64)?;
        let header: TokenHeader = miniserde::json::from_str(&header_json)
            .map_err(|e| Error::InvalidJson(format!("Failed to parse header: {e}")))?;

        // Decode payload (but don't parse claims yet - that happens after verification)
        let raw_payload = base64url::decode(&payload_b64)?;

        Ok(Self {
            header,
            header_b64,
            payload_b64,
            signature_b64,
            raw_payload,
        })
    }

    /// Get the token header
    pub fn header(&self) -> &TokenHeader {
        &self.header
    }

    /// Get the algorithm from the header
    pub fn algorithm(&self) -> Result<AlgorithmId> {
        self.header.parse_algorithm()
    }

    /// Get the raw payload JSON (before verification)
    ///
    /// Note: You should not trust this data until after signature verification!
    pub fn raw_payload(&self) -> &str {
        &self.raw_payload
    }

    /// Get the signing input (header.payload)
    pub(crate) fn signing_input(&self) -> String {
        format!("{}.{}", self.header_b64, self.payload_b64)
    }

    /// Get the signature
    pub(crate) fn signature(&self) -> &str {
        &self.signature_b64
    }

    /// Validate the issuer and move to TrustedToken state
    ///
    /// This enforces that you must validate the issuer (iss claim) before
    /// proceeding with signature verification. This prevents SSRF attacks
    /// where an attacker could make you fetch keys from arbitrary URLs.
    ///
    /// # Arguments
    /// * `validator` - Function that returns Ok(()) if the issuer is trusted
    ///
    /// # Example
    /// ```ignore
    /// let trusted = parsed.trust_issuer(|iss| {
    ///     if iss == "https://trusted-issuer.com" {
    ///         Ok(())
    ///     } else {
    ///         Err(Error::IssuerNotTrusted(iss.to_string()))
    ///     }
    /// })?;
    /// ```
    pub fn trust_issuer<F>(self, validator: F) -> Result<TrustedToken>
    where
        F: FnOnce(&str) -> Result<()>,
    {
        // Parse payload to get issuer claim
        #[derive(miniserde::Deserialize)]
        struct IssuerClaim {
            #[serde(rename = "iss")]
            issuer: Option<String>,
        }

        let payload: IssuerClaim = miniserde::json::from_str(&self.raw_payload)
            .map_err(|e| Error::InvalidJson(format!("Failed to parse payload: {e}")))?;

        // Extract issuer
        let issuer = payload
            .issuer
            .as_deref()
            .ok_or_else(|| Error::MissingField("iss".to_string()))?;

        // Validate issuer
        validator(issuer)?;

        // Move to TrustedToken state (store issuer to avoid re-parsing)
        Ok(TrustedToken::new(self, issuer.to_string()))
    }

    /// Alternative: Trust without issuer check (use with caution!)
    ///
    /// This skips issuer validation. Only use this if you're providing
    /// the signing key directly and not fetching it based on the token.
    ///
    /// For JWKS-based validation, you MUST use trust_issuer() instead.
    ///
    /// Note: This method sets issuer to an empty string since it's not validated.
    /// If you need the issuer later, use `trust_issuer()` instead.
    pub fn trust_without_issuer_check(self) -> TrustedToken {
        // Try to extract issuer for convenience, but don't validate
        #[derive(miniserde::Deserialize)]
        struct IssuerClaim {
            #[serde(rename = "iss")]
            issuer: Option<String>,
        }

        let issuer = miniserde::json::from_str::<IssuerClaim>(&self.raw_payload)
            .ok()
            .and_then(|c| c.issuer)
            .unwrap_or_default();

        TrustedToken::new(self, issuer)
    }

    /// Validate algorithm against policy
    pub fn validate_algorithm(&self, policy: &AlgorithmPolicy) -> Result<()> {
        let algorithm = self.algorithm()?;
        policy.validate(&algorithm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_token() {
        // HS256 token: {"alg":"HS256","typ":"JWT"}.{"iss":"test","sub":"user"}.<sig>
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let payload = r#"{"iss":"test","sub":"user"}"#;
        let header_b64 = base64url::encode(header);
        let payload_b64 = base64url::encode(payload);
        let signature_b64 = base64url::encode("signature");

        let token_str = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);
        let token = ParsedToken::from_string(&token_str).unwrap();

        assert_eq!(token.header().algorithm_str(), "HS256");
        assert!(token.header().token_type.as_deref() == Some("JWT"));
    }

    #[test]
    fn test_parse_invalid_format() {
        assert!(matches!(
            ParsedToken::from_string("not.enough"),
            Err(Error::InvalidFormat)
        ));
        assert!(matches!(
            ParsedToken::from_string("too.many.parts.here"),
            Err(Error::InvalidFormat)
        ));
    }

    #[test]
    fn test_parse_invalid_base64() {
        let result = ParsedToken::from_string("!!!.abc.def");
        assert!(matches!(result, Err(Error::InvalidBase64(_))));
    }

    #[test]
    fn test_parse_invalid_json() {
        let invalid_json = base64url::encode("not json");
        let valid_payload = base64url::encode(r#"{"iss":"test"}"#);
        let sig = base64url::encode("sig");

        let result =
            ParsedToken::from_string(&format!("{}.{}.{}", invalid_json, valid_payload, sig));
        assert!(matches!(result, Err(Error::InvalidJson(_))));
    }

    #[test]
    fn test_trust_issuer() {
        let header = r#"{"alg":"HS256"}"#;
        let payload = r#"{"iss":"https://trusted.com","sub":"user"}"#;
        let token_str = format!(
            "{}.{}.{}",
            base64url::encode(header),
            base64url::encode(payload),
            base64url::encode("sig")
        );

        let parsed = ParsedToken::from_string(&token_str).unwrap();

        // Should succeed with correct issuer
        let result = parsed.trust_issuer(|iss| {
            if iss == "https://trusted.com" {
                Ok(())
            } else {
                Err(Error::IssuerNotTrusted(iss.to_string()))
            }
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_trust_issuer_fails() {
        let header = r#"{"alg":"HS256"}"#;
        let payload = r#"{"iss":"https://untrusted.com","sub":"user"}"#;
        let token_str = format!(
            "{}.{}.{}",
            base64url::encode(header),
            base64url::encode(payload),
            base64url::encode("sig")
        );

        let parsed = ParsedToken::from_string(&token_str).unwrap();

        // Should fail with wrong issuer
        let result = parsed.trust_issuer(|iss| {
            if iss == "https://trusted.com" {
                Ok(())
            } else {
                Err(Error::IssuerNotTrusted(iss.to_string()))
            }
        });
        assert!(matches!(result, Err(Error::IssuerNotTrusted(_))));
    }
}
