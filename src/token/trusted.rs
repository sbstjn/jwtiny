use crate::algorithm::{get_verifier, AlgorithmId};
use crate::error::Result;
use crate::keys::Key;
use crate::token::{ParsedToken, TokenHeader, VerifiedToken};

/// A JWT token whose issuer has been validated
///
/// This is the second stage in the token validation pipeline.
/// At this stage:
/// - The token has been parsed
/// - The issuer (iss claim) has been validated
/// - We can now safely fetch keys based on the issuer
///
/// Next step: VerifiedToken (after signature verification)
pub struct TrustedToken {
    parsed: ParsedToken,
    issuer: String, // Stored after validation to avoid re-parsing
}

impl TrustedToken {
    pub(crate) fn new(parsed: ParsedToken, issuer: String) -> Self {
        Self { parsed, issuer }
    }

    /// Get the validated issuer
    ///
    /// This is safe to use because the issuer was already validated during
    /// the `trust_issuer()` step, which prevents SSRF attacks.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Get the token header
    pub fn header(&self) -> &TokenHeader {
        self.parsed.header()
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> Result<AlgorithmId> {
        self.parsed.algorithm()
    }

    /// Get the raw payload JSON (before verification)
    ///
    /// Note: You should not trust this data until after signature verification!
    pub fn raw_payload(&self) -> &str {
        self.parsed.raw_payload()
    }

    /// Verify the signature and move to VerifiedToken state
    ///
    /// # Arguments
    /// * `key` - The key to use for signature verification
    ///
    /// # Example
    /// ```ignore
    /// let key = Key::symmetric(b"your-secret");
    /// let verified = trusted.verify_signature(&key)?;
    /// ```
    pub fn verify_signature(self, key: &Key) -> Result<VerifiedToken> {
        let algorithm = self.algorithm()?;
        let verifier = get_verifier(&algorithm);

        // Verify the signature
        verifier.verify(&self.parsed.signing_input(), self.parsed.signature(), key)?;

        // Move to VerifiedToken state
        Ok(VerifiedToken::new(self.parsed, algorithm))
    }

    /// Get signing input for external verification
    pub fn signing_input(&self) -> String {
        self.parsed.signing_input()
    }

    /// Get signature for external verification
    pub fn signature(&self) -> &str {
        self.parsed.signature()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::ParsedToken;
    use crate::utils::base64url;

    #[test]
    fn test_verify_signature_hmac() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let header = r#"{"alg":"HS256"}"#;
        let payload = r#"{"iss":"test","sub":"user"}"#;
        let secret = b"secret";

        let header_b64 = base64url::encode(header);
        let payload_b64 = base64url::encode(payload);
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Compute signature
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing_input.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let signature_b64 = base64url::encode_bytes(&signature_bytes);

        let token_str = format!("{}.{}", signing_input, signature_b64);
        let parsed = ParsedToken::from_string(&token_str).unwrap();
        let trusted = parsed.danger_trust_without_issuer_check();

        let key = Key::symmetric(secret);
        let result = trusted.verify_signature(&key);
        assert!(result.is_ok(), "Valid signature should verify");
    }

    #[test]
    fn test_verify_signature_fails() {
        let header = r#"{"alg":"HS256"}"#;
        let payload = r#"{"iss":"test","sub":"user"}"#;

        let token_str = format!(
            "{}.{}.{}",
            base64url::encode(header),
            base64url::encode(payload),
            base64url::encode("wrong_signature")
        );

        let parsed = ParsedToken::from_string(&token_str).unwrap();
        let trusted = parsed.danger_trust_without_issuer_check();

        let key = Key::symmetric(b"secret");
        let result = trusted.verify_signature(&key);
        assert!(result.is_err(), "Invalid signature should fail");
    }
}
