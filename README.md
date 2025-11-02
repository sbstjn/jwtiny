# jwtiny

[![crates.io](https://img.shields.io/crates/v/jwtiny.svg)](https://crates.io/crates/jwtiny)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE.md)
[![CI](https://github.com/sbstjn/jwtiny/actions/workflows/release.yml/badge.svg)](https://github.com/sbstjn/jwtiny/actions/workflows/release.yml)
[![CI](https://github.com/sbstjn/jwtiny/actions/workflows/ci.yml/badge.svg)](https://github.com/sbstjn/jwtiny/actions/workflows/ci.yml)

> Minimal, type-safe JSON Web Token (JWT) validation for Rust.

**jwtiny** validates JWT tokens through a builder-pattern API that attempts to enforce correct validation order at compile time. Initially created to explore `miniserde` support, it aims to prioritize safety, clarity, and zero-cost abstractions.

> **Warning:** This is a learning project to get more familiar with Rust.

## Overview

JWTs (JSON Web Tokens) encode claims as JSON objects secured by digital signatures or message authentication codes. Validating them requires parsing Base64URL-encoded segments, verifying signatures with cryptographic keys, and checking temporal claims like expiration.

Common pitfalls include algorithm confusion attacks (accepting asymmetric algorithms when only symmetric keys are trusted), server-side request forgery (SSRF) via untrusted issuer URLs, and timing vulnerabilities in signature comparison.

**jwtiny** attempts to address these through a type-safe state machine: parsing yields a `ParsedToken`, issuer validation produces a `TrustedToken`, signature verification creates a `VerifiedToken`, and claims validation returns the final `Token`. Each stage must complete before the next begins, enforced by Rust's type system. The builder pattern configures all steps upfront, then executes them atomically—aiming to prevent partial validation and ensure cryptographic keys are only used after issuer checks complete.

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| HMAC | ✅ | HMAC algorithms (HS256, HS384, HS512) — always enabled |
| `rsa` | ❌ | RSA algorithms (RS256, RS384, RS512) |
| `ecdsa` | ❌ | ECDSA algorithms (ES256, ES384) |
| `aws-lc-rs` | ❌ | Use `aws-lc-rs` backend instead of `ring` for RSA/ECDSA |
| `all-algorithms` | ❌ | Enable all asymmetric algorithms (RSA + ECDSA) |
| `remote` | ❌ | Remote JWKS fetching (requires HTTP client implementation) |
| `remote-rustls` | ❌ | HTTPS support for JWKS (provide HTTPS-capable client) |

## Quick Start

Add **jwtiny** to your `Cargo.toml`:

```toml
[dependencies]
jwtiny = "1.0"
```

For asymmetric algorithms (RSA, ECDSA), enable features:

```toml
jwtiny = { version = "1.0", features = ["rsa", "ecdsa"] }
```

Minimal example validating an HMAC-signed token:

```rust
use jwtiny::*;

let token = TokenValidator::new(
    ParsedToken::from_string(token_str)?
)
    .ensure_issuer(|iss| Ok(iss == "https://trusted.com"))
    .verify_signature(SignatureVerification::with_secret(b"secret"))
    .validate_token(ValidationConfig::default())
    .run()?;

println!("Subject: {:?}", token.subject());
```

## Examples

### HMAC Validation

For tokens signed with symmetric keys (HS256, HS384, HS512):

```rust
use jwtiny::*;

let token = TokenValidator::new(ParsedToken::from_string(token_str)?)
    .skip_issuer_check()
    .verify_signature(
        SignatureVerification::with_secret(b"your-256-bit-secret")
            .allow_algorithms(AlgorithmPolicy::allow_only(vec![AlgorithmId::HS256]))
    )
    .validate_token(ValidationConfig::default())
    .run()?;
```

### RSA Public Key Validation

Requires the `rsa` feature:

```rust
use jwtiny::*;

let token = TokenValidator::new(ParsedToken::from_string(token_str)?)
    .ensure_issuer(|iss| Ok(iss == "https://auth.example.com"))
    .verify_signature(
        SignatureVerification::with_key(Key::rsa_public(public_key_der))
            .allow_algorithms(AlgorithmPolicy::allow_only(vec![AlgorithmId::RS256]))
    )
    .validate_token(ValidationConfig::default())
    .run()?;
```

### ECDSA Public Key Validation

Requires the `ecdsa` feature. Supports P-256 and P-384 curves:

```rust
use jwtiny::*;

let token = TokenValidator::new(ParsedToken::from_string(token_str)?)
    .ensure_issuer(|iss| Ok(iss == "https://auth.example.com"))
    .verify_signature(
        SignatureVerification::with_key(
            Key::ecdsa_public(public_key_der, EcdsaCurve::P256)
        )
    )
    .validate_token(ValidationConfig::default())
    .run()?;
```

### JWKS Flow (Remote Key Fetching)

Requires the `remote` feature. Fetch public keys from a JWKS endpoint:

```rust
use jwtiny::*;
use jwtiny::remote::HttpClient;

// Create an HTTP client function pointer
let http_client: HttpClient = {
    let client = reqwest::Client::new();
    Box::new(move |url: String| {
        let client = client.clone();
        Box::pin(async move {
            let response = client
                .get(&url)
                .send()
                .await
                .map_err(|e| Error::RemoteError(format!("network: {}", e)))?;
            
            if !response.status().is_success() {
                return Err(Error::RemoteError(
                    format!("http: status {}", response.status())
                ));
            }
            
            response.bytes().await
                .map_err(|e| Error::RemoteError(format!("network: {}", e)))
                .map(|b| b.to_vec())
        })
    })
};

// Validate with automatic key resolution from JWKS
let token = TokenValidator::new(ParsedToken::from_string(token_str)?)
    .ensure_issuer(|iss| {
        // CRITICAL: Validate issuer before fetching keys
        if iss == "https://auth.example.com" {
            Ok(())
        } else {
            Err(Error::IssuerNotTrusted(iss.to_string()))
        }
    })
    .verify_signature(
        SignatureVerification::with_jwks(http_client, true) // use_cache = true
    )
    .validate_token(ValidationConfig::default())
    .run_async()
    .await?;
```

**Security note:** Always validate the issuer before enabling JWKS fetching. Without issuer validation, an attacker can craft a token with an arbitrary `iss` claim, causing your application to fetch keys from attacker-controlled URLs—a classic SSRF vulnerability.

## API Overview

The validation flow proceeds through distinct stages, each producing a new type:

```rust
// Stage 1: Parse the token string
let parsed = ParsedToken::from_string(token_str)?;

// Stage 2: Build the validation pipeline
let token = TokenValidator::new(parsed)
    .ensure_issuer(/* closure */)      // Required: validate issuer (or use .skip_issuer_check())
    .verify_signature(/* config */)    // Required: verify signature
    .validate_token(/* config */)      // Optional: defaults to ValidationConfig::default() if omitted
    .run()?;                           // Execute all stages atomically

// Stage 3: Access validated claims
token.subject();    // Option<&str>
token.issuer();     // Option<&str>
token.claims();     // &Claims
```

### Issuer Validation

Always validate issuers when using JWKS to prevent SSRF attacks:

```rust
// ✅ Correct: Allowlist trusted issuers
.ensure_issuer(|iss| {
    let trusted = ["https://auth.example.com", "https://login.example.org"];
    trusted.contains(&iss)
        .then_some(())
        .ok_or(Error::IssuerNotTrusted(iss.to_string()))
})

// For same-service tokens, explicitly skip
.skip_issuer_check()
```

### Signature Verification

Choose verification based on the algorithm family:

**HMAC (symmetric keys)** — always enabled:

```rust
SignatureVerification::with_secret(b"your-256-bit-secret")
    .allow_algorithms(AlgorithmPolicy::allow_only(vec![AlgorithmId::HS256]))
```

**RSA (asymmetric keys)** — requires `rsa` feature:

```rust
SignatureVerification::with_key(Key::rsa_public(public_key_der))
    .allow_algorithms(AlgorithmPolicy::allow_only(vec![AlgorithmId::RS256]))
```

**ECDSA (asymmetric keys)** — requires `ecdsa` feature:

```rust
SignatureVerification::with_key(
    Key::ecdsa_public(public_key_der, EcdsaCurve::P256)
)
```

**Algorithm restrictions are recommended** to prevent algorithm confusion. Without `.allow_algorithms()`, any algorithm matching the key type is accepted; with it, only explicitly allowed algorithms pass validation.

### Claims Validation

Configure temporal and claim-specific checks:

```rust
ValidationConfig::default()
    .require_audience("my-api")           // Validate `aud` claim
    .max_age(3600)                        // Token must be < 1 hour old
    .clock_skew(60)                       // Allow 60s clock skew
    .no_exp_validation()                  // Skip expiration (dangerous)
    .custom(|claims| {                    // Custom validation logic
        if claims.subject.as_deref() != Some("admin") {
            Err(Error::ClaimValidationFailed(
                ClaimError::Custom("Admin only".to_string())
            ))
        } else {
            Ok(())
        }
    })
```

## Architecture

The library enforces a validation pipeline through type-level state transitions:

```
ParsedToken (parsed header and payload)
    │ .ensure_issuer()
    ▼
TrustedToken (issuer validated; internal type)
    │ .verify_signature()
    ▼
VerifiedToken (signature verified; internal type)
    │ .validate_token()
    ▼
ValidatedToken (claims validated; internal type)
    │ .run() / .run_async()
    ▼
Token (public API; safe to use)
```

Only the final `Token` type is exposed publicly. Intermediate types (`TrustedToken`, `VerifiedToken`, `ValidatedToken`) are internal, which helps prevent partial validation from escaping the builder.

## Security

### Algorithm Confusion Prevention

Always restrict algorithms explicitly. Without restrictions, a token declaring `RS256` might be accepted when you only intended to allow `HS256`:

```rust
// ✅ Correct: Only allow the algorithm you trust
.allow_algorithms(AlgorithmPolicy::allow_only(vec![AlgorithmId::HS256]))

// ❌ Incorrect: Accepts any algorithm compatible with the key type
SignatureVerification::with_secret(b"secret") // No restrictions
```

### SSRF Prevention

When using JWKS, validate issuers before fetching keys:

```rust
// ✅ Correct: Allowlist trusted issuers
.ensure_issuer(|iss| {
    let allowed = ["https://trusted.com", "https://auth.example.com"];
    allowed.contains(&iss)
        .then_some(())
        .ok_or(Error::IssuerNotTrusted(iss.to_string()))
})

// ❌ Incorrect: Attacker can make you fetch from any URL
.skip_issuer_check()  // Dangerous with JWKS!
```

### "none" Algorithm Rejection

The `"none"` algorithm (unsigned tokens) is always rejected per [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725):

```rust
ParsedToken::from_string("eyJhbGciOiJub25lIn0...")  
// Returns: Error::NoneAlgorithmRejected
```

### Timing Attack Protection

HMAC signature verification uses constant-time comparison via the [`constant_time_eq`](https://crates.io/crates/constant_time_eq) crate, which aims to mitigate timing-based key recovery attacks.

## Cryptographic Backends

**jwtiny** supports two backends for RSA and ECDSA:

1. **`ring`** (default) — battle-tested cryptography library
2. **`aws-lc-rs`** — FIPS-validated AWS cryptography library

Select exactly one backend. The choice affects signature verification compatibility.

### Using `ring` (default)

```toml
[dependencies]
jwtiny = { version = "1.0", features = ["rsa", "ecdsa"] }
```

### Using `aws-lc-rs`

```toml
[dependencies]
jwtiny = { version = "1.0", features = ["rsa", "ecdsa", "aws-lc-rs"] }
```

**Compatibility note:** If you're verifying tokens signed by services using `jsonwebtoken` with the `aws_lc_rs` feature (e.g., `jwkserve`), use the `aws-lc-rs` feature to ensure compatibility.

## Testing

**jwtiny** includes test coverage across algorithm families, edge cases, and integration scenarios.

### Running Tests

```bash
# All features with default backend
cargo test --lib --tests --bins --examples --all-features

# Specific algorithm features
cargo test --lib --tests --bins --examples
cargo test --lib --tests --bins --examples --features rsa
cargo test --lib --tests --bins --examples --features ecdsa

# aws-lc-rs backend (for compatibility testing)
cargo test --lib --tests --bins --examples --features rsa,aws-lc-rs
cargo test --lib --tests --bins --examples --features ecdsa,aws-lc-rs

# Remote JWKS fetching
cargo test --lib --tests --bins --examples --features remote,rsa

# Run specific test suite
cargo test --test algorithm_round_trips --features all-algorithms
cargo test --test jwkserve_integration --features remote,rsa,aws-lc-rs
cargo test --test edge_cases
```

### Test Coverage

- **Algorithm tests** (`tests/algorithm_round_trips.rs`): Round-trip signing and verification for HMAC, RSA, and ECDSA
- **Integration tests** (`tests/jwkserve_integration.rs`): End-to-end RS256 verification via JWKS (requires Docker)
- **Edge cases** (`tests/edge_cases.rs`): Token format validation, Base64URL edge cases, claims validation, algorithm confusion prevention
- **JWK support** (`tests/jwk_support.rs`): JWK metadata handling, key selection, RSA/ECDSA key extraction
- **JWT.io compatibility** (`tests/jwtio_compatibility.rs`): Verification of canonical JWT.io example tokens
- **Custom headers** (`tests/custom_headers.rs`): Header field preservation (`kid`, `typ`, custom fields), field order invariance, real-world header formats
- **Key formats** (`tests/key_formats.rs`): PKCS#8 DER, PKCS#1 DER, PEM format conversion, invalid/truncated key handling

### Running Examples

```bash
cargo run --example basic
cargo run --example multi_algorithm --features all-algorithms
```

## License

MIT

## References

- [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) — JSON Web Signature (JWS)
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — JSON Web Token (JWT)
- [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) — JSON Web Signature Best Practices
- [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648) — Base64URL encoding
- [Rust Book](https://doc.rust-lang.org/book/) — Ownership and borrowing
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) — Idiomatic Rust design
