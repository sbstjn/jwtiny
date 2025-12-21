# jwtiny

[![crates.io](https://img.shields.io/crates/v/jwtiny.svg)](https://crates.io/crates/jwtiny)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE.md)
[![CI](https://github.com/sbstjn/jwtiny/actions/workflows/release.yml/badge.svg)](https://github.com/sbstjn/jwtiny/actions/workflows/ci.yml)
[![CI](https://github.com/sbstjn/jwtiny/actions/workflows/ci.yml/badge.svg)](https://github.com/sbstjn/jwtiny/actions/workflows/ci.yml)

> Minimal JSON Web Token (JWT) validation for Rust.

**jwtiny** validates JWT tokens efficiently in production Rust applications. The validator follows a reusable pattern: configure it once at application startup, then verify tokens with minimal allocations. The validator can be shared across requests, which reduces memory footprint and improves performance.

The library supports **RSA** (RS256, RS384, RS512) and **ECDSA** (ES256, ES384, ES512) algorithms with an `aws-lc-rs` backend, and provides **JWKS support** for remote key fetching over HTTPS (`rustls`) with caching. It's been tested with [Axum](examples/axum/), [Poem](examples/poem/), [Rocket](examples/rocket/), and [Warp](examples/warp/).

## Installation

Add **jwtiny** to your `Cargo.toml`:

```bash
cargo add jwtiny
```

## Quick Start

### Static Key Validation

When you have a static public key, configure the validator like this:

```rust
use std::sync::Arc;
use jwtiny::{AlgorithmPolicy, ClaimsValidation, TokenValidator};

let validator = TokenValidator::new()
    .algorithms(AlgorithmPolicy::rs512_only())
    .validate(ClaimsValidation::default())
    .key(Arc::new(public_key_der));

let claims = validator.verify(token).await?;
```

That's it! The validator's ready to use. You can call `verify()` as many times as you need—the library is designed for reuse.

### JWKS Validation (Remote Key Fetching)

For production systems, you'll often want to fetch keys from a JWKS endpoint. Here's how the library sets this up:

```rust
use jwtiny::{AlgorithmPolicy, ClaimsValidation, TokenValidator};
use moka::future::Cache;
use std::time::Duration;

let client = reqwest::Client::new();
let cache = Cache::<String, Vec<u8>>::builder()
    .time_to_live(Duration::from_secs(300))
    .max_capacity(1000)
    .build();

let validator = TokenValidator::new()
    .algorithms(AlgorithmPolicy::rs512_only())
    .issuer(|iss| iss == "https://auth.example.com")
    .validate(ClaimsValidation::default().require_audience("my-api"))
    .jwks(client)
    .cache(cache);

let claims = validator.verify(token).await?;
```

The cache reduces network requests and improves performance. Set the TTL to match the key rotation schedule of the identity provider.

For testing, this works fine with [JWKServe](https://github.com/sbstjn/jwkserve) as well.

### Custom Claims

If you need custom claim structures, use the `#[claims]` macro:

```rust
use std::sync::Arc;
use jwtiny::{claims, AlgorithmPolicy, ClaimsValidation, TokenValidator};

#[claims]
struct MyClaims {
    pub role: String,
    pub permissions: Vec<String>,
}

let validator = TokenValidator::new()
    .algorithms(AlgorithmPolicy::rs256_only())
    .validate(ClaimsValidation::default())
    .key(Arc::new(public_key_der));

let claims = validator.verify_with_custom::<MyClaims>(token).await?;
```

The macro handles the standard claims (iss, sub, aud, exp, nbf, iat, jti) automatically, so you only need to define your custom fields.


## Performance

For **ECDSA** algorithms, `jwtiny` is particularly efficient — **ES384** performance is over 3x faster than `jsonwebtoken`, while **ES256** shows a solid 8% improvement. 

The **RSA** performance gains scale with key size: you'll see roughly 18–20% improvements with 2048-bit keys, 26–27% with 3072-bit keys, and around 30–31% with 4096-bit keys, regardless of the hash variant.

![jwtiny-jsonwebtoken-performance](https://raw.githubusercontent.com/sbstjn/jwtiny/refs/heads/main/docs/performance.png)

These improvements become more pronounced as cryptographic operations become computationally expensive, making jwtiny especially beneficial for high-throughput applications or services handling many concurrent token validations.

![jwtiny-jsonwebtoken-performance-token-size](https://raw.githubusercontent.com/sbstjn/jwtiny/refs/heads/main/docs/performance_size.png)

The throughput of **RS256** degrades ~35% from default token (60,203 ops/s at 550 bytes) to +1000% token size (39,173 ops/s at 7,830 bytes), while **ES384** stays stable with only ~16% degradation (5,696 to 4,807 ops/s) despite a 14x token size increase. 

At +1000% token size, jwtiny’s **RS256** advantage narrows to ~5%, while **ES384** maintains its ~3x advantage, indicating ES384’s validation is less sensitive to payload size than RS256.

## API Reference

### TokenValidator

Configure the validator once, then reuse it for multiple verifications:

```rust
use std::sync::Arc;

let validator = TokenValidator::new()
    .algorithms(AlgorithmPolicy::rs512_only())  // See AlgorithmPolicy section below
    .issuer(|iss| iss == "https://auth.example.com")
    .validate(ClaimsValidation::default().require_audience("my-api"))
    .key(Arc::new(public_key_der))  // Wrap in Arc for efficient sharing
    .jwks(client)                   // JWKS (mutually exclusive with key)
    .cache(cache);                  // Optional: cache JWKS keys

// Verify tokens (reusable)
let claims = validator.verify(token_str).await?;
let custom = validator.verify_with_custom::<MyClaims>(token_str).await?;
```

### AlgorithmPolicy

Control which algorithms are accepted:

```rust
use jwtiny::{AlgorithmPolicy, AlgorithmType};

// Predefined policies (zero-allocation, use stack arrays)
AlgorithmPolicy::rs256_only()  // RS256 only
AlgorithmPolicy::rs384_only()  // RS384 only
AlgorithmPolicy::rs512_only()  // RS512 only
AlgorithmPolicy::rsa_all()     // All RSA algorithms

AlgorithmPolicy::es256_only()  // ES256 (P-256) only
AlgorithmPolicy::es384_only()  // ES384 (P-384) only
AlgorithmPolicy::es512_only()  // ES512 (P-521) only
AlgorithmPolicy::ecdsa_all()   // All ECDSA algorithms

// Custom policies (accepts arrays)
AlgorithmPolicy::allow_only([AlgorithmType::RS256, AlgorithmType::ES256])
```

**Note**: The default policy is `rs256_only()` for security. Always configure the policy explicitly to match your identity provider's signing algorithm.

### ClaimsValidation

Configure temporal and audience validation:

```rust
ClaimsValidation::default()
    .require_audience("my-api")
    .max_age(3600)
    .clock_skew(60)
    .no_exp_validation()
    .no_nbf_validation()
    .no_iat_validation()
```

By default, the validator checks expiration (`exp`), not-before (`nbf`), and issued-at (`iat`), with a max age of 30 minutes and no clock skew. In distributed systems, adding clock skew tolerance can help handle time synchronisation differences.

## Error Handling

All validation errors are returned as `jwtiny::Error`:

```rust
match validator.verify(token).await {
    Ok(claims) => println!("Valid: {:?}", claims),
    Err(jwtiny::Error::TokenExpired { .. }) => eprintln!("Token expired"),
    Err(jwtiny::Error::SignatureInvalid) => eprintln!("Invalid signature"),
    Err(e) => eprintln!("Validation failed: {:?}", e),
}
```

## Examples

Complete working examples for various web frameworks:

- **Axum**: [`examples/axum/`](examples/axum/)
- **Poem**: [`examples/poem/`](examples/poem/)
- **Rocket**: [`examples/rocket/`](examples/rocket/)
- **Warp**: [`examples/warp/`](examples/warp/)

Run an example:

```bash
cargo run -p jwtiny-example-axum
```

## License

MIT

## References

- [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) — JSON Web Signature (JWS)
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — JSON Web Token (JWT)
- [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) — JSON Web Signature Best Practices