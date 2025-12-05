# jwtiny

[![crates.io](https://img.shields.io/crates/v/jwtiny.svg)](https://crates.io/crates/jwtiny)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE.md)
[![CI](https://github.com/sbstjn/jwtiny/actions/workflows/release.yml/badge.svg)](https://github.com/sbstjn/jwtiny/actions/workflows/ci.yml)
[![CI](https://github.com/sbstjn/jwtiny/actions/workflows/ci.yml/badge.svg)](https://github.com/sbstjn/jwtiny/actions/workflows/ci.yml)

> Minimal JSON Web Token (JWT) validation for Rust.

**jwtiny** validates JWT tokens efficiently in production Rust applications. The validator follows a reusable pattern: configure it once at application startup, then verify tokens with minimal allocations. The validator can be shared across requests, which reduces memory footprint and improves performance.

The library supports RSA algorithms (RS256, RS384, RS512) with an aws-lc-rs backend, and provides JWKS support for remote key fetching over HTTPS (rustls) with caching. It's been tested with [Axum](examples/axum/), [Poem](examples/poem/), [Rocket](examples/rocket/), and [Warp](examples/warp/).

## Installation

Add **jwtiny** to your `Cargo.toml`:

```bash
cargo add jwtiny
```

## Quick Start

### Static Key Validation

When you have a static public key, configure the validator like this:

```rust
use jwtiny::{AlgorithmPolicy, ClaimsValidation, TokenValidator};

let validator = TokenValidator::new()
    .algorithms(AlgorithmPolicy::rs512_only())
    .validate(ClaimsValidation::default())
    .key(&public_key_der)
    .build();

let claims = validator.verify(token).await?;
```

That's it! The validator's ready to use. You can call `verify()` as many times as you need—the library is designed for reuse.

### JWKS Validation (Remote Key Fetching)

For production systems, you'll often want to fetch keys from a JWKS endpoint. Here's how the library sets this up:

```rust
use jwtiny::{AlgorithmPolicy, ClaimsValidation, RemoteCacheKey, TokenValidator};
use moka::future::Cache;
use std::time::Duration;

let client = reqwest::Client::new();
let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
    .time_to_live(Duration::from_secs(300))
    .max_capacity(1000)
    .build();

let validator = TokenValidator::new()
    .algorithms(AlgorithmPolicy::rs512_only())
    .issuer(|iss| iss == "https://auth.example.com")
    .validate(ClaimsValidation::default().require_audience("my-api"))
    .jwks(client)
    .cache(cache)
    .build();

let claims = validator.verify(token).await?;
```

The cache reduces network requests and improves performance. Set the TTL to match the key rotation schedule of the identity provider.

For testing, this works fine with [JWKServe](https://github.com/sbstjn/jwkserve) as well.

### Custom Claims

If you need custom claim structures, use the `#[claims]` macro:

```rust
use jwtiny::{claims, AlgorithmPolicy, ClaimsValidation, TokenValidator};

#[claims]
struct MyClaims {
    pub role: String,
    pub permissions: Vec<String>,
}

let validator = TokenValidator::new()
    .algorithms(AlgorithmPolicy::rs256_only())
    .validate(ClaimsValidation::default())
    .key(&public_key_der)
    .build();

let claims = validator.verify_with_custom::<MyClaims>(token).await?;
```

The macro handles the standard claims (iss, sub, aud, exp, nbf, iat, jti) automatically, so you only need to define your custom fields.

## API Reference

### TokenValidator

Configure the validator once, then reuse it for multiple verifications:

```rust
let validator = TokenValidator::new()
    .algorithms(AlgorithmPolicy::rs512_only())  // RS256, RS384, RS512, or rsa_all()
    .issuer(|iss| iss == "https://auth.example.com")
    .validate(ClaimsValidation::default().require_audience("my-api"))
    .key(&public_key_der)      // Static key (mutually exclusive with jwks)
    .jwks(client)              // JWKS (mutually exclusive with key)
    .cache(cache)              // Optional: cache JWKS keys
    .build();

// Verify tokens (reusable)
let claims = validator.verify(token_str).await?;
let custom = validator.verify_with_custom::<MyClaims>(token_str).await?;
```

### AlgorithmPolicy

Control which algorithms are accepted:

```rust
AlgorithmPolicy::rs256_only()  // RS256 only
AlgorithmPolicy::rs512_only()  // RS512 only
AlgorithmPolicy::rsa_all()     // All RSA (default)
```

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
