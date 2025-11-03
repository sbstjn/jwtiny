# Changelog

See [GitHub Release](https://github.com/sbstjn/jwtiny/releases) for current release notes. Version `1.2.1` marks the initial release.

## [1.2.1] - 2025-11-03

### Added

- **HMAC algorithms** (always enabled): HS256, HS384, HS512
- **RSA algorithms** (via `rsa` feature): RS256, RS384, RS512
- **ECDSA algorithms** (via `ecdsa` feature): ES256, ES384
- **Remote JWKS fetching** (via `remote` feature): automatic key resolution from OpenID Connect providers
- **Type-safe validation pipeline** with compile-time enforced ordering:
  - `ParsedToken` → `TrustedToken` → `VerifiedToken` → `ValidatedToken` → `Token`
- **Algorithm confusion prevention** via explicit `AlgorithmPolicy` requirement
- **SSRF prevention** through mandatory issuer validation before key fetching
- **Constant-time HMAC comparison** using `constant_time_eq` crate
- **Claims validation**:
  - Temporal checks: `exp`, `nbf`, `iat`
  - Audience validation
  - Custom validation callbacks
  - Clock skew tolerance
  - Maximum token age (max_age)
- **Builder pattern API** via `TokenValidator` for declarative validation configuration
- **Algorithm-specific convenience constructors** for common use cases
- **Cryptographic backend support**:
  - `ring` (default) for RSA/ECDSA
  - `aws-lc-rs` (opt-in) for FIPS-compliant deployments

### Security

- **"none" algorithm rejection** per [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725)
- **Issuer validation** prevents SSRF attacks when using JWKS fetching
- **Algorithm policy enforcement** prevents accepting unexpected algorithms
- **Constant-time signature comparison** mitigates timing-based key recovery attacks
- **Mandatory issuer check** before fetching keys from remote endpoints

### Documentation

- Comprehensive README with security best practices
- Type-safe validation flow diagrams
- Code examples for all algorithm families
- JWKS integration examples
- Security considerations and attack prevention guidance
- Cargo.toml metadata for crates.io and docs.rs integration

