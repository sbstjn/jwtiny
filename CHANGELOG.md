# Changelog

See [GitHub Release](https://github.com/sbstjn/jwtiny/releases) for current release notes.

## [Unreleased]

### Current Features

- **RSA algorithms** (always enabled): RS256, RS384, RS512 with aws-lc-rs backend
- **Remote JWKS fetching** (via `remote` feature): automatic key resolution from OpenID Connect providers
- **Type-safe validation pipeline** with compile-time enforced ordering:
  - `ParsedToken` → `TrustedToken` → `VerifiedToken` → `ValidatedToken` → `Token`
- **Algorithm confusion prevention** via explicit `AlgorithmPolicy` requirement
- **SSRF prevention** through mandatory issuer validation before key fetching
- **Claims validation**:
  - Temporal checks: `exp`, `nbf`, `iat`
  - Audience validation
  - Clock skew tolerance
  - Maximum token age (max_age)
- **Builder pattern API** via `TokenValidator` for declarative validation configuration
- **Algorithm-specific convenience constructors** for common use cases

### Security

- **"none" algorithm rejection** per [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725)
- **Issuer validation** prevents SSRF attacks when using JWKS fetching
- **Algorithm policy enforcement** prevents accepting unexpected algorithms
- **Constant-time signature verification** via aws-lc-rs backend
- **Mandatory issuer check** before fetching keys from remote endpoints
- **Resource exhaustion prevention** with size limits on all inputs

