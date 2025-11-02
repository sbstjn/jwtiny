//! OIDC Discovery module
//!
//! This module provides functionality for OpenID Connect Discovery as defined
//! in the [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
//! specification. It fetches issuer metadata and resolves JWKS URIs from
//! `/.well-known/openid-configuration` endpoints.

#[cfg(feature = "remote")]
#[allow(clippy::module_inception)]
mod discovery;

#[cfg(feature = "remote")]
pub use discovery::*;
