//! Remote fetching module for JWKS and OIDC discovery
//!
//! This module provides support for fetching JSON Web Key Sets (JWKS) and
//! performing OpenID Connect (OIDC) discovery to resolve keys from remote
//! issuers. It defines the `HttpClient` trait that users must implement with
//! their preferred HTTP client library.

#[cfg(feature = "remote")]
pub mod config;
#[cfg(feature = "remote")]
pub mod http;

#[cfg(feature = "remote")]
pub use http::HttpClient;

// Test helper (only available in tests)
#[cfg(all(feature = "remote", test))]
pub mod test_helper;

#[cfg(all(feature = "remote", test))]
pub use test_helper::ReqwestClient;
