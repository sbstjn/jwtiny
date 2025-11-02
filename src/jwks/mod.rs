//! JSON Web Key Set (JWKS) module
//!
//! This module provides functionality for working with JSON Web Key Sets
//! (JWKS) as defined in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
//! It includes parsing JWKS documents, extracting keys, and matching keys
//! by key ID (`kid`) and algorithm.

#[cfg(feature = "remote")]
mod jwk;
#[cfg(feature = "remote")]
#[allow(clippy::module_inception)]
mod jwks;
#[cfg(feature = "remote")]
mod resolver;

#[cfg(feature = "remote")]
pub use jwk::*;
#[cfg(feature = "remote")]
pub use jwks::*;
#[cfg(feature = "remote")]
pub use resolver::*;
