//! A minimal JWT validation library.

mod error;
mod jwks;

// Internal modules
pub(crate) mod algorithm;
pub(crate) mod claims;
pub(crate) mod discovery;
pub(crate) mod header;
pub(crate) mod url;
pub(crate) mod utils;
pub(crate) mod validator;

// Public Interface
pub use algorithm::{AlgorithmPolicy, AlgorithmType};
pub use claims::Claims;
pub use claims::ClaimsValidation;
pub use error::{Error, Result};
pub use jwks::RemoteCacheKey;
pub use validator::TokenValidator;

pub use claims::StandardClaims;
pub use jwtiny_derive::claims;

pub(crate) mod limits;
