//! HTTP client for remote fetching

#[cfg(feature = "remote")]
use crate::error::Error;
#[cfg(feature = "remote")]
use std::future::Future;
#[cfg(feature = "remote")]
use std::pin::Pin;

/// HTTP client type for fetching remote resources
///
/// This is a function pointer that accepts a URL and returns a Future yielding bytes.
/// Users must provide an async function that fetches the URL and returns the response body.
/// The library does not provide a default implementation to keep dependencies minimal.
///
/// # Errors
///
/// Error messages should follow the pattern: `"component: error description"`
/// (e.g., `"network: connection failed"`, `"http: status 404"`).
#[cfg(feature = "remote")]
pub type HttpClient = Box<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + 'static>>
        + Send
        + Sync,
>;
