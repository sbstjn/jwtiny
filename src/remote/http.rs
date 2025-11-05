//! HTTP client for remote fetching

#[cfg(feature = "remote")]
use crate::error::Error;
#[cfg(feature = "remote")]
use std::future::Future;
#[cfg(feature = "remote")]
use std::pin::Pin;

/// HTTP client trait for fetching remote resources
///
/// Users implement this trait to provide HTTP functionality for JWKS and OIDC discovery.
/// The library does not provide a default implementation to keep dependencies minimal.
///
/// # Example
///
/// ```ignore
/// use jwtiny::remote::HttpClient;
/// use jwtiny::Error;
/// use std::pin::Pin;
/// use std::future::Future;
///
/// struct MyHttpClient {
///     client: reqwest::Client,
/// }
///
/// impl HttpClient for MyHttpClient {
///     fn fetch(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + '_>> {
///         let client = self.client.clone();
///         let url = url.to_string();
///         Box::pin(async move {
///             let response = client.get(&url).send().await
///                 .map_err(|e| Error::RemoteError(format!("network: {}", e)))?;
///
///             if !response.status().is_success() {
///                 return Err(Error::RemoteError(format!("http: status {}", response.status())));
///             }
///
///             let bytes = response.bytes().await
///                 .map_err(|e| Error::RemoteError(format!("network: {}", e)))?
///                 .to_vec();
///
///             Ok(bytes)
///         })
///     }
/// }
/// ```
///
/// # Errors
///
/// Implementations should return `Error::RemoteError` with component-prefixed messages
/// following the pattern: `"component: error description"`
/// (e.g., `"network: connection failed"`, `"http: status 404"`).
#[cfg(feature = "remote")]
pub trait HttpClient: Send + Sync {
    /// Fetch a URL and return the response body bytes
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to fetch
    ///
    /// # Errors
    ///
    /// Should return `Error::RemoteError` with format: "component: description"
    fn fetch(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + '_>>;
}
