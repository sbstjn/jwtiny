//! Test helper implementation of HttpClient
//!
//! This module provides a test helper for creating HttpClient function pointers
//! using `reqwest` for testing. It's only available in tests.

#[cfg(feature = "remote")]
use crate::error::Error;
#[cfg(feature = "remote")]
use crate::remote::http::HttpClient;

/// Create a test HTTP client using reqwest
///
/// This returns an HttpClient function pointer that uses reqwest internally.
/// It's only intended for testing.
#[cfg(all(feature = "remote", test))]
pub fn reqwest_client() -> HttpClient {
    Box::new(move |url: String| {
        let client = reqwest::Client::new();
        Box::pin(async move {
            let response = client
                .get(&url)
                .send()
                .await
                .map_err(|e| Error::RemoteError(format!("network: {}", e)))?;

            if !response.status().is_success() {
                return Err(Error::RemoteError(format!(
                    "http: status {}",
                    response.status()
                )));
            }

            let bytes = response
                .bytes()
                .await
                .map_err(|e| Error::RemoteError(format!("network: {}", e)))?
                .to_vec();

            Ok(bytes)
        })
    })
}
