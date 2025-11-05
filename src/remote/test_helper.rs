//! Test helper implementation of HttpClient
//!
//! This module provides a test helper for creating HttpClient implementations
//! using `reqwest` for testing. It's only available in tests.

#[cfg(feature = "remote")]
use crate::error::{Error, Result};
#[cfg(feature = "remote")]
use crate::remote::http::HttpClient;
#[cfg(feature = "remote")]
use std::future::Future;
#[cfg(feature = "remote")]
use std::pin::Pin;

/// Test HTTP client using reqwest
///
/// This implements the HttpClient trait using reqwest internally.
/// It's only intended for testing.
#[cfg(all(feature = "remote", test))]
pub struct ReqwestClient {
    client: reqwest::Client,
}

#[cfg(all(feature = "remote", test))]
impl ReqwestClient {
    /// Create a new ReqwestClient
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(all(feature = "remote", test))]
impl HttpClient for ReqwestClient {
    fn fetch(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + '_>> {
        let client = self.client.clone();
        let url = url.to_string();
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
    }
}
