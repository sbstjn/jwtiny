//! JWKS caching performance benchmarks
//!
//! Benchmarks the performance of JWKS fetching with caching using jwkserve on localhost:3000.
//!
//! Measures:
//! - Cache hit performance (no network)
//! - Cache miss performance (fetch + parse + cache insert)
//! - Cache lock contention under concurrent requests
//! - Parsing overhead (JSON deserialization)
//!
//! Requires jwkserve running on localhost:3000 (use docker-compose up -d or GitHub Actions service).
//! Benchmarks gracefully skip if jwkserve is not available.

#[cfg(feature = "remote")]
use criterion::{BenchmarkId, Throughput};
use criterion::{Criterion, criterion_group, criterion_main};
#[cfg(feature = "remote")]
use jwtiny::Error;
#[cfg(feature = "remote")]
use jwtiny::jwks;
#[cfg(feature = "remote")]
use jwtiny::remote::HttpClient;
#[cfg(feature = "remote")]
use std::sync::Arc;
#[cfg(feature = "remote")]
use std::time::Duration;
#[cfg(feature = "remote")]
use tokio::runtime::Runtime;

#[cfg(feature = "remote")]
const JWKSERVE_URL: &str = "http://localhost:3000";

#[cfg(feature = "remote")]
const JWKSERVE_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(feature = "remote")]
/// Check if jwkserve is available at localhost:3000
async fn is_jwkserve_available() -> bool {
    use tokio::time::timeout;
    let client = match reqwest::Client::builder().timeout(JWKSERVE_TIMEOUT).build() {
        Ok(client) => client,
        Err(_) => return false,
    };

    timeout(JWKSERVE_TIMEOUT, async {
        client
            .get(format!("{}/.well-known/openid-configuration", JWKSERVE_URL))
            .send()
            .await
            .ok()
            .and_then(|r| {
                if r.status().is_success() {
                    Some(())
                } else {
                    None
                }
            })
    })
    .await
    .is_ok()
}

#[cfg(feature = "remote")]
/// HTTP client implementation using reqwest for benchmarks
struct ReqwestHttpClient {
    client: reqwest::Client,
}

#[cfg(feature = "remote")]
impl HttpClient for ReqwestHttpClient {
    fn fetch(
        &self,
        url: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, Error>> + Send + '_>>
    {
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

#[cfg(feature = "remote")]
/// Create an HTTP client using reqwest for fetching JWKS
fn create_http_client() -> ReqwestHttpClient {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("Failed to create reqwest client");

    ReqwestHttpClient { client }
}

#[cfg(feature = "remote")]
/// Discover the JWKS URI from jwkserve
async fn discover_jwks_uri(client: &impl HttpClient) -> Option<String> {
    use jwtiny::discovery;

    discovery::discover_jwks_uri(JWKSERVE_URL, client)
        .await
        .ok()
}

#[cfg(feature = "remote")]
fn bench_jwks_cache_hit(c: &mut Criterion) {
    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Check if jwkserve is available
    if !rt.block_on(is_jwkserve_available()) {
        eprintln!(
            "SKIP: jwkserve not available at {}/.well-known/openid-configuration",
            JWKSERVE_URL
        );
        eprintln!("      Start jwkserve with: docker-compose up -d");
        return;
    }

    let client = Arc::new(create_http_client());

    // First, fetch once to populate cache
    let jwks_uri = match rt.block_on(discover_jwks_uri(&client)) {
        Some(uri) => uri,
        None => {
            eprintln!("SKIP: Failed to discover JWKS URI");
            return;
        }
    };

    if rt
        .block_on(jwks::fetch_jwks_cached(&client, &jwks_uri))
        .is_err()
    {
        eprintln!("SKIP: Failed to fetch JWKS");
        return;
    }

    let mut group = c.benchmark_group("jwks_cache_hit");
    group.throughput(Throughput::Elements(1));

    group.bench_function("cache_hit", |b| {
        let rt = &rt;
        let jwks_uri = jwks_uri.clone();
        let client = client.clone();
        b.iter(|| {
            rt.block_on(async {
                let _ = jwks::fetch_jwks_cached(&client, &jwks_uri).await;
            })
        });
    });

    group.finish();
}

#[cfg(feature = "remote")]
fn bench_jwks_cache_miss(c: &mut Criterion) {
    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Check if jwkserve is available
    if !rt.block_on(is_jwkserve_available()) {
        eprintln!(
            "SKIP: jwkserve not available at {}/.well-known/openid-configuration",
            JWKSERVE_URL
        );
        eprintln!("      Start jwkserve with: docker-compose up -d");
        return;
    }

    let client = Arc::new(create_http_client());
    let jwks_uri = match rt.block_on(discover_jwks_uri(&client)) {
        Some(uri) => uri,
        None => {
            eprintln!("SKIP: Failed to discover JWKS URI");
            return;
        }
    };

    // Clear cache by using a unique URI each time
    // We'll use the jwks_uri with a query param to bypass cache
    let mut group = c.benchmark_group("jwks_cache_miss");
    group.throughput(Throughput::Elements(1));

    // Clear cache before each run by accessing unique URIs
    group.bench_function("cache_miss", |b| {
        let rt = &rt;
        let jwks_uri = jwks_uri.clone();
        let client = client.clone();
        b.iter(|| {
            rt.block_on(async {
                // Use timestamp to ensure cache miss
                let unique_uri = format!(
                    "{}?t={}",
                    jwks_uri,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                );
                // Use non-cached fetch to simulate cache miss
                let _ = jwks::fetch_jwks(&client, &unique_uri).await;
            })
        });
    });

    group.finish();
}

#[cfg(feature = "remote")]
fn bench_jwks_parsing(c: &mut Criterion) {
    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Check if jwkserve is available
    if !rt.block_on(is_jwkserve_available()) {
        eprintln!(
            "SKIP: jwkserve not available at {}/.well-known/openid-configuration",
            JWKSERVE_URL
        );
        eprintln!("      Start jwkserve with: docker-compose up -d");
        return;
    }

    let client = create_http_client();
    let jwks_uri = match rt.block_on(discover_jwks_uri(&client)) {
        Some(uri) => uri,
        None => {
            eprintln!("SKIP: Failed to discover JWKS URI");
            return;
        }
    };

    // Fetch raw bytes once
    let raw_bytes = match rt.block_on(async {
        let bytes = client.fetch(&jwks_uri).await?;
        Ok::<Vec<u8>, Error>(bytes)
    }) {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!("SKIP: Failed to fetch JWKS bytes");
            return;
        }
    };

    let mut group = c.benchmark_group("jwks_parsing");
    group.throughput(Throughput::Bytes(raw_bytes.len() as u64));

    group.bench_function("json_parse", |b| {
        b.iter(|| {
            let body = std::str::from_utf8(&raw_bytes).expect("Invalid UTF-8");
            let _: jwtiny::jwks::JwkSet =
                miniserde::json::from_str(body).expect("Failed to parse JWKS");
        });
    });

    group.finish();
}

#[cfg(feature = "remote")]
fn bench_jwks_cache_concurrent(c: &mut Criterion) {
    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Check if jwkserve is available
    if !rt.block_on(is_jwkserve_available()) {
        eprintln!(
            "SKIP: jwkserve not available at {}/.well-known/openid-configuration",
            JWKSERVE_URL
        );
        eprintln!("      Start jwkserve with: docker-compose up -d");
        return;
    }

    let client = Arc::new(create_http_client());
    let jwks_uri = match rt.block_on(discover_jwks_uri(&client)) {
        Some(uri) => uri,
        None => {
            eprintln!("SKIP: Failed to discover JWKS URI");
            return;
        }
    };

    // Pre-populate cache
    if rt
        .block_on(jwks::fetch_jwks_cached(&client, &jwks_uri))
        .is_err()
    {
        eprintln!("SKIP: Failed to fetch JWKS");
        return;
    }

    let mut group = c.benchmark_group("jwks_cache_concurrent");
    group.throughput(Throughput::Elements(1));

    // Test concurrent cache hits
    for concurrency in [1, 4, 8, 16] {
        group.bench_with_input(
            BenchmarkId::from_parameter(concurrency),
            &concurrency,
            |b, &n| {
                let rt = &rt;
                let jwks_uri = jwks_uri.clone();
                let client = client.clone();
                b.iter(|| {
                    rt.block_on(async {
                        let tasks: Vec<_> = (0..n)
                            .map(|_| {
                                let jwks_uri = jwks_uri.clone();
                                let client = client.clone();
                                tokio::spawn(async move {
                                    jwks::fetch_jwks_cached(&client, &jwks_uri).await
                                })
                            })
                            .collect();
                        // Wait for all tasks
                        for task in tasks {
                            let _ = task.await;
                        }
                    })
                });
            },
        );
    }

    group.finish();
}

#[cfg(feature = "remote")]
fn bench_jwks_end_to_end(c: &mut Criterion) {
    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Check if jwkserve is available
    if !rt.block_on(is_jwkserve_available()) {
        eprintln!(
            "SKIP: jwkserve not available at {}/.well-known/openid-configuration",
            JWKSERVE_URL
        );
        eprintln!("      Start jwkserve with: docker-compose up -d");
        return;
    }

    let client = Arc::new(create_http_client());
    let jwks_uri = match rt.block_on(discover_jwks_uri(&client)) {
        Some(uri) => uri,
        None => {
            eprintln!("SKIP: Failed to discover JWKS URI");
            return;
        }
    };

    let mut group = c.benchmark_group("jwks_end_to_end");
    group.throughput(Throughput::Elements(1));

    group.bench_function("fetch_uncached", |b| {
        let rt = &rt;
        let jwks_uri = jwks_uri.clone();
        let client = client.clone();
        b.iter(|| {
            rt.block_on(async {
                // Use unique URI to bypass cache
                let unique_uri = format!(
                    "{}?t={}",
                    jwks_uri,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                );
                let _ = jwks::fetch_jwks(&client, &unique_uri).await;
            })
        });
    });

    group.bench_function("fetch_cached_first", |b| {
        let rt = &rt;
        let jwks_uri = jwks_uri.clone();
        let client = client.clone();
        b.iter(|| {
            rt.block_on(async {
                let _ = jwks::fetch_jwks_cached(&client, &jwks_uri).await;
            })
        });
    });

    group.finish();
}

#[cfg(feature = "remote")]
criterion_group!(
    benches,
    bench_jwks_cache_hit,
    bench_jwks_cache_miss,
    bench_jwks_parsing,
    bench_jwks_cache_concurrent,
    bench_jwks_end_to_end
);

#[cfg(not(feature = "remote"))]
fn bench_jwks_skip(_c: &mut Criterion) {
    eprintln!("SKIP: JWKS benchmarks require the 'remote' feature");
}

#[cfg(not(feature = "remote"))]
criterion_group!(benches, bench_jwks_skip);

criterion_main!(benches);
