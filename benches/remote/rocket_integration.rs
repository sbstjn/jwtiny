use criterion::{Criterion, black_box, criterion_group, criterion_main};
use jwtiny::{AlgorithmPolicy, ClaimsValidation, TokenValidator};
use moka::future::Cache;
use rocket::{
    config::{Config, LogLevel},
    http::Status,
    request::{FromRequest, Outcome, Request},
};
use serde_json::json;
use std::time::Duration;
use tokio::sync::oneshot;

const JWKSERVE_URL: &str = "http://127.0.0.1:3000";
const ISSUER: &str = "http://127.0.0.1:3000";
const ROCKET_PORT: u16 = 4000;

#[derive(Clone)]
struct AppState {
    validator: TokenValidator,
}

pub struct Authenticated(pub jwtiny::Claims);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authenticated {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let state = match request.rocket().state::<AppState>() {
            Some(s) => s.clone(),
            None => return Outcome::Error((Status::InternalServerError, ())),
        };

        let auth_header = match request.headers().get_one("authorization") {
            Some(h) => h,
            None => return Outcome::Error((Status::Unauthorized, ())),
        };

        let token_str = match auth_header.split_whitespace().nth(1) {
            Some(t) => t,
            None => return Outcome::Error((Status::BadRequest, ())),
        };

        let claims = match state.validator.verify(token_str).await {
            Ok(c) => c,
            Err(_) => return Outcome::Error((Status::Unauthorized, ())),
        };

        Outcome::Success(Authenticated(claims))
    }
}

#[rocket::get("/")]
async fn handler(_auth: Authenticated) -> &'static str {
    "OK"
}

#[rocket::catch(401)]
fn unauthorized() -> &'static str {
    "Unauthorized"
}

#[rocket::catch(400)]
fn bad_request() -> &'static str {
    "Bad Request"
}

#[rocket::catch(500)]
fn internal_server_error() -> &'static str {
    "Internal Server Error"
}

/// Generate a JWT token using jwkserve's /sign endpoint with the specified algorithm
async fn generate_token(algorithm: &str) -> String {
    let client = reqwest::Client::new();
    let claims = json!({
        "sub": "benchmark-user",
        "aud": "my-api",
        "iss": ISSUER,
    });

    let response = client
        .post(&format!("{}/sign/{}", JWKSERVE_URL, algorithm))
        .json(&claims)
        .send()
        .await
        .expect("Failed to connect to jwkserve. Ensure it's running on http://127.0.0.1:3000");

    if !response.status().is_success() {
        panic!("jwkserve returned error: {}", response.status());
    }

    let body: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse jwkserve response");

    body.get("token")
        .and_then(|t| t.as_str())
        .expect("Missing token in jwkserve response")
        .to_string()
}

/// Start a Rocket server with the specified validator configuration
async fn start_rocket_server(
    policy: AlgorithmPolicy,
    use_cache: bool,
) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let client = reqwest::Client::new();
    let validator = if use_cache {
        let cache = Cache::<String, Vec<u8>>::builder()
            .time_to_live(Duration::from_secs(300))
            .max_capacity(1000)
            .build();

        TokenValidator::new()
            .algorithms(policy)
            .issuer(|iss| iss == ISSUER)
            .validate(ClaimsValidation::default().require_audience("my-api"))
            .jwks(client)
            .cache(cache)
    } else {
        TokenValidator::new()
            .algorithms(policy)
            .issuer(|iss| iss == ISSUER)
            .validate(ClaimsValidation::default().require_audience("my-api"))
            .jwks(client)
    };

    let state = AppState { validator };

    let config = Config {
        port: ROCKET_PORT,
        address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        log_level: LogLevel::Critical,
        ..Config::default()
    };

    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let rocket_handle = tokio::spawn(async move {
        let rocket = rocket::custom(&config)
            .manage(state)
            .register(
                "/",
                rocket::catchers![unauthorized, bad_request, internal_server_error],
            )
            .mount("/", rocket::routes![handler]);

        let rocket = rocket.ignite().await.unwrap();
        let shutdown = rocket.shutdown();

        tokio::select! {
            _ = rocket.launch() => {},
            _ = shutdown_rx => {
                shutdown.notify();
            }
        }
    });

    // Wait for server to be ready by checking if the port is listening
    // We check the TCP connection directly to avoid triggering the auth guard
    for _ in 0..50 {
        match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ROCKET_PORT)).await {
            Ok(_) => break,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }

    (shutdown_tx, rocket_handle)
}

/// Benchmark Rocket integration for a specific algorithm and cache configuration
fn benchmark_rocket_integration(
    c: &mut Criterion,
    algorithm: &str,
    algorithm_policy: AlgorithmPolicy,
    use_cache: bool,
) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Generate token
    let token = rt.block_on(generate_token(algorithm));

    // Start Rocket server
    let (shutdown_tx, rocket_handle) =
        rt.block_on(start_rocket_server(algorithm_policy, use_cache));

    let cache_label = if use_cache {
        "with-cache"
    } else {
        "without-cache"
    };
    let algorithm_name = match algorithm {
        "RS256" => "SHA-256",
        "RS384" => "SHA-384",
        "RS512" => "SHA-512",
        _ => unreachable!(),
    };

    let bench_name = format!(
        "jwtiny-rocket-{}-validation-{}",
        algorithm_name, cache_label
    );

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}", ROCKET_PORT);
    let auth_header = format!("Bearer {}", token);

    c.bench_function(&bench_name, |b| {
        b.iter(|| {
            rt.block_on(async {
                let response = client
                    .get(&url)
                    .header("authorization", &auth_header)
                    .send()
                    .await
                    .unwrap();
                black_box(response.status());
            });
        });
    });

    // Shutdown server
    let _ = shutdown_tx.send(());
    rt.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(5), rocket_handle).await;
    });
}

fn benchmark_rocket_sha_256_without_cache(c: &mut Criterion) {
    benchmark_rocket_integration(c, "RS256", AlgorithmPolicy::rs256_only(), false);
}

fn benchmark_rocket_sha_256_with_cache(c: &mut Criterion) {
    benchmark_rocket_integration(c, "RS256", AlgorithmPolicy::rs256_only(), true);
}

fn benchmark_rocket_sha_384_without_cache(c: &mut Criterion) {
    benchmark_rocket_integration(c, "RS384", AlgorithmPolicy::rs384_only(), false);
}

fn benchmark_rocket_sha_384_with_cache(c: &mut Criterion) {
    benchmark_rocket_integration(c, "RS384", AlgorithmPolicy::rs384_only(), true);
}

fn benchmark_rocket_sha_512_without_cache(c: &mut Criterion) {
    benchmark_rocket_integration(c, "RS512", AlgorithmPolicy::rs512_only(), false);
}

fn benchmark_rocket_sha_512_with_cache(c: &mut Criterion) {
    benchmark_rocket_integration(c, "RS512", AlgorithmPolicy::rs512_only(), true);
}

criterion_group!(
    benches,
    benchmark_rocket_sha_256_without_cache,
    benchmark_rocket_sha_256_with_cache,
    benchmark_rocket_sha_384_without_cache,
    benchmark_rocket_sha_384_with_cache,
    benchmark_rocket_sha_512_without_cache,
    benchmark_rocket_sha_512_with_cache
);
criterion_main!(benches);
