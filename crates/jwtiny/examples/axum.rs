//! Run with
//!
//! ```not_rust
//! cargo run --example axum
//! ```

use std::time::Duration;

use axum::{
    Router,
    extract::{Request, State},
    http::{StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::Response,
    routing::get,
};
use jwtiny::{AlgorithmPolicy, Claims, ClaimsValidation, TokenValidator};
use moka::future::Cache;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    validator: TokenValidator,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let client = reqwest::Client::new();
    let cache = Cache::<String, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let validator = TokenValidator::new()
        .algorithms(AlgorithmPolicy::rs512_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .jwks(client)
        .cache(cache);

    let state = AppState { validator };

    let app = Router::new()
        .route("/", get(handler))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            jwt_auth_middleware,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn jwt_auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let auth_str = auth_header.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;

    let token_str = auth_str
        .split_whitespace()
        .nth(1)
        .ok_or(StatusCode::BAD_REQUEST)?;

    tracing::debug!("Validating JWT token");

    let claims = state.validator.verify(token_str).await.map_err(|e| {
        tracing::warn!("JWT validation failed: {:?}", e);
        StatusCode::UNAUTHORIZED
    })?;

    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

async fn handler(axum::extract::Extension(claims): axum::extract::Extension<Claims>) -> String {
    let subject = claims
        .subject
        .as_ref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    format!("Hello, World! You are authorized: {subject}")
}
