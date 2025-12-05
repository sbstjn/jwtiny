//! Run with
//!
//! ```not_rust
//! cargo run -p jwtiny-example-poem
//! ```

use std::time::Duration;

use jwtiny::{AlgorithmPolicy, Claims, ClaimsValidation, RemoteCacheKey, TokenValidator};
use moka::future::Cache;
use poem::{
    handler,
    http::{header::AUTHORIZATION, StatusCode},
    listener::TcpListener,
    Endpoint, EndpointExt, Error, IntoResponse, Request, Response, Result, Route, Server,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    validator: TokenValidator,
}

async fn jwt_auth<E: Endpoint>(next: E, mut req: Request) -> Result<Response> {
    let state = match req.data::<AppState>() {
        Some(s) => s.clone(),
        None => {
            return Err(Error::from_status(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };

    let auth_header = match req.headers().get(AUTHORIZATION) {
        Some(h) => h,
        None => {
            return Err(Error::from_status(StatusCode::UNAUTHORIZED));
        }
    };

    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
    };

    let token_str = match auth_str.split_whitespace().nth(1) {
        Some(t) => t,
        None => {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
    };

    tracing::debug!("Validating JWT token");

    let claims = match state.validator.verify(token_str).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("JWT validation failed: {:?}", e);
            return Err(Error::from_status(StatusCode::UNAUTHORIZED));
        }
    };

    req.extensions_mut().insert(claims);
    let res = next.call(req).await;

    match res {
        Ok(resp) => {
            let resp = resp.into_response();
            Ok(resp)
        }
        Err(err) => Err(err),
    }
}

#[handler]
async fn handler(req: &Request) -> poem::Result<String> {
    let claims = req
        .extensions()
        .get::<Claims>()
        .ok_or_else(|| Error::from_status(StatusCode::UNAUTHORIZED))?;

    let subject = claims
        .subject
        .as_ref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    Ok(format!("Hello, World! You are authorized: {subject}"))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let client = reqwest::Client::new();
    let cache = Cache::<RemoteCacheKey, Vec<u8>>::builder()
        .time_to_live(Duration::from_secs(300))
        .max_capacity(1000)
        .build();

    let validator = TokenValidator::new()
        .algorithms(AlgorithmPolicy::rs512_only())
        .issuer(|_| true)
        .validate(ClaimsValidation::default())
        .jwks(client)
        .cache(cache)
        .build();

    let state = AppState { validator };

    let app = Route::new().at("/", handler).around(jwt_auth).data(state);

    let listener = TcpListener::bind("127.0.0.1:4000");
    tracing::debug!("listening on 127.0.0.1:4000");
    Server::new(listener).run(app).await
}
