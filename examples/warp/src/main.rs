//! Run with
//!
//! ```not_rust
//! cargo run -p jwtiny-example-warp
//! ```

use std::{convert::Infallible, time::Duration};

use jwtiny::{AlgorithmPolicy, Claims, ClaimsValidation, TokenValidator};
use moka::future::Cache;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use warp::{Filter, Rejection, Reply};

#[derive(Clone)]
struct AppState {
    validator: TokenValidator,
}

fn with_state(state: AppState) -> impl Filter<Extract = (AppState,), Error = Infallible> + Clone {
    warp::any().map(move || state.clone())
}

async fn jwt_auth(header: Option<String>, state: AppState) -> Result<Claims, Rejection> {
    let auth_header = header.ok_or_else(|| {
        tracing::warn!("Missing Authorization header");
        warp::reject::custom(MissingAuth)
    })?;

    let token_str = auth_header.split_whitespace().nth(1).ok_or_else(|| {
        tracing::warn!("Invalid Authorization header format");
        warp::reject::custom(InvalidAuth)
    })?;

    tracing::debug!("Validating JWT token");

    let claims = state.validator.verify(token_str).await.map_err(|e| {
        tracing::warn!("JWT validation failed: {:?}", e);
        warp::reject::custom(InvalidToken)
    })?;

    Ok(claims)
}

fn with_claims(state: AppState) -> impl Filter<Extract = (Claims,), Error = Rejection> + Clone {
    warp::header::optional::<String>("authorization")
        .and(with_state(state))
        .and_then(jwt_auth)
}

#[derive(Debug)]
struct MissingAuth;

impl warp::reject::Reject for MissingAuth {}

#[derive(Debug)]
struct InvalidAuth;

impl warp::reject::Reject for InvalidAuth {}

#[derive(Debug)]
struct InvalidToken;

impl warp::reject::Reject for InvalidToken {}

async fn handler(claims: Claims) -> Result<impl Reply, Infallible> {
    let subject = claims
        .subject
        .as_ref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    Ok(format!("Hello, World! You are authorized: {subject}"))
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

    let routes = warp::path::end()
        .and(with_claims(state))
        .and_then(handler)
        .recover(|rej: Rejection| async move {
            let code;
            let msg;

            if rej.find::<MissingAuth>().is_some() {
                code = warp::http::StatusCode::UNAUTHORIZED;
                msg = "Missing Authorization header";
            } else if rej.find::<InvalidAuth>().is_some() {
                code = warp::http::StatusCode::BAD_REQUEST;
                msg = "Invalid Authorization header";
            } else if rej.find::<InvalidToken>().is_some() {
                code = warp::http::StatusCode::UNAUTHORIZED;
                msg = "Invalid or expired token";
            } else {
                code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
                msg = "Internal server error";
            }

            Ok::<_, Infallible>(warp::reply::with_status(msg, code))
        });

    tracing::debug!("listening on 127.0.0.1:4000");
    warp::serve(routes).run(([127, 0, 0, 1], 4000)).await;
}
