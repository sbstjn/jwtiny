//! Run with
//!
//! ```not_rust
//! cargo run -p jwtiny-example-rocket
//! ```

use std::time::Duration;

use jwtiny::{claims, AlgorithmPolicy, ClaimsValidation, TokenValidator};
use moka::future::Cache;
use rocket::{
    config::{Config, LogLevel},
    http::Status,
    request::{FromRequest, Outcome, Request},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[claims]
pub struct CustomClaims {
    #[serde(rename = "email")]
    pub email: Option<String>,
    #[serde(rename = "role")]
    pub role: Option<String>,
    #[serde(rename = "permission_list")]
    pub permissions: Option<Vec<String>>,
}

#[derive(Clone)]
struct AppState {
    validator: TokenValidator,
}

pub struct Authenticated(pub CustomClaims);

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

        tracing::debug!("Validating JWT token");

        let claims = match state
            .validator
            .verify_with_custom::<CustomClaims>(token_str)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("JWT validation failed: {:?}", e);
                return Outcome::Error((Status::Unauthorized, ()));
            }
        };

        Outcome::Success(Authenticated(claims))
    }
}

#[rocket::get("/")]
async fn handler(auth: Authenticated) -> String {
    let subject = auth
        .0
        .subject
        .as_ref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    format!("Hello, World! You are authorized: {subject}")
}

#[rocket::launch]
async fn rocket() -> _ {
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

    let config = Config {
        port: 4000,
        address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        log_level: LogLevel::Normal,
        ..Config::default()
    };

    tracing::debug!("listening on 127.0.0.1:4000");

    rocket::custom(&config)
        .manage(state)
        .mount("/", rocket::routes![handler])
}
