#![forbid(unsafe_code)]

use std::{env, error::Error, net::SocketAddr};

use axum::{Json, Router, routing::get};
use serde::Serialize;
use tokio::{net::TcpListener, signal};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();

    let address: SocketAddr = env::var("SMCV_LISTEN_ADDR")
        .unwrap_or_else(|_| String::from(DEFAULT_LISTEN))
        .parse()?;
    if !address.ip().is_loopback() {
        return Err("phase-zero server refuses plaintext non-loopback binding".into());
    }

    let request_id_header = axum::http::HeaderName::from_static("x-request-id");
    let app = Router::new()
        .route("/health/live", get(health))
        .route("/health/ready", get(health))
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(TraceLayer::new_for_http())
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid));

    let listener = TcpListener::bind(address).await?;
    info!(listen_address = %address, "SMCV phase-zero server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
}
