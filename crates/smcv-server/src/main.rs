#![forbid(unsafe_code)]

use std::{env, error::Error, net::SocketAddr, path::PathBuf};

use smcv_server::{ApiState, router};
use tokio::{net::TcpListener, signal};
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

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
    let protected_transport = env::var("SMCV_PROTECTED_TRANSPORT").as_deref() == Ok("1");
    if !address.ip().is_loopback() && !protected_transport {
        return Err("unprotected HTTP may bind only to loopback".into());
    }
    let working_directory = env::current_dir()?;
    let data_directory = env::var_os("SMCV_DATA_DIR")
        .map_or_else(|| working_directory.join(".smcv-data"), PathBuf::from);
    let key_directory = env::var_os("SMCV_KEY_DIR")
        .map_or_else(|| working_directory.join(".smcv-key"), PathBuf::from);
    let rp_id = env::var("SMCV_RP_ID").unwrap_or_else(|_| String::from("localhost"));
    let origin =
        env::var("SMCV_ORIGIN").unwrap_or_else(|_| format!("http://localhost:{}", address.port()));
    let state = ApiState::open(
        &data_directory.join("vault.sqlite"),
        &key_directory.join("root.key"),
        &rp_id,
        &origin,
    )?;

    let listener = TcpListener::bind(address).await?;
    info!(listen_address = %address, "SMCV server listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
}
