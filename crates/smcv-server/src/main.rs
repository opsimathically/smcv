#![forbid(unsafe_code)]

use std::{env, error::Error};

use smcv_server::{
    operational_router,
    operations::{LogFormat, ServerRuntimeConfig},
    router,
};
use tokio::{net::TcpListener, signal, sync::oneshot};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let preflight_only = match arguments.as_slice() {
        [] => false,
        [argument] if argument == "preflight" => true,
        _ => return Err("usage: smcv-server [preflight]".into()),
    };
    let config = ServerRuntimeConfig::from_environment()?;
    initialize_logging(config.log_format);
    info!(configuration = %config.safe_summary(), "SMCV startup preflight beginning");
    let state = config.open_state()?;
    if preflight_only {
        println!("status=ready");
        println!("configuration={}", config.safe_summary());
        return Ok(());
    }

    let listener = TcpListener::bind(config.listen_address).await?;
    info!(listen_address = %config.listen_address, "SMCV server listening");
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let product_state = state.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router(product_state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_receiver.await;
        })
        .await
    });
    let mut metrics_shutdown = None;
    let mut metrics_server = None;
    if let Some(metrics_address) = config.metrics_address {
        let listener = TcpListener::bind(metrics_address).await?;
        let (sender, receiver) = oneshot::channel();
        metrics_shutdown = Some(sender);
        metrics_server = Some(tokio::spawn(async move {
            axum::serve(listener, operational_router(state).into_make_service())
                .with_graceful_shutdown(async move {
                    let _ = receiver.await;
                })
                .await
        }));
        info!(listen_address = %metrics_address, "SMCV local metrics listening");
    }
    shutdown_signal().await;
    info!("SMCV graceful shutdown requested");
    let _ = shutdown_sender.send(());
    if let Some(sender) = metrics_shutdown {
        let _ = sender.send(());
    }
    match tokio::time::timeout(config.shutdown_grace, async move {
        server
            .await
            .map_err(|_| "product server task failed")?
            .map_err(|_| "product server failed")?;
        if let Some(metrics_server) = metrics_server {
            metrics_server
                .await
                .map_err(|_| "metrics server task failed")?
                .map_err(|_| "metrics server failed")?;
        }
        Ok::<(), &'static str>(())
    })
    .await
    {
        Ok(result) => result.map_err(|error| -> Box<dyn Error> { error.into() })?,
        Err(_) => return Err("graceful shutdown deadline exceeded".into()),
    }
    Ok(())
}

fn initialize_logging(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match format {
        LogFormat::Compact => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .json()
            .flatten_event(true)
            .init(),
    }
}

#[cfg(unix)]
async fn shutdown_signal() {
    let terminate = signal::unix::signal(signal::unix::SignalKind::terminate());
    if let Ok(mut terminate) = terminate {
        tokio::select! {
            _ = signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    } else {
        let _ = signal::ctrl_c().await;
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
}
