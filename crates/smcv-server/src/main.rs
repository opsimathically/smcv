#![forbid(unsafe_code)]

use std::{env, error::Error, net::TcpListener as StdTcpListener};

use smcv_server::{
    ApiState, lab_https,
    lab_https::PreparedLabHttps,
    operational_router,
    operations::{LogFormat, ServerRuntimeConfig},
    router,
};
use tokio::{net::TcpListener, signal, sync::oneshot, task::JoinSet};
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
    let prepared_lab_https = if let Some(lab_config) = &config.lab_https {
        let prepared = lab_https::prepare(lab_config).await?;
        info!(
            listen_address = %lab_config.listen_address,
            server_name = %lab_config.server_name,
            certificate_source = prepared.source_label,
            certificate_fingerprint_sha256 = %prepared.fingerprint_sha256,
            certificate_not_after_unix_seconds = prepared.not_after_unix_seconds,
            "SMCV native lab HTTPS identity ready"
        );
        Some(prepared)
    } else {
        None
    };
    if preflight_only {
        println!("status=ready");
        println!("configuration={}", config.safe_summary());
        if let (Some(lab_config), Some(prepared)) = (&config.lab_https, &prepared_lab_https) {
            println!("lab_https_origin={}", lab_config.https_origin());
            println!(
                "lab_https_certificate_fingerprint_sha256={}",
                prepared.fingerprint_sha256
            );
            println!(
                "lab_https_certificate_not_after_unix_seconds={}",
                prepared.not_after_unix_seconds
            );
        }
        return Ok(());
    }
    serve(config, state, prepared_lab_https).await
}

async fn serve(
    config: ServerRuntimeConfig,
    state: ApiState,
    prepared_lab_https: Option<PreparedLabHttps>,
) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(config.listen_address).await?;
    let metrics_listener = if let Some(metrics_address) = config.metrics_address {
        Some((metrics_address, TcpListener::bind(metrics_address).await?))
    } else {
        None
    };
    let lab_server =
        if let (Some(lab_config), Some(prepared)) = (&config.lab_https, prepared_lab_https) {
            let listener = StdTcpListener::bind(lab_config.listen_address)?;
            listener.set_nonblocking(true)?;
            Some((
                lab_config.listen_address,
                axum_server::from_tcp_rustls(listener, prepared.rustls)?,
            ))
        } else {
            None
        };

    let mut servers: JoinSet<Result<(), &'static str>> = JoinSet::new();
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let product_state = state.clone();
    servers.spawn(async move {
        axum::serve(
            listener,
            router(product_state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_receiver.await;
        })
        .await
        .map_err(|_| "product server failed")
    });
    info!(listen_address = %config.listen_address, "SMCV loopback product server listening");

    let mut metrics_shutdown = None;
    if let Some((metrics_address, listener)) = metrics_listener {
        let (sender, receiver) = oneshot::channel();
        metrics_shutdown = Some(sender);
        let metrics_state = state.clone();
        servers.spawn(async move {
            axum::serve(
                listener,
                operational_router(metrics_state).into_make_service(),
            )
            .with_graceful_shutdown(async move {
                let _ = receiver.await;
            })
            .await
            .map_err(|_| "metrics server failed")
        });
        info!(listen_address = %metrics_address, "SMCV local metrics listening");
    }

    let mut lab_handle = None;
    if let Some((listen_address, server)) = lab_server {
        let handle = axum_server::Handle::new();
        let server = server.handle(handle.clone()).serve(
            // The routers share vault, authentication, rate-limit, and
            // audit state across ingress paths.
            router(state.clone()).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        );
        servers.spawn(async move { server.await.map_err(|_| "native HTTPS server failed") });
        lab_handle = Some(handle);
        info!(listen_address = %listen_address, "SMCV native lab HTTPS server listening");
    }

    let unexpected_exit = tokio::select! {
        () = shutdown_signal() => None,
        result = servers.join_next() => Some(match result {
            Some(Ok(Ok(()))) => "server exited unexpectedly",
            Some(Ok(Err(error))) => error,
            Some(Err(_)) => "server task failed",
            None => "all server tasks exited unexpectedly",
        }),
    };
    info!("SMCV graceful shutdown requested");
    let _ = shutdown_sender.send(());
    if let Some(sender) = metrics_shutdown {
        let _ = sender.send(());
    }
    if let Some(handle) = lab_handle {
        handle.graceful_shutdown(Some(config.shutdown_grace));
    }
    let drain_result = tokio::time::timeout(config.shutdown_grace, async move {
        let mut first_error = None;
        while let Some(result) = servers.join_next().await {
            let result = result.unwrap_or(Err("server task failed"));
            if first_error.is_none() {
                first_error = result.err();
            }
        }
        first_error.map_or(Ok(()), Err)
    })
    .await;
    match drain_result {
        Ok(result) => result.map_err(|error| -> Box<dyn Error> { error.into() })?,
        Err(_) => return Err("graceful shutdown deadline exceeded".into()),
    }
    if let Some(error) = unexpected_exit {
        return Err(error.into());
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
