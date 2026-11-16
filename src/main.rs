//! Entrypoint binary for `xmr-ancap-gateway`.
//!
//! Initializes structured tracing, loads validated environment configuration, runs SQLite
//! WAL-mode migrations, spawns the background scanner and webhook retry workers, and serves
//! the Axum REST API until `SIGINT` or `SIGTERM` triggers a graceful shutdown.

#![deny(missing_docs)]

use std::{sync::Arc, time::Duration};

use tokio::{net::TcpListener, sync::watch};
use tracing_subscriber::{EnvFilter, fmt};

use xmr_ancap_gateway::{
    api::{AppState, build_router},
    config::{Config, LogFormat},
    db::{init_sqlite_pool, repository::InvoiceRepository},
    error::{GatewayError, GatewayResult},
    rpc::client::MoneroRpcClient,
    services::{scanner::ScannerService, webhook::WebhookDispatcher},
};

#[tokio::main]
async fn main() {
    if let Err(err) = run_gateway().await {
        eprintln!("fatal startup error: {err}");
        std::process::exit(1);
    }
}

async fn run_gateway() -> GatewayResult<()> {
    // Load .env if present (shell environment variables always take precedence).
    let _ = dotenvy::dotenv();

    let config = Arc::new(Config::from_env()?);
    init_tracing(config.log_format);

    tracing::info!(
        bind_addr = %config.bind_addr(),
        auto_sweep = config.enable_auto_sweep,
        required_confirmations = config.required_confirmations,
        scan_interval_seconds = config.scan_interval_seconds,
        "starting xmr-ancap-gateway"
    );

    let pool = init_sqlite_pool(&config.database_url).await?;
    let repo = InvoiceRepository::new(pool.clone());
    let rpc = MoneroRpcClient::new(
        &config.monero_rpc_url,
        config.monero_rpc_user.clone(),
        config.monero_rpc_pass.clone(),
    )?;

    let scanner = ScannerService::new(repo.clone(), rpc.clone(), config.clone());
    let webhook_dispatcher = WebhookDispatcher::new(
        repo.clone(),
        config.enable_auto_sweep,
        Duration::from_secs(config.webhook_poll_interval_seconds),
    )?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let scanner_handle = tokio::spawn(scanner.clone().run(shutdown_rx.clone()));
    let webhook_handle = tokio::spawn(webhook_dispatcher.run(shutdown_rx));

    let state = AppState {
        config: config.clone(),
        repo,
        rpc,
        scanner,
    };
    let router = build_router(state);

    let listener = TcpListener::bind(&config.bind_addr()).await.map_err(|e| {
        GatewayError::Internal(format!(
            "failed to bind TCP listener on {}: {e}",
            config.bind_addr()
        ))
    })?;

    tracing::info!(address = %config.bind_addr(), "HTTP API listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| GatewayError::Internal(format!("HTTP server error: {e}")))?;

    tracing::info!("HTTP server stopped; signaling background workers to exit");
    let _ = shutdown_tx.send(true);

    if let Err(err) = scanner_handle.await {
        tracing::error!(error = %err, "scanner worker panicked during shutdown");
    }
    if let Err(err) = webhook_handle.await {
        tracing::error!(error = %err, "webhook dispatcher panicked during shutdown");
    }

    pool.close().await;
    tracing::info!("xmr-ancap-gateway shutdown complete");
    Ok(())
}

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,xmr_ancap_gateway=debug"));

    match format {
        LogFormat::Json => {
            fmt().with_env_filter(filter).json().init();
        }
        LogFormat::Pretty => {
            fmt().with_env_filter(filter).pretty().init();
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "failed to install Ctrl+C signal handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "failed to install SIGTERM signal handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received SIGINT (Ctrl+C)"),
        () = terminate => tracing::info!("received SIGTERM"),
    }
}
