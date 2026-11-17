//! Entrypoint binary for `xmr-gateway`.
//!
//! Initializes structured tracing, loads validated environment configuration, runs SQLite
//! WAL-mode migrations, spawns the background scanner and webhook retry workers, and serves
//! the Axum REST API until `SIGINT` or `SIGTERM` triggers a graceful shutdown.

#![deny(missing_docs)]

use std::{sync::Arc, time::Duration};

use tokio::{net::TcpListener, sync::watch};
use tracing_subscriber::{EnvFilter, fmt};

use xmr_gateway::{
    api::{AppState, build_router},
    config::{Config, LogFormat},
    db::{acquire_database_lock, init_sqlite_pool, repository::InvoiceRepository},
    error::{GatewayError, GatewayResult},
    rpc::client::MoneroRpcClient,
    security::url_policy::resolve_and_validate_webhook_url,
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

    if let Some(ref default_url) = config.default_webhook_url {
        resolve_and_validate_webhook_url(
            default_url,
            "DEFAULT_WEBHOOK_URL",
            config.webhook_url_policy(),
        )
        .await?;
    }

    tracing::info!(
        bind_addr = %config.bind_addr(),
        wallet_mode = config.wallet_mode.as_str(),
        monero_trusted_daemon = config.monero_trusted_daemon,
        auto_sweep = config.enable_auto_sweep,
        required_confirmations = config.required_confirmations,
        scan_interval_seconds = config.scan_interval_seconds,
        "starting xmr-gateway"
    );

    let _db_lock = acquire_database_lock(&config.database_url)?;
    let pool = init_sqlite_pool(&config.database_url).await?;
    let repo = InvoiceRepository::new(pool.clone());
    let rpc = MoneroRpcClient::new(
        &config.monero_rpc_url,
        config.monero_rpc_user.clone(),
        config.monero_rpc_pass.clone(),
    )?;
    rpc.verify_wallet_mode(config.wallet_mode).await?;

    if let Some(ref cold_addr) = config.cold_wallet_address {
        let addr_check = rpc.validate_address(cold_addr).await?;
        if !addr_check.valid {
            return Err(GatewayError::Config(format!(
                "COLD_WALLET_ADDRESS failed monero-wallet-rpc validate_address check for active network (nettype='{}')",
                addr_check.nettype
            )));
        }
    }

    let scanner = ScannerService::new(repo.clone(), rpc.clone(), config.clone());
    match scanner.reconcile_in_flight_sweeps().await {
        Ok(0) => {}
        Ok(count) => tracing::warn!(
            reconciled_sweeps = count,
            "reconciled interrupted in-flight sweep attempts at startup"
        ),
        Err(err) => tracing::warn!(
            error = %err,
            "startup sweep reconciliation deferred to background scanner"
        ),
    }

    let webhook_dispatcher = WebhookDispatcher::new(
        repo.clone(),
        config.enable_auto_sweep,
        Duration::from_secs(config.webhook_poll_interval_seconds),
        config.webhook_url_policy(),
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
    tracing::info!("xmr-gateway shutdown complete");
    Ok(())
}

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,xmr_gateway=debug"));

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
