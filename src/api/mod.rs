//! Axum HTTP router, shared application state, and security/observability middleware stack.

pub mod dto;
pub mod handlers;
pub mod middleware;

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware as axum_mw,
    routing::{get, post},
};
use tower_http::{
    cors::{Any, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{
    config::Config, db::repository::InvoiceRepository, rpc::client::MoneroRpcClient,
    services::scanner::ScannerService,
};

/// Shared thread-safe state injected into Axum handlers and auth middleware.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Validated runtime configuration.
    pub config: Arc<Config>,
    /// SQLite persistence repository.
    pub repo: InvoiceRepository,
    /// `monero-wallet-rpc` JSON-RPC 2.0 client.
    pub rpc: MoneroRpcClient,
    /// Background & on-demand scanner/sweeper coordinator.
    pub scanner: ScannerService,
}

/// Maximum permitted HTTP JSON request body size (64 KiB) (`XMR-038`).
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// Constructs the complete Axum [`Router`] with public healthcheck, authenticated `/api/v1/*`
/// endpoints, sensitive header redaction, request body bounds, timeouts, CORS, and tracing.
pub fn build_router(state: AppState) -> Router {
    let protected_v1 = Router::new()
        .route("/invoices", post(handlers::create_invoice))
        .route("/invoices/{invoice_id}", get(handlers::get_invoice))
        .route(
            "/invoices/{invoice_id}/sweep",
            post(handlers::sweep_invoice),
        )
        .route(
            "/invoices/{invoice_id}/webhooks/retry",
            post(handlers::retry_invoice_webhooks),
        )
        .route(
            "/webhooks/{webhook_id}/retry",
            post(handlers::retry_webhook),
        )
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::require_api_key,
        ));

    let cors = build_cors_layer(&state.config.cors_allowed_origins);
    let x_request_id = HeaderName::from_static("x-request-id");
    let x_api_key = HeaderName::from_static(middleware::API_KEY_HEADER);

    Router::new()
        .route("/health", get(handlers::health_check))
        .nest("/api/v1", protected_v1)
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(SetSensitiveRequestHeadersLayer::new([
            x_api_key,
            header::AUTHORIZATION,
            header::COOKIE,
        ]))
        .layer(PropagateRequestIdLayer::new(x_request_id.clone()))
        .layer(SetRequestIdLayer::new(x_request_id, MakeRequestUuid))
}

fn build_cors_layer(origins: &[String]) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static(middleware::API_KEY_HEADER),
        ]);

    if origins.is_empty() {
        return base;
    }

    if origins.iter().any(|o| o == "*") {
        return base.allow_origin(Any);
    }

    let parsed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();

    if parsed.is_empty() {
        base
    } else {
        base.allow_origin(parsed)
    }
}
