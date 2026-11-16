//! HTTP route handlers for health checks, invoice lifecycle creation, status queries,
//! and manual sweep triggers.

use std::time::Duration;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::{Duration as ChronoDuration, Utc};
use uuid::Uuid;

use crate::{
    api::{
        AppState,
        dto::{
            CreateInvoiceRequest, CreateInvoiceResponse, HealthResponse, InvoiceStatusResponse,
            RpcHealthStatus, SweepInvoiceResponse,
        },
    },
    config::validate_http_url,
    domain::{
        amount::Piconero,
        invoice::{Invoice, InvoiceStatus, build_monero_uri, validate_order_id},
    },
    error::{GatewayError, GatewayResult},
    services::qr::generate_qr_png_base64,
};

/// Maximum permitted invoice TTL in seconds (30 days).
const MAX_INVOICE_TTL_SECONDS: u64 = 2_592_000;

/// Public healthcheck handler (`GET /health`).
///
/// Verifies SQLite readiness via `SELECT 1` and probes `monero-wallet-rpc` `get_version`
/// with a bounded 3-second timeout. Returns `503 Service Unavailable` if SQLite fails, or
/// `200 OK` with `"status": "ok" | "degraded"` depending on RPC reachability.
pub async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(err) = state.repo.health_check().await {
        tracing::error!(error = %err, "healthcheck SQLite failure");
        let body = HealthResponse {
            status: "unhealthy".to_string(),
            service: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            database: "disconnected".to_string(),
            monero_rpc: RpcHealthStatus {
                connected: false,
                version: None,
                error: Some("database unavailable".to_string()),
            },
            auto_sweep_enabled: state.config.enable_auto_sweep,
        };
        return (StatusCode::SERVICE_UNAVAILABLE, Json(body));
    }

    let rpc_status =
        match tokio::time::timeout(Duration::from_secs(3), state.rpc.get_version()).await {
            Ok(Ok(ver)) => RpcHealthStatus {
                connected: true,
                version: Some(ver.version),
                error: None,
            },
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "healthcheck monero-wallet-rpc probe failed");
                RpcHealthStatus {
                    connected: false,
                    version: None,
                    error: Some("monero-wallet-rpc unreachable".to_string()),
                }
            }
            Err(_) => RpcHealthStatus {
                connected: false,
                version: None,
                error: Some("monero-wallet-rpc healthcheck timed out".to_string()),
            },
        };

    let overall = if rpc_status.connected {
        "ok".to_string()
    } else {
        "degraded".to_string()
    };

    (
        StatusCode::OK,
        Json(HealthResponse {
            status: overall,
            service: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            database: "connected".to_string(),
            monero_rpc: rpc_status,
            auto_sweep_enabled: state.config.enable_auto_sweep,
        }),
    )
}

/// Creates a new isolated Monero subaddress invoice (`POST /api/v1/invoices`).
///
/// # Invariants
/// - Rejects `amount_piconero == 0` or values exceeding SQLite signed 64-bit integer bounds.
/// - Checks duplicate `order_id` BEFORE calling `monero-wallet-rpc` `create_address` so
///   retried requests do not allocate orphaned subaddresses in the wallet.
/// - Generates a dedicated subaddress under `account_index: 0` with label `inv_<order_id>`,
///   renders the Monero URI and Base64 PNG QR code, and persists in SQLite (`PENDING`).
///
/// # Errors
/// - `400 Bad Request` on invalid `order_id`, zero/overflow amount, invalid TTL, or invalid URL.
/// - `409 Conflict` if `order_id` already exists.
/// - `502 Bad Gateway` if `monero-wallet-rpc` fails.
pub async fn create_invoice(
    State(state): State<AppState>,
    Json(req): Json<CreateInvoiceRequest>,
) -> GatewayResult<(StatusCode, Json<CreateInvoiceResponse>)> {
    validate_order_id(&req.order_id)?;

    if req.amount_piconero == 0 {
        return Err(GatewayError::Validation(
            "amount_piconero must be greater than 0".to_string(),
        ));
    }

    let amount = Piconero(req.amount_piconero);
    // Validate SQLite signed 64-bit bound before allocating a wallet subaddress.
    let _ = amount.to_i64()?;

    let ttl_seconds = req.ttl_seconds.unwrap_or(state.config.invoice_ttl_seconds);
    if ttl_seconds == 0 || ttl_seconds > MAX_INVOICE_TTL_SECONDS {
        return Err(GatewayError::Validation(format!(
            "ttl_seconds must be between 1 and {MAX_INVOICE_TTL_SECONDS}"
        )));
    }
    let ttl_i64 = i64::try_from(ttl_seconds)
        .map_err(|_| GatewayError::Validation("ttl_seconds overflow".to_string()))?;

    let callback_url = match req.callback_url {
        Some(url) => {
            let trimmed = url.trim().to_string();
            if trimmed.is_empty() {
                return Err(GatewayError::Validation(
                    "callback_url cannot be empty when specified".to_string(),
                ));
            }
            validate_http_url(&trimmed, "callback_url")
                .map_err(|e| GatewayError::Validation(e.to_string()))?;
            Some(trimmed)
        }
        None => state.config.default_webhook_url.clone(),
    };

    if state
        .repo
        .get_invoice_by_order_id(&req.order_id)
        .await?
        .is_some()
    {
        return Err(GatewayError::Conflict(format!(
            "invoice for order_id '{}' already exists",
            req.order_id
        )));
    }

    let label = format!("inv_{}", req.order_id);
    let rpc_addr = state.rpc.create_address(0, &label).await?;

    let monero_uri = build_monero_uri(&rpc_addr.address, amount, &req.order_id);
    let qr_code_base64 = generate_qr_png_base64(&monero_uri)?;

    let now = Utc::now();
    let invoice = Invoice {
        id: Uuid::new_v4(),
        order_id: req.order_id,
        account_index: 0,
        address_index: rpc_addr.address_index,
        subaddress: rpc_addr.address,
        amount_piconero: amount,
        received_piconero: Piconero::ZERO,
        confirmations: 0,
        unlocked: false,
        double_spend_seen: false,
        status: InvoiceStatus::Pending,
        callback_url,
        monero_uri,
        qr_code_base64,
        sweep_tx_hashes: Vec::new(),
        sweep_amount_piconero: None,
        sweep_fee_piconero: None,
        last_sweep_error: None,
        created_at: now,
        updated_at: now,
        expires_at: now + ChronoDuration::seconds(ttl_i64),
        confirmed_at: None,
        swept_at: None,
        completed_at: None,
    };

    state.repo.insert_invoice(&invoice).await?;

    tracing::info!(
        invoice_id = %invoice.id,
        order_id = %invoice.order_id,
        address_index = invoice.address_index,
        amount_piconero = invoice.amount_piconero.as_u64(),
        "created non-custodial Monero invoice"
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateInvoiceResponse::from(&invoice)),
    ))
}

/// Retrieves detailed status, transfer breakdown, and sweep hashes (`GET /api/v1/invoices/{invoice_id}`).
///
/// # Errors
/// - `400 Bad Request` if `invoice_id` is not a valid UUID.
/// - `404 Not Found` if no invoice matches `invoice_id`.
pub async fn get_invoice(
    State(state): State<AppState>,
    Path(invoice_id_raw): Path<String>,
) -> GatewayResult<Json<InvoiceStatusResponse>> {
    let invoice_id = parse_invoice_uuid(&invoice_id_raw)?;

    let invoice = state
        .repo
        .get_invoice_by_id(invoice_id)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("invoice {invoice_id} not found")))?;

    let transfers = state.repo.list_transfers_for_invoice(invoice_id).await?;

    Ok(Json(InvoiceStatusResponse::from_invoice(
        &invoice, &transfers,
    )))
}

/// Triggers an immediate sweep of a confirmed, unlocked subaddress (`POST /api/v1/invoices/{invoice_id}/sweep`).
///
/// # Errors
/// - `400 Bad Request` if `invoice_id` is not a valid UUID.
/// - `404 Not Found` if invoice does not exist.
/// - `409 Conflict` if auto-sweep is disabled, invoice is already swept/completed/expired,
///   underpaid, or funds have not reached Monero's 10-block unlock threshold.
pub async fn sweep_invoice(
    State(state): State<AppState>,
    Path(invoice_id_raw): Path<String>,
) -> GatewayResult<Json<SweepInvoiceResponse>> {
    let invoice_id = parse_invoice_uuid(&invoice_id_raw)?;
    let swept = state.scanner.manual_sweep(invoice_id).await?;

    let sweep_amount = swept.sweep_amount_piconero.unwrap_or(Piconero::ZERO);
    let sweep_fee = swept.sweep_fee_piconero.unwrap_or(Piconero::ZERO);
    let swept_at = swept.swept_at.unwrap_or(swept.updated_at);

    Ok(Json(SweepInvoiceResponse {
        invoice_id: swept.id,
        order_id: swept.order_id,
        status: swept.status,
        sweep_tx_hashes: swept.sweep_tx_hashes,
        sweep_amount_piconero: sweep_amount.as_u64(),
        sweep_amount_xmr_formatted: sweep_amount.to_xmr_string(),
        sweep_fee_piconero: sweep_fee.as_u64(),
        sweep_fee_xmr_formatted: sweep_fee.to_xmr_string(),
        swept_at,
    }))
}

fn parse_invoice_uuid(raw: &str) -> GatewayResult<Uuid> {
    Uuid::parse_str(raw.trim())
        .map_err(|_| GatewayError::Validation(format!("invalid invoice_id UUID '{raw}'")))
}
