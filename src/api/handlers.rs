//! HTTP route handlers for health checks, invoice lifecycle creation, status queries,
//! and manual sweep triggers.

use std::time::Duration;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::{Duration as ChronoDuration, Utc};
use uuid::Uuid;

use crate::{
    api::{
        AppState,
        dto::{
            CreateInvoiceRequest, CreateInvoiceResponse, HealthResponse, InvoiceStatusResponse,
            RetryWebhookResponse, RpcHealthStatus, SweepInvoiceResponse,
        },
        middleware::{API_KEY_HEADER, constant_time_key_match},
    },
    domain::{
        amount::Piconero,
        invoice::{Invoice, InvoiceStatus, build_monero_uri, validate_order_id},
    },
    error::{GatewayError, GatewayResult},
    security::url_policy::resolve_and_validate_webhook_url,
    services::qr::generate_qr_png_base64,
};

/// Maximum permitted invoice TTL in seconds (30 days).
const MAX_INVOICE_TTL_SECONDS: u64 = 2_592_000;

/// Public / authenticated healthcheck handler (`GET /health`) (`XMR-033`).
///
/// Unauthenticated requests receive ONLY `{"status": "ok" | "degraded" | "unhealthy"}` without
/// leaking service version, internal error details, RPC metadata, or custody mode. Requests
/// carrying a valid `X-API-Key` header receive full diagnostic telemetry.
pub async fn health_check(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let authorized = headers
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|presented| constant_time_key_match(presented, &state.config.api_secret_key));

    if let Err(err) = state.repo.health_check().await {
        tracing::error!(error = %err, "healthcheck SQLite failure");
        let body = if authorized {
            HealthResponse {
                status: "unhealthy".to_string(),
                service: Some(env!("CARGO_PKG_NAME").to_string()),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                database: Some("disconnected".to_string()),
                monero_rpc: Some(RpcHealthStatus {
                    connected: false,
                    version: None,
                    error: Some("database unavailable".to_string()),
                }),
                auto_sweep_enabled: Some(state.config.enable_auto_sweep),
            }
        } else {
            HealthResponse {
                status: "unhealthy".to_string(),
                service: None,
                version: None,
                database: None,
                monero_rpc: None,
                auto_sweep_enabled: None,
            }
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

    let body = if authorized {
        HealthResponse {
            status: overall,
            service: Some(env!("CARGO_PKG_NAME").to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            database: Some("connected".to_string()),
            monero_rpc: Some(rpc_status),
            auto_sweep_enabled: Some(state.config.enable_auto_sweep),
        }
    } else {
        HealthResponse {
            status: overall,
            service: None,
            version: None,
            database: None,
            monero_rpc: None,
            auto_sweep_enabled: None,
        }
    };

    (StatusCode::OK, Json(body))
}

/// Creates a new isolated Monero subaddress invoice (`POST /api/v1/invoices`).
///
/// # Invariants & Idempotency (`XMR-019`)
/// - Rejects `amount_piconero == 0` or values exceeding SQLite signed 64-bit integer bounds.
/// - Serializes requests per `order_id` BEFORE checking the database or calling `create_address`
///   so concurrent retries cannot allocate orphaned Monero subaddresses.
/// - If an invoice with `order_id` already exists and has identical immutable parameters
///   (`amount_piconero` and resolved `callback_url`), returns `200 OK` idempotently with the
///   existing [`CreateInvoiceResponse`] without touching RPC.
/// - If an invoice with `order_id` exists with different `amount_piconero` or `callback_url`,
///   returns `409 Conflict`.
///
/// # Errors
/// - `400 Bad Request` on invalid `order_id`, zero/overflow amount, invalid TTL, or invalid URL.
/// - `409 Conflict` if `order_id` already exists with mismatched parameters.
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
            let validated = resolve_and_validate_webhook_url(
                &trimmed,
                "callback_url",
                state.config.webhook_url_policy(),
            )
            .await?;
            Some(validated.url.to_string())
        }
        None => match state.config.default_webhook_url.as_deref() {
            Some(default_url) => {
                let validated = resolve_and_validate_webhook_url(
                    default_url,
                    "DEFAULT_WEBHOOK_URL",
                    state.config.webhook_url_policy(),
                )
                .await?;
                Some(validated.url.to_string())
            }
            None => None,
        },
    };

    let order_id_key = req.order_id.clone();
    let order_lock = state.repo.acquire_order_lock(&order_id_key).await;
    let order_guard = order_lock.lock().await;
    let outcome = create_invoice_locked(&state, &order_id_key, amount, ttl_i64, callback_url).await;
    drop(order_guard);
    state
        .repo
        .release_order_lock(&order_id_key, order_lock)
        .await;
    outcome
}

async fn create_invoice_locked(
    state: &AppState,
    order_id: &str,
    amount: Piconero,
    ttl_i64: i64,
    callback_url: Option<String>,
) -> GatewayResult<(StatusCode, Json<CreateInvoiceResponse>)> {
    if let Some(existing) = state.repo.get_invoice_by_order_id(order_id).await? {
        if existing.amount_piconero == amount
            && existing.callback_url == callback_url
            && existing.ttl_seconds() == ttl_i64
        {
            return Ok((StatusCode::OK, Json(CreateInvoiceResponse::from(&existing))));
        }

        return Err(GatewayError::Conflict(format!(
            "invoice for order_id '{}' already exists with different parameters (expected amount_piconero={}, ttl_seconds={}, callback_url={:?})",
            order_id,
            existing.amount_piconero.as_u64(),
            existing.ttl_seconds(),
            existing.callback_url
        )));
    }

    let label = format!("inv_{order_id}");
    let rpc_addr = state.rpc.create_address(0, &label).await?;

    let monero_uri = build_monero_uri(&rpc_addr.address, amount, order_id);
    let qr_code_base64 = generate_qr_png_base64(&monero_uri)?;

    let now = Utc::now();
    let invoice = Invoice {
        id: Uuid::new_v4(),
        order_id: order_id.to_string(),
        account_index: 0,
        address_index: rpc_addr.address_index,
        subaddress: rpc_addr.address,
        amount_piconero: amount,
        received_piconero: Piconero::ZERO,
        confirmations: 0,
        unlocked: false,
        double_spend_seen: false,
        reorg_epoch: 0,
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
        settled_at: None,
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

/// Triggers an immediate sweep of a confirmed, unlocked subaddress or unswept late/overpayment
/// inflows (`POST /api/v1/invoices/{invoice_id}/sweep`).
///
/// # Errors
/// - `400 Bad Request` if `invoice_id` is not a valid UUID.
/// - `404 Not Found` if invoice does not exist.
/// - `409 Conflict` if auto-sweep is disabled, invoice is completed, already swept/expired with
///   no unswept anomaly inflows, underpaid, or funds have not reached Monero's 10-block unlock threshold.
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

/// Resets a permanently `FAILED` or backed-off `PENDING` webhook outbox delivery for immediate retry
/// (`POST /api/v1/webhooks/{webhook_id}/retry`) (`XMR-028`).
///
/// # Errors
/// - `400 Bad Request` if `webhook_id` is not a valid UUID.
/// - `404 Not Found` if `webhook_id` does not exist.
/// - `409 Conflict` if the webhook delivery is already `DELIVERED`.
pub async fn retry_webhook(
    State(state): State<AppState>,
    Path(webhook_id_raw): Path<String>,
) -> GatewayResult<Json<RetryWebhookResponse>> {
    let webhook_id = Uuid::parse_str(webhook_id_raw.trim()).map_err(|_| {
        GatewayError::Validation(format!("invalid webhook_id UUID '{webhook_id_raw}'"))
    })?;
    let now = Utc::now();

    let delivery = state
        .repo
        .reset_webhook_delivery_for_retry(webhook_id, now)
        .await?
        .ok_or_else(|| {
            GatewayError::NotFound(format!("webhook delivery {webhook_id} not found"))
        })?;

    tracing::info!(
        webhook_id = %delivery.id,
        invoice_id = %delivery.invoice_id,
        event_type = delivery.event_type.as_str(),
        "scheduled manual webhook delivery retry"
    );

    Ok(Json(RetryWebhookResponse {
        retried_count: 1,
        webhook_ids: vec![delivery.id],
        scheduled_at: now,
    }))
}

/// Resets all `FAILED` or backed-off `PENDING` webhook outbox deliveries for an invoice
/// (`POST /api/v1/invoices/{invoice_id}/webhooks/retry`) (`XMR-028`).
///
/// # Errors
/// - `400 Bad Request` if `invoice_id` is not a valid UUID.
/// - `404 Not Found` if `invoice_id` does not exist.
pub async fn retry_invoice_webhooks(
    State(state): State<AppState>,
    Path(invoice_id_raw): Path<String>,
) -> GatewayResult<Json<RetryWebhookResponse>> {
    let invoice_id = parse_invoice_uuid(&invoice_id_raw)?;
    let now = Utc::now();
    let deliveries = state
        .repo
        .reset_failed_webhooks_for_invoice(invoice_id, now)
        .await?;
    let webhook_ids: Vec<Uuid> = deliveries.iter().map(|d| d.id).collect();

    tracing::info!(
        invoice_id = %invoice_id,
        retried_count = webhook_ids.len(),
        "scheduled manual retry for invoice webhook deliveries"
    );

    Ok(Json(RetryWebhookResponse {
        retried_count: webhook_ids.len(),
        webhook_ids,
        scheduled_at: now,
    }))
}

fn parse_invoice_uuid(raw: &str) -> GatewayResult<Uuid> {
    Uuid::parse_str(raw.trim())
        .map_err(|_| GatewayError::Validation(format!("invalid invoice_id UUID '{raw}'")))
}
