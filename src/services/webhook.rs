//! HMAC-SHA256 webhook signing and durable exponential-backoff delivery worker.
//!
//! # Cryptographic Integrity & Retry Determinism
//! - Outbound payloads are serialized to canonical JSON bytes **once** at enqueue time and
//!   persisted in SQLite along with their lowercase hex HMAC-SHA256 signature (`X-Signature-256`).
//! - Retries transmit the exact persisted byte sequence without re-serialization, guaranteeing
//!   consistent signatures across restarts and transient merchant downtime.
//! - In View-Only Zero-Trust mode (`ENABLE_AUTO_SWEEP=false`), successful 2xx delivery of a
//!   `CONFIRMED` webhook atomically transitions the invoice from `CONFIRMED` to `COMPLETED`.

use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use hmac::{Hmac, Mac};
use reqwest::header;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::sync::watch;
use uuid::Uuid;

use crate::{
    db::repository::{InvoiceRepository, NewWebhookDelivery, WebhookDelivery},
    domain::{
        amount::Piconero,
        invoice::{Invoice, InvoiceStatus, WebhookEventType},
    },
    error::{GatewayError, GatewayResult},
    security::url_policy::{WebhookUrlPolicy, resolve_and_validate_webhook_url},
};

type HmacSha256 = Hmac<Sha256>;

/// Default maximum delivery attempts before marking a webhook delivery `FAILED`.
pub const DEFAULT_WEBHOOK_MAX_ATTEMPTS: u32 = 10;

/// Base backoff delay in seconds for attempt 1 (`5s, 10s, 20s, ...`).
const BACKOFF_BASE_SECONDS: i64 = 5;

/// Maximum backoff delay cap in seconds (1 hour).
const BACKOFF_MAX_SECONDS: i64 = 3600;

/// Canonical JSON webhook payload delivered to merchant backends (e.g., Telegram bots).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Unique event delivery identifier for consumer idempotency.
    pub event_id: Uuid,
    /// Lifecycle transition event (`MEMPOOL`, `UNDERPAID`, `CONFIRMED`, `SWEPT`, `EXPIRED`).
    pub event: WebhookEventType,
    /// Gateway invoice UUID.
    pub invoice_id: Uuid,
    /// Merchant's original `order_id`.
    pub order_id: String,
    /// Invoice status at the time this event was emitted.
    pub status: InvoiceStatus,
    /// Dedicated Monero subaddress assigned to the invoice.
    pub subaddress: String,
    /// Subaddress minor index under account 0.
    pub address_index: u32,
    /// Expected invoice total in piconero.
    pub amount_piconero: u64,
    /// Exact decimal XMR string formatted with 12 fractional digits.
    pub amount_xmr_formatted: String,
    /// Total valid (non-double-spent) piconero received so far.
    pub received_piconero: u64,
    /// Exact decimal XMR string of received piconero.
    pub received_xmr_formatted: String,
    /// Effective blockchain confirmations covering the invoice.
    pub confirmations: u64,
    /// Whether all outputs have unlocked (`>= 10` Monero blocks).
    pub unlocked: bool,
    /// Whether `monero-wallet-rpc` ever flagged a double-spend attempt on this subaddress.
    pub double_spend_seen: bool,
    /// Sweep transaction hashes (populated on `SWEPT` events).
    pub sweep_tx_hashes: Vec<String>,
    /// Net piconero swept to cold storage (populated on `SWEPT` events).
    pub sweep_amount_piconero: Option<u64>,
    /// Total network fee paid for sweep (populated on `SWEPT` events).
    pub sweep_fee_piconero: Option<u64>,
    /// Transaction hash that triggered a `LATE_PAYMENT` or `OVERPAYMENT` anomaly webhook.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub txid: Option<String>,
    /// Triggering transfer or excess amount in piconero for `LATE_PAYMENT` / `OVERPAYMENT`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub trigger_amount_piconero: Option<u64>,
    /// Event creation UTC timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Computes the lowercase hex HMAC-SHA256 digest for raw HTTP body bytes.
///
/// # Errors
/// Returns [`GatewayError::Webhook`] if HMAC key initialization fails.
pub fn sign_payload_hmac_sha256(secret: &str, raw_body: &[u8]) -> GatewayResult<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| GatewayError::Webhook(format!("invalid HMAC secret key: {e}")))?;
    mac.update(raw_body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Verifies a hex-encoded `X-Signature-256` HMAC-SHA256 signature in constant time.
#[must_use]
pub fn verify_payload_hmac_sha256(secret: &str, raw_body: &[u8], signature_hex: &str) -> bool {
    if secret.is_empty() {
        return false;
    }
    let Ok(expected_hex) = sign_payload_hmac_sha256(secret, raw_body) else {
        return false;
    };
    let Ok(presented_bytes) = hex::decode(signature_hex.trim()) else {
        return false;
    };
    let Ok(expected_bytes) = hex::decode(expected_hex) else {
        return false;
    };

    if presented_bytes.len() != expected_bytes.len() {
        return false;
    }

    bool::from(presented_bytes.ct_eq(&expected_bytes))
}

/// Builds a signed [`NewWebhookDelivery`] ready to enqueue atomically in SQLite.
///
/// # Deduplication Strategy
/// - `UNDERPAID` uses `"{invoice_id}:UNDERPAID:{received_piconero}"` so additional partial
///   payments emit fresh progress alerts while identical polling cycles remain idempotent.
/// - `REORGED` includes received/confirmation state so subsequent reorgs fire cleanly.
/// - `SWEPT` appends the sweep tx count when residual overpayments trigger additional sweeps.
/// - All other lifecycle events use `"{invoice_id}:{event_type}"` to fire at most once per invoice.
///
/// # Errors
/// Returns [`GatewayError::Webhook`] if JSON serialization or HMAC signing fails.
pub fn build_webhook_delivery(
    webhook_secret: &str,
    invoice: &Invoice,
    event_type: WebhookEventType,
    target_url: &str,
    now: DateTime<Utc>,
) -> GatewayResult<NewWebhookDelivery> {
    let delivery_id = Uuid::new_v4();
    let payload = WebhookPayload {
        event_id: delivery_id,
        event: event_type,
        invoice_id: invoice.id,
        order_id: invoice.order_id.clone(),
        status: invoice.status,
        subaddress: invoice.subaddress.clone(),
        address_index: invoice.address_index,
        amount_piconero: invoice.amount_piconero.as_u64(),
        amount_xmr_formatted: invoice.amount_piconero.to_xmr_string(),
        received_piconero: invoice.received_piconero.as_u64(),
        received_xmr_formatted: invoice.received_piconero.to_xmr_string(),
        confirmations: invoice.confirmations,
        unlocked: invoice.unlocked,
        double_spend_seen: invoice.double_spend_seen,
        sweep_tx_hashes: invoice.sweep_tx_hashes.clone(),
        sweep_amount_piconero: invoice.sweep_amount_piconero.map(Piconero::as_u64),
        sweep_fee_piconero: invoice.sweep_fee_piconero.map(Piconero::as_u64),
        txid: None,
        trigger_amount_piconero: None,
        timestamp: now,
    };

    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| GatewayError::Webhook(format!("failed to serialize webhook payload: {e}")))?;
    let signature_hex = sign_payload_hmac_sha256(webhook_secret, payload_json.as_bytes())?;

    let dedupe_key = match event_type {
        WebhookEventType::Underpaid => {
            format!(
                "{}:UNDERPAID:{}",
                invoice.id,
                invoice.received_piconero.as_u64()
            )
        }
        WebhookEventType::Reorged => {
            format!(
                "{}:REORGED:{}:{}",
                invoice.id,
                invoice.received_piconero.as_u64(),
                invoice.confirmations
            )
        }
        WebhookEventType::Swept if invoice.sweep_tx_hashes.len() > 1 => {
            format!("{}:SWEPT:{}", invoice.id, invoice.sweep_tx_hashes.len())
        }
        _ => format!("{}:{}", invoice.id, event_type.as_str()),
    };

    Ok(NewWebhookDelivery {
        id: delivery_id,
        invoice_id: invoice.id,
        event_type,
        dedupe_key,
        target_url: target_url.to_string(),
        payload_json,
        signature_hex,
        max_attempts: DEFAULT_WEBHOOK_MAX_ATTEMPTS,
        now,
    })
}

/// Builds a signed [`NewWebhookDelivery`] for per-transaction `LATE_PAYMENT` or `OVERPAYMENT`
/// accounting events deduplicated by `"{invoice_id}:{event_type}:{txid}"`.
///
/// # Errors
/// Returns [`GatewayError::Webhook`] if JSON serialization or HMAC signing fails.
pub fn build_transfer_anomaly_webhook_delivery(
    webhook_secret: &str,
    invoice: &Invoice,
    event_type: WebhookEventType,
    txid: &str,
    trigger_amount_piconero: Piconero,
    target_url: &str,
    now: DateTime<Utc>,
) -> GatewayResult<NewWebhookDelivery> {
    let delivery_id = Uuid::new_v4();
    let payload = WebhookPayload {
        event_id: delivery_id,
        event: event_type,
        invoice_id: invoice.id,
        order_id: invoice.order_id.clone(),
        status: invoice.status,
        subaddress: invoice.subaddress.clone(),
        address_index: invoice.address_index,
        amount_piconero: invoice.amount_piconero.as_u64(),
        amount_xmr_formatted: invoice.amount_piconero.to_xmr_string(),
        received_piconero: invoice.received_piconero.as_u64(),
        received_xmr_formatted: invoice.received_piconero.to_xmr_string(),
        confirmations: invoice.confirmations,
        unlocked: invoice.unlocked,
        double_spend_seen: invoice.double_spend_seen,
        sweep_tx_hashes: invoice.sweep_tx_hashes.clone(),
        sweep_amount_piconero: invoice.sweep_amount_piconero.map(Piconero::as_u64),
        sweep_fee_piconero: invoice.sweep_fee_piconero.map(Piconero::as_u64),
        txid: Some(txid.to_string()),
        trigger_amount_piconero: Some(trigger_amount_piconero.as_u64()),
        timestamp: now,
    };

    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| GatewayError::Webhook(format!("failed to serialize webhook payload: {e}")))?;
    let signature_hex = sign_payload_hmac_sha256(webhook_secret, payload_json.as_bytes())?;
    let dedupe_key = format!("{}:{}:{}", invoice.id, event_type.as_str(), txid);

    Ok(NewWebhookDelivery {
        id: delivery_id,
        invoice_id: invoice.id,
        event_type,
        dedupe_key,
        target_url: target_url.to_string(),
        payload_json,
        signature_hex,
        max_attempts: DEFAULT_WEBHOOK_MAX_ATTEMPTS,
        now,
    })
}

/// Calculates capped exponential backoff delay (`5s * 2^(attempt - 1)`, max `3600s`).
#[must_use]
pub fn compute_backoff_seconds(failed_attempts: u32) -> i64 {
    let shift = failed_attempts.saturating_sub(1).min(12);
    let multiplier = 1_i64 << shift;
    BACKOFF_BASE_SECONDS
        .saturating_mul(multiplier)
        .min(BACKOFF_MAX_SECONDS)
}

/// Asynchronous outbox worker dispatching signed webhooks with exponential backoff.
#[derive(Debug, Clone)]
pub struct WebhookDispatcher {
    repo: InvoiceRepository,
    http: reqwest::Client,
    enable_auto_sweep: bool,
    poll_interval: Duration,
    url_policy: WebhookUrlPolicy,
}

impl WebhookDispatcher {
    /// Constructs a new [`WebhookDispatcher`] permitting loopback targets for local tests.
    ///
    /// # Errors
    /// Returns [`GatewayError::Config`] if the HTTP client fails TLS initialization.
    pub fn new(
        repo: InvoiceRepository,
        enable_auto_sweep: bool,
        poll_interval: Duration,
    ) -> GatewayResult<Self> {
        Self::new_with_policy(
            repo,
            enable_auto_sweep,
            poll_interval,
            WebhookUrlPolicy {
                allow_private_webhooks: true,
                require_https_webhooks: false,
            },
        )
    }

    /// Constructs a new [`WebhookDispatcher`] enforcing an explicit [`WebhookUrlPolicy`].
    ///
    /// Configures `redirect::Policy::none()` so HTTP 3xx responses cannot pivot webhook traffic to
    /// internal hosts, and validates + pins DNS answers on every dispatch attempt.
    ///
    /// # Errors
    /// Returns [`GatewayError::Config`] if the HTTP client fails TLS initialization.
    pub fn new_with_policy(
        repo: InvoiceRepository,
        enable_auto_sweep: bool,
        poll_interval: Duration,
        url_policy: WebhookUrlPolicy,
    ) -> GatewayResult<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| GatewayError::Config(format!("failed to create webhook client: {e}")))?;

        Ok(Self {
            repo,
            http,
            enable_auto_sweep,
            poll_interval,
            url_policy,
        })
    }

    /// Runs the background retry loop until a shutdown signal arrives.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        tracing::info!(
            interval_secs = self.poll_interval.as_secs(),
            "webhook dispatcher started"
        );
        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(err) = self.process_due_deliveries().await {
                        tracing::error!(error = %err, "webhook dispatch tick failed");
                    }
                }
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        tracing::info!("webhook dispatcher received shutdown signal");
                        break;
                    }
                }
            }
        }
    }

    /// Processes all currently due webhook deliveries in FIFO order.
    ///
    /// Returns the number of deliveries attempted during this cycle.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] if querying or updating SQLite fails.
    pub async fn process_due_deliveries(&self) -> GatewayResult<usize> {
        let now = Utc::now();
        let due = self.repo.fetch_due_webhooks(now, 50).await?;
        let count = due.len();

        for delivery in due {
            self.deliver_one(&delivery).await?;
        }

        Ok(count)
    }

    async fn deliver_one(&self, delivery: &WebhookDelivery) -> GatewayResult<()> {
        let now = Utc::now();

        let validated = match resolve_and_validate_webhook_url(
            &delivery.target_url,
            "webhook target_url",
            self.url_policy,
        )
        .await
        {
            Ok(target) => target,
            Err(err) => {
                let err_msg = format!("SSRF policy rejected webhook target: {err}");
                self.schedule_retry_or_fail(delivery, None, &err_msg, now)
                    .await?;
                return Ok(());
            }
        };

        // Pin resolved socket addresses at connect time to prevent DNS rebinding TOCTOU attacks.
        let client = if validated.is_ip_literal {
            self.http.clone()
        } else {
            match reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .resolve_to_addrs(&validated.host, &validated.resolved_addrs)
                .build()
            {
                Ok(pinned) => pinned,
                Err(err) => {
                    let err_msg = format!("failed to construct pinned HTTP client: {err}");
                    self.schedule_retry_or_fail(delivery, None, &err_msg, now)
                        .await?;
                    return Ok(());
                }
            }
        };

        let send_result = client
            .post(validated.url)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::USER_AGENT, "xmr-gateway/0.1.0")
            .header("X-Signature-256", &delivery.signature_hex)
            .header("X-Webhook-Event", delivery.event_type.as_str())
            .header("X-Delivery-Id", delivery.id.to_string())
            .header("X-Webhook-Timestamp", delivery.created_at.to_rfc3339())
            .body(delivery.payload_json.clone())
            .send()
            .await;

        match send_result {
            Ok(resp) if resp.status().is_success() => {
                let code = resp.status().as_u16();
                tracing::info!(
                    delivery_id = %delivery.id,
                    invoice_id = %delivery.invoice_id,
                    event = delivery.event_type.as_str(),
                    status_code = code,
                    "webhook delivered"
                );
                self.repo
                    .mark_webhook_delivered(
                        delivery.id,
                        delivery.invoice_id,
                        delivery.event_type,
                        code,
                        now,
                        !self.enable_auto_sweep,
                    )
                    .await?;
            }
            Ok(resp) => {
                let code = resp.status().as_u16();
                let body_snippet = resp.text().await.unwrap_or_default();
                let truncated: String = body_snippet.chars().take(256).collect();
                let err_msg = format!("HTTP {code}: {truncated}");
                self.schedule_retry_or_fail(delivery, Some(code), &err_msg, now)
                    .await?;
            }
            Err(err) => {
                let sanitized = err.without_url();
                let err_msg = format!("transport error: {sanitized}");
                self.schedule_retry_or_fail(delivery, None, &err_msg, now)
                    .await?;
            }
        }

        Ok(())
    }

    async fn schedule_retry_or_fail(
        &self,
        delivery: &WebhookDelivery,
        status_code: Option<u16>,
        err_msg: &str,
        now: DateTime<Utc>,
    ) -> GatewayResult<()> {
        let next_attempt_num = delivery.attempts.saturating_add(1);
        let next_attempt_at = if next_attempt_num >= delivery.max_attempts {
            tracing::error!(
                delivery_id = %delivery.id,
                invoice_id = %delivery.invoice_id,
                attempts = next_attempt_num,
                error = err_msg,
                "webhook permanently failed after max retries"
            );
            None
        } else {
            let delay_secs = compute_backoff_seconds(next_attempt_num);
            tracing::warn!(
                delivery_id = %delivery.id,
                invoice_id = %delivery.invoice_id,
                attempt = next_attempt_num,
                retry_in_secs = delay_secs,
                error = err_msg,
                "webhook delivery failed; scheduled exponential backoff retry"
            );
            Some(now + ChronoDuration::seconds(delay_secs))
        };

        self.repo
            .mark_webhook_retry_or_failed(
                delivery.id,
                next_attempt_num,
                next_attempt_at,
                status_code,
                err_msg,
                now,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::*;
    use crate::{db::init_sqlite_pool, domain::invoice::build_monero_uri};

    fn sample_invoice(status: InvoiceStatus) -> Invoice {
        let now = Utc::now();
        let subaddr = format!("8{}", "A".repeat(94));
        let amount = Piconero(1_000_000_000_000);
        Invoice {
            id: Uuid::new_v4(),
            order_id: "ord-webhook-1".to_string(),
            account_index: 0,
            address_index: 1,
            subaddress: subaddr.clone(),
            amount_piconero: amount,
            received_piconero: amount,
            confirmations: 2,
            unlocked: false,
            double_spend_seen: false,
            status,
            callback_url: None,
            monero_uri: build_monero_uri(&subaddr, amount, "ord-webhook-1"),
            qr_code_base64: "ZmFrZQ==".to_string(),
            sweep_tx_hashes: Vec::new(),
            sweep_amount_piconero: None,
            sweep_fee_piconero: None,
            last_sweep_error: None,
            created_at: now,
            updated_at: now,
            expires_at: now + ChronoDuration::hours(1),
            confirmed_at: Some(now),
            settled_at: None,
            swept_at: None,
            completed_at: None,
        }
    }

    #[test]
    fn hmac_signature_verifies_and_rejects_tampering() {
        let secret = "super-secret-webhook-key";
        let payload = br#"{"event":"CONFIRMED","amount_piconero":1000000000000}"#;
        let sig = sign_payload_hmac_sha256(secret, payload).unwrap();

        assert_eq!(sig.len(), 64);
        assert!(verify_payload_hmac_sha256(secret, payload, &sig));
        assert!(!verify_payload_hmac_sha256("wrong-secret", payload, &sig));
        assert!(!verify_payload_hmac_sha256(
            secret,
            br#"{"event":"CONFIRMED","amount_piconero":999}"#,
            &sig
        ));
    }

    #[test]
    fn backoff_scales_exponentially_and_caps() {
        assert_eq!(compute_backoff_seconds(1), 5);
        assert_eq!(compute_backoff_seconds(2), 10);
        assert_eq!(compute_backoff_seconds(3), 20);
        assert_eq!(compute_backoff_seconds(4), 40);
        assert_eq!(compute_backoff_seconds(10), 2560);
        assert_eq!(compute_backoff_seconds(11), 3600);
        assert_eq!(compute_backoff_seconds(50), 3600);
    }

    #[tokio::test]
    async fn delivers_signed_webhook_and_completes_view_only_invoice() {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);

        let mock_server = MockServer::start().await;
        let secret = "webhook-secret-key-0123456789abcdef";

        let mut inv = sample_invoice(InvoiceStatus::Confirmed);
        inv.callback_url = Some(format!("{}/hook", mock_server.uri()));
        repo.insert_invoice(&inv).await.unwrap();

        let delivery = build_webhook_delivery(
            secret,
            &inv,
            WebhookEventType::Confirmed,
            inv.callback_url.as_deref().unwrap(),
            Utc::now(),
        )
        .unwrap();
        let expected_sig = delivery.signature_hex.clone();

        // Enqueue via apply_scan_update
        repo.apply_scan_update(crate::db::repository::ApplyScanUpdateParams {
            invoice_id: inv.id,
            received_piconero: inv.received_piconero,
            confirmations: 2,
            unlocked: false,
            double_spend_seen: false,
            next_status: InvoiceStatus::Confirmed,
            transfers: Vec::new(),
            webhook: Some(delivery),
            now: Utc::now(),
        })
        .await
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(header("X-Signature-256", expected_sig.as_str()))
            .and(header("X-Webhook-Event", "CONFIRMED"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let dispatcher =
            WebhookDispatcher::new(repo.clone(), false, Duration::from_secs(5)).unwrap();
        let processed = dispatcher.process_due_deliveries().await.unwrap();
        assert_eq!(processed, 1);

        let updated = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(updated.status, InvoiceStatus::Completed);
        assert!(updated.completed_at.is_some());

        let webhooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        assert_eq!(webhooks.len(), 1);
        assert_eq!(
            webhooks[0].status,
            crate::db::repository::WebhookDeliveryStatus::Delivered
        );
    }

    #[tokio::test]
    async fn marks_webhook_failed_when_max_attempts_exhausted() {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_server = MockServer::start().await;

        let mut inv = sample_invoice(InvoiceStatus::Confirmed);
        inv.order_id = "ord-webhook-fail".to_string();
        let hook_url = format!("{}/dead", mock_server.uri());
        inv.callback_url = Some(hook_url.clone());
        repo.insert_invoice(&inv).await.unwrap();

        let mut delivery = build_webhook_delivery(
            "webhook-secret-key-0123456789abcdef",
            &inv,
            WebhookEventType::Confirmed,
            &hook_url,
            Utc::now(),
        )
        .unwrap();
        delivery.max_attempts = 1;

        repo.apply_scan_update(crate::db::repository::ApplyScanUpdateParams {
            invoice_id: inv.id,
            received_piconero: inv.received_piconero,
            confirmations: 2,
            unlocked: false,
            double_spend_seen: false,
            next_status: InvoiceStatus::Confirmed,
            transfers: Vec::new(),
            webhook: Some(delivery),
            now: Utc::now(),
        })
        .await
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/dead"))
            .respond_with(ResponseTemplate::new(500).set_body_string("downstream error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let dispatcher =
            WebhookDispatcher::new(repo.clone(), true, Duration::from_secs(5)).unwrap();
        dispatcher.process_due_deliveries().await.unwrap();

        let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        assert_eq!(
            hooks[0].status,
            crate::db::repository::WebhookDeliveryStatus::Failed
        );
        assert_eq!(hooks[0].attempts, 1);
        assert_eq!(hooks[0].last_status_code, Some(500));
    }

    #[tokio::test]
    async fn blocks_redirects_and_ssrf_targets_on_delivery() {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);

        // 1) Strict policy blocks delivery to 127.0.0.1 even if enqueued beforehand
        let mock_server = MockServer::start().await;
        let mut inv = sample_invoice(InvoiceStatus::Confirmed);
        inv.order_id = "ord-ssrf-block".to_string();
        let hook_url = format!("{}/hook", mock_server.uri());
        inv.callback_url = Some(hook_url.clone());
        repo.insert_invoice(&inv).await.unwrap();

        let delivery = build_webhook_delivery(
            "webhook-secret-key-0123456789abcdef",
            &inv,
            WebhookEventType::Confirmed,
            &hook_url,
            Utc::now(),
        )
        .unwrap();
        repo.apply_scan_update(crate::db::repository::ApplyScanUpdateParams {
            invoice_id: inv.id,
            received_piconero: inv.received_piconero,
            confirmations: 2,
            unlocked: false,
            double_spend_seen: false,
            next_status: InvoiceStatus::Confirmed,
            transfers: Vec::new(),
            webhook: Some(delivery),
            now: Utc::now(),
        })
        .await
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        let strict_dispatcher = WebhookDispatcher::new_with_policy(
            repo.clone(),
            true,
            Duration::from_secs(5),
            WebhookUrlPolicy {
                allow_private_webhooks: false,
                require_https_webhooks: false,
            },
        )
        .unwrap();
        strict_dispatcher.process_due_deliveries().await.unwrap();
        let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        assert_eq!(hooks[0].attempts, 1);
        assert!(
            hooks[0]
                .last_error
                .as_deref()
                .unwrap_or("")
                .contains("SSRF policy")
        );

        // 2) Redirect responses (302 -> metadata endpoint) are NOT followed even when private hosts permitted
        let mock_redir = MockServer::start().await;
        let mut inv2 = sample_invoice(InvoiceStatus::Confirmed);
        inv2.order_id = "ord-redirect-block".to_string();
        inv2.address_index = 2;
        let hook_url2 = format!("{}/redir", mock_redir.uri());
        inv2.callback_url = Some(hook_url2.clone());
        repo.insert_invoice(&inv2).await.unwrap();

        let delivery2 = build_webhook_delivery(
            "webhook-secret-key-0123456789abcdef",
            &inv2,
            WebhookEventType::Confirmed,
            &hook_url2,
            Utc::now(),
        )
        .unwrap();
        repo.apply_scan_update(crate::db::repository::ApplyScanUpdateParams {
            invoice_id: inv2.id,
            received_piconero: inv2.received_piconero,
            confirmations: 2,
            unlocked: false,
            double_spend_seen: false,
            next_status: InvoiceStatus::Confirmed,
            transfers: Vec::new(),
            webhook: Some(delivery2),
            now: Utc::now(),
        })
        .await
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/redir"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "http://169.254.169.254/latest/meta-data/"),
            )
            .expect(1)
            .mount(&mock_redir)
            .await;

        let permissive_dispatcher = WebhookDispatcher::new_with_policy(
            repo.clone(),
            true,
            Duration::from_secs(5),
            WebhookUrlPolicy {
                allow_private_webhooks: true,
                require_https_webhooks: false,
            },
        )
        .unwrap();
        permissive_dispatcher
            .process_due_deliveries()
            .await
            .unwrap();
        let hooks2 = repo.list_webhooks_for_invoice(inv2.id).await.unwrap();
        assert_eq!(hooks2[0].last_status_code, Some(302));
        assert_eq!(
            hooks2[0].status,
            crate::db::repository::WebhookDeliveryStatus::Pending
        );
    }
}
