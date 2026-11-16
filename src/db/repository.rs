//! Transactional SQLite repository for invoices, observed transfers, and webhook outbox.
//!
//! Every financial state transition and webhook enqueue operation runs atomically inside an
//! explicit SQLite transaction (`BEGIN ... COMMIT`), preserving consistency across process
//! crashes and preventing duplicate webhook emissions via database `UNIQUE` constraints.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::{FromRow, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;

use crate::{
    domain::{
        amount::Piconero,
        invoice::{Invoice, InvoiceStatus, ObservedTransfer, WebhookEventType},
    },
    error::{GatewayError, GatewayResult},
};

/// Persisted webhook delivery status in the durable outbox queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookDeliveryStatus {
    /// Queued and eligible for delivery once `next_attempt_at <= now`.
    Pending,
    /// Successfully delivered with HTTP 2xx status.
    Delivered,
    /// Permanently failed after exhausting `max_attempts`.
    Failed,
}

impl WebhookDeliveryStatus {
    /// Returns canonical uppercase database representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Delivered => "DELIVERED",
            Self::Failed => "FAILED",
        }
    }
}

impl FromStr for WebhookDeliveryStatus {
    type Err = GatewayError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PENDING" => Ok(Self::Pending),
            "DELIVERED" => Ok(Self::Delivered),
            "FAILED" => Ok(Self::Failed),
            other => Err(GatewayError::Internal(format!(
                "unknown webhook delivery status '{other}'"
            ))),
        }
    }
}

/// Durable outbound webhook record stored in `webhook_deliveries`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookDelivery {
    /// Unique delivery UUID.
    pub id: Uuid,
    /// Associated invoice UUID.
    pub invoice_id: Uuid,
    /// Lifecycle event type.
    pub event_type: WebhookEventType,
    /// Idempotency deduplication key (`{invoice_id}:{event}` or `{invoice_id}:UNDERPAID:{amt}`).
    pub dedupe_key: String,
    /// Destination HTTP/HTTPS endpoint.
    pub target_url: String,
    /// Exact serialized JSON body bytes signed by `signature_hex`.
    pub payload_json: String,
    /// Lowercase hex HMAC-SHA256 signature of `payload_json`.
    pub signature_hex: String,
    /// Current outbox delivery status.
    pub status: WebhookDeliveryStatus,
    /// Number of failed/completed delivery attempts so far.
    pub attempts: u32,
    /// Maximum retry ceiling before marking `FAILED`.
    pub max_attempts: u32,
    /// Earliest UTC timestamp for the next delivery attempt.
    pub next_attempt_at: DateTime<Utc>,
    /// Most recent HTTP status returned by destination (if any).
    pub last_status_code: Option<u16>,
    /// Most recent transport or HTTP error message (if any).
    pub last_error: Option<String>,
    /// Enqueue timestamp.
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp.
    pub updated_at: DateTime<Utc>,
    /// Timestamp of final 2xx delivery.
    pub delivered_at: Option<DateTime<Utc>>,
}

/// Parameters for inserting a brand-new webhook delivery inside an existing DB transaction.
#[derive(Debug, Clone)]
pub struct NewWebhookDelivery {
    /// Unique delivery identifier.
    pub id: Uuid,
    /// Associated invoice identifier.
    pub invoice_id: Uuid,
    /// Triggering event type.
    pub event_type: WebhookEventType,
    /// Database-enforced deduplication key.
    pub dedupe_key: String,
    /// Webhook target URL.
    pub target_url: String,
    /// Exact JSON string to transmit.
    pub payload_json: String,
    /// HMAC-SHA256 hex signature of `payload_json`.
    pub signature_hex: String,
    /// Maximum retry attempts.
    pub max_attempts: u32,
    /// Timestamp when delivery becomes due (typically `now`).
    pub now: DateTime<Utc>,
}

/// Atomic update payload produced by a scanner pass for a single invoice.
#[derive(Debug, Clone)]
pub struct ApplyScanUpdateParams {
    /// Target invoice UUID.
    pub invoice_id: Uuid,
    /// Observed valid (non-double-spent) total in piconero.
    pub received_piconero: Piconero,
    /// Effective confirmation depth covering the obligation.
    pub confirmations: u64,
    /// Whether all outputs are unlocked (`>= 10` blocks).
    pub unlocked: bool,
    /// Whether any double-spend attempt was reported by RPC.
    pub double_spend_seen: bool,
    /// Target lifecycle status computed by the domain state machine.
    pub next_status: InvoiceStatus,
    /// Observed per-txid transfers for audit persistence.
    pub transfers: Vec<ObservedTransfer>,
    /// Optional outbox webhook event to enqueue atomically with the transition.
    pub webhook: Option<NewWebhookDelivery>,
    /// Current UTC timestamp.
    pub now: DateTime<Utc>,
}

/// Atomic update payload after `sweep_all` completes for a confirmed & unlocked invoice.
#[derive(Debug, Clone)]
pub struct MarkSweptParams {
    /// Target invoice UUID.
    pub invoice_id: Uuid,
    /// Transaction hashes returned by `monero-wallet-rpc` `sweep_all`.
    pub sweep_tx_hashes: Vec<String>,
    /// Total piconero swept across all sweep transactions.
    pub sweep_amount_piconero: Piconero,
    /// Total network fee paid across all sweep transactions.
    pub sweep_fee_piconero: Piconero,
    /// Optional `SWEPT` webhook outbox entry.
    pub webhook: Option<NewWebhookDelivery>,
    /// Current UTC timestamp.
    pub now: DateTime<Utc>,
}

/// SQLite repository providing transactional persistence for `xmr-gateway`.
#[derive(Debug, Clone)]
pub struct InvoiceRepository {
    pool: SqlitePool,
}

#[derive(Debug, FromRow)]
struct InvoiceRow {
    id: String,
    order_id: String,
    account_index: i64,
    address_index: i64,
    subaddress: String,
    amount_piconero: i64,
    received_piconero: i64,
    confirmations: i64,
    unlocked: i64,
    double_spend_seen: i64,
    status: String,
    callback_url: Option<String>,
    monero_uri: String,
    qr_code_base64: String,
    sweep_tx_hashes: String,
    sweep_amount_piconero: Option<i64>,
    sweep_fee_piconero: Option<i64>,
    last_sweep_error: Option<String>,
    created_at: String,
    updated_at: String,
    expires_at: String,
    confirmed_at: Option<String>,
    swept_at: Option<String>,
    completed_at: Option<String>,
}

#[derive(Debug, FromRow)]
struct TransferRow {
    txid: String,
    amount_piconero: i64,
    confirmations: i64,
    unlocked: i64,
    double_spend_seen: i64,
    in_pool: i64,
}

#[derive(Debug, FromRow)]
struct WebhookRow {
    id: String,
    invoice_id: String,
    event_type: String,
    dedupe_key: String,
    target_url: String,
    payload_json: String,
    signature_hex: String,
    status: String,
    attempts: i64,
    max_attempts: i64,
    next_attempt_at: String,
    last_status_code: Option<i64>,
    last_error: Option<String>,
    created_at: String,
    updated_at: String,
    delivered_at: Option<String>,
}

impl InvoiceRepository {
    /// Creates a new repository backed by the given `SqlitePool`.
    #[must_use]
    pub const fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Executes a lightweight connectivity check against SQLite.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] if the database connection is unavailable.
    pub async fn health_check(&self) -> GatewayResult<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Persists a newly created invoice in `PENDING` state.
    ///
    /// # Errors
    /// Returns [`GatewayError::Domain`] if piconero amounts exceed signed SQLite bounds, or
    /// [`GatewayError::Database`] on unique constraint violations (`order_id` or subaddress).
    pub async fn insert_invoice(&self, invoice: &Invoice) -> GatewayResult<()> {
        let amount_i64 = invoice.amount_piconero.to_i64()?;
        let received_i64 = invoice.received_piconero.to_i64()?;
        let confirmations_i64 = u64_to_i64(invoice.confirmations, "confirmations")?;
        let sweep_hashes_json = serde_json::to_string(&invoice.sweep_tx_hashes).map_err(|e| {
            GatewayError::Internal(format!("failed to serialize sweep hashes: {e}"))
        })?;

        sqlx::query(
            r#"
            INSERT INTO invoices (
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, swept_at, completed_at
            ) VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?
            )
            "#,
        )
        .bind(invoice.id.to_string())
        .bind(&invoice.order_id)
        .bind(i64::from(invoice.account_index))
        .bind(i64::from(invoice.address_index))
        .bind(&invoice.subaddress)
        .bind(amount_i64)
        .bind(received_i64)
        .bind(confirmations_i64)
        .bind(i64::from(invoice.unlocked))
        .bind(i64::from(invoice.double_spend_seen))
        .bind(invoice.status.as_str())
        .bind(&invoice.callback_url)
        .bind(&invoice.monero_uri)
        .bind(&invoice.qr_code_base64)
        .bind(sweep_hashes_json)
        .bind(
            invoice
                .sweep_amount_piconero
                .map(Piconero::to_i64)
                .transpose()?,
        )
        .bind(
            invoice
                .sweep_fee_piconero
                .map(Piconero::to_i64)
                .transpose()?,
        )
        .bind(&invoice.last_sweep_error)
        .bind(invoice.created_at.to_rfc3339())
        .bind(invoice.updated_at.to_rfc3339())
        .bind(invoice.expires_at.to_rfc3339())
        .bind(invoice.confirmed_at.map(|ts| ts.to_rfc3339()))
        .bind(invoice.swept_at.map(|ts| ts.to_rfc3339()))
        .bind(invoice.completed_at.map(|ts| ts.to_rfc3339()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Fetches an invoice by its UUID.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure or [`GatewayError::Internal`] on row
    /// decoding corruption.
    pub async fn get_invoice_by_id(&self, id: Uuid) -> GatewayResult<Option<Invoice>> {
        let row: Option<InvoiceRow> = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, swept_at, completed_at
            FROM invoices
            WHERE id = ?
            "#,
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        row.map(Invoice::try_from).transpose()
    }

    /// Fetches an invoice by merchant `order_id`.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn get_invoice_by_order_id(&self, order_id: &str) -> GatewayResult<Option<Invoice>> {
        let row: Option<InvoiceRow> = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, swept_at, completed_at
            FROM invoices
            WHERE order_id = ?
            "#,
        )
        .bind(order_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(Invoice::try_from).transpose()
    }

    /// Lists all incoming Monero transfers recorded for a given invoice.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn list_transfers_for_invoice(
        &self,
        invoice_id: Uuid,
    ) -> GatewayResult<Vec<ObservedTransfer>> {
        let rows: Vec<TransferRow> = sqlx::query_as(
            r#"
            SELECT txid, amount_piconero, confirmations, unlocked, double_spend_seen, in_pool
            FROM invoice_transfers
            WHERE invoice_id = ?
            ORDER BY id ASC
            "#,
        )
        .bind(invoice_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(ObservedTransfer::try_from).collect()
    }

    /// Fetches all non-terminal invoices (`PENDING`, `UNDERPAID`, `MEMPOOL`, `CONFIRMED`).
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn list_active_invoices(&self) -> GatewayResult<Vec<Invoice>> {
        let rows: Vec<InvoiceRow> = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, swept_at, completed_at
            FROM invoices
            WHERE status IN ('PENDING', 'UNDERPAID', 'MEMPOOL', 'CONFIRMED')
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(Invoice::try_from).collect()
    }

    /// Atomically persists observed transfers, state transition, and optional webhook outbox entry.
    ///
    /// # Concurrency Safety
    /// Re-reads the invoice row inside the transaction so terminal states (`SWEPT`, `COMPLETED`,
    /// `EXPIRED`) cannot be overwritten by an older in-flight scan result.
    ///
    /// # Errors
    /// Returns [`GatewayError::NotFound`] if the invoice vanished, [`GatewayError::Domain`] on
    /// illegal transitions or overflow, or [`GatewayError::Database`] on SQLite failures.
    pub async fn apply_scan_update(&self, params: ApplyScanUpdateParams) -> GatewayResult<Invoice> {
        let mut tx = self.pool.begin().await?;
        let id_str = params.invoice_id.to_string();

        let existing_row: InvoiceRow = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, swept_at, completed_at
            FROM invoices
            WHERE id = ?
            "#,
        )
        .bind(&id_str)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            GatewayError::NotFound(format!("invoice {} not found", params.invoice_id))
        })?;

        let existing = Invoice::try_from(existing_row)?;
        if existing.status.is_terminal() {
            tx.commit().await?;
            return Ok(existing);
        }

        existing.status.validate_transition(params.next_status)?;

        for tr in &params.transfers {
            upsert_transfer_tx(&mut tx, &id_str, tr, params.now).await?;
        }

        let confirmed_at = if existing.confirmed_at.is_some() {
            existing.confirmed_at
        } else if matches!(
            params.next_status,
            InvoiceStatus::Confirmed | InvoiceStatus::Completed
        ) {
            Some(params.now)
        } else {
            None
        };

        let completed_at = if existing.completed_at.is_some() {
            existing.completed_at
        } else if params.next_status == InvoiceStatus::Completed {
            Some(params.now)
        } else {
            None
        };

        let received_i64 = params.received_piconero.to_i64()?;
        let conf_i64 = u64_to_i64(params.confirmations, "confirmations")?;
        let double_spend_flag = existing.double_spend_seen || params.double_spend_seen;

        sqlx::query(
            r#"
            UPDATE invoices
            SET
                received_piconero = ?,
                confirmations = ?,
                unlocked = ?,
                double_spend_seen = ?,
                status = ?,
                updated_at = ?,
                confirmed_at = ?,
                completed_at = ?
            WHERE id = ?
            "#,
        )
        .bind(received_i64)
        .bind(conf_i64)
        .bind(i64::from(params.unlocked))
        .bind(i64::from(double_spend_flag))
        .bind(params.next_status.as_str())
        .bind(params.now.to_rfc3339())
        .bind(confirmed_at.map(|ts| ts.to_rfc3339()))
        .bind(completed_at.map(|ts| ts.to_rfc3339()))
        .bind(&id_str)
        .execute(&mut *tx)
        .await?;

        if let Some(webhook) = params.webhook {
            insert_webhook_tx(&mut tx, &webhook).await?;
        }

        let updated_row: InvoiceRow = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, swept_at, completed_at
            FROM invoices
            WHERE id = ?
            "#,
        )
        .bind(&id_str)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Invoice::try_from(updated_row)
    }

    /// Atomically transitions a `CONFIRMED` invoice to `SWEPT` and enqueues the `SWEPT` webhook.
    ///
    /// # Errors
    /// Returns [`GatewayError::NotFound`] if missing, [`GatewayError::Conflict`] if the invoice
    /// is not in `CONFIRMED` status, or [`GatewayError::Database`] on SQL failure.
    pub async fn mark_invoice_swept(&self, params: MarkSweptParams) -> GatewayResult<Invoice> {
        let mut tx = self.pool.begin().await?;
        let id_str = params.invoice_id.to_string();

        let existing_row: InvoiceRow = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, swept_at, completed_at
            FROM invoices
            WHERE id = ?
            "#,
        )
        .bind(&id_str)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            GatewayError::NotFound(format!("invoice {} not found", params.invoice_id))
        })?;

        let existing = Invoice::try_from(existing_row)?;
        if existing.status == InvoiceStatus::Swept {
            tx.commit().await?;
            return Ok(existing);
        }
        if existing.status != InvoiceStatus::Confirmed {
            return Err(GatewayError::Conflict(format!(
                "cannot mark invoice {} SWEPT from status {}",
                params.invoice_id, existing.status
            )));
        }

        let hashes_json = serde_json::to_string(&params.sweep_tx_hashes).map_err(|e| {
            GatewayError::Internal(format!("failed to serialize sweep hashes: {e}"))
        })?;
        let amount_i64 = params.sweep_amount_piconero.to_i64()?;
        let fee_i64 = params.sweep_fee_piconero.to_i64()?;
        let now_str = params.now.to_rfc3339();

        sqlx::query(
            r#"
            UPDATE invoices
            SET
                status = 'SWEPT',
                unlocked = 1,
                sweep_tx_hashes = ?,
                sweep_amount_piconero = ?,
                sweep_fee_piconero = ?,
                last_sweep_error = NULL,
                swept_at = ?,
                updated_at = ?
            WHERE id = ? AND status = 'CONFIRMED'
            "#,
        )
        .bind(hashes_json)
        .bind(amount_i64)
        .bind(fee_i64)
        .bind(&now_str)
        .bind(&now_str)
        .bind(&id_str)
        .execute(&mut *tx)
        .await?;

        if let Some(webhook) = params.webhook {
            insert_webhook_tx(&mut tx, &webhook).await?;
        }

        let updated_row: InvoiceRow = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, swept_at, completed_at
            FROM invoices
            WHERE id = ?
            "#,
        )
        .bind(&id_str)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Invoice::try_from(updated_row)
    }

    /// Records the latest transient sweep error without altering invoice status.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn record_sweep_error(
        &self,
        invoice_id: Uuid,
        error_msg: &str,
        now: DateTime<Utc>,
    ) -> GatewayResult<()> {
        sqlx::query(
            r#"
            UPDATE invoices
            SET last_sweep_error = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(error_msg)
        .bind(now.to_rfc3339())
        .bind(invoice_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetches pending webhook deliveries whose scheduled `next_attempt_at <= now`.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn fetch_due_webhooks(
        &self,
        now: DateTime<Utc>,
        limit: i64,
    ) -> GatewayResult<Vec<WebhookDelivery>> {
        let rows: Vec<WebhookRow> = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, event_type, dedupe_key, target_url,
                payload_json, signature_hex, status, attempts, max_attempts,
                next_attempt_at, last_status_code, last_error,
                created_at, updated_at, delivered_at
            FROM webhook_deliveries
            WHERE status = 'PENDING' AND next_attempt_at <= ?
            ORDER BY next_attempt_at ASC
            LIMIT ?
            "#,
        )
        .bind(now.to_rfc3339())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(WebhookDelivery::try_from).collect()
    }

    /// Marks a webhook delivery as `DELIVERED` and, in View-Only mode, transitions `CONFIRMED`
    /// invoices to `COMPLETED` inside the same atomic SQLite transaction.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn mark_webhook_delivered(
        &self,
        delivery_id: Uuid,
        invoice_id: Uuid,
        event_type: WebhookEventType,
        status_code: u16,
        now: DateTime<Utc>,
        complete_on_view_only: bool,
    ) -> GatewayResult<()> {
        let mut tx = self.pool.begin().await?;
        let now_str = now.to_rfc3339();

        sqlx::query(
            r#"
            UPDATE webhook_deliveries
            SET
                status = 'DELIVERED',
                attempts = attempts + 1,
                last_status_code = ?,
                last_error = NULL,
                delivered_at = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(i64::from(status_code))
        .bind(&now_str)
        .bind(&now_str)
        .bind(delivery_id.to_string())
        .execute(&mut *tx)
        .await?;

        if complete_on_view_only && event_type == WebhookEventType::Confirmed {
            sqlx::query(
                r#"
                UPDATE invoices
                SET
                    status = 'COMPLETED',
                    completed_at = COALESCE(completed_at, ?),
                    updated_at = ?
                WHERE id = ? AND status = 'CONFIRMED'
                "#,
            )
            .bind(&now_str)
            .bind(&now_str)
            .bind(invoice_id.to_string())
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Records a failed webhook attempt, scheduling exponential backoff or marking `FAILED`.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn mark_webhook_retry_or_failed(
        &self,
        delivery_id: Uuid,
        attempts: u32,
        next_attempt_at: Option<DateTime<Utc>>,
        status_code: Option<u16>,
        error_msg: &str,
        now: DateTime<Utc>,
    ) -> GatewayResult<()> {
        let now_str = now.to_rfc3339();
        let next_status = if next_attempt_at.is_some() {
            WebhookDeliveryStatus::Pending.as_str()
        } else {
            WebhookDeliveryStatus::Failed.as_str()
        };
        let next_attempt_str = next_attempt_at.unwrap_or(now).to_rfc3339();

        sqlx::query(
            r#"
            UPDATE webhook_deliveries
            SET
                status = ?,
                attempts = ?,
                next_attempt_at = ?,
                last_status_code = ?,
                last_error = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(next_status)
        .bind(i64::from(attempts))
        .bind(next_attempt_str)
        .bind(status_code.map(i64::from))
        .bind(error_msg)
        .bind(now_str)
        .bind(delivery_id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Lists all webhook outbox entries associated with an invoice.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn list_webhooks_for_invoice(
        &self,
        invoice_id: Uuid,
    ) -> GatewayResult<Vec<WebhookDelivery>> {
        let rows: Vec<WebhookRow> = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, event_type, dedupe_key, target_url,
                payload_json, signature_hex, status, attempts, max_attempts,
                next_attempt_at, last_status_code, last_error,
                created_at, updated_at, delivered_at
            FROM webhook_deliveries
            WHERE invoice_id = ?
            ORDER BY created_at ASC
            "#,
        )
        .bind(invoice_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(WebhookDelivery::try_from).collect()
    }
}

async fn upsert_transfer_tx(
    tx: &mut Transaction<'_, Sqlite>,
    invoice_id: &str,
    transfer: &ObservedTransfer,
    now: DateTime<Utc>,
) -> GatewayResult<()> {
    let amount_i64 = transfer.amount_piconero.to_i64()?;
    let conf_i64 = u64_to_i64(transfer.confirmations, "transfer.confirmations")?;
    let now_str = now.to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO invoice_transfers (
            invoice_id, txid, amount_piconero, confirmations,
            unlocked, double_spend_seen, in_pool, observed_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (invoice_id, txid) DO UPDATE SET
            amount_piconero = excluded.amount_piconero,
            confirmations = excluded.confirmations,
            unlocked = excluded.unlocked,
            double_spend_seen = MAX(invoice_transfers.double_spend_seen, excluded.double_spend_seen),
            in_pool = excluded.in_pool,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(invoice_id)
    .bind(&transfer.txid)
    .bind(amount_i64)
    .bind(conf_i64)
    .bind(i64::from(transfer.unlocked))
    .bind(i64::from(transfer.double_spend_seen))
    .bind(i64::from(transfer.in_pool))
    .bind(&now_str)
    .bind(&now_str)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

async fn insert_webhook_tx(
    tx: &mut Transaction<'_, Sqlite>,
    webhook: &NewWebhookDelivery,
) -> GatewayResult<()> {
    let now_str = webhook.now.to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO webhook_deliveries (
            id, invoice_id, event_type, dedupe_key, target_url,
            payload_json, signature_hex, status, attempts, max_attempts,
            next_attempt_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, ?, ?, ?, ?)
        ON CONFLICT (dedupe_key) DO NOTHING
        "#,
    )
    .bind(webhook.id.to_string())
    .bind(webhook.invoice_id.to_string())
    .bind(webhook.event_type.as_str())
    .bind(&webhook.dedupe_key)
    .bind(&webhook.target_url)
    .bind(&webhook.payload_json)
    .bind(&webhook.signature_hex)
    .bind(i64::from(webhook.max_attempts))
    .bind(&now_str)
    .bind(&now_str)
    .bind(&now_str)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

impl TryFrom<InvoiceRow> for Invoice {
    type Error = GatewayError;

    fn try_from(row: InvoiceRow) -> Result<Self, Self::Error> {
        let id = Uuid::parse_str(&row.id).map_err(|e| {
            GatewayError::Internal(format!("corrupt invoice uuid '{}': {e}", row.id))
        })?;
        let account_index = u32::try_from(row.account_index).map_err(|_| {
            GatewayError::Internal(format!("corrupt account_index {}", row.account_index))
        })?;
        let address_index = u32::try_from(row.address_index).map_err(|_| {
            GatewayError::Internal(format!("corrupt address_index {}", row.address_index))
        })?;
        let amount_piconero = Piconero::from_i64(row.amount_piconero)?;
        let received_piconero = Piconero::from_i64(row.received_piconero)?;
        let confirmations = u64::try_from(row.confirmations).map_err(|_| {
            GatewayError::Internal(format!("corrupt confirmations {}", row.confirmations))
        })?;
        let status = InvoiceStatus::from_str(&row.status)?;
        let sweep_tx_hashes: Vec<String> = serde_json::from_str(&row.sweep_tx_hashes)
            .map_err(|e| GatewayError::Internal(format!("corrupt sweep_tx_hashes JSON: {e}")))?;
        let sweep_amount_piconero = row
            .sweep_amount_piconero
            .map(Piconero::from_i64)
            .transpose()?;
        let sweep_fee_piconero = row.sweep_fee_piconero.map(Piconero::from_i64).transpose()?;

        Ok(Self {
            id,
            order_id: row.order_id,
            account_index,
            address_index,
            subaddress: row.subaddress,
            amount_piconero,
            received_piconero,
            confirmations,
            unlocked: row.unlocked != 0,
            double_spend_seen: row.double_spend_seen != 0,
            status,
            callback_url: row.callback_url,
            monero_uri: row.monero_uri,
            qr_code_base64: row.qr_code_base64,
            sweep_tx_hashes,
            sweep_amount_piconero,
            sweep_fee_piconero,
            last_sweep_error: row.last_sweep_error,
            created_at: parse_rfc3339(&row.created_at, "created_at")?,
            updated_at: parse_rfc3339(&row.updated_at, "updated_at")?,
            expires_at: parse_rfc3339(&row.expires_at, "expires_at")?,
            confirmed_at: row
                .confirmed_at
                .as_deref()
                .map(|s| parse_rfc3339(s, "confirmed_at"))
                .transpose()?,
            swept_at: row
                .swept_at
                .as_deref()
                .map(|s| parse_rfc3339(s, "swept_at"))
                .transpose()?,
            completed_at: row
                .completed_at
                .as_deref()
                .map(|s| parse_rfc3339(s, "completed_at"))
                .transpose()?,
        })
    }
}

impl TryFrom<TransferRow> for ObservedTransfer {
    type Error = GatewayError;

    fn try_from(row: TransferRow) -> Result<Self, Self::Error> {
        let amount_piconero = Piconero::from_i64(row.amount_piconero)?;
        let confirmations = u64::try_from(row.confirmations).map_err(|_| {
            GatewayError::Internal(format!(
                "corrupt transfer confirmations {}",
                row.confirmations
            ))
        })?;
        Ok(Self {
            txid: row.txid,
            amount_piconero,
            confirmations,
            unlocked: row.unlocked != 0,
            double_spend_seen: row.double_spend_seen != 0,
            in_pool: row.in_pool != 0,
        })
    }
}

impl TryFrom<WebhookRow> for WebhookDelivery {
    type Error = GatewayError;

    fn try_from(row: WebhookRow) -> Result<Self, Self::Error> {
        let id = Uuid::parse_str(&row.id)
            .map_err(|e| GatewayError::Internal(format!("corrupt webhook id '{}': {e}", row.id)))?;
        let invoice_id = Uuid::parse_str(&row.invoice_id).map_err(|e| {
            GatewayError::Internal(format!(
                "corrupt webhook invoice_id '{}': {e}",
                row.invoice_id
            ))
        })?;
        let event_type = WebhookEventType::from_str(&row.event_type)?;
        let status = WebhookDeliveryStatus::from_str(&row.status)?;
        let attempts = u32::try_from(row.attempts)
            .map_err(|_| GatewayError::Internal(format!("corrupt attempts {}", row.attempts)))?;
        let max_attempts = u32::try_from(row.max_attempts).map_err(|_| {
            GatewayError::Internal(format!("corrupt max_attempts {}", row.max_attempts))
        })?;
        let last_status_code = row
            .last_status_code
            .map(|code| {
                u16::try_from(code)
                    .map_err(|_| GatewayError::Internal(format!("corrupt HTTP status code {code}")))
            })
            .transpose()?;

        Ok(Self {
            id,
            invoice_id,
            event_type,
            dedupe_key: row.dedupe_key,
            target_url: row.target_url,
            payload_json: row.payload_json,
            signature_hex: row.signature_hex,
            status,
            attempts,
            max_attempts,
            next_attempt_at: parse_rfc3339(&row.next_attempt_at, "next_attempt_at")?,
            last_status_code,
            last_error: row.last_error,
            created_at: parse_rfc3339(&row.created_at, "created_at")?,
            updated_at: parse_rfc3339(&row.updated_at, "updated_at")?,
            delivered_at: row
                .delivered_at
                .as_deref()
                .map(|s| parse_rfc3339(s, "delivered_at"))
                .transpose()?,
        })
    }
}

fn parse_rfc3339(raw: &str, field: &str) -> GatewayResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| GatewayError::Internal(format!("corrupt RFC3339 timestamp '{field}': {e}")))
}

fn u64_to_i64(val: u64, field: &str) -> GatewayResult<i64> {
    i64::try_from(val)
        .map_err(|_| GatewayError::Internal(format!("{field} value {val} exceeds i64::MAX")))
}
