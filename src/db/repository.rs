//! Transactional SQLite repository for invoices, observed transfers, and webhook outbox.
//!
//! Every financial state transition and webhook enqueue operation runs atomically inside an
//! explicit SQLite transaction (`BEGIN ... COMMIT`), preserving consistency across process
//! crashes and preventing duplicate webhook emissions via database `UNIQUE` constraints.

use std::{collections::HashMap, str::FromStr, sync::Arc};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Sqlite, SqlitePool, Transaction};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    domain::{
        amount::Piconero,
        invoice::{
            Invoice, InvoiceStatus, ObservedTransfer, SubaddressTransferRecord,
            SubaddressTransferStatus, TransferClassification, WebhookEventType,
        },
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

/// Persisted crash-recovery state of an isolated subaddress sweep attempt (`XMR-003`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SweepAttemptStatus {
    /// Intent persisted in SQLite immediately before calling `monero-wallet-rpc sweep_all`.
    Prepared,
    /// `sweep_all` returned `tx_hash_list`; broadcast to daemon / waiting for confirmation.
    Submitted,
    /// Outgoing sweep transaction confirmed on-chain (`in` / `out` mined).
    Confirmed,
    /// Crash recovery matched an orphaned `PREPARED` attempt against `get_transfers(out/pending)`.
    Reconciled,
    /// Sweep aborted or confirmed absent after timeout; safe to retry.
    Failed,
    /// Outbound sweep transaction disappeared from `get_transfers(out, pending)` or flagged
    /// `double_spend_seen`; invoice escalated to `REORGED` and automatic re-sweep blocked.
    Reorged,
}

impl SweepAttemptStatus {
    /// Returns canonical uppercase database representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "PREPARED",
            Self::Submitted => "SUBMITTED",
            Self::Confirmed => "CONFIRMED",
            Self::Reconciled => "RECONCILED",
            Self::Failed => "FAILED",
            Self::Reorged => "REORGED",
        }
    }
}

impl FromStr for SweepAttemptStatus {
    type Err = GatewayError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PREPARED" => Ok(Self::Prepared),
            "SUBMITTED" => Ok(Self::Submitted),
            "CONFIRMED" => Ok(Self::Confirmed),
            "RECONCILED" => Ok(Self::Reconciled),
            "FAILED" => Ok(Self::Failed),
            "REORGED" => Ok(Self::Reorged),
            other => Err(GatewayError::Internal(format!(
                "unknown sweep attempt status '{other}'"
            ))),
        }
    }
}

/// Operator action resolving a `SWEEP_REORG_DETECTED` (`REORGED`) sweep incident (`XMR-041`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SweepResolutionAction {
    /// Fail-closed verified via RPC that the old sweep tx is dead; unblock invoice for re-sweep.
    AllowResweep,
    /// Operator confirmed settlement on-chain/cold wallet; mark attempt `RECONCILED` and restore `SWEPT` (or keep `EXPIRED`).
    MarkReconciled,
}

impl SweepResolutionAction {
    /// Returns canonical uppercase database representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowResweep => "ALLOW_RESWEEP",
            Self::MarkReconciled => "MARK_RECONCILED",
        }
    }
}

impl FromStr for SweepResolutionAction {
    type Err = GatewayError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ALLOW_RESWEEP" | "allow_resweep" => Ok(Self::AllowResweep),
            "MARK_RECONCILED" | "mark_reconciled" => Ok(Self::MarkReconciled),
            other => Err(GatewayError::Validation(format!(
                "unknown sweep resolution action '{other}'"
            ))),
        }
    }
}

/// Durable sweep execution ledger record persisted in `sweep_attempts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepAttempt {
    /// Unique sweep attempt UUID.
    pub id: Uuid,
    /// Target invoice UUID.
    pub invoice_id: Uuid,
    /// Wallet subaddress minor index swept.
    pub address_index: u32,
    /// Destination Monero address (cold wallet).
    pub destination_address: String,
    /// Snapshot of `subaddress_transfers.txid` values locked when preparing this sweep (`XMR-023`).
    pub snapshot_txids: Vec<String>,
    /// Current crash-recovery status.
    pub status: SweepAttemptStatus,
    /// Sweep transaction hashes (populated once submitted or reconciled).
    pub tx_hashes: Vec<String>,
    /// Total net piconero swept.
    pub swept_amount_piconero: Option<Piconero>,
    /// Total network fee paid in piconero.
    pub fee_piconero: Option<Piconero>,
    /// Error message recorded on failure.
    pub error_message: Option<String>,
    /// Operator incident resolution timestamp (UTC) when resolved (`XMR-041`).
    pub resolved_at: Option<DateTime<Utc>>,
    /// Operator resolution action recorded on `XMR-041` incident closure.
    pub resolution_action: Option<SweepResolutionAction>,
    /// Mandatory operator justification/audit note recorded on `XMR-041` incident closure.
    pub resolution_note: Option<String>,
    /// Creation timestamp (UTC).
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp (UTC).
    pub updated_at: DateTime<Utc>,
}

/// Atomic update payload committing a completed or reconciled [`SweepAttempt`] alongside
/// the `SWEPT` invoice transition and optional webhook delivery.
#[derive(Debug, Clone)]
pub struct CompleteSweepAttemptParams {
    /// Sweep attempt UUID (`PREPARED` or `SUBMITTED`).
    pub attempt_id: Uuid,
    /// Target invoice UUID.
    pub invoice_id: Uuid,
    /// Terminal attempt status (`Submitted`, `Confirmed`, or `Reconciled`).
    pub attempt_status: SweepAttemptStatus,
    /// Transaction hashes produced by `sweep_all` or recovered via `get_transfers`.
    pub sweep_tx_hashes: Vec<String>,
    /// Net piconero swept across these transactions.
    pub sweep_amount_piconero: Piconero,
    /// Network fee paid across these transactions.
    pub sweep_fee_piconero: Piconero,
    /// Optional `SWEPT` webhook outbox entry.
    pub webhook: Option<NewWebhookDelivery>,
    /// Current UTC timestamp.
    pub now: DateTime<Utc>,
}

/// Atomic update payload for recording a classified transfer in `subaddress_transfers` (`XMR-004`).
#[derive(Debug, Clone)]
pub struct RecordSubaddressTransferParams {
    /// Classified ledger record for `subaddress_transfers`.
    pub record: SubaddressTransferRecord,
    /// Full observed transfer snapshot for `invoice_transfers`.
    pub transfer: ObservedTransfer,
    /// Updated cumulative valid received piconero on the invoice.
    pub received_piconero: Piconero,
    /// Updated effective confirmation depth.
    pub confirmations: u64,
    /// Updated unlock flag.
    pub unlocked: bool,
    /// Optional signed `LATE_PAYMENT` or `OVERPAYMENT` webhook outbox entry.
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
    order_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
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
    reorg_epoch: i64,
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
    settled_at: Option<String>,
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
    orphaned: i64,
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

#[derive(Debug, FromRow)]
struct SweepAttemptRow {
    id: String,
    invoice_id: String,
    address_index: i64,
    destination_address: String,
    snapshot_txids_json: String,
    status: String,
    tx_hashes_json: String,
    swept_amount_piconero: Option<i64>,
    fee_piconero: Option<i64>,
    error_message: Option<String>,
    resolved_at: Option<String>,
    resolution_action: Option<String>,
    resolution_note: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, FromRow)]
struct SubaddressTransferRow {
    id: i64,
    txid: String,
    invoice_id: String,
    address_index: i64,
    amount_piconero: i64,
    confirmations: i64,
    classification: String,
    status: String,
    swept: i64,
    sweep_attempt_id: Option<String>,
    created_at: String,
}

impl InvoiceRepository {
    /// Creates a new repository backed by the given `SqlitePool`.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            order_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Acquires a per-`order_id` async mutex to serialize concurrent invoice creation requests
    /// so retried or racing requests never allocate orphaned Monero subaddresses (`XMR-019`).
    pub async fn acquire_order_lock(&self, order_id: &str) -> Arc<Mutex<()>> {
        let mut map = self.order_locks.lock().await;
        map.entry(order_id.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Prunes the per-`order_id` mutex once no other task holds or awaits it.
    pub async fn release_order_lock(&self, order_id: &str, lock: Arc<Mutex<()>>) {
        let mut map = self.order_locks.lock().await;
        if Arc::strong_count(&lock) <= 2 && lock.try_lock().is_ok() {
            map.remove(order_id);
        }
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
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
            ) VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?
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
        .bind(i64::from(invoice.reorg_epoch))
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
        .bind(invoice.settled_at.map(|ts| ts.to_rfc3339()))
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
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
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
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
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
            SELECT txid, amount_piconero, confirmations, unlocked, double_spend_seen, in_pool, orphaned
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

    /// Fetches all non-terminal invoices PLUS terminal invoices created on or after `cutoff`, or
    /// all invoices continuously when `cutoff` is `None` (`SUBADDRESS_MONITOR_DAYS=0`) so late
    /// payments and post-sweep overpayments never stop being detected (`XMR-004` / `P1-3`).
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn list_monitored_invoices(
        &self,
        cutoff: Option<DateTime<Utc>>,
    ) -> GatewayResult<Vec<Invoice>> {
        let rows: Vec<InvoiceRow> = match cutoff {
            Some(cutoff_ts) => {
                sqlx::query_as(
                    r#"
                    SELECT
                        id, order_id, account_index, address_index, subaddress,
                        amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                        reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                        sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                        created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
                    FROM invoices
                    WHERE status IN ('PENDING', 'UNDERPAID', 'MEMPOOL', 'CONFIRMING', 'CONFIRMED', 'SETTLED', 'REORGED')
                       OR created_at >= ?
                    ORDER BY created_at ASC
                    "#,
                )
                .bind(cutoff_ts.to_rfc3339())
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    r#"
                    SELECT
                        id, order_id, account_index, address_index, subaddress,
                        amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                        reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                        sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                        created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
                    FROM invoices
                    ORDER BY created_at ASC
                    "#,
                )
                .fetch_all(&self.pool)
                .await?
            }
        };

        rows.into_iter().map(Invoice::try_from).collect()
    }

    /// Lists all non-terminal invoices (`PENDING`, `UNDERPAID`, `MEMPOOL`, `CONFIRMING`, `CONFIRMED`, `SETTLED`, `REORGED`).
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn list_active_invoices(&self) -> GatewayResult<Vec<Invoice>> {
        let rows: Vec<InvoiceRow> = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
            FROM invoices
            WHERE status IN ('PENDING', 'UNDERPAID', 'MEMPOOL', 'CONFIRMING', 'CONFIRMED', 'SETTLED', 'REORGED')
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(Invoice::try_from).collect()
    }

    /// Atomically persists observed transfers, reconciles orphaned reorged transfers (`XMR-026`),
    /// updates state transitions & `reorg_epoch` (`XMR-025`), and enqueues optional webhook outbox entries.
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
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
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
        if matches!(
            existing.status,
            InvoiceStatus::Swept | InvoiceStatus::Expired
        ) {
            tx.commit().await?;
            return Ok(existing);
        }

        existing.status.validate_transition(params.next_status)?;

        for tr in &params.transfers {
            upsert_transfer_tx(&mut tx, &id_str, tr, params.now).await?;
        }

        let active_txids: Vec<&str> = params
            .transfers
            .iter()
            .filter(|tr| !tr.double_spend_seen && !tr.orphaned)
            .map(|tr| tr.txid.as_str())
            .collect();
        reconcile_orphaned_transfers_tx(&mut tx, &id_str, &active_txids, params.now).await?;

        let has_tainted_transfer: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM invoice_transfers WHERE invoice_id = ? AND double_spend_seen = 1)",
        )
        .bind(&id_str)
        .fetch_one(&mut *tx)
        .await?;

        let confirmed_at = if existing.confirmed_at.is_some() {
            existing.confirmed_at
        } else if matches!(
            params.next_status,
            InvoiceStatus::Confirmed | InvoiceStatus::Settled | InvoiceStatus::Completed
        ) {
            Some(params.now)
        } else {
            None
        };

        let settled_at = if existing.settled_at.is_some() {
            existing.settled_at
        } else if params.next_status == InvoiceStatus::Settled {
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
        let double_spend_flag = params.double_spend_seen || has_tainted_transfer;
        let next_reorg_epoch = if existing.status != InvoiceStatus::Reorged
            && params.next_status == InvoiceStatus::Reorged
        {
            existing.reorg_epoch.saturating_add(1)
        } else {
            existing.reorg_epoch
        };

        sqlx::query(
            r#"
            UPDATE invoices
            SET
                received_piconero = ?,
                confirmations = ?,
                unlocked = ?,
                double_spend_seen = ?,
                reorg_epoch = ?,
                status = ?,
                updated_at = ?,
                confirmed_at = ?,
                settled_at = ?,
                completed_at = ?
            WHERE id = ?
            "#,
        )
        .bind(received_i64)
        .bind(conf_i64)
        .bind(i64::from(params.unlocked))
        .bind(i64::from(double_spend_flag))
        .bind(i64::from(next_reorg_epoch))
        .bind(params.next_status.as_str())
        .bind(params.now.to_rfc3339())
        .bind(confirmed_at.map(|ts| ts.to_rfc3339()))
        .bind(settled_at.map(|ts| ts.to_rfc3339()))
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
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
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

    /// Reconciles orphaned or double-spent transfers on any monitored invoice (`XMR-026`).
    ///
    /// Marks disappeared/double-spent transfers in `invoice_transfers` (`orphaned = 1`) and
    /// active unswept rows in `subaddress_transfers` (`status = 'ORPHANED'`) without ever deleting rows.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn reconcile_orphaned_transfers(
        &self,
        invoice_id: Uuid,
        active_txids: &[String],
        now: DateTime<Utc>,
    ) -> GatewayResult<()> {
        let mut tx = self.pool.begin().await?;
        let id_str = invoice_id.to_string();
        let active_refs: Vec<&str> = active_txids.iter().map(String::as_str).collect();
        reconcile_orphaned_transfers_tx(&mut tx, &id_str, &active_refs, now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Atomically transitions a `SETTLED` invoice to `SWEPT` and enqueues the `SWEPT` webhook (`XMR-024`).
    ///
    /// # Errors
    /// Returns [`GatewayError::NotFound`] if missing, [`GatewayError::Conflict`] if the invoice
    /// is not in `SETTLED` status, or [`GatewayError::Database`] on SQL failure.
    pub async fn mark_invoice_swept(&self, params: MarkSweptParams) -> GatewayResult<Invoice> {
        let mut tx = self.pool.begin().await?;
        let id_str = params.invoice_id.to_string();

        let existing_row: InvoiceRow = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
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
        if existing.status != InvoiceStatus::Settled {
            return Err(GatewayError::Conflict(format!(
                "cannot mark invoice {} SWEPT from status {} (SETTLED finality required)",
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
                settled_at = COALESCE(settled_at, ?),
                sweep_tx_hashes = ?,
                sweep_amount_piconero = ?,
                sweep_fee_piconero = ?,
                last_sweep_error = NULL,
                swept_at = ?,
                updated_at = ?
            WHERE id = ? AND status = 'SETTLED'
            "#,
        )
        .bind(&now_str)
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
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
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

    /// Marks a webhook delivery as `DELIVERED` and, in View-Only mode, transitions `SETTLED`
    /// invoices to `COMPLETED` inside the same atomic SQLite transaction (`XMR-018`).
    ///
    /// Delivering an early `CONFIRMED` webhook keeps the invoice non-terminal so chain reorg
    /// monitoring remains active until `SETTLEMENT_CONFIRMATIONS` (`SETTLED`) is reached.
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

        if complete_on_view_only && event_type == WebhookEventType::Settled {
            sqlx::query(
                r#"
                UPDATE invoices
                SET
                    status = 'COMPLETED',
                    completed_at = COALESCE(completed_at, ?),
                    updated_at = ?
                WHERE id = ? AND status = 'SETTLED'
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

    /// Fetches a single webhook outbox entry by its UUID (`XMR-028`).
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn get_webhook_delivery_by_id(
        &self,
        webhook_id: Uuid,
    ) -> GatewayResult<Option<WebhookDelivery>> {
        let row: Option<WebhookRow> = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, event_type, dedupe_key, target_url,
                payload_json, signature_hex, status, attempts, max_attempts,
                next_attempt_at, last_status_code, last_error,
                created_at, updated_at, delivered_at
            FROM webhook_deliveries
            WHERE id = ?
            "#,
        )
        .bind(webhook_id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        row.map(WebhookDelivery::try_from).transpose()
    }

    /// Resets a `FAILED` or backed-off `PENDING` webhook delivery for immediate retry (`XMR-028`).
    ///
    /// Returns `Ok(None)` if no webhook delivery with `webhook_id` exists.
    ///
    /// # Errors
    /// Returns [`GatewayError::Conflict`] if the webhook is already `DELIVERED`, or
    /// [`GatewayError::Database`] on SQL failure.
    pub async fn reset_webhook_delivery_for_retry(
        &self,
        webhook_id: Uuid,
        now: DateTime<Utc>,
    ) -> GatewayResult<Option<WebhookDelivery>> {
        let mut tx = self.pool.begin().await?;
        let id_str = webhook_id.to_string();

        let existing_row: Option<WebhookRow> = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, event_type, dedupe_key, target_url,
                payload_json, signature_hex, status, attempts, max_attempts,
                next_attempt_at, last_status_code, last_error,
                created_at, updated_at, delivered_at
            FROM webhook_deliveries
            WHERE id = ?
            "#,
        )
        .bind(&id_str)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = existing_row else {
            tx.commit().await?;
            return Ok(None);
        };
        let existing = WebhookDelivery::try_from(row)?;
        if existing.status == WebhookDeliveryStatus::Delivered {
            return Err(GatewayError::Conflict(format!(
                "webhook delivery {webhook_id} is already DELIVERED"
            )));
        }

        let now_str = now.to_rfc3339();
        sqlx::query(
            r#"
            UPDATE webhook_deliveries
            SET
                status = 'PENDING',
                attempts = 0,
                next_attempt_at = ?,
                last_status_code = NULL,
                last_error = NULL,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&now_str)
        .bind(&now_str)
        .bind(&id_str)
        .execute(&mut *tx)
        .await?;

        let updated_row: WebhookRow = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, event_type, dedupe_key, target_url,
                payload_json, signature_hex, status, attempts, max_attempts,
                next_attempt_at, last_status_code, last_error,
                created_at, updated_at, delivered_at
            FROM webhook_deliveries
            WHERE id = ?
            "#,
        )
        .bind(&id_str)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some(WebhookDelivery::try_from(updated_row)?))
    }

    /// Resets all `FAILED` (or backed-off `PENDING`) webhook deliveries for `invoice_id` so they
    /// are immediately retried by the webhook dispatcher (`XMR-028`).
    ///
    /// # Errors
    /// Returns [`GatewayError::NotFound`] if `invoice_id` does not exist, or [`GatewayError::Database`]
    /// on SQL failure.
    pub async fn reset_failed_webhooks_for_invoice(
        &self,
        invoice_id: Uuid,
        now: DateTime<Utc>,
    ) -> GatewayResult<Vec<WebhookDelivery>> {
        let mut tx = self.pool.begin().await?;
        let id_str = invoice_id.to_string();

        let exists: Option<String> = sqlx::query_scalar("SELECT id FROM invoices WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&mut *tx)
            .await?;
        if exists.is_none() {
            return Err(GatewayError::NotFound(format!(
                "invoice {invoice_id} not found"
            )));
        }

        let now_str = now.to_rfc3339();
        sqlx::query(
            r#"
            UPDATE webhook_deliveries
            SET
                status = 'PENDING',
                attempts = 0,
                next_attempt_at = ?,
                last_status_code = NULL,
                last_error = NULL,
                updated_at = ?
            WHERE invoice_id = ? AND status IN ('FAILED', 'PENDING')
            "#,
        )
        .bind(&now_str)
        .bind(&now_str)
        .bind(&id_str)
        .execute(&mut *tx)
        .await?;

        let rows: Vec<WebhookRow> = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, event_type, dedupe_key, target_url,
                payload_json, signature_hex, status, attempts, max_attempts,
                next_attempt_at, last_status_code, last_error,
                created_at, updated_at, delivered_at
            FROM webhook_deliveries
            WHERE invoice_id = ? AND status = 'PENDING'
            ORDER BY created_at ASC
            "#,
        )
        .bind(&id_str)
        .fetch_all(&mut *tx)
        .await?;

        tx.commit().await?;
        rows.into_iter().map(WebhookDelivery::try_from).collect()
    }

    /// Persists a `PREPARED` row in `sweep_attempts` BEFORE issuing `sweep_all` RPC (`XMR-003` / `XMR-023`).
    ///
    /// Captures the exact snapshot of currently `ACTIVE`, unswept `subaddress_transfers.txid` rows
    /// for `invoice_id` so newly arriving post-sweep inflows are never erroneously marked swept.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn create_prepared_sweep_attempt(
        &self,
        invoice_id: Uuid,
        address_index: u32,
        destination_address: &str,
        now: DateTime<Utc>,
    ) -> GatewayResult<SweepAttempt> {
        let mut tx = self.pool.begin().await?;
        let id = Uuid::new_v4();
        let inv_str = invoice_id.to_string();
        let now_str = now.to_rfc3339();

        let snapshot_txids: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT txid
            FROM subaddress_transfers
            WHERE invoice_id = ? AND status = 'ACTIVE' AND swept = 0
            ORDER BY id ASC
            "#,
        )
        .bind(&inv_str)
        .fetch_all(&mut *tx)
        .await?;

        let snapshot_json = serde_json::to_string(&snapshot_txids).map_err(|e| {
            GatewayError::Internal(format!("failed to serialize snapshot txids: {e}"))
        })?;

        sqlx::query(
            r#"
            INSERT INTO sweep_attempts (
                id, invoice_id, address_index, destination_address,
                snapshot_txids_json, status, tx_hashes_json, swept_amount_piconero, fee_piconero,
                error_message, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'PREPARED', '[]', NULL, NULL, NULL, ?, ?)
            "#,
        )
        .bind(id.to_string())
        .bind(&inv_str)
        .bind(i64::from(address_index))
        .bind(destination_address)
        .bind(snapshot_json)
        .bind(&now_str)
        .bind(&now_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(SweepAttempt {
            id,
            invoice_id,
            address_index,
            destination_address: destination_address.to_string(),
            snapshot_txids,
            status: SweepAttemptStatus::Prepared,
            tx_hashes: Vec::new(),
            swept_amount_piconero: None,
            fee_piconero: None,
            error_message: None,
            resolved_at: None,
            resolution_action: None,
            resolution_note: None,
            created_at: now,
            updated_at: now,
        })
    }

    /// Lists all `PREPARED` or `SUBMITTED` sweep attempts requiring reconciliation.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn list_in_flight_sweep_attempts(&self) -> GatewayResult<Vec<SweepAttempt>> {
        let rows: Vec<SweepAttemptRow> = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, address_index, destination_address, snapshot_txids_json,
                status, tx_hashes_json, swept_amount_piconero, fee_piconero,
                error_message, resolved_at, resolution_action, resolution_note,
                created_at, updated_at
            FROM sweep_attempts
            WHERE status IN ('PREPARED', 'SUBMITTED')
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(SweepAttempt::try_from).collect()
    }

    /// Lists all active (`PREPARED`, `SUBMITTED`) and finalized (`CONFIRMED`, `RECONCILED`)
    /// sweep attempts whose parent invoice remains within the monitoring window (`cutoff`) and
    /// which have not already been explicitly closed by operator `MARK_RECONCILED` resolution.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn list_monitored_sweep_attempts(
        &self,
        cutoff: Option<DateTime<Utc>>,
    ) -> GatewayResult<Vec<SweepAttempt>> {
        let rows: Vec<SweepAttemptRow> = match cutoff {
            Some(cutoff_ts) => {
                sqlx::query_as(
                    r#"
                    SELECT
                        sa.id, sa.invoice_id, sa.address_index, sa.destination_address,
                        sa.snapshot_txids_json, sa.status, sa.tx_hashes_json,
                        sa.swept_amount_piconero, sa.fee_piconero, sa.error_message,
                        sa.resolved_at, sa.resolution_action, sa.resolution_note,
                        sa.created_at, sa.updated_at
                    FROM sweep_attempts sa
                    JOIN invoices inv ON inv.id = sa.invoice_id
                    WHERE COALESCE(sa.resolution_action, '') != 'MARK_RECONCILED'
                      AND (
                          sa.status IN ('PREPARED', 'SUBMITTED')
                          OR (sa.status IN ('CONFIRMED', 'RECONCILED') AND inv.created_at >= ?)
                      )
                    ORDER BY sa.created_at ASC
                    "#,
                )
                .bind(cutoff_ts.to_rfc3339())
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    r#"
                    SELECT
                        id, invoice_id, address_index, destination_address, snapshot_txids_json,
                        status, tx_hashes_json, swept_amount_piconero, fee_piconero,
                        error_message, resolved_at, resolution_action, resolution_note,
                        created_at, updated_at
                    FROM sweep_attempts
                    WHERE COALESCE(resolution_action, '') != 'MARK_RECONCILED'
                      AND status IN ('PREPARED', 'SUBMITTED', 'CONFIRMED', 'RECONCILED')
                    ORDER BY created_at ASC
                    "#,
                )
                .fetch_all(&self.pool)
                .await?
            }
        };

        rows.into_iter().map(SweepAttempt::try_from).collect()
    }

    /// Returns `true` if `invoice_id` has an unresolved `REORGED` sweep incident (`SWEEP_REORG_DETECTED`)
    /// requiring manual operator intervention before any further sweep execution.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn has_reorged_sweep_attempt(&self, invoice_id: Uuid) -> GatewayResult<bool> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM sweep_attempts
            WHERE invoice_id = ? AND status = 'REORGED'
            "#,
        )
        .bind(invoice_id.to_string())
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Lists all `PREPARED` or `SUBMITTED` sweep attempts for a specific invoice.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn list_in_flight_sweep_attempts_for_invoice(
        &self,
        invoice_id: Uuid,
    ) -> GatewayResult<Vec<SweepAttempt>> {
        let rows: Vec<SweepAttemptRow> = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, address_index, destination_address, snapshot_txids_json,
                status, tx_hashes_json, swept_amount_piconero, fee_piconero,
                error_message, resolved_at, resolution_action, resolution_note,
                created_at, updated_at
            FROM sweep_attempts
            WHERE invoice_id = ? AND status IN ('PREPARED', 'SUBMITTED')
            ORDER BY created_at ASC
            "#,
        )
        .bind(invoice_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(SweepAttempt::try_from).collect()
    }

    /// Lists every sweep attempt recorded for `invoice_id` in chronological order.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn list_sweep_attempts_for_invoice(
        &self,
        invoice_id: Uuid,
    ) -> GatewayResult<Vec<SweepAttempt>> {
        let rows: Vec<SweepAttemptRow> = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, address_index, destination_address, snapshot_txids_json,
                status, tx_hashes_json, swept_amount_piconero, fee_piconero,
                error_message, resolved_at, resolution_action, resolution_note,
                created_at, updated_at
            FROM sweep_attempts
            WHERE invoice_id = ?
            ORDER BY created_at ASC
            "#,
        )
        .bind(invoice_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(SweepAttempt::try_from).collect()
    }

    /// Marks an in-flight [`SweepAttempt`] `FAILED` and records the diagnostic error on both
    /// `sweep_attempts` and `invoices`.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn mark_sweep_attempt_failed(
        &self,
        attempt_id: Uuid,
        invoice_id: Uuid,
        error_msg: &str,
        now: DateTime<Utc>,
    ) -> GatewayResult<()> {
        let mut tx = self.pool.begin().await?;
        let now_str = now.to_rfc3339();

        sqlx::query(
            r#"
            UPDATE sweep_attempts
            SET status = 'FAILED', error_message = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(error_msg)
        .bind(&now_str)
        .bind(attempt_id.to_string())
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            UPDATE invoices
            SET last_sweep_error = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(error_msg)
        .bind(&now_str)
        .bind(invoice_id.to_string())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Updates a [`SweepAttempt`] status (e.g., advancing `SUBMITTED` -> `CONFIRMED` once mined).
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn update_sweep_attempt_status(
        &self,
        attempt_id: Uuid,
        status: SweepAttemptStatus,
        now: DateTime<Utc>,
    ) -> GatewayResult<()> {
        sqlx::query(
            r#"
            UPDATE sweep_attempts
            SET status = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(status.as_str())
        .bind(now.to_rfc3339())
        .bind(attempt_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Escalates an affected [`SweepAttempt`] to `REORGED` with `SWEEP_REORG_DETECTED` error
    /// diagnostics, atomically transitions a `SWEPT` invoice to `REORGED` (or preserves `EXPIRED`
    /// while recording the incident), increments `reorg_epoch`, and enqueues the epoch-scoped
    /// `REORGED` webhook (`XMR-042`).
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure or [`GatewayError::Domain`] on illegal
    /// state transition.
    pub async fn mark_sweep_attempt_reorged(
        &self,
        attempt_id: Uuid,
        invoice_id: Uuid,
        error_msg: &str,
        webhook: Option<NewWebhookDelivery>,
        now: DateTime<Utc>,
    ) -> GatewayResult<Option<Invoice>> {
        let mut tx = self.pool.begin().await?;
        let now_str = now.to_rfc3339();
        let inv_str = invoice_id.to_string();

        sqlx::query(
            r#"
            UPDATE sweep_attempts
            SET status = 'REORGED', error_message = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(error_msg)
        .bind(&now_str)
        .bind(attempt_id.to_string())
        .execute(&mut *tx)
        .await?;

        let existing_row: Option<InvoiceRow> = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
            FROM invoices
            WHERE id = ?
            "#,
        )
        .bind(&inv_str)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(existing_row) = existing_row else {
            tx.commit().await?;
            return Ok(None);
        };
        let existing = Invoice::try_from(existing_row)?;
        let next_epoch = existing.reorg_epoch.saturating_add(1);

        if existing.status == InvoiceStatus::Swept {
            existing
                .status
                .validate_transition(InvoiceStatus::Reorged)?;
            sqlx::query(
                r#"
                UPDATE invoices
                SET
                    status = 'REORGED',
                    reorg_epoch = ?,
                    last_sweep_error = ?,
                    updated_at = ?
                WHERE id = ?
                "#,
            )
            .bind(i64::from(next_epoch))
            .bind(error_msg)
            .bind(&now_str)
            .bind(&inv_str)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                r#"
                UPDATE invoices
                SET
                    reorg_epoch = ?,
                    last_sweep_error = ?,
                    updated_at = ?
                WHERE id = ?
                "#,
            )
            .bind(i64::from(next_epoch))
            .bind(error_msg)
            .bind(&now_str)
            .bind(&inv_str)
            .execute(&mut *tx)
            .await?;
        }

        if let Some(wh) = webhook {
            insert_webhook_tx(&mut tx, &wh).await?;
        }

        let updated_row: InvoiceRow = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
            FROM invoices
            WHERE id = ?
            "#,
        )
        .bind(&inv_str)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some(Invoice::try_from(updated_row)?))
    }

    /// Fetches the target `REORGED` sweep attempt for `invoice_id` (`XMR-041`).
    ///
    /// # Errors
    /// Returns [`GatewayError::NotFound`] if the invoice or specified `attempt_id` does not exist,
    /// or [`GatewayError::Conflict`] if no `REORGED` sweep incident exists for resolution.
    pub async fn get_reorged_sweep_attempt(
        &self,
        invoice_id: Uuid,
        attempt_id: Option<Uuid>,
    ) -> GatewayResult<(Invoice, SweepAttempt)> {
        let invoice = self
            .get_invoice_by_id(invoice_id)
            .await?
            .ok_or_else(|| GatewayError::NotFound(format!("invoice {invoice_id} not found")))?;

        let row: Option<SweepAttemptRow> = match attempt_id {
            Some(aid) => {
                sqlx::query_as(
                    r#"
                    SELECT
                        id, invoice_id, address_index, destination_address, snapshot_txids_json,
                        status, tx_hashes_json, swept_amount_piconero, fee_piconero,
                        error_message, resolved_at, resolution_action, resolution_note,
                        created_at, updated_at
                    FROM sweep_attempts
                    WHERE id = ? AND invoice_id = ?
                    "#,
                )
                .bind(aid.to_string())
                .bind(invoice_id.to_string())
                .fetch_optional(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    r#"
                    SELECT
                        id, invoice_id, address_index, destination_address, snapshot_txids_json,
                        status, tx_hashes_json, swept_amount_piconero, fee_piconero,
                        error_message, resolved_at, resolution_action, resolution_note,
                        created_at, updated_at
                    FROM sweep_attempts
                    WHERE invoice_id = ? AND status = 'REORGED'
                    ORDER BY created_at DESC
                    LIMIT 1
                    "#,
                )
                .bind(invoice_id.to_string())
                .fetch_optional(&self.pool)
                .await?
            }
        };

        let Some(row) = row else {
            return Err(match attempt_id {
                Some(aid) => GatewayError::NotFound(format!(
                    "sweep attempt {aid} not found for invoice {invoice_id}"
                )),
                None => GatewayError::Conflict(format!(
                    "invoice {invoice_id} has no unresolved REORGED sweep attempt"
                )),
            });
        };

        let attempt = SweepAttempt::try_from(row)?;
        if attempt.status != SweepAttemptStatus::Reorged {
            return Err(GatewayError::Conflict(format!(
                "sweep attempt {} is in status {}, expected REORGED",
                attempt.id,
                attempt.status.as_str()
            )));
        }

        Ok((invoice, attempt))
    }

    /// Resolves a `REORGED` sweep incident with `ALLOW_RESWEEP` after RPC has confirmed none of
    /// its transactions remain live in `out`, `pending`, or `pool` (`XMR-041`).
    ///
    /// Preserves the `sweep_attempts` audit row (`status = 'FAILED'`, `resolved_at`,
    /// `resolution_action = 'ALLOW_RESWEEP'`, `resolution_note`), restores non-`ORPHANED`
    /// `snapshot_txids` in `subaddress_transfers` back to `'ACTIVE'` (`swept = 0`), and deducts
    /// the invalidated attempt's hashes/amounts from `invoices` so a fresh sweep is clean.
    ///
    /// # Errors
    /// Returns [`GatewayError::Conflict`] if the attempt is no longer `REORGED`,
    /// [`GatewayError::NotFound`] if missing, or [`GatewayError::Database`] on SQL failure.
    pub async fn resolve_sweep_incident_allow_resweep(
        &self,
        attempt_id: Uuid,
        invoice_id: Uuid,
        note: &str,
        now: DateTime<Utc>,
    ) -> GatewayResult<(Invoice, SweepAttempt)> {
        let mut tx = self.pool.begin().await?;
        let now_str = now.to_rfc3339();
        let inv_str = invoice_id.to_string();
        let att_str = attempt_id.to_string();

        let existing_inv_row: InvoiceRow = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
            FROM invoices
            WHERE id = ?
            "#,
        )
        .bind(&inv_str)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("invoice {invoice_id} not found")))?;
        let existing_inv = Invoice::try_from(existing_inv_row)?;

        let att_row: SweepAttemptRow = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, address_index, destination_address, snapshot_txids_json,
                status, tx_hashes_json, swept_amount_piconero, fee_piconero,
                error_message, resolved_at, resolution_action, resolution_note,
                created_at, updated_at
            FROM sweep_attempts
            WHERE id = ? AND invoice_id = ?
            "#,
        )
        .bind(&att_str)
        .bind(&inv_str)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            GatewayError::NotFound(format!(
                "sweep attempt {attempt_id} not found for invoice {invoice_id}"
            ))
        })?;
        let attempt = SweepAttempt::try_from(att_row)?;
        if attempt.status != SweepAttemptStatus::Reorged {
            return Err(GatewayError::Conflict(format!(
                "sweep attempt {attempt_id} is in status {}, expected REORGED",
                attempt.status.as_str()
            )));
        }

        sqlx::query(
            r#"
            UPDATE sweep_attempts
            SET
                status = 'FAILED',
                resolved_at = ?,
                resolution_action = 'ALLOW_RESWEEP',
                resolution_note = ?,
                updated_at = ?
            WHERE id = ? AND status = 'REORGED'
            "#,
        )
        .bind(&now_str)
        .bind(note)
        .bind(&now_str)
        .bind(&att_str)
        .execute(&mut *tx)
        .await?;

        if !attempt.snapshot_txids.is_empty() {
            let mut qb: sqlx::QueryBuilder<Sqlite> = sqlx::QueryBuilder::new(
                "UPDATE subaddress_transfers SET swept = 0, status = 'ACTIVE', sweep_attempt_id = NULL WHERE invoice_id = ",
            );
            qb.push_bind(&inv_str);
            qb.push(" AND status = 'SWEPT' AND txid IN (");
            let mut sep = qb.separated(", ");
            for txid in &attempt.snapshot_txids {
                sep.push_bind(txid);
            }
            qb.push(")");
            qb.build().execute(&mut *tx).await?;
        }
        sqlx::query(
            r#"
            UPDATE subaddress_transfers
            SET swept = 0, status = 'ACTIVE', sweep_attempt_id = NULL
            WHERE invoice_id = ? AND sweep_attempt_id = ? AND status = 'SWEPT'
            "#,
        )
        .bind(&inv_str)
        .bind(&att_str)
        .execute(&mut *tx)
        .await?;

        let remaining_hashes: Vec<String> = existing_inv
            .sweep_tx_hashes
            .iter()
            .filter(|h| !attempt.tx_hashes.contains(h))
            .cloned()
            .collect();
        let hashes_json = serde_json::to_string(&remaining_hashes).map_err(|e| {
            GatewayError::Internal(format!("failed to serialize remaining sweep hashes: {e}"))
        })?;

        let (next_amt_i64, next_fee_i64) = if remaining_hashes.is_empty() {
            (None, None)
        } else {
            let amt = existing_inv.sweep_amount_piconero.map(|prev| {
                prev.as_u64()
                    .saturating_sub(attempt.swept_amount_piconero.map_or(0, Piconero::as_u64))
            });
            let fee = existing_inv.sweep_fee_piconero.map(|prev| {
                prev.as_u64()
                    .saturating_sub(attempt.fee_piconero.map_or(0, Piconero::as_u64))
            });
            (
                amt.map(|v| Piconero(v).to_i64()).transpose()?,
                fee.map(|v| Piconero(v).to_i64()).transpose()?,
            )
        };

        sqlx::query(
            r#"
            UPDATE invoices
            SET
                sweep_tx_hashes = ?,
                sweep_amount_piconero = ?,
                sweep_fee_piconero = ?,
                last_sweep_error = NULL,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(hashes_json)
        .bind(next_amt_i64)
        .bind(next_fee_i64)
        .bind(&now_str)
        .bind(&inv_str)
        .execute(&mut *tx)
        .await?;

        let updated_inv_row: InvoiceRow = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
            FROM invoices
            WHERE id = ?
            "#,
        )
        .bind(&inv_str)
        .fetch_one(&mut *tx)
        .await?;

        let updated_att_row: SweepAttemptRow = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, address_index, destination_address, snapshot_txids_json,
                status, tx_hashes_json, swept_amount_piconero, fee_piconero,
                error_message, resolved_at, resolution_action, resolution_note,
                created_at, updated_at
            FROM sweep_attempts
            WHERE id = ?
            "#,
        )
        .bind(&att_str)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok((
            Invoice::try_from(updated_inv_row)?,
            SweepAttempt::try_from(updated_att_row)?,
        ))
    }

    /// Resolves a `REORGED` sweep incident with `MARK_RECONCILED` when an operator confirms the
    /// sweep or replacement transaction settled cold storage (`XMR-041`).
    ///
    /// Transitions `sweep_attempts.status` to `'RECONCILED'` with audit fields and transitions the
    /// invoice back to `'SWEPT'` (unless `EXPIRED`, which preserves `'EXPIRED'`).
    ///
    /// # Errors
    /// Returns [`GatewayError::Conflict`] if the attempt is no longer `REORGED`,
    /// [`GatewayError::NotFound`] if missing, or [`GatewayError::Database`] on SQL failure.
    pub async fn resolve_sweep_incident_mark_reconciled(
        &self,
        attempt_id: Uuid,
        invoice_id: Uuid,
        replacement_tx_hash: Option<&str>,
        note: &str,
        now: DateTime<Utc>,
    ) -> GatewayResult<(Invoice, SweepAttempt)> {
        let mut tx = self.pool.begin().await?;
        let now_str = now.to_rfc3339();
        let inv_str = invoice_id.to_string();
        let att_str = attempt_id.to_string();

        let existing_inv_row: InvoiceRow = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
            FROM invoices
            WHERE id = ?
            "#,
        )
        .bind(&inv_str)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| GatewayError::NotFound(format!("invoice {invoice_id} not found")))?;
        let existing_inv = Invoice::try_from(existing_inv_row)?;

        let att_row: SweepAttemptRow = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, address_index, destination_address, snapshot_txids_json,
                status, tx_hashes_json, swept_amount_piconero, fee_piconero,
                error_message, resolved_at, resolution_action, resolution_note,
                created_at, updated_at
            FROM sweep_attempts
            WHERE id = ? AND invoice_id = ?
            "#,
        )
        .bind(&att_str)
        .bind(&inv_str)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            GatewayError::NotFound(format!(
                "sweep attempt {attempt_id} not found for invoice {invoice_id}"
            ))
        })?;
        let attempt = SweepAttempt::try_from(att_row)?;
        if attempt.status != SweepAttemptStatus::Reorged {
            return Err(GatewayError::Conflict(format!(
                "sweep attempt {attempt_id} is in status {}, expected REORGED",
                attempt.status.as_str()
            )));
        }

        let mut att_hashes = attempt.tx_hashes.clone();
        let mut inv_hashes = existing_inv.sweep_tx_hashes.clone();
        if let Some(rep_hash) = replacement_tx_hash {
            if !att_hashes.iter().any(|h| h == rep_hash) {
                att_hashes.push(rep_hash.to_string());
            }
            if !inv_hashes.iter().any(|h| h == rep_hash) {
                inv_hashes.push(rep_hash.to_string());
            }
        }

        let att_hashes_json = serde_json::to_string(&att_hashes).map_err(|e| {
            GatewayError::Internal(format!("failed to serialize sweep attempt hashes: {e}"))
        })?;
        let inv_hashes_json = serde_json::to_string(&inv_hashes).map_err(|e| {
            GatewayError::Internal(format!("failed to serialize invoice sweep hashes: {e}"))
        })?;

        sqlx::query(
            r#"
            UPDATE sweep_attempts
            SET
                status = 'RECONCILED',
                tx_hashes_json = ?,
                resolved_at = ?,
                resolution_action = 'MARK_RECONCILED',
                resolution_note = ?,
                updated_at = ?
            WHERE id = ? AND status = 'REORGED'
            "#,
        )
        .bind(att_hashes_json)
        .bind(&now_str)
        .bind(note)
        .bind(&now_str)
        .bind(&att_str)
        .execute(&mut *tx)
        .await?;

        let next_status = if existing_inv.status == InvoiceStatus::Expired {
            InvoiceStatus::Expired
        } else {
            existing_inv
                .status
                .validate_transition(InvoiceStatus::Swept)?;
            InvoiceStatus::Swept
        };

        sqlx::query(
            r#"
            UPDATE invoices
            SET
                status = ?,
                sweep_tx_hashes = ?,
                last_sweep_error = NULL,
                swept_at = CASE WHEN ? = 'SWEPT' THEN COALESCE(swept_at, ?) ELSE swept_at END,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(next_status.as_str())
        .bind(inv_hashes_json)
        .bind(next_status.as_str())
        .bind(&now_str)
        .bind(&now_str)
        .bind(&inv_str)
        .execute(&mut *tx)
        .await?;

        let updated_inv_row: InvoiceRow = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
            FROM invoices
            WHERE id = ?
            "#,
        )
        .bind(&inv_str)
        .fetch_one(&mut *tx)
        .await?;

        let updated_att_row: SweepAttemptRow = sqlx::query_as(
            r#"
            SELECT
                id, invoice_id, address_index, destination_address, snapshot_txids_json,
                status, tx_hashes_json, swept_amount_piconero, fee_piconero,
                error_message, resolved_at, resolution_action, resolution_note,
                created_at, updated_at
            FROM sweep_attempts
            WHERE id = ?
            "#,
        )
        .bind(&att_str)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok((
            Invoice::try_from(updated_inv_row)?,
            SweepAttempt::try_from(updated_att_row)?,
        ))
    }

    /// Atomically updates `sweep_attempts` (`SUBMITTED`/`CONFIRMED`/`RECONCILED`), transitions the
    /// `SETTLED` invoice to `SWEPT` (or appends residual overpayment sweep hashes/amounts if already
    /// `SWEPT`/`EXPIRED`), marks ONLY the attempt's `snapshot_txids` in `subaddress_transfers` as
    /// `swept = 1, status = 'SWEPT'` (`XMR-023`), and enqueues the `SWEPT` webhook delivery.
    ///
    /// # Errors
    /// Returns [`GatewayError::NotFound`] if the invoice is missing, [`GatewayError::Conflict`] if
    /// the invoice is not in `SETTLED`, `SWEPT`, or `EXPIRED` status, or [`GatewayError::Database`]
    /// on SQL failure.
    pub async fn complete_sweep_attempt(
        &self,
        params: CompleteSweepAttemptParams,
    ) -> GatewayResult<Invoice> {
        let mut tx = self.pool.begin().await?;
        let id_str = params.invoice_id.to_string();
        let attempt_id_str = params.attempt_id.to_string();

        let existing_row: InvoiceRow = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
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
        if !matches!(
            existing.status,
            InvoiceStatus::Settled | InvoiceStatus::Swept | InvoiceStatus::Expired
        ) {
            return Err(GatewayError::Conflict(format!(
                "cannot complete sweep for invoice {} from status {} (SETTLED finality required)",
                params.invoice_id, existing.status
            )));
        }

        let attempt_meta: Option<(String, String)> = sqlx::query_as(
            "SELECT snapshot_txids_json, created_at FROM sweep_attempts WHERE id = ?",
        )
        .bind(&attempt_id_str)
        .fetch_optional(&mut *tx)
        .await?;

        let (snapshot_txids, attempt_created_at) = match attempt_meta {
            Some((json, created)) => {
                let parsed: Vec<String> = serde_json::from_str(&json).map_err(|e| {
                    GatewayError::Internal(format!(
                        "corrupt sweep_attempt snapshot_txids_json: {e}"
                    ))
                })?;
                (parsed, Some(created))
            }
            None => (Vec::new(), None),
        };

        let attempt_hashes_json = serde_json::to_string(&params.sweep_tx_hashes).map_err(|e| {
            GatewayError::Internal(format!("failed to serialize attempt sweep hashes: {e}"))
        })?;
        let attempt_amt_i64 = params.sweep_amount_piconero.to_i64()?;
        let attempt_fee_i64 = params.sweep_fee_piconero.to_i64()?;
        let now_str = params.now.to_rfc3339();

        sqlx::query(
            r#"
            UPDATE sweep_attempts
            SET
                status = ?,
                tx_hashes_json = ?,
                swept_amount_piconero = ?,
                fee_piconero = ?,
                error_message = NULL,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(params.attempt_status.as_str())
        .bind(&attempt_hashes_json)
        .bind(attempt_amt_i64)
        .bind(attempt_fee_i64)
        .bind(&now_str)
        .bind(&attempt_id_str)
        .execute(&mut *tx)
        .await?;

        let (merged_hashes, total_amount, total_fee) = if !existing.sweep_tx_hashes.is_empty() {
            let mut hashes = existing.sweep_tx_hashes.clone();
            let mut has_new_tx = false;
            for h in &params.sweep_tx_hashes {
                if !hashes.contains(h) {
                    hashes.push(h.clone());
                    has_new_tx = true;
                }
            }
            if has_new_tx {
                let prev_amt = existing.sweep_amount_piconero.unwrap_or(Piconero::ZERO);
                let prev_fee = existing.sweep_fee_piconero.unwrap_or(Piconero::ZERO);
                (
                    hashes,
                    prev_amt.checked_add(params.sweep_amount_piconero)?,
                    prev_fee.checked_add(params.sweep_fee_piconero)?,
                )
            } else {
                (
                    hashes,
                    existing
                        .sweep_amount_piconero
                        .unwrap_or(params.sweep_amount_piconero),
                    existing
                        .sweep_fee_piconero
                        .unwrap_or(params.sweep_fee_piconero),
                )
            }
        } else {
            (
                params.sweep_tx_hashes.clone(),
                params.sweep_amount_piconero,
                params.sweep_fee_piconero,
            )
        };

        let merged_hashes_json = serde_json::to_string(&merged_hashes).map_err(|e| {
            GatewayError::Internal(format!("failed to serialize sweep hashes: {e}"))
        })?;
        let merged_amt_i64 = total_amount.to_i64()?;
        let merged_fee_i64 = total_fee.to_i64()?;

        // Critical financial invariant (XMR-017): sweeping late funds on an EXPIRED invoice MUST
        // preserve EXPIRED status rather than resurrecting the order to SWEPT.
        let next_status = if existing.status == InvoiceStatus::Expired {
            InvoiceStatus::Expired
        } else {
            InvoiceStatus::Swept
        };
        let next_settled_at = if existing.status == InvoiceStatus::Expired {
            existing.settled_at.map(|ts| ts.to_rfc3339())
        } else {
            Some(existing.settled_at.unwrap_or(params.now).to_rfc3339())
        };

        sqlx::query(
            r#"
            UPDATE invoices
            SET
                status = ?,
                unlocked = 1,
                settled_at = ?,
                sweep_tx_hashes = ?,
                sweep_amount_piconero = ?,
                sweep_fee_piconero = ?,
                last_sweep_error = NULL,
                swept_at = COALESCE(swept_at, ?),
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(next_status.as_str())
        .bind(next_settled_at)
        .bind(merged_hashes_json)
        .bind(merged_amt_i64)
        .bind(merged_fee_i64)
        .bind(&now_str)
        .bind(&now_str)
        .bind(&id_str)
        .execute(&mut *tx)
        .await?;

        // Snapshot-scoped ledger update (XMR-023): mark ONLY transfers captured at attempt prepare time.
        if !snapshot_txids.is_empty() {
            for snap_txid in &snapshot_txids {
                sqlx::query(
                    r#"
                    UPDATE subaddress_transfers
                    SET swept = 1, status = 'SWEPT', sweep_attempt_id = ?
                    WHERE invoice_id = ? AND txid = ? AND status = 'ACTIVE'
                    "#,
                )
                .bind(&attempt_id_str)
                .bind(&id_str)
                .bind(snap_txid)
                .execute(&mut *tx)
                .await?;
            }
        } else if let Some(ref created_cutoff) = attempt_created_at {
            sqlx::query(
                r#"
                UPDATE subaddress_transfers
                SET swept = 1, status = 'SWEPT', sweep_attempt_id = ?
                WHERE invoice_id = ? AND status = 'ACTIVE' AND swept = 0 AND created_at <= ?
                "#,
            )
            .bind(&attempt_id_str)
            .bind(&id_str)
            .bind(created_cutoff)
            .execute(&mut *tx)
            .await?;
        }

        if let Some(webhook) = params.webhook {
            insert_webhook_tx(&mut tx, &webhook).await?;
        }

        let updated_row: InvoiceRow = sqlx::query_as(
            r#"
            SELECT
                id, order_id, account_index, address_index, subaddress,
                amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
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

    /// Lists all classified ledger records from `subaddress_transfers` for `invoice_id`.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn list_subaddress_transfers_for_invoice(
        &self,
        invoice_id: Uuid,
    ) -> GatewayResult<Vec<SubaddressTransferRecord>> {
        let rows: Vec<SubaddressTransferRow> = sqlx::query_as(
            r#"
            SELECT
                id, txid, invoice_id, address_index, amount_piconero,
                confirmations, classification, status, swept, sweep_attempt_id, created_at
            FROM subaddress_transfers
            WHERE invoice_id = ?
            ORDER BY created_at ASC, id ASC
            "#,
        )
        .bind(invoice_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(SubaddressTransferRecord::try_from)
            .collect()
    }

    /// Returns `true` if `invoice_id` has any active, unswept `OVERPAYMENT` or `LATE_PAYMENT` inflows
    /// recorded in `subaddress_transfers` (`XMR-017` / `XMR-026`).
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn has_unswept_inflows(&self, invoice_id: Uuid) -> GatewayResult<bool> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM subaddress_transfers
            WHERE invoice_id = ?
              AND classification IN ('OVERPAYMENT', 'LATE_PAYMENT')
              AND status = 'ACTIVE'
              AND swept = 0
            "#,
        )
        .bind(invoice_id.to_string())
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Backwards-compatible alias for [`InvoiceRepository::has_unswept_inflows`].
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure.
    pub async fn has_unswept_overpayment(&self, invoice_id: Uuid) -> GatewayResult<bool> {
        self.has_unswept_inflows(invoice_id).await
    }

    /// Atomically persists a classified `subaddress_transfers` entry (`UNIQUE (invoice_id, txid)`),
    /// refreshes invoice totals/unlock metrics (preserving existing terminal `status`), and enqueues
    /// any anomaly webhook (`XMR-004` / `XMR-022`).
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] on SQL failure or [`GatewayError::Domain`] on overflow.
    pub async fn record_subaddress_transfer(
        &self,
        params: RecordSubaddressTransferParams,
    ) -> GatewayResult<Invoice> {
        let mut tx = self.pool.begin().await?;
        let id_str = params.record.invoice_id.to_string();

        upsert_transfer_tx(&mut tx, &id_str, &params.transfer, params.now).await?;

        let rec_amt_i64 = params.record.amount_piconero.to_i64()?;
        let rec_conf_i64 = u64_to_i64(params.record.confirmations, "record.confirmations")?;
        let rec_status = params.record.status.as_str();
        let attempt_id_str = params.record.sweep_attempt_id.map(|id| id.to_string());
        sqlx::query(
            r#"
            INSERT INTO subaddress_transfers (
                txid, invoice_id, address_index, amount_piconero,
                confirmations, classification, status, swept, sweep_attempt_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (invoice_id, txid) DO UPDATE SET
                confirmations = excluded.confirmations,
                amount_piconero = excluded.amount_piconero,
                status = CASE WHEN subaddress_transfers.swept = 1 THEN 'SWEPT' ELSE excluded.status END
            "#,
        )
        .bind(&params.record.txid)
        .bind(&id_str)
        .bind(i64::from(params.record.address_index))
        .bind(rec_amt_i64)
        .bind(rec_conf_i64)
        .bind(params.record.classification.as_str())
        .bind(rec_status)
        .bind(i64::from(params.record.swept))
        .bind(attempt_id_str)
        .bind(params.record.created_at.to_rfc3339())
        .execute(&mut *tx)
        .await?;

        let has_tainted_transfer: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM invoice_transfers WHERE invoice_id = ? AND double_spend_seen = 1)",
        )
        .bind(&id_str)
        .fetch_one(&mut *tx)
        .await?;

        let inv_rx_i64 = params.received_piconero.to_i64()?;
        let inv_conf_i64 = u64_to_i64(params.confirmations, "confirmations")?;
        sqlx::query(
            r#"
            UPDATE invoices
            SET
                received_piconero = ?,
                confirmations = ?,
                unlocked = ?,
                double_spend_seen = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(inv_rx_i64)
        .bind(inv_conf_i64)
        .bind(i64::from(params.unlocked))
        .bind(i64::from(has_tainted_transfer))
        .bind(params.now.to_rfc3339())
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
                reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
                sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
                created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
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
}

async fn reconcile_orphaned_transfers_tx(
    tx: &mut Transaction<'_, Sqlite>,
    invoice_id: &str,
    active_txids: &[&str],
    now: DateTime<Utc>,
) -> GatewayResult<()> {
    let now_str = now.to_rfc3339();

    if active_txids.is_empty() {
        sqlx::query(
            r#"
            UPDATE invoice_transfers
            SET orphaned = 1, updated_at = ?
            WHERE invoice_id = ?
              AND orphaned = 0
              AND txid NOT IN (
                  SELECT txid FROM subaddress_transfers WHERE invoice_id = ? AND status = 'SWEPT'
              )
            "#,
        )
        .bind(&now_str)
        .bind(invoice_id)
        .bind(invoice_id)
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            r#"
            UPDATE subaddress_transfers
            SET status = 'ORPHANED'
            WHERE invoice_id = ?
              AND status = 'ACTIVE'
              AND swept = 0
            "#,
        )
        .bind(invoice_id)
        .execute(&mut **tx)
        .await?;

        return Ok(());
    }

    let mut inv_qb: sqlx::QueryBuilder<Sqlite> =
        sqlx::QueryBuilder::new("UPDATE invoice_transfers SET orphaned = 1, updated_at = ");
    inv_qb.push_bind(&now_str);
    inv_qb.push(" WHERE invoice_id = ");
    inv_qb.push_bind(invoice_id);
    inv_qb.push(" AND orphaned = 0 AND (double_spend_seen = 1 OR (txid NOT IN (");
    let mut sep = inv_qb.separated(", ");
    for txid in active_txids {
        sep.push_bind(*txid);
    }
    inv_qb.push(") AND txid NOT IN (SELECT txid FROM subaddress_transfers WHERE invoice_id = ");
    inv_qb.push_bind(invoice_id);
    inv_qb.push(" AND status = 'SWEPT')))");
    inv_qb.build().execute(&mut **tx).await?;

    let mut sub_qb: sqlx::QueryBuilder<Sqlite> = sqlx::QueryBuilder::new(
        "UPDATE subaddress_transfers SET status = 'ORPHANED' WHERE invoice_id = ",
    );
    sub_qb.push_bind(invoice_id);
    sub_qb.push(" AND status = 'ACTIVE' AND swept = 0 AND txid NOT IN (");
    let mut sub_sep = sub_qb.separated(", ");
    for txid in active_txids {
        sub_sep.push_bind(*txid);
    }
    sub_qb.push(")");
    sub_qb.build().execute(&mut **tx).await?;

    Ok(())
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
    let initial_orphaned = transfer.orphaned || transfer.double_spend_seen;

    sqlx::query(
        r#"
        INSERT INTO invoice_transfers (
            invoice_id, txid, amount_piconero, confirmations,
            unlocked, double_spend_seen, in_pool, orphaned, observed_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (invoice_id, txid) DO UPDATE SET
            amount_piconero = excluded.amount_piconero,
            confirmations = excluded.confirmations,
            unlocked = excluded.unlocked,
            double_spend_seen = CASE
                WHEN excluded.confirmations > 0 AND excluded.double_spend_seen = 0 THEN 0
                ELSE MAX(invoice_transfers.double_spend_seen, excluded.double_spend_seen)
            END,
            in_pool = excluded.in_pool,
            orphaned = CASE
                WHEN excluded.confirmations > 0
                     AND excluded.double_spend_seen = 0
                     AND excluded.orphaned = 0 THEN 0
                WHEN MAX(invoice_transfers.double_spend_seen, excluded.double_spend_seen) = 1
                     OR excluded.orphaned = 1 THEN 1
                ELSE 0
            END,
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
    .bind(i64::from(initial_orphaned))
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
        let reorg_epoch = u32::try_from(row.reorg_epoch).map_err(|_| {
            GatewayError::Internal(format!("corrupt reorg_epoch {}", row.reorg_epoch))
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
            reorg_epoch,
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
            settled_at: row
                .settled_at
                .as_deref()
                .map(|s| parse_rfc3339(s, "settled_at"))
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
            orphaned: row.orphaned != 0,
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

impl TryFrom<SweepAttemptRow> for SweepAttempt {
    type Error = GatewayError;

    fn try_from(row: SweepAttemptRow) -> Result<Self, Self::Error> {
        let id = Uuid::parse_str(&row.id).map_err(|e| {
            GatewayError::Internal(format!("corrupt sweep_attempt uuid '{}': {e}", row.id))
        })?;
        let invoice_id = Uuid::parse_str(&row.invoice_id).map_err(|e| {
            GatewayError::Internal(format!(
                "corrupt sweep_attempt invoice_id '{}': {e}",
                row.invoice_id
            ))
        })?;
        let address_index = u32::try_from(row.address_index).map_err(|_| {
            GatewayError::Internal(format!(
                "corrupt sweep_attempt address_index {}",
                row.address_index
            ))
        })?;
        let snapshot_txids: Vec<String> =
            serde_json::from_str(&row.snapshot_txids_json).map_err(|e| {
                GatewayError::Internal(format!("corrupt sweep_attempt snapshot_txids_json: {e}"))
            })?;
        let status = SweepAttemptStatus::from_str(&row.status)?;
        let tx_hashes: Vec<String> = serde_json::from_str(&row.tx_hashes_json).map_err(|e| {
            GatewayError::Internal(format!("corrupt sweep_attempt tx_hashes_json: {e}"))
        })?;
        let swept_amount_piconero = row
            .swept_amount_piconero
            .map(Piconero::from_i64)
            .transpose()?;
        let fee_piconero = row.fee_piconero.map(Piconero::from_i64).transpose()?;
        let resolved_at = row
            .resolved_at
            .as_deref()
            .map(|s| parse_rfc3339(s, "resolved_at"))
            .transpose()?;
        let resolution_action = row
            .resolution_action
            .as_deref()
            .map(SweepResolutionAction::from_str)
            .transpose()?;

        Ok(Self {
            id,
            invoice_id,
            address_index,
            destination_address: row.destination_address,
            snapshot_txids,
            status,
            tx_hashes,
            swept_amount_piconero,
            fee_piconero,
            error_message: row.error_message,
            resolved_at,
            resolution_action,
            resolution_note: row.resolution_note,
            created_at: parse_rfc3339(&row.created_at, "created_at")?,
            updated_at: parse_rfc3339(&row.updated_at, "updated_at")?,
        })
    }
}

impl TryFrom<SubaddressTransferRow> for SubaddressTransferRecord {
    type Error = GatewayError;

    fn try_from(row: SubaddressTransferRow) -> Result<Self, Self::Error> {
        let invoice_id = Uuid::parse_str(&row.invoice_id).map_err(|e| {
            GatewayError::Internal(format!(
                "corrupt subaddress_transfer invoice_id '{}': {e}",
                row.invoice_id
            ))
        })?;
        let address_index = u32::try_from(row.address_index).map_err(|_| {
            GatewayError::Internal(format!(
                "corrupt subaddress_transfer address_index {}",
                row.address_index
            ))
        })?;
        let amount_piconero = Piconero::from_i64(row.amount_piconero)?;
        let confirmations = u64::try_from(row.confirmations).map_err(|_| {
            GatewayError::Internal(format!(
                "corrupt subaddress_transfer confirmations {}",
                row.confirmations
            ))
        })?;
        let classification = TransferClassification::from_str(&row.classification)?;
        let status = SubaddressTransferStatus::from_str(&row.status)?;
        let sweep_attempt_id = row
            .sweep_attempt_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|e| {
                GatewayError::Internal(format!("corrupt subaddress_transfer sweep_attempt_id: {e}"))
            })?;

        Ok(Self {
            id: row.id,
            txid: row.txid,
            invoice_id,
            address_index,
            amount_piconero,
            confirmations,
            classification,
            status,
            swept: row.swept != 0,
            sweep_attempt_id,
            created_at: parse_rfc3339(&row.created_at, "created_at")?,
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
