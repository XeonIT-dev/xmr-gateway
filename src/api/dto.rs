//! REST API JSON request and response Data Transfer Objects (DTOs).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::repository::{SweepAttempt, SweepAttemptStatus, SweepResolutionAction},
    domain::{
        amount::Piconero,
        invoice::{Invoice, InvoiceStatus, ObservedTransfer},
    },
};

/// Monero RPC connectivity details returned inside [`HealthResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcHealthStatus {
    /// Whether `monero-wallet-rpc` responded successfully to `get_version`.
    pub connected: bool,
    /// Numeric RPC version returned by `monero-wallet-rpc` when reachable.
    pub version: Option<u32>,
    /// Diagnostic error summary if `monero-wallet-rpc` could not be reached.
    pub error: Option<String>,
}

/// Public / authenticated healthcheck response returned by `GET /health` (`XMR-033`).
///
/// Unauthenticated callers receive only `status` (`"ok" | "degraded" | "unhealthy"`).
/// Detailed telemetry fields (`service`, `version`, `database`, `monero_rpc`, `auto_sweep_enabled`)
/// are populated exclusively when the caller authenticates with a valid `X-API-Key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall gateway status (`"ok"` when DB and RPC are healthy, `"degraded"` if RPC is down).
    pub status: String,
    /// Service name (authenticated diagnostics only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub service: Option<String>,
    /// Crate version from `Cargo.toml` (authenticated diagnostics only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version: Option<String>,
    /// SQLite database status (`"connected"` or `"disconnected"`; authenticated diagnostics only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub database: Option<String>,
    /// Live `monero-wallet-rpc` reachability snapshot (authenticated diagnostics only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub monero_rpc: Option<RpcHealthStatus>,
    /// Whether Hot Auto-Sweep mode (`ENABLE_AUTO_SWEEP=true`) is active (authenticated diagnostics only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub auto_sweep_enabled: Option<bool>,
}

/// Request payload for `POST /api/v1/invoices`.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateInvoiceRequest {
    /// Unique merchant order reference (e.g., Telegram order ID).
    pub order_id: String,
    /// Expected payment amount strictly in atomic piconero (`1 XMR = 10^12 piconero`).
    pub amount_piconero: u64,
    /// Optional per-invoice webhook override; falls back to `DEFAULT_WEBHOOK_URL` if omitted.
    pub callback_url: Option<String>,
    /// Optional expiration window in seconds; falls back to `INVOICE_TTL_SECONDS` if omitted.
    pub ttl_seconds: Option<u64>,
}

/// Response payload returned by `POST /api/v1/invoices` (`201 Created`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInvoiceResponse {
    /// Gateway invoice UUID.
    pub invoice_id: Uuid,
    /// Merchant's unique order reference.
    pub order_id: String,
    /// Initial lifecycle status (`PENDING`).
    pub status: InvoiceStatus,
    /// Dedicated Monero subaddress assigned exclusively to this invoice.
    pub subaddress: String,
    /// Monero wallet account index (`0`).
    pub account_index: u32,
    /// Subaddress minor index within account `0`.
    pub address_index: u32,
    /// Expected payment total in piconero.
    pub amount_piconero: u64,
    /// Exact 12-decimal XMR representation (`"1.000000000000"`).
    pub amount_xmr_formatted: String,
    /// Canonical `monero:<subaddress>?tx_amount=...&tx_description=...` payment URI.
    pub monero_uri: String,
    /// Base64-encoded high-contrast PNG QR code image of `monero_uri`.
    pub qr_code_base64: String,
    /// Invoice creation timestamp (UTC).
    pub created_at: DateTime<Utc>,
    /// Invoice expiration timestamp (UTC).
    pub expires_at: DateTime<Utc>,
}

impl From<&Invoice> for CreateInvoiceResponse {
    fn from(inv: &Invoice) -> Self {
        Self {
            invoice_id: inv.id,
            order_id: inv.order_id.clone(),
            status: inv.status,
            subaddress: inv.subaddress.clone(),
            account_index: inv.account_index,
            address_index: inv.address_index,
            amount_piconero: inv.amount_piconero.as_u64(),
            amount_xmr_formatted: inv.amount_piconero.to_xmr_string(),
            monero_uri: inv.monero_uri.clone(),
            qr_code_base64: inv.qr_code_base64.clone(),
            created_at: inv.created_at,
            expires_at: inv.expires_at,
        }
    }
}

/// Per-transaction incoming transfer audit item inside [`InvoiceStatusResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceTransferDto {
    /// Monero transaction hash.
    pub txid: String,
    /// Received amount in piconero.
    pub amount_piconero: u64,
    /// Exact 12-decimal XMR amount string.
    pub amount_xmr_formatted: String,
    /// Blockchain confirmation depth.
    pub confirmations: u64,
    /// Whether this output has cleared Monero's 10-block unlock lock.
    pub unlocked: bool,
    /// Whether a double-spend attempt was detected for this transaction.
    pub double_spend_seen: bool,
    /// `true` if currently unconfirmed in the mempool.
    pub in_pool: bool,
    /// `true` if this transfer vanished during a chain reorganization or was tainted (`XMR-026`).
    #[serde(default)]
    pub orphaned: bool,
}

impl From<&ObservedTransfer> for InvoiceTransferDto {
    fn from(tr: &ObservedTransfer) -> Self {
        Self {
            txid: tr.txid.clone(),
            amount_piconero: tr.amount_piconero.as_u64(),
            amount_xmr_formatted: tr.amount_piconero.to_xmr_string(),
            confirmations: tr.confirmations,
            unlocked: tr.unlocked,
            double_spend_seen: tr.double_spend_seen,
            in_pool: tr.in_pool,
            orphaned: tr.orphaned,
        }
    }
}

/// Detailed invoice view returned by `GET /api/v1/invoices/{invoice_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceStatusResponse {
    /// Gateway invoice UUID.
    pub invoice_id: Uuid,
    /// Merchant's unique order reference.
    pub order_id: String,
    /// Current invoice lifecycle state.
    pub status: InvoiceStatus,
    /// Dedicated Monero subaddress.
    pub subaddress: String,
    /// Wallet account index (`0`).
    pub account_index: u32,
    /// Subaddress index within account `0`.
    pub address_index: u32,
    /// Expected invoice total in piconero.
    pub amount_piconero: u64,
    /// Exact 12-decimal expected XMR string.
    pub amount_xmr_formatted: String,
    /// Valid non-double-spent piconero received so far.
    pub received_piconero: u64,
    /// Exact 12-decimal received XMR string.
    pub received_xmr_formatted: String,
    /// Effective confirmation depth covering the invoice obligation.
    pub confirmations: u64,
    /// Whether all incoming outputs on this subaddress are unlocked (`>= 10` blocks).
    pub unlocked: bool,
    /// Whether a double-spend attempt was observed on this subaddress.
    pub double_spend_seen: bool,
    /// Canonical Monero payment URI.
    pub monero_uri: String,
    /// Base64-encoded PNG QR code image.
    pub qr_code_base64: String,
    /// Transaction hashes produced by `sweep_all` once swept.
    pub sweep_tx_hashes: Vec<String>,
    /// Net piconero swept to cold storage (if swept).
    pub sweep_amount_piconero: Option<u64>,
    /// Network fee paid across sweep transactions in piconero (if swept).
    pub sweep_fee_piconero: Option<u64>,
    /// Last transient error message from a sweep attempt (if any).
    pub last_sweep_error: Option<String>,
    /// Individual incoming Monero transfers observed on this subaddress.
    pub transfers: Vec<InvoiceTransferDto>,
    /// Durable outbound sweep execution attempts recorded for this invoice (`XMR-003` / `XMR-041`).
    #[serde(default)]
    pub sweep_attempts: Vec<SweepAttemptDto>,
    /// Creation timestamp (UTC).
    pub created_at: DateTime<Utc>,
    /// Last update timestamp (UTC).
    pub updated_at: DateTime<Utc>,
    /// Expiration deadline (UTC).
    pub expires_at: DateTime<Utc>,
    /// Timestamp when `CONFIRMED` was reached.
    pub confirmed_at: Option<DateTime<Utc>>,
    /// Timestamp when `SETTLED` (10-block Monero lock finality) was reached.
    pub settled_at: Option<DateTime<Utc>>,
    /// Timestamp when `SWEPT` completed.
    pub swept_at: Option<DateTime<Utc>>,
    /// Timestamp when `COMPLETED` (View-Only terminal state) completed.
    pub completed_at: Option<DateTime<Utc>>,
}

/// Durable sweep attempt audit record returned in [`InvoiceStatusResponse`] and
/// [`ResolveSweepIncidentResponse`] (`XMR-041`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepAttemptDto {
    /// Sweep attempt UUID.
    pub id: Uuid,
    /// Parent invoice UUID.
    pub invoice_id: Uuid,
    /// Wallet subaddress minor index swept.
    pub address_index: u32,
    /// Destination cold-wallet address.
    pub destination_address: String,
    /// Lifecycle status (`PREPARED`, `SUBMITTED`, `CONFIRMED`, `RECONCILED`, `FAILED`, `REORGED`).
    pub status: SweepAttemptStatus,
    /// Outgoing sweep transaction hashes associated with this attempt.
    pub tx_hashes: Vec<String>,
    /// Net piconero swept across this attempt (if broadcast).
    pub swept_amount_piconero: Option<u64>,
    /// Network fee paid in piconero (if broadcast).
    pub fee_piconero: Option<u64>,
    /// Incident or failure diagnostic message (e.g. `SWEEP_REORG_DETECTED: ...`).
    pub error_message: Option<String>,
    /// Operator incident resolution timestamp (UTC), if resolved (`XMR-041`).
    pub resolved_at: Option<DateTime<Utc>>,
    /// Operator resolution action (`ALLOW_RESWEEP` | `MARK_RECONCILED`), if resolved.
    pub resolution_action: Option<SweepResolutionAction>,
    /// Mandatory operator justification/audit note recorded on resolution.
    pub resolution_note: Option<String>,
    /// Creation timestamp (UTC).
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp (UTC).
    pub updated_at: DateTime<Utc>,
}

impl From<&SweepAttempt> for SweepAttemptDto {
    fn from(attempt: &SweepAttempt) -> Self {
        Self {
            id: attempt.id,
            invoice_id: attempt.invoice_id,
            address_index: attempt.address_index,
            destination_address: attempt.destination_address.clone(),
            status: attempt.status,
            tx_hashes: attempt.tx_hashes.clone(),
            swept_amount_piconero: attempt.swept_amount_piconero.map(Piconero::as_u64),
            fee_piconero: attempt.fee_piconero.map(Piconero::as_u64),
            error_message: attempt.error_message.clone(),
            resolved_at: attempt.resolved_at,
            resolution_action: attempt.resolution_action,
            resolution_note: attempt.resolution_note.clone(),
            created_at: attempt.created_at,
            updated_at: attempt.updated_at,
        }
    }
}

impl InvoiceStatusResponse {
    /// Builds an [`InvoiceStatusResponse`] from a persisted [`Invoice`] and its observed transfers.
    #[must_use]
    pub fn from_invoice(inv: &Invoice, transfers: &[ObservedTransfer]) -> Self {
        Self::from_invoice_with_attempts(inv, transfers, &[])
    }

    /// Builds an [`InvoiceStatusResponse`] from a persisted [`Invoice`], its observed transfers,
    /// and its recorded [`SweepAttempt`] ledger entries.
    #[must_use]
    pub fn from_invoice_with_attempts(
        inv: &Invoice,
        transfers: &[ObservedTransfer],
        sweep_attempts: &[SweepAttempt],
    ) -> Self {
        Self {
            invoice_id: inv.id,
            order_id: inv.order_id.clone(),
            status: inv.status,
            subaddress: inv.subaddress.clone(),
            account_index: inv.account_index,
            address_index: inv.address_index,
            amount_piconero: inv.amount_piconero.as_u64(),
            amount_xmr_formatted: inv.amount_piconero.to_xmr_string(),
            received_piconero: inv.received_piconero.as_u64(),
            received_xmr_formatted: inv.received_piconero.to_xmr_string(),
            confirmations: inv.confirmations,
            unlocked: inv.unlocked,
            double_spend_seen: inv.double_spend_seen,
            monero_uri: inv.monero_uri.clone(),
            qr_code_base64: inv.qr_code_base64.clone(),
            sweep_tx_hashes: inv.sweep_tx_hashes.clone(),
            sweep_amount_piconero: inv.sweep_amount_piconero.map(Piconero::as_u64),
            sweep_fee_piconero: inv.sweep_fee_piconero.map(Piconero::as_u64),
            last_sweep_error: inv.last_sweep_error.clone(),
            transfers: transfers.iter().map(InvoiceTransferDto::from).collect(),
            sweep_attempts: sweep_attempts.iter().map(SweepAttemptDto::from).collect(),
            created_at: inv.created_at,
            updated_at: inv.updated_at,
            expires_at: inv.expires_at,
            confirmed_at: inv.confirmed_at,
            settled_at: inv.settled_at,
            swept_at: inv.swept_at,
            completed_at: inv.completed_at,
        }
    }
}

/// Request payload for `POST /api/v1/invoices/{invoice_id}/sweep/resolve` (`XMR-041`).
#[derive(Debug, Clone, Deserialize)]
pub struct ResolveSweepIncidentRequest {
    /// Optional target `sweep_attempts.id` UUID; defaults to the latest `REORGED` attempt.
    pub attempt_id: Option<String>,
    /// Resolution action: `"allow_resweep"` or `"mark_reconciled"`.
    pub action: SweepResolutionAction,
    /// Optional replacement sweep transaction hash when `action == "mark_reconciled"`.
    pub replacement_tx_hash: Option<String>,
    /// Mandatory non-empty operator audit note explaining the manual reconciliation verification.
    pub operator_note: String,
}

/// Response payload returned by `POST /api/v1/invoices/{invoice_id}/sweep/resolve` (`XMR-041`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveSweepIncidentResponse {
    /// Gateway invoice UUID.
    pub invoice_id: Uuid,
    /// Updated invoice status after incident resolution.
    pub status: InvoiceStatus,
    /// Updated `sweep_attempts` record containing audit timestamps and resolution metadata.
    pub resolved_attempt: SweepAttemptDto,
}

/// Response payload returned by `POST /api/v1/invoices/{invoice_id}/sweep`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepInvoiceResponse {
    /// Gateway invoice UUID.
    pub invoice_id: Uuid,
    /// Merchant order reference.
    pub order_id: String,
    /// Updated status (`SWEPT`, or `EXPIRED` when sweeping late inflows on an expired invoice).
    pub status: InvoiceStatus,
    /// Transaction hashes created by `sweep_all`.
    pub sweep_tx_hashes: Vec<String>,
    /// Net swept piconero sent to `COLD_WALLET_ADDRESS`.
    pub sweep_amount_piconero: u64,
    /// Exact 12-decimal XMR swept string.
    pub sweep_amount_xmr_formatted: String,
    /// Network fee paid in piconero.
    pub sweep_fee_piconero: u64,
    /// Exact 12-decimal XMR fee string.
    pub sweep_fee_xmr_formatted: String,
    /// Timestamp when the sweep finished (UTC).
    pub swept_at: DateTime<Utc>,
}

/// Response payload returned by manual webhook recovery endpoints (`XMR-028`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryWebhookResponse {
    /// Number of webhook outbox deliveries reset to `PENDING` for immediate retry.
    pub retried_count: usize,
    /// UUIDs of the queued webhook deliveries.
    pub webhook_ids: Vec<Uuid>,
    /// UTC timestamp when the deliveries became due.
    pub scheduled_at: DateTime<Utc>,
}
