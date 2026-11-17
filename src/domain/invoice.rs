//! Invoice aggregate, state machine rules, Monero URI builder, and transfer evaluation.
//!
//! # Cryptographic & Consensus Invariants
//! - **Subaddress Isolation:** Every invoice owns a dedicated Monero subaddress (`account_index = 0`,
//!   unique `address_index`), preventing cross-customer address reuse and off-chain correlation.
//! - **10-Block Consensus Unlock Rule:** In Monero, incoming transaction outputs remain locked
//!   for 10 blocks (`MONERO_UNLOCK_CONFIRMATIONS = 10`) or longer if a sender specifies a custom
//!   `unlock_time`. Sweeps to cold storage MUST ONLY run after all outputs on the invoice's
//!   subaddress are confirmed (`>= 10` confirmations) and unlocked (`locked == false`).
//! - **Double-Spend Rejection:** Any transfer marked `double_spend_seen == true` is excluded
//!   from received balance totals and raises a critical taint flag on the invoice.

use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{domain::amount::Piconero, error::DomainError};

/// Monero consensus coinbase/output lock window (10 blocks) before funds can be spent or swept.
pub const MONERO_UNLOCK_CONFIRMATIONS: u64 = 10;

/// Maximum accepted `order_id` length.
pub const MAX_ORDER_ID_LEN: usize = 128;

/// Deterministic lifecycle state of a non-custodial Monero invoice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvoiceStatus {
    /// Subaddress created; awaiting incoming transaction.
    Pending,
    /// Partial payment observed (`0 < received < expected`); monitoring continues until paid or expired.
    Underpaid,
    /// Full amount (`received >= expected`) detected in mempool (`0-conf`) without double-spend.
    Mempool,
    /// Full amount mined (`1 <= confirmations < REQUIRED_CONFIRMATIONS`), accumulating confirmations.
    Confirming,
    /// Full amount reached `REQUIRED_CONFIRMATIONS`; fulfillment webhook dispatched.
    Confirmed,
    /// Full amount reached `SETTLEMENT_CONFIRMATIONS` (default 10 blocks); reorg-resistant finality.
    Settled,
    /// Previously `MEMPOOL`/`CONFIRMING`/`CONFIRMED`/`SETTLED` payment dropped depth, disappeared, or saw a double-spend.
    Reorged,
    /// Terminal state in View-Only mode (`ENABLE_AUTO_SWEEP=false`) after `CONFIRMED`/`SETTLED` webhook delivery.
    Completed,
    /// Terminal state in Hot Auto-Sweep mode after unlocked funds (`>= 10` blocks) were swept to cold storage.
    Swept,
    /// Terminal state when no full payment arrived before `expires_at`.
    Expired,
}

impl InvoiceStatus {
    /// Returns the canonical uppercase database/wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Underpaid => "UNDERPAID",
            Self::Mempool => "MEMPOOL",
            Self::Confirming => "CONFIRMING",
            Self::Confirmed => "CONFIRMED",
            Self::Settled => "SETTLED",
            Self::Reorged => "REORGED",
            Self::Completed => "COMPLETED",
            Self::Swept => "SWEPT",
            Self::Expired => "EXPIRED",
        }
    }

    /// Returns `true` if no further automated primary lifecycle transitions occur.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Swept | Self::Expired)
    }

    /// Returns `true` if the background scanner should continue active status evaluation.
    #[must_use]
    pub const fn is_active(self) -> bool {
        !self.is_terminal()
    }

    /// Validates whether transitioning from `self` to `next` obeys the reorg-safe state machine graph.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidStateTransition`] if `self -> next` is forbidden.
    pub fn validate_transition(self, next: Self) -> Result<(), DomainError> {
        if self == next {
            return Ok(());
        }

        let allowed = match self {
            Self::Pending => matches!(
                next,
                Self::Underpaid
                    | Self::Mempool
                    | Self::Confirming
                    | Self::Confirmed
                    | Self::Settled
                    | Self::Completed
                    | Self::Expired
            ),
            Self::Underpaid => matches!(
                next,
                Self::Mempool
                    | Self::Confirming
                    | Self::Confirmed
                    | Self::Settled
                    | Self::Completed
                    | Self::Expired
                    | Self::Reorged
            ),
            Self::Mempool => matches!(
                next,
                Self::Confirming
                    | Self::Confirmed
                    | Self::Settled
                    | Self::Completed
                    | Self::Reorged
            ),
            Self::Confirming => matches!(
                next,
                Self::Confirmed | Self::Settled | Self::Completed | Self::Reorged
            ),
            Self::Confirmed => matches!(
                next,
                Self::Settled | Self::Completed | Self::Swept | Self::Reorged
            ),
            Self::Settled => matches!(next, Self::Completed | Self::Swept | Self::Reorged),
            Self::Reorged => matches!(
                next,
                Self::Confirming | Self::Confirmed | Self::Settled | Self::Expired
            ),
            Self::Completed | Self::Swept | Self::Expired => false,
        };

        if allowed {
            Ok(())
        } else {
            Err(DomainError::InvalidStateTransition {
                from: self.as_str().to_string(),
                to: next.as_str().to_string(),
                reason: "transition violates invoice lifecycle invariants".to_string(),
            })
        }
    }
}

impl fmt::Display for InvoiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for InvoiceStatus {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PENDING" => Ok(Self::Pending),
            "UNDERPAID" => Ok(Self::Underpaid),
            "MEMPOOL" => Ok(Self::Mempool),
            "CONFIRMING" => Ok(Self::Confirming),
            "CONFIRMED" => Ok(Self::Confirmed),
            "SETTLED" => Ok(Self::Settled),
            "REORGED" => Ok(Self::Reorged),
            "COMPLETED" => Ok(Self::Completed),
            "SWEPT" => Ok(Self::Swept),
            "EXPIRED" => Ok(Self::Expired),
            other => Err(DomainError::Validation(format!(
                "unknown invoice status '{other}'"
            ))),
        }
    }
}

/// Outbound webhook notification event emitted on invoice state transitions or subaddress anomalies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WebhookEventType {
    /// Partial payment observed (`0 < received < expected`).
    Underpaid,
    /// Full amount detected in mempool (`0-conf`).
    Mempool,
    /// Full amount reached `REQUIRED_CONFIRMATIONS`.
    Confirmed,
    /// Full amount reached `SETTLEMENT_CONFIRMATIONS` (default 10 blocks).
    Settled,
    /// Chain reorganization or post-payment double-spend compromised a confirming/confirmed invoice.
    Reorged,
    /// Unlocked balance swept to `COLD_WALLET_ADDRESS`.
    Swept,
    /// Invoice expired before full payment arrived.
    Expired,
    /// Confirmed payment arrived on an already `EXPIRED` invoice subaddress.
    LatePayment,
    /// Additional confirmed payment arrived exceeding `expected_amount` after settlement/sweep.
    Overpayment,
}

impl WebhookEventType {
    /// Returns the canonical uppercase event identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Underpaid => "UNDERPAID",
            Self::Mempool => "MEMPOOL",
            Self::Confirmed => "CONFIRMED",
            Self::Settled => "SETTLED",
            Self::Reorged => "REORGED",
            Self::Swept => "SWEPT",
            Self::Expired => "EXPIRED",
            Self::LatePayment => "LATE_PAYMENT",
            Self::Overpayment => "OVERPAYMENT",
        }
    }
}

impl fmt::Display for WebhookEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WebhookEventType {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UNDERPAID" => Ok(Self::Underpaid),
            "MEMPOOL" => Ok(Self::Mempool),
            "CONFIRMED" => Ok(Self::Confirmed),
            "SETTLED" => Ok(Self::Settled),
            "REORGED" => Ok(Self::Reorged),
            "SWEPT" => Ok(Self::Swept),
            "EXPIRED" => Ok(Self::Expired),
            "LATE_PAYMENT" => Ok(Self::LatePayment),
            "OVERPAYMENT" => Ok(Self::Overpayment),
            other => Err(DomainError::Validation(format!(
                "unknown webhook event type '{other}'"
            ))),
        }
    }
}

/// Persisted invoice record representing a single non-custodial Monero checkout session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invoice {
    /// Globally unique gateway identifier (UUID v4).
    pub id: Uuid,
    /// Merchant's unique order reference.
    pub order_id: String,
    /// Monero wallet account index (always `0` in this gateway).
    pub account_index: u32,
    /// Unique Monero subaddress minor index within `account_index`.
    pub address_index: u32,
    /// Base58-encoded Monero subaddress assigned exclusively to this invoice.
    pub subaddress: String,
    /// Expected invoice total in atomic piconero.
    pub amount_piconero: Piconero,
    /// Total valid (non-double-spent) incoming piconero observed on `subaddress`.
    pub received_piconero: Piconero,
    /// Effective confirmation depth covering the invoice obligation.
    pub confirmations: u64,
    /// `true` iff all non-tainted incoming outputs on the subaddress are unlocked (`>= 10` blocks).
    pub unlocked: bool,
    /// `true` if `monero-wallet-rpc` ever flagged a double-spend attempt targeting this subaddress.
    pub double_spend_seen: bool,
    /// Monotonically incremented counter bumped each time the invoice enters `REORGED` (`XMR-025`).
    pub reorg_epoch: u32,
    /// Current invoice lifecycle state.
    pub status: InvoiceStatus,
    /// Webhook target URL resolved at creation time (`request.callback_url` or `DEFAULT_WEBHOOK_URL`).
    pub callback_url: Option<String>,
    /// Canonical `monero:<subaddress>?tx_amount=...&tx_description=...` payment URI.
    pub monero_uri: String,
    /// Base64-encoded high-contrast PNG QR code rendering `monero_uri`.
    pub qr_code_base64: String,
    /// Transaction hashes produced by `sweep_all` once swept.
    pub sweep_tx_hashes: Vec<String>,
    /// Total piconero swept to cold storage (sum of `amount_list` from `sweep_all`).
    pub sweep_amount_piconero: Option<Piconero>,
    /// Total network fee paid across sweep transactions (sum of `fee_list`).
    pub sweep_fee_piconero: Option<Piconero>,
    /// Last transient error observed during a sweep attempt (if any).
    pub last_sweep_error: Option<String>,
    /// UTC timestamp when the invoice was created.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp of the last state or transfer update.
    pub updated_at: DateTime<Utc>,
    /// UTC deadline after which unpaid/underpaid invoices transition to `EXPIRED`.
    pub expires_at: DateTime<Utc>,
    /// UTC timestamp when `CONFIRMED` was reached.
    pub confirmed_at: Option<DateTime<Utc>>,
    /// UTC timestamp when `SETTLED` (10-block Monero lock finality) was reached.
    pub settled_at: Option<DateTime<Utc>>,
    /// UTC timestamp when `SWEPT` completed.
    pub swept_at: Option<DateTime<Utc>>,
    /// UTC timestamp when `COMPLETED` (View-Only mode terminal state) completed.
    pub completed_at: Option<DateTime<Utc>>,
}

impl Invoice {
    /// Returns the original invoice time-to-live window in whole seconds (`expires_at - created_at`).
    #[must_use]
    pub fn ttl_seconds(&self) -> i64 {
        (self.expires_at - self.created_at).num_seconds()
    }
}

/// Lifecycle status of a classified ledger row in `subaddress_transfers` (`XMR-022` / `XMR-026`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubaddressTransferStatus {
    /// Transfer is present on the canonical chain and not yet swept to cold storage.
    Active,
    /// Transfer disappeared during a chain reorganization or was flagged as a double-spend.
    Orphaned,
    /// Transfer outputs were included in a completed cold-storage sweep.
    Swept,
}

impl SubaddressTransferStatus {
    /// Returns canonical uppercase database/wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Orphaned => "ORPHANED",
            Self::Swept => "SWEPT",
        }
    }
}

impl fmt::Display for SubaddressTransferStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SubaddressTransferStatus {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ACTIVE" => Ok(Self::Active),
            "ORPHANED" => Ok(Self::Orphaned),
            "SWEPT" => Ok(Self::Swept),
            other => Err(DomainError::Validation(format!(
                "unknown subaddress transfer status '{other}'"
            ))),
        }
    }
}

/// Classification of a confirmed incoming transfer persisted in `subaddress_transfers` (`XMR-004`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferClassification {
    /// Expected invoice fulfillment payment received before expiration within invoice amount.
    Expected,
    /// Confirmed payment arriving after the invoice transitioned to `EXPIRED`.
    LatePayment,
    /// Confirmed payment exceeding `expected_amount` after fulfillment/settlement/sweep.
    Overpayment,
}

impl TransferClassification {
    /// Returns canonical uppercase database/wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Expected => "EXPECTED",
            Self::LatePayment => "LATE_PAYMENT",
            Self::Overpayment => "OVERPAYMENT",
        }
    }
}

impl fmt::Display for TransferClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TransferClassification {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "EXPECTED" => Ok(Self::Expected),
            "LATE_PAYMENT" => Ok(Self::LatePayment),
            "OVERPAYMENT" => Ok(Self::Overpayment),
            other => Err(DomainError::Validation(format!(
                "unknown transfer classification '{other}'"
            ))),
        }
    }
}

/// Ledger entry recording a classified confirmed incoming transfer on a monitored subaddress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubaddressTransferRecord {
    /// Surrogate SQLite primary key (`0` prior to database persistence).
    pub id: i64,
    /// Monero transaction hash (unique per `invoice_id`).
    pub txid: String,
    /// Associated invoice UUID.
    pub invoice_id: Uuid,
    /// Monero subaddress minor index under account `0`.
    pub address_index: u32,
    /// Atomic piconero amount attributed to this ledger entry.
    pub amount_piconero: Piconero,
    /// Block confirmations observed when recorded.
    pub confirmations: u64,
    /// Accounting classification (`EXPECTED`, `LATE_PAYMENT`, `OVERPAYMENT`).
    pub classification: TransferClassification,
    /// Lifecycle status (`ACTIVE`, `ORPHANED`, `SWEPT`).
    pub status: SubaddressTransferStatus,
    /// Whether the funds represented by this transfer have been swept to cold storage.
    pub swept: bool,
    /// Optional sweep attempt UUID that swept this transfer (`XMR-023`).
    pub sweep_attempt_id: Option<Uuid>,
    /// UTC creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Snapshot of an individual incoming transfer observed on an invoice's subaddress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedTransfer {
    /// Monero transaction hash (64-char hex).
    pub txid: String,
    /// Amount received on this invoice's subaddress in piconero.
    pub amount_piconero: Piconero,
    /// Current blockchain confirmation depth (`0` for mempool transfers).
    pub confirmations: u64,
    /// Whether this output has cleared Monero's 10-block lock and any custom `unlock_time`.
    pub unlocked: bool,
    /// Whether `monero-wallet-rpc` observed a double-spend attempt for this txid.
    pub double_spend_seen: bool,
    /// `true` if currently unconfirmed in the mempool (`pool` list); `false` if mined (`in` list).
    pub in_pool: bool,
    /// `true` if this transfer vanished from RPC history or was orphaned during a chain reorg (`XMR-026`).
    #[serde(default)]
    pub orphaned: bool,
}

/// Aggregated evaluation of all transfers observed on a single subaddress during a scan cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubaddressEvaluation {
    /// Sum of valid (`!double_spend_seen`) incoming outputs in piconero.
    pub received_piconero: Piconero,
    /// Effective confirmation depth of the paid amount (`0` if unconfirmed or unpaid).
    pub effective_confirmations: u64,
    /// `true` iff at least one valid transfer exists, none are in mempool, and all are unlocked.
    pub all_unlocked: bool,
    /// `true` if any transfer on this subaddress was flagged `double_spend_seen`.
    pub double_spend_seen: bool,
    /// Deduplicated per-txid transfer list recorded for auditability.
    pub transfers: Vec<ObservedTransfer>,
}

/// Pure function evaluating incoming RPC transfers against an expected invoice amount.
///
/// # Mathematical & Security Semantics
/// 1. **Double-spend isolation:** Any transfer with `double_spend_seen == true` is excluded from
///    `received_piconero` and `effective_confirmations`, while flipping `double_spend_seen = true`.
/// 2. **Split-payment confirmation depth:** Transfers are sorted by `confirmations` descending
///    and accumulated until `expected_amount` is covered; the minimum confirmation count of that
///    covering set is `effective_confirmations`. This prevents a late unconfirmed dust tip from
///    un-confirming an already confirmed payment, while preventing an old partial output from
///    inflating the confirmation depth of a fresh second partial output.
/// 3. **Unlock safety:** `all_unlocked` is `true` only when at least one valid mined transfer
///    exists, zero valid transfers remain in mempool (`!in_pool`), and every valid transfer
///    satisfies `unlocked && confirmations >= MONERO_UNLOCK_CONFIRMATIONS`.
#[must_use]
pub fn evaluate_subaddress_transfers(
    expected_amount: Piconero,
    transfers: &[ObservedTransfer],
) -> SubaddressEvaluation {
    let mut double_spend_seen = false;
    let mut valid_transfers: Vec<&ObservedTransfer> = Vec::with_capacity(transfers.len());
    let mut total_received = Piconero::ZERO;

    for transfer in transfers {
        if transfer.double_spend_seen || transfer.orphaned {
            if transfer.double_spend_seen {
                double_spend_seen = true;
            }
            continue;
        }
        total_received = total_received.saturating_add(transfer.amount_piconero);
        valid_transfers.push(transfer);
    }

    if valid_transfers.is_empty() {
        return SubaddressEvaluation {
            received_piconero: Piconero::ZERO,
            effective_confirmations: 0,
            all_unlocked: false,
            double_spend_seen,
            transfers: transfers.to_vec(),
        };
    }

    // Sort descending by confirmations to measure the confirmation depth covering `expected_amount`.
    valid_transfers.sort_by_key(|t| std::cmp::Reverse(t.confirmations));

    let effective_confirmations = if total_received >= expected_amount {
        let mut covered = Piconero::ZERO;
        let mut min_conf = u64::MAX;
        for tx in &valid_transfers {
            covered = covered.saturating_add(tx.amount_piconero);
            min_conf = min_conf.min(tx.confirmations);
            if covered >= expected_amount {
                break;
            }
        }
        if min_conf == u64::MAX { 0 } else { min_conf }
    } else {
        // Partial payment: report the lowest confirmation depth across observed valid transfers.
        valid_transfers
            .iter()
            .map(|tx| tx.confirmations)
            .min()
            .unwrap_or(0)
    };

    let all_unlocked = valid_transfers
        .iter()
        .all(|tx| !tx.in_pool && tx.unlocked && tx.confirmations >= MONERO_UNLOCK_CONFIRMATIONS);

    SubaddressEvaluation {
        received_piconero: total_received,
        effective_confirmations,
        all_unlocked,
        double_spend_seen,
        transfers: transfers.to_vec(),
    }
}

/// Computes the next [`InvoiceStatus`] using `MONERO_UNLOCK_CONFIRMATIONS` (`10`) as the
/// default settlement finality threshold.
#[must_use]
pub fn compute_next_status(
    current: InvoiceStatus,
    expected_amount: Piconero,
    eval: &SubaddressEvaluation,
    required_confirmations: u64,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> InvoiceStatus {
    compute_next_status_with_settlement(
        current,
        expected_amount,
        eval,
        required_confirmations,
        MONERO_UNLOCK_CONFIRMATIONS.max(required_confirmations),
        now,
        expires_at,
    )
}

/// Computes the next [`InvoiceStatus`] with explicit confirmation and settlement thresholds and
/// full chain-reorganization detection.
///
/// # State Machine Guarantees
/// - Terminal states (`COMPLETED`, `SWEPT`, `EXPIRED`) never transition.
/// - `CONFIRMED` continues tracking confirmations until `settlement_confirmations` (reaching
///   `SETTLED`), and drops into `REORGED` if confirmations fall below `required_confirmations`,
///   observed balance drops below `expected_amount`, or `double_spend_seen` is flagged.
/// - `CONFIRMING` tracks mined invoices (`1 <= conf < required_confirmations`) and transitions
///   to `REORGED` if orphaned back to `0` confirmations or double-spent.
/// - `MEMPOOL` never expires (`EXPIRED`) while waiting for block inclusion, but moves to
///   `REORGED` if previously full payment vanishes or gets double-spent.
/// - Always passes through `CONFIRMED` when first reaching `required_confirmations` so merchants
///   consistently receive the `CONFIRMED` webhook before `SETTLED`.
#[must_use]
pub fn compute_next_status_with_settlement(
    current: InvoiceStatus,
    expected_amount: Piconero,
    eval: &SubaddressEvaluation,
    required_confirmations: u64,
    settlement_confirmations: u64,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> InvoiceStatus {
    if current.is_terminal() {
        return current;
    }

    match current {
        InvoiceStatus::Settled => {
            if eval.double_spend_seen
                || eval.received_piconero < expected_amount
                || eval.effective_confirmations < settlement_confirmations
            {
                return InvoiceStatus::Reorged;
            }
            InvoiceStatus::Settled
        }
        InvoiceStatus::Confirmed => {
            if eval.double_spend_seen
                || eval.received_piconero < expected_amount
                || eval.effective_confirmations < required_confirmations
            {
                return InvoiceStatus::Reorged;
            }
            if eval.effective_confirmations >= settlement_confirmations {
                return InvoiceStatus::Settled;
            }
            InvoiceStatus::Confirmed
        }
        InvoiceStatus::Confirming => {
            if eval.double_spend_seen
                || eval.received_piconero < expected_amount
                || eval.effective_confirmations == 0
            {
                return InvoiceStatus::Reorged;
            }
            if eval.effective_confirmations >= required_confirmations {
                return InvoiceStatus::Confirmed;
            }
            InvoiceStatus::Confirming
        }
        InvoiceStatus::Reorged => {
            if !eval.double_spend_seen
                && eval.received_piconero >= expected_amount
                && eval.effective_confirmations >= required_confirmations
            {
                return InvoiceStatus::Confirmed;
            }
            InvoiceStatus::Reorged
        }
        InvoiceStatus::Mempool => {
            if eval.double_spend_seen || eval.received_piconero < expected_amount {
                return InvoiceStatus::Reorged;
            }
            if eval.effective_confirmations >= required_confirmations {
                return InvoiceStatus::Confirmed;
            }
            if eval.effective_confirmations >= 1 {
                return InvoiceStatus::Confirming;
            }
            InvoiceStatus::Mempool
        }
        InvoiceStatus::Pending | InvoiceStatus::Underpaid => {
            if eval.received_piconero >= expected_amount {
                if eval.effective_confirmations >= required_confirmations {
                    return InvoiceStatus::Confirmed;
                }
                if eval.effective_confirmations >= 1 {
                    return InvoiceStatus::Confirming;
                }
                return InvoiceStatus::Mempool;
            }

            if now >= expires_at {
                return InvoiceStatus::Expired;
            }

            if !eval.received_piconero.is_zero() {
                return InvoiceStatus::Underpaid;
            }

            current
        }
        InvoiceStatus::Completed | InvoiceStatus::Swept | InvoiceStatus::Expired => current,
    }
}

/// Validates a merchant-supplied `order_id`.
///
/// # Errors
/// Returns [`DomainError::Validation`] if `order_id` is empty, exceeds [`MAX_ORDER_ID_LEN`],
/// or contains unsafe characters outside `[A-Za-z0-9._:-]`.
pub fn validate_order_id(order_id: &str) -> Result<(), DomainError> {
    if order_id.is_empty() {
        return Err(DomainError::Validation(
            "order_id must not be empty".to_string(),
        ));
    }
    if order_id.len() > MAX_ORDER_ID_LEN {
        return Err(DomainError::Validation(format!(
            "order_id exceeds maximum length of {MAX_ORDER_ID_LEN} characters"
        )));
    }
    if !order_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(DomainError::Validation(
            "order_id may only contain ASCII alphanumerics and '-', '_', '.', ':'".to_string(),
        ));
    }
    Ok(())
}

/// Builds a canonical Monero URI (`monero:<subaddress>?tx_amount=<xmr>&tx_description=<order_id>`).
///
/// Percent-encodes `order_id` per RFC 3986 unreserved characters so special characters such as
/// `:` cannot corrupt query parsing in mobile wallets.
#[must_use]
pub fn build_monero_uri(subaddress: &str, amount: Piconero, order_id: &str) -> String {
    let encoded_desc = percent_encode_unreserved(order_id);
    format!(
        "monero:{subaddress}?tx_amount={}&tx_description={encoded_desc}",
        amount.to_xmr_string()
    )
}

/// Percent-encodes any byte outside RFC 3986 unreserved (`A-Z a-z 0-9 - _ . ~`).
fn percent_encode_unreserved(input: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn mk_tx(
        txid: &str,
        amount: u64,
        confirmations: u64,
        unlocked: bool,
        in_pool: bool,
    ) -> ObservedTransfer {
        ObservedTransfer {
            txid: txid.to_string(),
            amount_piconero: Piconero(amount),
            confirmations,
            unlocked,
            double_spend_seen: false,
            in_pool,
            orphaned: false,
        }
    }

    #[test]
    fn split_payment_confirmation_depth_and_late_tip() {
        let expected = Piconero(1_000_000_000_000); // 1.0 XMR

        // Two partial payments: 0.6 XMR (5 conf) + 0.4 XMR (0 conf in pool) -> MEMPOOL (0 conf)
        let eval_partial_mempool = evaluate_subaddress_transfers(
            expected,
            &[
                mk_tx("tx1", 600_000_000_000, 5, false, false),
                mk_tx("tx2", 400_000_000_000, 0, false, true),
            ],
        );
        assert_eq!(eval_partial_mempool.received_piconero, expected);
        assert_eq!(eval_partial_mempool.effective_confirmations, 0);
        assert!(!eval_partial_mempool.all_unlocked);

        let now = Utc::now();
        let next = compute_next_status(
            InvoiceStatus::Underpaid,
            expected,
            &eval_partial_mempool,
            2,
            now,
            now + Duration::hours(1),
        );
        assert_eq!(next, InvoiceStatus::Mempool);

        // Once tx2 reaches 2 confirmations, effective confirmations = 2 -> CONFIRMED
        let eval_both_confirmed = evaluate_subaddress_transfers(
            expected,
            &[
                mk_tx("tx1", 600_000_000_000, 7, false, false),
                mk_tx("tx2", 400_000_000_000, 2, false, false),
            ],
        );
        assert_eq!(eval_both_confirmed.effective_confirmations, 2);
        let next = compute_next_status(
            InvoiceStatus::Mempool,
            expected,
            &eval_both_confirmed,
            2,
            now,
            now + Duration::hours(1),
        );
        assert_eq!(next, InvoiceStatus::Confirmed);

        // Full payment already at 5 confs + extra 0-conf tip: effective confirmations stays 5!
        let eval_with_tip = evaluate_subaddress_transfers(
            expected,
            &[
                mk_tx("tx1", 1_000_000_000_000, 5, false, false),
                mk_tx("tx_tip", 100_000_000_000, 0, false, true),
            ],
        );
        assert_eq!(eval_with_tip.effective_confirmations, 5);
        // But all_unlocked must remain false while tx_tip is still in pool!
        assert!(!eval_with_tip.all_unlocked);
    }

    #[test]
    fn double_spend_output_is_excluded_from_balance() {
        let expected = Piconero(1_000_000_000_000);
        let mut tainted = mk_tx("bad_tx", 1_000_000_000_000, 0, false, true);
        tainted.double_spend_seen = true;

        let eval = evaluate_subaddress_transfers(expected, &[tainted]);
        assert_eq!(eval.received_piconero, Piconero::ZERO);
        assert!(eval.double_spend_seen);

        let now = Utc::now();
        let next = compute_next_status(
            InvoiceStatus::Pending,
            expected,
            &eval,
            2,
            now,
            now + Duration::hours(1),
        );
        assert_eq!(next, InvoiceStatus::Pending);
    }

    #[test]
    fn unlock_requires_ten_confirmations_and_unlocked_flag() {
        let expected = Piconero(500_000_000_000);
        // Even if unlocked=true with 9 confirmations, consensus guard requires >= 10
        let premature = evaluate_subaddress_transfers(
            expected,
            &[mk_tx("tx1", 500_000_000_000, 9, true, false)],
        );
        assert!(!premature.all_unlocked);

        // Locked=true (unlocked=false) at 15 confirmations (custom unlock_time) -> still locked
        let custom_locked = evaluate_subaddress_transfers(
            expected,
            &[mk_tx("tx1", 500_000_000_000, 15, false, false)],
        );
        assert!(!custom_locked.all_unlocked);

        // Exactly 10 confirmations and unlocked=true -> ready to sweep
        let mature = evaluate_subaddress_transfers(
            expected,
            &[mk_tx("tx1", 500_000_000_000, 10, true, false)],
        );
        assert!(mature.all_unlocked);
    }

    #[test]
    fn mempool_invoice_does_not_expire_past_ttl() {
        let expected = Piconero(1_000_000_000_000);
        let eval = evaluate_subaddress_transfers(
            expected,
            &[mk_tx("tx1", 1_000_000_000_000, 0, false, true)],
        );
        let now = Utc::now();
        let past_expiry = now - Duration::seconds(60);

        let next =
            compute_next_status(InvoiceStatus::Mempool, expected, &eval, 2, now, past_expiry);
        assert_eq!(next, InvoiceStatus::Mempool);

        // Pending past expiry without payment -> Expired
        let empty_eval = evaluate_subaddress_transfers(expected, &[]);
        let next_pending = compute_next_status(
            InvoiceStatus::Pending,
            expected,
            &empty_eval,
            2,
            now,
            past_expiry,
        );
        assert_eq!(next_pending, InvoiceStatus::Expired);
    }

    #[test]
    fn builds_monero_uri_with_exact_formatting() {
        let uri = build_monero_uri(
            "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H",
            Piconero(1_000_000_000_000),
            "ord:42",
        );
        assert_eq!(
            uri,
            "monero:888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H?tx_amount=1.000000000000&tx_description=ord%3A42"
        );
    }

    #[test]
    fn reorg_and_settlement_state_transitions() {
        let expected = Piconero(1_000_000_000_000);
        let now = Utc::now();
        let expires = now + Duration::hours(1);

        // 0-conf -> MEMPOOL -> CONFIRMING (1 conf with req=2) -> CONFIRMED (2 conf) -> SETTLED (10 conf)
        let eval0 =
            evaluate_subaddress_transfers(expected, &[mk_tx("tx1", expected.0, 0, false, true)]);
        let s1 = compute_next_status_with_settlement(
            InvoiceStatus::Pending,
            expected,
            &eval0,
            2,
            10,
            now,
            expires,
        );
        assert_eq!(s1, InvoiceStatus::Mempool);

        let eval1 =
            evaluate_subaddress_transfers(expected, &[mk_tx("tx1", expected.0, 1, false, false)]);
        let s2 = compute_next_status_with_settlement(s1, expected, &eval1, 2, 10, now, expires);
        assert_eq!(s2, InvoiceStatus::Confirming);

        let eval2 =
            evaluate_subaddress_transfers(expected, &[mk_tx("tx1", expected.0, 2, false, false)]);
        let s3 = compute_next_status_with_settlement(s2, expected, &eval2, 2, 10, now, expires);
        assert_eq!(s3, InvoiceStatus::Confirmed);

        // Reorg drops confirmation depth below required_confirmations (2 -> 1) => REORGED!
        let s_reorg_depth =
            compute_next_status_with_settlement(s3, expected, &eval1, 2, 10, now, expires);
        assert_eq!(s_reorg_depth, InvoiceStatus::Reorged);

        // Double spend seen while CONFIRMED => REORGED!
        let mut ds_tx = mk_tx("tx1", expected.0, 3, false, false);
        ds_tx.double_spend_seen = true;
        let eval_ds = evaluate_subaddress_transfers(expected, &[ds_tx]);
        let s_reorg_ds =
            compute_next_status_with_settlement(s3, expected, &eval_ds, 2, 10, now, expires);
        assert_eq!(s_reorg_ds, InvoiceStatus::Reorged);

        // Normal progression CONFIRMED (2) -> SETTLED (10)
        let eval10 =
            evaluate_subaddress_transfers(expected, &[mk_tx("tx1", expected.0, 10, true, false)]);
        let s_settled =
            compute_next_status_with_settlement(s3, expected, &eval10, 2, 10, now, expires);
        assert_eq!(s_settled, InvoiceStatus::Settled);
    }
}
