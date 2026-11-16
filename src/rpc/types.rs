//! Strongly-typed JSON-RPC 2.0 request and response payloads for `monero-wallet-rpc`.

use serde::{Deserialize, Serialize};

use crate::domain::invoice::MONERO_UNLOCK_CONFIRMATIONS;

/// Generic JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcRequest<T> {
    /// JSON-RPC protocol version (`"2.0"`).
    pub jsonrpc: &'static str,
    /// Client correlation identifier.
    pub id: String,
    /// Monero wallet RPC method name.
    pub method: &'static str,
    /// Method parameter object.
    pub params: T,
}

/// Generic JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcResponse<T> {
    /// JSON-RPC protocol version.
    #[serde(default)]
    pub jsonrpc: String,
    /// Echoed correlation identifier.
    #[serde(default)]
    pub id: Option<String>,
    /// Successful method result payload.
    pub result: Option<T>,
    /// Structured JSON-RPC error object if the call failed.
    pub error: Option<JsonRpcError>,
}

/// Structured JSON-RPC 2.0 error detail returned by `monero-wallet-rpc`.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcError {
    /// Numeric Monero/JSON-RPC error code.
    pub code: i64,
    /// Diagnostic error description.
    pub message: String,
}

/// Empty parameter object for parameterless RPC methods like `get_version`.
#[derive(Debug, Clone, Serialize)]
pub struct EmptyParams {}

/// Response from `monero-wallet-rpc` method `get_version`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GetVersionResponse {
    /// Encoded Monero RPC API version integer.
    pub version: u32,
    /// Whether the wallet binary is a release build.
    #[serde(default)]
    pub release: Option<bool>,
}

/// Request parameters for `create_address`.
#[derive(Debug, Clone, Serialize)]
pub struct CreateAddressParams<'a> {
    /// Wallet account index (always `0` in this gateway).
    pub account_index: u32,
    /// Human-readable subaddress label (`inv_<order_id>`).
    pub label: &'a str,
}

/// Response from `monero-wallet-rpc` method `create_address`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CreateAddressResponse {
    /// Base58-encoded newly generated subaddress.
    pub address: String,
    /// Minor subaddress index allocated under `account_index`.
    pub address_index: u32,
}

/// Request parameters for `get_transfers`.
#[derive(Debug, Clone, Serialize)]
pub struct GetTransfersParams<'a> {
    /// Include confirmed incoming transfers (`"in"`).
    #[serde(rename = "in")]
    pub in_transfers: bool,
    /// Include unconfirmed incoming transfers currently in the mempool (`"pool"`).
    pub pool: bool,
    /// Include outgoing transfers (`"out"`).
    pub out: bool,
    /// Include pending outgoing transfers (`"pending"`).
    pub pending: bool,
    /// Include failed outgoing transfers (`"failed"`).
    pub failed: bool,
    /// Wallet account index to filter on.
    pub account_index: u32,
    /// Specific subaddress minor indices to query in batch.
    pub subaddr_indices: &'a [u32],
}

/// Subaddress major/minor coordinate returned in `get_transfers` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct SubaddrIndex {
    /// Account index.
    #[serde(default)]
    pub major: u32,
    /// Subaddress index within the account.
    #[serde(default)]
    pub minor: u32,
}

/// Individual incoming transfer record returned in `get_transfers.in` or `get_transfers.pool`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TransferEntry {
    /// 64-character hex Monero transaction hash.
    pub txid: String,
    /// Total piconero received in this entry.
    pub amount: u64,
    /// Per-subaddress output amounts when a single tx pays multiple subaddresses.
    #[serde(default)]
    pub amounts: Vec<u64>,
    /// Block confirmations (`0` for mempool transactions).
    #[serde(default)]
    pub confirmations: u64,
    /// Flag set by Monero node/wallet if a conflicting double-spend tx was observed.
    #[serde(default)]
    pub double_spend_seen: bool,
    /// Real `monero-wallet-rpc` lock flag (`true` while locked, `false` once unlocked).
    #[serde(default)]
    pub locked: Option<bool>,
    /// Optional explicit `unlocked` flag accepted for interoperability with custom adapters/mocks.
    #[serde(default)]
    pub unlocked: Option<bool>,
    /// Primary subaddress index associated with this transfer entry.
    #[serde(default)]
    pub subaddr_index: SubaddrIndex,
    /// List of subaddress indices paid when a single transaction hits multiple subaddresses.
    #[serde(default)]
    pub subaddr_indices: Vec<SubaddrIndex>,
    /// Explicit consensus unlock height/timestamp embedded in the transaction.
    #[serde(default)]
    pub unlock_time: u64,
    /// Block height (`0` while in mempool).
    #[serde(default)]
    pub height: u64,
    /// Unix timestamp in seconds.
    #[serde(default)]
    pub timestamp: u64,
    /// Destination subaddress string.
    #[serde(default)]
    pub address: String,
}

impl TransferEntry {
    /// Determines whether this incoming output has cleared Monero's 10-block consensus lock.
    ///
    /// # Security Invariants
    /// - Mempool (`in_pool == true`) transfers are **never** unlocked.
    /// - Explicitly locked outputs (`locked == Some(true)` or `unlocked == Some(false)`) are
    ///   never unlocked even if `confirmations >= 10` (protects against custom `unlock_time`).
    /// - Confirmations MUST satisfy `confirmations >= MONERO_UNLOCK_CONFIRMATIONS` (`10`) even
    ///   if a response reports `locked == Some(false)` or `unlocked == Some(true)`.
    #[must_use]
    pub fn is_unlocked(&self, in_pool: bool) -> bool {
        if in_pool {
            return false;
        }
        if self.locked == Some(true) || self.unlocked == Some(false) {
            return false;
        }
        self.confirmations >= MONERO_UNLOCK_CONFIRMATIONS
    }

    /// Resolves `(subaddress_index, amount_piconero)` pairs belonging to `account_index`.
    ///
    /// Handles both single-output transfers (`subaddr_index` + `amount`) and batched multi-output
    /// payouts (`subaddr_indices` + `amounts`) in a single Monero transaction.
    #[must_use]
    pub fn subaddress_amounts(&self, account_index: u32) -> Vec<(u32, u64)> {
        if !self.amounts.is_empty() && self.amounts.len() == self.subaddr_indices.len() {
            self.subaddr_indices
                .iter()
                .zip(self.amounts.iter())
                .filter(|(idx, _)| idx.major == account_index)
                .map(|(idx, &amt)| (idx.minor, amt))
                .collect()
        } else if self.subaddr_index.major == account_index {
            vec![(self.subaddr_index.minor, self.amount)]
        } else {
            Vec::new()
        }
    }
}

/// Response from `monero-wallet-rpc` method `get_transfers`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct GetTransfersResponse {
    /// Confirmed incoming transactions.
    #[serde(rename = "in", default)]
    pub in_transfers: Vec<TransferEntry>,
    /// Unconfirmed incoming transactions currently in the mempool.
    #[serde(default)]
    pub pool: Vec<TransferEntry>,
}

/// Request parameters for `sweep_all`.
#[derive(Debug, Clone, Serialize)]
pub struct SweepAllParams<'a> {
    /// Cold storage Monero destination address.
    pub address: &'a str,
    /// Wallet account index (`0`).
    pub account_index: u32,
    /// Specific subaddress indices to sweep (`[subaddress_index]`).
    pub subaddr_indices: &'a [u32],
    /// Monero fee priority (`0..=4`).
    pub priority: u32,
    /// Consensus unlock time (`0` for standard 10-block rule).
    pub unlock_time: u64,
    /// Request transaction secret keys (`false` keeps response minimal).
    pub get_tx_keys: bool,
}

/// Response from `monero-wallet-rpc` method `sweep_all`.
///
/// Monero may split a sweep into multiple transactions if the subaddress accumulated more
/// outputs than fit within a single transaction's maximum weight/input limits.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct SweepAllResponse {
    /// Transaction hashes created by the sweep operation.
    #[serde(default)]
    pub tx_hash_list: Vec<String>,
    /// Net piconero sent per transaction (after fee deduction).
    #[serde(default)]
    pub amount_list: Vec<u64>,
    /// Network fee paid per transaction in piconero.
    #[serde(default)]
    pub fee_list: Vec<u64>,
    /// Optional transaction secret keys per sweep transaction.
    #[serde(default)]
    pub tx_key_list: Vec<String>,
}
