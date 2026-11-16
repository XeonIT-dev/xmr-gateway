//! Background blockchain/mempool scanner and isolated subaddress auto-sweep engine.
//!
//! # Operational & Security Invariants
//! 1. **Single-Query Batching:** Queries `monero-wallet-rpc` `get_transfers` once per scan tick
//!    for all active subaddress indices (`account_index = 0`), aggregating confirmed (`in`)
//!    and unconfirmed (`pool`) transfers per subaddress.
//! 2. **Txid Deduplication:** If a transaction transitions from `pool` to `in` concurrently with
//!    an RPC query and appears in both lists, `in` takes precedence and the txid is counted once.
//! 3. **Double-Spend Immunity:** Any output with `double_spend_seen == true` is excluded from
//!    paid totals and logged at `ERROR` severity.
//! 4. **10-Block Consensus Sweep Lock & Per-Invoice Mutex:** In `ENABLE_AUTO_SWEEP=true` mode,
//!    `sweep_all` is executed ONLY after the invoice is `CONFIRMED` AND all outputs on its
//!    dedicated `subaddress_index` report unlocked (`>= 10` confirmations and `!locked`). A
//!    per-invoice async mutex serializes background auto-sweeps against manual `POST /sweep`
//!    calls so `sweep_all` can never race on the same subaddress.

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

use chrono::Utc;
use tokio::sync::{Mutex, watch};
use uuid::Uuid;

use crate::{
    config::Config,
    db::repository::{ApplyScanUpdateParams, InvoiceRepository, MarkSweptParams},
    domain::{
        amount::Piconero,
        invoice::{
            Invoice, InvoiceStatus, MONERO_UNLOCK_CONFIRMATIONS, ObservedTransfer,
            SubaddressEvaluation, WebhookEventType, compute_next_status,
            evaluate_subaddress_transfers,
        },
    },
    error::{GatewayError, GatewayResult},
    rpc::{client::MoneroRpcClient, types::GetTransfersResponse},
    services::webhook::build_webhook_delivery,
};

/// Summary counters returned by a single scanner pass (primarily for diagnostics and tests).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Total active invoices inspected in this cycle.
    pub invoices_scanned: usize,
    /// Number of invoices whose status transitioned during this cycle.
    pub status_transitions: usize,
    /// Number of invoices successfully swept to cold storage during this cycle.
    pub invoices_swept: usize,
    /// Number of transient per-invoice sweep failures encountered.
    pub sweep_errors: usize,
}

/// Autonomous background scanner and cold-storage sweeper.
#[derive(Debug, Clone)]
pub struct ScannerService {
    repo: InvoiceRepository,
    rpc: MoneroRpcClient,
    config: Arc<Config>,
    sweep_locks: Arc<Mutex<HashMap<Uuid, Arc<Mutex<()>>>>>,
}

impl ScannerService {
    /// Creates a new [`ScannerService`].
    #[must_use]
    pub fn new(repo: InvoiceRepository, rpc: MoneroRpcClient, config: Arc<Config>) -> Self {
        Self {
            repo,
            rpc,
            config,
            sweep_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Runs the scanner polling loop until shutdown is signaled.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let interval = Duration::from_secs(self.config.scan_interval_seconds);
        tracing::info!(
            interval_secs = interval.as_secs(),
            auto_sweep = self.config.enable_auto_sweep,
            required_confirmations = self.config.required_confirmations,
            "blockchain scanner worker started"
        );

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(err) = self.scan_once().await {
                        tracing::error!(error = %err, "scanner cycle failed");
                    }
                }
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        tracing::info!("blockchain scanner worker received shutdown signal");
                        break;
                    }
                }
            }
        }
    }

    /// Executes one deterministic scan-and-sweep cycle across all active invoices.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] if active invoices cannot be fetched or updated, or
    /// [`GatewayError::RpcTransport`]/[`GatewayError::Rpc`] if batch `get_transfers` fails.
    pub async fn scan_once(&self) -> GatewayResult<ScanReport> {
        let active_invoices = self.repo.list_active_invoices().await?;
        let mut report = ScanReport {
            invoices_scanned: active_invoices.len(),
            ..ScanReport::default()
        };

        if active_invoices.is_empty() {
            return Ok(report);
        }

        let unique_indices: Vec<u32> = active_invoices
            .iter()
            .map(|inv| inv.address_index)
            .collect::<BTreeSet<u32>>()
            .into_iter()
            .collect();

        let transfers_resp = self.rpc.get_transfers(0, &unique_indices, true).await?;
        let grouped = group_transfers_by_subaddress(0, &transfers_resp);

        for invoice in active_invoices {
            let subaddr_transfers = grouped
                .get(&invoice.address_index)
                .map(Vec::as_slice)
                .unwrap_or(&[]);

            let eval = evaluate_subaddress_transfers(invoice.amount_piconero, subaddr_transfers);
            if eval.double_spend_seen && !invoice.double_spend_seen {
                tracing::error!(
                    invoice_id = %invoice.id,
                    order_id = %invoice.order_id,
                    subaddress = %invoice.subaddress,
                    "CRITICAL SECURITY ALERT: double_spend_seen detected on incoming transaction; tainted output excluded"
                );
            }

            let updated = self.persist_evaluation(&invoice, &eval).await?;
            if updated.status != invoice.status {
                report.status_transitions += 1;
            }

            if self.config.enable_auto_sweep
                && updated.status == InvoiceStatus::Confirmed
                && eval.all_unlocked
                && updated.received_piconero >= updated.amount_piconero
            {
                match self.execute_sweep_locked(updated.id).await {
                    Ok(_) => {
                        report.invoices_swept += 1;
                    }
                    Err(err) => {
                        report.sweep_errors += 1;
                        tracing::error!(
                            invoice_id = %updated.id,
                            order_id = %updated.order_id,
                            address_index = updated.address_index,
                            error = %err,
                            "auto-sweep attempt failed; will retry on next scan tick"
                        );
                    }
                }
            }
        }

        Ok(report)
    }

    /// Manually triggers a sweep attempt for `invoice_id` via `POST /api/v1/invoices/{id}/sweep`.
    ///
    /// Performs a live transfer refresh from `monero-wallet-rpc` before checking Monero's
    /// 10-block unlock rule and executing `sweep_all` under the per-invoice sweep lock.
    ///
    /// # Errors
    /// - [`GatewayError::Conflict`] if auto-sweep is disabled, invoice is in a terminal state,
    ///   invoice is underpaid/unpaid, or outputs have not yet unlocked (`< 10` blocks).
    /// - [`GatewayError::NotFound`] if `invoice_id` does not exist.
    /// - [`GatewayError::Rpc`] / [`GatewayError::RpcTransport`] if RPC fails.
    pub async fn manual_sweep(&self, invoice_id: Uuid) -> GatewayResult<Invoice> {
        if !self.config.enable_auto_sweep || self.config.cold_wallet_address.is_none() {
            return Err(GatewayError::Conflict(
                "auto-sweep is disabled in View-Only mode (ENABLE_AUTO_SWEEP=false)".to_string(),
            ));
        }

        let invoice = self
            .repo
            .get_invoice_by_id(invoice_id)
            .await?
            .ok_or_else(|| GatewayError::NotFound(format!("invoice {invoice_id} not found")))?;

        match invoice.status {
            InvoiceStatus::Swept => {
                return Err(GatewayError::Conflict(format!(
                    "invoice {invoice_id} has already been swept"
                )));
            }
            InvoiceStatus::Completed | InvoiceStatus::Expired => {
                return Err(GatewayError::Conflict(format!(
                    "invoice {invoice_id} is in terminal status {}",
                    invoice.status
                )));
            }
            _ => {}
        }

        let transfers_resp = self
            .rpc
            .get_transfers(invoice.account_index, &[invoice.address_index], true)
            .await?;
        let grouped = group_transfers_by_subaddress(invoice.account_index, &transfers_resp);
        let subaddr_transfers = grouped
            .get(&invoice.address_index)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let eval = evaluate_subaddress_transfers(invoice.amount_piconero, subaddr_transfers);
        let updated = self.persist_evaluation(&invoice, &eval).await?;

        if updated.received_piconero < updated.amount_piconero {
            return Err(GatewayError::Conflict(format!(
                "invoice {invoice_id} has not received full payment ({} / {} piconero)",
                updated.received_piconero.as_u64(),
                updated.amount_piconero.as_u64()
            )));
        }

        if updated.status != InvoiceStatus::Confirmed {
            return Err(GatewayError::Conflict(format!(
                "invoice {invoice_id} is in status {} and must reach CONFIRMED ({} confirmations) before sweeping",
                updated.status, self.config.required_confirmations
            )));
        }

        if !eval.all_unlocked {
            return Err(GatewayError::Conflict(format!(
                "subaddress funds are still locked ({}/{} confirmations required by Monero consensus)",
                eval.effective_confirmations, MONERO_UNLOCK_CONFIRMATIONS
            )));
        }

        self.execute_sweep_locked(invoice_id).await
    }

    async fn persist_evaluation(
        &self,
        invoice: &Invoice,
        eval: &SubaddressEvaluation,
    ) -> GatewayResult<Invoice> {
        let now = Utc::now();
        let mut next_status = compute_next_status(
            invoice.status,
            invoice.amount_piconero,
            eval,
            self.config.required_confirmations,
            now,
            invoice.expires_at,
        );

        // In View-Only mode with no webhook destination, CONFIRMED immediately completes.
        if next_status == InvoiceStatus::Confirmed
            && !self.config.enable_auto_sweep
            && invoice.callback_url.is_none()
        {
            next_status = InvoiceStatus::Completed;
        }

        let status_changed = next_status != invoice.status;
        let metrics_changed = eval.received_piconero != invoice.received_piconero
            || eval.effective_confirmations != invoice.confirmations
            || eval.all_unlocked != invoice.unlocked
            || eval.double_spend_seen != invoice.double_spend_seen;

        if !status_changed && !metrics_changed && eval.transfers.is_empty() {
            return Ok(invoice.clone());
        }

        let webhook_event = if status_changed {
            match next_status {
                InvoiceStatus::Underpaid => Some(WebhookEventType::Underpaid),
                InvoiceStatus::Mempool => Some(WebhookEventType::Mempool),
                InvoiceStatus::Confirmed | InvoiceStatus::Completed => {
                    Some(WebhookEventType::Confirmed)
                }
                InvoiceStatus::Expired => Some(WebhookEventType::Expired),
                InvoiceStatus::Pending | InvoiceStatus::Swept => None,
            }
        } else if next_status == InvoiceStatus::Underpaid
            && eval.received_piconero > invoice.received_piconero
        {
            // Additional partial payment arrived while still underpaid.
            Some(WebhookEventType::Underpaid)
        } else {
            None
        };

        let mut projected = invoice.clone();
        projected.status = next_status;
        projected.received_piconero = eval.received_piconero;
        projected.confirmations = eval.effective_confirmations;
        projected.unlocked = eval.all_unlocked;
        projected.double_spend_seen = invoice.double_spend_seen || eval.double_spend_seen;

        let webhook = match (webhook_event, invoice.callback_url.as_deref()) {
            (Some(event), Some(url)) => Some(build_webhook_delivery(
                &self.config.webhook_secret,
                &projected,
                event,
                url,
                now,
            )?),
            _ => None,
        };

        if status_changed {
            tracing::info!(
                invoice_id = %invoice.id,
                order_id = %invoice.order_id,
                from = invoice.status.as_str(),
                to = next_status.as_str(),
                received_piconero = eval.received_piconero.as_u64(),
                confirmations = eval.effective_confirmations,
                "invoice state transitioned"
            );
        }

        self.repo
            .apply_scan_update(ApplyScanUpdateParams {
                invoice_id: invoice.id,
                received_piconero: eval.received_piconero,
                confirmations: eval.effective_confirmations,
                unlocked: eval.all_unlocked,
                double_spend_seen: eval.double_spend_seen,
                next_status,
                transfers: eval.transfers.clone(),
                webhook,
                now,
            })
            .await
    }

    async fn execute_sweep_locked(&self, invoice_id: Uuid) -> GatewayResult<Invoice> {
        let lock = self.acquire_invoice_lock(invoice_id).await;
        let _guard = lock.lock().await;

        let current = self
            .repo
            .get_invoice_by_id(invoice_id)
            .await?
            .ok_or_else(|| GatewayError::NotFound(format!("invoice {invoice_id} not found")))?;

        if current.status == InvoiceStatus::Swept {
            return Ok(current);
        }
        if current.status != InvoiceStatus::Confirmed {
            return Err(GatewayError::Conflict(format!(
                "invoice {invoice_id} status is {}, expected CONFIRMED",
                current.status
            )));
        }

        let cold_addr = self.config.cold_wallet_address.as_deref().ok_or_else(|| {
            GatewayError::Config(
                "COLD_WALLET_ADDRESS is not configured for sweep execution".to_string(),
            )
        })?;

        let sweep_res = match self
            .rpc
            .sweep_subaddress(
                current.account_index,
                current.address_index,
                cold_addr,
                self.config.sweep_priority,
            )
            .await
        {
            Ok(res) => res,
            Err(err) => {
                let _ = self
                    .repo
                    .record_sweep_error(invoice_id, &err.to_string(), Utc::now())
                    .await;
                return Err(err);
            }
        };

        if sweep_res.tx_hash_list.is_empty() {
            let err = GatewayError::Rpc {
                code: None,
                message: "sweep_all returned empty tx_hash_list".to_string(),
            };
            let _ = self
                .repo
                .record_sweep_error(invoice_id, &err.to_string(), Utc::now())
                .await;
            return Err(err);
        }

        let total_amount = sum_u64_checked(&sweep_res.amount_list, "sweep amount_list")?;
        let total_fee = sum_u64_checked(&sweep_res.fee_list, "sweep fee_list")?;
        let now = Utc::now();

        let mut projected = current.clone();
        projected.status = InvoiceStatus::Swept;
        projected.unlocked = true;
        projected.sweep_tx_hashes = sweep_res.tx_hash_list.clone();
        projected.sweep_amount_piconero = Some(total_amount);
        projected.sweep_fee_piconero = Some(total_fee);
        projected.swept_at = Some(now);

        let webhook = match current.callback_url.as_deref() {
            Some(url) => Some(build_webhook_delivery(
                &self.config.webhook_secret,
                &projected,
                WebhookEventType::Swept,
                url,
                now,
            )?),
            None => None,
        };

        tracing::info!(
            invoice_id = %current.id,
            order_id = %current.order_id,
            address_index = current.address_index,
            sweep_tx_hashes = ?sweep_res.tx_hash_list,
            swept_piconero = total_amount.as_u64(),
            fee_piconero = total_fee.as_u64(),
            "subaddress swept to cold storage"
        );

        self.repo
            .mark_invoice_swept(MarkSweptParams {
                invoice_id: current.id,
                sweep_tx_hashes: sweep_res.tx_hash_list,
                sweep_amount_piconero: total_amount,
                sweep_fee_piconero: total_fee,
                webhook,
                now,
            })
            .await
    }

    async fn acquire_invoice_lock(&self, invoice_id: Uuid) -> Arc<Mutex<()>> {
        let mut map = self.sweep_locks.lock().await;
        map.entry(invoice_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

/// Groups and deduplicates `get_transfers` entries (`pool` + `in`) by subaddress minor index.
///
/// If the same `txid` appears in both `pool` and `in` (block mined mid-query), the confirmed
/// `in` entry overrides the `pool` entry so outputs are never double-counted.
fn group_transfers_by_subaddress(
    account_index: u32,
    resp: &GetTransfersResponse,
) -> HashMap<u32, Vec<ObservedTransfer>> {
    let mut per_subaddr_by_txid: HashMap<u32, HashMap<String, ObservedTransfer>> = HashMap::new();

    for entry in &resp.pool {
        for (minor_idx, amt) in entry.subaddress_amounts(account_index) {
            per_subaddr_by_txid.entry(minor_idx).or_default().insert(
                entry.txid.clone(),
                ObservedTransfer {
                    txid: entry.txid.clone(),
                    amount_piconero: Piconero(amt),
                    confirmations: 0,
                    unlocked: false,
                    double_spend_seen: entry.double_spend_seen,
                    in_pool: true,
                },
            );
        }
    }

    for entry in &resp.in_transfers {
        let is_unlocked = entry.is_unlocked(false);
        for (minor_idx, amt) in entry.subaddress_amounts(account_index) {
            per_subaddr_by_txid.entry(minor_idx).or_default().insert(
                entry.txid.clone(),
                ObservedTransfer {
                    txid: entry.txid.clone(),
                    amount_piconero: Piconero(amt),
                    confirmations: entry.confirmations,
                    unlocked: is_unlocked,
                    double_spend_seen: entry.double_spend_seen,
                    in_pool: false,
                },
            );
        }
    }

    per_subaddr_by_txid
        .into_iter()
        .map(|(minor_idx, tx_map)| (minor_idx, tx_map.into_values().collect()))
        .collect()
}

fn sum_u64_checked(values: &[u64], label: &str) -> GatewayResult<Piconero> {
    let mut acc = 0_u64;
    for &val in values {
        acc = acc
            .checked_add(val)
            .ok_or_else(|| GatewayError::Internal(format!("overflow summing {label}")))?;
    }
    Ok(Piconero(acc))
}

#[cfg(test)]
mod tests {
    use chrono::Duration as ChronoDuration;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method, path},
    };

    use super::*;
    use crate::{config::LogFormat, db::init_sqlite_pool, domain::invoice::build_monero_uri};

    fn test_config(rpc_url: String, enable_auto_sweep: bool) -> Arc<Config> {
        Arc::new(Config {
            host: "127.0.0.1".to_string(),
            port: 8080,
            cors_allowed_origins: vec!["*".to_string()],
            database_url: "sqlite::memory:".to_string(),
            api_secret_key: "a".repeat(32),
            webhook_secret: "b".repeat(32),
            default_webhook_url: None,
            monero_rpc_url: rpc_url,
            monero_rpc_user: None,
            monero_rpc_pass: None,
            cold_wallet_address: if enable_auto_sweep {
                Some(format!("4{}", "A".repeat(94)))
            } else {
                None
            },
            enable_auto_sweep,
            sweep_priority: 0,
            required_confirmations: 2,
            invoice_ttl_seconds: 3600,
            scan_interval_seconds: 10,
            webhook_poll_interval_seconds: 5,
            log_format: LogFormat::Json,
        })
    }

    fn insertable_invoice(address_index: u32, amount: u64, callback: Option<String>) -> Invoice {
        let now = Utc::now();
        let subaddr = format!("8{}", "B".repeat(94));
        Invoice {
            id: Uuid::new_v4(),
            order_id: format!("ord-{address_index}"),
            account_index: 0,
            address_index,
            subaddress: subaddr.clone(),
            amount_piconero: Piconero(amount),
            received_piconero: Piconero::ZERO,
            confirmations: 0,
            unlocked: false,
            double_spend_seen: false,
            status: InvoiceStatus::Pending,
            callback_url: callback,
            monero_uri: build_monero_uri(
                &subaddr,
                Piconero(amount),
                &format!("ord-{address_index}"),
            ),
            qr_code_base64: "ZmFrZQ==".to_string(),
            sweep_tx_hashes: Vec::new(),
            sweep_amount_piconero: None,
            sweep_fee_piconero: None,
            last_sweep_error: None,
            created_at: now,
            updated_at: now,
            expires_at: now + ChronoDuration::hours(1),
            confirmed_at: None,
            swept_at: None,
            completed_at: None,
        }
    }

    #[tokio::test]
    async fn scanner_drives_underpaid_mempool_confirmed_and_swept_lifecycle() {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;

        let inv = insertable_invoice(
            7,
            1_000_000_000_000,
            Some("http://127.0.0.1:9999/cb".to_string()),
        );
        repo.insert_invoice(&inv).await.unwrap();

        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), true);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg);

        // 1) Partial payment in mempool (0.4 XMR) -> UNDERPAID
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": {
                    "in": [],
                    "pool": [{
                        "txid": "1".repeat(64),
                        "amount": 400_000_000_000_u64,
                        "confirmations": 0,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 7 }
                    }]
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        let after_partial = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(after_partial.status, InvoiceStatus::Underpaid);
        assert_eq!(after_partial.received_piconero, Piconero(400_000_000_000));

        // 2) Second payment completes 1.0 XMR in mempool -> MEMPOOL
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "2",
                "result": {
                    "in": [],
                    "pool": [
                        {
                            "txid": "1".repeat(64),
                            "amount": 400_000_000_000_u64,
                            "confirmations": 0,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 7 }
                        },
                        {
                            "txid": "2".repeat(64),
                            "amount": 600_000_000_000_u64,
                            "confirmations": 0,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 7 }
                        }
                    ]
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        let after_mempool = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(after_mempool.status, InvoiceStatus::Mempool);
        assert_eq!(after_mempool.received_piconero, Piconero(1_000_000_000_000));

        // 3) 2 confirmations reached (still locked < 10 blocks) -> CONFIRMED (no sweep yet!)
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "3",
                "result": {
                    "in": [
                        {
                            "txid": "1".repeat(64),
                            "amount": 400_000_000_000_u64,
                            "confirmations": 3,
                            "double_spend_seen": false,
                            "locked": true,
                            "subaddr_index": { "major": 0, "minor": 7 }
                        },
                        {
                            "txid": "2".repeat(64),
                            "amount": 600_000_000_000_u64,
                            "confirmations": 2,
                            "double_spend_seen": false,
                            "locked": true,
                            "subaddr_index": { "major": 0, "minor": 7 }
                        }
                    ],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let report_conf = scanner.scan_once().await.unwrap();
        assert_eq!(report_conf.invoices_swept, 0);
        let after_conf = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(after_conf.status, InvoiceStatus::Confirmed);
        assert_eq!(after_conf.confirmations, 2);
        assert!(!after_conf.unlocked);

        // 4) 10 confirmations & unlocked=true -> executes sweep_all for subaddr_indices:[7] -> SWEPT
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "4",
                "result": {
                    "in": [
                        {
                            "txid": "1".repeat(64),
                            "amount": 400_000_000_000_u64,
                            "confirmations": 11,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 7 }
                        },
                        {
                            "txid": "2".repeat(64),
                            "amount": 600_000_000_000_u64,
                            "confirmations": 10,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 7 }
                        }
                    ],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("sweep_all"))
            .and(body_string_contains(r#""subaddr_indices":[7]"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "5",
                "result": {
                    "tx_hash_list": ["f".repeat(64)],
                    "amount_list": [999_900_000_000_u64],
                    "fee_list": [100_000_000_u64]
                }
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let report_swept = scanner.scan_once().await.unwrap();
        assert_eq!(report_swept.invoices_swept, 1);

        let after_swept = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(after_swept.status, InvoiceStatus::Swept);
        assert_eq!(after_swept.sweep_tx_hashes, vec!["f".repeat(64)]);
        assert_eq!(
            after_swept.sweep_amount_piconero,
            Some(Piconero(999_900_000_000))
        );
        assert_eq!(after_swept.sweep_fee_piconero, Some(Piconero(100_000_000)));

        // Verify all 4 webhooks (UNDERPAID, MEMPOOL, CONFIRMED, SWEPT) were queued once each
        let webhooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        let events: Vec<WebhookEventType> = webhooks.iter().map(|w| w.event_type).collect();
        assert_eq!(
            events,
            vec![
                WebhookEventType::Underpaid,
                WebhookEventType::Mempool,
                WebhookEventType::Confirmed,
                WebhookEventType::Swept,
            ]
        );
    }

    #[test]
    fn groups_and_deduplicates_pool_and_confirmed_multi_subaddress_transfers() {
        let json = serde_json::json!({
            "in": [{
                "txid": "c".repeat(64),
                "amount": 300_000_000_000_u64,
                "amounts": [100_000_000_000_u64, 200_000_000_000_u64],
                "confirmations": 3,
                "double_spend_seen": false,
                "locked": true,
                "subaddr_index": { "major": 0, "minor": 1 },
                "subaddr_indices": [
                    { "major": 0, "minor": 1 },
                    { "major": 0, "minor": 2 }
                ]
            }],
            "pool": [{
                "txid": "c".repeat(64),
                "amount": 300_000_000_000_u64,
                "amounts": [100_000_000_000_u64, 200_000_000_000_u64],
                "confirmations": 0,
                "double_spend_seen": false,
                "subaddr_index": { "major": 0, "minor": 1 },
                "subaddr_indices": [
                    { "major": 0, "minor": 1 },
                    { "major": 0, "minor": 2 }
                ]
            }]
        });

        let parsed: GetTransfersResponse = serde_json::from_value(json).unwrap();
        let grouped = group_transfers_by_subaddress(0, &parsed);
        assert_eq!(grouped.get(&1).unwrap().len(), 1);
        assert_eq!(
            grouped.get(&1).unwrap()[0].amount_piconero,
            Piconero(100_000_000_000)
        );
        assert!(!grouped.get(&1).unwrap()[0].in_pool);
        assert_eq!(grouped.get(&1).unwrap()[0].confirmations, 3);

        assert_eq!(grouped.get(&2).unwrap().len(), 1);
        assert_eq!(
            grouped.get(&2).unwrap()[0].amount_piconero,
            Piconero(200_000_000_000)
        );
        assert!(!grouped.get(&2).unwrap()[0].in_pool);
    }
}
