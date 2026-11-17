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
    cmp::Reverse,
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use tokio::sync::{Mutex, watch};
use uuid::Uuid;

use crate::{
    config::Config,
    db::repository::{
        ApplyScanUpdateParams, CompleteSweepAttemptParams, InvoiceRepository,
        RecordSubaddressTransferParams, SweepAttempt, SweepAttemptStatus, SweepResolutionAction,
    },
    domain::{
        amount::Piconero,
        invoice::{
            Invoice, InvoiceStatus, MONERO_UNLOCK_CONFIRMATIONS, ObservedTransfer,
            SubaddressEvaluation, SubaddressTransferRecord, SubaddressTransferStatus,
            TransferClassification, WebhookEventType, compute_next_status_with_settlement,
            evaluate_subaddress_transfers,
        },
    },
    error::{GatewayError, GatewayResult},
    rpc::{client::MoneroRpcClient, types::GetTransfersResponse},
    services::webhook::{
        build_sweep_webhook_delivery, build_transfer_anomaly_webhook_delivery,
        build_webhook_delivery,
    },
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

    fn monitor_cutoff(&self) -> Option<DateTime<Utc>> {
        if self.config.subaddress_monitor_days == 0 {
            None
        } else {
            let monitor_days = i64::try_from(self.config.subaddress_monitor_days).unwrap_or(90);
            Some(Utc::now() - ChronoDuration::days(monitor_days))
        }
    }

    /// Executes one deterministic scan-and-sweep cycle across all monitored invoices.
    ///
    /// Reconciles any active (`PREPARED` / `SUBMITTED`) and finalized (`CONFIRMED` / `RECONCILED`)
    /// sweep attempts within `SUBADDRESS_MONITOR_DAYS` against outgoing RPC transfer history,
    /// scans active, `COMPLETED` (for deep reorg detection), and terminal subaddresses (detecting
    /// late payments and overpayments), and triggers isolated sweeps for unlocked funds unless
    /// an unresolved `SWEEP_REORG_DETECTED` incident exists.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] if monitored invoices cannot be fetched or updated, or
    /// [`GatewayError::RpcTransport`]/[`GatewayError::Rpc`] if batch `get_transfers` fails.
    pub async fn scan_once(&self) -> GatewayResult<ScanReport> {
        let reconciled = self.reconcile_in_flight_sweeps().await?;
        let cutoff = self.monitor_cutoff();
        let monitored_invoices = self.repo.list_monitored_invoices(cutoff).await?;
        let mut report = ScanReport {
            invoices_scanned: monitored_invoices.len(),
            invoices_swept: reconciled,
            ..ScanReport::default()
        };

        if monitored_invoices.is_empty() {
            return Ok(report);
        }

        let unique_indices: Vec<u32> = monitored_invoices
            .iter()
            .map(|inv| inv.address_index)
            .collect::<BTreeSet<u32>>()
            .into_iter()
            .collect();

        let transfers_resp = self.rpc.get_transfers(0, &unique_indices, true).await?;
        let grouped = group_transfers_by_subaddress(0, &transfers_resp);

        for invoice in monitored_invoices {
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

            let has_reorged_sweep = if matches!(
                invoice.status,
                InvoiceStatus::Settled
                    | InvoiceStatus::Reorged
                    | InvoiceStatus::Swept
                    | InvoiceStatus::Expired
            ) {
                self.repo.has_reorged_sweep_attempt(invoice.id).await?
            } else {
                false
            };

            let updated = if matches!(
                invoice.status,
                InvoiceStatus::Swept | InvoiceStatus::Expired
            ) || (invoice.status == InvoiceStatus::Reorged && has_reorged_sweep)
            {
                invoice.clone()
            } else {
                let res = self.persist_evaluation(&invoice, &eval).await?;
                if res.status != invoice.status {
                    report.status_transitions += 1;
                }
                res
            };

            let updated = self
                .reconcile_subaddress_transfer_ledger(&updated, &eval)
                .await?;

            let min_sweep_confs = self
                .config
                .settlement_confirmations
                .max(MONERO_UNLOCK_CONFIRMATIONS);

            let should_auto_sweep = if has_reorged_sweep {
                tracing::warn!(
                    invoice_id = %updated.id,
                    order_id = %updated.order_id,
                    "blocking automatic re-sweep due to unresolved SWEEP_REORG_DETECTED incident; manual reconciliation required"
                );
                false
            } else if !self.config.enable_auto_sweep || !eval.all_unlocked {
                false
            } else if updated.status == InvoiceStatus::Settled
                && updated.received_piconero >= updated.amount_piconero
                && updated.confirmations >= min_sweep_confs
            {
                true
            } else if matches!(
                updated.status,
                InvoiceStatus::Swept | InvoiceStatus::Expired
            ) {
                self.has_settled_unswept_inflows(updated.id, &eval, min_sweep_confs)
                    .await?
            } else {
                false
            };

            if should_auto_sweep {
                let allow_terminal_inflows = matches!(
                    updated.status,
                    InvoiceStatus::Swept | InvoiceStatus::Expired
                );
                match self
                    .execute_sweep_internal(updated.id, allow_terminal_inflows)
                    .await
                {
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
    /// Also permits sweeping residual unswept `OVERPAYMENT` funds on an already `SWEPT` invoice,
    /// as well as unswept `LATE_PAYMENT` funds on an `EXPIRED` invoice while preserving `EXPIRED`
    /// status (`XMR-017`).
    ///
    /// # Errors
    /// - [`GatewayError::Conflict`] if auto-sweep is disabled, invoice is `COMPLETED`, already
    ///   swept/expired with no unswept anomaly inflows, underpaid, or outputs are locked (`< 10` blocks).
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

        if invoice.status == InvoiceStatus::Completed {
            return Err(GatewayError::Conflict(format!(
                "invoice {invoice_id} is in terminal status {}",
                invoice.status
            )));
        }

        if self.repo.has_reorged_sweep_attempt(invoice.id).await? {
            return Err(GatewayError::Conflict(format!(
                "invoice {invoice_id} has an unresolved SWEEP_REORG_DETECTED sweep incident requiring manual operator reconciliation via /sweep/resolve"
            )));
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
        let mut updated = if matches!(
            invoice.status,
            InvoiceStatus::Swept | InvoiceStatus::Expired
        ) {
            invoice.clone()
        } else {
            self.persist_evaluation(&invoice, &eval).await?
        };
        let min_sweep_confs = self
            .config
            .settlement_confirmations
            .max(MONERO_UNLOCK_CONFIRMATIONS);
        if invoice.status == InvoiceStatus::Reorged
            && updated.status == InvoiceStatus::Confirmed
            && updated.confirmations >= min_sweep_confs
            && eval.all_unlocked
        {
            updated = self.persist_evaluation(&updated, &eval).await?;
        }
        let updated = self
            .reconcile_subaddress_transfer_ledger(&updated, &eval)
            .await?;

        if updated.status == InvoiceStatus::Expired {
            if !self.repo.has_unswept_inflows(updated.id).await? {
                return Err(GatewayError::Conflict(format!(
                    "invoice {invoice_id} is EXPIRED with no unswept late payment inflows"
                )));
            }
            if !eval.all_unlocked
                || !self
                    .has_settled_unswept_inflows(updated.id, &eval, min_sweep_confs)
                    .await?
            {
                return Err(GatewayError::Conflict(format!(
                    "late payment funds on expired invoice {invoice_id} are still locked or awaiting settlement finality ({}/{} confirmations required)",
                    eval.effective_confirmations, min_sweep_confs
                )));
            }
            return self.execute_sweep_internal(invoice_id, true).await;
        }

        if updated.status == InvoiceStatus::Swept {
            if !self.repo.has_unswept_inflows(updated.id).await? {
                return Err(GatewayError::Conflict(format!(
                    "invoice {invoice_id} has already been swept"
                )));
            }
            if !eval.all_unlocked
                || !self
                    .has_settled_unswept_inflows(updated.id, &eval, min_sweep_confs)
                    .await?
            {
                return Err(GatewayError::Conflict(format!(
                    "residual overpayment funds are still locked or awaiting settlement finality ({}/{} confirmations required)",
                    eval.effective_confirmations, min_sweep_confs
                )));
            }
            return self.execute_sweep_internal(invoice_id, true).await;
        }

        if updated.received_piconero < updated.amount_piconero {
            return Err(GatewayError::Conflict(format!(
                "invoice {invoice_id} has not received full payment ({} / {} piconero)",
                updated.received_piconero.as_u64(),
                updated.amount_piconero.as_u64()
            )));
        }

        if updated.status != InvoiceStatus::Settled {
            return Err(GatewayError::Conflict(format!(
                "invoice {invoice_id} is in status {} and must reach SETTLED ({min_sweep_confs} confirmations) before sweeping",
                updated.status
            )));
        }

        if !eval.all_unlocked || updated.confirmations < min_sweep_confs {
            return Err(GatewayError::Conflict(format!(
                "subaddress funds are still locked or below settlement finality ({}/{min_sweep_confs} confirmations required)",
                eval.effective_confirmations
            )));
        }

        self.execute_sweep_internal(invoice_id, false).await
    }

    async fn has_settled_unswept_inflows(
        &self,
        invoice_id: Uuid,
        eval: &SubaddressEvaluation,
        min_sweep_confs: u64,
    ) -> GatewayResult<bool> {
        if !self.repo.has_unswept_inflows(invoice_id).await? {
            return Ok(false);
        }
        let records = self
            .repo
            .list_subaddress_transfers_for_invoice(invoice_id)
            .await?;
        let tx_by_id: HashMap<&str, &ObservedTransfer> = eval
            .transfers
            .iter()
            .map(|tr| (tr.txid.as_str(), tr))
            .collect();

        Ok(records.iter().any(|rec| {
            rec.status == SubaddressTransferStatus::Active
                && !rec.swept
                && matches!(
                    rec.classification,
                    TransferClassification::Overpayment | TransferClassification::LatePayment
                )
                && tx_by_id.get(rec.txid.as_str()).is_some_and(|tr| {
                    !tr.in_pool
                        && !tr.double_spend_seen
                        && !tr.orphaned
                        && tr.unlocked
                        && tr.confirmations >= min_sweep_confs
                })
        }))
    }

    async fn reconcile_subaddress_transfer_ledger(
        &self,
        invoice: &Invoice,
        eval: &SubaddressEvaluation,
    ) -> GatewayResult<Invoice> {
        if matches!(
            invoice.status,
            InvoiceStatus::Completed | InvoiceStatus::Swept | InvoiceStatus::Expired
        ) {
            let active_txids: Vec<String> = eval
                .transfers
                .iter()
                .filter(|tr| !tr.double_spend_seen && !tr.orphaned)
                .map(|tr| tr.txid.clone())
                .collect();
            self.repo
                .reconcile_orphaned_transfers(invoice.id, &active_txids, Utc::now())
                .await?;
        }

        let mut confirmed_valid: Vec<&ObservedTransfer> = eval
            .transfers
            .iter()
            .filter(|tr| {
                !tr.in_pool
                    && !tr.double_spend_seen
                    && !tr.orphaned
                    && tr.confirmations >= self.config.required_confirmations
            })
            .collect();

        if confirmed_valid.is_empty() {
            return Ok(invoice.clone());
        }

        confirmed_valid.sort_by(|a, b| {
            Reverse(a.confirmations)
                .cmp(&Reverse(b.confirmations))
                .then_with(|| a.txid.cmp(&b.txid))
        });

        let existing_records = self
            .repo
            .list_subaddress_transfers_for_invoice(invoice.id)
            .await?;
        let existing_by_txid: HashMap<&str, &SubaddressTransferRecord> = existing_records
            .iter()
            .filter(|r| r.status != SubaddressTransferStatus::Orphaned)
            .map(|r| (r.txid.as_str(), r))
            .collect();

        let track_expected_and_overpayment = matches!(
            invoice.status,
            InvoiceStatus::Confirmed
                | InvoiceStatus::Settled
                | InvoiceStatus::Completed
                | InvoiceStatus::Swept
        );

        let mut latest_invoice = invoice.clone();
        let mut cumulative_confirmed = 0_u64;
        let expected_u64 = invoice.amount_piconero.as_u64();

        for tr in confirmed_valid {
            let tx_amt = tr.amount_piconero.as_u64();
            if let Some(existing_rec) = existing_by_txid.get(tr.txid.as_str()) {
                if existing_rec.confirmations != tr.confirmations {
                    let now = Utc::now();
                    let mut synced = (*existing_rec).clone();
                    synced.confirmations = tr.confirmations;
                    latest_invoice = self
                        .repo
                        .record_subaddress_transfer(RecordSubaddressTransferParams {
                            record: synced,
                            transfer: tr.clone(),
                            received_piconero: eval.received_piconero,
                            confirmations: eval.effective_confirmations,
                            unlocked: eval.all_unlocked,
                            webhook: None,
                            now,
                        })
                        .await?;
                }
                cumulative_confirmed = cumulative_confirmed.saturating_add(tx_amt);
                continue;
            }

            let now = Utc::now();
            if latest_invoice.status == InvoiceStatus::Expired {
                let mut projected = latest_invoice.clone();
                projected.received_piconero = eval.received_piconero;
                projected.confirmations = eval.effective_confirmations;
                projected.unlocked = eval.all_unlocked;

                let webhook = match latest_invoice.callback_url.as_deref() {
                    Some(url) => Some(build_transfer_anomaly_webhook_delivery(
                        &self.config.webhook_secret,
                        &projected,
                        WebhookEventType::LatePayment,
                        &tr.txid,
                        tr.amount_piconero,
                        url,
                        now,
                    )?),
                    None => None,
                };

                let record = SubaddressTransferRecord {
                    id: 0,
                    txid: tr.txid.clone(),
                    invoice_id: latest_invoice.id,
                    address_index: latest_invoice.address_index,
                    amount_piconero: tr.amount_piconero,
                    confirmations: tr.confirmations,
                    classification: TransferClassification::LatePayment,
                    status: SubaddressTransferStatus::Active,
                    swept: false,
                    sweep_attempt_id: None,
                    created_at: now,
                };

                tracing::warn!(
                    invoice_id = %latest_invoice.id,
                    order_id = %latest_invoice.order_id,
                    txid = %tr.txid,
                    amount_piconero = tr.amount_piconero.as_u64(),
                    "recorded LATE_PAYMENT on expired subaddress"
                );

                latest_invoice = self
                    .repo
                    .record_subaddress_transfer(RecordSubaddressTransferParams {
                        record,
                        transfer: tr.clone(),
                        received_piconero: eval.received_piconero,
                        confirmations: eval.effective_confirmations,
                        unlocked: eval.all_unlocked,
                        webhook,
                        now,
                    })
                    .await?;
            } else if track_expected_and_overpayment {
                let new_total = cumulative_confirmed.saturating_add(tx_amt);
                if new_total > expected_u64 {
                    let excess =
                        Piconero(new_total.saturating_sub(cumulative_confirmed.max(expected_u64)));
                    let mut projected = latest_invoice.clone();
                    projected.received_piconero = eval.received_piconero;
                    projected.confirmations = eval.effective_confirmations;
                    projected.unlocked = eval.all_unlocked;

                    let webhook = match latest_invoice.callback_url.as_deref() {
                        Some(url) => Some(build_transfer_anomaly_webhook_delivery(
                            &self.config.webhook_secret,
                            &projected,
                            WebhookEventType::Overpayment,
                            &tr.txid,
                            excess,
                            url,
                            now,
                        )?),
                        None => None,
                    };

                    let record = SubaddressTransferRecord {
                        id: 0,
                        txid: tr.txid.clone(),
                        invoice_id: latest_invoice.id,
                        address_index: latest_invoice.address_index,
                        amount_piconero: excess,
                        confirmations: tr.confirmations,
                        classification: TransferClassification::Overpayment,
                        status: SubaddressTransferStatus::Active,
                        swept: false,
                        sweep_attempt_id: None,
                        created_at: now,
                    };

                    tracing::warn!(
                        invoice_id = %latest_invoice.id,
                        order_id = %latest_invoice.order_id,
                        txid = %tr.txid,
                        excess_piconero = excess.as_u64(),
                        "recorded OVERPAYMENT on subaddress"
                    );

                    latest_invoice = self
                        .repo
                        .record_subaddress_transfer(RecordSubaddressTransferParams {
                            record,
                            transfer: tr.clone(),
                            received_piconero: eval.received_piconero,
                            confirmations: eval.effective_confirmations,
                            unlocked: eval.all_unlocked,
                            webhook,
                            now,
                        })
                        .await?;
                } else {
                    let swept_already = latest_invoice.status == InvoiceStatus::Swept;
                    let record = SubaddressTransferRecord {
                        id: 0,
                        txid: tr.txid.clone(),
                        invoice_id: latest_invoice.id,
                        address_index: latest_invoice.address_index,
                        amount_piconero: tr.amount_piconero,
                        confirmations: tr.confirmations,
                        classification: TransferClassification::Expected,
                        status: if swept_already {
                            SubaddressTransferStatus::Swept
                        } else {
                            SubaddressTransferStatus::Active
                        },
                        swept: swept_already,
                        sweep_attempt_id: None,
                        created_at: now,
                    };

                    latest_invoice = self
                        .repo
                        .record_subaddress_transfer(RecordSubaddressTransferParams {
                            record,
                            transfer: tr.clone(),
                            received_piconero: eval.received_piconero,
                            confirmations: eval.effective_confirmations,
                            unlocked: eval.all_unlocked,
                            webhook: None,
                            now,
                        })
                        .await?;
                }
            }

            cumulative_confirmed = cumulative_confirmed.saturating_add(tx_amt);
        }

        Ok(latest_invoice)
    }

    async fn persist_evaluation(
        &self,
        invoice: &Invoice,
        eval: &SubaddressEvaluation,
    ) -> GatewayResult<Invoice> {
        let now = Utc::now();
        let mut next_status = compute_next_status_with_settlement(
            invoice.status,
            invoice.amount_piconero,
            eval,
            self.config.required_confirmations,
            self.config.settlement_confirmations,
            now,
            invoice.expires_at,
        );

        // In View-Only mode with no webhook destination, only SETTLED immediately completes
        // so CONFIRMED invoices remain actively monitored for reorgs until settlement finality.
        if next_status == InvoiceStatus::Settled
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
                InvoiceStatus::Settled => Some(WebhookEventType::Settled),
                InvoiceStatus::Reorged => Some(WebhookEventType::Reorged),
                InvoiceStatus::Expired => Some(WebhookEventType::Expired),
                InvoiceStatus::Pending | InvoiceStatus::Confirming | InvoiceStatus::Swept => None,
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
        if invoice.status != InvoiceStatus::Reorged && next_status == InvoiceStatus::Reorged {
            projected.reorg_epoch = invoice.reorg_epoch.saturating_add(1);
        }
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

    /// Reconciles active (`PREPARED`, `SUBMITTED`) and monitored (`CONFIRMED`, `RECONCILED`)
    /// sweep attempts against `monero-wallet-rpc` outgoing transfer history (`out` + `pending`):
    /// - Recovers crashed `PREPARED` attempts without duplicate `sweep_all` execution.
    /// - Enforces `SETTLEMENT_CONFIRMATIONS` finality gating (`SUBMITTED -> CONFIRMED`).
    /// - Detects disappeared or `double_spend_seen` outbound sweep transactions, escalating the
    ///   attempt to `REORGED` (`SWEEP_REORG_DETECTED`) and transitioning `SWEPT -> REORGED` while
    ///   blocking automatic re-sweep until manual operator reconciliation.
    ///
    /// Returns the number of interrupted `PREPARED` sweeps reconciled to `SWEPT`.
    ///
    /// # Errors
    /// Returns [`GatewayError::Database`] or [`GatewayError::RpcTransport`] / [`GatewayError::Rpc`]
    /// if querying SQLite or `monero-wallet-rpc` fails.
    pub async fn reconcile_in_flight_sweeps(&self) -> GatewayResult<usize> {
        let attempts = self
            .repo
            .list_monitored_sweep_attempts(self.monitor_cutoff())
            .await?;
        if attempts.is_empty() {
            return Ok(0);
        }

        let mut reconciled_count = 0_usize;
        for attempt in attempts {
            let lock = self.acquire_invoice_lock(attempt.invoice_id).await;
            let guard = lock.lock().await;
            let res = self.reconcile_single_attempt_locked(&attempt).await;
            drop(guard);
            self.release_invoice_lock(attempt.invoice_id, lock).await;
            if res?.is_some() {
                reconciled_count += 1;
            }
        }

        Ok(reconciled_count)
    }

    async fn reconcile_single_attempt_locked(
        &self,
        attempt: &SweepAttempt,
    ) -> GatewayResult<Option<Invoice>> {
        let Some(invoice) = self.repo.get_invoice_by_id(attempt.invoice_id).await? else {
            return Ok(None);
        };

        let out_resp = self
            .rpc
            .get_outgoing_transfers(invoice.account_index, &[attempt.address_index])
            .await?;

        if matches!(
            attempt.status,
            SweepAttemptStatus::Submitted
                | SweepAttemptStatus::Confirmed
                | SweepAttemptStatus::Reconciled
        ) {
            return self
                .reconcile_tracked_sweep_attempt(&invoice, attempt, &out_resp)
                .await;
        }

        if attempt.status != SweepAttemptStatus::Prepared {
            return Ok(None);
        }

        let mut matched_hashes = Vec::new();
        let mut total_amount = 0_u64;
        let mut total_fee = 0_u64;

        for entry in out_resp.out.iter().chain(out_resp.pending.iter()) {
            if entry.double_spend_seen
                || !entry.matches_sweep(
                    invoice.account_index,
                    attempt.address_index,
                    &attempt.destination_address,
                )
            {
                continue;
            }
            if invoice.sweep_tx_hashes.contains(&entry.txid) {
                continue;
            }
            if !matched_hashes.contains(&entry.txid) {
                matched_hashes.push(entry.txid.clone());
                total_amount = total_amount.checked_add(entry.amount).ok_or_else(|| {
                    GatewayError::Internal("overflow summing reconciled sweep amounts".to_string())
                })?;
                total_fee = total_fee.checked_add(entry.fee).ok_or_else(|| {
                    GatewayError::Internal("overflow summing reconciled sweep fees".to_string())
                })?;
            }
        }

        if matched_hashes.is_empty() {
            self.repo
                .mark_sweep_attempt_failed(
                    attempt.id,
                    invoice.id,
                    "reconciliation found no matching outgoing transfer in monero-wallet-rpc; safe to retry",
                    Utc::now(),
                )
                .await?;
            return Ok(None);
        }

        tracing::warn!(
            invoice_id = %invoice.id,
            attempt_id = %attempt.id,
            recovered_tx_hashes = ?matched_hashes,
            recovered_piconero = total_amount,
            "reconciled interrupted PREPARED sweep via monero-wallet-rpc outgoing history"
        );

        let reconciled = self
            .finalize_sweep_with_repo(
                &invoice,
                attempt.id,
                SweepAttemptStatus::Reconciled,
                matched_hashes,
                Piconero(total_amount),
                Piconero(total_fee),
                Utc::now(),
            )
            .await?;

        Ok(Some(reconciled))
    }

    async fn reconcile_tracked_sweep_attempt(
        &self,
        invoice: &Invoice,
        attempt: &SweepAttempt,
        out_resp: &GetTransfersResponse,
    ) -> GatewayResult<Option<Invoice>> {
        let mut mined_matches = Vec::new();
        let mut double_spent_tx: Option<String> = None;
        let mut missing_tx: Option<String> = None;

        if attempt.tx_hashes.is_empty() {
            let mut matched_any = false;
            for entry in out_resp.out.iter().chain(out_resp.pending.iter()) {
                if entry.matches_sweep(
                    invoice.account_index,
                    attempt.address_index,
                    &attempt.destination_address,
                ) {
                    matched_any = true;
                    if entry.double_spend_seen {
                        double_spent_tx = Some(entry.txid.clone());
                        break;
                    }
                }
            }
            for entry in &out_resp.out {
                if !entry.double_spend_seen
                    && entry.matches_sweep(
                        invoice.account_index,
                        attempt.address_index,
                        &attempt.destination_address,
                    )
                {
                    mined_matches.push(entry);
                }
            }
            if !matched_any && double_spent_tx.is_none() {
                missing_tx = Some("(unspecified sweep tx_hash)".to_string());
            }
        } else {
            for txid in &attempt.tx_hashes {
                let mined = out_resp.out.iter().find(|entry| &entry.txid == txid);
                let pending = out_resp.pending.iter().find(|entry| &entry.txid == txid);
                match (mined, pending) {
                    (Some(entry), _) | (None, Some(entry)) if entry.double_spend_seen => {
                        double_spent_tx = Some(txid.clone());
                        break;
                    }
                    (Some(entry), _) => {
                        mined_matches.push(entry);
                    }
                    (None, Some(_)) => {
                        // Still in mempool (pending): keep Submitted/non-final and continue monitoring.
                    }
                    (None, None) => {
                        missing_tx = Some(txid.clone());
                        break;
                    }
                }
            }
        }

        if let Some(reason) = double_spent_tx
            .map(|txid| format!("outgoing sweep tx {txid} flagged double_spend_seen=true"))
            .or_else(|| {
                missing_tx.map(|txid| {
                    format!(
                        "outgoing sweep tx {txid} disappeared from get_transfers(out=true, pending=true)"
                    )
                })
            })
        {
            let now = Utc::now();
            let err_msg = format!("SWEEP_REORG_DETECTED: {reason}");
            let mut projected = invoice.clone();
            if invoice.status == InvoiceStatus::Swept {
                projected.status = InvoiceStatus::Reorged;
            }
            projected.reorg_epoch = invoice.reorg_epoch.saturating_add(1);
            projected.last_sweep_error = Some(err_msg.clone());

            let webhook = match invoice.callback_url.as_deref() {
                Some(url) => Some(build_webhook_delivery(
                    &self.config.webhook_secret,
                    &projected,
                    WebhookEventType::Reorged,
                    url,
                    now,
                )?),
                None => None,
            };

            tracing::error!(
                invoice_id = %invoice.id,
                order_id = %invoice.order_id,
                attempt_id = %attempt.id,
                invoice_status = invoice.status.as_str(),
                reorg_epoch = projected.reorg_epoch,
                error = %err_msg,
                "CRITICAL SECURITY ALERT: outbound sweep reorg/double-spend detected; auto re-sweep blocked pending manual reconciliation"
            );

            self.repo
                .mark_sweep_attempt_reorged(attempt.id, invoice.id, &err_msg, webhook, now)
                .await?;
            return Ok(None);
        }

        let expected_count = if attempt.tx_hashes.is_empty() {
            usize::from(!mined_matches.is_empty())
        } else {
            attempt.tx_hashes.len()
        };
        let all_final = expected_count > 0
            && mined_matches.len() == expected_count
            && mined_matches.iter().all(|entry| {
                !entry.double_spend_seen
                    && entry.confirmations >= self.config.settlement_confirmations
            });

        match attempt.status {
            SweepAttemptStatus::Submitted | SweepAttemptStatus::Reconciled if all_final => {
                self.repo
                    .update_sweep_attempt_status(
                        attempt.id,
                        SweepAttemptStatus::Confirmed,
                        Utc::now(),
                    )
                    .await?;
            }
            SweepAttemptStatus::Confirmed if !all_final => {
                // Depth dropped below settlement_confirmations without disappearing or double-spending:
                // return attempt to SUBMITTED so finality is re-verified.
                self.repo
                    .update_sweep_attempt_status(
                        attempt.id,
                        SweepAttemptStatus::Submitted,
                        Utc::now(),
                    )
                    .await?;
            }
            _ => {}
        }

        Ok(None)
    }

    async fn execute_sweep_internal(
        &self,
        invoice_id: Uuid,
        allow_terminal_inflows: bool,
    ) -> GatewayResult<Invoice> {
        let lock = self.acquire_invoice_lock(invoice_id).await;
        let guard = lock.lock().await;
        let res = self
            .execute_sweep_under_lock(invoice_id, allow_terminal_inflows)
            .await;
        drop(guard);
        self.release_invoice_lock(invoice_id, lock).await;
        res
    }

    async fn execute_sweep_under_lock(
        &self,
        invoice_id: Uuid,
        allow_terminal_inflows: bool,
    ) -> GatewayResult<Invoice> {
        if self.repo.has_reorged_sweep_attempt(invoice_id).await? {
            return Err(GatewayError::Conflict(format!(
                "invoice {invoice_id} has an unresolved SWEEP_REORG_DETECTED sweep incident requiring manual operator reconciliation"
            )));
        }

        let in_flight = self
            .repo
            .list_in_flight_sweep_attempts_for_invoice(invoice_id)
            .await?;
        for attempt in &in_flight {
            if attempt.status == SweepAttemptStatus::Prepared
                && let Some(reconciled) = self.reconcile_single_attempt_locked(attempt).await?
            {
                return Ok(reconciled);
            }
        }

        let current = self
            .repo
            .get_invoice_by_id(invoice_id)
            .await?
            .ok_or_else(|| GatewayError::NotFound(format!("invoice {invoice_id} not found")))?;

        if matches!(
            current.status,
            InvoiceStatus::Swept | InvoiceStatus::Expired
        ) && !allow_terminal_inflows
        {
            if current.status == InvoiceStatus::Swept {
                return Ok(current);
            }
            return Err(GatewayError::Conflict(format!(
                "invoice {invoice_id} is EXPIRED without sweepable late-payment authorization"
            )));
        }
        if !matches!(
            current.status,
            InvoiceStatus::Settled | InvoiceStatus::Swept | InvoiceStatus::Expired
        ) {
            return Err(GatewayError::Conflict(format!(
                "invoice {invoice_id} status is {}, expected SETTLED",
                current.status
            )));
        }

        let cold_addr = self.config.cold_wallet_address.as_deref().ok_or_else(|| {
            GatewayError::Config(
                "COLD_WALLET_ADDRESS is not configured for sweep execution".to_string(),
            )
        })?;

        let attempt = self
            .repo
            .create_prepared_sweep_attempt(current.id, current.address_index, cold_addr, Utc::now())
            .await?;

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
            Err(err @ GatewayError::Rpc { .. }) => {
                // Deterministic JSON-RPC error means monero-wallet-rpc did not broadcast.
                let _ = self
                    .repo
                    .mark_sweep_attempt_failed(attempt.id, invoice_id, &err.to_string(), Utc::now())
                    .await;
                return Err(err);
            }
            Err(err) => {
                // Transport drop/timeout: retain PREPARED row so next scan reconciles via get_transfers(out/pending).
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
                .mark_sweep_attempt_failed(attempt.id, invoice_id, &err.to_string(), Utc::now())
                .await;
            return Err(err);
        }

        let total_amount = sum_u64_checked(&sweep_res.amount_list, "sweep amount_list")?;
        let total_fee = sum_u64_checked(&sweep_res.fee_list, "sweep fee_list")?;

        self.finalize_sweep_with_repo(
            &current,
            attempt.id,
            SweepAttemptStatus::Submitted,
            sweep_res.tx_hash_list,
            total_amount,
            total_fee,
            Utc::now(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn finalize_sweep_with_repo(
        &self,
        current: &Invoice,
        attempt_id: Uuid,
        attempt_status: SweepAttemptStatus,
        tx_hashes: Vec<String>,
        total_amount: Piconero,
        total_fee: Piconero,
        now: DateTime<Utc>,
    ) -> GatewayResult<Invoice> {
        let sweep_reason = match current.status {
            InvoiceStatus::Expired => Some("LATE_PAYMENT"),
            InvoiceStatus::Swept => Some("OVERPAYMENT"),
            _ => None,
        };

        let mut merged_hashes = current.sweep_tx_hashes.clone();
        for h in &tx_hashes {
            if !merged_hashes.contains(h) {
                merged_hashes.push(h.clone());
            }
        }

        let mut projected = current.clone();
        projected.status = if current.status == InvoiceStatus::Expired {
            InvoiceStatus::Expired
        } else {
            InvoiceStatus::Swept
        };
        projected.unlocked = true;
        projected.sweep_tx_hashes = merged_hashes;
        projected.sweep_amount_piconero = Some(
            current
                .sweep_amount_piconero
                .unwrap_or(Piconero::ZERO)
                .saturating_add(total_amount),
        );
        projected.sweep_fee_piconero = Some(
            current
                .sweep_fee_piconero
                .unwrap_or(Piconero::ZERO)
                .saturating_add(total_fee),
        );
        projected.swept_at = Some(current.swept_at.unwrap_or(now));

        let webhook = match current.callback_url.as_deref() {
            Some(url) => Some(build_sweep_webhook_delivery(
                &self.config.webhook_secret,
                &projected,
                sweep_reason,
                url,
                now,
            )?),
            None => None,
        };

        tracing::info!(
            invoice_id = %current.id,
            order_id = %current.order_id,
            address_index = current.address_index,
            attempt_id = %attempt_id,
            attempt_status = attempt_status.as_str(),
            sweep_tx_hashes = ?tx_hashes,
            swept_piconero = total_amount.as_u64(),
            fee_piconero = total_fee.as_u64(),
            "subaddress sweep persisted to SQLite"
        );

        self.repo
            .complete_sweep_attempt(CompleteSweepAttemptParams {
                attempt_id,
                invoice_id: current.id,
                attempt_status,
                sweep_tx_hashes: tx_hashes,
                sweep_amount_piconero: total_amount,
                sweep_fee_piconero: total_fee,
                webhook,
                now,
            })
            .await
    }

    /// Resolves a `REORGED` (`SWEEP_REORG_DETECTED`) sweep incident under the per-invoice sweep lock (`XMR-041` / `XMR-043` / `XMR-044`).
    ///
    /// - When `action == SweepResolutionAction::AllowResweep`:
    ///   1. Requires explicit `confirm_absent_on_chain == Some(true)` (`400 Bad Request`).
    ///   2. Verifies fail-closed wallet/daemon sync (`get_height` >= `get_info` height, non-zero;
    ///      `503` on RPC error, `409` on lag).
    ///   3. Verifies via `get_transfers(out=true, pending=true, pool=true)` that none of the
    ///      `REORGED` attempt's transactions remain alive without `double_spend_seen=true`.
    ///   4. Persists enriched audit metadata (`verified_at_utc`, `wallet_height`, `daemon_height`,
    ///      `prior_tx_hashes`, `operator_note`) in `resolution_note`.
    /// - When `action == SweepResolutionAction::MarkReconciled`:
    ///   1. Validates any supplied `replacement_tx_hash` as strict 64-hex normalized to lowercase.
    ///   2. Verifies via `get_transfers(out=true, pending=true, pool=true)` that
    ///      `replacement_tx_hash` exists in `out` or `pending` with `double_spend_seen=false` (`409` otherwise).
    ///
    /// # Errors
    /// - [`GatewayError::Validation`] (`400`) on blank `operator_note`, missing
    ///   `confirm_absent_on_chain=true`, or invalid non-64-hex `replacement_tx_hash`.
    /// - [`GatewayError::NotFound`] (`404`) if invoice or `attempt_id` is missing.
    /// - [`GatewayError::Conflict`] (`409`) if no `REORGED` attempt exists, wallet lags behind
    ///   daemon tip, old sweep tx is still live, or replacement tx is absent/double-spent.
    /// - [`GatewayError::ServiceUnavailable`] (`503`) / [`GatewayError::Rpc`] / [`GatewayError::Database`]
    ///   on RPC sync unavailability or backend failure.
    pub async fn resolve_sweep_incident(
        &self,
        invoice_id: Uuid,
        attempt_id: Option<Uuid>,
        action: SweepResolutionAction,
        replacement_tx_hash: Option<&str>,
        confirm_absent_on_chain: Option<bool>,
        operator_note: &str,
    ) -> GatewayResult<(Invoice, SweepAttempt)> {
        let trimmed_note = operator_note.trim();
        if trimmed_note.is_empty() {
            return Err(GatewayError::Validation(
                "operator_note must not be empty when resolving a sweep incident".to_string(),
            ));
        }
        if action == SweepResolutionAction::AllowResweep && confirm_absent_on_chain != Some(true) {
            return Err(GatewayError::Validation(
                "confirm_absent_on_chain must be explicitly set to true for action=allow_resweep"
                    .to_string(),
            ));
        }

        let cleaned_replacement = match replacement_tx_hash {
            Some(raw) => {
                let t = raw.trim();
                if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(GatewayError::Validation(
                        "replacement_tx_hash must be an exact 64-character hexadecimal Monero transaction hash"
                            .to_string(),
                    ));
                }
                Some(t.to_ascii_lowercase())
            }
            None => None,
        };

        let lock = self.acquire_invoice_lock(invoice_id).await;
        let guard = lock.lock().await;
        let res = self
            .resolve_sweep_incident_locked(
                invoice_id,
                attempt_id,
                action,
                cleaned_replacement.as_deref(),
                trimmed_note,
            )
            .await;
        drop(guard);
        self.release_invoice_lock(invoice_id, lock).await;
        res
    }

    async fn resolve_sweep_incident_locked(
        &self,
        invoice_id: Uuid,
        attempt_id: Option<Uuid>,
        action: SweepResolutionAction,
        replacement_tx_hash: Option<&str>,
        operator_note: &str,
    ) -> GatewayResult<(Invoice, SweepAttempt)> {
        let (invoice, attempt) = self
            .repo
            .get_reorged_sweep_attempt(invoice_id, attempt_id)
            .await?;

        let now = Utc::now();
        match action {
            SweepResolutionAction::AllowResweep => {
                let (wallet_height, daemon_height) = self
                    .rpc
                    .verify_wallet_synced(self.config.monero_daemon_rpc_url.as_deref())
                    .await?;

                let verify_resp = self
                    .rpc
                    .get_sweep_verification_transfers(
                        invoice.account_index,
                        &[attempt.address_index],
                    )
                    .await
                    .map_err(|err| {
                        GatewayError::ServiceUnavailable(format!(
                            "unable to verify sweep transfers from monero-wallet-rpc: {err}"
                        ))
                    })?;

                let still_alive = if attempt.tx_hashes.is_empty() {
                    verify_resp
                        .out
                        .iter()
                        .chain(verify_resp.pending.iter())
                        .chain(verify_resp.pool.iter())
                        .any(|entry| {
                            !entry.double_spend_seen
                                && entry.matches_sweep(
                                    invoice.account_index,
                                    attempt.address_index,
                                    &attempt.destination_address,
                                )
                        })
                } else {
                    attempt.tx_hashes.iter().any(|txid| {
                        verify_resp
                            .out
                            .iter()
                            .chain(verify_resp.pending.iter())
                            .chain(verify_resp.pool.iter())
                            .any(|entry| {
                                entry.txid.eq_ignore_ascii_case(txid) && !entry.double_spend_seen
                            })
                    })
                };

                if still_alive {
                    return Err(GatewayError::Conflict(format!(
                        "cannot allow_resweep for invoice {invoice_id} attempt {}: recorded sweep tx is still live in wallet/mempool (out/pending/pool) without double_spend_seen=true",
                        attempt.id
                    )));
                }

                let verified_at_utc = now.to_rfc3339();
                let prior_txids = if attempt.tx_hashes.is_empty() {
                    "none".to_string()
                } else {
                    attempt.tx_hashes.join(",")
                };
                let audit_note = format!(
                    "{operator_note} [verified_at_utc={verified_at_utc}; wallet_height={wallet_height}; daemon_height={daemon_height}; prior_tx_hashes={prior_txids}]"
                );

                tracing::warn!(
                    invoice_id = %invoice_id,
                    attempt_id = %attempt.id,
                    verified_at_utc = %verified_at_utc,
                    wallet_height = wallet_height,
                    daemon_height = daemon_height,
                    prior_tx_hashes = ?attempt.tx_hashes,
                    operator_note = %operator_note,
                    "operator resolved SWEEP_REORG_DETECTED via ALLOW_RESWEEP after fail-closed height sync & RPC transfer check"
                );

                self.repo
                    .resolve_sweep_incident_allow_resweep(attempt.id, invoice_id, &audit_note, now)
                    .await
            }
            SweepResolutionAction::MarkReconciled => {
                if let Some(rep_txid) = replacement_tx_hash {
                    let verify_resp = self
                        .rpc
                        .get_sweep_verification_transfers(
                            invoice.account_index,
                            &[attempt.address_index],
                        )
                        .await
                        .map_err(|err| {
                            GatewayError::ServiceUnavailable(format!(
                                "unable to verify replacement_tx_hash from monero-wallet-rpc: {err}"
                            ))
                        })?;

                    let verified_replacement = verify_resp
                        .out
                        .iter()
                        .chain(verify_resp.pending.iter())
                        .any(|entry| {
                            entry.txid.eq_ignore_ascii_case(rep_txid) && !entry.double_spend_seen
                        });

                    if !verified_replacement {
                        return Err(GatewayError::Conflict(format!(
                            "replacement_tx_hash {rep_txid} was not found in outgoing wallet transfers (out/pending) or is flagged double_spend_seen=true"
                        )));
                    }
                }

                tracing::warn!(
                    invoice_id = %invoice_id,
                    attempt_id = %attempt.id,
                    replacement_tx_hash = ?replacement_tx_hash,
                    operator_note = %operator_note,
                    "operator resolved SWEEP_REORG_DETECTED via MARK_RECONCILED"
                );

                self.repo
                    .resolve_sweep_incident_mark_reconciled(
                        attempt.id,
                        invoice_id,
                        replacement_tx_hash,
                        operator_note,
                        now,
                    )
                    .await
            }
        }
    }

    async fn acquire_invoice_lock(&self, invoice_id: Uuid) -> Arc<Mutex<()>> {
        let mut map = self.sweep_locks.lock().await;
        map.entry(invoice_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Prunes completed per-invoice sweep mutexes when no other task holds or awaits them (`P1-3`).
    async fn release_invoice_lock(&self, invoice_id: Uuid, lock: Arc<Mutex<()>>) {
        let mut map = self.sweep_locks.lock().await;
        if Arc::strong_count(&lock) <= 2 && lock.try_lock().is_ok() {
            map.remove(&invoice_id);
        }
    }

    /// Returns the number of currently retained per-invoice mutex entries (for leak regression tests).
    #[cfg(test)]
    pub async fn active_sweep_lock_count(&self) -> usize {
        self.sweep_locks.lock().await.len()
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
            per_subaddr_by_txid
                .entry(minor_idx)
                .or_default()
                .entry(entry.txid.clone())
                .and_modify(|existing| {
                    existing.amount_piconero =
                        Piconero(existing.amount_piconero.as_u64().saturating_add(amt));
                    existing.double_spend_seen =
                        existing.double_spend_seen || entry.double_spend_seen;
                })
                .or_insert_with(|| ObservedTransfer {
                    txid: entry.txid.clone(),
                    amount_piconero: Piconero(amt),
                    confirmations: 0,
                    unlocked: false,
                    double_spend_seen: entry.double_spend_seen,
                    in_pool: true,
                    orphaned: false,
                });
        }
    }

    for entry in &resp.in_transfers {
        let is_unlocked = entry.is_unlocked(false);
        for (minor_idx, amt) in entry.subaddress_amounts(account_index) {
            let tx_map = per_subaddr_by_txid.entry(minor_idx).or_default();
            match tx_map.get_mut(&entry.txid) {
                Some(existing) if existing.in_pool => {
                    *existing = ObservedTransfer {
                        txid: entry.txid.clone(),
                        amount_piconero: Piconero(amt),
                        confirmations: entry.confirmations,
                        unlocked: is_unlocked,
                        double_spend_seen: entry.double_spend_seen,
                        in_pool: false,
                        orphaned: false,
                    };
                }
                Some(existing) => {
                    existing.amount_piconero =
                        Piconero(existing.amount_piconero.as_u64().saturating_add(amt));
                    existing.confirmations = existing.confirmations.min(entry.confirmations);
                    existing.unlocked = existing.unlocked && is_unlocked;
                    existing.double_spend_seen =
                        existing.double_spend_seen || entry.double_spend_seen;
                }
                None => {
                    tx_map.insert(
                        entry.txid.clone(),
                        ObservedTransfer {
                            txid: entry.txid.clone(),
                            amount_piconero: Piconero(amt),
                            confirmations: entry.confirmations,
                            unlocked: is_unlocked,
                            double_spend_seen: entry.double_spend_seen,
                            in_pool: false,
                            orphaned: false,
                        },
                    );
                }
            }
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
    use crate::{
        config::{LogFormat, WalletMode, encode_monero_base58_address},
        db::init_sqlite_pool,
        domain::invoice::build_monero_uri,
    };

    fn test_config(rpc_url: String, enable_auto_sweep: bool) -> Arc<Config> {
        Arc::new(Config {
            host: "127.0.0.1".to_string(),
            port: 8080,
            cors_allowed_origins: vec!["*".to_string()],
            database_url: "sqlite::memory:".to_string(),
            api_secret_key: "a".repeat(32),
            operator_api_key: None,
            webhook_secret: "b".repeat(32),
            default_webhook_url: None,
            allow_private_webhooks: true,
            require_https_webhooks: false,
            monero_rpc_url: rpc_url,
            monero_daemon_rpc_url: None,
            monero_rpc_user: None,
            monero_rpc_pass: None,
            allow_unauthenticated_rpc: true,
            allow_insecure_remote_rpc: false,
            cold_wallet_address: if enable_auto_sweep {
                Some(encode_monero_base58_address(
                    18,
                    &[0x11; 32],
                    &[0x22; 32],
                    None,
                ))
            } else {
                None
            },
            wallet_mode: if enable_auto_sweep {
                WalletMode::HotWallet
            } else {
                WalletMode::ViewOnly
            },
            monero_trusted_daemon: false,
            allow_hot_wallet_without_sweep: false,
            enable_auto_sweep,
            sweep_priority: 0,
            required_confirmations: 2,
            settlement_confirmations: 10,
            invoice_ttl_seconds: 3600,
            scan_interval_seconds: 10,
            webhook_poll_interval_seconds: 5,
            subaddress_monitor_days: 0,
            log_format: LogFormat::Json,
        })
    }

    fn insertable_invoice(address_index: u32, amount: u64, callback: Option<String>) -> Invoice {
        let now = Utc::now();
        let subaddr = encode_monero_base58_address(42, &[0x44; 32], &[0x55; 32], None);
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
            reorg_epoch: 0,
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
            settled_at: None,
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

        // Verify all 5 webhooks (UNDERPAID, MEMPOOL, CONFIRMED, SETTLED, SWEPT) were queued once each
        let webhooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        let events: Vec<WebhookEventType> = webhooks.iter().map(|w| w.event_type).collect();
        assert_eq!(
            events,
            vec![
                WebhookEventType::Underpaid,
                WebhookEventType::Mempool,
                WebhookEventType::Confirmed,
                WebhookEventType::Settled,
                WebhookEventType::Swept,
            ]
        );
    }

    #[tokio::test]
    async fn scanner_emits_reorged_webhook_when_confirmed_invoice_loses_confirmations_or_sees_double_spend()
     {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;

        let inv = insertable_invoice(
            18,
            1_000_000_000_000,
            Some("http://127.0.0.1:9999/reorg".to_string()),
        );
        repo.insert_invoice(&inv).await.unwrap();

        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), false);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg);

        // 1) Reach CONFIRMED at 3 confirmations
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": {
                    "in": [{
                        "txid": "7".repeat(64),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 3,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 18 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        let conf = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(conf.status, InvoiceStatus::Confirmed);

        // 2) Reorg drops transaction back to 0 confirmations (mempool) => REORGED + webhook
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "2",
                "result": {
                    "in": [],
                    "pool": [{
                        "txid": "7".repeat(64),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 0,
                        "double_spend_seen": true,
                        "subaddr_index": { "major": 0, "minor": 18 }
                    }]
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        let reorged = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(reorged.status, InvoiceStatus::Reorged);
        assert!(reorged.double_spend_seen);

        let webhooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        let events: Vec<WebhookEventType> = webhooks.iter().map(|w| w.event_type).collect();
        assert_eq!(
            events,
            vec![WebhookEventType::Confirmed, WebhookEventType::Reorged]
        );
    }

    #[tokio::test]
    async fn reconciles_interrupted_prepared_sweep_via_outgoing_transfers_without_duplicate_sweep_all()
     {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;

        let mut inv = insertable_invoice(
            23,
            1_000_000_000_000,
            Some("http://127.0.0.1:9999/reconcile".to_string()),
        );
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 12;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), true);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap().to_string();

        // Simulate crash right after sweep_all broadcast: PREPARED attempt persisted in SQLite
        let attempt = repo
            .create_prepared_sweep_attempt(inv.id, inv.address_index, &cold_addr, Utc::now())
            .await
            .unwrap();
        assert_eq!(attempt.status, SweepAttemptStatus::Prepared);

        // Mock get_transfers returning outgoing tx in "out" & ensure sweep_all is NEVER called twice!
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("sweep_all"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_rpc)
            .await;

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""out":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": {
                    "out": [{
                        "txid": "8".repeat(64),
                        "amount": 999_800_000_000_u64,
                        "fee": 200_000_000_u64,
                        "confirmations": 1,
                        "subaddr_index": { "major": 0, "minor": 23 },
                        "destinations": [{
                            "amount": 999_800_000_000_u64,
                            "address": cold_addr
                        }]
                    }],
                    "pending": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "2",
                "result": {
                    "in": [{
                        "txid": "5".repeat(64),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 12,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 23 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg);

        let report = scanner.scan_once().await.unwrap();
        assert_eq!(report.invoices_swept, 1);

        let after = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(after.status, InvoiceStatus::Swept);
        assert_eq!(after.sweep_tx_hashes, vec!["8".repeat(64)]);
        assert_eq!(after.sweep_amount_piconero, Some(Piconero(999_800_000_000)));
        assert_eq!(after.sweep_fee_piconero, Some(Piconero(200_000_000)));

        let attempts = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].status, SweepAttemptStatus::Reconciled);

        let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].event_type, WebhookEventType::Swept);
    }

    #[tokio::test]
    async fn late_payment_on_expired_invoice_records_ledger_and_emits_webhook() {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;

        let mut inv = insertable_invoice(
            31,
            1_000_000_000_000,
            Some("http://127.0.0.1:9999/late".to_string()),
        );
        inv.expires_at = Utc::now() - ChronoDuration::minutes(5);
        repo.insert_invoice(&inv).await.unwrap();

        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), false);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg);

        // 1) Empty scan transitions expired invoice -> EXPIRED
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": { "in": [], "pool": [] }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        let expired = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(expired.status, InvoiceStatus::Expired);

        // 2) Confirmed transfer arrives AFTER invoice expired => LATE_PAYMENT ledger + webhook
        mock_rpc.reset().await;
        let late_txid = "b".repeat(64);
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "2",
                "result": {
                    "in": [{
                        "txid": late_txid,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 3,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 31 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();

        let ledger = repo
            .list_subaddress_transfers_for_invoice(inv.id)
            .await
            .unwrap();
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].txid, late_txid);
        assert_eq!(
            ledger[0].classification,
            TransferClassification::LatePayment
        );
        assert_eq!(ledger[0].amount_piconero, Piconero(1_000_000_000_000));

        let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        let events: Vec<WebhookEventType> = hooks.iter().map(|w| w.event_type).collect();
        assert_eq!(
            events,
            vec![WebhookEventType::Expired, WebhookEventType::LatePayment]
        );
        assert!(hooks[1].payload_json.contains(&late_txid));
        assert!(hooks[1].payload_json.contains(&inv.order_id));
    }

    #[tokio::test]
    async fn overpayment_after_swept_invoice_emits_webhook_and_remains_sweepable() {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;

        let inv = insertable_invoice(
            32,
            1_000_000_000_000,
            Some("http://127.0.0.1:9999/overpay".to_string()),
        );
        repo.insert_invoice(&inv).await.unwrap();

        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), true);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg);

        // 1) First payment confirms & unlocks (10 confs) -> CONFIRMED -> SWEPT
        let tx1 = "1".repeat(64);
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": {
                    "in": [{
                        "txid": tx1,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 10,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 32 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("sweep_all"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "2",
                "result": {
                    "tx_hash_list": ["9".repeat(64)],
                    "amount_list": [999_900_000_000_u64],
                    "fee_list": [100_000_000_u64]
                }
            })))
            .mount(&mock_rpc)
            .await;

        // First scan advances Pending -> Confirmed without sweeping (XMR-024); second advances Confirmed -> Settled -> Swept
        scanner.scan_once().await.unwrap();
        let conf1 = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(conf1.status, InvoiceStatus::Confirmed);
        assert!(conf1.sweep_tx_hashes.is_empty());

        scanner.scan_once().await.unwrap();
        let swept1 = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(swept1.status, InvoiceStatus::Swept);
        assert_eq!(swept1.sweep_tx_hashes, vec!["9".repeat(64)]);

        // 2) Second transfer arrives after invoice was SWEPT (0.5 XMR unlocked) => OVERPAYMENT + auto-swept residual!
        mock_rpc.reset().await;
        let tx2 = "2".repeat(64);
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "3",
                "result": {
                    "in": [
                        {
                            "txid": tx1,
                            "amount": 1_000_000_000_000_u64,
                            "confirmations": 22,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 32 }
                        },
                        {
                            "txid": tx2,
                            "amount": 500_000_000_000_u64,
                            "confirmations": 10,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 32 }
                        }
                    ],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""out":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "4",
                "result": {
                    "out": [{
                        "txid": "9".repeat(64),
                        "amount": 999_900_000_000_u64,
                        "fee": 100_000_000_u64,
                        "confirmations": 10,
                        "subaddr_index": { "major": 0, "minor": 32 }
                    }],
                    "pending": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("sweep_all"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "5",
                "result": {
                    "tx_hash_list": ["c".repeat(64)],
                    "amount_list": [499_900_000_000_u64],
                    "fee_list": [100_000_000_u64]
                }
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let report2 = scanner.scan_once().await.unwrap();
        assert_eq!(report2.invoices_swept, 1);

        let after2 = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(after2.status, InvoiceStatus::Swept);
        assert_eq!(after2.received_piconero, Piconero(1_500_000_000_000));
        assert_eq!(after2.sweep_tx_hashes, vec!["9".repeat(64), "c".repeat(64)]);
        assert_eq!(
            after2.sweep_amount_piconero,
            Some(Piconero(1_499_800_000_000))
        );

        let ledger = repo
            .list_subaddress_transfers_for_invoice(inv.id)
            .await
            .unwrap();
        assert_eq!(ledger.len(), 2);
        assert!(ledger.iter().any(|r| {
            r.txid == tx2
                && r.classification == TransferClassification::Overpayment
                && r.amount_piconero == Piconero(500_000_000_000)
                && r.swept
        }));

        let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        let events: Vec<WebhookEventType> = hooks.iter().map(|w| w.event_type).collect();
        assert!(events.contains(&WebhookEventType::Overpayment));
    }

    #[tokio::test]
    async fn view_only_invoice_stays_confirmed_until_settlement_detects_reorg_and_completes_on_settled()
     {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let mock_hook = MockServer::start().await;

        let hook_url = format!("{}/vo-hook", mock_hook.uri());
        let inv = insertable_invoice(41, 1_000_000_000_000, Some(hook_url));
        repo.insert_invoice(&inv).await.unwrap();

        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), false);
        assert_eq!(cfg.required_confirmations, 2);
        assert_eq!(cfg.settlement_confirmations, 10);

        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());
        let dispatcher = crate::services::webhook::WebhookDispatcher::new(
            repo.clone(),
            cfg.enable_auto_sweep,
            Duration::from_secs(5),
            cfg.webhook_url_policy(),
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/vo-hook"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_hook)
            .await;

        // 1) Reach 2 confirmations -> CONFIRMED; deliver CONFIRMED webhook -> MUST remain CONFIRMED!
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": {
                    "in": [{
                        "txid": "a".repeat(64),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 2,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 41 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        assert_eq!(
            repo.get_invoice_by_id(inv.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            InvoiceStatus::Confirmed
        );

        dispatcher.process_due_deliveries().await.unwrap();
        let after_conf_delivery = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(after_conf_delivery.status, InvoiceStatus::Confirmed);
        assert!(after_conf_delivery.completed_at.is_none());

        // 2) Reorg drops confirmations below 2 -> MUST transition to REORGED and emit REORGED webhook!
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "2",
                "result": {
                    "in": [{
                        "txid": "a".repeat(64),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 1,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 41 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        assert_eq!(
            repo.get_invoice_by_id(inv.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            InvoiceStatus::Reorged
        );

        // 3) Re-mines cleanly: 2 confs -> CONFIRMED, then 10 confs -> SETTLED -> COMPLETED on webhook!
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "3",
                "result": {
                    "in": [{
                        "txid": "b".repeat(64),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 10,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 41 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        assert_eq!(
            repo.get_invoice_by_id(inv.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            InvoiceStatus::Confirmed
        );
        scanner.scan_once().await.unwrap();
        assert_eq!(
            repo.get_invoice_by_id(inv.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            InvoiceStatus::Settled
        );

        dispatcher.process_due_deliveries().await.unwrap();
        let completed = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(completed.status, InvoiceStatus::Completed);
        assert!(completed.completed_at.is_some());

        let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        let events: Vec<WebhookEventType> = hooks.iter().map(|w| w.event_type).collect();
        assert!(events.contains(&WebhookEventType::Confirmed));
        assert!(events.contains(&WebhookEventType::Reorged));
        assert!(events.contains(&WebhookEventType::Settled));
    }

    #[tokio::test]
    async fn expired_invoice_late_payment_sweeps_and_preserves_expired_status() {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;

        let mut inv = insertable_invoice(
            42,
            1_000_000_000_000,
            Some("http://127.0.0.1:9999/late-sweep".to_string()),
        );
        inv.expires_at = Utc::now() - ChronoDuration::minutes(5);
        repo.insert_invoice(&inv).await.unwrap();

        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), true);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg);

        // 1) Expire invoice
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": { "in": [], "pool": [] }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        assert_eq!(
            repo.get_invoice_by_id(inv.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            InvoiceStatus::Expired
        );

        // 2) Unlocked late payment arrives -> records LATE_PAYMENT, sweeps once, preserves EXPIRED!
        mock_rpc.reset().await;
        let late_txid = "d".repeat(64);
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "2",
                "result": {
                    "in": [{
                        "txid": late_txid,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 10,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 42 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("sweep_all"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "3",
                "result": {
                    "tx_hash_list": ["e".repeat(64)],
                    "amount_list": [999_900_000_000_u64],
                    "fee_list": [100_000_000_u64]
                }
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let report = scanner.scan_once().await.unwrap();
        assert_eq!(report.invoices_swept, 1);

        let after_sweep = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(after_sweep.status, InvoiceStatus::Expired);
        assert_eq!(after_sweep.sweep_tx_hashes, vec!["e".repeat(64)]);

        let ledger = repo
            .list_subaddress_transfers_for_invoice(inv.id)
            .await
            .unwrap();
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger[0].classification,
            TransferClassification::LatePayment
        );
        assert!(ledger[0].swept);

        let attempts = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].status, SweepAttemptStatus::Submitted);

        let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        let events: Vec<WebhookEventType> = hooks.iter().map(|w| w.event_type).collect();
        assert_eq!(
            events,
            vec![
                WebhookEventType::Expired,
                WebhookEventType::LatePayment,
                WebhookEventType::Swept,
            ]
        );
        assert!(hooks[2].payload_json.contains(r#""status":"EXPIRED""#));
        assert!(
            hooks[2]
                .payload_json
                .contains(r#""sweep_reason":"LATE_PAYMENT""#)
        );

        // 3) Second scan must NOT re-sweep (sweep_all .expect(1) holds) and manual_sweep rejects empty
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""out":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "4",
                "result": {
                    "out": [{
                        "txid": "e".repeat(64),
                        "amount": 999_900_000_000_u64,
                        "fee": 100_000_000_u64,
                        "confirmations": 1,
                        "subaddr_index": { "major": 0, "minor": 42 }
                    }],
                    "pending": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let report2 = scanner.scan_once().await.unwrap();
        assert_eq!(report2.invoices_swept, 0);

        let manual_err = scanner.manual_sweep(inv.id).await.unwrap_err();
        assert!(matches!(manual_err, GatewayError::Conflict(_)));

        // 4) Second late payment arrives on same expired invoice -> manual_sweep sweeps & preserves EXPIRED
        let late_txid_2 = "f".repeat(64);
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "5",
                "result": {
                    "in": [
                        {
                            "txid": late_txid,
                            "amount": 1_000_000_000_000_u64,
                            "confirmations": 22,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 42 }
                        },
                        {
                            "txid": late_txid_2,
                            "amount": 250_000_000_000_u64,
                            "confirmations": 10,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 42 }
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
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "6",
                "result": {
                    "tx_hash_list": ["1".repeat(64)],
                    "amount_list": [249_900_000_000_u64],
                    "fee_list": [100_000_000_u64]
                }
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let manual_swept = scanner.manual_sweep(inv.id).await.unwrap();
        assert_eq!(manual_swept.status, InvoiceStatus::Expired);
        assert_eq!(
            manual_swept.sweep_tx_hashes,
            vec!["e".repeat(64), "1".repeat(64)]
        );
        assert_eq!(scanner.active_sweep_lock_count().await, 0);
    }

    #[tokio::test]
    async fn sweep_locks_map_prunes_entries_and_scans_old_expired_invoices_with_zero_monitor_days()
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;

        let mut old_expired = insertable_invoice(
            99,
            1_000_000_000_000,
            Some("http://127.0.0.1:9999/old".to_string()),
        );
        old_expired.status = InvoiceStatus::Expired;
        // Simulate an invoice created 365 days ago (> old 90-day cutoff)
        old_expired.created_at = Utc::now() - ChronoDuration::days(365);
        old_expired.expires_at = old_expired.created_at + ChronoDuration::hours(1);
        repo.insert_invoice(&old_expired).await.unwrap();

        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), true);
        assert_eq!(cfg.subaddress_monitor_days, 0);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg);

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": {
                    "in": [{
                        "txid": "a".repeat(64),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 12,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 99 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("sweep_all"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "2",
                "result": {
                    "tx_hash_list": ["b".repeat(64)],
                    "amount_list": [999_900_000_000_u64],
                    "fee_list": [100_000_000_u64]
                }
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let report = scanner.scan_once().await.unwrap();
        assert_eq!(report.invoices_scanned, 1);
        assert_eq!(report.invoices_swept, 1);
        assert_eq!(
            scanner.active_sweep_lock_count().await,
            0,
            "sweep_locks map must prune entry after sweep finishes"
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
