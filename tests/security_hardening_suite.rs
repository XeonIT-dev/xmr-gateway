//! Comprehensive security, financial-invariant, concurrency, fault-injection, and adversarial
//! regression test suite for `xmr-gateway` (XMR-022 through XMR-040).

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{Duration as ChronoDuration, Utc};
use http_body_util::BodyExt;
use tokio::sync::Barrier;
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, Request as WireRequest, Respond, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};

use xmr_gateway::{
    api::{
        AppState, build_router,
        dto::{
            CreateInvoiceResponse, HealthResponse, InvoiceStatusResponse,
            ResolveSweepIncidentResponse, RetryWebhookResponse, SweepInvoiceResponse,
        },
    },
    config::{
        Config, LogFormat, MoneroNetwork, WalletMode, encode_monero_base58_address,
        validate_monero_address,
    },
    db::{
        acquire_database_lock, checkpoint_and_close_pool, init_sqlite_pool,
        repository::{
            ApplyScanUpdateParams, CompleteSweepAttemptParams, InvoiceRepository,
            RecordSubaddressTransferParams, SweepAttemptStatus, SweepResolutionAction,
            WebhookDeliveryStatus,
        },
    },
    domain::{
        amount::Piconero,
        invoice::{
            Invoice, InvoiceStatus, ObservedTransfer, SubaddressTransferRecord,
            SubaddressTransferStatus, TransferClassification, WebhookEventType, build_monero_uri,
            evaluate_subaddress_transfers,
        },
    },
    error::GatewayError,
    rpc::{client::MoneroRpcClient, types::TransferEntry},
    security::url_policy::WebhookUrlPolicy,
    services::{
        scanner::{ScannerService, is_proven_pre_broadcast_rpc_error},
        webhook::{WebhookDispatcher, build_webhook_delivery},
    },
};

fn test_config(
    rpc_url: String,
    default_webhook: Option<String>,
    enable_auto_sweep: bool,
    req_conf: u64,
    settle_conf: u64,
) -> Arc<Config> {
    Arc::new(Config {
        host: "127.0.0.1".to_string(),
        port: 0,
        cors_allowed_origins: vec!["*".to_string()],
        database_url: "sqlite::memory:".to_string(),
        api_secret_key: "hardening-suite-api-secret-key-0123456789".to_string(),
        operator_api_key: None,
        webhook_secret: "hardening-suite-webhook-secret-0123456789".to_string(),
        default_webhook_url: default_webhook,
        allow_private_webhooks: true,
        require_https_webhooks: false,
        monero_network: MoneroNetwork::Mainnet,
        monero_rpc_url: rpc_url,
        monero_daemon_rpc_url: None,
        monero_remote_node: None,
        monero_daemon_rpc_user: None,
        monero_daemon_rpc_pass: None,
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
        required_confirmations: req_conf,
        settlement_confirmations: settle_conf,
        invoice_ttl_seconds: 3600,
        scan_interval_seconds: 10,
        scanner_subaddress_batch_size: xmr_gateway::config::DEFAULT_SCANNER_SUBADDRESS_BATCH_SIZE,
        webhook_poll_interval_seconds: 5,
        subaddress_monitor_days: 0,
        log_format: LogFormat::Json,
    })
}

fn make_invoice(address_index: u32, amount: u64, callback_url: Option<String>) -> Invoice {
    let now = Utc::now();
    let subaddr = encode_monero_base58_address(
        42,
        &[u8::try_from((address_index % 250) + 1).unwrap(); 32],
        &[0x55; 32],
        None,
    );
    let order_id = format!("suite-ord-{address_index}");
    Invoice {
        id: Uuid::new_v4(),
        order_id: order_id.clone(),
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
        callback_url,
        monero_uri: build_monero_uri(&subaddr, Piconero(amount), &order_id),
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
async fn regression_xmr_022_039_batch_tx_multi_invoice_and_multi_output_same_subaddress() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    // Create two distinct invoices on subaddress 1 and subaddress 2
    let inv1 = make_invoice(
        1,
        1_000_000_000_000,
        Some("http://127.0.0.1:9999/h1".to_string()),
    );
    let inv2 = make_invoice(
        2,
        2_000_000_000_000,
        Some("http://127.0.0.1:9999/h2".to_string()),
    );
    repo.insert_invoice(&inv1).await.unwrap();
    repo.insert_invoice(&inv2).await.unwrap();

    // XMR-039: verify TransferEntry with TWO outputs to the same subaddress sums instead of overwriting!
    let multi_same_subaddr: TransferEntry = serde_json::from_value(serde_json::json!({
        "txid": "e".repeat(64),
        "amount": 1_000_000_000_000_u64,
        "amounts": [400_000_000_000_u64, 600_000_000_000_u64],
        "confirmations": 12,
        "locked": false,
        "subaddr_index": { "major": 0, "minor": 1 },
        "subaddr_indices": [
            { "major": 0, "minor": 1 },
            { "major": 0, "minor": 1 }
        ]
    }))
    .unwrap();
    assert_eq!(
        multi_same_subaddr.subaddress_amounts(0).unwrap(),
        vec![(1, 1_000_000_000_000)]
    );

    // XMR-022: Single batch Monero txid paying BOTH invoice 1 (1.0 XMR) and invoice 2 (2.0 XMR)
    let batch_txid = "b".repeat(64);
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "in": [{
                    "txid": batch_txid,
                    "amount": 3_000_000_000_000_u64,
                    "amounts": [1_000_000_000_000_u64, 2_000_000_000_000_u64],
                    "confirmations": 12,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 1 },
                    "subaddr_indices": [
                        { "major": 0, "minor": 1 },
                        { "major": 0, "minor": 2 }
                    ]
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, false, 2, 10);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg);

    // First scan: Confirmed; Second scan: Settled (which reconciles both subaddress_transfers rows)
    scanner.scan_once().await.unwrap();
    scanner.scan_once().await.unwrap();

    let rows1 = repo
        .list_subaddress_transfers_for_invoice(inv1.id)
        .await
        .unwrap();
    let rows2 = repo
        .list_subaddress_transfers_for_invoice(inv2.id)
        .await
        .unwrap();

    assert_eq!(rows1.len(), 1);
    assert_eq!(rows2.len(), 1);
    assert_eq!(rows1[0].txid, batch_txid);
    assert_eq!(rows2[0].txid, batch_txid);
    assert_eq!(rows1[0].amount_piconero, Piconero(1_000_000_000_000));
    assert_eq!(rows2[0].amount_piconero, Piconero(2_000_000_000_000));
    assert_ne!(
        rows1[0].id, rows2[0].id,
        "surrogate keys must distinguish per-invoice rows for same txid"
    );
}

#[tokio::test]
async fn regression_xmr_023_sweep_snapshot_does_not_mark_later_overpayment_as_swept() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);

    let mut inv = make_invoice(
        11,
        1_000_000_000_000,
        Some("http://127.0.0.1:9999/snap".to_string()),
    );
    inv.status = InvoiceStatus::Settled;
    inv.received_piconero = Piconero(1_000_000_000_000);
    inv.confirmations = 10;
    inv.unlocked = true;
    repo.insert_invoice(&inv).await.unwrap();

    let t0 = Utc::now() - ChronoDuration::seconds(5);
    let tx_primary = "1".repeat(64);
    let tx_overpay = "2".repeat(64);

    // Record primary transfer before sweep prepare
    repo.record_subaddress_transfer(RecordSubaddressTransferParams {
        record: SubaddressTransferRecord {
            id: 0,
            txid: tx_primary.clone(),
            invoice_id: inv.id,
            address_index: inv.address_index,
            amount_piconero: Piconero(1_000_000_000_000),
            confirmations: 10,
            classification: TransferClassification::Expected,
            status: SubaddressTransferStatus::Active,
            swept: false,
            sweep_attempt_id: None,
            created_at: t0,
        },
        transfer: ObservedTransfer {
            txid: tx_primary.clone(),
            amount_piconero: Piconero(1_000_000_000_000),
            confirmations: 10,
            unlocked: true,
            double_spend_seen: false,
            in_pool: false,
            orphaned: false,
        },
        received_piconero: Piconero(1_000_000_000_000),
        confirmations: 10,
        unlocked: true,
        webhook: None,
        now: t0,
    })
    .await
    .unwrap();

    let cold = encode_monero_base58_address(18, &[0x11; 32], &[0x22; 32], None);
    let attempt = repo
        .create_prepared_sweep_attempt(
            inv.id,
            inv.address_index,
            &cold,
            t0 + ChronoDuration::seconds(1),
        )
        .await
        .unwrap();
    assert_eq!(attempt.snapshot_txids, vec![tx_primary.clone()]);

    // While sweep RPC is in-flight, a new OVERPAYMENT transfer arrives
    let t_later = t0 + ChronoDuration::seconds(2);
    repo.record_subaddress_transfer(RecordSubaddressTransferParams {
        record: SubaddressTransferRecord {
            id: 0,
            txid: tx_overpay.clone(),
            invoice_id: inv.id,
            address_index: inv.address_index,
            amount_piconero: Piconero(500_000_000_000),
            confirmations: 2,
            classification: TransferClassification::Overpayment,
            status: SubaddressTransferStatus::Active,
            swept: false,
            sweep_attempt_id: None,
            created_at: t_later,
        },
        transfer: ObservedTransfer {
            txid: tx_overpay.clone(),
            amount_piconero: Piconero(500_000_000_000),
            confirmations: 2,
            unlocked: false,
            double_spend_seen: false,
            in_pool: false,
            orphaned: false,
        },
        received_piconero: Piconero(1_500_000_000_000),
        confirmations: 10,
        unlocked: false,
        webhook: None,
        now: t_later,
    })
    .await
    .unwrap();

    // Complete first sweep attempt: ONLY tx_primary in snapshot_txids may become SWEPT!
    repo.complete_sweep_attempt(CompleteSweepAttemptParams {
        attempt_id: attempt.id,
        invoice_id: inv.id,
        attempt_status: SweepAttemptStatus::Submitted,
        sweep_tx_hashes: vec!["9".repeat(64)],
        sweep_amount_piconero: Piconero(999_900_000_000),
        sweep_fee_piconero: Piconero(100_000_000),
        webhook: None,
        now: t0 + ChronoDuration::seconds(3),
    })
    .await
    .unwrap();

    let rows = repo
        .list_subaddress_transfers_for_invoice(inv.id)
        .await
        .unwrap();
    let r_primary = rows.iter().find(|r| r.txid == tx_primary).unwrap();
    let r_overpay = rows.iter().find(|r| r.txid == tx_overpay).unwrap();

    assert!(r_primary.swept);
    assert_eq!(r_primary.status, SubaddressTransferStatus::Swept);
    assert_eq!(r_primary.sweep_attempt_id, Some(attempt.id));

    assert!(
        !r_overpay.swept,
        "concurrent/post-prepare overpayment MUST stay unswept (XMR-023)"
    );
    assert_eq!(r_overpay.status, SubaddressTransferStatus::Active);
    assert_eq!(r_overpay.sweep_attempt_id, None);
    // Overpayment has 2 confirmations (locked): not yet sweepable at 10 confs (`A3-2`),
    // while still tracked as an active unswept inflow at threshold 0.
    assert!(!repo.has_unswept_inflows(inv.id, 10).await.unwrap());
    assert!(repo.has_unswept_inflows(inv.id, 0).await.unwrap());
}

#[tokio::test]
async fn regression_xmr_024_blocks_auto_and_manual_sweep_until_settlement_confirmations() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    let inv = make_invoice(
        15,
        1_000_000_000_000,
        Some("http://127.0.0.1:9999/settle".to_string()),
    );
    repo.insert_invoice(&inv).await.unwrap();

    // SETTLEMENT_CONFIRMATIONS = 15 > MONERO_UNLOCK_CONFIRMATIONS = 10
    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 2, 15);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg);

    // Unlocked at 12 confirmations (12 >= 10, but 12 < SETTLEMENT_CONFIRMATIONS 15)
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
                    "subaddr_index": { "major": 0, "minor": 15 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("sweep_all"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_rpc)
        .await;

    // Two scans while at 12 confirmations MUST stay Confirmed and NEVER call sweep_all!
    scanner.scan_once().await.unwrap();
    let report = scanner.scan_once().await.unwrap();
    assert_eq!(report.invoices_swept, 0);
    let still_conf = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(still_conf.status, InvoiceStatus::Confirmed);

    // Manual sweep at 12 confirmations (< 15 settlement_confirmations) MUST fail with Conflict
    let manual_err = scanner.manual_sweep(inv.id).await.unwrap_err();
    assert!(manual_err.to_string().contains("SETTLED"));

    // Now advance to 15 confirmations -> SETTLED -> SWEPT
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
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 15 }
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
                "tx_hash_list": ["f".repeat(64)],
                "amount_list": [999_900_000_000_u64],
                "fee_list": [100_000_000_u64]
            }
        })))
        .expect(1)
        .mount(&mock_rpc)
        .await;

    let report2 = scanner.scan_once().await.unwrap();
    assert_eq!(report2.invoices_swept, 1);
    let final_inv = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(final_inv.status, InvoiceStatus::Swept);
}

#[tokio::test]
async fn regression_xmr_025_026_reorg_epoch_unblocks_recovery_webhooks_and_orphans_stale_txs() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;
    let mock_hook = MockServer::start().await;

    let hook_url = format!("{}/reorg-rec", mock_hook.uri());
    let inv = make_invoice(25, 1_000_000_000_000, Some(hook_url));
    repo.insert_invoice(&inv).await.unwrap();

    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, false, 2, 10);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());
    let dispatcher = WebhookDispatcher::new(
        repo.clone(),
        cfg.webhook_secret.clone(),
        false,
        Duration::from_secs(5),
        cfg.webhook_url_policy(),
    )
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/reorg-rec"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_hook)
        .await;

    // 1) tx_orphan confirms at 3 confs -> CONFIRMED (reorg_epoch = 0)
    let tx_orphan = "d".repeat(64);
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "in": [{
                    "txid": tx_orphan,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 3,
                    "double_spend_seen": false,
                    "locked": true,
                    "subaddr_index": { "major": 0, "minor": 25 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();
    let c0 = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(c0.status, InvoiceStatus::Confirmed);
    assert_eq!(c0.reorg_epoch, 0);

    // 2) Reorg drops tx_orphan out of chain -> REORGED (reorg_epoch bumps to 1, tx_orphan marked orphaned!)
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "2",
            "result": { "in": [], "pool": [] }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();
    let reorged = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(reorged.status, InvoiceStatus::Reorged);
    assert_eq!(reorged.reorg_epoch, 1);

    // Verify tx_orphan is still preserved in audit history AND marked orphaned=true (XMR-026)
    let transfers_after_reorg = repo.list_transfers_for_invoice(inv.id).await.unwrap();
    assert_eq!(transfers_after_reorg.len(), 1);
    assert_eq!(transfers_after_reorg[0].txid, tx_orphan);
    assert!(transfers_after_reorg[0].orphaned);

    // 3) New replacement tx_real mines to 3 confs -> recovery CONFIRMED (epoch 1!) -> then 10 confs -> SETTLED -> COMPLETED
    let tx_real = "e".repeat(64);
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "3",
            "result": {
                "in": [{
                    "txid": tx_real,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 10,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 25 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();
    scanner.scan_once().await.unwrap();

    dispatcher.process_due_deliveries().await.unwrap();
    let completed = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(completed.status, InvoiceStatus::Completed);

    let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
    let events: Vec<(WebhookEventType, WebhookDeliveryStatus)> =
        hooks.iter().map(|h| (h.event_type, h.status)).collect();
    assert_eq!(
        events,
        vec![
            (
                WebhookEventType::Confirmed,
                WebhookDeliveryStatus::Delivered
            ),
            (WebhookEventType::Reorged, WebhookDeliveryStatus::Delivered),
            (
                WebhookEventType::Confirmed,
                WebhookDeliveryStatus::Delivered
            ),
            (WebhookEventType::Settled, WebhookDeliveryStatus::Delivered),
        ]
    );
    assert!(hooks[0].dedupe_key.ends_with(":epoch:0"));
    assert!(hooks[2].dedupe_key.ends_with(":epoch:1"));
}

#[tokio::test]
async fn regression_xmr_027_slow_webhook_does_not_block_other_invoices_and_preserves_order() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);

    let slow_server = MockServer::start().await;
    let fast_server = MockServer::start().await;

    let inv_slow = make_invoice(
        27,
        1_000_000_000_000,
        Some(format!("{}/slow", slow_server.uri())),
    );
    let inv_fast = make_invoice(
        28,
        1_000_000_000_000,
        Some(format!("{}/fast", fast_server.uri())),
    );
    repo.insert_invoice(&inv_slow).await.unwrap();
    repo.insert_invoice(&inv_fast).await.unwrap();

    let t0 = Utc::now() - ChronoDuration::seconds(5);
    let slow_hook = build_webhook_delivery(
        "secret",
        &inv_slow,
        WebhookEventType::Confirmed,
        inv_slow.callback_url.as_deref().unwrap(),
        t0,
    )
    .unwrap();
    repo.apply_scan_update(ApplyScanUpdateParams {
        invoice_id: inv_slow.id,
        received_piconero: inv_slow.amount_piconero,
        confirmations: 2,
        unlocked: false,
        double_spend_seen: false,
        next_status: InvoiceStatus::Confirmed,
        transfers: Vec::new(),
        webhook: Some(slow_hook),
        now: t0,
    })
    .await
    .unwrap();

    // Two sequential webhooks for fast invoice
    let mut fast_c = inv_fast.clone();
    fast_c.status = InvoiceStatus::Confirmed;
    let fast_h1 = build_webhook_delivery(
        "secret",
        &fast_c,
        WebhookEventType::Confirmed,
        inv_fast.callback_url.as_deref().unwrap(),
        t0 + ChronoDuration::milliseconds(10),
    )
    .unwrap();
    repo.apply_scan_update(ApplyScanUpdateParams {
        invoice_id: inv_fast.id,
        received_piconero: inv_fast.amount_piconero,
        confirmations: 2,
        unlocked: false,
        double_spend_seen: false,
        next_status: InvoiceStatus::Confirmed,
        transfers: Vec::new(),
        webhook: Some(fast_h1),
        now: t0 + ChronoDuration::milliseconds(10),
    })
    .await
    .unwrap();

    let fast_h2 = build_webhook_delivery(
        "secret",
        &fast_c,
        WebhookEventType::Settled,
        inv_fast.callback_url.as_deref().unwrap(),
        t0 + ChronoDuration::milliseconds(20),
    )
    .unwrap();
    repo.apply_scan_update(ApplyScanUpdateParams {
        invoice_id: inv_fast.id,
        received_piconero: inv_fast.amount_piconero,
        confirmations: 10,
        unlocked: true,
        double_spend_seen: false,
        next_status: InvoiceStatus::Settled,
        transfers: Vec::new(),
        webhook: Some(fast_h2),
        now: t0 + ChronoDuration::milliseconds(20),
    })
    .await
    .unwrap();

    // Slow endpoint sleeps 450ms; fast endpoint completes concurrently
    let fast_done_ms = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    struct FastOrderResponder {
        start: Instant,
        fast_done_ms: Arc<AtomicUsize>,
    }
    impl Respond for FastOrderResponder {
        fn respond(&self, _request: &WireRequest) -> ResponseTemplate {
            let elapsed = usize::try_from(self.start.elapsed().as_millis()).unwrap_or(0);
            self.fast_done_ms.store(elapsed, Ordering::SeqCst);
            ResponseTemplate::new(200)
        }
    }

    Mock::given(method("POST"))
        .and(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(450)))
        .mount(&slow_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/fast"))
        .respond_with(FastOrderResponder {
            start,
            fast_done_ms: fast_done_ms.clone(),
        })
        .expect(2)
        .mount(&fast_server)
        .await;

    let dispatcher = WebhookDispatcher::new(
        repo.clone(),
        "secret".to_string(),
        false,
        Duration::from_secs(5),
        WebhookUrlPolicy {
            allow_private_webhooks: true,
            require_https_webhooks: false,
        },
    )
    .unwrap();

    let processed = dispatcher.process_due_deliveries().await.unwrap();
    assert_eq!(processed, 3);
    assert!(
        fast_done_ms.load(Ordering::SeqCst) < 350,
        "fast invoice must complete without waiting behind slow invoice 450ms HoL block (took {}ms)",
        fast_done_ms.load(Ordering::SeqCst)
    );

    let fast_hooks = repo.list_webhooks_for_invoice(inv_fast.id).await.unwrap();
    assert!(fast_hooks[0].delivered_at <= fast_hooks[1].delivered_at);
}

#[tokio::test]
async fn regression_xmr_028_029_033_038_api_hardening_endpoints_and_limits() {
    let mock_rpc = MockServer::start().await;
    let mock_hook = MockServer::start().await;
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);

    let cfg = test_config(
        format!("{}/json_rpc", mock_rpc.uri()),
        Some(format!("{}/hook", mock_hook.uri())),
        false,
        2,
        10,
    );
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
    let app = build_router(AppState {
        config: cfg.clone(),
        repo: repo.clone(),
        rpc,
        scanner,
    });

    // XMR-033: Public /health omits version, database, rpc, and auto_sweep_enabled when unauthenticated
    let unauth_health = app
        .clone()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauth_health.status(), StatusCode::OK);
    let unauth_bytes = unauth_health
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let unauth_text = String::from_utf8(unauth_bytes.to_vec()).unwrap();
    assert!(!unauth_text.contains("auto_sweep_enabled"));
    assert!(!unauth_text.contains("monero_rpc"));
    assert!(!unauth_text.contains("version"));
    let unauth_dto: HealthResponse = serde_json::from_str(&unauth_text).unwrap();
    assert_eq!(unauth_dto.status, "degraded");

    // XMR-033: Authenticated /health returns full diagnostics
    let auth_health = app
        .clone()
        .oneshot(
            Request::get("/health")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auth_health.status(), StatusCode::OK);
    let auth_dto: HealthResponse =
        serde_json::from_slice(&auth_health.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(auth_dto.service.as_deref(), Some("xmr-gateway"));
    assert!(auth_dto.monero_rpc.is_some());

    // XMR-038: Oversized request body (> 64 KiB) rejected with 413 Payload Too Large
    let huge_body = vec![b' '; 70 * 1024];
    let huge_resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/invoices")
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(huge_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(huge_resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // XMR-029: Create invoice with custom ttl_seconds=1800 -> idempotent on exact retry, 409 Conflict on ttl mismatch!
    let subaddr = encode_monero_base58_address(42, &[0x77; 32], &[0x88; 32], None);
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("create_address"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": { "address": subaddr, "address_index": 88 }
        })))
        .expect(1)
        .mount(&mock_rpc)
        .await;

    let req_1800 =
        r#"{"order_id":"ttl-order-1","amount_piconero":500000000000,"ttl_seconds":1800}"#;
    let create_r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/invoices")
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(req_1800))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_r.status(), StatusCode::CREATED);
    let created: CreateInvoiceResponse =
        serde_json::from_slice(&create_r.into_body().collect().await.unwrap().to_bytes()).unwrap();

    let idem_r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/invoices")
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(req_1800))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(idem_r.status(), StatusCode::OK);

    let ttl_conflict_r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/invoices")
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"order_id":"ttl-order-1","amount_piconero":500000000000,"ttl_seconds":900}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ttl_conflict_r.status(), StatusCode::CONFLICT);

    // XMR-028: Enqueue & fail a webhook delivery, then recover via authenticated POST /api/v1/webhooks/{id}/retry
    let inv = repo
        .get_invoice_by_id(created.invoice_id)
        .await
        .unwrap()
        .unwrap();
    let mut delivery = build_webhook_delivery(
        &cfg.webhook_secret,
        &inv,
        WebhookEventType::Confirmed,
        inv.callback_url.as_deref().unwrap(),
        Utc::now(),
    )
    .unwrap();
    delivery.max_attempts = 1;
    let delivery_id = delivery.id;

    repo.apply_scan_update(ApplyScanUpdateParams {
        invoice_id: inv.id,
        received_piconero: inv.amount_piconero,
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
        .respond_with(ResponseTemplate::new(502))
        .expect(1)
        .mount(&mock_hook)
        .await;

    let dispatcher = WebhookDispatcher::new(
        repo.clone(),
        cfg.webhook_secret.clone(),
        false,
        Duration::from_secs(5),
        cfg.webhook_url_policy(),
    )
    .unwrap();
    dispatcher.process_due_deliveries().await.unwrap();

    let failed = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
    assert_eq!(failed[0].status, WebhookDeliveryStatus::Failed);

    // Unauthorized retry rejected with 401
    let unauth_retry = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/webhooks/{delivery_id}/retry"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_retry.status(), StatusCode::UNAUTHORIZED);

    // Authorized retry resets status -> PENDING, attempts -> 0
    let ok_retry = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/webhooks/{delivery_id}/retry"))
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_retry.status(), StatusCode::OK);
    let retry_dto: RetryWebhookResponse =
        serde_json::from_slice(&ok_retry.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(retry_dto.retried_count, 1);
    assert_eq!(retry_dto.webhook_ids, vec![delivery_id]);

    // Deliver cleanly now that endpoint returns 200
    mock_hook.reset().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_hook)
        .await;
    dispatcher.process_due_deliveries().await.unwrap();

    // Retrying an already DELIVERED webhook returns 409 Conflict
    let conflict_retry = app
        .oneshot(
            Request::post(format!("/api/v1/webhooks/{delivery_id}/retry"))
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflict_retry.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn concurrency_race_between_scanner_and_manual_sweep_executes_sweep_all_once() {
    let mock_rpc = MockServer::start().await;
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);

    let mut inv = make_invoice(
        70,
        1_000_000_000_000,
        Some("http://127.0.0.1:9999/race".to_string()),
    );
    inv.status = InvoiceStatus::Settled;
    inv.received_piconero = Piconero(1_000_000_000_000);
    inv.confirmations = 12;
    inv.unlocked = true;
    inv.settled_at = Some(Utc::now());
    repo.insert_invoice(&inv).await.unwrap();

    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
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
                    "subaddr_index": { "major": 0, "minor": 70 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("sweep_all"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(80))
                .set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "2",
                    "result": {
                        "tx_hash_list": ["c".repeat(64)],
                        "amount_list": [999_900_000_000_u64],
                        "fee_list": [100_000_000_u64]
                    }
                })),
        )
        .expect(1)
        .mount(&mock_rpc)
        .await;

    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 2, 10);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
    let app = build_router(AppState {
        config: cfg.clone(),
        repo: repo.clone(),
        rpc,
        scanner: scanner.clone(),
    });

    let barrier = Arc::new(Barrier::new(2));
    let b1 = barrier.clone();
    let s1 = scanner.clone();
    let t_scan = tokio::spawn(async move {
        b1.wait().await;
        s1.scan_once().await
    });

    let b2 = barrier.clone();
    let key = cfg.api_secret_key.clone();
    let id = inv.id;
    let t_manual = tokio::spawn(async move {
        b2.wait().await;
        app.oneshot(
            Request::post(format!("/api/v1/invoices/{id}/sweep"))
                .header("X-API-Key", key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
    });

    let (scan_res, manual_res) = tokio::join!(t_scan, t_manual);
    assert!(scan_res.unwrap().is_ok());
    let manual_http = manual_res.unwrap().unwrap();
    assert!(
        manual_http.status() == StatusCode::OK || manual_http.status() == StatusCode::CONFLICT,
        "manual sweep must return either 200 (winner) or 409 (already swept cleanly), got {}",
        manual_http.status()
    );
    if manual_http.status() == StatusCode::OK {
        let dto: SweepInvoiceResponse =
            serde_json::from_slice(&manual_http.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(dto.sweep_tx_hashes, vec!["c".repeat(64)]);
    }

    let final_inv = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(final_inv.status, InvoiceStatus::Swept);
    assert_eq!(final_inv.sweep_tx_hashes, vec!["c".repeat(64)]);
}

#[test]
fn property_and_adversarial_monero_checksum_and_piconero_invariants() {
    // 1. Property test: flipping ANY single character in a checksum-valid Monero address MUST fail validation!
    let alphabet: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for net in [18_u8, 42_u8, 24_u8, 36_u8] {
        let valid = encode_monero_base58_address(net, &[0x42; 32], &[0x99; 32], None);
        assert!(validate_monero_address(&valid).is_ok());
        for pos in 0..valid.len() {
            let orig = valid.as_bytes()[pos];
            let replacement = if orig == alphabet[0] {
                alphabet[1]
            } else {
                alphabet[0]
            };
            let mut mutated = valid.clone().into_bytes();
            mutated[pos] = replacement;
            let mutated_str = String::from_utf8(mutated).unwrap();
            assert!(
                validate_monero_address(&mutated_str).is_err(),
                "mutating char at pos {pos} for net {net} unexpectedly passed checksum"
            );
        }
    }

    // 2. Property test: Piconero checked math and SQLite i64 bounds across boundary powers
    let max_i64 = u64::try_from(i64::MAX).unwrap();
    assert!(Piconero(max_i64).to_i64().is_ok());
    assert!(Piconero(max_i64 + 1).to_i64().is_err());
    assert!(Piconero(max_i64).checked_add(Piconero(1)).is_ok());
    assert!(Piconero(u64::MAX).checked_add(Piconero(1)).is_err());

    for exp in 0..=18_u32 {
        let amt = 10_u64.pow(exp);
        let p = Piconero(amt);
        let formatted = p.to_xmr_string();
        assert_eq!(Piconero::from_xmr_str(&formatted).unwrap(), p);
    }

    // 3. Domain invariant: double_spend_seen NEVER contributes to received_piconero even with 100 confs
    let eval = evaluate_subaddress_transfers(
        Piconero(1_000_000_000_000),
        &[ObservedTransfer {
            txid: "f".repeat(64),
            amount_piconero: Piconero(5_000_000_000_000),
            confirmations: 100,
            unlocked: true,
            double_spend_seen: true,
            in_pool: false,
            orphaned: false,
        }],
    );
    assert_eq!(eval.received_piconero, Piconero::ZERO);
    assert!(eval.double_spend_seen);
}

#[tokio::test]
async fn adversarial_malformed_http_inputs_never_panic_or_leak_500() {
    let mock_rpc = MockServer::start().await;
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, false, 2, 10);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
    let app = build_router(AppState {
        config: cfg.clone(),
        repo,
        rpc,
        scanner,
    });

    for bad_path in [
        "/api/v1/invoices/not-a-uuid",
        "/api/v1/invoices/%27%20OR%20%271%27=%271/sweep",
        "/api/v1/webhooks/not-a-uuid/retry",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::get(bad_path)
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.status().is_client_error());
    }

    for bad_body in [
        r#"{"order_id":"../etc/passwd","amount_piconero":1000}"#,
        r#"{"order_id":"valid-id","amount_piconero":0}"#,
        r#"{"order_id":"valid-id","amount_piconero":18446744073709551615}"#,
        r#"{"order_id":"valid-id","amount_piconero":1000,"callback_url":"javascript:alert(1)"}"#,
        r#"not valid json at all"#,
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/invoices")
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(bad_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status().is_client_error(),
            "expected 4xx on adversarial payload `{bad_body}`, got {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn sqlite_migration_idempotency_preserves_data_and_permissions() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let db_path = tmp_dir.path().join("reinit.db");
    let db_url = format!("sqlite://{}", db_path.display());

    let pool1 = init_sqlite_pool(&db_url).await.unwrap();
    let repo1 = InvoiceRepository::new(pool1.clone());
    let inv = make_invoice(99, 1_000_000_000_000, None);
    repo1.insert_invoice(&inv).await.unwrap();
    pool1.close().await;

    // Re-running init_sqlite_pool / sqlx::migrate! on existing populated DB must succeed cleanly
    let pool2 = init_sqlite_pool(&db_url).await.unwrap();
    let repo2 = InvoiceRepository::new(pool2.clone());
    let loaded = repo2.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(loaded.id, inv.id);
    assert_eq!(loaded.reorg_epoch, 0);
    pool2.close().await;
}

#[tokio::test]
async fn fault_injection_reorg_on_expired_invoice_and_overpayment_cleanup() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    let mut inv = make_invoice(
        101,
        1_000_000_000_000,
        Some("http://127.0.0.1:9999/fault".to_string()),
    );
    inv.status = InvoiceStatus::Expired;
    inv.expires_at = Utc::now() - ChronoDuration::minutes(30);
    repo.insert_invoice(&inv).await.unwrap();

    // Confirmed late payment arrives on expired invoice -> recorded ACTIVE in subaddress_transfers
    let late_tx = "7".repeat(64);
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "in": [{
                    "txid": late_tx,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 3,
                    "double_spend_seen": false,
                    "locked": true,
                    "subaddr_index": { "major": 0, "minor": 101 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, false, 2, 10);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg);

    scanner.scan_once().await.unwrap();
    assert!(!repo.has_unswept_inflows(inv.id, 10).await.unwrap());
    assert!(repo.has_unswept_inflows(inv.id, 0).await.unwrap());

    // Simulate deep reorg where late_tx is flagged double_spend_seen on terminal EXPIRED invoice (XMR-026)
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "2",
            "result": {
                "in": [{
                    "txid": late_tx,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 0,
                    "double_spend_seen": true,
                    "locked": true,
                    "subaddr_index": { "major": 0, "minor": 101 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();

    // Row MUST NOT be physically deleted; must be marked ORPHANED and excluded from unswept inflows!
    let ledger = repo
        .list_subaddress_transfers_for_invoice(inv.id)
        .await
        .unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].status, SubaddressTransferStatus::Orphaned);
    assert!(!repo.has_unswept_inflows(inv.id, 0).await.unwrap());
    assert!(!repo.has_unswept_inflows(inv.id, 10).await.unwrap());
}

#[tokio::test]
async fn regression_re_inclusion_of_orphaned_transfer_restores_active_status_and_balance() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    // Part A: Active invoice recovers previously ORPHANED transaction when re-included on canonical chain
    let inv = make_invoice(
        102,
        1_000_000_000_000,
        Some("http://127.0.0.1:9999/reinclusion".to_string()),
    );
    repo.insert_invoice(&inv).await.unwrap();

    let mut inv_expired = make_invoice(
        103,
        1_000_000_000_000,
        Some("http://127.0.0.1:9999/reinclusion-exp".to_string()),
    );
    inv_expired.status = InvoiceStatus::Expired;
    inv_expired.expires_at = Utc::now() - ChronoDuration::minutes(20);
    repo.insert_invoice(&inv_expired).await.unwrap();

    let tx_re = "a".repeat(64);
    let tx_late = "b".repeat(64);

    // 1) Both tx_re (3 confs) and tx_late (3 confs) arrive validly -> ACTIVE
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "in": [
                    {
                        "txid": tx_re,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 3,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 102 }
                    },
                    {
                        "txid": tx_late,
                        "amount": 500_000_000_000_u64,
                        "confirmations": 3,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 103 }
                    }
                ],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, false, 2, 10);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg);

    scanner.scan_once().await.unwrap();
    let inv_c = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(inv_c.status, InvoiceStatus::Confirmed);
    assert_eq!(inv_c.received_piconero, Piconero(1_000_000_000_000));
    // tx_late has 3 confirmations (locked): excluded from sweepable inflows at 10 confs (`A3-2`),
    // visible as active unswept inflow at threshold 0.
    assert!(!repo.has_unswept_inflows(inv_expired.id, 10).await.unwrap());
    assert!(repo.has_unswept_inflows(inv_expired.id, 0).await.unwrap());

    // 2) Temporary reorg drops BOTH transfers from RPC -> marked orphaned=true / status=ORPHANED, received=0
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "2",
            "result": { "in": [], "pool": [] }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();
    let inv_r = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(inv_r.status, InvoiceStatus::Reorged);
    assert_eq!(inv_r.received_piconero, Piconero::ZERO);
    assert!(repo.list_transfers_for_invoice(inv.id).await.unwrap()[0].orphaned);
    assert_eq!(
        repo.list_subaddress_transfers_for_invoice(inv.id)
            .await
            .unwrap()[0]
            .status,
        SubaddressTransferStatus::Orphaned
    );
    assert!(!repo.has_unswept_inflows(inv_expired.id, 0).await.unwrap());
    assert!(!repo.has_unswept_inflows(inv_expired.id, 10).await.unwrap());
    assert!(
        repo.list_transfers_for_invoice(inv_expired.id)
            .await
            .unwrap()[0]
            .orphaned
    );
    assert_eq!(
        repo.list_subaddress_transfers_for_invoice(inv_expired.id)
            .await
            .unwrap()[0]
            .status,
        SubaddressTransferStatus::Orphaned
    );

    // 3) Canonical chain re-includes tx_re (5 confs) and tx_late (10 confs) cleanly (double_spend_seen=false)
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
                        "txid": tx_re,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 5,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 102 }
                    },
                    {
                        "txid": tx_late,
                        "amount": 500_000_000_000_u64,
                        "confirmations": 10,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 103 }
                    }
                ],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();

    let inv_restored = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(inv_restored.status, InvoiceStatus::Confirmed);
    assert_eq!(inv_restored.received_piconero, Piconero(1_000_000_000_000));
    assert!(!repo.list_transfers_for_invoice(inv.id).await.unwrap()[0].orphaned);
    let sub_re = repo
        .list_subaddress_transfers_for_invoice(inv.id)
        .await
        .unwrap();
    assert_eq!(sub_re.len(), 1);
    assert_eq!(sub_re[0].status, SubaddressTransferStatus::Active);

    assert!(
        !repo
            .list_transfers_for_invoice(inv_expired.id)
            .await
            .unwrap()[0]
            .orphaned
    );
    let sub_late = repo
        .list_subaddress_transfers_for_invoice(inv_expired.id)
        .await
        .unwrap();
    assert_eq!(sub_late.len(), 1);
    assert_eq!(sub_late[0].status, SubaddressTransferStatus::Active);
    assert_eq!(sub_late[0].confirmations, 10);
    assert!(repo.has_unswept_inflows(inv_expired.id, 10).await.unwrap());
}

#[tokio::test]
async fn regression_deep_reorg_after_settled_and_confirmation_buffer_policy() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    // 1) View-Only invoice configured with REQUIRED_CONFIRMATIONS=10 and high-value buffer SETTLEMENT_CONFIRMATIONS=15
    let inv_vo = make_invoice(
        104,
        1_000_000_000_000,
        Some("http://127.0.0.1:9999/deep-reorg-vo".to_string()),
    );
    repo.insert_invoice(&inv_vo).await.unwrap();

    let cfg_vo = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, false, 10, 15);
    let rpc_vo = MoneroRpcClient::new(&cfg_vo.monero_rpc_url, None, None).unwrap();
    let scanner_vo = ScannerService::new(repo.clone(), rpc_vo, cfg_vo);

    // Reach CONFIRMED at 10 confs (still below SETTLEMENT_CONFIRMATIONS=15)
    let tx_vo = "c".repeat(64);
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "in": [{
                    "txid": tx_vo,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 10,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 104 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner_vo.scan_once().await.unwrap();
    assert_eq!(
        repo.get_invoice_by_id(inv_vo.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        InvoiceStatus::Confirmed
    );

    // Reach SETTLED at 15 confs
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "2",
            "result": {
                "in": [{
                    "txid": tx_vo,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 104 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner_vo.scan_once().await.unwrap();
    assert_eq!(
        repo.get_invoice_by_id(inv_vo.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        InvoiceStatus::Settled
    );

    // Deep reorg drops confirmations from 15 to 12 (< SETTLEMENT_CONFIRMATIONS=15) while SETTLED (not yet COMPLETED/SWEPT)
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "3",
            "result": {
                "in": [{
                    "txid": tx_vo,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 12,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 104 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner_vo.scan_once().await.unwrap();
    let after_deep_reorg = repo.get_invoice_by_id(inv_vo.id).await.unwrap().unwrap();
    assert_eq!(after_deep_reorg.status, InvoiceStatus::Reorged);
    assert_eq!(after_deep_reorg.reorg_epoch, 1);

    let hooks = repo.list_webhooks_for_invoice(inv_vo.id).await.unwrap();
    let events: Vec<WebhookEventType> = hooks.iter().map(|w| w.event_type).collect();
    assert_eq!(
        events,
        vec![
            WebhookEventType::Confirmed,
            WebhookEventType::Settled,
            WebhookEventType::Reorged,
        ]
    );

    // 2) Post-SWEPT deep reorg safety: terminal SWEPT invoice must not panic or issue blind duplicate sweep_all
    let mock_hot_rpc = MockServer::start().await;
    let mut inv_swept = make_invoice(
        105,
        1_000_000_000_000,
        Some("http://127.0.0.1:9999/post-swept-reorg".to_string()),
    );
    inv_swept.status = InvoiceStatus::Settled;
    inv_swept.received_piconero = Piconero(1_000_000_000_000);
    inv_swept.confirmations = 15;
    inv_swept.unlocked = true;
    repo.insert_invoice(&inv_swept).await.unwrap();

    let attempt = repo
        .create_prepared_sweep_attempt(
            inv_swept.id,
            inv_swept.address_index,
            &encode_monero_base58_address(18, &[0x11; 32], &[0x22; 32], None),
            Utc::now(),
        )
        .await
        .unwrap();
    repo.complete_sweep_attempt(CompleteSweepAttemptParams {
        attempt_id: attempt.id,
        invoice_id: inv_swept.id,
        attempt_status: SweepAttemptStatus::Submitted,
        sweep_tx_hashes: vec!["d".repeat(64)],
        sweep_amount_piconero: Piconero(999_900_000_000),
        sweep_fee_piconero: Piconero(100_000_000),
        webhook: None,
        now: Utc::now(),
    })
    .await
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "4",
            "result": {
                "in": [{
                    "txid": "e".repeat(64),
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 0,
                    "double_spend_seen": true,
                    "locked": true,
                    "subaddr_index": { "major": 0, "minor": 105 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_hot_rpc)
        .await;

    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "5",
            "result": {
                "out": [{
                    "txid": "d".repeat(64),
                    "amount": 999_900_000_000_u64,
                    "fee": 100_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "subaddr_index": { "major": 0, "minor": 105 }
                }],
                "pending": []
            }
        })))
        .mount(&mock_hot_rpc)
        .await;

    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("sweep_all"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_hot_rpc)
        .await;

    let cfg_hot = test_config(
        format!("{}/json_rpc", mock_hot_rpc.uri()),
        None,
        true,
        10,
        15,
    );
    let rpc_hot = MoneroRpcClient::new(&cfg_hot.monero_rpc_url, None, None).unwrap();
    let scanner_hot = ScannerService::new(repo.clone(), rpc_hot, cfg_hot);

    let report = scanner_hot.scan_once().await.unwrap();
    assert_eq!(report.invoices_swept, 0);
    let post = repo.get_invoice_by_id(inv_swept.id).await.unwrap().unwrap();
    assert_eq!(post.status, InvoiceStatus::Swept);
}

#[tokio::test]
async fn regression_reorg_after_completed_emits_reorged_webhook_and_recovers() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;
    let mock_webhook = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/merchant-hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_webhook)
        .await;

    let hook_url = format!("{}/merchant-hook", mock_webhook.uri());
    let inv = make_invoice(106, 1_000_000_000_000, Some(hook_url));
    repo.insert_invoice(&inv).await.unwrap();

    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, false, 10, 15);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());
    let dispatcher = WebhookDispatcher::new(
        repo.clone(),
        "secret".to_string(),
        false,
        Duration::from_secs(5),
        WebhookUrlPolicy {
            allow_private_webhooks: true,
            require_https_webhooks: false,
        },
    )
    .unwrap();

    let tx_vo = "1".repeat(64);

    // 1) Reach CONFIRMED (10 confs) -> SETTLED (15 confs) -> deliver SETTLED webhook -> COMPLETED
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "in": [{
                    "txid": tx_vo,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 10,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 106 }
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

    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "2",
            "result": {
                "in": [{
                    "txid": tx_vo,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 106 }
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
        InvoiceStatus::Settled
    );

    dispatcher.process_due_deliveries().await.unwrap();
    dispatcher.process_due_deliveries().await.unwrap();
    let completed = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(completed.status, InvoiceStatus::Completed);
    assert_eq!(completed.reorg_epoch, 0);

    // 2) Deep reorg AFTER COMPLETED: chain forks and confirmations fall back to 0 / disappeared
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "3",
            "result": { "in": [], "pool": [] }
        })))
        .mount(&mock_rpc)
        .await;
    scanner.scan_once().await.unwrap();

    let reorged = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(reorged.status, InvoiceStatus::Reorged);
    assert_eq!(reorged.reorg_epoch, 1);

    dispatcher.process_due_deliveries().await.unwrap();

    // 3) Canonical chain recovers cleanly: REORGED -> CONFIRMED (10 confs) -> SETTLED (15 confs) -> COMPLETED
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "4",
            "result": {
                "in": [{
                    "txid": tx_vo,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 106 }
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
    dispatcher.process_due_deliveries().await.unwrap();
    let recovered = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(recovered.status, InvoiceStatus::Completed);
    assert_eq!(recovered.reorg_epoch, 1);

    let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
    let events: Vec<WebhookEventType> = hooks.iter().map(|w| w.event_type).collect();
    assert_eq!(
        events,
        vec![
            WebhookEventType::Confirmed,
            WebhookEventType::Settled,
            WebhookEventType::Reorged,
            WebhookEventType::Confirmed,
            WebhookEventType::Settled,
        ]
    );
    assert!(
        hooks
            .iter()
            .all(|w| w.status == WebhookDeliveryStatus::Delivered),
        "all epoch-0 and epoch-1 recovery webhooks must deliver cleanly"
    );
}

#[tokio::test]
async fn regression_confirmed_sweep_reorg_detected_escalates_and_blocks_auto_resweep() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    let inv = make_invoice(
        107,
        1_000_000_000_000,
        Some("http://127.0.0.1:9999/sweep-reorg-hook".to_string()),
    );
    repo.insert_invoice(&inv).await.unwrap();

    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());

    let in_txid = "2".repeat(64);
    let sweep_txid = "3".repeat(64);

    // 1) Incoming payment matures to CONFIRMED (15) -> SETTLED (15) -> sweep_all executes once
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "in": [{
                    "txid": in_txid,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 107 }
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
                "tx_hash_list": [sweep_txid],
                "amount_list": [999_900_000_000_u64],
                "fee_list": [100_000_000_u64]
            }
        })))
        .expect(1)
        .mount(&mock_rpc)
        .await;

    // Tick 1: CONFIRMED -> Tick 2: SETTLED + sweep_all
    scanner.scan_once().await.unwrap();
    assert_eq!(
        repo.get_invoice_by_id(inv.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        InvoiceStatus::Confirmed
    );
    let r2 = scanner.scan_once().await.unwrap();
    assert_eq!(r2.invoices_swept, 1);
    assert_eq!(
        repo.get_invoice_by_id(inv.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        InvoiceStatus::Swept
    );

    // Attempt begins as SUBMITTED
    let a1 = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
    assert_eq!(a1.len(), 1);
    assert_eq!(a1[0].status, SweepAttemptStatus::Submitted);

    // 2) Outgoing sweep at 5 confs (< settlement_confirmations=15) MUST stay SUBMITTED (non-final)
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "3",
            "result": {
                "in": [{
                    "txid": in_txid,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 107 }
                }],
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
                    "txid": sweep_txid,
                    "amount": 999_900_000_000_u64,
                    "fee": 100_000_000_u64,
                    "confirmations": 5,
                    "double_spend_seen": false,
                    "subaddr_index": { "major": 0, "minor": 107 }
                }],
                "pending": []
            }
        })))
        .mount(&mock_rpc)
        .await;
    scanner.scan_once().await.unwrap();
    let a2 = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
    assert_eq!(a2[0].status, SweepAttemptStatus::Submitted);

    // 3) Outgoing sweep reaches 15 confs (>= settlement_confirmations) -> CONFIRMED
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "5",
            "result": {
                "in": [{
                    "txid": in_txid,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 20,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 107 }
                }],
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
            "id": "6",
            "result": {
                "out": [{
                    "txid": sweep_txid,
                    "amount": 999_900_000_000_u64,
                    "fee": 100_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "subaddr_index": { "major": 0, "minor": 107 }
                }],
                "pending": []
            }
        })))
        .mount(&mock_rpc)
        .await;
    scanner.scan_once().await.unwrap();
    let a3 = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
    assert_eq!(a3[0].status, SweepAttemptStatus::Confirmed);

    // 4) Deep reorg invalidates previously CONFIRMED sweep: disappears from out/pending!
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "7",
            "result": {
                "in": [{
                    "txid": in_txid,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 20,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 107 }
                }],
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
            "id": "8",
            "result": { "out": [], "pending": [] }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("sweep_all"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_rpc)
        .await;

    let reorg_report = scanner.scan_once().await.unwrap();
    assert_eq!(reorg_report.invoices_swept, 0);

    let escalated_inv = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(escalated_inv.status, InvoiceStatus::Reorged);
    assert_eq!(escalated_inv.reorg_epoch, 1);
    assert!(
        escalated_inv
            .last_sweep_error
            .as_deref()
            .is_some_and(|e| e.starts_with("SWEEP_REORG_DETECTED:"))
    );

    let a4 = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
    assert_eq!(a4[0].status, SweepAttemptStatus::Reorged);
    assert!(
        a4[0]
            .error_message
            .as_deref()
            .is_some_and(|e| e.starts_with("SWEEP_REORG_DETECTED:"))
    );

    let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
    assert!(
        hooks
            .iter()
            .any(|w| w.event_type == WebhookEventType::Reorged)
    );

    // 5) Subsequent scan cycles and manual_sweep MUST keep auto re-sweep blocked!
    let next_report = scanner.scan_once().await.unwrap();
    assert_eq!(next_report.invoices_swept, 0);
    assert_eq!(
        repo.get_invoice_by_id(inv.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        InvoiceStatus::Reorged
    );

    let manual_err = scanner.manual_sweep(inv.id).await.unwrap_err();
    assert!(matches!(manual_err, GatewayError::Conflict(_)));

    // 6) Verify double_spend_seen = true on a RECONCILED sweep attempt also triggers escalation
    let inv2 = make_invoice(108, 1_000_000_000_000, None);
    let mut inv2_settled = inv2.clone();
    inv2_settled.status = InvoiceStatus::Settled;
    inv2_settled.received_piconero = Piconero(1_000_000_000_000);
    inv2_settled.confirmations = 15;
    inv2_settled.unlocked = true;
    repo.insert_invoice(&inv2_settled).await.unwrap();

    let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();
    let att2 = repo
        .create_prepared_sweep_attempt(
            inv2_settled.id,
            inv2_settled.address_index,
            cold_addr,
            Utc::now(),
        )
        .await
        .unwrap();
    let sweep2_txid = "4".repeat(64);
    repo.complete_sweep_attempt(CompleteSweepAttemptParams {
        attempt_id: att2.id,
        invoice_id: inv2_settled.id,
        attempt_status: SweepAttemptStatus::Reconciled,
        sweep_tx_hashes: vec![sweep2_txid.clone()],
        sweep_amount_piconero: Piconero(999_900_000_000),
        sweep_fee_piconero: Piconero(100_000_000),
        webhook: None,
        now: Utc::now(),
    })
    .await
    .unwrap();

    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "9",
            "result": {
                "out": [{
                    "txid": sweep2_txid,
                    "amount": 999_900_000_000_u64,
                    "fee": 100_000_000_u64,
                    "confirmations": 1,
                    "double_spend_seen": true,
                    "subaddr_index": { "major": 0, "minor": 108 }
                }],
                "pending": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.reconcile_in_flight_sweeps().await.unwrap();
    let inv2_after = repo
        .get_invoice_by_id(inv2_settled.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inv2_after.status, InvoiceStatus::Reorged);
    let att2_after = repo
        .list_sweep_attempts_for_invoice(inv2_settled.id)
        .await
        .unwrap();
    assert_eq!(att2_after[0].status, SweepAttemptStatus::Reorged);
    assert!(
        att2_after[0]
            .error_message
            .as_deref()
            .is_some_and(|e| e.contains("double_spend_seen=true"))
    );
}

#[tokio::test]
async fn regression_double_spend_seen_in_mempool_recovers_when_canonically_mined() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    let inv = make_invoice(109, 1_000_000_000_000, None);
    repo.insert_invoice(&inv).await.unwrap();

    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, false, 10, 10);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg);

    let tx_ds = "5".repeat(64);

    // 1) Mempool false-positive / race flags double_spend_seen = true at 0 confs
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "in": [],
                "pool": [{
                    "txid": tx_ds,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 0,
                    "double_spend_seen": true,
                    "subaddr_index": { "major": 0, "minor": 109 }
                }]
            }
        })))
        .mount(&mock_rpc)
        .await;
    scanner.scan_once().await.unwrap();

    let inv_mempool_ds = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert!(inv_mempool_ds.double_spend_seen);
    assert_eq!(inv_mempool_ds.received_piconero, Piconero::ZERO);
    let tr1 = repo.list_transfers_for_invoice(inv.id).await.unwrap();
    assert_eq!(tr1.len(), 1);
    assert!(tr1[0].double_spend_seen);
    assert!(tr1[0].orphaned);

    // 2) Subsequent 0-conf mempool poll omitting double_spend_seen MUST remain conservative!
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
                    "txid": tx_ds,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 0,
                    "double_spend_seen": false,
                    "subaddr_index": { "major": 0, "minor": 109 }
                }]
            }
        })))
        .mount(&mock_rpc)
        .await;
    scanner.scan_once().await.unwrap();
    let tr2 = repo.list_transfers_for_invoice(inv.id).await.unwrap();
    assert!(
        tr2[0].double_spend_seen,
        "0-conf mempool update must preserve double_spend_seen=true until canonical mining"
    );
    assert!(tr2[0].orphaned);

    // 3) Canonically mined (confirmations=10, double_spend_seen=false) clears flag and confirms invoice
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "3",
            "result": {
                "in": [{
                    "txid": tx_ds,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 10,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 109 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;
    scanner.scan_once().await.unwrap();

    let inv_recovered = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert!(!inv_recovered.double_spend_seen);
    assert_eq!(inv_recovered.received_piconero, Piconero(1_000_000_000_000));
    assert_eq!(inv_recovered.status, InvoiceStatus::Confirmed);

    let tr3 = repo.list_transfers_for_invoice(inv.id).await.unwrap();
    assert!(!tr3[0].double_spend_seen);
    assert!(!tr3[0].orphaned);

    let sub3 = repo
        .list_subaddress_transfers_for_invoice(inv.id)
        .await
        .unwrap();
    assert_eq!(sub3.len(), 1);
    assert_eq!(sub3[0].status, SubaddressTransferStatus::Active);

    // 4) Also verify ORPHANED -> ACTIVE restoration when previously confirmed tx had temporary
    // double_spend_seen in mempool during shallow reorg, then canonically re-mines.
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "4",
            "result": {
                "in": [],
                "pool": [{
                    "txid": tx_ds,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 0,
                    "double_spend_seen": true,
                    "subaddr_index": { "major": 0, "minor": 109 }
                }]
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
    assert_eq!(
        repo.list_subaddress_transfers_for_invoice(inv.id)
            .await
            .unwrap()[0]
            .status,
        SubaddressTransferStatus::Orphaned
    );

    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "5",
            "result": {
                "in": [{
                    "txid": tx_ds,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 10,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 109 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;
    scanner.scan_once().await.unwrap();

    let inv_reconfirmed = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(inv_reconfirmed.status, InvoiceStatus::Confirmed);
    assert!(!inv_reconfirmed.double_spend_seen);
    let sub_final = repo
        .list_subaddress_transfers_for_invoice(inv.id)
        .await
        .unwrap();
    assert_eq!(sub_final[0].status, SubaddressTransferStatus::Active);
    let tr_final = repo.list_transfers_for_invoice(inv.id).await.unwrap();
    assert!(!tr_final[0].double_spend_seen);
    assert!(!tr_final[0].orphaned);
}

#[tokio::test]
async fn regression_xmr_041_sweep_incident_resolution_enforces_rpc_check_and_unblocks_resweep() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;
    let mock_daemon_rpc = MockServer::start().await;

    let inv = make_invoice(110, 1_000_000_000_000, None);
    repo.insert_invoice(&inv).await.unwrap();

    let mut cfg_val =
        (*test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15)).clone();
    cfg_val.monero_daemon_rpc_url = Some(format!("{}/json_rpc", mock_daemon_rpc.uri()));
    let cfg = Arc::new(cfg_val);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
    let app = build_router(AppState {
        config: cfg.clone(),
        repo: repo.clone(),
        rpc,
        scanner: scanner.clone(),
    });

    let in_txid = "6".repeat(64);
    let old_sweep_tx = "7".repeat(64);
    let new_sweep_tx = "8".repeat(64);

    // 1) Progress invoice through CONFIRMED -> SETTLED -> SWEPT
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "in": [{
                    "txid": in_txid,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 110 }
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
                "tx_hash_list": [old_sweep_tx],
                "amount_list": [999_900_000_000_u64],
                "fee_list": [100_000_000_u64]
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();
    scanner.scan_once().await.unwrap();
    assert_eq!(
        repo.get_invoice_by_id(inv.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        InvoiceStatus::Swept
    );
    assert_eq!(
        repo.list_subaddress_transfers_for_invoice(inv.id)
            .await
            .unwrap()[0]
            .status,
        SubaddressTransferStatus::Swept
    );

    // 2) Outbound sweep tx vanishes -> SWEEP_REORG_DETECTED locks invoice & marks attempt REORGED
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "3",
            "result": { "out": [], "pending": [], "pool": [] }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "4",
            "result": {
                "in": [{
                    "txid": in_txid,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 20,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 110 }
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
    let attempts_reorged = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
    assert_eq!(attempts_reorged.len(), 1);
    assert_eq!(attempts_reorged[0].status, SweepAttemptStatus::Reorged);

    // Verify manual /sweep is blocked while incident is unresolved
    let blocked_sweep_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep", inv.id))
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocked_sweep_resp.status(), StatusCode::CONFLICT);

    // Verify unauthenticated /sweep/resolve fails 401 and empty operator_note fails 400
    let unauth_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"check"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    let blank_note_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"   "}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blank_note_resp.status(), StatusCode::BAD_REQUEST);

    // 3) RPC still reports old_sweep_tx alive in pending -> allow_resweep MUST reject with 409 Conflict!
    mock_rpc.reset().await;
    mock_daemon_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_wallet_info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "wh1",
            "result": { "height": 3_400_100_u64 }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "di1",
            "result": {
                "height": 3_400_100_u64,
                "target_height": 3_400_100_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": false,
                "status": "OK",
                "nettype": "mainnet"
            }
        })))
        .mount(&mock_daemon_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "5",
            "result": {
                "out": [],
                "pending": [{
                    "txid": old_sweep_tx,
                    "amount": 999_900_000_000_u64,
                    "fee": 100_000_000_u64,
                    "confirmations": 0,
                    "double_spend_seen": false,
                    "subaddr_index": { "major": 0, "minor": 110 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    let live_conflict_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"operator attempting early unlock"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(live_conflict_resp.status(), StatusCode::CONFLICT);
    assert_eq!(
        repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap()[0].status,
        SweepAttemptStatus::Reorged
    );

    // 4) Old sweep tx confirmed dead in RPC (absent from out/pending/pool) -> allow_resweep succeeds!
    mock_rpc.reset().await;
    mock_daemon_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_wallet_info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "wh2",
            "result": { "height": 3_400_105_u64 }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "di2",
            "result": {
                "height": 3_400_105_u64,
                "target_height": 3_400_105_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": false,
                "status": "OK",
                "nettype": "mainnet"
            }
        })))
        .mount(&mock_daemon_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "6",
            "result": { "out": [], "pending": [], "pool": [] }
        })))
        .mount(&mock_rpc)
        .await;

    let resolve_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"confirmed old sweep tx absent in daemon mempool and chain"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resolve_resp.status(), StatusCode::OK);
    let resolved_dto: ResolveSweepIncidentResponse =
        serde_json::from_slice(&resolve_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(
        resolved_dto.resolved_attempt.status,
        SweepAttemptStatus::Failed
    );
    assert_eq!(
        resolved_dto.resolved_attempt.resolution_action,
        Some(SweepResolutionAction::AllowResweep)
    );
    assert!(resolved_dto.resolved_attempt.resolved_at.is_some());
    assert!(
        resolved_dto
            .resolved_attempt
            .resolution_note
            .as_deref()
            .is_some_and(|n| {
                n.starts_with("confirmed old sweep tx absent in daemon mempool and chain")
                    && n.contains("wallet_height=3400105")
                    && n.contains("daemon_height=3400105")
                    && n.contains(&old_sweep_tx)
            })
    );

    // Audit row retained without deletion and subaddress_transfers reverted to ACTIVE (unswept)
    let attempts_after_resolve = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
    assert_eq!(attempts_after_resolve.len(), 1);
    assert_eq!(attempts_after_resolve[0].status, SweepAttemptStatus::Failed);
    let sub_after_resolve = repo
        .list_subaddress_transfers_for_invoice(inv.id)
        .await
        .unwrap();
    assert_eq!(sub_after_resolve.len(), 1);
    assert!(!sub_after_resolve[0].swept);
    assert_eq!(
        sub_after_resolve[0].status,
        SubaddressTransferStatus::Active
    );

    // GET /api/v1/invoices/{id} exposes sweep_attempts audit history
    let status_resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/invoices/{}", inv.id))
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_resp.status(), StatusCode::OK);
    let status_dto: InvoiceStatusResponse =
        serde_json::from_slice(&status_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(status_dto.sweep_attempts.len(), 1);
    assert_eq!(
        status_dto.sweep_attempts[0].resolution_action,
        Some(SweepResolutionAction::AllowResweep)
    );

    // 5) Subsequent manual sweep executes cleanly with new_sweep_tx!
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "7",
            "result": {
                "in": [{
                    "txid": in_txid,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 20,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 110 }
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
            "id": "8",
            "result": {
                "tx_hash_list": [new_sweep_tx],
                "amount_list": [999_900_000_000_u64],
                "fee_list": [100_000_000_u64]
            }
        })))
        .expect(1)
        .mount(&mock_rpc)
        .await;

    let resweep_resp = app
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep", inv.id))
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resweep_resp.status(), StatusCode::OK);
    let resweep_dto: SweepInvoiceResponse =
        serde_json::from_slice(&resweep_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(resweep_dto.status, InvoiceStatus::Swept);
    assert_eq!(resweep_dto.sweep_tx_hashes, vec![new_sweep_tx]);
    assert_eq!(resweep_dto.sweep_amount_piconero, 999_900_000_000);

    let all_attempts = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
    assert_eq!(all_attempts.len(), 2);
    assert_eq!(all_attempts[0].status, SweepAttemptStatus::Failed);
    assert_eq!(all_attempts[1].status, SweepAttemptStatus::Submitted);
}

#[tokio::test]
async fn regression_xmr_042_expired_invoice_late_payment_sweep_reorg_emits_webhook_preserving_expired_status()
 {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;
    let mock_webhook = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/expired-sweep-hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_webhook)
        .await;

    let hook_url = format!("{}/expired-sweep-hook", mock_webhook.uri());
    let mut expired_inv = make_invoice(111, 1_000_000_000_000, Some(hook_url));
    expired_inv.status = InvoiceStatus::Expired;
    expired_inv.expires_at = Utc::now() - ChronoDuration::minutes(15);
    repo.insert_invoice(&expired_inv).await.unwrap();

    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());
    let dispatcher = WebhookDispatcher::new(
        repo.clone(),
        cfg.webhook_secret.clone(),
        true,
        Duration::from_secs(5),
        WebhookUrlPolicy {
            allow_private_webhooks: true,
            require_https_webhooks: false,
        },
    )
    .unwrap();

    let late_in_tx = "9".repeat(64);
    let late_sweep_tx = "a".repeat(64);

    // 1) Late payment arrives on EXPIRED invoice and is swept (preserving EXPIRED status)
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "in": [{
                    "txid": late_in_tx,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 111 }
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
                "tx_hash_list": [late_sweep_tx],
                "amount_list": [999_900_000_000_u64],
                "fee_list": [100_000_000_u64]
            }
        })))
        .expect(1)
        .mount(&mock_rpc)
        .await;

    let report1 = scanner.scan_once().await.unwrap();
    assert_eq!(report1.invoices_swept, 1);

    let after_sweep = repo
        .get_invoice_by_id(expired_inv.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_sweep.status, InvoiceStatus::Expired);
    assert_eq!(after_sweep.reorg_epoch, 0);
    let att_before = repo
        .list_sweep_attempts_for_invoice(expired_inv.id)
        .await
        .unwrap();
    assert_eq!(att_before.len(), 1);
    assert_eq!(att_before[0].status, SweepAttemptStatus::Submitted);

    // Deliver LATE_PAYMENT and SWEPT webhooks
    dispatcher.process_due_deliveries().await.unwrap();
    dispatcher.process_due_deliveries().await.unwrap();

    // 2) Simulate reorg / disappearance of the outgoing sweep tx on the EXPIRED invoice
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "3",
            "result": {
                "in": [{
                    "txid": late_in_tx,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 111 }
                }],
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
            "result": { "out": [], "pending": [] }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("sweep_all"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_rpc)
        .await;

    let report2 = scanner.scan_once().await.unwrap();
    assert_eq!(report2.invoices_swept, 0);

    // 3) Verify EXPIRED status is preserved, reorg_epoch incremented, and REORGED webhook delivered
    let after_reorg = repo
        .get_invoice_by_id(expired_inv.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_reorg.status, InvoiceStatus::Expired);
    assert_eq!(after_reorg.reorg_epoch, 1);
    assert!(
        after_reorg
            .last_sweep_error
            .as_deref()
            .is_some_and(|e| e.starts_with("SWEEP_REORG_DETECTED:"))
    );

    let att_after = repo
        .list_sweep_attempts_for_invoice(expired_inv.id)
        .await
        .unwrap();
    assert_eq!(att_after[0].status, SweepAttemptStatus::Reorged);

    dispatcher.process_due_deliveries().await.unwrap();

    let hooks = repo
        .list_webhooks_for_invoice(expired_inv.id)
        .await
        .unwrap();
    let events: Vec<WebhookEventType> = hooks.iter().map(|w| w.event_type).collect();
    assert_eq!(
        events,
        vec![
            WebhookEventType::LatePayment,
            WebhookEventType::Swept,
            WebhookEventType::Reorged,
        ]
    );
    let reorg_hook = &hooks[2];
    assert_eq!(reorg_hook.status, WebhookDeliveryStatus::Delivered);
    assert!(reorg_hook.dedupe_key.contains(":REORGED:epoch:1:"));
    assert!(reorg_hook.payload_json.contains(r#""event":"REORGED""#));
    assert!(reorg_hook.payload_json.contains(r#""status":"EXPIRED""#));
}

#[tokio::test]
async fn regression_xmr_043_allow_resweep_blocks_lagging_wallet_and_requires_confirmation() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;
    let mock_daemon_rpc = MockServer::start().await;

    let mut inv = make_invoice(112, 1_000_000_000_000, None);
    inv.status = InvoiceStatus::Settled;
    inv.received_piconero = Piconero(1_000_000_000_000);
    inv.confirmations = 15;
    inv.unlocked = true;
    repo.insert_invoice(&inv).await.unwrap();

    let mut cfg_val =
        (*test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15)).clone();
    cfg_val.monero_daemon_rpc_url = Some(format!("{}/json_rpc", mock_daemon_rpc.uri()));
    let cfg = Arc::new(cfg_val);
    let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();
    let old_tx = "b".repeat(64);
    let att = repo
        .create_prepared_sweep_attempt(inv.id, inv.address_index, cold_addr, Utc::now())
        .await
        .unwrap();
    repo.complete_sweep_attempt(CompleteSweepAttemptParams {
        attempt_id: att.id,
        invoice_id: inv.id,
        attempt_status: SweepAttemptStatus::Submitted,
        sweep_tx_hashes: vec![old_tx.clone()],
        sweep_amount_piconero: Piconero(999_900_000_000),
        sweep_fee_piconero: Piconero(100_000_000),
        webhook: None,
        now: Utc::now(),
    })
    .await
    .unwrap();
    repo.mark_sweep_attempt_reorged(
        att.id,
        inv.id,
        "SWEEP_REORG_DETECTED: missing",
        None,
        Utc::now(),
    )
    .await
    .unwrap();

    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
    let app = build_router(AppState {
        config: cfg.clone(),
        repo: repo.clone(),
        rpc,
        scanner,
    });

    // 1) Missing or false confirm_absent_on_chain -> 400 Bad Request
    for payload in [
        r#"{"action":"allow_resweep","operator_note":"missing confirm"}"#,
        r#"{"action":"allow_resweep","confirm_absent_on_chain":false,"operator_note":"false confirm"}"#,
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // 2) Lagging wallet (wallet_height=100 < daemon_height=110) -> 409 Conflict
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_wallet_info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": { "height": 100_u64 }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "d1",
            "result": {
                "height": 110_u64,
                "target_height": 110_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": false,
                "status": "OK",
                "nettype": "mainnet"
            }
        })))
        .mount(&mock_daemon_rpc)
        .await;

    let lag_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"checking sync lag"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(lag_resp.status(), StatusCode::CONFLICT);

    // 3) RPC error on get_height / monerod get_info -> 503 Service Unavailable (fail-closed)
    mock_rpc.reset().await;
    mock_daemon_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_daemon_rpc)
        .await;

    let rpc_err_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"rpc outage check"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rpc_err_resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    // 4) Synced wallet (wallet_height >= daemon_height), empty get_transfers, confirm_absent_on_chain=true -> 200 OK + audit metadata
    mock_rpc.reset().await;
    mock_daemon_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_wallet_info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "3",
            "result": { "height": 3_400_500_u64 }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "d4",
            "result": {
                "height": 3_400_500_u64,
                "target_height": 3_400_500_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": false,
                "status": "OK",
                "nettype": "mainnet"
            }
        })))
        .mount(&mock_daemon_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "5",
            "result": { "out": [], "pending": [], "pool": [] }
        })))
        .mount(&mock_rpc)
        .await;

    let ok_resp = app
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"manual sync & block explorer check OK"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_resp.status(), StatusCode::OK);
    let ok_dto: ResolveSweepIncidentResponse =
        serde_json::from_slice(&ok_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(ok_dto.resolved_attempt.status, SweepAttemptStatus::Failed);
    let note = ok_dto.resolved_attempt.resolution_note.unwrap();
    assert!(note.starts_with("manual sync & block explorer check OK"));
    assert!(note.contains("verified_at_utc="));
    assert!(note.contains("wallet_height=3400500"));
    assert!(note.contains("daemon_height=3400500"));
    assert!(note.contains(&format!("prior_tx_hashes={old_tx}")));
}

#[tokio::test]
async fn regression_xmr_044_045_mark_reconciled_validates_64_hex_verifies_rpc_and_prevents_resweep()
{
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
    let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();

    // Invoice A: SWEPT -> REORGED -> MARK_RECONCILED -> SWEPT
    let mut inv = make_invoice(113, 1_000_000_000_000, None);
    inv.status = InvoiceStatus::Settled;
    inv.received_piconero = Piconero(1_000_000_000_000);
    inv.confirmations = 15;
    inv.unlocked = true;
    repo.insert_invoice(&inv).await.unwrap();

    let old_tx = "c".repeat(64);
    let rep_upper = "D".repeat(64);
    let rep_lower = "d".repeat(64);

    let att = repo
        .create_prepared_sweep_attempt(inv.id, inv.address_index, cold_addr, Utc::now())
        .await
        .unwrap();
    repo.complete_sweep_attempt(CompleteSweepAttemptParams {
        attempt_id: att.id,
        invoice_id: inv.id,
        attempt_status: SweepAttemptStatus::Submitted,
        sweep_tx_hashes: vec![old_tx],
        sweep_amount_piconero: Piconero(999_900_000_000),
        sweep_fee_piconero: Piconero(100_000_000),
        webhook: None,
        now: Utc::now(),
    })
    .await
    .unwrap();
    repo.mark_sweep_attempt_reorged(
        att.id,
        inv.id,
        "SWEEP_REORG_DETECTED: reorged",
        None,
        Utc::now(),
    )
    .await
    .unwrap();

    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
    let app = build_router(AppState {
        config: cfg.clone(),
        repo: repo.clone(),
        rpc,
        scanner: scanner.clone(),
    });

    // 1) Reject invalid replacement_tx_hash formats with 400 Bad Request
    for bad_hash in [
        "abc",
        &"e".repeat(63),
        &"e".repeat(65),
        &format!("{}g", "a".repeat(63)),
    ] {
        let body = serde_json::json!({
            "action": "mark_reconciled",
            "replacement_tx_hash": bad_hash,
            "operator_note": "verifying hash format"
        });
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 for bad hash '{bad_hash}'"
        );
    }

    // 2) Reject 64-hex replacement_tx_hash if absent from RPC (409 Conflict)
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": { "out": [], "pending": [], "pool": [] }
        })))
        .mount(&mock_rpc)
        .await;

    let missing_rep = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    serde_json::json!({
                        "action": "mark_reconciled",
                        "replacement_tx_hash": rep_upper,
                        "operator_note": "hash absent in RPC"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_rep.status(), StatusCode::CONFLICT);

    // 3) Reject 64-hex replacement_tx_hash if double_spend_seen=true in RPC (409 Conflict)
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "2",
            "result": {
                "out": [{
                    "txid": rep_lower,
                    "amount": 999_900_000_000_u64,
                    "fee": 100_000_000_u64,
                    "confirmations": 5,
                    "double_spend_seen": true,
                    "subaddr_index": { "major": 0, "minor": 113 }
                }],
                "pending": [],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    let ds_rep = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    serde_json::json!({
                        "action": "mark_reconciled",
                        "replacement_tx_hash": rep_upper,
                        "operator_note": "double spend check"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ds_rep.status(), StatusCode::CONFLICT);

    // 4) Valid replacement_tx_hash (uppercase -> normalized lowercase) present in out without double-spend -> 200 OK
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "3",
            "result": {
                    "out": [{
                        "txid": rep_lower,
                        "amount": 999_900_000_000_u64,
                        "fee": 100_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 113 },
                        "destinations": [{
                            "amount": 999_900_000_000_u64,
                            "address": cold_addr
                        }]
                    }],
                "pending": [],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "4",
            "result": { "in": [], "pool": [] }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("sweep_all"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_rpc)
        .await;

    let ok_rep = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    serde_json::json!({
                        "action": "mark_reconciled",
                        "replacement_tx_hash": rep_upper,
                        "operator_note": "confirmed settlement of replacement sweep on cold wallet"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_rep.status(), StatusCode::OK);
    let ok_dto: ResolveSweepIncidentResponse =
        serde_json::from_slice(&ok_rep.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(ok_dto.status, InvoiceStatus::Swept);
    assert_eq!(
        ok_dto.resolved_attempt.status,
        SweepAttemptStatus::Reconciled
    );
    assert_eq!(
        ok_dto.resolved_attempt.resolution_action,
        Some(SweepResolutionAction::MarkReconciled)
    );
    assert!(ok_dto.resolved_attempt.resolved_at.is_some());
    assert!(ok_dto.resolved_attempt.tx_hashes.contains(&rep_lower));
    assert!(!ok_dto.resolved_attempt.tx_hashes.contains(&rep_upper));

    // Replaying /sweep/resolve returns 409 Conflict (idempotent protection against double reconciliation)
    let replay_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    serde_json::json!({
                        "action": "mark_reconciled",
                        "operator_note": "replay attempt"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_resp.status(), StatusCode::CONFLICT);

    // Subsequent scan_once & manual /sweep refuse to double-sweep
    let scan_after = scanner.scan_once().await.unwrap();
    assert_eq!(scan_after.invoices_swept, 0);
    let post_sweep_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep", inv.id))
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_sweep_resp.status(), StatusCode::CONFLICT);

    // 5) EXPIRED invoice late-payment sweep reorg -> MARK_RECONCILED keeps status=EXPIRED
    let mut exp_inv = make_invoice(114, 1_000_000_000_000, None);
    exp_inv.status = InvoiceStatus::Expired;
    exp_inv.expires_at = Utc::now() - ChronoDuration::minutes(30);
    repo.insert_invoice(&exp_inv).await.unwrap();

    let exp_att = repo
        .create_prepared_sweep_attempt(exp_inv.id, exp_inv.address_index, cold_addr, Utc::now())
        .await
        .unwrap();
    repo.complete_sweep_attempt(CompleteSweepAttemptParams {
        attempt_id: exp_att.id,
        invoice_id: exp_inv.id,
        attempt_status: SweepAttemptStatus::Submitted,
        sweep_tx_hashes: vec!["f".repeat(64)],
        sweep_amount_piconero: Piconero(999_900_000_000),
        sweep_fee_piconero: Piconero(100_000_000),
        webhook: None,
        now: Utc::now(),
    })
    .await
    .unwrap();
    repo.mark_sweep_attempt_reorged(
        exp_att.id,
        exp_inv.id,
        "SWEEP_REORG_DETECTED: expired sweep",
        None,
        Utc::now(),
    )
    .await
    .unwrap();

    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "exp_rep",
            "result": {
                "out": [{
                    "txid": "f".repeat(64),
                    "amount": 999_900_000_000_u64,
                    "fee": 100_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "subaddr_index": { "major": 0, "minor": 114 },
                    "destinations": [{
                        "amount": 999_900_000_000_u64,
                        "address": cold_addr
                    }]
                }],
                "pending": [],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    let exp_res = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", exp_inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"action":"mark_reconciled","operator_note":"expired late sweep arrived safely on cold wallet"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exp_res.status(), StatusCode::OK);
    let exp_dto: ResolveSweepIncidentResponse =
        serde_json::from_slice(&exp_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(exp_dto.status, InvoiceStatus::Expired);
    assert_eq!(
        exp_dto.resolved_attempt.status,
        SweepAttemptStatus::Reconciled
    );
    assert_eq!(
        exp_dto.resolved_attempt.resolution_action,
        Some(SweepResolutionAction::MarkReconciled)
    );
}

#[tokio::test]
async fn regression_operator_api_key_isolates_incident_resolution_from_merchant_key() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    let mut cfg_val =
        (*test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15)).clone();
    let op_key = "operator-privileged-secret-key-0123456789abcdef".to_string();
    cfg_val.operator_api_key = Some(op_key.clone());
    let cfg = Arc::new(cfg_val);

    let subaddr = encode_monero_base58_address(24, &[0x33; 32], &[0x44; 32], None);
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("create_address"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": { "address": subaddr, "address_index": 115 }
        })))
        .mount(&mock_rpc)
        .await;

    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
    let app = build_router(AppState {
        config: cfg.clone(),
        repo: repo.clone(),
        rpc,
        scanner,
    });

    // 1) Merchant API_SECRET_KEY can create & read invoices
    let create_resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/invoices")
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"order_id":"op-rbac-order-1","amount_piconero":1000000000000}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let created: CreateInvoiceResponse =
        serde_json::from_slice(&create_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();

    let get_resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/invoices/{}", created.invoice_id))
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);

    // Advance invoice through SETTLED -> SWEPT -> REORGED sweep incident
    repo.apply_scan_update(ApplyScanUpdateParams {
        invoice_id: created.invoice_id,
        received_piconero: Piconero(1_000_000_000_000),
        confirmations: 15,
        unlocked: true,
        double_spend_seen: false,
        next_status: InvoiceStatus::Settled,
        transfers: vec![ObservedTransfer {
            txid: "e".repeat(64),
            amount_piconero: Piconero(1_000_000_000_000),
            confirmations: 15,
            unlocked: true,
            double_spend_seen: false,
            in_pool: false,
            orphaned: false,
        }],
        webhook: None,
        now: Utc::now(),
    })
    .await
    .unwrap();
    let att = repo
        .create_prepared_sweep_attempt(
            created.invoice_id,
            115,
            cfg.cold_wallet_address.as_deref().unwrap(),
            Utc::now(),
        )
        .await
        .unwrap();
    repo.complete_sweep_attempt(CompleteSweepAttemptParams {
        attempt_id: att.id,
        invoice_id: created.invoice_id,
        attempt_status: SweepAttemptStatus::Submitted,
        sweep_tx_hashes: vec!["f".repeat(64)],
        sweep_amount_piconero: Piconero(999_900_000_000),
        sweep_fee_piconero: Piconero(100_000_000),
        webhook: None,
        now: Utc::now(),
    })
    .await
    .unwrap();
    repo.mark_sweep_attempt_reorged(
        att.id,
        created.invoice_id,
        "SWEEP_REORG_DETECTED: test rbac",
        None,
        Utc::now(),
    )
    .await
    .unwrap();

    // 2) Merchant API_SECRET_KEY is rejected (403 Forbidden) on /sweep/resolve and /sweep, and unknown key -> 401
    let merchant_forbidden = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/invoices/{}/sweep/resolve",
                created.invoice_id
            ))
            .header("content-type", "application/json")
            .header("X-API-Key", cfg.api_secret_key.as_str())
            .body(Body::from(
                r#"{"action":"mark_reconciled","operator_note":"merchant should fail"}"#,
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(merchant_forbidden.status(), StatusCode::FORBIDDEN);

    let merchant_sweep_forbidden = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep", created.invoice_id))
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(merchant_sweep_forbidden.status(), StatusCode::FORBIDDEN);

    let unknown_unauth = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/invoices/{}/sweep/resolve",
                created.invoice_id
            ))
            .header("content-type", "application/json")
            .header("X-API-Key", "completely-wrong-key")
            .body(Body::from(
                r#"{"action":"mark_reconciled","operator_note":"unknown key"}"#,
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_unauth.status(), StatusCode::UNAUTHORIZED);

    // 3) OPERATOR_API_KEY successfully resolves the incident!
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "op_rep",
            "result": {
                "out": [{
                    "txid": "f".repeat(64),
                    "amount": 999_900_000_000_u64,
                    "fee": 100_000_000_u64,
                    "confirmations": 12,
                    "double_spend_seen": false,
                    "subaddr_index": { "major": 0, "minor": 115 },
                    "destinations": [{
                        "amount": 999_900_000_000_u64,
                        "address": cfg.cold_wallet_address.as_deref().unwrap()
                    }]
                }],
                "pending": [],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    let operator_ok = app
        .oneshot(
            Request::post(format!(
                "/api/v1/invoices/{}/sweep/resolve",
                created.invoice_id
            ))
            .header("content-type", "application/json")
            .header("X-API-Key", op_key.as_str())
            .body(Body::from(
                r#"{"action":"mark_reconciled","operator_note":"authorized operator resolution"}"#,
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(operator_ok.status(), StatusCode::OK);
    let op_dto: ResolveSweepIncidentResponse =
        serde_json::from_slice(&operator_ok.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(
        op_dto.resolved_attempt.status,
        SweepAttemptStatus::Reconciled
    );
}

#[tokio::test]
async fn regression_audit_001_verify_wallet_synced_contract_and_daemon_security() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_wallet_rpc = MockServer::start().await;
    let mock_daemon_rpc = MockServer::start().await;

    // Helper to seed an invoice stuck in REORGED sweep state
    async fn seed_reorged_invoice(
        repo: &InvoiceRepository,
        address_index: u32,
        cold_addr: &str,
        tx_hash: &str,
    ) -> Invoice {
        let mut inv = make_invoice(address_index, 1_000_000_000_000, None);
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let att = repo
            .create_prepared_sweep_attempt(inv.id, inv.address_index, cold_addr, Utc::now())
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: att.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Submitted,
            sweep_tx_hashes: vec![tx_hash.to_string()],
            sweep_amount_piconero: Piconero(999_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now: Utc::now(),
        })
        .await
        .unwrap();
        repo.mark_sweep_attempt_reorged(
            att.id,
            inv.id,
            "SWEEP_REORG_DETECTED: disappeared",
            None,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap()
    }

    // ------------------------------------------------------------------------
    // 1) MONERO_DAEMON_RPC_URL is ABSENT -> fail-closed 503; NEVER calls get_info or get_wallet_info
    // ------------------------------------------------------------------------
    let cfg_no_daemon = test_config(
        format!("{}/json_rpc", mock_wallet_rpc.uri()),
        None,
        true,
        10,
        15,
    );
    let cold_addr = cfg_no_daemon.cold_wallet_address.as_deref().unwrap();

    let inv_no_daemon = seed_reorged_invoice(&repo, 120, cold_addr, &"1".repeat(64)).await;

    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_wallet_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_wallet_info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_wallet_rpc)
        .await;

    let rpc_no_daemon = MoneroRpcClient::new(&cfg_no_daemon.monero_rpc_url, None, None).unwrap();
    let scanner_no_daemon =
        ScannerService::new(repo.clone(), rpc_no_daemon.clone(), cfg_no_daemon.clone());
    let app_no_daemon = build_router(AppState {
        config: cfg_no_daemon.clone(),
        repo: repo.clone(),
        rpc: rpc_no_daemon,
        scanner: scanner_no_daemon,
    });

    let no_daemon_resp = app_no_daemon
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/invoices/{}/sweep/resolve",
                inv_no_daemon.id
            ))
            .header("content-type", "application/json")
            .header("X-API-Key", cfg_no_daemon.api_secret_key.as_str())
            .body(Body::from(
                r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"missing daemon url"}"#,
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_daemon_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        repo.list_sweep_attempts_for_invoice(inv_no_daemon.id)
            .await
            .unwrap()[0]
            .status,
        SweepAttemptStatus::Reorged
    );

    // ------------------------------------------------------------------------
    // 2) MONERO_DAEMON_RPC_URL + USER/PASS set -> monero-wallet-rpc get_height + authenticated monerod get_info
    // ------------------------------------------------------------------------
    struct AuthenticatedDaemonResponder {
        expected_user: String,
        daemon_height: u64,
    }

    impl Respond for AuthenticatedDaemonResponder {
        fn respond(&self, request: &WireRequest) -> ResponseTemplate {
            let has_digest = request
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.starts_with("Digest ") && s.contains(&self.expected_user));

            if has_digest {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "di_auth",
                    "result": {
                        "height": self.daemon_height,
                        "target_height": self.daemon_height,
                        "synchronized": true,
                        "offline": false,
                        "untrusted": false,
                        "status": "OK",
                        "nettype": "mainnet"
                    }
                }))
            } else {
                ResponseTemplate::new(401).insert_header(
                    "WWW-Authenticate",
                    r#"Digest realm="monerod-rpc", nonce="9a8b7c6d5e4f3a2b", qop="auth", algorithm="MD5""#,
                )
            }
        }
    }

    let mut cfg_daemon_val = (*cfg_no_daemon).clone();
    cfg_daemon_val.monero_daemon_rpc_url = Some(format!("{}/json_rpc", mock_daemon_rpc.uri()));
    cfg_daemon_val.monero_daemon_rpc_user = Some("daemon_rpc_user".to_string());
    cfg_daemon_val.monero_daemon_rpc_pass = Some("daemon-rpc-super-secret-pass-01".to_string());
    let cfg_daemon = Arc::new(cfg_daemon_val);

    let inv_bad_states = seed_reorged_invoice(&repo, 121, cold_addr, &"2".repeat(64)).await;
    let inv_rpc_down = seed_reorged_invoice(&repo, 122, cold_addr, &"3".repeat(64)).await;
    let inv_daemon_ok = seed_reorged_invoice(&repo, 123, cold_addr, &"4".repeat(64)).await;

    let rpc_daemon_mode = MoneroRpcClient::new(&cfg_daemon.monero_rpc_url, None, None).unwrap();
    let scanner_daemon_mode =
        ScannerService::new(repo.clone(), rpc_daemon_mode.clone(), cfg_daemon.clone());
    let app_daemon = build_router(AppState {
        config: cfg_daemon.clone(),
        repo: repo.clone(),
        rpc: rpc_daemon_mode,
        scanner: scanner_daemon_mode,
    });

    // ------------------------------------------------------------------------
    // 3) Lagging wallet / unsynced daemon / target_height > height / offline / bad status / zero height -> 409
    // ------------------------------------------------------------------------
    let invalid_sync_cases = [
        // wallet lags behind daemon height
        (
            3_499_999_u64,
            serde_json::json!({
                "height": 3_500_000_u64,
                "target_height": 3_500_000_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": false,
                "status": "OK",
                "nettype": "mainnet"
            }),
        ),
        // daemon still catching up to higher target_height
        (
            3_500_000_u64,
            serde_json::json!({
                "height": 3_500_000_u64,
                "target_height": 3_500_010_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": false,
                "status": "OK",
                "nettype": "mainnet"
            }),
        ),
        // daemon not synchronized
        (
            3_500_000_u64,
            serde_json::json!({
                "height": 3_500_000_u64,
                "target_height": 3_500_000_u64,
                "synchronized": false,
                "offline": false,
                "untrusted": false,
                "status": "OK",
                "nettype": "mainnet"
            }),
        ),
        // daemon offline
        (
            3_500_000_u64,
            serde_json::json!({
                "height": 3_500_000_u64,
                "target_height": 3_500_000_u64,
                "synchronized": true,
                "offline": true,
                "untrusted": false,
                "status": "OK",
                "nettype": "mainnet"
            }),
        ),
        // untrusted daemon (rpc_response_base.untrusted == true)
        (
            3_500_000_u64,
            serde_json::json!({
                "height": 3_500_000_u64,
                "target_height": 3_500_000_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": true,
                "status": "OK",
                "nettype": "mainnet"
            }),
        ),
        // daemon status != "OK"
        (
            3_500_000_u64,
            serde_json::json!({
                "height": 3_500_000_u64,
                "target_height": 3_500_000_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": false,
                "status": "BUSY",
                "nettype": "mainnet"
            }),
        ),
        // daemon network mismatch (stagenet daemon against mainnet config)
        (
            3_500_000_u64,
            serde_json::json!({
                "height": 3_500_000_u64,
                "target_height": 3_500_000_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": false,
                "status": "OK",
                "nettype": "stagenet",
                "stagenet": true
            }),
        ),
        // daemon missing network identifier
        (
            3_500_000_u64,
            serde_json::json!({
                "height": 3_500_000_u64,
                "target_height": 3_500_000_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": false,
                "status": "OK"
            }),
        ),
        // zero wallet height
        (
            0_u64,
            serde_json::json!({
                "height": 3_500_000_u64,
                "target_height": 3_500_000_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": false,
                "status": "OK",
                "nettype": "mainnet"
            }),
        ),
        // zero daemon height
        (
            3_500_000_u64,
            serde_json::json!({
                "height": 0_u64,
                "target_height": 0_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": false,
                "status": "OK",
                "nettype": "mainnet"
            }),
        ),
    ];

    for (wallet_h, daemon_result) in invalid_sync_cases {
        mock_wallet_rpc.reset().await;
        mock_daemon_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_info"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_wallet_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_wallet_info"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_wallet_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_height"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "wh_bad",
                "result": { "height": wallet_h }
            })))
            .mount(&mock_wallet_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "di_bad",
                "result": daemon_result
            })))
            .mount(&mock_daemon_rpc)
            .await;

        let res = app_daemon
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv_bad_states.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg_daemon.api_secret_key.as_str())
                    .body(Body::from(
                        r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"unsynced state check"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::CONFLICT,
            "invalid sync state must fail closed with 409 Conflict"
        );
        assert_eq!(
            repo.list_sweep_attempts_for_invoice(inv_bad_states.id)
                .await
                .unwrap()[0]
                .status,
            SweepAttemptStatus::Reorged
        );
    }

    // 3b) Missing mandatory get_info fields (untrusted / offline / synchronized / status) -> fail closed (503)
    for incomplete_info in [
        serde_json::json!({
            "height": 3_500_000_u64,
            "synchronized": true,
            "offline": false,
            "status": "OK",
            "nettype": "mainnet"
        }),
        serde_json::json!({
            "height": 3_500_000_u64,
            "synchronized": true,
            "untrusted": false,
            "status": "OK",
            "nettype": "mainnet"
        }),
        serde_json::json!({
            "height": 3_500_000_u64,
            "offline": false,
            "untrusted": false,
            "status": "OK",
            "nettype": "mainnet"
        }),
        serde_json::json!({
            "height": 3_500_000_u64,
            "synchronized": true,
            "offline": false,
            "untrusted": false,
            "nettype": "mainnet"
        }),
    ] {
        mock_wallet_rpc.reset().await;
        mock_daemon_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_height"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "wh_inc",
                "result": { "height": 3_500_000_u64 }
            })))
            .mount(&mock_wallet_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "di_inc",
                "result": incomplete_info
            })))
            .mount(&mock_daemon_rpc)
            .await;

        let res = app_daemon
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv_bad_states.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg_daemon.api_secret_key.as_str())
                    .body(Body::from(
                        r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"incomplete get_info check"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // 3c) Stagenet config rejecting mainnet monerod with 409 Conflict, then accepting stagenet monerod
    {
        let mut cfg_stage_val = (*cfg_daemon).clone();
        cfg_stage_val.monero_network = MoneroNetwork::Stagenet;
        let cfg_stage = Arc::new(cfg_stage_val);
        let inv_stage = seed_reorged_invoice(&repo, 124, cold_addr, &"5".repeat(64)).await;
        let rpc_stage = MoneroRpcClient::new(&cfg_stage.monero_rpc_url, None, None).unwrap();
        let scanner_stage = ScannerService::new(repo.clone(), rpc_stage.clone(), cfg_stage.clone());
        let app_stage = build_router(AppState {
            config: cfg_stage.clone(),
            repo: repo.clone(),
            rpc: rpc_stage,
            scanner: scanner_stage,
        });

        mock_wallet_rpc.reset().await;
        mock_daemon_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_height"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "wh_st_bad",
                "result": { "height": 1_800_000_u64 }
            })))
            .mount(&mock_wallet_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "di_main",
                "result": {
                    "height": 1_800_000_u64,
                    "target_height": 1_800_000_u64,
                    "synchronized": true,
                    "offline": false,
                    "untrusted": false,
                    "status": "OK",
                    "nettype": "mainnet",
                    "mainnet": true
                }
            })))
            .mount(&mock_daemon_rpc)
            .await;

        let net_mismatch_resp = app_stage
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv_stage.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg_stage.api_secret_key.as_str())
                    .body(Body::from(
                        r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"mainnet daemon against stagenet"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(net_mismatch_resp.status(), StatusCode::CONFLICT);
        assert_eq!(
            repo.list_sweep_attempts_for_invoice(inv_stage.id)
                .await
                .unwrap()[0]
                .status,
            SweepAttemptStatus::Reorged
        );

        // Now stagenet daemon matches MoneroNetwork::Stagenet -> 200 OK
        mock_daemon_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""pool":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "tr_st_ok",
                "result": { "out": [], "pending": [], "pool": [] }
            })))
            .mount(&mock_wallet_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "di_stage",
                "result": {
                    "height": 1_800_000_u64,
                    "target_height": 1_800_000_u64,
                    "synchronized": true,
                    "offline": false,
                    "untrusted": false,
                    "status": "OK",
                    "nettype": "stagenet",
                    "stagenet": true
                }
            })))
            .mount(&mock_daemon_rpc)
            .await;

        let stage_ok_resp = app_stage
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv_stage.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg_stage.api_secret_key.as_str())
                    .body(Body::from(
                        r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"stagenet daemon verified"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stage_ok_resp.status(), StatusCode::OK);
    }

    // ------------------------------------------------------------------------
    // 4) Unavailability of monerod OR monero-wallet-rpc -> 503 Service Unavailable
    // ------------------------------------------------------------------------
    mock_wallet_rpc.reset().await;
    mock_daemon_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "wh_ok",
            "result": { "height": 3_500_020_u64 }
        })))
        .mount(&mock_wallet_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_daemon_rpc)
        .await;

    let daemon_down_resp = app_daemon
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv_rpc_down.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg_daemon.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"daemon unavailable"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(daemon_down_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        repo.list_sweep_attempts_for_invoice(inv_rpc_down.id)
            .await
            .unwrap()[0]
            .status,
        SweepAttemptStatus::Reorged
    );

    mock_wallet_rpc.reset().await;
    mock_daemon_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_wallet_rpc)
        .await;

    let wallet_down_resp = app_daemon
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv_rpc_down.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg_daemon.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"wallet unavailable"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wallet_down_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        repo.list_sweep_attempts_for_invoice(inv_rpc_down.id)
            .await
            .unwrap()[0]
            .status,
        SweepAttemptStatus::Reorged
    );

    // ------------------------------------------------------------------------
    // 5) Happy path with Digest Authorization sent to monerod -> 200 OK
    // ------------------------------------------------------------------------
    mock_wallet_rpc.reset().await;
    mock_daemon_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_wallet_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_wallet_info"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_wallet_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "wh_final",
            "result": { "height": 3_500_050_u64 }
        })))
        .expect(1)
        .mount(&mock_wallet_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "tr_final",
            "result": { "out": [], "pending": [], "pool": [] }
        })))
        .expect(1)
        .mount(&mock_wallet_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(AuthenticatedDaemonResponder {
            expected_user: "daemon_rpc_user".to_string(),
            daemon_height: 3_500_050_u64,
        })
        .expect(2) // initial 401 Digest challenge + authenticated retry
        .mount(&mock_daemon_rpc)
        .await;

    let ok_daemon = app_daemon
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv_daemon_ok.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg_daemon.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"authenticated monerod get_info verified"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_daemon.status(), StatusCode::OK);
    let daemon_dto: ResolveSweepIncidentResponse =
        serde_json::from_slice(&ok_daemon.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        daemon_dto.resolved_attempt.status,
        SweepAttemptStatus::Failed
    );
    assert!(
        daemon_dto
            .resolved_attempt
            .resolution_note
            .as_deref()
            .is_some_and(
                |n| n.contains("wallet_height=3500050") && n.contains("daemon_height=3500050")
            )
    );

    // ------------------------------------------------------------------------
    // 6) Config::validate() security policy for MONERO_DAEMON_RPC_URL/USER/PASS
    // ------------------------------------------------------------------------
    let mut insecure_remote = Config {
        host: "127.0.0.1".to_string(),
        port: 8080,
        cors_allowed_origins: vec![],
        database_url: "sqlite::memory:".to_string(),
        api_secret_key: "a".repeat(32),
        operator_api_key: None,
        webhook_secret: "b".repeat(32),
        default_webhook_url: None,
        allow_private_webhooks: false,
        require_https_webhooks: true,
        monero_network: MoneroNetwork::Mainnet,
        monero_rpc_url: "http://127.0.0.1:18082/json_rpc".to_string(),
        monero_daemon_rpc_url: Some("http://192.168.10.20:18081/json_rpc".to_string()),
        monero_remote_node: None,
        monero_daemon_rpc_user: Some("daemon_user".to_string()),
        monero_daemon_rpc_pass: Some("daemon-strong-secret-pass".to_string()),
        monero_rpc_user: Some("wallet_user".to_string()),
        monero_rpc_pass: Some("wallet-strong-secret-pass".to_string()),
        allow_unauthenticated_rpc: false,
        allow_insecure_remote_rpc: false,
        cold_wallet_address: None,
        wallet_mode: WalletMode::ViewOnly,
        monero_trusted_daemon: false,
        allow_hot_wallet_without_sweep: false,
        enable_auto_sweep: false,
        sweep_priority: 0,
        required_confirmations: 10,
        settlement_confirmations: 10,
        invoice_ttl_seconds: 3600,
        scan_interval_seconds: 10,
        scanner_subaddress_batch_size: xmr_gateway::config::DEFAULT_SCANNER_SUBADDRESS_BATCH_SIZE,
        webhook_poll_interval_seconds: 5,
        subaddress_monitor_days: 0,
        log_format: LogFormat::Json,
    };
    assert!(
        insecure_remote.validate().is_err(),
        "cleartext non-loopback MONERO_DAEMON_RPC_URL must fail validation"
    );

    insecure_remote.monero_daemon_rpc_url =
        Some("https://node.example.org:18081/json_rpc".to_string());
    assert!(insecure_remote.validate().is_ok());

    insecure_remote.monero_daemon_rpc_pass = None;
    assert!(
        insecure_remote.validate().is_err(),
        "unpaired MONERO_DAEMON_RPC_USER/PASS must fail validation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn regression_audit_003_sweep_concurrency_and_recovery_races() {
    // ========================================================================
    // Scenario 1: Stale SweepAttempt overwrite in reconcile_in_flight_sweeps()
    // ========================================================================
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());

        let t0 = Utc::now() - ChronoDuration::seconds(180);
        let t1 = Utc::now() - ChronoDuration::seconds(170);

        let mut inv0 = make_invoice(200, 1_000_000_000_000, None);
        inv0.status = InvoiceStatus::Settled;
        inv0.received_piconero = Piconero(1_000_000_000_000);
        inv0.confirmations = 15;
        inv0.unlocked = true;
        inv0.created_at = t0;
        repo.insert_invoice(&inv0).await.unwrap();
        let att0 = repo
            .create_prepared_sweep_attempt(inv0.id, inv0.address_index, cold_addr, t0)
            .await
            .unwrap();

        let mut inv1 = make_invoice(201, 1_000_000_000_000, None);
        inv1.status = InvoiceStatus::Settled;
        inv1.received_piconero = Piconero(1_000_000_000_000);
        inv1.confirmations = 15;
        inv1.unlocked = true;
        inv1.created_at = t1;
        repo.insert_invoice(&inv1).await.unwrap();
        let att1 = repo
            .create_prepared_sweep_attempt(inv1.id, inv1.address_index, cold_addr, t1)
            .await
            .unwrap();

        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();

        struct PauseOnAtt0Responder {
            entered_tx: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
            done_rx: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        }

        impl Respond for PauseOnAtt0Responder {
            fn respond(&self, _req: &WireRequest) -> ResponseTemplate {
                if let Some(tx) = self.entered_tx.lock().unwrap().take() {
                    let _ = tx.send(());
                    let _ = self.done_rx.lock().unwrap().recv();
                }
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "out",
                    "result": { "out": [], "pending": [] }
                }))
            }
        }

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
            .respond_with(PauseOnAtt0Responder {
                entered_tx: std::sync::Mutex::new(Some(entered_tx)),
                done_rx: std::sync::Mutex::new(done_rx),
            })
            .mount(&mock_rpc)
            .await;

        let repo_conc = repo.clone();
        let inv1_id = inv1.id;
        let att1_id = att1.id;
        let reconciled_txid = "a".repeat(64);
        let updater = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
                .await
                .unwrap();
            repo_conc
                .complete_sweep_attempt(CompleteSweepAttemptParams {
                    attempt_id: att1_id,
                    invoice_id: inv1_id,
                    attempt_status: SweepAttemptStatus::Reconciled,
                    sweep_tx_hashes: vec![reconciled_txid],
                    sweep_amount_piconero: Piconero(999_900_000_000),
                    sweep_fee_piconero: Piconero(100_000_000),
                    webhook: None,
                    now: Utc::now(),
                })
                .await
                .unwrap();
            done_tx.send(()).unwrap();
        });

        scanner.reconcile_in_flight_sweeps().await.unwrap();
        updater.await.unwrap();

        // Stale att0 timed out past grace window -> MUST escalate to blocking REORGED (SWEEP_AMBIGUOUS_TIMEOUT),
        // NEVER auto-FAILED; concurrently completed att1 MUST remain RECONCILED!
        let att0_after = repo
            .get_sweep_attempt_by_id(att0.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(att0_after.status, SweepAttemptStatus::Reorged);
        assert!(
            att0_after
                .error_message
                .as_deref()
                .is_some_and(|m| m.contains("SWEEP_AMBIGUOUS_TIMEOUT"))
        );
        let att1_after = repo
            .get_sweep_attempt_by_id(att1.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(att1_after.status, SweepAttemptStatus::Reconciled);

        // Even a direct stale mark_sweep_attempt_failed MUST NOT clobber RECONCILED
        repo.mark_sweep_attempt_failed(att1.id, inv1.id, "stale error", Utc::now())
            .await
            .unwrap();
        assert_eq!(
            repo.get_sweep_attempt_by_id(att1.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            SweepAttemptStatus::Reconciled
        );
        assert!(
            repo.get_invoice_by_id(inv1.id)
                .await
                .unwrap()
                .unwrap()
                .last_sweep_error
                .is_none()
        );
    }

    // ========================================================================
    // Scenario 2: Concurrent allow_terminal_inflows double sweep guard
    // ========================================================================
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());

        let orig_tx = "b".repeat(64);
        let overpay_tx = "c".repeat(64);
        let sweep_orig_tx = "d".repeat(64);
        let sweep_over_tx = "e".repeat(64);

        let mut inv = make_invoice(202, 1_000_000_000_000, None);
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: orig_tx.clone(),
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 15,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: orig_tx.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 15,
                classification: TransferClassification::Expected,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: Utc::now(),
            },
            received_piconero: Piconero(1_000_000_000_000),
            confirmations: 15,
            unlocked: true,
            webhook: None,
            now: Utc::now(),
        })
        .await
        .unwrap();

        let att_orig = repo
            .create_prepared_sweep_attempt(inv.id, inv.address_index, cold_addr, Utc::now())
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: att_orig.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Confirmed,
            sweep_tx_hashes: vec![sweep_orig_tx],
            sweep_amount_piconero: Piconero(999_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now: Utc::now(),
        })
        .await
        .unwrap();

        // Record an active unswept overpayment on the SWEPT invoice
        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: overpay_tx.clone(),
                amount_piconero: Piconero(250_000_000_000),
                confirmations: 15,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: overpay_tx.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(250_000_000_000),
                confirmations: 15,
                classification: TransferClassification::Overpayment,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: Utc::now(),
            },
            received_piconero: Piconero(1_250_000_000_000),
            confirmations: 15,
            unlocked: true,
            webhook: None,
            now: Utc::now(),
        })
        .await
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in",
                "result": {
                    "in": [
                        {
                            "txid": orig_tx,
                            "amount": 1_000_000_000_000_u64,
                            "confirmations": 20,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 202 }
                        },
                        {
                            "txid": overpay_tx,
                            "amount": 250_000_000_000_u64,
                            "confirmations": 15,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 202 }
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
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(80))
                    .set_body_json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": "sw",
                        "result": {
                            "tx_hash_list": [sweep_over_tx],
                            "amount_list": [249_900_000_000_u64],
                            "fee_list": [100_000_000_u64]
                        }
                    })),
            )
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let barrier = Arc::new(Barrier::new(2));
        let s1 = scanner.clone();
        let b1 = barrier.clone();
        let h1 = tokio::spawn(async move {
            b1.wait().await;
            s1.manual_sweep(inv.id).await
        });
        let s2 = scanner.clone();
        let b2 = barrier.clone();
        let h2 = tokio::spawn(async move {
            b2.wait().await;
            s2.manual_sweep(inv.id).await
        });

        let (r1, r2) = tokio::join!(h1, h2);
        let outcomes = [r1.unwrap(), r2.unwrap()];
        let ok_count = outcomes.iter().filter(|r| r.is_ok()).count();
        let conflict_count = outcomes
            .iter()
            .filter(|r| matches!(r, Err(GatewayError::Conflict(_))))
            .count();
        assert_eq!(ok_count, 1, "exactly one concurrent sweep must succeed");
        assert_eq!(
            conflict_count, 1,
            "second concurrent sweep MUST reject without duplicate sweep_all"
        );
        assert!(!repo.has_unswept_inflows(inv.id, 0).await.unwrap());
        assert!(!repo.has_unswept_inflows(inv.id, 15).await.unwrap());
    }

    // ========================================================================
    // Scenario 3: Concurrent Settled -> Completed during scan_once()
    // ========================================================================
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 2, 10);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());

        let base = Utc::now();
        // inv_trigger (t0) reaches sweep_all; while in sweep_all RPC, inv_a (t1) moves Settled -> Completed,
        // and inv_b (t2) MUST still be scanned cleanly without aborting scan_once().
        let mut inv_trigger = make_invoice(203, 1_000_000_000_000, None);
        inv_trigger.status = InvoiceStatus::Settled;
        inv_trigger.received_piconero = Piconero(1_000_000_000_000);
        inv_trigger.confirmations = 12;
        inv_trigger.unlocked = true;
        inv_trigger.created_at = base + ChronoDuration::seconds(1);
        repo.insert_invoice(&inv_trigger).await.unwrap();

        let mut inv_a = make_invoice(
            204,
            1_000_000_000_000,
            Some("http://127.0.0.1:9999/cb".to_string()),
        );
        inv_a.status = InvoiceStatus::Settled;
        inv_a.received_piconero = Piconero(1_000_000_000_000);
        inv_a.confirmations = 12;
        inv_a.unlocked = true;
        inv_a.created_at = base + ChronoDuration::seconds(2);
        repo.insert_invoice(&inv_a).await.unwrap();

        let wh_a = build_webhook_delivery(
            &cfg.webhook_secret,
            &inv_a,
            WebhookEventType::Settled,
            "http://127.0.0.1:9999/cb",
            Utc::now(),
        )
        .unwrap();
        repo.apply_scan_update(ApplyScanUpdateParams {
            invoice_id: inv_a.id,
            received_piconero: inv_a.received_piconero,
            confirmations: 12,
            unlocked: true,
            double_spend_seen: false,
            next_status: InvoiceStatus::Settled,
            transfers: vec![],
            webhook: Some(wh_a.clone()),
            now: Utc::now(),
        })
        .await
        .unwrap();

        let mut inv_b = make_invoice(205, 1_000_000_000_000, None);
        inv_b.status = InvoiceStatus::Pending;
        inv_b.created_at = base + ChronoDuration::seconds(3);
        repo.insert_invoice(&inv_b).await.unwrap();

        let tx_trig_in = "11".repeat(32);
        let tx_a_in = "22".repeat(32);
        let tx_b_in = "33".repeat(32);
        let tx_trig_sweep = "44".repeat(32);

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "batch_in",
                "result": {
                    "in": [
                        {
                            "txid": tx_trig_in,
                            "amount": 1_000_000_000_000_u64,
                            "confirmations": 12,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 203 }
                        },
                        {
                            "txid": tx_a_in,
                            "amount": 1_000_000_000_000_u64,
                            "confirmations": 12,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 204 }
                        },
                        {
                            "txid": tx_b_in,
                            "amount": 1_000_000_000_000_u64,
                            "confirmations": 5,
                            "double_spend_seen": false,
                            "locked": true,
                            "subaddr_index": { "major": 0, "minor": 205 }
                        }
                    ],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let (sw_entered_tx, sw_entered_rx) = std::sync::mpsc::channel::<()>();
        let (sw_done_tx, sw_done_rx) = std::sync::mpsc::channel::<()>();

        struct CompleteInvoiceADuringSweep {
            entered_tx: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
            done_rx: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
            sweep_tx: String,
        }

        impl Respond for CompleteInvoiceADuringSweep {
            fn respond(&self, _req: &WireRequest) -> ResponseTemplate {
                if let Some(tx) = self.entered_tx.lock().unwrap().take() {
                    let _ = tx.send(());
                    let _ = self.done_rx.lock().unwrap().recv();
                }
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "sw",
                    "result": {
                        "tx_hash_list": [self.sweep_tx],
                        "amount_list": [999_900_000_000_u64],
                        "fee_list": [100_000_000_u64]
                    }
                }))
            }
        }

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("sweep_all"))
            .respond_with(CompleteInvoiceADuringSweep {
                entered_tx: std::sync::Mutex::new(Some(sw_entered_tx)),
                done_rx: std::sync::Mutex::new(sw_done_rx),
                sweep_tx: tx_trig_sweep,
            })
            .mount(&mock_rpc)
            .await;

        let repo_wh = repo.clone();
        let wh_id = wh_a.id;
        let inv_a_id = inv_a.id;
        let completer = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || sw_entered_rx.recv().unwrap())
                .await
                .unwrap();
            // Mark SETTLED webhook delivered concurrently (complete_on_view_only=true) -> inv_a moves Settled -> Completed
            repo_wh
                .mark_webhook_delivered(
                    wh_id,
                    inv_a_id,
                    WebhookEventType::Settled,
                    200,
                    Utc::now(),
                    true,
                )
                .await
                .unwrap();
            sw_done_tx.send(()).unwrap();
        });

        let report = scanner.scan_once().await.unwrap();
        completer.await.unwrap();
        assert_eq!(report.invoices_swept, 1);

        // inv_a remains COMPLETED and inv_b WAS reached & transitioned to CONFIRMED
        assert_eq!(
            repo.get_invoice_by_id(inv_a.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            InvoiceStatus::Completed
        );
        assert_eq!(
            repo.get_invoice_by_id(inv_b.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            InvoiceStatus::Confirmed
        );
    }

    // ========================================================================
    // Scenario 4: PREPARED ambiguity fail-closed protection & pre-broadcast RPC errors
    // ========================================================================
    {
        // 4A) Ambiguous RPC transport failure during sweep_all keeps PREPARED (< 60s) & blocks re-sweep
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let mock_daemon_rpc = MockServer::start().await;
        let mut cfg_val =
            (*test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15)).clone();
        cfg_val.monero_daemon_rpc_url = Some(format!("{}/json_rpc", mock_daemon_rpc.uri()));
        let cfg = Arc::new(cfg_val);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());

        let mut inv_ambig = make_invoice(206, 1_000_000_000_000, None);
        inv_ambig.status = InvoiceStatus::Settled;
        inv_ambig.received_piconero = Piconero(1_000_000_000_000);
        inv_ambig.confirmations = 15;
        inv_ambig.unlocked = true;
        repo.insert_invoice(&inv_ambig).await.unwrap();

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_ambig",
                "result": {
                    "in": [{
                        "txid": "55".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 206 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("sweep_all"))
            .respond_with(ResponseTemplate::new(502).set_body_string("upstream gateway timeout"))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let err_ambig = scanner.manual_sweep(inv_ambig.id).await.unwrap_err();
        assert!(matches!(err_ambig, GatewayError::RpcTransport(_)));

        let attempts_after_transport = repo
            .list_sweep_attempts_for_invoice(inv_ambig.id)
            .await
            .unwrap();
        assert_eq!(attempts_after_transport.len(), 1);
        assert_eq!(
            attempts_after_transport[0].status,
            SweepAttemptStatus::Prepared
        );

        // Next scan sees empty out/pending while age < 60s -> stays PREPARED, sweep_all NOT retried!
        mock_rpc.reset().await;
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
                "id": "out_empty_1",
                "result": { "out": [], "pending": [] }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_ambig_2",
                "result": {
                    "in": [{
                        "txid": "55".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 206 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let report_grace = scanner.scan_once().await.unwrap();
        assert_eq!(report_grace.invoices_swept, 0);
        assert_eq!(
            repo.get_sweep_attempt_by_id(attempts_after_transport[0].id)
                .await
                .unwrap()
                .unwrap()
                .status,
            SweepAttemptStatus::Prepared
        );
        assert!(matches!(
            scanner.manual_sweep(inv_ambig.id).await,
            Err(GatewayError::Conflict(_))
        ));

        // 4B) Aged PREPARED attempt (> 60s) absent from get_transfers -> escalates to REORGED
        //     (SWEEP_AMBIGUOUS_TIMEOUT), blocking auto & manual sweep until /sweep/resolve!
        let pool_aged = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo_aged = InvoiceRepository::new(pool_aged);
        let rpc_aged = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner_aged = ScannerService::new(repo_aged.clone(), rpc_aged.clone(), cfg.clone());
        let app_aged = build_router(AppState {
            config: cfg.clone(),
            repo: repo_aged.clone(),
            rpc: rpc_aged,
            scanner: scanner_aged.clone(),
        });

        let mut inv_aged = make_invoice(207, 1_000_000_000_000, None);
        inv_aged.status = InvoiceStatus::Settled;
        inv_aged.received_piconero = Piconero(1_000_000_000_000);
        inv_aged.confirmations = 15;
        inv_aged.unlocked = true;
        repo_aged.insert_invoice(&inv_aged).await.unwrap();

        let att_aged = repo_aged
            .create_prepared_sweep_attempt(
                inv_aged.id,
                inv_aged.address_index,
                cold_addr,
                Utc::now() - ChronoDuration::seconds(90),
            )
            .await
            .unwrap();

        let report_aged = scanner_aged.scan_once().await.unwrap();
        assert_eq!(report_aged.invoices_swept, 0);
        let att_aged_after = repo_aged
            .get_sweep_attempt_by_id(att_aged.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(att_aged_after.status, SweepAttemptStatus::Reorged);
        assert!(
            att_aged_after
                .error_message
                .as_deref()
                .is_some_and(|m| m.contains("SWEEP_AMBIGUOUS_TIMEOUT"))
        );
        assert!(
            repo_aged
                .has_reorged_sweep_attempt(inv_aged.id)
                .await
                .unwrap()
        );
        assert!(matches!(
            scanner_aged.manual_sweep(inv_aged.id).await,
            Err(GatewayError::Conflict(_))
        ));

        // Operator can safely unlock via POST /sweep/resolve (allow_resweep) after sync + absence check
        mock_rpc.reset().await;
        mock_daemon_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_height"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "wh_res",
                "result": { "height": 3_500_200_u64 }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""pool":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "tr_res",
                "result": { "out": [], "pending": [], "pool": [] }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "di_res",
                "result": {
                    "height": 3_500_200_u64,
                    "target_height": 3_500_200_u64,
                    "synchronized": true,
                    "offline": false,
                    "untrusted": false,
                    "status": "OK",
                    "nettype": "mainnet"
                }
            })))
            .mount(&mock_daemon_rpc)
            .await;

        let unlock_resp = app_aged
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv_aged.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"verified timed-out prepared sweep never left wallet"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unlock_resp.status(), StatusCode::OK);
        assert!(
            !repo_aged
                .has_reorged_sweep_attempt(inv_aged.id)
                .await
                .unwrap()
        );

        // 4C) PREPARED attempt matched in outgoing RPC reconciles to RECONCILED and SWEPT
        let pool_rec = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo_rec = InvoiceRepository::new(pool_rec);
        let rpc_rec = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner_rec = ScannerService::new(repo_rec.clone(), rpc_rec, cfg.clone());
        mock_rpc.reset().await;

        let mut inv_rec = make_invoice(208, 1_000_000_000_000, None);
        inv_rec.status = InvoiceStatus::Settled;
        inv_rec.received_piconero = Piconero(1_000_000_000_000);
        inv_rec.confirmations = 15;
        inv_rec.unlocked = true;
        repo_rec.insert_invoice(&inv_rec).await.unwrap();

        let att_rec = repo_rec
            .create_prepared_sweep_attempt(inv_rec.id, inv_rec.address_index, cold_addr, Utc::now())
            .await
            .unwrap();

        let recovered_txid = "88".repeat(32);
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
                "id": "out_rec",
                "result": {
                    "out": [{
                        "txid": recovered_txid,
                        "amount": 999_900_000_000_u64,
                        "fee": 100_000_000_u64,
                        "confirmations": 2,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 208 },
                        "destinations": [{
                            "amount": 999_900_000_000_u64,
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
                "id": "in_rec",
                "result": {
                    "in": [{
                        "txid": "99".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 208 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let report_rec = scanner_rec.scan_once().await.unwrap();
        assert_eq!(report_rec.invoices_swept, 1);
        assert_eq!(
            repo_rec
                .get_sweep_attempt_by_id(att_rec.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            SweepAttemptStatus::Reconciled
        );
        assert_eq!(
            repo_rec
                .get_invoice_by_id(inv_rec.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            InvoiceStatus::Swept
        );

        // 4D) Proven pre-broadcast JSON-RPC error (-37 WALLET_RPC_ERROR_CODE_NOT_ENOUGH_UNLOCKED_MONEY)
        //     immediately marks PREPARED -> FAILED and permits safe subsequent retry (`A3-1`)!
        let pool_rpc_err = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo_rpc_err = InvoiceRepository::new(pool_rpc_err);
        let rpc_err_client = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner_rpc_err =
            ScannerService::new(repo_rpc_err.clone(), rpc_err_client, cfg.clone());
        mock_rpc.reset().await;

        let mut inv_rpc_err = make_invoice(209, 1_000_000_000_000, None);
        inv_rpc_err.status = InvoiceStatus::Settled;
        inv_rpc_err.received_piconero = Piconero(1_000_000_000_000);
        inv_rpc_err.confirmations = 15;
        inv_rpc_err.unlocked = true;
        repo_rpc_err.insert_invoice(&inv_rpc_err).await.unwrap();

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_err",
                "result": {
                    "in": [{
                        "txid": "aa".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 209 }
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
                "id": "sw_err",
                "error": { "code": -37, "message": "not enough unlocked money" }
            })))
            .mount(&mock_rpc)
            .await;

        let err_rpc = scanner_rpc_err
            .manual_sweep(inv_rpc_err.id)
            .await
            .unwrap_err();
        assert!(matches!(err_rpc, GatewayError::Rpc { .. }));
        let err_attempts = repo_rpc_err
            .list_sweep_attempts_for_invoice(inv_rpc_err.id)
            .await
            .unwrap();
        assert_eq!(err_attempts.len(), 1);
        assert_eq!(err_attempts[0].status, SweepAttemptStatus::Failed);

        // Subsequent retry succeeds cleanly once daemon/wallet has unlocked funds
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_retry",
                "result": {
                    "in": [{
                        "txid": "aa".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 209 }
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
                "id": "sw_retry",
                "result": {
                    "tx_hash_list": ["bb".repeat(32)],
                    "amount_list": [999_900_000_000_u64],
                    "fee_list": [100_000_000_u64]
                }
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let retried = scanner_rpc_err.manual_sweep(inv_rpc_err.id).await.unwrap();
        assert_eq!(retried.status, InvoiceStatus::Swept);

        // 4E) PREPARED attempt seeing double_spend_seen=true in outgoing RPC escalates to REORGED & blocks re-sweep
        let pool_ds = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool_ds);
        let rpc_ds = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc_ds, cfg.clone());
        mock_rpc.reset().await;
        let mut inv_ds = make_invoice(210, 1_000_000_000_000, None);
        inv_ds.status = InvoiceStatus::Settled;
        inv_ds.received_piconero = Piconero(1_000_000_000_000);
        inv_ds.confirmations = 15;
        inv_ds.unlocked = true;
        repo.insert_invoice(&inv_ds).await.unwrap();

        let att_ds = repo
            .create_prepared_sweep_attempt(inv_ds.id, inv_ds.address_index, cold_addr, Utc::now())
            .await
            .unwrap();

        let double_spend_txid = "66".repeat(32);
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
                "id": "out_ds",
                "result": {
                    "out": [],
                    "pending": [{
                        "txid": double_spend_txid,
                        "amount": 999_900_000_000_u64,
                        "fee": 100_000_000_u64,
                        "confirmations": 0,
                        "double_spend_seen": true,
                        "subaddr_index": { "major": 0, "minor": 210 },
                        "destinations": [{
                            "amount": 999_900_000_000_u64,
                            "address": cold_addr
                        }]
                    }]
                }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_ds",
                "result": {
                    "in": [{
                        "txid": "77".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 210 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let report_ds = scanner.scan_once().await.unwrap();
        assert_eq!(report_ds.invoices_swept, 0);
        let att_ds_after = repo
            .get_sweep_attempt_by_id(att_ds.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(att_ds_after.status, SweepAttemptStatus::Reorged);
        assert!(
            att_ds_after.error_message.as_deref().is_some_and(|m| m
                .contains("SWEEP_REORG_DETECTED")
                && m.contains(&double_spend_txid))
        );
        assert!(repo.has_reorged_sweep_attempt(inv_ds.id).await.unwrap());
        let manual_blocked = scanner.manual_sweep(inv_ds.id).await;
        assert!(matches!(manual_blocked, Err(GatewayError::Conflict(_))));
    }
}

#[tokio::test]
async fn regression_audit_003_expired_late_payment_transfers_preserved_and_sweep_reorg_recovered() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    let cfg = test_config(
        format!("{}/json_rpc", mock_rpc.uri()),
        Some("http://127.0.0.1:9999/webhook".to_string()),
        true,
        10,
        15,
    );
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());

    let mut expired_inv = make_invoice(
        215,
        1_000_000_000_000,
        Some("http://127.0.0.1:9999/webhook".to_string()),
    );
    expired_inv.status = InvoiceStatus::Expired;
    expired_inv.expires_at = Utc::now() - ChronoDuration::hours(1);
    repo.insert_invoice(&expired_inv).await.unwrap();

    // Verify direct apply_scan_update() on EXPIRED preserves EXPIRED status while persisting
    // invoice_transfers + received_piconero (never returning early before saving transfers).
    let direct_txid = "cc".repeat(32);
    let after_direct = repo
        .apply_scan_update(ApplyScanUpdateParams {
            invoice_id: expired_inv.id,
            received_piconero: Piconero(500_000_000_000),
            confirmations: 10,
            unlocked: true,
            double_spend_seen: false,
            next_status: InvoiceStatus::Confirmed,
            transfers: vec![ObservedTransfer {
                txid: direct_txid.clone(),
                amount_piconero: Piconero(500_000_000_000),
                confirmations: 10,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            }],
            webhook: None,
            now: Utc::now(),
        })
        .await
        .unwrap();
    assert_eq!(after_direct.status, InvoiceStatus::Expired);
    assert_eq!(after_direct.received_piconero, Piconero(500_000_000_000));
    assert_eq!(after_direct.confirmations, 10);
    assert_eq!(
        repo.list_transfers_for_invoice(expired_inv.id)
            .await
            .unwrap()
            .len(),
        1
    );

    // Scenario A: EXPIRED invoice receives late incoming payment via scan_once(), persists
    // invoice_transfers & subaddress_transfers, keeps EXPIRED status, and auto-sweeps cleanly.
    let late_txid = "dd".repeat(32);
    let late_sweep_txid = "ee".repeat(32);
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "in_late",
            "result": {
                "in": [{
                    "txid": late_txid,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 215 }
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
            "id": "sw_late",
            "result": {
                "tx_hash_list": [late_sweep_txid],
                "amount_list": [999_900_000_000_u64],
                "fee_list": [100_000_000_u64]
            }
        })))
        .expect(1)
        .mount(&mock_rpc)
        .await;

    let report_a = scanner.scan_once().await.unwrap();
    assert_eq!(report_a.invoices_swept, 1);

    let inv_after_sweep = repo
        .get_invoice_by_id(expired_inv.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inv_after_sweep.status, InvoiceStatus::Expired);
    assert_eq!(
        inv_after_sweep.received_piconero,
        Piconero(1_000_000_000_000)
    );
    assert_eq!(
        inv_after_sweep.sweep_tx_hashes,
        vec![late_sweep_txid.clone()]
    );
    let sub_recs = repo
        .list_subaddress_transfers_for_invoice(expired_inv.id)
        .await
        .unwrap();
    assert_eq!(sub_recs.len(), 1);
    assert_eq!(
        sub_recs[0].classification,
        TransferClassification::LatePayment
    );
    assert_eq!(sub_recs[0].status, SubaddressTransferStatus::Swept);
    let inv_transfers = repo
        .list_transfers_for_invoice(expired_inv.id)
        .await
        .unwrap();
    assert!(inv_transfers.iter().any(|t| t.txid == late_txid));

    // Scenario B: Outbound sweep of the EXPIRED invoice disappears on reorg -> attempt transitions to
    // REORGED, REORGED webhook is queued, invoice preserves EXPIRED, and re-sweep is blocked.
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "out_reorg",
            "result": { "out": [], "pending": [] }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "in_reorg",
            "result": {
                "in": [{
                    "txid": late_txid,
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 20,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 215 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();
    let inv_after_reorg = repo
        .get_invoice_by_id(expired_inv.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inv_after_reorg.status, InvoiceStatus::Expired);
    let attempts = repo
        .list_sweep_attempts_for_invoice(expired_inv.id)
        .await
        .unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].status, SweepAttemptStatus::Reorged);

    let webhooks = repo
        .list_webhooks_for_invoice(expired_inv.id)
        .await
        .unwrap();
    assert!(
        webhooks
            .iter()
            .any(|w| w.event_type == WebhookEventType::Reorged)
    );
}

#[tokio::test]
async fn regression_audit_004_post_resweep_swept_webhook_and_mark_reconciled_validation() {
    // ========================================================================
    // Scenario 1: Post-ALLOW_RESWEEP SWEPT webhook delivery & swept_at reset
    // ========================================================================
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let mock_daemon_rpc = MockServer::start().await;
        let mock_bot = MockServer::start().await;

        let bot_hits: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let bot_hits_hook = bot_hits.clone();

        struct CaptureBotWebhook {
            hits: Arc<std::sync::Mutex<Vec<String>>>,
        }

        impl Respond for CaptureBotWebhook {
            fn respond(&self, req: &WireRequest) -> ResponseTemplate {
                self.hits
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&req.body).to_string());
                ResponseTemplate::new(200)
            }
        }

        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(CaptureBotWebhook {
                hits: bot_hits_hook,
            })
            .mount(&mock_bot)
            .await;

        let cb_url = format!("{}/hook", mock_bot.uri());
        let mut cfg_val = (*test_config(
            format!("{}/json_rpc", mock_rpc.uri()),
            Some(cb_url.clone()),
            true,
            10,
            15,
        ))
        .clone();
        cfg_val.monero_daemon_rpc_url = Some(format!("{}/json_rpc", mock_daemon_rpc.uri()));
        let cfg = Arc::new(cfg_val);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap().to_string();

        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
        let dispatcher = WebhookDispatcher::new(
            repo.clone(),
            cfg.webhook_secret.clone(),
            cfg.enable_auto_sweep,
            Duration::from_secs(1),
            cfg.webhook_url_policy(),
        )
        .unwrap();
        let app = build_router(AppState {
            config: cfg.clone(),
            repo: repo.clone(),
            rpc,
            scanner: scanner.clone(),
        });

        let mut inv = make_invoice(220, 1_000_000_000_000, Some(cb_url));
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let in_tx = "a1".repeat(32);
        let tx_hash_1 = "b1".repeat(32);
        let tx_hash_2 = "b2".repeat(32);

        // 1a) First sweep_all (tx_hash_1) -> emits & delivers 1st SWEPT webhook, sets swept_at
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in1",
                "result": {
                    "in": [{
                        "txid": in_tx,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 220 }
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
                "id": "sw1",
                "result": {
                    "tx_hash_list": [tx_hash_1],
                    "amount_list": [999_900_000_000_u64],
                    "fee_list": [100_000_000_u64]
                }
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        dispatcher.process_due_deliveries().await.unwrap();

        let after_sw1 = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(after_sw1.status, InvoiceStatus::Swept);
        assert!(after_sw1.swept_at.is_some());
        assert_eq!(after_sw1.sweep_tx_hashes, vec![tx_hash_1.clone()]);
        assert_eq!(bot_hits.lock().unwrap().len(), 1);
        assert!(bot_hits.lock().unwrap()[0].contains(&tx_hash_1));

        // 1b) Reorg of tx_hash_1 -> REORGED invoice + REORGED webhook
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""out":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "out_empty",
                "result": { "out": [], "pending": [] }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in2",
                "result": {
                    "in": [{
                        "txid": in_tx,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 20,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 220 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        dispatcher.process_due_deliveries().await.unwrap();
        let after_reorg = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(after_reorg.status, InvoiceStatus::Reorged);
        assert_eq!(after_reorg.reorg_epoch, 1);
        assert_eq!(bot_hits.lock().unwrap().len(), 2);

        // 1c) Operator resolves via ALLOW_RESWEEP -> clears swept_at to None
        mock_rpc.reset().await;
        mock_daemon_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_height"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "wh",
                "result": { "height": 3_600_000_u64 }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""pool":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "ver",
                "result": { "out": [], "pending": [], "pool": [] }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "di",
                "result": {
                    "height": 3_600_000_u64,
                    "target_height": 3_600_000_u64,
                    "synchronized": true,
                    "offline": false,
                    "untrusted": false,
                    "status": "OK",
                    "nettype": "mainnet"
                }
            })))
            .mount(&mock_daemon_rpc)
            .await;

        let resweep_resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"dead sweep_1 verified"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resweep_resp.status(), StatusCode::OK);

        let after_unlock = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert!(
            after_unlock.swept_at.is_none(),
            "ALLOW_RESWEEP must reset swept_at when no remaining sweep hashes exist"
        );
        assert!(after_unlock.sweep_tx_hashes.is_empty());

        // 1d) Re-sweep executes (tx_hash_2, 1 hash) -> MUST enqueue & deliver 2nd SWEPT webhook!
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in3",
                "result": {
                    "in": [{
                        "txid": in_tx,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 22,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 220 }
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
                "id": "sw2",
                "result": {
                    "tx_hash_list": [tx_hash_2],
                    "amount_list": [999_900_000_000_u64],
                    "fee_list": [100_000_000_u64]
                }
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        scanner.scan_once().await.unwrap();
        // Process any queued recovery webhooks in FIFO order until all are delivered
        for _ in 0..6 {
            if dispatcher.process_due_deliveries().await.unwrap() == 0 {
                break;
            }
        }

        let after_sw2 = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(after_sw2.status, InvoiceStatus::Swept);
        assert!(after_sw2.swept_at.is_some());
        assert_eq!(after_sw2.sweep_tx_hashes, vec![tx_hash_2.clone()]);

        let swept_hooks: Vec<_> = repo
            .list_webhooks_for_invoice(inv.id)
            .await
            .unwrap()
            .into_iter()
            .filter(|w| w.event_type == WebhookEventType::Swept)
            .collect();
        assert_eq!(
            swept_hooks.len(),
            2,
            "second SWEPT webhook MUST NOT be silently dropped after ALLOW_RESWEEP"
        );
        assert!(
            swept_hooks
                .iter()
                .all(|w| w.status == WebhookDeliveryStatus::Delivered)
        );
        assert!(
            bot_hits
                .lock()
                .unwrap()
                .iter()
                .any(|body| body.contains("\"event\":\"SWEPT\"") && body.contains(&tx_hash_2))
        );

        let _ = cold_addr;
    }

    // ========================================================================
    // Scenario 2: ALLOW_RESWEEP blocks when live matching sweep appears after SWEEP_AMBIGUOUS_TIMEOUT
    // Scenario 3: MARK_RECONCILED strict matches_sweep, old hash purge, SWEPT webhook & tracking
    // ========================================================================
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let mock_daemon_rpc = MockServer::start().await;

        let mut cfg_val = (*test_config(
            format!("{}/json_rpc", mock_rpc.uri()),
            Some("http://127.0.0.1:9999/cb".to_string()),
            true,
            10,
            15,
        ))
        .clone();
        cfg_val.monero_daemon_rpc_url = Some(format!("{}/json_rpc", mock_daemon_rpc.uri()));
        let cfg = Arc::new(cfg_val);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap().to_string();
        let other_cold_addr = encode_monero_base58_address(18, &[0x22; 32], &[0x33; 32], None);

        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
        let app = build_router(AppState {
            config: cfg.clone(),
            repo: repo.clone(),
            rpc,
            scanner: scanner.clone(),
        });

        // Create invoice with confirmed incoming transfer -> PREPARED -> aged SWEEP_AMBIGUOUS_TIMEOUT (empty tx_hashes)
        let mut inv = make_invoice(
            221,
            1_000_000_000_000,
            Some("http://127.0.0.1:9999/cb".to_string()),
        );
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let in_tx = "c1".repeat(32);
        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: in_tx.clone(),
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 15,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: in_tx.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 15,
                classification: TransferClassification::Expected,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: Utc::now() - ChronoDuration::seconds(120),
            },
            received_piconero: Piconero(1_000_000_000_000),
            confirmations: 15,
            unlocked: true,
            webhook: None,
            now: Utc::now(),
        })
        .await
        .unwrap();

        let att_ambig = repo
            .create_prepared_sweep_attempt(
                inv.id,
                inv.address_index,
                &cold_addr,
                Utc::now() - ChronoDuration::seconds(90),
            )
            .await
            .unwrap();
        assert_eq!(att_ambig.snapshot_txids, vec![in_tx.clone()]);

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""out":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "out_empty",
                "result": { "out": [], "pending": [] }
            })))
            .mount(&mock_rpc)
            .await;
        scanner.reconcile_in_flight_sweeps().await.unwrap();
        let att_reorged = repo
            .get_sweep_attempt_by_id(att_ambig.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(att_reorged.status, SweepAttemptStatus::Reorged);

        // Now live matching sweep tx (confirmed or unconfirmed) appears in out -> ALLOW_RESWEEP MUST return 409!
        let live_sweep_tx = "d1".repeat(32);
        mock_rpc.reset().await;
        mock_daemon_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_height"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "wh_amb",
                "result": { "height": 3_600_100_u64 }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "di_amb",
                "result": {
                    "height": 3_600_100_u64,
                    "target_height": 3_600_100_u64,
                    "synchronized": true,
                    "offline": false,
                    "untrusted": false,
                    "status": "OK",
                    "nettype": "mainnet"
                }
            })))
            .mount(&mock_daemon_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""pool":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "ver_amb",
                "result": {
                    "out": [{
                        "txid": live_sweep_tx,
                        "amount": 999_900_000_000_u64,
                        "fee": 100_000_000_u64,
                        "confirmations": 2,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 221 },
                        "destinations": [{
                            "amount": 999_900_000_000_u64,
                            "address": cold_addr
                        }]
                    }],
                    "pending": [],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let blocked_resweep = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"try unlock despite delayed sweep"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked_resweep.status(), StatusCode::CONFLICT);

        // 3a) MARK_RECONCILED with wrong subaddress or wrong destination address MUST reject 409!
        let wrong_subaddr_tx = "d2".repeat(32);
        let wrong_dest_tx = "d3".repeat(32);
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""pool":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "ver_mismatch",
                "result": {
                    "out": [
                        {
                            "txid": wrong_subaddr_tx,
                            "amount": 999_900_000_000_u64,
                            "fee": 100_000_000_u64,
                            "confirmations": 15,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 999 },
                            "destinations": [{
                                "amount": 999_900_000_000_u64,
                                "address": cold_addr
                            }]
                        },
                        {
                            "txid": wrong_dest_tx,
                            "amount": 999_900_000_000_u64,
                            "fee": 100_000_000_u64,
                            "confirmations": 15,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 221 },
                            "destinations": [{
                                "amount": 999_900_000_000_u64,
                                "address": other_cold_addr
                            }]
                        },
                        {
                            "txid": live_sweep_tx,
                            "amount": 999_900_000_000_u64,
                            "fee": 100_000_000_u64,
                            "confirmations": 2,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 221 },
                            "destinations": [{
                                "amount": 999_900_000_000_u64,
                                "address": cold_addr
                            }]
                        }
                    ],
                    "pending": [],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        for bad_rep in [&wrong_subaddr_tx, &wrong_dest_tx] {
            let bad_resp = app
                .clone()
                .oneshot(
                    Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                        .header("content-type", "application/json")
                        .header("X-API-Key", cfg.api_secret_key.as_str())
                        .body(Body::from(
                            serde_json::json!({
                                "action": "mark_reconciled",
                                "replacement_tx_hash": bad_rep,
                                "operator_note": "mismatch check"
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(bad_resp.status(), StatusCode::CONFLICT);
        }

        // 3b) MARK_RECONCILED with valid unconfirmed replacement tx (confs=2 < 15):
        //     marks snapshot subaddress_transfers SWEPT, sets invoice SWEPT, queues SWEPT webhook!
        let rec_resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        serde_json::json!({
                            "action": "mark_reconciled",
                            "replacement_tx_hash": live_sweep_tx,
                            "operator_note": "observed broadcast sweep in wallet out"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rec_resp.status(), StatusCode::OK);
        let rec_dto: ResolveSweepIncidentResponse =
            serde_json::from_slice(&rec_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(rec_dto.status, InvoiceStatus::Swept);
        assert_eq!(
            rec_dto.resolved_attempt.status,
            SweepAttemptStatus::Reconciled
        );
        assert_eq!(
            rec_dto.resolved_attempt.tx_hashes,
            vec![live_sweep_tx.clone()]
        );

        let sub_after = repo
            .list_subaddress_transfers_for_invoice(inv.id)
            .await
            .unwrap();
        assert_eq!(sub_after.len(), 1);
        assert!(sub_after[0].swept);
        assert_eq!(sub_after[0].status, SubaddressTransferStatus::Swept);

        let inv_hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        assert!(inv_hooks.iter().any(|w| {
            w.event_type == WebhookEventType::Swept && w.payload_json.contains(&live_sweep_tx)
        }));

        // 3c) Unconfirmed replacement tx disappears from out/pending on next scan -> re-escalates to REORGED!
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""out":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "out_vanished",
                "result": { "out": [], "pending": [] }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_after",
                "result": {
                    "in": [{
                        "txid": in_tx,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 18,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 221 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        let inv_rereorged = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(inv_rereorged.status, InvoiceStatus::Reorged);
        let att_rereorged = repo
            .get_sweep_attempt_by_id(att_ambig.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(att_rereorged.status, SweepAttemptStatus::Reorged);
        assert!(
            att_rereorged
                .error_message
                .as_deref()
                .is_some_and(|m| m.contains("SWEEP_REORG_DETECTED") && m.contains(&live_sweep_tx))
        );
    }

    // Also verify old dead hash purge on MARK_RECONCILED when replacing a prior recorded hash
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
        let app = build_router(AppState {
            config: cfg.clone(),
            repo: repo.clone(),
            rpc,
            scanner,
        });

        let mut inv = make_invoice(222, 1_000_000_000_000, None);
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let dead_hash = "e1".repeat(32);
        let rep_hash = "e2".repeat(32);
        let att = repo
            .create_prepared_sweep_attempt(inv.id, inv.address_index, cold_addr, Utc::now())
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: att.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Submitted,
            sweep_tx_hashes: vec![dead_hash.clone()],
            sweep_amount_piconero: Piconero(999_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now: Utc::now(),
        })
        .await
        .unwrap();
        repo.mark_sweep_attempt_reorged(
            att.id,
            inv.id,
            "SWEEP_REORG_DETECTED: dead sweep",
            None,
            Utc::now(),
        )
        .await
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""pool":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "ver_purge",
                "result": {
                    "out": [{
                        "txid": rep_hash,
                        "amount": 999_700_000_000_u64,
                        "fee": 300_000_000_u64,
                        "confirmations": 16,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 222 },
                        "destinations": [{
                            "amount": 999_700_000_000_u64,
                            "address": cold_addr
                        }]
                    }],
                    "pending": [],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let ok = app
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        serde_json::json!({
                            "action": "mark_reconciled",
                            "replacement_tx_hash": rep_hash,
                            "operator_note": "replaced dead sweep hash"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let updated_inv = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(updated_inv.sweep_tx_hashes, vec![rep_hash]);
        assert!(!updated_inv.sweep_tx_hashes.contains(&dead_hash));
        assert_eq!(
            updated_inv.sweep_amount_piconero,
            Some(Piconero(999_700_000_000))
        );
        assert_eq!(updated_inv.sweep_fee_piconero, Some(Piconero(300_000_000)));
        let updated_att = repo.get_sweep_attempt_by_id(att.id).await.unwrap().unwrap();
        assert_eq!(
            updated_att.swept_amount_piconero,
            Some(Piconero(999_700_000_000))
        );
        assert_eq!(updated_att.fee_piconero, Some(Piconero(300_000_000)));
    }
}

#[tokio::test]
async fn regression_phase35_a3_1_sweep_all_rpc_error_whitelist_fail_closed() {
    // 1) Verify exact pre-commit whitelist vs ambiguous/post-commit-capable codes
    for pre_commit_code in [
        -2, -5, -7, -13, -14, -15, -16, -17, -19, -20, -37, -46, -48, -50, -51, -52, -32700,
        -32600, -32601, -32602,
    ] {
        assert!(
            is_proven_pre_broadcast_rpc_error(Some(pre_commit_code)),
            "code {pre_commit_code} should be treated as proven pre-broadcast"
        );
    }
    for ambiguous_code in [Some(-4), Some(-38), Some(-3), Some(-1), Some(-32603), None] {
        assert!(
            !is_proven_pre_broadcast_rpc_error(ambiguous_code),
            "ambiguous/post-commit code {ambiguous_code:?} MUST stay fail-closed (PREPARED)"
        );
    }

    // 2) Code -4 (WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR) MUST retain PREPARED,
    //    block duplicate sweep_all during grace window, and reconcile if TX #0 was broadcast!
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());

        let mut inv = make_invoice(301, 1_000_000_000_000, None);
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let in_tx = "1a".repeat(32);
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_1",
                "result": {
                    "in": [{
                        "txid": in_tx,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 301 }
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
                "id": "sw_minus4",
                "error": { "code": -4, "message": "failed to relay tx #1 after tx #0 committed" }
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let err = scanner.manual_sweep(inv.id).await.unwrap_err();
        assert!(matches!(err, GatewayError::Rpc { code: Some(-4), .. }));

        let attempts = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].status,
            SweepAttemptStatus::Prepared,
            "code -4 MUST NOT mark attempt FAILED"
        );

        // Next tick within grace window sees empty out/pending -> MUST NOT re-invoke sweep_all!
        mock_rpc.reset().await;
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
                "id": "out_grace",
                "result": { "out": [], "pending": [] }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_2",
                "result": {
                    "in": [{
                        "txid": in_tx,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 301 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let rep = scanner.scan_once().await.unwrap();
        assert_eq!(rep.invoices_swept, 0);
        assert_eq!(
            repo.get_sweep_attempt_by_id(attempts[0].id)
                .await
                .unwrap()
                .unwrap()
                .status,
            SweepAttemptStatus::Prepared
        );

        // TX #0 appears in outgoing wallet history -> reconciles cleanly to RECONCILED + SWEPT!
        let tx0_hash = "1b".repeat(32);
        mock_rpc.reset().await;
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
                "id": "out_tx0",
                "result": {
                    "out": [{
                        "txid": tx0_hash,
                        "amount": 999_900_000_000_u64,
                        "fee": 100_000_000_u64,
                        "confirmations": 2,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 301 },
                        "destinations": [{ "amount": 999_900_000_000_u64, "address": cold_addr }]
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
                "id": "in_3",
                "result": {
                    "in": [{
                        "txid": in_tx,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 16,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 301 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let rep2 = scanner.scan_once().await.unwrap();
        assert_eq!(rep2.invoices_swept, 1);
        assert_eq!(
            repo.get_sweep_attempt_by_id(attempts[0].id)
                .await
                .unwrap()
                .unwrap()
                .status,
            SweepAttemptStatus::Reconciled
        );
        assert_eq!(
            repo.get_invoice_by_id(inv.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            InvoiceStatus::Swept
        );
    }

    // 3) Code -38 (WALLET_RPC_ERROR_CODE_NO_CONNECTION_TO_DAEMON) MUST also retain PREPARED
    //    and reject immediate duplicate manual_sweep with Conflict!
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());

        let mut inv = make_invoice(302, 1_000_000_000_000, None);
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let in_tx = "2a".repeat(32);
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_38",
                "result": {
                    "in": [{
                        "txid": in_tx,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 302 }
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
                "id": "sw_minus38",
                "error": { "code": -38, "message": "no connection to daemon" }
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let err = scanner.manual_sweep(inv.id).await.unwrap_err();
        assert!(matches!(
            err,
            GatewayError::Rpc {
                code: Some(-38),
                ..
            }
        ));
        let attempts = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].status, SweepAttemptStatus::Prepared);

        // Retry while PREPARED and out/pending empty -> Conflict without calling sweep_all!
        mock_rpc.reset().await;
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
                "id": "out_38",
                "result": { "out": [], "pending": [] }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_38_2",
                "result": {
                    "in": [{
                        "txid": in_tx,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 302 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        assert!(matches!(
            scanner.manual_sweep(inv.id).await,
            Err(GatewayError::Conflict(_))
        ));
    }
}

#[tokio::test]
async fn regression_phase35_a3_2_locked_overpayment_excluded_from_snapshot_and_sweep() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool.clone());
    let mock_rpc = MockServer::start().await;
    // required_confirmations = 2, settlement_confirmations = 10
    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 2, 10);
    let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());

    let mut inv = make_invoice(303, 1_000_000_000_000, None);
    inv.status = InvoiceStatus::Settled;
    inv.received_piconero = Piconero(1_000_000_000_000);
    inv.confirmations = 12;
    inv.unlocked = true;
    repo.insert_invoice(&inv).await.unwrap();

    let tx1 = "31".repeat(32);
    let tx2 = "32".repeat(32);
    let now = Utc::now();

    // Record unlocked primary tx1 (12 confs) + concurrent locked overpayment tx2 (2 confs)
    repo.record_subaddress_transfer(RecordSubaddressTransferParams {
        transfer: ObservedTransfer {
            txid: tx1.clone(),
            amount_piconero: Piconero(1_000_000_000_000),
            confirmations: 12,
            in_pool: false,
            unlocked: true,
            double_spend_seen: false,
            orphaned: false,
        },
        record: SubaddressTransferRecord {
            id: 0,
            txid: tx1.clone(),
            invoice_id: inv.id,
            address_index: inv.address_index,
            amount_piconero: Piconero(1_000_000_000_000),
            confirmations: 12,
            classification: TransferClassification::Expected,
            status: SubaddressTransferStatus::Active,
            swept: false,
            sweep_attempt_id: None,
            created_at: now - ChronoDuration::seconds(10),
        },
        received_piconero: Piconero(1_000_000_000_000),
        confirmations: 12,
        unlocked: true,
        webhook: None,
        now: now - ChronoDuration::seconds(10),
    })
    .await
    .unwrap();

    repo.record_subaddress_transfer(RecordSubaddressTransferParams {
        transfer: ObservedTransfer {
            txid: tx2.clone(),
            amount_piconero: Piconero(250_000_000_000),
            confirmations: 2,
            in_pool: false,
            unlocked: false,
            double_spend_seen: false,
            orphaned: false,
        },
        record: SubaddressTransferRecord {
            id: 0,
            txid: tx2.clone(),
            invoice_id: inv.id,
            address_index: inv.address_index,
            amount_piconero: Piconero(250_000_000_000),
            confirmations: 2,
            classification: TransferClassification::Overpayment,
            status: SubaddressTransferStatus::Active,
            swept: false,
            sweep_attempt_id: None,
            created_at: now - ChronoDuration::seconds(5),
        },
        received_piconero: Piconero(1_250_000_000_000),
        confirmations: 12,
        unlocked: false,
        webhook: None,
        now: now - ChronoDuration::seconds(5),
    })
    .await
    .unwrap();

    // 1) Snapshot preparation MUST include ONLY unlocked/settled tx1 and EXCLUDE locked tx2!
    let att1 = repo
        .create_prepared_sweep_attempt_with_min_confs(inv.id, inv.address_index, cold_addr, 10, now)
        .await
        .unwrap();
    assert_eq!(att1.snapshot_txids, vec![tx1.clone()]);

    // 2) Completing attempt 1 marks ONLY tx1 SWEPT; locked tx2 remains ACTIVE, swept=false!
    let sweep1_tx = "33".repeat(32);
    repo.complete_sweep_attempt_with_min_confs(
        CompleteSweepAttemptParams {
            attempt_id: att1.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Confirmed,
            sweep_tx_hashes: vec![sweep1_tx],
            sweep_amount_piconero: Piconero(999_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now,
        },
        10,
    )
    .await
    .unwrap();

    let rows = repo
        .list_subaddress_transfers_for_invoice(inv.id)
        .await
        .unwrap();
    let r1 = rows.iter().find(|r| r.txid == tx1).unwrap();
    let r2 = rows.iter().find(|r| r.txid == tx2).unwrap();
    assert!(r1.swept && r1.status == SubaddressTransferStatus::Swept);
    assert!(!r2.swept && r2.status == SubaddressTransferStatus::Active);
    assert_eq!(r2.sweep_attempt_id, None);
    assert!(
        !repo.has_unswept_inflows(inv.id, 10).await.unwrap(),
        "locked 2-conf overpayment MUST NOT count as sweepable at min_sweep_confs=10"
    );

    // 3) Once tx2 reaches 10 confirmations (unlocked), scan_once auto-sweeps tx2 cleanly!
    let sweep2_tx = "34".repeat(32);
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "out_a32",
            "result": {
                "out": [{
                    "txid": "33".repeat(32),
                    "amount": 999_900_000_000_u64,
                    "fee": 100_000_000_u64,
                    "confirmations": 12,
                    "double_spend_seen": false,
                    "subaddr_index": { "major": 0, "minor": 303 },
                    "destinations": [{ "amount": 999_900_000_000_u64, "address": cold_addr }]
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
            "id": "in_a32",
            "result": {
                "in": [
                    {
                        "txid": tx1,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 20,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 303 }
                    },
                    {
                        "txid": tx2,
                        "amount": 250_000_000_000_u64,
                        "confirmations": 10,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 303 }
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
            "id": "sw_a32",
            "result": {
                "tx_hash_list": [sweep2_tx],
                "amount_list": [249_900_000_000_u64],
                "fee_list": [100_000_000_u64]
            }
        })))
        .expect(1)
        .mount(&mock_rpc)
        .await;

    let report = scanner.scan_once().await.unwrap();
    assert_eq!(report.invoices_swept, 1);
    let rows_after = repo
        .list_subaddress_transfers_for_invoice(inv.id)
        .await
        .unwrap();
    assert!(
        rows_after
            .iter()
            .all(|r| r.swept && r.status == SubaddressTransferStatus::Swept)
    );

    // 4) Legacy empty-snapshot fallback in mark_snapshot_transfers_swept_tx MUST also skip locked tx!
    let mut inv_legacy = make_invoice(304, 1_000_000_000_000, None);
    inv_legacy.status = InvoiceStatus::Settled;
    inv_legacy.received_piconero = Piconero(1_000_000_000_000);
    inv_legacy.confirmations = 12;
    inv_legacy.unlocked = true;
    repo.insert_invoice(&inv_legacy).await.unwrap();

    let tx_unlk = "35".repeat(32);
    let tx_lock = "36".repeat(32);
    repo.record_subaddress_transfer(RecordSubaddressTransferParams {
        transfer: ObservedTransfer {
            txid: tx_unlk.clone(),
            amount_piconero: Piconero(1_000_000_000_000),
            confirmations: 12,
            in_pool: false,
            unlocked: true,
            double_spend_seen: false,
            orphaned: false,
        },
        record: SubaddressTransferRecord {
            id: 0,
            txid: tx_unlk.clone(),
            invoice_id: inv_legacy.id,
            address_index: inv_legacy.address_index,
            amount_piconero: Piconero(1_000_000_000_000),
            confirmations: 12,
            classification: TransferClassification::Expected,
            status: SubaddressTransferStatus::Active,
            swept: false,
            sweep_attempt_id: None,
            created_at: now - ChronoDuration::seconds(10),
        },
        received_piconero: Piconero(1_000_000_000_000),
        confirmations: 12,
        unlocked: true,
        webhook: None,
        now: now - ChronoDuration::seconds(10),
    })
    .await
    .unwrap();
    repo.record_subaddress_transfer(RecordSubaddressTransferParams {
        transfer: ObservedTransfer {
            txid: tx_lock.clone(),
            amount_piconero: Piconero(250_000_000_000),
            confirmations: 2,
            in_pool: false,
            unlocked: false,
            double_spend_seen: false,
            orphaned: false,
        },
        record: SubaddressTransferRecord {
            id: 0,
            txid: tx_lock.clone(),
            invoice_id: inv_legacy.id,
            address_index: inv_legacy.address_index,
            amount_piconero: Piconero(250_000_000_000),
            confirmations: 2,
            classification: TransferClassification::Overpayment,
            status: SubaddressTransferStatus::Active,
            swept: false,
            sweep_attempt_id: None,
            created_at: now - ChronoDuration::seconds(5),
        },
        received_piconero: Piconero(1_250_000_000_000),
        confirmations: 12,
        unlocked: false,
        webhook: None,
        now: now - ChronoDuration::seconds(5),
    })
    .await
    .unwrap();

    // Seed a legacy PREPARED attempt with empty snapshot_txids_json='[]'
    let legacy_att_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO sweep_attempts (
            id, invoice_id, address_index, destination_address, snapshot_txids_json,
            status, tx_hashes_json, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, '[]', 'PREPARED', '[]', ?, ?)
        "#,
    )
    .bind(legacy_att_id.to_string())
    .bind(inv_legacy.id.to_string())
    .bind(i64::from(inv_legacy.address_index))
    .bind(cold_addr)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(&pool)
    .await
    .unwrap();

    repo.complete_sweep_attempt_with_min_confs(
        CompleteSweepAttemptParams {
            attempt_id: legacy_att_id,
            invoice_id: inv_legacy.id,
            attempt_status: SweepAttemptStatus::Submitted,
            sweep_tx_hashes: vec!["37".repeat(32)],
            sweep_amount_piconero: Piconero(999_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now,
        },
        10,
    )
    .await
    .unwrap();

    let legacy_rows = repo
        .list_subaddress_transfers_for_invoice(inv_legacy.id)
        .await
        .unwrap();
    let lu = legacy_rows.iter().find(|r| r.txid == tx_unlk).unwrap();
    let ll = legacy_rows.iter().find(|r| r.txid == tx_lock).unwrap();
    assert!(lu.swept && lu.status == SubaddressTransferStatus::Swept);
    assert!(
        !ll.swept && ll.status == SubaddressTransferStatus::Active,
        "legacy fallback MUST NOT mark locked overpayment SWEPT"
    );
}

#[tokio::test]
async fn regression_phase35_a3_3_and_a3_4_secondary_sweep_reorg_and_apply_scan_update() {
    // Part A (`A3-3`): Secondary overpayment sweep hitting SWEEP_AMBIGUOUS_TIMEOUT on SWEPT invoice
    //                  MUST preserve invoices.status = SWEPT and swept_at while still escalating
    //                  attempt -> REORGED, bumping reorg_epoch, and queuing REORGED webhook.
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let mock_daemon = MockServer::start().await;
        let mut cfg_owned =
            (*test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15)).clone();
        cfg_owned.monero_daemon_rpc_url = Some(format!("{}/json_rpc", mock_daemon.uri()));
        let cfg = Arc::new(cfg_owned);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
        let app = build_router(AppState {
            config: cfg.clone(),
            repo: repo.clone(),
            rpc,
            scanner: scanner.clone(),
        });

        let mut inv = make_invoice(
            305,
            1_000_000_000_000,
            Some("http://127.0.0.1:9999/a33".to_string()),
        );
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let tx_primary = "41".repeat(32);
        let tx_overpay = "42".repeat(32);
        let sweep_primary = "43".repeat(32);
        let t0 = Utc::now() - ChronoDuration::minutes(5);

        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: tx_primary.clone(),
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 20,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: tx_primary.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 20,
                classification: TransferClassification::Expected,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: t0,
            },
            received_piconero: Piconero(1_000_000_000_000),
            confirmations: 20,
            unlocked: true,
            webhook: None,
            now: t0,
        })
        .await
        .unwrap();

        let att1 = repo
            .create_prepared_sweep_attempt_with_min_confs(
                inv.id,
                inv.address_index,
                cold_addr,
                15,
                t0,
            )
            .await
            .unwrap();
        let inv_swept = repo
            .complete_sweep_attempt_with_min_confs(
                CompleteSweepAttemptParams {
                    attempt_id: att1.id,
                    invoice_id: inv.id,
                    attempt_status: SweepAttemptStatus::Confirmed,
                    sweep_tx_hashes: vec![sweep_primary.clone()],
                    sweep_amount_piconero: Piconero(999_900_000_000),
                    sweep_fee_piconero: Piconero(100_000_000),
                    webhook: None,
                    now: t0,
                },
                15,
            )
            .await
            .unwrap();
        assert_eq!(inv_swept.status, InvoiceStatus::Swept);
        let orig_swept_at = inv_swept.swept_at.unwrap();

        // Overpayment arrives and creates a second PREPARED sweep attempt aged 90s (> grace window)
        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: tx_overpay.clone(),
                amount_piconero: Piconero(250_000_000_000),
                confirmations: 15,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: tx_overpay.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(250_000_000_000),
                confirmations: 15,
                classification: TransferClassification::Overpayment,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: Utc::now() - ChronoDuration::seconds(100),
            },
            received_piconero: Piconero(1_250_000_000_000),
            confirmations: 15,
            unlocked: true,
            webhook: None,
            now: Utc::now() - ChronoDuration::seconds(100),
        })
        .await
        .unwrap();

        let att2 = repo
            .create_prepared_sweep_attempt_with_min_confs(
                inv.id,
                inv.address_index,
                cold_addr,
                15,
                Utc::now() - ChronoDuration::seconds(90),
            )
            .await
            .unwrap();
        assert_eq!(att2.snapshot_txids, vec![tx_overpay.clone()]);

        // Outgoing RPC shows primary sweep intact, secondary attempt absent -> SWEEP_AMBIGUOUS_TIMEOUT
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""out":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "out_a33",
                "result": {
                    "out": [{
                        "txid": sweep_primary,
                        "amount": 999_900_000_000_u64,
                        "fee": 100_000_000_u64,
                        "confirmations": 20,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 305 },
                        "destinations": [{ "amount": 999_900_000_000_u64, "address": cold_addr }]
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
                "id": "in_a33",
                "result": {
                    "in": [
                        {
                            "txid": tx_primary,
                            "amount": 1_000_000_000_000_u64,
                            "confirmations": 25,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 305 }
                        },
                        {
                            "txid": tx_overpay,
                            "amount": 250_000_000_000_u64,
                            "confirmations": 16,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 305 }
                        }
                    ],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();

        let att2_after = repo
            .get_sweep_attempt_by_id(att2.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(att2_after.status, SweepAttemptStatus::Reorged);

        let inv_after_timeout = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(
            inv_after_timeout.status,
            InvoiceStatus::Swept,
            "primary sweep intact: invoice MUST remain SWEPT (`A3-3`)"
        );
        assert_eq!(inv_after_timeout.reorg_epoch, 1);
        assert_eq!(inv_after_timeout.swept_at, Some(orig_swept_at));

        let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].event_type, WebhookEventType::Reorged);
        assert!(hooks[0].payload_json.contains(r#""status":"SWEPT""#));

        // Operator resolves via ALLOW_RESWEEP -> status & swept_at preserved, no duplicate CONFIRMED/SETTLED!
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_height"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "wh_a33",
                "result": { "height": 3_700_000_u64 }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""pool":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "tr_a33",
                "result": {
                    "out": [{
                        "txid": sweep_primary,
                        "amount": 999_900_000_000_u64,
                        "fee": 100_000_000_u64,
                        "confirmations": 20,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 305 },
                        "destinations": [{ "amount": 999_900_000_000_u64, "address": cold_addr }]
                    }],
                    "pending": [],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "di_a33",
                "result": {
                    "height": 3_700_000_u64,
                    "target_height": 3_700_000_u64,
                    "synchronized": true,
                    "offline": false,
                    "untrusted": false,
                    "status": "OK",
                    "nettype": "mainnet"
                }
            })))
            .mount(&mock_daemon)
            .await;

        let res_resp = app
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"secondary overpayment sweep confirmed absent"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_resp.status(), StatusCode::OK);

        let inv_after_resolve = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(inv_after_resolve.status, InvoiceStatus::Swept);
        assert_eq!(inv_after_resolve.swept_at, Some(orig_swept_at));
        assert_eq!(inv_after_resolve.sweep_tx_hashes, vec![sweep_primary]);

        let hooks_after = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        assert!(
            !hooks_after.iter().any(|h| matches!(
                h.event_type,
                WebhookEventType::Confirmed | WebhookEventType::Settled
            )),
            "ALLOW_RESWEEP on SWEPT invoice MUST NOT re-emit CONFIRMED or SETTLED webhooks"
        );
    }

    // Part B (`A3-4`): apply_scan_update terminal guards for SWEPT and COMPLETED
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);

        let mut inv_swept = make_invoice(306, 1_000_000_000_000, None);
        inv_swept.status = InvoiceStatus::Swept;
        inv_swept.received_piconero = Piconero(1_000_000_000_000);
        inv_swept.confirmations = 15;
        inv_swept.unlocked = true;
        repo.insert_invoice(&inv_swept).await.unwrap();

        // SWEPT invoice preserves SWEPT even if a stale apply_scan_update arrives with next_status=Reorged or double_spend_seen=true
        let kept_swept = repo
            .apply_scan_update(ApplyScanUpdateParams {
                invoice_id: inv_swept.id,
                received_piconero: Piconero(1_000_000_000_000),
                confirmations: 15,
                unlocked: true,
                double_spend_seen: true,
                next_status: InvoiceStatus::Reorged,
                transfers: vec![],
                webhook: None,
                now: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(kept_swept.status, InvoiceStatus::Swept);

        let mut inv_completed = make_invoice(307, 1_000_000_000_000, None);
        inv_completed.status = InvoiceStatus::Completed;
        inv_completed.received_piconero = Piconero(1_000_000_000_000);
        inv_completed.confirmations = 15;
        inv_completed.unlocked = true;
        repo.insert_invoice(&inv_completed).await.unwrap();

        // COMPLETED with double_spend_seen=true and non-Reorged next_status MUST NOT fail InvalidStateTransition!
        let kept_completed = repo
            .apply_scan_update(ApplyScanUpdateParams {
                invoice_id: inv_completed.id,
                received_piconero: Piconero(1_000_000_000_000),
                confirmations: 15,
                unlocked: true,
                double_spend_seen: true,
                next_status: InvoiceStatus::Settled,
                transfers: vec![],
                webhook: None,
                now: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(kept_completed.status, InvoiceStatus::Completed);

        // COMPLETED with next_status=Reorged MUST still transition to REORGED (deep reorg detection)
        let reorged_completed = repo
            .apply_scan_update(ApplyScanUpdateParams {
                invoice_id: inv_completed.id,
                received_piconero: Piconero::ZERO,
                confirmations: 0,
                unlocked: false,
                double_spend_seen: true,
                next_status: InvoiceStatus::Reorged,
                transfers: vec![],
                webhook: None,
                now: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(reorged_completed.status, InvoiceStatus::Reorged);
    }
}

#[tokio::test]
async fn regression_phase35_a4_1_to_a4_4_mark_reconciled_hardening_and_unconditional_monitoring() {
    // Part 1 (`A4-1`, `A4-2`, `A4-3`): strict destination, txid binding, dust check, and amount/fee propagation
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap().to_string();
        let attacker_addr = encode_monero_base58_address(18, &[0xAB; 32], &[0xCD; 32], None);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
        let app = build_router(AppState {
            config: cfg.clone(),
            repo: repo.clone(),
            rpc,
            scanner,
        });

        // Another invoice with an already-bound sweep txid (cross-invoice reuse check)
        let mut other_inv = make_invoice(310, 1_000_000_000_000, None);
        other_inv.status = InvoiceStatus::Settled;
        other_inv.received_piconero = Piconero(1_000_000_000_000);
        other_inv.confirmations = 15;
        other_inv.unlocked = true;
        repo.insert_invoice(&other_inv).await.unwrap();
        let other_bound_tx = "50".repeat(32);
        let other_att = repo
            .create_prepared_sweep_attempt(
                other_inv.id,
                other_inv.address_index,
                &cold_addr,
                Utc::now(),
            )
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: other_att.id,
            invoice_id: other_inv.id,
            attempt_status: SweepAttemptStatus::Confirmed,
            sweep_tx_hashes: vec![other_bound_tx.clone()],
            sweep_amount_piconero: Piconero(999_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now: Utc::now(),
        })
        .await
        .unwrap();

        // Target invoice with primary confirmed sweep + secondary REORGED attempt (to also test same-invoice reuse)
        let mut inv = make_invoice(
            311,
            1_000_000_000_000,
            Some("http://127.0.0.1:9999/a4".to_string()),
        );
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let in_tx = "51".repeat(32);
        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: in_tx.clone(),
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 15,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: in_tx.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 15,
                classification: TransferClassification::Expected,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: Utc::now(),
            },
            received_piconero: Piconero(1_000_000_000_000),
            confirmations: 15,
            unlocked: true,
            webhook: None,
            now: Utc::now(),
        })
        .await
        .unwrap();

        // Timed-out PREPARED attempt -> REORGED (swept_amount_piconero=None, fee_piconero=None)
        let att = repo
            .create_prepared_sweep_attempt_with_min_confs(
                inv.id,
                inv.address_index,
                &cold_addr,
                15,
                Utc::now() - ChronoDuration::seconds(90),
            )
            .await
            .unwrap();
        repo.mark_sweep_attempt_reorged(
            att.id,
            inv.id,
            "SWEEP_AMBIGUOUS_TIMEOUT: ambiguous broadcast",
            None,
            Utc::now(),
        )
        .await
        .unwrap();

        let empty_dest_tx = "52".repeat(32);
        let split_leak_tx = "53".repeat(32);
        let dust_tx = "54".repeat(32);
        let valid_tx = "55".repeat(32);

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""pool":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "ver_a4",
                "result": {
                    "out": [
                        {
                            "txid": empty_dest_tx,
                            "amount": 999_900_000_000_u64,
                            "fee": 100_000_000_u64,
                            "confirmations": 5,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 311 }
                        },
                        {
                            "txid": split_leak_tx,
                            "amount": 1_000_000_000_000_u64,
                            "fee": 100_000_000_u64,
                            "confirmations": 5,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 311 },
                            "destinations": [
                                { "amount": 999_500_000_000_u64, "address": cold_addr },
                                { "amount": 500_000_000_u64, "address": attacker_addr }
                            ]
                        },
                        {
                            "txid": dust_tx,
                            "amount": 1_u64,
                            "fee": 100_000_000_u64,
                            "confirmations": 5,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 311 },
                            "destinations": [
                                { "amount": 1_u64, "address": cold_addr }
                            ]
                        },
                        {
                            "txid": other_bound_tx,
                            "amount": 999_900_000_000_u64,
                            "fee": 100_000_000_u64,
                            "confirmations": 15,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 311 },
                            "destinations": [
                                { "amount": 999_900_000_000_u64, "address": cold_addr }
                            ]
                        },
                        {
                            "txid": valid_tx,
                            "amount": 999_850_000_000_u64,
                            "fee": 150_000_000_u64,
                            "confirmations": 5,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 311 },
                            "destinations": [
                                { "amount": 999_850_000_000_u64, "address": cold_addr }
                            ]
                        }
                    ],
                    "pending": [],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        // Reject all 4 attack/invalid cases with 409 Conflict (`A4-1` + `A4-2`)
        for (label, bad_tx) in [
            ("empty destinations", &empty_dest_tx),
            ("multi-destination leak", &split_leak_tx),
            ("dust amount", &dust_tx),
            ("cross-invoice txid reuse", &other_bound_tx),
        ] {
            let resp = app
                .clone()
                .oneshot(
                    Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                        .header("content-type", "application/json")
                        .header("X-API-Key", cfg.api_secret_key.as_str())
                        .body(Body::from(
                            serde_json::json!({
                                "action": "mark_reconciled",
                                "replacement_tx_hash": bad_tx,
                                "operator_note": format!("test reject {label}")
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::CONFLICT,
                "MARK_RECONCILED MUST reject {label} with 409"
            );
        }

        // Valid MARK_RECONCILED propagates verified amount & fee to attempt, invoice, and SWEPT webhook (`A4-3`)
        let ok_resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        serde_json::json!({
                            "action": "mark_reconciled",
                            "replacement_tx_hash": valid_tx,
                            "operator_note": "verified valid cold sweep"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok_resp.status(), StatusCode::OK);
        let dto: ResolveSweepIncidentResponse =
            serde_json::from_slice(&ok_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(dto.status, InvoiceStatus::Swept);
        assert_eq!(
            dto.resolved_attempt.swept_amount_piconero,
            Some(999_850_000_000)
        );
        assert_eq!(dto.resolved_attempt.fee_piconero, Some(150_000_000));

        let inv_after = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(
            inv_after.sweep_amount_piconero,
            Some(Piconero(999_850_000_000))
        );
        assert_eq!(inv_after.sweep_fee_piconero, Some(Piconero(150_000_000)));

        let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
        let swept_hook = hooks
            .iter()
            .find(|h| h.event_type == WebhookEventType::Swept)
            .expect("SWEPT webhook must be queued");
        assert!(
            swept_hook
                .payload_json
                .contains(r#""sweep_amount_piconero":999850000000"#),
            "SWEPT webhook must carry verified sweep_amount_piconero: {}",
            swept_hook.payload_json
        );
        assert!(
            swept_hook
                .payload_json
                .contains(r#""sweep_fee_piconero":150000000"#),
            "SWEPT webhook must carry verified sweep_fee_piconero: {}",
            swept_hook.payload_json
        );

        // Same-invoice primary txid reuse on a second REORGED attempt MUST also return 409 (`A4-2`)
        let att_dup = repo
            .create_prepared_sweep_attempt(inv.id, inv.address_index, &cold_addr, Utc::now())
            .await
            .unwrap();
        repo.mark_sweep_attempt_reorged(
            att_dup.id,
            inv.id,
            "SWEEP_AMBIGUOUS_TIMEOUT: secondary",
            None,
            Utc::now(),
        )
        .await
        .unwrap();

        let same_inv_reuse = app
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        serde_json::json!({
                            "action": "mark_reconciled",
                            "replacement_tx_hash": valid_tx,
                            "operator_note": "attempting same-invoice primary hash reuse"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(same_inv_reuse.status(), StatusCode::CONFLICT);
    }

    // Part 2 (`A4-4`): Unconfirmed RECONCILED sweep attempt on an invoice older than SUBADDRESS_MONITOR_DAYS
    //                  MUST remain monitored unconditionally and escalate to REORGED if it disappears!
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let mut cfg_owned =
            (*test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15)).clone();
        cfg_owned.subaddress_monitor_days = 1;
        let cfg = Arc::new(cfg_owned);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());

        let old_ts = Utc::now() - ChronoDuration::days(5);
        let mut old_inv_reconciled = make_invoice(312, 1_000_000_000_000, None);
        old_inv_reconciled.status = InvoiceStatus::Settled;
        old_inv_reconciled.received_piconero = Piconero(1_000_000_000_000);
        old_inv_reconciled.confirmations = 15;
        old_inv_reconciled.unlocked = true;
        old_inv_reconciled.created_at = old_ts;
        old_inv_reconciled.updated_at = old_ts;
        repo.insert_invoice(&old_inv_reconciled).await.unwrap();

        let unconfirmed_rec_tx = "60".repeat(32);
        let att_rec = repo
            .create_prepared_sweep_attempt(
                old_inv_reconciled.id,
                old_inv_reconciled.address_index,
                cold_addr,
                old_ts,
            )
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: att_rec.id,
            invoice_id: old_inv_reconciled.id,
            attempt_status: SweepAttemptStatus::Reconciled,
            sweep_tx_hashes: vec![unconfirmed_rec_tx.clone()],
            sweep_amount_piconero: Piconero(999_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now: Utc::now(),
        })
        .await
        .unwrap();

        // Companion equally old invoice with CONFIRMED attempt MUST be filtered out by the 1-day cutoff
        let mut old_inv_confirmed = make_invoice(313, 1_000_000_000_000, None);
        old_inv_confirmed.status = InvoiceStatus::Settled;
        old_inv_confirmed.received_piconero = Piconero(1_000_000_000_000);
        old_inv_confirmed.confirmations = 15;
        old_inv_confirmed.unlocked = true;
        old_inv_confirmed.created_at = old_ts;
        old_inv_confirmed.updated_at = old_ts;
        repo.insert_invoice(&old_inv_confirmed).await.unwrap();

        let att_conf = repo
            .create_prepared_sweep_attempt(
                old_inv_confirmed.id,
                old_inv_confirmed.address_index,
                cold_addr,
                old_ts,
            )
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: att_conf.id,
            invoice_id: old_inv_confirmed.id,
            attempt_status: SweepAttemptStatus::Confirmed,
            sweep_tx_hashes: vec!["61".repeat(32)],
            sweep_amount_piconero: Piconero(999_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now: old_ts,
        })
        .await
        .unwrap();

        let cutoff = Some(Utc::now() - ChronoDuration::days(1));
        let monitored = repo.list_monitored_sweep_attempts(cutoff).await.unwrap();
        assert_eq!(monitored.len(), 1);
        assert_eq!(monitored[0].id, att_rec.id);

        // Unconfirmed RECONCILED tx disappears from out/pending -> scanner escalates to REORGED!
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""out":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "out_a44",
                "result": { "out": [], "pending": [] }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_a44",
                "result": { "in": [], "pool": [] }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        let att_after = repo
            .get_sweep_attempt_by_id(att_rec.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(att_after.status, SweepAttemptStatus::Reorged);
        assert!(
            att_after
                .error_message
                .as_deref()
                .is_some_and(|m| m.contains(&unconfirmed_rec_tx))
        );
        let inv_after = repo
            .get_invoice_by_id(old_inv_reconciled.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inv_after.status, InvoiceStatus::Reorged);
    }
}

#[tokio::test]
async fn regression_phase37_p36_1_empty_destinations_with_sender_address_fail_closed() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;
    let mock_daemon = MockServer::start().await;
    let mut cfg_owned =
        (*test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15)).clone();
    cfg_owned.monero_daemon_rpc_url = Some(format!("{}/json_rpc", mock_daemon.uri()));
    let cfg = Arc::new(cfg_owned);
    let cold_addr = cfg.cold_wallet_address.as_deref().unwrap().to_string();
    let hot_primary_addr = encode_monero_base58_address(18, &[0x99; 32], &[0x88; 32], None);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
    let app = build_router(AppState {
        config: cfg.clone(),
        repo: repo.clone(),
        rpc,
        scanner,
    });

    // Direct unit proof: TransferEntry with empty destinations MUST fail closed even when
    // `address` matches `cold_addr` (monero-wallet-rpc v0.18.5.4 sets `address` to sender primary).
    let entry_with_sender_addr: TransferEntry = serde_json::from_value(serde_json::json!({
        "txid": "a1".repeat(32),
        "amount": 999_900_000_000_u64,
        "fee": 100_000_000_u64,
        "confirmations": 12,
        "double_spend_seen": false,
        "address": cold_addr,
        "subaddr_index": { "major": 0, "minor": 400 },
        "destinations": []
    }))
    .unwrap();
    assert_eq!(
        entry_with_sender_addr.verified_sweep_destination_amount(0, 400, &cold_addr),
        None
    );
    assert!(!entry_with_sender_addr.matches_sweep(0, 400, &cold_addr));
    assert!(entry_with_sender_addr.matches_source_subaddress(0, 400));

    let mut inv = make_invoice(400, 1_000_000_000_000, None);
    inv.status = InvoiceStatus::Settled;
    inv.received_piconero = Piconero(1_000_000_000_000);
    inv.confirmations = 15;
    inv.unlocked = true;
    repo.insert_invoice(&inv).await.unwrap();

    let att = repo
        .create_prepared_sweep_attempt(inv.id, inv.address_index, &cold_addr, Utc::now())
        .await
        .unwrap();
    repo.mark_sweep_attempt_reorged(
        att.id,
        inv.id,
        "SWEEP_AMBIGUOUS_TIMEOUT: check empty destinations",
        None,
        Utc::now(),
    )
    .await
    .unwrap();

    // 1) MARK_RECONCILED with destinations=[] and address=cold_addr MUST return 409 Conflict
    let empty_dest_same_addr_tx = "a1".repeat(32);
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""pool":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "p36_1_mark",
            "result": {
                "out": [{
                    "txid": empty_dest_same_addr_tx,
                    "amount": 999_900_000_000_u64,
                    "fee": 100_000_000_u64,
                    "confirmations": 12,
                    "double_spend_seen": false,
                    "address": cold_addr,
                    "subaddr_index": { "major": 0, "minor": 400 },
                    "destinations": []
                }],
                "pending": [],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    let mark_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    serde_json::json!({
                        "action": "mark_reconciled",
                        "replacement_tx_hash": empty_dest_same_addr_tx,
                        "operator_note": "must reject empty destinations even if address equals cold"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mark_resp.status(), StatusCode::CONFLICT);

    // 2) ALLOW_RESWEEP with an unassociated outgoing tx from subaddress 400 having destinations=[]
    //    and address=hot_primary_addr (wallet restore from seed) MUST fail-closed with 409 Conflict!
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "wh_p36_1",
            "result": { "height": 3_800_000_u64 }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""pool":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "tr_p36_1",
            "result": {
                "out": [{
                    "txid": "a2".repeat(32),
                    "amount": 999_900_000_000_u64,
                    "fee": 100_000_000_u64,
                    "confirmations": 3,
                    "double_spend_seen": false,
                    "address": hot_primary_addr,
                    "subaddr_index": { "major": 0, "minor": 0 },
                    "subaddr_indices": [{ "major": 0, "minor": 400 }],
                    "destinations": []
                }],
                "pending": [],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "di_p36_1",
            "result": {
                "height": 3_800_000_u64,
                "target_height": 3_800_000_u64,
                "synchronized": true,
                "offline": false,
                "untrusted": false,
                "status": "OK",
                "nettype": "mainnet"
            }
        })))
        .mount(&mock_daemon)
        .await;

    let resweep_resp = app
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    r#"{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"must block live unassociated tx even with empty destinations"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resweep_resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn regression_phase37_p36_2_cross_invoice_toctou_and_overpayment_dust_bypass() {
    // Part A: Concurrent cross-invoice MARK_RECONCILED on file-backed SQLite (max_connections=8)
    //         submitting the SAME replacement_tx_hash simultaneously -> strictly 1 OK + 1 Conflict!
    {
        let db_path = std::env::temp_dir().join(format!("xmr-gw-p36-2-{}.sqlite", Uuid::new_v4()));
        let db_url = format!("sqlite://{}", db_path.display());
        let pool = init_sqlite_pool(&db_url).await.unwrap();
        let repo = InvoiceRepository::new(pool.clone());
        let mock_rpc = MockServer::start().await;
        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap().to_string();
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
        let app = build_router(AppState {
            config: cfg.clone(),
            repo: repo.clone(),
            rpc,
            scanner,
        });

        let mut inv_a = make_invoice(401, 1_000_000_000_000, None);
        inv_a.status = InvoiceStatus::Settled;
        inv_a.received_piconero = Piconero(1_000_000_000_000);
        inv_a.confirmations = 15;
        inv_a.unlocked = true;
        repo.insert_invoice(&inv_a).await.unwrap();

        let mut inv_b = make_invoice(402, 1_000_000_000_000, None);
        inv_b.status = InvoiceStatus::Settled;
        inv_b.received_piconero = Piconero(1_000_000_000_000);
        inv_b.confirmations = 15;
        inv_b.unlocked = true;
        repo.insert_invoice(&inv_b).await.unwrap();

        let att_a = repo
            .create_prepared_sweep_attempt(inv_a.id, inv_a.address_index, &cold_addr, Utc::now())
            .await
            .unwrap();
        repo.mark_sweep_attempt_reorged(
            att_a.id,
            inv_a.id,
            "SWEEP_AMBIGUOUS_TIMEOUT",
            None,
            Utc::now(),
        )
        .await
        .unwrap();

        let att_b = repo
            .create_prepared_sweep_attempt(inv_b.id, inv_b.address_index, &cold_addr, Utc::now())
            .await
            .unwrap();
        repo.mark_sweep_attempt_reorged(
            att_b.id,
            inv_b.id,
            "SWEEP_AMBIGUOUS_TIMEOUT",
            None,
            Utc::now(),
        )
        .await
        .unwrap();

        let shared_tx = "b1".repeat(32);
        // Delay RPC verification so BOTH tasks pass the pre-RPC check concurrently before DB write!
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""pool":true"#))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(80))
                    .set_body_json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": "toctou",
                        "result": {
                            "out": [{
                                "txid": shared_tx,
                                "amount": 999_900_000_000_u64,
                                "fee": 100_000_000_u64,
                                "confirmations": 15,
                                "double_spend_seen": false,
                                "subaddr_index": { "major": 0, "minor": 0 },
                                "subaddr_indices": [
                                    { "major": 0, "minor": 401 },
                                    { "major": 0, "minor": 402 }
                                ],
                                "destinations": [{
                                    "amount": 999_900_000_000_u64,
                                    "address": cold_addr
                                }]
                            }],
                            "pending": [],
                            "pool": []
                        }
                    })),
            )
            .mount(&mock_rpc)
            .await;

        let barrier = Arc::new(Barrier::new(2));
        let app_a = app.clone();
        let key_a = cfg.api_secret_key.clone();
        let tx_a = shared_tx.clone();
        let b_a = barrier.clone();
        let task_a = tokio::spawn(async move {
            b_a.wait().await;
            app_a
                .oneshot(
                    Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv_a.id))
                        .header("content-type", "application/json")
                        .header("X-API-Key", key_a.as_str())
                        .body(Body::from(
                            serde_json::json!({
                                "action": "mark_reconciled",
                                "replacement_tx_hash": tx_a,
                                "operator_note": "race A"
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        });

        let app_b = app.clone();
        let key_b = cfg.api_secret_key.clone();
        let tx_b = shared_tx.clone();
        let b_b = barrier.clone();
        let task_b = tokio::spawn(async move {
            b_b.wait().await;
            app_b
                .oneshot(
                    Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv_b.id))
                        .header("content-type", "application/json")
                        .header("X-API-Key", key_b.as_str())
                        .body(Body::from(
                            serde_json::json!({
                                "action": "mark_reconciled",
                                "replacement_tx_hash": tx_b,
                                "operator_note": "race B"
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        });

        let (st_a, st_b) = tokio::join!(task_a, task_b);
        let statuses = [st_a.unwrap(), st_b.unwrap()];
        assert_eq!(
            statuses.iter().filter(|&&s| s == StatusCode::OK).count(),
            1,
            "exactly one concurrent cross-invoice MARK_RECONCILED must succeed: {statuses:?}"
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|&&s| s == StatusCode::CONFLICT)
                .count(),
            1,
            "second concurrent cross-invoice MARK_RECONCILED must fail with 409: {statuses:?}"
        );

        let inv_a_after = repo.get_invoice_by_id(inv_a.id).await.unwrap().unwrap();
        let inv_b_after = repo.get_invoice_by_id(inv_b.id).await.unwrap().unwrap();
        let bound_count = usize::from(inv_a_after.sweep_tx_hashes.contains(&shared_tx))
            + usize::from(inv_b_after.sweep_tx_hashes.contains(&shared_tx));
        assert_eq!(
            bound_count, 1,
            "shared txid must be bound to exactly one invoice"
        );

        pool.close().await;
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(format!("{}-wal", db_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", db_path.display()));
    }

    // Part B: 10 XMR invoice paid in one tx of 10.000000000001 XMR (1 piconero overpayment delta
    //         stored in subaddress_transfers) -> dust MARK_RECONCILED of 1 piconero MUST fail 409!
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 2, 10);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap().to_string();
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
        let app = build_router(AppState {
            config: cfg.clone(),
            repo: repo.clone(),
            rpc,
            scanner: scanner.clone(),
        });

        let inv = make_invoice(403, 10_000_000_000_000, None);
        repo.insert_invoice(&inv).await.unwrap();

        let tx_overpaid = "b2".repeat(32);
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_ov",
                "result": {
                    "in": [{
                        "txid": tx_overpaid,
                        "amount": 10_000_000_000_001_u64,
                        "confirmations": 12,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 403 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;
        // Force sweep_all timeout so PREPARED attempt is created with snapshot_txids=[tx_overpaid]
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("sweep_all"))
            .respond_with(ResponseTemplate::new(502).set_body_string("timeout"))
            .mount(&mock_rpc)
            .await;

        // Tick 1: Pending -> Confirmed (records OVERPAYMENT full transfer amount in subaddress_transfers, excess delta=1 in webhook);
        // Tick 2: Confirmed -> Settled & triggers sweep_all
        scanner.scan_once().await.unwrap();
        scanner.scan_once().await.unwrap();

        // Confirm subaddress_transfers preserves full actual transfer amount (`AUDIT-005` balance conservation)
        let sub_rows = repo
            .list_subaddress_transfers_for_invoice(inv.id)
            .await
            .unwrap();
        assert_eq!(sub_rows.len(), 1);
        assert_eq!(sub_rows[0].amount_piconero, Piconero(10_000_000_000_001));
        assert_eq!(
            sub_rows[0].classification,
            TransferClassification::Overpayment
        );

        let attempts = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].snapshot_txids, vec![tx_overpaid.clone()]);
        repo.mark_sweep_attempt_reorged(
            attempts[0].id,
            inv.id,
            "SWEEP_AMBIGUOUS_TIMEOUT",
            None,
            Utc::now(),
        )
        .await
        .unwrap();

        let dust_tx = "b3".repeat(32);
        let full_tx = "b4".repeat(32);
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""pool":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "ver_ov",
                "result": {
                    "out": [
                        {
                            "txid": dust_tx,
                            "amount": 1_u64,
                            "fee": 100_000_000_u64,
                            "confirmations": 12,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 403 },
                            "destinations": [{ "amount": 1_u64, "address": cold_addr }]
                        },
                        {
                            "txid": full_tx,
                            "amount": 9_999_900_000_001_u64,
                            "fee": 100_000_000_u64,
                            "confirmations": 12,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 403 },
                            "destinations": [{ "amount": 9_999_900_000_001_u64, "address": cold_addr }]
                        }
                    ],
                    "pending": [],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let dust_resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        serde_json::json!({
                            "action": "mark_reconciled",
                            "replacement_tx_hash": dust_tx,
                            "operator_note": "dust bypass attempt"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            dust_resp.status(),
            StatusCode::CONFLICT,
            "1-piconero dust tx MUST NOT reconcile 10.000000000001 XMR overpaid invoice"
        );

        let full_resp = app
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        serde_json::json!({
                            "action": "mark_reconciled",
                            "replacement_tx_hash": full_tx,
                            "operator_note": "verified full overpaid sweep"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(full_resp.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn regression_phase37_p36_3_settlement_confs_above_10_snapshots_all_unlocked_outputs() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;
    // SETTLEMENT_CONFIRMATIONS = 20 > MONERO_UNLOCK_CONFIRMATIONS = 10
    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 2, 20);
    let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());

    let mut inv = make_invoice(404, 1_000_000_000_000, None);
    inv.status = InvoiceStatus::Settled;
    inv.received_piconero = Piconero(1_500_000_000_000);
    inv.confirmations = 20;
    inv.unlocked = true;
    repo.insert_invoice(&inv).await.unwrap();

    let tx1 = "c1".repeat(32); // 20 confs, unlocked
    let tx2 = "c2".repeat(32); // 12 confs, unlocked (spent by Monero sweep_all!)
    let tx3 = "c3".repeat(32); // 5 confs, locked (NOT spent by Monero sweep_all!)
    let now = Utc::now();

    for (txid, amt, confs, unlocked, cls) in [
        (
            &tx1,
            1_000_000_000_000_u64,
            20_u64,
            true,
            TransferClassification::Expected,
        ),
        (
            &tx2,
            500_000_000_000_u64,
            12_u64,
            true,
            TransferClassification::Overpayment,
        ),
        (
            &tx3,
            200_000_000_000_u64,
            5_u64,
            false,
            TransferClassification::Overpayment,
        ),
    ] {
        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: txid.clone(),
                amount_piconero: Piconero(amt),
                confirmations: confs,
                in_pool: false,
                unlocked,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: txid.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(amt),
                confirmations: confs,
                classification: cls,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: now,
            },
            received_piconero: Piconero(1_700_000_000_000),
            confirmations: 20,
            unlocked: false,
            webhook: None,
            now,
        })
        .await
        .unwrap();
    }

    // Prepare sweep with min_sweep_confs = 20: snapshot MUST include BOTH tx1 (20 conf) AND
    // tx2 (12 conf, unlocked in Monero) while EXCLUDING locked tx3 (5 conf)!
    let att = repo
        .create_prepared_sweep_attempt_with_min_confs(inv.id, inv.address_index, cold_addr, 20, now)
        .await
        .unwrap();
    assert_eq!(att.snapshot_txids, vec![tx1.clone(), tx2.clone()]);

    let sweep_tx = "c4".repeat(32);
    repo.complete_sweep_attempt_with_min_confs(
        CompleteSweepAttemptParams {
            attempt_id: att.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Confirmed,
            sweep_tx_hashes: vec![sweep_tx.clone()],
            sweep_amount_piconero: Piconero(1_499_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now,
        },
        20,
    )
    .await
    .unwrap();

    let rows = repo
        .list_subaddress_transfers_for_invoice(inv.id)
        .await
        .unwrap();
    let r1 = rows.iter().find(|r| r.txid == tx1).unwrap();
    let r2 = rows.iter().find(|r| r.txid == tx2).unwrap();
    let r3 = rows.iter().find(|r| r.txid == tx3).unwrap();
    assert!(r1.swept && r1.status == SubaddressTransferStatus::Swept);
    assert!(r2.swept && r2.status == SubaddressTransferStatus::Swept);
    assert!(!r3.swept && r3.status == SubaddressTransferStatus::Active);

    // 8 blocks later (tx2 at 20 confs, tx3 still locked at 8 confs): scan_once MUST NOT invoke
    // sweep_all (no infinite -17 loop on already-swept tx2!).
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
            "id": "out_p36_3",
            "result": {
                "out": [{
                    "txid": sweep_tx,
                    "amount": 1_499_900_000_000_u64,
                    "fee": 100_000_000_u64,
                    "confirmations": 20,
                    "double_spend_seen": false,
                    "subaddr_index": { "major": 0, "minor": 404 },
                    "destinations": [{ "amount": 1_499_900_000_000_u64, "address": cold_addr }]
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
            "id": "in_p36_3",
            "result": {
                "in": [
                    {
                        "txid": tx1,
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 28,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 404 }
                    },
                    {
                        "txid": tx2,
                        "amount": 500_000_000_000_u64,
                        "confirmations": 20,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 404 }
                    },
                    {
                        "txid": tx3,
                        "amount": 200_000_000_000_u64,
                        "confirmations": 8,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 404 }
                    }
                ],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    let report = scanner.scan_once().await.unwrap();
    assert_eq!(report.invoices_swept, 0);
    assert_eq!(report.sweep_errors, 0);
    assert!(!repo.has_unswept_inflows(inv.id, 20).await.unwrap());
}

#[tokio::test]
async fn regression_phase37_p36_4_and_p36_5_multi_attempt_reorg_and_aggregate_accounting() {
    // Sub-scenario A: Double reorg (A2 then A1) MUST transition invoice to REORGED (not stuck SWEPT)
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let cold_addr = encode_monero_base58_address(18, &[0x11; 32], &[0x22; 32], None);
        let now = Utc::now();

        let mut inv = make_invoice(405, 1_000_000_000_000, None);
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let tx_exp = "d1".repeat(32);
        let tx_ov = "d2".repeat(32);
        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: tx_exp.clone(),
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 15,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: tx_exp.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 15,
                classification: TransferClassification::Expected,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: now,
            },
            received_piconero: Piconero(1_000_000_000_000),
            confirmations: 15,
            unlocked: true,
            webhook: None,
            now,
        })
        .await
        .unwrap();

        let a1 = repo
            .create_prepared_sweep_attempt(inv.id, inv.address_index, &cold_addr, now)
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: a1.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Confirmed,
            sweep_tx_hashes: vec!["d3".repeat(32)],
            sweep_amount_piconero: Piconero(999_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now,
        })
        .await
        .unwrap();

        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: tx_ov.clone(),
                amount_piconero: Piconero(250_000_000_000),
                confirmations: 15,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: tx_ov.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(250_000_000_000),
                confirmations: 15,
                classification: TransferClassification::Overpayment,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: now,
            },
            received_piconero: Piconero(1_250_000_000_000),
            confirmations: 15,
            unlocked: true,
            webhook: None,
            now,
        })
        .await
        .unwrap();

        let a2 = repo
            .create_prepared_sweep_attempt(inv.id, inv.address_index, &cold_addr, now)
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: a2.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Submitted,
            sweep_tx_hashes: vec!["d4".repeat(32)],
            sweep_amount_piconero: Piconero(249_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now,
        })
        .await
        .unwrap();

        // A2 reorgs first while primary A1 is still live -> stays SWEPT
        let inv_after_a2 = repo
            .mark_sweep_attempt_reorged(a2.id, inv.id, "SWEEP_REORG_DETECTED: a2", None, now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inv_after_a2.status, InvoiceStatus::Swept);

        // A1 then also reorgs -> zero live attempts left -> MUST transition to REORGED!
        let inv_after_a1 = repo
            .mark_sweep_attempt_reorged(a1.id, inv.id, "SWEEP_REORG_DETECTED: a1", None, now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inv_after_a1.status, InvoiceStatus::Reorged);
    }

    // Sub-scenario B: Primary EXPECTED sweep A1 reorgs while secondary OVERPAYMENT A2 is live
    //                 -> MUST move to REORGED, and ALLOW_RESWEEP(A1) allows re-sweeping primary!
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap();
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());
        let now = Utc::now();

        let mut inv = make_invoice(406, 10_000_000_000_000, None);
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(10_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let tx_primary = "e1".repeat(32);
        let tx_overpay = "e2".repeat(32);
        let sweep_s1 = "e3".repeat(32);
        let sweep_s2 = "e4".repeat(32);
        let sweep_s3 = "e5".repeat(32);

        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: tx_primary.clone(),
                amount_piconero: Piconero(10_000_000_000_000),
                confirmations: 15,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: tx_primary.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(10_000_000_000_000),
                confirmations: 15,
                classification: TransferClassification::Expected,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: now,
            },
            received_piconero: Piconero(10_000_000_000_000),
            confirmations: 15,
            unlocked: true,
            webhook: None,
            now,
        })
        .await
        .unwrap();

        let a1 = repo
            .create_prepared_sweep_attempt(inv.id, inv.address_index, cold_addr, now)
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: a1.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Submitted,
            sweep_tx_hashes: vec![sweep_s1],
            sweep_amount_piconero: Piconero(9_999_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now,
        })
        .await
        .unwrap();

        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: tx_overpay.clone(),
                amount_piconero: Piconero(500_000_000_000),
                confirmations: 15,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: tx_overpay.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(500_000_000_000),
                confirmations: 15,
                classification: TransferClassification::Overpayment,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: now,
            },
            received_piconero: Piconero(10_500_000_000_000),
            confirmations: 15,
            unlocked: true,
            webhook: None,
            now,
        })
        .await
        .unwrap();

        let a2 = repo
            .create_prepared_sweep_attempt(inv.id, inv.address_index, cold_addr, now)
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: a2.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Confirmed,
            sweep_tx_hashes: vec![sweep_s2.clone()],
            sweep_amount_piconero: Piconero(499_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now,
        })
        .await
        .unwrap();

        // Primary A1 reorgs while A2 is live -> MUST transition SWEPT -> REORGED!
        let inv_reorg = repo
            .mark_sweep_attempt_reorged(a1.id, inv.id, "SWEEP_REORG_DETECTED: primary", None, now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inv_reorg.status, InvoiceStatus::Reorged);

        // ALLOW_RESWEEP(A1) resets EXPECTED tx_primary to ACTIVE and keeps status=REORGED
        let (inv_resweep, _) = repo
            .resolve_sweep_incident_allow_resweep(a1.id, inv.id, "resweep primary", now)
            .await
            .unwrap();
        assert_eq!(inv_resweep.status, InvoiceStatus::Reorged);
        assert_eq!(inv_resweep.sweep_tx_hashes, vec![sweep_s2.clone()]);
        assert_eq!(
            inv_resweep.sweep_amount_piconero,
            Some(Piconero(499_900_000_000))
        );
        let sub_rows = repo
            .list_subaddress_transfers_for_invoice(inv.id)
            .await
            .unwrap();
        let primary_row = sub_rows.iter().find(|r| r.txid == tx_primary).unwrap();
        assert!(!primary_row.swept && primary_row.status == SubaddressTransferStatus::Active);

        // manual_sweep cleanly re-sweeps primary 10 XMR without stranding!
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_resw",
                "result": {
                    "in": [
                        {
                            "txid": tx_primary,
                            "amount": 10_000_000_000_000_u64,
                            "confirmations": 20,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 406 }
                        },
                        {
                            "txid": tx_overpay,
                            "amount": 500_000_000_000_u64,
                            "confirmations": 20,
                            "double_spend_seen": false,
                            "locked": false,
                            "subaddr_index": { "major": 0, "minor": 406 }
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
                "id": "sw_resw",
                "result": {
                    "tx_hash_list": [sweep_s3],
                    "amount_list": [9_999_900_000_000_u64],
                    "fee_list": [100_000_000_u64]
                }
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let swept_again = scanner.manual_sweep(inv.id).await.unwrap();
        assert_eq!(swept_again.status, InvoiceStatus::Swept);
        assert_eq!(swept_again.sweep_tx_hashes, vec![sweep_s2, sweep_s3]);
        assert_eq!(
            swept_again.sweep_amount_piconero,
            Some(Piconero(10_499_800_000_000))
        );
        assert_eq!(swept_again.sweep_fee_piconero, Some(Piconero(200_000_000)));
    }

    // Sub-scenario C: Two REORGED attempts (A2 & A3) alongside live A1 ->
    //                 MARK_RECONCILED(A2) + ALLOW_RESWEEP(A3) MUST NOT double-subtract,
    //                 MUST NOT leak dead hash of A3, and MUST preserve last_sweep_error until A3 resolved!
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let mock_daemon = MockServer::start().await;
        let mut cfg_owned =
            (*test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15)).clone();
        cfg_owned.monero_daemon_rpc_url = Some(format!("{}/json_rpc", mock_daemon.uri()));
        let cfg = Arc::new(cfg_owned);
        let cold_addr = cfg.cold_wallet_address.as_deref().unwrap().to_string();
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
        let app = build_router(AppState {
            config: cfg.clone(),
            repo: repo.clone(),
            rpc,
            scanner,
        });
        let now = Utc::now();

        let mut inv = make_invoice(
            407,
            1_000_000_000_000,
            Some("http://127.0.0.1:9999/p36_5".to_string()),
        );
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let tx_in1 = "f1".repeat(32);
        let tx_in2 = "f2".repeat(32);
        let tx_in3 = "f3".repeat(32);
        let sw1 = "f4".repeat(32);
        let sw2 = "f5".repeat(32);
        let sw3 = "f6".repeat(32);
        let sw2_rep = "f7".repeat(32);

        // Live A1 (1000 XMR-scaled: 1_000_000_000_000 -> 999_900_000_000 + 100_000_000)
        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: tx_in1.clone(),
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 20,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: tx_in1.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 20,
                classification: TransferClassification::Expected,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: now,
            },
            received_piconero: Piconero(1_000_000_000_000),
            confirmations: 20,
            unlocked: true,
            webhook: None,
            now,
        })
        .await
        .unwrap();
        let a1 = repo
            .create_prepared_sweep_attempt(
                inv.id,
                inv.address_index,
                &cold_addr,
                now - ChronoDuration::seconds(20),
            )
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: a1.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Confirmed,
            sweep_tx_hashes: vec![sw1.clone()],
            sweep_amount_piconero: Piconero(999_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now: now - ChronoDuration::seconds(20),
        })
        .await
        .unwrap();

        // A2 (overpayment 500_000_000_000 -> 499_900_000_000 + 100_000_000)
        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: tx_in2.clone(),
                amount_piconero: Piconero(500_000_000_000),
                confirmations: 15,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: tx_in2.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(500_000_000_000),
                confirmations: 15,
                classification: TransferClassification::Overpayment,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: now - ChronoDuration::seconds(10),
            },
            received_piconero: Piconero(1_500_000_000_000),
            confirmations: 15,
            unlocked: true,
            webhook: None,
            now: now - ChronoDuration::seconds(10),
        })
        .await
        .unwrap();
        let a2 = repo
            .create_prepared_sweep_attempt(
                inv.id,
                inv.address_index,
                &cold_addr,
                now - ChronoDuration::seconds(10),
            )
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: a2.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Submitted,
            sweep_tx_hashes: vec![sw2],
            sweep_amount_piconero: Piconero(499_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now,
        })
        .await
        .unwrap();

        // A3 (overpayment 300_000_000_000 -> 299_900_000_000 + 100_000_000)
        repo.record_subaddress_transfer(RecordSubaddressTransferParams {
            transfer: ObservedTransfer {
                txid: tx_in3.clone(),
                amount_piconero: Piconero(300_000_000_000),
                confirmations: 15,
                in_pool: false,
                unlocked: true,
                double_spend_seen: false,
                orphaned: false,
            },
            record: SubaddressTransferRecord {
                id: 0,
                txid: tx_in3.clone(),
                invoice_id: inv.id,
                address_index: inv.address_index,
                amount_piconero: Piconero(300_000_000_000),
                confirmations: 15,
                classification: TransferClassification::Overpayment,
                status: SubaddressTransferStatus::Active,
                swept: false,
                sweep_attempt_id: None,
                created_at: now,
            },
            received_piconero: Piconero(1_800_000_000_000),
            confirmations: 15,
            unlocked: true,
            webhook: None,
            now,
        })
        .await
        .unwrap();
        let a3 = repo
            .create_prepared_sweep_attempt(inv.id, inv.address_index, &cold_addr, now)
            .await
            .unwrap();
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: a3.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Submitted,
            sweep_tx_hashes: vec![sw3.clone()],
            sweep_amount_piconero: Piconero(299_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now,
        })
        .await
        .unwrap();

        // Both A2 and A3 become REORGED
        repo.mark_sweep_attempt_reorged(a2.id, inv.id, "SWEEP_REORG_DETECTED: a2", None, now)
            .await
            .unwrap();
        repo.mark_sweep_attempt_reorged(a3.id, inv.id, "SWEEP_REORG_DETECTED: a3", None, now)
            .await
            .unwrap();

        // Resolve A2 via MARK_RECONCILED with sw2_rep (499_800_000_000 + 200_000_000 fee)
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""pool":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "ver_a2",
                "result": {
                    "out": [
                        {
                            "txid": sw1,
                            "amount": 999_900_000_000_u64,
                            "fee": 100_000_000_u64,
                            "confirmations": 20,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 407 },
                            "destinations": [{ "amount": 999_900_000_000_u64, "address": cold_addr }]
                        },
                        {
                            "txid": sw2_rep,
                            "amount": 499_800_000_000_u64,
                            "fee": 200_000_000_u64,
                            "confirmations": 15,
                            "double_spend_seen": false,
                            "subaddr_index": { "major": 0, "minor": 407 },
                            "destinations": [{ "amount": 499_800_000_000_u64, "address": cold_addr }]
                        }
                    ],
                    "pending": [],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        let rec_a2 = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        serde_json::json!({
                            "attempt_id": a2.id,
                            "action": "mark_reconciled",
                            "replacement_tx_hash": sw2_rep,
                            "operator_note": "reconcile a2 while a3 still reorged"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rec_a2.status(), StatusCode::OK);

        let inv_mid = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert!(
            inv_mid.last_sweep_error.is_some(),
            "last_sweep_error MUST NOT be cleared while A3 is still REORGED"
        );
        assert_eq!(inv_mid.sweep_tx_hashes, vec![sw1.clone(), sw2_rep.clone()]);
        assert!(!inv_mid.sweep_tx_hashes.contains(&sw3));
        assert_eq!(
            inv_mid.sweep_amount_piconero,
            Some(Piconero(1_499_700_000_000))
        );
        assert_eq!(inv_mid.sweep_fee_piconero, Some(Piconero(300_000_000)));
        assert!(
            repo.list_webhooks_for_invoice(inv.id)
                .await
                .unwrap()
                .is_empty(),
            "SWEPT webhook MUST NOT emit while A3 is still unresolved REORGED"
        );

        // Now resolve A3 via ALLOW_RESWEEP -> totals MUST stay 1_499_700_000_000 / 300_000_000
        // (NO double-subtraction of A3!), and last_sweep_error now clears!
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_height"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "wh_a3",
                "result": { "height": 3_810_000_u64 }
            })))
            .mount(&mock_rpc)
            .await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "di_a3",
                "result": {
                    "height": 3_810_000_u64,
                    "target_height": 3_810_000_u64,
                    "synchronized": true,
                    "offline": false,
                    "untrusted": false,
                    "status": "OK",
                    "nettype": "mainnet"
                }
            })))
            .mount(&mock_daemon)
            .await;

        let res_a3 = app
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep/resolve", inv.id))
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        serde_json::json!({
                            "attempt_id": a3.id,
                            "action": "allow_resweep",
                            "confirm_absent_on_chain": true,
                            "operator_note": "a3 confirmed dead"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_a3.status(), StatusCode::OK);

        let inv_final = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
        assert_eq!(inv_final.sweep_tx_hashes, vec![sw1, sw2_rep]);
        assert_eq!(
            inv_final.sweep_amount_piconero,
            Some(Piconero(1_499_700_000_000)),
            "ALLOW_RESWEEP(A3) MUST NOT double-subtract A3 after MARK_RECONCILED(A2)"
        );
        assert_eq!(inv_final.sweep_fee_piconero, Some(Piconero(300_000_000)));
        assert!(inv_final.last_sweep_error.is_none());
    }
}

#[tokio::test]
async fn regression_phase37_p36_6_stale_apply_scan_update_and_terminal_double_spend_seen() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;
    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, false, 2, 10);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg);
    let now = Utc::now();

    // 1) Stale in-flight apply_scan_update on SWEPT invoice MUST NOT regress confirmations or
    //    orphan a newer active overpayment!
    let mut inv_swept = make_invoice(408, 1_000_000_000_000, None);
    inv_swept.status = InvoiceStatus::Swept;
    inv_swept.received_piconero = Piconero(1_250_000_000_000);
    inv_swept.confirmations = 15;
    inv_swept.unlocked = true;
    repo.insert_invoice(&inv_swept).await.unwrap();

    let tx1 = "11".repeat(32);
    let tx2 = "22".repeat(32);
    repo.record_subaddress_transfer(RecordSubaddressTransferParams {
        transfer: ObservedTransfer {
            txid: tx1.clone(),
            amount_piconero: Piconero(1_000_000_000_000),
            confirmations: 15,
            in_pool: false,
            unlocked: true,
            double_spend_seen: false,
            orphaned: false,
        },
        record: SubaddressTransferRecord {
            id: 0,
            txid: tx1.clone(),
            invoice_id: inv_swept.id,
            address_index: inv_swept.address_index,
            amount_piconero: Piconero(1_000_000_000_000),
            confirmations: 15,
            classification: TransferClassification::Expected,
            status: SubaddressTransferStatus::Swept,
            swept: true,
            sweep_attempt_id: None,
            created_at: now,
        },
        received_piconero: Piconero(1_000_000_000_000),
        confirmations: 15,
        unlocked: true,
        webhook: None,
        now,
    })
    .await
    .unwrap();
    repo.record_subaddress_transfer(RecordSubaddressTransferParams {
        transfer: ObservedTransfer {
            txid: tx2.clone(),
            amount_piconero: Piconero(250_000_000_000),
            confirmations: 10,
            in_pool: false,
            unlocked: true,
            double_spend_seen: false,
            orphaned: false,
        },
        record: SubaddressTransferRecord {
            id: 0,
            txid: tx2.clone(),
            invoice_id: inv_swept.id,
            address_index: inv_swept.address_index,
            amount_piconero: Piconero(250_000_000_000),
            confirmations: 10,
            classification: TransferClassification::Overpayment,
            status: SubaddressTransferStatus::Active,
            swept: false,
            sweep_attempt_id: None,
            created_at: now,
        },
        received_piconero: Piconero(1_250_000_000_000),
        confirmations: 15,
        unlocked: true,
        webhook: None,
        now,
    })
    .await
    .unwrap();

    // Deliver stale in-flight scan snapshot (only tx1 at 3 confs, locked)
    let after_stale = repo
        .apply_scan_update(ApplyScanUpdateParams {
            invoice_id: inv_swept.id,
            received_piconero: Piconero(1_000_000_000_000),
            confirmations: 3,
            unlocked: false,
            double_spend_seen: false,
            next_status: InvoiceStatus::Confirmed,
            transfers: vec![ObservedTransfer {
                txid: tx1.clone(),
                amount_piconero: Piconero(1_000_000_000_000),
                confirmations: 3,
                in_pool: false,
                unlocked: false,
                double_spend_seen: false,
                orphaned: false,
            }],
            webhook: None,
            now,
        })
        .await
        .unwrap();
    assert_eq!(after_stale.status, InvoiceStatus::Swept);
    assert_eq!(after_stale.confirmations, 15);
    assert!(after_stale.unlocked);

    let inv_trs = repo.list_transfers_for_invoice(inv_swept.id).await.unwrap();
    let t1_after = inv_trs.iter().find(|t| t.txid == tx1).unwrap();
    assert_eq!(t1_after.confirmations, 15);
    assert!(t1_after.unlocked);
    let sub_trs = repo
        .list_subaddress_transfers_for_invoice(inv_swept.id)
        .await
        .unwrap();
    let s2_after = sub_trs.iter().find(|r| r.txid == tx2).unwrap();
    assert_eq!(
        s2_after.status,
        SubaddressTransferStatus::Active,
        "stale apply_scan_update MUST NOT orphan newer active overpayment"
    );

    // 2) scan_once observing double_spend_seen=true on SWEPT and EXPIRED invoices MUST persist
    //    invoices.double_spend_seen = true in SQLite!
    let mut inv_expired = make_invoice(409, 1_000_000_000_000, None);
    inv_expired.status = InvoiceStatus::Expired;
    inv_expired.expires_at = now - ChronoDuration::minutes(30);
    repo.insert_invoice(&inv_expired).await.unwrap();

    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "ds_term",
            "result": {
                "in": [],
                "pool": [
                    {
                        "txid": "33".repeat(32),
                        "amount": 500_000_000_000_u64,
                        "confirmations": 0,
                        "double_spend_seen": true,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 408 }
                    },
                    {
                        "txid": "44".repeat(32),
                        "amount": 500_000_000_000_u64,
                        "confirmations": 0,
                        "double_spend_seen": true,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 409 }
                    }
                ]
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();

    let swept_ds = repo.get_invoice_by_id(inv_swept.id).await.unwrap().unwrap();
    assert_eq!(swept_ds.status, InvoiceStatus::Swept);
    assert!(
        swept_ds.double_spend_seen,
        "double_spend_seen on SWEPT invoice MUST persist to SQLite"
    );
    let exp_ds = repo
        .get_invoice_by_id(inv_expired.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exp_ds.status, InvoiceStatus::Expired);
    assert!(
        exp_ds.double_spend_seen,
        "double_spend_seen on EXPIRED invoice MUST persist to SQLite"
    );
}

#[tokio::test]
async fn regression_phase37_p36_7_empty_or_missing_tx_hash_list_stays_prepared() {
    // Case A: HTTP 200 OK with empty tx_hash_list: [] -> MUST retain PREPARED (NOT mark FAILED)!
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg);

        let mut inv = make_invoice(410, 1_000_000_000_000, None);
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_empty_hash",
                "result": {
                    "in": [{
                        "txid": "71".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 410 }
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
                "id": "sw_empty",
                "result": { "tx_hash_list": [], "amount_list": [], "fee_list": [] }
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let err = scanner.manual_sweep(inv.id).await.unwrap_err();
        assert!(matches!(err, GatewayError::Rpc { code: None, .. }));
        let attempts = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].status,
            SweepAttemptStatus::Prepared,
            "empty tx_hash_list MUST remain PREPARED fail-closed (`P36-7`)"
        );
    }

    // Case B: HTTP 200 OK with omitted tx_hash_list field -> fails deserialization as RpcTransport
    //         and retains PREPARED (NOT mark FAILED)!
    {
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let mock_rpc = MockServer::start().await;
        let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc, cfg);

        let mut inv = make_invoice(411, 1_000_000_000_000, None);
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains(r#""in":true"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "in_missing_hash",
                "result": {
                    "in": [{
                        "txid": "72".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 15,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 411 }
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
                "id": "sw_missing",
                "result": {}
            })))
            .expect(1)
            .mount(&mock_rpc)
            .await;

        let err = scanner.manual_sweep(inv.id).await.unwrap_err();
        assert!(matches!(err, GatewayError::RpcTransport(_)));
        let attempts = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].status,
            SweepAttemptStatus::Prepared,
            "missing tx_hash_list MUST fail deserialization and remain PREPARED (`P36-7`)"
        );
    }
}

#[tokio::test]
async fn regression_audit_002_rbac_symmetry_failed_only_retry_and_health_diagnostics() {
    let mock_rpc = MockServer::start().await;
    let mock_hook = MockServer::start().await;
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool.clone());

    let mut cfg_val = (*test_config(
        format!("{}/json_rpc", mock_rpc.uri()),
        Some(format!("{}/hook", mock_hook.uri())),
        false,
        2,
        10,
    ))
    .clone();
    let merchant_key = cfg_val.api_secret_key.clone();
    let op_key = "operator-audit-002-distinct-secret-key-0123456789abcdef".to_string();

    // 1) Config::validate() MUST reject OPERATOR_API_KEY == API_SECRET_KEY (AUDIT-002)
    let mut dup_cfg = cfg_val.clone();
    dup_cfg.operator_api_key = Some(merchant_key.clone());
    assert!(
        matches!(dup_cfg.validate(), Err(GatewayError::Config(_))),
        "OPERATOR_API_KEY equal to API_SECRET_KEY must fail Config::validate()"
    );

    cfg_val.operator_api_key = Some(op_key.clone());
    assert!(cfg_val.validate().is_ok());
    let cfg = Arc::new(cfg_val);

    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
    let app = build_router(AppState {
        config: cfg.clone(),
        repo: repo.clone(),
        rpc,
        scanner,
    });

    // 2) GET /health diagnostics authorization matrix with OPERATOR_API_KEY configured (AUDIT-002)
    // 2a) Full diagnostics for X-Operator-Key: <op_key>, X-API-Key: <op_key>, X-API-Key: <merchant_key>
    for (hdr_name, hdr_val) in [
        ("X-Operator-Key", op_key.as_str()),
        ("X-API-Key", op_key.as_str()),
        ("X-API-Key", merchant_key.as_str()),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::get("/health")
                    .header(hdr_name, hdr_val)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let dto: HealthResponse =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(
            dto.service.as_deref(),
            Some("xmr-gateway"),
            "expected full diagnostics for {hdr_name}"
        );
        assert!(dto.monero_rpc.is_some());
        assert!(dto.auto_sweep_enabled.is_some());
    }

    // 2b) Minimal response (no telemetry) when unauthenticated, invalid key, or merchant key in X-Operator-Key
    for maybe_hdr in [
        None,
        Some(("X-API-Key", "invalid-secret-key-value")),
        Some(("X-Operator-Key", "invalid-operator-key-value")),
        Some(("X-Operator-Key", merchant_key.as_str())),
    ] {
        let mut req = Request::get("/health");
        if let Some((k, v)) = maybe_hdr {
            req = req.header(k, v);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            !text.contains("monero_rpc")
                && !text.contains("auto_sweep_enabled")
                && !text.contains("version"),
            "minimal /health must not leak telemetry for {maybe_hdr:?}, got: {text}"
        );
    }

    // 2c) Single-tenant mode (OPERATOR_API_KEY unset): X-Operator-Key: <merchant_key> gives full diagnostics
    {
        let mut single_cfg = (*cfg).clone();
        single_cfg.operator_api_key = None;
        let single_cfg = Arc::new(single_cfg);
        let single_rpc = MoneroRpcClient::new(&single_cfg.monero_rpc_url, None, None).unwrap();
        let single_scanner =
            ScannerService::new(repo.clone(), single_rpc.clone(), single_cfg.clone());
        let single_app = build_router(AppState {
            config: single_cfg.clone(),
            repo: repo.clone(),
            rpc: single_rpc,
            scanner: single_scanner,
        });

        let st_resp = single_app
            .oneshot(
                Request::get("/health")
                    .header("X-Operator-Key", merchant_key.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(st_resp.status(), StatusCode::OK);
        let st_dto: HealthResponse =
            serde_json::from_slice(&st_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(st_dto.service.as_deref(), Some("xmr-gateway"));
        assert!(st_dto.monero_rpc.is_some());
    }

    // Seed invoice with 3 webhooks: 1 FAILED, 1 backed-off PENDING (attempts=2, future next_attempt_at), 1 DELIVERED
    let inv = make_invoice(450, 1_000_000_000_000, cfg.default_webhook_url.clone());
    repo.insert_invoice(&inv).await.unwrap();
    let base_now = Utc::now();

    let wh_failed = build_webhook_delivery(
        &cfg.webhook_secret,
        &inv,
        WebhookEventType::Mempool,
        inv.callback_url.as_deref().unwrap(),
        base_now - ChronoDuration::seconds(30),
    )
    .unwrap();
    let wh_pending = build_webhook_delivery(
        &cfg.webhook_secret,
        &inv,
        WebhookEventType::Confirmed,
        inv.callback_url.as_deref().unwrap(),
        base_now - ChronoDuration::seconds(20),
    )
    .unwrap();
    let wh_delivered = build_webhook_delivery(
        &cfg.webhook_secret,
        &inv,
        WebhookEventType::Settled,
        inv.callback_url.as_deref().unwrap(),
        base_now - ChronoDuration::seconds(10),
    )
    .unwrap();

    let failed_id = wh_failed.id;
    let pending_id = wh_pending.id;
    let delivered_id = wh_delivered.id;
    let pending_next_at = base_now + ChronoDuration::minutes(15);

    for (wh, status, attempts, next_at, last_code, last_err, delivered_at) in [
        (
            &wh_failed,
            "FAILED",
            10_i64,
            base_now - ChronoDuration::seconds(5),
            Some(502_i64),
            Some("HTTP 502: bad gateway"),
            None,
        ),
        (
            &wh_pending,
            "PENDING",
            2_i64,
            pending_next_at,
            Some(503_i64),
            Some("HTTP 503: temporary outage"),
            None,
        ),
        (
            &wh_delivered,
            "DELIVERED",
            1_i64,
            base_now - ChronoDuration::seconds(10),
            Some(200_i64),
            None,
            Some(base_now - ChronoDuration::seconds(10)),
        ),
    ] {
        sqlx::query(
            r#"
            INSERT INTO webhook_deliveries (
                id, invoice_id, event_type, dedupe_key, target_url,
                payload_json, signature_hex, status, attempts, max_attempts,
                next_attempt_at, last_status_code, last_error,
                created_at, updated_at, delivered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(wh.id.to_string())
        .bind(wh.invoice_id.to_string())
        .bind(wh.event_type.as_str())
        .bind(&wh.dedupe_key)
        .bind(&wh.target_url)
        .bind(&wh.payload_json)
        .bind(&wh.signature_hex)
        .bind(status)
        .bind(attempts)
        .bind(i64::from(wh.max_attempts))
        .bind(next_at.to_rfc3339())
        .bind(last_code)
        .bind(last_err)
        .bind(wh.now.to_rfc3339())
        .bind(wh.now.to_rfc3339())
        .bind(delivered_at.map(|ts| ts.to_rfc3339()))
        .execute(&pool)
        .await
        .unwrap();
    }

    // 3) RBAC symmetry: POST /api/v1/invoices/{id}/webhooks/retry with merchant key -> 403 Forbidden (AUDIT-002)
    let merchant_batch_forbidden = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/webhooks/retry", inv.id))
                .header("X-API-Key", merchant_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(merchant_batch_forbidden.status(), StatusCode::FORBIDDEN);

    // Unknown key -> 401 Unauthorized
    let unknown_batch_unauth = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/webhooks/retry", inv.id))
                .header("X-API-Key", "completely-unknown-key-0123456789")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_batch_unauth.status(), StatusCode::UNAUTHORIZED);

    // 4) Single retry on PENDING webhook MUST return 409 Conflict and preserve attempts & next_attempt_at (AUDIT-002)
    let single_pending_conflict = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/webhooks/{pending_id}/retry"))
                .header("X-Operator-Key", op_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(single_pending_conflict.status(), StatusCode::CONFLICT);

    let hooks_after_single = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
    let pending_after_single = hooks_after_single
        .iter()
        .find(|w| w.id == pending_id)
        .unwrap();
    assert_eq!(pending_after_single.status, WebhookDeliveryStatus::Pending);
    assert_eq!(pending_after_single.attempts, 2);
    assert_eq!(pending_after_single.next_attempt_at, pending_next_at);
    assert_eq!(
        pending_after_single.last_error.as_deref(),
        Some("HTTP 503: temporary outage")
    );

    // Single retry on DELIVERED webhook -> 409 Conflict
    let single_delivered_conflict = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/webhooks/{delivered_id}/retry"))
                .header("X-Operator-Key", op_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(single_delivered_conflict.status(), StatusCode::CONFLICT);

    // 5) Batch retry with OPERATOR_API_KEY via X-Operator-Key resets ONLY FAILED, leaves PENDING & DELIVERED untouched
    let op_batch_ok = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/webhooks/retry", inv.id))
                .header("X-Operator-Key", op_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(op_batch_ok.status(), StatusCode::OK);
    let batch_dto: RetryWebhookResponse =
        serde_json::from_slice(&op_batch_ok.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(batch_dto.retried_count, 1);
    assert_eq!(batch_dto.webhook_ids, vec![failed_id]);

    let hooks_after_batch = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
    let failed_now = hooks_after_batch
        .iter()
        .find(|w| w.id == failed_id)
        .unwrap();
    let pending_now = hooks_after_batch
        .iter()
        .find(|w| w.id == pending_id)
        .unwrap();
    let delivered_now = hooks_after_batch
        .iter()
        .find(|w| w.id == delivered_id)
        .unwrap();

    assert_eq!(failed_now.status, WebhookDeliveryStatus::Pending);
    assert_eq!(failed_now.attempts, 0);
    assert!(failed_now.last_error.is_none());

    // PENDING row MUST remain untouched (attempts=2, original future next_attempt_at, last_error preserved)
    assert_eq!(pending_now.status, WebhookDeliveryStatus::Pending);
    assert_eq!(pending_now.attempts, 2);
    assert_eq!(pending_now.next_attempt_at, pending_next_at);
    assert_eq!(
        pending_now.last_error.as_deref(),
        Some("HTTP 503: temporary outage")
    );

    assert_eq!(delivered_now.status, WebhookDeliveryStatus::Delivered);

    // Repeating batch retry via X-API-Key: <OPERATOR_API_KEY> now returns 200 OK with 0 retried (no FAILED left)
    let op_batch_empty = app
        .oneshot(
            Request::post(format!("/api/v1/invoices/{}/webhooks/retry", inv.id))
                .header("X-API-Key", op_key.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(op_batch_empty.status(), StatusCode::OK);
    let empty_dto: RetryWebhookResponse = serde_json::from_slice(
        &op_batch_empty
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(empty_dto.retried_count, 0);
    assert!(empty_dto.webhook_ids.is_empty());
}

// ============================================================================
// AUDIT-005 Regression Tests:
//   1. Overpayment balance conservation in subaddress_transfers & re-scan invariance
//   2. Concurrent SQLite BEGIN IMMEDIATE write stress test (zero SQLITE_BUSY)
//   3. Graceful shutdown (biased shutdown priority) & SQLite WAL TRUNCATE checkpoint
// ============================================================================

#[tokio::test]
async fn regression_audit_005_overpayment_balance_conservation_and_rescan() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool.clone());
    let mock_rpc = MockServer::start().await;
    let mock_hook = MockServer::start().await;

    let hook_url = format!("{}/audit-005-overpay", mock_hook.uri());
    let cfg = test_config(
        format!("{}/json_rpc", mock_rpc.uri()),
        Some(hook_url.clone()),
        true,
        2,
        10,
    );
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());

    // ------------------------------------------------------------------------
    // Scenario 1: Single confirmed transfer exceeding invoice amount_piconero
    // (1.0 XMR expected, 1.35 XMR received -> 0.35 XMR excess in webhook,
    //  FULL 1.35 XMR preserved in subaddress_transfers.amount_piconero)
    // ------------------------------------------------------------------------
    let inv1 = make_invoice(501, 1_000_000_000_000, Some(hook_url.clone()));
    repo.insert_invoice(&inv1).await.unwrap();
    let tx_single = "51".repeat(32);

    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "in": [{
                    "txid": tx_single,
                    "amount": 1_350_000_000_000_u64,
                    "confirmations": 3,
                    "double_spend_seen": false,
                    "locked": true,
                    "subaddr_index": { "major": 0, "minor": 501 }
                }],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();

    let inv_txs_1 = repo.list_transfers_for_invoice(inv1.id).await.unwrap();
    let sub_txs_1 = repo
        .list_subaddress_transfers_for_invoice(inv1.id)
        .await
        .unwrap();
    assert_eq!(sub_txs_1.len(), 1);
    assert_eq!(
        sub_txs_1[0].classification,
        TransferClassification::Overpayment
    );
    assert_eq!(sub_txs_1[0].amount_piconero, Piconero(1_350_000_000_000));
    let inv_sum_1: u64 = inv_txs_1
        .iter()
        .filter(|t| !t.orphaned && t.confirmations > 0)
        .map(|t| t.amount_piconero.as_u64())
        .sum();
    let sub_sum_1: u64 = sub_txs_1
        .iter()
        .filter(|r| r.status != SubaddressTransferStatus::Orphaned)
        .map(|r| r.amount_piconero.as_u64())
        .sum();
    assert_eq!(
        sub_sum_1, inv_sum_1,
        "Scenario 1 ledger balance conservation must hold"
    );

    // Webhook OVERPAYMENT payload still carries the excess delta (0.35 XMR)
    let hooks_1 = repo.list_webhooks_for_invoice(inv1.id).await.unwrap();
    let overpay_hook_1 = hooks_1
        .iter()
        .find(|w| w.event_type == WebhookEventType::Overpayment)
        .expect("OVERPAYMENT webhook must be enqueued");
    let overpay_json_1: serde_json::Value =
        serde_json::from_str(&overpay_hook_1.payload_json).unwrap();
    assert_eq!(
        overpay_json_1["trigger_amount_piconero"].as_u64(),
        Some(350_000_000_000)
    );
    assert_eq!(
        overpay_json_1["received_piconero"].as_u64(),
        Some(1_350_000_000_000)
    );

    // Simulate legacy pre-AUDIT-005 partial-delta corruption and verify re-scan self-heals it
    sqlx::query("UPDATE subaddress_transfers SET amount_piconero = ? WHERE invoice_id = ?")
        .bind(350_000_000_000_i64)
        .bind(inv1.id.to_string())
        .execute(&pool)
        .await
        .unwrap();

    // Re-scan at 12 confirmations (unlocked=true) + auto-sweep of full 1.35 XMR balance
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "2",
            "result": {
                "in": [{
                    "txid": tx_single,
                    "amount": 1_350_000_000_000_u64,
                    "confirmations": 12,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 501 }
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
                "tx_hash_list": ["5a".repeat(32)],
                "amount_list": [1_349_900_000_000_u64],
                "fee_list": [100_000_000_u64]
            }
        })))
        .expect(1)
        .mount(&mock_rpc)
        .await;

    let report_rescan = scanner.scan_once().await.unwrap();
    assert_eq!(report_rescan.invoices_swept, 1);

    let sub_txs_1_after = repo
        .list_subaddress_transfers_for_invoice(inv1.id)
        .await
        .unwrap();
    assert_eq!(sub_txs_1_after.len(), 1);
    assert_eq!(
        sub_txs_1_after[0].amount_piconero,
        Piconero(1_350_000_000_000),
        "Re-scan must self-heal and preserve full transfer amount"
    );
    assert_eq!(sub_txs_1_after[0].confirmations, 12);
    assert!(sub_txs_1_after[0].swept);

    // ------------------------------------------------------------------------
    // Scenario 2: Two-transaction partial + crossing overpayment
    // (1.0 XMR expected; tx1 = 0.6 XMR -> EXPECTED, tx2 = 0.7 XMR -> OVERPAYMENT
    //  with excess = 0.3 XMR; ledger sum MUST equal 0.6 + 0.7 = 1.3 XMR)
    // ------------------------------------------------------------------------
    let inv2 = make_invoice(502, 1_000_000_000_000, Some(hook_url));
    repo.insert_invoice(&inv2).await.unwrap();
    let tx_part = "52".repeat(32);
    let tx_cross = "53".repeat(32);

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
                        "txid": tx_single,
                        "amount": 1_350_000_000_000_u64,
                        "confirmations": 13,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 501 }
                    },
                    {
                        "txid": tx_part,
                        "amount": 600_000_000_000_u64,
                        "confirmations": 5,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 502 }
                    },
                    {
                        "txid": tx_cross,
                        "amount": 700_000_000_000_u64,
                        "confirmations": 3,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 502 }
                    }
                ],
                "pool": []
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();

    let inv_txs_2 = repo.list_transfers_for_invoice(inv2.id).await.unwrap();
    let sub_txs_2 = repo
        .list_subaddress_transfers_for_invoice(inv2.id)
        .await
        .unwrap();
    assert_eq!(sub_txs_2.len(), 2);

    let rec_part = sub_txs_2.iter().find(|r| r.txid == tx_part).unwrap();
    let rec_cross = sub_txs_2.iter().find(|r| r.txid == tx_cross).unwrap();
    assert_eq!(rec_part.classification, TransferClassification::Expected);
    assert_eq!(rec_part.amount_piconero, Piconero(600_000_000_000));
    assert_eq!(
        rec_cross.classification,
        TransferClassification::Overpayment
    );
    assert_eq!(
        rec_cross.amount_piconero,
        Piconero(700_000_000_000),
        "Crossing OVERPAYMENT row must store full 0.7 XMR tx amount, not 0.3 XMR delta"
    );

    let inv_sum_2: u64 = inv_txs_2
        .iter()
        .filter(|t| !t.orphaned && t.confirmations > 0)
        .map(|t| t.amount_piconero.as_u64())
        .sum();
    let sub_sum_2: u64 = sub_txs_2
        .iter()
        .filter(|r| r.status != SubaddressTransferStatus::Orphaned)
        .map(|r| r.amount_piconero.as_u64())
        .sum();
    assert_eq!(inv_sum_2, 1_300_000_000_000);
    assert_eq!(
        sub_sum_2, inv_sum_2,
        "Scenario 2 ledger conservation: SUM(subaddress_transfers) == SUM(invoice_transfers)"
    );

    let hooks_2 = repo.list_webhooks_for_invoice(inv2.id).await.unwrap();
    let overpay_hook_2 = hooks_2
        .iter()
        .find(|w| w.event_type == WebhookEventType::Overpayment)
        .expect("OVERPAYMENT webhook must be enqueued for crossing tx2");
    let overpay_json_2: serde_json::Value =
        serde_json::from_str(&overpay_hook_2.payload_json).unwrap();
    assert_eq!(
        overpay_json_2["trigger_amount_piconero"].as_u64(),
        Some(300_000_000_000)
    );

    // Re-scan Scenario 2 with confirmations=12 & unlocked=true -> auto-sweeps full 1.3 XMR
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
                        "txid": tx_single,
                        "amount": 1_350_000_000_000_u64,
                        "confirmations": 20,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 501 }
                    },
                    {
                        "txid": tx_part,
                        "amount": 600_000_000_000_u64,
                        "confirmations": 14,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 502 }
                    },
                    {
                        "txid": tx_cross,
                        "amount": 700_000_000_000_u64,
                        "confirmations": 12,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 502 }
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
                "tx_hash_list": ["5b".repeat(32)],
                "amount_list": [1_299_900_000_000_u64],
                "fee_list": [100_000_000_u64]
            }
        })))
        .expect(1)
        .mount(&mock_rpc)
        .await;

    let report_2 = scanner.scan_once().await.unwrap();
    assert_eq!(report_2.invoices_swept, 1);

    let sub_txs_2_after = repo
        .list_subaddress_transfers_for_invoice(inv2.id)
        .await
        .unwrap();
    assert_eq!(sub_txs_2_after.len(), 2);
    assert!(sub_txs_2_after.iter().all(|r| r.swept));
    let sub_sum_2_after: u64 = sub_txs_2_after
        .iter()
        .map(|r| r.amount_piconero.as_u64())
        .sum();
    assert_eq!(sub_sum_2_after, 1_300_000_000_000);
}

#[tokio::test]
async fn regression_audit_005_concurrent_begin_immediate_writes_no_sqlite_busy() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let db_path = tmp_dir.path().join("concurrent_immediate.db");
    let db_url = format!("sqlite://{}", db_path.display());

    let pool = init_sqlite_pool(&db_url).await.unwrap();
    let repo = InvoiceRepository::new(pool.clone());
    let now = Utc::now();

    let mut invoice_ids = Vec::new();
    for idx in 1..=8_u32 {
        let mut inv = make_invoice(600 + idx, 1_000_000_000_000, None);
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 12;
        inv.unlocked = true;
        inv.confirmed_at = Some(now);
        inv.settled_at = Some(now);
        repo.insert_invoice(&inv).await.unwrap();

        // Seed a FAILED webhook via apply_scan_update so concurrent retry transactions contend too
        let hook = build_webhook_delivery(
            "secret-concurrent-0123456789abcdef",
            &inv,
            WebhookEventType::Settled,
            "http://127.0.0.1:9999/hook",
            now,
        )
        .unwrap();
        let hook_id = hook.id;
        repo.apply_scan_update(ApplyScanUpdateParams {
            invoice_id: inv.id,
            next_status: InvoiceStatus::Settled,
            received_piconero: inv.received_piconero,
            confirmations: inv.confirmations,
            unlocked: inv.unlocked,
            double_spend_seen: false,
            transfers: Vec::new(),
            webhook: Some(hook),
            now,
        })
        .await
        .unwrap();
        repo.mark_webhook_retry_or_failed(hook_id, 10, None, Some(500), "seeded failure", now)
            .await
            .unwrap();

        invoice_ids.push((inv.id, inv.address_index));
    }

    // Spawn 16 concurrent writers across all pool connections simultaneously (4 rounds each)
    let barrier = Arc::new(Barrier::new(16));
    let mut handles = Vec::with_capacity(16);

    for worker in 0..16_usize {
        let repo_cloned = repo.clone();
        let barrier_cloned = barrier.clone();
        let (inv_id, addr_idx) = invoice_ids[worker % invoice_ids.len()];
        let dest = encode_monero_base58_address(18, &[0x33; 32], &[0x44; 32], None);

        handles.push(tokio::spawn(async move {
            barrier_cloned.wait().await;
            for round in 0..4_u32 {
                let ts = Utc::now();
                let txid = format!("{:02x}{:02x}{}", worker, round, "a".repeat(60));
                let tr = ObservedTransfer {
                    txid: txid.clone(),
                    amount_piconero: Piconero(250_000_000_000),
                    confirmations: 12 + u64::from(round),
                    unlocked: true,
                    double_spend_seen: false,
                    in_pool: false,
                    orphaned: false,
                };

                match (worker + round as usize) % 4 {
                    0 => {
                        let rec = SubaddressTransferRecord {
                            id: 0,
                            txid,
                            invoice_id: inv_id,
                            address_index: addr_idx,
                            amount_piconero: tr.amount_piconero,
                            confirmations: tr.confirmations,
                            classification: TransferClassification::Overpayment,
                            status: SubaddressTransferStatus::Active,
                            swept: false,
                            sweep_attempt_id: None,
                            created_at: ts,
                        };
                        repo_cloned
                            .record_subaddress_transfer(RecordSubaddressTransferParams {
                                record: rec,
                                transfer: tr,
                                received_piconero: Piconero(1_250_000_000_000),
                                confirmations: 12,
                                unlocked: true,
                                webhook: None,
                                now: ts,
                            })
                            .await
                            .expect("record_subaddress_transfer must not hit SQLITE_BUSY");
                    }
                    1 => {
                        let attempt = repo_cloned
                            .create_prepared_sweep_attempt_with_min_confs(
                                inv_id, addr_idx, &dest, 10, ts,
                            )
                            .await
                            .expect("create_prepared_sweep_attempt must not hit SQLITE_BUSY");
                        repo_cloned
                            .mark_sweep_attempt_failed(attempt.id, inv_id, "simulated error", ts)
                            .await
                            .expect("mark_sweep_attempt_failed must not hit SQLITE_BUSY");
                    }
                    2 => {
                        let _ = repo_cloned
                            .reset_failed_webhooks_for_invoice(inv_id, ts)
                            .await
                            .expect("reset_failed_webhooks_for_invoice must not hit SQLITE_BUSY");
                    }
                    _ => {
                        repo_cloned
                            .apply_scan_update(ApplyScanUpdateParams {
                                invoice_id: inv_id,
                                next_status: InvoiceStatus::Settled,
                                received_piconero: Piconero(1_000_000_000_000),
                                confirmations: 12 + u64::from(round),
                                unlocked: true,
                                double_spend_seen: false,
                                transfers: vec![tr],
                                webhook: None,
                                now: ts,
                            })
                            .await
                            .expect("apply_scan_update must not hit SQLITE_BUSY");
                    }
                }
            }
        }));
    }

    for handle in handles {
        handle
            .await
            .expect("concurrent writer task panicked or failed with SQLITE_BUSY");
    }

    let summary = checkpoint_and_close_pool(pool, &db_url)
        .await
        .unwrap()
        .expect("file-backed DB must return checkpoint summary");
    assert_eq!(summary.busy, 0);
}

#[tokio::test]
async fn regression_audit_005_graceful_shutdown_and_wal_checkpoint() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let db_path = tmp_dir.path().join("graceful_shutdown.db");
    let wal_path = std::path::PathBuf::from(format!("{}-wal", db_path.display()));
    let db_url = format!("sqlite://{}", db_path.display());

    // 1) Acquire process lock, initialize WAL pool, persist financial state
    let db_lock = acquire_database_lock(&db_url).unwrap();
    let pool = init_sqlite_pool(&db_url).await.unwrap();
    let repo = InvoiceRepository::new(pool.clone());

    let mock_rpc = MockServer::start().await;
    let mock_hook = MockServer::start().await;

    // Neither worker may hit RPC or webhook server when shutdown is already signaled (`true`)
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_hook)
        .await;

    let hook_url = format!("{}/hook", mock_hook.uri());
    let inv = make_invoice(701, 2_500_000_000_000, Some(hook_url.clone()));
    repo.insert_invoice(&inv).await.unwrap();

    let hook = build_webhook_delivery(
        "shutdown-webhook-secret-0123456789abcdef",
        &inv,
        WebhookEventType::Mempool,
        &hook_url,
        Utc::now(),
    )
    .unwrap();
    repo.apply_scan_update(ApplyScanUpdateParams {
        invoice_id: inv.id,
        next_status: InvoiceStatus::Mempool,
        received_piconero: Piconero(2_500_000_000_000),
        confirmations: 0,
        unlocked: false,
        double_spend_seen: false,
        transfers: Vec::new(),
        webhook: Some(hook),
        now: Utc::now(),
    })
    .await
    .unwrap();

    // 2) Pre-signaled shutdown=true: both ScannerService::run and WebhookDispatcher::run
    //    must exit immediately without executing an extra tick (biased shutdown priority).
    let cfg = test_config(
        format!("{}/json_rpc", mock_rpc.uri()),
        Some(hook_url),
        false,
        2,
        10,
    );
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg.clone());
    let dispatcher = WebhookDispatcher::new(
        repo.clone(),
        cfg.webhook_secret.clone(),
        cfg.enable_auto_sweep,
        Duration::from_millis(50),
        cfg.webhook_url_policy(),
    )
    .unwrap();

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(true);
    let scanner_handle = tokio::spawn(scanner.run(shutdown_rx.clone()));
    let webhook_handle = tokio::spawn(dispatcher.run(shutdown_rx));

    tokio::time::timeout(Duration::from_secs(2), scanner_handle)
        .await
        .expect("scanner must exit promptly when shutdown is already true")
        .expect("scanner task must not panic");
    tokio::time::timeout(Duration::from_secs(2), webhook_handle)
        .await
        .expect("webhook dispatcher must exit promptly when shutdown is already true")
        .expect("webhook dispatcher task must not panic");

    // 3) Run WAL TRUNCATE checkpoint & close pool BEFORE releasing DatabaseProcessLock
    drop(repo);
    let summary = checkpoint_and_close_pool(pool, &db_url)
        .await
        .unwrap()
        .expect("file-backed DB must return WalCheckpointSummary");
    assert_eq!(summary.busy, 0, "WAL checkpoint must finish with busy == 0");

    if wal_path.exists() {
        assert_eq!(
            std::fs::metadata(&wal_path).unwrap().len(),
            0,
            "WAL file must be 0 bytes after TRUNCATE checkpoint and pool close"
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, ".db permissions must be 0600");
    }

    drop(db_lock);

    // 4) Reopen DB and verify data integrity & persistence
    let reopened = init_sqlite_pool(&db_url).await.unwrap();
    let reopened_repo = InvoiceRepository::new(reopened.clone());
    let loaded = reopened_repo
        .get_invoice_by_id(inv.id)
        .await
        .unwrap()
        .expect("persisted invoice must survive WAL checkpoint & reopen");
    assert_eq!(loaded.amount_piconero, Piconero(2_500_000_000_000));
    let loaded_hooks = reopened_repo
        .list_webhooks_for_invoice(inv.id)
        .await
        .unwrap();
    assert_eq!(loaded_hooks.len(), 1);
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check;")
        .fetch_one(&reopened)
        .await
        .unwrap();
    assert_eq!(integrity, "ok");

    checkpoint_and_close_pool(reopened, &db_url).await.unwrap();
}

/// End-to-end regression suite for external audit hardening findings (`XMR-AUDIT-001`,
/// `XMR-AUDIT-003`, and `XMR-AUDIT-004`):
/// - `XMR-AUDIT-001`: custom `unlock_time` outputs (`confirmations = 20, locked = true`) reach
///   `CONFIRMED` but MUST NOT transition to `SETTLED`/`COMPLETED` until unlocked; once
///   `SETTLED`/`COMPLETED`, a late 1-piconero mempool dust transfer MUST NOT trigger `REORGED`.
/// - `XMR-AUDIT-003`: `verify_wallet_mode` fails closed on non-watch-only JSON-RPC errors
///   (`-32601`, `-32603`, `-13`) and malformed/empty spend keys in both `ViewOnly` and `HotWallet`.
/// - `XMR-AUDIT-004`: `Config::validate` requires a distinct `OPERATOR_API_KEY` whenever
///   `WALLET_MODE=hot_wallet` or `ENABLE_AUTO_SWEEP=true`.
#[tokio::test]
async fn regression_external_audit_hardening_xmr_audit_001_003_004() {
    let mock_rpc = MockServer::start().await;
    let mock_hook = MockServer::start().await;

    // -------------------------------------------------------------------------
    // 1) XMR-AUDIT-003: fail-closed verify_wallet_mode against RPC errors/garbage
    // -------------------------------------------------------------------------
    let rpc_client =
        MoneroRpcClient::new(&format!("{}/json_rpc", mock_rpc.uri()), None, None).unwrap();

    for (code, msg) in [
        (-32601, "Method not found"),
        (-32603, "Internal error"),
        (-13, "No wallet file"),
    ] {
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "error": { "code": code, "message": msg }
            })))
            .mount(&mock_rpc)
            .await;

        assert!(
            rpc_client
                .verify_wallet_mode(WalletMode::ViewOnly)
                .await
                .is_err(),
            "RPC error {code} ({msg}) MUST NOT be treated as watch-only"
        );
        assert!(
            rpc_client
                .verify_wallet_mode(WalletMode::HotWallet)
                .await
                .is_err(),
            "RPC error {code} ({msg}) MUST fail closed in hot_wallet mode"
        );
    }

    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "2",
            "result": { "key": "" }
        })))
        .mount(&mock_rpc)
        .await;
    assert!(
        rpc_client
            .verify_wallet_mode(WalletMode::ViewOnly)
            .await
            .is_err(),
        "empty key MUST fail closed in view_only mode"
    );

    // -------------------------------------------------------------------------
    // 2) XMR-AUDIT-004 & XMR-AUDIT-006: hot_wallet RBAC & mainnet HTTPS webhooks
    // -------------------------------------------------------------------------
    let mut hot_cfg =
        (*test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 2, 10)).clone();
    hot_cfg.operator_api_key = None;
    assert!(
        hot_cfg.validate().is_err(),
        "hot_wallet without OPERATOR_API_KEY MUST fail validation"
    );
    hot_cfg.operator_api_key = Some("distinct-operator-secret-key-0123456789".to_string());
    assert!(
        hot_cfg.validate().is_ok(),
        "hot_wallet with distinct OPERATOR_API_KEY must pass validation"
    );

    let mut mainnet_http_cfg = hot_cfg.clone();
    mainnet_http_cfg.monero_network = MoneroNetwork::Mainnet;
    mainnet_http_cfg.allow_private_webhooks = false;
    mainnet_http_cfg.require_https_webhooks = false;
    assert!(
        mainnet_http_cfg.validate().is_err(),
        "mainnet with ALLOW_PRIVATE_WEBHOOKS=false and REQUIRE_HTTPS_WEBHOOKS=false MUST fail closed"
    );
    mainnet_http_cfg.require_https_webhooks = true;
    assert!(
        mainnet_http_cfg.validate().is_ok(),
        "mainnet with ALLOW_PRIVATE_WEBHOOKS=false and REQUIRE_HTTPS_WEBHOOKS=true must pass validation"
    );

    // -------------------------------------------------------------------------
    // 3) XMR-AUDIT-001: Scanner + DB + Webhook unlocked settlement & anti-Dust-DoS
    // -------------------------------------------------------------------------
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_hook)
        .await;

    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let hook_url = format!("{}/hook", mock_hook.uri());
    let cfg = test_config(
        format!("{}/json_rpc", mock_rpc.uri()),
        Some(hook_url.clone()),
        false,
        2,
        10,
    );
    let scanner = ScannerService::new(repo.clone(), rpc_client.clone(), cfg.clone());
    let dispatcher = WebhookDispatcher::new(
        repo.clone(),
        cfg.webhook_secret.clone(),
        false,
        Duration::from_millis(20),
        cfg.webhook_url_policy(),
    )
    .unwrap();

    let inv = make_invoice(77, 1_000_000_000_000, Some(hook_url));
    repo.insert_invoice(&inv).await.unwrap();

    // 3a) Full payment with 20 confirmations, but locked=true (custom unlock_time).
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "10",
            "result": {
                "in": [{
                    "txid": "a".repeat(64),
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 20,
                    "double_spend_seen": false,
                    "locked": true,
                    "subaddr_index": { "major": 0, "minor": 77 }
                }]
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();
    let after_first = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(after_first.status, InvoiceStatus::Confirmed);

    // Second scan while still locked=true MUST stay CONFIRMED (never SETTLED/COMPLETED).
    scanner.scan_once().await.unwrap();
    dispatcher.process_due_deliveries().await.unwrap();
    let still_confirmed = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(
        still_confirmed.status,
        InvoiceStatus::Confirmed,
        "locked output at 20 confs must remain CONFIRMED and never enter SETTLED/COMPLETED"
    );

    // 3b) Output unlocks (locked=false) -> transitions to SETTLED, then webhook completes -> COMPLETED.
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "11",
            "result": {
                "in": [{
                    "txid": "a".repeat(64),
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 20,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 77 }
                }]
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();
    let settled = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(settled.status, InvoiceStatus::Settled);

    dispatcher.process_due_deliveries().await.unwrap();
    let completed = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(completed.status, InvoiceStatus::Completed);

    // 3c) Anti-Dust-DoS: attacker sends 1 piconero into mempool on the COMPLETED subaddress.
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "12",
            "result": {
                "in": [{
                    "txid": "a".repeat(64),
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 20,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 77 }
                }],
                "pool": [{
                    "txid": "b".repeat(64),
                    "amount": 1_u64,
                    "confirmations": 0,
                    "double_spend_seen": false,
                    "locked": true,
                    "subaddr_index": { "major": 0, "minor": 77 }
                }]
            }
        })))
        .mount(&mock_rpc)
        .await;

    scanner.scan_once().await.unwrap();
    let after_dust = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(
        after_dust.status,
        InvoiceStatus::Completed,
        "1-piconero mempool dust MUST NOT force COMPLETED invoice into REORGED"
    );
    let hooks = repo.list_webhooks_for_invoice(inv.id).await.unwrap();
    assert!(
        hooks
            .iter()
            .all(|h| h.event_type != WebhookEventType::Reorged),
        "mempool dust MUST NOT emit a REORGED webhook"
    );
}

#[tokio::test]
async fn regression_v014_sweep_all_mismatched_amount_or_fee_list_stays_prepared() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;
    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg);

    let mut inv = make_invoice(401, 1_000_000_000_000, None);
    inv.status = InvoiceStatus::Settled;
    inv.received_piconero = Piconero(1_000_000_000_000);
    inv.confirmations = 15;
    inv.unlocked = true;
    repo.insert_invoice(&inv).await.unwrap();

    // Case 1: non-empty tx_hash_list, but amount_list is missing/empty -> MUST NOT finalize as SWEPT
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "in_401",
            "result": {
                "in": [{
                    "txid": "41".repeat(32),
                    "amount": 1_000_000_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 401 }
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
            "id": "sw_bad_amt",
            "result": {
                "tx_hash_list": ["a1".repeat(32)],
                "fee_list": [100_000_000_u64]
            }
        })))
        .expect(1)
        .mount(&mock_rpc)
        .await;

    let res = scanner.manual_sweep(inv.id).await;
    assert!(
        res.is_err(),
        "sweep_all with missing amount_list MUST return an error"
    );

    let inv_after = repo.get_invoice_by_id(inv.id).await.unwrap().unwrap();
    assert_eq!(
        inv_after.status,
        InvoiceStatus::Settled,
        "invoice MUST NOT transition to SWEPT when amount_list/fee_list is missing or shorter"
    );
    assert!(
        inv_after
            .last_sweep_error
            .as_deref()
            .is_some_and(|e| e.contains("mismatched array lengths")),
        "diagnostic error must be recorded on invoice: {:?}",
        inv_after.last_sweep_error
    );

    let attempts = repo.list_sweep_attempts_for_invoice(inv.id).await.unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts[0].status,
        SweepAttemptStatus::Prepared,
        "attempt MUST remain PREPARED for reconciliation"
    );

    // Case 2: two tx hashes in tx_hash_list, but fee_list has only 1 entry -> MUST also fail closed
    let mut inv2 = make_invoice(402, 2_000_000_000_000, None);
    inv2.status = InvoiceStatus::Settled;
    inv2.received_piconero = Piconero(2_000_000_000_000);
    inv2.confirmations = 15;
    inv2.unlocked = true;
    repo.insert_invoice(&inv2).await.unwrap();

    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""in":true"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "in_402",
            "result": {
                "in": [{
                    "txid": "42".repeat(32),
                    "amount": 2_000_000_000_000_u64,
                    "confirmations": 15,
                    "double_spend_seen": false,
                    "locked": false,
                    "subaddr_index": { "major": 0, "minor": 402 }
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
            "id": "sw_short_fee",
            "result": {
                "tx_hash_list": ["b1".repeat(32), "b2".repeat(32)],
                "amount_list": [999_900_000_000_u64, 999_900_000_000_u64],
                "fee_list": [100_000_000_u64]
            }
        })))
        .expect(1)
        .mount(&mock_rpc)
        .await;

    assert!(scanner.manual_sweep(inv2.id).await.is_err());
    let inv2_after = repo.get_invoice_by_id(inv2.id).await.unwrap().unwrap();
    assert_eq!(inv2_after.status, InvoiceStatus::Settled);
    let attempts2 = repo.list_sweep_attempts_for_invoice(inv2.id).await.unwrap();
    assert_eq!(attempts2.len(), 1);
    assert_eq!(attempts2[0].status, SweepAttemptStatus::Prepared);
}

#[tokio::test]
async fn regression_v014_reconcile_in_flight_sweeps_batches_get_outgoing_transfers() {
    use wiremock::{Request as WireRequest, Respond};

    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    let mut cfg_owned =
        (*test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15)).clone();
    cfg_owned.scanner_subaddress_batch_size = 2;
    let cfg = Arc::new(cfg_owned);
    let cold_addr = cfg.cold_wallet_address.as_deref().unwrap().to_string();
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg);

    // Create 5 SUBMITTED sweep attempts across subaddresses 1..=5
    for idx in 1_u32..=5 {
        let mut inv = make_invoice(idx, 1_000_000_000_000, None);
        inv.status = InvoiceStatus::Settled;
        inv.received_piconero = Piconero(1_000_000_000_000);
        inv.confirmations = 15;
        inv.unlocked = true;
        repo.insert_invoice(&inv).await.unwrap();

        let att = repo
            .create_prepared_sweep_attempt(inv.id, idx, &cold_addr, Utc::now())
            .await
            .unwrap();
        let tx_hash = format!("{idx:064x}");
        repo.complete_sweep_attempt(CompleteSweepAttemptParams {
            attempt_id: att.id,
            invoice_id: inv.id,
            attempt_status: SweepAttemptStatus::Submitted,
            sweep_tx_hashes: vec![tx_hash],
            sweep_amount_piconero: Piconero(999_900_000_000),
            sweep_fee_piconero: Piconero(100_000_000),
            webhook: None,
            now: Utc::now(),
        })
        .await
        .unwrap();
    }

    let recorded_out_batches: Arc<std::sync::Mutex<Vec<Vec<u32>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));

    struct OutgoingBatchResponder {
        recorded: Arc<std::sync::Mutex<Vec<Vec<u32>>>>,
        cold_addr: String,
    }

    impl Respond for OutgoingBatchResponder {
        fn respond(&self, request: &WireRequest) -> ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let indices: Vec<u32> = body["params"]["subaddr_indices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| u32::try_from(v.as_u64().unwrap()).unwrap())
                .collect();
            self.recorded.lock().unwrap().push(indices.clone());

            let out_entries: Vec<serde_json::Value> = indices
                .iter()
                .map(|&idx| {
                    serde_json::json!({
                        "txid": format!("{idx:064x}"),
                        "amount": 999_900_000_000_u64,
                        "fee": 100_000_000_u64,
                        "confirmations": 20,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": idx },
                        "destinations": [
                            { "amount": 999_900_000_000_u64, "address": self.cold_addr }
                        ]
                    })
                })
                .collect();

            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "out_batch",
                "result": { "out": out_entries, "pending": [] }
            }))
        }
    }

    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""out":true"#))
        .respond_with(OutgoingBatchResponder {
            recorded: recorded_out_batches.clone(),
            cold_addr,
        })
        .mount(&mock_rpc)
        .await;

    scanner.reconcile_in_flight_sweeps().await.unwrap();

    let batches = recorded_out_batches.lock().unwrap().clone();
    assert_eq!(
        batches,
        vec![vec![1, 2], vec![3, 4], vec![5]],
        "5 monitored sweep attempts with batch_size=2 MUST execute ceil(5/2)=3 batched get_outgoing_transfers calls"
    );
}

#[tokio::test]
async fn regression_v014_create_invoice_does_not_block_on_default_webhook_url_dns() {
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("create_address"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "ca1",
            "result": {
                "address": "55LTR8KniP4LQGJSPtbYDacR7dz8RBFnsfAKMaMuwUNYX6aQbBcovzDPyrQF9KXF9tVU6Xk3K8no1BywnJX6GvZX8yJsXvt",
                "address_index": 1
            }
        })))
        .mount(&mock_rpc)
        .await;

    // Configure DEFAULT_WEBHOOK_URL with an unresolvable domain (.invalid RFC 2606) under strict SSRF policy
    let mut cfg_owned = (*test_config(
        format!("{}/json_rpc", mock_rpc.uri()),
        Some("https://offline-webhook-target.invalid/hook".to_string()),
        false,
        2,
        10,
    ))
    .clone();
    cfg_owned.allow_private_webhooks = false;
    cfg_owned.require_https_webhooks = true;
    let cfg = Arc::new(cfg_owned);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
    let app = build_router(AppState {
        config: cfg.clone(),
        repo: repo.clone(),
        rpc,
        scanner,
    });

    // 1) Omitting callback_url uses static validation on DEFAULT_WEBHOOK_URL -> MUST succeed (201 Created)
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/v1/invoices")
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    serde_json::json!({
                        "order_id": "ord-dns-outage-1",
                        "amount_piconero": 500_000_000_000_u64
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "POST /api/v1/invoices without callback_url MUST NOT fail when DEFAULT_WEBHOOK_URL DNS is unreachable"
    );

    // 2) Client-supplied callback_url with unresolvable domain STILL undergoes live DNS validation -> 400 Bad Request
    let resp_client_url = app
        .oneshot(
            Request::post("/api/v1/invoices")
                .header("content-type", "application/json")
                .header("X-API-Key", cfg.api_secret_key.as_str())
                .body(Body::from(
                    serde_json::json!({
                        "order_id": "ord-dns-outage-2",
                        "amount_piconero": 500_000_000_000_u64,
                        "callback_url": "https://unresolvable-client.invalid/hook"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_client_url.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn regression_v014_cross_batch_size_1_subaddress_amounts_and_height_consistency() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use wiremock::{Request as WireRequest, Respond};

    // Part A: TransferEntry::subaddress_amounts rejects mismatched lengths and u64 overflow
    let mismatched: TransferEntry = serde_json::from_value(serde_json::json!({
        "txid": "c".repeat(64),
        "amount": 1_000_000_000_000_u64,
        "amounts": [500_000_000_000_u64, 500_000_000_000_u64],
        "subaddr_index": { "major": 0, "minor": 1 },
        "subaddr_indices": [
            { "major": 0, "minor": 1 }
        ]
    }))
    .unwrap();
    assert!(
        mismatched.subaddress_amounts(0).is_err(),
        "mismatched amounts.len() != subaddr_indices.len() MUST fail closed"
    );

    let overflow_entry: TransferEntry = serde_json::from_value(serde_json::json!({
        "txid": "d".repeat(64),
        "amount": u64::MAX,
        "amounts": [u64::MAX, 1_u64],
        "subaddr_index": { "major": 0, "minor": 1 },
        "subaddr_indices": [
            { "major": 0, "minor": 1 },
            { "major": 0, "minor": 1 }
        ]
    }))
    .unwrap();
    assert!(
        overflow_entry.subaddress_amounts(0).is_err(),
        "u64 overflow across duplicate subaddr_indices MUST fail closed with AmountOverflow"
    );

    // Part B: Multi-output txid paying 2 invoices across 2 separate batches with batch_size = 1,
    // plus fail-closed abort when get_height drifts between batch 1 and batch 2.
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_rpc = MockServer::start().await;

    let inv1 = make_invoice(1, 1_000_000_000_000, None);
    let inv2 = make_invoice(2, 2_000_000_000_000, None);
    repo.insert_invoice(&inv1).await.unwrap();
    repo.insert_invoice(&inv2).await.unwrap();

    let mut cfg_owned =
        (*test_config(format!("{}/json_rpc", mock_rpc.uri()), None, false, 2, 10)).clone();
    cfg_owned.scanner_subaddress_batch_size = 1;
    let cfg = Arc::new(cfg_owned);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg);

    let current_height = Arc::new(AtomicU64::new(5000));
    let drift_on_get_height = Arc::new(AtomicU64::new(0));

    struct HeightAndBatchResponder {
        height: Arc<AtomicU64>,
        drift_step: Arc<AtomicU64>,
    }

    impl Respond for HeightAndBatchResponder {
        fn respond(&self, request: &WireRequest) -> ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let method_name = body["method"].as_str().unwrap();
            if method_name == "get_height" {
                let delta = self.drift_step.load(Ordering::SeqCst);
                let h = self.height.fetch_add(delta, Ordering::SeqCst);
                return ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "h",
                    "result": { "height": h }
                }));
            }
            assert_eq!(method_name, "get_transfers");
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "gt",
                "result": {
                    "in": [{
                        "txid": "e".repeat(64),
                        "amount": 3_000_000_000_000_u64,
                        "amounts": [1_000_000_000_000_u64, 2_000_000_000_000_u64],
                        "confirmations": 12,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 1 },
                        "subaddr_indices": [
                            { "major": 0, "minor": 1 },
                            { "major": 0, "minor": 2 }
                        ]
                    }],
                    "pool": []
                }
            }))
        }
    }

    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .respond_with(HeightAndBatchResponder {
            height: current_height.clone(),
            drift_step: drift_on_get_height.clone(),
        })
        .mount(&mock_rpc)
        .await;

    // 1) Simulate chain height advancing mid-cycle (5000 before batch 1 -> 5001 after batch 2):
    //    scan_once MUST fail closed BEFORE mutating either invoice!
    drift_on_get_height.store(1, Ordering::SeqCst);
    let drift_err = scanner.scan_once().await.unwrap_err();
    assert!(
        drift_err
            .to_string()
            .contains("wallet chain height changed across get_transfers batches"),
        "expected height drift error, got: {drift_err}"
    );
    assert_eq!(
        repo.get_invoice_by_id(inv1.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        InvoiceStatus::Pending
    );
    assert_eq!(
        repo.get_invoice_by_id(inv2.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        InvoiceStatus::Pending
    );

    // 2) Stable chain height with batch_size = 1: both invoices transition Pending -> Confirmed -> Completed
    //    with exact per-subaddress amounts!
    drift_on_get_height.store(0, Ordering::SeqCst);
    scanner.scan_once().await.unwrap();
    scanner.scan_once().await.unwrap();

    let loaded1 = repo.get_invoice_by_id(inv1.id).await.unwrap().unwrap();
    let loaded2 = repo.get_invoice_by_id(inv2.id).await.unwrap().unwrap();
    assert_eq!(loaded1.status, InvoiceStatus::Completed);
    assert_eq!(loaded1.received_piconero, Piconero(1_000_000_000_000));
    assert_eq!(loaded2.status, InvoiceStatus::Completed);
    assert_eq!(loaded2.received_piconero, Piconero(2_000_000_000_000));
}

#[tokio::test]
async fn regression_v015_mempool_missing_reorg_deferred_while_wallet_lagging_and_fires_when_synced()
{
    let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
    let repo = InvoiceRepository::new(pool);
    let mock_wallet_rpc = MockServer::start().await;
    let mock_daemon_rpc = MockServer::start().await;

    let mut cfg_owned = (*test_config(
        format!("{}/json_rpc", mock_wallet_rpc.uri()),
        Some("http://127.0.0.1:9000/hook".to_string()),
        false,
        2,
        10,
    ))
    .clone();
    // Use MONERO_REMOTE_NODE (stripped of scheme) to verify fallback normalization too!
    cfg_owned.monero_remote_node = Some(
        mock_daemon_rpc
            .uri()
            .trim_start_matches("http://")
            .to_string(),
    );
    let cfg = Arc::new(cfg_owned);
    let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
    let scanner = ScannerService::new(repo.clone(), rpc, cfg);

    // Invoice 1: pays in mempool, vanishes while wallet lags -> must defer REORGED and later confirm cleanly!
    let inv_lag = make_invoice(
        501,
        1_000_000_000_000,
        Some("http://127.0.0.1:9000/hook".to_string()),
    );
    // Invoice 2: pays in mempool, gets real double_spend_seen while wallet lags -> MUST still REORG immediately!
    let inv_ds = make_invoice(
        502,
        1_000_000_000_000,
        Some("http://127.0.0.1:9000/hook".to_string()),
    );
    // Invoice 3: pays in mempool, vanishes when wallet is synced (lag=0) -> MUST transition to REORGED!
    let inv_synced = make_invoice(
        503,
        1_000_000_000_000,
        Some("http://127.0.0.1:9000/hook".to_string()),
    );
    repo.insert_invoice(&inv_lag).await.unwrap();
    repo.insert_invoice(&inv_ds).await.unwrap();
    repo.insert_invoice(&inv_synced).await.unwrap();

    // Tick 1: All 3 invoices observe 0-conf payments in mempool (`pool`) -> MEMPOOL
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "gt1",
            "result": {
                "in": [],
                "pool": [
                    {
                        "txid": "a1".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 0,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 501 }
                    },
                    {
                        "txid": "a2".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 0,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 502 }
                    },
                    {
                        "txid": "a3".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 0,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 503 }
                    }
                ]
            }
        })))
        .mount(&mock_wallet_rpc)
        .await;

    scanner.scan_once().await.unwrap();
    for id in [inv_lag.id, inv_ds.id, inv_synced.id] {
        assert_eq!(
            repo.get_invoice_by_id(id).await.unwrap().unwrap().status,
            InvoiceStatus::Mempool
        );
    }

    // Tick 2: Wallet lags behind daemon (wallet_height=2_000_000 < daemon_height=2_050_000, lag=50_000).
    // inv_lag vanishes from pool & in (mined into a block wallet hasn't scanned yet);
    // inv_ds has explicit double_spend_seen=true;
    // inv_synced stays in pool for now.
    mock_wallet_rpc.reset().await;
    mock_daemon_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "gt2",
            "result": {
                "in": [],
                "pool": [
                    {
                        "txid": "a2".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 0,
                        "double_spend_seen": true,
                        "subaddr_index": { "major": 0, "minor": 502 }
                    },
                    {
                        "txid": "a3".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 0,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 503 }
                    }
                ]
            }
        })))
        .mount(&mock_wallet_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "gh2",
            "result": { "height": 2_000_000_u64 }
        })))
        .mount(&mock_wallet_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "gi2",
            "result": {
                "height": 2_050_000_u64,
                "target_height": 2_050_000_u64,
                "synchronized": true
            }
        })))
        .mount(&mock_daemon_rpc)
        .await;

    scanner.scan_once().await.unwrap();

    let lag_after = repo.get_invoice_by_id(inv_lag.id).await.unwrap().unwrap();
    assert_eq!(
        lag_after.status,
        InvoiceStatus::Mempool,
        "missing pool tx while wallet lags (lag > 0) MUST NOT transition invoice to REORGED"
    );
    assert_eq!(lag_after.reorg_epoch, 0);
    assert!(
        repo.list_webhooks_for_invoice(inv_lag.id)
            .await
            .unwrap()
            .iter()
            .all(|w| w.event_type != WebhookEventType::Reorged),
        "must not emit false REORGED webhook while wallet is lagging"
    );

    let ds_after = repo.get_invoice_by_id(inv_ds.id).await.unwrap().unwrap();
    assert_eq!(
        ds_after.status,
        InvoiceStatus::Reorged,
        "explicit double_spend_seen MUST still transition to REORGED even while lagging"
    );
    assert_eq!(ds_after.reorg_epoch, 1);

    // Tick 3: Daemon reports synchronized=false (even with equal heights) -> still defer REORGED for inv_lag!
    mock_wallet_rpc.reset().await;
    mock_daemon_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "gt3",
            "result": {
                "in": [],
                "pool": [
                    {
                        "txid": "a3".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 0,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 503 }
                    }
                ]
            }
        })))
        .mount(&mock_wallet_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "gh3",
            "result": { "height": 2_050_000_u64 }
        })))
        .mount(&mock_wallet_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "gi3",
            "result": {
                "height": 2_050_000_u64,
                "target_height": 2_050_000_u64,
                "synchronized": false
            }
        })))
        .mount(&mock_daemon_rpc)
        .await;

    scanner.scan_once().await.unwrap();
    assert_eq!(
        repo.get_invoice_by_id(inv_lag.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        InvoiceStatus::Mempool,
        "missing pool tx while daemon reports synchronized=false MUST defer REORGED"
    );

    // Tick 4: Wallet is fully synced (wallet_height == daemon_height == 2_050_000, synchronized=true, lag=0).
    // inv_lag now appears mined in `in` with 2 confs -> transitions cleanly MEMPOOL -> CONFIRMED (reorg_epoch stays 0)!
    // inv_synced genuinely vanishes from pool & in at lag=0 -> MUST fail-closed transition MEMPOOL -> REORGED!
    mock_wallet_rpc.reset().await;
    mock_daemon_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "gt4",
            "result": {
                "in": [
                    {
                        "txid": "a1".repeat(32),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 2,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 501 }
                    }
                ],
                "pool": []
            }
        })))
        .mount(&mock_wallet_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "gh4",
            "result": { "height": 2_050_000_u64 }
        })))
        .mount(&mock_wallet_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "gi4",
            "result": {
                "height": 2_050_000_u64,
                "target_height": 2_050_000_u64,
                "synchronized": true
            }
        })))
        .mount(&mock_daemon_rpc)
        .await;

    scanner.scan_once().await.unwrap();

    let lag_confirmed = repo.get_invoice_by_id(inv_lag.id).await.unwrap().unwrap();
    assert_eq!(lag_confirmed.status, InvoiceStatus::Confirmed);
    assert_eq!(
        lag_confirmed.reorg_epoch, 0,
        "invoice recovered after sync catchup MUST never have incremented reorg_epoch"
    );

    let synced_reorged = repo
        .get_invoice_by_id(inv_synced.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        synced_reorged.status,
        InvoiceStatus::Reorged,
        "missing pool tx when wallet is synced (lag == 0) MUST fail-closed into REORGED"
    );
    assert_eq!(synced_reorged.reorg_epoch, 1);
    assert!(
        repo.list_webhooks_for_invoice(inv_synced.id)
            .await
            .unwrap()
            .iter()
            .any(|w| w.event_type == WebhookEventType::Reorged),
        "real mempool eviction at lag=0 MUST emit a REORGED webhook"
    );
}
