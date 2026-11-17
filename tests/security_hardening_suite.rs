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
        Config, LogFormat, WalletMode, encode_monero_base58_address, validate_monero_address,
    },
    db::{
        init_sqlite_pool,
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
        scanner::ScannerService,
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
        required_confirmations: req_conf,
        settlement_confirmations: settle_conf,
        invoice_ttl_seconds: 3600,
        scan_interval_seconds: 10,
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
        multi_same_subaddr.subaddress_amounts(0),
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
    assert!(repo.has_unswept_inflows(inv.id).await.unwrap());
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
    assert!(repo.has_unswept_inflows(inv.id).await.unwrap());

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
    assert!(!repo.has_unswept_inflows(inv.id).await.unwrap());
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
    assert!(repo.has_unswept_inflows(inv_expired.id).await.unwrap());

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
    assert!(!repo.has_unswept_inflows(inv_expired.id).await.unwrap());
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
    assert!(repo.has_unswept_inflows(inv_expired.id).await.unwrap());
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

    let inv = make_invoice(110, 1_000_000_000_000, None);
    repo.insert_invoice(&inv).await.unwrap();

    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
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
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "h1",
            "result": { "height": 3_400_100_u64 }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "i1",
            "result": { "height": 3_400_100_u64, "synchronized": true, "status": "OK" }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""pool":true"#))
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
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_height"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "h2",
            "result": { "height": 3_400_105_u64 }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains("get_info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": "i2",
            "result": { "height": 3_400_105_u64, "synchronized": true, "status": "OK" }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""pool":true"#))
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

    let mut inv = make_invoice(112, 1_000_000_000_000, None);
    inv.status = InvoiceStatus::Settled;
    inv.received_piconero = Piconero(1_000_000_000_000);
    inv.confirmations = 15;
    inv.unlocked = true;
    repo.insert_invoice(&inv).await.unwrap();

    let cfg = test_config(format!("{}/json_rpc", mock_rpc.uri()), None, true, 10, 15);
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
            "id": "2",
            "result": { "height": 110_u64, "synchronized": true, "status": "OK" }
        })))
        .mount(&mock_rpc)
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

    // 3) RPC error on get_info/get_height -> 503 Service Unavailable (fail-closed)
    mock_rpc.reset().await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_rpc)
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
            "id": "4",
            "result": { "height": 3_400_500_u64, "synchronized": true, "status": "OK" }
        })))
        .mount(&mock_rpc)
        .await;
    Mock::given(method("POST"))
        .and(path("/json_rpc"))
        .and(body_string_contains(r#""pool":true"#))
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
        .and(body_string_contains(r#""pool":true"#))
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
        .and(body_string_contains(r#""pool":true"#))
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
        .and(body_string_contains(r#""pool":true"#))
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
                    "subaddr_index": { "major": 0, "minor": 113 }
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
