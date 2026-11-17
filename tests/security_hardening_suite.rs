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
        dto::{CreateInvoiceResponse, HealthResponse, RetryWebhookResponse, SweepInvoiceResponse},
    },
    config::{
        Config, LogFormat, WalletMode, encode_monero_base58_address, validate_monero_address,
    },
    db::{
        init_sqlite_pool,
        repository::{
            ApplyScanUpdateParams, CompleteSweepAttemptParams, InvoiceRepository,
            RecordSubaddressTransferParams, SweepAttemptStatus, WebhookDeliveryStatus,
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
        webhook_secret: "hardening-suite-webhook-secret-0123456789".to_string(),
        default_webhook_url: default_webhook,
        allow_private_webhooks: true,
        require_https_webhooks: false,
        monero_rpc_url: rpc_url,
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
            "result": { "out": [], "pending": [] }
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
