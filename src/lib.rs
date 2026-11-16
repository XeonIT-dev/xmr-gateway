//! `xmr-gateway`: Production-grade non-custodial Monero (XMR) payment gateway and
//! isolated subaddress auto-sweep engine.
//!
//! # Architecture Overview
//! - [`domain`] — Pure integer [`domain::amount::Piconero`] arithmetic (`1 XMR = 10^12 piconero`),
//!   deterministic [`domain::invoice::InvoiceStatus`] state machine, and Monero URI builder.
//! - [`config`] — Validated environment configuration supporting View-Only Zero-Trust mode and
//!   Hot Auto-Sweep mode.
//! - [`db`] — Transactional SQLite WAL persistence for invoices, transfer audit records, and
//!   idempotent webhook outbox entries.
//! - [`rpc`] — JSON-RPC 2.0 HTTP client for `monero-wallet-rpc` with RFC 2617/7616 Digest Auth.
//! - [`security`] — Outbound SSRF protection, DNS rebinding guards, and URL validation policy.
//! - [`services`] — Base64 PNG QR generator, HMAC-SHA256 webhook dispatcher, and background
//!   blockchain scanner / 10-block unlock sweeper.
//! - [`api`] — Axum REST server with constant-time `X-API-Key` authentication.

#![deny(missing_docs)]

pub mod api;
pub mod config;
pub mod db;
pub mod domain;
pub mod error;
pub mod rpc;
pub mod security;
pub mod services;

#[cfg(test)]
mod integration_tests {
    use std::{sync::Arc, time::Duration};

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, header, method, path},
    };

    use crate::{
        api::{
            AppState, build_router,
            dto::{
                CreateInvoiceResponse, HealthResponse, InvoiceStatusResponse, SweepInvoiceResponse,
            },
        },
        config::{Config, LogFormat, WalletMode},
        db::{init_sqlite_pool, repository::InvoiceRepository},
        domain::invoice::InvoiceStatus,
        rpc::client::MoneroRpcClient,
        services::{
            scanner::ScannerService,
            webhook::{WebhookDispatcher, sign_payload_hmac_sha256},
        },
    };

    fn integration_config(
        rpc_url: String,
        default_webhook: Option<String>,
        enable_auto_sweep: bool,
    ) -> Arc<Config> {
        Arc::new(Config {
            host: "127.0.0.1".to_string(),
            port: 0,
            cors_allowed_origins: vec!["*".to_string()],
            database_url: "sqlite::memory:".to_string(),
            api_secret_key: "integration-test-api-secret-key-0123456789".to_string(),
            webhook_secret: "integration-test-webhook-secret-0123456789".to_string(),
            default_webhook_url: default_webhook,
            allow_private_webhooks: true,
            require_https_webhooks: false,
            monero_rpc_url: rpc_url,
            monero_rpc_user: None,
            monero_rpc_pass: None,
            cold_wallet_address: if enable_auto_sweep {
                Some(format!("4{}", "A".repeat(94)))
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
            subaddress_monitor_days: 90,
            log_format: LogFormat::Json,
        })
    }

    #[tokio::test]
    async fn end_to_end_api_auth_create_scan_webhook_and_manual_sweep() {
        let mock_rpc = MockServer::start().await;
        let mock_bot = MockServer::start().await;

        let subaddress = format!("8{}", "C".repeat(94));
        let hook_url = format!("{}/telegram/webhook", mock_bot.uri());

        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let cfg = integration_config(format!("{}/json_rpc", mock_rpc.uri()), Some(hook_url), true);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
        let dispatcher = WebhookDispatcher::new_with_policy(
            repo.clone(),
            cfg.enable_auto_sweep,
            Duration::from_secs(5),
            cfg.webhook_url_policy(),
        )
        .unwrap();

        let state = AppState {
            config: cfg.clone(),
            repo: repo.clone(),
            rpc,
            scanner: scanner.clone(),
        };
        let app = build_router(state);

        // 1) Public /health probe checks DB + RPC get_version
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_version"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": { "version": 196619, "release": true }
            })))
            .mount(&mock_rpc)
            .await;

        let health_resp = app
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health_resp.status(), StatusCode::OK);
        let health_bytes = health_resp.into_body().collect().await.unwrap().to_bytes();
        let health: HealthResponse = serde_json::from_slice(&health_bytes).unwrap();
        assert_eq!(health.status, "ok");
        assert!(health.monero_rpc.connected);

        // 2) Missing or wrong X-API-Key rejected with 401
        let unauth_resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/invoices")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"order_id":"ord-1","amount_piconero":1000}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

        // 3) Create invoice via authenticated POST /api/v1/invoices
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("create_address"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "2",
                "result": {
                    "address": subaddress,
                    "address_index": 5
                }
            })))
            .mount(&mock_rpc)
            .await;

        let create_resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/invoices")
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        r#"{"order_id":"tg-order-42","amount_piconero":2500000000000}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let create_bytes = create_resp.into_body().collect().await.unwrap().to_bytes();
        let created: CreateInvoiceResponse = serde_json::from_slice(&create_bytes).unwrap();
        assert_eq!(created.order_id, "tg-order-42");
        assert_eq!(created.address_index, 5);
        assert_eq!(created.amount_xmr_formatted, "2.500000000000");
        assert!(created.monero_uri.contains("tx_amount=2.500000000000"));
        let png_bytes = STANDARD.decode(&created.qr_code_base64).unwrap();
        assert_eq!(&png_bytes[..4], &[0x89, b'P', b'N', b'G']);

        // 4) Duplicate order_id rejected with 409 Conflict
        let dup_resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/invoices")
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        r#"{"order_id":"tg-order-42","amount_piconero":2500000000000}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dup_resp.status(), StatusCode::CONFLICT);

        // 5) Simulate 2 confirmations (CONFIRMED, still locked < 10 blocks)
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "3",
                "result": {
                    "in": [{
                        "txid": "a".repeat(64),
                        "amount": 2_500_000_000_000_u64,
                        "confirmations": 2,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 5 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();

        // Manual sweep while locked (< 10 blocks) MUST return 409 Conflict
        let premature_sweep = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep", created.invoice_id))
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(premature_sweep.status(), StatusCode::CONFLICT);

        // Deliver CONFIRMED webhook and verify exact X-Signature-256 against bot server
        let webhooks = repo
            .list_webhooks_for_invoice(created.invoice_id)
            .await
            .unwrap();
        assert_eq!(webhooks.len(), 1);
        let expected_sig =
            sign_payload_hmac_sha256(&cfg.webhook_secret, webhooks[0].payload_json.as_bytes())
                .unwrap();

        Mock::given(method("POST"))
            .and(path("/telegram/webhook"))
            .and(header("X-Signature-256", expected_sig.as_str()))
            .and(header("X-Webhook-Event", "CONFIRMED"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_bot)
            .await;

        dispatcher.process_due_deliveries().await.unwrap();

        // 6) Simulate 10 confirmations (unlocked) and trigger manual POST /sweep
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "4",
                "result": {
                    "in": [{
                        "txid": "a".repeat(64),
                        "amount": 2_500_000_000_000_u64,
                        "confirmations": 10,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 5 }
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
                "id": "5",
                "result": {
                    "tx_hash_list": ["9".repeat(64)],
                    "amount_list": [2_499_900_000_000_u64],
                    "fee_list": [100_000_000_u64]
                }
            })))
            .mount(&mock_rpc)
            .await;

        let sweep_resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep", created.invoice_id))
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sweep_resp.status(), StatusCode::OK);
        let sweep_bytes = sweep_resp.into_body().collect().await.unwrap().to_bytes();
        let swept: SweepInvoiceResponse = serde_json::from_slice(&sweep_bytes).unwrap();
        assert_eq!(swept.status, InvoiceStatus::Swept);
        assert_eq!(swept.sweep_tx_hashes, vec!["9".repeat(64)]);
        assert_eq!(swept.sweep_amount_xmr_formatted, "2.499900000000");

        // 7) GET /api/v1/invoices/{id} reports complete audit trail
        let status_resp = app
            .oneshot(
                Request::get(format!("/api/v1/invoices/{}", created.invoice_id))
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(status_resp.status(), StatusCode::OK);
        let status_bytes = status_resp.into_body().collect().await.unwrap().to_bytes();
        let status_dto: InvoiceStatusResponse = serde_json::from_slice(&status_bytes).unwrap();
        assert_eq!(status_dto.status, InvoiceStatus::Swept);
        assert_eq!(status_dto.transfers.len(), 1);
        assert_eq!(status_dto.transfers[0].confirmations, 10);
    }

    #[tokio::test]
    async fn view_only_mode_completes_on_webhook_and_rejects_sweep() {
        let mock_rpc = MockServer::start().await;
        let mock_bot = MockServer::start().await;
        let tmp_dir = tempfile::tempdir().unwrap();
        let db_path = tmp_dir.path().join("gateway.db");
        let db_url = format!("sqlite://{}", db_path.display());

        let subaddress = format!("8{}", "D".repeat(94));
        let hook_url = format!("{}/bot/hook", mock_bot.uri());

        let pool = init_sqlite_pool(&db_url).await.unwrap();
        // Verify WAL journal mode is active on file-backed SQLite DB
        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode;")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");

        let repo = InvoiceRepository::new(pool);
        let mut cfg_val = (*integration_config(
            format!("{}/json_rpc", mock_rpc.uri()),
            Some(hook_url),
            false,
        ))
        .clone();
        cfg_val.database_url = db_url;
        let cfg = Arc::new(cfg_val);

        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
        let dispatcher = WebhookDispatcher::new_with_policy(
            repo.clone(),
            cfg.enable_auto_sweep,
            Duration::from_secs(5),
            cfg.webhook_url_policy(),
        )
        .unwrap();

        let app = build_router(AppState {
            config: cfg.clone(),
            repo: repo.clone(),
            rpc,
            scanner: scanner.clone(),
        });

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("create_address"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": { "address": subaddress, "address_index": 12 }
            })))
            .mount(&mock_rpc)
            .await;

        let create_resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/invoices")
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        r#"{"order_id":"viewonly-1","amount_piconero":500000000000}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let created: CreateInvoiceResponse =
            serde_json::from_slice(&create_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();

        // Manual sweep MUST be rejected in View-Only mode
        let sweep_err = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invoices/{}/sweep", created.invoice_id))
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sweep_err.status(), StatusCode::CONFLICT);

        // Confirm payment via scan
        mock_rpc.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("get_transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "2",
                "result": {
                    "in": [{
                        "txid": "e".repeat(64),
                        "amount": 500_000_000_000_u64,
                        "confirmations": 2,
                        "double_spend_seen": false,
                        "locked": true,
                        "subaddr_index": { "major": 0, "minor": 12 }
                    }],
                    "pool": []
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();
        let after_conf = repo
            .get_invoice_by_id(created.invoice_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_conf.status, InvoiceStatus::Confirmed);

        // First webhook attempt fails (503) -> stays CONFIRMED, scheduled for retry
        Mock::given(method("POST"))
            .and(path("/bot/hook"))
            .respond_with(ResponseTemplate::new(503).set_body_string("bot restarting"))
            .expect(1)
            .mount(&mock_bot)
            .await;

        dispatcher.process_due_deliveries().await.unwrap();
        let still_conf = repo
            .get_invoice_by_id(created.invoice_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still_conf.status, InvoiceStatus::Confirmed);
        let hooks = repo
            .list_webhooks_for_invoice(created.invoice_id)
            .await
            .unwrap();
        assert_eq!(hooks[0].attempts, 1);
        assert_eq!(hooks[0].last_status_code, Some(503));
        assert!(hooks[0].next_attempt_at > hooks[0].updated_at);
    }

    #[tokio::test]
    async fn tainted_double_spend_transfer_is_excluded_from_api_balance() {
        let mock_rpc = MockServer::start().await;
        let subaddress = format!("8{}", "E".repeat(94));

        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);
        let cfg = integration_config(format!("{}/json_rpc", mock_rpc.uri()), None, false);
        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
        let app = build_router(AppState {
            config: cfg.clone(),
            repo,
            rpc,
            scanner: scanner.clone(),
        });

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .and(body_string_contains("create_address"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": { "address": subaddress, "address_index": 9 }
            })))
            .mount(&mock_rpc)
            .await;

        let create_resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/invoices")
                    .header("content-type", "application/json")
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::from(
                        r#"{"order_id":"ds-check-1","amount_piconero":1000000000000}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let created: CreateInvoiceResponse =
            serde_json::from_slice(&create_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();

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
                        "txid": "d".repeat(64),
                        "amount": 1_000_000_000_000_u64,
                        "confirmations": 0,
                        "double_spend_seen": true,
                        "subaddr_index": { "major": 0, "minor": 9 }
                    }]
                }
            })))
            .mount(&mock_rpc)
            .await;

        scanner.scan_once().await.unwrap();

        let status_resp = app
            .oneshot(
                Request::get(format!("/api/v1/invoices/{}", created.invoice_id))
                    .header("X-API-Key", cfg.api_secret_key.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status_dto: InvoiceStatusResponse =
            serde_json::from_slice(&status_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(status_dto.status, InvoiceStatus::Pending);
        assert_eq!(status_dto.received_piconero, 0);
        assert!(status_dto.double_spend_seen);
        assert_eq!(status_dto.transfers.len(), 1);
        assert!(status_dto.transfers[0].double_spend_seen);
    }

    #[tokio::test]
    async fn api_rejects_private_and_metadata_callback_urls_when_ssrf_guard_enabled() {
        let mock_rpc = MockServer::start().await;
        let pool = init_sqlite_pool("sqlite::memory:").await.unwrap();
        let repo = InvoiceRepository::new(pool);

        let mut cfg_val =
            (*integration_config(format!("{}/json_rpc", mock_rpc.uri()), None, false)).clone();
        cfg_val.allow_private_webhooks = false;
        let cfg = Arc::new(cfg_val);

        let rpc = MoneroRpcClient::new(&cfg.monero_rpc_url, None, None).unwrap();
        let scanner = ScannerService::new(repo.clone(), rpc.clone(), cfg.clone());
        let app = build_router(AppState {
            config: cfg.clone(),
            repo,
            rpc,
            scanner,
        });

        for bad_url in [
            "http://127.0.0.1:9000/hook",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1:8080/hook",
            "http://[::1]:9000/hook",
        ] {
            let resp = app
                .clone()
                .oneshot(
                    Request::post("/api/v1/invoices")
                        .header("content-type", "application/json")
                        .header("X-API-Key", cfg.api_secret_key.as_str())
                        .body(Body::from(format!(
                            r#"{{"order_id":"ssrf-test","amount_piconero":1000000,"callback_url":"{bad_url}"}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 Bad Request for SSRF callback_url {bad_url}"
            );
        }
    }
}
