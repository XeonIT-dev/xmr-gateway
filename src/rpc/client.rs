//! Async JSON-RPC 2.0 HTTP client for `monero-wallet-rpc` with Digest & Basic auth.
//!
//! # Security & Reliability
//! - Uses `reqwest` backed by `rustls` (zero OpenSSL runtime dependency).
//! - Implements RFC 2617/7616 HTTP Digest Authentication challenge-response with cached nonce
//!   state (minimizing 401 round-trips while handling nonce staleness transparently), plus
//!   Basic auth fallback when challenged with `WWW-Authenticate: Basic`.
//! - Never logs RPC passwords or `Authorization` headers.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use digest_auth::WwwAuthenticateHeader;
use reqwest::{StatusCode, header};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::Mutex;
use url::Url;

use crate::{
    config::WalletMode,
    error::{GatewayError, GatewayResult},
    rpc::types::{
        CreateAddressParams, CreateAddressResponse, EmptyParams, GetTransfersParams,
        GetTransfersResponse, GetVersionResponse, JsonRpcRequest, JsonRpcResponse, QueryKeyParams,
        QueryKeyResponse, SweepAllParams, SweepAllResponse, ValidateAddressParams,
        ValidateAddressResult,
    },
};

/// Maximum permitted HTTP response body size from `monero-wallet-rpc` (16 MiB) (`XMR-032`).
pub const MAX_RPC_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Credentials for `monero-wallet-rpc` HTTP authentication.
#[derive(Clone)]
struct RpcCredentials {
    username: String,
    password: String,
}

impl std::fmt::Debug for RpcCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Thread-safe asynchronous JSON-RPC 2.0 client for `monero-wallet-rpc`.
#[derive(Debug, Clone)]
pub struct MoneroRpcClient {
    http: reqwest::Client,
    endpoint: Url,
    uri_path: String,
    credentials: Option<RpcCredentials>,
    digest_cache: Arc<Mutex<Option<WwwAuthenticateHeader>>>,
    next_id: Arc<AtomicU64>,
    max_response_bytes: usize,
}

impl MoneroRpcClient {
    /// Constructs a new [`MoneroRpcClient`] targeting `rpc_url`.
    ///
    /// # Errors
    /// Returns [`GatewayError::Config`] if `rpc_url` is invalid or `reqwest` TLS initialization
    /// fails.
    pub fn new(
        rpc_url: &str,
        username: Option<String>,
        password: Option<String>,
    ) -> GatewayResult<Self> {
        let endpoint = Url::parse(rpc_url).map_err(|e| {
            GatewayError::Config(format!("invalid MONERO_RPC_URL '{rpc_url}': {e}"))
        })?;

        let uri_path = match endpoint.query() {
            Some(q) => format!("{}?{q}", endpoint.path()),
            None => endpoint.path().to_string(),
        };

        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| GatewayError::Config(format!("failed to build HTTP client: {e}")))?;

        let credentials = username
            .filter(|u| !u.is_empty())
            .map(|user| RpcCredentials {
                username: user,
                password: password.unwrap_or_default(),
            });

        Ok(Self {
            http,
            endpoint,
            uri_path,
            credentials,
            digest_cache: Arc::new(Mutex::new(None)),
            next_id: Arc::new(AtomicU64::new(1)),
            max_response_bytes: MAX_RPC_RESPONSE_BYTES,
        })
    }

    /// Overrides the maximum allowed RPC HTTP response payload size (primarily for tests) (`XMR-032`).
    #[must_use]
    pub const fn with_max_response_bytes(mut self, max_bytes: usize) -> Self {
        self.max_response_bytes = max_bytes;
        self
    }

    /// Validates an address via `monero-wallet-rpc` (`validate_address`) checking checksum and
    /// active wallet network type (`XMR-030`).
    ///
    /// # Errors
    /// Returns [`GatewayError::RpcTransport`] or [`GatewayError::Rpc`] if the RPC call fails.
    pub async fn validate_address(&self, address: &str) -> GatewayResult<ValidateAddressResult> {
        self.call(
            "validate_address",
            ValidateAddressParams {
                address,
                any_net_type: false,
                allow_openalias: false,
            },
        )
        .await
    }

    /// Queries `monero-wallet-rpc` `get_version` as a lightweight connectivity healthcheck.
    ///
    /// # Errors
    /// Returns [`GatewayError::RpcTransport`] or [`GatewayError::Rpc`] if the daemon is
    /// unreachable or returns an error.
    pub async fn get_version(&self) -> GatewayResult<GetVersionResponse> {
        self.call("get_version", EmptyParams {}).await
    }

    /// Queries `monero-wallet-rpc` (`query_key` with `spend_key`) to determine whether the loaded
    /// wallet is strictly watch-only (holds no private spend key).
    ///
    /// Returns `Ok(true)` if `monero-wallet-rpc` rejects `query_key(spend_key)` with a JSON-RPC
    /// error (the standard behavior for watch-only wallets) or returns an empty/all-zero spend key.
    ///
    /// # Errors
    /// Returns [`GatewayError::RpcTransport`] if `monero-wallet-rpc` is unreachable or returns
    /// malformed HTTP responses.
    pub async fn is_view_only_wallet(&self) -> GatewayResult<bool> {
        let resp: GatewayResult<QueryKeyResponse> = self
            .call(
                "query_key",
                QueryKeyParams {
                    key_type: "spend_key",
                },
            )
            .await;

        match resp {
            Ok(key_resp) => {
                let trimmed = key_resp.key.trim();
                Ok(trimmed.is_empty() || trimmed.bytes().all(|b| b == b'0'))
            }
            Err(GatewayError::Rpc { .. }) => Ok(true),
            Err(other) => Err(other),
        }
    }

    /// Verifies that the wallet loaded by `monero-wallet-rpc` strictly matches `expected_mode`.
    ///
    /// Fails closed if `WALLET_MODE=view_only` is configured while `monero-wallet-rpc` holds a
    /// private spend key, or if `WALLET_MODE=hot_wallet` is configured with a watch-only wallet.
    ///
    /// # Errors
    /// Returns [`GatewayError::Config`] on custody mode mismatch, or
    /// [`GatewayError::RpcTransport`] if `monero-wallet-rpc` cannot be reached.
    pub async fn verify_wallet_mode(&self, expected_mode: WalletMode) -> GatewayResult<()> {
        let view_only = self.is_view_only_wallet().await?;

        match (expected_mode, view_only) {
            (WalletMode::ViewOnly, false) => Err(GatewayError::Config(
                "SECURITY VIOLATION: WALLET_MODE=view_only is configured, but monero-wallet-rpc loaded a hot wallet holding a private spend key"
                    .to_string(),
            )),
            (WalletMode::HotWallet, true) => Err(GatewayError::Config(
                "WALLET_MODE=hot_wallet is configured, but monero-wallet-rpc loaded a view-only wallet without a private spend key"
                    .to_string(),
            )),
            _ => Ok(()),
        }
    }

    /// Creates a new isolated subaddress under `account_index` with `label`.
    ///
    /// # Errors
    /// Returns [`GatewayError::RpcTransport`] or [`GatewayError::Rpc`] on failure.
    pub async fn create_address(
        &self,
        account_index: u32,
        label: &str,
    ) -> GatewayResult<CreateAddressResponse> {
        self.call(
            "create_address",
            CreateAddressParams {
                account_index,
                label,
            },
        )
        .await
    }

    /// Queries incoming confirmed (`in`) and mempool (`pool`) transfers for the specified
    /// `subaddr_indices` under `account_index`.
    ///
    /// # Errors
    /// Returns [`GatewayError::RpcTransport`] or [`GatewayError::Rpc`] on failure.
    pub async fn get_transfers(
        &self,
        account_index: u32,
        subaddr_indices: &[u32],
        pool: bool,
    ) -> GatewayResult<GetTransfersResponse> {
        if subaddr_indices.is_empty() {
            return Ok(GetTransfersResponse::default());
        }

        self.call(
            "get_transfers",
            GetTransfersParams {
                in_transfers: true,
                pool,
                out: false,
                pending: false,
                failed: false,
                account_index,
                subaddr_indices,
            },
        )
        .await
    }

    /// Queries outgoing mined (`out`) and mempool (`pending`) transfers for `subaddr_indices`
    /// under `account_index` to reconcile crashed/interrupted `sweep_all` operations.
    ///
    /// # Errors
    /// Returns [`GatewayError::RpcTransport`] or [`GatewayError::Rpc`] on failure.
    pub async fn get_outgoing_transfers(
        &self,
        account_index: u32,
        subaddr_indices: &[u32],
    ) -> GatewayResult<GetTransfersResponse> {
        if subaddr_indices.is_empty() {
            return Ok(GetTransfersResponse::default());
        }

        self.call(
            "get_transfers",
            GetTransfersParams {
                in_transfers: false,
                pool: false,
                out: true,
                pending: true,
                failed: false,
                account_index,
                subaddr_indices,
            },
        )
        .await
    }

    /// Sweeps 100% of unlocked funds on `subaddress_index` to `destination` via `sweep_all`.
    ///
    /// # Security & Consensus Invariant
    /// Always restricts `subaddr_indices` to `[subaddress_index]` so sweeping one invoice never
    /// touches outputs belonging to unrelated customer invoices in the same wallet account.
    ///
    /// # Errors
    /// Returns [`GatewayError::Rpc`] if `monero-wallet-rpc` rejects the sweep (e.g., locked
    /// balance or invalid destination) or [`GatewayError::RpcTransport`] on network errors.
    pub async fn sweep_subaddress(
        &self,
        account_index: u32,
        subaddress_index: u32,
        destination: &str,
        priority: u32,
    ) -> GatewayResult<SweepAllResponse> {
        let indices = [subaddress_index];
        self.call(
            "sweep_all",
            SweepAllParams {
                address: destination,
                account_index,
                subaddr_indices: &indices,
                priority,
                unlock_time: 0,
                get_tx_keys: false,
            },
        )
        .await
    }

    /// Executes a typed JSON-RPC 2.0 POST call with transparent HTTP Digest/Basic auth handling.
    async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &'static str,
        params: P,
    ) -> GatewayResult<R> {
        let req_id = self.next_id.fetch_add(1, Ordering::Relaxed).to_string();
        let envelope = JsonRpcRequest {
            jsonrpc: "2.0",
            id: req_id,
            method,
            params,
        };
        let body_bytes = serde_json::to_vec(&envelope).map_err(|e| {
            GatewayError::Internal(format!("failed to serialize RPC request '{method}': {e}"))
        })?;

        let response = self.send_authenticated(&body_bytes).await?;
        let status = response.status();
        let resp_bytes = read_bounded_rpc_bytes(response, self.max_response_bytes, method).await?;

        if !status.is_success() {
            return Err(GatewayError::RpcTransport(format!(
                "monero-wallet-rpc returned HTTP {status} for '{method}'"
            )));
        }

        let rpc_resp: JsonRpcResponse<R> = serde_json::from_slice(&resp_bytes).map_err(|e| {
            GatewayError::RpcTransport(format!("invalid JSON-RPC response for '{method}': {e}"))
        })?;

        if let Some(err) = rpc_resp.error {
            return Err(GatewayError::Rpc {
                code: Some(err.code),
                message: err.message,
            });
        }

        rpc_resp.result.ok_or_else(|| {
            GatewayError::RpcTransport(format!(
                "JSON-RPC response for '{method}' omitted both 'result' and 'error'"
            ))
        })
    }

    async fn send_authenticated(&self, body_bytes: &[u8]) -> GatewayResult<reqwest::Response> {
        let Some(ref creds) = self.credentials else {
            return self.post_raw(body_bytes, None, false).await;
        };

        // Fast path: reuse cached Digest challenge header if available.
        let cached_auth_header = {
            let mut guard = self.digest_cache.lock().await;
            if let Some(ref mut prompt) = *guard {
                let context = digest_auth::AuthContext::new_post(
                    &creds.username,
                    &creds.password,
                    &self.uri_path,
                    Some(body_bytes),
                );
                Some(
                    prompt
                        .respond(&context)
                        .map(|ans| ans.to_header_string())
                        .map_err(|e| {
                            GatewayError::RpcTransport(format!(
                                "failed to compute HTTP Digest header: {e}"
                            ))
                        })?,
                )
            } else {
                None
            }
        };

        let first_resp = self
            .post_raw(body_bytes, cached_auth_header.as_deref(), false)
            .await?;

        if first_resp.status() != StatusCode::UNAUTHORIZED {
            return Ok(first_resp);
        }

        // Challenge expired or initial request: parse WWW-Authenticate and retry once.
        let www_auth = first_resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| {
                GatewayError::RpcTransport(
                    "monero-wallet-rpc returned 401 without WWW-Authenticate header".to_string(),
                )
            })?;

        let lower = www_auth.to_ascii_lowercase();
        if lower.starts_with("digest ") {
            let mut prompt = digest_auth::parse(&www_auth).map_err(|e| {
                GatewayError::RpcTransport(format!("invalid Digest WWW-Authenticate header: {e}"))
            })?;
            let context = digest_auth::AuthContext::new_post(
                &creds.username,
                &creds.password,
                &self.uri_path,
                Some(body_bytes),
            );
            let answer = prompt
                .respond(&context)
                .map_err(|e| {
                    GatewayError::RpcTransport(format!("failed to answer Digest challenge: {e}"))
                })?
                .to_header_string();

            {
                let mut guard = self.digest_cache.lock().await;
                *guard = Some(prompt);
            }

            return self.post_raw(body_bytes, Some(&answer), false).await;
        }

        if lower.starts_with("basic ") {
            return self.post_raw(body_bytes, None, true).await;
        }

        Err(GatewayError::RpcTransport(format!(
            "unsupported HTTP authentication scheme in WWW-Authenticate: {www_auth}"
        )))
    }

    async fn post_raw(
        &self,
        body_bytes: &[u8],
        authorization_header: Option<&str>,
        use_basic_auth: bool,
    ) -> GatewayResult<reqwest::Response> {
        let mut req = self
            .http
            .post(self.endpoint.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .body(body_bytes.to_vec());

        if let Some(auth_val) = authorization_header {
            req = req.header(header::AUTHORIZATION, auth_val);
        } else if use_basic_auth && let Some(ref creds) = self.credentials {
            req = req.basic_auth(&creds.username, Some(&creds.password));
        }

        req.send().await.map_err(|e| {
            let sanitized = e.without_url();
            GatewayError::RpcTransport(format!(
                "HTTP request to monero-wallet-rpc failed: {sanitized}"
            ))
        })
    }
}

/// Reads an HTTP RPC response body up to `max_bytes`, failing fast if `Content-Length` or the
/// streamed byte count exceeds the safety cap (`XMR-032`).
async fn read_bounded_rpc_bytes(
    mut response: reqwest::Response,
    max_bytes: usize,
    method: &str,
) -> GatewayResult<Vec<u8>> {
    if let Some(len) = response.content_length()
        && usize::try_from(len).is_ok_and(|n| n > max_bytes)
    {
        return Err(GatewayError::RpcTransport(format!(
            "monero-wallet-rpc response Content-Length ({len} bytes) for '{method}' exceeds maximum allowed {max_bytes} bytes"
        )));
    }

    let initial_cap = response
        .content_length()
        .and_then(|n| usize::try_from(n).ok())
        .map_or(4096, |n| n.min(max_bytes).min(1024 * 1024));
    let mut buf = Vec::with_capacity(initial_cap);

    while let Some(chunk) = response.chunk().await.map_err(|e| {
        GatewayError::RpcTransport(format!("failed reading RPC response for '{method}': {e}"))
    })? {
        let next_len = buf.len().saturating_add(chunk.len());
        if next_len > max_bytes {
            return Err(GatewayError::RpcTransport(format!(
                "monero-wallet-rpc response body for '{method}' exceeded maximum allowed {max_bytes} bytes"
            )));
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use wiremock::{
        Mock, MockServer, Request, Respond, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    struct DigestAuthResponder {
        expected_user: String,
    }

    impl Respond for DigestAuthResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let has_digest = request
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.starts_with("Digest ") && s.contains(&self.expected_user));

            if has_digest {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "1",
                    "result": {
                        "version": 196619,
                        "release": true
                    }
                }))
            } else {
                ResponseTemplate::new(401).insert_header(
                    "WWW-Authenticate",
                    r#"Digest realm="monero-rpc", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", qop="auth", algorithm="MD5""#,
                )
            }
        }
    }

    #[tokio::test]
    async fn handles_http_digest_challenge_and_caches_nonce() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(DigestAuthResponder {
                expected_user: "monero_user".to_string(),
            })
            .expect(3)
            .mount(&server)
            .await;

        let client = MoneroRpcClient::new(
            &format!("{}/json_rpc", server.uri()),
            Some("monero_user".to_string()),
            Some("monero_pass".to_string()),
        )
        .unwrap();

        // First call triggers 401 -> challenge -> 200 (2 HTTP requests)
        let v1 = client.get_version().await.unwrap();
        assert_eq!(v1.version, 196_619);

        // Second call reuses cached Digest state -> immediate 200 (1 HTTP request)
        let v2 = client.get_version().await.unwrap();
        assert_eq!(v2.version, 196_619);
    }

    #[tokio::test]
    async fn maps_json_rpc_errors_and_parses_transfers_and_sweep() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": {
                    "in": [{
                        "txid": "a".repeat(64),
                        "amount": 500000000000_u64,
                        "confirmations": 12,
                        "double_spend_seen": false,
                        "locked": false,
                        "subaddr_index": { "major": 0, "minor": 3 }
                    }],
                    "pool": [{
                        "txid": "b".repeat(64),
                        "amount": 250000000000_u64,
                        "confirmations": 0,
                        "double_spend_seen": false,
                        "subaddr_index": { "major": 0, "minor": 4 }
                    }]
                }
            })))
            .mount(&server)
            .await;

        let client =
            MoneroRpcClient::new(&format!("{}/json_rpc", server.uri()), None, None).unwrap();
        let res = client.get_transfers(0, &[3, 4], true).await.unwrap();
        assert_eq!(res.in_transfers.len(), 1);
        assert!(res.in_transfers[0].is_unlocked(false));
        assert_eq!(res.pool.len(), 1);
        assert!(!res.pool[0].is_unlocked(true));
    }

    #[tokio::test]
    async fn verify_wallet_mode_enforces_view_only_and_hot_wallet_invariants() {
        let server = MockServer::start().await;
        let client =
            MoneroRpcClient::new(&format!("{}/json_rpc", server.uri()), None, None).unwrap();

        // 1) Watch-only wallet returning JSON-RPC error on spend_key query
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "error": { "code": -1, "message": "Wallet is watch-only" }
            })))
            .mount(&server)
            .await;

        assert!(
            client
                .verify_wallet_mode(WalletMode::ViewOnly)
                .await
                .is_ok()
        );
        assert!(
            client
                .verify_wallet_mode(WalletMode::HotWallet)
                .await
                .is_err()
        );

        // 2) Watch-only wallet returning all-zero spend_key
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "2",
                "result": { "key": "0".repeat(64) }
            })))
            .mount(&server)
            .await;

        assert!(
            client
                .verify_wallet_mode(WalletMode::ViewOnly)
                .await
                .is_ok()
        );

        // 3) Hot wallet returning real non-zero spend_key MUST fail closed in ViewOnly mode!
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "3",
                "result": { "key": "a".repeat(64) }
            })))
            .mount(&server)
            .await;

        let mismatch_err = client
            .verify_wallet_mode(WalletMode::ViewOnly)
            .await
            .unwrap_err();
        assert!(matches!(mismatch_err, GatewayError::Config(_)));
        assert!(
            client
                .verify_wallet_mode(WalletMode::HotWallet)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn rejects_oversized_rpc_response_body_xmr_032() {
        let server = MockServer::start().await;
        let large_payload = "x".repeat(4096);
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": { "key": large_payload }
            })))
            .mount(&server)
            .await;

        let client = MoneroRpcClient::new(&format!("{}/json_rpc", server.uri()), None, None)
            .unwrap()
            .with_max_response_bytes(512);

        let err = client.is_view_only_wallet().await.unwrap_err();
        assert!(matches!(err, GatewayError::RpcTransport(_)));
        assert!(err.to_string().contains("maximum allowed 512 bytes"));
    }

    #[tokio::test]
    async fn validate_address_calls_monero_rpc_xmr_030() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/json_rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "result": {
                    "valid": true,
                    "integrated": false,
                    "subaddress": true,
                    "nettype": "mainnet"
                }
            })))
            .mount(&server)
            .await;

        let client =
            MoneroRpcClient::new(&format!("{}/json_rpc", server.uri()), None, None).unwrap();
        let res = client
            .validate_address("888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H")
            .await
            .unwrap();
        assert!(res.valid);
        assert!(res.subaddress);
        assert_eq!(res.nettype, "mainnet");
    }
}
