# `xmr-gateway`

[![CI](https://github.com/XeonIT-dev/xmr-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/XeonIT-dev/xmr-gateway/actions/workflows/ci.yml)
[![Security Audit](https://github.com/XeonIT-dev/xmr-gateway/actions/workflows/security.yml/badge.svg)](https://github.com/XeonIT-dev/xmr-gateway/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.94%2B-orange.svg)](https://www.rust-lang.org)

**A self-hosted, non-custodial Monero (XMR) payment gateway and isolated subaddress auto-sweep engine written in Rust.**

Designed for sovereign merchants, Telegram commerce bots, and privacy-first infrastructure operators who require zero third-party custody, zero KYC, deterministic atomic accounting, and verifiable cryptographic settlement.

---

## Key Features

- **Non-Custodial Architecture:** Funds settle directly to subaddresses derived from your own `monero-wallet-rpc` wallet. Enforces fail-closed **View-Only Zero-Trust Mode** (`WALLET_MODE=view_only`, verified against `query_key(spend_key)`) and explicit **Hot Auto-Sweep Mode** (`WALLET_MODE=hot_wallet`).
- **Subaddress-Per-Invoice Isolation:** Each invoice allocates a unique Monero subaddress (`account_index: 0`, unique `address_index`) enforced at the SQLite schema level (`UNIQUE(account_index, address_index)`), preventing address reuse and cross-customer correlation.
- **Strict Piconero Integer Accounting:** Floating-point arithmetic (`f32`/`f64`) is strictly banned across the entire codebase. Every amount, transfer, fee, and SQLite column uses atomic integer `Piconero(u64)` ($1\text{ XMR} = 10^{12}\text{ piconero}$) in SQLite WAL mode with `synchronous = FULL`, `0700`/`0600` filesystem hardening, and multi-output batched transaction accuracy (`UNIQUE(invoice_id, txid)`).
- **Reorg-Safe Payment State Machine & Continuous Subaddress Accounting:** Tracks `PENDING`, `UNDERPAID`, `MEMPOOL` (`0-conf`), `CONFIRMING` (`1..REQUIRED_CONFIRMATIONS`), `CONFIRMED` (`>= REQUIRED_CONFIRMATIONS`, default `10`), `SETTLED` (`>= SETTLEMENT_CONFIRMATIONS`, default `10`), `REORGED`, `COMPLETED`, `SWEPT`, and `EXPIRED`, plus `LATE_PAYMENT` and `OVERPAYMENT` ledger tracking across all subaddresses (`SUBADDRESS_MONITOR_DAYS=0` continuous monitoring by default), epoch-scoped webhook recovery after reorgs, and `ACTIVE` / `ORPHANED` / `SWEPT` audit states.
- **Double-Spend Protection & Crash-Safe Sweeps:** Outputs flagged `double_spend_seen == true` in mempool (`confirmations == 0`) stay excluded until canonically mined (`confirmations > 0 && !double_spend_seen`), which cleanly restores `ACTIVE` balance state. Isolated `sweep_all` operations record durable `sweep_attempts` (`PREPARED` → `SUBMITTED` → `CONFIRMED` (`>= SETTLEMENT_CONFIRMATIONS`) / `RECONCILED` | `FAILED` | `REORGED`) so crashed sweeps recover via `get_transfers(out, pending)`, and any disappeared or double-spent outbound sweep escalates `SWEPT -> REORGED` (`SWEEP_REORG_DETECTED`) while blocking automatic re-sweep.
- **SSRF-Hardened Durable HMAC-SHA256 Webhooks:** Outbound `callback_url` targets undergo IP/DNS SSRF filtering (`ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS`), connection-time socket pinning against DNS rebinding, zero redirect following, and SQLite WAL outbox retries (`5s` up to `3600s`, 10 attempts).
- **Constant-Time API Authentication:** `/api/v1/*` routes verify `X-API-Key` by hashing both presented and expected secrets with SHA-256 before `subtle::ConstantTimeEq` comparison, preventing length timing side-channels.

---

## Architecture & Payment Lifecycle

```text
+-----------------------+       POST /api/v1/invoices (X-API-Key)       +---------------------------+
|                       | --------------------------------------------> |                           |
|   Merchant Backend    |                                               |     xmr-gateway     |
| (Bot / Storefront)    | <-------------------------------------------- |      (Axum REST API)      |
|                       |   POST Webhook + X-Signature-256 (HMAC-SHA256)|       127.0.0.1:8080      |
+-----------------------+                                               +-------------+-------------+
                                                                                      |
                                          +-------------------------------------------+-------------------------------------------+
                                          |                                           |                                           |
                                          v                                           v                                           v
                              +-----------------------+                   +-----------------------+                   +-----------------------+
                              |  SQLite (WAL Mode)    |                   |  Background Scanner   |                   |  Webhook Dispatcher   |
                              |  data/xmr_gateway.db  | <---------------> | - batch get_transfers |                   | - durable outbox      |
                              | - invoices            |                   | - split-tx depth calc |                   | - exponential backoff |
                              | - invoice_transfers   |                   | - double-spend filter |                   | - View-Only complete  |
                              | - webhook_deliveries  |                   | - 10-block auto-sweep |                   +-----------------------+
                              +-----------------------+                   +-----------+-----------+
                                                                                      |
                                                                                      | JSON-RPC 2.0 (HTTP Digest Auth)
                                                                                      | 127.0.0.1:18082
                                                                                      v
                                                                          +-----------------------+
                                                                          |   monero-wallet-rpc   |
                                                                          |  data/wallet/         |
                                                                          | (View-Only / Transit) |
                                                                          +-----------+-----------+
                                                                                      |
                                                                                      | (Optional Tor SOCKS5 127.0.0.1:9050)
                                                                                      v
                                                                          +-----------------------+
                                                                          |     Monero Daemon     |
                                                                          |  (Mainnet / Stagenet) |
                                                                          +-----------------------+
```

### State Machine

```text
                                 +-------------+
                                 |   PENDING   | <--- create_address(account=0)
                                 +------+------+
                                        |
              +-------------------------+-------------------------+
              |                         |                         |
   (0 < rx < expected)          (now >= expires_at)       (rx >= expected,
              |                 & rx < expected           0 confirmations)
              v                         |                         |
      +-------+-------+                 |                         v
      |   UNDERPAID   | ----------------+                 +-------+-------+
      +-------+-------+                 |                 |    MEMPOOL    |
              |                         v                 +-------+-------+
              |                 +---------------+                 |
              |                 |    EXPIRED    |       (1 <= conf < REQ_CONF)
              |                 +-------+-------+                 |
              |             (late tx)   |                         v
              |                         v                 +-------+-------+
              |                  LATE_PAYMENT             |  CONFIRMING   |
              |                                           +-------+-------+
              |                                                   |
              +---------> (rx >= expected & conf >= REQ_CONF) <---+
                                        |
                                        v     (depth drops / double-spend)
                                +-------+-------+ ------------------------+
                                |   CONFIRMED   |                         |
                                +-------+-------+                         v
                                        |                         +-------+-------+
                       (conf >= SETTLEMENT_CONFIRMATIONS)         |    REORGED    |
                                        |                         +---------------+
                                        v                         (Webhook: REORGED)
                                +-------+-------+
                                |    SETTLED    | ---> Webhook: SETTLED
                                +-------+-------+
                                        |
              +-------------------------+-------------------------+
              |                                                   |
 (ENABLE_AUTO_SWEEP=false,                            (ENABLE_AUTO_SWEEP=true,
  only after SETTLED webhook 2xx)                      sweep_attempts PREPARED->SUBMITTED->CONFIRMED)
              |                                                   |
              v                                                   v
      +-------+-------+                                   +-------+-------+
      |   COMPLETED   | ---> (deep reorg -> REORGED)      |     SWEPT     | ---> Webhook: SWEPT
      +---------------+      (recovers via CONFIRMED)     +-------+-------+      (outbound sweep reorg -> REORGED,
                                                                                  auto re-sweep blocked)
      (continuously monitored via SUBADDRESS_MONITOR_DAYS=0; residual OVERPAYMENT / EXPIRED LATE_PAYMENT sweepable)
```

---

## Custody Modes: View-Only vs. Hot Auto-Sweep

| Feature | View-Only Mode (`WALLET_MODE=view_only`, `ENABLE_AUTO_SWEEP=false`) | Hot Auto-Sweep Mode (`WALLET_MODE=hot_wallet`, `ENABLE_AUTO_SWEEP=true`) |
| :--- | :--- | :--- |
| **Private Spend Key on Server** | **Forbidden** (`start.sh` and gateway verify `query_key(spend_key)` fails or returns zero) | **Yes** (hot transit wallet; explicit opt-in required) |
| **First-Run Bootstrap** | Fail-closed unless `MONERO_VIEW_ONLY_ADDRESS` & `MONERO_VIEW_ONLY_KEY` are set | Generates hot transit wallet (`ENABLE_AUTO_SWEEP=true` or `ALLOW_HOT_WALLET_WITHOUT_SWEEP=true`) |
| **Remote Daemon Policy** | `--untrusted-daemon` by default (`MONERO_TRUSTED_DAEMON=false`) | `--untrusted-daemon` unless `MONERO_TRUSTED_DAEMON=true` |
| **Settlement Flow** | Stays active in `CONFIRMED` for reorg checks until `SETTLED` webhook 2xx (`COMPLETED`); `COMPLETED` stays monitored for deep reorgs | Crash-safe `sweep_attempts` (`PREPARED`→`SUBMITTED`→`CONFIRMED` at `>= SETTLEMENT_CONFIRMATIONS` / `RECONCILED` / `REORGED`) |
| **Terminal State** | `COMPLETED` (monitored for deep reorg `COMPLETED->REORGED->CONFIRMED->SETTLED->COMPLETED`) | `SWEPT` (`SWEPT->REORGED` on outbound sweep reorg with auto re-sweep blocked; `EXPIRED` preserves `EXPIRED`) |

---

## Prerequisites & Quickstart

### 1. System Dependencies

Install Rust (`1.94+`) via [rustup](https://rustup.rs) and standard CLI tools:

- **Fedora:**
  ```bash
  sudo dnf install -y curl tar bzip2 openssl jq gcc pkg-config
  ```
- **Debian / Ubuntu:**
  ```bash
  sudo apt-get update && sudo apt-get install -y curl tar bzip2 openssl jq build-essential pkg-config
  ```

### 2. Clone, Configure & Build

```bash
git clone https://github.com/XeonIT-dev/xmr-gateway.git
cd xmr-gateway

cp .env.example .env
openssl rand -hex 32   # API_SECRET_KEY
openssl rand -hex 32   # WEBHOOK_SECRET
openssl rand -hex 24   # MONERO_RPC_PASS
```

Edit `.env` with your generated secrets and desired network (`MONERO_NETWORK=mainnet` or `stagenet`), or let `./start.sh` auto-generate missing secrets for you.

Build the optimized release binary:

```bash
cargo build --release
```

### 3. Install `monero-wallet-rpc` & Launch

Run the native orchestrator script:

```bash
./start.sh
```

What `./start.sh` handles automatically:
1. Generates 32-byte random secrets in `.env` if placeholders are still present.
2. Downloads the official Linux x64 Monero CLI release (`monero-wallet-rpc` and `monero-wallet-cli`) into `./bin/` and verifies its SHA-256 digest against `https://www.getmonero.org/downloads/hashes.txt` (or run `make setup-rpc` beforehand).
3. Initializes a local wallet in `./data/wallet/` at `WALLET_RESTORE_HEIGHT` (avoids scanning from genesis block `0`).
4. Starts `monero-wallet-rpc` bound strictly to `127.0.0.1:18082` connected to `MONERO_REMOTE_NODE` (zero local blockchain disk bloat), optionally routed through Tor (`MONERO_RPC_PROXY=127.0.0.1:9050`).
5. Starts `./target/release/xmr-gateway` and gracefully shuts down both processes on `SIGINT`/`SIGTERM`.

### 4. Single-Terminal Stagenet Live Demo

To test end-to-end payments with free Stagenet faucet coins in one terminal (with color-coded `[RPC]`, `[GATEWAY]`, and `[WEBHOOK]` logs plus an HMAC-verifying Python webhook listener):

```bash
# Configure .env with MONERO_NETWORK=stagenet and a stagenet remote node first
./demo-stagenet.sh
```

---

## API Reference

All `/api/v1/*` endpoints require header `X-API-Key: <API_SECRET_KEY>`.

### `GET /health` (Public Minified / Authenticated Detailed)

Unauthenticated requests return ONLY `{"status": "ok" | "degraded" | "unhealthy"}` without leaking version, database, or RPC details (`XMR-033`). Passing a valid `X-API-Key` header returns full service, database, RPC, and auto-sweep diagnostics:

```bash
curl -s http://127.0.0.1:8080/health | jq .
# -> {"status": "ok"}

curl -s -H "X-API-Key: ${API_SECRET_KEY}" http://127.0.0.1:8080/health | jq .
```

```json
{
  "status": "ok",
  "service": "xmr-gateway",
  "version": "0.1.0",
  "database": "connected",
  "monero_rpc": {
    "connected": true,
    "version": 196619,
    "error": null
  },
  "auto_sweep_enabled": false
}
```

### `POST /api/v1/invoices`

Creates a dedicated subaddress invoice and Base64-encoded PNG QR code. Enforces atomic per-`order_id` serialization and parameter-verified idempotency (`XMR-019` / `XMR-029`): retrying with identical `(order_id, amount_piconero, ttl_seconds, effective callback_url)` returns `200 OK` with the existing invoice without allocating a second subaddress, whereas reusing an `order_id` with different parameters (including changed `ttl_seconds`) returns `409 Conflict`. Note: first-request parameters remain bound even after `EXPIRED`.

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/invoices \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_SECRET_KEY}" \
  -d '{
    "order_id": "order-1042",
    "amount_piconero": 250000000000,
    "callback_url": "http://127.0.0.1:9000/webhooks/monero",
    "ttl_seconds": 3600
  }' | jq .
```

**Response (`201 Created`):**

```json
{
  "invoice_id": "3c8e0f18-7d66-4c31-97a0-6e8df4e53c12",
  "order_id": "order-1042",
  "status": "PENDING",
  "subaddress": "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H",
  "account_index": 0,
  "address_index": 14,
  "amount_piconero": 250000000000,
  "amount_xmr_formatted": "0.250000000000",
  "monero_uri": "monero:888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H?tx_amount=0.250000000000&tx_description=order-1042",
  "qr_code_base64": "iVBORw0KGgoAAAANSUhEUg...",
  "created_at": "2026-11-16T19:45:00Z",
  "expires_at": "2026-11-16T20:45:00Z"
}
```

### `GET /api/v1/invoices/{invoice_id}`

Returns invoice status, received piconero, effective confirmations, transfer breakdown, `sweep_attempts` audit ledger (including incident resolution fields), and sweep hashes.

```bash
curl -s http://127.0.0.1:8080/api/v1/invoices/3c8e0f18-7d66-4c31-97a0-6e8df4e53c12 \
  -H "X-API-Key: ${API_SECRET_KEY}" | jq .
```

### `POST /api/v1/invoices/{invoice_id}/sweep`

Manually triggers `sweep_all` for a `SETTLED` and unlocked (`>= SETTLEMENT_CONFIRMATIONS` / `10+` blocks) invoice, or for residual unswept `OVERPAYMENT`/`LATE_PAYMENT` inflows on `SWEPT` or `EXPIRED` invoices (preserving `EXPIRED` status on late-payment sweeps) when `ENABLE_AUTO_SWEEP=true`. Fails with `409 Conflict` if an unresolved `REORGED` (`SWEEP_REORG_DETECTED`) sweep attempt exists.

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/invoices/3c8e0f18-7d66-4c31-97a0-6e8df4e53c12/sweep \
  -H "X-API-Key: ${API_SECRET_KEY}" | jq .
```

### `POST /api/v1/invoices/{invoice_id}/sweep/resolve`

Safely resolves a `SWEEP_REORG_DETECTED` (`REORGED`) sweep incident while preserving immutable `sweep_attempts` audit history (`resolved_at`, `resolution_action`, `resolution_note`) (`XMR-041` / `XMR-043` / `XMR-044`). Protected by `OPERATOR_API_KEY` when configured (otherwise `API_SECRET_KEY`):

- **`"action": "allow_resweep"`:** Requires `"confirm_absent_on_chain": true` and non-empty `operator_note`; fail-closed verifies wallet sync (`get_height` >= daemon `get_info` height, non-zero; `409 Conflict` if lagging, `503 Service Unavailable` if RPC unavailable) (`XMR-043`) and queries `get_transfers(out=true, pending=true, pool=true)`. If any prior `tx_hash` is still present without `double_spend_seen=true`, rejects with `409 Conflict`. Otherwise marks the attempt `FAILED`, appends verified height/txid metadata to `resolution_note`, restores `subaddress_transfers` to `ACTIVE`, and unblocks re-sweep.
- **`"action": "mark_reconciled"`:** Validates optional `replacement_tx_hash` strictly as 64 hex chars (normalized lowercase) and verifies it exists in wallet `out`/`pending` without `double_spend_seen=true` (`XMR-044`), marks the attempt `RECONCILED`, and restores `SWEPT` status (or preserves `EXPIRED` for late-payment sweeps).

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/invoices/3c8e0f18-7d66-4c31-97a0-6e8df4e53c12/sweep/resolve \
  -H "X-API-Key: ${OPERATOR_API_KEY:-${API_SECRET_KEY}}" \
  -H "Content-Type: application/json" \
  -d '{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"verified old sweep tx absent in daemon mempool and explorer"}' | jq .
```

### `POST /api/v1/webhooks/{webhook_id}/retry` & `POST /api/v1/invoices/{invoice_id}/webhooks/retry`

Resets permanently `FAILED` (or backed-off `PENDING`) webhook outbox deliveries back to `PENDING` with `attempts = 0` for immediate asynchronous retry (`XMR-028`):

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/invoices/3c8e0f18-7d66-4c31-97a0-6e8df4e53c12/webhooks/retry \
  -H "X-API-Key: ${API_SECRET_KEY}" | jq .
```

---

## Hardened Production Systemd Deployment (`XMR-037`)

Production service profiles are provided under `deploy/systemd/`:

- `deploy/systemd/monero-wallet-rpc.service`
- `deploy/systemd/xmr-gateway.service`

```bash
sudo useradd --system --home-dir /var/lib/xmr-gateway --shell /usr/sbin/nologin xmr-gateway
sudo install -d -o xmr-gateway -g xmr-gateway -m 0700 /var/lib/xmr-gateway /var/lib/xmr-gateway/wallet
sudo install -d -m 0750 -o root -g xmr-gateway /etc/xmr-gateway
sudo install -m 0640 -o root -g xmr-gateway .env /etc/xmr-gateway/xmr-gateway.env
sudo install -m 0755 target/release/xmr-gateway /usr/local/bin/xmr-gateway
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now monero-wallet-rpc xmr-gateway
```

---

## Webhook Specification

### HTTP Headers

| Header | Description |
| :--- | :--- |
| `X-Signature-256` | Lowercase hex `HMAC-SHA256` digest of the raw UTF-8 request body signed with `WEBHOOK_SECRET` |
| `X-Webhook-Event` | Event type: `UNDERPAID`, `MEMPOOL`, `CONFIRMED`, `SETTLED`, `REORGED`, `SWEPT`, `EXPIRED`, `LATE_PAYMENT`, or `OVERPAYMENT` |
| `X-Delivery-Id` | Unique UUID of this webhook delivery record |
| `X-Webhook-Timestamp` | RFC 3339 UTC timestamp matching `payload.timestamp` |

### JSON Payload Schema

```json
{
  "event_id": "a7241e09-8d33-4a9b-83cc-1b7d22a1b4a0",
  "event": "CONFIRMED",
  "invoice_id": "3c8e0f18-7d66-4c31-97a0-6e8df4e53c12",
  "order_id": "order-1042",
  "status": "CONFIRMED",
  "subaddress": "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H",
  "address_index": 14,
  "amount_piconero": 250000000000,
  "amount_xmr_formatted": "0.250000000000",
  "received_piconero": 250000000000,
  "received_xmr_formatted": "0.250000000000",
  "confirmations": 2,
  "unlocked": false,
  "double_spend_seen": false,
  "sweep_tx_hashes": [],
  "sweep_amount_piconero": null,
  "sweep_fee_piconero": null,
  "timestamp": "2026-11-16T19:49:12Z"
}
```

### Retry & Replay Policy

- **Exponential Backoff & Bounded Response Reads:** Failed or non-`2xx` deliveries read at most `1024` bytes from the response body stream (truncating diagnostics to 256 chars) to prevent response-body memory exhaustion, and are persisted in SQLite WAL outbox for retry (`5 * 2^(attempt - 1)` seconds up to `3600` seconds, max `10` attempts before `FAILED`).
- **Signature & Replay Verification:** Consumers MUST verify `X-Signature-256` over the **exact raw request bytes** in constant time, enforce a freshness window on `timestamp`, and deduplicate by `event_id` (or `order_id` + `event`).

#### Python Verification Example

```python
import hashlib
import hmac

def verify_gateway_webhook(secret: str, raw_body: bytes, signature_header: str) -> bool:
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header.strip().lower())
```

#### Rust Verification Example

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub fn verify_webhook(secret: &str, raw_body: &[u8], signature_hex: &str) -> bool {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(raw_body);
    let expected = hex::encode(mac.finalize().into_bytes());
    let (Ok(a), Ok(b)) = (hex::decode(expected), hex::decode(signature_hex.trim())) else {
        return false;
    };
    a.len() == b.len() && bool::from(a.ct_eq(&b))
}
```

---

## Security Best Practices

- **Keep Loopback Bindings:** Leave `HOST=127.0.0.1` and expose the API only to local services or behind a TLS reverse proxy (Caddy/Nginx). Never expose `monero-wallet-rpc` (`127.0.0.1:18082`) to public interfaces.
- **SSRF & DNS Rebinding Defense (`XMR-001`):** Leave `ALLOW_PRIVATE_WEBHOOKS=false` in production (and optionally set `REQUIRE_HTTPS_WEBHOOKS=true`) so webhook callbacks cannot target loopback, RFC1918 subnets, cloud metadata endpoints (`169.254.169.254`), or HTTP `3xx` redirects.
- **Enforce Fail-Closed View-Only Mode (`XMR-002`):** Unless you require automated hot treasury sweeping, set `WALLET_MODE=view_only` and `ENABLE_AUTO_SWEEP=false`, providing `MONERO_VIEW_ONLY_ADDRESS` and `MONERO_VIEW_ONLY_KEY` in `.env`. Both `start.sh` and `xmr-gateway` abort startup if `monero-wallet-rpc` exposes a spend key in `view_only` mode.
- **Untrusted Remote Nodes (`XMR-005`):** `MONERO_TRUSTED_DAEMON=false` passes `--untrusted-daemon` by default. Route traffic through Tor (`MONERO_RPC_PROXY=127.0.0.1:9050`) when connecting to third-party public nodes.
- **SQLite Full Durability (`XMR-007`), Singleton Process Lock (`P1-3`), & Crash-Safe Sweeps (`XMR-003`):** SQLite WAL runs with `synchronous = FULL`; `acquire_database_lock` enforces an exclusive advisory lockfile (`<db_path>.lock`, mode `0600`) to prevent multiple instances from concurrently accessing the same wallet/DB; and `sweep_attempts` (`PREPARED`→`SUBMITTED`→`RECONCILED`) recovers interrupted sweeps via `get_transfers(out, pending)` without duplicate `sweep_all` calls.
- **Directory & Env Hardening:** `start.sh` enforces `umask 077`, `chmod 600 .env`, and `chmod 700` on `data/` and `data/wallet/` on every run.
- **Mainnet vs. Stagenet Checklist:**
  - Verify `MONERO_NETWORK=mainnet` and a mainnet `MONERO_REMOTE_NODE` before production launch.
  - Ensure `API_SECRET_KEY`, `WEBHOOK_SECRET`, and `MONERO_RPC_PASS` are freshly generated 32-byte random secrets (`openssl rand -hex 32`).
  - Back up your 25-word mnemonic seed offline (or hardware wallet seed in View-Only mode) and set `chmod 600` on `.env` and `./data/wallet/*`.

---

## Development & Verification

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Licensed under the [MIT License](LICENSE).
