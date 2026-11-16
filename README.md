# `xmr-gateway`

[![CI](https://github.com/XeonIT-dev/xmr-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/XeonIT-dev/xmr-gateway/actions/workflows/ci.yml)
[![Security Audit](https://github.com/XeonIT-dev/xmr-gateway/actions/workflows/security.yml/badge.svg)](https://github.com/XeonIT-dev/xmr-gateway/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.88%2B-orange.svg)](https://www.rust-lang.org)

**A self-hosted, non-custodial Monero (XMR) payment gateway and isolated subaddress auto-sweep engine written in Rust.**

Designed for sovereign merchants, Telegram commerce bots, and privacy-first infrastructure operators who require zero third-party custody, zero KYC, deterministic atomic accounting, and verifiable cryptographic settlement.

---

## Key Features

- **Non-Custodial Architecture:** Funds settle directly to subaddresses derived from your own `monero-wallet-rpc` wallet. Supports both **View-Only Zero-Trust Mode** (no spend key on the server) and **Hot Auto-Sweep Mode**.
- **Subaddress-Per-Invoice Isolation:** Each invoice allocates a unique Monero subaddress (`account_index: 0`, unique `address_index`) enforced at the SQLite schema level (`UNIQUE(account_index, address_index)`), preventing address reuse and cross-customer correlation.
- **Strict Piconero Integer Accounting:** Floating-point arithmetic (`f32`/`f64`) is strictly banned across the entire codebase. Every amount, transfer, fee, and SQLite column uses atomic integer `Piconero(u64)` ($1\text{ XMR} = 10^{12}\text{ piconero}$).
- **Idempotent Payment State Machine:** Tracks `PENDING`, `UNDERPAID` (multi-tx partial payments), `MEMPOOL` (`0-conf`), `CONFIRMED` (`>= REQUIRED_CONFIRMATIONS`), `COMPLETED` (View-Only terminal state), `SWEPT` (Auto-Sweep terminal state), and `EXPIRED`.
- **Double-Spend & 10-Block Consensus Protection:** Outputs flagged `double_spend_seen == true` are excluded from paid totals. Sweeps strictly enforce Monero's 10-block output lock (`confirmations >= 10` and `!locked`) and isolate `sweep_all` to `subaddr_indices: [address_index]`.
- **Durable HMAC-SHA256 Webhooks:** Payloads are serialized once, persisted in a SQLite WAL outbox, signed using `HMAC-SHA256` (`X-Signature-256`), and retried with capped exponential backoff (`5s` up to `3600s`, 10 attempts).
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
              |                 |    EXPIRED    |                 |
              |                 +---------------+                 |
              |                   (Terminal)                      |
              |                                                   |
              +-----------> (rx >= expected & conf >= REQ) <------+
                                        |
                                        v
                                +-------+-------+
                                |   CONFIRMED   | ---> Webhook: CONFIRMED
                                +-------+-------+
                                        |
              +-------------------------+-------------------------+
              |                                                   |
 (ENABLE_AUTO_SWEEP=false,                            (ENABLE_AUTO_SWEEP=true,
  after CONFIRMED webhook 2xx)                         all outputs unlocked >= 10 blocks)
              |                                                   |
              v                                                   v
      +-------+-------+                                   +-------+-------+
      |   COMPLETED   |                                   |     SWEPT     | ---> Webhook: SWEPT
      +---------------+                                   +---------------+
         (Terminal)                                          (Terminal)
```

---

## Custody Modes: View-Only vs. Hot Auto-Sweep

| Feature | View-Only Mode (`ENABLE_AUTO_SWEEP=false`) | Hot Auto-Sweep Mode (`ENABLE_AUTO_SWEEP=true`) |
| :--- | :--- | :--- |
| **Private Spend Key on Server** | **No** (view-only wallet only) | **Yes** (hot transit wallet) |
| **Server Compromise Impact** | Attacker can observe incoming invoice amounts; **funds cannot be spent** | Attacker could spend unlocked funds waiting on transit subaddresses |
| **Settlement Flow** | Funds remain directly in your offline/hardware wallet | Gateway sweeps each subaddress after 10 confirmations to `COLD_WALLET_ADDRESS` |
| **Terminal State** | `COMPLETED` (on `CONFIRMED` webhook 2xx) | `SWEPT` (on `sweep_all` success) |

---

## Prerequisites & Quickstart

### 1. System Dependencies

Install Rust (`1.88+`) via [rustup](https://rustup.rs) and standard CLI tools:

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

### `GET /health` (Public)

Checks SQLite database readiness and probes `monero-wallet-rpc` (`get_version`) with a 3-second timeout.

```bash
curl -s http://127.0.0.1:8080/health | jq .
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

Creates a dedicated subaddress invoice and Base64-encoded PNG QR code.

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

Returns invoice status, received piconero, effective confirmations, transfer breakdown, and sweep hashes.

```bash
curl -s http://127.0.0.1:8080/api/v1/invoices/3c8e0f18-7d66-4c31-97a0-6e8df4e53c12 \
  -H "X-API-Key: ${API_SECRET_KEY}" | jq .
```

### `POST /api/v1/invoices/{invoice_id}/sweep`

Manually triggers `sweep_all` for a `CONFIRMED` and unlocked (`>= 10` confirmations) invoice when `ENABLE_AUTO_SWEEP=true`.

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/invoices/3c8e0f18-7d66-4c31-97a0-6e8df4e53c12/sweep \
  -H "X-API-Key: ${API_SECRET_KEY}" | jq .
```

---

## Webhook Specification

### HTTP Headers

| Header | Description |
| :--- | :--- |
| `X-Signature-256` | Lowercase hex `HMAC-SHA256` digest of the raw UTF-8 request body signed with `WEBHOOK_SECRET` |
| `X-Webhook-Event` | Event type: `UNDERPAID`, `MEMPOOL`, `CONFIRMED`, `SWEPT`, or `EXPIRED` |
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

- **Exponential Backoff:** Failed or non-`2xx` deliveries are persisted in SQLite and retried with delay `5 * 2^(attempt - 1)` seconds, capped at `3600` seconds (1 hour), up to `10` attempts before transitioning to `FAILED`.
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
- **Reverse Proxy Example (Caddy):**
  ```caddyfile
  pay.example.com {
      reverse_proxy 127.0.0.1:8080
  }
  ```
- **Prefer View-Only Mode:** Unless you require automated hot treasury sweeping, set `ENABLE_AUTO_SWEEP=false` and run `monero-wallet-rpc` with a view-only wallet generated offline (`monero-wallet-cli --generate-from-view-key`).
- **Route Remote Node Traffic via Tor:** Install `tor` and set `MONERO_RPC_PROXY=127.0.0.1:9050` in `.env` so remote node operators cannot observe your server IP.
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
