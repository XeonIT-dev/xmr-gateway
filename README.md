# `xmr-gateway`

[![CI](https://github.com/XeonIT-dev/xmr-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/XeonIT-dev/xmr-gateway/actions/workflows/ci.yml)
[![Security Audit](https://github.com/XeonIT-dev/xmr-gateway/actions/workflows/security.yml/badge.svg)](https://github.com/XeonIT-dev/xmr-gateway/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.94%2B-orange.svg)](https://www.rust-lang.org)

**A self-hosted, non-custodial Monero (XMR) payment gateway and isolated subaddress auto-sweep engine written in Rust.**

Designed for sovereign merchants, Telegram commerce bots, and privacy-first infrastructure operators who want a self-hosted gateway with no third-party payment processor intermediary, deterministic atomic accounting, and verifiable cryptographic settlement.

---

## Key Features

- **Non-Custodial Architecture:** Funds settle directly to subaddresses derived from your own `monero-wallet-rpc` wallet. Enforces fail-closed **View-Only Zero-Trust Mode** (`WALLET_MODE=view_only`, verified against `query_key(spend_key)`) and explicit **Hot Auto-Sweep Mode** (`WALLET_MODE=hot_wallet`).
- **Subaddress-Per-Invoice Isolation:** Each invoice allocates a unique Monero subaddress (`account_index: 0`, unique `address_index`) enforced at the SQLite schema level (`UNIQUE(account_index, address_index)`), preventing address reuse and cross-customer correlation.
- **Strict Piconero Integer Accounting:** Floating-point arithmetic (`f32`/`f64`) is strictly banned across the entire codebase. Every amount, transfer, fee, and SQLite column uses atomic integer `Piconero(u64)` ($1\text{ XMR} = 10^{12}\text{ piconero}$) in SQLite WAL mode with `synchronous = FULL`, `0700`/`0600` filesystem hardening, and multi-output batched transaction accuracy (`UNIQUE(invoice_id, txid)`).
- **Reorg-Safe Payment State Machine & Continuous Subaddress Accounting:** Tracks `PENDING`, `UNDERPAID`, `MEMPOOL` (`0-conf`), `CONFIRMING` (`1..REQUIRED_CONFIRMATIONS`), `CONFIRMED` (`>= REQUIRED_CONFIRMATIONS`, default `10`), `SETTLED` (covering set of **unlocked** outputs `>= invoice amount` at `>= SETTLEMENT_CONFIRMATIONS`, default `10`, immune to mempool dust DoS; `XMR-AUDIT-001`), `REORGED`, `COMPLETED`, `SWEPT`, and `EXPIRED`, plus `LATE_PAYMENT` and `OVERPAYMENT` ledger tracking across all subaddresses (`SUBADDRESS_MONITOR_DAYS=0` continuous monitoring by default), epoch-scoped webhook recovery after reorgs, and `ACTIVE` / `ORPHANED` / `SWEPT` audit states.
- **Double-Spend Protection & Crash-Safe Sweeps:** Outputs flagged `double_spend_seen == true` in mempool (`confirmations == 0`) stay excluded until canonically mined (`confirmations > 0 && !double_spend_seen`), which cleanly restores `ACTIVE` balance state. Isolated `sweep_all` operations record durable `sweep_attempts` (`PREPARED` → `SUBMITTED` → `CONFIRMED` (`>= SETTLEMENT_CONFIRMATIONS`) / `RECONCILED` | `FAILED` | `REORGED`) so crashed sweeps recover via `get_transfers(out, pending)`, and any disappeared or double-spent outbound sweep escalates `SWEPT -> REORGED` (`SWEEP_REORG_DETECTED`) while blocking automatic re-sweep.
- **SSRF-Hardened Durable HMAC-SHA256 Webhooks:** Outbound `callback_url` targets undergo IP/DNS SSRF filtering (`ALLOW_PRIVATE_WEBHOOKS=false`, fail-closed `REQUIRE_HTTPS_WEBHOOKS=true` for public mainnet webhooks), connection-time socket pinning against DNS rebinding, zero redirect following, fresh per-attempt `X-Webhook-Timestamp` + `X-Webhook-Signature` signing across retries (with immutable `event_id` payload), and SQLite WAL outbox retries (`5s` up to `3600s`, 10 attempts).
- **Constant-Time API Authentication:** `/api/v1/*` routes verify `X-API-Key` by hashing both presented and expected secrets with SHA-256 before `subtle::ConstantTimeEq` comparison, preventing length timing side-channels.

---

## Architecture & Payment Lifecycle

```text
+-----------------------+       POST /api/v1/invoices (X-API-Key)       +---------------------------+
|                       | --------------------------------------------> |                           |
|   Merchant Backend    |                                               |     xmr-gateway     |
| (Bot / Storefront)    | <-------------------------------------------- |      (Axum REST API)      |
|                       |   POST Webhook + X-Webhook-Signature / TS     |       127.0.0.1:8080      |
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

### Trust Boundaries & Architectural Scope

- **View-Only Mode (`WALLET_MODE=view_only`, recommended default):** The server holds only the private view key and primary public address; no private spend key ever touches the gateway host. Even a full server compromise cannot steal funds (only view incoming amounts and metadata).
- **Hot-Wallet Mode (`WALLET_MODE=hot_wallet`):** The private spend key resides inside `monero-wallet-rpc` on the host so the gateway can sign `sweep_all` transactions. Treat it strictly as an **ephemeral operational transit wallet**: keep only minimal operational transit balances, strictly isolate the host/network and `127.0.0.1:18082` RPC endpoint, enforce a distinct `OPERATOR_API_KEY`, and sweep promptly to an offline or hardware `COLD_WALLET_ADDRESS`.
- **Single-Instance SQLite / Single-Merchant Model:** `xmr-gateway` is designed for **self-hosted, single-merchant operation** backed by a single SQLite WAL database and a single `monero-wallet-rpc` wallet. An exclusive `<db_path>.lock` file enforces strictly one active gateway process per database and wallet (do not horizontally scale multiple instances against the same SQLite file or wallet).
- **Opaque `order_id` Values (No PII):** Pass opaque internal identifiers (e.g., UUIDs or random order tokens such as `ord_7f9a2c`) as `order_id` rather than emails, usernames, phone numbers, or customer names — `order_id` is recorded in operational logs, `monero:` URI `tx_description` fields, and `monero-wallet-rpc` subaddress labels (`inv_<order_id>`).

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

> [!WARNING]
> **Two Critical Production Rules Before Accepting Payments** (full details in [DEPLOY_EN.md](DEPLOY_EN.md#32-configuring-etcxmr-gatewayenv--wallet-initialization) and [admin/GUIDE_EN.md](admin/GUIDE_EN.md)):
> 1. **Wait for initial wallet sync (`lag=0`) before creating invoices:** After creating, importing (`view_only`), or rescanning a wallet, do **not** open payment traffic while `config doctor` reports `lag > 0` on `wallet_daemon_sync`. While `wallet_height < daemon_height`, `monero-wallet-rpc` still sees unconfirmed mempool transactions (`pool`) immediately, but as soon as the transaction is mined into a block above `wallet_height` it disappears from `pool` before appearing in `in` — causing the scanner to fail-closed into `REORGED` and emit a transient **false `REORGED` webhook** (which self-heals to `CONFIRMED`/`SETTLED`/`COMPLETED` once `lag=0`, but can disrupt merchant order state). Verify sync first:
>    `./admin.sh config doctor` (or `sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config doctor | grep wallet_daemon_sync`) $\rightarrow$ `[PASS] wallet_daemon_sync ... (lag=0, daemon_synchronized=true)`.
> 2. **Always use a dedicated clean wallet (never attach a used wallet to a fresh DB):** Monero subaddresses are deterministic (`account=0, index=1, 2, 3...`). A fresh `xmr_gateway.db` allocates subaddresses starting from `index=1`; if the wallet already has historical incoming transactions on those subaddresses, the scanner will credit those old inflows toward newly created invoices — marking them `CONFIRMED`/`COMPLETED` (and emitting `OVERPAYMENT`) without any new payment from the customer. Never delete `xmr_gateway.db` while keeping an already-used wallet, and always back up/restore wallet files and `xmr_gateway.db` together.

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

Unauthenticated requests return ONLY `{"status": "ok" | "degraded" | "unhealthy"}` without leaking version, database, or RPC details (`XMR-033`). Passing a valid `X-API-Key` (merchant or operator key) or `X-Operator-Key` (`OPERATOR_API_KEY`, or `API_SECRET_KEY` when `OPERATOR_API_KEY` is unset; passing the merchant key in `X-Operator-Key` while `OPERATOR_API_KEY` is set is rejected as unauthenticated) returns full service, database, RPC, and auto-sweep diagnostics (`AUDIT-002`):

```bash
curl -s http://127.0.0.1:8080/health | jq .
# -> {"status": "ok"}

curl -s -H "X-API-Key: ${API_SECRET_KEY}" http://127.0.0.1:8080/health | jq .
curl -s -H "X-Operator-Key: ${OPERATOR_API_KEY}" http://127.0.0.1:8080/health | jq .
```

```json
{
  "status": "ok",
  "service": "xmr-gateway",
  "version": "0.1.5",
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

Creates a dedicated subaddress invoice and Base64-encoded PNG QR code. Use opaque, PII-free values for `order_id` (it appears in operational logs, `monero:` URIs, and wallet labels). Enforces atomic per-`order_id` serialization and parameter-verified idempotency (`XMR-019` / `XMR-029`): retrying with identical `(order_id, amount_piconero, ttl_seconds, effective callback_url)` returns `200 OK` with the existing invoice without allocating a second subaddress, whereas reusing an `order_id` with different parameters (including changed `ttl_seconds`) returns `409 Conflict`. Note: first-request parameters remain bound even after `EXPIRED`.

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

- **`"action": "allow_resweep"`:** Requires `"confirm_absent_on_chain": true`, non-empty `operator_note`, and a configured `MONERO_DAEMON_RPC_URL` (optionally authenticated via `MONERO_DAEMON_RPC_USER`/`MONERO_DAEMON_RPC_PASS`); fail-closed verifies wallet sync (`monero-wallet-rpc` `get_height` >= `monerod` `get_info` `height`/`target_height` > 0 with `synchronized=true`, `offline!=true`, `untrusted=false`, `status="OK"`, and matching `MONERO_NETWORK`; `503 Service Unavailable` if `MONERO_DAEMON_RPC_URL` is unset or either RPC is unreachable/incomplete, `409 Conflict` if lagging/unsynced/offline/untrusted/wrong-network) (`XMR-043` / `AUDIT-001`) and queries `get_transfers(out=true, pending=true, pool=true)`. Rejects with `409 Conflict` if any prior `tx_hash` OR any live unrecorded outgoing sweep matching the invoice subaddress/destination (e.g., after `SWEEP_AMBIGUOUS_TIMEOUT`) is still present without `double_spend_seen=true`. Otherwise marks the attempt `FAILED`, clears `swept_at` when no confirmed sweeps remain, appends verified height/txid metadata to `resolution_note`, restores `subaddress_transfers` to `ACTIVE`, and unblocks re-sweep (post-recovery `SWEPT` webhooks use epoch- and hash-scoped deduplication).
- **`"action": "mark_reconciled"`:** Validates `replacement_tx_hash` (required when prior `tx_hashes` are empty) strictly as 64 hex chars (normalized lowercase) and verifies the target transaction(s) in wallet `out`/`pending` with `amount > 0`, `!double_spend_seen`, and matching `(account_index, address_index, destination_address)` (`XMR-044` / `AUDIT-004`). Replaces stale reorged hashes on the invoice/attempt, marks snapshot `subaddress_transfers` as `SWEPT`, marks the attempt `RECONCILED` (continuing background confirmation/reorg monitoring through `SETTLEMENT_CONFIRMATIONS`), restores `SWEPT` status with an epoch-scoped `SWEPT` webhook (or preserves `EXPIRED` for late-payment sweeps).

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/invoices/3c8e0f18-7d66-4c31-97a0-6e8df4e53c12/sweep/resolve \
  -H "X-API-Key: ${OPERATOR_API_KEY:-${API_SECRET_KEY}}" \
  -H "Content-Type: application/json" \
  -d '{"action":"allow_resweep","confirm_absent_on_chain":true,"operator_note":"verified old sweep tx absent in daemon mempool and explorer"}' | jq .
```

### `POST /api/v1/webhooks/{webhook_id}/retry` & `POST /api/v1/invoices/{invoice_id}/webhooks/retry`

Both single-delivery and per-invoice webhook retry routes are operator-protected (`OPERATOR_API_KEY` via `X-Operator-Key` or `X-API-Key` when configured; otherwise `API_SECRET_KEY`) and reset strictly permanently `FAILED` webhook outbox deliveries back to `PENDING` (`attempts = 0`) for immediate asynchronous retry (`XMR-028` / `AUDIT-002`). Active or backed-off `PENDING` deliveries are never modified (`409 Conflict` on single retry, untouched and excluded from `retried_count`/`webhook_ids` on batch retry):

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/invoices/3c8e0f18-7d66-4c31-97a0-6e8df4e53c12/webhooks/retry \
  -H "X-Operator-Key: ${OPERATOR_API_KEY:-${API_SECRET_KEY}}" | jq .
```

---

## Production Deployment, Packages & Releases (`XMR-037`)

> For complete instructions across all deployment modes, cryptographic release verification (`SHA256SUMS`, GPG, GitHub Build Provenance Attestations), and reverse proxy hardening, see **[DEPLOY_EN.md](DEPLOY_EN.md)** (English) / **[DEPLOY_RU.md](DEPLOY_RU.md)** (Русский).

### Quick One-Line Installer (Linux `x86_64` & `aarch64`)

Automatically selects `.deb` (Debian/Ubuntu), `.rpm` (Fedora/RHEL), or binary `.tar.gz`, enforcing fail-closed `SHA256SUMS` verification (and optional GPG verification via `--require-gpg`):

```bash
curl -fsSL https://raw.githubusercontent.com/XeonIT-dev/xmr-gateway/main/scripts/install.sh -o install.sh
bash install.sh --dry-run
sudo bash install.sh
```

### Deployment Artifacts Included

- **GitHub Releases (`.deb`, `.rpm`, `.tar.gz`):** Prebuilt native Linux `x86_64` & `aarch64` packages installing `/usr/bin/xmr-gateway`, `/usr/bin/xmr-gateway-admin`, and hardened `systemd` units (never overwriting `/etc/xmr-gateway/.env` or deleting `/var/lib/xmr-gateway`).
- **Systemd Units (`deploy/systemd/`):** `monero-wallet-rpc.service` (delegates to standalone `0755` POSIX helper `/usr/share/xmr-gateway/scripts/render-wallet-rpc-conf.sh` to render RAM-only `0600` `/run/xmr-gateway/wallet-rpc.conf`, preventing password leaks in `ps`), `xmr-gateway.service` (`KillSignal=SIGTERM`, `TimeoutStopSec=30`), and daily hot SQLite backup timer (`xmr-gateway-backup.service` + `xmr-gateway-backup.timer`).
- **Reverse Proxy (`deploy/reverse-proxy/`):** Ready-to-use `Caddyfile` (automatic Let's Encrypt HTTPS) and `nginx-xmr-gateway.conf` (TLS 1.2/1.3 + operator route IP allowlist examples).
- **Docker Compose (`Containerfile`, `deploy/docker/`):** Multi-stage rootless-UID (`10001`) gateway image + SHA256-verified `Containerfile.monero-rpc`, isolated `xmr_internal` network (port `18082` never published), loopback-only `127.0.0.1:8080`, `read_only: true`, `cap_drop: [ALL]`, optional `--profile caddy`.
- **Rootless Podman Quadlet (`deploy/podman/quadlet/`):** Native `systemd --user` Quadlet units with `UserNS=keep-id:uid=10001,gid=10001` and Fedora/RHEL SELinux `:Z` volume relabeling.

---

## Webhook Specification

### HTTP Headers

| Header | Description |
| :--- | :--- |
| `X-Webhook-Timestamp` | Fresh Unix epoch timestamp (seconds) generated for **this delivery attempt** (updated on every automatic and manual retry) |
| `X-Webhook-Signature` | **Recommended primary signature:** lowercase hex `HMAC-SHA256(WEBHOOK_SECRET, "{X-Webhook-Timestamp}.{raw_body}")` freshly computed per delivery attempt to prevent replay attacks while keeping retries fresh |
| `X-Webhook-Event-Id` | Stable event UUID matching `payload.event_id` (constant across all retries for consumer idempotency) |
| `X-Delivery-Id` | Backwards-compatible alias of `X-Webhook-Event-Id` (`webhook_deliveries.id`) |
| `X-Signature-256` | Backwards-compatible legacy lowercase hex `HMAC-SHA256(WEBHOOK_SECRET, raw_body)` digest |
| `X-Webhook-Event` | Event type: `UNDERPAID`, `MEMPOOL`, `CONFIRMED`, `SETTLED`, `REORGED`, `SWEPT`, `EXPIRED`, `LATE_PAYMENT`, or `OVERPAYMENT` |

> [!NOTE]
> **Operational Edge Cases for `REORGED` and `OVERPAYMENT`:**
> - **Transient false `REORGED` when wallet is still syncing (`lag > 0`):** If an invoice is paid while `wallet_height` lags behind `daemon_height`, the gateway detects the 0-conf payment in `pool` (`MEMPOOL`), then temporarily loses sight of it when the transaction is mined at a block height the wallet has not scanned yet — triggering a fail-closed `REORGED` webhook (`reorg_epoch + 1`). Once the wallet catches up (`lag=0`), the invoice automatically recovers to `CONFIRMED` / `SETTLED` / `COMPLETED`. Prevent this by opening traffic only after `config doctor` reports `wallet_daemon_sync` `lag=0`.
> - **Unexpected immediate `CONFIRMED` / `COMPLETED` / `OVERPAYMENT` on a new invoice:** Occurs if a wallet with prior subaddress transaction history (`account=0, index=1, 2...`) is connected to a new or wiped `xmr_gateway.db`. Always provision a dedicated clean wallet for `xmr-gateway`.

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

### Retry, Freshness & Idempotency Policy

- **Exponential Backoff & Bounded Response Reads:** Failed or non-`2xx` deliveries read at most `1024` bytes from the response body stream (truncating diagnostics to 256 chars) to prevent response-body memory exhaustion, and are persisted in SQLite WAL outbox for retry (`5 * 2^(attempt - 1)` seconds up to `3600` seconds, max `10` attempts before `FAILED`).
- **Fresh Per-Attempt Signatures & Immutable Event Identity:** The business event (`event_id` / `X-Webhook-Event-Id` and exact raw JSON body bytes) never changes between retries. On **every delivery attempt** (initial send, exponential-backoff retry, and operator `webhooks retry`), `xmr-gateway` mints a fresh `X-Webhook-Timestamp` (Unix seconds) and computes `X-Webhook-Signature = HMAC-SHA256(WEBHOOK_SECRET, "{X-Webhook-Timestamp}.{raw_body}")` live so delayed retries after merchant downtime cleanly pass strict replay freshness checks.
- **Consumer Verification Contract:** Consumers MUST:
  1. Parse `X-Webhook-Timestamp` as an integer Unix epoch timestamp and reject requests outside a freshness window (recommended `abs(now - ts) <= 300` seconds).
  2. Verify `X-Webhook-Signature` over `f"{X-Webhook-Timestamp}.".encode() + raw_body` in constant time using `WEBHOOK_SECRET`.
  3. Deduplicate processed events idempotently by `event_id` (also sent in `X-Webhook-Event-Id`) so retried deliveries never credit an order twice.

#### Python Verification Example

```python
import hashlib
import hmac
import time

def verify_gateway_webhook(
    secret: str,
    raw_body: bytes,
    timestamp_header: str,
    signature_header: str,
    max_skew_seconds: int = 300,
) -> bool:
    try:
        ts = int(timestamp_header.strip())
    except ValueError:
        return False
    if abs(int(time.time()) - ts) > max_skew_seconds:
        return False
    signing_input = f"{ts}.".encode("utf-8") + raw_body
    expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header.strip().lower())
```

#### Rust Verification Example

```rust
use chrono::Utc;
use xmr_gateway::services::webhook::verify_timestamped_webhook_with_freshness;

pub fn verify_webhook(
    secret: &str,
    timestamp_header: &str,
    raw_body: &[u8],
    signature_hex: &str,
) -> bool {
    let Ok(ts) = timestamp_header.trim().parse::<i64>() else {
        return false;
    };
    verify_timestamped_webhook_with_freshness(
        secret,
        ts,
        raw_body,
        signature_hex,
        Utc::now().timestamp(),
        300,
    )
}
```

---

## Security Best Practices

- **Keep Loopback Bindings:** Leave `HOST=127.0.0.1` and expose the API only to local services or behind a TLS reverse proxy (Caddy/Nginx). Never expose `monero-wallet-rpc` (`127.0.0.1:18082`) to public interfaces.
- **SSRF, DNS Rebinding & Mainnet HTTPS Enforcement (`XMR-001` / `XMR-AUDIT-006`):** Leave `ALLOW_PRIVATE_WEBHOOKS=false` and `REQUIRE_HTTPS_WEBHOOKS=true` in production. On `MONERO_NETWORK=mainnet` with `ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS` defaults to `true` when unset and explicitly setting `REQUIRE_HTTPS_WEBHOOKS=false` **fails closed at startup** (and reports `FAIL` in `config doctor`), blocking plaintext public HTTP webhooks alongside loopback, RFC1918 subnets, cloud metadata (`169.254.169.254`), DNS rebinding, and HTTP `3xx` redirects. Cleartext HTTP remains allowed on `stagenet`/`testnet` or when `ALLOW_PRIVATE_WEBHOOKS=true` for a local loopback bot (`127.0.0.1`).
- **Bounded Scanner Batching:** Configure `SCANNER_SUBADDRESS_BATCH_SIZE` (`1..=1000`, default `100`) so `get_transfers` queries stay safely below the `16 MiB` RPC response cap as monitored invoices grow; partial batch failures fail closed before database mutation.
- **Enforce Fail-Closed View-Only Mode (`XMR-002` / `XMR-AUDIT-003`) & Hot-Wallet RBAC (`XMR-AUDIT-004`):** Unless you require automated hot treasury sweeping, set `WALLET_MODE=view_only` and `ENABLE_AUTO_SWEEP=false`, providing `MONERO_VIEW_ONLY_ADDRESS` and `MONERO_VIEW_ONLY_KEY` in `.env`. Both `start.sh` and `xmr-gateway` fail closed if `query_key(spend_key)` returns a spend key, malformed data, or any non-watch-only JSON-RPC error. In `WALLET_MODE=hot_wallet` (or `ENABLE_AUTO_SWEEP=true`), a distinct `OPERATOR_API_KEY` is strictly required at startup.
- **Zero-Argv-Leak RPC Credentials (`XMR-AUDIT-005`):** `start.sh`, `admin/service.sh`, `demo-stagenet.sh`, and the systemd/container units write `rpc-login=...` into a `0600` `--config-file` (in `$XDG_RUNTIME_DIR` / `/run/xmr-gateway` when available) and remove it on shutdown so `MONERO_RPC_PASS` never appears in `ps` / `/proc/<pid>/cmdline`.
- **Untrusted Remote Nodes (`XMR-005`):** `MONERO_TRUSTED_DAEMON=false` passes `--untrusted-daemon` by default. Route traffic through Tor (`MONERO_RPC_PROXY=127.0.0.1:9050`) when connecting to third-party public nodes.
- **SQLite Full Durability (`XMR-007`), `BEGIN IMMEDIATE` & WAL Checkpoint (`AUDIT-005`), Singleton Process Lock (`P1-3`), & Crash-Safe Sweeps (`XMR-003`):**
  - SQLite runs in WAL mode with `PRAGMA synchronous = FULL`, `PRAGMA foreign_keys = ON`, and a 5-second `busy_timeout`; all write transactions in `InvoiceRepository` acquire the write lock upfront via `BEGIN IMMEDIATE` to prevent `SQLITE_BUSY` errors during `DEFERRED` lock upgrades.
  - Directories are hardened to `0700` and `.db`, `-wal`, `-shm`, and `<db_path>.lock` files to `0600` on Unix (`XMR-040` / `AUDIT-005`).
  - On graceful shutdown (`SIGINT`/`SIGTERM`), HTTP serving and both background workers (`ScannerService` and `WebhookDispatcher`, using biased shutdown priority) exit cleanly before `checkpoint_and_close_pool()` executes `PRAGMA wal_checkpoint(TRUNCATE);`, re-enforces `0600` permissions, and closes the pool prior to releasing `<db_path>.lock`.
  - **NEVER copy a live WAL database with `cp`** (copying `.db` without synchronized `-wal`/`-shm` frames produces a corrupt or stale backup). Perform safe online backups using `sqlite3` and verify integrity:
    ```bash
    # Option 1: Atomic self-contained snapshot (recommended)
    sqlite3 data/xmr_gateway.db "VACUUM INTO 'data/xmr_gateway.backup.$(date +%F_%H%M%S).db';"
    # Option 2: Online Backup API
    sqlite3 data/xmr_gateway.db ".backup 'data/xmr_gateway.backup.$(date +%F_%H%M%S).db'"
    chmod 600 data/xmr_gateway.backup.*.db
    # Mandatory backup verification
    sqlite3 data/xmr_gateway.backup.<TIMESTAMP>.db "PRAGMA integrity_check;"
    ```
  - **Safe restore procedure:** stop `xmr-gateway` cleanly, remove stale `xmr_gateway.db-wal` and `xmr_gateway.db-shm` sidecars, replace `data/xmr_gateway.db` with the verified backup (`chmod 600`), run `sqlite3 data/xmr_gateway.db "PRAGMA integrity_check;"`, and restart the service.
  - `sweep_attempts` (`PREPARED`→`SUBMITTED`→`RECONCILED`) recovers interrupted sweeps via `get_transfers(out, pending)` without duplicate `sweep_all` calls, and `subaddress_transfers` preserves full transfer amounts on `OVERPAYMENT` rows so `SUM(subaddress_transfers) == SUM(confirmed non-orphaned invoice_transfers)` (`AUDIT-005`).
- **Directory & Env Hardening:** `start.sh` enforces `umask 077`, `chmod 600 .env`, and `chmod 700` on `data/` and `data/wallet/` on every run.
- **Mainnet vs. Stagenet Checklist:**
  - Verify `MONERO_NETWORK=mainnet` and a mainnet `MONERO_REMOTE_NODE` before production launch.
  - Ensure `API_SECRET_KEY`, `WEBHOOK_SECRET`, and `MONERO_RPC_PASS` are freshly generated 32-byte random secrets (`openssl rand -hex 32`).
  - Back up your 25-word mnemonic seed offline (or hardware wallet seed in View-Only mode) and set `chmod 600` on `.env` and `./data/wallet/*`.

---

## Unified Admin CLI (`./admin.sh` & `admin/`)

Run `./admin.sh` without arguments for an interactive bilingual (**EN / RU**) menu, or invoke scriptable subcommands (`./admin.sh [--env FILE] [--lang en|ru] [--json] [--yes] <module> <command> [args...]`):

- **Full Operational Guides:** [admin/GUIDE_EN.md](admin/GUIDE_EN.md) (English) | [admin/GUIDE_RU.md](admin/GUIDE_RU.md) (Русский) — or run `./admin.sh guide [--path]` directly from the CLI.
- **Language Switching:** use `--lang <en|ru>`, `ADMIN_LANG=<en|ru>`, `./admin.sh lang [show|en|ru]` (persisted to `data/.admin_lang`, mode `0600`), or press **`L`** in the interactive menu. `--json` output is strictly language-invariant.

| Module | Key Commands | Purpose |
| :--- | :--- | :--- |
| `service` | `start`, `stop`, `restart`, `status`, `logs`, `build`, `setup-rpc`, `systemd` | Lifecycle control with PID files, graceful shutdown (`wal_checkpoint(TRUNCATE)`), logs, and systemd helper |
| `config` | `show`, `doctor`, `rotate-keys`, `set-mode` | Masked config view, fail-closed security/RBAC/permissions diagnostics, 0600-backed key rotation, mode switching |
| `wallet` | `info`/`balance`, `transfers`, `refresh`, `set-height`, `rescan`, `create-hot`, `create-view-only`, `export-view-keys`, `transfer`, `sweep-all`, `cli` | Full hot & view-only wallet management (fail-closed spend guard in `view_only` mode; zero-float Decimal piconero conversion) |
| `invoices` | `create`, `get`, `list`, `inspect`, `sweep`, `resolve` | Merchant/operator REST API wrappers + read-only SQLite forensic inspection |
| `webhooks` | `list`, `inspect`, `retry`, `retry-invoice`, `verify-sig`, `test-receiver` | Webhook outbox inspection, operator `FAILED`-only retry, HMAC-SHA256 verification, and local test receiver |
| `db` | `stats`, `audit-invariants`, `backup`, `shell` | Read-only SQLite analytics, `AUDIT-005` balance-conservation audit, WAL-safe hot online backup (`0600`), RO/RW shell |
| `dev` | `check`, `health-rbac`, `demo` | Rust fmt/clippy/test runner, live `GET /health` `AUDIT-002` RBAC verifier, Stagenet demo launcher |
| `lang` / `guide` | `lang [show\|en\|ru]`, `guide [--path]` | Show/save interface language (`EN`/`RU`) and open the built-in operational guide |

All secrets are passed to `curl` exclusively via stdin (`--config -`, never in process `argv`), SQLite inspection runs strictly read-only (`mode=ro`), and financial/destructive operations display a `[MAINNET]` confirmation banner when `MONERO_NETWORK=mainnet`.

---

## Development & Verification

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
bash -n admin.sh admin/*.sh admin/lib/*.sh admin/i18n/*.sh && ./admin/test_admin.sh
```

Licensed under the [MIT License](LICENSE).
