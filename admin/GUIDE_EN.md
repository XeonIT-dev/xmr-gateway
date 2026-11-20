# `xmr-gateway` Admin Panel Operational Guide (`./admin.sh` & `admin/`)

> Complete operational reference for the modular CLI and interactive administration suite of `xmr-gateway`.
> Every command, flag, check, and playbook below maps directly to the scripts under `admin/` and the gateway implementation.

---

## 1. Quick Start & Operating Modes

### Interactive Menu & Scriptable CLI
- **Interactive Menu:** run `./admin.sh` with no arguments in a terminal. On first interactive launch (when no `--lang`, `ADMIN_LANG`, or `.admin_lang` state file exists), it prompts to choose `1) Русский / 2) English`.
- **Scriptable CLI:**
  ```bash
  ./admin.sh [--env <path>] [--lang <en|ru>] [--json] [--yes] <module> <command> [args...]
  ./admin.sh help
  ./admin.sh <module> help
  ```
- **Read this guide directly from the CLI:**
  ```bash
  ./admin.sh guide            # opens GUIDE_EN.md / GUIDE_RU.md (less -R on TTY, cat in pipes)
  ./admin.sh guide --path     # prints the guide path for the active language
  ```

### Language Selection & Priority (`EN` / `RU`)
Language resolution strictly follows top-to-bottom precedence:
1. CLI flag: `--lang en` or `--lang ru` (unknown values fail closed).
2. Environment variable: `ADMIN_LANG=en` or `ADMIN_LANG=ru`.
3. Saved state file: `${ADMIN_STATE_DIR:-./data}/.admin_lang` (inside gitignored `data/`, mode `0600`).
4. System locale: `LC_ALL` / `LANG` starting with `ru` → `ru`, otherwise `en`.

Manage language settings:
```bash
./admin.sh lang show        # display active language, source, and state file path
./admin.sh lang en          # save English preference
./admin.sh lang ru          # save Russian preference
```
Inside the main interactive menu, press **`L`** to toggle `EN ↔ RU` instantaneously without exiting, or **`G`** to open the guide in the active language.

### Global Flags & Strict `--json` Invariance
- `--env <path>` — target an alternate environment file (e.g., `./admin.sh --env .env.mainnet config doctor`). `DATA_DIR`, `DB_PATH`, `WALLET_FILE`, logs, and PID files are derived automatically from that file's `DATABASE_URL`, keeping `.env` and `.env.mainnet` strictly isolated.
- `--json` — machine-readable JSON output that is **byte-for-byte identical** under `--lang en` and `--lang ru` (keys, statuses, and enum values are never localized).
- `--yes` / `-y` — non-interactive confirmation for automation.
- **`[MAINNET]` Safety Guard:** when `MONERO_NETWORK=mainnet`, all financial or destructive actions (`transfer`, `sweep`, `sweep-all`, `resolve`, `rotate-keys`, `stop`, `set-mode`, `db shell --rw`) display a red `[MAINNET]` warning banner and require typing **`yes`** explicitly (or passing `--yes`). Non-interactive calls without `--yes` fail closed.
- **Zero-Argv-Leak Secret Passing:** `API_SECRET_KEY`, `OPERATOR_API_KEY`, `MONERO_RPC_PASS`, and `MONERO_DAEMON_RPC_PASS` are passed to `curl` strictly via stdin (`curl --config -`), and `monero-wallet-rpc` credentials are written to a temporary `0600` `--config-file` (deleted on stop) so secrets never appear in `ps aux`.

- **System-Wide Package Installs (`.deb` / `.rpm` / tarball):** once installed from a system package, invoke **`xmr-gateway-admin`** (`/usr/bin/xmr-gateway-admin` → `/usr/share/xmr-gateway/admin.sh`). When `--env` is omitted and no local `.env` exists, it automatically uses `/etc/xmr-gateway/.env` and stores `.admin_lang` in `/var/lib/xmr-gateway` or `~/.local/state/xmr-gateway/` (never attempting writes into read-only `/usr/share/xmr-gateway`). See [DEPLOY_EN.md](../DEPLOY_EN.md) for full `systemd`, Docker Compose, Podman Quadlet, and package instructions.

---

## 2. Service Lifecycle (`service`)

| Command | Description |
|---|---|
| `./admin.sh service start` | Starts `monero-wallet-rpc` (waits for `get_version`), then `xmr-gateway` (`target/release` or system `/usr/bin/xmr-gateway`), writing `0600` PID files to `data/pids/`. |
| `./admin.sh service stop` | Sends `SIGTERM` to `xmr-gateway` first (up to 25s wait so workers exit and `PRAGMA wal_checkpoint(TRUNCATE)` finishes before `.lock` drops), then stops `monero-wallet-rpc`. |
| `./admin.sh service restart` | Clean `stop` followed by `start`. |
| `./admin.sh service status [--json]` | Shows PIDs, endpoints, `/health` status, and `monero-wallet-rpc` version. |
| `./admin.sh service logs [gateway\|rpc\|cli] [-f] [-n N]` | Shows last `N` lines (default `gateway`, `50`) or live-tails (`-f`). |
| `./admin.sh service build` | Builds the locked release binary (`cargo build --release --locked`). |
| `./admin.sh service setup-rpc` | Installs and SHA256-verifies official Monero CLI tools via `./start.sh --setup-rpc`. |
| `./admin.sh service systemd [status\|install-dry-run\|restart]` | Inspects or restarts all `deploy/systemd/` units (`monero-wallet-rpc.service`, `xmr-gateway.service`, `xmr-gateway-backup.service` + `.timer`, aligned with `/etc/xmr-gateway/.env`, `UMask=0077`, `KillSignal=SIGTERM`). |

---

## 3. Configuration & Security Audit (`config`)

- **`./admin.sh config show [--json]`** — prints active settings with all secrets masked (`API_SECRET_KEY`, `OPERATOR_API_KEY`, `WEBHOOK_SECRET`, `MONERO_RPC_PASS`, `MONERO_DAEMON_RPC_PASS`, `MONERO_VIEW_ONLY_KEY`).
- **`./admin.sh config doctor [--strict-live] [--json]`** — fail-closed security diagnostic (exits `1` on any `FAIL`):

| Check (`check`) | Failure Severity | What It Verifies & Remediation |
|---|---|---|
| `env_permissions` | FAIL | Active `.env` must have mode `0600` (`chmod 600 .env`). |
| `wallet_*_permissions`, `db/wal/shm_permissions` | FAIL | `.keys`, `.password`, `.db`, `-wal`, `-shm` files must have mode `0600`. |
| `secret_api_secret_key`, `secret_webhook_secret`, `secret_operator_api_key` | FAIL | Must be `>= 32` bytes and free of placeholders (`replace-with-*`, `changeme*`). Rotate via `config rotate-keys`. |
| `rbac_key_separation` | FAIL / WARN | When set, `OPERATOR_API_KEY` must differ from `API_SECRET_KEY` (`AUDIT-002`). Missing `OPERATOR_API_KEY` is `FAIL` in `hot_wallet` / `ENABLE_AUTO_SWEEP=true` (`XMR-AUDIT-004`) and `WARN` in `view_only` (single-tenant fallback). |
| `wallet_mode`, `cold_wallet_address` | FAIL | `ENABLE_AUTO_SWEEP=true` requires `WALLET_MODE=hot_wallet` and `COLD_WALLET_ADDRESS`; `hot_wallet` without sweep requires `ALLOW_HOT_WALLET_WITHOUT_SWEEP=true`. |
| `confirmations`, `sweep_priority` | FAIL | `REQUIRED_CONFIRMATIONS >= 1`, `SETTLEMENT_CONFIRMATIONS >= REQUIRED_CONFIRMATIONS`, `SWEEP_PRIORITY` in `0..4`. |
| `ssrf_policy` | WARN / PASS | On `mainnet`, `ALLOW_PRIVATE_WEBHOOKS=true` or (`REQUIRE_HTTPS_WEBHOOKS=false` with `ALLOW_PRIVATE_WEBHOOKS=false`, `XMR-AUDIT-006`) triggers `WARN`; keep `ALLOW_PRIVATE_WEBHOOKS=false` + `REQUIRE_HTTPS_WEBHOOKS=true` in production. |
| `rpc_auth`, `daemon_rpc_security` | FAIL / WARN | `ALLOW_UNAUTHENTICATED_RPC=false` requires `MONERO_RPC_USER`/`PASS`; `MONERO_DAEMON_RPC_URL` enforces RPC transport & auth rules (`AUDIT-001`, required for `allow_resweep`). |
| `health_anon_privacy`, `health_auth_api`, `health_auth_operator` | FAIL | Confirms live unauthenticated `GET /health` hides telemetry (`service`/`monero_rpc`/`database`) while authenticated requests receive full diagnostics (`AUDIT-002`). |
| `wallet_daemon_sync` | WARN / PASS | Compares wallet `get_height` vs daemon `get_info` height; lag `> 5` blocks raises `WARN`. |

- **`./admin.sh config rotate-keys [api|operator|webhook|rpc|all]`** — creates a `0600` backup (`<env>.bak.<UTC>`), generates fresh secrets with `openssl rand -hex 32` (`24` bytes for `rpc`), and enforces `OPERATOR_API_KEY != API_SECRET_KEY`. Restart services (`./admin.sh service restart`) and update client credentials afterwards.
- **`./admin.sh config set-mode <view_only|hot_wallet>`** — validates prerequisites (`COLD_WALLET_ADDRESS` or `MONERO_VIEW_ONLY_ADDRESS`+`MONERO_VIEW_ONLY_KEY`/`.keys`), creates a `0600` `.env` backup, and updates `WALLET_MODE` and `ENABLE_AUTO_SWEEP`.

---

## 4. Monero Wallets (`wallet`)

### `hot_wallet` vs `view_only`
- **`view_only` (Zero-Trust, recommended):** server holds only the primary address and private view key. No private spend key exists on disk or in memory; `wallet transfer` and `wallet sweep-all` fail closed.
- **`hot_wallet` (Hot Auto-Sweep):** server holds a transit spend key and automatically sweeps unlocked (`>= 10` blocks) funds to `COLD_WALLET_ADDRESS`.

### Step-by-Step Migration to `view_only`
```bash
# 1. On the wallet origin host, export public address + private view key (spend key is NEVER printed):
./admin.sh wallet export-view-keys

# 2. Place MONERO_VIEW_ONLY_ADDRESS and MONERO_VIEW_ONLY_KEY into the target server's .env (chmod 600 .env)
#    and set WALLET_RESTORE_HEIGHT to the wallet creation height.

# 3. Create the zero-trust view-only wallet:
./admin.sh wallet create-view-only

# 4. Switch config to view_only and validate:
./admin.sh config set-mode view_only
./admin.sh config doctor
```

### Other `wallet` Commands
- `./admin.sh wallet info` (alias `balance`) — primary address, total/unlocked balances, per-subaddress balances, and wallet vs daemon height (`--json`).
- `./admin.sh wallet transfers [in|out|pool|pending|all]` — transfer history via `monero-wallet-rpc`.
- `./admin.sh wallet refresh` / `set-height <height>` / `rescan` — sync wallet, recover from an overly high restore height, or run full `rescan_blockchain`.
- `./admin.sh wallet create-hot [--restore-height H]` — create hot wallet + `0600` password file (back up the 25-word mnemonic seed offline!).
- `./admin.sh wallet transfer <addr> <amount_xmr> [priority]` & `sweep-all <addr> [subaddr_idx] [priority]` — manual payout (`hot_wallet` only, `validate_address` RPC check, exact Decimal piconero conversion, `[MAINNET]` confirmation).
- `./admin.sh wallet cli [-- extra_args...]` — launch `./bin/monero-wallet-cli` pre-wired with network, daemon, proxy, and wallet flags from `.env`.

---

## 5. Invoices & Sweep Incidents (`invoices`)

| Command | Auth / Source | Description |
|---|---|---|
| `./admin.sh invoices create --order-id ID --amount-xmr 0.25 [--callback-url URL] [--ttl 3600] [--qr-out /tmp/qr.png]` | `X-API-Key` (`POST /api/v1/invoices`) | Creates invoice (also accepts `--amount-piconero`); saves `0600` QR PNG when `--qr-out` is set. |
| `./admin.sh invoices get <invoice_id>` | `X-API-Key` (`GET /api/v1/invoices/{id}`) | Live status, incoming transfers, and sweep attempts via API. |
| `./admin.sh invoices list [--status STATUS] [--order-id ID] [--limit 25]` | SQLite RO | Lists invoices directly from SQLite in read-only mode. |
| `./admin.sh invoices inspect <invoice_id\|order_id>` | SQLite RO | Full forensic dump across `invoices`, `invoice_transfers`, `subaddress_transfers`, `sweep_attempts`, and `webhook_deliveries`. |
| `./admin.sh invoices sweep <invoice_id>` | `X-Operator-Key` (`POST .../sweep`) | Triggers manual sweep of unlocked funds (`>= 10` confirmations). |
| `./admin.sh invoices resolve <invoice_id> <action> --note "..." [...]` | `X-Operator-Key` (`POST .../sweep/resolve`) | Resolves a blocking `REORGED` sweep incident. |

### `REORGED` Sweep Incident Protocol (`resolve`)
1. Inspect full state first: `./admin.sh invoices inspect <invoice_id>` and `./admin.sh wallet transfers out`.
2. **Case A — old sweep tx is absent on-chain (unblock re-sweep):**
   Ensure `MONERO_DAEMON_RPC_URL` is configured on the running gateway (`AUDIT-001` requires wallet/daemon height sync verification), then run:
   ```bash
   ./admin.sh invoices resolve <invoice_id> allow_resweep \
     --confirm-absent \
     --note "Verified absent in get_transfers and block explorer"
   ```
3. **Case B — funds reached `COLD_WALLET_ADDRESS` (replacement/confirmed tx):**
   ```bash
   ./admin.sh invoices resolve <invoice_id> mark_reconciled \
     --tx-hash <64-hex-hash> \
     --note "Confirmed settled on cold wallet"
   ```

---

## 6. Webhooks (`webhooks`)

- `./admin.sh webhooks list [--status PENDING|FAILED|DELIVERED] [--invoice-id UUID] [--limit N]` — lists `webhook_deliveries` (SQLite RO).
- `./admin.sh webhooks inspect <webhook_id>` — full delivery payload, `signature_hex`, `attempts`, `last_status_code`, and `last_error`.
- `./admin.sh webhooks retry <webhook_id>` — operator retry strictly for `FAILED` deliveries (`POST /api/v1/webhooks/{id}/retry`; returns `409 Conflict` for `PENDING`/`DELIVERED`, `AUDIT-002`).
- `./admin.sh webhooks retry-invoice <invoice_id>` — operator batch retry of all `FAILED` deliveries for an invoice (`PENDING`/`DELIVERED` untouched).
- `./admin.sh webhooks verify-sig <signature_hex> [payload_file|-]` — local constant-time `X-Signature-256` verification against `WEBHOOK_SECRET`.
- `./admin.sh webhooks test-receiver [port]` — built-in local Python HTTP receiver on `127.0.0.1:<port>` (default `9000`) validating `X-Signature-256` in real time.

---

## 7. SQLite Database & Forensics (`db`)

- **`./admin.sh db stats [--json]`** — invoice counts by status, exact XMR totals (`expected`, `received`, `overpaid`, `swept`, `fees`), webhook counts, sweep attempt counts, and `.db`/`-wal`/`-shm`/`.lock` byte sizes.
- **`./admin.sh db audit-invariants [--json]`** — fail-closed SQLite audit (exits `1` on any violation):
  - `PRAGMA integrity_check;` (`ok`) and `PRAGMA foreign_key_check;` (`0` violations);
  - **`AUDIT-005` Balance Conservation:** per-row equality `subaddress_transfers.amount_piconero == invoice_transfers.amount_piconero` and per-invoice `SUM(subaddress_transfers) == SUM(confirmed non-orphaned invoice_transfers)`;
  - flags unresolved `REORGED` sweeps and stale (`> 10 min`) `PREPARED` sweeps.
- **`./admin.sh db backup [dest_dir] [--json]`** — WAL-safe hot online backup via Python `sqlite3.Connection.backup()` (never copy a live WAL `.db` with `cp`!), sets `chmod 600`, and immediately verifies `PRAGMA integrity_check;`.
  - **Restore procedure:** stop gateway (`./admin.sh service stop`), remove stale `-wal` and `-shm` sidecars, place the verified backup at `.db` (`chmod 600`), run `./admin.sh db audit-invariants`, and start (`./admin.sh service start`).
- **`./admin.sh db shell [--rw]`** — interactive SQLite shell (strictly read-only by default; `--rw` requires explicit confirmation).

---

## 8. Developer & Verification Tools (`dev`)

- `./admin.sh dev check` — runs `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets --all-features -- -D warnings`, and `cargo test --locked --all-targets`.
- `./admin.sh dev health-rbac [--json]` — live `AUDIT-002` RBAC probe on `GET /health`: confirms anonymous and invalid-key calls hide telemetry, valid `X-API-Key`/`X-Operator-Key` calls return diagnostics, and merchant key in `X-Operator-Key` is rejected when `OPERATOR_API_KEY` is configured.
- `./admin.sh dev demo` — runs `./demo-stagenet.sh`.
- `./admin/test_admin.sh` — isolated automated test suite for the admin panel itself.

---

## 9. Operational Playbooks ("What To Do If...")

### Playbook 1: Gateway refuses to start (SSRF error or `WALLET_MODE=view_only` with hot wallet)
1. Run `./admin.sh config doctor` and `./admin.sh service logs gateway -n 50`.
2. On `blocked by SSRF policy`: set `ALLOW_PRIVATE_WEBHOOKS=true` only for local dev; in production use a public `https://` callback URL.
3. On `WALLET_MODE=view_only ... contains a private spend key`: recreate a true watch-only wallet (`./admin.sh wallet create-view-only`) or explicitly switch to `./admin.sh config set-mode hot_wallet`.

### Playbook 2: Customer paid an invoice, but payment is not visible
1. Inspect invoice & subaddress: `./admin.sh invoices inspect <invoice_id>`.
2. Check wallet sync height and incoming transfers: `./admin.sh wallet info` and `./admin.sh wallet transfers in`.
3. If the wallet lags or `WALLET_RESTORE_HEIGHT` was set too high:
   ```bash
   ./admin.sh wallet refresh
   # If payment occurred before the current restore height:
   ./admin.sh wallet set-height <height_before_payment>
   ```
4. Review scanner logs: `./admin.sh service logs gateway -n 100`.

### Playbook 3: Webhooks transitioned to `FAILED` (downstream outage)
1. List failed deliveries: `./admin.sh webhooks list --status FAILED`.
2. Inspect `last_status_code` and `last_error`: `./admin.sh webhooks inspect <webhook_id>`.
3. Fix the receiver (optionally verify HMAC locally with `./admin.sh webhooks verify-sig`).
4. Trigger safe operator retry (`PENDING` rows remain untouched):
   ```bash
   ./admin.sh webhooks retry-invoice <invoice_id>
   ```

### Playbook 4: `REORGED` sweep incident detected
1. Identify affected invoices: `./admin.sh db audit-invariants` and `./admin.sh invoices inspect <invoice_id>`.
2. Cross-check outgoing wallet history: `./admin.sh wallet transfers all`.
3. Resolve via `allow_resweep` (with `MONERO_DAEMON_RPC_URL` configured and confirmed on-chain absence) or `mark_reconciled` with the verified tx hash (see Section 5).
4. Re-verify clean state: `./admin.sh db audit-invariants`.

### Playbook 5: Stagenet → Mainnet Cutover Checklist
1. Create a dedicated `.env.mainnet` (`chmod 600 .env.mainnet`) with isolated `DATABASE_URL=sqlite://data.mainnet/xmr_gateway.db`.
2. Set `MONERO_NETWORK=mainnet`, mainnet `MONERO_REMOTE_NODE`, `ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS=true`, `REQUIRED_CONFIRMATIONS=10`, and `SETTLEMENT_CONFIRMATIONS=15` (recommended).
3. Rotate fresh distinct secrets: `./admin.sh --env .env.mainnet config rotate-keys all` (ensure a distinct `OPERATOR_API_KEY` is configured).
4. Configure `WALLET_MODE=view_only` (or `hot_wallet` + verified mainnet `COLD_WALLET_ADDRESS`) and set `MONERO_DAEMON_RPC_URL`.
5. Run the pre-launch gate:
   ```bash
   ./admin.sh --env .env.mainnet config doctor
   ./admin.sh --env .env.mainnet service build
   ./admin.sh --env .env.mainnet service start
   ./admin.sh --env .env.mainnet dev health-rbac
   ./admin.sh --env .env.mainnet db audit-invariants
   ```
