# Security Policy

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities, cryptographic flaws, or private-key exposure bugs.

Instead, report vulnerabilities privately to the repository maintainers with:
1. A clear description of the vulnerability and its potential financial or cryptographic impact.
2. Steps to reproduce or a minimal proof-of-concept.
3. Affected component(s) and configuration (e.g., View-Only vs. Hot Auto-Sweep mode).

We aim to acknowledge reports within 48 hours and coordinate a fix before public disclosure.

---

## Production Security Checklist

Before deploying `xmr-gateway` on mainnet:

- [ ] **Strong Secrets & RPC Fail-Closed Policies (`XMR-031` / `XMR-035`):** `API_SECRET_KEY`, `WEBHOOK_SECRET`, and `MONERO_RPC_PASS` are freshly generated random secrets (not defaults/placeholders). Keep `ALLOW_UNAUTHENTICATED_RPC=false` and `ALLOW_INSECURE_REMOTE_RPC=false` in production; `start.sh` and `demo-stagenet.sh` fail closed without `--disable-rpc-login`.
- [ ] **Loopback Isolation & Body Bounds (`XMR-038`):** `HOST=127.0.0.1` is retained, external API access (if needed) is terminated through a TLS reverse proxy (Caddy/Nginx), and Axum enforces `DefaultBodyLimit` (`64 KiB`) plus a bounded `16 MiB` RPC response cap (`XMR-032`).
- [ ] **RPC Hardening:** `monero-wallet-rpc` binds strictly to `127.0.0.1:18082` with `--rpc-login` enabled and `MONERO_TRUSTED_DAEMON=false` (`--untrusted-daemon`) for third-party remote nodes.
- [ ] **Cryptographic Address Verification (`XMR-030`):** `COLD_WALLET_ADDRESS` undergoes pure-Rust Base58 block decoding and Keccak-256 4-byte checksum verification in `Config::validate()`, plus live `validate_address` JSON-RPC verification at startup.
- [ ] **Custody Minimization (`XMR-002`):** Use **View-Only Zero-Trust Mode** (`WALLET_MODE=view_only`, `ENABLE_AUTO_SWEEP=false`) with `MONERO_VIEW_ONLY_ADDRESS`/`MONERO_VIEW_ONLY_KEY` whenever possible; `start.sh` and `xmr-gateway` fail closed if a spend key is detected on `monero-wallet-rpc`.
- [ ] **Webhook Egress SSRF Guard & Recovery (`XMR-001` / `XMR-025` / `XMR-027` / `XMR-028`):** Keep `ALLOW_PRIVATE_WEBHOOKS=false` (and `REQUIRE_HTTPS_WEBHOOKS=true` in production) so loopback/RFC1918/metadata IPs, DNS rebinding, and HTTP 3xx redirects are blocked. Webhooks execute with bounded per-invoice concurrency, epoch-scoped reorg deduplication (`reorg_epoch`), and authenticated admin retry endpoints (`POST /api/v1/webhooks/{id}/retry`).
- [ ] **Settlement Finality, Reorg Protection & Snapshots (`XMR-006` / `XMR-022` / `XMR-023` / `XMR-024` / `XMR-026`):** Keep `REQUIRED_CONFIRMATIONS=10` (baseline) and consider `SETTLEMENT_CONFIRMATIONS=15` for high-value mainnet orders as a safety buffer above Monero's 10-block `MONERO_UNLOCK_CONFIRMATIONS`. Deep reorgs before `SWEPT` — including View-Only invoices that already reached `COMPLETED` — transition the invoice to `REORGED`, increment `reorg_epoch`, emit the compensating epoch-scoped `REORGED` webhook, and mark missing/tainted transfers `ORPHANED` (never physically deleting rows; cleanly re-activating them if re-included without `double_spend_seen`). When the chain recovers canonically (`confirmations > 0` with `double_spend_seen = false`), `invoice_transfers.double_spend_seen` / `orphaned` and `subaddress_transfers.status = 'ORPHANED'` clear cleanly (while `confirmations == 0` mempool updates remain conservatively sticky until mined). Outbound `sweep_attempts` remain `SUBMITTED` until `confirmations >= SETTLEMENT_CONFIRMATIONS && !double_spend_seen` (`CONFIRMED`) and continue to be monitored against `get_transfers(out=true, pending=true)`: if a sweep tx disappears or reports `double_spend_seen = true`, the attempt is escalated to `REORGED` (`SWEEP_REORG_DETECTED`), the `SWEPT` invoice transitions to `REORGED` with a signed `REORGED` webhook, and automatic re-sweep (`sweep_all`) is strictly blocked pending manual operator reconciliation.
- [ ] **Remote Node Trust Policy (`XMR-005`):** Setting `MONERO_TRUSTED_DAEMON=false` (`--untrusted-daemon`) restricts wallet-side daemon trust and Tor routing (`MONERO_RPC_PROXY=127.0.0.1:9050`) protects network privacy, but **neither mechanism provides cryptographic proof** that a third-party `MONERO_REMOTE_NODE` reports truthful blockchain height or confirmations. For high-assurance production mainnet deployments, run and connect to your own local full `monerod` node.
- [ ] **Supply-Chain & Systemd Hardening (`XMR-036` / `XMR-037`):** `./start.sh --setup-rpc` pins Monero CLI release `v0.18.5.4` + SHA-256 (or GPG-verifies `hashes.txt` against `binaryFate` key `81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92` for custom versions). For production servers, use the hardened units in `deploy/systemd/`.
- [ ] **SQLite Crash Durability, Singleton Lock & Permissions (`XMR-007` / `XMR-003` / `XMR-040` / `P1-3`):** Gateway enforces `PRAGMA synchronous = FULL`, acquires `<db_path>.lock` (`0600`), restricts SQLite directories to `0700` and DB/WAL/SHM files to `0600` on Unix, reads at most `1024` bytes from non-2xx webhook responses (`XMR-009`), and monitors all non-archived subaddresses (`SUBADDRESS_MONITOR_DAYS=0`).

---

## Known Upstream Dependency Exceptions & Risk Register (`cargo audit` / `XMR-034`)

- **`RUSTSEC-2026-0459` (`libsqlite3-sys v0.37.0` / bundled SQLite `3.51.3`) — `OPEN / ACCEPTED RISK (Mitigated by Controls)`:** **The underlying SQLite library vulnerability (`CVE-2026-119375`) is NOT patched** in `libsqlite3-sys v0.37.0` (bundled SQLite `3.51.3`), and upstream `sqlx-sqlite 0.9.0` (latest on `crates.io`) restricts `libsqlite3-sys` to `< 0.38.0` while the fix requires `libsqlite3-sys >= 0.39.0`. `.github/workflows/security.yml` explicitly ignores this advisory via `--ignore RUSTSEC-2026-0459`. Compensating controls: exploitation requires opening an attacker-crafted untrusted `.db` and mismatched `-wal` file pair; `xmr-gateway` exclusively creates and accesses its own local WAL DB in `0700` directories with `0600` file permissions (`XMR-040`) and never opens untrusted external SQLite files. Removal trigger: upgrade `sqlx-sqlite` once upstream supports `libsqlite3-sys >= 0.39.0` and drop `--ignore RUSTSEC-2026-0459`.
- **`RUSTSEC-2026-0543` (`chrono v0.4.45` `unmaintained` notice) — `OPEN / ACCEPTED RISK (Mitigated by Controls)`:** Upstream informational advisory with no published security vulnerability or patched `chrono` upgrade available as of `2026-11-17`. Compensating control: `xmr-gateway` restricts timestamp usage strictly to UTC arithmetic (`DateTime<Utc>`) and RFC 3339 parsing/serialization. Removal trigger: migrate to `time` / `jiff` or a maintained successor crate when stabilized.
