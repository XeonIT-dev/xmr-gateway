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

- [ ] **Strong Secrets:** `API_SECRET_KEY`, `WEBHOOK_SECRET`, and `MONERO_RPC_PASS` are freshly generated with at least 32 random bytes (`openssl rand -hex 32`), not defaults or placeholders.
- [ ] **Loopback Isolation:** `HOST=127.0.0.1` is retained, and external API access (if needed) is terminated through a TLS reverse proxy (Caddy/Nginx).
- [ ] **RPC Hardening:** `monero-wallet-rpc` binds strictly to `127.0.0.1:18082` with `--rpc-login` enabled and `MONERO_TRUSTED_DAEMON=false` (`--untrusted-daemon`) for third-party remote nodes.
- [ ] **Custody Minimization (`XMR-002`):** Use **View-Only Zero-Trust Mode** (`WALLET_MODE=view_only`, `ENABLE_AUTO_SWEEP=false`) with `MONERO_VIEW_ONLY_ADDRESS`/`MONERO_VIEW_ONLY_KEY` whenever possible; `start.sh` and `xmr-gateway` fail closed if a spend key is detected on `monero-wallet-rpc`.
- [ ] **Webhook Egress SSRF Guard (`XMR-001`):** Keep `ALLOW_PRIVATE_WEBHOOKS=false` (and `REQUIRE_HTTPS_WEBHOOKS=true` in production) so loopback/RFC1918/metadata IPs, DNS rebinding, and HTTP 3xx redirects are blocked.
- [ ] **Confirmations & Reorg Protection (`XMR-006`):** Keep `REQUIRED_CONFIRMATIONS=10` and `SETTLEMENT_CONFIRMATIONS=10` for 10-block finality on mainnet; handle `REORGED`, `LATE_PAYMENT`, and `OVERPAYMENT` webhook events in merchant backends.
- [ ] **SQLite Crash Durability (`XMR-007` / `XMR-003`):** Gateway enforces `PRAGMA synchronous = FULL` in WAL mode and reconciles `PREPARED`/`SUBMITTED` `sweep_attempts` at startup and per scan tick via `get_transfers(out, pending)`.
- [ ] **Cold Wallet Validation:** If `ENABLE_AUTO_SWEEP=true` (`WALLET_MODE=hot_wallet`) is enabled, verify `COLD_WALLET_ADDRESS` belongs to your hardware/offline wallet and test a small sweep before production traffic.
- [ ] **Restrictive CORS:** Leave `CORS_ALLOWED_ORIGINS` empty unless explicitly required by a trusted web origin.
- [ ] **Network Privacy:** Set `MONERO_RPC_PROXY=127.0.0.1:9050` with a local Tor daemon when connecting `monero-wallet-rpc` to an untrusted or public remote node, or run your own `monerod` node.
- [ ] **File Permissions:** Ensure `.env`, `./data/`, and `./data/wallet/` are readable only by the service user (`chmod 600` / `chmod 700`) and excluded from git commits.

---

## Known Upstream Dependency Exceptions (`cargo audit`)

- **`RUSTSEC-2026-0459` (`libsqlite3-sys` `< 0.39.0`):** Explicitly ignored in `.github/workflows/security.yml` via `--ignore RUSTSEC-2026-0459`. Upstream `sqlx-sqlite 0.9.0` currently restricts `libsqlite3-sys` to `< 0.38.0` (`0.37.0` in `Cargo.lock`). The underlying SQLite flaw (`CVE-2026-119375`) requires opening a crafted untrusted database and mismatched `-wal` file pair; `xmr-gateway` creates and exclusively accesses its own local WAL database in `./data/`. Once an upstream `sqlx-sqlite` release permits `libsqlite3-sys >= 0.39.0`, this exception should be removed.
