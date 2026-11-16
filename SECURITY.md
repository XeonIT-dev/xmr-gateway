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
- [ ] **RPC Hardening:** `monero-wallet-rpc` binds strictly to `127.0.0.1:18082` with `--rpc-login` enabled.
- [ ] **Custody Minimization:** Use **View-Only Zero-Trust Mode** (`ENABLE_AUTO_SWEEP=false`) whenever possible so private spend keys never reside on the server.
- [ ] **Cold Wallet Validation:** If `ENABLE_AUTO_SWEEP=true` is enabled, verify `COLD_WALLET_ADDRESS` belongs to your hardware/offline wallet and test a small sweep before production traffic.
- [ ] **Restrictive CORS:** Leave `CORS_ALLOWED_ORIGINS` empty unless explicitly required by a trusted web origin.
- [ ] **Network Privacy:** Set `MONERO_RPC_PROXY=127.0.0.1:9050` with a local Tor daemon when connecting `monero-wallet-rpc` to an untrusted or public remote node, or run your own `monerod` node.
- [ ] **File Permissions:** Ensure `.env`, `./data/`, and `./data/wallet/` are readable only by the service user (`chmod 600` / `chmod 700`) and excluded from git commits.
