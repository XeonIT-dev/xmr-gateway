# `xmr-gateway` Production Deployment & Release Guide

> Practical end-to-end reference for installing, verifying releases, running `xmr-gateway` in production (`systemd`, Docker Compose, rootless Podman Quadlet, Caddy/Nginx), and cutting signed releases.

---

## 1. Choosing an Installation Method

| Method | Best For | Advantages | Requirements |
|---|---|---|---|
| **One-line installer** (`scripts/install.sh`) | Fast VPS provisioning (Debian/Ubuntu/Fedora/RHEL) | Auto-selects `.deb`/`.rpm`/tarball + mandatory `SHA256SUMS` (+ optional GPG) | `curl`, `bash`, `sha256sum` |
| **Native `.deb` / `.rpm` packages** (GitHub Releases) | Bare-metal / VPS with `systemd` | Auto-creates `xmr-gateway` user, hardened systemd units, `xmr-gateway-admin` CLI; safe upgrades never overwrite `/etc/xmr-gateway/.env` | `apt`/`dpkg` or `dnf`/`rpm` |
| **Release tarball** (`.tar.gz`) | Minimal Linux hosts, `/opt/xmr-gateway` installs | Prebuilt `x86_64`/`aarch64` binary + `admin.sh` + `deploy/` (no Rust toolchain) | `tar`, `curl`, `python3` |
| **Docker Compose** (`deploy/docker/`) | Containerized Docker hosts | Isolated `xmr_internal` network, read-only rootfs, optional `--profile caddy` HTTPS | Docker Engine + Compose v2 |
| **Rootless Podman Quadlet** (`deploy/podman/quadlet/`) | Fedora / RHEL / Rocky with SELinux & rootless security | Native user `systemd` units, `UserNS=keep-id`, SELinux `:Z` relabeling | Podman 4.4+ / systemd user |
| **Build from source** (`cargo build --release --locked`) | Development, audits, custom distros | Full build transparency and full Rust test suite execution | Rust >= `1.94`, `cargo` |

---

## 2. Quick Installation & Release Verification

### 2.1. One-Line Fail-Closed Installer (`scripts/install.sh`)
Always inspect the execution plan with `--dry-run` first:
```bash
curl -fsSL https://raw.githubusercontent.com/XeonIT-dev/xmr-gateway/main/scripts/install.sh -o install.sh
bash install.sh --dry-run
sudo bash install.sh
```
Common options:
```bash
# Pin method and release version:
sudo bash install.sh --method deb --version v0.1.4
sudo bash install.sh --method rpm --version v0.1.4
sudo bash install.sh --method tarball --prefix /opt/xmr-gateway --version v0.1.4

# Unprivileged tarball install into your home directory (no sudo required):
bash install.sh --method tarball --prefix "$HOME/xmr-gateway" --version v0.1.4

# Enforce fail-closed GPG verification of SHA256SUMS.asc:
sudo bash install.sh --version v0.1.4 --gpg-key ./RELEASE_SIGNING_KEY.asc --require-gpg
```

### 2.2. Manual Cryptographic Release Verification
After downloading artifacts from GitHub Releases (`https://github.com/XeonIT-dev/xmr-gateway/releases`):
```bash
# 1. Verify SHA-256 checksum (mandatory)
sha256sum -c SHA256SUMS --ignore-missing

# 2. Verify GPG signature (when release is GPG-signed)
gpg --import RELEASE_SIGNING_KEY.asc
gpg --verify SHA256SUMS.asc SHA256SUMS

# 3. Verify GitHub Build Provenance Attestation (requires GitHub CLI `gh`)
gh attestation verify xmr-gateway_0.1.4_amd64.deb --owner XeonIT-dev
```

---

## 3. Bare-Metal / VPS (`systemd` + Reverse Proxy)

### 3.1. Installing `.deb` or `.rpm`
```bash
# Debian / Ubuntu:
sudo apt-get install -y ./xmr-gateway_0.1.4_amd64.deb

# Fedora / RHEL / Rocky:
sudo dnf install -y ./xmr-gateway-0.1.4-1.x86_64.rpm
```
The package automatically:
- creates system group & user `xmr-gateway` (`/usr/sbin/nologin`);
- creates `/var/lib/xmr-gateway`, `/var/lib/xmr-gateway/wallet`, `/var/lib/xmr-gateway/backups` (`0700`, `xmr-gateway:xmr-gateway`) and `/etc/xmr-gateway` (`0750`, `root:xmr-gateway`);
- seeds `/etc/xmr-gateway/.env` (`0600`) from `/etc/xmr-gateway/env.example` **only if it does not already exist** (upgrades never overwrite your `.env`!);
- installs `/usr/bin/xmr-gateway`, `/usr/bin/xmr-gateway-admin`, `/usr/share/xmr-gateway/` (including `start.sh` and `scripts/render-wallet-rpc-conf.sh` `0755`), and hardened units in `/usr/lib/systemd/system/`.

### 3.2. Configuring `/etc/xmr-gateway/.env` & Wallet Initialization
1. Generate all 4 fresh distinct secrets (`API_SECRET_KEY`, `OPERATOR_API_KEY`, `WEBHOOK_SECRET`, `MONERO_RPC_PASS`):
   ```bash
   sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys all
   ```
2. Edit `/etc/xmr-gateway/.env` (keep `0600`):
   - `DATABASE_URL=sqlite:///var/lib/xmr-gateway/xmr_gateway.db`
   - `MONERO_NETWORK=mainnet` (or `stagenet` / `testnet`; leaving `MONERO_REMOTE_NODE=` empty auto-selects a network-appropriate default node)
   - `WALLET_MODE=view_only`, `ENABLE_AUTO_SWEEP=false` (or `WALLET_MODE=hot_wallet` + `ENABLE_AUTO_SWEEP=true` + `COLD_WALLET_ADDRESS=...`)
   - `ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS=true`
   - `REQUIRED_CONFIRMATIONS=10`, `SETTLEMENT_CONFIRMATIONS=15`
   - `MONERO_VIEW_ONLY_ADDRESS=...`, `MONERO_VIEW_ONLY_KEY=...`, `WALLET_RESTORE_HEIGHT=...`
   - configure `MONERO_DAEMON_RPC_URL` if you plan to use `allow_resweep` incident resolution (`AUDIT-001`).
3. Install SHA256-verified official `monero-wallet-rpc` & `monero-wallet-cli` into `/usr/local/bin/`:
   ```bash
   sudo xmr-gateway-admin service setup-rpc
   ```
4. Initialize the wallet (automatically generates `0600` `/var/lib/xmr-gateway/wallet/gateway_wallet.password` required by `monero-wallet-rpc.service` and fixes `xmr-gateway:xmr-gateway` ownership when run via `sudo`):
   ```bash
   # View-Only Zero-Trust (recommended):
   sudo xmr-gateway-admin --env /etc/xmr-gateway/.env wallet create-view-only
   # Or Hot Auto-Sweep wallet:
   sudo xmr-gateway-admin --env /etc/xmr-gateway/.env wallet create-hot
   ```
5. Validate permissions, RBAC, remote-node alignment, and custody invariants (fail-closed):
   ```bash
   sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config doctor
   ```

> [!WARNING]
> **Critical Production Requirements Before Opening Payment Traffic**
>
> **1. Never accept live payments or create invoices while `lag > 0` (`wallet_daemon_sync`):**
> - **Rule:** After creating or importing a wallet (especially `WALLET_MODE=view_only` or after any `wallet rescan`), wait until initial blockchain synchronization finishes (`lag=0`) before opening checkout traffic.
> - **Mechanism:** `monero-wallet-rpc` observes unconfirmed mempool transactions (`pool`) directly from the daemon even when `wallet_height` lags behind `daemon_height`, so the gateway immediately moves a paid invoice to `MEMPOOL` and emits the `MEMPOOL` webhook. As soon as that transaction is mined into a block above `wallet_height`, it leaves `pool` but does not appear in `in` until the wallet scans up to that block height. Observing the transaction absent from both `pool` and `in`, the scanner fail-closed transitions the invoice to `REORGED`, increments `reorg_epoch`, and sends a **false `REORGED` webhook**.
> - **Recovery:** No funds are lost — once the wallet reaches the block height (`lag=0`), the scanner automatically recovers the invoice from `REORGED` to `CONFIRMED` / `SETTLED` / `COMPLETED` and emits fresh signed webhooks. However, a false `REORGED` event can trigger premature order cancellation or false security alerts in merchant billing systems.
> - **Verification command (must pass before enabling checkout):**
>   ```bash
>   # System package / systemd install:
>   sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config doctor | grep wallet_daemon_sync
>   # Local / tarball install:
>   ./admin.sh config doctor
>   # Target output:
>   # [PASS] wallet_daemon_sync ... (lag=0, daemon_synchronized=true)
>   ```
>
> **2. Always use a dedicated, clean Monero wallet (never pair a used wallet with a fresh SQLite DB):**
> - **Rule:** Provision a brand-new Monero wallet dedicated exclusively to `xmr-gateway` (in both `view_only` and `hot_wallet` modes). Never delete or reset `xmr_gateway.db` while keeping an already-used wallet.
> - **Why this is critical (risk of free order settlement):** Monero subaddresses are deterministic (`account=0, index=1, 2, 3...`). A fresh `xmr_gateway.db` assigns subaddresses starting from `index=1`. If the attached wallet already has historical incoming transactions on those subaddresses, the scanner will match those historical inflows against newly created invoices — automatically transitioning them to `CONFIRMED` / `COMPLETED` (and emitting `OVERPAYMENT`) without any payment from the customer.
> - **Migration & backup rule:** When migrating hosts or restoring from a backup, always back up and restore the wallet files (`gateway_wallet*`) and `xmr_gateway.db` **together** as a consistent pair.

### 3.3. Starting `systemd` & Daily Hot Backup Timer
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now monero-wallet-rpc.service xmr-gateway.service
sudo systemctl enable --now xmr-gateway-backup.timer   # daily 0600 online SQLite hot backup

# Check unit status and verify live /health RBAC matrix:
sudo systemctl status monero-wallet-rpc.service xmr-gateway.service xmr-gateway-backup.timer
sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env dev health-rbac
```
> **Systemd hardening highlights:** `monero-wallet-rpc.service` delegates `ExecStartPre` to `/usr/share/xmr-gateway/scripts/render-wallet-rpc-conf.sh` (`0755` POSIX helper) to render `/run/xmr-gateway/wallet-rpc.conf` (`0600`, RAM-only via `RuntimeDirectory=xmr-gateway`) so `MONERO_RPC_PASS` never appears in `ps aux`. Both services enforce `UMask=0077`, `ProtectSystem=strict`, `NoNewPrivileges=true`, and `KillSignal=SIGTERM` / `TimeoutStopSec=30` so SQLite `PRAGMA wal_checkpoint(TRUNCATE)` finishes cleanly on stop.

### 3.4. Reverse Proxy (Caddy / Nginx) & Firewall
Production templates live in `deploy/reverse-proxy/` (and `/usr/share/xmr-gateway/reverse-proxy/` when installed via package):
- **Caddy** (`deploy/reverse-proxy/Caddyfile`): replace `pay.example.com`, copy to `/etc/caddy/Caddyfile`, reload Caddy.
- **Nginx** (`deploy/reverse-proxy/nginx-xmr-gateway.conf`): update domain & Certbot paths, install to `/etc/nginx/sites-available/xmr-gateway.conf` (or `/etc/nginx/conf.d/`), run `sudo nginx -t && sudo systemctl reload nginx`.
- Uncomment the operator-route IP/VPN allowlist (`/api/v1/invoices/*/sweep*`, `/api/v1/webhooks/*`) for defense-in-depth alongside `OPERATOR_API_KEY`.
- **Firewall:** expose **only** `22/tcp`, `80/tcp`, `443/tcp`. Ports `8080` and `18082` bind exclusively to `127.0.0.1`:
  ```bash
  # Debian/Ubuntu (ufw):
  sudo ufw default deny incoming && sudo ufw allow OpenSSH && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw enable
  # Fedora/RHEL (firewalld):
  sudo firewall-cmd --permanent --add-service=http --add-service=https && sudo firewall-cmd --reload
  ```

---

## 4. Containers (Docker Compose & Rootless Podman Quadlet)

### 4.1. Docker Compose & Podman Compose (`deploy/docker/`)
Keep `DATA_HOST_DIR` (`data/gateway`) and `WALLET_HOST_DIR` (`data/wallet`) as **non-overlapping sibling directories** so `xmr-gateway` never sees wallet key files and SELinux labels never collide.

1. Prepare isolated sibling directories (`0700`) and configure environment:
   ```bash
   mkdir -p data/gateway data/wallet
   chmod 700 data data/gateway data/wallet
   cp deploy/docker/.env.docker.example deploy/docker/.env.docker
   chmod 600 deploy/docker/.env.docker
   # Edit deploy/docker/.env.docker and replace all placeholder secrets!
   ```
   - **On Docker Engine:**
     ```bash
     sudo chown -R 10001:10001 data/gateway data/wallet
     ```
   - **On Rootless Podman + SELinux `Enforcing` (Fedora / RHEL):**
     ```bash
     chcon -Rt container_file_t data/gateway data/wallet
     podman unshare chown -R 10001:10001 data/gateway data/wallet
     ```
2. Build images and initialize the wallet inside `data/wallet` (creates `gateway_wallet`, `gateway_wallet.keys`, and `0600` `gateway_wallet.password`) before starting the stack:
   ```bash
   # Build reproducible images (official Monero CLI verified via SHA256):
   docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env.docker build
   # (Or with podman-compose: podman-compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env.docker build)

   # One-shot wallet initialization example (replace --stagenet / --generate-from-view-key as needed):
   podman run --rm -it --entrypoint /bin/sh \
     --user 10001:10001 -v "$PWD/data/wallet:/wallet:rw" \
     localhost/docker_monero-wallet-rpc:latest -c '
       umask 077
       head -c 24 /dev/urandom | od -An -tx1 | tr -d " \n" > /wallet/gateway_wallet.password
       chmod 600 /wallet/gateway_wallet.password
       printf "N\n" | /usr/local/bin/monero-wallet-cli --offline --stagenet \
         --generate-new-wallet /wallet/gateway_wallet \
         --password-file /wallet/gateway_wallet.password \
         --restore-height 1600000 --mnemonic-language English --command address
       chmod 600 /wallet/gateway_wallet*
     '
   ```
3. Launch the stack:
   ```bash
   docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env.docker up -d

   # Optional automatic HTTPS via bundled Caddy profile:
   docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env.docker --profile caddy up -d
   ```
- `monero-wallet-rpc` port `18082` is **never** published to the host (internal-only `xmr_internal` network).
- `xmr-gateway` binds strictly to `127.0.0.1:8080:8080` and includes a native Compose `healthcheck:`.
- Both containers enforce non-root `10001:10001`, `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, and `stop_grace_period: 30s` for clean WAL truncation and wallet flush.

### 4.2. Rootless Podman Quadlet (`deploy/podman/quadlet/`) — Fedora / RHEL (SELinux `Enforcing`)
Quadlet maps your unprivileged user directly to UID `10001` (`UserNS=keep-id:uid=10001,gid=10001`), applies private SELinux `:Z` labels on **non-overlapping** `data/` and `wallet/` sibling directories, uses two bridge networks (`xmr-gateway-internal.network` + `xmr-gateway-egress.network`, avoiding Podman 5 `pasta`/bridge conflicts), and configures native OCI `HealthCmd=` and `StopTimeout=30`.

```bash
# 1. Build both images as your regular unprivileged user:
podman build -t localhost/xmr-gateway:latest -f Containerfile .
podman build -t localhost/xmr-gateway-wallet-rpc:latest -f deploy/docker/Containerfile.monero-rpc .

# 2. Prepare isolated sibling directories (0700) and 0600 env file:
mkdir -p ~/.local/share/xmr-gateway/data ~/.local/share/xmr-gateway/wallet ~/.config/xmr-gateway ~/.config/containers/systemd
chmod 700 ~/.local/share/xmr-gateway ~/.local/share/xmr-gateway/data ~/.local/share/xmr-gateway/wallet ~/.config/xmr-gateway
cp deploy/docker/.env.docker.example ~/.config/xmr-gateway/gateway.env
chmod 600 ~/.config/xmr-gateway/gateway.env
# Edit ~/.config/xmr-gateway/gateway.env and replace all placeholder secrets!

# 3. Initialize the wallet in ~/.local/share/xmr-gateway/wallet/ using a one-shot container
#    (creates gateway_wallet* and 0600 gateway_wallet.password; use --generate-from-view-key for view_only):
podman run --rm -it --entrypoint /bin/sh \
  --userns=keep-id:uid=10001,gid=10001 --user 10001:10001 \
  -v "$HOME/.local/share/xmr-gateway/wallet:/wallet:Z" \
  localhost/xmr-gateway-wallet-rpc:latest -c '
    umask 077
    head -c 24 /dev/urandom | od -An -tx1 | tr -d " \n" > /wallet/gateway_wallet.password
    chmod 600 /wallet/gateway_wallet.password
    printf "N\n" | /usr/local/bin/monero-wallet-cli --offline \
      --generate-new-wallet /wallet/gateway_wallet \
      --password-file /wallet/gateway_wallet.password \
      --restore-height 3280000 --mnemonic-language English --command address
    chmod 600 /wallet/gateway_wallet*
  '

# 4. Install ALL 4 Quadlet units (internal + egress networks + both containers):
cp deploy/podman/quadlet/xmr-gateway-internal.network \
   deploy/podman/quadlet/xmr-gateway-egress.network \
   deploy/podman/quadlet/monero-wallet-rpc.container \
   deploy/podman/quadlet/xmr-gateway.container \
   ~/.config/containers/systemd/

# 5. Reload and start (Quadlet units are generated dynamically — do NOT run `systemctl --user enable`;
#    boot autostart is already wired via `[Install] WantedBy=default.target` + linger):
systemctl --user daemon-reload
systemctl --user start monero-wallet-rpc.service xmr-gateway.service
systemctl --user status monero-wallet-rpc.service xmr-gateway.service

# 6. Enable lingering so rootless services persist across logouts and reboots:
loginctl enable-linger "$USER"
```

---

## 5. Upgrades, Key Rotation, Backups & Mainnet Cutover

- **Safe Package Upgrades (`.deb`/`.rpm`):**
  1. Take a hot online backup: `sudo -u xmr-gateway xmr-gateway-admin db backup`.
  2. Install the new package (`apt-get install ./xmr-gateway_...deb` or `dnf upgrade ./xmr-gateway-...rpm`) — `/etc/xmr-gateway/.env` and `/var/lib/xmr-gateway/` are never overwritten or deleted.
  3. Restart & audit: `sudo systemctl restart xmr-gateway.service && sudo -u xmr-gateway xmr-gateway-admin db audit-invariants`.
- **Secret Rotation & SELinux Context:** `sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys all` (creates a `0600` `.env.bak.<UTC>` backup, writes atomically inside `/etc/xmr-gateway/`, preserves owner and `etc_t` SELinux label via `restorecon`), then `sudo systemctl restart monero-wallet-rpc.service xmr-gateway.service`.
- **SQLite Backup Restore:** stop `xmr-gateway.service`, remove stale `xmr_gateway.db-wal` and `xmr_gateway.db-shm`, copy verified backup to `xmr_gateway.db` (`chmod 600`, `chown xmr-gateway:xmr-gateway`), run `xmr-gateway-admin db audit-invariants`, and start the service. Always restore wallet files and `xmr_gateway.db` together — never attach a wallet with prior subaddress history to an empty database.
- **Trust Model & Architectural Boundaries:**
  - **Self-hosted, single-instance / single-merchant:** `xmr-gateway` runs without a third-party payment processor intermediary, using one SQLite WAL database and one dedicated `monero-wallet-rpc` wallet per instance (strictly enforced via `<db_path>.lock`).
  - **View-only vs. hot-wallet:** In `WALLET_MODE=view_only` (recommended default), no private spend key resides on the host. In `WALLET_MODE=hot_wallet`, the spend key resides inside `monero-wallet-rpc` — keep only minimal operational transit balances, strictly isolate the host/RPC, require distinct `OPERATOR_API_KEY`, and sweep promptly to an offline/hardware `COLD_WALLET_ADDRESS`.
  - **Opaque `order_id` without PII:** Never embed emails, usernames, or customer PII in `order_id` because it is persisted in operational logs, `monero:` URIs, and wallet labels.
- **Webhook Verification Contract (Retries & Freshness):** Each delivery attempt (initial send, automatic backoff retry, and manual `webhooks retry`) emits a fresh Unix epoch `X-Webhook-Timestamp` and freshly computed `X-Webhook-Signature = HMAC-SHA256(WEBHOOK_SECRET, "{X-Webhook-Timestamp}.{raw_body}")`, while keeping `X-Webhook-Event-Id` (`payload.event_id`) and the JSON payload bytes immutable. Consumers should verify `abs(now - ts) <= 300s`, check `X-Webhook-Signature` in constant time, and deduplicate by `event_id` (legacy `X-Signature-256` is also sent).
- **Stagenet → Mainnet Cutover:** isolate `.env` and SQLite path, provision a **fresh dedicated Mainnet wallet** (no historical subaddress inflows), set `MONERO_NETWORK=mainnet`, `ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS=true` (setting `REQUIRE_HTTPS_WEBHOOKS=false` with `ALLOW_PRIVATE_WEBHOOKS=false` on mainnet **fails closed** at startup and in `config doctor`), tune `SCANNER_SUBADDRESS_BATCH_SIZE=100` (`1..=1000`), rotate distinct `API_SECRET_KEY`/`OPERATOR_API_KEY` (`OPERATOR_API_KEY` is strictly required for `WALLET_MODE=hot_wallet` / `ENABLE_AUTO_SWEEP=true`), and confirm `config doctor` reports `[PASS] wallet_daemon_sync ... (lag=0, daemon_synchronized=true)` + `dev health-rbac` before accepting live traffic.
- **Zero-Argv-Leak RPC & Unlocked Settlement:** systemd units (`render-wallet-rpc-conf.sh`), containers, `start.sh`, `admin/service.sh`, and `demo-stagenet.sh` all pass `monero-wallet-rpc` credentials via a `0600` `--config-file` (never `--rpc-login` in `argv`). `SETTLED`/`COMPLETED` finality requires unlocked covering outputs `>= invoice amount` at `>= SETTLEMENT_CONFIRMATIONS` (blocking custom `unlock_time` attacks while remaining immune to mempool dust DoS).

---

## 6. Maintainer Release Guide (GitHub Actions)

`.github/workflows/release.yml` natively builds Linux `x86_64` (`ubuntu-24.04`) and `aarch64` (`ubuntu-24.04-arm`) binaries, `.tar.gz` bundles, `.deb`, and `.rpm` packages, generates sorted `SHA256SUMS`, optionally GPG-signs `SHA256SUMS.asc`, and attaches GitHub Build Provenance Attestations.

### One-Time GPG Signing Setup (GitHub → Settings → Secrets and variables → Actions)
```bash
# Export your dedicated release signing key (ASCII-armored):
gpg --armor --export-secret-keys <KEY_FINGERPRINT>
```
Configure repository secrets:
- `GPG_PRIVATE_KEY` — ASCII-armored GPG private key.
- `GPG_PASSPHRASE` — passphrase for the key (if encrypted).

### Cutting a New Release (3 Commands)
```bash
# 1. Confirm Cargo.toml version matches the tag (e.g. 0.1.4) on up-to-date main:
git checkout main && git pull --ff-only

# 2. Create a (signed) annotated tag:
git tag -s v0.1.4 -m "Release v0.1.4"

# 3. Push the tag to trigger the automated Release workflow:
git push origin v0.1.4
```
To test packaging end-to-end without publishing a release, trigger **Actions → Release → Run workflow** with `dry_run: true`.
