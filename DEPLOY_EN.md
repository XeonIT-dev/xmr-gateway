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
sudo bash install.sh --method deb --version v0.1.0
sudo bash install.sh --method rpm --version v0.1.0
sudo bash install.sh --method tarball --prefix /opt/xmr-gateway --version v0.1.0

# Enforce fail-closed GPG verification of SHA256SUMS.asc:
sudo bash install.sh --version v0.1.0 --gpg-key ./RELEASE_SIGNING_KEY.asc --require-gpg
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
gh attestation verify xmr-gateway_0.1.0_amd64.deb --owner XeonIT-dev
```

---

## 3. Bare-Metal / VPS (`systemd` + Reverse Proxy)

### 3.1. Installing `.deb` or `.rpm`
```bash
# Debian / Ubuntu:
sudo apt-get install -y ./xmr-gateway_0.1.0_amd64.deb

# Fedora / RHEL / Rocky:
sudo dnf install -y ./xmr-gateway-0.1.0-1.x86_64.rpm
```
The package automatically:
- creates system group & user `xmr-gateway` (`/usr/sbin/nologin`);
- creates `/var/lib/xmr-gateway`, `/var/lib/xmr-gateway/wallet`, `/var/lib/xmr-gateway/backups` (`0700`, `xmr-gateway:xmr-gateway`) and `/etc/xmr-gateway` (`0750`, `root:xmr-gateway`);
- seeds `/etc/xmr-gateway/.env` (`0600`) from `/etc/xmr-gateway/env.example` **only if it does not already exist** (upgrades never overwrite your `.env`!);
- installs `/usr/bin/xmr-gateway`, `/usr/bin/xmr-gateway-admin` (`/usr/share/xmr-gateway/`), and hardened units in `/usr/lib/systemd/system/`.

### 3.2. Configuring `/etc/xmr-gateway/.env` & View-Only Wallet
1. Generate fresh distinct secrets (`API_SECRET_KEY != OPERATOR_API_KEY`, `WEBHOOK_SECRET`, `MONERO_RPC_PASS`):
   ```bash
   sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys all
   sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys operator
   ```
2. Edit `/etc/xmr-gateway/.env` (keep `0600`):
   - `DATABASE_URL=sqlite:///var/lib/xmr-gateway/xmr_gateway.db`
   - `MONERO_NETWORK=mainnet`, `WALLET_MODE=view_only`, `ENABLE_AUTO_SWEEP=false`
   - `ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS=true`
   - `REQUIRED_CONFIRMATIONS=10`, `SETTLEMENT_CONFIRMATIONS=15`
   - `MONERO_VIEW_ONLY_ADDRESS=...`, `MONERO_VIEW_ONLY_KEY=...`, `WALLET_RESTORE_HEIGHT=...`
   - configure `MONERO_DAEMON_RPC_URL` if you plan to use `allow_resweep` incident resolution (`AUDIT-001`).
3. Install SHA256-verified official `monero-wallet-rpc` & `monero-wallet-cli` into `/usr/local/bin/` and initialize the watch-only wallet:
   ```bash
   sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env wallet create-view-only
   ```
4. Validate permissions, RBAC, and custody invariants (fail-closed):
   ```bash
   sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env config doctor
   ```

### 3.3. Starting `systemd` & Daily Hot Backup Timer
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now monero-wallet-rpc.service xmr-gateway.service
sudo systemctl enable --now xmr-gateway-backup.timer   # daily 0600 online SQLite hot backup

# Check unit status and verify live /health RBAC matrix:
sudo systemctl status monero-wallet-rpc.service xmr-gateway.service xmr-gateway-backup.timer
sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env dev health-rbac
```
> **Systemd hardening highlights:** `monero-wallet-rpc.service` renders `/run/xmr-gateway/wallet-rpc.conf` (`0600`, RAM-only via `RuntimeDirectory=xmr-gateway`) so `MONERO_RPC_PASS` never appears in `ps aux`. Both services enforce `UMask=0077`, `ProtectSystem=strict`, `NoNewPrivileges=true`, and `KillSignal=SIGTERM` / `TimeoutStopSec=30` so SQLite `PRAGMA wal_checkpoint(TRUNCATE)` finishes cleanly on stop.

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

### 4.1. Docker Compose (`deploy/docker/`)
1. Prepare UID/GID `10001` host directories (`0700`) containing your `0600` wallet files:
   ```bash
   mkdir -p data/wallet
   sudo chown -R 10001:10001 data
   chmod 700 data data/wallet
   ```
2. Configure environment:
   ```bash
   cp deploy/docker/.env.docker.example deploy/docker/.env.docker
   chmod 600 deploy/docker/.env.docker
   # Edit deploy/docker/.env.docker and replace all placeholder secrets!
   ```
3. Build reproducible images (`Containerfile` + `deploy/docker/Containerfile.monero-rpc` with fail-closed SHA256 verification of official Monero CLI) and launch:
   ```bash
   docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env.docker up -d --build

   # Optional automatic HTTPS via bundled Caddy profile:
   docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env.docker --profile caddy up -d
   ```
- `monero-wallet-rpc` port `18082` is **never** published to the host (internal-only `xmr_internal` network).
- `xmr-gateway` binds strictly to `127.0.0.1:8080:8080`.
- Both containers enforce non-root `10001:10001`, `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, and `stop_grace_period: 30s` for clean WAL truncation.

### 4.2. Rootless Podman Quadlet (`deploy/podman/quadlet/`) — Fedora / RHEL
```bash
# 1. Build both images as your regular unprivileged user:
podman build -t localhost/xmr-gateway:latest -f Containerfile .
podman build -t localhost/xmr-gateway-wallet-rpc:latest -f deploy/docker/Containerfile.monero-rpc .

# 2. Prepare state/config directories (0700 / 0600):
mkdir -p ~/.local/share/xmr-gateway/wallet ~/.config/xmr-gateway ~/.config/containers/systemd
chmod 700 ~/.local/share/xmr-gateway ~/.local/share/xmr-gateway/wallet ~/.config/xmr-gateway
cp deploy/docker/.env.docker.example ~/.config/xmr-gateway/gateway.env
chmod 600 ~/.config/xmr-gateway/gateway.env
# Populate secrets in ~/.config/xmr-gateway/gateway.env and place wallet files in ~/.local/share/xmr-gateway/wallet/

# 3. Install Quadlet units (SELinux :Z labels and UserNS=keep-id:uid=10001,gid=10001 included):
cp deploy/podman/quadlet/* ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user enable --now monero-wallet-rpc.service xmr-gateway.service

# 4. Enable lingering so rootless services persist across logouts:
loginctl enable-linger "$USER"
```

---

## 5. Upgrades, Key Rotation, Backups & Mainnet Cutover

- **Safe Package Upgrades (`.deb`/`.rpm`):**
  1. Take a hot online backup: `sudo -u xmr-gateway xmr-gateway-admin db backup`.
  2. Install the new package (`apt-get install ./xmr-gateway_...deb` or `dnf upgrade ./xmr-gateway-...rpm`) — `/etc/xmr-gateway/.env` and `/var/lib/xmr-gateway/` are never overwritten or deleted.
  3. Restart & audit: `sudo systemctl restart xmr-gateway.service && sudo -u xmr-gateway xmr-gateway-admin db audit-invariants`.
- **Secret Rotation:** `sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys all` (creates `0600` `.env.bak.<UTC>`), then `sudo systemctl restart monero-wallet-rpc.service xmr-gateway.service`.
- **SQLite Backup Restore:** stop `xmr-gateway.service`, remove stale `xmr_gateway.db-wal` and `xmr_gateway.db-shm`, copy verified backup to `xmr_gateway.db` (`chmod 600`, `chown xmr-gateway:xmr-gateway`), run `xmr-gateway-admin db audit-invariants`, and start the service.
- **Stagenet → Mainnet Cutover:** isolate `.env` and SQLite path, set `MONERO_NETWORK=mainnet`, `ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS=true`, rotate distinct `API_SECRET_KEY`/`OPERATOR_API_KEY`, and pass `config doctor` + `dev health-rbac`.

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
# 1. Confirm Cargo.toml version matches the tag (e.g. 0.1.0) on up-to-date main:
git checkout main && git pull --ff-only

# 2. Create a (signed) annotated tag:
git tag -s v0.1.0 -m "Release v0.1.0"

# 3. Push the tag to trigger the automated Release workflow:
git push origin v0.1.0
```
To test packaging end-to-end without publishing a release, trigger **Actions → Release → Run workflow** with `dry_run: true`.
