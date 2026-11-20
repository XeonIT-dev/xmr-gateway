# Changelog

All notable changes to `xmr-gateway` are documented in this file.

## [0.1.2] - 2026-11-20

### Fixed
- **POSIX `sh` Newline Guard Regression (`monero-wallet-rpc.service` & `Containerfile.monero-rpc`):** Replaced broken `$(printf "\n")` (which POSIX command substitution strips to empty string, causing `**` to reject all valid credentials) with `nl="$(printf '\nx')"; nl="${nl%x}"` (and `%%` escaped as `${nl%%x}` / `${cr%%x}` inside systemd `ExecStartPre`), restoring startup for `.rpm`/`.deb` systemd services and Docker/Podman containers.
- **System Package `service setup-rpc` Target & Permissions (`admin/service.sh`, `start.sh`):** Always targets `/usr/local/bin` (instead of `/usr/share/xmr-gateway/bin`) when running from a system package install (`/usr/share/xmr-gateway`, `/usr/lib/*`, or `/etc/xmr-gateway/.env`), and creates `$BIN_DIR` via `install -d -m 0755` so `User=xmr-gateway` can always execute `monero-wallet-rpc` under `umask 077`.
- **Unified `.rpm`/`.deb` DB & Wallet Paths (`postinst`, `common.sh`, `wallet.sh`, `config.sh`):** System package post-install now rewrites seeded `/etc/xmr-gateway/.env` to `DATABASE_URL=sqlite:///var/lib/xmr-gateway/xmr_gateway.db`, `admin/lib/common.sh` flattens legacy relative `sqlite://data/...` paths for `/etc/xmr-gateway/.env`, and `admin/wallet.sh` enforces `0700`/`0600` `xmr-gateway:xmr-gateway` ownership on `/var/lib/xmr-gateway/wallet`, eliminating the `/var/lib/xmr-gateway/data/wallet` vs `/var/lib/xmr-gateway/wallet` mismatch.
- **Network-Aware Default `WALLET_RESTORE_HEIGHT` (`.env.example`, `.env.docker.example`):** Left `WALLET_RESTORE_HEIGHT=` empty by default so `start.sh` and `admin/lib/common.sh` auto-select `3280000` (mainnet), `1600000` (stagenet), or `2600000` (testnet) instead of overriding stagenet with mainnet height `3280000`.
- **Runtime Regression Tests (`admin/test_admin.sh`):** Added real executable runtime tests that run extracted `monero-wallet-rpc.service` `ExecStartPre` and `Containerfile.monero-rpc` `entrypoint-monero-rpc.sh` through `/bin/sh` (positive + `\n`/`\r` negative cases), verify `resolve_setup_rpc_bin_dir` + `0755` `BIN_DIR` under `umask 077`, and validate `postinst` + `load_env` path/height consistency.

## [0.1.1] - 2026-11-20

### Fixed
- **systemd (`monero-wallet-rpc.service`):** Escaped all `printf` format specifiers (`%%s`) in `ExecStartPre` so `systemd` no longer substitutes `%s` with `/bin/bash`; added newline-injection guards and network-aware default `MONERO_REMOTE_NODE` resolution.
- **Release Tarball, `.deb`, and `.rpm` Packaging:** Included `start.sh` (`0755`), `CHANGELOG.md`, and all Podman Quadlet files (including `xmr-gateway-egress.network`) in release tarballs and system packages; fixed `admin/service.sh` (`service setup-rpc`) to reliably resolve `start.sh` and target `/usr/local/bin` on read-only system installs (`XMR_BIN_DIR`) with `x86_64` and `aarch64` Monero CLI SHA256 pinning.
- **Podman 5 Quadlet Networking:** Replaced conflicting `Network=pasta` alongside `xmr-gateway-internal.network` with a dedicated `deploy/podman/quadlet/xmr-gateway-egress.network` bridge in both `monero-wallet-rpc.container` and `xmr-gateway.container`.
- **Container Volume Isolation & SELinux `:Z` Safety:** Separated gateway SQLite storage from wallet key files into non-overlapping sibling directories (`~/.local/share/xmr-gateway/data:/data:Z` in Quadlet and `../../data/gateway:/data:rw` in `docker-compose.yml` / `.env.docker.example`), eliminating both wallet file exposure to `xmr-gateway` and SELinux MCS `:Z` relabel conflicts.
- **RBAC Key Rotation & `.env.example`:** Uncommented `OPERATOR_API_KEY` in `.env.example`, updated `admin/config.sh` (`config rotate-keys all`) to always generate/rotate a distinct `OPERATOR_API_KEY`, and ensured `start.sh` replaces placeholder `OPERATOR_API_KEY` values automatically.
- **Container Graceful Shutdown (`SIGTERM`):** Added explicit `StopSignal=SIGTERM` and `StopTimeout=30` (`TimeoutStopSec=40`) in Podman Quadlet container units alongside `exec /usr/local/bin/monero-wallet-rpc --non-interactive --no-initial-sync` and log-size bounds in `Containerfile.monero-rpc`.
- **Systemd Wallet Initialization (`gateway_wallet.password`):** Hardened `admin/wallet.sh` (`create-hot`, `create-view-only`) to enforce `0600` permissions and automatically restore `xmr-gateway:xmr-gateway` ownership under `/var/lib/xmr-gateway/` when invoked via `sudo`.
- **OCI `HEALTHCHECK` & Podman Warnings:** Moved gateway healthchecks out of `Containerfile` into native `healthcheck:` (`deploy/docker/docker-compose.yml`) and `HealthCmd=` / `HealthInterval=` / `HealthTimeout=` / `HealthStartPeriod=` / `HealthRetries=` (`deploy/podman/quadlet/xmr-gateway.container`), eliminating OCI build warnings.
- **Network-Aware Default `MONERO_REMOTE_NODE`:** Automatically selects appropriate public remote nodes (`mainnet`, `stagenet`, `testnet`) when `MONERO_REMOTE_NODE` is empty across `start.sh`, `admin/lib/common.sh`, `monero-wallet-rpc.service`, and `Containerfile.monero-rpc`, and warns in `config doctor` on network/node mismatches.
- **Installer & Admin UX:** Split post-install output in `scripts/install.sh` cleanly between `tarball` (`$PREFIX` + `admin.sh`) and `deb`/`rpm` (`systemd`), enabled unprivileged `--prefix "$HOME/..."` tarball installs, silenced transient `curl: (7)` connection-refused spam in `admin/service.sh` startup polling loops, and derived webhook `User-Agent` from `CARGO_PKG_VERSION`.
- **Documentation (`DEPLOY_EN.md`, `DEPLOY_RU.md`, Quadlet headers):** Corrected Quadlet activation (`systemctl --user daemon-reload && systemctl --user start ...` instead of `enable --now`) and added complete Rootless Podman + SELinux `Enforcing` (`chcon`, `podman unshare chown`, one-shot wallet init container) guides.

## [0.1.0] - 2026-11-20

### Added
- Non-custodial Monero (XMR) payment gateway core (`axum`, SQLite WAL `BEGIN IMMEDIATE`, per-invoice subaddresses, reorg-safe state machine with unlocked covering-set `SETTLED`/`COMPLETED` finality, crash-safe `sweep_all`, HMAC-SHA256 SSRF-hardened webhooks, constant-time RBAC with mandatory `OPERATOR_API_KEY` for `hot_wallet`, fail-closed `view_only` RPC verification).
- Bilingual (`EN`/`RU`) CLI & interactive admin suite (`admin.sh`, `admin/*`), native `.deb`/`.rpm`/tarball packaging, fail-closed `scripts/install.sh`, hardened `systemd` units, Docker Compose, rootless Podman Quadlet, reverse-proxy templates, and GitHub Actions CI/Security/Release pipelines.
