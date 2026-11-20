# Руководство по установке и развёртыванию `xmr-gateway` (Production Deployment Guide)

> Полная практическая инструкция по установке, верификации релизов, эксплуатации в продакшене (`systemd`, Docker Compose, rootless Podman Quadlet, Caddy/Nginx) и выпуску релизов `xmr-gateway`.

---

## 1. Выбор способа установки

| Способ | Кому подходит | Плюсы | Артефакты / требования |
|---|---|---|---|
| **One-line installer** (`scripts/install.sh`) | Быстрый старт на VPS (Debian/Ubuntu/Fedora/RHEL) | Автовыбор `.deb`/`.rpm`/tarball + обязательный `SHA256SUMS` (+ опц. GPG) | `curl`, `bash`, `sha256sum` |
| **Пакеты `.deb` / `.rpm`** (GitHub Releases) | Классический Linux-сервер с `systemd` | Автосоздание пользователя `xmr-gateway`, юнитов `systemd`, команды `xmr-gateway-admin`, безопасные обновления без затирания `/etc/xmr-gateway/.env` | `apt`/`dpkg` или `dnf`/`rpm` |
| **Release tarball** (`.tar.gz`) | Минимальные Linux-системы, установка в `/opt/xmr-gateway` | Готовый бинарник `x86_64`/`aarch64` + `admin.sh` + `deploy/` без Rust-тулчейна | `tar`, `curl`, `python3` |
| **Docker Compose** (`deploy/docker/`) | Инфраструктура на Docker с изоляцией контейнеров | Изолированная сеть `xmr_internal`, read-only FS, опциональный профиль `--profile caddy` | Docker Engine + Compose v2 |
| **Rootless Podman Quadlet** (`deploy/podman/quadlet/`) | Fedora / RHEL / Rocky с SELinux и без root-демона | Нативные user-юниты `systemd`, `UserNS=keep-id`, SELinux `:Z` | Podman 4.4+ / systemd user |
| **Сборка из исходников** (`cargo build --release --locked`) | Разработка, аудит, нестандартные ОС | Полный контроль сборки и прогон всех Rust-тестов | Rust >= `1.94`, `cargo` |

---

## 2. Быстрая установка и верификация релизов

### 2.1. One-line установщик (`scripts/install.sh`)
Всегда проверяйте план через `--dry-run` перед установкой на боевой сервер:
```bash
curl -fsSL https://raw.githubusercontent.com/XeonIT-dev/xmr-gateway/main/scripts/install.sh -o install.sh
bash install.sh --dry-run
sudo bash install.sh
```
Дополнительные опции:
```bash
# Явный метод и версия:
sudo bash install.sh --method deb --version v0.1.0
sudo bash install.sh --method rpm --version v0.1.0
sudo bash install.sh --method tarball --prefix /opt/xmr-gateway --version v0.1.0

# Fail-closed проверка GPG-подписи SHA256SUMS.asc:
sudo bash install.sh --version v0.1.0 --gpg-key ./RELEASE_SIGNING_KEY.asc --require-gpg
```

### 2.2. Ручная криптографическая верификация релиза
После скачивания файлов из GitHub Releases (`https://github.com/XeonIT-dev/xmr-gateway/releases`):
```bash
# 1. Проверка SHA-256 контрольной суммы (обязательно)
sha256sum -c SHA256SUMS --ignore-missing

# 2. Проверка GPG-подписи (если релиз подписан ключом мейнтейнера)
gpg --import RELEASE_SIGNING_KEY.asc
gpg --verify SHA256SUMS.asc SHA256SUMS

# 3. Проверка GitHub Build Provenance Attestation (требует GitHub CLI `gh`)
gh attestation verify xmr-gateway_0.1.0_amd64.deb --owner XeonIT-dev
```

---

## 3. Bare-Metal / VPS (`systemd` + обратный прокси)

### 3.1. Установка пакета `.deb` или `.rpm`
```bash
# Debian / Ubuntu:
sudo apt-get install -y ./xmr-gateway_0.1.0_amd64.deb

# Fedora / RHEL / Rocky:
sudo dnf install -y ./xmr-gateway-0.1.0-1.x86_64.rpm
```
Пакет автоматически:
- создаёт системного пользователя и группу `xmr-gateway` (`/usr/sbin/nologin`);
- создаёт каталоги `/var/lib/xmr-gateway`, `/var/lib/xmr-gateway/wallet`, `/var/lib/xmr-gateway/backups` (`0700`, `xmr-gateway:xmr-gateway`) и `/etc/xmr-gateway` (`0750`, `root:xmr-gateway`);
- копирует шаблон в `/etc/xmr-gateway/.env` (`0600`) **только если файл ещё не существует** (при обновлениях существующий `.env` никогда не перезаписывается);
- устанавливает бинарник `/usr/bin/xmr-gateway`, системную админ-панель `/usr/bin/xmr-gateway-admin` (`/usr/share/xmr-gateway/`) и юниты в `/usr/lib/systemd/system/`.

### 3.2. Настройка `/etc/xmr-gateway/.env` и View-Only кошелька
1. Сгенерируйте сильные раздельные секреты (`API_SECRET_KEY != OPERATOR_API_KEY`, `WEBHOOK_SECRET`, `MONERO_RPC_PASS`):
   ```bash
   sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys all
   sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys operator
   ```
2. Отредактируйте `/etc/xmr-gateway/.env` (права `0600`):
   - `DATABASE_URL=sqlite:///var/lib/xmr-gateway/xmr_gateway.db`
   - `MONERO_NETWORK=mainnet`, `WALLET_MODE=view_only`, `ENABLE_AUTO_SWEEP=false`
   - `ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS=true`
   - `REQUIRED_CONFIRMATIONS=10`, `SETTLEMENT_CONFIRMATIONS=15`
   - `MONERO_VIEW_ONLY_ADDRESS=...`, `MONERO_VIEW_ONLY_KEY=...`, `WALLET_RESTORE_HEIGHT=...`
   - при использовании `allow_resweep` — задайте `MONERO_DAEMON_RPC_URL` (`AUDIT-001`).
3. Установите официальные бинарники Monero CLI (`monero-wallet-rpc` и `monero-wallet-cli`) с проверкой SHA256 в `/usr/local/bin/` и создайте watch-only кошелёк от пользователя `xmr-gateway`:
   ```bash
   sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env wallet create-view-only
   ```
4. Проверьте конфигурацию и права (fail-closed):
   ```bash
   sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env config doctor
   ```

### 3.3. Запуск `systemd` и ежедневный горячий бэкап
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now monero-wallet-rpc.service xmr-gateway.service
sudo systemctl enable --now xmr-gateway-backup.timer   # ежедневный горячий бэкап SQLite (0600)

# Проверка статуса и live RBAC на /health:
sudo systemctl status monero-wallet-rpc.service xmr-gateway.service xmr-gateway-backup.timer
sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env dev health-rbac
```
> **Безопасность `systemd`-юнитов:** `monero-wallet-rpc.service` формирует временный `/run/xmr-gateway/wallet-rpc.conf` (`0600`, RAM-only) через `RuntimeDirectory=xmr-gateway`, поэтому `MONERO_RPC_PASS` никогда не светится в `ps aux`. Оба сервиса работают с `UMask=0077`, `ProtectSystem=strict`, `NoNewPrivileges=true` и `KillSignal=SIGTERM` / `TimeoutStopSec=30` для гарантированного `PRAGMA wal_checkpoint(TRUNCATE)`.

### 3.4. Обратный прокси (Caddy / Nginx) и Firewall
Готовые шаблоны лежат в `deploy/reverse-proxy/` (и `/usr/share/xmr-gateway/reverse-proxy/` после установки из пакета):
- **Caddy** (`deploy/reverse-proxy/Caddyfile`): замените `pay.example.com`, скопируйте в `/etc/caddy/Caddyfile`, выполните `sudo systemctl reload caddy`.
- **Nginx** (`deploy/reverse-proxy/nginx-xmr-gateway.conf`): замените домен и пути сертификатов Certbot, скопируйте в `/etc/nginx/sites-available/xmr-gateway.conf` (или `/etc/nginx/conf.d/`), выполните `sudo nginx -t && sudo systemctl reload nginx`.
- Рекомендуется раскомментировать IP/VPN allowlist для операторских маршрутов (`/api/v1/invoices/*/sweep*`, `/api/v1/webhooks/*`) поверх встроенной проверки `OPERATOR_API_KEY`.
- **Firewall:** открывайте наружу **только** `22/tcp`, `80/tcp`, `443/tcp`. Порты `8080` и `18082` привязаны к `127.0.0.1` и не должны открываться в firewall:
  ```bash
  # Ubuntu/Debian (ufw):
  sudo ufw default deny incoming && sudo ufw allow OpenSSH && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw enable
  # Fedora/RHEL (firewalld):
  sudo firewall-cmd --permanent --add-service=http --add-service=https && sudo firewall-cmd --reload
  ```

---

## 4. Контейнеризация (Docker Compose и Rootless Podman Quadlet)

### 4.1. Docker Compose (`deploy/docker/`)
1. Подготовьте каталоги с владельцем UID/GID `10001` и правами `0700` (и поместите туда инициализированный кошелёк `gateway_wallet*` с правами `0600`):
   ```bash
   mkdir -p data/wallet
   sudo chown -R 10001:10001 data
   chmod 700 data data/wallet
   ```
2. Подготовьте окружение:
   ```bash
   cp deploy/docker/.env.docker.example deploy/docker/.env.docker
   chmod 600 deploy/docker/.env.docker
   # Отредактируйте deploy/docker/.env.docker: замените все placeholder-секреты!
   ```
3. Соберите воспроизводимые образы (`Containerfile` + `deploy/docker/Containerfile.monero-rpc` с обязательной SHA256-проверкой официального Monero CLI) и запустите стек:
   ```bash
   docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env.docker up -d --build

   # Опционально с встроенным Caddy (автоматический HTTPS):
   docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env.docker --profile caddy up -d
   ```
- Порт `18082` `monero-wallet-rpc` **никогда не публикуется на хост** (общение идёт по изолированной сети `xmr_internal` с `internal: true`).
- Порт `8080` шлюза привязан строго к `127.0.0.1:8080:8080`.
- Оба контейнера работают от непривилегированного `10001:10001`, с `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true` и `stop_grace_period: 30s` для чистого `WAL TRUNCATE`.

### 4.2. Rootless Podman Quadlet (`deploy/podman/quadlet/`) — Fedora / RHEL
```bash
# 1. Соберите оба локальных образа от непривилегированного пользователя:
podman build -t localhost/xmr-gateway:latest -f Containerfile .
podman build -t localhost/xmr-gateway-wallet-rpc:latest -f deploy/docker/Containerfile.monero-rpc .

# 2. Создайте каталоги данных и 0600 конфиг:
mkdir -p ~/.local/share/xmr-gateway/wallet ~/.config/xmr-gateway ~/.config/containers/systemd
chmod 700 ~/.local/share/xmr-gateway ~/.local/share/xmr-gateway/wallet ~/.config/xmr-gateway
cp deploy/docker/.env.docker.example ~/.config/xmr-gateway/gateway.env
chmod 600 ~/.config/xmr-gateway/gateway.env
# Заполните секреты в ~/.config/xmr-gateway/gateway.env и создайте кошелёк в ~/.local/share/xmr-gateway/wallet/

# 3. Скопируйте Quadlet-файлы (SELinux-метки :Z и UserNS=keep-id:uid=10001,gid=10001 уже настроены):
cp deploy/podman/quadlet/* ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user enable --now monero-wallet-rpc.service xmr-gateway.service

# 4. Включите linger, чтобы сервисы работали после выхода из SSH-сессии:
loginctl enable-linger "$USER"
```

---

## 5. Обновление, ротация ключей, бэкапы и переход на Mainnet

- **Безопасное обновление версии (`.deb`/`.rpm`):**
  1. Сделайте горячий бэкап: `sudo -u xmr-gateway xmr-gateway-admin db backup`.
  2. Установите новый пакет (`apt-get install ./xmr-gateway_...deb` или `dnf upgrade ./xmr-gateway-...rpm`) — `/etc/xmr-gateway/.env` и `/var/lib/xmr-gateway/` сохранятся нетронутыми.
  3. Перезапустите: `sudo systemctl restart xmr-gateway.service` и проверьте `xmr-gateway-admin db audit-invariants`.
- **Ротация секретов:** `sudo -u xmr-gateway xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys all` (создаёт `0600`-бэкап `.env.bak.<UTC>`), затем `sudo systemctl restart monero-wallet-rpc.service xmr-gateway.service`.
- **Восстановление БД из бэкапа:** остановите `xmr-gateway.service`, удалите старые `xmr_gateway.db-wal` и `xmr_gateway.db-shm`, скопируйте проверенный бэкап (`chmod 600`, `chown xmr-gateway:xmr-gateway`), проверьте `xmr-gateway-admin db audit-invariants` и запустите сервис.
- **Переход Stagenet → Mainnet:** используйте отдельный файл окружения и отдельную БД (`/var/lib/xmr-gateway`), выставите `MONERO_NETWORK=mainnet`, `ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS=true` (при `REQUIRE_HTTPS_WEBHOOKS=false` и `ALLOW_PRIVATE_WEBHOOKS=false` на `mainnet` шлюз и `config doctor` выдают предупреждение безопасности), свежие раздельные `API_SECRET_KEY`/`OPERATOR_API_KEY` (`OPERATOR_API_KEY` строго обязателен для `WALLET_MODE=hot_wallet` / `ENABLE_AUTO_SWEEP=true`), прогоните `config doctor` и `dev health-rbac`.
- **Изоляция RPC-пароля и разблокированная финальность:** systemd-юниты, контейнеры, `start.sh`, `admin/service.sh` и `demo-stagenet.sh` передают учётные данные `monero-wallet-rpc` строго через `0600` `--config-file` (никогда через `--rpc-login` в `argv`). Финальность `SETTLED`/`COMPLETED` требует разблокированных покрывающих выходов на сумму инвойса при глубине `>= SETTLEMENT_CONFIRMATIONS` (защита от кастомного `unlock_time` и mempool Dust-DoS).

---

## 6. Для мейнтейнеров: подпись и выпуск релизов GitHub Actions

Workflow `.github/workflows/release.yml` собирает нативные бинарники, `.tar.gz`, `.deb` и `.rpm` для `x86_64` (`ubuntu-24.04`) и `aarch64` (`ubuntu-24.04-arm`), формирует `SHA256SUMS`, подписывает его GPG (если задан секрет) и прикрепляет GitHub Build Provenance Attestation.

### Настройка GPG-подписи (один раз в GitHub → Settings → Secrets and variables → Actions)
```bash
# 1. Экспортируйте выделенный release-ключ GPG (ASCII-armored):
gpg --armor --export-secret-keys <KEY_FINGERPRINT>
```
Добавьте секреты репозитория:
- `GPG_PRIVATE_KEY` — ASCII-armored приватный ключ GPG.
- `GPG_PASSPHRASE` — парольная фраза ключа (если ключ защищён паролем).

### Выпуск релиза (3 шага)
```bash
# 1. Убедитесь, что version в Cargo.toml совпадает с тегом (например, 0.1.0), и main актуален:
git checkout main && git pull --ff-only

# 2. Создайте (подписанный) аннотированный тег:
git tag -s v0.1.0 -m "Release v0.1.0"

# 3. Запушьте тег — GitHub Actions автоматически соберёт и опубликует релиз:
git push origin v0.1.0
```
Для пробного прогона без публикации релиза запустите **Actions → Release → Run workflow** с параметром `dry_run: true`.
