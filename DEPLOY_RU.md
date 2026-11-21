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
sudo bash install.sh --method deb --version v0.1.3
sudo bash install.sh --method rpm --version v0.1.3
sudo bash install.sh --method tarball --prefix /opt/xmr-gateway --version v0.1.3

# Непривилегированная установка tarball в домашний каталог (без sudo):
bash install.sh --method tarball --prefix "$HOME/xmr-gateway" --version v0.1.3

# Fail-closed проверка GPG-подписи SHA256SUMS.asc:
sudo bash install.sh --version v0.1.3 --gpg-key ./RELEASE_SIGNING_KEY.asc --require-gpg
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
gh attestation verify xmr-gateway_0.1.3_amd64.deb --owner XeonIT-dev
```

---

## 3. Bare-Metal / VPS (`systemd` + обратный прокси)

### 3.1. Установка пакета `.deb` или `.rpm`
```bash
# Debian / Ubuntu:
sudo apt-get install -y ./xmr-gateway_0.1.3_amd64.deb

# Fedora / RHEL / Rocky:
sudo dnf install -y ./xmr-gateway-0.1.3-1.x86_64.rpm
```
Пакет автоматически:
- создаёт системного пользователя и группу `xmr-gateway` (`/usr/sbin/nologin`);
- создаёт каталоги `/var/lib/xmr-gateway`, `/var/lib/xmr-gateway/wallet`, `/var/lib/xmr-gateway/backups` (`0700`, `xmr-gateway:xmr-gateway`) и `/etc/xmr-gateway` (`0750`, `root:xmr-gateway`);
- копирует шаблон в `/etc/xmr-gateway/.env` (`0600`) **только если файл ещё не существует** (при обновлениях существующий `.env` никогда не перезаписывается);
- устанавливает бинарник `/usr/bin/xmr-gateway`, системную админ-панель `/usr/bin/xmr-gateway-admin`, каталог `/usr/share/xmr-gateway/` (включая `start.sh` и `scripts/render-wallet-rpc-conf.sh` `0755`) и юниты в `/usr/lib/systemd/system/`.

### 3.2. Настройка `/etc/xmr-gateway/.env` и инициализация кошелька
1. Сгенерируйте все 4 свежих раздельных секрета (`API_SECRET_KEY`, `OPERATOR_API_KEY`, `WEBHOOK_SECRET`, `MONERO_RPC_PASS`):
   ```bash
   sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys all
   ```
2. Отредактируйте `/etc/xmr-gateway/.env` (права `0600`):
   - `DATABASE_URL=sqlite:///var/lib/xmr-gateway/xmr_gateway.db`
   - `MONERO_NETWORK=mainnet` (либо `stagenet` / `testnet`; при пустом `MONERO_REMOTE_NODE=` нода подбирается автоматически под выбранную сеть)
   - `WALLET_MODE=view_only`, `ENABLE_AUTO_SWEEP=false` (или `WALLET_MODE=hot_wallet` + `ENABLE_AUTO_SWEEP=true` + `COLD_WALLET_ADDRESS=...`)
   - `ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS=true`
   - `REQUIRED_CONFIRMATIONS=10`, `SETTLEMENT_CONFIRMATIONS=15`
   - `MONERO_VIEW_ONLY_ADDRESS=...`, `MONERO_VIEW_ONLY_KEY=...`, `WALLET_RESTORE_HEIGHT=...`
   - при использовании `allow_resweep` — задайте `MONERO_DAEMON_RPC_URL` (`AUDIT-001`).
3. Установите официальные бинарники Monero CLI (`monero-wallet-rpc` и `monero-wallet-cli`) с проверкой SHA256 в `/usr/local/bin/`:
   ```bash
   sudo xmr-gateway-admin service setup-rpc
   ```
4. Инициализируйте кошелёк (команда автоматически создаёт `0600`-файл `/var/lib/xmr-gateway/wallet/gateway_wallet.password`, требуемый `monero-wallet-rpc.service`, и выставляет владельца `xmr-gateway:xmr-gateway` при запуске через `sudo`):
   ```bash
   # View-Only Zero-Trust (рекомендуется):
   sudo xmr-gateway-admin --env /etc/xmr-gateway/.env wallet create-view-only
   # Или Hot Auto-Sweep кошелёк:
   sudo xmr-gateway-admin --env /etc/xmr-gateway/.env wallet create-hot
   ```
5. Проверьте конфигурацию, права, соответствие ноды сети и RBAC (fail-closed):
   ```bash
   sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config doctor
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
> **Безопасность `systemd`-юнитов:** `monero-wallet-rpc.service` делегирует `ExecStartPre` автономному `0755` POSIX-скрипту `/usr/share/xmr-gateway/scripts/render-wallet-rpc-conf.sh`, который формирует временный `/run/xmr-gateway/wallet-rpc.conf` (`0600`, RAM-only) через `RuntimeDirectory=xmr-gateway`, поэтому `MONERO_RPC_PASS` никогда не светится в `ps aux`. Оба сервиса работают с `UMask=0077`, `ProtectSystem=strict`, `NoNewPrivileges=true` и `KillSignal=SIGTERM` / `TimeoutStopSec=30` для гарантированного `PRAGMA wal_checkpoint(TRUNCATE)`.

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

### 4.1. Docker Compose и Podman Compose (`deploy/docker/`)
Храните `DATA_HOST_DIR` (`data/gateway`) и `WALLET_HOST_DIR` (`data/wallet`) в **непересекающихся соседних каталогах**, чтобы контейнер `xmr-gateway` физически не видел ключи кошелька, а метки SELinux не конфликтовали.

1. Подготовьте изолированные соседние каталоги (`0700`) и файл окружения:
   ```bash
   mkdir -p data/gateway data/wallet
   chmod 700 data data/gateway data/wallet
   cp deploy/docker/.env.docker.example deploy/docker/.env.docker
   chmod 600 deploy/docker/.env.docker
   # Отредактируйте deploy/docker/.env.docker: замените все placeholder-секреты!
   ```
   - **Для Docker Engine:**
     ```bash
     sudo chown -R 10001:10001 data/gateway data/wallet
     ```
   - **Для Rootless Podman + SELinux `Enforcing` (Fedora / RHEL):**
     ```bash
     chcon -Rt container_file_t data/gateway data/wallet
     podman unshare chown -R 10001:10001 data/gateway data/wallet
     ```
2. Соберите образы и инициализируйте кошелёк в `data/wallet` (`gateway_wallet`, `gateway_wallet.keys` и `0600` `gateway_wallet.password`) одноразовым контейнером до `up -d`:
   ```bash
   # Сборка воспроизводимых образов (официальный Monero CLI проверяется по SHA256):
   docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env.docker build
   # (Или через podman-compose: podman-compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env.docker build)

   # Пример инициализации кошелька одноразовым контейнером (для view_only используйте --generate-from-view-key):
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
3. Запустите стек:
   ```bash
   docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env.docker up -d

   # Опционально с встроенным Caddy (автоматический HTTPS):
   docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env.docker --profile caddy up -d
   ```
- Порт `18082` `monero-wallet-rpc` **никогда не публикуется на хост** (общение идёт по изолированной сети `xmr_internal` с `internal: true`).
- Порт `8080` шлюза привязан строго к `127.0.0.1:8080:8080` и снабжён нативным Compose `healthcheck:`.
- Оба контейнера работают от непривилегированного `10001:10001`, с `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true` и `stop_grace_period: 30s` для чистого `WAL TRUNCATE` и сохранения кошелька.

### 4.2. Rootless Podman Quadlet (`deploy/podman/quadlet/`) — Fedora / RHEL (SELinux `Enforcing`)
Quadlet пробрасывает вашего непривилегированного пользователя в UID `10001` (`UserNS=keep-id:uid=10001,gid=10001`), применяет приватные SELinux-метки `:Z` к **непересекающимся** соседним каталогам `data/` и `wallet/`, использует две bridge-сети (`xmr-gateway-internal.network` + `xmr-gateway-egress.network`, исключая конфликт `pasta`/bridge в Podman 5) и задаёт нативные `HealthCmd=` и `StopTimeout=30`.

```bash
# 1. Соберите оба локальных образа от непривилегированного пользователя:
podman build -t localhost/xmr-gateway:latest -f Containerfile .
podman build -t localhost/xmr-gateway-wallet-rpc:latest -f deploy/docker/Containerfile.monero-rpc .

# 2. Создайте изолированные соседние каталоги (0700) и 0600 конфиг:
mkdir -p ~/.local/share/xmr-gateway/data ~/.local/share/xmr-gateway/wallet ~/.config/xmr-gateway ~/.config/containers/systemd
chmod 700 ~/.local/share/xmr-gateway ~/.local/share/xmr-gateway/data ~/.local/share/xmr-gateway/wallet ~/.config/xmr-gateway
cp deploy/docker/.env.docker.example ~/.config/xmr-gateway/gateway.env
chmod 600 ~/.config/xmr-gateway/gateway.env
# Отредактируйте ~/.config/xmr-gateway/gateway.env и замените все placeholder-секреты!

# 3. Инициализируйте кошелёк в ~/.local/share/xmr-gateway/wallet/ одноразовым контейнером
#    (создаёт gateway_wallet* и 0600 gateway_wallet.password; для view_only используйте --generate-from-view-key):
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

# 4. Скопируйте ВСЕ 4 Quadlet-файла (internal + egress сети + оба контейнера):
cp deploy/podman/quadlet/xmr-gateway-internal.network \
   deploy/podman/quadlet/xmr-gateway-egress.network \
   deploy/podman/quadlet/monero-wallet-rpc.container \
   deploy/podman/quadlet/xmr-gateway.container \
   ~/.config/containers/systemd/

# 5. Перечитайте генератор и запустите (динамические Quadlet-юниты НЕ поддерживают `systemctl --user enable`;
#    автозапуск уже задан секцией `[Install] WantedBy=default.target` + linger):
systemctl --user daemon-reload
systemctl --user start monero-wallet-rpc.service xmr-gateway.service
systemctl --user status monero-wallet-rpc.service xmr-gateway.service

# 6. Включите linger, чтобы сервисы работали после выхода из SSH и перезагрузки:
loginctl enable-linger "$USER"
```

---

## 5. Обновление, ротация ключей, бэкапы и переход на Mainnet

- **Безопасное обновление версии (`.deb`/`.rpm`):**
  1. Сделайте горячий бэкап: `sudo -u xmr-gateway xmr-gateway-admin db backup`.
  2. Установите новый пакет (`apt-get install ./xmr-gateway_...deb` или `dnf upgrade ./xmr-gateway-...rpm`) — `/etc/xmr-gateway/.env` и `/var/lib/xmr-gateway/` сохранятся нетронутыми.
  3. Перезапустите: `sudo systemctl restart xmr-gateway.service` и проверьте `xmr-gateway-admin db audit-invariants`.
- **Ротация секретов и SELinux:** `sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys all` (создаёт `0600`-бэкап `.env.bak.<UTC>`, атомарно обновляет `.env` внутри `/etc/xmr-gateway/`, сохраняет владельца и SELinux-контекст `etc_t` через `restorecon`), затем `sudo systemctl restart monero-wallet-rpc.service xmr-gateway.service`.
- **Восстановление БД из бэкапа:** остановите `xmr-gateway.service`, удалите старые `xmr_gateway.db-wal` и `xmr_gateway.db-shm`, скопируйте проверенный бэкап (`chmod 600`, `chown xmr-gateway:xmr-gateway`), проверьте `xmr-gateway-admin db audit-invariants` и запустите сервис.
- **Модель доверия и границы архитектуры:**
  - **Self-hosted single-instance / single-merchant:** шлюз работает без стороннего платёжного посредника в модели одного мерчанта, одной БД SQLite (WAL) и одного кошелька `monero-wallet-rpc` (эксклюзивная блокировка `<db_path>.lock` запрещает второй процесс).
  - **View-Only vs Hot-Wallet:** в `WALLET_MODE=view_only` (рекомендуется) приватный spend-ключ физически отсутствует на сервере. В `WALLET_MODE=hot_wallet` spend-ключ находится в `monero-wallet-rpc` — держите только минимальный операционный транзитный остаток, строго изолируйте хост/RPC, задавайте отдельный `OPERATOR_API_KEY` и выводите средства на холодный/аппаратный `COLD_WALLET_ADDRESS`.
  - **Непрозрачный `order_id` без PII:** не передавайте email, логины или персональные данные в `order_id`, т.к. он попадает в операционные логи, `monero:` URI и метки кошелька.
- **Контракт подписи вебхуков (ретраи и свежесть):** при каждой попытке доставки (первичная отправка, автоматический retry и ручной `webhooks retry`) формируются свежий Unix-timestamp `X-Webhook-Timestamp` и новая подпись `X-Webhook-Signature = HMAC-SHA256(WEBHOOK_SECRET, "{X-Webhook-Timestamp}.{raw_body}")`, тогда как `X-Webhook-Event-Id` (`payload.event_id`) и тело JSON остаются неизменными. Получатель обязан проверять окно свежести (`<= 300s`), подпись `X-Webhook-Signature` в constant-time и идемпотентность по `event_id` (обратно совместимый `X-Signature-256` также передаётся).
- **Переход Stagenet → Mainnet:** используйте отдельный файл окружения и отдельную БД (`/var/lib/xmr-gateway`), выставите `MONERO_NETWORK=mainnet`, `ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS=true` (при `REQUIRE_HTTPS_WEBHOOKS=false` и `ALLOW_PRIVATE_WEBHOOKS=false` на `mainnet` запуск **отклоняется fail-closed**, а `config doctor` выдаёт `FAIL`), настройте `SCANNER_SUBADDRESS_BATCH_SIZE=100` (`1..=1000`), свежие раздельные `API_SECRET_KEY`/`OPERATOR_API_KEY` (`OPERATOR_API_KEY` строго обязателен для `WALLET_MODE=hot_wallet` / `ENABLE_AUTO_SWEEP=true`), прогоните `config doctor` и `dev health-rbac`.
- **Изоляция RPC-пароля и разблокированная финальность:** systemd-юниты (`render-wallet-rpc-conf.sh`), контейнеры, `start.sh`, `admin/service.sh` и `demo-stagenet.sh` передают учётные данные `monero-wallet-rpc` строго через `0600` `--config-file` (никогда через `--rpc-login` в `argv`). Финальность `SETTLED`/`COMPLETED` требует разблокированных покрывающих выходов на сумму инвойса при глубине `>= SETTLEMENT_CONFIRMATIONS` (защита от кастомного `unlock_time` и mempool Dust-DoS).

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
# 1. Убедитесь, что version в Cargo.toml совпадает с тегом (например, 0.1.3), и main актуален:
git checkout main && git pull --ff-only

# 2. Создайте (подписанный) аннотированный тег:
git tag -s v0.1.3 -m "Release v0.1.3"

# 3. Запушьте тег — GitHub Actions автоматически соберёт и опубликует релиз:
git push origin v0.1.3
```
Для пробного прогона без публикации релиза запустите **Actions → Release → Run workflow** с параметром `dry_run: true`.
