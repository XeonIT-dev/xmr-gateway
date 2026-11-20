# Руководство по админ-панели `xmr-gateway` (`./admin.sh` и `admin/`)

> Полная эксплуатационная инструкция для модульной CLI/интерактивной системы администрирования `xmr-gateway`.
> Все команды, флаги, проверки и сценарии ниже соответствуют реальным скриптам в `admin/` и коду шлюза.

---

## 1. Быстрый старт и режимы работы

### Интерактивный режим и CLI
- **Интерактивное меню:** запустите `./admin.sh` без аргументов. При первом интерактивном запуске (если язык ещё не сохранён в `.admin_lang` и не задан через `--lang`/`ADMIN_LANG`) появится выбор `1) Русский / 2) English`.
- **Скриптовый CLI:**
  ```bash
  ./admin.sh [--env <path>] [--lang <en|ru>] [--json] [--yes] <module> <command> [args...]
  ./admin.sh help
  ./admin.sh <module> help
  ```
- **Просмотр этой инструкции прямо из CLI:**
  ```bash
  ./admin.sh guide            # открыть GUIDE_RU.md / GUIDE_EN.md (less -R в TTY, cat в пайпе)
  ./admin.sh guide --path     # вывести путь к файлу инструкции для активного языка
  ```

### Выбор и приоритет языка (`RU` / `EN`)
Язык определяется строго по приоритету сверху вниз:
1. Глобальный флаг CLI: `--lang ru` или `--lang en` (при неизвестном коде — fail-closed ошибка).
2. Переменная окружения: `ADMIN_LANG=ru` или `ADMIN_LANG=en`.
3. Сохранённый файл состояния: `${ADMIN_STATE_DIR:-./data}/.admin_lang` (в gitignored `data/`, права `0600`).
4. Системная локаль: `LC_ALL` / `LANG`, начинающиеся с `ru` → `ru`, иначе `en`.

Управление языком:
```bash
./admin.sh lang show        # показать активный язык, источник и путь к файлу состояния
./admin.sh lang ru          # сохранить русский язык
./admin.sh lang en          # сохранить английский язык
```
В главном интерактивном меню пункт **`[L]`** мгновенно переключает язык (`RU ↔ EN`) на лету без выхода из меню, а пункт **`[G]`** открывает инструкцию на текущем языке.

### Глобальные флаги и строгая инвариантность `--json`
- `--env <path>` — работа с отдельным конфигом, например `./admin.sh --env .env.mainnet config doctor`. Каталог БД (`DATA_DIR`), кошелёк (`WALLET_FILE`), логи и PID-файлы автоматически вычисляются из `DATABASE_URL` выбранного файла (полная изоляция `.env` и `.env.mainnet`).
- `--json` — машиночитаемый JSON-вывод, **байт-в-байт идентичный** при `--lang ru` и `--lang en` (ключи, статусы и enum-поля не переводятся).
- `--yes` / `-y` — неинтерактивное подтверждение для автоматизации.
- **Предохранитель `[MAINNET]`:** при `MONERO_NETWORK=mainnet` перед финансовыми/деструктивными операциями (`transfer`, `sweep`, `sweep-all`, `resolve`, `rotate-keys`, `stop`, `set-mode`, `db shell --rw`) выводится красный баннер `[MAINNET]` и требуется ввод точного слова **`yes`** (либо явный `--yes`). В неинтерактивном окружении без `--yes` команда завершается fail-closed.
- **Защита секретов в `ps aux`:** `API_SECRET_KEY`, `OPERATOR_API_KEY`, `MONERO_RPC_PASS` и `MONERO_DAEMON_RPC_PASS` передаются в `curl` строго через `stdin` (`curl --config -`), а учётные данные `monero-wallet-rpc` записываются во временный `0600`-файл (`--config-file`, удаляется при остановке), никогда не попадая в аргументы командной строки.

- **Системная установка (из `.deb` / `.rpm` или tarball):** после установки из пакета админ-панель доступна глобально как **`xmr-gateway-admin`** (`/usr/bin/xmr-gateway-admin` → `/usr/share/xmr-gateway/admin.sh`). Если флаг `--env` не передан и рядом нет локального `.env`, автоматически подхватывается `/etc/xmr-gateway/.env`, а файл языка `.admin_lang` сохраняется в `/var/lib/xmr-gateway` или `~/.local/state/xmr-gateway/` (никогда не пытаясь писать в read-only `/usr/share/xmr-gateway`). Полное руководство по деплою, `systemd`, Docker/Podman и пакетам см. в [DEPLOY_RU.md](../DEPLOY_RU.md).

---

## 2. Управление сервисами (`service`)

| Команда | Назначение |
|---|---|
| `./admin.sh service start` | Запускает `monero-wallet-rpc` (ждёт `get_version`), затем `xmr-gateway` (локальный `target/release` или системный `/usr/bin/xmr-gateway`), пишет PID в `data/pids/*.pid` (`0600`). |
| `./admin.sh service stop` | Отправляет `SIGTERM` сначала `xmr-gateway` (ожидание до 25с для завершения воркеров и `PRAGMA wal_checkpoint(TRUNCATE)` до освобождения `.lock`), затем `monero-wallet-rpc`. |
| `./admin.sh service restart` | Корректный `stop` + `start`. |
| `./admin.sh service status [--json]` | Показывает PID-ы, URL, HTTP-статус `/health` и версию `monero-wallet-rpc`. |
| `./admin.sh service logs [gateway\|rpc\|cli] [-f] [-n N]` | Просмотр последних `N` строк (по умолч. `gateway`, `50`) или live-tail (`-f`). |
| `./admin.sh service build` | Сборка release-бинарника: `cargo build --release --locked`. |
| `./admin.sh service setup-rpc` | Установка и проверка SHA256 официальных бинарников Monero CLI через `./start.sh --setup-rpc`. |
| `./admin.sh service systemd [status\|install-dry-run\|restart]` | Инспекция или перезапуск всех юнитов `deploy/systemd/` (`monero-wallet-rpc.service`, `xmr-gateway.service`, `xmr-gateway-backup.service` + `.timer`, синхронизировано с `/etc/xmr-gateway/.env`, `UMask=0077`, `KillSignal=SIGTERM`). |

---

## 3. Конфигурация и безопасность (`config`)

- **`./admin.sh config show [--json]`** — выводит активные параметры выбранного `.env` с маскированием всех секретов (`API_SECRET_KEY`, `OPERATOR_API_KEY`, `WEBHOOK_SECRET`, `MONERO_RPC_PASS`, `MONERO_DAEMON_RPC_PASS`, `MONERO_VIEW_ONLY_KEY`).
- **`./admin.sh config doctor [--strict-live] [--json]`** — комплексная fail-closed проверка (возвращает код `1` при любом `FAIL`):

| Проверка (`check`) | Статус | Что проверяется и как исправить при `FAIL`/`WARN` |
|---|---|---|
| `env_permissions` | FAIL | Права `.env` обязаны быть `0600` (`chmod 600 .env`). |
| `wallet_*_permissions`, `db/wal/shm_permissions` | FAIL | Файлы `.keys`, `.password`, `.db`, `-wal`, `-shm` должны иметь права `0600`. |
| `secret_api_secret_key`, `secret_webhook_secret`, `secret_operator_api_key` | FAIL | Длина `>= 32` байт, отсутствие плейсхолдеров (`replace-with-*`, `changeme*`). Сгенерируйте через `config rotate-keys`. |
| `rbac_key_separation` | FAIL / WARN | При заданном `OPERATOR_API_KEY` он обязан отличаться от `API_SECRET_KEY` (`AUDIT-002`). Отсутствие `OPERATOR_API_KEY` в `hot_wallet` / `ENABLE_AUTO_SWEEP=true` даёт `FAIL` (`XMR-AUDIT-004`), в `view_only` — `WARN` (single-tenant fallback). |
| `wallet_mode`, `cold_wallet_address` | FAIL | `ENABLE_AUTO_SWEEP=true` требует `WALLET_MODE=hot_wallet` и валидный `COLD_WALLET_ADDRESS`; `hot_wallet` без автосвипа требует `ALLOW_HOT_WALLET_WITHOUT_SWEEP=true`. |
| `confirmations`, `sweep_priority` | FAIL | `REQUIRED_CONFIRMATIONS >= 1`, `SETTLEMENT_CONFIRMATIONS >= REQUIRED_CONFIRMATIONS`, `SWEEP_PRIORITY` в `0..4`. |
| `ssrf_policy` | WARN / PASS | На `mainnet` флаги `ALLOW_PRIVATE_WEBHOOKS=true` или (`REQUIRE_HTTPS_WEBHOOKS=false` при `ALLOW_PRIVATE_WEBHOOKS=false`, `XMR-AUDIT-006`) помечаются как `WARN`; в продакшене оставляйте `ALLOW_PRIVATE_WEBHOOKS=false` + `REQUIRE_HTTPS_WEBHOOKS=true`. |
| `rpc_auth`, `daemon_rpc_security` | FAIL / WARN | При `ALLOW_UNAUTHENTICATED_RPC=false` обязательны `MONERO_RPC_USER`/`PASS`; при заданном `MONERO_DAEMON_RPC_URL` проверяются транспорт и креды (`AUDIT-001`). Отсутствие `MONERO_DAEMON_RPC_URL` — `WARN` (нужен для `allow_resweep`). |
| `health_anon_privacy`, `health_auth_api`, `health_auth_operator` | FAIL | Проверяет на живом шлюзе, что анонимный `GET /health` НЕ раскрывает `service`/`monero_rpc`/`database`, а авторизованный возвращает полную телеметрию (`AUDIT-002`). |
| `wallet_daemon_sync` | WARN / PASS | Сравнивает `get_height` кошелька и `get_info` демона; отставание `> 5` блоков помечается `WARN`. |

- **`./admin.sh config rotate-keys [api|operator|webhook|rpc|all]`** — создаёт резервную копию `<env>.bak.<UTC>` с правами `0600`, генерирует новые секреты через `openssl rand -hex 32` (`24` байта для `rpc`), гарантирует `OPERATOR_API_KEY != API_SECRET_KEY`. После ротации выполните `./admin.sh service restart` и обновите ключи в боте/клиентах.
- **`./admin.sh config set-mode <view_only|hot_wallet>`** — безопасно переключает `WALLET_MODE` (и `ENABLE_AUTO_SWEEP`) после проверки наличия `COLD_WALLET_ADDRESS` или `MONERO_VIEW_ONLY_ADDRESS`+`MONERO_VIEW_ONLY_KEY` / `.keys`, предварительно сохраняя `0600`-бэкап `.env`.

---

## 4. Кошельки Monero (`wallet`)

### Разница `hot_wallet` vs `view_only`
- **`view_only` (Zero-Trust, рекомендуется):** сервер хранит только публичный адрес и приватный ключ просмотра (`view_key`). Приватный `spend_key` отсутствует — даже при компрометации сервера украсть средства невозможно. Команды `wallet transfer` и `wallet sweep-all` fail-closed отклоняются.
- **`hot_wallet` (Hot Auto-Sweep):** сервер держит транзитный горячий кошелёк со `spend_key` и автоматически выводит разблокированные (`>= 10` блоков) платежи на `COLD_WALLET_ADDRESS`.

### Пошаговый перевод на `view_only`
```bash
# 1. На машине с исходным кошельком экспортируйте публичный адрес и view_key (spend_key не выводится):
./admin.sh wallet export-view-keys

# 2. Перенесите MONERO_VIEW_ONLY_ADDRESS и MONERO_VIEW_ONLY_KEY в .env целевого сервера (chmod 600 .env)
#    и укажите корректный WALLET_RESTORE_HEIGHT.

# 3. Создайте watch-only кошелёк (без приватного spend-ключа):
./admin.sh wallet create-view-only

# 4. Переключите конфиг в режим view_only и проверьте:
./admin.sh config set-mode view_only
./admin.sh config doctor
```

### Остальные команды `wallet`
- `./admin.sh wallet info` (или `balance`) — основной адрес, общий и разблокированный баланс, балансы по субадресам, высота кошелька vs демона (`--json`).
- `./admin.sh wallet transfers [in|out|pool|pending|all]` — список транзакций через `monero-wallet-rpc`.
- `./admin.sh wallet refresh` / `set-height <height>` / `rescan` — синхронизация, исправление завышенного `refresh-from-block-height` и полный перескан.
- `./admin.sh wallet create-hot [--restore-height H]` — генерация горячего кошелька и `0600` файла пароля (сохраните 25-словную seed-фразу офлайн!).
- `./admin.sh wallet transfer <addr> <amount_xmr> [priority]` и `sweep-all <addr> [subaddr_idx] [priority]` — ручной вывод средств (только `hot_wallet`, валидация адреса через `validate_address`, точная десятичная конвертация в пиконеро без float, подтверждение `[MAINNET]`).
- `./admin.sh wallet cli [-- extra_args...]` — запуск `./bin/monero-wallet-cli` с автоматически подставленными флагами сети, демона, прокси и кошелька из `.env`.

---

## 5. Инвойсы и инциденты свипа (`invoices`)

| Команда | Авторизация / Источник | Описание |
|---|---|---|
| `./admin.sh invoices create --order-id ID --amount-xmr 0.25 [--callback-url URL] [--ttl 3600] [--qr-out /tmp/qr.png]` | `X-API-Key` (`POST /api/v1/invoices`) | Создаёт инвойс (также поддерживает `--amount-piconero`); сохраняет PNG QR (`0600`) при `--qr-out`. |
| `./admin.sh invoices get <invoice_id>` | `X-API-Key` (`GET /api/v1/invoices/{id}`) | Актуальный статус, переводы и попытки свипа из API. |
| `./admin.sh invoices list [--status STATUS] [--order-id ID] [--limit 25]` | SQLite RO | Таблица инвойсов из локальной БД. |
| `./admin.sh invoices inspect <invoice_id\|order_id>` | SQLite RO | Полная форензика: `invoices`, `invoice_transfers`, `subaddress_transfers`, `sweep_attempts`, `webhook_deliveries`. |
| `./admin.sh invoices sweep <invoice_id>` | `X-Operator-Key` (`POST .../sweep`) | Ручной запуск свипа разблокированных средств (`>= 10` блоков). |
| `./admin.sh invoices resolve <invoice_id> <action> --note "..." [...]` | `X-Operator-Key` (`POST .../sweep/resolve`) | Разрешение блокирующего инцидента `REORGED`. |

### Протокол разбора `REORGED`-инцидента (`resolve`)
1. Сначала изучите картину: `./admin.sh invoices inspect <invoice_id>` и `./admin.sh wallet transfers out`.
2. **Вариант A — старый свип НЕ попал в сеть (нужен повторный свип):**
   Убедитесь, что на шлюзе задан `MONERO_DAEMON_RPC_URL` (`AUDIT-001` требует сверку высоты кошелька и демона!), затем выполните:
   ```bash
   ./admin.sh invoices resolve <invoice_id> allow_resweep \
     --confirm-absent \
     --note "Проверено в get_transfers и обозревателе: старый tx отсутствует"
   ```
3. **Вариант B — средства фактически дошли до `COLD_WALLET_ADDRESS` (ручной или альтернативный tx):**
   ```bash
   ./admin.sh invoices resolve <invoice_id> mark_reconciled \
     --tx-hash <64-hex-hash> \
     --note "Подтверждено поступление на холодный кошелёк"
   ```

---

## 6. Вебхуки (`webhooks`)

- `./admin.sh webhooks list [--status PENDING|FAILED|DELIVERED] [--invoice-id UUID] [--limit N]` — просмотр очереди `webhook_deliveries` (SQLite RO).
- `./admin.sh webhooks inspect <webhook_id>` — полные детали доставки: `payload_json`, `signature_hex`, `attempts`, `last_status_code`, `last_error`.
- `./admin.sh webhooks retry <webhook_id>` — операторский сброс **строго `FAILED`**-вебхука (`POST /api/v1/webhooks/{id}/retry`; для `PENDING`/`DELIVERED` вернёт `409 Conflict`, `AUDIT-002`).
- `./admin.sh webhooks retry-invoice <invoice_id>` — операторский пакетный сброс всех `FAILED`-вебхуков инвойса (`PENDING` и `DELIVERED` не затрагиваются).
- `./admin.sh webhooks verify-sig <signature_hex> [payload_file|-]` — локальная constant-time проверка `X-Signature-256` по `WEBHOOK_SECRET` из `.env`.
- `./admin.sh webhooks test-receiver [port]` — локальный Python HTTP-приёмник на `127.0.0.1:<port>` (по умолч. `9000`), проверяющий `X-Signature-256` в реальном времени и выводящий события.

---

## 7. База данных SQLite и форензика (`db`)

- **`./admin.sh db stats [--json]`** — сводка по статусам инвойсов, суммам (`expected`, `received`, `overpaid`, `swept`, `fees` в XMR), вебхукам, попыткам свипа и размерам `.db`/`-wal`/`-shm`/`.lock`.
- **`./admin.sh db audit-invariants [--json]`** — fail-closed аудит (код выхода `1` при любом нарушении):
  - `PRAGMA integrity_check;` (`ok`) и `PRAGMA foreign_key_check;` (`0` нарушений);
  - инвариант сохранения баланса **`AUDIT-005`**: по каждой активной/свипнутой строке `subaddress_transfers.amount_piconero == invoice_transfers.amount_piconero`, а также по каждому инвойсу `SUM(subaddress_transfers) == SUM(confirmed non-orphaned invoice_transfers)`;
  - поиск неразрешённых `REORGED` и зависших (`> 10` мин) `PREPARED` свипов.
- **`./admin.sh db backup [dest_dir] [--json]`** — горячий онлайн-бэкап через Python `sqlite3.Connection.backup()` (безопасно при активном WAL, никогда не копируйте `.db` через `cp`!), выставляет права `0600` и немедленно проверяет копию через `PRAGMA integrity_check;`.
  - **Восстановление:** остановите шлюз (`./admin.sh service stop`), удалите устаревшие `xmr_gateway.db-wal` и `xmr_gateway.db-shm`, скопируйте проверенный бэкап на место `.db` (`chmod 600`), проверьте `./admin.sh db audit-invariants` и запустите `./admin.sh service start`.
- **`./admin.sh db shell [--rw]`** — интерактивная SQLite-консоль (по умолчанию строго read-only; `--rw` требует явного подтверждения).

---

## 8. Проверки и разработка (`dev`)

- `./admin.sh dev check` — последовательно запускает `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets --all-features -- -D warnings` и `cargo test --locked --all-targets`.
- `./admin.sh dev health-rbac [--json]` — живая проверка `AUDIT-002` на работающем `GET /health`: убеждается, что анонимный запрос и неверный ключ не получают телеметрию, валидные `X-API-Key` и `X-Operator-Key` её получают, а мерчантский ключ в заголовке `X-Operator-Key` при заданном `OPERATOR_API_KEY` отклоняется.
- `./admin.sh dev demo` — запускает `./demo-stagenet.sh`.
- `./admin/test_admin.sh` — изолированные автотесты самой админ-панели.

---

## 9. Боевые сценарии (Playbooks — «Что делать, если...»)

### Сценарий 1: Шлюз не стартует (SSRF или `WALLET_MODE=view_only` с горячим кошельком)
1. Запустите `./admin.sh config doctor` и `./admin.sh service logs gateway -n 50`.
2. Если ошибка `blocked by SSRF policy`: на локальном тесте выставьте `ALLOW_PRIVATE_WEBHOOKS=true` в `.env`; в продакшене используйте публичный `https://` URL.
3. Если ошибка `WALLET_MODE=view_only ... contains a private spend key`: замените кошелёк на настоящий watch-only (`./admin.sh wallet create-view-only`) либо осознанно переключите режим (`./admin.sh config set-mode hot_wallet`).

### Сценарий 2: Клиент оплатил инвойс, а оплата не видна
1. Проверьте статус и субадрес: `./admin.sh invoices inspect <invoice_id>`.
2. Проверьте высоту кошелька и демона: `./admin.sh wallet info` и `./admin.sh wallet transfers in`.
3. Если высота кошелька отстаёт или `WALLET_RESTORE_HEIGHT` был завышен:
   ```bash
   ./admin.sh wallet refresh
   # Если блок оплаты был раньше restore height:
   ./admin.sh wallet set-height <высота_до_оплаты>
   ```
4. Проверьте логи сканера: `./admin.sh service logs gateway -n 100`.

### Сценарий 3: Вебхуки ушли в `FAILED` (бот был недоступен)
1. Посмотрите список упавших доставок: `./admin.sh webhooks list --status FAILED`.
2. Изучите причину (`last_status_code`, `last_error`): `./admin.sh webhooks inspect <webhook_id>`.
3. Устраните проблему на стороне приёмника (при необходимости проверьте подпись через `./admin.sh webhooks verify-sig`).
4. Перезапустите доставку (операторский маршрут, `PENDING` не затрагиваются):
   ```bash
   ./admin.sh webhooks retry-invoice <invoice_id>
   ```

### Сценарий 4: Возник `REORGED`-инцидент свипа
1. Выявите затронутые инвойсы: `./admin.sh db audit-invariants` и `./admin.sh invoices inspect <invoice_id>`.
2. Сверьте исходящие переводы: `./admin.sh wallet transfers all`.
3. Выполните `allow_resweep` (при наличии `MONERO_DAEMON_RPC_URL` и подтверждённом отсутствии старого tx) или `mark_reconciled` с хэшем подтверждённой транзакции (см. раздел 5).
4. Убедитесь, что аудит снова чист: `./admin.sh db audit-invariants`.

### Сценарий 5: Чек-лист перехода со Stagenet на Mainnet
1. Создайте отдельный конфиг `.env.mainnet` (`chmod 600 .env.mainnet`) с изолированным `DATABASE_URL=sqlite://data.mainnet/xmr_gateway.db`.
2. Установите `MONERO_NETWORK=mainnet`, mainnet `MONERO_REMOTE_NODE`, `ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS=true`, `REQUIRED_CONFIRMATIONS=10`, `SETTLEMENT_CONFIRMATIONS=15` (рекомендуемо).
3. Сгенерируйте свежие раздельные секреты: `./admin.sh --env .env.mainnet config rotate-keys all` (проверьте, что задан отдельный `OPERATOR_API_KEY`).
4. Настройте `WALLET_MODE=view_only` (или `hot_wallet` + проверенный mainnet `COLD_WALLET_ADDRESS`) и настройте `MONERO_DAEMON_RPC_URL`.
5. Выполните финальный гейт перед запуском:
   ```bash
   ./admin.sh --env .env.mainnet config doctor
   ./admin.sh --env .env.mainnet service build
   ./admin.sh --env .env.mainnet service start
   ./admin.sh --env .env.mainnet dev health-rbac
   ./admin.sh --env .env.mainnet db audit-invariants
   ```
