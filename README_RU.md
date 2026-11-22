# xmr-gateway — Руководство по архитектуре, настройке и эксплуатации

`xmr-gateway` — автономный (self-hosted), некастодиальный платёжный шлюз Monero (XMR) на языке Rust (без сторонних платёжных посредников) с изоляцией субадресов на каждый инвойс, учётом в SQLite (WAL), подписанными вебхуками (`HMAC-SHA256` со свежим `X-Webhook-Timestamp` на каждую попытку) и опциональным движком автоматического вывода средств на холодный кошелёк (Hot Auto-Sweep).

---

## 1. Оглавление

- [1. Оглавление](#1-оглавление)
- [2. Назначение и архитектура `xmr-gateway`](#2-назначение-и-архитектура-xmr-gateway)
  - [2.1. Компоненты системы](#21-компоненты-системы)
  - [2.2. HTTP API и разделение прав (RBAC)](#22-http-api-и-разделение-прав-rbac)
  - [2.3. Жизненный цикл инвойса и подтверждения](#23-жизненный-цикл-инвойса-и-подтверждения)
  - [2.4. Движок автосвипа и восстановление инцидентов](#24-движок-автосвипа-и-восстановление-инцидентов)
  - [2.5. Вебхуки, подпись `X-Webhook-Signature` / `X-Signature-256` и политика повторов](#25-вебхуки-подпись-x-webhook-signature--x-signature-256-и-политика-повторов)
- [3. Автоматические bash-скрипты и сценарии запуска](#3-автоматические-bash-скрипты-и-сценарии-запуска)
  - [3.1. Оркестратор `start.sh`](#31-оркестратор-startsh)
  - [3.2. Интерактивное демо `demo-stagenet.sh`](#32-интерактивное-демо-demo-stagenetsh)
  - [3.3. Сводная таблица скриптов, портов и файлов](#33-сводная-таблица-скриптов-портов-и-файлов)
  - [3.4. Остановка процессов и очистка артефактов](#34-остановка-процессов-и-очистка-артефактов)
  - [3.5. Единая админ-панель `./admin.sh` и модули `admin/`](#35-единая-админ-панель-adminsh-и-модули-admin)
- [4. Настройка `.env` и переменных окружения](#4-настройка-env-и-переменных-окружения)
  - [4.1. HTTP-сервер и SQLite](#41-http-сервер-и-sqlite)
  - [4.2. Авторизация API и вебхуки](#42-авторизация-api-и-вебхуки)
  - [4.3. Сеть Monero, RPC кошелька и демона](#43-сеть-monero-rpc-кошелька-и-демона)
  - [4.4. Режим кастодиальности и автосвип](#44-режим-кастодиальности-и-автосвип)
  - [4.5. Подтверждения, таймауты, интервалы и логирование](#45-подтверждения-таймауты-интервалы-и-логирование)
  - [4.6. Переменные скрипта `start.sh` (bootstrap и загрузка CLI)](#46-переменные-скрипта-startsh-bootstrap-и-загрузка-cli)
- [5. Проверки безопасности и ограничения при запуске](#5-проверки-безопасности-и-ограничения-при-запуске)
  - [5.1. Модель доверия: `view_only` vs `hot_wallet` и контроль `spend_key`](#51-модель-доверия-view_only-vs-hot_wallet-и-контроль-spend_key)
  - [5.2. Ограничения режима `hot_wallet` и `COLD_WALLET_ADDRESS`](#52-ограничения-режима-hot_wallet-и-cold_wallet_address)
  - [5.3. Требования к секретам и RPC-транспорту](#53-требования-к-секретам-и-rpc-транспорту)
  - [5.4. Анти-SSRF защита исходящих вебхуков](#54-анти-ssrf-защита-исходящих-вебхуков)
  - [5.5. Блокировка одиночного экземпляра и контроль миграций `sqlx`](#55-блокировка-одиночного-экземпляра-и-контроль-миграций-sqlx)
- [6. Пошаговый запуск на Stagenet и интеграция с ботом](#6-пошаговый-запуск-на-stagenet-и-интеграция-с-ботом)
  - [6.1. Быстрый автоматический запуск (`demo-stagenet.sh` и `start.sh`)](#61-быстрый-автоматический-запуск-demo-stagenetsh-и-startsh)
  - [6.2. Ручной запуск связки `monero-wallet-rpc` + `xmr-gateway`](#62-ручной-запуск-связки-monero-wallet-rpc--xmr-gateway)
  - [6.3. Проверка `/health`, создание инвойса и опрос статуса](#63-проверка-health-создание-инвойса-и-опрос-статуса)
  - [6.4. Интеграция с Telegram-ботом (создание счёта и приём вебхуков)](#64-интеграция-с-telegram-ботом-создание-счёта-и-приём-вебхуков)
  - [6.5. Типовые ошибки на старте и способы их решения](#65-типовые-ошибки-на-старте-и-способы-их-решения)
- [7. Сборка, тесты и эксплуатация](#7-сборка-тесты-и-эксплуатация)
  - [7.1. Сборка и команды `Makefile`](#71-сборка-и-команды-makefile)
  - [7.2. Запуск тестов и статического анализа](#72-запуск-тестов-и-статического-анализа)
  - [7.3. Работа с SQLite (WAL durability), резервное копирование, `systemd` и логи](#73-работа-с-sqlite-wal-durability-резервное-копирование-systemd-и-логи)
  - [7.4. Чеклист перед запуском на Mainnet](#74-чеклист-перед-запуском-на-mainnet)

---

## 2. Назначение и архитектура `xmr-gateway`

### 2.1. Компоненты системы

Сервис собирается как один бинарник `xmr-gateway` (Rust edition `2024`, MSRV `1.94`, см. `Cargo.toml`) и при запуске (`src/main.rs`) инициализирует четыре тесно координируемых подсистемы в одном асинхронном рантайме `tokio`:

```text
+--------------------+         HTTP REST (X-API-Key / X-Operator-Key)         +---------------------------+
| Мерчант / TG-бот   | -----------------------------------------------------> |  Axum HTTP API (src/api)  |
|                    | <---- Signed Webhooks (POST + X-Signature-256) ------- |  Body <= 64 KiB, 30s TO   |
+--------------------+                                                        +-------------+-------------+
                                                                                            |
                                                 +------------------------------------------+------------------------------------------+
                                                 |                                          |                                          |
                                                 v                                          v                                          v
                                    +--------------------------+             +-----------------------------+            +-----------------------------+
                                    |  SQLite WAL (sqlx 0.9)   | <---------> |  ScannerService (bg worker) | ---------> | MoneroRpcClient (JSON-RPC)  |
                                    |  synchronous = FULL      |             |  get_transfers + sweep_all  |            | HTTP Digest/Basic, <=16 MiB |
                                    |  foreign_keys = ON       |             +-----------------------------+            +--------------+--------------+
                                    |  <db_path>.lock (0600)   |                                                                       |
                                    +------------+-------------+                                                                       v
                                                 ^                                                                      +-----------------------------+
                                                 |                                                                      | monero-wallet-rpc (local)   |
                                    +------------+-------------+                                                        | 127.0.0.1:18082 -> monerod  |
                                    | WebhookDispatcher worker |                                                        +-----------------------------+
                                    | outbox, <=8 concurrent   |
                                    +--------------------------+
```

- **HTTP API (`src/api/`):** построен на `axum 0.8` + `tower-http`. Включает лимит тела запроса `64 KiB` (`MAX_REQUEST_BODY_BYTES`), таймаут обработки запроса `30s`, `x-request-id` (UUID), редактирование чувствительных заголовков (`x-api-key`, `x-operator-key`, `authorization`, `cookie`) в логах и настраиваемый CORS.
- **Хранилище SQLite (`src/db/`):** пул `sqlx` (`max_connections = 8` для файловой БД и `1` для `sqlite::memory:`), `journal_mode = WAL`, `synchronous = FULL`, `foreign_keys = ON`, `busy_timeout = 5s`. Все денежные суммы хранятся строго как целые `INTEGER` в атомарных пиконеро (`1 XMR = 10^12 piconero`, тип `Piconero`, без чисел с плавающей точкой).
- **Воркер сканера (`src/services/scanner.rs` — `ScannerService`):** раз в `SCAN_INTERVAL_SECONDS` группирует отслеживаемые субадреса по `account_index` и выполняет чанкованные батч-запросы `get_transfers` размером `SCANNER_SUBADDRESS_BATCH_SIZE` (по умолчанию `100`, лимит `1..=1000` для защиты от превышения лимита ответа RPC `16 MiB`), дедуплицирует транзакции между `pool` и `in` (приоритет у `in`) без двойного учёта кросс-батч транзакций, fail-closed отменяет цикл при сбое любого батча до записи в БД, исключает выходы с `double_spend_seen = true`, обновляет таблицы `invoices`, `invoice_transfers`, `subaddress_transfers`, обнаруживает реорганизации (reorg), поздние платежи (`LATE_PAYMENT`), переплаты (`OVERPAYMENT`) и при `ENABLE_AUTO_SWEEP=true` запускает изолированный `sweep_all` под per-invoice мьютексом.
- **Границы архитектуры и приватность `order_id`:**
  - **Single-instance SQLite / single-merchant:** шлюз рассчитан на одного мерчанта в self-hosted развёртывании без сторонних платёжных посредников. Один экземпляр процесса `xmr-gateway` обслуживает одну БД SQLite и один кошелёк `monero-wallet-rpc` (эксклюзивный `<db_path>.lock` не допускает запуск второго процесса на ту же БД).
  - **Непрозрачный `order_id` без PII:** используйте внутренние непрозрачные идентификаторы (`ord_7f9a2c`, UUID), **не** помещайте в `order_id` email, логины, телефоны или имена клиентов — `order_id` попадает в операционные логи, `tx_description` в `monero:` URI и метки субадресов кошелька (`inv_<order_id>`).
- **Диспетчер вебхуков (`src/services/webhook.rs` — `WebhookDispatcher`):** транзакционный outbox (`webhook_deliveries`). Раз в `WEBHOOK_POLL_INTERVAL_SECONDS` забирает до 50 готовых задач и доставляет их параллельно (до `8` одновременных отправок по разным инвойсам, сохраняя строгий порядок внутри одного инвойса).
- **RPC-клиент (`src/rpc/client.rs` — `MoneroRpcClient`):** JSON-RPC 2.0 клиент к `monero-wallet-rpc` (и опциональному `monerod` через `MONERO_DAEMON_RPC_URL`) с поддержкой HTTP Digest (RFC 2617/7616 с кэшированием nonce) и Basic аутентификации и жёстким лимитом размера ответа `16 MiB`.

### 2.2. HTTP API и разделение прав (RBAC)

Проверка ключей выполняется в `src/api/middleware.rs` за константное время через SHA-256 пре-хэширование и `subtle::ConstantTimeEq` (исключая утечку длины ключа по времени ответа).

| Метод и путь                                        | Аутентификация                                                                                                | Назначение                                                                                                                                                                                                                                                                             |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /health`                                       | Публичный (или `X-API-Key` / `X-Operator-Key` для диагностики, `AUDIT-002`)                                   | Без ключа возвращает только `{"status":"ok"\|"degraded"\|"unhealthy"}`. С валидным `X-API-Key` (мерчантский или операторский ключ) либо `X-Operator-Key` (`OPERATOR_API_KEY`, а в single-tenant режиме — `API_SECRET_KEY`; при заданном `OPERATOR_API_KEY` мерчантский ключ в `X-Operator-Key` не даёт телеметрию) добавляет `service`, `version`, `database`, `monero_rpc` (`connected`, `version`, `error`) и `auto_sweep_enabled`. |
| `POST /api/v1/invoices`                             | `X-API-Key` (`API_SECRET_KEY` или `OPERATOR_API_KEY`)                                                         | Создаёт новый изолированный субадрес (`create_address`), формирует `monero:` URI и PNG QR-код (`qr_code_base64`). Идемпотентен по `order_id`: повтор с теми же `amount_piconero`, `ttl_seconds`, `callback_url` возвращает `200 OK`; расхождение параметров возвращает `409 Conflict`. |
| `GET /api/v1/invoices/{invoice_id}`                 | `X-API-Key`                                                                                                   | Возвращает детальный статус инвойса, список входящих `transfers` и журнал исходящих попыток `sweep_attempts`.                                                                                                                                                                          |
| `POST /api/v1/invoices/{invoice_id}/sweep`          | `X-Operator-Key` или `X-API-Key` (если задан `OPERATOR_API_KEY`, требуется именно он; иначе `API_SECRET_KEY`) | Ручной запуск свипа подтверждённого разблокированного субадреса или невыведенных переплат/поздних платежей.                                                                                                                                                                            |
| `POST /api/v1/invoices/{invoice_id}/sweep/resolve`  | Оператор (`OPERATOR_API_KEY` при его наличии)                                                                 | Ручное разрешение блокирующего инцидента `SWEEP_REORG_DETECTED` / `SWEEP_AMBIGUOUS_TIMEOUT` (`action`: `"allow_resweep"` или `"mark_reconciled"`).                                                                                                                                     |
| `POST /api/v1/invoices/{invoice_id}/webhooks/retry` | Оператор (`OPERATOR_API_KEY` при его наличии, `AUDIT-002`)                                                    | Атомарно (`BEGIN IMMEDIATE`) сбрасывает **только `FAILED`** вебхуки указанного инвойса в `PENDING` (`attempts = 0`), не затрагивая уже находящиеся в очереди/повторе `PENDING` и `DELIVERED` записи; возвращает строго число/UUID переведённых `FAILED`-записей.                           |
| `POST /api/v1/webhooks/{webhook_id}/retry`          | Оператор (`OPERATOR_API_KEY` при его наличии, `AUDIT-002`)                                                    | Атомарно (`BEGIN IMMEDIATE`) сбрасывает одну `FAILED`-запись `webhook_deliveries` по её UUID (для `PENDING` и `DELIVERED` возвращает `409 Conflict`).                                                                                                                                   |

> Если `OPERATOR_API_KEY` задан, обращение с обычным мерчантским `API_SECRET_KEY` к операторским маршрутам возвращает `403 Forbidden`.

### 2.3. Жизненный цикл инвойса и подтверждения

Каждый инвойс получает собственный субадрес (`account_index = 0`, уникальный `address_index`), что исключает смешивание платежей разных заказов.

```text
                       (частичная оплата)
                  +-------------------------> UNDERPAID -------------------------+
                  |                               |                              |
                  |                               v (набрана полная сумма)       | (истёк TTL без полной оплаты)
PENDING ----------+-----------------------------> MEMPOOL (0-conf, не истекает)  +---> EXPIRED
                  |                               |                                     (поздний платёж -> LATE_PAYMENT;
                  |                               v (>= 1 блок, < REQUIRED_CONF)         статус остаётся EXPIRED)
                  |                           CONFIRMING
                  |                               |
                  |                               v (>= REQUIRED_CONFIRMATIONS)
                  |                           CONFIRMED
                  |                               |
                  |                               v (>= SETTLEMENT_CONFIRMATIONS, >= 10 блоков и unlocked)
                  |                            SETTLED
                  |                               |
                  |             +-----------------+-----------------+
                  |             | (ENABLE_AUTO_SWEEP=false)         | (ENABLE_AUTO_SWEEP=true)
                  |             v (после 2xx на SETTLED webhook)    v (после sweep_all)
                  |         COMPLETED                             SWEPT
                  |             |                                   |
                  |             +------- (глубокий reorg) ----------+----> REORGED (reorg_epoch++)
```

Ключевые правила машины состояний (`src/domain/invoice.rs`):
- **`MEMPOOL` не истекает по TTL:** как только в мемпуле видна полная сумма (`received_piconero >= amount_piconero`), инвойс не переходит в `EXPIRED` во время ожидания включения в блок.
- **Двухуровневые подтверждения:**
  - `REQUIRED_CONFIRMATIONS` (минимум `1`, по умолчанию `10`) — порог перехода в `CONFIRMED` и отправки вебхука `CONFIRMED`.
  - `SETTLEMENT_CONFIRMATIONS` (минимум `REQUIRED_CONFIRMATIONS`, по умолчанию `max(REQUIRED_CONFIRMATIONS, 10)`) — порог финальности (`SETTLED`). Переход `CONFIRMED -> SETTLED` и удержание `SETTLED`/`COMPLETED` требуют, чтобы покрывающее множество **разблокированных** (`!in_pool && unlocked`) выходов покрывало сумму инвойса на глубине `>= SETTLEMENT_CONFIRMATIONS` (`XMR-AUDIT-001`): транзакции с кастомным длинным `unlock_time` не могут преждевременно стать `SETTLED`/`COMPLETED`, а поздний мемпульный dust в 1 пиконеро не сбрасывает уже оплаченный инвойс в `REORGED`.
  - Константа протокола Monero `MONERO_UNLOCK_CONFIRMATIONS = 10`: вывод `sweep_all` возможен только когда выходы набрали `>= max(SETTLEMENT_CONFIRMATIONS, 10)` подтверждений и `locked = false`.
- **View-Only режим (`ENABLE_AUTO_SWEEP=false`):** успешная `2xx`-доставка вебхука `SETTLED` атомарно переводит инвойс из `SETTLED` в `COMPLETED`. При этом `COMPLETED` продолжает мониториться на глубокий reorg: при падении подтверждений/баланса или `double_spend_seen` инвойс переходит в `REORGED`, инкрементирует `reorg_epoch` и отправляет компенсирующий вебхук `REORGED`.
- **Непрерывный мониторинг аномалий (`SUBADDRESS_MONITOR_DAYS`):** по умолчанию `0` (бессрочный мониторинг). Подтверждённые поступления на уже `EXPIRED` субадрес регистрируются в `subaddress_transfers` как `LATE_PAYMENT` (не «воскрешая» заказ из `EXPIRED`), а доплаты сверх суммы после подтверждения/свипа — как `OVERPAYMENT`.

### 2.4. Движок автосвипа и восстановление инцидентов

В режиме `ENABLE_AUTO_SWEEP=true` (`WALLET_MODE=hot_wallet`):
1. Перед вызовом `monero-wallet-rpc::sweep_all` под per-invoice мьютексом в таблице `sweep_attempts` создаётся запись `PREPARED` со снимком `snapshot_txids_json` разблокированных поступлений (`confirmations >= 10`, `unlocked = 1`).
2. Если `sweep_all` возвращает код из белого списка строго pre-commit ошибок `monero-wallet-rpc` (например, `-17` `NOT_ENOUGH_MONEY`, `-37` `NOT_ENOUGH_UNLOCKED_MONEY`, `-2` `WRONG_ADDRESS`), попытка помечается `FAILED` и может быть безопасно повторена.
3. При любых неоднозначных ошибках (таймаут/обрыв HTTP, пустой/отсутствующий `tx_hash_list`, коды `-4`, `-38`, `-3`, `-1`, `-32603`) попытка **fail-closed остаётся в `PREPARED`** и сверяется с `get_transfers(out=true, pending=true)` в течение окна `PREPARED_INDEXING_GRACE_SECS = 60` сек.
4. Если исходящая транзакция не появилась после grace-окна (`SWEEP_AMBIGUOUS_TIMEOUT`), либо исчезла из `out`/`pending`, либо получила `double_spend_seen = true`, попытка переходит в `REORGED` (`SWEEP_REORG_DETECTED`), повторный `sweep_all` жёстко блокируется до ручного разрешения через `POST /api/v1/invoices/{invoice_id}/sweep/resolve`:
   - `action = "allow_resweep"` требует `confirm_absent_on_chain = true`, непустой `operator_note`, сверку синхронизации кошелька и демона (`MONERO_DAEMON_RPC_URL` обязателен!) и подтверждение отсутствия живых исходящих транзакций с этого субадреса.
   - `action = "mark_reconciled"` требует строгий 64-hex `replacement_tx_hash` (или сохранённые хэши попытки), fail-closed проверку, что все положительные выходы в `destinations` идут строго на `COLD_WALLET_ADDRESS`, защиту от dust-сумм и атомарную (`BEGIN IMMEDIATE`) проверку уникальности `tx_hash` между инвойсами.

### 2.5. Вебхуки, подпись `X-Webhook-Signature` / `X-Signature-256` и политика повторов

События (`WebhookEventType`): `UNDERPAID`, `MEMPOOL`, `CONFIRMED`, `SETTLED`, `REORGED`, `SWEPT`, `EXPIRED`, `LATE_PAYMENT`, `OVERPAYMENT`.

Бизнес-событие (`event_id` и байты JSON-тела) сериализуется один раз при записи в SQLite и остаётся **неизменным** между всеми ретраями для идемпотентной дедупликации на стороне мерчанта. При **каждой попытке доставки** (первичная отправка, автоматический экспоненциальный retry и ручной операторский `webhooks retry`) диспетчер генерирует свежий `X-Webhook-Timestamp` (Unix epoch seconds) и на лету вычисляет `X-Webhook-Signature = HMAC-SHA256(WEBHOOK_SECRET, "{X-Webhook-Timestamp}.{raw_body}")` — благодаря этому ретраи после простоя сервера мерчанта проходят строгую проверку свежести подписи (`<= 300s`):

| Заголовок | Значение |
|---|---|
| `Content-Type` | `application/json` |
| `User-Agent` | `xmr-gateway/0.1.5` |
| `X-Webhook-Timestamp` | Свежий Unix epoch timestamp (секунды) текущей попытки доставки (обновляется при каждом retry) |
| `X-Webhook-Signature` | **Рекомендуемая основная подпись:** lowercase hex `HMAC-SHA256(WEBHOOK_SECRET, "{X-Webhook-Timestamp}.{raw_body}")` |
| `X-Webhook-Event-Id` | Стабильный UUID бизнес-события (`payload.event_id`, неизменен между ретраями для идемпотентности) |
| `X-Delivery-Id` | Обратно совместимый алиас `X-Webhook-Event-Id` (`webhook_deliveries.id`) |
| `X-Signature-256` | Обратно совместимая подпись тела `HMAC-SHA256(WEBHOOK_SECRET, raw_body_bytes)` |
| `X-Webhook-Event` | Имя события (`MEMPOOL`, `CONFIRMED`, `SETTLED`, `SWEPT`, `REORGED`, `EXPIRED`, `UNDERPAID`, `LATE_PAYMENT`, `OVERPAYMENT`) |

> [!NOTE]
> **Эксплуатационные причины ложных `REORGED` и `OVERPAYMENT`:**
> - **Ложный `REORGED` при приёме платежей до завершения синхронизации кошелька (`lag > 0`):** даже если `wallet_height` отстаёт от `daemon_height`, `monero-wallet-rpc` сразу видит 0-conf транзакцию в мемпуле (`pool`), и шлюз отправляет вебхук `MEMPOOL`. Когда транзакция включается в блок выше текущего `wallet_height`, она исчезает из `pool`, но ещё не появляется в `in` — сканер fail-closed переводит инвойс в `REORGED` (`reorg_epoch + 1`) и шлёт вебхук `REORGED`. Когда кошелёк догонит сеть (`lag=0`), инвойс автоматически восстановится в `CONFIRMED` / `SETTLED` / `COMPLETED`. Чтобы исключить ложные `REORGED`, открывайте трафик строго после `lag=0` в `config doctor` (`wallet_daemon_sync`).
> - **Мгновенный `CONFIRMED` / `COMPLETED` / `OVERPAYMENT` на только что созданном инвойсе без оплаты:** возникает при подключении к новой или очищенной БД `xmr_gateway.db` уже использовавшегося кошелька с историей входящих переводов на субадресах (`account=0, index=1, 2...`). Всегда используйте выделенный чистый кошелёк.

- **Контракт проверки на стороне получателя:**
  1. Проверить окно свежести `abs(now_unix - int(X-Webhook-Timestamp)) <= 300` сек.
  2. Проверить `X-Webhook-Signature` в constant-time по строке `f"{X-Webhook-Timestamp}.".encode() + raw_body` с ключом `WEBHOOK_SECRET`.
  3. Выполнять идемпотентную дедупликацию по `event_id` (`X-Webhook-Event-Id`), чтобы повторная доставка не привела к двойному зачислению.
- **Таймауты и чтение ошибок:** connect `5s`, общий таймаут `10s`, HTTP `3xx` редиректы запрещены (`redirect::Policy::none()`), при неуспешном ответе читается не более `1024` байт тела ответа.
- **Ретраи:** максимум `10` попыток (`DEFAULT_WEBHOOK_MAX_ATTEMPTS`), экспоненциальная задержка `5s * 2^(attempt - 1)` с потолком `3600s` (1 час): `5s -> 10s -> 20s -> 40s -> 80s -> 160s -> 320s -> 640s -> 1280s -> 2560s`. После исчерпания попыток статус становится `FAILED` (ручной `webhooks retry` также формирует свежий `X-Webhook-Timestamp` и новую `X-Webhook-Signature`).

---

## 3. Автоматические bash-скрипты и сценарии запуска

В корне репозитория находятся два исполняемых bash-скрипта: `start.sh` и `demo-stagenet.sh`. Оба устанавливают строгий режим `set -euo pipefail`, перехватывают `SIGINT`/`SIGTERM`/`EXIT` и корректно завершают дочерние процессы.

### 3.1. Оркестратор `start.sh`

`start.sh` (624 строки, `umask 077`) автоматизирует полный цикл bare-metal запуска на Linux (Fedora / Debian и др.):

1. **Поддерживаемые флаги:**
   - `./start.sh` — полный запуск: инициализация `.env` и кошелька, старт `monero-wallet-rpc`, сборка `--release` (если бинарник отсутствует или исходники/миграции новее `target/release/xmr-gateway`), запуск `xmr-gateway`.
   - `./start.sh --setup-rpc` — скачать и проверить по SHA-256 (или GPG-подписи `binaryFate`, отпечаток `81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92`, если задана нестандартная версия без `MONERO_CLI_SHA256`) официальный архив Monero CLI (`monero-linux-x64-v0.18.5.4.tar.bz2`, только Linux `x86_64`), извлечь `monero-wallet-rpc` и `monero-wallet-cli` в `./bin/` (`chmod 755`) и выйти.
   - `./start.sh --init-wallet-only` — подготовить `.env`, проверить бинарники и создать файлы кошелька в `./data/wallet/`, затем выйти без запуска серверов.
   - `./start.sh -h` / `./start.sh --help` — краткая справка.
2. **Инициализация `.env`:** если `.env` отсутствует, копирует `.env.example` с правами `0600`. Если `API_SECRET_KEY`, `WEBHOOK_SECRET` или `MONERO_RPC_PASS` пустые или начинаются с `replace-with-` / `changeme`, скрипт автоматически генерирует их через `openssl rand -hex 32` (и `24` байта для `MONERO_RPC_PASS`).
3. **Инициализация кошелька (`./data/wallet/gateway_wallet`):**
   - Создаёт пароль кошелька `./data/wallet/gateway_wallet.password` (`chmod 600`, `openssl rand -hex 24`).
   - При `WALLET_MODE=view_only`: требует `MONERO_VIEW_ONLY_ADDRESS` и `MONERO_VIEW_ONLY_KEY` в `.env`, вызывает `monero-wallet-cli --offline --generate-from-view-key` (при `MONERO_NETWORK=stagenet` добавляет `--stagenet`).
   - При `WALLET_MODE=hot_wallet`: вызывает `monero-wallet-cli --offline --generate-new-wallet` и выводит 25-словную seed-фразу в терминал (обязательно сохранить!).
4. **Запуск `monero-wallet-rpc`:**
   - Извлекает порт из `MONERO_RPC_URL` (по умолчанию `18082`) и проверяет его свободность через `ss -ltn`.
   - Запускает `monero-wallet-rpc` строго на `127.0.0.1:<rpc_port>` с флагами `--non-interactive`, `--no-initial-sync`, `--rpc-login ${MONERO_RPC_USER}:${MONERO_RPC_PASS}`, `--daemon-address ${MONERO_REMOTE_NODE}`, `--untrusted-daemon` (или `--trusted-daemon` при `MONERO_TRUSTED_DAEMON=true`), `--stagenet` (для `stagenet`), опционально `--proxy ${MONERO_RPC_PROXY}`.
   - Ждёт готовности до 60 секунд (120 попыток по `0.5s`, запрос `get_version` с Digest-авторизацией).
   - Сразу проверяет режим кошелька вызовом `query_key({"key_type":"spend_key"})` — при несоответствии `WALLET_MODE` аварийно завершается до запуска `xmr-gateway`.
5. **Сборка и запуск `xmr-gateway`:** при необходимости запускает `cargo build --release` и стартует `./target/release/xmr-gateway`.

> [!WARNING]
> **Два обязательных правила перед открытием боевого приёма платежей** (подробно в [DEPLOY_RU.md](DEPLOY_RU.md#32-настройка-etcxmr-gatewayenv-и-инициализация-кошелька) и [admin/GUIDE_RU.md](admin/GUIDE_RU.md)):
> 1. **Не открывайте приём платежей при `lag > 0`:** после создания, импорта (`view_only`) или пересканирования (`rescan`) кошелька дождитесь полной синхронизации (`lag=0`). Пока `wallet_height < daemon_height`, платежи видны в мемпуле (`pool` $\rightarrow$ `MEMPOOL`), но в момент включения в блок пропадают из `pool` до того, как кошелёк досканирует до этого блока (`in`), что вызывает fail-closed переход в `REORGED` и отправку **ложного вебхука `REORGED`** (средства не теряются и статус автоматически восстановится при `lag=0`, но ложный `REORGED` может нарушить логику заказов). Команда проверки:
>    `./admin.sh config doctor` (или `sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config doctor | grep wallet_daemon_sync`) $\rightarrow$ `[PASS] wallet_daemon_sync ... (lag=0, daemon_synchronized=true)`.
> 2. **Всегда используйте выделенный чистый кошелёк (не подключайте кошелёк с историей к новой БД):** субадреса Monero детерминированы (`account=0, index=1, 2, 3...`). Чистая база `xmr_gateway.db` выдаёт субадреса начиная с `index=1`: если на этих субадресах кошелька уже были старые входящие переводы, сканер засчитает их в счёт новых инвойсов и автоматически закроет заказы (`CONFIRMED` / `COMPLETED` + `OVERPAYMENT`) без реальной оплаты. Никогда не удаляйте `xmr_gateway.db`, оставляя старый кошелёк, и всегда восстанавливайте кошелёк и БД вместе из согласованного бэкапа.

### 3.2. Интерактивное демо `demo-stagenet.sh`

`demo-stagenet.sh` (358 строк, аргументов CLI не принимает) поднимает в **одном терминале** полную тестовую среду Stagenet с цветными префиксами логов (`[DEMO]`, `[RPC]`, `[GATEWAY]`, `[WEBHOOK]`):

1. Вызывает `./start.sh --init-wallet-only` для гарантии наличия `.env`, бинарников и кошелька.
2. Загружает `.env`, но **принудительно переопределяет в окружении процесса**:
   - `MONERO_NETWORK="stagenet"`
   - `HOST="127.0.0.1"`, `PORT="8080"`
   - `MONERO_RPC_URL="http://127.0.0.1:18082/json_rpc"`
   - `LOG_FORMAT="pretty"`
   - `ALLOW_PRIVATE_WEBHOOKS="${ALLOW_PRIVATE_WEBHOOKS:-true}"`
   - `MONERO_REMOTE_NODE` по умолчанию `node.monerodevs.org:38089` (если не задан в `.env`).
3. Проверяет через `ss -ltn`, что порты **`18082`**, **`8080`** и **`9000`** свободны.
4. Запускает `monero-wallet-rpc --stagenet` на `127.0.0.1:18082` и транслирует `data/monero-wallet-rpc.log` с префиксом `[RPC]`.
5. Запускает встроенный Python HTTP-сервер на `127.0.0.1:9000` (`/webhooks/monero`), который проверяет подпись `X-Signature-256` через `hmac.compare_digest` против `WEBHOOK_SECRET` и печатает проверенные события с префиксом `[WEBHOOK]`.
6. Запускает `./target/release/xmr-gateway` на `127.0.0.1:8080` и ждёт `GET /health` -> `"status":"ok"` (до 30 секунд).
7. Создаёт тестовый инвойс через `POST /api/v1/invoices` на **`0.005 XMR` (`5000000000` piconero)** с `order_id = "stagenet_demo_1"` (при `409` добавляет Unix timestamp) и `callback_url = "http://127.0.0.1:9000/webhooks/monero"`.
8. Декодирует `qr_code_base64` в файл `/tmp/stagenet_qr.png`, выводит в терминал `Invoice ID`, `Subaddress`, `Monero URI` и остаётся работать до нажатия `Ctrl+C`.

> **Важно:** если в вашем `.env` указан `MONERO_REMOTE_NODE=xmr-node.cakewallet.com:18081` (mainnet-нода из `.env.example`), `demo-stagenet.sh` унаследует его из `.env`, потому что использует `: "${MONERO_REMOTE_NODE:=node.monerodevs.org:38089}"`. Для Stagenet задайте в `.env` stagenet-ноду (например, `MONERO_REMOTE_NODE=node.monerodevs.org:38089`) либо уберите mainnet-значение перед запуском демо.

### 3.3. Сводная таблица скриптов, портов и файлов

| Скрипт / Инструмент | Порты (localhost) | Основные файлы и артефакты | Назначение |
|---|---|---|---|
| `./start.sh` | `18082` (или из `MONERO_RPC_URL`), `8080` (или `PORT`) | `.env`, `bin/monero-wallet-{rpc,cli}`, `data/wallet/gateway_wallet*`, `data/monero-wallet-rpc.log`, `data/monero-wallet-cli.log`, `data/xmr_gateway.db*`, `target/release/xmr-gateway` | Боевой/локальный bare-metal запуск `monero-wallet-rpc` + `xmr-gateway` |
| `./start.sh --setup-rpc` | — | `bin/monero-wallet-rpc`, `bin/monero-wallet-cli` | Загрузка и SHA-256/GPG-проверка официального Monero CLI `v0.18.5.4` |
| `./start.sh --init-wallet-only` | — | `.env`, `data/wallet/gateway_wallet*` | Инициализация `.env` и кошелька без запуска демонов |
| `./demo-stagenet.sh` | `18082` (RPC), `8080` (API), `9000` (Python webhook listener) | Всё из `start.sh` + `/tmp/stagenet_qr.png` | Однотерминальная живая демонстрация полного цикла оплаты на Stagenet |
| `./admin.sh` | Использует порты и пути из `--env` (по умолчанию `.env`) | `admin/*.sh`, `admin/lib/common.sh`, `data/pids/*.pid`, `data/xmr-gateway.log`, `data/backups/*` | Интерактивное меню и скриптовый CLI для полного администрирования сервисов, кошельков, инвойсов, вебхуков, БД и проверок безопасности |

### 3.4. Остановка процессов и очистка артефактов

- **Штатная остановка:** нажмите `Ctrl+C` (`SIGINT`) или отправьте `SIGTERM` процессу скрипта.
  - В `start.sh`: сначала отправляется `SIGTERM` процессу `xmr-gateway` (он останавливает HTTP-сервер, завершает воркеры сканера и вебхуков, закрывает SQLite-пул и освобождает `.lock`), затем `SIGTERM` процессу `monero-wallet-rpc` (ожидание до 10 сек, после чего `SIGKILL`).
  - В `demo-stagenet.sh`: поочерёдно останавливаются `xmr-gateway`, Python webhook listener, `tail -F` и `monero-wallet-rpc` (ожидание до 5 сек на каждый, затем `SIGKILL`).
- **Проверка отсутствия «зависших» процессов и занятых портов:**
  ```bash
  ss -ltnp | grep -E ':(8080|18082|9000)\b' || echo "Все порты свободны"
  pgrep -af 'xmr-gateway|monero-wallet-rpc' || echo "Процессы не запущены"
  ```
- **Очистка временных артефактов демо (без потери кошелька и БД):**
  ```bash
  rm -f /tmp/stagenet_qr.png
  ```
- **Полный сброс локального Stagenet-окружения (ОСТОРОЖНО: удаляет тестовый кошелёк и БД, НЕ выполнять на mainnet!):**
  ```bash
  # Убедитесь, что процессы остановлены и это НЕ боевой каталог!
  rm -rf data/xmr_gateway.db* data/monero-wallet-rpc.log data/monero-wallet-cli.log
  # Только если нужно пересоздать тестовый stagenet-кошелёк:
  rm -rf data/wallet/
  ```

### 3.5. Единая админ-панель `./admin.sh` и модули `admin/`

Для повседневного администрирования, диагностики, форензики SQLite и безопасных финансовых операций предусмотрена модульная CLI/интерактивная консоль **`./admin.sh`** (общая библиотека в `admin/lib/common.sh`, модули в `admin/`):

- **Два режима работы и двуязычность (`RU` / `EN`):**
  - `./admin.sh` (без аргументов в терминале) — интерактивное меню по всем 7 разделам с пунктами **`[G]`** (открыть инструкцию) и **`[L]`** (мгновенно переключить язык `RU ↔ EN`).
  - `./admin.sh [--env <path>] [--lang <en|ru>] [--json] [--yes] <module> <command> [args...]` — скриптовый CLI с поддержкой выбора языка (`--lang`, `ADMIN_LANG`, `./admin.sh lang [show|en|ru]` с сохранением в `data/.admin_lang`), строго инвариантного к языку JSON (`--json`), альтернативного конфига (`--env .env.mainnet`) и неинтерактивного подтверждения (`--yes`).
  - **Полные инструкции:** [admin/GUIDE_RU.md](admin/GUIDE_RU.md) (на русском) и [admin/GUIDE_EN.md](admin/GUIDE_EN.md) (in English), а также команда `./admin.sh guide [--path]` прямо из CLI.
- **Инварианты безопасности админ-панели:**
  - Все секреты (`API_SECRET_KEY`, `OPERATOR_API_KEY`, `MONERO_RPC_PASS`, `MONERO_DAEMON_RPC_PASS`) передаются в `curl` строго через `stdin` (`curl --config -`), никогда не попадая в аргументы процесса (`ps aux`).
  - Автоматический выбор RBAC-заголовка: `X-API-Key` для merchant-маршрутов, `X-Operator-Key` (при заданном `OPERATOR_API_KEY`, иначе fallback на `X-API-Key`) для операторских маршрутов (`/sweep`, `/sweep/resolve`, `/retry`).
  - **Защита Mainnet:** при `MONERO_NETWORK=mainnet` перед финансовыми/деструктивными действиями (`transfer`, `sweep`, `sweep-all`, `resolve`, `rotate-keys`, `stop`, `set-mode`, `db shell --rw`) выводится красный баннер `[MAINNET]` с обязательным подтверждением (или `--yes`).
  - Доступ к SQLite выполняется в режиме строгого чтения (`mode=ro`, `PRAGMA query_only = ON`, `busy_timeout = 5000`); горячие бэкапы выполняются через `sqlite3.Connection.backup()` с `chmod 600` и проверкой `PRAGMA integrity_check;`.

| Модуль (`admin/*.sh`) | Команды | Назначение |
|---|---|---|
| `service` (`admin/service.sh`) | `start`, `stop`, `restart`, `status`, `logs [gateway\|rpc\|cli] [-f] [-n N]`, `build`, `setup-rpc`, `systemd [status\|install-dry-run\|restart]` | Жизненный цикл `monero-wallet-rpc` и `xmr-gateway` с PID-файлами, graceful shutdown (`wal_checkpoint(TRUNCATE)`), просмотр логов, сборка и хелпер для `deploy/systemd/`. |
| `config` (`admin/config.sh`) | `show`, `doctor [--strict-live]`, `rotate-keys [api\|operator\|webhook\|rpc\|all]`, `set-mode <view_only\|hot_wallet>` | Просмотр конфига с маскированием секретов, fail-closed диагностика (`0600`, RBAC `API_SECRET_KEY != OPERATOR_API_KEY`, режим кошелька, SSRF, `/health`, синхронизация высот), ротация секретов с бэкапом `0600` и безопасное переключение режима. |
| `wallet` (`admin/wallet.sh`) | `info` / `balance`, `transfers [in\|out\|pool\|pending\|all]`, `refresh`, `set-height <h>`, `rescan`, `create-hot`, `create-view-only`, `export-view-keys`, `transfer <addr> <xmr> [prio]`, `sweep-all <addr> [idx] [prio]`, `cli` | Полное управление hot и view-only кошельками; `transfer` и `sweep-all` используют точную десятичную конвертацию в пиконеро и fail-closed блокируются в режиме `view_only`. |
| `invoices` (`admin/invoices.sh`) | `create`, `get <id>`, `list [--status ...] [--order-id ...] [--limit N]`, `inspect <id>`, `sweep <id>`, `resolve <id> <allow_resweep\|mark_reconciled> --note ...` | Создание и просмотр инвойсов через REST API, форензика по всем таблицам SQLite, ручной свип и разрешение инцидентов `REORGED` (`XMR-041` / `AUDIT-001` / `AUDIT-004`). |
| `webhooks` (`admin/webhooks.sh`) | `list`, `inspect <id>`, `retry <id>`, `retry-invoice <invoice_id>`, `verify-sig <sig> [file\|-]`, `test-receiver [port]` | Диагностика очереди `webhook_deliveries`, операторский retry строго `FAILED`-записей (`AUDIT-002`), проверка `X-Signature-256` и встроенный локальный HMAC-приёмник. |
| `db` (`admin/db.sh`) | `stats`, `audit-invariants`, `backup [dest_dir]`, `shell [--rw]` | Сводка по статусам/суммам XMR и размерам `.db`/`-wal`/`-shm`, fail-closed аудит `PRAGMA integrity_check` + инварианта баланса `AUDIT-005` + зависших свипов, безопасный онлайн-бэкап `0600` и SQLite-консоль (RO по умолчанию). |
| `dev` (`admin/dev.sh`) | `check`, `health-rbac`, `demo` | Прогон `fmt`/`clippy`/`cargo test`, живая проверка RBAC-матрицы `GET /health` (`AUDIT-002`) и запуск `./demo-stagenet.sh`. |
| `lang` / `guide` (`admin.sh`) | `lang [show\|en\|ru]`, `guide [--path]` | Показ/переключение языка интерфейса (`RU`/`EN`) с сохранением в `data/.admin_lang` (`0600`) и просмотр встроенного руководства `admin/GUIDE_RU.md` / `admin/GUIDE_EN.md`. |

**Примеры использования и самопроверка админ-панели:**
```bash
./admin.sh                                      # Интерактивное меню (с переключением RU/EN)
./admin.sh lang ru                              # Сохранить русский язык интерфейса
./admin.sh guide                                # Открыть полное руководство (admin/GUIDE_RU.md)
./admin.sh config doctor                        # Fail-closed аудит конфигурации и прав
./admin.sh --json db audit-invariants           # Проверка целостности БД и инварианта AUDIT-005
./admin.sh db backup                            # Горячий онлайн-бэкап (0600 + integrity_check)
./admin.sh dev health-rbac                      # Живая проверка матрицы RBAC на GET /health
./admin/test_admin.sh                           # Изолированные автотесты самой админ-панели
```

---

## 4. Настройка `.env` и переменных окружения

`xmr-gateway` загружает `.env` через `dotenvy::dotenv()` (`src/main.rs:34`), причём переменные окружения текущей оболочки **всегда имеют приоритет** над `.env`. Булевы переменные принимают `true`/`1`/`yes` и `false`/`0`/`no` (регистронезависимо, `src/config.rs:951`).

### 4.1. HTTP-сервер и SQLite

| Переменная | Тип | По умолчанию | Обязательна | Описание и пример |
|---|---|---|---|---|
| `HOST` | IP / string | `127.0.0.1` | Нет | Интерфейс прослушивания HTTP API. Оставляйте `127.0.0.1` за обратным прокси (Caddy/Nginx). |
| `PORT` | `u16` | `8080` | Нет | TCP-порт REST API. Вместе с `HOST` проверяется как валидный `SocketAddr`. |
| `CORS_ALLOWED_ORIGINS` | CSV string | `""` (отключён) | Нет | Список разрешённых Origin через запятую (`https://shop.example.com`) или `*`. Пустое значение отключает кросс-доменный доступ из браузера. |
| `DATABASE_URL` | URI string | `sqlite://data/xmr_gateway.db` | Нет | Строка подключения SQLite. Родительская директория создаётся автоматически (`0700`), файлы `.db`/`-wal`/`-shm` и `.lock` получают права `0600`. Для тестов поддерживается `sqlite::memory:`. |

### 4.2. Авторизация API и вебхуки

| Переменная | Тип | По умолчанию | Обязательна | Описание и пример |
|---|---|---|---|---|
| `API_SECRET_KEY` | string (`>= 32` байт) | — | **Да** | Секрет для заголовка `X-API-Key`. Запрещены плейсхолдеры `replace-with-*`, `changeme*`, `example-*`. Генерация: `openssl rand -hex 32`. |
| `OPERATOR_API_KEY` | string (`>= 32` байт) | `None` | **Да** в `hot_wallet`; нет в `view_only` | Отдельный ключ (обязательно отличающийся от `API_SECRET_KEY`, `AUDIT-002` / `XMR-AUDIT-004`) для операторских маршрутов (`/sweep`, `/sweep/resolve`, `/webhooks/{id}/retry`, `/invoices/{id}/webhooks/retry`) и диагностики `GET /health`. **Обязателен** при `WALLET_MODE=hot_wallet` или `ENABLE_AUTO_SWEEP=true`; в `view_only` при отсутствии ключа сохраняется fallback на `API_SECRET_KEY`. |
| `WEBHOOK_SECRET` | string (`>= 32` байт) | — | **Да** | Общий секрет для расчёта подписи `HMAC-SHA256` в заголовке `X-Signature-256`. Генерация: `openssl rand -hex 32`. |
| `DEFAULT_WEBHOOK_URL` | HTTP/HTTPS URL | `None` | Нет | URL вебхука по умолчанию, если в `POST /api/v1/invoices` не передан `callback_url`. Валидируется (включая DNS) прямо на старте сервиса. |
| `ALLOW_PRIVATE_WEBHOOKS` | `bool` | `false` | Нет | Разрешает отправку вебхуков на loopback (`127.0.0.0/8`, `::1`), RFC1918, link-local (`169.254.169.254`), `.localhost`/`.local`/`.internal`. В продакшене строго `false`; для локального бота/демо — `true`. |
| `REQUIRE_HTTPS_WEBHOOKS` | `bool` | `true` на `mainnet` при `ALLOW_PRIVATE_WEBHOOKS=false`; иначе `false` | Нет | На `mainnet` при `ALLOW_PRIVATE_WEBHOOKS=false` публичные HTTP-вебхуки **строго запрещены (fail-closed на старте и `FAIL` в `config doctor`, `XMR-AUDIT-006`)**; если переменная не задана, по умолчанию используется `true`. На `stagenet`/`testnet` или при `ALLOW_PRIVATE_WEBHOOKS=true` (локальный бот на `127.0.0.1`) HTTP остаётся разрешённым. |

### 4.3. Сеть Monero, RPC кошелька и демона

| Переменная | Тип | По умолчанию | Обязательна | Описание и пример |
|---|---|---|---|---|
| `MONERO_NETWORK` | enum | `mainnet` | Нет | Целевая сеть: `mainnet`, `stagenet` или `testnet` (`start.sh` поддерживает `mainnet` и `stagenet`). Используется также при проверке `nettype` в `verify_wallet_synced()`. |
| `MONERO_RPC_URL` | HTTP/HTTPS URL | `http://127.0.0.1:18082/json_rpc` | Нет | Endpoint локального `monero-wallet-rpc`. Для не-loopback хостов `http://` запрещён без `ALLOW_INSECURE_REMOTE_RPC=true`. |
| `MONERO_RPC_USER` | string | `None` (`xmr_gateway_user` в `start.sh`) | **Да** (при `ALLOW_UNAUTHENTICATED_RPC=false`) | Логин HTTP Digest/Basic для `monero-wallet-rpc` (передаётся через `0600` `--config-file`, без утечки в `argv`, `XMR-AUDIT-005`). Должен задаваться парой с `MONERO_RPC_PASS`. |
| `MONERO_RPC_PASS` | string (`>= 16` симв.) | `None` | **Да** (при `ALLOW_UNAUTHENTICATED_RPC=false`) | Пароль для `monero-wallet-rpc` (`rpc-login=...` в `0600` `--config-file`). Не может совпадать с логином, содержать переносы строк, быть короче 16 символов или равняться слабым значениям (`password`, `admin`, `123456`, `monero`, `replace-with-*`, `changeme*`, `example-*`). |
| `MONERO_DAEMON_RPC_URL` | HTTP/HTTPS URL | `None` | Для `allow_resweep` | URL JSON-RPC узла `monerod` (например `http://127.0.0.1:18081/json_rpc` или stagenet `:38081/json_rpc`). Требуется для fail-closed проверки синхронизации `get_height` vs `get_info` при `POST .../sweep/resolve` (`action=allow_resweep`). |
| `MONERO_DAEMON_RPC_USER` | string | `None` | Если задан `MONERO_DAEMON_RPC_URL` и `ALLOW_UNAUTHENTICATED_RPC=false` | Логин для `MONERO_DAEMON_RPC_URL`. Нельзя задавать без `MONERO_DAEMON_RPC_URL` и без пароля. |
| `MONERO_DAEMON_RPC_PASS` | string (`>= 16` симв.) | `None` | Если задан `MONERO_DAEMON_RPC_URL` и `ALLOW_UNAUTHENTICATED_RPC=false` | Пароль для `MONERO_DAEMON_RPC_URL` (действуют те же правила сложности, что и для `MONERO_RPC_PASS`). |
| `ALLOW_UNAUTHENTICATED_RPC` | `bool` | `false` | Нет | Разрешает запуск без `MONERO_RPC_USER`/`PASS` (только для изолированных тестов; в `start.sh` и `demo-stagenet.sh` логин/пароль всё равно обязательны). |
| `ALLOW_INSECURE_REMOTE_RPC` | `bool` | `false` | Нет | Разрешает незашифрованный `http://` к не-loopback RPC-хостам. В продакшене держите `false` (используйте `https://` или SSH/WireGuard туннель на `127.0.0.1`). |
| `MONERO_TRUSTED_DAEMON` | `bool` | `false` | Нет | Управляет флагом `--trusted-daemon` vs `--untrusted-daemon` в `start.sh`/`demo-stagenet.sh`. Ставьте `true` **только** для собственного `monerod`. |

### 4.4. Режим кастодиальности и автосвип

| Переменная | Тип | По умолчанию | Обязательна | Описание и пример |
|---|---|---|---|---|
| `WALLET_MODE` | enum | `view_only` (если `ENABLE_AUTO_SWEEP=false`) / `hot_wallet` (если `true`) | Нет | Режим кошелька: `view_only` (`view-only`) или `hot_wallet` (`hot-wallet`). Проверяется на старте живым запросом `query_key(spend_key)` к `monero-wallet-rpc`. |
| `ENABLE_AUTO_SWEEP` | `bool` | `false` | Нет | `false` = View-Only Zero-Trust режим; `true` = Hot Auto-Sweep режим (автоматический `sweep_all` на `COLD_WALLET_ADDRESS` после разблокировки). |
| `ALLOW_HOT_WALLET_WITHOUT_SWEEP` | `bool` | `false` | Нет | Явное подтверждение оператора на запуск `WALLET_MODE=hot_wallet` при `ENABLE_AUTO_SWEEP=false` (например, для ручного тестирования на Stagenet). |
| `COLD_WALLET_ADDRESS` | Monero address (`95`/`106` симв.) | `None` | **Да** при `ENABLE_AUTO_SWEEP=true` | Адрес холодного кошелька для авто- и ручного свипа. Проходит чистую Rust-проверку Base58 + Keccak-256 checksum и живой RPC `validate_address` на старте. |
| `SWEEP_PRIORITY` | `u32` (`0..=4`) | `0` | Нет | Приоритет комиссии Monero для `sweep_all`: `0` (default), `1` (unimportant), `2` (normal), `3` (elevated), `4` (priority). Значения `> 4` отклоняются. |

### 4.5. Подтверждения, таймауты, интервалы и логирование

| Переменная | Тип | По умолчанию | Обязательна | Описание и пример |
|---|---|---|---|---|
| `REQUIRED_CONFIRMATIONS` | `u64` (`>= 1`) | `10` | Нет | Минимум подтверждений в блоках для перехода инвойса в `CONFIRMED` (`0` запрещено, 0-conf отслеживается как `MEMPOOL`). |
| `SETTLEMENT_CONFIRMATIONS` | `u64` (`>= REQUIRED_CONFIRMATIONS`) | `max(REQUIRED_CONFIRMATIONS, 10)` | Нет | Порог подтверждений для финальности `SETTLED` (для крупных сумм на mainnet можно задать, например, `15`). |
| `SUBADDRESS_MONITOR_DAYS` | `u64` | `0` | Нет | Окно (в днях) мониторинга терминальных субадресов (`COMPLETED`/`SWEPT`/`EXPIRED`). `0` = непрерывный бессрочный мониторинг всех неархивных субадресов. |
| `INVOICE_TTL_SECONDS` | `u64` (`>= 1`) | `3600` | Нет | Время жизни нового инвойса по умолчанию (в секундах; 3600 = 1 час). В API допустим per-invoice `ttl_seconds` до `2592000` (30 дней). |
| `SCAN_INTERVAL_SECONDS` | `u64` (`>= 1`) | `10` | Нет | Интервал опроса `monero-wallet-rpc` фоновым сканером (в секундах). |
| `SCANNER_SUBADDRESS_BATCH_SIZE` | `usize` (`1..=1000`) | `100` | Нет | Максимальное число субадресов в одном батче `get_transfers` (исключает превышение лимита ответа RPC `16 MiB` при росте числа инвойсов). |
| `WEBHOOK_POLL_INTERVAL_SECONDS` | `u64` (`>= 1`) | `5` | Нет | Интервал опроса таблицы `webhook_deliveries` фоновым диспетчером (в секундах). |
| `RUST_LOG` | `EnvFilter` string | `info,xmr_gateway=debug` | Нет | Директивы фильтрации логов `tracing` (например, `info,xmr_gateway=debug,sqlx=warn`). |
| `LOG_FORMAT` | enum | `json` | Нет | Формат вывода логов: `json` (структурированный JSON для продакшена) или `pretty` (читаемый формат для локальной отладки). |

### 4.6. Переменные скрипта `start.sh` (bootstrap и загрузка CLI)

Эти переменные читаются непосредственно `start.sh` / `demo-stagenet.sh` (но не самим Rust-бинарником `xmr-gateway`):

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `MONERO_REMOTE_NODE` | `xmr-node.cakewallet.com:18081` (`start.sh`) / `node.monerodevs.org:38089` (`demo-stagenet.sh`) | Адрес `host:port` удалённой (или локальной) ноды `monerod`, передаваемый в `--daemon-address`. |
| `WALLET_RESTORE_HEIGHT` | пусто (динамически `height - 1000`; оффлайн-fallback `mainnet=3500000`, `stagenet=2000000`, `testnet=2900000`) | Начальная высота блока при первичном создании кошелька (`--restore-height`); если оставить пустой, запрашивается текущая высота `MONERO_REMOTE_NODE` минус 1000 блоков. |
| `MONERO_RPC_PROXY` | `""` | Опциональный SOCKS5-прокси для трафика `monero-wallet-rpc -> monerod` (например `127.0.0.1:9050` для Tor). |
| `MONERO_VIEW_ONLY_ADDRESS` | `""` | Основной адрес кошелька. **Обязателен** в `start.sh` при первом создании кошелька в `WALLET_MODE=view_only`. |
| `MONERO_VIEW_ONLY_KEY` | `""` | Приватный view-ключ (64 hex). **Обязателен** в `start.sh` при первом создании кошелька в `WALLET_MODE=view_only`. |
| `MONERO_CLI_VERSION` | `v0.18.5.4` | Версия релиза Monero CLI для `./start.sh --setup-rpc`. |
| `MONERO_CLI_SHA256` | `ba2928962c101b609434bf8c1b43ad59ebe96c5525977284ca599d8bf0f02d10` | Закреплённая SHA-256 контрольная сумма архива `monero-linux-x64-v0.18.5.4.tar.bz2`. Если очистить при смене версии, `start.sh` проверит GPG-подпись `hashes.txt`. |

---

## 5. Проверки безопасности и ограничения при запуске

`xmr-gateway` спроектирован по принципу **fail-closed**: при нарушении любого инварианта безопасности сервис завершается с ненулевым кодом выхода (`fatal startup error: ...`) до открытия HTTP-порта.

### 5.1. Модель доверия: `view_only` vs `hot_wallet` и контроль `spend_key`

- **Режим `view_only` (рекомендуемый):** на сервере хранятся только публичный адрес и приватный `view_key`; приватный `spend_key` физически отсутствует на хосте. Компрометация сервера не позволяет вывести средства (риск ограничен чтением входящих сумм и метаданных).
- **Режим `hot_wallet`:** приватный `spend_key` находится в процессе `monero-wallet-rpc` на сервере для подписи `sweep_all`. Используйте его строго как **транзитный операционный кошелёк**: храните минимальный операционный остаток, жёстко изолируйте хост и `127.0.0.1:18082`, обязательно задавайте отдельный `OPERATOR_API_KEY` и регулярно выводите средства на оффлайн/аппаратный `COLD_WALLET_ADDRESS`.
- **При первом запуске `start.sh` (`validate_wallet_bootstrap_policy`):** если файл `data/wallet/gateway_wallet.keys` отсутствует и выбран `WALLET_MODE=view_only`, но не заданы `MONERO_VIEW_ONLY_ADDRESS` и `MONERO_VIEW_ONLY_KEY`, скрипт **отказывается** молча генерировать горячий кошелёк со spend-ключом.
- **Проверка через RPC (`start.sh::verify_rpc_wallet_mode` и `src/rpc/client.rs::verify_wallet_mode`):** на старте вызывается `query_key({"key_type": "spend_key"})`:
  - Если настроено `WALLET_MODE=view_only`, а `monero-wallet-rpc` вернул ненулевой приватный `spend_key` -> немедленная ошибка `SECURITY VIOLATION: WALLET_MODE=view_only is configured, but monero-wallet-rpc loaded a hot wallet holding a private spend key`.
  - Если настроено `WALLET_MODE=hot_wallet`, а кошелёк является watch-only (ошибка JSON-RPC или пустой/нулевой `spend_key`) -> немедленная ошибка запуска.

### 5.2. Ограничения режима `hot_wallet` и `COLD_WALLET_ADDRESS`

Проверки в `Config::validate()` (`src/config.rs:473-498`) и `src/main.rs:68-76`:
- `ENABLE_AUTO_SWEEP=true` при `WALLET_MODE=view_only` -> **отказ запуска** (`ENABLE_AUTO_SWEEP=true requires WALLET_MODE=hot_wallet`).
- `WALLET_MODE=hot_wallet` при `ENABLE_AUTO_SWEEP=false` -> **отказ запуска**, если явно не указано `ALLOW_HOT_WALLET_WITHOUT_SWEEP=true`. Это защищает от случайного хранения spend-ключа на сервере без настроенного автовывода.
- `ENABLE_AUTO_SWEEP=true` без `COLD_WALLET_ADDRESS` -> **отказ запуска**.
- Если `COLD_WALLET_ADDRESS` задан (даже при `ENABLE_AUTO_SWEEP=false`), он обязан пройти:
  1. Чистую Rust-валидацию `validate_monero_address()`: длина `95` (стандартный/субадрес) или `106` (интегрированный), корректный Base58, валидный байт сети (`18/42/19` mainnet, `24/36/25` stagenet, `53/63/54` testnet) и 4-байтную контрольную сумму **Keccak-256**.
  2. Живую RPC-проверку `validate_address` в `monero-wallet-rpc`, гарантирующую совпадение сети адреса с активной сетью кошелька (например, адрес mainnet не пройдёт на кошельке stagenet).

### 5.3. Требования к секретам и RPC-транспорту

- `API_SECRET_KEY`, `WEBHOOK_SECRET` и `OPERATOR_API_KEY`: длина **не менее 32 байт**, запрещены префиксы `replace-with-`, `changeme`, `example-`. При `WALLET_MODE=hot_wallet` или `ENABLE_AUTO_SWEEP=true` отдельный `OPERATOR_API_KEY` **обязателен** (`XMR-AUDIT-004`). При заданном `OPERATOR_API_KEY` он обязан отличаться от `API_SECRET_KEY` (сравнение в constant-time в `Config::validate()`, при совпадении запуск отклоняется, `AUDIT-002`).
- **Fail-closed проверка `view_only` (`XMR-AUDIT-003`):** и `xmr-gateway`, и `start.sh` проверяют `query_key(spend_key)` строго fail-closed — watch-only подтверждается только при 64 нулях (`null_skey`) или явном сообщении об ошибке watch-only; любые иные JSON-RPC ошибки (`-32601`, `-32603`, `-13`) или пустой/невалидный ответ блокируют запуск.
- **Изоляция учётных данных RPC (`XMR-AUDIT-005`):** `start.sh`, `admin/service.sh`, `demo-stagenet.sh` и systemd/контейнерные юниты передают `rpc-login` через временный `0600`-файл (`--config-file`) и удаляют его при остановке, чтобы пароль не отображался в `ps`.
- `MONERO_RPC_USER`/`MONERO_RPC_PASS` (и `MONERO_DAEMON_RPC_USER`/`PASS` при заданном `MONERO_DAEMON_RPC_URL`):
  - Логин и пароль должны задаваться только парой (либо оба заданы, либо оба опущены при `ALLOW_UNAUTHENTICATED_RPC=true`).
  - При `ALLOW_UNAUTHENTICATED_RPC=false` (по умолчанию) пароль обязан быть **не короче 16 символов**, отличаться от логина и не совпадать с тривиальными/плейсхолдерными строками (`password`, `admin`, `123456`, `monero`, `replace-with-*`, `changeme*`, `example-*`).
  - Незашифрованный `http://` на любой не-loopback хост запрещён при `ALLOW_INSECURE_REMOTE_RPC=false`.

### 5.4. Анти-SSRF защита исходящих вебхуков

Реализована в `src/security/url_policy.rs` и применяется в трёх точках: при старте (`DEFAULT_WEBHOOK_URL`), при создании инвойса (`POST /api/v1/invoices`) и **повторно перед каждой попыткой доставки** в `WebhookDispatcher`:
- Разрешены только схемы `http` и `https` (либо строго `https`, если `REQUIRE_HTTPS_WEBHOOKS=true`). Запрещены встроенные учётные данные (`user:pass@host`).
- При `ALLOW_PRIVATE_WEBHOOKS=false` (значение по умолчанию) блокируются:
  - IPv4: loopback (`127.0.0.0/8`), RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud metadata (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), multicast, broadcast, `0.0.0.0/8`, benchmark (`198.18.0.0/15`), зарезервированные (`>= 240.0.0.0/4`).
  - IPv6: `::1`, `::`, unique-local (`fc00::/7`), link-local (`fe80::/10`), multicast, а также IPv4-mapped и IPv4-compatible формы запрещённых IPv4.
  - Домены: `localhost`, `*.localhost`, `*.local`, `*.internal`, а также любой домен, чьи DNS-записи резолвятся в запрещённый IP.
- **Защита от DNS rebinding и редиректов:** проверенные `SocketAddr` закрепляются напрямую в HTTP-клиенте через `reqwest::ClientBuilder::resolve_to_addrs`, а HTTP `3xx` редиректы отключены (`Policy::none()`).

### 5.5. Блокировка одиночного экземпляра и контроль миграций `sqlx`

- **Одиночный процесс (`src/db/mod.rs::acquire_database_lock`):** перед открытием SQLite сервис захватывает неблокирующий эксклюзивный файловый lock `<db_path>.lock` (права `0600`). Запуск второго экземпляра `xmr-gateway` на той же БД сразу завершается ошибкой `singleton process lock '...' is already held by another running xmr-gateway instance`.
- **Права файловой системы:** на Unix директория БД переводится в `0700`, а файлы `.db`, `-wal`, `-shm` — в `0600`.
- **Встроенные миграции (`sqlx::migrate!("./migrations")`):** все 5 SQL-миграций вшиты в бинарник на этапе компиляции:
  1. `20260101000000_init_schema.sql` — базовые таблицы `invoices`, `invoice_transfers`, `webhook_deliveries`.
  2. `20260201000000_security_remediation_xmr_001_007.sql` — статусы `CONFIRMING`/`SETTLED`/`REORGED`, таблицы `sweep_attempts` и `subaddress_transfers`.
  3. `20260301000000_audit_hardening_xmr_022_040.sql` — `reorg_epoch`, `orphaned`, `snapshot_txids_json`, пересборка `subaddress_transfers` с `UNIQUE(invoice_id, txid)`.
  4. `20260302000000_sweep_reorg_detection.sql` — статус `REORGED` в `sweep_attempts`.
  5. `20260303000000_sweep_incident_resolution.sql` — колонки аудита `resolved_at`, `resolution_action`, `resolution_note`.
- `sqlx` хранит SHA-384 контрольную сумму каждой применённой миграции в таблице `_sqlx_migrations`. Если уже применённый SQL-файл был изменён задним числом (или база создана другой веткой с отличающимся текстом миграции), на старте сработает ошибка `VersionMismatch(...)` — см. раздел [6.5](#65-типовые-ошибки-на-старте-и-способы-их-решения).

---

## 6. Пошаговый запуск на Stagenet и интеграция с ботом

### 6.1. Быстрый автоматический запуск (`demo-stagenet.sh` и `start.sh`)

#### Шаг 1. Установка Monero CLI (один раз)
```bash
./start.sh --setup-rpc
```
**Проверка результата:**
```bash
./bin/monero-wallet-rpc --version
# Ожидается: Monero 'Fluorine Fermi' (v0.18.5.4-release)
```

#### Шаг 2. Настройка `.env` для Stagenet
Создайте `.env` из шаблона (если его ещё нет) и сгенерируйте секреты:
```bash
cp -n .env.example .env
chmod 600 .env
```
Пример минимального рабочего `.env` для тестирования на **Stagenet** с локальным ботом/webhook-listener (режим `hot_wallet` без автосвипа — не требует отдельного холодного адреса и view-ключей на первом тесте):

```env
HOST=127.0.0.1
PORT=8080
DATABASE_URL=sqlite://data/xmr_gateway.db

# Сгенерируйте через: openssl rand -hex 32 (либо оставьте replace-with-* — start.sh сгенерирует сам)
API_SECRET_KEY=replace-with-at-least-32-bytes-of-high-entropy-random-hex
WEBHOOK_SECRET=replace-with-at-least-32-bytes-of-webhook-hmac-secret

# Для локального webhook-сервера (127.0.0.1:9000 / локальный TG-бот)
ALLOW_PRIVATE_WEBHOOKS=true
REQUIRE_HTTPS_WEBHOOKS=false

# Stagenet и публичная stagenet-нода
MONERO_NETWORK=stagenet
MONERO_RPC_URL=http://127.0.0.1:18082/json_rpc
MONERO_RPC_USER=xmr_gateway_user
MONERO_RPC_PASS=replace-with-secure-rpc-password
MONERO_REMOTE_NODE=node.monerodevs.org:38089
MONERO_TRUSTED_DAEMON=false
WALLET_RESTORE_HEIGHT=1700000

# Быстрый старт на Stagenet: hot_wallet без автосвипа (для view_only см. раздел 4.6)
WALLET_MODE=hot_wallet
ENABLE_AUTO_SWEEP=false
ALLOW_HOT_WALLET_WITHOUT_SWEEP=true

# Для быстрых тестов на Stagenet можно снизить REQUIRED_CONFIRMATIONS (например, до 2)
REQUIRED_CONFIRMATIONS=2
SETTLEMENT_CONFIRMATIONS=10
SCAN_INTERVAL_SECONDS=10
WEBHOOK_POLL_INTERVAL_SECONDS=5
LOG_FORMAT=pretty
RUST_LOG=info,xmr_gateway=debug
```

#### Шаг 3. Запуск однотерминального демо или обычного оркестратора
- **Вариант А (живое демо со встроенным webhook-приёмником на `:9000` и тестовым инвойсом `0.005 XMR`):**
  ```bash
  ./demo-stagenet.sh
  ```
- **Вариант Б (обычный запуск `monero-wallet-rpc` + `xmr-gateway` без демо-инвойса, для работы с вашим ботом):**
  ```bash
  ./start.sh
  ```

### 6.2. Ручной запуск связки `monero-wallet-rpc` + `xmr-gateway`

Если вы предпочитаете контролировать процессы в двух отдельных терминалах (или под `tmux`/`systemd`):

1. **Инициализация кошелька Stagenet (если `data/wallet/gateway_wallet.keys` ещё нет):**
   ```bash
   mkdir -p data/wallet && chmod 700 data data/wallet
   openssl rand -hex 24 > data/wallet/gateway_wallet.password
   chmod 600 data/wallet/gateway_wallet.password

   # Вариант для hot_wallet:
   ./bin/monero-wallet-cli --offline --stagenet \
     --generate-new-wallet data/wallet/gateway_wallet \
     --password-file data/wallet/gateway_wallet.password \
     --restore-height 1700000 \
     --mnemonic-language English \
     --command address

   # ИЛИ вариант для view_only (Zero-Trust):
   ./bin/monero-wallet-cli --offline --stagenet \
     --generate-from-view-key data/wallet/gateway_wallet \
     --password-file data/wallet/gateway_wallet.password \
     --restore-height 1700000
   ```

2. **Терминал 1 — запуск `monero-wallet-rpc` в режиме Stagenet:**
   ```bash
   set -a; source .env; set +a
   ./bin/monero-wallet-rpc \
     --non-interactive \
     --no-initial-sync \
     --stagenet \
     --untrusted-daemon \
     --wallet-file data/wallet/gateway_wallet \
     --password-file data/wallet/gateway_wallet.password \
     --daemon-address "${MONERO_REMOTE_NODE:-node.monerodevs.org:38089}" \
     --rpc-bind-ip 127.0.0.1 \
     --rpc-bind-port 18082 \
     --rpc-login "${MONERO_RPC_USER}:${MONERO_RPC_PASS}" \
     --log-file data/monero-wallet-rpc.log \
     --log-level 1
   ```
   **Проверка RPC (в другом терминале):**
   ```bash
   set -a; source .env; set +a
   curl -sS --digest -u "${MONERO_RPC_USER}:${MONERO_RPC_PASS}" \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' \
     http://127.0.0.1:18082/json_rpc
   # Ожидается JSON с "result":{"version":...}
   ```

3. **Терминал 2 — сборка и запуск `xmr-gateway`:**
   ```bash
   cargo build --release
   ./target/release/xmr-gateway
   ```

### 6.3. Проверка `/health`, создание инвойса и опрос статуса

1. **Проверка `/health`:**
   ```bash
   # Публичная проверка (без утечки внутренних деталей):
   curl -sS http://127.0.0.1:8080/health
   # {"status":"ok"}

   # Полная диагностика (с X-API-Key):
   set -a; source .env; set +a
   curl -sS -H "X-API-Key: $API_SECRET_KEY" http://127.0.0.1:8080/health | python3 -m json.tool
   ```
   Ожидаемый ответ:
   ```json
   {
     "status": "ok",
     "service": "xmr-gateway",
     "version": "0.1.5",
     "database": "connected",
     "monero_rpc": {
       "connected": true,
       "version": 196615,
       "error": null
     },
     "auto_sweep_enabled": false
   }
   ```

2. **Создание инвойса (`POST /api/v1/invoices`):**
   ```bash
   set -a; source .env; set +a
   curl -sS -X POST http://127.0.0.1:8080/api/v1/invoices \
     -H "Content-Type: application/json" \
     -H "X-API-Key: $API_SECRET_KEY" \
     -d '{
       "order_id": "tg_order_1001",
       "amount_piconero": 5000000000,
       "callback_url": "http://127.0.0.1:9000/webhooks/monero",
       "ttl_seconds": 3600
     }' | python3 -m json.tool
   ```
   В ответе (`201 Created`) вы получите `invoice_id`, уникальный `subaddress` (начинается с `7...` на Stagenet или `8...` на Mainnet), `address_index`, `monero_uri` и `qr_code_base64`.

3. **Проверка статуса инвойса и транзакций (`GET /api/v1/invoices/{invoice_id}`):**
   ```bash
   curl -sS -H "X-API-Key: $API_SECRET_KEY" \
     "http://127.0.0.1:8080/api/v1/invoices/<INVOICE_UUID>" | python3 -m json.tool
   ```

### 6.4. Интеграция с Telegram-ботом (создание счёта и приём вебхуков)

Типовой поток интеграции Telegram-бота с `xmr-gateway`:
1. Пользователь нажимает «Оплатить XMR» -> бот вызывает `POST http://127.0.0.1:8080/api/v1/invoices` с заголовком `X-API-Key: <API_SECRET_KEY>`, уникальным **непрозрачным `order_id` без PII** (например `ord_7f9a2c41`, не используйте email/username/телефон), суммой в `amount_piconero` (`1 XMR = 1_000_000_000_000`) и `callback_url` на HTTP-обработчик бота.
2. Бот декодирует `qr_code_base64` в PNG-картинку и отправляет пользователю сообщение с QR-кодом, `subaddress`, `amount_xmr_formatted` и `monero_uri`.
3. Когда клиент отправляет тестовые монеты Stagenet (например, через Stagenet-кошелёк или публичный faucet), `xmr-gateway` последовательно шлёт подписанные `POST`-вебхуки: `MEMPOOL` (0-conf) -> `CONFIRMED` -> `SETTLED` (или `SWEPT`).
4. Бот **обязательно проверяет свежесть `X-Webhook-Timestamp` (например `<= 300s`) и подпись `X-Webhook-Signature` по `"{timestamp}.{raw_body}"`**, а также обеспечивает идемпотентность по `event_id` (`X-Webhook-Event-Id`):

```python
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.request

GATEWAY_URL = os.environ.get("XMR_GATEWAY_URL", "http://127.0.0.1:8080")
API_KEY = os.environ["API_SECRET_KEY"]
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode("utf-8")


def create_xmr_invoice(order_id: str, amount_piconero: int, callback_url: str) -> dict:
    body = json.dumps({
        "order_id": order_id,
        "amount_piconero": amount_piconero,
        "callback_url": callback_url,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{GATEWAY_URL}/api/v1/invoices",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        inv = json.loads(resp.read().decode("utf-8"))
    # Декодированный PNG для отправки методом sendPhoto в Telegram Bot API:
    inv["qr_png_bytes"] = base64.b64decode(inv["qr_code_base64"])
    return inv


def verify_webhook(
    raw_body: bytes,
    timestamp_header: str,
    sig_header: str,
    max_skew_seconds: int = 300,
) -> dict:
    ts = int(timestamp_header.strip())
    if abs(int(time.time()) - ts) > max_skew_seconds:
        raise ValueError("stale X-Webhook-Timestamp")
    signing_input = f"{ts}.".encode("utf-8") + raw_body
    expected = hmac.new(WEBHOOK_SECRET, signing_input, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig_header.strip().lower()):
        raise ValueError("invalid X-Webhook-Signature")
    return json.loads(raw_body.decode("utf-8"))
```

- Выдавать цифровой товар/подписку в боте рекомендуется по событию **`SETTLED`** (в View-Only режиме) или **`SWEPT`** (в Hot Auto-Sweep режиме); событие `MEMPOOL` используйте только для уведомления пользователя «Платёж обнаружен в мемпуле, ожидаем подтверждения».
- Если бот временно был недоступен и пропустил вебхуки (они перешли в `FAILED`), перезапустите доставку командой (операторский маршрут — при заданном `OPERATOR_API_KEY` требуется `X-Operator-Key` / `OPERATOR_API_KEY`, `AUDIT-002`):
  ```bash
  curl -sS -X POST -H "X-Operator-Key: ${OPERATOR_API_KEY:-$API_SECRET_KEY}" \
    "http://127.0.0.1:8080/api/v1/invoices/<INVOICE_UUID>/webhooks/retry"
  ```

### 6.5. Типовые ошибки на старте и способы их решения

| Симптом / текст ошибки                                                                                         | Причина                                                                                                                                 | Решение                                                                                                                                                                                                                                                                                                                                                                                                                         |
| -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VersionMismatch(2026...)` / `migration ... was previously applied but has been modified`                      | Конфликт контрольных сумм `sqlx` в таблице `_sqlx_migrations` (БД осталась от старой версии/ветки, где текст миграции отличался).       | **На Stagenet/локальном тесте:** остановите сервис, сделайте бэкап и пересоздайте тестовую БД (`mv data/xmr_gateway.db data/xmr_gateway.db.bak && rm -f data/xmr_gateway.db-wal data/xmr_gateway.db-shm`). **На продакшене:** НЕ удаляйте БД; восстановите точный бинарник/миграцию, которой применялась схема, либо проверьте diff таблицы `sqlite3 data/xmr_gateway.db "SELECT version, description FROM _sqlx_migrations;"`. |
| `TCP port 18082 is already in use` / `failed to bind TCP listener on 127.0.0.1:8080: Address already in use`   | Предыдущий экземпляр `monero-wallet-rpc`, `xmr-gateway` или другой сервис уже занял порт.                                               | Найдите процесс: `ss -ltnp \| grep -E ':(8080\|18082\|9000)\b'`, завершите его (`kill -TERM <PID>`) или поменяйте `PORT` / порт в `MONERO_RPC_URL`.                                                                                                                                                                                                                                                                             |
| `SECURITY VIOLATION: WALLET_MODE=view_only is configured, but the loaded wallet contains a private spend key!` | В `data/wallet/gateway_wallet` лежит горячий кошелёк, а в `.env` указан `WALLET_MODE=view_only`.                                        | Либо замените кошелёк на настоящий watch-only (`--generate-from-view-key`), либо осознанно переключите `.env` в `WALLET_MODE=hot_wallet` (+ `ENABLE_AUTO_SWEEP=true` или `ALLOW_HOT_WALLET_WITHOUT_SWEEP=true`).                                                                                                                                                                                                                |
| `WALLET_MODE=hot_wallet requires ENABLE_AUTO_SWEEP=true (or explicit ALLOW_HOT_WALLET_WITHOUT_SWEEP=true)`     | Выбран `hot_wallet` без автосвипа и без явного флага разрешения.                                                                        | Для Stagenet-тестов добавьте `ALLOW_HOT_WALLET_WITHOUT_SWEEP=true`, для боевого Hot Auto-Sweep включите `ENABLE_AUTO_SWEEP=true` и задайте `COLD_WALLET_ADDRESS`.                                                                                                                                                                                                                                                               |
| `COLD_WALLET_ADDRESS failed monero-wallet-rpc validate_address check for active network`                       | Адрес в `COLD_WALLET_ADDRESS` относится к другой сети (например, mainnet `4...`/`8...` при запущенном stagenet-кошельке `5...`/`7...`). | Укажите адрес, соответствующий `MONERO_NETWORK` (или очистите `COLD_WALLET_ADDRESS`, если `ENABLE_AUTO_SWEEP=false`).                                                                                                                                                                                                                                                                                                           |
| `target IP '127.0.0.1' is blocked by SSRF policy`                                                              | `callback_url` или `DEFAULT_WEBHOOK_URL` указывает на локальный/приватный адрес при `ALLOW_PRIVATE_WEBHOOKS=false`.                     | Для локального тестирования бота/демо установите `ALLOW_PRIVATE_WEBHOOKS=true` в `.env`. В продакшене используйте публичный `https://` домен.                                                                                                                                                                                                                                                                                   |
| `singleton process lock 'data/xmr_gateway.db.lock' is already held by another running xmr-gateway instance`    | Уже запущен другой экземпляр `xmr-gateway` на том же файле БД.                                                                          | Проверьте `pgrep -af xmr-gateway` и остановите лишний процесс; удалять `.lock` вручную не требуется — ОС освободит блокировку автоматически после завершения процесса.                                                                                                                                                                                                                                                          |
| `Timed out waiting for monero-wallet-rpc`                                                                      | Недоступна удалённая нода `MONERO_REMOTE_NODE`, неверный `--stagenet` флаг или ошибка открытия кошелька.                                | Проверьте хвост лога: `tail -n 50 data/monero-wallet-rpc.log`, убедитесь, что нода соответствует сети (`:38089` для stagenet, `:18081` для mainnet).                                                                                                                                                                                                                                                                            |
| `API_SECRET_KEY still contains a placeholder value` / `MONERO_RPC_PASS must be at least 16 characters long`    | В `.env` остались значения из `.env.example` или короткий пароль.                                                                       | Сгенерируйте ключи: `openssl rand -hex 32` (для API/Webhook) и `openssl rand -hex 24` (для RPC), либо запустите `./start.sh --init-wallet-only`.                                                                                                                                                                                                                                                                                |

---

## 7. Сборка, тесты и эксплуатация

### 7.1. Сборка и команды `Makefile`

```bash
# Сборка оптимизированного release-бинарника (./target/release/xmr-gateway)
cargo build --release --locked

# Или через Makefile:
make setup-rpc   # ./start.sh --setup-rpc
make release     # cargo build --release
make run         # ./start.sh
make test        # cargo test --all-targets
make lint        # cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings
make fmt         # cargo fmt --all
```

**Проверка артефакта сборки:**
```bash
ls -lh target/release/xmr-gateway
```

### 7.2. Запуск тестов и статического анализа

В проекте 55 модульных тестов (`src/lib.rs`) и 39 интеграционных/адверсарных тестов (`tests/security_hardening_suite.rs`), покрывающих криптографию адресов, SQLite durability/миграции/`BEGIN IMMEDIATE`/WAL checkpoint, сохранение баланса при переплатах, SSRF, RBAC, гонки свипа, реорги и восстановление инцидентов:

```bash
# Форматирование, Clippy и документация (строго без предупреждений)
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps

# Полный прогон тестов в debug и release
cargo test --locked --all-targets
cargo test --locked --release --all-targets
```

### 7.3. Работа с SQLite (WAL durability), резервное копирование, `systemd` и логи

- **Надёжность SQLite WAL и graceful shutdown (`XMR-007` / `XMR-040` / `AUDIT-005`):**
  - Пул SQLite открывается в режиме `journal_mode = WAL`, `PRAGMA synchronous = FULL`, `PRAGMA foreign_keys = ON`, `busy_timeout = 5s`; каталог БД получает права `0700`, а файлы `.db`, `-wal`, `-shm` и `.lock` — `0600` (на Unix).
  - Все write-транзакции в `InvoiceRepository` стартуют через `BEGIN IMMEDIATE`, захватывая `RESERVED`-блокировку сразу и исключая мгновенные ошибки `SQLITE_BUSY` при апгрейде `DEFERRED`-транзакции под конкурентной нагрузкой.
  - При `SIGINT`/`SIGTERM` HTTP-сервер и оба фоновых воркера (`ScannerService`, `WebhookDispatcher` с приоритетной проверкой `shutdown` через `tokio::select! { biased; ... }`) корректно завершают текущую итерацию без запуска нового тика, после чего `checkpoint_and_close_pool()` выполняет `PRAGMA wal_checkpoint(TRUNCATE);`, повторно выставляет права `0600` и закрывает пул **до** освобождения `<db_path>.lock`.
  - В леджере `subaddress_transfers` для переплат (`OVERPAYMENT`) сохраняется полная фактическая сумма транзакции (`tr.amount_piconero`), обеспечивая инвариант сохранения баланса `SUM(subaddress_transfers.amount_piconero) == SUM(confirmed non-orphaned invoice_transfers.amount_piconero)`.
- **Файлы SQLite в рабочем каталоге (`data/`):**
  - `xmr_gateway.db` — основная БД (права `0600`).
  - `xmr_gateway.db-wal` и `xmr_gateway.db-shm` — журнал Write-Ahead Log и shared-memory индекс (`0600`). Не удаляйте `-wal` вручную при работающем сервисе — в нём содержатся незачекпоинченные транзакции.
  - `xmr_gateway.db.lock` — lock-файл одиночного экземпляра (`0600`).
- **Безопасный онлайн-бэкап и восстановление SQLite (`AUDIT-005`):**
  - **СТРОГО ЗАПРЕЩЕНО копировать работающую WAL-базу через `cp data/xmr_gateway.db ...`:** без синхронизированных страниц `-wal`/`-shm` копия будет неконсистентной или повреждённой.
  - Используйте встроенные транзакционные механизмы SQLite (`VACUUM INTO` или `.backup`) с обязательной проверкой `PRAGMA integrity_check;`:
    ```bash
    # Способ 1 (рекомендуемый): атомарный самодостаточный снимок без -wal/-shm
    sqlite3 data/xmr_gateway.db "VACUUM INTO 'data/xmr_gateway.backup.$(date +%F_%H%M%S).db';"

    # Способ 2: SQLite Online Backup API
    sqlite3 data/xmr_gateway.db ".backup 'data/xmr_gateway.backup.$(date +%F_%H%M%S).db'"

    chmod 600 data/xmr_gateway.backup.*.db

    # Обязательная проверка целостности бэкапа (должно вернуть "ok"):
    sqlite3 data/xmr_gateway.backup.<TIMESTAMP>.db "PRAGMA integrity_check;"
    ```
  - **Восстановление из бэкапа:** остановите `xmr-gateway` (чтобы отпустить `.lock`), удалите старые `data/xmr_gateway.db-wal` и `data/xmr_gateway.db-shm`, скопируйте проверенный бэкап на место `data/xmr_gateway.db` с правами `chmod 600`, проверьте `sqlite3 data/xmr_gateway.db "PRAGMA integrity_check;"` и запустите сервис снова.
- **Полезные диагностические SQL-запросы (только чтение):**
  ```bash
  sqlite3 -header -column data/xmr_gateway.db \
    "SELECT id, order_id, status, amount_piconero, received_piconero, confirmations, reorg_epoch FROM invoices ORDER BY created_at DESC LIMIT 10;"

  sqlite3 -header -column data/xmr_gateway.db \
    "SELECT id, invoice_id, event_type, status, attempts, last_status_code, last_error FROM webhook_deliveries WHERE status != 'DELIVERED' ORDER BY created_at DESC LIMIT 10;"

  sqlite3 -header -column data/xmr_gateway.db \
    "SELECT id, invoice_id, status, error_message, resolution_action FROM sweep_attempts WHERE status IN ('PREPARED','REORGED','FAILED') ORDER BY created_at DESC LIMIT 10;"
  ```
- **Промышленная установка, пакеты и контейнеры (подробно в [DEPLOY_RU.md](DEPLOY_RU.md) / [DEPLOY_EN.md](DEPLOY_EN.md)):**
  - **One-line установщик (`scripts/install.sh`):** автовыбор `.deb` / `.rpm` / `.tar.gz` из GitHub Releases (`x86_64` / `aarch64`) с обязательной проверкой `SHA256SUMS` и опциональной GPG-проверкой (`--require-gpg`):
    ```bash
    curl -fsSL https://raw.githubusercontent.com/XeonIT-dev/xmr-gateway/main/scripts/install.sh -o install.sh
    bash install.sh --dry-run
    sudo bash install.sh
    ```
  - **Системные пакеты `.deb` / `.rpm`:** устанавливают `/usr/bin/xmr-gateway`, системную обёртку `/usr/bin/xmr-gateway-admin` (`/usr/share/xmr-gateway/`), шаблон `/etc/xmr-gateway/env.example` (не перезаписывая существующий `/etc/xmr-gateway/.env`) и 4 юнита `systemd` в `/usr/lib/systemd/system/`.
  - **Эксплуатация через `systemd` (`deploy/systemd/`):** `monero-wallet-rpc.service` (вызывает автономный `0755` POSIX-скрипт `/usr/share/xmr-gateway/scripts/render-wallet-rpc-conf.sh`, который рендерит `0600` `/run/xmr-gateway/wallet-rpc.conf` в RAM без утечки пароля в `ps`), `xmr-gateway.service` (`EnvironmentFile=/etc/xmr-gateway/.env`, `UMask=0077`, `KillSignal=SIGTERM`, `TimeoutStopSec=30`) и ежедневный горячий бэкап `xmr-gateway-backup.service` + `xmr-gateway-backup.timer`.
  - **Обратный прокси (`deploy/reverse-proxy/`):** готовые `Caddyfile` и `nginx-xmr-gateway.conf` (TLS 1.2/1.3, лимит тела, пример ограничения операторских маршрутов по IP/VPN).
  - **Контейнеры:** корневой `Containerfile` (UID/GID `10001`), воспроизводимый `deploy/docker/Containerfile.monero-rpc` (SHA256-проверка официального Monero CLI), `deploy/docker/docker-compose.yml` (изолированная сеть `xmr_internal`, `127.0.0.1:8080`, опциональный `--profile caddy`) и rootless Podman Quadlet (`deploy/podman/quadlet/` с `:Z` для SELinux).
- **Логи:**
  - `xmr-gateway` пишет логи в `stdout` (формат `LOG_FORMAT=json` или `pretty`, фильтрация через `RUST_LOG`). При работе через `systemd`: `journalctl -u xmr-gateway -f`.
  - `monero-wallet-rpc` пишет логи в `data/monero-wallet-rpc.log` (или `/var/lib/xmr-gateway/monero-wallet-rpc.log` в `systemd`).

### 7.4. Чеклист перед запуском на Mainnet

- [ ] **Секреты и разделение ролей:** сгенерированы свежие случайные `API_SECRET_KEY`, `WEBHOOK_SECRET` (`>= 32` байт), `MONERO_RPC_PASS` (`>= 16` симв.); при необходимости задан отдельный `OPERATOR_API_KEY` (`>= 32` байт). Файл `.env` имеет права `0600` и не попадает в Git.
- [ ] **Режим кастодиальности:** по возможности используется **View-Only Zero-Trust** (`WALLET_MODE=view_only`, `ENABLE_AUTO_SWEEP=false`, кошелёк создан из `MONERO_VIEW_ONLY_ADDRESS` + `MONERO_VIEW_ONLY_KEY`). Если выбран `hot_wallet`, проверены `ENABLE_AUTO_SWEEP=true`, `COLD_WALLET_ADDRESS` (mainnet) и резервная копия 25-словной seed-фразы.
- [ ] **Сетевая изоляция:** `HOST=127.0.0.1`, `MONERO_RPC_URL=http://127.0.0.1:18082/json_rpc`, `ALLOW_UNAUTHENTICATED_RPC=false`, `ALLOW_INSECURE_REMOTE_RPC=false`; внешний доступ (если нужен) — только через TLS reverse proxy (Caddy/Nginx).
- [ ] **Вебхуки:** `ALLOW_PRIVATE_WEBHOOKS=false`, `REQUIRE_HTTPS_WEBHOOKS=true` (обязательно на `mainnet` fail-closed), на стороне получателя проверяются свежесть `X-Webhook-Timestamp` (`<= 300s`), подпись `X-Webhook-Signature` и идемпотентность по `event_id` (`X-Webhook-Event-Id`).
- [ ] **Собственный `monerod` и инциденты:** для максимальной надёжности подключите собственный локальный `monerod` (`MONERO_REMOTE_NODE=127.0.0.1:18081`, `MONERO_TRUSTED_DAEMON=true`) и задайте `MONERO_DAEMON_RPC_URL` (+ логин/пароль), чтобы при инциденте работал `POST /api/v1/invoices/{id}/sweep/resolve` (`allow_resweep`).
- [ ] **Подтверждения и мониторинг:** `REQUIRED_CONFIRMATIONS=10` (и `SETTLEMENT_CONFIRMATIONS=15` для крупных заказов), `SUBADDRESS_MONITOR_DAYS=0`, `LOG_FORMAT=json`.
- [ ] **Выделенный чистый кошелёк и синхронизация `lag=0`:** используется новый, выделенный исключительно под шлюз кошелёк Monero без истории старых входящих переводов на субадресах (`account=0, index=1, 2...`); перед открытием боевого трафика проверка `wallet_daemon_sync` в `config doctor` подтверждает `lag=0, daemon_synchronized=true`.
- [ ] **Бэкапы и `systemd`:** настроены юниты из `deploy/systemd/` и регулярный онлайн-бэкап SQLite (`sqlite3 ... ".backup ..."`), файлы кошелька и `xmr_gateway.db` архивируются и восстанавливаются строго в паре.
