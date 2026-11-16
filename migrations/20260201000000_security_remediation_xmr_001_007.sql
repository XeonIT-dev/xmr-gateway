-- ============================================================================
-- xmr-gateway Security & Reliability Migration (XMR-001 through XMR-007)
-- ============================================================================
-- 1. Expands invoices.status CHECK constraint to support CONFIRMING, SETTLED,
--    and REORGED states, plus settled_at timestamp.
-- 2. Expands webhook_deliveries.event_type CHECK constraint to support
--    SETTLED, REORGED, LATE_PAYMENT, and OVERPAYMENT events.
-- 3. Adds sweep_attempts crash-recovery ledger (XMR-003).
-- 4. Adds subaddress_transfers continuous monitoring ledger (XMR-004).
-- ============================================================================

CREATE TABLE _bak_webhook_deliveries AS SELECT * FROM webhook_deliveries;
CREATE TABLE _bak_invoice_transfers AS SELECT * FROM invoice_transfers;
CREATE TABLE _bak_invoices AS SELECT * FROM invoices;

DROP TABLE webhook_deliveries;
DROP TABLE invoice_transfers;
DROP TABLE invoices;

CREATE TABLE invoices (
    id                    TEXT PRIMARY KEY NOT NULL,
    order_id              TEXT NOT NULL UNIQUE,
    account_index         INTEGER NOT NULL DEFAULT 0 CHECK (account_index >= 0),
    address_index         INTEGER NOT NULL CHECK (address_index >= 0),
    subaddress            TEXT NOT NULL,
    amount_piconero       INTEGER NOT NULL CHECK (amount_piconero > 0),
    received_piconero     INTEGER NOT NULL DEFAULT 0 CHECK (received_piconero >= 0),
    confirmations         INTEGER NOT NULL DEFAULT 0 CHECK (confirmations >= 0),
    unlocked              INTEGER NOT NULL DEFAULT 0 CHECK (unlocked IN (0, 1)),
    double_spend_seen     INTEGER NOT NULL DEFAULT 0 CHECK (double_spend_seen IN (0, 1)),
    status                TEXT NOT NULL CHECK (
        status IN (
            'PENDING',
            'UNDERPAID',
            'MEMPOOL',
            'CONFIRMING',
            'CONFIRMED',
            'SETTLED',
            'REORGED',
            'COMPLETED',
            'SWEPT',
            'EXPIRED'
        )
    ),
    callback_url          TEXT,
    monero_uri            TEXT NOT NULL,
    qr_code_base64        TEXT NOT NULL,
    sweep_tx_hashes       TEXT NOT NULL DEFAULT '[]',
    sweep_amount_piconero INTEGER CHECK (sweep_amount_piconero IS NULL OR sweep_amount_piconero >= 0),
    sweep_fee_piconero    INTEGER CHECK (sweep_fee_piconero IS NULL OR sweep_fee_piconero >= 0),
    last_sweep_error      TEXT,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    expires_at            TEXT NOT NULL,
    confirmed_at          TEXT,
    settled_at            TEXT,
    swept_at              TEXT,
    completed_at          TEXT,
    UNIQUE (account_index, address_index)
);

INSERT INTO invoices (
    id, order_id, account_index, address_index, subaddress,
    amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
    status, callback_url, monero_uri, qr_code_base64,
    sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
    created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at, completed_at
)
SELECT
    id, order_id, account_index, address_index, subaddress,
    amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
    status, callback_url, monero_uri, qr_code_base64,
    sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero, last_sweep_error,
    created_at, updated_at, expires_at, confirmed_at, NULL, swept_at, completed_at
FROM _bak_invoices;

CREATE TABLE invoice_transfers (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    invoice_id        TEXT NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
    txid              TEXT NOT NULL,
    amount_piconero   INTEGER NOT NULL CHECK (amount_piconero >= 0),
    confirmations     INTEGER NOT NULL DEFAULT 0 CHECK (confirmations >= 0),
    unlocked          INTEGER NOT NULL DEFAULT 0 CHECK (unlocked IN (0, 1)),
    double_spend_seen INTEGER NOT NULL DEFAULT 0 CHECK (double_spend_seen IN (0, 1)),
    in_pool           INTEGER NOT NULL DEFAULT 0 CHECK (in_pool IN (0, 1)),
    observed_at       TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    UNIQUE (invoice_id, txid)
);

INSERT INTO invoice_transfers (
    id, invoice_id, txid, amount_piconero, confirmations,
    unlocked, double_spend_seen, in_pool, observed_at, updated_at
)
SELECT
    id, invoice_id, txid, amount_piconero, confirmations,
    unlocked, double_spend_seen, in_pool, observed_at, updated_at
FROM _bak_invoice_transfers;

CREATE TABLE webhook_deliveries (
    id               TEXT PRIMARY KEY NOT NULL,
    invoice_id       TEXT NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
    event_type       TEXT NOT NULL CHECK (
        event_type IN (
            'MEMPOOL',
            'UNDERPAID',
            'CONFIRMED',
            'SETTLED',
            'REORGED',
            'SWEPT',
            'EXPIRED',
            'LATE_PAYMENT',
            'OVERPAYMENT'
        )
    ),
    dedupe_key       TEXT NOT NULL UNIQUE,
    target_url       TEXT NOT NULL,
    payload_json     TEXT NOT NULL,
    signature_hex    TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('PENDING', 'DELIVERED', 'FAILED')),
    attempts         INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts     INTEGER NOT NULL DEFAULT 10 CHECK (max_attempts > 0),
    next_attempt_at  TEXT NOT NULL,
    last_status_code INTEGER,
    last_error       TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    delivered_at     TEXT
);

INSERT INTO webhook_deliveries (
    id, invoice_id, event_type, dedupe_key, target_url,
    payload_json, signature_hex, status, attempts, max_attempts,
    next_attempt_at, last_status_code, last_error,
    created_at, updated_at, delivered_at
)
SELECT
    id, invoice_id, event_type, dedupe_key, target_url,
    payload_json, signature_hex, status, attempts, max_attempts,
    next_attempt_at, last_status_code, last_error,
    created_at, updated_at, delivered_at
FROM _bak_webhook_deliveries;

DROP TABLE _bak_webhook_deliveries;
DROP TABLE _bak_invoice_transfers;
DROP TABLE _bak_invoices;

CREATE INDEX IF NOT EXISTS idx_invoices_status
    ON invoices (status);

CREATE INDEX IF NOT EXISTS idx_invoices_expires_at
    ON invoices (expires_at);

CREATE INDEX IF NOT EXISTS idx_invoices_subaddr
    ON invoices (account_index, address_index);

CREATE INDEX IF NOT EXISTS idx_invoices_created_at
    ON invoices (created_at);

CREATE INDEX IF NOT EXISTS idx_invoice_transfers_invoice_id
    ON invoice_transfers (invoice_id);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due
    ON webhook_deliveries (status, next_attempt_at);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_invoice_id
    ON webhook_deliveries (invoice_id);

-- ============================================================================
-- Crash-Safe Sweep Attempts Ledger (XMR-003)
-- ============================================================================
CREATE TABLE IF NOT EXISTS sweep_attempts (
    id                    TEXT PRIMARY KEY NOT NULL,
    invoice_id            TEXT NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
    address_index         INTEGER NOT NULL CHECK (address_index >= 0),
    destination_address   TEXT NOT NULL,
    status                TEXT NOT NULL CHECK (
        status IN ('PREPARED', 'SUBMITTED', 'CONFIRMED', 'RECONCILED', 'FAILED')
    ),
    tx_hashes_json        TEXT NOT NULL DEFAULT '[]',
    swept_amount_piconero INTEGER CHECK (swept_amount_piconero IS NULL OR swept_amount_piconero >= 0),
    fee_piconero          INTEGER CHECK (fee_piconero IS NULL OR fee_piconero >= 0),
    error_message         TEXT,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sweep_attempts_invoice_id
    ON sweep_attempts (invoice_id);

CREATE INDEX IF NOT EXISTS idx_sweep_attempts_status
    ON sweep_attempts (status);

-- ============================================================================
-- Continuous Subaddress Transfer Classification Ledger (XMR-004)
-- ============================================================================
CREATE TABLE IF NOT EXISTS subaddress_transfers (
    txid            TEXT PRIMARY KEY NOT NULL,
    invoice_id      TEXT NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
    address_index   INTEGER NOT NULL CHECK (address_index >= 0),
    amount_piconero INTEGER NOT NULL CHECK (amount_piconero >= 0),
    confirmations   INTEGER NOT NULL DEFAULT 0 CHECK (confirmations >= 0),
    classification  TEXT NOT NULL CHECK (
        classification IN ('EXPECTED', 'LATE_PAYMENT', 'OVERPAYMENT')
    ),
    swept           INTEGER NOT NULL DEFAULT 0 CHECK (swept IN (0, 1)),
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_subaddress_transfers_invoice_id
    ON subaddress_transfers (invoice_id);
