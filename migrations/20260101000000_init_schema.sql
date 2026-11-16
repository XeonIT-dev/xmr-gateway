-- ============================================================================
-- xmr-gateway Initial Schema (SQLite WAL Mode)
-- ============================================================================
-- Financial Invariant:
--   All monetary quantities are stored strictly as signed 64-bit INTEGERs
--   representing piconero atomic units (1 XMR = 10^12 piconero).
--   Floating-point REAL columns are strictly prohibited.
-- ============================================================================

CREATE TABLE IF NOT EXISTS invoices (
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
            'CONFIRMED',
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
    swept_at              TEXT,
    completed_at          TEXT,
    -- Subaddress isolation invariant: at most one invoice per (account_index, address_index)
    UNIQUE (account_index, address_index)
);

CREATE INDEX IF NOT EXISTS idx_invoices_status
    ON invoices (status);

CREATE INDEX IF NOT EXISTS idx_invoices_expires_at
    ON invoices (expires_at);

CREATE INDEX IF NOT EXISTS idx_invoices_subaddr
    ON invoices (account_index, address_index);

-- ============================================================================
-- Observed Incoming Transfers Audit Table
-- ============================================================================
-- Tracks every non-trivial incoming Monero output observed for an invoice's
-- subaddress, deduplicated per (invoice_id, txid).
CREATE TABLE IF NOT EXISTS invoice_transfers (
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

CREATE INDEX IF NOT EXISTS idx_invoice_transfers_invoice_id
    ON invoice_transfers (invoice_id);

-- ============================================================================
-- Durable Webhook Delivery Queue (Exponential Backoff)
-- ============================================================================
-- Stores exact canonical JSON bytes and HMAC-SHA256 hex digest at enqueue time
-- so retries across process restarts always deliver identical signed payloads.
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id               TEXT PRIMARY KEY NOT NULL,
    invoice_id       TEXT NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
    event_type       TEXT NOT NULL CHECK (
        event_type IN ('MEMPOOL', 'UNDERPAID', 'CONFIRMED', 'SWEPT', 'EXPIRED')
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

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due
    ON webhook_deliveries (status, next_attempt_at);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_invoice_id
    ON webhook_deliveries (invoice_id);
