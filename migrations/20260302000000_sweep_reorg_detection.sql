-- ============================================================================
-- xmr-gateway Sweep Reorg Detection & Finality Migration
-- ============================================================================
-- Expands sweep_attempts.status CHECK constraint to support 'REORGED' when an
-- outbound sweep transaction vanishes from get_transfers(out=true, pending=true)
-- or is flagged double_spend_seen = true.
-- Rebuilds subaddress_transfers alongside sweep_attempts inside the migration
-- transaction so SQLite foreign_keys = ON preserves sweep_attempt_id lineage.
-- ============================================================================

CREATE TABLE _bak_subaddress_transfers AS SELECT * FROM subaddress_transfers;
CREATE TABLE _bak_sweep_attempts AS SELECT * FROM sweep_attempts;

DROP TABLE subaddress_transfers;
DROP TABLE sweep_attempts;

CREATE TABLE sweep_attempts (
    id                    TEXT PRIMARY KEY NOT NULL,
    invoice_id            TEXT NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
    address_index         INTEGER NOT NULL CHECK (address_index >= 0),
    destination_address   TEXT NOT NULL,
    snapshot_txids_json   TEXT NOT NULL DEFAULT '[]',
    status                TEXT NOT NULL CHECK (
        status IN (
            'PREPARED',
            'SUBMITTED',
            'CONFIRMED',
            'RECONCILED',
            'FAILED',
            'REORGED'
        )
    ),
    tx_hashes_json        TEXT NOT NULL DEFAULT '[]',
    swept_amount_piconero INTEGER CHECK (swept_amount_piconero IS NULL OR swept_amount_piconero >= 0),
    fee_piconero          INTEGER CHECK (fee_piconero IS NULL OR fee_piconero >= 0),
    error_message         TEXT,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);

INSERT INTO sweep_attempts (
    id, invoice_id, address_index, destination_address, snapshot_txids_json,
    status, tx_hashes_json, swept_amount_piconero, fee_piconero,
    error_message, created_at, updated_at
)
SELECT
    id, invoice_id, address_index, destination_address, snapshot_txids_json,
    status, tx_hashes_json, swept_amount_piconero, fee_piconero,
    error_message, created_at, updated_at
FROM _bak_sweep_attempts;

CREATE INDEX IF NOT EXISTS idx_sweep_attempts_invoice_id
    ON sweep_attempts (invoice_id);

CREATE INDEX IF NOT EXISTS idx_sweep_attempts_status
    ON sweep_attempts (status);

CREATE TABLE subaddress_transfers (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    txid             TEXT NOT NULL CHECK (length(trim(txid)) > 0),
    invoice_id       TEXT NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
    address_index    INTEGER NOT NULL CHECK (address_index >= 0),
    amount_piconero  INTEGER NOT NULL CHECK (amount_piconero >= 0),
    confirmations    INTEGER NOT NULL DEFAULT 0 CHECK (confirmations >= 0),
    classification   TEXT NOT NULL CHECK (
        classification IN ('EXPECTED', 'LATE_PAYMENT', 'OVERPAYMENT')
    ),
    status           TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (
        status IN ('ACTIVE', 'ORPHANED', 'SWEPT')
    ),
    swept            INTEGER NOT NULL DEFAULT 0 CHECK (swept IN (0, 1)),
    sweep_attempt_id TEXT REFERENCES sweep_attempts (id) ON DELETE SET NULL,
    created_at       TEXT NOT NULL,
    UNIQUE (invoice_id, txid)
);

INSERT INTO subaddress_transfers (
    id, txid, invoice_id, address_index, amount_piconero, confirmations,
    classification, status, swept, sweep_attempt_id, created_at
)
SELECT
    id, txid, invoice_id, address_index, amount_piconero, confirmations,
    classification, status, swept, sweep_attempt_id, created_at
FROM _bak_subaddress_transfers;

CREATE INDEX IF NOT EXISTS idx_subaddress_transfers_invoice_id
    ON subaddress_transfers (invoice_id);

CREATE INDEX IF NOT EXISTS idx_subaddress_transfers_unswept
    ON subaddress_transfers (invoice_id, swept, status);

CREATE INDEX IF NOT EXISTS idx_subaddress_transfers_status
    ON subaddress_transfers (status);

DROP TABLE _bak_subaddress_transfers;
DROP TABLE _bak_sweep_attempts;
