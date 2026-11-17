-- ============================================================================
-- xmr-gateway Audit Hardening Migration (XMR-022 through XMR-040)
-- ============================================================================
-- 1. XMR-025: Add reorg_epoch counter to invoices so post-reorg recovery
--    transitions generate fresh epoch-scoped webhook deduplication keys.
-- 2. XMR-026: Add orphaned flag to invoice_transfers so disappeared or
--    double-spent transfers are excluded from active balances while preserving
--    full audit history without physical DELETEs.
-- 3. XMR-023: Add snapshot_txids_json to sweep_attempts so completing a sweep
--    only marks the exact subaddress_transfers snapshot locked at prepare time.
-- 4. XMR-022 / XMR-026 / XMR-023: Rebuild subaddress_transfers with surrogate
--    INTEGER PRIMARY KEY AUTOINCREMENT, UNIQUE (invoice_id, txid), lifecycle
--    status ('ACTIVE', 'ORPHANED', 'SWEPT'), and sweep_attempt_id lineage.
-- ============================================================================

ALTER TABLE invoices
    ADD COLUMN reorg_epoch INTEGER NOT NULL DEFAULT 0 CHECK (reorg_epoch >= 0);

ALTER TABLE invoice_transfers
    ADD COLUMN orphaned INTEGER NOT NULL DEFAULT 0 CHECK (orphaned IN (0, 1));

CREATE INDEX IF NOT EXISTS idx_invoice_transfers_orphaned
    ON invoice_transfers (invoice_id, orphaned);

ALTER TABLE sweep_attempts
    ADD COLUMN snapshot_txids_json TEXT NOT NULL DEFAULT '[]';

CREATE TABLE subaddress_transfers_v3 (
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

INSERT INTO subaddress_transfers_v3 (
    txid, invoice_id, address_index, amount_piconero, confirmations,
    classification, status, swept, sweep_attempt_id, created_at
)
SELECT
    txid,
    invoice_id,
    address_index,
    amount_piconero,
    confirmations,
    classification,
    CASE WHEN swept = 1 THEN 'SWEPT' ELSE 'ACTIVE' END,
    swept,
    NULL,
    created_at
FROM subaddress_transfers;

DROP TABLE subaddress_transfers;
ALTER TABLE subaddress_transfers_v3 RENAME TO subaddress_transfers;

CREATE INDEX IF NOT EXISTS idx_subaddress_transfers_invoice_id
    ON subaddress_transfers (invoice_id);

CREATE INDEX IF NOT EXISTS idx_subaddress_transfers_unswept
    ON subaddress_transfers (invoice_id, swept, status);

CREATE INDEX IF NOT EXISTS idx_subaddress_transfers_status
    ON subaddress_transfers (status);
