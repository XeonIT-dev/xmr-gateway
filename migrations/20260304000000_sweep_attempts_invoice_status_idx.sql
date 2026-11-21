-- Composite index for O(log N) per-invoice sweep incident and live-attempt lookups (`v0.1.4`).
CREATE INDEX IF NOT EXISTS idx_sweep_attempts_invoice_status
    ON sweep_attempts(invoice_id, status);
