-- ============================================================================
-- xmr-gateway Sweep Reorg Incident Resolution Audit Migration (XMR-041)
-- ============================================================================
-- Extends sweep_attempts with immutable operator incident resolution audit
-- columns so SWEEP_REORG_DETECTED locks can be verified against wallet RPC
-- and resolved via ALLOW_RESWEEP or MARK_RECONCILED without deleting history.
-- ============================================================================

ALTER TABLE sweep_attempts
    ADD COLUMN resolved_at TEXT;

ALTER TABLE sweep_attempts
    ADD COLUMN resolution_action TEXT CHECK (
        resolution_action IS NULL
        OR resolution_action IN ('ALLOW_RESWEEP', 'MARK_RECONCILED')
    );

ALTER TABLE sweep_attempts
    ADD COLUMN resolution_note TEXT;
