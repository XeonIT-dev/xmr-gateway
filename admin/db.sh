#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Admin Suite — SQLite Operations & Forensics Module (admin/db.sh)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=admin/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    cat <<'EOF'
Usage: ./admin.sh db <command> [options]

Commands:
  stats                     Summary of invoices by status, XMR totals, webhooks, open sweep
                            incidents, and SQLite .db/-wal/-shm sizes (read-only, --json)
  audit-invariants          Fail-closed SQLite audit: PRAGMA integrity_check, foreign_key_check,
                            AUDIT-005 overpayment balance conservation, stuck/reorged sweeps (--json)
  backup [dest_dir]         Safe hot online backup via Python sqlite3.Connection.backup()
                            with chmod 600 and PRAGMA integrity_check verification (--json)
  shell [--rw]              Interactive SQLite console (strictly read-only by default)
  help                      Show this help message
EOF
}

cmd_stats() {
    load_env
    sqlite_ro_python "$ADMIN_JSON" <<'PYEOF'
import json, os, sqlite3, sys

db_path, as_json = sys.argv[1], sys.argv[2] == "1"
conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
conn.row_factory = sqlite3.Row
conn.execute("PRAGMA busy_timeout = 5000;")
conn.execute("PRAGMA query_only = ON;")

def fx(p):
    w, f = divmod(int(p or 0), 10**12)
    return f"{w}.{f:012d}"

inv_by_status = {
    r["status"]: r["cnt"]
    for r in conn.execute("SELECT status, COUNT(*) AS cnt FROM invoices GROUP BY status ORDER BY status")
}
totals = conn.execute(
    """
    SELECT
        COUNT(*) AS total_invoices,
        COALESCE(SUM(amount_piconero), 0) AS total_expected,
        COALESCE(SUM(received_piconero), 0) AS total_received,
        COALESCE(SUM(CASE WHEN received_piconero > amount_piconero THEN received_piconero - amount_piconero ELSE 0 END), 0) AS total_overpaid,
        COALESCE(SUM(COALESCE(sweep_amount_piconero, 0)), 0) AS total_swept,
        COALESCE(SUM(COALESCE(sweep_fee_piconero, 0)), 0) AS total_sweep_fees
    FROM invoices
    """
).fetchone()

wh_by_status = {
    r["status"]: r["cnt"]
    for r in conn.execute("SELECT status, COUNT(*) AS cnt FROM webhook_deliveries GROUP BY status ORDER BY status")
}
sw_by_status = {
    r["status"]: r["cnt"]
    for r in conn.execute("SELECT status, COUNT(*) AS cnt FROM sweep_attempts GROUP BY status ORDER BY status")
}
sub_by_class = {
    r["classification"]: {"count": r["cnt"], "amount_piconero": r["amt"], "amount_xmr": fx(r["amt"])}
    for r in conn.execute(
        "SELECT classification, COUNT(*) AS cnt, COALESCE(SUM(amount_piconero), 0) AS amt FROM subaddress_transfers WHERE status != 'ORPHANED' GROUP BY classification"
    )
}
conn.close()

files = {}
for label, suffix in [("db", ""), ("wal", "-wal"), ("shm", "-shm"), ("lock", ".lock")]:
    p = f"{db_path}{suffix}"
    files[label] = os.path.getsize(p) if os.path.exists(p) else None

out = {
    "db_path": db_path,
    "files_bytes": files,
    "invoices": {
        "total": totals["total_invoices"],
        "by_status": inv_by_status,
        "expected_piconero": totals["total_expected"],
        "expected_xmr": fx(totals["total_expected"]),
        "received_piconero": totals["total_received"],
        "received_xmr": fx(totals["total_received"]),
        "overpaid_piconero": totals["total_overpaid"],
        "overpaid_xmr": fx(totals["total_overpaid"]),
        "swept_piconero": totals["total_swept"],
        "swept_xmr": fx(totals["total_swept"]),
        "sweep_fees_piconero": totals["total_sweep_fees"],
        "sweep_fees_xmr": fx(totals["total_sweep_fees"]),
    },
    "subaddress_transfers_active_or_swept": sub_by_class,
    "webhooks_by_status": wh_by_status,
    "sweep_attempts_by_status": sw_by_status,
}

if as_json:
    print(json.dumps(out, indent=2))
    sys.exit(0)

print(f"=== SQLite Database Stats ({db_path}) ===")
print(f"  Files (bytes)    : db={files['db']} | wal={files['wal']} | shm={files['shm']} | lock={files['lock']}")
print(f"  Total Invoices   : {out['invoices']['total']}")
if inv_by_status:
    print("  By Status        : " + ", ".join(f"{k}={v}" for k, v in inv_by_status.items()))
print(f"  Expected Total   : {out['invoices']['expected_xmr']} XMR")
print(f"  Received Total   : {out['invoices']['received_xmr']} XMR (overpaid={out['invoices']['overpaid_xmr']} XMR)")
print(f"  Swept Total      : {out['invoices']['swept_xmr']} XMR (fees={out['invoices']['sweep_fees_xmr']} XMR)")
print("  Webhooks         : " + (", ".join(f"{k}={v}" for k, v in wh_by_status.items()) or "none"))
print("  Sweep Attempts   : " + (", ".join(f"{k}={v}" for k, v in sw_by_status.items()) or "none"))
open_incidents = sw_by_status.get("REORGED", 0) + sw_by_status.get("PREPARED", 0)
if open_incidents > 0:
    print(f"  [!] Open/In-Flight Sweep Incidents: REORGED={sw_by_status.get('REORGED', 0)}, PREPARED={sw_by_status.get('PREPARED', 0)}")
PYEOF
}

cmd_audit_invariants() {
    load_env
    sqlite_ro_python "$ADMIN_JSON" "$REQUIRED_CONFIRMATIONS" <<'PYEOF'
import json, sqlite3, sys
from datetime import datetime, timezone, timedelta

db_path = sys.argv[1]
as_json = sys.argv[2] == "1"
req_confs = int(sys.argv[3])

conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
conn.row_factory = sqlite3.Row
conn.execute("PRAGMA busy_timeout = 5000;")
conn.execute("PRAGMA query_only = ON;")

violations = []
warnings = []
checks = []

def record(ok, name, detail):
    checks.append({"status": "PASS" if ok else "FAIL", "check": name, "detail": detail})
    if not ok:
        violations.append({"check": name, "detail": detail})

# 1) PRAGMA integrity_check
integrity_rows = [r[0] for r in conn.execute("PRAGMA integrity_check;").fetchall()]
record(integrity_rows == ["ok"], "pragma_integrity_check", "; ".join(integrity_rows))

# 2) PRAGMA foreign_key_check
fk_rows = conn.execute("PRAGMA foreign_key_check;").fetchall()
record(len(fk_rows) == 0, "pragma_foreign_key_check", f"{len(fk_rows)} foreign key violations")

# 3) AUDIT-005 Per-transfer amount equality between subaddress_transfers and invoice_transfers
row_mismatches = conn.execute(
    """
    SELECT st.invoice_id, st.txid, st.classification, st.amount_piconero AS sub_amt, it.amount_piconero AS inv_amt
    FROM subaddress_transfers st
    JOIN invoice_transfers it
      ON it.invoice_id = st.invoice_id AND it.txid = st.txid
    WHERE st.status != 'ORPHANED'
      AND it.orphaned = 0
      AND st.amount_piconero != it.amount_piconero
    """
).fetchall()
if row_mismatches:
    detail = "; ".join(
        f"inv={r['invoice_id']} tx={r['txid'][:12]}({r['classification']}): sub={r['sub_amt']} != inv={r['inv_amt']}"
        for r in row_mismatches
    )
    record(False, "audit_005_row_amount_conservation", detail)
else:
    record(True, "audit_005_row_amount_conservation", "All active/swept subaddress_transfers match invoice_transfers.amount_piconero")

# 4) AUDIT-005 Per-invoice balance conservation:
#    SUM(non-orphaned subaddress_transfers) == SUM(confirmed non-orphaned non-double-spent invoice_transfers)
#    for every invoice that has subaddress_transfers or is CONFIRMED/SETTLED/COMPLETED/SWEPT.
inv_mismatches = conn.execute(
    """
    SELECT
        i.id,
        i.order_id,
        i.status,
        COALESCE((
            SELECT SUM(st.amount_piconero)
            FROM subaddress_transfers st
            WHERE st.invoice_id = i.id AND st.status != 'ORPHANED'
        ), 0) AS sub_sum,
        COALESCE((
            SELECT SUM(it.amount_piconero)
            FROM invoice_transfers it
            WHERE it.invoice_id = i.id
              AND it.orphaned = 0
              AND it.double_spend_seen = 0
              AND it.in_pool = 0
              AND it.confirmations >= ?
        ), 0) AS inv_sum
    FROM invoices i
    WHERE i.status IN ('CONFIRMED', 'SETTLED', 'COMPLETED', 'SWEPT')
       OR EXISTS (SELECT 1 FROM subaddress_transfers st2 WHERE st2.invoice_id = i.id AND st2.status != 'ORPHANED')
    """,
    (req_confs,),
).fetchall()

sum_bad = [r for r in inv_mismatches if r["sub_sum"] != r["inv_sum"]]
if sum_bad:
    detail = "; ".join(
        f"inv={r['id']}({r['status']}): SUM(subaddress_transfers)={r['sub_sum']} != SUM(invoice_transfers)={r['inv_sum']}"
        for r in sum_bad
    )
    record(False, "audit_005_invoice_balance_conservation", detail)
else:
    record(True, "audit_005_invoice_balance_conservation", f"Verified {len(inv_mismatches)} invoice(s): SUM(subaddress_transfers) == SUM(confirmed non-orphaned invoice_transfers)")

# 5) Check for unresolved REORGED sweep incidents
reorged_sweeps = conn.execute(
    "SELECT id, invoice_id, error_message, updated_at FROM sweep_attempts WHERE status = 'REORGED'"
).fetchall()
if reorged_sweeps:
    detail = "; ".join(f"attempt={r['id']} inv={r['invoice_id']} ({r['error_message']})" for r in reorged_sweeps)
    record(False, "unresolved_reorged_sweeps", detail)
else:
    record(True, "unresolved_reorged_sweeps", "0 unresolved REORGED sweep incidents")

# 6) Check for stale PREPARED sweep attempts (> 10 minutes old)
prepared_sweeps = conn.execute(
    "SELECT id, invoice_id, created_at FROM sweep_attempts WHERE status = 'PREPARED'"
).fetchall()
stale_prepared = []
now = datetime.now(timezone.utc)
for r in prepared_sweeps:
    try:
        ts = datetime.fromisoformat(r["created_at"].replace("Z", "+00:00"))
        if now - ts > timedelta(minutes=10):
            stale_prepared.append(r)
    except Exception:
        stale_prepared.append(r)
if stale_prepared:
    detail = "; ".join(f"attempt={r['id']} inv={r['invoice_id']} created={r['created_at']}" for r in stale_prepared)
    record(False, "stale_prepared_sweeps", detail)
else:
    record(True, "stale_prepared_sweeps", f"0 stale PREPARED sweeps ({len(prepared_sweeps)} recent)")

# 7) Non-fatal operational warnings (FAILED webhooks, double-spend tainted invoices)
failed_wh = conn.execute("SELECT COUNT(*) FROM webhook_deliveries WHERE status = 'FAILED'").fetchone()[0]
if failed_wh > 0:
    warnings.append({"check": "failed_webhooks", "detail": f"{failed_wh} FAILED webhook delivery(ies) require operator retry"})
ds_invs = conn.execute("SELECT COUNT(*) FROM invoices WHERE double_spend_seen = 1").fetchone()[0]
if ds_invs > 0:
    warnings.append({"check": "double_spend_seen_invoices", "detail": f"{ds_invs} invoice(s) have sticky double_spend_seen = 1"})

conn.close()

ok = len(violations) == 0
if as_json:
    print(json.dumps({
        "ok": ok,
        "db_path": db_path,
        "checks": checks,
        "violations": violations,
        "warnings": warnings,
    }, indent=2))
else:
    print(f"=== SQLite Invariants Audit ({db_path}) ===")
    for c in checks:
        print(f"  [{c['status']:4s}] {c['check']:<40s} {c['detail']}")
    for w in warnings:
        print(f"  [WARN] {w['check']:<40s} {w['detail']}")
    print(f"\nResult: {'OK' if ok else 'FAILED'} ({len(violations)} violation(s), {len(warnings)} warning(s))")

sys.exit(0 if ok else 1)
PYEOF
}

cmd_backup() {
    load_env
    local dest_dir="${1:-$DATA_DIR/backups}"
    [[ -n "${DB_PATH:-}" ]] || die "DATABASE_URL is in-memory; cannot back up."
    [[ -f "$DB_PATH" ]] || die "SQLite database not found: $DB_PATH"

    mkdir -p "$dest_dir"
    chmod 700 "$dest_dir"

    local ts backup_file
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    backup_file="${dest_dir%/}/xmr_gateway.backup.${ts}.db"

    python3 - "$DB_PATH" "$backup_file" "$ADMIN_JSON" <<'PYEOF'
import json, os, sqlite3, sys

src_path, dst_path, as_json = sys.argv[1], sys.argv[2], sys.argv[3] == "1"

# Safe hot online backup via SQLite Online Backup API (WAL-safe, never raw file copy)
src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True, timeout=10.0)
src.execute("PRAGMA busy_timeout = 10000;")
dst = sqlite3.connect(dst_path)
try:
    with dst:
        src.backup(dst)
finally:
    src.close()
    dst.close()

os.chmod(dst_path, 0o600)

# Verify integrity of resulting backup file
chk = sqlite3.connect(f"file:{dst_path}?mode=ro", uri=True)
res = [r[0] for r in chk.execute("PRAGMA integrity_check;").fetchall()]
chk.close()

if res != ["ok"]:
    os.remove(dst_path)
    sys.stderr.write(f"Backup integrity check FAILED ({res}); removed corrupt backup {dst_path}\n")
    sys.exit(1)

size = os.path.getsize(dst_path)
if as_json:
    print(json.dumps({
        "ok": True,
        "source": src_path,
        "backup_file": dst_path,
        "size_bytes": size,
        "mode": "0600",
        "integrity_check": "ok",
    }, indent=2))
else:
    print(f"Backup created & verified: {dst_path} ({size} bytes, mode 0600, PRAGMA integrity_check=ok)")
PYEOF
}

cmd_shell() {
    load_env
    local rw=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --rw) rw=1; shift ;;
            *) die "Unknown shell option: $1" ;;
        esac
    done

    [[ -n "${DB_PATH:-}" ]] || die "DATABASE_URL is in-memory; no database file to open."
    [[ -f "$DB_PATH" ]] || die "SQLite database not found: $DB_PATH"

    if [[ "$rw" -eq 1 ]]; then
        log_warn "Opening SQLite in READ-WRITE mode! Direct manual writes can violate financial ledger invariants."
        confirm_dangerous_action "Open READ-WRITE SQLite shell on $DB_PATH" 1
        if command -v sqlite3 >/dev/null 2>&1; then
            exec sqlite3 -header -column "$DB_PATH"
        else
            die "sqlite3 binary is not installed; refusing ad-hoc RW shell."
        fi
    fi

    log_info "Opening strictly READ-ONLY SQLite shell on $DB_PATH..."
    if command -v sqlite3 >/dev/null 2>&1; then
        exec sqlite3 -header -column -readonly "$DB_PATH"
    else
        # Fallback pure-Python read-only SQL REPL (use -c so stdin remains interactive TTY)
        python3 -c '
import sqlite3, sys
db_path = sys.argv[1]
conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
conn.execute("PRAGMA query_only = ON;")
print(f"Python SQLite read-only shell ({db_path}). Type .quit to exit.")
while True:
    try:
        q = input("sqlite-ro> ").strip()
    except (EOFError, KeyboardInterrupt):
        break
    if not q or q in (".quit", ".exit"):
        if q in (".quit", ".exit"):
            break
        continue
    try:
        cur = conn.execute(q)
        if cur.description:
            cols = [d[0] for d in cur.description]
            print(" | ".join(cols))
            for row in cur.fetchall():
                print(" | ".join(str(x) for x in row))
    except Exception as exc:
        print(f"Error: {exc}")
conn.close()
' "$DB_PATH"
    fi
}

main() {
    parse_global_flags "$@"
    set -- "${ADMIN_REST_ARGS[@]}"
    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        stats)            cmd_stats "$@" ;;
        audit-invariants) cmd_audit_invariants "$@" ;;
        backup)           cmd_backup "$@" ;;
        shell)            cmd_shell "$@" ;;
        help|-h|--help)   usage ;;
        *)                die "Unknown db command: '$cmd'. Run './admin.sh db help'." ;;
    esac
}

main "$@"
