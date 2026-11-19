#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Admin Suite — Invoice & Sweep Incident Module (admin/invoices.sh)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=admin/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    t invoices.usage
}

cmd_create() {
    load_env
    local order_id="" amount_xmr="" amount_pico="" callback_url="" ttl_seconds="" qr_out=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --order-id)        [[ $# -ge 2 ]] || die "--order-id requires a value"; order_id="$2"; shift 2 ;;
            --amount-xmr)      [[ $# -ge 2 ]] || die "--amount-xmr requires a value"; amount_xmr="$2"; shift 2 ;;
            --amount-piconero) [[ $# -ge 2 ]] || die "--amount-piconero requires a value"; amount_pico="$2"; shift 2 ;;
            --callback-url)    [[ $# -ge 2 ]] || die "--callback-url requires a value"; callback_url="$2"; shift 2 ;;
            --ttl|--ttl-seconds) [[ $# -ge 2 ]] || die "--ttl requires a value"; ttl_seconds="$2"; shift 2 ;;
            --qr-out)          [[ $# -ge 2 ]] || die "--qr-out requires a path"; qr_out="$2"; shift 2 ;;
            -*) die "Unknown create option: $1" ;;
            *)
                if [[ -z "$order_id" ]]; then
                    order_id="$1"
                elif [[ -z "$amount_xmr" && -z "$amount_pico" ]]; then
                    amount_xmr="$1"
                elif [[ -z "$callback_url" ]]; then
                    callback_url="$1"
                elif [[ -z "$ttl_seconds" ]]; then
                    ttl_seconds="$1"
                else
                    die "Unexpected positional argument: $1"
                fi
                shift
                ;;
        esac
    done

    [[ -n "$order_id" ]] || die "order_id is required (--order-id)."
    if [[ -n "$amount_xmr" && -n "$amount_pico" ]]; then
        die "Specify either --amount-xmr or --amount-piconero, not both."
    fi
    if [[ -n "$amount_xmr" ]]; then
        amount_pico="$(xmr_to_piconero "$amount_xmr")" || exit 1
    fi
    [[ "$amount_pico" =~ ^[1-9][0-9]*$ ]] || die "Positive integer amount_piconero is required."
    if [[ -n "$ttl_seconds" && ! "$ttl_seconds" =~ ^[1-9][0-9]*$ ]]; then
        die "ttl_seconds must be a positive integer."
    fi

    local payload
    payload="$(python3 - "$order_id" "$amount_pico" "$callback_url" "$ttl_seconds" <<'PYEOF'
import json, sys
req = {
    "order_id": sys.argv[1],
    "amount_piconero": int(sys.argv[2]),
}
if sys.argv[3]:
    req["callback_url"] = sys.argv[3]
if sys.argv[4]:
    req["ttl_seconds"] = int(sys.argv[4])
print(json.dumps(req))
PYEOF
)"

    gateway_api_call POST "/api/v1/invoices" merchant "$payload" || die "HTTP request to POST /api/v1/invoices failed."
    if [[ "$API_LAST_HTTP_CODE" != "201" && "$API_LAST_HTTP_CODE" != "200" ]]; then
        die "POST /api/v1/invoices failed (HTTP $API_LAST_HTTP_CODE): $API_LAST_BODY"
    fi

    if [[ -n "$qr_out" ]]; then
        _PY_BODY="$API_LAST_BODY" python3 - "$qr_out" <<'PYEOF'
import base64, json, os, sys
inv = json.loads(os.environ["_PY_BODY"])
b64 = inv.get("qr_code_base64", "")
if b64:
    with open(sys.argv[1], "wb") as f:
        f.write(base64.b64decode(b64))
    os.chmod(sys.argv[1], 0o600)
PYEOF
        log_info "$(t invoices.qr_saved "$qr_out")"
    fi

    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        printf '%s\n' "$API_LAST_BODY" | pretty_print_json
        return 0
    fi

    _PY_BODY="$API_LAST_BODY" python3 - "$API_LAST_HTTP_CODE" <<'PYEOF'
import json, os, sys
code = sys.argv[1]
inv = json.loads(os.environ["_PY_BODY"])
print(f"=== Invoice Created (HTTP {code}) ===")
print(f"  invoice_id   : {inv.get('invoice_id')}")
print(f"  order_id     : {inv.get('order_id')}")
print(f"  status       : {inv.get('status')}")
print(f"  subaddress   : {inv.get('subaddress')} (account={inv.get('account_index')}, index={inv.get('address_index')})")
print(f"  amount       : {inv.get('amount_xmr_formatted')} XMR ({inv.get('amount_piconero')} piconero)")
print(f"  expires_at   : {inv.get('expires_at')}")
print(f"  monero_uri   : {inv.get('monero_uri')}")
PYEOF
}

cmd_get() {
    load_env
    local invoice_id="${1:-}"
    [[ -n "$invoice_id" ]] || die "Usage: ./admin.sh invoices get <invoice_id>"

    gateway_api_call GET "/api/v1/invoices/${invoice_id}" merchant || die "HTTP request failed."
    if [[ "$API_LAST_HTTP_CODE" != "200" ]]; then
        die "GET /api/v1/invoices/${invoice_id} failed (HTTP $API_LAST_HTTP_CODE): $API_LAST_BODY"
    fi

    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        printf '%s\n' "$API_LAST_BODY" | pretty_print_json
        return 0
    fi

    _PY_BODY="$API_LAST_BODY" python3 - <<'PYEOF'
import json, os, sys
inv = json.loads(os.environ["_PY_BODY"])
print(f"=== Invoice {inv.get('invoice_id')} ===")
print(f"  order_id          : {inv.get('order_id')}")
print(f"  status            : {inv.get('status')}")
print(f"  subaddress        : {inv.get('subaddress')} (idx={inv.get('address_index')})")
print(f"  expected / recv   : {inv.get('amount_xmr_formatted')} / {inv.get('received_xmr_formatted')} XMR")
print(f"  confirmations     : {inv.get('confirmations')} (unlocked={inv.get('unlocked')}, double_spend={inv.get('double_spend_seen')})")
print(f"  created / expires : {inv.get('created_at')} / {inv.get('expires_at')}")
if inv.get("sweep_tx_hashes"):
    print(f"  sweep_tx_hashes   : {', '.join(inv['sweep_tx_hashes'])}")
if inv.get("last_sweep_error"):
    print(f"  last_sweep_error  : {inv.get('last_sweep_error')}")
txs = inv.get("transfers", []) or []
if txs:
    print(f"\n  Incoming Transfers ({len(txs)}):")
    for t in txs:
        print(f"    - {t['txid'][:16]}... {t['amount_xmr_formatted']} XMR confs={t['confirmations']} unlocked={t['unlocked']} pool={t['in_pool']} orphaned={t.get('orphaned')} ds={t['double_spend_seen']}")
atts = inv.get("sweep_attempts", []) or []
if atts:
    print(f"\n  Sweep Attempts ({len(atts)}):")
    for a in atts:
        print(f"    - {a['id']} status={a['status']} txs={len(a.get('tx_hashes') or [])} action={a.get('resolution_action')} err={a.get('error_message')}")
PYEOF
}

cmd_list() {
    load_env
    local status_filter="" order_filter="" limit="25"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --status)   [[ $# -ge 2 ]] || die "--status requires a value"; status_filter="${2^^}"; shift 2 ;;
            --order-id) [[ $# -ge 2 ]] || die "--order-id requires a value"; order_filter="$2"; shift 2 ;;
            --limit)    [[ $# -ge 2 ]] || die "--limit requires a number"; limit="$2"; shift 2 ;;
            *) die "Unknown list option: $1" ;;
        esac
    done
    [[ "$limit" =~ ^[1-9][0-9]*$ ]] || die "--limit must be a positive integer."
    if [[ -n "$status_filter" ]]; then
        case "$status_filter" in
            PENDING|UNDERPAID|MEMPOOL|CONFIRMING|CONFIRMED|SETTLED|REORGED|COMPLETED|SWEPT|EXPIRED) ;;
            *) die "Invalid invoice status '$status_filter'." ;;
        esac
    fi

    sqlite_ro_python "$ADMIN_JSON" "$status_filter" "$order_filter" "$limit" <<'PYEOF'
import json, sqlite3, sys

db_path, as_json, status_f, order_f, limit_s = sys.argv[1:6]
conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
conn.row_factory = sqlite3.Row
conn.execute("PRAGMA busy_timeout = 5000;")
conn.execute("PRAGMA query_only = ON;")

clauses, params = [], []
if status_f:
    clauses.append("status = ?")
    params.append(status_f)
if order_f:
    clauses.append("order_id = ?")
    params.append(order_f)
where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
params.append(int(limit_s))

rows = [dict(r) for r in conn.execute(
    f"""
    SELECT id, order_id, address_index, status, amount_piconero, received_piconero,
           confirmations, unlocked, double_spend_seen, reorg_epoch, created_at, expires_at
    FROM invoices
    {where}
    ORDER BY created_at DESC
    LIMIT ?
    """,
    params,
).fetchall()]
conn.close()

def fx(p):
    w, f = divmod(int(p or 0), 10**12)
    return f"{w}.{f:012d}"

if as_json == "1":
    for r in rows:
        r["amount_xmr"] = fx(r["amount_piconero"])
        r["received_xmr"] = fx(r["received_piconero"])
    print(json.dumps(rows, indent=2))
else:
    if not rows:
        print("No invoices matched.")
        sys.exit(0)
    print(f"{'INVOICE_ID':<36s} {'ORDER_ID':<20s} {'STATUS':<11s} {'EXPECTED XMR':>16s} {'RECEIVED XMR':>16s} {'CONFS':>5s} {'EP':>2s} {'CREATED_AT'}")
    for r in rows:
        print(
            f"{r['id']:<36s} {r['order_id'][:20]:<20s} {r['status']:<11s} "
            f"{fx(r['amount_piconero']):>16s} {fx(r['received_piconero']):>16s} "
            f"{r['confirmations']:5d} {r['reorg_epoch']:2d} {r['created_at']}"
        )
PYEOF
}

cmd_inspect() {
    load_env
    local invoice_id="${1:-}"
    [[ -n "$invoice_id" ]] || die "Usage: ./admin.sh invoices inspect <invoice_id>"

    sqlite_ro_python "$ADMIN_JSON" "$invoice_id" <<'PYEOF'
import json, sqlite3, sys

db_path, as_json, inv_id = sys.argv[1:4]
conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
conn.row_factory = sqlite3.Row
conn.execute("PRAGMA busy_timeout = 5000;")
conn.execute("PRAGMA query_only = ON;")

inv = conn.execute("SELECT * FROM invoices WHERE id = ? OR order_id = ?", (inv_id, inv_id)).fetchone()
if not inv:
    sys.stderr.write(f"Invoice not found: {inv_id}\n")
    sys.exit(1)
inv_d = dict(inv)
real_id = inv_d["id"]

inv_txs = [dict(r) for r in conn.execute(
    "SELECT txid, amount_piconero, confirmations, unlocked, double_spend_seen, in_pool, orphaned, observed_at, updated_at FROM invoice_transfers WHERE invoice_id = ? ORDER BY id ASC",
    (real_id,),
).fetchall()]
sub_txs = [dict(r) for r in conn.execute(
    "SELECT id, txid, address_index, amount_piconero, confirmations, classification, status, swept, sweep_attempt_id, created_at FROM subaddress_transfers WHERE invoice_id = ? ORDER BY id ASC",
    (real_id,),
).fetchall()]
sweeps = [dict(r) for r in conn.execute(
    "SELECT id, address_index, destination_address, snapshot_txids_json, status, tx_hashes_json, swept_amount_piconero, fee_piconero, error_message, resolved_at, resolution_action, resolution_note, created_at, updated_at FROM sweep_attempts WHERE invoice_id = ? ORDER BY created_at ASC",
    (real_id,),
).fetchall()]
hooks = [dict(r) for r in conn.execute(
    "SELECT id, event_type, dedupe_key, target_url, status, attempts, max_attempts, next_attempt_at, last_status_code, last_error, created_at, delivered_at FROM webhook_deliveries WHERE invoice_id = ? ORDER BY created_at ASC",
    (real_id,),
).fetchall()]
conn.close()

def fx(p):
    if p is None:
        return "null"
    w, f = divmod(int(p), 10**12)
    return f"{w}.{f:012d}"

out = {
    "invoice": inv_d,
    "invoice_transfers": inv_txs,
    "subaddress_transfers": sub_txs,
    "sweep_attempts": sweeps,
    "webhook_deliveries": hooks,
}
if as_json == "1":
    print(json.dumps(out, indent=2))
    sys.exit(0)

print(f"=== Forensic Invoice Inspection: {real_id} ===")
print(f"  order_id       : {inv_d['order_id']}")
print(f"  status         : {inv_d['status']} (reorg_epoch={inv_d['reorg_epoch']})")
print(f"  subaddress     : {inv_d['subaddress']} (account={inv_d['account_index']}, idx={inv_d['address_index']})")
print(f"  expected / rx  : {fx(inv_d['amount_piconero'])} / {fx(inv_d['received_piconero'])} XMR")
print(f"  confs / unlock : {inv_d['confirmations']} / unlocked={bool(inv_d['unlocked'])} / ds={bool(inv_d['double_spend_seen'])}")
print(f"  sweep_tx_hashes: {inv_d['sweep_tx_hashes']} (amount={fx(inv_d['sweep_amount_piconero'])}, fee={fx(inv_d['sweep_fee_piconero'])})")
if inv_d.get("last_sweep_error"):
    print(f"  last_sweep_err : {inv_d['last_sweep_error']}")

print(f"\n--- invoice_transfers ({len(inv_txs)}) ---")
for t in inv_txs:
    print(f"  {t['txid']} | {fx(t['amount_piconero'])} XMR | confs={t['confirmations']} unlocked={t['unlocked']} pool={t['in_pool']} orphaned={t['orphaned']} ds={t['double_spend_seen']}")

print(f"\n--- subaddress_transfers ({len(sub_txs)}) ---")
for s in sub_txs:
    print(f"  #{s['id']} {s['txid']} | {fx(s['amount_piconero'])} XMR | {s['classification']} | {s['status']} swept={s['swept']} attempt={s['sweep_attempt_id']}")

print(f"\n--- sweep_attempts ({len(sweeps)}) ---")
for a in sweeps:
    print(f"  {a['id']} | {a['status']} | amt={fx(a['swept_amount_piconero'])} fee={fx(a['fee_piconero'])} | action={a['resolution_action']} | txs={a['tx_hashes_json']} | err={a['error_message']}")
    if a.get("resolution_note"):
        print(f"    note: {a['resolution_note']}")

print(f"\n--- webhook_deliveries ({len(hooks)}) ---")
for w in hooks:
    print(f"  {w['id']} | {w['event_type']:<12s} | {w['status']:<9s} | att={w['attempts']}/{w['max_attempts']} | http={w['last_status_code']} | err={w['last_error']}")
PYEOF
}

cmd_sweep() {
    load_env
    local invoice_id="${1:-}"
    [[ -n "$invoice_id" ]] || die "Usage: ./admin.sh invoices sweep <invoice_id>"

    confirm_dangerous_action "$(t invoices.confirm_sweep "$invoice_id")" 1

    gateway_api_call POST "/api/v1/invoices/${invoice_id}/sweep" operator || die "HTTP request failed."
    if [[ "$API_LAST_HTTP_CODE" != "200" ]]; then
        die "POST /api/v1/invoices/${invoice_id}/sweep failed (HTTP $API_LAST_HTTP_CODE): $API_LAST_BODY"
    fi

    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        printf '%s\n' "$API_LAST_BODY" | pretty_print_json
        return 0
    fi

    _PY_BODY="$API_LAST_BODY" python3 - <<'PYEOF'
import json, os, sys
r = json.loads(os.environ["_PY_BODY"])
print("=== Manual Sweep Complete ===")
print(f"  invoice_id : {r.get('invoice_id')} (order={r.get('order_id')})")
print(f"  status     : {r.get('status')}")
print(f"  swept      : {r.get('sweep_amount_xmr_formatted')} XMR (fee={r.get('sweep_fee_xmr_formatted')} XMR)")
print(f"  tx_hashes  : {', '.join(r.get('sweep_tx_hashes') or [])}")
print(f"  swept_at   : {r.get('swept_at')}")
PYEOF
}

cmd_resolve() {
    load_env
    local invoice_id="${1:-}"
    local action="${2:-}"
    [[ -n "$invoice_id" && -n "$action" ]] || die "Usage: ./admin.sh invoices resolve <invoice_id> <allow_resweep|mark_reconciled> --note <text> [--attempt-id UUID] [--tx-hash 64HEX] [--confirm-absent]"
    shift 2

    action="${action,,}"
    case "$action" in
        allow_resweep|mark_reconciled) ;;
        *) die "Invalid action '$action'. Expected: allow_resweep | mark_reconciled" ;;
    esac

    local attempt_id="" tx_hash="" note="" confirm_absent=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --attempt-id)     [[ $# -ge 2 ]] || die "--attempt-id requires a UUID"; attempt_id="$2"; shift 2 ;;
            --tx-hash|--replacement-tx-hash) [[ $# -ge 2 ]] || die "--tx-hash requires a 64-hex hash"; tx_hash="$2"; shift 2 ;;
            --note|--operator-note) [[ $# -ge 2 ]] || die "--note requires a non-empty audit note"; note="$2"; shift 2 ;;
            --confirm-absent|--confirm-absent-on-chain) confirm_absent=1; shift ;;
            *) die "Unknown resolve option: $1" ;;
        esac
    done

    [[ -n "${note// /}" ]] || die "--note (operator_note) is required and must be non-empty."
    if [[ "$action" == "allow_resweep" ]]; then
        if [[ -z "${MONERO_DAEMON_RPC_URL:-}" ]]; then
            log_warn "$(t invoices.daemon_rpc_warn "$ACTIVE_ENV_FILE")"
        fi
        if [[ "$confirm_absent" -ne 1 ]]; then
            die "action=allow_resweep requires --confirm-absent (sets confirm_absent_on_chain=true) after verifying no prior sweep tx exists on-chain."
        fi
    fi
    if [[ -n "$tx_hash" && ! "$tx_hash" =~ ^[0-9a-fA-F]{64}$ ]]; then
        die "--tx-hash must be exactly 64 hex characters."
    fi

    confirm_dangerous_action "$(t invoices.confirm_resolve "$invoice_id" "$action")" 1

    local payload
    payload="$(python3 - "$action" "$attempt_id" "$tx_hash" "$confirm_absent" "$note" <<'PYEOF'
import json, sys
action, attempt_id, tx_hash, confirm_absent, note = sys.argv[1:6]
req = {
    "action": action,
    "operator_note": note,
}
if attempt_id:
    req["attempt_id"] = attempt_id
if tx_hash:
    req["replacement_tx_hash"] = tx_hash
if action == "allow_resweep" or confirm_absent == "1":
    req["confirm_absent_on_chain"] = (confirm_absent == "1")
print(json.dumps(req))
PYEOF
)"

    gateway_api_call POST "/api/v1/invoices/${invoice_id}/sweep/resolve" operator "$payload" || die "HTTP request failed."
    if [[ "$API_LAST_HTTP_CODE" != "200" ]]; then
        die "POST /api/v1/invoices/${invoice_id}/sweep/resolve failed (HTTP $API_LAST_HTTP_CODE): $API_LAST_BODY"
    fi

    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        printf '%s\n' "$API_LAST_BODY" | pretty_print_json
        return 0
    fi

    _PY_BODY="$API_LAST_BODY" python3 - <<'PYEOF'
import json, os, sys
r = json.loads(os.environ["_PY_BODY"])
att = r.get("resolved_attempt", {}) or {}
print("=== Sweep Incident Resolved ===")
print(f"  invoice_id        : {r.get('invoice_id')}")
print(f"  invoice_status    : {r.get('status')}")
print(f"  attempt_id        : {att.get('id')}")
print(f"  attempt_status    : {att.get('status')}")
print(f"  resolution_action : {att.get('resolution_action')}")
print(f"  resolved_at       : {att.get('resolved_at')}")
print(f"  resolution_note   : {att.get('resolution_note')}")
PYEOF
}

main() {
    parse_global_flags "$@"
    set -- "${ADMIN_REST_ARGS[@]}"
    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        create)  cmd_create "$@" ;;
        get)     cmd_get "$@" ;;
        list)    cmd_list "$@" ;;
        inspect) cmd_inspect "$@" ;;
        sweep)   cmd_sweep "$@" ;;
        resolve) cmd_resolve "$@" ;;
        help|-h|--help) usage ;;
        *)       die "$(t invoices.unknown_cmd "$cmd")" ;;
    esac
}

main "$@"
