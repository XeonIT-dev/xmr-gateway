#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Admin Suite — Webhook Diagnostics & Retry Module (admin/webhooks.sh)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=admin/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    t webhooks.usage
}

cmd_list() {
    load_env
    local status_filter="" invoice_filter="" limit="25"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --status)     [[ $# -ge 2 ]] || die "--status requires a value"; status_filter="${2^^}"; shift 2 ;;
            --invoice-id) [[ $# -ge 2 ]] || die "--invoice-id requires a UUID"; invoice_filter="$2"; shift 2 ;;
            --limit)      [[ $# -ge 2 ]] || die "--limit requires a number"; limit="$2"; shift 2 ;;
            *) die "Unknown list option: $1" ;;
        esac
    done
    [[ "$limit" =~ ^[1-9][0-9]*$ ]] || die "--limit must be a positive integer."
    if [[ -n "$status_filter" ]]; then
        case "$status_filter" in
            PENDING|FAILED|DELIVERED) ;;
            *) die "Invalid webhook status '$status_filter'. Expected: PENDING | FAILED | DELIVERED" ;;
        esac
    fi

    sqlite_ro_python "$ADMIN_JSON" "$status_filter" "$invoice_filter" "$limit" <<'PYEOF'
import json, sqlite3, sys

db_path, as_json, status_f, inv_f, limit_s = sys.argv[1:6]
conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
conn.row_factory = sqlite3.Row
conn.execute("PRAGMA busy_timeout = 5000;")
conn.execute("PRAGMA query_only = ON;")

clauses, params = [], []
if status_f:
    clauses.append("status = ?")
    params.append(status_f)
if inv_f:
    clauses.append("invoice_id = ?")
    params.append(inv_f)
where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
params.append(int(limit_s))

rows = [dict(r) for r in conn.execute(
    f"""
    SELECT id, invoice_id, event_type, status, attempts, max_attempts,
           next_attempt_at, last_status_code, last_error, created_at, delivered_at
    FROM webhook_deliveries
    {where}
    ORDER BY created_at DESC
    LIMIT ?
    """,
    params,
).fetchall()]
conn.close()

if as_json == "1":
    print(json.dumps(rows, indent=2))
else:
    if not rows:
        print("No webhook deliveries matched.")
        sys.exit(0)
    print(f"{'WEBHOOK_ID':<36s} {'EVENT':<12s} {'STATUS':<9s} {'ATT':<5s} {'HTTP':>4s} {'INVOICE_ID':<36s} {'LAST_ERROR'}")
    for r in rows:
        att = f"{r['attempts']}/{r['max_attempts']}"
        code = str(r["last_status_code"]) if r["last_status_code"] is not None else "-"
        err = (r["last_error"] or "")[:50]
        print(f"{r['id']:<36s} {r['event_type']:<12s} {r['status']:<9s} {att:<5s} {code:>4s} {r['invoice_id']:<36s} {err}")
PYEOF
}

cmd_inspect() {
    load_env
    local webhook_id="${1:-}"
    [[ -n "$webhook_id" ]] || die "Usage: ./admin.sh webhooks inspect <webhook_id>"

    sqlite_ro_python "$ADMIN_JSON" "$webhook_id" <<'PYEOF'
import json, sqlite3, sys

db_path, as_json, wh_id = sys.argv[1:4]
conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
conn.row_factory = sqlite3.Row
conn.execute("PRAGMA busy_timeout = 5000;")
conn.execute("PRAGMA query_only = ON;")

row = conn.execute("SELECT * FROM webhook_deliveries WHERE id = ?", (wh_id,)).fetchone()
conn.close()

if not row:
    sys.stderr.write(f"Webhook delivery not found: {wh_id}\n")
    sys.exit(1)

d = dict(row)
if as_json == "1":
    try:
        d["payload"] = json.loads(d["payload_json"])
    except Exception:
        pass
    print(json.dumps(d, indent=2))
    sys.exit(0)

print(f"=== Webhook Delivery {d['id']} ===")
print(f"  invoice_id       : {d['invoice_id']}")
print(f"  event_type       : {d['event_type']}")
print(f"  dedupe_key       : {d['dedupe_key']}")
print(f"  target_url       : {d['target_url']}")
print(f"  status           : {d['status']} (attempts={d['attempts']}/{d['max_attempts']})")
print(f"  next_attempt_at  : {d['next_attempt_at']}")
print(f"  last_status_code : {d['last_status_code']}")
print(f"  last_error       : {d['last_error']}")
print(f"  signature_hex    : {d['signature_hex']}")
print(f"  created_at       : {d['created_at']}")
print(f"  delivered_at     : {d['delivered_at']}")
print("\nPayload JSON:")
try:
    print(json.dumps(json.loads(d["payload_json"]), indent=2))
except Exception:
    print(d["payload_json"])
PYEOF
}

cmd_retry() {
    load_env
    local webhook_id="${1:-}"
    [[ -n "$webhook_id" ]] || die "Usage: ./admin.sh webhooks retry <webhook_id>"

    gateway_api_call POST "/api/v1/webhooks/${webhook_id}/retry" operator || die "HTTP request failed."
    if [[ "$API_LAST_HTTP_CODE" != "200" ]]; then
        die "POST /api/v1/webhooks/${webhook_id}/retry failed (HTTP $API_LAST_HTTP_CODE): $API_LAST_BODY"
    fi

    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        printf '%s\n' "$API_LAST_BODY" | pretty_print_json
    else
        log_info "$(t webhooks.retry_done "$webhook_id")"
        printf '%s\n' "$API_LAST_BODY" | pretty_print_json
    fi
}

cmd_retry_invoice() {
    load_env
    local invoice_id="${1:-}"
    [[ -n "$invoice_id" ]] || die "Usage: ./admin.sh webhooks retry-invoice <invoice_id>"

    gateway_api_call POST "/api/v1/invoices/${invoice_id}/webhooks/retry" operator || die "HTTP request failed."
    if [[ "$API_LAST_HTTP_CODE" != "200" ]]; then
        die "POST /api/v1/invoices/${invoice_id}/webhooks/retry failed (HTTP $API_LAST_HTTP_CODE): $API_LAST_BODY"
    fi

    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        printf '%s\n' "$API_LAST_BODY" | pretty_print_json
    else
        log_info "$(t webhooks.retry_invoice_done "$invoice_id")"
        printf '%s\n' "$API_LAST_BODY" | pretty_print_json
    fi
}

cmd_verify_sig() {
    load_env
    local sig_header="${1:-}"
    local payload_src="${2:--}"
    [[ -n "$sig_header" ]] || die "Usage: ./admin.sh webhooks verify-sig <signature_hex> [payload_file|-]"
    [[ -n "${WEBHOOK_SECRET:-}" ]] || die "WEBHOOK_SECRET is not set in $ACTIVE_ENV_FILE."

    # Use `python3 -c` (not heredoc on stdin) so `payload_src == "-"` reads the caller's real stdin!
    python3 -c '
import hashlib, hmac, json, os, sys

sig_header = sys.argv[1].strip().lower()
payload_src = sys.argv[2]
as_json = sys.argv[3] == "1"
secret = os.environ["WEBHOOK_SECRET"].encode("utf-8")

if payload_src == "-":
    raw_body = sys.stdin.buffer.read()
else:
    with open(payload_src, "rb") as f:
        raw_body = f.read()

expected = hmac.new(secret, raw_body, hashlib.sha256).hexdigest()
valid = hmac.compare_digest(expected, sig_header)

if as_json:
    print(json.dumps({
        "valid": valid,
        "bytes_checked": len(raw_body),
        "presented_signature": sig_header,
        "expected_signature": expected if valid else None,
    }, indent=2))
else:
    if valid:
        print(f"VALID X-Signature-256 ({len(raw_body)} bytes verified)")
    else:
        print(f"INVALID X-Signature-256 ({len(raw_body)} bytes checked)", file=sys.stderr)

sys.exit(0 if valid else 1)
' "$sig_header" "$payload_src" "$ADMIN_JSON"
}

cmd_test_receiver() {
    load_env
    require_cmd python3
    local port="${1:-9000}"
    [[ "$port" =~ ^[1-9][0-9]*$ ]] && [[ "$port" -le 65535 ]] || die "Invalid port: $port"
    [[ -n "${WEBHOOK_SECRET:-}" ]] || die "WEBHOOK_SECRET is not set in $ACTIVE_ENV_FILE."

    log_info "$(t webhooks.receiver_start "$port")"
    python3 -u - "$port" <<'PYEOF'
import hashlib, hmac, json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1])
secret = os.environ["WEBHOOK_SECRET"].encode("utf-8")

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        sig = self.headers.get("X-Signature-256", "").strip().lower()
        event_hdr = self.headers.get("X-Webhook-Event", "?")
        delivery_id = self.headers.get("X-Delivery-Id", "?")
        ts_hdr = self.headers.get("X-Webhook-Timestamp", "?")
        expected = hmac.new(secret, raw, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected, sig):
            print(f"[REJECTED] {self.path} | event={event_hdr} | delivery={delivery_id} | invalid X-Signature-256", flush=True)
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"invalid signature"}')
            return

        print(f"[VERIFIED] {self.path} | event={event_hdr} | delivery={delivery_id} | ts={ts_hdr}", flush=True)
        try:
            print(json.dumps(json.loads(raw.decode("utf-8")), indent=2), flush=True)
        except Exception:
            print(raw.decode("utf-8", errors="replace"), flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
try:
    srv.serve_forever()
except KeyboardInterrupt:
    print("\nShutting down webhook test receiver...", flush=True)
finally:
    srv.server_close()
PYEOF
}

main() {
    parse_global_flags "$@"
    set -- "${ADMIN_REST_ARGS[@]}"
    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        list)          cmd_list "$@" ;;
        inspect)       cmd_inspect "$@" ;;
        retry)         cmd_retry "$@" ;;
        retry-invoice) cmd_retry_invoice "$@" ;;
        verify-sig)    cmd_verify_sig "$@" ;;
        test-receiver) cmd_test_receiver "$@" ;;
        help|-h|--help) usage ;;
        *)             die "$(t webhooks.unknown_cmd "$cmd")" ;;
    esac
}

main "$@"
