#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Admin Suite — Isolated Automated Test Suite (admin/test_admin.sh)
# ==============================================================================
# Runs entirely on temporary files (temp .env, temp SQLite WAL DB created from
# real migrations/*.sql, and a local Python mock HTTP/RPC server). Never reads
# or modifies real .env, data/, or wallet files.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ADMIN_SH="$REPO_ROOT/admin.sh"

PASS_COUNT=0
FAIL_COUNT=0
TMP_DIR="$(mktemp -d)"
MOCK_PID=""

cleanup() {
    if [[ -n "$MOCK_PID" ]] && kill -0 "$MOCK_PID" 2>/dev/null; then
        kill -TERM "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
    fi
    chmod -R u+w "$TMP_DIR" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    printf '\033[1;32m[PASS]\033[0m %s\n' "$*"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2
}

assert_eq() {
    local actual="$1"
    local expected="$2"
    local msg="$3"
    if [[ "$actual" == "$expected" ]]; then
        pass "$msg"
    else
        fail "$msg (expected='$expected', actual='$actual')"
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        pass "$msg"
    else
        fail "$msg (missing '$needle')"
    fi
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        pass "$msg"
    else
        fail "$msg (unexpectedly contained '$needle')"
    fi
}

# Isolate language state directory completely inside TMP_DIR (never touch real data/)
export ADMIN_STATE_DIR="$TMP_DIR/state"
unset ADMIN_LANG ADMIN_CLI_LANG ADMIN_ACTIVE_LANG ADMIN_LANG_SOURCE || true

# ==============================================================================
# 1. Syntax & static analysis (bash -n, optional shellcheck)
# ==============================================================================
printf '\n=== 1. Syntax & Lint Checks ===\n'
ALL_SCRIPTS=(
    "$REPO_ROOT/admin.sh"
    "$REPO_ROOT/admin/lib/common.sh"
    "$REPO_ROOT/admin/lib/i18n.sh"
    "$REPO_ROOT/admin/i18n/en.sh"
    "$REPO_ROOT/admin/i18n/ru.sh"
    "$REPO_ROOT/admin/service.sh"
    "$REPO_ROOT/admin/config.sh"
    "$REPO_ROOT/admin/wallet.sh"
    "$REPO_ROOT/admin/invoices.sh"
    "$REPO_ROOT/admin/webhooks.sh"
    "$REPO_ROOT/admin/db.sh"
    "$REPO_ROOT/admin/dev.sh"
    "$REPO_ROOT/admin/test_admin.sh"
    "$REPO_ROOT/scripts/install.sh"
    "$REPO_ROOT/deploy/systemd/render-wallet-rpc-conf.sh"
    "$REPO_ROOT/deploy/packaging/xmr-gateway-admin"
    "$REPO_ROOT/deploy/packaging/deb/postinst"
    "$REPO_ROOT/deploy/packaging/deb/prerm"
    "$REPO_ROOT/deploy/packaging/deb/postrm"
    "$REPO_ROOT/deploy/packaging/rpm/postinst.sh"
    "$REPO_ROOT/deploy/packaging/rpm/prerm.sh"
    "$REPO_ROOT/deploy/packaging/rpm/postrm.sh"
)
syntax_ok=1
for s in "${ALL_SCRIPTS[@]}"; do
    if ! bash -n "$s"; then
        fail "bash -n failed for $s"
        syntax_ok=0
    fi
done
[[ "$syntax_ok" -eq 1 ]] && pass "bash -n passed for all ${#ALL_SCRIPTS[@]} admin scripts"

if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -x -P "$REPO_ROOT" "${ALL_SCRIPTS[@]}"; then
        pass "shellcheck passed for all admin scripts"
    else
        fail "shellcheck reported warnings/errors"
    fi
else
    printf '[INFO] shellcheck not installed; skipped optional shellcheck pass\n'
fi

# ==============================================================================
# 2. Setup isolated temp SQLite WAL DB (applying ALL real migrations/*.sql)
#    and start local Python mock Gateway + Monero Wallet RPC server
# ==============================================================================
printf '\n=== 2. Provisioning Isolated Test Environment ===\n'
mkdir -p "$TMP_DIR/data/wallet" "$TMP_DIR/shim"
chmod 700 "$TMP_DIR/data" "$TMP_DIR/data/wallet"

API_KEY="test-merchant-api-key-0123456789abcdef0123456789abcdef"
OP_KEY="test-operator-api-key-fedcba9876543210fedcba9876543210"
WH_SECRET="test-webhook-hmac-secret-0123456789abcdef0123456789abcd"
RPC_USER="test_rpc_user"
RPC_PASS="test-rpc-secret-password-0123456789"

DB_FILE="$TMP_DIR/data/test_gateway.db"
REQ_LOG="$TMP_DIR/mock_requests.jsonl"
ARGV_LOG="$TMP_DIR/curl_argv.log"
PORT_FILE="$TMP_DIR/mock_port.txt"
: > "$REQ_LOG"
: > "$ARGV_LOG"

# Apply all real SQL migrations in exact filename order & enable WAL mode
python3 - "$DB_FILE" "$REPO_ROOT/migrations" <<'PYEOF'
import glob, os, sqlite3, sys

db_path, mig_dir = sys.argv[1], sys.argv[2]
conn = sqlite3.connect(db_path)
conn.execute("PRAGMA journal_mode = WAL;")
conn.execute("PRAGMA synchronous = FULL;")
conn.execute("PRAGMA foreign_keys = ON;")

for sql_file in sorted(glob.glob(os.path.join(mig_dir, "*.sql"))):
    with open(sql_file, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

# Seed realistic valid financial data (including OVERPAYMENT obeying AUDIT-005)
inv1 = "11111111-1111-4111-8111-111111111111"
wh1  = "22222222-2222-4222-8222-222222222222"
att1 = "33333333-3333-4333-8333-333333333333"
tx1  = "a" * 64

conn.execute(
    """
    INSERT INTO invoices (
        id, order_id, account_index, address_index, subaddress,
        amount_piconero, received_piconero, confirmations, unlocked, double_spend_seen,
        reorg_epoch, status, callback_url, monero_uri, qr_code_base64,
        sweep_tx_hashes, sweep_amount_piconero, sweep_fee_piconero,
        created_at, updated_at, expires_at, confirmed_at, settled_at, swept_at
    ) VALUES (
        ?, 'ord-overpay-1', 0, 1, '8subaddrTest1',
        1000000000000, 1350000000000, 12, 1, 0,
        0, 'SWEPT', 'https://merchant.example/hook', 'monero:8subaddrTest1?tx_amount=1.000000000000', '',
        '["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]', 1349900000000, 100000000,
        '2026-11-19T10:00:00Z', '2026-11-19T10:20:00Z', '2026-11-19T11:00:00Z',
        '2026-11-19T10:05:00Z', '2026-11-19T10:15:00Z', '2026-11-19T10:20:00Z'
    )
    """,
    (inv1,),
)
conn.execute(
    """
    INSERT INTO invoice_transfers (
        invoice_id, txid, amount_piconero, confirmations, unlocked,
        double_spend_seen, in_pool, orphaned, observed_at, updated_at
    ) VALUES (?, ?, 1350000000000, 12, 1, 0, 0, 0, '2026-11-19T10:05:00Z', '2026-11-19T10:15:00Z')
    """,
    (inv1, tx1),
)
conn.execute(
    """
    INSERT INTO sweep_attempts (
        id, invoice_id, address_index, destination_address, snapshot_txids_json,
        status, tx_hashes_json, swept_amount_piconero, fee_piconero,
        created_at, updated_at
    ) VALUES (
        ?, ?, 1, '4coldAddrTest', ?, 'CONFIRMED',
        '["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]',
        1349900000000, 100000000, '2026-11-19T10:19:00Z', '2026-11-19T10:20:00Z'
    )
    """,
    (att1, inv1, f'["{tx1}"]'),
)
conn.execute(
    """
    INSERT INTO subaddress_transfers (
        txid, invoice_id, address_index, amount_piconero, confirmations,
        classification, status, swept, sweep_attempt_id, created_at
    ) VALUES (?, ?, 1, 1350000000000, 12, 'OVERPAYMENT', 'SWEPT', 1, ?, '2026-11-19T10:05:00Z')
    """,
    (tx1, inv1, att1),
)
conn.execute(
    """
    INSERT INTO webhook_deliveries (
        id, invoice_id, event_type, dedupe_key, target_url,
        payload_json, signature_hex, status, attempts, max_attempts,
        next_attempt_at, last_status_code, last_error, created_at, updated_at
    ) VALUES (
        ?, ?, 'SWEPT', ?, 'https://merchant.example/hook',
        '{"event":"SWEPT","order_id":"ord-overpay-1"}', 'deadbeef', 'FAILED', 10, 10,
        '2026-11-19T10:25:00Z', 502, 'HTTP 502: bad gateway', '2026-11-19T10:20:00Z', '2026-11-19T10:25:00Z'
    )
    """,
    (wh1, inv1, f"{inv1}:SWEPT:0:bbbb"),
)
conn.commit()
conn.close()
for suffix in ("", "-wal", "-shm"):
    p = db_path + suffix
    if os.path.exists(p):
        os.chmod(p, 0o600)
PYEOF

# Start isolated mock HTTP server implementing Gateway API (/health RBAC, /api/v1/*) + Monero RPC (/json_rpc)
MOCK_API_KEY="$API_KEY" MOCK_OP_KEY="$OP_KEY" MOCK_REQ_LOG="$REQ_LOG" MOCK_PORT_FILE="$PORT_FILE" \
python3 -u - <<'PYEOF' &
import base64, json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_KEY = os.environ["MOCK_API_KEY"]
OP_KEY = os.environ["MOCK_OP_KEY"]
REQ_LOG = os.environ["MOCK_REQ_LOG"]
PORT_FILE = os.environ["MOCK_PORT_FILE"]
SAMPLE_PNG_B64 = base64.b64encode(b"\x89PNG\r\n\x1a\nFAKEPNG").decode("ascii")

class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _record(self, method, raw_body):
        entry = {
            "method": method,
            "path": self.path,
            "x_api_key": self.headers.get("X-API-Key"),
            "x_operator_key": self.headers.get("X-Operator-Key"),
            "body": raw_body.decode("utf-8", errors="replace"),
        }
        with open(REQ_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def _send(self, code, obj):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._record("GET", b"")
        if self.path == "/health":
            h_api = self.headers.get("X-API-Key")
            h_op = self.headers.get("X-Operator-Key")
            authed = (h_api in (API_KEY, OP_KEY)) or (h_op == OP_KEY)
            if authed:
                self._send(200, {
                    "status": "ok",
                    "service": "xmr-gateway",
                    "version": "0.1.3",
                    "database": "connected",
                    "monero_rpc": {"connected": True, "version": 196619, "error": None},
                    "auto_sweep_enabled": False,
                })
            else:
                self._send(200, {"status": "ok"})
            return

        if self.path.startswith("/api/v1/invoices/"):
            if self.headers.get("X-API-Key") not in (API_KEY, OP_KEY):
                self._send(401, {"error": "unauthorized"})
                return
            inv_id = self.path.split("/")[-1]
            self._send(200, {
                "invoice_id": inv_id,
                "order_id": "ord-overpay-1",
                "status": "SWEPT",
                "subaddress": "8subaddrTest1",
                "account_index": 0,
                "address_index": 1,
                "amount_piconero": 1000000000000,
                "amount_xmr_formatted": "1.000000000000",
                "received_piconero": 1350000000000,
                "received_xmr_formatted": "1.350000000000",
                "confirmations": 12,
                "unlocked": True,
                "double_spend_seen": False,
                "monero_uri": "monero:8subaddrTest1",
                "qr_code_base64": SAMPLE_PNG_B64,
                "sweep_tx_hashes": ["b" * 64],
                "sweep_amount_piconero": 1349900000000,
                "sweep_fee_piconero": 100000000,
                "last_sweep_error": None,
                "transfers": [],
                "sweep_attempts": [],
                "created_at": "2026-11-19T10:00:00Z",
                "updated_at": "2026-11-19T10:20:00Z",
                "expires_at": "2026-11-19T11:00:00Z",
            })
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        self._record("POST", raw)
        data = json.loads(raw.decode("utf-8")) if raw else {}

        if self.path == "/json_rpc":
            m = data.get("method")
            if m == "get_version":
                self._send(200, {"jsonrpc": "2.0", "id": "admin", "result": {"version": 196619}})
            elif m == "get_height":
                self._send(200, {"jsonrpc": "2.0", "id": "admin", "result": {"height": 3300000}})
            elif m == "get_info":
                self._send(200, {"jsonrpc": "2.0", "id": "admin", "result": {"height": 3300000, "target_height": 3300000, "synchronized": True}})
            elif m == "get_balance":
                self._send(200, {"jsonrpc": "2.0", "id": "admin", "result": {"balance": 1500000000000, "unlocked_balance": 1500000000000, "blocks_to_unlock": 0, "per_subaddress": []}})
            elif m == "get_address":
                self._send(200, {"jsonrpc": "2.0", "id": "admin", "result": {"address": "5primaryMockAddr", "addresses": [{"address_index": 0}]}})
            else:
                self._send(200, {"jsonrpc": "2.0", "id": "admin", "result": {}})
            return

        if self.path == "/api/v1/invoices":
            if self.headers.get("X-API-Key") not in (API_KEY, OP_KEY):
                self._send(401, {"error": "unauthorized"})
                return
            self._send(201, {
                "invoice_id": "44444444-4444-4444-8444-444444444444",
                "order_id": data["order_id"],
                "status": "PENDING",
                "subaddress": "8newSubaddrMock",
                "account_index": 0,
                "address_index": 2,
                "amount_piconero": data["amount_piconero"],
                "amount_xmr_formatted": "1.250000000000",
                "monero_uri": "monero:8newSubaddrMock?tx_amount=1.250000000000",
                "qr_code_base64": SAMPLE_PNG_B64,
                "created_at": "2026-11-19T12:00:00Z",
                "expires_at": "2026-11-19T13:00:00Z",
            })
            return

        # Operator endpoints MUST require OP_KEY
        op_presented = self.headers.get("X-Operator-Key") or self.headers.get("X-API-Key")
        if op_presented != OP_KEY:
            self._send(403 if op_presented == API_KEY else 401, {"error": "operator required"})
            return

        if self.path.endswith("/sweep"):
            self._send(200, {
                "invoice_id": "11111111-1111-4111-8111-111111111111",
                "order_id": "ord-overpay-1",
                "status": "SWEPT",
                "sweep_tx_hashes": ["c" * 64],
                "sweep_amount_piconero": 1000000000000,
                "sweep_amount_xmr_formatted": "1.000000000000",
                "sweep_fee_piconero": 100000000,
                "sweep_fee_xmr_formatted": "0.000100000000",
                "swept_at": "2026-11-19T12:05:00Z",
            })
            return

        if self.path.endswith("/sweep/resolve"):
            self._send(200, {
                "invoice_id": "11111111-1111-4111-8111-111111111111",
                "status": "SETTLED" if data.get("action") == "allow_resweep" else "SWEPT",
                "resolved_attempt": {
                    "id": "33333333-3333-4333-8333-333333333333",
                    "invoice_id": "11111111-1111-4111-8111-111111111111",
                    "address_index": 1,
                    "destination_address": "4coldAddrTest",
                    "status": "FAILED" if data.get("action") == "allow_resweep" else "RECONCILED",
                    "tx_hashes": [data["replacement_tx_hash"]] if data.get("replacement_tx_hash") else [],
                    "resolution_action": data.get("action"),
                    "resolution_note": data.get("operator_note"),
                    "resolved_at": "2026-11-19T12:06:00Z",
                    "created_at": "2026-11-19T10:19:00Z",
                    "updated_at": "2026-11-19T12:06:00Z",
                },
            })
            return

        if self.path.endswith("/retry"):
            self._send(200, {
                "retried_count": 1,
                "webhook_ids": ["22222222-2222-4222-8222-222222222222"],
                "scheduled_at": "2026-11-19T12:07:00Z",
            })
            return

        self._send(404, {"error": "not found"})

srv = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
with open(PORT_FILE, "w", encoding="utf-8") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
PYEOF
MOCK_PID=$!

for _ in $(seq 1 40); do
    [[ -s "$PORT_FILE" ]] && break
    sleep 0.1
done
MOCK_PORT="$(cat "$PORT_FILE")"
pass "Mock Gateway+RPC server started on 127.0.0.1:${MOCK_PORT}"

# Create isolated valid 0600 temp .env
TEST_ENV="$TMP_DIR/test.env"
cat > "$TEST_ENV" <<EOF
HOST=127.0.0.1
PORT=${MOCK_PORT}
DATABASE_URL=sqlite://${DB_FILE}
API_SECRET_KEY=${API_KEY}
OPERATOR_API_KEY=${OP_KEY}
WEBHOOK_SECRET=${WH_SECRET}
ALLOW_PRIVATE_WEBHOOKS=true
REQUIRE_HTTPS_WEBHOOKS=false
MONERO_NETWORK=stagenet
WALLET_MODE=view_only
ENABLE_AUTO_SWEEP=false
MONERO_RPC_URL=http://127.0.0.1:${MOCK_PORT}/json_rpc
MONERO_RPC_USER=${RPC_USER}
MONERO_RPC_PASS=${RPC_PASS}
MONERO_DAEMON_RPC_URL=http://127.0.0.1:${MOCK_PORT}/json_rpc
MONERO_DAEMON_RPC_USER=daemon_user
MONERO_DAEMON_RPC_PASS=daemon-secret-pass-0123456789
MONERO_VIEW_ONLY_ADDRESS=5primaryMockAddr
MONERO_VIEW_ONLY_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
REQUIRED_CONFIRMATIONS=2
SETTLEMENT_CONFIRMATIONS=10
SWEEP_PRIORITY=0
EOF
chmod 600 "$TEST_ENV"

# Create a curl wrapper shim that records EVERY CLI argv passed to curl (verifying zero secret leaks!)
REAL_CURL="$(command -v curl)"
cat > "$TMP_DIR/shim/curl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$ARGV_LOG"
exec "$REAL_CURL" "\$@"
EOF
chmod 700 "$TMP_DIR/shim/curl"

# ==============================================================================
# 3. Secret masking & zero-argv-leak tests
# ==============================================================================
printf '\n=== 3. Secret Masking & Zero-Argv-Leak Checks ===\n'
SHOW_OUT="$("$ADMIN_SH" --env "$TEST_ENV" config show)"
SHOW_JSON="$("$ADMIN_SH" --env "$TEST_ENV" --json config show)"
for secret in "$API_KEY" "$OP_KEY" "$WH_SECRET" "$RPC_PASS"; do
    assert_not_contains "$SHOW_OUT" "$secret" "config show masks secret (${secret:0:8}...)"
    assert_not_contains "$SHOW_JSON" "$secret" "config show --json masks secret (${secret:0:8}...)"
done

# ==============================================================================
# 4. API & RBAC wrappers (with curl shim active to inspect argv)
# ==============================================================================
printf '\n=== 4. API Wrappers, RBAC Headers & JSON Payloads ===\n'
QR_OUT="$TMP_DIR/invoice_qr.png"
CREATE_JSON="$(PATH="$TMP_DIR/shim:$PATH" "$ADMIN_SH" --env "$TEST_ENV" --json invoices create \
    --order-id "ord-test-125" --amount-xmr "1.25" --callback-url "http://127.0.0.1:9999/cb" --ttl 1800 --qr-out "$QR_OUT")"
assert_contains "$CREATE_JSON" '"amount_piconero": 1250000000000' "invoices create converts 1.25 XMR -> exact 1250000000000 piconero"
if [[ -f "$QR_OUT" ]]; then
    pass "invoices create wrote QR PNG file"
else
    fail "QR PNG missing"
fi
assert_eq "$(stat -c '%a' "$QR_OUT")" "600" "QR PNG file has 0600 permissions"

GET_OUT="$(PATH="$TMP_DIR/shim:$PATH" "$ADMIN_SH" --env "$TEST_ENV" --json invoices get "11111111-1111-4111-8111-111111111111")"
assert_contains "$GET_OUT" '"order_id": "ord-overpay-1"' "invoices get returns expected invoice JSON"

SWEEP_OUT="$(PATH="$TMP_DIR/shim:$PATH" "$ADMIN_SH" --env "$TEST_ENV" --yes --json invoices sweep "11111111-1111-4111-8111-111111111111")"
assert_contains "$SWEEP_OUT" '"status": "SWEPT"' "invoices sweep succeeds via operator header"

RESOLVE_ALLOW="$(PATH="$TMP_DIR/shim:$PATH" "$ADMIN_SH" --env "$TEST_ENV" --yes --json invoices resolve \
    "11111111-1111-4111-8111-111111111111" allow_resweep --confirm-absent --note "verified absent on synced node")"
assert_contains "$RESOLVE_ALLOW" '"resolution_action": "allow_resweep"' "invoices resolve allow_resweep works"

RECON_HASH="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
RESOLVE_RECON="$(PATH="$TMP_DIR/shim:$PATH" "$ADMIN_SH" --env "$TEST_ENV" --yes --json invoices resolve \
    "11111111-1111-4111-8111-111111111111" mark_reconciled --tx-hash "$RECON_HASH" --note "confirmed in cold wallet")"
assert_contains "$RESOLVE_RECON" '"resolution_action": "mark_reconciled"' "invoices resolve mark_reconciled works"

WH_RETRY="$(PATH="$TMP_DIR/shim:$PATH" "$ADMIN_SH" --env "$TEST_ENV" --json webhooks retry "22222222-2222-4222-8222-222222222222")"
assert_contains "$WH_RETRY" '"retried_count": 1' "webhooks retry succeeds via operator header"

WH_BATCH="$(PATH="$TMP_DIR/shim:$PATH" "$ADMIN_SH" --env "$TEST_ENV" --json webhooks retry-invoice "11111111-1111-4111-8111-111111111111")"
assert_contains "$WH_BATCH" '"retried_count": 1' "webhooks retry-invoice succeeds via operator header"

HRBAC_OUT="$(PATH="$TMP_DIR/shim:$PATH" "$ADMIN_SH" --env "$TEST_ENV" --json dev health-rbac)"
assert_contains "$HRBAC_OUT" '"ok": true' "dev health-rbac passes AUDIT-002 matrix"

WINFO_OUT="$(PATH="$TMP_DIR/shim:$PATH" "$ADMIN_SH" --env "$TEST_ENV" --json wallet info)"
assert_contains "$WINFO_OUT" '"balance_xmr": "1.500000000000"' "wallet info formats exact balance_xmr"

# Fail-closed check: wallet transfer refused in view_only mode
if "$ADMIN_SH" --env "$TEST_ENV" --yes wallet transfer "5destAddr" "0.1" >/dev/null 2>&1; then
    fail "wallet transfer MUST fail closed in WALLET_MODE=view_only"
else
    pass "wallet transfer fails closed in WALLET_MODE=view_only"
fi

# Verify mock request log: exact headers & JSON bodies!
python3 - "$REQ_LOG" "$API_KEY" "$OP_KEY" "$RECON_HASH" <<'PYEOF'
import json, sys
log_path, api_key, op_key, recon_hash = sys.argv[1:5]
reqs = [json.loads(l) for l in open(log_path, encoding="utf-8") if l.strip()]

def find(method, path):
    return [r for r in reqs if r["method"] == method and r["path"] == path]

c = find("POST", "/api/v1/invoices")[0]
assert c["x_api_key"] == api_key and c["x_operator_key"] is None, f"create auth mismatch: {c}"
cb = json.loads(c["body"])
assert cb == {"order_id": "ord-test-125", "amount_piconero": 1250000000000, "callback_url": "http://127.0.0.1:9999/cb", "ttl_seconds": 1800}, cb

g = find("GET", "/api/v1/invoices/11111111-1111-4111-8111-111111111111")[0]
assert g["x_api_key"] == api_key, g

sw = find("POST", "/api/v1/invoices/11111111-1111-4111-8111-111111111111/sweep")[0]
assert sw["x_operator_key"] == op_key and sw["x_api_key"] is None, sw

res = find("POST", "/api/v1/invoices/11111111-1111-4111-8111-111111111111/sweep/resolve")
assert len(res) == 2
r0 = json.loads(res[0]["body"])
assert res[0]["x_operator_key"] == op_key
assert r0["action"] == "allow_resweep" and r0["confirm_absent_on_chain"] is True and r0["operator_note"] == "verified absent on synced node", r0
r1 = json.loads(res[1]["body"])
assert r1["action"] == "mark_reconciled" and r1["replacement_tx_hash"] == recon_hash and r1["operator_note"] == "confirmed in cold wallet", r1

wr = find("POST", "/api/v1/webhooks/22222222-2222-4222-8222-222222222222/retry")[0]
assert wr["x_operator_key"] == op_key and wr["x_api_key"] is None, wr

wb = find("POST", "/api/v1/invoices/11111111-1111-4111-8111-111111111111/webhooks/retry")[0]
assert wb["x_operator_key"] == op_key and wb["x_api_key"] is None, wb
PYEOF
pass "Mock server verified exact RBAC headers (X-API-Key vs X-Operator-Key) and JSON request schemas"

# Verify ZERO secrets appeared in curl CLI argv!
ARGV_CONTENT="$(cat "$ARGV_LOG")"
if [[ -n "$ARGV_CONTENT" ]]; then
    pass "curl shim captured live invocations"
else
    fail "curl shim log unexpectedly empty"
fi
for secret in "$API_KEY" "$OP_KEY" "$WH_SECRET" "$RPC_PASS" "daemon-secret-pass-0123456789"; do
    assert_not_contains "$ARGV_CONTENT" "$secret" "zero argv leak for secret (${secret:0:8}...) in curl ps/cmdline"
done

# ==============================================================================
# 5. Webhook HMAC verify-sig tests (valid + invalid)
# ==============================================================================
printf '\n=== 5. Webhook HMAC Signature Verification ===\n'
PAYLOAD_FILE="$TMP_DIR/sample_webhook.json"
printf '{"event":"CONFIRMED","order_id":"ord-1","amount_piconero":1000}' > "$PAYLOAD_FILE"
VALID_SIG="$(python3 -c 'import hashlib,hmac,sys; print(hmac.new(sys.argv[1].encode(), open(sys.argv[2],"rb").read(), hashlib.sha256).hexdigest())' "$WH_SECRET" "$PAYLOAD_FILE")"

if "$ADMIN_SH" --env "$TEST_ENV" webhooks verify-sig "$VALID_SIG" "$PAYLOAD_FILE" >/dev/null; then
    pass "webhooks verify-sig accepts valid HMAC-SHA256 (file)"
else
    fail "webhooks verify-sig rejected valid HMAC-SHA256 (file)"
fi

if "$ADMIN_SH" --env "$TEST_ENV" webhooks verify-sig "$VALID_SIG" - < "$PAYLOAD_FILE" >/dev/null; then
    pass "webhooks verify-sig accepts valid HMAC-SHA256 (stdin)"
else
    fail "webhooks verify-sig rejected valid HMAC-SHA256 (stdin)"
fi

if "$ADMIN_SH" --env "$TEST_ENV" webhooks verify-sig "0000000000000000000000000000000000000000000000000000000000000000" "$PAYLOAD_FILE" >/dev/null 2>&1; then
    fail "webhooks verify-sig MUST reject invalid signature"
else
    pass "webhooks verify-sig rejects invalid signature (fail-closed)"
fi

# ==============================================================================
# 6. SQLite RO queries, db stats, db audit-invariants (valid + corrupted), db backup
# ==============================================================================
printf '\n=== 6. SQLite Stats, Invariants Audit & Hot Backup ===\n'
STATS_JSON="$("$ADMIN_SH" --env "$TEST_ENV" --json db stats)"
assert_contains "$STATS_JSON" '"received_xmr": "1.350000000000"' "db stats computes exact received_xmr"
assert_contains "$STATS_JSON" '"overpaid_xmr": "0.350000000000"' "db stats computes exact overpaid_xmr"
assert_contains "$STATS_JSON" '"FAILED": 1' "db stats reports FAILED webhook count"

INV_LIST="$("$ADMIN_SH" --env "$TEST_ENV" invoices list --status SWEPT)"
assert_contains "$INV_LIST" "ord-overpay-1" "invoices list reads SWEPT invoice from SQLite RO"

INV_INSPECT="$("$ADMIN_SH" --env "$TEST_ENV" invoices inspect "11111111-1111-4111-8111-111111111111")"
assert_contains "$INV_INSPECT" "OVERPAYMENT" "invoices inspect displays subaddress_transfers & sweep_attempts"

WH_LIST="$("$ADMIN_SH" --env "$TEST_ENV" webhooks list --status FAILED)"
assert_contains "$WH_LIST" "22222222-2222-4222-8222-222222222222" "webhooks list displays FAILED delivery"

WH_INSPECT="$("$ADMIN_SH" --env "$TEST_ENV" webhooks inspect "22222222-2222-4222-8222-222222222222")"
assert_contains "$WH_INSPECT" "HTTP 502: bad gateway" "webhooks inspect displays last_error and payload"

# Valid DB must PASS audit-invariants
if AUDIT_OK="$("$ADMIN_SH" --env "$TEST_ENV" --json db audit-invariants)"; then
    assert_contains "$AUDIT_OK" '"ok": true' "db audit-invariants PASSES on valid AUDIT-005 database"
else
    fail "db audit-invariants unexpectedly failed on valid database"
fi

# Backup valid DB and verify 0600 + integrity
BACKUP_JSON="$("$ADMIN_SH" --env "$TEST_ENV" --json db backup "$TMP_DIR/backups")"
assert_contains "$BACKUP_JSON" '"integrity_check": "ok"' "db backup creates verified backup"
BACKUP_PATH="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["backup_file"])' <<< "$BACKUP_JSON")"
assert_eq "$(stat -c '%a' "$BACKUP_PATH")" "600" "db backup enforces 0600 permissions"

# Corrupt subaddress_transfers to simulate pre-AUDIT-005 partial-delta bug -> MUST FAIL CLOSED
python3 - "$DB_FILE" <<'PYEOF'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("UPDATE subaddress_transfers SET amount_piconero = 350000000000 WHERE invoice_id = '11111111-1111-4111-8111-111111111111'")
c.commit()
c.close()
PYEOF

if AUDIT_BAD="$("$ADMIN_SH" --env "$TEST_ENV" --json db audit-invariants 2>&1)"; then
    fail "db audit-invariants MUST fail closed when AUDIT-005 balance conservation is violated"
else
    assert_contains "$AUDIT_BAD" "audit_005_row_amount_conservation" "db audit-invariants detects row amount conservation violation (fail-closed)"
    assert_contains "$AUDIT_BAD" "audit_005_invoice_balance_conservation" "db audit-invariants detects invoice sum conservation violation (fail-closed)"
fi

# Restore amount and inject unresolved REORGED sweep -> MUST FAIL CLOSED
python3 - "$DB_FILE" <<'PYEOF'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("UPDATE subaddress_transfers SET amount_piconero = 1350000000000 WHERE invoice_id = '11111111-1111-4111-8111-111111111111'")
c.execute("UPDATE sweep_attempts SET status = 'REORGED', error_message = 'SWEEP_REORG_DETECTED' WHERE id = '33333333-3333-4333-8333-333333333333'")
c.commit()
c.close()
PYEOF

if AUDIT_REORG="$("$ADMIN_SH" --env "$TEST_ENV" --json db audit-invariants 2>&1)"; then
    fail "db audit-invariants MUST fail closed on unresolved REORGED sweep incident"
else
    assert_contains "$AUDIT_REORG" "unresolved_reorged_sweeps" "db audit-invariants detects unresolved REORGED sweep (fail-closed)"
fi

# ==============================================================================
# 7. config doctor (valid + broken RBAC + loose perms) & Mainnet guard & rotate-keys
# ==============================================================================
printf '\n=== 7. config doctor, Mainnet Guard & rotate-keys ===\n'
if DOC_OK="$(PATH="$TMP_DIR/shim:$PATH" "$ADMIN_SH" --env "$TEST_ENV" --json config doctor)"; then
    assert_contains "$DOC_OK" '"ok": true' "config doctor PASSES on valid 0600 config with live mock /health & RPC"
else
    fail "config doctor unexpectedly failed on valid config: $DOC_OK"
fi

# Broken config: API_SECRET_KEY == OPERATOR_API_KEY (AUDIT-002 violation)
BAD_RBAC_ENV="$TMP_DIR/bad_rbac.env"
cp "$TEST_ENV" "$BAD_RBAC_ENV"
sed -i "s|^OPERATOR_API_KEY=.*|OPERATOR_API_KEY=${API_KEY}|" "$BAD_RBAC_ENV"
chmod 600 "$BAD_RBAC_ENV"

if DOC_BAD_RBAC="$("$ADMIN_SH" --env "$BAD_RBAC_ENV" --json config doctor 2>&1)"; then
    fail "config doctor MUST fail closed when API_SECRET_KEY == OPERATOR_API_KEY"
else
    assert_contains "$DOC_BAD_RBAC" "rbac_key_separation" "config doctor rejects API_SECRET_KEY == OPERATOR_API_KEY (AUDIT-002)"
fi

# Broken config: loose 0644 permissions on .env
BAD_PERM_ENV="$TMP_DIR/bad_perm.env"
cp "$TEST_ENV" "$BAD_PERM_ENV"
chmod 644 "$BAD_PERM_ENV"
if DOC_BAD_PERM="$("$ADMIN_SH" --env "$BAD_PERM_ENV" --json config doctor 2>&1)"; then
    fail "config doctor MUST fail closed when .env permissions are 0644"
else
    assert_contains "$DOC_BAD_PERM" "env_permissions" "config doctor rejects 0644 .env permissions"
fi

# Mainnet non-interactive guard (without --yes must refuse financial/destructive action)
MAINNET_ENV="$TMP_DIR/mainnet.env"
cp "$TEST_ENV" "$MAINNET_ENV"
sed -i "s|^MONERO_NETWORK=.*|MONERO_NETWORK=mainnet|" "$MAINNET_ENV"
chmod 600 "$MAINNET_ENV"

if MAINNET_BLOCK="$("$ADMIN_SH" --env "$MAINNET_ENV" invoices sweep "11111111-1111-4111-8111-111111111111" </dev/null 2>&1)"; then
    fail "Mainnet guard MUST refuse non-interactive sweep without --yes"
else
    assert_contains "$MAINNET_BLOCK" "[MAINNET]" "Mainnet guard prints [MAINNET] banner and refuses without --yes"
fi

# rotate-keys creates 0600 backup and rotates API_SECRET_KEY
ROT_ENV="$TMP_DIR/rotate.env"
cp "$TEST_ENV" "$ROT_ENV"
chmod 600 "$ROT_ENV"
ROT_JSON="$("$ADMIN_SH" --env "$ROT_ENV" --yes --json config rotate-keys api)"
assert_contains "$ROT_JSON" '"API_SECRET_KEY"' "config rotate-keys api reports rotated key"
ROT_BAK="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["backup_file"])' <<< "$ROT_JSON")"
assert_eq "$(stat -c '%a' "$ROT_BAK")" "600" "config rotate-keys backup has 0600 permissions"
NEW_API_VAL="$(grep '^API_SECRET_KEY=' "$ROT_ENV" | cut -d= -f2)"
if [[ "$NEW_API_VAL" != "$API_KEY" && ${#NEW_API_VAL} -eq 64 ]]; then
    pass "config rotate-keys generated fresh 64-hex API_SECRET_KEY"
else
    fail "config rotate-keys did not update API_SECRET_KEY properly"
fi

# ==============================================================================
# 8. i18n Dictionary Parity, Language Priority, RU/EN Output, --json Invariance & Guide
# ==============================================================================
printf '\n=== 8. i18n (RU/EN), --json Invariance & Guides ===\n'

# 8a) 100% exact key parity & non-empty values between I18N_EN and I18N_RU
if (
    # shellcheck source=admin/i18n/en.sh
    source "$REPO_ROOT/admin/i18n/en.sh"
    # shellcheck source=admin/i18n/ru.sh
    source "$REPO_ROOT/admin/i18n/ru.sh"
    missing_in_ru=0
    extra_in_ru=0
    empty_vals=0
    for k in "${!I18N_EN[@]}"; do
        if [[ -z "${I18N_RU[$k]+x}" ]]; then
            printf 'Missing key in I18N_RU: %s\n' "$k" >&2
            missing_in_ru=$((missing_in_ru + 1))
        fi
        if [[ -z "${I18N_EN[$k]}" ]]; then
            printf 'Empty value in I18N_EN: %s\n' "$k" >&2
            empty_vals=$((empty_vals + 1))
        fi
    done
    for k in "${!I18N_RU[@]}"; do
        if [[ -z "${I18N_EN[$k]+x}" ]]; then
            printf 'Extra key in I18N_RU: %s\n' "$k" >&2
            extra_in_ru=$((extra_in_ru + 1))
        fi
        if [[ -z "${I18N_RU[$k]}" ]]; then
            printf 'Empty value in I18N_RU: %s\n' "$k" >&2
            empty_vals=$((empty_vals + 1))
        fi
    done
    [[ "$missing_in_ru" -eq 0 && "$extra_in_ru" -eq 0 && "$empty_vals" -eq 0 && "${#I18N_EN[@]}" -gt 50 ]]
); then
    pass "100% key parity and non-empty values between I18N_EN and I18N_RU"
else
    fail "I18N_EN and I18N_RU dictionary parity check failed"
fi

# 8b) Language resolution priority: --lang > ADMIN_LANG > saved file > locale, fail-closed on invalid
if "$ADMIN_SH" --lang fr help >/dev/null 2>&1; then
    fail "--lang fr MUST fail closed"
else
    pass "--lang fr fails closed"
fi

if ADMIN_LANG=de "$ADMIN_SH" help >/dev/null 2>&1; then
    fail "ADMIN_LANG=de MUST fail closed"
else
    pass "ADMIN_LANG=de fails closed"
fi

# Save 'ru' via `./admin.sh lang ru` -> stored in $ADMIN_STATE_DIR/.admin_lang (0600)
"$ADMIN_SH" lang ru >/dev/null
STATE_LANG_FILE="$ADMIN_STATE_DIR/.admin_lang"
if [[ -f "$STATE_LANG_FILE" ]]; then
    pass "lang ru created isolated .admin_lang state file"
else
    fail ".admin_lang missing"
fi
assert_eq "$(stat -c '%a' "$STATE_LANG_FILE")" "600" ".admin_lang has 0600 permissions"

LANG_FILE_JSON="$("$ADMIN_SH" --json lang show)"
assert_contains "$LANG_FILE_JSON" '"language": "ru"' "lang show reads saved 'ru' from file"
assert_contains "$LANG_FILE_JSON" '"source": "file"' "lang show reports source=file"

# ADMIN_LANG overrides saved file
LANG_ENV_JSON="$(ADMIN_LANG=en "$ADMIN_SH" --json lang show)"
assert_contains "$LANG_ENV_JSON" '"language": "en"' "ADMIN_LANG=en overrides saved file"
assert_contains "$LANG_ENV_JSON" '"source": "env"' "lang show reports source=env"

# --lang flag overrides ADMIN_LANG and saved file
LANG_FLAG_JSON="$(ADMIN_LANG=en "$ADMIN_SH" --lang ru --json lang show)"
assert_contains "$LANG_FLAG_JSON" '"language": "ru"' "--lang ru overrides ADMIN_LANG=en"
assert_contains "$LANG_FLAG_JSON" '"source": "flag"' "lang show reports source=flag"

# Restore valid DB state before comparing RU vs EN human & --json outputs
python3 - "$DB_FILE" <<'PYEOF'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("UPDATE subaddress_transfers SET amount_piconero = 1350000000000 WHERE invoice_id = '11111111-1111-4111-8111-111111111111'")
c.execute("UPDATE sweep_attempts SET status = 'CONFIRMED', error_message = NULL WHERE id = '33333333-3333-4333-8333-333333333333'")
c.commit()
c.close()
PYEOF

# 8c) Verify real localized RU vs EN output across key commands
HELP_EN="$("$ADMIN_SH" --lang en help)"
HELP_RU="$("$ADMIN_SH" --lang ru help)"
assert_contains "$HELP_EN" "xmr-gateway Admin Control Center" "--lang en help outputs English"
assert_contains "$HELP_RU" "Панель управления xmr-gateway" "--lang ru help outputs Russian"

SHOW_EN="$("$ADMIN_SH" --env "$TEST_ENV" --lang en config show)"
SHOW_RU="$("$ADMIN_SH" --env "$TEST_ENV" --lang ru config show)"
assert_contains "$SHOW_EN" "Active xmr-gateway Configuration" "config show EN localized"
assert_contains "$SHOW_RU" "Активная конфигурация xmr-gateway" "config show RU localized"

DOC_EN="$("$ADMIN_SH" --env "$TEST_ENV" --lang en config doctor)"
DOC_RU="$("$ADMIN_SH" --env "$TEST_ENV" --lang ru config doctor)"
assert_contains "$DOC_EN" "Summary:" "config doctor EN localized"
assert_contains "$DOC_RU" "Диагностика безопасности xmr-gateway" "config doctor RU localized"

STATS_EN="$("$ADMIN_SH" --env "$TEST_ENV" --lang en db stats)"
STATS_RU="$("$ADMIN_SH" --env "$TEST_ENV" --lang ru db stats)"
assert_contains "$STATS_EN" "SQLite Database Stats" "db stats EN localized"
assert_contains "$STATS_RU" "Статистика БД SQLite" "db stats RU localized"

AUD_EN="$("$ADMIN_SH" --env "$TEST_ENV" --lang en db audit-invariants)"
AUD_RU="$("$ADMIN_SH" --env "$TEST_ENV" --lang ru db audit-invariants)"
assert_contains "$AUD_EN" "SQLite Invariants Audit" "db audit-invariants EN localized"
assert_contains "$AUD_RU" "Аудит инвариантов SQLite" "db audit-invariants RU localized"

# 8d) Strict byte-for-byte --json invariance between --lang en and --lang ru
for subcmd in "config show" "db stats" "db audit-invariants" "invoices list"; do
    # shellcheck disable=SC2086
    out_en="$("$ADMIN_SH" --env "$TEST_ENV" --lang en --json $subcmd)"
    # shellcheck disable=SC2086
    out_ru="$("$ADMIN_SH" --env "$TEST_ENV" --lang ru --json $subcmd)"
    python3 -c 'import json, sys; json.loads(sys.stdin.read())' <<< "$out_en"
    assert_eq "$out_ru" "$out_en" "--json output for '$subcmd' is byte-for-byte identical between EN and RU"
done

# 8e) Guide files & `./admin.sh guide --path`
GUIDE_EN_PATH="$("$ADMIN_SH" --lang en guide --path)"
GUIDE_RU_PATH="$("$ADMIN_SH" --lang ru guide --path)"
assert_eq "$GUIDE_EN_PATH" "$REPO_ROOT/admin/GUIDE_EN.md" "guide --path resolves GUIDE_EN.md for --lang en"
assert_eq "$GUIDE_RU_PATH" "$REPO_ROOT/admin/GUIDE_RU.md" "guide --path resolves GUIDE_RU.md for --lang ru"
if [[ -s "$GUIDE_EN_PATH" ]]; then
    pass "admin/GUIDE_EN.md exists and is non-empty"
else
    fail "admin/GUIDE_EN.md missing or empty"
fi
if [[ -s "$GUIDE_RU_PATH" ]]; then
    pass "admin/GUIDE_RU.md exists and is non-empty"
else
    fail "admin/GUIDE_RU.md missing or empty"
fi

# ==============================================================================
# 9. Installer (scripts/install.sh), Read-Only System Install, YAML & Packaging Metadata
# ==============================================================================
printf '\n=== 9. Installer, Read-Only System Install, YAML & Packaging ===\n'

INSTALL_SH="$REPO_ROOT/scripts/install.sh"
if HELP_INST="$("$INSTALL_SH" --help)"; then
    assert_contains "$HELP_INST" "--method auto|deb|rpm|tarball" "install.sh --help displays usage"
else
    fail "install.sh --help failed"
fi

DRY_DEB="$("$INSTALL_SH" --dry-run --method deb --version v0.1.3)"
assert_contains "$DRY_DEB" "xmr-gateway_0.1.3_" "install.sh --dry-run --method deb computes .deb artifact"
assert_contains "$DRY_DEB" "SHA256SUMS" "install.sh --dry-run includes SHA256SUMS check"

DRY_RPM="$("$INSTALL_SH" --dry-run --method rpm --version v0.1.3)"
assert_contains "$DRY_RPM" "xmr-gateway-0.1.3-1." "install.sh --dry-run --method rpm computes .rpm artifact"

DRY_TAR="$("$INSTALL_SH" --dry-run --method tarball --version v0.1.3 --prefix /opt/xmr-custom --require-gpg)"
assert_contains "$DRY_TAR" "xmr-gateway-v0.1.3-linux-" "install.sh --dry-run --method tarball computes tarball artifact"
assert_contains "$DRY_TAR" "/opt/xmr-custom" "install.sh --dry-run --prefix applied"
assert_contains "$DRY_TAR" "REQUIRED (SHA256SUMS.asc)" "install.sh --require-gpg reflected in plan"

# Fail-closed validation checks on scripts/install.sh
if "$INSTALL_SH" --dry-run --method invalid_pkg >/dev/null 2>&1; then
    fail "install.sh MUST fail closed on invalid --method"
else
    pass "install.sh fails closed on invalid --method"
fi

for bad_ver in "../etc/passwd" "v1.0;id" "1.2.3" "v1.0.0/evil"; do
    if "$INSTALL_SH" --dry-run --version "$bad_ver" >/dev/null 2>&1; then
        fail "install.sh MUST fail closed on invalid --version '$bad_ver'"
    else
        pass "install.sh fails closed on invalid --version '$bad_ver'"
    fi
done

if "$INSTALL_SH" --dry-run --method tarball --prefix "relative/path" >/dev/null 2>&1; then
    fail "install.sh MUST fail closed on relative --prefix"
else
    pass "install.sh fails closed on relative --prefix"
fi

# Read-only system installation simulation (e.g. /usr/share/xmr-gateway)
RO_INSTALL="$TMP_DIR/ro_install"
XDG_STATE="$TMP_DIR/xdg_state"
mkdir -p "$RO_INSTALL/admin" "$XDG_STATE"
cp "$REPO_ROOT/admin.sh" "$RO_INSTALL/admin.sh"
cp -a "$REPO_ROOT/admin/lib" "$REPO_ROOT/admin/i18n" "$REPO_ROOT/admin/config.sh" "$RO_INSTALL/admin/"
chmod -R a-w "$RO_INSTALL"

if RO_OUT="$(env -u ADMIN_STATE_DIR -u ADMIN_LANG XDG_STATE_HOME="$XDG_STATE" "$RO_INSTALL/admin.sh" --env "$TEST_ENV" lang ru 2>&1)"; then
    pass "read-only admin.sh saves language outside read-only install dir"
else
    fail "read-only admin.sh failed to save language: $RO_OUT"
fi
RO_LANG_FILE="$XDG_STATE/xmr-gateway/.admin_lang"
if [[ -f "$RO_LANG_FILE" ]]; then
    pass "read-only admin.sh created XDG .admin_lang"
else
    fail "XDG .admin_lang missing"
fi
assert_eq "$(stat -c '%a' "$RO_LANG_FILE")" "600" "XDG .admin_lang has 0600 permissions"
if RO_SHOW="$(env -u ADMIN_STATE_DIR -u ADMIN_LANG XDG_STATE_HOME="$XDG_STATE" "$RO_INSTALL/admin.sh" --env "$TEST_ENV" config show)"; then
    assert_contains "$RO_SHOW" "Активная конфигурация xmr-gateway" "read-only admin.sh reads XDG saved Russian language & config"
else
    fail "read-only admin.sh config show failed"
fi

# Verify service systemd install-dry-run alignment with deploy/systemd/
SYS_PLAN="$("$ADMIN_SH" --env "$TEST_ENV" service systemd install-dry-run)"
assert_contains "$SYS_PLAN" "/etc/xmr-gateway/.env" "service systemd dry-run aligned with /etc/xmr-gateway/.env"
assert_contains "$SYS_PLAN" "xmr-gateway-backup.timer" "service systemd dry-run includes backup timer"

# Validate YAML files & Cargo.toml deb/rpm packaging asset paths
python3 - "$REPO_ROOT" <<'PYEOF'
import os, sys, tomllib

repo = sys.argv[1]

# 1) YAML syntax validation
try:
    import yaml
except ImportError:
    yaml = None

yaml_files = [
    ".github/workflows/ci.yml",
    ".github/workflows/security.yml",
    ".github/workflows/release.yml",
    "deploy/docker/docker-compose.yml",
]
for rel in yaml_files:
    p = os.path.join(repo, rel)
    assert os.path.isfile(p), f"Missing YAML file: {rel}"
    with open(p, "r", encoding="utf-8") as f:
        raw = f.read()
    if yaml is not None:
        doc = yaml.safe_load(raw)
        assert isinstance(doc, dict) and len(doc) > 0, f"Empty/invalid YAML root in {rel}"

# 2) Cargo.toml [package.metadata.deb] & [package.metadata.generate-rpm] asset existence check
with open(os.path.join(repo, "Cargo.toml"), "rb") as f:
    cargo = tomllib.load(f)

deb = cargo["package"]["metadata"]["deb"]
rpm = cargo["package"]["metadata"]["generate-rpm"]

assert os.path.isdir(os.path.join(repo, deb["maintainer-scripts"])), "deb maintainer-scripts dir missing"
for entry in deb["assets"]:
    src = entry[0]
    if src == "target/release/xmr-gateway":
        continue
    assert os.path.exists(os.path.join(repo, src)), f"deb asset missing: {src}"

for entry in rpm["assets"]:
    src = entry["source"]
    if src == "target/release/xmr-gateway":
        continue
    assert os.path.exists(os.path.join(repo, src)), f"rpm asset missing: {src}"

for key in ("post_install_script", "pre_uninstall_script", "post_uninstall_script"):
    script_path = rpm[key]
    assert os.path.isfile(os.path.join(repo, script_path)), f"rpm {key} missing: {script_path}"
PYEOF
pass "YAML workflows/compose and Cargo.toml deb/rpm packaging metadata validated cleanly"

# ==============================================================================
# 10. External Audit Hardening Checks (XMR-AUDIT-003 / 004 / 005 / 006)
# ==============================================================================
printf '\n=== 10. External Audit Hardening Checks ===\n'

# 10a) XMR-AUDIT-005: no --rpc-login in argv in start.sh, admin/service.sh, or demo-stagenet.sh
for rpc_script in "$REPO_ROOT/start.sh" "$REPO_ROOT/admin/service.sh" "$REPO_ROOT/demo-stagenet.sh"; do
    rel_name="${rpc_script#"$REPO_ROOT"/}"
    if grep -vE '^[[:space:]]*#' "$rpc_script" | grep -q -- '--rpc-login'; then
        fail "XMR-AUDIT-005: $rel_name still passes --rpc-login in process argv"
    else
        pass "XMR-AUDIT-005: $rel_name passes zero --rpc-login flags in argv"
    fi
    if grep -vE '^[[:space:]]*#' "$rpc_script" | grep -q -- '--config-file'; then
        pass "XMR-AUDIT-005: $rel_name passes --config-file for monero-wallet-rpc"
    else
        fail "XMR-AUDIT-005: $rel_name missing --config-file for monero-wallet-rpc"
    fi
done

# 10b) XMR-AUDIT-004: config doctor fails closed on hot_wallet without OPERATOR_API_KEY
HOT_NO_OP_ENV="$TMP_DIR/hot_no_op.env"
cat > "$HOT_NO_OP_ENV" <<EOF
HOST=127.0.0.1
PORT=${MOCK_PORT}
DATABASE_URL=sqlite://${DB_FILE}
API_SECRET_KEY=${API_KEY}
WEBHOOK_SECRET=${WH_SECRET}
ALLOW_PRIVATE_WEBHOOKS=true
REQUIRE_HTTPS_WEBHOOKS=false
MONERO_NETWORK=stagenet
WALLET_MODE=hot_wallet
ENABLE_AUTO_SWEEP=false
ALLOW_HOT_WALLET_WITHOUT_SWEEP=true
MONERO_RPC_URL=http://127.0.0.1:${MOCK_PORT}/json_rpc
MONERO_RPC_USER=rpc_user
MONERO_RPC_PASS=${RPC_PASS}
ALLOW_UNAUTHENTICATED_RPC=false
REQUIRED_CONFIRMATIONS=2
SETTLEMENT_CONFIRMATIONS=10
SWEEP_PRIORITY=0
EOF
chmod 600 "$HOT_NO_OP_ENV"
HOT_DOC_JSON=""
if HOT_DOC_JSON="$("$ADMIN_SH" --env "$HOT_NO_OP_ENV" --json config doctor 2>&1)"; then
    fail "XMR-AUDIT-004: config doctor MUST fail closed when hot_wallet lacks OPERATOR_API_KEY"
else
    assert_contains "$HOT_DOC_JSON" "OPERATOR_API_KEY is required" "XMR-AUDIT-004: config doctor rejects hot_wallet without OPERATOR_API_KEY"
fi

# 10c) XMR-AUDIT-006: config doctor FAILS CLOSED on mainnet cleartext public HTTP webhooks
MAINNET_HTTP_ENV="$TMP_DIR/mainnet_http.env"
cat > "$MAINNET_HTTP_ENV" <<EOF
HOST=127.0.0.1
PORT=${MOCK_PORT}
DATABASE_URL=sqlite://${DB_FILE}
API_SECRET_KEY=${API_KEY}
OPERATOR_API_KEY=${OP_KEY}
WEBHOOK_SECRET=${WH_SECRET}
ALLOW_PRIVATE_WEBHOOKS=false
REQUIRE_HTTPS_WEBHOOKS=false
MONERO_NETWORK=mainnet
WALLET_MODE=view_only
ENABLE_AUTO_SWEEP=false
MONERO_RPC_URL=http://127.0.0.1:${MOCK_PORT}/json_rpc
MONERO_RPC_USER=rpc_user
MONERO_RPC_PASS=${RPC_PASS}
ALLOW_UNAUTHENTICATED_RPC=false
REQUIRED_CONFIRMATIONS=10
SETTLEMENT_CONFIRMATIONS=10
SWEEP_PRIORITY=0
EOF
chmod 600 "$MAINNET_HTTP_ENV"
MAINNET_DOC_JSON=""
if MAINNET_DOC_JSON="$("$ADMIN_SH" --env "$MAINNET_HTTP_ENV" --json config doctor 2>&1)"; then
    fail "XMR-AUDIT-006: config doctor MUST fail closed on mainnet ALLOW_PRIVATE_WEBHOOKS=false + REQUIRE_HTTPS_WEBHOOKS=false"
else
    assert_contains "$MAINNET_DOC_JSON" '"status": "FAIL"' "XMR-AUDIT-006: config doctor reports FAIL on mainnet public HTTP webhooks"
    assert_contains "$MAINNET_DOC_JSON" "XMR-AUDIT-006" "XMR-AUDIT-006: config doctor cites mainnet HTTPS policy failure"
fi

# When REQUIRE_HTTPS_WEBHOOKS is omitted on mainnet + ALLOW_PRIVATE_WEBHOOKS=false, default is true (PASS)
MAINNET_DEF_ENV="$TMP_DIR/mainnet_default_https.env"
grep -v '^REQUIRE_HTTPS_WEBHOOKS=' "$MAINNET_HTTP_ENV" > "$MAINNET_DEF_ENV"
chmod 600 "$MAINNET_DEF_ENV"
MAINNET_DEF_DOC="$("$ADMIN_SH" --env "$MAINNET_DEF_ENV" --json config doctor)"
assert_contains "$MAINNET_DEF_DOC" 'REQUIRE_HTTPS_WEBHOOKS=true' "mainnet with omitted REQUIRE_HTTPS_WEBHOOKS defaults to true in config doctor"

# 10d) XMR-AUDIT-003: verify start.sh fail-closed JSON parser logic across RPC responses
python3 - "$REPO_ROOT/start.sh" <<'PYEOF'
import json, os, re, subprocess, sys

start_sh = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"python3 - \"\$WALLET_MODE\" <<'PYEOF'\n(.*?)\nPYEOF", start_sh, re.S)
assert m is not None, "Could not locate fail-closed Python query_key verifier in start.sh"
py_code = m.group(1)

def run_check(mode: str, raw_resp: str) -> int:
    env = dict(os.environ)
    env["RPC_QUERY_KEY_RESP"] = raw_resp
    proc = subprocess.run(
        [sys.executable, "-c", py_code, mode],
        env=env,
        capture_output=True,
        text=True,
    )
    return proc.returncode

# 64 zeros -> view_only OK, hot_wallet rejected
z64 = json.dumps({"jsonrpc": "2.0", "id": "1", "result": {"key": "0" * 64}})
assert run_check("view_only", z64) == 0
assert run_check("hot_wallet", z64) != 0

# Real 64-hex spend key -> hot_wallet OK, view_only rejected
k64 = json.dumps({"jsonrpc": "2.0", "id": "2", "result": {"key": "a" * 64}})
assert run_check("hot_wallet", k64) == 0
assert run_check("view_only", k64) != 0

# Explicit watch-only RPC error -> view_only OK, hot_wallet rejected
wo_err = json.dumps({"jsonrpc": "2.0", "id": "3", "error": {"code": -1, "message": "The wallet is watch-only"}})
assert run_check("view_only", wo_err) == 0
assert run_check("hot_wallet", wo_err) != 0

# Unknown RPC errors (-32601, -32603, -13), empty key, malformed key, broken JSON -> FAIL CLOSED in BOTH modes!
for bad in (
    json.dumps({"jsonrpc": "2.0", "id": "4", "error": {"code": -32601, "message": "Method not found"}}),
    json.dumps({"jsonrpc": "2.0", "id": "5", "error": {"code": -32603, "message": "Internal error"}}),
    json.dumps({"jsonrpc": "2.0", "id": "6", "error": {"code": -13, "message": "No wallet file"}}),
    json.dumps({"jsonrpc": "2.0", "id": "7", "result": {"key": ""}}),
    json.dumps({"jsonrpc": "2.0", "id": "8", "result": {"key": "0000"}}),
    json.dumps({"jsonrpc": "2.0", "id": "9", "result": {}}),
    "{broken-json",
):
    assert run_check("view_only", bad) != 0, f"view_only MUST fail closed on {bad!r}"
    assert run_check("hot_wallet", bad) != 0, f"hot_wallet MUST fail closed on {bad!r}"
PYEOF
pass "XMR-AUDIT-003: start.sh fail-closed query_key JSON verifier passed all positive & adversarial cases"

# ==============================================================================
# 11. Packaging, Systemd, Quadlet, Key Rotation & Network Node Checks
# ==============================================================================
printf '\n=== 11. Packaging, Systemd, Quadlet, Rotation & Network Checks ===\n'

# 11a) Verify systemd units have zero unescaped printf %s/%d specifiers & Quadlet/Compose isolation
python3 - "$REPO_ROOT" <<'PYEOF'
import glob, os, re, sys, tomllib

repo = sys.argv[1]

# 1) No unescaped printf-style %s/%d specifiers OR inline ${...} env expansion in ExecStart* of deploy/systemd/*.service
for svc in sorted(glob.glob(os.path.join(repo, "deploy/systemd/*.service"))):
    raw = open(svc, encoding="utf-8").read()
    cleaned = raw.replace("%%", "")
    for idx, line in enumerate(cleaned.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert "%s" not in line, f"Unescaped %s specifier in {svc}:{idx}: {line}"
        if stripped.startswith("ExecStart"):
            assert "${" not in line and "$" not in line, (
                f"Inline shell variable expansion forbidden in systemd ExecStart* ({svc}:{idx}): {line}"
            )
            assert "%" not in line, (
                f"Inline % specifier forbidden in systemd ExecStart* ({svc}:{idx}): {line}"
            )

# 2) Packaging includes start.sh, render-wallet-rpc-conf.sh (0755), CHANGELOG.md, and all 4 Quadlet units
with open(os.path.join(repo, "Cargo.toml"), "rb") as f:
    cargo = tomllib.load(f)
deb_assets = {e[0]: (e[1], e[2]) for e in cargo["package"]["metadata"]["deb"]["assets"]}
rpm_assets = {e["source"]: (e["dest"], e["mode"]) for e in cargo["package"]["metadata"]["generate-rpm"]["assets"]}
required_assets = {
    "start.sh",
    "deploy/systemd/render-wallet-rpc-conf.sh",
    "CHANGELOG.md",
    "deploy/podman/quadlet/xmr-gateway-internal.network",
    "deploy/podman/quadlet/xmr-gateway-egress.network",
    "deploy/podman/quadlet/monero-wallet-rpc.container",
    "deploy/podman/quadlet/xmr-gateway.container",
}
for req in required_assets:
    assert req in deb_assets, f"Missing {req} in deb assets"
    assert req in rpm_assets, f"Missing {req} in rpm assets"
    assert os.path.isfile(os.path.join(repo, req)), f"Required packaged file missing on disk: {req}"

assert deb_assets["deploy/systemd/render-wallet-rpc-conf.sh"] == (
    "usr/share/xmr-gateway/scripts/render-wallet-rpc-conf.sh",
    "755",
), f"Unexpected deb mapping for render-wallet-rpc-conf.sh: {deb_assets['deploy/systemd/render-wallet-rpc-conf.sh']}"
assert rpm_assets["deploy/systemd/render-wallet-rpc-conf.sh"] == (
    "/usr/share/xmr-gateway/scripts/render-wallet-rpc-conf.sh",
    "0755",
), f"Unexpected rpm mapping for render-wallet-rpc-conf.sh: {rpm_assets['deploy/systemd/render-wallet-rpc-conf.sh']}"

rel_yml = open(os.path.join(repo, ".github/workflows/release.yml"), encoding="utf-8").read()
assert "start.sh" in rel_yml, "release.yml tarball stage must include start.sh"
assert "render-wallet-rpc-conf.sh" in rel_yml, "release.yml tarball stage must enforce 0755 on render-wallet-rpc-conf.sh"

# 3) Quadlet networking, volume isolation, stop timeout, and healthcheck
rpc_q = open(os.path.join(repo, "deploy/podman/quadlet/monero-wallet-rpc.container"), encoding="utf-8").read()
gw_q = open(os.path.join(repo, "deploy/podman/quadlet/xmr-gateway.container"), encoding="utf-8").read()
for name, content in (("monero-wallet-rpc.container", rpc_q), ("xmr-gateway.container", gw_q)):
    assert "Network=pasta" not in content, f"{name} must not mix Network=pasta with bridge networks"
    assert "Network=xmr-gateway-egress.network" in content, f"{name} must attach to xmr-gateway-egress.network"
    assert "StopSignal=SIGTERM" in content and "StopTimeout=30" in content, f"{name} missing StopSignal/StopTimeout"
assert "Volume=%h/.local/share/xmr-gateway/data:/data:Z" in gw_q, "xmr-gateway.container must isolate /data sibling dir"
assert "HealthCmd=" in gw_q and "HealthInterval=30s" in gw_q, "xmr-gateway.container missing native Quadlet healthcheck"

# 4) Docker Compose isolation & healthcheck + OCI-clean Containerfile
compose_raw = open(os.path.join(repo, "deploy/docker/docker-compose.yml"), encoding="utf-8").read()
assert "../../data/gateway" in compose_raw, "docker-compose.yml must isolate DATA_HOST_DIR to ../../data/gateway"
assert "healthcheck:" in compose_raw, "docker-compose.yml must define healthcheck for xmr-gateway"
cfile_raw = open(os.path.join(repo, "Containerfile"), encoding="utf-8").read()
assert not re.search(r"^\s*HEALTHCHECK\b", cfile_raw, re.M), "Containerfile must not emit OCI HEALTHCHECK warning"

# 5) .env.example includes uncommented OPERATOR_API_KEY=
env_ex = open(os.path.join(repo, ".env.example"), encoding="utf-8").read()
assert re.search(r"^OPERATOR_API_KEY=", env_ex, re.M), ".env.example must contain uncommented OPERATOR_API_KEY="
PYEOF
pass "systemd escaping, packaging manifests, Quadlet/Compose isolation, OCI healthcheck & .env.example verified"

# 11b) Verify Podman Quadlet generator dry-run cleanly accepts all 4 units (if installed)
if [[ -x /usr/libexec/podman/quadlet ]]; then
    if QUADLET_UNIT_DIRS="$REPO_ROOT/deploy/podman/quadlet" /usr/libexec/podman/quadlet -dryrun -user >/dev/null 2>&1; then
        pass "podman quadlet -dryrun -user validated all 4 Quadlet units cleanly"
    else
        fail "podman quadlet -dryrun -user failed on deploy/podman/quadlet"
    fi
fi

# 11c) Bug #5: config rotate-keys all creates distinct OPERATOR_API_KEY even when absent from .env
ROT_ALL_ENV="$TMP_DIR/rotate_all_missing_op.env"
cat > "$ROT_ALL_ENV" <<EOF
HOST=127.0.0.1
PORT=${MOCK_PORT}
DATABASE_URL=sqlite://${DB_FILE}
API_SECRET_KEY=${API_KEY}
WEBHOOK_SECRET=${WH_SECRET}
MONERO_NETWORK=stagenet
WALLET_MODE=view_only
MONERO_RPC_USER=rpc_user
MONERO_RPC_PASS=${RPC_PASS}
EOF
chmod 600 "$ROT_ALL_ENV"
ROT_ALL_JSON="$("$ADMIN_SH" --env "$ROT_ALL_ENV" --yes --json config rotate-keys all)"
assert_contains "$ROT_ALL_JSON" '"OPERATOR_API_KEY"' "config rotate-keys all includes OPERATOR_API_KEY even when missing from .env"
ROT_ALL_API="$(grep '^API_SECRET_KEY=' "$ROT_ALL_ENV" | cut -d= -f2-)"
ROT_ALL_OP="$(grep '^OPERATOR_API_KEY=' "$ROT_ALL_ENV" | cut -d= -f2-)"
if [[ "${#ROT_ALL_OP}" -eq 64 && "$ROT_ALL_OP" != "$ROT_ALL_API" ]]; then
    pass "config rotate-keys all generated fresh 64-hex OPERATOR_API_KEY distinct from API_SECRET_KEY"
else
    fail "config rotate-keys all produced invalid or colliding OPERATOR_API_KEY"
fi

# 11d) Bug #12: network-aware default MONERO_REMOTE_NODE (stagenet/testnet) + config doctor mismatch WARN
STAGE_NODE_ENV="$TMP_DIR/stage_default_node.env"
cat > "$STAGE_NODE_ENV" <<EOF
HOST=127.0.0.1
PORT=${MOCK_PORT}
DATABASE_URL=sqlite://${DB_FILE}
API_SECRET_KEY=${API_KEY}
OPERATOR_API_KEY=${OP_KEY}
WEBHOOK_SECRET=${WH_SECRET}
MONERO_NETWORK=stagenet
MONERO_REMOTE_NODE=
WALLET_MODE=view_only
MONERO_RPC_USER=rpc_user
MONERO_RPC_PASS=${RPC_PASS}
EOF
chmod 600 "$STAGE_NODE_ENV"
STAGE_SHOW_JSON="$("$ADMIN_SH" --env "$STAGE_NODE_ENV" --json config show)"
assert_contains "$STAGE_SHOW_JSON" '"monero_remote_node": "node.monerodevs.org:38089"' "stagenet auto-selects stagenet default MONERO_REMOTE_NODE"

STAGE_BAD_NODE_ENV="$TMP_DIR/stage_bad_node.env"
cp "$STAGE_NODE_ENV" "$STAGE_BAD_NODE_ENV"
chmod 600 "$STAGE_BAD_NODE_ENV"
sed -i 's/^MONERO_REMOTE_NODE=$/MONERO_REMOTE_NODE=xmr-node.cakewallet.com:18081/' "$STAGE_BAD_NODE_ENV"
STAGE_BAD_DOC="$("$ADMIN_SH" --env "$STAGE_BAD_NODE_ENV" --json config doctor)"
assert_contains "$STAGE_BAD_DOC" "remote_node_network" "config doctor warns when stagenet explicitly uses mainnet remote node"

# 11e) Bug #10: scripts/install.sh tarball post-install instructions reference $PREFIX and admin.sh (not /etc/xmr-gateway)
TAR_NEXT_STEPS="$(bash -c 'source <(sed "/^main \"\$@\"$/d" "$1"); INSTALL_LANG=en; METHOD=tarball; PREFIX=/home/tester/xmr-app; print_next_steps' _ "$INSTALL_SH")"
assert_contains "$TAR_NEXT_STEPS" "/home/tester/xmr-app/admin.sh" "install.sh tarball next-steps uses actual PREFIX and admin.sh"
assert_not_contains "$TAR_NEXT_STEPS" "/etc/xmr-gateway/.env" "install.sh tarball next-steps does not print systemd /etc/xmr-gateway path"

# ==============================================================================
# 12. Real Runtime Regression Tests (render-wallet-rpc-conf, Containerfile,
#     setup-rpc target/umask, RPM/DEB paths, SELinux .env, timestamped webhooks)
# ==============================================================================
printf '\n=== 12. Runtime Regression Tests (ExecStartPre, Containerfile, setup-rpc, paths) ===\n'

# 12a) Real /bin/sh execution of standalone deploy/systemd/render-wallet-rpc-conf.sh
#      + verification that monero-wallet-rpc.service delegates cleanly without inline ${...}
python3 - "$REPO_ROOT/deploy/systemd/monero-wallet-rpc.service" "$REPO_ROOT/deploy/systemd/render-wallet-rpc-conf.sh" "$TMP_DIR" <<'PYEOF'
import os, stat, subprocess, sys

unit_path, helper_path, tmp_dir = sys.argv[1], sys.argv[2], sys.argv[3]
unit_raw = open(unit_path, encoding="utf-8").read()

expected_exec_pre = "ExecStartPre=/usr/share/xmr-gateway/scripts/render-wallet-rpc-conf.sh /run/xmr-gateway/wallet-rpc.conf"
assert expected_exec_pre in unit_raw, f"monero-wallet-rpc.service missing expected ExecStartPre: {expected_exec_pre}"
assert os.access(helper_path, os.X_OK), f"{helper_path} must be executable (0755)"

run_dir = os.path.join(tmp_dir, "systemd_run_xmr")
os.makedirs(run_dir, mode=0o700, exist_ok=True)
conf_path = os.path.join(run_dir, "wallet-rpc.conf")

# Positive runtime test 1: valid credentials + stagenet default remote node
env_ok = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "MONERO_RPC_USER": "u",
    "MONERO_RPC_PASS": "secret123",
    "MONERO_NETWORK": "stagenet",
    "MONERO_REMOTE_NODE": "",
}
res_ok = subprocess.run(["/bin/sh", helper_path, conf_path], env=env_ok, capture_output=True, text=True)
assert res_ok.returncode == 0, f"render-wallet-rpc-conf.sh positive case failed (rc={res_ok.returncode}): {res_ok.stderr}"
assert os.path.isfile(conf_path), "render-wallet-rpc-conf.sh did not create wallet-rpc.conf"
mode = stat.S_IMODE(os.stat(conf_path).st_mode)
assert mode == 0o600, f"wallet-rpc.conf mode expected 0600, got {oct(mode)}"
conf_body = open(conf_path, encoding="utf-8").read()
assert "rpc-login=u:secret123\n" in conf_body, f"Missing rpc-login in conf: {conf_body!r}"
assert "daemon-address=node.monerodevs.org:38089\n" in conf_body, f"Missing stagenet daemon-address: {conf_body!r}"
assert "stagenet=1\n" in conf_body, f"Missing stagenet=1: {conf_body!r}"
assert "untrusted-daemon=1\n" in conf_body, f"Missing untrusted-daemon=1: {conf_body!r}"

# Positive runtime test 2: mainnet + trusted daemon + SOCKS5 proxy
env_main = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "MONERO_RPC_USER": "xmr_user",
    "MONERO_RPC_PASS": "s3cr3t$%pass!1234",
    "MONERO_NETWORK": "mainnet",
    "MONERO_TRUSTED_DAEMON": "true",
    "MONERO_RPC_PROXY": "127.0.0.1:9050",
}
res_main = subprocess.run(["/bin/sh", helper_path, conf_path], env=env_main, capture_output=True, text=True)
assert res_main.returncode == 0, f"mainnet positive case failed: {res_main.stderr}"
main_body = open(conf_path, encoding="utf-8").read()
assert "rpc-login=xmr_user:s3cr3t$%pass!1234\n" in main_body
assert "daemon-address=xmr-node.cakewallet.com:18081\n" in main_body
assert "trusted-daemon=1\n" in main_body
assert "proxy=127.0.0.1:9050\n" in main_body

# Negative runtime tests: real \n and \r in credentials MUST fail closed
for label, bad_user, bad_pass in (
    ("LF in pass", "u", "secret\npass"),
    ("CR in pass", "u", "secret\rpass"),
    ("LF in user", "bad\nuser", "secret123"),
):
    env_bad = dict(env_ok)
    env_bad["MONERO_RPC_USER"] = bad_user
    env_bad["MONERO_RPC_PASS"] = bad_pass
    res_bad = subprocess.run(["/bin/sh", helper_path, conf_path], env=env_bad, capture_output=True, text=True)
    assert res_bad.returncode != 0, f"render-wallet-rpc-conf.sh MUST fail closed for {label}"
    assert "newlines" in res_bad.stderr.lower(), f"Expected newline error for {label}, got: {res_bad.stderr!r}"

# Negative runtime test: empty password MUST fail closed
env_empty = dict(env_ok)
env_empty["MONERO_RPC_PASS"] = ""
res_empty = subprocess.run(["/bin/sh", helper_path, conf_path], env=env_empty, capture_output=True, text=True)
assert res_empty.returncode != 0, "render-wallet-rpc-conf.sh MUST reject empty MONERO_RPC_PASS"
PYEOF
pass "Runtime test: deploy/systemd/render-wallet-rpc-conf.sh succeeds on valid creds (incl. $/%) & rejects LF/CR/empty"

# 12b) Real /bin/sh execution of entrypoint-monero-rpc.sh extracted from Containerfile.monero-rpc
python3 - "$REPO_ROOT/deploy/docker/Containerfile.monero-rpc" "$TMP_DIR" <<'PYEOF'
import os, re, stat, subprocess, sys

cfile_path, tmp_dir = sys.argv[1], sys.argv[2]
raw = open(cfile_path, encoding="utf-8").read()
m = re.search(
    r"RUN cat <<'EOF' > /usr/local/bin/entrypoint-monero-rpc\.sh\n(.*?)\nEOF",
    raw,
    re.S,
)
assert m is not None, "Could not locate entrypoint-monero-rpc.sh heredoc in Containerfile.monero-rpc"
ep_code = m.group(1)

work_dir = os.path.join(tmp_dir, "container_ep_test")
wallet_dir = os.path.join(work_dir, "wallet")
os.makedirs(wallet_dir, mode=0o700, exist_ok=True)
wallet_file = os.path.join(wallet_dir, "gateway_wallet")
pass_file = os.path.join(wallet_dir, "gateway_wallet.password")
open(wallet_file + ".keys", "w", encoding="utf-8").write("dummy-keys")
open(pass_file, "w", encoding="utf-8").write("dummy-pass")
os.chmod(wallet_file + ".keys", 0o600)
os.chmod(pass_file, 0o600)

conf_file = os.path.join(work_dir, "wallet-rpc.conf")
args_log = os.path.join(work_dir, "rpc_args.txt")
stub_rpc = os.path.join(work_dir, "stub-monero-wallet-rpc")
open(stub_rpc, "w", encoding="utf-8").write(
    f"#!/bin/sh\nprintf '%s\\n' \"$@\" > '{args_log}'\nexit 0\n"
)
os.chmod(stub_rpc, 0o755)

ep_patched = ep_code.replace('CONF_FILE="/tmp/wallet-rpc.conf"', f'CONF_FILE="{conf_file}"')
ep_patched = ep_patched.replace("exec /usr/local/bin/monero-wallet-rpc", f"exec '{stub_rpc}'")
ep_path = os.path.join(work_dir, "entrypoint-monero-rpc.sh")
open(ep_path, "w", encoding="utf-8").write(ep_patched)
os.chmod(ep_path, 0o755)

# Positive runtime test: passes newline check, writes 0600 conf, reaches exec stub
env_ok = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "MONERO_RPC_USER": "u",
    "MONERO_RPC_PASS": "secret123",
    "MONERO_NETWORK": "stagenet",
    "MONERO_REMOTE_NODE": "",
    "WALLET_FILE": wallet_file,
    "WALLET_PASS_FILE": pass_file,
}
res_ok = subprocess.run(["/bin/sh", ep_path], env=env_ok, capture_output=True, text=True)
assert res_ok.returncode == 0, f"Containerfile entrypoint positive case failed: {res_ok.stderr}"
assert stat.S_IMODE(os.stat(conf_file).st_mode) == 0o600, "Container wallet-rpc.conf must be 0600"
conf_body = open(conf_file, encoding="utf-8").read()
assert "rpc-login=u:secret123\n" in conf_body
assert "daemon-address=node.monerodevs.org:38089\n" in conf_body
assert "stagenet=1\n" in conf_body
invoked_args = open(args_log, encoding="utf-8").read()
assert "--non-interactive" in invoked_args and "--config-file" in invoked_args

# Negative runtime tests: LF and CR in MONERO_RPC_PASS MUST exit 1
for label, bad_pass in (("LF", "secret\npass"), ("CR", "secret\rpass")):
    env_bad = dict(env_ok)
    env_bad["MONERO_RPC_PASS"] = bad_pass
    res_bad = subprocess.run(["/bin/sh", ep_path], env=env_bad, capture_output=True, text=True)
    assert res_bad.returncode == 1, f"entrypoint MUST exit 1 on {label} in pass (got {res_bad.returncode})"
    assert "newlines" in res_bad.stderr.lower(), f"Expected newline error for {label}: {res_bad.stderr!r}"
PYEOF
pass "Runtime test: Containerfile.monero-rpc entrypoint-monero-rpc.sh succeeds on valid creds & rejects LF/CR"

# 12c) Runtime test: resolve_setup_rpc_bin_dir for system install vs tarball + 0755 BIN_DIR under umask 077
TARBALL_FAKE_ROOT="$TMP_DIR/tarball_fake_root"
mkdir -p "$TARBALL_FAKE_ROOT"
SERVICE_LIB_COPY="$TMP_DIR/service_lib_test.sh"
# shellcheck disable=SC2016
sed -e '/^SCRIPT_DIR=/d' -e '/^source "\$SCRIPT_DIR\/lib\/common\.sh"/d' -e '/^main "\$@"$/d' \
    "$REPO_ROOT/admin/service.sh" > "$SERVICE_LIB_COPY"

TARBALL_BIN_RES="$(bash -c '
    set -euo pipefail
    source "$1"
    source "$2"
    unset XMR_BIN_DIR ACTIVE_ENV_FILE ADMIN_ENV_FILE || true
    REPO_ROOT="$3"
    resolve_setup_rpc_bin_dir
' _ "$REPO_ROOT/admin/lib/common.sh" "$SERVICE_LIB_COPY" "$TARBALL_FAKE_ROOT")"
assert_eq "$TARBALL_BIN_RES" "$TARBALL_FAKE_ROOT/bin" "resolve_setup_rpc_bin_dir selects REPO_ROOT/bin for writable tarball install"

SYS_BIN_OUT=""
if SYS_BIN_OUT="$(bash -c '
    set -euo pipefail
    source "$1"
    source "$2"
    unset XMR_BIN_DIR || true
    REPO_ROOT="/usr/share/xmr-gateway"
    ACTIVE_ENV_FILE="/etc/xmr-gateway/.env"
    resolve_setup_rpc_bin_dir
' _ "$REPO_ROOT/admin/lib/common.sh" "$SERVICE_LIB_COPY" 2>&1)"; then
    assert_eq "$SYS_BIN_OUT" "/usr/local/bin" "resolve_setup_rpc_bin_dir selects /usr/local/bin for system package install"
else
    assert_contains "$SYS_BIN_OUT" "/usr/local/bin" "resolve_setup_rpc_bin_dir targets /usr/local/bin (never /usr/share/xmr-gateway/bin) on non-root system install"
    assert_not_contains "$SYS_BIN_OUT" "/usr/share/xmr-gateway/bin" "resolve_setup_rpc_bin_dir never falls back to /usr/share/xmr-gateway/bin"
fi

UMASK_TEST_BIN="$TMP_DIR/umask77_bin_dir"
(umask 077 && install -d -m 0755 "$UMASK_TEST_BIN")
assert_eq "$(stat -c '%a' "$UMASK_TEST_BIN")" "755" "install -d -m 0755 produces 0755 BIN_DIR even under umask 077"
# shellcheck disable=SC2016
if grep -q 'install -d -m 0755 "\$BIN_DIR"' "$REPO_ROOT/start.sh"; then
    pass "start.sh creates BIN_DIR with explicit 0755 permissions under umask 077"
else
    fail "start.sh missing explicit install -d -m 0755 for BIN_DIR"
fi

# 12d) Runtime test: RPM/DEB postinst DB rewrite + load_env wallet/DB consistency + WALLET_RESTORE_HEIGHT defaults
for pscript in "$REPO_ROOT/deploy/packaging/deb/postinst" "$REPO_ROOT/deploy/packaging/rpm/postinst.sh"; do
    rel_ps="${pscript#"$REPO_ROOT"/}"
    if grep -q 'DATABASE_URL=sqlite:///var/lib/xmr-gateway/xmr_gateway.db' "$pscript"; then
        pass "$rel_ps rewrites DATABASE_URL to /var/lib/xmr-gateway/xmr_gateway.db"
    else
        fail "$rel_ps missing canonical DATABASE_URL rewrite"
    fi
done

SEEDED_SYS_ENV="$TMP_DIR/seeded_sys.env"
sed 's|^DATABASE_URL=sqlite://data/xmr_gateway\.db$|DATABASE_URL=sqlite:///var/lib/xmr-gateway/xmr_gateway.db|' \
    "$REPO_ROOT/.env.example" > "$SEEDED_SYS_ENV"
chmod 600 "$SEEDED_SYS_ENV"
assert_contains "$(cat "$SEEDED_SYS_ENV")" "DATABASE_URL=sqlite:///var/lib/xmr-gateway/xmr_gateway.db" "postinst sed rewrite produces canonical /var/lib/xmr-gateway DB URL"

SYS_PATHS_OUT="$(bash -c '
    set -euo pipefail
    source "$1"
    ADMIN_ENV_FILE="$2"
    load_env
    printf "%s|%s|%s|%s|%s\n" "$DB_PATH" "$DATA_DIR" "$WALLET_DIR" "$WALLET_FILE" "$WALLET_PASS_FILE"
' _ "$REPO_ROOT/admin/lib/common.sh" "$SEEDED_SYS_ENV")"
assert_eq "$SYS_PATHS_OUT" \
    "/var/lib/xmr-gateway/xmr_gateway.db|/var/lib/xmr-gateway|/var/lib/xmr-gateway/wallet|/var/lib/xmr-gateway/wallet/gateway_wallet|/var/lib/xmr-gateway/wallet/gateway_wallet.password" \
    "load_env on postinst-seeded env matches systemd monero-wallet-rpc.service wallet & DB paths exactly"

LEGACY_SYS_DB="$(bash -c '
    set -euo pipefail
    source "$1"
    ACTIVE_ENV_FILE="/etc/xmr-gateway/.env"
    extract_sqlite_path "sqlite://data/xmr_gateway.db"
' _ "$REPO_ROOT/admin/lib/common.sh")"
assert_eq "$LEGACY_SYS_DB" "/var/lib/xmr-gateway/xmr_gateway.db" "legacy relative sqlite://data/xmr_gateway.db flattens cleanly under /etc/xmr-gateway/.env"

# Verify empty WALLET_RESTORE_HEIGHT= in templates & auto-selection for stagenet/testnet/mainnet
if grep -qE '^WALLET_RESTORE_HEIGHT=$' "$REPO_ROOT/.env.example" && grep -qE '^WALLET_RESTORE_HEIGHT=$' "$REPO_ROOT/deploy/docker/.env.docker.example"; then
    pass ".env.example and .env.docker.example leave WALLET_RESTORE_HEIGHT= empty for network-aware auto-selection"
else
    fail ".env.example or .env.docker.example still hardcodes non-empty WALLET_RESTORE_HEIGHT"
fi
assert_contains "$STAGE_SHOW_JSON" '"wallet_restore_height": "1600000"' "stagenet auto-selects default WALLET_RESTORE_HEIGHT=1600000 when empty"

TESTNET_NODE_ENV="$TMP_DIR/testnet_default.env"
cp "$STAGE_NODE_ENV" "$TESTNET_NODE_ENV"
chmod 600 "$TESTNET_NODE_ENV"
sed -i 's/^MONERO_NETWORK=stagenet$/MONERO_NETWORK=testnet/' "$TESTNET_NODE_ENV"
TESTNET_SHOW_JSON="$("$ADMIN_SH" --env "$TESTNET_NODE_ENV" --json config show)"
assert_contains "$TESTNET_SHOW_JSON" '"monero_remote_node": "testnet.xmr-tw.org:28081"' "testnet auto-selects testnet default MONERO_REMOTE_NODE"
assert_contains "$TESTNET_SHOW_JSON" '"wallet_restore_height": "2600000"' "testnet auto-selects default WALLET_RESTORE_HEIGHT=2600000 when empty"

# 12e) SELinux-safe same-directory atomic .env rewrite + timestamped webhook verify-sig
SELINUX_ENV_DIR="$TMP_DIR/selinux_env_dir"
mkdir -p "$SELINUX_ENV_DIR"
SELINUX_ENV_FILE="$SELINUX_ENV_DIR/.env"
printf 'API_SECRET_KEY=old_val\nWEBHOOK_SECRET=%s\n' "$WH_SECRET" > "$SELINUX_ENV_FILE"
chmod 600 "$SELINUX_ENV_FILE"
bash -c '
    set -euo pipefail
    source "$1"
    set_env_kv_file "$2" "API_SECRET_KEY" "new_val_12345"
' _ "$REPO_ROOT/admin/lib/common.sh" "$SELINUX_ENV_FILE"
assert_eq "$(stat -c '%a' "$SELINUX_ENV_FILE")" "600" "set_env_kv_file preserves 0600 permissions"
assert_contains "$(cat "$SELINUX_ENV_FILE")" "API_SECRET_KEY=new_val_12345" "set_env_kv_file updates target key atomically in same directory"
if grep -q '\.env\.tmp\.XXXXXX' "$REPO_ROOT/admin/lib/common.sh" \
    && grep -q 'restorecon' "$REPO_ROOT/admin/lib/common.sh" \
    && grep -q '\.env\.tmp\.XXXXXX' "$REPO_ROOT/start.sh"; then
    pass "set_env_kv_file and start.sh use same-directory mktemp + restorecon for SELinux etc_t preservation"
else
    fail "missing same-directory mktemp or restorecon in common.sh / start.sh"
fi

# Verify timestamped X-Webhook-Signature support in `webhooks verify-sig --timestamp`
TS_NOW="$(date +%s)"
TS_SIG="$(python3 -c 'import hashlib,hmac,sys; print(hmac.new(sys.argv[1].encode(), f"{sys.argv[2]}.".encode() + open(sys.argv[3],"rb").read(), hashlib.sha256).hexdigest())' "$WH_SECRET" "$TS_NOW" "$PAYLOAD_FILE")"
TS_VER_OUT="$("$ADMIN_SH" --env "$TEST_ENV" --json webhooks verify-sig "$TS_SIG" "$PAYLOAD_FILE" --timestamp "$TS_NOW")"
assert_contains "$TS_VER_OUT" '"valid": true' "webhooks verify-sig --timestamp validates X-Webhook-Signature"
assert_contains "$TS_VER_OUT" '"header": "X-Webhook-Signature"' "webhooks verify-sig --timestamp reports X-Webhook-Signature header"

printf '\n====================================================================\n'
printf 'Admin Test Summary: %d PASSED, %d FAILED\n' "$PASS_COUNT" "$FAIL_COUNT"
printf '====================================================================\n'
[[ "$FAIL_COUNT" -eq 0 ]]
