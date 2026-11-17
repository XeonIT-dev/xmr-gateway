#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Single-Terminal Stagenet Live Demo
# ==============================================================================
# Runs monero-wallet-rpc (Stagenet), xmr-gateway, and an HMAC-SHA256
# verifying Python webhook listener in one terminal with prefixed, color-coded
# logs ([RPC], [GATEWAY], [WEBHOOK]), creates a demo invoice (0.005 XMR),
# writes its QR PNG to /tmp/stagenet_qr.png, and shuts everything down cleanly
# on Ctrl+C.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE="$SCRIPT_DIR/.env"
DATA_DIR="$SCRIPT_DIR/data"
WALLET_FILE="$DATA_DIR/wallet/gateway_wallet"
WALLET_PASS_FILE="$DATA_DIR/wallet/gateway_wallet.password"
RPC_LOG_FILE="$DATA_DIR/monero-wallet-rpc.log"
GATEWAY_BIN="$SCRIPT_DIR/target/release/xmr-gateway"
QR_OUTPUT_PATH="/tmp/stagenet_qr.png"

C_RESET=$'\033[0m'
C_DEMO=$'\033[1;33m'
C_RPC=$'\033[1;36m'
C_GW=$'\033[1;32m'
C_HOOK=$'\033[1;35m'
C_ERR=$'\033[1;31m'

RPC_PID=""
RPC_TAIL_PID=""
WEBHOOK_PID=""
GATEWAY_PID=""
CLEANED_UP=0

demo_log() { printf '%s[DEMO]%s %s\n' "$C_DEMO" "$C_RESET" "$*"; }
demo_err() { printf '%s[DEMO]%s %s\n' "$C_ERR" "$C_RESET" "$*" >&2; }

stop_pid() {
    local pid="$1"
    local name="$2"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        demo_log "Stopping $name (PID $pid)..."
        kill -TERM "$pid" 2>/dev/null || true
        local waited=0
        while kill -0 "$pid" 2>/dev/null && [[ "$waited" -lt 20 ]]; do
            sleep 0.25
            waited=$((waited + 1))
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    if [[ "$CLEANED_UP" -eq 1 ]]; then
        return
    fi
    CLEANED_UP=1

    stop_pid "$GATEWAY_PID" "xmr-gateway"
    stop_pid "$WEBHOOK_PID" "webhook listener"
    stop_pid "$RPC_TAIL_PID" "RPC log tailer"
    stop_pid "$RPC_PID" "monero-wallet-rpc"
}

on_signal() {
    printf '\n'
    demo_log "Interrupt received — shutting down all demo processes..."
    cleanup
    exit 0
}

trap on_signal INT TERM
trap cleanup EXIT

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        demo_err "Required command '$1' not found in PATH."
        exit 1
    fi
}

check_port_free() {
    local port="$1"
    if command -v ss >/dev/null 2>&1 && ss -ltn | awk '{print $4}' | grep -qE "(^|:)${port}$"; then
        demo_err "Port $port is already in use on localhost. Stop the existing service first."
        exit 1
    fi
}

prefix_stream() {
    local tag="$1"
    awk -v tag="$tag" '{ print tag " " $0; fflush() }'
}

main() {
    require_cmd curl
    require_cmd python3
    require_cmd cargo

    # Ensure .env, Monero binaries, and Stagenet wallet are initialized non-interactively
    "$SCRIPT_DIR/start.sh" --init-wallet-only

    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a

    export MONERO_NETWORK="stagenet"
    export HOST="127.0.0.1"
    export PORT="8080"
    export MONERO_RPC_URL="http://127.0.0.1:18082/json_rpc"
    export LOG_FORMAT="pretty"
    export ALLOW_PRIVATE_WEBHOOKS="${ALLOW_PRIVATE_WEBHOOKS:-true}"
    : "${MONERO_REMOTE_NODE:=node.monerodevs.org:38089}"
    : "${MONERO_TRUSTED_DAEMON:=false}"
    : "${MONERO_RPC_USER:=xmr_gateway_user}"
    : "${MONERO_RPC_PASS:=}"

    check_port_free 18082
    check_port_free 8080
    check_port_free 9000

    local rpc_bin
    if [[ -x "$SCRIPT_DIR/bin/monero-wallet-rpc" ]]; then
        rpc_bin="$SCRIPT_DIR/bin/monero-wallet-rpc"
    elif command -v monero-wallet-rpc >/dev/null 2>&1; then
        rpc_bin="$(command -v monero-wallet-rpc)"
    else
        demo_err "monero-wallet-rpc not found. Run ./start.sh --setup-rpc first."
        exit 1
    fi

    # Build release binary if missing or outdated
    if [[ ! -x "$GATEWAY_BIN" ]] || find "$SCRIPT_DIR/Cargo.toml" "$SCRIPT_DIR/src" "$SCRIPT_DIR/migrations" \
        -type f -newer "$GATEWAY_BIN" 2>/dev/null | grep -q .; then
        demo_log "Building xmr-gateway (--release)..."
        cargo build --release
    fi

    mkdir -p "$DATA_DIR"
    : > "$RPC_LOG_FILE"

    # 1) Start monero-wallet-rpc in Stagenet mode
    local rpc_args=(
        --non-interactive
        --no-initial-sync
        --stagenet
        --wallet-file "$WALLET_FILE"
        --password-file "$WALLET_PASS_FILE"
        --daemon-address "$MONERO_REMOTE_NODE"
        --rpc-bind-ip 127.0.0.1
        --rpc-bind-port 18082
        --log-file "$RPC_LOG_FILE"
        --log-level 1
    )
    if [[ "${MONERO_TRUSTED_DAEMON,,}" == "true" || "${MONERO_TRUSTED_DAEMON}" == "1" ]]; then
        rpc_args+=(--trusted-daemon)
    else
        rpc_args+=(--untrusted-daemon)
    fi
    if [[ -n "$MONERO_RPC_USER" ]]; then
        rpc_args+=(--rpc-login "${MONERO_RPC_USER}:${MONERO_RPC_PASS}")
    else
        rpc_args+=(--disable-rpc-login)
    fi
    if [[ -n "${MONERO_RPC_PROXY:-}" ]]; then
        rpc_args+=(--proxy "$MONERO_RPC_PROXY")
    fi

    demo_log "Starting monero-wallet-rpc (stagenet -> $MONERO_REMOTE_NODE) on 127.0.0.1:18082..."
    "$rpc_bin" "${rpc_args[@]}" >/dev/null 2>&1 &
    RPC_PID=$!

    tail -n 0 -F "$RPC_LOG_FILE" > >(prefix_stream "${C_RPC}[RPC]${C_RESET}") 2>&1 &
    RPC_TAIL_PID=$!

    local curl_auth_args=()
    if [[ -n "$MONERO_RPC_USER" ]]; then
        curl_auth_args=(--digest -u "${MONERO_RPC_USER}:${MONERO_RPC_PASS}")
    fi

    local attempt=0
    while [[ "$attempt" -lt 120 ]]; do
        if ! kill -0 "$RPC_PID" 2>/dev/null; then
            demo_err "monero-wallet-rpc exited unexpectedly."
            exit 1
        fi
        local rpc_resp
        rpc_resp="$(curl -sS "${curl_auth_args[@]}" \
            -H 'Content-Type: application/json' \
            -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' \
            "http://127.0.0.1:18082/json_rpc" 2>/dev/null || true)"
        if [[ "$rpc_resp" == *'"result"'* ]]; then
            demo_log "monero-wallet-rpc is ready on 127.0.0.1:18082."
            break
        fi
        sleep 0.5
        attempt=$((attempt + 1))
    done

    if [[ "$attempt" -ge 120 ]]; then
        demo_err "Timed out waiting for monero-wallet-rpc on 127.0.0.1:18082."
        exit 1
    fi

    # 2) Start inline Python HMAC-SHA256 webhook listener on 127.0.0.1:9000
    demo_log "Starting Python HMAC-SHA256 webhook listener on 127.0.0.1:9000..."
    python3 -u -c '
import hashlib, hmac, json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ["WEBHOOK_SECRET"].encode("utf-8")

class WebhookHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length)
        sig_header = self.headers.get("X-Signature-256", "").strip().lower()
        expected = hmac.new(SECRET, raw_body, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected, sig_header):
            print(f"REJECTED webhook on {self.path}: invalid X-Signature-256", flush=True)
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"{\"error\":\"invalid signature\"}")
            return

        data = json.loads(raw_body.decode("utf-8"))
        event = data.get("event", "?")
        order_id = data.get("order_id", "?")
        status = data.get("status", "?")
        rx_xmr = data.get("received_xmr_formatted", "0")
        confs = data.get("confirmations", 0)
        swept = data.get("sweep_tx_hashes", [])
        print(
            f"VERIFIED X-Signature-256 | event={event} | order_id={order_id} | "
            f"status={status} | received={rx_xmr} XMR | confirmations={confs} | sweep_txs={swept}",
            flush=True,
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{\"ok\":true}")

print("Listening on http://127.0.0.1:9000/webhooks/monero", flush=True)
ThreadingHTTPServer(("127.0.0.1", 9000), WebhookHandler).serve_forever()
' > >(prefix_stream "${C_HOOK}[WEBHOOK]${C_RESET}") 2>&1 &
    WEBHOOK_PID=$!

    # 3) Start xmr-gateway on 127.0.0.1:8080
    demo_log "Starting xmr-gateway on http://127.0.0.1:8080..."
    "$GATEWAY_BIN" > >(prefix_stream "${C_GW}[GATEWAY]${C_RESET}") 2>&1 &
    GATEWAY_PID=$!

    attempt=0
    while [[ "$attempt" -lt 60 ]]; do
        if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
            demo_err "xmr-gateway exited unexpectedly."
            exit 1
        fi
        local health_json
        health_json="$(curl -sS http://127.0.0.1:8080/health 2>/dev/null || true)"
        if [[ "$health_json" == *'"status":"ok"'* ]]; then
            demo_log "Gateway is healthy and connected to Stagenet RPC."
            break
        fi
        sleep 0.5
        attempt=$((attempt + 1))
    done

    if [[ "$attempt" -ge 60 ]]; then
        demo_err "Timed out waiting for gateway /health to become ok."
        exit 1
    fi

    # 4) Create Stagenet demo invoice (0.005 XMR = 5000000000 piconero)
    local order_id="stagenet_demo_1"
    local tmp_body http_code
    tmp_body="$(mktemp)"
    http_code="$(curl -sS -o "$tmp_body" -w '%{http_code}' \
        -X POST http://127.0.0.1:8080/api/v1/invoices \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_SECRET_KEY" \
        -d "{\"order_id\":\"${order_id}\",\"amount_piconero\":5000000000,\"callback_url\":\"http://127.0.0.1:9000/webhooks/monero\"}")"

    if [[ "$http_code" == "409" ]]; then
        order_id="stagenet_demo_1_$(date +%s)"
        http_code="$(curl -sS -o "$tmp_body" -w '%{http_code}' \
            -X POST http://127.0.0.1:8080/api/v1/invoices \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $API_SECRET_KEY" \
            -d "{\"order_id\":\"${order_id}\",\"amount_piconero\":5000000000,\"callback_url\":\"http://127.0.0.1:9000/webhooks/monero\"}")"
    fi

    if [[ "$http_code" != "201" && "$http_code" != "200" ]]; then
        demo_err "Failed to create demo invoice (HTTP $http_code): $(cat "$tmp_body")"
        rm -f "$tmp_body"
        exit 1
    fi

    # Decode QR PNG & extract display fields cleanly
    local parsed_info
    parsed_info="$(python3 - "$tmp_body" "$QR_OUTPUT_PATH" <<'PYEOF'
import base64, json, sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    inv = json.load(f)

qr_bytes = base64.b64decode(inv["qr_code_base64"])
with open(sys.argv[2], "wb") as qr_f:
    qr_f.write(qr_bytes)

print(inv["invoice_id"])
print(inv["order_id"])
print(inv["subaddress"])
print(inv["amount_xmr_formatted"])
print(inv["monero_uri"])
PYEOF
)"
    rm -f "$tmp_body"

    local inv_id inv_order inv_subaddr inv_xmr inv_uri
    {
        read -r inv_id
        read -r inv_order
        read -r inv_subaddr
        read -r inv_xmr
        read -r inv_uri
    } <<< "$parsed_info"

    printf '\n'
    printf '================================================================================\n'
    printf '  STAGENET DEMO INVOICE READY (Send test coins & watch live events below)\n'
    printf '================================================================================\n'
    printf '  Invoice ID     : %s\n' "$inv_id"
    printf '  Order ID       : %s\n' "$inv_order"
    printf '  Subaddress     : %s\n' "$inv_subaddr"
    printf '  Exact Amount   : %s XMR (5000000000 piconero)\n' "$inv_xmr"
    printf '  Monero URI     : %s\n' "$inv_uri"
    printf '  QR Code PNG    : %s\n' "$QR_OUTPUT_PATH"
    printf '  Webhook Target : http://127.0.0.1:9000/webhooks/monero\n'
    printf '================================================================================\n'
    printf '  Watching MEMPOOL -> CONFIRMED -> COMPLETED webhooks. Press Ctrl+C to stop.\n'
    printf '================================================================================\n\n'

    wait "$GATEWAY_PID"
}

main "$@"
