#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Admin Suite — Service Lifecycle Module (admin/service.sh)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=admin/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    cat <<'EOF'
Usage: ./admin.sh service <command> [options]

Commands:
  start                            Start monero-wallet-rpc and xmr-gateway with PID files
  stop                             Gracefully stop xmr-gateway (WAL checkpoint) & monero-wallet-rpc
  restart                          Gracefully restart both services
  status                           Show PIDs, ports, /health, and wallet RPC status (--json supported)
  logs [gateway|rpc|cli] [-f] [-n N]
                                   Show or tail service logs (default: gateway, -n 50)
  build                            Build release binary (cargo build --release --locked)
  setup-rpc                        Install & SHA256-verify Monero CLI tools via ./start.sh --setup-rpc
  systemd [status|install-dry-run|restart]
                                   Inspect or manage deploy/systemd/ service units
  help                             Show this help message
EOF
}

read_pid_file() {
    local pid_file="$1"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid="$(tr -d '[:space:]' < "$pid_file" 2>/dev/null || true)"
        if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
            printf '%s\n' "$pid"
            return 0
        fi
    fi
    return 1
}

stop_process_gracefully() {
    local name="$1"
    local pid_file="$2"
    local timeout_sec="${3:-20}"

    local pid=""
    if ! pid="$(read_pid_file "$pid_file")"; then
        rm -f "$pid_file"
        log_info "$name is not running (no active PID in $pid_file)."
        return 0
    fi

    log_info "Sending SIGTERM to $name (PID $pid) for graceful shutdown..."
    kill -TERM "$pid" 2>/dev/null || true

    local ticks=$((timeout_sec * 2))
    local i=0
    while kill -0 "$pid" 2>/dev/null && [[ "$i" -lt "$ticks" ]]; do
        sleep 0.5
        i=$((i + 1))
    done

    if kill -0 "$pid" 2>/dev/null; then
        log_warn "$name (PID $pid) did not exit within ${timeout_sec}s; sending SIGKILL."
        kill -KILL "$pid" 2>/dev/null || true
        sleep 0.5
    fi

    rm -f "$pid_file"
    log_info "$name stopped."
}

cmd_start() {
    load_env
    require_cmd curl
    mkdir -p "$DATA_DIR" "$WALLET_DIR" "$PID_DIR"
    chmod 700 "$DATA_DIR" "$WALLET_DIR" "$PID_DIR"

    local rpc_bin
    rpc_bin="$(find_monero_bin monero-wallet-rpc)" || die "monero-wallet-rpc not found. Run: ./admin.sh service setup-rpc"

    if [[ ! -f "${WALLET_FILE}.keys" ]]; then
        die "Wallet file ${WALLET_FILE}.keys does not exist. Create one via './admin.sh wallet create-view-only' or './admin.sh wallet create-hot'."
    fi
    if [[ ! -f "$WALLET_PASS_FILE" ]]; then
        die "Wallet password file missing: $WALLET_PASS_FILE"
    fi
    if [[ ! -x "$GATEWAY_BIN" ]]; then
        log_warn "Release binary not found at $GATEWAY_BIN; building first..."
        cmd_build
    fi

    # 1) Start monero-wallet-rpc if not already running
    local rpc_port
    rpc_port="$(extract_url_port "$MONERO_RPC_URL" 18082)"

    if read_pid_file "$RPC_PID_FILE" >/dev/null; then
        log_info "monero-wallet-rpc is already running (PID $(cat "$RPC_PID_FILE"))."
    else
        if [[ -z "${MONERO_RPC_USER:-}" || -z "${MONERO_RPC_PASS:-}" ]] && ! is_truthy "$ALLOW_UNAUTHENTICATED_RPC"; then
            die "MONERO_RPC_USER and MONERO_RPC_PASS must be set in $ACTIVE_ENV_FILE."
        fi

        local rpc_args=(
            --non-interactive
            --no-initial-sync
            --wallet-file "$WALLET_FILE"
            --password-file "$WALLET_PASS_FILE"
            --daemon-address "$MONERO_REMOTE_NODE"
            --rpc-bind-ip 127.0.0.1
            --rpc-bind-port "$rpc_port"
            --log-file "$RPC_LOG_FILE"
            --log-level 1
        )
        if is_truthy "$MONERO_TRUSTED_DAEMON"; then
            rpc_args+=(--trusted-daemon)
        else
            rpc_args+=(--untrusted-daemon)
        fi
        case "$MONERO_NETWORK" in
            stagenet) rpc_args+=(--stagenet) ;;
            testnet)  rpc_args+=(--testnet) ;;
            mainnet)  ;;
            *) die "Unsupported MONERO_NETWORK='$MONERO_NETWORK'" ;;
        esac
        if [[ -n "${MONERO_RPC_USER:-}" ]]; then
            rpc_args+=(--rpc-login "${MONERO_RPC_USER}:${MONERO_RPC_PASS}")
        fi
        if [[ -n "${MONERO_RPC_PROXY:-}" ]]; then
            rpc_args+=(--proxy "$MONERO_RPC_PROXY")
        fi

        log_step "Starting monero-wallet-rpc ($MONERO_NETWORK) on 127.0.0.1:${rpc_port}..."
        nohup "$rpc_bin" "${rpc_args[@]}" >/dev/null 2>&1 &
        local rpc_pid=$!
        printf '%s\n' "$rpc_pid" > "$RPC_PID_FILE"
        chmod 600 "$RPC_PID_FILE"

        local attempt=0
        while [[ "$attempt" -lt 120 ]]; do
            if ! kill -0 "$rpc_pid" 2>/dev/null; then
                rm -f "$RPC_PID_FILE"
                log_err "monero-wallet-rpc exited unexpectedly. Last 20 log lines:"
                tail -n 20 "$RPC_LOG_FILE" >&2 || true
                exit 1
            fi
            if wallet_rpc_call "get_version" && [[ "$RPC_LAST_BODY" == *'"result"'* ]]; then
                log_info "monero-wallet-rpc is ready (PID $rpc_pid)."
                break
            fi
            sleep 0.5
            attempt=$((attempt + 1))
        done
        if [[ "$attempt" -ge 120 ]]; then
            die "Timed out waiting for monero-wallet-rpc readiness on 127.0.0.1:${rpc_port}."
        fi
    fi

    # 2) Start xmr-gateway if not already running
    if read_pid_file "$GATEWAY_PID_FILE" >/dev/null; then
        log_info "xmr-gateway is already running (PID $(cat "$GATEWAY_PID_FILE"))."
    else
        log_step "Starting xmr-gateway on ${GATEWAY_BASE_URL} (logs: $GATEWAY_LOG_FILE)..."
        (
            cd "$REPO_ROOT"
            nohup "$GATEWAY_BIN" >> "$GATEWAY_LOG_FILE" 2>&1 &
            printf '%s\n' "$!" > "$GATEWAY_PID_FILE"
        )
        chmod 600 "$GATEWAY_PID_FILE"
        local gw_pid
        gw_pid="$(cat "$GATEWAY_PID_FILE")"

        local attempt=0
        while [[ "$attempt" -lt 60 ]]; do
            if ! kill -0 "$gw_pid" 2>/dev/null; then
                rm -f "$GATEWAY_PID_FILE"
                log_err "xmr-gateway exited unexpectedly. Last 25 log lines:"
                tail -n 25 "$GATEWAY_LOG_FILE" >&2 || true
                exit 1
            fi
            if gateway_api_call GET "/health" none && [[ "$API_LAST_HTTP_CODE" == "200" ]]; then
                log_info "xmr-gateway is healthy (PID $gw_pid, ${GATEWAY_BASE_URL})."
                return 0
            fi
            sleep 0.5
            attempt=$((attempt + 1))
        done
        log_warn "xmr-gateway started (PID $gw_pid) but /health did not return 200 within 30s; inspect logs via './admin.sh service logs gateway'."
    fi
}

cmd_stop() {
    load_env
    confirm_dangerous_action "Stop xmr-gateway (WAL checkpoint + close) and monero-wallet-rpc"
    # Stop gateway FIRST so it runs PRAGMA wal_checkpoint(TRUNCATE) cleanly while RPC is still alive if needed
    stop_process_gracefully "xmr-gateway" "$GATEWAY_PID_FILE" 25
    stop_process_gracefully "monero-wallet-rpc" "$RPC_PID_FILE" 15
}

cmd_restart() {
    cmd_stop
    cmd_start
}

cmd_status() {
    load_env 1
    local gw_pid="" rpc_pid=""
    gw_pid="$(read_pid_file "$GATEWAY_PID_FILE" || true)"
    rpc_pid="$(read_pid_file "$RPC_PID_FILE" || true)"

    local health_http="unreachable" health_body="{}"
    if gateway_api_call GET "/health" health_api 2>/dev/null; then
        health_http="$API_LAST_HTTP_CODE"
        health_body="$API_LAST_BODY"
    elif gateway_api_call GET "/health" none 2>/dev/null; then
        health_http="$API_LAST_HTTP_CODE"
        health_body="$API_LAST_BODY"
    fi

    local rpc_http="unreachable" rpc_ver=""
    if wallet_rpc_call "get_version" 2>/dev/null && [[ "$RPC_LAST_HTTP_CODE" == "200" ]]; then
        rpc_http="200"
        rpc_ver="$(python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(d.get("result",{}).get("version",""))' <<< "$RPC_LAST_BODY" 2>/dev/null || true)"
    fi

    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        python3 - "$gw_pid" "$rpc_pid" "$GATEWAY_BASE_URL" "$MONERO_RPC_URL" "$health_http" "$health_body" "$rpc_http" "$rpc_ver" "$MONERO_NETWORK" "$WALLET_MODE" <<'PYEOF'
import json, sys
gw_pid, rpc_pid, gw_url, rpc_url, h_code, h_body, r_code, r_ver, net, mode = sys.argv[1:11]
try:
    h_json = json.loads(h_body)
except Exception:
    h_json = h_body
out = {
    "network": net,
    "wallet_mode": mode,
    "gateway": {
        "pid": int(gw_pid) if gw_pid else None,
        "running": bool(gw_pid),
        "url": gw_url,
        "health_http": h_code,
        "health": h_json,
    },
    "monero_wallet_rpc": {
        "pid": int(rpc_pid) if rpc_pid else None,
        "running": bool(rpc_pid),
        "url": rpc_url,
        "http": r_code,
        "version": int(r_ver) if r_ver.isdigit() else None,
    },
}
print(json.dumps(out, indent=2))
PYEOF
        return 0
    fi

    printf '%s=== xmr-gateway Service Status ===%s\n' "$C_BOLD" "$C_RESET"
    printf '  Env file         : %s\n' "$ACTIVE_ENV_FILE"
    printf '  Network / Mode   : %s / %s\n' "$MONERO_NETWORK" "$WALLET_MODE"
    printf '  xmr-gateway      : %s (URL: %s, /health HTTP: %s)\n' \
        "${gw_pid:+RUNNING (PID $gw_pid)}" "${GATEWAY_BASE_URL}" "$health_http"
    [[ -z "$gw_pid" ]] && printf '                     (no active PID file at %s)\n' "$GATEWAY_PID_FILE"
    printf '  monero-wallet-rpc: %s (URL: %s, RPC HTTP: %s%s)\n' \
        "${rpc_pid:+RUNNING (PID $rpc_pid)}" "$MONERO_RPC_URL" "$rpc_http" "${rpc_ver:+, version=$rpc_ver}"
    [[ -z "$rpc_pid" ]] && printf '                     (no active PID file at %s)\n' "$RPC_PID_FILE"
    if [[ "$health_http" == "200" || "$health_http" == "503" ]]; then
        printf '\n%s/health response:%s\n' "$C_CYAN" "$C_RESET"
        printf '%s\n' "$health_body" | pretty_print_json
    fi
}

cmd_logs() {
    load_env 1
    local target="gateway"
    local follow=0
    local lines=50

    while [[ $# -gt 0 ]]; do
        case "$1" in
            gateway|rpc|cli)
                target="$1"
                shift
                ;;
            -f|--follow)
                follow=1
                shift
                ;;
            -n|--lines)
                [[ $# -ge 2 ]] || die "-n requires a line count."
                lines="$2"
                shift 2
                ;;
            *)
                die "Unknown logs argument: $1"
                ;;
        esac
    done

    local log_file=""
    case "$target" in
        gateway) log_file="$GATEWAY_LOG_FILE" ;;
        rpc)     log_file="$RPC_LOG_FILE" ;;
        cli)     log_file="$CLI_LOG_FILE" ;;
    esac

    [[ -f "$log_file" ]] || die "Log file not found: $log_file"
    if [[ "$follow" -eq 1 ]]; then
        tail -n "$lines" -F "$log_file"
    else
        tail -n "$lines" "$log_file"
    fi
}

cmd_build() {
    require_cmd cargo
    log_step "Building xmr-gateway release binary (cargo build --release --locked)..."
    (cd "$REPO_ROOT" && cargo build --release --locked)
    ls -lh "$REPO_ROOT/target/release/xmr-gateway"
}

cmd_setup_rpc() {
    log_step "Running ./start.sh --setup-rpc (SHA256-verified Monero CLI installation)..."
    (cd "$REPO_ROOT" && ./start.sh --setup-rpc)
    for b in monero-wallet-rpc monero-wallet-cli; do
        if [[ -x "$REPO_ROOT/bin/$b" ]]; then
            local sha ver
            sha="$(sha256sum "$REPO_ROOT/bin/$b" | awk '{print $1}')"
            ver="$("$REPO_ROOT/bin/$b" --version 2>/dev/null | head -n 1 || true)"
            log_info "$b: $ver (sha256=$sha)"
        fi
    done
}

cmd_systemd() {
    local action="${1:-status}"
    case "$action" in
        status)
            require_cmd systemctl
            systemctl status --no-pager monero-wallet-rpc.service xmr-gateway.service || true
            ;;
        install-dry-run)
            cat <<EOF
=== Systemd Production Installation Plan (Dry-Run) ===
Unit sources:
  - $REPO_ROOT/deploy/systemd/monero-wallet-rpc.service
  - $REPO_ROOT/deploy/systemd/xmr-gateway.service

Recommended commands (review before executing as root):
  sudo useradd --system --home /var/lib/xmr-gateway --shell /usr/sbin/nologin xmr-gateway
  sudo install -d -m 0700 -o xmr-gateway -g xmr-gateway /var/lib/xmr-gateway /var/lib/xmr-gateway/wallet
  sudo install -d -m 0750 -o root -g xmr-gateway /etc/xmr-gateway
  sudo install -m 0640 -o root -g xmr-gateway .env /etc/xmr-gateway/xmr-gateway.env
  sudo install -m 0755 target/release/xmr-gateway /usr/local/bin/xmr-gateway
  sudo install -m 0755 bin/monero-wallet-rpc /usr/local/bin/monero-wallet-rpc
  sudo cp deploy/systemd/monero-wallet-rpc.service deploy/systemd/xmr-gateway.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now monero-wallet-rpc.service xmr-gateway.service
EOF
            ;;
        restart)
            load_env 1
            confirm_dangerous_action "Restart systemd services monero-wallet-rpc.service and xmr-gateway.service"
            require_cmd systemctl
            sudo systemctl restart monero-wallet-rpc.service xmr-gateway.service
            systemctl status --no-pager monero-wallet-rpc.service xmr-gateway.service || true
            ;;
        *)
            die "Unknown systemd action '$action'. Expected: status | install-dry-run | restart"
            ;;
    esac
}

main() {
    parse_global_flags "$@"
    set -- "${ADMIN_REST_ARGS[@]}"
    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        start)     cmd_start "$@" ;;
        stop)      cmd_stop "$@" ;;
        restart)   cmd_restart "$@" ;;
        status)    cmd_status "$@" ;;
        logs)      cmd_logs "$@" ;;
        build)     cmd_build "$@" ;;
        setup-rpc) cmd_setup_rpc "$@" ;;
        systemd)   cmd_systemd "$@" ;;
        help|-h|--help) usage ;;
        *)         die "Unknown service command: '$cmd'. Run './admin.sh service help'." ;;
    esac
}

main "$@"
