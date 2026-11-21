#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Admin Suite — Service Lifecycle Module (admin/service.sh)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=admin/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    t service.usage
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
        log_info "$(t service.not_running "$name" "$pid_file")"
        return 0
    fi

    log_info "$(t service.sending_sigterm "$name" "$pid")"
    kill -TERM "$pid" 2>/dev/null || true

    local ticks=$((timeout_sec * 2))
    local i=0
    while kill -0 "$pid" 2>/dev/null && [[ "$i" -lt "$ticks" ]]; do
        sleep 0.5
        i=$((i + 1))
    done

    if kill -0 "$pid" 2>/dev/null; then
        log_warn "$(t service.sigkill_warn "$name" "$pid" "$timeout_sec")"
        kill -KILL "$pid" 2>/dev/null || true
        sleep 0.5
    fi

    rm -f "$pid_file"
    log_info "$(t service.stopped "$name")"
}

rpc_conf_path() {
    if [[ -n "${XDG_RUNTIME_DIR:-}" && -d "$XDG_RUNTIME_DIR" && -w "$XDG_RUNTIME_DIR" ]]; then
        printf '%s/xmr-gateway-wallet-rpc.conf\n' "$XDG_RUNTIME_DIR"
    else
        printf '%s/.monero-wallet-rpc.conf\n' "$DATA_DIR"
    fi
}

cleanup_rpc_conf() {
    if [[ -n "${XDG_RUNTIME_DIR:-}" ]]; then
        rm -f "${XDG_RUNTIME_DIR}/xmr-gateway-wallet-rpc.conf"
    fi
    if [[ -n "${DATA_DIR:-}" ]]; then
        rm -f "${DATA_DIR}/.monero-wallet-rpc.conf"
    fi
}

write_rpc_conf() {
    local target="$1"
    if [[ "$MONERO_RPC_USER" == *$'\n'* || "$MONERO_RPC_USER" == *$'\r'* || "$MONERO_RPC_PASS" == *$'\n'* || "$MONERO_RPC_PASS" == *$'\r'* ]]; then
        die "MONERO_RPC_USER and MONERO_RPC_PASS must not contain newline characters."
    fi
    (
        umask 077
        printf 'rpc-login=%s:%s\n' "$MONERO_RPC_USER" "$MONERO_RPC_PASS" > "$target"
    )
    chmod 600 "$target"
}

cmd_start() {
    load_env
    require_cmd curl
    mkdir -p "$DATA_DIR" "$WALLET_DIR" "$PID_DIR"
    chmod 700 "$DATA_DIR" "$WALLET_DIR" "$PID_DIR"

    local rpc_bin
    rpc_bin="$(find_monero_bin monero-wallet-rpc)" || die "$(t service.rpc_missing)"

    if [[ ! -f "${WALLET_FILE}.keys" ]]; then
        die "$(t service.wallet_missing "${WALLET_FILE}.keys")"
    fi
    if [[ ! -f "$WALLET_PASS_FILE" ]]; then
        die "$(t service.pass_missing "$WALLET_PASS_FILE")"
    fi
    if [[ ! -x "$GATEWAY_BIN" ]]; then
        log_warn "$(t service.building_missing_bin "$GATEWAY_BIN")"
        cmd_build
    fi

    # 1) Start monero-wallet-rpc if not already running
    local rpc_port
    rpc_port="$(extract_url_port "$MONERO_RPC_URL" 18082)"

    if read_pid_file "$RPC_PID_FILE" >/dev/null; then
        log_info "$(t service.already_running "monero-wallet-rpc" "$(cat "$RPC_PID_FILE")")"
    else
        if [[ -z "${MONERO_RPC_USER:-}" || -z "${MONERO_RPC_PASS:-}" ]] && ! is_truthy "$ALLOW_UNAUTHENTICATED_RPC"; then
            die "MONERO_RPC_USER / MONERO_RPC_PASS: $ACTIVE_ENV_FILE"
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
        local rpc_conf=""
        if [[ -n "${MONERO_RPC_USER:-}" ]]; then
            rpc_conf="$(rpc_conf_path)"
            write_rpc_conf "$rpc_conf"
            rpc_args+=(--config-file "$rpc_conf")
        fi
        if [[ -n "${MONERO_RPC_PROXY:-}" ]]; then
            rpc_args+=(--proxy "$MONERO_RPC_PROXY")
        fi

        log_step "$(t service.starting_rpc "$MONERO_NETWORK" "$rpc_port")"
        nohup "$rpc_bin" "${rpc_args[@]}" >/dev/null 2>&1 &
        local rpc_pid=$!
        printf '%s\n' "$rpc_pid" > "$RPC_PID_FILE"
        chmod 600 "$RPC_PID_FILE"

        local attempt=0
        while [[ "$attempt" -lt 120 ]]; do
            if ! kill -0 "$rpc_pid" 2>/dev/null; then
                rm -f "$RPC_PID_FILE"
                cleanup_rpc_conf
                log_err "$(t service.rpc_exited)"
                tail -n 20 "$RPC_LOG_FILE" >&2 || true
                exit 1
            fi
            if wallet_rpc_call "get_version" 2>/dev/null && [[ "$RPC_LAST_BODY" == *'"result"'* ]]; then
                log_info "$(t service.rpc_ready "$rpc_pid")"
                break
            fi
            sleep 0.5
            attempt=$((attempt + 1))
        done
        if [[ "$attempt" -ge 120 ]]; then
            cleanup_rpc_conf
            die "$(t service.rpc_timeout "$rpc_port")"
        fi
    fi

    # 2) Start xmr-gateway if not already running
    if read_pid_file "$GATEWAY_PID_FILE" >/dev/null; then
        log_info "$(t service.already_running "xmr-gateway" "$(cat "$GATEWAY_PID_FILE")")"
    else
        log_step "$(t service.starting_gw "$GATEWAY_BASE_URL" "$GATEWAY_LOG_FILE")"
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
                log_err "$(t service.gw_exited)"
                tail -n 25 "$GATEWAY_LOG_FILE" >&2 || true
                exit 1
            fi
            if gateway_api_call GET "/health" none 2>/dev/null && [[ "$API_LAST_HTTP_CODE" == "200" ]]; then
                log_info "$(t service.gw_healthy "$gw_pid" "$GATEWAY_BASE_URL")"
                return 0
            fi
            sleep 0.5
            attempt=$((attempt + 1))
        done
        log_warn "$(t service.gw_health_warn "$gw_pid")"
    fi
}

cmd_stop() {
    load_env
    confirm_dangerous_action "$(t service.confirm_stop)"
    # Stop gateway FIRST so it runs PRAGMA wal_checkpoint(TRUNCATE) cleanly while RPC is still alive if needed
    stop_process_gracefully "xmr-gateway" "$GATEWAY_PID_FILE" 25
    stop_process_gracefully "monero-wallet-rpc" "$RPC_PID_FILE" 15
    cleanup_rpc_conf
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

    local gw_state rpc_state
    if [[ -n "$gw_pid" ]]; then
        gw_state="$(t service.status_running "$gw_pid")"
    else
        gw_state="$(t service.status_stopped)"
    fi
    if [[ -n "$rpc_pid" ]]; then
        rpc_state="$(t service.status_running "$rpc_pid")"
    else
        rpc_state="$(t service.status_stopped)"
    fi

    printf '%s%s%s\n' "$C_BOLD" "$(t service.status_header)" "$C_RESET"
    tln service.status_env "$ACTIVE_ENV_FILE"
    tln service.status_net "$MONERO_NETWORK" "$WALLET_MODE"
    tln service.status_gw "$gw_state" "$GATEWAY_BASE_URL" "$health_http"
    [[ -z "$gw_pid" ]] && tln service.status_no_pid "$GATEWAY_PID_FILE"
    tln service.status_rpc "$rpc_state" "$MONERO_RPC_URL" "$rpc_http" "${rpc_ver:+, version=$rpc_ver}"
    [[ -z "$rpc_pid" ]] && tln service.status_no_pid "$RPC_PID_FILE"
    if [[ "$health_http" == "200" || "$health_http" == "503" ]]; then
        printf '\n%s%s%s\n' "$C_CYAN" "$(t service.status_health_hdr)" "$C_RESET"
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

    [[ -f "$log_file" ]] || die "$(t service.log_not_found "$log_file")"
    if [[ "$follow" -eq 1 ]]; then
        tail -n "$lines" -F "$log_file"
    else
        tail -n "$lines" "$log_file"
    fi
}

cmd_build() {
    require_cmd cargo
    log_step "$(t service.building_release)"
    (cd "$REPO_ROOT" && cargo build --release --locked)
    ls -lh "$REPO_ROOT/target/release/xmr-gateway"
}

resolve_setup_rpc_bin_dir() {
    if [[ -n "${XMR_BIN_DIR:-}" ]]; then
        printf '%s\n' "$XMR_BIN_DIR"
        return 0
    fi
    # System package installations (/usr/share/xmr-gateway, /usr/lib/*, or /etc/xmr-gateway/.env)
    # MUST always install Monero CLI into /usr/local/bin so monero-wallet-rpc.service finds it.
    if [[ "$REPO_ROOT" == "/usr/share/xmr-gateway" \
        || "$REPO_ROOT" == /usr/lib/* \
        || "${ACTIVE_ENV_FILE:-}" == "/etc/xmr-gateway/.env" \
        || "${ADMIN_ENV_FILE:-}" == "/etc/xmr-gateway/.env" ]]; then
        if [[ -w "/usr/local/bin" ]]; then
            printf '/usr/local/bin\n'
            return 0
        fi
        die "System installation requires write access to /usr/local/bin. Run with sudo (or set XMR_BIN_DIR)."
    fi
    if [[ -w "$REPO_ROOT" ]]; then
        printf '%s/bin\n' "$REPO_ROOT"
        return 0
    fi
    if [[ -w "/usr/local/bin" ]]; then
        printf '/usr/local/bin\n'
        return 0
    fi
    die "Neither '$REPO_ROOT' nor '/usr/local/bin' is writable. Run with sudo (for /usr/local/bin) or set XMR_BIN_DIR."
}

cmd_setup_rpc() {
    log_step "$(t service.setup_rpc_run)"

    local start_sh=""
    if [[ -f "$REPO_ROOT/start.sh" ]]; then
        start_sh="$REPO_ROOT/start.sh"
    elif [[ -f "/usr/share/xmr-gateway/start.sh" ]]; then
        start_sh="/usr/share/xmr-gateway/start.sh"
    else
        die "start.sh not found in '$REPO_ROOT' or '/usr/share/xmr-gateway'."
    fi

    local target_bin_dir
    target_bin_dir="$(resolve_setup_rpc_bin_dir)"

    XMR_BIN_DIR="$target_bin_dir" bash "$start_sh" --setup-rpc
    for b in monero-wallet-rpc monero-wallet-cli; do
        if [[ -x "$target_bin_dir/$b" ]]; then
            local sha ver
            sha="$(sha256sum "$target_bin_dir/$b" | awk '{print $1}')"
            ver="$("$target_bin_dir/$b" --version 2>/dev/null | head -n 1 || true)"
            log_info "$b ($target_bin_dir/$b): $ver (sha256=$sha)"
        fi
    done
}

cmd_systemd() {
    local action="${1:-status}"
    local systemd_src="$REPO_ROOT/deploy/systemd"
    if [[ ! -d "$systemd_src" && -d "/usr/lib/systemd/system" ]]; then
        systemd_src="/usr/lib/systemd/system"
    fi
    case "$action" in
        status)
            require_cmd systemctl
            systemctl status --no-pager \
                monero-wallet-rpc.service \
                xmr-gateway.service \
                xmr-gateway-backup.timer || true
            ;;
        install-dry-run)
            cat <<EOF
=== Systemd Production Installation Plan (Dry-Run) ===
Unit sources (${systemd_src}):
  - monero-wallet-rpc.service  (User=xmr-gateway, UMask=0077, RuntimeDirectory=xmr-gateway, KillSignal=SIGTERM, TimeoutStopSec=30)
  - xmr-gateway.service        (User=xmr-gateway, UMask=0077, EnvironmentFile=/etc/xmr-gateway/.env, KillSignal=SIGTERM, TimeoutStopSec=30)
  - xmr-gateway-backup.service (daily online SQLite hot backup via xmr-gateway-admin, 0600 + integrity_check)
  - xmr-gateway-backup.timer   (OnCalendar=daily, RandomizedDelaySec=15m, Persistent=true)

Recommended commands (review before executing as root):
  sudo groupadd --system xmr-gateway || true
  sudo useradd --system --gid xmr-gateway --home-dir /var/lib/xmr-gateway --shell /usr/sbin/nologin xmr-gateway || true
  sudo install -d -m 0700 -o xmr-gateway -g xmr-gateway /var/lib/xmr-gateway /var/lib/xmr-gateway/wallet /var/lib/xmr-gateway/backups
  sudo install -d -m 0750 -o root -g xmr-gateway /etc/xmr-gateway
  sudo install -m 0600 -o xmr-gateway -g xmr-gateway .env.example /etc/xmr-gateway/.env
  sudo install -m 0755 target/release/xmr-gateway /usr/bin/xmr-gateway
  sudo install -m 0755 deploy/packaging/xmr-gateway-admin /usr/bin/xmr-gateway-admin
  sudo install -D -m 0755 "${systemd_src}/render-wallet-rpc-conf.sh" /usr/share/xmr-gateway/scripts/render-wallet-rpc-conf.sh
  sudo install -m 0755 bin/monero-wallet-rpc /usr/local/bin/monero-wallet-rpc
  sudo cp "${systemd_src}"/monero-wallet-rpc.service \
          "${systemd_src}"/xmr-gateway.service \
          "${systemd_src}"/xmr-gateway-backup.service \
          "${systemd_src}"/xmr-gateway-backup.timer \
          /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now monero-wallet-rpc.service xmr-gateway.service xmr-gateway-backup.timer
EOF
            ;;
        restart)
            load_env 1
            confirm_dangerous_action "$(t service.confirm_systemd_restart)"
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
        *)         die "$(t service.unknown_cmd "$cmd")" ;;
    esac
}

main "$@"
