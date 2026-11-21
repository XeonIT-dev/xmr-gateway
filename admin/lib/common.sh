#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Admin Suite — Shared Library (admin/lib/common.sh)
# ==============================================================================
# Provides safe .env parsing, secret masking, zero-argv-leak curl wrappers
# (using curl --config - on stdin), merchant/operator RBAC header selection,
# Monero wallet/daemon JSON-RPC helpers, read-only SQLite access via python3,
# exact integer/Decimal piconero formatting, and Mainnet confirmation guards.
# ==============================================================================

if [[ -n "${_XMR_ADMIN_COMMON_LOADED:-}" ]]; then
    return 0
fi
_XMR_ADMIN_COMMON_LOADED=1

set -euo pipefail

# Resolve repository root reliably regardless of caller CWD
ADMIN_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADMIN_DIR="$(cd "$ADMIN_LIB_DIR/.." && pwd)"
REPO_ROOT="$(cd "$ADMIN_DIR/.." && pwd)"

# Global runtime options (inheritable from ./admin.sh or set by direct module calls)
ADMIN_ENV_FILE="${ADMIN_ENV_FILE:-}"
ADMIN_JSON="${ADMIN_JSON:-0}"
ADMIN_YES="${ADMIN_YES:-0}"
# shellcheck disable=SC2034
ADMIN_ENV_LOADED=0

# Load pure-Bash RU/EN i18n subsystem
# shellcheck source=admin/lib/i18n.sh
source "$ADMIN_LIB_DIR/i18n.sh"

# ANSI colors (disabled automatically when stdout/stderr is not a TTY or NO_COLOR is set)
# shellcheck disable=SC2034
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[1;31m'
    C_GREEN=$'\033[1;32m'
    C_YELLOW=$'\033[1;33m'
    C_BLUE=$'\033[1;34m'
    C_CYAN=$'\033[1;36m'
    C_MAGENTA=$'\033[1;35m'
else
    C_RESET=""
    C_BOLD=""
    C_DIM=""
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_BLUE=""
    C_CYAN=""
    C_MAGENTA=""
fi

if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
    CE_RESET=$'\033[0m'
    CE_RED=$'\033[1;31m'
    CE_YELLOW=$'\033[1;33m'
    CE_GREEN=$'\033[1;32m'
    CE_CYAN=$'\033[1;36m'
else
    CE_RESET=""
    CE_RED=""
    CE_YELLOW=""
    CE_GREEN=""
    CE_CYAN=""
fi

log_info() { printf '%s[INFO]%s %s\n' "$CE_GREEN" "$CE_RESET" "$*" >&2; }
log_warn() { printf '%s[WARN]%s %s\n' "$CE_YELLOW" "$CE_RESET" "$*" >&2; }
log_err()  { printf '%s[ERR ]%s %s\n' "$CE_RED" "$CE_RESET" "$*" >&2; }
log_step() { printf '%s[STEP]%s %s\n' "$CE_CYAN" "$CE_RESET" "$*" >&2; }

die() {
    log_err "$*"
    exit 1
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        die "$(t common.required_cmd_missing "$cmd")"
    fi
}

# Extracts global flags (--env, --lang, --json, --yes) from an argument list and stores
# the remaining arguments in the global array ADMIN_REST_ARGS.
ADMIN_REST_ARGS=()
parse_global_flags() {
    ADMIN_REST_ARGS=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --env)
                [[ $# -ge 2 ]] || die "$(t common.env_flag_missing)"
                ADMIN_ENV_FILE="$2"
                shift 2
                ;;
            --env=*)
                ADMIN_ENV_FILE="${1#*=}"
                shift
                ;;
            --lang)
                [[ $# -ge 2 ]] || die "$(t common.lang_flag_missing)"
                if ! i18n_normalize_lang "$2" >/dev/null; then
                    die "$(t common.invalid_lang "$2")"
                fi
                ADMIN_CLI_LANG="$(i18n_normalize_lang "$2")"
                shift 2
                ;;
            --lang=*)
                local raw_lang="${1#*=}"
                if ! i18n_normalize_lang "$raw_lang" >/dev/null; then
                    die "$(t common.invalid_lang "$raw_lang")"
                fi
                ADMIN_CLI_LANG="$(i18n_normalize_lang "$raw_lang")"
                shift
                ;;
            --json)
                ADMIN_JSON=1
                shift
                ;;
            --yes|-y)
                ADMIN_YES=1
                shift
                ;;
            --)
                shift
                while [[ $# -gt 0 ]]; do
                    ADMIN_REST_ARGS+=("$1")
                    shift
                done
                ;;
            *)
                ADMIN_REST_ARGS+=("$1")
                shift
                ;;
        esac
    done
    i18n_init
    export ADMIN_ENV_FILE ADMIN_JSON ADMIN_YES ADMIN_CLI_LANG ADMIN_ACTIVE_LANG ADMIN_LANG_SOURCE
}

resolve_env_file() {
    if [[ -n "${ADMIN_ENV_FILE:-}" ]]; then
        if [[ "$ADMIN_ENV_FILE" == /* ]]; then
            printf '%s\n' "$ADMIN_ENV_FILE"
        elif [[ -f "$PWD/$ADMIN_ENV_FILE" ]]; then
            printf '%s\n' "$PWD/$ADMIN_ENV_FILE"
        else
            printf '%s\n' "$REPO_ROOT/$ADMIN_ENV_FILE"
        fi
    elif [[ -f "$REPO_ROOT/.env" ]]; then
        printf '%s\n' "$REPO_ROOT/.env"
    elif [[ -f "/etc/xmr-gateway/.env" ]]; then
        printf '%s\n' "/etc/xmr-gateway/.env"
    else
        printf '%s\n' "$REPO_ROOT/.env"
    fi
}

# Safe KEY=VALUE parser for .env files (does not execute shell expressions in .env).
# Sets defaults matching src/config.rs and start.sh, and derives DATA_DIR / DB_PATH / WALLET_FILE.
load_env() {
    local optional="${1:-0}"
    local env_path
    env_path="$(resolve_env_file)"
    ACTIVE_ENV_FILE="$env_path"

    if [[ -f "$env_path" ]]; then
        local line key val
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Strip trailing CR (CRLF safety)
            line="${line%$'\r'}"
            # Skip blank lines and comments
            [[ "$line" =~ ^[[:space:]]*$ ]] && continue
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            # Optional leading `export `
            line="${line#export }"
            if [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]]; then
                key="${BASH_REMATCH[1]}"
                val="${BASH_REMATCH[2]}"
                # Trim leading whitespace on value
                val="${val#"${val%%[![:space:]]*}"}"
                # Strip matching outer single or double quotes
                if [[ ${#val} -ge 2 && "${val:0:1}" == '"' && "${val: -1}" == '"' ]]; then
                    val="${val:1:${#val}-2}"
                elif [[ ${#val} -ge 2 && "${val:0:1}" == "'" && "${val: -1}" == "'" ]]; then
                    val="${val:1:${#val}-2}"
                else
                    # Trim trailing whitespace on unquoted values
                    val="${val%"${val##*[![:space:]]}"}"
                fi
                printf -v "$key" '%s' "$val"
                export "${key?}"
            fi
        done < "$env_path"
    elif [[ "$optional" != "1" ]]; then
        die "$(t common.env_not_found "$env_path")"
    fi

    # Defaults matching src/config.rs and start.sh
    : "${HOST:=127.0.0.1}"
    : "${PORT:=8080}"
    : "${CORS_ALLOWED_ORIGINS:=}"
    : "${DATABASE_URL:=sqlite://data/xmr_gateway.db}"
    : "${API_SECRET_KEY:=}"
    : "${OPERATOR_API_KEY:=}"
    : "${WEBHOOK_SECRET:=}"
    : "${DEFAULT_WEBHOOK_URL:=}"
    : "${ALLOW_PRIVATE_WEBHOOKS:=false}"
    : "${REQUIRE_HTTPS_WEBHOOKS:=false}"
    : "${MONERO_NETWORK:=mainnet}"
    : "${MONERO_RPC_URL:=http://127.0.0.1:18082/json_rpc}"
    : "${MONERO_RPC_USER:=xmr_gateway_user}"
    : "${MONERO_RPC_PASS:=}"
    : "${MONERO_DAEMON_RPC_URL:=}"
    : "${MONERO_DAEMON_RPC_USER:=}"
    : "${MONERO_DAEMON_RPC_PASS:=}"
    : "${ALLOW_UNAUTHENTICATED_RPC:=false}"
    : "${ALLOW_INSECURE_REMOTE_RPC:=false}"
    : "${MONERO_REMOTE_NODE:=}"
    : "${MONERO_TRUSTED_DAEMON:=false}"
    : "${WALLET_RESTORE_HEIGHT:=}"
    : "${MONERO_RPC_PROXY:=}"
    : "${ENABLE_AUTO_SWEEP:=false}"
    : "${ALLOW_HOT_WALLET_WITHOUT_SWEEP:=false}"
    : "${COLD_WALLET_ADDRESS:=}"
    : "${MONERO_VIEW_ONLY_ADDRESS:=}"
    : "${MONERO_VIEW_ONLY_KEY:=}"
    : "${SWEEP_PRIORITY:=0}"
    : "${REQUIRED_CONFIRMATIONS:=10}"
    : "${SETTLEMENT_CONFIRMATIONS:=10}"
    : "${SUBADDRESS_MONITOR_DAYS:=0}"
    : "${INVOICE_TTL_SECONDS:=3600}"
    : "${SCAN_INTERVAL_SECONDS:=10}"
    : "${WEBHOOK_POLL_INTERVAL_SECONDS:=5}"
    : "${RUST_LOG:=info,xmr_gateway=debug}"
    : "${LOG_FORMAT:=json}"

    MONERO_NETWORK="${MONERO_NETWORK,,}"
    if [[ -z "${MONERO_REMOTE_NODE:-}" ]]; then
        MONERO_REMOTE_NODE="$(default_remote_node_for_network "$MONERO_NETWORK")"
    fi
    if [[ -z "${WALLET_RESTORE_HEIGHT:-}" ]]; then
        WALLET_RESTORE_HEIGHT="$(default_restore_height_for_network "$MONERO_NETWORK")"
    fi
    if [[ -z "${WALLET_MODE:-}" ]]; then
        if is_truthy "$ENABLE_AUTO_SWEEP"; then
            WALLET_MODE="hot_wallet"
        else
            WALLET_MODE="view_only"
        fi
    else
        WALLET_MODE="${WALLET_MODE,,}"
        WALLET_MODE="${WALLET_MODE//-/_}"
    fi

    # Derive gateway base URL, SQLite path, data/wallet directories, logs, and PID files
    GATEWAY_BASE_URL="http://${HOST}:${PORT}"
    DB_PATH="$(extract_sqlite_path "$DATABASE_URL")"
    if [[ -n "$DB_PATH" ]]; then
        DATA_DIR="$(dirname "$DB_PATH")"
    elif [[ "$ACTIVE_ENV_FILE" == "/etc/xmr-gateway/.env" && -d "/var/lib/xmr-gateway" ]]; then
        DATA_DIR="/var/lib/xmr-gateway"
    else
        DATA_DIR="$REPO_ROOT/data"
    fi
    WALLET_DIR="$DATA_DIR/wallet"
    WALLET_FILE="$WALLET_DIR/gateway_wallet"
    WALLET_PASS_FILE="$WALLET_DIR/gateway_wallet.password"
    RPC_LOG_FILE="$DATA_DIR/monero-wallet-rpc.log"
    CLI_LOG_FILE="$DATA_DIR/monero-wallet-cli.log"
    GATEWAY_LOG_FILE="$DATA_DIR/xmr-gateway.log"
    PID_DIR="$DATA_DIR/pids"
    RPC_PID_FILE="$PID_DIR/monero-wallet-rpc.pid"
    GATEWAY_PID_FILE="$PID_DIR/xmr-gateway.pid"
    GATEWAY_BIN="$(find_gateway_bin || printf '%s' "$REPO_ROOT/target/release/xmr-gateway")"
    BIN_DIR="$REPO_ROOT/bin"

    # shellcheck disable=SC2034
    ADMIN_ENV_LOADED=1
    export ACTIVE_ENV_FILE GATEWAY_BASE_URL DB_PATH DATA_DIR WALLET_DIR WALLET_FILE WALLET_PASS_FILE
    export RPC_LOG_FILE CLI_LOG_FILE GATEWAY_LOG_FILE PID_DIR RPC_PID_FILE GATEWAY_PID_FILE
    export GATEWAY_BIN BIN_DIR WALLET_MODE MONERO_NETWORK MONERO_REMOTE_NODE WALLET_RESTORE_HEIGHT
}

default_remote_node_for_network() {
    case "${1:-mainnet}" in
        stagenet) printf 'node.monerodevs.org:38089\n' ;;
        testnet)  printf 'testnet.xmr-tw.org:28081\n' ;;
        *)        printf 'xmr-node.cakewallet.com:18081\n' ;;
    esac
}

default_restore_height_for_network() {
    case "${1:-mainnet}" in
        stagenet) printf '1600000\n' ;;
        testnet)  printf '2600000\n' ;;
        *)        printf '3280000\n' ;;
    esac
}

is_truthy() {
    local v="${1:-}"
    v="${v,,}"
    [[ "$v" == "true" || "$v" == "1" || "$v" == "yes" ]]
}

extract_sqlite_path() {
    local url="${1:-}"
    if [[ -z "$url" || "$url" == "sqlite::memory:" || "$url" == *"mode=memory"* ]]; then
        printf '\n'
        return 0
    fi
    local p="$url"
    p="${p#sqlite://}"
    p="${p#sqlite:}"
    p="${p%%\?*}"
    if [[ -z "$p" || "$p" == ":memory:" ]]; then
        printf '\n'
        return 0
    fi
    if [[ "$p" == /* ]]; then
        printf '%s\n' "$p"
    elif [[ "${ACTIVE_ENV_FILE:-}" == "/etc/xmr-gateway/.env" ]]; then
        # Flatten legacy relative `data/...` to `/var/lib/xmr-gateway/...` so system package
        # DB_PATH (/var/lib/xmr-gateway/xmr_gateway.db) and WALLET_DIR (/var/lib/xmr-gateway/wallet)
        # remain consistent with postinst and monero-wallet-rpc.service.
        p="${p#./}"
        p="${p#data/}"
        printf '%s\n' "/var/lib/xmr-gateway/$p"
    else
        printf '%s\n' "$REPO_ROOT/$p"
    fi
}

extract_url_port() {
    local url="$1"
    local default_port="${2:-18082}"
    if [[ "$url" =~ :([0-9]+)(/|$) ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    else
        printf '%s\n' "$default_port"
    fi
}

mask_secret() {
    local val="${1:-}"
    if [[ -z "$val" ]]; then
        printf '<unset>'
        return 0
    fi
    local len=${#val}
    if [[ "$len" -le 8 ]]; then
        printf '*** (len=%d)' "$len"
    else
        printf '%s...%s (len=%d)' "${val:0:4}" "${val: -4}" "$len"
    fi
}

is_placeholder_secret() {
    local val="${1:-}"
    local lower="${val,,}"
    [[ -z "$val" || "$lower" == replace-with-* || "$lower" == changeme* || "$lower" == example-* ]]
}

# Escapes a string for curl --config double-quoted parameter syntax.
curl_cfg_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
}

# Mainnet safety confirmation guard for financial or destructive operations.
# Usage: confirm_dangerous_action "description" [always_confirm=0]
confirm_dangerous_action() {
    local action_desc="$1"
    local always_confirm="${2:-0}"
    local is_mainnet=0
    if [[ "${MONERO_NETWORK:-mainnet}" == "mainnet" ]]; then
        is_mainnet=1
    fi

    if [[ "$is_mainnet" -eq 0 && "$always_confirm" -eq 0 ]]; then
        return 0
    fi

    if [[ "$is_mainnet" -eq 1 ]]; then
        printf '\n%s==============================================================================%s\n' "$CE_RED" "$CE_RESET" >&2
        printf '%s%s%s\n' "$CE_RED" "$(t common.mainnet_banner_title)" "$CE_RESET" >&2
        printf '%s%s%s\n' "$CE_RED" "$(t common.mainnet_action_label "$action_desc")" "$CE_RESET" >&2
        printf '%s%s%s\n' "$CE_RED" "$(t common.mainnet_env_label "${ACTIVE_ENV_FILE:-.env}")" "$CE_RESET" >&2
        printf '%s==============================================================================%s\n' "$CE_RED" "$CE_RESET" >&2
    else
        printf '\n%s%s%s\n' "$CE_YELLOW" "$(t common.confirm_tag "$action_desc")" "$CE_RESET" >&2
    fi

    if [[ "${ADMIN_YES:-0}" -eq 1 ]]; then
        log_warn "$(t common.proceed_non_interactive)"
        return 0
    fi

    if [[ ! -t 0 ]]; then
        die "$(t common.refuse_non_interactive "$action_desc")"
    fi

    local reply=""
    printf '%s' "$(t common.confirm_prompt)" >&2
    IFS= read -r reply || true
    if [[ "$reply" != "yes" ]]; then
        die "$(t common.cancelled)"
    fi
}

# Finds xmr-gateway binary in local release build, system paths, or PATH.
find_gateway_bin() {
    local candidate
    for candidate in \
        "$REPO_ROOT/target/release/xmr-gateway" \
        "$REPO_ROOT/xmr-gateway" \
        "/usr/bin/xmr-gateway" \
        "/usr/local/bin/xmr-gateway"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    if command -v xmr-gateway >/dev/null 2>&1; then
        command -v xmr-gateway
        return 0
    fi
    return 1
}

# Finds monero-wallet-rpc / monero-wallet-cli in ./bin/, standard system paths, or PATH.
find_monero_bin() {
    local name="$1"
    local candidate
    for candidate in \
        "$REPO_ROOT/bin/$name" \
        "/usr/local/bin/$name" \
        "/usr/bin/$name"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
        return 0
    fi
    return 1
}

# Safely updates or appends KEY=VALUE in a target .env file preserving 0600 permissions,
# original ownership (e.g. xmr-gateway:xmr-gateway under /etc/xmr-gateway/.env), and
# SELinux context (same-directory mktemp for atomic rename + optional restorecon).
set_env_kv_file() {
    local target_file="$1"
    local key="$2"
    local value="$3"
    local target_dir had_existing=0 orig_owner=""
    target_dir="$(dirname "$target_file")"
    if [[ -f "$target_file" ]]; then
        had_existing=1
        if [[ "$(id -u)" -eq 0 ]]; then
            orig_owner="$(stat -c '%u:%g' "$target_file" 2>/dev/null || true)"
        fi
    fi
    local tmp_env
    tmp_env="$(mktemp "${target_dir}/.env.tmp.XXXXXX")"
    chmod 600 "$tmp_env"
    if [[ "$had_existing" -eq 1 ]] && grep -qE "^[[:space:]]*(export[[:space:]]+)?${key}=" "$target_file"; then
        awk -v k="$key" -v v="$value" '
            BEGIN { replaced = 0 }
            $0 ~ "^[[:space:]]*(export[[:space:]]+)?" k "=" {
                if (!replaced) {
                    print k "=" v
                    replaced = 1
                }
                next
            }
            { print }
        ' "$target_file" > "$tmp_env"
    else
        if [[ "$had_existing" -eq 1 ]]; then
            cat "$target_file" > "$tmp_env"
        fi
        printf '\n%s=%s\n' "$key" "$value" >> "$tmp_env"
    fi
    if [[ "$(id -u)" -eq 0 && "$had_existing" -eq 1 ]]; then
        if ! chown --reference="$target_file" "$tmp_env" 2>/dev/null; then
            if [[ -n "$orig_owner" ]]; then
                chown "$orig_owner" "$tmp_env"
            fi
        fi
    fi
    chmod 600 "$tmp_env"
    mv "$tmp_env" "$target_file"
    if [[ "$target_file" == "/etc/xmr-gateway/.env" ]] && command -v restorecon >/dev/null 2>&1; then
        restorecon "$target_file" 2>/dev/null || true
    fi
}

# ==============================================================================
# Zero-Argv-Leak HTTP API Client (secrets passed via curl --config - on stdin)
# ==============================================================================
# Globals populated by gateway_api_call:
#   API_LAST_HTTP_CODE
#   API_LAST_BODY
# shellcheck disable=SC2034
API_LAST_HTTP_CODE=""
# shellcheck disable=SC2034
API_LAST_BODY=""

# Usage: gateway_api_call <METHOD> <PATH> <auth_mode: none|merchant|operator|health_api|health_operator> [json_body]
gateway_api_call() {
    require_cmd curl
    local method="$1"
    local path="$2"
    local auth_mode="$3"
    local json_body="${4:-}"

    local url="${GATEWAY_BASE_URL}${path}"
    local tmp_out tmp_body=""
    tmp_out="$(mktemp)"
    chmod 600 "$tmp_out"

    local curl_args=(
        -sS
        --connect-timeout 5
        --max-time 35
        -X "$method"
        -o "$tmp_out"
        -w '%{http_code}'
        --config -
    )

    if [[ -n "$json_body" ]]; then
        tmp_body="$(mktemp)"
        chmod 600 "$tmp_body"
        printf '%s' "$json_body" > "$tmp_body"
        curl_args+=(--data-binary "@${tmp_body}")
    fi

    local cfg_lines=()
    if [[ -n "$json_body" ]]; then
        cfg_lines+=("header = \"Content-Type: application/json\"")
    fi

    case "$auth_mode" in
        none)
            ;;
        merchant|health_api)
            [[ -n "${API_SECRET_KEY:-}" ]] || { rm -f "$tmp_out" "${tmp_body:-}"; die "$(t common.missing_api_key "${ACTIVE_ENV_FILE:-.env}")"; }
            cfg_lines+=("header = \"X-API-Key: $(curl_cfg_escape "$API_SECRET_KEY")\"")
            ;;
        operator)
            if [[ -n "${OPERATOR_API_KEY:-}" ]]; then
                cfg_lines+=("header = \"X-Operator-Key: $(curl_cfg_escape "$OPERATOR_API_KEY")\"")
            elif [[ -n "${API_SECRET_KEY:-}" ]]; then
                cfg_lines+=("header = \"X-API-Key: $(curl_cfg_escape "$API_SECRET_KEY")\"")
            else
                rm -f "$tmp_out" "${tmp_body:-}"
                die "$(t common.missing_operator_or_api_key "${ACTIVE_ENV_FILE:-.env}")"
            fi
            ;;
        health_operator)
            if [[ -n "${OPERATOR_API_KEY:-}" ]]; then
                cfg_lines+=("header = \"X-Operator-Key: $(curl_cfg_escape "$OPERATOR_API_KEY")\"")
            elif [[ -n "${API_SECRET_KEY:-}" ]]; then
                cfg_lines+=("header = \"X-Operator-Key: $(curl_cfg_escape "$API_SECRET_KEY")\"")
            else
                rm -f "$tmp_out" "${tmp_body:-}"
                die "Neither OPERATOR_API_KEY nor API_SECRET_KEY is set."
            fi
            ;;
        *)
            rm -f "$tmp_out" "${tmp_body:-}"
            die "Internal error: unknown auth_mode '$auth_mode'"
            ;;
    esac

    local rc=0
    # shellcheck disable=SC2034
    API_LAST_HTTP_CODE="$(
        printf '%s\n' "${cfg_lines[@]}" | curl "${curl_args[@]}" "$url"
    )" || rc=$?

    # shellcheck disable=SC2034
    API_LAST_BODY="$(cat "$tmp_out" 2>/dev/null || true)"
    rm -f "$tmp_out" "${tmp_body:-}"
    return "$rc"
}

# ==============================================================================
# Zero-Argv-Leak Monero Wallet & Daemon JSON-RPC Helpers
# ==============================================================================
# shellcheck disable=SC2034
RPC_LAST_HTTP_CODE=""
# shellcheck disable=SC2034
RPC_LAST_BODY=""

# Usage: monero_json_rpc_call <url> <user> <pass> <method> [params_json]
monero_json_rpc_call() {
    require_cmd curl
    local rpc_url="$1"
    local rpc_user="$2"
    local rpc_pass="$3"
    local rpc_method="$4"
    local params_json="${5:-}"

    local tmp_out tmp_body
    tmp_out="$(mktemp)"
    tmp_body="$(mktemp)"
    chmod 600 "$tmp_out" "$tmp_body"

    if [[ -n "$params_json" ]]; then
        printf '{"jsonrpc":"2.0","id":"admin","method":"%s","params":%s}' "$rpc_method" "$params_json" > "$tmp_body"
    else
        printf '{"jsonrpc":"2.0","id":"admin","method":"%s"}' "$rpc_method" > "$tmp_body"
    fi

    local cfg_lines=('header = "Content-Type: application/json"')
    if [[ -n "$rpc_user" ]]; then
        cfg_lines+=("digest")
        cfg_lines+=("user = \"$(curl_cfg_escape "${rpc_user}:${rpc_pass}")\"")
    fi

    local rc=0
    # shellcheck disable=SC2034
    RPC_LAST_HTTP_CODE="$(
        printf '%s\n' "${cfg_lines[@]}" | curl -sS \
            --connect-timeout 5 \
            --max-time 60 \
            -X POST \
            --data-binary "@${tmp_body}" \
            -o "$tmp_out" \
            -w '%{http_code}' \
            --config - \
            "$rpc_url"
    )" || rc=$?

    # shellcheck disable=SC2034
    RPC_LAST_BODY="$(cat "$tmp_out" 2>/dev/null || true)"
    rm -f "$tmp_out" "$tmp_body"
    return "$rc"
}

wallet_rpc_call() {
    local method="$1"
    local params_json="${2:-}"
    monero_json_rpc_call "$MONERO_RPC_URL" "${MONERO_RPC_USER:-}" "${MONERO_RPC_PASS:-}" "$method" "$params_json"
}

daemon_rpc_call() {
    local method="$1"
    local params_json="${2:-}"
    local daemon_url="${MONERO_DAEMON_RPC_URL:-}"
    if [[ -z "$daemon_url" ]]; then
        if [[ -n "${MONERO_REMOTE_NODE:-}" ]]; then
            local node="$MONERO_REMOTE_NODE"
            if [[ "$node" == http://* || "$node" == https://* ]]; then
                daemon_url="${node%/}/json_rpc"
            else
                daemon_url="http://${node%/}/json_rpc"
            fi
        else
            return 1
        fi
    fi
    monero_json_rpc_call "$daemon_url" "${MONERO_DAEMON_RPC_USER:-}" "${MONERO_DAEMON_RPC_PASS:-}" "$method" "$params_json"
}

# ==============================================================================
# Exact Piconero / XMR Conversion & JSON Formatting Helpers (Python3, no floats)
# ==============================================================================
piconero_to_xmr() {
    python3 - "$1" <<'PYEOF'
import sys
raw = int(sys.argv[1])
sign = "-" if raw < 0 else ""
n = abs(raw)
whole, frac = divmod(n, 10**12)
print(f"{sign}{whole}.{frac:012d}")
PYEOF
}

xmr_to_piconero() {
    python3 - "$1" <<'PYEOF'
from decimal import Decimal, InvalidOperation
import sys

raw = sys.argv[1].strip()
try:
    d = Decimal(raw)
except InvalidOperation:
    sys.stderr.write(f"Invalid XMR decimal amount: '{raw}'\n")
    sys.exit(1)

if not d.is_finite() or d <= 0:
    sys.stderr.write(f"Amount must be a positive finite XMR number: '{raw}'\n")
    sys.exit(1)

scaled = d * Decimal(10**12)
if scaled != scaled.to_integral_value():
    sys.stderr.write(f"Amount exceeds 12 decimal places (piconero precision): '{raw}'\n")
    sys.exit(1)

val = int(scaled)
if val <= 0 or val > (2**63 - 1):
    sys.stderr.write(f"Amount out of valid piconero range: '{raw}'\n")
    sys.exit(1)

print(val)
PYEOF
}

pretty_print_json() {
    python3 -m json.tool 2>/dev/null || cat
}

# Runs a read-only Python script against DB_PATH with uri mode=ro and busy_timeout=5000.
# Passes DB_PATH as sys.argv[1] and any extra args as sys.argv[2..].
# Script source is read from stdin.
sqlite_ro_python() {
    require_cmd python3
    [[ -n "${DB_PATH:-}" ]] || die "$(t common.db_memory_only)"
    [[ -f "$DB_PATH" ]] || die "$(t common.db_not_found "$DB_PATH")"
    python3 - "$DB_PATH" "$@"
}

# Check file permissions in octal (Unix)
file_perm_octal() {
    local path="$1"
    python3 - "$path" <<'PYEOF'
import os, stat, sys
p = sys.argv[1]
if not os.path.exists(p):
    print("MISSING")
else:
    print(f"{stat.S_IMODE(os.stat(p).st_mode):04o}")
PYEOF
}
