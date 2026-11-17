#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Native Bare-Metal Orchestrator (Fedora / Debian)
# ==============================================================================
# Manages .env secret initialization, optional SHA256-verified Monero CLI setup,
# non-interactive mainnet/stagenet wallet creation, local monero-wallet-rpc
# lifecycle (bound strictly to 127.0.0.1:18082 against a remote node), release
# build, and coordinated SIGINT/SIGTERM shutdown.
# ==============================================================================

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE="$SCRIPT_DIR/.env"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"
BIN_DIR="$SCRIPT_DIR/bin"
DATA_DIR="$SCRIPT_DIR/data"
WALLET_DIR="$DATA_DIR/wallet"
WALLET_FILE="$WALLET_DIR/gateway_wallet"
WALLET_PASS_FILE="$WALLET_DIR/gateway_wallet.password"
RPC_LOG_FILE="$DATA_DIR/monero-wallet-rpc.log"
CLI_LOG_FILE="$DATA_DIR/monero-wallet-cli.log"
GATEWAY_BIN="$SCRIPT_DIR/target/release/xmr-gateway"

MONERO_CLI_URL="https://downloads.getmonero.org/cli/linux64"
MONERO_HASHES_URL="https://www.getmonero.org/downloads/hashes.txt"

RPC_PID=""
GATEWAY_PID=""
CLEANED_UP=0

log_info() { printf '\033[1;32m[INFO]\033[0m %s\n' "$*"; }
log_warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
log_err()  { printf '\033[1;31m[ERR ]\033[0m %s\n' "$*" >&2; }

usage() {
    cat <<'EOF'
Usage: ./start.sh [OPTIONS]

Options:
  --setup-rpc         Download and SHA256-verify official Monero CLI tools into ./bin/ and exit.
  --init-wallet-only  Ensure .env and wallet files are initialized, then exit without starting servers.
  -h, --help          Show this help message.
EOF
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_err "Required command '$cmd' was not found in PATH."
        exit 1
    fi
}

cleanup() {
    if [[ "$CLEANED_UP" -eq 1 ]]; then
        return
    fi
    CLEANED_UP=1

    if [[ -n "$GATEWAY_PID" ]] && kill -0 "$GATEWAY_PID" 2>/dev/null; then
        log_info "Stopping xmr-gateway (PID $GATEWAY_PID)..."
        kill -TERM "$GATEWAY_PID" 2>/dev/null || true
        wait "$GATEWAY_PID" 2>/dev/null || true
    fi

    if [[ -n "$RPC_PID" ]] && kill -0 "$RPC_PID" 2>/dev/null; then
        log_info "Stopping monero-wallet-rpc (PID $RPC_PID)..."
        kill -TERM "$RPC_PID" 2>/dev/null || true
        local waited=0
        while kill -0 "$RPC_PID" 2>/dev/null && [[ "$waited" -lt 20 ]]; do
            sleep 0.5
            waited=$((waited + 1))
        done
        if kill -0 "$RPC_PID" 2>/dev/null; then
            log_warn "monero-wallet-rpc did not exit in 10s; sending SIGKILL."
            kill -KILL "$RPC_PID" 2>/dev/null || true
        fi
        wait "$RPC_PID" 2>/dev/null || true
    fi
}

on_signal() {
    printf '\n'
    log_info "Signal received; shutting down cleanly..."
    cleanup
    exit 0
}

trap on_signal INT TERM
trap cleanup EXIT

set_env_kv() {
    local key="$1"
    local value="$2"
    if grep -q "^${key}=" "$ENV_FILE"; then
        local tmp_env
        tmp_env="$(mktemp)"
        awk -v k="$key" -v v="$value" '
            index($0, k "=") == 1 { print k "=" v; next }
            { print }
        ' "$ENV_FILE" > "$tmp_env"
        mv "$tmp_env" "$ENV_FILE"
    else
        printf '\n%s=%s\n' "$key" "$value" >> "$ENV_FILE"
    fi
}

is_placeholder_secret() {
    local val="$1"
    [[ -z "$val" || "$val" == replace-with-* || "$val" == changeme* ]]
}

ensure_env_file() {
    mkdir -p "$DATA_DIR" "$WALLET_DIR"
    chmod 700 "$DATA_DIR" "$WALLET_DIR"

    if [[ ! -f "$ENV_FILE" ]]; then
        if [[ ! -f "$ENV_EXAMPLE" ]]; then
            log_err "Neither .env nor .env.example exists in $SCRIPT_DIR."
            exit 1
        fi
        log_info "Creating .env from .env.example..."
        cp "$ENV_EXAMPLE" "$ENV_FILE"
    fi
    chmod 600 "$ENV_FILE"

    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a

    if is_placeholder_secret "${API_SECRET_KEY:-}"; then
        require_cmd openssl
        set_env_kv "API_SECRET_KEY" "$(openssl rand -hex 32)"
        log_info "Generated fresh API_SECRET_KEY in .env"
    fi

    if is_placeholder_secret "${WEBHOOK_SECRET:-}"; then
        require_cmd openssl
        set_env_kv "WEBHOOK_SECRET" "$(openssl rand -hex 32)"
        log_info "Generated fresh WEBHOOK_SECRET in .env"
    fi

    if is_placeholder_secret "${MONERO_RPC_PASS:-}"; then
        require_cmd openssl
        set_env_kv "MONERO_RPC_PASS" "$(openssl rand -hex 24)"
        log_info "Generated fresh MONERO_RPC_PASS in .env"
    fi

    chmod 600 "$ENV_FILE"

    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a

    : "${HOST:=127.0.0.1}"
    : "${PORT:=8080}"
    : "${MONERO_NETWORK:=mainnet}"
    : "${MONERO_RPC_URL:=http://127.0.0.1:18082/json_rpc}"
    : "${MONERO_RPC_USER:=xmr_gateway_user}"
    : "${MONERO_REMOTE_NODE:=xmr-node.cakewallet.com:18081}"
    : "${WALLET_RESTORE_HEIGHT:=3280000}"
    : "${ENABLE_AUTO_SWEEP:=false}"
    : "${MONERO_TRUSTED_DAEMON:=false}"
    : "${ALLOW_HOT_WALLET_WITHOUT_SWEEP:=false}"

    if [[ -z "${WALLET_MODE:-}" ]]; then
        if [[ "${ENABLE_AUTO_SWEEP,,}" == "true" || "${ENABLE_AUTO_SWEEP}" == "1" ]]; then
            WALLET_MODE="hot_wallet"
        else
            WALLET_MODE="view_only"
        fi
    else
        WALLET_MODE="${WALLET_MODE,,}"
        WALLET_MODE="${WALLET_MODE//-/_}"
    fi
    export WALLET_MODE MONERO_TRUSTED_DAEMON ALLOW_HOT_WALLET_WITHOUT_SWEEP

    case "$WALLET_MODE" in
        view_only|hot_wallet) ;;
        *)
            log_err "Invalid WALLET_MODE='$WALLET_MODE': expected 'view_only' or 'hot_wallet'."
            exit 1
            ;;
    esac

    if [[ "${ENABLE_AUTO_SWEEP,,}" == "true" || "${ENABLE_AUTO_SWEEP}" == "1" ]] && [[ "$WALLET_MODE" != "hot_wallet" ]]; then
        log_err "ENABLE_AUTO_SWEEP=true requires WALLET_MODE=hot_wallet (got '$WALLET_MODE')."
        exit 1
    fi

    if [[ "$WALLET_MODE" == "hot_wallet" ]] \
        && [[ "${ENABLE_AUTO_SWEEP,,}" != "true" && "${ENABLE_AUTO_SWEEP}" != "1" ]] \
        && [[ "${ALLOW_HOT_WALLET_WITHOUT_SWEEP,,}" != "true" && "${ALLOW_HOT_WALLET_WITHOUT_SWEEP}" != "1" ]]; then
        log_err "WALLET_MODE=hot_wallet requires ENABLE_AUTO_SWEEP=true (or explicit ALLOW_HOT_WALLET_WITHOUT_SWEEP=true)."
        exit 1
    fi

    case "$MONERO_NETWORK" in
        mainnet|stagenet) ;;
        *)
            log_err "Invalid MONERO_NETWORK='$MONERO_NETWORK': expected 'mainnet' or 'stagenet'."
            exit 1
            ;;
    esac
}

validate_wallet_bootstrap_policy() {
    if [[ ! -f "${WALLET_FILE}.keys" && "$WALLET_MODE" == "view_only" ]]; then
        if [[ -z "${MONERO_VIEW_ONLY_ADDRESS:-}" || -z "${MONERO_VIEW_ONLY_KEY:-}" ]]; then
            log_err "WALLET_MODE=view_only requires MONERO_VIEW_ONLY_ADDRESS and MONERO_VIEW_ONLY_KEY in .env when no existing wallet exists."
            log_err "Refusing to silently generate a hot wallet with a private spend key in View-Only Zero-Trust mode."
            log_err "Provide view-only keys in .env, or explicitly opt into WALLET_MODE=hot_wallet (+ ENABLE_AUTO_SWEEP=true or ALLOW_HOT_WALLET_WITHOUT_SWEEP=true)."
            exit 1
        fi
    fi
}

network_flags() {
    if [[ "$MONERO_NETWORK" == "stagenet" ]]; then
        printf '%s\n' "--stagenet"
    fi
}

find_monero_bin() {
    local name="$1"
    if [[ -x "$BIN_DIR/$name" ]]; then
        printf '%s\n' "$BIN_DIR/$name"
        return 0
    fi
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
        return 0
    fi
    return 1
}

download_and_verify_monero_cli() {
    require_cmd curl
    require_cmd tar
    require_cmd bzip2
    require_cmd sha256sum

    local arch os
    arch="$(uname -m)"
    os="$(uname -s)"
    if [[ "$os" != "Linux" || "$arch" != "x86_64" ]]; then
        log_err "Automatic binary download supports Linux x86_64 only (detected $os/$arch)."
        log_err "Please install monero-wallet-rpc and monero-wallet-cli manually into PATH or ./bin/."
        exit 1
    fi

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap "rm -rf '$tmp_dir'" RETURN

    log_info "Resolving latest official Monero CLI Linux x64 release..."
    local effective_url tarball_name expected_sha256
    effective_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$MONERO_CLI_URL")"
    tarball_name="$(basename "$effective_url")"

    log_info "Fetching official SHA256 checksums from getmonero.org..."
    curl -fsSL "$MONERO_HASHES_URL" -o "$tmp_dir/hashes.txt"
    expected_sha256="$(awk -v file="$tarball_name" '$2 == file { print $1; exit }' "$tmp_dir/hashes.txt")"

    if [[ ! "$expected_sha256" =~ ^[0-9a-fA-F]{64}$ ]]; then
        log_err "Failed to locate valid SHA256 digest for '$tarball_name' in hashes.txt."
        exit 1
    fi

    log_info "Downloading $tarball_name..."
    curl -fSL --progress-bar "$effective_url" -o "$tmp_dir/$tarball_name"

    log_info "Verifying SHA256 checksum ($expected_sha256)..."
    if ! (cd "$tmp_dir" && printf '%s  %s\n' "$expected_sha256" "$tarball_name" | sha256sum -c -); then
        log_err "SHA256 verification failed for $tarball_name! Aborting."
        exit 1
    fi

    mkdir -p "$BIN_DIR"
    log_info "Extracting monero-wallet-rpc and monero-wallet-cli into ./bin/..."
    tar -xjf "$tmp_dir/$tarball_name" -C "$BIN_DIR" --strip-components=1 \
        --wildcards '*/monero-wallet-rpc' '*/monero-wallet-cli'
    chmod 755 "$BIN_DIR/monero-wallet-rpc" "$BIN_DIR/monero-wallet-cli"

    log_info "Monero CLI binaries installed and verified in $BIN_DIR"
}

ensure_monero_binaries() {
    local force_setup="${1:-0}"

    if [[ "$force_setup" -eq 1 ]]; then
        download_and_verify_monero_cli
        return 0
    fi

    if find_monero_bin monero-wallet-rpc >/dev/null 2>&1 && \
       { [[ -f "${WALLET_FILE}.keys" ]] || find_monero_bin monero-wallet-cli >/dev/null 2>&1; }; then
        return 0
    fi

    log_warn "monero-wallet-rpc (or monero-wallet-cli for first-time wallet setup) was not found in ./bin/ or PATH."
    if [[ -t 0 ]]; then
        printf 'Download & SHA256-verify the official Linux x64 Monero CLI release into ./bin/? [Y/n]: '
        local reply
        read -r reply
        if [[ -z "$reply" || "$reply" =~ ^[Yy]$ ]]; then
            download_and_verify_monero_cli
            return 0
        fi
    fi

    cat >&2 <<EOF
Please install monero-wallet-rpc and monero-wallet-cli manually, or run:
  ./start.sh --setup-rpc
Official download: $MONERO_CLI_URL
SHA256 checksums:  $MONERO_HASHES_URL
EOF
    exit 1
}

ensure_wallet() {
    mkdir -p "$WALLET_DIR"
    chmod 700 "$WALLET_DIR"

    if [[ ! -f "$WALLET_PASS_FILE" ]]; then
        require_cmd openssl
        printf '%s' "$(openssl rand -hex 24)" > "$WALLET_PASS_FILE"
        chmod 600 "$WALLET_PASS_FILE"
        log_info "Created wallet password file at $WALLET_PASS_FILE"
    fi

    if [[ -f "${WALLET_FILE}.keys" ]]; then
        return 0
    fi

    local wallet_cli
    wallet_cli="$(find_monero_bin monero-wallet-cli)"

    local net_args=()
    if [[ "$MONERO_NETWORK" == "stagenet" ]]; then
        net_args+=(--stagenet)
    fi

    log_info "Initializing $MONERO_NETWORK wallet at $WALLET_FILE (restore height: $WALLET_RESTORE_HEIGHT)..."

    if [[ "$WALLET_MODE" == "view_only" ]]; then
        if [[ -z "${MONERO_VIEW_ONLY_ADDRESS:-}" || -z "${MONERO_VIEW_ONLY_KEY:-}" ]]; then
            log_err "WALLET_MODE=view_only requires MONERO_VIEW_ONLY_ADDRESS and MONERO_VIEW_ONLY_KEY in .env."
            exit 1
        fi
        log_info "Creating View-Only wallet non-interactively from MONERO_VIEW_ONLY_ADDRESS/KEY..."
        printf '%s\n%s\n%s\nN\n' \
            "$MONERO_VIEW_ONLY_ADDRESS" \
            "$MONERO_VIEW_ONLY_KEY" \
            "$WALLET_RESTORE_HEIGHT" | "$wallet_cli" \
            --offline \
            "${net_args[@]}" \
            --generate-from-view-key "$WALLET_FILE" \
            --password-file "$WALLET_PASS_FILE" \
            --restore-height "$WALLET_RESTORE_HEIGHT" \
            --log-file "$CLI_LOG_FILE" \
            --command address
    elif [[ "$WALLET_MODE" == "hot_wallet" ]]; then
        log_warn "WALLET_MODE=hot_wallet: generating new $MONERO_NETWORK wallet at $WALLET_FILE. Back up the 25-word seed phrase below!"
        printf 'N\n' | "$wallet_cli" \
            --offline \
            "${net_args[@]}" \
            --generate-new-wallet "$WALLET_FILE" \
            --password-file "$WALLET_PASS_FILE" \
            --restore-height "$WALLET_RESTORE_HEIGHT" \
            --mnemonic-language English \
            --log-file "$CLI_LOG_FILE" \
            --command address
    else
        log_err "Refusing wallet generation for unrecognized WALLET_MODE='$WALLET_MODE'."
        exit 1
    fi

    if [[ ! -f "${WALLET_FILE}.keys" ]]; then
        log_err "Wallet creation failed (missing ${WALLET_FILE}.keys). Check $CLI_LOG_FILE."
        exit 1
    fi

    chmod 600 "${WALLET_FILE}"* 2>/dev/null || true
    log_info "Wallet initialized successfully."
}

extract_rpc_port() {
    local url="$1"
    if [[ "$url" =~ :([0-9]+)(/|$) ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    else
        printf '18082\n'
    fi
}

start_monero_wallet_rpc() {
    mkdir -p "$DATA_DIR" "$WALLET_DIR"
    chmod 700 "$DATA_DIR" "$WALLET_DIR"
    local rpc_bin rpc_port
    rpc_bin="$(find_monero_bin monero-wallet-rpc)"
    rpc_port="$(extract_rpc_port "$MONERO_RPC_URL")"

    if command -v ss >/dev/null 2>&1 && ss -ltn | awk '{print $4}' | grep -qE "(^|:)${rpc_port}$"; then
        log_err "TCP port $rpc_port is already in use on localhost. Stop the existing process before starting."
        exit 1
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

    if [[ "${MONERO_TRUSTED_DAEMON,,}" == "true" || "${MONERO_TRUSTED_DAEMON}" == "1" ]]; then
        log_warn "MONERO_TRUSTED_DAEMON=true: passing --trusted-daemon to monero-wallet-rpc"
        rpc_args+=(--trusted-daemon)
    else
        log_info "MONERO_TRUSTED_DAEMON=false: running monero-wallet-rpc with --untrusted-daemon"
        rpc_args+=(--untrusted-daemon)
    fi

    if [[ "$MONERO_NETWORK" == "stagenet" ]]; then
        rpc_args+=(--stagenet)
    fi

    if [[ -n "${MONERO_RPC_USER:-}" ]]; then
        rpc_args+=(--rpc-login "${MONERO_RPC_USER}:${MONERO_RPC_PASS}")
    else
        rpc_args+=(--disable-rpc-login)
    fi

    if [[ -n "${MONERO_RPC_PROXY:-}" ]]; then
        log_info "Routing monero-wallet-rpc daemon traffic via SOCKS5 proxy: $MONERO_RPC_PROXY"
        rpc_args+=(--proxy "$MONERO_RPC_PROXY")
    fi

    log_info "Starting monero-wallet-rpc ($MONERO_NETWORK) on 127.0.0.1:${rpc_port} (remote node: $MONERO_REMOTE_NODE)..."
    "$rpc_bin" "${rpc_args[@]}" >/dev/null 2>&1 &
    RPC_PID=$!

    local curl_auth_args=()
    if [[ -n "${MONERO_RPC_USER:-}" ]]; then
        curl_auth_args=(--digest -u "${MONERO_RPC_USER}:${MONERO_RPC_PASS}")
    fi

    log_info "Waiting for monero-wallet-rpc readiness..."
    local attempt=0
    while [[ "$attempt" -lt 120 ]]; do
        if ! kill -0 "$RPC_PID" 2>/dev/null; then
            log_err "monero-wallet-rpc exited unexpectedly. Last 25 log lines:"
            tail -n 25 "$RPC_LOG_FILE" >&2 || true
            exit 1
        fi

        local resp
        resp="$(curl -sS "${curl_auth_args[@]}" \
            -H 'Content-Type: application/json' \
            -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' \
            "http://127.0.0.1:${rpc_port}/json_rpc" 2>/dev/null || true)"

        if [[ "$resp" == *'"result"'* ]]; then
            log_info "monero-wallet-rpc is ready."
            verify_rpc_wallet_mode "$rpc_port"
            return 0
        fi

        sleep 0.5
        attempt=$((attempt + 1))
    done

    log_err "Timed out waiting for monero-wallet-rpc on 127.0.0.1:${rpc_port}. Tail of $RPC_LOG_FILE:"
    tail -n 25 "$RPC_LOG_FILE" >&2 || true
    exit 1
}

verify_rpc_wallet_mode() {
    local rpc_port="$1"
    local curl_auth_args=()
    if [[ -n "${MONERO_RPC_USER:-}" ]]; then
        curl_auth_args=(--digest -u "${MONERO_RPC_USER}:${MONERO_RPC_PASS}")
    fi

    local key_resp
    key_resp="$(curl -sS "${curl_auth_args[@]}" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":"verify_mode","method":"query_key","params":{"key_type":"spend_key"}}' \
        "http://127.0.0.1:${rpc_port}/json_rpc" 2>/dev/null || true)"

    if [[ "$key_resp" != *'"error"'* && "$key_resp" != *'"result"'* ]]; then
        log_err "Failed to verify wallet custody mode via query_key (unexpected RPC response). Aborting."
        exit 1
    fi

    if [[ "$WALLET_MODE" == "view_only" ]]; then
        local spend_key=""
        if [[ "$key_resp" =~ \"key\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]]; then
            spend_key="${BASH_REMATCH[1]}"
        fi
        if [[ -n "$spend_key" && ! "$spend_key" =~ ^0+$ ]]; then
            log_err "SECURITY VIOLATION: WALLET_MODE=view_only is configured, but the loaded wallet contains a private spend key! Aborting startup."
            exit 1
        fi
        log_info "Verified view-only wallet status via monero-wallet-rpc (no spend key present)."
    else
        if [[ "$key_resp" == *'"error"'* ]]; then
            log_err "WALLET_MODE=hot_wallet is configured, but the loaded wallet is view-only (missing spend key)! Aborting startup."
            exit 1
        fi
        log_info "Verified hot wallet status via monero-wallet-rpc."
    fi
}

build_gateway_if_needed() {
    require_cmd cargo
    local needs_build=0

    if [[ ! -x "$GATEWAY_BIN" ]]; then
        needs_build=1
    elif find "$SCRIPT_DIR/Cargo.toml" "$SCRIPT_DIR/src" "$SCRIPT_DIR/migrations" \
        -type f -newer "$GATEWAY_BIN" 2>/dev/null | grep -q .; then
        needs_build=1
    fi

    if [[ "$needs_build" -eq 1 ]]; then
        log_info "Building xmr-gateway (--release)..."
        cargo build --release
    else
        log_info "Using up-to-date release binary: $GATEWAY_BIN"
    fi
}

main() {
    local setup_only=0
    local init_wallet_only=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --setup-rpc)
                setup_only=1
                shift
                ;;
            --init-wallet-only)
                init_wallet_only=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_err "Unknown argument: $1"
                usage
                exit 1
                ;;
        esac
    done

    if [[ "$setup_only" -eq 1 ]]; then
        ensure_monero_binaries 1
        exit 0
    fi

    require_cmd curl
    ensure_env_file
    validate_wallet_bootstrap_policy
    ensure_monero_binaries 0
    ensure_wallet

    if [[ "$init_wallet_only" -eq 1 ]]; then
        exit 0
    fi

    start_monero_wallet_rpc
    build_gateway_if_needed

    log_info "Starting xmr-gateway on http://${HOST}:${PORT}..."
    "$GATEWAY_BIN" &
    GATEWAY_PID=$!
    wait "$GATEWAY_PID"
}

main "$@"
