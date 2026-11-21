#!/bin/sh
# ==============================================================================
# xmr-gateway — Systemd ExecStartPre helper for monero-wallet-rpc.service
# ==============================================================================
# Renders a RAM-only 0600 wallet-rpc.conf file from EnvironmentFile variables so
# MONERO_RPC_PASS never appears in process argv (`/proc/<pid>/cmdline`).
# Kept as a standalone POSIX sh script so systemd never performs `${...}`
# environment expansion or `%` specifier substitution on shell syntax.
# ==============================================================================

set -eu

CONF_PATH="${1:-/run/xmr-gateway/wallet-rpc.conf}"

umask 077

if [ -z "${MONERO_RPC_USER:-}" ] || [ -z "${MONERO_RPC_PASS:-}" ]; then
    echo "MONERO_RPC_USER/PASS required" >&2
    exit 1
fi

nl="$(printf '\nx')"
nl="${nl%x}"
cr="$(printf '\rx')"
cr="${cr%x}"

case "${MONERO_RPC_USER}${MONERO_RPC_PASS}" in
    *"$nl"*|*"$cr"*)
        echo "MONERO_RPC_USER/PASS must not contain newlines" >&2
        exit 1
        ;;
esac

case "${MONERO_REMOTE_NODE:-}${MONERO_RPC_PROXY:-}" in
    *"$nl"*|*"$cr"*)
        echo "MONERO_REMOTE_NODE/MONERO_RPC_PROXY must not contain newlines" >&2
        exit 1
        ;;
esac

case "${MONERO_NETWORK:-mainnet}" in
    stagenet|STAGENET) def_node="node.monerodevs.org:38089" ;;
    testnet|TESTNET)   def_node="testnet.xmr-tw.org:28081" ;;
    *)                 def_node="xmr-node.cakewallet.com:18081" ;;
esac

CONF_DIR="$(dirname "$CONF_PATH")"
TMP_CONF="$(mktemp "${CONF_DIR}/.wallet-rpc.conf.XXXXXX")"
chmod 0600 "$TMP_CONF"

{
    printf 'rpc-login=%s:%s\n' "${MONERO_RPC_USER}" "${MONERO_RPC_PASS}"
    printf 'daemon-address=%s\n' "${MONERO_REMOTE_NODE:-$def_node}"
    case "${MONERO_NETWORK:-mainnet}" in
        stagenet|STAGENET) printf 'stagenet=1\n' ;;
        testnet|TESTNET)   printf 'testnet=1\n' ;;
    esac
    case "${MONERO_TRUSTED_DAEMON:-false}" in
        true|TRUE|1|yes|YES) printf 'trusted-daemon=1\n' ;;
        *)                   printf 'untrusted-daemon=1\n' ;;
    esac
    if [ -n "${MONERO_RPC_PROXY:-}" ]; then
        printf 'proxy=%s\n' "${MONERO_RPC_PROXY}"
    fi
} > "$TMP_CONF"

chmod 0600 "$TMP_CONF"
mv "$TMP_CONF" "$CONF_PATH"
