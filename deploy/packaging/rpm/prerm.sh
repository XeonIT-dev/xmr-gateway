#!/bin/sh
set -eu

# Only stop/disable services on full package uninstall ($1 == 0), not upgrade ($1 >= 1)
if [ "${1:-0}" -eq 0 ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl stop xmr-gateway-backup.timer >/dev/null 2>&1 || true
        systemctl stop xmr-gateway.service >/dev/null 2>&1 || true
        systemctl stop monero-wallet-rpc.service >/dev/null 2>&1 || true
        systemctl disable xmr-gateway-backup.timer >/dev/null 2>&1 || true
        systemctl disable xmr-gateway.service >/dev/null 2>&1 || true
        systemctl disable monero-wallet-rpc.service >/dev/null 2>&1 || true
    fi
fi
