#!/bin/sh
set -eu

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

# Never delete /var/lib/xmr-gateway or /etc/xmr-gateway/.env automatically!
if [ "${1:-0}" -eq 0 ]; then
    echo "NOTE: Preserved /var/lib/xmr-gateway (SQLite DB & wallet keys) and /etc/xmr-gateway/.env." >&2
    echo "      Remove them manually only after backing up funds and mnemonic seeds." >&2
fi
