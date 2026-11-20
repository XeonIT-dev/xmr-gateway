#!/bin/sh
set -eu

if ! getent group xmr-gateway >/dev/null 2>&1; then
    groupadd --system xmr-gateway
fi
if ! getent passwd xmr-gateway >/dev/null 2>&1; then
    useradd --system --gid xmr-gateway --home-dir /var/lib/xmr-gateway \
        --no-create-home --shell /usr/sbin/nologin xmr-gateway
fi

install -d -m 0700 -o xmr-gateway -g xmr-gateway /var/lib/xmr-gateway
install -d -m 0700 -o xmr-gateway -g xmr-gateway /var/lib/xmr-gateway/wallet
install -d -m 0700 -o xmr-gateway -g xmr-gateway /var/lib/xmr-gateway/backups
install -d -m 0750 -o root -g xmr-gateway /etc/xmr-gateway

if [ -f /etc/xmr-gateway/env.example ]; then
    chown root:xmr-gateway /etc/xmr-gateway/env.example
    chmod 0640 /etc/xmr-gateway/env.example
fi

# Never overwrite an existing /etc/xmr-gateway/.env on upgrade!
if [ ! -f /etc/xmr-gateway/.env ] && [ -f /etc/xmr-gateway/env.example ]; then
    install -m 0600 -o xmr-gateway -g xmr-gateway /etc/xmr-gateway/env.example /etc/xmr-gateway/.env
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

cat <<'EOF'
==============================================================================
xmr-gateway installed! Services are NOT auto-started until secrets are set.
Next steps:
  1. Generate strong secrets:
       sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys all
  2. Configure /etc/xmr-gateway/.env (WALLET_MODE, MONERO_NETWORK, OPERATOR_API_KEY, etc.).
  3. Install monero-wallet-rpc into /usr/local/bin/monero-wallet-rpc and create
     the wallet in /var/lib/xmr-gateway/wallet/ (see DEPLOY_EN.md / DEPLOY_RU.md).
  4. Verify configuration:
       sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config doctor
  5. Enable and start services:
       sudo systemctl enable --now monero-wallet-rpc.service xmr-gateway.service
       sudo systemctl enable --now xmr-gateway-backup.timer   # optional daily hot backup
==============================================================================
EOF
