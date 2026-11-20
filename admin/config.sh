#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Admin Suite — Configuration, RBAC & Doctor Module (admin/config.sh)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=admin/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    t config.usage
}

cmd_show() {
    load_env
    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        python3 - <<'PYEOF'
import json, os

def mask(v):
    if not v:
        return None
    if len(v) <= 8:
        return f"*** (len={len(v)})"
    return f"{v[:4]}...{v[-4:]} (len={len(v)})"

out = {
    "env_file": os.environ.get("ACTIVE_ENV_FILE"),
    "host": os.environ.get("HOST"),
    "port": os.environ.get("PORT"),
    "cors_allowed_origins": os.environ.get("CORS_ALLOWED_ORIGINS"),
    "database_url": os.environ.get("DATABASE_URL"),
    "db_path": os.environ.get("DB_PATH"),
    "monero_network": os.environ.get("MONERO_NETWORK"),
    "wallet_mode": os.environ.get("WALLET_MODE"),
    "enable_auto_sweep": os.environ.get("ENABLE_AUTO_SWEEP"),
    "allow_hot_wallet_without_sweep": os.environ.get("ALLOW_HOT_WALLET_WITHOUT_SWEEP"),
    "cold_wallet_address": os.environ.get("COLD_WALLET_ADDRESS") or None,
    "monero_view_only_address": os.environ.get("MONERO_VIEW_ONLY_ADDRESS") or None,
    "monero_view_only_key": mask(os.environ.get("MONERO_VIEW_ONLY_KEY", "")),
    "monero_rpc_url": os.environ.get("MONERO_RPC_URL"),
    "monero_rpc_user": os.environ.get("MONERO_RPC_USER") or None,
    "monero_rpc_pass": mask(os.environ.get("MONERO_RPC_PASS", "")),
    "monero_daemon_rpc_url": os.environ.get("MONERO_DAEMON_RPC_URL") or None,
    "monero_daemon_rpc_user": os.environ.get("MONERO_DAEMON_RPC_USER") or None,
    "monero_daemon_rpc_pass": mask(os.environ.get("MONERO_DAEMON_RPC_PASS", "")),
    "monero_remote_node": os.environ.get("MONERO_REMOTE_NODE"),
    "monero_trusted_daemon": os.environ.get("MONERO_TRUSTED_DAEMON"),
    "monero_rpc_proxy": os.environ.get("MONERO_RPC_PROXY") or None,
    "wallet_restore_height": os.environ.get("WALLET_RESTORE_HEIGHT"),
    "allow_unauthenticated_rpc": os.environ.get("ALLOW_UNAUTHENTICATED_RPC"),
    "allow_insecure_remote_rpc": os.environ.get("ALLOW_INSECURE_REMOTE_RPC"),
    "api_secret_key": mask(os.environ.get("API_SECRET_KEY", "")),
    "operator_api_key": mask(os.environ.get("OPERATOR_API_KEY", "")),
    "webhook_secret": mask(os.environ.get("WEBHOOK_SECRET", "")),
    "default_webhook_url": os.environ.get("DEFAULT_WEBHOOK_URL") or None,
    "allow_private_webhooks": os.environ.get("ALLOW_PRIVATE_WEBHOOKS"),
    "require_https_webhooks": os.environ.get("REQUIRE_HTTPS_WEBHOOKS"),
    "required_confirmations": os.environ.get("REQUIRED_CONFIRMATIONS"),
    "settlement_confirmations": os.environ.get("SETTLEMENT_CONFIRMATIONS"),
    "sweep_priority": os.environ.get("SWEEP_PRIORITY"),
    "subaddress_monitor_days": os.environ.get("SUBADDRESS_MONITOR_DAYS"),
    "invoice_ttl_seconds": os.environ.get("INVOICE_TTL_SECONDS"),
    "scan_interval_seconds": os.environ.get("SCAN_INTERVAL_SECONDS"),
    "webhook_poll_interval_seconds": os.environ.get("WEBHOOK_POLL_INTERVAL_SECONDS"),
    "rust_log": os.environ.get("RUST_LOG"),
    "log_format": os.environ.get("LOG_FORMAT"),
}
print(json.dumps(out, indent=2))
PYEOF
        return 0
    fi

    printf '%s%s%s\n' "$C_BOLD" "$(t config.show_header)" "$C_RESET"
    if [[ "$ADMIN_ACTIVE_LANG" == "ru" ]]; then
        printf '  Файл окружения               : %s\n' "$ACTIVE_ENV_FILE"
        printf '  Адрес прослушивания          : %s:%s\n' "$HOST" "$PORT"
        printf '  DATABASE_URL                 : %s (файл: %s)\n' "$DATABASE_URL" "${DB_PATH:-в памяти}"
        printf '  MONERO_NETWORK               : %s\n' "$MONERO_NETWORK"
        printf '  WALLET_MODE                  : %s\n' "$WALLET_MODE"
        printf '  ENABLE_AUTO_SWEEP            : %s (allow_without_sweep=%s)\n' "$ENABLE_AUTO_SWEEP" "$ALLOW_HOT_WALLET_WITHOUT_SWEEP"
        printf '  COLD_WALLET_ADDRESS          : %s\n' "${COLD_WALLET_ADDRESS:-<не задан>}"
        printf '  MONERO_VIEW_ONLY_ADDRESS     : %s\n' "${MONERO_VIEW_ONLY_ADDRESS:-<не задан>}"
        printf '  MONERO_VIEW_ONLY_KEY         : %s\n' "$(mask_secret "$MONERO_VIEW_ONLY_KEY")"
        printf '  API_SECRET_KEY               : %s\n' "$(mask_secret "$API_SECRET_KEY")"
        printf '  OPERATOR_API_KEY             : %s\n' "$(mask_secret "$OPERATOR_API_KEY")"
        printf '  WEBHOOK_SECRET               : %s\n' "$(mask_secret "$WEBHOOK_SECRET")"
        printf '  DEFAULT_WEBHOOK_URL          : %s\n' "${DEFAULT_WEBHOOK_URL:-<не задан>}"
        printf '  ALLOW_PRIVATE_WEBHOOKS       : %s | REQUIRE_HTTPS_WEBHOOKS=%s\n' "$ALLOW_PRIVATE_WEBHOOKS" "$REQUIRE_HTTPS_WEBHOOKS"
        printf '  MONERO_RPC_URL               : %s (user=%s, pass=%s)\n' "$MONERO_RPC_URL" "${MONERO_RPC_USER:-<не задан>}" "$(mask_secret "$MONERO_RPC_PASS")"
        printf '  MONERO_DAEMON_RPC_URL        : %s (user=%s, pass=%s)\n' "${MONERO_DAEMON_RPC_URL:-<не задан>}" "${MONERO_DAEMON_RPC_USER:-<не задан>}" "$(mask_secret "$MONERO_DAEMON_RPC_PASS")"
        printf '  MONERO_REMOTE_NODE           : %s (trusted=%s, proxy=%s)\n' "$MONERO_REMOTE_NODE" "$MONERO_TRUSTED_DAEMON" "${MONERO_RPC_PROXY:-<нет>}"
        printf '  Переопределения RPC          : allow_unauth=%s | allow_insecure_remote=%s\n' "$ALLOW_UNAUTHENTICATED_RPC" "$ALLOW_INSECURE_REMOTE_RPC"
        printf '  Подтверждения                : required=%s | settlement=%s | sweep_priority=%s\n' "$REQUIRED_CONFIRMATIONS" "$SETTLEMENT_CONFIRMATIONS" "$SWEEP_PRIORITY"
        printf '  Интервалы / мониторинг       : ttl=%ss | scan=%ss | webhook_poll=%ss | monitor_days=%s\n' \
            "$INVOICE_TTL_SECONDS" "$SCAN_INTERVAL_SECONDS" "$WEBHOOK_POLL_INTERVAL_SECONDS" "$SUBADDRESS_MONITOR_DAYS"
        printf '  Логирование                  : format=%s | RUST_LOG=%s\n' "$LOG_FORMAT" "$RUST_LOG"
    else
        printf '  Env File                     : %s\n' "$ACTIVE_ENV_FILE"
        printf '  Bind Address                 : %s:%s\n' "$HOST" "$PORT"
        printf '  DATABASE_URL                 : %s (path: %s)\n' "$DATABASE_URL" "${DB_PATH:-in-memory}"
        printf '  MONERO_NETWORK               : %s\n' "$MONERO_NETWORK"
        printf '  WALLET_MODE                  : %s\n' "$WALLET_MODE"
        printf '  ENABLE_AUTO_SWEEP            : %s (allow_without_sweep=%s)\n' "$ENABLE_AUTO_SWEEP" "$ALLOW_HOT_WALLET_WITHOUT_SWEEP"
        printf '  COLD_WALLET_ADDRESS          : %s\n' "${COLD_WALLET_ADDRESS:-<unset>}"
        printf '  MONERO_VIEW_ONLY_ADDRESS     : %s\n' "${MONERO_VIEW_ONLY_ADDRESS:-<unset>}"
        printf '  MONERO_VIEW_ONLY_KEY         : %s\n' "$(mask_secret "$MONERO_VIEW_ONLY_KEY")"
        printf '  API_SECRET_KEY               : %s\n' "$(mask_secret "$API_SECRET_KEY")"
        printf '  OPERATOR_API_KEY             : %s\n' "$(mask_secret "$OPERATOR_API_KEY")"
        printf '  WEBHOOK_SECRET               : %s\n' "$(mask_secret "$WEBHOOK_SECRET")"
        printf '  DEFAULT_WEBHOOK_URL          : %s\n' "${DEFAULT_WEBHOOK_URL:-<unset>}"
        printf '  ALLOW_PRIVATE_WEBHOOKS       : %s | REQUIRE_HTTPS_WEBHOOKS=%s\n' "$ALLOW_PRIVATE_WEBHOOKS" "$REQUIRE_HTTPS_WEBHOOKS"
        printf '  MONERO_RPC_URL               : %s (user=%s, pass=%s)\n' "$MONERO_RPC_URL" "${MONERO_RPC_USER:-<unset>}" "$(mask_secret "$MONERO_RPC_PASS")"
        printf '  MONERO_DAEMON_RPC_URL        : %s (user=%s, pass=%s)\n' "${MONERO_DAEMON_RPC_URL:-<unset>}" "${MONERO_DAEMON_RPC_USER:-<unset>}" "$(mask_secret "$MONERO_DAEMON_RPC_PASS")"
        printf '  MONERO_REMOTE_NODE           : %s (trusted=%s, proxy=%s)\n' "$MONERO_REMOTE_NODE" "$MONERO_TRUSTED_DAEMON" "${MONERO_RPC_PROXY:-<none>}"
        printf '  RPC Overrides                : allow_unauth=%s | allow_insecure_remote=%s\n' "$ALLOW_UNAUTHENTICATED_RPC" "$ALLOW_INSECURE_REMOTE_RPC"
        printf '  Confirmations                : required=%s | settlement=%s | sweep_priority=%s\n' "$REQUIRED_CONFIRMATIONS" "$SETTLEMENT_CONFIRMATIONS" "$SWEEP_PRIORITY"
        printf '  Intervals / Retention        : ttl=%ss | scan=%ss | webhook_poll=%ss | monitor_days=%s\n' \
            "$INVOICE_TTL_SECONDS" "$SCAN_INTERVAL_SECONDS" "$WEBHOOK_POLL_INTERVAL_SECONDS" "$SUBADDRESS_MONITOR_DAYS"
        printf '  Logging                      : format=%s | RUST_LOG=%s\n' "$LOG_FORMAT" "$RUST_LOG"
    fi
}

cmd_doctor() {
    local strict_live=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --strict-live) strict_live=1; shift ;;
            *) die "Unknown doctor option: $1" ;;
        esac
    done

    load_env

    # Gather optional live telemetry cleanly via curl --config - (never leaking secrets in argv)
    local health_anon_code="" health_anon_body=""
    local health_api_code="" health_api_body=""
    local health_op_code="" health_op_body=""
    if gateway_api_call GET "/health" none 2>/dev/null; then
        health_anon_code="$API_LAST_HTTP_CODE"
        health_anon_body="$API_LAST_BODY"
        if [[ -n "$API_SECRET_KEY" ]]; then
            gateway_api_call GET "/health" health_api 2>/dev/null || true
            health_api_code="$API_LAST_HTTP_CODE"
            health_api_body="$API_LAST_BODY"
        fi
        if [[ -n "$OPERATOR_API_KEY" ]]; then
            gateway_api_call GET "/health" health_operator 2>/dev/null || true
            health_op_code="$API_LAST_HTTP_CODE"
            health_op_body="$API_LAST_BODY"
        fi
    fi

    local wallet_height="" daemon_height="" daemon_synced=""
    if wallet_rpc_call "get_height" 2>/dev/null && [[ "$RPC_LAST_HTTP_CODE" == "200" ]]; then
        wallet_height="$(python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(d.get("result",{}).get("height",""))' <<< "$RPC_LAST_BODY" 2>/dev/null || true)"
    fi
    if daemon_rpc_call "get_info" 2>/dev/null && [[ "$RPC_LAST_HTTP_CODE" == "200" ]]; then
        daemon_height="$(python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); r=d.get("result",{}); print(max(int(r.get("height",0) or 0), int(r.get("target_height",0) or 0)))' <<< "$RPC_LAST_BODY" 2>/dev/null || true)"
        daemon_synced="$(python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(str(bool(d.get("result",{}).get("synchronized", False))).lower())' <<< "$RPC_LAST_BODY" 2>/dev/null || true)"
    fi

    # Run all fail-closed checks inside Python for structured JSON + tabular output
    DOCTOR_HEALTH_ANON_CODE="$health_anon_code" \
    DOCTOR_HEALTH_ANON_BODY="$health_anon_body" \
    DOCTOR_HEALTH_API_CODE="$health_api_code" \
    DOCTOR_HEALTH_API_BODY="$health_api_body" \
    DOCTOR_HEALTH_OP_CODE="$health_op_code" \
    DOCTOR_HEALTH_OP_BODY="$health_op_body" \
    DOCTOR_WALLET_HEIGHT="$wallet_height" \
    DOCTOR_DAEMON_HEIGHT="$daemon_height" \
    DOCTOR_DAEMON_SYNCED="$daemon_synced" \
    DOCTOR_STRICT_LIVE="$strict_live" \
    DOCTOR_JSON="$ADMIN_JSON" \
    python3 - <<'PYEOF'
import json, os, stat, sys
from urllib.parse import urlparse

checks = []

def add(status, name, detail):
    checks.append({"status": status, "check": name, "detail": detail})

def is_truthy(v):
    return str(v or "").strip().lower() in ("true", "1", "yes")

def is_placeholder(v):
    vl = (v or "").strip().lower()
    return (not vl) or vl.startswith("replace-with-") or vl.startswith("changeme") or vl.startswith("example-")

def perm_octal(path):
    return f"{stat.S_IMODE(os.stat(path).st_mode):04o}"

env_file = os.environ["ACTIVE_ENV_FILE"]
net = os.environ.get("MONERO_NETWORK", "mainnet").strip().lower()
wallet_mode = os.environ.get("WALLET_MODE", "view_only").strip().lower()
auto_sweep = is_truthy(os.environ.get("ENABLE_AUTO_SWEEP"))
allow_hot_no_sweep = is_truthy(os.environ.get("ALLOW_HOT_WALLET_WITHOUT_SWEEP"))
cold_addr = os.environ.get("COLD_WALLET_ADDRESS", "").strip()
vo_addr = os.environ.get("MONERO_VIEW_ONLY_ADDRESS", "").strip()
vo_key = os.environ.get("MONERO_VIEW_ONLY_KEY", "").strip()
api_key = os.environ.get("API_SECRET_KEY", "")
op_key = os.environ.get("OPERATOR_API_KEY", "")
wh_secret = os.environ.get("WEBHOOK_SECRET", "")
allow_priv_wh = is_truthy(os.environ.get("ALLOW_PRIVATE_WEBHOOKS"))
req_https_wh = is_truthy(os.environ.get("REQUIRE_HTTPS_WEBHOOKS"))
allow_unauth_rpc = is_truthy(os.environ.get("ALLOW_UNAUTHENTICATED_RPC"))
allow_insec_rpc = is_truthy(os.environ.get("ALLOW_INSECURE_REMOTE_RPC"))
rpc_url = os.environ.get("MONERO_RPC_URL", "").strip()
rpc_user = os.environ.get("MONERO_RPC_USER", "").strip()
rpc_pass = os.environ.get("MONERO_RPC_PASS", "")
daemon_url = os.environ.get("MONERO_DAEMON_RPC_URL", "").strip()
daemon_user = os.environ.get("MONERO_DAEMON_RPC_USER", "").strip()
daemon_pass = os.environ.get("MONERO_DAEMON_RPC_PASS", "")
remote_node = os.environ.get("MONERO_REMOTE_NODE", "").strip()
db_path = os.environ.get("DB_PATH", "").strip()
wallet_file = os.environ.get("WALLET_FILE", "").strip()
wallet_pass_file = os.environ.get("WALLET_PASS_FILE", "").strip()
strict_live = os.environ.get("DOCTOR_STRICT_LIVE") == "1"

# 1) File permissions
if os.path.exists(env_file):
    mode = perm_octal(env_file)
    if mode == "0600":
        add("PASS", "env_permissions", f"{env_file} has mode 0600")
    else:
        add("FAIL", "env_permissions", f"{env_file} has mode {mode} (must be 0600)")
else:
    add("FAIL", "env_permissions", f"{env_file} not found")

for label, p in [
    ("wallet_keys_permissions", f"{wallet_file}.keys"),
    ("wallet_pass_permissions", wallet_pass_file),
    ("db_permissions", db_path),
    ("wal_permissions", f"{db_path}-wal" if db_path else ""),
    ("shm_permissions", f"{db_path}-shm" if db_path else ""),
]:
    if p and os.path.exists(p):
        m = perm_octal(p)
        if m == "0600":
            add("PASS", label, f"{p} has mode 0600")
        else:
            add("FAIL", label, f"{p} has mode {m} (expected 0600)")

# 2) Cryptographic secrets & AUDIT-002 RBAC distinctness
for name, val in [("API_SECRET_KEY", api_key), ("WEBHOOK_SECRET", wh_secret)]:
    if is_placeholder(val):
        add("FAIL", f"secret_{name.lower()}", f"{name} is unset or contains a placeholder")
    elif len(val.encode("utf-8")) < 32:
        add("FAIL", f"secret_{name.lower()}", f"{name} is {len(val.encode('utf-8'))} bytes (minimum 32)")
    else:
        add("PASS", f"secret_{name.lower()}", f"{name} length={len(val.encode('utf-8'))} bytes")

if op_key:
    if is_placeholder(op_key):
        add("FAIL", "secret_operator_api_key", "OPERATOR_API_KEY contains a placeholder")
    elif len(op_key.encode("utf-8")) < 32:
        add("FAIL", "secret_operator_api_key", f"OPERATOR_API_KEY is {len(op_key.encode('utf-8'))} bytes (minimum 32)")
    elif op_key == api_key or op_key.strip() == api_key.strip():
        add("FAIL", "rbac_key_separation", "OPERATOR_API_KEY must differ from API_SECRET_KEY (AUDIT-002)")
    else:
        add("PASS", "rbac_key_separation", "OPERATOR_API_KEY is set and distinct from API_SECRET_KEY")
elif wallet_mode == "hot_wallet" or auto_sweep:
    add("FAIL", "rbac_key_separation", "OPERATOR_API_KEY is required when WALLET_MODE=hot_wallet or ENABLE_AUTO_SWEEP=true (XMR-AUDIT-004)")
else:
    add("WARN", "rbac_key_separation", "OPERATOR_API_KEY unset (single-tenant mode in view_only: API_SECRET_KEY accepted on operator routes)")

# 3) Custody mode & wallet invariants (XMR-002)
if wallet_mode not in ("view_only", "hot_wallet"):
    add("FAIL", "wallet_mode", f"Invalid WALLET_MODE='{wallet_mode}' (expected view_only or hot_wallet)")
elif auto_sweep and wallet_mode != "hot_wallet":
    add("FAIL", "wallet_mode", "ENABLE_AUTO_SWEEP=true requires WALLET_MODE=hot_wallet")
elif auto_sweep and not cold_addr:
    add("FAIL", "cold_wallet_address", "ENABLE_AUTO_SWEEP=true requires COLD_WALLET_ADDRESS")
elif wallet_mode == "hot_wallet" and not auto_sweep and not allow_hot_no_sweep:
    add("FAIL", "wallet_mode", "WALLET_MODE=hot_wallet requires ENABLE_AUTO_SWEEP=true or ALLOW_HOT_WALLET_WITHOUT_SWEEP=true")
else:
    add("PASS", "wallet_mode", f"WALLET_MODE={wallet_mode}, ENABLE_AUTO_SWEEP={str(auto_sweep).lower()}")

if wallet_mode == "view_only" and not os.path.exists(f"{wallet_file}.keys"):
    if not vo_addr or not vo_key:
        add("WARN", "view_only_bootstrap", "No wallet .keys file and MONERO_VIEW_ONLY_ADDRESS/KEY not both set")
    else:
        add("PASS", "view_only_bootstrap", "View-only bootstrap credentials present")

# 4) Confirmations & priority bounds
try:
    req_c = int(os.environ.get("REQUIRED_CONFIRMATIONS", "10"))
    set_c = int(os.environ.get("SETTLEMENT_CONFIRMATIONS", "10"))
    prio = int(os.environ.get("SWEEP_PRIORITY", "0"))
    if req_c < 1:
        add("FAIL", "confirmations", f"REQUIRED_CONFIRMATIONS={req_c} (must be >= 1)")
    elif set_c < req_c:
        add("FAIL", "confirmations", f"SETTLEMENT_CONFIRMATIONS={set_c} < REQUIRED_CONFIRMATIONS={req_c}")
    else:
        add("PASS", "confirmations", f"REQUIRED={req_c}, SETTLEMENT={set_c}")
    if 0 <= prio <= 4:
        add("PASS", "sweep_priority", f"SWEEP_PRIORITY={prio}")
    else:
        add("FAIL", "sweep_priority", f"SWEEP_PRIORITY={prio} out of range 0..4")
except ValueError as exc:
    add("FAIL", "numeric_config", f"Invalid numeric config value: {exc}")

# 5) SSRF & RPC security flags
if net == "mainnet" and allow_priv_wh:
    add("WARN", "ssrf_policy", "ALLOW_PRIVATE_WEBHOOKS=true on mainnet (recommended false in production)")
elif net == "mainnet" and not req_https_wh and not allow_priv_wh:
    add("WARN", "ssrf_policy", "REQUIRE_HTTPS_WEBHOOKS=false on mainnet permits plaintext HTTP webhooks over public networks (set REQUIRE_HTTPS_WEBHOOKS=true, XMR-AUDIT-006)")
else:
    add("PASS", "ssrf_policy", f"ALLOW_PRIVATE_WEBHOOKS={str(allow_priv_wh).lower()}, REQUIRE_HTTPS_WEBHOOKS={str(req_https_wh).lower()}")

if not allow_unauth_rpc and (not rpc_user or is_placeholder(rpc_pass)):
    add("FAIL", "rpc_auth", "ALLOW_UNAUTHENTICATED_RPC=false requires MONERO_RPC_USER and non-placeholder MONERO_RPC_PASS")
else:
    add("PASS", "rpc_auth", f"ALLOW_UNAUTHENTICATED_RPC={str(allow_unauth_rpc).lower()}, MONERO_RPC_USER={rpc_user or '<unset>'}")

if daemon_url:
    parsed_d = urlparse(daemon_url)
    is_loopback = parsed_d.hostname in ("127.0.0.1", "localhost", "::1")
    if parsed_d.scheme == "http" and not is_loopback and not allow_insec_rpc:
        add("FAIL", "daemon_rpc_security", f"Cleartext remote MONERO_DAEMON_RPC_URL ({daemon_url}) blocked while ALLOW_INSECURE_REMOTE_RPC=false")
    elif not allow_unauth_rpc and (not daemon_user or not daemon_pass):
        add("FAIL", "daemon_rpc_security", "MONERO_DAEMON_RPC_URL set with ALLOW_UNAUTHENTICATED_RPC=false requires MONERO_DAEMON_RPC_USER/PASS")
    else:
        add("PASS", "daemon_rpc_security", f"MONERO_DAEMON_RPC_URL configured ({daemon_url})")
elif daemon_user or daemon_pass:
    add("FAIL", "daemon_rpc_security", "MONERO_DAEMON_RPC_USER/PASS set without MONERO_DAEMON_RPC_URL")
else:
    add("WARN", "daemon_rpc_security", "MONERO_DAEMON_RPC_URL unset (required for allow_resweep incident resolution, AUDIT-001)")

if remote_node:
    rn_low = remote_node.lower()
    if net in ("stagenet", "testnet") and (
        "xmr-node.cakewallet.com" in rn_low
        or (rn_low.endswith(":18081") and "stagenet" not in rn_low and "testnet" not in rn_low)
    ):
        add("WARN", "remote_node_network", f"MONERO_NETWORK={net} but MONERO_REMOTE_NODE='{remote_node}' appears to target a mainnet daemon port/host")
    elif net == "mainnet" and (rn_low.endswith(":38089") or rn_low.endswith(":38081") or rn_low.endswith(":28081")):
        add("WARN", "remote_node_network", f"MONERO_NETWORK=mainnet but MONERO_REMOTE_NODE='{remote_node}' uses a stagenet/testnet daemon port")
    else:
        add("PASS", "remote_node_network", f"MONERO_REMOTE_NODE={remote_node} ({net})")

# 6) SQLite DB / WAL / lock inventory
db_url = os.environ.get("DATABASE_URL", "").strip()
if env_file == "/etc/xmr-gateway/.env" and db_url and not db_url.startswith("sqlite:///"):
    add("WARN", "sqlite_path", f"System /etc/xmr-gateway/.env uses relative DATABASE_URL='{db_url}' (recommended: sqlite:///var/lib/xmr-gateway/xmr_gateway.db)")
if db_path:
    if os.path.exists(db_path):
        db_sz = os.path.getsize(db_path)
        wal_p = f"{db_path}-wal"
        lock_p = f"{db_path}.lock"
        wal_sz = os.path.getsize(wal_p) if os.path.exists(wal_p) else 0
        lock_present = os.path.exists(lock_p)
        add("PASS", "sqlite_files", f"db={db_sz}B, wal={wal_sz}B, lock_file={'present' if lock_present else 'absent'}")
    else:
        add("WARN", "sqlite_files", f"Database file not yet created: {db_path}")

# 7) Live /health & AUDIT-002 telemetry hiding check
anon_code = os.environ.get("DOCTOR_HEALTH_ANON_CODE", "")
if anon_code:
    try:
        anon_obj = json.loads(os.environ.get("DOCTOR_HEALTH_ANON_BODY", "{}"))
        leaked = [k for k in ("service", "version", "database", "monero_rpc", "auto_sweep_enabled") if k in anon_obj]
        if leaked:
            add("FAIL", "health_anon_privacy", f"Unauthenticated /health leaked telemetry fields: {leaked}")
        else:
            add("PASS", "health_anon_privacy", f"Unauthenticated /health HTTP {anon_code}, status={anon_obj.get('status')}, telemetry hidden")
    except Exception as exc:
        add("FAIL", "health_anon_privacy", f"Invalid JSON from /health: {exc}")

    api_code = os.environ.get("DOCTOR_HEALTH_API_CODE", "")
    if api_code:
        try:
            api_obj = json.loads(os.environ.get("DOCTOR_HEALTH_API_BODY", "{}"))
            if api_obj.get("service") and "monero_rpc" in api_obj:
                add("PASS", "health_auth_api", f"Authenticated /health (X-API-Key) HTTP {api_code}, db={api_obj.get('database')}, rpc_connected={api_obj.get('monero_rpc',{}).get('connected')}")
            else:
                add("FAIL", "health_auth_api", f"Authenticated /health (X-API-Key) missing diagnostics: {api_obj}")
        except Exception as exc:
            add("FAIL", "health_auth_api", f"Invalid JSON from authenticated /health: {exc}")

    op_code = os.environ.get("DOCTOR_HEALTH_OP_CODE", "")
    if op_key and op_code:
        try:
            op_obj = json.loads(os.environ.get("DOCTOR_HEALTH_OP_BODY", "{}"))
            if op_obj.get("service") and "monero_rpc" in op_obj:
                add("PASS", "health_auth_operator", f"Authenticated /health (X-Operator-Key) HTTP {op_code} returns full diagnostics")
            else:
                add("FAIL", "health_auth_operator", f"Authenticated /health (X-Operator-Key) missing diagnostics: {op_obj}")
        except Exception as exc:
            add("FAIL", "health_auth_operator", f"Invalid JSON from operator /health: {exc}")
else:
    add("FAIL" if strict_live else "WARN", "health_live", "Gateway HTTP /health unreachable (service stopped or bound elsewhere)")

# 8) Wallet vs Daemon sync check
wh = os.environ.get("DOCTOR_WALLET_HEIGHT", "")
dh = os.environ.get("DOCTOR_DAEMON_HEIGHT", "")
ds = os.environ.get("DOCTOR_DAEMON_SYNCED", "")
if wh.isdigit() and dh.isdigit():
    wh_i, dh_i = int(wh), int(dh)
    lag = dh_i - wh_i
    if lag > 5 or ds == "false":
        add("WARN", "wallet_daemon_sync", f"wallet_height={wh_i}, daemon_height={dh_i} (lag={lag}, daemon_synchronized={ds})")
    else:
        add("PASS", "wallet_daemon_sync", f"wallet_height={wh_i}, daemon_height={dh_i} (lag={lag}, daemon_synchronized={ds})")
elif wh.isdigit():
    add("WARN", "wallet_daemon_sync", f"wallet_height={wh}, daemon RPC unreachable for sync comparison")
else:
    add("FAIL" if strict_live else "WARN", "wallet_daemon_sync", "monero-wallet-rpc unreachable (skipping live height check)")

fails = [c for c in checks if c["status"] == "FAIL"]
warns = [c for c in checks if c["status"] == "WARN"]
passes = [c for c in checks if c["status"] == "PASS"]

if os.environ.get("DOCTOR_JSON") == "1":
    print(json.dumps({
        "ok": len(fails) == 0,
        "summary": {"pass": len(passes), "warn": len(warns), "fail": len(fails)},
        "checks": checks,
    }, indent=2))
else:
    lang = os.environ.get("ADMIN_ACTIVE_LANG", "en")
    ru_labels = {
        "env_permissions": "Права .env (0600)",
        "wallet_keys_permissions": "Права файла ключей кошелька",
        "wallet_pass_permissions": "Права файла пароля кошелька",
        "db_permissions": "Права файла БД SQLite",
        "wal_permissions": "Права файла -wal",
        "shm_permissions": "Права файла -shm",
        "secret_api_secret_key": "Секрет API_SECRET_KEY",
        "secret_webhook_secret": "Секрет WEBHOOK_SECRET",
        "secret_operator_api_key": "Секрет OPERATOR_API_KEY",
        "rbac_key_separation": "Разделение RBAC (AUDIT-002)",
        "wallet_mode": "Режим WALLET_MODE",
        "cold_wallet_address": "Адрес COLD_WALLET_ADDRESS",
        "view_only_bootstrap": "Параметры view_only",
        "confirmations": "Пороги подтверждений",
        "sweep_priority": "Приоритет SWEEP_PRIORITY",
        "numeric_config": "Числовые параметры",
        "ssrf_policy": "Политика SSRF вебхуков",
        "rpc_auth": "Аутентификация RPC",
        "daemon_rpc_security": "Безопасность MONERO_DAEMON_RPC_URL",
        "remote_node_network": "Соответствие MONERO_REMOTE_NODE сети",
        "sqlite_path": "Путь DATABASE_URL в системном .env",
        "sqlite_files": "Файлы SQLite / WAL / lock",
        "health_anon_privacy": "Скрытие телеметрии /health",
        "health_auth_api": "Диагностика /health (X-API-Key)",
        "health_auth_operator": "Диагностика /health (X-Operator-Key)",
        "health_live": "Доступность /health",
        "wallet_daemon_sync": "Синхронизация кошелька и демона",
    }
    if lang == "ru":
        print(f"=== Диагностика безопасности xmr-gateway ({env_file}) ===")
        for c in checks:
            lbl = ru_labels.get(c["check"], c["check"])
            print(f"  [{c['status']:4s}] {lbl:<36s} ({c['check']}) — {c['detail']}")
        print(f"\nИтог: {len(passes)} PASS, {len(warns)} WARN, {len(fails)} FAIL")
    else:
        print(f"=== xmr-gateway Doctor ({env_file}) ===")
        for c in checks:
            print(f"  [{c['status']:4s}] {c['check']:<26s} {c['detail']}")
        print(f"\nSummary: {len(passes)} PASS, {len(warns)} WARN, {len(fails)} FAIL")

sys.exit(1 if fails else 0)
PYEOF
}

cmd_rotate_keys() {
    load_env
    require_cmd openssl
    local scope="${1:-all}"
    case "$scope" in
        api|operator|webhook|rpc|all) ;;
        *) die "Invalid rotate-keys scope '$scope'. Expected: api | operator | webhook | rpc | all" ;;
    esac

    confirm_dangerous_action "$(t config.confirm_rotate "$scope" "$ACTIVE_ENV_FILE")" 1

    local ts backup_file
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    backup_file="${ACTIVE_ENV_FILE}.bak.${ts}"
    cp "$ACTIVE_ENV_FILE" "$backup_file"
    chmod 600 "$backup_file"
    log_info "$(t config.backup_created "$backup_file")"

    local rotated=()
    if [[ "$scope" == "api" || "$scope" == "all" ]]; then
        local new_api
        new_api="$(openssl rand -hex 32)"
        set_env_kv_file "$ACTIVE_ENV_FILE" "API_SECRET_KEY" "$new_api"
        API_SECRET_KEY="$new_api"
        rotated+=("API_SECRET_KEY")
    fi
    if [[ "$scope" == "operator" || "$scope" == "all" ]]; then
        local new_op
        new_op="$(openssl rand -hex 32)"
        while [[ "$new_op" == "${API_SECRET_KEY:-}" ]]; do
            new_op="$(openssl rand -hex 32)"
        done
        set_env_kv_file "$ACTIVE_ENV_FILE" "OPERATOR_API_KEY" "$new_op"
        OPERATOR_API_KEY="$new_op"
        rotated+=("OPERATOR_API_KEY")
    fi
    if [[ "$scope" == "webhook" || "$scope" == "all" ]]; then
        local new_wh
        new_wh="$(openssl rand -hex 32)"
        set_env_kv_file "$ACTIVE_ENV_FILE" "WEBHOOK_SECRET" "$new_wh"
        WEBHOOK_SECRET="$new_wh"
        rotated+=("WEBHOOK_SECRET")
    fi
    if [[ "$scope" == "rpc" || "$scope" == "all" ]]; then
        local new_rpc
        new_rpc="$(openssl rand -hex 24)"
        set_env_kv_file "$ACTIVE_ENV_FILE" "MONERO_RPC_PASS" "$new_rpc"
        MONERO_RPC_PASS="$new_rpc"
        rotated+=("MONERO_RPC_PASS")
    fi

    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        python3 - "$ACTIVE_ENV_FILE" "$backup_file" "${rotated[@]}" <<'PYEOF'
import json, sys
print(json.dumps({
    "env_file": sys.argv[1],
    "backup_file": sys.argv[2],
    "rotated_keys": sys.argv[3:],
    "restart_required": True,
}, indent=2))
PYEOF
    else
        log_info "$(t config.rotated_keys "${rotated[*]}")"
        log_warn "$(t config.restart_hint)"
    fi
}

cmd_set_mode() {
    load_env
    local target_mode="${1:-}"
    target_mode="${target_mode,,}"
    target_mode="${target_mode//-/_}"

    case "$target_mode" in
        view_only|hot_wallet) ;;
        *) die "Usage: ./admin.sh config set-mode <view_only|hot_wallet>" ;;
    esac

    if [[ "$target_mode" == "hot_wallet" ]]; then
        if [[ -z "${COLD_WALLET_ADDRESS:-}" ]] && ! is_truthy "$ALLOW_HOT_WALLET_WITHOUT_SWEEP"; then
            die "Cannot switch to hot_wallet: COLD_WALLET_ADDRESS is empty and ALLOW_HOT_WALLET_WITHOUT_SWEEP is false."
        fi
    else
        if [[ ! -f "${WALLET_FILE}.keys" && ( -z "${MONERO_VIEW_ONLY_ADDRESS:-}" || -z "${MONERO_VIEW_ONLY_KEY:-}" ) ]]; then
            die "Cannot switch to view_only: neither existing wallet (${WALLET_FILE}.keys) nor MONERO_VIEW_ONLY_ADDRESS + MONERO_VIEW_ONLY_KEY are set."
        fi
    fi

    confirm_dangerous_action "$(t config.confirm_set_mode "$target_mode" "$ACTIVE_ENV_FILE")" 1

    local ts backup_file
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    backup_file="${ACTIVE_ENV_FILE}.bak.${ts}"
    cp "$ACTIVE_ENV_FILE" "$backup_file"
    chmod 600 "$backup_file"
    log_info "$(t config.backup_created "$backup_file")"

    set_env_kv_file "$ACTIVE_ENV_FILE" "WALLET_MODE" "$target_mode"
    if [[ "$target_mode" == "view_only" ]]; then
        set_env_kv_file "$ACTIVE_ENV_FILE" "ENABLE_AUTO_SWEEP" "false"
        log_info "$(t config.set_mode_vo_done)"
        log_warn "$(t config.set_mode_vo_warn "$WALLET_FILE")"
    else
        if [[ -n "${COLD_WALLET_ADDRESS:-}" ]]; then
            set_env_kv_file "$ACTIVE_ENV_FILE" "ENABLE_AUTO_SWEEP" "true"
            log_info "$(t config.set_mode_hot_done "$COLD_WALLET_ADDRESS")"
        else
            log_info "$(t config.set_mode_hot_nosweep)"
        fi
    fi
}

main() {
    parse_global_flags "$@"
    set -- "${ADMIN_REST_ARGS[@]}"
    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        show)        cmd_show "$@" ;;
        doctor)      cmd_doctor "$@" ;;
        rotate-keys) cmd_rotate_keys "$@" ;;
        set-mode)    cmd_set_mode "$@" ;;
        help|-h|--help) usage ;;
        *)           die "$(t config.unknown_cmd "$cmd")" ;;
    esac
}

main "$@"
