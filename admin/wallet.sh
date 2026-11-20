#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Admin Suite — Monero Wallet Management Module (admin/wallet.sh)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=admin/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    t wallet.usage
}

require_hot_wallet_for_spend() {
    if [[ "$WALLET_MODE" == "view_only" ]]; then
        t wallet.view_only_refused >&2
        exit 1
    fi
}

rpc_extract_result_or_die() {
    local method="$1"
    if [[ "$RPC_LAST_HTTP_CODE" != "200" ]]; then
        die "monero-wallet-rpc '$method' failed (HTTP ${RPC_LAST_HTTP_CODE:-err}): ${RPC_LAST_BODY}"
    fi
    _PY_BODY="$RPC_LAST_BODY" python3 - "$method" <<'PYEOF'
import json, os, sys
method = sys.argv[1]
data = json.loads(os.environ["_PY_BODY"])
if "error" in data and data["error"] is not None:
    err = data["error"]
    sys.stderr.write(f"RPC error in {method} (code {err.get('code')}): {err.get('message')}\n")
    sys.exit(1)
print(json.dumps(data.get("result", {})))
PYEOF
}

cmd_info() {
    load_env
    wallet_rpc_call "get_balance" '{"account_index":0,"all_accounts":false}' || die "Cannot connect to monero-wallet-rpc at $MONERO_RPC_URL"
    local bal_json
    bal_json="$(rpc_extract_result_or_die "get_balance")"

    wallet_rpc_call "get_address" '{"account_index":0}' || die "get_address RPC failed"
    local addr_json
    addr_json="$(rpc_extract_result_or_die "get_address")"

    wallet_rpc_call "get_height" || die "get_height RPC failed"
    local height_json
    height_json="$(rpc_extract_result_or_die "get_height")"

    local daemon_json="{}"
    if daemon_rpc_call "get_info" 2>/dev/null && [[ "$RPC_LAST_HTTP_CODE" == "200" ]]; then
        daemon_json="$(python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(json.dumps(d.get("result",{})))' <<< "$RPC_LAST_BODY" 2>/dev/null || printf '{}')"
    fi

    python3 - "$ADMIN_JSON" "$MONERO_NETWORK" "$WALLET_MODE" "$bal_json" "$addr_json" "$height_json" "$daemon_json" <<'PYEOF'
import json, os, sys

as_json = sys.argv[1] == "1"
net, mode = sys.argv[2], sys.argv[3]
bal = json.loads(sys.argv[4])
addr = json.loads(sys.argv[5])
height = json.loads(sys.argv[6])
daemon = json.loads(sys.argv[7])

def fmt_xmr(pico):
    n = int(pico or 0)
    w, f = divmod(n, 10**12)
    return f"{w}.{f:012d}"

w_h = int(height.get("height", 0) or 0)
d_h = int(daemon.get("height", 0) or 0)
d_th = int(daemon.get("target_height", 0) or 0)
d_eff = max(d_h, d_th)

subaddrs = []
for s in bal.get("per_subaddress", []) or []:
    subaddrs.append({
        "address_index": s.get("address_index"),
        "address": s.get("address"),
        "label": s.get("label", ""),
        "balance_piconero": int(s.get("balance", 0)),
        "balance_xmr": fmt_xmr(s.get("balance", 0)),
        "unlocked_piconero": int(s.get("unlocked_balance", 0)),
        "unlocked_xmr": fmt_xmr(s.get("unlocked_balance", 0)),
        "num_unspent_outputs": s.get("num_unspent_outputs", 0),
    })

out = {
    "network": net,
    "wallet_mode": mode,
    "primary_address": addr.get("address"),
    "total_subaddresses": len(addr.get("addresses", []) or []),
    "balance_piconero": int(bal.get("balance", 0)),
    "balance_xmr": fmt_xmr(bal.get("balance", 0)),
    "unlocked_balance_piconero": int(bal.get("unlocked_balance", 0)),
    "unlocked_balance_xmr": fmt_xmr(bal.get("unlocked_balance", 0)),
    "blocks_to_unlock": bal.get("blocks_to_unlock", 0),
    "wallet_height": w_h,
    "daemon_height": d_eff if d_eff > 0 else None,
    "daemon_synchronized": daemon.get("synchronized") if daemon else None,
    "per_subaddress": subaddrs,
}

if as_json:
    print(json.dumps(out, indent=2))
else:
    lang = os.environ.get("ADMIN_ACTIVE_LANG", "en")
    if lang == "ru":
        print("=== Информация и баланс кошелька Monero ===")
        print(f"  Сеть / Режим       : {net} / {mode}")
        print(f"  Основной адрес     : {out['primary_address']}")
        print(f"  Общий баланс       : {out['balance_xmr']} XMR ({out['balance_piconero']} piconero)")
        print(f"  Разблокировано     : {out['unlocked_balance_xmr']} XMR ({out['unlocked_balance_piconero']} piconero)")
        print(f"  Блоков до разблок. : {out['blocks_to_unlock']}")
        print(f"  Субадресов всего   : {out['total_subaddresses']}")
        if out["daemon_height"] is not None:
            lag = out["daemon_height"] - w_h
            print(f"  Высота (Кош./Дем.) : {w_h} / {out['daemon_height']} (отставание={lag}, synced={out['daemon_synchronized']})")
        else:
            print(f"  Высота кошелька    : {w_h} (высота демона недоступна)")
        if subaddrs:
            print("\nАктивные / ненулевые субадреса:")
            print(f"  {'IDX':>5s}  {'БАЛАНС (XMR)':>18s}  {'РАЗБЛОК. (XMR)':>18s}  {'ВЫХ.':>4s}  {'МЕТКА'}")
            for s in subaddrs:
                print(f"  {s['address_index']:5d}  {s['balance_xmr']:>18s}  {s['unlocked_xmr']:>18s}  {s['num_unspent_outputs']:4d}  {s['label']}")
    else:
        print("=== Monero Wallet Info & Balance ===")
        print(f"  Network / Mode   : {net} / {mode}")
        print(f"  Primary Address  : {out['primary_address']}")
        print(f"  Total Balance    : {out['balance_xmr']} XMR ({out['balance_piconero']} piconero)")
        print(f"  Unlocked Balance : {out['unlocked_balance_xmr']} XMR ({out['unlocked_balance_piconero']} piconero)")
        print(f"  Blocks to Unlock : {out['blocks_to_unlock']}")
        print(f"  Subaddresses     : {out['total_subaddresses']} total")
        if out["daemon_height"] is not None:
            lag = out["daemon_height"] - w_h
            print(f"  Height (W / D)   : {w_h} / {out['daemon_height']} (lag={lag}, synced={out['daemon_synchronized']})")
        else:
            print(f"  Wallet Height    : {w_h} (daemon height unavailable)")
        if subaddrs:
            print("\nNon-zero / active subaddresses:")
            print(f"  {'IDX':>5s}  {'BALANCE (XMR)':>18s}  {'UNLOCKED (XMR)':>18s}  {'OUTS':>4s}  {'LABEL'}")
            for s in subaddrs:
                print(f"  {s['address_index']:5d}  {s['balance_xmr']:>18s}  {s['unlocked_xmr']:>18s}  {s['num_unspent_outputs']:4d}  {s['label']}")
PYEOF
}

cmd_transfers() {
    load_env
    local filter="${1:-all}"
    local params=""
    case "$filter" in
        in)      params='{"account_index":0,"in":true}' ;;
        out)     params='{"account_index":0,"out":true}' ;;
        pool)    params='{"account_index":0,"pool":true}' ;;
        pending) params='{"account_index":0,"pending":true}' ;;
        all)     params='{"account_index":0,"in":true,"out":true,"pool":true,"pending":true}' ;;
        *)       die "Invalid transfers filter '$filter'. Expected: in | out | pool | pending | all" ;;
    esac

    wallet_rpc_call "get_transfers" "$params" || die "get_transfers RPC failed"
    local res_json
    res_json="$(rpc_extract_result_or_die "get_transfers")"

    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        printf '%s\n' "$res_json" | pretty_print_json
        return 0
    fi

    python3 - "$res_json" <<'PYEOF'
import json, sys
res = json.loads(sys.stdin.read()) if False else json.loads(sys.argv[1])

def fmt_xmr(pico):
    w, f = divmod(int(pico or 0), 10**12)
    return f"{w}.{f:012d}"

rows = []
for bucket in ("in", "out", "pool", "pending"):
    for t in res.get(bucket, []) or []:
        sub = t.get("subaddr_index", {}) or {}
        rows.append((
            int(t.get("timestamp", 0) or 0),
            bucket.upper(),
            sub.get("minor", 0),
            fmt_xmr(t.get("amount", 0)),
            fmt_xmr(t.get("fee", 0)),
            int(t.get("confirmations", 0) or 0),
            bool(t.get("double_spend_seen", False)),
            t.get("txid", ""),
        ))

rows.sort(key=lambda r: r[0], reverse=True)
if not rows:
    print("No transfers found.")
    sys.exit(0)

print(f"{'TYPE':<8s} {'SUB':>4s} {'AMOUNT (XMR)':>18s} {'FEE (XMR)':>16s} {'CONFS':>6s} {'DS':<5s} {'TXID'}")
for _, b, sub, amt, fee, confs, ds, txid in rows:
    print(f"{b:<8s} {sub:4d} {amt:>18s} {fee:>16s} {confs:6d} {str(ds):<5s} {txid}")
PYEOF
}

cmd_refresh() {
    load_env
    wallet_rpc_call "refresh" '{}' || die "refresh RPC failed"
    local res_json
    res_json="$(rpc_extract_result_or_die "refresh")"
    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        printf '%s\n' "$res_json" | pretty_print_json
    else
        log_info "$(t wallet.refresh_done "$res_json")"
    fi
}

cmd_set_height() {
    load_env
    local height="${1:-}"
    [[ "$height" =~ ^[0-9]+$ ]] || die "Usage: ./admin.sh wallet set-height <block_height>"

    wallet_rpc_call "refresh" "{\"start_height\":${height}}" || die "refresh(start_height) RPC failed"
    local res_json
    res_json="$(rpc_extract_result_or_die "refresh")"
    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        printf '%s\n' "$res_json" | pretty_print_json
    else
        log_info "$(t wallet.set_height_done "$height" "$res_json")"
        log_info "$(t wallet.set_height_tip "$height" "$ACTIVE_ENV_FILE")"
    fi
}

cmd_rescan() {
    load_env
    confirm_dangerous_action "$(t wallet.confirm_rescan "$MONERO_NETWORK")"
    wallet_rpc_call "rescan_blockchain" '{}' || die "rescan_blockchain RPC failed"
    local res_json
    res_json="$(rpc_extract_result_or_die "rescan_blockchain")"
    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        printf '%s\n' "$res_json" | pretty_print_json
    else
        log_info "$(t wallet.rescan_done)"
    fi
}

fix_system_wallet_ownership() {
    if [[ "$(id -u)" -eq 0 ]] \
        && [[ "$ACTIVE_ENV_FILE" == "/etc/xmr-gateway/.env" || "$DATA_DIR" == /var/lib/xmr-gateway* ]] \
        && id xmr-gateway >/dev/null 2>&1; then
        chown xmr-gateway:xmr-gateway "$DATA_DIR" "$WALLET_DIR"
        if [[ -f "$WALLET_PASS_FILE" ]]; then
            chown xmr-gateway:xmr-gateway "$WALLET_PASS_FILE"
            chmod 600 "$WALLET_PASS_FILE"
        fi
        local wf
        for wf in "${WALLET_FILE}"*; do
            if [[ -e "$wf" ]]; then
                chown xmr-gateway:xmr-gateway "$wf"
                chmod 600 "$wf"
            fi
        done
        if [[ -f "$CLI_LOG_FILE" ]]; then
            chown xmr-gateway:xmr-gateway "$CLI_LOG_FILE"
            chmod 600 "$CLI_LOG_FILE"
        fi
    fi
}

cmd_create_hot() {
    load_env
    require_cmd openssl
    local restore_height="$WALLET_RESTORE_HEIGHT"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --restore-height)
                [[ $# -ge 2 ]] || die "--restore-height requires a height"
                restore_height="$2"
                shift 2
                ;;
            *) die "Unknown create-hot option: $1" ;;
        esac
    done
    [[ "$restore_height" =~ ^[0-9]+$ ]] || die "Invalid restore height: $restore_height"
    [[ ! -f "${WALLET_FILE}.keys" ]] || die "Wallet already exists at ${WALLET_FILE}.keys. Refusing to overwrite."

    confirm_dangerous_action "$(t wallet.confirm_create_hot "$WALLET_FILE")" 1

    local wallet_cli
    wallet_cli="$(find_monero_bin monero-wallet-cli)" || die "monero-wallet-cli not found. Run './admin.sh service setup-rpc'."

    mkdir -p "$WALLET_DIR"
    chmod 700 "$DATA_DIR" "$WALLET_DIR"
    if [[ ! -f "$WALLET_PASS_FILE" ]]; then
        printf '%s' "$(openssl rand -hex 24)" > "$WALLET_PASS_FILE"
        chmod 600 "$WALLET_PASS_FILE"
        log_info "Created 0600 wallet password file: $WALLET_PASS_FILE"
    else
        chmod 600 "$WALLET_PASS_FILE"
    fi

    local net_args=()
    [[ "$MONERO_NETWORK" == "stagenet" ]] && net_args+=(--stagenet)
    [[ "$MONERO_NETWORK" == "testnet" ]] && net_args+=(--testnet)

    log_warn "$(t wallet.seed_warn "$MONERO_NETWORK")"
    printf 'N\n' | "$wallet_cli" \
        --offline \
        "${net_args[@]}" \
        --generate-new-wallet "$WALLET_FILE" \
        --password-file "$WALLET_PASS_FILE" \
        --restore-height "$restore_height" \
        --mnemonic-language English \
        --log-file "$CLI_LOG_FILE" \
        --command address

    chmod 600 "${WALLET_FILE}"* 2>/dev/null || true
    fix_system_wallet_ownership
    log_info "$(t wallet.hot_created "$WALLET_FILE")"
}

cmd_create_view_only() {
    load_env
    require_cmd openssl
    local addr="${MONERO_VIEW_ONLY_ADDRESS:-}"
    local view_key="${MONERO_VIEW_ONLY_KEY:-}"
    local restore_height="$WALLET_RESTORE_HEIGHT"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --address)        [[ $# -ge 2 ]] || die "--address requires a value"; addr="$2"; shift 2 ;;
            --view-key)       [[ $# -ge 2 ]] || die "--view-key requires a value"; view_key="$2"; shift 2 ;;
            --restore-height) [[ $# -ge 2 ]] || die "--restore-height requires a value"; restore_height="$2"; shift 2 ;;
            *) die "Unknown create-view-only option: $1" ;;
        esac
    done

    [[ ! -f "${WALLET_FILE}.keys" ]] || die "Wallet already exists at ${WALLET_FILE}.keys. Refusing to overwrite."
    if [[ -z "$addr" && -t 0 ]]; then
        printf 'Primary Monero address: ' >&2
        IFS= read -r addr
    fi
    if [[ -z "$view_key" && -t 0 ]]; then
        printf 'Private view key (64 hex chars): ' >&2
        IFS= read -rs view_key
        printf '\n' >&2
    fi

    [[ -n "$addr" ]] || die "Primary address is required (--address or MONERO_VIEW_ONLY_ADDRESS)."
    [[ "$view_key" =~ ^[0-9a-fA-F]{64}$ ]] || die "Private view key must be exactly 64 hex characters."
    [[ "$restore_height" =~ ^[0-9]+$ ]] || die "Invalid restore height: $restore_height"

    local wallet_cli
    wallet_cli="$(find_monero_bin monero-wallet-cli)" || die "monero-wallet-cli not found. Run './admin.sh service setup-rpc'."

    mkdir -p "$WALLET_DIR"
    chmod 700 "$DATA_DIR" "$WALLET_DIR"
    if [[ ! -f "$WALLET_PASS_FILE" ]]; then
        printf '%s' "$(openssl rand -hex 24)" > "$WALLET_PASS_FILE"
        chmod 600 "$WALLET_PASS_FILE"
        log_info "Created 0600 wallet password file: $WALLET_PASS_FILE"
    else
        chmod 600 "$WALLET_PASS_FILE"
    fi

    local net_args=()
    [[ "$MONERO_NETWORK" == "stagenet" ]] && net_args+=(--stagenet)
    [[ "$MONERO_NETWORK" == "testnet" ]] && net_args+=(--testnet)

    log_step "$(t wallet.vo_creating "$WALLET_FILE" "$restore_height")"
    printf '%s\n%s\n%s\nN\n' "$addr" "$view_key" "$restore_height" | "$wallet_cli" \
        --offline \
        "${net_args[@]}" \
        --generate-from-view-key "$WALLET_FILE" \
        --password-file "$WALLET_PASS_FILE" \
        --restore-height "$restore_height" \
        --log-file "$CLI_LOG_FILE" \
        --command address

    chmod 600 "${WALLET_FILE}"* 2>/dev/null || true
    fix_system_wallet_ownership
    log_info "$(t wallet.vo_created "$WALLET_FILE")"
}

cmd_export_view_keys() {
    load_env
    local primary_addr="" view_key=""

    if wallet_rpc_call "get_address" '{"account_index":0}' 2>/dev/null && [[ "$RPC_LAST_HTTP_CODE" == "200" ]]; then
        primary_addr="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("result",{}).get("address",""))' <<< "$RPC_LAST_BODY")"
        wallet_rpc_call "query_key" '{"key_type":"view_key"}' || die "query_key(view_key) RPC failed"
        view_key="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("result",{}).get("key",""))' <<< "$RPC_LAST_BODY")"
    else
        [[ -f "${WALLET_FILE}.keys" ]] || die "Wallet RPC unreachable and local wallet ${WALLET_FILE}.keys not found."
        local wallet_cli
        wallet_cli="$(find_monero_bin monero-wallet-cli)" || die "monero-wallet-cli not found."
        local net_args=()
        [[ "$MONERO_NETWORK" == "stagenet" ]] && net_args+=(--stagenet)
        [[ "$MONERO_NETWORK" == "testnet" ]] && net_args+=(--testnet)
        primary_addr="$("$wallet_cli" --offline "${net_args[@]}" --wallet-file "$WALLET_FILE" --password-file "$WALLET_PASS_FILE" --log-file "$CLI_LOG_FILE" --command address 2>/dev/null | grep -oE '[4578][0-9A-Za-z]{94}' | head -n 1 || true)"
        view_key="$("$wallet_cli" --offline "${net_args[@]}" --wallet-file "$WALLET_FILE" --password-file "$WALLET_PASS_FILE" --log-file "$CLI_LOG_FILE" --command viewkey 2>/dev/null | grep -i 'secret:' | grep -oE '[0-9a-fA-F]{64}' | head -n 1 || true)"
    fi

    [[ -n "$primary_addr" && -n "$view_key" ]] || die "Could not extract primary address and private view key."

    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        python3 - "$MONERO_NETWORK" "$primary_addr" "$view_key" <<'PYEOF'
import json, sys
print(json.dumps({
    "network": sys.argv[1],
    "monero_view_only_address": sys.argv[2],
    "monero_view_only_key": sys.argv[3],
    "note": "Private spend key is NEVER exported by this command.",
}, indent=2))
PYEOF
        return 0
    fi

    cat <<EOF
=== Exported View-Only Credentials ($MONERO_NETWORK) ===
  (Private spend key is NEVER exported here.)

  MONERO_VIEW_ONLY_ADDRESS=${primary_addr}
  MONERO_VIEW_ONLY_KEY=${view_key}

Steps to deploy on a zero-trust View-Only server:
  1. Copy the two lines above into the target server's .env (chmod 600 .env).
  2. Set WALLET_MODE=view_only and ENABLE_AUTO_SWEEP=false in .env.
  3. Set WALLET_RESTORE_HEIGHT to the wallet creation block height.
  4. Run: ./admin.sh wallet create-view-only
  5. Verify with: ./admin.sh config doctor
EOF
}

cmd_transfer() {
    load_env
    require_hot_wallet_for_spend

    local dest="${1:-}"
    local amount_xmr="${2:-}"
    local priority="${3:-$SWEEP_PRIORITY}"
    [[ -n "$dest" && -n "$amount_xmr" ]] || die "Usage: ./admin.sh wallet transfer <address> <amount_xmr> [priority]"
    [[ "$priority" =~ ^[0-4]$ ]] || die "Invalid priority '$priority' (expected 0..4)."

    local amount_pico
    amount_pico="$(xmr_to_piconero "$amount_xmr")" || exit 1
    local formatted_xmr
    formatted_xmr="$(piconero_to_xmr "$amount_pico")"

    # Fail-closed address check against wallet RPC
    local val_params
    val_params="$(python3 -c 'import json,sys; print(json.dumps({"address": sys.argv[1]}))' "$dest")"
    wallet_rpc_call "validate_address" "$val_params" || die "validate_address RPC failed"
    local val_res
    val_res="$(rpc_extract_result_or_die "validate_address")"
    local is_valid
    is_valid="$(python3 -c 'import json,sys; print("1" if json.loads(sys.argv[1]).get("valid") else "0")' "$val_res")"
    [[ "$is_valid" == "1" ]] || die "Destination address failed monero-wallet-rpc validate_address: $dest"

    confirm_dangerous_action "$(t wallet.confirm_transfer "$formatted_xmr" "$amount_pico" "$dest" "$priority")" 1

    local tx_params
    tx_params="$(python3 - "$dest" "$amount_pico" "$priority" <<'PYEOF'
import json, sys
print(json.dumps({
    "destinations": [{"amount": int(sys.argv[2]), "address": sys.argv[1]}],
    "account_index": 0,
    "priority": int(sys.argv[3]),
    "get_tx_key": True,
}))
PYEOF
)"
    wallet_rpc_call "transfer" "$tx_params" || die "transfer RPC failed"
    local res_json
    res_json="$(rpc_extract_result_or_die "transfer")"

    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        printf '%s\n' "$res_json" | pretty_print_json
    else
        python3 - "$res_json" <<'PYEOF'
import json, sys
r = json.loads(sys.argv[1])
def fx(p): w, f = divmod(int(p or 0), 10**12); return f"{w}.{f:012d}"
print("=== Transfer Submitted ===")
print(f"  tx_hash : {r.get('tx_hash')}")
print(f"  amount  : {fx(r.get('amount'))} XMR ({r.get('amount')} piconero)")
print(f"  fee     : {fx(r.get('fee'))} XMR ({r.get('fee')} piconero)")
PYEOF
    fi
}

cmd_sweep_all() {
    load_env
    require_hot_wallet_for_spend

    local dest="${1:-}"
    local subaddr_idx="${2:-}"
    local priority="${3:-$SWEEP_PRIORITY}"
    [[ -n "$dest" ]] || die "Usage: ./admin.sh wallet sweep-all <address> [subaddress_index] [priority]"
    if [[ -n "$subaddr_idx" && ! "$subaddr_idx" =~ ^[0-9]+$ ]]; then
        die "Invalid subaddress_index '$subaddr_idx' (must be non-negative integer)."
    fi
    [[ "$priority" =~ ^[0-4]$ ]] || die "Invalid priority '$priority' (expected 0..4)."

    local val_params
    val_params="$(python3 -c 'import json,sys; print(json.dumps({"address": sys.argv[1]}))' "$dest")"
    wallet_rpc_call "validate_address" "$val_params" || die "validate_address RPC failed"
    local val_res
    val_res="$(rpc_extract_result_or_die "validate_address")"
    local is_valid
    is_valid="$(python3 -c 'import json,sys; print("1" if json.loads(sys.argv[1]).get("valid") else "0")' "$val_res")"
    [[ "$is_valid" == "1" ]] || die "Destination address failed monero-wallet-rpc validate_address: $dest"

    confirm_dangerous_action "$(t wallet.confirm_sweep_all "${subaddr_idx:-ALL}" "$priority" "$dest")" 1

    local sweep_params
    sweep_params="$(python3 - "$dest" "$subaddr_idx" "$priority" <<'PYEOF'
import json, sys
p = {
    "address": sys.argv[1],
    "account_index": 0,
    "priority": int(sys.argv[3]),
}
if sys.argv[2]:
    p["subaddr_indices"] = [int(sys.argv[2])]
print(json.dumps(p))
PYEOF
)"
    wallet_rpc_call "sweep_all" "$sweep_params" || die "sweep_all RPC failed"
    local res_json
    res_json="$(rpc_extract_result_or_die "sweep_all")"

    if [[ "$ADMIN_JSON" -eq 1 ]]; then
        printf '%s\n' "$res_json" | pretty_print_json
    else
        python3 - "$res_json" <<'PYEOF'
import json, sys
r = json.loads(sys.argv[1])
def fx(p): w, f = divmod(int(p or 0), 10**12); return f"{w}.{f:012d}"
hashes = r.get("tx_hash_list", []) or []
amts = r.get("amount_list", []) or []
fees = r.get("fee_list", []) or []
print("=== sweep_all Submitted ===")
print(f"  tx_count     : {len(hashes)}")
print(f"  total_amount : {fx(sum(amts))} XMR ({sum(amts)} piconero)")
print(f"  total_fee    : {fx(sum(fees))} XMR ({sum(fees)} piconero)")
for i, h in enumerate(hashes):
    a = amts[i] if i < len(amts) else 0
    f = fees[i] if i < len(fees) else 0
    print(f"  tx[{i}]        : {h} (amount={fx(a)} XMR, fee={fx(f)} XMR)")
PYEOF
    fi
}

cmd_cli() {
    load_env
    local wallet_cli
    wallet_cli="$(find_monero_bin monero-wallet-cli)" || die "monero-wallet-cli not found. Run './admin.sh service setup-rpc'."
    [[ -f "${WALLET_FILE}.keys" ]] || die "Wallet file not found: ${WALLET_FILE}.keys"

    local cli_args=(
        --wallet-file "$WALLET_FILE"
        --password-file "$WALLET_PASS_FILE"
        --daemon-address "$MONERO_REMOTE_NODE"
        --log-file "$CLI_LOG_FILE"
    )
    [[ "$MONERO_NETWORK" == "stagenet" ]] && cli_args+=(--stagenet)
    [[ "$MONERO_NETWORK" == "testnet" ]] && cli_args+=(--testnet)
    if is_truthy "$MONERO_TRUSTED_DAEMON"; then
        cli_args+=(--trusted-daemon)
    else
        cli_args+=(--untrusted-daemon)
    fi
    if [[ -n "${MONERO_RPC_PROXY:-}" ]]; then
        cli_args+=(--proxy "$MONERO_RPC_PROXY")
    fi

    log_info "$(t wallet.launching_cli "$MONERO_NETWORK" "$MONERO_REMOTE_NODE")"
    exec "$wallet_cli" "${cli_args[@]}" "$@"
}

main() {
    parse_global_flags "$@"
    set -- "${ADMIN_REST_ARGS[@]}"
    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        info|balance)     cmd_info "$@" ;;
        transfers)        cmd_transfers "$@" ;;
        refresh)          cmd_refresh "$@" ;;
        set-height)       cmd_set_height "$@" ;;
        rescan)           cmd_rescan "$@" ;;
        create-hot)       cmd_create_hot "$@" ;;
        create-view-only) cmd_create_view_only "$@" ;;
        export-view-keys) cmd_export_view_keys "$@" ;;
        transfer)         cmd_transfer "$@" ;;
        sweep-all)        cmd_sweep_all "$@" ;;
        cli)              cmd_cli "$@" ;;
        help|-h|--help)   usage ;;
        *)                die "$(t wallet.unknown_cmd "$cmd")" ;;
    esac
}

main "$@"
