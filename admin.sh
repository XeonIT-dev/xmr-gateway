#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Unified Admin Control Center (./admin.sh)
# ==============================================================================
# Interactive menu when invoked without arguments, or scriptable CLI:
#   ./admin.sh [--env FILE] [--json] [--yes] <module> <command> [args...]
#
# Modules:
#   service   - Lifecycle (start/stop/restart/status/logs/build/setup-rpc/systemd)
#   config    - Masked config view, fail-closed doctor, key rotation, mode switch
#   wallet    - Monero hot & view-only wallet operations, balance, transfers, CLI
#   invoices  - Invoice creation, lookup, SQLite inspection, sweep, incident resolve
#   webhooks  - Webhook outbox list/inspect, operator retry, HMAC verify, receiver
#   db        - SQLite stats, AUDIT-005 invariants audit, hot backup, RO/RW shell
#   dev       - Rust fmt/clippy/test check, live /health RBAC check, stagenet demo
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=admin/lib/common.sh
source "$ROOT_DIR/admin/lib/common.sh"

usage() {
    cat <<'EOF'
xmr-gateway Admin Control Center

Usage:
  ./admin.sh                                            Open interactive admin menu
  ./admin.sh [GLOBAL FLAGS] <module> <command> [args]   Run CLI command
  ./admin.sh help | ./admin.sh <module> help            Show help

Global Flags (accepted before or after <module> <command>):
  --env <path>     Load alternative environment file (default: .env)
  --json           Machine-readable JSON output where supported
  --yes, -y        Non-interactive confirmation (required for Mainnet actions in scripts)

Modules:
  service          start | stop | restart | status | logs | build | setup-rpc | systemd
  config           show | doctor | rotate-keys | set-mode
  wallet           info | balance | transfers | refresh | set-height | rescan |
                   create-hot | create-view-only | export-view-keys | transfer | sweep-all | cli
  invoices         create | get | list | inspect | sweep | resolve
  webhooks         list | inspect | retry | retry-invoice | verify-sig | test-receiver
  db               stats | audit-invariants | backup | shell
  dev              check | health-rbac | demo
EOF
}

dispatch_module() {
    local module="$1"
    shift || true
    case "$module" in
        service)  "$ADMIN_DIR/service.sh" "$@" ;;
        config)   "$ADMIN_DIR/config.sh" "$@" ;;
        wallet)   "$ADMIN_DIR/wallet.sh" "$@" ;;
        invoices) "$ADMIN_DIR/invoices.sh" "$@" ;;
        webhooks) "$ADMIN_DIR/webhooks.sh" "$@" ;;
        db)       "$ADMIN_DIR/db.sh" "$@" ;;
        dev)      "$ADMIN_DIR/dev.sh" "$@" ;;
        help|-h|--help) usage ;;
        *)        die "Unknown module '$module'. Run './admin.sh help'." ;;
    esac
}

pause_prompt() {
    printf '\nPress Enter to continue...'
    IFS= read -r _ || true
}

run_interactive_safe() {
    printf '\n'
    if ! "$@"; then
        log_warn "Command exited with non-zero status ($?)."
    fi
    pause_prompt
}

menu_service() {
    while true; do
        printf '\n%s--- [1] Service Lifecycle ---%s\n' "$C_CYAN" "$C_RESET"
        printf '  1) Status          5) Logs (gateway, -n 50)\n'
        printf '  2) Start           6) Logs (rpc, -n 50)\n'
        printf '  3) Stop            7) Build release binary\n'
        printf '  4) Restart         8) Setup Monero RPC binaries\n'
        printf '                     9) Systemd install dry-run\n'
        printf '  0) Back\n'
        printf 'Select> '
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/service.sh" status ;;
            2) run_interactive_safe "$ADMIN_DIR/service.sh" start ;;
            3) run_interactive_safe "$ADMIN_DIR/service.sh" stop ;;
            4) run_interactive_safe "$ADMIN_DIR/service.sh" restart ;;
            5) run_interactive_safe "$ADMIN_DIR/service.sh" logs gateway -n 50 ;;
            6) run_interactive_safe "$ADMIN_DIR/service.sh" logs rpc -n 50 ;;
            7) run_interactive_safe "$ADMIN_DIR/service.sh" build ;;
            8) run_interactive_safe "$ADMIN_DIR/service.sh" setup-rpc ;;
            9) run_interactive_safe "$ADMIN_DIR/service.sh" systemd install-dry-run ;;
            0|q) return 0 ;;
            *) log_warn "Invalid choice: $ch" ;;
        esac
    done
}

menu_config() {
    while true; do
        printf '\n%s--- [2] Config, RBAC & Doctor ---%s\n' "$C_CYAN" "$C_RESET"
        printf '  1) Show masked config\n'
        printf '  2) Run security doctor\n'
        printf '  3) Rotate keys (api|operator|webhook|rpc|all)\n'
        printf '  4) Switch WALLET_MODE (view_only|hot_wallet)\n'
        printf '  0) Back\n'
        printf 'Select> '
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/config.sh" show ;;
            2) run_interactive_safe "$ADMIN_DIR/config.sh" doctor ;;
            3)
                local scope=""
                printf 'Scope [api|operator|webhook|rpc|all] (default all): '
                IFS= read -r scope || true
                run_interactive_safe "$ADMIN_DIR/config.sh" rotate-keys "${scope:-all}"
                ;;
            4)
                local mode=""
                printf 'Target mode [view_only|hot_wallet]: '
                IFS= read -r mode || true
                [[ -n "$mode" ]] && run_interactive_safe "$ADMIN_DIR/config.sh" set-mode "$mode"
                ;;
            0|q) return 0 ;;
            *) log_warn "Invalid choice: $ch" ;;
        esac
    done
}

menu_wallet() {
    while true; do
        printf '\n%s--- [3] Monero Wallet ---%s\n' "$C_CYAN" "$C_RESET"
        printf '  1) Info & Balance          6) Create View-Only Wallet\n'
        printf '  2) Transfers (all)         7) Export View-Only Keys\n'
        printf '  3) Refresh                 8) Transfer XMR (hot only)\n'
        printf '  4) Set restore height      9) Sweep-All (hot only)\n'
        printf '  5) Create Hot Wallet      10) Launch monero-wallet-cli\n'
        printf '  0) Back\n'
        printf 'Select> '
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/wallet.sh" info ;;
            2) run_interactive_safe "$ADMIN_DIR/wallet.sh" transfers all ;;
            3) run_interactive_safe "$ADMIN_DIR/wallet.sh" refresh ;;
            4)
                local h=""
                printf 'Start block height: '
                IFS= read -r h || true
                [[ -n "$h" ]] && run_interactive_safe "$ADMIN_DIR/wallet.sh" set-height "$h"
                ;;
            5) run_interactive_safe "$ADMIN_DIR/wallet.sh" create-hot ;;
            6) run_interactive_safe "$ADMIN_DIR/wallet.sh" create-view-only ;;
            7) run_interactive_safe "$ADMIN_DIR/wallet.sh" export-view-keys ;;
            8)
                local addr="" amt="" prio=""
                printf 'Destination address: '; IFS= read -r addr || true
                printf 'Amount (XMR): '; IFS= read -r amt || true
                printf 'Priority [0-4, default from .env]: '; IFS= read -r prio || true
                if [[ -n "$addr" && -n "$amt" ]]; then
                    if [[ -n "$prio" ]]; then
                        run_interactive_safe "$ADMIN_DIR/wallet.sh" transfer "$addr" "$amt" "$prio"
                    else
                        run_interactive_safe "$ADMIN_DIR/wallet.sh" transfer "$addr" "$amt"
                    fi
                fi
                ;;
            9)
                local addr="" idx=""
                printf 'Destination address: '; IFS= read -r addr || true
                printf 'Subaddress index (blank for all): '; IFS= read -r idx || true
                if [[ -n "$addr" ]]; then
                    if [[ -n "$idx" ]]; then
                        run_interactive_safe "$ADMIN_DIR/wallet.sh" sweep-all "$addr" "$idx"
                    else
                        run_interactive_safe "$ADMIN_DIR/wallet.sh" sweep-all "$addr"
                    fi
                fi
                ;;
            10) "$ADMIN_DIR/wallet.sh" cli || true ;;
            0|q) return 0 ;;
            *) log_warn "Invalid choice: $ch" ;;
        esac
    done
}

menu_invoices() {
    while true; do
        printf '\n%s--- [4] Invoices & Sweep Incidents ---%s\n' "$C_CYAN" "$C_RESET"
        printf '  1) List recent invoices (SQLite RO)\n'
        printf '  2) Create invoice (API)\n'
        printf '  3) Get invoice (API)\n'
        printf '  4) Inspect invoice (SQLite forensic view)\n'
        printf '  5) Manual sweep (operator API)\n'
        printf '  6) Resolve REORGED sweep incident (operator API)\n'
        printf '  0) Back\n'
        printf 'Select> '
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/invoices.sh" list --limit 25 ;;
            2)
                local oid="" amt="" cb=""
                printf 'Order ID: '; IFS= read -r oid || true
                printf 'Amount (XMR): '; IFS= read -r amt || true
                printf 'Callback URL (optional): '; IFS= read -r cb || true
                if [[ -n "$oid" && -n "$amt" ]]; then
                    if [[ -n "$cb" ]]; then
                        run_interactive_safe "$ADMIN_DIR/invoices.sh" create --order-id "$oid" --amount-xmr "$amt" --callback-url "$cb"
                    else
                        run_interactive_safe "$ADMIN_DIR/invoices.sh" create --order-id "$oid" --amount-xmr "$amt"
                    fi
                fi
                ;;
            3)
                local id=""
                printf 'Invoice UUID: '; IFS= read -r id || true
                [[ -n "$id" ]] && run_interactive_safe "$ADMIN_DIR/invoices.sh" get "$id"
                ;;
            4)
                local id=""
                printf 'Invoice UUID or order_id: '; IFS= read -r id || true
                [[ -n "$id" ]] && run_interactive_safe "$ADMIN_DIR/invoices.sh" inspect "$id"
                ;;
            5)
                local id=""
                printf 'Invoice UUID to sweep: '; IFS= read -r id || true
                [[ -n "$id" ]] && run_interactive_safe "$ADMIN_DIR/invoices.sh" sweep "$id"
                ;;
            6)
                local id="" act="" note="" tx=""
                printf 'Invoice UUID: '; IFS= read -r id || true
                printf 'Action [allow_resweep|mark_reconciled]: '; IFS= read -r act || true
                printf 'Operator audit note: '; IFS= read -r note || true
                if [[ "$act" == "allow_resweep" ]]; then
                    run_interactive_safe "$ADMIN_DIR/invoices.sh" resolve "$id" allow_resweep --confirm-absent --note "$note"
                elif [[ "$act" == "mark_reconciled" ]]; then
                    printf 'Replacement tx hash (optional 64-hex): '; IFS= read -r tx || true
                    if [[ -n "$tx" ]]; then
                        run_interactive_safe "$ADMIN_DIR/invoices.sh" resolve "$id" mark_reconciled --tx-hash "$tx" --note "$note"
                    else
                        run_interactive_safe "$ADMIN_DIR/invoices.sh" resolve "$id" mark_reconciled --note "$note"
                    fi
                fi
                ;;
            0|q) return 0 ;;
            *) log_warn "Invalid choice: $ch" ;;
        esac
    done
}

menu_webhooks() {
    while true; do
        printf '\n%s--- [5] Webhooks ---%s\n' "$C_CYAN" "$C_RESET"
        printf '  1) List webhooks (all, limit 25)\n'
        printf '  2) List FAILED webhooks\n'
        printf '  3) Inspect webhook by UUID\n'
        printf '  4) Retry single FAILED webhook (operator)\n'
        printf '  5) Retry all FAILED webhooks for invoice (operator)\n'
        printf '  6) Start local HMAC test receiver (port 9000)\n'
        printf '  0) Back\n'
        printf 'Select> '
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/webhooks.sh" list --limit 25 ;;
            2) run_interactive_safe "$ADMIN_DIR/webhooks.sh" list --status FAILED --limit 25 ;;
            3)
                local wid=""
                printf 'Webhook UUID: '; IFS= read -r wid || true
                [[ -n "$wid" ]] && run_interactive_safe "$ADMIN_DIR/webhooks.sh" inspect "$wid"
                ;;
            4)
                local wid=""
                printf 'FAILED Webhook UUID: '; IFS= read -r wid || true
                [[ -n "$wid" ]] && run_interactive_safe "$ADMIN_DIR/webhooks.sh" retry "$wid"
                ;;
            5)
                local iid=""
                printf 'Invoice UUID: '; IFS= read -r iid || true
                [[ -n "$iid" ]] && run_interactive_safe "$ADMIN_DIR/webhooks.sh" retry-invoice "$iid"
                ;;
            6) "$ADMIN_DIR/webhooks.sh" test-receiver 9000 || true ;;
            0|q) return 0 ;;
            *) log_warn "Invalid choice: $ch" ;;
        esac
    done
}

menu_db() {
    while true; do
        printf '\n%s--- [6] SQLite DB & Forensics ---%s\n' "$C_CYAN" "$C_RESET"
        printf '  1) Database stats\n'
        printf '  2) Audit invariants (integrity + AUDIT-005 balance conservation)\n'
        printf '  3) Safe online hot backup\n'
        printf '  4) Interactive read-only SQLite shell\n'
        printf '  0) Back\n'
        printf 'Select> '
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/db.sh" stats ;;
            2) run_interactive_safe "$ADMIN_DIR/db.sh" audit-invariants ;;
            3) run_interactive_safe "$ADMIN_DIR/db.sh" backup ;;
            4) "$ADMIN_DIR/db.sh" shell || true ;;
            0|q) return 0 ;;
            *) log_warn "Invalid choice: $ch" ;;
        esac
    done
}

menu_dev() {
    while true; do
        printf '\n%s--- [7] Dev & Verification ---%s\n' "$C_CYAN" "$C_RESET"
        printf '  1) Rust check (fmt + clippy + cargo test)\n'
        printf '  2) Live GET /health RBAC verification (AUDIT-002)\n'
        printf '  3) Launch Stagenet demo (./demo-stagenet.sh)\n'
        printf '  0) Back\n'
        printf 'Select> '
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/dev.sh" check ;;
            2) run_interactive_safe "$ADMIN_DIR/dev.sh" health-rbac ;;
            3) "$ADMIN_DIR/dev.sh" demo || true ;;
            0|q) return 0 ;;
            *) log_warn "Invalid choice: $ch" ;;
        esac
    done
}

interactive_main_menu() {
    load_env 1
    while true; do
        local net_badge="$MONERO_NETWORK"
        if [[ "$MONERO_NETWORK" == "mainnet" ]]; then
            net_badge="${C_RED}[MAINNET]${C_RESET}"
        else
            net_badge="${C_GREEN}[${MONERO_NETWORK^^}]${C_RESET}"
        fi
        printf '\n%s====================================================================%s\n' "$C_BOLD" "$C_RESET"
        printf '  %sxmr-gateway Admin Control Center%s  %s  mode=%s\n' "$C_BOLD" "$C_RESET" "$net_badge" "$WALLET_MODE"
        printf '  Env: %s | Gateway: %s\n' "$ACTIVE_ENV_FILE" "$GATEWAY_BASE_URL"
        printf '%s====================================================================%s\n' "$C_BOLD" "$C_RESET"
        printf '  1) Service Lifecycle   (start / stop / status / logs / build / systemd)\n'
        printf '  2) Config & Security   (show / doctor / rotate-keys / set-mode)\n'
        printf '  3) Monero Wallet       (info / transfers / refresh / keys / transfer)\n'
        printf '  4) Invoices & Sweeps   (create / get / list / inspect / sweep / resolve)\n'
        printf '  5) Webhooks            (list / inspect / retry / verify-sig / receiver)\n'
        printf '  6) SQLite & Forensics  (stats / audit-invariants / backup / shell)\n'
        printf '  7) Dev & Verification  (cargo check / live /health RBAC / demo)\n'
        printf '  0) Exit\n'
        printf 'Select> '
        local choice=""
        IFS= read -r choice || return 0
        case "$choice" in
            1) menu_service ;;
            2) menu_config ;;
            3) menu_wallet ;;
            4) menu_invoices ;;
            5) menu_webhooks ;;
            6) menu_db ;;
            7) menu_dev ;;
            0|q|exit) return 0 ;;
            *) log_warn "Invalid selection: $choice" ;;
        esac
    done
}

main() {
    parse_global_flags "$@"
    set -- "${ADMIN_REST_ARGS[@]}"

    if [[ $# -eq 0 ]]; then
        if [[ ! -t 0 ]]; then
            usage
            exit 0
        fi
        interactive_main_menu
        exit 0
    fi

    dispatch_module "$@"
}

main "$@"
