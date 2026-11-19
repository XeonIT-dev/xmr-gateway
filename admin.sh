#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Unified Admin Control Center (./admin.sh)
# ==============================================================================
# Interactive menu when invoked without arguments, or scriptable CLI:
#   ./admin.sh [--env FILE] [--lang en|ru] [--json] [--yes] <module> <command> [args...]
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=admin/lib/common.sh
source "$ROOT_DIR/admin/lib/common.sh"

usage() {
    t main.usage
}

cmd_lang() {
    local action="${1:-show}"
    case "$action" in
        show)
            local sf
            sf="$(i18n_state_file)"
            if [[ "$ADMIN_JSON" -eq 1 ]]; then
                python3 - "$ADMIN_ACTIVE_LANG" "$ADMIN_LANG_SOURCE" "$sf" <<'PYEOF'
import json, sys
print(json.dumps({
    "language": sys.argv[1],
    "source": sys.argv[2],
    "state_file": sys.argv[3],
}, indent=2))
PYEOF
            else
                printf '%s%s%s\n' "$C_BOLD" "$(t lang.current_header)" "$C_RESET"
                tln lang.active_label "$ADMIN_ACTIVE_LANG"
                tln lang.source_label "$ADMIN_LANG_SOURCE"
                tln lang.state_file_label "$sf"
            fi
            ;;
        en|ru|EN|RU)
            i18n_save_lang "$action"
            local sf
            sf="$(i18n_state_file)"
            if [[ "$ADMIN_JSON" -eq 1 ]]; then
                python3 - "$ADMIN_ACTIVE_LANG" "$ADMIN_LANG_SOURCE" "$sf" <<'PYEOF'
import json, sys
print(json.dumps({
    "language": sys.argv[1],
    "source": sys.argv[2],
    "state_file": sys.argv[3],
    "saved": True,
}, indent=2))
PYEOF
            else
                log_info "$(t lang.saved "$ADMIN_ACTIVE_LANG" "$sf")"
            fi
            ;;
        help|-h|--help)
            t lang.usage
            ;;
        *)
            die "$(t common.invalid_lang "$action")"
            ;;
    esac
}

cmd_guide() {
    local print_path_only=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --path) print_path_only=1; shift ;;
            help|-h|--help) t guide.usage; return 0 ;;
            *) die "$(t common.invalid_choice "$1")" ;;
        esac
    done

    local guide_file="$ADMIN_DIR/GUIDE_EN.md"
    if [[ "$ADMIN_ACTIVE_LANG" == "ru" ]]; then
        guide_file="$ADMIN_DIR/GUIDE_RU.md"
    fi

    [[ -f "$guide_file" ]] || die "$(t guide.not_found "$guide_file")"

    if [[ "$print_path_only" -eq 1 ]]; then
        printf '%s\n' "$guide_file"
        return 0
    fi

    if [[ -t 1 ]] && command -v less >/dev/null 2>&1; then
        less -R "$guide_file"
    else
        cat "$guide_file"
    fi
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
        lang)     cmd_lang "$@" ;;
        guide)    cmd_guide "$@" ;;
        help|-h|--help) usage ;;
        *)        die "$(t common.unknown_module "$module")" ;;
    esac
}

pause_prompt() {
    printf '\n%s' "$(t common.press_enter)"
    IFS= read -r _ || true
}

run_interactive_safe() {
    printf '\n'
    local rc=0
    "$@" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        log_warn "$(t common.cmd_nonzero "$rc")"
    fi
    pause_prompt
}

menu_service() {
    while true; do
        printf '\n%s%s%s\n' "$C_CYAN" "$(t menu.service.title)" "$C_RESET"
        tln menu.service.row1
        tln menu.service.row2
        tln menu.service.row3
        tln menu.service.row4
        tln menu.service.row5
        tln menu.back
        t menu.select
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
            *) log_warn "$(t common.invalid_choice "$ch")" ;;
        esac
    done
}

menu_config() {
    while true; do
        printf '\n%s%s%s\n' "$C_CYAN" "$(t menu.config.title)" "$C_RESET"
        tln menu.config.i1
        tln menu.config.i2
        tln menu.config.i3
        tln menu.config.i4
        tln menu.back
        t menu.select
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/config.sh" show ;;
            2) run_interactive_safe "$ADMIN_DIR/config.sh" doctor ;;
            3)
                local scope=""
                t menu.config.prompt_scope
                IFS= read -r scope || true
                run_interactive_safe "$ADMIN_DIR/config.sh" rotate-keys "${scope:-all}"
                ;;
            4)
                local mode=""
                t menu.config.prompt_mode
                IFS= read -r mode || true
                [[ -n "$mode" ]] && run_interactive_safe "$ADMIN_DIR/config.sh" set-mode "$mode"
                ;;
            0|q) return 0 ;;
            *) log_warn "$(t common.invalid_choice "$ch")" ;;
        esac
    done
}

menu_wallet() {
    while true; do
        printf '\n%s%s%s\n' "$C_CYAN" "$(t menu.wallet.title)" "$C_RESET"
        tln menu.wallet.row1
        tln menu.wallet.row2
        tln menu.wallet.row3
        tln menu.wallet.row4
        tln menu.wallet.row5
        tln menu.back
        t menu.select
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/wallet.sh" info ;;
            2) run_interactive_safe "$ADMIN_DIR/wallet.sh" transfers all ;;
            3) run_interactive_safe "$ADMIN_DIR/wallet.sh" refresh ;;
            4)
                local h=""
                t menu.wallet.prompt_height
                IFS= read -r h || true
                [[ -n "$h" ]] && run_interactive_safe "$ADMIN_DIR/wallet.sh" set-height "$h"
                ;;
            5) run_interactive_safe "$ADMIN_DIR/wallet.sh" create-hot ;;
            6) run_interactive_safe "$ADMIN_DIR/wallet.sh" create-view-only ;;
            7) run_interactive_safe "$ADMIN_DIR/wallet.sh" export-view-keys ;;
            8)
                local addr="" amt="" prio=""
                t menu.wallet.prompt_dest; IFS= read -r addr || true
                t menu.wallet.prompt_amount; IFS= read -r amt || true
                t menu.wallet.prompt_priority; IFS= read -r prio || true
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
                t menu.wallet.prompt_dest; IFS= read -r addr || true
                t menu.wallet.prompt_subaddr; IFS= read -r idx || true
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
            *) log_warn "$(t common.invalid_choice "$ch")" ;;
        esac
    done
}

menu_invoices() {
    while true; do
        printf '\n%s%s%s\n' "$C_CYAN" "$(t menu.invoices.title)" "$C_RESET"
        tln menu.invoices.i1
        tln menu.invoices.i2
        tln menu.invoices.i3
        tln menu.invoices.i4
        tln menu.invoices.i5
        tln menu.invoices.i6
        tln menu.back
        t menu.select
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/invoices.sh" list --limit 25 ;;
            2)
                local oid="" amt="" cb=""
                t menu.invoices.prompt_order; IFS= read -r oid || true
                t menu.invoices.prompt_amount; IFS= read -r amt || true
                t menu.invoices.prompt_cb; IFS= read -r cb || true
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
                t menu.invoices.prompt_uuid; IFS= read -r id || true
                [[ -n "$id" ]] && run_interactive_safe "$ADMIN_DIR/invoices.sh" get "$id"
                ;;
            4)
                local id=""
                t menu.invoices.prompt_uuid_or_order; IFS= read -r id || true
                [[ -n "$id" ]] && run_interactive_safe "$ADMIN_DIR/invoices.sh" inspect "$id"
                ;;
            5)
                local id=""
                t menu.invoices.prompt_sweep_uuid; IFS= read -r id || true
                [[ -n "$id" ]] && run_interactive_safe "$ADMIN_DIR/invoices.sh" sweep "$id"
                ;;
            6)
                local id="" act="" note="" tx=""
                t menu.invoices.prompt_uuid; IFS= read -r id || true
                t menu.invoices.prompt_action; IFS= read -r act || true
                t menu.invoices.prompt_note; IFS= read -r note || true
                if [[ "$act" == "allow_resweep" ]]; then
                    run_interactive_safe "$ADMIN_DIR/invoices.sh" resolve "$id" allow_resweep --confirm-absent --note "$note"
                elif [[ "$act" == "mark_reconciled" ]]; then
                    t menu.invoices.prompt_txhash; IFS= read -r tx || true
                    if [[ -n "$tx" ]]; then
                        run_interactive_safe "$ADMIN_DIR/invoices.sh" resolve "$id" mark_reconciled --tx-hash "$tx" --note "$note"
                    else
                        run_interactive_safe "$ADMIN_DIR/invoices.sh" resolve "$id" mark_reconciled --note "$note"
                    fi
                fi
                ;;
            0|q) return 0 ;;
            *) log_warn "$(t common.invalid_choice "$ch")" ;;
        esac
    done
}

menu_webhooks() {
    while true; do
        printf '\n%s%s%s\n' "$C_CYAN" "$(t menu.webhooks.title)" "$C_RESET"
        tln menu.webhooks.i1
        tln menu.webhooks.i2
        tln menu.webhooks.i3
        tln menu.webhooks.i4
        tln menu.webhooks.i5
        tln menu.webhooks.i6
        tln menu.back
        t menu.select
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/webhooks.sh" list --limit 25 ;;
            2) run_interactive_safe "$ADMIN_DIR/webhooks.sh" list --status FAILED --limit 25 ;;
            3)
                local wid=""
                t menu.webhooks.prompt_wid; IFS= read -r wid || true
                [[ -n "$wid" ]] && run_interactive_safe "$ADMIN_DIR/webhooks.sh" inspect "$wid"
                ;;
            4)
                local wid=""
                t menu.webhooks.prompt_failed_wid; IFS= read -r wid || true
                [[ -n "$wid" ]] && run_interactive_safe "$ADMIN_DIR/webhooks.sh" retry "$wid"
                ;;
            5)
                local iid=""
                t menu.webhooks.prompt_iid; IFS= read -r iid || true
                [[ -n "$iid" ]] && run_interactive_safe "$ADMIN_DIR/webhooks.sh" retry-invoice "$iid"
                ;;
            6) "$ADMIN_DIR/webhooks.sh" test-receiver 9000 || true ;;
            0|q) return 0 ;;
            *) log_warn "$(t common.invalid_choice "$ch")" ;;
        esac
    done
}

menu_db() {
    while true; do
        printf '\n%s%s%s\n' "$C_CYAN" "$(t menu.db.title)" "$C_RESET"
        tln menu.db.i1
        tln menu.db.i2
        tln menu.db.i3
        tln menu.db.i4
        tln menu.back
        t menu.select
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/db.sh" stats ;;
            2) run_interactive_safe "$ADMIN_DIR/db.sh" audit-invariants ;;
            3) run_interactive_safe "$ADMIN_DIR/db.sh" backup ;;
            4) "$ADMIN_DIR/db.sh" shell || true ;;
            0|q) return 0 ;;
            *) log_warn "$(t common.invalid_choice "$ch")" ;;
        esac
    done
}

menu_dev() {
    while true; do
        printf '\n%s%s%s\n' "$C_CYAN" "$(t menu.dev.title)" "$C_RESET"
        tln menu.dev.i1
        tln menu.dev.i2
        tln menu.dev.i3
        tln menu.back
        t menu.select
        local ch=""
        IFS= read -r ch || return 0
        case "$ch" in
            1) run_interactive_safe "$ADMIN_DIR/dev.sh" check ;;
            2) run_interactive_safe "$ADMIN_DIR/dev.sh" health-rbac ;;
            3) "$ADMIN_DIR/dev.sh" demo || true ;;
            0|q) return 0 ;;
            *) log_warn "$(t common.invalid_choice "$ch")" ;;
        esac
    done
}

prompt_first_run_language() {
    if i18n_has_explicit_lang; then
        return 0
    fi
    printf '\n'
    t lang.first_run_prompt
    local ans=""
    IFS= read -r ans || return 0
    case "${ans,,}" in
        1|ru|рус|русский) i18n_save_lang ru ;;
        2|en|eng|english) i18n_save_lang en ;;
        "")               i18n_save_lang "$ADMIN_ACTIVE_LANG" ;;
        *)                log_warn "$(t common.invalid_choice "$ans")" ;;
    esac
}

interactive_main_menu() {
    load_env 1
    prompt_first_run_language
    while true; do
        local net_badge="$MONERO_NETWORK"
        if [[ "$MONERO_NETWORK" == "mainnet" ]]; then
            net_badge="${C_RED}[MAINNET]${C_RESET}"
        else
            net_badge="${C_GREEN}[${MONERO_NETWORK^^}]${C_RESET}"
        fi
        printf '\n%s====================================================================%s\n' "$C_BOLD" "$C_RESET"
        printf '  %s%s%s  %s  mode=%s\n' "$C_BOLD" "$(t menu.title)" "$C_RESET" "$net_badge" "$WALLET_MODE"
        tln menu.env_line "$ACTIVE_ENV_FILE" "$GATEWAY_BASE_URL" "${ADMIN_ACTIVE_LANG^^}"
        printf '%s====================================================================%s\n' "$C_BOLD" "$C_RESET"
        tln menu.item.service
        tln menu.item.config
        tln menu.item.wallet
        tln menu.item.invoices
        tln menu.item.webhooks
        tln menu.item.db
        tln menu.item.dev
        tln menu.item.guide
        tln menu.item.lang
        tln menu.item.exit
        t menu.select
        local choice=""
        IFS= read -r choice || return 0
        case "${choice,,}" in
            1) menu_service ;;
            2) menu_config ;;
            3) menu_wallet ;;
            4) menu_invoices ;;
            5) menu_webhooks ;;
            6) menu_db ;;
            7) menu_dev ;;
            g) cmd_guide || true ;;
            l)
                if [[ "$ADMIN_ACTIVE_LANG" == "ru" ]]; then
                    i18n_save_lang en
                else
                    i18n_save_lang ru
                fi
                log_info "$(t lang.saved "$ADMIN_ACTIVE_LANG" "$(i18n_state_file)")"
                ;;
            0|q|exit) return 0 ;;
            *) log_warn "$(t common.invalid_choice "$choice")" ;;
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
