#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Admin Suite — Pure-Bash i18n Loader (admin/lib/i18n.sh)
# ==============================================================================
# Resolution priority (strictly top to bottom):
#   1. CLI flag: --lang <en|ru> (ADMIN_CLI_LANG)
#   2. Environment variable: ADMIN_LANG
#   3. Saved state file: ${ADMIN_STATE_DIR:-$REPO_ROOT/data}/.admin_lang (0600)
#   4. System locale: LC_ALL / LANG starting with 'ru' -> ru, else en
# ==============================================================================

if [[ -n "${_XMR_ADMIN_I18N_LOADED:-}" ]]; then
    return 0
fi
_XMR_ADMIN_I18N_LOADED=1

set -euo pipefail

_I18N_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_I18N_ADMIN_DIR="$(cd "$_I18N_LIB_DIR/.." && pwd)"
_I18N_REPO_ROOT="$(cd "$_I18N_ADMIN_DIR/.." && pwd)"

# Load both dictionaries once
# shellcheck source=admin/i18n/en.sh
source "$_I18N_ADMIN_DIR/i18n/en.sh"
# shellcheck source=admin/i18n/ru.sh
source "$_I18N_ADMIN_DIR/i18n/ru.sh"

ADMIN_CLI_LANG="${ADMIN_CLI_LANG:-}"
ADMIN_ACTIVE_LANG="${ADMIN_ACTIVE_LANG:-en}"
ADMIN_LANG_SOURCE="${ADMIN_LANG_SOURCE:-locale}"

i18n_normalize_lang() {
    local raw="${1:-}"
    raw="${raw,,}"
    raw="${raw#"${raw%%[![:space:]]*}"}"
    raw="${raw%"${raw##*[![:space:]]}"}"
    case "$raw" in
        en|ru)
            printf '%s\n' "$raw"
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

i18n_state_file() {
    local state_dir="${ADMIN_STATE_DIR:-$_I18N_REPO_ROOT/data}"
    printf '%s/.admin_lang\n' "${state_dir%/}"
}

i18n_detect_locale_lang() {
    local loc="${LC_ALL:-${LANG:-}}"
    loc="${loc,,}"
    if [[ "$loc" == ru* ]]; then
        printf 'ru\n'
    else
        printf 'en\n'
    fi
}

# Resolves ADMIN_ACTIVE_LANG and ADMIN_LANG_SOURCE using the strict priority order.
# Fails closed on invalid --lang or invalid ADMIN_LANG.
i18n_init() {
    local norm=""

    # 1. CLI flag --lang
    if [[ -n "${ADMIN_CLI_LANG:-}" ]]; then
        if ! norm="$(i18n_normalize_lang "$ADMIN_CLI_LANG")"; then
            printf '[ERR ] Invalid language '\''%s'\'': expected '\''en'\'' or '\''ru'\''.\n' "$ADMIN_CLI_LANG" >&2
            return 1
        fi
        ADMIN_ACTIVE_LANG="$norm"
        ADMIN_LANG_SOURCE="flag"
        export ADMIN_ACTIVE_LANG ADMIN_LANG_SOURCE ADMIN_CLI_LANG
        return 0
    fi

    # 2. Environment variable ADMIN_LANG
    if [[ -n "${ADMIN_LANG:-}" ]]; then
        if ! norm="$(i18n_normalize_lang "$ADMIN_LANG")"; then
            printf '[ERR ] Invalid ADMIN_LANG='\''%s'\'': expected '\''en'\'' or '\''ru'\''.\n' "$ADMIN_LANG" >&2
            return 1
        fi
        ADMIN_ACTIVE_LANG="$norm"
        ADMIN_LANG_SOURCE="env"
        export ADMIN_ACTIVE_LANG ADMIN_LANG_SOURCE
        return 0
    fi

    # 3. Saved state file (.admin_lang)
    local sf
    sf="$(i18n_state_file)"
    if [[ -f "$sf" ]]; then
        local file_val=""
        IFS= read -r file_val < "$sf" || true
        if norm="$(i18n_normalize_lang "$file_val")"; then
            ADMIN_ACTIVE_LANG="$norm"
            ADMIN_LANG_SOURCE="file"
            export ADMIN_ACTIVE_LANG ADMIN_LANG_SOURCE
            return 0
        fi
    fi

    # 4. System locale fallback
    ADMIN_ACTIVE_LANG="$(i18n_detect_locale_lang)"
    ADMIN_LANG_SOURCE="locale"
    export ADMIN_ACTIVE_LANG ADMIN_LANG_SOURCE
    return 0
}

i18n_has_explicit_lang() {
    [[ "${ADMIN_LANG_SOURCE:-locale}" != "locale" ]]
}

# Persists chosen language ('en' or 'ru') to ${ADMIN_STATE_DIR:-$REPO_ROOT/data}/.admin_lang (0600)
# and updates live runtime state immediately.
i18n_save_lang() {
    local requested="$1"
    local norm=""
    if ! norm="$(i18n_normalize_lang "$requested")"; then
        printf '[ERR ] %s\n' "$(t common.invalid_lang "$requested")" >&2
        return 1
    fi

    local sf dir
    sf="$(i18n_state_file)"
    dir="$(dirname "$sf")"
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        chmod 700 "$dir"
    fi

    local tmp
    tmp="$(mktemp "$dir/.admin_lang.XXXXXX")"
    chmod 600 "$tmp"
    printf '%s\n' "$norm" > "$tmp"
    mv "$tmp" "$sf"
    chmod 600 "$sf"

    ADMIN_CLI_LANG=""
    ADMIN_ACTIVE_LANG="$norm"
    ADMIN_LANG_SOURCE="file"
    export ADMIN_CLI_LANG ADMIN_ACTIVE_LANG ADMIN_LANG_SOURCE
    return 0
}

# Translates key with optional printf arguments; falls back safely to EN then key name.
t() {
    local key="$1"
    shift || true
    local tmpl=""

    if [[ "${ADMIN_ACTIVE_LANG:-en}" == "ru" && -n "${I18N_RU[$key]+x}" ]]; then
        tmpl="${I18N_RU[$key]}"
    elif [[ -n "${I18N_EN[$key]+x}" ]]; then
        tmpl="${I18N_EN[$key]}"
    else
        tmpl="$key"
    fi

    if [[ $# -gt 0 ]]; then
        # Interpret \n escape sequences inside dictionary templates cleanly
        local rendered=""
        printf -v rendered '%b' "$tmpl"
        # shellcheck disable=SC2059
        printf -- "$rendered" "$@"
    else
        printf '%b' "$tmpl"
    fi
}

tln() {
    t "$@"
    printf '\n'
}

# Initialize immediately on source (may be re-invoked after parse_global_flags parses --lang)
i18n_init
