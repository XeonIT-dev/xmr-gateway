#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Fail-Closed Production Installer (scripts/install.sh)
# ==============================================================================
# Installs xmr-gateway from official GitHub Releases (XeonIT-dev/xmr-gateway)
# via native .deb, .rpm, or verified binary tarball with mandatory SHA256
# verification and optional fail-closed GPG signature verification.
#
# Quick usage:
#   curl -fsSL https://raw.githubusercontent.com/XeonIT-dev/xmr-gateway/main/scripts/install.sh -o install.sh
#   bash install.sh --dry-run
#   sudo bash install.sh
# ==============================================================================

set -euo pipefail
umask 077

REPO_SLUG="${XMR_GATEWAY_REPO:-XeonIT-dev/xmr-gateway}"
METHOD="auto"
VERSION="latest"
PREFIX="/opt/xmr-gateway"
GPG_KEY=""
REQUIRE_GPG=0
DRY_RUN=0
INSTALL_LANG=""
TMP_DIR=""

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

detect_lang() {
    if [[ -n "$INSTALL_LANG" ]]; then
        case "${INSTALL_LANG,,}" in
            en|ru) INSTALL_LANG="${INSTALL_LANG,,}" ;;
            *) echo "[ERR ] Invalid --lang '${INSTALL_LANG}': expected 'en' or 'ru'." >&2; exit 1 ;;
        esac
        return 0
    fi
    local loc="${LC_ALL:-${LANG:-}}"
    if [[ "${loc,,}" == ru* ]]; then
        INSTALL_LANG="ru"
    else
        INSTALL_LANG="en"
    fi
}

msg() {
    local en="$1"
    local ru="$2"
    if [[ "$INSTALL_LANG" == "ru" ]]; then
        printf '%s\n' "$ru"
    else
        printf '%s\n' "$en"
    fi
}

log_info() { printf '\033[1;32m[INFO]\033[0m %s\n' "$*" >&2; }
log_warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
log_err()  { printf '\033[1;31m[ERR ]\033[0m %s\n' "$*" >&2; }
die()      { log_err "$*"; exit 1; }

usage() {
    if [[ "$INSTALL_LANG" == "ru" ]]; then
        cat <<'EOF'
Безопасный установщик xmr-gateway (scripts/install.sh)

Использование:
  scripts/install.sh [ОПЦИИ]

Опции:
  --method auto|deb|rpm|tarball   Способ установки (по умолчанию: auto)
  --version latest|vX.Y.Z         Версия релиза GitHub (по умолчанию: latest)
  --prefix PATH                   Каталог для tarball-установки (по умолчанию: /opt/xmr-gateway)
  --gpg-key PATH_OR_URL           Путь или URL публичного GPG-ключа для проверки SHA256SUMS.asc
  --require-gpg                   Обязательная fail-closed проверка GPG-подписи SHA256SUMS.asc
  --dry-run                       Показать точный план без скачивания и изменений в системе
  --lang en|ru                    Язык вывода (по умолчанию: системная локаль)
  -h, --help                      Показать эту справку
EOF
    else
        cat <<'EOF'
xmr-gateway Fail-Closed Installer (scripts/install.sh)

Usage:
  scripts/install.sh [OPTIONS]

Options:
  --method auto|deb|rpm|tarball   Installation method (default: auto)
  --version latest|vX.Y.Z         GitHub Release version tag (default: latest)
  --prefix PATH                   Target directory for tarball installs (default: /opt/xmr-gateway)
  --gpg-key PATH_OR_URL           Local path or HTTPS URL of GPG public key for SHA256SUMS.asc
  --require-gpg                   Enforce fail-closed GPG verification of SHA256SUMS.asc
  --dry-run                       Print full install & verification plan without modifying the host
  --lang en|ru                    Output language (default: system locale)
  -h, --help                      Show this help message
EOF
    fi
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command '$1' was not found in PATH."
}

validate_version() {
    local v="$1"
    if [[ "$v" == "latest" ]]; then
        return 0
    fi
    if [[ ! "$v" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
        die "$(msg "Invalid --version '${v}': must be 'latest' or semantic tag like 'v0.1.1'." "Некорректная версия --version '${v}': ожидается 'latest' или тег вида 'v0.1.1'.")"
    fi
}

validate_prefix() {
    local p="$1"
    if [[ -z "$p" || "$p" != /* || "$p" == "/" || "$p" == *".."* ]]; then
        die "$(msg "Invalid --prefix '${p}': must be a safe non-root absolute path." "Некорректный --prefix '${p}': требуется безопасный абсолютный путь (не '/').")"
    fi
}

detect_arch() {
    local raw
    raw="$(uname -m)"
    case "$raw" in
        x86_64|amd64)  ARCH="x86_64";  DEB_ARCH="amd64"; RPM_ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64"; DEB_ARCH="arm64"; RPM_ARCH="aarch64" ;;
        *) die "$(msg "Unsupported CPU architecture: ${raw} (supported: x86_64, aarch64)." "Неподдерживаемая архитектура CPU: ${raw} (поддерживаются: x86_64, aarch64).")" ;;
    esac
}

detect_method() {
    case "$METHOD" in
        deb|rpm|tarball) return 0 ;;
        auto)
            if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
                METHOD="deb"
            elif command -v dnf >/dev/null 2>&1 || command -v rpm >/dev/null 2>&1; then
                METHOD="rpm"
            else
                METHOD="tarball"
            fi
            ;;
        *)
            die "$(msg "Invalid --method '${METHOD}': expected auto, deb, rpm, or tarball." "Некорректный --method '${METHOD}': ожидается auto, deb, rpm или tarball.")"
            ;;
    esac
}

resolve_latest_tag() {
    require_cmd curl
    local api_url="https://api.github.com/repos/${REPO_SLUG}/releases/latest"
    local tag=""
    tag="$(curl -fsSL -H "Accept: application/vnd.github+json" "$api_url" \
        | sed -n 's/^[[:space:]]*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n 1)"
    [[ -n "$tag" ]] || die "$(msg "Failed to resolve latest release tag from ${api_url}." "Не удалось получить последний тег релиза из ${api_url}.")"
    validate_version "$tag"
    printf '%s\n' "$tag"
}

compute_artifact_name() {
    local tag="$1"
    local ver="${tag#v}"
    case "$METHOD" in
        deb)     printf 'xmr-gateway_%s_%s.deb\n' "$ver" "$DEB_ARCH" ;;
        rpm)     printf 'xmr-gateway-%s-1.%s.rpm\n' "$ver" "$RPM_ARCH" ;;
        tarball) printf 'xmr-gateway-%s-linux-%s.tar.gz\n' "$tag" "$ARCH" ;;
    esac
}

verify_sha256() {
    local sums_file="$1"
    local artifact_name="$2"
    local expected
    expected="$(awk -v f="$artifact_name" '$2 == f || $2 == ("*" f) { print $1; exit }' "$sums_file")"
    if [[ ! "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
        die "$(msg "SHA256 entry for '${artifact_name}' not found in SHA256SUMS." "Запись SHA256 для '${artifact_name}' не найдена в SHA256SUMS.")"
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$(dirname "$sums_file")" && printf '%s  %s\n' "$expected" "$artifact_name" | sha256sum -c -)
    elif command -v shasum >/dev/null 2>&1; then
        (cd "$(dirname "$sums_file")" && printf '%s  %s\n' "$expected" "$artifact_name" | shasum -a 256 -c -)
    else
        die "Neither sha256sum nor shasum found."
    fi
}

verify_gpg_signature() {
    local sums_file="$1"
    local sig_file="$2"
    require_cmd gpg

    local gnupghome="$TMP_DIR/gnupg"
    mkdir -p "$gnupghome"
    chmod 700 "$gnupghome"

    if [[ -n "$GPG_KEY" ]]; then
        if [[ -f "$GPG_KEY" ]]; then
            gpg --homedir "$gnupghome" --batch --import "$GPG_KEY" >/dev/null 2>&1 \
                || die "Failed to import GPG public key from file: $GPG_KEY"
        elif [[ "$GPG_KEY" == https://* ]]; then
            curl -fsSL "$GPG_KEY" -o "$TMP_DIR/release-key.asc"
            gpg --homedir "$gnupghome" --batch --import "$TMP_DIR/release-key.asc" >/dev/null 2>&1 \
                || die "Failed to import GPG public key from URL: $GPG_KEY"
        else
            die "Invalid --gpg-key '${GPG_KEY}': expected local file path or https:// URL."
        fi
    else
        # Fallback: copy user's existing keyring read-only if --require-gpg used without --gpg-key
        if [[ -d "${HOME:-}/.gnupg" ]]; then
            cp -a "${HOME}/.gnupg/." "$gnupghome/" 2>/dev/null || true
            chmod 700 "$gnupghome"
        fi
    fi

    if ! gpg --homedir "$gnupghome" --batch --verify "$sig_file" "$sums_file"; then
        die "$(msg "GPG signature verification FAILED for SHA256SUMS.asc! Aborting installation." "Проверка GPG-подписи SHA256SUMS.asc ПРОВАЛЕНА! Установка прервана.")"
    fi
    log_info "$(msg "GPG signature verified for SHA256SUMS." "GPG-подпись SHA256SUMS успешно проверена.")"
}

run_as_root() {
    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        die "$(msg "Root privileges (or sudo) required for system installation." "Для системной установки требуются права root (или sudo).")"
    fi
}

install_tarball() {
    local tarball_path="$1"
    local extract_dir="$TMP_DIR/extracted"
    mkdir -p "$extract_dir"
    tar -xzf "$tarball_path" -C "$extract_dir"

    local top_dir
    top_dir="$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
    [[ -n "$top_dir" && -x "$top_dir/xmr-gateway" ]] || die "Invalid tarball layout: missing xmr-gateway binary."

    local parent_dir
    parent_dir="$(dirname "$PREFIX")"
    if [[ "$(id -u)" -ne 0 ]] && { [[ -d "$PREFIX" && -w "$PREFIX" ]] || [[ -d "$parent_dir" && -w "$parent_dir" ]]; }; then
        install -d -m 0755 "$PREFIX" "$PREFIX/admin" "$PREFIX/admin/lib" "$PREFIX/admin/i18n"
        cp -a "$top_dir/." "$PREFIX/"
        chmod 0755 "$PREFIX/xmr-gateway" "$PREFIX/admin.sh"
        if [[ -f "$PREFIX/start.sh" ]]; then
            chmod 0755 "$PREFIX/start.sh"
        fi
        if [[ -w /usr/local/bin ]]; then
            ln -sfn "$PREFIX/xmr-gateway" /usr/local/bin/xmr-gateway
            ln -sfn "$PREFIX/admin.sh" /usr/local/bin/xmr-gateway-admin
        fi
        log_info "$(msg "Installed tarball into ${PREFIX}." "Архив установлен в ${PREFIX}.")"
    else
        run_as_root install -d -m 0755 "$PREFIX" "$PREFIX/admin" "$PREFIX/admin/lib" "$PREFIX/admin/i18n"
        run_as_root cp -a "$top_dir/." "$PREFIX/"
        run_as_root chmod 0755 "$PREFIX/xmr-gateway" "$PREFIX/admin.sh"
        if [[ -f "$PREFIX/start.sh" ]]; then
            run_as_root chmod 0755 "$PREFIX/start.sh"
        fi
        run_as_root ln -sfn "$PREFIX/xmr-gateway" /usr/local/bin/xmr-gateway
        run_as_root ln -sfn "$PREFIX/admin.sh" /usr/local/bin/xmr-gateway-admin
        log_info "$(msg "Installed tarball into ${PREFIX} and linked /usr/local/bin/xmr-gateway{,-admin}." "Архив установлен в ${PREFIX}, созданы ссылки /usr/local/bin/xmr-gateway{,-admin}.")"
    fi
}

print_next_steps() {
    if [[ "$METHOD" == "tarball" ]]; then
        if [[ "$INSTALL_LANG" == "ru" ]]; then
            cat <<EOF

==============================================================================
Установка xmr-gateway (tarball -> ${PREFIX}) завершена! Что сделать дальше:
  1. Создайте 0600 конфигурацию из шаблона:
       cd "${PREFIX}" && cp .env.example .env && chmod 600 .env
  2. Сгенерируйте сильные раздельные секреты (включая OPERATOR_API_KEY):
       "${PREFIX}/admin.sh" --env "${PREFIX}/.env" config rotate-keys all
  3. Отредактируйте ${PREFIX}/.env (WALLET_MODE, MONERO_NETWORK, MONERO_VIEW_ONLY_ADDRESS/KEY
     либо COLD_WALLET_ADDRESS для hot_wallet; MONERO_REMOTE_NODE подберётся по сети автоматически).
  4. Установите официальный Monero CLI с SHA256-проверкой:
       "${PREFIX}/admin.sh" service setup-rpc
  5. Создайте кошелёк (и 0600 файл пароля gateway_wallet.password):
       "${PREFIX}/admin.sh" --env "${PREFIX}/.env" wallet create-view-only
       # или для hot auto-sweep режима:
       "${PREFIX}/admin.sh" --env "${PREFIX}/.env" wallet create-hot
  6. Проверьте конфигурацию и запустите сервисы:
       "${PREFIX}/admin.sh" --env "${PREFIX}/.env" config doctor
       "${PREFIX}/admin.sh" --env "${PREFIX}/.env" service start
==============================================================================
EOF
        else
            cat <<EOF

==============================================================================
xmr-gateway tarball installation (${PREFIX}) complete! Next steps:
  1. Create a 0600 environment file from the template:
       cd "${PREFIX}" && cp .env.example .env && chmod 600 .env
  2. Generate fresh distinct secrets (including OPERATOR_API_KEY):
       "${PREFIX}/admin.sh" --env "${PREFIX}/.env" config rotate-keys all
  3. Edit ${PREFIX}/.env (WALLET_MODE, MONERO_NETWORK, MONERO_VIEW_ONLY_ADDRESS/KEY
     or COLD_WALLET_ADDRESS for hot_wallet; MONERO_REMOTE_NODE auto-selects per network).
  4. Install SHA256-verified official Monero CLI binaries:
       "${PREFIX}/admin.sh" service setup-rpc
  5. Initialize the wallet (automatically creates 0600 gateway_wallet.password):
       "${PREFIX}/admin.sh" --env "${PREFIX}/.env" wallet create-view-only
       # or for hot auto-sweep mode:
       "${PREFIX}/admin.sh" --env "${PREFIX}/.env" wallet create-hot
  6. Run fail-closed diagnostics and start services:
       "${PREFIX}/admin.sh" --env "${PREFIX}/.env" config doctor
       "${PREFIX}/admin.sh" --env "${PREFIX}/.env" service start
==============================================================================
EOF
        fi
        return 0
    fi

    if [[ "$INSTALL_LANG" == "ru" ]]; then
        cat <<'EOF'

==============================================================================
Установка xmr-gateway (systemd-пакет) завершена! Что сделать дальше:
  1. Сгенерируйте сильные раздельные секреты (API_SECRET_KEY != OPERATOR_API_KEY):
       sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys all
  2. Отредактируйте /etc/xmr-gateway/.env (WALLET_MODE=view_only, MONERO_NETWORK,
     MONERO_VIEW_ONLY_ADDRESS/KEY; MONERO_REMOTE_NODE подберётся по сети автоматически).
  3. Установите SHA256-проверенный monero-wallet-rpc в /usr/local/bin/:
       sudo xmr-gateway-admin service setup-rpc
  4. Создайте кошелёк и 0600 файл пароля gateway_wallet.password в /var/lib/xmr-gateway/wallet/:
       sudo xmr-gateway-admin --env /etc/xmr-gateway/.env wallet create-view-only
       # или для hot_wallet режима:
       sudo xmr-gateway-admin --env /etc/xmr-gateway/.env wallet create-hot
  5. Проверьте безопасность и права:
       sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config doctor
  6. Включите и запустите сервисы:
       sudo systemctl enable --now monero-wallet-rpc.service xmr-gateway.service
       sudo systemctl enable --now xmr-gateway-backup.timer   # ежедневный горячий бэкап
==============================================================================
EOF
    else
        cat <<'EOF'

==============================================================================
xmr-gateway systemd package installation complete! Next steps:
  1. Generate fresh distinct secrets (API_SECRET_KEY != OPERATOR_API_KEY):
       sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config rotate-keys all
  2. Configure /etc/xmr-gateway/.env (WALLET_MODE=view_only, MONERO_NETWORK,
     MONERO_VIEW_ONLY_ADDRESS/KEY; MONERO_REMOTE_NODE auto-selects per network).
  3. Install SHA256-verified official monero-wallet-rpc into /usr/local/bin/:
       sudo xmr-gateway-admin service setup-rpc
  4. Initialize the wallet and 0600 gateway_wallet.password in /var/lib/xmr-gateway/wallet/:
       sudo xmr-gateway-admin --env /etc/xmr-gateway/.env wallet create-view-only
       # or for hot_wallet mode:
       sudo xmr-gateway-admin --env /etc/xmr-gateway/.env wallet create-hot
  5. Run the fail-closed security check:
       sudo xmr-gateway-admin --env /etc/xmr-gateway/.env config doctor
  6. Enable and start services:
       sudo systemctl enable --now monero-wallet-rpc.service xmr-gateway.service
       sudo systemctl enable --now xmr-gateway-backup.timer   # daily hot SQLite backup
==============================================================================
EOF
    fi
}

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --method)      [[ $# -ge 2 ]] || die "--method requires a value."; METHOD="$2"; shift 2 ;;
            --method=*)    METHOD="${1#*=}"; shift ;;
            --version)     [[ $# -ge 2 ]] || die "--version requires a value."; VERSION="$2"; shift 2 ;;
            --version=*)   VERSION="${1#*=}"; shift ;;
            --prefix)      [[ $# -ge 2 ]] || die "--prefix requires a path."; PREFIX="$2"; shift 2 ;;
            --prefix=*)    PREFIX="${1#*=}"; shift ;;
            --gpg-key)     [[ $# -ge 2 ]] || die "--gpg-key requires a path or URL."; GPG_KEY="$2"; REQUIRE_GPG=1; shift 2 ;;
            --gpg-key=*)   GPG_KEY="${1#*=}"; REQUIRE_GPG=1; shift ;;
            --require-gpg) REQUIRE_GPG=1; shift ;;
            --dry-run)     DRY_RUN=1; shift ;;
            --lang)        [[ $# -ge 2 ]] || die "--lang requires 'en' or 'ru'."; INSTALL_LANG="$2"; shift 2 ;;
            --lang=*)      INSTALL_LANG="${1#*=}"; shift ;;
            -h|--help)     detect_lang; usage; exit 0 ;;
            *)             detect_lang; die "Unknown option: $1" ;;
        esac
    done

    detect_lang
    validate_version "$VERSION"
    validate_prefix "$PREFIX"
    detect_arch
    detect_method

    local resolved_tag="$VERSION"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        local sample_tag="$VERSION"
        [[ "$sample_tag" == "latest" ]] && sample_tag="vX.Y.Z"
        local sample_artifact
        sample_artifact="$(compute_artifact_name "$sample_tag")"
        local base_url="https://github.com/${REPO_SLUG}/releases/download/${sample_tag}"
        printf '=== xmr-gateway Installer Dry-Run Plan ===\n'
        printf '  Repository      : %s\n' "$REPO_SLUG"
        printf '  Architecture    : %s (deb=%s, rpm=%s)\n' "$ARCH" "$DEB_ARCH" "$RPM_ARCH"
        printf '  Method          : %s\n' "$METHOD"
        printf '  Version         : %s\n' "$VERSION"
        printf '  Artifact        : %s\n' "$sample_artifact"
        printf '  Artifact URL    : %s/%s\n' "$base_url" "$sample_artifact"
        printf '  Checksums URL   : %s/SHA256SUMS\n' "$base_url"
        printf '  SHA256 Check    : MANDATORY (fail-closed)\n'
        local gpg_status="optional (enable via --require-gpg / --gpg-key)"
        if [[ "$REQUIRE_GPG" -eq 1 ]]; then
            gpg_status="REQUIRED (SHA256SUMS.asc)"
        fi
        printf '  GPG Check       : %s%s\n' "$gpg_status" "${GPG_KEY:+ [key=$GPG_KEY]}"
        if [[ "$METHOD" == "tarball" ]]; then
            printf '  Install Prefix  : %s\n' "$PREFIX"
        elif [[ "$METHOD" == "deb" ]]; then
            printf '  Install Action  : sudo apt-get install -y ./%s (or dpkg -i)\n' "$sample_artifact"
        else
            printf '  Install Action  : sudo dnf install -y ./%s (or rpm -Uvh)\n' "$sample_artifact"
        fi
        exit 0
    fi

    require_cmd curl
    if [[ "$resolved_tag" == "latest" ]]; then
        log_info "$(msg "Resolving latest release from ${REPO_SLUG}..." "Определение последнего релиза ${REPO_SLUG}...")"
        resolved_tag="$(resolve_latest_tag)"
    fi

    local artifact_name base_url
    artifact_name="$(compute_artifact_name "$resolved_tag")"
    base_url="https://github.com/${REPO_SLUG}/releases/download/${resolved_tag}"

    TMP_DIR="$(mktemp -d)"
    chmod 700 "$TMP_DIR"

    log_info "$(msg "Downloading SHA256SUMS for ${resolved_tag}..." "Загрузка SHA256SUMS для ${resolved_tag}...")"
    curl -fsSL "${base_url}/SHA256SUMS" -o "$TMP_DIR/SHA256SUMS"

    if [[ "$REQUIRE_GPG" -eq 1 ]]; then
        log_info "$(msg "Downloading SHA256SUMS.asc for GPG verification..." "Загрузка SHA256SUMS.asc для GPG-проверки...")"
        curl -fsSL "${base_url}/SHA256SUMS.asc" -o "$TMP_DIR/SHA256SUMS.asc" \
            || die "$(msg "Failed to download SHA256SUMS.asc while --require-gpg is set." "Не удалось скачать SHA256SUMS.asc при активном --require-gpg.")"
        verify_gpg_signature "$TMP_DIR/SHA256SUMS" "$TMP_DIR/SHA256SUMS.asc"
    fi

    log_info "$(msg "Downloading ${artifact_name}..." "Загрузка ${artifact_name}...")"
    curl -fSL --progress-bar "${base_url}/${artifact_name}" -o "$TMP_DIR/${artifact_name}"

    log_info "$(msg "Verifying SHA256 checksum (fail-closed)..." "Проверка контрольной суммы SHA256 (fail-closed)...")"
    verify_sha256 "$TMP_DIR/SHA256SUMS" "$artifact_name"

    case "$METHOD" in
        deb)
            if command -v apt-get >/dev/null 2>&1; then
                run_as_root apt-get install -y "$TMP_DIR/${artifact_name}"
            else
                run_as_root dpkg -i "$TMP_DIR/${artifact_name}"
            fi
            ;;
        rpm)
            if command -v dnf >/dev/null 2>&1; then
                run_as_root dnf install -y "$TMP_DIR/${artifact_name}"
            else
                run_as_root rpm -Uvh "$TMP_DIR/${artifact_name}"
            fi
            ;;
        tarball)
            install_tarball "$TMP_DIR/${artifact_name}"
            ;;
    esac

    print_next_steps
}

main "$@"
