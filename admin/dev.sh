#!/usr/bin/env bash
# ==============================================================================
# xmr-gateway Admin Suite — Developer & Live Verification Module (admin/dev.sh)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=admin/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    cat <<'EOF'
Usage: ./admin.sh dev <command> [options]

Commands:
  check          Run cargo fmt --check, cargo clippy -D warnings, and cargo test --locked --all-targets
  health-rbac    Verify live GET /health RBAC & telemetry-hiding matrix (AUDIT-002) (--json)
  demo           Launch ./demo-stagenet.sh interactive Stagenet demo
  help           Show this help message
EOF
}

cmd_check() {
    require_cmd cargo
    log_step "1/3 Running cargo fmt --all -- --check..."
    (cd "$REPO_ROOT" && cargo fmt --all -- --check)
    log_step "2/3 Running cargo clippy --locked --all-targets --all-features -- -D warnings..."
    (cd "$REPO_ROOT" && cargo clippy --locked --all-targets --all-features -- -D warnings)
    log_step "3/3 Running cargo test --locked --all-targets..."
    (cd "$REPO_ROOT" && cargo test --locked --all-targets)
    log_info "All Rust fmt, clippy, and test checks passed."
}

# Helper calling /health with an arbitrary header name/value via curl --config - (zero argv leak)
health_probe_custom() {
    local hdr_name="$1"
    local hdr_val="$2"
    local tmp_out
    tmp_out="$(mktemp)"
    chmod 600 "$tmp_out"
    local cfg=""
    if [[ -n "$hdr_name" ]]; then
        cfg="header = \"${hdr_name}: $(curl_cfg_escape "$hdr_val")\""
    fi
    local code rc=0
    code="$(printf '%s\n' "$cfg" | curl -sS --connect-timeout 5 --max-time 10 -o "$tmp_out" -w '%{http_code}' --config - "${GATEWAY_BASE_URL}/health")" || rc=$?
    local body
    body="$(cat "$tmp_out" 2>/dev/null || true)"
    rm -f "$tmp_out"
    printf '%s\n%s\n' "$code" "$body"
    return "$rc"
}

cmd_health_rbac() {
    load_env
    require_cmd curl
    require_cmd python3

    local anon_out api_out invalid_out op_out="" op_via_api_out="" merch_in_op_out=""
    anon_out="$(health_probe_custom "" "")" || die "Cannot reach ${GATEWAY_BASE_URL}/health"
    api_out="$(health_probe_custom "X-API-Key" "$API_SECRET_KEY")"
    invalid_out="$(health_probe_custom "X-API-Key" "invalid-key-probe-0123456789abcdef")"

    if [[ -n "${OPERATOR_API_KEY:-}" ]]; then
        op_out="$(health_probe_custom "X-Operator-Key" "$OPERATOR_API_KEY")"
        op_via_api_out="$(health_probe_custom "X-API-Key" "$OPERATOR_API_KEY")"
        merch_in_op_out="$(health_probe_custom "X-Operator-Key" "$API_SECRET_KEY")"
    else
        merch_in_op_out="$(health_probe_custom "X-Operator-Key" "$API_SECRET_KEY")"
    fi

    HRBAC_ANON="$anon_out" \
    HRBAC_API="$api_out" \
    HRBAC_INVALID="$invalid_out" \
    HRBAC_OP="$op_out" \
    HRBAC_OP_VIA_API="$op_via_api_out" \
    HRBAC_MERCH_IN_OP="$merch_in_op_out" \
    HRBAC_HAS_OP="$([[ -n "${OPERATOR_API_KEY:-}" ]] && echo 1 || echo 0)" \
    HRBAC_JSON="$ADMIN_JSON" \
    python3 - <<'PYEOF'
import json, os, sys

TELEMETRY_KEYS = ("service", "version", "database", "monero_rpc", "auto_sweep_enabled")

def parse_probe(raw):
    lines = raw.split("\n", 1)
    code = lines[0].strip()
    body_str = lines[1].strip() if len(lines) > 1 else ""
    try:
        body = json.loads(body_str)
    except Exception:
        body = None
    return code, body, body_str

results = []
failed = 0

def verify(name, raw, expect_telemetry):
    global failed
    code, body, body_str = parse_probe(raw)
    if code not in ("200", "503") or not isinstance(body, dict) or "status" not in body:
        results.append({"case": name, "ok": False, "http": code, "detail": f"Unexpected response: {body_str[:120]}"})
        failed += 1
        return
    present = [k for k in TELEMETRY_KEYS if k in body]
    if expect_telemetry:
        ok = ("service" in body and "monero_rpc" in body)
        detail = f"HTTP {code}, status={body.get('status')}, telemetry_fields={len(present)}"
    else:
        ok = (len(present) == 0)
        detail = f"HTTP {code}, status={body.get('status')}, leaked={present}"
    results.append({"case": name, "ok": ok, "http": code, "detail": detail})
    if not ok:
        failed += 1

has_op = os.environ.get("HRBAC_HAS_OP") == "1"
verify("unauthenticated", os.environ["HRBAC_ANON"], False)
verify("invalid_x_api_key", os.environ["HRBAC_INVALID"], False)
verify("merchant_x_api_key", os.environ["HRBAC_API"], True)

if has_op:
    verify("operator_x_operator_key", os.environ["HRBAC_OP"], True)
    verify("operator_x_api_key", os.environ["HRBAC_OP_VIA_API"], True)
    verify("merchant_in_x_operator_key_rejected", os.environ["HRBAC_MERCH_IN_OP"], False)
else:
    verify("single_tenant_x_operator_key_fallback", os.environ["HRBAC_MERCH_IN_OP"], True)

if os.environ.get("HRBAC_JSON") == "1":
    print(json.dumps({"ok": failed == 0, "operator_key_configured": has_op, "results": results}, indent=2))
else:
    print(f"=== Live GET /health RBAC Matrix (OPERATOR_API_KEY={'set' if has_op else 'unset'}) ===")
    for r in results:
        tag = "PASS" if r["ok"] else "FAIL"
        print(f"  [{tag}] {r['case']:<38s} {r['detail']}")

sys.exit(0 if failed == 0 else 1)
PYEOF
}

cmd_demo() {
    log_step "Launching ./demo-stagenet.sh..."
    exec "$REPO_ROOT/demo-stagenet.sh" "$@"
}

main() {
    parse_global_flags "$@"
    set -- "${ADMIN_REST_ARGS[@]}"
    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        check)       cmd_check "$@" ;;
        health-rbac) cmd_health_rbac "$@" ;;
        demo)        cmd_demo "$@" ;;
        help|-h|--help) usage ;;
        *)           die "Unknown dev command: '$cmd'. Run './admin.sh dev help'." ;;
    esac
}

main "$@"
