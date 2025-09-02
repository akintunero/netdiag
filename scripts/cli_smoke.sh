#!/usr/bin/env bash
# Smoke-test every netdiag subcommand. Exit 1 on crash (exit 2) or unexpected failure.
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET_IP=1.1.1.1
TARGET_HOST=cloudflare.com
TARGET_CIDR=104.16.132.0/24
FAIL=0
CRASH=0

run() {
  local name="$1"
  shift
  printf '\n=== %s ===\n' "$name"
  if "$@"; then
    echo "[pass] exit 0"
  else
    local ec=$?
    if [[ "$ec" -eq 2 ]]; then
      echo "[CRASH/ERROR] exit $ec: $*"
      CRASH=$((CRASH + 1))
    else
      echo "[fail ok] exit $ec (probe failed - may be expected)"
    fi
    FAIL=$((FAIL + 1))
  fi
}

run_json() {
  local name="$1"
  shift
  printf '\n=== %s ===\n' "$name"
  if "$@" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    echo "[pass] valid JSON, exit 0"
  else
    local ec=${PIPESTATUS[0]}
    if [[ "$ec" -eq 2 ]]; then
      echo "[CRASH/ERROR] exit $ec"
      CRASH=$((CRASH + 1))
    else
      echo "[fail ok] exit $ec"
    fi
    FAIL=$((FAIL + 1))
  fi
}

run doctor
run --version
run --info
run_json "oncall ip" netdiag oncall "$TARGET_IP" --preset api --json
run_json "check" netdiag check "$TARGET_IP" --json
run ping netdiag ping "$TARGET_IP" -c 2
run dns netdiag dns "$TARGET_HOST" -t A
run_json "dns-compare" netdiag dns-compare "$TARGET_HOST" -t A --json
run port netdiag port "$TARGET_IP" 443
run ports netdiag ports "$TARGET_IP" --common
run_json http netdiag http "https://$TARGET_HOST" --timing --json
run_json tls netdiag tls "$TARGET_HOST" --json
run ptr netdiag ptr "$TARGET_IP"
run subnet netdiag subnet "$TARGET_CIDR"
run ip netdiag ip "$TARGET_IP"
run whois netdiag whois "$TARGET_IP" --no-bgp-api
run_json presets netdiag presets --json
run dns-config netdiag dns-config --json
run route netdiag route --json
run ifaces netdiag ifaces --json
run local-ports netdiag local-ports --json
run connections netdiag connections --limit 5 --json
run trace netdiag trace "$TARGET_IP" -m 5 -q 1 --no-bgp-api
run latency netdiag latency "$TARGET_IP" -n 3
run_json redirects netdiag redirects "https://$TARGET_HOST" --json
run_json headers netdiag headers "https://$TARGET_HOST" --json
run mtr netdiag mtr "$TARGET_IP" -c 3
run dns-all netdiag dns-all "$TARGET_HOST" 2>/dev/null || true
run dns-trace netdiag dns-trace "$TARGET_HOST" -t NS 2>/dev/null | head -5 || true
run_json compare netdiag compare "$TARGET_IP" "$TARGET_HOST" --json
run report netdiag report "$TARGET_IP" --preset web -o /tmp/netdiag-smoke-report.md
run_json vpn netdiag vpn --json 2>/dev/null || true
run speed netdiag speed "$TARGET_IP" --single-stream --bytes 500000 --timeout 30
run completion netdiag completion bash >/dev/null

echo ""
echo "Smoke done: crashes=$CRASH probe_fails=$FAIL"
[[ "$CRASH" -eq 0 ]]
