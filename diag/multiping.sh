#!/usr/bin/env bash
set -u

# Description: run N single-probe pings to a host and count results.
# Default behavior uses a 500ms timeout and 1 packet per attempt.
# Useful for network diagnostics (e.g. ECMP) where different paths may behave differently.
#
# Usage:
#   ./multiping.sh <host> <count>
#   ./multiping.sh -h <host> -c <count> [-t <timeout_ms>] [-i <interval_ms>]
#
# Examples:
#   ./multiping.sh 192.168.1.1 10
#   ./multiping.sh -h 8.8.8.8 -c 100 -t 300 -i 20
#
# Output:
#   [10:00:00] Attempt 1: SUCCESS
#   [10:00:01] Attempt 2: FAILED

TARGET=""
COUNT=""
TIMEOUT_MS=500
INTERVAL_MS=0

SUCCESS=0
FAILED=0

die() {
  echo "Error: $*" >&2
  exit 2
}

usage() {
  cat >&2 <<'EOF'
Usage:
  multiping.sh <host> <count>
  multiping.sh -h <host> -c <count> [-t <timeout_ms>] [-i <interval_ms>]

Options:
  -h host         Target host/IP
  -c count        Number of attempts (positive integer)
  -t timeout_ms   Timeout per attempt in milliseconds (default: 500)
  -i interval_ms  Sleep between attempts in milliseconds (default: 0)
EOF
  exit 2
}

is_pos_int() { [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]; }
is_nonneg_int() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

# Parse args (supports both positional and flags for backwards compatibility).
if [[ $# -eq 2 && "${1:-}" != -* && "${2:-}" != -* ]]; then
  TARGET="$1"
  COUNT="$2"
else
  while getopts ":h:c:t:i:" opt; do
    case "$opt" in
      h) TARGET="$OPTARG" ;;
      c) COUNT="$OPTARG" ;;
      t) TIMEOUT_MS="$OPTARG" ;;
      i) INTERVAL_MS="$OPTARG" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  [[ $# -eq 0 ]] || usage
fi

[[ -n "$TARGET" ]] || usage
[[ -n "$COUNT" ]] || usage
is_pos_int "$COUNT" || die "'$COUNT' is not a positive integer"
is_pos_int "$TIMEOUT_MS" || die "'$TIMEOUT_MS' is not a positive integer"
is_nonneg_int "$INTERVAL_MS" || die "'$INTERVAL_MS' is not a non-negative integer"

has_cmd() { command -v "$1" >/dev/null 2>&1; }

sleep_ms() {
  local ms="$1"
  [[ "$ms" -gt 0 ]] || return 0
  # Important: avoid external deps; awk is widely available on macOS/Linux.
  awk -v ms="$ms" 'BEGIN{ printf "%.3f\n", (ms/1000) }' | {
    read -r sec
    sleep "$sec"
  }
}

ping_once() {
  local host="$1"
  local timeout_ms="$2"

  if has_cmd fping; then
    # fping timeout is in ms.
    fping -t "$timeout_ms" -c 1 "$host" >/dev/null 2>&1
    return $?
  fi

  # Fallback to system ping (platform differences):
  # - Linux: ping -W <seconds> (per-packet timeout), -c 1.
  # - macOS/BSD: ping -t <ttl> is NOT timeout; but -W exists on macOS (ms) for some versions.
  # We'll do a best-effort approach:
  local os
  os="$(uname -s 2>/dev/null || true)"
  case "$os" in
    Linux)
      local timeout_s=$(( (timeout_ms + 999) / 1000 ))
      ping -c 1 -W "$timeout_s" "$host" >/dev/null 2>&1
      ;;
    *)
      # macOS: try -W <timeout_ms> first; if not supported, run without and rely on system default.
      if ping -c 1 -W "$timeout_ms" "$host" >/dev/null 2>&1; then
        return 0
      fi
      ping -c 1 "$host" >/dev/null 2>&1
      ;;
  esac
}

if [[ -t 1 ]]; then
  GREEN=$'\033[32m'
  RED=$'\033[31m'
  DIM=$'\033[2m'
  RESET=$'\033[0m'
else
  GREEN=""; RED=""; DIM=""; RESET=""
fi

echo "--- Starting multiping for ${TARGET} (${COUNT} attempts, timeout ${TIMEOUT_MS}ms) ---"

for ((i=1; i<=COUNT; i++)); do
  if ping_once "$TARGET" "$TIMEOUT_MS"; then
    echo "[$(date +%H:%M:%S)] Attempt $i: ${GREEN}SUCCESS${RESET}"
    ((SUCCESS++))
  else
    echo "[$(date +%H:%M:%S)] Attempt $i: ${RED}FAILED${RESET}"
    ((FAILED++))
  fi

  # Important: small interval can reduce burstiness on flaky links.
  sleep_ms "$INTERVAL_MS"
done

PERCENT_INT=$(( 100 * SUCCESS / COUNT ))
PERCENT_FLOAT="$(awk -v ok="$SUCCESS" -v total="$COUNT" 'BEGIN{ printf "%.1f", (ok*100.0/total) }')"

echo "---------------------------------------"
echo "Summary for $TARGET:"
echo "Sent:            $COUNT"
echo "Success:         $SUCCESS"
echo "Lost:            $FAILED"
echo "Success rate:    ${PERCENT_FLOAT}% ${DIM}(int ${PERCENT_INT}%)${RESET}"
echo "---------------------------------------"

# Exit non-zero if there were any losses (useful for automation).
[[ "$FAILED" -eq 0 ]] && exit 0 || exit 1
