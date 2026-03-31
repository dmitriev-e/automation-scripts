#!/usr/bin/env bash
set -u

# Description: run N TCP connection attempts using netcat (nc) and count results.
# Useful for diagnosing reachability, firewall drops, SYN timeouts, and intermittent connectivity.
#
# Usage:
#   ./multinc.sh <host> <port> <count>
#   ./multinc.sh -h <host> -p <port> -c <count> [-t <timeout_s>] [-i <interval_ms>] [-n]
#
# Examples:
#   ./multinc.sh 10.0.0.5 443 20
#   ./multinc.sh -h example.com -p 443 -c 100 -t 1 -i 20
#   ./multinc.sh -h 10.0.0.5 -p 3306 -c 50 -t 2 -n
#
# Exit codes:
#   0: all attempts succeeded
#   1: at least one attempt failed
#   2: usage / validation error

HOST=""
PORT=""
COUNT=""
TIMEOUT_S=1
INTERVAL_MS=0
NO_DNS=0

SUCCESS=0
FAILED=0

die() {
  echo "Error: $*" >&2
  exit 2
}

usage() {
  cat >&2 <<'EOF'
Usage:
  multinc.sh <host> <port> <count>
  multinc.sh -h <host> -p <port> -c <count> [-t <timeout_s>] [-i <interval_ms>] [-n]

Options:
  -h host         Target host/IP
  -p port         TCP port (1-65535)
  -c count        Number of attempts (positive integer)
  -t timeout_s    Timeout per attempt in seconds (default: 1)
  -i interval_ms  Sleep between attempts in milliseconds (default: 0)
  -n              Do not resolve names (pass -n to nc)
EOF
  exit 2
}

is_pos_int() { [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]; }
is_nonneg_int() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

sleep_ms() {
  local ms="$1"
  [[ "$ms" -gt 0 ]] || return 0
  awk -v ms="$ms" 'BEGIN{ printf "%.3f\n", (ms/1000) }' | {
    read -r sec
    sleep "$sec"
  }
}

validate_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  [[ "$p" -ge 1 && "$p" -le 65535 ]]
}

# Parse args (supports both positional and flags for backwards compatibility).
if [[ $# -eq 3 && "${1:-}" != -* && "${2:-}" != -* && "${3:-}" != -* ]]; then
  HOST="$1"
  PORT="$2"
  COUNT="$3"
else
  while getopts ":h:p:c:t:i:n" opt; do
    case "$opt" in
      h) HOST="$OPTARG" ;;
      p) PORT="$OPTARG" ;;
      c) COUNT="$OPTARG" ;;
      t) TIMEOUT_S="$OPTARG" ;;
      i) INTERVAL_MS="$OPTARG" ;;
      n) NO_DNS=1 ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  [[ $# -eq 0 ]] || usage
fi

[[ -n "$HOST" ]] || usage
[[ -n "$PORT" ]] || usage
[[ -n "$COUNT" ]] || usage

validate_port "$PORT" || die "'$PORT' is not a valid TCP port (1-65535)"
is_pos_int "$COUNT" || die "'$COUNT' is not a positive integer"
is_pos_int "$TIMEOUT_S" || die "'$TIMEOUT_S' is not a positive integer"
is_nonneg_int "$INTERVAL_MS" || die "'$INTERVAL_MS' is not a non-negative integer"

has_cmd nc || die "'nc' not found (install netcat / nmap-ncat)"

if [[ -t 1 ]]; then
  GREEN=$'\033[32m'
  RED=$'\033[31m'
  DIM=$'\033[2m'
  RESET=$'\033[0m'
else
  GREEN=""; RED=""; DIM=""; RESET=""
fi

nc_args=(-z -w "$TIMEOUT_S")
[[ "$NO_DNS" -eq 1 ]] && nc_args+=(-n)

echo "--- Starting TCP connect checks for ${HOST}:${PORT} (${COUNT} attempts, timeout ${TIMEOUT_S}s) ---"

for ((i=1; i<=COUNT; i++)); do
  # -z: just scan/listen check (no data), -w: timeout.
  if nc "${nc_args[@]}" "$HOST" "$PORT" >/dev/null 2>&1; then
    echo "[$(date +%H:%M:%S)] Attempt $i: ${GREEN}SUCCESS${RESET}"
    ((SUCCESS++))
  else
    echo "[$(date +%H:%M:%S)] Attempt $i: ${RED}FAILED${RESET}"
    ((FAILED++))
  fi

  sleep_ms "$INTERVAL_MS"
done

PERCENT_INT=$(( 100 * SUCCESS / COUNT ))
PERCENT_FLOAT="$(awk -v ok="$SUCCESS" -v total="$COUNT" 'BEGIN{ printf "%.1f", (ok*100.0/total) }')"

echo "---------------------------------------"
echo "Summary for ${HOST}:${PORT}:"
echo "Total attempts:  $COUNT"
echo "Success:         $SUCCESS"
echo "Failed:          $FAILED"
echo "Success rate:    ${PERCENT_FLOAT}% ${DIM}(int ${PERCENT_INT}%)${RESET}"
echo "---------------------------------------"

[[ "$FAILED" -eq 0 ]] && exit 0 || exit 1

