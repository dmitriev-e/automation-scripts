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
# On SUCCESS, prints TCP connect time in ms using bash/GNU date only (no Python):
#   - Bash 5.1+ built-in EPOCHREALTIME when available
#   - else GNU date +%s%N (typical Linux)
#   - else no timing line (plain SUCCESS)
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
MS_SAMPLES=()

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

# Runs nc with given args; prints connect time in ms (one line) to stdout; exit code = nc's exit code.
# Timing: bash EPOCHREALTIME (5.1+), else GNU date +%s%N; else no stdout line (caller prints SUCCESS only).
run_nc_timed() {
  if [[ "${BASH_VERSINFO[0]:-0}" -ge 5 ]] && [[ -n "${EPOCHREALTIME+x}" ]]; then
    local t0="$EPOCHREALTIME" t1 rc
    nc "$@" >/dev/null 2>&1
    rc=$?
    t1="$EPOCHREALTIME"
    awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f\n", (b - a) * 1000.0 }'
    return "$rc"
  fi

  local start end rc delta_ns
  start="$(date +%s%N 2>/dev/null || true)"
  if [[ "$start" =~ ^[0-9]+$ ]] && [[ ${#start} -ge 14 ]]; then
    nc "$@" >/dev/null 2>&1
    rc=$?
    end="$(date +%s%N 2>/dev/null || true)"
    if [[ "$end" =~ ^[0-9]+$ ]]; then
      delta_ns=$((10#$end - 10#$start))
      [[ "$delta_ns" -ge 0 ]] || delta_ns=0
      awk -v ns="$delta_ns" 'BEGIN { printf "%.1f\n", ns / 1e6 }'
    fi
    return "$rc"
  fi

  nc "$@" >/dev/null 2>&1
  return $?
}

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
  connect_ms="$(run_nc_timed "${nc_args[@]}" "$HOST" "$PORT")"
  rc=$?
  if [[ "$rc" -eq 0 ]]; then
    if [[ -n "$connect_ms" ]]; then
      echo "[$(date +%H:%M:%S)] Attempt $i: ${GREEN}SUCCESS${RESET} (${connect_ms} ms)"
      MS_SAMPLES+=("$connect_ms")
    else
      echo "[$(date +%H:%M:%S)] Attempt $i: ${GREEN}SUCCESS${RESET}"
    fi
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
if [[ ${#MS_SAMPLES[@]} -gt 0 ]]; then
  read -r MS_MIN MS_AVG MS_MAX <<<"$(
    printf '%s\n' "${MS_SAMPLES[@]}" | awk '
      {
        v = $0 + 0
        sum += v
        if (NR == 1) { min = max = v }
        else {
          if (v < min) min = v
          if (v > max) max = v
        }
      }
      END { printf "%.1f %.1f %.1f\n", min, sum / NR, max }
    '
  )"
  echo "Connect time ms: min ${MS_MIN} / avg ${MS_AVG} / max ${MS_MAX} ${DIM}(${#MS_SAMPLES[@]} samples)${RESET}"
else
  echo "Connect time ms: ${DIM}n/a (no samples; need bash 5+ EPOCHREALTIME or GNU date +%s%N)${RESET}"
fi
echo "---------------------------------------"

[[ "$FAILED" -eq 0 ]] && exit 0 || exit 1

