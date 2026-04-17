#!/usr/bin/env bash
set -u

# Description: run N HTTP requests using curl and report response codes and timing.
# Useful for diagnosing flaky endpoints, CDN issues, timeouts, or intermittent errors.
#
# Timing comes from curl's built-in write-out format — no Python or bash tricks needed.
#
# Usage:
#   ./multicurl.sh <url> <count>
#   ./multicurl.sh -u <url> -c <count> [-t <timeout_s>] [-i <interval_ms>]
#                  [-e <expect>] [-k] [-L] [-A <user-agent>]
#
# Examples:
#   ./multicurl.sh https://example.com 10
#   ./multicurl.sh -u https://api.internal/health -c 50 -t 3 -i 200 -e 200
#   ./multicurl.sh -u https://example.com -c 20 -k -L
#
# -e <expect>  Expected HTTP code or class (default: 2xx).
#              Accepts: exact code (200), class (2xx/3xx/4xx/5xx), or comma-separated (200,201,204).
#
# Exit codes:
#   0: all attempts matched expected code
#   1: at least one attempt failed
#   2: usage / validation error

URL=""
COUNT=""
TIMEOUT_S=5
INTERVAL_MS=0
EXPECT="2xx"
INSECURE=0
FOLLOW=0
USER_AGENT=""

SUCCESS=0
FAILED=0

TOTAL_MS_SAMPLES=()   # response times for successful attempts
ALL_CODES=()          # every HTTP code seen (for distribution table)

TMPFILE=""

die() {
  echo "Error: $*" >&2
  exit 2
}

usage() {
  cat >&2 <<'EOF'
Usage:
  multicurl.sh <url> <count>
  multicurl.sh -u <url> -c <count> [-t <timeout_s>] [-i <interval_ms>]
               [-e <expect>] [-k] [-L] [-A <user-agent>]

Options:
  -u url          Target URL
  -c count        Number of attempts (positive integer)
  -t timeout_s    Max time per request in seconds (default: 5)
  -i interval_ms  Sleep between attempts in milliseconds (default: 0)
  -e expect       Expected HTTP code / class (default: 2xx)
                  Examples: 200  2xx  3xx  200,201,204
  -k              Skip TLS certificate verification
  -L              Follow redirects
  -A user-agent   Custom User-Agent header
EOF
  exit 2
}

is_pos_int()    { [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]; }
is_nonneg_int() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

sleep_ms() {
  local ms="$1"
  [[ "$ms" -gt 0 ]] || return 0
  awk -v ms="$ms" 'BEGIN{ printf "%.3f\n", (ms/1000) }' | { read -r sec; sleep "$sec"; }
}

# Returns 0 if $1 (numeric HTTP code) matches $EXPECT pattern.
code_matches() {
  local code="$1"
  [[ "$code" =~ ^[0-9]+$ ]] || return 1
  local pattern
  for pattern in ${EXPECT//,/ }; do
    case "$pattern" in
      [1-5]xx)
        [[ "${code:0:1}" == "${pattern:0:1}" ]] && return 0 ;;
      *)
        [[ "$code" == "$pattern" ]] && return 0 ;;
    esac
  done
  return 1
}

# Parse args (supports both positional and flags for backwards compatibility).
if [[ $# -eq 2 && "${1:-}" != -* && "${2:-}" != -* ]]; then
  URL="$1"
  COUNT="$2"
else
  while getopts ":u:c:t:i:e:A:kL" opt; do
    case "$opt" in
      u) URL="$OPTARG" ;;
      c) COUNT="$OPTARG" ;;
      t) TIMEOUT_S="$OPTARG" ;;
      i) INTERVAL_MS="$OPTARG" ;;
      e) EXPECT="$OPTARG" ;;
      k) INSECURE=1 ;;
      L) FOLLOW=1 ;;
      A) USER_AGENT="$OPTARG" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  [[ $# -eq 0 ]] || usage
fi

[[ -n "$URL" ]]   || usage
[[ -n "$COUNT" ]] || usage

is_pos_int    "$COUNT"       || die "'$COUNT' is not a positive integer"
is_pos_int    "$TIMEOUT_S"   || die "'$TIMEOUT_S' is not a positive integer"
is_nonneg_int "$INTERVAL_MS" || die "'$INTERVAL_MS' is not a non-negative integer"

has_cmd curl || die "'curl' not found"

# Map common curl exit codes to short descriptions (shown when stderr is empty).
curl_exit_desc() {
  case "$1" in
     1) echo "unsupported protocol" ;;
     3) echo "malformed URL" ;;
     5) echo "could not resolve proxy" ;;
     6) echo "could not resolve host" ;;
     7) echo "connection refused" ;;
    28) echo "operation timed out" ;;
    35) echo "SSL/TLS handshake failed" ;;
    51) echo "SSL peer certificate verification failed" ;;
    52) echo "empty reply from server" ;;
    56) echo "receive failure (reset by peer)" ;;
     *) echo "error ${1}" ;;
  esac
}

# Temp file for capturing curl stderr (error messages on connection failure).
TMPFILE="$(mktemp /tmp/multicurl_err.XXXXXX)"
trap 'rm -f "$TMPFILE"' EXIT

if [[ -t 1 ]]; then
  GREEN=$'\033[32m'
  RED=$'\033[31m'
  YELLOW=$'\033[33m'
  DIM=$'\033[2m'
  RESET=$'\033[0m'
else
  GREEN=""; RED=""; YELLOW=""; DIM=""; RESET=""
fi

# curl write-out fields (tab-separated to simplify awk parsing):
#   http_code  time_connect  time_starttransfer  time_total
# All times are in seconds with microsecond resolution.
CURL_FMT='%{http_code}\t%{time_connect}\t%{time_starttransfer}\t%{time_total}'

# -S keeps error messages on stderr even in silent mode.
curl_base=(-sS -o /dev/null -w "$CURL_FMT" --max-time "$TIMEOUT_S" --connect-timeout "$TIMEOUT_S")
[[ "$INSECURE" -eq 1 ]] && curl_base+=(-k)
[[ "$FOLLOW"   -eq 1 ]] && curl_base+=(-L)
[[ -n "$USER_AGENT"  ]] && curl_base+=(-A "$USER_AGENT")

echo "--- Starting HTTP checks for ${URL} (${COUNT} attempts, timeout ${TIMEOUT_S}s, expect ${EXPECT}) ---"

for ((i=1; i<=COUNT; i++)); do
  : >"$TMPFILE"
  raw="$(curl "${curl_base[@]}" "$URL" 2>"$TMPFILE")"
  curl_rc=$?

  http_code="$(   awk -F'\t' '{print $1}' <<<"$raw")"
  time_conn_s="$( awk -F'\t' '{print $2}' <<<"$raw")"
  time_ttfb_s="$( awk -F'\t' '{print $3}' <<<"$raw")"
  time_total_s="$(awk -F'\t' '{print $4}' <<<"$raw")"

  # Convert seconds → ms using awk (curl outputs decimal like 0.123456).
  total_ms="$(awk -v t="$time_total_s" 'BEGIN { printf "%.1f", t * 1000 }')"
  conn_ms="$( awk -v t="$time_conn_s"  'BEGIN { printf "%.1f", t * 1000 }')"
  ttfb_ms="$( awk -v t="$time_ttfb_s"  'BEGIN { printf "%.1f", t * 1000 }')"

  if [[ "$curl_rc" -eq 0 ]] && code_matches "$http_code"; then
    echo "[$(date +%H:%M:%S)] Attempt $i: ${GREEN}SUCCESS${RESET} HTTP ${http_code} (conn ${conn_ms} ms | ttfb ${ttfb_ms} ms | total ${total_ms} ms)"
    TOTAL_MS_SAMPLES+=("$total_ms")
    ALL_CODES+=("$http_code")
    ((SUCCESS++))
  else
    if [[ "$curl_rc" -ne 0 ]]; then
      # First meaningful line from curl's stderr; fall back to known exit code descriptions.
      err_msg="$(grep -v '^$' "$TMPFILE" 2>/dev/null | head -1 | sed 's/^curl: *([0-9]*) *//;s/^[[:space:]]*//' || true)"
      [[ -z "$err_msg" ]] && err_msg="$(curl_exit_desc "$curl_rc")"
      echo "[$(date +%H:%M:%S)] Attempt $i: ${RED}FAILED${RESET} (curl exit ${curl_rc}: ${err_msg})"
    else
      echo "[$(date +%H:%M:%S)] Attempt $i: ${YELLOW}FAILED${RESET} HTTP ${http_code} (total ${total_ms} ms)"
      ALL_CODES+=("$http_code")
    fi
    ((FAILED++))
  fi

  sleep_ms "$INTERVAL_MS"
done

PERCENT_INT=$(( 100 * SUCCESS / COUNT ))
PERCENT_FLOAT="$(awk -v ok="$SUCCESS" -v total="$COUNT" 'BEGIN { printf "%.1f", ok*100.0/total }')"

echo "---------------------------------------"
echo "Summary for ${URL}:"
echo "Expect code:     ${EXPECT}"
echo "Total attempts:  $COUNT"
echo "Success:         $SUCCESS"
echo "Failed:          $FAILED"
echo "Success rate:    ${PERCENT_FLOAT}% ${DIM}(int ${PERCENT_INT}%)${RESET}"

# HTTP code distribution.
if [[ ${#ALL_CODES[@]} -gt 0 ]]; then
  echo "HTTP codes:"
  printf '%s\n' "${ALL_CODES[@]}" | sort | uniq -c | sort -rn |
    awk '{ printf "  %-6s × %s\n", $2, $1 }'
fi

# Response time statistics over successful samples.
if [[ ${#TOTAL_MS_SAMPLES[@]} -gt 0 ]]; then
  read -r MS_MIN MS_AVG MS_MAX <<<"$(
    printf '%s\n' "${TOTAL_MS_SAMPLES[@]}" | awk '
      { v = $0 + 0; sum += v; if (NR==1){min=max=v} else {if(v<min)min=v; if(v>max)max=v} }
      END { printf "%.1f %.1f %.1f\n", min, sum/NR, max }
    '
  )"
  echo "Response ms:     min ${MS_MIN} / avg ${MS_AVG} / max ${MS_MAX} ${DIM}(${#TOTAL_MS_SAMPLES[@]} samples)${RESET}"
else
  echo "Response ms:     ${DIM}n/a (no successful requests)${RESET}"
fi

echo "---------------------------------------"

[[ "$FAILED" -eq 0 ]] && exit 0 || exit 1
