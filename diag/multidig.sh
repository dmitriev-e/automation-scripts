#!/usr/bin/env bash
set -u

# Description: run N DNS queries via dig and count results.
# Useful for diagnosing flaky resolvers, ECMP path issues, or intermittent packet loss.
#
# Usage:
#   ./multidig.sh <dns_server> <count> <name>
#   ./multidig.sh -s <dns_server> -c <count> -n <name> [-r <type>] [-t <timeout_s>] [-i <interval_ms>]
#
# Examples:
#   ./multidig.sh 8.8.8.8 10 example.com
#   ./multidig.sh -s 1.1.1.1 -c 100 -n example.com -r A -t 1 -i 20
#
# Output:
#   [10:00:00] Query 1: SUCCESS (Answer: 93.184.216.34)
#   [10:00:01] Query 2: FAILED (timeout / network error / no answer)

DNS_SERVER=""
COUNT=""
NAME=""
QTYPE="A"
TIMEOUT_S=1
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
  multidig.sh <dns_server> <count> <name>
  multidig.sh -s <dns_server> -c <count> -n <name> [-r <type>] [-t <timeout_s>] [-i <interval_ms>]

Options:
  -s dns_server   Resolver IP/hostname (e.g. 8.8.8.8)
  -c count        Number of queries (positive integer)
  -n name         Domain name to query (e.g. example.com)
  -r type         Record type (default: A; e.g. AAAA, TXT, NS, SOA, CNAME)
  -t timeout_s    Timeout per query in seconds (default: 1)
  -i interval_ms  Sleep between queries in milliseconds (default: 0)
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

# Parse args (supports both positional and flags for backwards compatibility).
if [[ $# -eq 3 && "${1:-}" != -* && "${2:-}" != -* && "${3:-}" != -* ]]; then
  DNS_SERVER="$1"
  COUNT="$2"
  NAME="$3"
else
  while getopts ":s:c:n:r:t:i:" opt; do
    case "$opt" in
      s) DNS_SERVER="$OPTARG" ;;
      c) COUNT="$OPTARG" ;;
      n) NAME="$OPTARG" ;;
      r) QTYPE="$OPTARG" ;;
      t) TIMEOUT_S="$OPTARG" ;;
      i) INTERVAL_MS="$OPTARG" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  [[ $# -eq 0 ]] || usage
fi

[[ -n "$DNS_SERVER" ]] || usage
[[ -n "$COUNT" ]] || usage
[[ -n "$NAME" ]] || usage

is_pos_int "$COUNT" || die "'$COUNT' is not a positive integer"
is_pos_int "$TIMEOUT_S" || die "'$TIMEOUT_S' is not a positive integer"
is_nonneg_int "$INTERVAL_MS" || die "'$INTERVAL_MS' is not a non-negative integer"

has_cmd dig || die "'dig' not found (install bind-utils / dnsutils)"

if [[ -t 1 ]]; then
  GREEN=$'\033[32m'
  RED=$'\033[31m'
  DIM=$'\033[2m'
  RESET=$'\033[0m'
else
  GREEN=""; RED=""; DIM=""; RESET=""
fi

echo "--- Starting DNS checks for ${NAME} via ${DNS_SERVER} (${COUNT} queries, type ${QTYPE}, timeout ${TIMEOUT_S}s) ---"

for ((i=1; i<=COUNT; i++)); do
  # +short: compact output; +tries=1: no retries; +time: per-try timeout (seconds)
  RAW="$(dig "@${DNS_SERVER}" "${NAME}" "${QTYPE}" +nocmd +noquestion +nocomments +nostats +short +time="${TIMEOUT_S}" +tries=1 2>&1)"
  EXIT_CODE=$?
  # dig may print diagnostics to stdout; treat only non-comment, non-empty lines as answers.
  ANSWER="$(printf "%s\n" "$RAW" | awk 'NF && $1 !~ /^;/' )"

  if [[ "$EXIT_CODE" -eq 0 && -n "$ANSWER" ]]; then
    CLEAN_ANSWER="$(printf "%s" "$ANSWER" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g; s/[[:space:]]*$//')"
    echo "[$(date +%H:%M:%S)] Query $i: ${GREEN}SUCCESS${RESET} (Answer: ${CLEAN_ANSWER})"
    ((SUCCESS++))
  else
    # Best-effort: show a short diagnostic snippet if present.
    DIAG="$(
      printf "%s\n" "$RAW" | awk '
        BEGIN{ best="" }
        $1 ~ /^;;/ {
          line=$0
          sub(/^;;[[:space:]]*/, "", line)
          # Prefer actionable diagnostics over "global options".
          if (line ~ /(timed out|no servers could be reached|connection timed out|SERVFAIL|NXDOMAIN|REFUSED)/) { print line; exit }
          if (best == "" && line !~ /^global options:/) { best=line }
        }
        END{ if (best != "") print best }
      '
    )"
    if [[ -n "$DIAG" ]]; then
      echo "[$(date +%H:%M:%S)] Query $i: ${RED}FAILED${RESET} (${DIAG})"
    else
      echo "[$(date +%H:%M:%S)] Query $i: ${RED}FAILED${RESET} (dig exit ${EXIT_CODE}; timeout / network error / no answer)"
    fi
    ((FAILED++))
  fi

  sleep_ms "$INTERVAL_MS"
done

PERCENT_INT=$(( 100 * SUCCESS / COUNT ))
PERCENT_FLOAT="$(awk -v ok="$SUCCESS" -v total="$COUNT" 'BEGIN{ printf "%.1f", (ok*100.0/total) }')"

echo "---------------------------------------"
echo "Summary for resolver $DNS_SERVER:"
echo "Name:            $NAME"
echo "Type:            $QTYPE"
echo "Total queries:   $COUNT"
echo "Success:         $SUCCESS"
echo "Failed:          $FAILED"
echo "Success rate:    ${PERCENT_FLOAT}% ${DIM}(int ${PERCENT_INT}%)${RESET}"
echo "---------------------------------------"

[[ "$FAILED" -eq 0 ]] && exit 0 || exit 1
