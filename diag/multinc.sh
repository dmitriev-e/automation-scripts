#!/usr/bin/env bash
set -u

# Description: run N TCP connection attempts using netcat (nc) and count results.
# Useful for diagnosing reachability, firewall drops, SYN timeouts, and intermittent connectivity.
#
# Usage:
#   ./multinc.sh <host> <port> <count>
#   ./multinc.sh -h <host> -p <port> -c <count> [-t <timeout_s>] [-i <interval_ms>] [-n]
#                [-u] [-s <src_base_port>] [-C [-I <iface>]]
#
# Examples:
#   ./multinc.sh 10.0.0.5 443 20
#   ./multinc.sh -h example.com -p 443 -c 100 -t 1 -i 20
#   ./multinc.sh -h 10.0.0.5 -p 3306 -c 50 -t 2 -n
#   ./multinc.sh -h 10.0.0.5 -p 5001 -c 200 -s 40000 -C        # fixed src ports + capture
#   ./multinc.sh -h 10.0.0.5 -p 5001 -c 200 -u -C              # UDP echo (peer: multinc-rx.sh -u)
#
# Counterpart on DST: multinc-rx.sh (listens on the port, captures, prints the same phase table).
# -C needs tcpdump + sudo and multinc-lib.sh next to this script; -u needs socat.
#
# ECMP note: in a Clos fabric the path is chosen by a 5-tuple hash. With -s every attempt uses a
# known src port (base+i-1), so failures can be re-run on the same ports and mapped to a path.
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
UDP=0
SRC_BASE=""
CAPTURE=0
IFACE=""

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
             [-u] [-s <src_base_port>] [-C [-I <iface>]]

Options:
  -h host         Target host/IP
  -p port         TCP/UDP port (1-65535)
  -c count        Number of attempts (positive integer)
  -t timeout_s    Timeout per attempt in seconds (default: 1)
  -i interval_ms  Sleep between attempts in milliseconds (default: 0)
  -n              Do not resolve names (pass -n to nc)
  -u              UDP mode: send one datagram per attempt, wait for echo (needs socat;
                  peer must echo, e.g. multinc-rx.sh -u)
  -s base_port    Fixed source ports: attempt i uses base_port+i-1 (ECMP path pinning)
  -C              Capture with tcpdump (sudo) and print per-phase TX/RX packet table
  -I iface        Capture interface (default: egress iface from `ip route get`, else any)
EOF
  exit 2
}

is_pos_int() { [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]; }
is_nonneg_int() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# BusyBox nc has no -z/-n; there we connect with stdin=/dev/null, so nc exits right after connect.
nc_supports_z() { nc -h 2>&1 | grep -qE '(^|[[:space:]])-z'; }

# Runs nc with given args; prints connect time in ms (one line) to stdout; exit code = nc's exit code.
# Timing: bash EPOCHREALTIME (5.1+), else GNU date +%s%N; else no stdout line (caller prints SUCCESS only).
run_nc_timed() {
  if [[ "${BASH_VERSINFO[0]:-0}" -ge 5 ]] && [[ -n "${EPOCHREALTIME+x}" ]]; then
    local t0="$EPOCHREALTIME" t1 rc
    nc "$@" </dev/null >/dev/null 2>&1
    rc=$?
    t1="$EPOCHREALTIME"
    awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f\n", (b - a) * 1000.0 }'
    return "$rc"
  fi

  local start end rc delta_ns
  start="$(date +%s%N 2>/dev/null || true)"
  if [[ "$start" =~ ^[0-9]+$ ]] && [[ ${#start} -ge 14 ]]; then
    nc "$@" </dev/null >/dev/null 2>&1
    rc=$?
    end="$(date +%s%N 2>/dev/null || true)"
    if [[ "$end" =~ ^[0-9]+$ ]]; then
      delta_ns=$((10#$end - 10#$start))
      [[ "$delta_ns" -ge 0 ]] || delta_ns=0
      awk -v ns="$delta_ns" 'BEGIN { printf "%.1f\n", ns / 1e6 }'
    fi
    return "$rc"
  fi

  nc "$@" </dev/null >/dev/null 2>&1
  return $?
}

# Current time in seconds with fraction (bash 5 EPOCHREALTIME or GNU date); empty if unavailable.
now_s() {
  if [[ -n "${EPOCHREALTIME:-}" ]]; then echo "${EPOCHREALTIME/,/.}"; return; fi
  local ns
  ns="$(date +%s%N 2>/dev/null || true)"
  [[ "$ns" =~ ^[0-9]{14,}$ ]] && awk -v ns="$ns" 'BEGIN { printf "%.6f\n", ns / 1e9 }'
}

# One UDP probe: run_udp_probe <seq> [src_port]. Prints RTT ms; rc 0 = echo received.
# Call inside $(...) (uses fd 9). socat output goes to a FIFO so we return as soon as the
# reply line arrives instead of waiting for socat's -t close timeout.
run_udp_probe() {
  local seq="$1" sport="${2:-}" target="$HOST" addr fifo t0 t1 cpid reply="" rc=1
  [[ "$target" == *:* && "$target" != \[* ]] && target="[$target]"
  addr="UDP:${target}:${PORT}"
  [[ -n "$sport" ]] && addr="${addr},sourceport=${sport}"
  fifo="$(mktemp -u "${TMPDIR:-/tmp}/multinc.XXXXXX")"
  mkfifo "$fifo" || return 1
  exec 9<>"$fifo"   # read-write open never blocks; FIFO can be unlinked right away
  rm -f "$fifo"
  t0="$(now_s)"
  # -t: after stdin EOF keep waiting up to timeout for the echo
  printf 'multinc %s %s\n' "$RUN_ID" "$seq" |
    socat -t "$TIMEOUT_S" -T "$((TIMEOUT_S + 1))" - "$addr" >&9 2>/dev/null &
  cpid=$!
  if read -r -t "$TIMEOUT_S" reply <&9 && [[ -n "$reply" ]]; then rc=0; fi
  t1="$(now_s)"
  kill "$cpid" 2>/dev/null
  wait "$cpid" 2>/dev/null
  exec 9<&-
  [[ "$rc" -eq 0 && -n "$t0" && -n "$t1" ]] && awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f\n", (b - a) * 1000.0 }'
  return "$rc"
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
  while getopts ":h:p:c:t:i:nus:CI:" opt; do
    case "$opt" in
      h) HOST="$OPTARG" ;;
      p) PORT="$OPTARG" ;;
      c) COUNT="$OPTARG" ;;
      t) TIMEOUT_S="$OPTARG" ;;
      i) INTERVAL_MS="$OPTARG" ;;
      n) NO_DNS=1 ;;
      u) UDP=1 ;;
      s) SRC_BASE="$OPTARG" ;;
      C) CAPTURE=1 ;;
      I) IFACE="$OPTARG" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  [[ $# -eq 0 ]] || usage
fi

[[ -n "$HOST" ]] || usage
[[ -n "$PORT" ]] || usage
[[ -n "$COUNT" ]] || usage

validate_port "$PORT" || die "'$PORT' is not a valid port (1-65535)"
is_pos_int "$COUNT" || die "'$COUNT' is not a positive integer"
is_pos_int "$TIMEOUT_S" || die "'$TIMEOUT_S' is not a positive integer"
is_nonneg_int "$INTERVAL_MS" || die "'$INTERVAL_MS' is not a non-negative integer"
if [[ -n "$SRC_BASE" ]]; then
  validate_port "$SRC_BASE" || die "'$SRC_BASE' is not a valid source port"
  [[ $((SRC_BASE + COUNT - 1)) -le 65535 ]] || die "source ports $SRC_BASE..$((SRC_BASE + COUNT - 1)) exceed 65535"
fi
[[ -n "$IFACE" && "$CAPTURE" -eq 0 ]] && echo "Warning: -I without -C; ignoring" >&2

if [[ "$UDP" -eq 1 ]]; then
  has_cmd socat || die "'socat' not found (apt install socat)"
else
  has_cmd nc || die "'nc' not found (install netcat / nmap-ncat)"
fi

PROTO="tcp"; [[ "$UDP" -eq 1 ]] && PROTO="udp"
RUN_ID="$(date +%s)-$$"

# Capture setup (only with -C): lib is sourced lazily so plain usage needs no extra files.
if [[ "$CAPTURE" -eq 1 ]]; then
  LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/multinc-lib.sh"
  [[ -r "$LIB" ]] || die "-C needs $LIB"
  # shellcheck source=multinc-lib.sh
  . "$LIB"
  has_cmd tcpdump || die "'tcpdump' not found (apt install tcpdump)"
  DST_IP="$(mn_resolve_ip "$HOST")"
  [[ -n "$DST_IP" ]] || die "cannot resolve '$HOST'"
  [[ -n "$IFACE" ]] || IFACE="$(mn_iface_for "$DST_IP")"
  PCAP="./multinc-${DST_IP//[^A-Za-z0-9._-]/_}-${PORT}-${PROTO}-$(date +%Y%m%d-%H%M%S).pcap"
  # ICMP is included to catch unreachables / admin-prohibited from firewalls on the path
  CAP_FILTER="(host ${DST_IP} and ${PROTO} port ${PORT}) or icmp or icmp6"
  mn_sudo_init || exit 2
  NSTAT_A="$(mktemp)"; NSTAT_B="$(mktemp)"
  trap 'mn_capture_stop >/dev/null; rm -f "$NSTAT_A" "$NSTAT_B"' EXIT
  trap 'exit 130' INT TERM
  mn_nstat_snap "$NSTAT_A"
  mn_capture_start "$IFACE" "$CAP_FILTER" "$PCAP" || exit 2
  echo "Capturing on ${IFACE}: ${CAP_FILTER} -> ${PCAP}"
fi

if [[ -n "$SRC_BASE" && "$UDP" -eq 0 ]]; then
  # Re-running the same src ports within ~60s may hit our own TIME_WAIT (bind/connect fails locally)
  echo "Note: fixed src ports; wait ~60s between re-runs on the same ports" \
       "(net.ipv4.tcp_tw_reuse=$(cat /proc/sys/net/ipv4/tcp_tw_reuse 2>/dev/null || echo '?'))" >&2
fi

if [[ -t 1 ]]; then
  GREEN=$'\033[32m'
  RED=$'\033[31m'
  DIM=$'\033[2m'
  RESET=$'\033[0m'
else
  GREEN=""; RED=""; DIM=""; RESET=""
fi

nc_args=(-w "$TIMEOUT_S")
if nc_supports_z; then
  nc_args+=(-z)
  [[ "$NO_DNS" -eq 1 ]] && nc_args+=(-n)
else
  [[ "$NO_DNS" -eq 1 ]] && echo "Warning: this nc has no -n; ignoring" >&2
fi

if [[ "$UDP" -eq 1 ]]; then
  echo "--- Starting UDP echo checks for ${HOST}:${PORT} (${COUNT} attempts, timeout ${TIMEOUT_S}s) ---"
else
  echo "--- Starting TCP connect checks for ${HOST}:${PORT} (${COUNT} attempts, timeout ${TIMEOUT_S}s) ---"
fi

for ((i=1; i<=COUNT; i++)); do
  src_port=""; src_tag=""
  if [[ -n "$SRC_BASE" ]]; then
    src_port=$((SRC_BASE + i - 1))
    src_tag=" ${DIM}src:${src_port}${RESET}"
  fi
  if [[ "$UDP" -eq 1 ]]; then
    connect_ms="$(run_udp_probe "$i" "$src_port")"
    rc=$?
  else
    # -z (if supported): just scan/listen check (no data), -w: timeout, -p: fixed src port.
    attempt_args=("${nc_args[@]}")
    [[ -n "$src_port" ]] && attempt_args+=(-p "$src_port")
    connect_ms="$(run_nc_timed "${attempt_args[@]}" "$HOST" "$PORT")"
    rc=$?
  fi
  if [[ "$rc" -eq 0 ]]; then
    if [[ -n "$connect_ms" ]]; then
      echo "[$(date +%H:%M:%S)] Attempt $i: ${GREEN}SUCCESS${RESET} (${connect_ms} ms)${src_tag}"
      MS_SAMPLES+=("$connect_ms")
    else
      echo "[$(date +%H:%M:%S)] Attempt $i: ${GREEN}SUCCESS${RESET}${src_tag}"
    fi
    ((SUCCESS++))
  else
    echo "[$(date +%H:%M:%S)] Attempt $i: ${RED}FAILED${RESET}${src_tag}"
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
TIME_LABEL="Connect time ms"; [[ "$UDP" -eq 1 ]] && TIME_LABEL="Echo RTT ms    "
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
  echo "${TIME_LABEL}: min ${MS_MIN} / avg ${MS_AVG} / max ${MS_MAX} ${DIM}(${#MS_SAMPLES[@]} samples)${RESET}"
else
  echo "${TIME_LABEL}: ${DIM}n/a (no samples; need bash 5+ EPOCHREALTIME or GNU date +%s%N)${RESET}"
fi
echo "---------------------------------------"

if [[ "$CAPTURE" -eq 1 ]]; then
  # Grace period: catch late SYN-ACK retransmits / RSTs / late echoes before stopping capture
  sleep 1
  mn_nstat_snap "$NSTAT_B"
  echo "Packet phases on this side (initiator, iface ${IFACE}):"
  mn_capture_stop
  mn_phases_report "$PCAP" "$PROTO" client "$PORT" "$DST_IP"
  mn_nstat_delta "$NSTAT_A" "$NSTAT_B"
  echo "pcap: ${PCAP}"
  echo "---------------------------------------"
fi

[[ "$FAILED" -eq 0 ]] && exit 0 || exit 1

