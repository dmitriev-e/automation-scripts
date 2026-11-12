#!/usr/bin/env bash
set -u

# Description: responder for multinc.sh. Listens on a TCP/UDP port (UDP = echo), captures the
# traffic with tcpdump and, on Ctrl+C / after -d seconds, prints per-phase TX/RX packet counts
# and the list of incomplete flows as seen from THIS (DST) side.
# Compare with `multinc.sh -C` output on the initiator to see on which leg packets are lost:
#   SYN TX(src) != SYN RX(dst)          -> forward path loss
#   SYN-ACK TX(dst) != SYN-ACK RX(src)  -> return path loss
#
# Usage:
#   ./multinc-rx.sh -p <port> [-u] [-I <iface>] [-d <seconds>] [-N] [-6] [-f <client_ip>]
#
# Examples:
#   ./multinc-rx.sh -p 5001                 # TCP listener + capture until Ctrl+C
#   ./multinc-rx.sh -p 5001 -u -d 120       # UDP echo for 120s
#   ./multinc-rx.sh -p 443 -N -I bond0      # real service already on 443: capture only
#
# Needs: tcpdump, socat (unless -N), sudo (unless root), multinc-lib.sh next to this script.
#
# Exit codes:
#   0: stats printed
#   2: usage / validation / startup error

PORT=""
UDP=0
IFACE="any"
DURATION=0
NO_LISTEN=0
IPV6=0
CLIENT=""

die() {
  echo "Error: $*" >&2
  exit 2
}

usage() {
  cat >&2 <<'EOF'
Usage:
  multinc-rx.sh -p <port> [-u] [-I <iface>] [-d <seconds>] [-N] [-6] [-f <client_ip>]

Options:
  -p port      Port to listen on / capture (1-65535)
  -u           UDP mode (echo every datagram back to the sender)
  -I iface     Capture interface (default: any; duplicates across bond/vlan are dropped)
  -d seconds   Stop after N seconds (default: run until Ctrl+C)
  -N           Do not start a listener (a real service already owns the port): capture only
  -6           Listen dual-stack (IPv6 + IPv4) instead of IPv4 only
  -f client_ip Capture only traffic from/to this client
EOF
  exit 2
}

while getopts ":p:uI:d:N6f:" opt; do
  case "$opt" in
    p) PORT="$OPTARG" ;;
    u) UDP=1 ;;
    I) IFACE="$OPTARG" ;;
    d) DURATION="$OPTARG" ;;
    N) NO_LISTEN=1 ;;
    6) IPV6=1 ;;
    f) CLIENT="$OPTARG" ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))
[[ $# -eq 0 ]] || usage

[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 1 && "$PORT" -le 65535 ]] || usage
[[ "$DURATION" =~ ^[0-9]+$ ]] || die "'$DURATION' is not a non-negative integer"

LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/multinc-lib.sh"
[[ -r "$LIB" ]] || die "needs $LIB"
# shellcheck source=multinc-lib.sh
. "$LIB"

mn_has_cmd tcpdump || die "'tcpdump' not found (apt install tcpdump)"
[[ "$NO_LISTEN" -eq 1 ]] || mn_has_cmd socat || die "'socat' not found (apt install socat)"

PROTO="tcp"; [[ "$UDP" -eq 1 ]] && PROTO="udp"
PCAP="./multinc-rx-${PORT}-${PROTO}-$(date +%Y%m%d-%H%M%S).pcap"
CAP_FILTER="${PROTO} port ${PORT}"
[[ -n "$CLIENT" ]] && CAP_FILTER="host ${CLIENT} and ${CAP_FILTER}"
# ICMP: unreachables we send (closed port with -N) or receive
CAP_FILTER="(${CAP_FILTER}) or icmp or icmp6"

mn_sudo_init || exit 2

LST_BG=""
LST_PIDF="$(mktemp)"
LST_ERR="$(mktemp)"
NSTAT_A="$(mktemp)"
NSTAT_B="$(mktemp)"

stop_listener() {
  [[ -n "$LST_BG" ]] || return 0
  mn_root_kill TERM "$LST_PIDF"
  wait "$LST_BG" 2>/dev/null || true
  LST_BG=""
}

cleanup() {
  stop_listener
  mn_capture_stop >/dev/null
  rm -f "$LST_PIDF" "$LST_ERR" "$NSTAT_A" "$NSTAT_B"
}
trap cleanup EXIT

mn_nstat_snap "$NSTAT_A"
mn_capture_start "$IFACE" "$CAP_FILTER" "$PCAP" || exit 2

if [[ "$NO_LISTEN" -eq 0 ]]; then
  fam=""; famopt=""
  [[ "$IPV6" -eq 1 ]] && { fam="6"; famopt=",ipv6only=0"; }
  if [[ "$UDP" -eq 1 ]]; then
    # Each datagram is handled by a forked child that echoes it back (PIPE) and exits after -T 1
    lst_cmd=(socat -T 1 "UDP${fam}-RECVFROM:${PORT},reuseaddr,fork${famopt}" PIPE)
  else
    # Accept and close immediately. backlog=1024: socat default is 5, which would itself
    # drop SYNs under a burst and look like fabric loss.
    lst_cmd=(socat -T 2 "TCP${fam}-LISTEN:${PORT},reuseaddr,fork,backlog=1024${famopt}" /dev/null)
  fi
  if [[ "$PORT" -lt 1024 ]]; then
    mn_root_bg "$LST_PIDF" "$LST_ERR" "${lst_cmd[@]}"
  else
    # Unprivileged port: run as the invoking user (MN_SUDO cleared just for this call)
    _sudo="$MN_SUDO"; MN_SUDO=""
    mn_root_bg "$LST_PIDF" "$LST_ERR" "${lst_cmd[@]}"
    MN_SUDO="$_sudo"
  fi
  LST_BG="$MN_BG_PID"
  sleep 0.3
  if ! kill -0 "$LST_BG" 2>/dev/null; then
    LST_BG=""
    echo "Error: listener failed to start (port busy? use -N to capture only):" >&2
    cat "$LST_ERR" >&2
    exit 2
  fi
  LISTEN_DESC="listening ${PROTO}/${PORT}$([[ "$UDP" -eq 1 ]] && echo ' (echo)')"
else
  LISTEN_DESC="no listener (-N), capture only"
fi

echo "--- multinc-rx: ${LISTEN_DESC}, capturing on ${IFACE}: ${CAP_FILTER} ---"
echo "pcap: ${PCAP}"
if [[ "$DURATION" -gt 0 ]]; then
  echo "Running for ${DURATION}s (Ctrl+C to stop earlier)..."
else
  echo "Running until Ctrl+C..."
fi

STOP=0
trap 'STOP=1' INT TERM
START_S=$SECONDS
while [[ "$STOP" -eq 0 ]]; do
  # background sleep + wait: the trap fires immediately on Ctrl+C
  sleep 1 &
  wait $! 2>/dev/null
  [[ "$DURATION" -gt 0 && $((SECONDS - START_S)) -ge "$DURATION" ]] && break
done
trap - INT TERM

echo
stop_listener
# let in-flight FIN/RST/echo packets land in the capture
sleep 0.5
mn_nstat_snap "$NSTAT_B"

echo "---------------------------------------"
echo "Packet phases on this side (responder ${PROTO}/${PORT}, iface ${IFACE}, $((SECONDS - START_S))s):"
mn_capture_stop
mn_phases_report "$PCAP" "$PROTO" server "$PORT"
mn_nstat_delta "$NSTAT_A" "$NSTAT_B"
echo "pcap: ${PCAP}"
echo "---------------------------------------"
exit 0
