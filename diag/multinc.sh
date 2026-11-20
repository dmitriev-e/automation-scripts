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
# Single self-contained file (copy just this script). -C needs tcpdump + sudo; -u needs socat.
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
# OpenBSD nc prints the connect error only with -v
nc_supports_v() { nc -h 2>&1 | grep -qE '(^|[[:space:]])-v'; }

NC_USAGE_RE='usage|invalid option|unrecognized option|illegal option|unknown option'

# True if nc rejects these options (prints usage) on a dummy connect to a closed local port.
# Needed because e.g. minimal BusyBox nc lists -p in help but only accepts it with -l.
nc_rejects() {
  local out
  out="$(nc "$@" 127.0.0.1 9 </dev/null 2>&1 >/dev/null)"
  grep -qiE "$NC_USAGE_RE" <<<"$out"
}

# Connector binary used by run_nc_timed: nc, or socat when nc can't bind a source port
TCP_BIN="nc"

# nc stderr of the last attempt (failure reason: refused / no route / bind error / timeout)
NC_ERR="$(mktemp 2>/dev/null || echo "/tmp/multinc.err.$$")"
trap 'rm -f "$NC_ERR"' EXIT

# Runs nc with given args; prints elapsed time in ms (one line) to stdout; exit code = nc's exit code.
# Timing: bash EPOCHREALTIME (5.1+), else GNU date +%s%N; else no stdout line (caller prints SUCCESS only).
run_nc_timed() {
  if [[ "${BASH_VERSINFO[0]:-0}" -ge 5 ]] && [[ -n "${EPOCHREALTIME+x}" ]]; then
    local t0="$EPOCHREALTIME" t1 rc
    "$TCP_BIN" "$@" </dev/null >/dev/null 2>"$NC_ERR"
    rc=$?
    t1="$EPOCHREALTIME"
    awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f\n", (b - a) * 1000.0 }'
    return "$rc"
  fi

  local start end rc delta_ns
  start="$(date +%s%N 2>/dev/null || true)"
  if [[ "$start" =~ ^[0-9]+$ ]] && [[ ${#start} -ge 14 ]]; then
    "$TCP_BIN" "$@" </dev/null >/dev/null 2>"$NC_ERR"
    rc=$?
    end="$(date +%s%N 2>/dev/null || true)"
    if [[ "$end" =~ ^[0-9]+$ ]]; then
      delta_ns=$((10#$end - 10#$start))
      [[ "$delta_ns" -ge 0 ]] || delta_ns=0
      awk -v ns="$delta_ns" 'BEGIN { printf "%.1f\n", ns / 1e6 }'
    fi
    return "$rc"
  fi

  "$TCP_BIN" "$@" </dev/null >/dev/null 2>"$NC_ERR"
  return $?
}

# Fixed-source-port connect via python3/perl (fallback when nc can't -p and socat is absent).
# probe_script <src_port>: prints elapsed connect ms (measured in-process, so interpreter
# startup is excluded); rc 0 = connected; error goes to stderr as "...: <reason>".
probe_script() {
  local sport="$1"
  if [[ "$TCP_BIN" == "python3" ]]; then
    python3 -c '
import socket, sys, time
h, p, sp, t = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
t0 = time.monotonic()
def done(rc, err=None):
    print("%.1f" % ((time.monotonic() - t0) * 1000.0))
    if err: sys.stderr.write("python3: %s\n" % err)
    sys.exit(rc)
try:
    ai = socket.getaddrinfo(h, p, 0, socket.SOCK_STREAM)[0]
    s = socket.socket(ai[0], socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(t)
    t0 = time.monotonic()
    s.bind(("::" if ai[0] == socket.AF_INET6 else "0.0.0.0", sp))
    s.connect(ai[4])
    s.close()
except socket.timeout:
    done(1, "timed out")
except OSError as e:
    done(1, e.strerror or str(e))
done(0)
' "$HOST" "$PORT" "$sport" "$TIMEOUT_S"
  else
    perl -MIO::Socket::INET -e '
my ($h, $p, $sp, $t) = @ARGV;
my $hr = eval { require Time::HiRes; 1 };
my $now = sub { $hr ? Time::HiRes::time() : time() };
my $t0 = $now->();
my $s = IO::Socket::INET->new(PeerAddr => $h, PeerPort => $p, LocalPort => $sp,
                              ReuseAddr => 1, Proto => "tcp", Timeout => $t);
printf "%.1f\n", ($now->() - $t0) * 1000 if $hr;
if (!$s) { my $e = $@ || $!; print STDERR "perl: $e\n"; exit 1 }
close $s; exit 0;
' "$HOST" "$PORT" "$sport" "$TIMEOUT_S"
  fi
}

# Short failure reason from the last nc/socat stderr line, e.g. "Connection refused".
nc_fail_reason() {
  [[ -s "$NC_ERR" ]] || return 0
  if grep -qiE "$NC_USAGE_RE|-e PROG" "$NC_ERR"; then
    echo "$TCP_BIN rejected options (printed usage)"
    return 0
  fi
  tail -n 1 "$NC_ERR" | sed -e 's/.*: //' -e 's/[[:space:]]*$//'
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

# ===== Capture helpers for -C (embedded copy of multinc-lib.sh, kept in sync with multinc-rx.sh) =====
# Needs: tcpdump, sudo (unless root), awk; nstat (iproute2) optional.
MN_SUDO=""
MN_CAP_USER=""
MN_CAP_BG=""
MN_CAP_PIDF=""
MN_CAP_ERR=""

mn_has_cmd() { command -v "$1" >/dev/null 2>&1; }

# Sets MN_SUDO / MN_CAP_USER and primes sudo credentials (background sudo cannot prompt).
mn_sudo_init() {
  if [[ "$EUID" -eq 0 ]]; then
    MN_SUDO=""
    MN_CAP_USER="root"
  else
    mn_has_cmd sudo || { echo "Error: not root and no sudo" >&2; return 1; }
    sudo -v || { echo "Error: sudo authentication failed" >&2; return 1; }
    MN_SUDO="sudo"
    MN_CAP_USER="$(id -un)"
  fi
}

# mn_root_bg <pidfile> <errfile> cmd...: runs cmd in background as root (via sudo if needed).
# Real child PID -> pidfile (needed to signal it through sudo); job PID -> MN_BG_PID.
# Must not be called inside $(...): the job must stay a child of the main shell for `wait`.
MN_BG_PID=""
mn_root_bg() {
  local pidf="$1" errf="$2"; shift 2
  # shellcheck disable=SC2016
  $MN_SUDO sh -c 'echo $$ >"$1"; shift; exec "$@"' sh "$pidf" "$@" </dev/null >/dev/null 2>"$errf" &
  MN_BG_PID="$!"
}

# Sends signal $1 to the PID stored in pidfile $2 (as root if needed).
mn_root_kill() {
  local sig="$1" pidf="$2" pid
  [[ -s "$pidf" ]] || return 0
  pid="$(cat "$pidf")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 0
  $MN_SUDO kill "-$sig" "$pid" 2>/dev/null || true
}

# Egress interface towards IP $1 (Linux `ip route get`); falls back to "any".
mn_iface_for() {
  local dev=""
  if mn_has_cmd ip; then
    dev="$(ip -o route get "$1" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')"
  fi
  echo "${dev:-any}"
}

# Resolves host to the first IP (IP literals are returned as is).
mn_resolve_ip() {
  local h="$1"
  if [[ "$h" =~ ^[0-9.]+$ || "$h" == *:* ]]; then echo "$h"; return 0; fi
  getent ahosts "$h" 2>/dev/null | awk 'NR == 1 { print $1; exit }'
}

# Starts tcpdump: mn_capture_start <iface> <bpf_filter> <pcap_path>. Waits until it is listening.
mn_capture_start() {
  local iface="$1" filter="$2" pcap="$3" i
  MN_CAP_ERR="$(mktemp)"
  MN_CAP_PIDF="$(mktemp)"
  # -U: flush per packet (nothing lost on stop), -s 160: headers only,
  # -Z: drop privs to the invoking user so the pcap is writable in cwd and owned by them.
  mn_root_bg "$MN_CAP_PIDF" "$MN_CAP_ERR" tcpdump -i "$iface" -nn -U -s 160 -Z "$MN_CAP_USER" -w "$pcap" "$filter"
  MN_CAP_BG="$MN_BG_PID"
  for ((i = 0; i < 50; i++)); do
    grep -q "listening on" "$MN_CAP_ERR" 2>/dev/null && return 0
    if ! kill -0 "$MN_CAP_BG" 2>/dev/null; then
      echo "Error: tcpdump failed to start:" >&2
      cat "$MN_CAP_ERR" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "Error: tcpdump did not report 'listening on' within 5s:" >&2
  cat "$MN_CAP_ERR" >&2
  return 1
}

# Stops tcpdump (SIGINT -> it flushes and prints counters) and prints its kernel-drop stats.
mn_capture_stop() {
  [[ -n "$MN_CAP_BG" ]] || return 0
  mn_root_kill INT "$MN_CAP_PIDF"
  wait "$MN_CAP_BG" 2>/dev/null || true
  MN_CAP_BG=""
  # e.g. "0 packets dropped by kernel" — non-zero means capture itself lost packets, stats are unreliable
  grep -E "packets (captured|dropped)" "$MN_CAP_ERR" 2>/dev/null | sed 's/^/  tcpdump: /'
  rm -f "$MN_CAP_ERR" "$MN_CAP_PIDF"
}

# System-wide kernel counters relevant to handshake / UDP loss.
MN_NSTAT_KEYS="TcpExtTCPSynRetrans TcpAttemptFails TcpOutRsts TcpRetransSegs TcpExtListenOverflows TcpExtListenDrops TcpExtTCPReqQFullDrop TcpExtSyncookiesSent TcpExtTCPTimeouts TcpExtIPReversePathFilter UdpInErrors UdpRcvbufErrors UdpSndbufErrors UdpNoPorts"

# mn_nstat_snap <file>: absolute counters, does not touch nstat history (-s).
mn_nstat_snap() {
  mn_has_cmd nstat || return 0
  nstat -asz 2>/dev/null | awk '$1 !~ /^#/ && NF >= 2 { print $1, $2 }' >"$1"
}

# mn_nstat_delta <before> <after>: prints non-zero deltas of MN_NSTAT_KEYS.
mn_nstat_delta() {
  [[ -s "$1" && -s "$2" ]] || return 0
  echo "Kernel counters delta (nstat, system-wide — other traffic included):"
  awk -v keys="$MN_NSTAT_KEYS" '
    BEGIN { n = split(keys, k, " "); for (i = 1; i <= n; i++) want[k[i]] = 1 }
    FNR == NR { a[$1] = $2; next }
    ($1 in want) { d = $2 - a[$1]; if (d != 0) { printf "  %-24s %+d\n", $1, d; shown++ } }
    END { if (!shown) print "  (all zero)" }
  ' "$1" "$2"
}

# --- pcap phase analyzer -------------------------------------------------------------------
# Input: `tcpdump -nn -tt -S -r <pcap>`. Vars: port, proto (tcp|udp), side (client|server),
# peer (optional DST IP for ICMP attribution), maxlist (optional, default 200).
# Direction: dport==port -> c2s, sport==port -> s2c. TX/RX columns depend on side.
# Flow key: client ip:port; a SYN with a new ISN on the same key starts a new flow.
MN_PHASES_AWK=""
read -r -d '' MN_PHASES_AWK <<'AWK' || true
function strip_colon(t) { sub(/:$/, "", t); return t }
function port_of(t) { t = strip_colon(t); match(t, /\.[^.]+$/); return substr(t, RSTART + 1) }
function addr_of(t) { t = strip_colon(t); match(t, /\.[^.]+$/); return substr(t, 1, RSTART - 1) }
function cell(n) { return (n == "" ? "-" : n + 0) }
function row(name, c2s, s2c,   tx, rx) {
  if (side == "client") { tx = c2s; rx = s2c } else { tx = s2c; rx = c2s }
  printf "  %-20s %8s %8s\n", name, cell(tx), cell(rx)
}
function new_flow(key, ts) { nf++; cur[key] = nf; fkey[nf] = key; fts[nf] = ts; return nf }

BEGIN {
  if (maxlist == "") maxlist = 200
  nf = 0; parsed = 0; dups = 0; icmp_unreach = 0; t0 = ""
  # numeric zeros: "" is reserved for "not applicable" cells in row()
  T_req = T_rep = T_syn = T_synrtx = T_synack = T_synackrtx = T_ack = 0
  T_finc = T_fins = T_rstc = T_rsts = T_datac = T_datas = 0
}

{
  # Locate IP/IP6 token (handles `-i any` SLL2 lines with "ifname In/Out" prefix)
  ip = 0
  for (i = 2; i <= NF; i++) if ($i == "IP" || $i == "IP6") { ip = i; break }
  if (!ip) next
  ts = $1 + 0
  if (t0 == "") t0 = ts

  # Same packet seen on several ifaces (bond + slave + vlan with -i any): identical content
  # from a DIFFERENT ifname within 5ms is a duplicate. Same-iface repeats (dup ACKs) are kept.
  ifn = (ip > 2) ? $2 : ""
  norm = ""
  for (j = ip; j <= NF; j++) norm = norm " " $j
  if (ifn != "" && (norm in last_ts) && last_if[norm] != ifn && ts - last_ts[norm] < 0.005) { dups++; next }
  last_ts[norm] = ts; last_if[norm] = ifn

  # ICMP unreachables related to our port / peer (firewall rejects, closed UDP port, ...)
  if (index($0, "ICMP") && index($0, "unreachable")) {
    if (index($0, "port " port " ") || (peer != "" && index($0, " " peer " ")) || index($0, "unreachable port")) {
      icmp_unreach++
      # breakdown by sender + message: tells which hop rejects (firewall / ACL / router)
      m = $0; sub(/.*ICMP6?,? /, "", m); sub(/, length.*/, "", m)
      icmp_by[strip_colon($(ip + 1)) " -> " strip_colon($(ip + 3)) ": " m]++
    }
    next
  }

  src = $(ip + 1); dst = $(ip + 3)
  sp = port_of(src); dp = port_of(dst)
  if (dp == port) { dir = "c2s"; key = addr_of(src) ":" sp }
  else if (sp == port) { dir = "s2c"; key = addr_of(dst) ":" dp }
  else next
  parsed++

  if (proto == "udp") {
    fid = (key in cur) ? cur[key] : new_flow(key, ts)
    if (dir == "c2s") { req[fid]++; T_req++ } else { rep[fid]++; T_rep++ }
    next
  }

  fl = ""; seq = ""; len = 0
  for (j = ip + 4; j <= NF; j++) {
    if ($j == "Flags") { fl = $(j + 1); gsub(/\[/, "", fl); gsub(/\]/, "", fl); gsub(/,/, "", fl) }
    else if ($j == "seq") { seq = $(j + 1); sub(/,$/, "", seq) }
    else if ($j == "length") { len = $(j + 1) + 0 }
  }
  has_syn = index(fl, "S"); has_ack = index(fl, ".")
  has_fin = index(fl, "F"); has_rst = index(fl, "R")

  if (has_syn && !has_ack && dir == "c2s") {
    # same ISN on the same key = retransmit, otherwise a new connection
    if ((key in cur) && isn[cur[key]] == seq) { fid = cur[key]; syn[fid]++; T_synrtx++ }
    else { fid = new_flow(key, ts); isn[fid] = seq; syn[fid] = 1; T_syn++ }
    next
  }

  if (key in cur) fid = cur[key]
  else { fid = new_flow(key, ts); nosyn[fid] = 1 }

  if (has_syn && has_ack && dir == "s2c") {
    synack[fid]++
    if (synack[fid] == 1) T_synack++; else T_synackrtx++
    next
  }

  # First client ACK after SYN-ACK = handshake done (even if it piggybacks FIN/data)
  if (dir == "c2s" && has_ack && synack[fid] && !hsack[fid] && !has_rst) { hsack[fid] = 1; T_ack++ }

  if (has_fin) { if (dir == "c2s") { finc[fid]++; T_finc++ } else { fins[fid]++; T_fins++ } }
  if (has_rst) { if (dir == "c2s") { rstc[fid]++; T_rstc++ } else { rsts[fid]++; T_rsts++ } }
  if (len > 0) { if (dir == "c2s") T_datac++; else T_datas++ }
}

END {
  printf "  %-20s %8s %8s\n", "Phase", "TX", "RX"
  if (proto == "udp") {
    row("REQ", T_req, "")
    row("REPLY", "", T_rep)
  } else {
    row("SYN", T_syn, "")
    row("SYN retrans", T_synrtx, "")
    row("SYN-ACK", "", T_synack)
    row("SYN-ACK retrans", "", T_synackrtx)
    row("ACK (handshake)", T_ack, "")
    row("FIN", T_finc, T_fins)
    row("RST", T_rstc, T_rsts)
    if (T_datac + T_datas > 0) row("DATA segments", T_datac, T_datas)
  }
  if (icmp_unreach > 0) {
    printf "  %-20s %8d (any direction)\n", "ICMP unreachable", icmp_unreach
    for (k in icmp_by) printf "    %6d  %s\n", icmp_by[k], k
  }

  # Hints for the classic "SYN arrives, nothing answers" pattern
  if (proto == "tcp" && T_syn > 0 && T_synack == 0) {
    if (side == "server") {
      print "  !! SYN received but NO SYN-ACK sent: dropped on this host after capture point."
      print "     Check: rp_filter (nstat TcpExtIPReversePathFilter, ip route get <client>),"
      print "     iptables/nft DROP, listener netns/VRF (ss -ltnp; net.ipv4.tcp_l3mdev_accept)."
    } else if (icmp_unreach > 0) {
      print "  !! No SYN-ACK at all, ICMP unreachables received: see senders above (path ACL/firewall?)."
    }
  }

  ok = 0; bad = 0
  for (f = 1; f <= nf; f++) {
    st = ""
    if (proto == "udp") {
      if (req[f] + 0 == 0) st = "reply without captured request"
      else if (rep[f] + 0 == 0) st = (side == "client" ? "no reply received" : "request received, no reply sent")
      else if (rep[f] < req[f]) st = "partial: " rep[f] "/" req[f] " replies"
      detail = sprintf("REQ x%d  REPLY x%d", req[f], rep[f])
    } else {
      if (nosyn[f]) st = "no SYN in capture (started before capture?)"
      else if (!synack[f] && rsts[f]) st = "RST from server (port closed / rejected)"
      else if (!synack[f]) st = (side == "client" ? "no SYN-ACK received" : "SYN received, no SYN-ACK sent (listen drop?)")
      else if (!hsack[f] && rstc[f]) st = (side == "client" ? "late SYN-ACK (1st lost?), client sent RST (gave up)" : "SYN-ACK sent, got RST from client (gave up)")
      else if (!hsack[f]) st = (side == "client" ? "SYN-ACK received, no ACK sent" : "SYN-ACK sent, no ACK received")
      detail = sprintf("SYN x%d  SYN-ACK x%d", syn[f], synack[f])
    }
    if (st == "") { ok++; continue }
    bad++
    if (bad <= maxlist) lst[bad] = sprintf("    +%8.3fs  %-28s %-22s %s", fts[f] - t0, fkey[f], detail, st)
  }

  printf "  Flows: %d total, %d complete, %d incomplete\n", nf, ok, bad
  if (bad > 0) {
    print "  Incomplete flows (time since capture start, client ip:port, counts, verdict):"
    for (k = 1; k <= bad && k <= maxlist; k++) print lst[k]
    if (bad > maxlist) printf "    ... %d more (see pcap)\n", bad - maxlist
  }
  printf "  Packets parsed: %d (duplicates from multiple ifaces dropped: %d)\n", parsed, dups
}
AWK

# mn_phases_report <pcap> <tcp|udp> <client|server> <port> [peer_ip]
mn_phases_report() {
  local pcap="$1" proto="$2" side="$3" port="$4" peer="${5:-}"
  [[ -s "$pcap" ]] || { echo "  (pcap empty or missing: $pcap)"; return 0; }
  tcpdump -nn -tt -S -r "$pcap" 2>/dev/null |
    awk -v port="$port" -v proto="$proto" -v side="$side" -v peer="$peer" "$MN_PHASES_AWK"
}
# ===== end of embedded multinc-lib.sh =====

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

# Capture setup (only with -C).
if [[ "$CAPTURE" -eq 1 ]]; then
  has_cmd tcpdump || die "'tcpdump' not found (apt install tcpdump)"
  DST_IP="$(mn_resolve_ip "$HOST")"
  [[ -n "$DST_IP" ]] || die "cannot resolve '$HOST'"
  [[ -n "$IFACE" ]] || IFACE="$(mn_iface_for "$DST_IP")"
  PCAP="./multinc-${DST_IP//[^A-Za-z0-9._-]/_}-${PORT}-${PROTO}-$(date +%Y%m%d-%H%M%S).pcap"
  # ICMP is included to catch unreachables / admin-prohibited from firewalls on the path
  CAP_FILTER="(host ${DST_IP} and ${PROTO} port ${PORT}) or icmp or icmp6"
  mn_sudo_init || exit 2
  NSTAT_A="$(mktemp)"; NSTAT_B="$(mktemp)"
  trap 'mn_capture_stop >/dev/null; rm -f "$NSTAT_A" "$NSTAT_B" "$NC_ERR"' EXIT
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
FAIL_REASONS=""
if [[ "$UDP" -eq 0 ]]; then
  # Probe-validate options against this nc build instead of trusting `nc -h`
  nc_rejects "${nc_args[@]}" && die "this nc rejects options: ${nc_args[*]} (nc -h to check)"
  # -v: make nc report why a connect failed (shown next to FAILED)
  if nc_supports_v && ! nc_rejects "${nc_args[@]}" -v; then nc_args+=(-v); fi
  if [[ -n "$SRC_BASE" ]] && nc_rejects "${nc_args[@]}" -p "$SRC_BASE"; then
    # e.g. minimal BusyBox nc: -p only works with -l -> first available fallback wins
    TCP_BIN=""
    for c in socat python3 perl; do
      if has_cmd "$c"; then TCP_BIN="$c"; break; fi
    done
    [[ -n "$TCP_BIN" ]] || die "this nc can't set a source port for outgoing connects (-s); need one of: socat, python3, perl, netcat-openbsd"
    echo "Note: this nc can't bind a source port; using ${TCP_BIN} for -s" >&2
  fi
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
    if [[ "$TCP_BIN" == "socat" ]]; then
      # connect from fixed src port, send nothing (/dev/null EOF), close
      sc_host="$HOST"; [[ "$sc_host" == *:* && "$sc_host" != \[* ]] && sc_host="[$sc_host]"
      connect_ms="$(run_nc_timed -T "$TIMEOUT_S" /dev/null \
        "TCP:${sc_host}:${PORT},sourceport=${src_port},connect-timeout=${TIMEOUT_S}")"
      rc=$?
    elif [[ "$TCP_BIN" == "python3" || "$TCP_BIN" == "perl" ]]; then
      connect_ms="$(probe_script "$src_port" 2>"$NC_ERR")"
      rc=$?
    else
      # -z (if supported): just scan/listen check (no data), -w: timeout, -p: fixed src port.
      attempt_args=("${nc_args[@]}")
      [[ -n "$src_port" ]] && attempt_args+=(-p "$src_port")
      connect_ms="$(run_nc_timed "${attempt_args[@]}" "$HOST" "$PORT")"
      rc=$?
    fi
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
    # Elapsed time tells fast reject (RST / ICMP, ~RTT) from silence (~timeout)
    reason=""
    if [[ "$UDP" -eq 0 ]]; then
      reason="$(nc_fail_reason)"
      reason="${reason%.}"
      # nc variants word timeouts differently ("Operation now in progress", "TIMEOUT", ...)
      if [[ -n "$connect_ms" ]] &&
         awk -v ms="$connect_ms" -v t="$TIMEOUT_S" 'BEGIN { exit !(ms >= t * 900) }'; then
        reason="timeout (no answer)"
      fi
    else
      reason="no echo (timeout)"
    fi
    fail_info=""
    [[ -n "$connect_ms" ]] && fail_info="${connect_ms} ms"
    [[ -n "$reason" ]] && fail_info="${fail_info:+${fail_info}, }${reason}"
    echo "[$(date +%H:%M:%S)] Attempt $i: ${RED}FAILED${RESET}${fail_info:+ (${fail_info})}${src_tag}"
    FAIL_REASONS="${FAIL_REASONS}${reason:-unknown}"$'\n'
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
elif [[ "$SUCCESS" -eq 0 ]]; then
  echo "${TIME_LABEL}: ${DIM}n/a (no successful attempts)${RESET}"
else
  echo "${TIME_LABEL}: ${DIM}n/a (no samples; need bash 5+ EPOCHREALTIME or GNU date +%s%N)${RESET}"
fi
if [[ -n "$FAIL_REASONS" ]]; then
  echo "Failure reasons:"
  printf '%s' "$FAIL_REASONS" | sort | uniq -c | sort -rn | sed 's/^/  /'
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

