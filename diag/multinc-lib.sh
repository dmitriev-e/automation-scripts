# shellcheck shell=bash
# multinc-lib.sh — shared helpers for multinc.sh (initiator) and multinc-rx.sh (responder).
# Sourced, not executed. Needs: tcpdump, sudo (unless root), awk; nstat (iproute2) optional.

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
  grep -E "captured|dropped" "$MN_CAP_ERR" 2>/dev/null | sed 's/^/  tcpdump: /'
  rm -f "$MN_CAP_ERR" "$MN_CAP_PIDF"
}

# System-wide kernel counters relevant to handshake / UDP loss.
MN_NSTAT_KEYS="TcpExtTCPSynRetrans TcpAttemptFails TcpOutRsts TcpRetransSegs TcpExtListenOverflows TcpExtListenDrops TcpExtTCPReqQFullDrop TcpExtSyncookiesSent TcpExtTCPTimeouts UdpInErrors UdpRcvbufErrors UdpSndbufErrors UdpNoPorts"

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
    if (index($0, "port " port " ") || (peer != "" && index($0, " " peer " ")) || index($0, "unreachable port"))
      icmp_unreach++
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
  if (icmp_unreach > 0) printf "  %-20s %8d (any direction)\n", "ICMP unreachable", icmp_unreach

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
