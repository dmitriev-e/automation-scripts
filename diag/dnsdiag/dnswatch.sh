#!/usr/bin/env bash
set -u
export LC_ALL=C

# Description: passively watch DNS traffic on an interface and report which queries
# to the given NS servers were answered, which were answered too slowly, and which
# got no answer at all.
# Useful for catching intermittent resolver loss and latency spikes that a synthetic
# probe like multidig.sh would miss, because it observes the real query stream.
#
# Usage:
#   ./dnswatch.sh <interface> <ns_ip[,ns_ip...]>
#   ./dnswatch.sh -I <iface> -s <ns_list> [-w <slow_ms>] [-T <timeout_ms>] [-d <sec>]
#                 [-u <unanswered_log>] [-S <slow_log>] [-p <port>] [-q] [-r <file>]
#
# Examples:
#   ./dnswatch.sh eth0 8.8.8.8,1.1.1.1
#   ./dnswatch.sh -I any -s 10.0.0.53 -w 50 -T 1000 -d 300 -q
#   ./dnswatch.sh -r captured.txt -s 8.8.8.8          # offline replay, no root needed
#
# Output:
#   [10:00:00.123] OK    8.8.8.8   example.com   A     12.3 ms  id=42381 NOERROR
#   [10:00:01.456] SLOW  8.8.8.8   slow.test     AAAA 247.8 ms  id=13947 NOERROR
#   [10:00:03.500] LOST  8.8.8.8   dead.test     A    >2000 ms  id=51002
#   [10:00:04.900] LATE  8.8.8.8   dead.test     A   3401.2 ms  id=51002
#
# Categories:
#   OK    answered within -w
#   SLOW  answered later than -w, but before we gave up on it
#   LOST  no answer within -T; written to the unanswered log
#   LATE  answer arrived after we had already declared the query LOST
#
# Limitations (deliberate, see docs/superpowers/specs/2026-07-29-dnswatch-design.md):
#   - UDP only; TCP-DNS (truncated/AXFR) and DoT/DoH are out of scope
#   - -s takes IPv4 addresses only
#   - VLAN-tagged traffic is not matched by the 'udp port 53' BPF filter
#   - no log rotation; that is logrotate's job
#   - the timezone offset is sampled at startup, so a DST switch mid-run shifts
#     timestamps by an hour

IFACE=""
NS_LIST=""
SLOW_MS=100
TIMEOUT_MS=2000
DURATION=0
UNANSWERED_LOG="./dns-unanswered.log"
SLOW_LOG="./dns-slow.log"
PORT=53
QUIET=0
REPLAY=""

# How often the ticker injects a synthetic "now" into the stream. Expiry is only
# swept on those ticks, so this is also the detection granularity for LOST.
TICK_INTERVAL=0.5

die() {
  echo "Error: $*" >&2
  exit 2
}

usage() {
  cat >&2 <<'EOF'
Usage:
  dnswatch.sh <interface> <ns_ip[,ns_ip...]>
  dnswatch.sh -I <iface> -s <ns_list> [-w <slow_ms>] [-T <timeout_ms>] [-d <sec>]
              [-u <unanswered_log>] [-S <slow_log>] [-p <port>] [-q] [-r <file>]

Options:
  -I iface        Interface to listen on ('any' is allowed on Linux)
  -s ns_list      Comma-separated NS server IPv4 addresses (e.g. 8.8.8.8,1.1.1.1)
  -w slow_ms      Answer slower than this is SLOW (default: 100)
  -T timeout_ms   No answer within this is LOST (default: 2000)
  -d sec          Stop after N seconds (default: 0 = run until Ctrl-C)
  -u path         Log file for unanswered queries (default: ./dns-unanswered.log)
  -S path         Log file for slow/late answers (default: ./dns-slow.log)
  -p port         DNS port (default: 53)
  -q              Do not print OK lines to stdout
  -r file         Replay a saved tcpdump text dump instead of capturing live

Exit codes:
  0  no lost queries
  1  at least one query was lost
  2  bad arguments or capture failure
EOF
  exit 2
}

is_pos_int() { [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]; }
is_nonneg_int() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

valid_ipv4() {
  local ip="${1:-}" octet
  [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  local IFS=.
  for octet in $ip; do
    # 10# guards against octets like 08 being read as octal.
    [[ $((10#$octet)) -le 255 ]] || return 1
  done
  return 0
}

# Parse args (supports both positional and flags for backwards compatibility).
if [[ $# -eq 2 && "${1:-}" != -* && "${2:-}" != -* ]]; then
  IFACE="$1"
  NS_LIST="$2"
else
  while getopts ":I:s:w:T:d:u:S:p:qr:" opt; do
    case "$opt" in
      I) IFACE="$OPTARG" ;;
      s) NS_LIST="$OPTARG" ;;
      w) SLOW_MS="$OPTARG" ;;
      T) TIMEOUT_MS="$OPTARG" ;;
      d) DURATION="$OPTARG" ;;
      u) UNANSWERED_LOG="$OPTARG" ;;
      S) SLOW_LOG="$OPTARG" ;;
      p) PORT="$OPTARG" ;;
      q) QUIET=1 ;;
      r) REPLAY="$OPTARG" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  [[ $# -eq 0 ]] || usage
fi

[[ -n "$NS_LIST" ]] || usage

if [[ -n "$REPLAY" ]]; then
  [[ -z "$IFACE" ]] || die "-r and -I are mutually exclusive"
  [[ -r "$REPLAY" ]] || die "cannot read replay file '$REPLAY'"
else
  [[ -n "$IFACE" ]] || usage
fi

is_nonneg_int "$SLOW_MS" || die "'$SLOW_MS' is not a non-negative integer"
is_nonneg_int "$TIMEOUT_MS" || die "'$TIMEOUT_MS' is not a non-negative integer"
is_nonneg_int "$DURATION" || die "'$DURATION' is not a non-negative integer"
is_pos_int "$PORT" || die "'$PORT' is not a positive integer"
[[ "$PORT" -le 65535 ]] || die "'$PORT' is not a valid port (1-65535)"
[[ "$SLOW_MS" -le "$TIMEOUT_MS" ]] || \
  die "slow threshold ($SLOW_MS ms) must not exceed lost threshold ($TIMEOUT_MS ms), otherwise SLOW is unreachable"

# Normalise and validate the NS list.
NS_ARR=()
OLD_IFS="$IFS"
IFS=','
for ns in $NS_LIST; do
  [[ -n "$ns" ]] || continue
  case "$ns" in
    *:*) die "'$ns' looks like IPv6; only IPv4 NS addresses are supported" ;;
  esac
  valid_ipv4 "$ns" || die "'$ns' is not a valid IPv4 address"
  NS_ARR+=("$ns")
done
IFS="$OLD_IFS"
[[ ${#NS_ARR[@]} -gt 0 ]] || die "no NS addresses given"

NS_JOINED=""
for ns in "${NS_ARR[@]}"; do
  NS_JOINED="${NS_JOINED:+$NS_JOINED,}$ns"
done

# Fail early rather than after the first slow answer arrives.
: >>"$UNANSWERED_LOG" || die "cannot write to '$UNANSWERED_LOG'"
: >>"$SLOW_LOG" || die "cannot write to '$SLOW_LOG'"

if [[ -z "$REPLAY" ]]; then
  has_cmd tcpdump || die "'tcpdump' not found (install tcpdump)"
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Warning: not running as root; capture will fail unless tcpdump has CAP_NET_RAW" >&2
  fi
fi

if [[ -t 1 ]]; then
  C_OK=$'\033[32m'
  C_SLOW=$'\033[33m'
  C_LOST=$'\033[31m'
  C_LATE=$'\033[35m'
  DIM=$'\033[2m'
  RESET=$'\033[0m'
else
  C_OK=""; C_SLOW=""; C_LOST=""; C_LATE=""; DIM=""; RESET=""
fi

# awk has no strftime in mawk/busybox, so local time is computed by hand from a
# fixed offset. Sampling it once also makes replay output deterministic.
TZ_RAW="$(date +%z 2>/dev/null || echo '+0000')"
case "$TZ_RAW" in
  [+-][0-9][0-9][0-9][0-9]) ;;
  *) TZ_RAW="+0000" ;;
esac
TZ_OFF=$(( 10#${TZ_RAW:1:2} * 3600 + 10#${TZ_RAW:3:2} * 60 ))
[[ "${TZ_RAW:0:1}" == "-" ]] && TZ_OFF=$(( -TZ_OFF ))

now_epoch() {
  if [[ "${BASH_VERSINFO[0]:-0}" -ge 5 ]] && [[ -n "${EPOCHREALTIME+x}" ]]; then
    printf '%s\n' "$EPOCHREALTIME"
    return 0
  fi
  local t
  t="$(date +%s.%N 2>/dev/null || true)"
  # BSD date without %N support leaves a literal 'N' behind.
  case "$t" in
    ""|*N) t="$(date +%s)" ;;
  esac
  printf '%s\n' "$t"
}

# Injects a synthetic clock into the same stream tcpdump writes to. awk has no
# timers, and "no answer arrived" is the absence of data, so it needs an external
# heartbeat to notice that a query has aged out.
ticker() {
  while :; do
    sleep "$TICK_INTERVAL"
    printf 'TICK %s\n' "$(now_epoch)"
  done
}

capture() {
  local rc=0 ticker_pid td_pid

  ticker &
  ticker_pid=$!

  # -l line-buffered, -nn no name resolution (resolving would generate the very
  # DNS traffic we are watching), -tt absolute epoch timestamps, -p no promiscuous
  # mode, -s 512 enough for the DNS header and question section.
  if [[ "$DURATION" -gt 0 ]]; then
    if has_cmd timeout; then
      timeout "${DURATION}s" tcpdump -i "$IFACE" -l -nn -tt -p -s 512 "$FILTER"
      rc=$?
    else
      tcpdump -i "$IFACE" -l -nn -tt -p -s 512 "$FILTER" &
      td_pid=$!
      ( sleep "$DURATION"; kill -TERM "$td_pid" 2>/dev/null ) &
      wait "$td_pid"
      rc=$?
    fi
  else
    tcpdump -i "$IFACE" -l -nn -tt -p -s 512 "$FILTER"
    rc=$?
  fi

  kill "$ticker_pid" 2>/dev/null

  # 124 = timeout(1) fired, 130/143 = SIGINT/SIGTERM. Anything else means tcpdump
  # itself failed, and without this awk would print an empty summary and exit 0.
  case "$rc" in
    0|124|130|143) ;;
    *) printf 'FATAL %s\n' "$rc" ;;
  esac
}

read -r -d '' AWK_PROG <<'AWK_END'
function last_dot(a,   i) {
  for (i = length(a); i > 0; i--) if (substr(a, i, 1) == ".") return i
  return 0
}
function addr_ip(a,   p) { p = last_dot(a); return p ? substr(a, 1, p - 1) : a }
function addr_port(a,   p) { p = last_dot(a); return p ? substr(a, p + 1) : "" }

# tcpdump suffixes the transaction id with flag characters: 42381+, 42381*-, 42381|
function norm_txid(t) { gsub(/[^0-9]/, "", t); return t }

# Sets globals cy/cm/cd. Howard Hinnant's civil_from_days.
function civil(z,   era, doe, yoe, y, doy, mp, d, m) {
  z += 719468
  era = int((z >= 0 ? z : z - 146096) / 146097)
  doe = z - era * 146097
  yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
  y = yoe + era * 400
  doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
  mp = int((5 * doy + 2) / 153)
  d = doy - int((153 * mp + 2) / 5) + 1
  m = mp + (mp < 10 ? 3 : -9)
  cy = y + (m <= 2); cm = m; cd = d
}
function frac_ms(t,   ms) {
  ms = int((t - int(t)) * 1000 + 0.5)
  return ms > 999 ? 999 : ms
}
function hms(t,   lt, secs) {
  lt = int(t) + tzoff
  secs = lt % 86400
  if (secs < 0) secs += 86400
  return sprintf("%02d:%02d:%02d.%03d", int(secs / 3600), int((secs % 3600) / 60), secs % 60, frac_ms(t))
}
function ymdhms(t,   lt, days, secs) {
  lt = int(t) + tzoff
  days = int(lt / 86400)
  secs = lt - days * 86400
  if (secs < 0) { secs += 86400; days-- }
  civil(days)
  return sprintf("%04d-%02d-%02d %02d:%02d:%02d.%03d", cy, cm, cd,
                 int(secs / 3600), int((secs % 3600) / 60), secs % 60, frac_ms(t))
}

function color_of(tag) {
  if (tag == "OK") return c_ok
  if (tag == "SLOW") return c_slow
  if (tag == "LOST") return c_lost
  return c_late
}
function emit(tag, t, ns, qname, qtype, rtt_str, txid, rcode) {
  if (tag == "OK" && quiet) return
  printf("[%s] %s%-4s%s %-15s %-28s %-5s %9s  id=%s%s\n",
         hms(t), color_of(tag), tag, c_reset, ns, qname, qtype, rtt_str, txid,
         rcode == "" ? "" : " " rcode)
  fflush()
}
function log_unans(t, ns, client, txid, qname, qtype) {
  printf("%s LOST ns=%s client=%s id=%s qname=%s qtype=%s waited_ms=%d\n",
         ymdhms(t), ns, client, txid, qname, qtype, timeout_ms) >> unans_file
  fflush(unans_file)
}
function log_slow(tag, t, ns, client, txid, qname, qtype, rtt, rcode) {
  printf("%s %s ns=%s client=%s id=%s qname=%s qtype=%s rtt_ms=%.1f rcode=%s\n",
         ymdhms(t), tag, ns, client, txid, qname, qtype, rtt, rcode) >> slow_file
  fflush(slow_file)
}

function add_rtt(ns, v) {
  if (rtt_n[ns] == 0) { rtt_min[ns] = v; rtt_max[ns] = v }
  else {
    if (v < rtt_min[ns]) rtt_min[ns] = v
    if (v > rtt_max[ns]) rtt_max[ns] = v
  }
  rtt_n[ns]++
  rtt_sum[ns] += v
}

function drop_pend(k) {
  delete pend_ts[k]; delete pend_qname[k]; delete pend_qtype[k]
  delete pend_client[k]; delete pend_ns[k]; delete pend_txid[k]
}
function drop_dead(k) {
  delete dead_ts[k]; delete dead_qname[k]; delete dead_qtype[k]
  delete dead_client[k]; delete dead_ns[k]; delete dead_txid[k]
}

function report_lost(k, now,   ns) {
  ns = pend_ns[k]
  lost[ns]++
  total_lost++
  emit("LOST", now, ns, pend_qname[k], pend_qtype[k],
       sprintf(">%d ms", timeout_ms), pend_txid[k], "")
  log_unans(now, ns, pend_client[k], pend_txid[k], pend_qname[k], pend_qtype[k])

  dead_ts[k] = pend_ts[k]; dead_qname[k] = pend_qname[k]
  dead_qtype[k] = pend_qtype[k]; dead_client[k] = pend_client[k]
  dead_ns[k] = ns; dead_txid[k] = pend_txid[k]
  drop_pend(k)
}

# Only ever called on a tick. Sweeping on every packet would make the whole run
# O(packets * in-flight), which on a busy resolver is the difference between
# negligible and unusable.
function sweep(now,   k, i, n, keys) {
  n = 0
  for (k in pend_ts) if (now - pend_ts[k] > timeout_s) { n++; keys[n] = k }
  for (i = 1; i <= n; i++) report_lost(keys[i], now)
  delete keys

  n = 0
  for (k in dead_ts) if (now - dead_ts[k] > dead_ttl) { n++; keys[n] = k }
  for (i = 1; i <= n; i++) drop_dead(keys[i])
  delete keys
}

function scan_question(from,   i, tok) {
  # EDNS puts a marker between the txid and the qtype: "42381+ [1au] A? name."
  for (i = from; i <= NF; i++) {
    tok = $i
    if (tok ~ /\?$/) {
      qtype = substr(tok, 1, length(tok) - 1)
      qname = (i < NF) ? $(i + 1) : "?"
      sub(/\.$/, "", qname)
      if (qtype == "") qtype = "?"
      if (qname == "") qname = "?"
      return 1
    }
  }
  qtype = "?"; qname = "?"
  return 0
}
function scan_rcode(from,   i) {
  for (i = from; i <= NF; i++)
    if ($i ~ /^(NXDomain|ServFail|Refused|FormErr|NotImp|YXDomain|YXRRSet|NXRRSet|NotAuth|NotZone)$/)
      return $i
  return "NOERROR"
}

BEGIN {
  n_ns = split(ns_list, arr, ",")
  for (i = 1; i <= n_ns; i++) {
    ns = arr[i]
    ns_order[i] = ns
    is_ns[ns] = 1
    seen[ns] = 0; ok[ns] = 0; slow[ns] = 0; lost[ns] = 0; late[ns] = 0; collided[ns] = 0
    rtt_n[ns] = 0; rtt_sum[ns] = 0; rtt_min[ns] = 0; rtt_max[ns] = 0
  }
  timeout_s = timeout_ms / 1000.0
  dead_ttl = timeout_s * 2
  first_ts = 0; last_ts = 0; total_lost = 0; fatal = 0
}

$1 == "FATAL" { fatal = $2 + 0; next }

$1 == "TICK" {
  now = $2 + 0
  if (now > 0) { if (now > last_ts) last_ts = now; sweep(now) }
  next
}

{
  # Field positions are not fixed: on `-i any` with SLL2, tcpdump prepends the
  # interface name and direction. Anchor on the "> " separator instead.
  gt = 0
  for (i = 2; i < NF; i++) if ($i == ">") { gt = i; break }
  if (gt < 3 || gt + 2 > NF) next

  dst = $(gt + 1)
  if (dst !~ /:$/) next
  sub(/:$/, "", dst)
  src = $(gt - 1)

  ts = $1 + 0
  if (ts <= 0) next
  if (first_ts == 0) first_ts = ts
  if (ts > last_ts) last_ts = ts

  sip = addr_ip(src); sport = addr_port(src)
  dip = addr_ip(dst); dport = addr_port(dst)
  txid = norm_txid($(gt + 2))
  if (txid == "") next

  if (dport + 0 == port && (dip in is_ns)) {
    ns = dip
    key = ns SUBSEP sport SUBSEP txid
    # Client reused (port, txid) while the previous query was still in flight.
    # The old one becomes unaccountable, so count it rather than let the summary
    # silently fail to add up.
    if (key in pend_ts) collided[ns]++
    scan_question(gt + 3)
    pend_ts[key] = ts; pend_qname[key] = qname; pend_qtype[key] = qtype
    pend_client[key] = sip ":" sport; pend_ns[key] = ns; pend_txid[key] = txid
    seen[ns]++
    next
  }

  if (sport + 0 == port && (sip in is_ns)) {
    ns = sip
    key = ns SUBSEP dport SUBSEP txid
    rcode = scan_rcode(gt + 3)

    if (key in pend_ts) {
      rtt = (ts - pend_ts[key]) * 1000.0
      if (rtt < 0) rtt = 0
      # Anything answered before the sweep declared it lost counts as answered,
      # even if it nominally exceeded -T between two ticks.
      if (rtt <= slow_ms) {
        ok[ns]++
        emit("OK", ts, ns, pend_qname[key], pend_qtype[key],
             sprintf("%.1f ms", rtt), txid, rcode)
      } else {
        slow[ns]++
        emit("SLOW", ts, ns, pend_qname[key], pend_qtype[key],
             sprintf("%.1f ms", rtt), txid, rcode)
        log_slow("SLOW", ts, ns, pend_client[key], txid,
                 pend_qname[key], pend_qtype[key], rtt, rcode)
      }
      add_rtt(ns, rtt)
      drop_pend(key)
    } else if (key in dead_ts) {
      rtt = (ts - dead_ts[key]) * 1000.0
      late[ns]++
      emit("LATE", ts, ns, dead_qname[key], dead_qtype[key],
           sprintf("%.1f ms", rtt), txid, rcode)
      log_slow("LATE", ts, ns, dead_client[key], txid,
               dead_qname[key], dead_qtype[key], rtt, rcode)
      drop_dead(key)
    }
    # else: a response to a query we never saw (we started mid-flight) - ignore.
    next
  }
}

END {
  if (fatal) {
    printf("Error: tcpdump exited with code %d (see messages above)\n", fatal) > "/dev/stderr"
    exit 2
  }

  for (k in pend_ns) pending[pend_ns[k]]++

  ran = (first_ts > 0 && last_ts > first_ts) ? last_ts - first_ts : 0
  printf("---------------------------------------\n")
  printf("Summary (ran %d s):\n", int(ran + 0.5))
  for (i = 1; i <= n_ns; i++) {
    ns = ns_order[i]
    answered = ok[ns] + slow[ns]
    printf("\nNS %s:\n", ns)
    printf("  Queries seen:      %d\n", seen[ns])
    if (seen[ns] > 0) {
      printf("  Answered in time:  %d  (%.1f%%)\n", answered, answered * 100.0 / seen[ns])
      printf("  Slow answers:      %d\n", slow[ns])
      printf("  Lost:              %d  (%.1f%%)\n", lost[ns], lost[ns] * 100.0 / seen[ns])
    } else {
      printf("  Answered in time:  0\n")
      printf("  Slow answers:      0\n")
      printf("  Lost:              0\n")
    }
    printf("    of them late:    %d\n", late[ns])
    printf("  Pending at exit:   %d\n", pending[ns] + 0)
    if (collided[ns] > 0)
      printf("  Dropped (dup id):  %d\n", collided[ns])
    if (rtt_n[ns] > 0)
      printf("  RTT ms:            min %.1f / avg %.1f / max %.1f  %s(%d samples)%s\n",
             rtt_min[ns], rtt_sum[ns] / rtt_n[ns], rtt_max[ns], dim, rtt_n[ns], c_reset)
    else
      printf("  RTT ms:            %sn/a (no answered queries)%s\n", dim, c_reset)
  }
  printf("---------------------------------------\n")
  exit (total_lost > 0 ? 1 : 0)
}
AWK_END

run_awk() {
  # SIG_IGN survives exec, so awk outlives the Ctrl-C that kills tcpdump and still
  # reaches its END block. Without this the summary is lost exactly when it matters.
  trap '' INT
  exec awk \
    -v ns_list="$NS_JOINED" \
    -v port="$PORT" \
    -v slow_ms="$SLOW_MS" \
    -v timeout_ms="$TIMEOUT_MS" \
    -v tzoff="$TZ_OFF" \
    -v quiet="$QUIET" \
    -v c_ok="$C_OK" -v c_slow="$C_SLOW" -v c_lost="$C_LOST" -v c_late="$C_LATE" \
    -v dim="$DIM" -v c_reset="$RESET" \
    'BEGIN { unans_file = ENVIRON["DNSWATCH_UNANS"]; slow_file = ENVIRON["DNSWATCH_SLOW"] }
     '"$AWK_PROG"
}

export DNSWATCH_UNANS="$UNANSWERED_LOG"
export DNSWATCH_SLOW="$SLOW_LOG"

if [[ -n "$REPLAY" ]]; then
  echo "--- Replaying ${REPLAY} for NS ${NS_JOINED} (slow > ${SLOW_MS} ms, lost > ${TIMEOUT_MS} ms) ---"
  run_awk <"$REPLAY"
else
  hosts=""
  for ns in "${NS_ARR[@]}"; do
    hosts="${hosts:+$hosts or }host $ns"
  done
  FILTER="udp port ${PORT} and (${hosts})"

  echo "--- Watching DNS on ${IFACE} for NS ${NS_JOINED} (slow > ${SLOW_MS} ms, lost > ${TIMEOUT_MS} ms) ---"
  capture | run_awk
fi
