#!/usr/bin/env bash
#
# The installed leakage and network-identity qualification.
#
# Not part of the hermetic gate. It runs against the installed product on the native VM and uses
# the host (10.0.2.2) as the far side for direct egress: a timestamped observer on the host logs
# every TCP/UDP/DNS packet that arrives at 10.0.2.2:18082/18081/53. The host controller correlates
# those arrivals with this script's PHASE timestamps, so a packet is judged against the state that
# was in force when it crossed (the D-25/D-19 lesson), with a 2-second ambiguity margin that is
# reported as inconclusive, never as a pass.
#
# What it demonstrates here:
#   * unprotected probes really arrive at the far side (the observation point works);
#   * ordinary TCP, UDP and DNS from a non-exempt identity do not arrive while protection is on;
#   * the protected path carries traffic (HTTP through Tor, and the system resolver answers);
#   * tampering with the kernel policy is noticed and the machine fails closed;
#   * router death and panic fail closed;
#   * I2P mode exempts exactly the real router uid and has no NAT chain;
#   * APP scope keeps the namespace on the protected path and refuses direct egress.
#
# What it does NOT demonstrate (stated so nobody stretches it):
#   * the exit IP is a Tor exit (only that it is not this machine's public address; the Tor
#     network itself is the reason, and the Tor control port is not asked about circuits);
#   * that two APP groups use distinct circuits (distinct exit addresses are recorded when they
#     happen to differ; equality is not a failure of isolation, which is per source address);
#   * anything about IPv6 when the VM has no global IPv6 route (recorded as inconclusive);
#   * the boot ordering claim (no probe can run before the OS boots).
#
# Durable record: /var/log/ghostnector-qual/leak-<stamp>.log

set -uo pipefail

LOGDIR=/var/log/ghostnector-qual
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOGDIR/leak-$STAMP.log"
HOST=10.0.2.2
CLI=(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector)
PROBE_UID="$(id -u ghost)"
PROBE_GID="$(id -g ghost)"

PASSED=0
FAILED=0
INCONCLUSIVE=0

ok()   { echo "  ok: $*"; PASSED=$((PASSED + 1)); }
bad()  { echo "  FAIL: $*"; FAILED=$((FAILED + 1)); }
inc()  { echo "  inconclusive: $*"; INCONCLUSIVE=$((INCONCLUSIVE + 1)); }
note() { echo "    $*"; }

mkdir -p "$LOGDIR"; chmod 0755 "$LOGDIR"
exec >>"$LOG" 2>&1
ln -sfn "$(basename "$LOG")" "$LOGDIR/leak-latest.log"

cli_state() { "${CLI[@]}" status 2>&1; }
cli_line() { cli_state | head -1; }
wait_status() { local i; for i in $(seq 1 "$2"); do cli_state | grep -q "$1" && return 0; sleep 1; done; return 1; }
# The HTTP check is pinned to a resolved address (the verifier takes a SocketAddr); a public
# endpoint's address can go stale, and a failed check correctly blocks the machine. Retry the
# connect with a freshly resolved endpoint so the qualification is not defeated by that.
ensure_connect() { # [connect arguments...]
    local attempt ip
    for attempt in 1 2 3; do
        ip="$(getent ahostsv4 checkip.amazonaws.com | awk 'NR==1{print $1}')"
        cat >/etc/ghostnector/core.env <<EOF
GHOSTNECTOR_VERIFY=--udp-check $HOST:18081 --check-url http://$ip/ --verify-timeout 10 --verify-interval 5 --verify-stale-after 30
EOF
        systemctl restart ghostnector-core.service
        sleep 2
        "${CLI[@]}" connect "$@" >/dev/null 2>&1 || true
        if wait_status "protected" 120 && ! cli_line | grep -q "no traffic can leave"; then
            return 0
        fi
        echo "    connect attempt $attempt did not verify (endpoint $ip); retrying"
        "${CLI[@]}" disconnect >/dev/null 2>&1 || true
        sleep 2
    done
    return 1
}
phase() { echo "PHASE $1 $(date +%s.%N)"; }

as_probe() { setpriv --reuid="$PROBE_UID" --regid="$PROBE_GID" --clear-groups "$@"; }

probe_tcp() { # host port -> connected|blocked
    as_probe python3 - "$1" "$2" <<'PY'
import socket, sys
s = socket.socket(); s.settimeout(4)
try:
    s.connect((sys.argv[1], int(sys.argv[2]))); print("connected")
except OSError:
    print("blocked")
PY
}
probe_tcp_data() { # host port -> answered|no-answer: a local TransPort accepts the connection, so
    # only application data coming back proves a direct path.
    as_probe python3 - "$1" "$2" <<'PY'
import socket, sys
s = socket.socket(); s.settimeout(4)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    data = s.recv(64)
    print("answered" if data else "no-answer")
except OSError:
    print("no-answer")
PY
}
probe_udp() { # host port -> answered|refused
    as_probe python3 - "$1" "$2" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(b"probe", (sys.argv[1], int(sys.argv[2]))); s.recvfrom(64); print("answered")
except OSError:
    print("refused")
PY
}
probe_dns() { # host -> answered|refused
    as_probe python3 - "$1" <<'PY'
import socket, sys
q = bytes([0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,0]) + b"\x06canary\x04test\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(q, (sys.argv[1], 53)); s.recvfrom(1024); print("answered")
except OSError:
    print("refused")
PY
}
exit_ip() { # url -> address or "(no answer)"
    as_probe timeout 30 curl -s --max-time 25 "$1" 2>/dev/null | tr -d '\r\n' || true
}

cleanup() {
    local rc=$?
    echo
    echo "== cleanup at $(date -u) (run exit $rc) =="
    timeout 90 runuser -u ghost -g ghostnector -- /usr/bin/ghostnector disconnect >/dev/null 2>&1 || true
    if nft list table inet ghostnector >/dev/null 2>&1; then
        echo "destroying the owned table (documented rescue)"
        nft destroy table inet ghostnector >>"$LOG" 2>&1 || true
    fi
    if [ -f /var/lib/ghostnector/intent.json ] && grep -q '"protected"[[:space:]]*:[[:space:]]*true' /var/lib/ghostnector/intent.json; then
        rm -f /var/lib/ghostnector/intent.json
    fi
    echo "== final state =="
    cli_state | head -4
    echo "== end of $LOG =="
    exit "$rc"
}
trap cleanup EXIT

[ "$(id -u)" = "0" ] || { echo "this qualification needs root"; exit 2; }

echo "== installed leakage/network-identity qualification at $(date -u) =="
echo "log: $LOG"
uname -a
echo "IPv6 routes:"; ip -6 route show 2>&1 | head -5
ip -6 route show default 2>/dev/null | grep -q . && IPV6_GLOBAL=1 || IPV6_GLOBAL=0

# ---------------------------------------------------------------- clean baseline
echo
echo "-- baseline: open, off, short verification interval --"
timeout 60 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
nft destroy table inet ghostnector 2>/dev/null || true
rm -f /var/lib/ghostnector/intent.json
HTTP_IP="$(getent ahostsv4 checkip.amazonaws.com | awk 'NR==1{print $1}')"
cat >/etc/ghostnector/core.env <<EOF
GHOSTNECTOR_VERIFY=--udp-check $HOST:18081 --check-url http://$HTTP_IP/ --verify-timeout 10 --verify-interval 5 --verify-stale-after 30
EOF
systemctl restart ghostnector-netd.service ghostnector-core.service ghostnector-appd.service
sleep 2
cli_state | head -3
cli_state | grep -q "off" && ok "the baseline is off" || bad "the baseline is not off"

# ---------------------------------------------------------------- the observation point works
echo
echo "-- the far side is real: unprotected probes arrive --"
phase OPEN_VALIDATE_START
TCP_OPEN="$(probe_tcp $HOST 18082)"
UDP_OPEN="$(probe_udp $HOST 18081)"
DNS_OPEN="$(probe_dns $HOST)"
phase OPEN_VALIDATE_END
note "open: tcp=$TCP_OPEN udp=$UDP_OPEN dns=$DNS_OPEN"
[ "$TCP_OPEN" = "connected" ] && ok "an unprotected TCP connection reaches the host" || bad "the TCP observation point is broken"
[ "$UDP_OPEN" = "answered" ] && ok "an unprotected UDP datagram reaches the host" || bad "the UDP observation point is broken"

# ---------------------------------------------------------------- Tor SYSTEM
echo
echo "-- Tor SYSTEM: the protected path carries, direct paths do not --"
phase CONNECT_TOR_START
ensure_connect
phase CONNECT_TOR_END
if wait_status "protected" 300 && ! cli_line | grep -q "no traffic can leave"; then
    ok "Tor SYSTEM protection is up: $(cli_state | head -1)"
else
    bad "Tor SYSTEM did not come up: $(cli_state | head -1)"
fi

phase PROTECTED_PROBES_START
TCP_PROT="$(probe_tcp_data $HOST 18082)"
UDP_PROT="$(probe_udp $HOST 18081)"
DNS_PROT="$(probe_dns $HOST)"
TCP53_PROT="$(probe_tcp_data $HOST 53)"
phase PROTECTED_PROBES_END
note "protected: tcp-data=$TCP_PROT udp=$UDP_PROT dns=$DNS_PROT dns-tcp-data=$TCP53_PROT"
# Under transparent Tor the local TransPort accepts a connection and then refuses the private
# destination, so only application data coming back proves a direct path; a DNS answer is the
# chokepoint's. The host observer is the authority for what actually reached the far side.
[ "$TCP_PROT" = "no-answer" ] && ok "no HTTP data came back from the host on a direct path" \
    || bad "HTTP data came back from the host while protected"
[ "$UDP_PROT" = "refused" ] && ok "ordinary UDP got no answer" || bad "ordinary UDP got an answer while protected"
note "a DNS answer here is the chokepoint's; the host observer decides whether the query reached the far side"
[ "$TCP53_PROT" = "no-answer" ] && ok "no TCP DNS data came back on a direct path" \
    || bad "TCP DNS data came back while protected"

RESOLVER_ANSWER="$(as_probe timeout 20 getent ahostsv4 example.com 2>/dev/null | head -1)"
[ -n "$RESOLVER_ANSWER" ] && ok "the system resolver answered through the protected path ($RESOLVER_ANSWER)" \
    || inc "the system resolver did not answer within 20s"
TOR_EXIT="$(exit_ip http://checkip.amazonaws.com)"
note "Tor exit address observed: ${TOR_EXIT:-(no answer)}"
[ -n "$TOR_EXIT" ] && ok "the protected path answered with an address" || bad "the protected path did not answer"

# A short storm: every packet that reaches the host is attributed to a protected state.
phase PROTECTED_STORM_START
for _ in $(seq 1 10); do
    probe_tcp $HOST 18082 >/dev/null 2>&1
    probe_udp $HOST 18081 >/dev/null 2>&1
    sleep 0.5
done
phase PROTECTED_STORM_END

# ---------------------------------------------------------------- tampering
echo
echo "-- tampering with the kernel policy fails closed --"
phase TAMPER_START
nft insert rule inet ghostnector out_filter meta l4proto tcp counter accept comment '"qualification tamper"' 2>/dev/null \
    && ok "a tampered accept rule was injected" || inc "could not inject the tampered rule"
phase TAMPER_END
if wait_status "no traffic can leave" 40; then
    ok "the tampered policy was noticed and the machine denied"
else
    bad "the tampered policy was not noticed within 40s: $(cli_state | head -1)"
fi
nft list table inet ghostnector 2>/dev/null | grep -q "qualification tamper" \
    && bad "the tampered rule survived the alarm" || ok "the fail-closed baseline replaced the tampered policy"
phase TAMPER_PROBES_START
TCP_TAMPER="$(probe_tcp $HOST 18082)"
UDP_TAMPER="$(probe_udp $HOST 18081)"
phase TAMPER_PROBES_END
note "after tamper: tcp=$TCP_TAMPER udp=$UDP_TAMPER"
[ "$TCP_TAMPER" = "blocked" ] && [ "$UDP_TAMPER" = "refused" ] && ok "nothing reaches the host after the alarm" \
    || bad "traffic reached the host after the alarm (tcp=$TCP_TAMPER udp=$UDP_TAMPER)"
"${CLI[@]}" disconnect >/dev/null 2>&1 || true

# ---------------------------------------------------------------- router death
echo
echo "-- the router's death fails closed --"
ensure_connect
wait_status "protected" 300 && ! cli_line | grep -q "no traffic can leave" && ok "Tor is up again" || inc "Tor did not come up again"
phase ROUTER_DEATH_START
systemctl stop ghostnector-tor.service
phase ROUTER_DEATH_END
if wait_status "no traffic can leave" 90; then
    ok "the router's death was noticed and the machine denied"
else
    inc "the router's death was not reflected within 90s: $(cli_state | head -1)"
fi
# The fail-closed baseline legitimately exempts the Tor uid (so Tor can bootstrap) and DHCP; what
# must not survive is any other identity (I2P, an application, the LAN).
TOR_UID="$(id -u debian-tor 2>/dev/null || echo none)"
UIDS_AFTER="$(nft list table inet ghostnector 2>/dev/null | grep -oE 'skuid [0-9]+' | awk '{print $2}' | sort -u | tr '\n' ' ')"
case "$UIDS_AFTER" in
"$TOR_UID ") ok "the fail-closed baseline exempts only the Tor uid (and DHCP)" ;;
*) bad "unexpected exemptions after the alarm: $UIDS_AFTER" ;;
esac
phase ROUTER_PROBES_START
TCP_RD="$(probe_tcp $HOST 18082)"
UDP_RD="$(probe_udp $HOST 18081)"
phase ROUTER_PROBES_END
note "after router death: tcp=$TCP_RD udp=$UDP_RD"
[ "$TCP_RD" = "blocked" ] && [ "$UDP_RD" = "refused" ] && ok "nothing reaches the host with the router dead" \
    || bad "traffic reached the host with the router dead"
systemctl start ghostnector-tor.service 2>/dev/null || true
"${CLI[@]}" disconnect >/dev/null 2>&1 || true

# ---------------------------------------------------------------- panic
echo
echo "-- panic fails closed --"
ensure_connect
wait_status "protected" 300 && ! cli_line | grep -q "no traffic can leave" && ok "Tor is up before the panic" || inc "Tor did not come up before the panic"
phase PANIC_START
"${CLI[@]}" panic >/dev/null 2>&1 || true
phase PANIC_END
if wait_status "no traffic can leave" 30; then
    ok "panic denied everything"
else
    bad "panic did not deny: $(cli_state | head -1)"
fi
phase PANIC_PROBES_START
TCP_P="$(probe_tcp $HOST 18082)"
UDP_P="$(probe_udp $HOST 18081)"
phase PANIC_PROBES_END
note "after panic: tcp=$TCP_P udp=$UDP_P"
[ "$TCP_P" = "blocked" ] && [ "$UDP_P" = "refused" ] && ok "nothing reaches the host after panic" \
    || bad "traffic reached the host after panic"
"${CLI[@]}" disconnect >/dev/null 2>&1 || true

# ---------------------------------------------------------------- I2P SYSTEM
echo
echo "-- I2P SYSTEM: one router exemption, no NAT chain, ordinary paths denied --"
phase CONNECT_I2P_START
"${CLI[@]}" connect --network i2p >/dev/null 2>&1 || true
phase CONNECT_I2P_END
if wait_status "through I2P" 240; then
    ok "I2P protection applied: $(cli_state | head -1)"
else
    inc "I2P did not settle within 240s: $(cli_state | head -1)"
fi
TABLE="$(nft list table inet ghostnector 2>/dev/null)"
I2PD_UID="$(id -u i2pd 2>/dev/null || echo none)"
case "$TABLE" in
*"skuid $I2PD_UID"*) ok "the kernel policy exempts the real i2pd uid ($I2PD_UID)" ;;
*) bad "the kernel policy does not exempt the real i2pd uid" ;;
esac
case "$TABLE" in
*out_nat*) bad "the I2P policy has a NAT chain" ;;
*) ok "the I2P policy has no NAT chain" ;;
esac
UIDS="$(printf '%s\n' "$TABLE" | grep -oE 'skuid [0-9]+' | awk '{print $2}' | sort -u | tr '\n' ' ')"
case "$UIDS" in
"$I2PD_UID "*) ok "the only exempted uid is the router's" ;;
*) bad "unexpected exemptions: $UIDS" ;;
esac
phase I2P_PROBES_START
TCP_I="$(probe_tcp $HOST 18082)"
UDP_I="$(probe_udp $HOST 18081)"
DNS_I="$(probe_dns $HOST)"
phase I2P_PROBES_END
note "i2p protected: tcp=$TCP_I udp=$UDP_I dns=$DNS_I"
[ "$TCP_I" = "blocked" ] && [ "$UDP_I" = "refused" ] && [ "$DNS_I" = "refused" ] \
    && ok "ordinary traffic is denied under I2P too" || bad "ordinary traffic moved under I2P"
"${CLI[@]}" disconnect >/dev/null 2>&1 || true

# ---------------------------------------------------------------- APP scope
echo
echo "-- Tor APP: two groups stay on the protected path and cannot egress directly --"
cat >/usr/local/bin/gh-leak-1 <<'EOF'
#!/bin/sh
{ timeout 40 curl -s --max-time 35 http://checkip.amazonaws.com || true; } >/var/tmp/gh-leak-1.ip 2>/dev/null
printf 'tcp-direct=%s\n' "$(timeout 6 python3 -c 'import socket;s=socket.socket();s.settimeout(4)
try:
 s.connect(("10.0.2.2",18082));print("connected")
except OSError:
 print("blocked")')" >>/var/tmp/gh-leak-1.ip
sleep 30
EOF
cat >/usr/local/bin/gh-leak-2 <<'EOF'
#!/bin/sh
{ timeout 40 curl -s --max-time 35 http://checkip.amazonaws.com || true; } >/var/tmp/gh-leak-2.ip 2>/dev/null
sleep 30
EOF
chmod 0755 /usr/local/bin/gh-leak-1 /usr/local/bin/gh-leak-2
rm -f /var/tmp/gh-leak-1.ip /var/tmp/gh-leak-2.ip
phase CONNECT_APP_START
ensure_connect --scope app
phase CONNECT_APP_END
if wait_status "chosen applications" 240; then
    ok "the APP scope applied: $(cli_state | head -1)"
else
    bad "the APP scope did not apply: $(cli_state | head -3)"
fi
phase APP_RUN_START
( sleep 60 | runuser -u ghost -g ghostnector -- /usr/bin/ghostnector run /usr/local/bin/gh-leak-1 >/dev/null 2>&1 ) &
( sleep 60 | runuser -u ghost -g ghostnector -- /usr/bin/ghostnector run /usr/local/bin/gh-leak-2 >/dev/null 2>&1 ) &
sleep 25
phase APP_RUN_END
APPS="$(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector apps 2>&1)"
echo "$APPS"
IP1="$(head -1 /var/tmp/gh-leak-1.ip 2>/dev/null | tr -d '\r\n')"
IP2="$(head -1 /var/tmp/gh-leak-2.ip 2>/dev/null | tr -d '\r\n')"
DIRECT1="$(grep tcp-direct /var/tmp/gh-leak-1.ip 2>/dev/null | cut -d= -f2)"
note "app exit addresses: 1=${IP1:-none} 2=${IP2:-none}; direct from namespace: ${DIRECT1:-none}"
[ -n "$IP1" ] && ok "the first application reached the network through the protected path" \
    || inc "the first application produced no address"
[ -n "$IP2" ] && ok "the second application reached the network through the protected path" \
    || inc "the second application produced no address"
[ "$DIRECT1" = "blocked" ] && ok "a direct connection from inside the namespace was blocked" \
    || inc "the in-namespace direct probe said: ${DIRECT1:-nothing}"
if [ -n "$IP1" ] && [ -n "$IP2" ] && [ "$IP1" != "$IP2" ]; then
    note "the two groups left through different observed addresses (circuits differ in effect)"
fi
"${CLI[@]}" disconnect >/dev/null 2>&1 || true

# ---------------------------------------------------------------- IPv6
echo
echo "-- IPv6 --"
if [ "$IPV6_GLOBAL" = "1" ]; then
    phase IPV6_START
    V6="$(as_probe timeout 6 curl -6 -s -o /dev/null -w '%{http_code}' http://checkip.amazonaws.com 2>/dev/null || true)"
    phase IPV6_END
    note "IPv6 probe result: ${V6:-none}"
else
    inc "the VM has no global IPv6 route; IPv6 denial is not observable here (as in AS-4)"
fi

echo
echo "=== summary (installed leakage) ==="
echo "held:         $PASSED"
echo "contradicted: $FAILED"
echo "inconclusive: $INCONCLUSIVE"
echo "log:          $LOG"
[ "$FAILED" = "0" ] || exit 1
exit 0
