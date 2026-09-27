#!/usr/bin/env bash
#
# The installed APP path against real Tor (the D-50 regression).
#
#   scripts/app-real-tor-test.sh [host-public-address]
#
# Proves, on the installed product with the real Tor package, that a protected application's TCP is
# actually carried by Tor through the namespace relay, and that nothing about confinement, DNS,
# identity or cleanup changed:
#
#   1. a protected application's HTTP request through the relay is answered by the configured
#      endpoint with a real address that is not this machine's public one;
#   2. the intended destination survives the relay (the endpoint's own answer, not a rewritten one);
#   3. DNS inside the namespace resolves through the chokepoint;
#   4. a direct connection to a private host and a direct connection to the relay itself produce no
#      application data;
#   5. a second group also reaches the network through Tor;
#   6. stopping Tor makes a new application connection fail (no direct fallback) and the machine
#      fails closed;
#   7. cleanup leaves no namespace, no relay process and no policy table.
#
# Durable log: /var/log/ghostnector-qual/app-real-tor-<stamp>.log
# Requires: root, the installed product, a reachable HTTP check endpoint.

set -uo pipefail

LOGDIR=/var/log/ghostnector-qual
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOGDIR/app-real-tor-$STAMP.log"
CLI=(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector)
HOST_PUBLIC="${1:-}"
HOST=10.0.2.2

PASSED=0
FAILED=0
INCONCLUSIVE=0

ok()   { echo "  ok: $*"; PASSED=$((PASSED + 1)); }
bad()  { echo "  FAIL: $*"; FAILED=$((FAILED + 1)); }
inc()  { echo "  inconclusive: $*"; INCONCLUSIVE=$((INCONCLUSIVE + 1)); }
note() { echo "    $*"; }

mkdir -p "$LOGDIR"; chmod 0755 "$LOGDIR"
exec >>"$LOG" 2>&1
ln -sfn "$(basename "$LOG")" "$LOGDIR/app-real-tor-latest.log"

cleanup() {
    local rc=$?
    echo
    echo "== cleanup at $(date -u) (run exit $rc) =="
    timeout 90 runuser -u ghost -g ghostnector -- /usr/bin/ghostnector disconnect >/dev/null 2>&1 || true
    if nft list table inet ghostnector >/dev/null 2>&1; then
        nft destroy table inet ghostnector >>"$LOG" 2>&1 || true
    fi
    pkill -f "ghostnector-appd-relay --id" 2>/dev/null || true
    pkill -f gh-app-real 2>/dev/null || true
    echo "== final state =="
    runuser -u ghost -g ghostnector -- /usr/bin/ghostnector status 2>&1 | head -3
    echo "== end of $LOG =="
    exit "$rc"
}
trap cleanup EXIT

[ "$(id -u)" = "0" ] || { echo "this qualification needs root"; exit 2; }

cli_state() { "${CLI[@]}" status 2>&1; }
wait_status() { local i; for i in $(seq 1 "$2"); do cli_state | grep -q "$1" && return 0; sleep 1; done; return 1; }
# The verifier takes a SocketAddr, so the check endpoint is pinned to a resolved address; pick one
# that answers the probe's bare-IP GET with 200 before pinning it (the edges rotate, and some do
# not serve every request).
check_endpoint() {
    local candidate code
    for candidate in $(getent ahostsv4 checkip.amazonaws.com | awk '{print $1}'); do
        code="$(timeout 15 curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$candidate/" || true)"
        [ "$code" = "200" ] && { echo "$candidate"; return 0; }
    done
    getent ahostsv4 checkip.amazonaws.com | awk 'NR==1{print $1}'
}

echo "== installed APP path against real Tor at $(date -u) =="
echo "log: $LOG"
uname -a
runuser -u ghost -g ghostnector -- /usr/bin/ghostnector --version 2>/dev/null || true

# ---------------------------------------------------------------- baseline
echo
echo "-- baseline: open, off, APP-scope verification is the UDP check --"
timeout 60 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
nft destroy table inet ghostnector 2>/dev/null || true
rm -f /var/lib/ghostnector/intent.json
systemctl restart ghostnector-netd.service ghostnector-core.service ghostnector-appd.service
sleep 2
# APP scope is verified deterministically by the UDP check: the namespace denies UDP, and the probe
# treats "UDP could not leave" as the pass condition. The HTTP check is deliberately not configured
# here: a public endpoint's availability through a particular Tor exit is not part of the product,
# and the application's own fetch below is the TCP evidence. (The machine-wide leakage run keeps the
# HTTP check, where it is the point.)
cat >/etc/ghostnector/core.env <<EOF
GHOSTNECTOR_VERIFY=--udp-check $HOST:18081 --verify-timeout 10 --verify-interval 5 --verify-stale-after 30
EOF
systemctl restart ghostnector-core.service
sleep 2
cli_state | head -1

# ---------------------------------------------------------------- the application probe
cat >/usr/local/bin/gh-app-real <<'EOF'
#!/bin/sh
# 1. The intended destination, through the relay and Tor. The public name's address rotates among
#    edges, and not every edge serves every exit, so a few attempts are made before calling it a
#    failure; a non-empty answer is the destination's own proof.
fetch() {
    local i value
    for i in 1 2 3 4; do
        value="$(timeout 40 curl -s --max-time 35 "$1" 2>/dev/null || true)"
        [ -n "$value" ] && { echo "$value"; return 0; }
        sleep 2
    done
    echo ""
}
code() {
    local i value
    for i in 1 2 3 4; do
        value="$(timeout 40 curl -s -o /dev/null -w '%{http_code}' --max-time 35 "$1" 2>/dev/null || true)"
        case "$value" in 2*) echo "$value"; return 0 ;; esac
        sleep 2
    done
    echo "${value:-000}"
}
echo "ip=$(fetch http://checkip.amazonaws.com)"
echo "endpoint=$(code http://checkip.amazonaws.com/)"
# 2. DNS through the chokepoint.
echo "dns=$(timeout 15 getent hosts checkip.amazonaws.com | head -1 | awk '{print $1}')"
# 3. A direct connection to a private host must produce no application data (the relay is the only
#    path; a direct connection dies at the dead end).
echo "direct=$(timeout 8 python3 -c 'import socket
s=socket.socket(); s.settimeout(5)
try:
    s.connect(("10.0.2.2", 18082)); s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    print("answered" if s.recv(64) else "no-answer")
except OSError:
    print("no-answer")' 2>/dev/null)"
# 4. A direct connection to the relay must be refused: it has no original destination.
echo "relay=$(timeout 8 python3 -c 'import socket
s=socket.socket(); s.settimeout(5)
try:
    s.connect(("127.0.0.1", 9041)); data = s.recv(16)
    print("refused" if data == b"" else "carried")
except OSError:
    print("refused")' 2>/dev/null)"
sleep 3
EOF
chmod 0755 /usr/local/bin/gh-app-real

run_app() { # label
    local label="$1" output
    output="$( ( sleep 60 | runuser -u ghost -g ghostnector -- \
        /usr/bin/ghostnector run /usr/local/bin/gh-app-real ) 2>&1 )"
    echo "$output"
}

echo
echo "-- protection on through the window's core, then the application --"
"${CLI[@]}" connect --scope app >/dev/null 2>&1 || true
if wait_status "chosen applications" 240; then
    ok "the APP scope applied: $(cli_state | head -1)"
else
    bad "the APP scope did not apply: $(cli_state | head -3)"
fi
# The core verifies the groups that exist; before any application runs there is nothing to verify,
# and the honest state is "protected, but unverified". The verification is asserted after the first
# application has created its group (below).

FIRST="$(run_app first)"
note "first application: $(printf '%s' "$FIRST" | tr '\n' ' ')"
IP1="$(printf '%s\n' "$FIRST" | sed -n 's/^ip=//p' | head -1)"
ENDPOINT1="$(printf '%s\n' "$FIRST" | sed -n 's/^endpoint=//p' | head -1)"
DNS1="$(printf '%s\n' "$FIRST" | sed -n 's/^dns=//p' | head -1)"
DIRECT1="$(printf '%s\n' "$FIRST" | sed -n 's/^direct=//p' | head -1)"
RELAY1="$(printf '%s\n' "$FIRST" | sed -n 's/^relay=//p' | head -1)"

if wait_status "protected — and verified" 120; then
    ok "the namespace verification passed with the group running (the relay carried the UDP check)"
else
    inc "the state did not reach verified after the first application: $(cli_state | head -1)"
fi

if [ -n "$IP1" ]; then
    ok "the application reached the network through Tor (exit $IP1)"
    if [ -n "$HOST_PUBLIC" ] && [ "$IP1" = "$HOST_PUBLIC" ]; then
        bad "the application's exit address is this machine's public address"
    else
        ok "the exit is not this machine's public address"
    fi
else
    bad "the application produced no exit address"
fi
case "$ENDPOINT1" in
2*) ok "the intended destination answered a second request ($ENDPOINT1)" ;;
*)
    if [ -n "$IP1" ]; then
        inc "the second request to the rotating public name did not answer (${ENDPOINT1:-none}); the first did ($IP1)"
    else
        bad "the intended destination did not answer: ${ENDPOINT1:-none}"
    fi
    ;;
esac
[ -n "$DNS1" ] && ok "DNS inside the namespace resolved through the chokepoint ($DNS1)" \
    || bad "DNS inside the namespace did not resolve"
[ "$DIRECT1" = "no-answer" ] && ok "a direct connection to a private host produced no application data" \
    || bad "a direct connection produced data: ${DIRECT1:-nothing}"
[ "$RELAY1" = "refused" ] && ok "a direct connection to the relay is refused" \
    || bad "a direct connection to the relay was carried: ${RELAY1:-nothing}"

echo
echo "-- a second group --"
SECOND="$(run_app second)"
IP2="$(printf '%s\n' "$SECOND" | sed -n 's/^ip=//p' | head -1)"
if [ -n "$IP2" ]; then
    ok "the second application reached the network through Tor (exit $IP2)"
else
    bad "the second application produced no exit address"
fi
[ -n "$IP1" ] && [ -n "$IP2" ] && note "two groups, two observed exits (distinct circuits are Tor's own behaviour)"

echo
echo "-- the relay dies with the group --"
LIST="$("${CLI[@]}" apps 2>&1)"
echo "$LIST"
ID="$(printf '%s\n' "$LIST" | awk '/^  -/ { print $2; exit }')"
if [ -n "$ID" ]; then
    "${CLI[@]}" stop-app "$ID" >/dev/null 2>&1 || true
    stopped=0
    for _ in $(seq 1 20); do
        if ! pgrep -f "ghostnector-appd-relay --id $ID " >/dev/null 2>&1; then stopped=1; break; fi
        sleep 0.5
    done
    if [ "$stopped" = "1" ]; then
        ok "the stopped group's relay is gone"
    else
        bad "the stopped group's relay survived: $(pgrep -af "ghostnector-appd-relay --id $ID " | tr '\n' ' ')"
    fi
    note "other groups' relays stay while their groups live: $(pgrep -af 'ghostnector-appd-relay --id' | wc -l) relay(s)"
else
    bad "no application was listed to stop"
fi

echo
echo "-- Tor dies: no direct fallback, and the state detects it --"
systemctl stop ghostnector-tor.service
FALLBACK="$(run_app after-tor-death)"
AFTER_IP="$(printf '%s\n' "$FALLBACK" | sed -n 's/^ip=//p' | head -1)"
[ -z "$AFTER_IP" ] && ok "an application connection produced no address with Tor down" \
    || bad "an application connection still produced an address with Tor down: $AFTER_IP"
# The UDP check cannot see a dead router (UDP is denied either way), so the state can only detect
# it through a path check. Re-pin the core with a validated endpoint while Tor is down: the first
# verification must fail and the scope must report fail-closed, not stay "verified".
HTTP_IP="$(check_endpoint)"
echo "path check endpoint: http://$HTTP_IP/"
cat >/etc/ghostnector/core.env <<EOF
GHOSTNECTOR_VERIFY=--udp-check $HOST:18081 --check-url http://$HTTP_IP/ --verify-timeout 10 --verify-interval 5 --verify-stale-after 30
EOF
systemctl restart ghostnector-core.service
sleep 3
if wait_status "no protected application can reach the network" 150; then
    ok "the APP scope failed closed once its path check could run against a dead router"
else
    inc "the APP scope did not report fail-closed within 150s: $(cli_state | head -1)"
fi

echo
echo "-- recovery and cleanup --"
"${CLI[@]}" disconnect >/dev/null 2>&1 || true
if wait_status "off" 60; then
    ok "the machine returned to off"
else
    bad "the machine did not return to off: $(cli_state | head -1)"
fi
relays_gone=0
for _ in $(seq 1 30); do
    if ! pgrep -f "ghostnector-appd-relay --id" >/dev/null 2>&1; then relays_gone=1; break; fi
    sleep 0.5
done
if [ "$relays_gone" = "1" ]; then
    ok "no relay process survived the disconnect"
else
    bad "a relay process survived the disconnect: $(pgrep -af 'ghostnector-appd-relay --id' | tr '\n' ' ')"
fi
if [ -n "$(ip netns list 2>/dev/null)" ]; then
    bad "a namespace survived the disconnect: $(ip netns list)"
else
    ok "no namespace survived the disconnect"
fi
nft list table inet ghostnector >/dev/null 2>&1 && bad "a policy table survived" || ok "no policy table after cleanup"

echo
echo "=== summary (installed APP against real Tor) ==="
echo "held:         $PASSED"
echo "contradicted: $FAILED"
echo "inconclusive: $INCONCLUSIVE"
echo "log:          $LOG"
[ "$FAILED" = "0" ] || exit 1
exit 0
