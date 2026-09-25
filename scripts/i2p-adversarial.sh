#!/usr/bin/env bash
#
# The I2P suite: the product path end to end against a fake router, and the IA adversarial cases.
#
#   scripts/i2p-adversarial.sh <target/debug directory>
#
# The fake router is deterministic and hermetic: it answers the configured canary and nothing else.
# The outside world is a *separate network namespace* ("the far side") reached over a veth pair, with
# a listener and an nft counter on the far end. Every "nothing crossed" assertion is made there — at
# the actual far end of the path — never by reading interface byte counters.
#
# Classifications match the M7/M8 suites:
#   ok            the claim held, observed from outside the component under test
#   FAIL          a claim was contradicted — this is a finding
#   inconclusive  the observation cannot establish either way, and is never counted as a pass
#
# Requires: root, iproute2, nftables, python3, setpriv (util-linux).

set -uo pipefail
cd "$(dirname "$0")/.."

TARGET_DIR="${1:?usage: i2p-adversarial.sh <target/debug directory>}"
RUNDIR="/run/ghostnector"
BINDIR="/tmp/gh-i2p-bin"
WORKDIR="/tmp/gh-i2p"
CORE_USER="ghostnector-core"
LAUNCH_USER="ghostnector-launch-test"
ROUTER_USER="ghostnector-i2p-test"
FAR_NS="gh-i2p-far"
VETH_ROOT="gh-i2p-root"
VETH_FAR="gh-i2p-far"
ROOT_ADDR="10.90.0.1"
FAR_ADDR="10.90.0.2"
BOUNDARY_ADDR="203.0.113.10"
BOUNDARY_PORT="8080"
I2P_HTTP_PORT="14444"
I2P_SOCKS_PORT="14447"
CONTROL_PORT="9051"
NETD_PID=""
CORE_PID=""
ROUTER_PID=""
FAR_PID=""
PROBE_PID=""

PASSED=0
FAILED=0
INCONCLUSIVE=0

cleanup() {
    for pid in "$PROBE_PID" "$ROUTER_PID" "$FAR_PID" "$CORE_PID" "$NETD_PID"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    ip netns del "$FAR_NS" 2>/dev/null || true
    ip link del "$VETH_ROOT" 2>/dev/null || true
    nft destroy table inet ghostnector 2>/dev/null || true
    rm -rf "$BINDIR" "$WORKDIR"
}
trap cleanup EXIT

ok() { echo "  ok: $*"; PASSED=$((PASSED + 1)); }
bad() { echo "  FAIL: $*"; FAILED=$((FAILED + 1)); }
inc() { echo "  inconclusive: $*"; INCONCLUSIVE=$((INCONCLUSIVE + 1)); }
note() { echo "    $*"; }

fail_setup() {
    echo "FAIL(setup): $*" >&2
    for log in "$WORKDIR/core.log" "$WORKDIR/netd.log" "$WORKDIR/router.log" \
        "$WORKDIR/router-stdout.log" "$WORKDIR/far.log"; do
        [ -f "$log" ] && { echo "--- $log ---"; tail -20 "$log"; }
    done
    exit 2
}

[ "$(id -u)" = "0" ] || fail_setup "this test needs root"

for user in "$CORE_USER" "$LAUNCH_USER"; do
    id -u "$user" >/dev/null 2>&1 || fail_setup "the user $user must exist (the M8 suites create it)"
done
if ! id -u "$ROUTER_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$ROUTER_USER"
fi
CORE_UID="$(id -u "$CORE_USER")"
CORE_GID="$(id -g "$CORE_USER")"
LAUNCH_UID="$(id -u "$LAUNCH_USER")"
LAUNCH_GID="$(id -g "$LAUNCH_USER")"
ROUTER_UID="$(id -u "$ROUTER_USER")"
ROUTER_GID="$(id -g "$ROUTER_USER")"

mkdir -p "$BINDIR" "$WORKDIR" "$RUNDIR" "$WORKDIR/root/etc"
printf 'nameserver 192.0.2.53\n' >"$WORKDIR/root/etc/resolv.conf"
for binary in ghostnector-netd ghostnector-core ghostnector ghostnector-dns; do
    install -m 0755 "$TARGET_DIR/$binary" "$BINDIR/$binary"
done
COOKIE="$WORKDIR/control_auth_cookie"
head -c 32 /dev/urandom >"$COOKIE"
chown -R "$CORE_UID" "$WORKDIR"
chmod 0755 "$RUNDIR"
chown "$CORE_UID" "$RUNDIR" 2>/dev/null || true
rm -f "$RUNDIR/core.sock" "$RUNDIR/netd.sock"

# ---------------------------------------------------------------- the far side: the outside world
ip netns add "$FAR_NS"
ip link add "$VETH_ROOT" type veth peer name "$VETH_FAR"
ip link set "$VETH_FAR" netns "$FAR_NS"
ip addr add "$ROOT_ADDR/24" dev "$VETH_ROOT"
ip link set "$VETH_ROOT" up
ip -n "$FAR_NS" addr add "$FAR_ADDR/24" dev "$VETH_FAR"
ip -n "$FAR_NS" addr add "$BOUNDARY_ADDR/24" dev "$VETH_FAR"
ip -n "$FAR_NS" link set "$VETH_FAR" up
ip -n "$FAR_NS" link set lo up
# The boundary address is reached over the veth, so a packet that arrives was really carried.
ip route add "$BOUNDARY_ADDR/32" via "$FAR_ADDR" dev "$VETH_ROOT"

# The far end counts and logs every arrival: this is the observation point.
ip netns exec "$FAR_NS" nft add table inet ghcount
ip netns exec "$FAR_NS" nft add chain inet ghcount input \
    '{ type filter hook input priority -10; policy accept; }'
ip netns exec "$FAR_NS" nft add rule inet ghcount input \
    ip daddr "$BOUNDARY_ADDR" counter comment '"boundary"'

: >"$WORKDIR/far-connections.log"
cat >"$WORKDIR/far.py" <<'PY'
import socket, sys, threading

log_path = sys.argv[1]
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("203.0.113.10", 8080))
srv.listen(16)
log = open(log_path, "a", buffering=1)


def handle(conn, peer):
    try:
        log.write(f"accepted from {peer[0]}\n")
        conn.recv(4096)
        conn.sendall(b"HTTP/1.0 200 OK\r\n\r\nclearnet-ok")
    except OSError:
        pass
    finally:
        conn.close()


while True:
    conn, peer = srv.accept()
    threading.Thread(target=handle, args=(conn, peer), daemon=True).start()
PY
ip netns exec "$FAR_NS" python3 "$WORKDIR/far.py" "$WORKDIR/far-connections.log" \
    >"$WORKDIR/far.log" 2>&1 &
FAR_PID=$!
sleep 0.3

# ---------------------------------------------------------------- the fake router
: >"$WORKDIR/router.log"
chown "$ROUTER_UID" "$WORKDIR/router.log"
cat >"$WORKDIR/fake-router.py" <<'PY'
"""A stand-in for i2pd: an HTTP proxy that answers the canary, and a SOCKS listener.

The point is not to be I2P; it is that the product path reaches *this* process with the router's own
uid, and that the canary's answer is the only thing that can produce a pass.
"""
import socket, sys, threading

http_port, socks_port, spoof_file, log_path = (
    int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
)
log = open(log_path, "a", buffering=1)


def serve_http():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", http_port))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        try:
            conn.settimeout(2)
            request = b""
            try:
                request = conn.recv(4096)
            except OSError:
                request = b""
            first = request.split(b"\r\n", 1)[0].decode(errors="replace")
            log.write(f"proxy: {first}\n")
            try:
                spoofing = open(spoof_file).read().strip() == "1"
            except OSError:
                spoofing = False
            if spoofing:
                conn.sendall(b"HTTP/1.0 200 OK\r\n\r\nspoofed-answer")
            else:
                conn.sendall(b"HTTP/1.0 200 OK\r\n\r\ni2p-ok")
        except OSError:
            pass
        conn.close()


def serve_socks():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", socks_port))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        log.write("socks: connection\n")
        conn.close()


threading.Thread(target=serve_socks, daemon=True).start()
serve_http()
PY
echo 0 >"$WORKDIR/spoof"
setpriv --reuid="$ROUTER_UID" --regid="$ROUTER_GID" --clear-groups \
    python3 "$WORKDIR/fake-router.py" "$I2P_HTTP_PORT" "$I2P_SOCKS_PORT" \
    "$WORKDIR/spoof" "$WORKDIR/router.log" >"$WORKDIR/router-stdout.log" 2>&1 &
ROUTER_PID=$!
sleep 0.3
[ "$(stat -c %u /proc/$ROUTER_PID 2>/dev/null)" = "$ROUTER_UID" ] ||
    fail_setup "the fake router did not start as uid $ROUTER_UID"

# ---------------------------------------------------------------- the stack
"$BINDIR/ghostnector-netd" --socket "$RUNDIR/netd.sock" --peer-uid "$CORE_UID" \
    --i2p-user "$ROUTER_USER" --i2p-http-port "$I2P_HTTP_PORT" --i2p-socks-port "$I2P_SOCKS_PORT" \
    --fallback-path "$WORKDIR/fail-closed.nft" >"$WORKDIR/netd.log" 2>&1 &
NETD_PID=$!
for _ in $(seq 1 60); do [ -S "$RUNDIR/netd.sock" ] && break; sleep 0.1; done
[ -S "$RUNDIR/netd.sock" ] || fail_setup "the firewall helper did not start"

setpriv --reuid="$CORE_UID" --regid="$CORE_GID" --clear-groups \
    --inh-caps +net_bind_service --ambient-caps +net_bind_service \
    "$BINDIR/ghostnector-core" \
    --socket "$RUNDIR/core.sock" --helper "$RUNDIR/netd.sock" \
    --journal "$WORKDIR/intent.json" --resolver-state "$WORKDIR/resolver.json" \
    --resolv-conf-root "$WORKDIR/root" \
    --services external --tor-cookie "$COOKIE" --tor-control-port "$CONTROL_PORT" \
    --tor-bootstrap-seconds 2 --dns-helper "$BINDIR/ghostnector-dns" \
    --i2p-ready-seconds 5 \
    --i2p-canary canary.i2p --i2p-canary-path / --i2p-canary-expect i2p-ok \
    --i2p-clearnet-check "$BOUNDARY_ADDR:$BOUNDARY_PORT" \
    --verify-interval 3 --verify-stale-after 60 --verify-timeout 3 \
    --group "$CORE_USER" >"$WORKDIR/core.log" 2>&1 &
CORE_PID=$!
for _ in $(seq 1 60); do [ -S "$RUNDIR/core.sock" ] && break; sleep 0.1; done
[ -S "$RUNDIR/core.sock" ] || fail_setup "the control plane did not start"

cli() {
    setpriv --reuid="$LAUNCH_UID" --regid="$LAUNCH_GID" --groups "$CORE_GID" \
        "$BINDIR/ghostnector" --socket "$RUNDIR/core.sock" "$@"
}
status() { cli status 2>&1; }

wait_for() { # wait_for <pattern> <seconds>
    for _ in $(seq 1 "$2"); do
        if status | grep -q "$1"; then return 0; fi
        sleep 1
    done
    return 1
}

boundary_packets() {
    local json
    json="$(ip netns exec "$FAR_NS" nft -j list chain inet ghcount input)"
    printf '%s' "$json" | python3 -c '
import json, sys
total = 0
for item in json.load(sys.stdin).get("nftables", []):
    rule = item.get("rule")
    if not rule or rule.get("comment") != "boundary":
        continue
    for expr in rule.get("expr", []):
        counter = expr.get("counter")
        if counter:
            total += counter.get("packets", 0)
print(total)
'
}

boundary_connections() {
    if [ -f "$WORKDIR/far-connections.log" ]; then wc -l <"$WORKDIR/far-connections.log"; else echo 0; fi
}

reach_as() { # reach_as <uid> <gid> -> "connected" or "blocked"
    local uid="$1" gid="$2"
    setpriv --reuid="$uid" --regid="$gid" --clear-groups \
        python3 - "$BOUNDARY_ADDR" "$BOUNDARY_PORT" <<'PY'
import socket, sys
s = socket.socket()
s.settimeout(4)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    print("connected")
except OSError:
    print("blocked")
PY
}

echo "=== I2P end to end and adversarial exposure ==="
echo "target: $TARGET_DIR"
echo

# ---------------------------------------------------------------- [1] APP+I2P is refused
echo "── IA-8: APP+I2P is refused and creates nothing"
if OUTPUT="$(cli connect --network i2p --scope app 2>&1)"; then
    bad "APP+I2P was accepted: $OUTPUT"
else
    case "$OUTPUT" in
    *"whole-system network only"*) ok "APP+I2P is refused with an explanation" ;;
    *) bad "the refusal was not explained: $OUTPUT" ;;
    esac
fi
if ip netns list 2>/dev/null | grep -q ghapp; then
    bad "the refused APP+I2P created a namespace"
else
    ok "no namespace was created"
fi

# ---------------------------------------------------------------- [2] the product path
echo "── the product path: connect, the router's egress, and Protected from evidence"
BEFORE_PACKETS="$(boundary_packets)"
BEFORE_CONNS="$(boundary_connections)"
if ! CONNECTED="$(cli connect --network i2p 2>&1)"; then
    echo "$CONNECTED"
    bad "connect --network i2p failed"
else
    case "$CONNECTED" in
    *"protected, but unverified"*) ok "the state starts degraded, as it must" ;;
    *) bad "unexpected connect output: $CONNECTED" ;;
    esac
    case "$CONNECTED" in
    *"through I2P"*) ok "the profile is reported as I2P" ;;
    *) bad "the profile was not reported: $CONNECTED" ;;
    esac
fi

# The one exemption works: the router's own uid reaches the far side.
if [ "$(reach_as "$ROUTER_UID" "$ROUTER_GID")" = "connected" ]; then
    ok "the router's own egress is carried (its exemption works)"
else
    bad "the router's own egress was blocked"
fi
AFTER_CONNS="$(boundary_connections)"
[ "$AFTER_CONNS" -gt "$BEFORE_CONNS" ] &&
    ok "the far side observed the router's connection at the boundary" ||
    bad "the far side saw no connection from the router"

# The kernel really has the I2P ruleset: no NAT chain, exactly the router's uid exempted.
TABLE="$(nft list table inet ghostnector 2>/dev/null)"
case "$TABLE" in
*"skuid $ROUTER_UID"*) ok "the kernel policy exempts the router's uid" ;;
*) bad "the kernel policy does not exempt the router's uid" ;;
esac
case "$TABLE" in
*"out_nat"*) bad "the I2P policy has a NAT chain" ;;
*) ok "the I2P policy has no NAT chain (no redirect is claimed)" ;;
esac
case "$TABLE" in
*"skuid $CORE_UID"*|*"skuid $LAUNCH_UID"*) bad "a non-router identity is exempted" ;;
*) ok "no non-router identity is exempted" ;;
esac

# The continuous probe: an ordinary identity must never reach the far side, at any moment.
: >"$WORKDIR/probe-success.log"
cat >"$WORKDIR/probe.py" <<'PY'
import socket, sys, time
while True:
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((sys.argv[1], int(sys.argv[2])))
        with open(sys.argv[3], "a") as log:
            log.write("reached\n")
    except OSError:
        pass
    finally:
        s.close()
    time.sleep(1)
PY
setpriv --reuid="$LAUNCH_UID" --regid="$LAUNCH_GID" --clear-groups \
    python3 "$WORKDIR/probe.py" "$BOUNDARY_ADDR" "$BOUNDARY_PORT" \
    "$WORKDIR/probe-success.log" >"$WORKDIR/probe.log" 2>&1 &
PROBE_PID=$!

if wait_for "protected — and verified" 25; then
    ok "the canary through the proxy turned the state into protected-and-verified"
else
    bad "the state never became verified: $(status)"
fi
if grep -q "proxy: GET http://canary.i2p/" "$WORKDIR/router.log"; then
    ok "the canary was fetched through the router's proxy"
else
    bad "the canary never reached the router"
fi

# ---------------------------------------------------------------- [3] the boundary denies everyone else
echo "── IA-1/IA-2: a non-router identity is denied at the boundary"
BEFORE_PACKETS="$(boundary_packets)"
BEFORE_CONNS="$(boundary_connections)"
TCP_RESULT="$(reach_as "$LAUNCH_UID" "$LAUNCH_GID")"
UDP_RESULT="$(setpriv --reuid="$LAUNCH_UID" --regid="$LAUNCH_GID" --clear-groups \
    python3 - "$BOUNDARY_ADDR" "$BOUNDARY_PORT" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
try:
    s.sendto(b"probe", (sys.argv[1], int(sys.argv[2])))
    s.recvfrom(64)
    print("answered")
except OSError:
    print("refused")
PY
)"
AFTER_PACKETS="$(boundary_packets)"
AFTER_CONNS="$(boundary_connections)"
note "tcp=$TCP_RESULT udp=$UDP_RESULT boundary_packets=$((AFTER_PACKETS - BEFORE_PACKETS)) connections=$((AFTER_CONNS - BEFORE_CONNS))"
[ "$TCP_RESULT" = "blocked" ] || bad "a non-router identity reached the boundary over TCP"
[ "$UDP_RESULT" = "refused" ] || bad "a non-router identity's UDP was not refused"
[ "$((AFTER_PACKETS - BEFORE_PACKETS))" = "0" ] ||
    bad "packets from a non-router identity arrived at the boundary"
[ "$((AFTER_CONNS - BEFORE_CONNS))" = "0" ] ||
    bad "the boundary accepted a connection from a non-router identity"
[ "$TCP_RESULT" = "blocked" ] && [ "$UDP_RESULT" = "refused" ] &&
    [ "$((AFTER_PACKETS - BEFORE_PACKETS))" = "0" ] &&
    [ "$((AFTER_CONNS - BEFORE_CONNS))" = "0" ] &&
    ok "nothing from a non-router identity arrived at the boundary"

# ---------------------------------------------------------------- [4] the proxies are not for the network
echo "── IA-6: the router's proxies are unreachable from outside"
if ip netns exec "$FAR_NS" timeout 3 bash -c \
    "echo > /dev/tcp/$ROOT_ADDR/$I2P_HTTP_PORT" 2>/dev/null; then
    bad "the HTTP proxy accepted a connection from the far side"
else
    ok "the HTTP proxy is closed to the network (the input guard holds)"
fi

# ---------------------------------------------------------------- [5] a wrong canary answer alarms
echo "── IA-7: a canary answered by something else is an alarm"
echo 1 >"$WORKDIR/spoof"
if wait_for "no traffic can leave" 20; then
    ok "the spoofed canary was noticed and the machine denied"
else
    bad "a spoofed canary did not alarm: $(status)"
fi
if nft list table inet ghostnector 2>/dev/null | grep -q "skuid $ROUTER_UID"; then
    bad "the I2P exemption survived the alarm"
else
    ok "the fail-closed baseline replaced the I2P policy"
fi
echo 0 >"$WORKDIR/spoof"

# ---------------------------------------------------------------- [6] a tampered ruleset alarms
echo "── IA-3: a tampered ruleset is noticed"
cli disconnect >/dev/null 2>&1
cli connect --network i2p >/dev/null 2>&1
wait_for "protected — and verified" 25 >/dev/null 2>&1
nft insert rule inet ghostnector out_filter meta l4proto tcp counter accept \
    comment '"hand edited during the test"' 2>/dev/null
if wait_for "no traffic can leave" 20; then
    ok "the injected accept was noticed and the machine denied"
else
    bad "an injected accept survived while I2P claimed protection: $(status)"
fi
if nft list table inet ghostnector 2>/dev/null | grep -q "hand edited"; then
    bad "the tampered policy survived the alarm"
else
    ok "the fail-closed baseline replaced the tampered policy"
fi

# ---------------------------------------------------------------- [7] the router dying alarms
echo "── IA-4: the router dying is noticed"
cli disconnect >/dev/null 2>&1
cli connect --network i2p >/dev/null 2>&1
wait_for "protected — and verified" 25 >/dev/null 2>&1
kill "$ROUTER_PID" 2>/dev/null || true
if wait_for "no traffic can leave" 20; then
    ok "the dead router was noticed and the machine denied"
else
    bad "I2P kept claiming protection with its router dead: $(status)"
fi

# ---------------------------------------------------------------- [8] transitions observed at the boundary
echo "── IA-5: transitions keep exactly one exemption, observed at the boundary"
setpriv --reuid="$ROUTER_UID" --regid="$ROUTER_GID" --clear-groups \
    python3 "$WORKDIR/fake-router.py" "$I2P_HTTP_PORT" "$I2P_SOCKS_PORT" \
    "$WORKDIR/spoof" "$WORKDIR/router.log" >"$WORKDIR/router-stdout2.log" 2>&1 &
ROUTER_PID=$!
sleep 0.3
cli disconnect >/dev/null 2>&1
cli connect --network i2p >/dev/null 2>&1
wait_for "protected — and verified" 25 >/dev/null 2>&1
# Under I2P, the router may leave; under the fail-closed baseline it may not.
if [ "$(reach_as "$ROUTER_UID" "$ROUTER_GID")" = "connected" ]; then
    ok "the router can leave while I2P is the active profile"
else
    inc "the router could not be observed leaving under I2P"
fi
cli panic >/dev/null 2>&1
if [ "$(reach_as "$ROUTER_UID" "$ROUTER_GID")" = "blocked" ]; then
    ok "under the fail-closed baseline the router is denied: the exemption did not survive"
else
    bad "the router could still leave under the fail-closed baseline"
fi
cli disconnect >/dev/null 2>&1
cli connect --network i2p >/dev/null 2>&1
wait_for "protected — and verified" 25 >/dev/null 2>&1
if [ "$(reach_as "$ROUTER_UID" "$ROUTER_GID")" = "connected" ]; then
    ok "the router's exemption came back only with the I2P profile"
else
    bad "the router could not leave after returning to I2P"
fi

# ---------------------------------------------------------------- [9] no metadata, and the boundary never leaked
echo "── IA-10: the interface carries no destinations, and the boundary never leaked"
if status | grep -q "canary.i2p"; then
    bad "the interface leaked the canary destination"
else
    ok "the interface does not name the canary destination"
fi
if status | grep -q "$BOUNDARY_ADDR"; then
    bad "the interface leaked a boundary address"
else
    ok "the interface does not name a boundary address"
fi
if [ -s "$WORKDIR/probe-success.log" ]; then
    note "$(cat "$WORKDIR/probe-success.log")"
    bad "an ordinary identity reached the boundary at some point during the run"
else
    ok "across every state and transition, an ordinary identity never reached the boundary"
fi

cli disconnect >/dev/null 2>&1
case "$(status)" in
*"traffic is not protected"*) ok "disconnect returned the machine to off" ;;
*) bad "disconnect did not return to off: $(status)" ;;
esac
nft list table inet ghostnector 2>/dev/null | grep -q ghostnector &&
    bad "the policy survived disconnect" ||
    ok "the policy is gone after disconnect"

echo
echo "=== summary ==="
echo "held:         $PASSED"
echo "contradicted: $FAILED"
echo "inconclusive: $INCONCLUSIVE"
[ "$FAILED" = "0" ] || exit 1
exit 0
