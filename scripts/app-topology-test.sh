#!/usr/bin/env bash
#
# The APP-scope topology assumption, proved against the real kernel (M8.0).
#
#   scripts/app-topology-test.sh
#
# This is the executable form of the experiment that corrected the old "no default route"
# formulation. It creates a throwaway namespace that is wired exactly like an APP namespace will be
# and asserts three things:
#
#   1. A namespace with no route to the destination cannot even start an intercepted connection:
#      `connect()` fails with ENETUNREACH *before* the netns-local DNAT chain runs. Literal
#      route-lessness is therefore not the mechanism; it would break every application instead of
#      protecting it.
#   2. A default route into a dead-end dummy device plus a netns-local DNAT carries a connection to
#      a host-local core address, with the application's source address preserved.
#   3. With the DNAT gone, the same connection dies locally: nothing reaches the host veth, not even
#      an ARP request. That is the approved fail-closed property — a flushed rule cannot create a
#      path, because the only route leads to a device with no peer and the host is never involved.
#
# Nothing here uses the real Ghostnector binaries: it pins the kernel behaviour the APP design rests
# on. The M8 adversarial suite (AA class) extends it to the real components.
#
# Requires: root, iproute2, nftables, python3, tcpdump.

set -euo pipefail

NS="gh-app-topology"
HOST_IF="gh-topo-h"
NS_IF="gh-topo-n"
DEAD_IF="ghdead"
HOST_ADDR="10.230.0.1"
NS_ADDR="10.230.0.2"
CORE_PORT="19099"
# TEST-NET-2: a destination that must never be reached without an explicit path.
DEST_ADDR="198.51.100.10"

LISTENER_PID=""
HOSTV_PID=""
WORK="$(mktemp -d /tmp/gh-app-topology.XXXXXX)"

cleanup() {
    [ -n "$LISTENER_PID" ] && kill "$LISTENER_PID" 2>/dev/null || true
    [ -n "$HOSTV_PID" ] && kill "$HOSTV_PID" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
ok() { echo "  ok: $*"; }
note() { echo "    $*"; }

[ "$(id -u)" = "0" ] || fail "this test needs root"
command -v tcpdump >/dev/null || fail "tcpdump is required to observe the host veth"
command -v nft >/dev/null || fail "nftables is required"
command -v python3 >/dev/null || fail "python3 is required"

# ---------------------------------------------------------------- a namespace, wired once
ip netns add "$NS"
ip link add "$HOST_IF" type veth peer name "$NS_IF"
ip link set "$NS_IF" netns "$NS"
ip addr add "$HOST_ADDR/30" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip -n "$NS" addr add "$NS_ADDR/30" dev "$NS_IF"
ip -n "$NS" link set "$NS_IF" up
ip -n "$NS" link set lo up
# The design disables IPv6 inside an APP namespace; doing it here keeps IPv6 control traffic out of
# the capture so the observation is about the IPv4 path.
ip netns exec "$NS" sysctl -qw net.ipv6.conf.all.disable_ipv6=1

# The dead end and the netns-local DNAT chain start empty: the first case is the literal
# route-less namespace.
ip -n "$NS" link add "$DEAD_IF" type dummy
ip -n "$NS" link set "$DEAD_IF" up
ip netns exec "$NS" nft add table inet ghapp
ip netns exec "$NS" nft 'add chain inet ghapp out { type nat hook output priority -100 ; }'

cat >"$WORK/listener.py" <<'PY'
import socket, sys
host, port, log, ready = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
server.listen(4)
server.settimeout(30)
with open(ready, "w") as flag:
    flag.write("ready\n")
with open(log, "a") as record:
    try:
        while True:
            connection, peer = server.accept()
            record.write(f"ACCEPT from {peer[0]}:{peer[1]}\n")
            record.flush()
            connection.close()
    except OSError:
        pass
PY

cat >"$WORK/probe.py" <<'PY'
import socket, sys
target, port = sys.argv[1], int(sys.argv[2])
sock = socket.socket()
sock.settimeout(3)
try:
    sock.connect((target, port))
    print("connect OK")
except Exception as error:
    print(f"connect {type(error).__name__}: {error}")
finally:
    sock.close()
PY

wait_for_listener() {
    for _ in $(seq 1 40); do
        [ -f "$WORK/listener.ready" ] && return 0
        sleep 0.05
    done
    return 1
}

python3 "$WORK/listener.py" "$HOST_ADDR" "$CORE_PORT" "$WORK/listener.log" "$WORK/listener.ready" \
    >"$WORK/listener.out" 2>&1 &
LISTENER_PID=$!
wait_for_listener || fail "the host-local listener did not start"

dnat_on() {
    ip netns exec "$NS" nft 'add rule inet ghapp out meta l4proto tcp dnat ip to 10.230.0.1:19099'
}
dnat_off() {
    ip netns exec "$NS" nft flush chain inet ghapp out
}

echo "[1] a literally route-less namespace cannot carry an intercepted connection"
: >"$WORK/listener.log"
ANSWER="$(ip netns exec "$NS" python3 "$WORK/probe.py" "$DEST_ADDR" 443)"
note "the probe said '$ANSWER'"
case "$ANSWER" in
*"Network is unreachable"*)
    ok "connect() was refused before the DNAT chain could run (ENETUNREACH)"
    ;;
*)
    fail "a namespace with no route unexpectedly reached the DNAT path: $ANSWER"
    ;;
esac
[ -s "$WORK/listener.log" ] && fail "the host listener saw traffic with no route in place"
ok "the host listener saw nothing"

echo "[2] a dead-end default route plus netns-local DNAT carries the connection, source preserved"
ip -n "$NS" route add default dev "$DEAD_IF"
dnat_on
: >"$WORK/listener.log"
ANSWER="$(ip netns exec "$NS" python3 "$WORK/probe.py" "$DEST_ADDR" 443)"
note "the probe said '$ANSWER'"
case "$ANSWER" in
*"connect OK"*) ok "the connection reached the host-local core address through the DNAT" ;;
*) fail "the DNAT path did not carry the connection: $ANSWER" ;;
esac
grep -q "ACCEPT from $NS_ADDR:" "$WORK/listener.log" ||
    fail "the listener did not record the application's own source address: $(cat "$WORK/listener.log")"
ok "the source address was preserved ($NS_ADDR), so no masquerade is involved"

echo "[3] with the DNAT gone, the connection dies locally and the host veth sees nothing"
dnat_off
# Close the listener and clear the host's neighbour entry first: otherwise the host may refresh it
# and the namespace's ARP *reply* to that host-initiated query is counted as a crossing, which it is
# not. The property is that the application cannot make the namespace send anything.
kill "$LISTENER_PID" 2>/dev/null || true
wait "$LISTENER_PID" 2>/dev/null || true
LISTENER_PID=""
ip neigh flush dev "$HOST_IF" 2>/dev/null || true
# Truncate, never unlink: the file is the record and a stale inode would read as "nothing happened"
# (D-04). The listener is gone, so nothing holds it open.
: >"$WORK/listener.log"
: >"$WORK/crossed.log"
# `-Q in` observes only frames the namespace sent: the property is about what leaves it, and the
# host's own ARP/IPv6 link-local chatter must not be mistaken for it (the D-02 lesson).
( timeout 8 tcpdump -n -Q in -i "$HOST_IF" -c 50 'arp or ip or ip6' >"$WORK/crossed.log" 2>/dev/null || true ) &
HOSTV_PID=$!
sleep 0.5
ANSWER="$(ip netns exec "$NS" python3 "$WORK/probe.py" "$DEST_ADDR" 443)"
note "the probe said '$ANSWER'"
case "$ANSWER" in
*"connect OK"*) fail "a connection succeeded with the DNAT removed" ;;
*) ok "the connection could not be made" ;;
esac
wait "$HOSTV_PID" 2>/dev/null || true
HOSTV_PID=""
CROSSED="$(grep -cE '^(ARP,|IP |IP6 )' "$WORK/crossed.log" 2>/dev/null || true)"
if [ "$CROSSED" != "0" ]; then
    echo "  ── what the host veth saw ──"
    sed 's/^/    /' "$WORK/crossed.log"
    fail "the host veth saw $CROSSED frame(s) with the DNAT removed"
fi
[ -s "$WORK/listener.log" ] && fail "the host listener saw traffic with the DNAT removed"
ok "no packet, no ARP, and no host involvement: the failure mode is a local dead end"

echo
echo "PASS: APP topology (dead-end route, DNAT-only path, source preservation)"
