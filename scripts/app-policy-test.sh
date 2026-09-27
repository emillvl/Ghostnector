#!/usr/bin/env bash
#
# The rendered APP policies, against the real kernel (M8.1).
#
#   scripts/app-policy-test.sh
#
# Three things are proved here, none of which a unit test can prove:
#
#   1. Every golden policy parses and resolves against the kernel that will apply it. The D-20
#      lesson: a rendered rule can be refused by nftables ("No symbol type information"), and a
#      policy that cannot be applied protects nothing.
#   2. The namespace policy carries an application connection to the namespace relay, which speaks
#      SOCKS to the core address as the application's own address (so the intended destination and
#      the source identity both survive); DNS goes to the chokepoint; direct SOCKS is left alone;
#      and — when its DNAT is flushed — nothing reaches the host link. The M8.0 topology test proves
#      the kernel mechanics with hand-written rules; this proves the rules Ghostnector actually
#      renders and the relay Ghostnector actually ships.
#   3. The host policy admits the app link only to the core listeners the namespace may use (the
#      chokepoint and SOCKS; not the TransPort): a connection to an unadmitted port on the core
#      address is dropped, and traffic aimed elsewhere is dropped by the forward chain. The host
#      table has no output policy, so nothing here claims the machine is protected.
#
# Requires: root, iproute2, nftables, python3, tcpdump.

set -euo pipefail

HOST_NS="gh-app-host"
LINK_NS="gh-app-link"
HOST_IF="ghbr0"
LINK_IF="ghappv0"
NS_IF="gh-appp-n"
HOST_VETH="gh-appp-h"
CORE="10.200.0.1"
APP="10.200.0.2"
TRANS_PORT="9040"
SOCKS_PORT="9050"
DNS_PORT="53"
RELAY_PORT="9041"
UNADMITTED_PORT="80"
REMOTE="198.51.100.10"
WORK="$(mktemp -d /tmp/gh-app-policy.XXXXXX)"
GOLDEN="crates/ghostnector-policy/golden"
RELAY="${1:-$(pwd)/target/debug/ghostnector-appd-relay}"
RELAY_UID="$(id -u nobody 2>/dev/null || echo 65534)"

PIDS=()

cleanup() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    exec 9>&- 2>/dev/null || true
    ip netns del "$HOST_NS" 2>/dev/null || true
    ip netns del "$LINK_NS" 2>/dev/null || true
    ip netns del "gh-app-ns" 2>/dev/null || true
    ip link del "$HOST_VETH" 2>/dev/null || true
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
command -v nft >/dev/null || fail "nftables is required"
command -v tcpdump >/dev/null || fail "tcpdump is required"
[ -d "$GOLDEN" ] || fail "run this from the repository root"
[ -x "$RELAY" ] || fail "the namespace relay is not built at $RELAY (cargo build --workspace --bins)"

# The relay exits when its standard input closes: that is the helper's shutdown channel (the helper
# keeps the write end of a pipe). Start it the same way, with a pipe this shell holds open.
RELAY_STDIN="$WORK/relay.stdin"
mkfifo "$RELAY_STDIN"
exec 9<>"$RELAY_STDIN"

# ---------------------------------------------------------------- helpers

cat >"$WORK/listener.py" <<'PY'
import socket, sys
mode, host, port, log, ready = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
record = open(log, "a")

def note(text):
    record.write(text + "\n")
    record.flush()

if mode == "udp":
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((host, port))
    server.settimeout(30)
    open(ready, "w").write("ready\n")
    try:
        while True:
            data, peer = server.recvfrom(2048)
            note(f"DGRAM from {peer[0]}:{peer[1]}")
            server.sendto(b"pong", peer)
    except OSError:
        pass
else:
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(8)
    server.settimeout(30)
    open(ready, "w").write("ready\n")
    try:
        while True:
            connection, peer = server.accept()
            if mode == "tcp":
                note(f"ACCEPT from {peer[0]}:{peer[1]}")
                connection.close()
                continue
            # mode == "socks": a minimal SOCKS5 server that records what the relay asked for and
            # answers, so the application's connection completes end to end.
            connection.settimeout(3)
            note(f"ACCEPT from {peer[0]}:{peer[1]}")
            try:
                greeting = connection.recv(3)
                if len(greeting) < 3 or greeting[0] != 0x05:
                    note(f"RAW from {peer[0]}:{peer[1]}")
                    continue
                connection.sendall(b"\x05\x02")
                auth = connection.recv(2)
                length = auth[1] if len(auth) > 1 else 0
                user = connection.recv(length)
                plen = connection.recv(1)
                connection.recv(plen[0] if plen else 0)
                connection.sendall(b"\x01\x00")
                request = connection.recv(4)
                destination = "unknown"
                if len(request) == 4 and request[3] == 1:
                    address = socket.inet_ntoa(connection.recv(4))
                    dport = int.from_bytes(connection.recv(2), "big")
                    destination = f"{address}:{dport}"
                note(
                    f"SOCKS from {peer[0]}:{peer[1]} user={user.decode(errors='replace')} "
                    f"destination={destination}"
                )
                connection.sendall(b"\x05\x00\x00\x01" + bytes(4) + bytes(2))
                connection.recv(4096)
            except OSError:
                pass
            finally:
                connection.close()
    except OSError:
        pass
PY

cat >"$WORK/probe.py" <<'PY'
import socket, sys
mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
if mode == "tcp":
    sock = socket.socket()
    sock.settimeout(3)
    try:
        sock.connect((host, port))
        print("connect OK")
    except Exception as error:
        print(f"connect {type(error).__name__}: {error}")
    finally:
        sock.close()
else:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(b"ping", (host, port))
    try:
        data, peer = sock.recvfrom(64)
        print(f"reply from {peer[0]}:{peer[1]}")
    except Exception as error:
        print(f"no reply: {type(error).__name__}: {error}")
PY

wait_for_ready() {
    for _ in $(seq 1 60); do
        [ -f "$1" ] && return 0
        sleep 0.05
    done
    return 1
}

start_listener() { # mode host port log
    local mode="$1" host="$2" port="$3" log="$4"
    local ready="$log.ready"
    ip netns exec "$HOST_NS" python3 "$WORK/listener.py" "$mode" "$host" "$port" "$log" "$ready" \
        >/dev/null 2>&1 &
    PIDS+=("$!")
    wait_for_ready "$ready" || fail "the $mode listener on $host:$port did not start"
}

start_relay() { # namespace source-address
    local ns="$1" source="$2"
    ip netns exec "$ns" "$RELAY" --id 1 --uid "$RELAY_UID" --listen-port "$RELAY_PORT" \
        --core "$CORE" --socks-port "$SOCKS_PORT" --source "$source" \
        <"$RELAY_STDIN" >"$WORK/relay.log" 2>&1 &
    PIDS+=("$!")
    for _ in $(seq 1 60); do
        if ip netns exec "$ns" python3 - "$RELAY_PORT" <<'PY'
import socket, sys
s = socket.socket()
s.settimeout(0.5)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
    sys.exit(0)
except OSError:
    sys.exit(1)
PY
        then return 0; fi
        sleep 0.1
    done
    fail "the namespace relay did not start: $(cat "$WORK/relay.log")"
}

echo "[1] every rendered policy is accepted by the kernel's own parser"
ip netns add "gh-app-ns"
ip netns exec "gh-app-ns" nft -c -f "$GOLDEN/tor_app_host.nft" ||
    fail "the APP host policy is not applicable"
ip netns exec "gh-app-ns" nft -c -f "$GOLDEN/tor_app_namespace.nft" ||
    fail "the APP namespace policy is not applicable"
for policy in "$GOLDEN"/fail_closed.nft "$GOLDEN"/dns_lockdown.nft "$GOLDEN"/tor_system.nft \
    "$GOLDEN"/tor_system_lan.nft "$GOLDEN"/tor_user.nft; do
    ip netns exec "gh-app-ns" nft -c -f "$policy" || fail "$policy is not applicable"
done
ip netns del "gh-app-ns"
ok "all rendered policies parse and resolve against the kernel"

# ---------------------------------------------------------------- the namespace policy

echo "[2] the namespace policy carries traffic to the core and preserves the source"
ip netns add "$HOST_NS"
ip netns add "$LINK_NS"
ip link add "$HOST_VETH" type veth peer name "$NS_IF"
ip link set "$HOST_VETH" netns "$HOST_NS"
ip link set "$NS_IF" netns "$LINK_NS"
ip -n "$HOST_NS" addr add "$CORE/24" dev "$HOST_VETH"
ip -n "$HOST_NS" link set "$HOST_VETH" up
ip -n "$HOST_NS" link set lo up
ip -n "$LINK_NS" addr add "$APP/24" dev "$NS_IF"
ip -n "$LINK_NS" link set "$NS_IF" up
ip -n "$LINK_NS" link set lo up
ip -n "$LINK_NS" link add ghdead type dummy
ip -n "$LINK_NS" link set ghdead up
ip -n "$LINK_NS" route add default dev ghdead
ip netns exec "$LINK_NS" sysctl -qw net.ipv6.conf.all.disable_ipv6=1

start_listener socks "$CORE" "$SOCKS_PORT" "$WORK/socks.log"
start_listener udp "$CORE" "$DNS_PORT" "$WORK/dns.log"
start_relay "$LINK_NS" "$APP"

ip netns exec "$LINK_NS" nft -f "$GOLDEN/tor_app_namespace.nft"

ANSWER="$(ip netns exec "$LINK_NS" python3 "$WORK/probe.py" tcp "$REMOTE" 443)"
note "the probe said '$ANSWER'"
case "$ANSWER" in
*"connect OK"*) ok "the namespace DNAT carried the connection to the relay" ;;
*) fail "the rendered namespace policy did not carry the connection: $ANSWER" ;;
esac
grep -q "SOCKS from $APP:" "$WORK/socks.log" ||
    fail "the relay did not speak SOCKS to the core as the application's address: $(cat "$WORK/socks.log")"
grep -q "destination=$REMOTE:443" "$WORK/socks.log" ||
    fail "the intended destination did not survive: $(cat "$WORK/socks.log")"
grep -q "user=app1" "$WORK/socks.log" ||
    fail "the relay did not authenticate with the per-group credential: $(cat "$WORK/socks.log")"
ok "the destination survived, the source was the application's own address, and the group was isolated"

# A direct connection to the relay must be refused: it has no original destination, so the relay can
# never be an open proxy for a destination of the caller's choosing.
REFUSED="$(ip netns exec "$LINK_NS" python3 - "$RELAY_PORT" <<'PY'
import socket, sys
s = socket.socket()
s.settimeout(3)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
    data = s.recv(16)
    print("refused" if data == b"" else f"data:{data!r}")
except OSError as error:
    print(f"error:{error}")
PY
)"
case "$REFUSED" in
refused) ok "a direct connection to the relay is refused (no original destination)" ;;
*) fail "the relay carried a connection with no original destination: $REFUSED" ;;
esac

ANSWER="$(ip netns exec "$LINK_NS" python3 "$WORK/probe.py" udp "$REMOTE" "$DNS_PORT")"
note "the DNS probe said '$ANSWER'"
case "$ANSWER" in
*"reply from"*) ok "DNS was rewritten to the core chokepoint" ;;
*) fail "the DNS rewrite did not reach the chokepoint: $ANSWER" ;;
esac
grep -q "DGRAM from $APP:" "$WORK/dns.log" ||
    fail "the chokepoint did not see the application's source: $(cat "$WORK/dns.log")"
ok "the DNS query reached the chokepoint with the source preserved"

ANSWER="$(ip netns exec "$LINK_NS" python3 "$WORK/probe.py" tcp "$CORE" "$SOCKS_PORT")"
note "the direct-SOCKS probe said '$ANSWER'"
case "$ANSWER" in
*"connect OK"*) ok "a direct SOCKS connection is left alone, not DNAT'ed" ;;
*) fail "the SOCKS return rule did not leave the connection alone: $ANSWER" ;;
esac
grep -q "RAW from $APP:" "$WORK/socks.log" ||
    fail "the direct connection did not reach the core listener untouched: $(cat "$WORK/socks.log")"
ok "the direct connection reached the core listener without the relay"

echo "[3] with the DNAT flushed, nothing reaches the host link"
ip netns exec "$LINK_NS" nft flush chain inet ghostnector out_nat
ip netns exec "$HOST_NS" ip neigh flush dev "$HOST_VETH" 2>/dev/null || true
: >"$WORK/crossed.log"
( ip netns exec "$HOST_NS" timeout 6 tcpdump -n -Q in -i "$HOST_VETH" -c 50 'arp or ip or ip6' \
    >"$WORK/crossed.log" 2>/dev/null || true ) &
T=$!
sleep 0.3
ANSWER="$(ip netns exec "$LINK_NS" python3 "$WORK/probe.py" tcp "$REMOTE" 443)"
note "the probe said '$ANSWER'"
case "$ANSWER" in
*"connect OK"*) fail "a connection succeeded with the DNAT flushed" ;;
*) ok "the connection could not be made" ;;
esac
wait "$T" 2>/dev/null || true
CROSSED="$(grep -cE '^(ARP,|IP |IP6 )' "$WORK/crossed.log" 2>/dev/null || true)"
if [ "$CROSSED" != "0" ]; then
    echo "  ── what the host veth saw ──"
    sed 's/^/    /' "$WORK/crossed.log"
    fail "the host veth saw $CROSSED frame(s) after the DNAT was flushed"
fi
ok "no packet and no ARP reached the host link: the flushed policy is a dead end"

# ---------------------------------------------------------------- the host policy

echo "[4] the host policy admits the app link only to the core listeners"
ip link del "$HOST_VETH" 2>/dev/null || true
ip netns del "$LINK_NS" 2>/dev/null || true
ip netns del "$HOST_NS" 2>/dev/null || true

ip netns add "$HOST_NS"
ip netns add "$LINK_NS"
ip link add "$HOST_IF" type veth peer name "$LINK_IF"
ip link set "$HOST_IF" netns "$HOST_NS"
ip link set "$LINK_IF" netns "$LINK_NS"
ip -n "$HOST_NS" addr add "$CORE/24" dev "$HOST_IF"
ip -n "$HOST_NS" link set "$HOST_IF" up
ip -n "$HOST_NS" link set lo up
ip -n "$LINK_NS" addr add "$APP/24" dev "$LINK_IF"
ip -n "$LINK_NS" link set "$LINK_IF" up
ip -n "$LINK_NS" link set lo up
ip -n "$LINK_NS" route add "$REMOTE/32" via "$CORE"
# Forwarding is what makes the forward chain relevant at all: on a machine running containers or
# virtual machines it is enabled, and the point of `fwd_filter` is that they cannot leak. The host
# needs a route for the forwarded packet to reach the forward hook at all; a dummy uplink stands in
# for the real one and, being a dummy, cannot actually carry anything.
ip netns exec "$HOST_NS" sysctl -qw net.ipv4.ip_forward=1
ip -n "$HOST_NS" link add ghupl0 type dummy
ip -n "$HOST_NS" link set ghupl0 up
ip -n "$HOST_NS" route add default dev ghupl0

start_listener tcp "$CORE" "$SOCKS_PORT" "$WORK/admitted.log"
start_listener tcp "$CORE" "$TRANS_PORT" "$WORK/trans-closed.log"
start_listener tcp "$CORE" "$UNADMITTED_PORT" "$WORK/unadmitted.log"
ip netns exec "$HOST_NS" nft -f "$GOLDEN/tor_app_host.nft"

ANSWER="$(ip netns exec "$LINK_NS" python3 "$WORK/probe.py" tcp "$CORE" "$SOCKS_PORT")"
note "the admitted probe said '$ANSWER'"
case "$ANSWER" in
*"connect OK"*) ok "the app link reached the SOCKS listener" ;;
*) fail "the app link was not admitted to the core listener: $ANSWER" ;;
esac
[ -s "$WORK/admitted.log" ] || fail "the admitted listener saw no connection"

ANSWER="$(ip netns exec "$LINK_NS" python3 "$WORK/probe.py" tcp "$CORE" "$TRANS_PORT")"
note "the TransPort probe said '$ANSWER'"
case "$ANSWER" in
*"connect OK"*) fail "the app link reached the core TransPort, which APP scope no longer uses" ;;
*) ok "the core TransPort is closed to the app link" ;;
esac
[ -s "$WORK/trans-closed.log" ] && fail "the TransPort listener saw a connection from the app link"

ANSWER="$(ip netns exec "$LINK_NS" python3 "$WORK/probe.py" tcp "$CORE" "$UNADMITTED_PORT")"
note "the unadmitted probe said '$ANSWER'"
case "$ANSWER" in
*"connect OK"*) fail "the app link reached an unadmitted core port" ;;
*) ok "an unadmitted core port is closed to the app link" ;;
esac
[ -s "$WORK/unadmitted.log" ] && fail "the unadmitted listener saw a connection"

BEFORE="$(ip netns exec "$HOST_NS" nft list chain inet ghostnector fwd_filter |
    awk '/counter packets/ { print $3; exit }')"
ip netns exec "$LINK_NS" python3 "$WORK/probe.py" tcp "$REMOTE" 443 >/dev/null 2>&1 || true
sleep 0.5
AFTER="$(ip netns exec "$HOST_NS" nft list chain inet ghostnector fwd_filter |
    awk '/counter packets/ { print $3; exit }')"
note "forward-chain counter: $BEFORE -> $AFTER"
[ "${AFTER:-0}" -gt "${BEFORE:-0}" ] ||
    fail "traffic aimed past the core address was not dropped by the forward chain"
ok "traffic aimed elsewhere was dropped by the forward chain"

echo
echo "PASS: APP policy (applicable, relay carries the destination as the app's address, dead end, bounded host link)"
