#!/usr/bin/env bash
#
# Adversarial APP scope: try to make an APP claim false while Ghostnector still reports it.
#
#   scripts/app-adversarial.sh <target/debug directory>
#
# Each case states what it observed, in the same three classifications the M7 suite uses:
#
#   ok            the claim held, observed from outside the component under test
#   FAIL          a claim was contradicted — this is a finding
#   inconclusive  the observation cannot establish either way, and is never counted as a pass
#
# The stack runs in the initial network namespace (as in production), creates only its own objects,
# and removes them all in the trap.
#
# Requires: root, iproute2, nftables, python3, tcpdump, setpriv (util-linux).

set -uo pipefail
cd "$(dirname "$0")/.."

TARGET_DIR="${1:?usage: app-adversarial.sh <target/debug directory>}"
RUNDIR="/run/ghostnector"
BINDIR="/tmp/gh-aa-bin"
WORKDIR="/tmp/gh-app-aa"
CORE_USER="ghostnector-core"
LAUNCH_USER="ghostnector-launch-test"
CONTROL_PORT="9051"
BRIDGE="ghaabr0"
CORE="10.233.0.1"
PREFIX="24"
DEAD="ghdead"
NETD_PID=""
APPD_PID=""
CORE_PID=""
TOR_PID=""

PASSED=0
FAILED=0
INCONCLUSIVE=0

cleanup() {
    for pid in "$CORE_PID" "$APPD_PID" "$NETD_PID" "$TOR_PID"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    for ns in ghapp1 ghapp2 ghapp3 ghapp4; do ip netns del "$ns" 2>/dev/null || true; done
    ip link del "$BRIDGE" 2>/dev/null || true
    nft destroy table inet ghostnector 2>/dev/null || true
    rm -rf "$BINDIR" "$WORKDIR"
}
trap cleanup EXIT

fail_setup() {
    echo "FAIL(setup): $*" >&2
    for log in "$WORKDIR/core.log" "$WORKDIR/appd.log" "$WORKDIR/netd.log"; do
        [ -f "$log" ] && { echo "--- $log ---"; tail -20 "$log"; }
    done
    exit 2
}
ok() { echo "  ok: $*"; PASSED=$((PASSED + 1)); }
bad() { echo "  FAIL: $*"; FAILED=$((FAILED + 1)); }
inc() { echo "  inconclusive: $*"; INCONCLUSIVE=$((INCONCLUSIVE + 1)); }
note() { echo "    $*"; }

[ "$(id -u)" = "0" ] || fail_setup "this test needs root"

id -u "$CORE_USER" >/dev/null 2>&1 || \
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$CORE_USER"
if ! id -u "$LAUNCH_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /bin/sh "$LAUNCH_USER"
fi
CORE_UID="$(id -u "$CORE_USER")"
CORE_GID="$(id -g "$CORE_USER")"
LAUNCH_UID="$(id -u "$LAUNCH_USER")"
LAUNCH_GID="$(id -g "$LAUNCH_USER")"

mkdir -p "$BINDIR" "$WORKDIR" "$RUNDIR" "$WORKDIR/root/etc"
printf 'nameserver 192.0.2.53\n' >"$WORKDIR/root/etc/resolv.conf"
for binary in ghostnector-netd ghostnector-appd ghostnector-appd-launch \
    ghostnector-appd-probe ghostnector-appd-relay ghostnector-core ghostnector ghostnector-dns; do
    install -m 0755 "$TARGET_DIR/$binary" "$BINDIR/$binary"
done
COOKIE="$WORKDIR/control_auth_cookie"
head -c 32 /dev/urandom >"$COOKIE"
chown -R "$CORE_UID" "$WORKDIR"
chmod 0755 "$RUNDIR"
chown "$CORE_UID" "$RUNDIR" 2>/dev/null || true
rm -f "$RUNDIR/core.sock" "$RUNDIR/netd.sock" "$RUNDIR/appd.sock"

cat >"$WORKDIR/fake-tor.py" <<'PY'
import json, socket, sys, threading, time

control_port, socks_port, dns_port, core, events = (
    int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
)
READY = (
    b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n"
    b"250 OK\r\n"
)


def record(kind, **fields):
    with open(events, "a") as log:
        log.write(json.dumps({"kind": kind, "ts": round(time.time(), 3), **fields}) + "\n")


def control_server():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", control_port))
    server.listen(16)

    def handle(connection):
        try:
            # Real Tor does not greet first: the client authenticates before it reads.
            while True:
                line = b""
                while not line.endswith(b"\r\n"):
                    chunk = connection.recv(4096)
                    if not chunk:
                        return
                    line += chunk
                if line.startswith(b"AUTHENTICATE"):
                    connection.sendall(b"250 OK\r\n")
                elif line.startswith(b"GETINFO"):
                    connection.sendall(READY)
                else:
                    connection.sendall(b"510 Unrecognized command\r\n")
        except OSError:
            pass

    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def socks_server():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    for _ in range(300):
        try:
            server.bind((core, socks_port))
            break
        except OSError:
            time.sleep(0.1)
    else:
        record("socks-unbound", address=core)
        return
    server.listen(16)
    while True:
        conn, peer = server.accept()
        try:
            conn.settimeout(5)
            greeting = conn.recv(3)
            if len(greeting) < 3 or greeting[0] != 0x05:
                record("socks-raw", from_address=peer[0], from_port=peer[1])
                conn.close()
                continue
            conn.sendall(b"\x05\x02")
            auth = conn.recv(2)
            length = auth[1] if len(auth) > 1 else 0
            user = conn.recv(length)
            plen = conn.recv(1)
            conn.recv(plen[0] if plen else 0)
            conn.sendall(b"\x01\x00")
            request = conn.recv(4)
            destination = "unknown"
            if len(request) == 4 and request[3] == 1:
                address = socket.inet_ntoa(conn.recv(4))
                dport = int.from_bytes(conn.recv(2), "big")
                destination = f"{address}:{dport}"
            record(
                "socks",
                from_address=peer[0],
                from_port=peer[1],
                user=user.decode(errors="replace"),
                destination=destination,
            )
            conn.sendall(b"\x05\x00\x00\x01" + bytes(4) + bytes(2))
            # The verification probe sends an HTTP request through the relay; an application that
            # just connects and reads gets the short answer. Both paths must complete.
            conn.settimeout(2)
            request = b""
            try:
                request = conn.recv(4096)
            except OSError:
                request = b""
            if request.startswith(b"GET "):
                conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n203.0.113.9\n")
            else:
                conn.sendall(b"tor-ok")
        except OSError:
            pass
        conn.close()


def dns_answer(query):
    question_end = 12
    while query[question_end] != 0:
        question_end += 1 + query[question_end]
    question_end += 5
    reply = bytearray(query[:2])
    reply += bytes([0x81, 0x80])
    reply += (1).to_bytes(2, "big")
    reply += (1).to_bytes(2, "big")
    reply += b"\x00\x00\x00\x00"
    reply += query[12:question_end]
    reply += b"\xc0\x0c"
    reply += (1).to_bytes(2, "big")
    reply += (1).to_bytes(2, "big")
    reply += (60).to_bytes(4, "big")
    reply += (4).to_bytes(2, "big")
    reply += bytes([203, 0, 113, 9])
    return bytes(reply)


def dns_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", dns_port))
    while True:
        query, peer = server.recvfrom(4096)
        record("dns", from_address=peer[0], from_port=peer[1])
        if len(query) >= 12:
            server.sendto(dns_answer(query), peer)


threading.Thread(target=control_server, daemon=True).start()
threading.Thread(target=dns_server, daemon=True).start()
socks_server()
PY

cat >"$WORKDIR/session.py" <<'PY'
import socket, sys

path, script = sys.argv[1], sys.argv[2]
connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.settimeout(20)
try:
    connection.connect(path)
except OSError as error:
    print(f"CONNECT-FAILED: {error}")
    sys.exit(3)
connection.sendall(script.encode())
connection.shutdown(socket.SHUT_WR)
data = b""
while True:
    try:
        chunk = connection.recv(65536)
    except OSError as error:
        print(f"READ-FAILED: {error}")
        break
    if not chunk:
        break
    data += chunk
sys.stdout.write(data.decode(errors="replace"))
PY

: >"$WORKDIR/events.jsonl"
python3 "$WORKDIR/fake-tor.py" "$CONTROL_PORT" 9050 9053 "$CORE" "$WORKDIR/events.jsonl" \
    >"$WORKDIR/tor.log" 2>&1 &
TOR_PID=$!
sleep 0.3

"$BINDIR/ghostnector-netd" --socket "$RUNDIR/netd.sock" --peer-uid "$CORE_UID" \
    --app-bridge "$BRIDGE" --app-core "$CORE" \
    --fallback-path "$WORKDIR/fail-closed.nft" >"$WORKDIR/netd.log" 2>&1 &
NETD_PID=$!
for _ in $(seq 1 60); do [ -S "$RUNDIR/netd.sock" ] && break; sleep 0.1; done
[ -S "$RUNDIR/netd.sock" ] || fail_setup "the firewall helper did not start"

"$BINDIR/ghostnector-appd" --socket "$RUNDIR/appd.sock" --peer-user "$CORE_USER" \
    --state-dir "$WORKDIR/apps" --launcher "$BINDIR/ghostnector-appd-launch" \
    --probe "$BINDIR/ghostnector-appd-probe" --relay "$BINDIR/ghostnector-appd-relay" \
    --bridge "$BRIDGE" --core "$CORE" --prefix "$PREFIX" --dead-device "$DEAD" \
    >"$WORKDIR/appd.log" 2>&1 &
APPD_PID=$!
for _ in $(seq 1 60); do [ -S "$RUNDIR/appd.sock" ] && break; sleep 0.1; done
[ -S "$RUNDIR/appd.sock" ] || fail_setup "the namespace helper did not start"

setpriv --reuid="$CORE_UID" --regid="$CORE_GID" --clear-groups \
    --inh-caps +net_bind_service --ambient-caps +net_bind_service \
    "$BINDIR/ghostnector-core" \
    --socket "$RUNDIR/core.sock" --helper "$RUNDIR/netd.sock" \
    --journal "$WORKDIR/intent.json" --resolver-state "$WORKDIR/resolver.json" \
    --resolv-conf-root "$WORKDIR/root" \
    --services external --tor-cookie "$COOKIE" --tor-control-port "$CONTROL_PORT" \
    --tor-bootstrap-seconds 10 --dns-helper "$BINDIR/ghostnector-dns" \
    --app-socket "$RUNDIR/appd.sock" --app-core "$CORE" \
    --udp-check 198.51.100.10:9999 --check-url http://198.51.100.10/ \
    --canary "canary.test@203.0.113.9" --canary-resolver "$CORE:53" \
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

run_probe() {
    cli run -- python3 "$WORKDIR/probe.py" 2>&1
}

cat >"$WORKDIR/probe.py" <<'PY'
import socket

print("uid:" + str(__import__("os").getuid()))
connection = socket.socket()
connection.settimeout(5)
connection.connect(("198.51.100.10", 80))
print("tcp:" + connection.recv(16).decode(errors="replace"))
connection.close()
query = bytes([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
query += b"\x06canary\x04test\x00\x00\x01\x00\x01"
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(query, ("10.233.0.1", 53))
answer, _ = udp.recvfrom(1024)
print("dns:" + ".".join(str(byte) for byte in answer[-4:]))
PY

app_id() {
    cli apps 2>&1 | awk '/^  -/ { print $2; exit }'
}
app_addr() {
    cli apps 2>&1 | awk '/^  -/ { print $3; exit }'
}

echo "=== APP adversarial exposure ==="
echo "target: $TARGET_DIR"
echo

# ---------------------------------------------------------------- setup: connect and one app
if ! cli connect --scope app >/dev/null 2>&1; then
    fail_setup "connect --scope app failed"
fi
if [ -z "$(run_probe | grep 'tcp:tor-ok')" ]; then
    fail_setup "the protected path did not work in setup"
fi
APP_ID="$(app_id)"
[ -n "$APP_ID" ] || fail_setup "no application was created"
if ! wait_for "and verified" 20; then
    fail_setup "verification never passed: $(status)"
fi

# ---------------------------------------------------------------- AA-1: namespace removed by hand
echo "â”€â”€ AA-1: a namespace removed by hand is noticed and denied"
ip netns del "ghapp$APP_ID" 2>/dev/null
if wait_for "no protected application can reach the network" 20; then
    ok "the removed namespace was noticed and the APP scope denied"
else
    bad "the state still claimed protection after its namespace was removed"
fi

# Reset for the next case: disconnect and connect again.
cli disconnect >/dev/null 2>&1
cli connect --scope app >/dev/null 2>&1
run_probe >/dev/null 2>&1
APP_ID="$(app_id)"
wait_for "and verified" 20 >/dev/null 2>&1

# ---------------------------------------------------------------- AA-2: a masquerade rule injected
echo "â”€â”€ AA-2: a masquerade rule injected into the host table is noticed"
nft add chain inet ghostnector aa_post '{ type nat hook postrouting priority 100 ; }' 2>/dev/null || true
nft add rule inet ghostnector aa_post masquerade 2>/dev/null || true
if nft list table inet ghostnector 2>/dev/null | grep -q masquerade; then
    if wait_for "no protected application can reach the network" 20; then
        ok "the injected masquerade rule was noticed and the APP scope denied"
    else
        bad "a masquerade rule survived while the APP scope claimed protection"
    fi
else
    inc "the kernel refused the injected masquerade rule, so the alarm was not exercised"
fi

cli disconnect >/dev/null 2>&1
cli connect --scope app >/dev/null 2>&1
run_probe >/dev/null 2>&1
APP_ID="$(app_id)"
APP_ADDR="$(app_addr)"
wait_for "and verified" 20 >/dev/null 2>&1

# ---------------------------------------------------------------- AA-3: a route injected inside
echo "â”€â”€ AA-3: a route injected inside the namespace does not create a direct path"
BEFORE="$(grep -c '"kind": "socks"' "$WORKDIR/events.jsonl" 2>/dev/null || true)"
ip netns exec "ghapp$APP_ID" ip route add 203.0.113.0/24 dev ghlink0 2>/dev/null || true
run_probe >/dev/null 2>&1
AFTER="$(grep -c '"kind": "socks"' "$WORKDIR/events.jsonl" 2>/dev/null || true)"
if [ "${AFTER:-0}" -gt "${BEFORE:-0}" ]; then
    ok "the connection still went through Tor; the injected route created no direct path"
else
    bad "the connection did not go through Tor after a route was injected"
fi

# ---------------------------------------------------------------- AA-4: proxy_arp turned on
echo "â”€â”€ AA-4: proxy_arp on the app link is noticed as a shape change"
sysctl -qw "net.ipv4.conf.ghav$APP_ID.proxy_arp=1"
if wait_for "no protected application can reach the network" 20; then
    ok "the shape change was noticed and the APP scope denied"
else
    bad "proxy_arp was enabled while the APP scope claimed protection"
fi
sysctl -qw "net.ipv4.conf.ghav$APP_ID.proxy_arp=0" 2>/dev/null || true

cli disconnect >/dev/null 2>&1
cli connect --scope app >/dev/null 2>&1
run_probe >/dev/null 2>&1
APP_ID="$(app_id)"
wait_for "and verified" 20 >/dev/null 2>&1

# ---------------------------------------------------------------- AA-5: an extra interface
echo "â”€â”€ AA-5: an extra interface inside the namespace is noticed"
ip netns exec "ghapp$APP_ID" ip link add ghrogue type dummy 2>/dev/null
if wait_for "no protected application can reach the network" 20; then
    ok "the extra interface was noticed and the APP scope denied"
else
    bad "an extra interface existed while the APP scope claimed protection"
fi

cli disconnect >/dev/null 2>&1
cli connect --scope app >/dev/null 2>&1

# ---------------------------------------------------------------- AA-6/9: two apps, distinct sources
echo "â”€â”€ AA-6/AA-9: two applications present distinct source identities, with no masquerade"
run_probe >/dev/null 2>&1
FIRST_ADDR="$(app_addr)"
run_probe >/dev/null 2>&1
LIST="$(cli apps 2>&1)"
SECOND_ADDR="$(printf '%s\n' "$LIST" | awk '/^  -/ { print $3 }' | tail -n1)"
note "application addresses: $FIRST_ADDR and $SECOND_ADDR"
if [ -z "$FIRST_ADDR" ] || [ -z "$SECOND_ADDR" ] || [ "$FIRST_ADDR" = "$SECOND_ADDR" ]; then
    bad "the two applications did not get distinct addresses"
elif grep -q "\"from_address\": \"$FIRST_ADDR\"" "$WORKDIR/events.jsonl" &&
    grep -q "\"from_address\": \"$SECOND_ADDR\"" "$WORKDIR/events.jsonl"; then
    ok "Tor saw both application addresses; no masquerade collapsed them"
else
    bad "Tor did not see both distinct source addresses"
fi

# ---------------------------------------------------------------- AA-7: panic with apps running
echo "â”€â”€ AA-7: panic with applications running removes their namespaces"
cli panic >/dev/null 2>&1
LEFT="$(cli apps 2>&1)"
case "$LEFT" in
*"no protected applications"*)
    if [ -z "$(ls /run/netns 2>/dev/null | grep -E '^ghapp' || true)" ]; then
        ok "panic removed every application namespace"
    else
        bad "panic left a namespace behind"
    fi
    ;;
*)
    bad "panic did not remove the applications: $LEFT"
    ;;
esac
case "$(status)" in
*"blocked"*) ok "the state is blocked after panic" ;;
*) bad "panic did not leave the machine denied: $(status)" ;;
esac

# ---------------------------------------------------------------- AA-10: DNS to a foreign resolver
echo "â”€â”€ AA-10: a query to a foreign resolver is carried by the chokepoint only"
cli disconnect >/dev/null 2>&1
CONNECT_OUT="$(cli connect --scope app 2>&1)"
case "$CONNECT_OUT" in
*"unverified"* | *"verified"*) ;;
*) bad "AA-10 could not re-establish APP protection: $CONNECT_OUT" ;;
esac
run_probe >/dev/null 2>&1
APP_ID="$(app_id)"
wait_for "and verified" 20 >/dev/null 2>&1
cat >"$WORKDIR/foreign.py" <<'PY'
import socket
query = bytes([0x56, 0x78, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
query += b"\x06canary\x04test\x00\x00\x01\x00\x01"
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(query, ("8.8.8.8", 53))
answer, _ = udp.recvfrom(1024)
print("dns:" + ".".join(str(byte) for byte in answer[-4:]))
PY
OUTPUT="$(cli run -- python3 "$WORKDIR/foreign.py" 2>&1)"
case "$OUTPUT" in
*"dns:203.0.113.9"*) ok "the foreign resolver query was answered by the chokepoint" ;;
*) bad "a query to a foreign resolver was not carried by the chokepoint: $OUTPUT" ;;
esac
# What matters is that no query from an application address reached a resolver directly. The fake
# resolver also sees one query from the WSL virtual gateway in this environment (classified, not
# whitelisted: it is not an application address and it is not part of the protected scope).
APP_LEAKS="$(grep '"kind": "dns"' "$WORKDIR/events.jsonl" | grep -E '10\.233\.0\.' || true)"
if [ -n "$APP_LEAKS" ]; then
    printf '%s\n' "$APP_LEAKS" | sed 's/^/    /'
    bad "a DNS query from an application address reached the resolver directly"
else
    ok "no query from an application address reached the resolver directly"
fi

# ---------------------------------------------------------------- AA-12: ruleset flushed
echo "â”€â”€ AA-12: flushing the namespace ruleset is noticed"
ip netns exec "ghapp$APP_ID" nft flush table inet ghostnector 2>/dev/null
if wait_for "no protected application can reach the network" 20; then
    ok "the flushed ruleset was noticed and the APP scope denied"
else
    bad "the namespace kept claiming protection with no ruleset"
fi

# ---------------------------------------------------------------- AA-13: appd killed
echo "â”€â”€ AA-13: killing the namespace helper loosens nothing"
cli disconnect >/dev/null 2>&1
cli connect --scope app >/dev/null 2>&1
run_probe >/dev/null 2>&1
APP_ID="$(app_id)"
kill "$APPD_PID" 2>/dev/null || true
sleep 1
# The existing namespace does not depend on the helper being alive; observe it directly.
OUTPUT="$(ip netns exec "ghapp$APP_ID" python3 "$WORKDIR/probe.py" 2>&1)"
case "$OUTPUT" in
*"tcp:tor-ok"*)
    ok "the existing namespace kept its protected path after the helper died"
    ;;
*)
    inc "the existing namespace could not be observed after the helper died: $OUTPUT"
    ;;
esac
if nft list table inet ghostnector 2>/dev/null | grep -q "iifname \"$BRIDGE\""; then
    ok "the host APP table survived the helper's death"
else
    bad "the host APP table disappeared with the helper"
fi
# Restart the helper so cleanup can revert cleanly.
"$BINDIR/ghostnector-appd" --socket "$RUNDIR/appd.sock" --peer-user "$CORE_USER" \
    --state-dir "$WORKDIR/apps" --launcher "$BINDIR/ghostnector-appd-launch" \
    --probe "$BINDIR/ghostnector-appd-probe" --relay "$BINDIR/ghostnector-appd-relay" \
    --bridge "$BRIDGE" --core "$CORE" --prefix "$PREFIX" --dead-device "$DEAD" \
    >"$WORKDIR/appd2.log" 2>&1 &
APPD_PID=$!
sleep 1

echo
echo "=== summary ==="
echo "held:         $PASSED"
echo "contradicted: $FAILED"
echo "inconclusive: $INCONCLUSIVE"
[ "$FAILED" = "0" ] || exit 1
exit 0


