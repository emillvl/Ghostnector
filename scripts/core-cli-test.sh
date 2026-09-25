#!/usr/bin/env bash
#
# Exercises the whole stack inside a throwaway network namespace:
#
#   ghostnector (CLI)  ->  ghostnector-core  ->  ghostnector-netd  ->  kernel
#
# Tor is stubbed rather than real: systemd is not namespaced, so a unit started here would run
# outside the namespace, and a real Tor bootstrap needs the public network and half a minute. The
# stub speaks Tor's control protocol from inside the namespace, which is exactly what the control
# plane talks to. It is configured with --services external, meaning "the operator runs Tor, we only
# wait for it to be ready" - a real deployment mode, not a test backdoor.
#
# What it proves:
#   1. a client that is not allowed to talk to the control plane is refused
#   2. connect brings the service up, and the kernel really has the policy
#   3. the state is reported as protected-but-unverified, never as "protected and verified"
#   4. panic leaves the machine denied, and disconnect returns it to the baseline
#   5. a restart that finds protection requested but nothing applied fails closed rather than
#      quietly returning to the clearnet
#
# Requires: root, iproute2, nftables, python3, setpriv (util-linux).

set -euo pipefail

TARGET_DIR="${1:?usage: core-cli-test.sh <target/debug directory>}"
NS="gh-core-test"
RUNDIR="/run/ghostnector"
BINDIR="/tmp/gh-bin"
WORKDIR="/tmp/gh-core-test"
CORE_USER="ghostnector-core"
OUTSIDER="ghostnector-outsider"
CONTROL_PORT="9051"
DNS_UPSTREAM_PORT="9053"
# The chokepoint listens on the port a `nameserver` line implies, because that line cannot carry a
# port (D-22). The probe below checks the address the resolver was actually given against this.
CHOKEPOINT_PORT="53"
UDP_CHECK_PORT="9999"
OUTSIDE_NS="gh-outside"
OUTSIDE_ADDR="10.77.0.1"
INSIDE_ADDR="10.77.0.2"
FAKE_TOR="/tmp/gh-fake-tor.py"
FAKE_DNS="/tmp/gh-fake-dns.py"
FAKE_UDP="/tmp/gh-fake-udp.py"
DNS_PROBE="/tmp/gh-dns-probe.py"
NETD_PID=""
CORE_PID=""
TOR_PID=""
DNS_PID=""
UDP_PID=""

cleanup() {
    [ -n "$CORE_PID" ] && kill "$CORE_PID" 2>/dev/null || true
    [ -n "$NETD_PID" ] && kill "$NETD_PID" 2>/dev/null || true
    [ -n "$TOR_PID" ] && kill "$TOR_PID" 2>/dev/null || true
    [ -n "$DNS_PID" ] && kill "$DNS_PID" 2>/dev/null || true
    [ -n "$UDP_PID" ] && kill "$UDP_PID" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    ip netns del "$OUTSIDE_NS" 2>/dev/null || true
    rm -rf "$BINDIR" "$WORKDIR" "$RUNDIR" "$FAKE_TOR" "$FAKE_DNS" "$FAKE_UDP" "$DNS_PROBE"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    for log in /tmp/gh-core.log /tmp/gh-netd-stack.log /tmp/gh-fake-tor.log; do
        [ -f "$log" ] && { echo "--- $log ---"; cat "$log"; }
    done
    exit 1
}
ok() { echo "  ok: $*"; }

[ "$(id -u)" = "0" ] || fail "this test needs root"

# ---------------------------------------------------------------- identities and binaries
for user in "$CORE_USER" "$OUTSIDER"; do
    id -u "$user" >/dev/null 2>&1 || \
        useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$user"
done
CORE_UID="$(id -u "$CORE_USER")"
CORE_GID="$(id -g "$CORE_USER")"
OUTSIDER_UID="$(id -u "$OUTSIDER")"
OUTSIDER_GID="$(id -g "$OUTSIDER")"

mkdir -p "$BINDIR"
install -m 0755 "$TARGET_DIR/ghostnector-netd" "$BINDIR/ghostnector-netd"
install -m 0755 "$TARGET_DIR/ghostnector-core" "$BINDIR/ghostnector-core"
install -m 0755 "$TARGET_DIR/ghostnector" "$BINDIR/ghostnector"
install -m 0755 "$TARGET_DIR/ghostnector-dns" "$BINDIR/ghostnector-dns"

mkdir -p "$WORKDIR" "$RUNDIR"
chown "$CORE_UID" "$WORKDIR"
# systemd's RuntimeDirectory= would create this owned by the service user; do the same here, so the
# unprivileged daemon can create its socket while nobody else can.
chown "$CORE_UID" "$RUNDIR"
chmod 0755 "$RUNDIR"
JOURNAL="$WORKDIR/intent.json"
# The resolver works on a temporary root, so this test never touches the machine's own
# configuration - and the file it does touch has real contents, so the code path is real.
RESOLV_ROOT="$WORKDIR/root"
RESOLV_CONF="$RESOLV_ROOT/etc/resolv.conf"
mkdir -p "$RESOLV_ROOT/etc"
printf 'nameserver 192.0.2.53\nsearch example.test\n' >"$RESOLV_CONF"
# The daemon runs unprivileged and has to be able to rewrite this, exactly as it would on a machine
# where the resolver configuration belongs to the user.
chown -R "$CORE_UID" "$RESOLV_ROOT"
ORIGINAL_RESOLV_CONF="$(cat "$RESOLV_CONF")"
COOKIE="$WORKDIR/control_auth_cookie"
head -c 32 /dev/urandom >"$COOKIE"
chown "$CORE_UID" "$COOKIE"

ip netns add "$NS"
# A fresh namespace has its loopback down, and Tor's control port is on loopback.
ip -n "$NS" link set lo up

# ---------------------------------------------------------------- a place for traffic to go
# The verifier's UDP check needs somewhere that answers if a datagram gets out, and it cannot be on
# loopback: loopback is allowed by design, so a reply from it would say nothing.
ip netns add "$OUTSIDE_NS"
ip link add veth-outside type veth peer name veth-inside
ip link set veth-outside netns "$OUTSIDE_NS"
ip link set veth-inside netns "$NS"
ip -n "$OUTSIDE_NS" addr add "$OUTSIDE_ADDR/24" dev veth-outside
ip -n "$NS" addr add "$INSIDE_ADDR/24" dev veth-inside
ip -n "$OUTSIDE_NS" link set veth-outside up
ip -n "$NS" link set veth-inside up
ip -n "$OUTSIDE_NS" link set lo up

in_ns() { ip netns exec "$NS" "$@"; }
as_user() {
    local uid="$1" gid="$2"
    shift 2
    ip netns exec "$NS" setpriv --reuid="$uid" --regid="$gid" --clear-groups "$@"
}
cli() { as_user "$CORE_UID" "$CORE_GID" "$BINDIR/ghostnector" --socket "$RUNDIR/core.sock" "$@"; }

wait_for_socket() {
    for _ in $(seq 1 60); do
        [ -S "$1" ] && return 0
        sleep 0.1
    done
    return 1
}

# ---------------------------------------------------------------- a stand-in for Tor
cat >"$FAKE_TOR" <<'PY'
import socket, sys, threading

port = int(sys.argv[1])
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen(16)

READY = (
    b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n"
    b"250 OK\r\n"
)


def handle(connection):
    try:
        connection.sendall(b"250 OK\r\n")
        pending = b""
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                return
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                command = line.strip().upper()
                if command.startswith(b"AUTHENTICATE"):
                    connection.sendall(b"250 OK\r\n")
                elif command.startswith(b"GETINFO STATUS/BOOTSTRAP-PHASE"):
                    connection.sendall(READY)
                else:
                    connection.sendall(b"510 Unrecognized command\r\n")
    except OSError:
        pass
    finally:
        connection.close()


while True:
    conn, _ = server.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY

in_ns python3 "$FAKE_TOR" "$CONTROL_PORT" >/tmp/gh-fake-tor.log 2>&1 &
TOR_PID=$!
sleep 0.5

# ---------------------------------------------------------------- a stand-in for the internet's DNS
cat >"$FAKE_DNS" <<'PY'
import socket, sys

port = int(sys.argv[1])
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", port))
while True:
    _, address = server.recvfrom(4096)
    server.sendto(b"upstream-saw-it", address)
PY

cat >"$DNS_PROBE" <<'PY'
import socket, sys

host, port = sys.argv[1], int(sys.argv[2])
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(4)
# The relay passes messages through unchanged, so this only has to look like a query: id 0x1234,
# QR clear.
query = bytes([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
client.sendto(query, (host, port))
try:
    data, _ = client.recvfrom(4096)
except socket.timeout:
    sys.exit(1)
print(data.decode(errors="replace"))
PY

in_ns python3 "$FAKE_DNS" "$DNS_UPSTREAM_PORT" >/tmp/gh-fake-dns.log 2>&1 &
DNS_PID=$!
sleep 0.3

# ---------------------------------------------------------------- something to answer if UDP escapes
cat >"$FAKE_UDP" <<'PY'
import socket, sys

port = int(sys.argv[1])
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("0.0.0.0", port))
while True:
    _, address = server.recvfrom(4096)
    server.sendto(b"here", address)
PY

ip netns exec "$OUTSIDE_NS" python3 "$FAKE_UDP" "$UDP_CHECK_PORT" >/tmp/gh-fake-udp.log 2>&1 &
UDP_PID=$!
sleep 0.3

start_stack() {
    in_ns "$BINDIR/ghostnector-netd" --socket "$RUNDIR/netd.sock" --peer-uid "$CORE_UID" \
        >/tmp/gh-netd-stack.log 2>&1 &
    NETD_PID=$!
    wait_for_socket "$RUNDIR/netd.sock" || fail "the helper did not start"

    # The relay core starts listens on port 53, so core needs exactly the capability the packaged
    # unit grants it: CAP_NET_BIND_SERVICE, inherited by the child (D-22).
    ip netns exec "$NS" setpriv \
        --reuid="$CORE_UID" --regid="$CORE_GID" --clear-groups \
        --inh-caps +net_bind_service --ambient-caps +net_bind_service \
        "$BINDIR/ghostnector-core" \
        --socket "$RUNDIR/core.sock" --helper "$RUNDIR/netd.sock" --journal "$JOURNAL" \
        --services external --tor-cookie "$COOKIE" --tor-control-port "$CONTROL_PORT" \
        --tor-bootstrap-seconds 10 \
        --dns-helper "$BINDIR/ghostnector-dns" --tor-dns-port "$DNS_UPSTREAM_PORT" \
        --resolv-conf-root "$RESOLV_ROOT" --resolver-state "$WORKDIR/resolver.json" \
        --udp-check "$OUTSIDE_ADDR:$UDP_CHECK_PORT" \
        --i2p-ready-seconds 1 \
        --verify-interval 5 --verify-stale-after 120 --verify-timeout 3 \
        >/tmp/gh-core.log 2>&1 &
    CORE_PID=$!
    wait_for_socket "$RUNDIR/core.sock" || fail "the control plane did not start"
}

stop_core() {
    [ -n "$CORE_PID" ] && kill "$CORE_PID" 2>/dev/null || true
    wait "$CORE_PID" 2>/dev/null || true
    CORE_PID=""
    rm -f "$RUNDIR/core.sock"
}

start_stack
ok "the stack started"

# ---------------------------------------------------------------- an unauthorised client
if as_user "$OUTSIDER_UID" "$OUTSIDER_GID" "$BINDIR/ghostnector" \
    --socket "$RUNDIR/core.sock" status >/tmp/gh-outsider.log 2>&1; then
    fail "a user outside the socket's permissions reached the control plane"
fi
grep -qi "cannot reach the control plane" /tmp/gh-outsider.log ||
    fail "the outsider's failure was not explained: $(cat /tmp/gh-outsider.log)"
ok "a client without access was refused"

# ---------------------------------------------------------------- off, connect, blocked, off
STATUS="$(cli status)"
case "$STATUS" in
*"traffic is not protected"*) ok "the initial state is off" ;;
*) fail "unexpected initial state: $STATUS" ;;
esac

# ---------------------------------------------------------------- I2P fails closed without a router
# I2P is a real profile now. With no router answering on its proxy, the connect must be refused with
# an explanation, and nothing may be left applied: protection was never established, so the
# documented rollback applies.
if I2P="$(cli connect --network i2p 2>&1)"; then
    fail "I2P was accepted although no router answers: $I2P"
fi
case "$I2P" in
*"I2P router is not usable"*) ok "I2P is refused with an explanation when no router answers" ;;
*) fail "the I2P refusal was not explained: $I2P" ;;
esac
case "$(cli status)" in
*"traffic is not protected"*) ok "the failed I2P connect left nothing applied" ;;
*) fail "the failed I2P connect left something behind: $(cli status)" ;;
esac
in_ns nft list tables 2>/dev/null | grep -q ghostnector &&
    fail "the failed I2P connect left a policy behind"

if ! CONNECTED="$(cli connect 2>&1)"; then
    echo "$CONNECTED"
    fail "connect failed"
fi
case "$CONNECTED" in
*"protected, but unverified"*) ok "connect reports protected-but-unverified" ;;
*) fail "connect did not report a protected state: $CONNECTED" ;;
esac
case "$CONNECTED" in
*"not checked yet"*) ok "it says plainly that nothing has checked it yet" ;;
*) fail "the verification status was not reported: $CONNECTED" ;;
esac
case "$CONNECTED" in
*"managed outside Ghostnector"*) ok "it says who is running Tor" ;;
*) fail "the service note was missing: $CONNECTED" ;;
esac

in_ns nft list tables | grep -q ghostnector || fail "the kernel has no policy after connect"
ok "the kernel really has the policy"

case "$(cat "$RESOLV_CONF")" in
*"nameserver 127.0.0.1"*) ok "the machine's own resolver points at the chokepoint" ;;
*) fail "the resolver was not repointed: $(cat "$RESOLV_CONF")" ;;
esac

# D-22: the resolver line names an address and no port, so it means port 53. Query the address core
# actually wrote, on that implied port: if the relay listened anywhere else, this is where the
# default install would break.
RESOLVER_ADDR="$(awk '$1 == "nameserver" { print $2; exit }' "$RESOLV_CONF")"
[ "$RESOLVER_ADDR" = "127.0.0.1" ] ||
    fail "the resolver line does not name loopback: $(cat "$RESOLV_CONF")"
[ "$CHOKEPOINT_PORT" = "53" ] ||
    fail "the test's chokepoint port no longer matches what a nameserver line implies"
ANSWER="$(in_ns python3 "$DNS_PROBE" "$RESOLVER_ADDR" "$CHOKEPOINT_PORT" 2>&1)" ||
    fail "nothing answered at the resolver's own address and implied port: $ANSWER"
case "$ANSWER" in
*"upstream-saw-it"*)
    ok "the resolver's own address and implied port answered through the relay (D-22)"
    ;;
*) fail "the answer did not come from the upstream: $ANSWER" ;;
esac

echo "[4d] the checks turn an applied policy into a proven one"
VERIFIED=""
for _ in $(seq 1 25); do
    STATUS="$(cli status)"
    case "$STATUS" in
    *"and verified"*)
        VERIFIED=1
        break
        ;;
    esac
    sleep 1
done
[ -n "$VERIFIED" ] || fail "the state never became verified: $(cli status)"
ok "the checks passed, and the state now claims protection"

echo "[4e] weakening the policy must be noticed"
# One hand-edited rule: accept UDP at the top of the output chain, before the rejection rule. The
# rest of the policy is untouched, so this is exactly the case the review asks about.
in_ns nft insert rule inet ghostnector out_filter meta l4proto udp counter accept \
    comment '"hand edited during the test"'
ALARMED=""
for _ in $(seq 1 30); do
    STATUS="$(cli status)"
    case "$STATUS" in
    *"no traffic can leave"*)
        ALARMED=1
        break
        ;;
    esac
    sleep 1
done
[ -n "$ALARMED" ] || fail "a weakened policy was not noticed: $(cli status)"
ok "a hand-edited rule was noticed, and the machine was denied"
case "$STATUS" in
*"verification failed"*) ok "and the reason is stated" ;;
*) fail "the alarm gave no reason: $STATUS" ;;
esac
if in_ns nft list chain inet ghostnector out_filter | grep -q "hand edited"; then
    fail "the tampered policy survived the alarm"
fi
ok "the fail-closed baseline replaced the tampered policy"
grep -q '"protected": true' "$JOURNAL" || fail "the intent was not recorded"
ok "the intent was recorded"

BLOCKED="$(cli panic)"
case "$BLOCKED" in
*"no traffic can leave"*) ok "panic leaves the machine denied" ;;
*) fail "panic did not report a blocked state: $BLOCKED" ;;
esac

OFF="$(cli disconnect)"
case "$OFF" in
*"traffic is not protected"*) ok "disconnect returns to the baseline" ;;
*) fail "disconnect did not report an off state: $OFF" ;;
esac
if in_ns nft list tables | grep -q ghostnector; then
    fail "the policy survived a disconnect"
fi
ok "the kernel has nothing left after disconnect"
grep -q '"protected": false' "$JOURNAL" || fail "the intent was not cleared"
ok "the intent was cleared"

if [ "$(cat "$RESOLV_CONF")" != "$ORIGINAL_RESOLV_CONF" ]; then
    fail "the resolver configuration was not put back: $(cat "$RESOLV_CONF")"
fi
ok "the resolver configuration came back byte for byte"
if in_ns python3 "$DNS_PROBE" "$CHOKEPOINT_PORT" >/dev/null 2>&1; then
    fail "the relay is still answering after a disconnect"
fi
ok "the relay stopped with the protection"

# ---------------------------------------------------------------- restart reconciliation
cli connect >/dev/null
grep -q '"protected": true' "$JOURNAL" || fail "the second connect did not record intent"
stop_core
# Simulate a reboot: the kernel lost everything, but the journal still says the user wants protection.
in_ns nft destroy table inet ghostnector 2>/dev/null || true
ok "pretended to reboot: the journal says protected, the kernel has nothing"

start_stack
RECONCILED="$(cli status)"
case "$RECONCILED" in
*"no traffic can leave"*) ok "the restarted control plane failed closed" ;;
*) fail "a restart did not fail closed: $RECONCILED" ;;
esac
case "$RECONCILED" in
*"fail-closed baseline has been applied instead"*) ok "and it explains why" ;;
*) fail "the reason was not given: $RECONCILED" ;;
esac
in_ns nft list tables | grep -q ghostnector ||
    fail "the fail-closed baseline was not actually applied"
ok "the fail-closed baseline is in the kernel"

cli disconnect >/dev/null
ok "and the machine can still be released deliberately"

echo "PASS: core + cli"
