#!/usr/bin/env bash
#
# APP scope end to end: CLI -> core -> netd + appd -> a real namespace session (M8.4).
#
#   scripts/core-app-test.sh <target/debug directory>
#
# It proves:
#   1. `connect --scope app` applies the host table, ensures the bridge, and claims nothing more
#      than `degraded` until verification exists;
#   2. `run` prepares a real session and runs the command the user asked for, as the user, inside
#      the namespace (the CLI writes the command to the user's own shell, never to a privileged
#      interface);
#   3. `apps` lists the protected application and `stop-app` removes it;
#   4. `disconnect` removes the namespaces, the bridge, and the host table;
#   5. `run` is refused while protection is off.
#
# Requires: root, iproute2, nftables, python3, setpriv (util-linux).

set -euo pipefail

TARGET_DIR="${1:?usage: core-app-test.sh <target/debug directory>}"
RUNDIR="/run/ghostnector"
BINDIR="/tmp/gh-app-bin"
WORKDIR="/tmp/gh-core-app"
CORE_USER="ghostnector-core"
LAUNCH_USER="ghostnector-launch-test"
CONTROL_PORT="9051"
BRIDGE="ghappbr0"
CORE="10.232.0.1"
PREFIX="24"
DEAD="ghdead"
NETD_PID=""
APPD_PID=""
CORE_PID=""
TOR_PID=""

cleanup() {
    for pid in "$CORE_PID" "$APPD_PID" "$NETD_PID" "$TOR_PID"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    for ns in ghapp1 ghapp2 ghapp3; do ip netns del "$ns" 2>/dev/null || true; done
    ip link del "$BRIDGE" 2>/dev/null || true
    nft destroy table inet ghostnector 2>/dev/null || true
    rm -rf "$BINDIR" "$WORKDIR" "$RUNDIR/appd.sock" "$RUNDIR/core.sock" "$RUNDIR/netd.sock"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    for log in "$WORKDIR/core.log" "$WORKDIR/appd.log" "$WORKDIR/netd.log" "$WORKDIR/tor.log"; do
        [ -f "$log" ] && { echo "--- $log ---"; tail -25 "$log"; }
    done
    exit 1
}
ok() { echo "  ok: $*"; }
note() { echo "    $*"; }

[ "$(id -u)" = "0" ] || fail "this test needs root"

for user in "$CORE_USER"; do
    id -u "$user" >/dev/null 2>&1 || \
        useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$user"
done
if ! id -u "$LAUNCH_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /bin/sh "$LAUNCH_USER"
fi
CORE_UID="$(id -u "$CORE_USER")"
CORE_GID="$(id -g "$CORE_USER")"
LAUNCH_UID="$(id -u "$LAUNCH_USER")"
LAUNCH_GID="$(id -g "$LAUNCH_USER")"

mkdir -p "$BINDIR" "$WORKDIR" "$RUNDIR"
install -m 0755 "$TARGET_DIR/ghostnector-netd" "$BINDIR/ghostnector-netd"
install -m 0755 "$TARGET_DIR/ghostnector-appd" "$BINDIR/ghostnector-appd"
install -m 0755 "$TARGET_DIR/ghostnector-appd-launch" "$BINDIR/ghostnector-appd-launch"
install -m 0755 "$TARGET_DIR/ghostnector-appd-probe" "$BINDIR/ghostnector-appd-probe"
install -m 0755 "$TARGET_DIR/ghostnector-appd-relay" "$BINDIR/ghostnector-appd-relay"
install -m 0755 "$TARGET_DIR/ghostnector-core" "$BINDIR/ghostnector-core"
install -m 0755 "$TARGET_DIR/ghostnector" "$BINDIR/ghostnector"
install -m 0755 "$TARGET_DIR/ghostnector-dns" "$BINDIR/ghostnector-dns"
chmod 0755 "$RUNDIR"
chown "$CORE_UID" "$RUNDIR" 2>/dev/null || true

# The whole stack runs in the initial network namespace, exactly as in production: `appd` must be
# able to create and re-enter named namespaces, which only works from the initial namespace. The
# test owns every object it creates and removes them all in the trap above.
COOKIE="$WORKDIR/control_auth_cookie"
head -c 32 /dev/urandom >"$COOKIE"
chown "$CORE_UID" "$COOKIE"
mkdir -p "$WORKDIR/root/etc"
printf 'nameserver 192.0.2.53\n' >"$WORKDIR/root/etc/resolv.conf"
chown -R "$CORE_UID" "$WORKDIR"

cat >"$WORKDIR/fake-tor.py" <<'PY'
"""A stand-in for Tor: control, SocksPort, and DNSPort.

It does not relay anywhere: the point of the test is that an APP session reaches *these* listeners
through the namespace relay, with its own source address and its intended destination, and gets an
answer back. The relay speaks SOCKS to this port; the fake records what it asked for.
"""
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
        log.write(json.dumps({"kind": kind, **fields}) + "\n")


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
    # The core address exists only after the helper has created the bridge; wait for it rather than
    # binding a wildcard. Nothing in this double is reachable except through the namespace relay.
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
    # The relay forwards to loopback; the fake never needs to be reachable from anywhere else.
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

: >"$WORKDIR/events.jsonl"
python3 "$WORKDIR/fake-tor.py" "$CONTROL_PORT" 9050 9053 "$CORE" "$WORKDIR/events.jsonl" \
    >"$WORKDIR/tor.log" 2>&1 &
TOR_PID=$!
sleep 0.3

# Wait until a helper socket exists AND carries its final mode.
#
# The daemons bind and then set the socket's group/mode immediately; a client that connects inside
# that microsecond window gets EACCES on a socket that is briefly owner-only behind the process's
# umask. The gate hit that race once (`core-app rc=1`, `FAIL: connect failed`). Waiting for the
# final mode removes the race without touching the product.
wait_socket() { # path expected-mode label
    local i
    for i in $(seq 1 100); do
        [ -S "$1" ] && [ "$(stat -c %a "$1" 2>/dev/null)" = "$2" ] && return 0
        sleep 0.1
    done
    return 1
}

"$BINDIR/ghostnector-netd" \
    --socket "$RUNDIR/netd.sock" --peer-uid "$CORE_UID" \
    --app-bridge "$BRIDGE" --app-core "$CORE" \
    --fallback-path "$WORKDIR/fail-closed.nft" >"$WORKDIR/netd.log" 2>&1 &
NETD_PID=$!
wait_socket "$RUNDIR/netd.sock" 600 "the firewall helper" ||
    fail "the firewall helper did not start"

"$BINDIR/ghostnector-appd" \
    --socket "$RUNDIR/appd.sock" --peer-user "$CORE_USER" \
    --state-dir "$WORKDIR/apps" --launcher "$BINDIR/ghostnector-appd-launch" \
    --probe "$BINDIR/ghostnector-appd-probe" --relay "$BINDIR/ghostnector-appd-relay" \
    --bridge "$BRIDGE" --core "$CORE" --prefix "$PREFIX" --dead-device "$DEAD" \
    >"$WORKDIR/appd.log" 2>&1 &
APPD_PID=$!
wait_socket "$RUNDIR/appd.sock" 600 "the namespace helper" ||
    fail "the namespace helper did not start"

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
    --group "$CORE_USER" \
    >"$WORKDIR/core.log" 2>&1 &
CORE_PID=$!
wait_socket "$RUNDIR/core.sock" 660 "the control plane" ||
    fail "the control plane did not start"

# The CLI runs as the launch user, with the control plane's group so it may reach the socket.
cli() {
    setpriv --reuid="$LAUNCH_UID" --regid="$LAUNCH_GID" \
        --groups "$CORE_GID" \
        "$BINDIR/ghostnector" --socket "$RUNDIR/core.sock" "$@"
}

echo "[1] connect --scope app prepares the structure and claims nothing yet"
CONNECTED="$(cli connect --scope app 2>&1)" || { echo "$CONNECTED"; fail "connect failed"; }
case "$CONNECTED" in
*"protected, but unverified"*) ok "the state is degraded until something verifies it" ;;
*) fail "unexpected connect output: $CONNECTED" ;;
esac
case "$CONNECTED" in
*"chosen applications"*) ok "the scope is reported as chosen applications" ;;
*) fail "the scope was not reported: $CONNECTED" ;;
esac
ip link show "$BRIDGE" >/dev/null 2>&1 ||
    fail "the bridge was not created"
nft list table inet ghostnector >/dev/null 2>&1 ||
    fail "the host table was not applied"
ok "the host table and the bridge exist"

echo "[2] a protected application session runs the command as the user, through Tor"
LIST="$(cli apps 2>&1)"
case "$LIST" in
*"no protected applications"*) ok "nothing is protected yet" ;;
*) fail "unexpected apps output: $LIST" ;;
esac

cat >"$WORKDIR/probe.py" <<'PY'
import socket

print("uid:" + str(__import__("os").getuid()))

# TCP: the namespace relay DNATs the connection to itself, reads the original destination, and
# speaks SOCKS to the core address, where this stand-in answers.
connection = socket.socket()
connection.settimeout(5)
connection.connect(("198.51.100.10", 80))
print("tcp:" + connection.recv(16).decode(errors="replace"))
connection.close()

# DNS: the namespace resolver points at the core address, and the chokepoint forwards to Tor.
query = bytes([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
query += b"\x06canary\x04test\x00\x00\x01\x00\x01"
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(query, ("10.232.0.1", 53))
answer, _ = udp.recvfrom(1024)
print("dns:" + ".".join(str(byte) for byte in answer[-4:]))
PY

OUTPUT="$(cli run -- python3 "$WORKDIR/probe.py" </dev/null 2>&1)" || { echo "$OUTPUT"; fail "run failed"; }
note "the session said: $OUTPUT"
case "$OUTPUT" in
*"uid:$LAUNCH_UID"*) ok "the command ran as uid $LAUNCH_UID inside the namespace" ;;
*) fail "the session did not run as the requesting user: $OUTPUT" ;;
esac
case "$OUTPUT" in
*"tcp:tor-ok"*) ok "TCP reached the core through the namespace relay" ;;
*) fail "the protected TCP path did not answer: $OUTPUT" ;;
esac
case "$OUTPUT" in
*"dns:203.0.113.9"*) ok "DNS was answered by Tor's DNSPort through the chokepoint" ;;
*) fail "the protected DNS path did not answer: $OUTPUT" ;;
esac

LIST="$(cli apps 2>&1)"
case "$LIST" in
*"running"*) ok "the protected application is listed" ;;
*) fail "the application was not listed: $LIST" ;;
esac
APP_ID="$(printf '%s\n' "$LIST" | awk '/^  -/ { print $2; exit }')"
APP_ADDR="$(printf '%s\n' "$LIST" | awk '/^  -/ { print $3; exit }')"
[ -n "$APP_ID" ] || fail "could not read the application id from: $LIST"
[ -n "$APP_ADDR" ] || fail "could not read the application address from: $LIST"

# Source and destination preservation: the relay spoke SOCKS as the application's own address and
# asked for the application's intended destination, not the relay's own or a rewritten one.
grep -q "\"kind\": \"socks\", \"from_address\": \"$APP_ADDR\"" "$WORKDIR/events.jsonl" ||
    { cat "$WORKDIR/events.jsonl"; fail "the core did not see the application's own source address"; }
grep -q "\"destination\": \"198.51.100.10:80\"" "$WORKDIR/events.jsonl" ||
    { cat "$WORKDIR/events.jsonl"; fail "the intended destination did not survive the relay"; }
grep -q "\"user\": \"app$APP_ID\"" "$WORKDIR/events.jsonl" ||
    { cat "$WORKDIR/events.jsonl"; fail "the relay did not authenticate with the per-group credential"; }
ok "the core saw the application's source address and destination ($APP_ADDR -> 198.51.100.10:80): no masquerade, no rewrite"

# The chokepoint forwarded the query to Tor's DNSPort from loopback, as designed.
grep -q '"kind": "dns", "from_address": "127.0.0.1"' "$WORKDIR/events.jsonl" ||
    { cat "$WORKDIR/events.jsonl"; fail "the chokepoint did not forward the query"; }
ok "the chokepoint forwarded the query to Tor's DNSPort"

echo "[2b] a session returns when its command ends even if the caller's stdin stays open"
# The CLI relays standard input; after the session ends it must not wait for that input to close,
# or an interactive terminal (or any pipe that stays open) would hang after the protected command
# has already finished. `sleep 30` holds stdin open via process substitution; the session runs
# `/bin/true` and must return promptly.
STARTED_AT="$(date +%s)"
if timeout 25 setpriv --reuid="$LAUNCH_UID" --regid="$LAUNCH_GID" --groups "$CORE_GID" \
    "$BINDIR/ghostnector" --socket "$RUNDIR/core.sock" run -- /bin/true \
    < <(sleep 30) >/dev/null 2>&1; then
    SESSION_RC=0
else
    SESSION_RC=$?
fi
SESSION_SECS=$(( $(date +%s) - STARTED_AT ))
[ "$SESSION_RC" = "0" ] ||
    fail "a session with held-open stdin did not return cleanly (rc=$SESSION_RC, ${SESSION_SECS}s)"
[ "$SESSION_SECS" -lt 15 ] ||
    fail "a session with held-open stdin took ${SESSION_SECS}s; it must return when the command does"
ok "the session returned in ${SESSION_SECS}s with its stdin still open"
# The [2b] session created its own group (its command has exited, but a group lives until it is
# stopped); remove every group except the one step [2] owns so the later listing assertions see
# the state they expect.
for extra in $(cli apps 2>&1 | awk '/^  -/ { print $2 }'); do
    [ "$extra" = "$APP_ID" ] || cli stop-app "$extra" >/dev/null 2>&1 || true
done

echo "[3] verification runs inside the namespace and is the only route to Protected"
VERIFIED=""
for _ in $(seq 1 20); do
    STATUS="$(cli status 2>&1)"
    case "$STATUS" in
    *"protected — and verified"*) VERIFIED=1; break ;;
    esac
    sleep 1
done
[ -n "$VERIFIED" ] || fail "the state never became verified: $(cli status 2>&1)"
ok "per-app evidence turned the state into protected-and-verified"
case "$STATUS" in
*"the canary resolved as expected"*) ok "the canary check ran inside the namespace" ;;
*) note "verification details: $STATUS" ;;
esac

echo "[4] stopping one application removes its namespace"
cli stop-app "$APP_ID" >/dev/null || fail "stop-app failed"
LIST="$(cli apps 2>&1)"
case "$LIST" in
*"no protected applications"*) ok "the application is gone" ;;
*) fail "the application survived stop-app: $LIST" ;;
esac
[ ! -e "/run/netns/ghapp$APP_ID" ] || fail "the namespace survived stop-app"
ok "the namespace is gone"

echo "[5] a tampered namespace blocks the APP scope and removes the namespaces"
OUTPUT="$(cli run -- python3 "$WORKDIR/probe.py" </dev/null 2>&1)" || { echo "$OUTPUT"; fail "run failed"; }
LIST="$(cli apps 2>&1)"
APP_ID="$(printf '%s\n' "$LIST" | awk '/^  -/ { print $2; exit }')"
[ -n "$APP_ID" ] || fail "no application to tamper with: $LIST"
for _ in $(seq 1 20); do
    case "$(cli status 2>&1)" in
    *"protected — and verified"*) break ;;
    esac
    sleep 1
done
note "namespaces before tampering: $(ip netns list 2>&1 | tr '\n' ' ')"
note "/run/netns: $(ls /run/netns 2>&1 | tr '\n' ' ')"
ip netns exec "ghapp$APP_ID" nft insert rule inet ghostnector out_filter \
    meta l4proto tcp counter accept
BLOCKED=""
for _ in $(seq 1 20); do
    STATUS="$(cli status 2>&1)"
    case "$STATUS" in
    *"no protected application can reach the network"*) BLOCKED=1; break ;;
    esac
    sleep 1
done
[ -n "$BLOCKED" ] || fail "the tampered namespace did not block the APP scope: $(cli status 2>&1)"
ok "the state is blocked with APP-scoped wording"
[ ! -e "/run/netns/ghapp$APP_ID" ] ||
    fail "the tampered namespace was not removed"
ok "the namespace was removed, so no application can reach the network"

echo "[6] disconnect removes everything and returns to off"
cli disconnect >/dev/null || fail "disconnect failed"
case "$(cli status 2>&1)" in
*"traffic is not protected"*) ok "the state is off" ;;
*) fail "unexpected state after disconnect: $(cli status 2>&1)" ;;
esac
ip link show "$BRIDGE" >/dev/null 2>&1 &&
    fail "the bridge survived disconnect"
nft list table inet ghostnector >/dev/null 2>&1 &&
    fail "the host table survived disconnect"
ok "the bridge and the host table are gone"

echo "[7] running an application is refused while protection is off"
OUTPUT="$(cli run -- id -u 2>&1)" && fail "run succeeded with protection off: $OUTPUT"
case "$OUTPUT" in
*"protection is not on"*) ok "the refusal explains why" ;;
*) fail "unexpected refusal: $OUTPUT" ;;
esac

echo
echo "PASS: APP scope end to end (connect, session, list, stop, disconnect)"
