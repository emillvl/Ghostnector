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
NS="gh-core-app"
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
    ip netns del "$NS" 2>/dev/null || true
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
install -m 0755 "$TARGET_DIR/ghostnector-core" "$BINDIR/ghostnector-core"
install -m 0755 "$TARGET_DIR/ghostnector" "$BINDIR/ghostnector"
install -m 0755 "$TARGET_DIR/ghostnector-dns" "$BINDIR/ghostnector-dns"
chmod 0755 "$RUNDIR"
chown "$CORE_UID" "$RUNDIR" 2>/dev/null || true

ip netns add "$NS"
ip -n "$NS" link set lo up

COOKIE="$WORKDIR/control_auth_cookie"
head -c 32 /dev/urandom >"$COOKIE"
chown "$CORE_UID" "$COOKIE"
mkdir -p "$WORKDIR/root/etc"
printf 'nameserver 192.0.2.53\n' >"$WORKDIR/root/etc/resolv.conf"
chown -R "$CORE_UID" "$WORKDIR"

cat >"$WORKDIR/fake-tor.py" <<'PY'
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
PY

ip netns exec "$NS" python3 "$WORKDIR/fake-tor.py" "$CONTROL_PORT" >"$WORKDIR/tor.log" 2>&1 &
TOR_PID=$!
sleep 0.3

ip netns exec "$NS" "$BINDIR/ghostnector-netd" \
    --socket "$RUNDIR/netd.sock" --peer-uid "$CORE_UID" \
    --fallback-path "$WORKDIR/fail-closed.nft" >"$WORKDIR/netd.log" 2>&1 &
NETD_PID=$!
for _ in $(seq 1 60); do [ -S "$RUNDIR/netd.sock" ] && break; sleep 0.1; done
[ -S "$RUNDIR/netd.sock" ] || fail "the firewall helper did not start"

ip netns exec "$NS" "$BINDIR/ghostnector-appd" \
    --socket "$RUNDIR/appd.sock" --peer-user "$CORE_USER" \
    --state-dir "$WORKDIR/apps" --launcher "$BINDIR/ghostnector-appd-launch" \
    --bridge "$BRIDGE" --core "$CORE" --prefix "$PREFIX" --dead-device "$DEAD" \
    >"$WORKDIR/appd.log" 2>&1 &
APPD_PID=$!
for _ in $(seq 1 60); do [ -S "$RUNDIR/appd.sock" ] && break; sleep 0.1; done
[ -S "$RUNDIR/appd.sock" ] || fail "the namespace helper did not start"

ip netns exec "$NS" setpriv --reuid="$CORE_UID" --regid="$CORE_GID" --clear-groups \
    "$BINDIR/ghostnector-core" \
    --socket "$RUNDIR/core.sock" --helper "$RUNDIR/netd.sock" \
    --journal "$WORKDIR/intent.json" --resolver-state "$WORKDIR/resolver.json" \
    --resolv-conf-root "$WORKDIR/root" \
    --services external --tor-cookie "$COOKIE" --tor-control-port "$CONTROL_PORT" \
    --tor-bootstrap-seconds 10 --dns-helper "$BINDIR/ghostnector-dns" \
    --app-socket "$RUNDIR/appd.sock" --app-core "$CORE" \
    --group "$CORE_USER" \
    >"$WORKDIR/core.log" 2>&1 &
CORE_PID=$!
for _ in $(seq 1 60); do [ -S "$RUNDIR/core.sock" ] && break; sleep 0.1; done
[ -S "$RUNDIR/core.sock" ] || fail "the control plane did not start"

# The CLI runs as the launch user, with the control plane's group so it may reach the socket.
cli() {
    ip netns exec "$NS" setpriv --reuid="$LAUNCH_UID" --regid="$LAUNCH_GID" \
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
ip netns exec "$NS" ip link show "$BRIDGE" >/dev/null 2>&1 ||
    fail "the bridge was not created"
ip netns exec "$NS" nft list table inet ghostnector >/dev/null 2>&1 ||
    fail "the host table was not applied"
ok "the host table and the bridge exist"

echo "[2] a protected application session runs the command as the user"
LIST="$(cli apps 2>&1)"
case "$LIST" in
*"no protected applications"*) ok "nothing is protected yet" ;;
*) fail "unexpected apps output: $LIST" ;;
esac
OUTPUT="$(cli run -- id -u 2>&1)" || { echo "$OUTPUT"; fail "run failed"; }
note "the session said: $OUTPUT"
case "$OUTPUT" in
*"$LAUNCH_UID"*) ok "the command ran as uid $LAUNCH_UID inside the namespace" ;;
*) fail "the session did not run as the requesting user: $OUTPUT" ;;
esac
case "$OUTPUT" in
*"$LAUNCH_UID"*"$LAUNCH_GID"*) ok "the session's group is the user's group" ;;
*) : ;;
esac

LIST="$(cli apps 2>&1)"
case "$LIST" in
*"running"*) ok "the protected application is listed" ;;
*) fail "the application was not listed: $LIST" ;;
esac
APP_ID="$(printf '%s\n' "$LIST" | awk '/^  -/ { print $2; exit }')"
[ -n "$APP_ID" ] || fail "could not read the application id from: $LIST"

echo "[3] stopping one application removes its namespace"
cli stop-app "$APP_ID" >/dev/null || fail "stop-app failed"
LIST="$(cli apps 2>&1)"
case "$LIST" in
*"no protected applications"*) ok "the application is gone" ;;
*) fail "the application survived stop-app: $LIST" ;;
esac
[ ! -e "/run/netns/ghapp$APP_ID" ] || fail "the namespace survived stop-app"
ok "the namespace is gone"

echo "[4] disconnect removes everything and returns to off"
cli disconnect >/dev/null || fail "disconnect failed"
case "$(cli status 2>&1)" in
*"traffic is not protected"*) ok "the state is off" ;;
*) fail "unexpected state after disconnect: $(cli status 2>&1)" ;;
esac
ip netns exec "$NS" ip link show "$BRIDGE" >/dev/null 2>&1 &&
    fail "the bridge survived disconnect"
ip netns exec "$NS" nft list table inet ghostnector >/dev/null 2>&1 &&
    fail "the host table survived disconnect"
ok "the bridge and the host table are gone"

echo "[5] running an application is refused while protection is off"
OUTPUT="$(cli run -- id -u 2>&1)" && fail "run succeeded with protection off: $OUTPUT"
case "$OUTPUT" in
*"protection is not on"*) ok "the refusal explains why" ;;
*) fail "unexpected refusal: $OUTPUT" ;;
esac

echo
echo "PASS: APP scope end to end (connect, session, list, stop, disconnect)"
