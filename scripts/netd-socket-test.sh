#!/usr/bin/env bash
#
# Exercises the privileged helper end to end: socket ownership, peer credentials, the closed verb
# set, and a real nftables apply/revert — all inside a throwaway network namespace, so nothing the
# host depends on is touched.
#
#   scripts/netd-socket-test.sh <path-to-ghostnector-netd>
#
# What it proves:
#   1. the helper creates a socket its single peer can use, and nobody else can
#   2. a connection from uid 0 is refused, even though root may open the file (SO_PEERCRED)
#   3. the peer can apply a profile, see the kernel-side table in the report, and revert it
#   4. the kernel really has no table afterwards, and no other table was created
#
# Requires: root, iproute2, nftables, python3, setpriv (util-linux).

set -euo pipefail

NETD="${1:?usage: netd-socket-test.sh <path-to-ghostnector-netd>}"
NS="gh-netd-test"
RUNDIR="/run/ghostnector"
SOCK="$RUNDIR/netd.sock"
PEER_USER="ghostnector-core"
OUTSIDER_USER="ghostnector-outsider"
CLIENT="/tmp/gh-netd-client.py"
LOG="/tmp/gh-netd.log"
NETD_PID=""

cleanup() {
    if [ -n "$NETD_PID" ]; then kill "$NETD_PID" 2>/dev/null || true; fi
    ip netns del "$NS" 2>/dev/null || true
    rm -f "$SOCK" "$CLIENT"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok: $*"; }

[ "$(id -u)" = "0" ] || fail "this test needs root"

# ---------------------------------------------------------------- the peer identity
if ! id -u "$PEER_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$PEER_USER"
fi
if ! id -u "$OUTSIDER_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$OUTSIDER_USER"
fi
PEER_UID="$(id -u "$PEER_USER")"
PEER_GID="$(id -g "$PEER_USER")"
OUTSIDER_UID="$(id -u "$OUTSIDER_USER")"
OUTSIDER_GID="$(id -g "$OUTSIDER_USER")"
[ "$PEER_UID" != "0" ] || fail "the peer identity must not be root"

ip netns add "$NS"
mkdir -p "$RUNDIR"

cat >"$CLIENT" <<'PY'
import json, socket, sys

sock_path, mode = sys.argv[1], sys.argv[2]


def send(s, obj):
    s.sendall((json.dumps(obj, separators=(",", ":")) + "\n").encode())


def recv_line(s):
    """Return the next line exactly as the helper sent it, or None at end of stream."""
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            return None
        buf += chunk
    return buf.decode().rstrip("\n")


def show(label, line):
    print(f"{label} {line if line is not None else 'EOF'}")


connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.settimeout(15)
try:
    connection.connect(sock_path)
    send(connection, {"verb": "hello", "protocol": 1})
    first = recv_line(connection)
except (ConnectionResetError, BrokenPipeError, ConnectionRefusedError, PermissionError):
    # An unauthorised peer is refused without a reply, and because the helper never reads from it
    # the kernel reports the closed connection as a reset rather than an orderly end of stream.
    first = None

if first is None:
    print("REFUSED")
    sys.exit(0)

show("HELLO", first)
if mode == "refused":
    sys.exit(0)

for label, request in (
    ("APPLY", {"verb": "apply_profile", "profile": "tor_system", "params": {}}),
    ("REPORT", {"verb": "report"}),
    ("REVERT", {"verb": "revert"}),
    ("REPORT", {"verb": "report"}),
):
    send(connection, request)
    show(label, recv_line(connection))
PY

# ---------------------------------------------------------------- start the helper
ip netns exec "$NS" "$NETD" --socket "$SOCK" --peer-uid "$PEER_UID" >"$LOG" 2>&1 &
NETD_PID=$!
for _ in $(seq 1 50); do
    [ -S "$SOCK" ] && break
    sleep 0.1
done
if [ ! -S "$SOCK" ]; then
    cat "$LOG"
    fail "the helper did not create its socket"
fi
ok "helper listening on $SOCK"

# ---------------------------------------------------------------- socket ownership
read -r mode owner < <(stat -c '%a %u' "$SOCK")
[ "$mode" = "600" ] || fail "socket mode is $mode, expected 600"
[ "$owner" = "$PEER_UID" ] || fail "socket owner is $owner, expected $PEER_UID"
ok "socket is mode 600, owned by uid $PEER_UID"

# ---------------------------------------------------------------- who may talk to the helper
ROOT_OUT="$(python3 "$CLIENT" "$SOCK" refused 2>&1 || true)"
case "$ROOT_OUT" in
HELLO*)
    ok "root is accepted, which is what the boot guard needs"
    ;;
*) fail "root should be accepted, got: $ROOT_OUT" ;;
esac

OUTSIDER_OUT="$(setpriv --reuid="$OUTSIDER_UID" --regid="$OUTSIDER_GID" --clear-groups \
    python3 "$CLIENT" "$SOCK" refused 2>&1 || true)"
case "$OUTSIDER_OUT" in
REFUSED*)
    ok "a user who is not the peer cannot reach the helper"
    ;;
*) fail "an outsider should not reach the helper, got: $OUTSIDER_OUT" ;;
esac

# ---------------------------------------------------------------- the peer's session
SESSION="$(setpriv --reuid="$PEER_UID" --regid="$PEER_GID" --clear-groups \
    python3 "$CLIENT" "$SOCK" full 2>&1)" || {
    echo "$SESSION"
    fail "the peer's session failed"
}

case "$SESSION" in
*'HELLO {"result":"hello"'*) ok "handshake" ;;
*) fail "handshake failed: $SESSION" ;;
esac
case "$SESSION" in
*'APPLY {"result":"applied"'*) ok "the peer applied TorSystem" ;;
*) fail "apply failed: $SESSION" ;;
esac
case "$SESSION" in
*'"applied":true'*) ok "the report saw the table in the kernel" ;;
*) fail "the report did not see the table: $SESSION" ;;
esac
case "$SESSION" in
*'"applied":false'*) ok "revert cleared the table" ;;
*) fail "revert did not clear the table: $SESSION" ;;
esac
case "$SESSION" in
*'system-user:tor'*) ok "the exemption list names Tor" ;;
*) fail "the exemption list looks wrong: $SESSION" ;;
esac

# ---------------------------------------------------------------- the kernel agrees
if ip netns exec "$NS" nft list tables | grep -q ghostnector; then
    fail "the table survived the revert"
fi
ok "the kernel has no ghostnector table after revert"

REMAINING="$(ip netns exec "$NS" nft list tables | wc -l)"
[ "$REMAINING" = "0" ] || fail "unexpected tables remain: $REMAINING"
ok "no other tables were created"

echo "PASS: netd socket"
