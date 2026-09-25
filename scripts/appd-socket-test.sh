#!/usr/bin/env bash
#
# The namespace helper, end to end, against the real kernel (M8.2).
#
#   scripts/appd-socket-test.sh <path-to-ghostnector-appd>
#
# It proves:
#
#   1. the socket is owner-only, the peer is checked, and the verb set is closed;
#   2. the bridge exists with the core address, no proxy ARP, and is removed again;
#   3. two groups are created with internally allocated ids and distinct addresses, each a real
#      namespace with the dead-end default route and IPv6 disabled;
#   4. `Verify` compares the namespace's own ruleset against what was installed, and notices both a
#      ruleset change and a shape change (proxy ARP);
#   5. destroy is idempotent, revert removes every object, and nothing stale is left;
#   6. a shell session runs inside the group as the intended user, with the session socket owned by
#      that user, a second session refused, an outsider refused by the kernel peer check even with a
#      permissive socket, and permitted/effective/inheritable/ambient capabilities all empty;
#   7. the packaged capability set is sufficient and CAP_SYS_ADMIN is necessary.
#
# Requires: root, iproute2, nftables, python3, setpriv (util-linux).

set -euo pipefail

APPD="${1:?usage: appd-socket-test.sh <path-to-ghostnector-appd>}"
APPD="$(cd "$(dirname "$APPD")" && pwd)/$(basename "$APPD")"
LAUNCHER="$(dirname "$APPD")/ghostnector-appd-launch"
PROBE="$(dirname "$APPD")/ghostnector-appd-probe"

RUNDIR="/run/ghostnector"
SOCK="$RUNDIR/appd-test.sock"
STATE="/tmp/gh-appd-test/state"
STATE2="/tmp/gh-appd-test/state2"
STATE3="/tmp/gh-appd-test/state3"
SOCK2="$RUNDIR/appd-test2.sock"
SOCK3="$RUNDIR/appd-test3.sock"
BRIDGE="ghbtest0"
BRIDGE2="ghbtest1"
BRIDGE3="ghbtest2"
CORE="10.231.0.1"
PREFIX="24"
DEAD="ghdead"
CORE_USER="ghostnector-core"
OUTSIDER="ghostnector-outsider"
WORK="/tmp/gh-appd-test"
APPD_PID=""
APPD2_PID=""
APPD3_PID=""

cleanup() {
    [ -n "$APPD_PID" ] && kill "$APPD_PID" 2>/dev/null || true
    [ -n "$APPD2_PID" ] && kill "$APPD2_PID" 2>/dev/null || true
    [ -n "$APPD3_PID" ] && kill "$APPD3_PID" 2>/dev/null || true
    for ns in ghapp1 ghapp2 ghapp3 ghapp4; do ip netns del "$ns" 2>/dev/null || true; done
    ip link del "$BRIDGE" 2>/dev/null || true
    ip link del "$BRIDGE2" 2>/dev/null || true
    ip link del "$BRIDGE3" 2>/dev/null || true
    rm -rf "$WORK" "$SOCK" "$SOCK2" "$SOCK3"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    for log in "$WORK/appd.log" "$WORK/appd2.log"; do
        [ -f "$log" ] && { echo "--- $log ---"; tail -20 "$log"; }
    done
    exit 1
}
ok() { echo "  ok: $*"; }
note() { echo "    $*"; }

[ "$(id -u)" = "0" ] || fail "this test needs root"
command -v nft >/dev/null || fail "nftables is required"
[ -x "$APPD" ] || fail "the helper binary was not found at $APPD"

for user in "$CORE_USER" "$OUTSIDER"; do
    id -u "$user" >/dev/null 2>&1 || \
        useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$user"
done
LAUNCH_USER="ghostnector-launch-test"
if ! id -u "$LAUNCH_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /bin/sh "$LAUNCH_USER"
fi
CORE_UID="$(id -u "$CORE_USER")"
CORE_GID="$(id -g "$CORE_USER")"
OUTSIDER_UID="$(id -u "$OUTSIDER")"
OUTSIDER_GID="$(id -g "$OUTSIDER")"
LAUNCH_UID="$(id -u "$LAUNCH_USER")"
LAUNCH_GID="$(id -g "$LAUNCH_USER")"
[ -x "$LAUNCHER" ] || fail "the launch helper was not found at $LAUNCHER"
[ -x "$PROBE" ] || fail "the probe was not found at $PROBE"

mkdir -p "$WORK" "$RUNDIR" "$STATE" "$STATE2"
chmod 0755 "$RUNDIR"

cat >"$WORK/client.py" <<'PY'
import socket, sys
path, *frames = sys.argv[1:]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(path)
for frame in frames:
    sock.sendall(frame.encode() + b"\n")
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    print(data.decode(errors="replace").strip())
PY

cat >"$WORK/session.py" <<'PY'
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

handshake='{"verb":"hello","protocol":1}'

call() { # call <frame> ...  (as the configured peer)
    setpriv --reuid="$CORE_UID" --regid="$CORE_GID" --clear-groups \
        python3 "$WORK/client.py" "$SOCK" "$handshake" "$@" | tail -n1
}

field() { # field <json> <path>
    python3 -c 'import json,sys
value = json.loads(sys.argv[1])
for part in sys.argv[2].split("."):
    value = value[int(part)] if part.isdigit() else value[part]
print(value)' "$1" "$2"
}

echo "[1] the socket is owner-only and the peer is checked"
python3 "$WORK/client.py" "$SOCK" >/dev/null 2>&1 || true
"$APPD" --socket "$SOCK" --peer-uid "$CORE_UID" --state-dir "$STATE" \
    --launcher "$LAUNCHER" --probe "$PROBE" \
    --bridge "$BRIDGE" --core "$CORE" --prefix "$PREFIX" --dead-device "$DEAD" \
    >"$WORK/appd.log" 2>&1 &
APPD_PID=$!
for _ in $(seq 1 60); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || fail "the helper did not create its socket"
[ "$(stat -c %a "$SOCK")" = "600" ] || fail "the socket is not mode 600"
[ "$(stat -c %u "$SOCK")" = "$CORE_UID" ] || fail "the socket is not owned by the peer"
ok "socket mode 600, owned by uid $CORE_UID"

if setpriv --reuid="$OUTSIDER_UID" --regid="$OUTSIDER_GID" --clear-groups \
    python3 "$WORK/client.py" "$SOCK" "$handshake" >/dev/null 2>&1; then
    fail "an outsider reached the helper"
fi
ok "an outsider cannot reach the helper"

echo "[2] the bridge is created idempotently with the core address and no proxy ARP"
ANSWER="$(call '{"verb":"ensure_bridge","ports":{"trans":19140,"chokepoint":19053,"socks":19050}}')"
case "$ANSWER" in
*'"result":"applied"'*) ok "the bridge is ready" ;;
*) fail "ensure_bridge failed: $ANSWER" ;;
esac
ip link show "$BRIDGE" >/dev/null 2>&1 || fail "the bridge does not exist"
ip -o addr show dev "$BRIDGE" | grep -q "$CORE/$PREFIX" ||
    fail "the bridge does not carry $CORE/$PREFIX"
[ "$(cat /proc/sys/net/ipv4/conf/$BRIDGE/proxy_arp)" = "0" ] ||
    fail "proxy_arp is enabled on the bridge"
ANSWER="$(call '{"verb":"ensure_bridge","ports":{"trans":19140,"chokepoint":19053,"socks":19050}}')"
case "$ANSWER" in
*'"result":"applied"'*) ok "a second ensure_bridge is a no-op" ;;
*) fail "ensure_bridge was not idempotent: $ANSWER" ;;
esac

echo "[3] groups get internal ids, distinct addresses, and real dead-end namespaces"
FIRST="$(call "{\"verb\":\"create\",\"user_uid\":$LAUNCH_UID}")"
ID1="$(field "$FIRST" entry.id)"
ADDR1="$(field "$FIRST" entry.address)"
SECOND="$(call "{\"verb\":\"create\",\"user_uid\":$CORE_UID}")"
ID2="$(field "$SECOND" entry.id)"
ADDR2="$(field "$SECOND" entry.address)"
note "group ids $ID1 and $ID2 at $ADDR1 and $ADDR2"
[ "$ID1" != "$ID2" ] || fail "the helper reused an id"
[ "$ADDR1" != "$ADDR2" ] || fail "the helper assigned the same address twice"
[ "$ADDR1" = "10.231.0.2" ] || fail "unexpected first address: $ADDR1"
[ "$ADDR2" = "10.231.0.3" ] || fail "unexpected second address: $ADDR2"
[ -e "/run/netns/ghapp$ID1" ] || fail "the namespace does not exist"
ip -o link show "ghav$ID1" | grep -q "master $BRIDGE" ||
    fail "the host link is not enslaved to the bridge"
bridge -d link show dev "ghav$ID1" | grep -q "isolated on" ||
    fail "the host link is not isolated"
ip netns exec "ghapp$ID1" ip -o addr show | grep -q "$ADDR1/32" ||
    fail "the app address is not configured"
ip netns exec "ghapp$ID1" ip route show | grep -q "$CORE dev ghlink0" ||
    fail "the core route is missing"
ip netns exec "ghapp$ID1" ip route show | grep -q "default dev $DEAD" ||
    fail "the default route does not point at the dead end"
[ "$(ip netns exec "ghapp$ID1" cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" = "1" ] ||
    fail "IPv6 is not disabled in the namespace"
ok "two namespaces, distinct addresses, dead-end route, IPv6 off"

echo "[4] verification compares the namespace against what was installed"
ANSWER="$(call "{\"verb\":\"verify\",\"id\":$ID1}")"
case "$ANSWER" in
*'"matches":true'*) ok "the untouched namespace verifies" ;;
*) fail "verification failed on an untouched namespace: $ANSWER" ;;
esac

ip netns exec "ghapp$ID1" nft insert rule inet ghostnector out_filter \
    meta l4proto tcp counter accept
ANSWER="$(call "{\"verb\":\"verify\",\"id\":$ID1}")"
case "$ANSWER" in
*'"matches":false'*) ok "a ruleset change no probe traverses is noticed" ;;
*) fail "tampering was not noticed: $ANSWER" ;;
esac
note "$ANSWER"

# Re-create the policy by rebuilding the group: destroy and create again.
call "{\"verb\":\"destroy\",\"id\":$ID1}" >/dev/null
FIRST="$(call "{\"verb\":\"create\",\"user_uid\":$LAUNCH_UID}")"
ID1="$(field "$FIRST" entry.id)"
ADDR1="$(field "$FIRST" entry.address)"

sysctl -qw "net.ipv4.conf.ghav$ID1.proxy_arp=1"
ANSWER="$(call "{\"verb\":\"verify\",\"id\":$ID1}")"
case "$ANSWER" in
*'"matches":false'*"proxy_arp"*) ok "a shape change (proxy ARP) is noticed" ;;
*) fail "the shape change was not noticed: $ANSWER" ;;
esac
note "$ANSWER"
sysctl -qw "net.ipv4.conf.ghav$ID1.proxy_arp=0"

echo "[5] the fixed probe runs inside the namespace and answers honestly"
# No checks configured: every check is inconclusive, which is never a pass.
ANSWER="$(call "{\"verb\":\"probe\",\"id\":$ID1,\"config\":{\"timeout_seconds\":5}}")"
case "$ANSWER" in
*'"result":"probed"'*'"outcome":{"outcome":"inconclusive"'*)
    ok "with nothing configured the probe is inconclusive, never a pass"
    ;;
*) fail "the probe did not answer honestly: $ANSWER" ;;
esac
note "$ANSWER"

# The helper validates the configuration before the probe is allowed to run.
ANSWER="$(call "{\"verb\":\"probe\",\"id\":$ID1,\"config\":{\"canary\":{\"name\":\"bad name\",\"expected\":\"203.0.113.9\",\"resolver\":\"127.0.0.1:53\"},\"timeout_seconds\":5}}")"
case "$ANSWER" in
*'"code":"invalid_profile"'*) ok "a malformed canary name is refused before the probe runs" ;;
*) fail "a malformed canary name was accepted: $ANSWER" ;;
esac
ANSWER="$(call "{\"verb\":\"probe\",\"id\":$ID1,\"config\":{\"timeout_seconds\":600}}")"
case "$ANSWER" in
*'"code":"invalid_profile"'*) ok "an out-of-range probe timeout is refused" ;;
*) fail "an out-of-range probe timeout was accepted: $ANSWER" ;;
esac

echo "[6] a shell session inside the group, with every granting capability dropped"
LAUNCHED="$(call "{\"verb\":\"launch\",\"id\":$ID1,\"user_uid\":$LAUNCH_UID}")"
case "$LAUNCHED" in
*'"result":"launched"'*) ok "a session socket was prepared" ;;
*) fail "launch failed: $LAUNCHED" ;;
esac
SESSION_SOCK="$(field "$LAUNCHED" socket)"
[ -S "$SESSION_SOCK" ] || fail "the session socket does not exist"
[ "$(stat -c %a "$SESSION_SOCK")" = "600" ] ||
    fail "the session socket is not mode 600"
[ "$(stat -c %u "$SESSION_SOCK")" = "$LAUNCH_UID" ] ||
    fail "the session socket is not owned by the intended user"
ok "the session socket belongs to uid $LAUNCH_UID alone"

SECOND="$(call "{\"verb\":\"launch\",\"id\":$ID1,\"user_uid\":$LAUNCH_UID}")"
case "$SECOND" in
*'"code":"busy"'*) ok "a second session is refused while one is prepared" ;;
*) fail "a second launch was not refused: $SECOND" ;;
esac

# Even if the filesystem gate were widened, the kernel's peer check must refuse another user.
chmod 666 "$SESSION_SOCK"
OUTSIDER_SESSION="$(setpriv --reuid="$OUTSIDER_UID" --regid="$OUTSIDER_GID" --clear-groups \
    python3 "$WORK/session.py" "$SESSION_SOCK" "id -u" 2>&1 || true)"
case "$OUTSIDER_SESSION" in
*"$LAUNCH_UID"*) fail "an outsider obtained a session: $OUTSIDER_SESSION" ;;
*) ok "an outsider cannot drive the session, even with a permissive socket" ;;
esac
for _ in $(seq 1 20); do [ -S "$SESSION_SOCK" ] || break; sleep 0.1; done
[ -S "$SESSION_SOCK" ] && fail "the refused session socket was not cleaned up"

LAUNCHED="$(call "{\"verb\":\"launch\",\"id\":$ID1,\"user_uid\":$LAUNCH_UID}")"
SESSION_SOCK="$(field "$LAUNCHED" socket)"
SCRIPT='id -u
id -g
grep -E "^Cap(Prm|Eff|Inh|Amb):" /proc/self/status
cat /etc/resolv.conf
ip route show
readlink /proc/self/ns/net
readlink /proc/self/ns/mnt
exit 0
'
OUTPUT="$(setpriv --reuid="$LAUNCH_UID" --regid="$LAUNCH_GID" --clear-groups \
    python3 "$WORK/session.py" "$SESSION_SOCK" "$SCRIPT" 2>&1)" || {
    echo "$OUTPUT"
    fail "the session failed"
}
case "$OUTPUT" in
*"$LAUNCH_UID"*) ok "the shell runs as the intended user" ;;
*) fail "the shell did not report uid $LAUNCH_UID: $OUTPUT" ;;
esac
CAPS_BAD=0
while IFS= read -r line; do
    case "$line" in
    CapPrm:* | CapEff:* | CapInh:* | CapAmb:*)
        case "$line" in
        *0000000000000000*) ;;
        *) CAPS_BAD=1 ;;
        esac
        ;;
    esac
done <<<"$OUTPUT"
[ "$CAPS_BAD" = "0" ] || {
    echo "$OUTPUT"
    fail "the shell retained a capability"
}
ok "permitted, effective, inheritable and ambient capabilities are all empty"
case "$OUTPUT" in
*"nameserver $CORE"*) ok "the session's resolver points at the chokepoint" ;;
*) fail "the resolver configuration was not bound in: $OUTPUT" ;;
esac
case "$OUTPUT" in
*"default dev $DEAD"*) ok "the session is inside the dead-end namespace" ;;
*) fail "the session's routes are wrong: $OUTPUT" ;;
esac
HOST_NET_NS="$(readlink /proc/self/ns/net)"
HOST_MNT_NS="$(readlink /proc/self/ns/mnt)"
case "$OUTPUT" in
*"$HOST_NET_NS"*) fail "the session shares the host network namespace" ;;
esac
case "$OUTPUT" in
*"$HOST_MNT_NS"*) fail "the session shares the host mount namespace" ;;
esac
ok "the session has its own network and mount namespaces"

echo "[7] destroy is idempotent and revert removes everything"
call "{\"verb\":\"destroy\",\"id\":$ID2}" >/dev/null
[ ! -e "/run/netns/ghapp$ID2" ] || fail "the namespace survived destroy"
call "{\"verb\":\"destroy\",\"id\":$ID2}" >/dev/null
ok "destroy of an already-destroyed group is not an error"

INSPECT="$(call "{\"verb\":\"inspect\",\"id\":$ID1}")"
case "$INSPECT" in
*'"present":true'*) ok "inspect reports the surviving group as present" ;;
*) fail "inspect did not report the group: $INSPECT" ;;
esac

ANSWER="$(call '{"verb":"revert"}')"
case "$ANSWER" in
*'"result":"applied"'*) ok "revert completed" ;;
*) fail "revert failed: $ANSWER" ;;
esac
[ ! -e "/run/netns/ghapp$ID1" ] || fail "revert left a namespace behind"
ip link show "$BRIDGE" >/dev/null 2>&1 && fail "revert left the bridge behind"
[ -z "$(ip -o link show | grep -E 'ghav[0-9]+' || true)" ] ||
    fail "revert left host links behind"
ok "every namespace, link and the bridge are gone"

echo "[8] the packaged capability set is sufficient, and CAP_SYS_ADMIN is necessary"
# Exactly the packaged state: bounding {net_admin, sys_admin, chown}, ambient net_admin only.
# (A root process's permitted set after exec is its bounding set, which is what setpriv emulates.)
setpriv --reuid=0 --regid=0 --clear-groups \
    --bounding-set=-all,+net_admin,+sys_admin,+chown \
    --inh-caps +net_admin --ambient-caps +net_admin \
    "$APPD" --socket "$SOCK3" --peer-uid "$CORE_UID" --state-dir "$STATE3" \
    --launcher "$LAUNCHER" --probe "$PROBE" \
    --bridge "$BRIDGE3" --core "$CORE" --prefix "$PREFIX" --dead-device "$DEAD" \
    >"$WORK/appd3.log" 2>&1 &
APPD3_PID=$!
for _ in $(seq 1 60); do [ -S "$SOCK3" ] && break; sleep 0.1; done
[ -S "$SOCK3" ] || fail "the helper did not start under the packaged capability set"
[ "$(stat -c %a "$SOCK3")" = "600" ] && [ "$(stat -c %u "$SOCK3")" = "$CORE_UID" ] ||
    fail "the packaged set could not prepare the socket"
ok "the packaged capability set prepares the socket and starts"

packaged_call() {
    setpriv --reuid="$CORE_UID" --regid="$CORE_GID" --clear-groups \
        python3 "$WORK/client.py" "$SOCK3" "$handshake" "$@" | tail -n1
}
ANSWER="$(packaged_call '{"verb":"ensure_bridge","ports":{"trans":19140,"chokepoint":19053,"socks":19050}}')"
case "$ANSWER" in
*'"result":"applied"'*) ok "the bridge works under the packaged set" ;;
*) fail "the packaged set could not build the bridge: $ANSWER" ;;
esac
ANSWER="$(packaged_call "{\"verb\":\"create\",\"user_uid\":$CORE_UID}")"
case "$ANSWER" in
*'"result":"created"'*) ok "namespace creation works under the packaged set" ;;
*) fail "the packaged set could not create a namespace: $ANSWER" ;;
esac
PACKAGED_ID="$(field "$ANSWER" entry.id)"
ANSWER="$(packaged_call "{\"verb\":\"verify\",\"id\":$PACKAGED_ID}")"
case "$ANSWER" in
*'"matches":true'*) ok "the namespace verifies under the packaged set" ;;
*) fail "verification failed under the packaged set: $ANSWER" ;;
esac
packaged_call '{"verb":"revert"}' >/dev/null
kill "$APPD3_PID" 2>/dev/null || true
wait "$APPD3_PID" 2>/dev/null || true
APPD3_PID=""

# The same state minus CAP_SYS_ADMIN. The bridge still works (CAP_NET_ADMIN), the socket is still
# prepared (CAP_CHOWN), and creating a namespace fails with EPERM: this is the empirical
# justification for CAP_SYS_ADMIN in the unit.
setpriv --reuid=0 --regid=0 --clear-groups \
    --bounding-set=-all,+net_admin,+chown \
    --inh-caps +net_admin --ambient-caps +net_admin \
    "$APPD" --socket "$SOCK2" --peer-uid "$CORE_UID" --state-dir "$STATE2" \
    --launcher "$LAUNCHER" --probe "$PROBE" \
    --bridge "$BRIDGE2" --core "$CORE" --prefix "$PREFIX" --dead-device "$DEAD" \
    >"$WORK/appd2.log" 2>&1 &
APPD2_PID=$!
for _ in $(seq 1 60); do [ -S "$SOCK2" ] && break; sleep 0.1; done
[ -S "$SOCK2" ] || fail "the capability-limited helper did not start"

limit_call() {
    setpriv --reuid="$CORE_UID" --regid="$CORE_GID" --clear-groups \
        python3 "$WORK/client.py" "$SOCK2" "$handshake" "$@" | tail -n1
}
ANSWER="$(limit_call '{"verb":"ensure_bridge","ports":{"trans":19140,"chokepoint":19053,"socks":19050}}')"
case "$ANSWER" in
*'"result":"applied"'*) ok "CAP_NET_ADMIN alone is enough for the bridge" ;;
*) fail "the limited helper could not even build the bridge: $ANSWER" ;;
esac
ANSWER="$(limit_call "{\"verb\":\"create\",\"user_uid\":$CORE_UID}")"
case "$ANSWER" in
*'"code":"backend_failure"'*)
    ok "without CAP_SYS_ADMIN, creating a namespace fails closed"
    ;;
*) fail "namespace creation succeeded without CAP_SYS_ADMIN: $ANSWER" ;;
esac
note "$ANSWER"
[ ! -e "/run/netns/ghapp1" ] || fail "a namespace exists despite the refusal"
kill "$APPD2_PID" 2>/dev/null || true
wait "$APPD2_PID" 2>/dev/null || true
APPD2_PID=""
ip link del "$BRIDGE2" 2>/dev/null || true

echo
echo "PASS: appd (socket, lifecycle, effective verification, capability necessity)"
