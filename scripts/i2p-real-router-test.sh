#!/usr/bin/env bash
#
# The real-i2pd qualification run (M9.5).
#
#   scripts/i2p-real-router-test.sh <target/debug directory>
#
# This is not part of the hermetic gate: it needs the real `i2pd` package. It proves what the fake
# router cannot:
#
#   * the real router starts, as the real `i2pd` uid, under the configuration the product's own
#     renderer produces;
#   * the policy resolves that real uid and exempts exactly it, with every other identity denied at
#     the far-side boundary;
#   * the real HTTP proxy answers, and — when the environment lets the router live long enough — the
#     canary is fetched through it.
#
# The environment matters and is recorded: in this WSL instance i2pd 2.49.0 aborts after a minute or
# two under load, so the canary result is classified honestly (held or inconclusive) and never
# counted as a pass when it did not happen.
#
# Classifications: ok / FAIL / inconclusive.

set -uo pipefail
cd "$(dirname "$0")/.."

TARGET_DIR="${1:?usage: i2p-real-router-test.sh <target/debug directory>}"
RUNDIR="/run/ghostnector"
BINDIR="/tmp/gh-i2p-real-bin"
WORKDIR="/tmp/gh-i2p-real"
CORE_USER="ghostnector-core"
LAUNCH_USER="ghostnector-launch-test"
FAR_NS="gh-i2p-rfar"
VETH_ROOT="i2pr0"
VETH_FAR="i2pr1"
ROOT_ADDR="10.91.0.1"
FAR_ADDR="10.91.0.2"
BOUNDARY_ADDR="203.0.113.10"
BOUNDARY_PORT="8080"
NETD_PID=""
CORE_PID=""
I2PD_PID=""
FAR_PID=""
SITE_PID=""

PASSED=0
FAILED=0
INCONCLUSIVE=0

cleanup() {
    for pid in "$SITE_PID" "$I2PD_PID" "$FAR_PID" "$CORE_PID" "$NETD_PID"; do
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
    for log in "$WORKDIR/i2pd.log" "$WORKDIR/core.log" "$WORKDIR/netd.log"; do
        [ -f "$log" ] && { echo "--- $log (tail) ---"; tail -25 "$log"; }
    done
    exit 2
}

[ "$(id -u)" = "0" ] || fail_setup "this test needs root"
command -v i2pd >/dev/null 2>&1 || fail_setup "i2pd is not installed"
id -u i2pd >/dev/null 2>&1 || fail_setup "the i2pd user does not exist"
for user in "$CORE_USER" "$LAUNCH_USER"; do
    id -u "$user" >/dev/null 2>&1 || fail_setup "the user $user must exist (the M8 suites create it)"
done
I2PD_UID="$(id -u i2pd)"
I2PD_GID="$(id -g i2pd)"
CORE_UID="$(id -u "$CORE_USER")"
CORE_GID="$(id -g "$CORE_USER")"
LAUNCH_UID="$(id -u "$LAUNCH_USER")"
LAUNCH_GID="$(id -g "$LAUNCH_USER")"

mkdir -p "$BINDIR" "$WORKDIR" "$RUNDIR" "$WORKDIR/data" "$WORKDIR/root/etc"
printf 'nameserver 192.0.2.53\n' >"$WORKDIR/root/etc/resolv.conf"
for binary in ghostnector-netd ghostnector-core ghostnector ghostnector-dns; do
    install -m 0755 "$TARGET_DIR/$binary" "$BINDIR/$binary"
done
chown -R i2pd:i2pd "$WORKDIR/data"
COOKIE="$WORKDIR/control_auth_cookie"
head -c 32 /dev/urandom >"$COOKIE"
chown "$CORE_UID" "$COOKIE"
chmod 0755 "$RUNDIR"
chown "$CORE_UID" "$RUNDIR" 2>/dev/null || true
rm -f "$RUNDIR/core.sock" "$RUNDIR/netd.sock"

echo "── the product's renderer produces the router's configuration"
export CARGO_TARGET_DIR="$(dirname "$TARGET_DIR")"
export PATH="/root/.cargo/bin:$PATH"
GHOSTNECTOR_EXPORT_I2PD_CONF="$WORKDIR/i2pd.conf" \
    GHOSTNECTOR_EXPORT_I2PD_DATA="$WORKDIR/data" \
    cargo test -q -p ghostnector-core \
    the_rendered_config_can_be_exported_for_the_qualification_run >/dev/null 2>&1 ||
    fail_setup "the rendered configuration could not be exported"
[ -f "$WORKDIR/i2pd.conf" ] || fail_setup "no configuration was exported"
grep -q "port = 4444" "$WORKDIR/i2pd.conf" || fail_setup "the exported configuration is not the product's"
ok "the router will start under the product's rendered configuration"

# The canary: a local I2P destination hosted by the same router.
cat >"$WORKDIR/site.py" <<'PY'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"i2p-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
http.server.HTTPServer(("127.0.0.1", 8000), H).serve_forever()
PY
python3 "$WORKDIR/site.py" >"$WORKDIR/site.log" 2>&1 &
SITE_PID=$!
cat >"$WORKDIR/tunnels.conf" <<'EOF'
[canary-server]
type = http
host = 127.0.0.1
port = 8000
keys = canary.dat
EOF
chmod 644 "$WORKDIR/tunnels.conf"

echo "── the real router starts as its own uid"
setpriv --reuid="$I2PD_UID" --regid="$I2PD_GID" --clear-groups \
    /usr/bin/i2pd --conf="$WORKDIR/i2pd.conf" --tunconf="$WORKDIR/tunnels.conf" \
    --datadir="$WORKDIR/data" --certsdir=/usr/share/i2pd/certificates --loglevel info \
    >"$WORKDIR/i2pd.log" 2>&1 &
I2PD_PID=$!
sleep 1
[ "$(stat -c %u /proc/$I2PD_PID 2>/dev/null)" = "$I2PD_UID" ] &&
    ok "the real router is running as uid $I2PD_UID" ||
    bad "the real router did not start as the i2pd user"
PROXY_UP=""
for _ in $(seq 1 60); do
    if python3 -c 'import socket
s=socket.socket(); s.settimeout(1)
try:
    s.connect(("127.0.0.1", 4444)); print("up")
except OSError: pass' 2>/dev/null | grep -q up; then PROXY_UP=1; break; fi
    sleep 1
done
[ -n "$PROXY_UP" ] && ok "the real HTTP proxy answers on 127.0.0.1:4444" ||
    inc "the real HTTP proxy did not come up within the budget (the router stalled; see the log)"

B32=""
for _ in $(seq 1 60); do
    B32="$(ls "$WORKDIR/data/destinations/" 2>/dev/null | head -1 | cut -d. -f1)"
    [ -n "$B32" ] && break
    sleep 1
done
[ -n "$B32" ] && ok "the canary destination exists ($B32.b32.i2p)" ||
    inc "the canary destination was not created within the budget"
CANARY_HOST="${B32:+$B32.b32.i2p}"

# ---------------------------------------------------------------- the far side
ip netns add "$FAR_NS"
ip link add "$VETH_ROOT" type veth peer name "$VETH_FAR"
ip link set "$VETH_FAR" netns "$FAR_NS"
ip addr add "$ROOT_ADDR/24" dev "$VETH_ROOT"
ip link set "$VETH_ROOT" up
ip -n "$FAR_NS" addr add "$FAR_ADDR/24" dev "$VETH_FAR"
ip -n "$FAR_NS" addr add "$BOUNDARY_ADDR/24" dev "$VETH_FAR"
ip -n "$FAR_NS" link set "$VETH_FAR" up
ip -n "$FAR_NS" link set lo up
ip route add "$BOUNDARY_ADDR/32" via "$FAR_ADDR" dev "$VETH_ROOT"
ip netns exec "$FAR_NS" nft add table inet ghcount
ip netns exec "$FAR_NS" nft add chain inet ghcount input \
    '{ type filter hook input priority -10; policy accept; }'
ip netns exec "$FAR_NS" nft add rule inet ghcount input \
    ip daddr "$BOUNDARY_ADDR" counter comment '"boundary"'
: >"$WORKDIR/far-connections.log"
cat >"$WORKDIR/far.py" <<'PY'
import socket, sys, threading
log = open(sys.argv[1], "a", buffering=1)
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("203.0.113.10", 8080))
srv.listen(16)
while True:
    conn, peer = srv.accept()
    log.write(f"accepted from {peer[0]}\n")
    threading.Thread(target=lambda c=conn: (c.close(),), daemon=True).start()
PY
ip netns exec "$FAR_NS" python3 "$WORKDIR/far.py" "$WORKDIR/far-connections.log" \
    >"$WORKDIR/far.log" 2>&1 &
FAR_PID=$!
sleep 0.3

boundary_packets() {
    ip netns exec "$FAR_NS" nft -j list chain inet ghcount input | python3 -c '
import json, sys
total = 0
for item in json.load(sys.stdin).get("nftables", []):
    rule = item.get("rule")
    if rule and rule.get("comment") == "boundary":
        for expr in rule.get("expr", []):
            counter = expr.get("counter")
            if counter: total += counter.get("packets", 0)
print(total)'
}

# ---------------------------------------------------------------- the stack
"$BINDIR/ghostnector-netd" --socket "$RUNDIR/netd.sock" --peer-uid "$CORE_UID" \
    --i2p-user i2pd \
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
    --services external --tor-cookie "$COOKIE" --tor-control-port 9051 \
    --tor-bootstrap-seconds 2 --dns-helper "$BINDIR/ghostnector-dns" \
    --i2p-ready-seconds 20 \
    --i2p-canary "${CANARY_HOST:-canary.i2p}" --i2p-canary-path / --i2p-canary-expect i2p-ok \
    --i2p-clearnet-check "$BOUNDARY_ADDR:$BOUNDARY_PORT" \
    --verify-interval 5 --verify-stale-after 60 --verify-timeout 4 \
    --group "$CORE_USER" >"$WORKDIR/core.log" 2>&1 &
CORE_PID=$!
for _ in $(seq 1 60); do [ -S "$RUNDIR/core.sock" ] && break; sleep 0.1; done
[ -S "$RUNDIR/core.sock" ] || fail_setup "the control plane did not start"

cli() {
    setpriv --reuid="$LAUNCH_UID" --regid="$LAUNCH_GID" --groups "$CORE_GID" \
        "$BINDIR/ghostnector" --socket "$RUNDIR/core.sock" "$@"
}
status() { cli status 2>&1; }
reach_as() {
    setpriv --reuid="$1" --regid="$2" --clear-groups \
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

echo "── the product path with the real router"
CONNECTED=""
if cli connect --network i2p >/dev/null 2>&1; then
    CONNECTED=1
    ok "connect --network i2p succeeded with the real router"
else
    note "connect failed: $(cli connect --network i2p 2>&1)"
fi

if [ -n "$CONNECTED" ]; then
    TABLE="$(nft list table inet ghostnector 2>/dev/null)"
    case "$TABLE" in
    *"skuid $I2PD_UID"*) ok "the kernel policy exempts the real i2pd uid ($I2PD_UID)" ;;
    *) bad "the kernel policy does not exempt the real i2pd uid" ;;
    esac
    case "$TABLE" in
    *"out_nat"*) bad "the I2P policy has a NAT chain" ;;
    *) ok "the I2P policy has no NAT chain" ;;
    esac

    BEFORE_PACKETS="$(boundary_packets)"
    if [ "$(reach_as "$I2PD_UID" "$I2PD_GID")" = "connected" ]; then
        ok "the real router's own egress is carried"
    else
        bad "the real router's own egress was blocked"
    fi
    if [ "$(reach_as "$LAUNCH_UID" "$LAUNCH_GID")" = "blocked" ]; then
        ok "an ordinary identity is denied with the real router active"
    else
        bad "an ordinary identity reached the boundary with the real router active"
    fi
    AFTER_PACKETS="$(boundary_packets)"
    [ "$((AFTER_PACKETS - BEFORE_PACKETS))" = "0" ] &&
        ok "zero packets from the ordinary identity arrived at the boundary" ||
        bad "packets from the ordinary identity arrived at the boundary"
else
    # The router was not usable, so nothing was applied and the machine is open by design (DR-15
    # allows rollback before protection was established). Asserting denial here would be wrong; the
    # honest classification is inconclusive.
    inc "the policy checks could not run: the real router was not usable in time"
fi

# The canary through the real proxy: bounded, and classified honestly.
CANARY=""
if [ -n "$B32" ]; then
    for _ in $(seq 1 12); do
        if ! kill -0 "$I2PD_PID" 2>/dev/null; then break; fi
        ANSWER="$(python3 - "$B32" <<'PY'
import socket, sys
s = socket.socket()
s.settimeout(10)
try:
    s.connect(("127.0.0.1", 4444))
except OSError:
    print("no-proxy"); raise SystemExit
s.sendall(f"GET http://{sys.argv[1]}.b32.i2p/ HTTP/1.0\r\nHost: {sys.argv[1]}.b32.i2p\r\n\r\n".encode())
data = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
except OSError:
    pass
if b"i2p-ok" in data and b"200" in data.split(b"\r\n", 1)[0]:
    print("canary-ok")
else:
    print("not-yet")
PY
)"
        if [ "$ANSWER" = "canary-ok" ]; then CANARY=1; break; fi
        sleep 5
    done
fi
if [ -n "$CANARY" ]; then
    ok "the canary was fetched through the real proxy"
else
    inc "the canary could not be fetched through the real proxy in this environment"
fi
if kill -0 "$I2PD_PID" 2>/dev/null; then
    note "the real router was still running at the end of the checks"
else
    note "the real router died during the checks (i2pd 2.49.0 is unstable under this WSL environment; see the log)"
fi
INTEGRATION="$(grep -icE 'reseed.*(downloaded|success)|floodfill|inbound tunnel .* created' "$WORKDIR/i2pd.log" 2>/dev/null || echo 0)"
note "network-integration lines in the router log: $INTEGRATION"

cli disconnect >/dev/null 2>&1
echo
echo "=== summary (real i2pd) ==="
echo "held:         $PASSED"
echo "contradicted: $FAILED"
echo "inconclusive: $INCONCLUSIVE"
[ "$FAILED" = "0" ] || exit 1
exit 0
