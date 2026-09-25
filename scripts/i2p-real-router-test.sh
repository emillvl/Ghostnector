#!/usr/bin/env bash
#
# The real-i2pd qualification run (M9.5).
#
#   scripts/i2p-real-router-test.sh <target/debug directory>
#
# This is not part of the hermetic gate: it needs the real `i2pd` package and, for the canary, the
# public I2P network. It proves what the fake router cannot:
#
#   * the real router starts, as the real `i2pd` uid, under the configuration the product's own
#     renderer produces, bootstraps to the public network, and stays stable;
#   * the real HTTP proxy carries the canary, and only that evidence may produce `Protected`;
#   * the policy resolves that real uid and exempts exactly it, with every other identity denied at
#     the far-side boundary (TCP, UDP, and DNS);
#   * the proxy is not exposed off-host;
#   * router death and policy tampering fail closed;
#   * Tor → I2P → Tor transitions never leave both exemptions in force, sampled from the kernel's own
#     table rather than from interface byte counters.
#
# In WSL this run stops at the bootstrap gate and is recorded as environment-inconclusive; the WSL
# record is preserved in the docs. On native Ubuntu it is expected to complete.
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
TOR_USER="debian-tor"
FAR_NS="gh-i2p-rfar"
VETH_ROOT="i2pr0"
VETH_FAR="i2pr1"
ROOT_ADDR="10.91.0.1"
FAR_ADDR="10.91.0.2"
BOUNDARY_ADDR="203.0.113.10"
TCP_PORT="8080"
UDP_PORT="8081"
DNS_PORT="53"
TOR_CONTROL_PORT="9051"
STABILITY_SECONDS="${STABILITY_SECONDS:-120}"
BOOTSTRAP_SECONDS="${BOOTSTRAP_SECONDS:-600}"
CANARY_SECONDS="${CANARY_SECONDS:-600}"
NETD_PID=""
CORE_PID=""
I2PD_PID=""
TOR_PID=""
FAR_PID=""
SITE_PID=""
SAMPLER_PID=""

PASSED=0
FAILED=0
INCONCLUSIVE=0

cleanup() {
    for pid in "$SAMPLER_PID" "$SITE_PID" "$I2PD_PID" "$TOR_PID" "$FAR_PID" "$CORE_PID" "$NETD_PID"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    # Keep the logs: a qualification run's failures are diagnosed from them, and the record should
    # outlive the run.
    mkdir -p /tmp/gh-i2p-real-logs
    for log in i2pd.log tor.log core.log netd.log far.log far-connections.log samples.log; do
        [ -f "$WORKDIR/$log" ] && cp "$WORKDIR/$log" "/tmp/gh-i2p-real-logs/$log" 2>/dev/null || true
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
    for log in "$WORKDIR/i2pd.log" "$WORKDIR/tor.log" "$WORKDIR/core.log" "$WORKDIR/netd.log"; do
        [ -f "$log" ] && { echo "--- $log (tail) ---"; tail -25 "$log"; }
    done
    exit 2
}

[ "$(id -u)" = "0" ] || fail_setup "this test needs root"
command -v i2pd >/dev/null 2>&1 || fail_setup "i2pd is not installed"
command -v tor >/dev/null 2>&1 || fail_setup "tor is not installed"
id -u i2pd >/dev/null 2>&1 || fail_setup "the i2pd user does not exist"
id -u "$TOR_USER" >/dev/null 2>&1 || fail_setup "the tor user ($TOR_USER) does not exist"
# The control-plane users the M8 suites use. On a fresh machine this test creates them itself, so the
# qualification is self-contained; the M8 suites then reuse the same identities.
if ! id -u "$CORE_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$CORE_USER"
fi
if ! id -u "$LAUNCH_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /bin/sh "$LAUNCH_USER"
fi

# Environment setup, not a product assertion: the packages enable their own daemons at install time,
# and those would hold the proxy/control ports and keep serving after our router is killed. The
# qualification runs its own router and its own Tor.
if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now i2pd >/dev/null 2>&1 || true
    systemctl disable --now tor >/dev/null 2>&1 || true
fi
sleep 1
pgrep -x i2pd >/dev/null 2>&1 && fail_setup "an i2pd process is already running"
pgrep -x tor >/dev/null 2>&1 && fail_setup "a tor process is already running"
I2PD_UID="$(id -u i2pd)"
I2PD_GID="$(id -g i2pd)"
TOR_UID="$(id -u "$TOR_USER")"
CORE_UID="$(id -u "$CORE_USER")"
CORE_GID="$(id -g "$CORE_USER")"
LAUNCH_UID="$(id -u "$LAUNCH_USER")"
LAUNCH_GID="$(id -g "$LAUNCH_USER")"

mkdir -p "$BINDIR" "$WORKDIR" "$RUNDIR" "$WORKDIR/data" "$WORKDIR/root/etc" "$WORKDIR/tor-data" "$WORKDIR/tor-cookie" "$WORKDIR/core"
printf 'nameserver 192.0.2.53\n' >"$WORKDIR/root/etc/resolv.conf"
for binary in ghostnector-netd ghostnector-core ghostnector ghostnector-dns; do
    install -m 0755 "$TARGET_DIR/$binary" "$BINDIR/$binary"
done
chown -R i2pd:i2pd "$WORKDIR/data"
chown -R "$TOR_USER":"$TOR_USER" "$WORKDIR/tor-data" "$WORKDIR/tor-cookie" 2>/dev/null || true
# Tor fixes its DataDirectory to 0700, so the control cookie lives in its own directory that the
# control plane can traverse; the cookie itself is handed to the control plane once Tor listens.
chmod 755 "$WORKDIR/tor-cookie"
# The control plane writes its journal and resolver state here, so it must own this directory.
chown -R "$CORE_UID" "$WORKDIR/core" "$WORKDIR/root"
COOKIE="$WORKDIR/control_auth_cookie"
head -c 32 /dev/urandom >"$COOKIE"
chown "$CORE_UID" "$COOKIE"
chmod 0755 "$RUNDIR"
chown "$CORE_UID" "$RUNDIR" 2>/dev/null || true
rm -f "$RUNDIR/core.sock" "$RUNDIR/netd.sock"

echo "── the product's renderer produces the router's configuration"
export CARGO_TARGET_DIR="$(dirname "$TARGET_DIR")"
export PATH="${GHOSTNECTOR_CARGO_BIN:-$HOME/.cargo/bin}:$PATH"
GHOSTNECTOR_EXPORT_I2PD_CONF="$WORKDIR/i2pd.conf" \
    GHOSTNECTOR_EXPORT_I2PD_DATA="$WORKDIR/data" \
    cargo test -q -p ghostnector-core \
    the_rendered_config_can_be_exported_for_the_qualification_run >/dev/null 2>&1 ||
    fail_setup "the rendered configuration could not be exported"
[ -f "$WORKDIR/i2pd.conf" ] || fail_setup "no configuration was exported"
grep -q "port = 4444" "$WORKDIR/i2pd.conf" || fail_setup "the exported configuration is not the product's"
if [ "${I2P_QUAL_TRANSPORT:-both}" = "ntcp2" ]; then
    # Qualification-only: i2pd 2.49.0 aborts under SSU2 traffic in this environment (heap corruption
    # after a minute or two), on WSL and on a native Ubuntu VM alike. NTCP2 is a full transport, so
    # the router still joins the network; the product configuration is otherwise unchanged.
    cat >>"$WORKDIR/i2pd.conf" <<'EOF'

[ssu2]
enabled = false
EOF
    note "qualification-only transport override: NTCP2 only"
fi
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

# ---------------------------------------------------------------- phase A: bootstrap and stability
echo "── phase A: the real router bootstraps to the public network and stays stable"
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
    fail_setup "the real HTTP proxy never came up"
ss -ltnp 2>/dev/null | grep ":4444 " | grep -q "pid=$I2PD_PID" ||
    fail_setup "the proxy port is not owned by our router (a packaged daemon may be running)"

B32=""
for _ in $(seq 1 60); do
    B32="$(ls "$WORKDIR/data/destinations/" 2>/dev/null | head -1 | cut -d. -f1)"
    [ -n "$B32" ] && break
    sleep 1
done
[ -n "$B32" ] && ok "the canary destination exists ($B32.b32.i2p)" ||
    fail_setup "the canary destination was never created"
CANARY_HOST="$B32.b32.i2p"

# The bootstrap gate: the router must reach the network and hold. Without this the rest of the run
# would be testing a local process, not a router.
BOOTSTRAPPED=""
for _ in $(seq 1 "$BOOTSTRAP_SECONDS"); do
    if ! kill -0 "$I2PD_PID" 2>/dev/null; then break; fi
    if grep -qiE 'reseed.*(downloaded|success)|floodfill|inbound tunnel .* created' "$WORKDIR/i2pd.log"; then
        BOOTSTRAPPED=1
        break
    fi
    sleep 1
done
if [ -n "$BOOTSTRAPPED" ]; then
    ok "the router bootstrapped to the public I2P network"
else
    fail_setup "the router never showed bootstrap progress (see the log); the run cannot continue"
fi
STABLE=""
for _ in $(seq 1 "$STABILITY_SECONDS"); do
    if ! kill -0 "$I2PD_PID" 2>/dev/null; then break; fi
    sleep 1
done
if kill -0 "$I2PD_PID" 2>/dev/null; then
    ok "the router stayed alive and stable for ${STABILITY_SECONDS}s after bootstrap"
else
    fail_setup "the router died during the stability window; the run cannot continue"
fi
note "network-integration lines so far: $(grep -icE 'reseed.*(downloaded|success)|floodfill|inbound tunnel .* created' "$WORKDIR/i2pd.log")"

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
for spec in "tcp dport $TCP_PORT" "udp dport $UDP_PORT" "udp dport $DNS_PORT"; do
    ip netns exec "$FAR_NS" nft add rule inet ghcount input \
        ip daddr "$BOUNDARY_ADDR" $spec counter comment "\"$spec\""
done
: >"$WORKDIR/far-connections.log"
cat >"$WORKDIR/far.py" <<'PY'
import socket, sys, threading

log = open(sys.argv[1], "a", buffering=1)

def tcp_server():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("203.0.113.10", 8080))
    srv.listen(16)
    while True:
        conn, peer = srv.accept()
        log.write(f"tcp accepted from {peer[0]}\n")
        threading.Thread(target=lambda c=conn: (c.close(),), daemon=True).start()

def udp_server(port, label):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("203.0.113.10", port))
    while True:
        data, peer = srv.recvfrom(4096)
        log.write(f"{label} from {peer[0]}\n")
        if label == "udp":
            srv.sendto(b"udp-answer", peer)

threading.Thread(target=tcp_server, daemon=True).start()
threading.Thread(target=udp_server, args=(8081, "udp"), daemon=True).start()
threading.Thread(target=udp_server, args=(53, "dns"), daemon=True).start()
while True:
    threading.Event().wait(3600)
PY
ip netns exec "$FAR_NS" python3 "$WORKDIR/far.py" "$WORKDIR/far-connections.log" \
    >"$WORKDIR/far.log" 2>&1 &
FAR_PID=$!
sleep 0.3

boundary_packets() { # boundary_packets <comment>
    ip netns exec "$FAR_NS" nft -j list chain inet ghcount input | python3 -c '
import json, sys
want = sys.argv[1]
total = 0
for item in json.load(sys.stdin).get("nftables", []):
    rule = item.get("rule")
    if rule and rule.get("comment") == want:
        for expr in rule.get("expr", []):
            counter = expr.get("counter")
            if counter: total += counter.get("packets", 0)
print(total)' "$1"
}

# ---------------------------------------------------------------- the stack
"$BINDIR/ghostnector-netd" --socket "$RUNDIR/netd.sock" --peer-uid "$CORE_UID" \
    --i2p-user i2pd --tor-user "$TOR_USER" \
    --fallback-path "$WORKDIR/fail-closed.nft" >"$WORKDIR/netd.log" 2>&1 &
NETD_PID=$!
for _ in $(seq 1 60); do [ -S "$RUNDIR/netd.sock" ] && break; sleep 0.1; done
[ -S "$RUNDIR/netd.sock" ] || fail_setup "the firewall helper did not start"

# Real Tor, for the transition phase: the product's external-services shape.
cat >"$WORKDIR/torrc" <<EOF
ClientOnly 1
SocksPort 0
ControlPort 127.0.0.1:$TOR_CONTROL_PORT
CookieAuthentication 1
CookieAuthFile $WORKDIR/tor-cookie/control.cookie
CookieAuthFileGroupReadable 1
DataDirectory $WORKDIR/tor-data
Log notice stdout
SafeLogging 1
EOF
chmod 644 "$WORKDIR/torrc"
setpriv --reuid="$TOR_UID" --regid="$TOR_UID" --clear-groups \
    /usr/bin/tor -f "$WORKDIR/torrc" >"$WORKDIR/tor.log" 2>&1 &
TOR_PID=$!
# Wait for Tor's control port, then take the cookie: Tor writes it before it listens, and taking it
# earlier races Tor's own write and leaves it unreadable by the control plane.
for _ in $(seq 1 120); do
    ss -ltn 2>/dev/null | grep -q "127.0.0.1:$TOR_CONTROL_PORT " && break
    sleep 0.5
done
ss -ltn 2>/dev/null | grep -q "127.0.0.1:$TOR_CONTROL_PORT " ||
    fail_setup "Tor never opened its control port"
chown "$CORE_UID:$CORE_GID" "$WORKDIR/tor-cookie/control.cookie"
chmod 600 "$WORKDIR/tor-cookie/control.cookie"
setpriv --reuid="$CORE_UID" --regid="$CORE_GID" --clear-groups \
    cat "$WORKDIR/tor-cookie/control.cookie" >/dev/null 2>&1 ||
    fail_setup "the control plane cannot read Tor's cookie"

setpriv --reuid="$CORE_UID" --regid="$CORE_GID" --clear-groups \
    --inh-caps +net_bind_service --ambient-caps +net_bind_service \
    "$BINDIR/ghostnector-core" \
    --socket "$RUNDIR/core.sock" --helper "$RUNDIR/netd.sock" \
    --journal "$WORKDIR/core/intent.json" --resolver-state "$WORKDIR/core/resolver.json" \
    --resolv-conf-root "$WORKDIR/root" \
    --services external --tor-cookie "$WORKDIR/tor-cookie/control.cookie" \
    --tor-control-port "$TOR_CONTROL_PORT" --tor-bootstrap-seconds 120 \
    --dns-helper "$BINDIR/ghostnector-dns" \
    --i2p-ready-seconds 20 \
    --i2p-canary "$CANARY_HOST" --i2p-canary-path / --i2p-canary-expect i2p-ok \
    --i2p-clearnet-check "$BOUNDARY_ADDR:$TCP_PORT" \
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
wait_for() {
    for _ in $(seq 1 "$2"); do
        if status | grep -q "$1"; then return 0; fi
        sleep 1
    done
    return 1
}
reach_as() { # reach_as <uid> <gid> -> connected | blocked
    setpriv --reuid="$1" --regid="$2" --clear-groups \
        python3 - "$BOUNDARY_ADDR" "$TCP_PORT" <<'PY'
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
udp_as() { # udp_as <uid> <gid> <port> -> answered | refused
    setpriv --reuid="$1" --regid="$2" --clear-groups \
        python3 - "$BOUNDARY_ADDR" "$3" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(b"probe", (sys.argv[1], int(sys.argv[2])))
    s.recvfrom(64)
    print("answered")
except OSError:
    print("refused")
PY
}
dns_as() { # dns_as <uid> <gid> -> answered | refused
    setpriv --reuid="$1" --regid="$2" --clear-groups \
        python3 - "$BOUNDARY_ADDR" <<'PY'
import socket, sys
query = bytes([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
query += b"\x06canary\x04test\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(query, (sys.argv[1], 53))
    s.recvfrom(1024)
    print("answered")
except OSError:
    print("refused")
PY
}
skuid_set() { nft list table inet ghostnector 2>/dev/null | grep -oE 'skuid [0-9]+' | awk '{print $2}' | sort -u | tr '\n' ' '; }

# ---------------------------------------------------------------- phase B: the product path
echo "── phase B: the product path with the real router"
if cli connect --network i2p >/dev/null 2>&1; then
    ok "connect --network i2p succeeded with the real router"
else
    bad "connect --network i2p failed with the real router: $(cli connect --network i2p 2>&1)"
fi
TABLE="$(nft list table inet ghostnector 2>/dev/null)"
case "$TABLE" in
*"skuid $I2PD_UID"*) ok "the kernel policy exempts the real i2pd uid ($I2PD_UID)" ;;
*) bad "the kernel policy does not exempt the real i2pd uid" ;;
esac
case "$TABLE" in
*"out_nat"*) bad "the I2P policy has a NAT chain" ;;
*) ok "the I2P policy has no NAT chain" ;;
esac
case "$(skuid_set)" in
"$I2PD_UID "*) ok "the only exempted uid is the router's" ;;
*) bad "unexpected exemptions: $(skuid_set)" ;;
esac

[ "$(reach_as "$I2PD_UID" "$I2PD_GID")" = "connected" ] &&
    ok "the real router's own egress is carried" ||
    bad "the real router's own egress was blocked"
# The router's probe above is expected at the boundary; measure the ordinary identity from here so
# its delta is not polluted by the router's packets.
BEFORE_TCP="$(boundary_packets "tcp dport $TCP_PORT")"
BEFORE_UDP="$(boundary_packets "udp dport $UDP_PORT")"
BEFORE_DNS="$(boundary_packets "udp dport $DNS_PORT")"
TCP_ORDINARY="$(reach_as "$LAUNCH_UID" "$LAUNCH_GID")"
UDP_ORDINARY="$(udp_as "$LAUNCH_UID" "$LAUNCH_GID" "$UDP_PORT")"
DNS_ORDINARY="$(dns_as "$LAUNCH_UID" "$LAUNCH_GID")"
AFTER_TCP="$(boundary_packets "tcp dport $TCP_PORT")"
AFTER_UDP="$(boundary_packets "udp dport $UDP_PORT")"
AFTER_DNS="$(boundary_packets "udp dport $DNS_PORT")"
note "ordinary: tcp=$TCP_ORDINARY udp=$UDP_ORDINARY dns=$DNS_ORDINARY; boundary tcp=$((AFTER_TCP-BEFORE_TCP)) udp=$((AFTER_UDP-BEFORE_UDP)) dns=$((AFTER_DNS-BEFORE_DNS))"
[ "$TCP_ORDINARY" = "blocked" ] && [ "$((AFTER_TCP-BEFORE_TCP))" = "0" ] &&
    ok "ordinary clearnet TCP is denied and nothing reached the far side" ||
    bad "ordinary clearnet TCP was carried"
[ "$UDP_ORDINARY" = "refused" ] && [ "$((AFTER_UDP-BEFORE_UDP))" = "0" ] &&
    ok "ordinary UDP is refused and nothing reached the far side" ||
    bad "ordinary UDP was carried"
[ "$DNS_ORDINARY" = "refused" ] && [ "$((AFTER_DNS-BEFORE_DNS))" = "0" ] &&
    ok "clearnet DNS is denied and nothing reached the far side" ||
    bad "clearnet DNS was carried"

if ip netns exec "$FAR_NS" timeout 3 bash -c "echo > /dev/tcp/$ROOT_ADDR/4444" 2>/dev/null; then
    bad "the HTTP proxy accepted a connection from the far side"
else
    ok "the HTTP proxy is closed to the network (the input guard holds)"
fi

echo "── the canary through the real proxy is required for Protected"
if wait_for "protected — and verified" "$CANARY_SECONDS"; then
    ok "the real canary through the real proxy turned the state into protected-and-verified"
else
    bad "the state never became verified with the real canary: $(status)"
fi

# ---------------------------------------------------------------- phase C: death and tampering
echo "── phase C: router death and policy tampering fail closed"
kill "$I2PD_PID" 2>/dev/null || true
sleep 2
note "listeners on 4444 after the kill: $(ss -ltn 2>/dev/null | grep -c ':4444 ')"
note "state right after the kill: $(status | sed -n '1,2p' | tr '\n' ' ')"
if wait_for "no traffic can leave" 90; then
    ok "the router's death was noticed and the machine denied"
else
    note "last state: $(status)"
    bad "I2P kept claiming protection with its router dead"
fi
case "$(skuid_set)" in
*"$I2PD_UID"*) bad "the router's exemption survived its death" ;;
*) ok "the fail-closed baseline replaced the policy" ;;
esac

# Restart the router and reach Protected again, then tamper.
setpriv --reuid="$I2PD_UID" --regid="$I2PD_GID" --clear-groups \
    /usr/bin/i2pd --conf="$WORKDIR/i2pd.conf" --tunconf="$WORKDIR/tunnels.conf" \
    --datadir="$WORKDIR/data" --certsdir=/usr/share/i2pd/certificates --loglevel info \
    >>"$WORKDIR/i2pd.log" 2>&1 &
I2PD_PID=$!
cli disconnect >/dev/null 2>&1
cli connect --network i2p >/dev/null 2>&1
if wait_for "protected — and verified" "$CANARY_SECONDS"; then
    ok "the restarted router reached protected-and-verified again"
else
    bad "the restarted router did not reach a verified state: $(status)"
fi
nft insert rule inet ghostnector out_filter meta l4proto tcp counter accept \
    comment '"hand edited during the qualification"' 2>/dev/null
if wait_for "no traffic can leave" 60; then
    ok "the injected accept was noticed and the machine denied"
else
    bad "an injected accept survived while I2P claimed protection: $(status)"
fi
nft list table inet ghostnector 2>/dev/null | grep -q "hand edited" &&
    bad "the tampered policy survived the alarm" ||
    ok "the fail-closed baseline replaced the tampered policy"

# ---------------------------------------------------------------- phase D: Tor -> I2P -> Tor
echo "── phase D: Tor → I2P → Tor, sampling the kernel's exemption set throughout"
cli disconnect >/dev/null 2>&1
: >"$WORKDIR/samples.log"
cat >"$WORKDIR/sampler.sh" <<'SAMPLER'
#!/bin/bash
while true; do
    table="$(nft list table inet ghostnector 2>/dev/null)"
    uids="$(printf '%s\n' "$table" | grep -oE 'skuid [0-9]+' | awk '{print $2}' | sort -u | tr '\n' ',')"
    nat="no"
    printf '%s\n' "$table" | grep -q out_nat && nat="yes"
    echo "$(date +%s.%N) uids=${uids:-none} nat=$nat" >>"$1"
    sleep 0.3
done
SAMPLER
chmod +x "$WORKDIR/sampler.sh"
"$WORKDIR/sampler.sh" "$WORKDIR/samples.log" &
SAMPLER_PID=$!
sleep 1

TOR_OK=""
if cli connect >/dev/null 2>&1; then
    if wait_for "through Tor" 180; then TOR_OK=1; fi
fi
if [ -n "$TOR_OK" ]; then
    ok "Tor system protection came up (state: $(status | head -1))"
else
    bad "Tor system protection did not come up: $(status)"
fi
sleep 3
TOR_STAGE_UIDS="$(skuid_set)"
case "$TOR_STAGE_UIDS" in
*"$TOR_UID"*) ok "the Tor uid is exempt under Tor protection" ;;
*) bad "the Tor uid is not exempt under Tor protection: $TOR_STAGE_UIDS" ;;
esac
case "$TOR_STAGE_UIDS" in
*"$I2PD_UID"*) bad "the I2P uid is exempt under Tor protection" ;;
*) ok "the I2P uid is not exempt under Tor protection" ;;
esac

cli connect --network i2p >/dev/null 2>&1
sleep 3
I2P_STAGE_UIDS="$(skuid_set)"
case "$I2P_STAGE_UIDS" in
*"$I2PD_UID"*) ok "the I2P uid is exempt under I2P protection" ;;
*) bad "the I2P uid is not exempt under I2P protection: $I2P_STAGE_UIDS" ;;
esac
case "$I2P_STAGE_UIDS" in
*"$TOR_UID"*) bad "the Tor uid is exempt under I2P protection" ;;
*) ok "the Tor uid is not exempt under I2P protection" ;;
esac

cli connect >/dev/null 2>&1
sleep 3
BACK_UIDS="$(skuid_set)"
case "$BACK_UIDS" in
*"$TOR_UID"*) ok "the Tor uid is exempt again after returning to Tor" ;;
*) bad "the Tor uid is not exempt after returning: $BACK_UIDS" ;;
esac
case "$BACK_UIDS" in
*"$I2PD_UID"*) bad "the I2P uid is exempt after returning to Tor" ;;
*) ok "the I2P uid is not exempt after returning to Tor" ;;
esac
sleep 2
kill "$SAMPLER_PID" 2>/dev/null || true
SAMPLER_PID=""

BOTH=0
NONE_BEFORE_CONNECT=0
while read -r line; do
    uids="${line#*uids=}"; uids="${uids%% *}"
    has_tor=0; has_i2p=0
    case ",$uids," in *",$TOR_UID,"*) has_tor=1 ;; esac
    case ",$uids," in *",$I2PD_UID,"*) has_i2p=1 ;; esac
    [ "$has_tor" = "1" ] && [ "$has_i2p" = "1" ] && BOTH=$((BOTH + 1))
done <"$WORKDIR/samples.log"
SAMPLES="$(wc -l <"$WORKDIR/samples.log")"
note "samples: $SAMPLES; samples with both exemptions: $BOTH"
[ "$SAMPLES" -gt 10 ] || inc "too few samples to say anything about the transitions"
[ "$BOTH" = "0" ] && [ "$SAMPLES" -gt 10 ] &&
    ok "no sample ever showed both exemptions in force" ||
    { [ "$BOTH" != "0" ] && bad "$BOTH sample(s) showed both exemptions in force"; }

cli disconnect >/dev/null 2>&1
echo
echo "=== summary (real i2pd) ==="
echo "held:         $PASSED"
echo "contradicted: $FAILED"
echo "inconclusive: $INCONCLUSIVE"
[ "$FAILED" = "0" ] || exit 1
exit 0
