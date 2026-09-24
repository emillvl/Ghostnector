#!/usr/bin/env bash
#
# Proves, in throwaway network namespaces, that a rendered policy does what it claims.
#
# This is the review's leak-testing principle (§14.1) in miniature: assertions are made on what the
# *far side* observed — new connections accepted by a fake internet — not on what an application
# reports, and not on raw byte counts (TCP teardown from an earlier probe can land inside a byte
# measurement window and look like a leak).
#
#   scripts/policy-netns-test.sh <policy.nft> [uid:expect]...
#
#   uid     identity to run the probe as (0 = root)
#   expect  block | allow
#
# Checks:
#   1. with no policy, the fake internet is reachable            (the harness itself works)
#   2. the policy is accepted by the kernel                      (nftables parses it)
#   3. per probe: the verdict matches, the fake internet accepted the expected number of new
#      connections, and a blocked identity put zero bytes on the wire
#   4. reverting removes only Ghostnector's table, and restores reachability
#
# The fake internet is deliberately in TEST-NET-3 (203.0.113.0/24): a private address would be
# legitimately reachable when the LAN exception is enabled, which would make a "blocked" assertion
# meaningless.
#
# Requires: root, iproute2, nftables, curl, setpriv (util-linux), python3.

set -euo pipefail

POLICY="${1:?usage: policy-netns-test.sh <policy.nft> [uid:expect]...}"
shift

NS_ISP="gh-isp"
NS_APP="gh-app"
VETH_ISP="veth-gh-isp"
VETH_APP="veth-gh-app"
ISP_ADDR="203.0.113.1"
APP_ADDR="203.0.113.2"
PORT="8080"
SETTLE="0.5"
CONN_LOG="/tmp/gh-isp-connections.log"
SRV_PID=""

cleanup() {
    if [ -n "$SRV_PID" ]; then kill "$SRV_PID" 2>/dev/null || true; fi
    ip netns del "$NS_ISP" 2>/dev/null || true
    ip netns del "$NS_APP" 2>/dev/null || true
    rm -f "$CONN_LOG"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup
ip netns add "$NS_ISP"
ip netns add "$NS_APP"
ip link add "$VETH_ISP" type veth peer name "$VETH_APP"
ip link set "$VETH_ISP" netns "$NS_ISP"
ip link set "$VETH_APP" netns "$NS_APP"

ip -n "$NS_ISP" addr add "$ISP_ADDR/24" dev "$VETH_ISP"
ip -n "$NS_APP" addr add "$APP_ADDR/24" dev "$VETH_APP"
ip -n "$NS_ISP" link set "$VETH_ISP" up
ip -n "$NS_APP" link set "$VETH_APP" up
ip -n "$NS_ISP" link set lo up
ip -n "$NS_APP" link set lo up
ip -n "$NS_APP" route add default via "$ISP_ADDR"

# Count, at the boundary, packets arriving for the destination under test. Interface byte counters
# are not good enough: IPv6 link-local and multicast control traffic from the veth lands in the same
# window and looks exactly like a leak.
ip netns exec "$NS_ISP" nft add table inet ghcount
ip netns exec "$NS_ISP" nft add chain inet ghcount input \
    '{ type filter hook input priority -10; policy accept; }'
ip netns exec "$NS_ISP" nft add rule inet ghcount input \
    ip daddr "$ISP_ADDR" counter comment '"probe destination"'

# The fake internet: answers 200 to anything and records every connection it accepts.
ip netns exec "$NS_ISP" python3 - "$ISP_ADDR" "$PORT" "$CONN_LOG" <<'PY' &
import socket, sys, threading

addr, port, log_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((addr, port))
srv.listen(16)
log = open(log_path, "a", buffering=1)


def handle(conn):
    try:
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok")
    except OSError:
        pass
    finally:
        conn.close()


while True:
    conn, _ = srv.accept()
    log.write("accepted\n")
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY
SRV_PID=$!
sleep 0.7

rx_bytes() { ip netns exec "$NS_ISP" cat "/sys/class/net/$VETH_ISP/statistics/rx_bytes"; }
connections() { if [ -f "$CONN_LOG" ]; then wc -l < "$CONN_LOG"; else echo 0; fi; }

# Packets that arrived at the fake internet destined for the service under test.
probe_packets() {
    local json
    json="$(ip netns exec "$NS_ISP" nft -j list chain inet ghcount input)"
    printf '%s' "$json" | python3 -c '
import json, sys

total = 0
for item in json.load(sys.stdin).get("nftables", []):
    rule = item.get("rule")
    if not rule or rule.get("comment") != "probe destination":
        continue
    for expr in rule.get("expr", []):
        counter = expr.get("counter")
        if counter:
            total += counter.get("packets", 0)
print(total)
'
}

probe_as() {
    local uid="$1" out
    if [ "$uid" = "0" ]; then
        if out=$(ip netns exec "$NS_APP" curl -q -s --noproxy '*' --max-time 3 -o /dev/null \
            -w '%{http_code}' "http://$ISP_ADDR:$PORT/"); then
            echo "$out"
        else
            # curl prints 000 for a failed request, so the exit status is the authority.
            echo blocked
        fi
    else
        if out=$(ip netns exec "$NS_APP" setpriv --reuid="$uid" --regid="$uid" --clear-groups \
            curl -q -s --noproxy '*' --max-time 3 -o /dev/null -w '%{http_code}' \
            "http://$ISP_ADDR:$PORT/"); then
            echo "$out"
        else
            echo blocked
        fi
    fi
}

check_probe() {
    local spec="$1" uid expect before_bytes after_bytes before_conns after_conns
    local before_pkts after_pkts got delta_bytes delta_conns delta_pkts
    uid="${spec%%:*}"
    expect="${spec##*:}"

    # Let anything still in flight from the previous probe land in the "before" measurement.
    sleep "$SETTLE"
    before_bytes="$(rx_bytes)"
    before_conns="$(connections)"
    before_pkts="$(probe_packets)"

    got="$(probe_as "$uid")"

    after_bytes="$(rx_bytes)"
    after_conns="$(connections)"
    after_pkts="$(probe_packets)"
    delta_bytes=$((after_bytes - before_bytes))
    delta_conns=$((after_conns - before_conns))
    delta_pkts=$((after_pkts - before_pkts))
    echo "    uid=$uid expect=$expect got=$got arrival_packets=$delta_pkts new_connections=$delta_conns iface_bytes=$delta_bytes"

    case "$expect" in
    block)
        [ "$got" = "blocked" ] || fail "uid $uid reached the fake internet ($got)"
        [ "$delta_conns" = "0" ] || fail "uid $uid opened $delta_conns connection(s) to the fake internet"
        [ "$delta_pkts" = "0" ] || fail "uid $uid delivered $delta_pkts packet(s) to the destination"
        ;;
    allow)
        [ "$got" = "200" ] || fail "uid $uid was expected to reach the fake internet ($got)"
        [ "$delta_conns" -ge 1 ] || fail "uid $uid was allowed but the fake internet saw no connection"
        [ "$delta_pkts" -ge 1 ] || fail "uid $uid was allowed but no packet arrived"
        ;;
    *)
        fail "unknown expectation '$expect'"
        ;;
    esac
}

echo "[1] baseline: no policy applied, root must reach the fake internet"
[ "$(probe_as 0)" = "200" ] || fail "the harness cannot reach its own fake internet"

echo "[2] applying policy: $(basename "$POLICY")"
ip netns exec "$NS_APP" nft -f "$POLICY" || fail "the kernel rejected the policy"

# Start counting from a clean slate, after the baseline connection has settled.
#
# Truncate rather than delete: the fake internet holds an open file descriptor to this path, and
# unlinking it would send every subsequent write to an unreachable inode.
sleep "$SETTLE"
: > "$CONN_LOG"

echo "[3] per-identity probes, measured at the boundary"
if [ "$#" -eq 0 ]; then
    check_probe "0:block"
else
    for spec in "$@"; do check_probe "$spec"; done
fi

echo "[4] tables Ghostnector owns"
ip netns exec "$NS_APP" nft list tables

echo "[5] reverting"
ip netns exec "$NS_APP" nft destroy table inet ghostnector
[ "$(probe_as 0)" = "200" ] || fail "reverting did not restore the previous state"
remaining="$(ip netns exec "$NS_APP" nft list tables)"
[ -z "$remaining" ] || fail "revert left tables behind: $remaining"

echo "PASS: $(basename "$POLICY")"
