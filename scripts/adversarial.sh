#!/usr/bin/env bash
#
# Adversarial exposure: try to make `Protected` false while Ghostnector still believes it is true.
#
#   scripts/adversarial.sh <target/debug directory>
#
# Each case states what it observed, in one of three classifications:
#
#   ok            the claim held, observed from outside the component under test
#   FAIL          a claim was contradicted — this is a finding
#   inconclusive  the observation cannot establish either way, and is never counted as a pass
#
# A case that demonstrates a *known* gap on purpose prints `demonstrated` and records the gap rather
# than pretending to pass.

set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/lib/gh-harness.sh

TARGET="${1:?usage: adversarial.sh <target/debug directory>}"
TARGET="$(cd "$TARGET" && pwd)"
H_TARGET="$TARGET"

PASSED=0
FAILED=0
INCONCLUSIVE=0
DEMONSTRATED=0
declare -a FINDINGS=()

# ---------------------------------------------------------------- helpers

watch_from_machine() { gh_from_machine; }

tcp_dns_probe() {
    # A DNS query over TCP, which is what a client does when an answer will not fit in a datagram.
    gh_probe python3 -c '
import socket, struct, sys
query = bytes([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
query += b"\x06canary\x04test\x00\x00\x01\x00\x01"
conn = socket.socket(); conn.settimeout(3)
conn.connect((sys.argv[1], int(sys.argv[2])))
conn.sendall(struct.pack("!H", len(query)) + query)
header = conn.recv(2)
length = struct.unpack("!H", header)[0]
answer = conn.recv(length)
sys.stdout.write(".".join(str(b) for b in answer[-4:]))
' "${1}" "${2}" 2>&1 || true
}

run_case() {
    local name="$1" description="$2" verdict=0
    echo "── $name: $description"
    "$name" || verdict=$?
    case "$verdict" in
    0) PASSED=$((PASSED + 1)) ;;
    1) FAILED=$((FAILED + 1)) ;;
    3) DEMONSTRATED=$((DEMONSTRATED + 1)) ;;
    *) INCONCLUSIVE=$((INCONCLUSIVE + 1)) ;;
    esac
    gh_teardown >/dev/null 2>&1 || true
    echo
}

bring_up() {
    gh_setup "${1:-yes}"
    gh_start_tor
    gh_start_dns_upstream
    gh_start_stack || return 1
    gh_connect >/dev/null
}

# ---------------------------------------------------------------- steady state

case_AS1() {
    bring_up || return 2
    local before_tcp before_machine after_tcp after_machine
    before_tcp="$(gh_events tcp)"
    before_machine="$(gh_from_machine)"
    local answer
    answer="$(gh_tcp_probe)"
    sleep 0.5
    after_tcp="$(gh_events tcp)"
    after_machine="$(gh_from_machine)"
    gh_note "probe said '${answer:-<nothing>}'"
    gh_note "outside saw $((after_tcp - before_tcp)) connection(s); packets from the machine: $((after_machine - before_machine))"
    if [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "a packet from the machine's own address reached the outside world"
        return 1
    fi
    if [ "$((after_tcp - before_tcp))" != "1" ]; then
        gh_inc "the destination was not reached exactly once, so the positive half is not established"
        return 2
    fi
    gh_ok "reached exactly once, through the conduit, with nothing crossing from the machine"
}

case_AS2() {
    bring_up || return 2
    local before_udp before_machine answer
    before_udp="$(gh_events udp)"
    before_machine="$(gh_from_machine)"
    answer="$(gh_udp_probe)"
    sleep 0.5
    gh_note "probe said '${answer:-<nothing>}'"
    local after_udp after_machine
    after_udp="$(gh_events udp)"
    after_machine="$(gh_from_machine)"
    gh_note "outside saw $((after_udp - before_udp)) datagram(s); packets from the machine: $((after_machine - before_machine))"
    if [ "$((after_udp - before_udp))" != "0" ] || [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "UDP left the machine"
        return 1
    fi
    gh_ok "no datagram arrived, and nothing crossed from the machine"
}

case_AS3() {
    bring_up yes || return 2
    local before_machine before_probe answer
    before_machine="$(gh_from_machine)"
    answer="$(gh_ipv6_probe)"
    sleep 0.5
    local after_machine
    after_machine="$(gh_from_machine)"
    gh_note "IPv6 probe said '${answer:-<nothing>}'"
    gh_note "IPv6 packets from the machine: $((after_machine - before_machine))"
    if [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "an IPv6 packet from the machine reached the outside world"
        return 1
    fi
    gh_ok "no IPv6 left the machine"
}

case_AS4() {
    bring_up no || return 2
    local answer
    answer="$(gh_ipv6_probe)"
    gh_note "IPv6 probe on a link with no IPv6 said '${answer:-<nothing>}'"
    gh_inc "there is no IPv6 on this link, so a failure here proves nothing about the policy"
    return 2
}

case_AS5() {
    bring_up || return 2
    local before_machine answer
    before_machine="$(gh_from_machine)"
    answer="$(gh_dns_probe "$H_OUT_ADDR" 53)"
    sleep 0.5
    local after_machine
    after_machine="$(gh_from_machine)"
    gh_note "query to a foreign resolver answered with '${answer:-<nothing>}'"
    gh_note "packets from the machine: $((after_machine - before_machine))"
    if [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "a query reached the foreign resolver"
        return 1
    fi
    case "$answer" in
    *"$H_CANARY_ADDR"*) gh_ok "the query was carried by the chokepoint and answered by the right upstream" ;;
    *) gh_inc "the query was not answered by the configured upstream, so redirect cannot be shown" ; return 2 ;;
    esac
}

case_AS6() {
    bring_up || return 2
    local before_machine answer
    before_machine="$(gh_from_machine)"
    answer="$(tcp_dns_probe "$H_OUT_ADDR" 53)"
    sleep 0.5
    local after_machine
    after_machine="$(gh_from_machine)"
    gh_note "DNS over TCP to a foreign resolver answered with '${answer:-<nothing>}'"
    gh_note "packets from the machine: $((after_machine - before_machine))"
    if [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "a TCP query reached the foreign resolver"
        return 1
    fi
    case "$answer" in
    *"$H_CANARY_ADDR"*) gh_ok "DNS over TCP is carried by the chokepoint" ;;
    *) gh_inc "DNS over TCP was not answered, so the relay's TCP path is not shown" ; return 2 ;;
    esac
}

# ---------------------------------------------------------------- lifecycle

case_AL1() {
    gh_setup yes
    gh_start_tor
    gh_start_dns_upstream
    # A storm starts before the policy exists. Traffic in that window is expected: the machine is
    # open, and the claim is only that a transition never makes it *more* permissive than the union
    # of before and after. What must hold is what follows the connect.
    gh_storm_start 20
    sleep 1
    gh_connect >/dev/null
    local from_here
    from_here="$(gh_from_machine)"
    sleep 5
    gh_storm_stop
    sleep 1
    local now
    now="$(gh_from_machine)"
    gh_note "packets from the machine after the connect completed: $((now - from_here))"
    if [ "$((now - from_here))" != "0" ]; then
        gh_bad "traffic crossed from the machine after the connect reported success"
        return 1
    fi
    gh_ok "once connected, nothing crossed from the machine"
}

case_AL4() {
    bring_up || return 2
    gh_storm_start 12
    sleep 1
    # Counted until the disconnect returns. Before that moment the policy is still in place, so any
    # packet from the machine in this window is a violation; afterwards the machine is open by
    # design and its traffic is beside the point.
    local before_machine
    before_machine="$(gh_from_machine)"
    gh_disconnect >/dev/null
    local at_disconnect
    at_disconnect="$(gh_from_machine)"
    gh_storm_stop
    gh_note "packets from the machine while the disconnect was in flight: $((at_disconnect - before_machine))"
    if [ "$((at_disconnect - before_machine))" != "0" ]; then
        gh_bad "traffic crossed from the machine during the disconnect"
        return 1
    fi
    gh_ok "nothing crossed from the machine while the disconnect was in flight"
}

case_AL7() {
    bring_up || return 2
    gh_storm_start 12
    sleep 1
    local before_machine
    before_machine="$(gh_from_machine)"
    gh_panic >/dev/null
    sleep 4
    gh_storm_stop
    sleep 1
    local after_machine
    after_machine="$(gh_from_machine)"
    gh_note "packets from the machine during panic: $((after_machine - before_machine))"
    if [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "traffic crossed from the machine while blocking everything"
        return 1
    fi
    gh_ok "nothing crossed from the machine during the panic"
}

# ---------------------------------------------------------------- failures

case_AF1() {
    bring_up || return 2
    gh_stop_tor
    local before_machine answer
    before_machine="$(gh_from_machine)"
    answer="$(gh_tcp_probe)"
    sleep 0.5
    local after_machine
    after_machine="$(gh_from_machine)"
    gh_note "probe with Tor dead said '${answer:-<nothing>}'"
    gh_note "packets from the machine: $((after_machine - before_machine))"
    if [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "traffic fell back to the clearnet when Tor died"
        return 1
    fi
    if gh_wait_for_state "no traffic can leave" 12; then
        gh_note "the machine escalated to blocked"
    else
        gh_note "the machine still reports: $(gh_status | head -1)"
    fi
    gh_ok "Tor dying did not open a path"
}

case_AF2() {
    bring_up || return 2
    gh_kill_relay
    sleep 0.5
    local before_machine answer
    before_machine="$(gh_from_machine)"
    answer="$(gh_dns_probe 127.0.0.1 53)"
    sleep 0.5
    local after_machine
    after_machine="$(gh_from_machine)"
    gh_note "resolution with the relay dead said '${answer:-<nothing>}'"
    gh_note "packets from the machine: $((after_machine - before_machine))"
    if [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "a query went somewhere else once the relay died"
        return 1
    fi
    gh_ok "the relay dying did not open a path"
    gh_note "state after the relay died: $(gh_status | head -1)"
}

case_AF3() {
    bring_up || return 2
    gh_stop_core
    local before_machine answer
    before_machine="$(gh_from_machine)"
    answer="$(gh_tcp_probe)"
    sleep 0.5
    local after_machine
    after_machine="$(gh_from_machine)"
    gh_note "probe with the control plane dead said '${answer:-<nothing>}'"
    gh_note "packets from the machine: $((after_machine - before_machine))"
    if [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "killing the control plane loosened the policy"
        return 1
    fi
    if gh_policy_present; then
        gh_ok "the policy is still in the kernel, and nothing crossed"
    else
        gh_bad "the policy disappeared with the control plane"
        return 1
    fi
}

case_AF4() {
    bring_up || return 2
    gh_stop_netd
    local before_machine answer
    before_machine="$(gh_from_machine)"
    answer="$(gh_tcp_probe)"
    sleep 0.5
    local after_machine
    after_machine="$(gh_from_machine)"
    gh_note "probe with the helper dead said '${answer:-<nothing>}'"
    gh_note "packets from the machine: $((after_machine - before_machine))"
    if [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "killing the helper loosened the policy"
        return 1
    fi
    gh_policy_present && gh_ok "the policy is still in the kernel, and nothing crossed"
}

# ---------------------------------------------------------------- corruption

case_AC3() {
    bring_up || return 2
    gh_destroy_policy
    gh_note "the policy was removed by hand: $(gh_policy_tables | tr '\n' ' ')"
    # While it is gone, traffic can leave. This is the injected fault, not a defect: the question is
    # what Ghostnector does about it.
    gh_storm_start 3
    sleep 3
    local during_machine
    during_machine="$(gh_from_machine)"
    gh_note "packets from the machine while the policy was gone: $during_machine"
    gh_storm_stop
    if gh_wait_for_state "no traffic can leave" 15; then
        gh_ok "the machine denied everything within the window"
    else
        gh_bad "the machine still claims: $(gh_status | head -1)"
        return 1
    fi
    if ! gh_policy_present; then
        gh_bad "the state says blocked but the kernel has no policy"
        return 1
    fi
    local after_denial_before after_denial_after
    after_denial_before="$(gh_from_machine)"
    gh_storm_start 3
    sleep 3
    gh_storm_stop
    after_denial_after="$(gh_from_machine)"
    gh_note "packets from the machine after re-denial: $((after_denial_after - after_denial_before))"
    if [ "$((after_denial_after - after_denial_before))" != "0" ]; then
        gh_bad "traffic still crosses after the machine said it had denied everything"
        return 1
    fi
    gh_ok "removal of the policy was noticed and answered, and the window is bounded"
    gh_note "window bound: one verification interval plus timeout (the documented bound)"
}

case_AC4() {
    bring_up || return 2
    # A change that permits traffic a configured check exercises.
    gh_inject_rule meta l4proto udp counter accept comment '"injected by the adversarial run"'
    local before_udp
    before_udp="$(gh_events udp)"
    gh_udp_probe >/dev/null
    sleep 1
    local after_udp
    after_udp="$(gh_events udp)"
    gh_note "datagrams that arrived after the injected rule: $((after_udp - before_udp))"
    if [ "$((after_udp - before_udp))" = "0" ]; then
        gh_inc "the injected rule did not actually let UDP out, so detection was not exercised"
        return 2
    fi
    if gh_wait_for_state "no traffic can leave" 15; then
        gh_ok "a UDP-permitting change was noticed, and the machine denied everything"
    else
        gh_bad "a UDP-permitting change was not noticed: $(gh_status | head -1)"
        return 1
    fi
}

case_AC5() {
    bring_up || return 2
    # A change that permits traffic no configured check exercises. Two rules, because TCP needs both
    # paths subverted: the nat chain redirects it before the filter ever sees the destination, so an
    # accept rule alone changes nothing — a property worth knowing rather than assuming.
    gh_inject_nat_return tcp dport "$H_TCP_PORT"
    gh_inject_rule tcp dport "$H_TCP_PORT" counter accept comment '"injected by the adversarial run"'
    local before_machine
    before_machine="$(gh_from_machine)"
    gh_tcp_probe >/dev/null
    sleep 1
    local after_machine
    after_machine="$(gh_from_machine)"
    gh_note "packets from the machine after the injected rules: $((after_machine - before_machine))"
    if [ "$((after_machine - before_machine))" = "0" ]; then
        gh_inc "the injected rules did not actually let TCP out, so nothing was demonstrated"
        return 2
    fi
    local state
    state="$(gh_status | head -1)"
    gh_note "state while traffic was leaving directly: $state"
    case "$state" in
    *"no traffic can leave"*)
        gh_ok "the machine had already denied everything"
        ;;
    *)
        echo "  demonstrated: a TCP-permitting change was invisible, and the state still claimed protection"
        FINDINGS+=("AC5: two injected rules that permit only TCP destinations are not detected (gap G3); the state kept claiming protection while traffic left directly")
        return 3
        ;;
    esac
}

case_AC6() {
    bring_up || return 2
    gh_stop_core
    gh_destroy_policy
    gh_note "journal says protected; kernel has: $(gh_policy_tables | tr '\n' ' ')"
    gh_start_stack || return 2
    local state
    state="$(gh_status)"
    if echo "$state" | grep -q "no traffic can leave"; then
        gh_ok "a stale journal with an empty kernel leads to a blocked machine, not an open one"
    else
        gh_bad "the machine did not fail closed: $(echo "$state" | head -1)"
        return 1
    fi
}

# ---------------------------------------------------------------- run

echo "=== Ghostnector adversarial exposure ==="
echo "target: $TARGET"
echo "commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo

run_case case_AS1 "steady state: TCP reaches the destination, and only through the conduit"
run_case case_AS2 "steady state: UDP cannot leave"
run_case case_AS3 "steady state: IPv6 cannot leave"
run_case case_AS4 "steady state: IPv6 on a link without IPv6 (must be inconclusive)"
run_case case_AS5 "steady state: a query to a foreign resolver is carried by the chokepoint"
run_case case_AS6 "steady state: DNS over TCP is carried by the chokepoint"
run_case case_AL1 "lifecycle: nothing crosses while connecting under load"
run_case case_AL4 "lifecycle: nothing crosses while disconnecting under load"
run_case case_AL7 "lifecycle: nothing crosses while blocking everything"
run_case case_AF1 "failure: Tor dying opens nothing"
run_case case_AF2 "failure: the DNS relay dying opens nothing"
run_case case_AF3 "failure: the control plane dying loosens nothing"
run_case case_AF4 "failure: the privileged helper dying loosens nothing"
run_case case_AC3 "corruption: a removed policy is noticed and answered"
run_case case_AC4 "corruption: a change a check exercises is noticed"
run_case case_AC5 "corruption: a change no check exercises (expected to be invisible)"
run_case case_AC6 "corruption: a stale journal with an empty kernel fails closed"

echo "=== summary ==="
echo "held:         $PASSED"
echo "contradicted: $FAILED"
echo "inconclusive: $INCONCLUSIVE"
echo "demonstrated: $DEMONSTRATED"
if [ "${#FINDINGS[@]}" -gt 0 ]; then
    echo
    echo "=== findings ==="
    for finding in "${FINDINGS[@]}"; do
        echo "- $finding"
    done
fi
echo
echo "logs are in $H_LOG (removed on teardown); findings above are the record"
