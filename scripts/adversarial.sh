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
    if [ -n "${CASE:-}" ] && [ "${name#case_}" != "$CASE" ]; then
        return 0
    fi
    echo "── $name: $description"
    "$name" || verdict=$?
    case "$verdict" in
    0) PASSED=$((PASSED + 1)) ;;
    1) FAILED=$((FAILED + 1)) ;;
    3) DEMONSTRATED=$((DEMONSTRATED + 1)) ;;
    *) INCONCLUSIVE=$((INCONCLUSIVE + 1)) ;;
    esac
    if [ "$verdict" = "1" ]; then
        echo "  ── what crossed, as the kernel saw it ──"
        gh_leaks | sed 's/^/    /'
        echo "  ── when, against what the case was doing ──"
        gh_timeline | sed 's/^/    /'
        echo "  ── what the machine said ──"
        gh_status | head -8 | sed 's/^/    /'
        echo "  ── what the components said ──"
        tail -12 "$H_LOG/core.log" 2>/dev/null | sed 's/^/    core: /'
        tail -12 "$H_LOG/netd.log" 2>/dev/null | sed 's/^/    netd: /'
    fi
    gh_teardown >/dev/null 2>&1 || true
    echo
}

bring_up() {
    gh_setup "${1:-yes}"
    gh_start_tor
    gh_start_dns_upstream
    gh_start_stack || return 2
    connect_or_fail_setup || return 2
    return 0
}

# A connect that did not put a policy in place leaves an open machine, and every observation after it
# would be an observation of an open machine. That is a broken run, not a finding, so it must be
# impossible to mistake for one.
connect_or_fail_setup() {
    local answer
    answer="$(gh_connect)"
    if ! gh_policy_present || printf '%s' "$answer" | grep -qi "failed"; then
        echo "  setup: the connect did not put a policy in place: $(printf '%s' "$answer" | head -3)"
        return 1
    fi
    return 0
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
    # The control plane is running, the policy is *not* applied: this is the state a machine is in
    # when someone presses Connect.
    gh_setup yes
    gh_start_tor
    gh_start_dns_upstream
    gh_start_stack >/dev/null 2>&1 || return 2
    gh_storm_start 25
    sleep 1
    gh_watch_start
    gh_mark "connect: begin (machine is off, storm running)"
    gh_connect >/dev/null
    gh_mark "connect: returned"
    sleep 6
    gh_storm_stop
    gh_watch_stop
    local crossings
    crossings="$(gh_watch_violations)"
    if [ -n "$crossings" ]; then
        gh_bad "traffic crossed while the machine reported protection: $crossings"
        return 1
    fi
    gh_ok "no crossing was ever attributed to a machine reporting protection"
}

case_AL4() {
    bring_up || return 2
    gh_storm_start 15
    sleep 1
    gh_watch_start
    gh_mark "disconnect: begin"
    gh_disconnect >/dev/null
    gh_mark "disconnect: returned"
    sleep 3
    gh_storm_stop
    gh_watch_stop
    local crossings
    crossings="$(gh_watch_violations)"
    if [ -n "$crossings" ]; then
        gh_bad "traffic crossed while the machine reported protection: $crossings"
        return 1
    fi
    gh_ok "no crossing was ever attributed to a machine reporting protection"
}

case_AL7() {
    bring_up || return 2
    gh_storm_start 15
    sleep 1
    gh_watch_start
    gh_mark "panic: begin"
    gh_panic >/dev/null
    gh_mark "panic: returned"
    sleep 4
    gh_storm_stop
    gh_watch_stop
    local crossings
    crossings="$(gh_watch_violations)"
    if [ -n "$crossings" ]; then
        gh_bad "traffic crossed while the machine reported protection: $crossings"
        return 1
    fi
    gh_ok "no crossing was ever attributed to a machine reporting protection"
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
    # A change that permits traffic no configured probe traverses. Two rules, because TCP needs both
    # paths subverted: the nat chain redirects it before the filter ever sees the destination, so an
    # accept rule alone changes nothing — a property worth knowing rather than assuming.
    local marker="injected by the adversarial run"
    gh_inject_nat_return tcp dport "$H_TCP_PORT"
    gh_inject_rule tcp dport "$H_TCP_PORT" counter accept comment "\"$marker\""
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

    # The counterexample was real: traffic left directly while the machine reported protection. It
    # must not survive a verification interval. Nothing about the probes changed, so only comparing
    # the kernel's own ruleset against the one that was applied can find it.
    if ! gh_wait_for_state "no traffic can leave" 20; then
        gh_bad "a TCP-permitting change was never noticed: $(gh_status | head -1)"
        return 1
    fi
    local before_denied after_denied
    before_denied="$(gh_from_machine)"
    gh_tcp_probe >/dev/null
    sleep 2
    after_denied="$(gh_from_machine)"
    if [ "$((after_denied - before_denied))" != "0" ]; then
        gh_bad "the change survived the alarm: traffic still left after the machine denied everything"
        return 1
    fi
    if gh_policy_mentions "$marker"; then
        gh_bad "the injected rule is still in the kernel after the alarm"
        return 1
    fi
    gh_ok "a TCP-permitting change was noticed, denied, and overwritten"
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

# ---------------------------------------------------------------- network changes

case_AN1() {
    # The link goes away and comes back under load. An outage is a fact, not a finding: the questions
    # are whether protection survives it and whether anything crossed while the report and the kernel
    # disagreed.
    bring_up || return 2
    gh_storm_start 20
    gh_watch_start
    sleep 1
    gh_mark "link: down"
    gh_link down
    sleep 3
    local during_machine
    during_machine="$(gh_from_machine)"
    gh_mark "link: up"
    gh_link up
    sleep 3
    gh_mark "probe after the flap"
    gh_tcp_probe >/dev/null
    sleep 2
    gh_storm_stop
    gh_watch_stop
    local crossings
    crossings="$(gh_watch_violations)"
    if [ -n "$crossings" ]; then
        gh_bad "traffic crossed while the machine reported protection: $crossings"
        return 1
    fi
    if [ "$during_machine" != "0" ]; then
        gh_bad "packets from the machine crossed while the link was down: $during_machine"
        return 1
    fi
    local after_probe
    after_probe="$(gh_from_machine)"
    gh_note "packets from the machine after the link returned: $after_probe"
    if [ "$after_probe" != "0" ]; then
        gh_bad "a packet from the machine left after the link returned"
        return 1
    fi
    if ! gh_policy_present; then
        gh_bad "the policy did not survive the link flap"
        return 1
    fi
    gh_note "state after the flap: $(gh_status | head -1)"
    gh_ok "the policy survived the flap, and nothing crossed while the machine reported protection"
}

case_AN2() {
    # The route to the outside disappears and comes back under load. The policy is not
    # route-dependent, so the question is what is enforced when the route returns.
    bring_up || return 2
    gh_storm_start 18
    gh_watch_start
    sleep 1
    gh_mark "default route: removed"
    gh_default_route del
    sleep 3
    gh_mark "default route: restored"
    gh_default_route add
    sleep 2
    gh_mark "probe after the route returned"
    gh_tcp_probe >/dev/null
    sleep 2
    gh_storm_stop
    gh_watch_stop
    local crossings
    crossings="$(gh_watch_violations)"
    if [ -n "$crossings" ]; then
        gh_bad "traffic crossed while the machine reported protection: $crossings"
        return 1
    fi
    if ! gh_policy_present; then
        gh_bad "the policy did not survive the route change"
        return 1
    fi
    gh_note "state after the route change: $(gh_status | head -1)"
    gh_ok "the policy survived the route change, and nothing crossed while it reported protection"
}

case_AN3() {
    # The machine's address changes under load, as a new lease does. The policy was written for the
    # identity that existed at connect time; the question is whether an identity it never named is
    # outside it.
    bring_up || return 2
    gh_storm_start 20
    gh_watch_start
    sleep 1
    gh_mark "address: replaced with $H_MUT_ADDR2"
    gh_machine_address "$H_MUT_ADDR2"
    sleep 2
    local answer
    gh_mark "probe from the new address"
    answer="$(gh_tcp_probe_from "$H_MUT_ADDR2" "$H_OUT_ADDR" "$H_TCP_PORT")"
    gh_note "probe from the new address said '${answer:-<nothing>}'"
    sleep 2
    gh_storm_stop
    gh_watch_stop
    local from_new crossings
    from_new="$(gh_crossed_count "$H_MUT_ADDR2")"
    gh_note "packets that reached the outside from the new address: $from_new"
    crossings="$(gh_watch_violations)"
    if [ -n "$crossings" ]; then
        gh_bad "traffic crossed while the machine reported protection: $crossings"
        return 1
    fi
    if [ "$from_new" != "0" ]; then
        gh_bad "the new address had a path the old one did not"
        return 1
    fi
    if ! gh_policy_present; then
        gh_bad "the policy did not survive the address change"
        return 1
    fi
    gh_ok "the new identity had no path the policy did not already deny, and nothing crossed"
}

case_AN4() {
    # The IPv6 address disappears, as it does when a link loses its prefix. IPv6 is denied in every
    # profile; the question is whether losing the address changes what IPv4 does.
    bring_up yes || return 2
    local before4 answer6
    before4="$(gh_from_machine)"
    gh_mark "IPv6 address: removed"
    ip -n "$H_MUT" -6 addr del "$H_MUT_ADDR6/64" dev veth-mut 2>/dev/null || true
    sleep 1
    answer6="$(gh_ipv6_probe)"
    gh_note "IPv6 probe with no IPv6 address said '${answer6:-<nothing>}'"
    gh_mark "IPv4 probe after the v6 address went away"
    gh_tcp_probe >/dev/null
    sleep 2
    local after4
    after4="$(gh_from_machine)"
    gh_note "packets from the machine after the change: $((after4 - before4))"
    if [ "$((after4 - before4))" != "0" ]; then
        gh_bad "a packet from the machine crossed after the IPv6 address disappeared"
        return 1
    fi
    if ! gh_policy_present; then
        gh_bad "the policy did not survive the IPv6 change"
        return 1
    fi
    gh_ok "losing the IPv6 address changed nothing about what may leave"
}

case_AN5() {
    # A second interface and route appear while the machine is protected, as a hotplugged device
    # would. The policy is written for a machine, not for an interface; this is where that has to be
    # visible.
    bring_up || return 2
    gh_second_path_add
    local listener
    listener="$(gh_listener_start "$H_OUT2_ADDR" "$H_TCP_PORT" tcp2)"
    sleep 0.5
    local before_machine answer
    before_machine="$(gh_from_machine)"
    gh_mark "probe over the new path"
    answer="$(gh_tcp_probe_from "$H_MUT2_ADDR" "$H_OUT2_ADDR" "$H_TCP_PORT")"
    gh_note "probe over the new path said '${answer:-<nothing>}'"
    sleep 1
    local after_machine direct carried
    after_machine="$(gh_from_machine)"
    direct="$(gh_events_from tcp2 "$H_MUT_ADDR")"
    carried="$(gh_events tcp2)"
    kill "$listener" 2>/dev/null || true
    gh_note "packets from the machine over the new path: $((after_machine - before_machine)); connections from the machine's address: $direct; connections in total: $carried"
    if [ "$direct" != "0" ] || [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "the new path carried traffic from the machine's own address"
        return 1
    fi
    if ! gh_policy_present; then
        gh_bad "the policy was lost when the new interface appeared"
        return 1
    fi
    gh_ok "the new path was subject to the same policy: nothing from the machine's address used it"
}

# ---------------------------------------------------------------- exemptions

case_AE1() {
    # Tor's own egress must be direct, or the design is circular. The exemption is an identity, so the
    # positive direction is that identity reaching the outside, and the negative is that an ordinary
    # identity cannot take the same direct path.
    bring_up || return 2
    local before_events before_machine
    before_events="$(gh_events tcp)"
    before_machine="$(gh_from_machine)"
    gh_mark "Tor's uid: direct egress"
    local answer
    answer="$(gh_as_tor python3 -c '
import socket, sys
conn = socket.socket(); conn.settimeout(3)
conn.bind((sys.argv[1], 0))
conn.connect((sys.argv[2], int(sys.argv[3])))
conn.sendall(b"tor")
sys.stdout.write(conn.recv(64).decode(errors="replace"))
' "$H_MUT_ADDR" "$H_OUT_ADDR" "$H_TCP_PORT" 2>&1 || true)"
    sleep 1
    local after_events after_machine
    after_events="$(gh_events tcp)"
    after_machine="$(gh_from_machine)"
    gh_note "Tor's uid got '${answer:-<nothing>}'"
    gh_note "connections seen outside: $((after_events - before_events)); packets from the machine's address: $((after_machine - before_machine))"
    if [ "$((after_events - before_events))" != "1" ]; then
        gh_bad "Tor's uid could not use its exemption"
        return 1
    fi
    if [ "$((after_machine - before_machine))" = "0" ]; then
        gh_inc "the connection did not come from the machine's own address, so the exemption is not what carried it"
        return 2
    fi

    before_machine="$(gh_from_machine)"
    gh_mark "an ordinary uid: the same operation"
    gh_tcp_probe >/dev/null
    sleep 1
    local after_negative
    after_negative="$(gh_from_machine)"
    if [ "$((after_negative - before_machine))" != "0" ]; then
        gh_bad "an unexempted identity used the direct path"
        return 1
    fi
    gh_ok "Tor's uid reached the outside directly, and an unexempted identity could not"
}

case_AE2() {
    # DHCP is a protocol exemption, not an identity: the client's request travels from its own port to
    # the server's. The positive direction is that request leaving; the negative is that neither an
    # ordinary source port nor the inverted shape does.
    bring_up || return 2
    local before_dhcp before_machine
    before_dhcp="$(gh_events dhcp)"
    before_machine="$(gh_from_machine)"
    gh_mark "DHCP client: a request from its own port"
    gh_udp_from_68 "$H_OUT_ADDR" 67 >/dev/null
    sleep 1
    local after_dhcp after_machine
    after_dhcp="$(gh_events dhcp)"
    after_machine="$(gh_from_machine)"
    gh_note "requests the outside recorded: $((after_dhcp - before_dhcp)); packets from the machine: $((after_machine - before_machine))"
    if [ "$((after_dhcp - before_dhcp))" != "1" ]; then
        gh_bad "the DHCP client's request did not leave the machine, so the exemption does not keep the link alive"
        return 1
    fi
    if [ "$((after_machine - before_machine))" = "0" ]; then
        gh_inc "a request arrived without a packet from the machine's address, so it cannot have been the client's"
        return 2
    fi

    local before_other
    before_other="$(gh_events dhcp)"
    gh_udp_to_port "$H_OUT_ADDR" 67 >/dev/null
    gh_udp_from_68 "$H_OUT_ADDR" 68 >/dev/null
    sleep 1
    local after_other
    after_other="$(gh_events dhcp)"
    gh_note "requests that left with an ordinary source port or the client's destination port: $((after_other - before_other))"
    if [ "$((after_other - before_other))" != "0" ]; then
        gh_bad "a datagram outside the exemption's shape reached the server's port"
        return 1
    fi
    gh_ok "the client's request left, and neither the ordinary port nor the inverted shape did"
}

case_AE3() {
    # The local network is an opt-in address exception: it must not exist unless it is asked for,
    # and when it is asked for it must carry traffic directly while verification stays honest. The
    # verifier's own endpoints are outside the LAN ranges (H_CHECK_ADDR), so this is decided by the
    # steady state, not by a race against the verifier's 2 s settle (D-26).
    gh_setup yes
    gh_start_tor
    gh_start_dns_upstream
    gh_start_stack >/dev/null 2>&1 || return 2
    connect_or_fail_setup || return 2
    sleep 2
    gh_tcp_probe >/dev/null
    sleep 1
    local default_direct
    default_direct="$(gh_events_from tcp "$H_MUT_ADDR")"
    gh_note "without the exception, connections from the machine's address: $default_direct"
    if [ "$default_direct" != "0" ]; then
        gh_bad "the local network was reachable directly without the exception"
        return 1
    fi

    gh_disconnect >/dev/null
    local lan_answer
    lan_answer="$(gh_cli connect --lan)"
    if ! gh_policy_present || printf '%s' "$lan_answer" | grep -qi "failed"; then
        echo "  setup: the opt-in connect did not put a policy in place: $(printf '%s' "$lan_answer" | head -3)"
        return 2
    fi

    # Wait for a verification run to finish. With the check endpoints outside the LAN ranges the
    # profile must verify; the old D-26 behaviour (the verifier's own probe reaching the exempt LAN
    # destination and being read as a leak) would show up as a Blocked machine here.
    local state=""
    local waited=0
    while [ "$waited" -lt 15 ]; do
        state="$(gh_status | head -1)"
        case "$state" in
        *"and verified"* | *"no traffic can leave"*) break ;;
        esac
        sleep 1
        waited=$((waited + 1))
    done
    gh_note "state after verification settled: $state"
    case "$state" in
    *"and verified"*) ;;
    *)
        gh_bad "a valid allow_lan configuration did not verify: $state"
        return 1
        ;;
    esac

    local before_lan answer after_lan
    before_lan="$(gh_events_from tcp "$H_MUT_ADDR")"
    gh_mark "with the LAN exception: a direct probe"
    answer="$(gh_tcp_probe)"
    sleep 1
    after_lan="$(gh_events_from tcp "$H_MUT_ADDR")"
    gh_note "probe with the exception said '${answer:-<nothing>}'; connections from the machine's address: $((after_lan - before_lan))"
    if [ "$((after_lan - before_lan))" = "0" ]; then
        gh_bad "the local network was still unreachable with the exception enabled"
        return 1
    fi
    case "$answer" in
    *ok*) ;;
    *) gh_inc "the direct connection was seen but not answered, so the positive half is not complete"; return 2 ;;
    esac
    gh_ok "the local network was unreachable by default, directly reachable when asked for, and verification stayed honest"
}

case_AE4() {
    # In Tor mode DNS goes to the chokepoint over loopback. The question is whether resolution works
    # without a resolver exemption and whether a foreign resolver can be reached directly.
    bring_up || return 2
    local before_machine answer_loop answer_foreign
    before_machine="$(gh_from_machine)"
    gh_mark "DNS: through the loopback chokepoint"
    answer_loop="$(gh_dns_probe 127.0.0.1 53)"
    gh_mark "DNS: aimed at a foreign resolver"
    answer_foreign="$(gh_dns_probe "$H_OUT_ADDR" 53)"
    sleep 1
    local after_machine
    after_machine="$(gh_from_machine)"
    gh_note "loopback query answered with '${answer_loop:-<nothing>}'"
    gh_note "foreign query answered with '${answer_foreign:-<nothing>}'"
    gh_note "packets from the machine: $((after_machine - before_machine))"
    case "$answer_loop" in
    *"$H_CANARY_ADDR"*) ;;
    *) gh_inc "the loopback chokepoint did not answer, so the positive half is not established"; return 2 ;;
    esac
    if [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "a query reached a foreign resolver"
        return 1
    fi
    if gh_status | grep -q "dnscrypt"; then
        gh_bad "the Tor profile reports a resolver exemption it must not have"
        return 1
    fi
    gh_ok "DNS worked over loopback, no resolver exemption exists, and nothing reached a foreign resolver"
}

case_AE5() {
    # Loopback is where the chokepoint and the SOCKS port live: an ordinary identity must be able to
    # reach a listener there, and nothing about it may leave the machine.
    bring_up || return 2
    local before_machine answer
    before_machine="$(gh_from_machine)"
    gh_mark "loopback: a round trip as an ordinary uid"
    answer="$(gh_loopback_probe)"
    sleep 1
    local after_machine
    after_machine="$(gh_from_machine)"
    gh_note "loopback round trip said '${answer:-<nothing>}'"
    gh_note "packets from the machine: $((after_machine - before_machine))"
    case "$answer" in
    *loopback-ok*) ;;
    *) gh_bad "an ordinary identity could not use loopback, where the chokepoint lives"; return 1 ;;
    esac
    if [ "$((after_machine - before_machine))" != "0" ]; then
        gh_bad "a loopback round trip sent something out of the machine"
        return 1
    fi
    gh_ok "loopback worked for an ordinary identity and nothing left the machine"
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
run_case case_AC5 "corruption: a change no probe traverses is found by comparing the kernel's ruleset"
run_case case_AC6 "corruption: a stale journal with an empty kernel fails closed"
run_case case_AN1 "network: a link flap does not change what may leave"
run_case case_AN2 "network: losing and regaining the route does not change what may leave"
run_case case_AN3 "network: a new address is not a new identity"
run_case case_AN4 "network: losing IPv6 changes nothing about IPv4"
run_case case_AN5 "network: a new interface is subject to the same policy"
run_case case_AE1 "exemption: Tor's uid may egress directly, and an ordinary uid may not"
run_case case_AE2 "exemption: a DHCP request leaves from the client's port, and no other shape does"
run_case case_AE3 "exemption: the local network is unreachable until opted in"
run_case case_AE4 "exemption: resolution works over loopback with no resolver exemption"
run_case case_AE5 "exemption: loopback works and goes nowhere else"

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
