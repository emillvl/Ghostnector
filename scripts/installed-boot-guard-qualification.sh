#!/usr/bin/env bash
#
# The boot guard on the installed product, across a real reboot (D-54).
#
#   installed-boot-guard-qualification.sh prepare
#   installed-boot-guard-qualification.sh verify-protected
#   installed-boot-guard-qualification.sh verify-off
#
# The controller drives the reboots; this script only prepares before one and verifies after one, so
# it can be run over the VMMDev channel (guest control), which survives the policy that cuts SSH.
#
# prepare:          clean off, remove the fallback copy (a fresh install has none), enable
#                   protection, and prove the copy appears with owner-only permissions; the
#                   persisted intent then asks for protection, so the next boot must deny.
# verify-protected: the boot guard itself succeeded (exit 0, its own journal message), its success
#                   preceded the network-pre barrier, the fail-closed table is present, and the
#                   machine reports blocked; then recover to off through the documented path.
# verify-off:       with no persisted intent, the guard exits 0 without applying anything, no table
#                   exists, and the machine is usable.
#
# Durable log: /var/log/ghostnector-qual/boot-guard-qualification.log (appended, root-owned 0644).
#
# Requires: root on the installed product.

set -uo pipefail

LOGDIR=/var/log/ghostnector-qual
LOG="$LOGDIR/boot-guard-qualification.log"
CLI=(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector)
COPY=/var/lib/ghostnector-netd/fail-closed.nft
SOCKET=/run/ghostnector/netd/netd.sock

PASSED=0
FAILED=0
INCONCLUSIVE=0

ok()   { echo "  ok: $*"; PASSED=$((PASSED + 1)); }
bad()  { echo "  FAIL: $*"; FAILED=$((FAILED + 1)); }
inc()  { echo "  inconclusive: $*"; INCONCLUSIVE=$((INCONCLUSIVE + 1)); }
note() { echo "    $*"; }

mkdir -p "$LOGDIR"; chmod 0755 "$LOGDIR"
{
    echo
    echo "== boot-guard ${1:-no-mode} at $(date -u) (boot $(cat /proc/sys/kernel/random/boot_id)) =="
} >>"$LOG"
exec >>"$LOG" 2>&1

[ "$(id -u)" = "0" ] || { echo "this qualification needs root"; exit 2; }

mode="${1:-}"
cli_state() { "${CLI[@]}" status 2>&1; }
wait_status() { local i; for i in $(seq 1 "$2"); do cli_state | head -1 | grep -q "$1" && return 0; sleep 1; done; return 1; }
guard_status() { systemctl show ghostnector-bootguard.service -p ExecMainStatus --value; }
guard_message() {
    # The program's own lines (journald prefixes them with the unit name); the systemd "Finished"
    # line says nothing about what the guard did.
    journalctl -b -u ghostnector-bootguard.service --no-pager 2>/dev/null |
        grep -v "systemd\[1\]" | tail -5
}

case "$mode" in
prepare)
    echo "-- prepare: a fresh install has no copy; a protected session must leave one --"
    timeout 60 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
    sleep 2
    rm -f /var/lib/ghostnector/intent.json "$COPY"
    [ -e "$COPY" ] && bad "the copy could not be removed for the fresh-install case" \
        || ok "the copy is absent, as on a fresh install"

    # A machine-wide session needs a verification endpoint that answers through Tor; the copy is
    # written by the apply itself, so the check only keeps the state honest while we wait.
    endpoint=""
    for candidate in $(getent ahostsv4 checkip.amazonaws.com | awk '{print $1}'); do
        code="$(timeout 15 curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$candidate/" || true)"
        [ "$code" = "200" ] && { endpoint="$candidate"; break; }
    done
    cat >/etc/ghostnector/core.env <<EOF
GHOSTNECTOR_VERIFY=--check-url http://$endpoint/ --verify-timeout 10 --verify-interval 5 --verify-stale-after 30
EOF
    systemctl restart ghostnector-core.service
    sleep 2

    "${CLI[@]}" connect >/dev/null 2>&1 || true
    for _ in $(seq 1 240); do
        [ -f "$COPY" ] && break
        sleep 1
    done
    note "state after connect: $(cli_state | head -1)"
    grep -q '"protected"[[:space:]]*:[[:space:]]*true' /var/lib/ghostnector/intent.json 2>/dev/null \
        && ok "the persisted intent asks for protection" \
        || bad "the intent does not ask for protection"

    if [ -f "$COPY" ]; then
        ok "the protected session left the fallback copy behind"
    else
        bad "no fallback copy after a protected apply"
    fi
    [ "$(stat -c %U "$COPY" 2>/dev/null)" = "ghostnector" ] \
        && ok "the copy is owned by the control plane's user" \
        || bad "the copy is owned by $(stat -c %U "$COPY" 2>/dev/null)"
    [ "$(stat -c %a "$COPY" 2>/dev/null)" = "600" ] \
        && ok "the copy is owner-only" \
        || bad "the copy's mode is $(stat -c %a "$COPY" 2>/dev/null)"
    head -1 "$COPY" 2>/dev/null | grep -q "destroy table inet ghostnector" \
        && ok "the copy is the fail-closed ruleset" \
        || bad "the copy does not look like the fail-closed ruleset"
    grep -q '"protected"[[:space:]]*:[[:space:]]*true' /var/lib/ghostnector/intent.json 2>/dev/null \
        && note "the next boot must deny before the network"

    # No unprivileged user may read the copy or reach the helper.
    if setpriv --reuid=1000 --regid=1000 --clear-groups /bin/cat "$COPY" >/dev/null 2>&1; then
        bad "an unprivileged user could read the fail-closed copy"
    else
        ok "an unprivileged user cannot read the copy"
    fi
    if setpriv --reuid=1000 --regid=1000 --clear-groups python3 -c 'import socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect(sys.argv[1])
except OSError:
    sys.exit(1)
sys.exit(0)' "$SOCKET" >/dev/null 2>&1; then
        bad "an unprivileged user could connect to the helper's socket"
    else
        ok "an unprivileged user cannot connect to the helper's socket"
    fi
    echo "    pre-reset state: $(cli_state | head -1)"
    ;;

verify-protected)
    echo "-- verify: the boot guard must have denied before the network --"
    status="$(guard_status)"
    if [ "$status" = "0" ]; then
        ok "the boot guard exited successfully (ExecMainStatus=0)"
    else
        bad "the boot guard did not succeed: ExecMainStatus=$status"
    fi
    message="$(guard_message)"
    case "$message" in
    *"denied everything"*) ok "the guard's own journal says the helper denied everything" ;;
    *"copy of the fail-closed policy was applied"*) ok "the guard's own journal says its copy was applied" ;;
    *"could not deny"*) bad "the guard reported it could not deny: $(echo "$message" | tail -1)" ;;
    *) inc "the guard's journal message was not recognised: $(echo "$message" | tail -1)" ;;
    esac

    guard_exit="$(systemctl show ghostnector-bootguard.service -p ExecMainExitTimestampMonotonic --value)"
    netpre="$(systemctl show network-pre.target -p ActiveEnterTimestampMonotonic --value)"
    if [ -n "$guard_exit" ] && [ "$guard_exit" != "0" ] && [ -n "$netpre" ] && [ "$netpre" != "0" ]; then
        if [ "$guard_exit" -le "$netpre" ]; then
            ok "the guard finished (${guard_exit}us) at or before the network-pre barrier (${netpre}us)"
        else
            bad "the guard finished after the network-pre barrier ($guard_exit > $netpre)"
        fi
    else
        inc "monotonic timestamps unavailable (guard=$guard_exit network-pre=$netpre)"
    fi

    nft list table inet ghostnector >/dev/null 2>&1 \
        && ok "the fail-closed table is present" \
        || bad "no policy table after a protected boot"
    state="$(cli_state | head -1)"
    case "$state" in
    *blocked*) ok "the machine reports blocked: $state" ;;
    *) bad "the machine did not report blocked: $state" ;;
    esac

    echo "    recovering through the documented path"
    "${CLI[@]}" disconnect >/dev/null 2>&1 || true
    if wait_status "off" 90; then
        ok "the documented disconnect recovered to off"
    else
        bad "recovery did not reach off: $(cli_state | head -1)"
    fi
    nft list table inet ghostnector >/dev/null 2>&1 \
        && bad "a policy table survived the recovery" \
        || ok "no policy table after the recovery"
    ;;

verify-off)
    echo "-- verify: with no persisted intent, nothing is applied --"
    status="$(guard_status)"
    if [ "$status" = "0" ]; then
        ok "the boot guard exited successfully (ExecMainStatus=0)"
    else
        bad "the boot guard did not succeed: ExecMainStatus=$status"
    fi
    message="$(guard_message)"
    case "$message" in
    *"nothing to do"*|*"not requested"*) ok "the guard did nothing, as the intent asked" ;;
    *) inc "the guard's journal message was not recognised: $(echo "$message" | tail -1)" ;;
    esac
    nft list table inet ghostnector >/dev/null 2>&1 \
        && bad "a policy table exists with no persisted intent" \
        || ok "no policy table with no persisted intent"
    state="$(cli_state | head -1)"
    case "$state" in
    *off*) ok "the machine is off: $state" ;;
    *) bad "the machine is not off: $state" ;;
    esac
    ;;

*)
    echo "usage: $0 prepare|verify-protected|verify-off"
    exit 2
    ;;
esac

echo "boot-guard ${mode}: held=$PASSED contradicted=$FAILED inconclusive=$INCONCLUSIVE"
echo "log: $LOG"
[ "$FAILED" = "0" ] || exit 1
exit 0
