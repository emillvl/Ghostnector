#!/usr/bin/env bash
#
# Exercises the whole stack inside a throwaway network namespace:
#
#   ghostnector (CLI)  ->  ghostnector-core  ->  ghostnector-netd  ->  kernel
#
# What it proves:
#   1. a client that is not allowed to talk to the control plane is refused
#   2. connect applies the policy, and the kernel really has it
#   3. the state is reported as protected-but-unverified, never as "protected and verified"
#   4. panic leaves the machine denied, and disconnect returns it to the baseline
#   5. a restart that finds protection requested but nothing applied fails closed rather than
#      quietly returning to the clearnet
#
# Requires: root, iproute2, nftables, setpriv (util-linux).

set -euo pipefail

TARGET_DIR="${1:?usage: core-cli-test.sh <target/debug directory>}"
NS="gh-core-test"
RUNDIR="/run/ghostnector"
BINDIR="/tmp/gh-bin"
WORKDIR="/tmp/gh-core-test"
CORE_USER="ghostnector-core"
OUTSIDER="ghostnector-outsider"
NETD_PID=""
CORE_PID=""

cleanup() {
    [ -n "$CORE_PID" ] && kill "$CORE_PID" 2>/dev/null || true
    [ -n "$NETD_PID" ] && kill "$NETD_PID" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    rm -rf "$BINDIR" "$WORKDIR" "$RUNDIR"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    for log in /tmp/gh-core.log /tmp/gh-netd-stack.log; do
        [ -f "$log" ] && { echo "--- $log ---"; cat "$log"; }
    done
    exit 1
}
ok() { echo "  ok: $*"; }

[ "$(id -u)" = "0" ] || fail "this test needs root"

# ---------------------------------------------------------------- identities and binaries
for user in "$CORE_USER" "$OUTSIDER"; do
    id -u "$user" >/dev/null 2>&1 || \
        useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$user"
done
CORE_UID="$(id -u "$CORE_USER")"
CORE_GID="$(id -g "$CORE_USER")"
OUTSIDER_UID="$(id -u "$OUTSIDER")"
OUTSIDER_GID="$(id -g "$OUTSIDER")"

# The build directory belongs to root, so the unprivileged daemon gets its own copy.
mkdir -p "$BINDIR"
install -m 0755 "$TARGET_DIR/ghostnector-netd" "$BINDIR/ghostnector-netd"
install -m 0755 "$TARGET_DIR/ghostnector-core" "$BINDIR/ghostnector-core"
install -m 0755 "$TARGET_DIR/ghostnector" "$BINDIR/ghostnector"

mkdir -p "$WORKDIR" "$RUNDIR"
chown "$CORE_UID" "$WORKDIR"
# systemd's RuntimeDirectory= would create this owned by the service user; do the same here, so the
# unprivileged daemon can create its socket while nobody else can.
chown "$CORE_UID" "$RUNDIR"
chmod 0755 "$RUNDIR"
JOURNAL="$WORKDIR/intent.json"

ip netns add "$NS"

in_ns() { ip netns exec "$NS" "$@"; }
as_user() {
    local uid="$1" gid="$2"
    shift 2
    ip netns exec "$NS" setpriv --reuid="$uid" --regid="$gid" --clear-groups "$@"
}
cli() { as_user "$CORE_UID" "$CORE_GID" "$BINDIR/ghostnector" --socket "$RUNDIR/core.sock" "$@"; }

wait_for_socket() {
    for _ in $(seq 1 60); do
        [ -S "$1" ] && return 0
        sleep 0.1
    done
    return 1
}

start_stack() {
    in_ns "$BINDIR/ghostnector-netd" --socket "$RUNDIR/netd.sock" --peer-uid "$CORE_UID" \
        >/tmp/gh-netd-stack.log 2>&1 &
    NETD_PID=$!
    wait_for_socket "$RUNDIR/netd.sock" || fail "the helper did not start"

    as_user "$CORE_UID" "$CORE_GID" "$BINDIR/ghostnector-core" \
        --socket "$RUNDIR/core.sock" --helper "$RUNDIR/netd.sock" --journal "$JOURNAL" \
        >/tmp/gh-core.log 2>&1 &
    CORE_PID=$!
    wait_for_socket "$RUNDIR/core.sock" || fail "the control plane did not start"
}

stop_core() {
    [ -n "$CORE_PID" ] && kill "$CORE_PID" 2>/dev/null || true
    wait "$CORE_PID" 2>/dev/null || true
    CORE_PID=""
    rm -f "$RUNDIR/core.sock"
}

start_stack
ok "the stack started"

# ---------------------------------------------------------------- an unauthorised client
if as_user "$OUTSIDER_UID" "$OUTSIDER_GID" "$BINDIR/ghostnector" \
    --socket "$RUNDIR/core.sock" status >/tmp/gh-outsider.log 2>&1; then
    fail "a user outside the socket's permissions reached the control plane"
fi
grep -qi "cannot reach the control plane" /tmp/gh-outsider.log ||
    fail "the outsider's failure was not explained: $(cat /tmp/gh-outsider.log)"
ok "a client without access was refused"

# ---------------------------------------------------------------- off, connect, blocked, off
STATUS="$(cli status)"
case "$STATUS" in
*"traffic is not protected"*) ok "the initial state is off" ;;
*) fail "unexpected initial state: $STATUS" ;;
esac

CONNECTED="$(cli connect)"
case "$CONNECTED" in
*"protected, but unverified"*) ok "connect reports protected-but-unverified" ;;
*) fail "connect did not report a protected state: $CONNECTED" ;;
esac
case "$CONNECTED" in
*"nothing can verify it yet"*) ok "it says plainly that nothing has verified it" ;;
*) fail "the verification status was not reported: $CONNECTED" ;;
esac

in_ns nft list tables | grep -q ghostnector || fail "the kernel has no policy after connect"
ok "the kernel really has the policy"
grep -q '"protected": true' "$JOURNAL" || fail "the intent was not recorded"
ok "the intent was recorded"

BLOCKED="$(cli panic)"
case "$BLOCKED" in
*"no traffic can leave"*) ok "panic leaves the machine denied" ;;
*) fail "panic did not report a blocked state: $BLOCKED" ;;
esac

OFF="$(cli disconnect)"
case "$OFF" in
*"traffic is not protected"*) ok "disconnect returns to the baseline" ;;
*) fail "disconnect did not report an off state: $OFF" ;;
esac
if in_ns nft list tables | grep -q ghostnector; then
    fail "the policy survived a disconnect"
fi
ok "the kernel has nothing left after disconnect"
grep -q '"protected": false' "$JOURNAL" || fail "the intent was not cleared"
ok "the intent was cleared"

# ---------------------------------------------------------------- restart reconciliation
cli connect >/dev/null
grep -q '"protected": true' "$JOURNAL" || fail "the second connect did not record intent"
stop_core
# Simulate a reboot: the kernel lost everything, but the journal still says the user wants protection.
in_ns nft destroy table inet ghostnector 2>/dev/null || true
ok "pretended to reboot: the journal says protected, the kernel has nothing"

start_stack
RECONCILED="$(cli status)"
case "$RECONCILED" in
*"no traffic can leave"*) ok "the restarted control plane failed closed" ;;
*) fail "a restart did not fail closed: $RECONCILED" ;;
esac
case "$RECONCILED" in
*"fail-closed baseline has been applied instead"*) ok "and it explains why" ;;
*) fail "the reason was not given: $RECONCILED" ;;
esac
in_ns nft list tables | grep -q ghostnector ||
    fail "the fail-closed baseline was not actually applied"
ok "the fail-closed baseline is in the kernel"

cli disconnect >/dev/null
ok "and the machine can still be released deliberately"

echo "PASS: core + cli"
