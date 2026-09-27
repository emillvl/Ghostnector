#!/usr/bin/env bash
#
# Exercises the boot guard: the thing that closes the window between "the machine started" and
# "the control plane is running".
#
# It runs in a throwaway network namespace, so nothing here touches the host's firewall.
#
# What it proves:
#   1. with no journal, nothing is applied — a machine that was not protected stays open
#   2. with a journal that asks for protection, everything is denied before anything else happens
#   3. when the helper cannot be reached, the helper's own copy of the policy is applied instead
#   4. the documented kernel-command-line escape really does leave the machine open
#   5. a journal that cannot be read is treated as a request for protection
#
# Requires: root, iproute2, nftables.

set -euo pipefail

TARGET_DIR="${1:?usage: bootguard-test.sh <target/debug directory>}"
NS="gh-bootguard-test"
RUNDIR="/run/ghostnector"
BINDIR="/tmp/gh-bg-bin"
WORKDIR="/tmp/gh-bg-test"
PEER_USER="ghostnector-bg"
NETD_PID=""

cleanup() {
    [ -n "$NETD_PID" ] && kill "$NETD_PID" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    ip netns exec "$NS" nft destroy table inet ghostnector 2>/dev/null || true
    rm -rf "$BINDIR" "$WORKDIR" "$RUNDIR"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok: $*"; }

[ "$(id -u)" = "0" ] || fail "this test needs root"

id -u "$PEER_USER" >/dev/null 2>&1 || \
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$PEER_USER"
PEER_UID="$(id -u "$PEER_USER")"
PEER_GID="$(id -g "$PEER_USER")"

mkdir -p "$BINDIR" "$WORKDIR" "$RUNDIR"
install -m 0755 "$TARGET_DIR/ghostnector-netd" "$BINDIR/ghostnector-netd"
install -m 0755 "$TARGET_DIR/ghostnector-bootguard" "$BINDIR/ghostnector-bootguard"
chmod 0755 "$RUNDIR"

JOURNAL="$WORKDIR/intent.json"
FALLBACK="$WORKDIR/fail-closed.nft"
CMDLINE="$WORKDIR/cmdline"
: >"$CMDLINE"

ip netns add "$NS"
in_ns() { ip netns exec "$NS" "$@"; }
guard() {
    in_ns "$BINDIR/ghostnector-bootguard" \
        --netd "$RUNDIR/netd.sock" \
        --intent "$JOURNAL" \
        --fallback "$FALLBACK" \
        --cmdline "$CMDLINE" \
        "$@"
}
# The installed model: the guard runs as the control plane's user with NET_ADMIN and nothing else.
guard_as_peer() {
    in_ns setpriv --reuid="$PEER_UID" --regid="$PEER_GID" --clear-groups \
        --bounding-set=-all,+net_admin --inh-caps +net_admin --ambient-caps +net_admin \
        "$BINDIR/ghostnector-bootguard" \
        --netd "$RUNDIR/netd.sock" \
        --intent "$JOURNAL" \
        --fallback "$FALLBACK" \
        --cmdline "$CMDLINE" \
        "$@"
}
tables() { in_ns nft list tables 2>/dev/null || true; }
denied() { tables | grep -q ghostnector; }
clear_policy() { in_ns nft destroy table inet ghostnector 2>/dev/null || true; }

# ---------------------------------------------------------------- 1. nothing was requested
rm -f "$JOURNAL"
OUT="$(guard 2>&1)" || fail "the guard failed with no journal: $OUT"
case "$OUT" in
*"not requested"*) ok "with no journal, nothing is applied" ;;
*) fail "unexpected output with no journal: $OUT" ;;
esac
denied && fail "a policy was applied although nothing was requested"
ok "the machine is still open"

# ---------------------------------------------------------------- 2. protection was requested
cat >"$JOURNAL" <<'JSON'
{"version": 1, "protected": true, "profile": "tor_system", "generation": 3}
JSON

in_ns "$BINDIR/ghostnector-netd" --socket "$RUNDIR/netd.sock" --peer-user "$PEER_USER" \
    --fallback-path "$FALLBACK" >/tmp/gh-bg-netd.log 2>&1 &
NETD_PID=$!
for _ in $(seq 1 50); do [ -S "$RUNDIR/netd.sock" ] && break; sleep 0.1; done
[ -S "$RUNDIR/netd.sock" ] || fail "the helper did not start"

OUT="$(guard 2>&1)" || fail "the guard failed with protection requested: $OUT"
case "$OUT" in
*"denied everything"*) ok "the guard asked the helper, and the helper denied everything" ;;
*) fail "unexpected output with protection requested: $OUT" ;;
esac
denied || fail "nothing was applied although protection was requested"
ok "the kernel really has the policy"
[ -f "$FALLBACK" ] || fail "the helper did not leave a copy of the policy for the boot guard"
ok "the helper left a copy of the policy behind"

# ---------------------------------------------------------------- 3. the helper is unreachable
kill "$NETD_PID" 2>/dev/null || true
wait "$NETD_PID" 2>/dev/null || true
NETD_PID=""
rm -f "$RUNDIR/netd.sock"
clear_policy

OUT="$(guard --wait-seconds 0 2>&1)" || fail "the guard failed to fall back: $OUT"
case "$OUT" in
*"copy of the fail-closed policy was applied"*) ok "with no helper, its own copy was applied" ;;
*) fail "unexpected output when falling back: $OUT" ;;
esac
denied || fail "the fallback did not deny anything"
ok "the kernel has the fail-closed policy again"

# ---------------------------------------------------------------- 4. the documented escape
echo "quiet ghostnector.unprotected=1 splash" >"$CMDLINE"
clear_policy
OUT="$(guard 2>&1)" || fail "the guard failed with the escape set: $OUT"
case "$OUT" in
*"kernel command line"*) ok "the escape was honoured" ;;
*) fail "unexpected output with the escape set: $OUT" ;;
esac
denied && fail "the escape did not leave the machine open"
ok "an operator can still get their machine back at the console"

# ---------------------------------------------------------------- 5. an unreadable journal
: >"$CMDLINE"
echo "{ this is not json" >"$JOURNAL"
OUT="$(guard --wait-seconds 0 2>&1)" || fail "the guard failed on a corrupt journal: $OUT"
case "$OUT" in
*"assuming protection was requested"*) ok "a corrupt journal is treated as a request" ;;
*) fail "unexpected output on a corrupt journal: $OUT" ;;
esac
denied || fail "a corrupt journal left the machine open"
ok "the machine denies rather than guessing"

# ---------------------------------------------------------------- 6. the installed identity model
# D-54: the unit runs the guard as the control plane's own user with NET_ADMIN and nothing else;
# netd hands its socket and the fail-closed copy to that user, so no capability that bypasses file
# permissions is needed. This section reproduces that model exactly.
echo "the installed identity model:"
echo '{"version": 1, "protected": true, "profile": "tor_system", "generation": 3}' >"$JOURNAL"
clear_policy

# The copy left by the last apply is already owned by the guard's user; the helper's socket is
# checked after it starts again (section 3 removed it).
[ "$(stat -c %U "$FALLBACK")" = "$PEER_USER" ] ||
    fail "the copy is not owned by the guard's user"
[ "$(stat -c %a "$FALLBACK")" = "600" ] || fail "the copy is not owner-only"

# With the helper up, the guard as that user reaches it and the helper denies everything.
in_ns "$BINDIR/ghostnector-netd" --socket "$RUNDIR/netd.sock" --peer-user "$PEER_USER" \
    --fallback-path "$FALLBACK" >/tmp/gh-bg-netd2.log 2>&1 &
NETD_PID=$!
for _ in $(seq 1 50); do [ -S "$RUNDIR/netd.sock" ] && break; sleep 0.1; done
[ -S "$RUNDIR/netd.sock" ] || fail "the helper did not start for the identity-model case"
[ "$(stat -c %U "$RUNDIR/netd.sock")" = "$PEER_USER" ] ||
    fail "the socket is not owned by the guard's user"

# A different unprivileged user must read neither the copy nor the socket.
if setpriv --reuid=65534 --regid=65534 --clear-groups /bin/cat "$FALLBACK" >/dev/null 2>&1; then
    fail "an unrelated user could read the fail-closed copy"
fi
if setpriv --reuid=65534 --regid=65534 --clear-groups python3 -c 'import socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect(sys.argv[1])
except OSError:
    sys.exit(1)
sys.exit(0)' "$RUNDIR/netd.sock" >/dev/null 2>&1; then
    fail "an unrelated user could connect to the helper's socket"
fi
ok "the copy and the socket are owner-only for the guard's user"

OUT="$(guard_as_peer 2>&1)" ||
    fail "the guard as the control-plane user failed with the helper up: $OUT"
case "$OUT" in
*"denied everything"*) ok "as the control-plane user, the guard reached the helper and it denied" ;;
*) fail "unexpected output as the control-plane user: $OUT" ;;
esac
denied || fail "nothing was applied in the identity-model case"

# With the helper gone, the same identity applies the copy itself.
kill "$NETD_PID" 2>/dev/null || true
wait "$NETD_PID" 2>/dev/null || true
NETD_PID=""
rm -f "$RUNDIR/netd.sock"
clear_policy
OUT="$(guard_as_peer --wait-seconds 0 2>&1)" ||
    fail "the guard as the control-plane user failed to fall back: $OUT"
case "$OUT" in
*"copy of the fail-closed policy was applied"*)
    ok "as the control-plane user, the guard applied its own copy" ;;
*) fail "unexpected output falling back as the control-plane user: $OUT" ;;
esac
denied || fail "the fallback did not deny as the control-plane user"

# A missing copy fails safely: the guard reports it and applies nothing.
rm -f "$FALLBACK"
clear_policy
if OUT="$(guard_as_peer --wait-seconds 0 2>&1)"; then
    fail "the guard claimed success with no copy: $OUT"
fi
case "$OUT" in
*"no copy of the fail-closed policy"*) ok "a missing copy is reported, and nothing is applied" ;;
*) fail "unexpected output with a missing copy: $OUT" ;;
esac
denied && fail "a missing copy still applied something"

# A corrupt copy fails safely: nft refuses it atomically, so no partial policy lands.
printf 'this is not a ruleset\n' >"$FALLBACK"
chown "$PEER_USER" "$FALLBACK"
chmod 0600 "$FALLBACK"
if OUT="$(guard_as_peer --wait-seconds 0 2>&1)"; then
    fail "the guard claimed success with a corrupt copy: $OUT"
fi
denied && fail "a corrupt copy left a partial policy behind"
ok "a corrupt copy is refused atomically, with nothing applied"

echo "PASS: boot guard"
