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

echo "PASS: boot guard"
