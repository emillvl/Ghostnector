#!/usr/bin/env bash
#
# The installed-stack qualification run (native Ubuntu, real Tor, the packaged units).
#
# This is not part of the hermetic gate. It exercises exactly what `packaging/install.sh`
# installs: the systemd units, the bounded polkit rule (D-30), the split runtime directories
# (D-29) and Tor's cookie directory (D-31). It is the run that turns "the source tree works"
# into "the installed product works".
#
# It is written to survive the one behaviour that is supposed to cut the operator off:
# SYSTEM-scope protection applies the deny-first baseline immediately, which drops every
# reply of the SSH session that started it (D-32b). Therefore:
#
#   * it is meant to be started detached (systemd-run, see the qualification notes), never as
#     the foreground command of an SSH session that is expected to survive;
#   * its output goes to a durable file under /var/log/ghostnector-qual (never /tmp, which is a
#     tmpfs on Ubuntu 24.04 and loses evidence across a reboot);
#   * a trap on EXIT always ends in `ghostnector disconnect`, and if that cannot restore the
#     machine it falls back to the two documented rescue steps (`nft destroy table inet
#     ghostnector`, remove the intent journal) before exiting;
#   * every phase is bounded by `timeout`.
#
# Usage: installed-qualification.sh [verified-wait-seconds]
#
# Environment overrides (qualification-only):
#   GHOSTNECTOR_QUAL_LOG_DIR   where logs are written   [default /var/log/ghostnector-qual]
#   GHOSTNECTOR_QUAL_UDP       the UDP check endpoint   [default 10.0.2.2:18081]
#   GHOSTNECTOR_QUAL_HTTP_HOST the host whose resolved IPv4 is the HTTP check [checkip.amazonaws.com]
#
# The HTTP check must be an IP literal (the verifier takes a SocketAddr) and must be reachable
# from a real Tor exit; a NAT-private address is refused by Tor itself, correctly (D-32a). The
# UDP check expects *no answer* (any answer is a leak), so the NAT gateway address is fine
# there; `connect --lan` is refused with it, which is the D-26 refusal, not a defect.

set -uo pipefail

WAIT_SECONDS="${1:-240}"
LOGDIR="${GHOSTNECTOR_QUAL_LOG_DIR:-/var/log/ghostnector-qual}"
UDP_CHECK="${GHOSTNECTOR_QUAL_UDP:-10.0.2.2:18081}"
HTTP_HOST="${GHOSTNECTOR_QUAL_HTTP_HOST:-checkip.amazonaws.com}"
CLI="/usr/bin/ghostnector"
CORE_ENV="/etc/ghostnector/core.env"
INTENT="/var/lib/ghostnector/intent.json"
TABLE="inet ghostnector"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$LOGDIR"
chmod 0755 "$LOGDIR"
LOG="$LOGDIR/$STAMP.log"
ln -sfn "$STAMP.log" "$LOGDIR/latest.log"

# Everything below is the record; the journal additionally keeps the unit's stdout when this is
# started with systemd-run.
exec >>"$LOG" 2>&1

PASSED=0
FAILED=0
INCONCLUSIVE=0

ok()   { echo "  ok: $*"; PASSED=$((PASSED + 1)); }
bad()  { echo "  FAIL: $*"; FAILED=$((FAILED + 1)); }
inc()  { echo "  inconclusive: $*"; INCONCLUSIVE=$((INCONCLUSIVE + 1)); }
note() { echo "    $*"; }

as_cli_user() {
    runuser -u ghost -g ghostnector -- timeout "${CLI_TIMEOUT:-60}" "$CLI" "$@"
}

status_text() {
    as_cli_user status 2>&1
}

state_line() {
    status_text | head -1
}

cleanup() {
    local rc=$?
    echo
    echo "== cleanup at $(date -u) (run exit $rc) =="
    # 1. Ask Ghostnector to stand down (documented way out #1). This is local and needs no
    #    network, so it works even while every packet is denied.
    timeout 90 runuser -u ghost -g ghostnector -- "$CLI" disconnect >>"$LOG" 2>&1 \
        && echo "disconnect: returned success" \
        || echo "disconnect: failed or timed out; falling back to the documented rescue"
    # 2. If the owned table survived, destroy it (documented way out #3, first line).
    if nft list table $TABLE >/dev/null 2>&1; then
        echo "policy still present; destroying $TABLE (documented rescue)"
        nft destroy table $TABLE >>"$LOG" 2>&1 || true
    fi
    # 3. If the journal still says protection is wanted, forget it (documented way out #3,
    #    second line). This is a qualification machine; leaving a Blocked intent behind would
    #    lock the next boot and every later test.
    if [ -f "$INTENT" ] && grep -q '"protected"[[:space:]]*:[[:space:]]*true' "$INTENT"; then
        echo "clearing the intent journal (documented rescue)"
        rm -f "$INTENT"
    fi
    systemctl stop ghostnector-tor.service >>"$LOG" 2>&1 || true
    echo "== final state =="
    status_text | head -6
    echo "== end of $LOG =="
    exit "$rc"
}
trap cleanup EXIT

echo "== installed-stack qualification at $(date -u) =="
echo "log: $LOG"
uname -a
nft --version
tor --version | head -1
echo "core binary: $(stat -c '%y %s bytes' /usr/libexec/ghostnector-core)"
echo "core unit:"
systemctl cat ghostnector-core.service | sed -n '1,40p'

[ "$(id -u)" = "0" ] || { bad "this qualification needs root"; exit 2; }

# ---------------------------------------------------------------- a clean, open baseline
echo
echo "-- baseline: the machine starts open, with no stale intent --"
timeout 60 runuser -u ghost -g ghostnector -- "$CLI" disconnect >/dev/null 2>&1 || true
nft destroy table $TABLE 2>/dev/null || true
rm -f "$INTENT"
systemctl restart ghostnector-netd.service
systemctl restart ghostnector-core.service
sleep 2
BASE="$(state_line)"
case "$BASE" in
*"off"*) ok "the baseline is open ($BASE)" ;;
*) bad "the baseline is not open: $BASE" ;;
esac
nft list table $TABLE >/dev/null 2>&1 &&
    bad "a policy table survived the baseline reset" ||
    ok "no policy table is applied at the baseline"

# ---------------------------------------------------------------- the units as systemd reads them
echo
echo "-- systemd's own opinion of the packaged units (D-35/D-36) --"
for unit in ghostnector-netd ghostnector-core ghostnector-appd ghostnector-bootguard \
    ghostnector-tor ghostnector-i2pd; do
    OUT="$(systemd-analyze verify "/usr/lib/systemd/system/$unit.service" 2>&1)"
    if [ -z "$OUT" ]; then
        ok "$unit verifies clean"
    else
        bad "$unit is not clean: $OUT"
    fi
done

# ---------------------------------------------------------------- D-29: runtime directories
echo
echo "-- D-29: both daemons' sockets live where the units say --"
for spec in "/run/ghostnector/core.sock ghostnector" "/run/ghostnector/netd/netd.sock ghostnector"; do
    set -- $spec
    if [ -S "$1" ]; then
        OWNER="$(stat -c %U "$1")"
        [ "$OWNER" = "$2" ] &&
            ok "$1 exists and is owned by $2 ($(stat -c %a "$1"))" ||
            bad "$1 is owned by $OWNER, expected $2"
    else
        bad "$1 does not exist"
    fi
done
case "$(status_text)" in
*"cannot be trusted"*|*"could not be asked"*)
    bad "the control plane cannot trust or reach the helper socket" ;;
*) ok "the control plane reaches the helper" ;;
esac

# ---------------------------------------------------------------- D-30: the polkit bound
echo
echo "-- D-30: only the two router units, only start/stop, only the service account --"
runuser -u ghostnector -- systemctl stop ghostnector-tor.service >/dev/null 2>&1
if runuser -u ghostnector -- systemctl start --no-block ghostnector-tor.service >/dev/null 2>&1; then
    ok "the control-plane account may start ghostnector-tor.service"
    runuser -u ghostnector -- systemctl stop ghostnector-tor.service >/dev/null 2>&1
else
    bad "the control-plane account was denied starting ghostnector-tor.service"
fi
if runuser -u ghostnector -- systemctl start --no-block cron.service >/dev/null 2>&1; then
    bad "the control-plane account may start cron.service (the rule is too wide)"
    runuser -u ghostnector -- systemctl stop cron.service >/dev/null 2>&1
else
    ok "the control-plane account is denied starting cron.service"
fi
if runuser -u ghostnector -- systemctl restart --no-block ghostnector-tor.service >/dev/null 2>&1; then
    bad "the control-plane account may restart ghostnector-tor.service (restart is not bounded in)"
else
    ok "the control-plane account is denied restarting ghostnector-tor.service"
fi
if runuser -u ghost -- systemctl start --no-block ghostnector-tor.service >/dev/null 2>&1; then
    bad "an ordinary user may start ghostnector-tor.service (the rule is too wide)"
else
    ok "an ordinary user is denied starting ghostnector-tor.service"
fi

# ---------------------------------------------------------------- the verification configuration
echo
echo "-- the verification endpoints (public HTTP, or Tor refuses it correctly) --"
HTTP_IP="$(getent ahostsv4 "$HTTP_HOST" | awk 'NR==1{print $1}')"
if [ -n "$HTTP_IP" ]; then
    ok "$HTTP_HOST resolves to $HTTP_IP"
else
    bad "$HTTP_HOST did not resolve; the HTTP check cannot be configured"
fi
cat >"$CORE_ENV" <<EOF
# Written by scripts/installed-qualification.sh at $STAMP.
GHOSTNECTOR_VERIFY=--udp-check $UDP_CHECK --check-url http://$HTTP_IP/ --verify-timeout 10
EOF
cat "$CORE_ENV"
systemctl restart ghostnector-core.service
sleep 2
case "$(status_text)" in
*"off"*) ok "the control plane restarted open, with the check configuration in place" ;;
*) bad "the control plane did not restart open: $(state_line)" ;;
esac

# ---------------------------------------------------------------- the connect
echo
echo "-- connect (Tor SYSTEM), bounded --"
CONNECT_START="$(date -u +%s)"
timeout 300 runuser -u ghost -g ghostnector -- "$CLI" connect
CONNECT_RC=$?
CONNECT_END="$(date -u +%s)"
echo "connect rc=$CONNECT_RC after $((CONNECT_END - CONNECT_START))s at $(date -u)"
[ "$CONNECT_RC" = "0" ] &&
    ok "connect returned within its 300s bound" ||
    bad "connect did not return success (rc=$CONNECT_RC)"

echo "-- waiting up to ${WAIT_SECONDS}s for a verified or blocked state --"
OUTCOME=""
for _ in $(seq 1 "$WAIT_SECONDS"); do
    LINE="$(state_line)"
    case "$LINE" in
    *"and verified"*) OUTCOME="verified"; break ;;
    *"no traffic can leave"*) OUTCOME="blocked"; break ;;
    esac
    sleep 1
done
echo "== state =="
status_text
case "$OUTCOME" in
verified) ok "the installed stack reached protected-and-verified through real Tor" ;;
blocked)  bad "the installed stack failed closed instead of verifying" ;;
*)        inc "the state did not settle within ${WAIT_SECONDS}s: $(state_line)" ;;
esac

# ---------------------------------------------------------------- the evidence
echo
echo "-- the kernel's own policy (first lines) --"
nft list table $TABLE 2>&1 | head -25
echo
echo "-- D-31: Tor's control cookie where the control plane reads it --"
ls -la /run/ghostnector-tor/ 2>&1
if [ -f "/run/ghostnector-tor/control.cookie" ]; then
    COOKIE_OWNER="$(stat -c '%U:%G %a' /run/ghostnector-tor/control.cookie)"
    case "$COOKIE_OWNER" in
    debian-tor:ghostnector*) ok "the cookie is debian-tor-owned and group-readable ($COOKIE_OWNER)" ;;
    *) bad "the cookie has unexpected ownership/mode: $COOKIE_OWNER" ;;
    esac
else
    bad "Tor did not write a control cookie"
fi
echo
echo "-- D-37/D-38: the resolver can be repointed (needs /proc/net/route and resolvectl authorization) --"
if status_text | grep -qE "proc/net/route|resolvectl.*refused"; then
    bad "the control plane could not repoint the resolver: $(status_text | grep 'not repointed' | head -1)"
else
    ok "no resolver-repointing failure is reported"
fi
if systemctl is-active --quiet systemd-resolved; then
    LINK="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
    if [ -n "$LINK" ] && resolvectl dns "$LINK" 2>/dev/null | grep -q "127.0.0.1"; then
        ok "systemd-resolved sends queries to the chokepoint ($(resolvectl dns "$LINK" 2>/dev/null | tr -d '\n'))"
    else
        bad "systemd-resolved does not show the chokepoint as its DNS server"
    fi
fi
echo
echo "-- managed Tor --"
systemctl is-active ghostnector-tor.service
journalctl -u ghostnector-tor.service --no-pager -n 12 2>&1 | tail -8
echo
echo "-- a final look at the daemons --"
systemctl is-active ghostnector-core ghostnector-netd ghostnector-appd ghostnector-bootguard

# ---------------------------------------------------------------- stand down
echo
echo "-- disconnect (the trap repeats this if anything above failed) --"
timeout 120 runuser -u ghost -g ghostnector -- "$CLI" disconnect
echo "disconnect rc=$? at $(date -u)"
sleep 1
echo "== after disconnect =="
status_text | head -4

echo
echo "=== summary (installed stack, real Tor) ==="
echo "held:         $PASSED"
echo "contradicted: $FAILED"
echo "inconclusive: $INCONCLUSIVE"
echo "log:          $LOG"
[ "$FAILED" = "0" ] || exit 1
exit 0
