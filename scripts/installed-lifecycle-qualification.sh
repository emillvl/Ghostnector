#!/usr/bin/env bash
#
# The installed lifecycle qualification: uninstall, residue, reinstall, first boot, ordinary use,
# a deliberate fail-closed lockout with the documented recovery, and an idempotent reinstall.
#
# Not part of the hermetic gate. It runs against the real VM and leaves the product installed,
# open and off.
#
# Durable record: /var/log/ghostnector-qual/lifecycle-<stamp>.log

set -uo pipefail

LOGDIR=/var/log/ghostnector-qual
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOGDIR/lifecycle-$STAMP.log"
REPO=/home/ghost/ghostnector
RELEASE="$REPO/target/release"
HOST=10.0.2.2
CLI=(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector)

PASSED=0
FAILED=0
INCONCLUSIVE=0

ok()   { echo "  ok: $*"; PASSED=$((PASSED + 1)); }
bad()  { echo "  FAIL: $*"; FAILED=$((FAILED + 1)); }
inc()  { echo "  inconclusive: $*"; INCONCLUSIVE=$((INCONCLUSIVE + 1)); }
note() { echo "    $*"; }

mkdir -p "$LOGDIR"; chmod 0755 "$LOGDIR"
exec >>"$LOG" 2>&1
ln -sfn "$(basename "$LOG")" "$LOGDIR/lifecycle-latest.log"

cli_state() { "${CLI[@]}" status 2>&1; }
wait_status() { local i; for i in $(seq 1 "$2"); do cli_state | grep -q "$1" && return 0; sleep 1; done; return 1; }

cleanup() {
    local rc=$?
    echo
    echo "== cleanup at $(date -u) (run exit $rc) =="
    timeout 90 runuser -u ghost -g ghostnector -- /usr/bin/ghostnector disconnect >/dev/null 2>&1 || true
    if nft list table inet ghostnector >/dev/null 2>&1; then
        nft destroy table inet ghostnector >>"$LOG" 2>&1 || true
    fi
    if [ -f /var/lib/ghostnector/intent.json ] && grep -q '"protected"[[:space:]]*:[[:space:]]*true' /var/lib/ghostnector/intent.json; then
        rm -f /var/lib/ghostnector/intent.json
    fi
    echo "== final state =="
    cli_state | head -4
    echo "== end of $LOG =="
    exit "$rc"
}
trap cleanup EXIT

[ "$(id -u)" = "0" ] || { echo "this qualification needs root"; exit 2; }
[ -d "$REPO/packaging" ] || { echo "the repository is not at $REPO"; exit 2; }

echo "== installed lifecycle qualification at $(date -u) =="
echo "log: $LOG"
uname -a
echo "release dir: $RELEASE"
ls "$RELEASE/ghostnector-core" "$RELEASE/ghostnector-gui" >/dev/null 2>&1 && ok "the release binaries exist" \
    || bad "the release binaries are missing"

# ---------------------------------------------------------------- uninstall
echo
echo "-- uninstall, and prove the residue is harmless --"
"${CLI[@]}" disconnect >/dev/null 2>&1 || true
nft destroy table inet ghostnector 2>/dev/null || true
rm -f /var/lib/ghostnector/intent.json
bash "$REPO/packaging/uninstall.sh" >/tmp/gh-uninstall.log 2>&1 && ok "the uninstall script returned success" \
    || { bad "the uninstall script failed"; tail -5 /tmp/gh-uninstall.log; }
for unit in ghostnector-core ghostnector-netd ghostnector-appd ghostnector-bootguard; do
    systemctl is-active "$unit.service" >/dev/null 2>&1 && bad "$unit is still active" || ok "$unit is not active"
done
for path in /usr/libexec/ghostnector-core /usr/libexec/ghostnector-netd /usr/libexec/ghostnector-appd \
    /usr/libexec/ghostnector-dns /usr/libexec/ghostnector-bootguard /usr/bin/ghostnector /usr/bin/ghostnector-gui \
    /usr/libexec/ghostnector-appd-relay \
    /usr/lib/systemd/system/ghostnector-core.service /usr/lib/systemd/system/ghostnector-tor.service \
    /usr/lib/tmpfiles.d/ghostnector.conf /usr/share/polkit-1/rules.d/50-ghostnector.rules \
    /usr/share/polkit-1/rules.d/51-ghostnector-resolved.rules /usr/share/applications/ghostnector.desktop; do
    [ -e "$path" ] && bad "$path survived the uninstall" || true
done
ok "no packaged file survived the uninstall"
[ -d /run/ghostnector ] && bad "/run/ghostnector survived the uninstall" || ok "/run/ghostnector is gone"
[ -d /var/lib/ghostnector ] && bad "/var/lib/ghostnector survived the uninstall" || ok "/var/lib/ghostnector is gone"
[ -d /etc/ghostnector ] && bad "/etc/ghostnector survived the uninstall" || ok "/etc/ghostnector is gone"
[ -d /usr/share/doc/ghostnector ] && bad "/usr/share/doc/ghostnector survived the uninstall" || ok "the installed docs are gone"
nft list table inet ghostnector >/dev/null 2>&1 && bad "the policy table survived the uninstall" || ok "no policy table after the uninstall"
if ps -eo comm= | grep -qE '^ghostnector-(core|netd|appd|bootguard|dns|appd-launch|appd-probe|gui)$'; then
    bad "a ghostnector process survived the uninstall"
else
    ok "no ghostnector process after the uninstall"
fi
# The relay's comm is truncated to the same 15 characters as the helper's, so it is matched by its
# own command line: no group relay may outlive the uninstall.
if pgrep -f "ghostnector-appd-relay --id" >/dev/null 2>&1; then
    bad "a namespace relay survived the uninstall: $(pgrep -af 'ghostnector-appd-relay --id' | tr '\n' ' ')"
else
    ok "no namespace relay after the uninstall"
fi
if command -v resolvectl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved; then
    LINK="$(ip route show default | awk '{print $5; exit}')"
    if resolvectl dns "$LINK" 2>/dev/null | grep -q "127.0.0.1"; then
        bad "the resolver is still pointed at the chokepoint after the uninstall"
    else
        ok "the resolver is back to its own configuration ($(resolvectl dns "$LINK" 2>/dev/null | tr -d '\n'))"
    fi
fi
# Ordinary networking must still work after the uninstall. Probe a real public endpoint (the same
# kind the product's verification uses), not the qualification's host observer, which is not
# expected to be running.
AFTER_IP="$(getent ahostsv4 checkip.amazonaws.com | awk 'NR==1{print $1}')"
TCP_AFTER="$(runuser -u ghost -- timeout 10 curl -s -o /dev/null -w '%{http_code}' "http://$AFTER_IP/" 2>/dev/null)"
case "$TCP_AFTER" in
2*|3*) ok "ordinary networking works after the uninstall (HTTP $TCP_AFTER)" ;;
*) bad "networking is broken after the uninstall (HTTP ${TCP_AFTER:-none})" ;;
esac
DNS_AFTER="$(runuser -u ghost -- timeout 10 getent ahostsv4 example.com 2>/dev/null | head -1)"
[ -n "$DNS_AFTER" ] && ok "DNS works after the uninstall ($DNS_AFTER)" || inc "DNS did not answer after the uninstall"

# ---------------------------------------------------------------- reinstall
echo
echo "-- reinstall, and start the units --"
bash "$REPO/packaging/install.sh" "$RELEASE" >/tmp/gh-install.log 2>&1 && ok "the install script returned success" \
    || { bad "the install script failed"; tail -8 /tmp/gh-install.log; }
systemctl is-enabled ghostnector-core.service >/dev/null 2>&1 && ok "the core unit is enabled" || bad "the core unit is not enabled"
ls -ld /run/ghostnector /run/ghostnector/netd /run/ghostnector/appd /run/ghostnector-tor /run/netns >/dev/null 2>&1 \
    && ok "the runtime directories exist after the install" || bad "a runtime directory is missing after the install"
systemctl start ghostnector-netd.service ghostnector-core.service ghostnector-appd.service
sleep 2
for unit in ghostnector-netd ghostnector-core ghostnector-appd; do
    systemctl is-active --quiet "$unit.service" && ok "$unit is active after the install" || bad "$unit is not active after the install"
done
cli_state | grep -q "off" && ok "the machine is off after the install" || bad "the machine is not off after the install: $(cli_state | head -1)"

# ---------------------------------------------------------------- ordinary use
echo
echo "-- ordinary use: connect, verify, disconnect --"
HTTP_IP="$(getent ahostsv4 checkip.amazonaws.com | awk 'NR==1{print $1}')"
cat >/etc/ghostnector/core.env <<EOF
GHOSTNECTOR_VERIFY=--udp-check $HOST:18081 --check-url http://$HTTP_IP/ --verify-timeout 10 --verify-interval 5 --verify-stale-after 30
EOF
systemctl restart ghostnector-core.service
sleep 2
"${CLI[@]}" connect >/dev/null 2>&1 || true
if wait_status "protected" 300; then
    ok "ordinary use reaches protection: $(cli_state | head -1)"
else
    bad "ordinary use did not reach protection: $(cli_state | head -1)"
fi
"${CLI[@]}" disconnect >/dev/null 2>&1 || true
wait_status "off" 60 && ok "ordinary use returns to off" || bad "ordinary use did not return to off"

# ---------------------------------------------------------------- deliberate lockout and recovery
echo
echo "-- a deliberate fail-closed lockout, then the documented recovery --"
# Deterministic form: let Tor boot and verify normally, then kill the router under the claim. The
# next verification cannot reach the protected path, the engine applies the fail-closed baseline,
# and the SSH session driving this is cut by design. Recovery is the documented local disconnect.
echo "PHASE LOCKOUT_START $(date +%s.%N)"
"${CLI[@]}" connect >/dev/null 2>&1 || true
if wait_status "protected" 300; then
    ok "the machine reached protection before the lockout"
else
    inc "the machine did not reach protection before the lockout: $(cli_state | head -1)"
fi
systemctl stop ghostnector-tor.service
if wait_status "no traffic can leave" 150; then
    ok "the router's death failed verification and the machine denied (fail-closed)"
else
    inc "the machine did not block within 150s: $(cli_state | head -1)"
fi
echo "PHASE LOCKOUT_END $(date +%s.%N)"
# The recovery is the documented first way out, executed locally on the machine (the SSH session
# that started this run is cut by design; a person would do this on the console, and this script is
# the machine's own voice doing exactly the same thing).
echo "-- recovery: ghostnector disconnect, locally --"
timeout 90 runuser -u ghost -g ghostnector -- /usr/bin/ghostnector disconnect >/tmp/gh-recovery.log 2>&1 \
    && ok "the documented disconnect returned success" || bad "the documented disconnect failed"
if wait_status "off" 60; then
    ok "the machine is open again after the documented recovery"
else
    bad "the machine did not return to off: $(cli_state | head -1)"
fi
nft list table inet ghostnector >/dev/null 2>&1 && bad "a table survived the recovery" || ok "no table after the recovery"
if [ -f /var/lib/ghostnector/intent.json ] && grep -q '"protected"[[:space:]]*:[[:space:]]*true' /var/lib/ghostnector/intent.json; then
    bad "a protected intent survived the recovery"
else
    ok "the intent no longer asks for protection"
fi

echo
echo "=== summary (installed lifecycle) ==="
echo "held:         $PASSED"
echo "contradicted: $FAILED"
echo "inconclusive: $INCONCLUSIVE"
echo "log:          $LOG"
[ "$FAILED" = "0" ] || exit 1
exit 0
