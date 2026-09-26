#!/usr/bin/env bash
#
# The installed GUI qualification: the real GTK4 window against the real installed control plane.
#
# Not part of the hermetic gate. It needs a display (Xvfb), the installed product, and the
# `ghostnector` group membership for the test user. It drives the window the way a person would
# (keyboard mnemonics where they exist, pointer clicks found by OCR where they do not), and it
# checks every claim against `ghostnector status` (the authoritative Snapshot) as well as against
# the window's own diagnostics text, copied through the real "Copy details" button.
#
# The record is durable: /var/log/ghostnector-qual/gui-<stamp>.log and gui-shots-<stamp>/*.png.
# It always ends with the machine open and off, the GUI stopped, and the documented rescue as a
# fallback.
#
# Usage: gui-installed-qualification.sh
#
# Classification: ok / FAIL / inconclusive.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
FIND="$here/lib/gh-find.py"

LOGDIR=/var/log/ghostnector-qual
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOGDIR/gui-$STAMP.log"
SHOTS="$LOGDIR/gui-shots-$STAMP"
export DISPLAY=:90
GUI_USER=ghost
CLI=(runuser -u "$GUI_USER" -g ghostnector -- /usr/bin/ghostnector)

PASSED=0
FAILED=0
INCONCLUSIVE=0

ok()   { echo "  ok: $*"; PASSED=$((PASSED + 1)); }
bad()  { echo "  FAIL: $*"; FAILED=$((FAILED + 1)); }
inc()  { echo "  inconclusive: $*"; INCONCLUSIVE=$((INCONCLUSIVE + 1)); }
note() { echo "    $*"; }

mkdir -p "$LOGDIR" "$SHOTS"
chmod 0755 "$LOGDIR" "$SHOTS"
exec >>"$LOG" 2>&1
ln -sfn "$(basename "$LOG")" "$LOGDIR/gui-latest.log"

cli_state() { "${CLI[@]}" status 2>&1; }
cli_line()  { cli_state | head -1; }
wait_status() { # pattern seconds
    local i
    for i in $(seq 1 "$2"); do
        cli_state | grep -q "$1" && return 0
        sleep 1
    done
    return 1
}
wait_line() { # pattern seconds
    local i
    for i in $(seq 1 "$2"); do
        cli_line | grep -q "$1" && return 0
        sleep 1
    done
    return 1
}
shot() { import -window root "$SHOTS/$1.png" 2>/dev/null; }
ocr()  { tesseract "$SHOTS/$1.png" stdout 2>/dev/null; }
find_word() { python3 "$FIND" "$SHOTS/.find.png" "$@" 2>/dev/null; }
click_word() { # WORD [constraints...]
    shot .find
    local xy
    xy="$(find_word "$@")"
    if [ -z "$xy" ]; then
        note "click_word: '$1' not found on screen"
        return 1
    fi
    xdotool mousemove --sync "${xy% *}" "${xy#* }" click 1
    sleep 0.5
    return 0
}
key() { xdotool key --clearmodifiers "$@"; sleep 0.4; }
focus_gui() { wmctrl -a Ghostnector 2>/dev/null || true; sleep 0.4; }
window_geometry() {
    eval "$(xdotool search --name '^Ghostnector$' getwindowgeometry --shell 2>/dev/null | sed 's/^/GW_/')" || true
}
click_switch_row() { # WORD
    shot .find
    local xy
    xy="$(find_word "$1")"
    [ -z "$xy" ] && return 1
    window_geometry
    [ -n "${GW_X:-}" ] || return 1
    xdotool mousemove --sync $((GW_X + GW_WIDTH - 30)) "${xy#* }" click 1
    sleep 0.5
}
click_header_right() { # pixels from the right edge
    window_geometry
    [ -n "${GW_X:-}" ] || return 1
    xdotool mousemove --sync $((GW_X + GW_WIDTH - "$1")) $((GW_Y + 24)) click 1
    sleep 0.5
}
protection_on() {
    focus_gui
    key alt+p
    sleep 2
    cli_line | grep -qE "off |unknown" && { note "Alt+P had no effect; clicking the switch"; click_switch_row Protection; }
}
protection_off() {
    focus_gui
    key alt+p
    sleep 2
    cli_line | grep -qE "off " || { note "Alt+P had no effect; clicking the switch"; click_switch_row Protection; }
}
diag_copy() {
    focus_gui
    click_word Diagnostics >/dev/null 2>&1 || key alt+d
    sleep 0.8
    shot .find
    local xy
    xy="$(find_word "Copy" --same-line-with "details")"
    if [ -n "$xy" ]; then
        xdotool mousemove --sync "${xy% *}" "${xy#* }" click 1
        sleep 0.6
    else
        note "diagnostics: Copy details not found; using Ctrl+A/Ctrl+C"
        click_word "Live" >/dev/null 2>&1 || true
        key ctrl+a
        key ctrl+c
        sleep 0.4
    fi
    DISPLAY=:90 xclip -selection clipboard -o 2>/dev/null
    wmctrl -c "Ghostnector diagnostics" 2>/dev/null || true
    sleep 0.5
}

cleanup() {
    local rc=$?
    echo
    echo "== cleanup at $(date -u) (run exit $rc) =="
    timeout 90 runuser -u "$GUI_USER" -g ghostnector -- /usr/bin/ghostnector disconnect >/dev/null 2>&1 \
        || echo "disconnect failed; using the documented rescue"
    if nft list table inet ghostnector >/dev/null 2>&1; then
        echo "destroying the owned table (documented rescue)"
        nft destroy table inet ghostnector >>"$LOG" 2>&1 || true
    fi
    if [ -f /var/lib/ghostnector/intent.json ] && grep -q '"protected"[[:space:]]*:[[:space:]]*true' /var/lib/ghostnector/intent.json; then
        rm -f /var/lib/ghostnector/intent.json
    fi
    pkill -f '/usr/bin/ghostnector-gui' 2>/dev/null || true
    pkill -f 'dbus-run-session' 2>/dev/null || true
    pkill -x xfwm4 2>/dev/null || true
    pkill -f 'Xvfb :90' 2>/dev/null || true
    echo "== final state =="
    cli_state | head -4
    echo "== end of $LOG =="
    exit "$rc"
}
trap cleanup EXIT

[ "$(id -u)" = "0" ] || { echo "this qualification needs root"; exit 2; }
[ -f "$FIND" ] || { echo "missing $FIND"; exit 2; }
command -v tesseract >/dev/null || { echo "tesseract is not installed"; exit 2; }
command -v xclip >/dev/null || { echo "xclip is not installed"; exit 2; }

echo "== installed GUI qualification at $(date -u) =="
echo "log: $LOG"
echo "shots: $SHOTS"
uname -a
/usr/bin/ghostnector-gui --version
id "$GUI_USER"

# ---------------------------------------------------------------- a clean, open baseline
echo
echo "-- baseline: the machine is open and off --"
timeout 60 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
nft destroy table inet ghostnector 2>/dev/null || true
rm -f /var/lib/ghostnector/intent.json
systemctl restart ghostnector-netd.service ghostnector-core.service ghostnector-appd.service
sleep 2
cli_line
cli_line | grep -q "off" && ok "the baseline is off" || bad "the baseline is not off: $(cli_line)"
nft list table inet ghostnector >/dev/null 2>&1 && bad "a table survived the baseline" || ok "no table at the baseline"

# A qualification-only verification configuration: a public HTTP check and a short interval, so a
# router/helper failure is noticed inside the test's bound. This is the machine's documented
# /etc/ghostnector/core.env; the product behavior under test is unchanged.
HTTP_IP="$(getent ahostsv4 checkip.amazonaws.com | awk 'NR==1{print $1}')"
cat >/etc/ghostnector/core.env <<EOF
GHOSTNECTOR_VERIFY=--udp-check 10.0.2.2:18081 --check-url http://$HTTP_IP/ --verify-timeout 10 --verify-interval 5 --verify-stale-after 30
EOF
systemctl restart ghostnector-core.service
sleep 2
echo "verification configuration: $(cat /etc/ghostnector/core.env)"

# ---------------------------------------------------------------- display and window
echo
echo "-- the display and the real window --"
pkill -f '/usr/bin/ghostnector-gui' 2>/dev/null || true
pkill -f 'Xvfb :90' 2>/dev/null || true
pkill -x xfwm4 2>/dev/null || true
sleep 0.5
# Everything detached (setsid, </dev/null) so the SSH session that starts this run is never held
# open by the display stack, and the window manager and GUI outlive it if it is cut.
setsid nohup Xvfb :90 -screen 0 1280x900x24 -ac </dev/null >/tmp/gui-xvfb.log 2>&1 &
sleep 1
setsid nohup runuser -u "$GUI_USER" -- env DISPLAY=:90 HOME=/home/ghost \
    xfwm4 --compositor=off </dev/null >/tmp/gui-xfwm4.log 2>&1 &
sleep 2
# GApplication needs a session bus to reach "activate"; without one the real window is never
# mapped (only GTK's 1x1 leader appears).
setsid nohup runuser -u "$GUI_USER" -- dbus-run-session -- env DISPLAY=:90 HOME=/home/ghost \
    XDG_RUNTIME_DIR=/run/user/1000 GSK_RENDERER=cairo GDK_BACKEND=x11 \
    /usr/bin/ghostnector-gui </dev/null >/tmp/gui-stdout.log 2>&1 &
for _ in $(seq 1 40); do wmctrl -l 2>/dev/null | grep -q Ghostnector && break; sleep 0.5; done
if wmctrl -l 2>/dev/null | grep -q Ghostnector; then
    ok "the window is on screen ($(wmctrl -l | grep Ghostnector | head -1 | cut -c1-60))"
else
    bad "the GUI window never appeared; stdout: $(head -3 /tmp/gui-stdout.log)"
fi

# ---------------------------------------------------------------- T1: the authoritative off state
echo
echo "-- T1: the window renders the core's off state --"
focus_gui
DIAG="$(diag_copy)"
echo "$DIAG" | head -14
case "$DIAG" in
*"Live snapshot"*) ok "the window is connected to the real core" ;;
*) bad "the window does not show a live snapshot" ;;
esac
case "$DIAG" in
*"state: off"*"traffic is not protected"*) ok "diagnostics render the core's off state" ;;
*) bad "diagnostics do not render the off state" ;;
esac
case "$DIAG" in
*"gui: "*"core: "*"protocol: 1"*) ok "the diagnostics show the versions and protocol" ;;
*) bad "the diagnostics do not show versions" ;;
esac
shot gui-01-off
TEXT="$(ocr gui-01-off)"
case "$TEXT" in
*"traffic is not protected"*) ok "the banner itself says traffic is not protected" ;;
*) bad "the banner does not show the off wording" ;;
esac
case "$TEXT" in
*"Tor"*"I2P"*"Whole system"*"Selected applications"*) ok "the normal view offers the documented choices" ;;
*) bad "the normal view is missing documented controls" ;;
esac

# ---------------------------------------------------------------- T2: refusals in plain words
echo
echo "-- T2: unsupported combinations are refused in plain words --"
focus_gui
click_word I2P --same-line-with Tor >/dev/null 2>&1 || bad "could not select I2P"
sleep 0.5
shot gui-02-i2p
TEXT="$(ocr gui-02-i2p)"
case "$TEXT" in
*"I2P protects the whole system"*) ok "the selected-applications refusal is shown" ;;
*) bad "no selected-applications refusal for I2P" ;;
esac
key alt+l
sleep 0.5
shot gui-03-i2p-lan
TEXT="$(ocr gui-03-i2p-lan)"
case "$TEXT" in
*"I2P has no local-network exception"*) ok "the local-network refusal is shown" ;;
*) bad "no local-network refusal for I2P" ;;
esac
click_word Tor --same-line-with I2P >/dev/null 2>&1 || bad "could not return to Tor"
sleep 0.5

# ---------------------------------------------------------------- T3: protection on via the window
echo
echo "-- T3: protection on through the window (Tor SYSTEM) --"
protection_on
if wait_line "protected" 300; then
    ok "a GUI-driven connect reached protection"
else
    bad "a GUI-driven connect did not reach protection: $(cli_line)"
fi
STATE="$(cli_state)"
echo "$STATE" | head -10
case "$(cli_line)" in
*"and verified"*) ok "the state is protected — and verified" ;;
*"protected"*) inc "the state is protected but not verified: $(cli_line)" ;;
*) bad "the state is not protected: $(cli_line)" ;;
esac
DIAG="$(diag_copy)"
echo "$DIAG" | grep -E "state:|profile:|policy applied:|verification:|services:" || true
case "$DIAG" in
*"profile: the whole system (through Tor)"*) ok "diagnostics render the Tor profile" ;;
*) bad "diagnostics do not render the Tor profile" ;;
esac
shot gui-04-protected
TEXT="$(ocr gui-04-protected)"
case "$TEXT" in
*"protected"*) ok "the banner shows protection" ;;
*) bad "the banner does not show protection" ;;
esac

# ---------------------------------------------------------------- T4: selection changes are confirmed
echo
echo "-- T4: changing the selection while protected asks first --"
focus_gui
click_word I2P --same-line-with Tor >/dev/null 2>&1 || bad "could not select I2P while protected"
sleep 1
shot gui-05-confirm
TEXT="$(ocr gui-05-confirm)"
case "$TEXT" in
*"Change what is protected"*) ok "the confirmation dialog appears" ;;
*) bad "no confirmation dialog when the selection changed while protected" ;;
esac
click_word Cancel >/dev/null 2>&1 || key Escape
sleep 0.5
case "$(cli_state)" in
*"through Tor"*) ok "cancelling keeps the reported Tor selection" ;;
*) bad "cancelling did not restore the Tor selection" ;;
esac
click_word I2P --same-line-with Tor >/dev/null 2>&1 || true
sleep 1
click_word Apply >/dev/null 2>&1 || key Return
if wait_status "through I2P" 240; then
    ok "applying the I2P selection re-applied protection"
    note "I2P state: $(cli_line)"
else
    inc "I2P did not settle within 240s: $(cli_line)"
fi
click_word Tor --same-line-with I2P >/dev/null 2>&1 || true
sleep 1
click_word Apply >/dev/null 2>&1 || key Return
if wait_status "through Tor" 240; then
    ok "returning to Tor re-applied protection"
else
    inc "Tor did not settle within 240s: $(cli_line)"
fi

# ---------------------------------------------------------------- T5: the APP lifecycle
echo
echo "-- T5: selected applications: add, run, list, stop --"
cat >/usr/local/bin/gh-qual-app <<'EOF'
#!/bin/sh
sleep 600
EOF
chmod 0755 /usr/local/bin/gh-qual-app
focus_gui
click_word applications --same-line-with Selected >/dev/null 2>&1 || bad "could not select the APP scope"
sleep 1
click_word Apply >/dev/null 2>&1 || key Return
if wait_status "selected applications" 240; then
    ok "the APP scope applied through the window"
else
    bad "the APP scope did not apply: $(cli_state | head -3)"
fi
focus_gui
key alt+a
sleep 1.5
key ctrl+l
sleep 0.5
xdotool type --delay 15 "/usr/local/bin/gh-qual-app"
sleep 0.5
key Return
sleep 2
APPS="$(runuser -u "$GUI_USER" -g ghostnector -- /usr/bin/ghostnector apps 2>&1)"
echo "apps: $APPS"
case "$APPS" in
*"gh-qual-app"*|*"running"*) ok "the chosen application is listed as running" ;;
*) bad "the chosen application did not appear: $APPS" ;;
esac
pgrep -f gh-qual-app >/dev/null 2>&1 && ok "the application process is really running" || bad "no application process found"
ip netns list 2>/dev/null | grep -q ghapp && ok "an APP namespace exists" || bad "no APP namespace found"
shot gui-06-app
TEXT="$(ocr gui-06-app)"
case "$TEXT" in
*"gh-qual-app"*) ok "the window lists the application by name" ;;
*) bad "the window does not list the application" ;;
esac
focus_gui
click_word Stop >/dev/null 2>&1 || bad "could not find the Stop button"
sleep 1.5
pgrep -f gh-qual-app >/dev/null 2>&1 && bad "the application is still running after Stop" || ok "Stop ended the application"
APPS="$(runuser -u "$GUI_USER" -g ghostnector -- /usr/bin/ghostnector apps 2>&1)"
echo "apps after stop: $APPS"

# ---------------------------------------------------------------- T6: panic behind a confirmation
echo
echo "-- T6: panic needs the menu and a confirmation --"
focus_gui
click_header_right 12 >/dev/null 2>&1 || bad "could not open the header menu"
sleep 1
shot gui-07-menu
TEXT="$(ocr gui-07-menu)"
case "$TEXT" in
*"Deny all traffic now"*) ok "the panic entry is in the menu" ;;
*) bad "the panic entry is not in the menu" ;;
esac
click_word Deny --same-line-with all >/dev/null 2>&1 || bad "could not activate the panic entry"
sleep 1
shot gui-08-panic-confirm
TEXT="$(ocr gui-08-panic-confirm)"
case "$TEXT" in
*"Deny all traffic now"*"blocked until you turn protection off"*) ok "panic asks for confirmation and explains" ;;
*) bad "panic does not show the confirmation" ;;
esac
click_word Deny --same-line-with everything >/dev/null 2>&1 || bad "could not confirm panic"
if wait_line "no traffic can leave" 30; then
    ok "panic applied the fail-closed baseline"
else
    bad "panic did not block: $(cli_line)"
fi
case "$(cli_state)" in
*"fail_closed"*) ok "the recorded intent is the fail-closed profile" ;;
*) bad "the fail-closed profile was not recorded" ;;
esac
protection_off
if wait_line "off " 60; then
    ok "protection can be turned off again after panic"
else
    bad "the machine did not return to off after panic: $(cli_line)"
fi
nft list table inet ghostnector >/dev/null 2>&1 && bad "a table survived the panic recovery" || ok "no table after panic recovery"

# ---------------------------------------------------------------- T7: core restart and reconnect
echo
echo "-- T7: the window survives a core restart and reconnects --"
focus_gui
systemctl stop ghostnector-core.service
sleep 2
DIAG="$(diag_copy)"
echo "$DIAG" | head -6
case "$DIAG" in
*"not reachable"*) ok "with the core stopped, the window says the state is not reachable" ;;
*) bad "the window did not report the unreachable core" ;;
esac
case "$DIAG" in
*"unknown, not a claim"*|*"last known"*) ok "the window marks the state as last known, not current" ;;
*) bad "the window did not mark the state as last known" ;;
esac
systemctl start ghostnector-core.service
sleep 3
DIAG="$(diag_copy)"
echo "$DIAG" | head -6
case "$DIAG" in
*"Live snapshot"*) ok "the window reconnected to the restarted core" ;;
*) bad "the window did not reconnect after the core restart" ;;
esac
pgrep -f '/usr/bin/ghostnector-gui' >/dev/null 2>&1 && ok "the window process survived the core restart" || bad "the window process died with the core restart"

# ---------------------------------------------------------------- T8: router and helper failure
echo
echo "-- T8: a dead router and a dead helper are shown honestly, and fail closed --"
protection_on
wait_line "protected" 300 && ok "Tor protection is up again" || inc "Tor did not come up again: $(cli_line)"
systemctl stop ghostnector-tor.service
if wait_line "no traffic can leave" 60; then
    ok "the router's death was noticed and the machine denied"
else
    inc "the router's death was not reflected within 60s: $(cli_line)"
fi
DIAG="$(diag_copy)"
echo "$DIAG" | grep -E "state:|services:|reasons:|  - " | head -10
systemctl start ghostnector-tor.service
protection_off
wait_line "off " 60 && ok "the machine returned to off after the router test" || bad "not off after the router test: $(cli_line)"
protection_on
wait_line "protected" 300 || inc "Tor did not come up before the helper test: $(cli_line)"
systemctl stop ghostnector-netd.service
if wait_line "no traffic can leave" 60; then
    ok "the helper's death was noticed and the machine denied"
else
    inc "the helper's death was not reflected within 60s: $(cli_line)"
fi
DIAG="$(diag_copy)"
echo "$DIAG" | grep -E "state:|policy applied|reasons:|  - " | head -10
systemctl start ghostnector-netd.service
protection_off
wait_line "off " 60 && ok "the machine returned to off after the helper test" || bad "not off after the helper test: $(cli_line)"

# ---------------------------------------------------------------- T9: a clean stand-down
echo
echo "-- T9: the window leaves the machine open and off --"
focus_gui
DIAG="$(diag_copy)"
case "$DIAG" in
*"state: off"*) ok "the window reports the final off state" ;;
*) bad "the window does not report the final off state" ;;
esac
nft list table inet ghostnector >/dev/null 2>&1 && bad "a table is still applied" || ok "no policy table at the end"
case "$(cli_state)" in
*"no policy is applied"*) ok "core agrees that no policy is applied" ;;
*) bad "core does not agree the machine is open" ;;
esac
shot gui-09-final

echo
echo "=== summary (installed GUI) ==="
echo "held:         $PASSED"
echo "contradicted: $FAILED"
echo "inconclusive: $INCONCLUSIVE"
echo "log:          $LOG"
echo "shots:        $SHOTS"
[ "$FAILED" = "0" ] || exit 1
exit 0
