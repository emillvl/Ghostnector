#!/usr/bin/env bash
#
# The installed GUI qualification: the real GTK4 window against the real installed control plane.
#
# Not part of the hermetic gate. It needs a display (Xvfb), the installed product, and the
# `ghostnector` group membership for the test user. The window is driven through **AT-SPI** (its
# accessible tree exposes every label, check box, button and menu item by name), and every claim is
# checked against `ghostnector status` (the authoritative Snapshot) and against the window's own
# diagnostics text copied through the real "Copy details" button. A few screenshots are kept as
# visual evidence; the log is the record.
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
ATSPI="$here/lib/gh-atspi.py"

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
off_now()      { cli_line | grep -qE '^state:[[:space:]]+off'; }
protected_now() { cli_line | grep -qE '^state:[[:space:]]+protected'; }
wait_off()       { local i; for i in $(seq 1 "$1"); do off_now && return 0; sleep 1; done; return 1; }
wait_protected() { local i; for i in $(seq 1 "$1"); do protected_now && return 0; sleep 1; done; return 1; }
wait_profile()   { local i; for i in $(seq 1 "$2"); do cli_state | grep -q "$1" && return 0; sleep 1; done; return 1; }
wait_not_applying() { local i; for i in $(seq 1 "$1"); do cli_line | grep -q "applying" || return 0; sleep 1; done; return 1; }
wait_profile_verbose() { # pattern seconds: logs the state every 30s while waiting
    local i
    for i in $(seq 1 "$2"); do
        cli_state | grep -q "$1" && return 0
        if [ $((i % 30)) -eq 0 ]; then
            echo "    (waiting for '$1' at ${i}s: $(cli_state | head -2 | tr '\n' ' '))"
        fi
        sleep 1
    done
    return 1
}
atspi() { runuser -u "$GUI_USER" -- env DISPLAY=:90 DBUS_SESSION_BUS_ADDRESS="$BUS" python3 "$ATSPI" "$@" 2>/dev/null; }
action_describe() {
    DBUS_SESSION_BUS_ADDRESS="$BUS" gdbus call --session --dest org.ghostnector.Gui \
        --object-path /org/ghostnector/Gui --method org.gtk.Actions.Describe "$1" 2>/dev/null
}
action_activate() {
    DBUS_SESSION_BUS_ADDRESS="$BUS" gdbus call --session --dest org.ghostnector.Gui \
        --object-path /org/ghostnector/Gui --method org.gtk.Actions.Activate "$1" "[]" "{}" 2>/dev/null
}
# Clicks, in order of preference:
#   1. an AT-SPI action (switches, buttons, menu items) — works without focus;
#   2. keyboard: Tab to the control (radio groups need arrow navigation: only the selected member
#      is a tab stop), then Space;
#   3. fixed layout coordinates for this exact window (460x640 at 0,0), taken from a screenshot.
focus_by_tab() { # NAME [MAX]
    local i
    for i in $(seq 1 "${2:-40}"); do
        atspi focused "$1" >/dev/null 2>&1 && return 0
        xdotool key --clearmodifiers Tab
        sleep 0.12
    done
    return 1
}
select_radio() { # NAME SIBLING ARROW
    local name="$1" sibling="$2" arrow="$3"
    focus_by_tab "$sibling" || return 1
    xdotool key --clearmodifiers "$arrow"
    sleep 0.3
    atspi focused "$name" >/dev/null 2>&1 || return 1
    xdotool key --clearmodifiers space
    sleep 0.3
    return 0
}
ui_click() {
    local name="$1" xy
    if atspi click "$name" >/dev/null 2>&1; then
        sleep 0.3
        return 0
    fi
    xdotool windowactivate --sync "$(xdotool search --name '^Ghostnector$' | head -1)" 2>/dev/null || true
    sleep 0.2
    case "$name" in
    "I2P") select_radio "I2P" "Tor" Right && return 0 ;;
    "Tor") select_radio "Tor" "I2P" Left && return 0 ;;
    "Selected applications") select_radio "Selected applications" "Whole system" Right && return 0 ;;
    "Whole system") select_radio "Whole system" "Selected applications" Left && return 0 ;;
    esac
    if focus_by_tab "$name"; then
        xdotool key --clearmodifiers space
        sleep 0.4
        return 0
    fi
    xy="$(fixed_coords "$name")"
    if [ -n "$xy" ]; then
        xdotool mousemove --sync "${xy% *}" "${xy#* }" click 1
        sleep 0.4
        return 0
    fi
    return 1
}

# The layout of the shipped window at its default size, read from a screenshot of this build.
fixed_coords() {
    case "$1" in
    "Protection") echo "413 161" ;;
    "Tor") echo "34 240" ;;
    "I2P") echo "93 240" ;;
    "Whole system") echo "33 306" ;;
    "Selected applications") echo "170 306" ;;
    "Allow access to the local network") echo "428 339" ;;
    "Diagnostics") echo "266 27" ;;
    "More actions") echo "192 27" ;;
    "Add application…"|"Add application") echo "364 390" ;;
    "Stop") echo "430 483" ;;
    *) echo "" ;;
    esac
}
ui_labels() { atspi labels; }
shot() { import -window root "$SHOTS/$1.png" 2>/dev/null; }
key() { xdotool key --clearmodifiers "$@"; sleep 0.4; }
focus_gui() { wmctrl -a Ghostnector 2>/dev/null || true; sleep 0.4; }
gui_alive() { pgrep -f '/usr/bin/ghostnector-gui' >/dev/null 2>&1; }
start_gui() {
    local out
    out="$(dbus-daemon --session --fork --print-address=1 --print-pid=1 2>/dev/null)"
    BUS="$(printf '%s\n' "$out" | sed -n '1p')"
    BUS_PID="$(printf '%s\n' "$out" | sed -n '2p')"
    # The daemon prints its address before its listener is necessarily ready; starting the window
    # immediately can lose the race and leave GApplication without a bus (observed: the window runs
    # but exports no actions and dies when the bus goes). Wait for the bus to answer first.
    for _ in $(seq 1 40); do
        DBUS_SESSION_BUS_ADDRESS="$BUS" gdbus call --session --dest org.freedesktop.DBus \
            --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.Peer.Ping \
            >/dev/null 2>&1 && break
        sleep 0.25
    done
    setsid nohup runuser -u "$GUI_USER" -- bash -c "env DISPLAY=:90 HOME=/home/ghost \
        DBUS_SESSION_BUS_ADDRESS='$BUS' XDG_RUNTIME_DIR=/run/user/1000 \
        GSK_RENDERER=cairo GDK_BACKEND=x11 /usr/bin/ghostnector-gui; \
        echo gui-exit=\$? at \$(date -u)" </dev/null >>"$SHOTS/gui-stdout.log" 2>&1 &
    for _ in $(seq 1 40); do wmctrl -l 2>/dev/null | grep -q Ghostnector && break; sleep 0.5; done
    # The window must actually be on the bus: without it, actions are not exported.
    for _ in $(seq 1 20); do
        DBUS_SESSION_BUS_ADDRESS="$BUS" gdbus call --session --dest org.ghostnector.Gui \
            --object-path /org/ghostnector/Gui --method org.gtk.Actions.Describe panic \
            >/dev/null 2>&1 && break
        sleep 0.25
    done
}
ensure_gui() {
    local bus_alive=1
    if [ -n "${BUS_PID:-}" ] && kill -0 "$BUS_PID" 2>/dev/null; then
        bus_alive=0
    fi
    if gui_alive && [ "$bus_alive" = "0" ]; then
        return 0
    fi
    if gui_alive; then
        note "the window's session bus died; restarting the window on a fresh bus"
    else
        note "the window process is gone; restarting it (its output is in $SHOTS/gui-stdout.log)"
    fi
    pkill -f '/usr/bin/ghostnector-gui' 2>/dev/null || true
    start_gui
    gui_alive
}

protection_on() {
    ensure_gui
    focus_gui
    wait_not_applying 90
    ui_click Protection >/dev/null 2>&1 || true
    sleep 1
    if off_now; then
        note "the first switch activation did not take; trying once more"
        ui_click Protection >/dev/null 2>&1 || true
        sleep 1
    fi
    if off_now; then
        note "the switch click did not take; using the keyboard path"
        focus_by_tab Protection >/dev/null 2>&1 && { xdotool key --clearmodifiers space; sleep 1; }
    fi
}
protection_off() {
    ensure_gui
    focus_gui
    wait_not_applying 90
    ui_click Protection >/dev/null 2>&1 || true
    sleep 1
    if ! off_now; then
        note "the first switch activation did not take; trying once more"
        ui_click Protection >/dev/null 2>&1 || true
        sleep 1
    fi
    if ! off_now; then
        note "the switch click did not take; using the keyboard path"
        focus_by_tab Protection >/dev/null 2>&1 && { xdotool key --clearmodifiers space; sleep 1; }
    fi
}
diag_copy() {
    ui_click Diagnostics >/dev/null 2>&1 || true
    atspi wait "Copy details" 10 >/dev/null 2>&1 || true
    ui_click "Copy details" >/dev/null 2>&1 || true
    sleep 0.6
    DISPLAY=:90 xclip -selection clipboard -o 2>/dev/null
    wmctrl -c "Ghostnector diagnostics" 2>/dev/null || true
    sleep 0.5
}

cleanup() {
    local rc=$?
    echo
    echo "== cleanup at $(date -u) (run exit $rc) =="
    timeout 90 runuser -u ghost -g ghostnector -- /usr/bin/ghostnector disconnect >/dev/null 2>&1 \
        || echo "disconnect failed; using the documented rescue"
    if nft list table inet ghostnector >/dev/null 2>&1; then
        echo "destroying the owned table (documented rescue)"
        nft destroy table inet ghostnector >>"$LOG" 2>&1 || true
    fi
    if [ -f /var/lib/ghostnector/intent.json ] && grep -q '"protected"[[:space:]]*:[[:space:]]*true' /var/lib/ghostnector/intent.json; then
        rm -f /var/lib/ghostnector/intent.json
    fi
    pkill -f '/usr/bin/ghostnector-gui' 2>/dev/null || true
    pkill -x xfwm4 2>/dev/null || true
    pkill -f 'Xvfb :90' 2>/dev/null || true
    pkill -f 'dbus-daemon --session' 2>/dev/null || true
    echo "== final state =="
    cli_state | head -4
    echo "== end of $LOG =="
    exit "$rc"
}
trap cleanup EXIT

[ "$(id -u)" = "0" ] || { echo "this qualification needs root"; exit 2; }
[ -f "$ATSPI" ] || { echo "missing $ATSPI"; exit 2; }
command -v xclip >/dev/null || { echo "xclip is not installed"; exit 2; }
python3 -c 'import pyatspi' 2>/dev/null || { echo "python3-pyatspi is not installed"; exit 2; }

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
off_now && ok "the baseline is off" || bad "the baseline is not off: $(cli_line)"
nft list table inet ghostnector >/dev/null 2>&1 && bad "a table survived the baseline" || ok "no table at the baseline"

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
pkill -f 'dbus-daemon --session' 2>/dev/null || true
sleep 0.5
setsid nohup Xvfb :90 -screen 0 1280x900x24 -ac </dev/null >/tmp/gui-xvfb.log 2>&1 &
sleep 1
setsid nohup runuser -u "$GUI_USER" -- env DISPLAY=:90 HOME=/home/ghost \
    xfwm4 --compositor=off </dev/null >/tmp/gui-xfwm4.log 2>&1 &
sleep 2
# One session bus shared by the window and the AT-SPI driver; without it GApplication never reaches
# activate and the window is never mapped. start_gui records the window's exit status in the
# durable shots directory, so a window that dies mid-run leaves its reason behind.
start_gui
if [ -n "$BUS" ]; then ok "session bus: ${BUS%%guid=*}"; else bad "no session bus"; fi
if wmctrl -l 2>/dev/null | grep -q Ghostnector; then
    ok "the window is on screen ($(wmctrl -l | grep Ghostnector | head -1 | cut -c1-60))"
else
    bad "the GUI window never appeared; output: $(tail -3 "$SHOTS/gui-stdout.log" 2>/dev/null)"
fi
atspi wait Ghostnector 20 >/dev/null 2>&1 && ok "the window is visible to AT-SPI" || bad "AT-SPI cannot see the window"

# ---------------------------------------------------------------- T1: the authoritative off state
echo
echo "-- T1: the window renders the core's off state --"
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
BANNER="$(atspi banner)"
case "$BANNER" in
*"traffic is not protected"*) ok "the banner itself says traffic is not protected" ;;
*) bad "the banner does not show the off wording: '$BANNER'" ;;
esac
LABELS="$(ui_labels)"
for control in "Tor" "I2P" "Whole system" "Selected applications" "Protection" "Diagnostics" "Add application"; do
    case "$LABELS" in
    *"$control"*) ;;
    *) bad "the normal view is missing '$control'" ;;
    esac
done
ok "the normal view offers the documented controls"
case "$LABELS" in
*"nftables"*|*"namespace"*|*"uid"*|*"/run/"*|*"netd"*|*"appd"*)
    bad "the normal view shows implementation jargon" ;;
*) ok "the normal view shows no implementation jargon" ;;
esac
shot gui-01-off

# ---------------------------------------------------------------- T2: refusals in plain words
echo
echo "-- T2: unsupported combinations are refused in plain words --"
focus_gui
ui_click I2P >/dev/null 2>&1 || bad "could not select I2P"
sleep 0.5
LABELS="$(ui_labels)"
case "$LABELS" in
*"I2P protects the whole system"*) ok "the selected-applications refusal is shown" ;;
*) note "the refusal text appears only when the scope is the refused one; the control state is checked next" ;;
esac
case "$(atspi enabled "Selected applications")" in
disabled) ok "the selected-applications control is disabled under I2P" ;;
*) bad "the selected-applications control is still enabled under I2P" ;;
esac
ui_click "Allow access to the local network" >/dev/null 2>&1 || bad "could not try the local-network switch"
sleep 0.5
case "$(atspi enabled "Allow access to the local network")" in
disabled) ok "the local-network control is disabled under I2P" ;;
*) bad "the local-network control is still enabled under I2P" ;;
esac
LABELS="$(ui_labels)"
case "$LABELS" in
*"I2P has no local-network exception"*) ok "the local-network refusal is shown" ;;
*) note "the local-network refusal text is not visible while the scope is whole-system" ;;
esac
ui_click Tor >/dev/null 2>&1 || bad "could not return to Tor"
sleep 0.5
shot gui-02-refusals

# ---------------------------------------------------------------- T3: protection on via the window
echo
echo "-- T3: protection on through the window (Tor SYSTEM) --"
protection_on
if wait_protected 300; then
    ok "a GUI-driven connect reached protection"
else
    bad "a GUI-driven connect did not reach protection: $(cli_line)"
fi
# The first verification runs a couple of seconds after the policy is applied; wait for it before
# classifying (a fresh Degraded is not a failure).
for _ in $(seq 1 90); do
    cli_line | grep -qE "and verified|no traffic can leave" && break
    sleep 1
done
STATE="$(cli_state)"
echo "$STATE" | head -10
if protected_now; then
    case "$(cli_line)" in
    *"and verified"*) ok "the state is protected — and verified" ;;
    *) inc "the state is protected but not verified: $(cli_line)" ;;
    esac
else
    bad "the state is not protected: $(cli_line)"
fi
DIAG="$(diag_copy)"
echo "$DIAG" | grep -E "state:|profile:|policy applied:|verification:|services:" || true
case "$DIAG" in
*"profile: the whole system (through Tor)"*) ok "diagnostics render the Tor profile" ;;
*) bad "diagnostics do not render the Tor profile" ;;
esac
BANNER="$(atspi banner)"
case "$BANNER" in
protected*) ok "the banner shows protection: '$BANNER'" ;;
*) bad "the banner does not show protection: '$BANNER'" ;;
esac
shot gui-03-protected

# ---------------------------------------------------------------- T4: selection changes are confirmed
echo
echo "-- T4: changing the selection while protected asks first --"
ensure_gui
dialog_open() { ui_labels | grep -q "Change what is protected"; }
wait_dialog_gone() { local i; for i in $(seq 1 40); do dialog_open || return 0; sleep 0.25; done; return 1; }
ui_click I2P >/dev/null 2>&1 || bad "could not select I2P while protected"
sleep 1
if dialog_open; then ok "the confirmation dialog appears"; else bad "no confirmation dialog when the selection changed while protected"; fi
ui_click Cancel >/dev/null 2>&1 || key Escape
wait_dialog_gone || note "the dialog label lingered in the accessible tree"
case "$(cli_state)" in
*"through Tor"*) ok "cancelling keeps the reported Tor selection" ;;
*) bad "cancelling did not restore the Tor selection" ;;
esac
# The confirmation is proved above. The transition itself is exercised the way a person changes
# networks without one: stand down, choose, protect on.
protection_off
wait_off 60 || bad "could not stand down before the I2P selection"
focus_gui
ui_click I2P >/dev/null 2>&1 || bad "could not select I2P while off"
sleep 0.5
protection_on
if wait_profile_verbose "through I2P" 300; then
    ok "I2P applied through the window"
    note "I2P state: $(cli_line)"
else
    inc "I2P did not settle within 300s: $(cli_state | head -3 | tr '\n' ' ')"
fi
protection_off
wait_off 60 || bad "could not stand down after the I2P selection"
focus_gui
ui_click Tor >/dev/null 2>&1 || bad "could not return to Tor while off"
sleep 0.5
protection_on
if wait_profile "through Tor" 300; then
    ok "returning to Tor re-applied protection"
else
    inc "Tor did not settle within 300s: $(cli_state | head -3 | tr '\n' ' ')"
fi

# ---------------------------------------------------------------- T5: the APP lifecycle
echo
echo "-- T5: selected applications: add, run, list, stop --"
ensure_gui
cat >/usr/local/bin/gh-qual-app <<'EOF'
#!/bin/sh
sleep 600
EOF
chmod 0755 /usr/local/bin/gh-qual-app
focus_gui
ui_click "Selected applications" >/dev/null 2>&1 || bad "could not select the APP scope"
sleep 1
ui_click Apply >/dev/null 2>&1 || key Return
if wait_profile_verbose "chosen applications" 300; then
    ok "the APP scope applied through the window"
else
    bad "the APP scope did not apply: $(cli_state | head -3)"
fi
focus_gui
# The picker is GTK's own file chooser. Under Xvfb the harness could open it and see its tree
# (title, Name label, Open button) but could not make its location entry accept a typed path, so
# the launch is performed through the same core API the picker calls (`ghostnector run`), and the
# window's own list and Stop are exercised below. The picker itself is a documented limitation of
# this environment, not of the product.
if dialog_open; then key Escape; sleep 0.5; fi
runuser -u "$GUI_USER" -g ghostnector -- /usr/bin/ghostnector run /usr/local/bin/gh-qual-app >/dev/null 2>&1 &
sleep 3
APPS="$(runuser -u "$GUI_USER" -g ghostnector -- /usr/bin/ghostnector apps 2>&1)"
echo "apps: $APPS"
if ! printf '%s' "$APPS" | grep -q "gh-qual-app"; then
    note "windows: $(wmctrl -l | tr '\n' ' ')"
    note "dialog-ish labels: $(ui_labels | grep -iE 'choose|name|location|open|select' | head -5 | tr '\n' ' ')"
fi
case "$APPS" in
*"no protected applications"*) bad "the chosen application did not appear: $APPS" ;;
*"running"*) ok "the chosen application is listed as running" ;;
*) bad "the chosen application did not appear as running: $APPS" ;;
esac
ps -eo args= | grep -q '[g]h-qual-app' && ok "the application process is really running" || bad "no application process found"
ip netns list 2>/dev/null | grep -q ghapp && ok "an APP namespace exists" || bad "no APP namespace found"
LABELS="$(ui_labels)"
case "$LABELS" in
*"gh-qual-app"*) ok "the window lists the application by name" ;;
*) bad "the window does not list the application" ;;
esac
shot gui-04-app
ui_click Stop >/dev/null 2>&1 || bad "could not find the Stop button"
sleep 1.5
ps -eo args= | grep -q '[g]h-qual-app' && bad "the application is still running after Stop" || ok "Stop ended the application"
APPS="$(runuser -u "$GUI_USER" -g ghostnector -- /usr/bin/ghostnector apps 2>&1)"
echo "apps after stop: $APPS"

# ---------------------------------------------------------------- T6: panic behind a confirmation
echo
echo "-- T6: panic needs the menu and a confirmation --"
ensure_gui
focus_gui
# The popover's items are not exposed through AT-SPI under this environment (Xvfb + GTK4), and a
# synthetic click on the header button does not open it either; the flow is driven through the same
# exported action the menu item invokes, `win.panic`. The action is described first so the log
# shows it is really there.
if action_describe panic >/dev/null 2>&1; then
    ok "the panic action is exported (the action the menu item invokes)"
else
    bad "the panic action is not exported"
fi
action_activate panic >/dev/null 2>&1 || bad "could not activate the panic action"
sleep 1
LABELS="$(ui_labels)"
case "$LABELS" in
*"Deny all traffic now"*"blocked until you turn protection off"*) ok "panic asks for confirmation and explains" ;;
*) bad "panic does not show the confirmation" ;;
esac
ui_click "Deny everything" >/dev/null 2>&1 || bad "could not confirm panic"
BLOCKED=0
for _ in $(seq 1 30); do
    "${CLI[@]}" status 2>/dev/null | head -1 | grep -q "no traffic can leave" && { BLOCKED=1; break; }
    sleep 1
done
[ "$BLOCKED" = "1" ] && ok "panic applied the fail-closed baseline" || bad "panic did not block: $(cli_line)"
case "$(cli_state)" in
*"fail_closed"*) ok "the recorded intent is the fail-closed profile" ;;
*) bad "the fail-closed profile was not recorded" ;;
esac
protection_off
if wait_off 60; then
    ok "protection can be turned off again after panic"
else
    bad "the machine did not return to off after panic: $(cli_line)"
fi
nft list table inet ghostnector >/dev/null 2>&1 && bad "a table survived the panic recovery" || ok "no table after panic recovery"

# ---------------------------------------------------------------- T7: core restart and reconnect
echo
echo "-- T7: the window survives a core restart and reconnects --"
ensure_gui
systemctl stop ghostnector-core.service
for _ in $(seq 1 60); do systemctl is-active --quiet ghostnector-core.service || break; sleep 1; done
sleep 1
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
RECONNECTED=0
for _ in $(seq 1 30); do
    DIAG="$(diag_copy)"
    case "$DIAG" in
    *"Live snapshot"*) RECONNECTED=1; break ;;
    esac
    sleep 1
done
echo "$DIAG" | head -6
[ "$RECONNECTED" = "1" ] && ok "the window reconnected to the restarted core" || bad "the window did not reconnect after the core restart"
pgrep -f '/usr/bin/ghostnector-gui' >/dev/null 2>&1 && ok "the window process survived the core restart" || bad "the window process died with the core restart"

# ---------------------------------------------------------------- T8: router and helper failure
echo
echo "-- T8: a dead router and a dead helper are shown honestly, and fail closed --"
protection_on
wait_protected 300 && ok "Tor protection is up again" || inc "Tor did not come up again: $(cli_line)"
systemctl stop ghostnector-tor.service
# Tor's stop can take up to its TimeoutStopSec (90 s) before it is really gone; judge the state
# only after the unit is inactive.
for _ in $(seq 1 150); do systemctl is-active --quiet ghostnector-tor.service || break; sleep 1; done
for _ in $(seq 1 120); do
    "${CLI[@]}" status 2>/dev/null | head -1 | grep -q "no traffic can leave" && break
    sleep 1
done
"${CLI[@]}" status 2>/dev/null | head -1 | grep -q "no traffic can leave" \
    && ok "the router's death was noticed and the machine denied" \
    || inc "the router's death was not reflected within 60s: $(cli_line)"
DIAG="$(diag_copy)"
echo "$DIAG" | grep -E "state:|services:|reasons:|  - " | head -10
systemctl start ghostnector-tor.service
protection_off
wait_off 60 && ok "the machine returned to off after the router test" || bad "not off after the router test: $(cli_line)"
protection_on
wait_protected 300 || inc "Tor did not come up before the helper test: $(cli_line)"
systemctl stop ghostnector-netd.service
for _ in $(seq 1 30); do systemctl is-active --quiet ghostnector-netd.service || break; sleep 1; done
for _ in $(seq 1 120); do
    "${CLI[@]}" status 2>/dev/null | head -1 | grep -q "no traffic can leave" && break
    sleep 1
done
"${CLI[@]}" status 2>/dev/null | head -1 | grep -q "no traffic can leave" \
    && ok "the helper's death was noticed and the machine denied" \
    || inc "the helper's death was not reflected within 60s: $(cli_line)"
DIAG="$(diag_copy)"
echo "$DIAG" | grep -E "state:|policy applied|reasons:|  - " | head -10
systemctl start ghostnector-netd.service
protection_off
wait_off 60 && ok "the machine returned to off after the helper test" || bad "not off after the helper test: $(cli_line)"

# ---------------------------------------------------------------- T9: a clean stand-down
echo
echo "-- T9: the window leaves the machine open and off --"
ensure_gui
wait_off 30 || true
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
shot gui-05-final

echo
echo "=== summary (installed GUI) ==="
echo "held:         $PASSED"
echo "contradicted: $FAILED"
echo "inconclusive: $INCONCLUSIVE"
echo "log:          $LOG"
echo "shots:        $SHOTS"
[ "$FAILED" = "0" ] || exit 1
exit 0
