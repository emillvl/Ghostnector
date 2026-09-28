#!/usr/bin/env bash
#
# CPU/RSS impact of one appd binary across N APP launches, measured from /proc deltas.
#
# Usage: perf-app-launch-cpu.sh [N] [LABEL]
#
# Run it once with the qualified binary and once with the candidate (swap
# /usr/libexec/ghostnector-appd between runs); both runs execute the same sequence.
set -uo pipefail

LOGDIR=/var/log/ghostnector-qual
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOGDIR/app-launch-cpu-$STAMP.log"
CORE_ENV_BAK=/var/tmp/gh-cpu-core.env.bak
CLI=(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector)
N="${1:-6}"
LABEL="${2:-unlabelled}"
CLK=$(getconf CLK_TCK)

mkdir -p "$LOGDIR"
exec >>"$LOG" 2>&1
echo "== appd launch CPU/RSS at $(date -u), label=$LABEL N=$N =="
ln -sfn "$(basename "$LOG")" "$LOGDIR/app-launch-cpu-latest.log"

cleanup() {
    timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
    if [ -f "$CORE_ENV_BAK" ]; then cp -a "$CORE_ENV_BAK" /etc/ghostnector/core.env; else rm -f /etc/ghostnector/core.env; fi
    systemctl restart ghostnector-core.service 2>/dev/null || true
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || exit 2
timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
rm -f /var/lib/ghostnector/intent.json
[ -f /etc/ghostnector/core.env ] && cp -a /etc/ghostnector/core.env "$CORE_ENV_BAK"
cat >/etc/ghostnector/core.env <<'EOF'
GHOSTNECTOR_VERIFY=--udp-check 10.0.2.2:18081 --verify-timeout 10 --verify-interval 3600 --verify-stale-after 7200
EOF
systemctl restart ghostnector-netd.service ghostnector-core.service ghostnector-appd.service
sleep 2

cat >/usr/local/bin/gh-perf-app-short <<'EOF'
#!/bin/sh
sleep 2
EOF
chmod 0755 /usr/local/bin/gh-perf-app-short

"${CLI[@]}" connect --scope app >/dev/null 2>&1 || true
for _ in $(seq 1 180); do
    "${CLI[@]}" status 2>/dev/null | grep -q "chosen applications" && break
    sleep 1
done
"${CLI[@]}" status | head -2

APPD_PID="$(systemctl show -p MainPID --value ghostnector-appd)"
CORE_PID="$(systemctl show -p MainPID --value ghostnector-core)"

ticks() { awk '{print $14+$15}' "/proc/$1/stat"; }
hwm() { awk '/VmHWM/{print $2}' "/proc/$1/status"; }

APPD_BEFORE="$(ticks "$APPD_PID")"; CORE_BEFORE="$(ticks "$CORE_PID")"
APPD_RSS="$(hwm "$APPD_PID")"; CORE_RSS="$(hwm "$CORE_PID")"
WALL_BEFORE="$(date +%s%N)"
for _ in $(seq 1 "$N"); do
    timeout 60 "${CLI[@]}" run /usr/local/bin/gh-perf-app-short </dev/null >/dev/null 2>&1 || true
    sleep 1
done
WALL_AFTER="$(date +%s%N)"
APPD_AFTER="$(ticks "$APPD_PID")"; CORE_AFTER="$(ticks "$CORE_PID")"

python3 - "$LABEL" "$N" "$CLK" "$APPD_BEFORE" "$APPD_AFTER" "$CORE_BEFORE" "$CORE_AFTER" \
    "$APPD_RSS" "$CORE_RSS" "$WALL_BEFORE" "$WALL_AFTER" <<'PY'
import sys
label, n, clk, ab, aa, cb, ca, arss, crss, wb, wa = sys.argv[1:]
n = int(n); clk = int(clk)
appd_ms = (int(aa) - int(ab)) / clk * 1000
core_ms = (int(ca) - int(cb)) / clk * 1000
wall_ms = (int(wa) - int(wb)) / 1e6
print(f"label={label}")
print(f"launches={n}")
print(f"appd_cpu_total_ms={appd_ms:.1f} appd_cpu_per_launch_ms={appd_ms/n:.1f}")
print(f"core_cpu_total_ms={core_ms:.1f} core_cpu_per_launch_ms={core_ms/n:.1f}")
print(f"wall_total_ms={wall_ms:.1f} wall_per_launch_ms={wall_ms/n:.1f}")
print(f"appd_rss_hwm_kb={arss} core_rss_hwm_kb={crss}")
PY

echo "log: $LOG"
