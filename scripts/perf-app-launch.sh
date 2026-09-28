#!/usr/bin/env bash
#
# H2: APP launch phase profiling, measurement only.
#
# Alternates a genuinely equivalent direct launch (runuser + bash + exec the same app) with a
# product launch (`ghostnector run`), and observes phase boundaries from outside:
#
#   CLI -> core IPC -> appd -> namespace -> relay -> session/launcher -> application exec
#
# The application writes its own CLOCK_REALTIME timestamp as its first action, so the exec
# measurement does not depend on polling granularity. Nothing in the product is instrumented
# or changed.
#
# Usage: perf-app-launch.sh [N]

set -uo pipefail

N="${1:-8}"
LOGDIR=/var/log/ghostnector-qual
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOGDIR/app-launch-profile-$STAMP.log"
CSV="$LOGDIR/app-launch-profile-$STAMP.csv"
CORE_ENV_BAK=/var/tmp/gh-app-profile-core.env.bak
WATCH=/usr/local/lib/gh-perf/perf-launch-watch.py
RESOURCES=/usr/local/lib/gh-perf/perf-resources.py
CLI=(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector)

mkdir -p "$LOGDIR"
exec >>"$LOG" 2>&1
ln -sfn "$(basename "$LOG")" "$LOGDIR/app-launch-latest.log"
echo "== APP launch profile at $(date -u), N=$N =="
echo "log: $LOG"
echo "csv: $CSV"

cleanup() {
    local rc=$?
    echo
    echo "== cleanup at $(date -u) (rc=$rc) =="
    pkill -f "/usr/local/bin/gh-perf-app" 2>/dev/null || true
    pkill -f "/usr/local/bin/gh-perf-download" 2>/dev/null || true
    timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
    if [ -f /var/lib/ghostnector/intent.json ] \
        && grep -q '"protected"[[:space:]]*:[[:space:]]*true' /var/lib/ghostnector/intent.json; then
        rm -f /var/lib/ghostnector/intent.json
    fi
    if [ -f "$CORE_ENV_BAK" ]; then
        cp -a "$CORE_ENV_BAK" /etc/ghostnector/core.env
    else
        rm -f /etc/ghostnector/core.env
    fi
    systemctl restart ghostnector-core.service 2>/dev/null || true
    echo "== final state =="
    "${CLI[@]}" status 2>&1 | head -4
    echo "== end of $LOG =="
    exit "$rc"
}
trap cleanup EXIT

[ "$(id -u)" = "0" ] || { echo "this profiler needs root"; exit 2; }

# ------------------------------------------------------------------ environment
echo
echo "-- reset to off --"
timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
nft destroy table inet ghostnector 2>/dev/null || true
rm -f /var/lib/ghostnector/intent.json
[ -f /etc/ghostnector/core.env ] && cp -a /etc/ghostnector/core.env "$CORE_ENV_BAK"
# UDP-only verification: the APP probe passes deterministically because the namespace denies
# UDP (the same configuration the focused APP qualification uses). The interval is set far
# above the measurement window so no scheduled probe runs inside it; the first verification
# still happens (Protected is evidence-based).
cat >/etc/ghostnector/core.env <<'EOF'
GHOSTNECTOR_VERIFY=--udp-check 10.0.2.2:18081 --verify-timeout 10 --verify-interval 3600 --verify-stale-after 7200
EOF
systemctl restart ghostnector-netd.service ghostnector-core.service ghostnector-appd.service
sleep 2

cat >/usr/local/bin/gh-perf-app <<'EOF'
#!/bin/sh
date +%s.%N
sleep 6
EOF
chmod 0755 /usr/local/bin/gh-perf-app
chown root:root /usr/local/bin/gh-perf-app

# ------------------------------------------------------------------ APP scope up
echo
echo "-- connect: Ghostnector APP scope --"
"${CLI[@]}" connect --scope app >/dev/null 2>&1 || true
APP_READY=0
for _ in $(seq 1 180); do
    if "${CLI[@]}" status 2>/dev/null | grep -q "chosen applications"; then
        APP_READY=1
        break
    fi
    sleep 1
done
"${CLI[@]}" status | head -3
if [ "$APP_READY" != "1" ]; then
    echo "APP scope did not come up; the launch measurements cannot proceed"
    exit 1
fi

remove_groups() {
    local output id
    output="$(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector apps 2>/dev/null || true)"
    for id in $(echo "$output" | awk '/^  - /{print $2}'); do
        runuser -u ghost -g ghostnector -- /usr/bin/ghostnector stop-app "$id" >/dev/null 2>&1 || true
    done
}

# ------------------------------------------------------------------ warmups
echo
echo "-- warmups (1 per mode, not recorded) --"
for mode in direct product; do
    pkill -f "/usr/local/bin/gh-perf-app" 2>/dev/null || true
    remove_groups
    sleep 1
    python3 "$WATCH" --mode "$mode" --label warmup 2>&1 | sed 's/^/    /'
done
# The warmup may leave a group behind (the app exits on its own after 6 s).
sleep 2
remove_groups

# ------------------------------------------------------------------ recorded runs
echo
echo "-- recorded: $N rounds per mode, order alternated --"
echo "label,mode,t0_epoch,self_epoch,exec_ms,netns_ms,relay_ms,launcher_ms,session_ms,app_ms,note" >"$CSV"
for round in $(seq 1 "$N"); do
    order="$(printf '%s\n' direct product | shuf)"
    for mode in $order; do
        pkill -f "/usr/local/bin/gh-perf-app" 2>/dev/null || true
        remove_groups
        sleep 1
        line="$(python3 "$WATCH" --mode "$mode" --label "run$round")"
        [ -n "$line" ] && echo "$line" | tee -a "$CSV" | sed 's/^/    /'
    done
done
remove_groups

# ------------------------------------------------------------------ process/spawn costs
echo
echo "-- process and IPC costs (medians) --"
python3 - <<'PY'
import statistics, subprocess, time

def timed(command, n):
    values = []
    for _ in range(n):
        began = time.perf_counter()
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        values.append((time.perf_counter() - began) * 1000.0)
    return values

cases = [
    ("ip link show lo", ["ip", "link", "show", "lo"], 50),
    ("nft list tables", ["nft", "list", "tables"], 50),
    ("ghostnector --version", ["/usr/bin/ghostnector", "--version"], 20),
    ("ghostnector apps (CLI+core+appd IPC)",
     ["runuser", "-u", "ghost", "-g", "ghostnector", "--", "/usr/bin/ghostnector", "apps"], 20),
    ("ghostnector status (CLI+core+netd+nft)",
     ["runuser", "-u", "ghost", "-g", "ghostnector", "--", "/usr/bin/ghostnector", "status"], 10),
]
for label, command, n in cases:
    values = timed(command, n)
    print(f"{label:42s} n={n:3d} med={statistics.median(values):7.2f}ms p90={sorted(values)[int(0.9*(len(values)-1))]:7.2f}ms")

# One namespace lifecycle, the kernel work a single `ghostnector run` performs around it.
starts = timed(["ip", "netns", "add", "gh-profile-tmp"], 10)
dels = timed(["ip", "netns", "del", "gh-profile-tmp"], 10)
print(f"{'ip netns add (one namespace)':42s} n=10 med={statistics.median(starts):7.2f}ms")
print(f"{'ip netns del (one namespace)':42s} n=10 med={statistics.median(dels):7.2f}ms")
PY

# ------------------------------------------------------------------ resources
echo
echo "-- corrected APP idle resources (60 s) --"
python3 "$RESOURCES" --label "APP protected idle (product)" --seconds 60 --match product

echo
echo "-- relay under a real download (30 s) --"
cat >/usr/local/bin/gh-perf-download <<'EOF'
#!/bin/sh
for _ in 1 2 3; do
    timeout 90 curl -s -o /dev/null --max-time 80 http://ipv4.download.thinkbroadband.com/1MB.zip || true
done
EOF
chmod 0755 /usr/local/bin/gh-perf-download
( sleep 200 | "${CLI[@]}" run /usr/local/bin/gh-perf-download >/dev/null 2>&1 ) &
DOWNLOAD_JOB=$!
sleep 5
python3 "$RESOURCES" --label "relay under download" --seconds 30 --match relay
wait "$DOWNLOAD_JOB" 2>/dev/null || true
pkill -f "/usr/local/bin/gh-perf-download" 2>/dev/null || true
remove_groups

# ------------------------------------------------------------------ summary
echo
echo "-- launch phase medians --"
python3 - "$CSV" <<'PY'
import csv, statistics, sys
rows = list(csv.DictReader(open(sys.argv[1], newline="")))
def number(row, key):
    try:
        return float(row[key])
    except (KeyError, ValueError):
        return None
for mode in ("direct", "product"):
    subset = [row for row in rows if row["mode"] == mode]
    usable = [row for row in subset if number(row, "exec_ms") is not None]
    print(f"\n{mode}: {len(usable)} usable / {len(subset)}")
    for field in ("exec_ms", "netns_ms", "relay_ms", "launcher_ms", "session_ms", "app_ms"):
        values = [number(row, field) for row in usable]
        values = [v for v in values if v is not None]
        if values:
            values.sort()
            p90 = values[int(0.9 * (len(values) - 1))]
            print(f"   {field:12s} n={len(values):2d} med={statistics.median(values):7.1f}ms p90={p90:7.1f}ms")
PY
echo
echo "csv kept at $CSV"
