#!/usr/bin/env bash
#
# APP-scope HTTP latency: the D-50 relay path vs direct SOCKS to the same Tor.
#
# APP scope does not touch the machine-wide network, so this can run while SSH is up; it is
# still started detached for uniformity. Always disconnects.
set -uo pipefail

LOGDIR=/var/log/ghostnector-qual
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOGDIR/app-http-$STAMP.log"
OUT="$LOGDIR/app-http-$STAMP.samples.csv"
CORE_ENV_BAK=/var/tmp/gh-app-http-core.env.bak
CLI=(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector)
CLIENT=/usr/local/lib/gh-perf/perf-app-http-client.py
N="${1:-25}"

mkdir -p "$LOGDIR"
exec >>"$LOG" 2>&1
ln -sfn "$(basename "$LOG")" "$LOGDIR/app-http-latest.log"
echo "== APP HTTP latency at $(date -u), N=$N =="

cleanup() {
    local rc=$?
    echo "== cleanup at $(date -u) (rc=$rc) =="
    pkill -f "/usr/local/lib/gh-perf/perf-app-http-client.py" 2>/dev/null || true
    timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
    if [ -f "$CORE_ENV_BAK" ]; then
        cp -a "$CORE_ENV_BAK" /etc/ghostnector/core.env
    else
        rm -f /etc/ghostnector/core.env
    fi
    systemctl restart ghostnector-core.service 2>/dev/null || true
    echo "== final state =="
    "${CLI[@]}" status 2>&1 | head -3
    echo "== end of $LOG =="
    exit "$rc"
}
trap cleanup EXIT

[ "$(id -u)" = "0" ] || exit 2
timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
rm -f /var/lib/ghostnector/intent.json
[ -f /etc/ghostnector/core.env ] && cp -a /etc/ghostnector/core.env "$CORE_ENV_BAK"
cat >/etc/ghostnector/core.env <<'EOF'
GHOSTNECTOR_VERIFY=--udp-check 10.0.2.2:18081 --verify-timeout 10 --verify-interval 3600 --verify-stale-after 7200
EOF
systemctl restart ghostnector-netd.service ghostnector-core.service ghostnector-appd.service
sleep 2

connect_and_wait() {
    local attempt start
    for attempt in 1 2; do
        start="$(date +%s)"
        "${CLI[@]}" connect --scope app >/dev/null 2>&1 || true
        for _ in $(seq 1 180); do
            "${CLI[@]}" status 2>/dev/null | grep -q "chosen applications" && break
            sleep 1
        done
        echo "attempt $attempt: connect took $(( $(date +%s) - start ))s"
        "${CLI[@]}" status | head -3
        "${CLI[@]}" status 2>/dev/null | grep -q "chosen applications" && return 0
        timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
        sleep 3
    done
    return 1
}
if ! connect_and_wait; then
    echo "ABORT: APP scope did not come up"
    exit 1
fi

echo
echo "-- running the in-namespace client (relay vs direct SOCKS, same Tor) --"
: >"$OUT"
timeout 600 "${CLI[@]}" run -- python3 "$CLIENT" --iterations "$N" >"$OUT" 2>>"$LOG" || true
echo "sample lines: $(wc -l <"$OUT")"

# Remove the group the run created, so nothing stays behind between phases.
remove_groups() {
    local output id
    output="$(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector apps 2>/dev/null || true)"
    for id in $(echo "$output" | awk '/^  - /{print $2}'); do
        runuser -u ghost -g ghostnector -- /usr/bin/ghostnector stop-app "$id" >/dev/null 2>&1 || true
    done
}
remove_groups

echo
echo "-- summary --"
python3 - "$OUT" <<'PY'
import csv, statistics, sys
rows = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line or not line[0].isdigit():
        continue
    parts = line.split(",")
    if len(parts) != 13:
        continue
    rows.append(
        {
            "iter": parts[0],
            "route": parts[2],
            "ok": parts[3],
            "dns_ms": parts[4],
            "connect_ms": parts[5],
            "socks_ms": parts[6],
            "ttfb_ms": parts[7],
            "body_ms": parts[8],
            "total_ms": parts[9],
            "bytes": parts[10],
            "exit_ip": parts[11],
        }
    )

def num(row, key):
    try:
        return float(row[key])
    except (KeyError, ValueError):
        return None

for route in ("relay", "socks"):
    subset = [row for row in rows if row["route"] == route]
    usable = [row for row in subset if row["ok"] == "1"]
    print(f"-- {route}: {len(usable)} usable / {len(subset)}")
    for field in ("dns_ms", "connect_ms", "socks_ms", "ttfb_ms", "total_ms"):
        values = [num(row, field) for row in usable]
        values = [value for value in values if value is not None]
        if values:
            values.sort()
            print(f"   {field:10s} n={len(values):3d} p10={values[int(0.1*(len(values)-1))]:8.1f} "
                  f"med={statistics.median(values):8.1f} p90={values[int(0.9*(len(values)-1))]:8.1f}")
# paired by iteration
relay = {row["iter"]: row for row in rows if row["route"] == "relay" and row["ok"] == "1"}
socks = {row["iter"]: row for row in rows if row["route"] == "socks" and row["ok"] == "1"}
diffs = []
for iteration, row in relay.items():
    other = socks.get(iteration)
    if other is None:
        continue
    a, b = num(row, "total_ms"), num(other, "total_ms")
    if a is not None and b is not None:
        diffs.append(a - b)
if diffs:
    diffs.sort()
    print(f"paired relay - direct_socks (total_ms): n={len(diffs)} "
          f"p10={diffs[int(0.1*(len(diffs)-1))]:8.1f} med={statistics.median(diffs):8.1f} "
          f"p90={diffs[int(0.9*(len(diffs)-1))]:8.1f}")
PY
echo "samples kept at $OUT"
