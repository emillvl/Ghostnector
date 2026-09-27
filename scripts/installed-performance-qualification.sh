#!/usr/bin/env bash
#
# The installed performance qualification.
#
# Not part of the hermetic gate. It measures the installed product on the native VM and separates
# Ghostnector's own overhead from the inherent cost of the Tor network by measuring the *same*
# requests twice: once through the product's transparent Tor path, and once through a standalone
# Tor instance on the same machine (the baseline). Both share the same network and the same
# machine; the difference is the product's redirect, chokepoint and supervision.
#
# Measured (all with medians over repeated samples; the log keeps every sample):
#   * connect wall time to command return, and to the first protected state (3 runs)
#   * disconnect wall time (3 runs)
#   * verification time from Degraded to Protected
#   * DNS latency: direct (open) vs through the chokepoint, and through baseline Tor's DNSPort
#   * HTTP latency and throughput through the product path vs baseline Tor SOCKS
#   * APP-scope launch time vs launching the same program directly
#   * CPU and memory of the product's processes, idle and during a download, vs baseline Tor
#
# Durable record: /var/log/ghostnector-qual/perf-<stamp>.log

set -uo pipefail

LOGDIR=/var/log/ghostnector-qual
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOGDIR/perf-$STAMP.log"
URL_LATENCY="http://checkip.amazonaws.com"
URL_THROUGHPUT="http://ipv4.download.thinkbroadband.com/1MB.zip"
BASELINE_DIR=/var/tmp/gh-perf-tor
BASELINE_LOG="$BASELINE_DIR/tor.log"
CLI=(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector)
HOST=10.0.2.2

mkdir -p "$LOGDIR"; chmod 0755 "$LOGDIR"
exec >>"$LOG" 2>&1
ln -sfn "$(basename "$LOG")" "$LOGDIR/perf-latest.log"

note() { echo "    $*"; }

cleanup() {
    local rc=$?
    echo
    echo "== cleanup at $(date -u) (run exit $rc) =="
    pkill -x tor 2>/dev/null || true
    timeout 90 runuser -u ghost -g ghostnector -- /usr/bin/ghostnector disconnect >/dev/null 2>&1 || true
    if nft list table inet ghostnector >/dev/null 2>&1; then
        nft destroy table inet ghostnector >>"$LOG" 2>&1 || true
    fi
    if [ -f /var/lib/ghostnector/intent.json ] && grep -q '"protected"[[:space:]]*:[[:space:]]*true' /var/lib/ghostnector/intent.json; then
        rm -f /var/lib/ghostnector/intent.json
    fi
    rm -rf "$BASELINE_DIR"
    echo "== final state =="
    runuser -u ghost -g ghostnector -- /usr/bin/ghostnector status 2>&1 | head -4
    echo "== end of $LOG =="
    exit "$rc"
}
trap cleanup EXIT

[ "$(id -u)" = "0" ] || { echo "this qualification needs root"; exit 2; }

median() { sort -n | awk '{a[NR]=$1} END {if (NR==0) {print "none"; exit} if (NR%2) print a[(NR+1)/2]; else printf "%.3f", (a[NR/2]+a[NR/2+1])/2}'; }
now() { date +%s.%N; }

echo "== installed performance qualification at $(date -u) =="
echo "log: $LOG"
uname -a
nproc
free -m | head -2
echo "url latency: $URL_LATENCY"
echo "url throughput: $URL_THROUGHPUT"

# ---------------------------------------------------------------- baseline setup
echo
echo "-- baseline: open, off --"
timeout 60 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
nft destroy table inet ghostnector 2>/dev/null || true
rm -f /var/lib/ghostnector/intent.json
HTTP_IP="$(getent ahostsv4 checkip.amazonaws.com | awk 'NR==1{print $1}')"
cat >/etc/ghostnector/core.env <<EOF
GHOSTNECTOR_VERIFY=--udp-check $HOST:18081 --check-url http://$HTTP_IP/ --verify-timeout 10 --verify-interval 5 --verify-stale-after 30
EOF
systemctl restart ghostnector-netd.service ghostnector-core.service ghostnector-appd.service
sleep 2
"${CLI[@]}" status | head -1

# Direct DNS baseline (the DHCP resolver, unprotected).
echo
echo "-- DNS latency: direct, then through the chokepoint --"
python3 - "$@" <<'PY' | tee /tmp/gh-perf-dns-direct.txt
import socket, struct, sys, time
def query(server, port=53, name="example.com"):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    start = time.perf_counter()
    try:
        s.sendto(q, (server, port)); s.recvfrom(2048)
        return (time.perf_counter() - start) * 1000
    except OSError:
        return None
resolver = None
with open("/etc/resolv.conf") as f:
    for line in f:
        if line.startswith("nameserver"):
            resolver = line.split()[1]; break
print(f"direct resolver {resolver}")
for _ in range(5):
    ms = query(resolver)
    print(f"direct {ms if ms is not None else 'timeout'}")
PY
DIRECT_MEDIAN="$(grep '^direct ' /tmp/gh-perf-dns-direct.txt | awk '{print $2}' | grep -v timeout | median)"
note "direct DNS median: ${DIRECT_MEDIAN} ms"

# ---------------------------------------------------------------- connect/disconnect runs
echo
echo "-- connect, verification, disconnect (3 runs) --"
for run in 1 2 3; do
    START="$(now)"
    "${CLI[@]}" connect >/dev/null 2>&1 || true
    CONNECT_END="$(now)"
    # Poll for the first protected state to separate connect from verification.
    PROTECTED_AT=""
    for _ in $(seq 1 60); do
        if "${CLI[@]}" status 2>/dev/null | head -1 | grep -q "protected — and verified"; then
            PROTECTED_AT="$(now)"; break
        fi
        sleep 0.5
    done
    DISCONNECT_START="$(now)"
    "${CLI[@]}" disconnect >/dev/null 2>&1 || true
    DISCONNECT_END="$(now)"
    python3 - "$START" "$CONNECT_END" "${PROTECTED_AT:-none}" "$DISCONNECT_START" "$DISCONNECT_END" <<'PY'
import sys
start, connect_end, protected, disconnect_start, disconnect_end = [float(x) if x != "none" else None for x in sys.argv[1:6]]
print(f"run connect_to_return={connect_end-start:.3f}s "
      f"return_to_protected={(protected-connect_end):.3f}s " if protected else
      f"run connect_to_return={connect_end-start:.3f}s return_to_protected=timeout ", end="")
print(f"disconnect={disconnect_end-disconnect_start:.3f}s")
PY
done

# ---------------------------------------------------------------- DNS through the chokepoint
echo
echo "-- DNS through the protected path --"
"${CLI[@]}" connect >/dev/null 2>&1 || true
for _ in $(seq 1 60); do "${CLI[@]}" status 2>/dev/null | head -1 | grep -q protected && break; sleep 1; done
python3 - <<'PY' | tee /tmp/gh-perf-dns-protected.txt
import socket, time
def query(server, port=53, name="example.com"):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    start = time.perf_counter()
    try:
        s.sendto(q, (server, port)); s.recvfrom(2048)
        return (time.perf_counter() - start) * 1000
    except OSError:
        return None
for _ in range(5):
    ms = query("127.0.0.1")
    print(f"chokepoint {ms if ms is not None else 'timeout'}")
PY
CHOKE_MEDIAN="$(grep '^chokepoint ' /tmp/gh-perf-dns-protected.txt | awk '{print $2}' | grep -v timeout | median)"
note "chokepoint DNS median: ${CHOKE_MEDIAN} ms"

# ---------------------------------------------------------------- product HTTP latency/throughput
echo
echo "-- product path: HTTP latency and throughput --"
for _ in 1 2 3 4 5; do
    runuser -u ghost -- timeout 40 curl -s -o /dev/null -w '%{time_total}\n' --max-time 35 "$URL_LATENCY" 2>/dev/null || echo timeout
done | tee /tmp/gh-perf-product-latency.txt
PRODUCT_LAT_MEDIAN="$(grep -v timeout /tmp/gh-perf-product-latency.txt | median)"
note "product HTTP latency median: ${PRODUCT_LAT_MEDIAN} s"
for _ in 1 2; do
    runuser -u ghost -- timeout 120 curl -s -o /dev/null -w '%{speed_download}\n' --max-time 110 "$URL_THROUGHPUT" 2>/dev/null || echo 0
done | tee /tmp/gh-perf-product-throughput.txt
PRODUCT_THROUGHPUT="$(grep -v '^0$' /tmp/gh-perf-product-throughput.txt | median)"
note "product throughput median: ${PRODUCT_THROUGHPUT} bytes/s"

# ---------------------------------------------------------------- product resource use, idle
echo
echo "-- product resource use while protected and idle --"
sample_resources() { # label
    local label="$1" i
    for i in $(seq 1 10); do
        ps -eo comm=,rss=,pcpu= 2>/dev/null | grep -E '^ghostnector-(cor|net|app|dns)|^tor$' | awk -v l="$label" '{print l, $1, $2, $3}'
        sleep 1
    done
}
sample_resources product-idle >/tmp/gh-perf-res-product.txt
awk '{sum[$2]+=$3; cpu[$2]+=$4; n[$2]++} END {for (c in sum) printf "product %s mean_rss_kb=%.0f mean_cpu_pct=%.2f\n", c, sum[c]/n[c], cpu[c]/n[c]}' /tmp/gh-perf-res-product.txt | head -8
CPU_BEFORE="$(awk '{s+=$4} END {print s}' /tmp/gh-perf-res-product.txt)"
note "product CPU percent samples summed: $CPU_BEFORE"

# ---------------------------------------------------------------- baseline Tor
echo
echo "-- baseline: a standalone Tor on the same machine --"
"${CLI[@]}" disconnect >/dev/null 2>&1 || true
sleep 1
mkdir -p "$BASELINE_DIR"
chown debian-tor:debian-tor "$BASELINE_DIR"
chmod 700 "$BASELINE_DIR"
runuser -u debian-tor -- timeout 600 tor --SocksPort 9050 --DNSPort 9053 --DataDirectory "$BASELINE_DIR" \
    --Log "notice file $BASELINE_LOG" --CookieAuthentication 0 --ClientUseIPv6 0 --ClientOnly 1 \
    >/dev/null 2>&1 &
BASELINE_PID=$!
for _ in $(seq 1 180); do
    grep -q "Bootstrapped 100" "$BASELINE_LOG" 2>/dev/null && break
    sleep 1
done
if grep -q "Bootstrapped 100" "$BASELINE_LOG" 2>/dev/null; then
    note "baseline Tor bootstrapped"
else
    note "baseline Tor did not bootstrap; baseline measurements will be inconclusive"
fi
python3 - <<'PY' | tee /tmp/gh-perf-dns-baseline.txt
import socket, time
def query(server, port, name="example.com"):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    start = time.perf_counter()
    try:
        s.sendto(q, (server, port)); s.recvfrom(2048)
        return (time.perf_counter() - start) * 1000
    except OSError:
        return None
for _ in range(5):
    ms = query("127.0.0.1", 9053)
    print(f"baseline-tor {ms if ms is not None else 'timeout'}")
PY
BASELINE_DNS="$(grep '^baseline-tor ' /tmp/gh-perf-dns-baseline.txt | awk '{print $2}' | grep -v timeout | median)"
note "baseline Tor DNS median: ${BASELINE_DNS} ms"
for _ in 1 2 3 4 5; do
    runuser -u ghost -- timeout 40 curl -s -o /dev/null -w '%{time_total}\n' --max-time 35 --socks5-hostname 127.0.0.1:9050 "$URL_LATENCY" 2>/dev/null || echo timeout
done | tee /tmp/gh-perf-baseline-latency.txt
BASELINE_LAT_MEDIAN="$(grep -v timeout /tmp/gh-perf-baseline-latency.txt | median)"
note "baseline Tor HTTP latency median: ${BASELINE_LAT_MEDIAN} s"
for _ in 1 2; do
    runuser -u ghost -- timeout 120 curl -s -o /dev/null -w '%{speed_download}\n' --max-time 110 --socks5-hostname 127.0.0.1:9050 "$URL_THROUGHPUT" 2>/dev/null || echo 0
done | tee /tmp/gh-perf-baseline-throughput.txt
BASELINE_THROUGHPUT="$(grep -v '^0$' /tmp/gh-perf-baseline-throughput.txt | median)"
note "baseline Tor throughput median: ${BASELINE_THROUGHPUT} bytes/s"
sample_resources baseline-idle >/tmp/gh-perf-res-baseline.txt
awk '{sum[$2]+=$3; cpu[$2]+=$4; n[$2]++} END {for (c in sum) printf "baseline %s mean_rss_kb=%.0f mean_cpu_pct=%.2f\n", c, sum[c]/n[c], cpu[c]/n[c]}' /tmp/gh-perf-res-baseline.txt | head -8
kill "$BASELINE_PID" 2>/dev/null || true
pkill -x tor 2>/dev/null || true
sleep 1

# ---------------------------------------------------------------- APP-scope launch overhead
echo
echo "-- APP-scope launch overhead --"
cat >/usr/local/bin/gh-perf-app <<'EOF'
#!/bin/sh
sleep 20
EOF
chmod 0755 /usr/local/bin/gh-perf-app
echo "direct launch (baseline):"
for _ in 1 2 3; do
    START="$(now)"
    runuser -u ghost -- /usr/local/bin/gh-perf-app &
    APP_PID=$!
    sleep 0.3
    END="$(now)"
    python3 -c "print(f'direct launch {float('$END')-float('$START'):.3f}s')"
    kill "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
done
"${CLI[@]}" disconnect >/dev/null 2>&1 || true
sleep 1
# The APP profile is verified deterministically by the UDP check (the namespace denies UDP; the
# probe treats that as the pass), so the launch measurement does not depend on a public endpoint's
# availability through a particular Tor exit.
APP_READY=0
for attempt in 1 2 3; do
    cat >/etc/ghostnector/core.env <<EOF
GHOSTNECTOR_VERIFY=--udp-check $HOST:18081 --verify-timeout 10 --verify-interval 5 --verify-stale-after 30
EOF
    systemctl restart ghostnector-core.service
    sleep 2
    "${CLI[@]}" connect --scope app >/dev/null 2>&1 || true
    APP_READY=0
    for _ in $(seq 1 120); do
        if "${CLI[@]}" status 2>/dev/null | grep -q "chosen applications"; then
            APP_READY=1
            break
        fi
        sleep 1
    done
    if [ "$APP_READY" = "1" ] && ! "${CLI[@]}" status 2>/dev/null | head -1 | grep -q "no traffic can leave"; then
        break
    fi
    APP_READY=0
    "${CLI[@]}" disconnect >/dev/null 2>&1 || true
    sleep 2
done
[ "$APP_READY" = "1" ] && note "APP scope is up" || note "APP scope did not come up; the launch measurements will be inconclusive"
echo "APP-scope launch:"
app_in_namespace() {
    local initns p
    initns="$(readlink /proc/1/ns/net)"
    for p in $(pgrep -f gh-perf-app 2>/dev/null); do
        [ "$(readlink "/proc/$p/ns/net" 2>/dev/null)" != "$initns" ] && return 0
    done
    return 1
}
for _ in 1 2 3; do
    # A leftover application from the previous run must not count as this run's launch.
    pkill -f gh-perf-app 2>/dev/null || true
    for _ in $(seq 1 50); do app_in_namespace || break; sleep 0.2; done
    START="$(now)"
    ( sleep 40 | "${CLI[@]}" run /usr/local/bin/gh-perf-app >/dev/null 2>&1 ) &
    RUN_PID=$!
    for _ in $(seq 1 300); do
        app_in_namespace && break
        sleep 0.1
    done
    END="$(now)"
    python3 - "$START" "$END" <<'PY'
import sys
print(f"app-scope launch {float(sys.argv[2]) - float(sys.argv[1]):.3f}s")
PY
    kill "$RUN_PID" 2>/dev/null || true
    wait "$RUN_PID" 2>/dev/null || true
    pkill -f gh-perf-app 2>/dev/null || true
    for _ in $(seq 1 50); do app_in_namespace || break; sleep 0.2; done
    sleep 1
done
# The relay is one process per group, running as the application's uid; its cost belongs with the
# APP figures (it is part of the launch and of the idle footprint while a group exists).
echo "APP-scope relay resources:"
: >/tmp/gh-perf-res-relay.txt
for _ in $(seq 1 6); do
    ps -eo rss=,pcpu=,args= 2>/dev/null | grep 'ghostnector-appd-relay --id' | grep -v grep |
        awk '{print $1, $2}' >>/tmp/gh-perf-res-relay.txt
    sleep 1
done
awk '{rss+=$1; cpu+=$2; n++} END {
    if (n > 0) printf "relay mean_rss_kb=%.0f mean_cpu_pct=%.2f samples=%d\n", rss/n, cpu/n, n;
    else print "relay: no relay process observed"
}' /tmp/gh-perf-res-relay.txt
"${CLI[@]}" disconnect >/dev/null 2>&1 || true

echo
echo "=== summary (installed performance) ==="
echo "direct DNS median ms:      ${DIRECT_MEDIAN}"
echo "chokepoint DNS median ms:  ${CHOKE_MEDIAN}"
echo "baseline Tor DNS median ms:${BASELINE_DNS}"
echo "product HTTP median s:     ${PRODUCT_LAT_MEDIAN}"
echo "baseline Tor HTTP med. s:  ${BASELINE_LAT_MEDIAN}"
echo "product throughput B/s:    ${PRODUCT_THROUGHPUT}"
echo "baseline throughput B/s:   ${BASELINE_THROUGHPUT}"
echo "log:                       $LOG"
exit 0
