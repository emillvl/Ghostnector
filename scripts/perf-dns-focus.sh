#!/usr/bin/env bash
#
# Focused protected-session DNS diagnostic.
#
# 1. chokepoint vs DNSPort directly, both on the product's own Tor, alternating in one
#    process as root (no NAT, no uid policy): isolates the relay process itself.
# 2. the exact benchmark shape: ghost -> 8.8.8.8:53 (product chain -> chokepoint) vs
#    nobody -> 8.8.8.8:53 (bench chain -> DNSPort), alternating per query, plus the
#    root direct-to-DNSPort reference.
#
# Detached; always disconnects.
set -uo pipefail

LOGDIR=/var/log/ghostnector-qual
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOGDIR/dns-focus-$STAMP.log"
CSV="$LOGDIR/dns-focus-$STAMP.csv"
CORE_ENV_BAK=/var/tmp/gh-dns-focus-core.env.bak
CLI=(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector)
NAME=checkip.amazonaws.com
N="${1:-150}"

mkdir -p "$LOGDIR"
exec >>"$LOG" 2>&1
ln -sfn "$(basename "$LOG")" "$LOGDIR/dns-focus-latest.log"
echo "== DNS focus at $(date -u), N=$N =="

cleanup() {
    local rc=$?
    echo "== cleanup at $(date -u) (rc=$rc) =="
    nft delete table inet ghperfbench 2>/dev/null || true
    timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
    if [ -f "$CORE_ENV_BAK" ]; then
        cp -a "$CORE_ENV_BAK" /etc/ghostnector/core.env
    else
        rm -f /etc/ghostnector/core.env
    fi
    systemctl restart ghostnector-core.service 2>/dev/null || true
    echo "== end of $LOG =="
    exit "$rc"
}
trap cleanup EXIT

[ "$(id -u)" = "0" ] || exit 2
timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
nft destroy table inet ghostnector 2>/dev/null || true
rm -f /var/lib/ghostnector/intent.json
[ -f /etc/ghostnector/core.env ] && cp -a /etc/ghostnector/core.env "$CORE_ENV_BAK"
cat >/etc/ghostnector/core.env <<'EOF'
GHOSTNECTOR_VERIFY=--udp-check 10.0.2.2:18081 --verify-timeout 10 --verify-interval 3600 --verify-stale-after 7200
EOF
systemctl restart ghostnector-netd.service ghostnector-core.service ghostnector-appd.service
sleep 2

connect_and_verify() {
    local attempt start
    for attempt in 1 2; do
        start="$(date +%s)"
        "${CLI[@]}" connect >/dev/null 2>&1 || true
        for _ in $(seq 1 240); do
            "${CLI[@]}" status 2>/dev/null | head -1 | grep -q "protected" && break
            sleep 1
        done
        echo "attempt $attempt: connect took $(( $(date +%s) - start ))s"
        "${CLI[@]}" status | head -1
        "${CLI[@]}" status 2>/dev/null | head -1 | grep -q "protected" && return 0
        timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
        sleep 3
    done
    return 1
}
if ! connect_and_verify; then
    echo "ABORT: not protected"
    exit 1
fi

echo
echo "-- A: chokepoint (127.0.0.1:53) vs DNSPort (127.0.0.1:9053), root, alternating --"
tcpdump -i lo -n -s 0 -w /tmp/dns-focus-a.pcap 'udp and (port 53 or port 9053)' >/dev/null 2>&1 &
TCPDUMP_A=$!
sleep 1
python3 /usr/local/lib/gh-perf/perf-dns-ab.py --direct 127.0.0.1:9053 --via 127.0.0.1:53 \
    --name "$NAME" --n "$N"
sleep 1
kill "$TCPDUMP_A" 2>/dev/null || true
wait "$TCPDUMP_A" 2>/dev/null || true
cp /tmp/dns-focus-a.pcap "$LOGDIR/dns-focus-$STAMP-a.pcap" 2>/dev/null || true
python3 /usr/local/lib/gh-perf/perf-pcap-dns.py /tmp/dns-focus-a.pcap 2>/dev/null || true

echo
echo "-- B: NAT-shaped, alternating per query --"
nft -f - <<'EOF'
table inet ghperfbench {
    chain out_nat {
        type nat hook output priority -150; policy accept;
        meta skuid 65534 udp dport 53 counter redirect to :9053 comment "bench equivalent"
        meta skuid 65534 meta l4proto tcp counter redirect to :9040 comment "bench equivalent"
    }
}
EOF
: >"$CSV"
echo "iter,user,resolver,ms,tag" >>"$CSV"
tcpdump -i lo -n -s 0 -w /tmp/dns-focus-b.pcap 'udp and (port 53 or port 9053)' >/dev/null 2>&1 &
TCPDUMP_B=$!
sleep 1
for iteration in $(seq 1 "$N"); do
    runuser -u ghost -- timeout 20 python3 /usr/local/lib/gh-perf/perf-dns-once.py \
        --resolver 8.8.8.8:53 --name "$NAME" --iter "$iteration" --tag product >>"$CSV"
    runuser -u nobody -- timeout 20 python3 /usr/local/lib/gh-perf/perf-dns-once.py \
        --resolver 8.8.8.8:53 --name "$NAME" --iter "$iteration" --tag equivalent >>"$CSV"
    timeout 20 python3 /usr/local/lib/gh-perf/perf-dns-once.py \
        --resolver 127.0.0.1:9053 --name "$NAME" --iter "$iteration" --tag direct >>"$CSV"
done
sleep 1
kill "$TCPDUMP_B" 2>/dev/null || true
wait "$TCPDUMP_B" 2>/dev/null || true
cp /tmp/dns-focus-b.pcap "$LOGDIR/dns-focus-$STAMP-b.pcap" 2>/dev/null || true
python3 /usr/local/lib/gh-perf/perf-pcap-dns.py /tmp/dns-focus-b.pcap 2>/dev/null || true
python3 - "$CSV" <<'PY'
import csv, statistics, sys
rows = list(csv.DictReader(open(sys.argv[1], newline="")))
for tag in ("product", "equivalent", "direct"):
    values = []
    for row in rows:
        if row["tag"] == tag and row["ms"] != "timeout":
            values.append(float(row["ms"]))
    if values:
        values.sort()
        print(f"{tag:12s} n={len(values):3d} p10={values[int(0.1*(len(values)-1))]:8.1f} "
              f"med={statistics.median(values):8.1f} p90={values[int(0.9*(len(values)-1))]:8.1f}")
product = {row["iter"]: row for row in rows if row["tag"] == "product"}
equivalent = {row["iter"]: row for row in rows if row["tag"] == "equivalent"}
differences = []
for iteration, row in product.items():
    other = equivalent.get(iteration)
    if other and row["ms"] != "timeout" and other["ms"] != "timeout":
        differences.append(float(row["ms"]) - float(other["ms"]))
if differences:
    differences.sort()
    print(f"paired product-equivalent: n={len(differences)} "
          f"p10={differences[int(0.1*(len(differences)-1))]:8.1f} "
          f"med={statistics.median(differences):8.1f} "
          f"p90={differences[int(0.9*(len(differences)-1))]:8.1f}")
PY
echo "csv at $CSV"
