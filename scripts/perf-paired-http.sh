#!/usr/bin/env bash
#
# H1: the paired, interleaved HTTP benchmark.
#
# Run this detached (systemd-run --property=RuntimeMaxSec=...) as root on the VM: connecting
# SYSTEM scope cuts SSH by design, and this script always disconnects on the way out.
#
# Three routes, measured in one protected window, interleaved in a fresh random order every
# iteration so Tor/circuit drift cannot systematically favour a route:
#
#   product     Ghostnector SYSTEM scope (DNS chokepoint -> Tor DNSPort; TransPort)
#   equivalent  standalone Tor with the same fundamental transparent shape (a low-priority
#               bench nft chain redirects a sample uid's DNS to its DNSPort and TCP to its
#               TransPort). This is the baseline the campaign cares about.
#   socks       curl-style SOCKS5 with the name handed to the standalone Tor (secondary
#               reference only; it is architecturally different, not the baseline)
#
# Raw samples go to a new durable file under /var/log/ghostnector-qual/; nothing that already
# exists there is touched. The script never writes to the repository.
#
# Usage: perf-paired-http.sh [N] [--quick]

set -uo pipefail

N="${1:-40}"
QUICK=0
SAME_INSTANCE=0
for argument in "${@:2}"; do
    case "$argument" in
        --quick) QUICK=1 ;;
        --same-instance) SAME_INSTANCE=1 ;;
        *) echo "unknown option: $argument" >&2; exit 2 ;;
    esac
done
if [ "$SAME_INSTANCE" = "1" ]; then
    VARIANT="same-instance (equivalent route reaches the product's own Tor: isolates Ghostnector's increment)"
    SOCKS_PORT=9050
    EQUIV_DNS_PORT=9053
    EQUIV_TCP_PORT=9040
else
    VARIANT="two-instance (equivalent route reaches a standalone Tor: Tor variance is included)"
    SOCKS_PORT=19050
    EQUIV_DNS_PORT=19053
    EQUIV_TCP_PORT=19040
fi

LOGDIR=/var/log/ghostnector-qual
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOGDIR/paired-http-$STAMP.log"
SAMPLES="$LOGDIR/paired-http-$STAMP.samples.csv"
SUMMARY="$LOGDIR/paired-http-$STAMP.summary.txt"
BASELINE_DIR=/var/tmp/gh-paired-tor
BASELINE_TORRC=/var/tmp/gh-paired-torrc
BASELINE_PID=""
CORE_ENV_BAK=/var/tmp/gh-paired-core.env.bak
CLIENT=/usr/local/lib/gh-perf/perf-paired-client.py
SUMMARY_TOOL=/usr/local/lib/gh-perf/perf-paired-summary.py
RESOURCES=/usr/local/lib/gh-perf/perf-resources.py
CLI=(runuser -u ghost -g ghostnector -- /usr/bin/ghostnector)
SAMPLE_UID=65534
HTTP_HOST=checkip.amazonaws.com
DL_HOST=ipv4.download.thinkbroadband.com
DL_PATH=/1MB.zip

mkdir -p "$LOGDIR"
exec >>"$LOG" 2>&1
ln -sfn "$(basename "$LOG")" "$LOGDIR/paired-latest.log"
echo "== paired HTTP benchmark at $(date -u), N=$N =="
echo "variant: $VARIANT"
echo "log: $LOG"
echo "samples: $SAMPLES"
uname -a

cleanup() {
    local rc=$?
    echo
    echo "== cleanup at $(date -u) (rc=$rc) =="
    nft delete table inet ghperfbench 2>/dev/null || true
    if [ -n "$BASELINE_PID" ]; then
        kill "$BASELINE_PID" 2>/dev/null || true
        wait "$BASELINE_PID" 2>/dev/null || true
    fi
    pkill -f "gh-paired-torrc" 2>/dev/null || true
    timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
    if nft list table inet ghostnector >/dev/null 2>&1; then
        nft destroy table inet ghostnector >>"$LOG" 2>&1 || true
    fi
    if [ -f /var/lib/ghostnector/intent.json ] \
        && grep -q '"protected"[[:space:]]*:[[:space:]]*true' /var/lib/ghostnector/intent.json; then
        rm -f /var/lib/ghostnector/intent.json
    fi
    # Restore the verification configuration even on an aborted or killed run.
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

[ "$(id -u)" = "0" ] || { echo "this benchmark needs root"; exit 2; }

# ------------------------------------------------------------------ a clean, off baseline
echo
echo "-- reset to off --"
timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
nft destroy table inet ghostnector 2>/dev/null || true
rm -f /var/lib/ghostnector/intent.json
[ -f /etc/ghostnector/core.env ] && cp -a /etc/ghostnector/core.env "$CORE_ENV_BAK"

# The verifier needs an endpoint that answers 200 through whatever path it is given. It is
# validated directly (machine is open here), then pinned exactly as the installed
# qualification does.
check_endpoint() {
    local candidate code
    for candidate in $(getent ahostsv4 "$HTTP_HOST" | awk '{print $1}'); do
        code="$(timeout 15 curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$candidate/" || true)"
        [ "$code" = "200" ] && { echo "$candidate"; return 0; }
    done
    getent ahostsv4 "$HTTP_HOST" | awk 'NR==1{print $1}'
}
HTTP_IP="$(check_endpoint)"
echo "verification endpoint: http://$HTTP_IP/"
cat >/etc/ghostnector/core.env <<EOF
GHOSTNECTOR_VERIFY=--udp-check 10.0.2.2:18081 --check-url http://$HTTP_IP/ --verify-timeout 10 --verify-interval 3600 --verify-stale-after 7200
EOF
systemctl restart ghostnector-netd.service ghostnector-core.service ghostnector-appd.service
sleep 2
"${CLI[@]}" status | head -1

# ------------------------------------------------------------------ the equivalent baseline Tor
echo
if [ "$SAME_INSTANCE" = "1" ]; then
    echo "-- same-instance mode: no standalone Tor; the equivalent route reaches the product's Tor --"
else
    echo "-- baseline: standalone Tor, same transparent shape --"
    rm -rf "$BASELINE_DIR"
    mkdir -p "$BASELINE_DIR"
    chown debian-tor:debian-tor "$BASELINE_DIR"
    chmod 700 "$BASELINE_DIR"
    cat >"$BASELINE_TORRC" <<EOF
SocksPort 127.0.0.1:19050
TransPort 127.0.0.1:19040
DNSPort 127.0.0.1:19053
DataDirectory $BASELINE_DIR
Log notice file $BASELINE_DIR/tor.log
ClientOnly 1
CookieAuthentication 0
ClientUseIPv6 0
AutomapHostsOnResolve 1
VirtualAddrNetworkIPv4 10.192.0.0/10
AvoidDiskWrites 1
EOF
    chown debian-tor:debian-tor "$BASELINE_TORRC"
    runuser -u debian-tor -- timeout 1200 tor -f "$BASELINE_TORRC" >/dev/null 2>&1 &
    BASELINE_PID=$!
    for _ in $(seq 1 300); do
        grep -q "Bootstrapped 100" "$BASELINE_DIR/tor.log" 2>/dev/null && break
        sleep 1
    done
    if grep -q "Bootstrapped 100" "$BASELINE_DIR/tor.log" 2>/dev/null; then
        echo "baseline Tor bootstrapped"
    else
        echo "baseline Tor did NOT bootstrap; the equivalent route will fail and the run is unusable"
    fi
fi

# The bench chain deliberately runs at priority -150, before the product's nat chain at -100,
# so the sample uid's traffic reaches the equivalent Tor no matter what the product redirects.
# It matches exactly one uid and nothing else.
nft -f - <<EOF
table inet ghperfbench {
    chain out_nat {
        type nat hook output priority -150; policy accept;
        meta skuid 65534 udp dport 53 counter redirect to :$EQUIV_DNS_PORT comment "bench equivalent-path DNS"
        meta skuid 65534 tcp dport 53 counter redirect to :$EQUIV_DNS_PORT comment "bench equivalent-path DNS"
        meta skuid 65534 meta l4proto tcp counter redirect to :$EQUIV_TCP_PORT comment "bench equivalent-path TCP"
    }
}
EOF
echo "bench chain installed (uid $SAMPLE_UID -> DNSPort $EQUIV_DNS_PORT, TransPort $EQUIV_TCP_PORT)"

# ------------------------------------------------------------------ connect the product
echo
echo "-- connect: Ghostnector SYSTEM scope --"
connect_and_verify() {
    local attempt start
    for attempt in 1 2; do
        start="$(date +%s)"
        "${CLI[@]}" connect >/dev/null 2>&1 || true
        for _ in $(seq 1 240); do
            if "${CLI[@]}" status 2>/dev/null | head -1 | grep -q "protected — and verified"; then
                break
            fi
            sleep 1
        done
        echo "attempt $attempt: connect took $(( $(date +%s) - start ))s"
        "${CLI[@]}" status | head -3
        if "${CLI[@]}" status 2>/dev/null | head -1 | grep -q "protected — and verified"; then
            return 0
        fi
        # The product's own connect either timed out (Tor bootstrap) or verification failed
        # and it failed closed. Roll back and try once more; Tor guard selection is not
        # deterministic and a stalled bootstrap is not a property of this benchmark.
        timeout 90 "${CLI[@]}" disconnect >/dev/null 2>&1 || true
        sleep 3
    done
    return 1
}
if ! connect_and_verify; then
    echo "ABORT: the product never reached 'protected — and verified'; no samples were taken"
    exit 1
fi

# ------------------------------------------------------------------ warmups and samples
sample() { # iteration route tag extra...
    local iteration="$1" route="$2" tag="$3"
    shift 3
    local line
    case "$route" in
        product)
            line="$(runuser -u ghost -g ghostnector -- timeout 40 python3 "$CLIENT" \
                --route product --iter "$iteration" --tag "$tag" "$@" 2>/dev/null)" ;;
        equivalent)
            line="$(runuser -u nobody -- timeout 40 python3 "$CLIENT" \
                --route equivalent --iter "$iteration" --tag "$tag" "$@" 2>/dev/null)" ;;
        socks)
            line="$(timeout 40 python3 "$CLIENT" \
                --route socks --iter "$iteration" --tag "$tag" --socks-port "$SOCKS_PORT" "$@" 2>/dev/null)" ;;
        *)
            echo "unknown route $route" >&2; return 1 ;;
    esac
    [ -n "$line" ] && echo "$line" >>"$SAMPLES"
}

echo
echo "-- warmups (3 rounds, not recorded) --"
for round in 1 2 3; do
    for route in $(printf '%s\n' product equivalent socks | shuf); do
        sample 0 "$route" warmup --host "$HTTP_HOST" --port 80
    done
done

echo
echo "-- recording $N rounds, route order randomized per round --"
echo "iter,epoch,route,ok,dns_ms,connect_ms,socks_ms,ttfb_ms,body_ms,total_ms,bytes,exit_ip,note" >"$SAMPLES"
for iteration in $(seq 1 "$N"); do
    for route in $(printf '%s\n' product equivalent socks | shuf); do
        sample "$iteration" "$route" latency --host "$HTTP_HOST" --port 80
        tail -n 1 "$SAMPLES" | sed 's/^/    /'
    done
done

# ------------------------------------------------------------------ throughput, interleaved
echo
echo "-- throughput: $DL_HOST$DL_PATH, 3 interleaved rounds per route --"
for iteration in 1 2 3; do
    for route in $(printf '%s\n' product equivalent socks | shuf); do
        sample "$iteration" "$route" throughput \
            --host "$DL_HOST" --http-path "$DL_PATH" --port 80 --timeout 60
        tail -n 1 "$SAMPLES" | sed 's/^/    /'
    done
done

# ------------------------------------------------------------------ corrected resources
if [ "$QUICK" = "0" ]; then
    echo
    echo "-- corrected idle resources (60 s, no status polling during the window) --"
    python3 "$RESOURCES" --label "SYSTEM protected idle (product) [$VARIANT]" \
        --seconds 60 --match product 2>&1 | tee -a "$SUMMARY"
    if [ "$SAME_INSTANCE" = "0" ]; then
        python3 "$RESOURCES" --label "baseline Tor idle" --seconds 60 --match baseline 2>&1 | tee -a "$SUMMARY"
    fi
fi

# ------------------------------------------------------------------ summary and teardown
echo
echo "-- summary --"
python3 "$SUMMARY_TOOL" "$SAMPLES" | tee -a "$SUMMARY"

echo
echo "-- disconnect --"
"${CLI[@]}" disconnect >/dev/null 2>&1 || true
nft delete table inet ghperfbench 2>/dev/null || true
if [ -n "$BASELINE_PID" ]; then
    kill "$BASELINE_PID" 2>/dev/null || true
    pkill -f "gh-paired-torrc" 2>/dev/null || true
    wait "$BASELINE_PID" 2>/dev/null || true
    BASELINE_PID=""
fi
if [ -f "$CORE_ENV_BAK" ]; then
    cp -a "$CORE_ENV_BAK" /etc/ghostnector/core.env
else
    rm -f /etc/ghostnector/core.env
fi
systemctl restart ghostnector-core.service
echo "samples kept at $SAMPLES"
echo "summary kept at $SUMMARY"
