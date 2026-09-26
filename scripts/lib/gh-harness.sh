#!/usr/bin/env bash
#
# Shared harness for adversarial testing.
#
# It builds a small, fully controlled network:
#
#   ┌───────────────── gh-mut (the machine under test) ─────────────────┐
#   │  10.88.0.2   the machine's own address                            │
#   │  10.88.0.3   the Tor conduit: the *only* thing that reaches out   │
#   │  fd00:88::2  the same, over IPv6                                  │
#   │  loopback:   fake Tor control + TransPort, fake DNS, the relay    │
#   └───────────────────────────────┬───────────────────────────────────┘
#                                   │ veth
#   ┌───────────────── gh-out ("the internet") ─────────────────────────┐
#   │  10.88.0.1  fd00:88::1   recording endpoints + nft counters       │
#   └───────────────────────────────────────────────────────────────────┘
#
# Two properties make the observations meaningful:
#
#   1. **Traffic from the machine's own address is the leak signal.** A protected application's
#      packets are redirected into loopback, so anything arriving at the outside world from
#      10.88.0.2 or fd00:88::2 has left by a path the design forbids.
#   2. **The Tor conduit is a separate identity that is allowed out.** The fake Tor runs as the
#      exempted uid and binds 10.88.0.3, so its own onward connections are expected and are counted
#      separately. Without that split, the harness could not tell "the conduit is working" from
#      "something leaked" - which is precisely the mistake this harness exists to prevent.
#
# Nothing here uses interface byte counters as a leak oracle.
#
# This file is sourced, so it deliberately sets no shell options: the caller decides whether a failing
# case aborts the run. The adversarial runner does not, because one failing exposure must not stop the
# others from being observed.

H_MUT="gh-mut"
H_OUT="gh-out"
H_MUT_ADDR="10.88.0.2"
H_CONDUIT_ADDR="10.88.0.3"
H_OUT_ADDR="10.88.0.1"
H_MUT_ADDR6="fd00:88::2"
H_OUT_ADDR6="fd00:88::1"
H_PREFIX="10.88.0.0/24"
H_PREFIX6="fd00:88::/64"
# An address the machine may acquire later, as a leased address would be. Cases that change the
# machine's address use it so the observation can tell the new identity from the old one.
H_MUT_ADDR2="10.88.0.9"
# A second path out of the machine, created by a case that asks whether a new interface is subject to
# the same policy as the first.
H_MUT2_ADDR="10.99.0.2"
H_OUT2_ADDR="10.99.0.1"
# An address outside the local-network exception (198.18.0.0/15 is the benchmarking range). The
# verifier's check endpoints point here: a check aimed inside the LAN exception could not conclude
# anything when the exception is on (D-26), so the checks and the exception never collide.
H_CHECK_ADDR="198.18.0.1"
H_TOR_USER="debian-tor"

H_WORK="/tmp/gh-harness"
H_BIN="$H_WORK/bin"
H_STATE="$H_WORK/state"
H_LOG="$H_WORK/log"
H_RUNDIR="/run/ghostnector"
H_EVENTS="$H_LOG/events.jsonl"
H_COOKIE="$H_STATE/control_auth_cookie"
H_JOURNAL="$H_STATE/intent.json"
H_RESOLV_ROOT="$H_STATE/root"
H_RESOLV_CONF="$H_RESOLV_ROOT/etc/resolv.conf"
H_CANARY_ADDR="203.0.113.9"
H_TCP_PORT="18080"
H_UDP_PORT="18081"
H_HTTP_PORT="18082"
H_DNS_PORT="18053"

H_NETD_PID=""
H_CORE_PID=""
H_TOR_PID=""
H_INTERNET_PID=""
H_STORM_PID=""
H_CAPTURE_PID=""
H_WATCH_PID=""
H_IPV6=1

# ---------------------------------------------------------------- output

gh_note() { echo "    $*"; }
gh_ok() { echo "  ok: $*"; }
gh_bad() { echo "  FAIL: $*"; }
gh_inc() { echo "  inconclusive: $*"; }

# ---------------------------------------------------------------- lifecycle

gh_setup() {
    local ipv6="${1:-yes}"
    H_IPV6=1
    [ "$ipv6" = "no" ] && H_IPV6=0

    gh_teardown >/dev/null 2>&1 || true
    mkdir -p "$H_BIN" "$H_STATE" "$H_LOG" "$H_RUNDIR" "$H_RESOLV_ROOT/etc"
    chmod 0755 "$H_RUNDIR"

    # A resolv.conf with real contents, so the resolver path is real.
    printf 'nameserver 192.0.2.53\nsearch canary.test\n' >"$H_RESOLV_CONF"

    # The control plane runs unprivileged, and has to be able to rewrite this, exactly as on a
    # machine where the resolver configuration belongs to the service user.
    for user in ghostnector-core debian-tor; do
        id -u "$user" >/dev/null 2>&1 || \
            useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$user"
    done
    chown -R "$(id -u ghostnector-core)" "$H_RESOLV_ROOT"
    chown "$(id -u ghostnector-core)" "$H_STATE"
    # The control plane runs unprivileged and creates its socket here; on a real machine systemd's
    # tmpfiles entry does this.
    chown "$(id -u ghostnector-core)" "$H_RUNDIR"
    printf '{"version":1,"protected":false,"generation":0}' >"$H_JOURNAL"
    chown "$(id -u ghostnector-core)" "$H_JOURNAL"
    : >"$H_LOG/timeline"

    ip netns add "$H_OUT"
    ip netns add "$H_MUT"

    ip link add veth-out type veth peer name veth-mut
    ip link set veth-out netns "$H_OUT"
    ip link set veth-mut netns "$H_MUT"

    ip -n "$H_OUT" addr add "$H_OUT_ADDR/24" dev veth-out
    ip -n "$H_OUT" addr add "$H_CHECK_ADDR/24" dev veth-out
    ip -n "$H_MUT" addr add "$H_MUT_ADDR/24" dev veth-mut
    # The conduit's own address: the only source the outside world should ever see.
    ip -n "$H_MUT" addr add "$H_CONDUIT_ADDR/32" dev veth-mut
    ip -n "$H_OUT" link set veth-out up
    ip -n "$H_MUT" link set veth-mut up
    ip -n "$H_OUT" link set lo up
    ip -n "$H_MUT" link set lo up
    ip -n "$H_MUT" route add default via "$H_OUT_ADDR"

    if [ "$H_IPV6" = "1" ]; then
        ip -n "$H_OUT" -6 addr add "$H_OUT_ADDR6/64" dev veth-out
        ip -n "$H_MUT" -6 addr add "$H_MUT_ADDR6/64" dev veth-mut
        ip -n "$H_MUT" -6 route add default via "$H_OUT_ADDR6"
        # Do not let the kernel autoconfigure anything else.
        ip netns exec "$H_MUT" sysctl -qw net.ipv6.conf.all.accept_ra=0 || true
    fi

    # Only now does the interface the capture watches exist.
    gh_capture_start

    gh_install_binaries
    gh_write_fakes
    gh_observer_start
    gh_internet_start
}

gh_teardown() {
    gh_capture_stop
    gh_watch_stop
    [ -n "$H_STORM_PID" ] && kill "$H_STORM_PID" 2>/dev/null || true
    [ -n "$H_CORE_PID" ] && kill "$H_CORE_PID" 2>/dev/null || true
    [ -n "$H_NETD_PID" ] && kill "$H_NETD_PID" 2>/dev/null || true
    [ -n "$H_TOR_PID" ] && kill "$H_TOR_PID" 2>/dev/null || true
    [ -n "$H_INTERNET_PID" ] && kill "$H_INTERNET_PID" 2>/dev/null || true
    H_STORM_PID=""
    H_CORE_PID=""
    H_NETD_PID=""
    H_TOR_PID=""
    H_INTERNET_PID=""
    ip netns del "$H_MUT" 2>/dev/null || true
    ip netns del "$H_OUT" 2>/dev/null || true
    rm -rf "$H_WORK" "$H_RUNDIR"
}

gh_install_binaries() {
    local target="${H_TARGET:-}"
    [ -n "$target" ] || { echo "the harness needs H_TARGET set to the build directory" >&2; exit 2; }
    install -m 0755 "$target/ghostnector-netd" "$H_BIN/ghostnector-netd"
    install -m 0755 "$target/ghostnector-core" "$H_BIN/ghostnector-core"
    install -m 0755 "$target/ghostnector" "$H_BIN/ghostnector"
    install -m 0755 "$target/ghostnector-dns" "$H_BIN/ghostnector-dns"
}

gh_write_fakes() {
    cat >"$H_BIN/fake-tor.py" <<'PY'
"""A stand-in for Tor: a control port that reports itself ready, and a TransPort that carries TCP.

It runs as the exempted uid and binds the conduit address for everything it sends onward, so the
outside world can tell the conduit's traffic apart from the machine's own.
"""
import os, socket, struct, sys, threading, time

control_port, trans_port, conduit, log_path = (
    int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4],
)
log = open(log_path, "a", buffering=1)


def record(kind, **fields):
    fields["kind"] = kind
    fields["t"] = time.time()
    log.write(__import__("json").dumps(fields) + "\n")


def control_server():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", control_port))
    server.listen(16)
    ready = (
        b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n"
        b"250 OK\r\n"
    )
    while True:
        conn, _ = server.accept()
        threading.Thread(target=control_session, args=(conn, ready), daemon=True).start()


def control_session(conn, ready):
    try:
        # Real Tor does not greet first: the client authenticates before it reads.
        pending = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                return
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                command = line.strip().upper()
                if command.startswith(b"AUTHENTICATE"):
                    conn.sendall(b"250 OK\r\n")
                elif command.startswith(b"GETINFO STATUS/BOOTSTRAP-PHASE"):
                    conn.sendall(ready)
                else:
                    conn.sendall(b"510 Unrecognized command\r\n")
    except OSError:
        pass
    finally:
        conn.close()


def original_destination(conn):
    """The address the application was trying to reach, via the kernel's redirect."""
    raw = conn.getsockopt(socket.SOL_IP, 80, 16)  # SO_ORIGINAL_DST
    port = struct.unpack("!H", raw[2:4])[0]
    address = socket.inet_ntoa(raw[4:8])
    return address, port


def trans_server():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", trans_port))
    server.listen(64)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=trans_session, args=(conn,), daemon=True).start()


def trans_session(client):
    try:
        address, port = original_destination(client)
    except OSError:
        client.close()
        return
    record("trans", destination=f"{address}:{port}")
    try:
        up = socket.socket()
        up.bind((conduit, 0))
        up.settimeout(5)
        up.connect((address, port))
    except OSError as error:
        record("trans-failed", destination=f"{address}:{port}", reason=str(error))
        client.close()
        return

    def pipe(source, sink):
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                sink.sendall(data)
        except OSError:
            pass
        finally:
            try:
                sink.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threading.Thread(target=pipe, args=(client, up), daemon=True).start()
    pipe(up, client)
    client.close()
    up.close()


threading.Thread(target=control_server, daemon=True).start()
trans_server()
PY

    cat >"$H_BIN/fake-dns.py" <<'PY'
"""A stand-in for the resolver the relay forwards to: one name, one address, over UDP and TCP.

Tor's DNSPort speaks both, so a double that speaks only one would make a working relay look broken
on the path that matters for answers that do not fit in a datagram.
"""
import socket, sys, threading

port, address = int(sys.argv[1]), sys.argv[2]
octets = bytes(int(part) for part in address.split("."))


def answer(query):
    if len(query) < 12:
        return None
    question_end = 12
    while query[question_end] != 0:
        question_end += 1 + query[question_end]
    question_end += 5
    reply = bytearray(query[:2])
    reply += bytes([0x81, 0x80])
    reply += (1).to_bytes(2, "big")
    reply += (1).to_bytes(2, "big")
    reply += b"\x00\x00\x00\x00"
    reply += query[12:question_end]
    reply += b"\xc0\x0c"
    reply += (1).to_bytes(2, "big")
    reply += (1).to_bytes(2, "big")
    reply += (60).to_bytes(4, "big")
    reply += (4).to_bytes(2, "big")
    reply += octets
    return bytes(reply)


def udp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", port))
    while True:
        query, from_address = server.recvfrom(4096)
        reply = answer(query)
        if reply:
            server.sendto(reply, from_address)


def tcp_server():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(16)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=tcp_session, args=(conn,), daemon=True).start()


def tcp_session(conn):
    try:
        header = conn.recv(2)
        if len(header) < 2:
            return
        length = int.from_bytes(header, "big")
        query = b""
        while len(query) < length:
            chunk = conn.recv(length - len(query))
            if not chunk:
                return
            query += chunk
        reply = answer(query)
        if reply:
            conn.sendall(len(reply).to_bytes(2, "big") + reply)
    except OSError:
        pass
    finally:
        conn.close()


threading.Thread(target=tcp_server, daemon=True).start()
udp_server()
PY

    cat >"$H_BIN/internet.py" <<'PY'
"""The outside world: recording endpoints, one per protocol, and a JSON-Lines event log.

It listens on every address it is given. The verifier's check endpoints are given an address outside
the local-network ranges (198.18.0.0/15), while the machine's probes still aim at the on-link address;
a check aimed inside the LAN exception could not prove confinement (D-26).
"""
import json, socket, sys, threading, time

addresses, tcp_port, udp_port, http_port, log_path = (
    sys.argv[1].split(","), int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5],
)
log = open(log_path, "a", buffering=1)


def record(kind, **fields):
    fields["kind"] = kind
    fields["t"] = time.time()
    log.write(json.dumps(fields) + "\n")


def tcp_server(address, port, kind):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port))
    server.listen(64)
    while True:
        conn, peer = server.accept()
        record(kind, peer=f"{peer[0]}:{peer[1]}")
        threading.Thread(target=tcp_session, args=(conn,), daemon=True).start()


def tcp_session(conn):
    try:
        conn.recv(4096)
        conn.sendall(b"ok")
    except OSError:
        pass
    finally:
        conn.close()


def http_server(address, port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port))
    server.listen(64)
    while True:
        conn, peer = server.accept()
        record("http", peer=f"{peer[0]}:{peer[1]}")
        threading.Thread(target=http_session, args=(conn,), daemon=True).start()


def http_session(conn):
    try:
        conn.recv(8192)
        body = b"198.51.100.7\n"
        conn.sendall(
            b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
        )
    except OSError:
        pass
    finally:
        conn.close()


def udp_server(address, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((address, port))
    while True:
        data, peer = server.recvfrom(4096)
        record("udp", peer=f"{peer[0]}:{peer[1]}", length=len(data))
        server.sendto(b"udp-answered", peer)


def dhcp_recorder(address):
    # A DHCP server's port, recording only: a DISCOVER gets no reply anywhere, and what matters here
    # is whether the request left the machine at all.
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, 67))
    while True:
        data, peer = server.recvfrom(4096)
        record("dhcp", peer=f"{peer[0]}:{peer[1]}", length=len(data))


for address in addresses:
    threading.Thread(target=tcp_server, args=(address, tcp_port, "tcp"), daemon=True).start()
    threading.Thread(target=http_server, args=(address, http_port), daemon=True).start()
    threading.Thread(target=udp_server, args=(address, udp_port), daemon=True).start()
    threading.Thread(target=dhcp_recorder, args=(address,), daemon=True).start()
while True:
    time.sleep(3600)
PY

    cat >"$H_BIN/storm.py" <<'PY'
"""Traffic from an ordinary, unprivileged identity: TCP, UDP and DNS, over and over."""
import socket, sys, threading, time

host, tcp_port, udp_port, dns_port, seconds = (
    sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]),
)
deadline = time.time() + seconds
counts = {"tcp": 0, "udp": 0, "dns": 0, "tcp_failed": 0, "udp_failed": 0, "dns_failed": 0}


def loop(name, attempt):
    while time.time() < deadline:
        try:
            attempt()
            counts[name] += 1
        except OSError:
            counts[name + "_failed"] += 1
        time.sleep(0.05)


def tcp():
    conn = socket.socket()
    conn.settimeout(2)
    conn.connect((host, tcp_port))
    conn.sendall(b"storm")
    conn.close()


def udp():
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn.settimeout(2)
    conn.sendto(b"storm", (host, udp_port))


def dns():
    query = bytes([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
    query += b"\x06canary\x04test\x00\x00\x01\x00\x01"
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn.settimeout(2)
    conn.sendto(query, ("127.0.0.1", dns_port))
    conn.recv(4096)


threads = [
    threading.Thread(target=loop, args=("tcp", tcp)),
    threading.Thread(target=loop, args=("udp", udp)),
    threading.Thread(target=loop, args=("dns", dns)),
]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
print(__import__("json").dumps(counts))
PY

    head -c 32 /dev/urandom >"$H_COOKIE"
    chmod 0644 "$H_COOKIE"
}

# ---------------------------------------------------------------- observation

gh_observer_start() {
    local ipv6_rules=""
    if [ "$H_IPV6" = "1" ]; then
        ipv6_rules="ip6 saddr $H_MUT_ADDR6 counter comment \"machine6\""
    fi
    ip netns exec "$H_OUT" nft -f - <<EOF
destroy table inet ghobserve
table inet ghobserve {
  chain input {
    type filter hook input priority -200; policy accept;
    ip saddr $H_MUT_ADDR log prefix "GHLEAK4 " level warn counter comment "machine"
    ip saddr $H_CONDUIT_ADDR counter comment "conduit"
    $ipv6_rules
  }
}
EOF
}

# A wall-clock mark, so an observation can be placed against a transition rather than against a
# total. Anything that crosses without a matching mark is a finding, not an average.
gh_mark() {
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S.%N')" "$1" >>"$H_LOG/timeline"
}

# Every packet that left by the machine's own address, captured independently on the far side of the
# veth rather than inferred from a counter. A counter says something crossed; a capture says what,
# when, and where it was going, which is what classifying it requires. The capture is of the whole
# subnet rather than one address, so a machine that acquires a different address is still observed.
gh_capture_start() {
    ip netns exec "$H_OUT" tcpdump -i veth-out -n -s 96 -w "$H_LOG/crossed.pcap" \
        "net $H_PREFIX or net $H_PREFIX6" >"$H_LOG/tcpdump.log" 2>&1 &
    H_CAPTURE_PID=$!
    sleep 0.5
    if ! kill -0 "$H_CAPTURE_PID" 2>/dev/null; then
        echo "  the capture did not start: $(tail -2 "$H_LOG/tcpdump.log" 2>/dev/null)" >&2
        H_CAPTURE_PID=""
    fi
}

gh_capture_stop() {
    [ -n "$H_CAPTURE_PID" ] && kill "$H_CAPTURE_PID" 2>/dev/null || true
    sleep 0.3
    H_CAPTURE_PID=""
}

# Anything in the capture whose source is one of the machine's addresses: it left the machine rather
# than arrived at it.
gh_leaks() {
    [ -f "$H_LOG/crossed.pcap" ] || { echo "(no capture)"; return; }
    tcpdump -r "$H_LOG/crossed.pcap" -tttt -n \
        "(src $H_MUT_ADDR or src $H_MUT_ADDR6 or src $H_MUT_ADDR2)" 2>/dev/null | tail -40 ||
        echo "(nothing recorded)"
}

# How many packets from a given source address reached the outside. The counter keys on the address
# the machine had at setup; a case that changes the address needs this instead.
gh_crossed_count() {
    local source="${1:-$H_MUT_ADDR}"
    [ -f "$H_LOG/crossed.pcap" ] || { echo 0; return; }
    tcpdump -r "$H_LOG/crossed.pcap" -n "src $source" 2>/dev/null | wc -l
}

# Sampling the counter against the state, so a crossing can be attributed to what the machine was
# reporting at that moment. A before/after count cannot tell "traffic crossed while the machine said
# it was protected" from "traffic crossed after the user was told protection was gone", and those are
# different findings.
gh_watch_start() {
    : >"$H_LOG/watch"
    (
        while true; do
            printf '%s|%s\n' "$(gh_from_machine)" "$(gh_status | head -1)" >>"$H_LOG/watch"
            sleep 0.2
        done
    ) &
    H_WATCH_PID=$!
}

gh_watch_stop() {
    [ -n "$H_WATCH_PID" ] && kill "$H_WATCH_PID" 2>/dev/null || true
    sleep 0.3
    H_WATCH_PID=""
}

# Crossings that happened while the machine was still reporting protection. Empty is the pass.
gh_watch_violations() {
    python3 - "$H_LOG/watch" <<'PY'
import sys

previous = None
for line in open(sys.argv[1]):
    count, _, state = line.strip().partition("|")
    try:
        count = int(count)
    except ValueError:
        continue
    protected = "protected, but unverified" in state or "and verified" in state
    if previous is not None and count > previous and protected:
        print(f"crossed while reporting: {state.strip()}")
    previous = count
PY
}

gh_timeline() {
    cat "$H_LOG/timeline" 2>/dev/null || echo "(no marks)"
}

# Packets the outside world received from a given source class.
gh_counter() {
    ip netns exec "$H_OUT" nft -j list chain inet ghobserve input | python3 -c '
import json, sys
want = sys.argv[1]
total = 0
for item in json.load(sys.stdin).get("nftables", []):
    rule = item.get("rule")
    if not rule or rule.get("comment") != want:
        continue
    for expr in rule.get("expr", []):
        counter = expr.get("counter")
        if counter:
            total += counter.get("packets", 0)
print(total)
' "$1"
}

# Anything from the machine's own address is a leak signal. The conduit's traffic is expected.
gh_from_machine() {
    echo $(( $(gh_counter machine) + $(gh_counter machine6) ))
}
gh_from_conduit() { gh_counter conduit; }

gh_internet_start() {
    # Both the outside recorder (root) and the fake Tor (the exempted uid) append to this file, so
    # it has to be writable by both. A test double that cannot write its own evidence is worse than
    # no double: the failure looks like the component it stands in for.
    : >"$H_EVENTS"
    chmod 0666 "$H_EVENTS"
    ip netns exec "$H_OUT" python3 "$H_BIN/internet.py" \
        "$H_OUT_ADDR,$H_CHECK_ADDR" "$H_TCP_PORT" "$H_UDP_PORT" "$H_HTTP_PORT" "$H_EVENTS" \
        >"$H_LOG/internet.log" 2>&1 &
    H_INTERNET_PID=$!
    sleep 0.3
}

# Events the outside world recorded, by kind.
gh_events() {
    [ -f "$H_EVENTS" ] || { echo 0; return; }
    python3 -c '
import json, sys
want = sys.argv[1]
count = 0
for line in open(sys.argv[2]):
    try:
        if json.loads(line).get("kind") == want:
            count += 1
    except ValueError:
        pass
print(count)
' "$1" "$H_EVENTS"
}

# Events from a particular source address, which is how the conduit is told from a leak.
gh_events_from() {
    [ -f "$H_EVENTS" ] || { echo 0; return; }
    python3 -c '
import json, sys
want, prefix = sys.argv[1], sys.argv[2]
count = 0
for line in open(sys.argv[3]):
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if event.get("kind") == want and str(event.get("peer", "")).startswith(prefix):
        count += 1
print(count)
' "$1" "$2" "$H_EVENTS"
}

# ---------------------------------------------------------------- the stack under test

gh_start_tor() {
    local uid
    uid="$(id -u "$H_TOR_USER")"
    ip netns exec "$H_MUT" setpriv --reuid="$uid" --regid="$(id -g "$H_TOR_USER")" --clear-groups \
        python3 "$H_BIN/fake-tor.py" 9051 9040 "$H_CONDUIT_ADDR" "$H_EVENTS" \
        >"$H_LOG/tor.log" 2>&1 &
    H_TOR_PID=$!
    sleep 0.3
}

gh_start_dns_upstream() {
    ip netns exec "$H_MUT" python3 "$H_BIN/fake-dns.py" 9053 "$H_CANARY_ADDR" \
        >"$H_LOG/dns.log" 2>&1 &
    sleep 0.3
}

# Start netd and core. core is given CAP_NET_BIND_SERVICE so the relay it starts can listen on
# 53, exactly as the unit file does.
gh_start_stack() {
    # The journal is written once, by gh_setup. It is deliberately not reset here: a restart has to
    # see what the previous run left behind, which is the whole point of several cases.
    [ -f "$H_JOURNAL" ] || printf '{"version":1,"protected":false,"generation":0}' >"$H_JOURNAL"

    # No port overrides: this runs the packaged defaults, including the chokepoint port that a
    # `nameserver` line implies (D-22).
    ip netns exec "$H_MUT" "$H_BIN/ghostnector-netd" \
        --socket "$H_RUNDIR/netd.sock" --peer-uid "$(id -u ghostnector-core)" \
        --fallback-path "$H_STATE/fail-closed.nft" \
        --tor-user "$H_TOR_USER" >"$H_LOG/netd.log" 2>&1 &
    H_NETD_PID=$!
    gh_wait_socket "$H_RUNDIR/netd.sock" || { cat "$H_LOG/netd.log"; return 1; }

    ip netns exec "$H_MUT" setpriv \
        --reuid="$(id -u ghostnector-core)" --regid="$(id -g ghostnector-core)" --clear-groups \
        --inh-caps +net_bind_service --ambient-caps +net_bind_service \
        "$H_BIN/ghostnector-core" \
        --socket "$H_RUNDIR/core.sock" --helper "$H_RUNDIR/netd.sock" \
        --journal "$H_JOURNAL" --resolver-state "$H_STATE/resolver.json" \
        --resolv-conf-root "$H_RESOLV_ROOT" \
        --services external --tor-cookie "$H_COOKIE" --tor-control-port 9051 \
        --tor-bootstrap-seconds 5 --tor-dns-port 9053 \
        --dns-helper "$H_BIN/ghostnector-dns" \
        --udp-check "$H_CHECK_ADDR:$H_UDP_PORT" \
        --check-url "http://$H_CHECK_ADDR:$H_HTTP_PORT/" \
        --canary "canary.test@$H_CANARY_ADDR" --canary-resolver "127.0.0.1:53" \
        --verify-interval 3 --verify-stale-after 60 --verify-timeout 2 \
        >"$H_LOG/core.log" 2>&1 &
    H_CORE_PID=$!
    gh_wait_socket "$H_RUNDIR/core.sock" || { cat "$H_LOG/core.log"; return 1; }
}

gh_wait_socket() {
    for _ in $(seq 1 60); do [ -S "$1" ] && return 0; sleep 0.1; done
    return 1
}

gh_stop_core() {
    [ -n "$H_CORE_PID" ] && kill "$H_CORE_PID" 2>/dev/null || true
    wait "$H_CORE_PID" 2>/dev/null || true
    H_CORE_PID=""
    rm -f "$H_RUNDIR/core.sock"
}

gh_stop_netd() {
    [ -n "$H_NETD_PID" ] && kill "$H_NETD_PID" 2>/dev/null || true
    wait "$H_NETD_PID" 2>/dev/null || true
    H_NETD_PID=""
    rm -f "$H_RUNDIR/netd.sock"
}

gh_stop_tor() {
    [ -n "$H_TOR_PID" ] && kill "$H_TOR_PID" 2>/dev/null || true
    wait "$H_TOR_PID" 2>/dev/null || true
    H_TOR_PID=""
}

gh_kill_relay() {
    # Matched by exact process name: the control plane's command line also contains the relay's path,
    # so a pattern match would kill both and the observation would be of the wrong fault.
    ip netns exec "$H_MUT" pkill -x ghostnector-dns 2>/dev/null || true
}

# ---------------------------------------------------------------- acting

gh_cli() {
    ip netns exec "$H_MUT" setpriv \
        --reuid="$(id -u ghostnector-core)" --regid="$(id -g ghostnector-core)" --clear-groups \
        "$H_BIN/ghostnector" --socket "$H_RUNDIR/core.sock" "$@"
}

gh_status() { gh_cli status 2>&1 || true; }

# Wait for the state to say something, up to a bound. Returns 1 on timeout.
gh_wait_for_state() {
    local pattern="$1" seconds="$2"
    for _ in $(seq 1 "$seconds"); do
        if gh_status | grep -q "$pattern"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

gh_connect() { gh_cli connect 2>&1 || true; }
gh_disconnect() { gh_cli disconnect 2>&1 || true; }
gh_panic() { gh_cli panic 2>&1 || true; }

# A probe as an ordinary, unprivileged identity: never root, never the exempted uid.
gh_probe() { ip netns exec "$H_MUT" setpriv --reuid=65534 --regid=65534 --clear-groups "$@"; }

# Do something as Tor's own identity, which the policy exempts.
gh_as_tor() {
    ip netns exec "$H_MUT" setpriv \
        --reuid="$(id -u "$H_TOR_USER")" --regid="$(id -g "$H_TOR_USER")" --clear-groups "$@"
}

# A datagram from the DHCP client's own port to a chosen destination port. Binding the client's port
# needs the capability the unit file grants a DHCP client, and nothing else here uses it.
gh_udp_from_68() {
    local dest="$1" port="$2"
    ip netns exec "$H_MUT" setpriv \
        --reuid=65534 --regid=65534 --clear-groups \
        --inh-caps +net_bind_service --ambient-caps +net_bind_service \
        python3 -c '
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", 68))
sock.settimeout(2)
sock.sendto(b"probe", (sys.argv[1], int(sys.argv[2])))
sys.stdout.write("sent")
' "$dest" "$port" 2>&1 || true
}

# A datagram from an ordinary ephemeral port to a chosen destination port.
gh_udp_to_port() {
    local dest="$1" port="$2"
    gh_probe python3 -c '
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.settimeout(2)
sock.sendto(b"probe", (sys.argv[1], int(sys.argv[2])))
sys.stdout.write("sent")
' "$dest" "$port" 2>&1 || true
}

# TCP from a chosen local address, for asking whether an identity the policy never saw has the same
# limits as the one it did.
gh_tcp_probe_from() {
    gh_probe python3 -c '
import socket, sys
conn = socket.socket(); conn.settimeout(3)
conn.bind((sys.argv[1], 0))
conn.connect((sys.argv[2], int(sys.argv[3])))
conn.sendall(b"probe")
sys.stdout.write(conn.recv(64).decode(errors="replace"))
' "$1" "$2" "$3" 2>&1 || true
}

# A recording TCP endpoint on an address the standing recorder does not cover. Prints its PID.
gh_listener_start() {
    local address="$1" port="$2" kind="$3"
    ip netns exec "$H_OUT" python3 -c '
import json, socket, sys, threading, time

address, port, kind, log_path = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
log = open(log_path, "a", buffering=1)
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((address, port))
server.listen(16)


def serve():
    while True:
        conn, peer = server.accept()
        log.write(json.dumps({"kind": kind, "peer": "%s:%d" % peer, "t": time.time()}) + "\n")
        try:
            conn.recv(4096)
            conn.sendall(b"ok")
        except OSError:
            pass
        finally:
            conn.close()


threading.Thread(target=serve, daemon=True).start()
while True:
    time.sleep(3600)
' "$address" "$port" "$kind" "$H_EVENTS" >"$H_LOG/listener-$kind.log" 2>&1 &
    echo $!
}

gh_tcp_probe() {
    gh_probe python3 -c '
import socket, sys
conn = socket.socket(); conn.settimeout(3)
conn.connect((sys.argv[1], int(sys.argv[2])))
conn.sendall(b"probe")
sys.stdout.write(conn.recv(64).decode(errors="replace"))
' "$H_OUT_ADDR" "$H_TCP_PORT" 2>&1 || true
}

# A loopback round trip as an ordinary identity, on an address in the loopback range rather than the
# most obvious one, so what is exercised is the rule and not the interface.
gh_loopback_probe() {
    gh_probe python3 -c '
import socket, sys, threading
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.2", 0))
server.listen(1)
port = server.getsockname()[1]


def serve():
    conn, _ = server.accept()
    conn.sendall(b"loopback-ok")
    conn.close()


threading.Thread(target=serve, daemon=True).start()
client = socket.socket(); client.settimeout(3)
client.connect(("127.0.0.2", port))
sys.stdout.write(client.recv(64).decode(errors="replace"))
' 2>&1 || true
}

gh_udp_probe() {
    gh_probe python3 -c '
import socket, sys
conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); conn.settimeout(3)
conn.sendto(b"probe", (sys.argv[1], int(sys.argv[2])))
sys.stdout.write(conn.recv(64).decode(errors="replace"))
' "$H_OUT_ADDR" "$H_UDP_PORT" 2>&1 || true
}

gh_dns_probe() {
    gh_probe python3 -c '
import socket, sys
query = bytes([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
query += b"\x06canary\x04test\x00\x00\x01\x00\x01"
conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); conn.settimeout(3)
conn.sendto(query, (sys.argv[1], int(sys.argv[2])))
answer = conn.recv(4096)
sys.stdout.write(".".join(str(b) for b in answer[-4:]))
' "${1:-127.0.0.1}" "${2:-53}" 2>&1 || true
}

gh_ipv6_probe() {
    gh_probe python3 -c '
import socket, sys
conn = socket.socket(socket.AF_INET6); conn.settimeout(3)
conn.connect((sys.argv[1], int(sys.argv[2])))
conn.sendall(b"probe")
sys.stdout.write("connected")
' "$H_OUT_ADDR6" "$H_TCP_PORT" 2>&1 || true
}

gh_storm_start() {
    local seconds="$1"
    ip netns exec "$H_MUT" setpriv \
        --reuid="$(id -u ghostnector-core)" --regid="$(id -g ghostnector-core)" --clear-groups \
        python3 "$H_BIN/storm.py" "$H_OUT_ADDR" "$H_TCP_PORT" "$H_UDP_PORT" 53 "$seconds" \
        >"$H_LOG/storm.json" 2>&1 &
    H_STORM_PID=$!
}

gh_storm_stop() {
    [ -n "$H_STORM_PID" ] && kill "$H_STORM_PID" 2>/dev/null || true
    H_STORM_PID=""
}

# ---------------------------------------------------------------- fault injection

gh_policy_tables() { ip netns exec "$H_MUT" nft list tables 2>/dev/null || true; }
gh_policy_present() { gh_policy_tables | grep -q ghostnector; }
gh_destroy_policy() { ip netns exec "$H_MUT" nft destroy table inet ghostnector 2>/dev/null || true; }

gh_inject_rule() {
    ip netns exec "$H_MUT" nft insert rule inet ghostnector out_filter "$@" 2>&1 || true
}

gh_inject_nat_return() {
    ip netns exec "$H_MUT" nft insert rule inet ghostnector out_nat "$@" return 2>&1 || true
}

# Whether the live policy still holds a line mentioning this, as evidence that a fix removed it.
gh_policy_mentions() {
    ip netns exec "$H_MUT" nft list table inet ghostnector 2>/dev/null | grep -qF -- "$1"
}

gh_corrupt_journal() { echo "{ this is not json" >"$H_JOURNAL"; }
gh_remove_journal() { rm -f "$H_JOURNAL"; }

# ---------------------------------------------------------------- network changes

gh_link() { ip -n "$H_MUT" link set veth-mut "$1"; }
gh_default_route() { ip -n "$H_MUT" route "$1" default via "$H_OUT_ADDR" 2>&1 || true; }

# Give the machine a different address, as a new lease would, keeping the conduit's address so the
# conduit can still be told apart from the machine.
gh_machine_address() {
    local new="$1"
    ip -n "$H_MUT" addr del "$H_MUT_ADDR/24" dev veth-mut 2>/dev/null || true
    ip -n "$H_MUT" addr add "$new/24" dev veth-mut
    ip -n "$H_MUT" route replace default via "$H_OUT_ADDR"
}

# A second path out of the machine, as a new interface appears.
gh_second_path_add() {
    ip link add veth2-out type veth peer name veth2-mut
    ip link set veth2-out netns "$H_OUT"
    ip link set veth2-mut netns "$H_MUT"
    ip -n "$H_OUT" addr add "$H_OUT2_ADDR/24" dev veth2-out
    ip -n "$H_MUT" addr add "$H_MUT2_ADDR/24" dev veth2-mut
    ip -n "$H_OUT" link set veth2-out up
    ip -n "$H_MUT" link set veth2-mut up
}

gh_second_path_remove() { ip -n "$H_MUT" link del veth2-mut 2>/dev/null || true; }
