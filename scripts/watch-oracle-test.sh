#!/bin/bash
#
# A deterministic test of the per-packet watch oracle (scripts/lib/watch-oracle.py).
#
# The oracle decides whether traffic that arrived at the far side crossed while the machine was
# actually claiming protection. It is the argument the lifecycle cases rest on, so it is tested
# directly: synthetic state logs and synthetic capture lines, no root, no kernel, no timing.
#
#   scripts/watch-oracle-test.sh

set -u
cd "$(dirname "$0")/.."
ORACLE="scripts/lib/watch-oracle.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

fail() {
    echo "  FAIL: $*" >&2
    FAIL=$((FAIL + 1))
}
ok() {
    echo "  ok: $*"
    PASS=$((PASS + 1))
}

# A state log where "off" becomes "protected, but unverified" at t=1002 and "blocked" at t=1004.
cat >"$WORK/state" <<'EOF'
1000.000000000|state:        off — traffic is not protected
1002.000000000|state:        protected, but unverified
1003.500000000|state:        protected — and verified
1004.000000000|state:        blocked — no traffic can leave
EOF

run() {
    python3 "$ORACLE" "$WORK/state" <"$1"
}

# 1. A packet that crossed before any protection claim: not a violation.
cat >"$WORK/before" <<'EOF'
1001.500000 IP 10.88.0.2.34416 > 10.88.0.1.18080: Flags [S], length 0
EOF
if run "$WORK/before" | grep -q .; then
    fail "a packet from the Off window was reported as a violation"
else
    ok "a packet that crossed while the machine was Off is not a violation"
fi

# 2. A packet that crossed while Degraded was in force: a violation.
cat >"$WORK/under" <<'EOF'
1002.500000 IP 10.88.0.2.34416 > 10.88.0.1.18080: Flags [S], length 0
EOF
if run "$WORK/under" | grep -q "crossed while reporting: state:        protected, but unverified"; then
    ok "a packet under a degraded claim is a violation, with the state named"
else
    fail "a packet under a degraded claim was not reported"
fi

# 3. A packet at the exact instant of the claim: the claim is in force, so it is a violation.
cat >"$WORK/exact" <<'EOF'
1002.000000 IP 10.88.0.2.34416 > 10.88.0.1.18080: Flags [S], length 0
EOF
if run "$WORK/exact" | grep -q "crossed while reporting"; then
    ok "a packet at the transition timestamp is attributed to the state that began then"
else
    fail "a packet at the transition timestamp was not attributed to the claim"
fi

# 4. A packet after the machine was Blocked: not a protection claim.
cat >"$WORK/blocked" <<'EOF'
1004.500000 IP 10.88.0.2.34416 > 10.88.0.1.18080: Flags [S], length 0
EOF
if run "$WORK/blocked" | grep -q .; then
    fail "a packet from the Blocked window was reported as a violation"
else
    ok "a packet that crossed while Blocked is not a protection violation"
fi

# 5. A packet before any recorded state: unattributed, and never a silent pass.
cat >"$WORK/unattributed" <<'EOF'
999.000000 IP 10.88.0.2.34416 > 10.88.0.1.18080: Flags [S], length 0
EOF
if run "$WORK/unattributed" | grep -q "unattributed crossing"; then
    ok "a packet with no earlier state record is reported, not passed"
else
    fail "a packet with no earlier state record passed silently"
fi

# 6. A real crossing inside a protected window is not hidden by an earlier Off sample.
cat >"$WORK/mixed" <<'EOF'
1001.000000 IP 10.88.0.2.34416 > 10.88.0.1.18080: Flags [S], length 0
1001.500000 IP 10.88.0.2.34418 > 10.88.0.1.18080: Flags [S], length 0
1002.500000 IP 10.88.0.2.34420 > 10.88.0.1.18080: Flags [S], length 0
1003.900000 IP 10.88.0.2.34422 > 10.88.0.1.18080: Flags [S], length 0
EOF
OUT="$(run "$WORK/mixed")"
if [ "$(printf '%s\n' "$OUT" | grep -c 'crossed while reporting')" = "2" ] &&
    printf '%s' "$OUT" | grep -q "34420" &&
    printf '%s' "$OUT" | grep -q "34422" &&
    ! printf '%s' "$OUT" | grep -q "34416" &&
    ! printf '%s' "$OUT" | grep -q "34418"; then
    ok "only the packets inside the protected window are violations (2 of 4)"
else
    fail "the mixed-timeline attribution is wrong: $OUT"
fi

# 7. An unsorted or duplicate state log is still read as a timeline.
cat >"$WORK/unsorted-state" <<'EOF'
1002.000000000|state:        protected, but unverified
1000.000000000|state:        off — traffic is not protected
1002.000000000|state:        protected, but unverified
EOF
if python3 "$ORACLE" "$WORK/unsorted-state" <"$WORK/before" | grep -q .; then
    fail "an unsorted state log changed the verdict for an Off-window packet"
else
    ok "an unsorted state log is read as a timeline"
fi

# 8. An unreadable capture line is reported rather than ignored.
cat >"$WORK/broken-line" <<'EOF'
not-a-timestamp this is not a tcpdump line
EOF
if run "$WORK/broken-line" | grep -q "unparseable capture line"; then
    ok "an unreadable capture line is reported"
else
    fail "an unreadable capture line was ignored"
fi

echo
echo "watch-oracle: $PASS held, $FAIL contradicted"
[ "$FAIL" = "0" ] || exit 1
