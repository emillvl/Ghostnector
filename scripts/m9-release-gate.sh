#!/usr/bin/env bash
#
# The M1–M9 release gate, runnable on any Linux host with the build and test dependencies.
#
#   scripts/m9-release-gate.sh [log path]
#
# It runs the complete static checks, the unit suite, and every hermetic script suite, in the same
# order the WSL gate uses. The environment-dependent real-router qualification
# (`scripts/i2p-real-router-test.sh`) is deliberately separate: it needs the real i2pd package and
# the public I2P network, and it is recorded as its own run.
#
# Requires: cargo (stable), nftables, iproute2, util-linux (setpriv), python3, curl, tcpdump,
# conntrack (optional), and root (the suites create namespaces and apply policy).

set -u
cd "$(dirname "$0")/.."
LOG="${1:-$(pwd)/m9-release-gate.log}"
BIN="$(pwd)/target/debug"

{
    date -u
    git rev-parse HEAD
    git status --porcelain
    echo "=== fmt ==="
    cargo fmt --all --check
    echo "fmt rc=$?"
    echo "=== check ==="
    cargo check --workspace --all-targets
    echo "check rc=$?"
    echo "=== clippy ==="
    cargo clippy --workspace --all-targets -- -D warnings
    echo "clippy rc=$?"
    echo "=== test ==="
    cargo test --workspace
    echo "test rc=$?"
    echo "=== build bins ==="
    cargo build --workspace --bins
    echo "build rc=$?"
    # The privileged helpers verify that the tools they execute are root-owned and not writable by
    # anyone else. On a machine where the build ran as another user, the artifacts are handed to
    # root before any suite runs; this is an environment step, not a product change.
    chown root:root target/debug/ghostnector* 2>/dev/null || true
    chmod go-w target/debug/ghostnector* 2>/dev/null || true
    # The packaged capability set drops CAP_DAC_OVERRIDE, so an unprivileged root must be able to
    # traverse the repository path; a 0750 home directory would otherwise deny the tool check.
    for dir in "$(pwd)" "$(dirname "$(pwd)")"; do chmod o+x "$dir" 2>/dev/null || true; done
    echo "ownership handed to root, path traversable"
    echo "=== app-topology-test ==="
    bash scripts/app-topology-test.sh
    echo "app-topology rc=$?"
    echo "=== app-policy-test ==="
    bash scripts/app-policy-test.sh
    echo "app-policy rc=$?"
    echo "=== appd-socket-test ==="
    bash scripts/appd-socket-test.sh "$BIN/ghostnector-appd"
    echo "appd-socket rc=$?"
    echo "=== core-app-test ==="
    bash scripts/core-app-test.sh "$BIN"
    echo "core-app rc=$?"
    echo "=== app-adversarial ==="
    bash scripts/app-adversarial.sh "$BIN"
    echo "app-adversarial rc=$?"
    echo "=== i2p policy: the golden against the kernel ==="
    bash scripts/policy-netns-test.sh crates/ghostnector-policy/golden/i2p_system.nft 0:block 989:allow
    echo "policy-netns-i2p rc=$?"
    echo "=== i2p end to end and adversarial ==="
    bash scripts/i2p-adversarial.sh "$BIN"
    echo "i2p-adversarial rc=$?"
    echo "=== policy-netns-test (tor) ==="
    bash scripts/policy-netns-test.sh crates/ghostnector-policy/golden/tor_system.nft 0:block 987:allow
    echo "policy-netns rc=$?"
    echo "=== netd-socket-test ==="
    bash scripts/netd-socket-test.sh "$BIN/ghostnector-netd"
    echo "netd-socket rc=$?"
    echo "=== core-cli-test ==="
    bash scripts/core-cli-test.sh "$BIN"
    echo "core-cli rc=$?"
    echo "=== bootguard-test ==="
    bash scripts/bootguard-test.sh "$BIN"
    echo "bootguard rc=$?"
    echo "=== watch-oracle-test ==="
    bash scripts/watch-oracle-test.sh
    echo "watch-oracle rc=$?"
    echo "=== adversarial (M1-M7) ==="
    bash scripts/adversarial.sh "$BIN"
    echo "adversarial rc=$?"
    date -u
} >"$LOG" 2>&1

grep -E '^(===|.*rc=)' "$LOG"
echo "log: $LOG"
