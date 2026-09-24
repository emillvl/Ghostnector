# Ghostnector

Network-level privacy for Linux: transparent Tor routing, encrypted DNS, isolated I2P, and a
fail-closed default-deny policy that cannot silently return traffic to the clearnet.

**Status:** early implementation (M0 — contracts and repo skeleton).
**Architecture:** [`ARCHITECTURE-REVIEW.md`](ARCHITECTURE-REVIEW.md) — read this first; every decision
in the code cites it.
**Plan:** [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md).

## Platform: Linux only

Ghostnector's guarantees are built out of Linux kernel primitives — nftables, network namespaces,
capabilities, cgroup/socket ownership. There is no Windows equivalent, and WSL2 is a *build and test*
environment, not a deployment target: a WSL2 instance is a separate VM behind its own NAT, so a
daemon running there cannot filter or redirect Windows applications' traffic.

The code is deliberately split so that everything except the kernel-facing backend is portable:

| Layer | Portability |
|---|---|
| `ghostnector-spec` — profile/scope/state/IPC vocabulary | Portable, no OS calls |
| `ghostnector-policy` — desired state → ruleset IR | Portable, pure functions |
| `ghostnector-journal` — intent log, snapshots, rollback | Portable |
| `ghostnector-netd` — the privileged helper that touches the kernel | Linux only |
| `ghostnector-core`, `ghostnector-cli` | Portable (talk to `netd` over a socket) |

A future non-Linux backend is therefore *possible* without rewriting the policy engine, but it would
be a different product with materially weaker guarantees.

## Layout

```
crates/
  ghostnector-spec/       shared vocabulary: profiles, state, exemptions, IPC, helper verbs
  ghostnector-policy/     (M1) desired state -> nftables ruleset IR + invariant checks
  ghostnector-netd/       (M1) privileged helper: apply/revert, conntrack, namespaces
  ghostnector-core/       (M2) state machine, journal, orchestration, IPC server
  ghostnector-cli/        (M2) command-line client
  ghostnector-bootguard/  (M6) early fail-closed baseline after reboot
  ghostnector-verify/     (M5) continuous escape/identity/canary verification
docs/
packaging/                (M1) systemd units, sysusers, tmpfiles, polkit policy
```

## Build and test

**Windows is for editing and static checks** — its Smart App Control policy blocks execution of
locally built unsigned binaries, so tests do not run there:

```powershell
$cargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"
& $cargo fmt --all
& $cargo clippy --workspace --all-targets -- -D warnings
& $cargo check --workspace --target x86_64-unknown-linux-gnu
```

**Linux/WSL2 is where everything executes** — unit tests, nftables, namespaces, systemd:

```bash
cd /mnt/c/Users/<you>/Desktop/Ghostnector
CARGO_TARGET_DIR=/root/ghostnector-target cargo test --workspace

# Regenerate the golden policy files *deliberately*, after reviewing the diff:
CARGO_TARGET_DIR=/root/ghostnector-target GHOSTNECTOR_UPDATE_GOLDEN=1 \
    cargo test -p ghostnector-policy --lib

# Prove the rendered policies against the real kernel, in throwaway namespaces (needs root):
bash scripts/policy-netns-test.sh crates/ghostnector-policy/golden/tor_system.nft 0:block 987:allow

# Prove the privileged helper end to end: socket ownership, peer credentials, apply, revert:
cargo build -p ghostnector-netd
bash scripts/netd-socket-test.sh "$CARGO_TARGET_DIR/debug/ghostnector-netd"

# Prove the whole stack (cli -> core -> netd -> kernel) in a throwaway namespace:
cargo build --workspace --bins
bash scripts/core-cli-test.sh "$CARGO_TARGET_DIR/debug"
```

`CARGO_TARGET_DIR` keeps build artefacts on the Linux filesystem; building directly into `/mnt/c`
is dramatically slower.


## License

Not yet chosen. The dependency set is deliberately permissive (MIT/Apache-2.0); the one prominent
nftables crate, `rustables`, is GPL-3.0, which is why the project uses the MIT-licensed netlink
crates instead. See `docs/IMPLEMENTATION-PLAN.md` (Risk register, R3).
