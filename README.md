# Ghostnector

Network-level privacy for Linux: transparent Tor routing, encrypted DNS, isolated I2P, and a
fail-closed default-deny policy that cannot silently return traffic to the clearnet. A simple GTK4
window renders the control plane's authoritative state; the command line does everything else.

**Status:** M1–M10 implemented. `v1.0.0-rc4` is the frozen M1–M9 checkpoint; the M10 candidate is
under final qualification (native clean install, whole-product adversarial campaign, anonymity and
performance qualification). Nothing is claimed beyond the evidence in
[`docs/PROTECTION-CLAIMS.md`](docs/PROTECTION-CLAIMS.md).
**Architecture:** [`ARCHITECTURE-REVIEW.md`](ARCHITECTURE-REVIEW.md) — read this first; every decision
in the code cites it. **M10 GUI:** [`docs/M10-DECISIONS.md`](docs/M10-DECISIONS.md).
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
| `ghostnector-netd` — the privileged helper that touches the host firewall | Linux only |
| `ghostnector-appd` — the privileged helper that owns APP namespaces | Linux only |
| `ghostnector-core` — the control plane: state machine, journal, orchestration | Linux only |
| `ghostnector-cli` | Linux only |
| `ghostnector-gui` — the GTK4 window | Linux only (GTK 4.12+) |
| `ghostnector-bootguard` — early fail-closed baseline after reboot | Linux only |
| `ghostnector-dns` — the DNS chokepoint relay | Linux only |

A future non-Linux backend is therefore *possible* without rewriting the policy engine, but it would
be a different product with materially weaker guarantees.

## Layout

```
crates/
  ghostnector-spec/       shared vocabulary: profiles, state, exemptions, IPC, helper verbs
  ghostnector-policy/     desired state -> nftables ruleset IR + invariant checks
  ghostnector-netd/       privileged helper: apply/revert the host firewall, conntrack
  ghostnector-appd/       privileged helper: APP namespaces, dead ends, namespace verification
  ghostnector-core/       state machine, journal, orchestration, verification, IPC server
  ghostnector-cli/        command-line client
  ghostnector-gui/        GTK4 presentation client (renders Snapshot; decides nothing)
  ghostnector-bootguard/  early fail-closed baseline after reboot
  ghostnector-dns/        the DNS chokepoint relay
docs/
packaging/                systemd units, sysusers, tmpfiles, desktop entry, icon, install scripts
```

## Install and use

```
sudo packaging/install.sh <target-dir>        # files, sysusers, tmpfiles, units, desktop entry
sudo usermod -aG ghostnector $USER            # then log back in
ghostnector connect                            # Tor, whole system (needs the group)
ghostnector connect --network i2p              # I2P, whole system
ghostnector connect --scope app && ghostnector run -- firefox
ghostnector status | watch | disconnect | panic
ghostnector-gui                                # the window: on/off, Tor/I2P, scope, apps, state
```

The GUI is an unprivileged client of `ghostnector-core`: it shows the daemon's authoritative
`Snapshot` (never its own guess), holds no capability, and is never exempt from policy. The window
covers protection on/off, Tor or I2P, whole system or selected applications, per-application
add/list/stop, a confirmed deny-everything action, and a secondary diagnostics view. Technical
information (exemptions, health, verification age, versions) lives there, not in normal use.

### Verification: what "protected and verified" needs

Applying a policy yields `protected, but unverified`; `protected — and verified` is only claimed
from evidence. The shipped unit has no check endpoints configured, so out of the box Ghostnector
reports `protected, but unverified` and names the checks that did not run. To let it conclude,
configure endpoints outside the local network in `/etc/ghostnector/core.env` (example shipped at
`/etc/ghostnector/core.env.example`) and restart `ghostnector-core`:

```
GHOSTNECTOR_VERIFY=--udp-check 203.0.113.10:9999 --check-url http://203.0.113.10/ \
    --canary canary.example@203.0.113.9 --canary-resolver 127.0.0.1:53
```

The UDP endpoint must answer a datagram if one reaches it; the HTTP endpoint must answer `200`
with the address it sees in the body; the canary must resolve to the expected address through the
chokepoint. All of them must be outside the local network, or `connect --lan` is refused with an
explanation (the exception would make the check meaningless). The HTTP endpoint must be reachable
**from a Tor exit** — a private or NAT-internal address is refused by Tor's own guard, which is a
correct fail-closed response, not a product failure.

Two operational notes that matter in real use:

* Starting whole-system protection **cuts remote SSH sessions** as soon as it begins (the deny-first
  baseline drops the server's replies, and transparent Tor carries outbound TCP only). Run the
  command from the console, or drive it from a detached script that disconnects when it is done.
* The install ships two bounded polkit rules: one lets the `ghostnector` service account start and
  stop exactly `ghostnector-tor.service` and `ghostnector-i2pd.service` (start/stop only, nothing
  else); the other lets it repoint systemd-resolved at the DNS chokepoint on connect and revert
  that on disconnect (the three `resolve1` actions `resolvectl` uses, nothing else). Without them
  the unprivileged control plane could not manage its own routers or its own resolver. The firewall
  remains the enforcement in both cases.

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

The GUI is behind a feature so the workspace builds without a display stack. On Linux with GTK
4.12+ development files (`libgtk-4-dev` on Ubuntu 24.04):

```bash
cargo build -p ghostnector-gui --features gtk
xvfb-run -a ./target/debug/ghostnector-gui --socket /run/ghostnector/core.sock   # headless check
```

`CARGO_TARGET_DIR` keeps build artefacts on the Linux filesystem; building directly into `/mnt/c`
is dramatically slower.


## License

Not yet chosen. The dependency set is deliberately permissive (MIT/Apache-2.0); the one prominent
nftables crate, `rustables`, is GPL-3.0, which is why the project uses the MIT-licensed netlink
crates instead. See `docs/IMPLEMENTATION-PLAN.md` (Risk register, R3).
