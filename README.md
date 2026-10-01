<p align="center">
  <img src="docs/assets/ghostnector-logo.png" alt="Ghostnector" width="640">
</p>

# Ghostnector

Ghostnector routes Linux traffic through Tor, either for the whole machine or for selected
applications. It also supports machine-wide I2P. An nftables policy blocks direct traffic when
protection fails. Privileged services apply and verify the kernel policy; you control them through
an unprivileged GTK4 window or command-line client.

- **Status:** the v1.0 product baseline is commit `9b0fe5d`, qualified and frozen. The evidence is in
  [`docs/RELEASE-CANDIDATE-REPORT.md`](docs/RELEASE-CANDIDATE-REPORT.md) and
  [`docs/QUALIFICATION-NOTES.md`](docs/QUALIFICATION-NOTES.md).
- **Platform:** Linux only. WSL2 is a *build and test* environment, not a deployment target.
- **Claims:** nothing is claimed beyond [`docs/PROTECTION-CLAIMS.md`](docs/PROTECTION-CLAIMS.md).
  Ghostnector does **not** provide anonymity against every adversary, and does not protect a
  compromised host. Read [What Ghostnector does not protect against](#what-ghostnector-does-not-protect-against)
  before relying on it.
- **License:** [Apache License 2.0](LICENSE).

---

## How protection works

Proxy settings alone leave enforcement to the application. A stopped proxy, a DNS
misconfiguration, or an application that ignores the setting can allow traffic to take a direct
path. A working connection does not by itself show that traffic went through Tor.

Ghostnector moves enforcement out of application configuration and into the kernel. It owns one
nftables table, applies it atomically, and keeps the machine in a deny-first state throughout. A
protected process cannot reach the network except through the configured path, and when Ghostnector
cannot prove the path is working it blocks instead of returning to the clearnet.

The fail-closed baseline is applied before other protection steps and removed last. If a check
contradicts the claimed protection, the policy disappears, or a router stops, Ghostnector blocks
traffic.

## Platform: Linux only

Ghostnector enforces its protections with Linux kernel primitives: nftables, network namespaces,
capabilities, cgroup and socket ownership. There is no Windows equivalent, and WSL2 is not a
deployment target: a WSL2 instance is a separate VM behind its own NAT, so a daemon running inside it
cannot filter or redirect Windows applications' traffic.

The shared specification and policy engine are portable. The services and clients target Linux:

| Layer | Portability |
|---|---|
| `ghostnector-spec`: profiles, scopes, state, exemptions, IPC, helper verbs | Portable, no OS calls |
| `ghostnector-policy`: desired state → ruleset IR, invariant checks | Portable, pure functions |
| `ghostnector-netd`: privileged helper that owns the host firewall | Linux only |
| `ghostnector-appd`: privileged helper that owns APP namespaces and their relays | Linux only |
| `ghostnector-core`: control plane: state machine, journal, orchestration, verification | Linux only |
| `ghostnector-cli`: command-line client | Linux only |
| `ghostnector-gui`: the GTK4 window | Linux only (GTK 4.12+) |
| `ghostnector-bootguard`: early fail-closed baseline after a reboot | Linux only |
| `ghostnector-dns`: the DNS chokepoint relay | Linux only |

A non-Linux backend could reuse the policy engine, but would need its own enforcement design and
protection claims.

## Concepts

### SYSTEM scope: machine-wide transparent Tor

`ghostnector connect` protects every local process. Locally generated TCP is redirected to Tor's
`TransPort`; port 53 is redirected to the DNS chokepoint; everything else is denied. The redirects
and the default-deny verdict live in one nftables table (`inet ghostnector`) applied as a single
atomic transaction, so the machine is never in a half-applied state. A small, enumerated set of
exemptions exists (Tor's own uid, the DHCP client, loopback, and an opt-in LAN set); the exemption
list is derived from the rules that cite it and shown in the interface, so users can inspect the
exceptions the policy permits.

Transparent Tor carries outbound TCP only. UDP packets are **rejected rather than dropped**, so
QUIC and real-time clients fail fast instead of hanging. This is a deliberate availability cost
documented in the protection claims.

### APP scope: per-application namespace isolation

`ghostnector connect --scope app` leaves the machine open and protects only applications launched
through `ghostnector run`. Each protected application gets its own network namespace whose default
route terminates on a dead-end local `dummy` device. There is no route capable of carrying
application traffic to an external network; the only mechanism that makes a destination reachable is
a namespace-local DNAT.

Because transparent Tor needs the original destination, and the original destination is lost when
the NAT happens inside the namespace, each namespace runs a small **per-namespace relay**:

- the namespace's catch-all TCP DNAT targets `127.0.0.1:9041`, inside the same namespace;
- the relay runs as the application's own uid with every capability set empty, reads
  `SO_ORIGINAL_DST` from the namespace's own conntrack, and refuses any connection that has no
  original destination (it is never an open proxy);
- it speaks SOCKS5 to the core's SocksPort as the application's address, with a per-group credential,
  so Tor's `IsolateSOCKSAuth` keys each group separately; it never parses payloads;
- the namespace may reach only the DNS chokepoint and the SocksPort, and IPv6 is absent by
  construction rather than denied by a rule.

Source identity is preserved: the path uses neither masquerade nor SNAT. Each group has a distinct
source address and its own isolation key. Whether Tor maps that to distinct circuits is Tor's behaviour and is not claimed.

APP scope has a structurally different claim set (PC-17…PC-21) and its own adversarial suite; see
[`docs/PROTECTION-CLAIMS.md`](docs/PROTECTION-CLAIMS.md).

### Tor and I2P

Choose either Tor or I2P. The validator refuses a request that enables both,
and refuses APP+I2P outright, because a per-application I2P conduit does not exist in v1. I2P runs
client-only, with no clearnet outproxy; the I2P ruleset carries exactly the router's own exemption
plus DHCP, and no redirect. I2P `Protected` requires a configured canary fetched through the
router's loopback proxy; without one the state stays `Degraded` by design.

### Fail-closed design

- **Deny first.** The fail-closed baseline is applied before any service starts and removed last.
- **Escalate, never fall back.** Once protection is requested, a failure produces `Blocked` and the
  baseline. It does not reopen direct access. Rollback to the open network is allowed only from a
  pre-protection state.
- **Bounded claims.** `Protected` means "a policy is applied, at least one configured check has
  passed since it was applied, and no configured check has contradicted a claim since then".
  The result expires after the verification interval plus its timeout.
- **Unactionable evidence is not a pass.** A check that cannot run is `inconclusive`, never a leak
  and never a pass. The interface lists the checks that did not run.

### DNS chokepoint

Every DNS query from a protected process is redirected to a loopback chokepoint relay, which
forwards to the configured upstream: Tor's `DNSPort` in Tor mode, or an encrypted resolver in
DNS-lockdown mode. The relay forwards bytes; it does not answer from cache, rewrite names, or log
queries (only a throttled drop counter). Pointing an application at a hard-coded resolver does not
bypass it: the packet is redirected. If the relay stops, resolution stops rather than falling back.

### nftables enforcement

Ghostnector owns one table, `inet ghostnector`, and replaces its rules atomically. Foreign tables are never
touched. `netd` is the only component that writes it, and the policy engine refuses a ruleset that
would accept traffic citing no listed exemption.

### Tor supervision

Ghostnector generates Tor's configuration, starts and stops it through a bounded polkit rule, waits
for bootstrap with a timeout, and treats "started and immediately exited" as a failed connect. A
profile change (for example, moving from SYSTEM to APP) rewrites the torrc and **restarts** Tor,
because the listeners move. Qualification defect D-53 records the earlier failure to restart an
instance that was still listening on loopback. Health is read over Tor's control port using cookie authentication,
and only aggregate statistics are used. Destinations are not collected.

### Boot guard

When protection was requested before shutdown, `ghostnector-bootguard` runs before
`network-pre.target` and applies the fail-closed baseline before the network is configured, so no
application packet leaves unprotected. The guard runs as the control plane's own user with exactly
`CAP_NET_ADMIN` and `NoNewPrivileges`; it owns the helper's socket and a copy of the fail-closed
policy that `netd` keeps current on every apply, and it writes nothing. The ordering claim itself
("no packet left before the deny") is not independently observed; see G6 below.

### Kernel-policy verification and tamper detection

Enforcement lives in the kernel and in independent services; the control plane holds no policy, so
killing it changes nothing. Verification is two-layered:

1. **Probes that are themselves subject to policy**: a UDP check that must not leave, an HTTP check
   that must leave through the protected path and report a foreign address, and a DNS canary through
   the chokepoint. If a probe can reach the internet directly, that is the alarm.
2. **An effective-policy comparison**: `netd` records what the kernel holds and compares it against
   what it applied. This catches a change that no probe traverses. It is exact (both sides use the
   same formatter) but not cryptographic; a process holding `CAP_NET_ADMIN` can replace its subject,
   which is the same out-of-scope line as root (G10).

On an alarm the fail-closed baseline replaces whatever is in the kernel, and the state becomes
`Blocked`.

### Panic

`ghostnector panic` denies everything immediately and leaves the services running. `disconnect`
reverts the policy, restores the resolver configuration byte-for-byte (refusing to clobber a change
someone else made in the meantime), stops the services Ghostnector started, and records that
protection is no longer wanted. [`docs/RECOVERY.md`](docs/RECOVERY.md) is the documented way out of a
blocked machine.

## Threat model

The full model, including adversaries, scope, and residual risks, is in
[`ARCHITECTURE-REVIEW.md`](ARCHITECTURE-REVIEW.md) §1, and the falsifiable claims are
[`docs/PROTECTION-CLAIMS.md`](docs/PROTECTION-CLAIMS.md). In summary:

### What Ghostnector protects against

- **Ordinary direct egress.** A protected process cannot open a clearnet TCP connection (PC-01) or
  send UDP (PC-02); IPv6 egress is denied (PC-05).
- **DNS leaks.** Port-53 traffic is redirected to the chokepoint, regardless of the resolver an
  application hard-codes (PC-03).
- **Routing through the configured anonymity network.** Supported traffic follows Tor (or I2P)
  while protection is reported (PC-06), and the exit is not this machine (PC-07).
- **Namespace and process isolation (APP scope).** An application cannot escape its namespace, and
  its traffic dies locally if the conduit is removed (PC-17, PC-18); source identity is preserved
  (PC-19) and DNS inside the namespace reaches only the chokepoint (PC-20).
- **Fail-closed behavior.** Tor stopping (PC-11), the DNS relay stopping (PC-13), the control plane
  dying (PC-12), or the policy disappearing (PC-16) does not open a path.
- **Policy tamper detection.** A modification that would permit prohibited traffic is noticed and
  replaced (PC-08).
- **Accidental bypass.** Transitions never widen the policy beyond the union of the before/after
  states (PC-14), and disconnect restores exactly what was there (PC-15).
- **Reboot with protection requested.** The fail-closed baseline is in place before the network
  (PC-10).

### What Ghostnector does not protect against

- **Anonymity against every adversary.** No claim is made about unlinkability, about the exit being
  trustworthy, or about what a destination or an exit can infer.
- **A compromised endpoint or boot chain.** Root, the kernel, and anything holding `CAP_NET_ADMIN`
  can replace the policy or the comparison that watches it (G10). This is the host-trusted line.
- **Application-layer identity disclosure.** Logging into an account, reusing a unique nickname, or
  sending identifying content is not addressed by a network policy.
- **Browser and device fingerprinting.** Ghostnector constrains the network path, not what the
  browser reveals about itself.
- **Behavioral and traffic correlation.** A global adversary correlating timing and volume at both
  ends is out of scope.
- **Anonymity-network weaknesses.** Ghostnector can route through Tor or I2P; it cannot fix
  weaknesses in them.
- **Anything outside the enforcement boundary.** A machine-wide scope covers local processes; it
  does not cover other machines. `USER` scope does not cover root daemons. Traffic that never
  traverses the host (for example, a separate device on the LAN) is not affected.
- **DHCPv6-only networks.** The DHCP exemption is IPv4 (G11), because IPv6 is denied in every
  profile, so a network that can only maintain connectivity through DHCPv6 lease renewal is not
  supported while protected.

### Realistic anonymity limitations

Routing traffic through Tor makes the network path harder to link to the machine; it does not make
the user unlinkable. The observable properties that remain include: what the destination learns from
the application protocol; what the user types and authenticates; the timing and volume of traffic;
and the fact that a network can often tell that Tor is being used, even when it cannot tell what is
being carried. Bridges raise the cost of blocking Tor, but they do not eliminate it. Distinct source
addresses between two APP groups give Tor an isolation key; they are not proof of distinct circuits.
The qualification measures what Ghostnector's own enforcement does, under a documented test
environment. It does not prove anonymity.

## Install and build

### Requirements

- A Linux host with a recent kernel (the qualification environment was Ubuntu 24.04.5, kernel 6.8)
  and `nftables` (1.0.9 in the qualification environment).
- Rust stable (the workspace pins `rust-version = "1.80"` and a `stable` toolchain in
  `rust-toolchain.toml`).
- `tor` for Tor mode, `i2pd` for I2P mode. A production install should pin a current `i2pd`: the
  Ubuntu-packaged 2.49.0 was observed to crash under load during qualification.
- GTK 4.12+ development files (`libgtk-4-dev`) to build the GUI; the workspace itself builds
  without a display stack because the GUI sits behind a feature.

### Build

```bash
cargo build --workspace --release
cargo build -p ghostnector-gui --features gtk        # the window, on Linux with GTK 4.12+
```

The installer expects all binaries in one build directory, including the GTK-enabled GUI. The GUI
command above creates a debug build by default. For a release installation, build it with
`cargo build -p ghostnector-gui --features gtk --release` as well, then use `target/release` as the
installer's `<target-dir>`. If you set `CARGO_TARGET_DIR`, use its `release` subdirectory.

### Install

```bash
sudo packaging/install.sh <target-dir>   # binaries, sysusers, tmpfiles, units, desktop entry
sudo usermod -aG ghostnector "$USER"     # then log back in
```

The install ships two bounded polkit rules: one lets the `ghostnector` service account start and stop
exactly `ghostnector-tor.service` and `ghostnector-i2pd.service`; the other lets it repoint the
resolver at the DNS chokepoint on connect and revert that on disconnect. Without them the
unprivileged control plane could not manage its own routers or resolver. The firewall remains the
enforcement in both cases.

The installer enables the system units but does not start the control plane immediately. After
logging back in with the new group membership, run `sudo systemctl start ghostnector-core` before
using the client.

### Basic usage

```bash
ghostnector status                            # state and why it is that way
ghostnector connect                           # Tor, whole system (needs the ghostnector group)
ghostnector connect --network i2p             # I2P, whole system
ghostnector connect --scope app               # protect only applications launched through `run`
ghostnector run -- firefox                    # launch one application into its namespace
ghostnector apps                              # list protected applications
ghostnector stop-app <ID>                     # stop one
ghostnector watch                             # follow state changes
ghostnector disconnect                        # return the network to how it was
ghostnector panic                             # deny everything now
ghostnector-gui                               # the window: on/off, Tor/I2P, scope, apps, state
```

The GUI is an unprivileged client of `ghostnector-core`: it renders the daemon's authoritative
snapshot (never its own guess), holds no capability, and is never exempt from policy. The window
covers protection on/off, Tor or I2P, whole system or selected applications, per-application
add/list/stop, a confirmed deny-everything action, and a secondary diagnostics view. Technical
information (exemptions, health, verification age, versions) lives there, not in normal use.

### What "protected and verified" needs

Applying a policy yields `protected, but unverified`; `protected — and verified` is only claimed from
evidence. The shipped unit has no check endpoints configured, so out of the box Ghostnector reports
`protected, but unverified` and names the checks that did not run. To let it conclude, configure
endpoints outside the local network in `/etc/ghostnector/core.env` (an example is shipped at
`/etc/ghostnector/core.env.example`) and restart `ghostnector-core`:

```
GHOSTNECTOR_VERIFY=--udp-check 203.0.113.10:9999 --check-url http://203.0.113.10/ \
    --canary canary.example@203.0.113.9 --canary-resolver 127.0.0.1:53
```

Replace the example addresses and domain with endpoints you control before enabling verification.

The UDP endpoint must answer a datagram if one reaches it; the HTTP endpoint must answer `200` with
the address it sees in the body; the canary must resolve to the expected address through the
chokepoint. All of them must be outside the local network, or `connect --lan` is refused with an
explanation (the exception would make the check meaningless). The HTTP endpoint must be reachable
**from a Tor exit**. Tor's own guard refuses a private or NAT-internal address. That is a
correct fail-closed response, not a product failure.

Before connecting:

- Starting whole-system protection **cuts remote SSH sessions** as soon as it begins (the deny-first
  baseline drops the server's replies, and transparent Tor carries outbound TCP only). Run the
  command from the console, or drive it from a detached script that disconnects when it is done.
- A persisted `Blocked` intent re-applies the baseline on the next start of the control plane. The
  documented recovery path is [`docs/RECOVERY.md`](docs/RECOVERY.md).

### Build and test notes

In the documented Windows development environment, Smart App Control blocks locally built
unsigned binaries. Windows was used for editing and static checks:

```powershell
$cargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"
& $cargo fmt --all
& $cargo clippy --workspace --all-targets -- -D warnings
& $cargo check --workspace --target x86_64-unknown-linux-gnu
```

Run the unit tests and the nftables, namespace, and systemd checks on Linux or WSL2:

```bash
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
4.12+ development files:

```bash
cargo build -p ghostnector-gui --features gtk
xvfb-run -a ./target/debug/ghostnector-gui --socket /run/ghostnector/core.sock   # headless check
```

`CARGO_TARGET_DIR` keeps build artefacts on the Linux filesystem; building directly into `/mnt/c` is
slower in the documented development environment.

## Architecture

```
crates/
  ghostnector-spec/       shared vocabulary: profiles, state, exemptions, IPC, helper verbs
  ghostnector-policy/     desired state -> nftables ruleset IR + invariant checks
  ghostnector-netd/       privileged helper: apply/revert the host firewall, conntrack, policy compare
  ghostnector-appd/       privileged helper: APP namespaces, dead ends, relays, namespace verification
  ghostnector-core/       state machine, journal, orchestration, verification, IPC server
  ghostnector-cli/        command-line client
  ghostnector-gui/        GTK4 presentation client (renders Snapshot; decides nothing)
  ghostnector-bootguard/  early fail-closed baseline after reboot
  ghostnector-dns/        the DNS chokepoint relay
docs/                     design records, claims, test plan, qualification and release reports
packaging/                systemd units, sysusers, tmpfiles, desktop entry, icon, install scripts
perf/                     performance campaign records and APP-launch optimization results
```

The architecture separates the portable policy engine from two privileged helpers with limited
operations:

- **`ghostnector-core`** owns the state machine and the journal, orchestrates Tor/I2P and the
  resolver, runs verification, and serves IPC. It holds **no** firewall capability and **no**
  exemption.
- **`ghostnector-netd`** is the only writer of the host table. **`ghostnector-appd`** owns APP
  namespaces and their relays. Both expose a small verb set over a `SO_PEERCRED`-checked unix
  socket.
- **`ghostnector-bootguard`** re-applies the fail-closed baseline before the network on a protected
  reboot.
- The **GUI** and **CLI** are unprivileged clients. Enforcement lives in the kernel and in independent
  services, so control-plane death does not change the data plane.

The full design rationale, the decision register (DR-1…DR-20), the topology diagrams and the
invariants are in [`ARCHITECTURE-REVIEW.md`](ARCHITECTURE-REVIEW.md); the milestone execution view is
[`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md).

## Security model

The security model is defined by the review and made falsifiable by
[`docs/PROTECTION-CLAIMS.md`](docs/PROTECTION-CLAIMS.md). The main properties are:

- **Kernel enforcement.** The policy is an nftables ruleset applied in one atomic transaction;
  application configuration is not the enforcement.
- **Least privilege.** The GUI holds no capability. `netd` and `appd` hold only what their verbs
  need. The boot guard holds exactly `CAP_NET_ADMIN` and `NoNewPrivileges`. The APP launcher clears
  every capability set before it executes the user's shell.
- **No persistent traffic metadata.** Counters and an in-memory block list only; bridge lines are
  treated as secrets.
- **Explicit, enumerated exemptions.** The exemption list is derived from the rules and displayed;
  an accept that cites no listed exemption is refused by the invariant checker.
- **Enablement is a validated state, not independent toggles.** Only coherent mode × scope
  combinations can be constructed, so dangerous combinations are unrepresentable.
- **Honest state.** An inconclusive check is never shown as protection or as a leak; unconfigured
  checks are named; a verification result expires.

## Qualification methodology

Ghostnector was qualified as an installed product on a native Ubuntu VM, not only as source. The
method is adversarial: the goal is to make `Protected` false while the product still believes it is
true, and to classify every observation as a held claim, a contradiction, or inconclusive, using an
observation point that is **not** Ghostnector. The methodology, observation points, control-traffic
inventory and the defect ledger are in
[`docs/ADVERSARIAL-TEST-PLAN.md`](docs/ADVERSARIAL-TEST-PLAN.md). Environment facts and workarounds
(so that later runs can tell environment artifacts apart from product findings) are in
[`docs/QUALIFICATION-NOTES.md`](docs/QUALIFICATION-NOTES.md).

The campaign covered: leakage with a host-side far-side observer and clock correlation; real-Tor APP
transparency; lifecycle (install/uninstall/reinstall/reboot/lockout recovery); the installed boot
guard across hard resets; create-path failure injection; APP and I2P adversarial suites; the M1-M7
adversarial suite; a full M1-M10 release gate; and a performance campaign followed by an APP-launch
optimization and its requalification.

**These are qualification results under the documented test environment and threat model.** They
show that, on that environment, the claims held and the listed adversarial cases failed to falsify
them. They are not a universal proof of anonymity, and an unconcluded check is never a pass.

### Qualification scoreboard (v1.0 product baseline `9b0fe5d`)

| Suite | Result |
|---|---|
| Leakage (VM-side) | **30 held / 0 contradicted / 0 inconclusive** |
| External leakage analyzer | **0 violations / 0 ambiguous**, observation channel proven live (expected arrivals and heartbeats observed) |
| Real-Tor APP | **17 / 0 / 0** |
| Lifecycle | **33 / 0 / 0** |
| Boot guard: prepare | **8 / 0 / 0** |
| Boot guard: verify protected | **7 / 0 / 0** |
| Boot guard: verify off | **4 / 0 / 0** |
| Create-path failure injections | **4 / 4 PASS** (partial `ip -batch`, nft apply, relay early death, relay never listening) |
| APP adversarial | **13 / 0 / 0** |
| I2P adversarial | **26 / 0 / 0** |
| M1-M7 adversarial | **27 / 0 / 1** (the one inconclusive is the documented no-IPv6 case, AS-4) |
| Full M1-M10 gate | **21 / 21**, all `rc=0` |
| Unit tests | **463 passed / 0 failed** |
| Release blockers at qualification close | **0** |

## Benchmarks

These are the final measured results from the installed product. They were produced by the
qualification campaign and are **not regenerated here**; the raw records and method notes are in
[`perf/CAMPAIGN-RESULTS.md`](perf/CAMPAIGN-RESULTS.md) and
[`perf/APP-LAUNCH-OPTIMIZATION.md`](perf/APP-LAUNCH-OPTIMIZATION.md). The measured environment was an
Ubuntu 24.04.5 VM (4 vCPU, 7.9 GB, kernel 6.8.0-142); absolute network numbers are not portable to
other links.

### APP launch (installed product, N = 10)

| Metric | Value |
|---|---|
| p10 | `291.9 ms` |
| median | `301.9 ms` |
| p90 | `352.7 ms` |
| direct same-run median | `63.4 ms` |
| previous qualified median | `665.6 ms` |
| improvement | `−54.6 %` |
| approximate Ghostnector-added median launch cost | `238 ms` |

Phase medians: **t0 → netns `78.3 ms`**, **netns → relay `147.6 ms`**, **relay → app `76.0 ms`**.

The reduction came from the `ghostnector-appd` namespace-create work: one `ip -batch` transaction per
phase instead of ~18 separate forks, `/sys/class/net` presence probes, a 10 ms relay-readiness poll
with fail-fast on a dead relay, and folding bridge isolation into the batch. No anonymity, isolation,
fail-closed or least-privilege property changed.

### HTTP / TTFB

The primary HTTP figure is the **same-instance** comparison, in which the equivalent baseline route
redirects into the product's own Tor instance. This controls the Tor instance and isolates
Ghostnector's increment; a two-instance design cannot, because two Tor instances differ from each
other by more than the product's overhead.

| Metric | Value |
|---|---|
| Ghostnector HTTP total | `526.4 ms` |
| equivalent Tor | `510.3 ms` |
| paired median delta | `+55.3 ms` |
| paired p10 / p90 delta | `−145.4 / +253.0 ms` |
| Ghostnector TTFB | `347.6 ms` |
| equivalent Tor TTFB | `365.7 ms` |

Read these with care. Tor and network variance dominate differences this small, and aggregate
medians and paired-median differences are different statistics: in the same-instance window the two
aggregate medians sit ~16 ms apart while the paired median difference is +55 ms, because pairing
cancels per-sample Tor variation. The campaign's earlier two-instance run even had the product
appearing faster, which was traced to instance variance rather than anything Ghostnector does.
**No claim is made that Ghostnector is faster than Tor.**

### DNS

| Metric | Value |
|---|---|
| chokepoint incremental paired median | `+3.9 ms` |
| p10 / p90 | `−19.7 / +24.0 ms` |
| NAT-shaped product route | `141.3 ms` |
| direct DNSPort | `138.8 ms` |
| equivalent route | `307.1 ms` |

The chokepoint's own hops are ~2 ms; the sign and size of any remaining difference move with Tor's
per-flow state, which swings by ±130 ms.

### CPU and memory

| Metric | Value |
|---|---|
| `appd` CPU per launch | `21.7 ms` (previous `56.7 ms`) |
| `core` CPU per launch | `6.7 ms` (previous `20.0 ms`) |
| `appd` RSS | `2.95 MB` |
| `core` RSS | `3.14 MB` |
| idle helpers | approximately `0.02 % CPU` |
| relay during a download | `2.58 MB` RSS / `0.566 % CPU` |

An earlier `ps pcpu` figure of "~0.7 % CPU idle" was a lifetime-average artifact; the campaign
replaced it with `/proc` deltas.

## Known and documented limitations

- **G6: boot ordering is not independently observed.** The boot guard applies the deny before the
  network-pre barrier and its own success is asserted on the installed product, but "no packet left
  before the deny" has not been observed at an independent boundary.
- **G8: no external vantage.** There is no ISP-facing observation point, so "the exit is not your
  ISP" and the external half of the DNS claim cannot be established from this machine.
- **G9: `Protected` is reachable with a subset of checks configured.** The interface names the
  checks that did not run, but nothing forces a minimum set.
- **G10: privileged attackers are out of scope.** Root and anything holding `CAP_NET_ADMIN` can
  replace the policy or the comparison that watches it. This is the host-trusted line.
- **G11: the DHCP exemption is IPv4 only**, because IPv6 is denied in every profile.
- **G12: a transient outage can leave the machine `Blocked`** until a person acts, because a failed
  verification is answered with the fail-closed baseline. This is deliberate.
- **GUI automation gaps.** Under Xvfb the header popover and the GTK file picker could not be driven
  by automation; their product-side behavior rests on model/unit tests, a D-Bus action probe, and the
  core API the picker calls.
- **No-IPv6 qualification case (AS-4).** The M1-M7 adversarial suite has one inconclusive case
  because the qualification link had no global IPv6; a failed IPv6 attempt there proves nothing
  about the policy. IPv6 denial is verified on a v6-capable link (AS-3).
- **APP adversarial boundary (GA-1).** The APP suite has no ISP-facing vantage: "nothing crossed" is
  observed at the host link and fake endpoints, not outside the host.
- **Distinct Tor circuits are not claimed (GA-2).** Per-group source identities are demonstrated;
  Tor's circuit choice is Tor's behavior.
- **APP exit-identity check is narrower (GA-3).** It compares against the namespace's own addresses
  and the core address, not every host interface.
- **I2P profile-change analogue (D-53).** The i2pd bring-up has the same start-without-reload shape
  that Tor did; its listeners do not move between profiles, so no failure has been observed. Recorded
  for a future change rather than altered during the closed campaign.
- **Disconnect latency (D-51 residual).** A router that ignores `SIGTERM` costs at most 20 s on
  disconnect instead of 90 s.
- **Dependency licensing.** Ghostnector itself is Apache-2.0. The dependency set is deliberately
  permissive (MIT / Apache-2.0); the one prominent nftables crate, `rustables`, is GPL-3.0, which is
  why the project uses the MIT-licensed netlink crates instead. See the risk register (R3) in
  [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md).

## Repository documentation

Start with the architecture review for the design, the protection claims for guarantees and limits,
and the release report for test evidence.

| Document | What it is |
|---|---|
| [`ARCHITECTURE-REVIEW.md`](ARCHITECTURE-REVIEW.md) | The design: threat model, decision register, topology, invariants. Read this first. |
| [`docs/PROTECTION-CLAIMS.md`](docs/PROTECTION-CLAIMS.md) | Every falsifiable claim (`Protected` means this), what falsifies it, and the open gaps. |
| [`docs/ADVERSARIAL-TEST-PLAN.md`](docs/ADVERSARIAL-TEST-PLAN.md) | The adversarial methodology, observation points, control-traffic inventory, and defect ledger. |
| [`docs/RELEASE-CANDIDATE-REPORT.md`](docs/RELEASE-CANDIDATE-REPORT.md) | The release-candidate and final-candidate qualification report, including the benchmark and requalification summary. |
| [`docs/QUALIFICATION-NOTES.md`](docs/QUALIFICATION-NOTES.md) | Qualification environment facts, workarounds, defect narratives, and the durability notes. |
| [`perf/CAMPAIGN-RESULTS.md`](perf/CAMPAIGN-RESULTS.md) | The performance campaign: HTTP, DNS, APP launch, resources, and the methodology corrections. |
| [`perf/APP-LAUNCH-OPTIMIZATION.md`](perf/APP-LAUNCH-OPTIMIZATION.md) | The APP-launch optimization: measured attribution, CPU/RSS impact, regressions, and the rejected change. |
| [`docs/RECOVERY.md`](docs/RECOVERY.md) | How to get a blocked machine back. |
| [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md) | The milestone execution view (M0-M10) and the risk register. |
| [`docs/M8-DECISIONS.md`](docs/M8-DECISIONS.md) | APP-scope decisions (dead-end namespaces, launcher, per-namespace relay amendment). |
| [`docs/M9-DECISIONS.md`](docs/M9-DECISIONS.md) | I2P decisions (independence, client-only, canary, explicit refusals). |
| [`docs/M10-DECISIONS.md`](docs/M10-DECISIONS.md) | GUI decisions, the Phase-1 findings, and the campaign decisions. |
| [`docs/HANDOFF-M10.md`](docs/HANDOFF-M10.md) | Historical milestone handoff (superseded: M10 is complete and qualified). Kept for the engineering record. |

## Development transparency

Ghostnector's implementation was produced with AI-assisted code generation. I acted as the project's architect and supervisor throughout: I defined the system architecture and threat model, made the design and security decisions, reviewed and directed implementation changes, chose debugging and remediation strategies, interpreted qualification failures, and decided which fixes or architectural changes were acceptable. The AI generated the code under that direction; I do not claim to have hand-written the repository line by line.

The design documents, defect ledger, qualification reports, adversarial findings, performance work, and release history record those decisions and the evidence used to assess them.

## Engineering history

The repository retains earlier measurements and findings. Later documents identify the results
that supersede them:

- The qualified v1.0 **product** baseline is commit `9b0fe5d`. Commits after it are qualification
  tooling and documentation only.
- `v1.0.0-rc1` … `v1.0.0-rc4` are historical checkpoints. RC1 was **not** a candidate whose claims
  all held: the M7 adversarial campaign falsified two claims (PC-03, PC-06) and found three more
  defects behind them. That falsification is preserved in
  [`docs/PROTECTION-CLAIMS.md`](docs/PROTECTION-CLAIMS.md) Appendix A, including the findings that led to corrections.
- Earlier performance numbers (for example the 93 ms and "~0.7 % CPU idle" figures) were produced by
  a different, inequivalent benchmark and were superseded by the campaign in
  [`perf/CAMPAIGN-RESULTS.md`](perf/CAMPAIGN-RESULTS.md); the earlier `APP-scope launch` numbers in
  [`docs/QUALIFICATION-NOTES.md`](docs/QUALIFICATION-NOTES.md) are likewise superseded by the final
  APP-launch results above.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). The dependency set is deliberately
permissive (MIT / Apache-2.0); see Risk R3 in
[`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md) for why `rustables` (GPL-3.0) is not
used.
