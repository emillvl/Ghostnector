# Ghostnector — Implementation Plan

Source of truth for *what to build and in what order*. Architecture and rationale live in
[`../ARCHITECTURE-REVIEW.md`](../ARCHITECTURE-REVIEW.md); this document is the execution view of it.
Every milestone below names the review sections and invariants it satisfies.

**Definition of done for any milestone:** its gate passes on real Linux (WSL2 bares bones fine, CI on a
distro container for the rest), the invariants it claims are covered by automated tests, and no
milestone leaves the repo in a state where `cargo test` fails.

---

## 1. Milestones

| # | Milestone | Delivers | Gate (must pass before moving on) | Review refs |
|---|---|---|---|---|
| **M0** | Contracts & skeleton | Workspace, `ghostnector-spec` (profiles, state, exemptions, IPC, helper verbs), plan, README | `cargo test` green on Windows; `cargo check --target x86_64-unknown-linux-gnu` green; invalid mode combinations unconstructable | §2.1, §3.2, DR-3, I8, I9 |
| **M1** | Policy engine + `netd` | `ghostnector-policy` (desired state → ruleset IR, invariants in code), `netd` applier with `ApplyProfile`/`Revert`/`FlushConntrack`/`Report`, journaled sysctls, atomic batches | On WSL: deny-all applies; a test process cannot reach the fake ISP; revert removes **only** our objects; fault injection at every batch boundary leaves the previous generation intact; golden ruleset tests | §7, §12, DR-1, DR-2, DR-17, I1, I5, I7, I9 |
| **M2** | Core state machine + CLI | `ghostnector-core` (desired/observed diff, `assert()`, journal + intent, IPC server), `ghostnector-cli` (`status`, `connect`, `disconnect`, `panic`, `exemptions`) | `kill -9` at every step of connect/disconnect; restart reconciles from the kernel, never from the journal alone; connect/disconnect storm shows zero clearnet packets at the fake ISP | §11, §12, DR-14, DR-15, I3, I4 |
| **M3** | Tor integration | `tor` unit + generated config, deny-first bootstrap, bootstrap wait with timeout, loop prevention, health via control port (cookie auth, aggregate stats only) | Bootstrap failure aborts and rolls back; Tor death leaves the host `BLOCKED`; no clearnet packet during the transition; no destination ever appears in logs | §9, DR-4, DR-8, DR-9, I1, I6 |
| **M4** | Resolver ownership | Detection + journaled changes for systemd-resolved / NetworkManager / static; hash-checked revert; conflict path | Revert leaves `/etc/resolv.conf` byte-identical; a concurrent edit produces a conflict warning, never a clobber; port-53 egress is kernel-blocked regardless of resolver state | §8.6, DR-10, I2, I5 |
| **M5** | Verification | `ghostnector-verify`: escape test, exit-identity check, DNS canary, freshness reporting; escalation to `BLOCKED` | Deleting one rule by hand causes escalation to `BLOCKED` within the configured window; the verifier is itself subject to policy (escape = alarm) | §14.5, DR-18, §11 |
| **M6** | Boot guard + recovery | `ghostnector-bootguard` unit, persisted intent, recovery path (`ghostnector recover`, kernel cmdline escape hatch) | Reboot with intent=protected: no application packet leaves before the baseline is applied; recovery works with the network down | §11.5, §12.5, DR-16 |
| **M7** | Test harness + CI | Hermetic harness (fake ISP netns, recording resolver/destination, canary zone; chutney job), GitHub Actions workflow, external-vantage release checklist. **Delivered:** the harness (`scripts/lib/gh-harness.sh`, `scripts/adversarial.sh`). **Not built:** CI workflow, chutney job, external-vantage checklist. | Full leak matrix (§14.3) automated; CI runs the privileged suite in a container; failures are attributable | §14, §17.3 |
| **M8** | `APP` scope | Dead-end APP namespaces (default route into a `dummy` with no peer), netns + veth + isolated bridge wiring, netns-local DNAT, source-address preservation, IPv6 disabled in-netns, shell-in-netns launcher, separate `ghostnector-appd` | Two apps present **distinct source identities** to Tor (the circuit claim is Tor's and is recorded separately); masquerading is detected and rejected by test; a flushed DNAT sends nothing to the host veth (`scripts/app-topology-test.sh` extended by the AA cases) | §3.4, §9.3, DR-6, DR-7, `docs/M8-DECISIONS.md` |
| **M9** | I2P module | `i2pd` unit in its own namespace, client-only, no outproxy, proxy exposure, explicit warnings | Enabling/disabling I2P never changes Tor policy; i2pd cannot reach the clearnet except as an I2P participant; CLEANET names fail | §10, DR-11 |
| **M10** | GUI | GTK4 client over the same IPC; evidence-first state display; exemption list; "cannot protect against" screen | GUI holds no privilege and no exemption; killing it changes nothing; every claim on screen is traceable to a `Snapshot` field | §5, §14.6, DR-12, DR-19 |

Milestones M1–M6 are the v1 product. M8 and M9 are v1.1/v1.2. M10 is deliberately last.

---

## 2. Implementation decisions that need your awareness

### D1 — Ruleset pipeline: IR first, applier behind a trait

```
DesiredState ──► RulesetIR ──► renderer ──► Applier
   (spec)         (policy)      (text/NL)     ├── NftCli  (M1, fast path)
                                              └── Netlink (M1.5, no external binary)
```

- The **IR and renderer are pure and portable**, so they are unit-tested and golden-filed on any host
  (including this Windows machine) — that is where policy correctness lives.
- The `NftCli` applier invokes `nft -f -` with an **absolute path, no shell, no user input**, and a
  generated script. It is the fast path to a working product and is what most infrastructure does.
- The `Netlink` applier writes the same IR over netlink (MIT-licensed `netlink-packet-netfilter`),
  removing the external binary from the privileged path and giving precise extended-ACK errors.
- Integration tests validate the *policy*, not the applier, so both appliers are held to the same bar.

Tradeoff being made: a small external-binary dependency in the privileged path for a short time, in
exchange for a working, testable product much earlier. If you want the no-external-binary rule
enforced from day one, say so and M1 slips by roughly the netlink encoder work.

### D2 — License: keep it permissive, avoid `rustables`

`rustables` (the mature nftables crate) is **GPL-3.0-or-later**. Linking it would make Ghostnector
GPL-3 as a whole. Everything else in the dependency set is MIT/Apache-2.0, and Tor/i2pd/dnscrypt-proxy
are BSD/ISC. Decision: implement on the MIT netlink crates so the license stays yours to choose.
Override is a one-line dependency change if you *want* copyleft (defensible for a privacy tool).

### D3 — Rust, `panic = "abort"` in release

A privileged daemon should die and be restarted by systemd rather than unwind into an unknown state;
`core` reconciles actual state from the kernel on restart, so this is safe by construction (DR-14).

---

## 3. Risk register

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | WSL2 kernel/systemd differs from bare metal | Integration tests pass where production would not | Keep the suite distro-agnostic; run it in a real distro container in CI as the authority; treat WSL as the fast loop only |
| R2 | Hand-rolled nftables netlink encoder is a large surface | M1.5 slips; subtle policy bugs | IR + golden tests make policy independent of the encoder; start with only the constructs v1 needs (table, chains, meta/ct expressions, sets, counters, verdicts, redirect/dnat/reject); keep `NftCli` as the reference applier |
| R3 | GPL-3 contamination via `rustables` | License change for the whole project | Avoided (D2); recorded here so it is a decision, not an accident |
| R4 | Tor bootstrap/control-port behavior varies by version | Health detection breaks, false `BLOCKED` | Version-tolerant control-port parsing + a TCP readiness probe + one self-test fetch; never gate on a single string |
| R5 | Resolver ownership differs across distros | "It broke my network" | Detect-and-branch (§8.6); never rely on resolver config for leak prevention; hash-checked revert |
| R6 | Hermetic Tor tests need chutney (builds Tor from source) | Slow/ brittle CI | Fast tests use a mock Tor SOCKS/TransPort stand-in; chutney runs in a nightly job and before releases |
| R7 | `CAP_SYS_ADMIN` for namespace mode widens `netd` | Bigger privileged attack surface | M8 keeps namespace verbs in a separate unit with a closed verb set; `APP` scope is not on the v1 critical path |
| R8 | Multi-distro packaging | Scope creep | Debian/Ubuntu first + portable tarball; other distros via user requests |
| R9 | **Windows Smart App Control blocks execution of freshly built (unsigned) test binaries** — observed 2026-09-24, CodeIntegrity event 3077, `os error 4551` | `cargo test` is unusable on this machine, unpredictably (one crate's test binary ran, another was blocked) | Windows is edit + `fmt`/`clippy`/`check --target x86_64-unknown-linux-gnu` only; **all test execution happens in WSL2/Linux** (which is the target platform anyway). Do not disable Smart App Control to work around it — it is irreversible without a Windows reset |

---

## 4. Explicitly not built (cut list)

Bridges UI and pluggable-transport management (config file supported, no fetch-over-clearnet),
onion-service hosting, relay/exit operation, remote management, a Windows network backend (see
README), multi-host routing, TUN/userspace-forwarding applier, ODoH resolver selection UI, Arti.

---

## 5. Status

| Milestone | State |
|---|---|
| M0 | **done and verified** — 28 unit tests pass (executed on Windows before Smart App Control started blocking local test binaries), `clippy -D warnings` clean, `check --target x86_64-unknown-linux-gnu` clean |
| M1 | **done and verified** — ruleset IR, 20-class invariant checker, profile compiler, nftables renderer pinned by golden files, and `netd`, the privileged helper. Evidence: 110 unit tests, 5 kernel-level policy tests, and an end-to-end socket test, all green in WSL2; `clippy -D warnings` clean on Windows and the Linux target |
| M2 | **done and verified** — `ghostnector-core` (state machine with the DR-15 guard, atomic intent journal, IPC server) and `ghostnector-cli`. Evidence: 161 unit tests, plus `scripts/core-cli-test.sh` proving cli → core → netd → kernel end to end, that an unauthorised client is refused, and that a restart with protection requested but nothing applied fails closed |
| M3 | **done and verified** — Tor's configuration and supervision are in place: a `torrc` renderer whose tests refuse the settings that trade privacy for speed, `systemd`/`external` service supervision, a cookie-authenticated read-only control-port client, and a connect sequence of *deny → bring up → wait for bootstrap → open*. Core derives Tor's ports from the helper's report, so the firewall and the service cannot disagree. The full-stack runs use the harness's fake Tor, so a public-network Tor observation remains outside this repository's evidence (the external-vantage gap, G8) |
| M4 | **done and verified** — the DNS chokepoint and resolver ownership, wired into a transition: connect starts the relay on the port the policy redirects into and points the machine's own resolver at it; disconnect puts the configuration back byte for byte and stops the relay. A relay that will not start fails the connect; a resolver that cannot be changed is a note, because the firewall is the enforcement. Evidence: per-environment unit tests plus an end-to-end run where a query reaches the configured upstream and the resolver file round-trips. The relay runs as a tethered child of core on the canonical chokepoint port (53, the port a `nameserver` line implies); D-22 in M8.0 made the default and the resolver line agree |
| M5 | **done and verified** — independent verification. Three checks behind one trait, all run from inside the protected set: UDP egress must be denied, the protected path must answer without reporting one of this machine's own addresses, and a configured canary must resolve to the expected address. A pass is the only route into `Protected`; a failure escalates to `BLOCKED` and is backed by applying the fail-closed baseline; a check that cannot conclude downgrades without alarming; and nothing is verified while the machine is meant to be open. Evidence: unit tests per probe against local stand-ins, plus an end-to-end run where a hand-edited rule is noticed and the tampered policy is replaced |
| M6 | **done and verified** — the boot guard: at boot it reads the journal, honours the documented `ghostnector.unprotected=1` console escape, and otherwise denies everything — asking the privileged helper, or applying the helper's own copy of the policy when the helper is unreachable. A journal that cannot be read is treated as a request for protection. Recovery is written down in `docs/RECOVERY.md`, including what is deliberately *not* a way out. Packaging lands with it: systemd units for the helper, control plane, boot guard and Tor, plus sysusers and tmpfiles. Evidence: unit tests plus an end-to-end run over all five cases |
| M7 | **done and verified** — the hermetic leak-test harness and the adversarial campaign: 27 cases (held 26, contradicted 0, inconclusive 1 by design), plus the effective-policy comparison that closed AC-5. Evidence and defects D-15…D-21 are in `docs/ADVERSARIAL-TEST-PLAN.md`. **Not built:** the GitHub Actions workflow, the chutney job and the external-vantage checklist the original row promised; no remote is configured, so CI is deferred |
| M8 | **done and qualified (M8.0–M8.6)** — decisions in `docs/M8-DECISIONS.md`; D-22 and D-23 resolved; the dead-end topology, the APP policy, the helper lifecycle and capability sets, the product-level core/CLI path, per-app verification and the AA adversarial class are all proved by committed scripts (`app-topology-test`, `app-policy-test`, `appd-socket-test`, `core-app-test`, `app-adversarial`). APP claims PC-17…PC-21 are recorded with their evidence and five explicit gaps (GA-1…GA-5) in `PROTECTION-CLAIMS.md` |
| M9 | **in progress — M9.0–M9.4 done; the real-`i2pd` qualification (M9.5) remains** — decisions in `docs/M9-DECISIONS.md`. M9.0: vocabulary, refusals (`MixedNetworks`, `I2pNeedsSystemScope`, `I2pWithLan`), CLI `--network`, decisions record. M9.1: the `I2pMachine` policy shape with **no NAT chain at all**, exactly one exemption (the router's own uid) plus DHCP, loopback-only proxies guarded on input, an invariant refusing a foreign exemption or a redirect, the `i2p_system.nft` golden, and netd identity/port support — kernel-verified. M9.2: the router service — an `i2pd.conf` renderer that refuses wildcard proxies and extra control surfaces, managed supervision with a real proxy-readiness check, the external-router option, and proxy ports reported by the helper. M9.3: core integration — `connect --network i2p`, no DNS chokepoint, and I2P's own verification where **the canary through the proxy is required for `Protected`**. M9.4: the hermetic fake-router end-to-end and IA suite — every denial observed at a **far-side boundary** (a separate network namespace with its own listener and counter), transitions included: **26 held, 0 contradicted, 0 inconclusive**. M9.5 runs the same machinery under real `i2pd` and records what that adds. The complete M1–M8 gate stays unchanged and green |

### What M1 built (`crates/ghostnector-netd`)

The only component with privileges. It exists so that `CAP_NET_ADMIN` is confined to one small,
auditable process:

| Property | How |
|---|---|
| Cannot be asked for arbitrary policy | the closed verb set: `Hello`, `ApplyProfile{ProfileId, Params}`, `Revert`, `FlushConntrack`, `Report` — no ruleset, command, or path can be expressed |
| Only one peer | socket is mode 0600 and chowned to the configured uid, **and** every connection is re-checked with `SO_PEERCRED`; an unauthorised peer is dropped without being read |
| No shell | policy tools run from an absolute path, verified root-owned and not group/other-writable, with the ruleset on stdin |
| Never unwinds into privilege | `no_new_privs` is set before anything else happens |
| Reports the truth | `Report.applied` comes from asking the kernel, not from memory — if someone removed our table, the report says so |
| Bounded blast radius | at most 16 concurrent connections, a read timeout per connection, and a poisoned lock is read rather than fatal |

### What the namespace test proves (`scripts/policy-netns-test.sh`)

Each rendered policy is applied with `nft -f` inside a throwaway namespace wired to a fake internet
by a veth, and the assertions are made **at the far side**:

| Claim | Evidence |
|---|---|
| The kernel accepts our nftables | `nft -f` exits 0 |
| Deny-by-default holds | a rooted probe delivers **0 packets** to the destination |
| Exemptions are real, and exactly as narrow as declared | the Tor uid (987) and the resolver uid (988) each complete a connection (5 packets, 1 accepted); nobody else does |
| `USER` scope carves out other identities | uid 0 and uid 987 pass; uid 1000 is blocked |
| Revert removes exactly our objects | `nft list tables` is empty afterwards and the probe works again |

**The measurement rule this test enforces (and why it matters for §14):** assertions are made on
*packets arriving at the destination under test*, never on interface byte counters. The first version
of this test counted interface bytes and reported a 250-byte "leak" on a policy that was in fact
blocking correctly — the bytes were IPv6 link-local/multicast control traffic from the veth. A leak
test that cannot distinguish "the policy failed" from "the network was noisy" is worse than no test,
because it teaches you to ignore failures.

### Two design refinements found while implementing M1

1. **`USER` scope needs an explicit carve-out, and it must be illegal anywhere else.** The IR has
   `SkuidNot` and `RuleOrigin::OutOfScope`; the checker rejects an out-of-scope rule in any scope
   other than `User`. Otherwise "leave the rest of the machine alone" is indistinguishable from a
   hole.
2. **Authenticated DNS over Tor needs no exemption at all.** The review (DR-10) required it to be
   "firewalled to the Tor SOCKS port only". Implementing it showed the requirement is satisfied
   *structurally*: the resolver has no exemption in Tor mode, so its only possible egress is
   loopback, where the only proxy is Tor's SOCKS port. The policy is therefore shorter and the
   guarantee is stronger (it depends on the absence of a rule, not on the correctness of one).

### Environment (as of 2026-09-24)

- Windows: Rust 1.98.1 (MSVC), Linux target std installed. Use for `fmt`, `clippy`, `check
  --target x86_64-unknown-linux-gnu`. **Cannot execute test binaries** (R9).
- **`clippy` alone is not enough for the unix-gated crates.** `ghostnector-netd`, `-core`, and `-cli`
  are `#![cfg(unix)]`, so on Windows they compile to nothing and clippy passes trivially. The real
  static check is `cargo check --workspace --all-targets --target x86_64-unknown-linux-gnu`; run it
  before believing anything is green.
- WSL2: Ubuntu 24.04.5 LTS, kernel 6.18.33.2-microsoft-standard-WSL2, systemd running, cgroup v2.
  Use for all test execution.
- Builds from `/mnt/c` are slow; keep artefacts inside the VM:
  `CARGO_TARGET_DIR=/root/ghostnector-target cargo test`.

### Decisions awaiting your input

- **D1 (applier):** `nft -f` on the fast path, pure-netlink afterwards. Say the word if you want
  no external binary in the privileged path from the start — M1 grows by the netlink encoder work.
- **D2 (license):** permissive (MIT/Apache-2.0) by default. If you *want* GPL-3, `rustables` becomes
  usable and the netlink work shrinks substantially. This is a one-line change today.

Nothing in M2–M6 depends on either decision, so both can wait until M1.
