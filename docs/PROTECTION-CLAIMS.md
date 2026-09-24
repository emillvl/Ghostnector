# What Ghostnector claims when it says `Protected`

This document is the definition. `Protected` is a claim about **network path**, and each claim below
is stated so that a specific observation could prove it false. If a claim cannot be stated that way,
it does not belong here.

## How to read a verdict

Three verdicts exist, and they never blur into each other:

| Verdict | Meaning | May be reported as |
|---|---|---|
| **Verified** | an observation was made and it supports the claim | the claim |
| **Inconclusive** | the check could not run, or could not establish the claim | "not established", never a leak, never a pass |
| **Contradiction** | an observation was made that falsifies the claim | an alarm, and the fail-closed policy |

Two rules govern every reading of this document:

1. **An inconclusive observation is never evidence of a leak.** A check that cannot run tells us
   nothing about the property, in either direction.
2. **The absence of detected leakage is never a stronger claim than the test supports.** "Nothing was
   observed escaping" is exactly that, and no more. It is not "nothing can escape".

## What `Protected` means today, precisely

> **`Protected` means: a policy is applied, at least one configured verification check has passed
> since it was applied, and no configured check has contradicted a claim since then.**

Two consequences follow, and both are load-bearing:

- Checks that are **not configured** are inconclusive, and the state does not become stronger for
  their absence. The interface lists them (`unknown: no canary name is configured`), so a reader can
  see how much of this document is actually being checked.
- `Protected` is **bounded in time**: a result older than the configured window stops counting, and
  the state falls back to `Degraded`. The bound is the verification interval plus its timeout.

`Protected` does **not** mean anonymous, unlinkable, or safe from a compromised host. It does not mean
"nothing can escape". Those are not claims this program makes anywhere.

## Claims about confinement

A **confinement** claim says that traffic which should not leave does not leave. Falsifying one is an
alarm: the state becomes `Blocked`, the fail-closed baseline is applied, and the machine denies
everything until a person looks at it.

### PC-01 — Ordinary TCP egress is confined to the protected path

| | |
|---|---|
| Property | A TCP connection from a protected process reaches the network only as a Tor stream. No TCP segment addressed to a clearnet destination leaves the machine from that process. |
| Responsible | nftables `inet ghostnector`: the `nat` chain redirects locally generated TCP into Tor's `TransPort`; the `filter` chain's default verdict is `drop`. Applied by `netd` as one atomic transaction. |
| In scope | Locally generated TCP from every uid except the documented exemptions, in `SYSTEM` scope. Includes connections that existed before the policy was applied (conntrack is flushed, and the filter's default deny catches them regardless). |
| Exempted | `system-user:tor` (its own egress, or the design is circular), loopback, and the DHCP client. |
| Confirms | A protected process completes a request to an external endpoint, and **no packet addressed to that destination is observed at an independent boundary**. |
| Falsifies | A TCP segment from a protected uid observed at an independent boundary addressed to a clearnet destination; or a direct connection succeeding while the state claims protection. |
| Inconclusive | The boundary was not observed; or the attempt failed for a reason unrelated to the policy (no route, no listener). |
| On falsification | `Blocked`, fail-closed baseline applied, the mismatch reported. Release blocker. |
| Evidence today | **Policy level: verified** (`policy-netns-test.sh`: uid 0 delivers 0 packets to the destination, `arrival_packets=0`). **Through the full stack: not yet observed** (see G2). |

### PC-02 — Ordinary UDP egress is denied

| | |
|---|---|
| Property | No UDP datagram from a protected process reaches any destination. |
| Responsible | The `filter` chain rejects UDP and ICMP, which is also what makes QUIC and real-time clients fail fast instead of hanging. |
| In scope | Locally generated UDP from every uid except the exemptions above. |
| Exempted | Loopback, DHCP, `system-user:tor` between it and its relays (Tor does not carry UDP to destinations). |
| Confirms | A UDP datagram sent to a configured endpoint that **would answer if it arrived** produces no reply, and no packet arrives at that endpoint. |
| Falsifies | Any reply. A reply is proof that the datagram left. |
| Inconclusive | No UDP endpoint configured; or the send failed locally for an unrelated reason. |
| On falsification | `Blocked`, fail-closed baseline applied. This is implemented and exercised. |
| Evidence today | **Verified**, including end to end: the check runs as an ordinary process, and the tamper test (PC-08) shows that one hand-edited rule makes it alarm. |

### PC-03 — DNS leaves only through the chokepoint

| | |
|---|---|
| Property | Every DNS query from a protected process reaches a resolver by way of the DNS chokepoint. A query aimed at a hard-coded resolver address is redirected, not sent. |
| Responsible | The `nat` chain redirects UDP and TCP port 53 to the chokepoint; the chokepoint relays to the configured upstream (Tor's `DNSPort`, or the encrypted resolver). The system resolver configuration is repointed as well, but it is not the enforcement. |
| In scope | Port 53 from every uid except the exemptions. |
| Exempted | The encrypted resolver's own upstream traffic in DNS-lockdown mode; loopback; `system-user:tor`. |
| Confirms | A query sent to a *foreign* resolver address is answered by the configured upstream, and the resolver that would have received it never sees it (the second half needs an external vantage: G8). |
| Falsifies | A port-53 datagram from a protected uid observed at an independent boundary; or an answer from a resolver other than the chokepoint. |
| Inconclusive | No canary configured, so a wrong answer cannot be told from a right one. |
| On falsification | `Blocked`, fail-closed baseline applied. |
| Evidence today | **Partially verified**: a hand-aimed query lands on the chokepoint and reaches the configured upstream (end to end). The "the ISP resolver never sees it" half is **not testable without the vantage point** (G8). |

### PC-04 — IPv4 is covered by PC-01, PC-02 and PC-03

| | |
|---|---|
| Property | The claims above hold for IPv4 destinations and IPv4 resolvers. |
| Responsible | The same chains. The table is `inet`, so one ruleset covers both families. |
| In scope, Exempted, Falsifies | As PC-01 to PC-03, restricted to IPv4. |
| Inconclusive | As above. |
| Evidence today | **Verified** — every existing test is IPv4. |

### PC-05 — IPv6 egress is denied

| | |
|---|---|
| Property | No IPv6 packet from a protected process reaches any destination. |
| Responsible | The same `filter` chain, which is family-agnostic, plus the rejection of ICMPv6. In `APP` scope (M8) IPv6 is absent by construction rather than denied by a rule. |
| In scope | All IPv6 from every uid except the exemptions. |
| Exempted | Loopback; `system-user:tor` may reach relays over IPv6 if the network is v6-only. |
| Confirms | An IPv6 connection attempt from a protected process fails, **and no IPv6 packet arrives at the boundary**. |
| Falsifies | An IPv6 packet from a protected uid observed at an independent boundary; or a successful IPv6 connection while protection is claimed. |
| Inconclusive | **The machine has no IPv6 connectivity at all.** A failed IPv6 attempt on a IPv4-only link proves nothing about the policy and must never be recorded as a pass. |
| On falsification | `Blocked`, fail-closed baseline applied. |
| Evidence today | **Not yet observed.** Every existing test is IPv4-only. This is the largest untested area of confinement (G1). |

### PC-08 — Tampering with the policy is noticed

| | |
|---|---|
| Property | A modification of Ghostnector's kernel policy that would permit prohibited traffic is detected, and the machine is denied before it is trusted again. |
| Responsible | The verification probes (specifically the UDP check) and the engine's escalate-then-reapply: on an alarm the fail-closed baseline replaces whatever is in the kernel. |
| In scope | Any change to `table inet ghostnector` made by anything other than `netd`. |
| Falsifies | A change that permits traffic a configured check exercises goes unnoticed for longer than one verification interval plus timeout. |
| Inconclusive | The change permits only traffic that no configured check exercises — **this is the known gap, and it is not a pass** (G3). |
| On falsification | `Blocked` and re-deny. |
| Evidence today | **Verified for the probed class**: a hand-edited `udp accept` rule is detected within the interval, the machine is denied, the reason is stated, and the tampered table is replaced. **Not covered**: a change that leaves UDP denied, such as allowing one TCP destination (G3). |

### PC-16 — The policy disappearing is noticed

| | |
|---|---|
| Property | If the policy is removed entirely, the machine is re-denied or reported as not protected — never silently open while claiming protection. |
| Responsible | As PC-08. On reboot, the boot guard (PC-10). |
| Confirms | `nft destroy table inet ghostnector` is followed, within one verification interval plus timeout, by `Blocked` with the baseline in the kernel. |
| Falsifies | The table gone and the state still claiming protection after that bound. |
| Inconclusive | The bound has not yet elapsed. **The claim is therefore bounded, and the bound is part of the claim.** |
| Evidence today | **Verified** for the removal case by the same test as PC-08. |

## Claims about availability

An **availability** claim says the protected path works. Falsifying one is *not* an alarm about
leaking — it means traffic is being blocked. The response is the same fail-closed state, but the
reason reported is different, and it must read differently to a person.

### PC-06 — The protected path carries traffic

| | |
|---|---|
| Property | While `Protected`, an ordinary request from a protected process to a configured endpoint is answered. Protection is not merely blocking everything. |
| Responsible | Tor bootstrap, `TransPort`, the chokepoint, and the policy that redirects into them. |
| Confirms | The configured endpoint answers `200` to a plain request made by an ordinary process. |
| Falsifies | The endpoint does not answer while protection is claimed. |
| Inconclusive | No endpoint configured; a non-200 answer from an endpoint that is merely broken. |
| On falsification | `Blocked`, fail-closed baseline applied, reason says availability rather than confinement. |
| Evidence today | **Unit-tested** against local stand-ins. **Not observed end to end**, because the end-to-end run configures only the UDP check (G2). |

### PC-07 — The exit is not this machine

| | |
|---|---|
| Property | The address reported by the configured check endpoint is not one of this machine's own addresses. |
| **Not claimed** | That the exit is a Tor exit, or that it differs from the address the ISP sees. Both need an external vantage (G8). |
| Responsible | The check endpoint plus the comparison against this machine's interfaces. |
| Confirms | A `200` whose body's first address is not one of this machine's addresses. |
| Falsifies | The reported address is one of this machine's own addresses. |
| Inconclusive | The endpoint answers `200` without reporting an address. **This is not a pass.** |
| Evidence today | **Unit-tested** with a local stand-in. **Not observed end to end** (G2). |

### PC-11 — Tor stopping does not open anything

| | |
|---|---|
| Property | If Tor stops, protected TCP and DNS stop with it. Nothing falls back to the clearnet. |
| Responsible | The redirect target no longer existing: the packet is delivered to a closed loopback port and refused. The `filter` chain's default deny is the second line. |
| Confirms | With Tor killed, a protected connection attempt fails, and **no packet arrives at an independent boundary**. |
| Falsifies | Any protected traffic reaching the boundary after Tor stopped. |
| Inconclusive | Nothing attempted. |
| On falsification | `Blocked`. |
| Evidence today | **Not yet tested** (G4). |

### PC-13 — The DNS relay stopping does not open anything

| | |
|---|---|
| Property | If the chokepoint stops, resolution stops. Queries do not fall back to a clearnet resolver. |
| Responsible | The redirect points at a port where nothing listens; the filter's default deny is the second line. |
| Confirms | With the relay killed, a protected query gets no answer, and no port-53 packet arrives at the boundary. |
| Falsifies | A port-53 datagram from a protected uid at the boundary. |
| Evidence today | **Not yet tested** (G4). |

## Claims about state

### PC-09 — The exemptions are exactly the documented ones, and only they

| | |
|---|---|
| Property | The exemption list reported by the helper is complete and accurate; each exempted identity can do only what is documented; no other identity can obtain the same path. |
| Responsible | The compiler derives the list from the rules that cite it (so a hole that exists is listed, and one that is not listed does not exist), and the invariant checker refuses a ruleset that accepts unenumerated traffic. |
| In scope | Every uid, protocol and address-set exemption in force. |
| Confirms, in both directions | (a) the exempted identity performs the documented traffic; (b) an identity **not** covered by that exemption cannot obtain the same path. |
| Falsifies | Traffic from a non-exempt identity taking an exempt path; or an exemption in the kernel that the report does not list. |
| Inconclusive | The test itself ran with privileges that produced the path — **an exemption that passes because the test was special is not evidence**. |
| Evidence today | **Verified for `system-user:tor` and `system-user:dnscrypt-proxy`** in both directions (the policy test allows exactly those uids and blocks uid 0 with 0 packets observed). **Not tested**: the DHCP and LAN exemptions (G7). |

### PC-10 — Boot with protection requested

| | |
|---|---|
| Property | When protection was requested before shutdown, the fail-closed policy is in place before the network is configured, so no application packet leaves unprotected. |
| Responsible | `ghostnector-bootguard`, ordered before `network-pre.target`; the helper's own copy of the policy is the fallback. |
| In scope | The whole boot, from the guard running until the control plane takes over. |
| Exempted | DHCP (or the link would never come up), plus the console escape `ghostnector.unprotected=1`. |
| Confirms | The policy exists before the network is up, and an independent boundary observes no packet from a protected scope during boot. |
| Falsifies | An egress packet observed at the boundary while the machine is booting with protection requested and the policy is not yet present. |
| Inconclusive | Nothing attempted traffic during the window. |
| Evidence today | **Partially verified**: the policy is applied, the fallback works without the helper, the console escape works, and an unreadable journal denies rather than guesses — all end to end. **The ordering claim** ("no packet before") is not independently observed yet (G6). |

### PC-12 — The control plane dying changes nothing

| | |
|---|---|
| Property | Enforcement survives the control plane; nothing is loosened because it died. |
| Responsible | The policy lives in the kernel and in independent services. `core` holds no policy. |
| Confirms | With `core` killed, the policy is still in the kernel and protected traffic is still confined. |
| Falsifies | Any loosening coincident with `core` dying. |
| Inconclusive | **Nobody can be asked for the state.** "Cannot reach the control plane" is not evidence of a leak, and must never be shown as one. |
| Evidence today | **Not yet tested** (G4). |

### PC-14 — Transitions never widen the policy

| | |
|---|---|
| Property | During a connect or disconnect, the machine is never more permissive than the union of the state before and the state after. |
| Responsible | Deny-first ordering, and applying policy as one atomic transaction. |
| Confirms | A storm of connect/disconnect with a storm of traffic from a protected process produces **zero** prohibited packets at an independent boundary. |
| Falsifies | One prohibited packet observed during any transition. |
| Inconclusive | No traffic attempted during the window. |
| Evidence today | The ordering is unit-tested. **The storm is not** (G5). |

### PC-15 — Disconnecting restores what was there

| | |
|---|---|
| Property | Disconnect returns the resolver configuration to exactly what it was, and does not clobber a change someone else made in the meantime. |
| Responsible | The resolver module: capture before, compare while restoring, report a conflict instead of overwriting. systemd-resolved is reverted through its own tool. |
| Confirms | The file's bytes equal the captured original; for resolved, the per-link configuration is reverted. |
| Falsifies | A disconnect that leaves a modified resolver configuration without saying so. |
| Inconclusive | The change was made by someone else, so restoring was refused as a conflict — this is a correct outcome, not a failure. |
| Evidence today | **Verified**, byte for byte, end to end. |

## What `Protected` does not claim

- **Not anonymity.** No claim about unlinkability, about the exit being trustworthy, or about what a
  destination or an exit can infer.
- **Not "the exit is not your ISP".** That needs a vantage point outside this machine (G8).
- **Not "nothing can escape".** It is "these checks, within this bound, observed no contradiction".
- **Not protection for anything outside the scope.** A machine-wide scope covers local processes; it
  does not cover other machines, and `USER` scope does not cover root daemons.
- **Not protection against the host.** Root, the kernel, and a compromised boot chain are out of
  scope, as is anything an application reveals about itself.
- **Not a claim that unconfigured checks passed.** They did not run.

## Gaps

Every gap here is a place where the implementation may be right but the claim is not yet supported by
an observation. They are the agenda for the adversarial phase.

| # | Gap | Claim affected |
|---|---|---|
| G1 | IPv6 has never been exercised. A v4-only link makes an IPv6 test inconclusive, so this needs a v6-capable environment. | PC-05 |
| G2 | The end-to-end run configures only the UDP check, so availability and identity were never observed through the full stack. | PC-06, PC-07 |
| G3 | Only the probed class of tampering is detected. A change that leaves UDP denied is invisible. | PC-08 |
| G4 | No test kills Tor, the relay, or the control plane. | PC-11, PC-12, PC-13 |
| G5 | Transition storms have never been run against an independent boundary. | PC-14 |
| G6 | The boot ordering claim is not observed: we know the policy is applied, not that nothing left before it was. | PC-10 |
| G7 | The DHCP and LAN exemptions are untested in both directions. | PC-09 |
| G8 | No vantage point outside the machine, so the ISP-facing half of DNS and the "is it a Tor exit" question cannot be answered. | PC-03, PC-07 |
| G9 | `Protected` is reachable with only a subset of checks configured. The interface lists what did not run, but nothing forces a minimum. | the definition of `Protected` |

## Appendix — what was verified for this candidate

- **Commit under test:** `14586614f98fca7759dc3bec5bd884dd66464566` (tagged `v1.0.0-rc1`)
- **Environment:** Ubuntu 24.04.5 LTS, kernel 6.18.33.2-microsoft-standard-WSL2, nftables 1.0.9,
  rustc/cargo 1.98.1
- **Unit tests:** 281 passed, 0 failed
- **Integration:** `policy-netns-test.sh` (two profiles) PASS · `netd-socket-test.sh` PASS ·
  `bootguard-test.sh` PASS · `core-cli-test.sh` PASS
- **Static checks:** `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -D
  warnings` clean · `cargo check --workspace --all-targets --target x86_64-unknown-linux-gnu` clean
- **Working tree:** clean at the tag

The clippy gate found two lints in the first pass that the Windows-hosted clippy could never see,
because the affected crate is `#![cfg(unix)]` and compiles to nothing on Windows. They were fixed
before the tag. This is recorded because it is a property of the gate, not of the code: **clippy must
be run against the target platform, not the development host.**
