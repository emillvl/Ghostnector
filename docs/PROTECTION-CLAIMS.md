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

One check is not a probe of traffic but a comparison of the kernel's own ruleset against the one the
helper applied. It exists because a policy change that no probe traverses cannot be found by any
amount of probing, and it is what makes PC-08 hold for changes rather than for probed changes only.
The comparison is text from the same formatter on both sides, so it is exact rather than heuristic.

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
| Evidence today | **Verified end to end.** AS-1 reaches the destination exactly once with nothing crossing from the machine's address; the transition storm (AL-1) and the fail-closed panic (AL-7) put zero prohibited packets on the wire; a link flap, a route change, an address change and a new interface (AN-1…AN-5) open no path. The only direct egress from the machine's own address that was ever observed is the exempted Tor uid (AE-1). |

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
| Evidence today | **Verified end to end**: AS-2 and the transition storms (AL-1/AL-4/AL-7) put no datagram on the wire; AC-4 shows one hand-edited UDP-permitting rule is enough to alarm; AE-1 shows UDP from the machine's address arrives only from the Tor uid. |

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
| Evidence today | **Verified end to end**: AS-5 and AS-6 send to a foreign resolver and the chokepoint answers with the configured upstream's address while the machine's own address puts nothing on the wire; AE-4 confirms there is no resolver exemption in Tor mode. **RC1 falsified this claim**: D-15 (shared chain priority) let redirects race the filter, so a query could leave without the chokepoint ever being involved. The fixes are in the priority split and the loopback destination sets (D-16), and the claim holds only from those commits on. The "the resolver that would have received it never sees it" half still needs an external vantage (G8). |

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
| Evidence today | **Verified on a v6-capable link**: AS-3 attempts an IPv6 connection with addresses and a default route present and observes no IPv6 packet from the machine; AS-4 records INCONCLUSIVE on a run that has no IPv6, as required; AN-4 removes the IPv6 address while protected and nothing changes. **Still unobserved**: `system-user:tor` reaching a relay over IPv6 when the network is v6-only — the exemption's own v6 path (G1). |

### PC-08 — Tampering with the policy is noticed

| | |
|---|---|
| Property | A modification of Ghostnector's kernel policy that would permit prohibited traffic is detected, and the machine is denied before it is trusted again. |
| Responsible | The verification probes, the effective-policy comparison (`netd` reports what the kernel holds and compares it against what was applied), and the engine's escalate-then-reapply: on an alarm the fail-closed baseline replaces whatever is in the kernel. |
| In scope | Any change to `table inet ghostnector` made by anything other than `netd`. |
| Falsifies | A change that permits prohibited traffic goes unnoticed for longer than one verification interval plus timeout. |
| Inconclusive | The comparison could not run (the helper could not be reached), so the policy's contents were not checked. The state falls back to `Degraded`; this is not a pass. |
| On falsification | `Blocked` and re-deny. |
| Evidence today | **Verified for changes to the policy.** A hand-edited `udp accept` rule is detected within the interval (AC-4); a change that leaves UDP denied but permits one TCP destination is detected by comparing the kernel's ruleset against the one that was applied (AC-5), and the tampered table is replaced. **RC1 did not hold this claim**: only the probed class was covered, which is what AC-5 demonstrated (gap G3). The comparison is not cryptographic and does not pretend to be: it detects a change to the ruleset, and a process that holds `CAP_NET_ADMIN` can replace the comparison's subject or remove the policy entirely — that is the same out-of-scope line as root (G10). |

### PC-16 — The policy disappearing is noticed

| | |
|---|---|
| Property | If the policy is removed entirely, the machine is re-denied or reported as not protected — never silently open while claiming protection. |
| Responsible | As PC-08. On reboot, the boot guard (PC-10). |
| Confirms | `nft destroy table inet ghostnector` is followed, within one verification interval plus timeout, by `Blocked` with the baseline in the kernel. |
| Falsifies | The table gone and the state still claiming protection after that bound. |
| Inconclusive | The bound has not yet elapsed. **The claim is therefore bounded, and the bound is part of the claim.** |
| Evidence today | **Verified** for the removal case: AC-3 destroys the table by hand, observes the machine's own address putting packets on the wire during the window (the injected fault, 290 packets), then within one interval plus timeout observes `no traffic can leave` with the baseline in the kernel and zero packets afterwards. |

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
| Evidence today | **Verified end to end.** The full-stack runs configure the HTTP check endpoint, the UDP check and the canary, and reach `protected - and verified`, which requires the endpoint to answer `200` to a request made by an ordinary unprivileged identity through the policy. **RC1 falsified this claim** in the same run as PC-03 (D-15/D-16: the redirect raced the filter, so the path was not reliably the chokepoint's), and the fix restored it. |

### PC-07 — The exit is not this machine

| | |
|---|---|
| Property | The address reported by the configured check endpoint is not one of this machine's own addresses. |
| **Not claimed** | That the exit is a Tor exit, or that it differs from the address the ISP sees. Both need an external vantage (G8). |
| Responsible | The check endpoint plus the comparison against this machine's interfaces. |
| Confirms | A `200` whose body's first address is not one of this machine's addresses. |
| Falsifies | The reported address is one of this machine's own addresses. |
| Inconclusive | The endpoint answers `200` without reporting an address. **This is not a pass.** |
| Evidence today | **Verified against a standalone endpoint**: the end-to-end runs configure a check URL whose body reports an address in TEST-NET-3, the check compares it against this machine's interfaces, and the state reaches `protected - and verified`. That the reported address belongs to a **Tor exit** remains outside the claim and needs an external vantage (G8). |

### PC-11 — Tor stopping does not open anything

| | |
|---|---|
| Property | If Tor stops, protected TCP and DNS stop with it. Nothing falls back to the clearnet. |
| Responsible | The redirect target no longer existing: the packet is delivered to a closed loopback port and refused. The `filter` chain's default deny is the second line. |
| Confirms | With Tor killed, a protected connection attempt fails, and **no packet arrives at an independent boundary**. |
| Falsifies | Any protected traffic reaching the boundary after Tor stopped. |
| Inconclusive | Nothing attempted. |
| On falsification | `Blocked`. |
| Evidence today | **Verified end to end**: AF-1 kills Tor, a protected connection then fails, and the machine's own address puts nothing on the wire afterwards. |

### PC-13 — The DNS relay stopping does not open anything

| | |
|---|---|
| Property | If the chokepoint stops, resolution stops. Queries do not fall back to a clearnet resolver. |
| Responsible | The redirect points at a port where nothing listens; the filter's default deny is the second line. |
| Confirms | With the relay killed, a protected query gets no answer, and no port-53 packet arrives at the boundary. |
| Falsifies | A port-53 datagram from a protected uid at the boundary. |
| Evidence today | **Verified end to end**: AF-2 kills the relay, resolution then fails, and nothing reaches the boundary. |

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
| Evidence today | **Verified in both directions for all four documented subjects**: `system-user:tor` (AE-1: the Tor uid's direct connection arrived from the machine's own address while an ordinary uid's did not), `dhcp-client` (AE-2: a request from 68 to 67 left; an ordinary source port and the inverted shape did not), the LAN set (AE-3: unreachable by default, directly reachable when opted in), and the resolver (AE-4/PC-03: loopback only, no exemption). **RC1 did not hold this claim**: the DHCP exemption was compiled against the wrong port (D-18) and permitted the one direction a client never sends. The machine's own confinement is verified by the policy test (uid 0 puts 0 packets on the wire). **Known narrowing**: the DHCP exemption is IPv4 only, because IPv6 is denied in every profile; a network whose connectivity can only be maintained by DHCPv6 lease renewal is not supported while protected (G11). |

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
| Evidence today | **Verified end to end**: AF-3 kills the control plane and the policy is still in the kernel with nothing crossing; AF-4 does the same for the privileged helper. |

### PC-14 — Transitions never widen the policy

| | |
|---|---|
| Property | During a connect or disconnect, the machine is never more permissive than the union of the state before and the state after. |
| Responsible | Deny-first ordering, and applying policy as one atomic transaction. |
| Confirms | A storm of connect/disconnect with a storm of traffic from a protected process produces **zero** prohibited packets at an independent boundary. |
| Falsifies | One prohibited packet observed during any transition. |
| Inconclusive | No traffic attempted during the window. |
| Evidence today | **Verified with a sampling oracle**: rather than counting packets before and after, the oracle reads the packet count and the reported state together, and a violation is an increase while the machine still reports protection. AL-1 (connect under load), AL-4 (disconnect under load) and AL-7 (panic under load) all hold. The oracle also found **D-19** — the state was updated after the policy was removed, so for a few hundred microseconds a caller would have been told "protected" while there was no policy; the transition is now announced before anything is touched. |

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
  scope, as is anything an application reveals about itself. In particular, anything holding
  `CAP_NET_ADMIN` can replace the policy, or the comparison that watches it (G10).
- **Not a claim that unconfigured checks passed.** They did not run.
- **Not a claim about DHCPv6.** The DHCP exemption is IPv4; a network that can only maintain
  connectivity through DHCPv6 lease renewal is not supported while protected (G11).

## Gaps

Every gap here is a place where the implementation may be right but the claim is not yet supported by
an observation. They are the agenda for the adversarial phase. A gap that was closed by an
observation is marked **closed**, with the case that closed it; a gap that changed shape is marked
**narrowed**.

| # | Gap | Claim affected |
|---|---|---|
| G1 | **Narrowed.** IPv6 *denial* is now verified on a v6-capable link (AS-3) and correctly INCONCLUSIVE on a v4-only one (AS-4). Still unobserved: `system-user:tor` reaching a relay over IPv6 when the network is v6-only. | PC-05, PC-09 |
| G2 | **Closed.** The end-to-end runs configure the HTTP check endpoint, the UDP check and the canary, so availability and exit identity are observed through the full stack (PC-06, PC-07). | PC-06, PC-07 |
| G3 | **Closed.** The helper compares the kernel's own ruleset against the one it applied; a change no probe traverses is detected within one interval and overwritten (AC-5). | PC-08 |
| G4 | **Closed.** AF-1…AF-4 kill Tor, the relay, the control plane and the helper; the policy survives each, and nothing crosses. | PC-11, PC-12, PC-13 |
| G5 | **Closed.** AL-1, AL-4 and AL-7 run the storms under a sampling oracle that attributes every crossing to the state reported at that moment. | PC-14 |
| G6 | **Open.** The boot ordering claim is not observed: we know the policy is applied at boot, not that nothing left before it was. | PC-10 |
| G7 | **Closed.** The Tor uid, the DHCP client and the LAN set are all exercised in both directions (AE-1…AE-3), and the resolver's absence is exercised too (AE-4). | PC-09 |
| G8 | **Open.** No vantage point outside the machine, so the ISP-facing half of DNS and the "is it a Tor exit" question cannot be answered. | PC-03, PC-07 |
| G9 | **Open.** `Protected` is reachable with only a subset of checks configured. The interface lists what did not run, but nothing forces a minimum. | the definition of `Protected` |
| G10 | **Out of scope, stated.** Root and anything holding `CAP_NET_ADMIN` can replace the policy, the comparison's subject, or the helper. This is the same line as the host being trusted; the comparison detects accidental and non-privileged divergence, not a privileged attacker. | PC-08, all confinement claims |
| G11 | **Narrowing.** The DHCP exemption is IPv4 only, because IPv6 is denied in every profile. A network whose connectivity can only be maintained by DHCPv6 lease renewal is not supported while protected. | PC-09 |
| G12 | **New, availability.** A transient loss of connectivity can leave the machine `Blocked` until a person acts, because a verification failure is answered with the fail-closed baseline (observed in AN-1). This is deliberate, and it is a cost rather than a leak. | PC-06, PC-14 |
| G13 | **New, residual.** The exemption list is derived from the rules that cite it and the invariant checker refuses an accept citing no listed exemption, but a one-by-one kernel-versus-report diff is not executed end to end. | PC-09 |

## APP scope (M8): what was demonstrated

The APP scope is the review's second, stronger mode: each protected application runs in its own
namespace whose default route terminates on a dead-end local `dummy` device, and the only mechanism
that makes a destination reachable is a netns-local DNAT to the host-local core address.

> The APP namespace has no route capable of carrying application traffic to an external network.
> Its default route terminates on a dead-end local dummy interface. Netns-local DNAT is the only
> mechanism that turns an application connection into a reachable Ghostnector core destination.

> If the APP DNAT/ruleset disappears or is invalid, application traffic dies locally without
> reaching the host veth, ARP/NDP, the host forwarding path, or an external network.

| Claim | What it says | Evidence | Falsifier |
|---|---|---|---|
| **PC-17** | An application in a protected namespace reaches the network only through the core address and Tor. | The namespace DNAT targets the namespace's own relay (`127.0.0.1:9041`); the relay runs as the application's uid with every capability set empty, reads the original destination from the namespace's *own* conntrack, and speaks SOCKS to the core's SocksPort as the application's address; it refuses any connection with no original destination (never an open proxy). `app-real-tor-test.sh` (real Tor): two groups' fetches returned real exit addresses, the destination answered 200, direct egress produced no data; `app-policy-test.sh` (destination survives, source preserved, direct relay connection refused, core TransPort closed); the APP host table admits the app link only to the chokepoint and SocksPort; AA-3 shows an injected route creates no direct path | Any packet from the application address observed outside the conduit |
| **PC-18** | The dead-end property holds: with the DNAT gone the application's traffic dies locally and is not observable on the host link. | `app-topology-test.sh` (no packet, no ARP, no host involvement with the DNAT removed; the rendered ruleset behaves the same in `app-policy-test.sh`); AA-1 and AA-12 (removed/flushed namespace policy is noticed and the APP scope denied) | One frame of application traffic on the host link, or one packet at a boundary while APP protection is reported |
| **PC-19** | Source identity is preserved: Tor sees each application's own address, and no masquerade/SNAT exists anywhere on the path. | `core-app-test.sh`: the stand-in SOCKS listener saw the application's address (`10.232.0.2`) and the application's intended destination; AA-6/AA-9: two applications presented distinct addresses and no masquerade rule existed; the relay authenticates to SocksPort with a per-group credential (`app<id>`), so Tor's `IsolateSOCKSAuth` keys each group separately; the IR has no source-rewriting verdict and the renderer test refuses `masquerade`/`snat`; AA-2: an injected masquerade rule is noticed and the APP scope denied | Two protected groups presented to Tor as the same source identity; a masquerade/SNAT rule in force; the core or host address appearing as an application's source at Tor |
| **PC-20** | DNS from inside an APP namespace reaches only the chokepoint, and an answer can only come from the configured upstream. | `core-app-test.sh`: the session's resolver is the chokepoint, and its query was answered by Tor's DNSPort through the relay; AA-10: a query to a foreign resolver was answered by the chokepoint and **no query from an application address reached the resolver directly** | A port-53 datagram from the application address at a boundary; an answer from a resolver other than the chokepoint |
| **PC-21** | Disconnect, panic and stop destroy every namespace, veth, bridge port, ruleset and group relay. | `core-app-test.sh` (stop-app, disconnect: namespaces, bridge and table gone); `appd-socket-test.sh` (destroy idempotent, revert removes everything **and every relay process, including under the packaged capability set that has no `CAP_KILL`**); AA-7 (panic with applications running removes every namespace); `app-real-tor-test.sh` (no relay, namespace or table survives the disconnect) | One registered namespace still usable after teardown, one leftover relay process, or one leftover Ghostnector APP object |
| update to **PC-05** | In APP scope IPv6 is absent by construction: no address, no route, and `disable_ipv6=1`, checked on every verification pass. | `appd-socket-test.sh` step 3 (the namespace's IPv6 is disabled); the shape check refuses a namespace where it is not; `app-policy-test.sh` proves the namespace ruleset carries no IPv6 path | An IPv6 packet from an application address at a boundary |
| update to **PC-08/PC-16** | The APP namespace's effective ruleset and shape are compared against what the helper installed, so a change no probe traverses is still detected. | `appd-socket-test.sh` (a changed ruleset and a changed `proxy_arp` are both reported); AA-12 (flushed ruleset), AA-4 (proxy ARP), AA-5 (extra interface), AA-1 (namespace removed), AA-2 (host table tampered) each deny the APP scope within the verification window | A changed namespace ruleset, route table, address set or sysctl unnoticed for longer than one interval plus timeout |

Two boundaries on the reading, kept here so they cannot blur:

- **Distinct source addresses are not proof of distinct Tor circuits.** PC-19 claims the identity
  Ghostnector supplies to Tor. Whether Tor maps that to different circuits is Tor's own behaviour
  and needs Tor/external evidence; it is not claimed by this document.
- **`Blocked` in APP scope is scoped.** It means the protected applications cannot reach the
  network. It does not claim the whole machine is denied unless a machine-wide state really denies
  it. Zero protected applications can never produce `Protected`: the state is `Degraded` with the
  explicit reason "APP protection is configured, but no application currently has verification
  evidence" until at least one application has passing evidence (`app_protection_is_never_claimed_without_per_app_evidence`).

### APP gaps and narrowings (M8 qualification)

| # | Gap | Claim |
|---|---|---|
| GA-1 | The adversarial suite has no independent boundary outside the host: the fake Tor stands in for the network, so "nothing crossed" is observed at the host link and at the fake endpoints, not at an ISP-facing vantage (the SYSTEM-scope G8 remains open for APP too). | PC-17, PC-20 |
| GA-2 | Distinct Tor circuits are not demonstrated; only distinct source identities are (Tor's behaviour needs Tor/external evidence). | PC-19 |
| GA-3 | PC-07 for APP is narrower than for SYSTEM: the probe compares the reported exit address against the namespace's own addresses and the core address, not against every host interface. | PC-07 |
| GA-4 | Reboot/reconcile of APP intent is covered by unit tests (adopt as `Degraded`, refresh from the registry) and by the conservative machine-wide boot guard, not by an end-to-end reboot run. | PC-10, PC-16 |
| GA-5 | `Protected` in APP scope still requires at least one configured check to pass (G9 applies unchanged): with no check endpoints configured, every group is inconclusive and the state stays `Degraded`. | definition of `Protected` |
| GA-6 | **Closed (D-50).** The M8 TCP evidence used a stand-in that never asked for the flow's original destination, so real Tor's transparent contract was unproven. The per-namespace relay reads `SO_ORIGINAL_DST` from the namespace that created the NAT and carries the stream to Tor's SocksPort as the application's address; `app-real-tor-test.sh` and the post-fix leakage run exercise it with real Tor, and the hermetic stand-in now speaks SOCKS and records the surviving destination, the source address and the per-group credential. The remaining external boundary is GA-1 (no ISP-facing vantage). | PC-17, GA-1 |

## I2P scope (M9): what was demonstrated

I2P is an independent, machine-wide network. There is no transparent-proxy equivalent, so the claim
is worded exactly: **clearnet egress is denied, and I2P is reachable only through the router's local
proxies**. Tor and I2P are alternatives, never layers: the validator refuses a request that enables
both, and an I2P ruleset that cited any exemption other than the router's own uid is refused by the
invariant checker.

| Claim | What it says | Evidence | Falsifier |
|---|---|---|---|
| **PC-22** | I2P is independent: no mixed-network configuration exists, and the I2P ruleset carries exactly the router's own exemption plus DHCP — no Tor uid, no application identity, and no redirect at all. | `i2p-adversarial.sh`: the kernel table under I2P has no `out_nat` and exempts only the router's uid; the transition case shows the router's exemption is absent under the fail-closed baseline and returns only with I2P; unit tests refuse `MixedNetworks`, `I2pNeedsSystemScope`, `I2pWithLan`, a foreign exemption, and any NAT chain in an I2P ruleset | A Tor/APP exemption in force under I2P, both networks enabled at once, or a redirect claimed by an I2P policy |
| **PC-23** | Every flow that is not the router's own is denied: an ordinary identity cannot reach the network over TCP or UDP, observed at the far end. | `i2p-adversarial.sh` (IA-1/IA-2): TCP refused and UDP refused, with **zero packets and zero connections at the far side**; the router's own uid does reach it (the exemption works); `policy-netns-test.sh` against the kernel: non-router uid blocked with zero packets, router uid allowed | One packet from a non-router identity at the boundary while I2P is reported |
| **PC-24** | Applications reach I2P only through the router's loopback proxies, and those proxies are closed to the network. | `i2p-adversarial.sh` (IA-6): a connection from the far side to the HTTP proxy is refused; the `i2pd.conf` renderer refuses a wildcard bind and the extra control surfaces (console, SAM, UPnP, outproxy) | A proxy reachable from off-host, or a proxy bound to anything but loopback |
| **PC-25** | I2P `Protected` requires evidence: clearnet TCP refused, the proxy answering, and the configured canary fetched through the proxy. Without a canary the state stays `Degraded`; a spoofed canary or a dead router alarms and the fail-closed baseline replaces the policy. | `i2p-adversarial.sh`: the canary through the proxy is what turns the state verified; the spoofed canary and the killed router each produce the fail-closed baseline; unit tests: `NoI2pEvidence` can never pass, a missing canary is inconclusive, a wrong answer and a dead proxy are alarms | `Protected` with no passing canary; a contradiction that does not apply the baseline |
| **PC-26** | Disconnect removes the policy and the exemption, and the interface never names a destination or a boundary address. | `i2p-adversarial.sh` (IA-10 and teardown): `status` names neither the canary host nor the boundary address; disconnect leaves no table; panic removes the router's exemption (observed at the boundary) | A destination or address in the interface, or a surviving exemption after teardown |

### I2P gaps and narrowings (M9 qualification)

| # | Gap | Claim |
|---|---|---|
| GI-1 | **Closed by the native qualification (M9.5).** On a clean Ubuntu 24.04.5 VM (VirtualBox, 4 vCPU / 8 GB, NAT networking) with real i2pd **2.61.0** from the official release, `scripts/i2p-real-router-test.sh` passed **29 held, 0 contradicted, 0 inconclusive**: the product's rendered configuration is accepted; the router starts as its real uid, bootstraps to the public network and stays stable; the real canary through the real HTTP proxy turns the state into `Protected`; ordinary clearnet TCP/UDP/DNS are denied with zero packets at the far-side boundary; the proxy is closed off-host; router death and tampering apply the fail-closed baseline; and Tor→I2P→Tor transitions never showed both exemptions (699 samples). Two environment findings are recorded: the Ubuntu-packaged i2pd **2.49.0 crashes** under load (heap corruption) on both WSL and the VM, so a production install should pin a current i2pd; and the qualification's operator-Tor config sets `ClientUseIPv6 0` and starts Tor early so its bootstrap overlaps the I2P phases. The earlier WSL result is preserved as environment-inconclusive. | PC-22…PC-26 |
| GI-2 | Public I2P network integration was demonstrated natively: the router reseeded, found floodfills and built tunnels (19 integration lines), and the canary was fetched through the real proxy. The hermetic suite's canary remains local. | PC-25 |
| GI-3 | APP+I2P is refused in M9; per-application I2P needs a conduit that does not exist yet. | PC-22 |
| GI-4 | The `Protected` definition's G9 rule applies: with no canary configured, an I2P profile stays `Degraded` by construction. | definition of `Protected` |

## What RC1 got wrong, and what M7 changed

RC1 (`v1.0.0-rc1`) is preserved as it was, and it was **not** a candidate whose claims all held. The
adversarial campaign falsified two of them, found three more defects behind them, and demonstrated
that a fourth claim was narrower than it read. That is recorded here rather than rewritten, because a
claim that was never falsified has not been tested.

| Defect | What it did to a claim | Fix |
|---|---|---|
| D-15, D-16 | **Falsified PC-03 and PC-06.** The `nat` and `filter` chains shared one priority, so their order was undefined and a redirect could race the filter that denies; and because the kernel recomputes the route after the filter verdict, a redirected packet's output interface in the filter chain is its *original* one, so the loopback allowance never matched redirected traffic. | Distinct priorities (`nat -100`, `filter 0`), an invariant that refuses a nat chain which can precede the filter, and loopback matched as a destination set (`127.0.0.0/8`, `::1/128`) in both chains. |
| D-17 | A relay that started and immediately exited was reported as protection. | The engine checks the relay is still running after start and fails the connect. |
| D-18 | **PC-09 was narrower than it read**: the DHCP exemption was compiled as `udp dport 68`, so it permitted the direction a client never sends and discarded the one it does — the link would die at the first renewal while the policy claimed to keep it alive. | `udp sport 68 udp dport 67`, a `Sport` expression in the IR, an invariant that refuses a DHCP exemption without a source-port match, and AE-2 observing both directions. |
| D-19 | **PC-14 was narrower than it read**: a disconnect removed the policy before the state stopped reporting protection, so for a few hundred microseconds a caller would have been told "protected" with no policy in the kernel. | The transition is announced before anything is touched, and a machine already `Off` announces nothing. |
| — | **PC-08 was not held as this document uses the term**: only tampering that a probe traverses could be detected (G3, demonstrated by AC-5). | The helper records the kernel's own report of the policy it applied and compares against it; a difference is an alarm and the fail-closed baseline replaces the table. |

What remains unverified is the list of open gaps above, and it is never to be read as passing.

## Appendix A — RC1, as it was

**Two claims below were subsequently falsified by the M7 campaign** (PC-03, PC-06, through D-15 and
D-16); the entries are left as they stood so the falsification can be read against them.

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

## Appendix B — RC2, and what M7 verified for it

- **Commit under test:** the commit this document is part of, tagged `v1.0.0-rc2`
- **Environment:** Ubuntu 24.04.5 LTS, kernel 6.18.33.2-microsoft-standard-WSL2, nftables 1.0.9,
  rustc/cargo 1.98.1
- **Unit tests:** 291 passed, 0 failed
- **Integration:** `policy-netns-test.sh` PASS · `netd-socket-test.sh` PASS · `bootguard-test.sh`
  PASS · `core-cli-test.sh` PASS
- **Adversarial suite** (`scripts/adversarial.sh`, 27 cases): **26 held, 0 contradicted, 1
  inconclusive by design** (AS-4: IPv6 denial is not demonstrated on a run whose link has no IPv6;
  it is demonstrated on the v6-capable runs, AS-3). No expected-failure marker remains: the case
  that demonstrated a gap at RC1 (AC-5) now holds.
- **Static checks:** `cargo clippy --workspace --all-targets -D warnings` clean · `cargo check
  --workspace --all-targets` clean · `cargo fmt --all --check` clean
- **Defects found and fixed in this campaign:** D-15…D-20, each with a regression test that fails on
  the old behaviour (see `ADVERSARIAL-TEST-PLAN.md`, Appendix A)
- **Claims changed by the campaign:** PC-03, PC-06 and PC-09 falsified at RC1 and verified after the
  fixes; PC-08 widened from "probed changes" to "changes to the policy"; PC-14 tightened by D-19;
  PC-01, PC-02, PC-05, PC-07, PC-11, PC-12, PC-13 moved from "not observed" to verified end to end
- **Open, and not passing:** G6 (boot ordering), G8 (external vantage), G9 (a minimum set of
  configured checks), G10 (privileged attackers, out of scope), G11 (DHCPv6), G12 (a transient
  outage can leave the machine blocked until a person acts), G13 (one-by-one exemption diff)
- **Working tree:** clean at the tag. The release-qualification suite was then re-run against a fresh
  checkout of the tagged commit in a clean environment, with its own build directory: **291 unit
  tests, four integration scripts, 26 held / 0 contradicted / 1 inconclusive by design, 0
  demonstrated**, `cargo fmt --check`, `cargo check --all-targets` and `clippy -D warnings` all
  clean. The rerun's per-case log is identical to the run recorded above.
