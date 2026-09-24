# Ghostnector — Architecture Review & Recommended Design

**Status:** design review, no implementation. Version 0.1 (draft for discussion).
**Scope:** Linux desktop (systemd-based), single-host. Not a router, not a VM gateway.
**Author's stance:** challenge everything; keep only what survives.

> Reading order: §0 gives the verdict and the decisions that matter. §1–§2 establish what we are
> defending against and why the current proposal is wrong in three specific places. §3–§13 are the
> design. §14–§16 are how we prove it works. §17 is what to build first.

---

## 0. Executive summary

Your prototype has the right instinct — transparent interception, one central switch, no per-app
proxy configuration — and three load-bearing mistakes:

1. **Three independent toggles is a coherence bug, not a feature.** It permits states that are
   *worse* than either component alone (notably "Tor on, DNS via DNSCrypt on the clearnet").
   Replace three booleans with a **validated mode + scope state machine**.
2. **DNSCrypt must not be in the Tor path by default.** It is not "more encryption"; it is a
   different trust graph that re-introduces the user's real IP into DNS at exactly the moment Tor
   removes it. In Tor modes, DNS belongs inside Tor. DNSCrypt belongs to clearnet ("DNS lockdown")
   mode. There is one narrow, explicitly-fenced exception (authenticated DNS *over* Tor).
3. **I2P is not an additive privacy layer on top of Tor.** It is a *separate destination network*
   with a *different* anonymity model (it hides destinations from you and you from destinations, but
   **not your IP from I2P peers**). Chaining I2P and Tor in either direction buys no meaningful
   anonymity and costs latency, reliability, and new linkage. Run it beside Tor, not under or over it.

The single most important structural finding: **in a transparent-proxy (`TransPort`) design, all
host traffic shares one Tor circuit pool, because Tor's "Application Address" isolation property is
identical for every local process.** That is a real anonymity loss versus what most people assume a
transparent proxy gives them. The fix is architectural, not a setting: give each protected app its
own **source address** by giving it its own network namespace, and the isolation returns — with no
SOCKS support required from the app.

**Load-bearing decisions** (full register in Appendix A):

| # | Decision |
|---|---|
| DR-1 | Egress policy is enforced in the kernel (nftables), never in resolver/application config. |
| DR-2 | One owned nftables table, applied by atomic ruleset replacement; foreign tables are never touched. |
| DR-3 | Validated **mode × scope** state machine instead of three independent component toggles. |
| DR-4 | **Deny-first bootstrap:** fail-closed baseline applied before any service starts; holes opened only after Tor reaches 100%. |
| DR-5 | Local TCP/DNS redirected to loopback-bound `TransPort`/`DNSPort`. No TUN, no userspace forwarding in v1. |
| DR-6 | **Route-less app namespace** mode: protected apps live in a netns with **no default route**; only a netns-local DNAT to a host-local core address exists. |
| DR-7 | Source addresses are preserved across the namespace boundary (never masqueraded) so per-app Tor circuit isolation is recovered. |
| DR-8 | UDP denied by default and **rejected, not dropped**, so QUIC/RTC fall back in milliseconds instead of hanging. |
| DR-9 | IPv6 egress denied host-wide; **absent by construction** inside app namespaces. |
| DR-10 | Tor modes resolve DNS through `DNSPort`. DNSCrypt is a clearnet-mode resolver only. Authenticated-DNS-over-Tor is opt-in and firewalled to the Tor SOCKS port. |
| DR-11 | I2P is an independent destination network in its own namespace; no Tor↔I2P chaining; off by default; client-only; no clearnet outproxy. |
| DR-12 | Exemptions are uid-scoped, enumerated, and visible in the UI. The GUI, the updater, and the core have **no** exemption. |
| DR-13 | Unprivileged GUI → unprivileged core → small capability-scoped `netd`. No root process, no `sudo` re-exec of the GUI. |
| DR-14 | Enforcement lives in the kernel and in independent services; **control-plane death never changes the data plane**. |
| DR-15 | Rollback to clearnet is allowed **only** from pre-protection states. Once protected, failure escalates to BLOCKED — never to clearnet. |
| DR-16 | Reboot with protection intent = deny-until-verified, with a documented local recovery path. |
| DR-17 | Every policy change is one atomic transaction; the network is never in a more-permissive-than-intended state. |
| DR-18 | Continuous verification by a process that is *inside* the protected set — if it can reach the internet directly, that is the alarm. |
| DR-19 | No persistent traffic metadata. Counters and an in-memory block list only. Bridge lines are secrets. |
| DR-20 | `forward` is default-deny: containers/VMs are blocked, not leaked. Audit for `CAP_NET_RAW`/`CAP_NET_ADMIN` file capabilities, which bypass or disable the policy. |

**What Ghostnector can and cannot do** — stated up front and repeated in the UI:

- **Can:** keep destination servers and network observers from learning your IP; keep your ISP from
  reading your traffic; keep local networks from tampering with your DNS; prevent most accidental
  clearnet egress; make protocol-level leaks structurally impossible for protected scopes.
- **Cannot:** protect a compromised host (root, kernel, or unprivileged-user malware can defeat or
  bypass much of this); defeat end-to-end traffic correlation by a global adversary; anonymize an
  identity you authenticate (logging into an account, reusing a unique nickname); prevent browser
  fingerprinting; stop application-layer identifiers, stylometry, or timing analysis; make
  real-time UDP (voice/video/games) both anonymous and usable; hide the fact that you use Tor from
  a network that blocks or fingerprints it (bridges raise the cost, they do not eliminate it).

---

## 1. Threat model

### 1.1 Adversaries

| # | Adversary | Capability | In scope? | Primary mitigation | Residual risk |
|---|---|---|---|---|---|
| A1 | ISP / transit, passive | Sees all your packets, sizes, timing, SNI, IPs | Yes | Tor hides destinations; TLS hides content; DNSCrypt hides DNS names | **Tor usage itself is visible**; timing/size correlation |
| A2 | ISP / transit, active | Blocking, TCP RST injection, DNS tampering, on-path MITM | Yes | Tor bridges/pluggable transports; authenticated DNS; TLS | Blockable; PT arms race |
| A3 | Hostile local network (café Wi-Fi, hotel) | Same subnet; can ARP/DNS/DHCP spoof, port-scan | Yes | Identical to A1/A2 for egress; DNS lockdown; LAN policy default-off | Local identity (MAC/hostname) still visible unless spoofed |
| A4 | Destination server | Sees the Tor exit, not you | Yes | Tor; onion services remove the exit from the path | Login/session/unique content de-anonymizes; exit is still seen |
| A5 | Malicious/colluding Tor exit | Reads/changes cleartext; lies in DNS answers; logs dests | Yes | End-to-end TLS; authenticated DNS (opt-in); onions; consistent exit policies | Cleartext protocols are exposed; exit-only attacks on timing |
| A6 | Malicious/compromised DNS resolver | Logs queries, returns forged answers, hijacks NXDOMAIN | Yes | DNSCrypt/DoH/ODoH + DNSSEC hard-fail; or Tor `DNSPort` | A resolver you chose can still profile you (unless ODoH-style unlinkability) |
| A7 | Local unprivileged malware | Can open sockets, spawn processes, use user namespaces, use `CAP_NET_RAW` file caps | **Partially** | Kernel policy is uid/transport-based, so it survives userspace-NAT escapes; capability audit | Can keylog, read files, exfiltrate via allowed paths, DoS |
| A8 | Root / kernel compromise | Total | **No** | None | Out of scope by definition |
| A9 | Global passive adversary (both ends) | Observable correlation of entry and exit | **Partially** | Tor's design; padding; circuit isolation; avoided identity reuse | End-to-end timing correlation is not solvable at this layer |
| A10 | Physical / hardware / supply chain | Evil maid, TPM, firmware | **No** | Disk encryption, verified boot (out of scope) | Out of scope |
| A11 | I2P peers | See your IP as a router participant | N/A (inherent) | Run client-only; don't run transit tunnels | I2P **does not** hide your IP from I2P peers. Document loudly. |
| A12 | Ghostnector itself | Bugs, misconfiguration, stale state | Yes | Default-deny, transactional state, verification, minimal privilege | This is the main in-scope risk we actually control |

### 1.2 Framing that prevents bad decisions

- **Anonymity = unlinkability of origin from destination.** Tor provides it. DNSCrypt does not; it
  provides *confidentiality and integrity* of DNS, while *adding* a party that knows your IP.
  I2P provides unlinkability *within I2P's destination space*, not against I2P peers.
- **Privacy vs anonymity:** DNSCrypt keeps your ISP from reading your DNS. It does not keep your
  resolver from knowing you. Do not let one goal silently substitute for the other.
- **The threat model is per-scope.** "Protected" means *a defined set of processes* has no path to
  the internet except through Tor. Unprotected system daemons on the same host (updates, NTP) are
  not protected, and in system-wide scope they must be **blocked**, not quietly permitted.
- **Trust boundaries must be enumerated.** Ask of every design: *how many new parties learn which
  of my queries go where?* A design can be encrypted everywhere and still be worse.

### 1.3 Invariants (tested, not aspirational)

- **I1** No packet leaves a non-loopback interface from a protected uid unless it is Tor traffic,
  DHCP, or an explicitly enabled, user-visible exception.
- **I2** No DNS query from a protected scope reaches a clearnet resolver in Tor modes; no plaintext
  DNS leaves the host at all in either Tor or DNS-lockdown modes.
- **I3** Stopping or crashing any Ghostnector userspace component never *increases* connectivity.
- **I4** The protected state is re-assertable and idempotent: applying it twice changes nothing.
- **I5** Disconnect restores exactly the captured baseline, or reports a conflict and takes the
  conservative default — it never "resets networking to defaults".
- **I6** No destination, query, or per-connection metadata is written to persistent storage.
- **I7** Policy changes are atomic; there is no window in which the host is more permissive than
  the union of (old state, new state).
- **I8** Every exemption is enumerated in runtime state and visible in the UI with its reason.
- **I9** The privileged helper exposes no verb that accepts an arbitrary ruleset, command, path, or
  interpreter input from an unprivileged peer.

---

## 2. Critique of the current Tor + DNSCrypt + I2P proposal

### 2.1 "Three independently controllable components" is the core flaw

Independent toggles generate invalid states. The most dangerous is the one your proposal implies by
default:

> **Tor enabled + DNSCrypt resolving on the clearnet.** Applications' TCP goes through Tor, but DNS
> goes to a public resolver directly, from your real IP, in cleartext-to-your-ISP (encrypted to the
> resolver). The resolver learns your real IP **and** your query stream. The ISP learns which
> resolver you use and when. If the resolver logs, you have a durable record linking *you* to *what
> you looked up* — precisely the linkage Tor exists to prevent. Time-correlating the resolver's
> query log with the exit's traffic log is trivial for a well-placed observer.

That single combination makes Tor mode *worse than plain Tor with a local caching resolver*. A UI
that lets a user select it is a UI that ships a footgun with a green "protected" badge.

**Fix:** replace component toggles with a **mode × scope** model (§3.2) whose combinations are
validated by the core. The GUI may still show three service tiles (Tor, DNS, I2P) — as *status*
displays, not as independent policy switches. Where a service can be toggled, the allowed
combinations are fixed by a matrix, and every invalid state is unrepresentable, not just discouraged.

### 2.2 DNSCrypt in Tor mode: not a layer, a different trust graph

You asked: DNSCrypt → clearnet, DNSCrypt while Tor carries app traffic, `DNSPort`, DNSCrypt through
Tor, encrypted DNS outside Tor, or per-mode strategies? The answer is **per-mode**, and the
comparison is not close (details in §8):

| Option | Who learns your real IP + queries | Authenticated answers? | Latency | Verdict |
|---|---|---|---|---|
| DNS to ISP, plaintext | ISP, local net, resolver | No | Lowest | Never |
| DNSCrypt → clearnet | The resolver (you chose it) | Yes (DNSCrypt cert / DNSSEC) | Low | **Clearnet mode only** |
| DNSCrypt → clearnet **with Tor on** | The resolver, from your real IP | Yes | Low | **Forbidden** — re-links you |
| DNSCrypt → over Tor SOCKS | Only the exit sees a Tor client; resolver sees exit IP | Yes | High | Opt-in, firewalled to the SOCKS port |
| Tor `DNSPort` | Nobody links query to you; the exit resolves (resolver sees exit IP) | **No** — exit can lie | Medium | **Default in Tor modes** |
| App-level DoH/DoT | The app's chosen resolver, from the exit | Yes | Mixed | Allowed; unauditable; not a leak in Tor mode |

The two defensible choices in Tor mode are `DNSPort` (default) and authenticated-DNS-over-Tor
(advanced). "Both at once" is incoherent: two resolvers for one name space = two places your
interests leak, plus a race between answer sets.

**Crucial failure-mode argument:** a DNSCrypt-proxy that is *supposed* to be tunneled through Tor but
silently loses its proxy configuration is a catastrophic, silent, real-IP DNS leak. If you ship that
feature, its egress must be **firewalled to the Tor SOCKS port only** (a resolver that must be
tunneled may only have a path to the tunnel). With that rule, the failure mode is "DNS stops", which
is correct.

### 2.3 I2P is not additive

- Tor→I2P ("reach I2P through Tor"): to be in I2P you must *be a participant*; tunnelling a router's
  transport through Tor gives a slow, differently-profiled peer, breaks I2P's UDP-based transport
  assumptions (Tor cannot carry UDP), and creates a linkage between an I2P identity and a Tor
  circuit that did not previously exist. **No benefit for the stated goal.**
- I2P→Tor (I2P outproxy onto Tor): makes you the bridge between two anonymity networks. Your I2P
  router IP is visible to I2P peers *anyway*; the destination sees a Tor exit; the composite gives
  roughly the anonymity of I2P alone while adding a Tor circuit that can be correlated. Also, running
  an outproxy from home is a known abuse magnet. **No.**
- I2P does **not** hide your IP from I2P peers (A11). If the user's mental model is "I2P is another
  Tor", the UI must correct it, or they will make bad decisions.

**Fix:** I2P is an independent destination network, enabled on demand, isolated in its own
namespace, with no outproxy and no Tor chaining (§10).

### 2.4 Interception-only is incomplete

The proposal says "transparent proxying of supported TCP traffic" — correct as far as it goes, and
then silent about the rest: UDP, QUIC, IPv6, ICMP, WebRTC, forwarded traffic (containers/VMs),
DNS-by-IP literals, interfaces that change under you, and the fact that a `REDIRECT`-based design
gives every app the *same* circuit pool. Each of those is a leak or a footgun. §7, §8, §11 cover them.

### 2.5 Missing subsystems

Not mentioned in the brief, all mandatory: boot-time re-assertion after reboot; ownership and
restoration of resolver configuration (systemd-resolved vs NetworkManager vs static file);
transactional state with a journal; continuous verification; captive-portal handling; capability
auditing (`CAP_NET_RAW` and `CAP_NET_ADMIN` file capabilities defeat or disable nftables policies);
the `forward` chain (containers/VMs leak around `OUTPUT`-only rules); and multi-user semantics.

### 2.6 What is right and should be kept

Keep: transparent interception as the *coverage* mechanism; one central Connect/Disconnect; health
and routing-state inspection; "no per-app proxy configuration required"; and — importantly — your
instinct that **Disconnect must restore the previous state rather than a default state**. That last
one is an unusually mature design goal and it shapes §12.

---

## 3. Recommended architecture

### 3.1 Component and plane model

```
        ┌──────────────────────── CONTROL PLANE (unprivileged) ────────────────────────┐
        │  ghostnector-gui        ghostnector-core                ghostnector-verify  │
        │  (session user)         (system user, no caps)          (blocked-by-policy) │
        │  displays state,        state machine, journal,         periodic probes:   │
        │  requests transitions   IPC, health, orchestration      "can I escape?"    │
        └───────────┬─────────────────────┬──────────────────────────────┬────────────┘
                    │ unix socket         │ unix socket                  │
        ┌───────────▼─────────────────────▼──────────────────────────────▼────────────┐
        │  ghostnector-netd   (CAP_NET_ADMIN, +CAP_SYS_ADMIN in ns mode)               │
        │  the ONLY component that writes policy: renders rulesets, applies them       │
        │  atomically over netlink, wires namespaces. Verb API, never shell.           │
        └───────────────────────────────────┬─────────────────────────────────────────┘
                                            │
        ┌───────────────────────────────────▼─────────────────────────────────────────┐
        │  DATA PLANE (kernel + independent daemons)                                  │
        │  nftables tables/sets · routing rules · netns/veth · conntrack              │
        │  tor  ·  dnscrypt-proxy  ·  i2pd    (separate systemd units, static uids)   │
        └─────────────────────────────────────────────────────────────────────────────┘
```

Three properties are deliberate:

- **Enforcement is kernel-resident (DR-14).** `nftables` state and netns routes persist regardless of
  what happens to `core`, `netd`, or the GUI. Killing the GUI — or the whole control plane — changes
  nothing about protection. This is the opposite of "the daemon holds the kill switch".
- **Only one component writes policy (DR-13).** `netd` is small enough to audit; its verbs are fixed
  (apply-this-named-profile, wire-this-namespace, flush-conntrack, revert). It never accepts a
  ruleset, a shell command, a path, or an interpreter string from a peer.
- **Services are separate units with static uids (DR-12).** Tor's exemption is `skuid == tor`, not a
  port or an interface, and it is visible in the UI's exemption list.

### 3.2 Modes and scopes

Replace three booleans with one **scope** selection and two **network** selections:

**Scope (how much of the machine is covered):**

| Scope | Coverage | Structural strength | Cost |
|---|---|---|---|
| `OFF` | Policy absent | — | — |
| `DNS` | Encrypted DNS only (no Tor) | Port-level lockdown | Minimal |
| `APP` | Apps explicitly launched into Ghostnector | **Strongest**: no route = no leak | Needs launcher |
| `USER` | All processes of the selecting user | Good | System daemons still clearnet/blocked |
| `SYSTEM` | All local processes | Good (uid/transport policy) | Breaks containers/VMs by design |

**Networks (destination planes):** `CLEARNET`, `TOR`, `I2P` — with validity rules:

| Combination | Valid? | Why |
|---|---|---|
| `CLEARNET` + `DNS` scope | Yes | DNS lockdown. |
| `TOR` + `DNS` scope | **No** | In Tor modes, DNS policy is owned by Tor (`DNSPort`). DNSCrypt on the clearnet while Tor carries traffic is exactly the forbidden combination from §2.1. |
| `TOR` + `APP`/`USER`/`SYSTEM` | Yes | The main modes. |
| `I2P` + anything | Yes, with a warning | I2P runs in its own namespace and is deliberately not joined to any Tor scope. Enabling it while in `SYSTEM` Tor scope is allowed but the UI must state that the ISP still sees I2P traffic from the same access line. |
| `I2P` + `DNS` scope | Yes | I2P names are not resolved via DNS; clearnet names are not resolved inside I2P. |
| `BLOCKED` (fail-closed) | Always available | Not a user mode; the failure state. |

**The mode is a state machine, not a bag of flags:** `OFF → APPLYING → PROTECTED ⇄ DEGRADED → BLOCKED`,
with `BLOCKED` reachable from any state and `PROTECTED` reachable only through a successful
verification (§14). The UI shows *evidence* ("last verified 12 s ago", "3 apps in protected
namespaces", "2 blocked egress attempts"), never a bare "Anonymous" badge.

### 3.3 The routing decision

**Two mechanisms, chosen by scope, not by taste:**

1. **`SYSTEM` scope → nftables redirect (DR-5).** Local TCP destined anywhere is redirected in
   `nat OUTPUT` to a loopback-bound Tor `TransPort`; UDP/TCP port 53 to `DNSPort`; everything else
   denied. Rationale: kernel-path forwarding, no userspace copy, no MTU/MSS pathology, no TUN
   device, and the policy is transport-based (uid/proto/port) rather than interface-based — which
   turns out to matter against escape attempts (§7.7).
2. **`APP` scope → route-less namespace (DR-6).** Each protected app gets a netns whose only
   reachable address is a host-local "core" address; inside the netns, a netns-local nat chain DNATs
   TCP and :53 to that address. The app namespace **has no default route at all**. Leaks are not
   prevented by rules; they are prevented by the absence of a path. IPv6 is disabled inside the
   namespace (a per-netns sysctl, zero host impact).

`USER` scope is the `SYSTEM` mechanism with the redirect/deny rules scoped to one uid, plus
loopback exemption for the rest of the machine. It is strictly weaker than `SYSTEM` (root daemons
still talk to the clearnet) and must be described that way in the UI.

**Rejected for v1** (kept in §16 as benchmark candidates): TUN/tun2socks-style userspace forwarding
(copy cost, MTU pathologies, and a userspace TCP stack in the trust path), TPROXY (needed only for
*forwarded* traffic; the route-less namespace removes the need), and per-app Tor instances (multiplies
guards, memory, and your network footprint for no gain over source-address isolation).

### 3.4 Why the route-less namespace is the strongest mode

- **Fail-closed by construction.** No default route ⇒ a newly installed app, a new protocol, a
  forgotten UDP port, or a stale firewall rule cannot leak. The failure mode of a broken rule is
  "no connectivity", not "clearnet connectivity".
- **IPv6 leak impossible.** No IPv6 address/route in the namespace (and IPv6 disabled there).
- **Per-app Tor circuit isolation for free (DR-7).** Tor's isolation profile includes the
  **Application Address** — the source address of the connection as Tor sees it. Host-wide
  `REDIRECT` makes every app appear as `127.0.0.1` (or the host's address), so *all* host traffic
  shares circuits. Preserving the namespace's distinct source address across the veth means each app
  has a different Application Address ⇒ different isolation profile ⇒ different circuits, with **no
  SOCKS support required from the app** and no masquerade. This is the single highest-value
  architectural move in this review.
- **Container-like cleanup.** Deleting the namespace deletes the policy. Restoration is trivial
  (§12) and cannot leave stale rules behind.

Costs, stated honestly: apps needing LAN discovery, inbound connections, or multicast will not work
unless the user opts into a LAN exception; the launcher is a small extra UX step; and it requires the
`netd` capability set to include `CAP_SYS_ADMIN` for namespace wiring (hence: keep `netd` tiny, and
ship `SYSTEM` mode first).

---

## 4. Traffic-flow diagrams

### D1 — `SYSTEM` scope, Tor network

```
   ┌────────────┐  ┌────────────┐  ┌─────────────┐
   │ browser    │  │ mail client│  │ package mgr │   protected scope: all local uids
   └──────┬─────┘  └──────┬─────┘  └──────┬──────┘
          └───────────────┴───────────────┘
                          │  ordinary sockets (any destination)
   ┌──────────────────────▼──────────────────────────────────────────────────────┐
   │ nftables `inet ghostnector`                                                 │
   │  nat/output    tcp                    → 127.0.0.7:9040   (TransPort)        │
   │  nat/output    udp/tcp dport 53       → 127.0.0.7:9053   (DNSPort)          │
   │  filter/output skuid tor → accept     (bootstrap + relay traffic only)      │
   │  filter/output udp dport 68 → accept  (DHCP, so the link stays up)          │
   │  filter/output LAN set → policy       (default: reject)                     │
   │  filter/output udp/icmp               → reject            (fast QUIC fallback)│
   │  filter/output everything else        → drop, counted                       │
   │  filter/forward everything            → drop, counted (containers/VMs)      │
   └──────┬────────────────────────────────────────────────┬─────────────────────┘
          │ 127.0.0.7:9040                                 │ 127.0.0.7:9053
   ┌──────▼─────────┐                            ┌─────────▼──────────┐
   │ tor TransPort  │                            │ tor DNSPort        │
   │ (loopback only)│                            │ (loopback only)    │
   └──────┬─────────┘                            └─────────┬──────────┘
          └──────────────────┬─────────────────────────────┘
                             │ Tor's own egress: exempt by skuid, still
                             │ subject to interface/route reality
                             ▼
              entry guard ──► middle relay ──► exit relay ──► destination
                   │                                  │
                   │                                  └─► resolver (exit's), or
                   └─ exit sees: destination IP, port, timing, cleartext if any
```

### D2 — DNS in each mode

```
  DNS-LOCKDOWN (clearnet)                    TOR (any scope)
  ─────────────────────────                  ────────────────────────────────
  app ─► 127.0.0.9:9053 (stub)               app ─► (redirect/DNAT) ─► chokepoint
        │                                          │
        │ only dnscrypt-proxy uid may reach        │ chokepoint forwards to
        │ 53/853/443 outbound; everyone else        │ Tor DNSPort
        │ is dropped/rejected at the kernel         │
        ▼                                          ▼
   dnscrypt-proxy ── ODoH / anonymized       DNSPort ── Tor circuit ── exit ──► resolver
        relay ──► resolver                          (resolver sees the exit, not you;
        (resolver never sees your IP;               answers are NOT authenticated)
         requires relay not colluding)

  ADVANCED (opt-in): authenticated DNS over Tor
  app ─► chokepoint ─► dnscrypt-proxy ──[egress firewalled to 127.0.0.7:9050 ONLY]──►
                                          Tor SOCKS ──► resolver
                                          (authenticated answers; slow; must not fall back)
```

### D3 — `APP` scope: route-less namespace

```
 ┌──────────────────────── app namespace N (one per app / identity group) ──────────────┐
 │  app, uid 1000, source address 10.200.N.2                                            │
 │  connect("93.184.216.34", 443)                                                       │
 │      │                                                                               │
 │      ▼  netns-local nftables                                                          │
 │  nat/output   tcp              → dnat 10.200.N.1:9040   (SOURCE PRESERVED)            │
 │  nat/output   udp/tcp dport 53 → dnat 10.200.N.1:9053                                 │
 │  filter/output udp, icmp       → reject (ICMP so the app fails fast)                  │
 │  routing: NO DEFAULT ROUTE. Only 10.200.N.0/30 on veth. IPv6 disabled in-netns.       │
 └───────────────────────────────────────┬──────────────────────────────────────────────┘
                                         │ veth, no masquerade, no forwarding rewrite
 ┌───────────────────────────────────────▼──────────────────────────────────────────────┐
 │ host: 10.200.N.1 is a host-local address, so the packet is delivered locally          │
 │   tor TransPort bound to the core address (or wildcard + input rules)                 │
 │     → Tor sees "Application Address = 10.200.N.2"  ⇒ per-app circuits                 │
 │   DNS chokepoint bound per app, upstream bound to the same source ⇒ per-app DNS too   │
 └───────────────────────────────────────────────────────────────────────────────────────┘
```

### D4 — I2P as an independent plane

```
  ┌──────────────── i2p namespace ────────────────┐
  │ i2pd (uid i2pd)                               │
  │  · client-only (no transit tunnels)           │
  │  · HTTP proxy :4444, SOCKS :4447, SAM :7656   │
  │  · NTCP2 (TCP) + SSU2 (UDP) to I2P peers      │
  │  · NO outproxy → clearnet names fail          │
  └──────────────┬────────────────────────────────┘
                 │ veth: only the proxy ports are reachable from the host
  ┌──────────────▼────────────────────────────────┐
  │ host: apps configured explicitly (PAC/profile) │
  │   *.i2p → 10.201.0.2:4447                      │
  │   everything else → unchanged / Tor scope      │
  └───────────────────────────────────────────────┘
  Note: I2P peers see this machine's IP. That is inherent to I2P, not a bug.
        Ghostnector never joins I2P to Tor and never exposes an outproxy.
```

### D5 — Connect transaction (ordering is the security property)

```
  1. PRECHECK     binaries present, uids stable, netd reachable, no conflicting firewall
  2. CAPTURE      baseline snapshot (routes, resolv.conf, sysctls, interface set, NM state) → journal
  3. DENY         apply fail-closed baseline atomically   ◄── the host is now safe but offline
                    allow: loopback, DHCP, skuid tor
                    deny:  everything else (TCP/UDP/ICMP/IPv6, forward)
  4. START        start tor --verify-config first; wait for bootstrap 100% (timeout ⇒ abort+rollback)
  5. RESOLVER     point the resolver layer at the chokepoint (which points at DNSPort)
  6. OPEN         atomically add redirects (TCP→TransPort, :53→DNSPort) and the scoped deny rules
  7. VERIFY       escaped? (must fail) · exit identity? (must differ) · DNS canary? (must not appear
                  at the ISP resolver) · counters sane? ⇒ PROTECTED, else BLOCKED
  8. REPORT       persist intent=protected, exemptions list, verification evidence, timestamps
```

Any failure in 3–6 rolls back to the captured baseline **only because protection was never
established** (DR-15). Failures in 7 never roll back to clearnet; they escalate to `BLOCKED`.

### D6 — Failure state machine

```
   OFF ──connect──► APPLYING ──ok──► PROTECTED ──service loss──► BLOCKED ──recovered──► PROTECTED
                       │                 │                        ▲   (only after re-verification)
                       │                 └──verif. unavailable──► DEGRADED
                       │                                              │
                       └── any failure ──► OFF (rollback, protection never existed)
   Any state ── "Panic / Block now" ──► BLOCKED (rules only; no rollback until user asks)
   BLOCKED never transitions to clearnet automatically. Only an explicit user action does that,
   and only with a warning + re-verification that the user understands the consequences.
```

---

## 5. Component responsibilities

| Component | Owns | Must never do | Runs as |
|---|---|---|---|
| `ghostnector-gui` | Presentation, user intent, evidence display, exemption list, transitions | Touch nftables/routes/resolv.conf; read Tor's control port directly; hold secrets beyond its own config | Session user |
| `ghostnector-core` | Mode state machine, journal, orchestration, health, IPC, resolver-layer coordination, verification scheduling | Apply kernel policy itself; run as root; read user files | System user, no capabilities |
| `ghostnector-netd` | Atomic ruleset application, sets/maps, netns+veth wiring, conntrack flush, whitelisted sysctls | Accept arbitrary rulesets/commands/paths; parse user input; network I/O | System user, `CAP_NET_ADMIN` (+`CAP_SYS_ADMIN` only in ns mode) |
| `ghostnector-boot-guard` | Early fail-closed baseline if intent=protected | Start Tor, resolve anything, reach the network | Same caps as netd, separate unit |
| `ghostnector-verify` | Continuous escape/identity/DNS-canary checks; emits verdicts | Be exempted from policy; log destinations persistently | System user, **inside** the protected set |
| `tor` | Tor client: TransPort, DNSPort, SOCKSPort, bridges, bootstrap | Be a relay/exit/HS host by default; be reachable from LAN | `debian-tor` (static), sandboxed |
| `dnscrypt-proxy` | Clearnet-mode encrypted resolver; ODoH/anonymized-relay capable; DNSSEC hard-fail | Talk to anything except its resolvers and (in advanced mode) the Tor SOCKS port | `ghostnector-dns` (static) |
| `i2pd` | I2P router (client-only), HTTP/SOCKS/SAM listeners | Have an outproxy; be reachable outside its namespace; be joined to Tor | `i2pd` (static) |
| nftables/routes/netns | The policy | Be written by anything but `netd` | kernel |

---

## 6. Privilege-separation design

### 6.1 What actually needs privilege (nothing else gets any)

| Operation | Required privilege | Notes |
|---|---|---|
| Write nftables rules | `CAP_NET_ADMIN` | Netlink. Do **not** shell out to `nft`; use libnftables/netlink and never string-concatenate rules |
| Policy routes / rules | `CAP_NET_ADMIN` | Same |
| Flush conntrack | `CAP_NET_ADMIN` | Needed on transitions so pre-existing flows cannot survive |
| Net policies (`net.ipv4.conf.*`, per-netns `disable_ipv6`) | `CAP_NET_ADMIN` (in the owning netns) | Journal every key/value written |
| Create/move netns, veth, move devices into netns | `CAP_SYS_ADMIN` (+`CAP_NET_ADMIN`) | Confine to `netd`; consider making an unprivileged-userns variant only as an experiment |
| Bind a privileged port | not needed here | The DNS chokepoint uses a high port and is reached by DNAT — drop `CAP_NET_BIND_SERVICE` |
| Start/stop services | systemd D-Bus + polkit policy | `core` gets a narrow polkit rule for its own units only |
| Write `/etc/resolv.conf` | root, or `resolvectl` via polkit | Prefer the systemd-resolved cooperation path (§8.6) |
| Read Tor's control port | cookie readable by `core`'s group | Control port is loopback-only, cookie auth, `core`-only |

`core` needs **zero** capabilities. The GUI needs **zero** privileges beyond being the user. The
only privileged process is `netd`, and it should stay under a few thousand lines of code.

### 6.2 Hardening expectations for the privileged units

Capability bounding set exactly as needed; `NoNewPrivileges`; `ProtectSystem=strict` with an explicit
read-write path for `/run/ghostnector`; `ProtectHome`; `PrivateTmp`; `PrivateDevices`;
`ProtectProc=invisible`/`ProcSubset=pid`; `RestrictAddressFamilies` narrowed per unit (`netd`:
`AF_UNIX` + `AF_NETLINK` only; Tor: `AF_INET`/`AF_INET6`/`AF_UNIX`); `SystemCallFilter` allowlists
rather than denylists; `MemoryDenyWriteExecute`; `LockPersonality`; `RestrictSUIDSGID`;
`RestrictNamespaces` (deny for everything except `netd`, which needs only `net`); static (non-
`DynamicUser`) uids because the policy is uid-based.

### 6.3 Uid stability is a security invariant

`skuid`-based exemptions only work if uids are stable. Consequences:

- Services use `systemd-sysusers`-allocated static system users; never `DynamicUser=yes`.
- At every Connect, `core` verifies that the configured uids still resolve to the expected names and
  **refuses to connect** if they do not (a reassigned uid would silently widen or break the policy).
- The exemption list is rendered from the same source of truth that produced the ruleset, so the UI
  cannot drift from the kernel.

### 6.4 IPC and authorization

- `GUI ↔ core`: unix socket in `/run/ghostnector/`, group-owned, `SO_PEERCRED` verified, schema-
  versioned, length-capped, no free-form strings.
- `core ↔ netd`: separate socket in a root-owned `0700` directory; `netd` accepts only from `core`'s
  exact uid; verbs are fixed (`apply_profile(name, params_validated_by_netd)`, `wire_namespace(id)`,
  `flush_conntrack`, `revert`). `netd` re-validates every parameter against its own tables and
  rejects anything outside a closed set.
- Sensitive transitions (`SYSTEM` scope, enabling bridges, enabling I2P, "allow LAN", disabling the
  kill switch) go through polkit as `auth_admin` even for the desktop user. Everything else is
  allowed for the owning session.
- No `LD_PRELOAD`, no env passthrough, no file descriptors from peers, no client-supplied paths.
- Version skew between `netd` and `core` must be a hard failure, not best-effort.

### 6.5 Secrets

| Secret | Why it matters | Handling |
|---|---|---|
| Bridge lines | Fingerprints your usage; identifies you to your ISP/bridge | `0640 root:ghostnector` file or the systemd credential store; never logged; never shown in the GUI's diagnostics; excluded from crash dumps |
| I2P destination/router keys | Compromise = identity compromise | `i2pd`-owned `0700`, never readable by `core`/GUI |
| DNSCrypt resolver config | Reveals which resolver you chose | `0640 root:ghostnector`, read-only to `dnscrypt-proxy` |
| Local state/journal | Reveals your protection history | No destinations; `0640`; no traffic timings persisted |

---

## 7. Firewall and routing strategy

### 7.1 nftables, one owned table, atomic replacement

**Decision:** nftables (`inet ghostnector` + one `ip` table if needed) over iptables.

**Reason:** a single `nft` batch is applied atomically with a generation counter, so there is no
intermediate state; sets and maps collapse many rules into one lookup; `inet` handles v4/v6 in one
place; the `meta skuid`/`socket cgroupv2` matchers are exactly what scoping needs. `iptables-nft` is a
compatibility shim: rule-at-a-time updates create windows and make rollback non-atomic.

**Privacy impact:** removes the "half-applied ruleset" window (invariant I7). **Performance impact:**
neutral-to-positive (O(1) set lookups). **Failure behavior:** a failed apply leaves the previous
generation intact; `netd` reports failure and `core` treats it as a Connect abort (§11).

Rules that follow from ownership (invariant I5): never `flush ruleset`; never edit `filter`, `nat`,
`firewalld`, `docker`, or `ufw` tables; never delete a rule we did not create; our chains carry a
Ghostnector-specific name and priority; uninstall removes exactly our tables.

### 7.2 Chain layout (`SYSTEM` scope, Tor)

| Chain | Hook / priority | Purpose |
|---|---|---|
| `out_nat` | `nat output` | `skuid tor → return` · :53 → `DNSPort` · all TCP → `TransPort` (scoped uids only) |
| `out_filter` | `filter output` | exemptions (tor, DHCP), LAN policy, UDP/ICMP reject, default drop, counters |
| `in_filter` | `filter input` | block LAN → proxy ports; allow only core-veth sources to the chokepoints; keep loopback services private |
| `fwd_filter` | `filter forward` | **default drop** so containers/VMs cannot bypass `OUTPUT`-only policy |
| `pre_nat` | `nat prerouting` | only if the benchmarked TPROXY variant is adopted; not needed for the route-less namespace |

**Sharp edges that must be handled explicitly:**

- **`REDIRECT` in `nat output` rewrites the destination to loopback** for locally generated packets
  (that is why Tor's default loopback binding works). For *forwarded* traffic `REDIRECT` behaves
  differently (it uses the ingress address), which is one reason forwarded namespaces use a netns-
  local DNAT to a host-local address instead.
- `ACCEPT` in our chain is **not** final across tables. A third-party firewall can still drop traffic
  *after* we accept, and can drop the redirected flows. Fail-closed, but it looks like "Tor is
  broken". `core` must detect `firewalld`/`ufw`/`docker` and either state a compatibility warning or
  offer a documented, reversible compatibility rule.
- Interface-agnostic rules are mandatory: match on `skuid`, protocol, port, and address sets — not on
  `oifname`. This survives Wi-Fi↔Ethernet switches and VPN bring-up without re-application, and (see
  §7.7) it also defeats userspace-NAT escape attempts.
- Allow DHCP explicitly (`udp dport 68`) so the link does not die, and count it so it is visible.

### 7.3 Exemptions — the whole list, always visible

| Exemption | Scope | Why it is necessary | Risk if abused |
|---|---|---|---|
| `skuid tor` (all) | Outbound TCP/53 to relays/authorities/DNSPort consumers | Tor cannot bootstrap without a direct path | A compromised Tor = unrestricted egress. Mitigate with Tor's own sandbox, dedicated uid, no extra services on that uid |
| DHCP (`udp dport 68`) | Outbound | Link maintenance | Reveals presence on the LAN (already known) |
| `dnscrypt-proxy` uid → 53/853/443 | Clearnet/DNS-lockdown only | Its resolution path | None in Tor modes: it is not started/its uid is not exempted there |
| `dnscrypt-proxy` uid → Tor SOCKS only | Advanced "authenticated DNS over Tor" | Its resolution path | Prevents the real-IP DNS leak; failure = DNS stops |
| LAN/loopback exception | Per-app, opt-in | Printers, discovery, dev servers, localhost services | Reveals you to the LAN only; never enables clearnet |

There is **no** exemption for: the GUI, `core`, `verify`, the updater, or any user uid. "The app
needs it" is not a reason — `APP` scope is the answer.

### 7.4 UDP policy (DR-8)

Tor carries no UDP. Silent drops make applications hang for seconds-to-minutes and make users blame
Tor. Therefore:

- Reject UDP and ICMP with an ICMP admin-prohibited/port-unreachable verdict so QUIC, STUN, mDNS, and
  torrent discovery fail in milliseconds and fall back to TCP where they can.
- Count and (optionally, in memory only) surface the blocked attempts so the user can see *what tried
  to leave*. Never persist destinations (I6).
- This is a **privacy-positive** performance optimization: it converts "silently broken" into "fast
  fallback", and it makes UDP-based leaks impossible rather than merely unlikely.

### 7.5 IPv6 (DR-9)

- `SYSTEM` scope: all IPv6 egress denied for non-Tor uids. Tor may use IPv6 for relay connections if
  the network is v6-only; destination IPv6 via Tor is unreliable because exit policies for IPv6 are
  sparse — do not promise it.
- `APP` scope: IPv6 disabled inside the namespace; there is no IPv6 route to leak.
- Do not disable IPv6 on the physical interface by default (it breaks LAN v6 and other users). Only
  offer it as an explicit "strict mode" that is journaled and restored.
- Reason for the asymmetry: a firewall rule can be flushed or forgotten; an absent route cannot.

### 7.6 LAN, DHCP, and inbound

- LAN egress: default **off**. A toggle enables the RFC1918/link-local set for the selected scope, and
  the UI says plainly: "apps can reach your local network; local devices can be identified."
- Inbound: our policy is egress-centric. Inbound SSH/shares from the LAN remain reachable unless the
  user enables "no inbound", which is a *de-anonymization* control more than a privacy one. State it.
- mDNS/SSDP/NetBIOS: part of the LAN set; blocked by default.
- Captive portals: a first-class "relax for portal" flow (§8.7).

### 7.7 Escapes and bypasses the design must survive

| Escape attempt | Why it fails | Residual |
|---|---|---|
| App opens a raw `AF_INET` socket | Raw IP still traverses netfilter; uid/proto rules apply | — |
| App creates a user+net namespace and runs a userspace NAT (slirp4netns/pasta) | The NAT engine's sockets live in the **host** netns and carry the user's uid, so transport-based policy still catches them | If the escape helper runs as root or with `CAP_NET_ADMIN`, it wins — root is out of scope |
| App uses `AF_PACKET` | Requires `CAP_NET_RAW`; bypasses netfilter entirely | **Audit for `CAP_NET_RAW` file capabilities** and warn. Do not grant it |
| App uses `SO_BINDTODEVICE`, `SO_MARK` | Our rules do not match on interface; a user cannot set arbitrary marks without `CAP_NET_ADMIN` | — |
| Container/VM traffic | `OUTPUT`-only rules do not see it | `fwd_filter` default-deny |
| Setuid/root-created socket | `sk_uid` is the *creating* identity, so a root-created socket is not exempted (and a privileged-dropped process keeps its pre-drop socket identity) | Design rule: never create sockets before dropping privileges |
| System resolver ignores our DNS | Policy is on port 53 egress, not on `resolv.conf` | — |

---

## 8. DNS strategy

### 8.1 Policy by mode (DR-10)

| Mode | Resolver path | Authenticated | Rationale |
|---|---|---|---|
| `CLEARNET` + `DNS` | `dnscrypt-proxy`, preferring ODoH or anonymized DNSCrypt relays; DNSSEC hard-fail; `require_nolog`/`require_nofilter` server selection | Yes | Hides names from ISP/local net; keeps IP off the authoritative resolver where possible |
| `TOR` (any scope) | Chokepoint → Tor `DNSPort` | **No** | Resolved inside Tor by an exit; nothing local links your identity to the query; queries and TCP land on different circuits |
| `TOR` + advanced toggle | Chokepoint → `dnscrypt-proxy` → **Tor SOCKS only**, egress firewalled to the SOCKS port | Yes | For users who do not trust exit DNS; slower and slightly more fingerprintable |
| `I2P` | No DNS for `.i2p`/`.b32.i2p`; clearnet names not resolved inside I2P | N/A | I2P names are resolved by i2pd, not DNS |

### 8.2 Why `DNSPort` is the default in Tor modes

- The query travels inside Tor; no local party can associate the name with you.
- The resolving exit is not the exit carrying your TCP (different circuits), so a single exit rarely
  sees both the name and the destination.
- Zero extra moving parts, and the firewall can make clearnet DNS impossible.

### 8.3 Why not "DNSCrypt plus DNSPort"

Two resolvers, two answer sets, two log surfaces, and a race. It cannot be more private; it can only
be more confusing.

### 8.4 The honest cost of `DNSPort`

Answers are only as trustworthy as the exit: an exit can lie, NXDOMAIN-hijack, or return a poisoned
address. That is a real weakness, and it is the reason the authenticated-DNS-over-Tor option exists.
Present the tradeoff, do not hide it. Also note the second effect: exit resolvers can be
geographically odd, so CDNs may hand you distant addresses — this looks like "Ghostnector is slow"
and must be visible in diagnostics as a resolution-quality signal.

### 8.5 DNS as a side channel

Even encrypted, query timing and volume correlate with activity. Mitigations that are worth having:
keep DNS inside the same anonymity set (Tor), keep the local cache in RAM, do not write logs, and do
not add a *new* resolver identity ("this user always asks X") visible outside Tor. Explicitly reject
the idea that layering a second encrypted DNS hop *outside* Tor improves anything — it re-introduces
your real IP and adds a stable, identifiable resolver relationship.

### 8.6 Resolver-layer ownership (a real-world mess, so handle all three cases)

| Environment | Strategy | Restore |
|---|---|---|
| systemd-resolved present | Cooperate: set the per-link DNS to the chokepoint with a routing domain, leave `127.0.0.53` intact; `resolvectl revert` on disconnect | Exactly reversible, no file edits |
| NetworkManager with own DNS handling | Either tell NM to stop managing DNS for the active connection (journaled), or replace `/etc/resolv.conf` with a journaled backup + hash | Hash-compare before restoring; refuse to clobber concurrent edits |
| Static `/etc/resolv.conf` | Rewrite with a backup, or better, bind-mount the chokepoint file read-only over it for the duration | Unmount restores the original exactly |

Regardless of strategy: **port-53 egress is blocked at the kernel**, so a resolver misconfiguration
can never become a leak — it can only become breakage.

### 8.7 Captive portals

Default-deny breaks captive portals, and users will then disable the firewall by hand (which is worse
than a controlled exception). Provide a first-class flow: detect the portal, show it, and offer
"relax protection for this network" which:
1. switches to a clearly-labeled transient state (`BLOCKED`-lite with clearnet DNS + HTTP/HTTPS to the
   detected portal only),
2. auto-relocks when connectivity check succeeds (or after a short timeout),
3. never remains active across a reboot,
4. is logged in the journal as a user-visible event.

---

## 9. Tor integration strategy

### 9.1 Port and role layout

| Listener | Binding | Consumers | Notes |
|---|---|---|---|
| `TransPort` | loopback address distinct from the system's (e.g. `127.0.0.7`) and/or the core namespace address | Redirected local TCP; DNAT'ed namespace TCP | Never a wildcard bind in `SYSTEM` scope unless `in_filter` blocks LAN access |
| `DNSPort` | same loopback family | Chokepoint | Accepts UDP and TCP (verify on your Tor version; if TCP is unsupported, keep the TCP redirect so it fails closed) |
| `SOCKSPort` | loopback | Apps that want per-destination isolation, browsers via PAC, the advanced DNS feature | `IsolateSOCKSAuth` enabled; credential-per-profile from the GUI |
| Control port | loopback, cookie auth, `core`-readable cookie only | Health/stats | Never exposed; never used by the GUI |
| Onion-service, relay, exit, bridge-relay | **off** | — | Separate future feature with its own consent flow; running an exit from a privacy appliance is a bad default |

### 9.2 Loop prevention and bootstrap

- Tor's own egress is exempt by `skuid`; the exemption is ordered before the redirect rules.
- The redirect rules must not capture the proxy ports themselves (a rule that redirects traffic
  *to* `127.0.0.7:9040` back into `TransPort` is a loop). Bound the redirect by "not already destined
  to the loopback proxy address", and keep the loopback shortcut before it.
- Bootstrap ordering is the security property (§4 D5): deny first, then bootstrap, then open.
- `--verify-config` before start; rollback on non-100% bootstrap with a timeout; never a "connect
  anyway" path.

### 9.3 Per-app isolation, precisely

- Host-wide `REDIRECT` ⇒ Tor sees one Application Address ⇒ one circuit pool for everything. Two apps
  with the same address are *not* isolated by Tor's design.
- `APP` scope ⇒ distinct namespace source address per app ⇒ distinct isolation profile ⇒ distinct
  circuits, with the added benefit that the isolation survives even if an app ignores proxy settings.
- Do **not** masquerade namespace traffic on the host side; NAT would collapse the source addresses
  back to one identity and silently destroy the isolation (this is a one-line change with a large
  privacy consequence, so it belongs in the invariants).
- Apps that support SOCKS should still be pointed at their own `SOCKSPort` credential where the user
  wants finer-than-app isolation (per-account, per-session), because application tokens are the only
  *strong* isolation property Tor has.
- Long-lived isolation groups should use keep-alive credentials so the useful circuit is not torn down
  by circuit rotation.

### 9.4 Bridges and pluggable transports

- Off by default; enabled when the network blocks Tor (preflight test in the UI), or by user choice.
- obfs4: small latency cost, good resistance; snowflake (WebRTC-based) and meek: much higher latency,
  last resort.
- Bridge lines are secrets: root-owned file/credential, never logged, excluded from GUI diagnostics.
- Do not fetch bridges over clearnet from the GUI. Fetch through Tor, or accept manual entry.

### 9.5 Traffic that must not be presented as "supported"

Tor cannot carry (or should not carry) the following. The UI must say this, and the firewall should
make the failure fast rather than mysterious:

- **All UDP**: QUIC/HTTP3, DNS-over-UDP (except `DNSPort`), STUN/WebRTC, torrent DHT/uTP, VoIP/RTC,
  NTP, mDNS/SSDP, WireGuard/IPsec.
- **Non-TCP/ICMP-dependent**: ping, traceroute, PMTU discovery signals, anything that relies on ICMP.
- **Inbound connections**: hosting, P2P servers, remote access. Onion services are the only clean
  answer, and they are a separate feature.
- **Real-time**: anything interactive that needs sub-second RTT.
- **Protocols that leak at the application layer regardless of path**: BitTorrent peer IDs/DHT, and
  any app that sends a stable device/account identifier.
- **Cleartext protocols**: an exit reads and can modify them.
- **Ports exits commonly reject**: a set of well-known ports is rejected by default on many exits,
  plus operator-specific rejections. Provide a preflight "port reachability through the chosen chain"
  check so users discover a restrictive exit before they blame Ghostnector.
- **Anything where the destination treats your IP as your identity** (IP-bound sessions, IP-based
  auth, geo-gating): Tor changes the exit's IP on every circuit; these will appear broken.

### 9.6 Other Tor-side decisions

- Keep connection padding at defaults; disabling it for speed is privacy-negative and must not be a
  user-facing optimization.
- Keep circuit dirtiness at defaults by default. Per-app isolation gives the isolation benefits
  without the "new circuit per destination" cost; offer per-destination isolation as an explicit,
  explained choice for high-sensitivity apps, not a global default.
- Do not pin exit countries by default: it shrinks the anonymity set and creates a distinctive
  selection. Offer it only for a stated usability need, with a warning.
- Enable Tor's own sandbox if the platform supports it; run it as a dedicated static user; keep the
  data directory `0700`; disable all log levels that could record destinations.
- Expose only aggregate health (bootstrap %, circuit count, bytes in/out, guard presence) via the
  control port. Never render circuit-level detail in the GUI by default — it is sensitive and it
  teaches users to fingerprint themselves.
- One Tor instance. Multiple instances multiply guards, memory, and your distinctiveness on the
  network with no isolation benefit over namespaces.

---

## 10. I2P integration strategy

**Decision (DR-11):** I2P is an independent destination network, isolated in its own namespace,
disabled by default, client-only, with no clearnet outproxy and no Tor chaining in either direction.

**Reason:** I2P hides your identity from *destinations* through garlic routing and tunnel pairs, but
**I2P peers see your IP** — you are a participant, not a client of a proxy. It is a different
anonymity model serving a different destination universe. Tor↔I2P bridges add latency, create new
linkages, and (for the I2P→Tor direction) make you an outproxy operator.

**Privacy impact:** keeps the I2P identity and the Tor identity in separate compartments; prevents
accidental attribution of I2P activity to a Tor circuit and vice versa. **Performance impact:**
positive by default (i2pd off unless needed; client-only means no transit traffic). **Failure
behavior:** i2pd down = I2P destinations unreachable; nothing else changes; no fallback to anything.

Design specifics:

- Run `i2pd` as a dedicated static user inside its own namespace, with NTCP2/SSU2 peers reachable
  directly (this is the one component whose clearnet presence is inherent and must be stated in the
  UI: "I2P exposes this machine's IP to I2P peers").
- **Client-only**: disable transit tunnels. Users who want to contribute bandwidth can opt in
  explicitly (with a warning about the IP exposure and the abuse/liability implications).
- **No outproxy.** Clearnet names simply fail inside I2P. If a user wants clearnet through I2P, the
  honest answer is "that is not what I2P is for; use Tor".
- Expose only the proxy listeners (HTTP/SOCKS/SAM) to the host, and only to the host — the I2P
  namespace has its own egress and never participates in Tor's policy.
- Integrate with apps via explicit proxy configuration (a browser profile or PAC rule sending
  `.i2p`/`.b32.i2p` to the I2P SOCKS listener and everything else to Tor). This is both
  privacy-positive (correct network per destination, clean separation) and performance-positive
  (no wasteful double proxying).
- **Interaction with Tor `SYSTEM` scope:** if Tor scope is `SYSTEM` and I2P is enabled, i2pd must not
  be given a host-level exemption; keep it in its own namespace (or fall back to a uid exemption only
  if the namespace is unavailable, which is strictly weaker and must be labeled as such). Even in the
  correct design, the ISP sees both Tor and I2P traffic on the same access line — that is unavoidable
  and must be disclosed; Ghostnector cannot decouple them.
- Battery/CPU: i2pd is the heaviest component. Do not auto-start it; do not leave it running for
  hours idle; show its resource cost.
- If `SYSTEM` Tor scope is active and the user turns I2P off, remove the namespace entirely; do not
  leave listeners behind.

---

## 11. Fail-closed / kill-switch design

### 11.1 The principle: the kill switch is an absence, not a rule

Two layers, and the stronger one does not depend on rules being present and correct:

1. **Structural (APP scope):** no route, no IPv6, no multicast. A flushed rule cannot create a path.
2. **Policy (SYSTEM/USER scope):** explicit default-deny with a short, enumerated allow list, applied
   atomically, living in the kernel independent of any daemon.

### 11.2 Deny-first bootstrap

Order matters more than content: the fail-closed baseline is applied **before** any service starts,
and the redirects are opened only after Tor reaches bootstrap 100% and the resolver layer is
committed. The alternative order (open, then protect) has a window; we do not ship windows (I7).

### 11.3 Behavior for each failure (summary; full matrix in §15)

| Failure | Effect on enforcement | Result |
|---|---|---|
| Tor dies | Rules remain; the redirect target is a dead port | `BLOCKED`; new connections fail; nothing reaches clearnet |
| DNSCrypt dies | Only relevant in clearnet/DNS mode; egress already restricted to its resolvers | Resolution fails (`DEGRADED`/`BLOCKED` in DNS mode); no leak |
| i2pd dies | Independent namespace | I2P unreachable; other modes unaffected |
| GUI crashes | GUI holds no policy | **No effect** (by design) |
| `core` crashes | `core` holds no policy | Enforcement persists; systemd restarts `core`; state is re-derived from the kernel + journal |
| `netd` crashes | Rules persist | Restart; if restart fails, stay in current state and alarm |
| Ruleset apply fails | Previous generation intact (atomic) | Connect aborts, rollback to baseline (protection never existed) |
| `forward`/conntrack flush | n/a | Containers lose connectivity before they can leak |
| Interface changes | Rules are interface-agnostic | Re-assert idempotently; recompute the LAN set |
| Suspend/resume | Rules persist; routes may change | Re-verify; if Tor cannot reconnect → `BLOCKED` |
| Reboot | Nothing in the kernel persists | `boot-guard` re-applies the fail-closed baseline if intent=protected |
| Verification fails | — | Escalate to `BLOCKED` + user-visible alarm, never to clearnet |

### 11.4 Rollback rules (DR-15)

- Rollback to the captured baseline is allowed **only** when protection was never established
  (a failed Connect). The user asked for protection and did not get it; returning them to their own
  prior state is correct and honest.
- Once `PROTECTED` or `DEGRADED` has been reached, no automatic path to clearnet exists. Recovery is
  an explicit user action, with a warning and a verification pass.
- `BLOCKED` is a first-class UI state with a reason, a timestamp, and a "recover" action — not an
  error dialog.

### 11.5 Panic and boot

- A "Block now" action applies the deny-all baseline without touching services, for incidents.
- `boot-guard` runs early (before any application can send), re-applies the baseline if
  `intent=protected`, and only then lets `core` proceed to re-establish the full protected state.
- Recovery from a broken protected boot must be documented and local: a kernel command-line flag, a
  console-accessible `ghostnector recover` action, and a systemd unit that can be masked. Do not
  invent a recovery path that requires the network.

---

## 12. State restoration strategy

### 12.1 Own only what you create

| We create | We never touch |
|---|---|
| `inet ghostnector` table and its chains/sets | `filter`/`nat`/`mangle`/`raw` tables, `firewalld`, `ufw`, `docker`, `libvirt` |
| Policy routes/rules with our own table id and mark | The user's routes in `main`, `local`, VPN tables |
| Namespaces + veths we create | Interfaces we did not create |
| Journaled resolver-layer changes | Unrelated NetworkManager/systemd-resolved configuration |
| Journaled sysctl writes | Any other sysctl |

Consequence: "Disconnect" is **delete our objects**, not "reset networking" (I5).

### 12.2 Baseline capture

Before any change, capture with a content hash: routing tables and rules, interface list and
addresses, `resolv.conf` content and whether it is a symlink and to what, resolved/NM DNS state,
every sysctl key we might write with its current value, the set of nftables tables present, and
whether third-party firewalls are active. Store in the journal, `fsync`ed, with the intent flag.

### 12.3 Journal semantics

Write-ahead: record the intended change and its inverse **before** applying it. Each entry has the
owner, the operation, the inverse, the pre-state hash, and a monotonically increasing sequence
number. On any abnormal termination, `core` reconstructs actual state from the kernel (by querying
nftables/routes/netns) rather than trusting the journal — the journal is an *intent* record, the
kernel is the *truth*.

### 12.4 Apply / revert

- `assert(desired_state)` is idempotent and converges from any partial state (I4). It computes a
  diff between observed and desired and applies it in one atomic batch.
- `revert()` removes our objects only; then, if the resolver layer was changed, restores from the
  journal **only if** the current content hash matches what we captured (no clobbering concurrent
  edits) — otherwise it reports a conflict and leaves the system resolver pinned to the chokepoint
  with a warning. Conservative default: never guess.
- A "foreign object changed" detector re-checks a hash of third-party firewall/route state after
  Connect and warns if something else modified networking while we were active (this is the case that
  makes naive restores dangerous).

### 12.5 Reboot

Kernel state is volatile by definition, so the design must not depend on it surviving. Persist
`intent=protected`, the mode/scope, and the exemption set. On boot: `boot-guard` applies the baseline,
then `core` attempts full re-establishment, and if it cannot, the host stays `BLOCKED` with a visible
reason. Never silently boot into clearnet while the user believes they are protected (DR-16).

### 12.6 Uninstall

Provide an explicit uninstall that runs `revert()`, deletes our tables/namespaces, restores the
resolver layer, removes the boot-guard unit, and verifies the network is exactly as captured. If the
journal is unavailable, the fallback is: delete named Ghostnector objects, restore only the resolver
file if a backup exists, and report what could not be restored.

---

## 13. Performance: where the cost is, and which optimizations are legitimate

### 13.1 Where degradation actually comes from

| Source | Typical magnitude | Class of the cost | Notes |
|---|---|---|---|
| Tor circuit RTT (3 hops + queueing) | +0.15–0.6 s typical; more with bad middle relays | Inherent to Tor | The dominant latency term for interactive use |
| Tor throughput | often single-digit to low-tens Mbps; highly variable | Inherent | Bottleneck is usually the slowest relay or exit, not your link |
| Circuit build (cold) | ~1–3 s | Inherent, amortized | Warm circuits and keep-alive isolation tokens hide most of it |
| Per-app isolation | one circuit set per identity group | Privacy-positive | New group = cold start; the price of unlinkability |
| DNS over Tor | +0.3–1.5 s uncached | Inherent to doing DNS inside Tor | RAM cache + browser cache make repeats negligible |
| DNSCrypt on clearnet | +20–60 ms uncached | Small | Compare against plaintext ISP DNS only for reference |
| DNSCrypt over Tor | +0.5–2 s uncached | Privacy-positive but expensive | Only for users who do not trust exit DNS |
| Firewall (nftables with sets/maps) | microseconds | Negligible | Do not use long linear rule chains |
| Userspace forwarding (TUN/relay) | 20–50% throughput, real CPU cost | **Avoidable** | Rejected for v1 |
| I2P | seconds of latency; low throughput | Inherent | Off by default; the heaviest battery cost |
| Blocked QUIC with fast reject | turns 1–30 s hangs into ~0 ms fallback | **Net win** | Privacy-positive and performance-positive |
| Double encapsulation (VPN inside Tor, Tor inside VPN) | one extra RTT + reduced MTU + reduced exit choice | Mostly avoidable | Offer only as explained tradeoffs |

### 13.2 Safe optimizations (and their classification)

| Optimization | Class | Why it is legitimate |
|---|---|---|
| Kernel-path redirect instead of userspace forwarding | Privacy-neutral | Same anonymity, less copying |
| Atomic single-batch rulesets with sets/maps | Privacy-neutral | Fewer, shorter chains; no window |
| Fast-reject UDP/QUIC so apps fall back | Privacy-**positive** | Removes silent blackholing; avoids users disabling protections |
| RAM-only DNS cache with sane TTL caps | Privacy-neutral (if never persisted) | Removes repeated Tor DNS cost |
| Warm circuits + SOCKS keep-alive for long-lived identity groups | Privacy-neutral | Isolation semantics unchanged |
| Per-app isolation (namespaces, source-address preservation) | Privacy-positive | More circuits, more unlinkability; cost is honest |
| One Tor instance for all scopes | Privacy-neutral | Avoids multiplying guards and network footprint |
| Client-only i2pd, started on demand | Privacy-neutral | No transit duty, no idle cost |
| Radius/interface-agnostic rules (no re-application storms) | Privacy-neutral | Stability, not speed |
| Browser PAC: `.i2p`→I2P proxy, else Tor SOCKS | Privacy-positive | Correct routing per destination, no double proxying |

### 13.3 Optimizations that must be refused

| Tempting "optimization" | Why it is refused |
|---|---|
| Disabling Tor connection padding | Reduces traffic-analysis resistance for a marginal bandwidth gain |
| Pinning exits to one country/ASN for speed | Shrinks the anonymity set; creates a signature |
| Per-destination isolation off "because it is slow" | Changes the threat model silently |
| Running traffic unprotected for "speed-sensitive" apps | Defeats the product |
| VPN-over-Tor for the Tor path | Adds a hop, weakens the anonymity argument, no latency benefit |
| Auto-fallback to clearnet on any error | Catastrophic and exactly what the product exists to prevent |
| Multiple Tor instances for "speed" | More guards, more memory, more distinctiveness, same throughput |

### 13.4 Measurement plan

Define metrics and gates **relative to the Tor baseline**, not to clearnet (clearnet comparison is
meaningless for an anonymity tool): cold/warm connect time, TTFB percentiles for a fixed site set,
DNS p50/p95 cached and uncached, single- and four-stream throughput, exit-country distribution,
failure rate per 100 requests, CPU/battery cost per hour, and memory per daemon. Compare:
`SYSTEM` redirect vs `TPROXY` vs TUN forwarder; `DNSPort` vs authenticated-DNS-over-Tor; one Tor vs
per-app namespaces; with/without NAT on the namespace boundary (to prove the isolation claim has no
hidden cost — it should be a source-address change, nothing more). Publish the numbers in the repo so
performance claims stay honest.

---

## 14. Leak-testing methodology

### 14.1 The principle

**Assert on packets observed at the boundary, not on application-level outcomes.** A test that says
"curl returned 200" proves nothing about where the packet went. Every test must observe the external
side (a fake ISP, a fake destination, a canary authorititative server) and assert on what it saw.

### 14.2 Hermetic harness (CI-friendly, no internet required)

- A private Tor network (Tor's `chutney`) as the "Tor" side, so tests do not depend on the public
  network and can be run offline.
- An "ISP" namespace with: a recording resolver, a recording HTTP server, a packet capture on the
  link, and an IPv6 router advertising prefixes.
- A "destination" namespace reachable only through the private Tor network's exits.
- A canary authoritative zone whose queries are logged with the querying source address.
- The system under test in a third namespace, with Ghostnector installed exactly as in production.

### 14.3 Test matrix

| Area | Test | Pass criterion |
|---|---|---|
| Public IPv4 | Request an IP-echo endpoint through the protected scope | Echoes the exit, never the ISP address |
| Public IPv6 | Same over v6, and a raw v6 connect attempt | Fails; ISP never sees a v6 packet from a protected uid |
| DNS | Resolve canary names in every mode | ISP resolver never receives them; Tor mode queries appear only at the exit |
| DNS integrity | Forged/negative responses from a hostile resolver | Rejected or surfaced; never silently trusted in authenticated modes |
| UDP | Send UDP to a recording server | Rejected instantly; nothing recorded at the ISP |
| QUIC | Use a QUIC-only client | Falls back or fails fast; no UDP 443 reaches the ISP |
| WebRTC | Browser ICE attempt | No STUN/TURN directly from the host; document app-layer limits |
| Routing | Inspect routes/rules pre/post | Our objects only; baseline untouched; no stale routes |
| Firewall bypass | User-namespace + userspace-NAT escape attempt | Egress still captured by transport policy |
| Capability bypass | Grant a test binary `CAP_NET_RAW`, attempt `AF_PACKET` | Detected by the audit and reported as a warning |
| Forward path | Start a container/VM and attempt egress | Blocked by `forward` default-deny |
| Service crash | `SIGKILL` tor/dnscrypt/i2pd/core/netd | No clearnet packet ever appears at the ISP |
| Interface change | Move the test link between two networks | Policy survives; LAN set recomputed; no leak window |
| Suspend/resume | Simulate suspend | Re-verification runs; state is `BLOCKED` or `PROTECTED`, never silently clearnet |
| Reboot | Reboot with intent=protected | Baseline applied before any app traffic; no leak |
| Races | Loop connect/disconnect while a background traffic storm runs | **Zero** clearnet packets at the ISP for the whole run |
| Transition | Kill during `APPLYING` at each step | Rollback completes, or the system ends `BLOCKED`; never half-open |
| Foreign change | Flush/modify third-party firewall state mid-session | Detection + alarm; no silent unprotected window |
| Partial apply | Inject a `netd` failure at each batch boundary | Previous generation intact; state reported accurately |

### 14.4 External vantage (release gate, not CI)

A small rented VPS or a collaborator's host that runs: an IP-echo endpoint, a packet counter, and the
canary authoritative DNS server. Tests assert that (a) the echo sees a Tor exit, (b) the canary's ISP
resolver never sees the client's queries, (c) no direct connection from the client's real IP appears
during a protection session. This is the only way to test the ISP/local-network adversaries (A1–A3)
end to end.

### 14.5 Continuous in-product verification (DR-18)

`ghostnector-verify` runs inside the protected set and periodically attempts: a direct clearnet
connection (must fail), an IP-echo lookup through Tor (must return a non-ISP address), and a canary
resolution (must not appear at the clearnet resolver). A *successful* direct connection is the alarm,
not a test failure — it escalates to `BLOCKED` immediately. Keep the verification's own traffic
minimal and avoid a fixed, recognizable fingerprint (randomize endpoints, keep the request shape
ordinary).

### 14.6 Honest reporting in the UI

Four states with explicit criteria; never "Anonymous":
`PROTECTED` (asserts pass, verification fresh) · `DEGRADED` (asserts pass, verification stale/unavailable
or an optional service down) · `BLOCKED` (fail-closed active, with reason) · `OFF`. Show the evidence
and the exemption list, and a "what this does not protect against" section (§1.3) reachable from the
main screen.

---

## 15. Failure scenarios and expected behavior

| Event | Immediate effect | Enforced behavior | State shown |
|---|---|---|---|
| Tor exits/`SIGKILL` | TransPort/DNSPort gone | Redirects remain → connections fail; no clearnet path | `BLOCKED` with reason |
| Tor cannot bootstrap (blocked network) | No relays reachable | Connect aborts, rollback to baseline | `OFF` + actionable hint (bridges) |
| DNSCrypt dies (clearnet/DNS mode) | Resolution stops | Egress already limited to its resolvers | `DEGRADED`/`BLOCKED` |
| i2pd dies | I2P offline | Nothing else changes | `DEGRADED` (I2P tile) |
| GUI crashes | Nothing | Policy untouched | unchanged |
| `core` crashes | Health/orchestration stops | Policy untouched; unit restarts; state re-derived | unchanged, then reconciled |
| `netd` crashes | Cannot change policy | Policy untouched; restart; alarm if it cannot restart | `DEGRADED` |
| nftables apply fails | Old generation intact | Connect aborts → rollback | `OFF` + error |
| Partial `Connect` | Intermediate | Rollback (protection never established) | `OFF` |
| Partial `Disconnect` | Intermediate | Re-assert `revert()` idempotently; report leftovers | `OFF` + report |
| Wi-Fi → Ethernet | Interface/route change | Interface-agnostic rules persist; LAN set recomputed; re-verify | `PROTECTED` after re-verify |
| New interface/route appears (VPN, tethering) | New paths possible | Still inside our policy; forwarded/VPN traffic hits the deny rules | unchanged + event logged |
| VPN brought up by the user | New default route | Tor keeps its exemption and runs over the VPN (if chosen); app TCP still redirects to Tor; VPN's own UDP gets rejected | `DEGRADED` note about chaining |
| Suspend/resume | Sockets and state stale | Rules persist; re-verify; reconnect Tor if needed | `BLOCKED` if Tor cannot return |
| Reboot (intent=protected) | Kernel state gone | `boot-guard` deny-all before apps start; Tor reconnects; else stay blocked | `BLOCKED`/`PROTECTED` |
| Reboot (intent=off) | n/a | Nothing applied | `OFF` |
| Resolver manager rewrites `resolv.conf` | Stub bypassed | Port-53 egress is still kernel-blocked → breakage, not leak | `DEGRADED` |
| Captive portal | All egress denied | Portal flow offers a labeled, transient relax | `PORTAL` |
| Disk full (journal) | Cannot write state | Refuse to change state; keep enforcement | `DEGRADED` |
| Clock skew | TLS failures | No time-dependent policy | `DEGRADED` |
| Container/VM starts | Forward traffic | Forward chain default-deny | unchanged |
| Another user logs in | Their traffic | `SYSTEM`: covered; `USER`: not covered | unchanged + documented |
| Binary with `CAP_NET_RAW` appears | Possible `AF_PACKET` bypass | Audit flags it; recommend removal; strict mode refuses to claim `PROTECTED` | `DEGRADED` |
| Tor exit rejects the port | App connection fails | No fallback to clearnet | `PROTECTED` + app-level error explained |
| IPv6 RA arrives | v6 route appears | v6 egress denied for protected uids | unchanged |
| Ghostnector updated mid-session | Binaries change | No policy change until an explicit re-apply; version skew is a hard failure | unchanged |
| Power loss | Everything volatile | Reboot path applies | `BLOCKED`/`PROTECTED` |

---

## 16. Alternative architectures worth benchmarking

| # | Alternative | Hypothesis | Why it might lose | How to decide | Ship in v1? |
|---|---|---|---|---|---|
| B1 | TPROXY instead of `REDIRECT` for host traffic | Uniform treatment of local + forwarded traffic | Extra policy-routing rules; no benefit for local-only; more state to restore | Latency/throughput parity is expected; then choose the one with less state | No |
| B2 | TUN + userspace forwarder (tun2socks/`sing-box`-style) | Complete capture of UDP/QUIC; one uniform path | Userspace TCP stack, MTU/MSS pathologies, CPU cost, larger attack surface, still no UDP anonymity | Measure throughput and p95 latency vs kernel redirect; only worth it if a UDP *policy* benefit appears that cannot be had otherwise | No |
| B3 | Per-app namespaces (chosen) vs uid-based `USER` scope | Stronger structural guarantees, real per-app isolation | Extra capability (`CAP_SYS_ADMIN`), launcher UX, LAN/inbound breakage | Compare leak-test results; namespaces should win on every structural test | **Yes** (as the high-assurance mode) |
| B4 | Whonix-style split VM (gateway + workstation) | Kernel-level isolation, no host-kernel leaks, strongest practical desktop model | Heavy, needs virtualization, very different product | Use as the reference point for "what we cannot achieve on one host"; document the gap | No (document as recommended for the highest-risk users) |
| B5 | Tor over VPN by default | Hides Tor usage from the ISP; helps where Tor is blocked | Adds a party, adds latency, shifts trust to the VPN; may reduce exit choice | Only as an explicit user choice, benchmarked; never default | No |
| B6 | ODoH / anonymized DNSCrypt vs plain DNSCrypt/DoH (clearnet mode) | Removes resolver-IP linkage | Fewer relays; another dependency; still blockable by IP | Measure failure rates and latency; prefer if stable | Yes (prefer where available) |
| B7 | Authenticated DNS over Tor (`dnscrypt-proxy` over SOCKS) | Defense against malicious exit DNS | 2× latency for resolution; config-sensitive; must be firewalled to the SOCKS port | Provide as advanced mode; measure cache hit rates; ensure hard failure if the SOCKS path breaks | Optional |
| B8 | Arti (Rust Tor) as the client | Memory safety, cleaner embedding | Feature parity gaps for transparent proxying and control-port monitoring | Re-evaluate annually; do not block v1 | No |
| B9 | eBPF cgroup egress allowlists in addition to nftables | Second, independent enforcement attached to app cgroups; survives rule flushes | Complexity; per-cgroup plumbing; only covers cgroup members | Add as defense-in-depth for `APP` scope if complexity budget allows | Later |
| B10 | Full host firewall by default (`SYSTEM`) vs "only what you launch" | Coverage of everything vs zero surprise | `SYSTEM` breaks containers/VMs by design | Default to `SYSTEM` for Connect; make `APP` the high-assurance alternative | `SYSTEM` yes |
| B11 | Port-based exemptions (allow the DNS port) vs uid exemptions | Simpler rules | Port exemptions are exploitable by any process | Never port-exempt unless uid-scoped | No |
| B12 | Per-user `nftables` `socket cgroupv2` matching instead of uid | Robust to uid reuse; works per slice | Requires cgroup v2 + matcher support; more coupling to systemd | Prefer cgroups for `APP`-like grouping if uid matching proves brittle | Later |

---

## 17. Final recommended prototype architecture

### 17.1 v1 scope ("Foundation") — ship this first

**Modes:** `DNS` lockdown (clearnet, encrypted DNS) and `TOR` + `SYSTEM` scope. Fail-closed baseline,
deny-first bootstrap, `DNSPort` for DNS, `TransPort` for TCP, UDP/ICMP fast-reject, IPv6 denied,
`forward` default-deny, boot-guard, journal + idempotent assert/revert, panic button, continuous
verification, privilege split (GUI / core / netd), no root, static uids, polkit for sensitive
transitions, honest UI states.

**Explicitly not in v1:** I2P, `APP` namespaces, bridges UI, authenticated DNS over Tor, TUN
variants, onion-service hosting, relays/exits, VPN integration, multi-host routing.

### 17.2 Build order (each milestone independently testable)

1. **Policy engine:** nftables profiles rendered and applied atomically by `netd`, with `revert()` and
   the deny-all baseline. Test: apply/revert/fault-inject; no leftovers.
2. **Journal + state machine** in `core`, plus `assert()` idempotency. Test: kill at every boundary.
3. **Tor integration:** TransPort/DNSPort, deny-first bootstrap, loop prevention, health.
4. **Resolver-layer ownership** across systemd-resolved / NetworkManager / static.
5. **Verification** (`APP`-style independent probes + canary) and the UI states.
6. **Boot-guard** + recovery path.
7. **Hermetic leak-test harness** (chutney + fake ISP) wired into CI.
8. **External vantage tests** as the release gate.

### 17.3 Acceptance gates

- Every invariant in §1.3 has at least one automated test; the race, crash, reboot, and interface-
  change tests must show **zero** clearnet packets at the fake ISP.
- Benchmark gates are *relative to the Tor baseline*: no architectural change may cost more than a
  defined percentage of Tor's own performance unless it buys a stated privacy property.
- The UI must never display `PROTECTED` without fresh verification evidence, and must always display
  the current exemption list and the "cannot protect against" section.

### 17.4 The one-paragraph answer

Build the smallest thing that makes leaks structurally impossible: kernel-enforced, uid- and
transport-scoped default-deny; DNS inside Tor; Tor's own traffic as the single exemption; a
privileged helper too small to be interesting; a state machine that never has a clearnet fallback
once protection exists; and a second, stronger mode — the route-less app namespace — for users who
need per-app circuit isolation and cannot tolerate a single rule being wrong. Add I2P beside it, as
its own network, with its own honest warning label. Refuse every feature that trades an anonymity
property for a benchmark number.

---

## Appendix A — Decision register

| # | Decision | Reason | Privacy impact | Performance impact | Failure behavior |
|---|---|---|---|---|---|
| DR-1 | Kernel-enforced egress policy | Survives userspace failures; no app cooperation | + | Neutral | Enforcement persists |
| DR-2 | One owned nftables table, atomic batches | No half-applied states; clean rollback | + | + | Old generation intact |
| DR-3 | Mode × scope state machine | Removes incoherent combinations | ++ | Neutral | Invalid states unrepresentable |
| DR-4 | Deny-first bootstrap | Eliminates the opening window | ++ | Neutral | Abort + rollback |
| DR-5 | Kernel redirect, no userspace forwarding | Fewer copies, no MTU pathology | Neutral | + | Fail-closed |
| DR-6 | Route-less app namespaces | Leaks impossible by construction | ++ | − (cold circuits) | No path = no leak |
| DR-7 | Preserve source addresses across veth | Recovers per-app Tor isolation | ++ | − (more circuits) | Isolation lost if NAT added — test for it |
| DR-8 | Reject UDP/ICMP instead of dropping | Fast fallback; no silent blackhole | + | + | Instant failure, counted |
| DR-9 | IPv6 denied host-wide, absent in namespaces | Dual-stack leaks are a classic failure | ++ | Neutral | v6 apps fail visibly |
| DR-10 | DNS via `DNSPort` in Tor modes | Removes real-IP DNS linkage | ++ | − (uncached) | Resolution fails, never leaks |
| DR-11 | I2P standalone, no chaining | Prevents new linkages; honest model | + | Neutral | I2P offline only |
| DR-12 | Enumerated uid exemptions, none for GUI/updater | Every exemption is a hole | ++ | Neutral | Exemptions visible |
| DR-13 | GUI / core / netd split, caps-only netd | Minimizes privileged surface | ++ | Neutral | Worst case = narrow |
| DR-14 | Enforcement independent of control plane | Daemon death ≠ leak | ++ | Neutral | Policy persists |
| DR-15 | Rollback only pre-protection | No silent clearnet return | ++ | Neutral | `BLOCKED` instead |
| DR-16 | Reboot = deny-until-verified | Volatile state must not mean unprotected | ++ | Neutral | Blocked + recovery path |
| DR-17 | Atomic policy transactions | No permissive windows | ++ | + | n/a |
| DR-18 | Verification inside the protected set | Escape attempts become alarms | ++ | − (tiny) | Escalate to `BLOCKED` |
| DR-19 | No persistent traffic metadata | Metadata is evidence | ++ | + | n/a |
| DR-20 | `forward` default-deny + capability audit | Containers/VMs and `AF_PACKET` are real bypasses | ++ | Neutral | Containers blocked by design |

## Appendix B — Mode matrix

| Scope ↓ / Network → | CLEARNET | TOR | I2P |
|---|---|---|---|
| `OFF` | all direct, no policy | — | — |
| `DNS` | encrypted DNS + port-53 lockdown | **invalid** (use a Tor scope) | I2P + encrypted clearnet DNS, both allowed, no linkage |
| `APP` | per-app DNS only | per-app route-less namespaces | apps launched into the I2P container |
| `USER` | per-user DNS only | redirect/deny scoped to one uid | I2P as a separate user-scope network |
| `SYSTEM` | system-wide encrypted DNS | system-wide transparent Tor | system-wide I2P (not recommended; explicit warning) |

## Appendix C — Open questions for you

1. **Target distros:** which resolver stack must be first-class (systemd-resolved, NetworkManager,
   plain `resolv.conf`)? The resolver-ownership design differs, and getting this wrong is the most
   common source of "it broke my network".
2. **Default scope:** should Connect default to `SYSTEM` (coverage, breaks containers/VMs by design)
   or `APP` (structural safety, requires launching apps through Ghostnector)? My recommendation:
   `SYSTEM` by default with `APP` advertised as the high-assurance mode.
3. **Multi-user:** is a second logged-in user's traffic in scope for `SYSTEM`? (I assume yes, and the
   UI must say so before enabling.)
4. **Containers/VMs:** are they a supported use case? If yes, they need their own namespaces or an
   explicit "no network while protected" statement.
5. **I2P audience:** is I2P a first-class feature or a power-user module? It changes how much UI and
   testing budget it gets.
6. **Bridges:** should Ghostnector detect Tor blocking and suggest bridges automatically, or stay
   manual to avoid a "probe the network" behavior that is itself observable?

## Appendix D — Glossary of terms used in this document

| Term | Meaning here |
|---|---|
| Application Address | Tor's isolation property equal to the source address of the connecting application; the reason host-wide redirects share circuits and namespaces do not |
| Chokepoint | The single DNS listener that the protected scopes are redirected to; forwards to `DNSPort` or to the authenticated resolver |
| Deny-first | Applying the fail-closed policy before any service starts |
| `DNSPort` / `TransPort` | Tor's DNS and transparent-proxy listeners |
| Route-less namespace | A namespace with no default route whose only reachable address is a host-local core address |
| Scope | How much of the machine is covered (`APP`, `USER`, `SYSTEM`) |
| Exemption | A uid/protocol/target that is allowed to leave the protected policy; always enumerated and visible |
| Intent | Persisted record that the user wants protection, used by the boot path |
| `BLOCKED` | Fail-closed state: no clearnet path, with reason and recovery action |
