# HANDOFF-M10 — build the Ghostnector GUI (GTK4)

This document is for a fresh agent starting milestone **M10**. It assumes no knowledge of the
conversation that produced it. Read this first, then the documents it points at. **Do not implement
M10 before its architecture questions are answered and reviewed** (see §6).

---

## 1. Current repository state

| | |
|---|---|
| HEAD | `b9499af5f3a3895c602ea1ce9388db71d7064f81` |
| Frozen release | annotated tag **`v1.0.0-rc4`** → `b9499af` (do not move it) |
| Product code | identical to `264c208` (the D-24 fix); `b9499af` adds docs and test-only scripts |
| Working tree | clean except `docs/HANDOFF-RC2.md` (historical, deliberately untracked — do not commit it) |
| Milestones | **M1–M9 done and qualified; M10 not started** |
| Language/toolchain | Rust workspace (stable), systemd units, bash test suites; Windows edit host, execution in WSL2 Ubuntu and a native Ubuntu VM |

**Test and gate counts (all green on the frozen tree):**

- **405 unit tests** across the workspace.
- **17-section release gate** (`scripts/m9-release-gate.sh`, runnable on any Linux host): fmt, check,
  clippy `-D warnings`, tests, build, then every script suite. On the native VM all 17 sections were
  `rc=0`.
- Hermetic script suites: `app-topology-test.sh`, `app-policy-test.sh`, `appd-socket-test.sh`,
  `core-app-test.sh`, `app-adversarial.sh` (13/0/0), `policy-netns-test.sh` (Tor and I2P goldens
  against the kernel), `i2p-adversarial.sh` (**26 held / 0 contradicted / 0 inconclusive**),
  `netd-socket-test.sh`, `core-cli-test.sh`, `bootguard-test.sh`, `adversarial.sh` (M1–M7:
  **26 held / 0 contradicted / 1 inconclusive** — AS-4 by design).
- **Native real-`i2pd` qualification** (`scripts/i2p-real-router-test.sh`): **29 held / 0
  contradicted / 0 inconclusive** on a clean Ubuntu 24.04.5 VM with real i2pd **2.61.0**.
- Gate logs from the qualification run: `C:\Users\user\Desktop\m9-native-gate.log`,
  `m9-native-qualification.log` (host artifacts; not in the repo).

**Recent commits worth knowing:** `4ad93da`…`8747afa` (M8/M9 phases), `264c208` (D-24 fix — the Tor
control client), `b9499af` (M9.5 docs + qualification script; tagged rc4).

**Where the evidence lives:**

- `docs/PROTECTION-CLAIMS.md` — every claim **PC-01…PC-26** with evidence and falsifiers, plus the
  open gaps **G1…G13** (SYSTEM), **GA-1…GA-5** (APP), **GI-1…GI-4** (I2P; GI-1 closed natively).
- `docs/ADVERSARIAL-TEST-PLAN.md` — the AC/AE/AF/AL/AN/AS classes, the AA class (M8), the IA class
  (M9), and the defect ledger **D-15…D-24**.
- `docs/IMPLEMENTATION-PLAN.md` — per-milestone status.
- `docs/M8-DECISIONS.md`, `docs/M9-DECISIONS.md` — binding decisions per milestone.
- `docs/ARCHITECTURE-REVIEW.md`, `docs/RECOVERY.md` — the review the design answers to, and the
  documented recovery/escape paths.

**How to run things (WSL):** `/root/gh <cmd>` sets the environment; `/root/m9-gate.sh` is the WSL
gate; `/root/m8-final-gate.sh` is the M1–M8 gate. On a native host use
`scripts/m9-release-gate.sh <log>`. The environment-dependent real-router run is separate by design.

---

## 2. What Ghostnector is now

A Linux privacy tool that enforces **transparent Tor** or **I2P** in the kernel (nftables), proves
that enforcement with independent checks, and fails closed. The GUI is the last milestone.

### Scopes and networks

- **Scope**: `system` (whole machine), `app` (only applications launched through Ghostnector),
  `user` (single uid; exists in the vocabulary), `dns` (encrypted DNS only, no overlay).
- **Network**: `tor` or `i2p`. **They are alternatives, never layers.**
- **Intentionally refused combinations** (validator refuses them with explicit reasons):
  - Tor **and** I2P at once (`MixedNetworks`); I2P-over-Tor is refused with it.
  - I2P outside `system` scope (`I2pNeedsSystemScope`) — **APP+I2P is not supported in M10**.
  - I2P with `allow_lan` (`I2pWithLan`).
  - APP scope with `allow_lan` (APP preserves source identity; no SNAT/masquerade exists).
  - `dns` scope with any overlay; bridges/authenticated-DNS require Tor.

### Authoritative state model (`Snapshot.state`)

`Off` → `Applying` → `Protected` | `Degraded` | `Blocked` | `Portal`.

- **`Protected` is reachable only from actual verification evidence** (`Cause::Verified`). It is
  never inferred from toggles, processes, or services.
- **`Degraded`** = policy applied but verification is stale/unavailable/inconclusive. Traffic is
  still under policy. This is the honest default after `connect` until checks pass.
- **`Blocked`** = fail-closed: the fail-closed baseline is in force; no traffic can leave. Reached
  after a verification **failure** (contradiction) or `panic`.
- **`Portal`** exists for a captive-portal exception; treat it as transient.
- **DR-15:** once protection has been established, Ghostnector never returns to `Off` on its own.
  Only an explicit user `disconnect` does. Failures escalate to `Blocked`.
- **G9 (still open):** `Protected` can be reached with only a subset of checks configured; the
  reasons list what did not run. For I2P, the canary is *required* for `Protected`; for APP, every
  group needs a passing probe; **zero protected apps ⇒ `Degraded`, never `Protected`**.

### Verification philosophy

The verifier is **inside the protected set** — no exemption, no privilege — so a check that passes
because it was special proves nothing. Three questions, per scope:

| Scope | Checks |
|---|---|
| SYSTEM (Tor) | UDP egress must be refused; a configured endpoint must answer through Tor and must not report this machine's address; a configured canary must resolve as expected |
| APP | per group: namespace shape + effective ruleset comparison, plus a fixed probe run **inside the namespace** (UDP refused; protected path answers; canary resolves) |
| I2P | clearnet TCP refused; the router's proxy answers; **the configured I2P canary must be fetched through the proxy** |

Every pass also compares the **kernel's own ruleset** against what was applied (tamper detection). A
contradiction applies the fail-closed baseline and reports `Blocked`; an inconclusive check only
downgrades to `Degraded`.

### Fail-closed behavior

- Deny first, then bring services up, then open the path; transitions replace the whole table in one
  nftables transaction.
- Verification failure ⇒ fail-closed baseline + `Blocked` (machine-wide for SYSTEM/I2P; for APP the
  namespaces are removed and the APP scope is denied with APP-scoped wording).
- `panic` applies the fail-closed baseline immediately and leaves services running.
- The boot guard applies the fail-closed baseline before the network is configured when protection
  was requested; `ghostnector.unprotected=1` is the documented console escape.
- Known costs (documented, deliberate): a transient connectivity loss can leave the machine
  `Blocked` until a person acts (G12); root/`CAP_NET_ADMIN` can replace policy (G10).

### Privileged component boundaries (do not widen)

| Component | Privileges | Job |
|---|---|---|
| `ghostnector-core` | none (only the DNS relay child gets `CAP_NET_BIND_SERVICE`) | state machine, services, verification, journal, unix socket `/run/ghostnector/core.sock` |
| `ghostnector-netd` | `CAP_NET_ADMIN`, `CAP_CHOWN` (ambient NET_ADMIN only) | renders/applies/verifies the nftables policy from a **closed verb set**; never accepts a ruleset |
| `ghostnector-appd` | `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_CHOWN` (ambient NET_ADMIN only) | APP namespaces: create/verify/destroy, sessions, probes; closed `AppVerb` set; never accepts commands, paths, namespaces or rulesets |
| `ghostnector-appd-launch` | drops every capability and switches uid | `setns`, mount-ns + `resolv.conf`, `setgroups/setgid/setuid`, clears all granting sets, `execve`s the **user's passwd shell**; the session socket's `SO_PEERCRED` is the enforcement |
| `ghostnector-dns` | none beyond inheriting `CAP_NET_BIND_SERVICE` | DNS chokepoint; listens on loopback, or on the exact private APP/I2P core address; never a wildcard |
| `ghostnector-bootguard` | none | boot-time fail-closed |

The interface/daemon identities are **never exempt from policy** (enforced by test). The GUI must be
another unprivileged client, never a component with special rights.

### Major protection claims (full list and evidence in `PROTECTION-CLAIMS.md`)

- **PC-01…PC-05**: TCP/UDP/DNS confinement, IPv4 coverage, IPv6 denial.
- **PC-06/PC-07**: the protected path carries traffic; the exit is not this machine.
- **PC-08/PC-16**: policy tampering and policy disappearance are noticed.
- **PC-09**: the exemption list is exactly the documented one, verified in both directions.
- **PC-10**: boot with protection requested.
- **PC-11…PC-14**: Tor dying, the control plane dying, the relay dying, and transitions never widen
  the policy.
- **PC-15**: disconnect restores what was there.
- **PC-17…PC-21** (APP): Tor-only conduit, dead-end property, source identity preserved, DNS only
  through the chokepoint, teardown removes everything.
- **PC-22…PC-26** (I2P): independence and exactly one exemption; every non-router flow denied at the
  far side; proxies loopback-only and closed off-host; evidence-only `Protected`; teardown/metadata.

**Explicit remaining gaps/limitations (do not paper over):** G6 (boot ordering not observed), G8
(no ISP-facing vantage), G9 (minimum checks not enforced), G10 (root is trusted), G11 (DHCPv6 not
supported while protected), G12 (transient loss can block until a person acts), G13 (no one-by-one
kernel-vs-report exemption diff), GA-1…GA-5 (APP boundary/PC-07 narrowing/reboot/reconcile),
GI-2 (public I2P integration observed but not relied on), GI-3 (APP+I2P refused), GI-4 (no canary ⇒
`Degraded`). Also: distinct source addresses are **not** proof of distinct Tor circuits.

---

## 3. The product-level API M10 should consume

Transport: **newline-delimited JSON `Frame` over `AF_UNIX`** at `/run/ghostnector/core.sock`
(mode 0600, owned by the `ghostnector` group; a client must be in that group). Protocol version is
in `ghostnector-spec::ipc` (`PROTOCOL_VERSION = 1`); a mismatch is a hard failure. The first frame
on a connection is `Hello`.

### Requests → Responses

| Request | Response | Notes |
|---|---|---|
| `Hello { protocol, client }` | `Hello { protocol, daemon_version }` | hard version check |
| `Snapshot` | `Snapshot(Box<Snapshot>)` | the authoritative state |
| `Connect { profile }` | `Accepted` or `Error` | `profile` is the raw `Profile`; core validates it |
| `Disconnect` | `Accepted` or `Error` | return to the captured baseline |
| `Panic` | `Accepted` or `Error` | fail-closed now, services keep running |
| `AppRun` | `AppSession { id, socket }` or `Error` | prepares a session for the requesting user |
| `AppList` | `AppList { apps: Vec<AppStatus> }` | ids, addresses, presence |
| `AppStop { id }` | `Accepted` or `Error` | stops one group |
| `Cancel` | `Accepted` or `Error` | cancel an in-flight transition |
| `Subscribe` | events | `StateChanged(Box<Snapshot>)`, `DeniedEgress { count }`, `Warning(Warning)`, `Notice { message }` |

Errors carry `{ code, message, sensitive }` with a closed code set: `protocol_mismatch`,
`not_authorized`, `invalid_profile`, `busy`, `backend_failure`, `unsafe_state`, `internal`.
Messages never contain destinations, queries, or secrets.

### `Profile` (what `Connect` carries)

```
Profile {
  scope: off | dns | app | user | system,
  networks: { tor: bool, i2p: bool },   // alternatives, never both
  allow_lan: bool,                       // refused in APP and I2P scope
  use_bridges: bool,                     // requires tor
  authenticated_dns_over_tor: bool,      // requires tor
}
```

Validation is core's job; the GUI should present the refusals as clear user-facing messages rather
than pre-computing them (but it may disable obviously unsupported combinations — see §6).

### `Snapshot` (the only source of truth for display)

```
state: ProtectionState            // off | applying | protected | degraded | blocked | portal
profile: Option<Profile>          // scope + networks in force (None when off)
warnings: Vec<Warning>            // e.g. I2pExposesHostIp, SystemScopeCoversAllUsers
reasons: Vec<Reason>              // short, non-sensitive, human-readable
exemptions: Vec<Exemption>        // every hole in the policy, for display
health: { tor, dns, i2p: ServiceHealth, policy_applied: bool, verification: Verification }
verified_ago_secs: Option<u64>
blocked_egress_attempts: u64      // a count only
apps: Vec<AppStatus { id, address, present }>
generation: u64                   // bump on every transition; discard stale updates
```

`ServiceHealth`: `unknown | down | starting | up | degraded`.
`Verification`: `unknown | fresh | stale | unavailable | failed`.

**State wording the GUI should mirror (already user-facing in the CLI):** `off — traffic is not
protected`; `applying — a transition is in progress`; `protected — and verified`; `protected, but
unverified`; `blocked — no traffic can leave` (or, in APP scope, `blocked — no protected
application can reach the network`); `portal — protection is relaxed`.

### APP operations (the whole protected-application UX)

1. `AppRun` → `{ id, socket }`. The **client** then connects to `socket` (a unix socket, 0600,
   owned by the requesting uid — the kernel enforces this with `SO_PEERCRED`) and writes the command
   to run, e.g. `exec firefox\n`, exactly as the CLI does. No command, path, uid or namespace ever
   crosses the privileged interfaces.
2. `AppList` → ids/addresses/presence for the list view.
3. `AppStop { id }` → the group and its namespace are destroyed.

There is no "edit policy", "add tunnel", or "choose port" operation, and M10 must not invent one.

### Network/scope selection (CLI equivalents for reference)

```
ghostnector connect                     # Tor, whole system
ghostnector connect --network i2p       # I2P, whole system
ghostnector connect --scope app         # Tor, selected apps
ghostnector run -- firefox              # run an app in a protected session
ghostnector apps / stop-app <id>
ghostnector disconnect / panic / status / watch
```

### What the GUI must never infer itself

It must not derive `Protected` from a toggle position, a running Tor/i2pd process, a service health
field alone, or its own memory of a request. It displays `Snapshot.state` and `Snapshot.reasons`
verbatim, and treats `generation` as the ordering authority.

---

## 4. M10 product constraint: the GUI is extremely simple

Backend complexity must not leak into normal operation. Conceptually the normal interface exposes
only:

- **Protection on/off** (connect/disconnect; panic available but not prominent).
- **Network**: Tor / I2P.
- **Scope**: whole system / selected applications, with unsupported combinations made clear
  (I2P is whole-system only in this version).
- **Authoritative status and concise reasons** (protected / degraded / blocked, and why).
- **APP scope**: run/add application, view protected applications, stop application.

**Namespace IDs, UIDs, ports, interface names, policy names, daemon names, capabilities, nftables
details and recovery internals must not appear in normal operation.** Technical information may
live behind an optional **diagnostics/details** view (exemptions, health fields, verification
age/details, journal path, versions). Even there, no destinations, queries, or per-flow data
(DR-19: `Snapshot` is non-sensitive by construction).

---

## 5. Security/UI rule

The GUI is a **presentation/control client, not another security authority**:

- It displays core's authoritative `Snapshot` and reasons; it never infers `Protected` from toggles,
  process existence, Tor/i2pd status, or its own assumptions.
- It holds no privileges, is never exempted from policy, and never talks to `netd`/`appd` directly.
- It performs only user-visible actions: connect, disconnect, panic, app run/list/stop.
- A GUI crash or exit must change nothing about protection (enforcement is in the kernel).

---

## 6. M10 architecture questions to resolve before implementation

Write these down and get them reviewed before writing code (the milestone's own decisions record,
e.g. `docs/M10-DECISIONS.md`):

1. **GTK4 structure and process model** — one process, or a thin client plus a background helper?
   (Prefer a single unprivileged GTK4 app; no background component unless justified.)
2. **Core socket interaction** — connect per action vs. one long-lived connection; how `Hello`,
   `Subscribe` and reconnection on core restart are handled.
3. **Privilege/authentication model** — the GUI runs as the logged-in user and must be in the
   `ghostnector` group (or use a session-level authorization decision; document it). No polkit
   escalation, no root.
4. **State refresh/event subscription** — subscribe once, render `StateChanged` snapshots by
   `generation`, re-fetch `Snapshot` on reconnect; never poll-infer.
5. **APP-launch UX** — how the user picks an application (desktop entry, file chooser, command
   line?), how `AppRun` + session socket is used, how the app's exit is reflected (`AppList`).
6. **Unsupported-combination UX** — I2P + selected apps, I2P + LAN, Tor+I2P: explain *why* and keep
   the refused request out of the backend (core still validates).
7. **Error/degraded/blocked/recovery presentation** — distinguish confinement failures from
   availability failures in wording; `Blocked` is serious and needs the reason; recovery actions
   are only the user's documented ones (disconnect/panic/reconnect), never hidden magic.
8. **Diagnostics view** — what to show (exemptions, health, verification age, warnings, versions),
   and how to keep it clearly secondary.
9. **Accessibility and keyboard operation** — screen-reader labels, focus order, keyboard-only
   flows for on/off/network/scope/app actions.
10. **Packaging/desktop integration** — a `.desktop` entry, icon, systemd user session or plain
    binary; how the GUI is installed next to the daemons; no new privileged units.
11. **Deterministic GUI tests** — how the UI is tested without a display and without weakening the
    backend gates (e.g. model/logic tests against recorded `Snapshot`/event sequences; a fake core
    socket; no test that requires root or changes policy). GUI tests must not replace or relax any
    M1–M9 suite.

---

## 7. Preserve the design principle: minimal backend change

M10 should require **as little backend modification as possible**. If implementing the GUI appears
to require:

- widening a privileged interface (`netd`, `appd`, the launcher),
- duplicating or caching security state outside core,
- changing proven M1–M9 semantics (state machine, verification, fail-closed, scoping), or
- adding a new authority (polkit rule, setuid helper, root daemon),

then **stop, write down the architectural change and its justification, and get it reviewed before
making it.** The intended shape is: GTK4 client → core unix socket → nothing else.

---

## 8. Final release work after M10

Only after M10 is accepted:

1. **Complete M1–M10 regression/adversarial qualification** (all hermetic suites plus the native
   real-router run) on the frozen M10 candidate.
2. **Clean-install/package testing on native Linux** — install from the packages/units on a fresh
   machine, not from the build tree; verify units, sysusers/tmpfiles, sockets, and the GUI entry.
3. **GUI correctness/usability testing** — every normal operation, every refused combination, every
   state wording, diagnostics view, keyboard/accessibility pass.
4. **Performance qualification** — measure Ghostnector's own overhead separately from the Tor/I2P
   network overhead (e.g. baseline direct, direct-through-Tor, through-Ghostnector-with-Tor;
   the kernel redirect and the chokepoint should add negligible overhead; the network is the cost).
5. Only then consider tagging the final **`v1.0.0`** (annotated, on a clean tree, with the complete
   gate and qualification record).

---

## START HERE TOMORROW

Recommended first prompt for the new chat:

> Read `docs/HANDOFF-M10.md` and the documents it points at (`PROTECTION-CLAIMS.md`,
> `ADVERSARIAL-TEST-PLAN.md`, `IMPLEMENTATION-PLAN.md`, `M9-DECISIONS.md`, `RECOVERY.md`). Confirm
> the repository state (HEAD `b9499af`, tag `v1.0.0-rc4`, clean tree). Then write
> `docs/M10-DECISIONS.md` answering the architecture questions in §6, with a concrete GTK4 plan
> that consumes only the product-level API in §3, obeys the UI constraints in §4/§5, and needs no
> backend modification. Do not implement M10 until that plan is reviewed.

Suggested work sequence after the plan is reviewed:

1. A minimal GTK4 shell that connects to core, does `Hello`/`Snapshot`/`Subscribe`, and renders
   state + reasons (no actions yet) — verified against a fake core socket in tests.
2. Protection on/off + network + scope selection, with unsupported combinations explained.
3. APP scope: run/list/stop, using the session socket exactly as the CLI does.
4. Degraded/blocked/error wording, recovery actions, warnings, accessibility pass.
5. Diagnostics view (secondary), packaging/desktop entry, deterministic GUI tests.
6. M1–M10 gate + native qualification + clean-install test + performance run; then the `v1.0.0`
   decision.
