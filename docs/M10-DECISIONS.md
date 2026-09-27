# M10 decisions — the GTK4 interface

Status: **implemented** (M10.1, commit `b92e994`). The native VM real-display qualification and the
clean-install/lifecycle tests were completed in the M10 qualification campaign; the record is in
`docs/QUALIFICATION-NOTES.md` and the consolidated result — including the D-50 APP-scope transparent
egress fix, which is now implemented and requalified against real Tor — is in
`docs/RELEASE-CANDIDATE-REPORT.md`. No M1–M9 backend boundary was widened.

---

## 0. Phase-1 prerequisites (findings that must be fixed first)

Phase 1 (verify the inherited baseline) reproduced the RC4 gate on the native Ubuntu 24.04.5 VM and
found that the recorded native run and the handoff disagree. The handoff claims the native M1–M7
adversarial suite was **26 held / 0 contradicted / 1 inconclusive**; the native gate log
(`m9-native-gate.log`, produced by the run that became `b9499af`) records **24 held / 2
contradicted / 1 inconclusive**. The 26/0/1 number is the WSL result, not the native one. Both
native contradictions reproduce. They are defects, not noise, and M10 must not be built on top of a
gate that reports them as noise.

### D-25 — the sampling oracle attributes pre-protection packets to the next state sample

* **Where:** `scripts/lib/gh-harness.sh` (`gh_watch_start`, `gh_watch_violations`, used by AL-1/4/7).
* **Mechanism:** the oracle samples (packet count, reported state) about every 0.2 s and attributes
  an increase to the state of the *later* sample. On the VM the `Off → Applying → Degraded`
  transition took about 0.9 s. Storm packets crossed while the machine was still `Off`/`Applying`
  (no protection was reported); the first sample after the increase read `Degraded` — a false
  contradiction.
* **Evidence:** native failure at 2026-09-25 23:56:31 (first crossing 31.609, `connect: begin`
  31.848, last crossing ~31.932, `connect: returned` 32.789, state at report `protected — and
  verified`). Reproduced on the VM at 2026-09-26 14:39 (first crossing 28.978, `connect: begin`
  29.0149, last crossing 29.3091, `connect: returned` 30.0637). All crossing packets predate any
  protection claim; the fail-closed baseline landed at ~29.3 and the crossing stopped there.
* **Classification:** test/oracle defect. Nothing crossed while the machine reported protection;
  the oracle cannot tell "crossed before the claim" from "crossed under the claim".
* **Fix:** per-packet attribution instead of count intervals. A timestamped state log (a
  `ghostnector watch` follower writing `epoch.ns state` lines on every `StateChanged`) plus the
  existing outside capture read with epoch timestamps: a packet is a violation iff a protected
  state (`Degraded` or `Protected`) was in force at the packet's timestamp. Ambiguity (a packet
  whose time has no state sample) is printed and counted as inconclusive, never as a pass. This is
  strictly stronger than the current oracle, and it makes AL-1/4/7 fail if any packet crosses while
  protection is claimed.
* **Regression:** the three lifecycle cases plus a new harness self-check that a packet injected
  after a protected state sample is reported.

### D-26 — `allow_lan` contradicts the built-in checks when a check endpoint is inside the LAN sets

* **Where:** `ghostnector-core` (`connect`/`plan` with `VerificationConfig`) and the verifier's
  premise; surfaced by `scripts/adversarial.sh` case `AE3` (the plan's **AE-6**, the LAN exemption).
* **Mechanism:** the LAN exception permits every destination in `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, `169.254.0.0/16` (`crates/ghostnector-policy/src/compile.rs`, `LAN4`). The
  verifier's UDP check sends one byte to the configured endpoint and treats **any answer as
  evidence that UDP is leaking** (`crates/ghostnector-core/src/verify.rs`). With `allow_lan` on and
  the endpoint inside the LAN sets, the datagram is legitimately allowed and answered, so the engine
  reports a leak, applies the fail-closed baseline and enters `Blocked`. The same premise makes the
  HTTP "protected path" check reach the direct path instead of Tor.
* **Evidence:** the RC4 native AE-3 failure; reproduced deterministically with a shadow run on the
  VM: `connect --lan` → at t+4 s the state is `blocked — no traffic can leave` with the reason
  `verification failed: a UDP datagram reached 10.88.0.1:18081: something is letting UDP out`. The
  hermetic suite only "passes" AE-3 when its LAN probe wins a race against the verifier's 2 s
  settle (`crates/ghostnector-core/src/main.rs`), which is why the WSL run and an isolated VM rerun
  can both pass while the native full run failed.
* **Classification:** product defect (fail-closed: no leak; but the profile is unusable with an
  in-LAN endpoint, the reported reason is wrong, and a machine can end `Blocked` for a
  configuration that is valid).
* **Chosen fix (for review):** refuse the combination at `connect` time — before announcing
  `Applying` and before touching anything — when `allow_lan` is requested and a configured check
  endpoint (the UDP endpoint or the HTTP check address) is inside the LAN sets. The message names
  the endpoint and the two ways out: configure an endpoint outside the local network, or turn the
  exception off. Implementation: a pure `inside_lan(IpAddr)` predicate next to the LAN constants in
  `ghostnector-policy`; one new `EngineError::Configuration(String)` (mapping to `invalid_profile`)
  so the message is honest instead of "not supported yet"; two unit tests (refused when in-LAN,
  allowed when not). No verification semantics change and no exemption widening.
* **Test fixes:** the harness must give the verifier endpoints outside the LAN sets (add
  `198.18.0.1/24` to the far side and use it for `--udp-check`/`--check-url`; the direct LAN probe
  in AE-3 keeps targeting `10.88.0.1`). AE-3 must wait until verification has settled (state is no
  longer "not checked yet") before judging, and assert the steady state is not `Blocked` and the LAN
  path is direct. A new regression case connects with `--lan` against an in-LAN endpoint and asserts
  a clean refusal, no policy applied, and an unchanged machine.
* **Docs:** correct the M9.5/handoff native record; after the fixes, rerun the native gate and
  update the numbers with the new run.

These two fixes are prerequisites, not M10 features. They change no protection semantics; they fix
a test oracle that over-claims and a configuration refusal that under-explains.

---

## 1. Answer to the architecture questions (HANDOFF-M10 §6)

### 1. GTK4 structure and process model

One process: `ghostnector-gui`, an unprivileged GTK4 application. No background helper, no user
service, no daemon, no root, no polkit, no setuid. Closing or crashing it changes nothing: the
policy is in the kernel and the control plane is `ghostnector-core`.

The crate is a workspace member with the GTK dependency behind a feature:

* `crates/ghostnector-gui` — lib (portable model/client) + bin `ghostnector-gui`.
* `[features] gtk = ["dep:gtk4"]`; default **off**; the binary declares
  `required-features = ["gtk"]`.
* `cargo test --workspace` builds and tests the model and the real unix-socket client everywhere,
  including Windows-hosted `cargo check --target x86_64-unknown-linux-gnu` (no GTK needed).
* The release gate adds `cargo check/clippy/build -p ghostnector-gui --features gtk` on Linux.

### 2. Core socket interaction

Two connections to `/run/ghostnector/core.sock`, because the protocol makes `Subscribe` terminal for
a connection (`crates/ghostnector-core/src/server.rs` streams events and returns):

* **Control connection** — `Hello`, then one request at a time, response matched by order, exactly
  like the CLI. Used for `Snapshot`, `Connect`, `Disconnect`, `Panic`, `AppRun`, `AppList`,
  `AppStop`, `Cancel`.
* **Event connection** — `Hello`, `Subscribe`, then read `StateChanged`, `Warning`, `Notice`,
  `DeniedEgress` frames until EOF.

One worker thread owns both connections and all I/O; the UI thread never blocks. Requests are
executed serially. Control reads have no short timeout (a Tor bootstrap is legitimately slow); a
local socket either answers, or the connection ends and the state becomes "unknown". On any
connection loss the worker closes both, notifies the UI (`Disconnected { reason }`), waits 2 s and
retries: control → `Hello` → `Snapshot`; events → `Hello` → `Subscribe`. Every reconnect starts a
new `epoch`; `generation` ordering is only applied within one epoch (a restarted core may legitimately
start lower).

### 3. Privilege and authentication model

The GUI runs as the logged-in user and must be in the `ghostnector` group, exactly like the CLI.
That group owns the core socket (0660); the kernel enforces it. No polkit decision, no root, no
capability, no exemption from policy. If the socket cannot be opened (absent or `EACCES`), the
window shows a single honest message ("Cannot reach the Ghostnector service…" / "This account may not
control Ghostnector (not in the ghostnector group)") and all controls are disabled. Membership is
documented in the README and the install step.

### 4. State refresh and event subscription

Subscribe once per event connection and render `StateChanged` snapshots by `generation`. The GUI
never infers `Protected`: it renders `Snapshot.state`, `Snapshot.profile`, `Snapshot.reasons`,
`Snapshot.warnings`, `Snapshot.exemptions` and `Snapshot.health` as produced. A 30 s `Snapshot`
refresh keeps `verified_ago_secs` current; that is a read of the authoritative snapshot, not
poll-inference. On disconnect, the last snapshot is marked "last known" and greyed, never shown as
current.

### 5. APP-launch UX

1. `AppRun` (only enabled when the active profile is APP and the state `is_protected()`).
2. The GUI opens the returned session socket, writes `exec '<path>'` (shell-quoted single argument —
   the command reaches only the user's own passwd shell inside the namespace, never a privileged
   interface), and keeps the connection in a per-group map with a drain thread.
3. `AppList`/`StateChanged` refreshes the list; Stop calls `AppStop { id }`, and the GUI closes its
   end of the session.
4. The picker is the native `gtk::FileDialog` (a fallback to `FileChooserNative` if the build GTK is
   older than the API); a chosen file must be executable, else it is refused locally with a clear
   message.
5. Labels: the group id is a handle the GUI keeps internally and never displays. A group launched in
   this window shows the chosen file name; after a GUI restart (or when another client launched it)
   it shows "Protected application ⟨n⟩" with running/not present. No namespace, uid, or address is
   displayed in normal operation.

### 6. Unsupported-combination UX

The simple view offers `system` and `app` scopes and `tor`/`i2p` networks only. Refusals are shown
as disabled controls with a one-line reason, and the raw `Profile` is still sent to core, which
remains the validator (a refusal there is rendered verbatim):

| Combination | UI behaviour | Reason shown |
|---|---|---|
| I2P + selected applications | `Selected applications` disabled | "I2P protects the whole system in this version." |
| I2P + local network | local-network switch disabled | "I2P has no local-network exception." |
| APP + local network | local-network switch disabled | "Per-application protection preserves source identity; local-network access is not available." |
| D-26 conflict (check endpoint in the LAN + local network on) | local-network switch disabled *after* the first refusal, or the core error rendered | the core message, verbatim |
| user/dns scopes, bridges, authenticated DNS | not offered in M10 | documented as CLI-only for v1 |

`Tor + I2P` cannot be selected (radio group) and is refused by core regardless (`MixedNetworks`).

### 7. Error, degraded, blocked and recovery presentation

The banner is the primary object and uses the CLI's exact wording (moved to
`ghostnector-spec::state` as pure functions so CLI and GUI cannot drift; the CLI output stays
byte-identical and its tests guard it):

| State | Banner | Colour |
|---|---|---|
| Off | `off — traffic is not protected` | grey |
| Applying | `applying — a transition is in progress` | amber, spinner |
| Protected | `protected — and verified` (+ "checked N s ago") | green |
| Degraded | `protected, but unverified` | amber |
| Blocked | `blocked — no traffic can leave` (APP: `…no protected application can reach the network`) | red |
| unknown (no connection) | `Protection state unknown — cannot reach the Ghostnector service` | grey |

`Snapshot.reasons` are listed under the banner verbatim, so a verification failure, a stale check,
a down service and a user disconnect are distinguishable without the GUI interpreting anything.
Recovery actions are only the documented ones: the main switch sends `Disconnect`; "Deny everything
now (panic)" lives in the header menu with a confirmation; when disconnected the only action is
"Retry". No hidden automatic reconnect and no silent state change.

### 8. Diagnostics view

A secondary page (or a second window) behind "Diagnostics", clearly not part of normal operation:
state, profile in force, policy applied, verification and its age, per-service health, warnings,
the complete exemption list, blocked-egress count, GUI/core/protocol versions, and a "Copy details"
button that copies exactly this non-sensitive text. It shows no destination, query, flow, exit
address, uid, namespace, port or policy text (DR-19).

### 9. Accessibility and keyboard operation

Native GTK4 widgets, logical focus order, mnemonics (`_Protection`, `_Network`, `_Scope`, `_Add
application…`), the status banner exposed with the `status` accessible role and its text as the
accessible name, labelled controls (no unlabelled icons), and a keyboard-only path for every
action (Space/arrows for the switch, radios, lists; Enter for Add/Stop; Escape closes dialogs).
Screenshots and a manual keyboard pass are part of the Phase-3 checklist; a `gtk::init()` smoke test
runs under Xvfb on the VM, never in the hermetic gate.

### 10. Packaging and desktop integration

* `ghostnector-gui` installed to `/usr/bin` with the other binaries.
* `packaging/desktop/ghostnector.desktop` → `/usr/share/applications`: `Name=Ghostnector`,
  `Exec=ghostnector-gui`, `Terminal=false`, `Categories=Network;Security;`, `Icon=ghostnector`.
* `packaging/icons/hicolor/scalable/apps/ghostnector.svg` (our own simple shield mark).
* No new systemd unit, no autostart, no polkit file, no privileged component.
* The install path is the Phase-3 `packaging/install.sh`/`uninstall.sh` (binaries, units, sysusers,
  tmpfiles, desktop entry, icon), tested on the clean VM, plus the documented group membership
  step. A distro `.deb` is a documented v1 gap, not a claimed feature.

### 11. Deterministic GUI tests

* **Model tests** (portable, in `cargo test --workspace`): state/region mapping from `Snapshot`
  fixtures including every `ProtectionState`, every `Verification` value, block/degraded/off, APP
  lists, warnings/exemptions, stale `generation` rejection within an epoch, reconnect/epoch
  behaviour, and the refusal matrix (row by row).
* **Protocol tests** against the real `UnixCoreClient` over a test unix socket (no root, no policy):
  handshake, version mismatch, request/response order, event stream, denied action, EOF → unknown,
  resubscribe after a restart.
* **Wording tests**: the spec helpers are shared with the CLI, and a fixture asserts the exact
  strings; the CLI's own tests keep passing unchanged.
* **GTK smoke test** (display-gated, run on the VM under Xvfb and once on the real desktop): the
  window builds from a fake client, does a keyboard pass, toggles protection against a fake core.
  Not part of the hermetic gate; documented as a Phase-3/7 step.
* No test requires root, changes a policy, or touches the M1–M9 suites. `scripts/m9-release-gate.sh`
  gains the GTK-feature check/clippy/build/test steps; all existing sections stay byte-for-byte
  unchanged.

---

## 2. Deliberate limits of M10

* The GUI does not offer `user` or `dns` scopes, bridges, or authenticated DNS; the CLI keeps them.
* It does not edit policy, choose ports, or manage services; there is no "add tunnel".
* It is not an authority: with no connection to core it shows "unknown", not the last known state as
  truth, and it never claims protection itself.
* It does not persist anything except ordinary window state; app labels are session-local. No
  destinations, queries or flows are ever stored or displayed.
* I2P is whole-system only in this version (unchanged from M9).

---

## As built (M10.1, commit `b92e994`)

The implementation follows the decisions above with these specifics, recorded so later work does not
have to re-derive them:

1. **Subscribe is on the event connection.** The protocol turns a connection into a stream when it
   receives `Subscribe`, and the control connection stays request/response. The worker owns both and
   reconnects them together under a new epoch.
2. **Selection changes while protection is on are confirmed, not locked.** Changing network, scope
   or the local-network switch while protected re-applies protection; the window asks first, and a
   cancelled change puts the controls back to what core last reported. While `Applying`, controls are
   frozen.
3. **GTK 4.12 or newer.** The window uses `FileDialog`/`AlertDialog` (4.10) and
   `CssProvider::load_from_string` (4.12). Ubuntu 24.04 ships 4.14. The dependency is behind the
   `gtk` cargo feature so the rest of the workspace builds everywhere.
4. **One wording module.** `ghostnector-spec::display` holds the state/scope/network/verification
   lines; the CLI renders through it unchanged and the GUI uses the same functions.
5. **Panic and diagnostics.** Panic is a header-menu action behind a confirmation dialog. The
   diagnostics view shows the last known snapshot clearly labelled as such when the core is
   unreachable, and copies as text; it never shows destinations, queries, or per-flow data.
6. **Session lifetime.** The window holds each launched application's session socket open with a
   drain thread and closes its end on Stop; closing the window does not stop an application that is
   already running (the daemon owns the group, the kernel owns the policy).
7. **Known limit:** a group launched by another client (or before this window started) is listed by
   a neutral ordinal, because `Snapshot` deliberately carries no command line the GUI could show.
8. **User-facing vocabulary (D-27).** Failure reasons are plain sentences: the interface never shows
   ports, paths, unit names or addresses. Core's error `Display` strings are the user-facing text
   (shared by CLI and GUI), and the technical detail (proxy address, cookie path, `systemctl` output)
   goes to the daemon log. Regression tests refuse a path, address or unit name in those strings.
9. **Diagnostics window close.** The stored window reference is dropped only after the close event
   has been processed; destroying it inside its own close handler makes X11 report `BadDrawable`.
   With a window manager and the real `WM_DELETE_WINDOW` path, closing diagnostics leaves the
   application running (proved on the VM).

---

## Decisions taken during the qualification campaign (M10 + full release)

These were forced by installed-product defects found while qualifying. Each preserves the M1–M9
boundaries; the alternatives that would have widened them were rejected and are recorded in the
defect ledger (`docs/ADVERSARIAL-TEST-PLAN.md`, D-40…D-46).

1. **I2P bring-up order (D-41).** The I2P profile — itself a deny-everything-except-the-router
   policy — is applied *before* the router starts, because the router resolves its reseed hosts by
   name and the fail-closed baseline (correctly) exempts only Tor's uid. At the moment the profile
   lands, the exemption belongs to a process that does not exist yet and everything else stays
   denied, so deny-first is preserved. The rejected alternative was adding the I2P uid to the
   baseline; that would have widened the blocked-machine policy and contradicted PC-22's
   mutually-exclusive exemption model.
2. **The router resolves from its own uid (D-42).** The engine discovers the machine's real upstream
   nameservers and writes `/run/ghostnector/i2pd-resolv.conf` plus a minimal nsswitch; the i2pd unit
   bind-mounts them over `/etc/resolv.conf` and `/etc/nsswitch.conf`. Name resolution therefore
   happens under the one identity I2P mode exempts. No exemption was added, and no other process can
   use those files. A Tor→I2P switch also restores the machine's resolver first, because I2P starts
   no chokepoint (D-43).
3. **The APP helper's sandbox names the syscalls and capabilities its job needs (D-44, D-46).**
   `@mount` is allowed because `ip netns add` must make `/run/netns` shared so a named namespace can
   persist; `CAP_SETUID`/`CAP_SETGID` are allowed because the launcher drops to the invoking user.
   Both were previously blocked by a filter/bounding set that the source-tree suites never applied;
   the appd hardening test now names the complete allowed set and refuses anything else. The
   unit keeps `NoNewPrivileges`, its syscall filter, and no `CAP_DAC_OVERRIDE`.
4. **The group session socket is reachable by its user (D-45).** `/run/ghostnector/apps` is
   `0710 root:ghostnector` (traversable by the accounts that may control Ghostnector, not listable);
   each socket stays `0600` owned by the invoking user and the launcher's peer check still decides
   who may use it.
5. **The APP TCP path is a per-namespace relay, not a DNAT to the core's TransPort (D-50).** Real
   Tor's transparent contract needs `SO_ORIGINAL_DST`, which only the namespace that created the NAT
   can answer, so the DNAT now targets a relay inside the application's own namespace. The relay
   runs as the application's uid with every capability set empty (proved by `d50-origdst-caps.log`),
   refuses any connection with no original destination (it can never be an open proxy), speaks SOCKS
   to the core's SocksPort as the application's address with a per-group credential (so Tor's
   `IsolateSOCKSAuth` keys each group separately), drains a refused client so a dead router reads as
   a failed check rather than an inconclusive one, and is stopped through a stdin pipe because the
   packaged set has no `CAP_KILL`. The namespace may reach only the chokepoint and SocksPort, APP
   mode no longer renders a TransPort, and the rejected alternatives were host-side interception (it
   would put application frames on the host link, falsifying PC-18) and narrowing the v1 APP claim to
   "no transparent egress" (it would drop a capability the M8 design promised).
6. **The boot guard runs as the control plane's user, and the helper keeps the fallback copy for it
   (D-54).** The guard must apply the fail-closed policy before the network with nothing but
   `CAP_NET_ADMIN`, so it runs as the user that owns both the helper's socket and the fallback copy:
   netd hands both over (the socket as before, the copy with the `CAP_CHOWN` it already carries) and
   keeps the copy current on every apply in its own root-owned state directory. No capability that
   bypasses file permissions and no widened file or socket mode was added; the alternatives (running
   the guard as root and granting `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH`, or a world-readable copy)
   were rejected as broader than the problem.
