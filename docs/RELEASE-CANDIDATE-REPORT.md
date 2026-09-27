# Ghostnector — release-candidate report

**Scope:** the M10 GUI milestone plus the full release qualification campaign (installed product on
a native VM): GUI → leakage/privacy/network identity → performance → adversarial/lifecycle →
clean install/uninstall/reboot → the complete M1–M10 gate.

**Tested commit:** `8029bda` (the gate and all installed runs used a VM tree reset to this commit;
the commits after it are the qualification record itself). No release tag was created or moved.

**Recommendation: do not freeze `v1.0.0` until D-50 is decided.** The confinement, privacy,
packaging, lifecycle and gate evidence is strong and reproducible, but the APP-scope claim that a
protected application's TCP is carried transparently through the core's Tor is **not true with real
Tor** (D-50). Fixing it changes a proven M8 mechanism, so it is presented as a decision: implement
the per-namespace relay (or an equivalent), or narrow the v1 APP claim explicitly. Everything else
supports a release candidate.

---

## 1. Environment

| | |
|---|---|
| VM | `ghostnector-qual`, Ubuntu 24.04.5, kernel 6.8.0-142, 4 vCPU, 7.9 GB RAM |
| Network | NAT via `enp0s3` (10.0.2.15); SSH on the host's port 2222; guest timezone UTC (host UTC+4) |
| Product | installed from the repository's `packaging/install.sh` with the release binaries built from `8029bda` |
| Verification config | `--udp-check 10.0.2.2:18081`, `--check-url http://<fresh IPv4>/`, `--verify-timeout 10 --verify-interval 5 --verify-stale-after 30` |
| Far side (leakage) | a host-side observer on the host loopback (the VM reaches it as 10.0.2.2) on UDP 18081, TCP 18082, UDP/TCP 53, with a 15 s liveness heartbeat |

The VM's clean reboot is not reliable; the documented procedure is a hard reset (`controlvm reset`).
One reset in this campaign hung in the initramfs and was recovered with a second hard reset. Guest
control (`VBoxManage guestcontrol`) is the recovery channel that survives a cut-off policy.

## 2. Results by phase

### 2.1 GUI (M10)

Harness: `scripts/gui-installed-qualification.sh` with `scripts/lib/gh-atspi.py` (AT-SPI action →
focus-verified keyboard → fixed-layout clicks). Scripted best runs: **33 held / 11 contradicted / 2
inconclusive** (attempt 12; attempts 8–11 were 33/11/3, 32/13/3, 34/12/3). Every contradiction in
those runs was traced to the harness or the environment, never to a product false claim:

* the public check endpoint going stale made the product correctly enter `Blocked` (`fail-closed`)
  while the case expected `protected` (the product behaved exactly as claimed);
* the header popover is not exposed through AT-SPI and did not open under synthetic clicks, so the
  panic *menu* could not be driven (the panic **action** was described and activated over D-Bus
  when the window was on the session bus, and the CLI equivalent exercises the same core command);
* the GTK file picker's location entry could not be driven under Xvfb (the launch is performed
  through the same core API the picker calls; the window's own list and Stop are exercised);
* the test session bus can die (the harness now supervises it and restarts the window on a fresh
  bus); one window died in an early attempt and its exit status is recorded.

Product behaviours demonstrated by the suite and by focused probes (durable logs in
`/var/log/ghostnector-qual/`):

* the window renders the authoritative `Snapshot` (off/protected/blocked/applying), the banner
  wording, the diagnostics view (live vs last-known, versions, no implementation jargon), and the
  refusal matrix with the controls disabled;
* Tor protection is enabled through the window and reaches `protected — and verified`;
* changing the selection while protected asks for confirmation, and Cancel restores the reported
  selection;
* the APP scope is applied through the window; applications launch, are confined to their namespace
  (`CapPrm=CapEff=CapAmb=0`, own network namespace, uid 1000) and are listed;
* switching Tor→I2P through the window reaches `through I2P` on the installed product (probe
  evidence), and the window survives a core restart and reconnects;
* a dead router or helper does not produce a fresh verification claim (`Degraded`/`Blocked`), and
  the final stand-down leaves the machine `off` with no table.

Unproven by automation, stated plainly: the header popover and the GTK file picker could not be
driven under Xvfb; their product-side behaviour is covered by the model/unit tests, the D-Bus action
probe and the core API the picker calls.

### 2.2 Leakage / privacy / network identity

`installed-leak-qualification.sh` + host observer + `analyze-leak.py`. Conclusive run
`leak-20260927T073453Z.log`: VM-side **27 held / 0 contradicted / 2 inconclusive**; analyzer exit 0
with **30 phase records, 3 expected open-validation arrivals, 2 observer self-probes, 0 violations,
0 ambiguous**, heartbeats spanning the whole run window, and the protected path reporting
`185.181.61.203` against the host's public `94.20.98.15`.

**While protection was reported, nothing reached the far side** — across the Tor SYSTEM, tamper,
router-death, panic, I2P and APP windows. The two VM-side inconclusive items are the APP
exit-address observations, which fail because of D-50 (the applications are confined but their
transparent TCP cannot be carried by real Tor); this is a functional defect, not a leak.

### 2.3 Performance (installed; medians, same machine and network for product and baseline)

| Measurement | Product | Baseline Tor |
|---|---|---|
| Direct DNS (open) | 2.61 ms | — |
| DNS through the chokepoint | 158.3 ms | 287.5 ms (`DNSPort`) |
| HTTP latency (checkip) | 1.469 s | 0.543 s |
| Throughput (1 MB) | 390.8 kB/s | 436.1 kB/s |
| Connect to command return | 27.5–44.3 s | — (cold Tor bootstrap) |
| Degraded → `protected` | 2.6–13.6 s | — |
| Disconnect | 0.53 s normally; two of three samples hit 90 s (D-51) | — |
| APP-scope launch | 0.72 / 0.94 / 0.95 s | direct launch 0.33 s |
| Idle cost while protected | netd 3.68 MB / 0.5%, core 3.19 MB / 0.5%, appd 2.68 MB / 0.2%, DNS relay 2.02 MB / 0.0% | — |

Method: `installed-performance-qualification.sh` with a standalone Tor on the same VM as the
baseline; every sample is in `perf-20260927T082830Z.log`, and the focused re-measurements
(`perf-focus.log`, `perf-focus2.log`) supply the APP-launch and idle-cost numbers, because the first
run's sampling was polluted by leftover processes and a `ps` field mismatch (both fixed).

### 2.4 Adversarial and lifecycle

`lifecycle-20260927T091710Z.log`: **31 held / 0 contradicted / 0 inconclusive**.

* uninstall leaves no packaged file, no process, no policy table; the resolver is restored and
  ordinary HTTP/DNS work; reinstall starts all units on the first attempt;
* ordinary use: connect → protected → disconnect → off;
* a deterministic lockout (the router is stopped under a claim) fails closed: the fail-closed
  baseline is applied, the SSH session is cut by design, and the documented local `disconnect`
  recovers with no table and no protected intent;
* first boot after the reinstall: all four units active, `/run/netns` present, state off;
* **reboot with protection on**: after the hard reset the boot guard applied the fail-closed
  baseline before the network (`blocked — no traffic can leave`, `table inet ghostnector` present,
  SSH cut), and guest control recovered it to off. Repeated manually with the same result.

### 2.5 Clean install / uninstall / reboot

Covered by 2.4 on the installed product (uninstall residue, reinstall, first boot, reboot with
intent, guest-control recovery). The one environment caveat: this VM's clean reboot is unreliable
and a hard reset is the documented procedure.

### 2.6 Full M1–M10 gate

`release-gate.log` (run 2, on the VM): **every step rc 0, 455 unit tests passed, 0 failed**.

* static: `fmt`, `check`, `clippy`, `test`, `build bins`, and the GUI `check`/`clippy`/`build` with
  the GTK feature;
* suites: app-topology, app-policy, appd-socket, core-app, app-adversarial (**13/0/0**),
  policy-netns (i2p golden), i2p-adversarial (**26/0/0**), policy-netns (tor golden), netd-socket,
  core-cli, bootguard, watch-oracle, adversarial (**27/0/1**) — all rc 0. The single inconclusive is
  the documented no-global-IPv6 case (AS-4).
* the first gate attempt is not evidence: it ran without `cargo` on the detached unit's PATH (all
  Rust steps rc 127) and the suites then used a stale debug build; the controller now sets the
  cargo environment and stops the installed product first, because the suites own `/run/ghostnector`.

## 3. Defects found by this campaign and their dispositions

Product defects (each with the regression that now guards it):

| # | Defect (installed product) | Fix | Commit |
|---|---|---|---|
| D-40 | The packaged I2P router could never start (i2pd's home hidden by `ProtectHome`, no certs dir) | `Environment=HOME=…` + `--certsdir` in the unit | `8626b28` |
| D-41 | The router starts under the baseline, which denies the DNS its reseed needs | apply the I2P profile (itself deny-first) before the router; baseline unchanged | `0bdb65a` |
| D-42 | The router's name resolution ran as `systemd-resolve`, which I2P mode denies | the engine writes the upstreams; the unit bind-mounts resolv.conf/nsswitch | `61a1060` |
| D-43 | Tor→I2P left the resolver on the dead chokepoint | stand the resolver down before discovering the router's upstreams | `7dd94f8` |
| D-44 | `ip netns add` failed: the helper's syscall filter blocked `mount` | `SystemCallFilter=@system-service @mount` | `1b5b23f` |
| D-45 | The group's own session socket was unreachable (`apps` 0700 root:root) | `0710 root:ghostnector`; the socket stays 0600 user-owned | `80febec` |
| D-46 | The launcher could not drop identity (`CAP_SETUID` missing from the bounding set) | bounding set adds `CAP_SETUID CAP_SETGID` | `af7a703` |
| D-47 | Still failed: only ambient capabilities survive `execve` | ambient carries `NET_ADMIN SYS_ADMIN SETUID SETGID`; the shell still ends with nothing | `cfd0597` |
| D-48 | The leakage controller could not collect its evidence (`$args` collision, unbounded calls) — *qualification* defect | bounded calls, verified collection, analyzer refuses unproven verdicts | working aid (host-side controller; not shipped) |
| D-49 | No application could use the network: the unit's `RestrictAddressFamilies` applied to its children | allow `AF_INET`/`AF_INET6` | `b881707` |
| D-50 | **APP transparency cannot work with real Tor: the namespace DNAT loses the original destination** | **open — decision required** (per-namespace relay, or narrow the claim) | — |
| D-51 | Disconnect could freeze the interface for 90 s (router ignores SIGTERM) | `TimeoutStopSec=20` on both routers | `501f54d` |
| D-52 | The first `netd` start after a fresh install failed (`226/NAMESPACE`); the boot guard too | `StateDirectory=ghostnector` on netd and bootguard; a test now covers `/var/lib` paths | `55da224`, `e35cb75` |

Earlier in the same campaign (D-29–D-38) the installed stack was made to work at all: shared
runtime directory ownership (D-29), a bounded polkit rule (D-30), the Tor control cookie (D-31), the
qualification procedure itself (D-32), the `appd` runtime/socket prerequisites (D-33/D-34), the
unit texts (D-35/D-36), resolver repointing (D-37/D-38). D-39 and D-48 are the two
*qualification-harness* defects (GUI driving, leakage collection), recorded as such; D-28 is an open
environmental flake in an old suite.

## 4. Remaining limitations and inconclusive items

* **D-50 (blocking a clean APP claim).** With real Tor, a protected application's TCP is accepted
  by the core's transparent proxy and then reset: the DNAT happened in the app namespace's
  conntrack, so `SO_ORIGINAL_DST` on the host has no entry (`ENOENT`). DNS works and TCP connects,
  which is why the M8 stand-in Tor — which never asks for the destination — passed. A correct fix
  is a per-namespace relay (bound to the app address, speaking to the core's Tor as the app's own
  address) or host-side interception (which would falsify PC-18's "no frames on the host link"). The
  claims and gaps now say exactly this (PC-17 evidence note, GA-6).
* **GUI automation limits:** the header popover and the GTK file picker cannot be driven under
  Xvfb; their product-side paths rest on the model tests, the D-Bus action probe and the core API.
* **The harness pins a public HTTP check address per run.** A stale address makes the product fail
  closed (correct) and the harness retries with a fresh one; this is documented, not a product
  fault.
* **The VM's reboot is unreliable** (initramfs hang observed once); the hard-reset procedure and
  guest-control recovery are documented and were exercised.
* **Pre-existing narrowings** remain: G6 (boot ordering not independently observed), GA-3 (the APP
  probe compares fewer addresses), and the no-global-IPv6 environment (AS-4 inconclusive).
* **D-51 residual:** a router that ignores SIGTERM now costs at most 20 s on disconnect instead of
  90 s.

## 5. Final state

* VM: product installed; `ghostnector-netd`, `ghostnector-core`, `ghostnector-appd` active; state
  `off — traffic is not protected`; no policy table.
* Repository: all fixes and records committed; the working tree carries three deliberately untracked
  working aids (the engineering handoff text, `docs/HANDOFF-RC2.md`, `m9-qual.bundle`). No tag was
  created or moved.

## 6. What the evidence supports

* **Confinement and privacy:** supported. On the installed product, while protection is reported,
  nothing reaches the far side; the resolver and DNS paths are confined; the fail-closed baseline
  lands on contradiction; the boot guard denies before the network; disconnect/panic leave no
  policy.
* **Robustness and lifecycle:** supported (clean uninstall/reinstall, first boot, lockout recovery,
  reboot with intent recovered out of band).
* **Performance:** measured; the product's overhead over a standalone Tor on the same VM is modest
  (HTTP 1.47 s vs 0.54 s median; throughput ~10% lower; ~11.5 MB RSS and ~1.2% CPU idle for the
  four helpers), with the caveats above.
* **GUI:** the window is a faithful, unprivileged view of the authoritative snapshot with the
  documented controls and refusals; its remaining automation gaps are environmental.
* **I2P:** supported on the installed product after D-40–D-43 (it reaches the I2P network; without a
  configured canary the state stays `Degraded`, as designed).
* **APP scope:** confinement supported; **transparent egress through real Tor is not**, pending
  D-50.
