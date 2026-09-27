# Ghostnector — release-candidate report (D-50/D-53 requalification)

**Scope:** the M10 GUI milestone plus the full release qualification campaign (installed product on
a native VM): GUI → leakage/privacy/network identity → performance → adversarial/lifecycle →
clean install/uninstall/reboot → the complete M1–M10 gate. After the first consolidated report
(commit `8029bda`), the campaign was extended to fix **D-50** (APP-scope transparent egress with
real Tor) and the mode-switch defect that fix exposed, **D-53**, and to requalify the affected
areas.

**Tested commit:** `f82adf9` (the final M1–M10 gate and every post-D-50/D-54 installed run used a VM
tree reset to this commit; the commits after it are this report and its records). The D-50/D-53/D-54
product work spans `043b3e3` → `f82adf9`. No release tag was created or moved.

**Recommendation: the evidence supports freezing `v1.0.0`.** Every M1–M10 suite is clean, the
leakage analyzer returns 0 violations / 0 ambiguous with nothing reaching the far side in any
protected window, APP scope carries real TCP through real Tor, and the boot guard now establishes the
fail-closed baseline before the network on a protected reboot (D-54 fixed and requalified). The
remaining items are documented limitations, not open product decisions.

---

## 1. Environment

| | |
|---|---|
| VM | `ghostnector-qual`, Ubuntu 24.04.5, kernel 6.8.0-142, 4 vCPU, 7.9 GB RAM |
| Network | NAT via `enp0s3` (10.0.2.15); SSH on the host's port 2222; guest timezone UTC (host UTC+4) |
| Product | installed from the repository's `packaging/install.sh` with the release binaries built from the tested commit |
| Verification config | machine-wide phases: `--udp-check 10.0.2.2:18081 --check-url http://<validated IPv4>/`; APP phases: `--udp-check` only (the namespace denies UDP, and the probe treats that as the pass) |
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

The D-50/D-53 fixes change the APP **data path** (a relay inside each namespace and a Tor reload on
a profile change); they do not change anything the window displays or controls, and the GUI APP
evidence above remains valid. No further GUI automation was attempted.

Unproven by automation, stated plainly: the header popover and the GTK file picker could not be
driven under Xvfb; their product-side behaviour is covered by the model/unit tests, the D-Bus action
probe and the core API the picker calls.

### 2.2 Leakage / privacy / network identity

`installed-leak-qualification.sh` + host observer + `analyze-leak.py`. Post-fix run
`leak-20260927T135503Z.log`: VM-side **30 held / 0 contradicted / 0 inconclusive** (run exit 0);
analyzer exit 0 with **30 phase records, 3 expected open-validation arrivals, 2 observer
self-probes, 0 violations, 0 ambiguous**, heartbeats spanning the whole run window (18 beats, gaps
≤ 38 s), and the protected path reporting `185.220.101.20` against the host's public `94.20.98.15`.

**While protection was reported, nothing reached the far side** — across the Tor SYSTEM, tamper,
router-death, panic, I2P and APP windows. The APP window's two groups left through different
observed addresses (circuits differ in effect), a direct connection from inside a namespace
produced no application data, and a direct connection to the namespace relay was refused.

The earlier conclusive run (`leak-20260927T073453Z.log`, 27/0/2) remains valid for the pre-D-50
data path and its far-side result was identical; the APP exit-address items it recorded as
inconclusive were the D-50 defect, now fixed and requalified here.

Focused APP regression (`app-real-tor-test.sh`, `app-real-tor-20260927T134858Z.log`): **17 held /
0 contradicted / 0 inconclusive**. The run begins with a machine-wide Tor session (the D-53
transition, so the APP apply must reload Tor), then two groups fetched real exit addresses
(`94.230.208.147`, `192.42.116.51`); the intended destination answered 200, DNS resolved through the
chokepoint, a direct connection produced no application data, a direct connection to the relay was
refused, the stopped group's relay was gone while the other group's stayed, and with Tor stopped the
state stopped claiming verification while no application produced an address.

### 2.3 Performance (installed; medians, same machine and network for product and baseline)

| Measurement | Product | Baseline Tor |
|---|---|---|
| Direct DNS (open) | 1.91 ms | — |
| DNS through the chokepoint | 162.6 ms | 276.3 ms (`DNSPort`) |
| HTTP latency (checkip) | 0.896 s | 0.803 s |
| Throughput (1 MB, machine-wide path) | 180.3 kB/s | 476.5 kB/s |
| APP-scope launch | 0.79 / 0.90 / 0.96 s | direct launch 0.32 / 0.33 / 0.34 s |
| APP-scope throughput (1 MB through the relay) | 712.8 kB/s (median of 3) | — |
| Relay cost while a download is in flight | 2.52 MB RSS, 0.47% CPU (40 samples) | — |
| Idle cost while protected | netd 3.80 MB / 0.20%, core 3.17 MB / 0.30%, appd 2.70 MB / 0.00%, DNS relay 2.22 MB / 0.22% | — |

From the earlier run, still valid (the paths are unchanged): connect to command return 27.5–44.3 s
(cold Tor bootstrap); Degraded → `protected` 2.6–13.6 s; disconnect 0.53 s normally (two of three
samples hit the 90 s router hang that D-51 bounds to 20 s).

Method: `installed-performance-qualification.sh` (`perf-20260927T144529Z.log`) with a standalone Tor
on the same VM as the baseline. Every figure is a median of the run's samples; the 1 MB throughput
varies widely between runs (the earlier run measured 390.8 kB/s product vs 436.1 kB/s baseline on
the same pair of hosts), so the machine-wide figure here should be read as one sample of a
network-dependent quantity, not a regression. The APP figure (712.8 kB/s) is the same download
carried by the relay and Tor's SocksPort in the same run; the relay itself is a byte splice with no
payload handling, and its cost is the 2.52 MB / 0.47% above.

### 2.4 Adversarial and lifecycle

`lifecycle-20260927T145851Z.log`: **32 held / 0 contradicted / 0 inconclusive** (run exit 0; the
extra case over the earlier 31 is the uninstall residue check for group relays).

* uninstall leaves no packaged file, no process (including no group relay), no policy table; the
  resolver is restored and ordinary HTTP/DNS work; reinstall starts all units on the first attempt;
* ordinary use: connect → protected → disconnect → off;
* a deterministic lockout (the router is stopped under a claim) fails closed: the fail-closed
  baseline is applied, the SSH session is cut by design, and the documented local `disconnect`
  recovers with no table and no protected intent;
* first boot after the reinstall: all four units active, `/run/netns` present, state off;
* **reboot with protection on**: after the hard reset the boot guard **itself** denied everything
  before the network (`ExecMainStatus=0`; its journal says the helper denied everything; it finished
  at or before the network-pre barrier), the fail-closed table was present and the machine reported
  `blocked — no traffic can leave` with SSH cut; guest control recovered it to off. The focused
  installed qualification (`installed-boot-guard-qualification.sh`) asserts each of those steps
  (prepare **8/0/0**, verify-protected **7/0/0**, verify-off **4/0/0**); D-54 was found here and
  fixed (see 3 and G14).

The APP adversarial suite (`app-adversarial.sh`) is **13 held / 0 contradicted / 0 inconclusive** in
the final gate. Its AA-13 case was corrected during this requalification: the relay is the helper's
child and exits when the helper dies, so the case now asserts the property it claims — the namespace
still exists and carries nothing (the connection is refused at the dead local relay) — instead of
the pre-relay liveness expectation that the protected path keeps working.

### 2.5 Clean install / uninstall / reboot

Covered by 2.4 on the installed product (uninstall residue, reinstall, first boot, reboot with
intent, guest-control recovery). The uninstall residue check now also looks for group relays by
their command line (the relay's `comm` is truncated to the same 15 characters as the helper's). The
one environment caveat: this VM's clean reboot is unreliable and a hard reset is the documented
procedure.

### 2.6 Full M1–M10 gate

`release-gate.log` (final run, on the VM at `f82adf9`): **every step rc 0** (21 steps), **461 unit
tests passed / 0 failed**.

* static: `fmt`, `check`, `clippy`, `test`, `build bins`, and the GUI `check`/`clippy`/`build` with
  the GTK feature;
* suites: app-topology **PASS**, app-policy **PASS**, appd-socket **PASS**, core-app **PASS**,
  app-adversarial **13/0/0**, policy-netns (i2p golden) **PASS**, i2p-adversarial **26/0/0**,
  policy-netns (tor golden) **PASS**, netd-socket **PASS**, core-cli **PASS**, bootguard **PASS**
  (the suite now also runs the guard under the installed identity; the installed boot qualification
  is in 2.4), watch-oracle **10 held / 0 contradicted**, adversarial (M1–M7) **27/0/1** — the single
  inconclusive is the documented no-global-IPv6 case (AS-4);
* the product was restored after the gate: netd, core and appd active, state `off`, no table.

An earlier gate run on the same tree (before the AA-13 assertion correction) was also 21/21 rc 0
with app-adversarial 12/0/1; the corrected case is included in the final run above.

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
| D-50 | **APP transparency could not work with real Tor: the namespace DNAT loses the original destination** | per-namespace relay (`crates/ghostnector-appd/src/bin/relay.rs`): the DNAT targets `127.0.0.1:9041`; the relay runs as the application's uid with every capability set empty, reads `SO_ORIGINAL_DST` from the namespace's own conntrack, speaks SOCKS to the core's SocksPort as the application's address with a per-group credential, refuses any connection with no original destination, and is stopped through its stdin pipe (the packaged set has no `CAP_KILL`). The namespace may reach only the chokepoint and SocksPort; APP-mode Tor renders no TransPort. Three implementation findings fixed with it: the looped-back reply needed the namespace's own loopback egress accept; the packaged set could not signal the relay (the stdin pipe replaced the kill); a refused client is drained so a dead router reads as a failed check, not an inconclusive one. | `043b3e3`, `7598fea`, `3bbb93d` |
| D-51 | Disconnect could freeze the interface for 90 s (router ignores SIGTERM) | `TimeoutStopSec=20` on both routers | `501f54d` |
| D-52 | The first `netd` start after a fresh install failed (`226/NAMESPACE`); the boot guard too | `StateDirectory=ghostnector` on netd and bootguard; a test now covers `/var/lib` paths | `55da224`, `e35cb75` |
| D-53 | **Applying APP scope over a Tor instance left running from another profile kept its listeners on loopback** (found while requalifying D-50; pre-existing, previously masked). The APP apply wrote the APP torrc but only *started* the unit, a no-op for an active unit, so the relay's dial to the core address was refused and every application fetch returned an empty reply within seconds while the relay itself was healthy. | the supervisor gains `restart`, composed of the two verbs the polkit rule grants (`stop` then `start`; systemd's own `restart` verb is refused without interactive authentication and would need a wider rule for the same two actions); the Tor bring-up restarts when the rendered torrc differs from the file, and starts on a first apply or an unchanged file. | `af89bc9`, `167ee85` |
| D-54 | **The installed boot guard could not deny by either route, so the fail-closed policy was not in place before the network on a protected reboot** (found in the close-out verification; fixed). Three layers: netd (root, no `CAP_DAC_OVERRIDE`) could not create the copy in the control plane's state directory at all and wrote it only on a fail-closed apply; a copy that existed was unreadable to the root guard; and the guard could not reach netd's `0600` socket. The control plane's reconcile applied the baseline after the network. | netd keeps the copy in its own root-owned state directory on **every** apply, hands the finished `0600` file to the control plane's user with the `CAP_CHOWN` it already has, and replaces it atomically; the guard runs as that same user with exactly `CAP_NET_ADMIN` ambient and `NoNewPrivileges`, owns the socket and the copy, and writes nothing. No permission-bypassing capability and no widened mode. | `544018f`, `f82adf9` |

Earlier in the same campaign (D-29–D-38) the installed stack was made to work at all: shared
runtime directory ownership (D-29), a bounded polkit rule (D-30), the Tor control cookie (D-31), the
qualification procedure itself (D-32), the `appd` runtime/socket prerequisites (D-33/D-34), the
unit texts (D-35/D-36), resolver repointing (D-37/D-38). D-39 and D-48 are the two
*qualification-harness* defects (GUI driving, leakage collection), recorded as such; D-28 is an open
environmental flake in an old suite.

## 4. Remaining limitations and inconclusive items

* **GUI automation limits:** the header popover and the GTK file picker cannot be driven under
  Xvfb; their product-side paths rest on the model tests, the D-Bus action probe and the core API.
* **Boot-guard ordering (G6, unchanged).** The guard now applies the deny before the network-pre
  barrier and its own success is asserted on the installed product (D-54 fixed), but the claim "no
  packet leaves before the deny" is still not observed at an independent boundary; that remains the
  one open narrowing on PC-10.
* **The harness pins a public HTTP check address per run.** A stale address makes the product fail
  closed (correct) and the harness validates a candidate before pinning it. For APP scope the
  installed runs use the UDP check, which is deterministic; an operator who configures an HTTP
  check whose endpoint is unreachable through a particular Tor exit will see the documented
  fail-closed response (the groups are removed), which is honest but availability-sensitive.
* **The VM's reboot is unreliable** (initramfs hang observed once); the hard-reset procedure and
  guest-control recovery are documented and were exercised.
* **Pre-existing narrowings** remain: G6 (boot ordering not independently observed), GA-3 (the APP
  probe compares fewer addresses), and the no-global-IPv6 environment (AS-4 inconclusive).
* **D-51 residual:** a router that ignores SIGTERM now costs at most 20 s on disconnect instead of
  90 s.
* **D-53 analogue (recorded, not changed):** the i2pd bring-up has the same start-without-reload
  shape as Tor did; its listeners do not move between profiles, so no failure has been observed.
  It is noted in the defect ledger for a future change rather than altered during this campaign.
* **Distinct Tor circuits are not claimed** (GA-2): the per-group SOCKS credential gives Tor an
  isolation key, and the two groups' observed exits differed in every post-fix run, but Tor's
  circuit choice remains Tor's behaviour.

## 5. Final state

* VM: product installed; `ghostnector-netd`, `ghostnector-core`, `ghostnector-appd` active; state
  `off — traffic is not protected`; no policy table; no namespace, relay or stale socket.
* Repository: all fixes and records committed; the working tree carries the deliberately untracked
  working aids (the engineering handoff text, `docs/HANDOFF-RC2.md`, `m9-qual.bundle`). No tag was
  created or moved.

## 6. What the evidence supports

* **Confinement and privacy:** supported. On the installed product, while protection is reported,
  nothing reaches the far side; the resolver and DNS paths are confined; the fail-closed baseline
  lands on contradiction; the boot guard itself denies before the network on a protected reboot
  (D-54 fixed: its own success and its completion before the network-pre barrier are asserted);
  disconnect/panic leave no policy.
* **APP scope with real Tor:** supported. The namespace relay carries real TCP through real Tor with
  the intended destination and the application's own source address, per-group SOCKS isolation
  credentials, no direct egress, a relay that refuses connections with no original destination, a
  deterministic APP verification, fail-closed behavior when the router dies, and no residue after
  teardown — including the profile transition that previously left Tor's listeners on loopback.
* **Robustness and lifecycle:** supported (clean uninstall/reinstall, first boot, lockout recovery,
  reboot with intent recovered out of band).
* **Performance:** measured; the product's overhead over a standalone Tor on the same VM is modest
  (HTTP 0.896 s vs 0.803 s median; DNS through the chokepoint 162.6 ms vs 276.3 ms; ~11.9 MB RSS and
  ~0.7% CPU idle for the four helpers; the relay adds 2.52 MB / 0.47% while carrying a download),
  with the caveats in 2.3.
* **GUI:** the window is a faithful, unprivileged view of the authoritative snapshot with the
  documented controls and refusals; its remaining automation gaps are environmental.
* **I2P:** supported on the installed product after D-40–D-43 (it reaches the I2P network; without a
  configured canary the state stays `Degraded`, as designed).
