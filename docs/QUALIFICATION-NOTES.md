# Qualification environment notes

These are environment facts and workarounds for the native Ubuntu 24.04 VirtualBox VM used to
qualify Ghostnector. They are **not product behavior**: nothing here changes what Ghostnector
enforces or claims. They are recorded so a future run can reproduce the qualification and can tell
environment artifacts apart from product findings.

## The VM

* `ghostnector-qual`: Ubuntu 24.04.5 LTS, kernel 6.8.0-142-generic, nftables 1.0.9, 4 vCPU, 8 GB,
  VirtualBox NAT with `ssh,tcp,127.0.0.1:2222,,22`. User `ghost` (passwordless sudo), SSH key
  `~/.ssh/ghost-qual`, timezone UTC.
* Real packages used by the qualification: `tor 0.4.9.11`, `i2pd 2.61.0` (official release),
  `libgtk-4-1`/`libgtk-4-dev 4.14`, `Xvfb`, `xfwm4`, `xdotool`, `wmctrl`.
* **`/tmp` is a tmpfs.** Everything written there (qualification logs, staged scripts) is lost on
  reboot. Durable evidence goes under `/var/log/` or `/var/lib/`.
* **A guest-initiated reboot can hang on this VM.** Twice a `systemctl reboot` (and once a
  `reboot -f` from a rescue shell) left the VM `running` but never completing the transition:
  VBoxService stopped, console blank, sshd gone, no CPU activity, and the state never came back.
  `VBoxManage controlvm ghostnector-qual reset` boots it normally afterwards (the journal recovers
  the filesystem). The qualification therefore treats "no SSH after a reboot" as reset-and-retry,
  with a bounded wait, rather than assuming the product blocked the network.
* **`systemd-analyze verify` is part of the installed qualification.** It found `KeepCapabilities=`
  (a directive that does not exist) and `Documentation=` references to files the package never
  installed (D-35/D-36); both were invisible in the source tree.

## Environment-only changes

* **Boot order set to disk first** (`VBoxManage modifyvm ghostnector-qual --boot1 disk --boot2 dvd
  --boot3 none --boot4 none`). A hard reset spent a long time in PXE before reaching GRUB; the
  product does not care about boot order, the qualification harness does.
* **GRUB rescue via console scancode injection.** When a fail-closed policy blocks SSH (by design),
  the documented rescue path (`docs/RECOVERY.md`, option 3) is the way out: reboot, edit the kernel
  line in GRUB with `init=/bin/bash`, then
  `mount -o remount,rw /`, `nft destroy table inet ghostnector`, `rm -f
  /var/lib/ghostnector/intent.json`, `reboot -f`. On a headless VM the keystrokes were injected with
  `VBoxManage controlvm ... keyboardputscancode` (or `keyboardputstring`); on a machine with a
  console, type them. The console is also reachable while the policy is applied — the policy blocks
  packets, not the local login — so the preferred recovery is to log in on tty1 and run
  `ghostnector disconnect`, and only reboot when that is impossible.
* **Host-side verification endpoints.** VirtualBox NAT exposes the host's loopback at `10.0.2.2`.
  A UDP echo on 18081 and an HTTP server on 18082 were run on the host. The **HTTP check that goes
  through Tor must use a public address**: `10.0.2.2` is private and Tor refuses private destinations
  on its TransPort ("Rejecting request for anonymous connection to private address"), which is
  correct Tor behavior. The qualification resolves `checkip.amazonaws.com` to an IPv4 literal and
  pins it, because the verifier takes a `SocketAddr`. The **UDP check may use `10.0.2.2`**: the
  verifier treats any answer as a leak, so the expected outcome there is silence, and `connect
  --lan` with it is refused by D-26.
* **GUI qualification display.** Xvfb (`:90`-`:95`) plus `xfwm4` as the window manager, so window
  close goes through the real `WM_DELETE_WINDOW` path (`wmctrl -c`); `GSK_RENDERER=cairo
  GDK_BACKEND=x11` because the GL renderer under Xvfb does not take input reliably. Screenshots via
  ImageMagick's `import -window root -screen`.

## Product behavior that looked like environment trouble

* **Starting system-wide protection cuts remote SSH immediately.** The fail-closed baseline is
  applied first (deny-first), so the SSH server's replies are dropped from the first second of
  `connect`, even though the state is still `applying`. Transparent Tor carries outbound TCP only,
  so there is no way to keep an inbound SSH session across a SYSTEM-scope connect. Drive the
  qualification from a detached script that disconnects when done, or use the console.
* **A verification failure blocks the machine and repeats its check every interval.** With the
  default `--verify-interval 300`, a failing check re-runs every five minutes; Tor's journal shows
  the matching warning each time. That is the designed bounded behaviour, not a hang.
* **A persisted Blocked intent re-applies the baseline on the next start.** If a `connect` fails
  and the policy cannot be shown to be absent, the journal records `fail_closed`. Restarting
  `ghostnector-core` (an install, a rebuild, a reboot) then correctly re-applies the deny-first
  baseline, which cuts SSH. This is the designed fail-closed behavior; the procedure must
  `disconnect` (or remove the intent) *before* restarting the control plane, and must never rely on
  the SSH session that its own test can sever.

## The second lockout (2026-09-26, 17:54–18:31 UTC) — reconstructed evidence

The chat that drove this campaign died (a request-size limit), not the VM; the VM was alive and, in
the end, sitting in a documented `init=/bin/bash` rescue shell. The reconstructed chain:

1. The installed machine still had **D-29**: `/run/ghostnector` was not writable by the
   `ghostnector` account or not creatable by netd, and `ghostnector-netd` was dead
   (`cannot use socket '/run/ghostnector/netd.sock': Permission denied`, restart counter 51→52,
   then start-limited).
2. A detached qualification at 17:54:15Z wrote `/etc/ghostnector/core.env` and ran
   `ghostnector connect`. The connect failed at once against the dead helper:
   `the helper's socket '/run/ghostnector/netd.sock' cannot be trusted: No such file or directory
   (os error 2) (BackendFailure)`. The engine reported
   `blocked — no traffic can leave`, `policy: not applied`, with the honest reason "connecting
   failed and the policy could not be withdrawn, so the machine is treated as denied", and recorded
   `intent.json` as `{"protected": true, "profile": "fail_closed", "generation": 2}`.
   **No policy was applied**, so SSH still worked at this point.
3. A background resync-and-reinstall job (started 17:58:29Z) rebuilt and reinstalled the tree with
   the D-29/D-30/D-31 fixes, then restarted `ghostnector-core` at 18:00:35Z. `reconcile()` read the
   persisted Blocked intent, found nothing applied, applied the fail-closed baseline and reported
   `state: Blocked, applied: true` — correctly. From that second, every SSH reply was dropped; the
   background job's log stopped at the `install.sh` output and the SSH client waited forever.
4. The operator then reset the VM and used the GRUB rescue path. The intent journal was still on
   disk and was preserved before clearing (`/root/lockout2/var-lib-ghostnector/intent.json`); the
   original was removed and the machine came up open.

Nothing in this chain is a product hang or crash. The product denied on ambiguity, said why, and
kept the documented way out. The defects were procedural: restarting the control plane with a
persisted Blocked intent without neutralising it first, driving that install over the session the
result cuts, writing evidence to `/tmp`, and having no detached cleanup.

## The qualification procedure now (D-32/D-33)

* `scripts/installed-qualification.sh` runs the installed stack with real Tor. It is meant to be
  started detached (`systemd-run` with `RuntimeMaxSec`, or `setsid nohup`), writes its record to
  `/var/log/ghostnector-qual/<timestamp>.log` (durable, `latest.log` symlink), bounds every phase,
  and **always ends in `disconnect`**; if that cannot restore the machine it falls back to the two
  documented rescue steps (`nft destroy table inet ghostnector`, remove the intent journal) before
  exiting. It also resets the baseline before starting, so a stale Blocked intent cannot lock the
  machine mid-run.
* The install/rebuild procedure must `ghostnector disconnect` (or remove the intent) **before**
  restarting `ghostnector-core`, and must not depend on the SSH session it is about to cut.
* `/run/netns` is created by `packaging/tmpfiles.d/ghostnector.conf`; without it the namespace
  helper cannot start at all on a fresh boot (D-33). The helper's socket lives in the root-owned
  `/run/ghostnector/appd/`, because it runs as root without `CAP_DAC_OVERRIDE` and cannot write in
  the control plane's directory (D-34).
* The installed qualification also requires `systemd-analyze verify` to be clean for all six units
  (it found D-35/D-36) and asserts that the control plane can read `/proc/net/route` (D-37) and is
  authorized to repoint the resolver (D-38); the machine carries two bounded polkit rules for
  exactly those two jobs.

## Installed-stack qualification record (2026-09-26, after D-29–D-38)

Run as a transient unit (`systemd-run --unit=ghostnector-qual --property=RuntimeMaxSec=1500`),
real Tor 0.4.9.11 from the packaged `ghostnector-tor.service`, public HTTP check
(`checkip.amazonaws.com` pinned to an IPv4 literal), UDP check to the host NAT endpoint, durable log
at `/var/log/ghostnector-qual/20260926T192852Z.log` (the run before the resolver fixes) and
`latest.log`. The final run: **22 held, 0 contradicted, 0 inconclusive**. It proved, on the installed
machine:

* all six units verify clean with `systemd-analyze verify`;
* both sockets exist, are trusted, and are owned as the units say (D-29);
* the polkit bound: the service account may start/stop the two routers, and is refused `cron`,
  `restart` and an ordinary-user attempt (D-30);
* managed Tor bootstraps to 100% and the control cookie is `debian-tor:ghostnector 0640` (D-31);
* the namespace helper and `/run/netns` work on a fresh boot (D-33/D-34);
* connect reaches `protected — and verified` through real Tor, with UDP denied, the protected path
  answering with an address that is not this machine, and the effective policy compared;
* systemd-resolved is repointed at the chokepoint (`resolvectl` shows `127.0.0.1`) and the
  `/proc/net/route` note is gone (D-37/D-38);
* disconnect returns the machine to `off`, with no table applied, and SSH returns by itself.

The qualification is safe to run over SSH because it is detached, bounded, logs durably, and always
ends in `disconnect` (with the documented rescue as a fallback): the run cut SSH for ~90 seconds and
restored it without any manual step.

## Installed I2P: D-40, D-41, D-42

The GUI qualification's I2P selection exposed that installed I2P mode was dead, and fixing it took
three defects in sequence (each only visible after the previous one was fixed):

1. **D-40** — the packaged `ghostnector-i2pd.service` could not start: i2pd stats `$HOME/.i2pd`
   before reading its configuration, the package user's home `/home/i2pd` does not exist, and
   `ProtectHome=yes` turns that into `EACCES`; the unit also omitted the package's certificate
   directory. Fixed with `Environment=HOME=/var/lib/ghostnector-i2pd` and
   `--certsdir=/usr/share/i2pd/certificates`.
2. **D-41** — the router starts under the fail-closed baseline, which (correctly) exempts only
   Tor's uid, so the I2P profile (itself a deny-everything-except-the-router policy) is now applied
   *before* the router starts. The baseline never carries the I2P uid; PC-22's mutually-exclusive
   exemption model is unchanged.
3. **D-42** — the router's name resolution ran as `systemd-resolve` through resolved's stub, an
   identity I2P mode denies, so reseed failed with `Host not found` even under the router's own
   policy. The engine now discovers the machine's upstream nameservers and writes
   `/run/ghostnector/i2pd-resolv.conf` and a minimal `i2pd-nsswitch.conf`; the unit bind-mounts them,
   so the router's queries leave from its own exempt uid.

Verified on the installed VM after a rebuild: `connect --network i2p` applies `I2pSystem`
(`i2pd unit: active`, a proxy listener on 4444, exactly one `skuid` exemption), and `disconnect`
returns to `off`. The state is `Degraded` rather than `Protected` because the shipped unit has no
I2P canary configured; the canary path was qualified natively in M9.5 (real i2pd, real canary) and
can be configured per machine with the operator's canary.

## Installed APP scope: D-44

The GUI qualification's APP lifecycle found that `ghostnector run` could not create a namespace on
the installed product: `ghostnector-appd.service` had `SystemCallFilter=@system-service`, and
`ip netns add` needs `mount --make-shared /run/netns`; `mount` is not in that set, so every launch
failed with `mount --make-shared /run/netns failed: Operation not permitted`. The unit now allows
`@mount` (the helper already holds `CAP_SYS_ADMIN` for exactly this work), the hardening test
requires it, and the installed `ghostnector run` launches an application inside its namespace while
the window lists and stops it.

The GTK file picker remains a harness limitation: under Xvfb the chooser opens and its tree is
visible, but its location entry did not accept a typed path from the automation, so the launch is
performed through the same core API the picker calls. The picker's own widgets are GTK's, not the
product's.

**D-45** was found immediately after D-44: the namespace existed and the group was listed, but the
invoking user could not reach its own session socket because `/run/ghostnector/apps` was
`0700 root:root`. It is now `0710 root:ghostnector` — traversable by the accounts that may control
Ghostnector, not listable — while the socket itself stays `0600` owned by that user.

**D-46, D-47** completed the chain. D-46 added `CAP_SETUID`/`CAP_SETGID` to appd's bounding set so
the launcher could drop identity at all; D-47 found that this was still not enough: an exec'd child
does not inherit the permitted or effective sets, only the ambient set survives `execve`, so the
launcher still had no `CAP_SETUID` and every launch died with `cannot set uid 1000: EPERM`. The
unit's ambient set now carries everything a child needs
(`CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SETUID CAP_SETGID`); the launcher still clears every granting set
before it execs the user's shell (measured: `CapPrm=CapEff=CapAmb=0`), and the same fix restores
`ip netns add`'s `CAP_SYS_ADMIN` in a child — it had only worked because `/run/netns` was made
shared by hand during the D-44 investigation. The hardening test now names the ambient set and
refuses `CAP_CHOWN` ambient.

**D-49** was the last link: with the launcher working, the group was still torn down within three
seconds and no application could use the network. The helper's unit restricted address families to
`AF_UNIX AF_NETLINK`, and systemd applies that to the whole unit tree — the verification probe and
the user's application are children of the helper, so their `AF_INET` sockets failed with
`EAFNOSUPPORT`, the verification failed (correctly) and the engine removed every namespace. The unit
now allows `AF_INET`/`AF_INET6`; the helper's own code still opens only unix and netlink sockets.

## Performance qualification (installed, 2026-09-27)

Method: the same machine, the same network, measured twice — through the product's transparent Tor
path and through a standalone Tor instance started on the same VM for the baseline. Medians over
repeated samples; every sample is in `perf-20260927T082830Z.log`.

| Measurement | Product | Baseline Tor | Notes |
|---|---|---|---|
| Direct DNS (open) | 2.61 ms | — | the VM's own resolver |
| DNS through the chokepoint | 158.3 ms | 287.5 ms (Tor `DNSPort`) | the chokepoint adds Tor's DNS path in both cases |
| HTTP latency (checkip) | 1.469 s | 0.543 s | five samples each; the product path includes the transparent redirect |
| Throughput (1 MB) | 390.8 kB/s | 436.1 kB/s | two samples each; ~10% below baseline on this VM |
| Connect to return | 27.5–44.3 s | — | cold Tor bootstrap each run |
| Return to `protected` after connect | 2.6–13.6 s | — | first verification through Tor |
| Disconnect | 0.527 s normally; two of three run samples hit 90.5 s | — | the 90 s samples are D-51; bounded to 20 s from here |
| APP-scope launch | 0.72 s / 0.94 s / 0.95 s (focused rerun) | direct launch 0.33 s | the run's own APP numbers were polluted by leftover processes and are superseded by the focused rerun |
| Product idle cost while protected | netd 3.68 MB / 0.5%, core 3.19 MB / 0.5%, appd 2.68 MB / 0.2%, DNS relay 2.02 MB / 0.0% | — | 10 samples, 1 s apart, excluding Tor itself |

The performance script's resource summary and APP-launch sampling were corrected after this run
(the `ps` field/comm mismatch printed zero means, and a leftover application could satisfy the
launch check); the table above uses the focused re-measurement.

## Lifecycle and adversarial qualification (installed, 2026-09-27)

`lifecycle-20260927T091710Z.log`: **31 held / 0 contradicted / 0 inconclusive** on the final run.

* uninstall: every packaged file gone, no process, no policy table, the resolver restored, ordinary
  HTTP and DNS working;
* reinstall: all three units active on the first attempt (after D-52);
* ordinary use: connect → protected → disconnect → off;
* deliberate lockout (deterministic): protected, the router is stopped, the next verification
  fails, the fail-closed baseline is applied (the SSH session driving the runs is cut by design),
  and the documented local `disconnect` recovers to off with no table and no protected intent;
* first boot after the reinstall (hard reset): all four units active, `/run/netns` present, state
  off;
* adversarial reboot with protection on: the intent was `protected — and verified`; after the hard
  reset the boot guard applied the fail-closed baseline before the network — `blocked — no traffic
  can leave`, the policy table asserted present (`table inet ghostnector`), SSH cut — and guest
  control (the VMMDev channel) recovered it to off. The same sequence was repeated manually with
  the same result.

## Full M1–M10 gate (installed VM, 2026-09-27)

`release-gate.log` (run 2): every step returned 0, **455 unit tests passed, 0 failed**.

* static: `fmt`, `check`, `clippy`, `test`, `build bins`, and the GUI `check`/`clippy`/`build` with
  the GTK feature — all rc 0;
* suites: app-topology, app-policy, appd-socket, core-app, app-adversarial (**13 held / 0
  contradicted / 0 inconclusive**), policy-netns (i2p golden), i2p-adversarial (**26/0/0**),
  policy-netns (tor golden), netd-socket, core-cli, bootguard, watch-oracle, and adversarial
  (**27/0/1**) — all rc 0. The single inconclusive is the documented IPv6-environment case (AS-4:
  this VM has no global IPv6, so a failure there proves nothing).

Environment notes, recorded because the first attempt was not evidence: the gate needs `cargo` on
the detached unit's PATH (the first run had rc=127 for every Rust step and the suites then used a
stale debug build), and it must run with the installed product stopped, because the suites create
their own cores and helpers on `/run/ghostnector`. The appd-socket test's simulated "packaged
capability set" had gone stale after D-46/D-47 and now mirrors the unit; the hardening test still
pins the unit itself.

## Leakage qualification (installed, far-side observation)

Method: a host-side observer (outside the VM, reached through the NAT as `10.0.2.2`) listens on UDP
18081, TCP 18082, UDP 53 and TCP 53 and timestamps every arrival; it emits a heartbeat every 15 s.
The VM-side script records `PHASE <name> <vm-epoch>` markers around each window and probes the far
side in the open window (expected arrivals) and in every protected window (must be silent). The
controller measures the VM/host clock offset before the run, collects the durable log and verifies
it really contains its phases, then correlates arrivals against phases with the offset. A verdict
is refused (exit 3) when there are no phases, no open-validation arrival (the channel would be
unproven), or the observer's last heartbeat predates the end of the run.

Result of the conclusive run (`leak-20260927T073453Z.log`, VM-side **27 held / 0 contradicted / 2
inconclusive**; analyzer exit 0 after the heartbeat check was corrected): 30 phase records; the only
far-side arrivals were the three open-validation probes (HTTP, UDP, DNS) and the two observer
self-probes; **zero arrivals in any protected, tamper, router-death, panic, I2P or APP window**; the
protected path reported `185.181.61.203` against a host public address of `94.20.98.15`; the
observer's heartbeats span the whole run window. The two VM-side inconclusive items are the APP
exit-address observations: the applications launch, are confined and are listed, but their
transparent TCP cannot work with real Tor (D-50) — the addresses are therefore absent, and this is a
functional defect rather than a leak. Earlier, the run-3 evidence (30 phases, the same three
expected arrivals and two self-probes, zero violations) was salvaged by re-correlating the intact
logs after the controller's collection defect (D-48); the analyzer now refuses a verdict with no
phases, no open-validation arrivals, or heartbeats that do not span the run.

**D-50 (fixed after this run).** The leakage run's APP section showed why the transparent path
failed with real Tor. A listener on the core address accepted an app's DNAT'ed connection, but
`SO_ORIGINAL_DST` returned `ENOENT`: the NAT happened in the app namespace's conntrack, and the
receiving host namespace had no entry to answer from, so real Tor could not learn the destination
(the installed probe read `the answer could not be read`; the app's `curl` got `Connection reset by
peer`). DNS worked because the chokepoint needs no original destination. The M8 evidence used a
stand-in Tor that never asked for the destination, so this went unnoticed (GA-6). The fix — a
per-namespace relay that reads the namespace's own `SO_ORIGINAL_DST` and speaks to the core's Tor as
the app's address — is implemented and requalified; see "D-50 fix" below and
`docs/RELEASE-CANDIDATE-REPORT.md`.

The run's own controller failed to collect the log (D-48: a PowerShell `$args` collision made the
collection run `sudo` with no arguments), which produced a `phases: 0` analysis. The raw evidence
was intact on both sides and was re-correlated directly with the measured offset; the analyzer now
refuses a `phases: 0` verdict. Every external operation in the controllers is bounded
(`Start-Process` + `WaitForExit`, SSH commands quoted as one argument), and the poll loop reads a
single-word unit state and keeps polling on anything unexpected. The analyzer's heartbeat check was
corrected too: it had required a heartbeat after the run's last phase, which fails whenever the
analyzer runs inside the 15-second beat window (it did, on run 4); it now checks that the beats span
the run window with bounded gaps.

## D-50 fix: the per-namespace relay (implemented and requalified)

Mechanism. The namespace's catch-all TCP DNAT now targets `127.0.0.1:9041`, where
`ghostnector-appd-relay` runs inside the same namespace. appd starts it (via `ip netns exec`) when a
group is created, as the application's own uid, and the relay drops every capability set before it
listens. Because the DNAT happened in the namespace's own conntrack, `SO_ORIGINAL_DST` answers there
(proved in `d50-origdst-caps.log`: a uid-1000 listener in the namespace that created the NAT reads
the original destination; no privilege is required). The relay refuses any connection with no
original destination, speaks SOCKS5 to the core's SocksPort with the per-group credential
`app<id>`/`ghostnector`, and splices bytes; it never parses payloads. Tor therefore sees the
application's own address and keys `IsolateSOCKSAuth` isolation per group. The namespace's egress
allows only the chokepoint (DNS) and the SocksPort; the host table admits the app link to the same
two ports; APP mode no longer renders a `TransPort`. A refused client is drained first, so a dead
router produces an empty answer (a failed check) rather than a read error (an inconclusive one), and
the state reports fail-closed. The relay's shutdown channel is its standard input: appd holds the
write end of the pipe and closes it to stop the relay (the packaged capability set has no
`CAP_KILL`), then reaps it with a bounded wait.

Evidence regenerated after the fix:

* `app-real-tor-test.sh`, installed product, real Tor (`app-real-tor-20260927T121825Z.log`): **16
  held / 0 contradicted / 0 inconclusive**. Two groups fetched real exit addresses
  (`141.98.11.62`, `185.100.87.174`) that differ from the host's public address; the intended
  destination answered 200 twice; DNS resolved through the chokepoint; a direct connection to a
  private host produced no data; a direct connection to the relay was refused; stopping one group
  removed its relay while the other group's stayed; with Tor stopped an application connection
  produced no address and the state stopped claiming verification (`protected, but unverified`;
  earlier runs with a path check configured reported `blocked - no traffic can leave`, the
  fail-closed baseline); disconnect left no relay, namespace or table.
* Kernel suites (source tree): `app-policy-test.sh` PASS (destination survives, source preserved,
  direct relay connection refused, core TransPort closed to the app link), `app-topology-test.sh`
  PASS, `appd-socket-test.sh` PASS (31 checks; no relay survives destroy/revert, including under the
  packaged capability set), `core-app-test.sh` PASS (the stand-in now speaks SOCKS and records the
  surviving destination, the source address and the per-group credential), `app-adversarial.sh`
  12 held / 0 contradicted / 1 inconclusive in WSL (the inconclusive is the WSL-specific namespace
  observation after the helper dies; the VM run is in the final gate).
* The post-fix leakage run and the full M1-M10 gate are recorded below.

Method notes: the verification probe's UDP check passes when UDP cannot leave, which is APP scope's
design, so the focused APP run verifies deterministically without depending on a public endpoint's
availability through a particular Tor exit. The path-check phase deliberately re-pins an HTTP check
while Tor is down to show the state stops claiming verification.

## D-53 fix: a profile change reloads Tor (found while requalifying D-50)

The leakage qualification's phase order (machine-wide Tor ? router-death ? panic ? I2P ? APP) left a
Tor instance running with the machine-wide torrc. The APP apply wrote the APP torrc but only
*started* the unit, a no-op for an active unit, so Tor kept its SocksPort on `127.0.0.1:9050`; the
namespace relay dialled the core address, was refused, drained and closed, and every application
fetch returned an empty reply within seconds - while the relay itself was healthy (a direct
connection to the relay was refused and the UDP verification passed, because UDP is denied either
way). The focused real-Tor run began from a clean state, which is why it had not caught this.

Fix: the supervisor gains `restart`, composed of the two verbs the polkit rule deliberately grants
(`stop` then `start`; systemd's own `restart` verb is refused without interactive authentication and
would need a wider rule for the same two actions), and the Tor bring-up compares the rendered torrc
with the file: a changed file means restart, a first apply or an unchanged file means start. The
i2pd path has the same shape but its listeners do not move between profiles; it is recorded as a
low-risk analogue, not changed here.

Evidence: `services::tests::app_scope_restarts_tor_when_the_listeners_move` (machine-wide then APP
must restart; the same profile again must not); `app-real-tor-test.sh` now begins with a
machine-wide Tor session, so the focused regression covers the transition; the focused rerun is
**17 held / 0 contradicted / 0 inconclusive** (`app-real-tor-20260927T134858Z.log`), with the two
groups' fetches returning `94.230.208.147` and `192.42.116.51`. The post-fix leakage run uses the
phase order that exposed the defect.

## Post-fix qualification records (2026-09-27, after D-50 and D-53)

* **Focused APP against real Tor** (`app-real-tor-test.sh`, `app-real-tor-20260927T134858Z.log`):
  **17 held / 0 contradicted / 0 inconclusive**. A machine-wide Tor session first (the D-53
  transition), then two groups fetched real exit addresses (`94.230.208.147`, `192.42.116.51`), the
  intended destination answered 200, DNS resolved through the chokepoint, a direct connection
  produced no data, a direct relay connection was refused, the stopped group's relay was gone while
  the other group's stayed, and with Tor stopped the state stopped claiming verification while no
  application produced an address.
* **Leakage** (`leak-20260927T135503Z.log`): VM-side **30/0/0** (run exit 0); analyzer exit 0 with
  30 phase records, 3 expected open-validation arrivals, 2 observer self-probes, **0 violations, 0
  ambiguous**, heartbeats spanning the run; the protected path reported `185.220.101.20` against
  the host's public `94.20.98.15`; nothing reached the far side in any protected window; the APP
  window's two groups left through different observed addresses.
* **Performance** (`perf-20260927T144529Z.log`): direct DNS 1.91 ms; chokepoint DNS 162.6 ms
  (baseline Tor 276.3 ms); HTTP 0.896 s (baseline 0.803 s); machine-wide throughput 180.3 kB/s
  (baseline 476.5 kB/s; this quantity varies widely between runs); APP launch 0.79/0.90/0.96 s
  against a direct launch of 0.32/0.33/0.34 s; APP throughput through the relay 712.8 kB/s (median
  of 3); the relay's cost during a download 2.52 MB RSS / 0.47% CPU (40 samples); idle helpers
  netd 3.80 MB / core 3.17 MB / appd 2.70 MB / DNS 2.22 MB.
* **Lifecycle** (`lifecycle-20260927T145851Z.log`): **32/0/0** (run exit 0), including the relay
  residue check after the uninstall, the reinstall's first boot, and the reboot-with-intent
  recovery to `off` via guest control.
* **Full M1-M10 gate** (`release-gate.log`, commit `e788aab`): 21 steps all rc 0; 460 unit tests
  passed, 0 failed; app-adversarial 13/0/0, i2p-adversarial 26/0/0, adversarial 27/0/1 (the
  documented no-IPv6 case), watch-oracle 10/0; the product was restored (three units active, state
  off, no table). (The final gate after the D-54 fix is in the D-54 paragraph below: `f82adf9`,
  21/21 rc 0, 461 unit tests.)
* **AA-13 correction.** The relay is the helper's child and exits when the helper dies (its stdin
  pipe closes), so the case now asserts what it claims - the namespace still exists and carries
  nothing, with the connection refused at the dead local relay - instead of the pre-relay liveness
  expectation that the protected path keeps working. WSL rerun 13/0/0; final gate 13/0/0.

**D-54 (found in the close-out verification; fixed and requalified).** The final lifecycle run's
reboot-with-intent boot did not actually have the boot guard deny, and the investigation found three
layers: netd (root, but with only `CAP_NET_ADMIN CAP_CHOWN`) could not create the copy in the
control plane's ghostnector-owned `/var/lib/ghostnector` at all — the apply note said `a copy of the
fail-closed policy could not be kept: Permission denied (os error 13)` — and the copy was produced
only on a fail-closed apply; a copy that existed was `0600` owned by `ghostnector`, which the root
guard (`NET_ADMIN` only) could not read; and the guard could not connect to netd's `0600` socket
either. The fix, least privilege: netd keeps the copy in its own root-owned state directory
(`StateDirectory=ghostnector-netd`) on **every** apply, hands the finished file to the control
plane's user with the `CAP_CHOWN` it already carries for the socket, and replaces it atomically
(root-owned temporary, `chown`, `rename` — `rename` needs only directory write, which netd owns);
netd no longer touches `/var/lib/ghostnector`, which also ends the latent ownership fight with the
core. The guard runs as that same control-plane user (`User=ghostnector`) with exactly
`CAP_NET_ADMIN` ambient and `NoNewPrivileges`, owns the socket and the copy, and writes nothing (no
state directory, no writable path). No capability that bypasses file permissions and no widened file
or socket mode.

Focused installed qualification (`installed-boot-guard-qualification.sh`, driven across real hard
resets; durable log `boot-guard-qualification.log`):

* **prepare 8/0/0**: with the copy removed (a fresh install has none), a protected session leaves a
  fresh copy owned by the control plane's user, mode 0600, containing the fail-closed ruleset; an
  unprivileged user can neither read it nor connect to the helper's socket; the persisted intent asks
  for protection.
* **verify-protected 7/0/0**: the boot guard exits 0, its own journal says the helper denied
  everything, it finishes **at or before the network-pre barrier** (e.g. 23019768us vs 23034512us),
  the fail-closed table is present, and the machine reports `blocked — no traffic can leave`; the
  documented disconnect recovers to off with no table.
* **verify-off 4/0/0**: with no persisted intent the guard exits 0, does nothing, no table exists and
  the machine is off.

The hermetic suite now runs the guard under that exact identity (both routes, an unrelated user
refused, missing and corrupt copies failing safely), and the hardening tests pin the guard's
identity, capability set and read-only posture plus the helper's own state directory. The full gate
at `f82adf9` is 21/21 rc 0 with 461 unit tests passing and the boot-guard suite PASS. The ordering
claim itself (no packet leaves before the deny) remains G6; the mechanism gap G14 is closed.

## Post-optimization requalification (2026-09-28/29)

The optimized candidate (`ghostnector-appd` APP-launch work in `012e9c0`, `6a53d20`, `0d947df`, plus
the `ghostnector-cli` session-exit fix `9b0fe5d`) was requalified on the same VM. Method: the VM tree
was reset to a frozen commit through a git bundle before each phase, the release tree was rebuilt and
installed with `packaging/install.sh`, and every installed run used the same detached / durable-log
procedure as the original campaign. Records (all under `/var/log/ghostnector-qual/` unless noted):

* **APP launch** (`perf/app-launch-profile-20260928T173332Z.csv`, N=10): product process appearance
  p10/med/p90 = 298.3 / **326.5** / 366.7 ms (was 665.6 at `f82adf9`); the application's own exec
  timestamp 315.3 / 349.4 / 396.0 ms against a direct launch of 52.4 ms; helper CPU 21.7 ms/launch
  and RSS ≈2.95 MB (was 56.7 ms; RSS unchanged). The per-optimization attribution is in
  `perf/APP-LAUNCH-OPTIMIZATION.md`.
* **Paired HTTP** (`paired-http-20260928T171914Z` two-instance, `…T172817Z` same-instance,
  `dns-focus-20260928T174245Z`): product total 501.8 ms vs a standalone transparent Tor at 918.3 ms
  in the two-instance window (instance variance); same-instance 526.4 vs 510.3 ms; the focused
  chokepoint-vs-DNSPort paired difference is +3.9 ms. The corrected `/proc`-delta resource method is
  unchanged from the campaign record.
* **Leakage** (`leak-20260928T200642Z.log`, host observer):
  VM-side **30 held / 0 contradicted / 0 inconclusive** (run exit 0); the analyzer returns exit 0
  with 30 phases, 5 arrivals, **3 expected open-validation arrivals**, 2 harness self-probes,
  **0 violations and 0 ambiguous**, the protected path reporting `192.42.116.103` against the host's
  `94.20.98.15`, and heartbeats spanning the run window. The APP window's two groups reached the
  network through Tor with the intended destination, a direct namespace connection produced no data
  and a direct relay connection was refused.
* **Focused real-Tor APP** (`app-real-tor-20260928T200015Z.log`): **17 held / 0 contradicted / 0
  inconclusive**.
* **Create-path failure probes** (`create-failure-probe-20260928T174828Z.log`): a partial `ip -batch`
  failure, an nft apply failure, a relay that exits immediately, and a relay that runs but never
  listens are each refused with no namespace, no host link and no registry entry; the silent relay
  is refused at the 5 s readiness deadline.
* **Lifecycle** (`lifecycle-20260928T184225Z.log`): **33 held / 0 contradicted / 0 inconclusive**
  (uninstall residue-free and networking restored, reinstall, ordinary use, lockout and the
  documented recovery).
* **Boot guard**: the first pass lost its `verify-protected` section to a hard reset (unflushed NUL
  region; D-57). The preserved pre-rerun log is
  `boot-guard-qualification.pre-rerun-20260928T184534Z.log`; the focused rerun flushed before each
  reset and records prepare **8/0/0**, verify-protected **7/0/0** (guard finished 20097696 µs ≤
  network-pre barrier 20100763 µs, fail-closed table present, `blocked`, recovery to off) and
  verify-off **4/0/0**.
* **Full M1–M10 gate** (`gate-final2.log`, tree at `9cfd0f1`): **21/21 steps rc=0, 463 unit tests
  passed** (461 at `f82adf9` plus the two new batch-order regressions); app-adversarial 13/0/0,
  i2p-adversarial 26/0/0, adversarial 27/0/1 (the documented no-IPv6 case), watch-oracle PASS, and
  the installed product restored (three units active, state `off`, no table) after the gate.

Two qualification-harness defects were found and fixed while obtaining this evidence: the leakage
controller kept the observer's inherited standard-output handle open after it had finished, hiding a
clean analysis behind a stalled pipeline (D-56; the recovered contemporaneous offset was `-402.299 s`,
and a later manual re-measurement of `-396.887 s` is preserved as INCOMPLETE — the VM clock moves, so
a re-measurement after the run is not a substitute for the controller's own offset); and
`core-app-test.sh` could connect to a helper socket before it was ready (D-58). The session-exit
defect D-55 was found because a standalone suite run over SSH inherited the SSH standard input.
None of the fixes changes a security, anonymity, isolation or fail-closed property; D-55 changes only
the CLI process lifetime after a session ends.
