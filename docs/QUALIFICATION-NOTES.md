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

**D-50 (recorded, decision for the maintainer).** The leakage run's APP section showed why the
transparent path fails with real Tor. A listener on the core address accepts an app's DNAT'ed
connection, but `SO_ORIGINAL_DST` returns `ENOENT`: the NAT happened in the app namespace's
conntrack, and the receiving host namespace has no entry to answer from, so real Tor cannot learn
the destination (the installed probe reads `the answer could not be read`; the app's `curl` gets
`Connection reset by peer`). DNS works because the chokepoint needs no original destination. The M8
evidence used a stand-in Tor that never asks for the destination, so this went unnoticed (GA-6).
A correct fix changes the M8 data-path mechanism — a per-namespace relay that reads the namespace's
own `SO_ORIGINAL_DST` and speaks to the core's Tor as the app's address, or host-side interception
(which would falsify PC-18) — so it is recorded rather than taken in this campaign.

The run's own controller failed to collect the log (D-48: a PowerShell `$args` collision made the
collection run `sudo` with no arguments), which produced a `phases: 0` analysis. The raw evidence
was intact on both sides and was re-correlated directly with the measured offset; the analyzer now
refuses a `phases: 0` verdict. Every external operation in the controllers is bounded
(`Start-Process` + `WaitForExit`, SSH commands quoted as one argument), and the poll loop reads a
single-word unit state and keeps polling on anything unexpected. The analyzer's heartbeat check was
corrected too: it had required a heartbeat after the run's last phase, which fails whenever the
analyzer runs inside the 15-second beat window (it did, on run 4); it now checks that the beats span
the run window with bounded gaps.
