# Ghostnector Engineering Handoff — after M7 / RC2

Snapshot taken from the working tree at `HEAD = dae5a6b` (2026-09-25), after `v1.0.0-rc2` (`9472c85`).

Authority order: repository > Git history > `docs/*` > this file. Everything here was gathered by reading the
code, docs, tags and by running the suites. Where a fact could not be confirmed from the repository it is marked
**UNCONFIRMED**. Where the repository contradicts a document, the discrepancy is called out in §1.9 and §6.

This file is a working aid, not part of the frozen RC2 candidate: `v1.0.0-rc2` points at `9472c85`, and this file
was written afterwards. Keep it that way unless the user decides otherwise.

---

## 1. Current repository state

### 1.1 Commits and tags

| Ref | Commit | Notes |
|---|---|---|
| `HEAD` (`main`) | `dae5a6bd9a2f8536954a8b88946ef13163bf6718` | "docs: record the RC2 clean-environment rerun, and add D-21" |
| `v1.0.0-rc1` | `a0d5ca9b986a156e5642fdd46f772085a2d5a02c` (annotated tag object `98d7892455f37ad61eabf8d20bd1638b7b07873d`) | Frozen candidate. **Never rewrite it.** Two of its claims were later falsified; that history is preserved in `PROTECTION-CLAIMS.md` and `ADVERSARIAL-TEST-PLAN.md`. |
| `v1.0.0-rc2` | `9472c8519bf3a3a496aa4a3fca32f9816bb875fe` (annotated tag object `9b34bd962bbb3c082bef086153c2a9005723e834`) | The RC2 commit under test. |
| commits after RC2 | exactly one: `dae5a6b` | Documentation only (RC2 rerun record + D-21). **The tag deliberately points at `9472c85`, not at `dae5a6b`.** Any new work starts from `dae5a6b`. |

11 commits total; first is `78853ee` ("Initial import..."). Working tree **clean**. **No remote configured**;
nothing has ever been pushed. Repo-local placeholder identity `Ghostnector <dev@localhost>`.

### 1.2 Size

- 75 tracked files; 40 `.rs` files; **16,072 Rust lines** under `crates/` (includes `#[cfg(test)]` modules).
- Workspace version `0.1.0`; `rust-toolchain.toml`: `stable` + rustfmt + clippy + `x86_64-unknown-linux-gnu` target.

### 1.3 Crates and binaries

| Crate | Kind | Owns |
|---|---|---|
| `ghostnector-spec` | lib (portable) | Vocabulary: `Profile`/`ValidProfile` + validity matrix, `Scope`, `Networks`, warnings; `ProfileId`, `Params`, `Verb`, `Report`, `Ports`, `ResolvedIdentity`; `Exemption`/catalogue; `ProtectionState`, `ServiceHealth`, `Verification`, `Health`, `Snapshot`; IPC `Request`/`Response`/`Event`/`ErrorBody`/`ErrorCode`/`HelperResponse`/`Frame`; `PROTOCOL_VERSION = 1`. No OS calls. |
| `ghostnector-policy` | lib (portable, pure) | `compile(ProfileId, &Params, &Environment) -> CompiledPolicy`; the IR (`ir.rs`); 20-class invariant checker (`invariants.rs`); nftables renderer (`render_table`, `render_replace_script`, `render_revert_script`); 5 golden policies. |
| `ghostnector-netd` | bin + lib (Linux only) | The privileged helper: the **only** writer of `inet ghostnector`; socket + peer-credential gate; tool checking; conntrack flush; fallback policy file for the boot guard; `Verb::Verify`. |
| `ghostnector-core` | bin + lib (portable except resolver/supervisor syscalls) | State machine (`state.rs`), orchestration (`engine.rs`), verification (`verify.rs`), DNS relay supervision (`chokepoint.rs`), resolver ownership (`resolver.rs`), journal (`journal.rs`), Tor supervision (`services.rs`, `supervisor.rs`, `torcontrol.rs`, `torrc.rs`), IPC server (`server.rs`), daemon (`main.rs`). |
| `ghostnector-cli` | bin `ghostnector` | `status`, `connect [--scope system\|user\|dns] [--lan]`, `disconnect`, `panic`, `watch`. |
| `ghostnector-dns` | bin + lib | The DNS chokepoint: relays UDP+TCP messages unchanged; loopback only; max 4096-byte messages; logs nothing but a throttled drop note; `--exit-when-stdin-closes`. |
| `ghostnector-bootguard` | bin (Linux only) | Early root oneshot: deny at boot if intent=protected, with a kernel-cmdline escape and a fallback copy of the fail-closed policy. |

**Discrepancies:** there is **no `ghostnector-verify` crate and no `ghostnector-journal` crate** — verification
lives in `crates/ghostnector-core/src/verify.rs` and the journal in `crates/ghostnector-core/src/journal.rs`.
`README.md`'s layout/portability table and `docs/IMPLEMENTATION-PLAN.md` §5 still name them. The plan's M5 gate
also refers to "`ghostnector-verify`" as a separate component.

### 1.4 Test counts (from `cargo test --workspace`)

| Crate | Unit tests |
|---|---|
| bootguard | 11 |
| cli (`ghostnector`) | 8 |
| core | 145 |
| dns | 8 |
| netd | 37 |
| policy | 53 |
| spec | 29 |
| **total** | **291 passed, 0 failed** |

No `#[ignore]`d tests anywhere; no expected-failure markers remain in code or scripts.

### 1.5 Integration scripts (root required, WSL/Linux)

| Script | Argument | What it proves |
|---|---|---|
| `scripts/policy-netns-test.sh` | `<policy.nft> [uid:expect]...` | A rendered policy applies; probes asserted **at the far side**; revert removes only our table. README example: `... golden/tor_system.nft 0:block 987:allow`. |
| `scripts/netd-socket-test.sh` | `<path-to-ghostnector-netd>` | Socket ownership, peer credentials, closed verb set, real apply/revert. |
| `scripts/core-cli-test.sh` | `<target/debug directory>` | cli -> core -> netd -> kernel end to end; unauthorised client refused; restart with intent but nothing applied fails closed. |
| `scripts/bootguard-test.sh` | `<target/debug directory>` | All five boot-guard cases, including fallback and the cmdline escape. |

### 1.6 Adversarial harness

- `scripts/adversarial.sh <target/debug directory>` — 27 cases: AS-1..AS-6, AL-1/4/7, AF-1..AF-4, AC-3..AC-6,
  AN-1..AN-5, AE-1..AE-5.
- `scripts/lib/gh-harness.sh` — namespaces `gh-mut`/`gh-out`, leak signal `10.88.0.2`, conduit `10.88.0.3`,
  nft observers in `gh-out`, a tcpdump capture of the outside veth, a sampling oracle
  (`gh_watch_violations`: a crossing counts only if the machine still reported protection when it happened),
  fake Tor / DNS / internet / DHCP recorder / storm, fault-injection helpers, `gh_mark` timeline.
- Single case: `CASE=AC5 bash scripts/adversarial.sh <dir>`.
- Verdicts: `ok` (held), `FAIL` (contradicted), `inconclusive`, and a `demonstrated` mechanism that no current
  case uses (kept for later milestones; never counted as a pass).

### 1.7 Gates (exact)

Run in WSL (native Linux, which is the target platform):

```bash
cd /path/to/Ghostnector
export CARGO_TARGET_DIR=/root/ghostnector-target
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

On the Windows host (edit-only; Smart App Control blocks running unsigned test binaries — risk R9 in the plan):

```powershell
cargo fmt --all
cargo check  --workspace --all-targets --target x86_64-unknown-linux-gnu
cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
```

**Lesson encoded as D-14:** `netd`, `core` and `cli` are `#![cfg(unix)]`; a Windows-native clippy compiles them
to nothing and passes trivially. Static checks are only meaningful **against the Linux target**.

### 1.8 Current release-qualification result

- Unit: **291 / 0**; integration: **4/4 PASS**; adversarial: **held 26, contradicted 0, inconclusive 1 (AS-4,
  by design), demonstrated 0**; `fmt`/`check --all-targets`/`clippy -D warnings` clean.
- **Clean-environment rerun** at the tag, from a fresh clone with its own target dir: identical results
  (`9472c85` = `v1.0.0-rc2`; 291 / 4 / 26-0-1-0; static checks clean).
- This is a qualification record, **not** a proof of security or of being leak-free. What it supports is exactly
  the claims/evidence table in §5.

### 1.9 Known stale documentation (do not trust, fix when touching it)

| Where | Stale claim |
|---|---|
| `README.md` line 6 | "Status: early implementation (M0 ...)" — actually M0–M7 done. |
| `README.md` layout table | Lists `ghostnector-verify` and `ghostnector-journal` crates that do not exist. |
| `README.md` packaging comment | Mentions a polkit policy; `packaging/` has **no** polkit file. |
| `docs/IMPLEMENTATION-PLAN.md` §5 | Status table stops at "M3 in progress / M7 next". |
| `docs/IMPLEMENTATION-PLAN.md` §1 M7 row | Promised CI workflow + chutney job + external-vantage checklist; **only the harness was built**. No `.github/`, no chutney, no vantage implementation exists. |
| `ARCHITECTURE-REVIEW.md` §4 D1 / §11.3 | Diagram uses `127.0.0.7:9040/9053` and `udp dport 68`; the implementation binds loopback `127.0.0.1`, redirects to `:9040` and `:9054`, and the DHCP rule is now `udp sport 68 udp dport 67` (D-18). |
| `ProtectionState::Portal` | Declared in `spec/state.rs`, labelled in the CLI, but **no code path ever enters it**. Captive-portal work is unimplemented. |
| Packaged identities | systemd units use user `ghostnector` (+ `ghostnector-netd` in sysusers); the **harness** creates and uses `ghostnector-core`. Not a bug, but do not confuse the two. |

---

## 2. Architecture (as built, M1–M7)

### 2.1 Component contract table

| Component | Privilege | Lifecycle | Interfaces | Deliberately NOT allowed | Failure behavior |
|---|---|---|---|---|---|
| `ghostnector-core` | Unprivileged user `ghostnector`; unit grants only `CAP_NET_BIND_SERVICE` (ambient) **so the child relay can bind :53** (unit: `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`) | `ghostnector-core.service`, `Restart=on-failure`, after netd | Unix socket `/run/ghostnector/core.sock`, mode **0660**, group `ghostnector` | No policy writing (`netd` only), no arbitrary command execution (unit names validated; `systemctl` invoked by absolute root-owned path via `tools.rs::check_tool`), no persistent traffic metadata | Holds no policy: enforcement persists in the kernel; systemd restarts it; `reconcile()` re-derives truth from kernel+journal |
| `ghostnector-netd` | `root` with **only** `CAP_NET_ADMIN`; `NoNewPrivileges`; `set_no_new_privs()` first thing; `RestrictAddressFamilies=AF_UNIX AF_NETLINK`; `RestrictNamespaces=yes`; syscall filter `@system-service` | `ghostnector-netd.service`, early (`Before=sysinit.target`), `Restart=on-failure` | Socket `/run/ghostnector/netd.sock`, mode 0600 + chown to `--peer-user ghostnector`, **and** `SO_PEERCRED` re-check per connection | No verb carries a ruleset, command, path, or interpreter string (see §3, I9); never touches foreign nftables tables; never unwinds (locked mutation path) | Policy persists in the kernel; bootguard can use the fallback copy `/var/lib/ghostnector/fail-closed.nft`; `Report.applied` is read from the kernel |
| `ghostnector-bootguard` | root, `CAP_NET_ADMIN` only | `ghostnector-bootguard.service`, oneshot, `DefaultDependencies=no`, `Before=sysinit.target network-pre.target`, `Wants=ghostnector-netd.service` | Reads `/var/lib/ghostnector/intent.json`, `/proc/cmdline`; talks to netd socket; applies `/var/lib/ghostnector/fail-closed.nft` via `/usr/sbin/nft` if netd is unreachable | Does not start services; does not open anything | Unreadable journal = "protection requested" = deny; escape is `ghostnector.unprotected=1` on the kernel cmdline |
| `ghostnector` (CLI) | Unprivileged; requires membership of the `ghostnector` group | on demand | core.sock frames | Holds no exemption, no capability, no policy | Cannot reach core = prints that; means nothing about enforcement |
| `ghostnector-dns` | Runs as core's uid, started as a **child of core**; inherits `CAP_NET_BIND_SERVICE` to bind :53 | child process, tethered by stdin; dies with core (also `--exit-when-stdin-closes`) | Listens on `127.0.0.1:<chokepoint>` (loopback only); forwards to `127.0.0.1:<upstream>` | Relays **unchanged**; no parsing of names, no rewriting, no caching, no answering of its own; logs nothing about queries (a throttled drop counter only) | Relay stopped = DNS stops; the policy keeps redirecting :53 into nothing -> fail closed |
| Tor | its own static uid `debian-tor` (policy exemption), `NoNewPrivileges`, sandbox per torrc | `ghostnector-tor.service`, started/stopped **only** by core (`WantedBy=multi-user.target` but not enabled at boot), `Restart=on-failure` | `-f /run/ghostnector/torrc` written by core; control port cookie; TransPort/DNSPort/SocksPort on loopback | Tor is not part of Ghostnector's policy engine; core reads only `AUTHENTICATE` + `GETINFO status/bootstrap-phase` and never circuits/streams/destinations | Tor dies = redirect target is a dead loopback port; no clearnet fallback |
| `ghostnector-policy` | in-process library | n/a | `compile`, `render_*`, `check` | Cannot name an arbitrary external destination in egress rules (IR has only `DaddrInSet`, and `DestinationAllowInEgress` rejects destination allows without an exemption) | An invalid/unsupported policy is a `PolicyError`; nothing is applied |

### 2.2 Ports and identifiers

- Defaults from `netd` `config.rs`: `nft /usr/sbin/nft`, `conntrack /usr/sbin/conntrack`, fallback
  `/var/lib/ghostnector/fail-closed.nft`, `tor-user debian-tor`, `dnscrypt-user dnscrypt-proxy`,
  `trans 9040`, `chokepoint 9054`, `socks 9050`, `dhcp client port 68`.
- **Single source of truth for ports:** core asks netd (`Verb::Report` -> `Report.ports`) and configures Tor
  with those numbers; the firewall and Tor cannot disagree. (Explicit design lesson: "two sources for one port
  is how DNS silently stops working".)
- `PROTOCOL_VERSION = 1`; a mismatch is a hard failure on both sockets.

### 2.3 End-to-end flows

**Connect** (`Engine::connect`, `engine.rs` ~241-284):
1. CLI sends `Request::Connect { profile }` (raw `Profile`); core validates (`Profile::validate` ->
   `ValidProfile`) and maps to `(ProfileId, Params)` in `plan()`.
2. State -> `Applying` (`Cause::UserRequested`), publish.
3. `bring_up_then_open` (`engine.rs` ~455):
   a. apply `FailClosed` (**deny first**, DR-4);
   b. fetch `Ports` from the helper;
   c. `services.bring_up` — start Tor unit / adopt external Tor, then wait for bootstrap via the control port;
   d. apply the target profile;
   e. `bring_up_dns` **last** — start the relay child and point the system resolver at `127.0.0.1:53`.
4. On success: state -> `Degraded` (`Cause::Automatic`) with the reason "nothing has verified this yet";
   record `Intent::requested`; set `verify_soon`; publish.
5. Verification runs (immediately after a ~2 s settle, then every interval); only a pass moves `Degraded` ->
   `Protected` (`Cause::Verified`).

**Connect failure** (`roll_back_failed_connect`, ~763): stop relay and services; `Verb::Revert`; **only if the
withdrawal succeeds** -> `Off` (`Cause::Automatic`) + intent off; otherwise `keep_denied()` -> apply
`FailClosed`, state `Blocked`, intent FailClosed. (D-10.)

**Disconnect** (~287): announce `Applying` ("removing the policy") **before touching anything** if the machine is
not already `Off` (D-19); `stand_down_dns` (restore resolver, stop relay); `services.stand_down`;
`Verb::Revert`; state `Off` (`Cause::UserRequested`); intent off; publish.

**Verification** (`verify_once` ~569, `expire_verification` ~664, thread in `main.rs` ~199):
- Only when state is `Degraded`/`Protected`; otherwise `Inconclusive` "nothing is applied" (so a probe
  succeeding on an open machine can never alarm).
- Three socket probes (`verify.rs`, all as an ordinary identity, no exemption): UDP egress **must fail**;
  protected path must answer HTTP with a body address that is **not** one of this machine's; canary must
  resolve to the expected address.
- Plus the **effective-policy comparison**: `Verb::Verify` -> netd compares the kernel's own listing against
  the read-back it recorded when it applied (canonical text; counters stripped).
- One failure => `Failed` => note + apply `FailClosed` + state `Blocked` (`Cause::Automatic`) + intent
  FailClosed. `Inconclusive` => if `Protected`, -> `Degraded`. Staleness: a `Fresh` result older than
  `stale_after` -> `Stale`, and `Protected` -> `Degraded`.

**Alarm semantics:** a `Failed` verification is the only automatic route to `Blocked` during protection;
`Blocked` never becomes open on its own.

**Reboot:**
- bootguard runs before `sysinit`/`network-pre`: escape present -> nothing; journal unreadable -> treated as
  requested; intent off -> nothing; intent on -> ask netd (wait up to 15 s) to apply `FailClosed`, else apply
  the fallback `.nft` itself.
- core starts, `reconcile()` (~353) loads the journal, asks netd `Report`: applied + known profile -> adopt
  (`Degraded`, or `Blocked` for FailClosed; unknown profile -> `Blocked`); nothing applied + intent.protected ->
  apply `FailClosed` -> `Blocked`; otherwise `Off`. Resolver baseline is loaded from `resolver.json`; if
  nothing is applied the resolver is stood down.
- `docs/RECOVERY.md` is the operator path: (1) `ghostnector disconnect`, (2) cmdline escape at next boot,
  (3) rescue shell: `nft destroy table inet ghostnector` + remove `intent.json`. It also lists what is
  deliberately **not** a way out.

**Resolver ownership** (`resolver.rs`): three environments handled differently — systemd-resolved via its own
tool and reverted with `resolvectl revert`; a plain file written/restored byte-for-byte with a hash check;
NetworkManager left alone with an explanation. **None of this is enforcement**; failures here are notes, never
reasons to claim protection. A concurrent edit produces a conflict, never a clobber.

**Journal** (`journal.rs`): persists *intent* only (`protected` flag, profile, params, generation, timestamp),
`INTENT_VERSION = 1`, atomic write + fsync + rename + directory fsync. Kernel and helper are the truth about
what is applied.

### 2.4 The adversarial harness architecture

- Two namespaces wired by a veth: `gh-mut` (system under test) and `gh-out` (the "outside world"). Addresses:
  machine `10.88.0.2` / `fd00:88::2`, conduit `10.88.0.3`, outside `10.88.0.1` / `fd00:88::1`; a second path
  (`10.99.0.x`) can be created by AN-5.
- Observations: nft counters in `gh-out` (keyed on source address), a `tcpdump` capture of the outside veth
  (whole subnet, so an address change is still seen), and a JSON-lines event log written by the fake endpoints
  (TCP/UDP/HTTP/DHCP/an optional `tcp2` listener) **and** by the fake Tor.
- Fake Tor runs as `debian-tor`, binds the conduit address for everything it sends onward (so conduit traffic
  can be told from machine traffic), speaks a minimal control protocol, and relays TCP via `SO_ORIGINAL_DST`.
- The **sampling oracle** (`gh_watch_start`/`gh_watch_violations`) is the transition test: it samples
  (packet count, reported state) pairs and flags a rise only while the report says protection. A before/after
  count cannot distinguish "leak while claiming protection" from "crossing after the user was told protection
  was gone".
- `connect_or_fail_setup` refuses to run a case on top of a failed `connect` (the D-20 lesson: otherwise every
  observation is of an open machine).

---

## 3. Security and privacy invariants

These are constraints on all future work. "Enforced by" names the code that makes it true; "Tested by" names
the tests/cases that would catch a regression.

### 3.1 The review invariants (I1–I9) and decision register (DR-1…DR-20)

The register is in `ARCHITECTURE-REVIEW.md` §0 and Appendix A. Load-bearing ones and their implementation:

| Invariant | Meaning | Enforced by | Tested by |
|---|---|---|---|
| **I1** | No packet leaves a non-loopback interface from a protected uid except Tor, DHCP, or an explicitly enabled visible exception | `inet ghostnector` filter chain: default `drop`; accepts only loopback destinations, `meta skuid <tor>`, DHCP, LAN sets, enumerated exemptions | AS-1/AS-2, AE-1…AE-5, policy-netns-test, invariant checker |
| **I2** | No DNS from a protected scope reaches a clearnet resolver in Tor modes | nat redirect udp/tcp 53 -> chokepoint; resolver pointed at loopback; no resolver exemption in Tor mode | AS-5/AS-6, AE-4, PC-03 evidence |
| **I3** | Stopping/crashing a userspace component never increases connectivity | kernel-resident policy; services independent; `core` holds no policy | AF-1…AF-4 |
| **I4** | Protected state is idempotent/re-assertable | `netd` apply replaces the owned table atomically | netd tests, core-cli-test |
| **I5** | Disconnect restores exactly the captured baseline or reports a conflict; never "reset networking" | `resolver.rs` hash-compared restore; revert only touches `inet ghostnector` | resolver unit tests, core-cli-test, PC-15 |
| **I6** | No destination/query/per-connection metadata persisted | `Snapshot` deliberately has no destinations/exit addresses; DNS relay logs nothing | model + relay tests; DR-19 |
| **I7** | Policy changes atomic; never more permissive than union(old,new) | full-table replacement; deny-first ordering; priorities (D-15) | AL-1/4/7, priority invariant |
| **I8** | Every exemption enumerated and visible | `effective_exemptions` derived from rules that cite them; `Report.exemptions` shown by CLI | `UnenumeratedAccept`/`UnenumeratedExemption` invariants; policy tests |
| **I9** | Privileged helper exposes no verb accepting arbitrary ruleset/command/path/interpreter input | **closed** `Verb` enum; `Params` = `user_uid: Option<u32>`, `netns_id: Option<u32>`, `allow_lan: bool` only; ruleset rendered by netd from `ProfileId` | `verb_tags_are_a_closed_set`, `parameters_cannot_expand_the_interface`, netd socket tests |

### 3.2 Specific mechanisms and where each lives

- **Fail-closed by default:** filter chain `policy drop`; forward chain `policy drop`; anything unenumerated is
  denied. `fwd_filter` blocks containers/VMs (DR-20).
- **Desired vs observed:** `Report.applied` is answered by asking the kernel (`table_present`), not by memory;
  `reconcile()` believes the kernel over the journal.
- **Entering `Protected`:** only `Machine::transition(Protected, Cause::Verified, ...)`.
  `Cause::Automatic`/`UserRequested` are rejected with `TransitionError::UnverifiedProtection`. Test:
  `nothing_may_claim_protection_without_verification`.
- **Leaving protection:** only `Cause::UserRequested` may go to `Off` from a protected/blocked state; automatic
  rollback is permitted only from `Off`/`Applying` (`may_auto_rollback`). Tests:
  `an_automatic_return_to_the_clearnet_is_refused_after_protection_exists`,
  `the_user_can_always_turn_protection_off`.
- **Effective-policy verification:** netd records `canonical()` of its own read-back after apply; `Verb::Verify`
  re-reads and compares; first differing line or extra/missing line is reported. `counters_are_not_part_of_the_policy`,
  `the_effective_policy_is_compared_against_what_was_applied`, `a_policy_that_vanishes_does_not_compare_equal`;
  engine: `a_policy_changed_in_the_kernel_is_noticed_and_denied`; adversarial AC-3/AC-4/AC-5. Bound: one
  verification interval + timeout. **Not cryptographic; defeated by CAP_NET_ADMIN (G10).**
- **Closed verb set:** `Verb` = `Hello`, `ApplyProfile{ProfileId, Params}`, `Revert`, `Verify`, `FlushConntrack`,
  `Report`. Nothing else parses. Dispatch is one `match` in `netd/src/server.rs::handle`.
- **Peer authentication:** netd socket mode 0600 + chowned to `--peer-user`/`--peer-uid`, plus `SO_PEERCRED`
  per connection (`is_authorized` accepts the configured uid, **and root** — D-13, because the boot guard is
  root). Core socket: mode 0660, group-owned; filesystem permissions are the authorization model; peer uid is
  recorded and used to scope `user` requests to the requester.
- **No arbitrary execution through IPC:** netd runs `nft`/`conntrack` by absolute path, root-owned, not
  group/other-writable (`netd`'s own copy of the check); core runs `systemctl`/`resolvectl` through
  `tools.rs::check_tool` with validated unit names (`supervisor.rs` tests `unit_names_are_restrained`,
  `a_unit_name_cannot_smuggle_an_option`). No shell anywhere in either path.
- **Tor bootstrap ordering:** deny -> bring services up -> wait for readiness -> open. Tested by ordering unit
  tests plus the harness storm cases; Tor's uid exemption is the only reason bootstrap is possible under the
  baseline.
- **Tor uid exemption:** `meta skuid <tor_uid>` `return` in nat and `accept` in filter; the uid is resolved from
  `debian-tor` by netd and **refused if it does not match the configured value** (uid stability is a security
  invariant, packaging/sysusers note).
- **DNS chokepoint:** redirect both UDP and TCP port 53 to the chokepoint port; relay is unchanged-message,
  loopback-only, no caching/rewriting; no exemption is needed because its upstream is loopback (the absence of
  a rule is the security property — a design refinement discovered in M1 and recorded in the plan).
- **DHCP exemption:** `udp sport <client port> udp dport 67 accept` — the direction a client actually sends. An
  invariant (`DhcpExemptionDirection`) refuses a DHCP exemption without a source-port match. Regression: D-18.
- **Boot guard:** as in §2.3; escape is cmdline-only; unreadable journal denies.
- **Privilege separation:** portable crates (`spec`, `policy`) have no OS calls; `netd` is the only
  CAP_NET_ADMIN holder; core is a plain user with one bind capability for its child relay; bootguard is root
  but tiny and oneshot; GUI (future) holds nothing.
- **Transition ordering:** `Applying` is announced before the policy is touched (D-19); nat chain must precede
  the filter chain on the same hook (`NatChainDoesNotPrecedeFilter`, D-15); loopback is matched as a
  **destination set** in both chains, never by interface name (`loopback4 127.0.0.0/8`, `loopback6 ::1/128`;
  D-16).
- **Policy tamper detection:** as above; AC-3 removal, AC-4 probed change, AC-5 unprobed change. Alarm response:
  `Blocked` + `FailClosed` applied (which overwrites the tampered table) + reason recorded + intent updated.
- **Recovery:** `docs/RECOVERY.md`; three ways out, plus an explicit list of non-ways (weakening a check,
  deleting the table without clearing intent, disabling the unit).

---

## 4. Exact meaning of states

`ProtectionState` (`crates/ghostnector-spec/src/state.rs`):

| State | Meaning | How it is entered | Evidence required |
|---|---|---|---|
| `Off` | No policy applied; network as the user left it | `disconnect` (`Cause::UserRequested`); failed-connect rollback only if withdrawal succeeded (`Cause::Automatic`, allowed only from `Off`/`Applying`) | `Verb::Revert` returned `applied: false` |
| `Applying` | A transition is in flight; together with `Off`, the only states from which automatic rollback is legal (DR-15) | connect, panic, and the start of a disconnect; `Cause::UserRequested` | none (bookkeeping) |
| `Degraded` | Policy applied, but the claim is not fresh: verification stale/unavailable, or an optional service down. **Traffic is still under policy** (`is_protected()` is true) | successful connect (`Cause::Automatic`); `Protected` -> `Degraded` on inconclusive/stale verification; adopt-after-restart | policy applied (`Report.applied`) |
| `Protected` | Policy applied **and** at least one configured check passed since it was applied **and** no configured check has contradicted since | **only** `Cause::Verified` | a passing verification run; an age (`verified_ago_secs`) is always attached |
| `Blocked` | Fail-closed: no path to clearnet, whatever the cause; first-class state with reason + timestamp | verification failed; reconcile found protection requested with nothing applied; policy could not be withdrawn; unknown applied profile | `FailClosed` applied in the kernel |
| `Portal` | Declared "captive-portal exception, transient, never survives a reboot" | **no code path enters it** — unimplemented | n/a |

Derived helpers: `is_protected() = Protected | Degraded`; `is_denied() = Blocked`;
`may_auto_rollback() = Off | Applying`.

Verdict semantics used throughout (and in claims/verification): **Verified** = an observation was made and
supports the claim; **Inconclusive** = the check could not run or could not establish the claim (never a pass,
never a leak); **Contradiction** = an observation falsifies the claim -> alarm + fail-closed. A repeated
transition to the same state updates reasons without bumping the generation.

The rule to preserve above all: **`Protected` is evidence-backed.** Applying a policy yields `Degraded`, never
`Protected`.

---

## 5. Protection claims and threat model (`docs/PROTECTION-CLAIMS.md`)

Compact map. "Evidence" is what the M7 campaign actually observed (see §7); "Falsifier" is the condition that
turns it into an alarm.

| Claim | What it says | Scope / exemptions | Evidence | Falsifier |
|---|---|---|---|---|
| **PC-01** | Ordinary TCP egress confined to the protected path (through Tor) | System-wide; exempt: `system-user:tor`, loopback, DHCP | AS-1 (destination reached exactly once via conduit, zero machine-source packets); AL-1/4/7; AN-1…AN-5; only exempted Tor uid ever egressed directly (AE-1) | A direct TCP segment from a protected uid observed at a boundary |
| **PC-02** | Ordinary UDP denied | Same | AS-2; AC-4 (injected UDP rule alarms); AE-1 control | Any reply / any datagram at a boundary |
| **PC-03** | DNS leaves only via the chokepoint; queries to foreign resolvers are redirected | Port 53, all uids except exemptions; exempt: resolver's own upstream (lockdown mode), loopback, Tor | AS-5/AS-6; AE-4. **RC1 falsified this (D-15/D-16)**; holds after the fixes | A port-53 datagram from a protected uid at a boundary; an answer from a non-chokepoint resolver |
| **PC-04** | IPv4 is covered by PC-01/02/03 | As above, v4 | All v4 tests | as PC-01…03 |
| **PC-05** | IPv6 egress denied | Host-wide; exempt: loopback, Tor's own v6 path if v6-only | AS-3 on a v6-capable link (no v6 packet); AS-4 INCONCLUSIVE on a v4-only link (by design); AN-4 | An IPv6 packet from a protected uid at a boundary |
| **PC-06** | The protected path carries traffic (not just blocking) | Endpoint configured by the operator | Verified end to end: full-stack runs reach `protected - and verified` with HTTP check + UDP check + canary; the endpoint answers 200 to an unprivileged identity. **RC1 falsified this (D-15/D-16)** | Endpoint does not answer while protection claimed |
| **PC-07** | The exit is not this machine | Endpoint-dependent | Verified against a standalone endpoint whose body reports a TEST-NET-3 address; comparison against local interfaces passes. **Not claimed:** that the exit is a Tor exit (needs external vantage, G8) | Reported address is one of this machine's own |
| **PC-08** | Tampering with the policy is noticed and answered | Any change by anything other than netd | AC-4 (probed class) and AC-5 (unprobed class, via the kernel read-back comparison); unit tests at netd and engine level. **RC1 did not hold this** (only probed changes; G3) | A change permitting prohibited traffic unnoticed for longer than one interval + timeout |
| **PC-09** | Exemptions are exactly the documented ones and only they | All uids/protocols/address sets in force | Verified in both directions for `system-user:tor` (AE-1), `dhcp-client` (AE-2), LAN (AE-3), and the resolver's **absence** in Tor mode (AE-4). **RC1 was wrong about DHCP (D-18).** Residual: one-by-one kernel-vs-report diff not executed (G13) | A non-exempt identity taking an exempt path; an unlisted hole in the kernel |
| **PC-10** | Boot with protection requested denies before the network is configured | Boot window; exempt DHCP + cmdline escape | Partially verified: policy applied, fallback and escape work, unreadable journal denies. **The ordering claim ("nothing left before") is NOT observed (G6)** | An egress packet observed before the baseline exists |
| **PC-11** | Tor stopping opens nothing | Protected set | AF-1 (Tor killed; no path) | Protected traffic reaches a boundary after Tor stopped |
| **PC-12** | Control-plane death changes nothing | — | AF-3; AF-4 for the helper | Any loosening coincident with the death |
| **PC-13** | DNS relay stopping opens nothing | — | AF-2 | A port-53 packet at a boundary |
| **PC-14** | Transitions never widen the policy | Connect/disconnect/panic windows | AL-1/AL-4/AL-7 under the sampling oracle; D-19 found and fixed by it | One prohibited packet while protection is reported |
| **PC-15** | Disconnect restores exactly what was there (no clobber) | Resolver configuration | Verified byte-for-byte end to end (resolver round-trip test) | A modified resolver config left without a word |
| **PC-16** | The policy disappearing is noticed | — | AC-3 (290 packets during the injected window, 0 after re-denial; bound = interval + timeout) | Table gone and protection still claimed after the bound |

**Explicitly not claimed** (`What Protected does not claim`): not anonymity; not "the exit is not your ISP"; not
"nothing can escape"; not protection outside the scope; not protection against the host (root/kernel/
`CAP_NET_ADMIN` — G10); not that unconfigured checks passed; not DHCPv6 (G11).

### 5.1 Open gaps (as documented now)

| # | Gap | Claim |
|---|---|---|
| G1 | **Narrowed**: v6 *denial* verified; Tor's own v6 egress on a v6-only network unobserved | PC-05, PC-09 |
| G6 | Boot ordering ("nothing left before the baseline") not independently observed | PC-10 |
| G8 | No external vantage: ISP-facing half of DNS and "is it a Tor exit" unanswerable | PC-03, PC-07 |
| G9 | `Protected` can be reached with only a subset of checks configured; the interface lists what did not run but nothing enforces a minimum | definition of `Protected` |
| G10 | Root/`CAP_NET_ADMIN` can replace policy, comparison subject or helper — out of scope, stated | PC-08 + all confinement |
| G11 | DHCP exemption is IPv4-only; DHCPv6-only lease renewal unsupported while protected | PC-09 |
| G12 | A transient connectivity loss can leave the machine `Blocked` until a person acts (observed AN-1) — deliberate availability cost | PC-06, PC-14 |
| G13 | Residual: exemption list is derived + invariant-checked, but no one-by-one kernel-vs-report diff end to end | PC-09 |

Closed by M7: G2 (end-to-end checks configured), G3 (effective-policy comparison), G4 (process-death cases),
G5 (transition storms), G7 (DHCP/LAN/resolver exemptions).

---

## 6. Defect ledger D-01…D-21 (and the AC5 gap)

Full table: `docs/ADVERSARIAL-TEST-PLAN.md` Appendix A. Compact ledger; the entries in **bold** are the ones
this campaign paid for and that future work must not re-earn.

| # | What was wrong | Why tests missed it | Found / fixed | Regression |
|---|---|---|---|---|
| D-01 | `dedup_by` only removes consecutive duplicates; the exemption catalogue listed `dhcp-client` twice | catalogue was never asserted | unit review | `the_catalogue_has_no_duplicate_subjects` |
| D-02 | **Leak oracle used interface byte counters**; a working policy "leaked" 250 bytes of IPv6 link-local control traffic | counters cannot distinguish policy failure from link noise | replaced with "packets arriving at the destination" | policy-netns assertions; plan rule 2; "not an observation point" note |
| D-03 | curl's `000` read as a status code, so a blocked probe looked successful | application-level outcome trusted | exit status is the authority | probe helper |
| D-04 | fake DNS log deleted while held open; every count read zero | — | truncate, never unlink | connection-count assertions |
| D-05 | Test asserted a frame tag that does not exist (`frames`) | oracle wrong | corrected | `a_snapshot_reports_the_current_state` |
| D-06 | Socket mode checked before the directory's | wrong failure reason | order fixed | `a_world_writable_directory_is_refused` |
| D-07 | Tor's quoted `SUMMARY=` truncated by whitespace tokenising | — | extract quoted value | `a_summary_containing_spaces_survives_intact` |
| D-08 | Compiler required a uid for every service, so Tor mode failed without the resolver installed | — | identities optional, named when missing | `a_machine_without_a_resolver_can_still_run_tor_mode` |
| D-09 | Oversized DNS datagram truncated and relayed corrupted (size check unreachable) | — | read one byte more than the limit | `a_datagram_larger_than_any_dns_message_is_dropped` |
| D-10 | Rollback reported `off` though the policy could not be withdrawn | — | withdrawal must succeed before claiming open | `a_failed_connect_whose_policy_cannot_be_withdrawn_stays_denied` |
| D-11 | Engine tests would write the real `/etc/resolv.conf` | — | temporary root with real contents | resolver round-trip |
| D-12 | Killed subscriber left its thread blocked forever | — | poll-based liveness | `a_subscription_streams_state_changes_and_ends_when_the_client_leaves` |
| D-13 | netd accepted only core, so the boot guard could never apply | — | root accepted, with reasoning written down | `authorization_is_an_exact_match_except_for_root` |
| D-14 | **Two clippy lints in `#![cfg(unix)]` crates invisible to Windows-hosted clippy** | host-platform clippy compiles unix crates to nothing | gate now runs clippy against the Linux target | freeze procedure in `PROTECTION-CLAIMS.md` |
| D-15 | **nat and filter shared priority `-150` -> undefined order; redirects could race the deny filter.** Falsified PC-03/PC-06 at RC1 | no test asserted chain ordering; the failure was probabilistic | distinct priorities (`NAT_PRIORITY -100`, `FILTER_PRIORITY 0`) + invariant | `a_nat_chain_that_does_not_precede_the_filter_chain_is_caught`; goldens pin priorities |
| D-16 | **A redirected packet reports its *original* output interface in the filter chain (route recomputed after the verdict), so `oifname "lo"` never matched redirected traffic** | same as D-15; the old shape looked natural | loopback matched as destination sets `loopback4`/`loopback6` with `RuleOrigin::Loopback`, allowed by `DestinationAllowInEgress` | goldens + `a_rule_claiming_loopback_but_matching_an_interface_is_still_caught` |
| D-17 | **A relay that started and immediately exited was reported as protection** | nothing checked liveness between start and claim | engine checks `relay.is_running()` after start and fails connect | `a_relay_that_starts_and_then_dies_fails_the_connect` |
| D-18 | **DHCP exemption compiled as `udp dport 68` (reply direction).** Observed against the exact RC1 policy in a scratch netns: `:68 -> :67` never matched (accept counter 0), `:68 -> :68` matched (counter 1). The link would die at first lease renewal while the policy claimed to keep it alive | the exemption was only asserted by subject, never by direction; the golden diff was never read against the protocol | `Expr::Sport` in the IR; rule is `udp sport 68 udp dport 67`; invariant `DhcpExemptionDirection` | `the_dhcp_exemption_matches_the_direction_a_client_sends`, `a_dhcp_exemption_matching_only_a_destination_is_caught`, adversarial AE-2 |
| D-19 | **Disconnect removed the policy before the state stopped reporting protection** (a few hundred microseconds of "protected" with no policy) | the original oracle counted before/after, not "while reporting"; the window is invisible to it | announce `Applying` before touching anything; nothing announced when already `Off` | `a_disconnect_reports_a_transition_before_it_removes_anything`; sampling oracle in AL-4 |
| D-20 | **The first D-18 fix rendered `udp sport 68 dport 67`, which nftables refuses; every connect failed and every adversarial case silently observed an open machine** | the harness ignored the connect result | renderer qualifies a second port match (`udp sport 68 udp dport 67`); `connect_or_fail_setup` refuses to run a case on a failed connect | `a_second_port_match_in_a_rule_is_qualified_by_its_protocol` |
| D-21 | The independent capture started before the interface existed, so tcpdump exited and every failure dump printed "(no capture)" — detection unaffected, diagnosis degraded | it was started in `gh_setup` before the veth existed | capture starts after the veth is up; a capture that dies says so; failure dump prints capture + timeline + state + logs | harness change |

**AC5 / G3 (not a D-number, a demonstrated gap):** two injected rules permitting only TCP destinations were
invisible to every probe while the state claimed protection. Fixed by netd recording the kernel's own read-back
at apply time and comparing it on every verification pass (`Verb::Verify`); a mismatch alarms, applies
`FailClosed`, and overwrites the change. Regressions: netd (`the_effective_policy_is_compared_against_what_was_applied`,
`a_policy_that_vanishes_does_not_compare_equal`, `counters_are_not_part_of_the_policy`), engine
(`a_policy_changed_in_the_kernel_is_noticed_and_denied`), adversarial AC-5. **Residual:** the comparison is
textual, not cryptographic, and cannot survive a privileged attacker (G10).

---

## 7. M7 / RC2 qualification evidence

### 7.1 What RC1 failed (preserved, never rewritten)

At `v1.0.0-rc1` (`a0d5ca9`), the frozen candidate's documents recorded 16 claims and 9 gaps, and the
adversarial campaign then established:

- **PC-03 and PC-06 were false** (D-15/D-16: undefined chain order and the redirected-output-interface
  assumption). This is recorded in `PROTECTION-CLAIMS.md` ("What RC1 got wrong"), and the RC1 appendix is left
  as it stood with an explicit note.
- **PC-08 was narrower than it read**: only probed tampering was detectable; AC-5 demonstrated the gap (G3).
- **PC-09 was wrong about DHCP** (D-18); RC1 shipped an exemption that permitted the direction a client never
  sends.
- **D-17** (relay liveness) was present.
- RC1 evidence then: 281 unit tests, 5 integration runs, clippy/check on the Linux target, clean tree.

### 7.2 What RC2 demonstrated

At `v1.0.0-rc2` (`9472c85`), from the working tree and again from a **fresh clone of the tag** with a separate
target dir (both runs identical):

| Category | Result |
|---|---|
| Unit tests | 291 passed, 0 failed (bootguard 11, cli 8, core 145, dns 8, netd 37, policy 53, spec 29) |
| Integration scripts | 4/4 PASS (`policy-netns-test`, `netd-socket-test`, `core-cli-test`, `bootguard-test`) |
| Adversarial cases | **held 26, contradicted 0, inconclusive 1 (AS-4, by design), demonstrated 0** |
| Static checks | `fmt --check` clean; `check --all-targets` clean; `clippy -D warnings` clean (Linux target) |
| Defects found in the campaign | D-15, D-16, D-17, D-18, D-19, D-20, D-21; each fixed with a regression test that fails on the old behaviour |
| Claims changed | PC-03/PC-06/PC-09 verified after fixes; PC-08 widened to "changes to the policy"; PC-14 tightened by D-19; PC-01/02/05/07/11/12/13 moved from "not observed" to verified end to end |
| Gaps closed | G2, G3, G4, G5, G7; G1 narrowed; new G10–G13 |

**Do not describe RC2 as "proven secure" or "leak-free".** The correct statement is: the defined adversarial
campaign produced 26 held / 0 contradicted / 1 inconclusive by design, the four integration suites and 291 unit
tests pass, and everything unverified is listed as an open gap in §5.1.

---

## 8. Commands and development workflow

Environment: Windows host = editing + `fmt`/`check`/`clippy` **with `--target x86_64-unknown-linux-gnu`** (Smart
App Control blocks running locally built unsigned binaries). All execution happens in WSL2 Ubuntu 24.04.5,
kernel 6.18.33.2-microsoft-standard-WSL2, nftables 1.0.9, rustc/cargo stable (1.98.1 at freeze). Keep artefacts
in the VM: `CARGO_TARGET_DIR=/root/ghostnector-target`.

```bash
# --- one-time environment (WSL, as root) -------------------------------------
apt-get install -y nftables iproute2 util-linux tcpdump python3
# the harness creates and uses debian-tor and ghostnector-core itself
export CARGO_TARGET_DIR=/root/ghostnector-target

# --- format / static analysis ------------------------------------------------
cd /mnt/c/Users/<you>/Desktop/Ghostnector
cargo fmt --all --check
cargo check  --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings

# --- unit tests --------------------------------------------------------------
cargo test --workspace

# --- build the binaries the scripts install ----------------------------------
cargo build --workspace --bins

# --- integration suites (all four must pass) ---------------------------------
bash scripts/policy-netns-test.sh \
    crates/ghostnector-policy/golden/tor_system.nft 0:block 987:allow
bash scripts/netd-socket-test.sh "$CARGO_TARGET_DIR/debug/ghostnector-netd"
bash scripts/core-cli-test.sh   "$CARGO_TARGET_DIR/debug"
bash scripts/bootguard-test.sh  "$CARGO_TARGET_DIR/debug"

# --- adversarial suite (27 cases; ~10-15 min) --------------------------------
bash scripts/adversarial.sh "$CARGO_TARGET_DIR/debug"
CASE=AC5 bash scripts/adversarial.sh "$CARGO_TARGET_DIR/debug"   # one case

# --- regenerate golden policies DELIBERATELY, after reading the diff ---------
GHOSTNECTOR_UPDATE_GOLDEN=1 cargo test -p ghostnector-policy rendered_policies_match_their_golden_files
git --no-pager diff crates/ghostnector-policy/golden

# --- clean-environment release qualification (what RC2 passed) ---------------
rm -rf /root/rc2 /root/rc2-target
git clone --branch v1.0.0-rc2 /mnt/c/Users/<you>/Desktop/Ghostnector /root/rc2
cd /root/rc2
export CARGO_TARGET_DIR=/root/rc2-target
cargo test --workspace
cargo build --workspace --bins
bash scripts/policy-netns-test.sh crates/ghostnector-policy/golden/tor_system.nft 0:block 987:allow
bash scripts/netd-socket-test.sh "$CARGO_TARGET_DIR/debug/ghostnector-netd"
bash scripts/core-cli-test.sh    "$CARGO_TARGET_DIR/debug"
bash scripts/bootguard-test.sh   "$CARGO_TARGET_DIR/debug"
cargo fmt --all --check && cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
bash scripts/adversarial.sh "$CARGO_TARGET_DIR/debug"
```

Windows-host static checks (no execution):

```powershell
cargo fmt --all
cargo check  --workspace --all-targets --target x86_64-unknown-linux-gnu
cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
```

Repo hygiene: **no remote is configured and the user has said not to publish.** Commit locally with
`git add -A && git commit`. Tags are annotated (`git tag -a`).

---

## 9. Repository map

| Path | Why it matters |
|---|---|
| `ARCHITECTURE-REVIEW.md` | Source of design intent: threat model, I1–I9, DR-1…DR-20, mode matrix, leak-testing methodology, M8/M9 rationale. 1234 lines; read before changing architecture. |
| `docs/IMPLEMENTATION-PLAN.md` | Milestones M0–M10, gates, risks R1–R9, cut list, D1–D3 implementation decisions. **§5 status is stale.** |
| `docs/PROTECTION-CLAIMS.md` | The definition of `Protected`; PC-01…PC-16 with evidence and falsifiers; the RC1-falsification record; gaps G1–G13; Appendix A = RC1 as it stood, Appendix B = RC2 record. |
| `docs/ADVERSARIAL-TEST-PLAN.md` | Observation points O1–O7, classification CPT/EEC/INC, the six test classes, executed-case results, D-01…D-21 ledger. |
| `docs/RECOVERY.md` | The three ways out and what is deliberately not one. |
| `crates/ghostnector-policy/src/compile.rs` | Profile -> ruleset; `NAT_PRIORITY`/`FILTER_PRIORITY`; loopback sets; DHCP rule; `Environment`. |
| `crates/ghostnector-policy/src/invariants.rs` | The 20-class checker; `ViolationCode` stable identifiers; `NEVER_EXEMPT_PREFIXES` (in `spec/exemption.rs`). |
| `crates/ghostnector-policy/src/render.rs` | Deterministic nftables renderer; port-protocol folding rules; golden test + `GHOSTNECTOR_UPDATE_GOLDEN`. |
| `crates/ghostnector-policy/golden/*.nft` | The five pinned policies: `fail_closed`, `dns_lockdown`, `tor_system`, `tor_system_lan`, `tor_user`. |
| `crates/ghostnector-spec/src/state.rs` | `ProtectionState`, `Health`, `Verification`, `Snapshot` (note what is deliberately absent). |
| `crates/ghostnector-core/src/state.rs` | `Machine` + `Cause` + `TransitionError` — DR-15 and "evidence only" encoded in code. |
| `crates/ghostnector-core/src/engine.rs` | Orchestration: connect/disconnect/panic/reconcile/verify_once/rollback; 1844 lines, the densest file. |
| `crates/ghostnector-core/src/verify.rs` | The three probes + `Verifier` outcome rules. |
| `crates/ghostnector-core/src/chokepoint.rs` | `DnsRelay` trait, `ChildRelay`, the liveness check (D-17). |
| `crates/ghostnector-core/src/resolver.rs` | Resolver ownership: three layouts, hash-checked restore, conflict path. |
| `crates/ghostnector-core/src/journal.rs` | Intent journal (atomic, versioned). |
| `crates/ghostnector-core/src/torcontrol.rs` | Cookie auth; only `AUTHENTICATE` + `GETINFO status/bootstrap-phase`. |
| `crates/ghostnector-core/src/torrc.rs` | Tor configuration and the tests that refuse privacy-for-speed settings. |
| `crates/ghostnector-core/src/services.rs` / `supervisor.rs` | Service bring-up and the validated-unit supervisor. |
| `crates/ghostnector-core/src/server.rs` | Core IPC: 0660 socket, group authorization, subscriptions. |
| `crates/ghostnector-core/src/main.rs` | Daemon flags, verification thread, reconcile-before-serve. |
| `crates/ghostnector-netd/src/server.rs` | The entire privileged dispatch surface + peer auth + `Verify`. |
| `crates/ghostnector-netd/src/backend.rs` | `NftCli`, `list_table`, `table_present`, tool checks. |
| `crates/ghostnector-netd/src/config.rs` | Defaults for ports/users/paths and strict CLI parsing. |
| `crates/ghostnector-dns/src/lib.rs` | Chokepoint relay rules (unchanged messages, size limit, no logging). |
| `crates/ghostnector-bootguard/src/guard.rs` | Boot decision table, cmdline escape, fallback apply. |
| `crates/ghostnector-cli/src/main.rs` | Command set and output labels ("protected, but unverified", "no traffic can leave"). |
| `packaging/systemd/*.service` | Capabilities, ordering, sandboxing per unit — the privilege story. |
| `packaging/sysusers.d`, `tmpfiles.d` | Static uids and `/run/ghostnector`. |
| `scripts/lib/gh-harness.sh` | The harness (namespaces, fakes, observers, sampling oracle). |
| `scripts/adversarial.sh` | The 27 cases and their verdicts. |
| `scripts/{policy-netns,netd-socket,core-cli,bootguard}-test.sh` | The four pre-existing integration suites. |

---

## 10. DO NOT CASUALLY REOPEN THESE DECISIONS

1. **Linux-only v1.** Guarantees are built from nftables, namespaces, capabilities and socket ownership. WSL2
   is a build/test environment, not a target. A non-Linux backend would be a different product with weaker
   guarantees.
2. **nftables enforcement in the kernel, one owned table** (`inet ghostnector`), full-table atomic replacement.
   Never touch foreign tables; disconnect deletes *our* objects, never "resets networking".
3. **Fail-closed on ambiguity.** A check that cannot conclude downgrades; a verification failure alarms and
   applies the baseline; an unreadable journal denies at boot. Do not add a "helpful" fallback to clearnet.
4. **`Protected` requires evidence.** The only route in is `Cause::Verified`. Applying a policy yields
   `Degraded`. Do not add a code path that claims protection from application success.
5. **DR-15: rollback only from `Off`/`Applying`.** Once protection exists, only an explicit user request
   returns to clearnet; everything else escalates to `Blocked`.
6. **The privileged helper's verb set stays closed.** No verb may carry a ruleset, command, path, interpreter
   input, or arbitrary namespace/interface name. Extend it with bounded, typed operations only (I9). New
   privileged work should get its own small unit rather than widening netd (risk R7).
7. **Ports come from one source: `netd`'s `Report`.** The firewall and Tor must never be configured from two
   sources.
8. **Tor stays separately supervised; core does not become Tor's owner in-process.** Services are systemd units
   (or an operator's Tor), readiness is required, and the control port is used for exactly two commands.
9. **The DNS chokepoint is a separate, tethered child process** that relays messages unchanged and logs no
   queries. Do not add parsing, caching, rewriting, or metrics about names.
10. **Resolver configuration is not enforcement.** It can fail; that is a note. Enforcement is the port-53
    redirect. Restores are hash-checked and never clobber a concurrent edit.
11. **The DHCP exemption matches the client's direction** (`sport 68 -> dport 67`) and an invariant enforces a
    source-port match. DHCPv6 is out of scope for v1 (G11).
12. **Loopback is matched as a destination set, never an interface name** (D-16), and the nat chain must precede
    the filter chain on the same hook (D-15). Both are invariant-checked.
13. **Effective kernel policy is independently compared.** The comparison is against the kernel's own read-back,
    not remembered intent; it remains the mechanism for PC-08. Do not downgrade it to "did apply return
    success".
14. **External observation, not interface byte counters** (D-02). Assert on what arrived at the far side;
    classify every observation as CPT/EEC/INC; INC is never a pass.
15. **Transitions are judged by "crossed while reporting protection"**, not before/after counts (D-19). Keep
    the sampling oracle.
16. **RC1 history is preserved.** Do not retcon the RC1 documents or the tag.
17. **Static checks run against the Linux target** (D-14). Windows-native clippy is meaningless for the
    unix-gated crates.
18. **No persistent traffic metadata** (DR-19): no destinations, queries, per-flow records, exit addresses, or
    byte counts per flow. `Snapshot` is the contract for what may be shown.
19. **No remote, no push** unless the user says otherwise.
20. **`forward` is default-deny** and containers/VMs are blocked by design (DR-20). Any M8 change that touches
    the forward path must keep that property (or explicitly and visibly narrow the claim).

---

## 11. Next milestone: M8 (`APP` scope / route-less namespaces)

**Do not implement any of this in the current chat.** What follows is what the existing plan and review have
settled, plus explicitly labelled open questions.

### 11.1 Intended behavior (settled in the review/plan)

- `Scope::App`: only applications explicitly launched into Ghostnector are covered; each gets a **route-less
  network namespace** — no default route, no IPv6 address/route (IPv6 disabled in-netns), and only a
  **netns-local DNAT** to a host-local core address (DR-6, review §3.4, §9.3, M8 row in the plan).
- **Source addresses are preserved across the namespace boundary; never masqueraded** (DR-7). This is what
  recovers Tor's per-app circuit isolation (Tor's "Application Address" = source address as Tor sees it) and
  the plan's gate for M8: *two apps in separate namespaces land on different Tor circuits; masquerading is
  detected and rejected by a test*.
- Fail-closed is **structural** in this scope: a flushed rule cannot create a path because there is no route.
- LAN access is opt-in per app, as in other scopes; the machine-wide `SYSTEM` scope remains the default and is
  unaffected by APP being enabled/disabled.

### 11.2 Current code state (what exists / what blocks it)

| Piece | State |
|---|---|
| `Scope::App` validity, warnings plumbing | Exists; `validity_matrix_is_exhaustive` covers it |
| `ProfileId::TorApp`, `Params.netns_id` | Exist in the wire vocabulary; `netns_id` documented as "from the helper's own registry" — **the registry does not exist** |
| `compile(ProfileId::TorApp \| I2pIsolated)` | Returns `PolicyError::Unsupported` (`compile.rs` ~169) |
| `engine::plan()` for `Scope::App` | Returns `EngineError::NotSupported("protecting single applications arrives in a later milestone")` |
| Namespace code in netd | **None.** No `netns` handling anywhere in netd; netd has no namespace verb |
| netd unit hardening | `RestrictNamespaces=yes` — would block namespace creation; M8 must revisit capability/unit layout (risk R7 suggests a separate unit) |
| Launcher / CLI | No launch/enter command exists |
| Harness | No namespace-under-test support inside `gh-mut`; fake Tor records only the conduit address, not per-connection source addresses in a form the isolation claim needs |

### 11.3 Invariants M8 must preserve

All of §3. Specifically: I1 (no unexempted egress), I2 (DNS stays inside the chokepoint path), I3 (crashes
never increase connectivity), I6/DR-19 (no traffic metadata), I7 (atomicity), I8 (exemptions visible), I9 (the
privileged verb set stays closed and typed); DR-4/DR-6/DR-7/DR-9/DR-14/DR-15/DR-17/DR-20; plus: enabling APP
must not change the SYSTEM-scope policy at all; namespace cleanup must be complete (no stale veth/routes/rules);
and the absence of a route must remain the failure mode rather than a rule that can be wrong.

### 11.4 How M8 could accidentally weaken M1–M7 (watch list)

1. Widening `netd` (`CAP_SYS_ADMIN`, `RestrictNamespaces=no`, new verbs) instead of a separate small
   privileged unit — R7.
2. Adding a default route or a catch-all DNAT "to make it work" — destroys the structural fail-closed
   property.
3. Adding any masquerade/`SNAT` on namespace traffic — silently collapses DR-7 isolation; must be an invariant
   plus a test that fails if a masquerade rule appears.
4. Letting the client name namespaces/interfaces/paths over IPC — reopens I9.
5. Touching `fwd_filter` to admit namespace traffic in a way that also admits containers/VMs (DR-20).
6. Reusing or widening the Tor uid exemption for namespace traffic.
7. Claiming per-app protection without per-app evidence — extend verification (namespace probes), and extend
   the claims document rather than stretching `Protected` to mean something it does not.
8. Changing the loopback destination sets or chain priorities while adding APP policy (D-15/D-16 regressions).
9. Leaking namespace identifiers or per-app traffic detail into `Snapshot` (DR-19).
10. Boot/restart: namespaces are volatile like the firewall; ensure reconciliation reports honestly
    (`Blocked`/`Degraded`) rather than silently dropping APP coverage.

### 11.5 Tests required before M8 can be called complete (proposal, not settled)

- **Policy level:** golden policy for the namespace profile; invariants: no destination allow without
  exemption; IPv6-relevant rules absent/denied inside the namespace profile; the host `inet ghostnector`
  policy unchanged by enabling APP.
- **netd level:** bounded namespace verbs (create/destroy/inspect by an id from netd's own registry,
  name-validated); idempotent create/destroy; refusal of arbitrary names; **no masquerade**: a connectivity
  test that inspects the host ruleset and fails if source addresses are rewritten.
- **Integration (harness):** two apps in two namespaces -> the fake Tor records **distinct source addresses**
  (distinct Application Addresses); direct egress from a namespace -> nothing at the outside; IPv6 inside a
  namespace -> impossible (no address/route); DNS inside a namespace -> answered through the chokepoint;
  disconnect/panic -> namespaces and veths removed, nothing left; crash of core -> policy and namespaces behave
  per DR-14 and reconciliation.
- **Adversarial cases (new class, e.g. AA-1…):** namespace removed by hand; masquerade rule injected; a route
  injected inside the namespace; the host's second-path trick (AN-5) repeated for a namespace; reconnect storm
  while apps run; `Blocked` state with apps running.
- **Gates:** the existing 291 unit tests, four integration scripts and 27 adversarial cases must still pass
  unchanged; new cases must not weaken SYSTEM-scope results.

### 11.6 Questions the next agent must answer before coding (unresolved)

1. Which process gets `CAP_SYS_ADMIN` and namespace verbs: a new small unit, or `netd` with its unit reworked?
   (Plan risk R7 prefers separate; code has neither.)
2. What is the namespace registry and its bounds? (`Params.netns_id` is an integer "from the helper's own
   registry" — nothing defines allocation, persistence, or collision handling.)
3. Which host-local address does the netns-local DNAT target, and how does the return path work without
   masquerade (host-side veth addressing/routing; does the host's input or forward chain see these packets;
   does `fwd_filter` drop them)?
4. Exactly how does the packet reach Tor's TransPort after the netns-local DNAT, and where is that path
   expressed in policy?
5. What does DNS look like inside the namespace (DNAT port 53 too? who writes the netns's `resolv.conf`; is a
   mount namespace needed)?
6. What is the launcher's privilege and identity model, and does the app keep the invoking uid (so uid-scoped
   rules and exemptions stay meaningful)?
7. What does `Snapshot`/`Protected` mean for APP scope when only some applications are covered? (One global
   state today.)
8. Boot: what is the APP intent's boot behavior beyond the existing machine-wide fail-closed baseline? How is
   a stale namespace registry cleaned?
9. Uninstall/cleanup: deleting namespaces/veths and proving nothing stale remains.
10. How is the isolation claim tested against a fake Tor (what does the harness need to record per connection)?
11. Which claims are added/changed, and which falsifiers do they get? (New PC entries; update
    `PROTECTION-CLAIMS.md` before the milestone closes.)
12. Performance: cold circuits per app are an expected cost (review §3.4) — confirm no "optimization"
    reintroduces shared circuits.

---

## 12. Fresh-chat bootstrap prompt

Copy the block below into the new chat, and point the new agent at this file and the repository.

---

You are continuing Ghostnector, a Linux privacy-networking application (kernel-enforced transparent Tor, DNS
chokepoint, fail-closed default-deny with evidence-backed claims). The repository is at
`C:\Users\user\Desktop\Ghostnector` (Windows edit host; **all execution happens in WSL2 Ubuntu 24.04 as root**
with `CARGO_TARGET_DIR=/root/ghostnector-target`). Nothing is pushed and there is no remote.

`docs/HANDOFF-RC2.md` (this file) was written after milestone M7 and the freezing of `v1.0.0-rc2`. Treat it as
an **index, not as truth**. The repository is authoritative.

Before doing anything else:

1. **Inspect the repository first.** Read `README.md`, `ARCHITECTURE-REVIEW.md` (threat model, invariants
   I1–I9, decision register DR-1…DR-20), `docs/IMPLEMENTATION-PLAN.md`, `docs/PROTECTION-CLAIMS.md`,
   `docs/ADVERSARIAL-TEST-PLAN.md`, `docs/RECOVERY.md`, then the crates.
2. **Verify the handoff against the code, docs and Git history**, including: `HEAD` (`dae5a6b`),
   `v1.0.0-rc1` (`a0d5ca9`), `v1.0.0-rc2` (`9472c85`), the working tree state, the test counts, and the
   documented gaps G1–G13 and defects D-01…D-21. Report every discrepancy you find **before modifying
   anything**.
3. **Run the existing gates** (all defined in §8 of the handoff): `cargo fmt --all --check`,
   `cargo check --workspace --all-targets`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`, the four integration scripts and `scripts/adversarial.sh`. Do not accept a
   passing result from Windows-native clippy; the unix-gated crates must be checked against
   `x86_64-unknown-linux-gnu`.
4. **Preserve the M1–M7 invariants.** In particular: `Protected` is only reachable via verification;
   rollback to clearnet is only legal from `Off`/`Applying`; the privileged helper's verb set stays closed;
   fail-closed on ambiguity; one owned nftables table; do not masquerade; do not add traffic metadata; do not
   "fix" a failing check by weakening it. The list in the handoff's "DO NOT CASUALLY REOPEN THESE DECISIONS"
   section is binding unless the user approves a change.
5. **Read the protection claims and the adversarial plan before touching policy or verification code**, and
   keep them honest: an untested property stays unverified, an inconclusive observation is never a pass, and
   RC1's history is never rewritten.
6. **Read the defect ledger** (D-01…D-21) and do not re-earn those mistakes — especially the chain-priority
   ordering (D-15), the redirected-output-interface assumption (D-16), the DHCP direction (D-18), the
   "crossed while reporting protection" oracle (D-19), the nftables render validity lesson (D-20), and the
   Linux-target static-check rule (D-14).
7. **Then propose an M8 implementation plan**, not code: `APP` scope with route-less namespaces (DR-6/DR-7,
   review §3.4 and §9.3). Answer the open questions listed in the handoff's M8 section — privileged-unit/
   capability layout, the namespace registry, the netns-local DNAT and the no-masquerade return path, how
   packets traverse (or avoid) the host's forward chain, DNS and resolver inside the namespace, the launcher's
   privilege model, what `Protected` means per-app, boot/cleanup behaviour, and the tests (unit, integration,
   adversarial) that would make the milestone complete. Label anything the existing plan has not settled as
   unresolved.
8. **Wait for approval** before beginning any large architectural change or widening a privileged interface.
   Small, clearly-scoped fixes with a regression test are fine to propose and, once approved, to implement.
9. Do not push, do not add a remote, and do not begin M8 code until the user says so.

Your first response must contain: the discrepancies you found, the gate results you observed, and your proposed
M8 plan with open questions. No code changes before that.
