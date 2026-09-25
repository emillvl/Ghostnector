# M8 decisions — recorded before implementation

These are the decisions the user approved for milestone M8 (`APP` scope: per-application protection
using dead-end Linux network namespaces). They bind the implementation and the documents; changing
one is a new decision, not an edit.

Source of the plan: `docs/HANDOFF-RC2.md` §11, `ARCHITECTURE-REVIEW.md` §3.4/§9.3, and the M8.0
topology experiment (`scripts/app-topology-test.sh`, defect D-22 below).

| # | Decision |
|---|---|
| 1 | **Routing:** an APP namespace has a default route into a dead-end local `dummy` device plus a netns-local DNAT to the host core address. The security property is authoritative, not the old literal phrase "no route". The scope-link default-route variant is not used. No SNAT/masquerade anywhere. |
| 2 | **Launcher:** shell-in-netns. No arbitrary command, executable path, interpreter, namespace name, interface name, or ruleset crosses privileged IPC. The privileged side launches only the invoking user's passwd-defined shell from internally derived state, drops supplementary groups and capabilities, and switches to the invoking uid before any user command runs. The exact privilege-drop sequence must be tested and documented before M8.3 is complete. |
| 3 | **Privileged component:** a separate `ghostnector-appd`. `netd` is not widened with `CAP_SYS_ADMIN` and its privilege boundary and IPC philosophy are unchanged. `appd` has a closed typed verb set and internally generated object names. Its capability and systemd-hardening set is minimized empirically and reviewed before M8.2 is complete. |
| 4 | **APP/SYSTEM composition:** mutually exclusive in M8. Activating one while the other is active is refused, never silently replaced. Composition is deferred. |
| 5 | **`allow_lan` in APP scope:** rejected for M8, with an explicit explanation (APP preserves source identity and does not use SNAT/masquerade, so LAN access is unsupported under the current APP architecture). The no-SNAT property is not weakened to support it. |
| 6 | **`Blocked` in APP scope:** means the protected applications cannot reach the network. It does not claim the whole machine is denied unless a machine-wide state really denies it. Bootguard behavior for persisted protected intent stays conservative and machine-wide during M8; it is not softened. |
| 7 | **Zero apps:** never `Protected`. `Degraded` with a reason equivalent to "APP protection is configured, but no application currently has verification evidence". `Cause::Verified` remains the only path into `Protected`. |
| 8 | **D-B / D-22:** fixed before M8 depends on the DNS architecture. The resolver configuration can only name an address, so the chokepoint listens on port 53, the same port an address-only `nameserver` line implies. One canonical configuration, enforced by tests. |
| 9 | **`appd` privilege surface:** start from the smallest capability/syscall/address-family surface demonstrated to work; add nothing for convenience; tests inspect the installed unit. |
| 10 | **Registry:** maximum 32 isolation groups; ids allocated internally; explicit lifecycle; namespaces persist until explicit stop/disconnect/panic/reboot rather than vanishing when a child exits; destroy is idempotent; no destination history or traffic metadata; `Snapshot` exposes only what is needed to identify/count protected APP groups. |

## Additional requirements carried into the implementation

- APP inactive ⇒ M1–M7 behavior and the SYSTEM goldens are byte-identical; the regression suite is
  run after every APP change.
- The APP host table must not acquire an OUTPUT policy that turns APP scope into SYSTEM scope.
- The bridge must never become a forwarding/uplink path.
- The effective APP namespace ruleset and namespace shape are independently verifiable, and a
  contradiction while reporting APP protection triggers the documented APP fail-closed behavior.
- Distinct namespace source addresses prove the identities Ghostnector supplies to Tor, **not**
  distinct Tor circuits. Circuit isolation is a separate property requiring Tor/external evidence.
- A phase that encounters evidence contradicting one of these assumptions stops and reports instead
  of improvising.

## Execution order

M8.0 (D-22 fix, wording, documentation, regression tests, full M1–M7 gate) → M8.1 policy → M8.2
`appd` → M8.3 launcher → M8.4 core integration → M8.5 verification → M8.6 harness/adversarial and
the claims record. A clean, tested checkpoint is kept after each phase.

| M8.2 `appd` | **done** — the measured capability set is `CAP_NET_ADMIN CAP_SYS_ADMIN CAP_CHOWN` (only `CAP_NET_ADMIN` ambient): namespace creation/entry need the middle one, links/addresses/routes/sysctls the first, and the socket handoff the last. The gate runs the helper under exactly that set (lifecycle and verification pass) and under the same set minus `CAP_SYS_ADMIN` (creation fails with EPERM), which is the empirical justification. The same measurement found **D-23** in `netd`'s packaged set (missing `CAP_CHOWN`), resolved under option A with the same two-direction test on `netd`. |
| M8.3 launcher | **done** — the launch helper's sequence is fixed and proved by `scripts/appd-socket-test.sh` step 5: (1) `setns` into the group's namespace; (2) `unshare(CLONE_NEWNS)`, make `/` private, bind the group's `resolv.conf` over `/etc/resolv.conf`; (3) `setgroups([])`, `setgid`, `setuid` to the user named by the passwd entry for the uid the control plane asked for; (4) clear permitted, effective, inheritable and ambient capabilities, refusing to continue if any ambient capability survives (the bounding set is left alone: dropping from it needs `CAP_SETPCAP`, which this component does not hold, and a bounding entry cannot grant anything by itself); (5) `execve` the passwd-defined shell, validated as root-owned and not group/other-writable, with a fixed environment. The evidence: the shell reports the intended uid, all four granting sets empty, the chokepoint `resolv.conf`, the dead-end routes, and its own network and mount namespaces; the session socket is owner-only; a second session is refused; and an outsider is refused by the kernel peer check even after the socket is chmodded 666. |
| M8.4 core surface | **in progress (a: done; b: remaining)** — the core API is deliberately product-level so M10 stays a thin presentation layer: `Connect{scope: app}`; `AppRun` (no parameters) returns a session handle and socket; `AppList` returns ids, addresses and presence; `AppStop{id}`; `Snapshot.apps` carries the same minimal status. No namespace, uid, port, interface, policy name, daemon, or capability appears in the interface's vocabulary. The CLI writes the command it was given to the *user's own shell* over the session socket, so no command ever crosses a privileged interface. `scripts/core-app-test.sh` proves the whole path end to end. Remaining (b): Tor's core-address listeners and the app-facing chokepoint, so a session can reach Tor. |

## The topology experiment (added in M8.0)

`scripts/app-topology-test.sh` proves against the real kernel:

1. A literally route-less namespace cannot start an intercepted connection at all: `connect()`
   fails with `ENETUNREACH` before the netns-local DNAT chain can run.
2. A default route into a dead-end `dummy` device plus a netns-local DNAT carries the connection to
   a host-local core address with the application's source address preserved.
3. With the DNAT gone, the connection dies locally: no packet, no ARP, and no host involvement. A
   flushed rule cannot create a path.

This is the evidence behind decision 1. It also records a pre-implementation design correction: the
original text ("no default route") was physically unimplementable for transparent interception, and
is corrected to the statement in decision 1. The correction is a design change, not a defect in
shipped code; the defect record for M8.0 is D-22 (the chokepoint port and the resolver line
disagreed), recorded in `ADVERSARIAL-TEST-PLAN.md` Appendix A.
