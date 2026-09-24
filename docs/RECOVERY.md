# Getting a machine back

Ghostnector denies everything when it cannot prove that protection is working. That is the point of
it, and it means a machine can end up with no network on purpose. This file is the way out.

## What you will see

```console
$ ghostnector status
state:        blocked — no traffic can leave
why:
  - protection was requested before the last restart, but nothing was applied; the fail-closed
    baseline has been applied instead
```

or, if the control plane itself is not running:

```console
$ ghostnector status
ghostnector: cannot reach the control plane at /run/ghostnector/core.sock: ...
```

## The three ways out, in order of preference

### 1. Ask Ghostnector to stand down

```console
$ ghostnector disconnect
```

This works with no network at all: everything it needs is local. It puts the resolver configuration
back the way it was, stops the services Ghostnector started, removes its own firewall table, and
records that protection is no longer wanted.

If `ghostnector-core` is not running, start it first:

```console
$ sudo systemctl start ghostnector-core
$ ghostnector disconnect
```

### 2. Boot with protection switched off

Add this to the kernel command line in your bootloader, once:

```
ghostnector.unprotected=1
```

Nothing is applied at boot, so the machine comes up open. The control plane will say so plainly
rather than pretending otherwise. Take the word back out afterwards, or the machine will keep
starting unprotected.

### 3. From a rescue shell

```console
$ sudo nft destroy table inet ghostnector
$ sudo rm -f /var/lib/ghostnector/intent.json
```

The first line removes Ghostnector's entire firewall policy. The second line forgets that protection
was requested, so the next boot does not re-apply it. Nothing else on the machine is touched: the
table is the one Ghostnector owns, and no other table was ever modified.

## What is deliberately *not* a way out

- **Editing the configuration to weaken a check.** Verification failing is what put the machine in
  this state; silencing the check would hide the reason rather than fix it.
- **Deleting the firewall table without clearing the intent.** It works until the next boot, when the
  guard applies the policy again — and now for a reason nobody can see.
- **Disabling `ghostnector-bootguard`.** Same trap: the intent outlives the unit.

## Why a machine denies everything in the first place

| What happened | What Ghostnector did | Why |
|---|---|---|
| Rebooted while protection was on | applied the fail-closed policy before any application started | kernel state does not survive a reboot, and the alternative is being open while you believe you are not |
| A verification check failed | denied everything and said which check failed | something was observed leaving outside the protected path; assuming it was harmless is not a decision this program gets to make |
| The journal could not be read at boot | denied everything and said so | a journal that cannot be read is not evidence that nothing was requested |

## Checking what actually happened

```console
$ ghostnector status                       # the state, the reasons, and the exemptions
$ journalctl -u ghostnector-bootguard     # what the guard did at boot
$ journalctl -u ghostnector-netd          # what the privileged helper applied
$ sudo nft list table inet ghostnector    # what is actually in the kernel
```
