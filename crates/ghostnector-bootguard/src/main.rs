//! The boot guard.
//!
//! Kernel state does not survive a reboot, so a machine that was protected when it stopped is open
//! while it starts: for those seconds, if an application managed to send something, it would leave
//! by the front door. This program closes that window.
//!
//! It runs early, as root, and does one of three things:
//!
//! 1. **Nothing**, if the journal says protection was not requested — the machine is meant to be
//!    open, so it stays open.
//! 2. **Nothing**, if the kernel command line carries `ghostnector.unprotected=1`. That is the
//!    documented way out for an operator whose machine will not come up, and it is deliberately
//!    something you can only do at the console.
//! 3. **Denies everything**, if protection was requested: first by asking the privileged helper, and
//!    — if the helper cannot be reached — by applying the copy of the fail-closed policy that the
//!    helper left behind.
//!
//! A journal that cannot be read is treated as "protection was requested", because the alternative
//! is a machine that is open while its owner believes otherwise. Recovery is documented in
//! `docs/RECOVERY.md`, and it does not need the network.

#[cfg(unix)]
mod guard;

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    guard::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("ghostnector-bootguard is a Linux component and cannot run on this platform");
    std::process::exit(2);
}
