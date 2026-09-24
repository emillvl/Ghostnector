// This crate is a Linux component: it talks to a unix socket, reads the system user database, and
// manages a system service's runtime files.
#![cfg(unix)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Ghostnector's control plane.
//!
//! [`netd`](ghostnector_netd) is the only component with privileges; this one holds none, and that
//! shapes everything here:
//!
//! * **It decides, it does not enforce.** Enforcement lives in the kernel and survives this process
//!   dying (DR-14). On startup it reconciles itself against the kernel rather than trusting its own
//!   memory or its journal.
//! * **It never returns to the clearnet on its own.** Once protection has been established, an
//!   automatic transition to `Off` is refused by the state machine (DR-15). Failures escalate to
//!   `Blocked`; only an explicit user request turns protection off.
//! * **It reports what it does not know.** Until the verifier exists, a successfully applied policy
//!   is reported as `Degraded` with verification `Unavailable` — never as `Protected`.

pub mod chokepoint;
pub mod engine;
pub mod fsutil;
pub mod helper;
pub mod journal;
pub mod resolver;
pub mod server;
pub mod services;
pub mod state;
pub mod supervisor;
pub mod tools;
pub mod torcontrol;
pub mod torrc;
pub mod verify;

#[cfg(test)]
pub mod testing;

pub use chokepoint::{ChildRelay, ChokepointError, DnsRelay};
pub use engine::{Engine, EngineConfig, EngineError};
pub use helper::{Helper, HelperError, HelperLink};
pub use journal::{Intent, Journal, JournalError};
pub use resolver::{
    Baseline, BaselineStore, CommandError, CommandRunner, Environment, Layout, Resolver,
    ResolverError, RestoreOutcome, SystemCommands,
};
pub use server::{bind_socket, Server, ServerError};
pub use services::{ExternalServices, ServiceError, Services, SystemdServices};
pub use state::{Cause, Machine, TransitionError};
pub use supervisor::{ServiceState, Supervisor, SupervisorError, SystemdUnits};
pub use torcontrol::{Bootstrap, TorControl, TorControlError};
pub use torrc::TorSettings;
pub use verify::{
    Canary, HttpEndpoint, NetworkProbes, Outcome, ProbeResult, Probes,
    Report as VerificationReport, Verification, VerificationConfig, Verifier,
};

/// The package version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Seconds since the unix epoch, as the interfaces use it.
///
/// A clock before 1970 would be a stranger problem than this function; zero keeps it harmless.
pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}
