// This crate is a Linux component: it speaks to nftables, system uids, and unix sockets. Gating the
// whole crate keeps `cargo check` and `clippy` meaningful on a development machine of any platform,
// while the cross-target check validates the real thing.
#![cfg(unix)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! The privileged helper: the only Ghostnector component that touches the kernel.
//!
//! It exists because policy changes need `CAP_NET_ADMIN`, and everything else should not have it.
//! The design constraints follow from that:
//!
//! * **A closed verb set.** It accepts [`Verb`](ghostnector_spec::backend::Verb), which carries a
//!   named profile and bounded integers. There is no request that can express a ruleset, a shell
//!   command, a filesystem path, or an interpreter string (invariant I9).
//! * **One writer.** Only this process writes Ghostnector's nftables table. It renders the ruleset
//!   from its own tables and applies it as one atomic batch.
//! * **No shell.** Policy tools are invoked with an absolute path, a fixed argument list, and the
//!   ruleset on standard input.
//! * **A peer it can name.** The socket is owned by the allowed uid and mode 0600, and every
//!   connection is re-checked with `SO_PEERCRED`. Both gates must pass.
//!
//! What it deliberately does *not* do: capture the baseline, restore resolver configuration, manage
//! services, or track user intent. Those belong to `core`, which holds no privileges at all.

pub mod backend;
pub mod config;
pub mod identities;
pub mod server;

#[cfg(test)]
pub mod testing;

pub use backend::{Backend, BackendError, NftCli};
pub use config::{Config, ConfigError, Parsed};
pub use identities::{Identities, IdentityError, SystemIdentities};
pub use server::{bind_socket, Server, ServerError};

/// The package version, reported in handshakes.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
