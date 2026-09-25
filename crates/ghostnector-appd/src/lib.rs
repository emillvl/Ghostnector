// This crate is a Linux component: it creates network namespaces, moves links into them, and
// speaks netlink through fixed tools.
#![cfg(unix)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! The APP-scope namespace helper.
//!
//! `netd` owns the host firewall and must not be widened with `CAP_SYS_ADMIN` (risk R7). This crate
//! is the second, narrowly scoped privileged component: it creates the bridge, creates and destroys
//! one dead-end namespace per isolation group, installs the namespace-local ruleset that is the
//! only mechanism capable of creating a usable path (M8 decision 1), and compares what the
//! namespace actually holds against what was installed.
//!
//! Three rules shape everything here:
//!
//! * **The verb set is closed and typed** ([`ghostnector_spec::appd`]). A client may ask for an
//!   operation with a bounded integer; it cannot name a namespace, an interface, a path, a command,
//!   or a ruleset. Every object name is generated from the id.
//! * **The ruleset is compiled and proved here**, by the same policy crate the host firewall uses,
//!   and checked again by the namespace invariant set before it reaches the kernel.
//! * **The effective policy is the kernel's own report**, canonicalised by the shared comparison
//!   from `ghostnector-policy`, not by anything this process remembers about its intentions.

pub mod backend;
pub mod config;
pub mod registry;
pub mod server;

#[cfg(test)]
pub mod hardening;
#[cfg(test)]
pub mod testing;

pub use backend::{BackendError, Namespaces, SystemNamespaces};
pub use config::{Config, ConfigError, Parsed};
pub use registry::{AppRecord, Registry, RegistryError};
pub use server::{bind_socket, Server, ServerError};

/// The package version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
