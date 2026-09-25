#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Shared, OS-independent vocabulary for Ghostnector.
//!
//! Nothing in this crate touches the kernel, the filesystem, or the network. That is deliberate:
//! it means the policy vocabulary can be exhaustively tested on any host, and it keeps the door
//! open for a non-Linux backend later without rewriting the policy layer.
//!
//! The two most important properties this crate encodes are:
//!
//! * **Valid combinations only** ([`profile`]). The architecture review's central critique is that
//!   independently toggleable components admit incoherent, unsafe combinations (Tor carrying
//!   traffic while DNS resolves on the clearnet). Here, downstream code only ever receives a
//!   [`ValidProfile`], which cannot exist unless it passed validation.
//! * **A closed privileged interface** ([`backend`]). The helper that touches the kernel accepts a
//!   fixed set of verbs carrying only a named profile and bounded integers. There is deliberately
//!   no variant that can express an arbitrary ruleset, command, or path (invariant I9).

pub mod app;
pub mod appd;
pub mod backend;
pub mod exemption;
pub mod ipc;
pub mod profile;
pub mod state;

pub use app::{
    app_core_element, valid_interface_name, APP_LINK_PREFIX, APP_NETNS_PREFIX, DEFAULT_APP_BRIDGE,
    DEFAULT_APP_CORE_ADDRESS, DEFAULT_APP_DEAD_DEVICE, DEFAULT_APP_PREFIX, MAX_APP_GROUPS,
};
pub use appd::{AppEntry, AppReport, AppResponse, AppVerb, APP_PROTOCOL_VERSION};
pub use backend::{Params, Ports, ProfileId, Report, ResolvedIdentity, Verb};
pub use exemption::{Exemption, ExemptionKind};
pub use ipc::{
    ErrorBody, ErrorCode, Event, Frame, HelperResponse, Request, Response, PROTOCOL_VERSION,
};
pub use profile::{Networks, Profile, ProfileError, Scope, ValidProfile, Warning};
pub use state::{
    AppStatus, Health, ProtectionState, Reason, ServiceHealth, Snapshot, Verification,
};
