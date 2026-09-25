//! The namespace helper's closed verb set.
//!
//! This is a second privileged interface, and it follows the same rule as [`crate::backend`]: it is
//! **closed and typed**. No verb carries a namespace name, an interface name, a path, a command, an
//! interpreter string, or a ruleset. A client may only ask for a named operation with a bounded
//! integer id; every object name, address, and ruleset is derived by the helper from its own
//! registry and configuration.
//!
//! The one piece of data that is not an id is [`crate::backend::Ports`]: the ports the *host*
//! firewall redirects into. They are reported by `netd` and passed through by the control plane so
//! both halves of APP scope name the same listeners — the D-22 lesson applied to APP scope. They
//! are two bounded integers plus a third, validated by the helper before use.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::backend::Ports;
use crate::ipc::ErrorBody;

/// Wire protocol version for the namespace helper.
///
/// A mismatch is a hard failure on both sides, exactly as on the other sockets.
pub const APP_PROTOCOL_VERSION: u32 = 1;

/// Requests accepted by `ghostnector-appd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "verb")]
pub enum AppVerb {
    /// Handshake. Must be the first request on a connection; a version mismatch is fatal.
    Hello {
        /// The protocol version the caller speaks.
        protocol: u32,
    },
    /// Idempotently ensure the bridge exists with the configured core address, and remember the
    /// ports the namespace rules must name. Safe to call before every transition.
    EnsureBridge {
        /// The ports the host firewall redirects into, as reported by `netd`.
        ports: Ports,
    },
    /// Create one isolation group for a user.
    ///
    /// The caller names the user the group belongs to (a bounded integer, not a name). The helper
    /// records it and, for a session, enforces it against the kernel: only a connection from that
    /// uid can drive the shell.
    Create {
        /// The user the group belongs to.
        user_uid: u32,
    },
    /// Destroy one isolation group. Idempotent: an unknown or already-destroyed id is not an error.
    Destroy {
        /// The group's id, as allocated by the helper.
        id: u32,
    },
    /// Report what the helper knows about one group, and whether its objects are still present.
    Inspect {
        /// The group's id.
        id: u32,
    },
    /// Compare the namespace's effective ruleset and shape against what was installed.
    Verify {
        /// The group's id.
        id: u32,
    },
    /// Prepare a shell session inside one group.
    ///
    /// The caller names the intended user (a bounded integer, not a command or a path). The helper
    /// enforces it against the kernel: the connection that drives the shell must come from exactly
    /// that uid via `SO_PEERCRED`, so a caller cannot obtain a shell as someone else.
    Launch {
        /// The group's id.
        id: u32,
        /// The user the session is for.
        user_uid: u32,
    },
    /// List every group the helper knows, with no traffic information of any kind.
    ReportRegistry,
    /// Destroy every group and the bridge: the APP-scope equivalent of reverting the policy.
    Revert,
}

/// One APP isolation group, as shown to the control plane.
///
/// Note what is absent: no destinations, no traffic counters, no queries. An id, the owner, the
/// address the helper assigned, when it was created, and whether its objects are still present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppEntry {
    /// The id the helper allocated.
    pub id: u32,
    /// The uid that asked for it, from `SO_PEERCRED` at creation.
    pub owner_uid: u32,
    /// The app address assigned inside the namespace.
    pub address: Ipv4Addr,
    /// When the group was created, in seconds since the epoch.
    pub created_at: i64,
    /// Whether the namespace and link exist right now, as the helper last observed.
    pub present: bool,
}

/// The helper's state, safe to show the interface (invariant I6 / DR-19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppReport {
    /// Whether the bridge exists with the core address.
    pub bridge_present: bool,
    /// The host-local core address the bridge carries.
    pub core: Ipv4Addr,
    /// Every registered group.
    pub entries: Vec<AppEntry>,
    /// Operational notes that are not failures.
    pub notes: Vec<String>,
}

impl Default for AppReport {
    fn default() -> Self {
        Self {
            bridge_present: false,
            core: crate::app::DEFAULT_APP_CORE_ADDRESS,
            entries: Vec::new(),
            notes: Vec::new(),
        }
    }
}

/// Replies from `ghostnector-appd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum AppResponse {
    /// Handshake reply.
    Hello {
        /// The helper protocol version.
        protocol: u32,
        /// The helper's package version.
        version: String,
    },
    /// A state-changing verb succeeded; the report reflects the state afterwards.
    Applied {
        /// The state after the operation.
        report: AppReport,
    },
    /// A group was created.
    Created {
        /// The new group.
        entry: AppEntry,
    },
    /// The answer to [`AppVerb::Inspect`].
    Inspected {
        /// The group, or `None` when no group has that id.
        entry: Option<AppEntry>,
        /// Notes, for example that the objects are missing.
        notes: Vec<String>,
    },
    /// The answer to [`AppVerb::Verify`].
    Verified {
        /// Whether the namespace shape and ruleset are the ones that were installed.
        matches: bool,
        /// The first difference, or a note when there is none. Policy text only.
        detail: String,
    },
    /// A shell session is prepared.
    Launched {
        /// The group the session belongs to.
        entry: AppEntry,
        /// The socket the intended user connects to. Derived by the helper from its own state
        /// directory and the group id; never accepted from a client.
        socket: String,
    },
    /// The answer to [`AppVerb::ReportRegistry`].
    Report(AppReport),
    /// The verb failed.
    Error(ErrorBody),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_verb_tags_are_a_closed_set() {
        assert_eq!(
            serde_json::to_string(&AppVerb::Hello { protocol: 1 }).unwrap(),
            r#"{"verb":"hello","protocol":1}"#
        );
        assert_eq!(
            serde_json::to_string(&AppVerb::Create { user_uid: 1000 }).unwrap(),
            r#"{"verb":"create","user_uid":1000}"#
        );
        assert_eq!(
            serde_json::to_string(&AppVerb::Destroy { id: 7 }).unwrap(),
            r#"{"verb":"destroy","id":7}"#
        );
        assert_eq!(
            serde_json::to_string(&AppVerb::Inspect { id: 7 }).unwrap(),
            r#"{"verb":"inspect","id":7}"#
        );
        assert_eq!(
            serde_json::to_string(&AppVerb::Verify { id: 7 }).unwrap(),
            r#"{"verb":"verify","id":7}"#
        );
        assert_eq!(
            serde_json::to_string(&AppVerb::Launch {
                id: 7,
                user_uid: 1000
            })
            .unwrap(),
            r#"{"verb":"launch","id":7,"user_uid":1000}"#
        );
        assert_eq!(
            serde_json::to_string(&AppVerb::ReportRegistry).unwrap(),
            r#"{"verb":"report_registry"}"#
        );
        assert_eq!(
            serde_json::to_string(&AppVerb::Revert).unwrap(),
            r#"{"verb":"revert"}"#
        );
    }

    #[test]
    fn parameters_cannot_expand_the_interface() {
        // The only non-id input is the typed `Ports`; there is no field anywhere that could carry a
        // name, a path, a command, or a ruleset.
        let verb = AppVerb::EnsureBridge {
            ports: Ports {
                trans: 9040,
                chokepoint: 53,
                socks: 9050,
            },
        };
        assert_eq!(
            serde_json::to_string(&verb).unwrap(),
            r#"{"verb":"ensure_bridge","ports":{"trans":9040,"chokepoint":53,"socks":9050}}"#
        );
    }

    #[test]
    fn requests_and_responses_round_trip() {
        let verbs = [
            AppVerb::Hello {
                protocol: APP_PROTOCOL_VERSION,
            },
            AppVerb::EnsureBridge {
                ports: Ports::default(),
            },
            AppVerb::Create { user_uid: 1000 },
            AppVerb::Destroy { id: 1 },
            AppVerb::Inspect { id: 1 },
            AppVerb::Verify { id: 1 },
            AppVerb::Launch {
                id: 1,
                user_uid: 1000,
            },
            AppVerb::ReportRegistry,
            AppVerb::Revert,
        ];
        for verb in verbs {
            let json = serde_json::to_string(&verb).unwrap();
            assert_eq!(serde_json::from_str::<AppVerb>(&json).unwrap(), verb);
        }

        let responses = [
            AppResponse::Hello {
                protocol: APP_PROTOCOL_VERSION,
                version: "0.1.0".to_string(),
            },
            AppResponse::Applied {
                report: AppReport::default(),
            },
            AppResponse::Created {
                entry: AppEntry {
                    id: 1,
                    owner_uid: 1000,
                    address: Ipv4Addr::new(10, 200, 0, 2),
                    created_at: 1,
                    present: true,
                },
            },
            AppResponse::Verified {
                matches: true,
                detail: "the namespace is the one that was installed".to_string(),
            },
            AppResponse::Launched {
                entry: AppEntry {
                    id: 1,
                    owner_uid: 1000,
                    address: Ipv4Addr::new(10, 200, 0, 2),
                    created_at: 1,
                    present: true,
                },
                socket: "/run/ghostnector/apps/1/stdio.sock".to_string(),
            },
            AppResponse::Report(AppReport::default()),
        ];
        for response in responses {
            let json = serde_json::to_string(&response).unwrap();
            assert_eq!(
                serde_json::from_str::<AppResponse>(&json).unwrap(),
                response
            );
        }
    }

    #[test]
    fn a_report_carries_no_traffic_metadata() {
        let report = AppReport {
            bridge_present: true,
            core: crate::app::DEFAULT_APP_CORE_ADDRESS,
            entries: vec![AppEntry {
                id: 3,
                owner_uid: 1000,
                address: Ipv4Addr::new(10, 200, 0, 4),
                created_at: 42,
                present: true,
            }],
            notes: vec!["nothing to report".to_string()],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("destination"), "{json}");
        assert!(!json.contains("query"), "{json}");
        assert!(!json.contains("bytes"), "{json}");
        assert!(json.contains("\"owner_uid\":1000"), "{json}");
    }
}
