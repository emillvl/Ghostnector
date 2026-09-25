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
    /// Run the fixed verification probe inside one group.
    ///
    /// The probe is a product binary run by the helper with no command line at all; it reads the
    /// check configuration below on standard input and prints typed verdicts. It runs as an
    /// unprivileged uid inside the namespace, so a caller cannot use it to obtain privilege — only
    /// to ask the same three questions the host-scope verifier asks.
    Probe {
        /// The group's id.
        id: u32,
        /// The checks to run. Endpoints are the operator's verification configuration, validated
        /// and bounded by the helper before the probe sees them.
        config: ProbeConfig,
    },
    /// List every group the helper knows, with no traffic information of any kind.
    ReportRegistry,
    /// Destroy every group and the bridge: the APP-scope equivalent of reverting the policy.
    Revert,
}

/// A single check's verdict, as the probe reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// The check ran and the result was the expected one.
    Passed,
    /// The check ran and the result was wrong. This is an alarm.
    Failed,
    /// The check could not reach a conclusion, which is never a pass.
    Inconclusive,
}

/// One check's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckVerdict {
    /// Which check: `udp`, `protected-path`, or `canary`.
    pub check: String,
    /// What it concluded.
    pub status: CheckStatus,
    /// A short, non-sensitive explanation.
    pub detail: String,
    /// For the protected-path check, the address the endpoint reported, if any.
    #[serde(default)]
    pub address: Option<Ipv4Addr>,
}

/// What the whole probe run concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum ProbeOutcome {
    /// Every check that could run passed.
    Passed,
    /// At least one check observed something wrong.
    Failed {
        /// Why, in one line.
        reason: String,
    },
    /// No check could reach a conclusion.
    Inconclusive {
        /// Why, in one line.
        reason: String,
    },
}

/// The endpoint for the liveness and identity check inside a namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCheck {
    /// Where to connect. Any destination works: the namespace DNAT carries it to the core address.
    pub address: std::net::SocketAddr,
    /// The `Host` header, which is also the name the endpoint expects.
    pub host: String,
    /// The path to request.
    pub path: String,
}

/// A name that should resolve to one particular address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryCheck {
    /// The name to ask for.
    pub name: String,
    /// The address only the right resolver should give.
    pub expected: Ipv4Addr,
    /// Which resolver to ask, usually the core chokepoint.
    pub resolver: std::net::SocketAddr,
}

/// The checks the probe should run inside a namespace.
///
/// Every field is optional: with nothing configured, every check is inconclusive and the state
/// honestly says nothing has verified the group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProbeConfig {
    /// A UDP endpoint that answers if a datagram reaches it.
    pub udp: Option<std::net::SocketAddr>,
    /// An endpoint that answers `200` to a GET if the protected path works.
    pub http: Option<HttpCheck>,
    /// A name that should resolve to a known address.
    pub canary: Option<CanaryCheck>,
    /// How long a single network operation may take, in seconds.
    pub timeout_seconds: u64,
    /// The host-local core address. Filled in by the helper from its own configuration; a value
    /// from a client is ignored, because it is not the client's machine.
    #[serde(default)]
    pub core: Option<Ipv4Addr>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            udp: None,
            http: None,
            canary: None,
            timeout_seconds: 10,
            core: None,
        }
    }
}

/// One APP isolation group, as shown to the control plane.///
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
    /// The answer to [`AppVerb::Probe`].
    Probed {
        /// What the probe run concluded.
        outcome: ProbeOutcome,
        /// One line per check, safe to show.
        details: Vec<String>,
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
        let probe = AppVerb::Probe {
            id: 7,
            config: ProbeConfig {
                timeout_seconds: 5,
                ..ProbeConfig::default()
            },
        };
        assert_eq!(
            serde_json::to_string(&probe).unwrap(),
            r#"{"verb":"probe","id":7,"config":{"udp":null,"http":null,"canary":null,"timeout_seconds":5,"core":null}}"#
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
            AppVerb::Probe {
                id: 1,
                config: ProbeConfig::default(),
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
            AppResponse::Probed {
                outcome: ProbeOutcome::Failed {
                    reason: "a UDP datagram reached 203.0.113.1".to_string(),
                },
                details: vec!["failed: a UDP datagram reached 203.0.113.1".to_string()],
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
