//! Wire protocol for the interface, the CLI, the core daemon, and the privileged helper.
//!
//! The transport is newline-delimited JSON of [`Frame`] over a unix socket. JSON is chosen
//! deliberately: it is inspectable during development and review, and the messages are small. The
//! privilege boundary is not the framing, it is the closed verb set in [`crate::backend`] plus peer
//! credential checks at the socket.

use serde::{Deserialize, Serialize};

use crate::profile::{Profile, Warning};
use crate::state::Snapshot;

/// Wire protocol version.
///
/// A mismatch is a hard failure, never a best-effort negotiation: version skew between components
/// that disagree about policy is exactly how holes appear.
pub const PROTOCOL_VERSION: u32 = 1;

/// Requests accepted by the core daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "request")]
pub enum Request {
    /// Handshake; must be the first frame on a connection.
    Hello {
        /// The protocol version the client speaks.
        protocol: u32,
        /// A non-sensitive client identifier for logs.
        client: String,
    },
    /// Fetch the current snapshot.
    Snapshot,
    /// Request a transition into the given profile (validated by the daemon).
    Connect {
        /// The requested profile, before validation.
        profile: Profile,
    },
    /// Return to the captured baseline.
    Disconnect,
    /// Apply the fail-closed baseline immediately, leaving services running.
    Panic,
    /// Cancel an in-flight transition.
    Cancel,
    /// Subscribe to state-change events.
    Subscribe,
}

/// Responses from the core daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "response")]
pub enum Response {
    /// Handshake reply carrying the daemon's version.
    Hello {
        /// The protocol version the daemon speaks.
        protocol: u32,
        /// The daemon's package version.
        daemon_version: String,
    },
    /// The current snapshot.
    Snapshot(Box<Snapshot>),
    /// The request was accepted; progress is reported through events.
    Accepted,
    /// The request failed.
    Error(ErrorBody),
}

/// Asynchronous notifications after [`Request::Subscribe`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "event")]
pub enum Event {
    /// The protection state or health changed.
    StateChanged(Box<Snapshot>),
    /// Egress was denied by policy. A cumulative count, never a destination.
    DeniedEgress {
        /// Cumulative denied-egress count since the last Connect.
        count: u64,
    },
    /// A profile-level warning applies to the current state.
    Warning(Warning),
    /// A discrete, non-sensitive notice worth showing to the user.
    Notice {
        /// The notice text.
        message: String,
    },
}

/// A failure, with an explicit flag for whether the detail is sensitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Machine-readable code.
    pub code: ErrorCode,
    /// Human-readable message. Must never contain destinations, queries, or secrets.
    pub message: String,
    /// True when the message should be shown only on explicit user request.
    pub sensitive: bool,
}

/// Closed set of failure codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Protocol version mismatch; a component must be updated.
    ProtocolMismatch,
    /// The peer is not authorised for the requested transition.
    NotAuthorized,
    /// The profile failed validation.
    InvalidProfile,
    /// Another transition is in flight.
    Busy,
    /// The privileged helper refused or failed the operation.
    BackendFailure,
    /// The requested state is not reachable from the current one.
    UnsafeState,
    /// Internal error; details are in the message.
    Internal,
}

/// Responses from the privileged helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum HelperResponse {
    /// Handshake reply carrying the helper's version.
    Hello {
        /// The helper protocol version the helper speaks.
        protocol: u32,
        /// The helper's package version.
        version: String,
    },
    /// A verb was carried out; the report reflects the state afterwards.
    Applied {
        /// The state after the operation.
        report: crate::backend::Report,
    },
    /// The current state, with nothing changed.
    Report(crate::backend::Report),
    /// The answer to [`crate::backend::Verb::Verify`].
    Verified {
        /// Whether the kernel's policy is the one that was applied.
        matches: bool,
        /// The first difference, or a note when there is none. Policy text only: no destinations
        /// and no traffic.
        detail: String,
    },
    /// The verb failed.
    Error(ErrorBody),
}

/// A single framed message. The transport is newline-delimited JSON of `Frame`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "frame")]
pub enum Frame {
    /// Client to daemon.
    Request(Request),
    /// Daemon to client.
    Response(Response),
    /// Daemon to subscribed clients.
    Event(Event),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Networks, Scope};
    use crate::state::{Health, ProtectionState};

    #[test]
    fn frames_round_trip() {
        let frames = [
            Frame::Request(Request::Hello {
                protocol: PROTOCOL_VERSION,
                client: "ghostnector-cli/0.1".to_string(),
            }),
            Frame::Request(Request::Connect {
                profile: Profile {
                    scope: Scope::System,
                    networks: Networks::tor(),
                    ..Profile::default()
                },
            }),
            Frame::Request(Request::Panic),
            Frame::Response(Response::Accepted),
            Frame::Response(Response::Hello {
                protocol: PROTOCOL_VERSION,
                daemon_version: "0.1.0".to_string(),
            }),
            Frame::Response(Response::Snapshot(Box::new(Snapshot {
                state: ProtectionState::Blocked,
                ..Snapshot::default()
            }))),
            Frame::Response(Response::Error(ErrorBody {
                code: ErrorCode::BackendFailure,
                message: "policy apply rejected".to_string(),
                sensitive: false,
            })),
            Frame::Event(Event::DeniedEgress { count: 4 }),
            Frame::Event(Event::Warning(Warning::I2pExposesHostIp)),
            Frame::Event(Event::Notice {
                message: "tor bootstrapped".to_string(),
            }),
        ];

        for frame in frames {
            let json = serde_json::to_string(&frame).unwrap();
            let decoded: Frame = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, frame, "round trip changed {json}");
        }
    }

    #[test]
    fn frames_are_single_line() {
        // The transport is newline-delimited, so no serialised frame may contain a newline.
        let frame = Frame::Event(Event::Notice {
            message: "multi\nline".to_string(),
        });
        let json = serde_json::to_string(&frame).unwrap();
        assert!(!json.contains('\n'));
    }

    #[test]
    fn error_codes_are_a_closed_set() {
        for (code, tag) in [
            (ErrorCode::ProtocolMismatch, "protocol_mismatch"),
            (ErrorCode::NotAuthorized, "not_authorized"),
            (ErrorCode::InvalidProfile, "invalid_profile"),
            (ErrorCode::Busy, "busy"),
            (ErrorCode::BackendFailure, "backend_failure"),
            (ErrorCode::UnsafeState, "unsafe_state"),
            (ErrorCode::Internal, "internal"),
        ] {
            assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{tag}\""));
        }
    }

    #[test]
    fn health_is_not_carried_in_errors() {
        // Errors are text plus a code; there is no field that could smuggle a destination.
        let body = ErrorBody {
            code: ErrorCode::Internal,
            message: "unexpected".to_string(),
            sensitive: false,
        };
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(
            json,
            r#"{"code":"internal","message":"unexpected","sensitive":false}"#
        );
        let _ = Health::default();
    }
}
