//! Protection lifecycle, service health, and the interface-facing snapshot.

use serde::{Deserialize, Serialize};

use crate::exemption::Exemption;
use crate::profile::{Profile, Warning};

/// Lifecycle state of the protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionState {
    /// No policy is applied; the network is as the user left it.
    #[default]
    Off,
    /// A transition is in flight. Together with `Off`, this is the only state from which
    /// Ghostnector may return to the captured baseline automatically (review §11.4, DR-15).
    Applying,
    /// Policy applied, services healthy, verification fresh.
    Protected,
    /// Policy applied, but something non-fatal is wrong: verification is stale or unavailable, or
    /// an optional service is down. Traffic is still under policy.
    Degraded,
    /// Fail-closed: no path to the clearnet exists, whatever the cause.
    Blocked,
    /// A captive-portal exception is active. Transient, never survives a reboot.
    Portal,
}

impl ProtectionState {
    /// True when traffic in the protected scope is expected to be under policy.
    pub const fn is_protected(self) -> bool {
        matches!(self, Self::Protected | Self::Degraded)
    }

    /// True when the state guarantees no path to the clearnet.
    pub const fn is_denied(self) -> bool {
        matches!(self, Self::Blocked)
    }

    /// Whether Ghostnector may return to the user's captured baseline *automatically*.
    ///
    /// This is the code-level form of DR-15: rollback is a recovery mechanism for a protection that
    /// was never established, never a fallback for a protection that failed later.
    pub const fn may_auto_rollback(self) -> bool {
        matches!(self, Self::Off | Self::Applying)
    }
}

/// A short, non-sensitive explanation for a state change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reason(pub String);

impl Reason {
    /// Construct from anything string-like.
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Health of a managed service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceHealth {
    /// No information yet.
    #[default]
    Unknown,
    /// Not running.
    Down,
    /// Starting or bootstrapping.
    Starting,
    /// Running and usable.
    Up,
    /// Running but impaired (for example: Tor bootstrapped through a slow bridge).
    Degraded,
}

/// Freshness of the independent verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    /// No verification has run yet.
    #[default]
    Unknown,
    /// Recent and passing.
    Fresh,
    /// Passing but older than the freshness window.
    Stale,
    /// Could not run (for example: no vantage point reachable).
    Unavailable,
    /// Ran and observed something wrong; the state must escalate to `Blocked`.
    Failed,
}

/// Aggregate health. Every field is non-sensitive by construction.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Health {
    /// Tor client health.
    pub tor: ServiceHealth,
    /// Resolver path health (Tor's `DNSPort` or the authenticated resolver).
    pub dns: ServiceHealth,
    /// I2P router health.
    pub i2p: ServiceHealth,
    /// Whether Ghostnector's policy is currently installed in the kernel.
    pub policy_applied: bool,
    /// Verification freshness.
    pub verification: Verification,
}

/// Everything the interface needs, and nothing sensitive (invariant I6 / DR-19).
///
/// Note what is *absent*: destinations, queries, per-connection records, exit addresses, guard
/// fingerprints, and byte counts per flow.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    /// Current lifecycle state.
    pub state: ProtectionState,
    /// The profile in force, if any.
    pub profile: Option<Profile>,
    /// Warnings the interface must display for the profile in force.
    pub warnings: Vec<Warning>,
    /// Short, non-sensitive reasons for the current state.
    pub reasons: Vec<Reason>,
    /// The complete list of holes in the policy, for display (invariant I8).
    pub exemptions: Vec<Exemption>,
    /// Health of each managed service.
    pub health: Health,
    /// Seconds since the last successful verification.
    pub verified_ago_secs: Option<u64>,
    /// Egress attempts denied by policy since the last Connect. A count only.
    pub blocked_egress_attempts: u64,
    /// Bumped on every transition so clients can discard stale updates.
    pub generation: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_is_only_allowed_before_protection_was_established() {
        assert!(ProtectionState::Off.may_auto_rollback());
        assert!(ProtectionState::Applying.may_auto_rollback());
        for state in [
            ProtectionState::Protected,
            ProtectionState::Degraded,
            ProtectionState::Blocked,
            ProtectionState::Portal,
        ] {
            assert!(
                !state.may_auto_rollback(),
                "{state:?} must never return to the clearnet on its own (DR-15)"
            );
        }
    }

    #[test]
    fn protected_and_denied_are_different_things() {
        assert!(ProtectionState::Protected.is_protected());
        assert!(ProtectionState::Degraded.is_protected());
        assert!(!ProtectionState::Blocked.is_protected());
        assert!(ProtectionState::Blocked.is_denied());
        assert!(!ProtectionState::Protected.is_denied());
    }

    #[test]
    fn snapshot_defaults_to_a_safe_reading() {
        let snapshot = Snapshot::default();
        assert_eq!(snapshot.state, ProtectionState::Off);
        assert!(!snapshot.health.policy_applied);
        assert_eq!(snapshot.health.verification, Verification::Unknown);
        assert_eq!(snapshot.blocked_egress_attempts, 0);
    }

    #[test]
    fn snapshot_round_trips() {
        let snapshot = Snapshot {
            state: ProtectionState::Protected,
            profile: Some(Profile {
                scope: crate::profile::Scope::System,
                networks: crate::profile::Networks::tor(),
                ..Profile::default()
            }),
            warnings: vec![Warning::SystemScopeCoversAllUsers],
            reasons: vec![Reason::new("tor bootstrapped")],
            exemptions: crate::exemption::tor_baseline(),
            health: Health {
                tor: ServiceHealth::Up,
                dns: ServiceHealth::Up,
                i2p: ServiceHealth::Unknown,
                policy_applied: true,
                verification: Verification::Fresh,
            },
            verified_ago_secs: Some(12),
            blocked_egress_attempts: 3,
            generation: 7,
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let decoded: Snapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn reason_text_is_just_text() {
        let reason = Reason::new("service stopped");
        assert_eq!(reason.as_str(), "service stopped");
    }
}
