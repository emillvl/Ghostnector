//! The closed verb set of the privileged helper.
//!
//! Invariant I9: the helper that touches the kernel exposes no verb that accepts an arbitrary
//! ruleset, shell command, filesystem path, or interpreter string from an unprivileged peer. A
//! client can select a named profile and supply bounded integers; everything else is rendered by
//! the helper from its own tables. Encoding this in the shared vocabulary means a future change
//! that widens the interface has to change a type that reviewers are looking at.

use serde::{Deserialize, Serialize};

/// A named policy profile the helper knows how to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileId {
    /// Deny everything except loopback, DHCP, and Tor's own egress. Applied before any service
    /// starts, so the host is never more permissive than this during a transition (DR-4).
    FailClosed,
    /// Encrypted-DNS lockdown; no overlay network.
    DnsLockdown,
    /// Transparent Tor for every local uid.
    TorSystem,
    /// Transparent Tor for a single uid.
    TorUser,
    /// Transparent Tor inside one route-less namespace.
    TorApp,
    /// I2P router isolated in its own namespace.
    I2pIsolated,
}

/// Bounded, typed parameters accepted alongside a [`ProfileId`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Params {
    /// The uid a `TorUser` profile applies to.
    pub user_uid: Option<u32>,
    /// A namespace identifier from the helper's own registry (`TorApp`, `I2pIsolated`).
    pub netns_id: Option<u32>,
    /// Whether the local network is reachable from the protected scope.
    pub allow_lan: bool,
}

/// Requests the privileged helper accepts.
///
/// This set is closed. In particular, there is no variant carrying a ruleset: a compromised or
/// malicious client can only ask for a policy the helper already knows how to build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "verb")]
pub enum Verb {
    /// Handshake. Must be the first request on a connection; a version mismatch is fatal.
    Hello {
        /// The helper protocol version the caller speaks.
        protocol: u32,
    },
    /// Apply a named profile, atomically replacing Ghostnector's previous policy.
    ApplyProfile {
        /// Which named profile to render.
        profile: ProfileId,
        /// Typed parameters for that profile.
        params: Params,
    },
    /// Remove Ghostnector's policy. The captured baseline is restored by core, not by the helper.
    Revert,
    /// Compare the policy in the kernel against the one this helper applied.
    ///
    /// The comparison is against what the *kernel* reported when it was applied, not against what
    /// this helper intended: a change made by anything else is therefore visible, whether or not the
    /// helper knows about it.
    Verify,
    /// Drop conntrack entries so pre-existing flows cannot survive a transition.
    FlushConntrack,
    /// Report what Ghostnector currently has installed, and which uids it resolved.
    Report,
}

/// A system identity the helper resolved, for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedIdentity {
    /// Configured user name, for example `debian-tor`.
    pub name: String,
    /// Resolved uid, or `None` when the identity is not installed on this machine.
    pub uid: Option<u32>,
}

/// The port the DNS chokepoint listens on, and therefore the port the machine's resolver is pointed
/// at.
///
/// This is the one port that cannot be chosen freely. A `nameserver` line and `resolvectl dns` both
/// take an address without a port, so `nameserver 127.0.0.1` means port 53; the chokepoint must
/// listen there or the machine's own lookup path is pointed at a closed port (defect D-22). That is
/// why the control plane's unit grants its child relay `CAP_NET_BIND_SERVICE`. The redirect rules
/// use the same constant, so the firewall and the resolver cannot disagree.
pub const DEFAULT_CHOKEPOINT_PORT: u16 = 53;

/// The ports the policy redirects into.
///
/// Reported by the helper so that the control plane can configure the services it supervises with
/// the *same* numbers the firewall uses. Two sources for one port is how DNS silently stops working.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ports {
    /// Tor's transparent proxy port.
    pub trans: u16,
    /// The DNS chokepoint port.
    pub chokepoint: u16,
    /// Tor's SOCKS port.
    pub socks: u16,
}

impl Default for Ports {
    fn default() -> Self {
        Self {
            trans: 9040,
            chokepoint: DEFAULT_CHOKEPOINT_PORT,
            socks: 9050,
        }
    }
}

/// What the privileged helper currently has installed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    /// Whether Ghostnector's table exists in the kernel right now.
    pub applied: bool,
    /// The profile the helper last applied, if any.
    pub profile: Option<ProfileId>,
    /// The effective exemption list of that profile, for display (invariant I8).
    pub exemptions: Vec<crate::exemption::Exemption>,
    /// Identities the helper resolved, so the interface can show whose traffic is exempt.
    pub resolved: Vec<ResolvedIdentity>,
    /// The ports the policy redirects into, so services can be configured to match.
    pub ports: Ports,
    /// Operational notes that are not failures, for example a skipped conntrack flush.
    pub notes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_tags_are_a_closed_set() {
        let profile = Verb::ApplyProfile {
            profile: ProfileId::TorSystem,
            params: Params::default(),
        };
        let json = serde_json::to_string(&profile).unwrap();
        assert!(json.contains("\"verb\":\"apply_profile\""));
        assert!(json.contains("\"profile\":\"tor_system\""));

        assert_eq!(
            serde_json::to_string(&Verb::Revert).unwrap(),
            r#"{"verb":"revert"}"#
        );
        assert_eq!(
            serde_json::to_string(&Verb::FlushConntrack).unwrap(),
            r#"{"verb":"flush_conntrack"}"#
        );
        assert_eq!(
            serde_json::to_string(&Verb::Report).unwrap(),
            r#"{"verb":"report"}"#
        );
    }

    #[test]
    fn profile_ids_are_exhaustively_serialisable() {
        for (profile, tag) in [
            (ProfileId::FailClosed, "fail_closed"),
            (ProfileId::DnsLockdown, "dns_lockdown"),
            (ProfileId::TorSystem, "tor_system"),
            (ProfileId::TorUser, "tor_user"),
            (ProfileId::TorApp, "tor_app"),
            (ProfileId::I2pIsolated, "i2p_isolated"),
        ] {
            let json = serde_json::to_string(&profile).unwrap();
            assert_eq!(json, format!("\"{tag}\""));
        }
    }

    #[test]
    fn parameters_cannot_expand_the_interface() {
        // Every parameter is an integer, a boolean, or absent. A client cannot smuggle a rule, a
        // path, or a command through `Params`; the test documents that by asserting the exact
        // serialised shape.
        let params = Params {
            user_uid: Some(1000),
            netns_id: None,
            allow_lan: true,
        };
        assert_eq!(
            serde_json::to_string(&params).unwrap(),
            r#"{"user_uid":1000,"netns_id":null,"allow_lan":true}"#
        );
    }

    #[test]
    fn the_chokepoint_port_is_the_one_a_nameserver_line_implies() {
        // Regression for D-22: the resolver configuration cannot express a port, so the port the
        // relay listens on must be the port an address-only `nameserver` line means. Changing this
        // without changing how the resolver is pointed at the chokepoint breaks every lookup on a
        // default install while the policy keeps claiming to carry DNS.
        assert_eq!(DEFAULT_CHOKEPOINT_PORT, 53);
        assert_eq!(Ports::default().chokepoint, DEFAULT_CHOKEPOINT_PORT);
    }

    #[test]
    fn verbs_round_trip() {
        let verbs = [
            Verb::ApplyProfile {
                profile: ProfileId::DnsLockdown,
                params: Params::default(),
            },
            Verb::ApplyProfile {
                profile: ProfileId::TorApp,
                params: Params {
                    netns_id: Some(3),
                    ..Params::default()
                },
            },
            Verb::Revert,
            Verb::FlushConntrack,
            Verb::Report,
        ];
        for verb in verbs {
            let json = serde_json::to_string(&verb).unwrap();
            let decoded: Verb = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, verb);
        }
    }
}
