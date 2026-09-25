//! The complete, enumerable list of holes in the deny-by-default policy.
//!
//! Invariant I8 / DR-12: every exemption is enumerated in runtime state and visible in the
//! interface. This module is the catalogue of *permitted subjects*; the compiler cites them, and
//! the effective list carried in a [`crate::state::Snapshot`] is derived from the rules that
//! actually cite them — so the interface can never show a hole that does not exist, or hide one
//! that does.
//!
//! Two things that look like they need an exemption but do not:
//!
//! * **Authenticated DNS over Tor.** The resolver reaches Tor's SOCKS port on loopback, which the
//!   loopback rule already permits and which cannot reach the internet by itself. Adding an
//!   exemption here would widen the policy for no benefit; its absence is the security property.
//! * **The DNS chokepoint.** It forwards to a loopback listener, so it needs nothing either.

use serde::{Deserialize, Serialize};

/// What an exemption grants egress to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExemptionKind {
    /// A system user's sockets, matched on socket ownership rather than on an interface.
    Uid,
    /// A protocol/port pair with a fixed purpose.
    Protocol,
    /// An address range, such as the local network.
    AddressSet,
    /// A listener that protected scopes are allowed to reach.
    Service,
}

/// One hole in the deny-by-default policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exemption {
    /// What kind of subject this is.
    pub kind: ExemptionKind,
    /// Non-sensitive identifier, for example `system-user:tor` or `dhcp-client`.
    pub subject: String,
    /// Why the exemption exists. Shown verbatim in the interface.
    pub reason: String,
    /// True when it cannot be disabled without breaking the design.
    pub required: bool,
}

/// Subjects that must never appear in an exemption list.
///
/// DR-12: the interface, the core, the verifier, the updater, and general user identities are never
/// exempt from policy. The test below enforces this, so adding such an exemption fails the build
/// rather than shipping quietly.
pub const NEVER_EXEMPT_PREFIXES: [&str; 6] = [
    "system-user:ghostnector-core",
    "system-user:ghostnector-verify",
    "system-user:ghostnector-gui",
    "system-user:ghostnector-netd",
    "process:",
    "user:",
];

/// The subject used for Tor's own egress.
pub const SUBJECT_TOR: &str = "system-user:tor";

/// The subject used for the I2P router's own egress.
pub const SUBJECT_I2P: &str = "system-user:i2p";

/// The subject used for the resolver's egress in encrypted-DNS mode.
pub const SUBJECT_DNSCRYPT: &str = "system-user:dnscrypt-proxy";

/// The subject used for the DHCP client.
pub const SUBJECT_DHCP: &str = "dhcp-client";

/// The subject used for the opt-in local-network exception.
pub const SUBJECT_LAN: &str = "lan";

/// The exemptions that exist whenever Tor is enabled.
///
/// Tor's own egress must be direct or the design is circular; DHCP must survive or the link dies.
/// Nothing else belongs here.
pub fn tor_baseline() -> Vec<Exemption> {
    vec![
        Exemption {
            kind: ExemptionKind::Uid,
            subject: SUBJECT_TOR.to_string(),
            reason: "Tor must reach relays, bridges, and directory authorities without going \
                     through itself"
                .to_string(),
            required: true,
        },
        Exemption {
            kind: ExemptionKind::Protocol,
            subject: SUBJECT_DHCP.to_string(),
            reason: "The link must survive; DHCP reveals nothing the local network does not \
                     already know"
                .to_string(),
            required: true,
        },
    ]
}

/// The exemptions that exist whenever I2P is enabled.
///
/// The router's own egress must be direct: it speaks to I2P peers on arbitrary ports and to
/// reseed servers over clearnet, and routing that through anything else would be circular. Nothing
/// else belongs here — in particular, no application uid: applications reach I2P only through the
/// router's local proxies, which the loopback rule already permits.
pub fn i2p_baseline() -> Vec<Exemption> {
    vec![
        Exemption {
            kind: ExemptionKind::Uid,
            subject: SUBJECT_I2P.to_string(),
            reason: "The I2P router must reach peers and reseed servers without going through \
                     itself"
                .to_string(),
            required: true,
        },
        Exemption {
            kind: ExemptionKind::Protocol,
            subject: SUBJECT_DHCP.to_string(),
            reason: "The link must survive; DHCP reveals nothing the local network does not \
                     already know"
                .to_string(),
            required: true,
        },
    ]
}

/// The exemptions that exist in encrypted-DNS-only scope.
///
/// The resolver is the only identity permitted to speak to the outside world, and only because it
/// is the component whose whole purpose is to talk to resolvers. Every other uid is locked out of
/// DNS entirely.
pub fn dns_lockdown_baseline() -> Vec<Exemption> {
    vec![
        Exemption {
            kind: ExemptionKind::Uid,
            subject: SUBJECT_DNSCRYPT.to_string(),
            reason: "The resolver must reach its own resolvers; no other identity may speak DNS"
                .to_string(),
            required: true,
        },
        Exemption {
            kind: ExemptionKind::Protocol,
            subject: SUBJECT_DHCP.to_string(),
            reason: "The link must survive; DHCP reveals nothing the local network does not \
                     already know"
                .to_string(),
            required: true,
        },
    ]
}

/// Optional: reach the local network from the protected scope.
pub fn lan_exemption() -> Exemption {
    Exemption {
        kind: ExemptionKind::AddressSet,
        subject: SUBJECT_LAN.to_string(),
        reason:
            "Opt-in: protected applications may reach the local network, which identifies this \
                 machine to local devices"
                .to_string(),
        required: false,
    }
}

/// Every subject the compiler is allowed to cite.
///
/// Order is first-appearance, and duplicates are removed by subject: `dhcp-client` legitimately
/// appears in more than one baseline, but the catalogue must present it once.
pub fn catalogue() -> Vec<Exemption> {
    let mut all: Vec<Exemption> = Vec::new();
    let candidates = tor_baseline()
        .into_iter()
        .chain(i2p_baseline())
        .chain(dns_lockdown_baseline())
        .chain(std::iter::once(lan_exemption()));
    for exemption in candidates {
        if !all
            .iter()
            .any(|existing| existing.subject == exemption.subject)
        {
            all.push(exemption);
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_interface_and_daemons_are_never_exempt() {
        for exemption in catalogue() {
            for prefix in NEVER_EXEMPT_PREFIXES {
                assert!(
                    !exemption.subject.starts_with(prefix),
                    "{} must never be exempt from policy",
                    exemption.subject
                );
            }
        }
    }

    #[test]
    fn required_exemptions_are_the_minimum_set() {
        let tor_required: Vec<_> = tor_baseline()
            .into_iter()
            .filter(|e| e.required)
            .map(|e| e.subject)
            .collect();
        assert_eq!(
            tor_required,
            vec![SUBJECT_TOR.to_string(), SUBJECT_DHCP.to_string()]
        );

        // I2P's list is the router's own uid and DHCP, and nothing else: applications reach I2P
        // only through the router's proxies, which loopback already carries.
        let i2p_required: Vec<_> = i2p_baseline()
            .into_iter()
            .filter(|e| e.required)
            .map(|e| e.subject)
            .collect();
        assert_eq!(
            i2p_required,
            vec![SUBJECT_I2P.to_string(), SUBJECT_DHCP.to_string()]
        );
    }

    #[test]
    fn the_catalogue_has_no_duplicate_subjects() {
        let all = catalogue();
        let mut subjects: Vec<&str> = all.iter().map(|e| e.subject.as_str()).collect();
        let total = subjects.len();
        subjects.sort_unstable();
        subjects.dedup();
        assert_eq!(subjects.len(), total, "catalogue repeats a subject");
    }

    #[test]
    fn optional_exemptions_are_marked_optional() {
        assert!(!lan_exemption().required);
    }

    #[test]
    fn every_exemption_explains_itself() {
        for exemption in catalogue() {
            assert!(
                !exemption.reason.trim().is_empty(),
                "{} has no stated reason, which the interface requires",
                exemption.subject
            );
        }
    }

    #[test]
    fn exemptions_round_trip() {
        let list = tor_baseline();
        let json = serde_json::to_string(&list).unwrap();
        let decoded: Vec<Exemption> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, list);
    }
}
