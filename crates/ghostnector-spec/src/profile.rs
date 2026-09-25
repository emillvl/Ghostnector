//! Mode/scope vocabulary and the validity matrix.
//!
//! The review ([§2.1](../ARCHITECTURE-REVIEW.md)) identifies independently toggleable components as
//! the flaw that lets a user select an incoherent, dangerous combination. The structural fix is
//! that only validated combinations exist: callers build a raw [`Profile`], and every downstream
//! component accepts only a [`ValidProfile`], which cannot be constructed except through
//! [`Profile::validate`]. `ValidProfile` intentionally does **not** implement `Deserialize`, so no
//! wire input can bypass validation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// How much of the machine a policy covers.
///
/// Ordered from least to most coverage. `System` covers a superset of `User`, which covers a
/// superset of `App` — but note that *coverage* and *structural strength* trade off in the other
/// direction (see the review, §3.4).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// No policy is applied.
    #[default]
    Off,
    /// Encrypted DNS plus port-53 lockdown. No overlay network.
    Dns,
    /// Only applications explicitly launched into Ghostnector.
    App,
    /// Every process of the requesting user.
    User,
    /// Every local process on the machine.
    System,
}

impl Scope {
    /// Human-readable label for the interface.
    pub const fn label(self) -> &'static str {
        match self {
            Scope::Off => "off",
            Scope::Dns => "encrypted DNS only",
            Scope::App => "protected applications",
            Scope::User => "current user",
            Scope::System => "whole system",
        }
    }

    /// True when the scope is expected to cover processes Ghostnector did not launch itself.
    pub const fn is_machine_wide(self) -> bool {
        matches!(self, Scope::System)
    }

    /// True when the scope can carry overlay-network traffic.
    pub const fn can_carry_overlay(self) -> bool {
        matches!(self, Scope::App | Scope::User | Scope::System)
    }
}

/// Destination planes a caller may request.
///
/// They are **alternatives, never layers**: validation refuses a request that enables both at once.
/// The raw shape keeps both flags so the refusal is a decision the validator makes, not a value a
/// malformed message can smuggle past it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Networks {
    /// Route supported traffic through Tor.
    pub tor: bool,
    /// Run the I2P router as the machine's only overlay.
    pub i2p: bool,
}

impl Networks {
    /// No overlay networks.
    pub const fn none() -> Self {
        Self {
            tor: false,
            i2p: false,
        }
    }

    /// Tor only.
    pub const fn tor() -> Self {
        Self {
            tor: true,
            i2p: false,
        }
    }

    /// I2P only.
    pub const fn i2p() -> Self {
        Self {
            tor: false,
            i2p: true,
        }
    }

    /// Tor and I2P requested together. Kept as a constructor so tests can prove the refusal, but
    /// validation never accepts it: the two networks are independent and are never enabled together.
    pub const fn both() -> Self {
        Self {
            tor: true,
            i2p: true,
        }
    }

    /// True when neither overlay is requested.
    pub const fn is_empty(self) -> bool {
        !self.tor && !self.i2p
    }
}

/// A user's requested configuration, before validation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    /// How much of the machine to cover.
    pub scope: Scope,
    /// Which overlay networks to enable.
    pub networks: Networks,
    /// Permit egress to the local network (RFC1918, link-local, multicast).
    pub allow_lan: bool,
    /// Reach Tor through bridges / pluggable transports.
    pub use_bridges: bool,
    /// Resolve through an authenticated resolver carried over Tor instead of Tor's `DNSPort`.
    ///
    /// Slower, and it must be firewalled to the Tor SOCKS port so a broken tunnel cannot leak
    /// (review §8.1, DR-10).
    pub authenticated_dns_over_tor: bool,
}

/// Non-fatal consequences of a valid profile that the interface must disclose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Warning {
    /// I2P participants see this machine's IP address; this is inherent to I2P.
    I2pExposesHostIp,
    /// System scope also covers other logged-in users and system services.
    SystemScopeCoversAllUsers,
    /// Allowing LAN egress widens what protected applications can reach.
    LanExceptionWidensExposure,
    /// Authenticated DNS over Tor adds latency to every uncached lookup.
    AuthenticatedDnsOverTorIsSlower,
    /// Bridges cost latency and are only worth it where Tor is blocked.
    BridgesCostLatency,
}

/// Reasons a raw [`Profile`] cannot be applied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// `Scope::Off` means "no policy", so no overlay may be requested.
    #[error("scope off cannot enable tor or i2p")]
    OverlayWithScopeOff,
    /// The DNS-only scope cannot carry overlay traffic.
    #[error(
        "the encrypted-DNS scope cannot carry tor or i2p traffic; choose app, user, or system"
    )]
    DnsScopeWithOverlay,
    /// Authenticated DNS over Tor is meaningless without Tor.
    #[error("authenticated DNS over Tor requires tor")]
    AuthenticatedDnsWithoutTor,
    /// Bridges are a Tor mechanism.
    #[error("bridges require tor")]
    BridgesWithoutTor,
    /// Tor and I2P are independent networks and are never enabled together.
    #[error("tor and i2p are independent networks and are never enabled together; choose one")]
    MixedNetworks,
    /// I2P is machine-wide in this version.
    #[error(
        "i2p is available as a whole-system network only; per-application and per-user i2p are not \
         supported"
    )]
    I2pNeedsSystemScope,
    /// I2P has no local-network exception.
    #[error(
        "i2p has no local-network exception: every flow that is not the router's own is denied"
    )]
    I2pWithLan,
}

/// A profile that has passed [`Profile::validate`].
///
/// The inner field is private on purpose: the only way to obtain one is validation, so downstream
/// code may rely on these invariants:
///
/// * any enabled overlay has a scope that can carry traffic;
/// * Tor is never enabled together with the DNS-only scope (review §2.1);
/// * the bridge and authenticated-DNS options imply Tor;
/// * the warning set is complete for the profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidProfile {
    profile: Profile,
    warnings: BTreeSet<Warning>,
}

impl ValidProfile {
    /// The validated profile.
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Warnings the interface must disclose, in stable order.
    pub fn warnings(&self) -> impl Iterator<Item = Warning> + '_ {
        self.warnings.iter().copied()
    }

    /// The covered scope.
    pub fn scope(&self) -> Scope {
        self.profile.scope
    }

    /// Whether Tor is enabled.
    pub fn tor(&self) -> bool {
        self.profile.networks.tor
    }

    /// Whether I2P is enabled.
    pub fn i2p(&self) -> bool {
        self.profile.networks.i2p
    }

    /// True when no policy would be applied at all.
    pub fn is_off(&self) -> bool {
        self.profile.scope == Scope::Off
    }
}

impl TryFrom<Profile> for ValidProfile {
    type Error = ProfileError;

    fn try_from(profile: Profile) -> Result<Self, Self::Error> {
        profile.validate()
    }
}

impl Profile {
    /// Validate the profile, producing the only type the rest of Ghostnector accepts.
    pub fn validate(self) -> Result<ValidProfile, ProfileError> {
        let scope = self.scope;
        let nets = self.networks;

        if scope == Scope::Off {
            if !nets.is_empty() {
                return Err(ProfileError::OverlayWithScopeOff);
            }
            if self.authenticated_dns_over_tor {
                return Err(ProfileError::AuthenticatedDnsWithoutTor);
            }
            if self.use_bridges {
                return Err(ProfileError::BridgesWithoutTor);
            }
            return Ok(ValidProfile {
                profile: self,
                warnings: BTreeSet::new(),
            });
        }

        if scope == Scope::Dns && !nets.is_empty() {
            return Err(ProfileError::DnsScopeWithOverlay);
        }
        if self.authenticated_dns_over_tor && !nets.tor {
            return Err(ProfileError::AuthenticatedDnsWithoutTor);
        }
        if self.use_bridges && !nets.tor {
            return Err(ProfileError::BridgesWithoutTor);
        }

        // The two overlay networks are independent: they are alternatives, never layers, and are
        // never enabled together (M9 decision 5).
        if nets.tor && nets.i2p {
            return Err(ProfileError::MixedNetworks);
        }
        // I2P is machine-wide in this version: the APP conduit carries Tor, and per-user I2P needs a
        // different exemption model than the one this version proves (M9 decision 5).
        if nets.i2p && scope != Scope::System {
            return Err(ProfileError::I2pNeedsSystemScope);
        }
        // The whole point of I2P scope is that the router's own egress is the only one; a LAN
        // exception would open a second path for every other process.
        if nets.i2p && self.allow_lan {
            return Err(ProfileError::I2pWithLan);
        }

        let mut warnings = BTreeSet::new();
        if nets.i2p {
            warnings.insert(Warning::I2pExposesHostIp);
        }
        if scope.is_machine_wide() {
            warnings.insert(Warning::SystemScopeCoversAllUsers);
        }
        if self.allow_lan {
            warnings.insert(Warning::LanExceptionWidensExposure);
        }
        if self.authenticated_dns_over_tor {
            warnings.insert(Warning::AuthenticatedDnsOverTorIsSlower);
        }
        if self.use_bridges {
            warnings.insert(Warning::BridgesCostLatency);
        }

        Ok(ValidProfile {
            profile: self,
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(scope: Scope, networks: Networks) -> Profile {
        Profile {
            scope,
            networks,
            ..Profile::default()
        }
    }

    #[test]
    fn off_scope_accepts_no_overlay() {
        for networks in [Networks::tor(), Networks::i2p(), Networks::both()] {
            assert_eq!(
                profile(Scope::Off, networks).validate(),
                Err(ProfileError::OverlayWithScopeOff)
            );
        }
        assert!(profile(Scope::Off, Networks::none()).validate().is_ok());
    }

    #[test]
    fn dns_scope_rejects_overlays() {
        for networks in [Networks::tor(), Networks::i2p(), Networks::both()] {
            assert_eq!(
                profile(Scope::Dns, networks).validate(),
                Err(ProfileError::DnsScopeWithOverlay)
            );
        }
        assert!(profile(Scope::Dns, Networks::none()).validate().is_ok());
    }

    /// The full validity matrix from the review (Appendix B), as amended by M9: the networks are
    /// alternatives, and I2P is machine-wide only.
    #[test]
    fn validity_matrix_is_exhaustive() {
        let expected_valid = |scope: Scope, nets: Networks| -> bool {
            if nets.tor && nets.i2p {
                return false;
            }
            if nets.is_empty() {
                return true;
            }
            if nets.i2p {
                return scope == Scope::System;
            }
            matches!(scope, Scope::App | Scope::User | Scope::System)
        };

        for scope in [
            Scope::Off,
            Scope::Dns,
            Scope::App,
            Scope::User,
            Scope::System,
        ] {
            for nets in [
                Networks::none(),
                Networks::tor(),
                Networks::i2p(),
                Networks::both(),
            ] {
                let is_valid = profile(scope, nets).validate().is_ok();
                assert_eq!(
                    is_valid,
                    expected_valid(scope, nets),
                    "{scope:?} + {nets:?} produced the wrong verdict"
                );
            }
        }
    }

    #[test]
    fn tor_is_available_in_every_carrying_scope() {
        for scope in [Scope::App, Scope::User, Scope::System] {
            let valid = profile(scope, Networks::tor()).validate().unwrap();
            assert!(valid.tor());
            assert!(!valid.i2p());
            assert!(valid.scope().can_carry_overlay());
        }
    }

    #[test]
    fn options_imply_tor() {
        let mut with_bridges = profile(Scope::System, Networks::i2p());
        with_bridges.use_bridges = true;
        assert_eq!(
            with_bridges.validate(),
            Err(ProfileError::BridgesWithoutTor)
        );

        let mut auth_dns = profile(Scope::System, Networks::none());
        auth_dns.authenticated_dns_over_tor = true;
        assert_eq!(
            auth_dns.validate(),
            Err(ProfileError::AuthenticatedDnsWithoutTor)
        );
    }

    #[test]
    fn warnings_are_disclosed_not_hidden() {
        let valid = profile(Scope::System, Networks::i2p()).validate().unwrap();
        let warnings: Vec<_> = valid.warnings().collect();
        assert!(warnings.contains(&Warning::I2pExposesHostIp));
        assert!(warnings.contains(&Warning::SystemScopeCoversAllUsers));
        assert!(!warnings.contains(&Warning::LanExceptionWidensExposure));
        assert!(!warnings.contains(&Warning::BridgesCostLatency));
    }

    #[test]
    fn independent_networks_are_never_combined() {
        // A raw request may still carry both flags; validation is what refuses it.
        for scope in [Scope::App, Scope::User, Scope::System] {
            assert_eq!(
                profile(scope, Networks::both()).validate(),
                Err(ProfileError::MixedNetworks),
                "{scope:?}"
            );
        }
    }

    #[test]
    fn i2p_is_machine_wide_only() {
        for scope in [Scope::App, Scope::User, Scope::Dns] {
            let error = profile(scope, Networks::i2p()).validate().unwrap_err();
            assert!(
                matches!(
                    error,
                    ProfileError::I2pNeedsSystemScope | ProfileError::DnsScopeWithOverlay
                ),
                "{scope:?}: {error}"
            );
        }
        let valid = profile(Scope::System, Networks::i2p()).validate().unwrap();
        assert!(valid.i2p());
        assert!(!valid.tor());
    }

    #[test]
    fn i2p_has_no_lan_exception() {
        let mut with_lan = profile(Scope::System, Networks::i2p());
        with_lan.allow_lan = true;
        assert_eq!(with_lan.validate(), Err(ProfileError::I2pWithLan));
    }

    #[test]
    fn raw_profile_round_trips_over_the_wire_but_valid_profile_does_not() {
        // The raw profile is what travels over IPC; core validates it on receipt.
        let raw = profile(Scope::System, Networks::tor());
        let json = serde_json::to_string(&raw).unwrap();
        let decoded: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, raw);

        // `ValidProfile` is serialize-only by construction; the following line
        // would not compile, which is the point:
        //     let _: ValidProfile = serde_json::from_str(&json).unwrap();
        let valid = raw.validate().unwrap();
        let encoded = serde_json::to_string(&valid).unwrap();
        assert!(encoded.contains("\"tor\":true"));
    }

    #[test]
    fn try_from_delegates_to_validate() {
        let raw = profile(Scope::User, Networks::tor());
        assert_eq!(ValidProfile::try_from(raw.clone()), raw.clone().validate());
    }

    #[test]
    fn scope_labels_are_stable() {
        // The interface and documentation quote these; changing them is a user-visible change.
        assert_eq!(Scope::Off.label(), "off");
        assert_eq!(Scope::System.label(), "whole system");
    }

    #[test]
    fn default_profile_is_inert() {
        // `Profile::default()` must mean "no policy", never a partially-enabled one. This matters
        // because deserialisation is `#[serde(default)]`: a truncated or malformed message must
        // never be interpreted as an enabled overlay.
        let default = Profile::default();
        assert_eq!(default.scope, Scope::Off);
        assert!(default.networks.is_empty());
        assert!(!default.allow_lan);
        assert!(!default.use_bridges);
        assert!(!default.authenticated_dns_over_tor);
        assert!(default.validate().unwrap().is_off());
    }
}
