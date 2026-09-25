//! Deployment constants for `APP` scope, shared by everything that touches it.
//!
//! These values are the vocabulary's single source of truth for the APP topology. The privileged
//! helper that renders the host-side ruleset and the helper that builds namespaces must agree on
//! them exactly, for the same reason the ports must agree: two sources for one identifier is how a
//! working design silently becomes a broken one (defect D-22 in `docs/ADVERSARIAL-TEST-PLAN.md`).
//!
//! Nothing here is accepted from a client. A helper may override a default from its own
//! command-line configuration (systemd owns that), but the value is validated against these rules
//! before use — never taken from `Params`, a peer, or the environment.

use std::net::Ipv4Addr;

/// The most APP isolation groups one machine may have. Bounded so the registry, the namespace
/// count, and the identifier space cannot grow without limit (M8 decision 10).
pub const MAX_APP_GROUPS: usize = 32;

/// The bridge that carries all app links on the host side. It has no uplink port: the only
/// addresses on it are the core address and the app addresses.
pub const DEFAULT_APP_BRIDGE: &str = "ghbr0";

/// The host-local address an app namespace's DNAT targets, and the address the app-facing Tor and
/// chokepoint listeners bind. It never leaves the host.
pub const DEFAULT_APP_CORE_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

/// Prefix length of the APP address space. App addresses are taken from this block, one per group.
pub const DEFAULT_APP_PREFIX: u8 = 24;

/// The dead-end device every app namespace's default route points at. It has no peer, so a packet
/// that is not rewritten by the namespace's DNAT dies here (see the M8.0 topology test).
pub const DEFAULT_APP_DEAD_DEVICE: &str = "ghdead";

/// The interface-name prefix the namespace helper generates for app links, for example `ghav7`.
pub const APP_LINK_PREFIX: &str = "ghav";

/// The namespace-name prefix the helper generates, for example `ghapp7`.
pub const APP_NETNS_PREFIX: &str = "ghapp";

/// Validate an interface name that will be handed to the kernel.
///
/// Linux interface names are at most 15 bytes (`IFNAMSIZ` minus the terminator), cannot be empty,
/// cannot start with `-`, and cannot contain `/` (which would make `ip`-style tools interpret it as
/// a path or a netns separator). This is deliberately stricter than the kernel: it accepts only
/// names that are safe to use in a generated command line, because a value that reaches a
/// privileged argv must not need quoting.
pub fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// The host-local core address as a set element: a single host prefix.
///
/// It is a `/32`, not the APP address space's prefix: the only address an APP packet may reach is
/// the core itself, and a match on the whole block would admit every app's address.
pub fn app_core_element(core: Ipv4Addr) -> String {
    format!("{core}/32")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shared_constants_are_the_documented_ones() {
        assert_eq!(MAX_APP_GROUPS, 32);
        assert_eq!(DEFAULT_APP_BRIDGE, "ghbr0");
        assert_eq!(DEFAULT_APP_CORE_ADDRESS, Ipv4Addr::new(10, 200, 0, 1));
        assert_eq!(DEFAULT_APP_PREFIX, 24);
        assert_eq!(DEFAULT_APP_DEAD_DEVICE, "ghdead");
    }

    #[test]
    fn interface_names_are_restrained() {
        for good in ["ghbr0", "ghav1", "ghav-32", "a", "gh_top.0"] {
            assert!(valid_interface_name(good), "{good}");
        }
        for bad in [
            "",
            "-leading",
            "with slash",
            "with/slash",
            "with space",
            "0123456789abcdef",
        ] {
            assert!(!valid_interface_name(bad), "{bad}");
        }
    }

    #[test]
    fn the_core_element_is_a_host_prefix() {
        assert_eq!(app_core_element(DEFAULT_APP_CORE_ADDRESS), "10.200.0.1/32");
    }
}
