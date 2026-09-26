//! The user-facing words for a snapshot.
//!
//! These strings are the interface contract: the CLI prints them, the GUI renders them, and the
//! qualification runs assert on them. They live here, next to the state vocabulary, so the two
//! interfaces cannot drift apart and no interface can invent a rosier wording than another.
//!
//! They are pure functions of the snapshot. Nothing here decides anything: `Protected` still means
//! only what [`crate::state::ProtectionState`] means, and a caller that renders "protected" for a
//! different state would fail the tests below rather than a user.

use crate::profile::{Profile, Scope};
use crate::state::{ProtectionState, Snapshot, Verification};

/// The one-line state description, exactly as the CLI has always worded it.
pub fn state_line(snapshot: &Snapshot) -> String {
    let scope = snapshot.profile.as_ref().map(|profile| profile.scope);
    match snapshot.state {
        ProtectionState::Off => "off — traffic is not protected".to_string(),
        ProtectionState::Applying => "applying — a transition is in progress".to_string(),
        ProtectionState::Protected => "protected — and verified".to_string(),
        ProtectionState::Degraded => "protected, but unverified".to_string(),
        ProtectionState::Blocked if scope == Some(Scope::App) => {
            "blocked — no protected application can reach the network".to_string()
        }
        ProtectionState::Blocked => "blocked — no traffic can leave".to_string(),
        ProtectionState::Portal => "captive portal — protection is relaxed".to_string(),
    }
}

/// How much of the machine a scope covers, in the words the interface uses.
pub fn scope_line(scope: Scope) -> &'static str {
    match scope {
        Scope::Off => "off",
        Scope::Dns => "encrypted DNS",
        Scope::App => "chosen applications",
        Scope::User => "your processes",
        Scope::System => "the whole system",
    }
}

/// How fresh the independent verification is, in the words the interface uses.
pub fn verification_line(verification: Verification) -> &'static str {
    match verification {
        Verification::Unknown => "not checked yet",
        Verification::Fresh => "checked recently",
        Verification::Stale => "not checked recently",
        Verification::Unavailable => "nothing can verify it yet",
        Verification::Failed => "CHECKED AND FAILED",
    }
}

/// Which network a profile carries traffic through, in the words the interface uses.
pub fn network_line(profile: &Profile) -> &'static str {
    if profile.networks.tor {
        "through Tor"
    } else if profile.networks.i2p {
        "through I2P"
    } else {
        "encrypted DNS only"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Networks;

    fn snapshot(state: ProtectionState, scope: Option<Scope>) -> Snapshot {
        Snapshot {
            state,
            profile: scope.map(|scope| Profile {
                scope,
                networks: Networks::tor(),
                ..Profile::default()
            }),
            ..Snapshot::default()
        }
    }

    #[test]
    fn every_state_has_exactly_one_line() {
        for (state, scope, expected) in [
            (ProtectionState::Off, None, "off — traffic is not protected"),
            (
                ProtectionState::Applying,
                None,
                "applying — a transition is in progress",
            ),
            (
                ProtectionState::Protected,
                Some(Scope::System),
                "protected — and verified",
            ),
            (
                ProtectionState::Degraded,
                Some(Scope::System),
                "protected, but unverified",
            ),
            (
                ProtectionState::Blocked,
                Some(Scope::System),
                "blocked — no traffic can leave",
            ),
            (
                ProtectionState::Blocked,
                Some(Scope::App),
                "blocked — no protected application can reach the network",
            ),
            (
                ProtectionState::Portal,
                None,
                "captive portal — protection is relaxed",
            ),
        ] {
            assert_eq!(state_line(&snapshot(state, scope)), expected);
        }
    }

    #[test]
    fn a_blocked_app_machine_says_so_in_app_words() {
        assert!(
            state_line(&snapshot(ProtectionState::Blocked, Some(Scope::App)))
                .contains("application")
        );
        assert!(!state_line(&snapshot(ProtectionState::Blocked, None)).contains("application"));
    }

    #[test]
    fn the_scope_and_network_words_are_stable() {
        assert_eq!(scope_line(Scope::System), "the whole system");
        assert_eq!(scope_line(Scope::App), "chosen applications");
        let tor = Profile {
            networks: Networks::tor(),
            ..Profile::default()
        };
        let i2p = Profile {
            networks: Networks::i2p(),
            ..Profile::default()
        };
        assert_eq!(network_line(&tor), "through Tor");
        assert_eq!(network_line(&i2p), "through I2P");
    }

    #[test]
    fn an_unverified_state_never_reads_as_verified() {
        assert_eq!(verification_line(Verification::Unknown), "not checked yet");
        assert_eq!(
            verification_line(Verification::Stale),
            "not checked recently"
        );
        assert_eq!(
            verification_line(Verification::Unavailable),
            "nothing can verify it yet"
        );
        assert_eq!(
            verification_line(Verification::Failed),
            "CHECKED AND FAILED"
        );
        for state in [ProtectionState::Degraded, ProtectionState::Applying] {
            let line = state_line(&snapshot(state, Some(Scope::System)));
            assert!(
                !line.contains("and verified"),
                "{state:?} must not read as verified: {line}"
            );
        }
    }
}
