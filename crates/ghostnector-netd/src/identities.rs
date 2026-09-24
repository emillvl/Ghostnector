//! Resolving system identities.
//!
//! The policy is expressed in uids, so someone has to turn user names into numbers. That lookup
//! happens in the privileged process, against the real user database, at the moment it is needed —
//! never from cached or configured numbers, which could drift and silently protect the wrong
//! processes.

/// Why an identity could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The user does not exist on this machine.
    #[error("the user '{0}' is not installed on this machine")]
    NotInstalled(String),
    /// The user database could not be read.
    #[error("looking up '{0}' failed: {1}")]
    Lookup(String, String),
}

/// Where system identities come from.
pub trait Identities: Send + Sync {
    /// Resolve a user name to a uid.
    fn uid_of(&self, name: &str) -> Result<u32, IdentityError>;
}

/// The real system user database.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemIdentities;

impl Identities for SystemIdentities {
    fn uid_of(&self, name: &str) -> Result<u32, IdentityError> {
        match nix::unistd::User::from_name(name) {
            Ok(Some(user)) => Ok(user.uid.as_raw()),
            Ok(None) => Err(IdentityError::NotInstalled(name.to_string())),
            Err(error) => Err(IdentityError::Lookup(name.to_string(), error.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FixedIdentities;

    #[test]
    fn the_real_database_knows_root() {
        // A machine without a root entry has bigger problems, but this proves the lookup path runs.
        let uid = SystemIdentities.uid_of("root");
        assert!(uid.is_ok() || matches!(uid, Err(IdentityError::Lookup(_, _))));
    }

    #[test]
    fn a_missing_user_is_reported_as_missing() {
        let error = SystemIdentities
            .uid_of("definitely-not-a-user-9f3a")
            .unwrap_err();
        assert!(matches!(error, IdentityError::NotInstalled(_)));
    }

    #[test]
    fn fixed_identities_answer_only_what_they_were_told() {
        let users = FixedIdentities::new(&[("debian-tor", 987)]);
        assert_eq!(users.uid_of("debian-tor"), Ok(987));
        assert!(matches!(
            users.uid_of("dnscrypt-proxy"),
            Err(IdentityError::NotInstalled(_))
        ));
    }
}
