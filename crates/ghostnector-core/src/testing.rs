//! Doubles for tests.

use std::sync::Mutex;

use ghostnector_spec::backend::{ProfileId, Report, Verb};
use ghostnector_spec::exemption::tor_baseline;
use ghostnector_spec::ipc::{ErrorCode, HelperResponse, PROTOCOL_VERSION};
use ghostnector_spec::ResolvedIdentity;

use crate::helper::{HelperError, HelperLink};

/// A helper that records what it was asked, and can be told to fail in specific ways.
#[derive(Debug, Default)]
pub struct MockHelper {
    verbs: Mutex<Vec<Verb>>,
    applied: Mutex<Option<ProfileId>>,
    fail_apply: Mutex<Option<String>>,
    fail_apply_of: Mutex<Option<ProfileId>>,
    fail_revert: Mutex<Option<String>>,
    reachable: bool,
}

impl MockHelper {
    /// A helper that is present and willing.
    pub fn new() -> Self {
        Self {
            reachable: true,
            ..Self::default()
        }
    }

    /// A helper whose socket is gone.
    pub fn unreachable() -> Self {
        Self::default()
    }

    /// Every verb that reached the helper, in order.
    pub fn verbs(&self) -> Vec<Verb> {
        self.verbs.lock().expect("mock lock").clone()
    }

    /// Fail every apply with this message.
    pub fn fail_apply_with(&self, message: &str) {
        *self.fail_apply.lock().expect("mock lock") = Some(message.to_string());
    }

    /// Fail only this profile's apply, so a sequence can fail halfway through.
    pub fn fail_apply_of(&self, profile: ProfileId) {
        *self.fail_apply_of.lock().expect("mock lock") = Some(profile);
    }

    /// Fail attempts to withdraw the policy.
    pub fn fail_revert_with(&self, message: &str) {
        *self.fail_revert.lock().expect("mock lock") = Some(message.to_string());
    }

    /// Pretend the kernel already has this applied, as after a restart.
    pub fn force_applied(&self, profile: Option<ProfileId>) {
        *self.applied.lock().expect("mock lock") = profile;
    }

    /// The profiles that were applied, in order.
    pub fn applied_sequence(&self) -> Vec<ProfileId> {
        self.verbs()
            .into_iter()
            .filter_map(|verb| match verb {
                Verb::ApplyProfile { profile, .. } => Some(profile),
                _ => None,
            })
            .collect()
    }

    fn current(&self) -> Option<ProfileId> {
        *self.applied.lock().expect("mock lock")
    }

    fn report(&self) -> Report {
        let applied = self.current();
        Report {
            applied: applied.is_some(),
            profile: applied,
            exemptions: if applied.is_some() {
                tor_baseline()
            } else {
                Vec::new()
            },
            resolved: vec![ResolvedIdentity {
                name: "debian-tor".to_string(),
                uid: Some(987),
            }],
            notes: Vec::new(),
        }
    }
}

impl HelperLink for MockHelper {
    fn invoke(&self, verb: Verb) -> Result<HelperResponse, HelperError> {
        if !self.reachable {
            return Err(HelperError::Connect {
                path: "/run/ghostnector/netd.sock".into(),
                reason: "no such file or directory".to_string(),
            });
        }
        self.verbs.lock().expect("mock lock").push(verb.clone());

        match verb {
            Verb::Hello { .. } => Ok(HelperResponse::Hello {
                protocol: PROTOCOL_VERSION,
                version: "test".to_string(),
            }),
            Verb::ApplyProfile { profile, .. } => {
                if let Some(message) = self.fail_apply.lock().expect("mock lock").clone() {
                    return Err(HelperError::Refused {
                        code: ErrorCode::BackendFailure,
                        message,
                        sensitive: false,
                    });
                }
                if *self.fail_apply_of.lock().expect("mock lock") == Some(profile) {
                    return Err(HelperError::Refused {
                        code: ErrorCode::BackendFailure,
                        message: format!("{profile:?} was refused by the kernel"),
                        sensitive: false,
                    });
                }
                *self.applied.lock().expect("mock lock") = Some(profile);
                Ok(HelperResponse::Applied {
                    report: self.report(),
                })
            }
            Verb::Revert => {
                if let Some(message) = self.fail_revert.lock().expect("mock lock").clone() {
                    return Err(HelperError::Refused {
                        code: ErrorCode::BackendFailure,
                        message,
                        sensitive: false,
                    });
                }
                *self.applied.lock().expect("mock lock") = None;
                Ok(HelperResponse::Applied {
                    report: self.report(),
                })
            }
            Verb::FlushConntrack => Ok(HelperResponse::Applied {
                report: self.report(),
            }),
            Verb::Report => Ok(HelperResponse::Report(self.report())),
        }
    }
}
