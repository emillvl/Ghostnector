//! Doubles for tests.

use std::sync::Mutex;

use ghostnector_spec::backend::{Ports, ProfileId, Report, Verb};
use ghostnector_spec::exemption::tor_baseline;
use ghostnector_spec::ipc::{ErrorCode, HelperResponse, PROTOCOL_VERSION};
use ghostnector_spec::ResolvedIdentity;

use crate::helper::{HelperError, HelperLink};
use crate::resolver::{CommandError, CommandRunner};
use crate::services::{ServiceError, Services};
use crate::verify::Outcome;

/// A helper that records what it was asked, and can be told to fail in specific ways.
#[derive(Debug, Default)]
pub struct MockHelper {
    verbs: Mutex<Vec<Verb>>,
    applied: Mutex<Option<ProfileId>>,
    fail_apply: Mutex<Option<String>>,
    fail_apply_of: Mutex<Option<ProfileId>>,
    fail_revert: Mutex<Option<String>>,
    policy_tampered: Mutex<bool>,
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

    /// Pretend something else changed the policy in the kernel.
    pub fn tamper_policy(&self) {
        *self.policy_tampered.lock().expect("mock lock") = true;
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
            ports: Ports::default(),
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
            Verb::Verify => {
                if *self.policy_tampered.lock().expect("mock lock") {
                    Ok(HelperResponse::Verified {
                        matches: false,
                        detail: "the kernel has lines that were not applied".to_string(),
                    })
                } else {
                    Ok(HelperResponse::Verified {
                        matches: true,
                        detail: "the kernel's policy is the one that was applied".to_string(),
                    })
                }
            }
            Verb::Report => Ok(HelperResponse::Report(self.report())),
        }
    }
}

/// Services that record what they were asked to do.
#[derive(Debug, Default)]
pub struct MockServices {
    brought_up: Mutex<Vec<ProfileId>>,
    stood_down: Mutex<Vec<ProfileId>>,
    fail_bring_up: Mutex<Option<String>>,
    notes: Mutex<Vec<String>>,
}

impl MockServices {
    /// Services that work.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every profile whose services were brought up, in order.
    pub fn brought_up(&self) -> Vec<ProfileId> {
        self.brought_up.lock().expect("mock lock").clone()
    }

    /// Every profile whose services were stood down, in order.
    pub fn stood_down(&self) -> Vec<ProfileId> {
        self.stood_down.lock().expect("mock lock").clone()
    }

    /// Fail the next bring-up with this message.
    pub fn fail_bring_up_with(&self, message: &str) {
        *self.fail_bring_up.lock().expect("mock lock") = Some(message.to_string());
    }

    /// Attach a note, as a real implementation does when something cannot be checked.
    pub fn add_note(&self, note: &str) {
        self.notes.lock().expect("mock lock").push(note.to_string());
    }
}

impl Services for MockServices {
    fn bring_up(&self, profile: ProfileId, _ports: Ports) -> Result<(), ServiceError> {
        if let Some(message) = self.fail_bring_up.lock().expect("mock lock").clone() {
            return Err(ServiceError::Config(message));
        }
        self.brought_up.lock().expect("mock lock").push(profile);
        Ok(())
    }

    fn stand_down(&self, profile: ProfileId) -> Result<(), ServiceError> {
        self.stood_down.lock().expect("mock lock").push(profile);
        Ok(())
    }

    fn notes(&self, _profile: ProfileId) -> Vec<String> {
        self.notes.lock().expect("mock lock").clone()
    }
}

/// A verifier whose answer the test chooses.
#[derive(Debug, Default)]
pub struct MockVerification {
    outcome: Mutex<Option<Outcome>>,
}

impl MockVerification {
    /// A verifier that cannot reach a conclusion, which is the honest default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Make every run pass.
    pub fn passing(&self) {
        *self.outcome.lock().expect("mock lock") = Some(Outcome::Passed);
    }

    /// Make every run report this failure.
    pub fn failing(&self, reason: &str) {
        *self.outcome.lock().expect("mock lock") = Some(Outcome::Failed {
            reason: reason.to_string(),
        });
    }

    /// Make every run unable to conclude anything.
    pub fn inconclusive(&self) {
        *self.outcome.lock().expect("mock lock") = None;
    }
}

impl crate::verify::Verification for MockVerification {
    fn run_once(&self) -> crate::verify::Report {
        let outcome =
            self.outcome
                .lock()
                .expect("mock lock")
                .clone()
                .unwrap_or(Outcome::Inconclusive {
                    reason: "no checks are configured".to_string(),
                });
        let details = vec![format!("mock: {outcome:?}")];
        crate::verify::Report { outcome, details }
    }
}

/// A DNS relay that records what it was asked to do.
#[derive(Debug, Default)]
pub struct MockRelay {
    started: Mutex<Vec<String>>,
    running: Mutex<bool>,
    fail_start: Mutex<Option<String>>,
    dies: Mutex<bool>,
}

impl MockRelay {
    /// A relay that starts and stops successfully.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every `start`, as `"listen -> upstream"`, in order.
    pub fn started(&self) -> Vec<String> {
        self.started.lock().expect("mock lock").clone()
    }

    /// Pretend the relay starts and immediately exits, as it does when its port is taken.
    pub fn die_on_start(&self) {
        *self.dies.lock().expect("mock lock") = true;
    }

    /// Fail the next start with this message.
    pub fn fail_start_with(&self, message: &str) {
        *self.fail_start.lock().expect("mock lock") = Some(message.to_string());
    }
}

impl crate::chokepoint::DnsRelay for MockRelay {
    fn start(
        &self,
        listen: std::net::SocketAddr,
        upstream: std::net::SocketAddr,
    ) -> Result<(), crate::chokepoint::ChokepointError> {
        if let Some(message) = self.fail_start.lock().expect("mock lock").clone() {
            return Err(crate::chokepoint::ChokepointError::Start(message));
        }
        self.started
            .lock()
            .expect("mock lock")
            .push(format!("{listen} -> {upstream}"));
        *self.running.lock().expect("mock lock") = !*self.dies.lock().expect("mock lock");
        Ok(())
    }

    fn stop(&self) -> Result<(), crate::chokepoint::ChokepointError> {
        *self.running.lock().expect("mock lock") = false;
        Ok(())
    }

    fn is_running(&self) -> bool {
        *self.running.lock().expect("mock lock")
    }
}

/// A command runner that records what it was asked to do.
#[derive(Debug, Default)]
pub struct MockRunner {
    calls: Mutex<Vec<String>>,
    fail: Mutex<Option<String>>,
}

impl MockRunner {
    /// A runner that succeeds and remembers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every call, as `"program argument argument"`, in order.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("mock lock").clone()
    }

    /// Fail every call with this message.
    pub fn fail_with(&self, message: &str) {
        *self.fail.lock().expect("mock lock") = Some(message.to_string());
    }
}

impl CommandRunner for MockRunner {
    fn run(&self, program: &std::path::Path, arguments: &[&str]) -> Result<String, CommandError> {
        let mut call = program.display().to_string();
        for argument in arguments {
            call.push(' ');
            call.push_str(argument);
        }
        self.calls.lock().expect("mock lock").push(call);

        match self.fail.lock().expect("mock lock").clone() {
            Some(message) => Err(CommandError::Refused {
                program: program.to_path_buf(),
                reason: message,
            }),
            None => Ok(String::new()),
        }
    }
}
