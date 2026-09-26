//! Doubles for tests.

use std::sync::Mutex;

use ghostnector_spec::appd::{AppEntry, AppReport, AppResponse, AppVerb, APP_PROTOCOL_VERSION};
use ghostnector_spec::backend::{Ports, ProfileId, Report, Verb};
use ghostnector_spec::exemption::tor_baseline;
use ghostnector_spec::ipc::{ErrorCode, HelperResponse, PROTOCOL_VERSION};
use ghostnector_spec::ResolvedIdentity;

use crate::apphelper::AppHelperLink;
use crate::helper::{HelperError, HelperLink};
use crate::resolver::{CommandError, CommandRunner};
use crate::services::{ServiceError, Services};
use crate::verify::Outcome;

/// A supervisor that records what it was asked, and reports units as running.
#[derive(Debug, Default)]
pub struct MockSupervisor {
    started: Mutex<Vec<String>>,
    stopped: Mutex<Vec<String>>,
}

impl MockSupervisor {
    /// A supervisor that accepts everything.
    pub fn new() -> Self {
        Self::default()
    }

    /// Units that were started, in order.
    pub fn started(&self) -> Vec<String> {
        self.started.lock().expect("mock lock").clone()
    }

    /// Units that were stopped, in order.
    pub fn stopped(&self) -> Vec<String> {
        self.stopped.lock().expect("mock lock").clone()
    }
}

impl crate::supervisor::Supervisor for MockSupervisor {
    fn start(&self, unit: &str) -> Result<(), crate::supervisor::SupervisorError> {
        self.started
            .lock()
            .expect("mock lock")
            .push(unit.to_string());
        Ok(())
    }

    fn stop(&self, unit: &str) -> Result<(), crate::supervisor::SupervisorError> {
        self.stopped
            .lock()
            .expect("mock lock")
            .push(unit.to_string());
        Ok(())
    }

    fn state(
        &self,
        _unit: &str,
    ) -> Result<crate::supervisor::ServiceState, crate::supervisor::SupervisorError> {
        Ok(crate::supervisor::ServiceState::Running)
    }
}

/// A namespace helper that records what it was asked and can fail on demand.
#[derive(Debug, Default)]
pub struct MockAppHelper {
    bridge: Mutex<bool>,
    entries: Mutex<Vec<AppEntry>>,
    calls: Mutex<Vec<AppVerb>>,
    fail_create: Mutex<Option<String>>,
    fail_launch: Mutex<Option<String>>,
    fail_verify: Mutex<Option<String>>,
}

impl MockAppHelper {
    /// A helper that is present and willing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every verb that reached the helper, in order.
    pub fn calls(&self) -> Vec<AppVerb> {
        self.calls.lock().expect("mock lock").clone()
    }

    /// Whether a bridge was ensured.
    pub fn bridge_ready(&self) -> bool {
        *self.bridge.lock().expect("mock lock")
    }

    /// Fail the next create.
    pub fn fail_create_with(&self, message: &str) {
        *self.fail_create.lock().expect("mock lock") = Some(message.to_string());
    }

    /// Fail the next launch.
    pub fn fail_launch_with(&self, message: &str) {
        *self.fail_launch.lock().expect("mock lock") = Some(message.to_string());
    }

    /// Make the next `Verify` report a changed namespace.
    pub fn fail_verify_with(&self, detail: &str) {
        *self.fail_verify.lock().expect("mock lock") = Some(detail.to_string());
    }

    fn report(&self) -> AppReport {
        AppReport {
            bridge_present: *self.bridge.lock().expect("mock lock"),
            entries: self.entries.lock().expect("mock lock").clone(),
            ..AppReport::default()
        }
    }

    fn refused(message: &str) -> HelperError {
        HelperError::Refused {
            code: ErrorCode::BackendFailure,
            message: message.to_string(),
            sensitive: false,
        }
    }
}

impl AppHelperLink for MockAppHelper {
    fn invoke(&self, verb: AppVerb) -> Result<AppResponse, HelperError> {
        self.calls.lock().expect("mock lock").push(verb.clone());
        match verb {
            AppVerb::Hello { .. } => Ok(AppResponse::Hello {
                protocol: APP_PROTOCOL_VERSION,
                version: "mock".to_string(),
            }),
            AppVerb::EnsureBridge { .. } => {
                *self.bridge.lock().expect("mock lock") = true;
                Ok(AppResponse::Applied {
                    report: self.report(),
                })
            }
            AppVerb::Create { user_uid } => {
                if let Some(message) = self.fail_create.lock().expect("mock lock").take() {
                    return Err(Self::refused(&message));
                }
                let mut entries = self.entries.lock().expect("mock lock");
                let id = (1..=32)
                    .find(|id| !entries.iter().any(|entry| entry.id == *id))
                    .expect("the mock has room");
                let entry = AppEntry {
                    id,
                    owner_uid: user_uid,
                    address: std::net::Ipv4Addr::new(10, 200, 0, (id + 1) as u8),
                    created_at: 0,
                    present: true,
                };
                entries.push(entry.clone());
                Ok(AppResponse::Created { entry })
            }
            AppVerb::Destroy { id } => {
                self.entries
                    .lock()
                    .expect("mock lock")
                    .retain(|entry| entry.id != id);
                Ok(AppResponse::Applied {
                    report: self.report(),
                })
            }
            AppVerb::Inspect { id } => Ok(AppResponse::Inspected {
                entry: self
                    .entries
                    .lock()
                    .expect("mock lock")
                    .iter()
                    .find(|entry| entry.id == id)
                    .cloned(),
                notes: Vec::new(),
            }),
            AppVerb::Verify { .. } => {
                if let Some(detail) = self.fail_verify.lock().expect("mock lock").take() {
                    return Ok(AppResponse::Verified {
                        matches: false,
                        detail,
                    });
                }
                Ok(AppResponse::Verified {
                    matches: true,
                    detail: "the mock namespace is unchanged".to_string(),
                })
            }
            AppVerb::Launch { id, user_uid } => {
                if let Some(message) = self.fail_launch.lock().expect("mock lock").take() {
                    return Err(Self::refused(&message));
                }
                let entry = self
                    .entries
                    .lock()
                    .expect("mock lock")
                    .iter()
                    .find(|entry| entry.id == id)
                    .cloned()
                    .ok_or_else(|| Self::refused("no such group"))?;
                let _ = user_uid;
                Ok(AppResponse::Launched {
                    entry,
                    socket: format!("/tmp/ghostnector-mock-session-{id}.sock"),
                })
            }
            AppVerb::Probe { .. } => Ok(AppResponse::Probed {
                outcome: ghostnector_spec::appd::ProbeOutcome::Passed,
                details: vec!["ok: the mock probe passed".to_string()],
            }),
            AppVerb::ReportRegistry => Ok(AppResponse::Report(self.report())),
            AppVerb::Revert => {
                *self.bridge.lock().expect("mock lock") = false;
                self.entries.lock().expect("mock lock").clear();
                Ok(AppResponse::Applied {
                    report: self.report(),
                })
            }
        }
    }
}

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

    /// The profile currently applied, as the mock remembers it.
    pub fn current(&self) -> Option<ProfileId> {
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
            i2p_ports: ghostnector_spec::backend::I2pPorts::default(),
            notes: Vec::new(),
        }
    }
}

impl HelperLink for MockHelper {
    fn invoke(&self, verb: Verb) -> Result<HelperResponse, HelperError> {
        if !self.reachable {
            return Err(HelperError::Connect {
                path: "/run/ghostnector/netd/netd.sock".into(),
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
    router_nameservers: Mutex<Vec<std::net::IpAddr>>,
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

    /// The nameservers the engine asked to be written for the router.
    pub fn router_nameservers(&self) -> Vec<std::net::IpAddr> {
        self.router_nameservers.lock().expect("mock lock").clone()
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
    fn bring_up(
        &self,
        profile: ProfileId,
        _ports: Ports,
        _app_core: Option<std::net::Ipv4Addr>,
        _i2p_ports: ghostnector_spec::backend::I2pPorts,
    ) -> Result<(), ServiceError> {
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

    fn configure_router_resolver(
        &self,
        nameservers: &[std::net::IpAddr],
    ) -> Result<(), ServiceError> {
        *self.router_nameservers.lock().expect("mock lock") = nameservers.to_vec();
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

/// An I2P verifier whose answer the test decides.
///
/// The default is "no evidence": like the real `NoI2pEvidence`, a mock that was not told otherwise
/// can never pass.
#[derive(Debug, Default)]
pub struct MockI2pVerification {
    outcome: Mutex<Option<Outcome>>,
}

impl MockI2pVerification {
    /// A verifier with no evidence yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Script what the next run concludes.
    pub fn set_outcome(&self, outcome: Outcome) {
        *self.outcome.lock().expect("mock lock") = Some(outcome);
    }
}

impl crate::verify_i2p::I2pVerification for MockI2pVerification {
    fn run_once(&self, _ports: ghostnector_spec::backend::I2pPorts) -> crate::verify::Report {
        let outcome =
            self.outcome
                .lock()
                .expect("mock lock")
                .clone()
                .unwrap_or(Outcome::Inconclusive {
                    reason: "no I2P evidence".to_string(),
                });
        let details = vec![format!("mock I2P: {outcome:?}")];
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
