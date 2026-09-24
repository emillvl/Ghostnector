//! Orchestration: turning a request into a policy, and a failure into a safe state.
//!
//! The interesting behaviour is not the happy path. It is:
//!
//! * **Deny first (DR-4).** A connect applies the fail-closed baseline *before* the profile it was
//!   asked for, so there is no instant in which the machine is more permissive than intended.
//! * **A failed connect may roll back; a failed protection may not (DR-15).** If protection was
//!   never established, rolling back to the captured baseline is honest. Once it has been
//!   established, the engine keeps the machine denied and says so.
//! * **A restart is reconciled against the kernel (§12.3).** If the kernel says nothing is applied
//!   but the journal says the user wanted protection, the engine applies the fail-closed baseline
//!   rather than quietly returning to the clearnet (DR-16).
//! * **It never claims more than it knows.** A successfully applied policy becomes `Degraded` with
//!   verification `Unavailable`, not `Protected`, until something has actually verified it.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};

use ghostnector_spec::backend::{Params, Ports, ProfileId, Report, Verb};
use ghostnector_spec::{
    Event, Health, Profile, ProfileError, ProtectionState, Reason, Scope, ServiceHealth, Snapshot,
    ValidProfile, Verification,
};

use crate::helper::{HelperError, HelperLink};
use crate::journal::{Intent, Journal, JournalError};
use crate::now_unix;
use crate::services::{ServiceError, Services};
use crate::state::{Cause, Machine, TransitionError};

/// Where the intent file lives on a real system.
pub const DEFAULT_JOURNAL: &str = "/var/lib/ghostnector/intent.json";

/// What the engine needs to know about its environment.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Where to record what the user asked for.
    pub journal_path: PathBuf,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            journal_path: PathBuf::from(DEFAULT_JOURNAL),
        }
    }
}

/// Why an operation failed.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The requested profile is not one that can be enforced.
    #[error("the requested profile is not valid: {0}")]
    InvalidProfile(#[from] ProfileError),
    /// The profile is valid in principle but not implemented in this milestone.
    #[error("cannot do that yet: {0}")]
    NotSupported(String),
    /// The helper could not be reached or refused.
    #[error("{0}")]
    Helper(#[from] HelperError),
    /// The helper said it applied the policy, but the policy is not present.
    #[error("the helper reported success, but no policy is present")]
    NotApplied,
    /// The helper answered the wrong kind of thing.
    #[error("the helper answered unexpectedly: {0}")]
    Protocol(String),
    /// The state machine refused the transition.
    #[error("{0}")]
    Transition(#[from] TransitionError),
    /// The journal could not be read or written.
    #[error("{0}")]
    Journal(#[from] JournalError),
    /// A service the profile needs could not be brought up.
    #[error("{0}")]
    Services(#[from] ServiceError),
}

/// The control plane.
pub struct Engine {
    machine: Mutex<Machine>,
    helper: Arc<dyn HelperLink>,
    services: Arc<dyn Services>,
    journal: Journal,
    last_report: Mutex<Report>,
    requested: Mutex<Option<Profile>>,
    notes: Mutex<Vec<Reason>>,
    subscribers: Mutex<Vec<Sender<Event>>>,
}

impl Engine {
    /// Build an engine around a helper link.
    pub fn new(
        config: EngineConfig,
        helper: Arc<dyn HelperLink>,
        services: Arc<dyn Services>,
    ) -> Self {
        Self {
            machine: Mutex::new(Machine::new()),
            helper,
            services,
            journal: Journal::new(config.journal_path),
            last_report: Mutex::new(Report::default()),
            requested: Mutex::new(None),
            notes: Mutex::new(Vec::new()),
            subscribers: Mutex::new(Vec::new()),
        }
    }

    /// The intent file in use.
    pub fn journal_path(&self) -> &std::path::Path {
        self.journal.path()
    }

    /// Everything a client needs to display, and nothing sensitive.
    pub fn snapshot(&self) -> Snapshot {
        let machine = self.lock_machine();
        let report = self.lock_report().clone();
        let requested = self.lock_requested().clone();
        let mut reasons: Vec<Reason> = machine.reasons().to_vec();
        reasons.extend(self.lock_notes().iter().cloned());

        Snapshot {
            state: machine.state(),
            profile: requested,
            warnings: Vec::new(),
            reasons,
            exemptions: report.exemptions.clone(),
            health: Health {
                // Service health arrives with the service supervisor (M3).
                tor: ServiceHealth::Unknown,
                dns: ServiceHealth::Unknown,
                i2p: ServiceHealth::Unknown,
                policy_applied: report.applied,
                // Nothing has verified anything yet; saying otherwise would be a lie.
                verification: Verification::Unavailable,
            },
            verified_ago_secs: None,
            blocked_egress_attempts: 0,
            generation: machine.generation(),
        }
    }

    /// Ask the helper what the kernel has, without failing if it cannot answer.
    pub fn refresh(&self) {
        match self.helper.invoke(Verb::Report) {
            Ok(answer) => match report_from(answer) {
                Ok(report) => {
                    self.remember_report(report);
                    self.clear_note_containing("helper");
                }
                Err(error) => self.add_note(format!("the helper's answer was unusable: {error}")),
            },
            Err(error) => self.add_note(format!(
                "the helper could not be asked what is applied ({error}); the policy may differ \
                 from what is shown"
            )),
        }
    }

    /// Apply a profile for the user, or leave the machine safely denied.
    pub fn connect(&self, profile: Profile, requester_uid: u32) -> Result<(), EngineError> {
        let requested = profile.clone();
        let valid = profile.validate()?;
        let (target, params) = plan(&valid, requester_uid)?;

        self.set_state(
            ProtectionState::Applying,
            Cause::UserRequested,
            vec![Reason::new("applying the policy")],
        )?;
        self.publish();

        match self.bring_up_then_open(target, &params) {
            Ok(report) => {
                self.remember_report(report);
                *self.lock_requested() = Some(requested);
                let mut reasons = vec![
                    Reason::new(format!("{target:?} is applied")),
                    Reason::new(
                        "nothing has verified this yet, so it is reported as degraded rather \
                         than protected",
                    ),
                ];
                // Anything the services want the user to know belongs in the state, not in a log
                // line nobody reads.
                reasons.extend(self.services.notes(target).into_iter().map(Reason::new));
                self.set_state(ProtectionState::Degraded, Cause::Automatic, reasons)?;
                self.record_intent(Intent::requested(
                    target,
                    params,
                    now_unix(),
                    self.generation(),
                ))?;
                self.publish();
                Ok(())
            }
            Err(error) => {
                self.roll_back_failed_connect(target, &error);
                Err(error)
            }
        }
    }

    /// Return to the captured baseline, because the user asked for it.
    pub fn disconnect(&self) -> Result<(), EngineError> {
        // Stop what we started first. With the policy gone the service would have no exemption and
        // would be blocked anyway, which looks like a failure rather than a shutdown.
        let profile = self.lock_report().profile;
        if let Some(profile) = profile {
            if let Err(error) = self.services.stand_down(profile) {
                self.add_note(format!(
                    "stopping the services did not finish cleanly: {error}"
                ));
            }
        }

        let report = report_from(self.helper.invoke(Verb::Revert)?)?;
        self.remember_report(report);
        self.set_state(
            ProtectionState::Off,
            Cause::UserRequested,
            vec![Reason::new("protection was turned off by the user")],
        )?;
        *self.lock_requested() = None;
        self.record_intent(Intent::off(now_unix(), self.generation()))?;
        self.publish();
        Ok(())
    }

    /// Deny everything, immediately, regardless of what was applied before.
    pub fn panic(&self) -> Result<(), EngineError> {
        let report = self.apply(ProfileId::FailClosed, &Params::default())?;
        self.remember_report(report);
        *self.lock_requested() = None;
        self.set_state(
            ProtectionState::Blocked,
            Cause::UserRequested,
            vec![Reason::new("the user asked for the fail-closed baseline")],
        )?;
        self.record_intent(Intent::requested(
            ProfileId::FailClosed,
            Params::default(),
            now_unix(),
            self.generation(),
        ))?;
        self.publish();
        Ok(())
    }

    /// Bring the engine's view in line with reality after a restart.
    ///
    /// The enforcement lives in the kernel and outlives this process, so the kernel is asked first
    /// and believed over anything remembered here.
    pub fn reconcile(&self) -> Result<(), EngineError> {
        let intent = self.journal.load()?;
        let report = report_from(self.helper.invoke(Verb::Report)?)?;
        let applied = report.applied;
        let profile = report.profile;
        self.remember_report(report);

        let (next, reasons) = if applied {
            match profile {
                Some(ProfileId::FailClosed) => (
                    ProtectionState::Blocked,
                    vec![Reason::new(
                        "the fail-closed baseline is applied; adopted after a restart",
                    )],
                ),
                Some(other) => {
                    *self.lock_requested() = profile_of(other);
                    (
                        ProtectionState::Degraded,
                        vec![
                            Reason::new(format!("{other:?} is applied; adopted after a restart")),
                            Reason::new(
                                "nothing has verified this yet, so it is reported as degraded \
                                 rather than protected",
                            ),
                        ],
                    )
                }
                None => (
                    ProtectionState::Blocked,
                    vec![Reason::new(
                        "a policy is applied whose profile is unknown, so it is treated as \
                         fail-closed",
                    )],
                ),
            }
        } else if intent.protected {
            // The user asked to be protected and nothing is applied. Fail closed now, rather than
            // quietly returning to the clearnet (DR-16).
            let report = self.apply(ProfileId::FailClosed, &Params::default())?;
            self.remember_report(report);
            (
                ProtectionState::Blocked,
                vec![Reason::new(
                    "protection was requested before the last restart, but nothing was applied; \
                     the fail-closed baseline has been applied instead",
                )],
            )
        } else {
            (
                ProtectionState::Off,
                vec![Reason::new("no policy is applied")],
            )
        };

        // A refusal here means the machine was already protected and is not willing to leave that
        // state on its own. That is the correct outcome; record it rather than fighting it.
        if let Err(refused) = self.set_state(next, Cause::Automatic, reasons) {
            self.add_note(format!(
                "the kernel and the state machine disagree: {refused}"
            ));
        }
        if next == ProtectionState::Blocked && !intent.protected {
            let _ = self.record_intent(Intent::requested(
                ProfileId::FailClosed,
                Params::default(),
                now_unix(),
                self.generation(),
            ));
        }
        self.publish();
        Ok(())
    }

    /// Receive state changes as they happen.
    pub fn subscribe(&self) -> Receiver<Event> {
        let (sender, receiver) = mpsc::channel();
        self.lock_subscribers().push(sender);
        receiver
    }

    // ---------------------------------------------------------------- internals

    /// Deny before opening anything, bring up what the profile needs, then open exactly what was
    /// asked for.
    ///
    /// The order is the security property (DR-4): the machine is denied while Tor bootstraps, and
    /// Tor can bootstrap because the baseline exempts its uid. Nothing is opened until the service
    /// says it is ready.
    fn bring_up_then_open(
        &self,
        target: ProfileId,
        params: &Params,
    ) -> Result<Report, EngineError> {
        if target != ProfileId::FailClosed {
            self.apply(ProfileId::FailClosed, &Params::default())?;
        }

        // The ports come from the helper, so Tor is configured with the same numbers the firewall
        // redirects into. Two sources for one port is how DNS silently stops working.
        let ports = self.helper_ports()?;
        self.services.bring_up(target, ports)?;

        self.apply(target, params)
    }

    /// Ask the helper which ports its policy redirects into.
    fn helper_ports(&self) -> Result<Ports, EngineError> {
        Ok(report_from(self.helper.invoke(Verb::Report)?)?.ports)
    }

    fn apply(&self, profile: ProfileId, params: &Params) -> Result<Report, EngineError> {
        let answer = self.helper.invoke(Verb::ApplyProfile {
            profile,
            params: params.clone(),
        })?;
        let report = report_from(answer)?;
        if !report.applied {
            return Err(EngineError::NotApplied);
        }
        Ok(report)
    }

    /// The state a failed connect leaves behind.
    ///
    /// Rolling back is permitted only because protection was never established; the state machine
    /// enforces that. But withdrawal has to *succeed* before the machine may claim to be
    /// unprotected: if the policy cannot be withdrawn, the honest report is that the machine is
    /// still denied, not that it is open.
    fn roll_back_failed_connect(&self, target: ProfileId, error: &EngineError) {
        // Whatever was started for an attempt that failed should not be left running for a
        // protection that never happened.
        if let Err(stop_error) = self.services.stand_down(target) {
            self.add_note(format!(
                "stopping the services did not finish cleanly: {stop_error}"
            ));
        }

        let withdrawn = match self.helper.invoke(Verb::Revert) {
            Ok(answer) => report_from(answer)
                .map(|report| !report.applied)
                .unwrap_or(false),
            Err(_) => false,
        };

        if withdrawn {
            let reason = Reason::new(format!(
                "connecting failed, so nothing was applied: {error}"
            ));
            match self.set_state(ProtectionState::Off, Cause::Automatic, vec![reason]) {
                Ok(()) => {
                    *self.lock_requested() = None;
                    let _ = self.record_intent(Intent::off(now_unix(), self.generation()));
                }
                Err(refused) => self.keep_denied(format!(
                    "a failed transition met protection that was already established: {refused}"
                )),
            }
        } else {
            self.keep_denied(format!(
                "connecting failed and the policy could not be withdrawn, so the machine is \
                 treated as denied: {error}"
            ));
        }
        self.publish();
    }

    /// Deny everything and say why, without pretending the machine is open.
    fn keep_denied(&self, reason: String) {
        let _ = self.apply(ProfileId::FailClosed, &Params::default());
        let _ = self.set_state(
            ProtectionState::Blocked,
            Cause::Automatic,
            vec![Reason::new(reason)],
        );
        let _ = self.record_intent(Intent::requested(
            ProfileId::FailClosed,
            Params::default(),
            now_unix(),
            self.generation(),
        ));
    }

    fn set_state(
        &self,
        next: ProtectionState,
        cause: Cause,
        reasons: Vec<Reason>,
    ) -> Result<(), EngineError> {
        self.lock_machine()
            .transition(next, cause, reasons, now_unix())?;
        Ok(())
    }

    fn generation(&self) -> u64 {
        self.lock_machine().generation()
    }

    fn record_intent(&self, intent: Intent) -> Result<(), EngineError> {
        self.journal.save(&intent).map_err(EngineError::from)
    }

    fn remember_report(&self, report: Report) {
        *self.lock_report() = report;
    }

    fn add_note(&self, note: impl Into<String>) {
        let mut notes = self.lock_notes();
        let note = Reason::new(note);
        if !notes
            .iter()
            .any(|existing| existing.as_str() == note.as_str())
        {
            notes.push(note);
        }
    }

    fn clear_note_containing(&self, needle: &str) {
        self.lock_notes()
            .retain(|note| !note.as_str().contains(needle));
    }

    fn publish(&self) {
        let event = Event::StateChanged(Box::new(self.snapshot()));
        self.lock_subscribers()
            .retain(|subscriber| subscriber.send(event.clone()).is_ok());
    }

    // A panic while holding one of these locks must not take the control plane down with it: the
    // data is still readable, and refusing to serve a slightly stale snapshot is the worse failure.
    fn lock_machine(&self) -> MutexGuard<'_, Machine> {
        self.machine
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_report(&self) -> MutexGuard<'_, Report> {
        self.last_report
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_requested(&self) -> MutexGuard<'_, Option<Profile>> {
        self.requested
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_notes(&self) -> MutexGuard<'_, Vec<Reason>> {
        self.notes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_subscribers(&self) -> MutexGuard<'_, Vec<Sender<Event>>> {
        self.subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn report_from(answer: ghostnector_spec::HelperResponse) -> Result<Report, EngineError> {
    match answer {
        ghostnector_spec::HelperResponse::Report(report)
        | ghostnector_spec::HelperResponse::Applied { report } => Ok(report),
        other => Err(EngineError::Protocol(format!(
            "expected a report, got {other:?}"
        ))),
    }
}

/// Translate a validated profile into the helper's vocabulary.
fn plan(valid: &ValidProfile, requester_uid: u32) -> Result<(ProfileId, Params), EngineError> {
    let mut params = Params {
        allow_lan: valid.profile().allow_lan,
        user_uid: None,
        netns_id: None,
    };

    let target = match (valid.scope(), valid.tor(), valid.i2p()) {
        (Scope::System, true, false) => ProfileId::TorSystem,
        (Scope::User, true, false) => {
            // A user may only ask to protect themselves.
            params.user_uid = Some(requester_uid);
            ProfileId::TorUser
        }
        (Scope::Dns, false, false) | (Scope::System, false, false) => ProfileId::DnsLockdown,
        (Scope::App, _, _) => {
            return Err(EngineError::NotSupported(
                "protecting single applications arrives in a later milestone".to_string(),
            ))
        }
        (_, _, true) => {
            return Err(EngineError::NotSupported(
                "I2P arrives in a later milestone".to_string(),
            ))
        }
        (Scope::Off, _, _) => {
            return Err(EngineError::NotSupported(
                "use disconnect to turn protection off".to_string(),
            ))
        }
        _ => {
            return Err(EngineError::NotSupported(
                "this combination has no policy yet; encrypted DNS is machine-wide".to_string(),
            ))
        }
    };
    Ok((target, params))
}

/// A best-effort profile for display when all that is known is the helper's profile id.
fn profile_of(id: ProfileId) -> Option<Profile> {
    let (scope, tor) = match id {
        ProfileId::DnsLockdown => (Scope::Dns, false),
        ProfileId::TorSystem => (Scope::System, true),
        ProfileId::TorUser => (Scope::User, true),
        // The baseline is not something the user asked for, and the others are unimplemented.
        ProfileId::FailClosed | ProfileId::TorApp | ProfileId::I2pIsolated => return None,
    };
    Some(Profile {
        scope,
        networks: if tor {
            ghostnector_spec::Networks::tor()
        } else {
            ghostnector_spec::Networks::none()
        },
        ..Profile::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{MockHelper, MockServices};

    const USER_UID: u32 = 1000;

    fn engine_with(helper: Arc<MockHelper>, services: Arc<MockServices>) -> (Engine, PathBuf) {
        let directory = std::env::temp_dir().join(format!(
            "ghostnector-engine-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let path = directory.join("intent.json");
        let engine = Engine::new(
            EngineConfig { journal_path: path },
            helper as Arc<dyn HelperLink>,
            services as Arc<dyn Services>,
        );
        (engine, directory)
    }

    fn engine() -> (Arc<MockHelper>, Engine, PathBuf) {
        let helper = Arc::new(MockHelper::new());
        let services = Arc::new(MockServices::new());
        let (engine, directory) = engine_with(Arc::clone(&helper), Arc::clone(&services));
        (helper, engine, directory)
    }

    fn engine_and_services() -> (Arc<MockHelper>, Arc<MockServices>, Engine, PathBuf) {
        let helper = Arc::new(MockHelper::new());
        let services = Arc::new(MockServices::new());
        let (engine, directory) = engine_with(Arc::clone(&helper), Arc::clone(&services));
        (helper, services, engine, directory)
    }

    fn system_tor_profile() -> Profile {
        Profile {
            scope: Scope::System,
            networks: ghostnector_spec::Networks::tor(),
            ..Profile::default()
        }
    }

    #[test]
    fn connecting_denies_first_and_then_opens_the_requested_profile() {
        let (helper, engine, _dir) = engine();
        engine
            .connect(system_tor_profile(), USER_UID)
            .expect("connect");

        let applied: Vec<ProfileId> = helper
            .verbs()
            .into_iter()
            .filter_map(|verb| match verb {
                Verb::ApplyProfile { profile, .. } => Some(profile),
                _ => None,
            })
            .collect();
        assert_eq!(
            applied,
            vec![ProfileId::FailClosed, ProfileId::TorSystem],
            "the baseline must be applied before anything is opened"
        );
    }

    #[test]
    fn a_successful_connect_reports_degraded_not_protected() {
        let (_helper, engine, _dir) = engine();
        engine
            .connect(system_tor_profile(), USER_UID)
            .expect("connect");
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.state, ProtectionState::Degraded);
        assert_eq!(snapshot.health.verification, Verification::Unavailable);
        assert!(snapshot.health.policy_applied);
        assert!(snapshot
            .reasons
            .iter()
            .any(|reason| reason.as_str().contains("degraded rather than protected")));
    }

    #[test]
    fn connecting_records_the_intent() {
        let (_helper, engine, _dir) = engine();
        engine
            .connect(system_tor_profile(), USER_UID)
            .expect("connect");
        let intent = Journal::new(engine.journal_path()).load().expect("load");
        assert!(intent.protected);
        assert_eq!(intent.profile, Some(ProfileId::TorSystem));
    }

    #[test]
    fn a_failed_connect_rolls_back_and_records_that_nothing_is_applied() {
        let (helper, engine, _dir) = engine();
        helper.fail_apply_with("the kernel said no");
        let error = engine
            .connect(system_tor_profile(), USER_UID)
            .expect_err("connect must fail");
        assert!(error.to_string().contains("the kernel said no"), "{error}");

        let snapshot = engine.snapshot();
        assert_eq!(snapshot.state, ProtectionState::Off);
        assert!(!snapshot.health.policy_applied);
        let intent = Journal::new(engine.journal_path()).load().expect("load");
        assert!(
            !intent.protected,
            "a failed connect must not claim protection"
        );
    }

    #[test]
    fn a_user_scope_connection_can_only_cover_the_requester() {
        let (helper, engine, _dir) = engine();
        let profile = Profile {
            scope: Scope::User,
            networks: ghostnector_spec::Networks::tor(),
            ..Profile::default()
        };
        engine.connect(profile, USER_UID).expect("connect");
        let user_uid = helper.verbs().into_iter().find_map(|verb| match verb {
            Verb::ApplyProfile { profile, params } if profile == ProfileId::TorUser => {
                params.user_uid
            }
            _ => None,
        });
        assert_eq!(user_uid, Some(USER_UID));
    }

    #[test]
    fn disconnecting_is_a_user_request_and_survives_the_state_machine() {
        let (_helper, engine, _dir) = engine();
        engine
            .connect(system_tor_profile(), USER_UID)
            .expect("connect");
        engine.disconnect().expect("disconnect");
        assert_eq!(engine.snapshot().state, ProtectionState::Off);
        assert!(
            !Journal::new(engine.journal_path())
                .load()
                .expect("load")
                .protected
        );
    }

    #[test]
    fn panicking_denies_everything_and_stays_denied() {
        let (_helper, engine, _dir) = engine();
        engine
            .connect(system_tor_profile(), USER_UID)
            .expect("connect");
        engine.panic().expect("panic");
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.state, ProtectionState::Blocked);
        assert!(snapshot.health.policy_applied);
        assert!(
            Journal::new(engine.journal_path())
                .load()
                .expect("load")
                .protected
        );
    }

    #[test]
    fn a_restart_adopts_what_the_kernel_already_has() {
        let (helper, engine, _dir) = engine();
        helper.force_applied(Some(ProfileId::TorSystem));
        engine.reconcile().expect("reconcile");
        let snapshot = engine.snapshot();
        assert_eq!(
            snapshot.state,
            ProtectionState::Degraded,
            "an applied policy is adopted, and still not called protected"
        );
        assert_eq!(
            snapshot.profile.map(|profile| profile.scope),
            Some(Scope::System)
        );
    }

    #[test]
    fn a_restart_with_protection_requested_but_nothing_applied_fails_closed() {
        let (helper, engine, _dir) = engine();
        // The user asked to be protected, then the machine rebooted and the kernel lost everything.
        Journal::new(engine.journal_path())
            .save(&Intent::requested(
                ProfileId::TorSystem,
                Params::default(),
                1,
                1,
            ))
            .expect("save");
        helper.force_applied(None);

        engine.reconcile().expect("reconcile");
        let snapshot = engine.snapshot();
        assert_eq!(
            snapshot.state,
            ProtectionState::Blocked,
            "nothing may quietly return to the clearnet"
        );
        assert!(
            snapshot.reasons.iter().any(|reason| reason
                .as_str()
                .contains("fail-closed baseline has been applied")),
            "{:?}",
            snapshot.reasons
        );
        assert_eq!(
            helper
                .verbs()
                .into_iter()
                .filter_map(|verb| match verb {
                    Verb::ApplyProfile { profile, .. } => Some(profile),
                    _ => None,
                })
                .last(),
            Some(ProfileId::FailClosed)
        );
    }

    #[test]
    fn a_restart_with_nothing_requested_stays_off() {
        let (helper, engine, _dir) = engine();
        helper.force_applied(None);
        engine.reconcile().expect("reconcile");
        assert_eq!(engine.snapshot().state, ProtectionState::Off);
    }

    #[test]
    fn a_restart_when_the_helper_is_unreachable_does_not_invent_a_state() {
        let helper = Arc::new(MockHelper::unreachable());
        let (engine, _dir) = engine_with(Arc::clone(&helper), Arc::new(MockServices::new()));
        assert!(
            engine.reconcile().is_err(),
            "an unreachable helper is an error"
        );
        engine.refresh();
        assert!(
            engine
                .snapshot()
                .reasons
                .iter()
                .any(|reason| reason.as_str().contains("could not be asked")),
            "the interface must be told that the policy is unknown"
        );
    }

    #[test]
    fn subscribers_see_every_change() {
        let (_helper, engine, _dir) = engine();
        let receiver = engine.subscribe();
        engine
            .connect(system_tor_profile(), USER_UID)
            .expect("connect");
        engine.disconnect().expect("disconnect");

        let mut seen = Vec::new();
        while let Ok(event) = receiver.try_recv() {
            if let Event::StateChanged(snapshot) = event {
                seen.push(snapshot.state);
            }
        }
        assert!(seen.contains(&ProtectionState::Applying), "{seen:?}");
        assert!(seen.contains(&ProtectionState::Degraded), "{seen:?}");
        assert!(seen.contains(&ProtectionState::Off), "{seen:?}");
    }

    #[test]
    fn unsupported_profiles_are_refused_with_an_explanation() {
        let (_helper, engine, _dir) = engine();
        for profile in [
            Profile {
                scope: Scope::App,
                networks: ghostnector_spec::Networks::tor(),
                ..Profile::default()
            },
            Profile {
                scope: Scope::System,
                networks: ghostnector_spec::Networks::i2p(),
                ..Profile::default()
            },
            Profile {
                scope: Scope::User,
                networks: ghostnector_spec::Networks::none(),
                ..Profile::default()
            },
        ] {
            let error = engine
                .connect(profile, USER_UID)
                .expect_err("must be refused");
            assert!(
                matches!(error, EngineError::NotSupported(_)),
                "expected a clear refusal, got {error}"
            );
        }
    }

    #[test]
    fn an_invalid_profile_is_refused_before_anything_is_applied() {
        let (helper, engine, _dir) = engine();
        let invalid = Profile {
            scope: Scope::Dns,
            networks: ghostnector_spec::Networks::tor(),
            ..Profile::default()
        };
        let error = engine
            .connect(invalid, USER_UID)
            .expect_err("must be refused");
        assert!(matches!(error, EngineError::InvalidProfile(_)));
        assert!(
            helper.verbs().is_empty(),
            "an invalid request must not reach the helper"
        );
    }

    #[test]
    fn dns_only_scope_maps_to_the_resolver_profile() {
        let (helper, engine, _dir) = engine();
        engine
            .connect(
                Profile {
                    scope: Scope::Dns,
                    ..Profile::default()
                },
                USER_UID,
            )
            .expect("connect");
        assert!(helper.verbs().iter().any(|verb| matches!(
            verb,
            Verb::ApplyProfile { profile, .. } if *profile == ProfileId::DnsLockdown
        )));
    }

    #[test]
    fn connecting_denies_before_it_starts_anything_or_opens_anything() {
        let (helper, services, engine, _dir) = engine_and_services();
        engine
            .connect(system_tor_profile(), USER_UID)
            .expect("connect");

        let sequence: Vec<String> = helper
            .verbs()
            .iter()
            .map(|verb| match verb {
                Verb::ApplyProfile { profile, .. } => format!("apply:{profile:?}"),
                Verb::Report => "report".to_string(),
                Verb::Revert => "revert".to_string(),
                Verb::FlushConntrack => "flush".to_string(),
                Verb::Hello { .. } => "hello".to_string(),
            })
            .collect();
        assert_eq!(
            sequence,
            vec![
                "apply:FailClosed".to_string(),
                // The ports come from the helper, so Tor is configured to match the firewall.
                "report".to_string(),
                "apply:TorSystem".to_string(),
            ],
            "the baseline must be applied before the services start, and before anything is opened"
        );
        assert_eq!(services.brought_up(), vec![ProfileId::TorSystem]);
    }

    #[test]
    fn a_service_that_will_not_come_up_leaves_the_machine_unprotected_and_says_so() {
        let (helper, services, engine, _dir) = engine_and_services();
        services.fail_bring_up_with("Tor did not become usable");

        let error = engine
            .connect(system_tor_profile(), USER_UID)
            .expect_err("connect must fail");
        assert!(
            error.to_string().contains("did not become usable"),
            "{error}"
        );

        assert_eq!(engine.snapshot().state, ProtectionState::Off);
        assert!(
            !Journal::new(engine.journal_path())
                .load()
                .expect("load")
                .protected,
            "a failed connect must not claim protection"
        );
        assert_eq!(
            services.stood_down(),
            vec![ProfileId::TorSystem],
            "services must not be left running for a protection that never happened"
        );
        assert!(
            helper
                .verbs()
                .iter()
                .any(|verb| matches!(verb, Verb::Revert)),
            "the baseline applied on the way in must be withdrawn"
        );
    }

    #[test]
    fn service_notes_reach_the_reported_state() {
        let (_helper, services, engine, _dir) = engine_and_services();
        services.add_note("the resolver's health cannot be checked yet");
        engine
            .connect(system_tor_profile(), USER_UID)
            .expect("connect");
        assert!(
            engine
                .snapshot()
                .reasons
                .iter()
                .any(|reason| reason.as_str().contains("cannot be checked yet")),
            "{:?}",
            engine.snapshot().reasons
        );
    }

    #[test]
    fn disconnecting_stops_what_was_started() {
        let (_helper, services, engine, _dir) = engine_and_services();
        engine
            .connect(system_tor_profile(), USER_UID)
            .expect("connect");
        engine.disconnect().expect("disconnect");
        assert_eq!(services.stood_down(), vec![ProfileId::TorSystem]);
        assert_eq!(engine.snapshot().state, ProtectionState::Off);
    }
}
