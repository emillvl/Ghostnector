//! The protection state machine.
//!
//! Its whole reason for existing is one rule, DR-15: **once protection has been established, only an
//! explicit user request may return the machine to the clearnet.** Everything else about the state
//! is bookkeeping. Encoding the rule here — rather than in every call site — means a future code
//! path that tries to "helpfully" fall back to the clearnet fails to compile or fails a test, rather
//! than quietly leaking.

use ghostnector_spec::{ProtectionState, Reason};

/// Who or what is asking for a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// Ghostnector decided on its own.
    Automatic,
    /// The user asked for it, so the state machine's protections do not apply.
    UserRequested,
    /// Something verified that the policy is working. The only way into `Protected`.
    Verified,
}

/// Why a transition was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    /// An automatic transition tried to return to the clearnet after protection was established.
    #[error(
        "refusing to leave {from:?} for the clearnet automatically: only an explicit user request \
         can turn protection off (DR-15)"
    )]
    RollbackFromProtected {
        /// The state the machine was in.
        from: ProtectionState,
    },
    /// A transition to `Protected` was attempted without anything having verified it.
    #[error("refusing to claim protection: it must be verified before it can be called protected")]
    UnverifiedProtection,
}

/// The machine.
#[derive(Debug, Clone)]
pub struct Machine {
    state: ProtectionState,
    generation: u64,
    reasons: Vec<Reason>,
    since: Option<i64>,
}

impl Default for Machine {
    fn default() -> Self {
        Self::new()
    }
}

impl Machine {
    /// A machine that has not applied anything.
    pub fn new() -> Self {
        Self {
            state: ProtectionState::Off,
            generation: 0,
            reasons: Vec::new(),
            since: None,
        }
    }

    /// The current state.
    pub fn state(&self) -> ProtectionState {
        self.state
    }

    /// A counter that advances on every change, so clients can discard stale updates.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The current explanations.
    pub fn reasons(&self) -> &[Reason] {
        &self.reasons
    }

    /// When the current state began.
    pub fn since(&self) -> Option<i64> {
        self.since
    }

    /// Move to `next`, or explain why that is not allowed.
    ///
    /// Repeating the current state is not a change: the reasons are replaced and the generation is
    /// left alone, so subscribers are not woken for nothing.
    pub fn transition(
        &mut self,
        next: ProtectionState,
        cause: Cause,
        reasons: Vec<Reason>,
        now: i64,
    ) -> Result<(), TransitionError> {
        // "Protected" is a claim about evidence, so the only way in is a verification.
        if next == ProtectionState::Protected && cause != Cause::Verified {
            return Err(TransitionError::UnverifiedProtection);
        }

        // Leaving protection for the clearnet is a decision, not a consequence: only the user can
        // make it, and only when protection was never established may it happen automatically.
        if next == ProtectionState::Off
            && cause != Cause::UserRequested
            && !self.state.may_auto_rollback()
        {
            return Err(TransitionError::RollbackFromProtected { from: self.state });
        }

        if next == self.state {
            self.reasons = reasons;
            return Ok(());
        }

        self.state = next;
        self.reasons = reasons;
        self.generation += 1;
        self.since = Some(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(text: &str) -> Vec<Reason> {
        vec![Reason::new(text)]
    }

    fn machine_in(state: ProtectionState) -> Machine {
        let mut machine = Machine::new();
        // `Verified` is the only cause that can reach every state the tests need, since `Protected`
        // now requires evidence and `Off` requires the user.
        machine
            .transition(state, Cause::Verified, vec![], 100)
            .expect("setup");
        machine
    }

    #[test]
    fn it_starts_turned_off_with_no_history() {
        let machine = Machine::new();
        assert_eq!(machine.state(), ProtectionState::Off);
        assert_eq!(machine.generation(), 0);
        assert!(machine.reasons().is_empty());
        assert_eq!(machine.since(), None);
    }

    #[test]
    fn an_automatic_return_to_the_clearnet_is_refused_after_protection_exists() {
        for state in [
            ProtectionState::Protected,
            ProtectionState::Degraded,
            ProtectionState::Blocked,
            ProtectionState::Portal,
        ] {
            let mut machine = machine_in(state);
            let error = machine
                .transition(ProtectionState::Off, Cause::Automatic, vec![], 200)
                .unwrap_err();
            assert_eq!(
                error,
                TransitionError::RollbackFromProtected { from: state }
            );
            assert_eq!(machine.state(), state, "the state must not have moved");
        }
    }

    #[test]
    fn an_automatic_return_to_the_clearnet_is_allowed_before_protection_exists() {
        for state in [ProtectionState::Off, ProtectionState::Applying] {
            let mut machine = machine_in(state);
            assert!(machine
                .transition(
                    ProtectionState::Off,
                    Cause::Automatic,
                    reason("connect failed"),
                    200
                )
                .is_ok());
            assert_eq!(machine.state(), ProtectionState::Off);
        }
    }

    #[test]
    fn the_user_can_always_turn_protection_off() {
        for state in [
            ProtectionState::Off,
            ProtectionState::Applying,
            ProtectionState::Protected,
            ProtectionState::Degraded,
            ProtectionState::Blocked,
            ProtectionState::Portal,
        ] {
            let mut machine = machine_in(state);
            assert!(
                machine
                    .transition(
                        ProtectionState::Off,
                        Cause::UserRequested,
                        reason("asked"),
                        300
                    )
                    .is_ok(),
                "the user must be able to leave {state:?}"
            );
        }
    }

    #[test]
    fn nothing_may_claim_protection_without_verification() {
        for cause in [Cause::Automatic, Cause::UserRequested] {
            let mut machine = Machine::new();
            let error = machine
                .transition(ProtectionState::Protected, cause, vec![], 1)
                .unwrap_err();
            assert_eq!(error, TransitionError::UnverifiedProtection, "{cause:?}");
        }

        // Evidence is the only door.
        let mut machine = machine_in(ProtectionState::Degraded);
        assert!(machine
            .transition(ProtectionState::Protected, Cause::Verified, vec![], 2)
            .is_ok());
        assert_eq!(machine.state(), ProtectionState::Protected);
    }

    #[test]
    fn verification_is_not_a_way_out_of_protection() {
        let mut machine = machine_in(ProtectionState::Protected);
        let error = machine
            .transition(ProtectionState::Off, Cause::Verified, vec![], 3)
            .unwrap_err();
        assert_eq!(
            error,
            TransitionError::RollbackFromProtected {
                from: ProtectionState::Protected
            }
        );
    }

    #[test]
    fn failures_may_always_escalate_to_blocked() {
        for state in [
            ProtectionState::Applying,
            ProtectionState::Degraded,
            ProtectionState::Protected,
        ] {
            let mut machine = machine_in(state);
            assert!(machine
                .transition(
                    ProtectionState::Blocked,
                    Cause::Automatic,
                    reason("tor died"),
                    5
                )
                .is_ok());
            assert_eq!(machine.state(), ProtectionState::Blocked);
        }
    }

    #[test]
    fn a_repeated_state_updates_the_explanation_without_a_new_generation() {
        let mut machine = machine_in(ProtectionState::Degraded);
        let generation = machine.generation();
        machine
            .transition(
                ProtectionState::Degraded,
                Cause::Automatic,
                reason("still degraded"),
                400,
            )
            .expect("same state");
        assert_eq!(machine.generation(), generation);
        assert_eq!(machine.reasons()[0].as_str(), "still degraded");
    }

    #[test]
    fn a_real_change_advances_the_generation_and_the_timestamp() {
        let mut machine = Machine::new();
        machine
            .transition(ProtectionState::Applying, Cause::UserRequested, vec![], 10)
            .expect("applying");
        assert_eq!(machine.generation(), 1);
        assert_eq!(machine.since(), Some(10));
        machine
            .transition(ProtectionState::Degraded, Cause::Automatic, vec![], 20)
            .expect("degraded");
        assert_eq!(machine.generation(), 2);
        assert_eq!(machine.since(), Some(20));
    }
}
