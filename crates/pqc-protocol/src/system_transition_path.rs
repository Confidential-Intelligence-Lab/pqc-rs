//! Advisory evaluation of full-system-state transition paths.
//!
//! A path is represented by caller-supplied states and authorization
//! decisions. Evaluation does not authenticate those inputs, execute
//! cryptographic operations, or enforce the resulting decision.

use crate::{AuthorizationDecision, CryptographicSystemState};

/// A proposed transition between complete cryptographic system states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemTransitionStep {
    /// Source state of the proposed transition.
    pub source: CryptographicSystemState,
    /// Destination state of the proposed transition.
    pub destination: CryptographicSystemState,
    /// Advisory authorization decision supplied for this step.
    pub authorization: AuthorizationDecision,
}

/// Result of evaluating a full-system-state transition path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemPathEvaluation {
    /// All represented states satisfy the supplied invariant.
    Complete,
    /// The initial state violates the supplied invariant.
    InitialInvariantViolation,
    /// A step does not begin at the preceding state.
    Disconnected {
        /// Zero-based index of the disconnected step.
        step: usize,
    },
    /// A step lacks affirmative advisory authorization.
    NotAuthorized {
        /// Zero-based index of the step.
        step: usize,
        /// Authorization decision supplied for the step.
        decision: AuthorizationDecision,
    },
    /// A destination state violates the supplied invariant.
    InvariantViolation {
        /// Zero-based index of the step.
        step: usize,
    },
    /// The final represented state differs from the requested target.
    TargetMismatch,
}

/// Evaluate continuity, advisory authorization, and invariant preservation.
///
/// The invariant is supplied by the caller and is evaluated for the initial
/// state and every represented destination state. This function does not
/// establish the trustworthiness of the states, decisions, or invariant.
///
/// An empty path completes only if the initial state satisfies the invariant
/// and equals the requested target.
pub fn evaluate_system_transition_path<F>(
    initial: CryptographicSystemState,
    target: CryptographicSystemState,
    steps: &[SystemTransitionStep],
    invariant: F,
) -> SystemPathEvaluation
where
    F: Fn(CryptographicSystemState) -> bool,
{
    if !invariant(initial) {
        return SystemPathEvaluation::InitialInvariantViolation;
    }

    let mut current = initial;

    for (index, step) in steps.iter().enumerate() {
        if step.source != current {
            return SystemPathEvaluation::Disconnected { step: index };
        }

        if step.authorization != AuthorizationDecision::Allow {
            return SystemPathEvaluation::NotAuthorized {
                step: index,
                decision: step.authorization,
            };
        }

        if !invariant(step.destination) {
            return SystemPathEvaluation::InvariantViolation { step: index };
        }

        current = step.destination;
    }

    if current != target {
        return SystemPathEvaluation::TargetMismatch;
    }

    SystemPathEvaluation::Complete
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AlgorithmId, ConfigurationIdentity, DeploymentStateIdentity, EvidenceStateIdentity,
        ImplementationRevision, ParameterSetId, PolicyStateIdentity, ProviderId,
    };

    fn state(
        provider: u32,
        policy: u64,
        evidence: u64,
        deployment: u64,
    ) -> CryptographicSystemState {
        CryptographicSystemState::new(
            ConfigurationIdentity::new(
                AlgorithmId::new(1),
                ParameterSetId::new(768),
                ProviderId::new(provider),
                ImplementationRevision::new(1),
            ),
            PolicyStateIdentity::new(policy),
            EvidenceStateIdentity::new(evidence),
            DeploymentStateIdentity::new(deployment),
        )
    }

    fn step(
        source: CryptographicSystemState,
        destination: CryptographicSystemState,
        authorization: AuthorizationDecision,
    ) -> SystemTransitionStep {
        SystemTransitionStep {
            source,
            destination,
            authorization,
        }
    }

    #[test]
    fn continuous_authorized_full_state_path_completes() {
        let a = state(1, 1, 1, 1);
        let b = state(2, 1, 1, 1);
        let c = state(3, 2, 2, 2);

        let steps = [
            step(a, b, AuthorizationDecision::Allow),
            step(b, c, AuthorizationDecision::Allow),
        ];

        assert_eq!(
            evaluate_system_transition_path(a, c, &steps, |_| true),
            SystemPathEvaluation::Complete
        );
    }

    #[test]
    fn policy_change_can_violate_invariant_without_configuration_change() {
        let a = state(1, 1, 1, 1);
        let b = state(1, 2, 1, 1);

        assert_eq!(a.configuration(), b.configuration());

        assert_eq!(
            evaluate_system_transition_path(
                a,
                b,
                &[step(a, b, AuthorizationDecision::Allow)],
                |s| s.policy() == PolicyStateIdentity::new(1),
            ),
            SystemPathEvaluation::InvariantViolation { step: 0 }
        );
    }

    #[test]
    fn evidence_change_can_violate_invariant_without_configuration_change() {
        let a = state(1, 1, 1, 1);
        let b = state(1, 1, 2, 1);

        assert_eq!(a.configuration(), b.configuration());

        assert_eq!(
            evaluate_system_transition_path(
                a,
                b,
                &[step(a, b, AuthorizationDecision::Allow)],
                |s| s.evidence() == EvidenceStateIdentity::new(1),
            ),
            SystemPathEvaluation::InvariantViolation { step: 0 }
        );
    }

    #[test]
    fn deployment_change_can_violate_invariant_without_configuration_change() {
        let a = state(1, 1, 1, 1);
        let b = state(1, 1, 1, 2);

        assert_eq!(a.configuration(), b.configuration());

        assert_eq!(
            evaluate_system_transition_path(
                a,
                b,
                &[step(a, b, AuthorizationDecision::Allow)],
                |s| s.deployment() == DeploymentStateIdentity::new(1),
            ),
            SystemPathEvaluation::InvariantViolation { step: 0 }
        );
    }

    #[test]
    fn disconnected_full_state_path_is_rejected() {
        let a = state(1, 1, 1, 1);
        let b = state(2, 1, 1, 1);
        let changed = state(2, 2, 1, 1);
        let c = state(3, 2, 1, 1);

        let steps = [
            step(a, b, AuthorizationDecision::Allow),
            step(changed, c, AuthorizationDecision::Allow),
        ];

        assert_eq!(
            evaluate_system_transition_path(a, c, &steps, |_| true),
            SystemPathEvaluation::Disconnected { step: 1 }
        );
    }

    #[test]
    fn denied_step_prevents_completion() {
        let a = state(1, 1, 1, 1);
        let b = state(2, 1, 1, 1);

        assert_eq!(
            evaluate_system_transition_path(
                a,
                b,
                &[step(a, b, AuthorizationDecision::Deny)],
                |_| true,
            ),
            SystemPathEvaluation::NotAuthorized {
                step: 0,
                decision: AuthorizationDecision::Deny,
            }
        );
    }

    #[test]
    fn deferred_step_prevents_completion() {
        let a = state(1, 1, 1, 1);
        let b = state(2, 1, 1, 1);

        assert_eq!(
            evaluate_system_transition_path(
                a,
                b,
                &[step(a, b, AuthorizationDecision::Defer)],
                |_| true,
            ),
            SystemPathEvaluation::NotAuthorized {
                step: 0,
                decision: AuthorizationDecision::Defer,
            }
        );
    }

    #[test]
    fn unknown_step_prevents_completion() {
        let a = state(1, 1, 1, 1);
        let b = state(2, 1, 1, 1);

        assert_eq!(
            evaluate_system_transition_path(
                a,
                b,
                &[step(a, b, AuthorizationDecision::Unknown)],
                |_| true,
            ),
            SystemPathEvaluation::NotAuthorized {
                step: 0,
                decision: AuthorizationDecision::Unknown,
            }
        );
    }

    #[test]
    fn initial_invariant_violation_is_detected() {
        let a = state(1, 2, 1, 1);

        assert_eq!(
            evaluate_system_transition_path(a, a, &[], |s| {
                s.policy() == PolicyStateIdentity::new(1)
            }),
            SystemPathEvaluation::InitialInvariantViolation
        );
    }

    #[test]
    fn incorrect_target_is_rejected() {
        let a = state(1, 1, 1, 1);
        let b = state(2, 1, 1, 1);
        let c = state(3, 1, 1, 1);

        assert_eq!(
            evaluate_system_transition_path(
                a,
                c,
                &[step(a, b, AuthorizationDecision::Allow)],
                |_| true,
            ),
            SystemPathEvaluation::TargetMismatch
        );
    }

    #[test]
    fn empty_path_completes_only_at_target() {
        let a = state(1, 1, 1, 1);
        let b = state(2, 1, 1, 1);

        assert_eq!(
            evaluate_system_transition_path(a, a, &[], |_| true),
            SystemPathEvaluation::Complete
        );

        assert_eq!(
            evaluate_system_transition_path(a, b, &[], |_| true),
            SystemPathEvaluation::TargetMismatch
        );
    }
}
