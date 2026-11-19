//! Advisory evaluation of cryptographic transition paths.
//!
//! This module checks path continuity, supplied authorization decisions,
//! and a caller-defined configuration invariant. It does not authenticate
//! decisions, execute transitions, or enforce a security policy.

use crate::{AuthorizationDecision, ConfigurationIdentity, CryptographicTransition};

/// A transition and its externally obtained advisory authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionPathStep {
    /// Requested cryptographic transition.
    pub transition: CryptographicTransition,
    /// Advisory authorization decision for this transition.
    pub authorization: AuthorizationDecision,
}

/// Outcome of evaluating a transition path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathEvaluation {
    /// Every step satisfies the modeled conditions and reaches the target.
    ///
    /// This is advisory, not permission to execute the path.
    Complete,
    /// The initial configuration violates the supplied invariant.
    InitialInvariantViolation,
    /// A step does not begin at the preceding configuration.
    Disconnected {
        /// Zero-based index of the disconnected step.
        step: usize,
    },
    /// A step lacks an affirmative advisory authorization decision.
    NotAuthorized {
        /// Zero-based index of the unauthorized step.
        step: usize,
        /// Advisory decision that prevented path completion.
        decision: AuthorizationDecision,
    },
    /// A step's destination violates the supplied invariant.
    InvariantViolation {
        /// Zero-based index of the step violating the invariant.
        step: usize,
    },
    /// The final configuration differs from the requested target.
    TargetMismatch,
}

/// Evaluate an abstract sequence of cryptographic configuration changes.
///
/// The invariant is evaluated on the initial configuration and after each
/// transition. Authorization decisions must already have been obtained
/// through an appropriate external process.
///
/// This function does not establish decision freshness, provenance,
/// atomic execution, or the security of intermediate operations.
pub fn evaluate_transition_path<F>(
    initial: ConfigurationIdentity,
    target: ConfigurationIdentity,
    steps: &[TransitionPathStep],
    invariant: F,
) -> PathEvaluation
where
    F: Fn(ConfigurationIdentity) -> bool,
{
    if !invariant(initial) {
        return PathEvaluation::InitialInvariantViolation;
    }

    let mut current = initial;

    for (index, step) in steps.iter().enumerate() {
        if step.transition.source() != current {
            return PathEvaluation::Disconnected { step: index };
        }

        if step.authorization != AuthorizationDecision::Allow {
            return PathEvaluation::NotAuthorized {
                step: index,
                decision: step.authorization,
            };
        }

        let destination = step.transition.destination();

        if !invariant(destination) {
            return PathEvaluation::InvariantViolation { step: index };
        }

        current = destination;
    }

    if current != target {
        return PathEvaluation::TargetMismatch;
    }

    PathEvaluation::Complete
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlgorithmId, EvidenceScope, ImplementationRevision, ParameterSetId, ProviderId};

    fn configuration(algorithm: u32, provider: u32) -> ConfigurationIdentity {
        ConfigurationIdentity::new(
            AlgorithmId::new(algorithm),
            ParameterSetId::new(1),
            ProviderId::new(provider),
            ImplementationRevision::new(1),
        )
    }

    fn step(
        source: ConfigurationIdentity,
        destination: ConfigurationIdentity,
        authorization: AuthorizationDecision,
    ) -> TransitionPathStep {
        TransitionPathStep {
            transition: CryptographicTransition::new(
                source,
                destination,
                EvidenceScope::Encapsulation,
            ),
            authorization,
        }
    }

    #[test]
    fn continuous_authorized_path_preserving_invariant_completes() {
        let a = configuration(1, 1);
        let b = configuration(2, 1);
        let c = configuration(2, 2);

        let steps = [
            step(a, b, AuthorizationDecision::Allow),
            step(b, c, AuthorizationDecision::Allow),
        ];

        assert_eq!(
            evaluate_transition_path(a, c, &steps, |_| true),
            PathEvaluation::Complete
        );
    }

    #[test]
    fn disconnected_path_is_rejected() {
        let a = configuration(1, 1);
        let b = configuration(2, 1);
        let c = configuration(3, 1);

        let steps = [step(b, c, AuthorizationDecision::Allow)];

        assert_eq!(
            evaluate_transition_path(a, c, &steps, |_| true),
            PathEvaluation::Disconnected { step: 0 }
        );
    }

    #[test]
    fn later_discontinuity_reports_correct_index() {
        let a = configuration(1, 1);
        let b = configuration(2, 1);
        let c = configuration(3, 1);
        let d = configuration(4, 1);

        let steps = [
            step(a, b, AuthorizationDecision::Allow),
            step(c, d, AuthorizationDecision::Allow),
        ];

        assert_eq!(
            evaluate_transition_path(a, d, &steps, |_| true),
            PathEvaluation::Disconnected { step: 1 }
        );
    }

    #[test]
    fn denied_transition_prevents_completion() {
        let a = configuration(1, 1);
        let b = configuration(2, 1);

        let steps = [step(a, b, AuthorizationDecision::Deny)];

        assert_eq!(
            evaluate_transition_path(a, b, &steps, |_| true),
            PathEvaluation::NotAuthorized {
                step: 0,
                decision: AuthorizationDecision::Deny,
            }
        );
    }

    #[test]
    fn deferred_transition_prevents_completion() {
        let a = configuration(1, 1);
        let b = configuration(2, 1);

        let steps = [step(a, b, AuthorizationDecision::Defer)];

        assert_eq!(
            evaluate_transition_path(a, b, &steps, |_| true),
            PathEvaluation::NotAuthorized {
                step: 0,
                decision: AuthorizationDecision::Defer,
            }
        );
    }

    #[test]
    fn unknown_transition_prevents_completion() {
        let a = configuration(1, 1);
        let b = configuration(2, 1);

        let steps = [step(a, b, AuthorizationDecision::Unknown)];

        assert_eq!(
            evaluate_transition_path(a, b, &steps, |_| true),
            PathEvaluation::NotAuthorized {
                step: 0,
                decision: AuthorizationDecision::Unknown,
            }
        );
    }

    #[test]
    fn authorized_classical_fallback_can_violate_path_invariant() {
        // Abstract identifiers: 1 = classical, 2 = hybrid, 3 = PQ.
        // These are test labels, not a cryptographic strength ordering.
        let pq = configuration(3, 1);
        let classical = configuration(1, 1);

        let steps = [step(pq, classical, AuthorizationDecision::Allow)];

        assert_eq!(
            evaluate_transition_path(pq, classical, &steps, |config| config.algorithm().value()
                != 1,),
            PathEvaluation::InvariantViolation { step: 0 }
        );
    }

    #[test]
    fn initial_invariant_violation_is_detected() {
        let classical = configuration(1, 1);
        let pq = configuration(3, 1);

        let steps = [step(classical, pq, AuthorizationDecision::Allow)];

        assert_eq!(
            evaluate_transition_path(classical, pq, &steps, |config| config.algorithm().value()
                != 1,),
            PathEvaluation::InitialInvariantViolation
        );
    }

    #[test]
    fn wrong_final_target_is_rejected() {
        let a = configuration(1, 1);
        let b = configuration(2, 1);
        let c = configuration(3, 1);

        let steps = [step(a, b, AuthorizationDecision::Allow)];

        assert_eq!(
            evaluate_transition_path(a, c, &steps, |_| true),
            PathEvaluation::TargetMismatch
        );
    }

    #[test]
    fn empty_path_is_complete_only_at_the_target() {
        let a = configuration(1, 1);
        let b = configuration(2, 1);

        assert_eq!(
            evaluate_transition_path(a, a, &[], |_| true),
            PathEvaluation::Complete
        );

        assert_eq!(
            evaluate_transition_path(a, b, &[], |_| true),
            PathEvaluation::TargetMismatch
        );
    }

    #[test]
    fn provider_restriction_is_preserved_across_steps() {
        let a = configuration(2, 1);
        let b = configuration(2, 2);
        let c = configuration(2, 3);

        let steps = [
            step(a, b, AuthorizationDecision::Allow),
            step(b, c, AuthorizationDecision::Allow),
        ];

        assert_eq!(
            evaluate_transition_path(a, c, &steps, |config| config.provider().value() != 3,),
            PathEvaluation::InvariantViolation { step: 1 }
        );
    }
}

// R9.3 temporal path evaluation

/// Outcome of evaluating a history-dependent migration constraint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalPathEvaluation {
    /// The path reaches its target without violating the temporal rule.
    ///
    /// This is advisory, not an execution permit.
    Complete,
    /// A transition does not start at the preceding configuration.
    Disconnected {
        /// Zero-based index of the disconnected transition.
        step: usize,
    },
    /// A transition lacks affirmative advisory authorization.
    NotAuthorized {
        /// Zero-based index of the transition.
        step: usize,
        /// Authorization decision supplied for that transition.
        decision: AuthorizationDecision,
    },
    /// A configuration violates the post-milestone constraint.
    Regression {
        /// Index of the configuration violating the constraint.
        ///
        /// Zero identifies the initial configuration; one identifies
        /// the destination of the first transition.
        configuration: usize,
    },
    /// The path does not reach the requested target.
    TargetMismatch,
}

/// Evaluate a migration path with a history-dependent security constraint.
///
/// `milestone` identifies configurations that activate the temporal rule.
/// Once activated, `post_milestone` must hold for the activating
/// configuration and every subsequent configuration.
///
/// Both predicates are caller-supplied and are not authenticated.
/// This function does not execute transitions, verify evidence,
/// or establish freshness of authorization decisions.
pub fn evaluate_temporal_path<M, Q>(
    initial: ConfigurationIdentity,
    target: ConfigurationIdentity,
    steps: &[TransitionPathStep],
    milestone: M,
    post_milestone: Q,
) -> TemporalPathEvaluation
where
    M: Fn(ConfigurationIdentity) -> bool,
    Q: Fn(ConfigurationIdentity) -> bool,
{
    let mut current = initial;
    let mut activated = milestone(initial);

    if activated && !post_milestone(initial) {
        return TemporalPathEvaluation::Regression { configuration: 0 };
    }

    for (index, step) in steps.iter().enumerate() {
        if step.transition.source() != current {
            return TemporalPathEvaluation::Disconnected { step: index };
        }

        if step.authorization != AuthorizationDecision::Allow {
            return TemporalPathEvaluation::NotAuthorized {
                step: index,
                decision: step.authorization,
            };
        }

        current = step.transition.destination();
        activated |= milestone(current);

        if activated && !post_milestone(current) {
            return TemporalPathEvaluation::Regression {
                configuration: index + 1,
            };
        }
    }

    if current != target {
        return TemporalPathEvaluation::TargetMismatch;
    }

    TemporalPathEvaluation::Complete
}

#[cfg(test)]
mod temporal_tests {
    use super::*;
    use crate::{AlgorithmId, EvidenceScope, ImplementationRevision, ParameterSetId, ProviderId};

    fn config(algorithm: u32) -> ConfigurationIdentity {
        ConfigurationIdentity::new(
            AlgorithmId::new(algorithm),
            ParameterSetId::new(1),
            ProviderId::new(1),
            ImplementationRevision::new(1),
        )
    }

    fn transition(
        source: ConfigurationIdentity,
        destination: ConfigurationIdentity,
        decision: AuthorizationDecision,
    ) -> TransitionPathStep {
        TransitionPathStep {
            transition: CryptographicTransition::new(
                source,
                destination,
                EvidenceScope::Encapsulation,
            ),
            authorization: decision,
        }
    }

    fn milestone(c: ConfigurationIdentity) -> bool {
        c.algorithm().value() == 3
    }

    fn acceptable_after_milestone(c: ConfigurationIdentity) -> bool {
        c.algorithm().value() >= 2
    }

    #[test]
    fn migration_reaching_milestone_completes() {
        let classical = config(1);
        let hybrid = config(2);
        let pq = config(3);

        let steps = [
            transition(classical, hybrid, AuthorizationDecision::Allow),
            transition(hybrid, pq, AuthorizationDecision::Allow),
        ];

        assert_eq!(
            evaluate_temporal_path(classical, pq, &steps, milestone, acceptable_after_milestone,),
            TemporalPathEvaluation::Complete
        );
    }

    #[test]
    fn classical_configuration_before_milestone_is_permitted() {
        let classical = config(1);
        let hybrid = config(2);

        let steps = [transition(classical, hybrid, AuthorizationDecision::Allow)];

        assert_eq!(
            evaluate_temporal_path(
                classical,
                hybrid,
                &steps,
                milestone,
                acceptable_after_milestone,
            ),
            TemporalPathEvaluation::Complete
        );
    }

    #[test]
    fn classical_fallback_after_milestone_is_rejected() {
        let pq = config(3);
        let classical = config(1);

        let steps = [transition(pq, classical, AuthorizationDecision::Allow)];

        assert_eq!(
            evaluate_temporal_path(pq, classical, &steps, milestone, acceptable_after_milestone,),
            TemporalPathEvaluation::Regression { configuration: 1 }
        );
    }

    #[test]
    fn regression_after_multiple_steps_is_detected() {
        let classical = config(1);
        let hybrid = config(2);
        let pq = config(3);

        let steps = [
            transition(classical, hybrid, AuthorizationDecision::Allow),
            transition(hybrid, pq, AuthorizationDecision::Allow),
            transition(pq, classical, AuthorizationDecision::Allow),
        ];

        assert_eq!(
            evaluate_temporal_path(
                classical,
                classical,
                &steps,
                milestone,
                acceptable_after_milestone,
            ),
            TemporalPathEvaluation::Regression { configuration: 3 }
        );
    }

    #[test]
    fn post_milestone_hybrid_configuration_can_be_permitted() {
        let pq = config(3);
        let hybrid = config(2);

        let steps = [transition(pq, hybrid, AuthorizationDecision::Allow)];

        assert_eq!(
            evaluate_temporal_path(pq, hybrid, &steps, milestone, acceptable_after_milestone,),
            TemporalPathEvaluation::Complete
        );
    }

    #[test]
    fn milestone_must_itself_satisfy_post_milestone_rule() {
        let pq = config(3);

        assert_eq!(
            evaluate_temporal_path(pq, pq, &[], milestone, |_| false,),
            TemporalPathEvaluation::Regression { configuration: 0 }
        );
    }

    #[test]
    fn disconnected_transition_is_rejected() {
        let classical = config(1);
        let hybrid = config(2);
        let pq = config(3);

        let steps = [transition(hybrid, pq, AuthorizationDecision::Allow)];

        assert_eq!(
            evaluate_temporal_path(classical, pq, &steps, milestone, acceptable_after_milestone,),
            TemporalPathEvaluation::Disconnected { step: 0 }
        );
    }

    #[test]
    fn denied_transition_is_rejected() {
        let classical = config(1);
        let pq = config(3);

        let steps = [transition(classical, pq, AuthorizationDecision::Deny)];

        assert_eq!(
            evaluate_temporal_path(classical, pq, &steps, milestone, acceptable_after_milestone,),
            TemporalPathEvaluation::NotAuthorized {
                step: 0,
                decision: AuthorizationDecision::Deny,
            }
        );
    }

    #[test]
    fn incorrect_target_is_rejected() {
        let classical = config(1);
        let hybrid = config(2);
        let pq = config(3);

        let steps = [transition(classical, hybrid, AuthorizationDecision::Allow)];

        assert_eq!(
            evaluate_temporal_path(classical, pq, &steps, milestone, acceptable_after_milestone,),
            TemporalPathEvaluation::TargetMismatch
        );
    }

    #[test]
    fn empty_path_at_target_is_valid() {
        let classical = config(1);

        assert_eq!(
            evaluate_temporal_path(
                classical,
                classical,
                &[],
                milestone,
                acceptable_after_milestone,
            ),
            TemporalPathEvaluation::Complete
        );
    }
}
