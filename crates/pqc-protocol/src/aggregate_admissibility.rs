//! Advisory aggregation of bound transition-trace admissibility.
//!
//! Evaluation uses caller-supplied assessments, context revisions, state
//! identities, and invariants. It does not authenticate those inputs,
//! enforce authorization, or execute a transition.

use crate::{
    evaluate_admissibility_components, evaluate_integrated_transition_path,
    AdmissibilityComponentEvaluation, AdmissibilityComponents, AuthorizationDecision,
    CryptographicSystemState, IntegratedPathEvaluation, IntegratedTransitionStep,
    SystemPathEvaluation,
};

/// Outcome of aggregate advisory admissibility evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateAdmissibilityEvaluation {
    /// A trace with no steps cannot establish transition admissibility.
    EmptyTrace,
    /// Structural or contextual failure prevents aggregation.
    InvalidTrace {
        /// Diagnostic from the integrated trace evaluator.
        result: IntegratedPathEvaluation,
    },
    /// Every represented step was evaluated and permitted.
    Complete {
        /// Aggregate advisory decision.
        decision: AuthorizationDecision,
        /// Components for the final represented transition.
        components: AdmissibilityComponents,
    },
    /// Evaluation stopped at the first non-affirmative step.
    ///
    /// The decision concerns this step, not the entire remaining trace.
    Partial {
        /// Zero-based index of the first non-affirmative step.
        step: usize,
        /// Aggregate advisory decision for this step.
        decision: AuthorizationDecision,
        /// Components for this step.
        components: AdmissibilityComponents,
    },
}

/// Combine component decisions using conservative four-valued semantics.
///
/// Known prohibition dominates unresolved information; unresolved
/// information dominates a pending prerequisite. `Allow` requires
/// every component to be affirmative.
pub fn combine_admissibility_components(
    components: AdmissibilityComponents,
) -> AuthorizationDecision {
    use AuthorizationDecision::{Allow, Defer, Deny, Unknown};

    let path = match components.path_safe {
        SystemPathEvaluation::Complete => Allow,
        SystemPathEvaluation::NotAuthorized { decision, .. } => decision,
        _ => Unknown,
    };

    let decisions = [
        components.authorized,
        components.acceptable,
        path,
        components.feasible,
        components.legacy_authorization,
    ];

    if decisions.contains(&Deny) {
        Deny
    } else if decisions.contains(&Unknown) {
        Unknown
    } else if decisions.contains(&Defer) {
        Defer
    } else {
        Allow
    }
}

/// Evaluate a supplied trace and aggregate its admissibility diagnostics.
///
/// A complete result covers all represented steps but exposes components
/// only for the final step; previous steps were required to yield `Allow`.
/// A partial result concerns only the first non-affirmative step.
/// Structural failures are never converted into authorization decisions.
///
/// The caller is responsible for the authenticity and currency of inputs.
/// No result constitutes an execution permit.
pub fn evaluate_aggregate_admissibility<F>(
    initial: CryptographicSystemState,
    target: CryptographicSystemState,
    steps: &[IntegratedTransitionStep],
    invariant: F,
) -> AggregateAdmissibilityEvaluation
where
    F: Fn(CryptographicSystemState) -> bool,
{
    if steps.is_empty() {
        return AggregateAdmissibilityEvaluation::EmptyTrace;
    }

    let trace = evaluate_integrated_transition_path(initial, target, steps, invariant);

    let (index, path_result, partial) = match trace {
        IntegratedPathEvaluation::Complete => {
            (steps.len() - 1, SystemPathEvaluation::Complete, false)
        }
        IntegratedPathEvaluation::NotAuthorized { step, decision } => (
            step,
            SystemPathEvaluation::NotAuthorized { step, decision },
            true,
        ),
        failure => {
            return AggregateAdmissibilityEvaluation::InvalidTrace { result: failure };
        }
    };

    let selected = &steps[index];
    let components = match evaluate_admissibility_components(
        selected.requested_binding.transition,
        selected.assessments,
        path_result,
    ) {
        AdmissibilityComponentEvaluation::Evaluated(components) => components,
        AdmissibilityComponentEvaluation::TransitionMismatch => {
            // The integrated evaluator already checks the same
            // transition-assessment consistency. This branch remains
            // conservative if the underlying API changes.
            return AggregateAdmissibilityEvaluation::InvalidTrace {
                result: IntegratedPathEvaluation::NotAuthorized {
                    step: index,
                    decision: AuthorizationDecision::Unknown,
                },
            };
        }
    };

    let decision = combine_admissibility_components(components);

    if partial {
        AggregateAdmissibilityEvaluation::Partial {
            step: index,
            decision,
            components,
        }
    } else {
        AggregateAdmissibilityEvaluation::Complete {
            decision,
            components,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AlgorithmId, AssessedExecutionContext, ConfigurationIdentity, ContextRevision,
        CryptographicTransition, CurrentExecutionContext, DeploymentStateIdentity,
        EvidenceApplicability, EvidenceScope, EvidenceStateIdentity, ExecutionRevisions,
        ImplementationRevision, OperationalReadiness, ParameterSetId, PolicyAssessment,
        PolicyStateIdentity, ProviderId, SystemTransitionBinding, TransitionAssessments,
    };

    fn state(provider: u32, policy: u64) -> CryptographicSystemState {
        CryptographicSystemState::new(
            ConfigurationIdentity::new(
                AlgorithmId::new(1),
                ParameterSetId::new(768),
                ProviderId::new(provider),
                ImplementationRevision::new(1),
            ),
            PolicyStateIdentity::new(policy),
            EvidenceStateIdentity::new(20),
            DeploymentStateIdentity::new(30),
        )
    }

    fn step(
        source: CryptographicSystemState,
        destination: CryptographicSystemState,
    ) -> IntegratedTransitionStep {
        let transition = CryptographicTransition::new(
            source.configuration(),
            destination.configuration(),
            EvidenceScope::Encapsulation,
        );
        let binding = SystemTransitionBinding {
            source,
            destination,
            transition,
        };
        let revisions = ExecutionRevisions {
            policy: ContextRevision::new(1),
            evidence: ContextRevision::new(1),
            deployment: ContextRevision::new(1),
            source_state: ContextRevision::new(1),
        };
        IntegratedTransitionStep {
            assessed_binding: binding,
            requested_binding: binding,
            assessed_context: AssessedExecutionContext {
                transition,
                revisions,
            },
            current_context: CurrentExecutionContext {
                transition,
                revisions,
            },
            assessments: TransitionAssessments {
                assessed_transition: transition,
                transition_policy: PolicyAssessment::Permitted,
                source_policy: PolicyAssessment::Permitted,
                destination_policy: PolicyAssessment::Permitted,
                destination_evidence: EvidenceApplicability::Applicable,
                readiness: OperationalReadiness::Ready,
            },
        }
    }

    #[test]
    fn permitted_trace_is_complete() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let result = evaluate_aggregate_admissibility(a, c, &[step(a, b), step(b, c)], |_| true);
        assert!(matches!(
            result,
            AggregateAdmissibilityEvaluation::Complete {
                decision: AuthorizationDecision::Allow,
                ..
            }
        ));
    }

    #[test]
    fn prohibited_first_step_is_partial_denial() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let mut first = step(a, b);
        first.assessments.transition_policy = PolicyAssessment::Prohibited;
        let result = evaluate_aggregate_admissibility(a, c, &[first, step(b, c)], |_| true);
        assert!(matches!(
            result,
            AggregateAdmissibilityEvaluation::Partial {
                step: 0,
                decision: AuthorizationDecision::Deny,
                ..
            }
        ));
    }

    #[test]
    fn missing_evidence_defers() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut s = step(a, b);
        s.assessments.destination_evidence = EvidenceApplicability::Missing;
        assert!(matches!(
            evaluate_aggregate_admissibility(a, b, &[s], |_| true),
            AggregateAdmissibilityEvaluation::Partial {
                step: 0,
                decision: AuthorizationDecision::Defer,
                ..
            }
        ));
    }

    #[test]
    fn unknown_readiness_is_unresolved() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut s = step(a, b);
        s.assessments.readiness = OperationalReadiness::Unknown;
        assert!(matches!(
            evaluate_aggregate_admissibility(a, b, &[s], |_| true),
            AggregateAdmissibilityEvaluation::Partial {
                decision: AuthorizationDecision::Unknown,
                ..
            }
        ));
    }

    #[test]
    fn stale_context_remains_structural_failure() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut s = step(a, b);
        s.current_context.revisions.policy = ContextRevision::new(2);
        assert!(matches!(
            evaluate_aggregate_admissibility(a, b, &[s], |_| true),
            AggregateAdmissibilityEvaluation::InvalidTrace {
                result: IntegratedPathEvaluation::RevalidationFailure { step: 0, .. }
            }
        ));
    }

    #[test]
    fn unsafe_intermediate_state_is_not_allowed() {
        let a = state(1, 10);
        let b = state(2, 99);
        let c = state(3, 12);
        assert!(matches!(
            evaluate_aggregate_admissibility(a, c, &[step(a, b), step(b, c)], |s| s
                .policy()
                .value()
                != 99,),
            AggregateAdmissibilityEvaluation::InvalidTrace {
                result: IntegratedPathEvaluation::InvariantViolation { step: 0 }
            }
        ));
    }

    #[test]
    fn empty_trace_is_not_transition_admissibility() {
        let a = state(1, 10);
        assert_eq!(
            evaluate_aggregate_admissibility(a, a, &[], |_| true),
            AggregateAdmissibilityEvaluation::EmptyTrace
        );
    }

    #[test]
    fn decision_precedence_preserves_known_denial() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut s = step(a, b);
        s.assessments.transition_policy = PolicyAssessment::Prohibited;
        s.assessments.readiness = OperationalReadiness::Unknown;
        assert!(matches!(
            evaluate_aggregate_admissibility(a, b, &[s], |_| true),
            AggregateAdmissibilityEvaluation::Partial {
                decision: AuthorizationDecision::Deny,
                ..
            }
        ));
    }
}
