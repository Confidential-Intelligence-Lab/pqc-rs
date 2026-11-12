//! Advisory evaluation of bound and revalidated system-state traces.
//!
//! All state identities, assessments, revisions, and invariants are
//! supplied externally. This evaluator does not authenticate observations,
//! enforce decisions, or execute cryptographic transitions.

use crate::{
    evaluate_system_transition_binding, revalidate_transition, AssessedExecutionContext,
    AuthorizationDecision, CryptographicSystemState, CurrentExecutionContext, RevalidationResult,
    SystemBindingEvaluation, SystemTransitionBinding, TransitionAssessments,
};

/// One proposed step with its own assessment and execution contexts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegratedTransitionStep {
    /// Binding recorded when the step was assessed.
    pub assessed_binding: SystemTransitionBinding,
    /// Binding of the currently requested step.
    pub requested_binding: SystemTransitionBinding,
    /// Execution context recorded at assessment.
    pub assessed_context: AssessedExecutionContext,
    /// Execution context supplied for revalidation.
    pub current_context: CurrentExecutionContext,
    /// Current assessments for this step.
    pub assessments: TransitionAssessments,
}

/// Diagnostic outcome of evaluating an integrated trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegratedPathEvaluation {
    /// All represented steps passed the advisory checks.
    Complete,
    /// The initial state violates the supplied invariant.
    InitialInvariantViolation,
    /// A step does not begin at the preceding state.
    Disconnected {
        /// Zero-based index of the step.
        step: usize,
    },
    /// An execution context is inconsistent with its associated binding.
    ExecutionContextMismatch {
        /// Zero-based index of the step.
        step: usize,
    },
    /// Full-state binding or configuration consistency failed.
    BindingFailure {
        /// Zero-based index of the step.
        step: usize,
        /// Exact binding diagnostic.
        result: SystemBindingEvaluation,
    },
    /// Execution-time revalidation failed.
    RevalidationFailure {
        /// Zero-based index of the step.
        step: usize,
        /// Exact revalidation diagnostic.
        result: RevalidationResult,
    },
    /// Current assessments did not yield affirmative authorization.
    NotAuthorized {
        /// Zero-based index of the step.
        step: usize,
        /// Derived advisory decision.
        decision: AuthorizationDecision,
    },
    /// A represented destination violates the supplied invariant.
    InvariantViolation {
        /// Zero-based index of the step.
        step: usize,
    },
    /// The final represented state differs from the target.
    TargetMismatch,
}

/// Evaluate a complete represented trace without allocation.
///
/// Each step's authorization is derived from its assessments. Both
/// execution contexts must describe their corresponding bindings.
/// The invariant is checked at the initial state and every represented
/// destination, not at unrepresented states within an operation.
///
/// An empty trace completes only when the initial state satisfies
/// the invariant and equals the requested target.
pub fn evaluate_integrated_transition_path<F>(
    initial: CryptographicSystemState,
    target: CryptographicSystemState,
    steps: &[IntegratedTransitionStep],
    invariant: F,
) -> IntegratedPathEvaluation
where
    F: Fn(CryptographicSystemState) -> bool,
{
    if !invariant(initial) {
        return IntegratedPathEvaluation::InitialInvariantViolation;
    }

    let mut current = initial;

    for (index, step) in steps.iter().enumerate() {
        let requested = step.requested_binding;

        if requested.source != current {
            return IntegratedPathEvaluation::Disconnected { step: index };
        }

        if step.assessed_context.transition != step.assessed_binding.transition
            || step.current_context.transition != requested.transition
        {
            return IntegratedPathEvaluation::ExecutionContextMismatch { step: index };
        }

        let binding =
            evaluate_system_transition_binding(step.assessed_binding, requested, step.assessments);

        let binding_decision = match binding {
            SystemBindingEvaluation::Evaluated(decision) => decision,
            failure => {
                return IntegratedPathEvaluation::BindingFailure {
                    step: index,
                    result: failure,
                };
            }
        };

        let revalidation = revalidate_transition(
            step.assessed_context,
            step.current_context,
            step.assessments,
        );

        let revalidated_decision = match revalidation {
            RevalidationResult::Evaluated(decision) => decision,
            failure => {
                return IntegratedPathEvaluation::RevalidationFailure {
                    step: index,
                    result: failure,
                };
            }
        };

        // Both evaluators use the same R7 authorization semantics.
        // This guard prevents divergent decisions from being accepted.
        if binding_decision != revalidated_decision {
            return IntegratedPathEvaluation::NotAuthorized {
                step: index,
                decision: AuthorizationDecision::Unknown,
            };
        }

        if revalidated_decision != AuthorizationDecision::Allow {
            return IntegratedPathEvaluation::NotAuthorized {
                step: index,
                decision: revalidated_decision,
            };
        }

        if !invariant(requested.destination) {
            return IntegratedPathEvaluation::InvariantViolation { step: index };
        }

        current = requested.destination;
    }

    if current != target {
        return IntegratedPathEvaluation::TargetMismatch;
    }

    IntegratedPathEvaluation::Complete
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AlgorithmId, ConfigurationIdentity, ContextRevision, CryptographicTransition,
        DeploymentStateIdentity, EvidenceApplicability, EvidenceScope, EvidenceStateIdentity,
        ExecutionRevisions, ImplementationRevision, OperationalReadiness, ParameterSetId,
        PolicyAssessment, PolicyStateIdentity, ProviderId,
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
    fn fully_bound_trace_completes() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let steps = [step(a, b), step(b, c)];
        assert_eq!(
            evaluate_integrated_transition_path(a, c, &steps, |_| true),
            IntegratedPathEvaluation::Complete
        );
    }

    #[test]
    fn unsafe_intermediate_state_is_rejected() {
        let a = state(1, 10);
        let b = state(2, 99);
        let c = state(3, 12);
        let steps = [step(a, b), step(b, c)];
        assert_eq!(
            evaluate_integrated_transition_path(a, c, &steps, |s| s.policy().value() != 99),
            IntegratedPathEvaluation::InvariantViolation { step: 0 }
        );
    }

    #[test]
    fn changed_policy_identity_rejects_reuse() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut s = step(a, b);
        s.requested_binding.destination = state(2, 99);
        assert_eq!(
            evaluate_integrated_transition_path(a, state(2, 99), &[s], |_| true),
            IntegratedPathEvaluation::BindingFailure {
                step: 0,
                result: SystemBindingEvaluation::AssessmentBindingMismatch,
            }
        );
    }

    #[test]
    fn stale_revision_is_rejected() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut s = step(a, b);
        s.current_context.revisions.policy = ContextRevision::new(2);
        assert_eq!(
            evaluate_integrated_transition_path(a, b, &[s], |_| true),
            IntegratedPathEvaluation::RevalidationFailure {
                step: 0,
                result: RevalidationResult::StaleContext,
            }
        );
    }

    #[test]
    fn caller_cannot_force_allow_over_denial() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut s = step(a, b);
        s.assessments.transition_policy = PolicyAssessment::Prohibited;
        assert_eq!(
            evaluate_integrated_transition_path(a, b, &[s], |_| true),
            IntegratedPathEvaluation::NotAuthorized {
                step: 0,
                decision: AuthorizationDecision::Deny,
            }
        );
    }

    #[test]
    fn inconsistent_execution_context_is_rejected() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut s = step(a, b);
        s.current_context.transition = CryptographicTransition::new(
            a.configuration(),
            b.configuration(),
            EvidenceScope::Decapsulation,
        );
        assert_eq!(
            evaluate_integrated_transition_path(a, b, &[s], |_| true),
            IntegratedPathEvaluation::ExecutionContextMismatch { step: 0 }
        );
    }

    #[test]
    fn disconnected_trace_is_rejected() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        assert_eq!(
            evaluate_integrated_transition_path(a, c, &[step(b, c)], |_| true),
            IntegratedPathEvaluation::Disconnected { step: 0 }
        );
    }

    #[test]
    fn target_mismatch_is_rejected() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        assert_eq!(
            evaluate_integrated_transition_path(a, c, &[step(a, b)], |_| true),
            IntegratedPathEvaluation::TargetMismatch
        );
    }

    #[test]
    fn empty_trace_requires_matching_target() {
        let a = state(1, 10);
        let b = state(2, 11);
        assert_eq!(
            evaluate_integrated_transition_path(a, a, &[], |_| true),
            IntegratedPathEvaluation::Complete
        );
        assert_eq!(
            evaluate_integrated_transition_path(a, b, &[], |_| true),
            IntegratedPathEvaluation::TargetMismatch
        );
    }

    #[test]
    fn initial_invariant_is_checked() {
        let a = state(1, 99);
        assert_eq!(
            evaluate_integrated_transition_path(a, a, &[], |s| s.policy().value() != 99),
            IntegratedPathEvaluation::InitialInvariantViolation
        );
    }
}
