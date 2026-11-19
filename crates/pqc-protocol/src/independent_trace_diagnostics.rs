//! Independent diagnostics for proposed cryptographic transition traces.
//!
//! Structural path safety and per-step authorization are evaluated
//! independently. All identities, assessments, revisions, and invariants
//! are caller-supplied. No transition is executed or enforced.

use crate::{
    evaluate_system_transition_binding, revalidate_transition, AuthorizationDecision,
    CryptographicSystemState, IndependentPathSafety, IndependentPathStep, IntegratedTransitionStep,
    RevalidationResult, SystemBindingEvaluation,
};

/// Diagnostic outcome for one proposed transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepDiagnostic {
    /// The execution context does not describe its associated binding.
    ExecutionContextMismatch,
    /// The assessed and requested full-state bindings are inconsistent.
    BindingFailure(SystemBindingEvaluation),
    /// The supplied assessments concern a different transition.
    ///
    /// The transition identity includes the cryptographic operation.
    AssessmentTransitionMismatch,
    /// The execution context could not be revalidated.
    RevalidationFailure(RevalidationResult),
    /// Binding and revalidation completed with this advisory decision.
    Evaluated(AuthorizationDecision),
}

/// Summary of independently evaluated proposed transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceDiagnosticSummary {
    /// Structural safety of the complete represented path.
    pub path_safety: IndependentPathSafety,
    /// Number of proposed transitions evaluated.
    pub evaluated_steps: usize,
}

/// Outcome of trace diagnostic collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceDiagnosticEvaluation {
    /// The caller-provided buffer cannot hold every step diagnostic.
    ///
    /// No diagnostic entries are written when capacity is insufficient.
    InsufficientCapacity {
        /// Required number of diagnostic entries.
        required: usize,
        /// Available number of diagnostic entries.
        available: usize,
    },
    /// Every proposed transition has a corresponding diagnostic.
    Complete(TraceDiagnosticSummary),
}

/// Evaluate one proposed transition without executing it.
///
/// Assessment-binding and revalidation failures remain distinct from
/// four-valued advisory authorization decisions.
fn evaluate_step(step: IntegratedTransitionStep) -> StepDiagnostic {
    let requested = step.requested_binding;

    if step.assessed_context.transition != step.assessed_binding.transition
        || step.current_context.transition != requested.transition
    {
        return StepDiagnostic::ExecutionContextMismatch;
    }

    // Assessment identity includes the requested operation.
    // Reject mismatches before deriving advisory authorization.
    if step.assessments.assessed_transition != requested.transition {
        return StepDiagnostic::AssessmentTransitionMismatch;
    }

    let binding =
        evaluate_system_transition_binding(step.assessed_binding, requested, step.assessments);

    let binding_decision = match binding {
        SystemBindingEvaluation::Evaluated(decision) => decision,
        failure => return StepDiagnostic::BindingFailure(failure),
    };

    let revalidation = revalidate_transition(
        step.assessed_context,
        step.current_context,
        step.assessments,
    );

    let revalidated_decision = match revalidation {
        RevalidationResult::Evaluated(decision) => decision,
        failure => return StepDiagnostic::RevalidationFailure(failure),
    };

    // Both checks must agree on the advisory authorization decision.
    if binding_decision != revalidated_decision {
        return StepDiagnostic::Evaluated(AuthorizationDecision::Unknown);
    }

    StepDiagnostic::Evaluated(revalidated_decision)
}

/// Evaluate structural safety and all proposed steps independently.
///
/// The supplied diagnostic buffer must contain at least `steps.len()`
/// entries. If it is too small, no diagnostics are written and the
/// invariant is not evaluated.
///
/// Only the first `steps.len()` entries are written; any remaining
/// buffer entries are preserved.
///
/// Structural safety covers represented states and their continuity.
/// Step diagnostics cover binding, revalidation, and advisory
/// authorization. Neither result establishes execution authorization,
/// input authenticity, or safety of unrepresented intermediate states.
pub fn evaluate_independent_trace_diagnostics<F>(
    initial: CryptographicSystemState,
    target: CryptographicSystemState,
    steps: &[IntegratedTransitionStep],
    diagnostics: &mut [StepDiagnostic],
    invariant: F,
) -> TraceDiagnosticEvaluation
where
    F: Fn(CryptographicSystemState) -> bool,
{
    if diagnostics.len() < steps.len() {
        return TraceDiagnosticEvaluation::InsufficientCapacity {
            required: steps.len(),
            available: diagnostics.len(),
        };
    }

    // Evaluate structural path safety without consuming authorization.
    //
    // Avoid allocating a temporary vector by implementing the same
    // independent structural checks directly over integrated bindings.
    // The public independent-path evaluator remains the reference API.
    let path_safety = {
        if !invariant(initial) {
            IndependentPathSafety::InitialInvariantViolation
        } else {
            let mut current = initial;
            let mut failure = None;

            for (index, step) in steps.iter().enumerate() {
                let IndependentPathStep {
                    source,
                    destination,
                } = IndependentPathStep {
                    source: step.requested_binding.source,
                    destination: step.requested_binding.destination,
                };

                if source != current {
                    failure = Some(IndependentPathSafety::Disconnected { step: index });
                    break;
                }

                if !invariant(destination) {
                    failure = Some(IndependentPathSafety::InvariantViolation { step: index });
                    break;
                }

                current = destination;
            }

            match failure {
                Some(result) => result,
                None if current != target => IndependentPathSafety::TargetMismatch,
                None => IndependentPathSafety::Safe,
            }
        }
    };

    for (output, step) in diagnostics.iter_mut().zip(steps.iter()) {
        *output = evaluate_step(*step);
    }

    TraceDiagnosticEvaluation::Complete(TraceDiagnosticSummary {
        path_safety,
        evaluated_steps: steps.len(),
    })
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

    fn empty() -> StepDiagnostic {
        StepDiagnostic::Evaluated(AuthorizationDecision::Unknown)
    }

    #[test]
    fn permitted_steps_are_all_evaluated() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let steps = [step(a, b), step(b, c)];
        let mut diagnostics = [empty(); 2];

        assert_eq!(
            evaluate_independent_trace_diagnostics(a, c, &steps, &mut diagnostics, |_| true,),
            TraceDiagnosticEvaluation::Complete(TraceDiagnosticSummary {
                path_safety: IndependentPathSafety::Safe,
                evaluated_steps: 2,
            })
        );

        assert_eq!(
            diagnostics,
            [
                StepDiagnostic::Evaluated(AuthorizationDecision::Allow),
                StepDiagnostic::Evaluated(AuthorizationDecision::Allow),
            ]
        );
    }

    #[test]
    fn denial_does_not_suppress_later_step() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let mut first = step(a, b);
        first.assessments.transition_policy = PolicyAssessment::Prohibited;
        let steps = [first, step(b, c)];
        let mut diagnostics = [empty(); 2];

        let result =
            evaluate_independent_trace_diagnostics(a, c, &steps, &mut diagnostics, |_| true);

        assert_eq!(
            result,
            TraceDiagnosticEvaluation::Complete(TraceDiagnosticSummary {
                path_safety: IndependentPathSafety::Safe,
                evaluated_steps: 2,
            })
        );
        assert_eq!(
            diagnostics,
            [
                StepDiagnostic::Evaluated(AuthorizationDecision::Deny),
                StepDiagnostic::Evaluated(AuthorizationDecision::Allow),
            ]
        );
    }

    #[test]
    fn denial_and_unsafe_destination_remain_visible() {
        let a = state(1, 10);
        let b = state(2, 99);
        let mut first = step(a, b);
        first.assessments.transition_policy = PolicyAssessment::Prohibited;
        let mut diagnostics = [empty(); 1];

        let result =
            evaluate_independent_trace_diagnostics(a, b, &[first], &mut diagnostics, |s| {
                s.policy().value() != 99
            });

        assert_eq!(
            result,
            TraceDiagnosticEvaluation::Complete(TraceDiagnosticSummary {
                path_safety: IndependentPathSafety::InvariantViolation { step: 0 },
                evaluated_steps: 1,
            })
        );
        assert_eq!(
            diagnostics[0],
            StepDiagnostic::Evaluated(AuthorizationDecision::Deny)
        );
    }

    #[test]
    fn stale_context_does_not_suppress_later_step() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let mut first = step(a, b);
        first.current_context.revisions.policy = ContextRevision::new(2);
        let steps = [first, step(b, c)];
        let mut diagnostics = [empty(); 2];

        let result =
            evaluate_independent_trace_diagnostics(a, c, &steps, &mut diagnostics, |_| true);

        assert!(matches!(result, TraceDiagnosticEvaluation::Complete(_)));
        assert_eq!(
            diagnostics[0],
            StepDiagnostic::RevalidationFailure(RevalidationResult::StaleContext)
        );
        assert_eq!(
            diagnostics[1],
            StepDiagnostic::Evaluated(AuthorizationDecision::Allow)
        );
    }

    #[test]
    fn full_state_binding_failure_is_retained() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut first = step(a, b);
        first.requested_binding.destination = state(2, 99);
        let mut diagnostics = [empty(); 1];

        let result = evaluate_independent_trace_diagnostics(
            a,
            state(2, 99),
            &[first],
            &mut diagnostics,
            |_| true,
        );

        assert!(matches!(result, TraceDiagnosticEvaluation::Complete(_)));
        assert_eq!(
            diagnostics[0],
            StepDiagnostic::BindingFailure(SystemBindingEvaluation::AssessmentBindingMismatch)
        );
    }

    #[test]
    fn disconnected_path_is_independent_of_step_authorization() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let steps = [step(b, c)];
        let mut diagnostics = [empty(); 1];

        let result =
            evaluate_independent_trace_diagnostics(a, c, &steps, &mut diagnostics, |_| true);

        assert_eq!(
            result,
            TraceDiagnosticEvaluation::Complete(TraceDiagnosticSummary {
                path_safety: IndependentPathSafety::Disconnected { step: 0 },
                evaluated_steps: 1,
            })
        );
        assert_eq!(
            diagnostics[0],
            StepDiagnostic::Evaluated(AuthorizationDecision::Allow)
        );
    }

    #[test]
    fn insufficient_capacity_does_not_write_diagnostics() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let steps = [step(a, b), step(b, c)];
        let mut diagnostics = [empty(); 1];
        let before = diagnostics;

        assert_eq!(
            evaluate_independent_trace_diagnostics(a, c, &steps, &mut diagnostics, |_| {
                panic!("invariant must not be evaluated")
            },),
            TraceDiagnosticEvaluation::InsufficientCapacity {
                required: 2,
                available: 1,
            }
        );
        assert_eq!(diagnostics, before);
    }

    #[test]
    fn unresolved_policy_remains_unknown() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut first = step(a, b);
        first.assessments.transition_policy = PolicyAssessment::Unknown;
        let mut diagnostics = [empty(); 1];

        let result =
            evaluate_independent_trace_diagnostics(a, b, &[first], &mut diagnostics, |_| true);

        assert!(matches!(result, TraceDiagnosticEvaluation::Complete(_)));
        assert_eq!(
            diagnostics[0],
            StepDiagnostic::Evaluated(AuthorizationDecision::Unknown)
        );
    }

    #[test]
    fn assessment_mismatch_precedes_full_state_binding_failure() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);

        let mut first = step(a, b);
        first.requested_binding.destination = state(2, 99);
        first.assessments.assessed_transition = CryptographicTransition::new(
            a.configuration(),
            c.configuration(),
            EvidenceScope::Encapsulation,
        );

        let mut diagnostics = [empty(); 1];

        let result = evaluate_independent_trace_diagnostics(
            a,
            state(2, 99),
            &[first],
            &mut diagnostics,
            |_| true,
        );

        assert!(matches!(result, TraceDiagnosticEvaluation::Complete(_)));
        assert_eq!(diagnostics[0], StepDiagnostic::AssessmentTransitionMismatch);
    }

    #[test]
    fn mismatched_assessment_destination_is_distinct() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let mut first = step(a, b);
        first.assessments.assessed_transition = CryptographicTransition::new(
            a.configuration(),
            c.configuration(),
            EvidenceScope::Encapsulation,
        );
        let mut diagnostics = [empty(); 1];

        let result =
            evaluate_independent_trace_diagnostics(a, b, &[first], &mut diagnostics, |_| true);

        assert!(matches!(result, TraceDiagnosticEvaluation::Complete(_)));
        assert_eq!(diagnostics[0], StepDiagnostic::AssessmentTransitionMismatch);
    }

    #[test]
    fn mismatched_operation_is_not_allowed() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut first = step(a, b);
        first.assessments.assessed_transition = CryptographicTransition::new(
            a.configuration(),
            b.configuration(),
            EvidenceScope::Decapsulation,
        );
        let mut diagnostics = [empty(); 1];

        let result =
            evaluate_independent_trace_diagnostics(a, b, &[first], &mut diagnostics, |_| true);

        assert!(matches!(result, TraceDiagnosticEvaluation::Complete(_)));
        assert_eq!(diagnostics[0], StepDiagnostic::AssessmentTransitionMismatch);
    }
}
