//! Trace-wide advisory admissibility of proposed cryptographic changes.
//!
//! Independent structural safety and every represented transition are
//! evaluated without first-failure authorization short-circuiting.
//! Inputs are caller-supplied and unauthenticated. No transition executes.

use crate::{
    evaluate_admissibility_components, evaluate_four_predicate_admissibility,
    evaluate_independent_trace_diagnostics, AdmissibilityComponentEvaluation,
    AuthorizationDecision, CryptographicSystemState, FourPredicateComponents,
    FourPredicateEvaluation, IndependentPathSafety, IntegratedTransitionStep, StepDiagnostic,
    SystemPathEvaluation, TraceDiagnosticEvaluation,
};

/// Summary of the complete proposed trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceWideSummary {
    /// Advisory aggregation of available step decisions.
    ///
    /// This field never constitutes execution authorization.
    pub decision: AuthorizationDecision,
    /// Independent represented-path structural safety.
    pub path_safety: IndependentPathSafety,
    /// Number of proposed transitions diagnosed.
    pub evaluated_steps: usize,
    /// Number of steps without a completed, consistent diagnostic evaluation.
    pub diagnostic_failures: usize,
    /// Number of steps with conflicting completed decision evaluations.
    pub decision_inconsistencies: usize,
}

/// Result of trace-wide advisory evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceWideEvaluation {
    /// A trace with no proposed transitions.
    EmptyTrace,
    /// The supplied diagnostic buffer was insufficient.
    InsufficientCapacity {
        /// Number of diagnostic entries required.
        required: usize,
        /// Number of diagnostic entries supplied.
        available: usize,
    },
    /// Every step was diagnosed and the represented path is safe.
    Evaluated(TraceWideSummary),
    /// The represented path is structurally invalid.
    ///
    /// The summary retains independent step-level information.
    InvalidPath(TraceWideSummary),
}

/// Four-valued conjunction, with denial taking precedence.
fn combine(current: AuthorizationDecision, next: AuthorizationDecision) -> AuthorizationDecision {
    use AuthorizationDecision::{Allow, Defer, Deny, Unknown};

    if current == Deny || next == Deny {
        Deny
    } else if current == Unknown || next == Unknown {
        Unknown
    } else if current == Defer || next == Defer {
        Defer
    } else {
        Allow
    }
}

/// Conservatively reconcile independently completed decisions.
///
/// A denial from either evaluation is retained. Other disagreements
/// resolve using the established four-valued precedence.
fn reconcile_decisions(
    derived: AuthorizationDecision,
    observed: AuthorizationDecision,
) -> AuthorizationDecision {
    combine(derived, observed)
}

/// Evaluate a complete proposed trace using caller-provided storage.
///
/// Every step is diagnosed, including those following a denial or
/// structural failure. The diagnostic buffer must hold all steps.
///
/// The aggregate advisory decision is derived from the four
/// predicates, using independent path safety. A failed binding,
/// inconsistent assessment, or failed revalidation contributes
/// `Unknown` rather than an affirmative decision.
///
/// The result never authenticates inputs, authorizes execution,
/// or establishes safety of unrepresented intermediate states.
pub fn evaluate_trace_wide_admissibility<F>(
    initial: CryptographicSystemState,
    target: CryptographicSystemState,
    steps: &[IntegratedTransitionStep],
    diagnostics: &mut [StepDiagnostic],
    invariant: F,
) -> TraceWideEvaluation
where
    F: Fn(CryptographicSystemState) -> bool,
{
    if steps.is_empty() {
        return TraceWideEvaluation::EmptyTrace;
    }

    let trace =
        evaluate_independent_trace_diagnostics(initial, target, steps, diagnostics, invariant);

    let summary = match trace {
        TraceDiagnosticEvaluation::InsufficientCapacity {
            required,
            available,
        } => {
            return TraceWideEvaluation::InsufficientCapacity {
                required,
                available,
            };
        }
        TraceDiagnosticEvaluation::Complete(summary) => summary,
    };

    let mut decision = AuthorizationDecision::Allow;
    let mut diagnostic_failures = 0;
    let mut decision_inconsistencies = 0;

    for (index, step) in steps.iter().enumerate() {
        let step_decision = match diagnostics[index] {
            StepDiagnostic::Evaluated(authorization) => {
                let components = evaluate_admissibility_components(
                    step.requested_binding.transition,
                    step.assessments,
                    SystemPathEvaluation::Complete,
                );

                match components {
                    AdmissibilityComponentEvaluation::Evaluated(c) => {
                        // Per-step component evaluation is structurally
                        // independent of the complete trace path.
                        let four = FourPredicateComponents {
                            authorized: c.authorized,
                            acceptable: c.acceptable,
                            path_safe: IndependentPathSafety::Safe,
                            feasible: c.feasible,
                        };

                        match evaluate_four_predicate_admissibility(four) {
                            FourPredicateEvaluation::Evaluated(value) => {
                                // An inconsistent derived decision must
                                // never become affirmative.
                                if value != authorization {
                                    decision_inconsistencies += 1;
                                }
                                reconcile_decisions(value, authorization)
                            }
                            FourPredicateEvaluation::InvalidPath(_) => {
                                AuthorizationDecision::Unknown
                            }
                        }
                    }
                    AdmissibilityComponentEvaluation::TransitionMismatch => {
                        diagnostic_failures += 1;
                        AuthorizationDecision::Unknown
                    }
                }
            }
            _ => {
                diagnostic_failures += 1;
                AuthorizationDecision::Unknown
            }
        };

        decision = combine(decision, step_decision);
    }

    let result = TraceWideSummary {
        decision,
        path_safety: summary.path_safety,
        evaluated_steps: summary.evaluated_steps,
        diagnostic_failures,
        decision_inconsistencies,
    };

    if summary.path_safety == IndependentPathSafety::Safe {
        TraceWideEvaluation::Evaluated(result)
    } else {
        TraceWideEvaluation::InvalidPath(result)
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

    fn buffer() -> [StepDiagnostic; 3] {
        [StepDiagnostic::ExecutionContextMismatch; 3]
    }

    #[test]
    fn all_permitted_steps_allow() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let mut diagnostics = buffer();

        let result = evaluate_trace_wide_admissibility(
            a,
            c,
            &[step(a, b), step(b, c)],
            &mut diagnostics,
            |_| true,
        );

        assert!(matches!(
            result,
            TraceWideEvaluation::Evaluated(TraceWideSummary {
                decision: AuthorizationDecision::Allow,
                evaluated_steps: 2,
                diagnostic_failures: 0,
                ..
            })
        ));
    }

    #[test]
    fn later_denial_is_not_skipped() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let mut second = step(b, c);
        second.assessments.transition_policy = PolicyAssessment::Prohibited;
        let mut diagnostics = buffer();

        let result = evaluate_trace_wide_admissibility(
            a,
            c,
            &[step(a, b), second],
            &mut diagnostics,
            |_| true,
        );

        assert!(matches!(
            result,
            TraceWideEvaluation::Evaluated(TraceWideSummary {
                decision: AuthorizationDecision::Deny,
                evaluated_steps: 2,
                ..
            })
        ));
        assert_eq!(
            diagnostics[1],
            StepDiagnostic::Evaluated(AuthorizationDecision::Deny)
        );
    }

    #[test]
    fn earlier_denial_does_not_hide_later_step() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let mut first = step(a, b);
        first.assessments.transition_policy = PolicyAssessment::Prohibited;
        let mut diagnostics = buffer();

        let result =
            evaluate_trace_wide_admissibility(a, c, &[first, step(b, c)], &mut diagnostics, |_| {
                true
            });

        assert!(matches!(
            result,
            TraceWideEvaluation::Evaluated(TraceWideSummary {
                decision: AuthorizationDecision::Deny,
                evaluated_steps: 2,
                ..
            })
        ));
        assert_eq!(
            diagnostics[1],
            StepDiagnostic::Evaluated(AuthorizationDecision::Allow)
        );
    }

    #[test]
    fn denial_and_unsafe_path_are_both_preserved() {
        let a = state(1, 10);
        let b = state(2, 99);
        let c = state(3, 12);
        let mut first = step(a, b);
        first.assessments.transition_policy = PolicyAssessment::Prohibited;
        let mut diagnostics = buffer();

        let result =
            evaluate_trace_wide_admissibility(a, c, &[first, step(b, c)], &mut diagnostics, |s| {
                s.policy().value() != 99
            });

        assert!(matches!(
            result,
            TraceWideEvaluation::InvalidPath(TraceWideSummary {
                decision: AuthorizationDecision::Deny,
                path_safety: IndependentPathSafety::InvariantViolation { step: 0 },
                evaluated_steps: 2,
                ..
            })
        ));
    }

    #[test]
    fn missing_evidence_defers() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut s = step(a, b);
        s.assessments.destination_evidence = EvidenceApplicability::Missing;
        let mut diagnostics = buffer();

        assert!(matches!(
            evaluate_trace_wide_admissibility(a, b, &[s], &mut diagnostics, |_| true),
            TraceWideEvaluation::Evaluated(TraceWideSummary {
                decision: AuthorizationDecision::Defer,
                ..
            })
        ));
    }

    #[test]
    fn stale_context_is_not_allowed() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut s = step(a, b);
        s.current_context.revisions.policy = ContextRevision::new(2);
        let mut diagnostics = buffer();

        assert!(matches!(
            evaluate_trace_wide_admissibility(a, b, &[s], &mut diagnostics, |_| true),
            TraceWideEvaluation::Evaluated(TraceWideSummary {
                decision: AuthorizationDecision::Unknown,
                diagnostic_failures: 1,
                ..
            })
        ));
    }

    #[test]
    fn disconnected_path_is_invalid() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);
        let mut diagnostics = buffer();

        assert!(matches!(
            evaluate_trace_wide_admissibility(
                a,
                c,
                &[step(a, b), step(a, c)],
                &mut diagnostics,
                |_| true,
            ),
            TraceWideEvaluation::InvalidPath(TraceWideSummary {
                path_safety: IndependentPathSafety::Disconnected { step: 1 },
                evaluated_steps: 2,
                ..
            })
        ));
    }

    #[test]
    fn insufficient_buffer_writes_nothing() {
        let a = state(1, 10);
        let b = state(2, 11);
        let mut diagnostics = [];

        assert_eq!(
            evaluate_trace_wide_admissibility(a, b, &[step(a, b)], &mut diagnostics, |_| true),
            TraceWideEvaluation::InsufficientCapacity {
                required: 1,
                available: 0,
            }
        );
    }

    #[test]
    fn empty_trace_is_distinct() {
        let a = state(1, 10);
        let mut diagnostics = buffer();

        assert_eq!(
            evaluate_trace_wide_admissibility(a, a, &[], &mut diagnostics, |_| true),
            TraceWideEvaluation::EmptyTrace
        );
    }

    #[test]
    fn reconciliation_preserves_derived_denial() {
        assert_eq!(
            reconcile_decisions(AuthorizationDecision::Deny, AuthorizationDecision::Allow,),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn reconciliation_preserves_observed_denial() {
        assert_eq!(
            reconcile_decisions(AuthorizationDecision::Allow, AuthorizationDecision::Deny,),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn reconciliation_respects_unknown_over_defer() {
        assert_eq!(
            reconcile_decisions(AuthorizationDecision::Unknown, AuthorizationDecision::Defer,),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn unknown_and_defer_precedence() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);

        let mut first = step(a, b);
        first.assessments.readiness = OperationalReadiness::Pending;

        let mut second = step(b, c);
        second.assessments.readiness = OperationalReadiness::Unknown;

        let mut diagnostics = buffer();

        assert!(matches!(
            evaluate_trace_wide_admissibility(a, c, &[first, second], &mut diagnostics, |_| true,),
            TraceWideEvaluation::Evaluated(TraceWideSummary {
                decision: AuthorizationDecision::Unknown,
                ..
            })
        ));
    }
}
