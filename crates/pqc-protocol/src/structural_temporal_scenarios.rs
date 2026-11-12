//! Test-only composition of bound structural evidence and temporal continuity.
//!
//! All security assessments, threat phases, and execution contexts are
//! illustrative caller-supplied inputs. No result authorizes deployment.

use crate::{
    evaluate_aggregate_admissibility, evaluate_continuous_migration,
    evaluate_four_predicate_admissibility, evaluate_security_continuity, ActiveConfiguration,
    AggregateAdmissibilityEvaluation, AlgorithmId, AssessedExecutionContext, AuthorizationDecision,
    ConfigurationIdentity, ContextRevision, ContinuitySegment, ContinuousMigrationEvaluation,
    CryptographicSystemState, CryptographicTransition, CurrentExecutionContext,
    DeploymentStateIdentity, EvidenceApplicability, EvidenceScope, EvidenceStateIdentity,
    ExecutionRevisions, FourPredicateComponents, FourPredicateEvaluation, ImplementationRevision,
    IndependentPathSafety, IntegratedPathEvaluation, IntegratedTransitionStep, MigrationDuration,
    MigrationFeasibility, MigrationTiming, MigrationTimingEvidence, ModelTime,
    OperationalReadiness, ParameterSetId, PolicyAssessment, PolicyStateIdentity, ProtectionHorizon,
    ProviderId, SecurityAcceptability, SecurityAssessment, SecurityAssessmentBinding,
    SecurityContinuityEvaluation, SecurityRequirementId, SystemTransitionBinding, ThreatPhase,
    ThreatPhaseId, ThreatSchedule, TimeInterval, TransitionAssessments, TransitionInterval,
};

fn t(value: u64) -> ModelTime {
    ModelTime::new(value)
}

fn configuration(revision: u64) -> ConfigurationIdentity {
    ConfigurationIdentity::new(
        AlgorithmId::new(1),
        ParameterSetId::new(768),
        ProviderId::new(2),
        ImplementationRevision::new(revision),
    )
}

fn state(revision: u64) -> CryptographicSystemState {
    CryptographicSystemState::new(
        configuration(revision),
        PolicyStateIdentity::new(10),
        EvidenceStateIdentity::new(20),
        DeploymentStateIdentity::new(30),
    )
}

fn bound_step() -> IntegratedTransitionStep {
    let source = state(1);
    let destination = state(2);
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

fn structural_evaluation(step: IntegratedTransitionStep) -> AggregateAdmissibilityEvaluation {
    evaluate_aggregate_admissibility(state(1), state(2), &[step], |_| true)
}

fn independently_derived_admissibility(
    aggregate: AggregateAdmissibilityEvaluation,
) -> FourPredicateEvaluation {
    let components = match aggregate {
        AggregateAdmissibilityEvaluation::Complete {
            decision: AuthorizationDecision::Allow,
            components,
        } => components,
        other => panic!("expected complete structural admissibility: {other:?}"),
    };

    assert_eq!(components.authorized, AuthorizationDecision::Allow);
    assert_eq!(components.acceptable, AuthorizationDecision::Allow);
    assert_eq!(components.feasible, AuthorizationDecision::Allow);
    assert_eq!(components.path_safe, crate::SystemPathEvaluation::Complete);

    let result = evaluate_four_predicate_admissibility(FourPredicateComponents {
        authorized: components.authorized,
        acceptable: components.acceptable,
        path_safe: IndependentPathSafety::Safe,
        feasible: components.feasible,
    });

    assert_eq!(
        result,
        FourPredicateEvaluation::Evaluated(AuthorizationDecision::Allow)
    );
    result
}

fn phase(start: u64, end: u64, threat: u64) -> ThreatPhase {
    ThreatPhase::new(
        TimeInterval::new(t(start), t(end)).unwrap(),
        ThreatPhaseId::new(threat),
    )
}

fn assessment(revision: u64, threat: u64, outcome: SecurityAcceptability) -> SecurityAssessment {
    SecurityAssessment::new(
        SecurityAssessmentBinding::new(
            configuration(revision),
            ThreatPhaseId::new(threat),
            SecurityRequirementId::new(1),
        ),
        outcome,
    )
}

fn evaluate_cutover(
    cutover: u64,
    admissibility: FourPredicateEvaluation,
) -> ContinuousMigrationEvaluation {
    let horizon = ProtectionHorizon::new(t(0), t(10)).unwrap();
    let phases = [phase(0, 4, 1), phase(4, 10, 2)];
    let schedule = ThreatSchedule::new(&phases, horizon).unwrap();
    let transition = TransitionInterval::new(horizon, t(cutover)).unwrap();

    let timely = [
        assessment(1, 1, SecurityAcceptability::Acceptable),
        assessment(2, 2, SecurityAcceptability::Acceptable),
    ];

    let delayed = [
        assessment(1, 1, SecurityAcceptability::Acceptable),
        assessment(1, 2, SecurityAcceptability::Unacceptable),
        assessment(2, 2, SecurityAcceptability::Acceptable),
    ];

    let assessments: &[SecurityAssessment] = if cutover <= 4 { &timely } else { &delayed };

    let continuity = evaluate_security_continuity(
        &schedule,
        transition,
        configuration(1),
        configuration(2),
        SecurityRequirementId::new(1),
        assessments,
    );

    let timing = MigrationTimingEvidence::Known(
        MigrationTiming::new(t(0), t(1), MigrationDuration::new(2)).unwrap(),
    );

    evaluate_continuous_migration(continuity, transition, timing, t(8), admissibility)
}

#[test]
fn timely_cutover_is_structurally_and_temporally_acceptable() {
    let admissibility = independently_derived_admissibility(structural_evaluation(bound_step()));

    match evaluate_cutover(4, admissibility) {
        ContinuousMigrationEvaluation::Evaluated {
            decision,
            diagnostics,
        } => {
            assert_eq!(decision, AuthorizationDecision::Allow);
            assert_eq!(diagnostics.admissibility, AuthorizationDecision::Allow);
            assert_eq!(
                diagnostics.continuity,
                SecurityContinuityEvaluation::Continuous
            );
            assert_eq!(
                diagnostics.cutover_feasibility,
                MigrationFeasibility::Feasible
            );
            println!("INTEGRATED_TIMELY_STATUS=PASS");
        }
        other => panic!("unexpected timely outcome: {other:?}"),
    }
}

#[test]
fn delayed_cutover_is_structurally_admissible_but_discontinuous() {
    let admissibility = independently_derived_admissibility(structural_evaluation(bound_step()));

    match evaluate_cutover(6, admissibility) {
        ContinuousMigrationEvaluation::Evaluated {
            decision,
            diagnostics,
        } => {
            assert_eq!(decision, AuthorizationDecision::Deny);
            assert_eq!(diagnostics.admissibility, AuthorizationDecision::Allow);
            assert_eq!(
                diagnostics.cutover_feasibility,
                MigrationFeasibility::Feasible
            );
            assert_eq!(
                diagnostics.deadline_feasibility,
                MigrationFeasibility::Feasible
            );
            assert_eq!(
                diagnostics.continuity,
                SecurityContinuityEvaluation::Discontinuous(ContinuitySegment {
                    phase: 1,
                    active: ActiveConfiguration::Source,
                    interval: TimeInterval::new(t(4), t(6)).unwrap(),
                })
            );
            println!("INTEGRATED_DELAYED_STATUS=PASS");
            println!("EXPOSURE_INTERVAL=[4,6)");
        }
        other => panic!("unexpected delayed outcome: {other:?}"),
    }
}

#[test]
fn stale_structural_context_cannot_establish_admissibility() {
    let mut step = bound_step();
    step.current_context.revisions.policy = ContextRevision::new(2);

    assert!(matches!(
        structural_evaluation(step),
        AggregateAdmissibilityEvaluation::InvalidTrace {
            result: IntegratedPathEvaluation::RevalidationFailure { step: 0, .. }
        }
    ));

    println!("INTEGRATED_STALE_CONTEXT_STATUS=PASS");
}

#[cfg(test)]
mod organizational_case_study;
