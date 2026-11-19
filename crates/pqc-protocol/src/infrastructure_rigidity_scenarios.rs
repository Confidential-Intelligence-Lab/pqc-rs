//! Test-only infrastructure-rigidity scenarios.
//!
//! Candidate activation times are externally supplied assumptions.
//! No deployment scheduler, readiness probe, or activation mechanism
//! is implemented by these fixtures.

use crate::{
    evaluate_continuous_migration, evaluate_security_continuity, AlgorithmId,
    AuthorizationDecision, ConfigurationIdentity, ContinuousMigrationDiagnostics,
    ContinuousMigrationEvaluation, FourPredicateEvaluation, ImplementationRevision,
    MigrationDuration, MigrationFeasibility, MigrationTiming, MigrationTimingEvidence, ModelTime,
    ParameterSetId, ProtectionHorizon, ProviderId, SecurityAcceptability, SecurityAssessment,
    SecurityAssessmentBinding, SecurityContinuityEvaluation, SecurityRequirementId, ThreatPhase,
    ThreatPhaseId, ThreatSchedule, TimeInterval, TransitionInterval,
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

fn assessment(revision: u64) -> SecurityAssessment {
    SecurityAssessment::new(
        SecurityAssessmentBinding::new(
            configuration(revision),
            ThreatPhaseId::new(1),
            SecurityRequirementId::new(1),
        ),
        SecurityAcceptability::Acceptable,
    )
}

fn timing() -> MigrationTimingEvidence {
    MigrationTimingEvidence::Known(
        MigrationTiming::new(t(0), t(1), MigrationDuration::new(2)).unwrap(),
    )
}

fn evaluate_candidate(cutover: u64) -> (AuthorizationDecision, ContinuousMigrationDiagnostics) {
    let protection = ProtectionHorizon::new(t(0), t(12)).unwrap();
    let transition = TransitionInterval::new(protection, t(cutover)).unwrap();
    let phases = [ThreatPhase::new(
        TimeInterval::new(t(0), t(12)).unwrap(),
        ThreatPhaseId::new(1),
    )];
    let schedule = ThreatSchedule::new(&phases, protection).unwrap();
    let assessments = [assessment(1), assessment(2)];

    let continuity = evaluate_security_continuity(
        &schedule,
        transition,
        configuration(1),
        configuration(2),
        SecurityRequirementId::new(1),
        &assessments,
    );

    assert_eq!(continuity, Ok(SecurityContinuityEvaluation::Continuous));

    match evaluate_continuous_migration(
        continuity,
        transition,
        timing(),
        t(8),
        FourPredicateEvaluation::Evaluated(AuthorizationDecision::Allow),
    ) {
        ContinuousMigrationEvaluation::Evaluated {
            decision,
            diagnostics,
        } => (decision, diagnostics),
        ContinuousMigrationEvaluation::Invalid(error) => {
            panic!("unexpected invalid candidate: {error:?}")
        }
    }
}

/// Test-local handling of a missing activation time.
/// No effective cutover is invented or passed to the production evaluator.
fn evaluate_optional_activation(activation: Option<u64>) -> AuthorizationDecision {
    match activation {
        Some(cutover) => evaluate_candidate(cutover).0,
        None => AuthorizationDecision::Unknown,
    }
}

#[test]
fn ir_a_flexible_activation_allows() {
    let (decision, diagnostics) = evaluate_candidate(3);

    assert_eq!(decision, AuthorizationDecision::Allow);
    assert_eq!(
        diagnostics.continuity,
        SecurityContinuityEvaluation::Continuous
    );
    assert_eq!(
        diagnostics.cutover_feasibility,
        MigrationFeasibility::Feasible
    );
    assert_eq!(
        diagnostics.deadline_feasibility,
        MigrationFeasibility::Feasible
    );
    assert!(diagnostics.cutover_within_deadline);
}

#[test]
fn ir_b_late_activation_denies_despite_early_readiness() {
    let (decision, diagnostics) = evaluate_candidate(9);

    assert_eq!(decision, AuthorizationDecision::Deny);
    assert_eq!(
        diagnostics.continuity,
        SecurityContinuityEvaluation::Continuous
    );
    assert_eq!(
        diagnostics.cutover_feasibility,
        MigrationFeasibility::Feasible
    );
    assert_eq!(
        diagnostics.deadline_feasibility,
        MigrationFeasibility::Feasible
    );
    assert!(!diagnostics.cutover_within_deadline);
}

#[test]
fn ir_c_unknown_activation_cannot_establish_feasibility() {
    assert_eq!(
        evaluate_optional_activation(None),
        AuthorizationDecision::Unknown
    );
    assert_eq!(
        evaluate_optional_activation(Some(3)),
        AuthorizationDecision::Allow
    );
}

#[test]
fn ir_d_activation_before_completion_denies() {
    let (decision, diagnostics) = evaluate_candidate(2);

    assert_eq!(decision, AuthorizationDecision::Deny);
    assert_eq!(
        diagnostics.continuity,
        SecurityContinuityEvaluation::Continuous
    );
    assert_eq!(
        diagnostics.cutover_feasibility,
        MigrationFeasibility::Infeasible
    );
    assert_eq!(
        diagnostics.deadline_feasibility,
        MigrationFeasibility::Feasible
    );
    assert!(diagnostics.cutover_within_deadline);
}

#[test]
fn ir_e_activation_exactly_at_deadline_allows() {
    let (decision, diagnostics) = evaluate_candidate(8);

    assert_eq!(decision, AuthorizationDecision::Allow);
    assert_eq!(
        diagnostics.continuity,
        SecurityContinuityEvaluation::Continuous
    );
    assert_eq!(
        diagnostics.cutover_feasibility,
        MigrationFeasibility::Feasible
    );
    assert_eq!(
        diagnostics.deadline_feasibility,
        MigrationFeasibility::Feasible
    );
    assert!(diagnostics.cutover_within_deadline);
}

#[test]
fn ir_f_activation_one_tick_after_deadline_denies() {
    let (decision, diagnostics) = evaluate_candidate(9);

    assert_eq!(decision, AuthorizationDecision::Deny);
    assert!(diagnostics.deadline_feasibility == MigrationFeasibility::Feasible);
    assert!(!diagnostics.cutover_within_deadline);
}
