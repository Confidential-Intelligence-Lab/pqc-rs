//! Test-only HNDL confidentiality scenarios.
//!
//! All times, threat identities, and acceptability outcomes are
//! illustrative caller-supplied assumptions, not measured forecasts.

use crate::{
    evaluate_continuous_migration, evaluate_security_continuity, ActiveConfiguration, AlgorithmId,
    AuthorizationDecision, ConfigurationIdentity, ContinuitySegment,
    ContinuousMigrationDiagnostics, ContinuousMigrationError, ContinuousMigrationEvaluation,
    FourPredicateEvaluation, ImplementationRevision, MigrationDuration, MigrationFeasibility,
    MigrationTiming, MigrationTimingEvidence, ModelTime, ParameterSetId, ProtectionHorizon,
    ProviderId, SecurityAcceptability, SecurityAssessment, SecurityAssessmentBinding,
    SecurityContinuityError, SecurityContinuityEvaluation, SecurityRequirementId, ThreatPhase,
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

fn horizon() -> ProtectionHorizon {
    ProtectionHorizon::new(t(0), t(10)).unwrap()
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

fn timing() -> MigrationTimingEvidence {
    MigrationTimingEvidence::Known(
        MigrationTiming::new(t(0), t(1), MigrationDuration::new(2)).unwrap(),
    )
}

fn evaluate(cutover: u64, assessments: &[SecurityAssessment]) -> ContinuousMigrationEvaluation {
    let phases = [phase(0, 4, 1), phase(4, 10, 2)];
    let schedule = ThreatSchedule::new(&phases, horizon()).unwrap();
    let transition = TransitionInterval::new(horizon(), t(cutover)).unwrap();

    let continuity = evaluate_security_continuity(
        &schedule,
        transition,
        configuration(1),
        configuration(2),
        SecurityRequirementId::new(1),
        assessments,
    );

    evaluate_continuous_migration(
        continuity,
        transition,
        timing(),
        t(8),
        FourPredicateEvaluation::Evaluated(AuthorizationDecision::Allow),
    )
}

fn evaluated(
    result: ContinuousMigrationEvaluation,
) -> (AuthorizationDecision, ContinuousMigrationDiagnostics) {
    match result {
        ContinuousMigrationEvaluation::Evaluated {
            decision,
            diagnostics,
        } => (decision, diagnostics),
        ContinuousMigrationEvaluation::Invalid(error) => {
            panic!("unexpected invalid scenario: {error:?}")
        }
    }
}

#[test]
fn hndl_a_timely_cutover_preserves_continuity() {
    let inputs = [
        assessment(1, 1, SecurityAcceptability::Acceptable),
        assessment(2, 2, SecurityAcceptability::Acceptable),
    ];

    let (decision, diagnostics) = evaluated(evaluate(4, &inputs));

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
}

#[test]
fn hndl_b_delayed_cutover_exposes_source() {
    let inputs = [
        assessment(1, 1, SecurityAcceptability::Acceptable),
        assessment(1, 2, SecurityAcceptability::Unacceptable),
        assessment(2, 2, SecurityAcceptability::Acceptable),
    ];

    let (decision, diagnostics) = evaluated(evaluate(6, &inputs));

    assert_eq!(decision, AuthorizationDecision::Deny);
    assert_eq!(
        diagnostics.continuity,
        SecurityContinuityEvaluation::Discontinuous(ContinuitySegment {
            phase: 1,
            active: ActiveConfiguration::Source,
            interval: TimeInterval::new(t(4), t(6)).unwrap(),
        })
    );
    assert_eq!(
        diagnostics.cutover_feasibility,
        MigrationFeasibility::Feasible
    );
}

#[test]
fn hndl_c_unknown_source_exposure_remains_unknown() {
    let inputs = [
        assessment(1, 1, SecurityAcceptability::Acceptable),
        assessment(1, 2, SecurityAcceptability::Unknown),
        assessment(2, 2, SecurityAcceptability::Acceptable),
    ];

    let (decision, diagnostics) = evaluated(evaluate(6, &inputs));

    assert_eq!(decision, AuthorizationDecision::Unknown);
    assert_eq!(
        diagnostics.continuity,
        SecurityContinuityEvaluation::Unknown(ContinuitySegment {
            phase: 1,
            active: ActiveConfiguration::Source,
            interval: TimeInterval::new(t(4), t(6)).unwrap(),
        })
    );
    assert_eq!(
        diagnostics.cutover_feasibility,
        MigrationFeasibility::Feasible
    );
}

#[test]
fn hndl_d_cutover_before_migration_completion_denies() {
    let inputs = [
        assessment(1, 1, SecurityAcceptability::Acceptable),
        assessment(2, 1, SecurityAcceptability::Acceptable),
        assessment(2, 2, SecurityAcceptability::Acceptable),
    ];

    let (decision, diagnostics) = evaluated(evaluate(2, &inputs));

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
}

#[test]
fn hndl_e_malformed_binding_is_invalid_not_denied() {
    let inputs = [
        assessment(1, 1, SecurityAcceptability::Acceptable),
        assessment(9, 2, SecurityAcceptability::Unacceptable),
        assessment(2, 2, SecurityAcceptability::Acceptable),
    ];

    assert_eq!(
        evaluate(6, &inputs),
        ContinuousMigrationEvaluation::Invalid(ContinuousMigrationError::Continuity(
            SecurityContinuityError::BindingMismatch {
                assessment: 1,
                mismatch: crate::SecurityAssessmentEvaluation::ConfigurationMismatch,
            }
        ))
    );
}
