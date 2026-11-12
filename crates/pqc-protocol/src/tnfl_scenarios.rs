//! Test-only Trust Now, Forge Later (TNFL) counterexamples.
//!
//! Artifact trust is a caller-supplied assumption. These tests do not
//! verify signatures, authenticate timestamps, or implement archival
//! validation or signature renewal.

use crate::{
    evaluate_continuous_migration, evaluate_security_continuity, AlgorithmId,
    AuthorizationDecision, ConfigurationIdentity, ContinuousMigrationEvaluation,
    FourPredicateEvaluation, ImplementationRevision, MigrationDuration, MigrationTiming,
    MigrationTimingEvidence, ModelTime, ParameterSetId, ProtectionHorizon, ProviderId,
    SecurityAcceptability, SecurityAssessment, SecurityAssessmentBinding,
    SecurityContinuityEvaluation, SecurityRequirementId, ThreatPhase, ThreatPhaseId,
    ThreatSchedule, TimeInterval, TransitionInterval,
};

fn t(value: u64) -> ModelTime {
    ModelTime::new(value)
}

fn configuration(revision: u64) -> ConfigurationIdentity {
    ConfigurationIdentity::new(
        AlgorithmId::new(1),
        ParameterSetId::new(65),
        ProviderId::new(2),
        ImplementationRevision::new(revision),
    )
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
            SecurityRequirementId::new(2),
        ),
        outcome,
    )
}

fn configuration_decision() -> AuthorizationDecision {
    let protection = ProtectionHorizon::new(t(0), t(10)).unwrap();
    let transition = TransitionInterval::new(protection, t(4)).unwrap();

    let phases = [phase(0, 4, 1), phase(4, 6, 2), phase(6, 10, 3)];
    let schedule = ThreatSchedule::new(&phases, protection).unwrap();

    let assessments = [
        assessment(1, 1, SecurityAcceptability::Acceptable),
        assessment(2, 2, SecurityAcceptability::Acceptable),
        assessment(2, 3, SecurityAcceptability::Acceptable),
    ];

    let continuity = evaluate_security_continuity(
        &schedule,
        transition,
        configuration(1),
        configuration(2),
        SecurityRequirementId::new(2),
        &assessments,
    );

    assert_eq!(continuity, Ok(SecurityContinuityEvaluation::Continuous));

    let timing = MigrationTimingEvidence::Known(
        MigrationTiming::new(t(0), t(1), MigrationDuration::new(2)).unwrap(),
    );

    match evaluate_continuous_migration(
        continuity,
        transition,
        timing,
        t(8),
        FourPredicateEvaluation::Evaluated(AuthorizationDecision::Allow),
    ) {
        ContinuousMigrationEvaluation::Evaluated { decision, .. } => decision,
        ContinuousMigrationEvaluation::Invalid(error) => {
            panic!("unexpected invalid configuration evaluation: {error:?}")
        }
    }
}

/// Test-local representation of one previously signed artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactTrust {
    issued_at: ModelTime,
    required_until: ModelTime,
    issued_under: ConfigurationIdentity,
    before_threat_change: SecurityAcceptability,
    after_threat_change: SecurityAcceptability,
}

impl ArtifactTrust {
    fn evaluate(self) -> AuthorizationDecision {
        assert_eq!(self.issued_at, t(2));
        assert_eq!(self.required_until, t(10));
        assert_eq!(self.issued_under, configuration(1));

        // Explicitly check the artifact's post-cutover exposure.
        // This is an illustrative assessment, not a signature verifier.
        let mut unknown = false;

        for outcome in [self.before_threat_change, self.after_threat_change] {
            match outcome {
                SecurityAcceptability::Unacceptable => {
                    return AuthorizationDecision::Deny;
                }
                SecurityAcceptability::Unknown => unknown = true,
                SecurityAcceptability::Acceptable => {}
            }
        }

        if unknown {
            AuthorizationDecision::Unknown
        } else {
            AuthorizationDecision::Allow
        }
    }
}

/// Test-local conservative conjunction; not a production evaluator.
fn combine(
    configuration: AuthorizationDecision,
    artifact: AuthorizationDecision,
) -> AuthorizationDecision {
    use AuthorizationDecision::{Allow, Defer, Deny, Unknown};

    if configuration == Deny || artifact == Deny {
        Deny
    } else if configuration == Unknown || artifact == Unknown {
        Unknown
    } else if configuration == Defer || artifact == Defer {
        Defer
    } else {
        Allow
    }
}

fn artifact(after_threat_change: SecurityAcceptability) -> ArtifactTrust {
    ArtifactTrust {
        issued_at: t(2),
        required_until: t(10),
        issued_under: configuration(1),
        before_threat_change: SecurityAcceptability::Acceptable,
        after_threat_change,
    }
}

#[test]
fn tnfl_a_configuration_and_artifact_both_acceptable() {
    let configuration = configuration_decision();
    let trust = artifact(SecurityAcceptability::Acceptable).evaluate();

    assert_eq!(configuration, AuthorizationDecision::Allow);
    assert_eq!(trust, AuthorizationDecision::Allow);
    assert_eq!(combine(configuration, trust), AuthorizationDecision::Allow);
}

#[test]
fn tnfl_b_configuration_continuous_but_artifact_untrustworthy() {
    let configuration = configuration_decision();
    let trust = artifact(SecurityAcceptability::Unacceptable).evaluate();

    assert_eq!(configuration, AuthorizationDecision::Allow);
    assert_eq!(trust, AuthorizationDecision::Deny);
    assert_eq!(combine(configuration, trust), AuthorizationDecision::Deny);
}

#[test]
fn tnfl_c_configuration_continuous_but_artifact_trust_unknown() {
    let configuration = configuration_decision();
    let trust = artifact(SecurityAcceptability::Unknown).evaluate();

    assert_eq!(configuration, AuthorizationDecision::Allow);
    assert_eq!(trust, AuthorizationDecision::Unknown);
    assert_eq!(
        combine(configuration, trust),
        AuthorizationDecision::Unknown
    );
}

#[test]
fn tnfl_d_unacceptable_artifact_precedes_unknown() {
    let mut item = artifact(SecurityAcceptability::Unknown);
    item.before_threat_change = SecurityAcceptability::Unacceptable;

    assert_eq!(item.evaluate(), AuthorizationDecision::Deny);
}
