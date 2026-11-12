//! Advisory security acceptability over a validated protection horizon.
//!
//! Assessments correspond one-to-one with scheduled intervals, in order.
//! Inputs are externally supplied; this module does not verify provenance,
//! estimate cryptographic strength, or authorize transitions.

use crate::{
    evaluate_security_assessment, ConfigurationIdentity, SecurityAcceptability, SecurityAssessment,
    SecurityAssessmentBinding, SecurityAssessmentEvaluation, SecurityRequirementId, ThreatSchedule,
};

/// Aggregate security acceptability over the complete protection horizon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HorizonSecurityEvaluation {
    /// Every scheduled interval has an acceptable assessment.
    Acceptable,
    /// At least one scheduled interval has an unacceptable assessment.
    Unacceptable,
    /// No interval is unacceptable, but at least one is unknown.
    Unknown,
}

/// Invalid or incomplete assessment input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HorizonSecurityError {
    /// The number of assessments differs from the number of intervals.
    AssessmentCountMismatch {
        /// Required number of assessments.
        expected: usize,
        /// Supplied number of assessments.
        actual: usize,
    },
    /// An assessment does not match its corresponding scheduled interval.
    BindingMismatch {
        /// Zero-based index of the offending interval.
        phase: usize,
        /// Exact mismatch category reported by the binding evaluator.
        mismatch: SecurityAssessmentEvaluation,
    },
}

/// Evaluate a fixed configuration and requirement across a threat schedule.
///
/// The assessment at index `i` must be bound to the configuration,
/// threat identity of scheduled interval `i`, and security requirement.
///
/// All bindings are checked before aggregating outcomes. Consequently,
/// malformed input is reported even when another interval is known
/// to be unacceptable.
///
/// Aggregation precedence is Unacceptable > Unknown > Acceptable.
/// Repeated threat identities still require separate interval assessments.
pub fn evaluate_horizon_security(
    schedule: &ThreatSchedule<'_>,
    configuration: ConfigurationIdentity,
    requirement: SecurityRequirementId,
    assessments: &[SecurityAssessment],
) -> Result<HorizonSecurityEvaluation, HorizonSecurityError> {
    let phases = schedule.phases();

    if assessments.len() != phases.len() {
        return Err(HorizonSecurityError::AssessmentCountMismatch {
            expected: phases.len(),
            actual: assessments.len(),
        });
    }

    let mut has_unacceptable = false;
    let mut has_unknown = false;

    for (index, (phase, assessment)) in phases.iter().zip(assessments.iter()).enumerate() {
        let requested = SecurityAssessmentBinding::new(configuration, phase.threat(), requirement);

        match evaluate_security_assessment(requested, *assessment) {
            SecurityAssessmentEvaluation::Matched(SecurityAcceptability::Acceptable) => {}
            SecurityAssessmentEvaluation::Matched(SecurityAcceptability::Unacceptable) => {
                has_unacceptable = true
            }
            SecurityAssessmentEvaluation::Matched(SecurityAcceptability::Unknown) => {
                has_unknown = true
            }
            mismatch => {
                return Err(HorizonSecurityError::BindingMismatch {
                    phase: index,
                    mismatch,
                });
            }
        }
    }

    if has_unacceptable {
        Ok(HorizonSecurityEvaluation::Unacceptable)
    } else if has_unknown {
        Ok(HorizonSecurityEvaluation::Unknown)
    } else {
        Ok(HorizonSecurityEvaluation::Acceptable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AlgorithmId, ImplementationRevision, ModelTime, ParameterSetId, ProtectionHorizon,
        ProviderId, SecurityAcceptability as A, ThreatPhase, ThreatPhaseId, TimeInterval,
    };

    fn configuration(revision: u64) -> ConfigurationIdentity {
        ConfigurationIdentity::new(
            AlgorithmId::new(1),
            ParameterSetId::new(768),
            ProviderId::new(2),
            ImplementationRevision::new(revision),
        )
    }

    fn requirement() -> SecurityRequirementId {
        SecurityRequirementId::new(7)
    }

    fn phase(start: u64, end: u64, id: u64) -> ThreatPhase {
        ThreatPhase::new(
            TimeInterval::new(ModelTime::new(start), ModelTime::new(end)).unwrap(),
            ThreatPhaseId::new(id),
        )
    }

    fn schedule<'a>(phases: &'a [ThreatPhase]) -> ThreatSchedule<'a> {
        ThreatSchedule::new(
            phases,
            ProtectionHorizon::new(ModelTime::new(0), ModelTime::new(10)).unwrap(),
        )
        .unwrap()
    }

    fn assessment(
        revision: u64,
        threat: u64,
        requirement_id: u64,
        outcome: A,
    ) -> SecurityAssessment {
        SecurityAssessment::new(
            SecurityAssessmentBinding::new(
                configuration(revision),
                ThreatPhaseId::new(threat),
                SecurityRequirementId::new(requirement_id),
            ),
            outcome,
        )
    }

    #[test]
    fn all_acceptable_is_acceptable() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let inputs = [
            assessment(1, 1, 7, A::Acceptable),
            assessment(1, 2, 7, A::Acceptable),
        ];
        assert_eq!(
            evaluate_horizon_security(&schedule(&phases), configuration(1), requirement(), &inputs),
            Ok(HorizonSecurityEvaluation::Acceptable)
        );
    }

    #[test]
    fn initially_acceptable_can_become_unacceptable() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let inputs = [
            assessment(1, 1, 7, A::Acceptable),
            assessment(1, 2, 7, A::Unacceptable),
        ];
        assert_eq!(
            evaluate_horizon_security(&schedule(&phases), configuration(1), requirement(), &inputs),
            Ok(HorizonSecurityEvaluation::Unacceptable)
        );
    }

    #[test]
    fn unknown_without_unacceptable_is_unknown() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let inputs = [
            assessment(1, 1, 7, A::Unknown),
            assessment(1, 2, 7, A::Acceptable),
        ];
        assert_eq!(
            evaluate_horizon_security(&schedule(&phases), configuration(1), requirement(), &inputs),
            Ok(HorizonSecurityEvaluation::Unknown)
        );
    }

    #[test]
    fn unacceptable_takes_precedence_over_unknown() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let inputs = [
            assessment(1, 1, 7, A::Unknown),
            assessment(1, 2, 7, A::Unacceptable),
        ];
        assert_eq!(
            evaluate_horizon_security(&schedule(&phases), configuration(1), requirement(), &inputs),
            Ok(HorizonSecurityEvaluation::Unacceptable)
        );
    }

    #[test]
    fn missing_assessment_is_explicit_error() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let inputs = [assessment(1, 1, 7, A::Acceptable)];
        assert_eq!(
            evaluate_horizon_security(&schedule(&phases), configuration(1), requirement(), &inputs),
            Err(HorizonSecurityError::AssessmentCountMismatch {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn extra_assessment_is_explicit_error() {
        let phases = [phase(0, 10, 1)];
        let inputs = [
            assessment(1, 1, 7, A::Acceptable),
            assessment(1, 2, 7, A::Acceptable),
        ];
        assert_eq!(
            evaluate_horizon_security(&schedule(&phases), configuration(1), requirement(), &inputs),
            Err(HorizonSecurityError::AssessmentCountMismatch {
                expected: 1,
                actual: 2,
            })
        );
    }

    #[test]
    fn configuration_mismatch_reports_phase_index() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let inputs = [
            assessment(1, 1, 7, A::Acceptable),
            assessment(9, 2, 7, A::Acceptable),
        ];
        assert_eq!(
            evaluate_horizon_security(&schedule(&phases), configuration(1), requirement(), &inputs),
            Err(HorizonSecurityError::BindingMismatch {
                phase: 1,
                mismatch: SecurityAssessmentEvaluation::ConfigurationMismatch,
            })
        );
    }

    #[test]
    fn threat_mismatch_reports_phase_index() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let inputs = [
            assessment(1, 1, 7, A::Acceptable),
            assessment(1, 3, 7, A::Acceptable),
        ];
        assert_eq!(
            evaluate_horizon_security(&schedule(&phases), configuration(1), requirement(), &inputs),
            Err(HorizonSecurityError::BindingMismatch {
                phase: 1,
                mismatch: SecurityAssessmentEvaluation::ThreatMismatch,
            })
        );
    }

    #[test]
    fn requirement_mismatch_reports_phase_index() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let inputs = [
            assessment(1, 1, 7, A::Acceptable),
            assessment(1, 2, 8, A::Acceptable),
        ];
        assert_eq!(
            evaluate_horizon_security(&schedule(&phases), configuration(1), requirement(), &inputs),
            Err(HorizonSecurityError::BindingMismatch {
                phase: 1,
                mismatch: SecurityAssessmentEvaluation::RequirementMismatch,
            })
        );
    }

    #[test]
    fn malformed_input_is_not_hidden_by_unacceptable() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let inputs = [
            assessment(1, 1, 7, A::Unacceptable),
            assessment(1, 9, 7, A::Acceptable),
        ];
        assert_eq!(
            evaluate_horizon_security(&schedule(&phases), configuration(1), requirement(), &inputs),
            Err(HorizonSecurityError::BindingMismatch {
                phase: 1,
                mismatch: SecurityAssessmentEvaluation::ThreatMismatch,
            })
        );
    }

    #[test]
    fn repeated_threat_identity_uses_separate_assessments() {
        let phases = [phase(0, 5, 1), phase(5, 10, 1)];
        let inputs = [
            assessment(1, 1, 7, A::Acceptable),
            assessment(1, 1, 7, A::Unknown),
        ];
        assert_eq!(
            evaluate_horizon_security(&schedule(&phases), configuration(1), requirement(), &inputs),
            Ok(HorizonSecurityEvaluation::Unknown)
        );
    }

    #[test]
    fn single_phase_schedule_is_supported() {
        let phases = [phase(0, 10, 1)];
        let inputs = [assessment(1, 1, 7, A::Acceptable)];
        assert_eq!(
            evaluate_horizon_security(&schedule(&phases), configuration(1), requirement(), &inputs),
            Ok(HorizonSecurityEvaluation::Acceptable)
        );
    }
}
