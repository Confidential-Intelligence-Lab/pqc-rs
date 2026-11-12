//! Advisory security continuity across an atomic configuration cutover.
//!
//! Assessments are caller-supplied and ordered by threat phase, then
//! source and destination when a phase crosses cutover.
//! No cryptographic strength or actual deployment state is inferred.

use crate::{
    evaluate_security_assessment, ActiveConfiguration, ConfigurationIdentity,
    SecurityAcceptability, SecurityAssessment, SecurityAssessmentBinding,
    SecurityAssessmentEvaluation, SecurityRequirementId, ThreatSchedule, TimeInterval,
    TransitionInterval,
};

/// Invalid input to a continuity evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityContinuityError {
    /// The transition and threat schedule cover different horizons.
    HorizonMismatch,
    /// The supplied assessment count differs from active intersections.
    AssessmentCountMismatch {
        /// Number of required assessments.
        expected: usize,
        /// Number of supplied assessments.
        actual: usize,
    },
    /// An assessment does not match its active configuration and threat.
    BindingMismatch {
        /// Zero-based assessment index.
        assessment: usize,
        /// Exact binding mismatch.
        mismatch: SecurityAssessmentEvaluation,
    },
    /// Equal bindings have contradictory outcomes in one snapshot.
    InconsistentAssessment {
        /// Earlier assessment index.
        first: usize,
        /// Later assessment index.
        second: usize,
    },
}

/// An active portion of a threat phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuitySegment {
    /// Zero-based index in the original threat schedule.
    pub phase: usize,
    /// Configuration responsible for the segment.
    pub active: ActiveConfiguration,
    /// Nonempty half-open segment.
    pub interval: TimeInterval,
}

/// Advisory continuity result over the complete protection horizon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityContinuityEvaluation {
    /// All active segments are assessed acceptable.
    Continuous,
    /// At least one segment is assessed unacceptable.
    Discontinuous(ContinuitySegment),
    /// No segment is unacceptable, but evidence is unknown.
    Unknown(ContinuitySegment),
}

/// Evaluate caller-supplied assessments over the active configuration.
///
/// Assessments are ordered chronologically by threat phase, with source
/// preceding destination when both intersect the same threat phase.
/// Each nonempty intersection requires exactly one assessment.
///
/// All bindings and repeated-binding consistency are validated before
/// outcomes are aggregated. Unacceptable takes precedence over Unknown.
/// The returned segment is the first segment with the dominant outcome.
///
/// This does not authenticate assessments, prove deployment activation,
/// authorize a migration, or establish protection between observations.
pub fn evaluate_security_continuity(
    schedule: &ThreatSchedule<'_>,
    transition: TransitionInterval,
    source: ConfigurationIdentity,
    destination: ConfigurationIdentity,
    requirement: SecurityRequirementId,
    assessments: &[SecurityAssessment],
) -> Result<SecurityContinuityEvaluation, SecurityContinuityError> {
    if schedule.protection() != transition.protection() {
        return Err(SecurityContinuityError::HorizonMismatch);
    }

    let cutover = transition.cutover();
    let mut expected = 0usize;

    for phase in schedule.phases() {
        let interval = phase.interval();
        if interval.start() < cutover {
            expected += 1;
        }
        if interval.end() > cutover {
            expected += 1;
        }
    }

    if assessments.len() != expected {
        return Err(SecurityContinuityError::AssessmentCountMismatch {
            expected,
            actual: assessments.len(),
        });
    }

    let mut index = 0usize;
    let mut first_unacceptable = None;
    let mut first_unknown = None;

    for (phase_index, phase) in schedule.phases().iter().enumerate() {
        let interval = phase.interval();

        for active in [
            ActiveConfiguration::Source,
            ActiveConfiguration::Destination,
        ] {
            let bounds = match active {
                ActiveConfiguration::Source => {
                    if interval.start() >= cutover {
                        None
                    } else {
                        let end = if interval.end() < cutover {
                            interval.end()
                        } else {
                            cutover
                        };
                        Some((interval.start(), end))
                    }
                }
                ActiveConfiguration::Destination => {
                    if interval.end() <= cutover {
                        None
                    } else {
                        let start = if interval.start() > cutover {
                            interval.start()
                        } else {
                            cutover
                        };
                        Some((start, interval.end()))
                    }
                }
            };

            let Some((start, end)) = bounds else {
                continue;
            };

            let segment = ContinuitySegment {
                phase: phase_index,
                active,
                interval: TimeInterval::new(start, end)
                    .expect("nonempty intersection of validated intervals"),
            };

            let configuration = match active {
                ActiveConfiguration::Source => source,
                ActiveConfiguration::Destination => destination,
            };

            let requested =
                SecurityAssessmentBinding::new(configuration, phase.threat(), requirement);

            match evaluate_security_assessment(requested, assessments[index]) {
                SecurityAssessmentEvaluation::Matched(SecurityAcceptability::Acceptable) => {}
                SecurityAssessmentEvaluation::Matched(SecurityAcceptability::Unacceptable) => {
                    if first_unacceptable.is_none() {
                        first_unacceptable = Some(segment);
                    }
                }
                SecurityAssessmentEvaluation::Matched(SecurityAcceptability::Unknown) => {
                    if first_unknown.is_none() {
                        first_unknown = Some(segment);
                    }
                }
                mismatch => {
                    return Err(SecurityContinuityError::BindingMismatch {
                        assessment: index,
                        mismatch,
                    });
                }
            }

            index += 1;
        }
    }

    debug_assert_eq!(index, expected);

    // Enforce consistency across all active segments, including
    // repeated threat identities in nonadjacent schedule phases.
    for second in 1..assessments.len() {
        for first in 0..second {
            if assessments[first].binding() == assessments[second].binding()
                && assessments[first].acceptability() != assessments[second].acceptability()
            {
                return Err(SecurityContinuityError::InconsistentAssessment { first, second });
            }
        }
    }

    if let Some(segment) = first_unacceptable {
        Ok(SecurityContinuityEvaluation::Discontinuous(segment))
    } else if let Some(segment) = first_unknown {
        Ok(SecurityContinuityEvaluation::Unknown(segment))
    } else {
        Ok(SecurityContinuityEvaluation::Continuous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AlgorithmId, ImplementationRevision, ModelTime, ParameterSetId, ProtectionHorizon,
        ProviderId, ThreatPhase, ThreatPhaseId,
    };

    fn time(t: u64) -> ModelTime {
        ModelTime::new(t)
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
        ProtectionHorizon::new(time(0), time(10)).unwrap()
    }

    fn phase(start: u64, end: u64, threat: u64) -> ThreatPhase {
        ThreatPhase::new(
            TimeInterval::new(time(start), time(end)).unwrap(),
            ThreatPhaseId::new(threat),
        )
    }

    fn assessment(
        revision: u64,
        threat: u64,
        outcome: SecurityAcceptability,
    ) -> SecurityAssessment {
        SecurityAssessment::new(
            SecurityAssessmentBinding::new(
                configuration(revision),
                ThreatPhaseId::new(threat),
                SecurityRequirementId::new(7),
            ),
            outcome,
        )
    }

    fn evaluate(
        phases: &[ThreatPhase],
        cutover: u64,
        assessments: &[SecurityAssessment],
    ) -> Result<SecurityContinuityEvaluation, SecurityContinuityError> {
        let schedule = ThreatSchedule::new(phases, horizon()).unwrap();
        let transition = TransitionInterval::new(horizon(), time(cutover)).unwrap();
        evaluate_security_continuity(
            &schedule,
            transition,
            configuration(1),
            configuration(2),
            SecurityRequirementId::new(7),
            assessments,
        )
    }

    #[test]
    fn continuous_across_threat_boundary() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let inputs = [
            assessment(1, 1, SecurityAcceptability::Acceptable),
            assessment(2, 2, SecurityAcceptability::Acceptable),
        ];
        assert_eq!(
            evaluate(&phases, 5, &inputs),
            Ok(SecurityContinuityEvaluation::Continuous)
        );
    }

    #[test]
    fn cutover_inside_phase_requires_two_assessments() {
        let phases = [phase(0, 10, 1)];
        let inputs = [
            assessment(1, 1, SecurityAcceptability::Acceptable),
            assessment(2, 1, SecurityAcceptability::Acceptable),
        ];
        assert_eq!(
            evaluate(&phases, 6, &inputs),
            Ok(SecurityContinuityEvaluation::Continuous)
        );
        assert_eq!(
            evaluate(&phases, 6, &inputs[..1]),
            Err(SecurityContinuityError::AssessmentCountMismatch {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn source_exposure_before_cutover_is_detected() {
        let phases = [phase(0, 6, 1), phase(6, 9, 2), phase(9, 10, 3)];
        let inputs = [
            assessment(1, 1, SecurityAcceptability::Acceptable),
            assessment(1, 2, SecurityAcceptability::Unacceptable),
            assessment(2, 3, SecurityAcceptability::Acceptable),
        ];
        assert_eq!(
            evaluate(&phases, 9, &inputs),
            Ok(SecurityContinuityEvaluation::Discontinuous(
                ContinuitySegment {
                    phase: 1,
                    active: ActiveConfiguration::Source,
                    interval: TimeInterval::new(time(6), time(9)).unwrap(),
                }
            ))
        );
    }

    #[test]
    fn destination_failure_after_cutover_is_detected() {
        let phases = [phase(0, 10, 1)];
        let inputs = [
            assessment(1, 1, SecurityAcceptability::Acceptable),
            assessment(2, 1, SecurityAcceptability::Unacceptable),
        ];
        assert!(matches!(
            evaluate(&phases, 4, &inputs),
            Ok(SecurityContinuityEvaluation::Discontinuous(
                ContinuitySegment {
                    active: ActiveConfiguration::Destination,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn unacceptable_precedes_unknown() {
        let phases = [phase(0, 10, 1)];
        let inputs = [
            assessment(1, 1, SecurityAcceptability::Unknown),
            assessment(2, 1, SecurityAcceptability::Unacceptable),
        ];
        assert!(matches!(
            evaluate(&phases, 4, &inputs),
            Ok(SecurityContinuityEvaluation::Discontinuous(_))
        ));
    }

    #[test]
    fn unknown_is_not_continuous() {
        let phases = [phase(0, 10, 1)];
        let inputs = [
            assessment(1, 1, SecurityAcceptability::Acceptable),
            assessment(2, 1, SecurityAcceptability::Unknown),
        ];
        assert!(matches!(
            evaluate(&phases, 4, &inputs),
            Ok(SecurityContinuityEvaluation::Unknown(_))
        ));
    }

    #[test]
    fn immediate_cutover_requires_only_destination() {
        let phases = [phase(0, 10, 1)];
        let inputs = [assessment(2, 1, SecurityAcceptability::Acceptable)];
        assert_eq!(
            evaluate(&phases, 0, &inputs),
            Ok(SecurityContinuityEvaluation::Continuous)
        );
    }

    #[test]
    fn horizon_cutover_requires_only_source() {
        let phases = [phase(0, 10, 1)];
        let inputs = [assessment(1, 1, SecurityAcceptability::Acceptable)];
        assert_eq!(
            evaluate(&phases, 10, &inputs),
            Ok(SecurityContinuityEvaluation::Continuous)
        );
    }

    #[test]
    fn mismatched_configuration_is_an_error() {
        let phases = [phase(0, 10, 1)];
        let inputs = [
            assessment(1, 1, SecurityAcceptability::Acceptable),
            assessment(9, 1, SecurityAcceptability::Acceptable),
        ];
        assert_eq!(
            evaluate(&phases, 5, &inputs),
            Err(SecurityContinuityError::BindingMismatch {
                assessment: 1,
                mismatch: SecurityAssessmentEvaluation::ConfigurationMismatch,
            })
        );
    }

    #[test]
    fn mismatched_threat_is_an_error() {
        let phases = [phase(0, 10, 1)];
        let inputs = [
            assessment(1, 1, SecurityAcceptability::Acceptable),
            assessment(2, 9, SecurityAcceptability::Acceptable),
        ];
        assert_eq!(
            evaluate(&phases, 5, &inputs),
            Err(SecurityContinuityError::BindingMismatch {
                assessment: 1,
                mismatch: SecurityAssessmentEvaluation::ThreatMismatch,
            })
        );
    }

    #[test]
    fn mismatched_requirement_is_an_error() {
        let phases = [phase(0, 10, 1)];
        let inputs = [
            assessment(1, 1, SecurityAcceptability::Acceptable),
            SecurityAssessment::new(
                SecurityAssessmentBinding::new(
                    configuration(2),
                    ThreatPhaseId::new(1),
                    SecurityRequirementId::new(8),
                ),
                SecurityAcceptability::Acceptable,
            ),
        ];
        assert_eq!(
            evaluate(&phases, 5, &inputs),
            Err(SecurityContinuityError::BindingMismatch {
                assessment: 1,
                mismatch: SecurityAssessmentEvaluation::RequirementMismatch,
            })
        );
    }

    #[test]
    fn repeated_binding_contradiction_is_an_error() {
        let phases = [phase(0, 3, 1), phase(3, 6, 2), phase(6, 10, 1)];
        let inputs = [
            assessment(1, 1, SecurityAcceptability::Acceptable),
            assessment(1, 2, SecurityAcceptability::Acceptable),
            assessment(1, 1, SecurityAcceptability::Unacceptable),
        ];
        assert_eq!(
            evaluate(&phases, 10, &inputs),
            Err(SecurityContinuityError::InconsistentAssessment {
                first: 0,
                second: 2,
            })
        );
    }

    #[test]
    fn malformed_binding_precedes_unacceptable_result() {
        let phases = [phase(0, 10, 1)];
        let inputs = [
            assessment(1, 1, SecurityAcceptability::Unacceptable),
            assessment(9, 1, SecurityAcceptability::Acceptable),
        ];
        assert!(matches!(
            evaluate(&phases, 5, &inputs),
            Err(SecurityContinuityError::BindingMismatch { assessment: 1, .. })
        ));
    }

    #[test]
    fn horizon_mismatch_is_rejected() {
        let phases = [phase(0, 10, 1)];
        let schedule = ThreatSchedule::new(&phases, horizon()).unwrap();
        let other = ProtectionHorizon::new(time(0), time(11)).unwrap();
        let transition = TransitionInterval::new(other, time(5)).unwrap();
        assert_eq!(
            evaluate_security_continuity(
                &schedule,
                transition,
                configuration(1),
                configuration(2),
                SecurityRequirementId::new(7),
                &[],
            ),
            Err(SecurityContinuityError::HorizonMismatch)
        );
    }

    #[test]
    fn first_unknown_segment_is_reported() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let inputs = [
            assessment(1, 1, SecurityAcceptability::Unknown),
            assessment(2, 2, SecurityAcceptability::Unknown),
        ];
        assert_eq!(
            evaluate(&phases, 5, &inputs),
            Ok(SecurityContinuityEvaluation::Unknown(ContinuitySegment {
                phase: 0,
                active: ActiveConfiguration::Source,
                interval: TimeInterval::new(time(0), time(5)).unwrap(),
            }))
        );
    }
}
