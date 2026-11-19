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

/// Errors from caller-owned scratch evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityContinuityScratchError {
    /// Existing continuity validation failed.
    Evaluation(SecurityContinuityError),
    /// Caller-provided workspace is too small.
    InsufficientScratch {
        /// Required number of index entries.
        required: usize,
        /// Available number of index entries.
        actual: usize,
    },
}

impl From<SecurityContinuityError> for SecurityContinuityScratchError {
    fn from(error: SecurityContinuityError) -> Self {
        Self::Evaluation(error)
    }
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

/// Evaluate continuity with caller-provided index storage.
///
/// Scratch capacity must be at least `assessments.len()`. For at most
/// 16 assessments, scratch is left unchanged. For larger inputs, the
/// first `assessments.len()` entries are overwritten.
/// No heap allocation is performed. Extra scratch capacity is ignored.
///
/// This variant preserves the original evaluator's error precedence for
/// sufficiently sized scratch storage.
pub fn evaluate_security_continuity_with_scratch(
    schedule: &ThreatSchedule<'_>,
    transition: TransitionInterval,
    source: ConfigurationIdentity,
    destination: ConfigurationIdentity,
    requirement: SecurityRequirementId,
    assessments: &[SecurityAssessment],
    scratch: &mut [usize],
) -> Result<SecurityContinuityEvaluation, SecurityContinuityScratchError> {
    if schedule.protection() != transition.protection() {
        return Err(SecurityContinuityError::HorizonMismatch.into());
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
        }
        .into());
    }

    if scratch.len() < assessments.len() {
        return Err(SecurityContinuityScratchError::InsufficientScratch {
            required: assessments.len(),
            actual: scratch.len(),
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
                ActiveConfiguration::Source if interval.start() < cutover => {
                    Some((interval.start(), core::cmp::min(interval.end(), cutover)))
                }
                ActiveConfiguration::Destination if interval.end() > cutover => {
                    Some((core::cmp::max(interval.start(), cutover), interval.end()))
                }
                _ => None,
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
                    }
                    .into());
                }
            }

            index += 1;
        }
    }

    debug_assert_eq!(index, expected);

    // For small inputs, pairwise comparison avoids sorting overhead.
    // The ordering matches the reference evaluator exactly.
    const SMALL_ASSESSMENT_THRESHOLD: usize = 16;

    if assessments.len() <= SMALL_ASSESSMENT_THRESHOLD {
        for second in 1..assessments.len() {
            for first in 0..second {
                if assessments[first].binding() == assessments[second].binding()
                    && assessments[first].acceptability() != assessments[second].acceptability()
                {
                    return Err(
                        SecurityContinuityError::InconsistentAssessment { first, second }.into(),
                    );
                }
            }
        }

        if let Some(segment) = first_unacceptable {
            return Ok(SecurityContinuityEvaluation::Discontinuous(segment));
        }
        if let Some(segment) = first_unknown {
            return Ok(SecurityContinuityEvaluation::Unknown(segment));
        }
        return Ok(SecurityContinuityEvaluation::Continuous);
    }

    let indices = &mut scratch[..assessments.len()];

    for (index, slot) in indices.iter_mut().enumerate() {
        *slot = index;
    }

    // Sort original indices by the complete assessment binding.
    // The final index component makes ordering deterministic.
    indices.sort_unstable_by(|&left, &right| {
        let key = |index: usize| {
            let binding = assessments[index].binding();
            let configuration = binding.configuration();

            (
                configuration.algorithm().value(),
                configuration.parameters().value(),
                configuration.provider().value(),
                configuration.revision().value(),
                binding.threat().value(),
                binding.requirement().value(),
            )
        };

        key(left).cmp(&key(right)).then_with(|| left.cmp(&right))
    });

    // Match the reference evaluator's earliest contradictory pair.
    // Minimize second index first, then first index.
    let mut contradiction: Option<(usize, usize)> = None;
    let mut group_start = 0usize;

    while group_start < indices.len() {
        let binding = assessments[indices[group_start]].binding();
        let mut first_by_outcome: [Option<usize>; 3] = [None; 3];
        let mut group_end = group_start;

        while group_end < indices.len() && assessments[indices[group_end]].binding() == binding {
            let current = indices[group_end];

            let outcome = match assessments[current].acceptability() {
                SecurityAcceptability::Acceptable => 0,
                SecurityAcceptability::Unacceptable => 1,
                SecurityAcceptability::Unknown => 2,
            };

            for (other_outcome, earlier) in first_by_outcome.iter().enumerate() {
                if other_outcome != outcome {
                    if let Some(first) = earlier {
                        let candidate = (*first, current);
                        if contradiction.map_or(true, |existing| {
                            (candidate.1, candidate.0) < (existing.1, existing.0)
                        }) {
                            contradiction = Some(candidate);
                        }
                    }
                }
            }

            if first_by_outcome[outcome].is_none() {
                first_by_outcome[outcome] = Some(current);
            }

            group_end += 1;
        }

        group_start = group_end;
    }

    if let Some((first, second)) = contradiction {
        return Err(SecurityContinuityError::InconsistentAssessment { first, second }.into());
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

    #[test]
    fn scratch_differential_exhaustive_outcomes() {
        // Exhaustively enumerate 3^5 acceptability combinations.
        // Repeated threat identities exercise exact contradiction indices.
        let phases = [
            phase(0, 2, 1),
            phase(2, 4, 2),
            phase(4, 6, 1),
            phase(6, 8, 2),
            phase(8, 10, 1),
        ];
        let schedule = ThreatSchedule::new(&phases, horizon()).unwrap();
        let transition = TransitionInterval::new(horizon(), time(10)).unwrap();

        let outcomes = [
            SecurityAcceptability::Acceptable,
            SecurityAcceptability::Unacceptable,
            SecurityAcceptability::Unknown,
        ];

        for pattern in 0..243usize {
            let mut digits = pattern;
            let mut inputs = [assessment(1, 1, SecurityAcceptability::Acceptable); 5];

            for (index, item) in inputs.iter_mut().enumerate() {
                let outcome = outcomes[digits % 3];
                digits /= 3;
                let threat = if index % 2 == 0 { 1 } else { 2 };
                *item = assessment(1, threat, outcome);
            }

            let reference = evaluate_security_continuity(
                &schedule,
                transition,
                configuration(1),
                configuration(2),
                SecurityRequirementId::new(7),
                &inputs,
            );

            let mut scratch = [usize::MAX; 8];
            let optimized = evaluate_security_continuity_with_scratch(
                &schedule,
                transition,
                configuration(1),
                configuration(2),
                SecurityRequirementId::new(7),
                &inputs,
                &mut scratch,
            );

            assert_eq!(
                optimized,
                reference.map_err(SecurityContinuityScratchError::Evaluation),
                "pattern={pattern}"
            );
            assert_eq!(scratch[5..], [usize::MAX; 3]);
        }
    }

    #[test]
    fn scratch_differential_malformed_binding_precedence() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let schedule = ThreatSchedule::new(&phases, horizon()).unwrap();
        let transition = TransitionInterval::new(horizon(), time(10)).unwrap();

        let inputs = [
            assessment(1, 1, SecurityAcceptability::Unacceptable),
            assessment(9, 2, SecurityAcceptability::Acceptable),
        ];

        let reference = evaluate_security_continuity(
            &schedule,
            transition,
            configuration(1),
            configuration(2),
            SecurityRequirementId::new(7),
            &inputs,
        );

        let mut scratch = [0usize; 2];
        let optimized = evaluate_security_continuity_with_scratch(
            &schedule,
            transition,
            configuration(1),
            configuration(2),
            SecurityRequirementId::new(7),
            &inputs,
            &mut scratch,
        );

        assert_eq!(
            optimized,
            reference.map_err(SecurityContinuityScratchError::Evaluation)
        );
        assert!(matches!(
            optimized,
            Err(SecurityContinuityScratchError::Evaluation(
                SecurityContinuityError::BindingMismatch { assessment: 1, .. }
            ))
        ));
    }

    #[test]
    fn scratch_insufficient_capacity_is_explicit() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let schedule = ThreatSchedule::new(&phases, horizon()).unwrap();
        let transition = TransitionInterval::new(horizon(), time(10)).unwrap();

        let inputs = [
            assessment(1, 1, SecurityAcceptability::Acceptable),
            assessment(1, 2, SecurityAcceptability::Acceptable),
        ];

        let mut scratch = [0usize; 1];
        let result = evaluate_security_continuity_with_scratch(
            &schedule,
            transition,
            configuration(1),
            configuration(2),
            SecurityRequirementId::new(7),
            &inputs,
            &mut scratch,
        );

        assert_eq!(
            result,
            Err(SecurityContinuityScratchError::InsufficientScratch {
                required: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn scratch_differential_threshold_boundary() {
        // Each phase occupies one unit in a 16- or 17-unit horizon.
        // Repeated threat IDs deliberately create identical bindings.
        for count in [16usize, 17] {
            let protection = ProtectionHorizon::new(time(0), time(count as u64)).unwrap();

            let phases: Vec<_> = (0..count)
                .map(|index| phase(index as u64, index as u64 + 1, (index % 3 + 1) as u64))
                .collect();

            let schedule = ThreatSchedule::new(&phases, protection).unwrap();
            let transition = TransitionInterval::new(protection, time(count as u64)).unwrap();

            let outcomes = [
                SecurityAcceptability::Acceptable,
                SecurityAcceptability::Unacceptable,
                SecurityAcceptability::Unknown,
            ];

            for pattern in 0..81usize {
                let mut digits = pattern;

                let inputs: Vec<_> = (0..count)
                    .map(|index| {
                        let outcome = if index < 4 {
                            let value = outcomes[digits % 3];
                            digits /= 3;
                            value
                        } else {
                            outcomes[(index + pattern) % 3]
                        };

                        assessment(1, (index % 3 + 1) as u64, outcome)
                    })
                    .collect();

                let reference = evaluate_security_continuity(
                    &schedule,
                    transition,
                    configuration(1),
                    configuration(2),
                    SecurityRequirementId::new(7),
                    &inputs,
                );

                let mut scratch = vec![usize::MAX; count + 2];

                let optimized = evaluate_security_continuity_with_scratch(
                    &schedule,
                    transition,
                    configuration(1),
                    configuration(2),
                    SecurityRequirementId::new(7),
                    &inputs,
                    &mut scratch,
                );

                assert_eq!(
                    optimized,
                    reference.map_err(SecurityContinuityScratchError::Evaluation),
                    "count={count}, pattern={pattern}"
                );

                assert_eq!(
                    scratch[count..],
                    [usize::MAX; 2],
                    "extra scratch modified: count={count}, pattern={pattern}"
                );

                if count == 16 {
                    assert!(
                        scratch.iter().all(|value| *value == usize::MAX),
                        "small-input path modified scratch"
                    );
                } else {
                    let mut sorted = scratch[..count].to_vec();
                    sorted.sort_unstable();
                    assert_eq!(
                        sorted,
                        (0..count).collect::<Vec<_>>(),
                        "large-input path did not initialize scratch indices"
                    );
                }
            }
        }
    }

    #[test]
    fn scratch_workspace_can_be_reused() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let schedule = ThreatSchedule::new(&phases, horizon()).unwrap();
        let transition = TransitionInterval::new(horizon(), time(10)).unwrap();

        let mut scratch = [usize::MAX; 4];

        for outcome in [
            SecurityAcceptability::Acceptable,
            SecurityAcceptability::Unacceptable,
            SecurityAcceptability::Unknown,
        ] {
            let inputs = [assessment(1, 1, outcome), assessment(1, 2, outcome)];

            let reference = evaluate_security_continuity(
                &schedule,
                transition,
                configuration(1),
                configuration(2),
                SecurityRequirementId::new(7),
                &inputs,
            );

            let optimized = evaluate_security_continuity_with_scratch(
                &schedule,
                transition,
                configuration(1),
                configuration(2),
                SecurityRequirementId::new(7),
                &inputs,
                &mut scratch,
            );

            assert_eq!(
                optimized,
                reference.map_err(SecurityContinuityScratchError::Evaluation)
            );
            assert_eq!(scratch[2..], [usize::MAX; 2]);
        }
    }
}
