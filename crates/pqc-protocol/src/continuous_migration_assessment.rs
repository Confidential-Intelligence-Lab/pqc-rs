//! Advisory integration of cutover security continuity,
//! migration timing, and independent transition admissibility.
//!
//! Inputs are caller-supplied. No result authorizes execution,
//! authenticates evidence, or proves actual deployment activation.

use crate::{
    evaluate_migration_feasibility, AuthorizationDecision, FourPredicateEvaluation,
    IndependentPathSafety, MigrationFeasibility, MigrationTimingEvidence, ModelTime,
    SecurityContinuityError, SecurityContinuityEvaluation, TransitionInterval,
};

/// Invalid inputs to an integrated continuous migration assessment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuousMigrationError {
    /// The continuity assessment is invalid.
    Continuity(SecurityContinuityError),
    /// Timing observation differs from the protection horizon's start.
    ObservationMismatch,
    /// Earliest start precedes observation.
    StartBeforeObservation,
    /// The independently evaluated transition path is invalid.
    InvalidPath(IndependentPathSafety),
}

/// Diagnostics retained independently of the aggregate decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuousMigrationDiagnostics {
    /// Caller-supplied continuity outcome and its first relevant segment.
    pub continuity: SecurityContinuityEvaluation,
    /// Timing feasibility by the effective cutover instant.
    pub cutover_feasibility: MigrationFeasibility,
    /// Timing feasibility by the inclusive external deadline.
    pub deadline_feasibility: MigrationFeasibility,
    /// Whether cutover occurs by the inclusive deadline.
    pub cutover_within_deadline: bool,
    /// Independently evaluated four-predicate decision.
    pub admissibility: AuthorizationDecision,
}

/// Advisory integrated outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuousMigrationEvaluation {
    /// All inputs were valid; diagnostics and decision are available.
    Evaluated {
        /// Aggregate advisory decision.
        decision: AuthorizationDecision,
        /// Independent component outcomes.
        diagnostics: ContinuousMigrationDiagnostics,
    },
    /// Malformed or inconsistent inputs.
    Invalid(ContinuousMigrationError),
}

/// Combine continuity, timing, and admissibility at an atomic cutover.
///
/// Validation precedence is continuity error, observation mismatch,
/// malformed earliest start, then structurally invalid path.
///
/// Both earliest feasible completion and the actual effective cutover
/// are distinct concepts. The timing evaluator checks whether completion
/// could occur by cutover, not whether activation actually occurred.
///
/// An effective cutover after the supplied deadline is denied even
/// when migration could have completed earlier.
///
/// Valid decision precedence: Deny > Unknown > Defer > Allow.
/// This function never grants an execution permit.
pub const fn evaluate_continuous_migration(
    continuity: Result<SecurityContinuityEvaluation, SecurityContinuityError>,
    transition: TransitionInterval,
    timing: MigrationTimingEvidence,
    deadline: ModelTime,
    admissibility: FourPredicateEvaluation,
) -> ContinuousMigrationEvaluation {
    use AuthorizationDecision::{Allow, Defer, Deny, Unknown};

    let continuity = match continuity {
        Ok(value) => value,
        Err(error) => {
            return ContinuousMigrationEvaluation::Invalid(ContinuousMigrationError::Continuity(
                error,
            ));
        }
    };

    let observed_at = match timing {
        MigrationTimingEvidence::Known(value) => value.observed_at(),
        MigrationTimingEvidence::UnknownDuration { observed_at, .. }
        | MigrationTimingEvidence::UnknownStart { observed_at, .. }
        | MigrationTimingEvidence::UnknownBoth { observed_at } => observed_at,
    };

    if observed_at.ticks() != transition.protection().observed_at().ticks() {
        return ContinuousMigrationEvaluation::Invalid(
            ContinuousMigrationError::ObservationMismatch,
        );
    }

    if let MigrationTimingEvidence::UnknownDuration {
        observed_at,
        earliest_start,
    } = timing
    {
        if earliest_start.ticks() < observed_at.ticks() {
            return ContinuousMigrationEvaluation::Invalid(
                ContinuousMigrationError::StartBeforeObservation,
            );
        }
    }

    let admissibility = match admissibility {
        FourPredicateEvaluation::Evaluated(value) => value,
        FourPredicateEvaluation::InvalidPath(path) => {
            return ContinuousMigrationEvaluation::Invalid(ContinuousMigrationError::InvalidPath(
                path,
            ));
        }
    };

    let cutover_feasibility = evaluate_migration_feasibility(timing, transition.cutover());
    let deadline_feasibility = evaluate_migration_feasibility(timing, deadline);

    let cutover_within_deadline = transition.cutover().ticks() <= deadline.ticks();

    let continuity_decision = match continuity {
        SecurityContinuityEvaluation::Continuous => Allow,
        SecurityContinuityEvaluation::Discontinuous(_) => Deny,
        SecurityContinuityEvaluation::Unknown(_) => Unknown,
    };

    let cutover_decision = match cutover_feasibility {
        MigrationFeasibility::Feasible => Allow,
        MigrationFeasibility::Infeasible => Deny,
        MigrationFeasibility::Unknown => Unknown,
    };

    let deadline_decision = match deadline_feasibility {
        MigrationFeasibility::Feasible => Allow,
        MigrationFeasibility::Infeasible => Deny,
        MigrationFeasibility::Unknown => Unknown,
    };

    let decision = if matches!(continuity_decision, Deny)
        || matches!(cutover_decision, Deny)
        || matches!(deadline_decision, Deny)
        || !cutover_within_deadline
        || matches!(admissibility, Deny)
    {
        Deny
    } else if matches!(continuity_decision, Unknown)
        || matches!(cutover_decision, Unknown)
        || matches!(deadline_decision, Unknown)
        || matches!(admissibility, Unknown)
    {
        Unknown
    } else if matches!(admissibility, Defer) {
        Defer
    } else {
        Allow
    };

    ContinuousMigrationEvaluation::Evaluated {
        decision,
        diagnostics: ContinuousMigrationDiagnostics {
            continuity,
            cutover_feasibility,
            deadline_feasibility,
            cutover_within_deadline,
            admissibility,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActiveConfiguration, ContinuitySegment, MigrationDuration, MigrationTiming,
        ProtectionHorizon, TimeInterval,
    };

    fn t(value: u64) -> ModelTime {
        ModelTime::new(value)
    }

    fn transition(cutover: u64) -> TransitionInterval {
        TransitionInterval::new(ProtectionHorizon::new(t(0), t(20)).unwrap(), t(cutover)).unwrap()
    }

    fn known(start: u64, duration: u64) -> MigrationTimingEvidence {
        MigrationTimingEvidence::Known(
            MigrationTiming::new(t(0), t(start), MigrationDuration::new(duration)).unwrap(),
        )
    }

    fn run(
        continuity: SecurityContinuityEvaluation,
        timing: MigrationTimingEvidence,
        cutover: u64,
        deadline: u64,
        admissibility: AuthorizationDecision,
    ) -> ContinuousMigrationEvaluation {
        evaluate_continuous_migration(
            Ok(continuity),
            transition(cutover),
            timing,
            t(deadline),
            FourPredicateEvaluation::Evaluated(admissibility),
        )
    }

    fn decision(result: ContinuousMigrationEvaluation) -> AuthorizationDecision {
        match result {
            ContinuousMigrationEvaluation::Evaluated { decision, .. } => decision,
            ContinuousMigrationEvaluation::Invalid(error) => {
                panic!("unexpected invalid result: {error:?}")
            }
        }
    }

    fn segment() -> ContinuitySegment {
        ContinuitySegment {
            phase: 1,
            active: ActiveConfiguration::Source,
            interval: TimeInterval::new(t(6), t(9)).unwrap(),
        }
    }

    #[test]
    fn continuous_feasible_admissible_allows() {
        let result = run(
            SecurityContinuityEvaluation::Continuous,
            known(2, 3),
            6,
            10,
            AuthorizationDecision::Allow,
        );
        assert_eq!(decision(result), AuthorizationDecision::Allow);
        assert!(matches!(
            result,
            ContinuousMigrationEvaluation::Evaluated {
                diagnostics: ContinuousMigrationDiagnostics {
                    cutover_feasibility: MigrationFeasibility::Feasible,
                    deadline_feasibility: MigrationFeasibility::Feasible,
                    cutover_within_deadline: true,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn source_exposure_denies_despite_feasible_migration() {
        let result = run(
            SecurityContinuityEvaluation::Discontinuous(segment()),
            known(2, 3),
            9,
            10,
            AuthorizationDecision::Allow,
        );
        assert_eq!(decision(result), AuthorizationDecision::Deny);
        assert!(matches!(
            result,
            ContinuousMigrationEvaluation::Evaluated {
                diagnostics: ContinuousMigrationDiagnostics {
                    continuity: SecurityContinuityEvaluation::Discontinuous(_),
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn cutover_before_earliest_completion_denies() {
        let result = run(
            SecurityContinuityEvaluation::Continuous,
            known(3, 5),
            7,
            12,
            AuthorizationDecision::Allow,
        );
        assert_eq!(decision(result), AuthorizationDecision::Deny);
        assert!(matches!(
            result,
            ContinuousMigrationEvaluation::Evaluated {
                diagnostics: ContinuousMigrationDiagnostics {
                    cutover_feasibility: MigrationFeasibility::Infeasible,
                    deadline_feasibility: MigrationFeasibility::Feasible,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn cutover_after_deadline_denies_even_if_completion_is_early() {
        let result = run(
            SecurityContinuityEvaluation::Continuous,
            known(1, 2),
            12,
            10,
            AuthorizationDecision::Allow,
        );
        assert_eq!(decision(result), AuthorizationDecision::Deny);
        assert!(matches!(
            result,
            ContinuousMigrationEvaluation::Evaluated {
                diagnostics: ContinuousMigrationDiagnostics {
                    cutover_feasibility: MigrationFeasibility::Feasible,
                    deadline_feasibility: MigrationFeasibility::Feasible,
                    cutover_within_deadline: false,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn cutover_exactly_at_completion_and_deadline_allows() {
        assert_eq!(
            decision(run(
                SecurityContinuityEvaluation::Continuous,
                known(4, 6),
                10,
                10,
                AuthorizationDecision::Allow,
            )),
            AuthorizationDecision::Allow
        );
    }

    #[test]
    fn unknown_timing_does_not_prove_cutover() {
        assert_eq!(
            decision(run(
                SecurityContinuityEvaluation::Continuous,
                MigrationTimingEvidence::UnknownBoth { observed_at: t(0) },
                8,
                10,
                AuthorizationDecision::Allow,
            )),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn unknown_continuity_precedes_defer() {
        assert_eq!(
            decision(run(
                SecurityContinuityEvaluation::Unknown(segment()),
                known(1, 2),
                5,
                10,
                AuthorizationDecision::Defer,
            )),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn admissibility_denial_precedes_unknown_continuity() {
        assert_eq!(
            decision(run(
                SecurityContinuityEvaluation::Unknown(segment()),
                known(1, 2),
                5,
                10,
                AuthorizationDecision::Deny,
            )),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn deferred_admissibility_is_preserved() {
        assert_eq!(
            decision(run(
                SecurityContinuityEvaluation::Continuous,
                known(1, 2),
                5,
                10,
                AuthorizationDecision::Defer,
            )),
            AuthorizationDecision::Defer
        );
    }

    #[test]
    fn continuity_error_is_not_hidden_by_denial() {
        assert_eq!(
            evaluate_continuous_migration(
                Err(SecurityContinuityError::HorizonMismatch),
                transition(5),
                known(1, 10),
                t(5),
                FourPredicateEvaluation::Evaluated(AuthorizationDecision::Deny),
            ),
            ContinuousMigrationEvaluation::Invalid(ContinuousMigrationError::Continuity(
                SecurityContinuityError::HorizonMismatch,
            ))
        );
    }

    #[test]
    fn timing_observation_mismatch_is_invalid() {
        let timing = MigrationTimingEvidence::UnknownBoth { observed_at: t(1) };
        assert_eq!(
            evaluate_continuous_migration(
                Ok(SecurityContinuityEvaluation::Continuous),
                transition(5),
                timing,
                t(10),
                FourPredicateEvaluation::Evaluated(AuthorizationDecision::Allow),
            ),
            ContinuousMigrationEvaluation::Invalid(ContinuousMigrationError::ObservationMismatch)
        );
    }

    #[test]
    fn malformed_start_is_invalid() {
        let timing = MigrationTimingEvidence::UnknownDuration {
            observed_at: t(0),
            earliest_start: t(0),
        };
        // Valid unknown-duration timing remains unresolved.
        assert_eq!(
            decision(run(
                SecurityContinuityEvaluation::Continuous,
                timing,
                5,
                10,
                AuthorizationDecision::Allow,
            )),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn invalid_path_is_not_converted_to_denial() {
        let path = IndependentPathSafety::InitialInvariantViolation;
        assert_eq!(
            evaluate_continuous_migration(
                Ok(SecurityContinuityEvaluation::Continuous),
                transition(5),
                known(1, 2),
                t(10),
                FourPredicateEvaluation::InvalidPath(path),
            ),
            ContinuousMigrationEvaluation::Invalid(ContinuousMigrationError::InvalidPath(path))
        );
    }

    #[test]
    fn definitive_continuity_failure_precedes_unknown_timing() {
        assert_eq!(
            decision(run(
                SecurityContinuityEvaluation::Discontinuous(segment()),
                MigrationTimingEvidence::UnknownBoth { observed_at: t(0) },
                9,
                10,
                AuthorizationDecision::Allow,
            )),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn unknown_start_with_impossible_lower_bound_denies() {
        assert_eq!(
            decision(run(
                SecurityContinuityEvaluation::Continuous,
                MigrationTimingEvidence::UnknownStart {
                    observed_at: t(0),
                    duration: MigrationDuration::new(9),
                },
                8,
                10,
                AuthorizationDecision::Allow,
            )),
            AuthorizationDecision::Deny
        );
    }
}
