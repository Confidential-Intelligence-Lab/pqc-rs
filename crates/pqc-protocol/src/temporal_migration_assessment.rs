//! Advisory integration of horizon security, migration timing,
//! and independently evaluated transition admissibility.
//!
//! Inputs are caller-supplied. This module neither authenticates
//! assessments nor authorizes or executes a migration.

use crate::{
    evaluate_migration_feasibility, AuthorizationDecision, FourPredicateEvaluation,
    HorizonSecurityError, HorizonSecurityEvaluation, IndependentPathSafety, MigrationFeasibility,
    MigrationTimingEvidence, ModelTime,
};

/// Invalid input to the integrated temporal migration assessment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalMigrationError {
    /// The supplied horizon security assessment is invalid.
    Horizon(HorizonSecurityError),
    /// The supplied earliest start precedes observation.
    StartBeforeObservation,
    /// The represented transition path is structurally invalid.
    InvalidPath(IndependentPathSafety),
}

/// Advisory integrated migration result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalMigrationEvaluation {
    /// All inputs were valid and an advisory decision was computed.
    Evaluated(AuthorizationDecision),
    /// The supplied inputs were invalid.
    Invalid(TemporalMigrationError),
}

/// Integrate independently evaluated migration conditions.
///
/// Validation precedence is horizon error, malformed timing evidence,
/// then structural path failure. Valid decisions use the existing
/// Deny > Unknown > Defer > Allow precedence.
///
/// The security input concerns the configuration and horizon evaluated
/// by the caller. This function does not prove protection of the source
/// configuration throughout the migration interval.
///
/// No result is an execution permit.
pub const fn evaluate_temporal_migration(
    security: Result<HorizonSecurityEvaluation, HorizonSecurityError>,
    timing: MigrationTimingEvidence,
    deadline: ModelTime,
    admissibility: FourPredicateEvaluation,
) -> TemporalMigrationEvaluation {
    use AuthorizationDecision::{Allow, Defer, Deny, Unknown};

    let security = match security {
        Ok(value) => value,
        Err(error) => {
            return TemporalMigrationEvaluation::Invalid(TemporalMigrationError::Horizon(error));
        }
    };

    if let MigrationTimingEvidence::UnknownDuration {
        observed_at,
        earliest_start,
    } = timing
    {
        if earliest_start.ticks() < observed_at.ticks() {
            return TemporalMigrationEvaluation::Invalid(
                TemporalMigrationError::StartBeforeObservation,
            );
        }
    }

    let admissibility = match admissibility {
        FourPredicateEvaluation::Evaluated(decision) => decision,
        FourPredicateEvaluation::InvalidPath(path) => {
            return TemporalMigrationEvaluation::Invalid(TemporalMigrationError::InvalidPath(path));
        }
    };

    let security_decision = match security {
        HorizonSecurityEvaluation::Acceptable => Allow,
        HorizonSecurityEvaluation::Unacceptable => Deny,
        HorizonSecurityEvaluation::Unknown => Unknown,
    };

    let timing_decision = match evaluate_migration_feasibility(timing, deadline) {
        MigrationFeasibility::Feasible => Allow,
        MigrationFeasibility::Infeasible => Deny,
        MigrationFeasibility::Unknown => Unknown,
    };

    let decision = if matches!(security_decision, Deny)
        || matches!(timing_decision, Deny)
        || matches!(admissibility, Deny)
    {
        Deny
    } else if matches!(security_decision, Unknown)
        || matches!(timing_decision, Unknown)
        || matches!(admissibility, Unknown)
    {
        Unknown
    } else if matches!(admissibility, Defer) {
        Defer
    } else {
        Allow
    };

    TemporalMigrationEvaluation::Evaluated(decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MigrationDuration, MigrationTiming};

    fn time(value: u64) -> ModelTime {
        ModelTime::new(value)
    }

    fn known(start: u64, duration: u64) -> MigrationTimingEvidence {
        MigrationTimingEvidence::Known(
            MigrationTiming::new(time(0), time(start), MigrationDuration::new(duration)).unwrap(),
        )
    }

    fn evaluate(
        security: Result<HorizonSecurityEvaluation, HorizonSecurityError>,
        timing: MigrationTimingEvidence,
        deadline: u64,
        decision: AuthorizationDecision,
    ) -> TemporalMigrationEvaluation {
        evaluate_temporal_migration(
            security,
            timing,
            time(deadline),
            FourPredicateEvaluation::Evaluated(decision),
        )
    }

    #[test]
    fn all_affirmative_allows() {
        assert_eq!(
            evaluate(
                Ok(HorizonSecurityEvaluation::Acceptable),
                known(2, 3),
                5,
                AuthorizationDecision::Allow
            ),
            TemporalMigrationEvaluation::Evaluated(AuthorizationDecision::Allow)
        );
    }

    #[test]
    fn deadline_failure_denies() {
        assert_eq!(
            evaluate(
                Ok(HorizonSecurityEvaluation::Acceptable),
                known(2, 4),
                5,
                AuthorizationDecision::Allow
            ),
            TemporalMigrationEvaluation::Evaluated(AuthorizationDecision::Deny)
        );
    }

    #[test]
    fn horizon_rejection_denies_even_if_timing_unknown() {
        assert_eq!(
            evaluate(
                Ok(HorizonSecurityEvaluation::Unacceptable),
                MigrationTimingEvidence::UnknownBoth {
                    observed_at: time(0),
                },
                10,
                AuthorizationDecision::Defer
            ),
            TemporalMigrationEvaluation::Evaluated(AuthorizationDecision::Deny)
        );
    }

    #[test]
    fn unknown_precedes_defer() {
        assert_eq!(
            evaluate(
                Ok(HorizonSecurityEvaluation::Unknown),
                known(0, 1),
                10,
                AuthorizationDecision::Defer
            ),
            TemporalMigrationEvaluation::Evaluated(AuthorizationDecision::Unknown)
        );
    }

    #[test]
    fn defer_is_preserved_when_other_conditions_allow() {
        assert_eq!(
            evaluate(
                Ok(HorizonSecurityEvaluation::Acceptable),
                known(0, 1),
                10,
                AuthorizationDecision::Defer
            ),
            TemporalMigrationEvaluation::Evaluated(AuthorizationDecision::Defer)
        );
    }

    #[test]
    fn malformed_timing_is_not_unknown() {
        assert_eq!(
            evaluate(
                Ok(HorizonSecurityEvaluation::Acceptable),
                MigrationTimingEvidence::UnknownDuration {
                    observed_at: time(8),
                    earliest_start: time(7),
                },
                10,
                AuthorizationDecision::Allow
            ),
            TemporalMigrationEvaluation::Invalid(TemporalMigrationError::StartBeforeObservation)
        );
    }

    #[test]
    fn horizon_error_precedes_timing_error() {
        let horizon_error = HorizonSecurityError::AssessmentCountMismatch {
            expected: 2,
            actual: 1,
        };

        assert_eq!(
            evaluate(
                Err(horizon_error),
                MigrationTimingEvidence::UnknownDuration {
                    observed_at: time(8),
                    earliest_start: time(7),
                },
                10,
                AuthorizationDecision::Deny
            ),
            TemporalMigrationEvaluation::Invalid(TemporalMigrationError::Horizon(horizon_error))
        );
    }

    #[test]
    fn disconnected_path_is_invalid_even_when_security_denies() {
        let path = IndependentPathSafety::Disconnected { step: 0 };

        let result = evaluate_temporal_migration(
            Ok(HorizonSecurityEvaluation::Unacceptable),
            known(0, 1),
            time(10),
            FourPredicateEvaluation::InvalidPath(path),
        );

        assert_eq!(
            result,
            TemporalMigrationEvaluation::Invalid(TemporalMigrationError::InvalidPath(path))
        );
    }

    #[test]
    fn invariant_violation_is_invalid_even_when_timing_denies() {
        let path = IndependentPathSafety::InvariantViolation { step: 1 };

        let result = evaluate_temporal_migration(
            Ok(HorizonSecurityEvaluation::Acceptable),
            known(5, 6),
            time(10),
            FourPredicateEvaluation::InvalidPath(path),
        );

        assert_eq!(
            result,
            TemporalMigrationEvaluation::Invalid(TemporalMigrationError::InvalidPath(path))
        );
    }

    #[test]
    fn malformed_timing_precedes_admissibility_denial() {
        let result = evaluate(
            Ok(HorizonSecurityEvaluation::Acceptable),
            MigrationTimingEvidence::UnknownDuration {
                observed_at: time(8),
                earliest_start: time(7),
            },
            10,
            AuthorizationDecision::Deny,
        );

        assert_eq!(
            result,
            TemporalMigrationEvaluation::Invalid(TemporalMigrationError::StartBeforeObservation)
        );
    }

    #[test]
    fn unknown_timing_remains_unknown() {
        assert_eq!(
            evaluate(
                Ok(HorizonSecurityEvaluation::Acceptable),
                MigrationTimingEvidence::UnknownBoth {
                    observed_at: time(0),
                },
                10,
                AuthorizationDecision::Allow
            ),
            TemporalMigrationEvaluation::Evaluated(AuthorizationDecision::Unknown)
        );
    }

    #[test]
    fn timing_infeasibility_dominates_unknown_security() {
        assert_eq!(
            evaluate(
                Ok(HorizonSecurityEvaluation::Unknown),
                known(5, 6),
                10,
                AuthorizationDecision::Allow
            ),
            TemporalMigrationEvaluation::Evaluated(AuthorizationDecision::Deny)
        );
    }
}
