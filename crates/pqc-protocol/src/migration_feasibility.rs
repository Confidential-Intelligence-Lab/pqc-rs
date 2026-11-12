//! Advisory migration feasibility against a security deadline.
//!
//! The deadline is an inclusive latest-completion instant.
//! Feasibility here concerns timing only, not transition authorization,
//! cryptographic security, or operational readiness.

use crate::{MigrationDuration, MigrationTiming, ModelTime};

/// Caller-supplied information about migration start and duration.
///
/// Missing timing inputs are represented explicitly rather than inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationTimingEvidence {
    /// Both earliest start and duration are known and validated.
    Known(MigrationTiming),
    /// Earliest start is known, but duration is unavailable.
    UnknownDuration {
        /// Observation time.
        observed_at: ModelTime,
        /// Earliest permissible start.
        earliest_start: ModelTime,
    },
    /// Earliest start is unavailable, but duration is known.
    UnknownStart {
        /// Observation time.
        observed_at: ModelTime,
        /// Known migration duration.
        duration: MigrationDuration,
    },
    /// Neither earliest start nor duration is available.
    UnknownBoth {
        /// Observation time.
        observed_at: ModelTime,
    },
}

/// Timing-only migration feasibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationFeasibility {
    /// Completion can occur by the inclusive deadline.
    Feasible,
    /// Completion cannot occur by the inclusive deadline.
    Infeasible,
    /// Available timing evidence cannot establish either conclusion.
    Unknown,
}

/// Evaluate migration timing against an inclusive security deadline.
///
/// All times use the same caller-defined logical tick domain.
///
/// Unknown durations are nonnegative, and unknown starts cannot precede
/// observation. These lower bounds can prove infeasibility even when
/// some timing information is missing.
///
/// This advisory result does not authorize execution.
pub const fn evaluate_migration_feasibility(
    evidence: MigrationTimingEvidence,
    deadline: ModelTime,
) -> MigrationFeasibility {
    use MigrationFeasibility::{Feasible, Infeasible, Unknown};

    match evidence {
        MigrationTimingEvidence::Known(timing) => {
            if deadline.ticks() < timing.observed_at().ticks() {
                return Infeasible;
            }

            match timing.earliest_completion() {
                Ok(completion) => {
                    if completion.ticks() <= deadline.ticks() {
                        Feasible
                    } else {
                        Infeasible
                    }
                }
                Err(_) => Infeasible,
            }
        }
        MigrationTimingEvidence::UnknownDuration {
            observed_at,
            earliest_start,
        } => {
            // Reject impossible supplied constraints conservatively.
            if earliest_start.ticks() < observed_at.ticks() {
                return Unknown;
            }

            if earliest_start.ticks() > deadline.ticks() {
                Infeasible
            } else {
                Unknown
            }
        }
        MigrationTimingEvidence::UnknownStart {
            observed_at,
            duration,
        } => {
            // Observation is a lower bound on any permissible start.
            match observed_at.ticks().checked_add(duration.ticks()) {
                Some(earliest_possible) if earliest_possible <= deadline.ticks() => Unknown,
                _ => Infeasible,
            }
        }
        MigrationTimingEvidence::UnknownBoth { observed_at } => {
            if observed_at.ticks() > deadline.ticks() {
                Infeasible
            } else {
                Unknown
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(value: u64) -> ModelTime {
        ModelTime::new(value)
    }

    fn known(start: u64, duration: u64) -> MigrationTimingEvidence {
        MigrationTimingEvidence::Known(
            MigrationTiming::new(time(0), time(start), MigrationDuration::new(duration)).unwrap(),
        )
    }

    #[test]
    fn completion_before_deadline_is_feasible() {
        assert_eq!(
            evaluate_migration_feasibility(known(2, 3), time(6)),
            MigrationFeasibility::Feasible
        );
    }

    #[test]
    fn completion_at_deadline_is_feasible() {
        assert_eq!(
            evaluate_migration_feasibility(known(2, 3), time(5)),
            MigrationFeasibility::Feasible
        );
    }

    #[test]
    fn completion_after_deadline_is_infeasible() {
        assert_eq!(
            evaluate_migration_feasibility(known(2, 3), time(4)),
            MigrationFeasibility::Infeasible
        );
    }

    #[test]
    fn deadline_before_observation_is_infeasible() {
        let timing = MigrationTiming::new(time(10), time(10), MigrationDuration::new(0)).unwrap();

        assert_eq!(
            evaluate_migration_feasibility(MigrationTimingEvidence::Known(timing), time(9)),
            MigrationFeasibility::Infeasible
        );
    }

    #[test]
    fn overflow_is_infeasible() {
        assert_eq!(
            evaluate_migration_feasibility(known(u64::MAX, 1), time(u64::MAX)),
            MigrationFeasibility::Infeasible
        );
    }

    #[test]
    fn unknown_duration_can_be_infeasible() {
        let evidence = MigrationTimingEvidence::UnknownDuration {
            observed_at: time(0),
            earliest_start: time(8),
        };

        assert_eq!(
            evaluate_migration_feasibility(evidence, time(7)),
            MigrationFeasibility::Infeasible
        );
    }

    #[test]
    fn unknown_duration_remains_unknown_when_start_fits() {
        let evidence = MigrationTimingEvidence::UnknownDuration {
            observed_at: time(0),
            earliest_start: time(8),
        };

        assert_eq!(
            evaluate_migration_feasibility(evidence, time(8)),
            MigrationFeasibility::Unknown
        );
    }

    #[test]
    fn unknown_start_can_be_infeasible_from_lower_bound() {
        let evidence = MigrationTimingEvidence::UnknownStart {
            observed_at: time(5),
            duration: MigrationDuration::new(4),
        };

        assert_eq!(
            evaluate_migration_feasibility(evidence, time(8)),
            MigrationFeasibility::Infeasible
        );
    }

    #[test]
    fn unknown_start_remains_unknown_when_lower_bound_fits() {
        let evidence = MigrationTimingEvidence::UnknownStart {
            observed_at: time(5),
            duration: MigrationDuration::new(4),
        };

        assert_eq!(
            evaluate_migration_feasibility(evidence, time(9)),
            MigrationFeasibility::Unknown
        );
    }

    #[test]
    fn unknown_start_overflow_is_infeasible() {
        let evidence = MigrationTimingEvidence::UnknownStart {
            observed_at: time(u64::MAX),
            duration: MigrationDuration::new(1),
        };

        assert_eq!(
            evaluate_migration_feasibility(evidence, time(u64::MAX)),
            MigrationFeasibility::Infeasible
        );
    }

    #[test]
    fn unknown_both_is_infeasible_after_deadline() {
        let evidence = MigrationTimingEvidence::UnknownBoth {
            observed_at: time(10),
        };

        assert_eq!(
            evaluate_migration_feasibility(evidence, time(9)),
            MigrationFeasibility::Infeasible
        );
    }

    #[test]
    fn unknown_both_remains_unknown_before_deadline() {
        let evidence = MigrationTimingEvidence::UnknownBoth {
            observed_at: time(5),
        };

        assert_eq!(
            evaluate_migration_feasibility(evidence, time(9)),
            MigrationFeasibility::Unknown
        );
    }

    #[test]
    fn zero_duration_at_deadline_is_feasible() {
        assert_eq!(
            evaluate_migration_feasibility(known(5, 0), time(5)),
            MigrationFeasibility::Feasible
        );
    }

    #[test]
    fn invalid_unknown_duration_start_is_not_accepted() {
        let evidence = MigrationTimingEvidence::UnknownDuration {
            observed_at: time(8),
            earliest_start: time(7),
        };

        assert_eq!(
            evaluate_migration_feasibility(evidence, time(10)),
            MigrationFeasibility::Unknown
        );
    }
}
