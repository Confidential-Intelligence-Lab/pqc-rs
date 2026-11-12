//! Advisory migration timing in a caller-defined logical time domain.
//!
//! Timing inputs are externally supplied. This module does not infer
//! operational readiness, enforce migration, or assess security deadlines.

use crate::ModelTime;

/// Nonnegative migration duration in logical ticks.
///
/// The caller must use the same tick scale as `ModelTime`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationDuration(u64);

impl MigrationDuration {
    /// Construct a migration duration.
    pub const fn new(ticks: u64) -> Self {
        Self(ticks)
    }

    /// Return the duration in logical ticks.
    pub const fn ticks(self) -> u64 {
        self.0
    }
}

/// Invalid migration timing inputs or arithmetic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationTimingError {
    /// The earliest permissible start precedes observation.
    StartBeforeObservation,
    /// Computing the completion time would overflow logical time.
    CompletionOverflow,
}

/// Caller-supplied migration timing constraints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationTiming {
    observed_at: ModelTime,
    earliest_start: ModelTime,
    duration: MigrationDuration,
}

impl MigrationTiming {
    /// Construct timing constraints with a non-retroactive start.
    ///
    /// A zero-duration migration is permitted as a model boundary case.
    /// Completion-time arithmetic is checked separately.
    pub const fn new(
        observed_at: ModelTime,
        earliest_start: ModelTime,
        duration: MigrationDuration,
    ) -> Result<Self, MigrationTimingError> {
        if earliest_start.ticks() < observed_at.ticks() {
            return Err(MigrationTimingError::StartBeforeObservation);
        }

        Ok(Self {
            observed_at,
            earliest_start,
            duration,
        })
    }

    /// Return the observation time.
    pub const fn observed_at(self) -> ModelTime {
        self.observed_at
    }

    /// Return the earliest permissible migration start.
    pub const fn earliest_start(self) -> ModelTime {
        self.earliest_start
    }

    /// Return the caller-supplied migration duration.
    pub const fn duration(self) -> MigrationDuration {
        self.duration
    }

    /// Calculate the earliest completion time without arithmetic overflow.
    ///
    /// This calculation does not establish deadline feasibility.
    pub const fn earliest_completion(self) -> Result<ModelTime, MigrationTimingError> {
        match self
            .earliest_start
            .ticks()
            .checked_add(self.duration.ticks())
        {
            Some(ticks) => Ok(ModelTime::new(ticks)),
            None => Err(MigrationTimingError::CompletionOverflow),
        }
    }
}

/// Evaluate the earliest completion time for validated timing constraints.
///
/// The returned time is advisory and is not an authorization decision.
pub const fn evaluate_migration_timing(
    timing: MigrationTiming,
) -> Result<ModelTime, MigrationTimingError> {
    timing.earliest_completion()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(ticks: u64) -> ModelTime {
        ModelTime::new(ticks)
    }

    #[test]
    fn duration_round_trip() {
        assert_eq!(MigrationDuration::new(42).ticks(), 42);
    }

    #[test]
    fn timing_accessors_preserve_inputs() {
        let timing = MigrationTiming::new(time(2), time(5), MigrationDuration::new(7)).unwrap();

        assert_eq!(timing.observed_at(), time(2));
        assert_eq!(timing.earliest_start(), time(5));
        assert_eq!(timing.duration(), MigrationDuration::new(7));
    }

    #[test]
    fn immediate_start_is_permitted() {
        let timing = MigrationTiming::new(time(3), time(3), MigrationDuration::new(4)).unwrap();

        assert_eq!(evaluate_migration_timing(timing), Ok(time(7)));
    }

    #[test]
    fn delayed_start_changes_completion() {
        let timing = MigrationTiming::new(time(3), time(8), MigrationDuration::new(4)).unwrap();

        assert_eq!(evaluate_migration_timing(timing), Ok(time(12)));
    }

    #[test]
    fn start_before_observation_is_rejected() {
        assert_eq!(
            MigrationTiming::new(time(8), time(7), MigrationDuration::new(1)),
            Err(MigrationTimingError::StartBeforeObservation)
        );
    }

    #[test]
    fn zero_duration_completes_at_start() {
        let timing = MigrationTiming::new(time(1), time(9), MigrationDuration::new(0)).unwrap();

        assert_eq!(evaluate_migration_timing(timing), Ok(time(9)));
    }

    #[test]
    fn completion_at_maximum_tick_is_valid() {
        let timing =
            MigrationTiming::new(time(0), time(u64::MAX - 1), MigrationDuration::new(1)).unwrap();

        assert_eq!(evaluate_migration_timing(timing), Ok(time(u64::MAX)));
    }

    #[test]
    fn completion_overflow_is_explicit() {
        let timing =
            MigrationTiming::new(time(0), time(u64::MAX), MigrationDuration::new(1)).unwrap();

        assert_eq!(
            evaluate_migration_timing(timing),
            Err(MigrationTimingError::CompletionOverflow)
        );
    }
}
