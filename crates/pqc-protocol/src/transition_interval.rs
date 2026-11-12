//! Advisory atomic-cutover responsibility intervals.
//!
//! A cutover is a caller-supplied effective activation instant.
//! It is not inferred from migration completion or authorization.
//! The model assumes exactly one responsible configuration at each
//! instant in the protection horizon.

use crate::{ModelTime, ProtectionHorizon, TimeInterval};

/// Invalid atomic-cutover construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionIntervalError {
    /// Effective cutover precedes observation.
    CutoverBeforeObservation,
    /// Effective cutover exceeds the exclusive protection horizon.
    CutoverAfterHorizon,
}

/// Which configuration is responsible at a modeled instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveConfiguration {
    /// The source configuration is responsible.
    Source,
    /// The destination configuration is responsible.
    Destination,
}

/// Validated atomic cutover within a protection horizon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionInterval {
    protection: ProtectionHorizon,
    cutover: ModelTime,
}

impl TransitionInterval {
    /// Construct a cutover within the closed boundary range
    /// from observation through the exclusive horizon endpoint.
    pub const fn new(
        protection: ProtectionHorizon,
        cutover: ModelTime,
    ) -> Result<Self, TransitionIntervalError> {
        if cutover.ticks() < protection.observed_at().ticks() {
            return Err(TransitionIntervalError::CutoverBeforeObservation);
        }

        if cutover.ticks() > protection.required_until().ticks() {
            return Err(TransitionIntervalError::CutoverAfterHorizon);
        }

        Ok(Self {
            protection,
            cutover,
        })
    }

    /// Return the validated protection horizon.
    pub const fn protection(self) -> ProtectionHorizon {
        self.protection
    }

    /// Return the caller-supplied effective cutover instant.
    pub const fn cutover(self) -> ModelTime {
        self.cutover
    }

    /// Return the source responsibility interval, if nonempty.
    ///
    /// The source is responsible over [observation, cutover).
    pub const fn source_interval(self) -> Option<TimeInterval> {
        if self.cutover.ticks() == self.protection.observed_at().ticks() {
            None
        } else {
            match TimeInterval::new(self.protection.observed_at(), self.cutover) {
                Ok(interval) => Some(interval),
                Err(_) => None,
            }
        }
    }

    /// Return the destination responsibility interval, if nonempty.
    ///
    /// The destination is responsible over [cutover, horizon).
    pub const fn destination_interval(self) -> Option<TimeInterval> {
        if self.cutover.ticks() == self.protection.required_until().ticks() {
            None
        } else {
            match TimeInterval::new(self.cutover, self.protection.required_until()) {
                Ok(interval) => Some(interval),
                Err(_) => None,
            }
        }
    }

    /// Return the responsible configuration at a time in the horizon.
    ///
    /// Returns None outside the protection horizon.
    pub const fn active_at(self, time: ModelTime) -> Option<ActiveConfiguration> {
        if time.ticks() < self.protection.observed_at().ticks()
            || time.ticks() >= self.protection.required_until().ticks()
        {
            None
        } else if time.ticks() < self.cutover.ticks() {
            Some(ActiveConfiguration::Source)
        } else {
            Some(ActiveConfiguration::Destination)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(ticks: u64) -> ModelTime {
        ModelTime::new(ticks)
    }

    fn horizon() -> ProtectionHorizon {
        ProtectionHorizon::new(time(2), time(10)).unwrap()
    }

    #[test]
    fn interior_cutover_partitions_horizon() {
        let transition = TransitionInterval::new(horizon(), time(6)).unwrap();

        assert_eq!(transition.protection(), horizon());
        assert_eq!(transition.cutover(), time(6));
        assert_eq!(
            transition.source_interval(),
            Some(TimeInterval::new(time(2), time(6)).unwrap())
        );
        assert_eq!(
            transition.destination_interval(),
            Some(TimeInterval::new(time(6), time(10)).unwrap())
        );
    }

    #[test]
    fn cutover_belongs_to_destination() {
        let transition = TransitionInterval::new(horizon(), time(6)).unwrap();

        assert_eq!(
            transition.active_at(time(5)),
            Some(ActiveConfiguration::Source)
        );
        assert_eq!(
            transition.active_at(time(6)),
            Some(ActiveConfiguration::Destination)
        );
    }

    #[test]
    fn immediate_cutover_has_no_source_interval() {
        let transition = TransitionInterval::new(horizon(), time(2)).unwrap();

        assert_eq!(transition.source_interval(), None);
        assert_eq!(
            transition.destination_interval(),
            Some(horizon().interval())
        );
        assert_eq!(
            transition.active_at(time(2)),
            Some(ActiveConfiguration::Destination)
        );
    }

    #[test]
    fn horizon_cutover_has_no_destination_interval() {
        let transition = TransitionInterval::new(horizon(), time(10)).unwrap();

        assert_eq!(transition.destination_interval(), None);
        assert_eq!(transition.source_interval(), Some(horizon().interval()));
        assert_eq!(
            transition.active_at(time(9)),
            Some(ActiveConfiguration::Source)
        );
    }

    #[test]
    fn cutover_before_observation_is_rejected() {
        assert_eq!(
            TransitionInterval::new(horizon(), time(1)),
            Err(TransitionIntervalError::CutoverBeforeObservation)
        );
    }

    #[test]
    fn cutover_after_horizon_is_rejected() {
        assert_eq!(
            TransitionInterval::new(horizon(), time(11)),
            Err(TransitionIntervalError::CutoverAfterHorizon)
        );
    }

    #[test]
    fn outside_horizon_has_no_active_configuration() {
        let transition = TransitionInterval::new(horizon(), time(6)).unwrap();

        assert_eq!(transition.active_at(time(1)), None);
        assert_eq!(transition.active_at(time(10)), None);
    }

    #[test]
    fn last_included_tick_is_assigned() {
        let transition = TransitionInterval::new(horizon(), time(6)).unwrap();

        assert_eq!(
            transition.active_at(time(9)),
            Some(ActiveConfiguration::Destination)
        );
    }

    #[test]
    fn maximum_tick_boundary_is_safe() {
        let protection = ProtectionHorizon::new(time(u64::MAX - 1), time(u64::MAX)).unwrap();
        let transition = TransitionInterval::new(protection, time(u64::MAX)).unwrap();

        assert_eq!(transition.destination_interval(), None);
        assert_eq!(
            transition.active_at(time(u64::MAX - 1)),
            Some(ActiveConfiguration::Source)
        );
        assert_eq!(transition.active_at(time(u64::MAX)), None);
    }

    #[test]
    fn each_tick_has_exactly_one_responsible_configuration() {
        for cutover in 2..=10 {
            let transition = TransitionInterval::new(horizon(), time(cutover)).unwrap();

            for tick in 2..10 {
                let active = transition.active_at(time(tick));
                assert!(matches!(
                    active,
                    Some(ActiveConfiguration::Source) | Some(ActiveConfiguration::Destination)
                ));

                assert_eq!(active == Some(ActiveConfiguration::Source), tick < cutover);
            }
        }
    }
}
