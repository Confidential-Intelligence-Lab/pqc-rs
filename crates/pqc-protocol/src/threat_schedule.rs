//! Allocation-free representation of time-varying threat assumptions.
//!
//! A schedule describes caller-supplied threat identities. It does not
//! establish threat authenticity or cryptographic security.

use crate::{ModelTime, ProtectionHorizon, ThreatPhaseId, TimeInterval};

/// A threat identity applicable over a nonempty interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreatPhase {
    interval: TimeInterval,
    threat: ThreatPhaseId,
}

impl ThreatPhase {
    /// Construct a phase using a validated interval.
    pub const fn new(interval: TimeInterval, threat: ThreatPhaseId) -> Self {
        Self { interval, threat }
    }

    /// Return the phase interval.
    pub const fn interval(self) -> TimeInterval {
        self.interval
    }

    /// Return the threat identity.
    pub const fn threat(self) -> ThreatPhaseId {
        self.threat
    }
}

/// Structural errors in a represented threat schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreatScheduleError {
    /// No phases were supplied.
    Empty,
    /// The first phase does not start at the protection horizon.
    StartMismatch,
    /// A phase ends before the next phase starts.
    Gap {
        /// Index of the phase starting after the gap.
        phase: usize,
    },
    /// A phase overlaps or follows a later phase out of order.
    OverlapOrRegression {
        /// Index of the overlapping or out-of-order phase.
        phase: usize,
    },
    /// The last phase does not end at the protection deadline.
    EndMismatch,
}

/// Borrowed, validated threat phases covering a protection horizon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreatSchedule<'a> {
    phases: &'a [ThreatPhase],
    protection: ProtectionHorizon,
}

impl<'a> ThreatSchedule<'a> {
    /// Validate complete, contiguous coverage of the protection interval.
    pub fn new(
        phases: &'a [ThreatPhase],
        protection: ProtectionHorizon,
    ) -> Result<Self, ThreatScheduleError> {
        let Some(first) = phases.first() else {
            return Err(ThreatScheduleError::Empty);
        };

        if first.interval().start() != protection.observed_at() {
            return Err(ThreatScheduleError::StartMismatch);
        }

        for index in 1..phases.len() {
            let previous_end = phases[index - 1].interval().end();
            let current_start = phases[index].interval().start();

            if current_start > previous_end {
                return Err(ThreatScheduleError::Gap { phase: index });
            }
            if current_start < previous_end {
                return Err(ThreatScheduleError::OverlapOrRegression { phase: index });
            }
        }

        if phases[phases.len() - 1].interval().end() != protection.required_until() {
            return Err(ThreatScheduleError::EndMismatch);
        }

        Ok(Self { phases, protection })
    }

    /// Return the validated protection horizon.
    pub const fn protection(&self) -> ProtectionHorizon {
        self.protection
    }

    /// Return the original borrowed phase sequence.
    pub const fn phases(&self) -> &'a [ThreatPhase] {
        self.phases
    }

    /// Return the threat phase covering a time point, if any.
    pub fn threat_at(&self, time: ModelTime) -> Option<ThreatPhaseId> {
        self.phases
            .iter()
            .find(|phase| phase.interval().contains(time))
            .map(|phase| phase.threat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(value: u64) -> ModelTime {
        ModelTime::new(value)
    }

    fn interval(start: u64, end: u64) -> TimeInterval {
        TimeInterval::new(time(start), time(end)).unwrap()
    }

    fn horizon(start: u64, end: u64) -> ProtectionHorizon {
        ProtectionHorizon::new(time(start), time(end)).unwrap()
    }

    fn phase(start: u64, end: u64, id: u64) -> ThreatPhase {
        ThreatPhase::new(interval(start, end), ThreatPhaseId::new(id))
    }

    #[test]
    fn single_phase_covers_horizon() {
        let phases = [phase(0, 10, 1)];
        let schedule = ThreatSchedule::new(&phases, horizon(0, 10)).unwrap();
        assert_eq!(schedule.phases(), &phases);
        assert_eq!(schedule.protection(), horizon(0, 10));
    }

    #[test]
    fn contiguous_phases_are_accepted() {
        let phases = [phase(0, 4, 1), phase(4, 7, 2), phase(7, 10, 3)];
        assert!(ThreatSchedule::new(&phases, horizon(0, 10)).is_ok());
    }

    #[test]
    fn empty_schedule_is_rejected() {
        assert_eq!(
            ThreatSchedule::new(&[], horizon(0, 10)),
            Err(ThreatScheduleError::Empty)
        );
    }

    #[test]
    fn incorrect_start_is_rejected() {
        let phases = [phase(1, 10, 1)];
        assert_eq!(
            ThreatSchedule::new(&phases, horizon(0, 10)),
            Err(ThreatScheduleError::StartMismatch)
        );
    }

    #[test]
    fn gap_is_rejected() {
        let phases = [phase(0, 4, 1), phase(5, 10, 2)];
        assert_eq!(
            ThreatSchedule::new(&phases, horizon(0, 10)),
            Err(ThreatScheduleError::Gap { phase: 1 })
        );
    }

    #[test]
    fn overlap_is_rejected() {
        let phases = [phase(0, 6, 1), phase(5, 10, 2)];
        assert_eq!(
            ThreatSchedule::new(&phases, horizon(0, 10)),
            Err(ThreatScheduleError::OverlapOrRegression { phase: 1 })
        );
    }

    #[test]
    fn reversed_order_is_rejected() {
        let phases = [phase(0, 6, 1), phase(2, 10, 2)];
        assert_eq!(
            ThreatSchedule::new(&phases, horizon(0, 10)),
            Err(ThreatScheduleError::OverlapOrRegression { phase: 1 })
        );
    }

    #[test]
    fn incorrect_end_is_rejected() {
        let phases = [phase(0, 9, 1)];
        assert_eq!(
            ThreatSchedule::new(&phases, horizon(0, 10)),
            Err(ThreatScheduleError::EndMismatch)
        );
    }

    #[test]
    fn threat_lookup_respects_half_open_boundaries() {
        let phases = [phase(0, 5, 1), phase(5, 10, 2)];
        let schedule = ThreatSchedule::new(&phases, horizon(0, 10)).unwrap();

        assert_eq!(schedule.threat_at(time(0)), Some(ThreatPhaseId::new(1)));
        assert_eq!(schedule.threat_at(time(4)), Some(ThreatPhaseId::new(1)));
        assert_eq!(schedule.threat_at(time(5)), Some(ThreatPhaseId::new(2)));
        assert_eq!(schedule.threat_at(time(9)), Some(ThreatPhaseId::new(2)));
        assert_eq!(schedule.threat_at(time(10)), None);
    }

    #[test]
    fn threat_lookup_outside_horizon_returns_none() {
        let phases = [phase(10, 20, 1)];
        let schedule = ThreatSchedule::new(&phases, horizon(10, 20)).unwrap();

        assert_eq!(schedule.threat_at(time(9)), None);
        assert_eq!(schedule.threat_at(time(20)), None);
    }

    #[test]
    fn adjacent_equal_threats_are_allowed() {
        let phases = [phase(0, 5, 1), phase(5, 10, 1)];
        assert!(ThreatSchedule::new(&phases, horizon(0, 10)).is_ok());
    }
}
