//! Advisory temporal security context.
//!
//! Time values are caller-assigned logical ticks, not wall-clock timestamps.
//! Threat identities and protection horizons do not establish actual security.

/// An ordered point in a caller-defined logical time domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelTime(u64);

impl ModelTime {
    /// Construct a logical time point.
    pub const fn new(ticks: u64) -> Self {
        Self(ticks)
    }

    /// Return the caller-assigned tick value.
    pub const fn ticks(self) -> u64 {
        self.0
    }
}

/// An invalid temporal construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalError {
    /// The interval has no positive extent.
    EmptyOrReversedInterval,
    /// The protection deadline is not later than observation.
    ExpiredProtectionHorizon,
}

/// A nonempty half-open interval [start, end).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeInterval {
    start: ModelTime,
    end: ModelTime,
}

impl TimeInterval {
    /// Construct a validated interval.
    pub const fn new(start: ModelTime, end: ModelTime) -> Result<Self, TemporalError> {
        if start.ticks() >= end.ticks() {
            return Err(TemporalError::EmptyOrReversedInterval);
        }
        Ok(Self { start, end })
    }

    /// Return the inclusive start.
    pub const fn start(self) -> ModelTime {
        self.start
    }

    /// Return the exclusive end.
    pub const fn end(self) -> ModelTime {
        self.end
    }

    /// Test membership in the half-open interval.
    pub const fn contains(self, time: ModelTime) -> bool {
        self.start.ticks() <= time.ticks() && time.ticks() < self.end.ticks()
    }
}

/// A protection requirement extending beyond an observation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionHorizon {
    observed_at: ModelTime,
    required_until: ModelTime,
}

impl ProtectionHorizon {
    /// Construct a protection horizon with a future deadline.
    pub const fn new(
        observed_at: ModelTime,
        required_until: ModelTime,
    ) -> Result<Self, TemporalError> {
        if observed_at.ticks() >= required_until.ticks() {
            return Err(TemporalError::ExpiredProtectionHorizon);
        }
        Ok(Self {
            observed_at,
            required_until,
        })
    }

    /// Return the observation time.
    pub const fn observed_at(self) -> ModelTime {
        self.observed_at
    }

    /// Return the exclusive protection deadline.
    pub const fn required_until(self) -> ModelTime {
        self.required_until
    }

    /// Return the required protection interval.
    pub const fn interval(self) -> TimeInterval {
        TimeInterval {
            start: self.observed_at,
            end: self.required_until,
        }
    }
}

/// Opaque identity of externally specified threat assumptions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ThreatPhaseId(u64);

impl ThreatPhaseId {
    /// Construct a caller-assigned threat-phase identity.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the threat-phase identifier.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Temporal context for advisory security evaluation.
///
/// This type identifies a threat phase and protection interval.
/// It does not evaluate cryptographic strength, authenticate
/// threat information, or authorize a transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemporalSecurityContext {
    threat_phase: ThreatPhaseId,
    protection: ProtectionHorizon,
}

impl TemporalSecurityContext {
    /// Construct a context from a validated protection horizon.
    pub const fn new(threat_phase: ThreatPhaseId, protection: ProtectionHorizon) -> Self {
        Self {
            threat_phase,
            protection,
        }
    }

    /// Return the threat-phase identity.
    pub const fn threat_phase(self) -> ThreatPhaseId {
        self.threat_phase
    }

    /// Return the observation time.
    pub const fn observed_at(self) -> ModelTime {
        self.protection.observed_at()
    }

    /// Return the protection horizon.
    pub const fn protection(self) -> ProtectionHorizon {
        self.protection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_ordering_is_numeric() {
        assert!(ModelTime::new(1) < ModelTime::new(2));
        assert_eq!(ModelTime::new(42).ticks(), 42);
    }

    #[test]
    fn interval_accepts_positive_extent() {
        let interval = TimeInterval::new(ModelTime::new(2), ModelTime::new(5)).unwrap();
        assert_eq!(interval.start(), ModelTime::new(2));
        assert_eq!(interval.end(), ModelTime::new(5));
    }

    #[test]
    fn interval_rejects_equal_endpoints() {
        assert_eq!(
            TimeInterval::new(ModelTime::new(5), ModelTime::new(5)),
            Err(TemporalError::EmptyOrReversedInterval)
        );
    }

    #[test]
    fn interval_rejects_reversed_endpoints() {
        assert_eq!(
            TimeInterval::new(ModelTime::new(6), ModelTime::new(5)),
            Err(TemporalError::EmptyOrReversedInterval)
        );
    }

    #[test]
    fn interval_membership_is_half_open() {
        let interval = TimeInterval::new(ModelTime::new(2), ModelTime::new(5)).unwrap();
        assert!(!interval.contains(ModelTime::new(1)));
        assert!(interval.contains(ModelTime::new(2)));
        assert!(interval.contains(ModelTime::new(4)));
        assert!(!interval.contains(ModelTime::new(5)));
    }

    #[test]
    fn horizon_requires_future_deadline() {
        assert_eq!(
            ProtectionHorizon::new(ModelTime::new(10), ModelTime::new(10),),
            Err(TemporalError::ExpiredProtectionHorizon)
        );
        assert_eq!(
            ProtectionHorizon::new(ModelTime::new(11), ModelTime::new(10),),
            Err(TemporalError::ExpiredProtectionHorizon)
        );
    }

    #[test]
    fn horizon_exposes_protection_interval() {
        let horizon = ProtectionHorizon::new(ModelTime::new(10), ModelTime::new(20)).unwrap();
        let interval = horizon.interval();
        assert_eq!(interval.start(), ModelTime::new(10));
        assert_eq!(interval.end(), ModelTime::new(20));
    }

    #[test]
    fn context_preserves_threat_and_protection() {
        let horizon = ProtectionHorizon::new(ModelTime::new(10), ModelTime::new(20)).unwrap();
        let context = TemporalSecurityContext::new(ThreatPhaseId::new(3), horizon);
        assert_eq!(context.threat_phase().value(), 3);
        assert_eq!(context.observed_at(), ModelTime::new(10));
        assert_eq!(context.protection(), horizon);
    }

    #[test]
    fn distinct_threat_phases_remain_distinct() {
        assert_ne!(ThreatPhaseId::new(1), ThreatPhaseId::new(2));
    }

    #[test]
    fn boundary_values_do_not_overflow() {
        let interval =
            TimeInterval::new(ModelTime::new(u64::MAX - 1), ModelTime::new(u64::MAX)).unwrap();
        assert!(interval.contains(ModelTime::new(u64::MAX - 1)));
        assert!(!interval.contains(ModelTime::new(u64::MAX)));
    }
}
