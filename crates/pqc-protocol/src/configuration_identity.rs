//! Cryptographic configuration identity.
//!
//! These types identify configurations without interpreting security policy,
//! resolving providers, or executing cryptographic operations.

/// Identifier for a cryptographic algorithm or suite.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AlgorithmId(u32);

impl AlgorithmId {
    /// Construct an algorithm identifier.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the identifier value.
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Identifier for an algorithm parameter set.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ParameterSetId(u32);

impl ParameterSetId {
    /// Construct a parameter-set identifier.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the identifier value.
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Identifier for a cryptographic implementation provider.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProviderId(u32);

impl ProviderId {
    /// Construct a provider identifier.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the identifier value.
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Identifier for a specific implementation revision.
///
/// The identifier is opaque. Its assignment and authenticity are external
/// responsibilities.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ImplementationRevision(u64);

impl ImplementationRevision {
    /// Construct an implementation revision identifier.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the identifier value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Exact identity of a cryptographic configuration.
///
/// Equality requires matching algorithm, parameters, provider, and
/// implementation revision. This type does not represent assurance evidence
/// or authorization to execute a configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConfigurationIdentity {
    algorithm: AlgorithmId,
    parameters: ParameterSetId,
    provider: ProviderId,
    revision: ImplementationRevision,
}

impl ConfigurationIdentity {
    /// Construct a configuration identity.
    pub const fn new(
        algorithm: AlgorithmId,
        parameters: ParameterSetId,
        provider: ProviderId,
        revision: ImplementationRevision,
    ) -> Self {
        Self {
            algorithm,
            parameters,
            provider,
            revision,
        }
    }

    /// Return the algorithm identifier.
    pub const fn algorithm(self) -> AlgorithmId {
        self.algorithm
    }

    /// Return the parameter-set identifier.
    pub const fn parameters(self) -> ParameterSetId {
        self.parameters
    }

    /// Return the provider identifier.
    pub const fn provider(self) -> ProviderId {
        self.provider
    }

    /// Return the implementation revision.
    pub const fn revision(self) -> ImplementationRevision {
        self.revision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ConfigurationIdentity {
        ConfigurationIdentity::new(
            AlgorithmId::new(1),
            ParameterSetId::new(768),
            ProviderId::new(10),
            ImplementationRevision::new(42),
        )
    }

    #[test]
    fn identical_configurations_compare_equal() {
        assert_eq!(identity(), identity());
    }

    #[test]
    fn different_algorithms_are_distinct() {
        let baseline = identity();
        let changed = ConfigurationIdentity::new(
            AlgorithmId::new(2),
            baseline.parameters(),
            baseline.provider(),
            baseline.revision(),
        );
        assert_ne!(baseline, changed);
    }

    #[test]
    fn different_parameters_are_distinct() {
        let baseline = identity();
        let changed = ConfigurationIdentity::new(
            baseline.algorithm(),
            ParameterSetId::new(1024),
            baseline.provider(),
            baseline.revision(),
        );
        assert_ne!(baseline, changed);
    }

    #[test]
    fn different_providers_are_distinct() {
        let baseline = identity();
        let changed = ConfigurationIdentity::new(
            baseline.algorithm(),
            baseline.parameters(),
            ProviderId::new(11),
            baseline.revision(),
        );
        assert_ne!(baseline, changed);
    }

    #[test]
    fn different_revisions_are_distinct() {
        let baseline = identity();
        let changed = ConfigurationIdentity::new(
            baseline.algorithm(),
            baseline.parameters(),
            baseline.provider(),
            ImplementationRevision::new(43),
        );
        assert_ne!(baseline, changed);
    }

    #[test]
    fn accessors_preserve_all_fields() {
        let value = identity();
        assert_eq!(value.algorithm().value(), 1);
        assert_eq!(value.parameters().value(), 768);
        assert_eq!(value.provider().value(), 10);
        assert_eq!(value.revision().value(), 42);
    }
}
