//! Identity of a cryptographic system state.
//!
//! These types represent configuration, policy, evidence, and deployment
//! state identities without interpreting their security properties.
//! Identity equality does not establish authenticity, freshness,
//! acceptability, or authorization.

use crate::ConfigurationIdentity;

/// Identity of a security-policy state.
///
/// This is distinct from the protocol-level `PolicyId`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PolicyStateIdentity(u64);

impl PolicyStateIdentity {
    /// Construct a policy-state identity.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the policy-state identifier.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Identity of an assurance-evidence state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EvidenceStateIdentity(u64);

impl EvidenceStateIdentity {
    /// Construct an evidence-state identity.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the evidence-state identifier.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Identity of an operational deployment state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DeploymentStateIdentity(u64);

impl DeploymentStateIdentity {
    /// Construct a deployment-state identity.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the deployment-state identifier.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Identity of a cryptographic system state.
///
/// Represents the tuple (configuration, policy, evidence, deployment).
/// The identifiers are caller-assigned and opaque. Equality compares
/// represented identities only; it does not establish that the underlying
/// system conditions are unchanged or trustworthy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CryptographicSystemState {
    configuration: ConfigurationIdentity,
    policy: PolicyStateIdentity,
    evidence: EvidenceStateIdentity,
    deployment: DeploymentStateIdentity,
}

impl CryptographicSystemState {
    /// Construct a cryptographic system-state identity.
    pub const fn new(
        configuration: ConfigurationIdentity,
        policy: PolicyStateIdentity,
        evidence: EvidenceStateIdentity,
        deployment: DeploymentStateIdentity,
    ) -> Self {
        Self {
            configuration,
            policy,
            evidence,
            deployment,
        }
    }

    /// Return the cryptographic configuration identity.
    pub const fn configuration(self) -> ConfigurationIdentity {
        self.configuration
    }

    /// Return the security-policy state identity.
    pub const fn policy(self) -> PolicyStateIdentity {
        self.policy
    }

    /// Return the assurance-evidence state identity.
    pub const fn evidence(self) -> EvidenceStateIdentity {
        self.evidence
    }

    /// Return the deployment-state identity.
    pub const fn deployment(self) -> DeploymentStateIdentity {
        self.deployment
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlgorithmId, ImplementationRevision, ParameterSetId, ProviderId};

    fn configuration(provider: u32) -> ConfigurationIdentity {
        ConfigurationIdentity::new(
            AlgorithmId::new(1),
            ParameterSetId::new(768),
            ProviderId::new(provider),
            ImplementationRevision::new(1),
        )
    }

    fn state() -> CryptographicSystemState {
        CryptographicSystemState::new(
            configuration(10),
            PolicyStateIdentity::new(20),
            EvidenceStateIdentity::new(30),
            DeploymentStateIdentity::new(40),
        )
    }

    #[test]
    fn state_accessors_preserve_all_components() {
        let s = state();
        assert_eq!(s.configuration(), configuration(10));
        assert_eq!(s.policy(), PolicyStateIdentity::new(20));
        assert_eq!(s.evidence(), EvidenceStateIdentity::new(30));
        assert_eq!(s.deployment(), DeploymentStateIdentity::new(40));
    }

    #[test]
    fn identifier_values_round_trip() {
        assert_eq!(PolicyStateIdentity::new(20).value(), 20);
        assert_eq!(EvidenceStateIdentity::new(30).value(), 30);
        assert_eq!(DeploymentStateIdentity::new(40).value(), 40);
    }

    #[test]
    fn identical_system_states_compare_equal() {
        assert_eq!(state(), state());
    }

    #[test]
    fn configuration_change_changes_state_identity() {
        let s = state();
        let changed = CryptographicSystemState::new(
            configuration(11),
            s.policy(),
            s.evidence(),
            s.deployment(),
        );
        assert_ne!(s, changed);
    }

    #[test]
    fn policy_change_changes_state_identity() {
        let s = state();
        let changed = CryptographicSystemState::new(
            s.configuration(),
            PolicyStateIdentity::new(21),
            s.evidence(),
            s.deployment(),
        );
        assert_ne!(s, changed);
    }

    #[test]
    fn evidence_or_deployment_change_changes_state_identity() {
        let s = state();

        let evidence_changed = CryptographicSystemState::new(
            s.configuration(),
            s.policy(),
            EvidenceStateIdentity::new(31),
            s.deployment(),
        );

        let deployment_changed = CryptographicSystemState::new(
            s.configuration(),
            s.policy(),
            s.evidence(),
            DeploymentStateIdentity::new(41),
        );

        assert_ne!(s, evidence_changed);
        assert_ne!(s, deployment_changed);
    }
}
