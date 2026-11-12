//! Assurance-evidence applicability.
//!
//! This module separates evidence metadata from externally established
//! verification. Applicability does not authorize cryptographic execution.

use crate::ConfigurationIdentity;

/// Opaque identifier for an assurance-evidence record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EvidenceId(u64);

impl EvidenceId {
    /// Construct an evidence identifier.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the identifier value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Security property or operation covered by evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EvidenceScope {
    /// Key generation.
    KeyGeneration,
    /// Encapsulation.
    Encapsulation,
    /// Decapsulation.
    Decapsulation,
    /// Signing.
    Signing,
    /// Signature verification.
    SignatureVerification,
}

/// Metadata describing an assurance-evidence record.
///
/// Construction does not verify authenticity, provenance, or validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceRecord {
    id: EvidenceId,
    configuration: ConfigurationIdentity,
    scope: EvidenceScope,
}

impl EvidenceRecord {
    /// Construct unverified evidence metadata.
    pub const fn new(
        id: EvidenceId,
        configuration: ConfigurationIdentity,
        scope: EvidenceScope,
    ) -> Self {
        Self {
            id,
            configuration,
            scope,
        }
    }

    /// Return the evidence identifier.
    pub const fn id(self) -> EvidenceId {
        self.id
    }

    /// Return the configuration covered by this record.
    pub const fn configuration(self) -> ConfigurationIdentity {
        self.configuration
    }

    /// Return the operation covered by this record.
    pub const fn scope(self) -> EvidenceScope {
        self.scope
    }
}

/// Evidence whose verification has been established externally.
///
/// This type cannot currently be constructed through the public API.
/// A future verifier must establish provenance and validity before creating
/// instances. The test-only constructor exercises applicability semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedEvidence {
    record: EvidenceRecord,
}

impl VerifiedEvidence {
    /// Return the verified evidence metadata.
    pub const fn record(self) -> EvidenceRecord {
        self.record
    }

    #[cfg(test)]
    const fn for_test(record: EvidenceRecord) -> Self {
        Self { record }
    }
}

/// Result of checking evidence applicability.
///
/// `Applicable` means the supplied verified evidence matches the requested
/// configuration and scope. It does not authorize execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceApplicability {
    /// Verified evidence matches the requested configuration and scope.
    Applicable,
    /// Evidence does not cover the requested configuration or scope.
    Mismatch,
    /// No evidence record was supplied.
    Missing,
    /// Evidence exists, but its verification has not been established.
    Indeterminate,
}

/// Evidence input available to the applicability evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceInput {
    /// No evidence supplied.
    Missing,
    /// Metadata exists without established verification.
    Unverified(EvidenceRecord),
    /// Evidence verification was established externally.
    Verified(VerifiedEvidence),
}

/// Evaluate evidence applicability to an exact configuration and scope.
///
/// This function does not authenticate evidence, interpret security policy,
/// or authorize cryptographic execution.
pub fn evaluate_evidence(
    input: EvidenceInput,
    configuration: ConfigurationIdentity,
    scope: EvidenceScope,
) -> EvidenceApplicability {
    match input {
        EvidenceInput::Missing => EvidenceApplicability::Missing,
        EvidenceInput::Unverified(_) => EvidenceApplicability::Indeterminate,
        EvidenceInput::Verified(evidence) => {
            let record = evidence.record();

            if record.configuration() != configuration || record.scope() != scope {
                EvidenceApplicability::Mismatch
            } else {
                EvidenceApplicability::Applicable
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlgorithmId, ImplementationRevision, ParameterSetId, ProviderId};

    fn configuration() -> ConfigurationIdentity {
        ConfigurationIdentity::new(
            AlgorithmId::new(1),
            ParameterSetId::new(768),
            ProviderId::new(10),
            ImplementationRevision::new(42),
        )
    }

    fn record() -> EvidenceRecord {
        EvidenceRecord::new(
            EvidenceId::new(100),
            configuration(),
            EvidenceScope::Encapsulation,
        )
    }

    fn verified(record: EvidenceRecord) -> EvidenceInput {
        EvidenceInput::Verified(VerifiedEvidence::for_test(record))
    }

    #[test]
    fn exact_verified_evidence_is_applicable() {
        assert_eq!(
            evaluate_evidence(
                verified(record()),
                configuration(),
                EvidenceScope::Encapsulation,
            ),
            EvidenceApplicability::Applicable
        );
    }

    #[test]
    fn missing_evidence_is_not_applicable() {
        assert_eq!(
            evaluate_evidence(
                EvidenceInput::Missing,
                configuration(),
                EvidenceScope::Encapsulation,
            ),
            EvidenceApplicability::Missing
        );
    }

    #[test]
    fn unverified_evidence_is_indeterminate() {
        assert_eq!(
            evaluate_evidence(
                EvidenceInput::Unverified(record()),
                configuration(),
                EvidenceScope::Encapsulation,
            ),
            EvidenceApplicability::Indeterminate
        );
    }

    #[test]
    fn provider_mismatch_is_rejected() {
        let original = configuration();
        let changed = ConfigurationIdentity::new(
            original.algorithm(),
            original.parameters(),
            ProviderId::new(11),
            original.revision(),
        );

        assert_eq!(
            evaluate_evidence(verified(record()), changed, EvidenceScope::Encapsulation,),
            EvidenceApplicability::Mismatch
        );
    }

    #[test]
    fn revision_mismatch_is_rejected() {
        let original = configuration();
        let changed = ConfigurationIdentity::new(
            original.algorithm(),
            original.parameters(),
            original.provider(),
            ImplementationRevision::new(43),
        );

        assert_eq!(
            evaluate_evidence(verified(record()), changed, EvidenceScope::Encapsulation,),
            EvidenceApplicability::Mismatch
        );
    }

    #[test]
    fn scope_mismatch_is_rejected() {
        assert_eq!(
            evaluate_evidence(
                verified(record()),
                configuration(),
                EvidenceScope::Decapsulation,
            ),
            EvidenceApplicability::Mismatch
        );
    }

    #[test]
    fn evidence_metadata_accessors_preserve_values() {
        let value = record();
        assert_eq!(value.id().value(), 100);
        assert_eq!(value.configuration(), configuration());
        assert_eq!(value.scope(), EvidenceScope::Encapsulation);
    }

    #[test]
    fn algorithm_mismatch_is_rejected() {
        let original = configuration();
        let changed = ConfigurationIdentity::new(
            AlgorithmId::new(2),
            original.parameters(),
            original.provider(),
            original.revision(),
        );

        assert_eq!(
            evaluate_evidence(verified(record()), changed, EvidenceScope::Encapsulation,),
            EvidenceApplicability::Mismatch
        );
    }

    #[test]
    fn parameter_mismatch_is_rejected() {
        let original = configuration();
        let changed = ConfigurationIdentity::new(
            original.algorithm(),
            ParameterSetId::new(1024),
            original.provider(),
            original.revision(),
        );

        assert_eq!(
            evaluate_evidence(verified(record()), changed, EvidenceScope::Encapsulation,),
            EvidenceApplicability::Mismatch
        );
    }
}
