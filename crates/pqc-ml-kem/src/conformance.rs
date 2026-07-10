#![allow(clippy::module_name_repetitions)]
//! FIPS 203 conformance status and validation manifests.
//!
//! This module deliberately separates structural validation from normative
//! conformance. No API in this module implies FIPS 203 validation.

use crate::MlKemParameterSet;

/// Implementation maturity for an algorithmic component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConformanceLevel {
    /// API shape or control flow exists, but normative behavior is not claimed.
    Structural,
    /// Experimental implementation exists and is under validation.
    Experimental,
    /// Behavior has internal deterministic tests but no official KAT evidence.
    InternallyValidated,
    /// Behavior has passed official or independently authoritative vectors.
    KatValidated,
}

/// Validation status for one implementation component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentStatus {
    /// Stable component identifier.
    pub id: &'static str,
    /// Current maturity level.
    pub level: ConformanceLevel,
    /// Human-readable rationale.
    pub note: &'static str,
}

/// Aggregate status for one ML-KEM parameter set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParameterSetStatus {
    /// Parameter set.
    pub parameter_set: MlKemParameterSet,
    /// Whether full FIPS 203 conformance is currently claimed.
    pub fips203_conformant: bool,
    /// Whether official KATs have passed.
    pub official_kats_passed: bool,
}

/// Return the current aggregate conformance status.
pub const fn parameter_set_status(parameter_set: MlKemParameterSet) -> ParameterSetStatus {
    ParameterSetStatus {
        parameter_set,
        fips203_conformant: false,
        official_kats_passed: false,
    }
}

/// Current component-level implementation manifest.
pub const COMPONENT_STATUS: &[ComponentStatus] = &[
    ComponentStatus {
        id: "field-arithmetic",
        level: ConformanceLevel::InternallyValidated,
        note: "Canonical, centered, Montgomery, and compression helpers have unit tests.",
    },
    ComponentStatus {
        id: "fips-ntt",
        level: ConformanceLevel::Experimental,
        note: "Butterfly path exists but exact FIPS 203 domain/scaling remains pending.",
    },
    ComponentStatus {
        id: "matrix-expansion",
        level: ConformanceLevel::Structural,
        note: "Deterministic expansion exists; official intermediate vectors are pending.",
    },
    ComponentStatus {
        id: "kpke-keygen",
        level: ConformanceLevel::Structural,
        note: "Deterministic structure exists using current baseline arithmetic.",
    },
    ComponentStatus {
        id: "kpke-encrypt",
        level: ConformanceLevel::Structural,
        note: "Deterministic structure exists using current baseline arithmetic.",
    },
    ComponentStatus {
        id: "kpke-decrypt",
        level: ConformanceLevel::Structural,
        note: "Message-recovery structure exists; exact K-PKE correctness is pending.",
    },
    ComponentStatus {
        id: "ml-kem-cca-transform",
        level: ConformanceLevel::Structural,
        note: "High-level KEM API remains scaffolded.",
    },
];

/// Return a component status by identifier.
pub fn component_status(id: &str) -> Option<ComponentStatus> {
    COMPONENT_STATUS
        .iter()
        .copied()
        .find(|entry| entry.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_parameter_set_claims_fips_conformance() {
        for parameter_set in [
            MlKemParameterSet::MlKem512,
            MlKemParameterSet::MlKem768,
            MlKemParameterSet::MlKem1024,
        ] {
            let status = parameter_set_status(parameter_set);
            assert!(!status.fips203_conformant);
            assert!(!status.official_kats_passed);
        }
    }

    #[test]
    fn manifest_contains_expected_components() {
        assert!(component_status("field-arithmetic").is_some());
        assert!(component_status("fips-ntt").is_some());
        assert!(component_status("kpke-keygen").is_some());
        assert!(component_status("kpke-encrypt").is_some());
        assert!(component_status("kpke-decrypt").is_some());
        assert!(component_status("ml-kem-cca-transform").is_some());
    }

    #[test]
    fn unknown_component_returns_none() {
        assert_eq!(component_status("not-a-component"), None);
    }
}
