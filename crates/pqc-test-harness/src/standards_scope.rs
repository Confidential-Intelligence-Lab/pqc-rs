//! Standards provenance and claim boundaries.
//!
//! This module prevents the repository from conflating:
//!
//! - validation against a cryptographic test corpus;
//! - implementation of a protocol specification;
//! - traceability to informational engineering guidance; and
//! - experimental support for an Internet-Draft.

/// Maturity or evidence class for one standards target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceClass {
    /// Normative algorithm behavior validated against authoritative vectors.
    VectorValidated,
    /// Normative protocol implementation with its own interoperability tests.
    ProtocolImplemented,
    /// Informational guidance mapped to engineering evidence.
    GuidanceTraced,
    /// Work-in-progress Internet-Draft pinned for experimentation.
    DraftPinned,
    /// Work has not started or has not yet reached its acceptance gate.
    Pending,
}

/// Repository status for one external document or standard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardsTarget {
    /// Stable repository identifier.
    pub id: &'static str,
    /// Human-readable title.
    pub title: &'static str,
    /// Document designation.
    pub designation: &'static str,
    /// Standards-track or publication status.
    pub publication_status: &'static str,
    /// Current evidence class in this repository.
    pub evidence: EvidenceClass,
    /// Whether the repository may claim complete conformance.
    pub complete_conformance_claim: bool,
    /// Scope note.
    pub note: &'static str,
}

/// FIPS 203 ML-KEM status.
pub const FIPS_203: StandardsTarget = StandardsTarget {
    id: "fips-203",
    title: "Module-Lattice-Based Key-Encapsulation Mechanism Standard",
    designation: "FIPS 203",
    publication_status: "Final",
    evidence: EvidenceClass::VectorValidated,
    complete_conformance_claim: false,
    note: "All imported NIST ACVP ML-KEM KeyGen, encapsulation, decapsulation, and key-check cases pass. This is algorithm-vector validation, not a CMVP module validation claim.",
};

/// RFC 9958 engineering-guidance status.
pub const RFC_9958: StandardsTarget = StandardsTarget {
    id: "rfc-9958",
    title: "Post-Quantum Cryptography for Engineers",
    designation: "RFC 9958",
    publication_status: "Informational",
    evidence: EvidenceClass::GuidanceTraced,
    complete_conformance_claim: false,
    note: "RFC 9958 supplies migration and engineering guidance. It does not define an executable cryptographic protocol or conformance test suite.",
};

/// RFC 9180 HPKE status.
pub const RFC_9180: StandardsTarget = StandardsTarget {
    id: "rfc-9180",
    title: "Hybrid Public Key Encryption",
    designation: "RFC 9180",
    publication_status: "Informational",
    evidence: EvidenceClass::Pending,
    complete_conformance_claim: false,
    note: "HPKE key schedule, context handling, AEAD processing, modes, and RFC 9180 vectors remain to be implemented.",
};

/// Pinned post-quantum HPKE Internet-Draft status.
pub const HPKE_PQ_DRAFT_05: StandardsTarget = StandardsTarget {
    id: "draft-ietf-hpke-pq-05",
    title: "Post-Quantum and Post-Quantum/Traditional Hybrid Algorithms for HPKE",
    designation: "draft-ietf-hpke-pq-05",
    publication_status: "Internet-Draft; Work in Progress; 6 July 2026",
    evidence: EvidenceClass::DraftPinned,
    complete_conformance_claim: false,
    note: "Pinned experimental integration target for pure ML-KEM and PQ/traditional hybrid HPKE KEMs. The draft may change, be replaced, or expire.",
};

/// Standards targets tracked by Stage 7A.
pub const TARGETS: &[StandardsTarget] = &[FIPS_203, RFC_9958, RFC_9180, HPKE_PQ_DRAFT_05];

/// Look up one standards target.
pub fn target(id: &str) -> Option<&'static StandardsTarget> {
    TARGETS.iter().find(|entry| entry.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_9958_is_guidance_not_protocol_conformance() {
        assert_eq!(RFC_9958.publication_status, "Informational");
        assert_eq!(RFC_9958.evidence, EvidenceClass::GuidanceTraced);
    }

    #[test]
    fn hpke_protocol_remains_pending() {
        assert_eq!(RFC_9180.evidence, EvidenceClass::Pending);
    }

    #[test]
    fn pq_hpke_target_is_explicitly_a_pinned_draft() {
        assert_eq!(HPKE_PQ_DRAFT_05.designation, "draft-ietf-hpke-pq-05");
        assert_eq!(HPKE_PQ_DRAFT_05.evidence, EvidenceClass::DraftPinned);
    }

    #[test]
    fn fips_203_status_does_not_overstate_module_validation() {
        assert_eq!(FIPS_203.evidence, EvidenceClass::VectorValidated);
    }

    #[test]
    fn targets_have_unique_identifiers() {
        for (index, left) in TARGETS.iter().enumerate() {
            for right in &TARGETS[index + 1..] {
                assert_ne!(left.id, right.id);
            }
        }
    }

    #[test]
    fn no_target_claims_complete_conformance() {
        for entry in TARGETS {
            assert!(
                !entry.complete_conformance_claim,
                "{} must not claim complete conformance",
                entry.designation,
            );
        }
    }
}
