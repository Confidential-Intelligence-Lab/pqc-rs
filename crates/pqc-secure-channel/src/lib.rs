#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Secure-channel integration between PQC-rs protocol negotiation and HPKE.
//!
//! This crate interprets already-validated protocol negotiation evidence as a
//! closed set of implementation-defined HPKE profiles. Peer-controlled
//! capability identifiers cannot directly supply KEM, KDF, or AEAD
//! identifiers.

use core::fmt;

use pqc_hpke::{hybrid_kem::HybridKem, AeadId, HpkeSuite, HpkeSuiteId, KdfId, MlKemHpke};
use pqc_protocol::{
    CapabilityId, NegotiatedCapability, PolicyId, HPKE_ML_KEM_1024, HPKE_ML_KEM_768,
    HPKE_ML_KEM_768_X25519,
};

/// Closed cryptographic interpretation of a negotiated HPKE capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpkeProfileKind {
    /// ML-KEM-768 with HKDF-SHA256 and AES-256-GCM.
    MlKem768 {
        /// Validated HPKE suite.
        suite: HpkeSuite,
    },
    /// ML-KEM-1024 with HKDF-SHA384 and AES-256-GCM.
    MlKem1024 {
        /// Validated HPKE suite.
        suite: HpkeSuite,
    },
    /// ML-KEM-768 + X25519 with HKDF-SHA256 and AES-256-GCM.
    MlKem768X25519 {
        /// Hybrid KEM implementation.
        kem: HybridKem,
        /// Fixed HPKE suite identifier used by the hybrid setup path.
        suite: HpkeSuiteId,
    },
}

/// A cryptographic HPKE profile resolved from validated negotiation evidence.
///
/// Construction is restricted to [`resolve_hpke_profile`]. The resolved value
/// retains the original [`NegotiatedCapability`] so that local policy evidence
/// remains bound to the selected cryptographic profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedHpkeProfile {
    negotiated: NegotiatedCapability,
    kind: HpkeProfileKind,
}

impl ResolvedHpkeProfile {
    /// Return the negotiation evidence from which this profile was resolved.
    pub const fn negotiated(self) -> NegotiatedCapability {
        self.negotiated
    }

    /// Return the locally bound policy identifier.
    pub const fn policy_id(self) -> PolicyId {
        self.negotiated.policy_id()
    }

    /// Return the negotiated protocol capability identifier.
    pub const fn capability(self) -> CapabilityId {
        self.negotiated.capability()
    }

    /// Return the closed HPKE profile kind.
    pub const fn kind(self) -> HpkeProfileKind {
        self.kind
    }

    /// Return the concrete HPKE suite identifier.
    pub const fn suite_id(self) -> HpkeSuiteId {
        match self.kind {
            HpkeProfileKind::MlKem768 { suite } | HpkeProfileKind::MlKem1024 { suite } => {
                suite.id()
            }
            HpkeProfileKind::MlKem768X25519 { suite, .. } => suite,
        }
    }
}

/// Error returned when negotiation evidence cannot be resolved to a supported
/// secure-channel HPKE profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpkeProfileResolutionError {
    /// The negotiated capability has no secure-channel HPKE profile.
    UnsupportedCapability {
        /// Unsupported capability identifier.
        capability: CapabilityId,
    },
    /// An implementation-defined profile failed internal HPKE validation.
    InvalidProfile,
}

impl fmt::Display for HpkeProfileResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCapability { .. } => {
                formatter.write_str("unsupported negotiated HPKE capability")
            }
            Self::InvalidProfile => {
                formatter.write_str("implementation-defined HPKE profile is invalid")
            }
        }
    }
}

impl std::error::Error for HpkeProfileResolutionError {}

/// Resolve validated protocol negotiation evidence to a closed HPKE profile.
///
/// The peer does not provide KEM, KDF, or AEAD identifiers through this API.
/// A negotiated [`CapabilityId`] selects one complete implementation-defined
/// profile or is rejected.
///
/// # Errors
///
/// Returns [`HpkeProfileResolutionError::UnsupportedCapability`] when the
/// negotiated capability is not registered as a secure-channel HPKE profile.
/// Returns [`HpkeProfileResolutionError::InvalidProfile`] if one of the
/// implementation-defined pure-ML-KEM suites fails HPKE validation.
pub fn resolve_hpke_profile(
    negotiated: NegotiatedCapability,
) -> Result<ResolvedHpkeProfile, HpkeProfileResolutionError> {
    let kind = match negotiated.capability() {
        HPKE_ML_KEM_768 => {
            let suite =
                HpkeSuite::new(MlKemHpke::MlKem768, KdfId::HKDF_SHA256, AeadId::AES_256_GCM)
                    .map_err(|_| HpkeProfileResolutionError::InvalidProfile)?;

            HpkeProfileKind::MlKem768 { suite }
        }

        HPKE_ML_KEM_1024 => {
            let suite = HpkeSuite::new(
                MlKemHpke::MlKem1024,
                KdfId::HKDF_SHA384,
                AeadId::AES_256_GCM,
            )
            .map_err(|_| HpkeProfileResolutionError::InvalidProfile)?;

            HpkeProfileKind::MlKem1024 { suite }
        }

        HPKE_ML_KEM_768_X25519 => {
            let kem = HybridKem::MlKem768X25519;
            let suite = HpkeSuiteId {
                kem_id: kem.kem_id(),
                kdf_id: KdfId::HKDF_SHA256,
                aead_id: AeadId::AES_256_GCM,
            };

            HpkeProfileKind::MlKem768X25519 { kem, suite }
        }

        capability => {
            return Err(HpkeProfileResolutionError::UnsupportedCapability { capability });
        }
    };

    Ok(ResolvedHpkeProfile { negotiated, kind })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqc_protocol::{negotiate_policy_permitted_common, CapabilityOffer, CapabilityPolicy};

    fn negotiated(capability: CapabilityId, policy_id: PolicyId) -> NegotiatedCapability {
        let local_ids = [capability];
        let peer_ids = [capability];
        let allowed = [capability];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(policy_id, &allowed).unwrap();

        negotiate_policy_permitted_common(local, peer, policy).unwrap()
    }

    #[test]
    fn resolves_ml_kem_768_profile_exactly() {
        let evidence = negotiated(HPKE_ML_KEM_768, PolicyId::new(1));
        let profile = resolve_hpke_profile(evidence).unwrap();

        assert_eq!(profile.negotiated(), evidence);
        assert_eq!(profile.policy_id(), PolicyId::new(1));
        assert_eq!(profile.capability(), HPKE_ML_KEM_768);

        let HpkeProfileKind::MlKem768 { suite } = profile.kind() else {
            panic!("unexpected profile kind");
        };

        assert_eq!(suite.id().kem_id, MlKemHpke::MlKem768.kem_id());
        assert_eq!(suite.id().kdf_id, KdfId::HKDF_SHA256);
        assert_eq!(suite.id().aead_id, AeadId::AES_256_GCM);
    }

    #[test]
    fn resolves_ml_kem_1024_profile_exactly() {
        let evidence = negotiated(HPKE_ML_KEM_1024, PolicyId::new(2));
        let profile = resolve_hpke_profile(evidence).unwrap();

        let HpkeProfileKind::MlKem1024 { suite } = profile.kind() else {
            panic!("unexpected profile kind");
        };

        assert_eq!(suite.id().kem_id, MlKemHpke::MlKem1024.kem_id());
        assert_eq!(suite.id().kdf_id, KdfId::HKDF_SHA384);
        assert_eq!(suite.id().aead_id, AeadId::AES_256_GCM);
    }

    #[test]
    fn resolves_hybrid_profile_exactly() {
        let evidence = negotiated(HPKE_ML_KEM_768_X25519, PolicyId::new(3));
        let profile = resolve_hpke_profile(evidence).unwrap();

        let HpkeProfileKind::MlKem768X25519 { kem, suite } = profile.kind() else {
            panic!("unexpected profile kind");
        };

        assert_eq!(kem, HybridKem::MlKem768X25519);
        assert_eq!(suite.kem_id, kem.kem_id());
        assert_eq!(suite.kdf_id, KdfId::HKDF_SHA256);
        assert_eq!(suite.aead_id, AeadId::AES_256_GCM);
    }

    #[test]
    fn unsupported_negotiated_capability_is_rejected() {
        let unsupported = CapabilityId::new(0xfefe);
        let evidence = negotiated(unsupported, PolicyId::new(4));

        assert_eq!(
            resolve_hpke_profile(evidence),
            Err(HpkeProfileResolutionError::UnsupportedCapability {
                capability: unsupported,
            })
        );
    }

    #[test]
    fn resolution_is_deterministic() {
        let evidence = negotiated(HPKE_ML_KEM_768, PolicyId::new(5));

        let first = resolve_hpke_profile(evidence).unwrap();

        for _ in 0..16 {
            assert_eq!(resolve_hpke_profile(evidence).unwrap(), first);
        }
    }

    #[test]
    fn local_policy_evidence_survives_resolution() {
        let policy_id = PolicyId::new(0x1234);
        let evidence = negotiated(HPKE_ML_KEM_768_X25519, policy_id);

        let profile = resolve_hpke_profile(evidence).unwrap();

        assert_eq!(profile.policy_id(), policy_id);
        assert_eq!(profile.negotiated(), evidence);
    }

    #[test]
    fn each_registered_hpke_capability_maps_to_distinct_suite() {
        let ml768 = resolve_hpke_profile(negotiated(HPKE_ML_KEM_768, PolicyId::new(1))).unwrap();
        let ml1024 = resolve_hpke_profile(negotiated(HPKE_ML_KEM_1024, PolicyId::new(1))).unwrap();
        let hybrid =
            resolve_hpke_profile(negotiated(HPKE_ML_KEM_768_X25519, PolicyId::new(1))).unwrap();

        assert_ne!(ml768.suite_id(), ml1024.suite_id());
        assert_ne!(ml768.suite_id(), hybrid.suite_id());
        assert_ne!(ml1024.suite_id(), hybrid.suite_id());
    }
}
