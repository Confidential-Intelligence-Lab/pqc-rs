//! M2.B fail-closed public-evidence gate. No QKD secret enters this module.
//!
//! This gate is deliberately *not* a general positive authorization API.
//! Future qualified providers require a separately reviewed, non-forgeable
//! key-source interface and composable security evidence.

/// Reason a public distillation-evidence report cannot authorize a QKD handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffDenial {
    /// Evidence originates from a quantum simulator, not a qualified QKD source.
    SimulationProvenance,
    /// One or more required security-evidence assertions are absent.
    MissingEvidence,
    /// Public assertions cannot authorize a provider; no qualified provider exists yet.
    QualifiedProviderNotImplemented,
}

/// Public, untrusted report fields used solely for fail-closed handoff checks.
///
/// This type intentionally contains no cryptographic key material or grant token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicDistillationEvidence<'a> {
    /// Reported origin of the candidate material; never a trust anchor.
    pub provenance: &'a str,
    /// Reported status of the QKD security-model review.
    pub security_model_validated: bool,
    /// Reported aggregate qualification status.
    pub security_qualified: bool,
    /// Reported status of a justified quantum min-entropy bound.
    pub quantum_min_entropy_proven: bool,
    /// Reported presence of a QKD PSK; not a secret-bearing field.
    pub qkd_psk_available: bool,
    /// Reported export authorization; never sufficient by itself.
    pub hpke_export_authorized: bool,
}

/// Always deny the M2.A->HPKE production path until an independently audited
/// qualified key source exists. Reports alone are never sufficient to confer
/// authority, even if an attacker sets all public flags to true.
pub fn production_handoff(evidence: PublicDistillationEvidence<'_>) -> Result<(), HandoffDenial> {
    if evidence.provenance == "CUDA_Q_SIMULATION_NOT_SECURE_QKD" {
        return Err(HandoffDenial::SimulationProvenance);
    }
    if !evidence.security_model_validated
        || !evidence.security_qualified
        || !evidence.quantum_min_entropy_proven
        || !evidence.qkd_psk_available
        || !evidence.hpke_export_authorized
    {
        return Err(HandoffDenial::MissingEvidence);
    }
    Err(HandoffDenial::QualifiedProviderNotImplemented)
}
