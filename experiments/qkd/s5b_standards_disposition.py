"""S5.B-S: standards-referenced research profile classification (not certification).

Grounded in published ETSI GS QKD 005 V1.1.1 and 016 V2.1.1.
The evaluator deliberately cannot establish a theorem or authorize any key.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

STANDARD_SET = (
    ('ETSI-GS-QKD-005-V1.1.1', 'scientific proof vs implementation verification'),
    ('ETSI-GS-QKD-016-V2.1.1-FCS_QKD.1', 'security parameter tied to a valid composed proof'),
    ('ISO-IEC-23837-1-2023', 'module security requirements; hardware out of scope'),
    ('ISO-IEC-23837-2-2023', 'evaluation methods; hardware out of scope'),
    ('ITU-T-X.1711-2026', 'protocol architecture; informative for research model'),
    ('ITU-T-X.1710-2020', 'network security; deferred to S6'),
)

REQUIRED_EVIDENCE = (
    'security/S4A_QUANTUM_SOURCE_ADVERSARY_MODEL.md',
    'security/S4B_THEOREM_IMPLEMENTATION_CORRESPONDENCE.md',
    'security/S4C_FINITE_KEY_EQUATION_LEAKAGE_AUDIT.md',
    'security/S4D_ENTROPY_PROOF_APPLICABILITY.md',
    'security/S4E_PROOF_PROFILE_PRECOMMITMENT.md',
    'security/S4F_SOURCE_MODEL_PARAMETER_INTEGRITY.md',
    'security/S4G_MEASUREMENT_AND_S4_CLOSURE.md',
    'security/S3D_AUTHENTICATION_CONTRACT.md',
    'security/S5A_COMPOSABLE_SECURITY_DEFINITION.md',
    'security/S5B_THEOREM_CORRESPONDENCE_AND_CAP_COUPLING.md',
)

OPEN_PROOF_BLOCKERS = (
    'TLGR_SUPPLEMENTARY_HYPOTHESES_UNREVIEWED',
    'CAP_ACCEPTED_BRANCH_COUPLING_UNPROVED',
    'OBSERVED_K_SUBSTITUTION_UNJUSTIFIED',
    'GENERAL_EVE_SMOOTH_MIN_ENTROPY_UNPROVED',
    'COMPLETE_LEAKAGE_AND_CONFIRMATION_REDUCTION_UNPROVED',
    'QUANTUM_PROOF_TOEPLITZ_EXTRACTION_UNPROVED',
    'COMPUTATIONAL_MULTI_MAC_ADVANTAGE_UNPROVED',
    'INDEPENDENT_SECURITY_REVIEW_PENDING',
)

@dataclass(frozen=True)
class ResearchDisposition:
    evidence_directory: str | Path

    def assess(self) -> dict:
        root = Path(self.evidence_directory)
        present = [x for x in REQUIRED_EVIDENCE if (root / x).is_file()]
        missing = [x for x in REQUIRED_EVIDENCE if x not in present]
        return {
            'stage': 'S5B_STANDARDS_ALIGNMENT',
            'reference_set': [x[0] for x in STANDARD_SET],
            'document_inventory_complete': not missing,
            'evidence_documents_present': present,
            'missing_evidence_documents': missing,
            'research_profile_alignment': 'DOCUMENTED_MAPPING_REVIEW_REQUIRED' if not missing else 'INCOMPLETE_MAPPING_EVIDENCE',
            'formal_standards_conformance_certified': False,
            'gate_a_approved_by_this_report': False,
            'conditional_security_supported': False,
            'theorem_applicability_proven': False,
            'proof_obligations_open': list(OPEN_PROOF_BLOCKERS),
            'security_model_validated': False,
            'security_qualified': False,
            'hpke_export_authorized': False,
            'qkd_psk_available': False,
            'production_handoff_permitted': False,
        }
