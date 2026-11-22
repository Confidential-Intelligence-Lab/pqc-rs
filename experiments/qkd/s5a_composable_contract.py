"""S5.A: machine-readable composable-security obligations; never a QKD proof.

This is a research *planning* ledger. No caller-supplied report, epsilon, or
claim can mark the quantum security theorem or the actual HMAC reduction proven.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from math import ceil


class SecurityContractError(ValueError):
    """Invalid numerical planning parameter or unsupported evidence claim."""


OPEN_OBLIGATIONS = (
    'L1_ideal_source_preparation_and_receiver_model',
    'L2_general_quantum_adversary_and_causality',
    'L3_first_hit_quota_cap_and_public_disclosure_coupling',
    'L4_accepted_branch_smooth_conditional_min_entropy',
    'L5_complete_reconciliation_confirmation_leakage',
    'L6_quantum_proof_toeplitz_privacy_amplification',
    'L7_authentication_KDF_MAC_and_multiframe_reduction',
    'L8_composable_real_ideal_HPKEnonexport_boundary',
)


def _fraction(value: str, name: str) -> Decimal:
    if type(value) is not str or not value or 'e' in value.lower():
        raise SecurityContractError(name + ' must be a canonical decimal string')
    try:
        x = Decimal(value)
    except InvalidOperation as exc:
        raise SecurityContractError('invalid ' + name) from exc
    if not x.is_finite() or not Decimal(0) < x < Decimal(1):
        raise SecurityContractError(name + ' must be in (0,1)')
    if format(x.normalize(), 'f') != value:
        raise SecurityContractError(name + ' must use canonical decimal notation')
    return x


@dataclass(frozen=True)
class PlanningBudget:
    """Desired bounds only; these are NOT certified upper bounds."""
    secrecy: str
    correctness: str
    authentication: str
    total_target: str

    def __post_init__(self):
        for field in ('secrecy', 'correctness', 'authentication', 'total_target'):
            _fraction(getattr(self, field), field)

    def ledger(self) -> dict:
        sec = _fraction(self.secrecy, 'secrecy')
        cor = _fraction(self.correctness, 'correctness')
        auth = _fraction(self.authentication, 'authentication')
        target = _fraction(self.total_target, 'total_target')
        desired_sum = sec + cor + auth
        return {
            'planning_sum': str(desired_sum),
            'planning_target': str(target),
            'planning_sum_within_target': desired_sum <= target,
            'sum_is_proven_bound': False,
            'authentication_advantage_proven': False,
            'quantum_secrecy_bound_proven': False,
            'correctness_bound_proven_for_full_protocol': False,
        }


def build_assessment(*, n_key: int, k_test: int, max_transmissions: int,
                     confirmation_tag_bits: int, budget: PlanningBudget,
                     numerical_report: dict | None = None) -> dict:
    """Create an explicitly non-authorizing security assessment.

    numerical_report is never used to assert a security property. Unexpected
    caller-provided claimed qualification is rejected, rather than ignored.
    """
    for name, value in (('n_key', n_key), ('k_test', k_test),
                        ('max_transmissions', max_transmissions),
                        ('confirmation_tag_bits', confirmation_tag_bits)):
        if type(value) is not int or value <= 0:
            raise SecurityContractError('invalid ' + name)
    if (n_key < 128 or n_key > 65536 or k_test > 100000 or
            n_key + k_test > max_transmissions or max_transmissions > 100000 or
            confirmation_tag_bits > 256):
        raise SecurityContractError('invalid protocol bounds')
    if type(budget) is not PlanningBudget:
        raise SecurityContractError('explicit S5.A planning budget required')
    if numerical_report is not None:
        if type(numerical_report) is not dict:
            raise SecurityContractError('numerical report must be a mapping')
        if any(numerical_report.get(k) is True for k in (
                'security_model_validated', 'security_qualified',
                'hpke_export_authorized', 'qkd_psk_available',
                'protocol_assumptions_verified', 'quantum_min_entropy_proven')):
            raise SecurityContractError('untrusted security promotion in diagnostic report')
    ec_blocks = (n_key + 127) // 128
    return {
        'stage': 'S5A_COMPOSABLE_SECURITY_CONTRACT',
        'decision': 'OPEN_THEOREM_AND_AUTHENTICATION_OBLIGATIONS',
        'assumption_ledger_version': 1,
        'real_ideal_definition': 'ABORT_AWARE_SUBNORMALIZED_ACCEPTED_BRANCH',
        'real_output_registers': ('K_A', 'K_B', 'accept_or_abort',
                                  'key_length', 'public_transcript', 'E_quantum'),
        'ideal_secret_key_on_accept': 'uniform_shared_key_independent_of_E_and_public_transcript',
        'correctness_event': 'ACCEPT_AND_KEY_MISMATCH',
        'authentication_model': 'HMAC_SHA256_COMPUTATIONAL_UNPROVEN_ADVANTAGE',
        'authenticated_channel_idealization_proven': False,
        'trusted_source_proven': False,
        'full_accepted_branch_coupling_proven': False,
        'quantum_min_entropy_proven': False,
        'theorem_applicability_proven': False,
        'full_protocol_correctness_proven': False,
        'proof_obligations_open': list(OPEN_OBLIGATIONS),
        'n_key': n_key,
        'k_test_minimum': k_test,
        'max_transmissions': max_transmissions,
        'ec_syndrome_blocks': ec_blocks,
        'ec_syndrome_disclosure_upper_bits': 32 * ec_blocks,
        'confirmation_tag_bits': confirmation_tag_bits,
        's3d_outer_frame_resource_count': 17 + ec_blocks,
        'inner_MACs_in_outer_frame_count': False,
        'epsilon_ledger': budget.ledger(),
        'numerical_candidate_security_evidence': False,
        'production_handoff_permitted': False,
        'security_model_validated': False,
        'security_qualified': False,
        'hpke_export_authorized': False,
        'qkd_psk_available': False,
    }
