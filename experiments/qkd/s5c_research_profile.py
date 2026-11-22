"""S5.C numerical research-profile freeze, not a QKD security proof.

Never returns key material or a certified secret-bit count. The TLGR equation
is evaluated against precommitted k_min (not optional observed Z overshoot).
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from math import ceil

from m1g3_tomamichel_bound import BoundInput, evaluate


class ProfileError(ValueError):
    pass


@dataclass(frozen=True)
class ResearchProfile:
    name: str = 'TLGR2012_IDEAL_BB84_P50_N16384_K16384_V1'
    n_key: int = 16384
    k_test_min: int = 16384
    max_transmissions: int = 100000
    x_basis_probability_ppm: int = 500000
    q_tolerance_ppm: int = 20000
    preparation_quality: float = 1.0
    epsilon_secrecy: float = 1e-10
    epsilon_correctness: float = 1e-10
    epsilon_authentication_target: float = 1e-12
    epsilon_total_target: float = 1e-9
    block_size: int = 128
    syndrome_bits_per_block: int = 32
    confirmation_tag_bits: int = 64
    requested_key_bits: int = 256


def assess(profile: ResearchProfile, *, observed_z_count: int | None = None) -> dict:
    if type(profile) is not ResearchProfile:
        raise ProfileError('require exact frozen ResearchProfile')
    if (profile.n_key < 128 or profile.n_key > 65536 or
        profile.k_test_min < 1 or profile.max_transmissions > 100000 or
        profile.n_key + profile.k_test_min > profile.max_transmissions or
        not 0 < profile.x_basis_probability_ppm < 1000000 or
        not 0 <= profile.q_tolerance_ppm <= 500000 or
        profile.block_size != 128 or profile.syndrome_bits_per_block != 32 or
        not 1 <= profile.confirmation_tag_bits <= 256 or
        not 1 <= profile.requested_key_bits <= profile.n_key):
        raise ProfileError('invalid or incompatible frozen research profile')
    for e in (profile.epsilon_secrecy, profile.epsilon_correctness,
              profile.epsilon_authentication_target, profile.epsilon_total_target):
        if type(e) is not float or not 0 < e < 1:
            raise ProfileError('invalid epsilon')
    if profile.preparation_quality != 1.0:
        raise ProfileError('ideal source research profile only')
    if observed_z_count is not None and (
        type(observed_z_count) is not int or observed_z_count < profile.k_test_min
        or observed_z_count > profile.max_transmissions):
        raise ProfileError('observed Z count invalid or below quota')
    ec_leak = profile.syndrome_bits_per_block * ceil(profile.n_key / profile.block_size)
    numerical = evaluate(BoundInput(
        n_key=profile.n_key,
        k_test=profile.k_test_min,
        q_tolerance=profile.q_tolerance_ppm / 1000000,
        leakage_ec_bits=ec_leak,
        epsilon_secrecy=profile.epsilon_secrecy,
        epsilon_correctness=profile.epsilon_correctness,
        preparation_quality=profile.preparation_quality,
    ))
    candidate = numerical['maximum_numerical_key_bits']
    requested_fits = candidate >= profile.requested_key_bits
    return {
        'stage': 'S5C_THEOREM_MATCHED_NUMERICAL_RESEARCH_PROFILE',
        'profile': asdict(profile),
        'reference': 'TLGR-2012-Eq2; ETSI-GS-QKD-005-V1.1.1-methodology',
        'profile_precommitted_k': profile.k_test_min,
        'observed_z_count': observed_z_count,
        'observed_k_used_for_eq2': False,
        'equation_k': profile.k_test_min,
        'ec_leakage_upper_bits': ec_leak,
        'confirmation_tag_bits_reported_separately': profile.confirmation_tag_bits,
        'confirmation_tag_not_double_subtracted_from_tlgr_penalty': True,
        'numerical_candidate_key_bits': candidate,
        'requested_length_numerically_fits': requested_fits,
        'numerical_bound': numerical,
        'nominal_epsilon_sum': profile.epsilon_secrecy + profile.epsilon_correctness + profile.epsilon_authentication_target,
        'nominal_budget_within_target': (
            profile.epsilon_secrecy + profile.epsilon_correctness + profile.epsilon_authentication_target
            <= profile.epsilon_total_target),
        'nominal_authentication_advantage_proven': False,
        'finite_key_theorem_hypotheses_verified': False,
        'capped_quantum_protocol_coupling_proven': False,
        'randomness_and_universality_proven': False,
        'complete_reconciliation_leakage_proven': False,
        'research_profile_alignment': 'FROZEN_NUMERICAL_CANDIDATE_REVIEW_REQUIRED',
        'security_disposition': 'RESEARCH_NUMERICAL_CANDIDATE_UNQUALIFIED',
        'conditional_security_supported': False,
        'security_model_validated': False,
        'security_qualified': False,
        'hpke_export_authorized': False,
        'qkd_psk_available': False,
    }


if __name__ == '__main__':
    import json
    print(json.dumps(assess(ResearchProfile()), sort_keys=True, indent=2))
    print('QKD_S5C_SECURITY_QUALIFIED=false')
