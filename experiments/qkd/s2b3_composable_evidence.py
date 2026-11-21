"""S2.B3: typed, fail-closed finite-key evidence and composable-budget audit.

All results are diagnostic. Neither source code nor caller claims can certify the
quantum model, smooth min entropy, authentication provisioning, or an HPKE PSK.
No key bits or confidential transcript contents are accepted or returned.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path

from m1g3_tomamichel_bound import BoundInput, evaluate as numerical_equation

REQUIRED_SOURCES = (
    'm1h2_authenticated_sampling.py',
    'm1g3_tomamichel_bound.py',
    'm1e3_finite_key.py',
    'm2a_authenticated_distillation.py',
    's2a1_universal_confirmation.py',
    's2a2_syndrome_reconciliation.py',
    's2b1_entropy_conformance_audit.py',
    's2b2_strict_theorem_reference.py',
)


class EvidenceError(ValueError):
    """Invalid public parameters or inconsistent budget declarations."""


@dataclass(frozen=True)
class PublicExperiment:
    """Public-only candidate scenario; no bit strings, keys or source claims."""
    n_key: int
    k_test: int
    matched_z: int
    test_errors: int
    syndrome_disclosure_bits: int
    confirmation_tag_bits: int
    block_size: int
    syndrome_bits_per_block: int
    q_tolerance: float
    preparation_quality: float = 1.0  # assumed, NEVER measured/certified


@dataclass(frozen=True)
class SecurityBudget:
    """Diagnostic risk allocation, not proof that components satisfy it.

    epsilon_sec is the TOP LEVEL secrecy target used by Eq (2). Values for
    sampling/smoothing/PA are an ALTERNATIVE proof-work allocation and may not
    be inserted as extra Equation (2) deductions without a separate derivation.
    epsilon_auth is kept separate from eps_sec/eps_cor and contributes to an
    additive, conservative target envelope.
    """
    epsilon_sec: float
    epsilon_cor: float
    epsilon_auth: float
    epsilon_total: float
    epsilon_sampling: float
    epsilon_smoothing: float
    epsilon_pa: float


@dataclass(frozen=True)
class AssumptionReview:
    """Caller-supplied assertions, deliberately not trusted as proof evidence."""
    source_preparation_reviewed: bool = False
    quantum_sampling_reviewed: bool = False
    authentication_key_reviewed: bool = False
    extractor_reviewed: bool = False
    transcript_reviewed: bool = False


def _prob(name: str, value: float) -> float:
    if type(value) not in (float, int) or not math.isfinite(value) or not 0 < value < 1:
        raise EvidenceError(name + ' must be finite, strictly between zero and one')
    return float(value)


def _int(name: str, value: int, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise EvidenceError(name + ' must be integer >= ' + str(minimum))
    return value


def source_fingerprints(directory: str | Path) -> dict[str, str]:
    """Fingerprint the exact modules in the diagnostic evidence chain."""
    root = Path(directory)
    result = {}
    for name in REQUIRED_SOURCES:
        file = root / name
        if not file.is_file():
            raise EvidenceError('required source missing: ' + name)
        result[name] = hashlib.sha256(file.read_bytes()).hexdigest()
    return result


def assess(experiment: PublicExperiment, budget: SecurityBudget,
           source_dir: str | Path, *, review: AssumptionReview | None = None) -> dict:
    """Evaluate public numeric consistency; NEVER authorize entropy or export."""
    if type(experiment) is not PublicExperiment or type(budget) is not SecurityBudget:
        raise EvidenceError('typed PublicExperiment and SecurityBudget required')
    if review is not None and type(review) is not AssumptionReview:
        raise EvidenceError('typed AssumptionReview required')
    if review is not None and any(type(v) is not bool for v in asdict(review).values()):
        raise EvidenceError('review entries must be booleans')
    p = experiment
    for n, minimum in (('n_key', 1), ('k_test', 1), ('matched_z', 1),
                       ('test_errors', 0), ('syndrome_disclosure_bits', 0),
                       ('confirmation_tag_bits', 1), ('block_size', 1),
                       ('syndrome_bits_per_block', 1)):
        _int(n, getattr(p, n), minimum)
    if p.test_errors > p.matched_z or p.matched_z < p.k_test:
        raise EvidenceError('invalid Z test observations')
    if p.n_key % p.block_size:
        raise EvidenceError('key size must consist of full reconciliation blocks')
    if p.syndrome_bits_per_block > p.block_size:
        raise EvidenceError('syndrome dimensions invalid')
    expected = (p.n_key // p.block_size) * p.syndrome_bits_per_block
    if p.syndrome_disclosure_bits != expected:
        raise EvidenceError('syndrome disclosure inconsistent with block matrix')
    if p.confirmation_tag_bits > p.n_key:
        raise EvidenceError('confirmation tag larger than key')
    if type(p.q_tolerance) not in (float, int) or not math.isfinite(p.q_tolerance) or not 0 <= p.q_tolerance <= .5:
        raise EvidenceError('invalid QBER tolerance')
    if type(p.preparation_quality) not in (float, int) or not math.isfinite(p.preparation_quality) or not 0 < p.preparation_quality <= 1:
        raise EvidenceError('invalid assumed preparation quality')
    observed = p.test_errors / p.matched_z
    b = budget
    e = {n: _prob(n, getattr(b, n)) for n in
         ('epsilon_sec', 'epsilon_cor', 'epsilon_auth', 'epsilon_total',
          'epsilon_sampling', 'epsilon_smoothing', 'epsilon_pa')}
    if observed > p.q_tolerance:
        observation_decision = 'ABORT_PARAMETER_ESTIMATION'
    else:
        observation_decision = 'PUBLIC_PARAMETERS_CONSISTENT'
    # Universal Toeplitz hash correctness bound is conditional on independent seed.
    collision = math.ldexp(1.0, -p.confirmation_tag_bits)
    if e['epsilon_cor'] < collision:
        raise EvidenceError('declared correctness budget smaller than 2^-tag_bits')
    # Explicit risk allocation is a PLANNING convention, not an Eq (2) theorem.
    alternative_sum = math.fsum((e['epsilon_sampling'], e['epsilon_smoothing'], e['epsilon_pa']))
    if alternative_sum > e['epsilon_sec'] * (1 + 1e-12):
        raise EvidenceError('alternative secrecy proof-work allocation exceeds secrecy target')
    envelope = math.fsum((e['epsilon_sec'], e['epsilon_cor'], e['epsilon_auth']))
    if envelope > e['epsilon_total'] * (1 + 1e-12):
        raise EvidenceError('top-level additive target envelope exceeded')
    hashes = source_fingerprints(source_dir)
    # Independently check old S2.B1 source-level markers on its six original files.
    from s2b1_entropy_conformance_audit import audit as legacy_audit
    legacy = legacy_audit(source_dir, n_key=p.n_key, k_test=p.matched_z,
                          q_tolerance=p.q_tolerance,
                          syndrome_leak_bits=p.syndrome_disclosure_bits,
                          confirmation_leak_bits=p.confirmation_tag_bits,
                          epsilon_secrecy=b.epsilon_sec,
                          epsilon_correctness=b.epsilon_cor)
    if legacy['decision'] != 'THEOREM_CONFORMANCE_NOT_ESTABLISHED':
        raise EvidenceError('unexpected legacy audit state')
    equation = numerical_equation(BoundInput(
        n_key=p.n_key, k_test=p.matched_z, q_tolerance=p.q_tolerance,
        leakage_ec_bits=p.syndrome_disclosure_bits,
        epsilon_secrecy=b.epsilon_sec, epsilon_correctness=b.epsilon_cor,
        preparation_quality=p.preparation_quality))
    # Both are calculations on declared public parameters, NOT a min-entropy proof.
    return {
        'stage': 'S2B3_COMPOSABLE_EVIDENCE',
        'decision': ('REJECT_QBER_ABOVE_TOLERANCE' if observed > p.q_tolerance
                     else 'REJECT_UNVERIFIED_QUANTUM_ASSUMPTIONS'),
        'public_experiment': asdict(p),
        'observed_test_qber': observed,
        'observation_decision': observation_decision,
        'accounted_disclosure_bits': p.syndrome_disclosure_bits + p.confirmation_tag_bits,
        'equation2_error_correction_leak_bits': p.syndrome_disclosure_bits,
        'equation2_confirmation_penalty_via_epsilon_cor': True,
        'confirmation_collision_bound': collision,
        'budget': {
            **asdict(b),
            'alternative_suballocation_sum': alternative_sum,
            'additive_top_level_envelope': envelope,
            'alternative_suballocation_is_not_extra_eq2_deduction': True,
            'authentication_failure_probability_not_validated': True,
        },
        'numerical_equation_only': {
            'maximum_numerical_key_bits': equation['maximum_numerical_key_bits'],
            'phase_error_upper': equation['phase_error_upper'],
            'finite_sample_mu': equation['mu'],
            'positive_length_is_not_entropy_evidence': True,
        },
        'source_sha256': hashes,
        'asserted_reviews_are_not_certificates': True,
        'review_assertion_count': sum(asdict(review or AssumptionReview()).values()),
        'theorem_sampling_validated': False,
        'pre_leak_min_entropy_certified': False,
        'authentication_provisioning_validated': False,
        'security_model_validated': False,
        'security_qualified': False,
        'qkd_psk_available': False,
        'hpke_export_authorized': False,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source-dir', default=str(Path(__file__).parent))
    ap.add_argument('--self-check', action='store_true')
    args = ap.parse_args()
    if not args.self_check:
        ap.error('only --self-check supported; arbitrary external evidence is not accepted')
    p = PublicExperiment(4096, 4096, 4096, 0, 1024, 40, 128, 32, .05)
    b = SecurityBudget(1e-10, 2**-40, 1e-12, 1.02e-10, 1e-11, 1e-11, 1e-11)
    result = assess(p,b,args.source_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    print('QKD_S2B3_COMPOSABLE_EVIDENCE_STATUS=PASS')
    print('QKD_S2B3_MIN_ENTROPY_CERTIFIED=false')
    print('QKD_S2B3_SECURITY_MODEL_VALIDATED=false')
    print('QKD_S2B3_HPKE_EXPORT_AUTHORIZED=false')


if __name__ == '__main__':
    main()
