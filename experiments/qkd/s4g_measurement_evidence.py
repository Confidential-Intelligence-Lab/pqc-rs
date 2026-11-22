"""S4.G: diagnostic BB84 measurement and intercept/resend evidence.

Research-only simulator experiment. Statistical agreement with an ideal distribution
is not quantum conditional min-entropy evidence and cannot authorize HPKE export.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import random
from typing import Callable

from s4f_source_conformance import audit_prepare_and_measure


class MeasurementEvidenceError(ValueError):
    pass


def ideal_p_one(bit: int, preparation_basis: int, measurement_basis: int) -> float:
    if any(type(x) is not int or x not in (0, 1)
           for x in (bit, preparation_basis, measurement_basis)):
        raise MeasurementEvidenceError('bit and bases must be binary integers')
    return float(bit) if preparation_basis == measurement_basis else 0.5


def checked_outcome(outcome) -> int:
    if type(outcome) is not int or outcome not in (0, 1):
        raise MeasurementEvidenceError('quantum measurement returned nonbinary outcome')
    return outcome


def tolerance(n: int, *, alpha: float, families: int) -> float:
    """Union-bounded Hoeffding radius for a PREDECLARED family of Bernoulli tests."""
    if (type(n) is not int or n < 1 or type(families) is not int or families < 1
            or type(alpha) not in (int, float) or not math.isfinite(alpha)
            or not 0 < alpha < 1):
        raise MeasurementEvidenceError('invalid predeclared statistical test inputs')
    return math.sqrt(math.log(2 * families / alpha) / (2 * n))


def bb84_cases(measure: Callable[[int, int, int], int], *,
               shots: int = 256, alpha: float = 0.01) -> dict:
    """All 8 combinations: 2 bits x 2 preparation bases x 2 measurement bases."""
    if not callable(measure):
        raise MeasurementEvidenceError('measurement oracle required')
    # Validate settings before any samples.
    radius = tolerance(shots, alpha=alpha, families=8)
    cases = []
    for bit in (0, 1):
        for a in (0, 1):
            for b in (0, 1):
                ones = sum(checked_outcome(measure(bit, a, b)) for _ in range(shots))
                expected = ideal_p_one(bit, a, b)
                observed = ones / shots
                cases.append({'bit': bit, 'preparation_basis': a,
                              'measurement_basis': b, 'shots': shots,
                              'ones': ones, 'expected_p_one': expected,
                              'observed_p_one': observed,
                              'within_predeclared_tolerance': abs(observed - expected) <= radius})
    return {'experiment': 'S4G_BB84_EIGHT_CASES', 'shots_per_case': shots,
            'familywise_alpha': float(alpha), 'hoeffding_radius': radius,
            'cases': cases,
            'decision': 'MODEL_STATISTICS_PASS_UNQUALIFIED' if all(
                x['within_predeclared_tolerance'] for x in cases)
                else 'MODEL_STATISTICS_FAIL',
            'security_model_validated': False, 'security_qualified': False,
            'hpke_export_authorized': False, 'qkd_psk_available': False}


def intercept_resend(measure: Callable[[int, int, int], int], *,
                     trials: int = 1024, seed: int = 20261121,
                     alpha: float = 0.01) -> dict:
    """Full intercept/resend; independent fixture RNG for *diagnostic* choices.

    Alice/Bob choose uniform bases; Eve chooses a uniform interception basis.
    QBER is conditioned on matched Alice/Bob basis. Theoretical value is 1/4.
    """
    if not callable(measure):
        raise MeasurementEvidenceError('measurement oracle required')
    if type(trials) is not int or trials < 1 or type(seed) is not int or seed < 0:
        raise MeasurementEvidenceError('invalid attack experiment parameters')
    if type(alpha) not in (int, float) or not math.isfinite(alpha) or not 0 < alpha < 1:
        raise MeasurementEvidenceError('invalid statistical error rate')
    rng = random.Random(seed)
    matched = errors = 0
    for _ in range(trials):
        bit, alice_basis, bob_basis, eve_basis = (rng.randrange(2) for _ in range(4))
        eve_bit = checked_outcome(measure(bit, alice_basis, eve_basis))
        bob_bit = checked_outcome(measure(eve_bit, eve_basis, bob_basis))
        if alice_basis == bob_basis:
            matched += 1
            errors += bob_bit != bit
    if not matched:
        return {'experiment': 'S4G_FULL_INTERCEPT_RESEND', 'decision': 'INSUFFICIENT_MATCHED_EVENTS',
                'security_qualified': False, 'hpke_export_authorized': False}
    radius = tolerance(matched, alpha=alpha, families=1)
    qber = errors / matched
    return {'experiment': 'S4G_FULL_INTERCEPT_RESEND', 'trials': trials,
            'matched': matched, 'errors': errors, 'observed_qber': qber,
            'expected_qber': 0.25, 'familywise_alpha': float(alpha),
            'hoeffding_radius': radius, 'fixture_seed': seed,
            'decision': ('MODEL_STATISTICS_PASS_UNQUALIFIED'
                         if abs(qber - 0.25) <= radius else 'MODEL_STATISTICS_FAIL'),
            'general_quantum_eve_validated': False,
            'security_model_validated': False, 'security_qualified': False,
            'hpke_export_authorized': False, 'qkd_psk_available': False}


def run(*, shots: int = 256, trials: int = 1024,
        seed: int = 20261121, alpha: float = 0.01,
        measure=None) -> dict:
    """Use actual CUDA-Q measured_bit unless a test oracle is injected."""
    structural = audit_prepare_and_measure()
    if measure is None:
        from bb84_cudaq import measured_bit
        measure = measured_bit
        backend = 'cudaq-sample-single-shot'
    else:
        backend = 'injected-test-oracle-NOT-CUDAQ'
    cases = bb84_cases(measure, shots=shots, alpha=alpha)
    attack = intercept_resend(measure, trials=trials, seed=seed, alpha=alpha)
    kernel_file = Path(__file__).with_name('bb84_cudaq.py')
    sha = hashlib.sha256(kernel_file.read_bytes()).hexdigest()
    return {'stage': 'S4G_MEASUREMENT_CONFORMANCE', 'backend': backend,
            'quantum_kernel_sha256': sha,
            'circuit_structure_matches_ideal_model': structural['circuit_structure_matches_ideal_model'],
            'bb84_eight_cases': cases, 'intercept_resend': attack,
            'decision': ('EXPERIMENTS_PASS_UNQUALIFIED'
                         if cases['decision'] == 'MODEL_STATISTICS_PASS_UNQUALIFIED'
                         and attack['decision'] == 'MODEL_STATISTICS_PASS_UNQUALIFIED'
                         else 'EXPERIMENTS_FAIL'),
            'quantum_min_entropy_proven': False, 'source_attested': False,
            'general_quantum_eve_validated': False,
            'security_model_validated': False, 'security_qualified': False,
            'hpke_export_authorized': False, 'qkd_psk_available': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shots', type=int, default=256)
    parser.add_argument('--attack-trials', type=int, default=1024)
    parser.add_argument('--seed', type=int, default=20261121)
    parser.add_argument('--alpha', type=float, default=0.01)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    out = run(shots=args.shots, trials=args.attack_trials,
              seed=args.seed, alpha=args.alpha)
    encoded = json.dumps(out, sort_keys=True, indent=2) + '\n'
    if args.output:
        args.output.write_text(encoded, encoding='utf-8')
    print(encoded, end='')
    print('QKD_S4G_MEASUREMENT_STATUS=' + out['decision'])
    if out['decision'] != 'EXPERIMENTS_PASS_UNQUALIFIED':
        raise SystemExit(2)


if __name__ == '__main__':
    main()
