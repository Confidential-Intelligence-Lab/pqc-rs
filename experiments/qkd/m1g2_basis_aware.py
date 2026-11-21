#!/usr/bin/env python3
"""Basis-aware BB84 simulation diagnostics. NOT a security proof or secure key source.

The experiment preserves matched-basis X and Z populations but does not implement
an authenticated sifting transcript, theorem-specific quota stopping, or a phase-
error bound. Deterministic PRNG seeds are for reproducibility only.
"""
from __future__ import annotations
import argparse
import json
import random
from typing import Callable


def experiment(transmissions: int, seed: int, intercept_percent: int = 0,
               z_probability: float = 0.5,
               measure: Callable[[int, int, int], int] | None = None) -> dict:
    if type(transmissions) is not int or transmissions < 1:
        raise ValueError('transmissions must be a positive integer')
    if type(seed) is not int or seed < 0:
        raise ValueError('seed must be a nonnegative integer')
    if type(intercept_percent) is not int or not 0 <= intercept_percent <= 100:
        raise ValueError('intercept_percent must be in [0,100]')
    if type(z_probability) not in (float, int) or not 0 < z_probability < 1:
        raise ValueError('z_probability must be strictly between 0 and 1')
    if measure is None:
        import cudaq
        from bb84_cudaq import measured_bit
        cudaq.set_random_seed(seed)
        measure = measured_bit
    rng = random.Random(seed)
    matched = {'X': [], 'Z': []}
    discarded = 0
    for _ in range(transmissions):
        bit = rng.randrange(2)
        a_basis = 0 if rng.random() < z_probability else 1
        b_basis = 0 if rng.random() < z_probability else 1
        if rng.randrange(100) < intercept_percent:
            eve_basis = rng.randrange(2)
            eve_bit = measure(bit, a_basis, eve_basis)
            observed = measure(eve_bit, eve_basis, b_basis)
        else:
            observed = measure(bit, a_basis, b_basis)
        if type(observed) is not int or observed not in (0, 1):
            raise ValueError('measurement function must return a binary integer')
        if a_basis != b_basis:
            discarded += 1
            continue
        matched['Z' if a_basis == 0 else 'X'].append((bit, observed))
    result = {}
    for basis in ('Z', 'X'):
        pairs = matched[basis]
        errors = sum(a != b for a, b in pairs)
        result[basis] = {'matched': len(pairs), 'errors': errors,
                         'qber': errors / len(pairs) if pairs else None}
    return {
        'transmissions': transmissions,
        'seed_is_publicly_reproducible': True,
        'intercept_percent': intercept_percent,
        'z_probability': z_probability,
        'z_key_candidates': result['Z'],
        'x_parameter_estimation_candidates': result['X'],
        'basis_mismatches': discarded,
        'accounting_valid': result['Z']['matched'] + result['X']['matched'] + discarded == transmissions,
        'basis_announcement_authenticated': False,
        'theorem_specific_protocol_validated': False,
        'finite_key_phase_error_bound': None,
        'security_model_validated': False,
        'security_qualified': False,
        'hpke_export_authorized': False,
        'provenance': 'CUDA_Q_SIMULATION_NOT_SECURE_QKD',
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bits', type=int, default=2048)
    ap.add_argument('--seed', type=int, default=20261120)
    ap.add_argument('--intercept-percent', type=int, default=0)
    ap.add_argument('--z-probability', type=float, default=0.5)
    args = ap.parse_args()
    print(json.dumps(experiment(args.bits, args.seed, args.intercept_percent,
                                args.z_probability), indent=2, sort_keys=True))
    print('QKD_M1G2_BASIS_AWARE_STATUS=PASS')
    print('QKD_M1G2_SECURITY_MODEL_VALIDATED=false')

if __name__ == '__main__':
    main()
