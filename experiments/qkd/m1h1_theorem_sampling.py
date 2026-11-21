"""Experimental Box-1-oriented X-key/Z-test selection. NOT theorem conformance.

Operates on separate Alice/Bob records. Public deterministic seeds are test-only.
The selected positions and bits are kept in memory; never exported by CLI.
"""
from __future__ import annotations

import random
import secrets
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class Selection:
    x_key_positions: tuple[int, ...]
    z_test_positions: tuple[int, ...]
    z_test_errors: int
    eligible_x: int
    eligible_z: int
    public_seed_used: bool


def select(alice: Sequence, bob: Sequence, *, n_key: int, k_test: int,
           seed: int | None = None) -> Selection:
    """Select n eligible X key positions, k Z test positions, without replacement.

    For a true theorem implementation, randomness and sampling/stopping assumptions
    must be reviewed; this only demonstrates index selection and basis semantics.
    """
    if type(n_key) is not int or n_key <= 0 or type(k_test) is not int or k_test <= 0:
        raise ValueError('n_key and k_test must be positive integers')
    if len(alice) != len(bob) or not alice:
        raise ValueError('mismatched or empty record sequences')
    if seed is not None and (type(seed) is not int or seed < 0):
        raise ValueError('test seed must be a nonnegative integer')
    for a, b in zip(alice, bob):
        if (type(a.basis) is not int or a.basis not in (0, 1)
            or type(b.basis) is not int or b.basis not in (0, 1)
            or type(a.bit) is not int or a.bit not in (0, 1)
            or type(b.bit) is not int or b.bit not in (0, 1)):
            raise ValueError('invalid per-peer record')
    x = [i for i, (a, b) in enumerate(zip(alice, bob)) if a.basis == b.basis == 1]
    z = [i for i, (a, b) in enumerate(zip(alice, bob)) if a.basis == b.basis == 0]
    if len(x) < n_key or len(z) < k_test:
        raise ValueError('insufficient matched basis populations: abort')
    rng = random.Random(seed) if seed is not None else secrets.SystemRandom()
    key_indices = tuple(sorted(rng.sample(x, n_key)))
    test_indices = tuple(sorted(rng.sample(z, k_test)))
    z_errors = sum(alice[i].bit != bob[i].bit for i in test_indices)
    return Selection(key_indices, test_indices, z_errors, len(x), len(z), seed is not None)


def diagnostic(*, n_key: int, k_test: int, max_transmissions: int,
               seed: int = 20261120, measure=None) -> dict:
    # Existing C1 record generator has Z-quota first. Reverse its quotas here
    # to meet this candidate theorem orientation: n_key X and k_test Z.
    from m1g5c1_measurement_transcript import simulate_records
    alice, bob = simulate_records(n_z=k_test, k_x=n_key,
        max_transmissions=max_transmissions, seed=seed, measure=measure)
    try:
        result = select(alice, bob, n_key=n_key, k_test=k_test, seed=seed)
    except ValueError as exc:
        return {'decision': 'ABORT', 'reason': str(exc),
            'security_model_validated': False, 'hpke_export_authorized': False}
    return {'decision': 'SAMPLE_SELECTED_UNQUALIFIED',
        'transmissions': len(alice), 'key_basis': 'X', 'test_basis': 'Z',
        'x_key_bits': len(result.x_key_positions),
        'z_test_bits': len(result.z_test_positions), 'z_test_errors': result.z_test_errors,
        'z_test_qber': result.z_test_errors / k_test,
        'eligible_x': result.eligible_x, 'eligible_z': result.eligible_z,
        'public_reproducible_seed': True,
        'authenticated_sample_selection': False,
        'theorem_specific_protocol_validated': False,
        'security_model_validated': False, 'security_qualified': False,
        'hpke_export_authorized': False}


if __name__ == '__main__':
    import argparse
    import json
    p = argparse.ArgumentParser()
    p.add_argument('--n-key', type=int, default=128)
    p.add_argument('--k-test', type=int, default=128)
    p.add_argument('--max-transmissions', type=int, default=4096)
    p.add_argument('--seed', type=int, default=20261120)
    a = p.parse_args()
    print(json.dumps(diagnostic(n_key=a.n_key, k_test=a.k_test,
        max_transmissions=a.max_transmissions, seed=a.seed), indent=2, sort_keys=True))
    print('QKD_M1H1_SAMPLING_STATUS=PASS')
    print('QKD_M1H1_SECURITY_MODEL_VALIDATED=false')
