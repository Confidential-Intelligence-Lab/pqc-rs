"""Independent classical oracle for idealized quota-stopped BB84 basis acquisition.

Does not implement a security proof. Assumes independent basis draws and unit detection.
An engineering transmission cap is an extra abort condition, not automatically a
feature of the Tomamichel et al. (2012) protocol.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from math import comb, isfinite
from typing import Mapping


@dataclass(frozen=True)
class QuotaModel:
    n_x: int
    k_z: int
    p_x: float
    max_transmissions: int

    def __post_init__(self) -> None:
        if type(self.n_x) is not int or self.n_x < 1 or type(self.k_z) is not int or self.k_z < 1:
            raise ValueError('quotas must be positive integers')
        if type(self.max_transmissions) is not int or self.max_transmissions < self.n_x + self.k_z:
            raise ValueError('cap must be integer and at least sum of quotas')
        if type(self.p_x) not in (float, int) or not isfinite(self.p_x) or not 0 < self.p_x < 1:
            raise ValueError('p_x must be strictly between zero and one')


def probabilities(p_x: float) -> tuple[float, float, float]:
    if type(p_x) not in (float, int) or not isfinite(p_x) or not 0 < p_x < 1:
        raise ValueError('invalid p_x')
    x = p_x * p_x
    z = (1.0 - p_x) ** 2
    return x, z, 1.0 - x - z


def stopping_pmf(m: QuotaModel) -> dict:
    """Exact DP in independent basis-draw model; capped counts, including overshoots.

    States record capped matched-basis counts, while extra same-basis draws after
    one quota is met are still possible and are not interpreted as mismatches.
    """
    px, pz, pm = probabilities(m.p_x)
    active: dict[tuple[int, int], float] = {(0, 0): 1.0}
    stop: dict[int, float] = {}
    for t in range(1, m.max_transmissions + 1):
        nxt = defaultdict(float)
        for (x, z), mass in active.items():
            for nx, nz, chance in ((min(m.n_x, x + 1), z, px),
                                   (x, min(m.k_z, z + 1), pz),
                                   (x, z, pm)):
                if nx == m.n_x and nz == m.k_z:
                    stop[t] = stop.get(t, 0.0) + mass * chance
                else:
                    nxt[(nx, nz)] += mass * chance
        active = nxt
    abort = sum(active.values())
    stop_mass = sum(stop.values())
    return {
        'p_xx': px, 'p_zz': pz, 'p_mismatch': pm,
        'stop_pmf': stop, 'p_quota_complete': stop_mass,
        'p_abort_cap': abort, 'mass_error': abs(1.0 - stop_mass - abort),
        'expected_transmissions_if_complete':
            sum(t * v for t, v in stop.items()) / stop_mass if stop_mass else None,
        'security_model_validated': False,
        'theorem_sampling_validated': False,
        'hpke_export_authorized': False,
    }


def uniform_subset_probability(population: int, sample_size: int, subset: tuple[int, ...]) -> float:
    if type(population) is not int or type(sample_size) is not int or population < 0 or not 0 <= sample_size <= population:
        raise ValueError('invalid population/sample size')
    if (type(subset) is not tuple or len(subset) != sample_size or
            any(type(i) is not int or not 0 <= i < population for i in subset) or
            len(set(subset)) != sample_size):
        raise ValueError('invalid subset')
    return 1.0 / comb(population, sample_size)


def report(m: QuotaModel) -> dict:
    r = stopping_pmf(m)
    return {k: (v if k != 'stop_pmf' else {str(t): p for t, p in v.items()}) for k, v in r.items()} | {
        'n_x': m.n_x, 'k_z': m.k_z, 'p_x': m.p_x,
        'max_transmissions': m.max_transmissions,
        'ideal_lossless_independent_basis_draws': True,
        'conditional_cap_abort_is_extra_engineering_policy': True,
        'source_randomness_and_device_assumptions_proved': False,
    }


if __name__ == '__main__':
    import argparse
    import json
    p = argparse.ArgumentParser()
    p.add_argument('--n-x', type=int, default=4)
    p.add_argument('--k-z', type=int, default=3)
    p.add_argument('--p-x', type=float, default=0.5)
    p.add_argument('--max-transmissions', type=int, default=40)
    a = p.parse_args()
    print(json.dumps(report(QuotaModel(a.n_x, a.k_z, a.p_x, a.max_transmissions)), indent=2, sort_keys=True))
    print('QKD_M1H4A_CLASSICAL_ORACLE_STATUS=PASS')
    print('QKD_M1H4A_SECURITY_MODEL_VALIDATED=false')
