"""Exact classical conditional subset law at BB84 first-passage stopping.

This is an idealized model, not a finite-key theorem, quantum-security proof,
or authorization to export a QKD secret into HPKE.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from itertools import combinations
from math import comb
import json

from m1h4f_quota_overshoot import exact_joint, probability


def _subset_args(population: int, selected: int) -> None:
    if type(population) is not int or type(selected) is not int or population < 1 or selected < 1 or selected > population:
        raise ValueError('require 1 <= selected <= population')


def conditional_law(population: int, selected: int) -> dict[tuple[int, ...], Fraction]:
    """Uniform index-subset law, conditioned on a *preselection* population.

    Assumes independent uniform subset randomness, not established by this model.
    """
    _subset_args(population, selected)
    p = Fraction(1, comb(population, selected))
    return {s: p for s in combinations(range(population), selected)}


def postannouncement_law(population: int, selected: int, announced: tuple[int, ...]) -> dict[tuple[int, ...], Fraction]:
    """After authentic announcement, selected indices are public and fixed."""
    _subset_args(population, selected)
    if type(announced) is not tuple or len(announced) != selected or any(type(i) is not int for i in announced) or tuple(sorted(set(announced))) != announced or any(i < 0 or i >= population for i in announced):
        raise ValueError('invalid announced subset')
    return {announced: Fraction(1)}


def conditional_on_success(n_x: int, k_z: int, cap: int, selected: int, p_x: str = '1/2') -> dict:
    """Mix exact first-passage population law with independent uniform selection.

    The sample is represented in *eligible-population rank coordinates*.
    Absolute transmission positions depend on the preselection basis transcript.
    """
    if type(selected) is not int or selected < 1 or selected > n_x:
        raise ValueError('selected X count exceeds X quota')
    model = exact_joint(n_x, k_z, cap, p_x)
    success = model['p_success']
    if not success:
        raise ValueError('zero successful completion probability')
    marginal: dict[tuple[int, ...], Fraction] = {}
    by_size: dict[int, Fraction] = {}
    for (_, x, _), weight in model['joint'].items():
        by_size[x] = by_size.get(x, Fraction()) + weight / success
        for subset, q in conditional_law(x, selected).items():
            marginal[subset] = marginal.get(subset, Fraction()) + (weight / success) * q
    assert sum(by_size.values(), Fraction()) == 1
    assert sum(marginal.values(), Fraction()) == 1
    return {'model': model, 'selected': selected, 'population_given_success': dict(sorted(by_size.items())), 'subset_rank_given_success': dict(sorted(marginal.items()))}


def report(n_x: int, k_z: int, cap: int, selected: int, p_x: str = '1/2') -> dict:
    result = conditional_on_success(n_x, k_z, cap, selected, p_x)
    model = result['model']
    xdist = result['population_given_success']
    example = min(xdist)
    # Full public transcript after sample selection reveals indices. Before
    # selection, a fixed eligible population may be conditioned upon.
    return {
        'decision': 'CLASSICAL_CONDITIONAL_SAMPLING_IDENTITY_CHECKED',
        'parameters': {'n_x': n_x, 'k_z': k_z, 'cap': cap, 'p_x': str(probability(p_x)), 'selected_x': selected},
        'p_cap_success': float(model['p_success']),
        'p_cap_abort': float(model['p_abort']),
        'x_population_given_success': {str(x):float(v) for x,v in xdist.items()},
        'rank_subset_probability_given_success': {','.join(map(str,s)):float(v) for s,v in result['subset_rank_given_success'].items()},
        'fixed_population_example': {'eligible_x':example,'subset_probability':float(Fraction(1, comb(example, selected)))},
        'conditional_on_preselection_basis_transcript': 'UNIFORM_IF_INDEPENDENT_SELECTION_RANDOMNESS',
        'conditional_on_cap_success': 'UNIFORM_GIVEN_PRESELECTION_POPULATION_IF_SELECTION_RANDOMNESS_INDEPENDENT',
        'conditional_on_postselection_transcript': 'ANNOUNCED_INDICES_ARE_DETERMINISTIC',
        'unconditional_rank_subset_uniform_across_variable_populations': False,
        'quantum_sampling_theorem_mapped': False,
        'authentication_provisioning_validated': False,
        'quantum_source_and_eve_independence_proved': False,
        'finite_key_leakage_and_correctness_verified': False,
        'theorem_sampling_validated': False,
        'security_model_validated': False,
        'hpke_export_authorized': False,
    }


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--n-x',type=int,default=2)
    parser.add_argument('--k-z',type=int,default=2)
    parser.add_argument('--cap',type=int,default=12)
    parser.add_argument('--selected',type=int,default=1)
    parser.add_argument('--p-x',default='1/2')
    args=parser.parse_args()
    print(json.dumps(report(args.n_x,args.k_z,args.cap,args.selected,args.p_x),indent=2,sort_keys=True))
    print('QKD_M1H4G_CONDITIONAL_SAMPLING_STATUS=PASS')
    print('QKD_M1H4G_THEOREM_SAMPLING_VALIDATED=false')
    print('QKD_M1H4G_SECURITY_MODEL_VALIDATED=false')
    print('QKD_M1H4G_HPKE_EXPORT_AUTHORIZED=false')


if __name__ == '__main__':
    main()
