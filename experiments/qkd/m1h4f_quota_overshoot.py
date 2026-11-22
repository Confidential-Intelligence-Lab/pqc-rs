"""Exact finite-cap joint stopping and overshoot probabilities for ideal BB84 basis events.

Uses rational arithmetic; this is a classical ideal-source model, not a QKD
security proof. Events XX, ZZ, mismatch are independent across transmissions.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from fractions import Fraction
import itertools
import json
from math import comb


def probability(value: str | Fraction) -> Fraction:
    try:
        p = Fraction(value)
    except (ValueError, ZeroDivisionError, TypeError) as exc:
        raise ValueError('invalid basis probability') from exc
    if not 0 < p < 1:
        raise ValueError('basis probability must lie strictly between 0 and 1')
    return p


def event_probabilities(p_x: str | Fraction = '1/2') -> dict[str, Fraction]:
    p = probability(p_x)
    return {'X': p * p, 'Z': (1-p) * (1-p), 'M': 2*p*(1-p)}


def _arguments(n_x: int, k_z: int, cap: int) -> None:
    for v in (n_x, k_z, cap):
        if type(v) is not int or v < 1:
            raise ValueError('quotas and cap must be positive integers')
    if cap < n_x+k_z:
        raise ValueError('cap smaller than theoretical minimum completion length')
    if cap > 256:
        raise ValueError('cap > 256 is outside this exact rational reference model')


def exact_joint(n_x: int, k_z: int, cap: int, p_x: str | Fraction = '1/2') -> dict:
    """First passage joint law P(T=t, X_T=x, Z_T=z), incl. abort by cap.

    States contain the *actual* number of matched events; do not saturate
    quotas or include an event after the first successful stopping time.
    """
    _arguments(n_x, k_z, cap)
    probs = event_probabilities(p_x)
    live = {(0, 0): Fraction(1)}
    completed = defaultdict(Fraction)
    for t in range(1, cap + 1):
        next_live = defaultdict(Fraction)
        for (x,z), mass in live.items():
            for ev, q in probs.items():
                xx, zz = x+(ev == 'X'), z+(ev == 'Z')
                weight = mass*q
                if xx >= n_x and zz >= k_z:
                    completed[(t,xx,zz)] += weight
                else:
                    next_live[(xx,zz)] += weight
        live = dict(next_live)
    abort = sum(live.values(), Fraction())
    success = sum(completed.values(), Fraction())
    assert success + abort == 1
    by_stop = defaultdict(Fraction)
    by_counts = defaultdict(Fraction)
    x_extra = z_extra = Fraction()
    for (t,x,z), mass in completed.items():
        by_stop[t] += mass
        by_counts[(x,z)] += mass
        if x>n_x: x_extra += mass
        if z>k_z: z_extra += mass
    # First passage: at stopping time at most one basis count may exceed quota.
    assert all(not (x>n_x and z>k_z) for (_,x,z) in completed)
    return {
        'event_probs': probs, 'joint': dict(completed), 'by_stop':dict(by_stop),
        'by_counts':dict(by_counts), 'p_success':success, 'p_abort':abort,
        'p_x_overshoot': x_extra, 'p_z_overshoot': z_extra,
        'p_x_overshoot_given_success': x_extra/success if success else None,
        'p_z_overshoot_given_success': z_extra/success if success else None,
        'mean_stop_given_success': sum((Fraction(t)*mass for t,mass in by_stop.items()),Fraction())/success if success else None,
        'n_x':n_x,'k_z':k_z,'cap':cap,
    }


def enumerate_small(n_x: int, k_z: int, cap: int, p_x: str | Fraction = '1/2') -> dict:
    """Independent exhaustive path enumeration for tiny caps (<=10)."""
    _arguments(n_x,k_z,cap)
    if cap > 10:
        raise ValueError('exhaustive oracle restricted to cap <= 10')
    probs = event_probabilities(p_x)
    joint=defaultdict(Fraction)
    abort=Fraction()
    for length in range(1,cap+1):
        for path in itertools.product('XZM',repeat=length):
            x=z=0
            finished_at=None
            for j,ev in enumerate(path,1):
                x += ev=='X'; z += ev=='Z'
                if x>=n_x and z>=k_z:
                    finished_at=j
                    break
            if finished_at != length:
                continue
            mass=Fraction(1)
            for ev in path:
                mass*=probs[ev]
            joint[(length,x,z)]+=mass
    for path in itertools.product('XZM',repeat=cap):
        x=path.count('X'); z=path.count('Z')
        if x>=n_x and z>=k_z:
            continue
        mass=Fraction(1)
        for ev in path:mass*=probs[ev]
        abort+=mass
    assert sum(joint.values(),Fraction())+abort == 1
    return {'joint':dict(joint),'p_abort':abort}


def subset_probability(population: int, selected: int) -> Fraction:
    if type(population) is not int or type(selected) is not int or population < 0 or not 0 <= selected <= population:
        raise ValueError('invalid subset dimensions')
    return Fraction(1,comb(population,selected))


def public_report(model: dict) -> dict:
    def decimal(v): return None if v is None else float(v)
    return {
        'decision':'CLASSICAL_JOINT_STOPPING_ORACLE_COMPLETE',
        'n_x':model['n_x'],'k_z':model['k_z'],'cap':model['cap'],
        'event_probabilities': {k:decimal(v) for k,v in model['event_probs'].items()},
        'p_success':decimal(model['p_success']),'p_abort_cap':decimal(model['p_abort']),
        'p_x_overshoot':decimal(model['p_x_overshoot']),
        'p_z_overshoot':decimal(model['p_z_overshoot']),
        'p_x_overshoot_given_success':decimal(model['p_x_overshoot_given_success']),
        'p_z_overshoot_given_success':decimal(model['p_z_overshoot_given_success']),
        'mean_stop_given_success':decimal(model['mean_stop_given_success']),
        'joint_stop_count_pmf': {f't={t},x={x},z={z}':decimal(p) for (t,x,z),p in sorted(model['joint'].items())},
        'conditional_subset_uniform_given_preselection_population':'COMBINATORIAL_ONLY',
        'conditional_on_complete_public_transcript_uniform':False,
        'theorem_stopping_rule_validated':False,
        'theorem_sampling_validated':False,
        'security_model_validated':False,
        'hpke_export_authorized':False,
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--n-x',type=int,default=2)
    parser.add_argument('--k-z',type=int,default=2)
    parser.add_argument('--cap',type=int,default=12)
    parser.add_argument('--p-x',default='1/2')
    args=parser.parse_args()
    report=public_report(exact_joint(args.n_x,args.k_z,args.cap,args.p_x))
    print(json.dumps(report,indent=2,sort_keys=True))
    print('QKD_M1H4F_EXACT_QUOTA_DISTRIBUTION_STATUS=PASS')
    print('QKD_M1H4F_THEOREM_SAMPLING_VALIDATED=false')
    print('QKD_M1H4F_SECURITY_MODEL_VALIDATED=false')
    print('QKD_M1H4F_HPKE_EXPORT_AUTHORIZED=false')

if __name__=='__main__':main()
