"""H4.B: empirical sampling comparison against the independent H4.A oracle.

Classical basis/measurement backend exercises H3.A production acquisition. A separate
H3.B authenticated-session check exercises public subset announcements. No security proof.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
import math

from m1h3a_randomness import RandomnessConfiguration, RandomnessStreams, simulate_records
from m1h3b_sampling_conformance import experiment as authenticated_experiment
from m1h4a_sampling_model import QuotaModel, stopping_pmf, uniform_subset_probability


def ideal(bit: int, preparation: int, measurement: int) -> int:
    return bit if preparation == measurement else 0


def compare_stopping(*, n_x: int, k_z: int, p_x: float, cap: int, trials: int,
                     mode: str = 'fixture', seed_start: int = 17000) -> dict:
    if type(trials) is not int or trials < 100 or trials > 100000:
        raise ValueError('trials must be integer in [100,100000]')
    if mode not in ('fixture', 'os'):
        raise ValueError('unsupported randomness mode')
    oracle = stopping_pmf(QuotaModel(n_x, k_z, p_x, cap))
    observed = Counter()
    aborted = 0
    for i in range(trials):
        rng = RandomnessStreams(RandomnessConfiguration(mode, seed_start + i if mode == 'fixture' else None))
        alice, bob = simulate_records(n_z=k_z, k_x=n_x, max_transmissions=cap,
                                      randomness=rng, z_probability=1.0-p_x,
                                      measure=ideal)
        t = len(alice)
        x_count = sum(a.basis == b.basis == 1 for a,b in zip(alice,bob))
        z_count = sum(a.basis == b.basis == 0 for a,b in zip(alice,bob))
        if x_count >= n_x and z_count >= k_z:
            observed[t] += 1
        else:
            if t != cap:
                raise AssertionError('premature acquisition abort')
            aborted += 1
    empirical_abort = aborted / trials
    expected_abort = oracle['p_abort_cap']
    # DKW-style empirical-CDF envelope. This is a conservative engineering
    # acceptance heuristic, NOT a proof of the BB84 theorem assumptions.
    alpha = 0.001
    envelope = 1.35*math.sqrt(math.log(2/alpha)/(2*trials))
    cumulative_emp = 0.0
    cumulative_exact = 0.0
    max_cdf_difference = 0.0
    for t in range(n_x+k_z, cap+1):
        cumulative_emp += observed[t] / trials
        cumulative_exact += oracle['stop_pmf'].get(t,0.0)
        max_cdf_difference = max(max_cdf_difference, abs(cumulative_emp-cumulative_exact))
    max_cdf_difference = max(max_cdf_difference, abs(empirical_abort-expected_abort))
    return {
        'mode': mode, 'n_x': n_x, 'k_z': k_z, 'p_x': p_x, 'cap': cap,
        'trials': trials, 'oracle_abort_probability': expected_abort,
        'observed_abort_fraction': empirical_abort,
        'max_cdf_difference': max_cdf_difference, 'cdf_acceptance_envelope': envelope,
        'status': 'PASS' if max_cdf_difference <= envelope else 'FAIL',
        'security_model_validated': False,
    }


def compare_authenticated_subset(*, trials: int = 600, mode: str = 'fixture') -> dict:
    """Exercise actual H3.B authenticated selections; test X subset conditional on |X|=4.

    n_key=2, oversample=2 -> acquisition quota 4. Filter to |eligible X|=4;
    conditional on that event, the expected two-of-four subset is uniform.
    """
    if type(trials) is not int or trials < 100 or trials > 100000:
        raise ValueError('invalid subset trial count')
    if mode not in ('fixture','os'):
        raise ValueError('invalid randomness mode')
    chosen = Counter()
    eligible_events = 0
    sessions = 0
    for i in range(trials):
        bases = {}
        sample = {}
        def hook(kind, data, tag):
            # This is a passive observer of authenticated public messages only.
            frame = json.loads(data)
            if kind in ('alice_bases', 'bob_bases'):
                bases[kind] = frame['payload']['bases']
            if kind == 'x_key_selection':
                sample['indices'] = frame['payload']['indices']
            return data,tag
        r = authenticated_experiment(n_key=2, k_test=2, oversample=2,
                max_transmissions=90, randomness_mode=mode,
                fixture_seed=70000+i if mode=='fixture' else None,
                z_probability=.5, measure=ideal, hook=hook)
        if r['decision'] != 'PARAMETER_ESTIMATION_PASS_UNQUALIFIED':
            continue
        sessions += 1
        ax = [j for j,(a,b) in enumerate(zip(bases['alice_bases'],bases['bob_bases'])) if a==b==1]
        selected = sample['indices']
        if len(ax)==4:
            eligible_events += 1
            rank = tuple(sorted(ax.index(j) for j in selected))
            assert len(rank)==2 and len(set(rank))==2
            chosen[rank] += 1
    if eligible_events < 100:
        return {'status':'FAIL', 'reason':'INSUFFICIENT_CONDITIONAL_SUBSET_EVENTS',
                'conditional_events':eligible_events, 'sessions':sessions,
                'security_model_validated':False}
    all_pairs = [(a,b) for a in range(4) for b in range(a+1,4)]
    p = uniform_subset_probability(4,2,(0,1))
    expected = eligible_events*p
    chi2 = sum((chosen[pair]-expected)**2/expected for pair in all_pairs)
    # Chi-square df=5: threshold 20.515 corresponds to p approx 0.001.
    return {'mode':mode,'sessions':sessions,'conditional_events':eligible_events,
            'uniform_pair_reference':p, 'pair_counts':{f'{a}-{b}': chosen[(a,b)] for a,b in all_pairs},
            'chi_square_df5':chi2, 'chi_square_threshold':20.515,
            'status':'PASS' if chi2 <=20.515 else 'FAIL',
            'theorem_sampling_validated':False,'security_model_validated':False,
            'hpke_export_authorized':False}


def campaign(trials: int=1500, subset_trials: int=900) -> dict:
    cases = [(3,2,.5,32),(4,3,.5,36),(3,2,.35,50),(3,2,.65,50)]
    stopping = [compare_stopping(n_x=n,k_z=k,p_x=p,cap=cap,trials=trials,
               seed_start=20000+10000*j) for j,(n,k,p,cap) in enumerate(cases)]
    # OS mode is a separate run; statistics are not reproducible.
    stopping.append(compare_stopping(n_x=3,k_z=2,p_x=.5,cap=32,
                                    trials=trials,mode='os'))
    subset = compare_authenticated_subset(trials=subset_trials)
    ok = all(x['status']=='PASS' for x in stopping) and subset['status']=='PASS'
    return {'decision':'EMPIRICAL_COMPARISON_PASS' if ok else 'EMPIRICAL_COMPARISON_FAIL',
            'stopping':stopping,'authenticated_subset':subset,
            'theorem_sampling_validated':False,'security_model_validated':False,
            'security_qualified':False,'hpke_export_authorized':False}


if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--trials',type=int,default=1500)
    p.add_argument('--subset-trials',type=int,default=900)
    a=p.parse_args()
    result=campaign(a.trials,a.subset_trials)
    print(json.dumps(result,sort_keys=True,indent=2))
    print('QKD_M1H4B_EMPIRICAL_COMPARISON_STATUS='+('PASS' if result['decision']=='EMPIRICAL_COMPARISON_PASS' else 'FAIL'))
    print('QKD_M1H4B_THEOREM_SAMPLING_VALIDATED=false')
    print('QKD_M1H4B_SECURITY_MODEL_VALIDATED=false')
    if result['decision']!='EMPIRICAL_COMPARISON_PASS':
        raise SystemExit(2)
