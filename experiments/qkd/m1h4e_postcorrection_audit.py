"""H4.E post-correction structural audit and strict-reference CANDIDATE.

Exposes observable properties and open proof obligations. Not a security proof.
No quantum secret key is emitted; no HPKE export is permitted.
"""
from __future__ import annotations
import argparse
import ast
import itertools
import json
from pathlib import Path

SYMBOLS = ('X', 'Z', 'M')


def stop(trace, nx, kz, cap=None):
    if type(nx) is not int or type(kz) is not int or nx < 1 or kz < 1:
        raise ValueError('invalid quotas')
    if cap is not None and (type(cap) is not int or cap < 1):
        raise ValueError('invalid transmission cap')
    x = z = 0
    for i, symbol in enumerate(trace, 1):
        if symbol not in SYMBOLS:
            raise ValueError('invalid basis event')
        if cap is not None and i > cap:
            break
        x += symbol == 'X'
        z += symbol == 'Z'
        if x >= nx and z >= kz:
            return {'decision': 'QUOTAS_MET', 'stop': i, 'matched_x': x,
                    'matched_z': z, 'z_excess': z-kz, 'x_excess': x-nx}
    return {'decision': 'ABORT_OR_INCOMPLETE', 'stop': None,
            'matched_x': x, 'matched_z': z, 'z_excess': max(z-kz, 0),
            'x_excess': max(x-nx, 0)}


def exhaustive(nx=1, kz=1, max_length=7):
    if type(max_length) is not int or not 2 <= max_length <= 10:
        raise ValueError('invalid exhaustive trace length')
    total = excess_z = excess_x = 0
    first_z = first_x = None
    for length in range(2, max_length+1):
        for trace in itertools.product(SYMBOLS, repeat=length):
            result = stop(trace, nx, kz)
            if result['stop'] != length:
                continue
            total += 1
            if result['z_excess']:
                excess_z += 1
                if first_z is None: first_z = ''.join(trace)
            if result['x_excess']:
                excess_x += 1
                if first_x is None: first_x = ''.join(trace)
    return {'first_stop_traces': total, 'traces_with_z_overshoot': excess_z,
            'traces_with_x_overshoot': excess_x,
            'z_overshoot_example': first_z, 'x_overshoot_example': first_x}


def guard_sources(source_dir):
    source_dir = Path(source_dir)
    names = ['m1h2_authenticated_sampling.py','m1h3a_randomness.py',
             'm1h3b_sampling_conformance.py']
    texts = {}
    for name in names:
        texts[name] = ast.unparse(ast.parse((source_dir/name).read_text(encoding='utf-8')))
    h2, h3a, h3b = (texts[n] for n in names)
    guards = {
        'h2_discloses_full_z_population': 'chosen_z = list(az)' in h2 and 'value[\'indices\'] != bz' in h2,
        'h2_uses_actual_z_count_for_bound': 'BoundInput(n_key, actual_z_test_size' in h2,
        'h2_uniformly_selects_x': 'rng.sample(ax, n_key)' in h2 and 'sample_indices(len(ax), n_key)' in h2,
        'h3a_quota_stop': 'z_count < n_z or x_count < k_x' in h3a,
        'h3a_tracks_quota_filled_events': 'z_count < n_z' in h3a and 'x_count < k_x' in h3a,
        'h3b_explicit_oversampling_parameter': 'n_z=k_test * oversample' in h3b and 'k_x=n_key * oversample' in h3b,
        'h3b_calls_authenticated_h2': 'selection_streams=randomness' in h3b,
    }
    if not all(guards.values()):
        raise RuntimeError('source changed: review required; '+str([k for k,v in guards.items() if not v]))
    return guards


def audit(source_dir, *, n_key=8, k_test=8, oversample=1, cap=256):
    for k in (n_key,k_test,oversample,cap):
        if type(k) is not int or k < 1:
            raise ValueError('positive integer configuration required')
    if cap < (n_key+k_test)*oversample:
        raise ValueError('cap shorter than minimal quota acquisition')
    guards=guard_sources(source_dir)
    proof_obligations={
        'z_parameter_estimation_full_matched_set': 'IMPLEMENTATION_CHECKED',
        'x_uniform_selection_before_public_sample_announcement': 'IMPLEMENTATION_CHECKED_NOT_THEOREM_PROOF',
        'explicit_oversampling_eliminated': oversample == 1,
        'quota_overshoot_distribution_mapped_to_theorem': False,
        'cap_abort_conditional_security_argument': False,
        'quantum_source_and_independence_assumptions': False,
        'authentication_key_provisioning': False,
        'finite_key_bound_parameters_and_leakage_proven': False,
    }
    return {
        'decision':'POSTCORRECTION_AUDIT_COMPLETE_OPEN_OBLIGATIONS',
        'mode':'STRICT_REFERENCE_CANDIDATE' if oversample == 1 else 'EXPERIMENTAL_OVERSAMPLING',
        'n_key':n_key,'k_test':k_test,'oversample':oversample,'cap':cap,
        'source_guards':guards,'exhaustive_small_traces':exhaustive(),
        'proof_obligations':proof_obligations,
        'box1_exact_protocol_equivalent':False,
        'theorem_sampling_validated':False,'security_model_validated':False,
        'security_qualified':False,'hpke_export_authorized':False,
    }


def strict_reference_candidate(*, n_key=8,k_test=8,cap=256,randomness_mode='fixture',fixture_seed=20261120,measure=None):
    """Use existing authenticated pipeline with oversample=1; NEVER claim conformance."""
    from m1h3b_sampling_conformance import experiment
    result = experiment(n_key=n_key,k_test=k_test,max_transmissions=cap,
                        randomness_mode=randomness_mode,fixture_seed=fixture_seed,
                        oversample=1,measure=measure)
    return dict(result, mode='STRICT_REFERENCE_CANDIDATE',
                exact_theorem_protocol_equivalent=False,
                theorem_stopping_rule_validated=False,
                theorem_sampling_distribution_validated=False,
                security_model_validated=False,security_qualified=False,
                hpke_export_authorized=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-dir',type=Path,default=Path(__file__).resolve().parent)
    p.add_argument('--n-key',type=int,default=8)
    p.add_argument('--k-test',type=int,default=8)
    p.add_argument('--oversample',type=int,default=1)
    p.add_argument('--cap',type=int,default=256)
    args=p.parse_args()
    print(json.dumps(audit(args.source_dir,n_key=args.n_key,k_test=args.k_test,
                           oversample=args.oversample,cap=args.cap),indent=2,sort_keys=True))
    print('QKD_M1H4E_POSTCORRECTION_AUDIT_STATUS=PASS')
    print('QKD_M1H4E_EXACT_BOX1_EQUIVALENCE=false')
    print('QKD_M1H4E_SECURITY_MODEL_VALIDATED=false')
    print('QKD_M1H4E_HPKE_EXPORT_AUTHORIZED=false')

if __name__=='__main__': main()
