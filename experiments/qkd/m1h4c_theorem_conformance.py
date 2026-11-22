"""H4.C: fail-closed structural audit of an idealized BB84 protocol implementation.

This is a conformance gap analysis, not a quantum security proof. No security
qualification, cryptographic key generation, or key export is performed.
"""
from __future__ import annotations

import argparse
import ast
import itertools
import json
from pathlib import Path

# A trace is a sequence of two-party basis outcomes: X (both X), Z (both Z),
# M (unmatched bases). All symbols are public basis information only.
SYMBOLS = ('X', 'Z', 'M')


def first_quota_stop(trace: tuple[str, ...], n_x: int, k_z: int) -> int | None:
    if type(n_x) is not int or type(k_z) is not int or n_x < 1 or k_z < 1:
        raise ValueError('quotas must be positive integers')
    x = z = 0
    for t, symbol in enumerate(trace, 1):
        if symbol not in SYMBOLS:
            raise ValueError('invalid public basis symbol')
        x += symbol == 'X'
        z += symbol == 'Z'
        if x >= n_x and z >= k_z:
            return t
    return None


def witness_extra_z() -> dict:
    """Shortest example where Z quota is met before the X quota."""
    # Quotas are one per basis; two Z matches precede the final X match.
    trace = ('Z', 'Z', 'X')
    stop = first_quota_stop(trace, 1, 1)
    assert stop == 3
    z_observed = trace[:stop].count('Z')
    z_disclosed_by_h2 = 1
    return {
        'public_basis_trace': ''.join(trace), 'stop_at': stop,
        'matched_z_at_stop': z_observed, 'h2_z_sample_size': z_disclosed_by_h2,
        'box1_uses_all_matched_z': True,
        'exact_z_parameter_estimation_equivalent': z_observed == z_disclosed_by_h2,
    }


def exhaustive_small_traces(max_length: int = 7) -> dict:
    if type(max_length) is not int or not 3 <= max_length <= 10:
        raise ValueError('max_length out of range')
    completed = 0
    with_extra_z = 0
    examples = []
    for length in range(2, max_length + 1):
        for trace in itertools.product(SYMBOLS, repeat=length):
            stop = first_quota_stop(trace, 1, 1)
            if stop != length:
                continue
            completed += 1
            if trace.count('Z') > 1:
                with_extra_z += 1
                if len(examples) < 3:
                    examples.append(''.join(trace))
    return {
        'completed_first_stop_traces': completed,
        'traces_with_more_z_than_test_quota': with_extra_z,
        'examples': examples,
        'counterexample_exists': with_extra_z > 0,
    }


def source_checks(root: Path) -> dict:
    """Reject unknown revisions rather than asserting behavior from assumptions.

    Checks deliberately use the specific AST assignments and calls in H3.A/B
    and H2. They are guards, not a sound static verifier of arbitrary Python.
    """
    files = {
        'h3a': root / 'm1h3a_randomness.py',
        'h3b': root / 'm1h3b_sampling_conformance.py',
        'h2': root / 'm1h2_authenticated_sampling.py',
    }
    trees = {k: ast.parse(p.read_text(encoding='utf-8')) for k, p in files.items()}
    h3a = ast.unparse(trees['h3a'])
    h3b = ast.unparse(trees['h3b'])
    h2 = ast.unparse(trees['h2'])
    checks = {
        'h3a_stops_at_both_quotas': 'z_count < n_z or x_count < k_x' in h3a,
        'h3a_counts_are_capped': 'z_count < n_z' in h3a and 'x_count < k_x' in h3a,
        'h3b_oversamples_both_populations': 'n_z=k_test * oversample' in h3b and 'k_x=n_key * oversample' in h3b,
        'h3b_uses_h2_authenticated_selection': 'selection_streams=randomness' in h3b,
        'h2_uses_full_z_population': 'chosen_z = list(az)' in h2 and 'rng.sample(az, k_test)' not in h2,
        'h2_discloses_all_matched_z': 'alice[i].bit for i in chosen_z' in h2 and "value['indices'] != bz" in h2,
        'h2_chooses_x_subset': 'rng.sample(ax, n_key)' in h2,
    }
    if not all(checks.values()):
        raise RuntimeError('source guard failed: audit requires manual review of changed implementation')
    return checks


def audit(root: Path, n_key: int, k_test: int, oversample: int, cap: int) -> dict:
    for v in (n_key, k_test, oversample, cap):
        if type(v) is not int or v <= 0:
            raise ValueError('positive integer parameters required')
    if cap < (n_key + k_test) * oversample:
        raise ValueError('cap below required acquisition counts')
    checks = source_checks(root)
    witness = witness_extra_z()
    exhaustive = exhaustive_small_traces()
    # Even oversample=1 is not enough: quota stopping can overshoot Z while X
    # acquisition remains incomplete, and H2 samples only k_test of those Zs.
    findings = {
        'basis_key_test_orientation': 'X_RAW_KEY_Z_PARAMETER_ESTIMATION',
        'acquisition_matches_quota_model': True,
        'h3b_acquisition_x_quota': n_key * oversample,
        'h3b_acquisition_z_quota': k_test * oversample,
        'h2_raw_x_size': n_key,
        'h2_disclosed_z_size': 'ALL_MATCHED_Z_AT_ACQUISITION_STOP',
        'box1_z_uses_entire_matched_z_set': True,
        'box1_z_disclosure_policy_equivalent': True,
        'box1_parameter_estimation_equivalent': False,
        'box1_exact_protocol_equivalent': False,
        'oversampling_is_an_extra_protocol_transformation': oversample != 1,
        'quota_overshoot_requires_z_policy_revision': False,
        'cap_abort_needs_separate_security_argument': True,
        'uniform_selection_is_conditional_on_preselection_eligibility': True,
        'uniformity_does_not_hold_conditioned_on_transcript_after_indices_are_announced': True,
        'device_and_authentication_assumptions_verified': False,
    }
    return {
        'decision': 'FORMAL_CONFORMANCE_GAPS_IDENTIFIED',
        'source_guards': checks, 'findings': findings,
        'z_overshoot_witness': witness,
        'exhaustive_public_basis_trace_check': exhaustive,
        'recommended_next_step': 'Review oversampled acquisition, realized k, stopping, and cap assumptions',
        'theorem_sampling_validated': False,
        'security_model_validated': False,
        'security_qualified': False,
        'hpke_export_authorized': False,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-dir', type=Path, default=Path(__file__).resolve().parent)
    p.add_argument('--n-key', type=int, default=16)
    p.add_argument('--k-test', type=int, default=16)
    p.add_argument('--oversample', type=int, default=2)
    p.add_argument('--cap', type=int, default=2048)
    a = p.parse_args()
    result = audit(a.source_dir, a.n_key, a.k_test, a.oversample, a.cap)
    print(json.dumps(result, sort_keys=True, indent=2))
    print('QKD_M1H4C_CONFORMANCE_AUDIT_STATUS=PASS')
    print('QKD_M1H4C_EXACT_BOX1_EQUIVALENCE=false')
    print('QKD_M1H4C_SECURITY_MODEL_VALIDATED=false')
    print('QKD_M1H4C_HPKE_EXPORT_AUTHORIZED=false')


if __name__ == '__main__':
    main()
