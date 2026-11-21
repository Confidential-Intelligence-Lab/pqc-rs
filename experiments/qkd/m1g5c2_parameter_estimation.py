"""G5.C2: authenticated X-sample disclosures from actual simulated BB84 records.

Experimental numerical integration only. The deterministic simulated source is not
secret, selected X positions are quota-ordered (not random theorem sampling),
MAC key provisioning is not validated, and no key export is permitted.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from typing import Callable

from m1g5b_authenticated_transcript import PublicDiscussion, TranscriptError
from m1g5c1_measurement_transcript import simulate_records, _positions
from m1g3_tomamichel_bound import BoundInput, evaluate as numerical_bound

DOMAIN = b'pqc-rs/qkd/g5c2/x-sample-disclosure/v1\x00'


def _wire(sender: PublicDiscussion, receiver: PublicDiscussion, kind: str,
          payload: dict, hook=None) -> None:
    data, tag = sender.send(kind, payload)
    if hook is not None:
        data, tag = hook(kind, data, tag)
    receiver.receive(data, tag)


def _disclose(key: bytes, session_id: bytes, binding: str, kind: str,
              indices: list[int], bits: list[int], order: int, hook=None) -> list[int]:
    """Model an independently authenticated public bit disclosure.

    The verifier receives only the authenticated frame, not the sender's local
    record objects. Session/transcript/order/index bindings prevent substitution.
    """
    if len(indices) != len(bits) or not indices or any(type(b) is not int or b not in (0, 1) for b in bits):
        raise TranscriptError('invalid public sample bit disclosure')
    frame = {'v': 1, 'sid': session_id.hex(), 'parent': binding,
             'kind': kind, 'exchange_order': order, 'indices': indices,
             'bits': bits}
    canonical = lambda obj: json.dumps(obj, sort_keys=True, separators=(',', ':'),
                                       ensure_ascii=True, allow_nan=False).encode('ascii')
    data = canonical(frame)
    tag = hmac.digest(key, DOMAIN + data, 'sha256')
    if hook is not None:
        data, tag = hook(kind, data, tag)
    if type(data) is not bytes or type(tag) is not bytes or len(data) > 1000000 or len(tag) != 32:
        raise TranscriptError('malformed public sample disclosure')
    if not hmac.compare_digest(tag, hmac.digest(key, DOMAIN + data, 'sha256')):
        raise TranscriptError('sample disclosure authentication failed')
    try:
        decoded = json.loads(data)
        if type(decoded) is not dict or canonical(decoded) != data:
            raise ValueError('noncanonical frame')
    except (ValueError, TypeError, UnicodeError) as exc:
        raise TranscriptError('invalid public sample frame') from exc
    if set(decoded) != set(frame) or any(decoded[k] != frame[k] for k in frame if k != 'bits'):
        raise TranscriptError('sample disclosure context mismatch')
    received_bits = decoded['bits']
    if type(received_bits) is not list or len(received_bits) != len(indices) or any(
        type(b) is not int or b not in (0, 1) for b in received_bits
    ):
        raise TranscriptError('invalid authenticated sample bits')
    return received_bits


def evaluate_records(alice_records, bob_records, *, n_z: int, k_x: int,
                     max_transmissions: int, q_tolerance: float,
                     leakage_ec_bits: int, epsilon_secrecy: float,
                     epsilon_correctness: float,
                     authentication_key: bytes | None = None,
                     session_id: bytes | None = None,
                     frame_hook: Callable | None = None) -> dict:
    if type(n_z) is not int or n_z < 1 or type(k_x) is not int or k_x < 1:
        raise ValueError('invalid quotas')
    if type(max_transmissions) is not int or max_transmissions < n_z + k_x or max_transmissions > 100000:
        raise ValueError('invalid transmission limit')
    if not alice_records or len(alice_records) != len(bob_records) or len(alice_records) > max_transmissions:
        raise ValueError('invalid measurement record lengths')
    # Validate numerical parameters BEFORE opening an authenticated session.
    bound_input = BoundInput(n_z, k_x, q_tolerance, leakage_ec_bits,
                             epsilon_secrecy, epsilon_correctness)
    numerical_bound(bound_input)
    key = authentication_key if authentication_key is not None else os.urandom(32)
    sid = session_id if session_id is not None else os.urandom(24)
    alice_peer = PublicDiscussion(key, sid, 'alice')
    bob_peer = PublicDiscussion(key, sid, 'bob')
    a_bases = [r.basis for r in alice_records]
    b_bases = [r.basis for r in bob_records]
    _wire(alice_peer, bob_peer, 'alice_bases', {'bases': a_bases}, frame_hook)
    _wire(bob_peer, alice_peer, 'bob_bases', {'bases': b_bases}, frame_hook)
    # Derive sifting indices from each peer's authenticated bases, not aggregate totals.
    z_a, x_a, mismatch_a = _positions(a_bases, alice_peer._bob_bases, n_z, k_x)
    z_b, x_b, mismatch_b = _positions(bob_peer._alice_bases, b_bases, n_z, k_x)
    if (z_a, x_a, mismatch_a) != (z_b, x_b, mismatch_b):
        raise TranscriptError('sifting positions disagree')
    if len(z_a) != n_z or len(x_a) != k_x:
        _wire(alice_peer, bob_peer, 'abort', {'reason': 'QUOTAS_UNMET'}, frame_hook)
        return {'decision': 'ABORT_QUOTAS', 'security_model_validated': False,
                'hpke_export_authorized': False, 'transcript_hash_agreement':
                alice_peer.transcript_hash == bob_peer.transcript_hash}
    _wire(alice_peer, bob_peer, 'quota_status', {
        'decision': 'QUOTAS_MET', 'z_accepted': n_z, 'x_accepted': k_x,
        'transmissions': len(alice_records)}, frame_hook)
    # G5.B expects indices in the entire X-matched population. Retain the first
    # k_x X matches selected by quota policy; they are NOT random samples.
    all_x_positions = [i for i, (a, b) in enumerate(zip(a_bases, b_bases)) if a == b == 1]
    selected = [all_x_positions.index(i) for i in x_a]
    assert len(selected) == k_x
    _wire(alice_peer, bob_peer, 'sample_selection', {
        'indices': selected, 'population_size': len(all_x_positions)}, frame_hook)
    binding = alice_peer.transcript_hash
    if binding != bob_peer.transcript_hash:
        raise TranscriptError('transcript disagreement before disclosures')
    # The X test bits are intentionally public: Alice and Bob can *both* verify
    # the reported error count. No Z-key bits are sent in the public discussion.
    a_test = _disclose(key, sid, binding, 'alice_x_sample_bits', selected,
                       [alice_records[i].bit for i in x_a], 0, frame_hook)
    b_test = _disclose(key, sid, binding, 'bob_x_sample_bits', selected,
                       [bob_records[i].bit for i in x_b], 1, frame_hook)
    errors = sum(a != b for a, b in zip(a_test, b_test))
    observed_qber = errors / k_x
    _wire(bob_peer, alice_peer, 'sample_statistics', {
        'sample_size': k_x, 'error_count': errors}, frame_hook)
    # NOTE: threshold must be fixed in advance; it is not measured QBER itself.
    passed = observed_qber <= q_tolerance
    _wire(alice_peer, bob_peer, 'final_decision', {
        'decision': 'CONTINUE_UNQUALIFIED' if passed else 'ABORT'}, frame_hook)
    if alice_peer.transcript_hash != bob_peer.transcript_hash:
        raise TranscriptError('final transcript mismatch')
    bound = numerical_bound(bound_input) if passed else None
    return {
        'decision': 'PARAMETER_ESTIMATION_PASS_UNQUALIFIED' if passed else 'ABORT_ERROR_THRESHOLD',
        'transmissions': len(alice_records), 'z_key_bits': n_z, 'x_test_bits': k_x,
        'x_test_errors': errors, 'observed_x_qber': observed_qber,
        'configured_q_tolerance': q_tolerance,
        'accepted_x_positions': len(x_a),
        'x_test_bits_disclosed_publicly': 2 * k_x,
        'z_key_bits_disclosed_publicly': 0,
        'basis_announcements_authenticated': True,
        'sample_disclosures_authenticated': True,
        'sample_statistics_independently_checkable': True,
        'transcript_hash_agreement': True,
        'public_discussion_messages': alice_peer.seq + 2,
        'parameter_estimation_quota_ordered_not_random': True,
        'numerical_bound': {
            'decision': bound['decision'] if bound is not None else 'NOT_APPLICABLE_ABORT',
            'maximum_numerical_key_bits': bound['maximum_numerical_key_bits'] if bound is not None else 0,
            'phase_error_upper': bound['phase_error_upper'] if bound is not None else None,
            'protocol_assumptions_verified': False,
        },
        'authentication_key_provisioning_validated': False,
        'theorem_specific_protocol_validated': False,
        'security_model_validated': False, 'security_qualified': False,
        'hpke_export_authorized': False,
        'provenance': 'CUDA_Q_SIMULATION_NOT_SECURE_QKD',
    }


def experiment(*, n_z: int, k_x: int, max_transmissions: int, seed: int,
               z_probability: float = .5, intercept_percent: int = 0,
               q_tolerance: float = .05, leakage_ec_bits: int = 0,
               epsilon_secrecy: float = 1e-10,
               epsilon_correctness: float = 1e-10,
               measure=None) -> dict:
    alice, bob = simulate_records(n_z=n_z, k_x=k_x,
                                  max_transmissions=max_transmissions, seed=seed,
                                  z_probability=z_probability,
                                  intercept_percent=intercept_percent,
                                  measure=measure)
    return evaluate_records(alice, bob, n_z=n_z, k_x=k_x,
                            max_transmissions=max_transmissions,
                            q_tolerance=q_tolerance,
                            leakage_ec_bits=leakage_ec_bits,
                            epsilon_secrecy=epsilon_secrecy,
                            epsilon_correctness=epsilon_correctness)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--n-z', type=int, default=128)
    ap.add_argument('--k-x', type=int, default=128)
    ap.add_argument('--max-transmissions', type=int, default=4096)
    ap.add_argument('--seed', type=int, default=20261120)
    ap.add_argument('--z-probability', type=float, default=.5)
    ap.add_argument('--intercept-percent', type=int, default=0)
    ap.add_argument('--q-tolerance', type=float, default=.05)
    ap.add_argument('--leak-ec', type=int, default=0)
    ap.add_argument('--epsilon-sec', type=float, default=1e-10)
    ap.add_argument('--epsilon-cor', type=float, default=1e-10)
    args = ap.parse_args()
    result = experiment(n_z=args.n_z, k_x=args.k_x,
                        max_transmissions=args.max_transmissions, seed=args.seed,
                        z_probability=args.z_probability,
                        intercept_percent=args.intercept_percent,
                        q_tolerance=args.q_tolerance, leakage_ec_bits=args.leak_ec,
                        epsilon_secrecy=args.epsilon_sec,
                        epsilon_correctness=args.epsilon_cor)
    print(json.dumps(result, indent=2, sort_keys=True))
    print('QKD_M1G5C2_AUTHENTICATED_PARAMETER_ESTIMATION_STATUS=PASS')
    print('QKD_M1G5C2_SECURITY_MODEL_VALIDATED=false')
    if result['decision'].startswith('ABORT'):
        raise SystemExit(2)


if __name__ == '__main__':
    main()
