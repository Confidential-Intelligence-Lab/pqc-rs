"""M1.H2/H4.D: authenticated X selection and full eligible Z disclosure from BB84 records.

Experimental model only. Randomness/authentication provisioning/security theorem
assumptions are not validated. No key material is output or exported.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import random
import secrets
from typing import Callable

from m1g5b_authenticated_transcript import PublicDiscussion, TranscriptError
from m1g5c1_measurement_transcript import simulate_records
from m1g3_tomamichel_bound import BoundInput, evaluate as numerical_bound

DOMAIN = b'pqc-rs/qkd/h2/authenticated-selection/v1\x00'
STEPS = (('alice', 'x_key_selection'), ('alice', 'z_test_selection'),
         ('alice', 'z_test_bits_alice'), ('bob', 'z_test_bits_bob'),
         ('bob', 'z_error_summary'), ('alice', 'final_decision'))


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _matched(alice_bases: list[int], bob_bases: list[int], basis: int) -> list[int]:
    return [i for i, (a, b) in enumerate(zip(alice_bases, bob_bases)) if a == b == basis]


def _selected(values, eligible, expected):
    if (type(values) is not list or len(values) != expected or
        any(type(v) is not int for v in values) or
        len(set(values)) != len(values) or
        any(v not in eligible for v in values)):
        raise TranscriptError('invalid or nonmember selection')


def _bits(values, size):
    if type(values) is not list or len(values) != size or any(type(v) is not int or v not in (0, 1) for v in values):
        raise TranscriptError('invalid disclosure bits')


def run_records(alice, bob, *, n_key: int, k_test: int, max_transmissions: int,
                q_tolerance: float = .05, leakage_ec_bits: int = 0,
                epsilon_secrecy: float = 1e-10, epsilon_correctness: float = 1e-10,
                authentication_key: bytes | None = None, session_id: bytes | None = None,
                selection_seed: int | None = None, hook: Callable | None = None,
                selection_streams=None, s3c_pair=None) -> dict:
    """Run per-peer authenticated protocol; hooks operate on transmitted bytes/tags.

    The selection_seed is a public *test fixture* option, not secret randomness.
    The public discussion MAC key must be independently provisioned in real QKD.
    """
    if type(n_key) is not int or n_key <= 0 or type(k_test) is not int or k_test <= 0:
        raise ValueError('invalid quotas')
    if (type(max_transmissions) is not int or max_transmissions < n_key+k_test or
        max_transmissions > 100000):
        raise ValueError('invalid transmission limit')
    if (type(selection_seed) is not int or selection_seed < 0) and selection_seed is not None:
        raise ValueError('invalid selection seed')
    if selection_streams is not None:
        from m1h3a_randomness import RandomnessStreams
        if not isinstance(selection_streams, RandomnessStreams) or selection_seed is not None:
            raise ValueError('selection_streams requires a randomness provider and no seed')
    if type(leakage_ec_bits) is not int or leakage_ec_bits < 0 or leakage_ec_bits > n_key:
        raise ValueError('invalid provisional leakage')
    if not alice or len(alice) != len(bob) or len(alice) > max_transmissions:
        raise ValueError('invalid measurement lengths')
    # Reject unsupported security parameters before opening a protocol session.
    numerical_bound(BoundInput(n_key, k_test, q_tolerance, leakage_ec_bits,
                               epsilon_secrecy, epsilon_correctness))
    a_bases = [r.basis for r in alice]
    b_bases = [r.basis for r in bob]
    for a, b in zip(alice, bob):
        if (type(a.basis) is not int or a.basis not in (0, 1) or
            type(b.basis) is not int or b.basis not in (0, 1) or
            type(a.bit) is not int or a.bit not in (0, 1) or
            type(b.bit) is not int or b.bit not in (0, 1)):
            raise ValueError('invalid measurement record')
    # The strict S3.C path uses two independent per-role authenticated states.
    # Legacy standalone diagnostic tests may omit s3c_pair.
    if s3c_pair is not None:
        from s3c_authenticated_transcript import TranscriptSession
        if (type(s3c_pair) is not tuple or len(s3c_pair) != 2 or
                any(not isinstance(x, TranscriptSession) for x in s3c_pair)):
            raise ValueError('invalid paired authenticated transcript')
        if authentication_key is None or session_id is None:
            raise ValueError('S3.C requires provisioned authentication and explicit session ID')
        s3c_alice, s3c_bob = s3c_pair

        def s3c_wire(sender_role, kind, body, tag):
            from s3c_authenticated_transcript import canonical, TranscriptError
            sender, receiver = ((s3c_alice, s3c_bob) if sender_role == 'alice'
                                else (s3c_bob, s3c_alice))
            # Transitional double authenticated envelope: S3.C is the *wire*
            # transport, and legacy inner MAC verification is retained until
            # S3.C-2b replaces the old paths. Receiver uses only verified bytes.
            wire_payload = canonical({'body_hex': body.hex(), 'tag_hex': tag.hex()})
            outer, outer_tag = sender.send('h2_' + kind, wire_payload)
            delivered_stage, delivered = receiver.receive(outer, outer_tag)
            if delivered_stage != 'h2_' + kind:
                sender.abort(); receiver.abort()
                raise TranscriptError('unexpected authenticated H2 message')
            import json as _json
            obj = _json.loads(delivered)
            if (type(obj) is not dict or set(obj) != {'body_hex', 'tag_hex'} or
                    type(obj['body_hex']) is not str or type(obj['tag_hex']) is not str):
                sender.abort(); receiver.abort()
                raise TranscriptError('invalid S3.C inner encoding')
            actual_body = bytes.fromhex(obj['body_hex'])
            actual_tag = bytes.fromhex(obj['tag_hex'])
            if canonical({'body_hex': actual_body.hex(), 'tag_hex': actual_tag.hex()}) != delivered:
                sender.abort(); receiver.abort()
                raise TranscriptError('noncanonical S3.C inner encoding')
            return actual_body, actual_tag
    key = authentication_key if authentication_key is not None else os.urandom(32)
    sid = session_id if session_id is not None else os.urandom(24)
    pa = PublicDiscussion(key, sid, 'alice')
    pb = PublicDiscussion(key, sid, 'bob')

    def send_basis(sender, receiver, kind, payload):
        data, tag = sender.send(kind, payload)
        if hook:
            data, tag = hook(kind, data, tag)
        if s3c_pair is not None:
            role = 'alice' if sender is pa else 'bob'
            data, tag = s3c_wire(role, kind, data, tag)
        receiver.receive(data, tag)

    send_basis(pa, pb, 'alice_bases', {'bases': a_bases})
    send_basis(pb, pa, 'bob_bases', {'bases': b_bases})
    # Both peers derive eligibility from their own bases and authenticated peer bases.
    ax = _matched(a_bases, pa._bob_bases, 1)
    az = _matched(a_bases, pa._bob_bases, 0)
    bx = _matched(pb._alice_bases, b_bases, 1)
    bz = _matched(pb._alice_bases, b_bases, 0)
    if ax != bx or az != bz:
        raise TranscriptError('sifting disagrees')
    if len(ax) < n_key or len(az) < k_test:
        send_basis(pa, pb, 'abort', {'reason': 'QUOTAS_UNMET'})
        if s3c_pair is not None:
            if (not s3c_alice.status().closed or not s3c_bob.status().closed or
                    s3c_alice.status().transcript_digest != s3c_bob.status().transcript_digest):
                raise TranscriptError('S3.C abort transcript disagreement')
        return {'decision': 'ABORT_QUOTAS', 'authenticated_abort': True,
                'security_model_validated': False, 'hpke_export_authorized': False}
    send_basis(pa, pb, 'quota_status', {
        'decision': 'QUOTAS_MET', 'z_accepted': len(az),
        'x_accepted': len(ax), 'transmissions': len(alice)})
    actual_z_test_size = len(az)
    if pa.transcript_hash != pb.transcript_hash:
        raise TranscriptError('basis transcript mismatch')
    parent = pa.transcript_hash
    if selection_streams is None:
        rng = random.Random(selection_seed) if selection_seed is not None else secrets.SystemRandom()
        chosen_x = sorted(rng.sample(ax, n_key))
        chosen_z = list(az)  # Full eligible Z set: no post-sifting subsampling.
    else:
        chosen_x = sorted(ax[i] for i in selection_streams.sample_indices(len(ax), n_key))
        chosen_z = list(az)  # Full matched Z set, including quota overshoot.

    # Chained extension frames are authenticated under a distinct domain, and
    # bound to the verified G5.B basis transcript. G5.B is not marked finished.
    chain_a = chain_b = bytes.fromhex(parent)
    receiver_x = receiver_z = receiver_a = receiver_b = None
    checked_errors = None
    outcome = None

    for seq, (sender, kind) in enumerate(STEPS):
        if kind == 'x_key_selection':
            payload = {'indices': chosen_x}
        elif kind == 'z_test_selection':
            payload = {'indices': chosen_z}
        elif kind == 'z_test_bits_alice':
            payload = {'bits': [alice[i].bit for i in chosen_z]}
        elif kind == 'z_test_bits_bob':
            payload = {'bits': [bob[i].bit for i in receiver_z]}
        elif kind == 'z_error_summary':
            payload = {'sample_size': actual_z_test_size,
                       'error_count': sum(x != y for x, y in zip(receiver_a, receiver_b))}
        else:
            if checked_errors is None:
                raise TranscriptError('missing error verification')
            payload = {'decision': 'CONTINUE_UNQUALIFIED' if checked_errors/actual_z_test_size <= q_tolerance else 'ABORT'}
        frame = {'v': 1, 'sid': sid.hex(), 'parent': parent,
                 'seq': seq, 'previous': chain_a.hex(), 'sender': sender,
                 'kind': kind, 'payload': payload}
        data = _canon(frame)
        tag = hmac.digest(key, DOMAIN + data, 'sha256')
        if hook:
            data, tag = hook(kind, data, tag)
        if s3c_pair is not None:
            data, tag = s3c_wire(sender, kind, data, tag)
        if type(data) is not bytes or type(tag) is not bytes or len(data) > 1000000 or len(tag) != 32:
            raise TranscriptError('malformed extension frame')
        if not hmac.compare_digest(tag, hmac.digest(key, DOMAIN + data, 'sha256')):
            raise TranscriptError('extension MAC failed')
        try:
            received = json.loads(data)
            if type(received) is not dict or _canon(received) != data:
                raise ValueError('noncanonical frame')
        except (TypeError, ValueError, UnicodeError) as exc:
            raise TranscriptError('malformed canonical frame') from exc
        if (set(received) != set(frame) or
            any(received[k] != frame[k] for k in frame if k != 'payload') or
            received['previous'] != chain_b.hex()):
            raise TranscriptError('session, parent, sequence, sender or chain mismatch')
        value = received['payload']
        if type(value) is not dict or set(value) != set(payload):
            raise TranscriptError('invalid message fields')
        if kind == 'x_key_selection':
            _selected(value['indices'], bx, n_key)
            receiver_x = value['indices']
        elif kind == 'z_test_selection':
            _selected(value['indices'], bz, actual_z_test_size)
            if value['indices'] != bz:
                raise TranscriptError('Z selection must contain entire eligible population')
            if set(value['indices']) & set(receiver_x):
                raise TranscriptError('key and test indices overlap')
            receiver_z = value['indices']
        elif kind == 'z_test_bits_alice':
            _bits(value['bits'], actual_z_test_size)
            if value['bits'] != [alice[i].bit for i in receiver_z]:
                raise TranscriptError('Alice disclosure inconsistent with Alice records')
            receiver_a = value['bits']
        elif kind == 'z_test_bits_bob':
            _bits(value['bits'], actual_z_test_size)
            if value['bits'] != [bob[i].bit for i in receiver_z]:
                raise TranscriptError('Bob disclosure inconsistent with Bob records')
            receiver_b = value['bits']
        elif kind == 'z_error_summary':
            verified = sum(x != y for x, y in zip(receiver_a, receiver_b))
            if (type(value['sample_size']) is not int or value['sample_size'] != actual_z_test_size or
                type(value['error_count']) is not int or value['error_count'] != verified):
                raise TranscriptError('parameter estimation not independently verified')
            checked_errors = verified
        elif kind == 'final_decision':
            expected = 'CONTINUE_UNQUALIFIED' if checked_errors/actual_z_test_size <= q_tolerance else 'ABORT'
            if value['decision'] != expected:
                raise TranscriptError('inconsistent final decision')
            outcome = expected
        chain_a = hashlib.sha256(chain_a + data + tag).digest()
        chain_b = hashlib.sha256(chain_b + data + tag).digest()
        if chain_a != chain_b:
            raise TranscriptError('transcript hash divergence')

    if s3c_pair is not None:
        if (not s3c_alice.status().closed or not s3c_bob.status().closed or
                s3c_alice.status().transcript_digest != s3c_bob.status().transcript_digest):
            raise TranscriptError('S3.C parameter-estimation transcript disagreement')
    bound = numerical_bound(BoundInput(n_key, actual_z_test_size, q_tolerance,
                                      leakage_ec_bits, epsilon_secrecy, epsilon_correctness))
    return {
        'decision': 'PARAMETER_ESTIMATION_PASS_UNQUALIFIED' if outcome == 'CONTINUE_UNQUALIFIED' else 'ABORT_QBER',
        'transmissions': len(alice), 'key_basis': 'X', 'test_basis': 'Z',
        'x_key_bits': len(receiver_x), 'z_test_bits': len(receiver_z),
        'z_test_errors': checked_errors, 'observed_z_qber': checked_errors / actual_z_test_size,
        'configured_q_tolerance': q_tolerance,
        'authenticated_basis_announcements': True,
        'authenticated_x_key_selection': True, 'authenticated_z_test_selection': True,
        'authenticated_z_disclosures': True, 'statistics_independently_verified': True,
        'transcript_hash_agreement': chain_a == chain_b,
        's3c_h2_authenticated': s3c_pair is not None,
        's3c_h2_digest_agreement': (s3c_alice.status().transcript_digest ==
                                    s3c_bob.status().transcript_digest) if s3c_pair is not None else False,
        'public_discussion_messages': pa.seq + len(STEPS),
        'public_z_bits_disclosed': 2*actual_z_test_size, 'public_x_key_bits_disclosed': 0,
        'all_eligible_z_disclosed': True, 'eligible_z_count': len(az),
        'public_seed_is_not_secret': (selection_seed is not None or
                                       (selection_streams is not None and selection_streams.mode == 'fixture')),
        'source_randomness_qualified': False, 'authentication_provisioning_validated': False,
        'theorem_specific_protocol_validated': False,
        'numerical_bound': {'decision': bound['decision'],
                            'maximum_numerical_key_bits': bound['maximum_numerical_key_bits'],
                            'protocol_assumptions_verified': False},
        'security_model_validated': False, 'security_qualified': False,
        'hpke_export_authorized': False,
        'provenance': 'CUDA_Q_SIMULATION_NOT_SECURE_QKD',
    }


def experiment(*, n_key=128, k_test=128, max_transmissions=4096,
               seed=20261120, intercept_percent=0, q_tolerance=.05,
               measure=None, hook=None) -> dict:
    alice, bob = simulate_records(n_z=k_test, k_x=n_key,
                                  max_transmissions=max_transmissions,
                                  seed=seed, intercept_percent=intercept_percent,
                                  measure=measure)
    return run_records(alice, bob, n_key=n_key, k_test=k_test,
                       max_transmissions=max_transmissions, q_tolerance=q_tolerance,
                       selection_seed=seed, hook=hook)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--n-key', type=int, default=128)
    p.add_argument('--k-test', type=int, default=128)
    p.add_argument('--max-transmissions', type=int, default=4096)
    p.add_argument('--seed', type=int, default=20261120)
    p.add_argument('--intercept-percent', type=int, default=0)
    p.add_argument('--q-tolerance', type=float, default=.05)
    a = p.parse_args()
    result = experiment(n_key=a.n_key, k_test=a.k_test,
                        max_transmissions=a.max_transmissions,
                        seed=a.seed, intercept_percent=a.intercept_percent,
                        q_tolerance=a.q_tolerance)
    print(json.dumps(result, sort_keys=True, indent=2))
    print('QKD_M1H2_AUTHENTICATED_SAMPLING_STATUS=PASS')
    print('QKD_M1H2_SECURITY_MODEL_VALIDATED=false')
    if result['decision'] != 'PARAMETER_ESTIMATION_PASS_UNQUALIFIED':
        raise SystemExit(2)


if __name__ == '__main__':
    main()
