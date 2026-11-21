"""M2.A: authenticated BB84 observations -> experimental distillation lifecycle.

All results are unqualified. No key material is serialized or exported to HPKE.
The MAC-key provisioning, quantum entropy bound, reconciliation theorem and
security composition are not established by this experiment.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import secrets

from m1h2_authenticated_sampling import run_records
from s2a2_syndrome_reconciliation import SyndromeError, reconcile_syndromes, public_report
from m1e3_finite_key import FiniteKeyInput, evaluate
from m1e2_privacy_amplification import random_toeplitz_seed, toeplitz_hash


def _pack(bits: str) -> bytes:
    return (int(bits, 2) << ((-len(bits)) % 8)).to_bytes((len(bits) + 7) // 8, 'big')


def run_distillation(alice, bob, *, n_key: int, k_test: int,
                     max_transmissions: int, q_tolerance: float = .05,
                     requested_key_bits: int = 32, block_size: int = 128,
                     epsilon_pa: float = 1e-6, confirmation_tag_bits: int = 40,
                     selection_seed: int | None = None, selection_streams=None,
                     demo_pre_leak_min_entropy_bits: float | None = None,
                     hook=None) -> dict:
    """Capture authenticated X indices, then run S2.A2 syndrome reconciliation.

    Optional entropy is a HYPOTHETICAL illustration, never external evidence.
    Even if PA executes in illustration mode, its bytes never leave this call.
    """
    if type(requested_key_bits) is not int or requested_key_bits <= 0:
        raise ValueError('invalid key bit request')
    if type(block_size) is not int or block_size != 128:
        raise ValueError('S2.A2 requires 128-bit syndrome blocks; no implicit padding')
    if type(confirmation_tag_bits) is not int or not 1 <= confirmation_tag_bits <= 256:
        raise ValueError('invalid confirmation tag bits')
    if demo_pre_leak_min_entropy_bits is not None and not isinstance(demo_pre_leak_min_entropy_bits, (int, float)):
        raise ValueError('invalid hypothetical entropy')
    selected = []

    def observe(kind, data, tag):
        if hook is not None:
            data, tag = hook(kind, data, tag)
        if kind == 'x_key_selection':
            try:
                frame = json.loads(data)
                indices = frame['payload']['indices']
            except (TypeError, ValueError, KeyError) as exc:
                raise ValueError('invalid authenticated X-selection frame') from exc
            # Only used after run_records validates this MAC and selection.
            selected.append(indices)
        return data, tag

    h2 = run_records(alice, bob, n_key=n_key, k_test=k_test,
                     max_transmissions=max_transmissions, q_tolerance=q_tolerance,
                     selection_seed=selection_seed, selection_streams=selection_streams,
                     hook=observe)
    base = {
        'provenance': 'CUDA_Q_SIMULATION_NOT_SECURE_QKD',
        'authenticated_parameter_estimation': h2,
        'privacy_amplification': {'status': 'NOT_RUN', 'key_bytes_exported': False},
        'finite_key': {'decision': 'REJECT', 'reason': 'PARAMETER_ESTIMATION_NOT_ACCEPTED'},
        'reconciliation': {'status': 'NOT_RUN'},
        'qkd_psk_available': False, 'security_model_validated': False,
        'security_qualified': False, 'hpke_export_authorized': False,
        'authentication_provisioning_validated': False,
        'quantum_min_entropy_proven': False,
    }
    if h2['decision'] != 'PARAMETER_ESTIMATION_PASS_UNQUALIFIED':
        base['decision'] = 'ABORT_PARAMETER_ESTIMATION'
        return base
    if len(selected) != 1 or not h2['transcript_hash_agreement']:
        raise ValueError('missing or inconsistent authenticated X selection')
    indices = selected[0]
    eligible_x = {i for i, (a, b) in enumerate(zip(alice, bob)) if a.basis == b.basis == 1}
    if (type(indices) is not list or len(indices) != n_key or
        len(set(indices)) != n_key or any(type(i) is not int or i not in eligible_x for i in indices)):
        raise ValueError('X selection inconsistent with authenticated records')
    alice_key = ''.join(str(alice[i].bit) for i in indices)
    bob_key = ''.join(str(bob[i].bit) for i in indices)
    # A short diagnostic key must not be silently padded or processed by the
    # legacy parity-search implementation. The full security path requires at
    # least one 128-bit S2.A2 block; the final block may be shorter.
    if n_key < 128:
        base['decision'] = 'ABORT_UNSUPPORTED_RECONCILIATION_SIZE'
        base['reconciliation'] = {'status': 'NOT_RUN', 'reason': 'RAW_KEY_BELOW_128_BITS'}
        return base
    try:
        # The simulator owns both parties' private records. Only the S2.A2
        # protocol's authenticated syndromes and universal-hash confirmation
        # decide acceptance; never compare both raw keys as an acceptance gate.
        corrected, ec = reconcile_syndromes(
            alice_key, bob_key, session_id=secrets.token_bytes(16),
            authentication_key=secrets.token_bytes(32),
            tag_bits=confirmation_tag_bits)
    except SyndromeError:
        base['decision'] = 'ABORT_RECONCILIATION'
        base['reconciliation'] = {'status': 'REJECT'}
        return base
    base['reconciliation'] = {
        'status': 'PASS', 'mechanism': 'S2A2_AUTHENTICATED_SYNDROME',
        'decoder_guarantee': ec.decoder_guarantee,
        'corrected_bits': ec.corrected_errors,
        'syndrome_leak_bits': ec.syndrome_leakage_upper_bound_bits,
        'parity_leak_bits': ec.syndrome_leakage_upper_bound_bits,
        'confirmation_leak_bits': ec.confirmation_leakage_upper_bound_bits,
        'total_leak_bits': ec.total_leakage_upper_bound_bits,
        'authenticated_syndrome_messages': ec.authenticated_syndrome_messages,
        'authenticated_confirmation_messages': ec.authenticated_confirmation_messages,
        'epsilon_correctness_bound': ec.epsilon_correctness_bound,
        'confirmed': True, 'authentication_provisioning_validated': False,
    }
    base['correctness_bound'] = ec.epsilon_correctness_bound
    demo = demo_pre_leak_min_entropy_bits is not None
    f = evaluate(FiniteKeyInput(
        sifted_bits=n_key + h2['z_test_bits'],
        test_bits=h2['z_test_bits'], test_errors=h2['z_test_errors'],
        reconciled_bits=n_key,
        reconciliation_leak_bits=ec.syndrome_leakage_upper_bound_bits,
        confirmation_leak_bits=ec.confirmation_leakage_upper_bound_bits,
        requested_key_bits=requested_key_bits, epsilon_pa=epsilon_pa,
        pre_leak_min_entropy_bits=demo_pre_leak_min_entropy_bits,
        entropy_evidence_id='HYPOTHETICAL_ONLY_NOT_EVIDENCE' if demo else None,
        authenticated_transcript=True,
        uniform_independent_toeplitz_seed=True,
        reconciliation_confirmed=True))
    base['finite_key'] = asdict(f)
    base['entropy_evidence'] = 'HYPOTHETICAL_ONLY' if demo else 'MISSING'
    if demo and f.decision == 'CONDITIONAL_PASS':
        # Data is ephemeral and NOT exported or represented as an authorized PSK.
        seed = random_toeplitz_seed(n_key, requested_key_bits)
        pa_a = toeplitz_hash(_pack(alice_key), n_key, requested_key_bits, seed)
        pa_b = toeplitz_hash(_pack(corrected), n_key, requested_key_bits, seed)
        base['privacy_amplification'] = {
            'status': 'HYPOTHETICAL_DEMO_ONLY' if pa_a.key == pa_b.key else 'REJECT',
            'alice_bob_agree': pa_a.key == pa_b.key,
            'key_bytes_exported': False,
        }
        del pa_a, pa_b, seed
    base['decision'] = ('DISTILLATION_DEMO_UNQUALIFIED'
                        if base['privacy_amplification']['status'] == 'HYPOTHETICAL_DEMO_ONLY'
                        else 'REJECT_NO_VERIFIED_ENTROPY')
    return base
