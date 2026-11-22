"""S5.D-4: role-separated S3.C authenticated Cascade trace (research only).

A single-process test orchestrator owns two logically separate role-local bitstrings.
Each parity bit is sent by its own S3.C authenticated endpoint; the other
endpoint verifies the public positions and shared message sequence. No keys
are exported. This is NOT a distributed transport, root-provisioning proof,
QKD secrecy proof, or a replacement for the original S3.D schedule.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from s3c_authenticated_transcript import TranscriptSession, TranscriptError, canonical
from s5d2_cascade_reconciliation import CascadeError, reconcile_cascade
from s5d3_bounded_cascade import BoundedProfile, BoundedCascadeError


class IntegratedCascadeError(ValueError):
    pass


def run_s3c_cascade(alice_bits: str, bob_bits: str, *, root: bytes,
                    session_id: bytes, key_id: str = 'research-root',
                    profile: BoundedProfile = BoundedProfile(),
                    permutation_seed: bytes, wire_hook=None) -> dict:
    """Synchronously drive two independently authenticated S3.C role states.

    The public outer transcript is genuine S3.C. The inner Cascade engine is
    still a single-process reference; this is *not* a two-process protocol.
    Aborts produce no key and do not assert a cryptographic advantage bound.
    """
    if type(profile) is not BoundedProfile or type(permutation_seed) is not bytes or len(permutation_seed) != 32:
        raise IntegratedCascadeError('explicit frozen profile and public 32-byte seed required')
    if (type(alice_bits) is not str or type(bob_bits) is not str or
            len(alice_bits) != profile.n_key or len(bob_bits) != profile.n_key or
            set(alice_bits) - {'0', '1'} or set(bob_bits) - {'0', '1'}):
        raise IntegratedCascadeError('invalid role-local binary inputs')
    if type(root) is not bytes or len(root) < 32:
        raise IntegratedCascadeError('externally provisioned >=32-byte root required')
    bound = profile.candidate()
    if not bound['numerical_fits']:
        raise IntegratedCascadeError('precommitted numeric leakage ceiling does not fit')
    ctx = dict(root=root, key_id=key_id, session_id=session_id,
               alice_id='alice', bob_id='bob', schedule_id='s5d4-cascade-v1',
               cascade_max_pairs=profile.max_parity_pairs,
               precommit_digest=profile.public_fingerprint())
    a = TranscriptSession(role='alice', **ctx)
    b = TranscriptSession(role='bob', **ctx)
    queries = 0
    sent = 0

    def exchange(sender, receiver, stage, payload):
        nonlocal sent
        body, tag = sender.send(stage, canonical(payload))
        if wire_hook is not None:
            body, tag = wire_hook(sent, stage, body, tag)
        actual_stage, data = receiver.receive(body, tag)
        if actual_stage != stage or data != canonical(payload):
            raise IntegratedCascadeError('verified payload does not match local expectation')
        sent += 1

    def query(seq, body, tag):
        nonlocal queries
        if seq != queries or queries >= profile.max_parity_pairs:
            raise IntegratedCascadeError('public parity-query limit exhausted')
        # The S5.D-2 engine is a local oracle. Recompute each parity from its
        # respective role-owned string to ensure the S3.C messages contain
        # genuine role-specific parity values rather than a relay echo.
        try:
            item = json.loads(body)
        except (ValueError, UnicodeError, TypeError) as exc:
            raise IntegratedCascadeError('malformed inner parity request') from exc
        if (type(item) is not dict or
                set(item) != {'v', 'sid', 'seq', 'positions', 'alice_parity', 'bob_parity'} or
                item['v'] != 1 or item['sid'] != session_id.hex() or item['seq'] != queries or
                type(item['positions']) is not list or not item['positions'] or
                any(type(i) is not int or i < 0 or i >= profile.n_key for i in item['positions']) or
                len(set(item['positions'])) != len(item['positions'])):
            raise IntegratedCascadeError('invalid inner query')
        positions = item['positions']
        alice_parity = sum(int(alice_bits[i]) for i in positions) & 1
        # Bob's local correction state may change after each query. The inner
        # engine owns that state: do not pretend this input is an independent
        # distributed Bob decoder. We validate against the signed local oracle
        # for Bob and report this trust boundary as unqualified.
        bob_parity = item['bob_parity']
        if item['alice_parity'] != alice_parity or type(bob_parity) is not int or bob_parity not in (0, 1):
            raise IntegratedCascadeError('role parity disagrees with local oracle')
        exchange(a, b, 'cascade_alice_parity', {
            'seq': seq, 'positions': positions, 'parity': alice_parity})
        exchange(b, a, 'cascade_bob_parity', {
            'seq': seq, 'positions': positions, 'parity': bob_parity})
        queries += 1
        return body, tag

    try:
        exchange(a, b, 'cascade_profile', {
            'profile_sha256': profile.public_fingerprint(),
            'public_permutation_seed': permutation_seed.hex(),
            'max_pairs': profile.max_parity_pairs,
            'n_key': profile.n_key})
        exchange(b, a, 'cascade_profile_ack', {
            'profile_sha256': profile.public_fingerprint(), 'accepted': True})
        corrected, report = reconcile_cascade(
            alice_bits, bob_bits, session_id=session_id,
            authentication_key=root, tag_bits=profile.confirmation_tag_bits,
            max_parity_pairs=profile.max_parity_pairs,
            permutation_seed=permutation_seed, wire_hook=query)
        if queries != report.public_parity_pairs or report.parity_disclosure_upper_bits != 2*queries:
            raise IntegratedCascadeError('public leakage/accounting disagreement')
        exchange(a, b, 'cascade_finish', {
            'pairs': queries, 'parity_disclosure_bits': 2*queries,
            'confirmation_passed_locally': True,
            'inner_public_digest': report.transcript_sha256})
        exchange(b, a, 'cascade_finish_ack', {'pairs': queries, 'accepted': True})
        exchange(a, b, 'cascade_commit', {'pairs': queries, 'decision': 'RESEARCH_UNQUALIFIED'})
        sa, sb = a.status(), b.status()
        if (not sa.closed or not sb.closed or sa.aborted or sb.aborted or
                sa.event_count != sent or sa.event_count != sb.event_count or
                sa.transcript_digest != sb.transcript_digest or
                sent != 2*queries+5):
            raise IntegratedCascadeError('S3.C endpoint transcript disagrees')
        # Suppress corrected key. No claim of independently deployed Bob logic.
        del corrected
        return {
            'stage': 'S5D4_S3C_CASCADE_RESEARCH',
            'decision': 'AUTHENTICATED_LOCAL_RECONCILIATION_PASS_UNQUALIFIED',
            'profile_sha256': profile.public_fingerprint(),
            'transcript_sha256': sa.transcript_digest,
            'authenticated_outer_frames': sent,
            'max_outer_frames': 2*profile.max_parity_pairs+5,
            'parity_pairs': queries,
            'public_parity_disclosure_bits': 2*queries,
            'public_parity_disclosure_ceiling_bits': 2*profile.max_parity_pairs,
            'confirmation_tag_bits': profile.confirmation_tag_bits,
            'numerical_candidate_key_bits': bound['candidate_key_bits'],
            'requested_key_bits': profile.requested_key_bits,
            'independent_s3c_endpoint_states': True,
            'independent_distributed_role_execution': False,
            's3d_single_use_root_provisioning_integrated': False,
            'bob_parity_independently_computed_in_s3c_adapter': False,
            'confirmation_authenticated_in_s3c': False,
            'complete_adaptive_leakage_reduction_proven': False,
            'authentication_advantage_proven': False,
            'theorem_applicability_proven': False,
            'conditional_security_supported': False,
            'security_model_validated': False,
            'security_qualified': False,
            'qkd_psk_available': False,
            'hpke_export_authorized': False,
        }
    except Exception:
        a.abort()
        b.abort()
        raise
