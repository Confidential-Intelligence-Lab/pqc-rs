"""S5.D-3: bounded authenticated *local* Cascade integration experiment.

A precommitted conservative disclosure ceiling is checked BEFORE each parity
query. An independent relay MAC binds the source experiment's public frames to
session/profile/counter and records an immutable transcript digest. This is
NOT the existing S3.C schedule, NOT a distributed two-peer implementation,
and NOT an authentication security reduction or quantum entropy theorem.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json

from m1g3_tomamichel_bound import BoundInput, evaluate
from s5d2_cascade_reconciliation import CascadeError, reconcile_cascade

DOMAIN = b'pqc-rs/qkd/s5d3/relay/v1\x00'
DEFAULT_MAX_PAIRS = 4800


class BoundedCascadeError(ValueError):
    pass


@dataclass(frozen=True)
class BoundedProfile:
    n_key: int = 16384
    k_test: int = 16384
    max_transmissions: int = 100000
    q_tolerance_ppm: int = 20000
    requested_key_bits: int = 256
    epsilon_secrecy: float = 1e-10
    epsilon_correctness: float = 1e-10
    confirmation_tag_bits: int = 64
    max_parity_pairs: int = DEFAULT_MAX_PAIRS

    def __post_init__(self):
        if (type(self.n_key) is not int or self.n_key != 16384 or
                type(self.k_test) is not int or self.k_test != 16384 or
                self.max_transmissions != 100000 or
                self.q_tolerance_ppm != 20000 or
                self.requested_key_bits != 256 or
                self.confirmation_tag_bits != 64 or
                self.epsilon_secrecy != 1e-10 or
                self.epsilon_correctness != 1e-10 or
                type(self.max_parity_pairs) is not int or
                not 1 <= self.max_parity_pairs <= DEFAULT_MAX_PAIRS):
            raise BoundedCascadeError('unsupported or nonfrozen S5.D-3 research profile')

    def public_fingerprint(self) -> str:
        return hashlib.sha256(DOMAIN + json.dumps(asdict(self), sort_keys=True,
            separators=(',', ':'), allow_nan=False).encode()).hexdigest()

    def candidate(self) -> dict:
        worst = 2 * self.max_parity_pairs
        result = evaluate(BoundInput(self.n_key, self.k_test,
            self.q_tolerance_ppm / 1000000, worst,
            self.epsilon_secrecy, self.epsilon_correctness))
        return {
            'worst_case_parity_disclosure_bits': worst,
            'confirmation_tag_bits_accounted_by_separate_correctness_term': self.confirmation_tag_bits,
            'candidate_key_bits': result['maximum_numerical_key_bits'],
            'requested_key_bits': self.requested_key_bits,
            'numerical_fits': result['maximum_numerical_key_bits'] >= self.requested_key_bits,
            'theorem_applicability_proven': False,
            'conditional_security_supported': False,
        }


class _AuthenticatedLocalRelay:
    """Both sides are simulated in one process; this is NOT distributed S3.C."""
    def __init__(self, session_id: bytes, root: bytes, profile: BoundedProfile):
        if (type(session_id) is not bytes or not 16 <= len(session_id) <= 64 or
                type(root) is not bytes or len(root) < 32):
            raise BoundedCascadeError('invalid external authentication inputs')
        self.context = DOMAIN + session_id + bytes.fromhex(profile.public_fingerprint())
        self.key = hmac.digest(root, DOMAIN + b'key\x00' + self.context, 'sha256')
        self.seq = 0
        self.limit = profile.max_parity_pairs
        self.digest = hashlib.sha256(DOMAIN + b'initial\x00' + self.context).digest()

    def hook(self, seq: int, body: bytes, inner_tag: bytes):
        if seq != self.seq or seq >= self.limit:
            raise BoundedCascadeError('abort: precommitted parity exchange limit reached')
        if type(body) is not bytes or type(inner_tag) is not bytes or len(inner_tag) != 32:
            raise BoundedCascadeError('malformed source frame')
        frame = (self.context + self.seq.to_bytes(8, 'big') + self.digest +
                 len(body).to_bytes(4, 'big') + body + inner_tag)
        tag = hmac.digest(self.key, frame, 'sha256')
        # Simulated receive; the first HMAC is separately checked inside S5.D-2.
        if not hmac.compare_digest(tag, hmac.digest(self.key, frame, 'sha256')):
            raise BoundedCascadeError('relay MAC failed')
        self.digest = hashlib.sha256(self.digest + frame + tag).digest()
        self.seq += 1
        return body, inner_tag


def run_local_bounded_reconciliation(alice_bits: str, bob_bits: str, *,
                                     session_id: bytes, authentication_key: bytes,
                                     profile: BoundedProfile = BoundedProfile(),
                                     permutation_seed: bytes | None = None) -> dict:
    """Public metrics ONLY. In-process corrected key is deliberately discarded."""
    if type(profile) is not BoundedProfile:
        raise BoundedCascadeError('explicit S5.D-3 profile required')
    if type(alice_bits) is not str or type(bob_bits) is not str or len(alice_bits) != profile.n_key or len(bob_bits) != profile.n_key:
        raise BoundedCascadeError('raw length mismatch with frozen profile')
    candidate = profile.candidate()
    if not candidate['numerical_fits']:
        raise BoundedCascadeError('precommitted leakage budget invalidates numerical candidate')
    relay = _AuthenticatedLocalRelay(session_id, authentication_key, profile)
    try:
        _corrected, report = reconcile_cascade(
            alice_bits, bob_bits, session_id=session_id,
            authentication_key=authentication_key, tag_bits=profile.confirmation_tag_bits,
            max_parity_pairs=profile.max_parity_pairs,
            permutation_seed=permutation_seed,
            wire_hook=relay.hook)
    except (CascadeError, BoundedCascadeError):
        # No key escapes; report errors through exception as in S5.D-2.
        raise
    if relay.seq != report.public_parity_pairs or report.parity_disclosure_upper_bits > candidate['worst_case_parity_disclosure_bits']:
        raise BoundedCascadeError('authenticated transcript and disclosure disagreement')
    return {
        'stage': 'S5D3_BOUNDED_CASCADE_LOCAL_RESEARCH',
        'decision': 'LOCAL_RECONCILIATION_PASS_UNQUALIFIED',
        'public_profile_sha256': profile.public_fingerprint(),
        'public_transcript_sha256': relay.digest.hex(),
        'parity_pairs': report.public_parity_pairs,
        'relay_authenticated_parity_frames': relay.seq,
        'confirmation_frames_legacy_local': 1,
        'total_authentication_operations_not_reduced': report.authenticated_frames + relay.seq,
        'observed_parity_disclosure_bits': report.parity_disclosure_upper_bits,
        'worst_case_parity_disclosure_bits': candidate['worst_case_parity_disclosure_bits'],
        'requested_key_bits': profile.requested_key_bits,
        'worst_case_numerical_candidate_key_bits': candidate['candidate_key_bits'],
        'source_and_receiver_independently_deployed': False,
        's3c_transcript_schedule_integrated': False,
        'computational_authentication_advantage_proven': False,
        'variable_length_interactive_leakage_proven': False,
        'theorem_applicability_proven': False,
        'conditional_security_supported': False,
        'security_model_validated': False,
        'security_qualified': False,
        'qkd_psk_available': False,
        'hpke_export_authorized': False,
    }
