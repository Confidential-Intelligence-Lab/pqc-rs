"""S4.E experimental authenticated pre-acquisition proof-profile contract.

This does not attest the source or validate any quantum security theorem.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Callable

from s3c_authenticated_transcript import TranscriptSession, TranscriptError, canonical
from s3b_persistent_strict_path import burn_session_id, _run_strict_after_burn, StrictSessionError
from s2b2_strict_theorem_reference import assess_prefix

DOMAIN = b'pqc-rs/qkd/s4e/proof-profile/v1\x00'


@dataclass(frozen=True)
class ProofProfile:
    """Immutable, explicit, public *claim* about a candidate BB84 model.

    z_probability_ppm is the intended Z-basis probability (not attested).
    q_tolerance_ppm is the maximum Z test QBER in parts per million.
    Security-budget fields remain planning inputs, not validated proofs.
    """
    theorem_id: str
    source_model_id: str
    measurement_model_id: str
    randomness_mode: str
    n_key: int
    k_test: int
    max_transmissions: int
    z_probability_ppm: int
    q_tolerance_ppm: int
    requested_key_bits: int
    confirmation_tag_bits: int
    epsilon_pa: str
    epsilon_secrecy: str
    epsilon_correctness: str
    block_size: int = 128
    authentication_model_id: str = 'hmac-sha256-computational-unqualified-v1'
    schedule_id: str = 'h2-ec-pa-v1'
    profile_version: int = 1

    def __post_init__(self):
        for k in ('theorem_id', 'source_model_id', 'measurement_model_id',
                  'authentication_model_id'):
            v = getattr(self, k)
            if type(v) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,127}', v):
                raise StrictSessionError('invalid proof-profile identifier: ' + k)
        if self.theorem_id != 'TLGR-2012-Phi' or self.source_model_id != 'pqc-rs/qkd/s4a/ideal-bb84/v0.1':
            raise StrictSessionError('unsupported theorem or source-model profile')
        if self.measurement_model_id != 'ideal-projective-lossless-v1':
            raise StrictSessionError('unsupported receiver model')
        if self.randomness_mode != 'os':
            raise StrictSessionError('precommitted acquisition forbids deterministic fixture mode')
        if self.authentication_model_id != 'hmac-sha256-computational-unqualified-v1':
            raise StrictSessionError('unsupported authentication model')
        if self.schedule_id != 'h2-ec-pa-v1' or type(self.profile_version) is not int or self.profile_version != 1:
            raise StrictSessionError('unsupported protocol schedule or profile version')
        for k in ('n_key', 'k_test', 'max_transmissions', 'z_probability_ppm',
                  'q_tolerance_ppm', 'requested_key_bits', 'confirmation_tag_bits', 'block_size'):
            if type(getattr(self, k)) is not int:
                raise StrictSessionError('noninteger proof-profile parameter: ' + k)
        if not (128 <= self.n_key <= 65536 and 1 <= self.k_test and
                self.n_key + self.k_test <= self.max_transmissions <= 100000 and
                (self.n_key + 127)//128 <= 512):
            raise StrictSessionError('invalid acquisition quotas or cap')
        if not (1 <= self.z_probability_ppm <= 999999 and
                0 <= self.q_tolerance_ppm <= 500000 and
                1 <= self.requested_key_bits <= self.n_key and
                1 <= self.confirmation_tag_bits <= 256 and self.block_size == 128):
            raise StrictSessionError('invalid selection, error or distillation parameters')
        import math
        for k in ('epsilon_pa', 'epsilon_secrecy', 'epsilon_correctness'):
            v = getattr(self, k)
            if type(v) is not str or not re.fullmatch(r'0\.[0-9]{1,24}', v):
                raise StrictSessionError('invalid canonical epsilon encoding: ' + k)
            f = float(v)
            if not math.isfinite(f) or not 0 < f < (0.5 if k == 'epsilon_pa' else 1.0):
                raise StrictSessionError('invalid epsilon range: ' + k)

    def encode(self) -> bytes:
        return canonical(asdict(self))

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(DOMAIN + self.encode()).hexdigest()


def run_precommitted_distillation(acquire_records: Callable[[ProofProfile], tuple], *,
                                 proof_profile: ProofProfile, authentication_key: bytes,
                                 bob_expected_profile: ProofProfile | None = None,
                                 key_id: str, session_id: bytes, registry_dir: str | Path) -> dict:
    """Authenticate proof profile before calling acquisition. Still UNQUALIFIED.

    The caller supplies the acquisition callback. This proves call ordering and
    transcript integrity in one process; it does not attest physical acquisition,
    external randomness, source model, or independently isolated peers.
    """
    if type(proof_profile) is not ProofProfile or not callable(acquire_records):
        raise StrictSessionError('explicit validated proof profile and acquisition callback required')
    if bob_expected_profile is not None and type(bob_expected_profile) is not ProofProfile:
        raise StrictSessionError('invalid Bob proof profile')
    if type(authentication_key) is not bytes or len(authentication_key) < 32:
        raise StrictSessionError('externally supplied authentication root required')
    # Intentional one-way burn BEFORE any frame exchange or source acquisition.
    burn_session_id(registry_dir, key_id, session_id)
    scoped_key = hmac.digest(authentication_key,
        b'pqc-rs/qkd/s3b/key-identity/v1\x00' + key_id.encode('ascii'), 'sha256')
    ctx = dict(root=scoped_key, key_id=key_id, session_id=session_id,
               alice_id='alice', bob_id='bob', schedule_id='s4e-proof-v1')
    alice = TranscriptSession(role='alice', **ctx)
    bob = TranscriptSession(role='bob', **ctx)
    try:
        proposal = proof_profile.encode()
        body, tag = alice.send('proof_profile', proposal)
        stage, payload = bob.receive(body, tag)
        if stage != 'proof_profile' or payload != proposal or (
                bob_expected_profile is not None and payload != bob_expected_profile.encode()):
            raise TranscriptError('proof profile substitution or peer policy mismatch')
        ack = canonical({'profile_sha256': proof_profile.fingerprint, 'accepted': True})
        body, tag = bob.send('proof_ack', ack)
        stage, payload = alice.receive(body, tag)
        if stage != 'proof_ack' or payload != ack:
            raise TranscriptError('proof profile acknowledgement mismatch')
        sa, sb = alice.status(), bob.status()
        if not sa.closed or not sb.closed or sa.aborted or sb.aborted or sa.transcript_digest != sb.transcript_digest:
            raise TranscriptError('pre-acquisition proof transcript mismatch')
        # Acquisition is not invoked until both endpoints finish authenticated
        # precommitment; its callback is trusted only as a simulated boundary.
        records = acquire_records(proof_profile)
        if type(records) is not tuple or len(records) != 2:
            raise StrictSessionError('acquisition must return (alice_records, bob_records)')
        a, b = records
        prefix = assess_prefix(a, b, n_key=proof_profile.n_key,
                               k_test=proof_profile.k_test,
                               max_transmissions=proof_profile.max_transmissions)
        if prefix.decision not in ('PREFIX_CONFORMS_UNQUALIFIED', 'ABORT_QUOTAS_NOT_MET'):
            raise StrictSessionError('acquisition violates precommitted stopping contract')
        result = _run_strict_after_burn(
            a, b, authentication_key=authentication_key, key_id=key_id,
            session_id=session_id, registry_dir=registry_dir,
            n_key=proof_profile.n_key, k_test=proof_profile.k_test,
            max_transmissions=proof_profile.max_transmissions,
            q_tolerance=proof_profile.q_tolerance_ppm / 1000000,
            epsilon_secrecy=float(proof_profile.epsilon_secrecy),
            epsilon_correctness=float(proof_profile.epsilon_correctness),
            requested_key_bits=proof_profile.requested_key_bits,
            block_size=proof_profile.block_size,
            confirmation_tag_bits=proof_profile.confirmation_tag_bits,
            epsilon_pa=float(proof_profile.epsilon_pa),
            precommit_digest=sa.transcript_digest)
        # If raw record acquisition is not independently attested, this stays
        # a functional precommitment test, not source-security evidence.
        result['s4e_preacquisition_profile_authenticated'] = True
        result['s4e_profile_sha256'] = proof_profile.fingerprint
        result['s4e_precommit_digest'] = sa.transcript_digest
        result['s4e_acquisition_order_checked'] = True
        result['s4e_source_attested'] = False
        result['security_model_validated'] = False
        result['security_qualified'] = False
        result['hpke_export_authorized'] = False
        result['qkd_psk_available'] = False
        return result
    except Exception:
        alice.abort()
        bob.abort()
        raise
