"""S3.D optional single-use credential contract for the S4.F simulator.

Research ONLY: computational HMAC; caller-asserted external credential origin.
No theorem, MAC advantage, quantum entropy or production key is certified.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path

from s3b_persistent_strict_path import StrictSessionError, burn_session_id
from s4e_proof_precommit import ProofProfile
from s4f_source_conformance import run_profiled_simulation

AUTH_MODEL = 'hmac-sha256-computational-unqualified-v1'
PROVISIONING_MODEL = 'externally-provisioned-shared-secret-assumed-v1'
REGISTRY_MODEL = 'single-host-durable-no-rollback-assumed-v1'


@dataclass(frozen=True, repr=False)
class AssumedProvisionedCredential:
    """Local secret plus public metadata; *not* a proof of its origin.

    The same externally provisioned >=256-bit root is assumed to be present
    independently at Alice and Bob. Caller labels are not credential evidence.
    """
    root: bytes = field(repr=False)
    key_id: str
    origin_model: str = PROVISIONING_MODEL
    registry_model: str = REGISTRY_MODEL

    def __post_init__(self):
        if type(self.root) is not bytes or len(self.root) < 32:
            raise StrictSessionError('S3.D requires externally supplied >=32-byte root')
        if (type(self.key_id) is not str or not 1 <= len(self.key_id) <= 64
                or not self.key_id.isascii() or not all(
                    c.isalnum() or c in '._-' for c in self.key_id)):
            raise StrictSessionError('invalid S3.D credential key ID')
        if (self.origin_model != PROVISIONING_MODEL or
                self.registry_model != REGISTRY_MODEL):
            raise StrictSessionError('unsupported S3.D credential assumption')

    def __repr__(self):
        return 'AssumedProvisionedCredential(root=<redacted>, key_id=%r)' % self.key_id


@dataclass(frozen=True)
class AuthenticationBudget:
    """Local resource limit, NOT a proved epsilon_auth.

    max_outer_frames limits wire frames (one tag per transmitted frame).
    max_root_sessions is fixed to 1 because multi-session accounting and a
    multi-user cryptographic reduction have NOT been established.
    """
    max_outer_frames: int
    max_root_sessions: int = 1
    model_id: str = AUTH_MODEL

    def __post_init__(self):
        if (type(self.max_outer_frames) is not int or
                not 1 <= self.max_outer_frames <= 1024 or
                type(self.max_root_sessions) is not int or
                self.max_root_sessions != 1 or self.model_id != AUTH_MODEL):
            raise StrictSessionError('invalid S3.D authentication budget')


def planned_outer_frames(profile: ProofProfile) -> int:
    """Conservative normal-path outer frame count for S4.E + S3.C.

    2 proof frames, 9 H2, ceil(n_key/128) syndrome frames, 3 EC
    confirmation/ack/commit frames, 3 PA agreement frames.
    This does NOT count additional inner H2/EC MACs, and is NOT an advantage
    bound. Abort paths produce fewer outer frames by design.
    """
    if type(profile) is not ProofProfile:
        raise StrictSessionError('S3.D requires exact proof profile')
    return 2 + 9 + (profile.n_key + 127) // 128 + 3 + 3


def validate_auth_contract(profile: ProofProfile,
                           credential: AssumedProvisionedCredential,
                           budget: AuthenticationBudget) -> int:
    if (type(credential) is not AssumedProvisionedCredential or
            type(budget) is not AuthenticationBudget):
        raise StrictSessionError('explicit S3.D credential and budget required')
    if profile.authentication_model_id != budget.model_id:
        raise StrictSessionError('S3.D authentication model mismatch')
    expected = planned_outer_frames(profile)
    if expected > budget.max_outer_frames:
        raise StrictSessionError('S3.D outer-frame budget insufficient')
    return expected


def _root_marker_namespace(key_id: str) -> str:
    # Distinct marker namespace from user session IDs. Root is not hashed into
    # public markers. Key-ID uniqueness remains an external provisioning duty.
    return 's3d-' + hashlib.sha256(key_id.encode('ascii')).hexdigest()[:48]


def run_s3d_profiled_simulation(*, proof_profile: ProofProfile,
                                credential: AssumedProvisionedCredential,
                                budget: AuthenticationBudget,
                                session_id: bytes, registry_dir: str | Path,
                                bob_expected_profile: ProofProfile | None = None,
                                measure=None) -> dict:
    """One root-use lease, then normal S4.F authenticated simulated protocol.

    The lease is durable on a trusted single host; consumed even if the next
    step aborts. Do not claim distributed replay resistance or secure origin.
    """
    expected = validate_auth_contract(proof_profile, credential, budget)
    # Fail closed BEFORE all frame exchange/acquisition. The root's public
    # key_id can be used exactly once in this private local registry.
    burn_session_id(registry_dir, _root_marker_namespace(credential.key_id),
                    hashlib.sha256(b'pqc-rs/qkd/s3d/root-once/v1\x00').digest())
    result = run_profiled_simulation(
        proof_profile=proof_profile, authentication_key=credential.root,
        key_id=credential.key_id, session_id=session_id, registry_dir=registry_dir,
        bob_expected_profile=bob_expected_profile, measure=measure)
    if (result.get('security_model_validated') is not False or
            result.get('security_qualified') is not False or
            result.get('hpke_export_authorized') is not False or
            result.get('qkd_psk_available') is not False):
        raise StrictSessionError('S3.D downstream security invariant violation')
    result['s3d_authentication_model'] = AUTH_MODEL
    result['s3d_credential_origin_verified'] = False
    result['s3d_root_single_use_reserved'] = True
    result['s3d_outer_frames_budgeted_max'] = expected
    result['s3d_outer_frames_limit'] = budget.max_outer_frames
    result['s3d_cryptographic_authentication_bound_proven'] = False
    result['s3d_registry_scope'] = REGISTRY_MODEL
    return result
