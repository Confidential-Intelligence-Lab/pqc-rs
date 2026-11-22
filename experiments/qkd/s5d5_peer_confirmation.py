"""S5.D-5 single-host research adapter: bounded authenticated peer confirmation.

Does not attest external provisioning or independently distributed decoding.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from s3b_persistent_strict_path import burn_session_id, StrictSessionError
from s3d_authentication_contract import AssumedProvisionedCredential, _root_marker_namespace
from s5d3_bounded_cascade import BoundedProfile
from s5d4_s3c_cascade import run_s3c_cascade


class S5D5Error(ValueError):
    pass


@dataclass(frozen=True)
class CascadeAuthenticationBudget:
    """Single-session message ceiling, NOT a cryptographic advantage bound."""
    max_pairs: int = 4800
    max_outer_frames: int = 9607
    max_root_sessions: int = 1

    def __post_init__(self):
        if (type(self.max_pairs) is not int or not 1 <= self.max_pairs <= 4800 or
                type(self.max_outer_frames) is not int or
                self.max_outer_frames != 2*self.max_pairs + 7 or
                type(self.max_root_sessions) is not int or self.max_root_sessions != 1):
            raise S5D5Error('invalid precommitted adaptive authentication budget')


def run_single_use_confirmed_cascade(alice_bits: str, bob_bits: str, *,
                                     credential: AssumedProvisionedCredential,
                                     session_id: bytes, registry_dir: str | Path,
                                     permutation_seed: bytes,
                                     profile: BoundedProfile = BoundedProfile(),
                                     budget: CascadeAuthenticationBudget = CascadeAuthenticationBudget(),
                                     wire_hook=None) -> dict:
    """Consume a locally registered root and run authenticated two-role simulation.

    Burn happens before parity disclosure. Returns PUBLIC metrics ONLY.
    The single-process Cascade oracle and root provisioning remain assumptions.
    """
    if type(credential) is not AssumedProvisionedCredential:
        raise S5D5Error('explicit externally supplied credential contract required')
    if type(profile) is not BoundedProfile or type(budget) is not CascadeAuthenticationBudget:
        raise S5D5Error('explicit bounded profile and authentication budget required')
    if profile.max_parity_pairs != budget.max_pairs:
        raise S5D5Error('disclosure and authentication limits disagree')
    if not isinstance(registry_dir, (str, Path)):
        raise S5D5Error('registry directory required')
    if type(session_id) is not bytes or not 16 <= len(session_id) <= 64:
        raise S5D5Error('session ID invalid')
    # Reserve the credential for exactly one invocation, even on subsequent abort.
    burn_session_id(registry_dir, _root_marker_namespace(credential.key_id),
                    b'pqc-rs/qkd/s5d5/single-use/v1')
    report = run_s3c_cascade(
        alice_bits, bob_bits, root=credential.root, session_id=session_id,
        key_id=credential.key_id, profile=profile, permutation_seed=permutation_seed,
        wire_hook=wire_hook, peer_confirmation=True)
    if (report['authenticated_outer_frames'] > budget.max_outer_frames or
            report['max_outer_frames'] != budget.max_outer_frames or
            report['confirmation_authenticated_in_s3c'] is not True):
        raise S5D5Error('authentication budget or confirmation invariant violated')
    report['stage'] = 'S5D5_SINGLE_USE_AUTHENTICATED_CASCADE_RESEARCH'
    report['s3d_single_use_root_provisioning_integrated'] = True
    report['external_root_provisioning_verified'] = False
    report['authentication_frame_budget_limit'] = budget.max_outer_frames
    report['authentication_advantage_proven'] = False
    report['conditional_security_supported'] = False
    report['security_model_validated'] = False
    report['security_qualified'] = False
    report['hpke_export_authorized'] = False
    report['qkd_psk_available'] = False
    return report
