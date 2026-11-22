"""S2.B2 strict quota-stopping wrapper around the experimental BB84 pipeline.

This checks observable record-prefix conformance, NOT a quantum security proof.
No recorded assertion or externally supplied property authorizes secret-key export.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, asdict
from typing import Sequence


class ReferenceProtocolError(ValueError):
    """Input or visible reference-protocol condition was violated."""


@dataclass(frozen=True)
class PrefixAssessment:
    decision: str
    records_received: int
    predeclared_transmission_cap: int
    n_key: int
    k_test_quota: int
    matched_x: int
    matched_z: int
    first_quota_hit_index: int | None
    z_overshoot: int
    x_overshoot: int
    full_z_population_required: bool = True
    x_random_subset_required: bool = True
    acquisition_precommitment_verified: bool = False
    basis_randomness_independence_verified: bool = False
    quantum_sampling_theorem_verified: bool = False
    security_model_validated: bool = False
    hpke_export_authorized: bool = False


def assess_prefix(alice: Sequence, bob: Sequence, *, n_key: int,
                  k_test: int, max_transmissions: int) -> PrefixAssessment:
    """Check *observed* first quota-crossing without reading private bit values.

    This intentionally does not infer that the acquisition schedule was actually
    precommitted or that an adversarial quantum source obeyed the theorem.
    """
    if any(type(x) is not int for x in (n_key, k_test, max_transmissions)):
        raise ReferenceProtocolError('quotas and cap must be integers')
    if n_key < 1 or k_test < 1 or max_transmissions < n_key + k_test or max_transmissions > 100000:
        raise ReferenceProtocolError('invalid quotas or resource cap')
    if not isinstance(alice, (list, tuple)) or not isinstance(bob, (list, tuple)):
        raise ReferenceProtocolError('records must be ordered finite sequences')
    if len(alice) != len(bob) or len(alice) > max_transmissions:
        raise ReferenceProtocolError('length mismatch or cap exceeded')
    nx = nz = 0
    first_hit = None
    for i, (a, b) in enumerate(zip(alice, bob)):
        # Avoid checking raw bits (which are private). M2.A validates them.
        if any(type(r.basis) is not int or r.basis not in (0, 1) for r in (a,b)):
            raise ReferenceProtocolError('invalid basis record')
        if a.basis == b.basis == 1:
            nx += 1
        if a.basis == b.basis == 0:
            nz += 1
        if first_hit is None and nx >= n_key and nz >= k_test:
            first_hit = i
    if first_hit is None:
        decision = 'ABORT_QUOTAS_NOT_MET'
    elif first_hit + 1 != len(alice):
        # The record sequence includes material acquired after quota success.
        # No security proof about adaptive filtering/late termination is inferred.
        decision = 'REJECT_POST_STOP_RECORDS'
    else:
        decision = 'PREFIX_CONFORMS_UNQUALIFIED'
    return PrefixAssessment(
        decision=decision, records_received=len(alice),
        predeclared_transmission_cap=max_transmissions,
        n_key=n_key, k_test_quota=k_test,
        matched_x=nx, matched_z=nz,
        first_quota_hit_index=first_hit,
        z_overshoot=max(0,nz-k_test), x_overshoot=max(0,nx-n_key))


def run_strict_reference(alice: Sequence, bob: Sequence, *, n_key: int,
                         k_test: int, max_transmissions: int,
                         q_tolerance: float = .05,
                         requested_key_bits: int = 32,
                         epsilon_pa: float = 1e-6,
                         confirmation_tag_bits: int = 40) -> dict:
    """Execute existing M2.A only on a first-hitting prefix, never qualify keys.

    No deterministic selection fixtures or hypothetical entropy input accepted.
    An external precommitment to the cap/basis randomness is *not* established.
    """
    a = assess_prefix(alice,bob,n_key=n_key,k_test=k_test,
                      max_transmissions=max_transmissions)
    out = {'stage': 'S2B2_STRICT_THEOREM_REFERENCE',
           'prefix': asdict(a),
           'acquisition_precommitment_verified': False,
           'quantum_sampling_theorem_verified': False,
           'pre_leak_min_entropy_certified': False,
           'authentication_provisioning_validated': False,
           'qkd_psk_available': False, 'security_model_validated': False,
           'security_qualified': False, 'hpke_export_authorized': False}
    if a.decision != 'PREFIX_CONFORMS_UNQUALIFIED':
        out['decision'] = a.decision
        return out
    if n_key < 128:
        out['decision'] = 'ABORT_UNSUPPORTED_RECONCILIATION_SIZE'
        return out
    from m2a_authenticated_distillation import run_distillation
    # M2.A selects n out of matched X using the OS RNG; all matched Z are
    # disclosed as test bits. No caller-supplied deterministic fixture seed.
    result = run_distillation(
        alice,bob,n_key=n_key,k_test=k_test,
        max_transmissions=max_transmissions,
        q_tolerance=q_tolerance,
        requested_key_bits=requested_key_bits,
        epsilon_pa=epsilon_pa,
        confirmation_tag_bits=confirmation_tag_bits,
        selection_seed=None, selection_streams=None,
        demo_pre_leak_min_entropy_bits=None)
    h2 = result.get('authenticated_parameter_estimation', {})
    if h2.get('decision') == 'PARAMETER_ESTIMATION_PASS_UNQUALIFIED':
        if (h2.get('transmissions') != len(alice) or
            h2.get('x_key_bits') != n_key or
            h2.get('z_test_bits') != a.matched_z or
            h2.get('eligible_z_count') != a.matched_z or
            h2.get('all_eligible_z_disclosed') is not True or
            h2.get('public_x_key_bits_disclosed') != 0 or
            h2.get('theorem_specific_protocol_validated') is not False):
            raise ReferenceProtocolError('authenticated parameter-estimation evidence inconsistent')
    if result.get('hpke_export_authorized') is not False or result.get('qkd_psk_available') is not False:
        raise ReferenceProtocolError('downstream attempted unauthorized key promotion')
    fk = result.get('finite_key', {})
    if fk.get('decision') == 'CONDITIONAL_PASS':
        raise ReferenceProtocolError('unqualified entropy unexpectedly accepted')
    out['decision'] = 'PIPELINE_UNQUALIFIED_' + str(result.get('decision','UNKNOWN'))
    out['pipeline'] = result
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-check', action='store_true', required=True)
    args = parser.parse_args()
    if args.self_check:
        # Import-free negative test; the installer runs the complete regressions.
        from types import SimpleNamespace
        a = [SimpleNamespace(basis=1)] * 128 + [SimpleNamespace(basis=0)] * 40
        same = assess_prefix(a,a,n_key=128,k_test=40,max_transmissions=200)
        late = assess_prefix(a+[SimpleNamespace(basis=0)],a+[SimpleNamespace(basis=0)],
                             n_key=128,k_test=40,max_transmissions=200)
        assert same.decision == 'PREFIX_CONFORMS_UNQUALIFIED'
        assert late.decision == 'REJECT_POST_STOP_RECORDS'
        print(json.dumps(asdict(same),sort_keys=True,indent=2))
        print('QKD_S2B2_STRICT_PREFIX_STATUS=PASS')
        print('QKD_S2B2_QUANTUM_SAMPLING_THEOREM_VERIFIED=false')
        print('QKD_S2B2_HPKE_EXPORT_AUTHORIZED=false')

if __name__ == '__main__':
    main()
