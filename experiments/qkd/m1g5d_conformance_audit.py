"""Fail-closed source/evidence audit for experimental QKD model conformance.

This reports implementation signals, NOT cryptographic security proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

FILES = {
    'quota': 'm1g5a_quota_sifting.py',
    'authentication': 'm1g5b_authenticated_transcript.py',
    'measurement': 'm1g5c1_measurement_transcript.py',
    'estimation': 'm1g5c2_parameter_estimation.py',
    'reconciliation': 'm1e1_reconciliation.py',
    'amplification': 'm1e2_privacy_amplification.py',
    'budget': 'm1g3_tomamichel_bound.py',
    'lifecycle': 'm1f_distillation.py',
}

# Each signal is checked only for reporting; never enough to assert conformance.
SIGNALS = {
    'QUOTA_SIFTING': ('quota', ('max_transmissions', 'QUOTAS_MET')),
    'AUTHENTICATED_PUBLIC_CHANNEL_PRIMITIVE': ('authentication', ('PublicDiscussion', 'hmac')),
    'AUTHENTICATED_ACTUAL_BASIS_RECORDS': ('measurement', ('AliceRecord', 'BobRecord', 'authenticate_sifting')),
    'AUTHENTICATED_PARAMETER_ESTIMATION_COMPONENT': ('estimation', ('q_tolerance', 'sample', 'authentication')),
    'RECONCILIATION_COMPONENT': ('reconciliation', ('reconcile_single_error_blocks',)),
    'TOEPLITZ_COMPONENT': ('amplification', ('toeplitz_hash',)),
    'FINITE_KEY_NUMERICAL_COMPONENT': ('budget', ('BoundInput', 'evaluate')),
}

# These are NOT automatically satisfied by source-search heuristics.
REQUIREMENTS = [
    ('QKD-01', 'Protocol and device model maps exactly to cited theorem', 'NOT_VALIDATED', 'Requires formal source/measurement/detection assumptions and peer review'),
    ('QKD-02', 'Quota-based acquisition and abort', 'COMPONENT_TESTED', 'G5.A tests; theorem-level quota and selection review outstanding'),
    ('QKD-03', 'Actual basis announcements authenticated', 'COMPONENT_TESTED', 'G5.C1 tests; authentication provisioning still unvalidated'),
    ('QKD-04', 'Parameter-estimation messages authenticated', 'COMPONENT_TESTED', 'G5.C2 tests; quota-ordered sample rather than independently selected theorem sample'),
    ('QKD-05', 'Random subset selection matches theorem', 'BLOCKED', 'Current procedure uses quota order; authenticated transcript does not establish sample randomness'),
    ('QKD-06', 'Private independent source bits and bases', 'BLOCKED', 'Public deterministic PRNG seed in CUDA-Q experiment'),
    ('QKD-07', 'Authentication key provisioning and error budget', 'BLOCKED', 'Ephemeral MAC key demonstrated, independent provisioning not validated'),
    ('QKD-08', 'Correctness verification and leakage integrated end-to-end', 'BLOCKED', 'Reconciliation is tested separately; composable correctness/accounting unverified'),
    ('QKD-09', 'Universal hashing integrated after validated key-length acceptance', 'BLOCKED', 'Toeplitz tested separately; no qualified distillation-to-export path'),
    ('QKD-10', 'Finite-key theorem assumptions and epsilon composition', 'BLOCKED', 'Equation tested independently, but source evidence does not establish theorem premises'),
    ('QKD-11', 'Physical device implementation security', 'OUT_OF_SCOPE', 'Idealized simulator, not physical QKD'),
    ('QKD-12', 'QKD-to-HPKE security composition', 'BLOCKED', 'No qualified key export; hybrid security argument remains separate'),
]


def audit(directory: Path) -> dict:
    if not directory.is_dir():
        raise ValueError('QKD experiment directory missing')
    observed = {}
    for key, rel in FILES.items():
        path = directory / rel
        if not path.is_file():
            raise ValueError(f'required source missing: {rel}')
        observed[key] = path.read_text(encoding='utf-8')
    indicators = {}
    for signal, (file_key, fragments) in SIGNALS.items():
        indicators[signal] = {
            'source': FILES[file_key],
            'present': all(fragment in observed[file_key] for fragment in fragments),
            'meaning': 'source-presence indicator only; not a proof or test execution',
        }
    requirements = [dict(id=i, requirement=label, status=status, rationale=why)
                    for i, label, status, why in REQUIREMENTS]
    blockers = [r['id'] for r in requirements if r['status'] in ('BLOCKED', 'NOT_VALIDATED')]
    return {
        'reference': 'Tomamichel-Lim-Gisin-Renner-2012-Box1-Eq2',
        'reference_doi': '10.1038/ncomms1631',
        'commit_baseline_expected': '2250fba',
        'implementation_indicators': indicators,
        'requirements': requirements,
        'blocking_requirements': blockers,
        'validated_theorem_conformance': False,
        'security_model_validated': False,
        'security_qualified': False,
        'hpke_export_authorized': False,
        'decision': 'BLOCKED_SECURITY_MODEL_NOT_VALIDATED',
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--directory', type=Path, default=Path(__file__).resolve().parent)
    args = p.parse_args()
    report = audit(args.directory)
    print(json.dumps(report, indent=2, sort_keys=True))
    print('QKD_M1G5D_CONFORMANCE_AUDIT_STATUS=PASS')
    print('QKD_M1G5D_SECURITY_MODEL_VALIDATED=false')


if __name__ == '__main__':
    main()
