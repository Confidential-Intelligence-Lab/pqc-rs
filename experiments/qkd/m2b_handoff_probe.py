"""Public-only evidence handoff from M2.A to a Rust denial gate.

Never sends key material. This is a cross-language *policy test*, not a PSK exporter.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
from m2a_authenticated_distillation import run_distillation

@dataclass(frozen=True)
class Record:
    bit: int
    basis: int


def evidence() -> dict:
    a = [Record(i % 2, 1) for i in range(128)] + [Record(i % 2, 0) for i in range(40)]
    b = list(a)
    r = run_distillation(a, b, n_key=128, k_test=40,
                         max_transmissions=512, selection_seed=20261121)
    if r['reconciliation']['status'] != 'PASS':
        raise RuntimeError('unexpected M2.A reconciliation failure')
    if r['decision'] != 'REJECT_NO_VERIFIED_ENTROPY':
        raise RuntimeError('M2.A did not reject unverified entropy')
    if r['privacy_amplification']['status'] != 'NOT_RUN':
        raise RuntimeError('privacy amplification unexpectedly ran')
    if r['qkd_psk_available'] or r['hpke_export_authorized']:
        raise RuntimeError('M2.A unexpectedly authorized QKD PSK')
    return r


def public_wire(r: dict) -> str:
    """Strict public facts, no simulated raw bits or secret keys."""
    fields = (
        'M2A_EVIDENCE_V1',
        r['provenance'],
        str(r['security_model_validated']).lower(),
        str(r['security_qualified']).lower(),
        str(r['quantum_min_entropy_proven']).lower(),
        str(r['qkd_psk_available']).lower(),
        str(r['hpke_export_authorized']).lower(),
        r['decision'],
    )
    assert all('\t' not in str(v) and '\n' not in str(v) for v in fields)
    return '\t'.join(fields)


if __name__ == '__main__':
    print(public_wire(evidence()))
    print('QKD_M2B_PYTHON_EVIDENCE_GATE=PASS', file=__import__('sys').stderr)
