"""Fail-closed, conditional finite-key length accounting for experimental BB84.

An externally justified lower bound on quantum conditional min-entropy is
REQUIRED. Observed QBER is diagnostic; it is never converted into entropy by
this module. No security qualification or key export is implemented.
"""
from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class FiniteKeyInput:
    sifted_bits: int
    test_bits: int
    test_errors: int
    reconciled_bits: int
    reconciliation_leak_bits: int
    confirmation_leak_bits: int
    requested_key_bits: int
    epsilon_pa: float
    # Must be a rigorously justified lower bound on H_min(X | E) for the
    # retained reconciled_bits *before* public reconciliation/confirmation.
    pre_leak_min_entropy_bits: float | None = None
    entropy_evidence_id: str | None = None
    authenticated_transcript: bool = False
    uniform_independent_toeplitz_seed: bool = False
    reconciliation_confirmed: bool = False


@dataclass(frozen=True)
class FiniteKeyDecision:
    decision: str
    reason: str
    observed_test_qber: float
    maximum_conditional_key_bits: int
    entropy_after_leak_bits: float | None
    leakage_bits: int
    epsilon_pa: float
    security_qualified: bool = False
    hpke_export_authorized: bool = False


class FiniteKeyError(ValueError):
    pass


def _nonnegative_int(name: str, value: int, *, positive: bool = False) -> None:
    if type(value) is not int or value < (1 if positive else 0):
        raise FiniteKeyError(f"{name} must be {'positive' if positive else 'nonnegative'} integer")


def evaluate(p: FiniteKeyInput) -> FiniteKeyDecision:
    for name in ('sifted_bits', 'test_bits', 'test_errors', 'reconciled_bits',
                 'reconciliation_leak_bits', 'confirmation_leak_bits',
                 'requested_key_bits'):
        _nonnegative_int(name, getattr(p, name), positive=name in
                         ('sifted_bits', 'test_bits', 'reconciled_bits', 'requested_key_bits'))
    if p.test_bits > p.sifted_bits or p.test_errors > p.test_bits:
        raise FiniteKeyError('invalid sample sizes/error count')
    if p.reconciled_bits > p.sifted_bits - p.test_bits:
        raise FiniteKeyError('retained bits exceed untested sifted bits')
    if not isinstance(p.epsilon_pa, (float, int)) or isinstance(p.epsilon_pa, bool) or not math.isfinite(p.epsilon_pa) or not 0 < p.epsilon_pa < 0.5:
        raise FiniteKeyError('epsilon_pa must be finite and in (0, 0.5)')
    if p.pre_leak_min_entropy_bits is not None:
        h = p.pre_leak_min_entropy_bits
        if not isinstance(h, (float, int)) or isinstance(h, bool) or not math.isfinite(h) or not 0 <= h <= p.reconciled_bits:
            raise FiniteKeyError('pre-leak min-entropy must be finite and within retained bit count')
    if p.entropy_evidence_id is not None and (not isinstance(p.entropy_evidence_id, str) or not p.entropy_evidence_id.strip()):
        raise FiniteKeyError('entropy_evidence_id must be nonempty when supplied')
    for name in ('authenticated_transcript', 'uniform_independent_toeplitz_seed', 'reconciliation_confirmed'):
        if type(getattr(p, name)) is not bool:
            raise FiniteKeyError(f'{name} must be boolean')
    qber = p.test_errors / p.test_bits
    leakage = p.reconciliation_leak_bits + p.confirmation_leak_bits

    def reject(reason: str, remaining: float | None = None, maximum: int = 0) -> FiniteKeyDecision:
        return FiniteKeyDecision('REJECT', reason, qber, maximum, remaining, leakage, float(p.epsilon_pa))

    if p.pre_leak_min_entropy_bits is None or p.entropy_evidence_id is None:
        return reject('NO_EXTERNALLY_JUSTIFIED_MIN_ENTROPY_BOUND')
    if not p.authenticated_transcript:
        return reject('CLASSICAL_TRANSCRIPT_NOT_AUTHENTICATED')
    if not p.reconciliation_confirmed:
        return reject('RECONCILIATION_NOT_CONFIRMED')
    if not p.uniform_independent_toeplitz_seed:
        return reject('TOEPLITZ_SEED_ASSUMPTIONS_NOT_MET')

    # Quantum leftover-hash lemma, *conditional* on certified H_min(X|E).
    # Delta <= 1/2 sqrt(2^(ell - H_min)); require Delta <= epsilon_pa.
    # The entropy input must already account for the eavesdropper's quantum
    # side information and any parameter-estimation security failure.
    remaining = max(0.0, float(p.pre_leak_min_entropy_bits) - leakage)
    penalty = 2.0 * math.log2(1.0 / (2.0 * float(p.epsilon_pa)))
    # Conservative floating-point rounding against accepting boundary cases.
    maximum = max(0, min(p.reconciled_bits, math.floor(math.nextafter(remaining - penalty, -math.inf))))
    if p.requested_key_bits > maximum:
        return reject('REQUEST_EXCEEDS_CONDITIONAL_ENTROPY_BUDGET', remaining, maximum)
    return FiniteKeyDecision('CONDITIONAL_PASS',
                             'LENGTH_ONLY_REQUIRES_EXTERNAL_SECURITY_PROOF',
                             qber, maximum, remaining, leakage, float(p.epsilon_pa))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', required=True, help='path to JSON FiniteKeyInput; never contains key material')
    args = ap.parse_args()
    with open(args.input, encoding='utf-8') as f:
        raw = json.load(f)
    result = evaluate(FiniteKeyInput(**raw))
    print(json.dumps(asdict(result), sort_keys=True, indent=2))
    print('QKD_M1E3_SECURITY_QUALIFIED=false')
    if result.decision == 'REJECT':
        raise SystemExit(2)


if __name__ == '__main__':
    main()
