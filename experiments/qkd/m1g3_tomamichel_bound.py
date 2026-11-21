"""Numerical evaluation of Tomamichel et al. (2012), Eq. (2).

This is NOT a validated BB84 protocol or a security-qualified key source.
The theorem applies only when its *entire protocol/device model* is satisfied.
Inputs are protocol parameters, not self-certifying measurement evidence.
"""
from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class BoundInput:
    n_key: int
    k_test: int
    q_tolerance: float
    leakage_ec_bits: int
    epsilon_secrecy: float
    epsilon_correctness: float
    preparation_quality: float = 1.0


class BoundError(ValueError):
    pass


def _h2(x: float) -> float:
    if x == 0 or x == 1:
        return 0.0
    return -x * math.log2(x) - (1 - x) * math.log2(1 - x)


def evaluate(p: BoundInput) -> dict:
    for name in ('n_key', 'k_test', 'leakage_ec_bits'):
        v = getattr(p, name)
        if type(v) is not int or v < (0 if name == 'leakage_ec_bits' else 1):
            raise BoundError(f'{name} must be an integer in the allowed range')
    for name in ('q_tolerance', 'epsilon_secrecy', 'epsilon_correctness', 'preparation_quality'):
        v = getattr(p, name)
        if type(v) not in (int, float) or not math.isfinite(v):
            raise BoundError(f'{name} must be finite')
    if not 0 <= p.q_tolerance <= 0.5:
        raise BoundError('q_tolerance must be in [0, 0.5]')
    if not 0 < p.epsilon_secrecy < 1 or not 0 < p.epsilon_correctness < 1:
        raise BoundError('epsilon parameters must be in (0,1)')
    if not 0 < p.preparation_quality <= 1:
        raise BoundError('preparation_quality must be in (0,1]')
    if p.leakage_ec_bits > p.n_key:
        raise BoundError('leakage_ec_bits must not exceed n_key')

    n, k = p.n_key, p.k_test
    # Tomamichel, Lim, Gisin, Renner, Nature Communications 3:634 (2012), Eq (2).
    mu = math.sqrt(((n + k) / (n * k)) * ((k + 1) / k) * math.log(2 / p.epsilon_secrecy))
    phase_bound = p.q_tolerance + mu
    penalty = math.log2(2 / (p.epsilon_secrecy**2 * p.epsilon_correctness))
    if phase_bound >= 0.5:
        raw = None
        maximum = 0
        reason = 'FINITE_SAMPLE_PHASE_BOUND_NOT_USEFUL'
    else:
        raw = n * (p.preparation_quality - _h2(phase_bound)) - p.leakage_ec_bits - penalty
        maximum = max(0, min(n, math.floor(math.nextafter(raw, -math.inf))))
        reason = 'POSITIVE_NUMERICAL_BOUND' if maximum > 0 else 'NONPOSITIVE_NUMERICAL_BOUND'
    return {
        'reference': 'Tomamichel-Lim-Gisin-Renner-2012-Eq2',
        'decision': 'NUMERICAL_CANDIDATE' if maximum > 0 else 'NO_KEY',
        'reason': reason,
        'n_key': n, 'k_test': k,
        'mu': mu, 'phase_error_upper': phase_bound,
        'raw_bound_bits': raw, 'maximum_numerical_key_bits': maximum,
        'protocol_assumptions_verified': False,
        'security_model_validated': False,
        'security_qualified': False,
        'hpke_export_authorized': False,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--n', type=int, required=True)
    ap.add_argument('--k', type=int, required=True)
    ap.add_argument('--q-tolerance', type=float, required=True)
    ap.add_argument('--leak-ec', type=int, required=True)
    ap.add_argument('--epsilon-sec', type=float, required=True)
    ap.add_argument('--epsilon-cor', type=float, required=True)
    ap.add_argument('--preparation-quality', type=float, default=1.0)
    args = ap.parse_args()
    try:
        result = evaluate(BoundInput(args.n, args.k, args.q_tolerance, args.leak_ec,
                                     args.epsilon_sec, args.epsilon_cor, args.preparation_quality))
    except BoundError as exc:
        ap.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    print('QKD_M1G3_EQUATION_STATUS=PASS')
    print('QKD_M1G3_SECURITY_MODEL_VALIDATED=false')


if __name__ == '__main__':
    main()
