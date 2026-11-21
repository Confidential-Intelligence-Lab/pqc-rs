"""M1.F reproducible *simulation-only* BB84 distillation experiment.

No certified min-entropy or authenticated BB84 sifting is established.
No distilled key bytes are persisted, logged, or exported to HPKE.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import random
import secrets
import time

from bb84_cudaq import run as bb84_run
from m1e1_reconciliation import ReconciliationError, reconcile_single_error_blocks
from m1e2_privacy_amplification import random_toeplitz_seed, toeplitz_hash
from m1e3_finite_key import FiniteKeyInput, evaluate


def _pack(bits: str) -> bytes:
    return (int(bits, 2) << ((-len(bits)) % 8)).to_bytes((len(bits) + 7) // 8, 'big')


@dataclass(frozen=True)
class DistillationConfig:
    transmissions: int = 2048
    seed: int = 20261120
    intercept_percent: int = 0
    test_fraction: float = 0.25
    block_size: int = 32
    requested_key_bits: int = 128
    epsilon_pa: float = 1e-6
    # Hypothetical evidence exclusively for simulation demonstrations.
    demo_pre_leak_min_entropy_bits: float | None = None


def execute(config: DistillationConfig, *, bb84_fn=bb84_run) -> dict:
    if not isinstance(config.transmissions, int) or isinstance(config.transmissions, bool) or config.transmissions < 512:
        raise ValueError('transmissions must be an integer >= 512')
    if not isinstance(config.seed, int) or isinstance(config.seed, bool) or config.seed < 0:
        raise ValueError('seed must be a nonnegative integer')
    if not isinstance(config.intercept_percent, int) or isinstance(config.intercept_percent, bool) or not 0 <= config.intercept_percent <= 100:
        raise ValueError('intercept_percent must be in [0,100]')
    if not isinstance(config.test_fraction, (float, int)) or isinstance(config.test_fraction, bool) or not 0 < config.test_fraction < 1:
        raise ValueError('test_fraction must be in (0,1)')
    if not isinstance(config.block_size, int) or isinstance(config.block_size, bool) or config.block_size < 2:
        raise ValueError('block_size must be >= 2')

    start = time.perf_counter()
    alice, bob, errors = bb84_fn(config.transmissions, config.seed, config.intercept_percent)
    quantum_ms = 1000 * (time.perf_counter() - start)
    if len(alice) != len(bob) or len(alice) < 4 or any(x not in (0, 1) for x in alice + bob):
        raise ValueError('invalid sifted BB84 simulator output')
    sifted = len(alice)
    test_size = max(1, min(sifted - 1, int(sifted * config.test_fraction)))
    # Reproducible sample selection is not a QKD-security-approved randomness source.
    sample_rng = random.Random(config.seed ^ 0x514B445F4D3146)
    sample = set(sample_rng.sample(range(sifted), test_size))
    test_errors = sum(alice[i] != bob[i] for i in sample)
    alice_key = ''.join(str(bit) for i, bit in enumerate(alice) if i not in sample)
    bob_key = ''.join(str(bit) for i, bit in enumerate(bob) if i not in sample)
    retained = len(alice_key)

    start = time.perf_counter()
    report = None
    reconciliation_error = None
    try:
        # Ephemeral simulation MAC key. Real authenticated sifting and key
        # provisioning are NOT implemented here.
        bob_reconciled, report = reconcile_single_error_blocks(
            alice_key, bob_key, secrets.token_bytes(32), config.block_size)
    except ReconciliationError as exc:
        reconciliation_error = str(exc)
        bob_reconciled = None
    reconciliation_ms = 1000 * (time.perf_counter() - start)
    leak_ec = report.parity_bits_revealed if report else 0
    leak_confirm = report.confirmation_bits_revealed if report else 0

    # The existing finite-key estimator is only a conditional arithmetic
    # checker; do not assert that BB84 sifting and parameter-estimation
    # announcements were authenticated. Even a hypothetical entropy input
    # therefore cannot imply genuine QKD acceptance.
    demo = config.demo_pre_leak_min_entropy_bits is not None
    estimate = evaluate(FiniteKeyInput(
        sifted_bits=sifted,
        test_bits=test_size,
        test_errors=test_errors,
        reconciled_bits=retained,
        reconciliation_leak_bits=leak_ec,
        confirmation_leak_bits=leak_confirm,
        requested_key_bits=config.requested_key_bits,
        epsilon_pa=config.epsilon_pa,
        pre_leak_min_entropy_bits=config.demo_pre_leak_min_entropy_bits,
        entropy_evidence_id='HYPOTHETICAL_DEMO_NOT_SECURITY_EVIDENCE' if demo else None,
        authenticated_transcript=demo and report is not None,  # hypothetical assumption ONLY
        uniform_independent_toeplitz_seed=demo,
        reconciliation_confirmed=report is not None,
    ))

    start = time.perf_counter()
    amplification_agreement = None
    if demo and estimate.decision == 'CONDITIONAL_PASS' and report is not None:
        # An isolated illustration of the computational extraction stage;
        # output never leaves this function. This is not a secure key.
        seed = random_toeplitz_seed(retained, config.requested_key_bits)
        pa_alice = toeplitz_hash(_pack(alice_key), retained, config.requested_key_bits, seed)
        pa_bob = toeplitz_hash(_pack(bob_reconciled), retained, config.requested_key_bits, seed)
        amplification_agreement = pa_alice.key == pa_bob.key
        del pa_alice, pa_bob, seed
    amplification_ms = 1000 * (time.perf_counter() - start)

    result = {
        'provenance': 'CUDA_Q_SIMULATION_NOT_SECURE_QKD',
        'transmissions': config.transmissions,
        'sifted_bits': sifted,
        'sifted_errors': errors,
        'sifted_qber': errors / sifted,
        'test_bits': test_size,
        'test_errors': test_errors,
        'test_qber': test_errors / test_size,
        'retained_bits': retained,
        'reconciliation': {
            'status': 'PASS' if report else 'REJECT',
            'failure_reason': reconciliation_error,
            'corrected_bits': report.corrected_bits if report else None,
            'parity_leak_bits': leak_ec if report else None,
            'confirmation_leak_bits': leak_confirm if report else None,
            'total_leak_bits': report.total_leakage_upper_bound_bits if report else None,
        },
        'finite_key': asdict(estimate),
        'entropy_evidence': 'HYPOTHETICAL_ONLY' if demo else 'MISSING',
        'privacy_amplification': {
            'status': ('DEMO_ONLY' if amplification_agreement else
                       'REJECT' if amplification_agreement is False else 'NOT_RUN'),
            'alice_bob_agree': amplification_agreement,
            'key_bytes_exported': False,
        },
        'timing_ms': {
            'bb84': round(quantum_ms, 3),
            'reconciliation': round(reconciliation_ms, 3),
            'amplification': round(amplification_ms, 3),
        },
        'basis_and_parameter_estimation_authenticated': False,
        'security_model_validated': False,
        'security_qualified': False,
        'hpke_export_authorized': False,
    }
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bits', type=int, default=2048)
    ap.add_argument('--seed', type=int, default=20261120)
    ap.add_argument('--intercept-percent', type=int, default=0)
    ap.add_argument('--test-fraction', type=float, default=0.25)
    ap.add_argument('--block-size', type=int, default=32)
    ap.add_argument('--requested-key-bits', type=int, default=128)
    ap.add_argument('--epsilon-pa', type=float, default=1e-6)
    ap.add_argument('--demo-pre-leak-min-entropy-bits', type=float, help='HYPOTHETICAL ONLY; never qualifies security')
    args = ap.parse_args()
    result = execute(DistillationConfig(
        transmissions=args.bits, seed=args.seed,
        intercept_percent=args.intercept_percent,
        test_fraction=args.test_fraction, block_size=args.block_size,
        requested_key_bits=args.requested_key_bits, epsilon_pa=args.epsilon_pa,
        demo_pre_leak_min_entropy_bits=args.demo_pre_leak_min_entropy_bits,
    ))
    print(json.dumps(result, indent=2, sort_keys=True))
    print('QKD_M1F_LIFECYCLE_STATUS=PASS')
    print('QKD_M1F_SECURITY_MODEL_VALIDATED=false')
    print('QKD_M1F_SECURITY_QUALIFIED=false')


if __name__ == '__main__':
    main()
