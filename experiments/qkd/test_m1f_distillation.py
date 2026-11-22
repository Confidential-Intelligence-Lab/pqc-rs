"""M1.F lifecycle integration tests; use a deterministic simulator stub."""
import sys
import types
import unittest
from pathlib import Path

# CI tests without CUDA-Q installed; live CUDA-Q requires its dedicated venv.
try:
    import cudaq  # noqa: F401
except ImportError:
    fake = types.ModuleType('bb84_cudaq')
    fake.run = lambda *_: ([], [], 0)
    sys.modules.setdefault('bb84_cudaq', fake)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from m1f_distillation import DistillationConfig, execute


def ideal(bits, seed, attack):
    alice = [((i * 13 + i // 7) % 2) for i in range(512)]
    return alice, alice[:], 0


def error_one(bits, seed, attack):
    a, b, _ = ideal(bits, seed, attack)
    b[31] ^= 1
    return a, b, 1


def error_many(bits, seed, attack):
    a, b, _ = ideal(bits, seed, attack)
    for i in range(len(b)):
        b[i] ^= 1
    return a, b, len(a)


class LifecycleTests(unittest.TestCase):
    def test_default_fail_closed(self):
        r = execute(DistillationConfig(), bb84_fn=ideal)
        self.assertEqual(r['finite_key']['decision'], 'REJECT')
        self.assertEqual(r['finite_key']['reason'], 'NO_EXTERNALLY_JUSTIFIED_MIN_ENTROPY_BOUND')
        self.assertEqual(r['privacy_amplification']['status'], 'NOT_RUN')
        self.assertFalse(r['hpke_export_authorized'])
        self.assertFalse(r['security_model_validated'])

    def test_reproducible_observables(self):
        a = execute(DistillationConfig(), bb84_fn=ideal)
        b = execute(DistillationConfig(), bb84_fn=ideal)
        for f in ('sifted_bits', 'sifted_qber', 'test_bits', 'test_errors', 'retained_bits'):
            self.assertEqual(a[f], b[f])

    def test_hypothetical_budget_and_toeplitz_agreement(self):
        cfg = DistillationConfig(requested_key_bits=64, demo_pre_leak_min_entropy_bits=350)
        r = execute(cfg, bb84_fn=ideal)
        self.assertEqual(r['finite_key']['decision'], 'CONDITIONAL_PASS')
        self.assertEqual(r['privacy_amplification']['status'], 'DEMO_ONLY')
        self.assertTrue(r['privacy_amplification']['alice_bob_agree'])
        self.assertFalse(r['security_qualified'])
        self.assertFalse(r['hpke_export_authorized'])
        self.assertEqual(r['entropy_evidence'], 'HYPOTHETICAL_ONLY')

    def test_impossible_budget_rejects(self):
        cfg = DistillationConfig(requested_key_bits=256, demo_pre_leak_min_entropy_bits=50)
        r = execute(cfg, bb84_fn=ideal)
        self.assertEqual(r['finite_key']['decision'], 'REJECT')
        self.assertEqual(r['privacy_amplification']['status'], 'NOT_RUN')

    def test_error_handling_with_no_entropy(self):
        r = execute(DistillationConfig(), bb84_fn=error_one)
        self.assertEqual(r['finite_key']['decision'], 'REJECT')
        self.assertFalse(r['hpke_export_authorized'])

    def test_widespread_errors_reject_or_disagree(self):
        r = execute(DistillationConfig(), bb84_fn=error_many)
        self.assertEqual(r['finite_key']['decision'], 'REJECT')
        self.assertFalse(r['security_qualified'])

    def test_bad_configuration(self):
        for cfg in (DistillationConfig(transmissions=8), DistillationConfig(intercept_percent=101),
                    DistillationConfig(test_fraction=1), DistillationConfig(block_size=1)):
            with self.assertRaises(ValueError):
                execute(cfg, bb84_fn=ideal)

    def test_no_secret_in_output(self):
        result = execute(DistillationConfig(requested_key_bits=64, demo_pre_leak_min_entropy_bits=350), bb84_fn=ideal)
        self.assertNotIn('key', result)
        self.assertFalse(result['privacy_amplification']['key_bytes_exported'])


if __name__ == '__main__':
    unittest.main()
