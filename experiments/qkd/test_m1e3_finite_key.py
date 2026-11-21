"""Independent arithmetic and fail-closed regression checks for M1.E3."""
import math
import unittest
from dataclasses import replace

from m1e3_finite_key import FiniteKeyError, FiniteKeyInput, evaluate


def sample(**changes):
    p = FiniteKeyInput(
        sifted_bits=12000, test_bits=2000, test_errors=20,
        reconciled_bits=10000, reconciliation_leak_bits=600,
        confirmation_leak_bits=64, requested_key_bits=256,
        epsilon_pa=1e-10, pre_leak_min_entropy_bits=8000,
        entropy_evidence_id='EXAMPLE-EXTERNAL-PROOF-NOT-ACTUAL',
        authenticated_transcript=True, reconciliation_confirmed=True,
        uniform_independent_toeplitz_seed=True)
    return replace(p, **changes)


class FiniteKeyTests(unittest.TestCase):
    def test_missing_entropy_rejected(self):
        r = evaluate(sample(pre_leak_min_entropy_bits=None))
        self.assertEqual(r.reason, 'NO_EXTERNALLY_JUSTIFIED_MIN_ENTROPY_BOUND')
        self.assertFalse(r.security_qualified)

    def test_missing_evidence_rejected(self):
        self.assertEqual(evaluate(sample(entropy_evidence_id=None)).decision, 'REJECT')

    def test_conditional_budget_reference(self):
        p = sample()
        r = evaluate(p)
        penalty = 2 * math.log2(1 / (2 * p.epsilon_pa))
        self.assertEqual(r.maximum_conditional_key_bits, math.floor(8000 - 664 - penalty))
        self.assertEqual(r.decision, 'CONDITIONAL_PASS')
        self.assertFalse(r.security_qualified)
        self.assertFalse(r.hpke_export_authorized)
        self.assertAlmostEqual(r.observed_test_qber, .01)

    def test_insufficient_entropy_rejected(self):
        self.assertEqual(evaluate(sample(pre_leak_min_entropy_bits=700)).decision, 'REJECT')

    def test_each_failed_prerequisite_rejected(self):
        for key in ('authenticated_transcript', 'uniform_independent_toeplitz_seed', 'reconciliation_confirmed'):
            with self.subTest(key=key):
                self.assertEqual(evaluate(sample(**{key: False})).decision, 'REJECT')

    def test_invalid_counts_rejected(self):
        for v in [sample(test_errors=2001), sample(reconciled_bits=10001),
                  sample(test_bits=0), sample(sifted_bits=-1),
                  sample(reconciliation_leak_bits=-1), sample(requested_key_bits=True)]:
            with self.subTest(v=v):
                with self.assertRaises(FiniteKeyError):
                    evaluate(v)

    def test_invalid_entropy_epsilon_rejected(self):
        for v in [sample(epsilon_pa=0), sample(epsilon_pa=math.nan),
                  sample(epsilon_pa=.5), sample(pre_leak_min_entropy_bits=10001),
                  sample(pre_leak_min_entropy_bits=math.inf)]:
            with self.subTest(v=v):
                with self.assertRaises(FiniteKeyError):
                    evaluate(v)

    def test_leakage_monotonicity(self):
        a = evaluate(sample(reconciliation_leak_bits=600)).maximum_conditional_key_bits
        b = evaluate(sample(reconciliation_leak_bits=1600)).maximum_conditional_key_bits
        self.assertEqual(a - b, 1000)

    def test_epsilon_monotonicity(self):
        strict = evaluate(sample(epsilon_pa=1e-12)).maximum_conditional_key_bits
        relaxed = evaluate(sample(epsilon_pa=1e-8)).maximum_conditional_key_bits
        self.assertLess(strict, relaxed)

    def test_no_qber_to_security_inference(self):
        r = evaluate(sample(test_errors=0, pre_leak_min_entropy_bits=None))
        self.assertEqual(r.decision, 'REJECT')
        self.assertEqual(r.observed_test_qber, 0)


if __name__ == '__main__':
    unittest.main()
