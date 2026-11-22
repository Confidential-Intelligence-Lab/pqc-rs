"""S4.G diagnostics: CPU-only oracle tests; actual CUDA-Q run is separate."""
import random
import unittest
from unittest.mock import patch

from s4g_measurement_evidence import (MeasurementEvidenceError, bb84_cases,
    checked_outcome, ideal_p_one, intercept_resend, run, tolerance)


class IdealQubitOracle:
    """Reference probability oracle, NOT a CUDA-Q backend or security proof."""
    def __init__(self, seed=17):
        self.rng = random.Random(seed)

    def __call__(self, bit, a, b):
        return bit if a == b else self.rng.randrange(2)


class S4GMeasurementTests(unittest.TestCase):
    def test_truth_table(self):
        for bit in (0, 1):
            for a in (0, 1):
                for b in (0, 1):
                    self.assertEqual(ideal_p_one(bit, a, b), bit if a == b else .5)

    def test_invalid_boolean_or_nonbinary_inputs(self):
        for value in (True, -1, 2, 0.5, '1'):
            with self.assertRaises(MeasurementEvidenceError):
                ideal_p_one(value, 0, 0)
            with self.assertRaises(MeasurementEvidenceError):
                checked_outcome(value)

    def test_ideal_oracle_passes_eight_cases(self):
        r = bb84_cases(IdealQubitOracle(), shots=512)
        self.assertEqual(len(r['cases']), 8)
        self.assertEqual(r['decision'], 'MODEL_STATISTICS_PASS_UNQUALIFIED')
        self.assertFalse(r['security_qualified'])

    def test_biased_oracle_fails(self):
        r = bb84_cases(lambda bit, a, b: 0, shots=512)
        self.assertEqual(r['decision'], 'MODEL_STATISTICS_FAIL')

    def test_ideal_full_intercept_qber(self):
        r = intercept_resend(IdealQubitOracle(), trials=4096)
        self.assertEqual(r['decision'], 'MODEL_STATISTICS_PASS_UNQUALIFIED')
        self.assertGreater(r['matched'], 0)
        self.assertFalse(r['general_quantum_eve_validated'])

    def test_wrong_attack_oracle_rejects(self):
        r = intercept_resend(lambda bit, a, b: bit, trials=2048)
        self.assertEqual(r['decision'], 'MODEL_STATISTICS_FAIL')

    def test_invalid_oracle_result_rejected(self):
        with self.assertRaises(MeasurementEvidenceError):
            bb84_cases(lambda bit, a, b: True, shots=2)
        with self.assertRaises(MeasurementEvidenceError):
            intercept_resend(lambda bit, a, b: '0', trials=2)

    def test_predeclared_bounds_validate_inputs(self):
        for n, a, f in ((0, .01, 8), (10, 0, 8), (10, 1, 8), (10, .1, 0)):
            with self.assertRaises(MeasurementEvidenceError):
                tolerance(n, alpha=a, families=f)

    def test_combined_injected_oracle_not_qualified(self):
        r = run(shots=256, trials=1024, measure=IdealQubitOracle())
        self.assertEqual(r['decision'], 'EXPERIMENTS_PASS_UNQUALIFIED')
        self.assertEqual(r['backend'], 'injected-test-oracle-NOT-CUDAQ')
        for field in ('source_attested', 'quantum_min_entropy_proven',
                      'security_model_validated', 'security_qualified',
                      'hpke_export_authorized', 'qkd_psk_available'):
            self.assertFalse(r[field])

    def test_structural_mutation_blocks_execution(self):
        with patch('s4g_measurement_evidence.audit_prepare_and_measure',
                   side_effect=MeasurementEvidenceError('changed')):
            with self.assertRaises(MeasurementEvidenceError):
                run(shots=16, trials=16, measure=IdealQubitOracle())


if __name__ == '__main__':
    unittest.main()
