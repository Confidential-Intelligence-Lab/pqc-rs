import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from m1h4c_theorem_conformance import audit, exhaustive_small_traces, first_quota_stop, source_checks, witness_extra_z


class H4CConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent

    def test_public_basis_trace_stop(self):
        self.assertEqual(first_quota_stop(('Z', 'Z', 'X'), 1, 1), 3)

    def test_unfinished_trace(self):
        self.assertIsNone(first_quota_stop(('X', 'M', 'X'), 1, 1))

    def test_invalid_basis(self):
        with self.assertRaises(ValueError):
            first_quota_stop(('Q',), 1, 1)

    def test_witness(self):
        w = witness_extra_z()
        self.assertEqual(w['matched_z_at_stop'], 2)
        self.assertFalse(w['exact_z_parameter_estimation_equivalent'])

    def test_exhaustive_counterexample(self):
        self.assertTrue(exhaustive_small_traces()['counterexample_exists'])

    def test_source_guard(self):
        self.assertTrue(all(source_checks(self.root).values()))

    def test_oversample_one_still_not_equivalent(self):
        r = audit(self.root, 2, 2, 1, 128)
        self.assertFalse(r['findings']['oversampling_is_an_extra_protocol_transformation'])
        self.assertFalse(r['findings']['box1_parameter_estimation_equivalent'])

    def test_oversampling_mismatch(self):
        r = audit(self.root, 4, 3, 2, 128)
        self.assertTrue(r['findings']['oversampling_is_an_extra_protocol_transformation'])
        self.assertEqual(r['findings']['h3b_acquisition_z_quota'], 6)
        self.assertEqual(r['findings']['h2_disclosed_z_size'], 3)

    def test_fail_closed(self):
        r = audit(self.root, 4, 3, 2, 128)
        self.assertFalse(r['security_model_validated'])
        self.assertFalse(r['theorem_sampling_validated'])
        self.assertFalse(r['hpke_export_authorized'])

    def test_invalid_cap(self):
        with self.assertRaises(ValueError):
            audit(self.root, 4, 3, 2, 10)

    def test_revision_requires_reaudit(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                source_checks(Path(tmp))


if __name__ == '__main__':
    unittest.main()
