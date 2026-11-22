"""Source-level S2.B1 fail-closed audit tests."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from s2b1_entropy_conformance_audit import audit, SOURCE_FILES

class S2B1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(__file__).resolve().parent

    def test_current_source_audit(self):
        a = audit(self.source)
        self.assertEqual(a['decision'], 'THEOREM_CONFORMANCE_NOT_ESTABLISHED')
        self.assertEqual(len(a['open_obligations']), 10)
        self.assertTrue(all(a['implementation_markers'].values()))

    def test_missing_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,'source missing'):
                audit(tmp)

    def test_source_drift_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in SOURCE_FILES:
                (Path(tmp)/name).write_bytes((self.source/name).read_bytes())
            p = Path(tmp)/'m2a_authenticated_distillation.py'
            p.write_text(p.read_text().replace('HYPOTHETICAL_ONLY_NOT_EVIDENCE', 'UNVERIFIED'))
            with self.assertRaisesRegex(ValueError,'source drift'):
                audit(tmp)

    def test_no_qualification_even_positive_length(self):
        a = audit(self.source,n_key=100000,k_test=10000,q_tolerance=0,
                  syndrome_leak_bits=10000,confirmation_leak_bits=40)
        self.assertGreater(a['numerical_diagnostic_only']['maximum_numerical_key_bits'], 0)
        self.assertFalse(a['pre_leak_min_entropy_certified'])
        self.assertFalse(a['hpke_export_authorized'])

    def test_sample_size_invalid(self):
        with self.assertRaises(ValueError): audit(self.source,n_key=0)

    def test_negative_leakage_invalid(self):
        with self.assertRaises(ValueError): audit(self.source,syndrome_leak_bits=-1)

    def test_q_tolerance_monotonicity(self):
        a = audit(self.source, q_tolerance=0.0)
        b = audit(self.source, q_tolerance=0.05)
        self.assertGreaterEqual(a['numerical_diagnostic_only']['maximum_numerical_key_bits'],
                                b['numerical_diagnostic_only']['maximum_numerical_key_bits'])

    def test_increased_leakage_never_increases_length(self):
        a = audit(self.source,syndrome_leak_bits=100)
        b = audit(self.source,syndrome_leak_bits=1024)
        self.assertGreaterEqual(a['numerical_diagnostic_only']['maximum_numerical_key_bits'],
                                b['numerical_diagnostic_only']['maximum_numerical_key_bits'])

    def test_all_obligations_open(self):
        a = audit(self.source)
        self.assertTrue(all(o['state']=='OPEN' for o in a['open_obligations']))

    def test_public_only_report(self):
        a = audit(self.source)
        self.assertFalse(any('raw_key' in k or 'psk_bytes' in k for k in a.keys()))

if __name__=='__main__': unittest.main()
