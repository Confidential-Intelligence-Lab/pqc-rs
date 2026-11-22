"""S5.D-1 independent Bernoulli robustness diagnostic and security denials."""
import math
from pathlib import Path
import tempfile
import unittest
from s5d_assurance_audit import AuditInputs, SOURCE_FILES, audit

class S5DTests(unittest.TestCase):
    def test_nominal_syndrome_bits(self):
        r = audit()
        self.assertEqual(r['syndrome_disclosure_upper_bits'], 4096)
        self.assertEqual(r['confirmation_tag_bits_disclosed'], 64)

    def test_iid_block_probability(self):
        r = audit()
        self.assertAlmostEqual(r['toy_block_success_probability'], 0.5270850040531452, places=12)

    def test_iid_session_is_not_proof(self):
        r = audit()
        self.assertLess(r['toy_session_success_probability'], 1e-30)
        self.assertFalse(r['conditional_security_supported'])

    def test_no_security_promotion(self):
        r = audit()
        for x in ('security_qualified','hpke_export_authorized','qkd_psk_available',
                  'quantum_cap_coupling_proven','multi_mac_authentication_advantage_proven'):
            self.assertIs(r[x], False)

    def test_invalid_inputs_fail_closed(self):
        for kwargs in ({'assumed_iid_x_error_rate': float('nan')},
                       {'block_size': 0}, {'max_correctable_per_block': 129},
                       {'n_key': True}, {'confirmation_tag_bits': 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                AuditInputs(**kwargs)

    def test_source_inventory_detects_missing(self):
        with tempfile.TemporaryDirectory() as d:
            r = audit(source_dir=d)
            self.assertFalse(r['source_inventory_complete'])
            self.assertEqual(set(r['missing_source_files']), set(SOURCE_FILES))

    def test_zero_error_reference(self):
        r = audit(AuditInputs(assumed_iid_x_error_rate=0.0))
        self.assertEqual(r['toy_session_success_probability'], 1.0)

if __name__ == '__main__':
    unittest.main()
