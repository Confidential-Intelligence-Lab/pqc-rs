"""S5.B classical trace checks and numerical-parameter review, not quantum proof."""
from dataclasses import dataclass
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from s5b_theorem_correspondence import analyze_prefix, audit_h2_numerical_argument, CorrespondenceError
from s2b2_strict_theorem_reference import ReferenceProtocolError


@dataclass(frozen=True)
class Record:
    basis: int


def trace(x: int, z: int):
    return tuple([Record(1)] * x + [Record(0)] * z)


class S5BTests(unittest.TestCase):
    def test_exact_first_hit_matches_prefix(self):
        a = trace(128, 8)
        d = analyze_prefix(a, a, n_key=128, k_test=8, max_transmissions=200)
        self.assertTrue(d['accepted_history_prefix_matches'])
        self.assertTrue(d['public_filter_eligible'])
        self.assertEqual(d['stop_index'], 135)
        self.assertFalse(d['quantum_coupling_proven'])

    def test_post_stop_rejected(self):
        a = trace(128, 9)
        d = analyze_prefix(a, a, n_key=128, k_test=8, max_transmissions=200)
        self.assertEqual(d['decision'], 'REJECT_POST_STOP_RECORDS')
        self.assertFalse(d['accepted_history_prefix_matches'])

    def test_quota_failure_is_abort(self):
        a = trace(128, 7)
        d = analyze_prefix(a, a, n_key=128, k_test=8, max_transmissions=200)
        self.assertEqual(d['decision'], 'ABORT_QUOTAS_NOT_MET')
        self.assertFalse(d['public_filter_eligible'])

    def test_z_overshoot_larger_than_min(self):
        a = trace(7, 18) + trace(121, 0)
        d = analyze_prefix(a, a, n_key=128, k_test=8, max_transmissions=200)
        self.assertEqual(d['k_actual'], 18)
        self.assertEqual(d['k_min'], 8)
        self.assertTrue(d['numerical_k_equals_precommitted_k'])

    def test_substitute_observed_k_not_theorem_proof(self):
        a = trace(7, 18) + trace(121, 0)
        d = analyze_prefix(a, a, n_key=128, k_test=8,
                           max_transmissions=200, numerical_k=18)
        self.assertFalse(d['numerical_k_equals_precommitted_k'])
        self.assertFalse(d['theorem_applicability_proven'])
        self.assertFalse(d['hpke_export_authorized'])

    def test_reject_over_cap(self):
        a = trace(128, 8)
        with self.assertRaises(ReferenceProtocolError):
            analyze_prefix(a, a, n_key=128, k_test=8, max_transmissions=135)

    def test_reject_invalid_numerical_k(self):
        a = trace(128, 8)
        for bad in (0, True, 1.5):
            with self.assertRaises(CorrespondenceError):
                analyze_prefix(a, a, n_key=128, k_test=8, max_transmissions=200,
                               numerical_k=bad)

    def test_h2_ast_requires_review_of_observed_k(self):
        d = audit_h2_numerical_argument()
        self.assertTrue(d['uses_observed_k_for_diagnostic'])
        self.assertFalse(d['observed_k_substitution_theorem_justified'])

    def test_h2_ast_change_fails_closed(self):
        source = Path(__file__).with_name('m1h2_authenticated_sampling.py').read_text()
        self.assertIn('BoundInput(n_key, actual_z_test_size,', source)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'altered.py'
            p.write_text(source.replace('BoundInput(n_key, actual_z_test_size,',
                                        'BoundInput(n_key, k_test,', 1))
            with self.assertRaises(CorrespondenceError):
                audit_h2_numerical_argument(p)

    def test_security_denials_stay_false(self):
        a = trace(128, 8)
        d = analyze_prefix(a, a, n_key=128, k_test=8, max_transmissions=200)
        for k in ('quantum_coupling_proven', 'entropy_proven', 'theorem_applicability_proven',
                  'security_model_validated', 'security_qualified', 'hpke_export_authorized',
                  'qkd_psk_available'):
            self.assertIs(d[k], False)


if __name__ == '__main__':
    unittest.main()
