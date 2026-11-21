"""S2.B3 tests: numerical and policy assertions cannot certify entropy."""
import dataclasses
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from s2b3_composable_evidence import (
    PublicExperiment, SecurityBudget, AssumptionReview, EvidenceError, assess)

HERE = Path(__file__).resolve().parent
P = PublicExperiment(4096,4096,4096,0,1024,40,128,32,.05)
B = SecurityBudget(1e-10,2**-40,1e-12,1.02e-10,1e-11,1e-11,1e-11)

class S2B3Tests(unittest.TestCase):
    def eval(self, p=P, b=B, review=None, root=HERE):
        return assess(p,b,root,review=review)

    def test_diagnostic_never_qualified(self):
        r=self.eval()
        self.assertGreater(r['numerical_equation_only']['maximum_numerical_key_bits'],0)
        self.assertEqual(r['decision'],'REJECT_UNVERIFIED_QUANTUM_ASSUMPTIONS')
        for name in ('theorem_sampling_validated','pre_leak_min_entropy_certified',
                     'security_model_validated','security_qualified','qkd_psk_available',
                     'hpke_export_authorized','authentication_provisioning_validated'):
            self.assertIs(r[name],False)
    def test_all_review_flags_do_not_grant_authority(self):
        review=AssumptionReview(True,True,True,True,True)
        r=self.eval(review=review)
        self.assertEqual(r['review_assertion_count'],5)
        self.assertFalse(r['pre_leak_min_entropy_certified'])
    def test_qber_above_tolerance_aborts(self):
        r=self.eval(p=dataclasses.replace(P,test_errors=206))
        self.assertEqual(r['decision'],'REJECT_QBER_ABOVE_TOLERANCE')
    def test_qber_boundary_accepted_diagnostic(self):
        r=self.eval(p=dataclasses.replace(P,test_errors=204))
        self.assertEqual(r['observation_decision'],'PUBLIC_PARAMETERS_CONSISTENT')
    def test_short_z_population_rejected(self):
        with self.assertRaisesRegex(EvidenceError,'Z test'):
            self.eval(p=dataclasses.replace(P,matched_z=4095))
    def test_inconsistent_syndrome_disclosure_rejected(self):
        with self.assertRaisesRegex(EvidenceError,'syndrome disclosure'):
            self.eval(p=dataclasses.replace(P,syndrome_disclosure_bits=1023))
    def test_partial_block_rejected(self):
        with self.assertRaisesRegex(EvidenceError,'full reconciliation blocks'):
            self.eval(p=dataclasses.replace(P,n_key=4097))
    def test_too_strict_correctness_rejected(self):
        with self.assertRaisesRegex(EvidenceError,'correctness budget'):
            self.eval(b=dataclasses.replace(B,epsilon_cor=2**-41))
    def test_insufficient_top_level_budget_rejected(self):
        with self.assertRaisesRegex(EvidenceError,'envelope'):
            self.eval(b=dataclasses.replace(B,epsilon_total=1e-10))
    def test_explicit_suballocation_over_target_rejected(self):
        with self.assertRaisesRegex(EvidenceError,'allocation'):
            self.eval(b=dataclasses.replace(B,epsilon_sampling=8e-11,
                                            epsilon_smoothing=8e-11))
    def test_separate_eq2_penalties(self):
        r=self.eval()
        self.assertEqual(r['equation2_error_correction_leak_bits'],1024)
        self.assertEqual(r['accounted_disclosure_bits'],1064)
        self.assertTrue(r['equation2_confirmation_penalty_via_epsilon_cor'])
    def test_larger_syndrome_never_increases_length(self):
        base=self.eval()['numerical_equation_only']['maximum_numerical_key_bits']
        # Another permissible matrix shape at same block size.
        p=dataclasses.replace(P,syndrome_bits_per_block=40,syndrome_disclosure_bits=1280)
        higher=self.eval(p=p)['numerical_equation_only']['maximum_numerical_key_bits']
        self.assertLessEqual(higher,base)
    def test_smaller_secrecy_target_never_increases_length(self):
        base=self.eval()['numerical_equation_only']['maximum_numerical_key_bits']
        b=dataclasses.replace(B,epsilon_sec=1e-11,epsilon_sampling=1e-12,
                              epsilon_smoothing=1e-12,epsilon_pa=1e-12)
        # Total target must still cover the top-level envelope.
        shorter=self.eval(b=b)['numerical_equation_only']['maximum_numerical_key_bits']
        self.assertLessEqual(shorter,base)
    def test_missing_source_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(EvidenceError,'required source missing'):
                self.eval(root=tmp)
    def test_unsupported_review_object(self):
        with self.assertRaisesRegex(EvidenceError,'typed AssumptionReview'):
            self.eval(review={'quantum_sampling_reviewed':True})
    def test_invalid_numeric_bool_rejected(self):
        with self.assertRaises(EvidenceError):
            self.eval(p=dataclasses.replace(P,n_key=True))
        with self.assertRaises(EvidenceError):
            self.eval(b=dataclasses.replace(B,epsilon_auth=True))
    def test_no_secret_in_output(self):
        import json
        r=json.dumps(self.eval(),sort_keys=True)
        self.assertNotIn('raw_key_value',r)
        self.assertNotIn('shared_secret',r)
        self.assertFalse(self.eval()['qkd_psk_available'])
    def test_strict_prefix_binding_exists(self):
        r=self.eval()
        self.assertIn('s2b2_strict_theorem_reference.py',r['source_sha256'])

if __name__=='__main__': unittest.main()
